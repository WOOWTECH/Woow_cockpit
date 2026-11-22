"""Private exact native-path proof for API-masked original object fields.

Only actual API/native collectors mint receipts. Flat scanner membership, caller
config dictionaries and manually constructed PostRestoreValues prove nothing.
No HTTP/native IO here; compares bounded completed observations, not future live
state. Rule metadata has a narrow three-way pinned5.8.9 semantic profile: source
integer milliseconds must equal fresh native cooked metadata and API RFC3339
instants. emqx_rule_engine_api:add_metadata/1, format_rule_info_resp/1 and
emqx_rule_engine:with_parsed_rule/3 define the mapping. Metadata schema is map(),
not uint: unknown fields/partial maps and out-of-profile times explicitly refuse.
OTP26 calendar docs system_time_to_rfc3339/2 specify default T/local offset and
exactly3 fractional digits for millisecond (https://www.erlang.org/docs/26/man/calendar.html). Caller owns exclusion across API/native phases and later publication.
"""
import copy
import re
from datetime import datetime, timedelta, timezone
from itertools import count
import weakref

from emqx_private_boundary import PrivateFailure

_API=weakref.WeakKeyDictionary()
_NATIVE=weakref.WeakKeyDictionary()
_ORDER=count()
MASK='******'  # pinned emqx_utils:redact/1 secret marker, never equality proof.


CATEGORIES=('rules','actions','connectors')
REASONS=('type','missing','value','secret_wrapper')
OBJECT_STAGES=frozenset(('identity','registry','order','collector',
    *(category+'_'+reason for category in CATEGORIES for reason in REASONS)))
OBJECT_PHASES=frozenset('object_integrity_'+stage for stage in OBJECT_STAGES)

class NativeObjectPhaseRefused(PrivateFailure):
    def __init__(self,stage):
        self.phase='object_integrity_'+(stage if stage in OBJECT_STAGES else 'collector')
        super().__init__('native-object-integrity-refused')

class _Difference(ValueError):
    def __init__(self,reason):
        self.reason=reason if reason in REASONS else 'value'
        super().__init__('native-object-difference')


def _root(registry):
    from emqx_post_restore_values import PostRestoreValues
    from emqx_runtime_workflow import CombinedRegistry
    for _ in range(4):
        if type(registry) is PostRestoreValues:registry=registry._previous
    if type(registry) is not CombinedRegistry:raise ValueError()
    registry.scan(b'')
    return registry


def _record_api(result,provision,cid,identity):
    """Collector-only hook AFTER successful requests/identity/lease cleanup."""
    from emqx_source_api_validator import SourceAPIResult
    if type(result) is not SourceAPIResult or result in _API:raise ValueError()
    registry=_root(result._prior)
    if result._runtime is not registry._runtime or identity[0]!=cid:raise ValueError()
    _API[result]=(provision,cid,copy.deepcopy(identity),registry,
                  next(_ORDER),copy.deepcopy(result._documents))
    return result


def _record_native(result,wire,generation,provision,cid,identity):
    """Collector-only hook AFTER full native validation/identity/lease cleanup.

    Retains actual private decoded config+v2 wrapper paths, not inferred secrets.
    Existing strict native producer/consumer remains the only wire authority.
    """
    from emqx_post_restore_values import PostRestoreValues
    from emqx_owner_target import _read_reply,_decode,_config_secret_metadata
    from emqx_semantic_readers import Values
    if (type(result) is not PostRestoreValues or result in _NATIVE or
            result._persisted.generation!=generation or identity[0]!=cid):raise ValueError()
    raw,doc=_read_reply(wire,generation)
    if not result._persisted.matches('schema',raw):raise ValueError()
    values=Values();config=_decode(doc['config'],values)
    wrappers=[]
    if doc['contract']=='emqx-owner-live-target-v2':
        wrappers=_decode(doc['config_secret_wrappers'],values)
        _config_secret_metadata(config,wrappers)
    paths={}
    for wrapper in wrappers:
        # Metadata validation above proved path container kinds and exact binary
        # environment equal the cooked config value. Flatten ONLY for JSON paths.
        path=[]
        for kind,key in wrapper['path']:
            if type(key) is bytes:key=key.decode('utf-8')
            path.append(key)
        key=tuple(path)
        if key in paths:raise ValueError()
        paths[key]=wrapper['env'][0]
    _NATIVE[result]={'owner':provision,'cid':cid,'identity':copy.deepcopy(identity),
        'registry':_root(result),'generation':generation,'persisted':result._persisted,
        'config':config,'secrets':paths,'order':next(_ORDER)}
    return result


class NativeObjectComparison:
    def __init__(self,expected,api,native):self._expected,self._api,self._native=expected,api,native
    def __repr__(self):return '<EMQX private native-path object comparison>'
    def scan(self,payload):
        self._expected.scan(payload);self._api.scan(payload);self._native.scan(payload)
    def scope(self):
        return ('source-explicit-object-fields-api-plus-native-secret-paths',
                'not-final-mnesia-rows-or-active-acl-or-rule-delivery')


def _same(expected,actual,path,secrets):
    if path in secrets:
        # Binary plaintext is observed at THIS native path; neither hashes nor
        # same bytes elsewhere in config/scanner can establish this equality.
        if (type(expected) is not str or expected.encode()!=secrets[path]
                or type(actual) is not str or actual not in (expected,MASK)):raise _Difference('secret_wrapper')
        return
    if type(expected) is not type(actual):raise _Difference('type')
    if type(expected) is dict:
        if not set(expected)<=set(actual):raise _Difference('missing')
        for key,value in expected.items():_same(value,actual[key],path+(key,),secrets)
    elif type(expected) is list:
        if len(expected)!=len(actual):raise _Difference('value')
        for index,(left,right) in enumerate(zip(expected,actual)):_same(left,right,path+(index,),secrets)
    elif type(actual) is str and actual==MASK:
        raise _Difference('secret_wrapper')  # Even a literal expected mask cannot prove equality.
    elif expected!=actual:raise _Difference('value')


# Narrow supported timestamp profile, not a claim that metadata map() is uint.
# emqx_utils_calendar's validated nonnegative millisecond ceiling; native decoder
# also requires signed64 integers. No floating point conversion or coercion.
_METADATA_KEYS=frozenset(('created_at','last_modified_at'))
_MAX_METADATA_MS=253402214400000
_API_TIME=re.compile(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})([+-])([0-9]{2}):([0-9]{2})')
_EPOCH=datetime(1970,1,1,tzinfo=timezone.utc)


def _timestamp_ms(value):
    # Vendor passes ONLY {unit,millisecond}: default T, exactly3 fraction digits,
    # default local numeric offset. No Z/lowercase/space/unknown-offset profile.
    if type(value) is not str:raise _Difference('type')
    match=_API_TIME.fullmatch(value)
    if match is None:raise _Difference('value')
    y,mo,d,h,mi,sec,ms,sign,oh,om=match.groups()
    oh,om=int(oh),int(om)
    if oh>23 or om>59 or (sign=='-' and oh==om==0):raise _Difference('value')
    offset=timedelta(hours=oh,minutes=om)*(1 if sign=='+' else -1)
    try:
        delta=datetime(int(y),int(mo),int(d),int(h),int(mi),int(sec),int(ms)*1000,
                       tzinfo=timezone(offset)).astimezone(timezone.utc)-_EPOCH
    except (ValueError,OverflowError):raise _Difference('value') from None
    result=(delta.days*86400+delta.seconds)*1000+delta.microseconds//1000
    if not 0<=result<=_MAX_METADATA_MS:raise _Difference('value')
    return result


def _same_rule(expected,actual,path,secrets,config):
    if 'metadata' not in expected:
        return _same(expected,actual,path,secrets)
    metadata=expected['metadata']
    if type(metadata) is not dict:raise _Difference('type')
    if set(metadata)!=_METADATA_KEYS:raise _Difference('missing' if set(metadata)<_METADATA_KEYS else 'value')
    try:
        current=config['rule_engine']['rules'][path[-1]]['metadata']
    except (KeyError,TypeError):raise _Difference('missing') from None
    if type(current) is not dict:raise _Difference('type')
    if set(current)!=_METADATA_KEYS:raise _Difference('missing' if set(current)<_METADATA_KEYS else 'value')
    if type(actual) is not dict:raise _Difference('type')
    for key in _METADATA_KEYS:
        source=metadata[key];native=current[key]
        if type(source) is not int or type(native) is not int:raise _Difference('type')
        if not 0<=source<=_MAX_METADATA_MS or source!=native:raise _Difference('value')
        if key not in actual:raise _Difference('missing')
        if _timestamp_ms(actual[key])!=source:raise _Difference('value')
    # Every remaining source field retains its previous strict comparison.
    for key,value in expected.items():
        if key=='metadata':continue
        if key not in actual:raise _Difference('missing')
        _same(value,actual[key],path+(key,),secrets)


def compare_b1_objects_native(*,expected,source_api,native_values):
    """Keep nonsecret API comparison; resolve ONLY validated native secret paths.

    Fresh native receipt AFTER API completion, same issued owner, full CID,
    pin/config/mount identity and original combined
    registry required for API/native receipts. V1 native observations may compare
    unmasked fields but offer NO secret wrapper proof. Old/handmade scanner-only
    observations, incomplete metadata, unknown paths or masked plaintext refuse.
    """
    stage='collector'
    try:
        from emqx_b1_object_integrity import SourceObjects,_RECORDS
        from emqx_source_api_validator import _rows
        from emqx_owner_fixture_files import _record
        if type(expected) is not SourceObjects:raise ValueError()
        original=_RECORDS[expected];api=_API[source_api];native=_NATIVE[native_values]
        stage='identity'
        if (native['owner'] is not api[0] or native['cid']!=api[1]
                or native['identity']!=api[2]):raise ValueError()
        stage='registry'
        if (native['registry'] is not api[3] or original['registry'] is not api[3]
                or _root(source_api._prior) is not api[3] or _root(native_values) is not api[3]):raise ValueError()
        stage='order'
        if native['order']<=api[4]:raise ValueError()
        stage='collector'
        if (source_api._documents!=api[5]
                or native['persisted'] is not native_values._persisted
                or native['generation']!=native_values._persisted.generation
                or _record(api[0].file_capability)[1] is not api[0]):raise ValueError()
        stage='registry'
        expected.scan(b'');source_api.scan(b'');native_values.scan(b'')
        stage='collector'
        documents=source_api.private_documents()
        for category in CATEGORIES:
            actual={}
            stage=category+'_missing'
            document=documents[category]
            stage=category+'_type'
            rows=_rows(document,category)
            for row in rows:
                stage=category+'_missing'
                key=row['id'] if category=='rules' else (row['type'],row['name'])
                stage=category+'_value'
                if key in actual:raise ValueError()
                actual[key]=row
            for key,obj in original['objects'][category].items():
                path=('rule_engine','rules',key) if category=='rules' else (category,*key)
                stage=category+'_missing'
                observed=actual[key]
                try:
                    if category=='rules':_same_rule(obj,observed,path,native['secrets'],native['config'])
                    else:_same(obj,observed,path,native['secrets'])
                except _Difference as error:
                    raise NativeObjectPhaseRefused(category+'_'+error.reason) from None
        return NativeObjectComparison(expected,source_api,native_values)
    except (KeyboardInterrupt,SystemExit):raise PrivateFailure('native-object-integrity-cancelled') from None
    except NativeObjectPhaseRefused:raise
    except Exception:raise NativeObjectPhaseRefused(stage) from None
