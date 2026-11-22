"""Private exact native-path proof for API-masked original object fields.

Only actual API/native collectors mint receipts. Flat scanner membership, caller
config dictionaries and manually constructed PostRestoreValues prove nothing.
No HTTP/native IO here; compares bounded completed observations, not future live
state. Caller owns exclusion across API/native phases and later publication.
"""
import copy
from itertools import count
import weakref

from emqx_private_boundary import PrivateFailure

_API=weakref.WeakKeyDictionary()
_NATIVE=weakref.WeakKeyDictionary()
_ORDER=count()
MASK='******'  # pinned emqx_utils:redact/1 secret marker, never equality proof.


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
                or type(actual) is not str or actual not in (expected,MASK)):raise ValueError()
        return
    if type(expected) is not type(actual):raise ValueError()
    if type(expected) is dict:
        if not set(expected)<=set(actual):raise ValueError()
        for key,value in expected.items():_same(value,actual[key],path+(key,),secrets)
    elif type(expected) is list:
        if len(expected)!=len(actual):raise ValueError()
        for index,(left,right) in enumerate(zip(expected,actual)):_same(left,right,path+(index,),secrets)
    elif type(actual) is str and actual==MASK:
        raise ValueError()  # Even a literal expected mask cannot prove equality.
    elif expected!=actual:raise ValueError()


def compare_b1_objects_native(*,expected,source_api,native_values):
    """Keep nonsecret API comparison; resolve ONLY validated native secret paths.

    Fresh native receipt AFTER API completion, same issued owner, full CID,
    pin/config/mount identity and original combined
    registry required for API/native receipts. V1 native observations may compare
    unmasked fields but offer NO secret wrapper proof. Old/handmade scanner-only
    observations, incomplete metadata, unknown paths or masked plaintext refuse.
    """
    try:
        from emqx_b1_object_integrity import SourceObjects,_RECORDS
        from emqx_source_api_validator import _rows
        from emqx_owner_fixture_files import _record
        if type(expected) is not SourceObjects:raise ValueError()
        original=_RECORDS[expected];api=_API[source_api];native=_NATIVE[native_values]
        if (native['owner'] is not api[0] or native['cid']!=api[1]
                or native['identity']!=api[2] or native['registry'] is not api[3]
                or original['registry'] is not api[3] or native['order']<=api[4]
                or source_api._documents!=api[5]
                or native['persisted'] is not native_values._persisted
                or native['generation']!=native_values._persisted.generation
                or _root(source_api._prior) is not api[3] or _root(native_values) is not api[3]
                or _record(api[0].file_capability)[1] is not api[0]):raise ValueError()
        expected.scan(b'');source_api.scan(b'');native_values.scan(b'')
        documents=source_api.private_documents()
        for category in ('rules','actions','connectors'):
            actual={}
            for row in _rows(documents[category],category):
                key=row['id'] if category=='rules' else (row['type'],row['name'])
                if key in actual:raise ValueError()
                actual[key]=row
            for key,obj in original['objects'][category].items():
                path=('rule_engine','rules',key) if category=='rules' else (category,*key)
                _same(obj,actual[key],path,native['secrets'])
        return NativeObjectComparison(expected,source_api,native_values)
    except (KeyboardInterrupt,SystemExit):raise PrivateFailure('native-object-integrity-cancelled') from None
    except Exception:raise PrivateFailure('native-object-integrity-refused') from None
