"""Private equality of explicit B1 HOCON objects and observed API object data.

Source expectation is minted ONLY from an actual verified, joined, sealed Capture
while alive. It survives capture close for post-restore comparison. No second
Capture, builder, source broker, reference resolution or evidence publication.
This does NOT derive final Mnesia rows/counts from cold historical receipts.
"""
import copy
import json
import tarfile
import time
import uuid
import weakref

from emqx_captured_candidate import _authorized
from emqx_hocon_context import CONTRACT, HTTP_CONTRACT, SQL_CONTRACT
from emqx_persisted_values import PersistedValues
from emqx_private_boundary import PrivateFailure
from emqx_semantic_readers import _contract, MAX_INPUT, MAX_OUTPUT, Values
from emqx_source_profiles import source_profile
from emqx_runtime_workflow import CombinedRegistry
from emqx_post_restore_values import PostRestoreValues
from emqx_source_api_validator import SourceAPIResult, _rows
from woowbackup import habackup, ha_emqx

MODES=('--source-vendor-acl-sql-aliases','--x86-source-vendor-acl-sql-aliases')
_RECORDS=weakref.WeakKeyDictionary()


class SourceObjects:
    def __repr__(self):return '<EMQX private original object expectations>'
    def scan(self,payload):
        if self not in _RECORDS:raise PrivateFailure('object-integrity-refused')
        record=_RECORDS[self]
        record['registry'].scan(payload);record['values'].scan(payload)


class ObjectComparison:
    def __init__(self,expected,observed):self._expected,self._observed=expected,observed
    def __repr__(self):return '<EMQX private explicit object comparison>'
    def scan(self,payload):self._expected.scan(payload);self._observed.scan(payload)
    def scope(self):
        return ('source-explicit-rule-action-connector-fields',
                'not-final-mnesia-rows-or-active-acl-or-rule-delivery')


def _leaves(value,values,depth=0):
    values.tick(depth)
    if type(value) is dict:
        for key,child in value.items():
            if type(key) is not str:raise ValueError()
            _leaves(key,values,depth+1);_leaves(child,values,depth+1)
    elif type(value) is list:
        for child in value:_leaves(child,values,depth+1)
    elif type(value) is str:
        if value:values.add(value.encode())
    elif value is None or type(value) in (bool,int,float):
        values.add(json.dumps(value,allow_nan=False).encode())
    else:raise ValueError()


def _objects(document):
    rules=document.get('rule_engine',{}).get('rules')
    if type(rules) is not dict or not 1<=len(rules)<=64:raise ValueError()
    if not {'b1_rule_republish','b1_rule_http'}<=set(rules):raise ValueError()
    for name,rule in rules.items():
        if (type(name) is not str or not name or type(rule) is not dict or
                type(rule.get('sql')) is not str or not rule['sql'] or type(rule.get('actions')) is not list):raise ValueError()
    result={'rules':copy.deepcopy(rules)}
    for category in ('actions','connectors'):
        groups=document.get(category)
        if type(groups) is not dict or not groups or len(groups)>64:raise ValueError()
        selected={}
        for kind,objects in groups.items():
            if type(kind) is not str or not kind or type(objects) is not dict:raise ValueError()
            for name,obj in objects.items():
                if type(name) is not str or not name or type(obj) is not dict or not obj or len(selected)>=64:raise ValueError()
                selected[(kind,name)]=copy.deepcopy(obj)
        required=('http','b1_http_action' if category=='actions' else 'b1_http')
        if required not in selected:raise ValueError()
        result[category]=selected
    return result


def capture_b1_object_expectations(*,captured,session,source_mode):
    """Call AFTER actual combined preflight, BEFORE build/source context exit.

    Compiled source SHA/architecture only. Readonly already-authenticated replay;
    complete strict tar traversal, one <=8MiB cluster.hocon, existing actual native
    parser with full digest/EOF/nonresolving receipt. <=64 objects/category,
    unchanged private value budgets,120s cooperative deadline. All source-explicit
    fields are compared later; API-only defaults may add fields. No field dropping,
    masked-value waiver, guessed normalization or claim of full effective equality.
    """
    try:
        if source_mode not in MODES:raise ValueError()
        profile=source_profile(source_mode)
        binding=captured._private_binding
        proof=_authorized(captured,binding,session,profile.sha256)
        if proof[3].arch!=profile.arch:raise ValueError()
        deadline=time.monotonic()+120
        def timely():
            if time.monotonic()>=deadline:raise ValueError()
        target=ha_emqx.DATA+'/configs/cluster.hocon';raw=None
        with binding['open'](proof[2]) as stream:
            report=habackup.Report()
            for _ in habackup.iter_entries(stream,report=report,addon=True):timely()
            if not report.complete:raise ValueError()
            stream.seek(0)
            with tarfile.open(fileobj=stream,mode='r:') as archive:
                for index,entry in enumerate(archive):
                    timely()
                    if index>=4096:raise ValueError()
                    if habackup.normalize(entry.name)!=target:continue
                    if raw is not None or not entry.isfile() or not 0<entry.size<=MAX_INPUT:raise ValueError()
                    with archive.extractfile(entry) as handle:raw=handle.read(MAX_INPUT+1)
                    if len(raw)!=entry.size:raise ValueError()
        if raw is None:raise ValueError()
        encoded=captured._hocon_parser(raw);timely()
        if type(encoded) is not bytes or len(encoded)>MAX_OUTPUT:raise ValueError()
        kind=json.loads(encoded)['contract']
        if kind not in ('emqx-hocon-json-v1',CONTRACT,HTTP_CONTRACT,SQL_CONTRACT):raise ValueError()
        doc=_contract(raw,lambda _:encoded,kind)
        if (set(doc)!={'contract','version','input_sha256','input_bytes','complete','resolution','references','document'}
                or doc['resolution']!='disabled' or doc['references']!=[]):raise ValueError()
        envelope=doc['document']
        fields={'parsed','syntax_strings'}
        if kind in (CONTRACT,HTTP_CONTRACT,SQL_CONTRACT):fields|={'string_bindings','concat_strings'}
        if kind==SQL_CONTRACT:fields.add('alias_bindings')
        if (type(envelope) is not dict or set(envelope)!=fields
                or type(envelope.get('parsed')) is not dict
                or type(envelope.get('syntax_strings')) is not list
                or any(type(x) is not str for x in envelope['syntax_strings'])
                or any(type(envelope[key]) is not list for key in fields-{'parsed','syntax_strings'})):
            raise ValueError()
        # Both fixed native producers put effective values here. Sibling syntax
        # ledgers remain registered data, never alternate expected object values.
        objects=_objects(envelope['parsed'])
        values=Values()
        # Entire native source document stays private, including syntax/template
        # witnesses and secret fields that an API may mask. Never execute refs.
        _leaves(doc['document'],values)
        companion=PersistedValues(uuid.uuid4().hex,'source',{},values.values)
        _authorized(captured,binding,session,profile.sha256);timely()
        token=SourceObjects()
        _RECORDS[token]={'objects':objects,'registry':session.registry,'values':companion,
                         'sha256':profile.sha256}
        return token
    except (KeyboardInterrupt,SystemExit):raise PrivateFailure('object-integrity-cancelled') from None
    except Exception:raise PrivateFailure('object-integrity-refused') from None


def _subset(expected,actual,depth=0):
    if depth>16 or type(expected) is not type(actual):raise ValueError()
    if type(expected) is dict:
        if not set(expected)<=set(actual):raise ValueError()
        for key,value in expected.items():_subset(value,actual[key],depth+1)
    elif type(expected) is list:
        if len(expected)!=len(actual):raise ValueError()
        for left,right in zip(expected,actual):_subset(left,right,depth+1)
    elif expected!=actual:raise ValueError()


def compare_b1_objects(*,expected,source_api):
    """No IO; exact source-explicit values against API from SAME joined registry.

    Missing/changed/masked source fields refuse. Runtime-added objects/defaults
    are allowed, not silently counted as original source objects. API views are
    not native final-row truth, ACL authorization or rule/action execution proof.
    """
    try:
        if type(expected) is not SourceObjects or type(source_api) is not SourceAPIResult:raise ValueError()
        record=_RECORDS[expected];root=source_api._prior
        for _ in range(4):
            if type(root) is PostRestoreValues:root=root._previous
        if type(root) is not CombinedRegistry or root is not record['registry'] or source_api._runtime is not root._runtime:raise ValueError()
        expected.scan(b'');source_api.scan(b'')
        documents=source_api.private_documents()
        for category in ('rules','actions','connectors'):
            actual={}
            for row in _rows(documents[category],category):
                key=row['id'] if category=='rules' else (row['type'],row['name'])
                if key in actual:raise ValueError()
                actual[key]=row
            for key,obj in record['objects'][category].items():
                _subset(obj,actual[key])
        return ObjectComparison(expected,source_api)
    except (KeyboardInterrupt,SystemExit):raise PrivateFailure('object-integrity-cancelled') from None
    except Exception:raise PrivateFailure('object-integrity-refused') from None
