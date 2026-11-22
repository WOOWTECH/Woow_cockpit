"""Private original-B1 API acceptance, through an already owned isolated runtime.

No CLI/files/credential discovery, provisioning, candidate or evidence publisher.
Caller holds actual source/target exclusion via quiesce. Fixed loopback HTTP only;
login is the only write. API views may mask values: this retains EVERY returned
value, never reconstructs plaintext or claims native/final storage completeness.
Mnesia ACL API facts do NOT attest the active file ACL or MQTT authorization.
"""
import base64
import copy
import io
import json
import re
import time

from emqx_adapter_owner import OwnerProvision, LabOwnerRunner
from emqx_owner_fixture_files import _record
from emqx_post_restore_values import _runtime_identity, PostRestoreValues
from emqx_private_owner_driver import curl_login_transport, HTTP_OUTPUT
from emqx_private_boundary import PrivateFailure, MAX_VALUE
from emqx_runtime_credentials import RuntimeRegistry, login_registered, parse_json
from emqx_runtime_workflow import CombinedRegistry, PrivateSession

# Paths are protocol constants, never supplied or derived from response values.
PATHS = {
 'mqtt_users':'/authentication/password_based:built_in_database/users?page=1&limit=1000',
 'acl_users':'/authorization/sources/built_in_database/rules/users?page=1&limit=1000',
 'acl_clients':'/authorization/sources/built_in_database/rules/clients?page=1&limit=1000',
 'acl_all':'/authorization/sources/built_in_database/rules/all',
 'authorization_settings':'/authorization/settings', 'authorization_sources':'/authorization/sources',
 'banned':'/banned?page=1&limit=1000', 'rules':'/rules?page=1&limit=1000',
 'connectors':'/connectors', 'actions':'/actions', 'retainer':'/mqtt/retainer/messages?page=1&limit=1000',
 'dashboard_users':'/users', 'api_keys':'/api_key', 'nodes':'/nodes',
}
PAGED = {'mqtt_users','acl_users','acl_clients','banned','rules','retainer'}


class SourceAPIResult:
    def __init__(self, prior, runtime, documents, facts):
        self._prior, self._runtime = prior, runtime
        self._documents, self._facts = documents, facts

    def __repr__(self):
        return '<EMQX private B1 API observation>'

    def scan(self, payload):
        self._prior.scan(payload)
        self._runtime.scan(payload)

    def private_documents(self):
        return copy.deepcopy(self._documents)

    def private_facts(self):
        """RAM only. Counts/IDs describe these API responses, not cold history."""
        return copy.deepcopy(self._facts)


def _register_document(runtime, raw):
    # Preserve raw body, keys, all scalar values, JWT-adjacent metadata and
    # masked strings as observed. Existing registry budgets/encodings unchanged.
    document = parse_json(raw)
    values = [raw] if raw else []
    nodes = 0
    def walk(value, depth=0):
        nonlocal nodes
        nodes += 1
        if nodes > 4096 or depth > 16: raise ValueError()
        if type(value) is dict:
            for key, child in value.items():
                walk(key,depth+1);walk(child,depth+1)
        elif type(value) is list:
            for child in value: walk(child,depth+1)
        elif type(value) is str:
            if value: values.append(value.encode())
        elif value is None or type(value) in (bool,int,float):
            values.append(json.dumps(value,allow_nan=False).encode())
        else: raise ValueError()
    walk(document)
    runtime.register_bundle({'runtime-login-token':values})
    return document


def _rows(document, name):
    if name in PAGED:
        if type(document) is not dict or type(document.get('meta')) is not dict: raise ValueError()
        meta=document['meta']
        if (type(meta.get('count')) is not int or meta['count'] < 0 or meta['count'] > 1000
                or meta.get('page',1) != 1 or meta.get('hasnext',False) is not False): raise ValueError()
    rows = document.get('data') if type(document) is dict else document
    if (type(rows) is not list or len(rows)>1000 or any(type(x) is not dict for x in rows)
            or (name in PAGED and document['meta']['count'] != len(rows))): raise ValueError()
    return rows


def _facts(documents, admin, second, topics):
    rows={name:_rows(doc,name) for name,doc in documents.items()
          if name not in ('acl_all','authorization_settings','authorization_sources')}
    def ids(name, key):
        values=[row[key] for row in rows[name]]
        if any(type(v) is not str or not v for v in values) or len(set(values))!=len(values): raise ValueError()
        return sorted(values)
    facts={name:{'count':len(value)} for name,value in rows.items()}
    for name,key in [('mqtt_users','user_id'),('dashboard_users','username'),('api_keys','name'),
                     ('rules','id'),('retainer','topic'),('nodes','node')]: facts[name]['ids']=ids(name,key)
    for name in ('connectors','actions'):
        pairs=[(r['type'],r['name']) for r in rows[name]]
        if any(type(x) is not str or not x for pair in pairs for x in pair) or len(set(pairs))!=len(pairs): raise ValueError()
        facts[name]['ids']=sorted(pairs)
    for name,key in [('acl_users','username'),('acl_clients','clientid')]:
        facts[name]['ids']=ids(name,key)
        if any(type(r.get('rules')) is not list for r in rows[name]): raise ValueError()
        facts[name]['rule_counts']={r[key]:len(r['rules']) for r in rows[name]}
    bans=[(r['as'],r['who']) for r in rows['banned']]
    if any(type(x) is not str or not x for pair in bans for x in pair) or len(set(bans))!=len(bans): raise ValueError()
    facts['banned']['ids']=sorted(bans)
    settings=documents['authorization_settings']
    sources=documents['authorization_sources']
    if type(sources) is dict: sources=sources.get('sources')
    if (type(settings) is not dict or settings.get('no_match') not in ('allow','deny')
            or type(sources) is not list or len(sources)>1000
            or any(type(x) is not dict or type(x.get('type')) is not str or type(x.get('enable')) is not bool for x in sources)):
        raise ValueError()
    facts['authorization_sources']={'types':[x['type'] for x in sources]}
    all_rules=documents['acl_all']
    if type(all_rules) is not dict or type(all_rules.get('rules')) is not list: raise ValueError()
    facts['acl_all']={'count':len(all_rules['rules'])}
    if (not {admin.decode(),second.decode()} <= set(facts['dashboard_users']['ids'])
            or not any(r.get('name')=='b1-import-key' and r.get('enable') is True for r in rows['api_keys'])
            or not {'b1_rule_republish','b1_rule_http'} <= set(facts['rules']['ids'])
            or ('http','b1_http') not in facts['connectors']['ids']
            or ('http','b1_http_action') not in facts['actions']['ids']
            or not any(r.get('as')=='clientid' and r.get('who')=='b1-banned-client' for r in rows['banned'])
            or not {x.decode() for x in topics} <= set(facts['retainer']['ids'])
            or facts['acl_users']['rule_counts'] != {'b1-gateway':2,'b1-sensor':2}
            or facts['acl_clients']['rule_counts'] != {'b1-dashboard-panel':1}
            or facts['acl_all']['count'] != 1 or not rows['nodes']): raise ValueError()
    facts['acl_scope']='source-mnesia-data-only'
    facts['active_file_acl_behavior']='requires-separate-mqtt-validation'
    return facts


def validate_source_api(*, prior_registry, provision, expected_container_id, quiesce,
                        port, admin_username, admin_password, second_username,
                        second_password, api_key, api_secret, retained_topics):
    """Explicit RAM credentials; no defaults. 120s cooperative deadline, no retries,
    18 HTTP calls (each runner timeout10s; identity inspect5s). Late finish refuses.

    Current CID/pin/network-none proof is independent of old file capability CID.
    Capability only proves invocation issuance/lifetime and is never rebound.
    GETs are fixed, single-page/1000-row bounded and refuse incomplete inventory.
    Returned result is private; caller MUST scan evidence through it. No evidence
    is emitted even on success, and failures disclose only a fixed code.
    """
    try:
        prior=prior_registry.registry if type(prior_registry) is PrivateSession else prior_registry
        root=prior
        for _ in range(4):
            if type(root) is PostRestoreValues: root=root._previous
        if (type(root) is not CombinedRegistry or type(root._runtime) is not RuntimeRegistry
                or type(provision) is not OwnerProvision or not isinstance(provision.runner,LabOwnerRunner)
                or provision.runner.owner!='appowner' or not callable(quiesce)
                or type(expected_container_id) is not str or re.fullmatch('[0-9a-f]{64}',expected_container_id) is None
                or type(port) is not int or not 1<=port<=65535): raise ValueError()
        runtime=root._runtime
        prior.scan(b'')
        credentials=(admin_username,admin_password,second_username,second_password,api_key,api_secret)
        if (any(type(x) is not bytes or not 1<=len(x)<=4096 for x in credentials)
                or admin_username!=b'admin' or second_username!=b'b1ops' or b':' in api_key
                or any(c in api_key+api_secret for c in (b'\r',b'\n',b'\x00'))
                or type(retained_topics) not in (list,tuple) or len(retained_topics)!=2
                or len(set(retained_topics))!=2
                or any(type(x) is not bytes or re.fullmatch(rb'b1/retained/[A-Za-z0-9_/-]{1,110}',x) is None for x in retained_topics)):
            raise ValueError()
        basic=b'Basic '+base64.b64encode(api_key+b':'+api_secret)
        runtime.register_bundle({'runtime-login-input':list(credentials)+[api_key+b':'+api_secret,basic]+list(retained_topics)})
        record,owner=_record(provision.file_capability)
        if owner is not provision: raise ValueError()
        old_cid=record['cid']; deadline=time.monotonic()+120
        def timely():
            if time.monotonic()>=deadline: raise ValueError()
        def get(name, authorization):
            timely()
            if name not in PATHS or type(authorization) is not bytes or any(c in authorization for c in (b'\r',b'\n',b'\x00')): raise ValueError()
            config=['url = '+json.dumps('http://127.0.0.1:'+str(port)+'/api/v5'+PATHS[name]),
                'silent','show-error','max-time = 5','connect-timeout = 3','proxy = ""','noproxy = "*"',
                'proto = "=http"','max-redirs = 0','request = "GET"',
                'header = '+json.dumps('Authorization: '+authorization.decode('ascii')),
                'write-out = "\\n%{content_type}\\n%{http_code}"']
            response=provision.runner.podman('exec','-i',expected_container_id,'curl','-q','--config','-',
                input=('\n'.join(config)+'\n').encode(),timeout=10,max_output=HTTP_OUTPUT,check=False)
            timely()
            if response.returncode or type(response.stdout) is not bytes or len(response.stdout)>HTTP_OUTPUT: raise ValueError()
            body,ctype,status=response.stdout.rsplit(b'\n',2)
            if len(body)>MAX_VALUE or ctype.split(b';',1)[0].strip().lower()!=b'application/json' or status!=b'200': raise ValueError()
            return _register_document(runtime,body)
        with quiesce():
            timely(); before=_runtime_identity(provision,expected_container_id)
            if before[3].get('NetworkMode')!='none': raise ValueError()
            transport=curl_login_transport(runner=provision.runner,broker=expected_container_id,
                login_url='http://127.0.0.1:'+str(port)+'/api/v5/login')
            # Register full login response as well as login_registered's JWT/Bearer.
            def observed_login(username,password):
                timely();status,ctype,stream=transport(username,password)
                try: raw=stream.read(MAX_VALUE+1)
                finally: stream.close()
                timely();_register_document(runtime,raw)
                return status,ctype,io.BytesIO(raw)
            admin=login_registered(runtime,observed_login,username=admin_username,password=admin_password)
            second=login_registered(runtime,observed_login,username=second_username,password=second_password)
            if not _rows(second.with_bearer(lambda bearer:get('nodes',bearer)),'nodes'): raise ValueError()
            if not _rows(get('nodes',basic),'nodes'): raise ValueError()
            documents={name:admin.with_bearer(lambda bearer,name=name:get(name,bearer)) for name in PATHS}
            facts=_facts(documents,admin_username,second_username,retained_topics)
            _register_document(runtime,json.dumps(facts,separators=(',',':')).encode())
            if _runtime_identity(provision,expected_container_id)!=before or record['cid']!=old_cid: raise ValueError()
        if _record(provision.file_capability)[1] is not provision or record['cid']!=old_cid: raise ValueError()
        timely();prior.scan(b'')
        from emqx_native_object_integrity import _record_api
        return _record_api(SourceAPIResult(prior,runtime,documents,facts),
                           provision,expected_container_id,before)
    except (KeyboardInterrupt,SystemExit):
        raise PrivateFailure('source-api-cancelled') from None
    except Exception:
        raise PrivateFailure('source-api-refused') from None
