"""Practical owner-side broker observation; no default broker or lab execution.

Reads actual cooked config/provider state and current native table inventory.
Native read transaction/fold is not a checkpoint or historical cold-file replay.
"""
import base64
from contextlib import contextmanager, ExitStack
import hashlib
import io
import json
import math
from pathlib import Path
import uuid

from emqx_private_boundary import MAX_VALUES
from emqx_semantic_readers import MAX_OUTPUT, Values, TABLES, _pairs
from emqx_persisted_values import PersistedValues, native_name
from emqx_target_capture import (TargetCaptureUnsupported, bind_target_persisted,
    unsupported)
from emqx_target_snapshots import inline
from emqx_private_boundary import PrivateFailure

EXPRESSION = Path(__file__).with_suffix('.expr')
MAX_WIRE = 4 * ((MAX_OUTPUT + 2) // 3) + 64

CONSUMER_PHASES=frozenset(('wire','config_terms','config_secret_wrappers','provider_terms','schema_terms',
    'inventory','tables','roots','references','connectors','cluster','api_bootstrap',
    'authentication','listeners','dashboard','provider','mqtt_projection','readers'))

CONSUMER_REASONS = frozenset(('private_refused','inventory_names_type','inventory_names_bound',
    'inventory_name_shape','inventory_duplicate_name','inventory_missing_schema',
    'inventory_schema_type','inventory_schema_count','inventory_schema_entry_shape',
    'inventory_schema_name_kind','inventory_schema_duplicate','inventory_schema_binding',
    'inventory_tables_type','inventory_tables_count','inventory_builtin_profile','reference_file_authorizer','reference_template',
    'reference_env','reference_vault','reference_file_uri','reference_url','reference_file_setting',
    'cluster_discovery_missing','cluster_discovery_type','cluster_discovery_unsupported',
    'cluster_rpc_protocol_missing','cluster_rpc_protocol_type','cluster_rpc_protocol_unsupported',
    'cluster_proto_dist_missing','cluster_proto_dist_type','cluster_proto_dist_unsupported',
    'dashboard_root_type','dashboard_listeners_missing','dashboard_listeners_type',
    'dashboard_listener_unknown','dashboard_https_type','dashboard_https_bind_missing',
    'dashboard_https_bind_type','dashboard_https_enabled','dashboard_username_missing',
    'dashboard_username_type','dashboard_username_charlist','dashboard_username_invalid',
    'dashboard_password_missing','dashboard_password_type','dashboard_password_charlist',
    'dashboard_password_invalid'))


# Extracted from hocon_schema:roots(emqx_conf_schema) in pinned IMAGE, metadata
# only. Never derive public enum members from runtime configuration keys.
PINNED_REFERENCE_ROOTS = frozenset(('actions','alarm','api_key','authentication','authorization',
    'auto_subscribe','banned','bridges','broker','cluster','conn_congestion','connectors',
    'crl_cache','dashboard','delayed','durable_sessions','durable_storage','exhook',
    'flapping_detect','force_gc','force_shutdown','gateway','limiter','listeners','log','mqtt',
    'node','overload_protection','plugins','prometheus','psk_authentication','retainer','rewrite',
    'rpc','rule_engine','slow_subs','sources','stats','sys_topics','sysmon','telemetry',
    'topic_metrics','trace','zones'))
REFERENCE_ROOTS = PINNED_REFERENCE_ROOTS | {'other_root'}
MAX_REFERENCE_DIAGNOSTICS = 128
REFERENCE_KEYS = frozenset(('certfile','keyfile','cacertfile','bootstrap_file','init_file','config_files',
    'crash_dump_file','cookie','path','type','job_name','check_origins','origins','responder_url',
    'root','root_dir','install_dir','data_dir','directory','dir','base_dir','work_dir','log_dir','backup_dir',
    'output_dir','file','filename','url','server','servers','endpoint','bucket',
    'other_file_key','other_key'))
REFERENCE_CONTEXTS = frozenset(('ssl_disabled','ssl_enabled','wss_disabled','wss_enabled',
    'ws_disabled','ws_enabled','tcp_disabled','tcp_enabled',
    'dashboard_https_disabled','dashboard_https_enabled','log_console_disabled','log_console_enabled',
    'log_file_disabled','log_file_enabled','root_disabled','root_enabled',
    'durable_storage_builtin_local','durable_storage_builtin_raft',
    'prometheus_push_disabled','prometheus_push_enabled','not_assessed'))


class OwnerCaptureRefused(TargetCaptureUnsupported):
    def __init__(self,phase,reason='private_refused',reference=None,reference_batch=None,reference_batch_truncated=False):
        super().__init__()
        self.phase=phase if type(phase) is str and phase in CONSUMER_PHASES else 'wire'
        self.reason=reason if type(reason) is str and reason in CONSUMER_REASONS else 'private_refused'
        self.reference = None
        if (self.phase == 'references' and type(reference) is dict and set(reference) == {'root','key','context'}
                and type(reference['root']) is str and reference['root'] in REFERENCE_ROOTS
                and type(reference['key']) is str and reference['key'] in REFERENCE_KEYS
                and type(reference['context']) is str and reference['context'] in REFERENCE_CONTEXTS):
            self.reference = dict(reference)
        self.reference_batch = None
        self.reference_batch_truncated = False
        if self.phase == 'references' and type(reference_batch) is list:
            safe = []
            for item in reference_batch[:MAX_REFERENCE_DIAGNOSTICS]:
                if (type(item) is not dict or set(item) != {'reason','root','key','context'}
                        or type(item['reason']) is not str or item['reason'] not in CONSUMER_REASONS
                        or type(item['root']) is not str or item['root'] not in REFERENCE_ROOTS
                        or type(item['key']) is not str or item['key'] not in REFERENCE_KEYS
                        or type(item['context']) is not str or item['context'] not in REFERENCE_CONTEXTS):
                    continue
                safe.append(dict(item))
            self.reference_batch = safe
            self.reference_batch_truncated = reference_batch_truncated is True or len(reference_batch) > MAX_REFERENCE_DIAGNOSTICS



def _decode(term, values, depth=0):
    """Bounded native-data terms only; retain ALL numeric and atom values too."""
    values.tick(depth)
    if type(term) is not dict or set(term) != {'type', 'value'}:
        unsupported()
    kind, value = term['type'], term['value']
    if kind in ('binary', 'atom'):
        if type(value) is not str:
            unsupported()
        if kind == 'binary':
            raw = base64.b64decode(value, validate=True)
            if base64.b64encode(raw).decode() != value:
                unsupported()
        else:
            raw = value.encode('utf-8')
        values.add(raw)
        return raw if kind == 'binary' else value
    if kind == 'integer' and type(value) is int and -(2**63) <= value < 2**63:
        values.add(str(value).encode())
        return value
    if kind == 'float' and type(value) in (int, float) and math.isfinite(value):
        values.add(repr(float(value)).encode())
        return float(value)
    if kind in ('tuple', 'list') and type(value) is list:
        result = [_decode(child, values, depth + 1) for child in value]
        if kind == 'list' and result and all(type(x) is int for x in result):
            if all(0 <= x <= 255 for x in result):
                values.add(bytes(result))
            values.add(''.join(chr(x) for x in result).encode('utf-8'))
        return tuple(result) if kind == 'tuple' else result
    if kind == 'map' and type(value) is list:
        result, seen = {}, set()
        for pair in value:
            if type(pair) is not list or len(pair) != 2:
                unsupported()
            canonical = json.dumps(pair[0], sort_keys=True)
            if canonical in seen:
                unsupported()
            seen.add(canonical)
            key = _decode(pair[0], values, depth + 1)
            if type(key) is bytes:
                key = key.decode('utf-8')
            if type(key) is not str or key in result:
                unsupported()
            result[key] = _decode(pair[1], values, depth + 1)
        return result
    unsupported()


def _text(value):
    if type(value) is bytes:
        return value.decode('utf-8')
    if type(value) is str:
        return value
    unsupported()



def _reference_diagnostic(path,key,config):
    root=path[0] if path and type(path[0]) is str and path[0] in REFERENCE_ROOTS else 'other_root'
    safe_key=key if key in REFERENCE_KEYS else ('other_file_key' if key.endswith('_file') else 'other_key')
    context='not_assessed'
    # These flags are observations for diagnostics only, never reference waivers.
    if root == 'listeners' and len(path) >= 3 and path[1] in ('ssl','wss','ws','tcp'):
        listeners=config.get('listeners',{})
        group=listeners.get(path[1],{}) if type(listeners) is dict else {}
        listener=group.get(path[2]) if type(group) is dict else None
        if type(listener) is dict and listener.get('enable') in ('false','true'):
            context=path[1]+('_disabled' if listener['enable']=='false' else '_enabled')
    elif root == 'dashboard' and path[:3] == ('dashboard','listeners','https'):
        dashboard=config.get('dashboard',{})
        listeners=dashboard.get('listeners',{}) if type(dashboard) is dict else {}
        https=listeners.get('https',{}) if type(listeners) is dict else {}
        bind=https.get('bind') if type(https) is dict else None
        if type(bind) is int:
            context='dashboard_https_disabled' if bind == 0 else 'dashboard_https_enabled'
    elif root == 'log' and len(path) >= 2:
        logs=config.get('log',{})
        logs=logs if type(logs) is dict else {}
        handler=logs.get('console') if path[1]=='console' else None
        kind='console'
        if path[1]=='file' and len(path) >= 3:
            files=logs.get('file',{})
            handler=files.get(path[2]) if type(files) is dict else None
            kind='file'
        if type(handler) is dict and handler.get('enable') in ('false','true'):
            context='log_'+kind+('_disabled' if handler['enable']=='false' else '_enabled')
    if root == 'prometheus' and path[:2] == ('prometheus','push_gateway'):
        prometheus=config.get('prometheus',{})
        gateway=prometheus.get('push_gateway',{}) if type(prometheus) is dict else {}
        if type(gateway) is dict and gateway.get('enable') in ('true','false'):
            context='prometheus_push_enabled' if gateway['enable']=='true' else 'prometheus_push_disabled'
    if context == 'not_assessed' and root in PINNED_REFERENCE_ROOTS:
        subtree=config.get(root,{})
        if type(subtree) is dict and subtree.get('enable') in ('true','false'):
            context='root_enabled' if subtree['enable']=='true' else 'root_disabled'
        elif root == 'durable_storage' and len(path) >= 2:
            store=subtree.get(path[1],{}) if type(subtree) is dict else {}
            backend=store.get('backend') if type(store) is dict else None
            if backend in ('builtin_local',b'builtin_local'):
                context='durable_storage_builtin_local'
            elif backend in ('builtin_raft',b'builtin_raft'):
                context='durable_storage_builtin_raft'
    return {'root':root,'key':safe_key,'context':context}


def _no_refs(value, key='', path=(), config=None, vendor_policy=None):
    if config is None:
        config=value
    from emqx_target_vendor_policy import inactive_default_origins, inactive_default_prometheus_job
    if vendor_policy is not None and vendor_policy.allows_acl_path(config, path, value):
        return
    if inactive_default_origins(config, path, value) or inactive_default_prometheus_job(config,path,value):
        return
    def refuse(reason):
        raise OwnerCaptureRefused('references',reason,_reference_diagnostic(path,key,config))
    if type(value) is dict:
        # File authorizers retain the original implicit-path refusal.
        if value.get('type') in ('file', b'file'):
            if vendor_policy is None or not vendor_policy.acl_source(config, path, value):
                refuse('reference_file_authorizer')
        for name, child in value.items():
            _no_refs(child,name,path+(name,),config,vendor_policy)
    elif type(value) in (tuple, list):
        for index,child in enumerate(value):
            _no_refs(child,key,path+(index,),config,vendor_policy)
    elif type(value) in (bytes, str):
        text = _text(value)
        if vendor_policy is not None and vendor_policy.allows(config, path, text):
            return
        for marker,reason in (('${','reference_template'),('env:','reference_env'),
                ('vault:','reference_vault'),('file:','reference_file_uri'),('://','reference_url')):
            if marker in text.lower():
                refuse(reason)
        if text and (key in ('certfile', 'keyfile', 'cacertfile', 'bootstrap_file', 'init_file')
                     or key.endswith('_file')):
            refuse('reference_file_setting')


def _reference_failure_batch(config, vendor_policy=None):
    """Collect fixed categories only; the original reference guard still rejects.

    No dynamic path component/value is retained. Bound the distinct public set,
    continue traversal on overflow, and report truncation rather than full proof.
    """
    from emqx_target_vendor_policy import inactive_default_origins, inactive_default_prometheus_job
    found, truncated = set(), False
    def record(failure):
        nonlocal truncated
        if failure.reference is None:
            return
        item=(failure.reason, failure.reference['root'], failure.reference['key'],
              failure.reference['context'])
        if item not in found:
            if len(found) < MAX_REFERENCE_DIAGNOSTICS:
                found.add(item)
            else:
                truncated=True
    def walk(value, key='', path=()):
        if inactive_default_origins(config,path,value) or inactive_default_prometheus_job(config,path,value):
            return
        if vendor_policy is not None and vendor_policy.allows_acl_path(config,path,value):
            return
        if type(value) is dict:
            if value.get('type') in ('file',b'file'):
                try: _no_refs(value,key,path,config,vendor_policy)
                except OwnerCaptureRefused as failure: record(failure)
            for name,child in value.items(): walk(child,name,path+(name,))
        elif type(value) in (list,tuple):
            for index,child in enumerate(value): walk(child,key,path+(index,))
        else:
            try: _no_refs(value,key,path,config,vendor_policy)
            except OwnerCaptureRefused as failure: record(failure)
    walk(config)
    return [dict(zip(('reason','root','key','context'),item)) for item in sorted(found)], truncated


def _absence_profile(config, provider, mark=lambda _:None, vendor_policy=None):
    """Derive absence from native cooked roots, retaining all full-tree values."""
    mark('roots')
    required = {'connectors', 'bridges', 'actions', 'sources', 'gateway', 'exhook',
        'authentication', 'listeners', 'dashboard', 'api_key', 'cluster', 'rpc', 'node'}
    if type(config) is not dict or not required <= set(config):
        unsupported()
    mark('references')
    try:
        _no_refs(config, vendor_policy=vendor_policy)
    except OwnerCaptureRefused as failure:
        batch,truncated = _reference_failure_batch(config,vendor_policy)
        raise OwnerCaptureRefused(failure.phase,failure.reason,failure.reference,batch,truncated) from None
    mark('connectors')
    for root in ('connectors', 'bridges', 'actions', 'sources', 'gateway'):
        if type(config[root]) is not dict or config[root]:
            unsupported()
    if config['exhook'].get('servers') != []:
        unsupported()
    mark('cluster')
    def exact_cluster_field(root, key, expected, code):
        section=config[root]
        if type(section) is not dict or key not in section:
            raise OwnerCaptureRefused('cluster',code+'_missing')
        value=section[key]
        if type(value) not in (str,bytes):
            raise OwnerCaptureRefused('cluster',code+'_type')
        if value not in (expected,expected.encode()):
            raise OwnerCaptureRefused('cluster',code+'_unsupported')
    exact_cluster_field('cluster','discovery_strategy','manual','cluster_discovery')
    # Pinned cooked schema uses rpc.protocol; driver is an input alias only.
    exact_cluster_field('rpc','protocol','tcp','cluster_rpc_protocol')
    # Public distribution setting lives under cluster, never node.dist_proto.
    exact_cluster_field('cluster','proto_dist','inet_tcp','cluster_proto_dist')
    mark('api_bootstrap')
    if config['api_key'].get('bootstrap_file') not in (b'', ''):
        unsupported()
    mark('authentication')
    auth = config['authentication']
    if type(auth) is not list or len(auth) != 1 or type(auth[0]) is not dict:
        unsupported()
    if (_text(auth[0]['mechanism']) != 'password_based'
            or _text(auth[0]['backend']) != 'built_in_database'
            or _text(auth[0]['user_id_type']) != 'username'
            or auth[0]['enable'] != 'true'):
        unsupported()
    # Local chains are separate scopes; do not drop them from the global proof.
    mark('listeners')
    listeners = config['listeners']
    if type(listeners) is not dict or set(listeners) != {'tcp', 'ssl', 'ws', 'wss'}:
        unsupported()
    if type(listeners['tcp']) is not dict or not listeners['tcp']:
        unsupported()
    for kind, named in listeners.items():
        if type(named) is not dict:
            unsupported()
        for name, listener in named.items():
            if not native_name(name) or type(listener) is not dict:
                unsupported()
            if listener.get('authentication') not in (None, []):
                unsupported()
            enabled = listener.get('enable')
            if enabled not in ('true', 'false') or (kind != 'tcp' and enabled != 'false'):
                unsupported()
    mark('dashboard')
    dashboard = config['dashboard']
    def dashboard_refuse(code):
        raise OwnerCaptureRefused('dashboard','dashboard_'+code)
    if type(dashboard) is not dict:
        dashboard_refuse('root_type')
    if 'listeners' not in dashboard:
        dashboard_refuse('listeners_missing')
    dashboard_listeners=dashboard['listeners']
    if type(dashboard_listeners) is not dict:
        dashboard_refuse('listeners_type')
    if not set(dashboard_listeners) <= {'http','https'}:
        dashboard_refuse('listener_unknown')
    # Public https_converter(undefined) preserves absence; dashboard startup
    # traverses only present listener-map entries. Do not invent bind=0.
    if 'https' in dashboard_listeners:
        https=dashboard_listeners['https']
        if type(https) is not dict:
            dashboard_refuse('https_type')
        if 'bind' not in https:
            dashboard_refuse('https_bind_missing')
        if type(https['bind']) is not int:
            dashboard_refuse('https_bind_type')
        if https['bind'] != 0:
            dashboard_refuse('https_enabled')
    def credential(key,label):
        if key not in dashboard:
            dashboard_refuse(label+'_missing')
        value=dashboard[key]
        if type(value) not in (str,bytes):
            dashboard_refuse(label+('_charlist' if type(value) is list else '_type'))
        try:
            text=_text(value)
            inline(text)
        except Exception:
            dashboard_refuse(label+'_invalid')
        return text
    # ConfigSecrets already normalized exact known closures to binary; complete
    # metadata/env binding was validated before this projection. No function call.
    bootstrap = {'username': credential('default_username','username'),
                 'password': credential('default_password','password')}
    mark('provider')
    if (type(provider) is not list or len(provider) != 1 or type(provider[0]) is not dict
            or _text(provider[0]['id']) != 'password_based:built_in_database'
            or provider[0]['provider'] != 'emqx_authn_mnesia'
            or provider[0]['enable'] != 'true'
            or provider[0]['state']['user_id_type'] != 'username'):
        unsupported()
    group = provider[0]['state']['user_group']
    group = group if type(group) is bytes else _text(group).encode()
    if not group:
        unsupported()
    return bootstrap, group


def _read_reply(wire, generation):
    if type(wire) is not bytes or len(wire) > MAX_WIRE:
        unsupported()
    wire = wire.strip()
    if not wire.startswith(b'WOOWTARGET:') or not wire.endswith(b':ENDok'):
        unsupported()
    raw = base64.b64decode(wire[11:-6], validate=True)
    if len(raw) > MAX_OUTPUT:
        unsupported()
    doc = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: unsupported())
    base_keys = {'contract', 'version', 'otp_release', 'erts_version', 'generation',
                 'complete', 'config', 'providers', 'schema_metadata', 'table_names', 'tables'}
    if type(doc) is not dict:
        unsupported()
    expected_keys = base_keys if doc.get('contract') == 'emqx-owner-live-target-v1' else base_keys | {'config_secret_wrappers'}
    if (set(doc) != expected_keys
            or doc['contract'] not in ('emqx-owner-live-target-v1', 'emqx-owner-live-target-v2')
            or doc['version'] != '5.8.9' or doc['otp_release'] != '26'
            or doc['erts_version'] != '14.2.5.11' or doc['generation'] != generation
            or doc['complete'] is not True):
        unsupported()
    return raw, doc


def _config_secret_metadata(config, metadata):
    """v2 config-only provenance, decoded into private Values before validation.

    This is data from the fixed native producer; it is never executable code.
    Paths bind each complete binary environment to its normalized cooked value.
    """
    if type(metadata) is not list or len(metadata) > 128:
        unsupported()
    seen = set()
    fixed = {'module': 'emqx_secret', 'name': '-wrap/1-fun-0-', 'arity': 0,
             'type': 'local', 'index': 0, 'new_index': 0, 'uniq': 85191762,
             'new_uniq': b'A27D8A4F73E7689F1F8B78E0DCB7C91B'}
    for item in metadata:
        if (type(item) is not dict or set(item) != set(fixed) | {'path', 'env'}
                or any(type(item[k]) is not type(v) or item[k] != v for k,v in fixed.items())
                or type(item['env']) is not list or len(item['env']) != 1
                or type(item['env'][0]) is not bytes or len(item['env'][0]) > 65536
                or type(item['path']) is not list or len(item['path']) > 16):
            unsupported()
        value = config
        path = []
        for step in item['path']:
            if type(step) is not tuple or len(step) != 2:
                unsupported()
            kind, key = step
            if kind == 'map' and type(value) is dict and type(key) in (str, bytes):
                key = _text(key)
                if key not in value:
                    unsupported()
            elif (kind in ('list', 'tuple') and type(value) is (list if kind == 'list' else tuple)
                  and type(key) is int and 0 <= key < len(value)):
                pass
            else:
                unsupported()
            path.append((kind,key))
            value = value[key]
        binding = tuple(path)
        if binding in seen or type(value) is not bytes or value != item['env'][0]:
            unsupported()
        seen.add(binding)




# Exact builtin declaration in pinned MRIA 0.8.18. LIVE producer only: this
# exception must never reach generic private_table callbacks/filename validators.
_LIVE_SYNC_TABLE = '$mria_rlog_sync'
_LIVE_SYNC_ATTRIBUTES = ['reply_to','shard','extra']


def _live_table_name(name):
    return native_name(name) or (type(name) is str and name == _LIVE_SYNC_TABLE)


def _validate_sync_builtin(schema,tables):
    def refuse():
        raise OwnerCaptureRefused('inventory','inventory_builtin_profile')
    records=[t for t in tables if type(t) is dict and t.get('table') == _LIVE_SYNC_TABLE]
    if len(records) != 1:
        refuse()
    table=records[0]
    if (table.get('record_name') != _LIVE_SYNC_TABLE or table.get('attributes') != _LIVE_SYNC_ATTRIBUTES
            or type(table.get('row_count')) is not int or table['row_count'] != 0
            or table.get('rows') != []):
        refuse()
    properties=next(props for name,props in schema if _text(name) == _LIVE_SYNC_TABLE)
    if (type(properties) is not list or any(type(p) is not tuple or len(p) != 2 or
            type(p[0]) is not str for p in properties)):
        refuse()
    props=dict(properties)
    if len(props) != len(properties):
        refuse()
    if (props.get('name') != _LIVE_SYNC_TABLE or props.get('record_name') != _LIVE_SYNC_TABLE
            or props.get('attributes') != _LIVE_SYNC_ATTRIBUTES
            or any(props.get(k) != [] for k in ('ram_copies','disc_copies','disc_only_copies'))
            or type(props.get('null_copies')) is not list or not props['null_copies']
            or not all(type(node) is str and 0 < len(node) <= 255 for node in props['null_copies'])):
        refuse()


def _validate_inventory(names,schema,tables):
    """Same strict inventory contract, split into bounded value-free reasons."""
    def refuse(reason):
        raise OwnerCaptureRefused('inventory',reason)
    if type(names) is not list:
        refuse('inventory_names_type')
    if not names or len(names) > 64:
        refuse('inventory_names_bound')
    if not all(_live_table_name(name) for name in names):
        refuse('inventory_name_shape')
    if len(set(names)) != len(names):
        refuse('inventory_duplicate_name')
    if 'schema' not in names:
        refuse('inventory_missing_schema')
    if type(schema) is not list:
        refuse('inventory_schema_type')
    if len(schema) != len(names):
        refuse('inventory_schema_count')
    if any(type(item) is not tuple or len(item) != 2 for item in schema):
        refuse('inventory_schema_entry_shape')
    try:
        schema_names=[_text(item[0]) for item in schema]
    except (TargetCaptureUnsupported,UnicodeError):
        refuse('inventory_schema_name_kind')
    if len(set(schema_names)) != len(names):
        refuse('inventory_schema_duplicate')
    if set(schema_names) != set(names):
        refuse('inventory_schema_binding')
    if type(tables) is not list:
        refuse('inventory_tables_type')
    if len(tables) != len(names)-1:
        refuse('inventory_tables_count')
    if _LIVE_SYNC_TABLE in names:
        _validate_sync_builtin(schema,tables)


def _build_checked(wire, generation, mark, vendor_policy=None, private_values=None):
    mark('wire')
    raw, doc = _read_reply(wire, generation)
    values = private_values if private_values is not None else Values()
    mark('config_terms')
    config = _decode(doc['config'], values)
    mark('config_secret_wrappers')
    if doc['contract'] == 'emqx-owner-live-target-v2':
        _config_secret_metadata(config, _decode(doc['config_secret_wrappers'], values))
    mark('provider_terms')
    providers = _decode(doc['providers'], values)
    mark('schema_terms')
    schema = _decode(doc['schema_metadata'], values)
    mark('inventory')
    names = doc['table_names']
    _validate_inventory(names,schema,doc['tables'])
    mark('tables')
    tables, row_total = {}, 0
    for table in doc['tables']:
        if (type(table) is not dict or set(table) != {'table', 'record_name', 'attributes', 'row_count', 'rows'}
                or not _live_table_name(table['table']) or table['table'] in tables
                or not (table['record_name'] == _LIVE_SYNC_TABLE if table['table'] == _LIVE_SYNC_TABLE
                        else native_name(table['record_name'])) or type(table['attributes']) is not list
                or not table['attributes'] or not all(native_name(a) for a in table['attributes'])
                or len(set(table['attributes'])) != len(table['attributes'])
                or type(table['rows']) is not list or type(table['row_count']) is not int
                or table['row_count'] != len(table['rows'])):
            unsupported()
        row_total += len(table['rows'])
        if row_total > MAX_VALUES:
            unsupported()
        for row in table['rows']:
            if (type(row) is not dict or row.get('type') != 'tuple'
                    or type(row.get('value')) is not list
                    or len(row['value']) != len(table['attributes']) + 1
                    or row['value'][0] != {'type': 'atom', 'value': table['record_name']}):
                unsupported()
            _decode(row, values)
        tables[table['table']] = table
    if set(tables) != set(names) - {'schema'}:
        unsupported()
    bootstrap, group = _absence_profile(config, providers, mark, vendor_policy)
    mark('mqtt_projection')
    for name in ('emqx_authn_mnesia', 'emqx_app'):
        record, attrs = TABLES[name]
        if tables[name]['record_name'] != record or tables[name]['attributes'] != list(attrs):
            unsupported()
    if tables['emqx_app']['rows']:
        unsupported()  # API hashes never substitute for plaintext credentials.
    # Project actual live native rows under the existing exact MQTT field rules.
    # This is a live observation, never labeled as a checkpoint export.
    from emqx_target_capture import _binary, _group_matches
    mqtt = []
    for row in tables['emqx_authn_mnesia']['rows']:
        _, identity, hashed, salt, superuser = row['value']
        if (identity['type'] != 'tuple' or len(identity['value']) != 2
                or not _group_matches(identity['value'][0], group)
                or superuser not in ({'type': 'atom', 'value': 'true'}, {'type': 'atom', 'value': 'false'})):
            unsupported()
        record = {'username': _binary(identity['value'][1]).decode(),
                  'password_hash': _binary(hashed).decode(), 'salt': _binary(salt).decode()}
        for field, text in record.items():
            inline(text, empty=field == 'salt')
        if any(existing['username'] == record['username'] for existing in mqtt):
            unsupported()
        mqtt.append(record)
    # This is a live receipt digest, NOT emqx-mnesia-checkpoint-json-v1.
    bindings = {name: {'input_sha256': hashlib.sha256(raw).hexdigest(), 'input_bytes': len(raw)}
                for name in names}
    companion = PersistedValues(generation, 'target', bindings, values.values)
    mark('readers')
    docs = {name: {'schema': 1, 'complete': True, 'records': []}
            for name in ('mqtt-auth', 'api-keys', 'connectors', 'tls', 'target-bootstrap')}
    docs['mqtt-auth']['records'] = mqtt
    docs['target-bootstrap']['records'] = [bootstrap]
    readers = {name: (lambda data=json.dumps(document).encode(): io.BytesIO(data))
               for name, document in docs.items()}
    return bind_target_persisted(readers, persisted_values=companion, generation=generation)


def _build(wire,generation,vendor_policy=None,private_values=None):
    phase=['wire']
    def mark(value):
        phase[0]=value if value in CONSUMER_PHASES else 'wire'
    try:
        return _build_checked(wire,generation,mark,vendor_policy,private_values)
    except OwnerCaptureRefused:
        raise
    except Exception:
        raise OwnerCaptureRefused(phase[0]) from None


@contextmanager
def owner_target_readers(*, private_eval, quiesce, vendor_observer=None):
    """Hold owner's actual quiescence context through capture AND consumer use.

    private_eval(expression)->bounded private bytes (same owner emqx eval transport
    used by emqx_broker_export). It MUST suppress diagnostics and bound execution.
    quiesce() is trusted owner code excluding writers/issuance, not a JSON flag.
    Never invoke this on production or an unowned broker. No default transport.
    """
    try:
        with quiesce(), ExitStack() as lease:
            generation = uuid.uuid4().hex
            # emqx's CLI transport does not preserve a multiline expression in
            # the same form as erl_scan. Only this fixed public source is folded;
            # no user/config text is rewritten or interpolated into code.
            expression = ' '.join(line.strip() for line in EXPRESSION.read_text().splitlines()
                                  if line.strip() and not line.lstrip().startswith('%'))
            expression = expression.replace('__OWNER_NONCE__', generation)
            values, policy = Values(), None
            if vendor_observer is not None:
                from emqx_target_vendor_policy import DisabledVendorTLS
                policy = DisabledVendorTLS(lease.enter_context(
                    vendor_observer(generation=generation, private_values=values)))
            readers = _build(private_eval(expression), generation, policy, values)
            yield readers
    except OwnerCaptureRefused:
        raise
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('runtime-private-cancelled') from None
    except Exception:
        raise TargetCaptureUnsupported() from None


def broker_target_readers(*, broker, checked, quiesce, vendor_observer=None):
    """Practical adapter to emqx_broker_export's owner checked transport.

    Creating this context does not execute commands; entering it does. Broker
    identity/authorization and invocation budget are exclusively the owner's.
    """
    return owner_target_readers(private_eval=lambda expression:
        checked('exec', broker, 'emqx', 'eval', expression), quiesce=quiesce, vendor_observer=vendor_observer)
