"""Practical owner-side broker observation; no default broker or lab execution.

Reads actual cooked config/provider state and current native table inventory.
Native read transaction/fold is not a checkpoint or historical cold-file replay.
"""
import base64
from contextlib import contextmanager
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

class OwnerCaptureRefused(TargetCaptureUnsupported):
    def __init__(self,phase):
        super().__init__()
        self.phase=phase if phase in CONSUMER_PHASES else 'wire'



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


def _no_refs(value, key=''):
    if type(value) is dict:
        # A file authorizer also has a dependency when its path is implicit.
        # No target file observer is installed in this restricted live profile.
        if value.get('type') in ('file', b'file'):
            unsupported()
        for name, child in value.items():
            _no_refs(child, name)
    elif type(value) in (tuple, list):
        for child in value:
            _no_refs(child, key)
    elif type(value) in (bytes, str):
        text = _text(value)
        if any(marker in text.lower() for marker in ('${', 'env:', 'vault:', 'file:', '://')):
            unsupported()
        if text and (key in ('certfile', 'keyfile', 'cacertfile', 'bootstrap_file', 'init_file')
                     or key.endswith('_file')):
            unsupported()


def _absence_profile(config, provider, mark=lambda _:None):
    """Derive absence from native cooked roots, retaining all full-tree values."""
    mark('roots')
    required = {'connectors', 'bridges', 'actions', 'sources', 'gateway', 'exhook',
        'authentication', 'listeners', 'dashboard', 'api_key', 'cluster', 'rpc', 'node'}
    if type(config) is not dict or not required <= set(config):
        unsupported()
    mark('references')
    _no_refs(config)
    mark('connectors')
    for root in ('connectors', 'bridges', 'actions', 'sources', 'gateway'):
        if type(config[root]) is not dict or config[root]:
            unsupported()
    if config['exhook'].get('servers') != []:
        unsupported()
    mark('cluster')
    if _text(config['cluster']['discovery_strategy']) != 'manual':
        unsupported()
    if _text(config['rpc']['driver']) != 'tcp' or _text(config['node']['dist_proto']) != 'inet_tcp':
        unsupported()
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
    https = dashboard['listeners']['https']
    if type(https) is not dict or type(https.get('bind')) is not int or https['bind'] != 0:
        unsupported()
    # Real native config values, never hand-filled bootstrap acknowledgement.
    bootstrap = {'username': _text(dashboard['default_username']),
                 'password': _text(dashboard['default_password'])}
    inline(bootstrap['username']); inline(bootstrap['password'])
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


def _build_checked(wire, generation, mark):
    mark('wire')
    raw, doc = _read_reply(wire, generation)
    values = Values()
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
    if (type(names) is not list or not names or len(names) > 64
            or not all(native_name(name) for name in names)
            or len(set(names)) != len(names) or 'schema' not in names
            or type(schema) is not list or len(schema) != len(names)):
        unsupported()
    # Native metadata must enumerate the exact same schema/table set.
    if any(type(item) is not tuple or len(item) != 2 for item in schema):
        unsupported()
    if len({_text(item[0]) for item in schema}) != len(names) or {_text(item[0]) for item in schema} != set(names):
        unsupported()
    if type(doc['tables']) is not list or len(doc['tables']) != len(names) - 1:
        unsupported()
    mark('tables')
    tables, row_total = {}, 0
    for table in doc['tables']:
        if (type(table) is not dict or set(table) != {'table', 'record_name', 'attributes', 'row_count', 'rows'}
                or not native_name(table['table']) or table['table'] in tables
                or not native_name(table['record_name']) or type(table['attributes']) is not list
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
    bootstrap, group = _absence_profile(config, providers, mark)
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


def _build(wire,generation):
    phase=['wire']
    def mark(value):
        phase[0]=value if value in CONSUMER_PHASES else 'wire'
    try:
        return _build_checked(wire,generation,mark)
    except Exception:
        raise OwnerCaptureRefused(phase[0]) from None


@contextmanager
def owner_target_readers(*, private_eval, quiesce):
    """Hold owner's actual quiescence context through capture AND consumer use.

    private_eval(expression)->bounded private bytes (same owner emqx eval transport
    used by emqx_broker_export). It MUST suppress diagnostics and bound execution.
    quiesce() is trusted owner code excluding writers/issuance, not a JSON flag.
    Never invoke this on production or an unowned broker. No default transport.
    """
    try:
        with quiesce():
            generation = uuid.uuid4().hex
            # emqx's CLI transport does not preserve a multiline expression in
            # the same form as erl_scan. Only this fixed public source is folded;
            # no user/config text is rewritten or interpolated into code.
            expression = ' '.join(line.strip() for line in EXPRESSION.read_text().splitlines()
                                  if line.strip() and not line.lstrip().startswith('%'))
            expression = expression.replace('__OWNER_NONCE__', generation)
            readers = _build(private_eval(expression), generation)
            yield readers
    except OwnerCaptureRefused:
        raise
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('runtime-private-cancelled') from None
    except Exception:
        raise TargetCaptureUnsupported() from None


def broker_target_readers(*, broker, checked, quiesce):
    """Practical adapter to emqx_broker_export's owner checked transport.

    Creating this context does not execute commands; entering it does. Broker
    identity/authorization and invocation budget are exclusively the owner's.
    """
    return owner_target_readers(private_eval=lambda expression:
        checked('exec', broker, 'emqx', 'eval', expression), quiesce=quiesce)
