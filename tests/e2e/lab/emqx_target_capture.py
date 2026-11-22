"""Restricted private target producer; no IO/default native exporter installed.

Uses the existing semantic exporter contract unchanged. This module does not
implement Mnesia traversal and does not attest whole-target inventory coverage.
Supports MQTT projection and a restricted owner-observed absence profile.
"""
import base64
import io
import json

from emqx_private_boundary import PrivateFailure
from emqx_runtime_credentials import TARGET_CATEGORIES, parse_json
from emqx_semantic_readers import read_mnesia
from emqx_target_snapshots import inline


class TargetCaptureUnsupported(PrivateFailure):
    def __init__(self):
        super().__init__('target-capture-unsupported')


def unsupported():
    raise TargetCaptureUnsupported() from None


def _binary(term):
    if not isinstance(term, dict) or set(term) != {'type', 'value'} or term['type'] != 'binary':
        unsupported()
    return base64.b64decode(term['value'], validate=True)


def _group_matches(term, expected):
    # Live 5.8.9 global chains use atom groups. Compare the already validated
    # native atom NAME to an independently owner-verified provider group; no
    # atom creation, row-derived expected group, coercion of other types or filter.
    if type(term) is dict and set(term) == {'type', 'value'} and term['type'] == 'atom':
        if type(term['value']) is not str:
            unsupported()
        return term['value'].encode('utf-8') == expected
    return _binary(term) == expected


def mqtt_password_table(raw, *, exporter, username_group):
    """Trusted pinned native exporter(raw) -> complete typed table JSON bytes.

    username_group is owner-verified native authentication group bytes, never
    inferred from data. Native binary or UTF-8 atom group names must exactly
    match it; every row must belong to that group. Client-id auth,
    SCRAM, other tables and non-UTF8 binary hashes remain unsupported. Empty
    salt must be an actual exported empty binary, never a missing-field default.
    This is table coverage only, NOT discovery of every authenticator/listener.
    """
    try:
        if type(username_group) is not bytes or not username_group or not callable(exporter):
            unsupported()
        # Execute exactly once. Existing validator checks digest, version, schema,
        # all typed terms and bounds before any projection becomes available.
        encoded = None
        def once(source):
            nonlocal encoded
            encoded = exporter(source)
            return encoded
        read_mnesia(raw, 'emqx_authn_mnesia', once)
        doc = parse_json(encoded)
        records, seen = [], set()
        for row in doc['rows']:
            _, identity, password_hash, salt, superuser = row['value']
            if (identity['type'] != 'tuple' or len(identity['value']) != 2
                    or not _group_matches(identity['value'][0], username_group)
                    or superuser not in ({'type': 'atom', 'value': 'true'},
                                         {'type': 'atom', 'value': 'false'})):
                unsupported()
            username = _binary(identity['value'][1]).decode('utf-8')
            if username in seen:
                unsupported()
            seen.add(username)
            record = {'username': username,
                      'password_hash': _binary(password_hash).decode('utf-8'),
                      'salt': _binary(salt).decode('utf-8')}
            for field, value in record.items():
                inline(value, empty=field == 'salt')
            records.append(record)
        result = json.dumps({'schema': 1, 'complete': True, 'records': records}).encode()
        # Same bound/duplicate policy as exact target readers.
        parse_json(result)
        return result
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('runtime-private-cancelled') from None
    except Exception:
        raise TargetCaptureUnsupported() from None


def exact_target_readers(raw, *, exporter, username_group):
    """Return exact category callables, with explicit unsupported category gates.

    register_target_snapshots remains atomic: unsupported api-keys, connectors,
    tls or bootstrap prevents ANY target registration. No empty placeholders.
    Mnesia emqx_app cannot supply plaintext api_secret. An eventual creation
    credential producer also needs full inventory and runtime issuance coverage.
    """
    def mqtt():
        return io.BytesIO(mqtt_password_table(
            raw, exporter=exporter, username_group=username_group))
    return {category: mqtt if category == 'mqtt-auth' else unsupported
            for category in TARGET_CATEGORIES}


def mqtt_table_reader(raw, *, exporter, username_group):
    """Private single-category reader for owner integration; NOT full acceptance.

    Caller must separately establish whole-target inventory and install remaining
    producers before register_target_snapshots/login_preflight can be used.
    The returned stream is consumed/closed by the existing reader contract.
    """
    encoded = mqtt_password_table(raw, exporter=exporter, username_group=username_group)
    return lambda: io.BytesIO(encoded)


# Narrow, explicit effective-config profile. Unknown roots are not silently
# assumed irrelevant. Broader EMQX installations need a reviewed profile.
EFFECTIVE_ROOTS = frozenset(('authentication', 'connectors', 'bridges', 'listeners',
    'dashboard', 'gateway', 'exhook', 'cluster', 'rpc', 'node', 'api_key'))


class ObservedTargetReaders(dict):
    """Exact mapping carrying the mandatory persisted scanner into preflight."""
    def __repr__(self):
        return '<EMQX private observed target readers>'


def bind_target_persisted(readers, *, persisted_values, generation):
    """Attach full native coverage to already reviewed exact owner readers.

    Independent of the narrow effective-config absence profile. It validates the
    existing five-category contract; provenance of those business projections
    remains the trusted owner's responsibility. Does not convert existing API
    hashes or claim that historical superset terms represent final live records.
    Keep this mapping intact when passing it to login_preflight.
    """
    from emqx_persisted_values import PersistedValues
    from emqx_runtime_credentials import RuntimeRegistry
    from emqx_target_snapshots import register_target_snapshots
    try:
        if (not isinstance(persisted_values, PersistedValues)
                or persisted_values.scope != 'target'
                or persisted_values.generation != generation):
            unsupported()
        if (type(readers) is not dict or set(readers) != TARGET_CATEGORIES
                or not all(callable(reader) for reader in readers.values())):
            unsupported()
        from emqx_runtime_credentials import read_bounded
        frozen = {}
        for category, reader in readers.items():
            stream = reader()
            try:
                raw = read_bounded(stream)
                if hasattr(stream, 'finish'):
                    stream.finish()
            finally:
                stream.close()
            frozen[category] = lambda data=raw: io.BytesIO(data)
        register_target_snapshots(RuntimeRegistry(), frozen)
        result = ObservedTargetReaders(frozen)
        result.persisted_values = persisted_values
        result.generation = generation
        return result
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('runtime-private-cancelled') from None
    except Exception:
        raise TargetCaptureUnsupported() from None


def observed_target_readers(*, private_capture, exporter, username_group,
                            persisted_values=None):
    """Capture one owner-quiesced target generation and build all exact readers.

    private_capture is TRUSTED owner code, not an archive-selected callback. It
    returns a bounded JSON byte stream; no IO/transport defaults are installed.
    Its contract attests full effective config (defaults/overrides resolved),
    complete bootstrap input observation, and same-generation native checkpoints.
    It must enforce its own runtime limits and serialize mutations/issuance until
    registration completes. Assertion fields do not authenticate untrusted code.
    Native checkpoint JSON is validated by the unchanged semantic reader.
    """
    try:
        stream = private_capture()
        try:
            from emqx_runtime_credentials import read_bounded
            capture = parse_json(read_bounded(stream))
        finally:
            stream.close()
        if (type(capture) is not dict or set(capture) != {
                'contract', 'version', 'schema', 'complete', 'generation',
                'quiesced', 'references', 'effective_config', 'mqtt_checkpoint',
                'app_checkpoint', 'bootstrap', 'persistent_inventory'}
                or capture['contract'] != 'emqx-target-observation-v1'
                or capture['version'] != '5.8.9' or type(capture['schema']) is not int
                or capture['schema'] != 1 or capture['complete'] is not True
                or capture['quiesced'] is not True or capture['references'] != []
                or type(capture['generation']) is not str or not capture['generation']):
            unsupported()
        from emqx_persisted_values import PersistedValues
        inventory = capture['persistent_inventory']
        if (not isinstance(persisted_values, PersistedValues)
                or persisted_values.scope != 'target'
                or persisted_values.generation != capture['generation']
                or type(inventory) is not dict
                or set(inventory) != {'complete', 'generation', 'tables'}
                or inventory['complete'] is not True
                or inventory['generation'] != capture['generation']
                or type(inventory['tables']) is not list
                or len(inventory['tables']) != len(set(inventory['tables']))
                or set(inventory['tables']) != persisted_values.tables
                or not {'emqx_authn_mnesia', 'emqx_app'} <= persisted_values.tables):
            unsupported()
        config = capture['effective_config']
        if type(config) is not dict or set(config) != {'root_presence', 'document'}:
            unsupported()
        roots = config['root_presence']
        document = config['document']
        if (type(roots) is not list or len(roots) != len(EFFECTIVE_ROOTS)
                or set(roots) != EFFECTIVE_ROOTS or type(document) is not dict
                or set(document) != EFFECTIVE_ROOTS):
            unsupported()
        # Exact restricted absence profile, not truthiness: missing/null/false
        # and hidden extra keys do not count as empty/disabled.
        for root in ('connectors', 'bridges', 'gateway'):
            if type(document[root]) is not dict or document[root] != {}:
                unsupported()
        if document['exhook'] != {'servers': []}:
            unsupported()
        if document['cluster'] != {'discovery_strategy': 'manual'}:
            unsupported()
        if document['rpc'] != {'driver': 'tcp'}:
            unsupported()
        if document['node'] != {'dist_proto': 'inet_tcp'}:
            unsupported()
        if document['api_key'] != {'bootstrap_file': ''}:
            unsupported()
        if document['authentication'] != [{'mechanism': 'password_based',
                'backend': 'built_in_database', 'user_id_type': 'username'}]:
            unsupported()
        listeners = document['listeners']
        if (type(listeners) is not dict or set(listeners) != {'tcp', 'ssl', 'ws', 'wss'}
                or any(listeners[name] != {} for name in ('ssl', 'ws', 'wss'))
                or type(listeners['tcp']) is not dict or set(listeners['tcp']) != {'default'}):
            unsupported()
        for listener in listeners['tcp'].values():
            if (type(listener) is not dict or set(listener) != {'enable', 'bind'}
                    or listener['enable'] is not True or type(listener['bind']) is not int
                    or not 1 <= listener['bind'] <= 65535):
                unsupported()
        # HTTPS disabled must be explicit and contain no cert/key references.
        dashboard = document['dashboard']
        if (type(dashboard) is not dict or set(dashboard) != {'listeners'}
                or json.dumps(dashboard['listeners'], sort_keys=True) != json.dumps(
                    {'http': {'bind': 18083}, 'https': {'bind': 0}}, sort_keys=True)):
            unsupported()
        def checkpoint(name):
            value = capture[name]
            if type(value) is not str:
                unsupported()
            decoded = base64.b64decode(value, validate=True)
            if base64.b64encode(decoded).decode('ascii') != value:
                unsupported()
            return decoded
        app = checkpoint('app_checkpoint')
        mqtt_raw = checkpoint('mqtt_checkpoint')
        if (not persisted_values.matches('emqx_app', app)
                or not persisted_values.matches('emqx_authn_mnesia', mqtt_raw)):
            unsupported()
        encoded = None
        def app_export(source):
            nonlocal encoded
            encoded = exporter(source)
            return encoded
        read_mnesia(app, 'emqx_app', app_export)
        if parse_json(encoded)['rows'] != []:
            # Hashes are not plaintext secrets, even for disabled/expired keys.
            unsupported()
        bootstrap = capture['bootstrap']
        if (type(bootstrap) is not dict or set(bootstrap) != {
                'generation', 'complete', 'producer', 'records'}
                or bootstrap['generation'] != capture['generation']
                or bootstrap['complete'] is not True
                or bootstrap['producer'] != 'private-bootstrap-input-v1'
                or type(bootstrap['records']) is not list or not bootstrap['records']):
            unsupported()
        documents = {category: {'schema': 1, 'complete': True, 'records': []}
                     for category in TARGET_CATEGORIES}
        documents['mqtt-auth'] = parse_json(mqtt_password_table(
            mqtt_raw, exporter=exporter, username_group=username_group))
        documents['target-bootstrap']['records'] = bootstrap['records']
        payloads = {category: json.dumps(doc).encode() for category, doc in documents.items()}
        readers = {category: (lambda data=data: io.BytesIO(data))
                   for category, data in payloads.items()}
        # Validate every output/field before exposing any reader. Use the original
        # atomic registry; never relax its secret/reference/size rules.
        return bind_target_persisted(readers, persisted_values=persisted_values,
                                     generation=capture['generation'])
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('runtime-private-cancelled') from None
    except Exception:
        raise TargetCaptureUnsupported() from None
