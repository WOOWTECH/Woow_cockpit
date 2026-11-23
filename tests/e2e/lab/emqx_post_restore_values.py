"""Supplemental native VALUE-ONLY capture of an owned post-operation runtime.

Not the initial target producer: no absence profile, API plaintext projection,
five-category assertion, file/reference authorization, build or replay capability.
Config reference strings are retained as data, never resolved/executed. Uses the
unchanged fixed native producer (full config/providers/schema/table EOF/stability)
and its strict wire, typed-term and inventory validators. Unknown terms refuse.

The prior complete CombinedRegistry, including dynamic runtime tokens, remains
mandatory. Returned scanners retain historical native values for at most four
post-operation generations. Caller must collect after the last API/client write
in each phase and use the returned scanner before publishing anything.
"""
import hashlib
import json
import re
import uuid

from emqx_adapter_owner import OwnerProvision, LabOwnerRunner
from emqx_native_runtime import IMAGE
from emqx_owner_fixture_files import _record, _secret_mapping, BASE, ACL, BOOTSTRAP, LIMIT
from emqx_owner_target import (EXPRESSION, MAX_WIRE, _read_reply, _decode,
    _config_secret_metadata, _validate_inventory, _live_table_name, _LIVE_SYNC_TABLE)
from emqx_persisted_values import PersistedValues, native_name
from emqx_private_boundary import PrivateFailure, MAX_VALUES
from emqx_runtime_workflow import CombinedRegistry
from emqx_semantic_readers import (Values, _pairs, MAX_NODES, MAX_OUTPUT,
    MAX_VALUES as MAX_SEMANTIC_VALUES)

MAX_CAPTURES = 4
# Fixed collector stages only; the private failure text never escapes.


class PostCaptureRefused(PrivateFailure):
    def __init__(self, stage):
        self.stage = stage if stage in CAPTURE_STAGES else 'input'
        super().__init__('post-native-values-refused')


class PostRestoreValues:
    """Historical supplemental scanner only, never a target/file capability."""
    def __init__(self, previous, persisted, generations, preflight_generations):
        self._previous, self._persisted = previous, persisted
        self._generations, self._preflight_generations = tuple(generations), tuple(preflight_generations)

    def __repr__(self):
        return '<EMQX private post-operation native values>'

    def scan(self, payload):
        self._previous.scan(payload)
        self._persisted.scan(payload)


# Fixed decode sub-steps; *_nodes/_values/_bytes name which shared Values budget
# (MAX_NODES/MAX_VALUES/MAX_OUTPUT) was exhausted, *_other any other refusal.
DECODE_STEPS = ('reply', 'inventory', 'table_shape', 'rows_rowcount', 'table_set',
                *(step + '_' + budget for step in ('config', 'secrets', 'providers', 'schema', 'rows')
                  for budget in ('nodes', 'values', 'bytes', 'other')))


CAPTURE_STAGES = ('input', 'limit', 'quiesce_enter', 'identity_before', 'exec', 'decode',
                  *('decode_' + step for step in DECODE_STEPS),
                  'identity_after', 'prior_scan', 'quiesce_exit', 'record', 'record_native')


class NativeDecodeRefused(ValueError):
    def __init__(self, step):
        self.step = step if step in DECODE_STEPS else 'reply'
        super().__init__('native-decode-refused')


def _budget(values):
    if values._nodes > MAX_NODES:
        return 'nodes'
    if len(values._values) >= MAX_SEMANTIC_VALUES:
        return 'values'
    if values._total > MAX_OUTPUT:
        return 'bytes'
    return 'other'


def _native_values(wire, generation):
    values = Values()
    step = 'reply'
    try:
        raw, doc = _read_reply(wire, generation)
        step = 'config'
        config = _decode(doc['config'], values)
        step = 'secrets'
        if doc['contract'] == 'emqx-owner-live-target-v2':
            _config_secret_metadata(config, _decode(doc['config_secret_wrappers'], values))
        step = 'providers'
        _decode(doc['providers'], values)
        step = 'schema'
        schema = _decode(doc['schema_metadata'], values)
        names = doc['table_names']
        step = 'inventory'
        _validate_inventory(names, schema, doc['tables'])
        tables, total = set(), 0
        for table in doc['tables']:
            step = 'table_shape'
            if (type(table) is not dict or set(table) != {'table','record_name','attributes','row_count','rows'}
                    or not _live_table_name(table['table']) or table['table'] in tables
                    or not (table['record_name'] == _LIVE_SYNC_TABLE if table['table'] == _LIVE_SYNC_TABLE
                            else native_name(table['record_name']))
                    or type(table['attributes']) is not list or not table['attributes']
                    or not all(native_name(x) for x in table['attributes'])
                    or len(set(table['attributes'])) != len(table['attributes'])
                    or type(table['rows']) is not list or type(table['row_count']) is not int
                    or table['row_count'] != len(table['rows'])):
                raise ValueError()
            total += len(table['rows'])
            if total > MAX_VALUES:
                step = 'rows_rowcount'
                raise ValueError()
            step = 'rows'
            for row in table['rows']:
                if (type(row) is not dict or row.get('type') != 'tuple'
                        or type(row.get('value')) is not list
                        or len(row['value']) != len(table['attributes']) + 1
                        or row['value'][0] != {'type':'atom','value':table['record_name']}):
                    raise ValueError()
                _decode(row, values)  # All tables/rows, no business projection or filtering.
            tables.add(table['table'])
        step = 'table_set'
        if tables != set(names) - {'schema'}:
            raise ValueError()
    except Exception:
        if step in ('config', 'secrets', 'providers', 'schema', 'rows'):
            step = step + '_' + _budget(values)
        raise NativeDecodeRefused(step) from None
    bindings = {name: {'input_sha256':hashlib.sha256(raw).hexdigest(), 'input_bytes':len(raw)} for name in names}
    return PersistedValues(generation, 'target', bindings, values.values)


def _runtime_identity(provision, cid):
    """Independent runtime ownership proof; NEVER resets/rebinds FixtureFiles CID.

    Only inspect the caller's exact new CID through its actual issued lab runner.
    Check same name/node/image/volume/config/secret declarations. This authorizes
    no file read: original file capability and composite policy remain unchanged.
    """
    runner, fixture = provision.runner, provision.fixture
    result = runner.podman('container', 'inspect', cid, timeout=5, max_output=LIMIT, check=False)
    raw = result.stdout
    if result.returncode or type(raw) is not bytes or not 0 < len(raw) <= LIMIT:
        raise ValueError()
    def invalid(_):
        raise ValueError()
    rows = json.loads(raw, object_pairs_hook=_pairs, parse_constant=invalid)
    if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict:
        raise ValueError()
    doc = rows[0]
    fixture.validate_inspection(doc)
    env = doc['Config']['Env']
    if (doc.get('Id') != cid or type(doc.get('Image')) is not str or
            doc['Image'] not in (IMAGE, IMAGE.removeprefix('sha256:')) or
            doc['State']['Running'] is not True or doc['HostConfig']['PidsLimit'] != 512 or
            doc['HostConfig']['LogConfig']['Type'] != 'none' or type(env) is not list or
            any(type(x) is not str for x in env) or
            [x for x in env if x.split('=',1)[0] == 'EMQX_NODE__NAME'] != ['EMQX_NODE__NAME=emqx@127.0.0.1']):
        raise ValueError()
    _secret_mapping(doc['Config'].get('CreateCommand'), fixture)
    mounts = doc['Mounts']
    allowed = {BASE, ACL, '/opt/emqx/data', '/opt/emqx/log'}
    if (type(mounts) is not list or len(mounts) != 4 or
            any(type(x) is not dict or x.get('Destination') not in allowed for x in mounts) or
            len({x['Destination'] for x in mounts}) != 4):
        raise ValueError()
    for name, destination in zip(fixture.volumes, ('/opt/emqx/data','/opt/emqx/log')):
        mount = next(x for x in mounts if x['Destination'] == destination)
        if mount['Type'] != 'volume' or mount.get('Name') != name or mount.get('RW') is not True:
            raise ValueError()
    expected = {BASE: runner.home+'/.config/'+fixture.prefix+'/base.hocon',
                ACL: runner.home+'/.config/'+fixture.prefix+'/acl.conf'}
    for path in (BASE, ACL, BOOTSTRAP):
        matches = []
        for mount in doc['Mounts']:
            dest = mount['Destination']
            if (type(dest) is not str or not dest.startswith('/') or
                    (dest != '/' and any(x in ('','.','..') for x in dest[1:].split('/')))):
                raise ValueError()
            if dest == '/' or dest == path or path.startswith(dest+'/'):
                matches.append(mount)
        if path == BOOTSTRAP:
            if matches:
                raise ValueError()
        elif (len(matches) != 1 or matches[0]['Destination'] != path or matches[0]['Type'] != 'bind'
                or matches[0]['RW'] is not False or matches[0]['Source'] != expected[path]):
            raise ValueError()
    return doc['Id'], IMAGE, doc['Config'], doc['HostConfig'], doc['Mounts']


def collect_post_restore_values(*, prior_registry, provision, expected_container_id, quiesce):
    """Bounded value-only capture through the actual issued owner runner.

    No transport/credential/profile defaults. CID is explicit and reverified
    before/after INSIDE caller's actual exclusion lease. Producer exec targets CID,
    not a name that can race a restart. Inspect:5s/64KiB; native exec:30s/MAX_WIRE
    (decoded native limit1MiB, depth16,8192 nodes,4096 values/rows). OwnerRunner
    enforces bounded private subprocess output/timeouts. Cleanup must succeed
    before return. The old file token's bound CID must remain untouched.
    """
    stage = 'input'
    try:
        if (type(prior_registry) not in (CombinedRegistry, PostRestoreValues)
                or type(provision) is not OwnerProvision or not isinstance(provision.runner, LabOwnerRunner)
                or provision.runner.owner != 'appowner' or not callable(quiesce)
                or type(expected_container_id) is not str or re.fullmatch('[0-9a-f]{64}', expected_container_id) is None):
            raise ValueError()
        record, owner = _record(provision.file_capability)
        if owner is not provision:
            raise ValueError()
        old_cid = record['cid']
        generations = prior_registry._generations if type(prior_registry) is PostRestoreValues else ()
        previous = (prior_registry._preflight_generations if type(prior_registry) is PostRestoreValues else tuple(
            p.generation for p in prior_registry._persisted if isinstance(p, PersistedValues) and p.scope == 'target'))
        stage = 'limit'
        if len(generations) >= MAX_CAPTURES:
            raise ValueError()
        stage = 'prior_scan'
        prior_registry.scan(b'')
        result = None
        stage = 'quiesce_enter'
        with quiesce():
            stage = 'identity_before'
            before = _runtime_identity(provision, expected_container_id)
            generation = uuid.uuid4().hex
            if generation in generations + previous:
                raise ValueError()
            expression = ' '.join(line.strip() for line in EXPRESSION.read_text().splitlines()
                                  if line.strip() and not line.lstrip().startswith('%'))
            expression = expression.replace('__OWNER_NONCE__', generation)
            stage = 'exec'
            output = provision.runner.podman('exec', expected_container_id, 'emqx', 'eval', expression,
                timeout=30, max_output=MAX_WIRE, check=False)
            if output.returncode:
                raise ValueError()
            stage = 'decode'
            try:
                companion = _native_values(output.stdout, generation)
            except NativeDecodeRefused as error:
                stage = 'decode_' + error.step
                raise
            stage = 'identity_after'
            if before != _runtime_identity(provision, expected_container_id):
                raise ValueError()
            if _record(provision.file_capability)[0] is not record or record['cid'] != old_cid:
                raise ValueError()
            stage = 'prior_scan'
            prior_registry.scan(b'')
            result = PostRestoreValues(prior_registry, companion, generations+(generation,), previous)
            stage = 'quiesce_exit'
        stage = 'record'
        if _record(provision.file_capability)[0] is not record or record['cid'] != old_cid:
            raise ValueError()
        from emqx_native_object_integrity import _record_native
        stage = 'record_native'
        recorded=_record_native(result,output.stdout,generation,provision,expected_container_id,before)
        # Value-only emqx_acl projection of this SAME wire; consumed only by FILE target proof.
        from emqx_file_policy_api import _record_native_acl
        return _record_native_acl(recorded,output.stdout,generation)
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('post-native-values-cancelled') from None
    except Exception:
        raise PostCaptureRefused(stage) from None
