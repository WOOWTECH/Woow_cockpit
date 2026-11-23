"""Owner-only live data-export inventory and separate owner checkpoint receipts.

No path/bytes input from HA, external archives or callers. The only producer is
this invocation's fresh synthetic broker. Native ETF decoding is never done here.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tempfile

from emqx_runtime_live import IMAGE, checked
from emqx_native_runtime import run_native
from emqx_checkpoint_json import read_owned_checkpoint_export
from emqx_target_capture import mqtt_table_reader, exact_target_readers
from emqx_runtime_credentials import RuntimeRegistry, read_bounded, parse_json
from emqx_target_snapshots import register_target_snapshots
from emqx_private_boundary import PrivateFailure

EXPORTER_COMMIT = '545d816b9b1c5ac5a5583aa9b4029ab0e9c0b870'
TABLE = 'emqx_authn_mnesia'
ATTRIBUTES = '[user_id,password_hash,salt,is_superuser]'


def bounded_private(path, limit):
    """Only invocation-created files; exact identity and EOF, no path discovery."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        assert before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600
        assert 0 < before.st_size <= limit
        with os.fdopen(fd, 'rb', closefd=False) as source:
            raw = source.read(limit + 1)
        after = os.fstat(fd)
        stable = lambda s: (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        assert stable(before) == stable(after) and len(raw) == before.st_size
        return raw
    finally:
        os.close(fd)


def inventory(raw):
    """Bounded metadata only, no extraction; never chooses a native decoder."""
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as source:
        expanded = source.read(64 * 1024 * 1024 + 1)
        assert len(expanded) <= 64 * 1024 * 1024 and not source.read(1)
    entries, seen = [], set()
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        for member in archive:
            assert len(seen) < 256 and member.name not in seen
            seen.add(member.name)
            path = PurePosixPath(member.name)
            assert not path.is_absolute() and '..' not in path.parts
            assert member.isdir() or member.isfile()
            if member.isdir():
                continue
            assert 0 <= member.size <= 8 * 1024 * 1024
            # Only a known native export layout may appear in the public inventory.
            canonical = '/'.join(path.parts[1:])
            assert canonical in {'META.hocon','cluster.hocon','mnesia/emqx_authn_mnesia',
                                 'mnesia/emqx_authn_scram_mnesia'}
            content = archive.extractfile(member)
            assert content is not None
            with content:
                data = content.read(member.size + 1)
                assert len(data) == member.size
            entries.append({'path':canonical,'bytes':member.size})
    assert entries
    return entries


def run_export(root, broker, scan, report):
    checks = report['checks']
    report['exporter_commit'] = EXPORTER_COMMIT
    report['data_export_decoder_selection'] = 'none'
    exports = root / 'exports'
    exports.mkdir(mode=0o700)
    # Fingerprints stay private and only establish nonmutation of this one table.
    fingerprint = ('Rows = lists:flatmap(fun(K) -> mnesia:dirty_read(' + TABLE + ',K) end, '
                   'lists:sort(mnesia:dirty_all_keys(' + TABLE + '))), '
                   'io:format("~s",[binary:encode_hex(crypto:hash(sha256,term_to_binary(Rows)))]).')
    before = checked('exec', broker, 'emqx', 'eval', fingerprint)
    checked('exec', broker, 'emqx', 'ctl', 'data', 'export', '--root-keys',
            'authorization,mqtt', '--table-sets', 'builtin_authn', '--dir', '/work/exports')
    candidates = list(exports.glob('emqx-export-*.tar.gz'))
    assert len(candidates) == 1 and not candidates[0].is_symlink()
    candidates[0].chmod(0o600)
    archive_raw = bounded_private(candidates[0], 8 * 1024 * 1024)
    report['data_export_files'] = inventory(archive_raw)
    checks['actual_broker_data_export_inventory'] = True
    # No archive member is passed to the checkpoint exporter. Independently mint
    # a fresh owner checkpoint directly in this broker, under the pinned routine.
    work = root / 'checkpoint'
    work.mkdir(mode=0o700)
    expression = ('ordered_set = mnesia:table_info(' + TABLE + ',type), '
        'user_info = mnesia:table_info(' + TABLE + ',record_name), '
        + ATTRIBUTES + ' = mnesia:table_info(' + TABLE + ',attributes), '
        'disc_copies = mnesia:table_info(' + TABLE + ',storage_type), '
        '{ok,owner_checkpoint,Nodes} = mnesia:activate_checkpoint('
        '[{name,owner_checkpoint},{min,[' + TABLE + ']},{allow_remote,false}]), '
        'try [Expected] = Nodes, Expected = node(), '
        'ok = mnesia:backup_checkpoint(owner_checkpoint,"/work/checkpoint/source.checkpoint"), '
        'ok = file:change_mode("/work/checkpoint/source.checkpoint",8#600), '
        'io:format("owner-checkpoint-created") '
        'after mnesia:deactivate_checkpoint(owner_checkpoint) end.')
    report['export_stage'] = 'create-owner-checkpoint'
    result = checked('exec', broker, 'emqx', 'eval', expression)
    report['checkpoint_file_created'] = (work / 'source.checkpoint').is_file()
    report['checkpoint_output_bytes'] = len(result)
    assert result.strip() in (b'owner-checkpoint-created', b'owner-checkpoint-createdok')
    report['export_stage'] = 'native-typed-export'
    raw = bounded_private(work / 'source.checkpoint', 8 * 1024 * 1024)
    source_hash = hashlib.sha256(raw).hexdigest()
    # Private receipt cannot be supplied externally or selected by an archive.
    receipt = {'container_id':checked('inspect','--format','{{.Id}}',broker).decode().strip(), 'producer':'fresh-synthetic-live-broker','image':IMAGE,'table':TABLE,
               'input_sha256':source_hash,'input_bytes':len(raw),'exporter_commit':EXPORTER_COMMIT}
    receipt_path = root / 'checkpoint-receipt.json'
    with receipt_path.open('x') as output:
        os.chmod(receipt_path,0o600)
        json.dump(receipt,output,sort_keys=True)
    checks['owner_checkpoint_receipt_created'] = True
    code = Path(__file__).parent
    with tempfile.TemporaryFile() as diagnostics:
        status = run_native(code,'emqx_mnesia_export.escript',
            ('--owner-created-checkpoint',TABLE,'/work/source.checkpoint','/work/export.json'),
            writable_directory=work,output=diagnostics)
        report['native_exit_status'] = status
        assert status == 0
    encoded = bounded_private(work / 'export.json', 1024 * 1024)
    doc = json.loads(encoded)
    values = read_owned_checkpoint_export(raw,TABLE,work / 'export.json').values
    assert doc['schema_validated'] is True and len(doc['rows']) == 1 and values
    assert hashlib.sha256(bounded_private(work / 'source.checkpoint',8388608)).hexdigest() == source_hash
    scan.add(values)
    checks['native_schema_typed_export_and_semantic_read'] = True
    checks['all_semantic_values_registered'] = True
    report['checkpoint_table'] = TABLE
    report['checkpoint_bytes'] = len(raw)
    report['typed_rows'] = len(doc['rows'])
    report['semantic_unique_values'] = len(values)
    after = checked('exec',broker,'emqx','eval',fingerprint)
    assert before == after
    checks['broker_table_fingerprint_unchanged'] = True
    # Real extracted values must be blocked before diagnostics can be published.
    for value in values:
        try:
            scan.scan(value)
        except RuntimeError:
            continue
        raise RuntimeError('semantic-leak-not-blocked')
    checks['actual_semantic_value_leaks_refused'] = True
    report['export_stage'] = 'target-mqtt-consumer'
    # Group is taken from the accepted runtime provider STATE, never inferred
    # from native row identity or a caller-supplied projection shortcut.
    group_expression = ('Authenticators = case emqx_authn_chains:list_authenticators(\'mqtt:global\') of '
        '{ok,L0} -> L0; _ -> {ok,L1}=emqx_authn_chains:list_authenticators(<<"mqtt:global">>),L1 end, '
        '[#{id := <<"password_based:built_in_database">>, provider := emqx_authn_mnesia, '
        'enable := true, state := #{user_group := Group,user_id_type := username}}] = Authenticators, '
        '{GroupKind,GroupBytes} = case Group of G when is_binary(G) -> {binary,G}; '
        'G when is_atom(G) -> {atom,atom_to_binary(G)} end, '
        'io:format("GROUP:~s:~s:END",[atom_to_binary(GroupKind),base64:encode(GroupBytes)]).')
    group_response = checked('exec',broker,'emqx','eval',group_expression).strip()
    assert group_response.startswith(b'GROUP:') and group_response.endswith(b':ENDok')
    import base64
    group_kind, group_encoded = group_response[6:-6].split(b':',1)
    assert group_kind in (b'atom',b'binary')
    report['native_state_group_type'] = group_kind.decode()
    row_group_kind = doc['rows'][0]['value'][1]['value'][0]['type']
    assert row_group_kind in ('atom','binary')
    report['native_row_group_type'] = row_group_kind
    group = base64.b64decode(group_encoded,validate=True)
    checks['username_group_bound_to_native_provider_state'] = True
    # Already validated immutable bytes; this callback never executes native code
    # a second time and binds only the same original checkpoint identity.
    def exporter(source):
        assert source == raw
        return encoded
    reader = mqtt_table_reader(raw,exporter=exporter,username_group=group)
    stream = reader()
    try:
        target_document = parse_json(read_bounded(stream))
    finally:
        stream.close()
    assert target_document['complete'] is True and len(target_document['records']) == 1
    for record in target_document['records']:
        assert set(record) == {'username','password_hash','salt'}
        assert record['username'] == 'workload-user'
        scan.add([v.encode() for v in record.values() if v])
    checks['target_mqtt_single_category_consumer'] = True
    report['target_mqtt_records'] = len(target_document['records'])
    runtime = RuntimeRegistry()
    try:
        register_target_snapshots(runtime,exact_target_readers(raw,exporter=exporter,username_group=group))
    except PrivateFailure:
        checks['incomplete_full_target_registration_refused'] = True
    else:
        raise RuntimeError('false-target-completeness')
    try:
        runtime.summary()
    except PrivateFailure:
        checks['full_target_registry_remains_unsealed'] = True
    else:
        raise RuntimeError('false-target-summary')
    report['export_stage'] = 'finished'
