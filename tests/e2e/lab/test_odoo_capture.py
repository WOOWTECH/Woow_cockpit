"""Offline failure injection for same-run capture. No lab, database or real secrets."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('odoo_capture', Path(__file__).with_name('odoo_capture.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def records():
    result = [{'kind': 'capture_metadata', 'schema_version': 1, 'database': 'fixture', 'other_clients': 0}]
    for table in sorted(m.TABLES):
        result.extend({'kind': 'column', 'table': table, 'position': i, 'name': name,
                       'type': 'integer' if name == 'id' else 'text', 'not_null': name == 'id',
                       'primary_key': name == 'id', 'identity': '', 'generated': '', 'collation': None, 'default_sha256': None} for i, name in enumerate(('id', 'value', 'unknown_future_field'), 1))
        result.append({'kind': 'row', 'table': table, 'id': 1, 'row_sha256': 'a' * 64,
                       'field_sha256': {name: 'b' * 64 for name in ('id', 'value', 'unknown_future_field')}})
        result.append({'kind': 'count', 'table': table, 'count': 1})
    return result


def wire(data):
    return b'\n'.join(m.encoded(r) for r in data)


def records_v2(tables):
    result = [{'kind': 'capture_metadata', 'schema_version': 2, 'database': 'fixture', 'other_clients': 0}]
    result += [{'kind': 'table_fingerprint', 'line': f'{t} 1 ' + 'c' * 32} for t in sorted(m.TABLES | m.OPTIONAL_TABLES)]
    for r in records()[1:]:
        if r['kind'] == 'row':
            r = dict(r, safe={'id': 1})
        result.append(r)
    for table in sorted(tables):
        result.append({'kind': 'column', 'table': table, 'position': 1, 'name': 'id', 'type': 'integer',
                       'not_null': True, 'primary_key': True, 'identity': '', 'generated': '', 'collation': None,
                       'default_sha256': None})
        result.append({'kind': 'count', 'table': table, 'count': 0})
    return result


class CaptureTests(unittest.TestCase):
    def test_complete_all_fields(self):
        self.assertEqual(set(m.validate(records())), m.TABLES)

    def test_v2_mail_tables_both_or_none(self):
        self.assertEqual(set(m.validate(records_v2(m.OPTIONAL_TABLES))), m.TABLES | m.OPTIONAL_TABLES)
        self.assertEqual(set(m.validate(records_v2(set()))), m.TABLES)
        with self.assertRaises(ValueError):
            m.validate(records_v2({'public.mail_mail'}))
        with self.assertRaises(ValueError):
            m.validate(records() + records_v2(m.OPTIONAL_TABLES)[-2:])   # version 1 never holds mail rows

    def test_reject_partial_duplicates_missing_columns_and_unquiet(self):
        base = records()
        cases = [base[:-1], base + [base[0]], base + [base[-1]]]
        for kind in ('row', 'column'):
            cases.append(base + [next(r for r in base if r['kind'] == kind)])
        altered = copy.deepcopy(base)
        next(r for r in altered if r['kind'] == 'row')['field_sha256'].pop('unknown_future_field')
        cases.append(altered)
        altered = copy.deepcopy(base)
        altered[0]['other_clients'] = 1
        cases.append(altered)
        for case in cases:
            with self.subTest(case=len(case)), self.assertRaises(ValueError):
                m.validate(case, quiet=True)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ValueError):
            m.loads('{"a":1,"a":2}')

    def test_null_empty_and_unknown_field_deltas_never_exempt(self):
        for table in m.TABLES:
            left, right = records(), records()
            row = next(r for r in right if r.get('table') == table and r['kind'] == 'row')
            row['field_sha256']['unknown_future_field'] = m.digest(b'null')
            row['row_sha256'] = 'c' * 64
            delta = m.differences(m.validate(left), m.validate(right))
            self.assertEqual(delta[0]['fields'], ['unknown_future_field'])
            self.assertEqual(delta[0]['table'], table)
        self.assertNotEqual(m.digest(b'null'), m.digest(b'""'))

    def test_missing_added_rows_and_schema(self):
        before, after = records(), records()
        row = next(r for r in after if r['kind'] == 'row')
        row['id'] = 2
        next(r for r in after if r['kind'] == 'column')['type'] = 'bigint'
        kinds = {d['kind'] for d in m.differences(m.validate(before), m.validate(after))}
        self.assertEqual(kinds, {'schema', 'added', 'removed'})

    def make_chain(self, root, mutate=None):
        identity = dict(run_id='synthetic', archive_sha256='a'*64, engine_sha256='b'*64,
                        sql_sha256='c'*64, ha_backup_id='ha-synthetic', convert_job='convert-one')
        recorder = m.Recorder(root, identity, 'SQL')
        for stage in m.STAGES:
            data = records()
            data[0]['database'] = 'woowtest' if stage == 'source_cold' else 'odoo'
            if mutate:
                mutate(stage, data)
            extra = {'restore_job': 'restore-one', 'converted_backup_id': 'converted'} if stage in ('runtime', 'quiescent') else {}
            if stage == 'quiescent':
                extra['odoo_active'] = 'inactive'
            recorder.capture(stage, lambda sql: wire(data), **extra)
        m.private_write(root / 'runtime-journal.bin', b'synthetic events')
        recorder.files['runtime-journal.bin'] = m.digest(b'synthetic events')
        m.private_write(root / 'complete.json', m.encoded({'status': 'complete', 'run_id': 'synthetic',
                        'files': recorder.files, 'baseline_restored': True, 'restore_job': 'restore-one', 'source_database': 'woowtest', 'converted_backup_id': 'converted'}))

    def test_same_run_chain_and_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.make_chain(root)
            self.assertTrue(m.compare(root)['acceptance'])
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in root.iterdir()))
            with self.assertRaises(FileExistsError):
                m.private_write(root / 'complete.json', b'overwrite')

    def test_changed_runtime_field_with_journal_still_fails(self):
        def mutate(stage, data):
            if stage in ('runtime', 'quiescent'):
                row = next(r for r in data if r['kind'] == 'row')
                row['field_sha256']['value'] = 'e'*64
                row['row_sha256'] = 'f'*64
        with tempfile.TemporaryDirectory() as d:
            self.make_chain(Path(d), mutate)
            report = m.compare(d)
            self.assertFalse(report['acceptance'])
            self.assertEqual(report['status'], 'unverified_differences')
            self.assertTrue(report['differences']['converted_cold->runtime'])

    def test_missing_truncated_tampered_or_cross_run_capture_fails(self):
        for mode in ('missing', 'truncated', 'tampered', 'other-run', 'other-archive', 'other-job', 'not-stopped'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                self.make_chain(root)
                path = root / 'quiescent.json'
                if mode == 'missing':
                    path.unlink()
                elif mode == 'truncated':
                    path.write_bytes(b'{')
                else:
                    obj = m.loads(path.read_bytes())
                    if mode == 'other-run': obj['run_id'] = 'other'
                    elif mode == 'other-archive': obj['archive_sha256'] = 'f'*64
                    elif mode == 'other-job': obj['restore_job'] = 'other'
                    elif mode == 'not-stopped': obj['odoo_active'] = 'active'
                    else: obj['records'][0]['other_clients'] = 3
                    path.write_bytes(m.encoded(obj))
                    # Update file hash: semantic binding must still reject, not merely checksum.
                    manifest = m.loads((root / 'complete.json').read_bytes())
                    manifest['files']['quiescent.json'] = m.file_hash(path)
                    (root / 'complete.json').write_bytes(m.encoded(manifest))
                with self.assertRaises((ValueError, OSError)):
                    m.compare(root)

    def test_partial_capture_never_creates_stage(self):
        with tempfile.TemporaryDirectory() as d:
            rec = m.Recorder(d, {}, 'sql')
            with self.assertRaises(ValueError):
                rec.capture('target_before', lambda sql: wire(records()[:-1]))
            self.assertEqual(list(Path(d).iterdir()), [])

    def test_real_conversion_seams_and_cleanup_on_failure(self):
        calls = []
        tmp = types.SimpleNamespace(exec=lambda *a, **k: types.SimpleNamespace(stdout=wire(records())))
        def cluster(*args):
            return types.SimpleNamespace(tmp=tmp, role='hapg', superuser='postgres')
        module = types.SimpleNamespace(start_ha_cluster=lambda *a: cluster(), restore_dump=lambda *a: None,
                                       live_settings=lambda *a: {}, carry_settings=lambda *a: None, Cluster=cluster)
        originals = vars(module).copy()
        work = types.SimpleNamespace(runner=lambda app: types.SimpleNamespace(podman=lambda *a, **k:
                                     types.SimpleNamespace(stdout=wire(records()))))
        live = types.SimpleNamespace(db_container='target', db_user='postgres')
        rec = types.SimpleNamespace(capture=lambda stage, query: (calls.append(stage), m.validate(
                                    [m.loads(line) for line in query('sql').splitlines()])))
        with self.assertRaises(RuntimeError):
            with m.conversion_hooks(module, rec, 'woowtest'):
                module.live_settings(work, None, live, None)
                module.start_ha_cluster(work, tmp, None)
                module.restore_dump(work, tmp, 'actual dump', 'woowtest')
                module.carry_settings(work, None, live, cluster())
                raise RuntimeError('synthetic failure')
        self.assertEqual(calls, list(m.STAGES[:4]))
        self.assertEqual(vars(module), originals)

    def test_compare_cli_nonzero_and_no_raw_error(self):
        result = subprocess.run([sys.executable, '-B', '-I', str(Path(m.__file__)), 'compare',
                                 '/nonexistent/SYNTHETIC_SECRET'], capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b'SYNTHETIC_SECRET', result.stderr)


class PipelineTests(unittest.TestCase):
    def test_pipeline_source_comes_from_conversion_and_baseline_recovers_failures(self):
        for failure in (None, 'restore', 'capture', 'baseline'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                archive = root / 'immutable.tar'
                archive.write_bytes(b'synthetic real archive stand-in')
                engine = root / 'engine'
                engine.mkdir()
                (engine / 'ha_odoo.py').write_text('# synthetic engine')
                output = root / 'captures'
                def mapped(path):
                    path = str(path)
                    if path == '/var/lib/woowtech-backup/odoo-captures': return output
                    if path == '/usr/local/lib/woowtech-cockpit-backup/woowbackup': return engine
                    return Path(path)
                def data(db):
                    result = records()
                    result[0]['database'] = db
                    return wire(result)
                def db_exec(role, argv, **kwargs):
                    return types.SimpleNamespace(stdout=data(argv[argv.index('-d')+1]))
                container = types.SimpleNamespace(exec=db_exec)
                def cluster(*args):
                    return types.SimpleNamespace(tmp=container, role='hapg', superuser='postgres')
                module = types.SimpleNamespace(start_ha_cluster=lambda *a: cluster(),
                    restore_dump=lambda *a: None, live_settings=lambda *a: {},
                    carry_settings=lambda *a: None, Cluster=cluster)
                work = types.SimpleNamespace(runner=lambda app: types.SimpleNamespace(podman=lambda *a, **k:
                    types.SimpleNamespace(stdout=data('odoo'))))
                live = types.SimpleNamespace(db_container='target', db_user='postgres')
                queued = {}
                def start(paths, kind, params, request_id, **kwargs):
                    ident = 'job-' + str(len(queued))
                    queued[ident] = (kind, params)
                    return {'job_id': ident}
                def run(paths, ident):
                    kind, params = queued[ident]
                    if kind == 'backup':
                        module.live_settings(work, None, live, None)
                        module.start_ha_cluster(work, container, None)
                        module.restore_dump(work, container, 'archive-derived-dump', 'woowtest')
                        module.carry_settings(work, None, live, cluster())
                        return {'state': 'succeeded', 'result': {'backup_id': 'converted'}}
                    failed = ((failure == 'restore' and params['backup_id'] == 'converted') or
                              (failure == 'baseline' and params['backup_id'] == 'baseline'))
                    return {'state': 'failed' if failed else 'succeeded', 'result': {}}
                def command(argv, **kwargs):
                    if 'psql' in argv:
                        if failure == 'capture': raise ValueError('synthetic capture failure')
                        return data('odoo')
                    if '--value' in argv: return b'inactive\n'
                    if argv[0] == 'journalctl': return b'synthetic journal'
                    return b''
                package = types.ModuleType('woowbackup')
                package.jobs = types.SimpleNamespace(start_job=start, run_job=run)
                package.ha_odoo = module
                package.hastore = types.SimpleNamespace(HaStore=lambda paths: types.SimpleNamespace(file_path=lambda ident: archive))
                paths_module = types.ModuleType('woowbackup.paths')
                paths_module.Paths = lambda: None
                request = {'ha_backup_id': 'ha-exact', 'archive_sha256': m.file_hash(archive),
                           'database': 'woowtest', 'baseline': 'baseline'}
                original_path = list(sys.path)
                try:
                    with patch.dict(sys.modules, {'woowbackup': package, 'woowbackup.paths': paths_module}), \
                         patch.object(m, 'Path', side_effect=mapped), patch.object(m, 'checked', side_effect=command):
                        if failure:
                            with self.assertRaises(ValueError): m.device_run(request, 'synthetic SQL')
                        else:
                            result = m.device_run(request, 'synthetic SQL')
                            # The device only captures; the comparison runs on the host (fetch / compare).
                            self.assertEqual(result['status'], 'captured')
                            self.assertIsNone(result['acceptance'])
                finally:
                    sys.path[:] = original_path
                run_dir = next(output.iterdir())
                if failure is None:
                    self.assertTrue(m.compare(run_dir)['acceptance'])
                outcome = m.loads((run_dir / 'outcome.json').read_bytes())
                self.assertEqual(outcome['baseline_restored'], failure != 'baseline')
                self.assertEqual((run_dir / 'complete.json').exists(), failure is None)
                restores = [p['backup_id'] for k, p in queued.values() if k == 'restore']
                self.assertEqual(restores, ['converted', 'baseline'])

    def test_guard_refuses_before_private_request_read(self):
        with patch.object(m.sys, 'argv', ['capture', 'run', '--slot-granted', '--request', '/missing-private']), \
             patch.object(m, 'checked', return_value=b'true bridge {}') as checked:
            with self.assertRaises(ValueError): m.main()
        self.assertEqual(checked.call_count, 1)

    def test_fetch_rejects_traversal_without_reading_device_files(self):
        with tempfile.TemporaryDirectory() as d, patch.object(m, 'checked', return_value=b'true none {}') as checked:
            with self.assertRaises(ValueError): m.fetch('labpodman', '../../etc', Path(d) / 'capture')
            self.assertEqual(checked.call_count, 1)


import sys
if __name__ == '__main__':
    unittest.main()
