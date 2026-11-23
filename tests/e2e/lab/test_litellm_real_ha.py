"""Offline checks of the real LiteLLM HA lab harness (no device, no secret file, synthetic values only)."""
import io
import json
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import litellm_real_capture as capture
import litellm_real_ha as harness
from credential_ledger import CoverageError, Ledger
from woowbackup import ha_odoo

PACKAGE_CONFIG = Path.home() / 'Woow_podman_litellm/config/config.yaml'


class FakeTmp:
    def __init__(self, stdout, code=0):
        self.stdout, self.code = stdout, code

    def exec(self, role, argv, **kwargs):
        return SimpleNamespace(returncode=self.code, stdout=self.stdout)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        harness.LEDGER = Ledger(harness.SOURCES)
        harness.EVENTS.clear()

    def test_declared_sources_are_all_registered_by_the_run(self):
        text = Path(harness.__file__).read_text(encoding='utf-8')
        for source in harness.SOURCES:
            if source.startswith('ha.'):
                self.assertIn("LEDGER.register('ha.' + name", text)
                self.assertIn(source.split('.', 1)[1], harness.candidate.SECRET_NAMES)
            else:
                self.assertRegex(text, r"(LEDGER\.register\(|\(')" + re.escape(source) + "'", source)

    def test_scan_fails_while_any_declared_source_is_missing(self):
        for index, value in enumerate(harness.SOURCES[:-1]):
            harness.LEDGER.register(value, f'synthetic-{index}-value')
        with self.assertRaises(CoverageError):
            harness.LEDGER.require_clean([b'x'])

    def test_worker_registers_issued_key_before_failing(self):
        reply = json.dumps({'ok': False, 'issued': ['sk-synthetic-issued-0001']}).encode()
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(harness.Failed):
                harness.worker(FakeTmp(reply, code=1), 'x', 'ha-verify', {})
        self.assertTrue(harness.LEDGER.registered('issued.virtual_key'))

    def test_events_with_registered_values_are_suppressed(self):
        harness.LEDGER.register('target.master_key', 'sk-synthetic-master-0001')
        out = io.StringIO()
        with redirect_stdout(out):
            harness.emit('x', value='sk-synthetic-master-0001')
            harness.emit('y', ok=True)
        self.assertNotIn('sk-synthetic-master-0001', out.getvalue())
        self.assertIn('suppressed_event', out.getvalue())

    def test_printable_counts_drop_secret_named_fields(self):
        counts = {'vkey_models': 3, 'issued_key_info': 200, 'users': 1, 'model_values': 9, 'salt_row_matches': True,
                  'token_rows': 5, 'text': 'free text'}
        self.assertEqual(harness.printable(counts), {'client_models': 3, 'issued_client_status': 200, 'users': 1,
                                                      'model_values': 9, 'salt_row_matches': True})
        rows = {'public.LiteLLM_UserTable': [1, 'a'], 'public.LiteLLM_VerificationToken': [2, 'b'],
                'woow_platform.chatgpt_auth': [1, 'c'], 'sequence-state': 'd'}
        self.assertEqual(harness.printable_counts(rows), {'LiteLLM_UserTable': 1})

    def test_schema_difference_reports_counts_by_kind(self):
        a = [['column', 'woow', 'meta', 'key'], ['index', 'public', 't', 'i']]
        b = [['index', 'public', 't', 'i'], ['column', 'woow_platform', 'settings', 'key']]
        self.assertEqual(harness.schema_difference(a, b), ({'column': 1}, {'column': 1}))

    def test_ha_cluster_overrides_every_library_and_command_setting(self):
        args = harness.ha_server_args()
        settings = args[2::2]
        self.assertEqual(args[0], 'postgres')
        self.assertIn('hba_file=/var/lib/postgresql/pg_hba.conf', settings)
        self.assertIn('ident_file=/var/lib/postgresql/pg_ident.conf', settings)
        for setting in ha_odoo.HA_SERVER_SETTINGS:
            if not setting.startswith(('hba_file=', 'ident_file=')):
                self.assertIn(setting, settings)
        self.assertEqual(settings[-1], 'shared_buffers=16MB')

    def test_worker_program_compiles_and_carries_the_package_config(self):
        compile(harness.WORKER, 'litellm_real_worker.py', 'exec')
        if PACKAGE_CONFIG.is_file():
            namespace = {}
            exec(compile(harness.WORKER.split('def decrypt_counts')[0].split('PACKAGE_CONFIG = ', 1)[1]
                         .join(['PACKAGE_CONFIG = ', '']), 'cfg', 'exec'), namespace)
            text = PACKAGE_CONFIG.read_text()
            self.assertEqual(namespace['PACKAGE_CONFIG'],
                             '\n'.join(l for l in text.splitlines() if l.strip() and not l.lstrip().startswith('#'))
                             + '\n')

    def test_run_requires_explicit_isolation_confirmation(self):
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            harness.main(['--run'])

    def test_private_dir_must_be_outside_the_repository(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(harness.Failed):
            harness.main(['--private-dir', str(harness.REPO / '.local')])


class FakeDb:
    def __init__(self):
        self.queries = []

    def query_json(self, sql, database='postgres', **kwargs):
        self.queries.append(sql)
        if sql == harness.TABLES:
            return [['public', 'LiteLLM_UserTable'], ['woow', "o'dd"]]
        if sql == harness.SEQUENCES:
            return [['public', 's', 1, 1, 9, 1, False, 1, 3]]
        return [['public.LiteLLM_UserTable', 1, 'aa'], ["woow.o'dd", 0, '']]


class DigestTests(unittest.TestCase):
    def test_one_statement_for_all_tables(self):
        db = FakeDb()
        found = harness.digests(db)
        self.assertEqual(len(db.queries), 3)
        self.assertEqual(db.queries[1].count('UNION ALL'), 1)
        self.assertIn("'woow.o''dd'", db.queries[1])
        self.assertIn('"o\'dd"', db.queries[1])
        self.assertTrue(db.queries[1].startswith("SET TIME ZONE 'UTC'; "))
        self.assertEqual(found['public.LiteLLM_UserTable'], [1, 'aa'])
        self.assertEqual(len(found['sequence-state']), 64)


class CaptureTests(unittest.TestCase):
    def test_only_fixed_event_lines_are_kept(self):
        good = json.dumps({'stage': 'ha_restored', 'all_tables_rows_equal': True, 'counts': {'LiteLLM_UserTable': 1}})
        bad = [json.dumps({'stage': 'x', 'text': 'has spaces in it'}), 'free text line',
               json.dumps({'stage': 'Bad-Stage'}), json.dumps({'stage': 'x', 'v': {'a': {'b': {'c': 1}}}})]
        self.assertEqual(capture.status_lines('\n'.join([good] + bad)), [good])


if __name__ == '__main__':
    unittest.main()
