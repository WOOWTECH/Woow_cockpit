"""armcompare with row evidence: synthetic captures only (AST-extracted driver functions, no lab, no real values)."""
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import types
import unittest

import odoo_capture

ROOT = Path(__file__).resolve().parent
FUNCTIONS = ('parse_arm_fingerprint', 'scenario_armcompare', 'sibling', 'arm_row_capture', 'odoo_cron_log',
             'arm_row_evidence')
FOUR = ('bus_bus', 'ir_config_parameter', 'ir_cron', 'ir_cron_progress')
RESTORE = datetime(2026, 11, 23, 2, 0, 0)
LIVE_URL, MARKER = 'http://localhost:8069', '{"digest":"sha256:feed"}'


class Failed(Exception):
    pass


class Evidence:
    def __init__(self):
        self.checks, self.saved = [], {}

    def check(self, name, ok, detail=''):
        self.checks.append((name, bool(ok)))

    def save(self, name, value):
        self.saved[name] = value

    def log(self, text):
        pass


def h(value):
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()


def rows_of(table, rows):
    out = []
    for r in rows:
        safe = dict(r)
        out.append({'kind': 'row', 'table': 'public.' + table, 'id': r['id'], 'row_sha256': h(r),
                    'field_sha256': {k: h(v) for k, v in r.items()}, 'safe': safe})
    return out


def capture(tables, prints, database, captured_at='2026-11-23T02:05:00+00:00'):
    records = [{'kind': 'capture_metadata', 'schema_version': 2, 'database': database, 'other_clients': 0,
                'captured_at': captured_at}]
    records += [{'kind': 'table_fingerprint', 'line': f'{t} {c} {m}'} for t, (c, m) in sorted(prints.items())]
    for table, rows in tables.items():
        columns = sorted({k for r in source_rows().get(table, rows) for k in r} | {'id'})   # same schema both sides
        records += [{'kind': 'column', 'table': 'public.' + table, 'name': c, 'position': i + 1, 'type': 'text',
                     'not_null': c == 'id', 'primary_key': c == 'id', 'identity': '', 'generated': '',
                     'collation': None, 'default_sha256': None} for i, c in enumerate(columns)]
        records += rows_of(table, rows)
        records.append({'kind': 'count', 'table': 'public.' + table, 'count': len(rows)})
    return records


def cron(i, xmlid, nextcall, lastcall):
    return {'id': i, 'xmlid': xmlid, 'cron_name': xmlid, 'active': True, 'interval_number': 1,
            'interval_type': 'days', 'nextcall': nextcall, 'lastcall': lastcall, 'failure_count': 0,
            'first_failure_date': None, 'write_date': '2026-11-19T01:00:00'}


def source_rows():
    return {'ir_config_parameter': [
                {'id': 4, 'key': 'web.base.url', 'value': 'http://192.0.2.34:8069', 'create_date': 'x', 'write_date': 'x'},
                {'id': 11, 'key': 'web.base.url.freeze', 'value': 'True', 'create_date': 'x', 'write_date': 'x'}],
            'ir_cron': [cron(1, 'base.autovacuum_job', '2026-11-20T01:00:00', '2026-11-19T01:00:00')],
            'ir_cron_progress': [{'id': 7, 'cron_id': 1, 'done': 0, 'remaining': 0, 'deactivate': None,
                                  'timed_out_counter': 0, 'create_date': '2026-11-19T01:00:00',
                                  'write_date': '2026-11-19T01:00:00'}],
            'bus_bus': [{'id': 20, 'create_date': '2026-11-19T00:00:00'}]}


def target_rows():
    rows = source_rows()
    rows['ir_config_parameter'] = [
        {'id': 4, 'key': 'web.base.url', 'value': LIVE_URL, 'create_date': 'x', 'write_date': 'y'},
        {'id': 50, 'key': 'woow_paas_platform.upgrade_done', 'value': MARKER, 'create_date': 'y', 'write_date': 'y'}]
    rows['ir_cron'] = [cron(1, 'base.autovacuum_job', '2026-11-24T01:00:00', '2026-11-23T02:01:05')]
    rows['ir_cron_progress'].append({'id': 8, 'cron_id': 1, 'done': 0, 'remaining': 0, 'deactivate': None,
                                     'timed_out_counter': 0, 'create_date': '2026-11-23T02:01:01',
                                     'write_date': '2026-11-23T02:01:02'})
    rows['bus_bus'] = []
    return rows


def prints(changed=()):
    names = list(FOUR) + ['res_partner', 'woow_import_probe', 'res_partner_category', 'res_country',
                          'mail_mail', 'mail_message'] + [f'table_{i}' for i in range(195)]
    out = {f'public.{n}': ('15', 'a' * 32) for n in names}
    for name in changed:
        out[name] = ('16', 'b' * 32)
    return out


class RowEvidenceTests(unittest.TestCase):
    def setUp(self):
        tree = ast.parse((ROOT / 'ha_import_e2e.py').read_text())
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in FUNCTIONS]
        self.assertEqual(len(nodes), len(FUNCTIONS))
        self.state = {'restore_started_utc': RESTORE.isoformat(),
                      'restore_started_epoch': RESTORE.replace(tzinfo=timezone.utc).timestamp(),
                      'live_before': {'base_url': LIVE_URL, 'marker': MARKER}, 'live_freeze': ''}
        self.ns = {'Path': Path, 're': re, 'sys': sys, 'Failed': Failed, 'FINGERPRINT_SQL': 'synthetic',
                   'STATE': self.state, 'NAMES': {'enc': 'woow-arm-enc'}, 'require_isolated_device': lambda: None,
                   '__file__': str(ROOT / 'ha_import_e2e.py')}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<driver>', 'exec'), self.ns)
        self.ns['psql'] = lambda *a: self.fail('row evidence must not use the separate fingerprint query')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        archive = base / 'fixtures' / 'woow-arm-enc' / 'woow-arm-enc.tar'
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b'synthetic archive')
        self.archive_sha = odoo_capture.file_hash(archive)
        self.args = types.SimpleNamespace(fingerprint=base / 'fingerprint.txt', fixtures=base / 'fixtures',
                                          source_capture=base / 'capture')
        self.write_fingerprint(prints())
        self.write_source(source_rows(), prints())
        self.target = (target_rows(), prints(changed=['public.' + t for t in FOUR]))
        self.log = "odoo.addons.base.models.ir_cron: Job 'Base: Auto-vacuum internal data' (1) starting\n"

    def write_fingerprint(self, values):
        self.args.fingerprint.write_text('#DB woowtest\n' + '\n'.join(f'{t} {c} {m}' for t, (c, m) in values.items()))

    def write_source(self, rows, values, archive_sha=None):
        directory = self.args.source_capture
        directory.mkdir(exist_ok=True)
        cap = {'stage': 'source_cold', 'archive_sha256': archive_sha or self.archive_sha,
               'records': capture(rows, values, 'woowtest')}
        raw = odoo_capture.encoded(cap)
        (directory / 'source_cold.json').write_bytes(raw)
        (directory / 'complete.json').write_bytes(odoo_capture.encoded(
            {'status': 'complete', 'run_id': 'r' * 32, 'files': {'source_cold.json': odoo_capture.digest(raw)}}))

    def run_compare(self):
        rows, values = self.target
        out = '\n'.join(json.dumps(r) for r in capture(rows, values, 'odoo')).encode()
        self.ns['owner'] = lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=out)
        self.ns['root'] = lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=self.log.encode())
        ev = Evidence()
        self.ns['scenario_armcompare'](ev, self.args)
        return all(ok for _, ok in ev.checks), ev

    def test_explained_rows_pass(self):
        passed, ev = self.run_compare()
        report = ev.saved['arm-compare.json']
        self.assertTrue(passed, ev.checks)
        self.assertEqual(report['status'], 'explained_row_differences')
        self.assertEqual(report['identical'], 201)
        self.assertEqual(report['row_evidence']['summary']['unexplained'], 0)
        self.assertEqual(report['row_evidence']['explained_tables'], ['public.' + t for t in FOUR])
        self.assertEqual(sorted({e['rule'] for e in report['row_evidence']['events']}),
                         ['bus-gc', 'cron-progress', 'cron-schedule', 'import-settings'])

    def test_cron_not_in_log_fails(self):
        self.log = ''
        passed, ev = self.run_compare()
        self.assertFalse(passed)
        self.assertEqual(ev.saved['arm-compare.json']['status'], 'unverified_differences')

    def test_unexplained_config_row_fails(self):
        rows, values = self.target
        rows['ir_config_parameter'].append({'id': 60, 'key': 'mail.catchall.domain', 'value': 'SYNTHETIC',
                                            'create_date': 'y', 'write_date': 'y'})
        passed, ev = self.run_compare()
        self.assertFalse(passed)
        self.assertNotIn('SYNTHETIC', json.dumps(ev.saved['arm-compare.json']))

    def test_other_table_difference_fails(self):
        rows, values = self.target
        values['public.table_3'] = ('15', 'c' * 32)
        passed, ev = self.run_compare()
        self.assertFalse(passed)
        self.assertIn('public.table_3', ev.saved['arm-compare.json']['unverified_tables'])

    def test_source_must_equal_ha_fingerprint(self):
        self.write_fingerprint(prints(changed=['public.table_5']))
        passed, ev = self.run_compare()
        self.assertFalse(passed)
        self.assertEqual(ev.saved['arm-compare.json']['row_evidence']['binding']['differ_from_ha_fingerprint'],
                         ['public.table_5'])

    def test_capture_of_another_archive_is_invalid(self):
        self.write_source(source_rows(), prints(), archive_sha='0' * 64)
        passed, ev = self.run_compare()
        self.assertFalse(passed)
        self.assertEqual(ev.saved['arm-compare.json']['status'], 'invalid_input')

    def test_altered_source_capture_is_invalid(self):
        path = self.args.source_capture / 'source_cold.json'
        path.write_bytes(path.read_bytes() + b' ')
        passed, ev = self.run_compare()
        self.assertFalse(passed)
        self.assertEqual(ev.saved['arm-compare.json']['status'], 'invalid_input')

    def test_mail_rows_of_a_newer_target_capture_stay_whole_table_checks(self):
        rows, values = self.target
        rows['mail_mail'] = [{'id': 1, 'mail_message_id': 1, 'state': 'outgoing', 'create_date': 'x'}]
        rows['mail_message'] = [{'id': 1, 'model': 'res.users', 'res_id': 2, 'message_type': 'email_outgoing',
                                 'create_date': 'x'}]
        passed, ev = self.run_compare()
        self.assertTrue(passed, ev.checks)   # the source capture has no mail rows: equal whole tables suffice
        values['public.mail_mail'] = ('16', 'b' * 32)
        passed, ev = self.run_compare()
        self.assertFalse(passed)
        self.assertEqual(ev.saved['arm-compare.json']['row_evidence']['tables_outside_row_evidence'],
                         ['public.mail_mail'])

    def test_rows_and_fingerprints_must_agree(self):
        rows, values = self.target
        values['public.bus_bus'] = ('15', 'a' * 32)   # fingerprint equal, yet the rows say bus rows went away
        passed, ev = self.run_compare()
        self.assertFalse(passed)


if __name__ == '__main__':
    unittest.main()
