"""Offline gates of the page-emqx mode; no device, lease, browser or relay is used."""
import ast
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


pe = module('prepared_page_emqx', 'focus_acceptance_ui_page_emqx.py')
ui = module('prepared_ui_for_page_emqx', 'focus_acceptance_ui.py')
DRIVER, SOURCE, HA = 'a' * 40, 'b' * 40, 'ha-' + 'f' * 20
IDS = ['j20261128T0102%02dZ-0a1b2c3d' % n for n in range(3)]
KEY_S, KEY_E1, KEY_E2 = 'files.skipped:' + '1' * 16, 'emqx.device-psk:' + '2' * 16, 'emqx.exhook:' + '3' * 16


def lease(source=REPO, **changes):
    value = {'granted': True, 'device': 'woowbk-dev-d', 'case': 'page-emqx', 'phase': 'page-emqx', 'source': str(source),
             'source_commit': SOURCE, 'driver_commit': DRIVER, 'page_guard_sha256': 'c' * 64,
             'expires': (datetime.now(timezone.utc) + timedelta(minutes=60)).isoformat()}
    value.update(changes)
    return value


def check_job():
    issues = [{'id': 'emqx.device-psk', 'level': 'confirm', 'message': 'psk', 'items': [], 'more': 0, 'key': KEY_E1},
              {'id': 'emqx.exhook', 'level': 'confirm', 'message': 'exhook', 'items': [], 'more': 0, 'key': KEY_E2},
              {'id': 'emqx.device-psk', 'level': 'confirm', 'message': 'psk again', 'items': [], 'more': 0, 'key': KEY_E1},
              {'id': 'legacy.warning', 'level': 'notice', 'message': 'hot', 'items': [], 'more': 0},
              {'id': 'emqx.access-from-ha', 'level': 'auto', 'message': 'auto', 'items': [], 'more': 0}]
    return {'id': IDS[2], 'type': 'verify', 'state': 'succeeded',
            'params': {'source': 'ha', 'ha_backup_id': HA, 'apps': ['emqx'], 'key_provided': True},
            'result': {'ha_check': {'schema': 2, 'ha_backup_id': HA,
                                    'shared': [{'id': 'files.skipped', 'level': 'confirm', 'message': 'skipped',
                                                'items': ['x'], 'more': 0, 'key': KEY_S}],
                                    'apps': [{'app_id': 'emqx', 'importable': True, 'issues': issues,
                                              'emqx': {'mqtt_users': 3, 'hot_backup': True}}]}}}


EXPECTED = {'_shared': [KEY_S], 'emqx': sorted([KEY_E1, KEY_E2])}


def chain():
    ack = copy.deepcopy(EXPECTED)
    first = {'id': IDS[0], 'type': 'backup', 'state': 'succeeded',
             'params': {'source': 'ha', 'ha_backup_id': HA, 'apps': ['emqx'], 'test_mode': False, 'acknowledged': ack,
                        'chain': {'apps': ['emqx'], 'test_mode': False, 'then_restore': True, 'acknowledged': copy.deepcopy(ack)}},
             'result': {'backup_id': '20261128T010200Z-0c0c0c0c', 'group': {'next_job_id': IDS[1], 'results': []}}}
    second = {'id': IDS[1], 'type': 'restore', 'state': 'succeeded',
              'params': {'backup_id': '20261128T010200Z-0c0c0c0c', 'apps': ['emqx'], 'ha_backup_id': HA},
              'result': {'safety_backup_id': '20261128T010300Z-0d0d0d0d',
                         'group': {'next_job_id': None, 'results': [{'app_id': 'emqx', 'status': 'imported'}]}}}
    return [first, second]


class LeaseTests(unittest.TestCase):
    def test_lease_is_exact_fresh_and_bound_to_source_and_both_full_commits(self):
        pe.validate_lease(lease(), DRIVER, SOURCE, REPO, time.time())
        soon = (datetime.now(timezone.utc) + timedelta(minutes=44)).isoformat()
        naive = (datetime.now() + timedelta(minutes=60)).isoformat()
        for change in ({'granted': False}, {'granted': 'yes'}, {'device': 'woowbk-dev-e'}, {'case': 'r1-three-selected-memory'},
                       {'phase': 'helper-three-selected'}, {'source': '/tmp/other-product'}, {'source': 'relative/path'},
                       {'driver_commit': DRIVER[:12]}, {'driver_commit': 'd' * 40}, {'source_commit': 'e' * 40},
                       {'source_commit': SOURCE[:12]}, {'page_guard_sha256': 'short'}, {'page_guard_sha256': None},
                       {'expires': soon}, {'expires': naive}, {'expires': 'tomorrow'}, {'expires': None}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'exact fresh page-emqx lease'):
                pe.validate_lease(lease(**change), DRIVER, SOURCE, REPO, time.time())
        for value in (lease(expires=None) | {'expires': 1}, [], 'lease', {k: v for k, v in lease().items() if k != 'expires'}):
            with self.subTest(value=str(value)[:30]), self.assertRaisesRegex(ValueError, 'exact fresh page-emqx lease'):
                pe.validate_lease(value, DRIVER, SOURCE, REPO, time.time())

    def test_the_checkouts_own_heads_must_be_full_commits(self):
        for driver, source in ((DRIVER[:12], SOURCE), (DRIVER, SOURCE[:12]), (DRIVER.upper(), SOURCE)):
            with self.subTest(driver=driver, source=source), self.assertRaises(ValueError):
                pe.validate_lease(lease(driver_commit=driver, source_commit=source), driver, source, REPO, time.time())

    def test_default_paths_are_this_modes_own(self):
        self.assertEqual(pe.LEASE, Path('/tmp/parity-focus-20261127/lease-page-emqx-dev-d.json'))
        self.assertEqual(pe.STATE_NAME, 'focus_acceptance_page_emqx.json')
        self.assertNotEqual(pe.STATE_NAME, ui.STATE.name)
        self.assertEqual(pe.R1_STATE_NAME, 'focus_acceptance_r1_helper.json')


class ProductPinTests(unittest.TestCase):
    """The module's copies of product and harness constants stay equal to their sources (read, never imported)."""

    def constant(self, path, name):
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                return ast.literal_eval(node.value) if not isinstance(node.value, ast.Call) else node.value
        raise AssertionError(name)

    def test_baseline_key_levels_shared_and_safety_retention_match_their_sources(self):
        b1 = HERE / 'ha_import_b1_e2e.py'
        self.assertEqual(self.constant(b1, 'BASELINE_IDS')['emqx'], pe.BASELINE)
        engine = REPO / 'backup-engine/woowbackup'
        self.assertEqual(self.constant(engine / 'flows.py', 'SAFETY_KEEP'), pe.SAFETY_KEEP)
        self.assertEqual(self.constant(engine / 'haissues.py', 'LEVELS'), pe.LEVELS)
        self.assertEqual(self.constant(engine / 'haissues.py', 'SHARED'), pe.SHARED)
        key_re = self.constant(engine / 'haissues.py', 'KEY_RE')
        self.assertEqual(key_re.args[0].value, pe.KEY.pattern)
        page = (REPO / 'backup/backup.js').read_text()
        self.assertIn('const HA_ISSUE_KEY_RE = /^' + pe.KEY.pattern.removesuffix('\\Z') + '$/;', page)


class CheckAcceptanceTests(unittest.TestCase):
    def test_importable_emqx_check_yields_every_listed_key_once_and_its_section(self):
        expected, section = pe.check_accepted(check_job(), HA)
        self.assertEqual(expected, EXPECTED)
        self.assertEqual(section['mqtt_users'], 3)
        job = check_job(); job['result']['ha_check']['shared'] = []
        job['result']['ha_check']['apps'][0]['issues'] = [{'id': 'legacy.warning', 'level': 'notice', 'message': 'x'}]
        self.assertEqual(pe.check_accepted(job, HA)[0], {})   # a valid zero: nothing to confirm

    def test_blocked_stopped_unkeyed_or_foreign_checks_refuse(self):
        def broken(how):
            job = check_job(); result = job['result']['ha_check']; row = result['apps'][0]
            if how == 'emqx-not-importable': row['importable'] = False
            elif how == 'stop-line': row['issues'].append({'id': 'failure.corrupt-archive', 'level': 'stop', 'message': 'x'})
            elif how == 'shared-stop': result['shared'].append({'id': 'x.y', 'level': 'stop', 'message': 'x'})
            elif how == 'confirm-no-key': del row['issues'][0]['key']
            elif how == 'confirm-bad-key': row['issues'][1]['key'] = 'not a key'
            elif how == 'confirm-no-message': row['issues'][1]['message'] = ''
            elif how == 'confirm-database': row['issues'][1]['database'] = 'db'
            elif how == 'unknown-level': row['issues'].append({'id': 'x.y', 'level': 'urgent', 'message': 'x'})
            elif how == 'two-apps': result['apps'].append(dict(row, app_id='hermes'))
            elif how == 'other-app': row['app_id'] = 'hermes'
            elif how == 'no-section': del row['emqx']
            elif how == 'other-backup': result['ha_backup_id'] = 'ha-' + '0' * 20
            elif how == 'params-backup': job['params']['ha_backup_id'] = 'ha-' + '0' * 20
            elif how == 'params-apps': job['params']['apps'] = ['emqx', 'hermes']
            elif how == 'schema-1': result['schema'] = 1
            elif how == 'job-failed': job['state'] = 'failed'
            elif how == 'not-verify': job['type'] = 'backup'
            return job
        for how in ('emqx-not-importable', 'stop-line', 'shared-stop', 'confirm-no-key', 'confirm-bad-key', 'confirm-no-message',
                    'confirm-database', 'unknown-level', 'two-apps', 'other-app', 'no-section', 'other-backup',
                    'params-backup', 'params-apps', 'schema-1', 'job-failed', 'not-verify'):
            with self.subTest(how=how), self.assertRaises(ValueError):
                pe.check_accepted(broken(how), HA)
        with self.assertRaises(ValueError):
            pe.check_accepted({}, HA)


class AcknowledgementTests(unittest.TestCase):
    def test_import_and_page_request_carry_each_listed_key_exactly_once(self):
        first = chain()[0]
        self.assertTrue(pe.acknowledged_exactly(EXPECTED, first['params'], copy.deepcopy(EXPECTED)))
        params = {'chain': {'acknowledged': {}}}
        self.assertTrue(pe.acknowledged_exactly({}, params, {}))   # nothing to confirm: nothing sent, none recorded
        self.assertFalse(pe.acknowledged_exactly({}, params, None))  # but the page must have observed the request

    def test_missing_extra_duplicate_or_regrouped_keys_refuse(self):
        def variants():
            yield 'missing', {'_shared': [KEY_S], 'emqx': [KEY_E1]}
            yield 'extra', {'_shared': [KEY_S], 'emqx': sorted([KEY_E1, KEY_E2, 'emqx.jq-rule:' + '4' * 16])}
            yield 'duplicate', {'_shared': [KEY_S], 'emqx': [KEY_E1, KEY_E1, KEY_E2]}
            yield 'regrouped', {'emqx': sorted([KEY_S, KEY_E1, KEY_E2])}
            yield 'extra-group', dict(EXPECTED, hermes=[KEY_E1])
            yield 'empty-group', dict(EXPECTED, hermes=[])
            yield 'bad-key', {'_shared': ['nope'], 'emqx': sorted([KEY_E1, KEY_E2])}
            yield 'not-a-list', {'_shared': KEY_S, 'emqx': sorted([KEY_E1, KEY_E2])}
        for where in ('params', 'chain', 'sent'):
            for name, wrong in variants():
                with self.subTest(where=where, name=name):
                    params = chain()[0]['params']; sent = copy.deepcopy(EXPECTED)
                    if where == 'params': params['acknowledged'] = wrong
                    elif where == 'chain': params['chain']['acknowledged'] = wrong
                    else: sent = wrong
                    self.assertFalse(pe.acknowledged_exactly(EXPECTED, params, sent))
        params = chain()[0]['params']; del params['chain']
        self.assertFalse(pe.acknowledged_exactly(EXPECTED, params, copy.deepcopy(EXPECTED)))


class ChainTests(unittest.TestCase):
    def test_two_linked_jobs_conversion_then_its_restore(self):
        self.assertTrue(pe.chain_complete(chain(), HA))

    def test_other_layouts_states_links_or_results_refuse(self):
        def broken(how):
            records = chain(); first, second = records
            if how == 'three': records.append(dict(second, id=IDS[2]))
            elif how == 'one': records = records[:1]
            elif how == 'order': records = [second, first]
            elif how == 'restore-failed': second['state'] = 'failed'
            elif how == 'rolled-back': second['state'] = 'rolled-back'
            elif how == 'convert-failed': first['state'] = 'failed'
            elif how == 'link': first['result']['group']['next_job_id'] = IDS[2]
            elif how == 'continues': second['result']['group']['next_job_id'] = IDS[2]
            elif how == 'other-backup': second['params']['backup_id'] = '20261128T000000Z-00000000'
            elif how == 'other-ha': first['params']['ha_backup_id'] = 'ha-' + '0' * 20
            elif how == 'restore-ha': second['params']['ha_backup_id'] = 'ha-' + '0' * 20
            elif how == 'test-mode': first['params']['test_mode'] = True
            elif how == 'convert-only': first['params']['chain']['then_restore'] = False
            elif how == 'apps': first['params']['chain']['apps'] = ['emqx', 'hermes']
            elif how == 'restore-apps': second['params']['apps'] = ['hermes']
            elif how == 'result-extra': second['result']['group']['results'].append({'app_id': 'hermes', 'status': 'imported'})
            elif how == 'result-status': second['result']['group']['results'][0]['status'] = 'rolled-back'
            elif how == 'duplicate-id': second['id'] = IDS[0]
            elif how == 'bad-id': second['id'] = 'job-2'
            elif how == 'no-backup': del first['result']['backup_id']
            return records
        for how in ('three', 'one', 'order', 'restore-failed', 'rolled-back', 'convert-failed', 'link', 'continues', 'other-backup',
                    'other-ha', 'restore-ha', 'test-mode', 'convert-only', 'apps', 'restore-apps', 'result-extra',
                    'result-status', 'duplicate-id', 'bad-id', 'no-backup'):
            with self.subTest(how=how):
                self.assertFalse(pe.chain_complete(broken(how), HA))

    def test_native_records_must_match_and_share_the_first_unit(self):
        records = chain()
        unit = 'woowtech-backup-' + IDS[0] + '.service'
        native = [{'id': r['id'], 'type': r['type'], 'state': r['state'], 'unit': unit} for r in records]
        self.assertTrue(pe.native_units_ok(native, records))
        for change in ({'unit': 'woowtech-backup-' + IDS[1] + '.service'}, {'state': 'failed'}, {'id': IDS[2]}):
            with self.subTest(change=change):
                bad = copy.deepcopy(native); bad[1].update(change)
                self.assertFalse(pe.native_units_ok(bad, records))
        self.assertFalse(pe.native_units_ok(native[:1], records))
        self.assertIn('len(ids)==2', pe.NATIVE_UNITS)
        compile(pe.NATIVE_UNITS, '<native units>', 'exec')


class LiveDataTests(unittest.TestCase):
    before = {'mqtt_users': ['woowbk-lab-baseline'], 'retained': ['woowbk-lab/baseline'], 'banned': ['woowbk-lab-baseline'],
              'mqtt_user_count': 2}
    section = {'mqtt_users': 3}

    def live(self, **changes):
        value = {'mqtt_users': [], 'retained': [], 'banned': [], 'mqtt_user_count': 4}
        value.update(changes)
        return value

    def test_ha_accounts_replace_dev_d_markers(self):
        self.assertTrue(pe.live_matches_ha(self.live(), self.section, self.before))
        self.assertTrue(pe.live_matches_ha(self.live(mqtt_user_count=3), self.section, self.before))

    def test_a_dev_d_marker_left_or_an_account_count_outside_has_bounds_refuses(self):
        for change in ({'mqtt_users': ['woowbk-lab-baseline']}, {'retained': ['woowbk-lab/baseline']},
                       {'banned': ['woowbk-lab-baseline']}, {'mqtt_user_count': 2}, {'mqtt_user_count': 5},
                       {'mqtt_user_count': True}, {'mqtt_users': None}):
            with self.subTest(change=change):
                self.assertFalse(pe.live_matches_ha(self.live(**change), self.section, self.before))
        for section in ({'mqtt_users': 0}, {}, {'mqtt_users': '3'}):
            with self.subTest(section=section):
                self.assertFalse(pe.live_matches_ha(self.live(), section, self.before))
        self.assertFalse(pe.live_matches_ha(self.live(), self.section, None))


class SafetyRetentionTests(unittest.TestCase):
    def row(self, bid, created, apps=('emqx',), kind='safety', **extra):
        return dict({'id': bid, 'type': kind, 'created': created, 'apps': [{'id': a} for a in apps]}, **extra)

    def test_two_new_emqx_copies_can_prune_only_beyond_the_newest_existing_one(self):
        rows = [self.row('s-new', '2026-11-27T10:00:00Z'), self.row('s-old', '2026-11-26T10:00:00Z'),
                self.row('s-oldest', '2026-11-25T10:00:00Z'), self.row('m', '2026-11-19T07:28:31Z', kind='manual'),
                self.row('h', '2026-11-20T00:00:00Z', apps=('hermes',))]
        self.assertEqual(pe.safety_at_risk(rows, []), ['s-old', 's-oldest'])
        self.assertEqual(pe.safety_at_risk(rows, ['s-old']), ['s-oldest'])
        self.assertEqual(pe.safety_at_risk(rows[:1] + rows[3:], []), [])
        self.assertEqual(pe.safety_at_risk([], []), [])
        kept = [self.row('s-new', '2026-11-27T10:00:00Z'), self.row('k', '2026-11-26T10:00:00Z', kept=True)]
        self.assertEqual(pe.safety_at_risk(kept, []), [])
        both = [self.row('s-new', '2026-11-27T10:00:00Z'), self.row('mixed', '2026-11-26T10:00:00Z', apps=('hermes', 'emqx'))]
        self.assertEqual(pe.safety_at_risk(both, []), ['mixed'])


class OwnershipAndBaselineTests(unittest.TestCase):
    digest = '1234567890abcdef' * 4
    ha_id = 'ha-' + digest[:20]

    def test_new_upload_is_owned_and_one_exact_existing_record_is_protected(self):
        self.assertTrue(pe.original_record_owned([{'id': 'ha-other', 'sha256': '0' * 64}], self.ha_id, self.digest))
        self.assertFalse(pe.original_record_owned([{'id': self.ha_id, 'sha256': self.digest}], self.ha_id, self.digest))

    def test_differing_duplicate_or_misnamed_records_refuse(self):
        row = {'id': self.ha_id, 'sha256': self.digest}
        for rows, ha_id in (([dict(row, sha256='0' * 64)], self.ha_id), ([row, row], self.ha_id), ([], 'ha-' + '0' * 20)):
            with self.subTest(rows=len(rows), ha_id=ha_id), self.assertRaises(ValueError):
                pe.original_record_owned(rows, ha_id, self.digest)

    def test_baseline_restore_needs_a_clean_preflight(self):
        ok = {'ok': True, 'apps': [{'id': 'emqx', 'issues': [{'level': 'notice'}, {'level': 'auto'}]}]}
        self.assertTrue(pe.baseline_ready(ok))
        for level in ('confirm', 'stop'):
            bad = copy.deepcopy(ok); bad['apps'][0]['issues'].append({'level': level})
            self.assertFalse(pe.baseline_ready(bad))
        self.assertFalse(pe.baseline_ready(dict(ok, ok=False)))
        self.assertFalse(pe.baseline_ready(None))


class R1PredecessorTests(unittest.TestCase):
    def build(self, root, *, guard=None, docs=None, mode=0o600):
        case = root / 'evidence' / 'focus-acceptance-r1-helper' / '20261128T044707'
        case.mkdir(parents=True)
        files = {'summary.json': {'baseline_restored': True, 'recovery_verified': True, 'failed': 0, 'passed': 70},
                 'recovery.json': {}, 'results.json': {'passed': 70, 'failed': 0, 'results': []},
                 'leaks.json': {'hits': 0, 'scanned': 600, 'regular_json_roots_scanned': 2, 'archive_index_sidecars_scanned': 19},
                 'helper-trace.json': {'completed': True}}
        for name, value in (docs or {}).items():
            files[name] = value
        for name, value in files.items():
            path = case / name; path.write_text(json.dumps(value)); path.chmod(mode)
        old = {'phase': 'complete', 'mode': 'helper-three-selected', 'baseline_restored': True, 'recovery_verified': True,
               'inflight': None, 'ha_record_owned': False, 'evidence_dir': str(case),
               'previous_independent_recovery': {'sha256': 'c' * 64},
               'protected_existing_backups': ['b-1', 'b-2', 'b-3'], 'prior_case_safety_pruning': [{'id': 'b-2'}]}
        old.update(guard or {})
        path = root / 'run' / pe.R1_STATE_NAME
        path.parent.mkdir(); raw = json.dumps(old).encode(); path.write_bytes(raw); path.chmod(0o600)
        return raw, path, root / 'evidence'

    def test_reads_only_a_terminal_r1_bound_to_the_leased_page_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw, path, evidence = self.build(Path(tmp).resolve())
            old, provenance, protected = pe.r1_predecessor(lease(), raw, path, evidence)
            self.assertEqual(provenance['retained_case_archive_ids'], ['b-1', 'b-3'])
            self.assertIs(provenance['acceptance_passed'], False)
            self.assertEqual(provenance['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(len(protected), 6)   # the guard and its five evidence files, by digest
            self.assertEqual(old['phase'], 'complete')

    def test_incomplete_unbound_unsafe_or_badly_accounted_r1_refuses(self):
        cases = (('not-complete', {'guard': {'phase': 'recovery-retained'}}), ('other-mode', {'guard': {'mode': 'page'}}),
                 ('other-page-guard', {'guard': {'previous_independent_recovery': {'sha256': 'd' * 64}}}),
                 ('inflight', {'guard': {'inflight': IDS[0]}}), ('owned-ha', {'guard': {'ha_record_owned': True}}),
                 ('not-recovered', {'guard': {'recovery_verified': False}}),
                 ('pruned-unknown', {'guard': {'prior_case_safety_pruning': [{'id': 'b-9'}]}}),
                 ('failed-check', {'docs': {'summary.json': {'baseline_restored': True, 'recovery_verified': True, 'failed': 1}}}),
                 ('leak-hit', {'docs': {'leaks.json': {'hits': 1, 'scanned': 6, 'regular_json_roots_scanned': 2,
                                                       'archive_index_sidecars_scanned': 1}}}),
                 ('trace-incomplete', {'docs': {'helper-trace.json': {'completed': False}}}),
                 ('readable-evidence', {'mode': 0o644}))
        for name, kwargs in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                raw, path, evidence = self.build(Path(tmp).resolve(), **kwargs)
                with self.assertRaises(ValueError):
                    pe.r1_predecessor(lease(), raw, path, evidence)
        with tempfile.TemporaryDirectory() as tmp:
            raw, path, evidence = self.build(Path(tmp).resolve())
            with self.assertRaises(ValueError):
                pe.r1_predecessor(lease(), raw + b' ', path, evidence)   # bytes other than the guard's own
            target = path.with_name('target.json'); path.rename(target); path.symlink_to(target)
            with self.assertRaises(ValueError):
                pe.r1_predecessor(lease(), raw, path, evidence)


class MarkerProgramTests(unittest.TestCase):
    def programs(self):
        base = ui.marker_program((HERE / 'batch1_markers.py').read_text())
        return base, pe.ha_admin_marker_program(base)

    def test_ha_admin_read_is_the_harness_program_with_one_login_override_before_the_handler(self):
        base, variant = self.programs()
        compile(variant, '<ha admin marker read>', 'exec')
        self.assertEqual(variant.replace('\n' + pe.HA_LOGIN_OVERRIDE, '', 1), base)   # nothing else differs
        self.assertLess(variant.index('def secret(name):\n    if name =='), variant.index(pe.ANCHOR))
        self.assertLess(variant.index('def secret(name):'), variant.index('_page_emqx_device_secret = secret'))
        self.assertIn('issued.append(token)', variant)
        self.assertEqual(ui.marker_program((HERE / 'batch1_markers.py').read_text()), base)   # device read untouched
        for changed in (base.replace(pe.ANCHOR, '\n'), base + pe.ANCHOR, base.replace('def secret(', 'def other(')):
            with self.subTest(size=len(changed)), self.assertRaises(ValueError):
                pe.ha_admin_marker_program(changed)

    def test_override_returns_the_stdin_credential_for_the_dashboard_only(self):
        calls = []
        space = {'json': json, 'sys': SimpleNamespace(stdin=io.StringIO(json.dumps({'ha_dashboard_password': 'ha-admin-value'}))),
                 'secret': lambda name: calls.append(name) or 'device-' + name}
        exec(pe.HA_LOGIN_OVERRIDE, space)
        self.assertEqual(space['secret']('woow-emqx-dashboard-password'), 'ha-admin-value')
        self.assertEqual(space['secret']('woow-emqx-node-cookie'), 'device-woow-emqx-node-cookie')
        self.assertEqual(calls, ['woow-emqx-node-cookie'])
        empty = {'json': json, 'sys': SimpleNamespace(stdin=io.StringIO('{}')), 'secret': lambda name: 'x'}
        exec(pe.HA_LOGIN_OVERRIDE, empty)
        with self.assertRaises(SystemExit):
            empty['secret']('woow-emqx-dashboard-password')


class PageSettingsTests(unittest.TestCase):
    def test_page_receives_emqx_only_settings_its_own_parser_accepts(self):
        settings = pe.page_settings()
        config = {'ha_id': HA, 'result': '/private/browser.json', 'base': 'https://127.0.0.1:1', **settings}
        script = ("import { readFileSync } from 'node:fs'; import { pathToFileURL } from 'node:url';"
                  "const { pageExpectations } = await import(pathToFileURL(process.argv[1]).href);"
                  "console.log(JSON.stringify(pageExpectations(JSON.parse(readFileSync(0, 'utf8')))));")
        proc = subprocess.run(['node', '--input-type=module', '-e', script, str(HERE / 'focus_acceptance_ui_protocol.mjs')],
                              input=json.dumps(config).encode(), capture_output=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode()[-300:])
        parsed = json.loads(proc.stdout)
        self.assertEqual((parsed['apps'], parsed['importable'], parsed['blocked'], parsed['importApps']),
                         (['emqx'], ['emqx'], [], ['emqx']))
        self.assertEqual(parsed['result_rows'], [['emqx', 'imported']])
        self.assertIs(parsed['exact'], True)
        self.assertEqual(parsed['texts'], settings['texts'])
        vocabulary = re.compile(r'[A-Za-z0-9 ,()/:\'<>.=_-]{3,140}')
        self.assertTrue(all(vocabulary.fullmatch(text) for text in settings['texts'].values()))


def ready():
    unit = 'woowtech-backup-' + IDS[0] + '.service'
    trace = {'completed': True, 'browser_used': True, 'check_accepted': True, 'acknowledged_exact': True,
             'chain_verified': True, 'native_units_verified': True, 'native_units': [unit, unit],
             'restore_safety_verified': True, 'live_data_verified': True, 'first_job_id': IDS[0],
             'all_observed_marker_tokens_registered': True, 'observed_marker_tokens': 3, 'actual_sidecars': 19}
    receipt = {'baseline_restored': True, 'inflight': None}
    report = {'hits': 0, 'scanned': 650, 'regular_json_roots_scanned': 2, 'archive_index_sidecars_scanned': 19}
    browser = {'completed': True, 'issued_values_scanned': True}
    return trace, receipt, report, browser


class CleanupGateTests(unittest.TestCase):
    def test_deletion_waits_for_the_whole_proved_case(self):
        trace, receipt, report, browser = ready()
        self.assertTrue(pe.cleanup_ready(trace, receipt, report, 0, browser))
        changes = {
            'page-not-completed': lambda t, r, s, b: t.update(completed=False),
            'browser-incomplete': lambda t, r, s, b: b.update(completed=False),
            'cookie-scan-missing': lambda t, r, s, b: b.update(issued_values_scanned=False),
            'check-refused': lambda t, r, s, b: t.update(check_accepted=False),
            'keys-not-exact': lambda t, r, s, b: t.update(acknowledged_exact=False),
            'chain': lambda t, r, s, b: t.update(chain_verified=False),
            'native': lambda t, r, s, b: t.update(native_units_verified=False),
            'second-unit': lambda t, r, s, b: t['native_units'].__setitem__(1, 'woowtech-backup-' + IDS[1] + '.service'),
            'no-safety': lambda t, r, s, b: t.update(restore_safety_verified=False),
            'no-ha-data': lambda t, r, s, b: t.update(live_data_verified=False),
            'tokens-unregistered': lambda t, r, s, b: t.update(all_observed_marker_tokens_registered=False),
            'no-tokens': lambda t, r, s, b: t.update(observed_marker_tokens=0),
            'bad-first-job': lambda t, r, s, b: t.update(first_job_id='job'),
            'baseline-not-restored': lambda t, r, s, b: r.update(baseline_restored=False),
            'job-inflight': lambda t, r, s, b: r.update(inflight=IDS[1]),
            'scan-hit': lambda t, r, s, b: s.update(hits=1),
            'nothing-scanned': lambda t, r, s, b: s.update(scanned=0),
            'json-roots': lambda t, r, s, b: s.update(regular_json_roots_scanned=1),
            'sidecars-differ': lambda t, r, s, b: s.update(archive_index_sidecars_scanned=18),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                values = copy.deepcopy(ready())
                change(*values)
                trace, receipt, report, browser = values
                self.assertFalse(pe.cleanup_ready(trace, receipt, report, 0, browser))
        self.assertFalse(pe.cleanup_ready(*ready()[:3], 1, ready()[3]))   # a value found on the host
        self.assertFalse(pe.cleanup_ready(*ready()[:3], 0, None))


class HarnessEntryTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(HERE))
        import ha_import_e2e
        self.h = ha_import_e2e

    def tearDown(self):
        sys.path.remove(str(HERE))

    def test_a_stale_page_emqx_lease_stops_before_any_device_access(self):
        head = subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'lease.json'
            for expires in ((datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                            (datetime.now() + timedelta(minutes=90)).isoformat()):
                # Only the expiry is wrong: exact commits of this very checkout, its own path as the source.
                path.write_text(json.dumps(lease(driver_commit=head, source_commit=head, expires=expires)))
                with self.subTest(expires=expires), patch.object(
                        self.h, 'require_isolated_device', side_effect=AssertionError('device touched')) as isolated:
                    with self.assertRaisesRegex(ValueError, 'exact fresh page-emqx lease'):
                        ui.run(REPO, page_emqx=True, page_emqx_lease_path=path)
                    isolated.assert_not_called()

    def test_both_modes_at_once_never_start(self):
        with patch.object(self.h, 'require_isolated_device', side_effect=AssertionError('device touched')):
            with self.assertRaisesRegex(ValueError, 'one mode per run'):
                ui.run(REPO, helper_three_selected=True, page_emqx=True)

    def test_command_line_routes_only_the_named_mode(self):
        with patch.object(ui, 'run', return_value=0) as run:
            self.assertEqual(ui.main(['--run', '--page-emqx', '--lease', '/tmp/x.json']), 0)
            self.assertEqual(run.call_args.kwargs, {'page_emqx': True, 'page_emqx_lease_path': Path('/tmp/x.json')})
            self.assertEqual(ui.main(['--run', '--page-emqx']), 0)
            self.assertIsNone(run.call_args.kwargs['page_emqx_lease_path'])
            for argv in (['--run', '--page-emqx', '--helper-three-selected'], ['--page-emqx', '--helper-three-selected']):
                with self.subTest(argv=argv), patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit):
                    ui.main(argv)
            self.assertEqual(run.call_count, 2)
        with patch.object(ui, 'run', side_effect=AssertionError('unleased runtime')) as run:
            self.assertEqual(ui.main(['--page-emqx']), 0)   # without --run: syntax only
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
