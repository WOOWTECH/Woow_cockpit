"""Offline checks of the R1 helper-three-selected mode; no device, lease, browser or relay is used."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


helper = module('prepared_helper', 'focus_acceptance_ui_helper.py')
ui = module('prepared_ui_for_helper', 'focus_acceptance_ui.py')
DRIVER, SOURCE, HA = 'a' * 40, 'b' * 40, 'ha-' + '1' * 20
IDS = ['j20261128T0102%02dZ-0a1b2c3d' % n for n in range(5)]


def lease(**changes):
    value = {'granted': True, 'case': 'r1-three-selected-memory', 'phase': 'helper-three-selected',
             'helper_three_selected': True, 'device': 'woowbk-dev-d', 'driver_commit': DRIVER,
             'source_commit': SOURCE, 'page_guard_sha256': 'c' * 64,
             'expires': (datetime.now(timezone.utc) + timedelta(minutes=60)).isoformat()}
    value.update(changes)
    return value


def check_job():
    return {'state': 'succeeded', 'result': {'ha_check': {'schema': 2, 'ha_backup_id': HA, 'shared': [], 'apps': [
        {'app_id': 'emqx', 'importable': False, 'issues': [{'level': 'stop'}]},
        {'app_id': 'omnigent', 'importable': True, 'issues': [{'level': 'notice'}]},
        {'app_id': 'hermes', 'importable': True, 'issues': []}]}}}


def chain():
    kinds = ['backup', 'backup', 'restore', 'backup', 'restore']
    states = ['failed', 'succeeded', 'succeeded', 'succeeded', 'succeeded']
    apps = [['emqx'], ['omnigent'], ['omnigent'], ['hermes'], ['hermes']]
    records = [{'id': IDS[n], 'type': kinds[n], 'state': states[n], 'params': {'apps': apps[n]},
                'result': {'group': {'next_job_id': IDS[n + 1] if n < 4 else None}}} for n in range(5)]
    records[-1]['result']['group']['results'] = [{'app_id': 'emqx', 'status': 'failed'},
        {'app_id': 'omnigent', 'status': 'imported'}, {'app_id': 'hermes', 'status': 'imported'}]
    return records


def ready():
    unit = 'woowtech-backup-' + IDS[0] + '.service'
    trace = {'completed': True, 'browser_used': False, 'chain_verified': True, 'native_units_verified': True,
             'live_data_verified': True, 'distinct_restore_safeties_verified': True, 'first_job_id': IDS[0],
             'native_units': [unit] * 5, 'all_observed_marker_tokens_registered': True, 'observed_marker_tokens': 3,
             'actual_sidecars': 9, 'memory': {'unit': unit, 'through_terminal_chain': True, 'sampler_stopped': True,
                                              'samples': 40, 'peak_bytes': 30 * 1024**2}}
    receipt = {'baseline_restored': True, 'inflight': None}
    report = {'hits': 0, 'scanned': 120, 'regular_json_roots_scanned': 2, 'archive_index_sidecars_scanned': 9}
    return trace, receipt, report


class LeaseAndCheckTests(unittest.TestCase):
    def test_lease_must_be_exact_fresh_and_bound_to_both_commits(self):
        helper.validate_lease(lease(), DRIVER, SOURCE, time.time())
        soon = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        naive = (datetime.now() + timedelta(minutes=60)).isoformat()
        for change in ({'granted': False}, {'case': 'r1'}, {'phase': 'page'}, {'helper_three_selected': False},
                       {'device': 'woowbk-dev-e'}, {'driver_commit': 'd' * 40}, {'source_commit': 'e' * 40},
                       {'page_guard_sha256': 'short'}, {'expires': soon}, {'expires': naive}):
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                helper.validate_lease(lease(**change), DRIVER, SOURCE, time.time())

    def test_check_must_stop_only_emqx_and_ask_no_unreviewed_confirmation(self):
        self.assertTrue(helper.check_ready(check_job(), HA))
        def broken(how):
            job = check_job(); rows = job['result']['ha_check']['apps']
            if how == 'emqx-importable': rows[0]['importable'] = True
            elif how == 'emqx-no-stop': rows[0]['issues'] = [{'level': 'notice'}]
            elif how == 'hermes-blocked': rows[2]['importable'] = False
            elif how == 'confirm-shared': job['result']['ha_check']['shared'] = [{'level': 'confirm'}]
            elif how == 'confirm-app': rows[1]['issues'].append({'level': 'confirm'})
            elif how == 'other-backup': job['result']['ha_check']['ha_backup_id'] = 'ha-' + '2' * 20
            elif how == 'two-apps': del rows[2]
            elif how == 'job-failed': job['state'] = 'failed'
            return job
        for how in ('emqx-importable', 'emqx-no-stop', 'hermes-blocked', 'confirm-shared', 'confirm-app',
                    'other-backup', 'two-apps', 'job-failed'):
            with self.subTest(how=how):
                self.assertFalse(helper.check_ready(broken(how), HA))

    def test_chain_must_be_the_five_linked_jobs_with_the_isolated_emqx_failure(self):
        self.assertTrue(helper.chain_complete(chain()))
        def broken(how):
            records = chain()
            if how == 'four': records = records[:4]
            elif how == 'order': records[1], records[2] = records[2], records[1]
            elif how == 'link': records[2]['result']['group']['next_job_id'] = IDS[4]
            elif how == 'duplicate': records[3]['id'] = IDS[1]
            elif how == 'emqx-ok': records[0]['state'] = 'succeeded'
            elif how == 'outcome': records[-1]['result']['group']['results'][2]['status'] = 'failed'
            return records
        for how in ('four', 'order', 'link', 'duplicate', 'emqx-ok', 'outcome'):
            with self.subTest(how=how):
                self.assertFalse(helper.chain_complete(broken(how)))


class CleanupGateTests(unittest.TestCase):
    def test_deletion_waits_for_baseline_scans_one_unit_and_bounded_memory(self):
        self.assertTrue(helper.cleanup_ready(*ready(), 0))
        changes = {
            'browser-used': lambda t, r, s: t.update(browser_used=True),
            'second-unit': lambda t, r, s: t['native_units'].__setitem__(4, 'woowtech-backup-' + IDS[4] + '.service'),
            'memory-1gib': lambda t, r, s: t['memory'].update(peak_bytes=1024**3),
            'sampler-alive': lambda t, r, s: t['memory'].update(sampler_stopped=False),
            'no-samples': lambda t, r, s: t['memory'].update(samples=0),
            'tokens-unregistered': lambda t, r, s: t.update(all_observed_marker_tokens_registered=False),
            'baseline-not-restored': lambda t, r, s: r.update(baseline_restored=False),
            'job-inflight': lambda t, r, s: r.update(inflight=IDS[2]),
            'scan-hit': lambda t, r, s: s.update(hits=1),
            'sidecars-differ': lambda t, r, s: s.update(archive_index_sidecars_scanned=8),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                trace, receipt, report = copy.deepcopy(ready())
                change(trace, receipt, report)
                self.assertFalse(helper.cleanup_ready(trace, receipt, report, 0))
        self.assertFalse(helper.cleanup_ready(*ready(), 1))   # a value found on the host


class PredecessorTests(unittest.TestCase):
    def build(self, root, *, guard_changes=None, leaks=None, mode=0o600):
        case = root / 'evidence' / 'focus-acceptance-ui' / '20261127T102112'
        case.mkdir(parents=True)
        docs = {'summary.json': {'baseline_restored': True, 'recovery_verified': True}, 'recovery.json': {},
                'browser.json': {'issued_values_scanned': True}, 'results.json': {},
                'leaks.json': leaks or {'hits': 0, 'scanned': 50, 'regular_json_roots_scanned': 2,
                                        'archive_index_sidecars_scanned': 8}}
        for name, doc in docs.items():
            path = case / name; path.write_text(json.dumps(doc)); path.chmod(mode)
        guard = {'phase': 'complete', 'baseline_restored': True, 'recovery_verified': True, 'inflight': None,
                 'evidence_dir': str(case), 'protected_existing_backups': ['b-1', 'b-2', 'b-3'],
                 'prior_case_safety_pruning': [{'id': 'b-2'}]}
        guard.update(guard_changes or {})
        guard_path = root / 'focus_acceptance_ui.json'
        raw = json.dumps(guard).encode(); guard_path.write_bytes(raw); guard_path.chmod(0o600)
        return raw, guard_path, root / 'evidence'

    def test_reads_only_an_exact_complete_page_recovery_and_keeps_its_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw, guard_path, evidence = self.build(Path(tmp).resolve())
            ok_lease = lease(page_guard_sha256=hashlib.sha256(raw).hexdigest())
            old, provenance, protected = helper.predecessor(ok_lease, raw, guard_path, evidence)
            self.assertEqual(provenance['retained_case_archive_ids'], ['b-1', 'b-3'])
            self.assertEqual(len(protected), 6)   # the guard and the five evidence files, by digest
            self.assertIs(provenance['acceptance_passed'], False)
            with self.assertRaisesRegex(ValueError, 'exact terminal page guard'):
                helper.predecessor(lease(), raw, guard_path, evidence)

    def test_incomplete_unsafe_or_badly_accounted_recoveries_refuse(self):
        for name, kwargs in (('not-complete', {'guard_changes': {'phase': 'recovery'}}),
                             ('pruned-unknown', {'guard_changes': {'prior_case_safety_pruning': [{'id': 'b-9'}]}}),
                             ('leak-hit', {'leaks': {'hits': 1, 'scanned': 50, 'regular_json_roots_scanned': 2,
                                                     'archive_index_sidecars_scanned': 8}}),
                             ('readable-evidence', {'mode': 0o644})):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                raw, guard_path, evidence = self.build(Path(tmp).resolve(), **kwargs)
                with self.assertRaises(ValueError):
                    helper.predecessor(lease(page_guard_sha256=hashlib.sha256(raw).hexdigest()), raw, guard_path, evidence)


class FirstUnitMemoryTests(unittest.TestCase):
    def test_samples_only_the_first_jobs_unit_and_counts_bad_readings(self):
        unit = 'woowtech-backup-' + IDS[0] + '.service'
        def answer(text):
            return SimpleNamespace(returncode=0, stdout=text.encode())
        good = 'Id=%s\nMemoryPeak=31457280\nMemoryMax=2147483648\nTasksMax=512\nInvocationID=%s\n' % (unit, 'f' * 32)
        for readings, samples, errors in (([good], 1, 0), (['Id=other.service\n' + good.split('\n', 1)[1]], 0, 1),
                                          ([good.replace('TasksMax=512', 'TasksMax=4096')], 0, 1)):
            with self.subTest(readings=readings[0][:30]):
                sampler = helper.FirstUnitMemory(IDS[0], None)
                calls = []
                def root(*args, timeout):
                    calls.append(args); sampler.stop.set(); return answer(readings[0])
                sampler.root = root
                sampler.thread.start()
                result = sampler.finish(True)
                self.assertEqual((result['samples'], result['read_errors'], result['unit']), (samples, errors, unit))
                self.assertTrue(result['sampler_stopped'] and result['through_terminal_chain'])
                self.assertEqual(calls[0][:3], ('systemctl', 'show', unit))
        self.assertEqual(result['peak_bytes'], 0)
        with self.assertRaises(ValueError):
            helper.FirstUnitMemory('not-a-job', None)


class HarnessEntryTests(unittest.TestCase):
    def test_a_stale_helper_lease_stops_before_any_device_access(self):
        repo = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'lease.json'
            path.write_text(json.dumps(lease(expires=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat())))
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            try:
                import ha_import_e2e
                with patch.object(ha_import_e2e, 'require_isolated_device', side_effect=AssertionError('device touched')):
                    with self.assertRaisesRegex(ValueError, 'exact fresh helper-three-selected lease'):
                        ui.run(repo, helper_three_selected=True, helper_lease_path=path)
            finally:
                sys.path.remove(str(Path(__file__).resolve().parent))


if __name__ == '__main__':
    unittest.main()
