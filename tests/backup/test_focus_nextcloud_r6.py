"""Offline R6 acceptance-launch boundaries. No lab, credentials, images or fixtures."""
import contextlib
import copy
import datetime
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1] / 'e2e/lab'


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'path', [str(HERE)] + sys.path):
        spec.loader.exec_module(module)
    return module


plan = load('focus_nextcloud_r6_plan')
recover = load('focus_nextcloud_r6_recover')
flow = load('focus_nextcloud_r6')
sources = load('focus_nextcloud_r6_sources')


def checked(case):
    return {'state': 'succeeded', 'result': {'ha_check': {'apps': [
        {'app_id': 'nextcloud', 'importable': True, 'issues': [
            {'id': name, 'level': 'confirm', 'key': name + ':0123456789abcdef'}
            for name in sorted(plan.CASES[case])]}]}}}


class ResourceTests(unittest.TestCase):
    def test_recovery_counts_two_temporary_compressed_copies_and_prior_images(self):
        budget = plan.image_budget([2 * plan.GIB, plan.GIB])
        self.assertEqual(budget['sequential_phases'][1]['additional_peak_bytes'],
                         2 * plan.GIB + plan.GIB + 2 * (plan.GIB + 16 * plan.MIB) + plan.MARGIN)
        self.assertEqual(budget['wake_additional_peak_bytes'], 6 * plan.GIB + plan.MARGIN)
        self.assertEqual(budget['minimum_start_free_bytes'], plan.RESERVE + budget['additional_peak_bytes'])

    def test_actual_five_sizes_fit_observed_free_with_reserve(self):
        budget = plan.image_budget([1969012061, 1329397778, 446255297, 119464062, 54273323])
        self.assertEqual(budget['additional_peak_bytes'], 7676498905)
        self.assertGreater(33807986688 - budget['additional_peak_bytes'], plan.RESERVE)

    def test_no_new_full_fixture_copy_is_counted_but_upload_is(self):
        bound = plan.acceptance_budget(100, 100, 100, 100, 100)
        self.assertEqual(bound['extra_original_fixture_copy_bytes'], 0)
        self.assertGreater(bound['upload_and_convert_peak_bytes'], plan.FIXTURE_BYTES)
        self.assertGreater(plan.acceptance_budget(100, 100, 100, plan.GIB, plan.GIB)
                           ['restore_with_retained_safety_peak_bytes'], 4 * plan.GIB)

    def test_invalid_sizes_refuse(self):
        for bad in (-1, 0, '10', None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                plan.image_budget([bad])


class ConfirmationTests(unittest.TestCase):
    def test_original_share_has_no_confirmation(self):
        self.assertEqual(plan.confirmation_keys(checked('fullshare'), 'fullshare'), [])

    def test_two_reviewed_skips_use_the_actual_bound_keys(self):
        keys = plan.confirmation_keys(checked('skipped-files'), 'skipped-files')
        self.assertEqual(keys, sorted(x + ':0123456789abcdef' for x in plan.CASES['skipped-files']))

    def test_encryption_warning_does_not_acknowledge_any_other_issue(self):
        job = checked('server-encryption')
        job['result']['ha_check']['apps'][0]['issues'].append(
            {'id': 'nextcloud.no-share', 'level': 'confirm', 'key': 'nextcloud.no-share:0123456789abcdef'})
        with self.assertRaises(ValueError):
            plan.confirmation_keys(job, 'server-encryption')

    def test_unknown_missing_duplicate_malformed_and_stop_refuse(self):
        original = checked('skipped-files')
        variations = []
        for change in ('unknown', 'missing', 'duplicate', 'malformed', 'stop'):
            job = copy.deepcopy(original)
            issues = job['result']['ha_check']['apps'][0]['issues']
            if change == 'unknown': issues[0]['id'] = 'nextcloud.no-share'
            if change == 'missing': issues.pop()
            if change == 'duplicate': issues[1] = dict(issues[0])
            if change == 'malformed': issues[0]['key'] = issues[1]['key']
            if change == 'stop': issues.append({'id': 'stop', 'level': 'stop'})
            variations.append((change, job))
        for label, job in variations:
            with self.subTest(label=label), self.assertRaises(ValueError):
                plan.confirmation_keys(job, 'skipped-files')

    def test_failed_job_wrong_app_and_not_importable_refuse(self):
        for change in ('state', 'app_id', 'importable'):
            job = checked('fullshare')
            if change == 'state': job['state'] = 'failed'
            else: job['result']['ha_check']['apps'][0][change] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                plan.confirmation_keys(job, 'fullshare')


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.datetime(2026, 11, 27, tzinfo=datetime.timezone.utc)
        self.lease = {'device': 'woowbk-dev-e', 'source_commit': 'a' * 40, 'lane': 'nextcloud-r6',
                      'phases': ['image-recovery'], 'not_before_utc': '2026-11-26T23:00:00Z',
                      'expires_utc': '2026-11-27T01:00:00Z', 'reserve_bytes': plan.RESERVE,
                      'memory_cap_bytes': plan.DEVICE_CAP}

    def test_exact_lease_passes(self):
        plan.lease_check(self.lease, 'a' * 40, 'image-recovery', self.now)

    def test_no_larger_cap_lower_reserve_wrong_device_commit_or_phase(self):
        for field, value in [('memory_cap_bytes', 4 * plan.GIB), ('reserve_bytes', 12 * plan.GIB),
                             ('device', 'woowbk-dev-d'), ('source_commit', 'b' * 40),
                             ('phases', ['fullshare']), ('lane', 'other')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                plan.lease_check(dict(self.lease, **{field: value}), 'a' * 40, 'image-recovery', self.now)

    def test_expired_future_and_naive_times_refuse(self):
        for field, value in [('expires_utc', '2026-11-26T23:59:59Z'),
                             ('not_before_utc', '2026-11-27T00:01:00Z'),
                             ('expires_utc', '2026-11-27T01:00:00'), ('expires_utc', 'invalid')]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                plan.lease_check(dict(self.lease, **{field: value}), 'a' * 40, 'image-recovery', self.now)


class ControllerTests(unittest.TestCase):
    def test_frozen_controller_has_higher_floor_and_device_load_supervisor(self):
        body = recover.bounded_controller(recover.CONTROLLER.read_text(), 1795737600)
        self.assertIn('FLOOR_GIB=13\n', body)
        self.assertIn('RESERVE_GIB=1\n', body)
        self.assertIn('R6 compressed cap exceeded', body)
        self.assertIn('woowbk-owner', body)
        self.assertIn('p.wait(timeout=60)', body)
        self.assertNotIn('guarded 3600 nice -n 10 "$LP" exec -i "$NAME" /usr/local/bin/woowbk-owner podman', body)
        syntax = subprocess.run(['bash', '-n'], input=body.encode(), capture_output=True)
        self.assertEqual(syntax.returncode, 0)

    def test_changed_controller_is_not_silently_patched(self):
        with self.assertRaises(ValueError):
            recover.bounded_controller(recover.CONTROLLER.read_text() + '\n', 1795737600)

    def test_inner_load_is_terminated_and_reaped_before_supervisor_returns(self):
        events = []
        class Child:
            pid = 12345
            def poll(self): return None if not events else 2
            def wait(self, timeout=None): events.append(('wait', timeout)); return 2
        fake_sub = types.SimpleNamespace(Popen=lambda *a, **k: Child(), DEVNULL=-3,
                                         TimeoutExpired=subprocess.TimeoutExpired)
        fake_os = types.SimpleNamespace(killpg=lambda *x: events.append(('killpg', x)))
        fake_shutil = types.SimpleNamespace(disk_usage=lambda p: types.SimpleNamespace(free=plan.RESERVE))
        fake_time = types.SimpleNamespace(time=lambda: 0, sleep=lambda n: None)
        with patch.dict(sys.modules, {'subprocess': fake_sub, 'os': fake_os,
                                     'shutil': fake_shutil, 'time': fake_time}), \
                patch.object(sys, 'argv', ['loader', '/home/test', '', '999999']), \
                self.assertRaises(SystemExit) as stopped:
            exec(compile(recover.LOAD_SUPERVISOR, '<supervisor>', 'exec'), {})
        self.assertEqual(stopped.exception.code, 2)
        self.assertEqual(events[0][0], 'killpg')
        self.assertEqual(events[-1], ('wait', 60))


class OfflineTests(unittest.TestCase):
    def test_default_entrypoints_do_not_access_devices_or_host_images(self):
        for module in (flow, recover):
            with self.subTest(module=module.__name__), patch.object(sys, 'argv', ['driver']), \
                    patch.object(subprocess, 'run', side_effect=AssertionError('no subprocess')), \
                    patch.object(subprocess, 'check_output', side_effect=AssertionError('no subprocess')), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(module.main(), 0)

    def test_host_source_probe_can_only_inspect_fixed_fields(self):
        identity = {'id': '1' * 64, 'architecture': 'amd64', 'os': 'linux', 'size': 100,
                    'repo_tags': [], 'repo_digests': []}
        with patch.object(sources.subprocess, 'run', return_value=types.SimpleNamespace(
                returncode=0, stdout=json.dumps(identity).encode())) as run:
            row = sources.inspect('1' * 64)
        self.assertEqual(run.call_args.args[0], ['podman', 'image', 'inspect', '--format', sources.FORMAT, '1' * 64])
        self.assertEqual(row['id'], 'sha256:' + '1' * 64)
        self.assertNotIn('Env', sources.FORMAT)

    def test_ha_encryption_or_a_flag_cannot_fake_a_genuine_s5_fixture(self):
        facts = {'files': {'file': 'a' * 64}, 'digests': {'user': 'b' * 64},
                 'section': {'datadir_in_backup': True, 'encryption_enabled': True},
                 'fixture': str(flow.FIXTURE), 'sha256': flow.FIXTURE_SHA}
        for k in ('user_pw', 'app_pw', 'user2_pw', 'link_pw', 'link_token'):
            facts[k] = 'B2_NC_X86_SHARE_TEST'
        flow.validate_facts(facts, 'fullshare')
        with self.assertRaisesRegex(ValueError, 'derived-fixture-review'):
            flow.validate_facts(facts, 'server-encryption')


if __name__ == '__main__':
    unittest.main()
