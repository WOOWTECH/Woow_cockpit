"""Offline tests of the emqx-product real harness (no device, no podman, no secret)."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


real = _load('emqx_product_real_ha')
capture = _load('emqx_product_real_capture')

SRC = {'mqtt_users': [{'user_id': 'b1-sensor', 'is_superuser': False}, {'user_id': 'b1-gateway', 'is_superuser': False},
                      {'user_id': 'b1-admin', 'is_superuser': True}],
       'retained_messages': ['b1/retained/thermostat', 'b1/retained/door'],
       'rules': ['b1_rule_republish', 'b1_rule_http'], 'dashboard_users': ['admin', 'b1ops']}
H1, H2 = 'a' * 64, 'b' * 64
FACTS = {'version': '5.8.9', 'node': 'emqx@127.0.0.1',
         'mnesia_sizes': {'emqx_authn_mnesia': 3, 'emqx_acl': 4, 'emqx_admin': 2, 'emqx_app': 1, 'emqx_banned': 1,
                          'emqx_psk': 0, 'emqx_retainer_message': 2}}


def imported_probe(mode):
    builtin = mode == 'builtin'
    stored = [['b1/retained/door', H2], ['b1/retained/thermostat', H1]]
    return {
        'mode': mode, 'login': {'ha_admin': 200, 'ha_user2': 200, 'device_admin': 401},
        'mqtt_users': [['b1-admin', True], ['b1-gateway', False], ['b1-sensor', False], ['woow', False]],
        'authz_settings': {'no_match': 'deny', 'deny_action': 'ignore'},
        'authz_sources': [['file', True]] + ([['built_in_database', True]] if builtin else []),
        'file_acl_readback_equal': True,
        'acl_api': ({'users': [200, [['b1-gateway', 2], ['b1-sensor', 2]]], 'clients': [200, [['b1-dashboard-panel', 1]]],
                     'all': [200, 1]} if builtin else {'users': [404, []], 'clients': [404, []], 'all': [404, 0]}),
        'native_counts': {'emqx_acl': 4, 'emqx_retainer_message': 5},
        'retained_api': {'b1/retained/thermostat': H1, 'b1/retained/door': H2, '$SYS/brokers': 'c' * 64},
        'rules': [['b1_rule_http', True], ['b1_rule_republish', True]],
        'connectors': [['http', 'b1_http', 'connected']], 'actions': [['http', 'b1_http_action', 'connected']],
        'banned': [['clientid', 'b1-banned-client']], 'dashboard_users': ['admin', 'b1ops'],
        'api_keys': [['b1-import-key', True]], 'api_key_works': 200, 'config_sha256': 'd' * 64,
        'mqtt': {'login_b1-sensor': 0, 'login_b1-gateway': 0, 'login_b1-admin': 0, 'wrong_password': 4,
                 'anonymous': 5, 'banned_client': 5, 'bootstrap_woow': 0,
                 'admin_retained': {'connack': 0, 'suback': 1, 'retained': stored},
                 'gateway_retained': ({'connack': 0, 'suback': 1, 'retained': stored} if builtin
                                      else {'connack': 0, 'suback': 0x80, 'retained': []}),
                 'sensor_secret': {'connack': 0, 'suback': 0x80, 'retained': []},
                 'own_topic': {'connack': [0, 0], 'suback': 1, 'puback': True, 'received': 1}},
        'delivery': {'publisher': 'b1-sensor' if builtin else 'b1-admin', 'listener': 'b1-gateway' if builtin else 'b1-admin',
                     'suback': 1, 'puback': True, 'received': 1, 'payload_equal': True,
                     'metrics_before': {'republish': {'matched': 3}, 'http_rule': {'matched': 1},
                                        'http_action': {'matched': 1, 'success': 0, 'failed': 1}},
                     'metrics_after': {'republish': {'matched': 4}, 'http_rule': {'matched': 2},
                                       'http_action': {'matched': 2, 'success': 0, 'failed': 2}}},
        'ctl_status': ["Node 'emqx@127.0.0.1' 5.8.9 is started"],
    }


def failed(results):
    return [name for name, ok, _detail in results if not ok]


REAL_RUN_PROBE = real.run_probe   # before any test replaces it


class EvaluateTests(unittest.TestCase):
    def test_a_complete_import_passes_in_both_modes(self):
        for mode in real.MODES:
            with self.subTest(mode=mode):
                self.assertEqual(failed(real.evaluate_imported(imported_probe(mode), SRC, mode)), [])

    def test_the_file_target_must_refuse_has_rows_and_must_not_use_them(self):
        probe = imported_probe('file')
        probe['mqtt']['gateway_retained'] = {'connack': 0, 'suback': 1, 'retained': probe['mqtt']['admin_retained']['retained']}
        self.assertTrue(any('file ACL governs' in name for name in failed(real.evaluate_imported(probe, SRC, 'file'))))
        probe = imported_probe('file')
        probe['native_counts']['emqx_acl'] = 0
        self.assertTrue(any('inactive' in name for name in failed(real.evaluate_imported(probe, SRC, 'file'))))

    def test_the_file_target_with_a_backup_without_acl_rows(self):
        probe = imported_probe('file')
        probe['native_counts']['emqx_acl'] = 0
        self.assertEqual(failed(real.evaluate_imported(probe, SRC, 'file', acl_rows=0)), [])
        probe['native_counts']['emqx_acl'] = 4   # rows appeared from nowhere
        self.assertTrue(any('holds no ACL row' in name
                            for name in failed(real.evaluate_imported(probe, SRC, 'file', acl_rows=0))))
        self.assertEqual(real.ACL_ROWS, {'arm-cold': 4, 'x86-cold': 4, 'x86-fileonly': 0, 'x86-noacl': 0})

    def test_the_builtin_target_must_apply_has_rules(self):
        probe = imported_probe('builtin')
        probe['mqtt']['gateway_retained'] = {'connack': 0, 'suback': 0x80, 'retained': []}
        self.assertTrue(any('active here' in name for name in failed(real.evaluate_imported(probe, SRC, 'builtin'))))
        probe = imported_probe('builtin')
        probe['acl_api']['users'] = [200, [['b1-gateway', 2]]]
        self.assertTrue(any('active in the built-in database' in name
                            for name in failed(real.evaluate_imported(probe, SRC, 'builtin'))))

    def test_each_protection_is_a_separate_check(self):
        cases = {
            'authorization sources': lambda p: p.update(authz_sources=[['built_in_database', True]]),
            'authorization settings': lambda p: p.update(authz_settings={'no_match': 'allow', 'deny_action': 'ignore'}),
            'reads back byte-equal': lambda p: p.update(file_acl_readback_equal=False),
            'old admin password': lambda p: p['login'].update(device_admin=200),
            'bootstrap user woow still logs in': lambda p: p['mqtt'].update(bootstrap_woow=5),
            'anonymous login': lambda p: p['mqtt'].update(anonymous=0),
            'payload equals the stored one': lambda p: p['mqtt']['admin_retained'].update(retained=[]),
            'b1/secret/#': lambda p: p['mqtt']['sensor_secret'].update(suback=1),
            'file rule still lets': lambda p: p['mqtt']['own_topic'].update(received=0),
            'republish rule delivers': lambda p: p['delivery'].update(received=0),
            'HTTP action ran': lambda p: p['delivery']['metrics_after'].update(http_action={'matched': 1, 'success': 0,
                                                                                             'failed': 1}),
            'API key': lambda p: p.update(api_key_works=401),
            'node is started': lambda p: p.update(ctl_status=['Node is not running']),
        }
        for words, mutate in cases.items():
            with self.subTest(words=words):
                probe = imported_probe('file')
                mutate(probe)
                names = failed(real.evaluate_imported(probe, SRC, 'file'))
                self.assertTrue(names and all(words in name for name in names), (words, names))


class DigestTests(unittest.TestCase):
    def test_sys_retained_messages_and_counters_are_left_out(self):
        a, b = imported_probe('file'), imported_probe('file')
        b['retained_api']['$SYS/brokers'] = 'e' * 64
        self.assertEqual(real.digest(a), real.digest(b))
        b['native_counts']['emqx_retainer_message'] = 6
        self.assertNotEqual(real.digest(a), real.digest(b))
        self.assertEqual(real.stable(a), real.stable(b))
        b['retained_api']['b1/retained/door'] = 'f' * 64
        self.assertEqual(real.diff_digest(real.stable(a), real.stable(b)), ['retained_api'])


class ProgramTests(unittest.TestCase):
    def test_self_check_and_the_steps(self):
        real.self_check()
        self.assertEqual(real.parse_step('import:arm-cold:builtin'), ('import', 'arm-cold', 'builtin'))
        self.assertEqual(real.parse_step('cleanup-baseline'), ('cleanup-baseline', None, None))
        self.assertEqual(real.parse_step('rollback:x86-cold'), ('rollback', 'x86-cold', 'builtin'))
        for tag in ('x86-noacl', 'x86-fileonly'):
            self.assertEqual(real.parse_step(f'import:{tag}:file'), ('import', tag, 'file'))
            self.assertEqual(real.parse_step(f'rollback:{tag}'), ('rollback', tag, 'file'))
        for bad in ('import:arm-enc:file', 'import:x86-cold', 'import:x86-cold:mnesia', 'restore', 'rollback:arm-enc',
                    'rollback', 'import:x86-noacl:builtin', 'import:x86-fileonly:builtin', 'import:x86-noacl'):
            self.assertEqual(real.parse_step(bad), (None, None, None))

    def test_every_step_has_an_estimate_and_the_two_halves_fit_one_hold_each(self):
        for name in ('setup', 'before', 'check', 'check-hot', 'import:arm-cold:file', 'import:arm-cold:builtin',
                     'rollback:arm-cold', 'cleanup', 'cleanup-baseline', 'reclaim', 'leaks', 'import:x86-noacl:file',
                     'rollback:x86-noacl', 'import:x86-fileonly:file', 'rollback:x86-fileonly', 'suggest-health'):
            self.assertGreater(real.estimate(name), 0, name)
        self.assertGreater(real.estimate('import:x86-noacl:file'), real.estimate('import:x86-cold:file'),
                           'the lab-made backup runs the whole chain')
        self.assertLessEqual(real.estimate('setup') + real.estimate('import:x86-cold:builtin'), real.HOLD_LIMIT)
        self.assertLessEqual(real.estimate('setup') + real.estimate('rollback:x86-cold'), real.HOLD_LIMIT)
        self.assertLessEqual(real.HOLD_LIMIT, 40 * 60)

    def test_the_hold_never_passes_forty_minutes_and_keeps_the_closing_steps(self):
        budget, limit = real.HOLD_BUDGET, real.HOLD_LIMIT
        self.assertFalse(real.hold_spent(1, 60, 'import:x86-cold:builtin'))
        self.assertTrue(real.hold_spent(2, budget + 1, 'import:x86-cold:file'), 'no long step after the budget')
        for name in ('reclaim', 'leaks', 'catalog-own', 'cleanup', 'cleanup-baseline'):
            self.assertFalse(real.hold_spent(3, budget + 1, name), name)
            self.assertTrue(real.hold_spent(3, limit - real.estimate(name) + 1, name), name)
        self.assertTrue(real.hold_spent(1, limit - real.estimate('rollback:x86-cold') + 1, 'rollback:x86-cold'))
        self.assertFalse(real.hold_spent(0, 0, 'setup'))
        self.assertLessEqual(budget + real.SHORT_STEP, limit)

    def test_the_probe_logs_in_exactly_three_times_and_never_retries_a_login(self):
        logins = re.findall(r'call\(E, "POST", "/api/v5/login"', real.PROBE)
        self.assertEqual(len(logins), 3)
        self.assertNotIn('"/api/v5/login", {"username": "admin", "password": REQ["ha_admin_password"]}, wait',
                         real.PROBE)
        self.assertEqual(real.PROBE.count('time.sleep(7)'), 2, 'the entrance limits logins to 10 per minute')

    def test_the_tamper_script_is_valid_and_appends_one_hocon_line(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / 'tamper.sh'
            script.write_bytes(real.TAMPER)
            self.assertEqual(subprocess.run(['sh', '-n', str(script)]).returncode, 0)
        self.assertIn(b'log.console.formatter = json', real.TAMPER)
        self.assertTrue(real.TAMPER_DROPIN.startswith(real.DROPDIR + '/') and real.DROPIN.startswith(real.DROPDIR + '/'))
        self.assertNotEqual(real.TAMPER_MARKER, real.MARKER)

    def test_the_leak_scan_reads_the_engines_whole_state(self):
        """The driver's program with the engine's two state folders as roots, run on a made-up tree."""
        import subprocess
        import sys
        import tempfile
        self.assertNotIn('index.json', real.LEAK_SCAN)
        compile(real.LEAK_SCAN, 'LEAK_SCAN', 'exec')
        with tempfile.TemporaryDirectory() as root:
            state, run, bin_dir = Path(root) / 'lib', Path(root) / 'run', Path(root) / 'bin'
            for path in (state / 'jobs', state / 'archives', state / 'ha-backups', run, bin_dir):
                path.mkdir(parents=True)
            (state / 'requests.json').write_text('{"note": "canary-secret-value"}')      # one hit
            (state / 'archives' / 'b.tar').write_text('canary-secret-value')              # a backup: not read
            (state / 'jobs' / 'j.json').write_text('{}')
            (bin_dir / 'journalctl').write_text('#!/bin/sh\necho nothing\n')
            (bin_dir / 'runuser').write_text('#!/bin/sh\necho device-secret-value\n')
            for path in bin_dir.iterdir():
                path.chmod(0o755)
            program = real.LEAK_SCAN.replace('"/var/lib/woowtech-backup"', json.dumps(str(state)))
            program = program.replace('"/run/woowtech-backup"', json.dumps(str(run)))
            request = {'secrets': {'A': 'canary-secret-value'}, 'podman_secrets': ['x'], 'uid': 1, 'since': 0}
            proc = subprocess.run([sys.executable, '-I', '-c', program], input=json.dumps(request).encode(),
                                  capture_output=True, env={'PATH': f'{bin_dir}:/usr/bin:/bin'}, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual((report['scanned'], report['hits']), (2, 1))

    def test_only_anonymous_and_job_volumes_count_as_left_behind(self):
        from types import SimpleNamespace
        from unittest import mock
        anonymous, job = 'a1' * 32, 'woowbk-j20261124T000000Z-0123abcd-emqx-new'
        listed = '\n'.join([anonymous, job, 'headscale-data', 'headscale-run', 'headplane-data', 'woow_emqx_data'])
        proc = SimpleNamespace(returncode=0, stdout=listed.encode(), stderr=b'')
        with mock.patch.object(real.drv, 'owner', lambda *_a, **_k: proc):
            self.assertEqual(real.dangling_volumes(), {anonymous, job})
        proc = SimpleNamespace(returncode=125, stdout=b'', stderr=b'')
        with mock.patch.object(real.drv, 'owner', lambda *_a, **_k: proc):
            with self.assertRaises(real.Failed):
                real.dangling_volumes()

    def test_the_capture_wrapper_publishes_the_harness_lines(self):
        lines = ['source commit ' + '0' * 40, 'dev-d isolation: true none {}', 'lock acquired after 12 s',
                 'STEP import:arm-cold:builtin: PASS seconds=1234', 'STEP setup: FAIL seconds=3',
                 'backup id converted 20261123T101010Z-0123abcd', 'backup id baseline 20261123T101010Z-0123abcd',
                 "CHECK import arm-cold/emqx (file target) after restore: MQTT: HA's three users log in: PASS",
                 'dev-d reclaim headroom_before=1576128512 headroom_after=2700000000 journal_before=150000000 '
                 'journal_after=60000000 rounds=3', 'RESULT 120/121 passed']
        self.assertEqual(capture.status_lines('\n'.join(lines + ['secret-looking detail'])), lines)
        self.assertEqual(real.label('a\nb|c'), 'a_b_c')


class DecisionCTests(unittest.TestCase):
    """OWNER DECISION 2026-11-23 「C」: on the file target the check must refuse with exactly the owner's text."""

    class Ev:
        def __init__(self):
            self.results = []

        def check(self, name, ok, detail=''):
            self.results.append((name, bool(ok)))
            return bool(ok)

        def time(self, *_args):
            pass

        def save(self, *_args):
            pass

    def failing(self, mode, result, tag='arm-cold'):
        from unittest import mock
        ev = self.Ev()
        args = type('Args', (), {'secrets': {'HA_BACKUP_KEY': 'not-a-key'}})()
        job = {'state': 'succeeded', 'result': {'ha_check': {'apps': [result]}}}
        self.keys = []

        def run_check(*_args, **kwargs):
            self.keys.append(kwargs.get('key'))
            return job, 1.0

        with mock.patch.object(real.drv, 'run_check', run_check), \
                mock.patch.object(real.drv, 'compare_check', lambda *_a, **_k: None), \
                mock.patch.object(real.drv, 'source', lambda _m: {'emqx': FACTS}), \
                mock.patch.dict(real.drv.STATE, {f'ha_{tag}': 'ha-test'}):
            real.check_one(ev, args, tag, mode=mode)
        return [name for name, ok in ev.results if not ok]

    def result(self, **changes):
        found = {'ok': False, 'blockers': [real.OWNER_ACL_TEXT], 'warnings': [], 'arch': 'aarch64', 'version': '5.9.1',
                 'target_version': '5.8.9', 'emqx': {'target_authorization': ['file']}}
        found.update(changes)
        return found

    def test_the_file_target_passes_only_with_the_owners_text_as_the_only_blocker(self):
        self.assertEqual(self.failing('file', self.result()), [])
        for bad in (self.result(ok=True, blockers=[], warnings=['HA 的 ACL 規則不會生效']),   # the old warning design
                    self.result(blockers=[real.OWNER_ACL_TEXT, '另一個原因']),
                    self.result(blockers=['另一個原因']),
                    self.result(emqx={'target_authorization': ['file', 'built_in_database']})):
            with self.subTest(bad=bad):
                self.assertTrue(self.failing('file', bad))

    def test_the_lab_made_backup_without_rows_must_be_accepted_on_the_file_target(self):
        section = {'target_authorization': ['file'], 'emqx_version': '5.8.9', 'target_version': '5.8.9',
                   'node_name': 'emqx@127.0.0.1', 'mqtt_users': 3, 'acl_rules': 0, 'dashboard_users': 2, 'api_keys': 1,
                   'banned': 1, 'psk': 0, 'default_dashboard_password': False, 'anonymous': False, 'hot_backup': False,
                   'retained_messages': 5}
        good = self.result(ok=True, blockers=[], arch='amd64', emqx=section)
        for tag in real.LAB_MADE:
            self.assertEqual(self.failing('file', good, tag), [])
            self.assertEqual(self.keys, [None], 'an unencrypted upload is checked without a key')
        for bad in (self.result(arch='amd64', emqx=section),                                      # still refused
                    self.result(ok=True, blockers=[], arch='amd64', emqx=dict(section, acl_rules=4)),
                    self.result(ok=True, blockers=[], arch='amd64', emqx=dict(section, retained_messages=1)),
                    self.result(ok=True, blockers=[], arch='amd64', emqx=dict(section, target_authorization=['file', 'x']))):
            with self.subTest(bad=bad):
                self.assertTrue(self.failing('file', bad, 'x86-fileonly'))
        self.assertEqual(self.failing('file', self.result()), [])
        self.assertEqual(self.keys, ['not-a-key'], 'the real uploads are encrypted')

    def test_the_builtin_target_must_be_ok(self):
        good = self.result(ok=True, blockers=[], emqx={'target_authorization': ['file', 'built_in_database']})
        self.assertEqual(self.failing('builtin', good), [])
        self.assertTrue(self.failing('builtin', self.result()))

    def test_the_owners_text_is_the_products(self):
        from woowbackup import ha_emqx
        self.assertEqual(real.OWNER_ACL_TEXT, ha_emqx.ACL_NEEDS_BUILTIN)


class DraftTests(unittest.TestCase):
    """catalog-draft / catalog-own: the page's own draft between the two, dev-d's own entry always back."""

    class Helper:
        """The engine's catalog commands over one installed entry (no device)."""

        def __init__(self):
            self.own = {'id': 'emqx', 'health': [], 'name': 'own'}
            self.installed, self.calls = dict(self.own), []
            self.draft = {'id': 'emqx', 'name': 'draft', 'health': [
                {'type': 'http', 'url': 'http://127.0.0.1:18083/api/v5/error_codes', 'expect_status': 200}]}
            self.break_install = False

        @staticmethod
        def sha(entry):
            return 'sha-' + entry['name'] if entry else None

        def ok(self, command, request=None, **_kwargs):
            request = request or {}
            self.calls.append((command, bool(request.get('confirm'))))
            if command == 'catalog-suggest':
                entry = dict(self.installed) if self.installed else dict(self.draft)
                installed = ({'entry': dict(self.installed), 'sha256': self.sha(self.installed),
                              'same': self.installed['name'] == 'draft', 'changes': []} if self.installed else None)
                return {'apps': [{'id': 'emqx', 'entry': entry, 'valid': True, 'installed': installed,
                                  'hints': ['emqx-entrance.container 的健康檢查網址 /readyz 只回應容器內部，會得到 403']}]}
            if command == 'catalog-remove':
                if request.get('confirm'):
                    assert request['expected_sha256'] == self.sha(self.installed)
                    self.installed = None
                return {'expected_sha256': self.sha(self.installed)}
            if command == 'catalog-install':
                if request.get('confirm'):
                    self.installed = dict(request['entry'], name='broken') if self.break_install else dict(request['entry'])
                return {'valid': True, 'expected_sha256': 'x', 'sha256': self.sha(self.installed)}
            if command == 'status':
                return {'apps': [{'id': 'emqx', 'state': 'running', 'problems': []}]}
            raise AssertionError(command)

    def setUp(self):
        from unittest import mock
        self.helper = self.Helper()
        self.ev = DecisionCTests.Ev()
        patches = (mock.patch.object(real.drv, 'ok', self.helper.ok), mock.patch.object(real.drv, 'save_state', lambda: None),
                   mock.patch.dict(real.drv.STATE, {}, clear=True))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def failing(self):
        return [name for name, ok in self.ev.results if not ok]

    def test_the_draft_is_installed_unedited_and_the_own_entry_comes_back(self):
        real.step_catalog_draft(self.ev, None)
        self.assertEqual(self.helper.installed, self.helper.draft)
        self.assertEqual(real.drv.STATE['own_entry'], {'entry': self.helper.own, 'sha256': 'sha-own'})
        real.draft_installed(self.ev, 'import')
        self.assertTrue([n for n, ok in self.ev.results if 'own unedited draft' in n])
        with self.assertRaises(real.Failed):
            real.step_catalog_draft(self.ev, None)          # never twice: the saved own entry must not be overwritten
        with self.assertRaises(real.Failed):
            real.step_suggest_health(self.ev, None)
        real.step_catalog_own(self.ev, None)
        self.assertEqual(self.helper.installed, self.helper.own)
        self.assertIsNone(real.drv.STATE['own_entry'])
        self.assertEqual(self.failing(), [])
        with self.assertRaises(real.Failed):
            real.step_catalog_own(self.ev, None)

    def test_the_own_entry_is_recorded_before_anything_is_removed(self):
        seen = []

        def save():
            seen.append((dict(real.drv.STATE.get('own_entry') or {}), list(self.helper.calls)))
        from unittest import mock
        with mock.patch.object(real.drv, 'save_state', save):
            real.step_catalog_draft(self.ev, None)
        self.assertEqual(seen[0][0], {'entry': self.helper.own, 'sha256': 'sha-own'})
        self.assertNotIn('catalog-remove', [c for c, _confirm in seen[0][1]])

    def test_another_entry_than_the_own_one_keeps_the_record(self):
        real.step_catalog_draft(self.ev, None)
        self.helper.break_install = True
        with self.assertRaises(real.Failed):
            real.step_catalog_own(self.ev, None)
        self.assertTrue(real.drv.STATE['own_entry'])
        self.assertTrue([n for n in self.failing() if 'installed again' in n])

    def test_a_draft_that_asks_another_url_fails(self):
        self.helper.draft['health'][0]['url'] = 'http://127.0.0.1:18083/'
        real.step_catalog_draft(self.ev, None)
        self.assertTrue([n for n in self.failing() if 'public API' in n])

    def test_an_edited_entry_is_not_the_draft(self):
        real.step_catalog_draft(self.ev, None)
        self.helper.installed = dict(self.helper.installed, name='edited')
        real.draft_installed(self.ev, 'import')
        self.assertTrue([n for n in self.failing() if 'own unedited draft' in n])

    def test_without_a_draft_nothing_is_claimed(self):
        real.draft_installed(self.ev, 'import')
        self.assertEqual(self.ev.results, [])


class RoundTests(unittest.TestCase):
    """The failing restores: what each round checks can fail (no constant True)."""

    def setUp(self):
        from unittest import mock
        self.ev = DecisionCTests.Ev()
        self.job = {'state': 'rolled-back', 'result': {'rolled_back': True}, 'error': {'code': 'job-failed', 'message': 'x'}}
        self.log, self.seen, self.left, self.removed = [], '2', set(), None
        self.armed = []

        def arm(files, script, dropin, marker_text):
            self.armed.append((files, script, dropin))
            return True

        def disarm(files, dir_existed):
            return self.removed if self.removed is not None else {f: 'removed' for f in files[:2]}

        from types import SimpleNamespace
        patches = (mock.patch.object(real, 'arm', arm), mock.patch.object(real, 'disarm', disarm),
                   mock.patch.object(real, 'stat_owner', lambda paths: {p: p in self.left for p in paths}),
                   mock.patch.object(real, 'restore_with', lambda *_a, **_k: (self.job, self.log, 1.0)),
                   mock.patch.object(real.drv, 'owner', lambda *_a, **_k: SimpleNamespace(stdout=self.seen.encode(), returncode=0)))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def failing(self, round_):
        self.ev.results = []
        round_(self.ev, 'x', 'backup', 'name')
        return [name for name, ok in self.ev.results if not ok]

    def test_the_start_failure_round(self):
        self.assertEqual(self.failing(real.start_failure_round), [])
        self.assertEqual(self.armed[0][0], real.FAIL_FILES)
        self.assertEqual(len(self.ev.results), 3)
        for change in ({'job': {'state': 'succeeded', 'result': {'rolled_back': False}}},
                       {'job': dict(self.job, state='failed')}, {'left': {real.MARKER}},
                       {'seen': '0'}, {'seen': ''}, {'removed': {f: 'absent' for f in real.FAIL_FILES}},
                       {'removed': {'error': 'x'}}, {'left': {real.FAIL_SEEN}}, {'left': {real.DROPIN}}):
            with self.subTest(change=change):
                saved = {k: getattr(self, k) for k in change}
                for key, value in change.items():
                    setattr(self, key, value)
                self.assertTrue(self.failing(real.start_failure_round))
                for key, value in saved.items():
                    setattr(self, key, value)

    def test_the_readback_round(self):
        good = {'code': 'job-failed', 'message': real.READBACK_DIFF + '，已停止；…'}
        self.job = dict(self.job, error=good)
        self.assertEqual(self.failing(real.readback_round), [])
        self.assertEqual(self.armed[0][0], real.TAMPER_FILES)
        for change in ({'job': dict(self.job, error=dict(good, message='EMQX 還原後的設定（listeners、log）和轉換時核對的不同'))},
                       {'job': dict(self.job, error=dict(good, message='EMQX 還原後的設定（log）、內建資料庫（emqx_admin）和轉換時核對的不同'))},
                       {'job': dict(self.job, error=dict(good, message='無法啟動服務'))},
                       {'job': dict(self.job, state='succeeded')}, {'log': [real.READBACK_LOG]},
                       {'left': {real.TAMPER_MARKER}}, {'removed': {f: 'absent' for f in real.TAMPER_FILES}}):
            with self.subTest(change=change):
                saved = {k: getattr(self, k) for k in change}
                for key, value in change.items():
                    setattr(self, key, value)
                self.assertTrue(self.failing(real.readback_round))
                for key, value in saved.items():
                    setattr(self, key, value)

    def test_the_readback_diff_text_is_the_products(self):
        from woowbackup import ha_emqx
        problems = ha_emqx.compare_readback({'config_roots': {'log': 'a', 'mqtt': 'b'}, 'tables': {'emqx_admin': [1, 'x']}},
                                            {'config_roots': {'log': 'c', 'mqtt': 'b'}, 'tables': {'emqx_admin': [1, 'x']}})
        self.assertTrue(('EMQX 還原後的' + '、'.join(problems) + '和轉換時核對的不同').startswith(real.READBACK_DIFF))

    def test_the_failing_start_script(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            home, bin_dir, volume = Path(root) / 'home', Path(root) / 'bin', Path(root) / 'volume'
            for path in (home / '.config', bin_dir, volume / 'configs'):
                path.mkdir(parents=True)
            (volume / 'configs' / 'cluster.hocon').write_text('rule_engine {rules {b1_rule_republish {}}}\n')
            (bin_dir / 'podman').write_text(f'#!/bin/sh\nif [ "$1" = volume ]; then echo {volume}; exit 0; fi\n'
                                            '[ "$1" = unshare ] || exit 9\nshift\nexec "$@"\n')
            (bin_dir / 'podman').chmod(0o755)
            script = Path(root) / 'fail.sh'
            script.write_bytes(real.FAIL_ONCE)

            def run():
                return subprocess.run(['sh', str(script)], env={'HOME': str(home), 'PATH': f'{bin_dir}:/usr/bin:/bin'},
                                      timeout=30).returncode
            seen = home / '.config' / 'emqx-woowbk-fail-seen'
            self.assertEqual(run(), 0, 'without the marker the unit starts')
            self.assertFalse(seen.exists())
            (home / '.config' / 'emqx-woowbk-fail-once').write_text('fail once\n')
            self.assertEqual(run(), 1)
            self.assertEqual(seen.read_text().strip(), '1')
            self.assertFalse((home / '.config' / 'emqx-woowbk-fail-once').exists(), 'one shot')
            self.assertEqual(run(), 0)
            (volume / 'configs' / 'cluster.hocon').write_text('nothing of HA\n')
            (home / '.config' / 'emqx-woowbk-fail-once').write_text('fail once\n')
            self.assertEqual(run(), 1)
            self.assertEqual(seen.read_text().strip(), '0', 'the own data is told from HA\'s')


class OwnStateTests(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.ev = DecisionCTests.Ev()
        self.marked = True
        self.probe = {'login': {'device_admin': 200, 'ha_admin': 401}, 'authz_sources': [['file', True]],
                      'authz_settings': {'no_match': 'deny', 'deny_action': 'ignore'}, 'file_acl_readback_equal': True,
                      'mqtt_users': [['woow', False]], 'rules': [], 'retained_api': {'woowbk-lab/baseline': 'h'},
                      'api_keys': [], 'own_mqtt': {'ha_b1-sensor': 5, 'ha_b1-gateway': 5, 'ha_b1-admin': 4, 'bootstrap_woow': 0}}
        self.requested = []

        def run_probe(_ev, _args, _label, mode, tag=None, **kwargs):
            self.requested.append((mode, kwargs))
            return self.probe
        patches = (mock.patch.object(real, 'run_probe', run_probe),
                   mock.patch.object(real, 'markers', lambda ev, label_text: ev.check('markers', self.marked)))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def failing(self, own=None, mode='file'):
        self.ev.results = []
        real.own_state(self.ev, None, 'x', real.digest(self.probe) if own is None else own, mode)
        return [name for name, ok in self.ev.results if not ok]

    def test_the_own_state_passes_and_every_part_can_fail(self):
        self.assertEqual(self.failing(), [])
        self.assertEqual(self.requested[0], ('base', {'own_mqtt': True}))
        own = real.digest(self.probe)
        for change in ({'own_mqtt': dict(self.probe['own_mqtt'], bootstrap_woow=5)},
                       {'own_mqtt': dict(self.probe['own_mqtt'], **{'ha_b1-sensor': 0})},
                       {'own_mqtt': dict(self.probe['own_mqtt'], **{'ha_b1-sensor': None})},
                       {'own_mqtt': {'bootstrap_woow': 0}}, {'own_mqtt': None},
                       {'login': {'device_admin': 401, 'ha_admin': 200}}, {'mqtt_users': [['b1-sensor', False]]},
                       {'retained_api': {}}, {'authz_sources': [['file', True], ['built_in_database', True]]}):
            with self.subTest(change=change):
                saved = dict(self.probe)
                self.probe.update(change)
                self.assertTrue(self.failing(own))
                self.probe = saved
        self.marked = False
        self.assertIn('markers', self.failing(own))

    def test_the_builtin_target_keeps_its_added_source(self):
        self.probe['authz_sources'] = [['file', True], ['built_in_database', True]]
        self.assertEqual(self.failing(mode='builtin'), [])
        self.assertTrue(self.failing(mode='file'))

    def test_the_first_rounds_run_for_the_untouched_and_the_builtin_target(self):
        self.assertEqual(set(real.FIRST_ROUNDS), {'arm-cold', 'x86-cold', 'x86-fileonly'})
        self.assertEqual(real.estimate('import:x86-fileonly:file'), real.estimate('import:x86-cold:builtin'))
        self.assertGreater(real.estimate('import:x86-cold:builtin'), real.estimate('import:x86-noacl:file'))
        self.assertGreater(real.estimate('import:x86-cold:builtin'), real.estimate('import:x86-cold:file'))

    def test_the_leak_scan_counts_one_token_per_successful_login(self):
        from types import SimpleNamespace
        from unittest import mock
        args = SimpleNamespace(secrets=None)
        answers = [{'login': {'ha_admin': 200, 'ha_user2': 200, 'device_admin': 401}}, {'login': {'device_admin': 200}}, {}]
        with mock.patch.object(real.drv, 'event_device_python', lambda *_a, **_k: answers.pop(0)), \
                mock.patch.object(real, 'probe_request', lambda *_a, **_k: {}):
            self.real_run_probe = REAL_RUN_PROBE
            for _ in range(3):
                self.real_run_probe(self.ev, args, 'x', 'base')
        self.assertEqual(args.logins, 3)


if __name__ == '__main__':
    unittest.main()
