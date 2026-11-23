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
        for bad in ('import:arm-enc:file', 'import:x86-cold', 'import:x86-cold:mnesia', 'restore', 'rollback:arm-enc',
                    'rollback'):
            self.assertEqual(real.parse_step(bad), (None, None, None))

    def test_every_step_has_an_estimate_and_the_two_halves_fit_one_hold_each(self):
        for name in ('setup', 'before', 'check', 'check-hot', 'import:arm-cold:file', 'import:arm-cold:builtin',
                     'rollback:arm-cold', 'cleanup', 'cleanup-baseline', 'leaks'):
            self.assertGreater(real.estimate(name), 0, name)
        self.assertLessEqual(real.estimate('setup') + real.estimate('import:x86-cold:builtin'), real.HOLD_LIMIT)
        self.assertLessEqual(real.estimate('setup') + real.estimate('rollback:x86-cold'), real.HOLD_LIMIT)
        self.assertLessEqual(real.HOLD_LIMIT, 40 * 60)

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

    def test_the_capture_wrapper_publishes_the_harness_lines(self):
        lines = ['source commit ' + '0' * 40, 'dev-d isolation: true none {}', 'lock acquired after 12 s',
                 'STEP import:arm-cold:builtin: PASS seconds=1234', 'STEP setup: FAIL seconds=3',
                 'backup id converted 20261123T101010Z-0123abcd', 'backup id baseline 20261123T101010Z-0123abcd',
                 "CHECK import arm-cold/emqx (file target) after restore: MQTT: HA's three users log in: PASS",
                 'RESULT 120/121 passed']
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

    def failing(self, mode, result):
        from unittest import mock
        ev = self.Ev()
        args = type('Args', (), {'secrets': {'HA_BACKUP_KEY': 'not-a-key'}})()
        job = {'state': 'succeeded', 'result': {'ha_check': {'apps': [result]}}}
        with mock.patch.object(real.drv, 'run_check', lambda *_a, **_k: (job, 1.0)), \
                mock.patch.object(real.drv, 'compare_check', lambda *_a, **_k: None), \
                mock.patch.dict(real.drv.STATE, {'ha_arm-cold': 'ha-test'}):
            real.check_one(ev, args, 'arm-cold', mode=mode)
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

    def test_the_builtin_target_must_be_ok(self):
        good = self.result(ok=True, blockers=[], emqx={'target_authorization': ['file', 'built_in_database']})
        self.assertEqual(self.failing('builtin', good), [])
        self.assertTrue(self.failing('builtin', self.result()))

    def test_the_owners_text_is_the_products(self):
        from woowbackup import ha_emqx
        self.assertEqual(real.OWNER_ACL_TEXT, ha_emqx.ACL_NEEDS_BUILTIN)


if __name__ == '__main__':
    unittest.main()
