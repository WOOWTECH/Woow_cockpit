"""Offline: the page import bridge's two optional inputs, key=None (an unencrypted HA backup) and choices (what a check
offers: an Odoo database, an add-on, a node), against a simulated device; and the proof that every earlier call is
unchanged: the reviewed bridge of a1ca42b2 (from git, pinned by SHA-256) hands the page the same config, byte for byte,
and judges the same simulated import to the same summary.
"""
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BASE = 'a1ca42b2edecfaef99ea8d7a1db93e8acd0d59ac'
OLD_BRIDGE_SHA = '81356e9f7f92737dc3bca1bf83b019d9a7ec4e5b80a294df309b172d90ee607f'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


bridge = module('modes_bridge', HERE / 'focus_page_bridge.py')
known = module('modes_bridge_test', HERE / 'focus_page_bridge_test.py')   # its Device, check_job, chain and fake_page


def old_bridge():
    """The base commit's bridge (from git), loaded as if it were this file (its relay is this tree's)."""
    shown = subprocess.run(['git', '-C', str(REPO), 'show', f'{BASE}:tests/e2e/lab/focus_page_bridge.py'],
                           capture_output=True, timeout=60)
    if shown.returncode:
        return None
    assert hashlib.sha256(shown.stdout).hexdigest() == OLD_BRIDGE_SHA
    spec = importlib.util.spec_from_loader('modes_old_bridge', loader=None)
    value = importlib.util.module_from_spec(spec)
    value.__file__ = str(HERE / 'focus_page_bridge.py')
    exec(compile(shown.stdout, value.__file__, 'exec'), value.__dict__)
    return value


HA_KEY = known.HA_KEY
PASSWORD = known.PASSWORD
S = known.S
OTHER = 'restore.other-databases:' + '7' * 16
DB1, DB2 = 'odoo.custom-modules:' + '1' * 16, 'odoo.custom-modules:' + '2' * 16
NODES = [{'value': 'emqx@a.lab', 'label': 'a', 'default': True}, {'value': 'emqx@b.lab', 'label': 'b'}]


def odoo_check(*, databases=(('woowtest', True), ('woowtest2', True))):
    return {'schema': 2, 'shared': [{'id': 'files.skipped', 'level': 'confirm', 'message': 'skipped', 'key': S}],
            'apps': [{'app_id': 'odoo', 'importable': True,
                      'odoo': {'databases': [{'name': name, 'ok': ok} for name, ok in databases]},
                      'choices': {'database': [{'value': name, 'label': name, 'ok': ok} for name, ok in databases]},
                      'issues': [{'id': 'restore.other-databases', 'level': 'confirm', 'message': 'other', 'key': OTHER},
                                 {'id': 'odoo.custom-modules', 'level': 'confirm', 'message': 'm1', 'key': DB1,
                                  'database': 'woowtest'},
                                 {'id': 'odoo.custom-modules', 'level': 'confirm', 'message': 'm2', 'key': DB2,
                                  'database': 'woowtest2'},
                                 {'id': 'odoo.mail', 'level': 'stop', 'message': 'only about woowtest', 'database': 'woowtest'
                                  } if dict(databases).get('woowtest') is False else
                                 {'id': 'odoo.mail', 'level': 'notice', 'message': 'mail', 'database': 'woowtest2'}]}]}


def plain_check(app, *, choices=None, issues=None):
    row = {'app_id': app, 'importable': True, 'issues': issues if issues is not None else []}
    if choices:
        row['choices'] = choices
    return {'schema': 2, 'shared': [], 'apps': [row]}


def mode_page(device, scenario):
    """The real page's effects for one app in the new modes: upload, each check of `scenario['checks']`
    ([(params extra, ha_check)]), one acknowledged import whose two linked jobs carry `scenario['first']` (params extra of
    the conversion) and `scenario['chain']` (extra of params.chain); the browser record as the page writes it."""
    def run_page(config, seconds, name):
        device.configs.append((dict(config), seconds, name))
        ha_id, app = config['ha_id'], config['apps'][0]
        if not any(row['id'] == ha_id for row in device.ha):
            device.ha.append({'id': ha_id, 'sha256': hashlib.sha256(Path(config['fixture']).read_bytes()).hexdigest()})
        for extra, result in scenario['checks']:
            check = copy.deepcopy(result)
            check['ha_backup_id'] = ha_id
            device.job('verify', {'source': 'ha', 'ha_backup_id': ha_id, 'apps': [app],
                                  'key_provided': scenario.get('key_provided', True), **extra}, 'succeeded', {'ha_check': check})
        sent = scenario.get('sent', {})
        records = known.chain(ha_id, (app,), sent, first='j20261128T020000Z-0000e000')
        for template in records:
            params, result = template['params'], template['result']
            if template['type'] == 'backup':
                params.update(scenario.get('first', {}))
                params['chain'].update(scenario.get('chain', {}))
                device.backups[result['backup_id']] = {'id': result['backup_id'], 'type': 'manual'}
            else:
                params['backup_id'] = device.jobs[-1]['result']['backup_id']
                device.backups[result['safety_backup_id']] = {'id': result['safety_backup_id'], 'type': 'safety'}
            new = device.job(template['type'], params, 'succeeded', result)
            if template['type'] == 'restore':
                device.jobs[-2]['result']['group']['next_job_id'] = new['id']
        names = ['UI real administrative Cockpit bridge reaches this device', config['texts']['select'],
                 config['texts']['lines'], config['texts']['keys']]
        browser = {'stage': 'issued-value-scan', 'failure_kind': None, 'completed': True, 'issued_values_scanned': True,
                   'checks': [{'check': n, 'ok': True} for n in names], 'confirmations': scenario['confirmations'],
                   'issued_scan_counts': {'scan_completed': True, 'observed_values': 2, 'observations_complete': True,
                                          'credential_device_hits': 0, 'credential_host_hits': 0, 'device_files': 40,
                                          'host_files': 4, 'archive_index_sidecars': 3, 'regular_json_roots': 2},
                   'wire': {'import_starts': 1}, **copy.deepcopy(scenario.get('browser', {}))}
        Path(config['result']).write_text(json.dumps(browser))
        return {'started': True, 'exit': 0, 'timed_out': False, 'interrupted': False, 'stop': 'exited', 'relay_clean': True,
                'relay_error': None, 'children_left': []}
    return run_page


class ModeCase(unittest.TestCase):
    device_name = 'woowbk-dev-d'

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.lock = self.tmp / f'{self.device_name}-mutation.lock'
        self.lock_fd = os.open(self.lock, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(os.close, self.lock_fd)
        self.fixture = self.tmp / 'fixture.tar'
        self.fixture.write_bytes(os.urandom(4096))
        for name in ('playwright.mjs', 'chrome'):
            (self.tmp / name).write_text('stand-in')
        (self.tmp / 'ev').mkdir(mode=0o700)
        self.n = 0

    def device(self):
        return known.Device(hostname=self.device_name)

    def run_bridge(self, dev, page, module=bridge, **changes):
        self.n += 1
        options = dict(device=self.device_name, apps=[changes.get('app', 'headscale')],
                       importable=[changes.get('app', 'headscale')], stops=[], fixture=self.fixture, password=PASSWORD,
                       evidence=self.tmp / 'ev' / f'page-{self.n}', deadline=time.monotonic() + 25 * 60,
                       ops=module.Ops(dev.helper, dev.wait_job, dev.root_json), lock=self.lock,
                       playwright=self.tmp / 'playwright.mjs', chromium=self.tmp / 'chrome')
        changes.pop('app', None)
        options.update(changes)
        with patch.object(module, 'run_page', page), patch.object(module, 'host_available_kib', lambda: 8 * 1024 * 1024):
            return module.import_via_page(**options)


class EarlierCallsTests(ModeCase):
    device_name = 'woowbk-dev-e'

    def test_settings_and_page_config_are_byte_identical_to_the_reviewed_bridge(self):
        old = old_bridge()
        if old is None:
            self.skipTest(f'base commit {BASE} is not in this checkout')
        for apps, importable, stops in ((['open-design'], ['open-design'], []), (['emqx', 'omnigent', 'hermes'],
                                                                               ['hermes', 'omnigent'], ['emqx'])):
            self.assertEqual(json.dumps(bridge.page_settings(apps, importable, stops)),
                             json.dumps(old.page_settings(apps, importable, stops)))
        runs, evidence = [], self.tmp / 'ev' / 'same-page'
        for which in (old, bridge):
            dev = self.device()
            with patch('time.time', lambda: 1764300000.5):
                result = self.run_bridge(dev, known.fake_page(dev), module=which, app='open-design', key=HA_KEY,
                                         evidence=evidence)
            [(config, seconds, name)] = dev.configs
            runs.append((json.dumps(config), seconds, name, result.summary, dev.calls))
            shutil.rmtree(evidence)   # the same new directory for the next bridge: its path is part of the config
        (old_config, old_seconds, old_name, old_summary, old_calls), (config, seconds, name, summary, calls) = runs
        self.assertEqual(config, old_config)                 # the same keys, values and order: the page reads the same bytes
        self.assertIn('"key": "' + HA_KEY + '"', config)
        self.assertNotIn('encrypted', config)
        self.assertNotIn('choices', config)
        self.assertEqual((name, abs(seconds - old_seconds) <= 1), (old_name, True))
        self.assertEqual(calls, old_calls)                   # the same device reads in the same order
        drop = ('elapsed_s', 'budget_s', 'page')   # times only: every judged fact is the same
        self.assertEqual({k: v for k, v in summary.items() if k not in drop},
                         {k: v for k, v in old_summary.items() if k not in drop})
        self.assertEqual({k: v for k, v in summary['page'].items() if k != 'elapsed_s'},
                         {k: v for k, v in old_summary['page'].items() if k != 'elapsed_s'})
        self.assertEqual(set(summary['gates']), set(old_summary['gates']))
        self.assertTrue(summary['passed'] and old_summary['passed'])
        self.assertEqual(bridge.check_outcome.__defaults__, (None,))   # a database line still refuses without choices
        with self.assertRaisesRegex(ValueError, 'chooses no database'):
            bridge.check_outcome(self.check_with_database(), 'ha-' + 'a' * 20, ['odoo'], ['odoo'], [])

    @staticmethod
    def check_with_database():
        job = {'type': 'verify', 'state': 'succeeded', 'params': {'source': 'ha', 'ha_backup_id': 'ha-' + 'a' * 20,
                                                                  'apps': ['odoo']},
               'result': {'ha_check': odoo_check()}}
        job['result']['ha_check']['ha_backup_id'] = 'ha-' + 'a' * 20
        return job


class UnencryptedTests(ModeCase):
    CONFIRMATIONS = {'expected_keys': {}, 'sent_keys': {}, 'lines_expected': 0, 'lines_shown': 0,
                     'check_importable': ['headscale']}
    BROWSER = {'key_step': {'stepper_key_steps': 0, 'key_fields_after_check': 0},
               'choices': {'named': {}, 'database': None, 'picks': {}, 'import_choices': {}, 'check_choices': {},
                           'rechecks': 0, 'problems': []},
               'requests': {'check': [{'key': False, 'choices': None}], 'import': {'key': False, 'choices': None}}}

    def scenario(self, **changes):
        value = {'checks': [({}, plain_check('headscale', issues=[{'id': 'headscale.api-keys', 'level': 'notice',
                                                                  'message': 'API keys stay'}]))],
                 'key_provided': False, 'sent': {}, 'first': {'key_provided': False}, 'chain': {'key_provided': False},
                 'confirmations': self.CONFIRMATIONS, 'browser': copy.deepcopy(self.BROWSER)}
        value.update(changes)
        return value

    def test_no_key_reaches_the_page_and_every_gate_including_the_engines_view_passes(self):
        dev = self.device()
        result = self.run_bridge(dev, mode_page(dev, self.scenario()), key=None, choices={})
        self.assertTrue(result.passed, (result.gates, result.summary.get('reasons')))
        self.assertEqual(set(result.gates), {'expected_outcome', 'acknowledged_exact', 'chain', 'native_units', 'own_jobs',
                                             'record', 'no_unexplained_backups', 'page_bounded', 'cleanup',
                                             'browser_flow', 'issued_scan', 'unencrypted', 'choices'})
        self.assertTrue(result.gates['unencrypted'])
        self.assertTrue(result.gates['choices'])
        self.assertIs(result.summary['unencrypted'], True)
        [(config, _seconds, _name)] = dev.configs
        self.assertNotIn('key', config)
        self.assertIs(config['encrypted'], False)
        self.assertEqual(config['choices'], {})
        self.assertEqual(result.summary['browser']['key_step'], self.BROWSER['key_step'])
        for root, _dirs, files in os.walk(self.tmp / 'ev'):
            for name in files:
                self.assertNotIn(PASSWORD.encode(), (Path(root) / name).read_bytes(), name)

    def test_a_key_step_a_sent_key_or_a_job_given_a_key_fails_the_gate(self):
        for label, change in (
                ('stepper', {'browser': dict(self.BROWSER, key_step={'stepper_key_steps': 1, 'key_fields_after_check': 0})}),
                ('field', {'browser': dict(self.BROWSER, key_step={'stepper_key_steps': 0, 'key_fields_after_check': 1})}),
                ('check request', {'browser': dict(self.BROWSER, requests={'check': [{'key': True, 'choices': None}],
                                                                           'import': {'key': False, 'choices': None}})}),
                ('import request', {'browser': dict(self.BROWSER, requests={'check': [{'key': False, 'choices': None}],
                                                                            'import': {'key': True, 'choices': None}})}),
                ('check job', {'key_provided': True}), ('conversion', {'first': {'key_provided': True}}),
                ('chain', {'chain': {'key_provided': True}})):
            with self.subTest(label):
                dev = self.device()
                result = self.run_bridge(dev, mode_page(dev, self.scenario(**change)), key=None, choices={})
                self.assertFalse(result.gates['unencrypted'])
                self.assertFalse(result.passed)

    def test_keyless_without_choices_keeps_the_earlier_choice_behaviour(self):
        dev = self.device()
        scenario = self.scenario(browser={k: v for k, v in self.BROWSER.items() if k != 'choices'})
        result = self.run_bridge(dev, mode_page(dev, scenario), key=None)
        self.assertTrue(result.passed, (result.gates, result.summary.get('reasons')))
        self.assertNotIn('choices', result.gates)
        [(config, _seconds, _name)] = dev.configs
        self.assertNotIn('choices', config)

    def test_a_short_key_or_choices_outside_the_selection_refuse_before_any_read(self):
        for label, change, pattern in (('short key', {'key': 'short'}, 'HA key or Cockpit password'),
                                       ('foreign app', {'choices': {'odoo': {'database': 'x'}}}, 'choices'),
                                       ('database of another app', {'choices': {'headscale': {'database': 'x'}}}, 'choices'),
                                       ('unsafe value', {'choices': {'headscale': {'addon': 'a b'}}}, 'choices'),
                                       ('empty kinds', {'choices': {'headscale': {}}}, 'choices')):
            with self.subTest(label):
                dev = self.device()
                with self.assertRaisesRegex(bridge.Refused, pattern):
                    self.run_bridge(dev, lambda *a: self.fail('the page must not start'), **change)
                self.assertEqual(dev.calls, [])


class OdooDatabaseTests(ModeCase):
    device_name = 'woowbk-dev-c'

    def scenario(self, database='woowtest2', **changes):
        keys = {'_shared': [S], 'odoo': sorted([OTHER, DB2 if database == 'woowtest2' else DB1])}
        wanted = {'odoo': {'database': database}}
        value = {'checks': [({}, odoo_check())], 'sent': keys, 'first': {'choices': wanted, 'odoo_database': database},
                 'chain': {'choices': wanted},
                 'confirmations': {'expected_keys': keys, 'sent_keys': keys, 'lines_expected': 4, 'lines_shown': 4,
                                   'check_importable': ['odoo']},
                 'browser': {'choices': {'named': {'odoo': {'database': database}}, 'database': database, 'picks': {},
                                         'import_choices': wanted, 'check_choices': {}, 'rechecks': 0, 'problems': []},
                             'requests': {'check': [{'key': True, 'choices': None}], 'import': {'key': True, 'choices': wanted}}}}
        value.update(changes)
        return value

    def run_odoo(self, scenario, choices=None):
        dev = self.device()
        return dev, self.run_bridge(dev, mode_page(dev, scenario), app='odoo', key=HA_KEY,
                                    choices={'odoo': {'database': 'woowtest2'}} if choices is None else choices)

    def test_the_named_database_its_lines_keys_and_the_chain_carrying_it_pass(self):
        dev, result = self.run_odoo(self.scenario())
        self.assertTrue(result.passed, (result.gates, result.summary.get('reasons')))
        self.assertEqual(result.summary['chosen'], {'database': 'woowtest2', 'import_choices': {'odoo': {'database': 'woowtest2'}},
                                                    'check_choices': {}, 'checks': 1})
        self.assertEqual(result.summary['expected_acknowledged'], {'_shared': [S], 'odoo': sorted([OTHER, DB2])})
        self.assertEqual(result.summary['confirmation_lines'], 4)   # shared, the whole-app line, woowtest2's, the page's own
        [(config, _seconds, _name)] = dev.configs
        self.assertEqual(config['choices'], {'odoo': {'database': 'woowtest2'}})
        self.assertNotIn('encrypted', config)

    def test_the_only_database_that_can_move_needs_no_name(self):
        check = odoo_check(databases=(('woowtest', False), ('woowtest2', True)))
        scenario = self.scenario(checks=[({}, check)])
        scenario['browser']['choices']['named'] = {}
        _dev, result = self.run_odoo(scenario, choices={})
        self.assertTrue(result.passed, (result.gates, result.summary.get('reasons')))
        self.assertEqual(result.summary['chosen']['database'], 'woowtest2')

    def test_another_database_anywhere_or_none_named_of_several_fails(self):
        for label, change in (
                ('conversion database', {'first': {'choices': {'odoo': {'database': 'woowtest2'}}, 'odoo_database': 'woowtest'}}),
                ('conversion choices', {'first': {'choices': {'odoo': {'database': 'woowtest'}}, 'odoo_database': 'woowtest2'}}),
                ('chain choices', {'chain': {'choices': {}}}),
                ('page record', {'browser': dict(self.scenario()['browser'], choices=dict(
                    self.scenario()['browser']['choices'], database='woowtest'))}),
                ('import request', {'browser': dict(self.scenario()['browser'], requests={
                    'check': [{'key': True, 'choices': None}], 'import': {'key': True, 'choices': None}})})):
            with self.subTest(label):
                _dev, result = self.run_odoo(self.scenario(**change))
                self.assertFalse(result.gates['choices'], label)
                self.assertFalse(result.passed)
        _dev, result = self.run_odoo(self.scenario(), choices={})   # two can move, none named
        self.assertFalse(result.gates['choices'])
        self.assertFalse(result.gates['expected_outcome'])
        self.assertIn('named none', result.summary['reasons']['choices'])
        _dev, result = self.run_odoo(self.scenario(), choices={'odoo': {'database': 'missing'}})
        self.assertIn('not one the check can move', result.summary['reasons']['choices'])

    def test_expected_lines_and_keys_follow_the_chosen_database(self):
        job = EarlierCallsTests.check_with_database()
        ha = 'ha-' + 'a' * 20
        self.assertEqual(bridge.check_outcome(job, ha, ['odoo'], ['odoo'], [], {'odoo': {'database': 'woowtest2'}}),
                         ({'_shared': [S], 'odoo': sorted([OTHER, DB2])}, 4))
        self.assertEqual(bridge.check_outcome(job, ha, ['odoo'], ['odoo'], [], {'odoo': {'database': 'woowtest'}}),
                         ({'_shared': [S], 'odoo': sorted([OTHER, DB1])}, 4))
        said = copy.deepcopy(job)
        said['result']['ha_check']['apps'][0]['issues'].append(
            {'id': 'odoo.databases-left', 'level': 'confirm', 'message': 'left', 'key': 'odoo.databases-left:' + '3' * 16})
        self.assertEqual(bridge.check_outcome(said, ha, ['odoo'], ['odoo'], [], {'odoo': {'database': 'woowtest2'}})[1], 4)
        stopped = copy.deepcopy(job)
        stopped['result']['ha_check']['apps'][0]['issues'].append(
            {'id': 'odoo.x', 'level': 'stop', 'message': 'no', 'database': 'woowtest2'})
        with self.assertRaisesRegex(ValueError, 'chosen database'):
            bridge.check_outcome(stopped, ha, ['odoo'], ['odoo'], [], {'odoo': {'database': 'woowtest2'}})


class RecheckTests(ModeCase):
    def scenario(self, **changes):
        picks = {'emqx': {'node': 'emqx@b.lab'}}
        check = plain_check('emqx', choices={'node': NODES})
        value = {'checks': [({}, check), ({'choices': picks}, check)], 'sent': {}, 'first': {'choices': picks},
                 'chain': {'choices': picks},
                 'confirmations': {'expected_keys': {}, 'sent_keys': {}, 'lines_expected': 0, 'lines_shown': 0,
                                   'check_importable': ['emqx']},
                 'browser': {'choices': {'named': picks, 'database': None, 'picks': picks, 'import_choices': picks,
                                         'check_choices': picks, 'rechecks': 1, 'problems': []},
                             'requests': {'check': [{'key': True, 'choices': None}, {'key': True, 'choices': picks}],
                                          'import': {'key': True, 'choices': picks}}}}
        value.update(changes)
        return value

    def run_emqx(self, scenario, choices=None):
        dev = self.device()
        return self.run_bridge(dev, mode_page(dev, scenario), app='emqx', key=HA_KEY,
                               choices={'emqx': {'node': 'emqx@b.lab'}} if choices is None else choices)

    def test_a_picked_node_the_recheck_and_the_import_carrying_it_pass_with_two_checks(self):
        result = self.run_emqx(self.scenario())
        self.assertTrue(result.passed, (result.gates, result.summary.get('reasons')))
        self.assertEqual(result.summary['chosen']['checks'], 2)
        self.assertEqual(len(result.summary['check_job_ids']), 2)
        self.assertEqual(len(result.check_jobs), 2)
        self.assertEqual((result.check_job.get('params') or {}).get('choices'), {'emqx': {'node': 'emqx@b.lab'}})

    def test_a_recheck_without_need_a_missing_one_or_one_with_other_picks_fails(self):
        check = plain_check('emqx', choices={'node': NODES})
        default = {'emqx': {'node': 'emqx@a.lab'}}
        result = self.run_emqx(self.scenario(), choices=default)   # the default named: no recheck was needed
        self.assertFalse(result.gates['choices'])
        self.assertFalse(result.gates['own_jobs'])
        result = self.run_emqx(self.scenario(checks=[({}, check)]))   # a non-default pick without the recheck
        self.assertFalse(result.gates['choices'])
        result = self.run_emqx(self.scenario(checks=[({}, check), ({'choices': default}, check)]))
        self.assertFalse(result.gates['choices'])
        self.assertIn('exactly the picked', result.summary['reasons']['choices'])


class PlanParityTests(unittest.TestCase):
    """The bridge plans exactly as the page does: plan_choices against focus_acceptance_ui_protocol.planChoices."""

    def js(self, cases):
        script = ("import { readFileSync } from 'node:fs'; import { pathToFileURL } from 'node:url';"
                  "const p = await import(pathToFileURL(process.argv[1]).href);"
                  "const cases = JSON.parse(readFileSync(0, 'utf8'));"
                  "console.log(JSON.stringify(cases.map(([check, named, picked]) => { const r = p.planChoices(check, named, picked);"
                  " return { problems: r.problems, clicks: r.clicks, database: r.database, import_choices: r.importChoices,"
                  " check_choices: r.checkChoices }; })));")
        proc = subprocess.run(['node', '--input-type=module', '-e', script, str(HERE / 'focus_acceptance_ui_protocol.mjs')],
                              input=json.dumps(cases).encode(), capture_output=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode()[-400:])
        return json.loads(proc.stdout)

    def test_the_same_plan_for_every_case(self):
        emqx = plain_check('emqx', choices={'node': NODES})
        single = plain_check('n8n', choices={'addon': [{'value': 'abc_n8n'}]})
        cases = [[emqx, {'emqx': {'node': 'emqx@b.lab'}}, {}], [emqx, {'emqx': {'node': 'emqx@b.lab'}}, {'emqx': {'node': 'emqx@b.lab'}}],
                 [emqx, {'emqx': {'node': 'emqx@a.lab'}}, {}], [emqx, {}, {}], [emqx, {'emqx': {'node': 'emqx@x'}}, {}],
                 [emqx, {'hermes': {'addon': 'h'}}, {}], [single, {'n8n': {'addon': 'abc_n8n'}}, {}],
                 [single, {'n8n': {'addon': 'other'}}, {}], [single, {}, {}],
                 [odoo_check(), {'odoo': {'database': 'woowtest2'}}, {}], [odoo_check(), {}, {}],
                 [odoo_check(databases=(('woowtest', False), ('woowtest2', True))), {}, {}],
                 [odoo_check(databases=(('woowtest', False), ('woowtest2', True))), {'odoo': {'database': 'woowtest'}}, {}]]
        self.assertEqual([bridge.plan_choices(check, named, picked) for check, named, picked in cases], self.js(cases))


if __name__ == '__main__':
    unittest.main()
