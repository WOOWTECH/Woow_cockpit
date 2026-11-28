"""Offline: the page import bridge's third optional input, waits (a large backup: the page's own waits for the upload, each
check and the import's result, and a page bound beyond 20 minutes), against a simulated device; and the proof that every
earlier call is unchanged: the bridge of this branch's base (f9e5af00, from git, pinned by SHA-256) hands the page the
same config, byte for byte, makes the same device reads and judges the same simulated import to the same summary, for an
encrypted import, an unencrypted one with choices and an Odoo database choice.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import unittest
from unittest.mock import patch

import focus_page_bridge_modes_test as modes   # its ModeCase, scenarios, mode_page and the bridge test's fakes

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BASE = 'f9e5af00e92392369d5fc70604c1ec0f72357759'
BASE_BRIDGE_SHA = '32369c6d972e6df583ec5ceb147bebd265558d37ad9ea53358580ea6799c084c'
bridge, known = modes.bridge, modes.known
WAITS = {'upload': 30 * 60, 'check': 10 * 60, 'result': 25 * 60}


def base_bridge():
    """The branch base's bridge (from git), loaded as if it were this file (its relay is this tree's)."""
    shown = subprocess.run(['git', '-C', str(REPO), 'show', f'{BASE}:tests/e2e/lab/focus_page_bridge.py'],
                           capture_output=True, timeout=60)
    if shown.returncode:
        return None
    assert hashlib.sha256(shown.stdout).hexdigest() == BASE_BRIDGE_SHA
    spec = __import__('importlib.util').util.spec_from_loader('waits_base_bridge', loader=None)
    value = __import__('importlib.util').util.module_from_spec(spec)
    value.__file__ = str(HERE / 'focus_page_bridge.py')
    exec(compile(shown.stdout, value.__file__, 'exec'), value.__dict__)
    return value


class EarlierCallsTests(modes.ModeCase):
    device_name = 'woowbk-dev-e'

    def same(self, page_for, **options):
        """One simulated import through the base bridge and through this one: (config, seconds, name, summary, calls)."""
        old = base_bridge()
        if old is None:
            self.skipTest(f'base commit {BASE} is not in this checkout')
        runs, evidence = [], self.tmp / 'ev' / 'same-page'
        for which in (old, bridge):
            dev = self.device()
            with patch('time.time', lambda: 1764300000.5):
                result = self.run_bridge(dev, page_for(dev), module=which, evidence=evidence, **options)
            [(config, seconds, name)] = dev.configs
            runs.append((json.dumps(config), seconds, name, result.summary, dev.calls))
            shutil.rmtree(evidence)   # the same new directory for the next bridge: its path is part of the config
        (old_config, old_seconds, old_name, old_summary, old_calls), (config, seconds, name, summary, calls) = runs
        self.assertEqual(config, old_config)                 # the same keys, values and order: the page reads the same bytes
        self.assertNotIn('waits_ms', config)
        self.assertEqual((name, abs(seconds - old_seconds) <= 1), (old_name, True))
        self.assertLessEqual(seconds, 20 * 60)
        self.assertEqual(calls, old_calls)                   # the same device reads in the same order
        drop = ('elapsed_s', 'budget_s', 'page')   # times only: every judged fact is the same
        self.assertEqual({k: v for k, v in summary.items() if k not in drop},
                         {k: v for k, v in old_summary.items() if k not in drop})
        self.assertNotIn('waits', summary)
        self.assertTrue(summary['passed'] and old_summary['passed'], summary.get('reasons'))
        return config

    def test_an_encrypted_import_is_byte_identical_to_the_base_bridge(self):
        config = self.same(lambda dev: known.fake_page(dev), app='open-design', key=modes.HA_KEY)
        self.assertIn('"key": "' + modes.HA_KEY + '"', config)

    def test_an_unencrypted_import_with_choices_is_byte_identical_to_the_base_bridge(self):
        scenario = modes.UnencryptedTests.scenario(modes.UnencryptedTests())
        config = self.same(lambda dev: modes.mode_page(dev, scenario), key=None, choices={})
        self.assertNotIn('"key"', config)

    def test_an_odoo_database_choice_is_byte_identical_to_the_base_bridge(self):
        scenario = modes.OdooDatabaseTests.scenario(modes.OdooDatabaseTests())
        self.same(lambda dev: modes.mode_page(dev, scenario), app='odoo', key=modes.HA_KEY,
                  choices={'odoo': {'database': 'woowtest2'}})

    def test_without_waits_the_bound_is_still_twenty_minutes(self):
        self.assertEqual((bridge.PAGE_SECONDS, bridge.LONG_PAGE_SECONDS), (20 * 60, 60 * 60))
        for page_seconds in (20 * 60 + 1, 50 * 60):
            dev = self.device()
            with self.assertRaisesRegex(bridge.Refused, 'not enough time'):
                self.run_bridge(dev, lambda *a: self.fail('the page must not start'), app='open-design',
                                key=modes.HA_KEY, page_seconds=page_seconds, deadline=time.monotonic() + 3600)
            self.assertEqual(dev.calls, [])
        self.assertEqual(bridge.page_settings(['nextcloud'], ['nextcloud'], []),
                         bridge.page_settings(['nextcloud'], ['nextcloud'], [], waits=None))


class WaitsTests(modes.ModeCase):
    device_name = 'woowbk-dev-e'

    def run_waits(self, dev, **changes):
        options = dict(app='open-design', key=modes.HA_KEY, page_seconds=50 * 60, waits=dict(WAITS),
                       deadline=time.monotonic() + 55 * 60)
        options.update(changes)
        return self.run_bridge(dev, known.fake_page(dev), **options)

    def test_the_page_gets_its_own_waits_and_the_longer_bound_and_nothing_else_changes(self):
        dev = self.device()
        result = self.run_waits(dev)
        self.assertTrue(result.passed, (result.gates, result.summary.get('reasons')))
        [(config, seconds, _name)] = dev.configs
        self.assertEqual(config['waits_ms'], {'upload': 1800000, 'check': 600000, 'result': 1500000})
        self.assertEqual(seconds, 50 * 60)
        self.assertEqual(result.summary['waits'], WAITS)
        self.assertEqual(result.summary['budget_s'], 50 * 60)
        # Everything else of the config is what the same call without waits gives.
        plain = self.device()
        self.run_bridge(plain, known.fake_page(plain), app='open-design', key=modes.HA_KEY,
                        evidence=self.tmp / 'ev' / 'plain')
        [(before, _seconds, _name)] = plain.configs
        self.assertEqual({k: v for k, v in config.items() if k not in ('waits_ms', 'evidence', 'result', 'since')},
                         {k: v for k, v in before.items() if k not in ('evidence', 'result', 'since')})
        self.assertEqual(set(result.gates), {'expected_outcome', 'acknowledged_exact', 'chain', 'native_units', 'own_jobs',
                                             'record', 'no_unexplained_backups', 'page_bounded', 'cleanup',
                                             'browser_flow', 'issued_scan'})

    def test_less_time_than_the_bound_gives_the_page_what_is_left(self):
        dev = self.device()
        self.run_waits(dev, deadline=time.monotonic() + 40 * 60)
        self.assertTrue(39 * 60 - 5 <= dev.configs[0][1] <= 39 * 60)

    def test_malformed_waits_or_a_bound_they_do_not_fit_refuse_before_any_read(self):
        for label, change in (('missing', {'waits': {'upload': 1800, 'check': 600}}),
                              ('extra', {'waits': dict(WAITS, scan=60)}),
                              ('bool', {'waits': dict(WAITS, check=True)}),
                              ('float', {'waits': dict(WAITS, check=600.0)}),
                              ('too short', {'waits': dict(WAITS, check=59)}),
                              ('too long', {'waits': dict(WAITS, upload=3601)}),
                              ('not a dict', {'waits': [1800, 600, 1500]}),
                              ('a wait longer than the bound', {'page_seconds': 29 * 60}),
                              ('a bound beyond an hour', {'page_seconds': 61 * 60, 'deadline': time.monotonic() + 90 * 60})):
            with self.subTest(label):
                dev = self.device()
                with self.assertRaises(bridge.Refused):
                    self.run_bridge(dev, lambda *a: self.fail('the page must not start'),
                                    **dict(dict(app='open-design', key=modes.HA_KEY, page_seconds=50 * 60,
                                                waits=dict(WAITS), deadline=time.monotonic() + 55 * 60), **change))
                self.assertEqual(dev.calls, [])

    def test_the_page_protocol_reads_the_bridges_waits_and_refuses_others(self):
        script = ("import { readFileSync } from 'node:fs'; import { pathToFileURL } from 'node:url';"
                  "const { pageExpectations } = await import(pathToFileURL(process.argv[1]).href);"
                  "const out = []; for (const config of JSON.parse(readFileSync(0, 'utf8'))) {"
                  " try { out.push(pageExpectations(config).waits_ms ?? null); } catch { out.push('refused'); } }"
                  "console.log(JSON.stringify(out));")
        good = bridge.page_settings(['nextcloud'], ['nextcloud'], [], waits=WAITS)
        plain = bridge.page_settings(['nextcloud'], ['nextcloud'], [])
        configs = [dict(good, device='woowbk-dev-e'), dict(plain, device='woowbk-dev-e')] + [
            dict(good, device='woowbk-dev-e', waits_ms=bad) for bad in (
                {'upload': 1800000, 'check': 600000}, dict(good['waits_ms'], scan=60000), dict(good['waits_ms'], check=59999),
                dict(good['waits_ms'], upload=3600001), dict(good['waits_ms'], result=1.5e6 + 0.5), [1, 2, 3], None)]
        proc = subprocess.run(['node', '--input-type=module', '-e', script, str(HERE / 'focus_acceptance_ui_protocol.mjs')],
                              input=json.dumps(configs).encode(), capture_output=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode()[-300:])
        self.assertEqual(json.loads(proc.stdout), [{'upload': 1800000, 'check': 600000, 'result': 1500000}, None]
                         + ['refused'] * 7)


if __name__ == '__main__':
    unittest.main()
