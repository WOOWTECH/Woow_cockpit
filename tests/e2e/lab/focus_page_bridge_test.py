"""Offline gates of the page import bridge and the device-general transport; no lab device, browser or labpodman.

The device side is a simulation (Device below) and the page is either a simulation of its effects (fake_page) or a tiny
node stand-in that only plays the page's process behaviour (exit, SIGTERM, a stubborn process group). The relay runs
for real on 127.0.0.1 with its exec command replaced by a local echo program.
"""
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BASE = 'b058df278d661cc6195cd40936ff6494036c63a1'
OLD_RELAY_SHA = '51b1f531162fc421eccf2bb07727726414cf7fa018e30cb78b56381b29e0c4ae'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


bridge = module('prepared_page_bridge', 'focus_page_bridge.py')
relay = bridge.relay
DEVICE = 'woowbk-dev-e'
APP = 'open-design'
HA_KEY = 'FAKE-HA-KEY-0123456789-ABCDEFGHIJ'
PASSWORD = 'generated-cockpit-pass-3333'
S = 'files.skipped:' + '1' * 16
OD1, OD2 = 'opendesign.unknown-entries:' + '2' * 16, 'opendesign.other-entries:' + '3' * 16
ECHO = 'import os\nwhile True:\n    b = os.read(0, 65536)\n    if not b: break\n    os.write(1, b)\n'


def tree_page():
    return {name: hashlib.sha256((REPO / 'backup' / name).read_bytes()).hexdigest() for name in bridge.PAGE_FILES}


def old_relay():
    """The base commit's relay module (from git), or None when this checkout has no history."""
    shown = subprocess.run(['git', '-C', str(REPO), 'show', f'{BASE}:tests/e2e/lab/focus_acceptance_ui_relay.py'],
                           capture_output=True, timeout=60)
    if shown.returncode:
        return None
    assert hashlib.sha256(shown.stdout).hexdigest() == OLD_RELAY_SHA
    space = {'__name__': 'base_relay'}
    exec(compile(shown.stdout, 'base_relay.py', 'exec'), space)
    return space


# ---------------------------------------------------------------- transport and locks

class DeviceTransportTests(unittest.TestCase):
    def test_default_transport_is_the_reviewed_dev_d_one(self):
        self.assertEqual(relay.command(), [str(relay.LP), 'exec', '-i', '--user', 'devadmin', 'woowbk-dev-d', 'python3',
                                           '-I', '-c', relay.REMOTE])
        self.assertEqual(relay.command('woowbk-dev-d'), relay.command())
        self.assertEqual(relay.Relay().device, 'woowbk-dev-d')
        base = old_relay()
        if base is None:
            self.skipTest(f'base commit {BASE} is not in this checkout')
        self.assertEqual(base['command'](), relay.command())
        self.assertEqual(base['REMOTE'], relay.REMOTE)

    def test_a_named_lab_device_and_nothing_else(self):
        cmd = relay.command(DEVICE)
        self.assertEqual(cmd[:7], [str(relay.LP), 'exec', '-i', '--user', 'devadmin', DEVICE, 'python3'])
        self.assertEqual(cmd[7:], ['-I', '-c', relay.REMOTE])
        self.assertEqual(relay.Relay(DEVICE).device, DEVICE)
        for bad in ('dev-e', 'woowbk-dev-E', 'woowbk-dev-ee', 'woowbk-dev-e;id', 'woowbk-dev-e\n', '', None, 5):
            with self.subTest(device=bad):
                with self.assertRaises(ValueError):
                    relay.command(bad)
                with self.assertRaises(ValueError):
                    relay.Relay(bad)
                with self.assertRaises(ValueError):
                    bridge.lock_path(bad)

    def test_a_real_relay_starts_one_exec_child_per_connection_for_its_device_and_reaps_them(self):
        devices = []

        def command(device='woowbk-dev-d'):
            devices.append(device)
            return [sys.executable, '-I', '-c', ECHO]

        before = set(bridge.child_pids())
        with patch.object(relay, 'command', command):
            channel = relay.Relay(DEVICE)
            with channel:
                port = int(channel.base.rsplit(':', 1)[1])
                for n in range(3):
                    with socket.create_connection(('127.0.0.1', port), timeout=10) as conn:
                        conn.sendall(b'ping-%d' % n)
                        conn.shutdown(socket.SHUT_WR)
                        data = b''
                        while chunk := conn.recv(65536):
                            data += chunk
                    self.assertEqual(data, b'ping-%d' % n)
                bridge.drain(channel, 10)   # as run_page does once the browser is gone
        self.assertEqual(devices, [DEVICE] * 3)
        self.assertEqual(channel.connections, 3)
        self.assertEqual(channel.children, set())
        self.assertFalse(channel.thread.is_alive())
        self.assertLessEqual(set(bridge.child_pids()), before)


class LockTests(unittest.TestCase):
    def test_each_device_has_its_own_mutation_lock(self):
        self.assertEqual(bridge.lock_path('woowbk-dev-e'), '/tmp/woowbk-dev-e-mutation.lock')
        self.assertEqual(bridge.lock_path('woowbk-dev-d'), '/tmp/woowbk-dev-d-mutation.lock')
        self.assertEqual(bridge.lock_path('woowbk-dev-c'), '/tmp/woowbk-dev-c-mutation.lock')

    def test_only_this_process_holding_the_exclusive_lock_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'device.lock'
            self.assertFalse(bridge.lock_held(path))   # absent
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                self.assertFalse(bridge.lock_held(path))   # nobody holds it
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertTrue(bridge.lock_held(path))
                self.assertFalse(bridge.lock_held(path, pid=os.getpid() + 100000))
                self.assertFalse(bridge.lock_held(Path(tmp) / 'other.lock'))
                fcntl.flock(fd, fcntl.LOCK_UN)
                holder = subprocess.Popen([sys.executable, '-I', '-c', 'import fcntl,os,sys,time\n'
                                           'fd=os.open(sys.argv[1], os.O_RDWR); fcntl.flock(fd, fcntl.LOCK_EX)\n'
                                           'print("held", flush=True); time.sleep(60)', str(path)],
                                          stdout=subprocess.PIPE)
                try:
                    self.assertEqual(holder.stdout.readline().strip(), b'held')
                    self.assertFalse(bridge.lock_held(path))                 # another process holds it
                    self.assertTrue(bridge.lock_held(path, pid=holder.pid))
                finally:
                    holder.kill()
                    holder.wait()
                    holder.stdout.close()
            finally:
                os.close(fd)
            st = os.stat(path)
            ident = '%02x:%02x:%d' % (os.major(st.st_dev), os.minor(st.st_dev), st.st_ino)
            me = os.getpid()
            for text in (f'1: -> FLOCK  ADVISORY  WRITE {me} {ident} 0 EOF',      # waiting, not holding
                         f'1: FLOCK  ADVISORY  READ {me} {ident} 0 EOF',          # shared
                         f'1: POSIX  ADVISORY  WRITE {me} {ident} 0 EOF'):        # another lock kind
                with self.subTest(text=text):
                    self.assertFalse(bridge.lock_held(path, locks=text))
            self.assertTrue(bridge.lock_held(path, locks=f'7: FLOCK  ADVISORY  WRITE {me} {ident} 0 EOF'))


# ---------------------------------------------------------------- what the page is told

class PageSettingsTests(unittest.TestCase):
    def parse(self, settings):
        config = {'ha_id': 'ha-' + 'f' * 20, 'result': '/private/browser.json', 'base': 'https://127.0.0.1:1',
                  'device': DEVICE, **settings}
        script = ("import { readFileSync } from 'node:fs'; import { pathToFileURL } from 'node:url';"
                  "const { pageExpectations } = await import(pathToFileURL(process.argv[1]).href);"
                  "console.log(JSON.stringify(pageExpectations(JSON.parse(readFileSync(0, 'utf8')))));")
        proc = subprocess.run(['node', '--input-type=module', '-e', script, str(HERE / 'focus_acceptance_ui_protocol.mjs')],
                              input=json.dumps(config).encode(), capture_output=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode()[-300:])
        return json.loads(proc.stdout)

    def test_the_page_accepts_the_bridge_settings_for_one_app_and_for_a_stopped_one(self):
        parsed = self.parse(bridge.page_settings([APP], [APP], []))
        self.assertEqual((parsed['apps'], parsed['importable'], parsed['blocked'], parsed['importApps'], parsed['device']),
                         ([APP], [APP], [], [APP], DEVICE))
        self.assertEqual(parsed['result_rows'], [[APP, 'imported']])
        self.assertIs(parsed['exact'], True)
        self.assertEqual(parsed['texts']['select'], 'UI selects exactly open-design')
        three = bridge.page_settings(['emqx', 'omnigent', 'hermes'], ['hermes', 'omnigent'], ['emqx'])
        parsed = self.parse(three)
        self.assertEqual((parsed['importable'], parsed['blocked']), (['omnigent', 'hermes'], ['emqx']))
        self.assertEqual(parsed['result_rows'], [['omnigent', 'imported'], ['hermes', 'imported'], ['emqx', 'excluded']])
        self.assertEqual(parsed['texts']['view'], 'UI check shows omnigent, hermes importable and emqx stopped')

    def test_inconsistent_selections_are_refused(self):
        for apps, importable, stops in (([], [], []), ([APP], [], [APP]), ([APP], [APP], [APP]), ([APP, 'emqx'], [APP], []),
                                        ([APP], ['emqx'], []), (['Open-Design'], ['Open-Design'], []), ([APP, APP], [APP], []),
                                        ('open-design', [APP], [])):
            with self.subTest(apps=apps, importable=importable, stops=stops), self.assertRaises(ValueError):
                bridge.page_settings(apps, importable, stops)
        many = ['app-%02d-with-a-long-name' % n for n in range(8)]
        with self.assertRaisesRegex(ValueError, 'too long'):
            bridge.page_settings(many, many, [])


# ---------------------------------------------------------------- the check, the keys, the chain

def check_job(ha_id, *, apps=None, importable=True, issues=None, shared=None, job_id='j20261128T010000Z-0000c0c0'):
    apps = apps or [{'app_id': APP, 'importable': importable, 'issues': issues if issues is not None else (
        [{'id': 'opendesign.unknown-entries', 'level': 'confirm', 'message': 'unknown entries', 'items': ['x'], 'more': 0,
          'key': OD1},
         {'id': 'opendesign.unknown-entries', 'level': 'confirm', 'message': 'the same again', 'items': [], 'more': 0,
          'key': OD1},
         {'id': 'opendesign.other-entries', 'level': 'confirm', 'message': 'other', 'items': [], 'more': 0, 'key': OD2},
         {'id': 'opendesign.links-copied', 'level': 'auto', 'message': 'links', 'items': [], 'more': 0},
         {'id': 'opendesign.project-folders', 'level': 'notice', 'message': 'folders', 'items': [], 'more': 0}]
        if importable else [{'id': 'opendesign.no-database', 'level': 'stop', 'message': 'no database', 'action': 'x',
                             'items': [], 'more': 0}]), APP: {'projects': 12}}]
    return {'id': job_id, 'type': 'verify', 'state': 'succeeded',
            'params': {'source': 'ha', 'ha_backup_id': ha_id, 'apps': [row['app_id'] for row in apps], 'key_provided': True},
            'result': {'ha_check': {'schema': 2, 'ha_backup_id': ha_id, 'apps': apps,
                                    'shared': shared if shared is not None else [
                                        {'id': 'files.skipped', 'level': 'confirm', 'message': 'skipped', 'items': ['y'],
                                         'more': 0, 'key': S}]}}}


HA = 'ha-' + 'a' * 20
EXPECTED = {'_shared': [S], APP: sorted([OD1, OD2])}


class CheckOutcomeTests(unittest.TestCase):
    def test_keys_and_lines_come_from_the_check_itself(self):
        expected, lines = bridge.check_outcome(check_job(HA), HA, [APP], [APP], [])
        self.assertEqual(expected, EXPECTED)
        self.assertEqual(lines, 4)   # the shared line and three of open-design (one key twice)
        job = check_job(HA, issues=[{'id': 'x.y', 'level': 'notice', 'message': 'n'}], shared=[])
        self.assertEqual(bridge.check_outcome(job, HA, [APP], [APP], []), ({}, 0))   # a valid zero
        stopped = {'app_id': 'emqx', 'importable': False, 'issues': [{'id': 'failure.x', 'level': 'stop', 'message': 'm'},
                                                                     {'id': 'e.c', 'level': 'confirm', 'message': 'c',
                                                                      'key': 'emqx.c:' + '4' * 16}]}
        both = check_job(HA)
        both['result']['ha_check']['apps'].append(stopped)
        both['params']['apps'].append('emqx')
        expected, lines = bridge.check_outcome(both, HA, [APP, 'emqx'], [APP], ['emqx'])
        self.assertEqual((expected, lines), (EXPECTED, 4))   # a stopped app's lines are never confirmed

    def test_any_other_outcome_or_an_unkeyed_line_refuses(self):
        def broken(how):
            job = check_job(HA)
            result = job['result']['ha_check']
            row = result['apps'][0]
            if how == 'not-importable':
                row['importable'] = False
            elif how == 'stop-in-importable':
                row['issues'].append({'id': 'x.y', 'level': 'stop', 'message': 'm'})
            elif how == 'shared-stop':
                result['shared'].append({'id': 'x.y', 'level': 'stop', 'message': 'm'})
            elif how == 'no-key':
                del row['issues'][0]['key']
            elif how == 'bad-key':
                row['issues'][2]['key'] = 'not a key'
            elif how == 'no-message':
                row['issues'][2]['message'] = ''
            elif how == 'database':
                row['issues'][2]['database'] = 'db1'
            elif how == 'level':
                row['issues'].append({'id': 'x.y', 'level': 'urgent', 'message': 'm'})
            elif how == 'extra-app':
                result['apps'].append(dict(row, app_id='emqx'))
            elif how == 'other-app':
                row['app_id'] = 'emqx'
            elif how == 'other-backup':
                result['ha_backup_id'] = 'ha-' + '0' * 20
            elif how == 'params-backup':
                job['params']['ha_backup_id'] = 'ha-' + '0' * 20
            elif how == 'params-apps':
                job['params']['apps'] = [APP, 'emqx']
            elif how == 'schema':
                result['schema'] = 1
            elif how == 'failed':
                job['state'] = 'failed'
            elif how == 'not-verify':
                job['type'] = 'backup'
            elif how == 'issues':
                row['issues'] = None
            return job
        for how in ('not-importable', 'stop-in-importable', 'shared-stop', 'no-key', 'bad-key', 'no-message', 'database',
                    'level', 'extra-app', 'other-app', 'other-backup', 'params-backup', 'params-apps', 'schema', 'failed',
                    'not-verify', 'issues'):
            with self.subTest(how=how), self.assertRaises(ValueError):
                bridge.check_outcome(broken(how), HA, [APP], [APP], [])
        for job in (None, {}, []):
            with self.assertRaises(ValueError):
                bridge.check_outcome(job, HA, [APP], [APP], [])
        # Expected stopped, but the check calls it importable; a stopped app without any stop line.
        both = check_job(HA, apps=[{'app_id': APP, 'importable': True, 'issues': []},
                                   {'app_id': 'emqx', 'importable': True, 'issues': []}])
        with self.assertRaisesRegex(ValueError, 'expected it stopped'):
            bridge.check_outcome(both, HA, [APP, 'emqx'], [APP], ['emqx'])
        quiet = check_job(HA, apps=[{'app_id': APP, 'importable': True, 'issues': []},
                                    {'app_id': 'emqx', 'importable': False, 'issues': [{'level': 'notice', 'message': 'm'}]}])
        with self.assertRaisesRegex(ValueError, 'without a stop line'):
            bridge.check_outcome(quiet, HA, [APP, 'emqx'], [APP], ['emqx'])


def chain(ha_id=HA, apps=(APP,), sent=None, *, first='j20261128T010100Z-0000a000'):
    sent = copy.deepcopy(EXPECTED if sent is None else sent)
    records, ids = [], ['j20261128T0101%02dZ-0000a%03d' % (n, n) for n in range(2 * len(apps))]
    ids[0] = first
    for index, app in enumerate(apps):
        own = {group: keys for group, keys in sent.items() if group in (app, '_shared')}
        convert = {'id': ids[2 * index], 'type': 'backup', 'state': 'succeeded',
                   'params': {'source': 'ha', 'ha_backup_id': ha_id, 'apps': [app], 'test_mode': False,
                              **({'acknowledged': own} if own else {}),
                              'group': {'kind': 'ha-import', 'index': index, 'count': len(apps)},
                              'chain': {'apps': list(apps), 'test_mode': False, 'then_restore': True,
                                        'acknowledged': copy.deepcopy(sent)}},
                   'result': {'backup_id': '20261128T0102%02dZ-0b0b0b%02d' % (index, index),
                              'group': {'next_job_id': ids[2 * index + 1], 'results': []}}}
        restore = {'id': ids[2 * index + 1], 'type': 'restore', 'state': 'succeeded',
                   'params': {'backup_id': convert['result']['backup_id'], 'apps': [app], 'ha_backup_id': ha_id},
                   'result': {'safety_backup_id': '20261128T0103%02dZ-0c0c0c%02d' % (index, index), 'rolled_back': False,
                              'health': [{'status': 'ok'}],
                              'group': {'next_job_id': ids[2 * index + 2] if 2 * index + 2 < len(ids) else None,
                                        'results': [{'app_id': a, 'status': 'imported'} for a in apps[:index + 1]]}}}
        records += [convert, restore]
    return records


class AcknowledgementTests(unittest.TestCase):
    def test_each_listed_key_exactly_once_in_the_request_and_the_import(self):
        first = chain()[0]
        self.assertTrue(bridge.acknowledged_exactly(EXPECTED, first['params'], copy.deepcopy(EXPECTED)))
        none = chain(sent={})[0]
        self.assertTrue(bridge.acknowledged_exactly({}, none['params'], {}))
        self.assertFalse(bridge.acknowledged_exactly({}, none['params'], None))   # the page must have seen its request
        # Two importable apps: the first conversion keeps only its own app's keys and the shared ones.
        two = {'_shared': [S], APP: [OD1], 'emqx': ['emqx.c:' + '4' * 16]}
        first = chain(apps=(APP, 'emqx'), sent=two)[0]
        self.assertEqual(first['params']['acknowledged'], {'_shared': [S], APP: [OD1]})
        self.assertTrue(bridge.acknowledged_exactly(two, first['params'], copy.deepcopy(two)))
        first['params']['acknowledged'] = copy.deepcopy(two)
        self.assertFalse(bridge.acknowledged_exactly(two, first['params'], copy.deepcopy(two)))

    def test_missing_extra_duplicate_or_regrouped_keys_refuse_wherever_they_are(self):
        wrong = {'missing': {'_shared': [S], APP: [OD1]}, 'extra': {'_shared': [S], APP: sorted([OD1, OD2, 'a.b:' + '5' * 16])},
                 'duplicate': {'_shared': [S], APP: [OD1, OD1, OD2]}, 'regrouped': {APP: sorted([S, OD1, OD2])},
                 'empty-group': dict(EXPECTED, emqx=[]), 'bad-key': {'_shared': ['nope'], APP: sorted([OD1, OD2])},
                 'not-a-list': {'_shared': S, APP: sorted([OD1, OD2])}}
        for where in ('params', 'chain', 'sent'):
            for name, value in wrong.items():
                with self.subTest(where=where, name=name):
                    params, sent = chain()[0]['params'], copy.deepcopy(EXPECTED)
                    if where == 'params':
                        params['acknowledged'] = value
                    elif where == 'chain':
                        params['chain']['acknowledged'] = value
                    else:
                        sent = value
                    self.assertFalse(bridge.acknowledged_exactly(EXPECTED, params, sent))
        params = chain()[0]['params']
        del params['chain']
        self.assertFalse(bridge.acknowledged_exactly(EXPECTED, params, copy.deepcopy(EXPECTED)))


class ChainTests(unittest.TestCase):
    def test_two_linked_jobs_per_importable_app_in_the_engines_order(self):
        self.assertTrue(bridge.chain_complete(chain(), HA, [APP]))
        self.assertTrue(bridge.chain_complete(chain(apps=('omnigent', 'hermes')), HA, ['hermes', 'omnigent']))
        records = chain()
        self.assertEqual(bridge.created_by(records), ['20261128T010200Z-0b0b0b00', '20261128T010300Z-0c0c0c00'])
        kept = copy.deepcopy(records)   # a restore that kept a whole database service first (kept.py S4): its copy too
        kept[1]['result']['kept'] = {APP: {'backup_id': '20261128T010400Z-0d0d0d00', 'put_back': [], 'not_put_back': []},
                                     'broken': 'not a view'}
        self.assertEqual(bridge.created_by(kept), ['20261128T010200Z-0b0b0b00', '20261128T010300Z-0c0c0c00',
                                                   '20261128T010400Z-0d0d0d00'])
        kept[0]['result']['kept'] = {APP: {'backup_id': '20261128T010500Z-0e0e0e00'}}   # only a restore's result counts
        self.assertNotIn('20261128T010500Z-0e0e0e00', bridge.created_by(kept))
        self.assertEqual(bridge.by_app(records, 'backup', 'backup_id'), {APP: '20261128T010200Z-0b0b0b00'})
        self.assertEqual(bridge.by_app(records, 'restore', 'safety_backup_id'), {APP: '20261128T010300Z-0c0c0c00'})

    def test_other_layouts_states_links_or_results_refuse(self):
        def broken(how):
            records = chain()
            first, second = records
            if how == 'three':
                records.append(dict(second, id='j20261128T010199Z-0000a999'))
            elif how == 'one':
                records = records[:1]
            elif how == 'order':
                records = [second, first]
            elif how == 'restore-failed':
                second['state'] = 'failed'
            elif how == 'rolled-back':
                second['state'] = 'rolled-back'
            elif how == 'link':
                first['result']['group']['next_job_id'] = 'j20261128T010199Z-0000a999'
            elif how == 'continues':
                second['result']['group']['next_job_id'] = 'j20261128T010199Z-0000a999'
            elif how == 'other-backup':
                second['params']['backup_id'] = '20261128T000000Z-00000000'
            elif how == 'other-ha':
                first['params']['ha_backup_id'] = 'ha-' + '0' * 20
            elif how == 'test-mode':
                first['params']['test_mode'] = True
            elif how == 'convert-only':
                first['params']['chain']['then_restore'] = False
            elif how == 'chain-apps':
                first['params']['chain']['apps'] = [APP, 'emqx']
            elif how == 'result-status':
                second['result']['group']['results'][0]['status'] = 'rolled-back'
            elif how == 'result-extra':
                second['result']['group']['results'].append({'app_id': 'emqx', 'status': 'imported'})
            elif how == 'duplicate-id':
                second['id'] = first['id']
            elif how == 'bad-id':
                second['id'] = 'job-2'
            return records
        for how in ('three', 'one', 'order', 'restore-failed', 'rolled-back', 'link', 'continues', 'other-backup', 'other-ha',
                    'test-mode', 'convert-only', 'chain-apps', 'result-status', 'result-extra', 'duplicate-id', 'bad-id'):
            with self.subTest(how=how):
                self.assertFalse(bridge.chain_complete(broken(how), HA, [APP]))
        self.assertFalse(bridge.chain_complete([], HA, [APP]))
        self.assertFalse(bridge.chain_complete(chain(), HA, [APP, 'emqx']))

    def test_native_records_must_agree_and_share_the_first_unit(self):
        records = chain()
        unit = 'woowtech-backup-' + records[0]['id'] + '.service'
        native = [{'id': r['id'], 'type': r['type'], 'state': r['state'], 'unit': unit} for r in records]
        self.assertTrue(bridge.native_units_ok(native, records))
        for change in ({'unit': 'woowtech-backup-' + records[1]['id'] + '.service'}, {'state': 'failed'}, {'id': 'j1'}):
            bad = copy.deepcopy(native)
            bad[1].update(change)
            self.assertFalse(bridge.native_units_ok(bad, records))
        self.assertFalse(bridge.native_units_ok(native[:1], records))
        self.assertFalse(bridge.native_units_ok(None, records))
        compile(bridge.NATIVE_UNITS, '<native units>', 'exec')
        compile(bridge.PRECONDITIONS, '<preconditions>', 'exec')


class PreconditionAndOpsTests(unittest.TestCase):
    facts = {'cockpit_socket': True, 'hostname': DEVICE, 'devadmin_uid': 1000, 'headroom': 2 * 1024 ** 3}

    def test_every_device_precondition_is_named(self):
        good = dict(self.facts, page=tree_page())
        self.assertEqual(bridge.preconditions_failed(good, REPO, DEVICE, bridge.DEVICE_HEADROOM), [])
        changes = {'installed page differs from the tree': {'page': dict(tree_page(), **{'backup.js': '0' * 64})},
                   'cockpit.socket not active': {'cockpit_socket': False},
                   'device hostname is not its name': {'hostname': 'woowbk-dev-d'},
                   'no devadmin account': {'devadmin_uid': None},
                   'device memory headroom below 1280 MiB': {'headroom': 1024 ** 3}}
        for name, change in changes.items():
            with self.subTest(name=name):
                self.assertEqual(bridge.preconditions_failed(dict(good, **change), REPO, DEVICE, bridge.DEVICE_HEADROOM), [name])
        self.assertIn('device memory headroom below 1280 MiB',
                      bridge.preconditions_failed(dict(good, headroom=None), REPO, DEVICE, bridge.DEVICE_HEADROOM))
        self.assertEqual(len(bridge.preconditions_failed(None, REPO, DEVICE, bridge.DEVICE_HEADROOM)), 5)

    def test_only_read_only_commands_and_the_two_fixed_programs_pass(self):
        calls = []
        ops = bridge.Ops(helper=lambda c, r=None: calls.append(('helper', c)) or {},
                         wait_job=lambda j, t: calls.append(('wait', j)) or {},
                         root_json=lambda s, r: calls.append(('root', s[:10])) or {})
        for command in ('status', 'list', 'jobs'):
            ops.helper(command)
        ops.helper('job-status', {'job_id': 'j20261128T010000Z-00000000'})
        for command in ('delete', 'ha-delete', 'restore-start', 'ha-import-start', 'ha-convert-start', 'upload-begin',
                        'catalog-install', 'job-cancel', 'key-init'):
            with self.subTest(command=command), self.assertRaises(PermissionError):
                ops.helper(command, {})
        with self.assertRaises(PermissionError):
            ops.root_json('import os; os.remove("/x")', {})
        with self.assertRaises(ValueError):
            ops.wait_job('../x', 1)
        ops.root_json(bridge.PRECONDITIONS, {})
        ops.wait_job('j20261128T010000Z-00000000', 5)
        self.assertEqual([c for c in calls if c[0] == 'helper'], [('helper', c) for c in ('status', 'list', 'jobs', 'job-status')])
        self.assertEqual(len(calls), 6)


# ---------------------------------------------------------------- the page process itself

PAGES = {
    'ok': r'''
import { readFileSync, writeFileSync } from 'node:fs';
const config = JSON.parse(readFileSync(0, 'utf8'));
const stat = readFileSync('/proc/self/stat', 'utf8'); const f = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
writeFileSync(config.fake_log, JSON.stringify({ argv: process.argv.slice(2), pid: process.pid, pgrp: Number(f[2]),
  sid: Number(f[3]), key: config.key, password: config.password, base: config.base, device: config.device }));
writeFileSync(config.result, JSON.stringify({ completed: true, checks: [{ check: 'UI fake', ok: true }] }));
''',
    'hang': r'''
import { readFileSync, writeFileSync } from 'node:fs';
const config = JSON.parse(readFileSync(0, 'utf8'));
process.once('SIGTERM', () => { writeFileSync(config.result, JSON.stringify({ completed: false,
  checks: [{ check: 'UI controller runtime stayed bounded', ok: false }] })); process.exit(124); });
writeFileSync(config.fake_log, JSON.stringify({ pid: process.pid }));
setInterval(() => {}, 1000);
''',
    'stubborn': r'''
import { readFileSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
const config = JSON.parse(readFileSync(0, 'utf8'));
process.on('SIGTERM', () => {});
const child = spawn('sleep', ['300'], { stdio: 'ignore' });
writeFileSync(config.fake_log, JSON.stringify({ pid: process.pid, grandchild: child.pid }));
setInterval(() => {}, 1000);
''',
}


def gone(pid, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            state = Path(f'/proc/{pid}/stat').read_text()
        except OSError:
            return True
        if state[state.rfind(')') + 2] == 'Z' and state.split()[3] != str(os.getpid()):
            return True   # a zombie of some other reaper: dead
        time.sleep(0.1)
    return False


class RunPageTests(unittest.TestCase):
    def run_fake(self, kind, seconds=60, before_stop=None):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        page = tmp / f'{kind}.mjs'
        page.write_text(PAGES[kind])
        log = tmp / 'log.json'
        config = {'key': HA_KEY, 'password': PASSWORD, 'device': DEVICE, 'result': str(tmp / 'browser.json'),
                  'fake_log': str(log)}
        devices = []

        def command(device='woowbk-dev-d'):
            devices.append(device)
            return [sys.executable, '-I', '-c', ECHO]

        hits = []
        previous = signal.signal(signal.SIGTERM, lambda *_: hits.append('test handler'))
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        guard = signal.getsignal(signal.SIGTERM)
        timer = None
        if before_stop:
            def stop_when_ready():
                deadline = time.monotonic() + 30
                while not log.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                time.sleep(0.3)
                os.kill(os.getpid(), signal.SIGTERM)
            timer = threading.Thread(target=stop_when_ready, daemon=True)
            timer.start()
        before = set(bridge.child_pids())
        with patch.object(bridge, 'PAGE', page), patch.object(relay, 'command', command), \
                patch.object(bridge, 'TERM_GRACE', 2):
            outcome = bridge.run_page(config, seconds, DEVICE)
        if timer:
            timer.join(5)
        self.assertIs(signal.getsignal(signal.SIGTERM), guard)   # the previous handler is back
        self.assertEqual(hits, [])                                # a SIGTERM during the page was the bridge's
        info = json.loads(log.read_text()) if log.exists() else {}
        self.assertLessEqual(set(outcome['children_left']), before)
        self.assertNotIn(info.get('pid'), outcome['children_left'])
        self.assertEqual(devices, [])   # no browser connection, so no exec child; the relay still ran for this device
        result = json.loads((tmp / 'browser.json').read_text()) if (tmp / 'browser.json').exists() else None
        return outcome, info, result

    def test_a_finished_page_got_its_secrets_on_stdin_only_in_its_own_session(self):
        outcome, info, result = self.run_fake('ok')
        self.assertEqual({k: outcome[k] for k in ('started', 'exit', 'timed_out', 'interrupted', 'stop', 'relay_clean')},
                         {'started': True, 'exit': 0, 'timed_out': False, 'interrupted': False, 'stop': 'exited',
                          'relay_clean': True})
        self.assertEqual(info['argv'], ['--run'])
        self.assertEqual((info['key'], info['password'], info['device']), (HA_KEY, PASSWORD, DEVICE))
        self.assertRegex(info['base'], r'^https://127\.0\.0\.1:[0-9]{1,5}$')
        self.assertEqual(info['pgrp'], info['pid'])   # start_new_session: its own process group and session
        self.assertEqual(info['sid'], info['pid'])
        self.assertTrue(result['completed'])

    def test_the_bound_stops_the_page_with_sigterm_so_it_writes_its_record(self):
        outcome, info, result = self.run_fake('hang', seconds=2)
        self.assertEqual((outcome['timed_out'], outcome['stop'], outcome['exit'], outcome['interrupted']),
                         (True, 'terminated', 124, False))
        self.assertEqual(result['checks'], [{'check': 'UI controller runtime stayed bounded', 'ok': False}])
        self.assertTrue(gone(info['pid']))

    def test_a_sigterm_to_the_driver_stops_the_browser_in_order_and_is_reported(self):
        outcome, info, result = self.run_fake('hang', seconds=60, before_stop=True)
        self.assertEqual((outcome['interrupted'], outcome['timed_out'], outcome['stop'], outcome['exit']),
                         (True, False, 'terminated', 124))
        self.assertTrue(outcome['relay_clean'])
        self.assertFalse(result['completed'])
        self.assertTrue(gone(info['pid']))

    def test_a_page_that_ignores_sigterm_loses_its_whole_process_group(self):
        outcome, info, _result = self.run_fake('stubborn', seconds=2)
        self.assertEqual((outcome['timed_out'], outcome['stop']), (True, 'killed'))
        self.assertEqual(outcome['exit'], -signal.SIGKILL)
        self.assertTrue(gone(info['pid']))
        self.assertTrue(gone(info['grandchild']))   # the page's own child went with it
        self.assertTrue(outcome['relay_clean'])

    def test_a_page_that_cannot_start_is_reported_and_the_relay_still_closes(self):
        real = subprocess.Popen

        def popen(args, *rest, **kwargs):
            if args and args[0] == 'node':
                raise FileNotFoundError('node')
            return real(args, *rest, **kwargs)
        with patch.object(bridge.subprocess, 'Popen', popen):
            outcome = bridge.run_page({'key': HA_KEY, 'password': PASSWORD}, 60, DEVICE)
        self.assertEqual((outcome['started'], outcome['start_error'], outcome['exit'], outcome['stop'],
                          outcome['relay_clean'], outcome['interrupted']),
                         (False, 'FileNotFoundError', None, None, True, False))

    def test_a_relay_that_cannot_reap_its_children_is_reported_not_raised(self):
        class Stuck:
            def __init__(self, device):
                self.device, self.children, self.base = device, {'child'}, 'https://127.0.0.1:1'
                self.thread = threading.Thread()

            def __enter__(self):
                return self

            def __exit__(self, *_):
                raise RuntimeError('private relay cleanup incomplete')
        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp) / 'ok.mjs'
            page.write_text(PAGES['ok'])
            config = {'key': HA_KEY, 'password': PASSWORD, 'result': str(Path(tmp) / 'b.json'),
                      'fake_log': str(Path(tmp) / 'l.json')}
            with patch.object(bridge, 'PAGE', page), patch.object(relay, 'Relay', Stuck), \
                    patch.object(bridge, 'RELAY_DRAIN', 0.5):
                outcome = bridge.run_page(config, 60, DEVICE)
        self.assertEqual((outcome['exit'], outcome['relay_clean'], outcome['relay_error']),
                         (0, False, 'private relay cleanup incomplete'))

    def test_the_relay_is_stopped_only_after_the_closed_browsers_connections_finished(self):
        class Closing:
            def __init__(self):
                self.tasks, self.children = {'connection'}, {'exec child'}
                threading.Timer(0.4, self.finish).start()

            def finish(self):
                self.tasks.clear()
                self.children.clear()
        channel = Closing()
        started = time.monotonic()
        bridge.drain(channel, 10)
        self.assertEqual((channel.tasks, channel.children), (set(), set()))
        self.assertLess(time.monotonic() - started, 5)
        stuck = Closing.__new__(Closing)
        stuck.tasks, stuck.children = set(), {'exec child'}
        started = time.monotonic()
        bridge.drain(stuck, 0.3)   # bounded: a child that never ends is left for the relay's own check
        self.assertLess(time.monotonic() - started, 2)


# ---------------------------------------------------------------- the whole bridge against a simulated device

def page_keys(check):
    """What the real page derives from the check it shows (focus_acceptance_ui_protocol.issueKeys / confirmLineCount)."""
    groups = [('_shared', check['shared'])] + [(row['app_id'], row['issues']) for row in check['apps'] if row['importable']]
    keys, lines = {}, 0
    for group, issues in groups:
        found = sorted({issue['key'] for issue in issues if issue.get('level') == 'confirm'})
        lines += sum(1 for issue in issues if issue.get('level') == 'confirm' and issue.get('message'))
        if found:
            keys[group] = found
    return keys, lines


class Device:
    """The device as the bridge reads it: helper replies, job records and the two fixed programs."""

    def __init__(self, **facts):
        self.facts = {'page': tree_page(), 'cockpit_socket': True, 'hostname': DEVICE, 'devadmin_uid': 1000,
                      'headroom': 2 * 1024 ** 3, **facts}
        self.backups = {'20261120T000000Z-0000base': {'id': '20261120T000000Z-0000base', 'type': 'manual'}}
        self.ha, self.jobs, self.calls, self.configs, self.active = [], [], [], [], None
        self.sequence = 0

    def job(self, kind, params, state, result):
        self.sequence += 1
        record = {'id': 'j20261128T02%02d00Z-0000d%03d' % (self.sequence, self.sequence), 'type': kind, 'state': state,
                  'phase': 'done', 'progress': {}, 'params': params, 'result': result}
        self.jobs.append(record)
        return record

    def helper(self, command, request=None):
        self.calls.append(command)
        if command == 'status':
            return {'active_job': self.active}
        if command == 'list':
            return {'backups': [dict(row) for row in self.backups.values()], 'ha_backups': [dict(row) for row in self.ha]}
        if command == 'jobs':
            return {'jobs': [copy.deepcopy(row) for row in reversed(self.jobs)][:50]}
        raise AssertionError(command)

    def wait_job(self, job_id, timeout):
        record = next(row for row in self.jobs if row['id'] == job_id)
        if record['state'] in ('queued', 'running'):
            raise RuntimeError(f'job {job_id} did not finish in {timeout} s')
        return copy.deepcopy(record)

    def root_json(self, script, request):
        self.calls.append('root:' + ('preconditions' if script == bridge.PRECONDITIONS else 'native'))
        if script == bridge.PRECONDITIONS:
            return dict(self.facts)
        unit = 'woowtech-backup-' + request['ids'][0] + '.service'
        return [{'id': row['id'], 'unit': unit, 'type': row['type'], 'state': row['state']}
                for row in (next(r for r in self.jobs if r['id'] == job_id) for job_id in request['ids'])]


def fake_page(device, *, importable=True, sent=None, restore_state='succeeded', outcome=None, check=None, extra=None):
    """The real page's effects on the device and its record: upload, one check, with an importable app one acknowledged
    import whose chain converts and restores; `sent` replaces what the acknowledgement carried."""
    def run_page(config, seconds, name):
        device.configs.append((dict(config), seconds, name))
        ha_id = config['ha_id']
        if not any(row['id'] == ha_id for row in device.ha):
            device.ha.append({'id': ha_id, 'sha256': hashlib.sha256(Path(config['fixture']).read_bytes()).hexdigest(),
                              'importable_apps': [{'app_id': APP, 'installed': True}]})
        job = check(ha_id) if check else check_job(ha_id, importable=importable)
        record = device.job('verify', job['params'], 'succeeded', job['result'])
        keys, lines = page_keys(job['result']['ha_check'])
        imported = all(row['importable'] for row in job['result']['ha_check']['apps'])
        confirmations = {'expected_keys': keys, 'sent_keys': None, 'lines_expected': lines, 'lines_shown': lines,
                         'check_importable': sorted(r['app_id'] for r in job['result']['ha_check']['apps'] if r['importable'])}
        names = ['UI real administrative Cockpit bridge reaches this device', config['texts']['upload'],
                 config['texts']['select'], config['texts']['view'], config['texts']['lines']]
        checks = [{'check': n, 'ok': True} for n in names]
        if imported:
            confirmations['sent_keys'] = copy.deepcopy(keys if sent is None else sent)
            for template in chain(ha_id, (APP,), confirmations['sent_keys'], first='j20261128T020000Z-0000e000'):
                params, result = template['params'], template['result']
                if template['type'] == 'backup':
                    device.backups[result['backup_id']] = {'id': result['backup_id'], 'type': 'manual'}
                else:
                    params['backup_id'] = device.jobs[-1]['result']['backup_id']
                    device.backups[result['safety_backup_id']] = {'id': result['safety_backup_id'], 'type': 'safety'}
                new = device.job(template['type'], params, restore_state if template['type'] == 'restore' else 'succeeded',
                                 result)
                if template['type'] == 'restore':
                    device.jobs[-2]['result']['group']['next_job_id'] = new['id']
            ok = sent is None
            checks += [{'check': config['texts']['result'], 'ok': True}, {'check': config['texts']['intent'], 'ok': True},
                       {'check': config['texts']['keys'], 'ok': ok}]
        else:
            ok = False
            checks[3]['ok'] = False
        if extra:
            extra(device)
        checks.append({'check': 'UI every issued credential absent from records journal and private evidence; proved '
                                'public markers counted separately', 'ok': True})
        browser = {'stage': 'issued-value-scan', 'failure_kind': None if ok else 'check-or-browser-error', 'completed': ok,
                   'issued_values_scanned': True, 'checks': checks, 'confirmations': confirmations,
                   'issued_scan_counts': {'scan_completed': True, 'observed_values': 2, 'observations_complete': True,
                                          'credential_device_hits': 0, 'credential_host_hits': 0, 'device_files': 40,
                                          'host_files': 4, 'archive_index_sidecars': 3, 'regular_json_roots': 2},
                   'wire': {'import_starts': 1 if imported else 0}}
        Path(config['result']).write_text(json.dumps(browser))
        Path(config['evidence'], 'confirmation.png').write_bytes(b'fake image')
        result = {'started': True, 'exit': 0 if ok else 1, 'timed_out': False, 'interrupted': False, 'stop': 'exited',
                  'relay_clean': True, 'relay_error': None, 'children_left': []}
        result.update(outcome or {})
        return result
    return run_page


class ImportViaPageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.lock = self.tmp / 'woowbk-dev-e-mutation.lock'
        self.lock_fd = os.open(self.lock, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(os.close, self.lock_fd)
        self.fixture = self.tmp / 'fixture.tar'
        self.fixture.write_bytes(os.urandom(4096))
        self.ha_id = 'ha-' + hashlib.sha256(self.fixture.read_bytes()).hexdigest()[:20]
        for name in ('playwright.mjs', 'chrome'):
            (self.tmp / name).write_text('stand-in')
        (self.tmp / 'ev').mkdir(mode=0o700)
        self.evidence = self.tmp / 'ev' / 'page'

    def run_bridge(self, dev, page=None, *, clock=None, **changes):
        options = dict(device=DEVICE, apps=[APP], importable=[APP], stops=[], fixture=self.fixture, key=HA_KEY,
                       password=PASSWORD, evidence=self.evidence, deadline=time.monotonic() + 25 * 60,
                       ops=bridge.Ops(dev.helper, dev.wait_job, dev.root_json), lock=self.lock,
                       playwright=self.tmp / 'playwright.mjs', chromium=self.tmp / 'chrome')
        options.update(changes)
        if clock:
            options['clock'] = clock
        with patch.object(bridge, 'run_page', page or fake_page(dev)), \
                patch.object(bridge, 'host_available_kib', lambda: 8 * 1024 * 1024):
            return bridge.import_via_page(**options)

    def private_files(self):
        found = {}
        for root, _dirs, files in os.walk(self.evidence):
            for name in files:
                found[name] = (Path(root) / name).read_bytes()
        return found

    def test_a_good_import_passes_every_gate_and_names_what_the_page_made(self):
        device = Device()
        result = self.run_bridge(device)
        self.assertTrue(result.passed, result.summary.get('reasons'))
        self.assertEqual(set(result.gates), {'expected_outcome', 'acknowledged_exact', 'chain', 'native_units', 'own_jobs',
                                             'record', 'no_unexplained_backups', 'page_bounded', 'cleanup', 'browser_flow',
                                             'issued_scan'})
        self.assertTrue(all(result.gates.values()))
        summary = result.summary
        check, convert, restore = device.jobs
        self.assertEqual((summary['check_job_id'], summary['root_job_id'], summary['chain_job_ids']),
                         (check['id'], convert['id'], [convert['id'], restore['id']]))
        self.assertEqual(summary['created_backups'], [convert['result']['backup_id'], restore['result']['safety_backup_id']])
        self.assertEqual((summary['ha_id'], summary['ha_record_existed'], summary['ha_record_present']), (self.ha_id, False, True))
        self.assertEqual(summary['expected_acknowledged'], EXPECTED)
        self.assertEqual(summary['confirmation_lines'], 4)
        self.assertEqual([c['id'] for c in [result.check_job]], [check['id']])
        self.assertEqual([j['id'] for j in result.chain], summary['chain_job_ids'])
        self.assertEqual(summary['browser']['issued_scan']['credential_device_hits'], 0)
        # Only reads went to the device; the page got its config once, with the device and the secrets (stdin only).
        self.assertLessEqual({c for c in device.calls if not c.startswith('root:')}, bridge.READ_ONLY)
        self.assertEqual(device.calls.count('root:preconditions'), 1)
        [(config, seconds, name)] = device.configs
        self.assertEqual((name, config['device'], config['apps'], config['key'], config['password']),
                         (DEVICE, DEVICE, [APP], HA_KEY, PASSWORD))
        self.assertEqual(config['fixture'], str(self.fixture))
        self.assertEqual(config['evidence'], str(self.evidence))
        self.assertLessEqual(seconds, 20 * 60)
        self.assertEqual({k: config[k] for k in bridge.page_settings([APP], [APP], [])}, bridge.page_settings([APP], [APP], []))
        # The evidence is private and holds no secret; the summary is what the driver keeps.
        self.assertEqual(self.evidence.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.evidence / 'page-bridge.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((self.evidence / 'page-bridge.json').read_text()), json.loads(json.dumps(summary)))
        for name, data in self.private_files().items():
            self.assertNotIn(HA_KEY.encode(), data, name)
            self.assertNotIn(PASSWORD.encode(), data, name)

    def test_an_existing_record_of_the_same_bytes_is_reported_as_not_made_by_the_page(self):
        device = Device()
        device.ha.append({'id': self.ha_id, 'sha256': hashlib.sha256(self.fixture.read_bytes()).hexdigest()})
        result = self.run_bridge(device)
        self.assertTrue(result.passed, result.summary.get('reasons'))
        self.assertIs(result.summary['ha_record_existed'], True)

    def test_an_outcome_other_than_expected_fails_its_gate(self):
        device = Device()
        result = self.run_bridge(device, fake_page(device, importable=False))
        self.assertFalse(result.passed)
        self.assertFalse(result.gates['expected_outcome'])
        self.assertIn('expected it importable', result.summary['reasons']['expected_outcome'])
        self.assertEqual((result.gates['chain'], result.summary['chain_job_ids'], result.summary['created_backups']),
                         (False, [], []))
        self.assertFalse(result.gates['browser_flow'])
        # Expected stopped, found importable: the same gate fails (the stopped app is read from the check, never assumed).
        device = Device()
        self.evidence = self.tmp / 'ev' / 'page2'
        two = lambda ha_id: check_job(ha_id, apps=[{'app_id': APP, 'importable': True, 'issues': []},
                                                   {'app_id': 'emqx', 'importable': True, 'issues': []}])
        result = self.run_bridge(device, fake_page(device, check=two), apps=[APP, 'emqx'], importable=[APP], stops=['emqx'])
        self.assertFalse(result.gates['expected_outcome'])

    def test_a_key_acknowledged_other_than_exactly_once_fails_its_gate(self):
        for n, sent in enumerate(({'_shared': [S], APP: [OD1]}, {'_shared': [S], APP: [OD1, OD1, OD2]},
                                  {APP: sorted([S, OD1, OD2])})):
            with self.subTest(sent=sent):
                device = Device()
                self.evidence = self.tmp / 'ev' / f'page-keys-{n}'
                result = self.run_bridge(device, fake_page(device, sent=sent))
                self.assertFalse(result.gates['acknowledged_exact'])
                self.assertFalse(result.passed)
                self.assertTrue(result.gates['expected_outcome'])   # the check itself was as expected

    def test_the_deadline_bounds_the_page_and_the_reading_of_a_chain_that_still_runs(self):
        device = Device()
        now = [1000.0]
        page = fake_page(device, restore_state='running',
                         outcome={'timed_out': True, 'stop': 'terminated', 'exit': 124})

        def advancing(*args):
            result = page(*args)
            now[0] += 30 * 60   # the page used the whole time
            device.active = device.jobs[-1]['id']
            return result
        result = self.run_bridge(device, advancing, clock=lambda: now[0], deadline=1000.0 + 25 * 60)
        self.assertFalse(result.passed)
        self.assertFalse(result.gates['page_bounded'])
        self.assertFalse(result.gates['own_jobs'])
        self.assertFalse(result.gates['chain'])
        self.assertEqual(result.summary['inflight'], device.jobs[1]['id'])   # the conversion was never read: no time
        self.assertIn('deadline', result.summary['reasons']['jobs'])
        [(_config, seconds, _name)] = device.configs
        self.assertEqual(seconds, 20 * 60)
        # Less time than the page's bound: the page gets what is left minus the time to read its jobs.
        device = Device()
        self.evidence = self.tmp / 'ev' / 'page-short'
        self.run_bridge(device, deadline=time.monotonic() + 10 * 60)
        self.assertTrue(9 * 60 - 5 <= device.configs[0][1] <= 9 * 60)

    def test_a_restore_that_did_not_succeed_or_a_job_left_running_fails(self):
        device = Device()
        result = self.run_bridge(device, fake_page(device, restore_state='rolled-back'))
        self.assertFalse(result.gates['chain'])
        self.assertFalse(result.passed)
        self.assertIn(device.jobs[2]['result']['safety_backup_id'], result.summary['created_backups'])   # still reported

    def test_browser_relay_and_child_cleanup_are_gates(self):
        for change in ({'relay_clean': False, 'relay_error': 'private relay cleanup incomplete'}, {'children_left': [4242]},
                       {'stop': 'killed'}):
            with self.subTest(change=change):
                device = Device()
                self.evidence = self.tmp / 'ev' / ('page-' + '-'.join(change))
                result = self.run_bridge(device, fake_page(device, outcome=change))
                self.assertFalse(result.gates['cleanup'])
                self.assertFalse(result.passed)

    def test_another_new_backup_or_job_fails_the_accounting(self):
        device = Device()

        def other(dev):
            dev.backups['20261128T030000Z-0000ffff'] = {'id': '20261128T030000Z-0000ffff', 'type': 'manual'}
        result = self.run_bridge(device, fake_page(device, extra=other))
        self.assertFalse(result.gates['no_unexplained_backups'])
        self.assertEqual(result.summary['unexplained_new_backups'], ['20261128T030000Z-0000ffff'])
        device = Device()
        self.evidence = self.tmp / 'ev' / 'page-second-check'
        ha_id = self.ha_id

        def recheck(dev):   # a second check of the same upload (the page's "check again")
            dev.job('verify', {'source': 'ha', 'ha_backup_id': ha_id, 'apps': [APP]}, 'succeeded', {})
        result = self.run_bridge(device, fake_page(device, extra=recheck))
        self.assertFalse(result.gates['own_jobs'])
        self.assertFalse(result.gates['expected_outcome'])   # no single current check

    def test_preconditions_refuse_before_the_page_and_change_nothing(self):
        cases = {'installed page differs from the tree': {'page': {}},
                 'device hostname is not its name': {'hostname': 'woowbk-dev-d'},
                 'no devadmin account': {'devadmin_uid': None},
                 'device memory headroom below 1280 MiB': {'headroom': 512 * 1024 ** 2},
                 'cockpit.socket not active': {'cockpit_socket': False}}
        for n, (reason, facts) in enumerate(cases.items()):
            with self.subTest(reason=reason):
                device = Device(**facts)
                self.evidence = self.tmp / 'ev' / f'refused-{n}'
                with self.assertRaises(bridge.Refused) as caught:
                    self.run_bridge(device, lambda *a: self.fail('the page must not start'))
                self.assertIn(reason, caught.exception.summary['reasons'])
                self.assertEqual(json.loads((self.evidence / 'page-bridge.json').read_text())['phase'], 'refused')
                self.assertLessEqual({c for c in device.calls if not c.startswith('root:')}, bridge.READ_ONLY)
        device = Device()
        device.active = 'j20261128T000000Z-00000000'
        self.evidence = self.tmp / 'ev' / 'refused-active'
        with self.assertRaisesRegex(bridge.Refused, 'a job is active'):
            self.run_bridge(device, lambda *a: self.fail('the page must not start'))
        device = Device()
        device.ha.append({'id': self.ha_id, 'sha256': '0' * 64})
        self.evidence = self.tmp / 'ev' / 'refused-record'
        with self.assertRaisesRegex(bridge.Refused, 'other bytes'):
            self.run_bridge(device, lambda *a: self.fail('the page must not start'))

    def test_inputs_and_the_lock_refuse_before_any_device_read(self):
        def refused(pattern, **changes):
            device = Device()
            with self.assertRaisesRegex(bridge.Refused, pattern):
                self.run_bridge(device, lambda *a: self.fail('the page must not start'), **changes)
            self.assertEqual(device.calls, [])
        other = self.tmp / 'other.lock'
        other.touch()
        refused('does not hold', lock=other)
        refused('does not hold', lock=None)   # the device's own /tmp lock, not held by this test process
        refused('lab device name', device='dev-e')
        refused('either importable or stopped', importable=[], stops=[APP])
        refused('not enough time', deadline=time.monotonic() + 60)
        refused('not enough time', page_seconds=10)
        refused('HA key or Cockpit password', key='short')
        refused('HA key or Cockpit password', password=None)
        link = self.tmp / 'link.tar'
        link.symlink_to(self.fixture)
        refused('fixture is not a regular file', fixture=link)
        self.evidence.mkdir()
        refused('evidence must be a new directory')
        self.evidence.rmdir()
        refused('browser package or Chromium missing', chromium=self.tmp / 'absent')
        self.assertFalse(self.evidence.exists())

    def test_a_soft_stop_reports_the_pages_jobs_and_writes_the_record(self):
        device = Device()
        page = fake_page(device, restore_state='running',
                         outcome={'interrupted': True, 'stop': 'terminated', 'exit': 124})
        with self.assertRaises(bridge.Interrupted) as caught:
            self.run_bridge(device, page)
        summary = caught.exception.summary
        self.assertEqual(summary['phase'], 'interrupted')
        self.assertEqual(summary['check_job_ids'], [device.jobs[0]['id']])
        self.assertEqual(summary['root_job_ids'], [device.jobs[1]['id']])
        self.assertEqual(json.loads((self.evidence / 'page-bridge.json').read_text())['phase'], 'interrupted')
        self.assertNotIn('job-status', device.calls)   # nothing waited for the running jobs
        # The finished conversion's backup and the running restore's safety backup (named in its record) go to cleanup.
        self.assertEqual(summary['created_backups'], [device.jobs[1]['result']['backup_id'],
                                                      device.jobs[2]['result']['safety_backup_id']])


class HarnessPinTests(unittest.TestCase):
    def test_the_same_browser_and_product_constants_as_the_page_harness(self):
        ui = module('pin_ui', 'focus_acceptance_ui.py')
        pe = module('pin_page_emqx', 'focus_acceptance_ui_page_emqx.py')
        self.assertEqual((bridge.PLAYWRIGHT, bridge.CHROMIUM), (ui.PLAYWRIGHT, ui.CHROMIUM))
        self.assertEqual((bridge.SHARED, bridge.LEVELS, bridge.KEY.pattern), (pe.SHARED, pe.LEVELS, pe.KEY.pattern))
        self.assertEqual(bridge.PAGE, HERE / 'focus_acceptance_ui_page.mjs')
        self.assertEqual(bridge.PAGE_SECONDS, 20 * 60)
        self.assertEqual(bridge.READ_ONLY, frozenset({'status', 'list', 'jobs', 'job-status'}))
        self.assertEqual(subprocess.run([sys.executable, '-B', str(HERE / 'focus_page_bridge.py')], capture_output=True,
                                        timeout=60).returncode, 0)


if __name__ == '__main__':
    unittest.main()
