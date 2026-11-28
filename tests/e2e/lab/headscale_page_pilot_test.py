"""Offline: headscale_full_flow.py with and without --via-page against a simulated dev-d (no device, no labpodman, no
browser, no real secret; every lab path points into a temporary folder with generated values).

- The default run of this checkout and of the reviewed base (a1ca42b2, from git) send the same device calls in the same
  order and produce the same checks; the simulated run reproduces the real 96/96 run's fixed status lines
  (tests/backup/evidence/parity-headscale-virtual-20261127/original-ha-x86-full-flow.json) line for line.
- --via-page replaces exactly the upload, found-state, check and import checks with the page's (through the REAL bridge,
  whose page process is simulated): no key reaches the page (the b1 backup is plain), nothing is chosen, the lab DERP
  config stays, and every later check is unchanged.

The tailscale clients are not simulated: their four methods are replaced by stand-ins that write the same check lines in
both drivers (they never touch the import).
"""
import contextlib
import copy
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BASE = 'a1ca42b2edecfaef99ea8d7a1db93e8acd0d59ac'
OLD_DRIVER_SHA = 'a0e6329b39c1175b2883cacd69c547967e0fbabc0905547d1eb8af8914ecf7e3'
PASSWORD = 'generated-cockpit-pass-3333'
HA_NOISE = 'privkey:' + '5' * 64
HA_API = 'hskey-api-' + 'G' * 30
HA_COOKIE = 'generated-cookie-secret-' + 'h' * 16
SECTION = {'users': 3, 'nodes': 2, 'preauth_keys': 2, 'api_keys': 1, 'routes': 1, 'dns_records': 1}
ENTRY = {'id': 'headscale', 'owner': 'appowner', 'units': ['headscale.service', 'headplane.service',
                                                           'headscale-entrance.service'],
         'volumes': [{'name': 'headscale-data'}, {'name': 'headplane-data'}],
         'health': [{'url': 'http://127.0.0.1:28080/health', 'expect_status': 200}]}
DEV_D_CONFIG = b'server_url: http://localhost:28080\nderp:\n  server:\n    enabled: false\n  urls: []\ndns:\n  magic_dns: true\n'


def load_new(name='hsff_new'):
    spec = importlib.util.spec_from_file_location(name, HERE / 'headscale_full_flow.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def load_base():
    """The base commit's driver (from git), run as if it were this file (its HERE and its b1 driver are this tree's)."""
    shown = subprocess.run(['git', '-C', str(REPO), 'show', f'{BASE}:tests/e2e/lab/headscale_full_flow.py'],
                           capture_output=True, timeout=60)
    if shown.returncode:
        return None
    assert hashlib.sha256(shown.stdout).hexdigest() == OLD_DRIVER_SHA
    spec = importlib.util.spec_from_loader('hsff_base', loader=None)
    value = importlib.util.module_from_spec(spec)
    value.__file__ = str(HERE / 'headscale_full_flow.py')
    exec(compile(shown.stdout, value.__file__, 'exec'), value.__dict__)
    return value


def bridge_module():
    spec = importlib.util.spec_from_file_location('hsff_test_bridge', HERE / 'focus_page_bridge.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def answer(stdout=b'', returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=stdout if isinstance(stdout, bytes) else stdout.encode(), stderr=b'')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def facts(machine):
    """drv.source(machine): the b1 source facts the driver compares with (generated stand-ins)."""
    users = [[1, 'default'], [2, 'alice'], [3, 'bob']]
    nodes = [{'id': 1, 'given_name': 'b1-alice-laptop', 'user': 'alice', 'ip_addresses': ['100.64.0.1', 'fd7a::1']},
             {'id': 2, 'given_name': 'b1-bob-nas', 'user': 'bob', 'ip_addresses': ['100.64.0.2', 'fd7a::2']}]
    return {'headscale': {'users': users, 'nodes': nodes, 'server_public_key': 'mkey:' + ('b' if machine == 'x86' else 'c') * 64,
                          'noise_private_key_sha256': hashlib.sha256(HA_NOISE.encode()).hexdigest()}}


class Dev:
    """dev-d as headscale_full_flow.py (and, with --via-page, the bridge) sees it: its own Headscale, the b1 plain
    backup with one importable Headscale, the lab config file and the engine."""

    def __init__(self, module, fixture_sha, *, record_exists=True):
        self.m, self.store_id, self.fixture_sha = module, 'ha-' + fixture_sha[:20], fixture_sha
        self.calls, self.jobs, self.sequence = [], [], 0
        self.backups = {module.BASELINE: {'id': module.BASELINE, 'type': 'manual'}}
        self.ha = [self.record()] if record_exists else []
        self.files = {module.CONFIG_REL: DEV_D_CONFIG}
        self.catalog_installed = False
        self.data = 'own'                # whose Headscale data is live: dev-d's ('own') or HA's ('ha')
        self.clients = 0
        self.private = None
        self.lab_config = False
        self.converted = self.bridge = None

    def record(self):
        return {'id': self.store_id, 'sha256': self.fixture_sha,
                'importable_apps': [{'slug': 'abc_woow-headscale', 'app_id': 'headscale', 'installed': True}]}

    def log(self, *entry):
        self.calls.append(entry)

    def backup(self, kind, **extra):
        self.sequence += 1
        bid = '20261128T1000%02dZ-%08x' % (self.sequence, self.sequence)
        self.backups[bid] = {'id': bid, 'type': kind, 'key_id': 'k-1', 'size': 1000, **extra}
        return bid

    def job(self, kind, params, state, result, unit=None):
        self.sequence += 1
        jid = 'j20261128T1100%02dZ-%08x' % (self.sequence, self.sequence)
        record = {'id': jid, 'type': kind, 'state': state, 'phase': 'done', 'progress': {}, 'params': params,
                  'result': result, 'unit': unit or f'woowtech-backup-{jid}.service'}
        self.jobs.append(record)
        return record

    @staticmethod
    def public(job):
        return {k: copy.deepcopy(v) for k, v in job.items() if k != 'unit'}

    # ---------------------------------------------------------------- what the engine answers
    def check_result(self, ha_id):
        return {'ha_check': {'schema': 2, 'ha_backup_id': ha_id, 'shared': [], 'apps': [{
            'app_id': 'headscale', 'ok': True, 'importable': True, 'blockers': [], 'arch': 'amd64', 'version': '0.1.3',
            'target_version': '0.29.4', 'warnings': ['HA 的 API 金鑰不會搬過來，請在這台建立新的。'],
            'issues': [{'id': 'headscale.api-keys', 'level': 'notice', 'message': 'API keys stay', 'items': [], 'more': 0}],
            'headscale': dict(SECTION)}]}}

    def convert_result(self):
        self.converted = self.backup('manual', from_ha={'ha_backup_id': self.store_id})
        return {'backup_id': self.converted, 'ha_import': {'apps': ['headscale'], 'test_mode': False,
                                                           'notes': ['Headscale: clients keep their node'],
                                                           'reminders_by_app': {'headscale': [
                                                               'clients use http://localhost:28080']}}}

    def restore_result(self, backup_id):
        marker = self.m.MARKER_REL
        if backup_id == self.converted and marker in self.files:   # the injected one-shot ExecStartPre failure
            del self.files[marker]
            return 'rolled-back', {'rolled_back': True, 'safety_backup_id': self.backup('safety')}
        self.data = 'ha' if backup_id == self.converted else 'own'
        if self.data == 'own':
            self.clients = 0
        return 'succeeded', {'rolled_back': False, 'safety_backup_id': self.backup('safety'),
                             'health': [{'id': 'headscale', 'status': 'ok'}], 'downtime_seconds': 6}

    def probe(self, request):
        own = self.data == 'own'
        src = facts('x86')['headscale']
        if own:
            state = {'users': [[1, 'woowbk-lab-baseline']],
                     'nodes': [[1, 'woowbk-lab-baseline-node', 'woowbk-lab-baseline', ['100.64.0.9'], [], True, []]],
                     'preauthkeys': [[1, 'woowbk-lab-baseline', False, False, []]],
                     'dns_records': [['woowbk-lab-baseline.ts.local', 'A', '100.64.0.9']],
                     'noise_text_sha256': 'own-noise', 'server_public_key': 'mkey:' + 'd' * 64}
        else:
            nodes = [[n['id'], n['given_name'], n['user'], n['ip_addresses'],
                      ['192.168.88.0/24'] if n['given_name'] == 'b1-bob-nas' else [], False, []] for n in src['nodes']]
            nodes += [[100 + i, f'hsff-new{i}', 'bob', [f'100.64.0.{100 + i}'], [], True, []] for i in range(1, self.clients + 1)]
            state = {'users': src['users'], 'nodes': sorted(nodes),
                     'preauthkeys': [[1, 'alice', False, True, []], [2, 'bob', True, False, []]],
                     'dns_records': [['b1-nas.ts.local', 'A', '100.64.0.250']],
                     'noise_text_sha256': src['noise_private_key_sha256'], 'server_public_key': src['server_public_key']}
        state.update(health=200, metrics=200, apikeys=[[1, 'devprefx']], api_device_key=[200, len(state['nodes'])])
        if request.get('ha_api_key'):
            state['api_ha_key'] = 401
        return state

    # ---------------------------------------------------------------- the b1 driver's device calls
    def run(self, argv, *, input=None, timeout=600, check=False):
        m = self.m
        self.log('run', tuple(Path(str(a)).name if str(a).startswith('/') else a for a in argv[:3]))
        if argv[:2] == ['bash', str(HERE / 'deploy-src.sh')]:
            return answer('deployed this tree\n')
        if argv[:5] == [m.drv.LP, 'exec', '-i', m.drv.DEVICE, m.drv.OWNER] and argv[5:8] == ['python3', '-I', '-c']:
            if argv[8] == m.drv.MARKERS:
                return answer(json.dumps({'users': ['woowbk-lab-baseline'], 'preauthkeys': ['woowbk-lab-baseline'],
                                          'nodes': ['woowbk-lab-baseline'],
                                          'dns_records': ['woowbk-lab-baseline.ts.local']} if self.data == 'own' else {}) + '\n')
            if argv[8] == m.KEEP_KEYS:
                return answer('{"kept": 2}\n')
        raise AssertionError(('run', argv[:6]))   # nothing else may ever leave this process

    def owner(self, *argv, input=None, timeout=600, check=False):
        self.log('owner', argv[:4], None if input is None else hashlib.sha256(input).hexdigest()[:12])
        home = '/home/appowner/'
        if argv[:2] == ('mktemp', '-d'):
            self.private = '/home/appowner/.services-a2-hsff.AbCdEf12'
            return answer(self.private + '\n')
        if argv[0] == 'cat':
            rel = argv[1][len(home):]
            return answer(self.files[rel]) if rel in self.files else answer(returncode=1)
        if argv[:2] == ('test', '-e'):
            rel = argv[2][len(home):]
            return answer(returncode=0 if rel in self.files or (self.private and argv[2] == self.private) else 1)
        if argv[:2] == ('sh', '-c'):
            self.files[argv[4]] = input
            return answer()
        if argv[:3] == ('systemctl', '--user', 'is-active'):
            return answer('active\n' if self.lab_config else 'activating\n')
        if argv[:3] == ('systemctl', '--user', 'restart'):
            self.lab_config = self.files.get(self.m.CONFIG_REL) != DEV_D_CONFIG
            return answer()
        if argv[:3] == ('systemctl', '--user', 'daemon-reload') or argv[0] in ('mkdir', 'rmdir'):
            return answer()
        if argv[:2] == ('rm', '-f'):
            for path in argv[2:]:
                self.files.pop(path[len(home):], None)
            return answer()
        if argv[:3] == ('rm', '-rf', '--'):
            self.private = None
            return answer()
        raise AssertionError(('owner', argv))

    def root(self, *argv, input=None, timeout=600, check=False):
        self.log('root', argv[:3])
        if argv[:2] == ('systemctl', 'mask'):
            return answer()
        if argv[0] == 'cat' and argv[1].startswith('/var/lib/woowtech-backup/ha-backups/'):
            return answer(json.dumps({'sha256': self.fixture_sha, 'filename': 'woow-b1-x86-plain.tar'}))
        if argv[:3] == ('rm', '-rf', '--'):
            return answer()
        if argv[:2] == ('test', '-e'):
            return answer(returncode=1)
        raise AssertionError(('root', argv))

    def device_python(self, script, request=None, *, as_owner=True, timeout=600):
        m, bridge = self.m, self.bridge
        name = next((n for n in ('ENGINE_HASHES', 'HS_PROBE', 'SPACE', 'LEAKS') if script == getattr(m, n)), None)
        if name is None and script == m.drv.RUN_LIST:
            name = 'RUN_LIST'
        if name is None and bridge is not None:
            name = {bridge.PRECONDITIONS: 'PRECONDITIONS', bridge.NATIVE_UNITS: 'NATIVE_UNITS'}.get(script)
        self.log('device_python', name, as_owner, copy.deepcopy(request) if name != 'LEAKS' else sorted(request['secrets']))
        if name == 'ENGINE_HASHES':
            lib = REPO / 'backup-engine/woowbackup'
            return {'lib': {str(p.relative_to(lib)): sha(p) for p in lib.rglob('*.py') if '__pycache__' not in p.parts},
                    'helper': sha(REPO / 'backup-engine/woowtech-cockpit-backup')}
        if name == 'HS_PROBE':
            return self.probe(request or {})
        if name == 'SPACE':
            return {'total': 100 << 30, 'running_reserve': 1 << 30, 'watch_margin': 1 << 30, 'floor': 2 << 30,
                    'min_free': 50 << 30}
        if name == 'LEAKS':
            return {'scanned': 50, 'client_logs': request['clients'], 'journal_bytes': 4096, 'names': len(request['secrets']),
                    'volume_keys': 2, 'client_states': request['clients'], 'hits': 0}
        if name == 'RUN_LIST':
            return {'/var/lib/woowtech-backup/staging': [], '/run/woowtech-backup': ['engine.lock']}
        if name == 'PRECONDITIONS':
            return {'page': {n: sha(REPO / 'backup' / n) for n in bridge.PAGE_FILES}, 'cockpit_socket': True,
                    'hostname': 'woowbk-dev-d', 'devadmin_uid': 1000, 'headroom': 2000 * 1024 ** 2}
        if name == 'NATIVE_UNITS':
            rows = {job['id']: job for job in self.jobs}
            return [{k: rows[j][k] for k in ('id', 'unit', 'type', 'state')} for j in request['ids']]
        raise AssertionError(('device_python', script[:60]))

    def ok(self, command, request=None, *, ev, timeout=1800):
        self.log('ok', command, copy.deepcopy(request) if command != 'inspect' else sorted(request))
        if command == 'status':
            apps = [{'id': 'headscale', 'state': 'running', 'problems': []}] if self.catalog_installed else []
            return {'version': (REPO / 'VERSION').read_text().strip(), 'apps': apps, 'active_job': None}
        if command == 'inspect' and request.get('backup_id') == self.m.BASELINE:
            return {'preflight': {'ok': True, 'apps': [{'id': 'headscale', 'settings': {'state': 'missing',
                                                                                        'entry': copy.deepcopy(ENTRY)}}]}}
        if command == 'inspect':
            return {'ok': True, 'preflight': {'ok': True, 'checks': [], 'apps': [
                {'id': 'headscale', 'mode': 'inplace', 'settings': {'state': 'same'}}]}}
        if command == 'catalog-install':
            if request.get('confirm'):
                self.catalog_installed = True
                return {'installed': True}
            return {'valid': True, 'errors': [], 'warnings': [], 'conflicts': [], 'expected_sha256': 'e' * 64}
        if command == 'catalog-remove':
            return {'expected_sha256': 'f' * 64}
        if command == 'key-init':
            return {'key': {'key_id': 'k-1'}, 'created': False}
        if command == 'list':
            return {'backups': [dict(row) for row in self.backups.values()], 'ha_backups': [dict(row) for row in self.ha]}
        if command == 'jobs':
            return {'jobs': [self.public(job) for job in reversed(self.jobs)]}
        raise AssertionError(('ok', command))

    def helper(self, command, request=None, *, timeout=1800):
        self.log('helper', command, copy.deepcopy(request))
        if command == 'delete':
            return (0, {}) if self.backups.pop(request['backup_id'], None) else (1, {'error': 'not-found'})
        if command == 'ha-delete':
            before = len(self.ha)
            self.ha = [row for row in self.ha if row['id'] != request['ha_backup_id']]
            return (0, {}) if len(self.ha) < before else (1, {'error': 'not-found'})
        if command == 'catalog-remove':
            self.catalog_installed = False
            return 0, {}
        raise AssertionError(('helper', command))

    def upload(self, path, *, ev):
        self.log('upload', Path(path).name)
        if not any(row['id'] == self.store_id for row in self.ha):
            self.ha.append(self.record())
        return 0, {'ha_backup': {'id': self.store_id, 'importable_apps': [{'app_id': 'headscale', 'installed': True}]}}

    def run_check(self, ha, apps, *, ev, key=None, tag='check'):
        self.log('run_check', ha, tuple(apps), key, tag)
        job = self.job('verify', {'source': 'ha', 'ha_backup_id': ha, 'apps': list(apps), 'key_provided': False},
                       'succeeded', self.check_result(ha))
        return self.public(job), 2.0

    def convert(self, ha, apps, test_mode, *, ev, key, tag):
        self.log('convert', ha, tuple(apps), test_mode, key, tag)
        job = self.job('backup', {'source': 'ha', 'ha_backup_id': ha, 'apps': list(apps), 'test_mode': test_mode},
                       'succeeded', self.convert_result())
        return self.public(job), 3.0

    def restore(self, backup_id, apps, *, ev, tag):
        self.log('restore', backup_id, tuple(apps), tag)
        state, result = self.restore_result(backup_id)
        return self.public(self.job('restore', {'backup_id': backup_id, 'apps': list(apps)}, state, result)), 4.0

    def wait_job(self, job_id, *, ev, timeout=5400):
        self.log('wait_job', job_id)
        return self.public(next(job for job in self.jobs if job['id'] == job_id))

    def labelled(self):
        self.log('labelled')
        return {'containers': [], 'volumes': [], 'networks': []}

    def catalog(self, app):
        self.log('catalog', app)
        return copy.deepcopy(ENTRY)

    # ---------------------------------------------------------------- stand-ins the run calls beside the engine
    def compare_check(self, ev, label, app, result, machine, hot, upload=None):
        self.log('compare_check', label, app)
        ev.check(f'{label}: headscale section equals the source facts', result.get('headscale') == SECTION,
                 result.get('headscale'))

    def app_health(self, ev, app, label):
        self.log('app_health', app, label)
        ev.check(f'{label}: engine status running, no problems', self.catalog_installed)
        ev.check(f'{label}: the catalog health URLs answer as expected', self.data == 'ha')

    # ---------------------------------------------------------------- the real page's effects (--via-page)
    def page(self, config, seconds, device):
        """What dev-d's real page does through the relay: upload (the record may exist: the same bytes), one check of
        headscale without a key, its one confirmation (no line to confirm), one import whose two linked jobs convert and
        restore in the first job's unit."""
        self.log('page', device, tuple(config['apps']), seconds <= 20 * 60, 'key' in config, config.get('encrypted'),
                 config.get('choices'), config['password'] == PASSWORD)
        if not any(row['id'] == self.store_id for row in self.ha):
            self.ha.append(self.record())
        self.job('verify', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['headscale'], 'key_provided': False},
                 'succeeded', self.check_result(config['ha_id']))
        result = self.convert_result()
        first = self.job('backup', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['headscale'],
                                    'odoo_database': None, 'test_mode': False, 'encrypt': True, 'key_provided': False,
                                    'group': {'kind': 'ha-import', 'step': 'convert', 'index': 0, 'count': 1},
                                    'chain': {'apps': ['headscale'], 'test_mode': False, 'then_restore': True,
                                              'encrypt': True, 'key_provided': False, 'acknowledged': {}, 'choices': {}}},
                         'succeeded', result)
        state, restored = self.restore_result(self.converted)
        restored['group'] = {'next_job_id': None, 'results': [{'app_id': 'headscale', 'status': 'imported'}]}
        second = self.job('restore', {'backup_id': self.converted, 'apps': ['headscale'], 'key_provided': False,
                                      'ha_backup_id': config['ha_id']}, state, restored, unit=first['unit'])
        result['group'] = {'next_job_id': second['id'], 'results': []}
        browser = {'stage': 'issued-value-scan', 'failure_kind': None, 'completed': True, 'issued_values_scanned': True,
                   'checks': [{'check': n, 'ok': True} for n in page_names(config['texts'])],
                   'confirmations': {'expected_keys': {}, 'sent_keys': {}, 'lines_expected': 0, 'lines_shown': 0,
                                     'check_importable': ['headscale']},
                   'issued_scan_counts': {'scan_completed': True, 'observed_values': 2, 'observations_complete': True,
                                          'credential_device_hits': 0, 'credential_host_hits': 0, 'device_files': 30,
                                          'host_files': 3, 'archive_index_sidecars': 4, 'regular_json_roots': 2},
                   'wire': {'import_starts': 1}, 'key_step': {'stepper_key_steps': 0, 'key_fields_after_check': 0},
                   'choices': {'named': {}, 'database': None, 'picks': {}, 'import_choices': {}, 'check_choices': {},
                               'rechecks': 0, 'problems': []},
                   'requests': {'check': [{'key': False, 'choices': None}], 'import': {'key': False, 'choices': None}}}
        Path(config['result']).write_text(json.dumps(browser))
        return {'started': True, 'exit': 0, 'timed_out': False, 'interrupted': False, 'stop': 'exited',
                'relay_clean': True, 'relay_error': None, 'children_left': []}


def page_names(texts):
    """The real page's check names of a keyless run with choices (focus_page_bridge_modes_test.mjs drives them)."""
    return ['UI real administrative Cockpit bridge reaches this device', texts['upload'], texts['select'],
            'UI unencrypted HA backup: the wizard asks for no key', 'UI unencrypted HA backup: the check ran without a key step',
            'UI selects each choice the run named, only from what the check offers',
            'UI actual check confirmation keys observed including valid zero', texts['view'], texts['lines'],
            'UI has exactly one acknowledgement and import waits for it', 'UI check did not start an import or separate restore',
            'UI real key field removed before screenshot', 'UI one acknowledgement enables import', texts['result'],
            texts['intent'], texts['keys'], 'UI unencrypted HA backup: neither the check nor the import request carried a key',
            'UI the check and import requests carry exactly the chosen choices',
            'UI no page script errors during this page flow', 'UI cookie observation completed without gaps',
            'UI every issued credential absent from records journal and private evidence; proved public markers counted '
            'separately']


# The tailscale clients (unchanged by --via-page): stand-ins writing the real run's lines in both drivers.
def client_setup(self):
    self.client_dirs = True
    self.ev.check('setup: the lab tailscale client binaries are staged in dev-d (sha256 as recorded)', True)


def clients_phase(self):
    for index in (1, 2):
        self.dev.clients += 1
        self.clients.append(f'new{index}')
        self.client_states += 1
        self.ev.check(f'client x86: new device {index} joins with HA\'s reusable pre-auth key (key file removed)', True)
    self.verify('clients x86 (two new devices)', extra_nodes=2)
    self.ev.check('client x86: new device 2 -> new device 1: pings through the embedded DERP region (10/10 pongs)', True)


def clients_reconnect(self, label_text):
    self.ev.check(f'{label_text}: every client reconnected by itself (Running, online on the server, same node)',
                  self.dev.data == 'ha' and self.dev.clients == 2)


def clients_stop(self):
    self.clients.clear()


SECRET_FILES = {'b1-creds.env': ''.join(f'B1_X86_HS_{name}=hskey-auth-{"z" * 24}{n}\n' for n, name in enumerate(
    ('KEY_BOB_REUSABLE', 'KEY_ALICE_SINGLE', 'KEY_SPARE_ONE', 'KEY_SPARE_TWO'))),
                'dev-d-markers.json': '{}', 'devadmin.pass': PASSWORD + '\n',
                'dev-d-kit.txt': '# generated kit\nAGE-SECRET-KEY-1' + 'Q' * 58 + '\n'}


def lab(root):
    for name, text in SECRET_FILES.items():
        path = root / 'secrets' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o600)
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode='w:gz') as tar:
        for name, value in (('./data/noise_private.key', HA_NOISE), ('./data/.headplane_api_key', HA_API),
                            ('./data/.headplane_cookie_secret', HA_COOKIE)):
            data = value.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    fixture = root / 'fixtures' / 'x86' / 'woow-b1-x86-plain' / 'woow-b1-x86-plain.tar'
    fixture.parent.mkdir(parents=True)
    with tarfile.open(fixture, 'w') as outer:
        info = tarfile.TarInfo('abc_woow-headscale.tar.gz')
        info.size = len(inner.getvalue())
        outer.addfile(info, io.BytesIO(inner.getvalue()))
    return fixture


def fake_path(real):
    def make(*parts):
        if parts == ('/proc/meminfo',):
            return SimpleNamespace(read_text=lambda: 'MemTotal: 16000000 kB\nMemAvailable:    6291456 kB\n')
        return real(*parts)
    return make


@contextlib.contextmanager
def simulated(m, root, *, bridge=None, lock=None, record_exists=True):
    """Every device-facing function of the driver `m` answered by Dev; every lab path in `root`."""
    fixture = lab(root)
    dev = Dev(m, sha(fixture), record_exists=record_exists)
    dev.bridge = bridge
    m.drv.STATE.clear()
    with contextlib.ExitStack() as stack:
        for target, name, value in (
                (m, 'LAB', root), (m.drv, 'LAB', root), (m.drv, 'FIXTURES', root / 'fixtures'),
                (m, 'FIXTURE_SHA', {'x86': sha(fixture), 'arm': '0' * 64}), (m, 'OLD_KIT', root / 'secrets/dev-d-kit.txt'),
                (m.drv, 'source', facts), (m.drv, 'run', dev.run), (m.drv, 'root', dev.root), (m.drv, 'owner', dev.owner),
                (m.drv, 'ok', dev.ok), (m.drv, 'helper', dev.helper), (m.drv, 'device_python', dev.device_python),
                (m.drv, 'upload', dev.upload), (m.drv, 'run_check', dev.run_check), (m.drv, 'convert', dev.convert),
                (m.drv, 'restore', dev.restore), (m.drv, 'wait_job', dev.wait_job), (m.drv, 'labelled', dev.labelled),
                (m.drv, 'catalog', dev.catalog), (m.drv, 'compare_check', dev.compare_check),
                (m.drv, 'app_health', dev.app_health), (m.Run, 'client_setup', client_setup),
                (m.Run, 'clients_phase', clients_phase), (m.Run, 'clients_reconnect', clients_reconnect),
                (m.Run, 'clients_stop', clients_stop), (m.time, 'sleep', lambda _seconds: None),
                (os, 'statvfs', lambda _path: SimpleNamespace(f_bavail=(200 << 30) // 4096, f_frsize=4096))):
            stack.enter_context(patch.object(target, name, value))
        if lock is not None:
            stack.enter_context(patch.object(m.guard, 'LOCK', Path(lock)))
        if bridge is not None:
            stack.enter_context(patch.object(m, '_load_bridge', lambda: bridge))
            for name, value in (('run_page', dev.page), ('host_available_kib', lambda: 6 * 1024 * 1024),
                                ('PLAYWRIGHT', fixture), ('CHROMIUM', fixture)):
                stack.enter_context(patch.object(bridge, name, value))
        yield dev


def simulate(m, *, via_page=False, bridge=None, record_exists=True):
    """One whole run_all of driver `m` on a fresh simulated dev-d: stdout check lines, results, device calls, files."""
    root = Path(tempfile.mkdtemp()).resolve()
    try:
        lock = root / 'woowbk-dev-d-mutation.lock'
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # the driver's own hold of the dev-d lock (main() takes it)
        try:
            with simulated(m, root, bridge=bridge, lock=lock, record_exists=record_exists) as dev:
                secrets = m.drv.Secrets([root / 'secrets/b1-creds.env'], root / 'secrets/dev-d-markers.json')
                if via_page:
                    secrets.register('COCKPIT_PASSWORD', (root / 'secrets/devadmin.pass').read_text().strip())
                args = SimpleNamespace(run=True, self_check=False, arch='x86', secrets=secrets,
                                       **({'via_page': True} if via_page else {}))
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    ev = m.Ev(secrets, 'services-a-2-hsff')
                    m.drv.STATE['created_backups'] = []
                    run = m.Run(args, ev)
                    run.dev = dev
                    run.lock_started = time.monotonic()
                    failure = m.run_all(run)
                files = {str(p.relative_to(ev.dir)): p.read_bytes() for p in ev.dir.rglob('*') if p.is_file()}
                lines = [line for line in out.getvalue().splitlines() if line.endswith((': PASS', ': FAIL'))]
                return SimpleNamespace(ok=failure is None and all(r['ok'] for r in ev.results), failure=failure, lines=lines,
                                       results=ev.results, calls=dev.calls, run=run, dev=dev, files=files,
                                       state=copy.deepcopy(m.drv.STATE))
        finally:
            os.close(fd)
    finally:
        shutil.rmtree(root, ignore_errors=True)


REAL = json.loads((REPO / 'tests/backup/evidence/parity-headscale-virtual-20261127/original-ha-x86-full-flow.json').read_text())
# main()'s own tree line is not a check of the run (run_all is simulated, main is not).
REAL_CHECKS = [line for line in REAL['fixed_status'] if line.endswith(': PASS') and line != 'source tree committed: PASS']
HELPER_IMPORT = REAL_CHECKS[10:14] + REAL_CHECKS[14:15] + REAL_CHECKS[23:35]   # upload 4, found state 1, check 6, import 6


class DefaultRunTests(unittest.TestCase):
    def test_the_simulated_default_run_is_the_real_96_check_run_line_for_line(self):
        run = simulate(load_new())
        self.assertEqual(len(REAL_CHECKS), 96)
        self.assertEqual(run.lines, REAL_CHECKS)
        self.assertTrue(run.ok, [r for r in run.results if not r['ok']])
        self.assertFalse(any(call[0] == 'page' for call in run.calls))
        self.assertEqual(run.state['created_backups'], [])   # everything it made was deleted
        self.assertEqual(run.dev.data, 'own')                # dev-d's own Headscale is back
        self.assertEqual(run.dev.files, {load_new().CONFIG_REL: DEV_D_CONFIG})   # the original config, nothing else
        leaks = [call for call in run.calls if call[:2] == ('device_python', 'LEAKS')]
        self.assertNotIn('COCKPIT_PASSWORD', leaks[0][3])

    def test_this_checkouts_default_run_equals_the_reviewed_base_call_for_call(self):
        base = load_base()
        if base is None:
            self.skipTest(f'base commit {BASE} is not in this checkout')
        before, after = simulate(base), simulate(load_new())
        self.assertEqual(after.calls, before.calls)   # the same device calls, with the same requests, in the same order
        self.assertEqual([(r['check'], r['ok']) for r in after.results], [(r['check'], r['ok']) for r in before.results])
        self.assertEqual(after.lines, before.lines)
        self.assertEqual(sorted(after.files), sorted(before.files))
        for name in ('check-x86-plain-headscale.json', 'convert-job.json', 'restore-job.json', 'leaks.json'):
            self.assertEqual(after.files[name], before.files[name], name)


def page_block(texts, tag='x86-plain'):
    return ([f'upload {tag}: the local file is the recorded b1 fixture (sha256)',
             f'page import {tag}: real space: free space of staging/home/storage above the product\'s floor (running '
             'reserve + watch margin) the convert job enforces']
            + ['page: ' + name for name in page_names(texts)]
            + ['page: bounded (20 min), the browser closed in order and every relay exec child reaped',
               'page: the uploaded HA record is the fixture (id and SHA-256)',
               'page: exactly the page\'s own check and import jobs, none left running, no other new backup',
               'page: the check calls headscale importable, stops nothing, and lists every confirmation line keyed '
               '(read from the actual check)',
               'page: the one acknowledgement, the import and its jobs carry every listed confirmation key exactly once',
               'page: one conversion and its restore succeeded as two linked jobs in the first job\'s unit',
               'page: the plain backup: no key step, no key in either request, the engine was given none',
               'page: nothing to choose: the check offers no choice and neither request nor the chain carries one',
               'page: every issued Cockpit session value is absent from the records, the journal and the private evidence',
               f'upload {tag}: headscale is importable and installed here',
               f'upload {tag}: the stored sidecar names the fixture SHA-256',
               f'check {tag}/headscale: the page\'s check job succeeded',
               f'check {tag}/headscale: ok, no blockers', f'check {tag}/headscale: source amd64, add-on 0.1.3, target 0.29.4',
               f'check {tag}/headscale: headscale section equals the source facts',
               f'check {tag}/headscale: HA\'s API key does not move', 'check: no throwaway container, volume or network left',
               f'import {tag}: the page\'s conversion job succeeded with a backup id',
               f'import {tag}: ha_import: apps headscale, not test mode, the Headscale note, reminders name this device\'s URL',
               f'import {tag}: the converted backup is listed as manual with its HA origin',
               f'import {tag}: the page\'s restore of the converted backup succeeded with a safety backup, not rolled back, '
               'every health check ok'])


class ViaPageRunTests(unittest.TestCase):
    def test_via_page_replaces_only_the_import_checks_and_passes_through_the_real_bridge(self):
        m, bridge = load_new('hsff_page'), bridge_module()
        default = simulate(m)
        run = simulate(m, via_page=True, bridge=bridge)
        self.assertTrue(run.ok, [r for r in run.results if not r['ok']])
        names = [r['check'] for r in run.results]
        old = [r['check'] for r in default.results]
        block = page_block(bridge.page_settings(['headscale'], ['headscale'], [])['texts'])
        # secrets, setup (10), then the lab config and `before` (8) moved ahead of the page; the rest unchanged.
        self.assertEqual(names[:10], old[:10])
        self.assertEqual(names[10:18], old[15:23])
        self.assertEqual(names[18:18 + len(block)], block)
        self.assertEqual(names[18 + len(block):], old[35:])
        self.assertEqual((len(default.results), len(HELPER_IMPORT), len(block), len(run.results)), (96, 17, 44, 123))
        kinds = [call[0] for call in run.calls]
        self.assertEqual(kinds.count('page'), 1)
        for name in ('upload', 'run_check', 'convert'):
            self.assertNotIn(name, kinds)
        self.assertNotIn(('ok', 'inspect'), [call[:2] for call in run.calls if call[2:] and call[2] != ['backup_id', 'key']])
        restores = [call[3] for call in run.calls if call[0] == 'restore']
        self.assertEqual(restores, ['restore-inject-x86-headscale', 'rollback-x86-headscale'])   # only the later steps
        [page] = [call for call in run.calls if call[0] == 'page']
        self.assertEqual(page, ('page', 'woowbk-dev-d', ('headscale',), True, False, False, {}, True))   # no key at all
        bridge_reads = [c for c in run.calls if c[:2] in (('device_python', 'PRECONDITIONS'), ('device_python', 'NATIVE_UNITS'))]
        self.assertEqual([c[1] for c in bridge_reads], ['PRECONDITIONS', 'NATIVE_UNITS'])
        self.assertTrue(all(c[2] is False for c in bridge_reads))
        # The lab DERP config was on before the page and the original is back; dev-d's own data restored at the end.
        lab_on = next(i for i, c in enumerate(run.calls) if c[:2] == ('owner', ('systemctl', '--user', 'restart',
                                                                                 'headscale.service')))
        self.assertLess(lab_on, run.calls.index(page))
        self.assertEqual(run.dev.files, {m.CONFIG_REL: DEV_D_CONFIG})
        self.assertEqual(run.dev.data, 'own')
        self.assertEqual(run.state['created_backups'], [])
        summary = json.loads(run.files['page/page-bridge.json'])
        self.assertTrue(summary['passed'])
        self.assertIs(summary['unencrypted'], True)
        self.assertEqual(summary['device'], 'woowbk-dev-d')
        self.assertTrue(summary['ha_record_existed'])   # dev-d holds the plain b1 upload already: the page's is the same
        leaks = [call for call in run.calls if call[:2] == ('device_python', 'LEAKS')]
        self.assertIn('COCKPIT_PASSWORD', leaks[0][3])
        for name, data in run.files.items():
            for secret in (PASSWORD, HA_NOISE, HA_API, HA_COOKIE):
                self.assertNotIn(secret.encode(), data, name)

    def test_a_record_the_page_uploaded_is_removed_by_the_runs_own_cleanup(self):
        m, bridge = load_new('hsff_page_new_record'), bridge_module()
        run = simulate(m, via_page=True, bridge=bridge, record_exists=False)
        self.assertTrue(run.ok, [r for r in run.results if not r['ok']])
        self.assertEqual(run.dev.ha, [])
        self.assertEqual(run.results[-4]['check'], 'cleanup: the HA store record this run created is deleted')
        self.assertEqual(len(run.results), 124)

    def test_the_driver_hands_the_bridge_exactly_its_inputs(self):
        m = load_new('hsff_inputs')
        seen = {}

        class FakeBridge:
            Ops = staticmethod(lambda **kw: ('ops', sorted(kw)))

            class BridgeError(Exception):
                summary = {}

            Refused = BridgeError

            @staticmethod
            def import_via_page(**kwargs):
                seen.update(kwargs)
                raise FakeBridge.BridgeError('stop here')

        root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, root, True)
        with simulated(m, root) as dev:
            secrets = m.drv.Secrets([root / 'secrets/b1-creds.env'], root / 'secrets/dev-d-markers.json')
            secrets.register('COCKPIT_PASSWORD', PASSWORD)
            with contextlib.redirect_stdout(io.StringIO()):
                ev = m.Ev(secrets, 'services-a-2-hsff')
                run = m.Run(SimpleNamespace(secrets=secrets, via_page=True, arch='x86'), ev)
                run.lock_started = time.monotonic()
                started = time.monotonic()
                with self.assertRaisesRegex(m.Failed, 'did not run to the end'):
                    run.step_page_import(bridge=FakeBridge)
        self.assertEqual({k: seen[k] for k in ('device', 'lock', 'apps', 'importable', 'stops', 'fixture', 'key', 'choices',
                                               'password', 'evidence', 'source')},
                         {'device': 'woowbk-dev-d', 'lock': '/tmp/woowbk-dev-d-mutation.lock', 'apps': ['headscale'],
                          'importable': ['headscale'], 'stops': [], 'fixture': run.fixture, 'key': None, 'choices': {},
                          'password': PASSWORD, 'evidence': ev.dir / 'page', 'source': m.REPO})
        self.assertEqual(seen['ops'], ('ops', ['helper', 'root_json', 'wait_job']))
        self.assertLessEqual(seen['deadline'], started + 25 * 60 + 1)
        self.assertLessEqual(seen['deadline'], run.lock_started + m.HOLD_BUDGET - m.REST_RESERVE + 1)
        self.assertEqual([r['check'] for r in ev.results][-1], 'page import: refused before the page started (nothing changed)')
        self.assertIsNone(run.created_store)
        self.assertIsNone(run.safety)   # nothing restored: no closing rollback to run

    def test_a_failed_gate_after_the_restore_still_returns_dev_ds_own_headscale(self):
        m, bridge = load_new('hsff_page_gate'), bridge_module()
        real_page = Dev.page

        def scan_missing(self, config, seconds, device):
            outcome = real_page(self, config, seconds, device)
            browser = json.loads(Path(config['result']).read_text())
            browser['issued_scan_counts']['scan_completed'] = False
            Path(config['result']).write_text(json.dumps(browser))
            return outcome
        with patch.object(Dev, 'page', scan_missing):
            run = simulate(m, via_page=True, bridge=bridge)
        self.assertIsInstance(run.failure, m.Failed)
        self.assertIn('rollback: restore-start of the import\'s safety backup succeeded, every health check ok',
                      [r['check'] for r in run.results if r['ok']])
        self.assertEqual(run.dev.data, 'own')
        self.assertEqual(run.state['created_backups'], [])
        self.assertEqual(run.dev.files, {m.CONFIG_REL: DEV_D_CONFIG})


class CommandLineTests(unittest.TestCase):
    def test_only_via_page_reads_the_cockpit_login_and_changes_the_phases(self):
        m = load_new('hsff_cli')
        for via_page, expected in ((None, ['secrets', 'setup', 'upload', 'found state', 'lab config', 'before', 'check',
                                           'import', 'verify', 'volume keys', 'status', 'clients', 'restart',
                                           'auto rollback']),
                                   (True, ['secrets', 'setup', 'lab config', 'before', 'page import', 'verify',
                                           'volume keys', 'status', 'clients', 'restart', 'auto rollback'])):
            with self.subTest(via_page=via_page):
                order = []
                args = SimpleNamespace() if via_page is None else SimpleNamespace(via_page=via_page)
                run = SimpleNamespace(args=args, ev=SimpleNamespace(log=lambda text: order.append(text[3:]),
                                                                    check=lambda *a, **k: True),
                                      budget=lambda name: None, private=None, safety=None)
                for name in ('load_secrets', 'setup', 'step_upload', 'step_found_state_check', 'lab_config_on',
                             'step_before', 'step_check', 'step_import', 'step_page_import', 'clients_phase', 'step_restart',
                             'step_auto_rollback', 'clients_stop', 'inject_off', 'lab_config_off', 'step_cleanup'):
                    setattr(run, name, lambda: None)
                run.verify = lambda *a, **k: None
                with patch.object(m, 'keep_volume_keys', lambda *a: None), patch.object(m, 'app_status', lambda *a: None), \
                        patch.object(m.drv, 'app_health', lambda *a: None):
                    self.assertIsNone(m.run_all(run))
                self.assertEqual(order, expected)
        parser_help = subprocess.run([sys.executable, '-B', str(HERE / 'headscale_full_flow.py'), '--help'],
                                     capture_output=True, text=True, timeout=60).stdout
        self.assertIn('--via-page', parser_help)


if __name__ == '__main__':
    unittest.main()
