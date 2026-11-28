"""Offline: focus_nextcloud_r6_page.py (the no-share Nextcloud import through dev-e's real page, cold to cold) against a
simulated dev-e: the R6 inventory, wake, pin/revert and cold-stop programs, the root helper's transport (the real b1
driver's ok/wait_job/restore run on top of it), the device programs and the page process behind the REAL bridge. No
device, no labpodman, no browser, no real secret; every lab path points into a temporary folder with generated values.
"""
import base64
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
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
HA_KEY = 'GENERATED-HA-KEY-0123456789abcdef'
PASSWORD = 'generated-cockpit-pass-3333'
USER_PW = 'generated-noshare-user-pass-5555'
APP_PW = 'generated-noshare-app-pass-6666'
MARKER_PW = 'generated-marker-pass-7777'
KIT = '# generated stand-in kit\nAGE-SECRET-KEY-1GENERATEDSTANDIN0123456789ABCDEFGHJKLMNPQRSTUV\n'
NO_SHARE_KEY = 'nextcloud.no-share:' + 'a' * 16
EXTRA_KEY = 'nextcloud.db-objects-skipped:' + 'b' * 16
COMMIT = '0' * 40

sys.path.insert(0, str(HERE))


def load_page(name='r6_page'):
    spec = importlib.util.spec_from_file_location(name, HERE / 'focus_nextcloud_r6_page.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def bridge_module():
    spec = importlib.util.spec_from_file_location('r6_page_test_bridge', HERE / 'focus_page_bridge.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def answer(stdout=b'', returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=stdout if isinstance(stdout, bytes) else stdout.encode(), stderr=b'')


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else Path(data).read_bytes()).hexdigest()


UNIT_NAMES = ('nextcloud.target', 'nextcloud-app.service', 'nextcloud-db.service', 'nextcloud-redis.service',
              'nextcloud-office.service', 'nextcloud-gateway.service', 'nextcloud-cron.timer', 'woowtech-backup-schedule.timer')
OFFICE = {'richdocuments.wopi_url': 'http://127.0.0.1:9980', 'core.backgroundjobs_mode': 'cron'}
CAPS = {'keys': ['collabora', 'config', 'productName'], 'config': {'wopi_url': 'http://127.0.0.1:9980'},
        'collabora': ['convert-to'], 'product': 'Nextcloud Office'}


class NcDev:
    """dev-e as focus_nextcloud_r6_page.py sees it: Nextcloud cold with the five original images loaded, its own
    baseline data live, the encrypted baseline backup kept; the page imports the no-share backup."""

    def __init__(self, p, nc, fixture_sha, bridge):
        self.p, self.nc, self.bridge = p, nc, bridge
        self.store_id = 'ha-' + fixture_sha[:20]
        self.fixture_sha = fixture_sha
        self.calls, self.helper_calls = [], []
        self.running = False
        self.pinned = False
        self.timer = 'enabled'
        self.deployed = False
        self.data = 'base'
        self.ha, self.jobs = [], []
        self.backups = {p.BASELINE: {'id': p.BASELINE, 'type': 'manual', 'key_id': 'k-1', 'size': 422031360,
                                     'holds': 'base'},
                        '20261127T120000Z-0000prev': {'id': '20261127T120000Z-0000prev', 'type': 'manual',
                                                      'key_id': 'k-1', 'size': 1000, 'holds': 'other'}}
        self.sequence = 0
        self.headroom = 1500 * 1024 ** 2
        self.page_mode = 'normal'
        self.extra_confirm = False
        self.client_fails = False
        self.office_flag = False
        self.lock = threading.Lock()

    # ---------------------------------------------------------------- bookkeeping
    def log(self, *entry):
        with self.lock:
            self.calls.append(entry)

    def new_backup(self, kind, holds, **extra):
        self.sequence += 1
        bid = '20261128T1000%02dZ-%08x' % (self.sequence, self.sequence)
        self.backups[bid] = {'id': bid, 'type': kind, 'key_id': 'k-1', 'size': 600 * 1024 ** 2, 'holds': holds, **extra}
        return bid

    def job(self, kind, params, state, result, unit=None):
        self.sequence += 1
        jid = 'j20261128T1100%02dZ-%08x' % (self.sequence, self.sequence)
        record = {'id': jid, 'type': kind, 'state': state, 'phase': 'done' if state not in ('queued', 'running') else 'run',
                  'progress': {}, 'params': params, 'result': result, 'unit': unit or f'woowtech-backup-{jid}.service'}
        self.jobs.append(record)
        return record

    def public(self, job):
        return {k: copy.deepcopy(v) for k, v in job.items() if k != 'unit'}

    def restore_of(self, backup_id):
        """A restore of `backup_id`: its data goes live, a safety backup keeps what was live."""
        safety = self.new_backup('safety', self.data)
        self.data = self.backups[backup_id]['holds']
        return 'succeeded', {'rolled_back': False, 'safety_backup_id': safety, 'health': [{'status': 'ok'}],
                             'downtime_seconds': 100}

    # ---------------------------------------------------------------- the R6 programs (wake.device / cold.device)
    def quadlet(self, name):
        ref, config = self.p.wake.FILES[name]
        image = f'sha256:{config}' if self.pinned else ref
        extra = 'Pull=never\n' if self.pinned else ''
        return f'[Container]\nImage={image}\n{extra}'.encode()

    def snapshot(self):
        return {'rows': [{'name': name, 'data_b64': base64.b64encode(self.quadlet(name)).decode(),
                          'sha256': sha(self.quadlet(name)), 'config_id': config, 'original_ref': ref}
                         for name, (ref, config) in self.p.wake.FILES.items()]}

    def unit_states(self):
        out = {}
        for name in UNIT_NAMES:
            on = self.running and name != 'woowtech-backup-schedule.timer'
            out[name] = {'ActiveState': 'active' if on else 'inactive', 'SubState': 'running' if on else 'dead',
                         'UnitFileState': 'enabled' if name.endswith(('.target', '.timer')) else 'generated'}
        out['woowtech-backup-schedule.timer']['UnitFileState'] = ''
        return out

    def installed(self):
        lib = REPO / 'backup-engine/woowbackup'
        tree = {str(q.relative_to(lib)): sha(q) for q in lib.rglob('*.py') if '__pycache__' not in q.parts}
        return tree if self.deployed else dict(tree, **{'hacommands.py': 'f' * 64})

    def collect(self):
        self.log('collect')
        quadlets = {name: {'sha256': sha(self.quadlet(name)), 'images': [self.quadlet(name).decode().split('Image=')[1]
                                                                          .split('\n')[0]]}
                    for name in self.p.wake.FILES}
        quadlets['nextcloud.network'] = {'sha256': 'n' * 64, 'images': []}
        images = [{'ref': ref, 'present': True, 'identity': {'id': 'sha256:' + config, 'architecture': 'amd64',
                                                             'os': 'linux', 'size': 1, 'repo_tags': [ref],
                                                             'repo_digests': []}}
                  for ref, config in self.p.ORIGINALS.items()]
        installed = self.installed()
        return {'status': 'read-only-inventoried', 'device': 'woowbk-dev-e',
                'isolation': {'running': True, 'network': 'none', 'ports': {}, 'memory_limit': self.p.DEVICE_CAP},
                'owner': {'images': images, 'units': self.unit_states(), 'quadlets': quadlets},
                'root': {'memory_current': 554872832, 'memory_max': str(self.p.DEVICE_CAP), 'varlib_free_bytes': 29 << 30,
                         'installed_hashes': {n: installed.get(n) for n in self.p.ENGINE_MODULES}, 'catalog_exists': True,
                         'catalog_sha256': self.p.ORIGINAL_CATALOG_SHA,
                         'original_baseline_entries': [{'bytes': 655, 'directory': False}]},
                'host_free_bytes': 29 << 30, 'host_memory_available_mib': 4549}

    def wake_device(self, program, request=None, *, root=False, timeout=300):
        p = self.p
        if program == p.control.RESOURCE:
            return {'free': 29 << 30, 'memory': 1200 * 1024 ** 2}
        names = {p.wake.CONTROL: 'CONTROL', p.wake.BASELINE_HASH: 'BASELINE_HASH', p.cold.CLAIM: 'CLAIM',
                 p.cold.STOP: 'STOP', p.control.QUIESCENT: 'QUIESCENT', p.control.BASELINE_INSPECT: 'BASELINE_INSPECT'}
        name = 'UNITS' if program == p.wake.unit_program() else names.get(program)
        action = (request or {}).get('action')
        self.log('wake', name if action is None else f'{name}:{action}', root)
        if name == 'UNITS' and action == 'snapshot':
            return self.snapshot()
        if name == 'UNITS' and action == 'pin':
            assert not self.pinned and request['snapshot'] == self.snapshot()
            self.pinned = True
            return {'status': 'pinned', 'files': 5}
        if name == 'UNITS' and action == 'revert':
            self.pinned = False
            return {'status': 'reverted', 'files': 5}
        if name == 'CONTROL' and action == 'start':
            assert self.pinned, 'the loaded images are only reachable through the pins'
            self.running = True
            return {'status': 'started', 'minimum_free_bytes': 28 << 30, 'peak_memory_bytes': 809451520}
        if name == 'BASELINE_HASH':
            return [{'name': p.BASELINE + '.json', 'size': 655, 'sha256': '1' * 64},
                    {'name': p.BASELINE + '.tar', 'size': 422031360, 'sha256': '2' * 64}]
        if name == 'CLAIM':
            return {'ActiveState': 'active', 'MainPID': '4242', 'InvocationID': 'abc'}
        if name == 'STOP':
            if getattr(self, 'stop_fails', False):
                raise RuntimeError('fixed-wake-device-step-failed')
            self.running = False
            return {'status': 'stopped', 'only_owned_office_failed_flag_cleared': self.office_flag}
        if name == 'QUIESCENT':
            return {'active_jobs': sum(job['state'] in ('queued', 'running') for job in self.jobs)}
        if name == 'BASELINE_INSPECT':
            assert request['key'] == KIT and root
            return {'status': 'passed', 'baseline_id': p.BASELINE, 'encrypted_manifest_opened': True,
                    'preflight_ok_settings_same_inplace': True, 'persistent_key_import': False, 'record_update': False}
        raise AssertionError(('wake', name, action))

    def reload_units(self):
        self.log('reload')

    def baseline_verify(self):
        self.log('baseline_verify')
        return self.running and self.data == 'base'

    # ---------------------------------------------------------------- the b1 driver's transport and device calls
    def root(self, *argv, input=None, timeout=600, check=False):
        self.log('root', argv)
        if argv[:2] == ('systemctl', 'is-enabled'):
            return answer(self.timer + '\n')
        if argv[:2] == ('systemctl', 'mask'):
            self.found_timer, self.timer = self.timer, 'masked'
            return answer()
        if argv[:2] == ('systemctl', 'unmask'):
            self.timer = self.found_timer
            return answer()
        raise AssertionError(('root', argv))

    def run(self, argv, *, input=None, stdin=None, timeout=600, check=False):
        self.log('run', tuple(Path(a).name if str(a).startswith('/') else a for a in argv[:3]))
        if argv[:2] == ['bash', str(HERE / 'deploy-src.sh')] and argv[2:] == ['e', '--src', str(REPO), '--no-demo-catalog']:
            assert not self.running, 'deploy-src.sh runs while Nextcloud is cold'
            self.deployed = True
            return answer('deployed this tree\n')
        raise AssertionError(('run', argv))   # nothing else may ever leave this process

    def owner(self, *argv, input=None, timeout=600, check=False):
        self.log('owner', argv[:2] + argv[4:] if argv[:3] == ('python3', '-I', '-c') else argv)
        if argv[:3] == ('python3', '-I', '-c') and argv[4:] == ('nextcloud', 'read'):
            assert json.loads(input)['password'] == MARKER_PW and self.running
            found = ({'users': ['woowbk-lab-baseline'], 'files': ['woowbk-lab-baseline.txt:0a0a0a0a']}
                     if self.data == 'base' else {'users': [], 'files': []})
            return answer(json.dumps(found) + '\n')
        if argv[:4] == ('podman', 'unshare', 'du', '-sb'):
            size = {'html': 849259813, 'postgres': 75382634, 'data': 234187031}[argv[4].rsplit('/', 1)[1]]
            return answer(f'{size}\t{argv[4]}\n')
        raise AssertionError(('owner', argv))

    def state(self):
        base = self.data == 'base'
        return {'config_sha256': 'c' * 64 if base else 'd' * 64,
                'users': ['admin', 'woowbk-lab-baseline'] if base else ['admin', 'woow-import-test', 'woow-mcp-test'],
                'status': {'installed': True, 'version': '35.0.1.1', 'maintenance': False, 'needsDbUpgrade': False},
                'db': {'storages': ['home::admin'], 'users': 2 if base else 3},
                'data_top': ['.htaccess', '.ncdata', 'admin', 'woowbk-lab-baseline'] if base else ['.htaccess', '.ncdata'],
                'units': {u: 'active' if self.running else 'inactive' for u in self.nc.UNITS},
                'office': dict(OFFICE), 'fingerprint': '1111aaaa2222bbbb' if base else '3333cccc4444dddd',
                'filecache_rows': 191}

    def device_python(self, script, request=None, *, as_owner=True, timeout=600):
        nc, bridge, p = self.nc, self.bridge, self.p
        name = {nc.ENGINE_HASHES: 'ENGINE_HASHES', nc.STATE: 'STATE', nc.CLIENT: 'CLIENT', nc.LEAKS: 'LEAKS',
                nc.drv.RUN_LIST: 'RUN_LIST', p.NOSHARE_CLIENT: 'NOSHARE_CLIENT', bridge.PRECONDITIONS: 'PRECONDITIONS',
                bridge.NATIVE_UNITS: 'NATIVE_UNITS'}.get(script)
        self.log('device_python', name, as_owner)
        if name == 'ENGINE_HASHES':
            return self.installed()
        if name == 'STATE':
            return self.state()
        if name == 'CLIENT':      # dev-e's own account (only its own data knows it)
            assert request['user'] == 'woowbk-lab-baseline' and request['user_pw'] == MARKER_PW
            own = self.data == 'base'
            return {'status': self.state()['status'], 'ocs': {'password': [200 if own else 401, own], 'wrong': [401, False]},
                    'capabilities': [200, copy.deepcopy(CAPS)], 'fingerprint': [207, '1111aaaa2222bbbb'],
                    'discovery': [200, True]}
        if name == 'NOSHARE_CLIENT':
            if self.client_fails:
                raise self.nc.Failed('device probe failed (rc 1); diagnostic output suppressed')
            assert request == {'user': 'woow-import-test', 'user_pw': USER_PW}
            imported = self.data == 'ha'
            return {'status': self.state()['status'],
                    'ocs': {'password': [200 if imported else 401, imported], 'wrong': [401, False]},
                    'capabilities': [200, copy.deepcopy(CAPS)], 'discovery': [200, True],
                    'web': {'control': 200, 'codes': [403, 404, 403],
                            'htaccess': sha(self.nc.ha_nextcloud.DATA_HTACCESS), 'htaccess_below': '0'},
                    'storage': 'local::/var/www/html/data/', 'owners': 'oc_admin'}
        if name == 'LEAKS':
            assert not as_owner
            self.leak_names = sorted(request['secrets'])
            return {'scanned': 210, 'journal_bytes': 4096, 'names': len(request['secrets']), 'hits': 0,
                    'url_token_access_log_hits': 0, 'url_token_hits_elsewhere': 0}
        if name == 'RUN_LIST':
            return {'/var/lib/woowtech-backup/staging': [], '/run/woowtech-backup': ['engine.lock']}
        if name == 'PRECONDITIONS':
            assert self.running
            return {'page': {n: sha(REPO / 'backup' / n) for n in bridge.PAGE_FILES}, 'cockpit_socket': True,
                    'hostname': 'woowbk-dev-e', 'devadmin_uid': 1000, 'headroom': self.headroom}
        if name == 'NATIVE_UNITS':
            rows = {job['id']: job for job in self.jobs}
            return [{k: rows[j][k] for k in ('id', 'unit', 'type', 'state')} for j in request['ids']]
        raise AssertionError(('device_python', script[:60]))

    def helper(self, command, request=None, *, timeout=1800):
        """The root helper (one JSON request, one reply); the b1 driver's ok, wait_job and restore run on top of it."""
        self.helper_calls.append((command, copy.deepcopy(request)))
        if command == 'status':
            return 0, {'version': (REPO / 'VERSION').read_text().strip(), 'key': {'key_id': 'k-1'},
                       'active_job': next((j['id'] for j in self.jobs if j['state'] in ('queued', 'running')), None)}
        if command == 'list':
            return 0, {'backups': [{k: v for k, v in row.items() if k != 'holds'} for row in self.backups.values()],
                       'ha_backups': [dict(row) for row in self.ha]}
        if command == 'jobs':
            return 0, {'jobs': [self.public(job) for job in reversed(self.jobs)]}
        if command == 'job-status':
            return 0, {'job': self.public(next(j for j in self.jobs if j['id'] == request['job_id'])), 'log': []}
        if command == 'restore-start':
            assert request['backup_id'] in self.backups and request['confirm'] is True and request['request_id']
            state, result = self.restore_of(request['backup_id'])
            return 0, {'job_id': self.job('restore', {'backup_id': request['backup_id'], 'apps': request['apps']},
                                          state, result)['id']}
        if command == 'delete':
            return (0, {}) if self.backups.pop(request['backup_id'], None) else (1, {'error': 'not-found'})
        if command == 'ha-delete':
            before = len(self.ha)
            self.ha = [row for row in self.ha if row['id'] != request['ha_backup_id']]
            return (0, {}) if len(self.ha) < before else (1, {'error': 'not-found'})
        if command == 'job-cancel':
            job = next(j for j in self.jobs if j['id'] == request['job_id'])
            if job['type'] == 'restore' and job['state'] == 'running':   # the engine's own rollback puts the data back
                safety = self.new_backup('safety', 'base')
                self.data = 'base'
                job.update(state='rolled-back', phase='done',
                           result={'rolled_back': True, 'safety_backup_id': safety, 'health': []})
            elif job['state'] in ('queued', 'running'):
                job.update(state='cancelled', phase='done')
            return 0, {}
        raise AssertionError(('helper', command))   # upload, check, convert, inspect, import: never the driver itself

    def labelled(self):
        self.log('labelled')
        return {'containers': [], 'volumes': [], 'networks': []}

    def catalog(self, app):
        self.log('catalog', app)
        return {'id': 'nextcloud', 'units': list(self.nc.UNITS), 'postgres': None, 'volumes': [],
                'data_dirs': [{'path': f'.local/share/nextcloud-office/{n}'} for n in ('data', 'html', 'postgres', 'redis')]}

    # ---------------------------------------------------------------- the real page's effects
    def check_result(self, ha_id):
        issues = [{'id': 'nextcloud.no-share', 'level': 'confirm', 'message': 'no share folder', 'items': ['/share/nextcloud'],
                   'more': 0, 'key': NO_SHARE_KEY},
                  {'id': 'legacy.warning', 'level': 'notice', 'message': 'w', 'items': [], 'more': 0}]
        if self.extra_confirm:
            issues.append({'id': 'nextcloud.db-objects-skipped', 'level': 'confirm', 'message': 'functions left out',
                           'items': ['f'], 'more': 0, 'key': EXTRA_KEY})
        return {'ha_check': {'schema': 2, 'ha_backup_id': ha_id, 'shared': [],
                             'apps': [{'app_id': 'nextcloud', 'ok': False, 'blockers': ['no share'], 'importable': True,
                                       'warnings': ['no share'], 'arch': 'amd64', 'version': '0.2.3',
                                       'target_version': '35.0.1.1', 'issues': issues,
                                       'nextcloud': dict(self.nc.SECTION)}]}}

    def page(self, config, seconds, device):
        self.log('page', device, tuple(config['apps']), seconds <= 20 * 60, config['key'] == HA_KEY,
                 config['password'] == PASSWORD)
        assert self.running and config['ha_id'] == self.store_id
        if not any(row['id'] == self.store_id for row in self.ha):
            self.ha.append({'id': self.store_id, 'sha256': self.fixture_sha,
                            'importable_apps': [{'slug': 'nc', 'app_id': 'nextcloud', 'installed': True}]})
        self.job('verify', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['nextcloud'], 'key_provided': True},
                 'succeeded', self.check_result(config['ha_id']))
        sent = {'nextcloud': sorted([NO_SHARE_KEY] + ([EXTRA_KEY] if self.extra_confirm else []))}
        converted = self.new_backup('manual', 'ha', from_ha={'ha_backup_id': self.store_id})
        result = {'backup_id': converted,
                  'ha_import': {'apps': ['nextcloud'], 'test_mode': False,
                                'notes': ['n1', 'Office: this device\'s Collabora stays', 'n3', 'n4'],
                                'reminders_by_app': {'nextcloud': ['r1', 'r2', 'r3', 'r4', 'r5',
                                                                   'Woow Nextcloud MCP Server: log in again']}}}
        first = self.job('backup', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['nextcloud'],
                                    'test_mode': False, 'acknowledged': copy.deepcopy(sent),
                                    'group': {'kind': 'ha-import', 'step': 'convert', 'index': 0, 'count': 1},
                                    'chain': {'apps': ['nextcloud'], 'test_mode': False, 'then_restore': True,
                                              'acknowledged': copy.deepcopy(sent)}}, 'succeeded', result)
        restore_params = {'backup_id': converted, 'apps': ['nextcloud'], 'ha_backup_id': config['ha_id']}
        if self.page_mode == 'interrupt':     # SIGTERM while the import's restore runs
            self.data = 'ha'
            second = self.job('restore', restore_params, 'running', {}, unit=first['unit'])
            result['group'] = {'next_job_id': second['id'], 'results': []}
            Path(config['result']).write_text(json.dumps({'completed': False, 'checks': []}))
            return {'started': True, 'exit': -15, 'timed_out': False, 'interrupted': True, 'stop': 'terminated',
                    'relay_clean': True, 'relay_error': None, 'children_left': []}
        state, restored = self.restore_of(converted)
        restored['group'] = {'next_job_id': None, 'results': [{'app_id': 'nextcloud', 'status': 'imported'}]}
        second = self.job('restore', restore_params, state, restored, unit=first['unit'])
        result['group'] = {'next_job_id': second['id'], 'results': []}
        texts = config['texts']
        names = ['UI real administrative Cockpit bridge reaches this device', texts['upload'], texts['select'],
                 'UI actual check confirmation keys observed including valid zero', texts['view'], texts['lines'],
                 'UI has exactly one acknowledgement and import waits for it',
                 'UI check did not start an import or separate restore', 'UI real key field removed before screenshot',
                 'UI one acknowledgement enables import', texts['result'], texts['intent'], texts['keys'],
                 'UI no page script errors during this page flow', 'UI cookie observation completed without gaps',
                 'UI every issued credential absent from records journal and private evidence; proved public markers '
                 'counted separately']
        lines = len(sent['nextcloud'])
        browser = {'stage': 'issued-value-scan', 'failure_kind': None, 'completed': True, 'issued_values_scanned': True,
                   'checks': [{'check': n, 'ok': True} for n in names],
                   'confirmations': {'expected_keys': sent, 'sent_keys': sent, 'lines_expected': lines,
                                     'lines_shown': lines, 'check_importable': ['nextcloud']},
                   'issued_scan_counts': {'scan_completed': True, 'observed_values': 2, 'observations_complete': True,
                                          'credential_device_hits': 0, 'credential_host_hits': 0, 'device_files': 30,
                                          'host_files': 3, 'archive_index_sidecars': 4, 'regular_json_roots': 2},
                   'wire': {'import_starts': 1}}
        Path(config['result']).write_text(json.dumps(browser))
        return {'started': True, 'exit': 0, 'timed_out': False, 'interrupted': False, 'stop': 'exited',
                'relay_clean': True, 'relay_error': None, 'children_left': []}


def lab(root):
    files = {'b1-creds.env': f'HA_BACKUP_KEY={HA_KEY}\nB2_NC_X86_NOSHARE_USER_PW={USER_PW}\n'
                             f'B2_NC_X86_NOSHARE_APP_PW={APP_PW}\n',
             'ha-import-creds.env': 'GENERATED_OTHER_PW=generated-other-pass-1234\n',
             'dev-e-markers.json': json.dumps({'nextcloud': MARKER_PW}), 'devadmin.pass': PASSWORD + '\n',
             'dev-e-kit.txt': KIT}
    for name, text in files.items():
        path = root / 'secrets' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o600)
    fixture = root / 'fixture.tar'
    fixture.write_bytes(b'generated stand-in for the encrypted no-share Nextcloud HA backup ' * 64)
    return fixture


def lease_for(p, nc, commit=COMMIT, **change):
    now = time.time()
    lease = {'device': 'woowbk-dev-e', 'lane': 'nextcloud-r6', 'phases': ['noshare-page'], 'source_commit': commit,
             'reserve_bytes': p.RESERVE, 'memory_cap_bytes': p.DEVICE_CAP,
             'not_before_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 60)),
             'expires_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 2 * 3600)),
             'fixture_sha256': nc.FIXTURE_SHA, 'pin_refresh_policy': p.PIN_POLICY, 'recovery_grace_seconds': 1800,
             'source_deployment': 'deploy-src-this-checkout', 'page_device': 'woowbk-dev-e'}
    lease.update(change)
    return lease


@contextlib.contextmanager
def simulated(root, configure=None):
    """The page module with every device-facing function answered by NcDev and every lab path in `root`."""
    p = load_page()
    p.ORIGINALS = sys.modules['focus_nextcloud_r6_inventory'].ORIGINALS
    bridge = bridge_module()
    fixture = lab(root)
    real_load_flow = p.load_flow
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(p, 'LAB', root))
        nc = real_load_flow()
        dev = NcDev(p, nc, sha(fixture), bridge)
        if configure:
            configure(dev)
        lock = root / 'woowbk-dev-e-mutation.lock'
        for target, name, value in (
                (p, 'LOCK', str(lock)), (p, 'load_flow', lambda: nc),
                (p, '_load', lambda name, alias=None: bridge if name == 'focus_page_bridge' else None),
                (p, 'collect', dev.collect), (p, 'baseline_verify', dev.baseline_verify),
                (p.wake, 'device', dev.wake_device), (p.cold, 'device', dev.wake_device),
                (p.control, 'reload_units', dev.reload_units),
                (nc, 'SECRET_FILES', (root / 'secrets' / 'ha-import-creds.env', root / 'secrets' / 'b1-creds.env')),
                (nc, 'MARKERS', root / 'secrets' / 'dev-e-markers.json'), (nc, 'FIXTURE', fixture),
                (nc, 'FIXTURE_SHA', sha(fixture)), (nc.drv, 'LAB', root),
                (nc.drv, 'run', dev.run), (nc.drv, 'root', dev.root), (nc.drv, 'owner', dev.owner),
                (nc.drv, 'helper', dev.helper), (nc.drv, 'device_python', dev.device_python),
                (nc.drv, 'labelled', dev.labelled), (nc.drv, 'catalog', dev.catalog),
                (bridge, 'run_page', dev.page), (bridge, 'host_available_kib', lambda: 6 * 1024 * 1024),
                (bridge, 'PLAYWRIGHT', fixture), (bridge, 'CHROMIUM', fixture), (time, 'sleep', lambda _s: None)):
            stack.enter_context(patch.object(target, name, value))
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        stack.callback(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # main() takes it; the bridge checks this process holds it
        yield SimpleNamespace(p=p, nc=nc, dev=dev, bridge=bridge, fixture=fixture, lock=lock)


def run_once(configure=None):
    root = Path(tempfile.mkdtemp()).resolve()
    try:
        with simulated(root, configure) as sim:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code, ev = sim.p.control_run(lease_for(sim.p, sim.nc), COMMIT, time.monotonic())
                final = sim.p.finish(ev, code)
            files = {str(q.relative_to(ev.dir)): q.read_bytes() for q in ev.dir.rglob('*') if q.is_file()}
            receipt = json.loads((root / 'run' / sim.p.RECEIPT_NAME).read_text()) \
                if (root / 'run' / sim.p.RECEIPT_NAME).exists() else None
            return SimpleNamespace(code=code, final=final, results=ev.results, names=[r['check'] for r in ev.results],
                                   failed=[r['check'] for r in ev.results if not r['ok']], dev=sim.dev, files=files,
                                   stdout=out.getvalue(), receipt=receipt, p=sim.p, bridge=sim.bridge)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def page_block(texts):
    browser = ['UI real administrative Cockpit bridge reaches this device', texts['upload'], texts['select'],
               'UI actual check confirmation keys observed including valid zero', texts['view'], texts['lines'],
               'UI has exactly one acknowledgement and import waits for it', 'UI check did not start an import or separate restore',
               'UI real key field removed before screenshot', 'UI one acknowledgement enables import', texts['result'],
               texts['intent'], texts['keys'], 'UI no page script errors during this page flow',
               'UI cookie observation completed without gaps',
               'UI every issued credential absent from records journal and private evidence; proved public markers counted '
               'separately']
    return ['page: ' + name for name in browser] + [
        'page: bounded (20 min), the browser closed in order and every relay exec child reaped',
        'page: the uploaded HA record is the fixture (id and SHA-256)',
        'page: exactly the page\'s own check and import jobs, none left running, no other new backup',
        'page: the check calls nextcloud importable, stops nothing, and lists every confirmation line keyed (read from the '
        'actual check)',
        'page: the one acknowledgement, the import and its jobs carry every listed confirmation key exactly once',
        'page: one conversion and its restore succeeded as two linked jobs in the first job\'s unit',
        'page: every issued Cockpit session value is absent from the records, the journal and the private evidence']


ADMISSION = ['admission: dev-e is cold and isolated (network none, no port, 3 GiB cap), five original images loaded, '
             'Quadlets unpinned, wake admitted',
             'admission: the host keeps the 13 GiB reserve after the page import\'s historical peak (upload, check, '
             'conversion, restore)',
             'admission: no job is running on dev-e and no earlier run of this case is pending']
DEPLOY_WAKE = ['deploy: the scheduled-backup timer is masked (shared lab, no schedule)',
               'deploy: deploy-src.sh e --src <this tree> --no-demo-catalog (the page and the engine of this checkout; '
               'Nextcloud cold)',
               'wake: the five Quadlets pinned to their loaded config IDs and the stack started within the reserve and the '
               'memory cap',
               'wake: the original baseline verified before the import (batch2_baseline.py --verify nextcloud)']
SETUP_BEFORE = ['setup: the installed engine is exactly this tree',
                'setup: the helper answers status with this tree\'s VERSION; a device key exists',
                'setup: the original nextcloud catalog entry (R6 hash) names the five units and the four data dirs',
                'setup: five units active and Nextcloud healthy (status.php installed 35.0.1.1, no maintenance)',
                'before: the original encrypted baseline opens with the existing private kit (preflight in place)',
                'before: dev-e\'s own markers read (baseline user and its WebDAV file)',
                'before: dev-e\'s own account logs in (OCS) and the wrong password is refused',
                'before: fresh live directory sizes available']
RESERVE_CHECK = ['page import: dev-e keeps the 13 GiB reserve after the import\'s peak (upload, check, conversion and '
                 'restore, from the live sizes)']
JUDGED = ['upload: nextcloud is importable and installed here', 'check: the page\'s check job succeeded',
          'check: the job answers one app: nextcloud importable, the missing share folder (nextcloud.no-share) its only '
          'line to confirm, nothing stops',
          'check: the section equals the backup facts (HA cluster opened and read: users, files, tokens, apps)',
          'check: amd64, add-on 0.2.3, target 35.0.1.1', 'check: no throwaway container, volume or network left',
          'import: the page\'s conversion job succeeded with a backup id',
          'import: the notes and reminders name Collabora and the MCP admin lines',
          'import: the converted backup is listed as manual with its HA origin, encrypted',
          'import: the page\'s restore of the converted backup succeeded with a safety backup, not rolled back, every '
          'health check ok']
VERIFY = ['import: status.php installed 35.0.1.1, no maintenance, no database upgrade needed',
          'import: HA\'s users are live (the HA test user there, dev-e\'s own marker user gone, the check\'s user count)',
          'import: the HA test user logs in (OCS, HA\'s password moved); a wrong password gets 401',
          'import: Office settings (richdocuments wopi keys) and the cron mode are exactly this device\'s',
          'import: Nextcloud reports this device\'s Office server (capabilities as for dev-e\'s own account)',
          'import: Collabora discovery is served on this device\'s gateway',
          'import: config.php carries a new data fingerprint (the restored-from-backup signal)',
          'import: the web server serves nothing below the data dir (Nextcloud\'s own protection file; static control '
          'served)',
          'import: database: root storage is this device\'s data dir, tables owned by oc_admin']


def rollback(phase):
    return [f'{phase}: the import\'s safety backup restored (manual rollback), every health check ok',
            f'{phase}: dev-e\'s own markers are back exactly and the HA-only users are gone',
            f'{phase}: dev-e\'s own account logs in again (OCS)',
            f'{phase}: the original baseline verified (batch2_baseline.py --verify nextcloud)']


AFTER = ['after: dev-e\'s own markers are unchanged', 'after: config.php unchanged', 'after: the users unchanged',
         'after: the storages and user count in the database unchanged', 'after: the data dir top entries unchanged',
         'after: the five units unchanged', 'after: status.php unchanged', 'after: the Office settings and the cron mode unchanged']


def cleanup(deleted, ha=True):
    return (['cleanup: a backup this run created is deleted'] * deleted
            + (['cleanup: the HA store record of this run is deleted'] if ha else [])
            + ['cleanup: no throwaway container, volume or network of a job left',
               'cleanup: no staging folder and no key file left',
               'leaks: no HA key, HA test credential, marker or Cockpit password or kit in engine records, uploads, staging, '
               'run dir, journal or evidence'])


RETURN = ['return: no job is running on dev-e (before the stop)',
          'return: the Nextcloud stack is cold again (every unit inactive; only this run\'s own Office failed flag cleared)',
          'return: the five Quadlets are byte for byte as before (pins reverted)',
          'return: units, Quadlets, images, catalog, baseline archive, isolation, memory cap as before; the engine modules '
          'are this checkout\'s',
          'return: the scheduled-backup timer is unmasked again (as found)']


def owned_only(test, run):
    """The driver's own helper commands: reads, the restore of the import's safety backup, deletes of what it made."""
    commands = {command for command, _request in run.dev.helper_calls}
    test.assertLessEqual(commands, {'status', 'list', 'jobs', 'job-status', 'restore-start', 'delete', 'ha-delete',
                                    'job-cancel'})
    for command, request in run.dev.helper_calls:
        if command in ('restore-start', 'delete'):
            test.assertNotEqual(request['backup_id'], run.p.BASELINE)
            test.assertNotEqual(request['backup_id'], '20261127T120000Z-0000prev')
    test.assertIn(run.p.BASELINE, run.dev.backups)                       # the baseline and others' backups stay
    test.assertIn('20261127T120000Z-0000prev', run.dev.backups)


class WholeRunTests(unittest.TestCase):
    def test_the_page_imports_the_no_share_backup_and_dev_e_returns_cold_with_only_its_own_backups(self):
        run = run_once()
        texts = run.bridge.page_settings(['nextcloud'], ['nextcloud'], [])['texts']
        expected = (ADMISSION + DEPLOY_WAKE + SETUP_BEFORE + RESERVE_CHECK + page_block(texts) + JUDGED + VERIFY
                    + rollback('rollback') + AFTER + cleanup(3) + RETURN)
        self.assertEqual(run.failed, [])
        self.assertEqual(run.names, expected)
        self.assertEqual((len(run.names), run.code, run.final), (82, 0, 0))
        self.assertIn('nextcloud no-share page: 82/82 PASS', run.stdout)
        dev = run.dev
        # dev-e as found: cold, unpinned, its own data, the timer as found, nothing of the run's left.
        self.assertEqual((dev.running, dev.pinned, dev.data, dev.timer, dev.ha), (False, False, 'base', 'enabled', []))
        self.assertEqual(sorted(dev.backups), sorted([run.p.BASELINE, '20261127T120000Z-0000prev']))
        self.assertEqual(run.receipt['pending'], False)
        self.assertEqual(len(run.receipt['created_backups']), 3)   # converted, the import's safety, the rollback's
        self.assertFalse(set(run.receipt['created_backups']) & set(dev.backups))
        owned_only(self, run)
        # The page made the upload, the check and the import; the driver sent none of those itself.
        [page] = [c for c in dev.calls if c[0] == 'page']
        self.assertEqual(page, ('page', 'woowbk-dev-e', ('nextcloud',), True, True, True))
        restores = [r for c, r in dev.helper_calls if c == 'restore-start']
        self.assertEqual(len(restores), 1)                                # only the manual rollback, of the safety
        # Order: deploy while cold, pin before the start, the stop before the revert, the timer last.
        order = [c for c in dev.calls if c[0] in ('run', 'wake', 'reload', 'page') or c[:2] == ('root', ('systemctl', 'unmask',
                                                                                                         run.p.TIMER))]
        kinds = [c[1] if c[0] == 'wake' else c[0] for c in order]
        self.assertEqual([k for k in kinds if k in ('run', 'UNITS:pin', 'CONTROL:start', 'page', 'STOP', 'UNITS:revert',
                                                     'root')],
                         ['run', 'UNITS:pin', 'CONTROL:start', 'page', 'STOP', 'UNITS:revert', 'root'])
        # The leak scan looked for every secret of the run; no secret is in the evidence.
        self.assertEqual(dev.leak_names, ['B2_NC_X86_NOSHARE_APP_PW', 'B2_NC_X86_NOSHARE_USER_PW', 'COCKPIT_PASSWORD',
                                          'DEV_D_MARKER_NEXTCLOUD', 'HA_BACKUP_KEY', 'R6_BASELINE_AGE_1',
                                          'R6_BASELINE_KIT'])
        for name, data in run.files.items():
            for secret in (HA_KEY, PASSWORD, USER_PW, APP_PW, MARKER_PW, KIT.splitlines()[1]):
                self.assertNotIn(secret.encode(), data, name)
        summary = json.loads(run.files['page/page-bridge.json'])
        self.assertTrue(summary['passed'])
        self.assertEqual((summary['expected_acknowledged'], summary['confirmation_lines']), ({'nextcloud': [NO_SHARE_KEY]}, 1))

    def test_a_stop_after_the_import_restores_dev_es_own_nextcloud_before_any_cleanup(self):
        run = run_once(lambda dev: setattr(dev, 'client_fails', True))
        texts = run.bridge.page_settings(['nextcloud'], ['nextcloud'], [])['texts']
        expected = (ADMISSION + DEPLOY_WAKE + SETUP_BEFORE + RESERVE_CHECK + page_block(texts) + JUDGED
                    + ['case stopped; recovery and the cold return follow'] + rollback('recovery') + AFTER + cleanup(3)
                    + RETURN)
        self.assertEqual(run.names, expected)
        self.assertEqual(run.failed, ['case stopped; recovery and the cold return follow'])
        self.assertEqual((run.code, run.final), (0, 1))     # dev-e is safely back; the run itself is a FAIL
        self.assertEqual((run.dev.running, run.dev.pinned, run.dev.data, run.dev.ha), (False, False, 'base', []))
        self.assertEqual(run.receipt['pending'], False)
        owned_only(self, run)

    def test_an_unreviewed_confirmation_the_page_acknowledged_is_recovered(self):
        run = run_once(lambda dev: setattr(dev, 'extra_confirm', True))
        self.assertEqual(run.failed, ['check: the job answers one app: nextcloud importable, the missing share folder '
                                      '(nextcloud.no-share) its only line to confirm, nothing stops',
                                      'case stopped; recovery and the cold return follow'])
        self.assertIn('recovery: the original baseline verified (batch2_baseline.py --verify nextcloud)', run.names)
        self.assertNotIn('import: the page\'s conversion job succeeded with a backup id', run.names)
        self.assertEqual((run.dev.running, run.dev.pinned, run.dev.data, run.dev.ha), (False, False, 'base', []))
        self.assertEqual(sorted(run.dev.backups), sorted([run.p.BASELINE, '20261127T120000Z-0000prev']))
        owned_only(self, run)

    def test_a_page_refused_by_the_bridge_changes_nothing_and_still_returns_cold(self):
        run = run_once(lambda dev: setattr(dev, 'headroom', 1000 * 1024 ** 2))
        expected = (ADMISSION + DEPLOY_WAKE + SETUP_BEFORE + RESERVE_CHECK
                    + ['page import: refused before the page started (nothing changed)',
                       'case stopped; recovery and the cold return follow',
                       'cleanup gate: the original baseline verified (batch2_baseline.py --verify nextcloud)']
                    + AFTER + cleanup(0, ha=False) + RETURN)
        self.assertEqual(run.names, expected)
        self.assertEqual(run.failed, ['page import: refused before the page started (nothing changed)',
                                      'case stopped; recovery and the cold return follow'])
        self.assertFalse([c for c in run.dev.calls if c[0] == 'page'])
        self.assertFalse([c for c, _r in run.dev.helper_calls if c in ('restore-start', 'delete', 'ha-delete')])
        self.assertEqual((run.dev.running, run.dev.pinned, run.dev.data), (False, False, 'base'))

    def test_a_signal_during_the_import_cancels_only_this_runs_job_and_recovers(self):
        run = run_once(lambda dev: setattr(dev, 'page_mode', 'interrupt'))
        self.assertEqual(run.failed, ['page import: stopped by a signal (the browser closed in order, the relay reaped)',
                                      'case stopped; recovery and the cold return follow'])
        cancels = [r['job_id'] for c, r in run.dev.helper_calls if c == 'job-cancel']
        restore = next(j for j in run.dev.jobs if j['type'] == 'restore' and j['params'].get('ha_backup_id'))
        self.assertEqual(cancels, [restore['id']])                       # only the page's running restore
        self.assertEqual(restore['state'], 'rolled-back')
        self.assertIn('recovery: the import\'s safety backup restored (manual rollback), every health check ok', run.names)
        self.assertEqual((run.dev.running, run.dev.pinned, run.dev.data, run.dev.ha), (False, False, 'base', []))
        self.assertEqual(sorted(run.dev.backups), sorted([run.p.BASELINE, '20261127T120000Z-0000prev']))
        self.assertEqual(run.receipt['pending'], False)
        owned_only(self, run)

    def test_a_cold_return_that_cannot_finish_keeps_the_receipt_pending_for_the_coordinator(self):
        run = run_once(lambda dev: setattr(dev, 'stop_fails', True))
        self.assertEqual(run.failed, ['return: the cold return needs the private prior copies (coordinator)',
                                      'return: the scheduled-backup timer stays masked until the coordinator finished the '
                                      'cold return'])
        self.assertEqual((run.code, run.final, run.receipt['pending']), (1, 1, True))
        self.assertTrue(run.dev.pinned)                                   # the revert waits for the stop: never reverse
        self.assertEqual(run.dev.data, 'base')                            # dev-e's own data was back before the return
        self.assertEqual(run.dev.timer, 'masked')                         # no scheduled job races the recovery

    def test_admission_refuses_a_woken_or_pinned_stack_before_any_change(self):
        for change in ('running', 'pinned'):
            with self.subTest(change=change):
                run = run_once(lambda dev, change=change: setattr(dev, change, True))
                self.assertEqual(run.names, ADMISSION[:1])
                self.assertEqual((run.code, run.final), (2, 2))
                self.assertNotIn('pending', run.receipt)                  # only the refused attempt is recorded
                self.assertEqual(len(run.receipt['runs']), 1)
                self.assertFalse([c for c in run.dev.calls if c[0] in ('run', 'reload', 'page')
                                  or c[:2] == ('wake', 'UNITS:pin') or c[0] == 'root'])
                self.assertEqual(run.dev.helper_calls, [])

    def test_a_pending_earlier_run_refuses_before_any_change(self):
        def configure(dev):
            path = dev.p.LAB / 'run' / dev.p.RECEIPT_NAME
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({'pending': True}))
        run = run_once(configure)
        self.assertEqual(run.names, ADMISSION)
        self.assertEqual(run.failed, ADMISSION[2:])
        self.assertEqual((run.code, run.receipt['pending'], len(run.receipt['runs'])), (2, True, 1))   # kept pending
        self.assertFalse([c for c in run.dev.calls if c[0] in ('run', 'root', 'reload', 'page')])

    def test_an_unreadable_receipt_counts_as_pending(self):
        def configure(dev):
            path = dev.p.LAB / 'run' / dev.p.RECEIPT_NAME
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{not json')
        root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, root, True)
        with simulated(root, configure) as sim, contextlib.redirect_stdout(io.StringIO()):
            code, ev = sim.p.control_run(lease_for(sim.p, sim.nc), COMMIT, time.monotonic())
        self.assertEqual((code, [r['check'] for r in ev.results if not r['ok']]), (2, ADMISSION[2:]))


class WatchdogTests(unittest.TestCase):
    def test_a_breach_cancels_only_jobs_this_run_started(self):
        p = load_page('r6_page_watch')
        cancelled = []
        jobs = [{'id': 'jold', 'state': 'running'}, {'id': 'jnew', 'state': 'running'}, {'id': 'jdone', 'state': 'succeeded'}]
        d = SimpleNamespace(ok=lambda command, request=None, ev=None: {'jobs': jobs},
                            helper=lambda command, request=None, timeout=0: cancelled.append((command, request)))
        nc = SimpleNamespace(drv=d)
        ev = SimpleNamespace(log=lambda text: None)
        case = SimpleNamespace(stop=threading.Event(), recovery=threading.Event(), tripped=threading.Event(),
                               expires=time.time() + 3600, inflight=set(), jobs_before={'jold'})
        metrics = {'minimum_free_bytes': None, 'peak_memory_current_bytes': 0}
        with patch.object(p, 'WATCH_INTERVAL', 0.01), \
                patch.object(p.wake, 'device', lambda *a, **k: {'free': p.RESERVE, 'memory': 1 << 30}):
            thread = threading.Thread(target=p.watchdog, args=(nc, ev, case, metrics))
            thread.start()
            thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertTrue(case.tripped.is_set())
        self.assertEqual(cancelled, [('job-cancel', {'job_id': 'jnew'})])
        self.assertEqual(metrics['trip']['reason'], {'free': p.RESERVE, 'memory': 1 << 30})


class LeaseAndCommandLineTests(unittest.TestCase):
    def test_the_lease_binds_the_phase_the_commit_the_fixture_and_the_headroom(self):
        p = load_page('r6_page_lease')
        nc = p.load_flow()
        p.admit_lease(lease_for(p, nc), COMMIT, nc.FIXTURE_SHA)
        template = p.lease_template(COMMIT)
        self.assertEqual({k: v for k, v in template.items() if not k.endswith('_utc')},
                         {k: v for k, v in lease_for(p, nc).items() if not k.endswith('_utc')})
        soon = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 30 * 60))
        for change in ({'phases': ['fullshare']}, {'source_commit': '1' * 40}, {'fixture_sha256': '0' * 64},
                       {'pin_refresh_policy': 'other'}, {'source_deployment': 'frozen'}, {'expires_utc': soon},
                       {'reserve_bytes': 12 << 30}, {'lane': 'other'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                p.admit_lease(lease_for(p, nc, **change), COMMIT, nc.FIXTURE_SHA)

    def main(self, argv, *, dirty=False, heavy=True, lease=None):
        root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, root, True)
        p = load_page('r6_page_cli')
        nc = p.load_flow()
        calls = []

        def check_output(argv_, **kwargs):
            return ' M x\n' if argv_[:2] == ['git', 'status'] and dirty else (COMMIT + '\n' if argv_[:2] == ['git', 'rev-parse']
                                                                              else '')
        if lease is not None:
            (root / 'lease.json').write_text(json.dumps(lease))
        env = {'HEAVY_FREE': str(root / 'x.lock')} if heavy else {}
        with patch.object(p, 'LOCK', str(root / 'x.lock')), patch.object(p.subprocess, 'check_output', check_output), \
                patch.object(p, 'control_run', lambda *a: calls.append(a) or (0, SimpleNamespace(
                    finish=lambda: True, results=[]))), patch.dict(os.environ, env, clear=False), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            if not heavy:
                os.environ.pop('HEAVY_FREE', None)
            try:
                code = p.main(argv + (['--lease', str(root / 'lease.json')] if lease is not None else []))
            except SystemExit as error:
                code = error.code
        return code, calls, out.getvalue(), err.getvalue(), p, nc

    def test_only_run_with_an_exact_lease_and_the_heavy_seat_reaches_the_device(self):
        code, calls, out, _err, p, nc = self.main([])
        self.assertEqual((code, calls, json.loads(out)['mutations']), (0, [], 0))
        code, calls, out, _err, p, nc = self.main(['--lease-template'])
        self.assertEqual((code, calls, json.loads(out)['phases']), (0, [], ['noshare-page']))
        code, calls, _out, _err, p, nc = self.main(['--run'])
        self.assertEqual((code, calls), (2, []))                          # --run requires a lease (argparse error)
        good = lease_for(p, nc)
        for kwargs in ({'dirty': True}, {'heavy': False}, {'lease': dict(good, phases=['fullshare'])}):
            with self.subTest(kwargs=kwargs):
                code, calls, _out, err, *_rest = self.main(['--run'], **dict({'lease': good}, **kwargs))
                self.assertEqual((code, calls), (2, []))
                self.assertIn('no case mutation started', err)
        code, calls, out, _err, *_rest = self.main(['--run'], lease=good)
        self.assertEqual((code, len(calls)), (0, 1))
        self.assertIn(f'source commit {COMMIT}', out)
        self.assertIn('lock held for', out)


class UnchangedTests(unittest.TestCase):
    def test_nextcloud_flow_and_the_r6_modules_are_unchanged_by_the_page_case(self):
        # The commit that added this case (cherry-picked or merged, whatever its hash) changed no R6 module and not
        # nextcloud_flow.py. Later R6 changes are their own commits (S5-B's optional hooks keep R6's defaults).
        added = subprocess.run(['git', '-C', str(REPO), 'log', '--diff-filter=A', '--format=%H', '--',
                                'tests/e2e/lab/focus_nextcloud_r6_page.py'], capture_output=True, text=True, timeout=60)
        commits = added.stdout.split()
        if added.returncode or not commits:
            self.skipTest('the commit that added the page case is not in this checkout')
        changed = subprocess.run(['git', '-C', str(REPO), 'diff-tree', '--no-commit-id', '--name-only', '-r', commits[-1]],
                                 capture_output=True, text=True, timeout=60).stdout.split()
        r6 = [n for n in changed if n == 'tests/e2e/lab/nextcloud_flow.py'
              or (n.startswith('tests/e2e/lab/focus_nextcloud_r6') and not n.startswith('tests/e2e/lab/focus_nextcloud_r6_page'))]
        self.assertTrue(changed)
        self.assertEqual(r6, [])

    def test_the_device_program_compiles_and_every_label_is_fixed_vocabulary(self):
        p = load_page('r6_page_compile')
        compile(p.NOSHARE_CLIENT, '<device program>', 'exec')
        run = run_once()
        for name in run.names:   # never cut by the capture's 140 characters
            self.assertLessEqual(len(name), 140, name)
        for line in run.stdout.splitlines():
            if line.endswith((': PASS', ': FAIL')):
                self.assertLessEqual(len(line.rsplit(': ', 1)[0]), 140)
                self.assertRegex(line, r"^[A-Za-z0-9 ,()/:'<>.=_-]{3,140}: (PASS|FAIL)$")


if __name__ == '__main__':
    unittest.main()
