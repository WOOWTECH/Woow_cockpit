"""Offline: focus_nextcloud_r6_fullshare_page.py (the FULL-SHARE Nextcloud import through dev-e's real page, cold to
cold) against a simulated dev-e: the R6 inventory, wake, pin/revert and cold-stop programs, the root helper's transport
(the real b1 driver's ok/wait_job/restore run on top of it), nextcloud_flow's device programs (state, client, Office,
leaks), the owner commands of the restart and of the injected failure, the upload area, and the page process behind the
REAL bridge (with the page's own waits). No device, no labpodman, no browser, no real secret, no real facts: every lab
path points into a temporary folder with generated values.
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
MARKER_PW = 'generated-marker-pass-7777'
NOSHARE_PW, NOSHARE_APP = 'generated-noshare-user-pass-5555', 'generated-noshare-app-pass-6666'
USER_PW, APP_PW = 'generated-share-user-pass-1111', 'generated-share-app-pass-2222'
USER2_PW, LINK_PW, LINK_TOKEN = 'generated-share-friend-pass-4444', 'generated-link-pass-8888', 'GeneratedLinkToken9999'
KIT = '# generated stand-in kit\nAGE-SECRET-KEY-1GENERATEDSTANDIN0123456789ABCDEFGHJKLMNPQRSTUV\n'
SECRET_VALUES = (HA_KEY, PASSWORD, MARKER_PW, NOSHARE_PW, NOSHARE_APP, USER_PW, APP_PW, USER2_PW, LINK_PW, LINK_TOKEN,
                 KIT.splitlines()[1])
EXTRA_KEY = 'nextcloud.htaccess-skipped:' + 'b' * 16
COMMIT = '0' * 40
OTHER = '20261127T120000Z-0000prev'
OTHER_UPLOADS = {'u00000000000000a1': {'done'}, 'u00000000000000b2': {'json', 'part'}}   # another lane's, never touched
SECTION = {'nextcloud_version': '35.0.1.1', 'pg_version': '16', 'users': 4, 'files': 420, 'shares': 2, 'tokens': 125,
           'calendar_objects': 7, 'contacts': 8, 'custom_apps': ['notes', 'richdocuments', 'tasks'],
           'datadir': '/share/nextcloud', 'datadir_in_backup': True}

sys.path.insert(0, str(HERE))


def load_page(name='r6_fullshare_page'):
    spec = importlib.util.spec_from_file_location(name, HERE / 'focus_nextcloud_r6_fullshare_page.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def bridge_module():
    spec = importlib.util.spec_from_file_location('r6_fullshare_page_test_bridge', HERE / 'focus_page_bridge.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def answer(stdout=b'', returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=stdout if isinstance(stdout, bytes) else stdout.encode(), stderr=b'')


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else Path(data).read_bytes()).hexdigest()


def facts_for(fixture):
    """Generated share-run facts in the shape focus_nextcloud_r6.validate_facts and nextcloud_flow read (names only)."""
    return {'fixture': str(fixture), 'sha256': sha(fixture), 'section': dict(SECTION),
            'user': 'woow-share-test', 'user_pw': 'B2_NC_X86_SHARE_USER_PW', 'app_pw': 'B2_NC_X86_SHARE_APP_PW',
            'user2': 'woow-share-friend', 'user2_pw': 'B2_NC_X86_SHARE_USER2_PW', 'user2_file': 'Shared/報告.docx',
            'user2_shared': '報告.docx', 'link_token': 'B2_NC_X86_SHARE_LINK_TOKEN', 'link_pw': 'B2_NC_X86_SHARE_LINK_PW',
            'link_file': '報告.docx',
            'files': {'報告.docx': 'a' * 64, 'nested/深層/binary-4mib.bin': 'b' * 16, 'notes.md': 'c' * 64},
            'digests': {'woow-share-test': 'd' * 64, 'woow-share-friend': 'e' * 64},
            'versioned': 'notes.md', 'versions': 2, 'caldav': 'personal/event.ics', 'caldav_uid': 'uid-cal-1',
            'carddav': 'contacts/card.vcf', 'carddav_uid': 'uid-card-1'}


UNIT_NAMES = ('nextcloud.target', 'nextcloud-app.service', 'nextcloud-db.service', 'nextcloud-redis.service',
              'nextcloud-office.service', 'nextcloud-gateway.service', 'nextcloud-cron.timer', 'woowtech-backup-schedule.timer')
OFFICE = {'richdocuments.wopi_url': 'http://127.0.0.1:9980', 'core.backgroundjobs_mode': 'cron'}
CAPS = {'keys': ['collabora', 'config', 'productName'], 'config': {'wopi_url': 'http://127.0.0.1:9980'},
        'collabora': ['convert-to'], 'product': 'Nextcloud Office'}


class FsDev:
    """dev-e as focus_nextcloud_r6_fullshare_page.py sees it: Nextcloud cold with the five original images loaded, its
    own baseline data live, the encrypted baseline backup kept, another lane's finished and pending uploads; the page
    imports the full-share backup."""

    def __init__(self, p, nc, facts, bridge):
        self.p, self.nc, self.facts, self.bridge = p, nc, facts, bridge
        self.store_id = 'ha-' + facts['sha256'][:20]
        self.calls, self.helper_calls, self.configs = [], [], []
        self.running = self.pinned = self.deployed = False
        self.timer = 'enabled'
        self.data = 'base'
        self.ha, self.jobs = [], []
        self.backups = {p.BASELINE: {'id': p.BASELINE, 'type': 'manual', 'key_id': 'k-1', 'size': 422031360, 'holds': 'base'},
                        OTHER: {'id': OTHER, 'type': 'manual', 'key_id': 'k-1', 'size': 1000, 'holds': 'other'}}
        self.uploads = copy.deepcopy(OTHER_UPLOADS)
        self.owner_files, self.dropin_dir = set(), False
        self.sequence = self.link_requests = 0
        self.free = 29 << 30
        self.headroom = 1500 * 1024 ** 2
        self.page_mode = 'normal'
        self.extra_confirm = self.client_fails = self.no_rollback = self.stop_fails = self.office_fails = False
        self.lock = threading.Lock()

    # ---------------------------------------------------------------- bookkeeping
    def log(self, *entry):
        with self.lock:
            self.calls.append(entry)

    def new_backup(self, kind, holds, **extra):
        self.sequence += 1
        bid = '20261128T1000%02dZ-%08x' % (self.sequence, self.sequence)
        self.backups[bid] = {'id': bid, 'type': kind, 'key_id': 'k-1', 'size': 1300 * 1024 ** 2, 'holds': holds, **extra}
        return bid

    def job(self, kind, params, state, result, unit=None):
        self.sequence += 1
        jid = 'j20261128T1100%02dZ-%08x' % (self.sequence, self.sequence)
        record = {'id': jid, 'type': kind, 'state': state, 'phase': 'done' if state not in ('queued', 'running') else 'run',
                  'progress': {}, 'params': params, 'result': result, 'created': '2026-11-28T11:00:00Z',
                  'started': '2026-11-28T11:00:00Z', 'finished': '2026-11-28T11:05:10Z',
                  'unit': unit or f'woowtech-backup-{jid}.service'}
        self.jobs.append(record)
        return record

    def public(self, job):
        return {k: copy.deepcopy(v) for k, v in job.items() if k != 'unit'}

    def restore_of(self, backup_id):
        """A restore of `backup_id`: with the injected one-shot failure the app does not start and the engine rolls back
        (the data stays, the marker is consumed); otherwise its data goes live. A safety backup keeps what was live."""
        safety = self.new_backup('safety', self.data)
        if self.nc.FAIL_MARKER_REL in self.owner_files and not self.no_rollback:
            self.owner_files.discard(self.nc.FAIL_MARKER_REL)
            return 'rolled-back', {'rolled_back': True, 'safety_backup_id': safety, 'health': []}
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
                'root': {'memory_current': 554872832, 'memory_max': str(self.p.DEVICE_CAP), 'varlib_free_bytes': self.free,
                         'installed_hashes': {n: installed.get(n) for n in self.p.ENGINE_MODULES}, 'catalog_exists': True,
                         'catalog_sha256': self.p.ORIGINAL_CATALOG_SHA,
                         'original_baseline_entries': [{'bytes': 655, 'directory': False}]},
                'host_free_bytes': self.free, 'host_memory_available_mib': 4549}

    def wake_device(self, program, request=None, *, root=False, timeout=300):
        p = self.p
        if program == p.control.RESOURCE:
            return {'free': self.free, 'memory': 1200 * 1024 ** 2}
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
            if self.stop_fails:
                raise RuntimeError('fixed-wake-device-step-failed')
            self.running = False
            return {'status': 'stopped', 'only_owned_office_failed_flag_cleared': False}
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
        home = '/home/appowner/'
        self.log('owner', argv[:2] + argv[4:] if argv[:3] == ('python3', '-I', '-c') else argv)
        if argv[:3] == ('python3', '-I', '-c') and argv[4:] == ('nextcloud', 'read'):
            assert json.loads(input)['password'] == MARKER_PW and self.running
            found = ({'users': ['woowbk-lab-baseline'], 'files': ['woowbk-lab-baseline.txt:0a0a0a0a']}
                     if self.data == 'base' else {'users': [], 'files': []})
            return answer(json.dumps(found) + '\n')
        if argv[:4] == ('podman', 'unshare', 'du', '-sb'):
            size = {'html': 849259813, 'postgres': 75382634, 'data': 234187031}[argv[4].rsplit('/', 1)[1]]
            return answer(f'{size}\t{argv[4]}\n')
        if argv == ('systemctl', '--user', 'restart', 'nextcloud-app.service'):
            assert self.running
            return answer()
        if argv == ('systemctl', '--user', 'daemon-reload'):
            return answer()
        if argv[:2] == ('mkdir', '-p') and argv[2] == home + self.nc.DROPIN_DIR_REL:
            self.dropin_dir = True
            return answer()
        if argv[:3] == ('sh', '-c', 'umask 077; cat > "$1" && chmod "$2" "$1"'):
            rel = argv[4][len(home):]
            assert rel in (self.nc.DROPIN_REL, self.nc.FAIL_MARKER_REL) and input
            self.owner_files.add(rel)
            return answer()
        if argv[0] == 'test' and argv[1] in ('-e', '-d'):
            rel = argv[2][len(home):]
            present = self.dropin_dir if argv[1] == '-d' else rel in self.owner_files
            return answer(returncode=0 if present else 1)
        if argv[:2] == ('rm', '-f'):
            for path in argv[2:]:
                self.owner_files.discard(path[len(home):])
            return answer()
        if argv[0] == 'rmdir' and argv[1] == home + self.nc.DROPIN_DIR_REL:
            self.dropin_dir = False
            return answer()
        raise AssertionError(('owner', argv))

    def state(self):
        base = self.data == 'base'
        f = self.facts
        return {'config_sha256': 'c' * 64 if base else 'd' * 64,
                'users': ['admin', 'woowbk-lab-baseline'] if base else sorted(['admin', f['user'], f['user2'], 'woow-mcp-test']),
                'status': {'installed': True, 'version': '35.0.1.1', 'maintenance': False, 'needsDbUpgrade': False},
                'db': {'storages': ['home::admin'], 'users': 2 if base else 4},
                'data_top': ['.htaccess', '.ncdata', 'admin', 'woowbk-lab-baseline'] if base else ['.htaccess', '.ncdata'],
                'units': {u: 'active' if self.running else 'inactive' for u in self.nc.UNITS},
                'office': dict(OFFICE), 'fingerprint': 'f' * 16 if base else 'e' * 16, 'filecache_rows': 191}

    def client(self, request):
        """nextcloud_flow.CLIENT: dev-e's own account, or the share run's HA test user (its secrets by value)."""
        f = self.facts
        if request['user'] == 'woowbk-lab-baseline':
            assert request['user_pw'] == MARKER_PW
            own = self.data == 'base'
            return {'status': self.state()['status'], 'ocs': {'password': [200 if own else 401, own], 'wrong': [401, False]},
                    'capabilities': [200, copy.deepcopy(CAPS)], 'fingerprint': [207, 'f' * 16 if own else 'e' * 16],
                    'discovery': [200, True]}
        if self.client_fails:
            raise self.nc.Failed('device probe failed (rc 1); diagnostic output suppressed')
        assert (request['user'], request['user_pw'], request['app_pw']) == (f['user'], USER_PW, APP_PW)
        assert (request['user2'], request['user2_pw'], request['user2_file']) == (f['user2'], USER2_PW, f['user2_file'])
        assert (request['link_token'], request['link_pw']) == (LINK_TOKEN, LINK_PW)
        assert sorted(request['files']) == sorted(f['files']) and request['digest_users'] == sorted(f['digests'])
        self.link_requests += 3   # with the password, without, with a wrong one: each an access-log line with the token
        ok = self.data == 'ha'

        def full(want):
            return (want + '0' * 64)[:64] if ok else 'HTTP401'
        return {'status': self.state()['status'],
                'ocs': {'password': [200, True] if ok else [401, False], 'app_password': [200, True] if ok else [401, False],
                        'wrong': [401, False]},
                'capabilities': [200, copy.deepcopy(CAPS)], 'fingerprint': [207, 'e' * 16 if ok else 'f' * 16],
                'discovery': [200, True], 'files': {n: full(v) for n, v in f['files'].items()},
                'user2_file': full(f['files'][f['user2_shared']]), 'link': [full(f['files'][f['user2_shared']]), 401, 401],
                'caldav': [200, ok], 'carddav': [200, ok], 'versions': {'dav': [207, f['versions']], 'on_disk': str(f['versions'])},
                'digests': dict(f['digests']) if ok else {},
                'web': {'control': 200, 'picked': True, 'codes': [403, 404, 403, 404],
                        'htaccess': sha(self.nc.ha_nextcloud.DATA_HTACCESS), 'htaccess_below': '0'},
                'scan': {'folders': 40, 'files': 300, 'new': 0, 'updated': 0, 'removed': 0, 'errors': 0, 'rc': 0},
                'setup': {'checks': 31, 'data_dir': 'success', 'not_success': []},
                'storage': 'local::/var/www/html/data/', 'owners': 'oc_admin', 'lastcron': '1795800000'}

    def office(self, script, request):
        assert request == {'user': self.facts['user2'], 'user_pw': USER2_PW}
        assert 'woowbk-r6-relay-' in script and '"--image-volume=ignore",' in script   # this run's own relay (R6)
        ok = self.data == 'ha' and not self.office_fails
        return {'document': [True, True, True], 'copy': 201, 'direct': [200, True], 'page': [200, True, True],
                'wopi_info': [200, True, True, True], 'wopi_file': [200, True], 'wopi_wrong_token': 403, 'relay': 0,
                'loaded': [1, True, ok, 6.0], 'perm': 'perm: edit', 'text': [200, 30, 30, True], 'saved': ok,
                'saved_in_nextcloud': [ok, ok], 'deleted': 204, 'trash_deleted': [204], 'relay_gone': True}

    def device_python(self, script, request=None, *, as_owner=True, timeout=600):
        nc, bridge, p = self.nc, self.bridge, self.p
        name = {nc.ENGINE_HASHES: 'ENGINE_HASHES', nc.STATE: 'STATE', nc.CLIENT: 'CLIENT', nc.LEAKS: 'LEAKS',
                nc.OFFICE: 'OFFICE', nc.drv.RUN_LIST: 'RUN_LIST', bridge.PRECONDITIONS: 'PRECONDITIONS',
                bridge.NATIVE_UNITS: 'NATIVE_UNITS', p.UPLOADS: 'UPLOADS'}.get(script)
        self.log('device_python', name, as_owner)
        if name == 'ENGINE_HASHES':
            return self.installed()
        if name == 'STATE':
            return self.state()
        if name == 'CLIENT':
            return self.client(request)
        if name == 'OFFICE':
            return self.office(script, request)
        if name == 'LEAKS':
            assert not as_owner
            self.leak_names, self.url_tokens = sorted(request['secrets']), list(request['url_tokens'])
            return {'scanned': 210, 'journal_bytes': 4096, 'names': len(request['secrets']), 'hits': 0,
                    'url_token_access_log_hits': self.link_requests, 'url_token_hits_elsewhere': 0}
        if name == 'RUN_LIST':
            return {'/var/lib/woowtech-backup/staging': [], '/run/woowtech-backup': ['engine.lock']}
        if name == 'PRECONDITIONS':
            assert self.running
            return {'page': {n: sha(REPO / 'backup' / n) for n in bridge.PAGE_FILES}, 'cockpit_socket': True,
                    'hostname': 'woowbk-dev-e', 'devadmin_uid': 1000, 'headroom': self.headroom}
        if name == 'NATIVE_UNITS':
            rows = {job['id']: job for job in self.jobs}
            return [{k: rows[j][k] for k in ('id', 'unit', 'type', 'state')} for j in request['ids']]
        if name == 'UPLOADS':
            assert not as_owner
            return {uid: sorted(kinds) for uid, kinds in sorted(self.uploads.items())}
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
        if command == 'inspect':
            backup = self.backups[request['backup_id']]
            return 0, {'backup': {k: v for k, v in backup.items() if k != 'holds'},
                       'manifest': {'apps': [{'id': 'nextcloud', 'data_dirs': [
                           {'path': f'.local/share/nextcloud-office/{n}'} for n in ('data', 'html', 'postgres', 'redis')]}]},
                       'preflight': {'ok': True, 'checks': [{'id': 'space', 'status': 'ok'}],
                                     'apps': [{'id': 'nextcloud', 'mode': 'inplace', 'settings': {'state': 'same'}}]}}
        if command == 'upload-abort':
            return (0, {}) if self.uploads.pop(request['upload_id'], None) is not None else (0, {})
        raise AssertionError(('helper', command))   # upload, check, convert, import: never the driver itself

    def labelled(self):
        self.log('labelled')
        return {'containers': [], 'volumes': [], 'networks': []}

    def catalog(self, app):
        self.log('catalog', app)
        return {'id': 'nextcloud', 'units': list(self.nc.UNITS), 'postgres': None, 'volumes': [],
                'data_dirs': [{'path': f'.local/share/nextcloud-office/{n}'} for n in ('data', 'html', 'postgres', 'redis')]}

    # ---------------------------------------------------------------- the real page's effects
    def check_result(self, ha_id):
        issues = [{'id': 'nextcloud.office-cache', 'level': 'notice', 'message': 'office', 'items': [], 'more': 0}]
        if self.extra_confirm:
            issues.append({'id': 'nextcloud.htaccess-skipped', 'level': 'confirm', 'message': 'skipped', 'items': ['x'],
                           'more': 0, 'key': EXTRA_KEY})
        return {'ha_check': {'schema': 2, 'ha_backup_id': ha_id, 'shared': [],
                             'apps': [{'app_id': 'nextcloud', 'ok': True, 'blockers': [], 'importable': True,
                                       'warnings': [], 'arch': 'amd64', 'version': '0.2.3', 'target_version': '35.0.1.1',
                                       'issues': issues, 'nextcloud': dict(self.facts['section'])}]}}

    def page(self, config, seconds, device):
        self.configs.append((dict(config), seconds))
        self.log('page', device, tuple(config['apps']), seconds, config['key'] == HA_KEY, config['password'] == PASSWORD)
        assert self.running and config['ha_id'] == self.store_id
        upload_id = 'u%016x' % (0xc0de + len(self.configs))
        texts = config['texts']
        if self.page_mode == 'upload-stuck':   # the page's own upload wait ended; the placeholder and the temp file stay
            self.uploads[upload_id] = {'json', 'part', 'temp'}
            Path(config['result']).write_text(json.dumps({
                'stage': 'upload', 'failure_kind': 'timeout', 'completed': False, 'issued_values_scanned': True,
                'checks': [{'check': 'UI real administrative Cockpit bridge reaches this device', 'ok': True},
                           {'check': 'UI bounded flow completed', 'ok': False}],
                'issued_scan_counts': {'scan_completed': True}, 'wire': {'import_starts': 0}}))
            return {'started': True, 'exit': 1, 'timed_out': False, 'interrupted': False, 'stop': 'exited',
                    'relay_clean': True, 'relay_error': None, 'children_left': []}
        self.uploads[upload_id] = {'done'}
        if not any(row['id'] == self.store_id for row in self.ha):
            self.ha.append({'id': self.store_id, 'sha256': self.facts['sha256'],
                            'importable_apps': [{'slug': 'nc', 'app_id': 'nextcloud', 'installed': True}]})
        self.job('verify', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['nextcloud'], 'key_provided': True},
                 'succeeded', self.check_result(config['ha_id']))
        sent = {'nextcloud': [EXTRA_KEY]} if self.extra_confirm else {}
        converted = self.new_backup('manual', 'ha', from_ha={'ha_backup_id': self.store_id})
        result = {'backup_id': converted,
                  'ha_import': {'apps': ['nextcloud'], 'test_mode': False,
                                'notes': ['n1', 'Office: this device\'s Collabora stays', '新的資料指紋', 'n4'],
                                'reminders_by_app': {'nextcloud': ['r1', 'r2', 'Woow Nextcloud MCP Server: log in again']}}}
        first = self.job('backup', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['nextcloud'],
                                    'test_mode': False, **({'acknowledged': copy.deepcopy(sent)} if sent else {}),
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
        names = ['UI real administrative Cockpit bridge reaches this device', texts['upload'], texts['select'],
                 'UI actual check confirmation keys observed including valid zero', texts['view'], texts['lines'],
                 'UI has exactly one acknowledgement and import waits for it',
                 'UI check did not start an import or separate restore', 'UI real key field removed before screenshot',
                 'UI one acknowledgement enables import', texts['result'], texts['intent'], texts['keys'],
                 'UI no page script errors during this page flow', 'UI cookie observation completed without gaps',
                 'UI every issued credential absent from records journal and private evidence; proved public markers '
                 'counted separately']
        lines = len(sent.get('nextcloud') or [])
        browser = {'stage': 'issued-value-scan', 'failure_kind': None, 'completed': True, 'issued_values_scanned': True,
                   'checks': [{'check': n, 'ok': True} for n in names],
                   'confirmations': {'expected_keys': sent, 'sent_keys': sent, 'lines_expected': lines,
                                     'lines_shown': lines, 'check_importable': ['nextcloud']},
                   'issued_scan_counts': {'scan_completed': True, 'observed_values': 2, 'observations_complete': True,
                                          'credential_device_hits': 0, 'credential_host_hits': 0, 'device_files': 30,
                                          'host_files': 3, 'archive_index_sidecars': 4, 'regular_json_roots': 2},
                   'wire': {'import_starts': 1}, 'waits_ms': config.get('waits_ms')}
        Path(config['result']).write_text(json.dumps(browser))
        return {'started': True, 'exit': 0, 'timed_out': False, 'interrupted': False, 'stop': 'exited',
                'relay_clean': True, 'relay_error': None, 'children_left': []}


def lab(root):
    files = {'b1-creds.env': (f'HA_BACKUP_KEY={HA_KEY}\nB2_NC_X86_NOSHARE_USER_PW={NOSHARE_PW}\n'
                              f'B2_NC_X86_NOSHARE_APP_PW={NOSHARE_APP}\nB2_NC_X86_SHARE_USER_PW={USER_PW}\n'
                              f'B2_NC_X86_SHARE_APP_PW={APP_PW}\nB2_NC_X86_SHARE_USER2_PW={USER2_PW}\n'
                              f'B2_NC_X86_SHARE_LINK_PW={LINK_PW}\nB2_NC_X86_SHARE_LINK_TOKEN={LINK_TOKEN}\n'),
             'ha-import-creds.env': 'GENERATED_OTHER_PW=generated-other-pass-1234\n',
             'dev-e-markers.json': json.dumps({'nextcloud': MARKER_PW}), 'devadmin.pass': PASSWORD + '\n',
             'dev-e-kit.txt': KIT}
    for name, text in files.items():
        path = root / 'secrets' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o600)
    fixture = root / 'fixture.tar'
    fixture.write_bytes(b'generated stand-in for the encrypted full-share Nextcloud HA backup ' * 64)
    facts = facts_for(fixture)
    (root / 'share-facts.json').write_text(json.dumps(facts, ensure_ascii=False))
    return fixture, facts


def lease_for(p, commit=COMMIT, facts_sha='f' * 64, **change):
    now = time.time()
    lease = {'device': 'woowbk-dev-e', 'lane': 'nextcloud-r6', 'phases': ['fullshare-page'], 'source_commit': commit,
             'reserve_bytes': p.RESERVE, 'memory_cap_bytes': p.DEVICE_CAP,
             'not_before_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 60)),
             'expires_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 3 * 3600)),
             'fixture_sha256': p.FIXTURE_SHA, 'facts_sha256': facts_sha, 'page_seconds': 50 * 60,
             'pin_refresh_policy': p.PIN_POLICY, 'recovery_grace_seconds': 1800,
             'source_deployment': 'deploy-src-this-checkout', 'page_device': 'woowbk-dev-e'}
    lease.update(change)
    return lease


@contextlib.contextmanager
def simulated(root, configure=None):
    """The page module with every device-facing function answered by FsDev and every lab path in `root`."""
    p = load_page()
    p.ORIGINALS = sys.modules['focus_nextcloud_r6_inventory'].ORIGINALS
    bridge = bridge_module()
    fixture, facts = lab(root)
    real_load_flow = p.load_flow
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(p, 'LAB', root))
        nc = real_load_flow(facts)
        dev = FsDev(p, nc, facts, bridge)
        lock = root / 'woowbk-dev-e-mutation.lock'
        for target, name, value in (
                (p, 'LOCK', str(lock)), (p, 'load_flow', lambda facts=None: nc),
                (p, '_load', lambda name, alias=None: bridge if name == 'focus_page_bridge' else None),
                (p, 'FIXTURE', fixture), (p, 'FIXTURE_SHA', sha(fixture)), (p, 'FIXTURE_BYTES', fixture.stat().st_size),
                (p, 'collect', dev.collect), (p, 'baseline_verify', dev.baseline_verify),
                (p.wake, 'device', dev.wake_device), (p.cold, 'device', dev.wake_device),
                (p.control, 'reload_units', dev.reload_units),
                (nc, 'SECRET_FILES', (root / 'secrets' / 'ha-import-creds.env', root / 'secrets' / 'b1-creds.env')),
                (nc, 'MARKERS', root / 'secrets' / 'dev-e-markers.json'), (nc.drv, 'LAB', root),
                (nc.drv, 'run', dev.run), (nc.drv, 'root', dev.root), (nc.drv, 'owner', dev.owner),
                (nc.drv, 'helper', dev.helper), (nc.drv, 'device_python', dev.device_python),
                (nc.drv, 'labelled', dev.labelled), (nc.drv, 'catalog', dev.catalog),
                (bridge, 'run_page', dev.page), (bridge, 'host_available_kib', lambda: 6 * 1024 * 1024),
                (bridge, 'PLAYWRIGHT', fixture), (bridge, 'CHROMIUM', fixture), (time, 'sleep', lambda _s: None)):
            stack.enter_context(patch.object(target, name, value))
        if configure:
            configure(dev)
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        stack.callback(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # main() takes it; the bridge checks this process holds it
        yield SimpleNamespace(p=p, nc=nc, dev=dev, bridge=bridge, fixture=fixture, facts=facts, lock=lock)


def run_once(configure=None, facts_change=None, lease_change=None):
    root = Path(tempfile.mkdtemp()).resolve()
    try:
        with simulated(root, configure) as sim:
            facts = dict(sim.facts, **(facts_change or {}))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code, ev = sim.p.control_run(lease_for(sim.p, **(lease_change or {})), COMMIT, time.monotonic(), facts)
                final = sim.p.finish(ev, code)
            files = {str(q.relative_to(ev.dir)): q.read_bytes() for q in ev.dir.rglob('*') if q.is_file()}
            path = root / 'run' / sim.p.RECEIPT_NAME
            receipt = json.loads(path.read_text()) if path.exists() else None
            return SimpleNamespace(code=code, final=final, results=ev.results, names=[r['check'] for r in ev.results],
                                   failed=[r['check'] for r in ev.results if not r['ok']], dev=sim.dev, files=files,
                                   stdout=out.getvalue(), receipt=receipt, p=sim.p, bridge=sim.bridge, nc=sim.nc)
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------- the expected check lines, in order

ADMISSION = ['admission: the share run\'s facts name the original full-share fixture and only credentials this lab holds',
             'admission: dev-e is cold and isolated (network none, no port, 3 GiB cap), five original images loaded, '
             'Quadlets unpinned, wake admitted',
             'admission: the host keeps the 13 GiB reserve after the page import\'s historical peak (the upload kept '
             'through conversion and restore)',
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
RESERVE_CHECK = ['page import: dev-e keeps the 13 GiB reserve after the import\'s peak (the upload kept through conversion '
                 'and restore, live sizes)']
JUDGED = ['upload: nextcloud is importable and installed here', 'check: the page\'s check job succeeded',
          'check: the job answers one app: nextcloud importable, nothing stops and no line to confirm (the full share, as '
          'the actual check lists it)',
          'check: current facts match the original full-share source (HA cluster opened and read, the data dir in the '
          'backup)',
          'check: the file lists of HA\'s database equal the files in the backup (no warning)',
          'check: amd64, add-on 0.2.3, target 35.0.1.1', 'check: no throwaway container, volume or network left',
          'import: the page\'s conversion job succeeded with a backup id',
          'import: the notes and reminders name Collabora, the data fingerprint and the MCP admin lines',
          'import: the converted backup is listed as manual with its HA origin, encrypted',
          'import: inspect of the page\'s converted backup: preflight passes, settings same, in place',
          'import: the page\'s restore of the converted backup succeeded with a safety backup, not rolled back, every '
          'health check ok',
          'import: the page\'s uploaded HA file is deleted after the import, as the page allows (space for the rollbacks)']


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
        'page: bounded (50 min), the browser closed in order and every relay exec child reaped',
        'page: the uploaded HA record is the fixture (id and SHA-256)',
        'page: exactly the page\'s own check and import jobs, none left running, no other new backup',
        'page: the check calls nextcloud importable, stops nothing, and lists every confirmation line keyed (read from the '
        'actual check)',
        'page: the one acknowledgement, the import and its jobs carry every listed confirmation key exactly once',
        'page: one conversion and its restore succeeded as two linked jobs in the first job\'s unit',
        'page: every issued Cockpit session value is absent from the records, the journal and the private evidence']


def verify(phase):
    """nextcloud_flow.Run.verify's lines for the share run's facts (user share, public link, CalDAV, CardDAV, versions,
    Office), exactly the 21 of fullshare05 per phase."""
    return [f'{phase}: status.php installed 35.0.1.1, no maintenance, no database upgrade needed',
            f'{phase}: the HA test user\'s WebDAV files (CJK names, nested, 4 MiB binary) have the recorded SHA-256',
            f'{phase}: every HA user\'s files on disk equal the backup (per-user manifest digests, showcase method)',
            f'{phase}: OCS login with the HA password and with HA\'s app password (secret moved); wrong password 401',
            f'{phase}: the second HA user reads the file shared with them (user share moved)',
            f'{phase}: the password-protected public link serves the file; without or with a wrong password 401',
            f'{phase}: the HA test user\'s CalDAV event is served with its UID',
            f'{phase}: the HA test user\'s CardDAV contact is served with its UID',
            f'{phase}: the older version is on disk and listed by the versions API',
            f'{phase}: Office settings (richdocuments wopi keys) and the cron mode are exactly this device\'s',
            f'{phase}: Nextcloud reports this device\'s Office server (capabilities as for dev-e\'s own account)',
            f'{phase}: Collabora discovery is served on this device\'s gateway',
            f'{phase}: clients see a new data fingerprint (restored-from-backup signal), the one in config.php',
            f'{phase}: occ files:scan --all: nothing new, nothing removed, no error (the database and the files agree)',
            f'{phase}: Nextcloud\'s own setup check says the data directory is protected',
            f'{phase}: the web server serves nothing below the data dir (Nextcloud\'s own protection file; static control '
            'served)',
            f'{phase}: database: root storage is this device\'s data dir, tables owned by oc_admin',
            f'{phase}: Office: the HA user\'s document has a WOPI session of this device (its file served, wrong token 403)',
            f'{phase}: Office: this device\'s Collabora opens the document over WOPI and its text is the document\'s',
            f'{phase}: Office: a text typed in Collabora is saved into Nextcloud (the rest of the document kept)',
            f'{phase}: Office: the copy, its trash entry and the lab relay are gone']


RESTART = ['restart: nextcloud-app restarted, five units active, status.php answers'] + verify('restart')


def manual(phase):
    return [f'{phase}: the import\'s safety backup restored (manual rollback), every health check ok',
            f'{phase}: dev-e\'s own markers are back exactly and the HA-only users are gone',
            f'{phase}: dev-e\'s own account logs in again (OCS)',
            f'{phase}: the original baseline verified (batch2_baseline.py --verify nextcloud)']


ROLLBACK = (['rollback: new owned injection paths are absent',
             'auto rollback: a restore with a one-shot ExecStartPre failure ends rolled-back'] + verify('auto rollback')
            + ['auto rollback: its own safety backup (the imported state) is deleted'] + manual('rollback'))
AFTER = ['after: dev-e\'s own markers are unchanged', 'after: config.php unchanged', 'after: the users unchanged',
         'after: the storages and user count in the database unchanged', 'after: the data dir top entries unchanged',
         'after: the five units unchanged', 'after: status.php unchanged', 'after: the Office settings and the cron mode unchanged']
LEAKS = ['leaks: no HA key, HA test credential, marker or Cockpit password or kit in engine records, uploads, staging, run '
         'dir, journal or evidence',
         'leaks: the public link token is only in the web servers\' access logs of the client\'s own public-link requests']


def cleanup(deleted, ha=False):
    return (['cleanup: a backup this run created is deleted'] * deleted
            + (['cleanup: the HA store record of this run is deleted'] if ha else [])
            + ['cleanup: no throwaway container, volume or network of a job left',
               'cleanup: no staging folder and no key file left',
               'cleanup: no upload of this run is left pending (an interrupted page upload is aborted)'] + LEAKS)


RETURN = ['return: no job is running on dev-e (before the stop)',
          'return: the Nextcloud stack is cold again (every unit inactive; only this run\'s own Office failed flag cleared)',
          'return: the five Quadlets are byte for byte as before (pins reverted)',
          'return: units, Quadlets, images, catalog, baseline archive, isolation, memory cap as before; the engine modules '
          'are this checkout\'s',
          'return: the scheduled-backup timer is unmasked again (as found)']
STOPPED = ['case stopped; recovery and the cold return follow']


def owned_only(test, run):
    """The driver's own helper commands: reads, inspect, the restores of what it made, deletes of what it made, the abort
    of an upload of its own page; never the baseline, another lane's backup or another lane's upload."""
    commands = {command for command, _request in run.dev.helper_calls}
    test.assertLessEqual(commands, {'status', 'list', 'jobs', 'job-status', 'restore-start', 'delete', 'ha-delete',
                                    'job-cancel', 'inspect', 'upload-abort'})
    for command, request in run.dev.helper_calls:
        if command in ('restore-start', 'delete'):
            test.assertNotIn(request['backup_id'], (run.p.BASELINE, OTHER))
        if command == 'upload-abort':
            test.assertNotIn(request['upload_id'], OTHER_UPLOADS)
    test.assertIn(run.p.BASELINE, run.dev.backups)                       # the baseline and others' backups stay
    test.assertIn(OTHER, run.dev.backups)
    test.assertEqual({k: v for k, v in run.dev.uploads.items() if k in OTHER_UPLOADS}, OTHER_UPLOADS)


def as_found(test, run, *, data='base'):
    """dev-e as found: cold, unpinned, its own data, the timer as found, no HA record, only the baseline and the other
    lane's backup, no pending upload of the run."""
    dev = run.dev
    test.assertEqual((dev.running, dev.pinned, dev.data, dev.timer, dev.ha), (False, False, data, 'enabled', []))
    test.assertEqual(sorted(dev.backups), sorted([run.p.BASELINE, OTHER]))
    test.assertEqual(run.p.pending_uploads(dev.uploads), set(k for k, v in OTHER_UPLOADS.items() if v & {'json', 'part'}))
    test.assertEqual((dev.owner_files, dev.dropin_dir), (set(), False))   # no injected drop-in or marker left


class WholeRunTests(unittest.TestCase):
    def test_the_page_imports_the_full_share_and_every_helper_fact_holds_then_dev_e_returns_cold(self):
        run = run_once()
        texts = run.bridge.page_settings(['nextcloud'], ['nextcloud'], [])['texts']
        expected = (ADMISSION + DEPLOY_WAKE + SETUP_BEFORE + RESERVE_CHECK + page_block(texts) + JUDGED + verify('import')
                    + RESTART + ROLLBACK + AFTER + cleanup(3) + RETURN)
        self.assertEqual(run.failed, [])
        self.assertEqual(run.names, expected)
        self.assertEqual((len(run.names), run.code, run.final), (run.p.EXPECTED_CHECKS, 0, 0))
        self.assertEqual(run.p.EXPECTED_CHECKS, 145)
        self.assertIn('nextcloud full-share page: 145/145 PASS', run.stdout)
        as_found(self, run)
        owned_only(self, run)
        self.assertEqual(run.receipt['pending'], False)
        # converted, the import's safety, the automatic rollback's safety (deleted in the rollback), the manual rollback's
        self.assertEqual(len(run.receipt['created_backups']), 4)
        self.assertFalse(set(run.receipt['created_backups']) & set(run.dev.backups))
        # The page made the upload, the check and the import, with the page's own waits for this file and its bound.
        [(config, seconds)] = run.dev.configs
        self.assertEqual(config['waits_ms'], {'upload': 30 * 60000, 'check': 10 * 60000, 'result': 25 * 60000})
        self.assertEqual(seconds, 50 * 60)
        self.assertEqual({k: config[k] for k in ('apps', 'importable', 'blocked', 'exact')},
                         {'apps': ['nextcloud'], 'importable': ['nextcloud'], 'blocked': [], 'exact': True})
        restores = [r['backup_id'] for c, r in run.dev.helper_calls if c == 'restore-start']
        converted, safety = run.receipt['created_backups'][:2]
        self.assertEqual(restores, [converted, safety])                  # the automatic rollback, then the manual one
        self.assertEqual([r['ha_backup_id'] for c, r in run.dev.helper_calls if c == 'ha-delete'],
                         [run.dev.store_id])                              # after the import, before the rollbacks
        ha_delete = next(i for i, (c, _r) in enumerate(run.dev.helper_calls) if c == 'ha-delete')
        first_restore = next(i for i, (c, _r) in enumerate(run.dev.helper_calls) if c == 'restore-start')
        self.assertLess(ha_delete, first_restore)
        self.assertNotIn('upload-abort', {c for c, _r in run.dev.helper_calls})   # the finished upload keeps its .done
        # Order: deploy while cold, pin before the start, the page, the restart, the stop before the revert, the timer last.
        kinds = [c[1] if c[0] == 'wake' else (c[0] if c[0] != 'owner' else 'restart')
                 for c in run.dev.calls if c[0] in ('run', 'wake', 'page')
                 or c[:2] == ('owner', ('systemctl', '--user', 'restart', 'nextcloud-app.service'))
                 or c[:2] == ('root', ('systemctl', 'unmask', run.p.TIMER))]
        self.assertEqual([k for k in kinds if k in ('run', 'UNITS:pin', 'CONTROL:start', 'page', 'restart', 'STOP',
                                                     'UNITS:revert', 'root')],
                         ['run', 'UNITS:pin', 'CONTROL:start', 'page', 'restart', 'STOP', 'UNITS:revert', 'root'])
        # The leak scan looked for every secret of the run, the link token counted apart; no secret is in the evidence.
        self.assertEqual(run.dev.leak_names, sorted(['HA_BACKUP_KEY', 'DEV_D_MARKER_NEXTCLOUD', 'COCKPIT_PASSWORD',
                                                     'B2_NC_X86_NOSHARE_USER_PW', 'B2_NC_X86_NOSHARE_APP_PW',
                                                     'B2_NC_X86_SHARE_USER_PW', 'B2_NC_X86_SHARE_APP_PW',
                                                     'B2_NC_X86_SHARE_USER2_PW', 'B2_NC_X86_SHARE_LINK_PW',
                                                     'B2_NC_X86_SHARE_LINK_TOKEN', 'R6_BASELINE_AGE_1', 'R6_BASELINE_KIT']))
        self.assertEqual(run.dev.url_tokens, ['B2_NC_X86_SHARE_LINK_TOKEN'])
        for name, data in run.files.items():
            for secret in SECRET_VALUES:
                self.assertNotIn(secret.encode(), data, name)
        summary = json.loads(run.files['page/page-bridge.json'])
        self.assertTrue(summary['passed'])
        self.assertEqual((summary['expected_acknowledged'], summary['confirmation_lines']), ({}, 0))   # a valid zero
        self.assertEqual(summary['waits'], {'upload': 1800, 'check': 600, 'result': 1500})
        timings = {row['kind']: row for row in json.loads(run.files['timings.json']) if row['upload'] != 'fullshare'}
        self.assertEqual(timings['convert']['wall_s'], 310.0)            # from the job's own record
        scope = json.loads(run.files['scope.json'])
        self.assertEqual((scope['page_seconds'], scope['page_waits_seconds']), (3000, {'upload': 1800, 'check': 600,
                                                                                       'result': 1500}))

    def test_a_stop_at_the_import_verification_restores_dev_es_own_nextcloud_before_any_cleanup(self):
        run = run_once(lambda dev: setattr(dev, 'client_fails', True))
        texts = run.bridge.page_settings(['nextcloud'], ['nextcloud'], [])['texts']
        expected = (ADMISSION + DEPLOY_WAKE + SETUP_BEFORE + RESERVE_CHECK + page_block(texts) + JUDGED + STOPPED
                    + manual('recovery') + AFTER + cleanup(3) + RETURN)
        self.assertEqual(run.names, expected)
        self.assertEqual(run.failed, STOPPED)
        self.assertEqual((run.code, run.final), (0, 1))     # dev-e is safely back; the run itself is a FAIL
        as_found(self, run)
        self.assertEqual(run.receipt['pending'], False)
        owned_only(self, run)

    def test_a_failed_fact_after_the_import_is_recorded_and_the_rollbacks_still_run(self):
        run = run_once(lambda dev: setattr(dev, 'office_fails', True))
        office = [n for n in run.failed if 'Office: this device' in n or 'Office: a text typed' in n]
        self.assertEqual(run.failed, office)
        self.assertEqual(len(office), 6)                    # opened and saved, after the import, the restart, the rollback
        self.assertEqual(len(run.names), run.p.EXPECTED_CHECKS)
        self.assertEqual((run.code, run.final), (0, 1))
        as_found(self, run)
        self.assertIn('nextcloud full-share page: 139/145 FAIL', run.stdout)

    def test_an_injected_failure_that_does_not_roll_back_fails_its_fact_and_dev_e_still_returns(self):
        run = run_once(lambda dev: setattr(dev, 'no_rollback', True))
        self.assertEqual(run.failed, ['auto rollback: a restore with a one-shot ExecStartPre failure ends rolled-back'])
        as_found(self, run)
        self.assertEqual(run.receipt['pending'], False)
        owned_only(self, run)

    def test_an_unreviewed_confirmation_the_page_acknowledged_is_recovered_and_its_record_deleted(self):
        run = run_once(lambda dev: setattr(dev, 'extra_confirm', True))
        self.assertEqual(run.failed, ['check: the job answers one app: nextcloud importable, nothing stops and no line to '
                                      'confirm (the full share, as the actual check lists it)'] + STOPPED)
        self.assertIn('recovery: the original baseline verified (batch2_baseline.py --verify nextcloud)', run.names)
        self.assertNotIn('import: the page\'s conversion job succeeded with a backup id', run.names)
        self.assertIn('cleanup: the HA store record of this run is deleted', run.names)   # never reached the deletion
        as_found(self, run)
        owned_only(self, run)

    def test_a_page_refused_by_the_bridge_changes_nothing_and_still_returns_cold(self):
        run = run_once(lambda dev: setattr(dev, 'headroom', 1000 * 1024 ** 2))
        expected = (ADMISSION + DEPLOY_WAKE + SETUP_BEFORE + RESERVE_CHECK
                    + ['page import: refused before the page started (nothing changed)'] + STOPPED
                    + ['cleanup gate: the original baseline verified (batch2_baseline.py --verify nextcloud)']
                    + AFTER + cleanup(0) + RETURN)
        self.assertEqual(run.names, expected)
        self.assertEqual(run.failed, ['page import: refused before the page started (nothing changed)'] + STOPPED)
        self.assertFalse([c for c in run.dev.calls if c[0] == 'page'])
        self.assertFalse([c for c, _r in run.dev.helper_calls if c in ('restore-start', 'delete', 'ha-delete', 'upload-abort')])
        as_found(self, run)

    def test_a_page_that_would_not_get_its_whole_bound_and_the_rest_of_the_case_never_starts(self):
        soon = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 90 * 60))   # 90 < 55 + 40 minutes
        run = run_once(lease_change={'expires_utc': soon})
        expected = (ADMISSION + DEPLOY_WAKE + SETUP_BEFORE + STOPPED
                    + ['cleanup gate: the original baseline verified (batch2_baseline.py --verify nextcloud)']
                    + AFTER + cleanup(0) + RETURN)
        self.assertEqual(run.names, expected)
        self.assertEqual(run.failed, STOPPED)
        stop = next(r for r in run.results if r['check'] == STOPPED[0])
        self.assertIn('fixed-page-bound-and-rest-do-not-fit-the-lease', stop['detail'])
        self.assertFalse([c for c in run.dev.calls if c[0] == 'page'])
        self.assertFalse([c for c in run.dev.calls if c[:2] == ('device_python', 'UPLOADS')])   # nothing read for it
        as_found(self, run)

    def test_an_upload_the_page_could_not_finish_is_aborted_and_only_that_one(self):
        run = run_once(lambda dev: setattr(dev, 'page_mode', 'upload-stuck'))
        self.assertIn('page: UI bounded flow completed', run.failed)
        self.assertEqual(run.failed[-1], STOPPED[0])
        aborted = [r['upload_id'] for c, r in run.dev.helper_calls if c == 'upload-abort']
        self.assertEqual(len(aborted), 1)
        self.assertNotIn(aborted[0], OTHER_UPLOADS)
        self.assertIn('cleanup: no upload of this run is left pending (an interrupted page upload is aborted)', run.names)
        self.assertNotIn('cleanup: no upload of this run is left pending (an interrupted page upload is aborted)', run.failed)
        self.assertFalse([c for c, _r in run.dev.helper_calls if c in ('restore-start', 'delete', 'ha-delete')])
        as_found(self, run)
        self.assertEqual(run.receipt['pending'], False)

    def test_a_signal_during_the_import_cancels_only_this_runs_job_and_recovers(self):
        run = run_once(lambda dev: setattr(dev, 'page_mode', 'interrupt'))
        self.assertEqual(run.failed, ['page import: stopped by a signal (the browser closed in order, the relay reaped)']
                         + STOPPED)
        cancels = [r['job_id'] for c, r in run.dev.helper_calls if c == 'job-cancel']
        restore = next(j for j in run.dev.jobs if j['type'] == 'restore' and j['params'].get('ha_backup_id'))
        self.assertEqual(cancels, [restore['id']])                       # only the page's running restore
        self.assertEqual(restore['state'], 'rolled-back')
        self.assertIn('recovery: the import\'s safety backup restored (manual rollback), every health check ok', run.names)
        self.assertIn('cleanup: the HA store record of this run is deleted', run.names)
        as_found(self, run)
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
                self.assertEqual(run.names, ADMISSION[:2])
                self.assertEqual((run.code, run.final), (2, 2))
                self.assertNotIn('pending', run.receipt)                  # only the refused attempt is recorded
                self.assertEqual(len(run.receipt['runs']), 1)
                self.assertFalse([c for c in run.dev.calls if c[0] in ('run', 'reload', 'page')
                                  or c[:2] == ('wake', 'UNITS:pin') or c[0] == 'root'])
                self.assertEqual(run.dev.helper_calls, [])

    def test_admission_refuses_less_free_space_than_the_page_imports_peak_needs(self):
        def configure(dev):
            fixture = dev.p.FIXTURE.stat().st_size
            dev.free = dev.p.page_peak(dev.p.HISTORICAL_SIZES, fixture)['minimum_free_bytes'] - 1
        run = run_once(configure)
        self.assertEqual(run.names, ADMISSION[:3])
        self.assertEqual(run.failed, ADMISSION[2:3])
        self.assertEqual(run.code, 2)
        self.assertFalse([c for c in run.dev.calls if c[0] in ('run', 'root', 'reload', 'page')])

    def test_facts_naming_a_credential_this_lab_lacks_or_another_fixture_refuse_before_any_device_read(self):
        for label, change in (('unknown credential', {'facts_change': {'link_pw': 'B2_NC_X86_SHARE_ABSENT_PW'}}),
                              ('other fixture', {'configure': lambda dev: dev.p.__dict__.update(FIXTURE_BYTES=1)})):
            with self.subTest(label):
                run = run_once(change.get('configure'), change.get('facts_change'))
                self.assertEqual((run.names, run.failed, run.code), (ADMISSION[:1], ADMISSION[:1], 2))
                self.assertEqual(run.dev.calls, [])
                self.assertEqual(run.dev.helper_calls, [])

    def test_a_pending_earlier_run_refuses_before_any_change(self):
        def configure(dev):
            path = dev.p.LAB / 'run' / dev.p.RECEIPT_NAME
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({'pending': True}))
        run = run_once(configure)
        self.assertEqual(run.names, ADMISSION)
        self.assertEqual(run.failed, ADMISSION[3:])
        self.assertEqual((run.code, run.receipt['pending'], len(run.receipt['runs'])), (2, True, 1))   # kept pending
        self.assertFalse([c for c in run.dev.calls if c[0] in ('run', 'root', 'reload', 'page')])


class WatchdogTests(unittest.TestCase):
    def watch(self, jobs, case, resource, *, until):
        p = load_page('r6_fullshare_page_watch')
        cancelled = []

        def helper(command, request=None, timeout=0):
            cancelled.append(request['job_id'])
            next(row for row in jobs if row['id'] == request['job_id'])['state'] = 'cancelled'
        d = SimpleNamespace(ok=lambda command, request=None, ev=None: {'jobs': [dict(row) for row in jobs]}, helper=helper)
        metrics = {'minimum_free_bytes': None, 'peak_memory_current_bytes': 0}
        with patch.object(p, 'WATCH_INTERVAL', 0.01), patch.object(p.wake, 'device', lambda *a, **k: resource):
            thread = threading.Thread(target=p.watchdog, args=(SimpleNamespace(drv=d), SimpleNamespace(log=lambda t: None),
                                                                case, metrics))
            thread.start()
            until(p, cancelled)
            thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        return p, cancelled, metrics

    def test_a_breach_cancels_this_runs_jobs_and_every_job_it_starts_later_until_the_recovery(self):
        jobs = [{'id': 'jold', 'state': 'running'}, {'id': 'jcheck', 'state': 'running'}, {'id': 'jdone', 'state': 'succeeded'}]
        case = SimpleNamespace(stop=threading.Event(), recovery=threading.Event(), tripped=threading.Event(),
                               expires=time.time() + 3600, inflight=set(), jobs_before={'jold'})

        def until(p, cancelled):
            deadline = time.monotonic() + 10
            while 'jcheck' not in cancelled and time.monotonic() < deadline:
                time.sleep(0.01)
            jobs.append({'id': 'jconvert', 'state': 'running'})    # the page goes on after the trip: its next job
            while 'jconvert' not in cancelled and time.monotonic() < deadline:
                time.sleep(0.01)
            case.recovery.set()                                     # the recovery's own restore must run
            time.sleep(0.1)
            jobs.append({'id': 'jrecovery', 'state': 'running'})
            time.sleep(0.1)
            case.stop.set()
        p, cancelled, metrics = self.watch(jobs, case, {'free': 13 << 30, 'memory': 1 << 30}, until=until)
        self.assertTrue(case.tripped.is_set())
        self.assertEqual(cancelled, ['jcheck', 'jconvert'])            # never jold (not this run's), never jrecovery
        self.assertEqual(metrics['trip']['reason'], {'free': 13 << 30, 'memory': 1 << 30})

    def test_a_trip_during_the_recovery_cancels_its_job_once_as_in_r6(self):
        jobs = [{'id': 'jrecovery', 'state': 'running'}]
        case = SimpleNamespace(stop=threading.Event(), recovery=threading.Event(), tripped=threading.Event(),
                               expires=time.time() - 3 * 3600, inflight=set(), jobs_before=set())
        case.recovery.set()                                             # past the lease and its recovery grace

        def until(p, cancelled):
            deadline = time.monotonic() + 10
            while not cancelled and time.monotonic() < deadline:
                time.sleep(0.01)
        _p, cancelled, metrics = self.watch(jobs, case, {'free': 20 << 30, 'memory': 1 << 30}, until=until)
        self.assertEqual((cancelled, metrics['trip']['reason']), (['jrecovery'], 'lease-expired'))


class ResourceModelTests(unittest.TestCase):
    def test_the_upload_stays_through_the_chain_so_the_page_needs_the_file_more_than_the_helper_path(self):
        p = load_page('r6_fullshare_page_model')
        model = p.page_peak(p.HISTORICAL_SIZES, p.FIXTURE_BYTES)
        self.assertEqual(model['additional_peak_bytes'],
                         p.FIXTURE_BYTES + max(model['conversion_bytes'], model['restore_bytes']) + p.MARGIN)
        self.assertEqual(model['minimum_free_bytes'], p.RESERVE + p.MARGIN + model['additional_peak_bytes'])
        self.assertEqual(model['minimum_free_bytes'], 29065749324)      # 27.07 GiB on the host and dev-e's /var/lib
        self.assertGreater(model['additional_peak_bytes'], model['helper_path_additional_peak_bytes'])
        self.assertEqual(model['restore_bytes'], p.CONVERTED_BOUND + p.SAFETY_BOUND + 2 * p.CONVERTED_BOUND
                         + 2 * sum(p.HISTORICAL_SIZES) + 2 * p.GIB)
        plan = p.plan()
        self.assertEqual((plan['mutations'], plan['expected']['checks'], plan['page']['bound_seconds']), (0, 145, 3000))
        self.assertEqual(plan['resources']['minimum_free_bytes_host_and_dev_e_var_lib'], 29065749324)
        # The page's bound and waits fit the bridge's long-page ceiling; the page step leaves the rest of the lease.
        bridge = bridge_module()
        self.assertEqual(bridge.normalized_waits(p.PAGE_WAITS, p.PAGE_SECONDS), p.PAGE_WAITS)
        self.assertLessEqual(p.PAGE_SECONDS, bridge.LONG_PAGE_SECONDS)
        self.assertGreaterEqual(p.LEASE_HEADROOM, p.PAGE_STEP_BUDGET + p.REST_RESERVE + 20 * 60)

    def test_pending_uploads_are_the_unfinished_ones(self):
        p = load_page('r6_fullshare_page_uploads')
        self.assertEqual(p.pending_uploads({'u1': ['done'], 'u2': ['json', 'part'], 'u3': ['temp'], 'u4': ['done', 'part']}),
                         {'u2', 'u3', 'u4'})
        compile(p.UPLOADS, '<device program>', 'exec')


class LeaseAndCommandLineTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.fixture, self.facts = lab(self.root)
        self.facts_path = self.root / 'share-facts.json'
        self.facts_sha = sha(self.facts_path)

    def page(self, name):
        p = load_page(name)
        for target, attr, value in ((p.r6, 'FIXTURE', self.fixture), (p.r6, 'FIXTURE_SHA', sha(self.fixture))):
            patcher = patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        return p

    def test_the_lease_binds_the_phase_the_commit_the_fixture_the_facts_the_page_bound_and_the_headroom(self):
        p = self.page('r6_fullshare_page_lease')
        good = lease_for(p, facts_sha=self.facts_sha)
        p.admit_lease(good, COMMIT, p.FIXTURE_SHA, self.facts_sha)
        template = p.lease_template(COMMIT, self.facts_path)
        self.assertEqual({k: v for k, v in template.items() if not k.endswith('_utc')},
                         {k: v for k, v in good.items() if not k.endswith('_utc')})
        soon = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 100 * 60))
        for change in ({'phases': ['noshare-page']}, {'source_commit': '1' * 40}, {'fixture_sha256': '0' * 64},
                       {'facts_sha256': '0' * 64}, {'page_seconds': 20 * 60}, {'pin_refresh_policy': 'other'},
                       {'source_deployment': 'frozen'}, {'expires_utc': soon}, {'reserve_bytes': 12 << 30},
                       {'lane': 'other'}, {'page_device': 'woowbk-dev-d'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                p.admit_lease(dict(good, **change), COMMIT, p.FIXTURE_SHA, self.facts_sha)

    def test_facts_other_than_the_share_runs_refuse(self):
        p = self.page('r6_fullshare_page_facts')
        self.assertEqual(p.load_facts(self.facts_path), (self.facts, self.facts_sha))
        for label, change in (('a value instead of a name', {'link_pw': LINK_PW}), ('no share data dir',
                              {'section': dict(SECTION, datadir_in_backup=False)}),
                              ('another fixture', {'sha256': '0' * 64}), ('no digests', {'digests': {}})):
            with self.subTest(label):
                path = self.root / 'other-facts.json'
                path.write_text(json.dumps(dict(self.facts, **change)))
                with self.assertRaises(ValueError):
                    p.load_facts(path)
        (self.root / 'broken.json').write_text('{not json')
        for path in (self.root / 'broken.json', self.root / 'absent.json'):
            with self.assertRaisesRegex(ValueError, 'facts-unreadable'):
                p.load_facts(path)

    def main(self, argv, *, dirty=False, heavy=True, lease=None, facts=None):
        p = self.page('r6_fullshare_page_cli')
        calls = []

        def check_output(argv_, **kwargs):
            return ' M x\n' if argv_[:2] == ['git', 'status'] and dirty else (COMMIT + '\n' if argv_[:2] == ['git', 'rev-parse']
                                                                              else '')
        if lease is not None:
            (self.root / 'lease.json').write_text(json.dumps(lease))
        env = {'HEAVY_FREE': str(self.root / 'x.lock')} if heavy else {}
        argv = argv + ['--facts', str(facts or self.facts_path)]
        with patch.object(p, 'LOCK', str(self.root / 'x.lock')), patch.object(p.subprocess, 'check_output', check_output), \
                patch.object(p, 'control_run', lambda *a: calls.append(a) or (0, SimpleNamespace(
                    finish=lambda: True, results=[]))), patch.dict(os.environ, env, clear=False), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            if not heavy:
                os.environ.pop('HEAVY_FREE', None)
            try:
                code = p.main(argv + (['--lease', str(self.root / 'lease.json')] if lease is not None else []))
            except SystemExit as error:
                code = error.code
        return code, calls, out.getvalue(), err.getvalue(), p

    def test_only_run_with_an_exact_lease_the_share_facts_and_the_heavy_seat_reaches_the_device(self):
        code, calls, out, _err, p = self.main([])
        self.assertEqual((code, calls, json.loads(out)['mutations']), (0, [], 0))
        code, calls, out, _err, p = self.main(['--lease-template'])
        self.assertEqual((code, calls, json.loads(out)['phases'], json.loads(out)['facts_sha256']),
                         (0, [], ['fullshare-page'], self.facts_sha))
        code, calls, _out, _err, p = self.main(['--run'])
        self.assertEqual((code, calls), (2, []))                          # --run requires a lease (argparse error)
        good = lease_for(p, facts_sha=self.facts_sha)
        other_facts = self.root / 'other-facts.json'
        other_facts.write_text(json.dumps(dict(self.facts, versions=3)))  # valid, but not the facts the lease bound
        for kwargs in ({'dirty': True}, {'heavy': False}, {'lease': dict(good, phases=['noshare-page'])},
                       {'facts': other_facts}, {'facts': self.root / 'absent.json'}):
            with self.subTest(kwargs=kwargs):
                code, calls, _out, err, *_rest = self.main(['--run'], **dict({'lease': good}, **kwargs))
                self.assertEqual((code, calls), (2, []))
                self.assertIn('no case mutation started', err)
        code, calls, out, _err, _p = self.main(['--run'], lease=good)
        self.assertEqual((code, len(calls)), (0, 1))
        self.assertEqual(calls[0][3], self.facts)
        self.assertIn(f'source commit {COMMIT}', out)
        self.assertIn('lock held for', out)


class UnchangedTests(unittest.TestCase):
    def test_nextcloud_flow_and_the_r6_modules_are_unchanged_by_the_full_share_page_case(self):
        # The commit that added this case (cherry-picked or merged, whatever its hash) changed no R6 module and not
        # nextcloud_flow.py: the page case reuses them as they are (only the page bridge and the page script gained
        # their optional waits, whose absence keeps every earlier config byte for byte).
        added = subprocess.run(['git', '-C', str(REPO), 'log', '--diff-filter=A', '--format=%H', '--',
                                'tests/e2e/lab/focus_nextcloud_r6_fullshare_page.py'], capture_output=True, text=True,
                               timeout=60)
        commits = added.stdout.split()
        if added.returncode or not commits:
            self.skipTest('the commit that added the full-share page case is not in this checkout')
        changed = subprocess.run(['git', '-C', str(REPO), 'diff-tree', '--no-commit-id', '--name-only', '-r', commits[-1]],
                                 capture_output=True, text=True, timeout=60).stdout.split()
        r6 = [n for n in changed if n == 'tests/e2e/lab/nextcloud_flow.py'
              or (n.startswith('tests/e2e/lab/focus_nextcloud_r6')
                  and not n.startswith(('tests/e2e/lab/focus_nextcloud_r6_fullshare_page',)))]
        self.assertTrue(changed)
        self.assertEqual(r6, [])

    def test_every_label_is_fixed_vocabulary(self):
        for configure in (None, lambda dev: setattr(dev, 'client_fails', True)):
            run = run_once(configure)
            for name in run.names:   # never cut by the capture's 140 characters
                self.assertLessEqual(len(name), 140, name)
            for line in run.stdout.splitlines():
                if line.endswith((': PASS', ': FAIL')):
                    self.assertRegex(line, r"^[A-Za-z0-9 ,()/:'<>.=_-]{3,140}: (PASS|FAIL)$")
            self.assertRegex(run.stdout.splitlines()[-1], r"^[A-Za-z0-9 ,()/:'<>.=_-]{3,140}: [0-9]{1,3}/[0-9]{1,3} (PASS|FAIL)$")


if __name__ == '__main__':
    unittest.main()
