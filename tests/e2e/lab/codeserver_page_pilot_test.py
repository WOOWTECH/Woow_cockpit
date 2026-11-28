"""Offline: codeserver_full_flow.py with and without --via-page against a simulated dev-e (no device, no labpodman, no
browser, no real secret; every lab path points into a temporary folder with generated values).

- The default run (no --via-page) of this checkout and of the reviewed base (a1ca42b2, from git) send the same device
  calls in the same order and produce the same checks; the simulated run reproduces the real 87/87 run's fixed status
  lines (tests/backup/evidence/parity-codeserver-r8-20261126/current-full-flow.json) line for line.
- --via-page replaces exactly the upload, check and import checks with the page's (through the REAL bridge, whose page
  process is simulated), passes the bridge the right inputs, and leaves every later check unchanged.
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
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BASE = 'a1ca42b2edecfaef99ea8d7a1db93e8acd0d59ac'
OLD_DRIVER_SHA = '06d50034747792a3da24fe6f10265193b91562b0f13f0cab7587b290b486f61b'
HA_KEY = 'GENERATED-HA-KEY-0123456789abcdef'
PASSWORD = 'generated-cockpit-pass-3333'
TEST_LOGIN = 'woowbk-test-generated-login-0123456789'


def load_new(name='csff_new'):
    spec = importlib.util.spec_from_file_location(name, HERE / 'codeserver_full_flow.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def load_base():
    """The base commit's driver (from git), run as if it were this file (its HERE and its b1 driver are this tree's)."""
    shown = subprocess.run(['git', '-C', str(REPO), 'show', f'{BASE}:tests/e2e/lab/codeserver_full_flow.py'],
                           capture_output=True, timeout=60)
    if shown.returncode:
        return None
    assert hashlib.sha256(shown.stdout).hexdigest() == OLD_DRIVER_SHA
    spec = importlib.util.spec_from_loader('csff_base', loader=None)
    value = importlib.util.module_from_spec(spec)
    value.__file__ = str(HERE / 'codeserver_full_flow.py')
    exec(compile(shown.stdout, value.__file__, 'exec'), value.__dict__)
    return value


def bridge_module():
    spec = importlib.util.spec_from_file_location('csff_test_bridge', HERE / 'focus_page_bridge.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def answer(stdout=b'', returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=stdout if isinstance(stdout, bytes) else stdout.encode(), stderr=b'')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# What dev-e's code-server holds (SHA-256 prefixes only, as the device programs print them).
SNAPSHOT = {'pi': {'map': {'auth.json': 'f 600 64 0a1b2c3d4e5f', 'settings.json': 'f 644 90 1a2b3c4d5e6f',
                           'skills/woowbk-lab-baseline': 'd 755',
                           'skills/woowbk-lab-baseline/SKILL.md': 'f 644 40 2b3c4d5e6f70'}, 'missing': ['mcp-auth.json']},
            'ide': {'map': {'machineid': 'f 644 36 3c4d5e6f7081', 'workspaceStorage': 'd 755'}, 'missing': []},
            'ext': {'map': {'.': 'd 755'}, 'missing': []},
            'desktop': {'map': {'woowbk-lab-baseline.txt': 'f 644 50 4d5e6f708192'}},
            'secret': 'aaaa1111bbbb2222', 'env': 'cccc3333dddd4444'}
NEVER_MISSING = {'pi': ['connectors', 'omnigent', 'codex-bootstrap', 'trust.json', 'mcp-auth.json',
                        'claude/.credentials.json', 'codex/auth.json'],
                 'ide': ['workspaceStorage/-296a321', 'caches/CachedConfigurations']}


class Dev:
    """dev-e as codeserver_full_flow.py (and, with --via-page, the bridge) sees it, one code-server that can be
    imported."""

    def __init__(self, module, fixture_sha):
        self.m = module
        self.store_id = 'ha-' + fixture_sha[:20]
        self.fixture_sha = fixture_sha
        self.calls, self.ha, self.jobs = [], [], []
        self.backups = {'20261123T120000Z-0000base': {'id': '20261123T120000Z-0000base', 'type': 'manual', 'key_id': 'k-1'}}
        self.data = 'base'           # whose code-server data is live: this device's ('base') or HA's ('ha')
        self.dropin = self.marker_file = self.needles = False
        self.login_file = False      # the generated test login (pi:auth.json) the run seeds when missing
        self.converted = self.safety = None
        self.sequence = 0

    # ---------------------------------------------------------------- bookkeeping
    def log(self, *entry):
        self.calls.append(entry)

    def backup(self, kind, **extra):
        bid = '20261128T1000%02dZ-%08x' % (self.sequence + 1, self.sequence + 1)
        self.sequence += 1
        self.backups[bid] = {'id': bid, 'type': kind, 'key_id': 'k-1', 'size': 1000, **extra}
        return bid

    def job(self, kind, params, state, result, unit=None):
        self.sequence += 1
        jid = 'j20261128T1100%02dZ-%08x' % (self.sequence, self.sequence)
        record = {'id': jid, 'type': kind, 'state': state, 'phase': 'done', 'progress': {}, 'params': params,
                  'result': result, 'unit': unit or f'woowtech-backup-{jid}.service'}
        self.jobs.append(record)
        return record

    def check_result(self, ha_id):
        pins = dict(self.m.PINS)
        return {'ha_check': {'schema': 2, 'ha_backup_id': ha_id, 'shared': [],
                             'apps': [{'app_id': 'woow-code-server', 'ok': True, 'blockers': [], 'arch': 'amd64',
                                       'version': '0.1.14', 'target_version': '4.139.1', 'importable': True,
                                       'warnings': ['this backup has no share folder: no workspace moves',
                                                    'codex-bootstrap stays in HA', 'symlinks skipped', 'MCP review'],
                                       'issues': [{'id': 'codeserver.no-share', 'level': 'notice', 'message': 'n',
                                                   'items': [], 'more': 0},
                                                  {'id': 'codeserver.unknown-entries', 'level': 'notice', 'message': 'u',
                                                   'items': ['codex-bootstrap'], 'more': 0},
                                                  {'id': 'codeserver.symlinks-skipped', 'level': 'notice', 'message': 's',
                                                   'items': [], 'more': 0},
                                                  {'id': 'codeserver.mcp-review', 'level': 'notice', 'message': 'm',
                                                   'items': [], 'more': 0}],
                                       'woow-code-server': {'pins': pins, 'target_pins': dict(pins), 'sessions': 28,
                                                            'claude_projects': 20, 'codex_sessions': 15, 'skills': 3,
                                                            'snippets': 1, 'extensions': 0, 'mcp_servers': 9,
                                                            'files': 386, 'share': False, 'workspace': False,
                                                            'unknown': ['codex-bootstrap']}}]}}

    def convert_result(self):
        self.converted = self.backup('manual', from_ha={'ha_backup_id': self.store_id})
        return {'backup_id': self.converted,
                'ha_import': {'apps': ['woow-code-server'], 'test_mode': False,
                              'notes': ['code-server: the IDE settings merge', 'logins stay'],
                              'reminders_by_app': {'woow-code-server': ['log in again at /login',
                                                                        'copy the workspace to /share/projects']}}}

    def restore_result(self, backup_id):
        if backup_id == self.converted and self.marker_file:      # the injected one-shot failure
            self.marker_file = False
            return 'rolled-back', {'rolled_back': True, 'safety_backup_id': self.backup('safety')}
        self.data = 'ha' if backup_id == self.converted else 'base'
        safety = self.backup('safety')
        if backup_id == self.converted and self.safety is None:
            self.safety = safety
        return 'succeeded', {'rolled_back': False, 'safety_backup_id': safety, 'health': [{'status': 'ok'}],
                             'downtime_seconds': 12}

    def public(self, job):
        return {k: copy.deepcopy(v) for k, v in job.items() if k != 'unit'}

    # ---------------------------------------------------------------- the b1 driver's device calls
    def owner(self, *argv, input=None, timeout=600, check=False):
        self.log('owner', argv, input)
        m = self.m
        if argv[:3] == ('systemctl', '--user', 'is-active'):
            return answer('active\n')
        if argv[:3] in (('systemctl', '--user', 'restart'), ('systemctl', '--user', 'daemon-reload')) or argv[0] in (
                'mkdir', 'rmdir'):
            return answer()
        if argv[:2] == ('sh', '-c'):
            if argv[4].endswith(m.MARKER_REL):
                self.marker_file = True
            elif argv[4].endswith(m.DROPIN_REL):
                self.dropin = True
            return answer()
        if argv[:2] == ('test', '-e'):
            exists = (argv[2].endswith(m.MARKER_REL) and self.marker_file) or (argv[2].endswith(m.DROPIN_REL)
                                                                               and self.dropin)
            return answer(returncode=0 if exists else 1)
        if argv[:2] == ('rm', '-f'):
            self.dropin = self.marker_file = False
            return answer()
        raise AssertionError(('owner', argv))

    def root(self, *argv, input=None, timeout=600, check=False):
        self.log('root', argv, input)
        if argv[:2] == ('sh', '-c') and 'memory.stat' in argv[2]:
            return answer('anon 1073741824\nkernel 104857600\n3221225472\n')
        if argv == ('id', '-u', 'appowner'):
            return answer('1025\n')
        if argv[:2] == ('systemctl', 'is-enabled'):
            return answer('enabled\n')
        if argv[:2] in (('systemctl', 'mask'), ('systemctl', 'unmask')):
            return answer()
        if argv[:2] == ('rm', '-rf'):
            self.needles = False
            return answer()
        if argv[:2] == ('test', '-e'):
            return answer(returncode=0 if self.needles else 1)
        raise AssertionError(('root', argv))

    def run(self, argv, *, input=None, stdin=None, timeout=600, check=False):
        self.log('run', tuple(Path(a).name if str(a).startswith('/') else a for a in argv[:3]))
        if argv[:2] == ['bash', str(HERE / 'deploy-src.sh')]:
            return answer('deployed this tree\n')
        raise AssertionError(('run', argv))   # nothing else may ever leave this process

    def client(self, request):
        imported = self.data == 'ha'
        out = {'health': 200, 'login_status': 302, 'login_cookie': True, 'login_location': ['./'], 'root_status': 302,
               'root_redirect': './?folder=/workspace', 'workbench_status': 200, 'workbench_page': True,
               'anonymous_status': 302, 'anonymous_to_login': True,
               'served': dict(self.m.HA_MARKERS) if imported else {spec: 'HTTP 404' for spec in request['ha_markers']},
               'seen': dict(self.m.HA_MARKERS) if imported else {spec: 'rc 1' for spec in request['ha_markers']},
               'device_markers': {spec: '5e6f70819203a4b5' for spec in request['device_markers']},
               'acp_agents': {'pi': 'pi-code', 'claude': 'claude-agent-acp', 'codex': 'codex-code'},
               'default_shell': None, 'ha_keys': {k: True for k in request['ha_setting_keys']}, 'trust_enabled': False,
               'pi_sessions': 30 if imported else 2, 'claude_projects': 21 if imported else 1,
               'codex_sessions': 16 if imported else 1,
               'skills': ['woow-import-test-20261123', 'woowbk-lab-baseline'] if imported else ['woowbk-lab-baseline'],
               'never_missing': copy.deepcopy(NEVER_MISSING), 'ide_nonroot': 0, 'ha_nonroot': 0,
               'snapshot': copy.deepcopy(SNAPSHOT)}
        if request.get('wrong'):
            out.update(wrong_status=200, wrong_cookie=False)
        return out

    def device_python(self, script, request=None, *, as_owner=True, timeout=600):
        m, bridge = self.m, getattr(self, 'bridge', None)
        name = next((n for n in ('ENGINE_HASHES', 'SEED', 'UNSEED', 'BEFORE', 'CLIENT', 'COLLECT', 'LEAKS', 'SPACE')
                     if script == getattr(m, n)), None)
        if name is None and script == m.drv.RUN_LIST:
            name = 'RUN_LIST'
        if name is None and bridge is not None:
            name = {bridge.PRECONDITIONS: 'PRECONDITIONS', bridge.NATIVE_UNITS: 'NATIVE_UNITS'}.get(script)
        self.log('device_python', name, as_owner, copy.deepcopy(request))
        if name == 'ENGINE_HASHES':
            lib = REPO / 'backup-engine/woowbackup'
            return {'lib': {str(p.relative_to(lib)): sha(p) for p in lib.rglob('*.py') if '__pycache__' not in p.parts},
                    'helper': sha(REPO / 'backup-engine/woowtech-cockpit-backup')}
        if name == 'SEED':
            created = []
            if request.get('login') and not self.login_file:
                self.login_file = True
                created.append(request['login'])
            return {'created': created}
        if name == 'UNSEED':
            if m.TEST_LOGIN in request['created']:
                self.login_file = False
            return {'removed': list(request['created']), 'left': []}
        if name == 'BEFORE':
            return dict(copy.deepcopy(SNAPSHOT), health=200, never_missing=copy.deepcopy(NEVER_MISSING))
        if name == 'CLIENT':
            return self.client(request)
        if name == 'SPACE':
            return {'running_reserve': 1 << 30, 'watch_margin': 1 << 29, 'floor': 3 << 29, 'min_free': 50 << 30, 'free': {}}
        if name == 'COLLECT':
            self.needles = True
            return {'values': 9}
        if name == 'LEAKS':
            return {'scanned': 308, 'journal_bytes': 4096, 'names': len(request['secrets']) + 1, 'moved_values': 9,
                    'hits': 0, 'journal_hits': 0, 'app_log_hits': 0}
        if name == 'RUN_LIST':
            return {'/var/lib/woowtech-backup/staging': [], '/run/woowtech-backup': ['engine.lock']}
        if name == 'PRECONDITIONS':
            return {'page': {n: sha(REPO / 'backup' / n) for n in bridge.PAGE_FILES}, 'cockpit_socket': True,
                    'hostname': 'woowbk-dev-e', 'devadmin_uid': 1000, 'headroom': 1500 * 1024 ** 2}
        if name == 'NATIVE_UNITS':
            rows = {job['id']: job for job in self.jobs}
            return [{k: rows[j][k] for k in ('id', 'unit', 'type', 'state')} for j in request['ids']]
        raise AssertionError(('device_python', script[:60]))

    def ok(self, command, request=None, *, ev, timeout=1800):
        self.log('ok', command, copy.deepcopy(request))
        if command == 'status':
            return {'version': (REPO / 'VERSION').read_text().strip(), 'active_job': None}
        if command == 'key-init':
            return {'key': {'key_id': 'k-1'}, 'created': False}
        if command == 'list':
            return {'backups': [dict(row) for row in self.backups.values()], 'ha_backups': [dict(row) for row in self.ha]}
        if command == 'inspect':
            return {'ok': True, 'preflight': {'ok': True, 'checks': [], 'apps': [
                {'id': 'woow-code-server', 'mode': 'inplace', 'settings': {'state': 'same'}}]}}
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
        raise AssertionError(('helper', command))

    def record(self):
        if not any(row['id'] == self.store_id for row in self.ha):
            self.ha.append({'id': self.store_id, 'sha256': self.fixture_sha,
                            'importable_apps': [{'slug': 'x', 'app_id': 'woow-code-server', 'installed': True}]})

    def upload(self, path, *, ev):
        self.log('upload', Path(path).name)
        self.record()
        return 0, {'ha_backup': {'id': self.store_id,
                                 'importable_apps': [{'app_id': 'woow-code-server', 'installed': True}]}}

    def run_check(self, ha, apps, *, ev, key=None, tag='check'):
        self.log('run_check', ha, tuple(apps), key == HA_KEY, tag)
        job = self.job('verify', {'source': 'ha', 'ha_backup_id': ha, 'apps': list(apps), 'key_provided': True},
                       'succeeded', self.check_result(ha))
        return self.public(job), 2.0

    def convert(self, ha, apps, test_mode, *, ev, key, tag):
        self.log('convert', ha, tuple(apps), test_mode, key == HA_KEY, tag)
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
        return json.loads((HERE / 'catalog' / 'woow-code-server.json').read_text(encoding='utf-8'))

    # ---------------------------------------------------------------- the real page's effects (--via-page)
    def page(self, config, seconds, device):
        """What dev-e's real page does through the relay: upload, one check of woow-code-server (no confirmation line,
        as the real check), its one acknowledgement, one import whose two linked jobs convert and restore in the first
        job's unit."""
        self.log('page', device, tuple(config['apps']), seconds <= 20 * 60, config['key'] == HA_KEY,
                 config['password'] == PASSWORD)
        self.record()
        self.job('verify', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['woow-code-server'],
                            'key_provided': True}, 'succeeded', self.check_result(config['ha_id']))
        result = self.convert_result()
        first = self.job('backup', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['woow-code-server'],
                                    'test_mode': False,
                                    'group': {'kind': 'ha-import', 'step': 'convert', 'index': 0, 'count': 1},
                                    'chain': {'apps': ['woow-code-server'], 'test_mode': False, 'then_restore': True,
                                              'acknowledged': {}}}, 'succeeded', result)
        state, restored = self.restore_result(self.converted)
        restored['group'] = {'next_job_id': None, 'results': [{'app_id': 'woow-code-server', 'status': 'imported'}]}
        second = self.job('restore', {'backup_id': self.converted, 'apps': ['woow-code-server'],
                                      'ha_backup_id': config['ha_id']}, state, restored, unit=first['unit'])
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
        browser = {'stage': 'issued-value-scan', 'failure_kind': None, 'completed': True, 'issued_values_scanned': True,
                   'checks': [{'check': n, 'ok': True} for n in names],
                   'confirmations': {'expected_keys': {}, 'sent_keys': {}, 'lines_expected': 0, 'lines_shown': 0,
                                     'check_importable': ['woow-code-server']},
                   'issued_scan_counts': {'scan_completed': True, 'observed_values': 2, 'observations_complete': True,
                                          'credential_device_hits': 0, 'credential_host_hits': 0, 'device_files': 30,
                                          'host_files': 3, 'archive_index_sidecars': 4, 'regular_json_roots': 2},
                   'wire': {'import_starts': 1}}
        Path(config['result']).write_text(json.dumps(browser))
        return {'started': True, 'exit': 0, 'timed_out': False, 'interrupted': False, 'stop': 'exited',
                'relay_clean': True, 'relay_error': None, 'children_left': []}


SECRET_FILES = {'b1-creds.env': f'HA_BACKUP_KEY={HA_KEY}\nB1_EMQX_ADMIN_PW=generated-ha-admin-pass-4711\n',
                'ha-import-creds.env': 'GENERATED_OTHER_PW=generated-other-pass-1234\n', 'dev-d-markers.json': '{}',
                'devadmin.pass': PASSWORD + '\n'}


def lab(root):
    for name, text in SECRET_FILES.items():
        path = root / 'secrets' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o600)
    fixture = root / 'fixture.tar'
    fixture.write_bytes(b'generated stand-in for the encrypted code-server HA backup ' * 64)
    return fixture


def fake_path(real):
    def make(*parts):
        if parts == ('/proc/meminfo',):
            return SimpleNamespace(read_text=lambda: 'MemTotal: 16000000 kB\nMemAvailable:    6291456 kB\n')
        return real(*parts)
    return make


@contextlib.contextmanager
def simulated(m, root, *, bridge=None, lock=None):
    """Every device-facing function of the driver `m` answered by Dev; every lab path in `root`; no real sleep."""
    fixture = lab(root)
    dev = Dev(m, sha(fixture))
    dev.bridge = bridge
    m.drv.STATE.clear()
    with contextlib.ExitStack() as stack:
        for target, name, value in (
                (m, 'LAB', root), (m.drv, 'LAB', root), (m, 'FIXTURE', fixture), (m, 'FIXTURE_SHA', sha(fixture)),
                (m, 'isolation', lambda: 'true none {}'), (m, 'clean_tree', lambda: True), (m, 'Path', fake_path(Path)),
                (m.drv, 'run', dev.run), (m.drv, 'root', dev.root), (m.drv, 'owner', dev.owner), (m.drv, 'ok', dev.ok),
                (m.drv, 'helper', dev.helper), (m.drv, 'device_python', dev.device_python), (m.drv, 'upload', dev.upload),
                (m.drv, 'run_check', dev.run_check), (m.drv, 'convert', dev.convert), (m.drv, 'restore', dev.restore),
                (m.drv, 'wait_job', dev.wait_job), (m.drv, 'labelled', dev.labelled), (m.drv, 'catalog', dev.catalog),
                (os, 'statvfs', lambda _path: SimpleNamespace(f_bavail=(200 << 30) // 4096, f_frsize=4096)),
                (time, 'sleep', lambda _seconds: None)):
            stack.enter_context(patch.object(target, name, value))
        if lock is not None:
            stack.enter_context(patch.object(m, 'LOCK', str(lock)))
        if bridge is not None:
            real_load = m._load
            stack.enter_context(patch.object(m, '_load', lambda name: bridge if name == 'focus_page_bridge' else real_load(name)))
            for name, value in (('run_page', dev.page), ('host_available_kib', lambda: 6 * 1024 * 1024),
                                ('PLAYWRIGHT', fixture), ('CHROMIUM', fixture)):
                stack.enter_context(patch.object(bridge, name, value))
        yield dev


def secrets_of(m, root, *, via_page):
    secrets = m.drv.Secrets([root / 'secrets/b1-creds.env', root / 'secrets/ha-import-creds.env'],
                            root / 'secrets/dev-d-markers.json')
    if via_page:
        secrets.register('COCKPIT_PASSWORD', (root / 'secrets/devadmin.pass').read_text().strip())
    secrets.register('CSFF_TEST_LOGIN', TEST_LOGIN)
    return secrets


def simulate(m, *, via_page=False, bridge=None):
    """One whole run_all of driver `m` on a fresh simulated dev-e: (stdout check lines, results, device calls, run, dev)."""
    root = Path(tempfile.mkdtemp()).resolve()
    try:
        lock = root / 'woowbk-dev-e-mutation.lock'
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # the driver's own hold of the dev-e lock (main() takes it)
        try:
            with simulated(m, root, bridge=bridge, lock=lock) as dev:
                secrets = secrets_of(m, root, via_page=via_page)
                args = SimpleNamespace(run=True, self_check=False, secrets=secrets, test_login=TEST_LOGIN,
                                       **({'via_page': True} if via_page else {}))
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    ev = m.Ev(secrets, area='codeserver-csff')
                    run = m.Run(args, ev)
                    run.lock_started = time.monotonic()
                    ok = m.run_all(run)
                    passed = ev.finish()
                files = {str(p.relative_to(ev.dir)): p.read_bytes() for p in ev.dir.rglob('*') if p.is_file()}
                lines = [line for line in out.getvalue().splitlines() if line.endswith((': PASS', ': FAIL'))]
                return SimpleNamespace(ok=ok and passed, lines=lines, results=ev.results, calls=dev.calls, run=run, dev=dev,
                                       files=files, state=copy.deepcopy(m.drv.STATE))
        finally:
            os.close(fd)
    finally:
        shutil.rmtree(root, ignore_errors=True)


REAL = json.loads((REPO / 'tests/backup/evidence/parity-codeserver-r8-20261126/current-full-flow.json').read_text())
REAL_CHECKS = [line for line in REAL['fixed_status'] if line.endswith(': PASS')]


class DefaultRunTests(unittest.TestCase):
    def test_the_simulated_default_run_is_the_real_87_check_run_line_for_line(self):
        run = simulate(load_new())
        self.assertEqual(len(REAL_CHECKS), 87)
        self.assertEqual(run.lines, REAL_CHECKS)
        self.assertTrue(run.ok)
        self.assertFalse(any(call[0] in ('page',) for call in run.calls))
        leaks = [call for call in run.calls if call[:2] == ('device_python', 'LEAKS')]
        self.assertEqual(sorted(leaks[0][3]['secrets']), ['HA_BACKUP_KEY', 'TEST_LOGIN'])   # the helper flow's scan
        self.assertEqual(run.state['created_backups'], [])                                 # everything it made is gone
        self.assertEqual(run.dev.ha, [])
        self.assertFalse(run.dev.login_file)                                              # the seeded test login too

    def test_this_checkouts_default_run_equals_the_reviewed_base_call_for_call(self):
        base = load_base()
        if base is None:
            self.skipTest(f'base commit {BASE} is not in this checkout')
        before, after = simulate(base), simulate(load_new())
        self.assertEqual(after.calls, before.calls)   # the same device calls, with the same requests, in the same order
        self.assertEqual([(r['check'], r['ok']) for r in after.results], [(r['check'], r['ok']) for r in before.results])
        self.assertEqual(after.lines, before.lines)
        self.assertEqual(sorted(after.files), sorted(before.files))   # the same evidence files
        for name in ('check-result.json', 'convert-job.json', 'restore-job.json', 'state-before.json', 'leaks.json'):
            self.assertEqual(after.files[name], before.files[name], name)


# The checks the page replaces: upload (3), check (7), import (8) of the helper flow.
HELPER_IMPORT = REAL_CHECKS[19:37]


def page_block(texts):
    browser = ['UI real administrative Cockpit bridge reaches this device', texts['upload'], texts['select'],
               'UI actual check confirmation keys observed including valid zero', texts['view'], texts['lines'],
               'UI has exactly one acknowledgement and import waits for it', 'UI check did not start an import or separate restore',
               'UI real key field removed before screenshot', 'UI one acknowledgement enables import', texts['result'],
               texts['intent'], texts['keys'], 'UI no page script errors during this page flow',
               'UI cookie observation completed without gaps',
               'UI every issued credential absent from records journal and private evidence; proved public markers counted '
               'separately']
    return (['page import: host disk keeps the 12 GiB floor after the upload, check, conversion and restore writes',
             'page import: real space above the product\'s floor (running reserve + watch margin) the conversion enforces']
            + ['page: ' + name for name in browser]
            + ['page: bounded (20 min), the browser closed in order and every relay exec child reaped',
               'page: the uploaded HA record is the fixture (id and SHA-256)',
               'page: exactly the page\'s own check and import jobs, none left running, no other new backup',
               'page: the check calls woow-code-server importable, stops nothing, and lists every confirmation line keyed '
               '(read from the actual check)',
               'page: the one acknowledgement, the import and its jobs carry every listed confirmation key exactly once',
               'page: one conversion and its restore succeeded as two linked jobs in the first job\'s unit',
               'page: every issued Cockpit session value is absent from the records, the journal and the private evidence',
               'upload: woow-code-server is importable and installed here', 'check: the page\'s check job succeeded',
               'check: ok, no blockers',
               'check: source amd64, add-on 0.1.14, this device\'s code-server 4.139.1, the four programs equal',
               'check: the section counts equal the backup\'s facts (sessions, skills, snippets, MCP servers, files)',
               'check: no workspace (no share folder) and codex-bootstrap named as not moved; warnings say so',
               'check: no throwaway container, volume or network left (the version container is gone)',
               'import: the page\'s conversion job succeeded with a backup id',
               'import: ha_import names woow-code-server, the code-server notes and its reminders (logins, history, '
               'connectors, SSH, workspace)',
               'import: the converted backup is listed as manual with its HA origin, encrypted',
               'import: the page\'s restore of the converted backup succeeded with a safety backup, not rolled back, '
               'every health check ok'])


class ViaPageRunTests(unittest.TestCase):
    def test_via_page_replaces_only_the_import_checks_and_passes_through_the_real_bridge(self):
        m, bridge = load_new('csff_page'), bridge_module()
        default = simulate(m)
        run = simulate(m, via_page=True, bridge=bridge)
        self.assertTrue(run.ok, [r for r in run.results if not r['ok']])
        names = [r['check'] for r in run.results]
        block = page_block(bridge.page_settings(['woow-code-server'], ['woow-code-server'], [])['texts'])
        self.assertEqual(names[:19], [r['check'] for r in default.results][:19])          # preflight, setup, before
        self.assertEqual(names[19:19 + len(block)], block)
        tail = [r['check'] for r in default.results][37:]
        self.assertEqual(names[-len(tail):], tail)                                         # verify ... after: unchanged
        self.assertEqual(len(names), 19 + len(block) + len(tail))
        self.assertEqual((len(default.results), len(HELPER_IMPORT), len(block), len(tail), len(run.results)),
                         (87, 18, 36, 50, 105))
        # The page made the upload, the check and the import; the driver sent none of those helper commands itself.
        kinds = [call[0] for call in run.calls]
        self.assertEqual(kinds.count('page'), 1)
        for name in ('upload', 'run_check', 'convert'):
            self.assertNotIn(name, kinds)
        self.assertNotIn(('ok', 'inspect'), [call[:2] for call in run.calls])
        restores = [call for call in run.calls if call[0] == 'restore']
        self.assertEqual([c[3] for c in restores], ['restore-inject-cs-x86', 'rollback-cs-x86'])   # only the later steps
        [page] = [call for call in run.calls if call[0] == 'page']
        self.assertEqual(page, ('page', 'woowbk-dev-e', ('woow-code-server',), True, True, True))
        # The bridge read only: status, list, jobs (helper) and its two device programs; the rest is the driver's own.
        bridge_reads = [call for call in run.calls if call[:2] in (('device_python', 'PRECONDITIONS'),
                                                                   ('device_python', 'NATIVE_UNITS'))]
        self.assertEqual([c[1] for c in bridge_reads], ['PRECONDITIONS', 'NATIVE_UNITS'])
        self.assertTrue(all(c[2] is False for c in bridge_reads))   # as root, read-only programs
        page_files = {name for name in run.files if name.startswith('page/')}
        self.assertEqual(page_files, {'page/browser.json', 'page/page-bridge.json'})
        summary = json.loads(run.files['page/page-bridge.json'])
        self.assertTrue(summary['passed'])
        self.assertEqual((summary['device'], summary['expected_acknowledged'], summary['confirmation_lines']),
                         ('woowbk-dev-e', {}, 0))                  # the real check lists no confirmation line
        # What the page made was cleaned up by the driver's own cleanup; the leak scan also looked for the password.
        self.assertEqual(run.state['created_backups'], [])
        self.assertEqual(run.dev.ha, [])
        self.assertFalse(run.dev.login_file)
        leaks = [call for call in run.calls if call[:2] == ('device_python', 'LEAKS')]
        self.assertEqual(sorted(leaks[0][3]['secrets']), ['COCKPIT_PASSWORD', 'HA_BACKUP_KEY', 'TEST_LOGIN'])
        for name, data in run.files.items():
            for secret in (HA_KEY, PASSWORD, TEST_LOGIN):
                self.assertNotIn(secret.encode(), data, name)
        # Everything before the page step and after it sends exactly the default run's device calls.
        first_page = next(i for i, call in enumerate(run.calls) if call[:2] == ('device_python', 'SPACE'))
        first_default = next(i for i, call in enumerate(default.calls) if call[0] == 'ok' and call[1] == 'list'
                             and i > next(j for j, c in enumerate(default.calls) if c[:2] == ('device_python', 'BEFORE')))
        self.assertEqual(run.calls[:first_page], default.calls[:first_default])

    def test_an_unreviewed_confirmation_on_the_pages_check_fails_the_run_after_the_import(self):
        m, bridge = load_new('csff_unreviewed'), bridge_module()
        real_check, real_page = Dev.check_result, Dev.page

        def with_confirmation(dev, ha_id):
            result = real_check(dev, ha_id)
            result['ha_check']['apps'][0]['issues'].append({'id': 'codeserver.databases-unchecked', 'level': 'confirm',
                                                            'message': 'c', 'items': [], 'more': 0,
                                                            'key': 'codeserver.databases-unchecked:' + '3' * 16})
            return result

        def page_with_key(dev, config, seconds, device):
            outcome = real_page(dev, config, seconds, device)
            browser = json.loads(Path(config['result']).read_text())
            keys = {'woow-code-server': ['codeserver.databases-unchecked:' + '3' * 16]}
            browser['confirmations'].update(expected_keys=keys, sent_keys=keys, lines_expected=1, lines_shown=1)
            Path(config['result']).write_text(json.dumps(browser))
            first = next(job for job in dev.jobs if job['type'] == 'backup')
            first['params']['acknowledged'] = copy.deepcopy(keys)
            first['params']['chain']['acknowledged'] = copy.deepcopy(keys)
            return outcome

        with patch.object(Dev, 'check_result', with_confirmation), patch.object(Dev, 'page', page_with_key):
            run = simulate(m, via_page=True, bridge=bridge)
        self.assertFalse(run.ok)
        failed = [r['check'] for r in run.results if not r['ok']]
        self.assertEqual(failed, ['run stopped in a step (Failed)'])   # the page and its gates passed; the review did not
        self.assertIn('check: no workspace (no share folder) and codex-bootstrap named as not moved; warnings say so',
                      [r['check'] for r in run.results])
        self.assertNotIn('import: the page\'s conversion job succeeded with a backup id', [r['check'] for r in run.results])
        # The run's own cleanup still removed what the page made (the batch2 baseline is the recovery, as for any stop
        # past the import); the check gate names the unreviewed confirmation in the private evidence only.
        self.assertEqual(run.state['created_backups'], [])
        self.assertEqual(run.dev.ha, [])
        self.assertIn(b'codeserver.databases-unchecked', run.files['results.json'])

    def test_the_driver_hands_the_bridge_exactly_its_inputs(self):
        m = load_new('csff_inputs')
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
            secrets = secrets_of(m, root, via_page=True)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                ev = m.Ev(secrets, area='codeserver-csff')
                run = m.Run(SimpleNamespace(secrets=secrets, via_page=True, test_login=TEST_LOGIN), ev)
                run.lock_started = time.monotonic()
                started = time.monotonic()
                with self.assertRaisesRegex(m.Failed, 'did not run to the end'):
                    run.step_page_import(bridge=FakeBridge)
            fixture = m.FIXTURE   # the run's own fixture (here the generated stand-in)
        self.assertEqual({k: seen[k] for k in ('device', 'lock', 'apps', 'importable', 'stops', 'fixture', 'key', 'password',
                                               'evidence', 'source')},
                         {'device': 'woowbk-dev-e', 'lock': '/tmp/woowbk-dev-e-mutation.lock', 'apps': ['woow-code-server'],
                          'importable': ['woow-code-server'], 'stops': [], 'fixture': fixture, 'key': HA_KEY,
                          'password': PASSWORD, 'evidence': ev.dir / 'page', 'source': m.REPO})
        self.assertEqual(seen['ops'], ('ops', ['helper', 'root_json', 'wait_job']))
        self.assertLessEqual(seen['deadline'], started + 25 * 60 + 1)
        self.assertLessEqual(seen['deadline'], run.lock_started + m.HOLD_BUDGET - m.REST_RESERVE + 1)
        self.assertEqual([r['check'] for r in ev.results][-1],
                         'page import: refused before the page started (nothing changed)')
        self.assertIsNone(run.created_store)   # nothing was uploaded: nothing of the page's to clean up
        self.assertEqual(m.LOCK, '/tmp/woowbk-dev-e-mutation.lock')
        self.assertEqual(m.DEVICE, 'woowbk-dev-e')

    def test_a_signal_during_the_page_leaves_what_the_page_made_to_the_runs_own_cleanup(self):
        m = load_new('csff_signal')
        root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, root, True)
        with simulated(m, root) as dev:
            converted = dev.backup('manual')

            class Stop(Exception):
                summary = {'phase': 'interrupted', 'created_backups': [converted], 'check_job_ids': ['j1'],
                           'root_job_ids': ['j2']}

            class FakeBridge:
                Ops = staticmethod(lambda **kw: None)
                BridgeError = Exception

                class Refused(Exception):
                    pass

                @staticmethod
                def import_via_page(**kwargs):
                    dev.record()   # the page had uploaded the file when the stop came
                    raise Stop('page import interrupted')

            secrets = secrets_of(m, root, via_page=True)
            with contextlib.redirect_stdout(io.StringIO()):
                ev = m.Ev(secrets, area='codeserver-csff')
                run = m.Run(SimpleNamespace(secrets=secrets, via_page=True, test_login=TEST_LOGIN), ev)
                run.lock_started = time.monotonic()
                with self.assertRaisesRegex(m.Failed, 'did not run to the end'):
                    run.step_page_import(bridge=FakeBridge)
                self.assertEqual(m.drv.STATE['created_backups'], [converted])
                self.assertEqual(run.created_store, dev.store_id)
                run.step_cleanup()
        stopped = [r for r in ev.results if r['check'].startswith('page import: stopped by a signal')]
        self.assertEqual([(r['check'], r['ok']) for r in stopped],
                         [('page import: stopped by a signal (the browser closed in order, the relay reaped)', False)])
        self.assertNotIn(converted, dev.backups)   # the run's own cleanup removed what the page had made
        self.assertEqual(dev.ha, [])


class CommandLineTests(unittest.TestCase):
    def main(self, argv):
        m = load_new('csff_cli')
        root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, root, True)
        lab(root)
        runs = []

        def run_all(run):
            runs.append(run)
            return True
        with patch.object(m, 'LAB', root), patch.object(m.drv, 'LAB', root), patch.object(m, 'LOCK', str(root / 'x.lock')), \
                patch.object(m, 'run_all', run_all), contextlib.redirect_stdout(io.StringIO()) as out:
            code = m.main(argv)
        return code, runs, out.getvalue()

    def test_only_via_page_chooses_the_bridge_and_reads_the_cockpit_login(self):
        code, [run], out = self.main(['--run'])
        self.assertEqual(code, 0)
        self.assertIs(run.args.via_page, False)
        self.assertNotIn('COCKPIT_PASSWORD', run.args.secrets.values)
        code, [run], out = self.main(['--run', '--via-page'])
        self.assertEqual(code, 0)
        self.assertIs(run.args.via_page, True)
        self.assertEqual(run.args.secrets['COCKPIT_PASSWORD'], PASSWORD)
        self.assertNotIn(PASSWORD, out)
        for argv in ([], ['--self-check'], ['--via-page']):
            with self.subTest(argv=argv):
                code, runs, out = self.main(argv)
                self.assertEqual((code, runs, out.strip()), (0, [], 'self-check: PASS'))

    def test_the_step_list_changes_only_with_via_page(self):
        m = load_new('csff_steps')
        for via_page, expected in ((None, ['setup', 'before', 'upload', 'check', 'import', 'verify', 'needles', 'restart',
                                           'auto rollback', 'rollback']),
                                   (False, ['setup', 'before', 'upload', 'check', 'import', 'verify', 'needles', 'restart',
                                            'auto rollback', 'rollback']),
                                   (True, ['setup', 'before', 'page import', 'verify', 'needles', 'restart',
                                           'auto rollback', 'rollback'])):
            with self.subTest(via_page=via_page):
                order = []
                args = SimpleNamespace() if via_page is None else SimpleNamespace(via_page=via_page)
                run = SimpleNamespace(args=args, ev=SimpleNamespace(log=lambda text: None, check=lambda *a, **k: True),
                                      needles=False, budget=lambda name: order.append(name), step_cleanup=lambda: None)
                for name in ('setup', 'step_before', 'step_upload', 'step_check', 'step_import', 'step_page_import',
                             'collect_needles', 'step_restart', 'step_auto_rollback', 'step_rollback_to_own'):
                    setattr(run, name, lambda: None)
                run.verify = lambda label_text, **kw: None
                with patch.object(m, 'isolation', lambda: 'true none {}'), contextlib.redirect_stdout(io.StringIO()):
                    self.assertTrue(m.run_all(run))
                self.assertEqual(order, expected)


if __name__ == '__main__':
    unittest.main()
