"""Offline: the leased LiteLLM instance controller's flow (focus_litellm_instance_acceptance_run.py, 68/68 on dev-d) with
and without --via-page against a simulated dev-d (no device, no labpodman, no browser, no real secret).

- The default flow of this checkout and of the reviewed base (a1ca42b2, from git) send the same device commands, helper
  requests and operations in the same order and require the same 67 stages as the real run
  (tests/backup/evidence/focus-instances-20261127/litellm-instance-fullflow-07.json; its 68th, the outer isolation, is
  main()'s).
- --via-page (with a lease that says import_path page) replaces exactly the upload, check, conversion and import with the
  page's (through the REAL bridge, its page process simulated): the later outside write moves before the page, every page
  job is waited for and recorded in the receipt, the recovery cleans up what the page made and scans for the Cockpit
  password; everything else is unchanged.
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
import tempfile
import time
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BASE = 'a1ca42b2edecfaef99ea8d7a1db93e8acd0d59ac'
OLD_RUN_SHA = '4f82cfa011196e645ff78eee1b5eb2b0e324edf619e8ac9407fdbe3cc9a6d383'
PASSWORD = 'generated-cockpit-pass-3333'
HA_KEY = 'GENR-ATED-HAKE-YFOR-TEST-ONLY-ABCD'
NAME = 'woowbk_focus_litellm_0123456789ab'
NOW = 1800000000.0
sys.path.insert(0, str(HERE))


def load(name, path=None):
    spec = importlib.util.spec_from_file_location(name, path or HERE / 'focus_litellm_instance_acceptance_run.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def load_base():
    shown = subprocess.run(['git', '-C', str(REPO), 'show', f'{BASE}:tests/e2e/lab/focus_litellm_instance_acceptance_run.py'],
                           capture_output=True, timeout=60)
    if shown.returncode:
        return None
    assert hashlib.sha256(shown.stdout).hexdigest() == OLD_RUN_SHA
    spec = importlib.util.spec_from_loader('ll_base', loader=None)
    value = importlib.util.module_from_spec(spec)
    value.__file__ = str(HERE / 'focus_litellm_instance_acceptance_run.py')
    exec(compile(shown.stdout, value.__file__, 'exec'), value.__dict__)
    return value


def bridge_module():
    spec = importlib.util.spec_from_file_location('ll_test_bridge', HERE / 'focus_page_bridge.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


saved_real = load('ll_saved_real', HERE / 'litellm_full_flow.py')   # its check gate, expected shape and leak program
drv = saved_real.drv


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def answer(value=b'', returncode=0):
    data = value if isinstance(value, bytes) else (value if isinstance(value, str) else json.dumps(value)).encode()
    return SimpleNamespace(returncode=returncode, stdout=data, stderr=b'')


ENTRY = {'id': 'litellm', 'owner': 'appowner', 'adapter': 'quadlet-postgres', 'units': ['litellm-postgres.service',
                                                                                         'litellm.service'],
         'postgres': [{'id': 'main', 'container': 'litellm-postgres', 'unit': 'litellm-postgres.service',
                       'database': 'litellm', 'user': 'litellm', 'data_volume': 'litellm-pgdata'}]}
BEFORE = {'catalogs': {'emqx.json': 'c' * 64}, 'files': {}, 'volumes': {'emqx-data': 'v1'}, 'secrets': {}, 'containers': {},
          'external_containers': {}, 'networks': {}, 'running': [], 'units': {'litellm.service': {'ActiveState': 'inactive'}},
          'timer': {'UnitFileState': 'masked-runtime', 'ActiveState': 'inactive'}, 'package': None,
          'config_directory': None, 'images': ['a' * 64], 'image_refs': {}, 'active_jobs': []}


class Dev:
    """dev-d as the controller (and, with --via-page, the bridge) sees it, one LiteLLM case from install to recovery."""

    def __init__(self, m, fixture):
        self.m, self.plan, self.fixture = m, m.plan, fixture
        self.store_id = 'ha-' + sha(fixture)[:20]
        self.calls, self.jobs, self.ha, self.sequence = [], [], [], 0
        self.backups = {'20261127T080000Z-0000base': {'id': '20261127T080000Z-0000base', 'type': 'manual', 'apps': []}}
        self.catalog = None            # sha256 of the installed litellm.json, none at first
        self.pg_tag = False
        self.outside = self.late = False
        self.app_data = 'own'          # whose LiteLLM data is in the litellm database: the case's own ('own') or HA's ('ha')
        self.hook = self.hook_consumed = False
        self.taken = []
        self.converted = None
        self.bridge = None
        self.ops_source = None

    def log(self, *entry):
        self.calls.append(entry)

    def backup(self, kind, apps=('litellm',)):
        self.sequence += 1
        bid = '20261128T1000%02dZ-%08x' % (self.sequence, self.sequence)
        self.backups[bid] = {'id': bid, 'type': kind, 'apps': [{'id': a} for a in apps]}
        return bid

    def job(self, kind, params, state, result, unit=None, log=None):
        self.sequence += 1
        jid = 'j20261128T1100%02dZ-%08x' % (self.sequence, self.sequence)
        self.jobs.append({'id': jid, 'type': kind, 'state': state, 'phase': 'done', 'progress': {}, 'params': params,
                          'result': result, 'unit': unit or f'woowtech-backup-{jid}.service', 'log': log or []})
        return self.jobs[-1]

    # ---------------------------------------------------------------- what the controller reads back
    def inventory(self):
        value = copy.deepcopy(BEFORE)
        if self.catalog:
            value['catalogs']['litellm.json'] = self.catalog
        if self.pg_tag:
            value['image_refs'][self.plan.PG_TAG] = self.plan.PG
        return value

    def snapshot(self):
        names = ['litellm', 'postgres'] + ([NAME + '_outside'] if self.outside else [])
        databases = {n: {'digest': f'{n}-d', 'access': f'{n}-a', 'schema': f'{n}-s'} for n in names}
        databases['litellm']['digest'] = 'litellm-' + self.app_data
        if self.late:
            databases[NAME + '_outside']['digest'] += '-late'
        return {'database_names': names, 'databases': databases, 'roles': 'roles-late' if self.late else 'roles',
                'members': [], 'settings': [], 'metadata': [[n, 'postgres', 'UTF8', 'C', 'C', False, True, None] for n in names]}

    def manifest(self, backup_id):
        names = ['litellm', 'postgres'] + ([NAME + '_outside'] if self.outside else [])
        marked = backup_id == self.converted
        return {'scope': 'instance', 'ha_database': 'litellm' if marked else None, 'ha_access_valid': marked,
                'globals_present': True, 'roles_count': 4, 'digests': {'postgres-digest': 'x'},
                'databases': [[n, 'owner'] for n in names]}

    def operation(self, q):
        op = q['op']
        self.log('op', op, {k: v for k, v in q.items() if k not in ('op', 'case', 'password', 'bytes', 'program')})
        if op == 'inventory':
            return self.inventory()
        if op == 'init':
            return self.inventory()
        if op == 'hashes':
            lib = REPO / 'backup-engine/woowbackup'
            found = {str(p.relative_to(lib)): sha(p) for p in lib.rglob('*.py') if '__pycache__' not in p.parts}
            found['../woowtech-cockpit-backup'] = sha(REPO / 'backup-engine/woowtech-cockpit-backup')
            return found
        if op == 'catalog_bytes':
            return {'sha256': 'n' * 63 + str(len(self.taken) % 10), 'bytes': 'e30='}
        if op == 'snapshot':
            self.taken.append(q['tag'])
            return self.snapshot()
        if op == 'snapshot_restate':
            self.app_data = 'own'
            return self.snapshot()
        if op == 'receipt':
            return {'snapshots': {tag: True for tag in self.taken}, 'before': None}
        if op == 'fixture':
            if q['action'] == 'create':
                self.outside = True
            else:
                self.late = True
            return True
        if op == 'job_quiescent':
            return True
        if op == 'hook':
            self.hook = q['enable']
            return True
        if op == 'hook_consumed':
            return self.hook_consumed
        if op == 'cleanup_owned_package':
            self.outside = self.late = False
            return True
        if op == 'restore_catalog':
            self.catalog = None
            return True
        if op in ('claim_install', 'capture_installed', 'patch_package_pg', 'authorize_catalog'):
            return True
        raise AssertionError(('op', op))

    def root(self, *argv, input=None, timeout=180):
        request = json.loads(input) if input else {}
        if argv[:3] == ('python3', '-I', '-c'):
            script = argv[3]
            if script == self.ops_source:
                return answer(self.operation(request))
            if script == self.plan.ENDPOINT_PROBE:
                self.log('endpoint')
                return answer({'database': 'litellm', 'user': 'litellm', 'host': 'litellm-postgres', 'port': 5432})
            if script == self.plan.MANIFEST_PROBE:
                self.log('manifest', request['backup_id'])
                return answer(self.manifest(request['backup_id']))
            if 'memory.stat' in script and 'staging' in script:
                self.log('resources')
                return answer({'headroom': 2500 * 1024 ** 2, 'free': 100 << 30})
            if self.bridge is not None and script == self.bridge.PRECONDITIONS:
                self.log('precondition read')
                return answer({'page': {n: sha(REPO / 'backup' / n) for n in self.bridge.PAGE_FILES}, 'cockpit_socket': True,
                               'hostname': 'woowbk-dev-d', 'devadmin_uid': 1000, 'headroom': 2000 * 1024 ** 2})
            if self.bridge is not None and script == self.bridge.NATIVE_UNITS:
                rows = {job['id']: job for job in self.jobs}
                self.log('native units', tuple(request['ids']))
                return answer([{k: rows[j][k] for k in ('id', 'unit', 'type', 'state')} for j in request['ids']])
        if argv[:2] in (('systemctl', 'mask'), ('systemctl', 'unmask'), ('systemctl', 'start'), ('systemctl', 'stop')):
            self.log('root', argv[:2])
            return answer()
        raise AssertionError(('root', argv[:3]))

    def owner(self, *argv, input=None, timeout=180):
        self.log('owner', argv[:3])
        if argv[:3] == ('podman', 'image', 'inspect') and '{{.Digest}}' in argv:
            return answer('sha256:' + 'd' * 64 + '\n')
        if argv[:3] == ('podman', 'image', 'inspect'):
            ref = argv[-1]
            image = self.plan.PG if ref in (self.plan.PG_TAG, 'sha256:' + self.plan.PG) else self.plan.APP_BASE \
                if ref == 'sha256:' + self.plan.APP_BASE else 'f' * 64
            return answer(f'{image} amd64 linux\n')
        if argv[:2] == ('podman', 'tag'):
            self.pg_tag = True
            return answer()
        if argv[:2] == ('podman', 'untag'):
            self.pg_tag = False
            return answer()
        if argv[0] in ('mkdir', 'tar', 'env') or argv[:3] == ('systemctl', '--user', 'start'):
            return answer()
        raise AssertionError(('owner', argv))

    def helper(self, command, request=None, timeout=180):
        self.log('helper', command, {k: v for k, v in (request or {}).items() if k not in ('key', 'entry')})
        if command == 'list':
            return 0, {'ok': True, 'backups': [dict(b) for b in self.backups.values()],
                       'ha_backups': [dict(row) for row in self.ha]}
        if command == 'status':
            return 0, {'ok': True, 'active_job': None}
        if command == 'jobs':
            return 0, {'ok': True, 'jobs': [{k: v for k, v in job.items() if k not in ('unit', 'log')}
                                            for job in reversed(self.jobs)]}
        if command == 'job-status':
            job = next(job for job in self.jobs if job['id'] == request['job_id'])
            return 0, {'ok': True, 'job': {k: v for k, v in job.items() if k not in ('unit', 'log')}, 'log': job['log']}
        if command == 'catalog-suggest':
            return 0, {'ok': True, 'apps': [{'id': 'litellm', 'entry': copy.deepcopy(ENTRY)}]}
        if command == 'catalog-install':
            if request.get('confirm'):
                self.catalog = 'n' * 63 + str((len(self.taken)) % 10)
                return 0, {'ok': True}
            return 0, {'ok': True, 'valid': True, 'expected_sha256': self.catalog, 'new_sha256': 'n' * 63 + str(len(self.taken) % 10)}
        if command == 'key-init':
            return 0, {'ok': True, 'key': {'key_id': 'k-1'}}
        if command == 'delete':
            return (0, {'ok': True}) if self.backups.pop(request['backup_id'], None) else (1, {'ok': False})
        if command == 'ha-delete':
            before = len(self.ha)
            self.ha = [row for row in self.ha if row['id'] != request['ha_backup_id']]
            return (0, {'ok': True}) if len(self.ha) < before else (1, {'ok': False})
        if command in ('backup-start', 'ha-check-start', 'ha-convert-start', 'restore-start'):
            return 0, {'ok': True, 'job_id': self.start(command, request)['id']}
        raise AssertionError(('helper', command))

    def start(self, command, request):
        if command == 'backup-start':
            return self.job('backup', {'apps': ['litellm']}, 'succeeded', {'backup_id': self.backup('manual')})
        if command == 'ha-check-start':
            return self.job('verify', {'source': 'ha', 'ha_backup_id': request['ha_backup_id'], 'apps': ['litellm'],
                                       'key_provided': True}, 'succeeded', self.check_result(request['ha_backup_id']))
        if command == 'ha-convert-start':
            self.converted = self.backup('manual')
            return self.job('backup', {'source': 'ha', 'ha_backup_id': request['ha_backup_id'], 'apps': ['litellm']},
                            'succeeded', {'backup_id': self.converted})
        return self.restore(request['backup_id'])

    def restore(self, backup_id, unit=None, ha_id=None):
        safety = self.backup('safety')
        if backup_id == self.converted and self.hook:
            self.hook_consumed = True
            return self.job('restore', {'backup_id': backup_id, 'apps': ['litellm']}, 'rolled-back',
                            {'rolled_back': True, 'safety_backup_id': safety},
                            log=['資料摘要 db-main 與備份時一致'])
        self.app_data = 'ha' if backup_id == self.converted else 'own'
        params = {'backup_id': backup_id, 'apps': ['litellm'], **({'ha_backup_id': ha_id} if ha_id else {})}
        return self.job('restore', params, 'succeeded',
                        {'rolled_back': False, 'safety_backup_id': safety, 'health': [{'status': 'ok'}],
                         'verification': [{'checks': [{'match': True}]}]}, unit=unit)

    def check_result(self, ha_id):
        return {'ha_check': {'schema': 2, 'ha_backup_id': ha_id, 'shared': [], 'apps': [{
            'app_id': 'litellm', 'ok': True, 'importable': True, 'blockers': [], 'warnings': [],
            'issues': [{'id': 'litellm.keys', 'level': 'notice', 'message': 'keys stay', 'items': [], 'more': 0}],
            'litellm': dict(saved_real.EXPECTED)}]}}

    def upload(self, path, *, ev):
        self.log('upload', Path(path).name)
        self.ha.append({'id': self.store_id, 'sha256': sha(path)})
        return 0, {'ha_backup': {'id': self.store_id}}

    def device_python(self, script, request=None, *, as_owner=True, timeout=600):
        if script == self.plan.API_WITNESS:
            self.log('witness', request['action'])
            return {'status': 200, 'success': True, 'found': True}
        if script == saved_real.LEAKS:
            self.log('leaks', sorted(request['secrets']), request['podman_secrets'])
            return {'scanned': 30, 'journal_bytes': 4096, 'names': len(request['secrets']), 'hits': 0}
        raise AssertionError(('device_python', script[:40]))

    # ---------------------------------------------------------------- the real page's effects (--via-page)
    def page(self, config, seconds, device):
        self.log('page', device, tuple(config['apps']), seconds <= 20 * 60, config.get('key') == HA_KEY,
                 config.get('choices'), config['password'] == PASSWORD)
        if not any(row['id'] == self.store_id for row in self.ha):
            self.ha.append({'id': self.store_id, 'sha256': sha(config['fixture'])})
        self.job('verify', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['litellm'], 'key_provided': True},
                 'succeeded', self.check_result(config['ha_id']))
        self.converted = self.backup('manual')
        first = self.job('backup', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['litellm'], 'odoo_database': None,
                                    'test_mode': False, 'encrypt': True, 'key_provided': True,
                                    'group': {'kind': 'ha-import', 'step': 'convert', 'index': 0, 'count': 1},
                                    'chain': {'apps': ['litellm'], 'test_mode': False, 'then_restore': True, 'encrypt': True,
                                              'key_provided': True, 'acknowledged': {}, 'choices': {}}},
                         'succeeded', {'backup_id': self.converted, 'group': {'next_job_id': None, 'results': []}})
        second = self.restore(self.converted, unit=first['unit'], ha_id=config['ha_id'])
        second['result']['group'] = {'next_job_id': None, 'results': [{'app_id': 'litellm', 'status': 'imported'}]}
        first['result']['group']['next_job_id'] = second['id']
        texts = config['texts']
        names = ['UI real administrative Cockpit bridge reaches this device', texts['upload'], texts['select'],
                 'UI selects each choice the run named, only from what the check offers',
                 'UI actual check confirmation keys observed including valid zero', texts['view'], texts['lines'],
                 'UI has exactly one acknowledgement and import waits for it',
                 'UI check did not start an import or separate restore', 'UI real key field removed before screenshot',
                 'UI one acknowledgement enables import', texts['result'], texts['intent'], texts['keys'],
                 'UI the check and import requests carry exactly the chosen choices',
                 'UI no page script errors during this page flow', 'UI cookie observation completed without gaps',
                 'UI every issued credential absent from records journal and private evidence; proved public markers '
                 'counted separately']
        Path(config['result']).write_text(json.dumps({
            'stage': 'issued-value-scan', 'failure_kind': None, 'completed': True, 'issued_values_scanned': True,
            'checks': [{'check': n, 'ok': True} for n in names],
            'confirmations': {'expected_keys': {}, 'sent_keys': {}, 'lines_expected': 0, 'lines_shown': 0,
                              'check_importable': ['litellm']},
            'issued_scan_counts': {'scan_completed': True, 'observed_values': 2, 'observations_complete': True,
                                   'credential_device_hits': 0, 'credential_host_hits': 0, 'device_files': 30,
                                   'host_files': 3, 'archive_index_sidecars': 4, 'regular_json_roots': 2},
            'wire': {'import_starts': 1},
            'choices': {'named': {}, 'database': None, 'picks': {}, 'import_choices': {}, 'check_choices': {},
                        'rechecks': 0, 'problems': []},
            'requests': {'check': [{'key': True, 'choices': None}], 'import': {'key': True, 'choices': None}}}))
        return {'started': True, 'exit': 0, 'timed_out': False, 'interrupted': False, 'stop': 'exited',
                'relay_clean': True, 'relay_error': None, 'children_left': []}


class FakeEv:
    def __init__(self, secrets, area):
        self.secrets, self.results = secrets, []
        self.dir = Path(tempfile.mkdtemp(dir=os.environ['LL_PILOT_ROOT'])) / 'evidence'
        self.dir.mkdir(mode=0o700)

    def check(self, name, ok, detail=''):
        self.results.append({'check': name, 'ok': bool(ok)})
        return bool(ok)

    def save(self, name, value):
        path = self.dir / name
        path.write_text(self.secrets.redact(value if isinstance(value, str) else json.dumps(value)))


class FakeRun:
    """The saved 80-check flow's Run as the controller uses it: its readers, the seed probe and the app assertions."""

    def __init__(self, args, ev):
        self.args, self.ev, self.before = args, ev, None
        self.dev = None

    def load_secrets(self):
        for name, value in (('OWN_LITELLM_KEY', 'sk-generated-own-key-0001'), ('OWN_SEED_CREDENTIAL', 'generated-seed-0002'),
                            ('WRONG_SALT', 'generated-wrong-salt-0003')):
            self.args.secrets.register(name, value)
        self.own_key = self.args.secrets['OWN_LITELLM_KEY']

    def probe(self, label, **kwargs):
        return {'seed': {'credential': 200, 'model': 200, 'key': 200, 'key_echo_matches': True}}

    def step_before(self):
        self.before = {'models': 24}
        self.ev.check('before: own models', True)

    def verify(self, label):
        self.ev.check(f'{label}: HA data', DEVICES[-1].app_data == 'ha')

    def step_restart(self):
        self.ev.check('restart: HA data again', DEVICES[-1].app_data == 'ha')

    def own_state(self, label):
        self.ev.check(f'{label}: own data', DEVICES[-1].app_data == 'own')

    def step_leaks(self):
        names = sorted(n for n in self.args.secrets.values if n.startswith(('HA_BACKUP_KEY', 'OWN_', 'WRONG_SALT')))
        DEVICES[-1].log('saved80 leaks', names)
        self.ev.check('leaks: zero', True)


DEVICES = []
SECRET_FILES = {'b1-creds.env': f'HA_BACKUP_KEY={HA_KEY}\nLITELLM_TEST_VKEY=sk-generated-test-vkey-0004\n',
                'ha-import-creds.env': 'GENERATED_OTHER=generated-other-0005\n', 'dev-d-markers.json': '{}',
                'devadmin.pass': PASSWORD + '\n'}


def lease(plan, *, page=False, fixture_sha):
    value = {'granted': True, 'case': 'litellm-instance-original', 'device': plan.DEVICE, 'phases': list(plan.PHASES),
             'driver_commit': 'a' * 40, 'source_commit': plan.FROZEN_PRODUCT, 'name': NAME, 'fixture_sha256': fixture_sha,
             'derivation_sha256': plan.DERIVATION_SHA, 'package_commit': plan.PACKAGE_COMMIT,
             'baseline_sha256': hashlib.sha256(json.dumps(BEFORE, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
             'baseline_policy': 'require-litellm-absent', 'image_policy': 'retain-for-case',
             'expires_utc': datetime.fromtimestamp(NOW + 3600, timezone.utc).isoformat()}
    if page:
        value['import_path'] = 'page'
    return value


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        self.now += 0.01
        return self.now


def simulate(m, *, via_page=False, bridge=None, page=None):
    root = Path(tempfile.mkdtemp()).resolve()
    os.environ['LL_PILOT_ROOT'] = str(root)
    try:
        secrets_dir = root / 'secrets'
        secrets_dir.mkdir()
        for name, text in SECRET_FILES.items():
            (secrets_dir / name).write_text(text)
        fixture = root / 'woow-litellm-x86-enc-20261123.tar'
        fixture.write_bytes(b'generated stand-in for the encrypted LiteLLM HA backup ' * 64)
        lock = root / 'woowbk-dev-d-mutation.lock'
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # main()'s own hold of the dev-d lock (saved.acquire)
        dev = Dev(m, fixture)
        dev.bridge = bridge
        DEVICES.append(dev)
        transport = SimpleNamespace(root=dev.root, owner=dev.owner, helper=dev.helper, upload=dev.upload,
                                    device_python=dev.device_python, scan_host_evidence=drv.scan_host_evidence,
                                    Secrets=drv.Secrets, SECRET_DIR=secrets_dir)
        saved = SimpleNamespace(drv=transport, Ev=FakeEv, Run=FakeRun, FIXTURE=fixture, EXPECTED=saved_real.EXPECTED,
                                require_reviewed_check=saved_real.require_reviewed_check, LEAKS=saved_real.LEAKS, LOCK=lock,
                                PACKAGE=root / 'Woow_podman_litellm', fresh_draft_problems=lambda draft: [])
        receipt = root / 'receipt.json'
        receipt.write_text(json.dumps({'name': NAME, 'device': m.plan.DEVICE, 'version': 1, 'pending': None, 'jobs': {},
                                       'created_backups': [], 'full_safety': None, 'safety_verified': False,
                                       'catalog_intent': False, 'timer_intent': False, 'install_intent': False,
                                       'hook_intent': False, 'recovery_verified': False, 'complete': False,
                                       'images_ready': True, 'derived_image': 'f' * 64}))
        receipt.chmod(0o600)
        real_check_output = subprocess.check_output

        def check_output(argv, *args, **kwargs):
            if argv[:2] == ['git', '-C'] and 'archive' in argv:
                return b'package tar bytes'
            return real_check_output(argv, *args, **kwargs)
        with contextlib.ExitStack() as stack:
            for target, name, value in (
                    (m.plan, 'FIXTURE_SHA', sha(fixture)), (m, 'git', lambda path, *args: m.plan.PACKAGE_COMMIT),
                    (subprocess, 'check_output', check_output), (m, 'Path', HostPath),
                    (os, 'statvfs', lambda _path: SimpleNamespace(f_bavail=(200 << 30) // 4096, f_frsize=4096))):
                stack.enter_context(patch.object(target, name, value))
            if bridge is not None:
                for name, value in (('run_page', page or dev.page), ('host_available_kib', lambda: 6 * 1024 * 1024),
                                    ('PLAYWRIGHT', fixture), ('CHROMIUM', fixture)):
                    stack.enter_context(patch.object(bridge, name, value))
                stack.enter_context(patch.object(m, 'load_bridge', lambda: bridge))
            args = SimpleNamespace(phase='flow', source=str(REPO), receipt=receipt, **({'via_page': True} if via_page else {}))
            value = lease(m.plan, page=via_page, fixture_sha=sha(fixture))
            m.validate_lease(value, 'flow', now=NOW, driver_commit='a' * 40, source_commit=m.plan.FROZEN_PRODUCT,
                             **({'via_page': True} if via_page else {}))
            controller = m.Controller(args, value, saved, clock=Clock(), sleep=lambda _s: None)
            dev.ops_source = controller.ops_source
            failure = None
            with contextlib.redirect_stdout(io.StringIO()) as out:
                try:
                    controller.flow()
                except Exception as error:   # noqa: BLE001 - the simulation reports how the flow ended
                    failure = error
            evidence = controller.run.ev.dir if controller.run else None
            files = {str(p.relative_to(evidence)): p.read_bytes() for p in evidence.rglob('*') if p.is_file()} if evidence else {}
            return SimpleNamespace(failure=failure, results=controller.results, r=json.loads(receipt.read_text()),
                                   calls=dev.calls, dev=dev, files=files, stdout=out.getvalue(),
                                   app_results=controller.run.ev.results if controller.run else [])
    finally:
        os.close(fd)
        shutil.rmtree(root, ignore_errors=True)


class HostPath(type(Path())):
    """The controller's Path with this host's memory answer fixed (resources() reads /proc/meminfo itself)."""

    def read_text(self, *args, **kwargs):
        if str(self) == '/proc/meminfo':
            return 'MemTotal: 16000000 kB\nMemAvailable:    6291456 kB\n'
        return super().read_text(*args, **kwargs)


REAL = json.loads((REPO / 'tests/backup/evidence/focus-instances-20261127/litellm-instance-fullflow-07.json').read_text())
REAL_STAGES = [row['check'] for row in REAL['checks']][:-1]   # without main()'s outer isolation
IMPORT = REAL_STAGES[34:46]                                    # upload 2, check 4, conversion 3, import 3


class DefaultFlowTests(unittest.TestCase):
    def test_the_simulated_default_flow_requires_the_real_runs_stages_and_equals_the_base_call_for_call(self):
        after = simulate(load('ll_new'))
        self.assertIsNone(after.failure, after.failure)
        self.assertEqual(len(REAL_STAGES), 67)
        self.assertEqual([r['check'] for r in after.results], REAL_STAGES)
        self.assertTrue(all(r['ok'] for r in after.results))
        self.assertTrue(after.r['complete'] and after.r['recovery_verified'] and after.r['flow_verified'])
        self.assertEqual(sorted(after.dev.backups), ['20261127T080000Z-0000base'])   # every case backup deleted
        self.assertEqual(after.dev.ha, [])
        self.assertFalse(any(call[0] == 'page' for call in after.calls))
        self.assertNotIn('COCKPIT_PASSWORD', json.dumps(after.r))
        base = load_base()
        if base is None:
            self.skipTest(f'base commit {BASE} is not in this checkout')
        before = simulate(base)
        self.assertEqual(after.calls, before.calls)
        self.assertEqual(after.results, before.results)
        self.assertEqual({k: v for k, v in after.r.items() if k not in ('generated_credentials',)},
                         {k: v for k, v in before.r.items() if k not in ('generated_credentials',)})


def page_block(texts):
    browser = ['UI real administrative Cockpit bridge reaches this device', texts['upload'], texts['select'],
               'UI selects each choice the run named, only from what the check offers',
               'UI actual check confirmation keys observed including valid zero', texts['view'], texts['lines'],
               'UI has exactly one acknowledgement and import waits for it', 'UI check did not start an import or separate restore',
               'UI real key field removed before screenshot', 'UI one acknowledgement enables import', texts['result'],
               texts['intent'], texts['keys'], 'UI the check and import requests carry exactly the chosen choices',
               'UI no page script errors during this page flow', 'UI cookie observation completed without gaps',
               'UI every issued credential absent from records journal and private evidence; proved public markers counted '
               'separately']
    return (['original_fixture_sha256', 'actual_installed_proxy_reader', 'owned_catalog_before_job']
            + ['page: ' + name for name in browser]
            + ['page_bounded_browser_closed_relay_reaped', 'page_uploaded_record_is_the_fixture',
               'page_own_jobs_only_none_running_no_other_backup', 'page_check_litellm_importable_nothing_stopped_lines_keyed',
               'page_every_listed_key_acknowledged_exactly_once', 'page_conversion_and_restore_linked_in_one_unit',
               'page_nothing_to_choose', 'page_issued_cookie_values_absent', 'original_check_succeeded',
               'original_fixture_shape', 'actual_installed_proxy_reader', 'instance_conversion_succeeded',
               'actual_complete_instance_manifest', 'selective_instance_import'])


class ViaPageFlowTests(unittest.TestCase):
    def test_via_page_replaces_only_the_import_stages_through_the_real_bridge(self):
        m, bridge = load('ll_page'), bridge_module()
        default = simulate(m)
        run = simulate(m, via_page=True, bridge=bridge)
        self.assertIsNone(run.failure, (run.failure, [r for r in run.results if not r['ok']]))
        names, old = [r['check'] for r in run.results], [r['check'] for r in default.results]
        block = page_block(bridge.page_settings(['litellm'], ['litellm'], [])['texts'])
        self.assertEqual(names[:34], old[:34])
        self.assertEqual(names[34:34 + len(block)], block)
        tail = old[46:]
        leaks = tail.index('saved80_step_leaks') + 1
        self.assertEqual(names[34 + len(block):], tail[:leaks] + ['page_cockpit_password_absent'] + tail[leaks:])
        self.assertEqual((len(old), len(IMPORT), len(block), len(names)), (67, 12, 35, 91))
        self.assertTrue(all(r['ok'] for r in run.results))
        kinds = [call[0] for call in run.calls]
        self.assertEqual(kinds.count('page'), 1)
        self.assertNotIn('upload', kinds)
        starts = [call[1] for call in run.calls if call[0] == 'helper' and call[1].endswith('-start')]
        self.assertEqual(starts, ['backup-start', 'restore-start', 'restore-start'])   # safety, forced failure, recovery
        [page] = [call for call in run.calls if call[0] == 'page']
        self.assertEqual(page, ('page', 'woowbk-dev-d', ('litellm',), True, True, {}, True))
        # The later outside write and its snapshot came before the page; the page's jobs are this case's own.
        late = run.calls.index(('op', 'fixture', {'action': 'late'}))
        self.assertLess(late, run.calls.index(page))
        page_jobs = [job['id'] for job in run.dev.jobs if job['type'] in ('verify', 'backup', 'restore')
                     and job['params'].get('ha_backup_id')]
        self.assertTrue(set(page_jobs) <= set(run.r['jobs']))
        self.assertEqual(run.r['converted'], run.dev.converted)
        self.assertEqual(run.r['store_id'], run.dev.store_id)
        self.assertTrue(run.r['page']['passed'])
        self.assertEqual(run.r['page_password_scan'], {'device_hits': 0, 'scanned': 30, 'host_hits': 0})
        self.assertTrue(run.r['complete'] and run.r['recovery_verified'] and run.r['flow_verified'])
        self.assertEqual(sorted(run.dev.backups), ['20261127T080000Z-0000base'])
        self.assertEqual(run.dev.ha, [])
        self.assertNotIn(PASSWORD, json.dumps(run.r))
        self.assertNotIn(PASSWORD, run.stdout)
        for name, data in run.files.items():
            self.assertNotIn(PASSWORD.encode(), data, name)
            self.assertNotIn(HA_KEY.encode(), data, name)

    def test_a_failed_page_gate_still_recovers_and_owns_what_the_page_made(self):
        m, bridge = load('ll_page_gate'), bridge_module()
        dev_page = Dev.page

        def unscanned(dev, config, seconds, device):
            outcome = dev_page(dev, config, seconds, device)
            value = json.loads(Path(config['result']).read_text())
            value['issued_scan_counts']['scan_completed'] = False
            Path(config['result']).write_text(json.dumps(value))
            return outcome
        run = simulate(m, via_page=True, bridge=bridge, page=lambda *a: unscanned(DEVICES[-1], *a))
        self.assertIsInstance(run.failure, RuntimeError)
        self.assertEqual([r for r in run.results if not r['ok']], [{'check': 'page_issued_cookie_values_absent', 'ok': False}])
        self.assertTrue(run.r['complete'] and run.r['recovery_verified'])
        self.assertFalse(run.r.get('flow_verified', False))
        self.assertEqual(sorted(run.dev.backups), ['20261127T080000Z-0000base'])   # the page's backups were the case's
        self.assertEqual(run.dev.ha, [])
        self.assertIn('page_cockpit_password_absent', [r['check'] for r in run.results])

    def test_the_bridges_wait_ends_at_the_terminal_state_and_recovery_waits_for_the_busy_unit(self):
        """The chain runs in its first job's unit: the conversion is terminal while that unit still runs the restore. The
        bridge's wait (page_wait) returns at the terminal state and owns the backup at once; adopting the page then waits
        for every unit to be quiet with the chain's first job as the receipt's pending job (recovery would settle it)."""
        m = load('ll_waits')
        first, second = 'j20261128T120000Z-0000aaa1', 'j20261128T120001Z-0000aaa2'
        converted, safety = '20261128T120000Z-0b0b0b01', '20261128T120001Z-0c0c0c01'
        root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, root, True)
        path = root / 'receipt.json'
        seen = {'polls': 0, 'pending_while_busy': []}
        jobs = {first: {'id': first, 'type': 'backup', 'state': 'succeeded', 'result': {
                    'backup_id': converted, 'group': {'next_job_id': second}}},
                second: {'id': second, 'type': 'restore', 'state': 'running', 'result': {}}}

        class Transport:
            def helper(self, command, request, **_kwargs):
                if command == 'job-status':
                    return 0, {'ok': True, 'job': copy.deepcopy(jobs[request['job_id']])}
                if command == 'list':
                    return 0, {'ok': True, 'backups': [], 'ha_backups': []}
                raise AssertionError(command)

            def root(self, *_args, input, **_kwargs):
                q = json.loads(input)
                assert q['op'] == 'job_quiescent', q['op']
                seen['polls'] += 1
                seen['pending_while_busy'].append(json.loads(path.read_text())['pending'])
                if seen['polls'] == 3:   # the restore ends: the first job's unit goes quiet
                    jobs[second].update(state='succeeded', result={'safety_backup_id': safety,
                                                                   'group': {'next_job_id': None, 'results': []}})
                return SimpleNamespace(returncode=0, stdout=json.dumps(seen['polls'] >= 3).encode())
        c = m.Controller(SimpleNamespace(receipt=path, source='unused'), lease(m.plan, fixture_sha=m.plan.FIXTURE_SHA),
                         SimpleNamespace(drv=Transport()), clock=Clock(), sleep=lambda _s: None)
        c.r['before_backups'] = []
        with contextlib.redirect_stdout(io.StringIO()):
            job = c.page_wait(first, 600)
            self.assertEqual((job['state'], seen['polls'], c.r['created_backups']), ('succeeded', 0, [converted]))
            with self.assertRaisesRegex(TimeoutError, 'still running'):
                c.page_wait(second, 0.05)   # bounded by the bridge's own timeout
            c.adopt_page({'phase': 'judged', 'root_job_id': first, 'check_job_id': None})
        self.assertEqual(seen['pending_while_busy'][0], {'command': 'page', 'request_id': 'page', 'tag': 'page',
                                                         'job_id': first})
        self.assertIsNone(c.r['pending'])
        self.assertEqual(c.r['created_backups'], [converted, safety])
        self.assertEqual(c.r['converted'], converted)
        self.assertEqual(set(c.r['jobs']), {first, second})
        self.assertNotIn('store_id', c.r)   # nothing listed: no upload of the page's to remove

    def test_the_lease_must_name_the_page_import_exactly_when_via_page_is_given(self):
        m = load('ll_lease')
        plan = m.plan
        for via_page, page in ((False, True), (True, False)):
            with self.subTest(via_page=via_page), self.assertRaisesRegex(ValueError, 'import_path'):
                m.validate_lease(lease(plan, page=page, fixture_sha=plan.FIXTURE_SHA), 'flow', now=NOW,
                                 driver_commit='a' * 40, source_commit=plan.FROZEN_PRODUCT,
                                 **({'via_page': True} if via_page else {}))
        m.validate_lease(lease(plan, fixture_sha=plan.FIXTURE_SHA), 'flow', now=NOW, driver_commit='a' * 40,
                         source_commit=plan.FROZEN_PRODUCT)
        m.validate_lease(lease(plan, page=True, fixture_sha=plan.FIXTURE_SHA), 'flow', now=NOW, driver_commit='a' * 40,
                         source_commit=plan.FROZEN_PRODUCT, via_page=True)
        help_text = subprocess.run([sys.executable, '-B', str(HERE / 'focus_litellm_instance_acceptance_run.py'), '--help'],
                                   capture_output=True, text=True, timeout=60).stdout
        self.assertIn('--via-page', help_text)


if __name__ == '__main__':
    unittest.main()
