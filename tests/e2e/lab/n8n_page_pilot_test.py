"""Offline: focus_acceptance_n8n.py (the saved n8n application flow: the historical 34 checks of 2026-11-26 plus the
three preflight checks the promoted driver added, 37) with and without --via-page against a simulated dev-c (no device,
no labpodman, no browser, no real secret; every lab path points into a temporary folder).

- The default run of this checkout and of the reviewed base (a1ca42b2, from git) send the same device calls in the same
  order and produce the same 37 checks.
- --via-page replaces exactly the upload, check and one-action import with the page's (through the REAL bridge, whose
  page process is simulated), passes the bridge the right device, lock, key and product source, cleans up what the page
  made and leaves every later check unchanged; --source points the engine and page checks at another product checkout.
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
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BASE = 'a1ca42b2edecfaef99ea8d7a1db93e8acd0d59ac'
OLD_DRIVER_SHA = '0ce256cdabe52dc4d2fab08045e74c3c4459321001a207c3f52358ce428e35b9'
HA_KEY = 'GENR-ATED-HAKE-YFOR-TEST-ONLY-ABCD'
PASSWORD = 'generated-cockpit-pass-3333'
VALUES = {'HA_BACKUP_KEY': HA_KEY, 'ODOO_ADMIN_PW': 'generated-odoo-admin-1', 'ODOO_PROBE_PW': 'generated-odoo-probe-2',
          'N8N_OWNER_PW': 'generated-n8n-owner-3', 'ODOO_MASTER_PW': 'generated-odoo-master-4',
          'ODOO_DB_PW': 'generated-odoo-db-5'}
CREDENTIAL_VALUE = 'generated-credential-value-6'
sys.path.insert(0, str(HERE))
import ha_import_e2e as h   # noqa: E402 - the module the driver imports by name: patched here, used there


def load_new(name='n8n_new'):
    spec = importlib.util.spec_from_file_location(name, HERE / 'focus_acceptance_n8n.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def load_base():
    shown = subprocess.run(['git', '-C', str(REPO), 'show', f'{BASE}:tests/e2e/lab/focus_acceptance_n8n.py'],
                           capture_output=True, timeout=60)
    if shown.returncode:
        return None
    assert hashlib.sha256(shown.stdout).hexdigest() == OLD_DRIVER_SHA
    spec = importlib.util.spec_from_loader('n8n_base', loader=None)
    value = importlib.util.module_from_spec(spec)
    value.__file__ = str(HERE / 'focus_acceptance_n8n.py')
    exec(compile(shown.stdout, value.__file__, 'exec'), value.__dict__)
    return value


def bridge_module():
    spec = importlib.util.spec_from_file_location('n8n_test_bridge', HERE / 'focus_page_bridge.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class HostPath(type(Path())):
    """The driver's Path with this host's memory answer fixed (the flow reads /proc/meminfo itself)."""

    def read_text(self, *args, **kwargs):
        if str(self) == '/proc/meminfo':
            return 'MemTotal: 16000000 kB\nMemAvailable:    6291456 kB\n'
        return super().read_text(*args, **kwargs)


def answer(stdout=b'', returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=stdout if isinstance(stdout, bytes) else stdout.encode(), stderr=b'')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def engine(product):
    lib = Path(product) / 'backup-engine/woowbackup'
    return {'lib': {str(p.relative_to(lib)): sha(p) for p in lib.rglob('*.py') if '__pycache__' not in p.parts},
            'helper': sha(Path(product) / 'backup-engine/woowtech-cockpit-backup')}


class Dev:
    """dev-c as the saved n8n flow (and, with --via-page, the bridge) sees it: n8n running at its baseline."""

    def __init__(self, fixture_sha, baseline, product=REPO):
        self.store_id = 'ha-' + fixture_sha[:20]
        self.fixture_sha, self.baseline, self.product = fixture_sha, baseline, product
        self.calls, self.jobs, self.ha, self.sequence = [], [], [], 0
        self.backups = {baseline: {'id': baseline, 'type': 'manual'}}
        self.data = 'baseline'          # whose n8n data is live: the lab baseline, or HA's ('ha')
        self.bridge = None
        self.programs = {}

    def log(self, *entry):
        self.calls.append(entry)

    @staticmethod
    def quiet(request):
        """A request without its time-made request id (both drivers make one per run)."""
        return {k: ('<id>' if k == 'request_id' else v) for k, v in (request or {}).items()} if isinstance(request, dict) else request

    def backup(self, kind):
        self.sequence += 1
        bid = '20261128T1000%02dZ-%08x' % (self.sequence, self.sequence)
        self.backups[bid] = {'id': bid, 'type': kind}
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

    def check_result(self, ha_id):
        return {'ha_check': {'schema': 2, 'ha_backup_id': ha_id, 'shared': [], 'apps': [{
            'app_id': 'n8n', 'ok': True, 'importable': True, 'blockers': [], 'warnings': [], 'issues': [],
            'n8n': {'workflows': 3, 'credentials': 1, 'executions': 4}}]}}

    def chain(self, ha_id, unit_shared=False, key_provided=True):
        """The one-action import's two linked jobs: n8n's conversion, then the restore of that backup."""
        converted = self.backup('manual')
        first = self.job('backup', {'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['n8n'], 'odoo_database': None,
                                    'test_mode': False, 'encrypt': True, 'key_provided': key_provided,
                                    'group': {'kind': 'ha-import', 'step': 'convert', 'index': 0, 'count': 1},
                                    'chain': {'apps': ['n8n'], 'test_mode': False, 'then_restore': True, 'encrypt': True,
                                              'key_provided': key_provided, 'acknowledged': {}, 'choices': {}}},
                         'succeeded', {'backup_id': converted, 'group': {'next_job_id': None, 'results': []}})
        self.data = 'ha'
        second = self.job('restore', {'backup_id': converted, 'apps': ['n8n'], 'ha_backup_id': ha_id}, 'succeeded',
                          {'rolled_back': False, 'safety_backup_id': self.backup('safety'), 'health': [{'status': 'ok'}],
                           'group': {'next_job_id': None, 'results': [{'app_id': 'n8n', 'status': 'imported'}]}},
                          unit=first['unit'] if unit_shared else None)
        first['result']['group']['next_job_id'] = second['id']
        return first, second

    # ---------------------------------------------------------------- ha_import_e2e's device calls
    def root(self, *argv, input=None, timeout=600, check=False):
        program = argv[3] if argv[:3] == ('python3', '-I', '-c') else None
        name = self.programs.get(program)
        self.log('root', name or argv[:3], None if name == 'LEAK_SCAN' else (json.loads(input) if input else None))
        if name == 'HEADROOM':
            return answer(str(2 * 1024 ** 3) + '\n')
        if name == 'ENGINE_HASHES':
            return answer(json.dumps(engine(self.product)) + '\n')
        if name == 'LEAK_SCAN':
            return answer(json.dumps({'scanned': 20, 'journal_bytes': 4096, 'hits': {}}) + '\n')
        if name == 'PRECONDITIONS':
            return answer(json.dumps({'page': {n: sha(self.product / 'backup' / n) for n in self.bridge.PAGE_FILES},
                                      'cockpit_socket': True, 'hostname': 'woowbk-dev-c', 'devadmin_uid': 1000,
                                      'headroom': 2000 * 1024 ** 2}) + '\n')
        if name == 'NATIVE_UNITS':
            rows = {job['id']: job for job in self.jobs}
            return answer(json.dumps([{k: rows[j][k] for k in ('id', 'unit', 'type', 'state')}
                                      for j in json.loads(input)['ids']]) + '\n')
        if argv[:2] == ('ls', '-A') or argv[:2] == ('sh', '-c'):
            return answer('')
        raise AssertionError(('root', argv[:3]))

    def owner(self, *argv, input=None, timeout=600, check=False):
        self.log('owner', argv[:3])
        if argv[0] == 'podman' and argv[1] in ('ps', 'volume', 'network'):
            return answer('')
        raise AssertionError(('owner', argv))

    def ok(self, command, request=None, *, ev, timeout=1800):
        self.log('ok', command, self.quiet(request))
        if command == 'inspect':
            return {'ok': True, 'preflight': {'ok': True, 'checks': [], 'apps': [{'id': 'n8n'}]}}
        if command == 'list':
            return {'backups': [dict(row) for row in self.backups.values()], 'ha_backups': [dict(row) for row in self.ha]}
        if command == 'status':
            return {'active_job': None}
        if command == 'jobs':
            return {'jobs': [self.public(job) for job in reversed(self.jobs)]}
        if command == 'ha-import-start':
            first, _second = self.chain(request['ha_backup_id'])
            return {'job_id': first['id'], 'group': {'id': 'g1'}}
        raise AssertionError(('ok', command))

    def helper(self, command, request=None, *, timeout=1800):
        self.log('helper', command, self.quiet(request))
        if command == 'delete':
            return (0, {}) if self.backups.pop(request['backup_id'], None) else (1, {'error': 'not-found'})
        if command == 'ha-delete':
            before = len(self.ha)
            self.ha = [row for row in self.ha if row['id'] != request['ha_backup_id']]
            return (0, {}) if len(self.ha) < before else (1, {'error': 'not-found'})
        raise AssertionError(('helper', command))

    def upload(self, path, *, ev):
        self.log('upload', Path(path).name)
        if not any(row['id'] == self.store_id for row in self.ha):
            self.ha.append({'id': self.store_id, 'sha256': self.fixture_sha})
        return 0, {'ha_backup': {'id': self.store_id}}

    def run_check(self, ha, apps, *, ev, key=None, tag='check'):
        self.log('run_check', ha, tuple(apps), key == HA_KEY, tag)
        return self.public(self.job('verify', {'source': 'ha', 'ha_backup_id': ha, 'apps': list(apps), 'key_provided': True},
                                    'succeeded', self.check_result(ha)))

    def wait_job(self, job_id, *, ev, timeout=3600):
        self.log('wait_job', job_id, timeout)
        return self.public(next(job for job in self.jobs if job['id'] == job_id))

    def restore(self, backup_id, apps, *, ev, tag):
        self.log('restore', backup_id, tuple(apps), tag)
        self.data = 'baseline' if backup_id == self.baseline else self.data
        job = self.job('restore', {'backup_id': backup_id, 'apps': list(apps)}, 'succeeded',
                       {'rolled_back': False, 'safety_backup_id': self.backup('safety'), 'health': [{'status': 'ok'}]})
        return self.public(job), 5.0

    def psql(self, container, user, database, sql):
        self.log('psql', container, database, hashlib.sha256(sql.encode()).hexdigest()[:12])
        if 'woowbk.lab.baseline.before' in sql:
            return '1|0|0' if self.data == 'baseline' else '0|0|3'
        if 'FROM workflow_entity ORDER BY name' in sql:
            return ('WOOW 匯入測試 - 手動|false\nWOOW 匯入測試 - 排程|true\nWOOW 匯入測試 - Webhook|false'
                    if self.data == 'ha' else '')
        if 'execution_entity' in sql:
            return '4' if self.data == 'ha' else '0'
        raise AssertionError(('psql', sql[:40]))

    def http_code(self, url):
        self.log('http_code', url)
        return '200'

    def device_probe(self, request):
        self.log('device_probe', sorted(request['n8n']))
        return {'n8n_login': self.data == 'ha'}

    def credential_probe(self, name, value):
        self.log('credential_probe', name, value == CREDENTIAL_VALUE)
        return {'found': True, 'match': self.data == 'ha'}

    # ---------------------------------------------------------------- the real page's effects (--via-page)
    def page(self, config, seconds, device):
        self.log('page', device, tuple(config['apps']), seconds <= 20 * 60, config.get('key') == HA_KEY,
                 config.get('choices'), config['password'] == PASSWORD)
        if not any(row['id'] == self.store_id for row in self.ha):
            self.ha.append({'id': self.store_id, 'sha256': self.fixture_sha})
        self.job('verify', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['n8n'], 'key_provided': True},
                 'succeeded', self.check_result(config['ha_id']))
        self.chain(config['ha_id'], unit_shared=True)
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
        browser = {'stage': 'issued-value-scan', 'failure_kind': None, 'completed': True, 'issued_values_scanned': True,
                   'checks': [{'check': n, 'ok': True} for n in names],
                   'confirmations': {'expected_keys': {}, 'sent_keys': {}, 'lines_expected': 0, 'lines_shown': 0,
                                     'check_importable': ['n8n']},
                   'issued_scan_counts': {'scan_completed': True, 'observed_values': 2, 'observations_complete': True,
                                          'credential_device_hits': 0, 'credential_host_hits': 0, 'device_files': 30,
                                          'host_files': 3, 'archive_index_sidecars': 4, 'regular_json_roots': 2},
                   'wire': {'import_starts': 1},
                   'choices': {'named': {}, 'database': None, 'picks': {}, 'import_choices': {}, 'check_choices': {},
                               'rechecks': 0, 'problems': []},
                   'requests': {'check': [{'key': True, 'choices': None}], 'import': {'key': True, 'choices': None}}}
        Path(config['result']).write_text(json.dumps(browser))
        return {'started': True, 'exit': 0, 'timed_out': False, 'interrupted': False, 'stop': 'exited',
                'relay_clean': True, 'relay_error': None, 'children_left': []}


def lab(root):
    home = root / 'home'
    secrets = home / '.woowbk-lab' / 'secrets'
    secrets.mkdir(parents=True)
    (secrets / 'ha-import-creds.env').write_text(''.join(f'{k}={v}\n' for k, v in VALUES.items()))
    (secrets / 'ha-import-n8n-testdata.sh').write_text(
        'curl --data \'{"name":"HA probe header","type":"httpHeaderAuth","data":{"value":"' + CREDENTIAL_VALUE + '"}}\'\n')
    (secrets / 'devadmin.pass').write_text(PASSWORD + '\n')
    fixture = home / '.woowbk-lab/ha-fixtures/20261118/woow-import-test-enc/woow-import-test-enc.tar'
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes(b'generated stand-in for the encrypted Odoo and n8n HA backup ' * 64)
    repo = root / 'repo'   # the driver's REPO: the real engine and page, a private evidence folder for its public record
    (repo / 'tests/backup/evidence/focus-acceptance-20261127').mkdir(parents=True)
    for name in ('backup-engine', 'backup'):
        (repo / name).symlink_to(REPO / name)
    return home, fixture, repo


@contextlib.contextmanager
def simulated(m, root, *, bridge=None, product=None):
    home, fixture, repo = lab(root)
    lock = root / 'woowbk-dev-c-mutation.lock'
    dev = Dev(sha(fixture), '20261118T095520Z-33eb7474', product=Path(product) if product else repo)
    dev.bridge = bridge
    real_check_output = subprocess.check_output

    def check_output(argv, *args, **kwargs):
        if argv[:2] == ['git', '-C'] and argv[3:4] == ['status']:
            return ''
        if argv[:2] == ['git', '-C'] and argv[3:4] == ['rev-parse']:
            return 'f' * 40 + '\n'
        return real_check_output(argv, *args, **kwargs)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # main()'s own hold of the dev-c lock
    try:
        with contextlib.ExitStack() as stack:
            for target, name, value in (
                    (Path, 'home', lambda: home), (m, 'Path', HostPath), (m, 'REPO', repo), (m, 'LOCK', str(lock)),
                    (h, 'LAB', root / 'lab'),
                    (h, 'require_isolated_device', lambda: None), (h, 'root', dev.root), (h, 'owner', dev.owner),
                    (h, 'ok', dev.ok), (h, 'helper', dev.helper), (h, 'upload', dev.upload), (h, 'run_check', dev.run_check),
                    (h, 'wait_job', dev.wait_job), (h, 'restore', dev.restore), (h, 'psql', dev.psql),
                    (h, 'http_code', dev.http_code), (h, 'device_probe', dev.device_probe),
                    (h, 'credential_probe', dev.credential_probe), (subprocess, 'check_output', check_output),
                    (os, 'statvfs', lambda _path: SimpleNamespace(f_bavail=(200 << 30) // 4096, f_frsize=4096))):
                stack.enter_context(patch.object(target, name, value))
            dev.programs = {m.ENGINE_HASHES: 'ENGINE_HASHES', h.LEAK_SCAN: 'LEAK_SCAN'}
            if bridge is not None:
                dev.programs.update({bridge.PRECONDITIONS: 'PRECONDITIONS', bridge.NATIVE_UNITS: 'NATIVE_UNITS'})
                stack.enter_context(patch.object(m, '_load_bridge', lambda: bridge))
                for name, value in (('run_page', dev.page), ('host_available_kib', lambda: 6 * 1024 * 1024),
                                    ('PLAYWRIGHT', fixture), ('CHROMIUM', fixture)):
                    stack.enter_context(patch.object(bridge, name, value))
            real_root = dev.root

            def root(*argv, **kwargs):
                if argv[:3] == ('python3', '-I', '-c') and argv[3] not in dev.programs and 'memory.max' in argv[3]:
                    dev.programs[argv[3]] = 'HEADROOM'
                return real_root(*argv, **kwargs)
            stack.enter_context(patch.object(h, 'root', root))
            yield dev, repo
    finally:
        os.close(fd)


def simulate(m, *, via_page=False, bridge=None, product=None, run=None):
    """One whole _run of driver `m` on a fresh simulated dev-c."""
    root = Path(tempfile.mkdtemp()).resolve()
    try:
        with simulated(m, root, bridge=bridge, product=product) as (dev, repo):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                if run is not None:
                    code = run(m)
                elif via_page or product:
                    code = m._run(product=product, via_page=via_page)
                else:
                    code = m._run()
            evidence = next((root / 'lab' / 'evidence' / 'focus-acceptance-n8n').iterdir())
            results = json.loads((evidence / 'results.json').read_text())['results']
            public = [json.loads(p.read_text()) for p in (repo / 'tests/backup/evidence/focus-acceptance-20261127').iterdir()]
            files = {str(p.relative_to(evidence)): p.read_bytes() for p in evidence.rglob('*') if p.is_file()}
            return SimpleNamespace(code=code, results=results, calls=dev.calls, dev=dev, public=public, files=files,
                                   stdout=out.getvalue())
    finally:
        shutil.rmtree(root, ignore_errors=True)


DEFAULT_CHECKS = ['dev-c is isolated: network none, no published port', 'source checkout is clean',
                  'real HA fixture is present', 'host reserve and memory are ready',
                  'device has at least one GiB memory headroom', 'installed helper and all engine modules match this source',
                  'before: baseline marker and no imported workflow', 'before: both n8n health endpoints answer 200',
                  'baseline backup can restore n8n on this engine']
IMPORT_CHECKS = ['real HA fixture uploaded', 'HA check job succeeded', 'HA check has exactly n8n',
                 'n8n is importable, no unreviewed issue or blocker', 'HA source has three workflows, one credential and executions',
                 'one-action import started a group and first job', 'chain job id is new', 'chain job id is new',
                 'one n8n import has at most two jobs', 'one-action import made convert then restore jobs',
                 'both n8n jobs succeeded', 'group reports n8n imported', 'restore made a safety backup']


class DefaultRunTests(unittest.TestCase):
    def test_the_default_run_is_the_37_check_flow_and_equals_the_reviewed_base_call_for_call(self):
        after = simulate(load_new())
        self.assertEqual((after.code, len(after.results), all(r['ok'] for r in after.results)), (0, 37, True),
                         [r for r in after.results if not r['ok']])
        self.assertEqual([r['check'] for r in after.results][:22], DEFAULT_CHECKS + IMPORT_CHECKS)
        self.assertEqual(after.dev.data, 'baseline')
        self.assertEqual(sorted(after.dev.backups), ['20261118T095520Z-33eb7474'])   # only the baseline is left
        self.assertEqual(after.dev.ha, [])
        self.assertNotIn('import_path', after.public[0])
        base = load_base()
        if base is None:
            self.skipTest(f'base commit {BASE} is not in this checkout')
        before = simulate(base)
        self.assertEqual(after.calls, before.calls)   # the same device calls, with the same requests, in the same order
        self.assertEqual([(r['check'], r['ok']) for r in after.results], [(r['check'], r['ok']) for r in before.results])
        self.assertEqual(sorted(after.files), sorted(before.files))
        self.assertEqual({k: v for k, v in after.public[0].items() if k != 'evidence_dir'},
                         {k: v for k, v in before.public[0].items() if k != 'evidence_dir'})


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
    return (['page: ' + name for name in browser]
            + ['page: bounded (20 min), the browser closed in order and every relay exec child reaped',
               'page: the uploaded HA record is the fixture (id and SHA-256)',
               'page: exactly the page\'s own check and import jobs, none left running, no other new backup',
               'page: the check calls n8n importable, stops nothing, and lists every confirmation line keyed '
               '(read from the actual check)',
               'page: the one acknowledgement, the import and its jobs carry every listed confirmation key exactly once',
               'page: one conversion and its restore succeeded as two linked jobs in the first job\'s unit',
               'page: nothing to choose: the check offers no choice and neither request nor the chain carries one',
               'page: every issued Cockpit session value is absent from the records, the journal and the private evidence',
               'page import passed every gate']
            + IMPORT_CHECKS[1:5] + IMPORT_CHECKS[9:])   # the bridge followed the chain: no follow() checks


class ViaPageRunTests(unittest.TestCase):
    def test_via_page_replaces_only_the_import_checks_and_passes_through_the_real_bridge(self):
        m, bridge = load_new('n8n_page'), bridge_module()
        default = simulate(m)
        run = simulate(m, via_page=True, bridge=bridge)
        self.assertEqual(run.code, 0, [r for r in run.results if not r['ok']])
        names, old = [r['check'] for r in run.results], [r['check'] for r in default.results]
        block = page_block(bridge.page_settings(['n8n'], ['n8n'], [])['texts'])
        self.assertEqual(names[:9], old[:9])
        self.assertEqual(names[9:9 + len(block)], block)
        self.assertEqual(names[9 + len(block):-1], old[22:])                       # every later check unchanged
        self.assertEqual(names[-1], 'no Cockpit login password in the engine\'s records, logs, index, registry or the '
                                    'device journal')
        self.assertEqual((len(old), len(block), len(names)), (37, 35, 60))
        self.assertTrue(all(r['ok'] for r in run.results))
        kinds = [call[0] for call in run.calls]
        self.assertEqual(kinds.count('page'), 1)
        for name in ('upload', 'run_check'):
            self.assertNotIn(name, kinds)
        self.assertNotIn(('ok', 'ha-import-start'), [call[:2] for call in run.calls])
        [page] = [call for call in run.calls if call[0] == 'page']
        self.assertEqual(page, ('page', 'woowbk-dev-c', ('n8n',), True, True, {}, True))
        bridge_reads = [c[1] for c in run.calls if c[0] == 'root' and c[1] in ('PRECONDITIONS', 'NATIVE_UNITS')]
        self.assertEqual(bridge_reads, ['PRECONDITIONS', 'NATIVE_UNITS'])
        # What the page made was cleaned up after the baseline came back; the password scan ran on the device.
        self.assertEqual(run.dev.data, 'baseline')
        self.assertEqual(sorted(run.dev.backups), ['20261118T095520Z-33eb7474'])
        self.assertEqual(run.dev.ha, [])
        self.assertEqual([c[1] for c in run.calls if c[0] == 'root'].count('LEAK_SCAN'), 2)
        self.assertEqual(run.public[0]['import_path'], 'page')
        self.assertTrue(all(run.public[0]['page_gates'].values()))
        summary = json.loads(run.files['page/page-bridge.json'])
        self.assertEqual((summary['device'], summary['passed']), ('woowbk-dev-c', True))
        for name, data in run.files.items():
            for secret in (PASSWORD, HA_KEY, CREDENTIAL_VALUE, *VALUES.values()):
                self.assertNotIn(secret.encode(), data, name)
        self.assertNotIn(PASSWORD, run.stdout)

    def test_the_driver_hands_the_bridge_exactly_its_inputs_and_a_refusal_changes_nothing(self):
        m = load_new('n8n_inputs')
        seen = {}

        class FakeBridge:
            Ops = staticmethod(lambda **kw: ('ops', sorted(kw)))

            class BridgeError(Exception):
                summary = {'phase': 'refused', 'reasons': ['stop here'], 'ha_id': 'ha-' + '0' * 20}

            Refused = BridgeError

            @staticmethod
            def import_via_page(**kwargs):
                seen.update(kwargs)
                raise FakeBridge.BridgeError('stop here')
        product = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, product, True)
        for name in ('backup-engine', 'backup'):
            (product / name).symlink_to(REPO / name)
        started = time.monotonic()
        run = simulate(m, run=lambda module: module._run(product=product, via_page=True, bridge=FakeBridge), product=product)
        self.assertEqual({k: seen[k] for k in ('device', 'lock', 'apps', 'importable', 'stops', 'key', 'choices', 'password',
                                               'source')},
                         {'device': 'woowbk-dev-c', 'lock': seen['lock'], 'apps': ['n8n'], 'importable': ['n8n'], 'stops': [],
                          'key': HA_KEY, 'choices': {}, 'password': PASSWORD, 'source': product})
        self.assertTrue(seen['lock'].endswith('woowbk-dev-c-mutation.lock'))
        self.assertEqual(seen['fixture'].name, 'woow-import-test-enc.tar')
        self.assertEqual(seen['ops'], ('ops', ['helper', 'root_json', 'wait_job']))
        self.assertLessEqual(seen['deadline'], started + 25 * 60 + 5)
        checks = [(r['check'], r['ok']) for r in run.results]
        self.assertIn(('product checkout (--source) is clean', True), checks)
        self.assertIn(('page import: refused before the page started (nothing changed)', False), checks)
        self.assertIn(('full import completed', False), checks)
        self.assertIn(('cleanup: baseline marker and no imported workflow', True), checks)   # nothing to restore
        self.assertNotIn('helper', [call[0] for call in run.calls])   # nothing was made, so nothing deleted
        self.assertEqual(run.code, 1)
        self.assertEqual(run.public[0]['product_commit'], 'f' * 40)


class CommandLineTests(unittest.TestCase):
    def test_the_default_command_line_calls_the_flow_exactly_as_before(self):
        m = load_new('n8n_cli')
        calls = []
        with patch.object(m, '_run', lambda *a, **k: calls.append((a, k)) or 0), \
                patch.object(m, 'LOCK', str(Path(tempfile.mkdtemp()) / 'x.lock')):
            self.assertEqual(m.main(['--run']), 0)
            self.assertEqual(m.main(['--run', '--via-page']), 0)
            self.assertEqual(m.main(['--run', '--source', '/tmp/product']), 0)
        self.assertEqual(calls, [((), {}), ((), {'product': None, 'via_page': True}),
                                 ((), {'product': Path('/tmp/product'), 'via_page': False})])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main([]), 0)
        self.assertIn('offline check PASS', out.getvalue())


if __name__ == '__main__':
    unittest.main()
