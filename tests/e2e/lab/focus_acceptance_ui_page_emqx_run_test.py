"""Offline end-to-end of the real controller run(page_emqx=True) against a simulated dev-d.

Nothing here reaches a device, the host's podman, a browser or a relay: the helper commands, the unit/image probes, the
marker reads, the page and the relay are answered by Dev below, and every lab path points into a temporary folder with
generated values (no real secret is read). It proves the wiring: the checks and their order, what is deleted (only what
the run owns), what stays (protected records, PAGE5 and R1 files), and where a failure or a precondition stops.
"""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import focus_acceptance_n8n  # noqa: E402  (its ENGINE_HASHES program text only)
import focus_acceptance_ui as ui  # noqa: E402
import focus_acceptance_ui_page_emqx as pe  # noqa: E402
import focus_acceptance_ui_relay as relay_module  # noqa: E402
import ha_import_e2e as h  # noqa: E402

HEAD = subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip()
KEY_S, KEY_E1, KEY_E2 = 'files.skipped:' + '1' * 16, 'emqx.device-psk:' + '2' * 16, 'emqx.exhook:' + '3' * 16
EXPECTED = {'_shared': [KEY_S], 'emqx': sorted([KEY_E1, KEY_E2])}
DERIVED_SHA = 'd' * 64
DERIVED_HA = 'ha-' + DERIVED_SHA[:20]
SECRETS = {'b1-creds.env': 'HA_BACKUP_KEY=FAKE-HA-KEY-0123456789\nB1_EMQX_ADMIN_PW=generated-ha-admin-pass-4711\n'
                           'B1_MQTT_USER1=b1-sensor\nB1_MQTT_PW1=generated-mqtt-pass-0815\n',
           'ha-import-creds.env': 'GENERATED_OTHER_PW=generated-other-pass-1234\n',
           'dev-d-markers.json': '{"emqx": "generated-marker-pass-2222"}', 'devadmin.pass': 'generated-cockpit-pass-3333\n',
           'dev-d-kit.txt': 'AGE-SECRET-KEY-GENERATED0123456789\n'}
DEV_MARKERS = {'emqx': {'mqtt_users': ['woowbk-lab-baseline'], 'retained': ['woowbk-lab/baseline'],
                        'banned': ['woowbk-lab-baseline'], 'mqtt_user_count': 2},
               'omnigent': {'users': ['woowbk-lab-baseline'], 'projects': ['woowbk-lab-baseline'],
                            'scheduled_tasks': ['woowbk-lab-baseline']},
               'hermes': {'sessions': {'woowbk-lab-baseline': 1}, 'memory_markers': ['woowbk-lab-baseline'],
                          'cron_jobs': ['woowbk-lab-baseline'], 'session_count': 1}}
HA_EMQX = {'mqtt_users': [], 'retained': [], 'banned': [], 'mqtt_user_count': 4}
UNIT_ROWS = ([{'unit': unit, 'active': 'active', 'sub': 'running'} for unit in ui.IMAGE_UNITS]
             + [{'unit': ui.HEALTH_TIMER, 'active': 'active', 'sub': 'waiting'},
                {'unit': ui.HEALTH_PROBE, 'active': 'inactive', 'sub': 'dead'},
                {'unit': 'headscale.service', 'active': 'activating', 'sub': 'auto-restart'}])
TIMER = {'UnitFileState': 'masked', 'ActiveState': 'inactive'}


def answer(stdout=b'', returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=stdout if isinstance(stdout, bytes) else stdout.encode(),
                           stderr=b'')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Dev:
    """dev-d as the controller sees it: helper replies, probes, marker reads and the real page's effects."""

    def __init__(self, fixture_sha, *, original_exists=True, emqx_catalog=True, importable=True, extra_emqx_safety=0):
        self.fixture_sha = fixture_sha
        self.ha_id = 'ha-' + fixture_sha[:20]
        self.importable = importable
        self.catalog = {'emqx.json': 'c-emqx', 'hermes.json': 'c-hermes', 'omnigent.json': 'c-omnigent'}
        if not emqx_catalog:
            del self.catalog['emqx.json']
        self.backups = {}
        for app, bid in (('hermes', ui.BASELINES['hermes']), ('omnigent', ui.BASELINES['omnigent']), ('emqx', pe.BASELINE)):
            self.backups[bid] = {'id': bid, 'type': 'manual', 'created': '2026-11-19T07:2%dZ' % len(self.backups),
                                 'apps': [{'id': app}]}
        for bid, kind, app in (('20261126T100000Z-0000aaaa', 'manual', 'hermes'), ('20261126T110000Z-0000bbbb', 'safety', 'omnigent')):
            self.backups[bid] = {'id': bid, 'type': kind, 'created': bid[:15], 'apps': [{'id': app}]}
        for n in range(extra_emqx_safety):
            bid = '20261125T1%d0000Z-0000ccc%d' % (n, n)
            self.backups[bid] = {'id': bid, 'type': 'safety', 'created': bid[:15], 'apps': [{'id': 'emqx'}]}
        self.ha = [{'id': DERIVED_HA, 'sha256': DERIVED_SHA}]
        if original_exists:
            self.ha.append({'id': self.ha_id, 'sha256': fixture_sha})
        self.jobs, self.order, self.calls, self.marker_inputs, self.page_configs = {}, [], [], [], []
        self.emqx, self.sequence, self.tokens, self.isolation_checks = 'dev', 0, 0, 0

    # ------------------------------------------------------------ helpers
    def next(self):
        self.sequence += 1
        return self.sequence

    def new_backup(self, kind, app):
        n = self.next()
        bid = '20261128T10%02d00Z-%08x' % (n, n)
        self.backups[bid] = {'id': bid, 'type': kind, 'created': bid[:15], 'apps': [{'id': app}]}
        return bid

    def new_job(self, kind, params, state, result, unit=None):
        n = self.next()
        jid = 'j20261128T10%02d00Z-%08x' % (n, n)
        self.jobs[jid] = {'id': jid, 'type': kind, 'state': state, 'phase': 'done', 'progress': {}, 'params': params,
                          'result': result, 'unit': unit or 'woowtech-backup-' + jid + '.service'}
        self.order.append(jid)
        return self.jobs[jid]

    @staticmethod
    def public(job):
        return {k: copy.deepcopy(v) for k, v in job.items() if k != 'unit'}

    def ok(self, command, request=None, *, ev, timeout=1800):
        self.calls.append((command, copy.deepcopy(request)))
        if command == 'status':
            return {'active_job': None}
        if command == 'list':
            return {'backups': [dict(row) for row in self.backups.values()], 'ha_backups': [dict(row) for row in self.ha]}
        if command == 'jobs':
            return {'jobs': [self.public(self.jobs[j]) for j in reversed(self.order)]}
        if command == 'inspect':
            app = self.backups[request['backup_id']]['apps'][0]['id']
            state = 'same' if app + '.json' in self.catalog else 'missing'
            return {'ok': True, 'preflight': {'ok': True, 'apps': [{'id': app, 'issues': [{'level': 'notice'}],
                    'settings': {'state': state, 'entry': {'id': app, 'owner': 'appowner'}}}]}}
        if command == 'restore-start':
            assert request['backup_id'] == pe.BASELINE and request['apps'] == ['emqx'] and request['confirm'] is True
            safety = self.new_backup('safety', 'emqx')
            job = self.new_job('restore', {'backup_id': pe.BASELINE, 'apps': ['emqx']}, 'succeeded', {'safety_backup_id': safety})
            self.emqx = 'dev'
            return {'job_id': job['id']}
        if command == 'delete':
            del self.backups[request['backup_id']]
            return {}
        if command == 'ha-delete':
            assert request['confirm'] is True
            self.ha = [row for row in self.ha if row['id'] != request['ha_backup_id']]
            return {}
        if command == 'catalog-install':
            assert request['entry'] == {'id': 'emqx', 'owner': 'appowner'}
            if request.get('confirm'):
                self.catalog['emqx.json'] = 'c-own-emqx'
                return {}
            return {'valid': True, 'new_sha256': 'c-own-emqx', 'expected_sha256': None}
        if command == 'catalog-remove':
            assert request['id'] == 'emqx'
            if request.get('confirm'):
                assert request['expected_sha256'] == self.catalog['emqx.json']
                del self.catalog['emqx.json']
                return {}
            return {'expected_sha256': self.catalog['emqx.json']}
        raise AssertionError('unexpected helper command ' + command)

    def wait_job(self, job_id, *, ev, timeout=3600):
        job = self.public(self.jobs[job_id])
        ev.save(f'job-{job_id}.json', {'job': job, 'log': []})
        return job

    def owner(self, *argv, input=None, timeout=600, check=False):
        if argv[:3] == ('systemctl', '--user', 'list-units'):
            return answer(json.dumps(UNIT_ROWS))
        if argv[:4] == ('systemctl', '--user', 'show', '--property=Id,Type,RemainAfterExit,Unit,UnitFileState'):
            blocks = []
            for name in argv[5:]:
                kind = {ui.HEALTH_PROBE: ('oneshot', 'no', ''), ui.HEALTH_TIMER: ('', '', ui.HEALTH_PROBE)}.get(name, ('simple', 'no', ''))
                blocks.append(f'Id={name}\nType={kind[0]}\nRemainAfterExit={kind[1]}\nUnit={kind[2]}\nUnitFileState=enabled')
            return answer('\n\n'.join(blocks) + '\n')
        if argv[:4] == ('systemctl', '--user', 'show', '--property=Id,SourcePath'):
            return answer('\n\n'.join(f'Id={unit}\nSourcePath=/home/appowner/.config/containers/systemd/'
                                      f'{unit.removesuffix(".service")}.container' for unit in argv[5:]))
        if argv[:2] == ('podman', 'ps'):
            return answer('\n'.join(f'{name} img-{name}' for name in [*ui.IMAGE_UNITS.values(), 'headscale']) + '\n')
        if argv[:3] == ('python3', '-I', '-c') and argv[5:] == ('read',):
            program, app = argv[3], argv[4]
            variant = pe.HA_LOGIN_OVERRIDE in program
            self.marker_inputs.append((app, variant, input))
            if variant:
                if app != 'emqx' or self.emqx != 'ha' or json.loads(input)['ha_dashboard_password'] != 'generated-ha-admin-pass-4711':
                    return answer(b'', 1)   # HA's Dashboard admin exists only while HA's administrator table is live
                found = HA_EMQX
            else:
                assert program == ui.marker_program((HERE / 'batch1_markers.py').read_text()) and input == b'{}'
                if app == 'emqx' and self.emqx == 'ha':
                    return answer(b'', 1)   # dev-d's own admin password no longer logs in
                found = DEV_MARKERS[app]
            self.tokens += 1
            issued = ['generated-issued-token-%04d' % self.tokens] if app == 'emqx' else []
            return answer(json.dumps({'markers': found, 'issued': issued}))
        raise AssertionError(argv[:4])

    def root(self, *argv, input=None, timeout=600, check=False):
        if argv[:3] == ('python3', '-I', '-c'):
            return answer(json.dumps(self.root_json(argv[3], json.loads(input or b'{}'))))
        if argv == ('systemctl', 'is-active', '--quiet', 'cockpit.socket'):
            return answer()
        if argv[:3] == ('systemctl', 'show', ui.TIMER):
            return answer(''.join(f'{k}={v}\n' for k, v in TIMER.items()))
        raise AssertionError(argv[:4])

    def root_json(self, script, request):
        if 'memory.stat' in script:
            return 4 * 1024**3
        if script == focus_acceptance_n8n.ENGINE_HASHES:
            lib = REPO / 'backup-engine/woowbackup'
            return {'lib': {str(p.relative_to(lib)): sha(p) for p in lib.rglob('*.py') if '__pycache__' not in p.parts},
                    'helper': sha(REPO / 'backup-engine/woowtech-cockpit-backup')}
        if '/usr/local/share/cockpit/woowtechbackup' in script:
            return {n: sha(REPO / 'backup' / n) for n in ('backup.js', 'backup.css', 'index.html', 'manifest.json')}
        if '/etc/woowtech-cockpit/backup/apps' in script:
            return dict(self.catalog)
        if 'configparser' in script:
            return {unit: {'source': path, 'source_sha256': 's', 'container_name': ui.IMAGE_UNITS[unit]}
                    for unit, path in request['sources'].items()}
        if script == pe.NATIVE_UNITS:
            assert len(request['ids']) == 2
            return [{k: self.jobs[j][k] for k in ('id', 'unit', 'type', 'state')} for j in request['ids']]
        if 'secret_scan_needles' in script:
            assert request['values'] and 'woow-emqx-dashboard-password' in request['podman_secrets']
            return {'scanned': 650, 'hits': 0, 'journal_bytes': 10, 'archive_index_sidecars_scanned': len(self.backups),
                    'regular_json_roots_scanned': 2}
        if 'archives").rglob' in script:
            return len(self.backups)
        raise AssertionError(script[:60])

    def page(self, config):
        """What the real page does through the relay: upload (deduplicated when the record exists), one EMQX check, and
        with EMQX importable one acknowledged import whose chain converts and restores in the first job's unit."""
        self.page_configs.append(config)
        if not any(row['id'] == config['ha_id'] for row in self.ha):
            self.ha.append({'id': config['ha_id'], 'sha256': self.fixture_sha})
        issues = [{'id': 'emqx.device-psk', 'level': 'confirm', 'message': 'psk', 'items': [], 'more': 0, 'key': KEY_E1},
                  {'id': 'emqx.exhook', 'level': 'confirm', 'message': 'exhook', 'items': [], 'more': 0, 'key': KEY_E2},
                  {'id': 'legacy.warning', 'level': 'notice', 'message': 'hot backup', 'items': [], 'more': 0}]
        if not self.importable:
            issues = [{'id': 'failure.incompatible', 'level': 'stop', 'message': 'hot database', 'items': [], 'more': 0}]
        self.new_job('verify', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['emqx'], 'key_provided': True},
                     'succeeded', {'ha_check': {'schema': 2, 'ha_backup_id': config['ha_id'],
                     'shared': [{'id': 'files.skipped', 'level': 'confirm', 'message': 'skipped', 'items': [], 'more': 0,
                                 'key': KEY_S}],
                     'apps': [{'app_id': 'emqx', 'importable': self.importable, 'issues': issues,
                               'emqx': {'mqtt_users': 3}}]}})
        names = browser_names(config['texts'])
        if not self.importable:
            view = names.index(config['texts']['view'])
            checks = [{'check': name, 'ok': True} for name in names[:view]] + [{'check': names[view], 'ok': False},
                      {'check': 'UI bounded flow completed', 'ok': False}] + [{'check': name, 'ok': True} for name in names[-2:]]
            browser = {'completed': False, 'issued_values_scanned': True, 'checks': checks,
                       'confirmations': {'expected_keys': {'_shared': [KEY_S]}, 'sent_keys': None}}
        else:
            converted = self.new_backup('manual', 'emqx')
            params = {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['emqx'], 'test_mode': False,
                      'acknowledged': copy.deepcopy(EXPECTED), 'group': {'kind': 'ha-import', 'step': 'convert'},
                      'chain': {'apps': ['emqx'], 'test_mode': False, 'then_restore': True, 'acknowledged': copy.deepcopy(EXPECTED)}}
            first = self.new_job('backup', params, 'succeeded', {'backup_id': converted})
            safety = self.new_backup('safety', 'emqx')
            second = self.new_job('restore', {'backup_id': converted, 'apps': ['emqx'], 'ha_backup_id': config['ha_id']},
                                  'succeeded', {'safety_backup_id': safety, 'group': {'next_job_id': None,
                                  'results': [{'app_id': 'emqx', 'status': 'imported'}]}}, unit=first['unit'])
            first['result']['group'] = {'next_job_id': second['id'], 'results': []}
            self.emqx = 'ha'
            browser = {'completed': True, 'issued_values_scanned': True,
                       'checks': [{'check': name, 'ok': True} for name in names],
                       'confirmations': {'expected_keys': copy.deepcopy(EXPECTED), 'sent_keys': copy.deepcopy(EXPECTED),
                                         'lines_expected': 3, 'lines_shown': 3, 'check_importable': ['emqx']}}
        with open(config['result'], 'x') as handle:
            json.dump(browser, handle)
        os.chmod(config['result'], 0o600)
        return 0 if self.importable else 1


def browser_names(texts):
    """The real page's check names in its order (focus_acceptance_ui_page_drive_test proves the page writes these)."""
    return ['UI real administrative Cockpit bridge reaches this device', texts['upload'], texts['select'],
            'UI actual check confirmation keys observed including valid zero', texts['view'], texts['lines'],
            'UI has exactly one acknowledgement and import waits for it', 'UI check did not start an import or separate restore',
            'UI real key field removed before screenshot', 'UI one acknowledgement enables import', texts['result'],
            texts['intent'], texts['keys'], 'UI no page script errors during this page flow',
            'UI cookie observation completed without gaps',
            'UI every issued credential absent from records journal and private evidence; proved public markers counted separately']


class FakeRelay:
    def __init__(self):
        self.children, self.base = set(), 'https://127.0.0.1:65000'
        self.thread = SimpleNamespace(is_alive=lambda: False)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class FakeNode:
    def __init__(self, dev):
        self.dev, self.returncode = dev, None

    def communicate(self, input=None, timeout=None):
        self.returncode = self.dev.page(json.loads(input))
        return b'', b''


class Lab:
    """A temporary ~/.woowbk-lab with generated secrets, the terminal PAGE5 and R1 guards and their evidence."""

    def __init__(self, root, dev, fixture):
        self.root, self.dev, self.fixture = root, dev, fixture
        for name, text in SECRETS.items():
            path = root / 'secrets' / name
            path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text); path.chmod(0o600)
        (root / 'run').mkdir()
        page_case = root / 'evidence/focus-acceptance-ui/20261127T102112'
        page_case.mkdir(parents=True)
        for name, value in (('summary.json', {'baseline_restored': True, 'recovery_verified': True}), ('recovery.json', {}),
                            ('browser.json', {'issued_values_scanned': True}), ('results.json', {}),
                            ('leaks.json', {'hits': 0, 'scanned': 651, 'regular_json_roots_scanned': 2,
                                            'archive_index_sidecars_scanned': 19})):
            self.write(page_case / name, value)
        protected = ['20261126T100000Z-0000aaaa', '20261126T110000Z-0000bbbb']
        self.page_guard = root / 'run/focus_acceptance_ui.json'
        self.write(self.page_guard, {'phase': 'complete', 'baseline_restored': True, 'recovery_verified': True,
                                     'inflight': None, 'evidence_dir': str(page_case),
                                     'protected_existing_backups': protected, 'prior_case_safety_pruning': [],
                                     'ha_id': DERIVED_HA, 'derived_fixture_sha256': DERIVED_SHA, 'ha_record_owned': False})
        r1_case = root / 'evidence/focus-acceptance-r1-helper/20261128T044707'
        r1_case.mkdir(parents=True)
        for name, value in (('summary.json', {'baseline_restored': True, 'recovery_verified': True, 'failed': 0}),
                            ('recovery.json', {}), ('results.json', {'passed': 70, 'failed': 0, 'results': []}),
                            ('leaks.json', {'hits': 0, 'scanned': 650, 'regular_json_roots_scanned': 2,
                                            'archive_index_sidecars_scanned': 19}),
                            ('helper-trace.json', {'completed': True})):
            self.write(r1_case / name, value)
        units = ui.stable_units(UNIT_ROWS, {ui.HEALTH_PROBE: {'Type': 'oneshot', 'RemainAfterExit': 'no'}})
        self.r1_guard = root / 'run' / pe.R1_STATE_NAME
        self.write(self.r1_guard, {
            'phase': 'complete', 'mode': 'helper-three-selected', 'baseline_restored': True, 'recovery_verified': True,
            'inflight': None, 'ha_record_owned': False, 'evidence_dir': str(r1_case),
            'previous_independent_recovery': {'sha256': sha(self.page_guard)}, 'protected_existing_backups': protected,
            'prior_case_safety_pruning': [], 'original_catalog': dict(dev.catalog), 'original_units': units,
            'original_images': {name: 'img-' + name for name in ui.IMAGE_UNITS.values()}, 'original_timer': TIMER,
            'before_markers': DEV_MARKERS, 'ha_id': DERIVED_HA, 'derived_fixture_sha256': DERIVED_SHA})
        self.lease = root / 'lease-page-emqx-dev-d.json'
        self.write(self.lease, {'granted': True, 'device': 'woowbk-dev-d', 'case': 'page-emqx', 'phase': 'page-emqx',
                                'source': str(REPO), 'source_commit': HEAD, 'driver_commit': HEAD,
                                'page_guard_sha256': sha(self.page_guard),
                                'expires': (datetime.now(timezone.utc) + timedelta(minutes=50)).isoformat()})
        for name in ('playwright.mjs', 'chrome'):
            (root / name).write_text('stand-in')

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value)); path.chmod(0o600)

    def protected(self):
        files = [self.page_guard, self.r1_guard, *sorted((self.root / 'evidence/focus-acceptance-ui').rglob('*.json')),
                 *sorted((self.root / 'evidence/focus-acceptance-r1-helper').rglob('*.json'))]
        return {str(p): sha(p) for p in files}

    @contextlib.contextmanager
    def patched(self):
        dev = self.dev
        real_check_output, real_popen = subprocess.check_output, subprocess.Popen

        def check_output(args, *rest, **kwargs):   # the checkout under test may carry this lane's uncommitted edits
            return '' if isinstance(args, list) and 'status' in args else real_check_output(args, *rest, **kwargs)

        def popen(args, *rest, **kwargs):
            if isinstance(args, list) and args and args[0] == 'node':
                return FakeNode(dev)
            return real_popen(args, *rest, **kwargs)

        def isolated():
            dev.isolation_checks += 1

        with contextlib.ExitStack() as stack:
            for target, name, value in (
                    (ui, 'LAB', self.root), (ui, 'STATE', self.page_guard), (ui, 'FIXTURE', self.fixture),
                    (ui, 'FIXTURE_SHA', sha(self.fixture)), (ui, 'LOCK', str(self.root / 'dev-d.lock')),
                    (ui, 'PLAYWRIGHT', self.root / 'playwright.mjs'), (ui, 'CHROMIUM', self.root / 'chrome'),
                    (h, 'LAB', self.root), (h, 'require_isolated_device', isolated), (h, 'ok', dev.ok),
                    (h, 'wait_job', dev.wait_job), (h, 'owner', dev.owner), (h, 'root', dev.root),
                    (h, 'scenario_cleanup', lambda ev, _args: (ev.check('no throwaway container, volume or network left', True),
                                                               ev.check('no staging folder and no key file left', True))),
                    (relay_module, 'Relay', FakeRelay), (subprocess, 'check_output', check_output),
                    (subprocess, 'Popen', popen),
                    (os, 'statvfs', lambda _path: SimpleNamespace(f_bavail=10**12 // 4096, f_frsize=4096))):
                stack.enter_context(patch.object(target, name, value))
            yield


def run_case(test, **options):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        fixture = root / 'woow-b1-x86-enc.tar'
        fixture.write_bytes(b'generated stand-in for the original encrypted B1 backup')
        dev = Dev(sha(fixture), **options)
        lab = Lab(root, dev, fixture)
        before = lab.protected()
        umask = os.umask(0o022); os.umask(umask)
        output = io.StringIO()
        try:
            with lab.patched(), contextlib.redirect_stdout(output):
                code = ui.run(REPO, page_emqx=True, page_emqx_lease_path=lab.lease)
        finally:
            os.umask(umask)
        test.assertEqual(lab.protected(), before)   # PAGE5's and R1's guards and evidence stay byte for byte
        case = next((root / 'evidence' / pe.EVIDENCE_AREA).iterdir())
        results = json.loads((case / 'results.json').read_text())['results']
        guard = root / 'run' / pe.STATE_NAME
        return SimpleNamespace(code=code, dev=dev, results=results, names=[r['check'] for r in results],
                               failed=[r['check'] for r in results if not r['ok']], output=output.getvalue(),
                               guard=json.loads(guard.read_text()) if guard.exists() else None, fixture=str(fixture),
                               files={path.name: path.read_bytes() for path in case.iterdir()})


PRECONDITIONS = [
    'scan: exact reviewed rendered program parity', 'source: both reviewed checkouts clean',
    'fixture: original recorded full encrypted HA hash matches', 'browser: existing package and Chromium ready',
    'secrets: HA EMQX admin credential registered for the live data read',
    'resources: device headroom at least1900MiB', 'resources: host available memory at least1200MiB',
    'resources: host keeps13GiB plus bounded phase writes',
    'source: installed helper and every module equal frozen source', 'source: installed actual page equals frozen source',
    'Cockpit: existing socket active', 'before: no active backup job',
    'before: app services already active and all eight selected image configs present',
    'before: selected health timer enabled active and bound to its nonpersistent probe', 'before: schedule inactive or failed',
    'replay: original catalog units images and timer still match independent receipt',
    'replay: every old archive remains a protected existing backup', 'replay: old HA record retained at exact derived SHA',
    'before: no unowned EMQX safety backup can be pruned by this run']
MARKERS = ['before: exact original emqx marker baseline', 'replay: exact recovered original emqx markers still match',
           'before: exact original omnigent marker baseline', 'replay: exact recovered original omnigent markers still match',
           'before: exact original hermes marker baseline', 'replay: exact recovered original hermes markers still match']
RESOURCES = ['resources: device headroom at least1900MiB', 'resources: host available memory at least1200MiB',
             'resources: host keeps13GiB plus bounded phase writes']
TEXTS = pe.page_settings()['texts']
PAGE = (['transport: private relay closed all exec children', 'UI: real page completed one bounded flow']
        + browser_names(TEXTS) + ['UI: browser result and issued-value scan complete'])
RECOVERY = [
    'check: one current EMQX-only check, EMQX importable, every confirmation line keyed',
    'confirmation: page and import carry every listed confirmation key exactly once',
    'chain: one EMQX conversion and its restore succeeded as two linked jobs', 'chain: both jobs share the first systemd unit',
    'chain: the EMQX restore has its own safety backup',
    'live: EMQX holds HA data (HA admin logs in, no dev-d marker left, every HA MQTT account present)',
    'recovery: no active job before baseline restore', *RESOURCES,
    'recovery: original baseline has no unreviewed confirmation', 'recovery: original emqx restore succeeded',
    'recovery: exact original emqx markers returned', 'recovery: unselected Omnigent and Hermes unchanged',
    'recovery: original app unit states and image configs returned', 'recovery: original full HA fixture hash retained',
    'leaks: registered and observed values absent from records journal and text evidence',
    'leaks: browser issued-value scan completed before deletion',
    'page-emqx: check, keys, chain, live data, baseline and scans complete before deletion',
    'page-emqx: PAGE5 and R1 guards and evidence remain byte unchanged',
    'recovery: backup inventory contains no untracked new archive']
CLEANUP = ['recovery: original catalog hashes returned', 'no throwaway container, volume or network left',
           'no staging folder and no key file left', 'cleanup: original backups retained except proved prior test safety pruning',
           'cleanup: original HA inventory retained']
AFTER = ['recovery: original schedule state returned', 'after: networknone and zero published ports preserved',
         'page-emqx: PAGE5 and R1 guards and evidence unchanged after recovery']


def expected_names(*, owned, catalog_added=False):
    setup = ['before: encrypted emqx baseline opens']
    if catalog_added:
        setup += ['catalog: only missing EMQX can be added', 'catalog: trusted carried entry matches appowner',
                  'catalog: carried entry preview valid']
    setup += ['before: emqx original baseline restore preflight ready', 'before: emqx original baseline has no unreviewed confirmation',
              'upload: original HA record is new or an exact protected existing record', *RESOURCES]
    cleanup = (['catalog: only own new entry changed', 'catalog: remove matches own installed entry'] if catalog_added else []) + CLEANUP
    if not owned:
        cleanup.append('cleanup: protected original HA record remains at exact fixture SHA')
    cleanup.append('cleanup: protected old HA remains at exact derived SHA')
    return PRECONDITIONS + MARKERS + setup + PAGE + RECOVERY + cleanup + AFTER


class PageEmqxRunTests(unittest.TestCase):
    def assert_owned_cleanup(self, run, owned_ha):
        dev = run.dev
        created = set(run.guard['created_backups'])
        deleted = {request['backup_id'] for command, request in dev.calls if command == 'delete'}
        self.assertEqual(len(created), 3)   # the converted backup, the import's safety copy, the baseline restore's copy
        self.assertEqual(deleted, created)
        self.assertTrue(all(bid not in dev.backups for bid in created))
        self.assertIn(pe.BASELINE, dev.backups)
        ha_deletes = [request['ha_backup_id'] for command, request in dev.calls if command == 'ha-delete']
        self.assertEqual(ha_deletes, [dev.ha_id] if owned_ha else [])
        self.assertIn(DERIVED_HA, {row['id'] for row in dev.ha})
        self.assertEqual(dev.ha_id in {row['id'] for row in dev.ha}, not owned_ha)

    def test_normal_import_of_the_original_backup_with_its_protected_existing_upload(self):
        run = run_case(self)
        self.assertEqual(run.failed, [])
        self.assertEqual(run.names, expected_names(owned=False))
        self.assertEqual(run.code, 0)
        self.assertIn('page-emqx real Cockpit: %d/%d PASS' % (len(run.names), len(run.names)), run.output)
        self.assertEqual((run.guard['phase'], run.guard['recovery_verified'], run.guard['ha_record_owned']), ('complete', True, False))
        self.assert_owned_cleanup(run, owned_ha=False)
        dev = run.dev
        self.assertEqual(dev.isolation_checks, 2)   # network none and no published port, before and after
        [config] = dev.page_configs
        self.assertEqual(config['fixture'], run.fixture)   # the ORIGINAL file itself, never a derived copy
        self.assertEqual({k: config[k] for k in pe.page_settings()}, pe.page_settings())
        self.assertTrue({'previous-guard.json', 'previous-page-guard.json', 'browser.json', 'leaks.json'} <= set(run.files))
        # HA's admin password reached the device only on the stdin of the one HA-admin marker read, after the import.
        variants = [(app, json.loads(data)) for app, variant, data in dev.marker_inputs if variant]
        self.assertEqual(variants, [('emqx', {'ha_dashboard_password': 'generated-ha-admin-pass-4711'})])
        self.assertTrue(all(data == b'{}' for _app, variant, data in dev.marker_inputs if not variant))
        self.assertEqual([c for c, _r in dev.calls].count('restore-start'), 1)
        trace = json.loads(run.files['page-emqx-trace.json'])
        self.assertEqual(trace['expected_acknowledged'], EXPECTED)
        self.assertEqual(trace['safety_copies_at_risk'], [])
        self.assertEqual(trace['native_units'], ['woowtech-backup-' + trace['first_job_id'] + '.service'] * 2)
        for name, data in run.files.items():   # no generated secret value in any private evidence file
            self.assertFalse(any(value.encode() in data for value in ('FAKE-HA-KEY-0123456789', 'generated-ha-admin-pass-4711',
                                                                      'generated-cockpit-pass-3333', 'generated-issued-token')),
                             name)

    def test_a_new_upload_is_owned_and_deleted_with_the_runs_own_archives(self):
        run = run_case(self, original_exists=False)
        self.assertEqual(run.failed, [])
        self.assertEqual(run.names, expected_names(owned=True))
        self.assertEqual(run.code, 0)
        self.assertIs(run.guard['ha_record_owned'], True)
        self.assert_owned_cleanup(run, owned_ha=True)

    def test_a_missing_emqx_catalog_entry_is_added_from_the_baseline_and_only_that_entry_removed(self):
        run = run_case(self, emqx_catalog=False)
        self.assertEqual(run.failed, [])
        self.assertEqual(run.names, expected_names(owned=False, catalog_added=True))
        self.assertEqual(run.code, 0)
        self.assertNotIn('emqx.json', run.dev.catalog)
        self.assertEqual([c for c, r in run.dev.calls if c.startswith('catalog-')],
                         ['catalog-install', 'catalog-install', 'catalog-remove', 'catalog-remove'])

    def test_emqx_not_importable_restores_nothing_deletes_nothing_and_retains_the_guard(self):
        run = run_case(self, importable=False, original_exists=False)
        self.assertEqual(run.code, 1)
        self.assertIn('UI: real page completed one bounded flow', run.failed)
        self.assertIn({'check': 'UI check shows EMQX importable', 'ok': False}, json.loads(run.files['browser.json'])['checks'])
        self.assertIn('page-emqx: bounded real page flow completed', run.failed)
        self.assertIn('page-emqx: check, keys, chain, live data, baseline and scans complete before deletion', run.failed)
        self.assertIn('recovery: copies and receipt retained on uncertainty', run.failed)
        self.assertNotIn('chain: both jobs share the first systemd unit', run.names)   # no import was started
        commands = [c for c, _r in run.dev.calls]
        self.assertFalse({'restore-start', 'delete', 'ha-delete', 'catalog-install', 'catalog-remove'} & set(commands))
        self.assertEqual((run.guard['phase'], run.guard['recovery_verified']), ('recovery-retained', False))
        self.assertIs(run.guard['ha_record_owned'], True)   # the new upload stays for a reviewed recovery
        self.assertIn('recovery: exact original emqx markers returned', run.names)
        self.assertEqual(run.dev.isolation_checks, 2)

    def test_an_unowned_emqx_safety_copy_the_product_could_prune_stops_before_any_mutation(self):
        run = run_case(self, extra_emqx_safety=2)
        self.assertEqual(run.code, 1)
        self.assertEqual(run.failed, ['before: no unowned EMQX safety backup can be pruned by this run',
                                      'page-emqx: bounded real page flow completed'])
        self.assertEqual(run.names[-1], 'preconditions: old guard retained without device mutation')
        self.assertIsNone(run.guard)   # never armed: no guard was written
        self.assertEqual({c for c, _r in run.dev.calls}, {'status', 'list'})
        self.assertEqual(run.dev.page_configs, [])
        self.assertIn('page-emqx preconditions stopped; no device mutation', run.output)

    def test_an_existing_page_emqx_guard_stops_before_anything_else(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            fixture = root / 'fixture.tar'; fixture.write_bytes(b'x')
            dev = Dev(sha(fixture))
            lab = Lab(root, dev, fixture)
            guard = root / 'run' / pe.STATE_NAME
            guard.write_text('{"phase": "recovery-retained"}')
            with lab.patched(), self.assertRaisesRegex(ValueError, 'page-emqx guard already exists'):
                ui.run(REPO, page_emqx=True, page_emqx_lease_path=lab.lease)
            self.assertEqual(guard.read_text(), '{"phase": "recovery-retained"}')
            self.assertEqual(dev.calls, [])
            self.assertFalse((root / 'evidence' / pe.EVIDENCE_AREA).exists())


if __name__ == '__main__':
    unittest.main()
