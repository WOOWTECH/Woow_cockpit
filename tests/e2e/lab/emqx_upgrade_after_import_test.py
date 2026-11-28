"""Offline tests of the EMQX upgrade-after-import lab driver (emqx_upgrade_after_import.py), its device side
(emqx_upgrade_device.py) and the host-side image helper (emqx_upgrade_image_prep.py).

No device, no podman, no secret: dev-d is a simulation (SimDevice) driven through the driver's own Run, the device side
runs against a temporary home with a fake command runner, the image helper against a fake host. Run through the guard
with cwd tests/e2e/lab.
"""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import unittest

HERE = Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name + '_under_test', HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drv = _load('emqx_upgrade_after_import')
prep = _load('emqx_upgrade_image_prep')


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


DIGEST = 'sha256:' + 'e' * 64          # dev-d's digest of the loaded 5.9.4 image (simulated)
NEW_REF = drv.TARGET['name'] + '@' + DIGEST
OLD_TEMPLATE = ('# Woow EMQX 5.8.9 MQTT broker\n[Container]\nContainerName=woow-emqx\n'
                'Image=docker.io/emqx/emqx:5.8.9@sha256:35b46f7aa7a0d51f3959e4344221ac5ec7f948b03e43099286b6c40a07bb393b\n'
                'PublishPort=@@EMQX_PUBLISH_MQTT@@:1883\nPublishPort=@@EMQX_PUBLISH_DASHBOARD@@:18083\n'
                'HealthCmd=emqx ctl status\nHealthInterval=30s\n')
NEW_TEMPLATE = OLD_TEMPLATE.replace('HealthCmd=emqx ctl status\n',
                                    '# The local node endpoint avoids starting another Erlang VM on each probe.\n'
                                    'HealthCmd=curl -fsS --max-time 8 -o /dev/null http://127.0.0.1:18093/status\n')
ENTRANCE_TEMPLATE = ('[Container]\nContainerName=woow-emqx-entrance\nImage=docker.io/nginxinc/nginx-unprivileged:1.27-alpine'
                     '@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0\n')
OLD_SMOKE = b'#!/usr/bin/env bash\necho old smoke\n'
SRC = {'mqtt_users': [{'user_id': 'b1-sensor', 'is_superuser': False}, {'user_id': 'b1-gateway', 'is_superuser': False},
                      {'user_id': 'b1-admin', 'is_superuser': True}],
       'retained_messages': ['b1/retained/thermostat', 'b1/retained/door'], 'rules': ['b1_rule_republish', 'b1_rule_http'],
       'dashboard_users': ['admin', 'b1ops'], 'banned': ['b1-banned-client'], 'api_keys': ['b1-import-key']}
CREDS = {'HA_BACKUP_KEY': 'ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12', 'B1_EMQX_ADMIN_PW': 'fake-ha-admin-password',
         'B1_EMQX_USER2': 'b1ops', 'B1_EMQX_USER2_PW': 'fake-ha-user2-password', 'B1_MQTT_USER1': 'b1-sensor',
         'B1_MQTT_PW1': 'fake-mqtt-pw-sensor', 'B1_MQTT_USER2': 'b1-gateway', 'B1_MQTT_PW2': 'fake-mqtt-pw-gateway',
         'B1_MQTT_USER3': 'b1-admin', 'B1_MQTT_PW3': 'fake-mqtt-pw-admin', 'B1_X86_EMQX_API_KEY': 'fake-api-key-x86',
         'B1_X86_EMQX_API_SECRET': 'fake-api-secret-x86'}


def render(text):
    return text.replace('@@EMQX_PUBLISH_MQTT@@', '127.0.0.1:1883').replace('@@EMQX_PUBLISH_DASHBOARD@@', '127.0.0.1:18083')


def meta(text, mode=0o644):
    data = text.encode() if isinstance(text, str) else text
    return {'sha256': sha(data), 'mode': mode, 'uid': 1019, 'gid': 1019, 'size': len(data)}


def job_id(n):
    return 'j20261128T15%04dZ-%08x' % (n, n)


def backup_id(n):
    return '20261128T15%04dZ-%08x' % (n, 0xb000 + n)


class FakePackage:
    """The leased package checkout: c01c897 files and two blobs of ea5886c."""

    def __init__(self, extra_image_line=False):
        self.extra = extra_image_line

    def files(self, commit):
        assert commit == drv.PACKAGE_COMMIT
        quadlet = NEW_TEMPLATE + ('Image=second\n' if self.extra else '')
        return {'quadlet/emqx.container': (quadlet.encode(), 0o664),
                'quadlet/emqx-entrance.container': (ENTRANCE_TEMPLATE.encode(), 0o664),
                'scripts/upgrade.sh': (b'#!/usr/bin/env bash\necho upgrade\n', 0o775),
                'tests/smoke.sh': (b'#!/usr/bin/env bash\necho smoke\n', 0o775),
                'README.md': (b'# Woow EMQX\n', 0o664)}

    def show(self, commit, rel):
        assert commit == drv.INSTALLED_COMMIT
        return {'tests/smoke.sh': OLD_SMOKE, 'quadlet/emqx.container': OLD_TEMPLATE.encode()}[rel]


class SimDevice:
    """dev-d for Run: the product helper, the fixed root programs, the owner operations and the probes, over a model."""

    def __init__(self, secrets, source, **knobs):
        self.secrets, self.knobs, self.calls, self.observed = secrets, knobs, [], []
        self.engine = drv.tree_engine(source)
        self.quadlet_text = render(drv.pinned(OLD_TEMPLATE, 'Image=' + drv.OLD['ref']))
        self.files = {drv.QUADLET: meta(self.quadlet_text),
                      '.config/containers/systemd/emqx-entrance.container': meta(drv.pinned(ENTRANCE_TEMPLATE, 'Image=' + drv.ENTRANCE['ref'])),
                      '.config/containers/systemd/emqx.network': meta('[Network]\n'),
                      '.config/emqx/base.hocon': meta('authentication = []\n'),
                      '.config/emqx/emqx.env': meta('EMQX_LOG__CONSOLE__LEVEL=warning\n', 0o600),
                      '.local/state/woow-quadlet/emqx/applied-env.sha256': meta('f' * 64 + '\n', 0o600)}
        self.manifest = {'/home/appowner/' + rel: m['sha256'] for rel, m in self.files.items() if '/state/' not in rel
                         and not rel.endswith('emqx.env')}
        self._manifest_meta()
        self.dirs = {'.config/emqx': 0o700, '.local/state/woow-quadlet/emqx': 0o700}
        self.images = {drv.OLD['ref']: {'present': True, 'id': drv.OLD['image_id'], 'digest': drv.OLD['ref'].split('@')[1],
                                        'tags': ['docker.io/emqx/emqx:5.8.9'], 'exists': True},
                       drv.ENTRANCE['ref']: {'present': True, 'id': drv.ENTRANCE['image_id'],
                                             'digest': drv.ENTRANCE['ref'].split('@')[1],
                                             'tags': ['docker.io/nginxinc/nginx-unprivileged:1.27-alpine'], 'exists': True}}
        if not knobs.get('no_new_image'):
            digest = knobs.get('device_digest', DIGEST)
            self.images[drv.TARGET['name']] = {'present': True, 'id': knobs.get('new_id', drv.TARGET['image_id']),
                                               'digest': digest, 'tags': [drv.TARGET['name']], 'exists': True}
            self.images[drv.TARGET['name'] + '@' + digest] = dict(self.images[drv.TARGET['name']])
        self.containers = {'woow-emqx': {'present': True, 'image_id': drv.OLD['image_id'], 'image_name': drv.OLD['ref'],
                                         'running': True},
                           'woow-emqx-entrance': {'present': True, 'image_id': drv.ENTRANCE['image_id'],
                                                  'image_name': drv.ENTRANCE['ref'], 'running': True}}
        self.units = {'emqx.service': ['active', 'running'], 'emqx-entrance.service': ['active', 'running'],
                      'emqx-data-volume.service': ['active', 'exited'], 'emqx-log-volume.service': ['active', 'exited'],
                      'emqx-network.service': ['active', 'exited']}
        self.data, self.version, self.marker = 'baseline', '5.8.9', False
        self.backups = [{'id': drv.BASELINE, 'type': 'manual', 'apps': [{'id': 'emqx'}]},
                        {'id': backup_id(900), 'type': 'manual', 'apps': [{'id': 'hermes'}]}]
        self.ha = [{'id': drv.HA_ID, 'sha256': drv.FIXTURE_SHA}] if knobs.get('ha_present') else []
        self.jobs, self.serial = {}, 0
        self.backup_root = self.backup_parent = None
        self.run = {'exists': False}
        self.captured = self.staged_quadlet = None
        self.upgrade_log = []
        self.timer_state = {'UnitFileState': 'masked', 'ActiveState': 'inactive'}
        self.catalog = {'emqx.json': 'a' * 64, 'hermes.json': 'b' * 64}
        self.initial = self.snapshot()

    # -------- model helpers
    def _manifest_meta(self):
        text = ''.join(f'{d}  {p}\n' for p, d in sorted(self.manifest.items()))
        self.files[drv.STATE_MANIFEST] = meta(text, 0o600)

    def snapshot(self):
        return copy.deepcopy({k: getattr(self, k) for k in (
            'files', 'dirs', 'manifest', 'quadlet_text', 'containers', 'units', 'data', 'version', 'marker', 'backups', 'ha',
            'backup_root', 'backup_parent', 'images', 'timer_state', 'catalog')})

    def stop(self, where):
        if self.knobs.get('stop_at') == where:
            self.knobs['stop_at'] = None
            raise drv.Stopped('signal 15')

    def next_id(self):
        self.serial += 1
        return self.serial

    def add_job(self, **job):
        job.setdefault('id', job_id(self.next_id()))
        job.setdefault('state', 'succeeded')
        self.jobs[job['id']] = job
        return job

    def restart_emqx(self):
        new = self.quadlet_text != self.initial['quadlet_text']
        self.containers['woow-emqx'] = {'present': True, 'image_id': drv.TARGET['image_id'] if new else drv.OLD['image_id'],
                                        'image_name': NEW_REF if new else drv.OLD['ref'], 'running': True}
        self.version = '5.9.4' if new else '5.8.9'

    # -------- the device interface of Run
    def isolated(self):
        return not self.knobs.get('not_isolated')

    def timer(self):
        return dict(self.timer_state)

    def helper(self, command, request=None, timeout=1800):
        request = request or {}
        self.calls.append(command)
        self.stop(command)
        if command == 'status':
            return 0, {'active_job': None, 'apps': [{'id': 'emqx', 'state': 'running', 'problems': []}]}
        if command == 'list':
            return 0, {'backups': copy.deepcopy(self.backups), 'ha_backups': copy.deepcopy(self.ha)}
        if command == 'jobs':
            return 0, {'jobs': [copy.deepcopy(job) for job in self.jobs.values()]}
        if command == 'job-status':
            self.stop('job-status:' + str(self.jobs[request['job_id']].get('type')))
            return 0, {'job': copy.deepcopy(self.jobs[request['job_id']]), 'log': []}
        if command == 'inspect':
            assert request == {'backup_id': drv.BASELINE, 'key': 'FAKE-KIT-0000-0000'}
            return 0, {'ok': True, 'preflight': {'ok': True, 'apps': [{'id': 'emqx', 'issues': []}]}}
        if command == 'ha-check-start':
            assert set(request) == {'ha_backup_id', 'apps', 'request_id', 'key'}
            section = {'mqtt_users': 3, 'acl_rules': 4, 'dashboard_users': 2, 'api_keys': 1, 'banned': 1}
            issues = [{'id': 'emqx.access-from-ha', 'level': 'auto', 'message': 'x'}]
            if self.knobs.get('check_stop'):
                issues.append({'id': 'emqx.blocked', 'level': 'stop', 'message': 'no'})
            job = self.add_job(type='verify', params={'source': 'ha', 'ha_backup_id': drv.HA_ID, 'apps': ['emqx']},
                               result={'ha_check': {'schema': 2, 'ha_backup_id': drv.HA_ID, 'shared': [],
                                                    'apps': [{'app_id': 'emqx', 'importable': True, 'issues': issues,
                                                              'emqx': section}]}})
            return 0, {'job_id': job['id']}
        if command == 'ha-import-start':
            assert request['check_job_id'] in self.jobs and request['acknowledged'] == {}
            converted, safety = backup_id(self.next_id()), backup_id(self.next_id())
            second = self.add_job(type='restore', params={'backup_id': converted, 'apps': ['emqx'], 'ha_backup_id': drv.HA_ID},
                                  result={'safety_backup_id': safety, 'rolled_back': False,
                                          'group': {'next_job_id': None, 'results': [{'app_id': 'emqx', 'status': 'imported'}]}})
            first = self.add_job(type='backup', params={'source': 'ha', 'ha_backup_id': drv.HA_ID, 'apps': ['emqx'],
                                                        'test_mode': False, 'acknowledged': {},
                                                        'chain': {'apps': ['emqx'], 'then_restore': True, 'test_mode': False,
                                                                  'acknowledged': {}}},
                                 result={'backup_id': converted, 'group': {'next_job_id': second['id']}})
            self.backups += [{'id': converted, 'type': 'manual', 'apps': [{'id': 'emqx'}]},
                             {'id': safety, 'type': 'safety', 'apps': [{'id': 'emqx'}]}]
            self.data, self.marker = 'ha', True
            self.restart_emqx()
            self.stop('ha-import-start:after')
            return 0, {'job_id': first['id'], 'group': True}
        if command == 'restore-start':
            assert request['backup_id'] == drv.BASELINE and request['key'] == 'FAKE-KIT-0000-0000'
            safety = backup_id(self.next_id())
            failed = self.knobs.get('baseline_fails')
            job = self.add_job(type='restore', state='failed' if failed else 'succeeded',
                               result={'safety_backup_id': safety, 'rolled_back': bool(failed)})
            self.backups.append({'id': safety, 'type': 'safety', 'apps': [{'id': 'emqx'}]})
            if not failed:
                self.data, self.marker = 'baseline', False
                self.restart_emqx()
            return 0, {'job_id': job['id']}
        if command == 'delete':
            self.backups = [b for b in self.backups if b['id'] != request['backup_id']]
            return 0, {}
        if command == 'ha-delete':
            self.ha = [r for r in self.ha if r['id'] != request['ha_backup_id']]
            return 0, {}
        raise AssertionError(command)

    def upload(self, path, ev):
        self.calls.append('upload')
        self.ha.append({'id': drv.HA_ID, 'sha256': drv.FIXTURE_SHA})
        return 0, {'ha_backup': {'id': drv.HA_ID}}

    def root_json(self, script, request=None, timeout=300):
        if script is drv.HEADROOM:
            return {'used': 1500 * 1024 ** 2, 'limit': 4 * 1024 ** 3}
        if script is drv.ENGINE_HASHES:
            return copy.deepcopy(self.engine)
        if script is drv.CATALOG:
            return dict(self.catalog)
        if script is drv.SIDECARS:
            return len(self.backups)
        if 'secret_scan_needles' in script:
            self.calls.append('scan')
            assert set(request['podman_secrets']) == set(drv.PODMAN_SECRETS) and request['values']
            return {'scanned': 40, 'hits': 0, 'journal_bytes': 1000, 'archive_index_sidecars_scanned': len(self.backups),
                    'regular_json_roots_scanned': 2}
        raise AssertionError('unknown root program')

    def markers(self):
        self.calls.append('markers')
        token = 'issued-device-token-%d' % len(self.observed)
        self.secrets.register_issued([token])
        self.observed.append(token)
        if self.data != 'baseline':
            raise drv.Failed('read-only marker probe failed')
        return {'mqtt_users': ['woowbk-lab-baseline'], 'retained': ['woowbk-lab/baseline'], 'banned': ['woowbk-lab-baseline'],
                'mqtt_user_count': 2}

    def probe(self, request):
        self.calls.append('probe')
        self.stop('probe:' + self.version)
        tokens = ['issued-ha-token-%d-a' % len(self.observed), 'issued-ha-token-%d-b' % len(self.observed)]
        for token in tokens:
            self.secrets.register_observed(token)
            self.observed.append(token)
        assert request['ha_admin_password'] == CREDS['B1_EMQX_ADMIN_PW']
        if self.data != 'ha':
            return {}
        acl_users = [['b1-gateway', 2], ['b1-sensor', 2]]
        if self.knobs.get('acl_lost_on_upgrade') and self.version == '5.9.4':
            acl_users = [['b1-gateway', 2]]
        users = [u for u, _p in request['mqtt']]
        return {'api_ready_after_s': 1.0, 'dashboard_admin_ha_password': 200, 'dashboard_user2_ha_password': 200,
                'dashboard_admin_device_password': 401,
                'mqtt_users': [['b1-admin', True], ['b1-gateway', False], ['b1-sensor', False], ['woow', False]],
                'authenticators': [['password_based:built_in_database', True]],
                'authz_settings': {'no_match': 'allow', 'deny_action': 'ignore'},
                'authz_sources': [['built_in_database', True], ['file', True]],
                'acl': {'users': acl_users, 'clients': [['b1-dashboard-panel', 1]], 'all': 1},
                'retained': ['$SYS/brokers', 'b1/retained/door', 'b1/retained/thermostat'],
                'rules': [['b1_rule_http', True], ['b1_rule_republish', True]],
                'connectors': [['http', 'b1_http', 'connected' if self.version == '5.8.9' else 'connecting']],
                'actions': [['http', 'b1_http_action', 'connected']], 'banned': [['clientid', 'b1-banned-client']],
                'dashboard_users': ['admin', 'b1ops'], 'api_keys': [['b1-import-key', True]],
                'nodes': [['emqx@127.0.0.1', self.version, 'running']], 'api_key_works': 200,
                'mqtt': dict({'login_' + u: 0 for u in users}, gateway_retained={'suback': 1, 'topics': [
                    'b1/retained/door', 'b1/retained/thermostat']}, sensor_denied_topic_suback=128,
                    sensor_unlisted_topic_suback=1, anonymous=4, wrong_password=4, banned_client=5, bootstrap_woow=0),
                'ctl_status': ["Node 'emqx@127.0.0.1' %s is started" % self.version]}

    def scenario_cleanup(self, ev):
        ev.check('no throwaway container, volume or network left', True)
        ev.check('no staging folder and no key file left', True)

    def op(self, op, request=None, timeout=300):
        request = request or {}
        self.calls.append('op:' + op)
        self.stop('op:' + op)
        return getattr(self, 'op_' + op.replace('-', '_'))(request)

    def op_facts(self, q):
        out = {'files': copy.deepcopy(self.files), 'dirs': dict(self.dirs), 'manifest': dict(self.manifest),
               'quadlet': {'emqx.container': {'image': [l[6:] for l in self.quadlet_text.splitlines() if l.startswith('Image=')][0],
                                              'health': [l[10:] for l in self.quadlet_text.splitlines()
                                                         if l.startswith('HealthCmd=')][0]},
                           'emqx-entrance.container': {'image': drv.ENTRANCE['ref'], 'health': None}},
               'images': {ref: copy.deepcopy(self.images.get(ref, {'present': False})) for ref in q.get('refs') or []},
               'containers': {c: dict(self.containers[c]) for c in q.get('containers') or []},
               'units': {u: list(self.units[u]) for u in q.get('units') or []},
               'marker': {'present': self.marker, 'exact': self.marker},
               'package': {'files': 60, 'digest': 'd' * 64, 'smoke_sha256': sha(OLD_SMOKE)},
               'lab_source': drv.INSTALLED_COMMIT, 'backup_root': copy.deepcopy(self.backup_root),
               'backup_parent': copy.deepcopy(self.backup_parent),
               'secrets': ['woow-emqx-dashboard-password', 'woow-emqx-mqtt-bootstrap', 'woow-emqx-mqtt-password',
                           'woow-emqx-node-cookie'],
               'volumes': ['woow_emqx_data', 'woow_emqx_log'], 'container_names': ['hermes-agent', 'woow-emqx', 'woow-emqx-entrance'],
               'image_list': sorted([v['id'], v['tags'], v['digest']] for k, v in self.images.items() if '@' not in k
                                    or k in (drv.OLD['ref'], drv.ENTRANCE['ref'])),
               'run': dict(self.run)}
        if q.get('deltas'):
            out['deltas'] = {drv.QUADLET: drv.ops.line_delta(self.captured['quadlet_text'], self.quadlet_text)}
        return out

    def op_capture(self, q):
        if self.run.get('exists'):
            raise drv.Failed('device operation capture refused: fixed-emqx-upgrade-run-dir-exists')
        self.run = {'exists': True, 'capture': True, 'staged': False, 'upgrade_started': False, 'upgrade_done': False}
        self.captured = copy.deepcopy({'files': self.files, 'dirs': self.dirs, 'manifest': self.manifest,
                                       'quadlet_text': self.quadlet_text})
        return {'files': copy.deepcopy(self.files), 'dirs': dict(self.dirs)}

    def op_stage(self, q):
        raw = base64.b64decode(q['tar_b64'])
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            got = {m.name: archive.extractfile(m).read() for m in archive}
        assert {k: [sha(v), q['files'][k][1]] for k, v in got.items()} == q['files']
        self.staged_quadlet = got['quadlet/emqx.container'].decode()
        self.run['staged'] = True
        return {'files': len(got), 'equal': not self.knobs.get('stage_differs'), 'differ': []}

    def _upgrade_lines(self, rolled_back=False):
        lines = ['upgrade.sh: podman 4.9.3 (>= 4.9)', 'backup.sh: exported the broker data',
                 'upgrade.sh: pre-upgrade data backup: /home/appowner/.local/share/woow-backups/emqx/backup-20261128-150102',
                 'upgrade.sh: saved the installed units in /home/appowner/.local/share/woow-backups/emqx/upgrade-20261128-150101/units',
                 'install.sh: changed: emqx.container', 'install.sh: restarting (changed): emqx.service',
                 'PASS A1 emqx.service is active', 'PASS A1 emqx-entrance.service is active', 'PASS A2 woow-emqx is healthy',
                 'PASS A2 woow-emqx-entrance is healthy', 'PASS A3 five ports published on 127.0.0.1',
                 'WARN A4 dashboard login skipped: this broker\'s Dashboard accounts come from a Home Assistant import',
                 'PASS A9 dashboard entrance answers HTTP 200', 'PASS A9 private endpoints return 404',
                 'PASS A9 MQTT WebSocket upgrade through /mqtt',
                 'WARN A5/A6/A10 MQTT access checks skipped: this broker\'s authentication and ACL come from a Home Assistant import',
                 'PASS A7 bootstrap CSV is 0400 emqx', 'PASS A7 base.hocon is mounted read-only',
                 'PASS A8 no secret in the journal, the container log or (for the MQTT password) podman inspect']
        if rolled_back:
            lines[-6] = 'FAIL A9 MQTT WebSocket upgrade returned HTTP 400'
            return lines + ['10 passed, 1 failed, 2 warnings',
                            'upgrade.sh: WARNING: upgrade failed; rolling back to the units saved in /x/units',
                            'PASS A1 emqx.service is active', '9 passed, 0 failed, 1 warnings (quick)',
                            'upgrade.sh: ERROR: upgrade failed and was rolled back; the previous version is running again']
        return lines + ['11 passed, 0 failed, 2 warnings',
                        'upgrade.sh: upgrade complete (unit snapshot: /home/appowner/.local/share/woow-backups/emqx/upgrade-20261128-150101)']

    def op_upgrade(self, q):
        assert q['timeout'] == drv.UPGRADE_TIMEOUT
        mode = self.knobs.get('upgrade', 'pass')
        self.run.update(upgrade_started=True)
        self.backup_parent = [['emqx', 'dir']]
        self.backup_root = [['backup-20261128-150102', 'dir'], ['upgrade-20261128-150101', 'dir']]
        if mode in ('pass', 'stop', 'secret'):
            self.quadlet_text = render(self.staged_quadlet)
            self.files[drv.QUADLET] = meta(self.quadlet_text)
            self.manifest['/home/appowner/' + drv.QUADLET] = self.files[drv.QUADLET]['sha256']
            self._manifest_meta()
            self.restart_emqx()
        if mode == 'stop':
            self.upgrade_log = self._upgrade_lines()[:5]
            raise drv.Stopped('signal 15')
        self.run.update(upgrade_done=True)
        lines = self._upgrade_lines(rolled_back=mode == 'rollback')
        if mode == 'extra-file':
            self.files['.config/emqx/surprise.conf'] = meta('x')
        return {'rc': 1 if mode == 'rollback' else 0, 'timed_out': False, 'seconds': 95.0, 'lines': lines,
                'device_secret_hits': 1 if mode == 'secret' else 0, 'truncated': False}

    def op_upgrade_log(self, q):
        return {'started': True, 'done': False, 'rc': None, 'lines': self.upgrade_log, 'device_secret_hits': 0,
                'truncated': False}

    def op_stop_upgrade(self, q):
        started = bool(self.run.get('upgrade_started'))
        running = bool(self.knobs.get('upgrade_stuck'))
        return {'started': started, 'running': running, 'was_running': started and not self.run.get('upgrade_done')}

    def op_restore_files(self, q):
        self.files = copy.deepcopy(self.captured['files'])
        self.dirs = dict(self.captured['dirs'])
        self.manifest = dict(self.captured['manifest'])
        self.quadlet_text = self.captured['quadlet_text']
        return {'written': [drv.QUADLET], 'removed': [], 'reload_rc': 0, 'equal': True,
                'files': copy.deepcopy(self.files), 'dirs': dict(self.dirs)}

    def op_ready(self, q):
        return {'ready': True, 'seconds': 2.0}

    def op_smoke(self, q):
        good = self.data == 'baseline' and self.containers['woow-emqx']['image_id'] == drv.OLD['image_id']
        lines = ['PASS A1 emqx.service is active', 'PASS A1 emqx-entrance.service is active', 'PASS A2 woow-emqx is healthy',
                 'PASS A2 woow-emqx-entrance is healthy', 'PASS A3 five ports published on 127.0.0.1',
                 'PASS A4 dashboard login with the generated password' if good else 'FAIL A4 dashboard login returned HTTP 401',
                 'PASS A4 admin/public is rejected', 'PASS A9 dashboard entrance answers HTTP 200',
                 'PASS A9 private endpoints return 404', 'PASS A9 MQTT WebSocket upgrade through /mqtt',
                 '10 passed, 0 failed, 0 warnings (quick)' if good else '9 passed, 1 failed, 0 warnings (quick)']
        return {'rc': 0 if good else 1, 'timed_out': False, 'lines': lines, 'device_secret_hits': 0, 'truncated': False}

    def op_cleanup(self, q):
        if self.backup_root is not None:
            known = {row[0] for row in q['backup_root_before'] or []}
            self.backup_root = [row for row in self.backup_root if row[0] in known] or (None if q['backup_root_before'] is None
                                                                                          else [])
        if self.backup_root is None and q['backup_parent_before'] is None:
            self.backup_parent = None
        self.run = {'exists': False}
        return {'removed': ['backup-20261128-150102'], 'unexplained': [], 'run_dir_removed': True,
                'backup_root': copy.deepcopy(self.backup_root), 'backup_parent': copy.deepcopy(self.backup_parent)}


# ---------------------------------------------------------------- the harness around Run

class Harness:
    def __init__(self, test, **knobs):
        self.tmp = Path(test.enterContext(tempfile.TemporaryDirectory()))
        secret_dir = self.tmp / 'secrets'
        secret_dir.mkdir()
        (secret_dir / 'b1-creds.env').write_text(''.join(f'{k}={v}\n' for k, v in CREDS.items() if k != 'HA_BACKUP_KEY'))
        (secret_dir / 'ha-import-creds.env').write_text(f'HA_BACKUP_KEY={CREDS["HA_BACKUP_KEY"]}\n')
        (secret_dir / 'dev-d-markers.json').write_text(json.dumps({'emqx': 'fake-marker-password'}))
        self.secrets = drv.b1.Secrets([secret_dir / 'b1-creds.env', secret_dir / 'ha-import-creds.env'],
                                      secret_dir / 'dev-d-markers.json')
        self.secrets.register('DEV_D_KIT', 'FAKE-KIT-0000-0000')
        source = self.tmp / 'product'
        (source / 'backup-engine' / 'woowbackup').mkdir(parents=True)
        (source / 'backup-engine' / 'woowbackup' / 'cli.py').write_text('# engine\n')
        (source / 'backup-engine' / 'woowtech-cockpit-backup').write_text('#!/usr/bin/env python3\n')
        self.lease = {'granted': True, 'device': drv.DEVICE, 'case': drv.CASE, 'phase': drv.PHASE, 'run_id': '0123456789ab',
                      'driver_commit': 'a' * 40, 'source': str(source), 'source_commit': 'b' * 40,
                      'package': str(self.tmp / 'package'), 'package_commit': drv.PACKAGE_COMMIT,
                      'target_image': drv.TARGET['name'], 'target_image_id': drv.TARGET['image_id'],
                      'target_device_digest': DIGEST, 'image_receipt_sha256': 'c' * 64,
                      'expires': time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time() + 7200))}
        self.dev = SimDevice(self.secrets, source, **knobs)
        self.ev = drv.Ev(self.secrets, root=self.tmp / 'evidence')
        self.receipt = drv.Receipt(self.tmp / 'run' / 'receipt.json')
        args = types.SimpleNamespace(lease_doc=self.lease, secrets=self.secrets)
        self.run = drv.Run(args, self.ev, self.dev, self.receipt, sleep=lambda _s: None,
                           host=lambda: (4 * 1024 ** 2, 100 * 1024 ** 3), src=SRC, package=FakePackage(knobs.get('extra_image')),
                           scan_text=drv.SCAN_SNIPPET.read_text(encoding='utf-8'))

    def go(self):
        drv.SIGNALS.update(recovering=False, ignored=0)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            ok = drv.run_all(self.run)
        self.stdout = out.getvalue()
        drv.SIGNALS.update(recovering=False, ignored=0)
        return ok and all(r['ok'] for r in self.ev.results)     # what main() reports (run_all and every check)

    def results(self):
        return {r['check']: r['ok'] for r in self.ev.results}

    def failed(self):
        return [r['check'] for r in self.ev.results if not r['ok']]


class DriverTests(unittest.TestCase):
    def assert_restored(self, harness):
        now, initial = harness.dev.snapshot(), harness.dev.initial
        self.assertEqual({k: v for k, v in now.items()}, initial)
        self.assertFalse(harness.dev.run.get('exists'))

    def test_upgrade_passes_with_55_checks_and_dev_d_is_restored_exactly(self):
        hn = Harness(self)
        self.assertTrue(hn.go(), hn.failed())
        self.assertEqual(len(hn.ev.results), 55)
        self.assertEqual(hn.failed(), [])
        self.assert_restored(hn)
        receipt = json.loads(hn.receipt.path.read_text())
        self.assertTrue(receipt['complete'] and receipt['restored'] and receipt['cleaned'])
        calls = hn.dev.calls
        self.assertEqual(calls.count('op:upgrade'), 1)
        self.assertLess(calls.index('op:capture'), calls.index('upload'))
        self.assertLess(calls.index('ha-import-start'), calls.index('op:upgrade'))
        self.assertLess(calls.index('op:upgrade'), calls.index('op:restore-files'))
        self.assertLess(calls.index('op:restore-files'), calls.index('restore-start'))
        self.assertIn('op:stop-upgrade', calls)
        # every stdout line is a fixed status line of services_a_capture's vocabulary
        capture = _load('services_a_capture')
        for line in hn.stdout.splitlines():
            self.assertTrue(capture.status_lines(line), line)
        for r in hn.ev.results:
            self.assertLessEqual(len(r['check']), 140)

    def test_protected_existing_ha_record_is_used_and_kept(self):
        hn = Harness(self, ha_present=True)
        self.assertTrue(hn.go(), hn.failed())
        self.assertNotIn('upload', hn.dev.calls)
        self.assertNotIn('ha-delete', hn.dev.calls)
        self.assertEqual(hn.dev.ha, [{'id': drv.HA_ID, 'sha256': drv.FIXTURE_SHA}])

    def test_rolled_back_upgrade_is_a_fail_and_everything_is_restored(self):
        hn = Harness(self, upgrade='rollback')
        self.assertFalse(hn.go())
        results = hn.results()
        self.assertFalse(results['upgrade: scripts/upgrade.sh of the 5.9.4 copy ran as appowner and exited 0 within its time'])
        self.assertFalse(results['upgrade: it was not rolled back (upgrade complete reported, no rollback line)'])
        self.assertFalse(results['upgrade: its smoke.sh lines are exactly the imported set: A4 and A5/A6/A10 WARN, 11 PASS, 0 FAIL'])
        self.assertNotIn('after upgrade: the node reports EMQX 5.9.4 (was 5.8.9), the same node name, started', results)
        self.assert_restored(hn)
        self.assertTrue(json.loads(hn.receipt.path.read_text())['complete'])

    def test_missing_new_image_refuses_before_any_change(self):
        for knobs in ({'no_new_image': True}, {'device_digest': 'sha256:' + '9' * 64}, {'new_id': 'f' * 64}):
            with self.subTest(knobs=knobs):
                hn = Harness(self, **knobs)
                self.assertFalse(hn.go())
                self.assertIn('preflight: the new image emqx:5.9.4 is in dev-d\'s owner store with the pinned ID and the '
                              'leased digest (tag and digest resolve)', hn.failed())
                for call in ('op:capture', 'upload', 'ha-check-start', 'ha-import-start', 'op:upgrade', 'restore-start',
                             'delete'):
                    self.assertNotIn(call, hn.dev.calls)
                self.assertFalse(hn.receipt.path.exists())
                self.assert_restored(hn)

    def test_a_stop_in_every_phase_restores_dev_d(self):
        # (where, knobs, the baseline is restored, the upgrade process is stopped)
        cases = [('capture', {'stop_at': 'op:capture'}, False, False),
                 ('stage', {'stop_at': 'op:stage'}, False, False),
                 ('check', {'stop_at': 'ha-check-start'}, False, False),
                 ('import reply lost', {'stop_at': 'ha-import-start:after'}, True, False),
                 ('import restore job', {'stop_at': 'job-status:restore'}, True, False),
                 ('import probe', {'stop_at': 'probe:5.8.9'}, True, False),
                 ('upgrade not started', {'stop_at': 'op:upgrade'}, True, True),
                 ('upgrade half done', {'upgrade': 'stop'}, True, True),
                 ('upgraded probe', {'stop_at': 'probe:5.9.4'}, True, True)]
        for where, knobs, data_touched, upgrade in cases:
            with self.subTest(stop=where):
                hn = Harness(self, **knobs)
                self.assertFalse(hn.go())
                self.assertEqual(['run stopped in a step (Stopped)'], hn.failed(), where)
                self.assert_restored(hn)
                calls = hn.dev.calls
                self.assertEqual('restore-start' in calls, data_touched, where)
                self.assertEqual('op:stop-upgrade' in calls, upgrade, where)
                self.assertEqual('op:upgrade-log' in calls, upgrade and where != 'upgraded probe', where)
                self.assertTrue(json.loads(hn.receipt.path.read_text())['complete'], where)
                self.assertFalse(hn.receipt.pending(), where)

    def test_check_stop_line_imports_nothing_and_restores(self):
        hn = Harness(self, check_stop=True)
        self.assertFalse(hn.go())
        self.assertIn('import: the check calls EMQX importable, nothing stops it, every confirmation line keyed', hn.failed())
        self.assertNotIn('ha-import-start', hn.dev.calls)
        self.assertNotIn('restore-start', hn.dev.calls)
        self.assert_restored(hn)

    def test_upgrade_changing_another_file_is_a_fail(self):
        hn = Harness(self, upgrade='extra-file')
        self.assertFalse(hn.go())
        self.assertIn('upgrade: only emqx.container (Image= and HealthCmd lines, the template diff) and the Quadlet '
                      'manifest changed, all else byte for byte', hn.failed())
        self.assert_restored(hn)

    def test_secret_in_upgrade_output_is_a_fail(self):
        hn = Harness(self, upgrade='secret')
        self.assertFalse(hn.go())
        self.assertEqual(['upgrade: no dev-d EMQX secret value in the upgrade output', 'run stopped in a step (Failed)'],
                         hn.failed())
        self.assert_restored(hn)

    def test_lost_imported_data_after_the_upgrade_is_a_fail(self):
        hn = Harness(self, acl_lost_on_upgrade=True)
        self.assertFalse(hn.go())
        self.assertIn('after upgrade: Dashboard and MQTT accounts, authenticators, authorization settings, sources and ACL '
                      'rows exactly as after the import', hn.failed())
        self.assert_restored(hn)

    def test_failed_baseline_restore_keeps_everything_for_the_coordinator(self):
        hn = Harness(self, baseline_fails=True)
        self.assertFalse(hn.go())
        receipt = json.loads(hn.receipt.path.read_text())
        self.assertFalse(receipt['complete'])
        self.assertTrue(receipt['created_backups'])
        self.assertNotIn('delete', hn.dev.calls)
        self.assertNotIn('op:cleanup', hn.dev.calls)
        self.assertTrue(hn.receipt.pending())

    def test_a_stuck_upgrade_process_stops_the_recovery_before_any_restore(self):
        hn = Harness(self, upgrade='stop', upgrade_stuck=True)
        self.assertFalse(hn.go())
        calls = hn.dev.calls
        self.assertNotIn('op:restore-files', calls)
        self.assertNotIn('restore-start', calls)
        self.assertFalse(json.loads(hn.receipt.path.read_text())['complete'])

    def test_staging_refuses_a_package_with_two_image_lines(self):
        hn = Harness(self, extra_image=True)
        self.assertFalse(hn.go())
        self.assertNotIn('op:stage', hn.dev.calls)
        self.assert_restored(hn)

    def test_a_leftover_run_folder_refuses_before_any_change(self):
        hn = Harness(self)
        hn.dev.run = {'exists': True, 'capture': True}
        self.assertFalse(hn.go())
        self.assertNotIn('op:capture', hn.dev.calls)
        self.assertNotIn('op:restore-files', hn.dev.calls)
        self.assertFalse(hn.receipt.path.exists())

    def test_not_isolated_refuses_before_any_change(self):
        hn = Harness(self, not_isolated=True)
        self.assertFalse(hn.go())
        self.assertEqual(hn.dev.calls, [])

    def test_upgrade_output_and_evidence_never_hold_a_registered_value(self):
        hn = Harness(self)
        self.assertTrue(hn.go(), hn.failed())
        values = [v for v in hn.secrets.secret_values() if len(v) >= 6]
        self.assertEqual(drv.scan_evidence(hn.ev.dir, values)['hits'], 0)
        for path in hn.ev.dir.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, path.name)
        self.assertEqual(hn.ev.dir.stat().st_mode & 0o777, 0o700)


class PureTests(unittest.TestCase):
    def lease(self, **changes):
        now = time.time()
        lease = {'granted': True, 'device': drv.DEVICE, 'case': drv.CASE, 'phase': drv.PHASE, 'run_id': 'abcdef012345',
                 'driver_commit': 'a' * 40, 'source': '/tmp/product', 'source_commit': 'b' * 40, 'package': '/tmp/package',
                 'package_commit': drv.PACKAGE_COMMIT, 'target_image': drv.TARGET['name'],
                 'target_image_id': drv.TARGET['image_id'], 'target_device_digest': DIGEST,
                 'image_receipt_sha256': 'c' * 64,
                 'expires': time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(now + 120 * 60))}
        lease.update(changes)
        return lease, now

    def test_lease_validation(self):
        lease, now = self.lease()
        self.assertIs(drv.validate_lease(lease, driver_commit='a' * 40, now=now), lease)
        bad = [{'granted': False}, {'device': 'woowbk-dev-c'}, {'case': 'page-emqx'}, {'run_id': 'xyz'},
               {'driver_commit': 'd' * 40}, {'source': 'relative/path'}, {'package_commit': 'e' * 40},
               {'target_image': 'docker.io/emqx/emqx:5.9.3'}, {'target_image_id': 'f' * 64},
               {'target_device_digest': 'sha256:short'}, {'image_receipt_sha256': None},
               {'expires': time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(now + 7200))},
               {'expires': time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(now + 30 * 60))},
               {'expires': time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(now + 400 * 60))}]
        for change in bad:
            with self.subTest(change=change):
                broken, now = self.lease(**change)
                with self.assertRaises(ValueError):
                    drv.validate_lease(broken, driver_commit='a' * 40, now=now)

    def test_image_receipt_binding(self):
        lease, _now = self.lease()
        doc = {'device': drv.DEVICE, 'image': drv.TARGET['name'], 'image_id': drv.TARGET['image_id'],
               'index_digest': drv.TARGET['index_digest'], 'device_digest': DIGEST, 'loaded': True, 'removed': False}
        raw = json.dumps(doc).encode()
        lease['image_receipt_sha256'] = sha(raw)
        self.assertTrue(drv.image_receipt_ok(raw, lease))
        self.assertFalse(drv.image_receipt_ok(raw + b' ', lease))
        for change in ({'device_digest': 'sha256:' + '1' * 64}, {'removed': True}, {'loaded': False}):
            other = json.dumps(dict(doc, **change)).encode()
            self.assertFalse(drv.image_receipt_ok(other, dict(lease, image_receipt_sha256=sha(other))))

    def test_lease_template_is_not_granted(self):
        doc = drv.lease_template(driver_commit='a' * 40, source='/s', source_commit='b' * 40, package='/p',
                                 receipt_sha='c' * 64, run_id='0123456789ab', minutes=120)
        self.assertFalse(doc['granted'])
        self.assertEqual(doc['package_commit'], drv.PACKAGE_COMMIT)

    def test_upgrade_judgement(self):
        dev = SimDevice.__new__(SimDevice)
        lines = SimDevice._upgrade_lines(dev)
        verdict = drv.judge_upgrade({'rc': 0, 'timed_out': False, 'lines': lines, 'device_secret_hits': 0, 'truncated': False})
        self.assertTrue(verdict['exit_zero'] and verdict['complete'] and verdict['smoke_exact'] and verdict['secret_free'])
        self.assertEqual((verdict['snapshot'], verdict['data_backup']), ('upgrade-20261128-150101', 'backup-20261128-150102'))
        rolled = drv.judge_upgrade({'rc': 1, 'timed_out': False, 'lines': SimDevice._upgrade_lines(dev, True),
                                    'device_secret_hits': 0, 'truncated': False})
        self.assertTrue(rolled['rolled_back'])
        self.assertFalse(rolled['complete'] or rolled['smoke_exact'] or rolled['exit_zero'])
        for broken in (lines[:-3] + lines[-2:], lines + ['PASS A5 anonymous MQTT is refused'],
                       [line.replace('WARN A4', 'FAIL A4') for line in lines]):
            self.assertFalse(drv.judge_upgrade({'rc': 0, 'timed_out': False, 'lines': broken, 'device_secret_hits': 0,
                                                'truncated': False})['smoke_exact'])
        self.assertFalse(drv.judge_upgrade({'rc': 0, 'timed_out': True, 'lines': lines, 'device_secret_hits': 0,
                                            'truncated': False})['exit_zero'])

    def test_restore_smoke_judgement(self):
        dev = SimDevice.__new__(SimDevice)
        dev.data, dev.containers = 'baseline', {'woow-emqx': {'image_id': drv.OLD['image_id']}}
        self.assertTrue(drv.judge_restore_smoke(SimDevice.op_smoke(dev, {}))[0])
        dev.data = 'ha'
        self.assertFalse(drv.judge_restore_smoke(SimDevice.op_smoke(dev, {}))[0])

    def test_repin_changes_only_the_two_image_lines(self):
        files = FakePackage().files(drv.PACKAGE_COMMIT)
        lines = {'quadlet/emqx.container': 'Image=' + NEW_REF, 'quadlet/emqx-entrance.container': 'Image=' + drv.ENTRANCE['ref']}
        staged, report = drv.repin(files, lines)
        self.assertTrue(drv.repin_exact(files, staged, lines))
        self.assertEqual(report['quadlet/emqx.container']['new'], 'Image=' + NEW_REF)
        self.assertFalse(drv.repin_exact(files, dict(staged, **{'README.md': (b'x', 0o664)}), lines))
        with self.assertRaises(drv.Failed):
            drv.repin(FakePackage(extra_image_line=True).files(drv.PACKAGE_COMMIT), lines)
        tar_b64, expected = drv.pack(staged)
        self.assertEqual(expected['scripts/upgrade.sh'][1], True)
        self.assertEqual(expected['README.md'][1], False)
        with tarfile.open(fileobj=io.BytesIO(base64.b64decode(tar_b64))) as archive:
            modes = {m.name: m.mode for m in archive}
        self.assertEqual(modes['scripts/upgrade.sh'], 0o755)
        self.assertEqual(modes['README.md'], 0o644)

    def test_expected_quadlet_delta_is_the_template_diff_with_the_device_pins(self):
        staged = drv.pinned(NEW_TEMPLATE, 'Image=' + NEW_REF)
        want = drv.ops.line_delta(drv.pinned(OLD_TEMPLATE, 'Image=' + drv.OLD['ref']), staged)
        self.assertEqual(want['removed'], sorted(['HealthCmd=emqx ctl status', 'Image=' + drv.OLD['ref']]))
        self.assertEqual(want['added'], sorted(['# The local node endpoint avoids starting another Erlang VM on each probe.',
                                                'HealthCmd=curl -fsS --max-time 8 -o /dev/null http://127.0.0.1:18093/status',
                                                'Image=' + NEW_REF]))
        rendered = drv.ops.line_delta(render(drv.pinned(OLD_TEMPLATE, 'Image=' + drv.OLD['ref'])), render(staged))
        self.assertEqual(rendered, want)

    def test_manifest_follows_only_the_quadlet(self):
        before = {'/home/appowner/' + drv.QUADLET: 'a' * 64, '/home/appowner/.config/emqx/base.hocon': 'b' * 64}
        files = {drv.QUADLET: {'sha256': 'c' * 64}}
        self.assertTrue(drv.manifest_follows(before, dict(before, **{'/home/appowner/' + drv.QUADLET: 'c' * 64}), files))
        self.assertFalse(drv.manifest_follows(before, dict(before, **{'/home/appowner/.config/emqx/base.hocon': 'c' * 64}), files))
        self.assertFalse(drv.manifest_follows(before, None, files))

    def test_imported_view_ignores_status_words_and_sys_topics(self):
        dev = SimDevice.__new__(SimDevice)
        dev.knobs, dev.observed, dev.data = {}, [], 'ha'
        dev.calls = []
        dev.secrets = types.SimpleNamespace(register_observed=lambda value: None)
        dev.version = '5.8.9'
        before = drv.imported_view(SimDevice.probe(dev, {'ha_admin_password': CREDS['B1_EMQX_ADMIN_PW'],
                                                         'mqtt': [['b1-sensor', 'x'], ['b1-gateway', 'x'], ['b1-admin', 'x']]}))
        dev.version = '5.9.4'
        after = drv.imported_view(SimDevice.probe(dev, {'ha_admin_password': CREDS['B1_EMQX_ADMIN_PW'],
                                                        'mqtt': [['b1-sensor', 'x'], ['b1-gateway', 'x'], ['b1-admin', 'x']]}))
        self.assertEqual(before['data'], after['data'])          # connector status words differ, names do not
        self.assertNotIn('$SYS/brokers', before['data']['retained'])
        self.assertTrue(drv.ha_data_ok(before, SRC) and drv.ha_mqtt_ok(before, SRC))
        self.assertEqual(drv.node_version(before), ['5.8.9'])
        self.assertEqual(drv.node_version(after), ['5.9.4'])
        broken = copy.deepcopy(before)
        broken['accounts']['mqtt_users'].append(['woowbk-lab-baseline', False])
        self.assertFalse(drv.ha_data_ok(broken, SRC))

    def test_literal_helper_requests_use_only_schema_fields(self):
        sys.path.insert(0, str(HERE.parents[2] / 'backup-engine'))
        try:
            from woowbackup import cli
        finally:
            sys.path.pop(0)
        shapes = _load_shapes()
        found = shapes.literal_requests(HERE / 'emqx_upgrade_after_import.py')
        self.assertGreaterEqual(len(found), 8)
        for line, command, fields in found:
            self.assertIn(command, cli.SPECS, line)
            self.assertLessEqual(fields, set(cli.SPECS[command]), (line, command))

    def test_self_check(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(drv.self_check(), 0)


class RealPackageTests(unittest.TestCase):
    """The staging rules on the real Woow_podman_emqx objects (git only, read-only), when that checkout is here."""

    PACKAGE = Path(os.environ.get('WOOWBK_EMQX_PACKAGE', '/tmp/parity-emqx-pkg-main-20261128'))

    def setUp(self):
        if not (self.PACKAGE / '.git').exists():
            self.skipTest('no Woow_podman_emqx checkout here')
        self.source = drv.PackageSource(self.PACKAGE)
        if subprocess.run(['git', '-C', str(self.PACKAGE), 'cat-file', '-e', drv.PACKAGE_COMMIT + '^{commit}'],
                          capture_output=True).returncode != 0:
            self.skipTest('the checkout lacks the pinned package commit')

    def test_the_real_tree_repins_exactly_two_lines_and_the_delta_is_the_health_and_image_lines(self):
        files = self.source.files(drv.PACKAGE_COMMIT)
        self.assertIn('scripts/upgrade.sh', files)
        self.assertTrue(files['scripts/upgrade.sh'][1] & 0o111)
        lines = {'quadlet/emqx.container': 'Image=' + NEW_REF, 'quadlet/emqx-entrance.container': 'Image=' + drv.ENTRANCE['ref']}
        staged, report = drv.repin(files, lines)
        self.assertTrue(drv.repin_exact(files, staged, lines))
        self.assertEqual(report['quadlet/emqx.container']['old'],
                         'Image=docker.io/emqx/emqx:5.8.9@sha256:35b46f7aa7a0d51f3959e4344221ac5ec7f948b03e43099286b6c40a07bb393b')
        old = self.source.show(drv.INSTALLED_COMMIT, 'quadlet/emqx.container').decode()
        want = drv.ops.line_delta(drv.pinned(old, 'Image=' + drv.OLD['ref']), staged['quadlet/emqx.container'][0].decode())
        self.assertEqual(want['removed'], sorted(['HealthCmd=emqx ctl status', 'Image=' + drv.OLD['ref']]))
        self.assertEqual(want['added'], sorted(['# The local node endpoint avoids starting another Erlang VM on each probe.',
                                                'HealthCmd=curl -fsS --max-time 8 -o /dev/null http://127.0.0.1:18093/status',
                                                'Image=' + NEW_REF]))
        smoke = files['tests/smoke.sh'][0].decode()
        self.assertIn('woow-ha-import.json', smoke)          # PR #11: the import marker turns A4/A5/A6/A10 into warnings
        self.assertIn('if podman image exists "$img" >/dev/null 2>&1; then continue; fi',
                      files['scripts/lib/quadlet-lib.sh'][0].decode())   # ql_pull_images skips present images
        tar_b64, expected = drv.pack(staged)
        self.assertEqual(len(expected), len(files))
        self.assertLess(len(tar_b64), 4 * 1024 * 1024)
        self.assertTrue(self.source.show(drv.INSTALLED_COMMIT, 'tests/smoke.sh'))


def _load_shapes():
    spec = importlib.util.spec_from_file_location('lab_request_shapes_for_emqx_upgrade',
                                                  HERE.parents[1] / 'backup' / 'test_lab_request_shapes.py')
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(HERE.parents[2] / 'backup-engine'))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


# ---------------------------------------------------------------- the device side, on a temporary home

class FakeRun:
    """podman/systemctl as the device side calls them; every call is recorded."""

    def __init__(self, secrets=None):
        self.calls, self.secrets = [], secrets or {}
        self.reload_rc = 0

    def __call__(self, argv, *, timeout=120, data=None):
        self.calls.append(list(argv))
        if argv[:4] == ['podman', 'secret', 'inspect', '--showsecret']:
            value = self.secrets.get(argv[-1])
            return (0, (value + '\n').encode()) if value is not None else (125, b'')
        if argv[:3] == ['systemctl', '--user', 'daemon-reload']:
            return self.reload_rc, b''
        if argv[:3] == ['systemctl', '--user', 'show']:
            units = argv[argv.index('--') + 1:]
            return 0, '\n\n'.join(f'Id={u}\nActiveState=active\nSubState=running' for u in units).encode()
        if argv[:3] == ['podman', 'image', 'inspect']:
            return (0, ('%s|sha256:%s|["%s"]' % ('a' * 64, 'b' * 64, argv[-1].split('@')[0])).encode())
        if argv[:3] == ['podman', 'image', 'exists']:
            return 0, b''
        if argv[:3] == ['podman', 'container', 'inspect']:
            return 0, ('%s|%s|true' % ('c' * 64, 'docker.io/emqx/emqx:5.8.9')).encode()
        if argv[:3] == ['podman', 'exec', 'woow-emqx']:
            return (1, b'') if 'test' in argv else (1, b'')
        if argv[:3] == ['podman', 'secret', 'ls']:
            return 0, b'woow-emqx-node-cookie\nother\nwoow-emqx-dashboard-password\n'
        if argv[:3] == ['podman', 'volume', 'ls']:
            return 0, b'woow_emqx_data\nwoow_emqx_log\nhermes-data\n'
        if argv[:2] == ['podman', 'ps']:
            return 0, b'woow-emqx\nwoow-emqx-entrance\n'
        if argv[:3] == ['podman', 'image', 'ls']:
            return 0, json.dumps([{'Id': 'a' * 64, 'Names': ['docker.io/emqx/emqx:5.8.9'], 'Digest': 'sha256:' + 'b' * 64}]).encode()
        if argv[:3] == ['podman', 'healthcheck', 'run']:
            return 0, b''
        raise AssertionError(argv)


class DeviceTests(unittest.TestCase):
    def setUp(self):
        self.dev = _load('emqx_upgrade_device')
        self.home = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.dev.HOME_OVERRIDE = str(self.home)
        self.run = FakeRun({'woow-emqx-dashboard-password': 'device-dashboard-secret-0001',
                            'woow-emqx-node-cookie': 'device-cookie-secret-0002'})
        self.dev.RUN = self.run
        for rel, text, mode in (('.config/containers/systemd/emqx.container', 'Image=old\n', 0o644),
                                ('.config/containers/systemd/emqx-entrance.container', 'Image=nginx\n', 0o644),
                                ('.config/containers/systemd/hermes.container', 'Image=hermes\n', 0o644),
                                ('.config/emqx/emqx.env', 'EMQX_LOG__CONSOLE__LEVEL=warning\n', 0o600),
                                ('.local/state/woow-quadlet/emqx/manifest', 'a' * 64 + '  /x\n', 0o600),
                                ('Woow_podman_emqx/tests/smoke.sh', '#!/bin/sh\n', 0o755),
                                ('Woow_podman_emqx.lab-source', drv.INSTALLED_COMMIT + '\n', 0o644)):
            path = self.home / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            os.chmod(path, mode)
        os.chmod(self.home / '.config/emqx', 0o700)
        os.chmod(self.home / '.local/state/woow-quadlet/emqx', 0o700)

    def q(self, op, **fields):
        return dict(fields, op=op, run_id='0123456789ab')

    def test_walk_selects_only_emqx_files(self):
        files, dirs = self.dev.walk()
        self.assertEqual(sorted(files), ['.config/containers/systemd/emqx-entrance.container',
                                         '.config/containers/systemd/emqx.container', '.config/emqx/emqx.env',
                                         '.local/state/woow-quadlet/emqx/manifest'])
        self.assertEqual(files['.config/emqx/emqx.env']['mode'], 0o600)
        self.assertEqual(sorted(dirs), ['.config/emqx', '.local/state/woow-quadlet/emqx'])
        os.symlink('/etc/passwd', self.home / '.config/emqx/link.conf')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.dev.walk()

    def test_capture_then_restore_files_is_exact(self):
        before = self.dev.walk()
        captured = self.dev.dispatch(self.q('capture'))
        self.assertEqual((captured['files'], captured['dirs']), before)
        run_dir = self.home / 'woowbk-emqx-upgrade-0123456789ab'
        self.assertEqual(run_dir.stat().st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(ValueError, 'run-dir-exists'):
            self.dev.dispatch(self.q('capture'))
        (self.home / '.config/containers/systemd/emqx.container').write_text('Image=new\n')
        os.chmod(self.home / '.config/emqx/emqx.env', 0o644)
        (self.home / '.local/state/woow-quadlet/emqx/lock.d').mkdir()
        (self.home / '.local/state/woow-quadlet/emqx/lock.d/owner').write_text('x')
        (self.home / '.config/systemd/user/emqx.service.d').mkdir(parents=True)
        (self.home / '.config/systemd/user/emqx.service.d/x.conf').write_text('[Service]\n')
        self.assertNotEqual(self.dev.walk(), before)
        result = self.dev.dispatch(self.q('restore-files'))
        self.assertTrue(result['equal'])
        self.assertEqual(self.dev.walk(), before)
        self.assertEqual(result['reload_rc'], 0)
        self.assertIn(['systemctl', '--user', 'daemon-reload'], self.run.calls)
        self.assertEqual((self.home / '.config/containers/systemd/hermes.container').read_text(), 'Image=hermes\n')

    def test_facts_and_deltas(self):
        self.dev.dispatch(self.q('capture'))
        (self.home / '.config/containers/systemd/emqx.container').write_text('Image=new\nHealthCmd=curl\n')
        facts = self.dev.dispatch(self.q('facts', refs=['docker.io/emqx/emqx:5.9.4@sha256:' + 'e' * 64],
                                         containers=['woow-emqx'], units=['emqx.service'],
                                         deltas=['.config/containers/systemd/emqx.container']))
        self.assertEqual(facts['deltas']['.config/containers/systemd/emqx.container'],
                         {'removed': ['Image=old'], 'added': ['HealthCmd=curl', 'Image=new']})
        self.assertEqual(facts['secrets'], ['woow-emqx-dashboard-password', 'woow-emqx-node-cookie'])
        self.assertEqual(facts['volumes'], ['woow_emqx_data', 'woow_emqx_log'])
        self.assertEqual(facts['lab_source'], drv.INSTALLED_COMMIT)
        self.assertEqual(facts['marker'], {'present': False, 'exact': False})
        self.assertEqual(facts['units'], {'emqx.service': ['active', 'running']})
        self.assertEqual(facts['quadlet']['emqx.container'], {'image': 'new', 'health': 'curl'})
        self.assertEqual(facts['run'], {'exists': True, 'capture': True, 'staged': False, 'upgrade_started': False,
                                        'upgrade_done': False})
        self.assertIsNone(facts['backup_root'])
        json.dumps(facts)

    def stage_tar(self, files):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for name, (data, mode) in files.items():
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), mode
                archive.addfile(info, io.BytesIO(data))
        return base64.b64encode(buffer.getvalue()).decode()

    def test_stage_checks_every_file_and_refuses_bad_members(self):
        self.dev.dispatch(self.q('capture'))
        files = {'scripts/upgrade.sh': (b'#!/bin/sh\necho ok\n', 0o755), 'README.md': (b'x', 0o644)}
        expected = {name: [sha(data), bool(mode & 0o111)] for name, (data, mode) in files.items()}
        result = self.dev.dispatch(self.q('stage', tar_b64=self.stage_tar(files), files=expected))
        self.assertTrue(result['equal'])
        staged = self.home / 'woowbk-emqx-upgrade-0123456789ab/Woow_podman_emqx/scripts/upgrade.sh'
        self.assertEqual(staged.stat().st_mode & 0o777, 0o755)
        with self.assertRaisesRegex(ValueError, 'stage-exists'):
            self.dev.dispatch(self.q('stage', tar_b64=self.stage_tar(files), files=expected))
        for run_id, name in (('0123456789ac', '../escape'), ('0123456789ad', '/abs/path')):
            q = dict(self.q('stage', tar_b64=self.stage_tar({name: (b'x', 0o644)}), files={name: [sha(b'x'), False]}),
                     run_id=run_id)
            self.dev.capture(q)
            with self.assertRaisesRegex(ValueError, 'stage-member-name'):
                self.dev.stage(q)

    def write_upgrade(self, body):
        self.dev.dispatch(self.q('capture'))
        script = self.home / 'woowbk-emqx-upgrade-0123456789ab/Woow_podman_emqx/scripts/upgrade.sh'
        script.parent.mkdir(parents=True)
        script.write_text('#!/bin/sh\n' + body)
        os.chmod(script, 0o755)

    def test_upgrade_runs_the_staged_script_and_blanks_dev_d_secrets(self):
        self.write_upgrade('echo "PASS A1 emqx.service is active"\necho "leak device-dashboard-secret-0001"\nexit 0\n')
        result = self.dev.dispatch(self.q('upgrade', timeout=600))
        self.assertEqual(result['rc'], 0)
        self.assertFalse(result['timed_out'])
        self.assertEqual(result['device_secret_hits'], 1)
        self.assertIn('leak ' + self.dev.BLANK, result['lines'])
        self.assertNotIn('device-dashboard-secret-0001', json.dumps(result))
        run_dir = self.home / 'woowbk-emqx-upgrade-0123456789ab'
        self.assertTrue((run_dir / 'upgrade.done').exists())
        self.assertEqual((run_dir / 'upgrade.log').stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ValueError, 'already-started'):
            self.dev.dispatch(self.q('upgrade', timeout=600))
        self.assertEqual(self.dev.dispatch(self.q('stop-upgrade')), {'started': True, 'running': False, 'was_running': False})
        log = self.dev.dispatch(self.q('upgrade-log'))
        self.assertTrue(log['done'] and log['rc'] == 0)

    def test_upgrade_timeout_stops_the_whole_group(self):
        self.write_upgrade('sleep 60 &\nsleep 60\n')
        original = self.dev.bounded
        self.dev.bounded = lambda value, low, high: value
        try:
            started = time.monotonic()
            result = self.dev.dispatch(self.q('upgrade', timeout=1))
        finally:
            self.dev.bounded = original
        self.assertTrue(result['timed_out'])
        self.assertLess(time.monotonic() - started, 40)
        self.assertNotEqual(result['rc'], 0)

    def test_stop_upgrade_kills_a_recorded_running_group(self):
        self.dev.dispatch(self.q('capture'))
        proc = subprocess.Popen(['sleep', '60'], start_new_session=True)
        try:
            run_dir = self.home / 'woowbk-emqx-upgrade-0123456789ab'
            ticks = self.dev.start_ticks(proc.pid)
            (run_dir / 'upgrade.pid').write_text(f'{proc.pid} {ticks}\n')
            with self.assertRaisesRegex(ValueError, 'upgrade-still-running'):
                self.dev.dispatch(self.q('cleanup', backup_root_before=None, backup_parent_before=None, remove_run_dir=True))
            waiter = __import__('threading').Thread(target=proc.wait)
            waiter.start()
            result = self.dev.dispatch(self.q('stop-upgrade'))
            waiter.join(20)
            self.assertTrue(result['was_running'])
            self.assertFalse(result['running'])
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_cleanup_removes_only_the_runs_package_folders(self):
        self.dev.dispatch(self.q('capture'))
        root = self.home / '.local/share/woow-backups/emqx'
        for name in ('backup-20261128-150102', 'upgrade-20261128-150101', 'notes'):
            (root / name).mkdir(parents=True)
            (root / name / 'f').write_text('x')
        result = self.dev.dispatch(self.q('cleanup', backup_root_before=None, backup_parent_before=None, remove_run_dir=True))
        self.assertEqual(sorted(result['removed']), ['backup-20261128-150102', 'upgrade-20261128-150101'])
        self.assertEqual(result['unexplained'], ['notes'])
        self.assertTrue(result['run_dir_removed'])
        self.assertEqual(result['backup_root'], [['notes', 'dir']])
        (root / 'notes' / 'f').unlink()
        (root / 'notes').rmdir()
        result = self.dev.dispatch(self.q('cleanup', backup_root_before=None, backup_parent_before=None))
        self.assertIsNone(result['backup_root'])
        self.assertIsNone(result['backup_parent'])
        (root / 'backup-20261101-000000').mkdir(parents=True)
        result = self.dev.dispatch(self.q('cleanup', backup_root_before=[['backup-20261101-000000', 'dir']],
                                          backup_parent_before=[['emqx', 'dir']]))
        self.assertEqual(result['backup_root'], [['backup-20261101-000000', 'dir']])

    def test_ready_waits_for_the_api_routes(self):
        answers = iter([(200, 404), (200, 404), (200, 401)])
        seen = []

        def http_code(url):
            if not seen or seen[-1][1] is not None:
                seen.append([next(answers), None])
            pair = seen[-1][0]
            if url.endswith('api/v5/nodes'):
                seen[-1][1] = True
                return pair[1]
            return pair[0]
        original, sleep = self.dev.http_code, self.dev.time.sleep
        self.dev.http_code, self.dev.time.sleep = http_code, lambda _s: None
        try:
            result = self.dev.dispatch(self.q('ready', timeout=60))
        finally:
            self.dev.http_code, self.dev.time.sleep = original, sleep
        self.assertTrue(result['ready'])
        self.assertEqual(len(seen), 3)
        self.assertEqual(sum(1 for call in self.run.calls if call[:3] == ['podman', 'healthcheck', 'run']), 3)

    def test_dispatch_refuses_unknown_operations_and_run_ids(self):
        with self.assertRaisesRegex(ValueError, 'operation'):
            self.dev.dispatch({'op': 'rm', 'run_id': '0123456789ab'})
        with self.assertRaisesRegex(ValueError, 'run-id'):
            self.dev.dispatch({'op': 'facts', 'run_id': '../x'})

    def test_device_program_compiles_and_fits_one_argument(self):
        program = (HERE / 'emqx_upgrade_device.py').read_text() + self.dev.ENTRY
        compile(program, '<device>', 'exec')
        self.assertLess(len(program.encode()), 120 * 1024)


# ---------------------------------------------------------------- the image helper

class FakeHost:
    def __init__(self, *, lab=True, device=None, free=100 * 1024 ** 3, users=''):
        self.calls, self.lab, self.device, self.disk, self.users = [], lab, device, free, users
        self.locked = 0

    def run(self, argv, *, timeout=600, data=None):
        self.calls.append(argv)
        tail = argv[1:]
        if tail[:2] == ['image', 'inspect'] and tail[-1] in (prep.PULL_REF, prep.IMAGE_ID):
            return (0, f'{prep.IMAGE_ID}|linux|amd64'.encode()) if self.lab else (125, b'')
        if tail[:1] == ['pull']:
            self.lab = True
            return 0, b''
        if tail[:4] == ['exec', '-i', prep.DEVICE, prep.OWNER]:
            inner = tail[4:]
            if inner[:3] == ['podman', 'image', 'inspect'] and inner[-1] == prep.TAG:
                if self.device is None:
                    return 125, b''
                return 0, ('%s|%s|["%s"]' % (self.device['id'], self.device['digest'], prep.TAG)).encode()
            if inner[:3] == ['podman', 'image', 'inspect'] and inner[-1] == prep.IMAGE_ID:
                return 0, (prep.IMAGE_ID + '\n').encode()
            if inner[:3] == ['podman', 'image', 'exists']:
                if inner[-1] == prep.IMAGE_ID:
                    return (0 if self.device else 1), b''
                return (0 if self.device and inner[-1].endswith(self.device['digest']) else 1), b''
            if inner[:2] == ['podman', 'tag']:
                self.device = {'id': prep.IMAGE_ID, 'digest': 'sha256:' + 'e' * 64}
                return 0, b''
            if inner[:2] == ['podman', 'ps']:
                return 0, self.users.encode()
            if inner[:2] == ['podman', 'rmi']:
                self.device = None
                return 0, b''
        raise AssertionError(argv)

    def free(self):
        return self.disk

    def wrapper_ok(self):
        return True

    def stream(self, save_argv, load_argv, timeout=1800):
        self.calls.append(['stream', save_argv, load_argv])
        return 0, 0, 'f' * 64, 500

    def lock(self):
        self.locked += 1
        return 7

    def unlock(self, fd):
        self.locked -= 1

    def isolated(self):
        return True


class ImagePrepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.receipt = self.tmp / 'receipt.json'
        self.seat = {'HEAVY_FREE': prep.LOCK}

    def test_plan_touches_nothing(self):
        host = FakeHost()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(prep.main([], host=host), 0)
        self.assertEqual(host.calls, [])
        self.assertFalse(json.loads(out.getvalue())['device_access'])

    def test_pull_only_into_the_lab_store_and_checks_the_id(self):
        host = FakeHost(lab=False)
        code, doc = prep.pull(host)
        self.assertEqual(code, 0)
        self.assertTrue(doc['ok'])
        self.assertTrue(all(call[0] == str(prep.LP) for call in host.calls))
        self.assertIn([str(prep.LP), 'pull', '--quiet', '--platform', 'linux/amd64', prep.PULL_REF], host.calls)
        self.assertEqual(prep.pull(FakeHost(free=10 * 1024 ** 3))[0], 2)

    def test_stream_needs_the_heavy_seat_and_writes_the_receipt(self):
        host = FakeHost()
        self.assertEqual(prep.stream(host, environ={}, receipt=self.receipt)[0], 2)
        self.assertEqual(host.calls, [])
        code, doc = prep.stream(host, environ=self.seat, receipt=self.receipt)
        self.assertEqual((code, doc['ok'], doc['loaded_now']), (0, True, True))
        receipt = json.loads(self.receipt.read_text())
        self.assertEqual((receipt['device_digest'], receipt['image_id'], receipt['loaded']),
                         ('sha256:' + 'e' * 64, prep.IMAGE_ID, True))
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertEqual(doc['receipt_sha256'], sha(self.receipt.read_bytes()))
        self.assertEqual(host.locked, 0)
        stream = [call for call in host.calls if call[0] == 'stream'][0]
        self.assertEqual(stream[1], [str(prep.LP), 'save', '--format', 'docker-archive', prep.IMAGE_ID])
        self.assertEqual(stream[2], [str(prep.LP), 'exec', '-i', prep.DEVICE, prep.OWNER, 'podman', 'load'])
        again = FakeHost(device={'id': prep.IMAGE_ID, 'digest': 'sha256:' + 'e' * 64})
        code, doc = prep.stream(again, environ=self.seat, receipt=self.receipt)
        self.assertEqual((code, doc['loaded_now']), (0, False))
        taken = FakeHost(device={'id': 'f' * 64, 'digest': 'sha256:' + 'e' * 64})
        self.assertEqual(prep.stream(taken, environ=self.seat, receipt=self.receipt)[1]['reason'], 'tag_taken_by_another_image')
        self.assertEqual(prep.stream(FakeHost(lab=False), environ=self.seat, receipt=self.receipt)[0], 2)

    def test_verify_and_remove(self):
        host = FakeHost()
        prep.stream(host, environ=self.seat, receipt=self.receipt)
        self.assertEqual(prep.verify(host, receipt=self.receipt)[0], 0)
        busy = FakeHost(device=dict(host.device), users='woow-emqx\n')
        self.assertEqual(prep.remove(busy, environ=self.seat, receipt=self.receipt)[1]['reason'], 'image_in_use')
        code, doc = prep.remove(host, environ=self.seat, receipt=self.receipt)
        self.assertEqual((code, doc['ok']), (0, True))
        self.assertTrue(json.loads(self.receipt.read_text())['removed'])
        self.assertEqual(prep.remove(host, environ={}, receipt=self.receipt)[0], 2)


if __name__ == '__main__':
    unittest.main()
