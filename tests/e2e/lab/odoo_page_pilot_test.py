"""Offline: odoo_cold_keep_flow.py (the Odoo cold-keep import with the database choice woowtest2) against a simulated dev-c
running the substitute Odoo stack: no device, no labpodman, no browser, no real secret; every lab path in a temporary
folder with generated values.

- --via-page goes through the REAL page bridge (its page process simulated: the effects of dev-c's real Cockpit page),
  with choices {'odoo': {'database': 'woowtest2'}}; the kept whole-cluster copy is the restore's own backup.
- The default run sends exactly the helper calls the page sends (ha-import-start with the choice and every key of
  woowtest2's lines acknowledged once).
- Both leave the simulated dev-c exactly as found: its Odoo data and databases, its backups and HA records, its units.
- Refusals: the heavy seat, a held lock, a dirty checkout, a pending receipt, units in a mixed state, an older Odoo safety
  backup, a retention policy; the page's lock refusal, a check that does not offer woowtest2, a page that stops before
  the acknowledgement, a signal during the page or after the import, a failed put-back, a failed own restore.
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
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
HA_KEY = 'GENR-ATED-HAKE-YFOR-TEST-ONLY-ODOO'
PASSWORD = 'generated-cockpit-pass-4444'
VALUES = {'HA_BACKUP_KEY': HA_KEY, 'ODOO_ADMIN_PW': 'generated-odoo-admin-1', 'ODOO_PROBE_PW': 'generated-odoo-probe-2',
          'N8N_OWNER_PW': 'generated-n8n-owner-3', 'ODOO_MASTER_PW': 'generated-odoo-master-4',
          'ODOO_DB_PW': 'generated-odoo-db-5'}
CREDENTIAL_VALUE = 'generated-credential-value-6'
LEFT = {name: 'odoo.databases-left:' + digit * 16 for name, digit in (('woowtest', '1'), ('woowtest2', '2'), ('woowtest3', '3'))}
OTHER = 'restore.other-databases:' + '7' * 16
EXTRA = 'woowbk_lab_other'
OWN_MANUAL = '20261124T152938Z-3b26976e'      # dev-c's own earlier backups: never touched
N8N_BASELINE = '20261118T095520Z-33eb7474'
CONTAINER_UNIT = {'odoo18-db': 'odoo-db.service', 'odoo18-web': 'odoo.service', 'odoo18-gateway': 'odoo-gateway.service'}


def load(name='odoo_ck'):
    spec = importlib.util.spec_from_file_location(name, HERE / 'odoo_cold_keep_flow.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def bridge_module():
    spec = importlib.util.spec_from_file_location('odoo_ck_bridge', HERE / 'focus_page_bridge.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def answer(stdout=b'', returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=stdout if isinstance(stdout, bytes) else stdout.encode(), stderr=b'')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Dev:
    """dev-c as the driver and the bridge see it: the substitute Odoo stack (three user units), its PostgreSQL cluster
    (databases odoo and postgres, 41 partners), the engine's backups, HA records and jobs."""

    def __init__(self, m, fixture_sha, *, units='inactive', offer=('woowtest', 'woowtest2'), page_mode='pass'):
        self.m = m
        self.store_id = 'ha-' + fixture_sha[:20]
        self.fixture_sha = fixture_sha
        self.calls, self.jobs, self.ha = [], [], []
        self.units = {unit: units for unit in m.UNIT_NAMES}
        self.files = dict(m.REPIN_SHA)
        self.data, self.dbs, self.marker = 'base', ['odoo', 'postgres'], None
        self.facts = {'base_url': 'http://localhost:8069',
                      'marker': json.dumps({'digest': 'sha256:' + m.SUBSTITUTE['web']['id'], 'core_date': '18.0.20260926'})}
        self.partners = {'base': '41', 'ha': '23'}
        self.backups = {OWN_MANUAL: {'id': OWN_MANUAL, 'type': 'manual', 'apps': [{'id': 'odoo'}]},
                        N8N_BASELINE: {'id': N8N_BASELINE, 'type': 'manual', 'apps': [{'id': 'n8n'}]}}
        self.snapshots = {}
        self.policy = {'schema': 1, 'default_keep_last': None, 'apps': {}}
        self.offer, self.page_mode = list(offer), page_mode
        self.put_back_ok, self.own_restore_ok, self.isolated = True, True, True
        self.stop_after_import = self.stop_in_baseline = self.stop_in_bridge = False
        self.failing_starts = set()
        self.sequence = 0
        self.bridge = None
        self.programs = {}
        self.configs = []

    # ---------------------------------------------------------------- bookkeeping
    def log(self, *entry):
        self.calls.append(entry)

    def up(self):
        return all(state == 'active' for state in self.units.values())

    def backup(self, kind, **extra):
        self.sequence += 1
        bid = '20261128T1000%02dZ-%08x' % (self.sequence, self.sequence)
        self.backups[bid] = {'id': bid, 'type': kind, 'apps': [{'id': 'odoo'}], **extra}
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

    def record_ha(self):
        if not any(row['id'] == self.store_id for row in self.ha):
            self.ha.append({'id': self.store_id, 'sha256': self.fixture_sha,
                            'importable_apps': [{'app_id': 'odoo', 'installed': True}, {'app_id': 'n8n', 'installed': True}]})

    def check_result(self, ha_id):
        others = {name: [x for x in self.offer if x != name] for name in self.offer}
        issues = [{'id': 'odoo.databases-left', 'level': 'confirm', 'database': name, 'message': 'stays on HA',
                   'items': others[name], 'key': LEFT[name]} for name in self.offer]
        issues += [{'id': 'restore.other-databases', 'level': 'confirm', 'database': None, 'message': 'whole cluster kept',
                    'items': [db for db in self.dbs if db != 'postgres'], 'key': OTHER},
                   {'id': 'odoo.mail-servers-active', 'level': 'notice', 'database': self.offer[0], 'message': 'mail'},
                   {'id': 'odoo.crons-active', 'level': 'notice', 'database': 'woowtest2', 'message': 'crons'}]
        return {'ha_check': {'schema': 2, 'ha_backup_id': ha_id, 'shared': [], 'apps': [{
            'app_id': 'odoo', 'ok': True, 'importable': True, 'blockers': [], 'warnings': [], 'issues': issues,
            'choices': {'database': [{'value': name, 'label': name, 'ok': True} for name in self.offer]},
            'odoo': {'databases': [{'name': name, 'ok': True, 'partners': 23 if name == 'woowtest2' else 7}
                                   for name in self.offer]}}]}}

    def chain(self, ha_id, ack, choices, unit_shared=False):
        """The one-action import's two linked jobs: the conversion of woowtest2, then its restore with the kept copy."""
        converted = self.backup('manual', from_ha={'ha_backup_id': ha_id, 'kept': None})
        own = {group: keys for group, keys in ack.items() if group in ('odoo', '_shared')}
        first = self.job('backup', {'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['odoo'], 'test_mode': False,
                                    'choices': copy.deepcopy(choices), 'odoo_database': choices['odoo']['database'],
                                    'key_provided': True, 'acknowledged': own,
                                    'group': {'kind': 'ha-import', 'step': 'convert', 'index': 0, 'count': 1},
                                    'chain': {'apps': ['odoo'], 'test_mode': False, 'then_restore': True, 'key_provided': True,
                                              'acknowledged': copy.deepcopy(ack), 'choices': copy.deepcopy(choices)}},
                         'succeeded', {'backup_id': converted,
                                       'ha_import': {'apps': ['odoo'], 'odoo_database': choices['odoo']['database'],
                                                     'test_mode': False},
                                       'group': {'next_job_id': None, 'results': [{'app_id': 'odoo', 'status': 'converted'}]}})
        safety = self.backup('safety', created='before-kept')
        kept = self.backup('safety', kept=True)
        self.backups[converted]['from_ha']['kept'] = kept
        others = [db for db in self.dbs if db not in ('odoo', 'postgres')]
        view = {'backup_id': kept, 'databases': ['odoo', *others], 'more': 0, 'notes': [],
                'put_back': others if self.put_back_ok else [],
                'not_put_back': [] if self.put_back_ok else [{'name': name, 'reason': 'failed'} for name in others]}
        if self.put_back_ok:
            self.data, self.dbs = 'ha', sorted(['odoo', 'postgres', *others])
        state = 'succeeded' if self.put_back_ok else 'rolled-back'
        second = self.job('restore', {'backup_id': converted, 'apps': ['odoo'], 'ha_backup_id': ha_id,
                                      'acknowledged': copy.deepcopy(ack), 'chain': {'apps': ['odoo']}},
                          state, {'safety_backup_id': safety, 'rolled_back': not self.put_back_ok,
                                  'health': [{'id': 'odoo/health-1', 'status': 'ok'}, {'id': 'odoo/health-2', 'status': 'ok'}],
                                  'warnings': [] if self.put_back_ok else ['not all put back'], 'kept': {'odoo': view},
                                  'group': {'next_job_id': None, 'results': [{'app_id': 'odoo', 'status': 'imported'}]}},
                          unit=first['unit'] if unit_shared else None)
        first['result']['group']['next_job_id'] = second['id']
        return first, second

    # ---------------------------------------------------------------- ha_import_e2e's device calls
    def require_isolated_device(self):
        self.log('isolation')
        if not self.isolated:
            raise self.m.Failed('lab must be running with network=none and no published ports')

    def root(self, *argv, input=None, timeout=600, check=False):
        program = argv[3] if argv[:3] == ('python3', '-I', '-c') else None
        name = self.programs.get(program)
        self.log('root', name or argv[:3])
        if name == 'HEADROOM':
            return answer(json.dumps({'used': (400 + (900 if self.up() else 0)) << 20, 'limit': 3 << 30}) + '\n')
        if name == 'ENGINE_HASHES':
            return answer(json.dumps(self.m.tree_engine(REPO)) + '\n')
        if name == 'LEAK_SCAN':
            return answer(json.dumps({'scanned': 30, 'journal_bytes': 4096, 'hits': {}}) + '\n')
        if name == 'PRECONDITIONS':
            return answer(json.dumps({'page': {n: sha(REPO / 'backup' / n) for n in self.bridge.PAGE_FILES},
                                      'cockpit_socket': True, 'hostname': 'woowbk-dev-c', 'devadmin_uid': 1000,
                                      'headroom': 1500 * 1024 ** 2}) + '\n')
        if name == 'NATIVE_UNITS':
            rows = {job['id']: job for job in self.jobs}
            return answer(json.dumps([{k: rows[j][k] for k in ('id', 'unit', 'type', 'state')}
                                      for j in json.loads(input)['ids']]) + '\n')
        if argv[:2] in (('ls', '-A'), ('sh', '-c')):
            return answer('')
        raise AssertionError(('root', argv[:3]))

    def owner(self, *argv, input=None, timeout=600, check=False):
        m = self.m
        if argv[:3] == ('python3', '-I', '-c') and argv[3] == m.UNITS_PROGRAM:
            request = json.loads(input)
            self.log('owner', 'UNITS', tuple(request['containers']))
            images = {name: item['ref'] for name, item in m.SUBSTITUTE.items()}
            return answer(json.dumps({
                'sha256': dict(self.files), 'images': images,
                'env_images': {key: m.SUBSTITUTE[name]['ref'] for key, name in m.ENV_IMAGES.items()},
                'ids': {name: m.SUBSTITUTE[name]['id'] for name in images},
                'units': {unit: self.units[unit] for unit in request['units']},
                'containers': {c: (next(i['id'] for i in m.SUBSTITUTE.values() if i['container'] == c) if self.up() else None)
                               for c in request['containers']}}) + '\n')
        self.log('owner', argv[:4])
        if argv[:3] == ('systemctl', '--user', 'start'):
            if argv[3] in self.failing_starts:   # the unit's start fails (11-26 attempt 1: odoo.service returned 1)
                self.units[argv[3]] = 'failed'
                return answer(returncode=1)
            self.units[argv[3]] = 'active'
            return answer()
        if argv[:3] == ('systemctl', '--user', 'stop'):   # a failed unit stays failed until reset-failed
            self.units[argv[3]] = 'failed' if self.units[argv[3]] == 'failed' else 'inactive'
            return answer()
        if argv[:3] == ('systemctl', '--user', 'reset-failed'):
            self.units[argv[3]] = 'inactive' if self.units[argv[3]] == 'failed' else self.units[argv[3]]
            return answer()
        if argv[:3] == ('systemctl', '--user', 'is-active'):
            return answer(self.units[argv[3]] + '\n')
        if argv[:3] == ('podman', 'healthcheck', 'run'):
            return answer(returncode=0 if self.units[CONTAINER_UNIT[argv[3]]] == 'active' else 1)
        if argv[0] == 'podman' and argv[1] in ('ps', 'volume', 'network'):
            return answer('')
        raise AssertionError(('owner', argv))

    def ok(self, command, request=None, *, ev, timeout=1800):
        self.log('ok', command, {k: v for k, v in (request or {}).items() if k not in ('request_id', 'key')})
        if command == 'status':
            return {'version': '2026.11.28', 'active_job': None,
                    'apps': [{'id': 'odoo', 'state': 'running' if self.up() else 'stopped', 'problems': []},
                             {'id': 'n8n', 'state': 'stopped', 'problems': []}]}
        if command == 'list':
            return {'backups': [dict(row) for row in self.backups.values()], 'ha_backups': [dict(row) for row in self.ha]}
        if command == 'jobs':
            return {'jobs': [self.public(job) for job in reversed(self.jobs)]}
        if command == 'retention-plan':
            return {'policy': self.policy, 'saved_policy': copy.deepcopy(self.policy), 'policy_problem': None}
        if command == 'inspect':
            return {'ok': True, 'preflight': {'ok': True, 'checks': [{'id': 'safety', 'status': 'ok'}],
                                              'apps': [{'id': 'odoo', 'mode': 'inplace'}]}}
        if command == 'backup-start':
            assert request['apps'] == ['odoo'] and request['include_images'] is False
            bid = self.backup('manual', note=request['note'])
            self.snapshots[bid] = (self.data, list(self.dbs), self.marker)
            job = self.job('backup', {'apps': ['odoo'], 'include_images': False}, 'succeeded',
                           {'backup_id': bid, 'size': 12902400, 'retention_deleted': []})
            if self.stop_in_baseline:   # a SIGTERM while the helper answered: the job runs, its id never arrives
                raise self.m.Stopped('signal 15')
            return {'job_id': job['id']}
        if command == 'restore-start':
            data, dbs, marker = self.snapshots[request['backup_id']]
            if self.own_restore_ok:
                self.data, self.dbs, self.marker = data, list(dbs), marker
            result = {'safety_backup_id': self.backup('safety'), 'rolled_back': not self.own_restore_ok,
                      'health': [{'id': 'odoo/health-1', 'status': 'ok'}]}
            return {'job_id': self.job('restore', {'backup_id': request['backup_id'], 'apps': ['odoo']},
                                       'succeeded' if self.own_restore_ok else 'rolled-back', result)['id']}
        if command == 'ha-import-start':
            assert request['choices'] == {'odoo': {'database': 'woowtest2'}} and request['check_job_id']
            first, _second = self.chain(request['ha_backup_id'], request['acknowledged'], request['choices'])
            return {'job_id': first['id'], 'group': {'id': 'g1'}}
        raise AssertionError(('ok', command))

    def helper(self, command, request=None, *, timeout=1800):
        self.log('helper', command, request)
        if command == 'delete':
            return (0, {}) if self.backups.pop(request['backup_id'], None) else (1, {'error': 'not-found'})
        if command == 'ha-delete':
            before = len(self.ha)
            self.ha = [row for row in self.ha if row['id'] != request['ha_backup_id']]
            return (0, {}) if len(self.ha) < before else (1, {'error': 'not-found'})
        raise AssertionError(('helper', command))

    def upload(self, path, *, ev):
        self.log('upload', Path(path).name)
        self.record_ha()
        return 0, {'ha_backup': {'id': self.store_id, 'importable_apps': self.ha[-1]['importable_apps']}}

    def run_check(self, ha, apps, *, ev, key=None, tag='check'):
        self.log('run_check', ha, tuple(apps), key == HA_KEY, tag)
        return self.public(self.job('verify', {'source': 'ha', 'ha_backup_id': ha, 'apps': list(apps), 'key_provided': True},
                                    'succeeded', self.check_result(ha)))

    def wait_job(self, job_id, *, ev, timeout=3600):
        self.log('wait_job', job_id)
        job = next(job for job in self.jobs if job['id'] == job_id)
        if self.stop_in_bridge and job['type'] == 'backup' and job['params'].get('source') == 'ha':
            self.stop_in_bridge = False   # a SIGTERM while the bridge followed the page's chain (after the page)
            raise self.m.Stopped('signal 15')
        return self.public(job)

    def psql(self, container, user, database, sql):
        m = self.m
        self.log('psql', database, sql[:24])
        assert container == 'odoo18-db' and user == 'postgres' and self.units['odoo-db.service'] == 'active'
        if sql == m.SQL_DATABASES:
            return '\n'.join(sorted(self.dbs))
        if sql == m.SQL_PARTNERS:
            if self.stop_after_import and self.data == 'ha':
                raise m.Stopped('signal 15')   # a SIGTERM right after the import (the driver's handler raises this)
            return self.partners[self.data]
        if "key = 'web.base.url';" in sql:
            return self.facts['base_url']
        if 'upgrade_done' in sql:
            return self.facts['marker']
        if sql == f'CREATE DATABASE {EXTRA};':
            self.dbs.append(EXTRA)
            return ''
        if sql.startswith('CREATE TABLE lab_keep') and database == EXTRA:
            self.marker = 'preserved|1'
            return ''
        if sql == m.SQL_MARKER and database == EXTRA and EXTRA in self.dbs:
            return self.marker
        if sql == f'DROP DATABASE {EXTRA} WITH (FORCE);':
            self.dbs.remove(EXTRA)
            self.marker = None
            return ''
        raise AssertionError(('psql', database, sql))

    def http_code(self, url):
        self.log('http_code', url)
        web = self.units['odoo.service'] == 'active'
        served = web if ':18069/' in url else web and self.units['odoo-gateway.service'] == 'active'
        return '200' if served else '000'

    # ---------------------------------------------------------------- the real page's effects (--via-page)
    def page(self, config, seconds, device):
        self.configs.append({k: v for k, v in config.items() if k not in ('key', 'password')})
        self.log('page', device, tuple(config['apps']), config.get('key') == HA_KEY, config.get('choices'),
                 config['password'] == PASSWORD, seconds <= 20 * 60)
        self.record_ha()
        check = self.job('verify', {'source': 'ha', 'ha_backup_id': config['ha_id'], 'apps': ['odoo'], 'key_provided': True},
                         'succeeded', self.check_result(config['ha_id']))
        texts = config['texts']
        head = ['UI real administrative Cockpit bridge reaches this device', texts['upload'], texts['select']]
        tail = ['UI cookie observation completed without gaps',
                'UI every issued credential absent from records journal and private evidence; proved public markers '
                'counted separately']
        lines = check['result']['ha_check']['apps'][0]['issues']
        keys = {'odoo': sorted(i['key'] for i in lines if i['level'] == 'confirm' and i.get('database') in (None, 'woowtest2'))}
        wanted = {'odoo': {'database': 'woowtest2'}}
        record = {'named': config['choices'], 'database': 'woowtest2', 'picks': {}, 'import_choices': wanted,
                  'check_choices': {}, 'rechecks': 0, 'problems': []}
        browser = {'stage': 'issued-value-scan', 'failure_kind': None, 'completed': True, 'issued_values_scanned': True,
                   'issued_scan_counts': {'scan_completed': True, 'observed_values': 2, 'observations_complete': True,
                                          'credential_device_hits': 0, 'credential_host_hits': 0, 'device_files': 30,
                                          'host_files': 3, 'archive_index_sidecars': 4, 'regular_json_roots': 2},
                   'confirmations': {'expected_keys': keys, 'sent_keys': keys, 'lines_expected': 2, 'lines_shown': 2,
                                     'check_importable': ['odoo']},
                   'wire': {'import_starts': 1}, 'choices': record,
                   'requests': {'check': [{'key': True, 'choices': None}], 'import': {'key': True, 'choices': wanted}}}
        outcome = {'started': True, 'exit': 0, 'timed_out': False, 'interrupted': False, 'stop': 'exited',
                   'relay_clean': True, 'relay_error': None, 'children_left': []}
        if 'woowtest2' not in self.offer or self.page_mode == 'stop-before-ack':
            # The page stops before it ticks the acknowledgement (a failed check throws): no import request, no chain.
            choose = 'UI selects each choice the run named, only from what the check offers'
            if 'woowtest2' not in self.offer:   # planChoices: the named database is not one the check can move
                done, stop = head, choose
                record.update(database=None, import_choices=None,
                              problems=['odoo: the named database is not one the check can move'])
            else:
                done = head + [choose, 'UI actual check confirmation keys observed including valid zero', texts['view'],
                               texts['lines']]
                stop = 'UI has exactly one acknowledgement and import waits for it'
            checks = ([{'check': n, 'ok': True} for n in done] + [{'check': stop, 'ok': False},
                                                                  {'check': 'UI bounded flow completed', 'ok': False}]
                      + [{'check': n, 'ok': True} for n in tail])
            browser.update(completed=False, failure_kind='check-or-browser-error', checks=checks, wire={'import_starts': 0},
                           requests={'check': [{'key': True, 'choices': None}], 'import': None})
            browser['confirmations'] = dict(browser['confirmations'], sent_keys=None)
            Path(config['result']).write_text(json.dumps(browser))
            return dict(outcome, exit=1)
        self.chain(config['ha_id'], keys, wanted, unit_shared=True)
        names = head + ['UI selects each choice the run named, only from what the check offers',
                        'UI actual check confirmation keys observed including valid zero', texts['view'], texts['lines'],
                        'UI has exactly one acknowledgement and import waits for it',
                        'UI check did not start an import or separate restore', 'UI real key field removed before screenshot',
                        'UI one acknowledgement enables import', texts['result'], texts['intent'], texts['keys'],
                        'UI the check and import requests carry exactly the chosen choices',
                        'UI no page script errors during this page flow'] + tail
        browser['checks'] = [{'check': n, 'ok': True} for n in names]
        Path(config['result']).write_text(json.dumps(browser))
        if self.page_mode == 'interrupt':   # a SIGTERM while the page ran: the browser stopped in order
            return dict(outcome, exit=None, interrupted=True, stop='terminated')
        return outcome


def lab(root, *, values=VALUES):
    secrets = root / 'lab' / 'secrets'
    secrets.mkdir(parents=True)
    (secrets / 'ha-import-creds.env').write_text(''.join(f'{k}={v}\n' for k, v in values.items()))
    (secrets / 'ha-import-n8n-testdata.sh').write_text(
        'curl --data \'{"name":"HA probe header","type":"httpHeaderAuth","data":{"value":"' + CREDENTIAL_VALUE + '"}}\'\n')
    (secrets / 'devadmin.pass').write_text(PASSWORD + '\n')
    fixture = root / 'lab' / 'woow-import-test-enc.tar'
    fixture.write_bytes(b'generated stand-in for the encrypted Odoo and n8n HA backup ' * 64)
    return fixture


@contextlib.contextmanager
def simulated(m, root, *, bridge=None, dirty=False, heavy=True, dev_options=None, values=VALUES):
    fixture = lab(root, values=values)
    dev = Dev(m, sha(fixture), **(dev_options or {}))
    dev.bridge = bridge

    def git(path, *args):
        dev.log('git', args[0])
        if args[0] == 'status':
            return 0, ' M tests/e2e/lab/odoo_cold_keep_flow.py' if dirty else ''
        if args[0] == 'rev-parse':
            return 0, 'f' * 40
        if args[0] == 'merge-base':
            return 0, ''
        raise AssertionError(('git', args))
    env = {'HEAVY_FREE': str(root / 'woowbk-dev-c-mutation.lock')} if heavy else {}
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, env, clear=False))
        if not heavy:
            os.environ.pop('HEAVY_FREE', None)
        for target, name, value in (
                (m, 'LAB', root / 'lab'), (m.h, 'LAB', root / 'lab'), (m, 'LOCK', str(root / 'woowbk-dev-c-mutation.lock')),
                (m, 'FIXTURE', fixture), (m, 'FIXTURE_SHA', sha(fixture)), (m, 'HA_ID', 'ha-' + sha(fixture)[:20]),
                (m, 'git', git), (m, 'host_available_kib', lambda: 6 * 1024 * 1024),
                (os, 'statvfs', lambda _path: SimpleNamespace(f_bavail=(200 << 30) // 4096, f_frsize=4096)),
                (m.h, 'require_isolated_device', dev.require_isolated_device), (m.h, 'root', dev.root),
                (m.h, 'owner', dev.owner), (m.h, 'ok', dev.ok), (m.h, 'helper', dev.helper), (m.h, 'upload', dev.upload),
                (m.h, 'run_check', dev.run_check), (m.h, 'wait_job', dev.wait_job), (m.h, 'psql', dev.psql),
                (m.h, 'http_code', dev.http_code), (time, 'sleep', lambda _s: None)):
            stack.enter_context(patch.object(target, name, value))
        dev.programs = {m.HEADROOM: 'HEADROOM', m.ENGINE_HASHES: 'ENGINE_HASHES', m.h.LEAK_SCAN: 'LEAK_SCAN'}
        if bridge is not None:
            dev.programs.update({bridge.PRECONDITIONS: 'PRECONDITIONS', bridge.NATIVE_UNITS: 'NATIVE_UNITS'})
            stack.enter_context(patch.object(m, 'load_bridge', lambda: bridge))
            for name, value in (('run_page', dev.page), ('host_available_kib', lambda: 6 * 1024 * 1024),
                                ('PLAYWRIGHT', fixture), ('CHROMIUM', fixture)):
                stack.enter_context(patch.object(bridge, name, value))
        yield dev


def simulate(m, argv, *, bridge=None, hold_lock=False, prepare=None, **options):
    """One main(argv) of driver `m` on a fresh simulated dev-c: exit code, stdout, results, evidence files and their
    modes, the receipt. `hold_lock`: another holder of the dev-c lock; `prepare(m)`: runs before main()."""
    root = Path(tempfile.mkdtemp()).resolve()
    try:
        with simulated(m, root, bridge=bridge, **options) as dev:
            holder = None
            if hold_lock:   # another open file description holds the dev-c lock (as another process would)
                holder = os.open(root / 'woowbk-dev-c-mutation.lock', os.O_RDWR | os.O_CREAT, 0o600)
                fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if prepare is not None:
                prepare(m)
            out = io.StringIO()
            try:
                with contextlib.redirect_stdout(out):
                    code = m.main(argv)
            finally:
                if holder is not None:
                    os.close(holder)
            areas = root / 'lab' / 'evidence' / 'odoo-cold-keep'
            evidence = next(areas.iterdir()) if areas.is_dir() else None
            paths = list(evidence.rglob('*')) if evidence else []
            results = (json.loads((evidence / 'results.json').read_text())['results']
                       if evidence and (evidence / 'results.json').is_file() else [])
            files = {str(p.relative_to(evidence)): p.read_bytes() for p in paths if p.is_file()}
            modes = {'dirs': {str(p.relative_to(evidence)): p.stat().st_mode & 0o777
                              for p in paths + ([evidence] if evidence else []) if p.is_dir()},
                     'files': {str(p.relative_to(evidence)): p.stat().st_mode & 0o777 for p in paths if p.is_file()}}
            receipt_path = root / 'lab' / 'run' / 'odoo_cold_keep_flow.json'
            receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else None
            return SimpleNamespace(code=code, stdout=out.getvalue(), results=results, files=files, modes=modes, dev=dev,
                                   receipt=receipt, evidence=evidence,
                                   receipt_mode=receipt_path.stat().st_mode & 0o777 if receipt_path.exists() else None)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def names(run):
    return [r['check'] for r in run.results]


def failed(run):
    return [r['check'] for r in run.results if not r['ok']]


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
               'page: exactly the page\'s own check and import jobs, none left running, no other new backup (the kept copy '
               'is the restore\'s)',
               'page: the check calls odoo importable, stops nothing, and lists every confirmation line of woowtest2 keyed '
               '(read from the actual check)',
               'page: the one acknowledgement, the import and its jobs carry every listed confirmation key exactly once',
               'page: one conversion and its restore succeeded as two linked jobs in the first job\'s unit',
               'page: woowtest2 picked from what the check offers, both requests, the conversion and the chain carry exactly it',
               'page: every issued Cockpit session value is absent from the records, the journal and the private evidence',
               'page import passed every gate'])


PREFLIGHT = [
    'preflight: dev-c runs with network none and no published port',
    'preflight: the checkout has no tracked change (the source commit describes the code), nor has the product source',
    'preflight: the product source holds the cold-keep fixes (816e4889 kept copy and put-back, 647fe670 first-check line)',
    'preflight: no earlier run of this case is pending (its receipt would list what it made)',
    'preflight: the local file is the recorded real x86 encrypted Odoo and n8n HA backup (SHA-256)',
    'preflight: host MemAvailable >= 1200 MiB (the browser) and the host disk keeps the 12 GiB floor after this run\'s writes',
    'preflight: the installed engine is the product source (every module and the helper SHA-256, the page for --via-page)',
    'preflight: no job is running on dev-c',
    'preflight: the Odoo Quadlets and env file pin the documented substitute images, each loaded with its recorded image ID',
    'preflight: odoo-db, odoo and odoo-gateway are all inactive (started for this run) or all active (used as they are)',
    'preflight: the retention policy keeps every manual Odoo backup (the baseline makes it delete none)',
    'preflight: no earlier Odoo safety backup that this run\'s two restores would make the product prune (keep 3 newest)']
SETUP_TO_EXTRA = [
    'setup: dev-c\'s substitute Odoo stack is up: odoo-db, odoo and odoo-gateway active and healthy (started by this run '
    'when found inactive)',
    'setup: the engine reports Odoo running without problems',
    'setup: the running containers are the substitute images and Odoo\'s upgrade marker names the substitute web image',
    'setup: dev-c memory headroom with Odoo up >= 1280 MiB (the jobs and the Cockpit session)',
    'before: dev-c\'s own Odoo answers (web and gateway health 200), its facts, partner count and databases are recorded',
    'before: no database woowbk_lab_other exists in dev-c\'s Odoo cluster (nothing of an earlier run)',
    'baseline: a fresh backup of dev-c\'s own Odoo succeeded (this run\'s own, deleted at the end)',
    'baseline: it opens and its restore preflight passes (Odoo in place, no failed check)',
    'baseline: it deleted no backup (retention) and is listed as a manual Odoo backup',
    'extra database: woowbk_lab_other with one marker row created in dev-c\'s Odoo cluster (this run\'s own)']
SPACE = ['import: host disk keeps the 12 GiB floor after the upload, check, conversion and restore writes']
CHECK = [
    'check: the job succeeded and checks exactly odoo of this HA record',
    'check: Odoo is importable, no stop line for the app, the shared part or woowtest2',
    'check: the database choice offers exactly woowtest and woowtest2, both can move, woowtest2\'s partner count is read',
    'check: the whole-cluster line (restore.other-databases) names woowbk_lab_other',
    'check: every confirmation line of woowtest2 is a reviewed one (odoo.databases-left, restore.other-databases), each keyed']
CHAIN = [
    'import: two linked jobs, the conversion then the restore, both succeeded',
    'import: the conversion moved odoo with the database woowtest2 (choices, odoo_database), not in test mode, with exactly '
    'the acknowledged keys',
    'import: the group reports odoo imported',
    'import: the restore made a safety backup, was not rolled back, every health check ok, no warning',
    'import: the restore kept a whole-cluster copy and put woowbk_lab_other back automatically, nothing left out']
VERIFY = [
    'verify: the converted backup is a manual one from this HA record pointing to the kept copy, which is listed as kept',
    'verify: woowtest2\'s partner count from the check reached dev-c\'s live Odoo database',
    'verify: the databases are exactly dev-c\'s own plus woowbk_lab_other, whose marker row survived',
    'verify: web.base.url and the upgrade marker are dev-c\'s own, as before the import',
    'verify: odoo.service active (the upgrade gate passed), web and gateway health 200, the engine reports Odoo running']
RECOVERY = [
    'recovery: the baseline restore of dev-c\'s own Odoo succeeded (not rolled back, every health check ok)',
    'recovery: dev-c\'s own Odoo is back: facts, partner count and databases exactly as before (woowbk_lab_other gone)']
UNCHANGED = ['recovery: no import ran, dev-c\'s own Odoo is as before (facts, partner count, woowbk_lab_other dropped, '
             'databases exactly as before)']
CLEANUP = [
    'cleanup: every backup this run made is deleted (the conversion, the safety backups, the kept copy, the baseline)',
    'cleanup: the HA records are as before (the one this run uploaded is deleted)',
    'cleanup: dev-c\'s Odoo units are as found (stopped again when this run started them)',
    'no throwaway container, volume or network left', 'no staging folder and no key file left']
LEAKS = ['no test secret in the engine\'s records, logs, index, registry or the device journal']
COCKPIT = ['no Cockpit login password in the engine\'s records, logs, index, registry or the device journal']
EVIDENCE = ['leaks: no registered value (HA key, HA test credentials, Cockpit password) in this run\'s private evidence']
AFTER = ['after: dev-c still runs with network none and no published port',
         'after: dev-c\'s backups and HA records are exactly the ones it had before',
         'after: the Odoo Quadlets and env file are byte for byte as before, no job running']
HELPER = (PREFLIGHT + SETUP_TO_EXTRA + SPACE
          + ['upload: upload-begin, copy, upload-finish answer the HA record (id from the SHA-256), Odoo importable and '
             'installed here'] + CHECK
          + ['import: one-action import started with the database woowtest2 and every listed key acknowledged once'] + CHAIN
          + VERIFY + RECOVERY + CLEANUP + LEAKS + EVIDENCE + AFTER)


def as_found(test, dev):
    """The simulated dev-c is exactly as it was: its Odoo data, databases and units, its backups and HA records."""
    test.assertEqual((dev.data, dev.dbs, dev.marker), ('base', ['odoo', 'postgres'], None))
    test.assertEqual(sorted(dev.backups), sorted([OWN_MANUAL, N8N_BASELINE]))
    test.assertEqual(dev.ha, [])
    test.assertEqual(set(dev.units.values()), {'inactive'})


def no_secret(test, run):
    for name, data in run.files.items():
        for secret in (HA_KEY, PASSWORD, CREDENTIAL_VALUE, *VALUES.values()):
            test.assertNotIn(secret.encode(), data, name)
    for secret in (HA_KEY, PASSWORD, CREDENTIAL_VALUE, *VALUES.values()):
        test.assertNotIn(secret, run.stdout)


def device_writes(dev):
    """Every call that could change dev-c (a helper command that is not a read, a unit start/stop, a psql change)."""
    reads = {'status', 'list', 'jobs', 'retention-plan', 'inspect'}
    return [c for c in dev.calls if (c[0] == 'ok' and c[1] not in reads) or c[0] in ('helper', 'upload', 'run_check', 'page')
            or (c[0] == 'owner' and c[1][:3] in (('systemctl', '--user', 'start'), ('systemctl', '--user', 'stop')))
            or (c[0] == 'psql' and not c[2].startswith('SELECT'))]


class FullRunTests(unittest.TestCase):
    def test_via_page_through_the_real_bridge_with_the_database_choice_leaves_dev_c_as_found(self):
        m, bridge = load('odoo_ck_page'), bridge_module()
        run = simulate(m, ['--run', '--via-page'], bridge=bridge)
        self.assertEqual(run.code, 0, failed(run))
        texts = bridge.page_settings(['odoo'], ['odoo'], [], choices={'odoo': {'database': 'woowtest2'}})['texts']
        expected = (PREFLIGHT + SETUP_TO_EXTRA + SPACE + page_block(texts) + CHECK + CHAIN + VERIFY + RECOVERY + CLEANUP
                    + LEAKS + COCKPIT + EVIDENCE + AFTER)
        self.assertEqual(names(run), expected)
        self.assertEqual(len(expected), 78)
        self.assertTrue(all(r['ok'] for r in run.results))
        lines = run.stdout.splitlines()
        self.assertEqual(lines[0], 'source commit ' + 'f' * 40)
        self.assertEqual(lines[-1], 'odoo cold keep flow: 78/78 PASS')
        self.assertRegex(lines[-2], r'lock held for [0-9]+ s')
        self.assertEqual([line for line in lines[1:-2]], [m.label(n) + ': PASS' for n in expected])
        as_found(self, run.dev)
        # The page was told exactly the run's choice, the key and the password (on stdin only), for odoo only.
        [page] = [c for c in run.dev.calls if c[0] == 'page']
        self.assertEqual(page, ('page', 'woowbk-dev-c', ('odoo',), True, {'odoo': {'database': 'woowtest2'}}, True, True))
        [config] = run.dev.configs
        self.assertEqual((config['apps'], config['importable'], config['blocked']), (['odoo'], ['odoo'], []))
        summary = json.loads(run.files['page/page-bridge.json'])
        self.assertTrue(summary['passed'])
        self.assertTrue(all(summary['gates'].values()))
        self.assertEqual(summary['chosen'], {'database': 'woowtest2', 'import_choices': {'odoo': {'database': 'woowtest2'}},
                                             'check_choices': {}, 'checks': 1})
        self.assertEqual(summary['expected_acknowledged'], {'odoo': sorted([LEFT['woowtest2'], OTHER])})
        self.assertEqual(summary['confirmation_lines'], 2)
        self.assertEqual(len(summary['created_backups']), 3)   # the conversion, the import's safety backup, the kept copy
        self.assertEqual(summary['unexplained_new_backups'], [])
        # The driver sent none of the page's helper commands itself; the bridge read only.
        kinds = [c[0] for c in run.dev.calls]
        self.assertNotIn('upload', kinds)
        self.assertNotIn('run_check', kinds)
        self.assertNotIn(('ok', 'ha-import-start'), [c[:2] for c in run.dev.calls])
        restores = [c for c in run.dev.calls if c[:2] == ('ok', 'restore-start')]
        self.assertEqual(len(restores), 1)   # only the automatic restore of dev-c's own baseline
        self.assertEqual([c[1] for c in run.dev.calls if c[0] == 'root' and c[1] in ('PRECONDITIONS', 'NATIVE_UNITS')],
                         ['PRECONDITIONS', 'NATIVE_UNITS'])
        self.assertEqual([c[1] for c in run.dev.calls if c[0] == 'root'].count('LEAK_SCAN'), 2)   # test values, password
        # The units were started in order and stopped in reverse order.
        starts = [c[1][3] for c in run.dev.calls if c[0] == 'owner' and c[1][:3] == ('systemctl', '--user', 'start')]
        stops = [c[1][3] for c in run.dev.calls if c[0] == 'owner' and c[1][:3] == ('systemctl', '--user', 'stop')]
        self.assertEqual(starts, ['odoo-db.service', 'odoo.service', 'odoo-gateway.service'])
        self.assertEqual(stops, list(reversed(starts)))
        # Private evidence: 0700 folders, 0600 files (the page's own files too); the receipt is complete and 0600.
        self.assertEqual(set(run.modes['dirs'].values()), {0o700}, run.modes['dirs'])
        self.assertEqual(set(run.modes['files'].values()), {0o600}, run.modes['files'])
        self.assertIn('page/browser.json', run.modes['files'])
        self.assertEqual((run.receipt['complete'], run.receipt['restored'], run.receipt['mode']), (True, True, 'page'))
        self.assertEqual((run.receipt['created_backups'], run.receipt['baseline_id'], run.receipt['started_units']),
                         ([], None, []))
        self.assertEqual(run.receipt_mode, 0o600)
        no_secret(self, run)

    def test_the_helper_path_sends_what_the_page_sends_and_leaves_dev_c_as_found(self):
        m = load('odoo_ck_helper')
        run = simulate(m, ['--run'])
        self.assertEqual(run.code, 0, failed(run))
        self.assertEqual(names(run), HELPER)
        self.assertEqual(len(HELPER), 52)
        self.assertEqual(run.stdout.splitlines()[-1], 'odoo cold keep flow: 52/52 PASS')
        as_found(self, run.dev)
        [start] = [c for c in run.dev.calls if c[:2] == ('ok', 'ha-import-start')]
        self.assertEqual(start[2], {'ha_backup_id': run.dev.store_id, 'apps': ['odoo'], 'confirm': True, 'test_mode': False,
                                    'then_restore': True, 'overwrite': True,
                                    'check_job_id': start[2]['check_job_id'],
                                    'choices': {'odoo': {'database': 'woowtest2'}},
                                    'acknowledged': {'odoo': sorted([LEFT['woowtest2'], OTHER])}})
        self.assertIn(('run_check', run.dev.store_id, ('odoo',), True, 'odoo-ck-check'), run.dev.calls)
        self.assertNotIn('page', [c[0] for c in run.dev.calls])
        self.assertEqual([c[1] for c in run.dev.calls if c[0] == 'root'].count('LEAK_SCAN'), 1)
        self.assertEqual(run.receipt['complete'], True)
        no_secret(self, run)

    def test_units_found_active_are_used_and_left_running(self):
        m = load('odoo_ck_active')
        run = simulate(m, ['--run'], dev_options={'units': 'active'})
        self.assertEqual(run.code, 0, failed(run))
        self.assertEqual(len(run.results), 52)
        self.assertEqual(set(run.dev.units.values()), {'active'})
        self.assertFalse([c for c in run.dev.calls if c[0] == 'owner' and c[1][:3] in (('systemctl', '--user', 'start'),
                                                                                      ('systemctl', '--user', 'stop'))])
        self.assertEqual((run.dev.data, run.dev.dbs), ('base', ['odoo', 'postgres']))
        self.assertEqual(sorted(run.dev.backups), sorted([OWN_MANUAL, N8N_BASELINE]))


class AdmissionTests(unittest.TestCase):
    """Refused before the lock, the secrets and any device call."""

    def refused(self, run, line):
        self.assertEqual(run.code, 2)
        self.assertIn(line + ': FAIL', run.stdout.splitlines())
        self.assertEqual([c for c in run.dev.calls if c[0] != 'git'], [])
        self.assertIsNone(run.evidence)
        self.assertIsNone(run.receipt)

    def test_without_the_heavy_seat(self):
        run = simulate(load('odoo_ck_heavy'), ['--run', '--via-page'], heavy=False)
        self.refused(run, 'admission: the heavy seat (HEAVY_FREE is the dev-c lock: run through heavy.sh)')

    def test_a_dirty_checkout(self):
        run = simulate(load('odoo_ck_dirty'), ['--run', '--via-page'], dirty=True)
        self.refused(run, 'admission: the checkout and the product source have no tracked change')

    def test_a_pending_receipt(self):
        def pending(m):
            path = m.LAB / 'run' / 'odoo_cold_keep_flow.json'
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({'complete': False, 'created_backups': ['20261127T000000Z-0000dead']}))
        run = simulate(load('odoo_ck_pending'), ['--run'], prepare=pending)
        self.assertEqual(run.code, 2)
        self.assertIn('admission: no earlier run of this case is pending: FAIL', run.stdout.splitlines())
        self.assertEqual([c for c in run.dev.calls if c[0] != 'git'], [])

    def test_a_missing_test_value(self):
        values = {k: v for k, v in VALUES.items() if k != 'ODOO_DB_PW'}
        run = simulate(load('odoo_ck_values'), ['--run'], values=values)
        self.refused(run, 'admission: the test credential files name every value the run and its leak scan need')

    def test_a_held_lock(self):
        m = load('odoo_ck_lock')
        with patch.object(m, 'LOCK_WAIT', 0):
            run = simulate(m, ['--run', '--via-page'], hold_lock=True)
        self.assertEqual(run.code, 3)
        self.assertIn('lock: FAIL', run.stdout.splitlines())
        self.assertEqual([c for c in run.dev.calls if c[0] != 'git'], [])
        self.assertIsNone(run.receipt)

    def test_the_default_command_line_is_the_offline_self_check(self):
        m = load('odoo_ck_cli')
        for argv in ([], ['--self-check'], ['--via-page']):
            with self.subTest(argv=argv), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(m.main(argv), 0)
            self.assertEqual(out.getvalue().strip(), 'self-check: PASS')


class PreflightRefusalTests(unittest.TestCase):
    """Refused under the lock by a read-only preflight: nothing on dev-c changed, no receipt written."""

    def refused(self, run, check):
        self.assertEqual(run.code, 1)
        self.assertIn(check, failed(run))
        self.assertEqual(device_writes(run.dev), [])
        self.assertIsNone(run.receipt)
        self.assertEqual(names(run)[-1], 'after: dev-c still runs with network none and no published port')
        self.assertNotIn('cleanup', ' '.join(names(run)))

    def test_units_in_a_mixed_state(self):
        original = Dev.__init__

        def init(dev, *a, **k):
            original(dev, *a, **k)
            dev.units['odoo.service'] = 'failed'
        with patch.object(Dev, '__init__', init):
            run = simulate(load('odoo_ck_mixed'), ['--run'])
        self.refused(run, 'preflight: odoo-db, odoo and odoo-gateway are all inactive (started for this run) or all active '
                          '(used as they are)')

    def test_an_older_odoo_safety_backup_the_restores_would_make_the_product_prune(self):
        original = Dev.__init__

        def init(dev, *a, **k):
            original(dev, *a, **k)
            dev.backups['20261120T000000Z-00005afe'] = {'id': '20261120T000000Z-00005afe', 'type': 'safety',
                                                        'apps': [{'id': 'odoo'}, {'id': 'n8n'}]}
        with patch.object(Dev, '__init__', init):
            run = simulate(load('odoo_ck_prune'), ['--run'])
        self.refused(run, 'preflight: no earlier Odoo safety backup that this run\'s two restores would make the product '
                          'prune (keep 3 newest)')
        self.assertIn('20261120T000000Z-00005afe', run.dev.backups)

    def test_a_retention_policy_that_would_delete_older_manual_backups(self):
        original = Dev.__init__

        def init(dev, *a, **k):
            original(dev, *a, **k)
            dev.policy = {'schema': 1, 'default_keep_last': 2, 'apps': {}}
        with patch.object(Dev, '__init__', init):
            run = simulate(load('odoo_ck_policy'), ['--run'])
        self.refused(run, 'preflight: the retention policy keeps every manual Odoo backup (the baseline makes it delete none)')

    def test_dev_c_not_isolated(self):
        original = Dev.__init__

        def init(dev, *a, **k):
            original(dev, *a, **k)
            dev.isolated = False
        with patch.object(Dev, '__init__', init):
            run = simulate(load('odoo_ck_isolation'), ['--run'])
        self.refused(run, 'preflight: dev-c runs with network none and no published port')


class PageStopTests(unittest.TestCase):
    """The page or the run stops: nothing imported means no restore; an import means dev-c's own baseline comes back."""

    def test_the_page_bridge_refuses_without_this_process_holding_the_lock(self):
        m, bridge = load('odoo_ck_nolock'), bridge_module()
        root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, root, True)
        with simulated(m, root, bridge=bridge) as dev:
            secrets = m.load_secrets(True)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                ev = m.Ev(secrets)
                run = m.Run(SimpleNamespace(secrets=secrets, via_page=True, source=None), ev)
                ok = m.run_all(run)   # main() takes the lock; here nobody holds it
                ev.finish()
        self.assertFalse(ok)
        checks = [(r['check'], r['ok']) for r in ev.results]
        self.assertIn(('page import: refused before the page started (nothing changed)', False), checks)
        self.assertIn((UNCHANGED[0], True), checks)
        self.assertNotIn('page', [c[0] for c in dev.calls])
        self.assertNotIn(('ok', 'restore-start'), [c[:2] for c in dev.calls])   # nothing imported: nothing restored
        as_found(self, dev)
        self.assertTrue(run.receipt.data['complete'])

    def test_a_check_that_does_not_offer_woowtest2_stops_the_page_before_the_acknowledgement(self):
        m, bridge = load('odoo_ck_offer'), bridge_module()
        run = simulate(m, ['--run', '--via-page'], bridge=bridge, dev_options={'offer': ('woowtest', 'woowtest3')})
        self.assertEqual(run.code, 1)
        bad = failed(run)
        for name in ('page: UI selects each choice the run named, only from what the check offers',
                     'page: woowtest2 picked from what the check offers, both requests, the conversion and the chain carry '
                     'exactly it', 'page import passed every gate'):
            self.assertIn(name, bad)
        summary = json.loads(run.files['page/page-bridge.json'])
        self.assertIn('not one the check can move', summary['reasons']['choices'])
        self.assertEqual(summary['chain_job_ids'], [])
        self.assertIn(UNCHANGED[0], names(run))
        self.assertNotIn(RECOVERY[0], names(run))
        self.assertNotIn(('ok', 'restore-start'), [c[:2] for c in run.dev.calls])
        as_found(self, run.dev)
        self.assertTrue(run.receipt['complete'])
        self.assertEqual([r['check'] for r in run.results if not r['ok'] and r['check'].startswith(('cleanup', 'after'))], [])

    def test_the_helper_path_imports_nothing_when_the_check_does_not_offer_woowtest2(self):
        run = simulate(load('odoo_ck_offer_helper'), ['--run'], dev_options={'offer': ('woowtest', 'woowtest3')})
        self.assertEqual(run.code, 1)
        self.assertIn(CHECK[2], failed(run))
        self.assertNotIn(('ok', 'ha-import-start'), [c[:2] for c in run.dev.calls])
        self.assertIn(UNCHANGED[0], names(run))
        as_found(self, run.dev)

    def test_a_page_that_stops_before_it_ticks_the_acknowledgement_imports_nothing(self):
        m, bridge = load('odoo_ck_ack'), bridge_module()
        run = simulate(m, ['--run', '--via-page'], bridge=bridge, dev_options={'page_mode': 'stop-before-ack'})
        self.assertEqual(run.code, 1)
        self.assertIn('page: UI has exactly one acknowledgement and import waits for it', failed(run))
        self.assertIn('page import passed every gate', failed(run))
        self.assertIn(UNCHANGED[0], names(run))
        self.assertNotIn(('ok', 'restore-start'), [c[:2] for c in run.dev.calls])
        as_found(self, run.dev)
        self.assertTrue(run.receipt['complete'])

    def test_a_signal_during_the_page_after_the_import_started_restores_dev_cs_own_odoo(self):
        m, bridge = load('odoo_ck_interrupt'), bridge_module()
        run = simulate(m, ['--run', '--via-page'], bridge=bridge, dev_options={'page_mode': 'interrupt'})
        self.assertEqual(run.code, 1)
        self.assertIn('page import: stopped by a signal (the browser closed in order, the relay reaped)', failed(run))
        self.assertEqual([(r['check'], r['ok']) for r in run.results if r['check'] in RECOVERY],
                         [(RECOVERY[0], True), (RECOVERY[1], True)])
        self.assertEqual(len([c for c in run.dev.calls if c[:2] == ('ok', 'restore-start')]), 1)
        as_found(self, run.dev)   # the conversion, both safety backups, the kept copy and the baseline are gone
        self.assertTrue(run.receipt['complete'])
        for name in CLEANUP + AFTER:
            self.assertIn((name, True), [(r['check'], r['ok']) for r in run.results])

    def test_a_signal_right_after_the_import_restores_dev_cs_own_odoo(self):
        original = Dev.__init__

        def init(dev, *a, **k):
            original(dev, *a, **k)
            dev.stop_after_import = True
        with patch.object(Dev, '__init__', init):
            run = simulate(load('odoo_ck_stopped2'), ['--run'])
        self.assertEqual(run.code, 1)
        self.assertIn('run stopped in a step (Stopped)', failed(run))
        self.assertIn((RECOVERY[0], True), [(r['check'], r['ok']) for r in run.results])
        as_found(self, run.dev)
        self.assertTrue(run.receipt['complete'])

    def test_a_signal_while_the_baseline_is_made_finds_its_backup_and_deletes_it(self):
        original = Dev.__init__

        def init(dev, *a, **k):
            original(dev, *a, **k)
            dev.stop_in_baseline = True
        with patch.object(Dev, '__init__', init):
            run = simulate(load('odoo_ck_baseline_stop'), ['--run', '--via-page'], bridge=bridge_module())
        self.assertEqual(run.code, 1)
        self.assertIn('run stopped in a step (Stopped)', failed(run))
        self.assertIn((UNCHANGED[0], True), [(r['check'], r['ok']) for r in run.results])
        self.assertNotIn('page', [c[0] for c in run.dev.calls])
        as_found(self, run.dev)   # the baseline the run never heard of was found among the new jobs and deleted
        self.assertTrue(run.receipt['complete'])

    def test_a_signal_inside_the_bridge_after_the_page_imported_still_restores_and_cleans_up(self):
        original = Dev.__init__

        def init(dev, *a, **k):
            original(dev, *a, **k)
            dev.stop_in_bridge = True
        with patch.object(Dev, '__init__', init):
            run = simulate(load('odoo_ck_bridge_stop'), ['--run', '--via-page'], bridge=bridge_module())
        self.assertEqual(run.code, 1)
        self.assertIn('run stopped in a step (Stopped)', failed(run))
        self.assertEqual([(r['check'], r['ok']) for r in run.results if r['check'] in RECOVERY],
                         [(RECOVERY[0], True), (RECOVERY[1], True)])
        for name in CLEANUP + AFTER:   # the chain and the HA record found by the run itself, then removed
            self.assertIn((name, True), [(r['check'], r['ok']) for r in run.results])
        as_found(self, run.dev)
        self.assertTrue(run.receipt['complete'])

    def test_a_unit_that_fails_to_start_stops_the_run_before_any_data_change_and_is_returned_as_found(self):
        original = Dev.__init__

        def init(dev, *a, **k):
            original(dev, *a, **k)
            dev.failing_starts = {'odoo.service'}
        with patch.object(Dev, '__init__', init):
            run = simulate(load('odoo_ck_start'), ['--run', '--via-page'], bridge=bridge_module())
        self.assertEqual(run.code, 1)
        self.assertIn(SETUP_TO_EXTRA[0], failed(run))
        self.assertNotIn(('ok', 'backup-start'), [c[:2] for c in run.dev.calls])   # no baseline, no import, no restore
        starts = [c[1][3] for c in run.dev.calls if c[0] == 'owner' and c[1][:3] == ('systemctl', '--user', 'start')]
        self.assertEqual(starts, ['odoo-db.service', 'odoo.service'])               # the gateway was never started
        self.assertIn((CLEANUP[2], True), [(r['check'], r['ok']) for r in run.results])
        as_found(self, run.dev)   # odoo-db stopped, odoo.service's failed state reset
        self.assertTrue(run.receipt['complete'])

    def test_a_put_back_that_fails_rolls_back_and_dev_cs_own_odoo_comes_back(self):
        original = Dev.__init__

        def init(dev, *a, **k):
            original(dev, *a, **k)
            dev.put_back_ok = False
        with patch.object(Dev, '__init__', init):
            run = simulate(load('odoo_ck_putback'), ['--run', '--via-page'], bridge=bridge_module())
        self.assertEqual(run.code, 1)
        self.assertIn('page import passed every gate', failed(run))
        self.assertEqual([(r['check'], r['ok']) for r in run.results if r['check'] in RECOVERY],
                         [(RECOVERY[0], True), (RECOVERY[1], True)])
        as_found(self, run.dev)

    def test_an_own_restore_that_fails_leaves_everything_for_the_coordinator_and_the_receipt_pending(self):
        original = Dev.__init__

        def init(dev, *a, **k):
            original(dev, *a, **k)
            dev.own_restore_ok = False
        with patch.object(Dev, '__init__', init):
            m = load('odoo_ck_own')
            run = simulate(m, ['--run'])
        self.assertEqual(run.code, 1)
        self.assertIn(RECOVERY[0], failed(run))
        self.assertNotIn(RECOVERY[1], names(run))
        self.assertIn(CLEANUP[0], failed(run))
        self.assertIn(CLEANUP[2], failed(run))   # the units stay running for the coordinator
        self.assertEqual(set(run.dev.units.values()), {'active'})
        self.assertNotIn('delete', [c[1] for c in run.dev.calls if c[0] == 'helper'])
        self.assertFalse(run.receipt['complete'])
        self.assertTrue(run.receipt['baseline_id'])
        self.assertEqual(len(run.receipt['created_backups']), 4)   # conversion, two safety backups, the kept copy
        self.assertEqual(run.receipt['started_units'], list(m.UNIT_NAMES))


class InputTests(unittest.TestCase):
    def test_the_driver_hands_the_bridge_exactly_its_inputs(self):
        m = load('odoo_ck_inputs')
        seen = {}

        class FakeBridge:
            Ops = staticmethod(lambda **kw: ('ops', sorted(kw)))

            class BridgeError(Exception):
                summary = {'phase': 'refused', 'reasons': ['stop here']}

            Refused = BridgeError

            @staticmethod
            def import_via_page(**kwargs):
                seen.update(kwargs)
                raise FakeBridge.BridgeError('stop here')
        product = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, product, True)
        for name in ('backup-engine', 'backup'):
            (product / name).symlink_to(REPO / name)
        root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, root, True)
        with simulated(m, root) as _dev:
            secrets = m.load_secrets(True)
            with contextlib.redirect_stdout(io.StringIO()):
                ev = m.Ev(secrets)
                run = m.Run(SimpleNamespace(secrets=secrets, via_page=True, source=product), ev)
                started = time.monotonic()
                with self.assertRaisesRegex(m.Failed, 'did not run to the end'):
                    run.step_page_import(bridge=FakeBridge)
            lock, fixture = m.LOCK, m.FIXTURE   # this run's (patched) lock and fixture
        self.assertEqual({k: seen[k] for k in ('device', 'lock', 'apps', 'importable', 'stops', 'key', 'choices', 'password',
                                               'source', 'evidence', 'fixture')},
                         {'device': 'woowbk-dev-c', 'lock': lock, 'apps': ['odoo'], 'importable': ['odoo'], 'stops': [],
                          'key': HA_KEY, 'choices': {'odoo': {'database': 'woowtest2'}}, 'password': PASSWORD,
                          'source': product, 'evidence': ev.dir / 'page', 'fixture': fixture})
        self.assertEqual(seen['ops'], ('ops', ['helper', 'root_json', 'wait_job']))
        self.assertLessEqual(seen['deadline'], started + 25 * 60 + 1)
        self.assertTrue(m.LOCK.endswith('woowbk-dev-c-mutation.lock'))
        self.assertEqual(ev.results[-1]['check'], 'page import: refused before the page started (nothing changed)')

    def test_the_real_lock_device_and_constants(self):
        m = load('odoo_ck_constants')
        self.assertEqual((m.DEVICE, m.LOCK, m.h.DEVICE), ('woowbk-dev-c', '/tmp/woowbk-dev-c-mutation.lock', 'woowbk-dev-c'))
        self.assertEqual(m.HA_ID, 'ha-1840b054568cb54d9b79')
        self.assertEqual([unit for unit, _c, _u in m.UNITS], ['odoo-db.service', 'odoo.service', 'odoo-gateway.service'])
        for name in HELPER + COCKPIT + UNCHANGED + page_block({k: 'x' * 3 for k in ('upload', 'select', 'view', 'lines',
                                                                                  'result', 'intent', 'keys')})[18:]:
            self.assertEqual(m.label(name), name)   # the driver's own lines are in the fixed vocabulary, none is cut
        bridge = bridge_module()
        texts = bridge.page_settings(['odoo'], ['odoo'], [], choices={'odoo': {'database': 'woowtest2'}})['texts']
        self.assertTrue(all(len(m.label(n)) <= 140 for n in page_block(texts)))

    def test_signals_stop_the_run_but_not_its_recovery(self):
        m = load('odoo_ck_signals')
        with self.assertRaises(m.Stopped):
            m._stop(15, None)
        m.SIGNALS['recovering'] = True
        try:
            self.assertIsNone(m._stop(15, None))
            self.assertEqual(m.SIGNALS['ignored'], 1)
        finally:
            m.SIGNALS.update(recovering=False, ignored=0)

    def test_the_acknowledgement_and_the_kept_copy_rules(self):
        m = load('odoo_ck_rules')
        dev = Dev(m, 'a' * 64)
        dev.dbs.append(EXTRA)
        result = dev.check_result('ha-' + 'a' * 20)['ha_check']
        self.assertEqual(m.acknowledgement(m.confirm_lines(result)), {'odoo': sorted([LEFT['woowtest2'], OTHER])})
        self.assertEqual(m.acknowledgement(m.confirm_lines(result, 'woowtest')), {'odoo': sorted([LEFT['woowtest'], OTHER])})
        first, second = dev.chain('ha-' + 'a' * 20, {'odoo': [OTHER]}, {'odoo': {'database': 'woowtest2'}})
        kept = second['result']['kept']['odoo']['backup_id']
        self.assertEqual(m.owned_from([first, second]), [first['result']['backup_id'], second['result']['safety_backup_id'],
                                                         kept])
        self.assertEqual(second['result']['kept']['odoo']['put_back'], [EXTRA])


if __name__ == '__main__':
    unittest.main()
