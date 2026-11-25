"""One HA import as a chain of single-app jobs (hachain.py, jobs.run_job, cli.py; CONTRACT section 8 "HA import chain";
DESIGN C3-C6, option S): convert A, restore A, convert B, ... in one process under the engine lock; whatever one app meets
stops that app only; cancel, stop after this app, kill and recovery; the checks of the restore side (nested archives,
missing app, preflight, health) stop one app of a chain, never the others. Team E2 (lane F2).

Most tests run the real `jobs.run_job` loop with fake job handlers; `RestoreSideTests` runs the real `flows.run_restore`
(fake adapters, the nested-archive checks of nested.py on hostile tars) as the chain's restore step."""
import contextlib
import copy
import errno
import io
import json
import os
import random
import signal
import tarfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import catalog as catalogmod
from woowbackup import flows, habackup, hachain, haissues, jobs, nested
from woowbackup.errors import BackupError

from . import hafixtures as hx
from .tarfixtures import volume_tar
from .test_ha_import import FlowCase as HaFlowCase
from .test_flows import FakeAdapter, FakeArchive, FakeKeys, FakeStorage, HOST, World, demo_entry, make_catalog, user_lookup
from .test_jobs import JobCase

HA_ID = 'ha-' + '0' * 20
APPS = ['odoo', 'n8n', 'emqx']
THREE_RESTORE = APPS  # a split restore of three apps of one converted backup
KEY = hx.PASSWORD


def backup_id(n):
    return f'20261125T1000{n:02d}Z-a1b2c3d4'


def convert_row(app_id, status='converted', code=None, message=None):
    return {'app_id': app_id, 'status': status, 'code': code, 'message': message, 'issues': []}


class Script:
    """The job handlers of a chain test: they record what ran (`events`) and fail on demand, per app."""

    def __init__(self, test):
        self.test = test
        self.events = []          # ('convert' | 'restore', app id), in the order they ran
        self.converts = 0
        self.convert_fail = {}    # app id -> exception raised by its conversion (given a `.result` unless it has one)
        self.restore_fail = {}    # app id -> exception raised by its restore
        self.restore_result = {}  # app id -> result its restore returns
        self.before = {}          # ('convert' | 'restore', app id) -> callable(ctx, params) run first
        self.seen = []            # (step, app id, ctx.ha_key, ctx.key_file) of each job

    def handlers(self):
        return {'backup': self.convert, 'restore': self.restore}

    def convert(self, ctx, params):
        app_id = params['apps'][0]
        self.events.append(('convert', app_id))
        self.seen.append(('convert', app_id, ctx.ha_key, ctx.key_file))
        ctx.phase('prepare')
        if ('convert', app_id) in self.before:
            self.before[('convert', app_id)](ctx, params)
        if app_id in self.convert_fail:
            error = self.convert_fail[app_id]
            if isinstance(error, BackupError) and not hasattr(error, 'result'):
                error.result = {'results': [convert_row(app_id, 'failed', error.code, error.message)]}
            raise error
        self.converts += 1
        return {'backup_id': backup_id(self.converts), 'size': 1, 'apps': [app_id], 'encrypted': True,
                'ha_import': {'group': params.get('group', {}).get('id')}, 'results': [convert_row(app_id)]}

    def restore(self, ctx, params):
        app_id = params['apps'][0]
        self.events.append(('restore', app_id))
        self.seen.append(('restore', app_id, ctx.ha_key, ctx.key_file))
        ctx.phase('prepare')
        if ('restore', app_id) in self.before:
            self.before[('restore', app_id)](ctx, params)
        if app_id in self.restore_fail:
            raise self.restore_fail[app_id]
        return self.restore_result.get(app_id) or {'apps': [app_id], 'safety_backup_id': f'20261125T1100{len(self.events):02d}Z-5afe0001',
                                                   'changed': True, 'rolled_back': False}


class ChainCase(JobCase):
    """A chain of jobs in a temp layout: `start()` writes the first job like `ha-import-start`, `run()` is its unit."""
    counter = 0

    def setUp(self):
        super().setUp()
        self.script = Script(self)
        self.group = None

    def fresh(self):
        """A new layout and script inside one test (a table of cases); the first one's temp directory goes."""
        self.tmp.cleanup()
        JobCase.setUp(self)
        self.script = Script(self)
        self.group = None

    def start_chain(self, apps=APPS, *, then_restore=True, key=None, results=(), kind='ha-import', restore_backup=None, **chain):
        ChainCase.counter += 1
        self.group = hachain.new_group_id()
        step = 'restore' if kind == 'ha-restore' else 'convert'
        if kind == 'ha-restore':
            params = hachain.restore_params(restore_backup or backup_id(90), apps[0])
        else:
            params = hachain.convert_params(HA_ID, [apps[0]], database=None, test_mode=False, encrypt=True,
                                            key_provided=key is not None, acknowledged={}, choices={})
        params['group'] = hachain.group_params(self.group, kind, step, apps[0], 0, len(apps))
        params['chain'] = hachain.new_chain(apps, then_restore=then_restore, key_provided=key is not None,
                                            ha_backup_id=HA_ID if kind == 'ha-import' else None, results=results, **chain)
        started = jobs.start_job(self.paths, 'restore' if kind == 'ha-restore' else 'backup', params,
                                 f'req-chain-{self.counter:04d}', key_text=key, key_kind='ha' if key else 'age',
                                 launcher=self.launcher, unit_active=self.unit_active)
        self.first = started['job_id']
        return started

    def run_chain(self, **kwargs):
        with contextlib.redirect_stderr(io.StringIO()):
            return jobs.run_job(self.paths, self.first, deps=kwargs.pop('deps', object()),
                                handlers=kwargs.pop('handlers', self.script.handlers()), **kwargs)

    def records(self):
        """The records of the group, in the order the jobs ran."""
        rows = [r for r in self.store.list(limit=None) if (r['params'].get('group') or {}).get('id') == self.group]
        return sorted(rows, key=lambda r: (r['created'], r['id']))

    def shape(self):
        return [(r['params']['group']['step'], r['params']['group']['app_id'], r['state']) for r in self.records()]

    def last_results(self):
        """{app id: GroupResult} of the newest job of the import."""
        last = self.records()[-1]
        return {row['app_id']: row for row in last['result']['group']['results']}

    def statuses(self):
        return {app: row['status'] for app, row in self.last_results().items()}


class ParamsTests(unittest.TestCase):
    """What a chain record says, and the jobs it writes."""

    def group(self, **change):
        group = hachain.group_params('g0123456789abcdef', 'ha-import', 'convert', 'odoo', 0, 3)
        group.update(change)
        return group

    def params(self, group=None, **chain):
        chain = hachain.new_chain(APPS, ha_backup_id=HA_ID, **chain)
        return {'group': group or self.group(), 'chain': chain, 'ha_backup_id': HA_ID}

    def test_a_good_record_is_read_back_whole(self):
        params = self.params(acknowledged={'odoo': ['odoo.modules:1f0c52ab9d3e4f60'], '_shared': ['shared.pauses:77aa77aa77aa77aa']},
                             choices={'odoo': {'database': 'prod'}}, results=[hachain.group_result('hermes', 'skipped', 'not-found', 'x')])
        group, chain = hachain.group_of(params), hachain.chain_of(params)
        self.assertEqual(group, {'id': 'g0123456789abcdef', 'kind': 'ha-import', 'step': 'convert', 'app_id': 'odoo',
                                 'index': 0, 'count': 3})
        self.assertEqual((chain['apps'], chain['then_restore'], chain['encrypt'], chain['ha_backup_id']), (APPS, True, True, HA_ID))
        self.assertEqual(chain['acknowledged']['_shared'], ['shared.pauses:77aa77aa77aa77aa'])
        self.assertEqual(chain['choices'], {'odoo': {'database': 'prod'}})
        self.assertEqual([row['app_id'] for row in chain['results']], ['hermes'])
        self.assertTrue(hachain.in_chain({'params': params}))
        self.assertFalse(hachain.in_chain({'params': {'apps': ['odoo']}}))
        self.assertFalse(hachain.in_chain(None))

    def test_a_record_that_does_not_make_sense_is_no_chain(self):
        good = self.params()
        for label, change in (
                ('group id', lambda p: p['group'].update(id='g1')), ('kind', lambda p: p['group'].update(kind='x')),
                ('step', lambda p: p['group'].update(step='x')), ('index', lambda p: p['group'].update(index=3)),
                ('index type', lambda p: p['group'].update(index=True)), ('count', lambda p: p['group'].update(count=2)),
                ('app', lambda p: p['group'].update(app_id='Odoo')), ('restore kind with a convert step',
                                                                         lambda p: p['group'].update(kind='ha-restore')),
                ('apps do not hold the app at its index', lambda p: p['chain'].update(apps=['n8n', 'odoo', 'emqx'])),
                ('apps do not hold the app', lambda p: p['chain'].update(apps=['n8n', 'hermes', 'emqx'])),
                ('apps twice', lambda p: p['chain']['apps'].__setitem__(1, 'odoo')),
                ('apps type', lambda p: p['chain'].update(apps='odoo')), ('no chain', lambda p: p.pop('chain')),
                ('no group', lambda p: p.pop('group')), ('chain type', lambda p: p.update(chain=[])),
                ('too many apps', lambda p: (p['chain'].update(apps=[f'app-{i}' for i in range(20)]),
                                             p['group'].update(app_id='app-0', count=20)))):
            params = json.loads(json.dumps(good))
            change(params)
            with self.subTest(label):
                self.assertFalse(hachain.in_chain({'params': params}), label)
        self.assertIsNone(hachain.group_of('x'))
        self.assertIsNone(hachain.chain_of({'group': self.group(), 'chain': {'apps': None}}))

    def test_what_a_hostile_record_adds_is_dropped(self):
        params = self.params()
        params['chain'].update(acknowledged={'odoo': ['x', 5, 'odoo.modules:1f0c52ab9d3e4f60'], 'BAD APP': ['a'], 'n8n': 'x'},
                               choices={'odoo': {'database': 5, 'addon': 'ok'}, '../x': {'a': 'b'}, 'n8n': 'x'},
                               ha_backup_id='../../etc', convert_job_id='x', test_mode='yes',
                               results=[{'app_id': 'odoo', 'status': 'imported', 'backup_id': '../x', 'message': 'a‮b',
                                         'convert_job_id': 'nope', 'code': 'c' * 99}, {'status': 'imported'}, 5,
                                        {'app_id': 'odoo', 'status': 'weird'}])
        chain = hachain.chain_of(params)
        self.assertEqual(chain['acknowledged'], {'odoo': ['odoo.modules:1f0c52ab9d3e4f60']})
        self.assertEqual(chain['choices'], {'odoo': {'addon': 'ok'}})
        self.assertEqual((chain['ha_backup_id'], chain['convert_job_id'], chain['test_mode']), (None, None, False))
        self.assertEqual(len(chain['results']), 1)
        row = chain['results'][0]
        self.assertEqual((row['backup_id'], row['convert_job_id'], row['code']), (None, None, None))
        self.assertNotIn('‮', row['message'])
        self.assertEqual(list(row), list(hachain.RESULT_KEYS))

    def test_old_records_of_the_first_job_still_read(self):
        """F1's first job had neither `key_provided` nor `ha_backup_id` in its chain: both come from the job's params."""
        params = {'ha_backup_id': HA_ID, 'key_provided': True, 'group': self.group(),
                  'chain': {'apps': APPS, 'test_mode': False, 'then_restore': True, 'encrypt': True, 'acknowledged': {},
                            'choices': {}, 'results': []}}
        chain = hachain.chain_of(params)
        self.assertEqual((chain['ha_backup_id'], chain['key_provided']), (HA_ID, True))

    def test_the_next_conversion_is_the_ordinary_one_for_one_app(self):
        record = {'id': 'j20261125T100000Z-00000001'}
        chain = hachain.chain_of(self.params(acknowledged={'odoo': ['odoo.modules:1f0c52ab9d3e4f60'], 'n8n': ['n8n.credentials:1f0c52ab9d3e4f60'],
                                                            '_shared': ['shared.pauses:77aa77aa77aa77aa']},
                                             choices={'odoo': {'database': 'prod'}, 'n8n': {'addon': 'a_b'}}, key_provided=True,
                                             test_mode=True))
        group = hachain.group_of(self.params())
        job_type, params = hachain._step_job(chain, group, record, 'convert', 'n8n', [], None)
        self.assertEqual(job_type, 'backup')
        self.assertEqual({k: v for k, v in params.items() if k not in ('group', 'chain')},
                         {'source': 'ha', 'ha_backup_id': HA_ID, 'apps': ['n8n'], 'odoo_database': None, 'test_mode': True,
                          'encrypt': True, 'key_provided': True,
                          'acknowledged': {'n8n': ['n8n.credentials:1f0c52ab9d3e4f60'], '_shared': ['shared.pauses:77aa77aa77aa77aa']},
                          'choices': {'n8n': {'addon': 'a_b'}}})
        self.assertEqual(params['group'], {'id': 'g0123456789abcdef', 'index': 1, 'count': 3, 'kind': 'ha-import',
                                           'step': 'convert', 'app_id': 'n8n'})
        _t, odoo = hachain._step_job(chain, group, record, 'convert', 'odoo', [], None)
        self.assertEqual(odoo['odoo_database'], 'prod', 'the chosen Odoo database goes to the conversion of Odoo only')
        odd = hachain.chain_of(self.params(choices={'odoo': {'database': 'prod'}, 'n8n': {'database': 'not-for-n8n'}}))
        _t, other = hachain._step_job(odd, group, record, 'convert', 'n8n', [], None)
        self.assertIsNone(other['odoo_database'], 'a database choice of another app is never taken for Odoo\'s')
        self.assertEqual(params['chain']['apps'], APPS)
        self.assertEqual(params['chain']['results'], [])

    def test_the_restore_of_one_app_carries_its_lines_and_never_a_key(self):
        record = {'id': 'j20261125T100000Z-00000001'}
        chain = hachain.chain_of(self.params(acknowledged={'odoo': ['odoo.modules:1f0c52ab9d3e4f60'], 'n8n': ['n8n.credentials:1f0c52ab9d3e4f60'],
                                                            '_shared': ['shared.pauses:77aa77aa77aa77aa']}, key_provided=True))
        job_type, params = hachain._step_job(chain, hachain.group_of(self.params()), record, 'restore', 'odoo', [], backup_id(1))
        self.assertEqual(job_type, 'restore')
        self.assertEqual({k: v for k, v in params.items() if k not in ('group', 'chain')},
                         {'backup_id': backup_id(1), 'apps': ['odoo'], 'key_provided': False, 'ha_backup_id': HA_ID,
                          'acknowledged': {'odoo': ['odoo.modules:1f0c52ab9d3e4f60'], '_shared': ['shared.pauses:77aa77aa77aa77aa']}})
        self.assertEqual(params['chain']['convert_job_id'], record['id'])
        self.assertEqual(params['group']['step'], 'restore')
        self.assertNotIn('key', json.dumps(params).lower().replace('key_provided', '').replace('acknowledged', '')
                         .replace('n8n.credentials:1f0c52ab9d3e4f60', '').replace('shared.pauses', '').replace('odoo.modules', ''))

    def test_a_chain_never_builds_a_conversion_without_its_ha_backup(self):
        params = self.params()
        params['chain'].pop('ha_backup_id')
        params.pop('ha_backup_id')
        chain = hachain.chain_of(params)
        with self.assertRaises(BackupError):
            hachain._step_job(chain, hachain.group_of(params), {'id': 'j20261125T100000Z-00000001'}, 'convert', 'n8n', [], None)

    def test_the_texts_the_customer_reads_say_what_happened_and_what_to_do(self):
        for name, text in hachain.STOPPED.items():
            with self.subTest(name):
                self.assertLessEqual(len(text), haissues.MAX_MESSAGE)
                self.assertIn('沒有開始', text)
                self.assertIn('這台的這個應用沒有任何變更', text)
                self.assertRegex(text, '重新|請')
                self.assertNotRegex(text, r'[`$]')
        for text in (hachain.NOT_STARTED, hachain.CONVERTED_KEPT, hachain.CANCELLED_RESTORE, hachain.UNCHANGED_TAIL,
                     hachain.UNCHANGED_BAD_TAIL, hachain.ROLLED_BACK_TAIL, hachain.NO_BACKUP):
            self.assertLessEqual(len(text), haissues.MAX_MESSAGE)
            self.assertNotRegex(text, r'[`$]')

    def test_odd_records_never_raise_where_recovery_reads_them(self):
        """Fixed-seed fuzz: whatever a record holds, group_of / chain_of / in_chain / interrupted answer (never raise): recovery
        reads every record on every status call."""
        import random
        rng = random.Random(20261125)
        good = self.params(results=[hachain.group_result('odoo', 'imported', None, 'x')])
        values = [None, True, 0, -1, 5, 2 ** 70, 1.5, '', 'g0123456789abcdef', 'odoo', 'x' * 500, [], [1, 2], {}, {'a': 1},
                  ['odoo', 'odoo'], {'apps': 5}, '\u202e', 'a\x00b']

        def mutate(value, depth=0):
            if isinstance(value, dict) and value:
                out = dict(value)
                key = rng.choice(sorted(out, key=str))
                if depth < 2 and rng.random() < 0.5:
                    out[key] = mutate(out[key], depth + 1)
                elif rng.random() < 0.2:
                    del out[key]
                else:
                    out[key] = rng.choice(values)
                return out
            if isinstance(value, list) and value:
                out = list(value)
                out[rng.randrange(len(out))] = rng.choice(values) if rng.random() < 0.5 else mutate(out[rng.randrange(len(out))], depth + 1)
                return out
            return rng.choice(values)

        accepted = 0
        for _ in range(600):
            params = mutate(json.loads(json.dumps(good)))
            record = {'id': 'j20261125T100000Z-00000001', 'params': params, 'started': rng.choice([None, '2026-11-25T10:00:00Z', 5])}
            group, chain = hachain.group_of(params), hachain.chain_of(params)
            self.assertEqual(hachain.in_chain(record), chain is not None)
            message, result = hachain.interrupted(record, 'm', {'x': 1})
            self.assertIsInstance(message, str)
            if chain is None:
                self.assertEqual((message, result), ('m', {'x': 1}))
            else:
                accepted += 1
                self.assertEqual(result['group']['id'], group['id'])
                for row in result['group']['results']:
                    self.assertEqual(list(row), list(hachain.RESULT_KEYS))
        self.assertGreater(accepted, 50, 'the fuzz reaches the accepting paths too')
        self.assertIsNone(hachain.group_of(5))
        self.assertEqual(hachain.interrupted({'params': 5}, 'm', None), ('m', None))
        self.assertEqual(hachain.interrupted({}, 'm', None), ('m', None))

    def test_the_stop_names_its_reason_and_text(self):
        for code, key in (('cancelled', 'cancelled'), ('stopped', 'stopped'), ('interrupted', 'interrupted'),
                          ('key-required', 'key'), ('wrong-key', 'key'), ('insufficient-space', 'space'),
                          ('corrupt-archive', 'file'), ('busy', 'busy'), ('no-device-key', 'other'), ('anything', 'other')):
            stop = hachain.Stop(code)
            self.assertEqual((stop.code, stop.message), (code, hachain.STOPPED[key]))
        self.assertEqual(hachain.Stop('internal-error', 'x').message, 'x')


class RunTests(ChainCase):
    """The loop: every job of the import in one process, in order, under the engine lock."""

    def test_an_import_is_a_chain_of_single_app_jobs(self):
        self.start_chain()
        first = self.run_chain()
        self.assertEqual(self.script.events, [(step, app) for app in APPS for step in ('convert', 'restore')])
        self.assertEqual(self.shape(), [(step, app, 'succeeded') for app in APPS for step in ('convert', 'restore')])
        self.assertEqual((first['id'], first['state']), (self.first, 'succeeded'), 'run_job answers with the job it was given')
        records = self.records()
        self.assertEqual({r['unit'] for r in records}, {jobs.unit_name(self.first)}, 'one unit for the whole import')
        self.assertEqual([r['type'] for r in records], ['backup', 'restore'] * 3)
        for index, record in enumerate(records):
            group, view = record['params']['group'], record['result']['group']
            self.assertEqual((group['id'], group['index'], group['count'], group['kind']), (self.group, index // 2, 3, 'ha-import'))
            self.assertEqual((view['id'], view['index'], view['count'], view['step']), (self.group, index // 2, 3, group['step']))
            self.assertEqual(view['next_job_id'], records[index + 1]['id'] if index + 1 < len(records) else None)
        self.assertEqual(self.statuses(), {app: 'imported' for app in APPS})
        row = self.last_results()['n8n']
        self.assertEqual((row['convert_job_id'], row['restore_job_id']), (records[2]['id'], records[3]['id']))
        self.assertEqual(row['backup_id'], backup_id(2))
        self.assertTrue(row['safety_backup_id'])
        self.assertEqual(list(row), list(hachain.RESULT_KEYS))
        self.assertTrue(jobs.lock_is_free(self.paths))
        self.assertEqual(jobs.JobStore(self.paths).stop_requested(self.group), False)

    def test_each_job_runs_while_the_engine_lock_is_held(self):
        self.start_chain()
        held = []
        for key in (('convert', 'n8n'), ('restore', 'emqx')):
            self.script.before[key] = lambda ctx, params: held.append(jobs.lock_is_free(self.paths))
        self.run_chain()
        self.assertEqual(held, [False, False])
        self.assertEqual(Path(self.paths.lock).read_bytes(), b'', 'the lock file holds no job id after the run')

    def test_the_lock_file_names_the_job_that_runs(self):
        self.start_chain(['odoo', 'n8n'])
        names = []
        for key in (('convert', 'odoo'), ('restore', 'odoo'), ('convert', 'n8n')):
            self.script.before[key] = lambda ctx, params: names.append(Path(self.paths.lock).read_text().strip())
        self.run_chain()
        self.assertEqual(names, [r['id'] for r in self.records()][:3])

    def test_the_next_job_is_written_before_the_finished_one(self):
        self.start_chain(['odoo', 'n8n'])
        seen = []
        original = jobs.JobReporter.finish

        def finish(reporter, state, **kwargs):
            states = {r['id']: r['state'] for r in self.store.list(limit=None)}
            seen.append((reporter.job_id, state, dict(states)))
            return original(reporter, state, **kwargs)

        with mock.patch.object(jobs.JobReporter, 'finish', finish):
            self.run_chain()
        self.assertEqual(len(seen), 4)
        ids = [r['id'] for r in self.records()]
        for position, (job_id, _state, states) in enumerate(seen[:-1]):
            self.assertEqual(job_id, ids[position])
            self.assertEqual(states[job_id], 'running')
            self.assertEqual(states[ids[position + 1]], 'queued', f'job {position + 1} exists, queued, before job {position} ends')
        self.assertEqual(sum(1 for state in seen[-1][2].values() if state in jobs.ACTIVE), 1, 'the last job is the only active one')

    def test_there_is_never_a_moment_without_an_active_job_and_nothing_else_can_start(self):
        self.start_chain(['odoo', 'n8n'])
        moments, original = [], jobs.JobReporter.begin

        def begin(reporter):
            active = [r['id'] for r in self.store.list(limit=None) if r['state'] in jobs.ACTIVE]
            try:
                self.start(request_id=f'req-other-{len(moments):04d}')
                busy = None
            except BackupError as error:
                busy = error.code
            moments.append((len(active), busy))
            return original(reporter)

        with mock.patch.object(jobs.JobReporter, 'begin', begin):
            self.run_chain()
        self.assertEqual(moments, [(1, 'busy')] * 4, 'at the start of every job exactly the job itself is active: a start says busy')

    def test_the_key_is_in_memory_only_and_masked_for_the_whole_chain(self):
        started = self.start_chain(key=KEY)
        key_file = self.store.key_path(started['job_id'])
        self.assertTrue(key_file.exists())
        seen = {}

        self.addCleanup(jobs.unmask_secret, KEY)  # haimport.read_key_file masks a key it reads for the rest of the process

        def look(label):
            def run(ctx, params):
                seen[label] = (key_file.exists(), ctx.ha_key, ctx.key_file, jobs._MASK_COUNTS.get(KEY))
                ctx.log(f'the key is {KEY} here')
            return run

        for key in (('convert', 'odoo'), ('restore', 'odoo'), ('convert', 'n8n'), ('convert', 'emqx')):
            self.script.before[key] = look(key)
        self.run_chain()
        self.assertEqual(seen[('convert', 'odoo')][0], True, 'the first job still has its key file')
        self.assertEqual(seen[('convert', 'odoo')][1], KEY)
        for key in (('convert', 'n8n'), ('convert', 'emqx')):
            self.assertEqual(seen[key][:2], (False, KEY), 'later conversions get the key from memory; the file is gone')
            self.assertIsNone(seen[key][2])
            self.assertEqual(seen[key][3], 2, 'the run still holds its own mask of the key (and the reader\'s permanent one)')
        self.assertEqual(seen[('restore', 'odoo')][0], False)
        self.assertFalse(key_file.exists())
        self.assertEqual(list(Path(self.paths.run).glob('key-*')), [])
        for record in self.records():
            self.assertNotIn(KEY, json.dumps(record))
            self.assertNotIn(KEY, '\n'.join(self.store.read_log(record['id'], limit=500)))
            self.assertNotIn(KEY, self.store.log_path(record['id']).read_text())
        self.assertIn(jobs.REDACTED, self.store.log_path(self.records()[4]['id']).read_text())
        self.assertEqual(jobs._MASK_COUNTS.get(KEY), 1, 'the run took its own mask off; only the reader\'s permanent one is left')
        self.assertNotIn(KEY, self.files_text())

    def test_a_chain_started_without_a_key_has_none(self):
        self.start_chain(['odoo', 'n8n'])
        self.run_chain()
        self.assertEqual({entry[2] for entry in self.script.seen}, {None})

    def test_run_job_without_the_chain_runs_one_job_only(self):
        self.start_chain()
        first = self.run_chain(chain=False)
        self.assertEqual(self.script.events, [('convert', 'odoo')])
        self.assertEqual(first['state'], 'succeeded')
        self.assertNotIn('group', first['result'], 'a job that runs alone concludes no chain')
        self.assertEqual(len(self.records()), 1)

    def test_an_import_that_cannot_get_the_engine_says_which_apps_it_did_not_reach(self):
        self.start_chain()
        held = jobs.acquire_engine_lock(self.paths, timeout=0)
        try:
            first = self.run_chain(lock_timeout=0.3)
        finally:
            os.close(held)
        self.assertEqual((first['state'], first['error']['code']), ('failed', 'busy'))
        self.assertEqual(self.script.events, [])
        results = {row['app_id']: row for row in first['result']['group']['results']}
        self.assertEqual({app: row['status'] for app, row in results.items()}, {app: 'not-started' for app in APPS})
        self.assertEqual({row['code'] for row in results.values()}, {'busy'})
        self.assertEqual(results['n8n']['message'], hachain.STOPPED['busy'])
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(jobs.JobStore(self.paths).get(self.first)['result'], first['result'])

    def test_the_memory_of_one_job_is_collected_before_the_next_one_starts(self):
        self.start_chain(['odoo', 'n8n'])
        with mock.patch.object(jobs.gc, 'collect') as collect:
            self.run_chain()
        self.assertEqual(collect.call_count, 3, 'between the four jobs of one process (DESIGN H-c)')

    def test_a_chain_that_never_ends_is_cut_at_two_jobs_per_app(self):
        """A bug of the chain's own must not make one process run jobs for ever."""
        real = hachain.conclude

        def conclude(ctx, record, outcome):
            final, created = real(ctx, record, outcome)
            if created is None:
                params = json.loads(json.dumps(record['params']))
                created = ctx.reporter.store.create(record['type'], params, unit=record.get('unit'),
                                                    now=time.time() + 1000 * len(self.script.events))
            return final, created

        self.start_chain(['odoo'])
        with mock.patch.object(hachain, 'conclude', conclude):
            self.run_chain()
        self.assertEqual(len(self.script.events), 2 * hachain.MAX_APPS + 1, 'the first job and then at most two per possible app')
        self.assertIn('超過上限', '\n'.join(self.store.read_log(self.records()[-2]['id'])))
        self.assertTrue(jobs.lock_is_free(self.paths))

    def test_a_job_with_a_group_but_no_valid_chain_is_run_as_any_job(self):
        """Only a record whose group AND chain make sense is followed by more jobs; the chain code is not even asked."""
        group = hachain.group_params(hachain.new_group_id(), 'ha-import', 'convert', 'odoo', 0, 2)
        for label, extra in (('no chain', {}), ('a chain of other apps', {'chain': hachain.new_chain(['n8n', 'emqx'])})):
            with self.subTest(label):
                self.fresh()
                started = self.start(job_type='backup', params={'apps': ['odoo'], 'group': group, **extra},
                                     request_id=f'req-nochain-{len(label):04d}')
                with mock.patch.object(hachain, 'conclude', side_effect=AssertionError('not a chain')) as conclude:
                    record = jobs.run_job(self.paths, started['job_id'], deps=object(),
                                          handlers={'backup': lambda ctx, params: {'ok': 1}})
                self.assertEqual((record['state'], record['result'], conclude.call_count), ('succeeded', {'ok': 1}, 0))

    def test_a_job_that_is_no_import_is_run_as_before(self):
        result = self.start(job_type='backup', params={'apps': ['a']}, request_id='req-plain-0001')
        record = jobs.run_job(self.paths, result['job_id'], deps=object(), handlers={'backup': lambda ctx, p: {'ok': 1}})
        self.assertEqual((record['state'], record['result']), ('succeeded', {'ok': 1}))
        self.assertEqual(len(self.store.list(limit=None)), 1)

    def test_apps_left_out_at_the_start_stay_in_the_results(self):
        left = [hachain.group_result('hermes', 'skipped', 'not-found', '這份 HA 備份沒有這個附加元件。')]
        self.start_chain(['odoo', 'n8n'], results=left)
        self.run_chain()
        self.assertEqual(self.statuses(), {'hermes': 'skipped', 'odoo': 'imported', 'n8n': 'imported'})
        self.assertEqual(list(self.last_results()), ['hermes', 'odoo', 'n8n'])

    def test_an_import_that_only_converts_has_no_restore(self):
        self.start_chain(then_restore=False)
        self.run_chain()
        self.assertEqual(self.script.events, [('convert', app) for app in APPS])
        self.assertEqual(self.statuses(), {app: 'converted' for app in APPS})
        self.assertEqual([r['type'] for r in self.records()], ['backup'] * 3)

    def test_one_app_is_a_chain_of_two(self):
        self.start_chain(['odoo'])
        self.run_chain()
        self.assertEqual(self.shape(), [('convert', 'odoo', 'succeeded'), ('restore', 'odoo', 'succeeded')])
        self.assertIsNone(self.records()[-1]['result']['group']['next_job_id'])

    def test_the_log_of_a_job_says_what_comes_next_without_a_key(self):
        self.start_chain(['odoo', 'n8n'], key=KEY)
        self.run_chain()
        text = '\n'.join(self.store.read_log(self.records()[0]['id']))
        self.assertIn('匯入進度：odoo 已轉換成備份，接著匯入它。', text)
        text = '\n'.join(self.store.read_log(self.records()[1]['id']))
        self.assertIn('匯入進度：odoo 已匯入；接著轉換 n8n。', text)
        self.assertIn('這次匯入的應用都處理完了', '\n'.join(self.store.read_log(self.records()[3]['id'])))

    def test_the_jobs_of_the_chain_are_listed_in_order_even_in_one_second(self):
        self.start_chain()
        self.run_chain()
        listed = [r['id'] for r in reversed(self.store.list(limit=None))]
        self.assertEqual(listed, [r['id'] for r in self.records()])
        created = [r['created'] for r in self.records()]
        self.assertEqual(created, sorted(created))
        self.assertEqual(len(set(created)), len(created), 'every job is created in a second of its own')



class IsolationTests(ChainCase):
    """Whatever one app meets stops that app only (DESIGN C1; rows FL-08, FL-09, FL-20, X-AD-30, X-AD-33 at the chain's level:
    one job is one app, so its failure, its own safety backup and its own rollback never touch the others)."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hachain, '_outer_file_damaged', lambda ctx, chain: False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fail_convert(self, app_id, error):
        from woowbackup import haimport
        error.result = {'results': [haimport.convert_result(app_id, error, [])]}
        self.script.convert_fail[app_id] = error

    def test_one_apps_failed_conversion_stops_only_that_app(self):
        self.fail_convert('n8n', BackupError('corrupt-archive', '這個應用的資料讀不出來。'))
        self.start_chain()
        first = self.run_chain()
        self.assertEqual(self.script.events, [('convert', 'odoo'), ('restore', 'odoo'), ('convert', 'n8n'), ('convert', 'emqx'),
                                              ('restore', 'emqx')])
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'imported'})
        row = self.last_results()['n8n']
        self.assertEqual((row['code'], row['message'], row['backup_id'], row['restore_job_id']),
                         ('corrupt-archive', '這個應用的資料讀不出來。', None, None))
        self.assertEqual(first['state'], 'succeeded')
        failed = self.records()[2]
        self.assertEqual((failed['state'], failed['error']['code']), ('failed', 'corrupt-archive'))
        self.assertEqual(failed['result']['group']['next_job_id'], self.records()[3]['id'])

    def test_every_code_of_one_app_leaves_the_others_alone(self):
        for code in ('corrupt-archive', 'insufficient-space', 'permission-denied', 'invalid-manifest', 'internal-error',
                     'incompatible', 'job-failed', 'limit-exceeded', 'unsupported-format', 'owner-missing', 'not-deployed',
                     'app-not-in-catalog', 'not-found', 'confirmation-required', 'invalid-request', 'wrong-key',
                     'key-required'):
            with self.subTest(code=code):
                self.fresh()
                error = BackupError(code, f'測試：{code}。')
                if code == 'key-required':
                    error = haissues.job_wide(error)
                self.fail_convert('n8n', error)
                self.start_chain()
                self.run_chain()
                if code == 'key-required':
                    self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'skipped', 'emqx': 'not-started'})
                    continue
                self.assertEqual(self.statuses()['n8n'], 'skipped' if code in ('not-found', 'app-not-in-catalog', 'owner-missing',
                                                                              'not-deployed', 'confirmation-required',
                                                                              'invalid-request', 'wrong-key') else 'failed')
                self.assertEqual((self.statuses()['odoo'], self.statuses()['emqx']), ('imported', 'imported'))

    def test_every_code_of_one_restore_leaves_the_others_alone(self):
        for code in ('corrupt-archive', 'insufficient-space', 'permission-denied', 'invalid-manifest', 'internal-error',
                     'incompatible', 'job-failed', 'limit-exceeded', 'unsupported-format', 'owner-missing', 'not-deployed',
                     'app-not-in-catalog', 'not-found', 'invalid-request', 'wrong-key', 'key-required', 'no-device-key'):
            with self.subTest(code=code):
                self.fresh()
                error = BackupError(code, f'測試：{code}。')
                error.result = {'changed': False, 'rolled_back': False, 'safety_backup_id': None}
                self.script.restore_fail['n8n'] = error
                self.start_chain()
                self.run_chain()
                self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'imported'}, code)
                self.assertEqual(self.last_results()['n8n']['code'], code)

    def test_ten_apps_in_one_import_fit_their_records_and_each_second_one_may_fail(self):
        from woowbackup import haapps
        apps = list(haapps.APP_IDS)
        self.assertEqual(len(apps), 10)
        for app_id in apps[1::2]:
            self.fail_convert(app_id, BackupError('corrupt-archive', f'{app_id} 的資料讀不出來。' + '長' * 200))
        self.start_chain(apps)
        self.run_chain()
        statuses = self.statuses()
        self.assertEqual(statuses, {app: ('failed' if index % 2 else 'imported') for index, app in enumerate(apps)})
        records = self.records()
        self.assertEqual(len(records), 5 * 2 + 5)
        for record in records:
            self.assertLess(Path(self.store.path(record['id'])).stat().st_size, jobs.MAX_RECORD_BYTES // 8)
        self.assertEqual(len(records[-1]['result']['group']['results']), 10)
        self.assertEqual(self.last_results()[apps[9]]['code'], 'corrupt-archive')

    def test_a_restore_that_is_refused_before_anything_changed_is_that_apps_alone(self):
        """FL-09: the restore check of one app does not pass; the others are restored. The converted backup stays."""
        error = BackupError('incompatible', '相容性檢查未通過：缺少映像 localhost/x:1。')
        error.result = {'changed': False, 'rolled_back': False, 'safety_backup_id': None}
        self.script.restore_fail['n8n'] = error
        self.start_chain()
        self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'imported'})
        row = self.last_results()['n8n']
        self.assertEqual((row['code'], row['backup_id'], row['safety_backup_id']), ('incompatible', backup_id(2), None))
        self.assertIn('缺少映像', row['message'])
        self.assertTrue(row['message'].endswith(hachain.UNCHANGED_TAIL))
        self.assertEqual(self.script.events[-2:], [('convert', 'emqx'), ('restore', 'emqx')])

    def test_a_restore_that_is_rolled_back_is_rolled_back_alone(self):
        """FL-20, X-AD-33: an unexpected error or a service that does not start rolls this app back; the others go on."""
        error = BackupError('job-failed', '應用「n8n」還原後健康檢查未通過：無法啟動服務。')
        result = {'rolled_back': True, 'changed': True, 'safety_backup_id': '20261125T110000Z-5afe0002'}
        self.script.restore_fail['n8n'] = flows.RolledBack(error, result)
        self.start_chain()
        self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'rolled-back', 'emqx': 'imported'})
        row = self.last_results()['n8n']
        self.assertEqual((row['code'], row['safety_backup_id'], row['backup_id']), ('job-failed', '20261125T110000Z-5afe0002',
                                                                                  backup_id(2)))
        self.assertIn('無法啟動服務', row['message'])
        self.assertTrue(row['message'].endswith(hachain.ROLLED_BACK_TAIL))
        record = self.records()[3]
        self.assertEqual((record['state'], record['result']['rolled_back']), ('rolled-back', True))

    def test_a_restore_that_cannot_be_rolled_back_needs_a_person_and_the_others_still_go_on(self):
        error = BackupError('job-failed', '還原失敗，且自動回復未完成，需人工處理：「n8n」回復後健康檢查未通過。可使用還原前備份 20261125T110000Z-5afe0003 再次還原。')
        error.result = {'rolled_back': False, 'changed': True, 'safety_backup_id': '20261125T110000Z-5afe0003'}
        self.script.restore_fail['n8n'] = error
        self.start_chain()
        self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'imported'})
        row = self.last_results()['n8n']
        self.assertIn('需人工處理', row['message'])
        self.assertEqual(row['safety_backup_id'], '20261125T110000Z-5afe0003')
        self.assertNotIn(hachain.UNCHANGED_TAIL, row['message'], 'this app did change: it is not told that nothing did')

    def test_a_restore_that_wants_a_line_confirmed_is_skipped_not_failed(self):
        """RESTORE lane: `confirmation-required` of a restore (a line of its check was not confirmed) kept the app out before
        anything of it was touched; its converted backup stays."""
        error = BackupError('confirmation-required', '還原 n8n 前還有事情要確認。')
        error.result = {'changed': False}
        self.script.restore_fail['n8n'] = error
        self.start_chain()
        self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'skipped', 'emqx': 'imported'})
        row = self.last_results()['n8n']
        self.assertEqual((row['code'], row['backup_id']), ('confirmation-required', backup_id(2)))
        self.assertTrue(row['message'].endswith(hachain.UNCHANGED_TAIL))

    def test_an_unexpected_exception_of_one_step_is_told_generically(self):
        self.script.restore_fail['n8n'] = RuntimeError('boom detail with /home/secret/path')
        self.start_chain()
        self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'imported'})
        row = self.last_results()['n8n']
        self.assertEqual(row['code'], 'internal-error')
        self.assertNotIn('boom', json.dumps(self.records()))
        self.assertNotIn('/home/secret', json.dumps(self.records()))

    def test_a_conversion_that_names_no_backup_is_not_restored(self):
        original = self.script.convert

        def convert(ctx, params):
            result = original(ctx, params)
            if params['apps'] == ['n8n']:
                result.pop('backup_id')
            return result

        self.script.convert = convert
        self.start_chain()
        self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'imported'})
        row = self.last_results()['n8n']
        self.assertEqual((row['code'], row['message']), ('internal-error', hachain.NO_BACKUP))
        self.assertNotIn(('restore', 'n8n'), self.script.events)

    def test_every_app_may_fail_and_the_import_still_ends_with_its_result(self):
        for app_id in APPS:
            self.fail_convert(app_id, BackupError('corrupt-archive', f'{app_id} 壞了。'))
        self.start_chain()
        first = self.run_chain()
        self.assertEqual(self.statuses(), {app: 'failed' for app in APPS})
        self.assertEqual(first['state'], 'failed', 'run_job answers with the first job, which failed')
        self.assertEqual([r['state'] for r in self.records()], ['failed'] * 3)
        self.assertIsNone(self.records()[-1]['result']['group']['next_job_id'])
        self.assertTrue(jobs.lock_is_free(self.paths))

    def test_the_first_and_the_last_app_fail_alike(self):
        self.script.restore_fail['odoo'] = BackupError('incompatible', 'x。')
        self.script.restore_fail['emqx'] = BackupError('incompatible', 'y。')
        self.start_chain()
        self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'failed', 'n8n': 'imported', 'emqx': 'failed'})

    def test_an_import_that_only_converts_survives_a_failed_conversion(self):
        self.fail_convert('odoo', BackupError('corrupt-archive', 'x。'))
        self.start_chain(then_restore=False)
        self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'failed', 'n8n': 'converted', 'emqx': 'converted'})
        self.assertEqual(self.script.events, [('convert', app) for app in APPS])

    def test_an_app_the_backup_does_not_hold_fails_alone_in_a_restore_chain(self):
        """FL-08, X-AR-12 on the restore side: a selected app the backup does not hold (`incompatible`) is that app's."""
        self.script.restore_fail['n8n'] = BackupError('incompatible', '此備份不包含應用「n8n」。', app='n8n')
        self.start_chain(['odoo', 'n8n', 'emqx'], kind='ha-restore')
        self.run_chain()
        self.assertEqual(self.script.events, [('restore', app) for app in APPS])
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'imported'})
        self.assertEqual(self.last_results()['n8n']['code'], 'incompatible')


class StopTests(ChainCase):
    """What ends the whole import (DESIGN C1): the apps not reached are `not-started`, with the reason and what to do."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hachain, '_outer_file_damaged', lambda ctx, chain: False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fail_convert(self, app_id, error):
        from woowbackup import haimport
        error.result = {'results': [haimport.convert_result(app_id, error, [])]}
        self.script.convert_fail[app_id] = error

    def assert_stopped_at_n8n(self, code, text_key, status='failed'):
        self.assertEqual(self.script.events, [('convert', 'odoo'), ('restore', 'odoo'), ('convert', 'n8n')])
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': status, 'emqx': 'not-started'})
        row = self.last_results()['emqx']
        self.assertEqual((row['code'], row['message'], row['convert_job_id'], row['backup_id']),
                         (code, hachain.STOPPED[text_key], None, None))
        last = self.records()[-1]
        self.assertEqual(last['result']['group']['next_job_id'], None)
        self.assertEqual(len(self.records()), 3, 'no job was written for the app that was not reached')
        self.assertFalse(self.store.stop_requested(self.group))

    def test_what_ends_the_job_ends_the_import(self):
        for label, error, code, text, status in (
                ('no key', haissues.job_wide(BackupError('key-required', '需要金鑰。')), 'key-required', 'key', 'skipped'),
                ('a key that opens nothing', haissues.job_wide(BackupError('wrong-key', '金鑰不對。')), 'wrong-key', 'key',
                 'skipped'),
                ('no device key', haissues.job_wide(BackupError('no-device-key', '沒有金鑰。')), 'no-device-key', 'other',
                 'failed'),
                ('another job holds the engine', BackupError('busy', '忙。'), 'busy', 'busy', 'failed'),
                ('anything marked job-wide', haissues.job_wide(BackupError('job-failed', 'x。')), 'job-failed', 'other',
                 'failed')):
            with self.subTest(label):
                self.fresh()
                self.fail_convert('n8n', error)
                self.start_chain()
                self.run_chain()
                self.assert_stopped_at_n8n(code, text, status)

    def test_a_key_the_import_has_already_used_is_that_apps_problem_when_it_does_not_open_this_member(self):
        """F1: inside an import `wrong-key` is not job-wide (the key opened another member): that app alone is stopped."""
        self.fail_convert('n8n', BackupError('wrong-key', '這個附加元件的金鑰不對。'))
        self.start_chain()
        self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'skipped', 'emqx': 'imported'})

    def test_a_disk_that_ran_full_stops_the_import_while_it_is_still_full(self):
        full = haissues.job_wide(BackupError('insufficient-space', '空間不足。'))
        self.fail_convert('n8n', full)
        with mock.patch.object(hachain, '_space_recovered', return_value=False) as probe:
            self.start_chain()
            self.run_chain()
        self.assertEqual(probe.call_count, 1)
        self.assert_stopped_at_n8n('insufficient-space', 'space')
        self.assertIn('磁碟空間不足', self.last_results()['emqx']['message'])

    def test_a_disk_that_ran_full_and_has_room_again_only_fails_that_app(self):
        self.fail_convert('n8n', haissues.job_wide(BackupError('insufficient-space', '空間不足。')))
        with mock.patch.object(hachain, '_space_recovered', return_value=True):
            self.start_chain()
            self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'imported'})

    def test_the_engines_own_disk_full_is_the_same(self):
        self.script.restore_fail['n8n'] = OSError(errno.ENOSPC, 'No space left on device')
        for recovered in (False, True):
            with self.subTest(recovered=recovered):
                self.fresh()
                self.script.restore_fail['n8n'] = OSError(errno.ENOSPC, 'No space left on device')
                with mock.patch.object(hachain, '_space_recovered', return_value=recovered):
                    self.start_chain()
                    self.run_chain()
                self.assertEqual(self.statuses()['emqx'], 'imported' if recovered else 'not-started')
                self.assertEqual(self.statuses()['n8n'], 'failed')

    def test_an_apps_own_space_estimate_is_only_that_apps(self):
        """DESIGN C1: `insufficient-space` that is not the floor (not job-wide) stops that app; the next estimates itself."""
        self.fail_convert('n8n', BackupError('insufficient-space', '空間不足以轉換這個應用。'))
        with mock.patch.object(hachain, '_space_recovered', side_effect=AssertionError('no probe for an own estimate')):
            self.start_chain()
            self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'imported'})

    def test_the_space_probe_reads_the_floor_a_job_keeps_free(self):
        from woowbackup import haimport
        ctx = types.SimpleNamespace(storage=types.SimpleNamespace(free_bytes=lambda: 10 * 1024 ** 3),
                                    paths=types.SimpleNamespace(reserve_bytes=512 * 1024 ** 2))
        with mock.patch.object(flows, 'running_reserve', lambda c: 2 * 1024 ** 3):
            self.assertTrue(hachain._space_recovered(ctx))
            ctx.storage.free_bytes = lambda: 2 * 1024 ** 3 + haimport.WATCH_MARGIN - 1
            self.assertFalse(hachain._space_recovered(ctx))
            ctx.storage.free_bytes = lambda: 2 * 1024 ** 3 + haimport.WATCH_MARGIN
            self.assertTrue(hachain._space_recovered(ctx))
            ctx.storage.free_bytes = mock.Mock(side_effect=OSError('x'))
            self.assertFalse(hachain._space_recovered(ctx), 'what cannot be measured is not enough room')
            ctx.storage.free_bytes = lambda: None
            self.assertFalse(hachain._space_recovered(ctx))

    def test_a_damaged_ha_file_stops_the_import_but_a_damaged_member_does_not(self):
        self.fail_convert('n8n', BackupError('corrupt-archive', 'n8n 的資料讀不出來。'))
        with mock.patch.object(hachain, '_outer_file_damaged', lambda ctx, chain: True):
            self.start_chain()
            self.run_chain()
        self.assert_stopped_at_n8n('corrupt-archive', 'file')
        self.assertIn('重新上傳', self.last_results()['emqx']['message'])
        self.fresh()
        self.fail_convert('n8n', BackupError('corrupt-archive', 'n8n 的資料讀不出來。'))
        self.start_chain()
        self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'imported'})

    def test_the_ha_file_is_looked_at_only_when_a_conversion_says_corrupt_archive(self):
        self.fail_convert('n8n', BackupError('incompatible', 'x。'))
        self.script.restore_fail['emqx'] = BackupError('corrupt-archive', '轉換出來的備份壞了。')
        with mock.patch.object(hachain, '_outer_file_damaged', side_effect=AssertionError('not looked at')):
            self.start_chain()
            self.run_chain()
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'failed'},
                         'a converted backup that is damaged is that one app (its own file), never the HA file')

    def test_a_cancel_that_came_a_moment_too_late_for_a_job_still_stops_the_import(self):
        """job-cancel was accepted while the job ran; the job ended well before it looked: the import stops all the same."""
        self.script.before[('restore', 'odoo')] = lambda ctx, params: jobs.cancel_job(self.paths, ctx.job_id, wait_seconds=0)
        self.start_chain()
        first = self.run_chain()
        self.assertEqual(self.script.events, [('convert', 'odoo'), ('restore', 'odoo')])
        self.assertEqual(first['state'], 'succeeded')
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'not-started', 'emqx': 'not-started'})
        self.assertEqual(self.last_results()['n8n']['code'], 'cancelled')
        self.assertEqual(self.store.stop_requested(self.group), False)
        self.assertEqual(list(Path(self.paths.jobs).glob('*.cancel')), [], 'no request file is left')

    def test_a_late_cancel_between_the_conversion_and_its_restore_keeps_the_converted_backup(self):
        self.script.before[('convert', 'n8n')] = lambda ctx, params: jobs.cancel_job(self.paths, ctx.job_id, wait_seconds=0)
        self.start_chain()
        self.run_chain()
        self.assertEqual(self.script.events, [('convert', 'odoo'), ('restore', 'odoo'), ('convert', 'n8n')])
        row = self.last_results()['n8n']
        self.assertEqual((row['status'], row['code'], row['backup_id']), ('converted', 'cancelled', backup_id(2)))
        self.assertEqual(row['message'], hachain.CONVERTED_KEPT)
        self.assertEqual(self.last_results()['emqx']['status'], 'not-started')



class CancelTests(ChainCase):
    """`job-cancel` stops the whole import; `after_this` lets the app being worked on finish first."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hachain, '_outer_file_damaged', lambda ctx, chain: False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def cancel_in(self, step, app_id, **kwargs):
        def run(ctx, params):
            self.answers.append(jobs.cancel_job(self.paths, ctx.job_id, wait_seconds=0, **kwargs))
            ctx.checkpoint()
        self.answers = []
        self.script.before[(step, app_id)] = run

    def test_cancel_during_a_conversion_stops_the_import(self):
        self.cancel_in('convert', 'n8n')
        self.start_chain()
        first = self.run_chain()
        self.assertEqual(self.script.events, [('convert', 'odoo'), ('restore', 'odoo'), ('convert', 'n8n')])
        self.assertEqual((first['state'], self.records()[2]['state']), ('succeeded', 'cancelled'))
        self.assertEqual(self.answers, [{'state': 'running'}])
        results = self.last_results()
        self.assertEqual({app: row['status'] for app, row in results.items()},
                         {'odoo': 'imported', 'n8n': 'not-started', 'emqx': 'not-started'})
        for app in ('n8n', 'emqx'):
            self.assertEqual((results[app]['code'], results[app]['message']), ('cancelled', hachain.STOPPED['cancelled']))
        self.assertEqual(len(self.records()), 3)
        self.assertIsNone(self.records()[-1]['result']['group']['next_job_id'])
        self.assertEqual(list(Path(self.paths.jobs).glob('*.cancel')), [])
        self.assertTrue(jobs.lock_is_free(self.paths))

    def test_cancel_during_a_restore_before_its_safe_point_stops_it_and_the_rest(self):
        self.cancel_in('restore', 'odoo')
        self.start_chain()
        self.run_chain()
        self.assertEqual(self.script.events, [('convert', 'odoo'), ('restore', 'odoo')])
        row = self.last_results()['odoo']
        self.assertEqual((row['status'], row['code'], row['message'], row['backup_id']),
                         ('converted', 'cancelled', hachain.CANCELLED_RESTORE, backup_id(1)))
        self.assertEqual(self.records()[1]['state'], 'cancelled')

    def test_cancel_names_any_job_of_the_import_and_means_the_live_one(self):
        """The page may hold the id of the first job; it is over long ago. The import's live job is the one cancelled."""
        original = jobs.JobReporter.begin
        asked = []

        def begin(reporter):
            group = reporter.record['params'].get('group') or {}
            if (group.get('step'), group.get('app_id')) == ('convert', 'n8n') and not asked:  # queued, not begun
                asked.append(jobs.cancel_job(self.paths, self.first, wait_seconds=0))
            return original(reporter)

        self.start_chain()
        with mock.patch.object(jobs.JobReporter, 'begin', begin):
            self.run_chain()
        self.assertEqual(asked, [{'state': 'queued'}])
        self.assertEqual(self.script.events, [('convert', 'odoo'), ('restore', 'odoo')])
        self.assertEqual([r['state'] for r in self.records()], ['succeeded', 'succeeded', 'cancelled'])
        results = self.last_results()
        self.assertEqual({app: row['status'] for app, row in results.items()},
                         {'odoo': 'imported', 'n8n': 'not-started', 'emqx': 'not-started'})
        self.assertEqual(self.records()[2]['result']['group']['results'], self.records()[-1]['result']['group']['results'])
        self.assertEqual(list(Path(self.paths.jobs).glob('*.cancel')), [], 'the request of a job that never ran is cleared')

    def test_a_queued_restore_that_is_cancelled_keeps_its_converted_backup(self):
        original = jobs.JobReporter.begin

        def begin(reporter):
            if reporter.record.get('type') == 'restore' and not self.answers:
                self.answers.append(jobs.cancel_job(self.paths, reporter.job_id, wait_seconds=0))
            return original(reporter)

        self.answers = []
        self.start_chain()
        with mock.patch.object(jobs.JobReporter, 'begin', begin):
            self.run_chain()
        self.assertEqual(self.script.events, [('convert', 'odoo')])
        row = self.last_results()['odoo']
        self.assertEqual((row['status'], row['code'], row['backup_id'], row['restore_job_id'], row['convert_job_id']),
                         ('converted', 'cancelled', backup_id(1), None, self.first))
        self.assertEqual(row['message'], hachain.CANCELLED_RESTORE)

    def test_a_first_job_that_is_cancelled_before_it_starts_answers_with_its_results(self):
        self.start_chain()
        jobs.cancel_job(self.paths, self.first, wait_seconds=0)
        first = self.run_chain()
        self.assertEqual((first['state'], self.script.events), ('cancelled', []))
        results = first['result']['group']['results']
        self.assertEqual({row['app_id']: row['status'] for row in results}, {app: 'not-started' for app in APPS})
        self.assertEqual({row['code'] for row in results}, {'cancelled'})
        self.assertEqual(len(self.records()), 1)

    def test_stop_after_this_app_lets_its_restore_run(self):
        self.answers = []
        self.script.before[('convert', 'n8n')] = lambda ctx, params: self.answers.append(
            jobs.cancel_job(self.paths, ctx.job_id, after_this=True))
        self.start_chain()
        first = self.run_chain()
        self.assertEqual(self.answers, [{'state': 'running', 'after_this': True}])
        self.assertEqual(self.script.events, [('convert', 'odoo'), ('restore', 'odoo'), ('convert', 'n8n'), ('restore', 'n8n')])
        self.assertEqual(first['state'], 'succeeded')
        results = self.last_results()
        self.assertEqual({app: row['status'] for app, row in results.items()},
                         {'odoo': 'imported', 'n8n': 'imported', 'emqx': 'not-started'})
        self.assertEqual((results['emqx']['code'], results['emqx']['message']), ('stopped', hachain.STOPPED['stopped']))
        self.assertFalse(self.store.stop_requested(self.group), 'the request has done its work')
        self.assertIn(hachain.STOP_REQUESTED_LOG, '\n'.join(self.store.read_log(self.records()[2]['id'])))

    def test_a_split_restore_stops_after_the_app_it_is_restoring_and_a_cancel_stops_it_at_once(self):
        self.answers = []
        self.script.before[('restore', 'n8n')] = lambda ctx, params: self.answers.append(
            jobs.cancel_job(self.paths, ctx.job_id, after_this=True))
        self.start_chain(THREE_RESTORE, kind='ha-restore')
        self.run_chain()
        self.assertEqual(self.script.events, [('restore', 'odoo'), ('restore', 'n8n')])
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'imported', 'emqx': 'not-started'})
        self.assertEqual(self.last_results()['emqx']['code'], 'stopped')
        self.fresh()
        self.cancel_in('restore', 'odoo')
        self.start_chain(THREE_RESTORE, kind='ha-restore')
        self.run_chain()
        self.assertEqual(self.script.events, [('restore', 'odoo')])
        self.assertEqual(self.statuses(), {'odoo': 'converted', 'n8n': 'not-started', 'emqx': 'not-started'})
        self.assertEqual({row['code'] for row in self.last_results().values()}, {'cancelled'})

    def test_stop_after_this_app_is_also_accepted_where_the_job_cannot_be_cancelled(self):
        answers = []

        def run(ctx, params):
            ctx.cancellable(False)
            with self.assertRaises(BackupError) as caught:
                jobs.cancel_job(self.paths, ctx.job_id, wait_seconds=0)
            answers.append(caught.exception.code)
            answers.append(jobs.cancel_job(self.paths, ctx.job_id, after_this=True))

        self.script.before[('restore', 'odoo')] = run
        self.start_chain()
        self.run_chain()
        self.assertEqual(answers, ['not-cancellable', {'state': 'running', 'after_this': True}])
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'not-started', 'emqx': 'not-started'})
        self.assertEqual(self.last_results()['n8n']['code'], 'stopped')

    def test_stop_after_this_app_on_the_last_app_changes_nothing(self):
        self.script.before[('restore', 'emqx')] = lambda ctx, params: jobs.cancel_job(self.paths, ctx.job_id, after_this=True)
        self.start_chain()
        self.run_chain()
        self.assertEqual(self.statuses(), {app: 'imported' for app in APPS})
        self.assertFalse(self.store.stop_requested(self.group))

    def race(self, app_id, step, **request):
        """A job-cancel that arrives while the chain concludes the job (app_id, step): it waits for the record lock the chain
        holds, and the chain waits for it before it begins the next job (so the order is the same every time)."""
        real, begin = hachain.conclude, jobs.JobReporter.begin
        threads = []
        self.answers = []

        def conclude(ctx, record, outcome):
            group = record['params']['group']
            if (group['app_id'], group['step']) == (app_id, step) and not threads:
                thread = threading.Thread(target=lambda: self.answers.append(
                    jobs.cancel_job(self.paths, record['id'], wait_seconds=0, **request)))
                thread.start()
                threads.append(thread)
                time.sleep(0.4)
                self.assertTrue(thread.is_alive(), 'the request waits for the record lock the chain holds')
            return real(ctx, record, outcome)

        def join_then_begin(reporter):
            for thread in threads:
                thread.join(10)
            return begin(reporter)

        return mock.patch.object(hachain, 'conclude', conclude), mock.patch.object(jobs.JobReporter, 'begin', join_then_begin)

    def test_a_request_that_arrives_at_the_boundary_belongs_to_the_next_app(self):
        """The customer pressed 'after this app' while the restore of the first app was ending: the conversion of the next app
        was written already, so 'this app' is the next one (never lost, never a whole app late)."""
        patches = self.race('odoo', 'restore', after_this=True)
        self.start_chain()
        with patches[0], patches[1]:
            self.run_chain()
        self.assertEqual(self.answers, [{'state': 'queued', 'after_this': True}])
        self.assertEqual(self.script.events, [('convert', 'odoo'), ('restore', 'odoo'), ('convert', 'n8n'), ('restore', 'n8n')])
        self.assertEqual(self.statuses(), {'odoo': 'imported', 'n8n': 'imported', 'emqx': 'not-started'})

    def test_a_cancel_that_waits_for_the_lock_of_a_job_that_ends_finds_its_successor(self):
        patches = self.race('odoo', 'convert')
        self.start_chain()
        with patches[0], patches[1]:
            self.run_chain()
        self.assertEqual(self.answers, [{'state': 'queued'}])
        self.assertEqual(self.script.events, [('convert', 'odoo')])
        self.assertEqual([r['state'] for r in self.records()], ['succeeded', 'cancelled'])
        row = self.last_results()['odoo']
        self.assertEqual((row['status'], row['code'], row['backup_id']), ('converted', 'cancelled', backup_id(1)))

    def test_a_cancel_of_an_import_that_is_over_changes_nothing(self):
        self.start_chain(['odoo'])
        self.run_chain()
        for request in ({}, {'after_this': True}):
            self.assertEqual(jobs.cancel_job(self.paths, self.first, **request), {'state': 'succeeded'})
        self.assertEqual(list(Path(self.paths.jobs).glob('*.cancel')) + list(Path(self.paths.jobs).glob('*.stop')), [])

    def test_a_job_that_is_no_import_refuses_to_stop_after_this_app(self):
        job_id = self.start()['job_id']
        with self.assertRaises(BackupError) as caught:
            jobs.cancel_job(self.paths, job_id, after_this=True)
        self.assertEqual((caught.exception.code, caught.exception.details['field']), ('invalid-request', 'after_this'))
        self.assertEqual(jobs.cancel_job(self.paths, job_id, wait_seconds=0), {'state': 'queued'}, 'a plain cancel is as before')
        self.assertTrue(self.store.cancel_requested(job_id))

    def test_the_stop_request_is_a_file_named_after_the_import_only(self):
        for bad in ('x', '../g0123456789abcdef', 'g0123456789ABCDEF', 'g0123456789abcde', None, 5):
            with self.assertRaises(BackupError):
                self.store.stop_path(bad)
        self.store.ensure()
        self.store.request_stop('g0123456789abcdef')
        path = self.store.stop_path('g0123456789abcdef')
        self.assertEqual((path.name, oct(path.stat().st_mode & 0o777)), ('g0123456789abcdef.stop', '0o600'))
        self.assertTrue(self.store.stop_requested('g0123456789abcdef'))
        self.store.clear_stop('g0123456789abcdef')
        self.store.clear_stop('g0123456789abcdef')
        self.assertFalse(self.store.stop_requested('g0123456789abcdef'))


class KeyFileTests(ChainCase):
    """The key of a restore chain (an age key the customer typed) stays a file for the whole run; the HA key of an import
    never does."""

    def test_the_age_key_of_a_split_restore_stays_for_every_job_and_goes_with_the_run(self):
        from .test_flows import TEST_SECRET
        ChainCase.counter += 1
        self.group = hachain.new_group_id()
        params = hachain.restore_params(backup_id(90), 'odoo', key_provided=True)
        params['group'] = hachain.group_params(self.group, 'ha-restore', 'restore', 'odoo', 0, 3)
        params['chain'] = hachain.new_chain(APPS, key_provided=True)
        self.first = jobs.start_job(self.paths, 'restore', params, 'req-keyfile-0001', key_text=TEST_SECRET, key_kind='age',
                                    launcher=self.launcher, unit_active=self.unit_active)['job_id']
        key_file = self.store.key_path(self.first)
        seen = []

        def look(ctx, params):
            # every status poll runs a recovery pass: it must not take the key of a chain that is still running
            jobs.recover_interrupted(self.paths, unit_active=lambda unit: True)
            seen.append((ctx.key_file, ctx.key_file.exists(), ctx.ha_key))

        for app in APPS:
            self.script.before[('restore', app)] = look
        self.run_chain()
        self.assertEqual(seen, [(key_file, True, None)] * 3)
        self.assertFalse(key_file.exists())
        self.assertEqual(list(Path(self.paths.run).glob('key-*')), [])
        self.assertNotIn(TEST_SECRET, self.files_text())

    def test_the_ha_key_file_of_an_import_goes_with_its_first_job(self):
        started = self.start_chain(['odoo', 'n8n'], key=KEY)
        key_file = self.store.key_path(started['job_id'])
        seen = []
        self.script.before[('restore', 'odoo')] = lambda ctx, params: seen.append(key_file.exists())
        self.addCleanup(jobs.unmask_secret, KEY)
        self.run_chain()
        self.assertEqual(seen, [False])



class Killed(BaseException):
    """What a SIGKILL or a power cut is to the process: nothing after this point runs, not even a `finally` that matters."""


class RecoveryTests(ChainCase):
    """A process that dies mid-import: the records it leaves are marked interrupted by the next helper call, each says what
    became of its app, and nothing is continued by itself (DESIGN C4)."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hachain, '_outer_file_damaged', lambda ctx, chain: False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def kill_in(self, step, app_id, phase=None):
        def run(ctx, params):
            if phase:
                ctx.phase(phase)
            raise Killed()
        self.script.before[(step, app_id)] = run

    def run_until_killed(self):
        with self.assertRaises(Killed), contextlib.redirect_stderr(io.StringIO()):
            jobs.run_job(self.paths, self.first, deps=object(), handlers=self.script.handlers())

    def recover(self, **kwargs):
        kwargs.setdefault('unit_active', self.unit_active)
        return jobs.recover_interrupted(self.paths, **kwargs)

    def test_a_job_that_was_running_is_interrupted_and_the_import_says_what_is_done(self):
        self.kill_in('convert', 'n8n')
        self.start_chain()
        self.run_until_killed()
        self.assertEqual(self.shape(), [('convert', 'odoo', 'succeeded'), ('restore', 'odoo', 'succeeded'), ('convert', 'n8n', 'running')])
        self.assertTrue(jobs.lock_is_free(self.paths), 'the engine lock goes with the process')
        changed = self.recover()
        killed = self.records()[2]
        self.assertEqual(changed, [killed['id']])
        self.assertEqual(self.shape()[-1], ('convert', 'n8n', 'interrupted'))
        results = self.last_results()
        self.assertEqual({app: row['status'] for app, row in results.items()}, {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'not-started'})
        self.assertEqual((results['n8n']['code'], results['n8n']['convert_job_id']), ('job-failed', killed['id']))
        self.assertEqual(results['emqx']['code'], 'interrupted')
        self.assertIn('轉換 HA 備份的作業意外中斷', killed['error']['message'] if killed['error'] else '')
        record = self.records()[2]
        self.assertTrue(record['error']['message'].endswith(hachain.INTERRUPTED_TAIL))
        self.assertIsNone(record['result']['group']['next_job_id'])
        self.assertEqual(self.records()[0]['state'], 'succeeded', 'what was done is not touched')
        self.assertEqual(self.recover(), [], 'nothing is continued, nothing is decided twice')

    def test_a_restore_that_was_running_keeps_the_restore_guidance(self):
        self.kill_in('restore', 'n8n', phase='restore')
        self.start_chain()
        self.run_until_killed()
        self.recover()
        record = self.records()[3]
        self.assertEqual(record['state'], 'interrupted')
        self.assertIn('還原作業意外中斷', record['error']['message'])
        self.assertIn('應用可能處於不完整狀態', record['error']['message'])
        row = self.last_results()['n8n']
        self.assertEqual((row['status'], row['code'], row['backup_id'], row['restore_job_id']), ('failed', 'job-failed', backup_id(2), record['id']))
        self.assertEqual(row['convert_job_id'], self.records()[2]['id'])
        self.assertEqual(self.last_results()['odoo']['status'], 'imported')
        self.assertEqual(self.last_results()['emqx']['status'], 'not-started')

    def test_a_restore_killed_before_it_changed_anything_says_so(self):
        self.kill_in('restore', 'n8n')
        self.start_chain()
        self.run_until_killed()
        self.recover()
        record = self.records()[3]
        self.assertIn('應用資料沒有被變更', record['error']['message'])
        self.assertEqual(self.last_results()['n8n']['status'], 'failed')

    def killed_between(self, state_of_next='queued'):
        """The process died after it wrote the next job and before it finished this one."""
        original = jobs.JobReporter.finish

        def finish(reporter, state, **kwargs):
            if reporter.job_id == self.first:
                raise Killed()
            return original(reporter, state, **kwargs)

        self.start_chain()
        with mock.patch.object(jobs.JobReporter, 'finish', finish):
            self.run_until_killed()

    def test_the_job_written_for_the_next_step_is_interrupted_after_its_grace_and_says_it_never_started(self):
        self.killed_between()
        self.assertEqual(self.shape(), [('convert', 'odoo', 'running'), ('restore', 'odoo', 'queued')])
        self.assertEqual(self.records()[1]['unit'], jobs.unit_name(self.first))
        changed = self.recover()
        self.assertEqual(changed, [self.first], 'the young queued job is left alone (its run-job may be about to take the lock)')
        self.assertEqual(self.shape(), [('convert', 'odoo', 'interrupted'), ('restore', 'odoo', 'queued')])
        with self.assertRaises(BackupError) as caught:
            self.start(request_id='req-after-kill-0001')
        self.assertEqual(caught.exception.code, 'busy', 'until recovery decides, nothing else may start')
        changed = self.recover(now=time.time() + jobs.QUEUED_GRACE_SECONDS + 5)
        self.assertEqual(changed, [self.records()[1]['id']])
        queued = self.records()[1]
        self.assertEqual((queued['state'], queued['error']['message']), ('interrupted', hachain.NOT_STARTED))
        row = self.last_results()['odoo']
        self.assertEqual((row['status'], row['code'], row['backup_id'], row['restore_job_id'], row['convert_job_id']),
                         ('converted', 'interrupted', backup_id(1), None, self.first), 'its backup is kept, its restore never ran')
        self.assertEqual({app: r['status'] for app, r in self.last_results().items()},
                         {'odoo': 'converted', 'n8n': 'not-started', 'emqx': 'not-started'})
        self.assertEqual(self.start(request_id='req-after-kill-0002')['deduplicated'], False, 'the engine is free again')

    def test_a_job_that_was_written_after_its_predecessor_finished_and_never_began(self):
        """Killed between two jobs: the first one is finished (its result names the next), the next never began."""
        original = jobs.JobReporter.begin

        def begin(reporter):
            if reporter.record['params']['group']['step'] == 'restore':
                raise Killed()
            return original(reporter)

        self.start_chain()
        with mock.patch.object(jobs.JobReporter, 'begin', begin):
            self.run_until_killed()
        self.assertEqual(self.shape(), [('convert', 'odoo', 'succeeded'), ('restore', 'odoo', 'queued')])
        self.assertEqual(self.records()[0]['result']['group']['next_job_id'], self.records()[1]['id'])
        self.assertEqual(self.recover(), [], 'young: left alone for its grace')
        self.recover(now=time.time() + jobs.QUEUED_GRACE_SECONDS + 5)
        self.assertEqual(self.shape(), [('convert', 'odoo', 'succeeded'), ('restore', 'odoo', 'interrupted')])
        self.assertEqual(self.records()[1]['error']['message'], hachain.NOT_STARTED)
        row = self.last_results()['odoo']
        self.assertEqual((row['status'], row['backup_id'], row['code']), ('converted', backup_id(1), 'interrupted'))
        self.assertEqual({app: r['status'] for app, r in self.last_results().items() if app != 'odoo'},
                         {'n8n': 'not-started', 'emqx': 'not-started'})

    def test_a_record_recovery_cannot_read_is_still_marked_interrupted(self):
        """jobs._mark_interrupted guards hachain: whatever it raises, the job is finished with its own words."""
        job = self.store.create('backup', {'apps': ['a']}, now=time.time() - 1000)
        record = self.store.get(job['id'])
        record['state'] = 'running'
        self.store.save(record)
        with mock.patch.object(hachain, 'interrupted', side_effect=RuntimeError('boom')), \
                contextlib.redirect_stderr(io.StringIO()):
            changed = jobs.recover_interrupted(self.paths, unit_active=lambda unit: False)
        self.assertEqual(changed, [job['id']])
        self.assertEqual(self.store.get(job['id'])['state'], 'interrupted')

    def test_while_the_unit_lives_neither_job_is_touched(self):
        """Every job of the import carries the unit of the first one: it keeps the queued job from being judged dead."""
        self.killed_between()
        self.active_units.add(jobs.unit_name(self.first))
        later = time.time() + 10 * jobs.QUEUED_GRACE_SECONDS
        self.assertEqual(self.recover(now=later), [])
        self.assertEqual(self.shape(), [('convert', 'odoo', 'running'), ('restore', 'odoo', 'queued')])

    def test_while_the_chain_holds_the_engine_lock_recovery_decides_nothing(self):
        seen = []

        def look(ctx, params):
            seen.append(self.recover(unit_active=lambda unit: False, now=time.time() + 1000))

        self.script.before[('convert', 'n8n')] = look
        self.start_chain()
        self.run_chain()
        self.assertEqual(seen, [[]])
        self.assertEqual(self.statuses(), {app: 'imported' for app in APPS})

    def test_the_results_of_a_dead_import_are_read_from_its_newest_record(self):
        self.kill_in('convert', 'emqx')
        self.start_chain()
        self.run_until_killed()
        self.recover()
        view = self.records()[-1]['result']['group']
        self.assertEqual((view['id'], view['index'], view['count'], view['step']), (self.group, 2, 3, 'convert'))
        self.assertEqual([(row['app_id'], row['status']) for row in view['results']],
                         [('odoo', 'imported'), ('n8n', 'imported'), ('emqx', 'failed')])


class TerminationTests(ChainCase):
    """A termination signal (systemctl stop, shutdown): the job it hits is interrupted, nothing more is started, and a signal
    that arrives while the chain writes the next job and finishes this one is only noted (the pair is never cut in half)."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hachain, '_outer_file_damaged', lambda ctx, chain: False)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.previous = signal.getsignal(signal.SIGTERM)

    def test_a_signal_in_a_job_interrupts_it_and_ends_the_import(self):
        def run(ctx, params):
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(5)

        self.script.before[('convert', 'n8n')] = run
        self.start_chain()
        first = self.run_chain()
        self.assertEqual(first['state'], 'succeeded')
        self.assertEqual(self.shape(), [('convert', 'odoo', 'succeeded'), ('restore', 'odoo', 'succeeded'), ('convert', 'n8n', 'interrupted')])
        self.assertEqual({app: row['status'] for app, row in self.last_results().items()},
                         {'odoo': 'imported', 'n8n': 'failed', 'emqx': 'not-started'})
        self.assertEqual(self.last_results()['emqx']['code'], 'interrupted')
        self.assertEqual(signal.getsignal(signal.SIGTERM), self.previous, 'the handlers are back')
        self.assertTrue(jobs.lock_is_free(self.paths))
        self.assertEqual(list(Path(self.paths.run).glob('key-*')), [])

    def test_a_signal_while_the_next_job_is_written_is_noted_and_the_next_job_never_starts(self):
        real = hachain.conclude

        def conclude(ctx, record, outcome):
            result = real(ctx, record, outcome)
            if record['params']['group']['app_id'] == 'odoo' and record['params']['group']['step'] == 'convert':
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(0.2)  # the handler runs: it only notes it
            return result

        self.start_chain()
        with mock.patch.object(hachain, 'conclude', conclude):
            first = self.run_chain()
        self.assertEqual(self.script.events, [('convert', 'odoo')])
        self.assertEqual(first['state'], 'succeeded', 'the job it hit had finished: it ends as it ended, written whole')
        self.assertEqual([r['state'] for r in self.records()], ['succeeded', 'interrupted'])
        queued = self.records()[1]
        self.assertEqual(queued['error']['message'], hachain.NOT_STARTED)
        self.assertEqual({app: row['status'] for app, row in self.last_results().items()},
                         {'odoo': 'converted', 'n8n': 'not-started', 'emqx': 'not-started'})
        self.assertEqual(first['result']['group']['next_job_id'], queued['id'])
        self.assertEqual(signal.getsignal(signal.SIGTERM), self.previous)
        self.assertEqual([r for r in self.store.list(limit=None) if r['state'] in jobs.ACTIVE], [])
        self.assertTrue(jobs.lock_is_free(self.paths))

    def test_a_signal_outside_the_critical_section_still_raises_where_it_always_did(self):
        with jobs._termination_deferred() as state:
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.2)
        self.assertEqual((state.pending, state.signum), (True, signal.SIGTERM))
        self.assertEqual(signal.getsignal(signal.SIGTERM), self.previous)
        with jobs.signals_as_exceptions():
            with self.assertRaises(jobs.Terminated):
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(2)

    def test_the_deferral_does_nothing_off_the_main_thread(self):
        seen = []

        def work():
            with jobs._termination_deferred() as state:
                seen.append(state.pending)

        thread = threading.Thread(target=work)
        thread.start()
        thread.join(5)
        self.assertEqual(seen, [False])



THREE = ['woowbk-demo', 'woowbk-two', 'woowbk-three']


def good_tar(app_id):
    return volume_tar([{'name': 'files/', 'kind': tarfile.DIRTYPE, 'mode': 0o755},
                       {'name': 'files/a.txt', 'data': f'{app_id}-from-ha'.encode(), 'mode': 0o644}])


class TarAdapter(FakeAdapter):
    """The fake adapter whose restore check runs the REAL nested-archive check of nested.py on the volume tar, as the real
    adapter's preflight does before any app is stopped or any safety backup is taken."""

    def preflight(self, app_manifest, *, mode, entry_sizes=None, extracted_dir=None):
        checks = super().preflight(app_manifest, mode=mode, entry_sizes=entry_sizes, extracted_dir=extracted_dir)
        nested.check_volume(Path(extracted_dir) / app_manifest['volumes'][0]['entry'])
        return checks

    def health(self):
        if self.run == 'restore' and self.app.id in self.world.start_fails:  # the restore's units do not come up
            return [{'id': f'{self.app.id}/start', 'status': 'fail', 'message': '無法啟動服務：woowbk-demo-app.service 沒有在執行。'}]
        return super().health()


class TarWorld(World):
    def __init__(self):
        super().__init__()
        self.start_fails = set()
        for app_id in THREE:
            self.data[app_id] = good_tar(app_id)
            self.mode[app_id] = 'inplace'
            self.deployed[app_id] = True

    def factory(self, app, *, log, phase=None, checkpoint=None, writers_hook=None, imported_hook=None):
        adapter = TarAdapter(app, self, log, phase, checkpoint, writers_hook, imported_hook)
        self.adapters.append(adapter)
        return adapter


class RestoreSideCase(ChainCase):
    """The chain with the REAL restore flow (flows.run_restore: preflight, safety backup, restore, health, automatic rollback)
    and fake adapters; the conversion step makes an ordinary backup of the app (the conversions themselves are
    test_ha_import / test_ha_flows). What the device held when its app was converted is `marker(app)`: it differs from what
    the backup holds, so the data after the chain shows which apps were imported and which were left or rolled back."""

    @staticmethod
    def marker(app_id):
        return f'{app_id}-on-this-device'.encode()

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hachain, '_outer_file_damaged', lambda ctx, chain: False)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.build()

    def fresh(self):
        super().fresh()
        self.build()

    def build(self):
        root = Path(self.tmp.name)
        self.storage = FakeStorage(root / 'data')
        self.storage.pending = Path(self.paths.pending)
        self.keys = FakeKeys(root)
        self.archive = FakeArchive()
        self.world = TarWorld()
        self.catalog = make_catalog(self.paths)
        third = copy.deepcopy(demo_entry(self.paths))
        third.update(id='woowbk-three', name='第三個應用', config_files=[{'path': '.config/woowbk-three/app.env', 'mode': '0600'}])
        self.catalog['woowbk-three'] = catalogmod.validate_entry(third, paths=self.paths, user_lookup=user_lookup)
        self.deps = flows.Deps(storage=self.storage, keys=self.keys, archive=self.archive, load_catalog=lambda: self.catalog,
                               adapter_factory=self.world.factory, host_info=lambda: dict(HOST))

    def convert(self, ctx, params):
        app_id = params['apps'][0]
        ctx.phase('prepare')
        result = flows.run_backup(ctx, {'apps': [app_id], 'include_images': False, 'note': f'由 HA 備份轉換：{app_id}'})
        self.script.events.append(('convert', app_id))
        self.world.data[app_id] = self.marker(app_id)  # the device moves on after the conversion
        return {'backup_id': result['backup_id'], 'size': result['size'], 'apps': result['apps'],
                'encrypted': result['encrypted'], 'ha_import': {}, 'results': [convert_row(app_id)]}

    def run_real(self, **kwargs):
        return self.run_chain(deps=self.deps, handlers={'backup': self.convert, 'restore': flows.run_restore}, **kwargs)

    def restores(self):
        """The apps whose restore the (fake) adapters ran, and those they rolled back."""
        return ([e[1] for e in self.world.events if e[0] == 'restore' and e[3] == 'restore'],
                [e[1] for e in self.world.events if e[0] == 'restore' and e[3] == 'rollback'])

    def safeties(self):
        return {m['apps'][0]['id']: m for m in self.storage.list_backups() if m['type'] == 'safety'}

    def assert_imported(self, *apps):
        for app_id in apps:
            self.assertEqual(self.world.data[app_id], good_tar(app_id), f'{app_id} holds what the backup held')

    def assert_untouched(self, *apps):
        for app_id in apps:
            self.assertEqual(self.world.data[app_id], self.marker(app_id), f'{app_id} is as the device had it')


class RestoreSideTests(RestoreSideCase):
    """The restore side of the chain with the real restore flow."""

    def test_three_apps_each_with_its_own_safety_backup(self):
        self.start_chain(THREE)
        self.run_real()
        self.assertEqual(self.statuses(), {app: 'imported' for app in THREE})
        self.assertEqual(self.restores(), (THREE, []))
        self.assert_imported(*THREE)
        safeties = self.safeties()
        self.assertEqual(sorted(safeties), sorted(THREE), 'one pre-restore backup per app')
        for app_id, row in self.last_results().items():
            self.assertEqual(row['safety_backup_id'], safeties[app_id]['id'])
            self.assertEqual([item['id'] for item in self.storage.get(row['backup_id'])['apps']], [app_id],
                             'every converted backup holds one app')
        self.assertEqual(len({row['backup_id'] for row in self.last_results().values()}), 3)

    def test_a_restore_check_that_does_not_pass_leaves_that_app_and_restores_the_others(self):
        """FL-09: the restore check (any item) does not pass for one app: only that app is refused, the others are restored."""
        self.world.preflight_fail.add('woowbk-two')
        self.start_chain(THREE)
        self.run_real()
        self.assertEqual(self.statuses(), {'woowbk-demo': 'imported', 'woowbk-two': 'failed', 'woowbk-three': 'imported'})
        row = self.last_results()['woowbk-two']
        self.assertEqual(row['code'], 'incompatible')
        self.assertIn('相容性檢查未通過', row['message'])
        self.assertTrue(row['message'].endswith(hachain.UNCHANGED_TAIL))
        self.assertEqual((row['safety_backup_id'], self.restores()), (None, (['woowbk-demo', 'woowbk-three'], [])))
        self.assert_imported('woowbk-demo', 'woowbk-three')
        self.assert_untouched('woowbk-two')
        self.assertNotIn('woowbk-two', self.safeties(), 'refused before the safety backup: nothing was taken, nothing stopped')
        self.assertTrue(self.storage.get(row['backup_id']), 'the converted backup stays')

    def test_a_restore_that_fails_after_it_started_is_rolled_back_for_that_app_only(self):
        """FL-20: an error in the middle of one restore rolls that app back from its own safety backup; the others stay imported."""
        self.world.fail_restore_after['woowbk-two'] = 1
        self.start_chain(THREE)
        self.run_real()
        self.assertEqual(self.statuses(), {'woowbk-demo': 'imported', 'woowbk-two': 'rolled-back', 'woowbk-three': 'imported'})
        self.assertEqual(self.restores(), (THREE, ['woowbk-two']))
        self.assert_imported('woowbk-demo', 'woowbk-three')
        self.assert_untouched('woowbk-two')
        row = self.last_results()['woowbk-two']
        self.assertEqual((row['code'], row['safety_backup_id']), ('job-failed', self.safeties()['woowbk-two']['id']))
        self.assertTrue(row['message'].endswith(hachain.ROLLED_BACK_TAIL))
        record = self.records()[3]
        self.assertEqual((record['state'], record['result']['rolled_back']), ('rolled-back', True))

    def test_a_service_that_does_not_start_is_rolled_back_for_that_app_only(self):
        """X-AD-33: an app that is not healthy after its restore is taken back; the next app is imported all the same."""
        self.world.start_fails.add('woowbk-demo')
        self.start_chain(THREE)
        self.run_real()
        self.assertEqual(self.statuses(), {'woowbk-demo': 'rolled-back', 'woowbk-two': 'imported', 'woowbk-three': 'imported'})
        self.assertEqual(self.restores(), (THREE, ['woowbk-demo']))
        self.assert_untouched('woowbk-demo')
        self.assert_imported('woowbk-two', 'woowbk-three')
        self.assertIn('無法啟動服務', self.last_results()['woowbk-demo']['message'])

    def test_a_backup_that_misses_a_file_is_rolled_back_for_that_app_only(self):
        """X-AD-30: the extracted backup lacks an item (the adapter says so after its restore began): that app only."""
        self.world.raise_in['woowbk-three'] = BackupError('job-failed', '備份內容缺少項目 volumes/data.tar。')
        self.start_chain(THREE)
        self.run_real()
        self.assertEqual(self.statuses(), {'woowbk-demo': 'imported', 'woowbk-two': 'imported', 'woowbk-three': 'rolled-back'})
        self.assertIn('備份內容缺少項目', self.last_results()['woowbk-three']['message'])
        self.assert_untouched('woowbk-three')

    def test_a_rollback_that_fails_needs_a_person_and_the_other_apps_are_still_imported(self):
        self.world.fail_restore_after['woowbk-demo'] = 1
        self.world.fail_rollback_restore.add('woowbk-demo')
        self.start_chain(THREE)
        self.run_real()
        self.assertEqual(self.statuses(), {'woowbk-demo': 'failed', 'woowbk-two': 'imported', 'woowbk-three': 'imported'})
        row = self.last_results()['woowbk-demo']
        self.assertIn('需人工處理', row['message'])
        self.assertEqual(row['safety_backup_id'], self.safeties()['woowbk-demo']['id'])
        self.assertIn(row['safety_backup_id'], row['message'], 'the message names the backup to restore from')
        self.assertEqual(self.records()[1]['state'], 'failed')
        self.assert_imported('woowbk-two', 'woowbk-three')

    def test_a_backup_that_does_not_hold_the_app_leaves_that_app_and_restores_the_others(self):
        """FL-08, X-AR-12: of the apps asked for, one is not in the backup (restore chain of a converted backup)."""
        ids = []

        def two_of_three(ctx, params):
            app_ids = ['woowbk-demo', 'woowbk-three']
            result = flows.run_backup(ctx, {'apps': app_ids, 'include_images': False, 'note': '兩個應用'})
            ids.append(result['backup_id'])
            return {'backup_id': result['backup_id']}

        job = self.start()  # a plain backup job to make the one backup the chain restores
        jobs.run_job(self.paths, job['job_id'], deps=self.deps, handlers={'backup': two_of_three})
        self.world.data.update({app: self.marker(app) for app in THREE})
        self.start_chain(THREE, kind='ha-restore', restore_backup=ids[0])
        self.run_real()
        self.assertEqual(self.statuses(), {'woowbk-demo': 'imported', 'woowbk-two': 'failed', 'woowbk-three': 'imported'})
        row = self.last_results()['woowbk-two']
        self.assertEqual(row['code'], 'incompatible')
        self.assertIn('此備份不包含應用「woowbk-two」', row['message'])
        self.assertEqual(self.restores(), (['woowbk-demo', 'woowbk-three'], []))
        self.assert_untouched('woowbk-two')
        self.assert_imported('woowbk-demo', 'woowbk-three')

    def test_a_converted_backup_that_cannot_be_read_is_that_apps_alone(self):
        original = self.convert

        def convert(ctx, params):
            result = original(ctx, params)
            if params['apps'] == ['woowbk-two']:
                self.archive.corrupt.add(self.storage.archive_path(result['backup_id']).name)
            return result

        self.convert = convert
        self.start_chain(THREE)
        self.run_real()
        self.assertEqual(self.statuses(), {'woowbk-demo': 'imported', 'woowbk-two': 'failed', 'woowbk-three': 'imported'})
        self.assertEqual(self.last_results()['woowbk-two']['code'], 'corrupt-archive')
        self.assert_untouched('woowbk-two')



def pax_global():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT, pax_headers={'path': 'x'}) as tar:
        tar.addfile(tarfile.TarInfo('a'))
    return buffer.getvalue()


# The hostile nested archives of the restore check, by the rows of the owner's list that name them (nested.py refuses each;
# the restore side's checks are not relaxed: only the one app whose backup carries it is left out).
HOSTILE = {
    'X-NS-01': {
        'an absolute name': [{'name': '/etc/cron.d/x', 'data': b'x'}],
        'a name with ..': [{'name': 'a/../../x', 'data': b'x'}],
        'an empty component': [{'name': 'a//b', 'data': b'x'}],
        'a name that is too long': [{'name': 'a/' + 'b' * 5000, 'data': b'x'}]},
    'X-NS-05': {
        'a device file': [{'name': 'dev', 'kind': tarfile.CHRTYPE}],
        'a block device': [{'name': 'disk', 'kind': tarfile.BLKTYPE}],
        'a name twice': [{'name': 'a', 'data': b'1'}, {'name': 'a', 'data': b'2'}],
        'a file where a directory was': [{'name': 'd/x', 'data': b'1'}, {'name': 'd', 'data': b'2'}],
        'a link where a directory was': [{'name': 'd/', 'kind': tarfile.DIRTYPE},
                                         {'name': 'd', 'kind': tarfile.SYMTYPE, 'linkname': '/etc'}]},
    'X-NS-06': {
        'a file below a file': [{'name': 'f', 'data': b'x'}, {'name': 'f/x', 'data': b'x'}],
        'a file below a link that leaves the volume': [{'name': 'esc', 'kind': tarfile.SYMTYPE, 'linkname': '/home/appowner'},
                                                       {'name': 'esc/containers.conf', 'data': b'[engine]\n'}],
        'a file below a fifo': [{'name': 'pipe', 'kind': tarfile.FIFOTYPE}, {'name': 'pipe/x', 'data': b'x'}],
        'a file below a hard link': [{'name': 'f', 'data': b'x'}, {'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': 'f'},
                                     {'name': 'l/x', 'data': b'x'}]},
    'X-NS-07': {
        'a hard link to nothing': [{'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': 'missing'}],
        'a hard link outside': [{'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': '/etc/shadow'}],
        'a hard link with ..': [{'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': '../x'}],
        'a hard link through a link': [{'name': 'esc', 'kind': tarfile.SYMTYPE, 'linkname': '/home/appowner'},
                                       {'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': 'esc/.bashrc'}],
        'a hard link to a directory': [{'name': 'd/', 'kind': tarfile.DIRTYPE},
                                       {'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': 'd'}]},
}
RAW = {
    'X-NS-02': {'bytes that are no tar': b'\x1f\x8b' + b'\0' * 2000, 'random bytes': bytes(range(256)) * 12, 'nothing at all': b''},
    'X-NS-04': {'a global PAX header': pax_global()},
}


class NestedArchiveTests(RestoreSideCase):
    """X-NS-01, 02, 04, 05, 06, 07, 10 and X-AD-20: the nested-archive checks of the restore (nested.py, the real code on hostile
    tars) are not loosened: a chain whose second app carries a hostile or damaged archive restores the first and the third
    as usual, and the second is left exactly as the device had it, with nothing stopped and no safety backup taken."""

    def chain_with(self, data):
        self.fresh()
        self.world.data['woowbk-two'] = data
        self.start_chain(THREE)
        self.run_real()

    def assert_only_the_second_is_left_out(self, label):
        self.assertEqual(self.statuses(), {'woowbk-demo': 'imported', 'woowbk-two': 'failed', 'woowbk-three': 'imported'}, label)
        row = self.last_results()['woowbk-two']
        self.assertEqual(row['code'], 'corrupt-archive', label)
        self.assertIn('這台設備沒有任何變更', row['message'], label)
        self.assertTrue(row['message'].endswith(hachain.UNCHANGED_BAD_TAIL), 'a backup that is bad is not offered again: ' + label)
        self.assertEqual(self.restores(), (['woowbk-demo', 'woowbk-three'], []), label)
        self.assert_imported('woowbk-demo', 'woowbk-three')
        self.assert_untouched('woowbk-two')
        self.assertNotIn('woowbk-two', self.safeties(), 'refused before the safety backup: nothing was taken, nothing stopped')
        self.assertTrue(self.storage.get(row['backup_id']), 'the converted backup of the app stays')
        self.assertEqual(self.records()[3]['state'], 'failed')
        self.assertEqual(self.records()[3]['result']['changed'], False)
        self.assertEqual(self.records()[3]['result']['group']['results'][-1]['status'], 'failed')
        self.assertEqual(self.records()[-1]['state'], 'succeeded')

    def test_every_hostile_tar_of_the_list_leaves_only_its_app(self):
        for row_id, samples in HOSTILE.items():
            for label, members in samples.items():
                with self.subTest(row=row_id, sample=label):
                    self.chain_with(volume_tar(members))
                    self.assert_only_the_second_is_left_out(f'{row_id} {label}')

    def test_what_is_no_tar_and_the_global_pax_header_leave_only_their_app(self):
        for row_id, samples in RAW.items():
            for label, data in samples.items():
                with self.subTest(row=row_id, sample=label):
                    self.chain_with(data)
                    self.assert_only_the_second_is_left_out(f'{row_id} {label}')

    def test_the_checks_are_the_real_ones(self):
        """The tars above are refused by nested.py itself (so the chain test is about the real refusal), and a good one is not."""
        tmp = Path(self.tmp.name)
        for samples in HOSTILE.values():
            for label, members in samples.items():
                (tmp / 'x.tar').write_bytes(volume_tar(members))
                with self.assertRaises(BackupError, msg=label) as caught:
                    nested.check_volume(tmp / 'x.tar')
                self.assertEqual(caught.exception.code, 'corrupt-archive', label)
        (tmp / 'x.tar').write_bytes(good_tar('woowbk-two'))
        nested.check_volume(tmp / 'x.tar')

    def test_data_that_is_cut_short_while_it_is_prepared_rolls_back_only_its_app(self):
        """X-NS-10: a member's data ends early, or preparing it fails: found while the restore streams it, after the app was
        stopped. That app is rolled back from its own safety backup; the others stay imported."""
        whole = volume_tar([{'name': 'files/', 'kind': tarfile.DIRTYPE}, {'name': 'files/a.bin', 'data': b'A' * 5000}])
        path = Path(self.tmp.name) / 'cut.tar'
        path.write_bytes(whole[:1024 + 2500])
        with self.assertRaises(BackupError) as caught, nested.pipe_from(lambda out: nested.stream_volume(path, out)) as reader:
            reader.read()
        error = caught.exception
        self.assertEqual((error.code, error.message), ('internal-error', '準備還原資料時發生錯誤。'))
        for label, raised in (('data cut short', error), ('preparing fails', BackupError('internal-error', '準備還原資料時發生錯誤。'))):
            with self.subTest(label):
                self.fresh()
                self.world.raise_in['woowbk-two'] = raised
                self.start_chain(THREE)
                self.run_real()
                self.assertEqual(self.statuses(), {'woowbk-demo': 'imported', 'woowbk-two': 'rolled-back', 'woowbk-three': 'imported'})
                self.assertEqual(self.restores(), (THREE, ['woowbk-two']))
                self.assert_untouched('woowbk-two')
                self.assert_imported('woowbk-demo', 'woowbk-three')
                self.assertIn('準備還原資料時發生錯誤', self.last_results()['woowbk-two']['message'])

    def test_a_second_hostile_app_and_a_first_one_are_both_left_out_and_the_third_still_goes(self):
        self.fresh()
        self.world.data['woowbk-demo'] = volume_tar([{'name': '/etc/x', 'data': b'x'}])
        self.world.data['woowbk-two'] = volume_tar([{'name': 'dev', 'kind': tarfile.CHRTYPE}])
        self.start_chain(THREE)
        self.run_real()
        self.assertEqual(self.statuses(), {'woowbk-demo': 'failed', 'woowbk-two': 'failed', 'woowbk-three': 'imported'})
        self.assertEqual(self.restores(), (['woowbk-three'], []))
        self.assert_untouched('woowbk-demo', 'woowbk-two')
        self.assert_imported('woowbk-three')



class OuterFileTests(HaFlowCase):
    """hachain._outer_file_damaged on a real stored HA file: the file itself is what ends an import; one damaged add-on never."""

    def setUp(self):
        super().setUp()
        self.ha_id = self.upload(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member()), (f'{hx.N8N}.tar.gz', hx.addon_member(
            'woow-n8n', image='ghcr.io/woowtech/woow-ha-n8n-amd64'))], hx.ha_doc(addons=(hx.ODOO, hx.N8N))))
        self.path = hastore_path(self.paths, self.ha_id)
        self.ctx = types.SimpleNamespace(paths=self.paths)
        self.chain = {'ha_backup_id': self.ha_id}

    def test_the_file_as_it_was_uploaded_is_fine(self):
        self.assertFalse(hachain._outer_file_damaged(self.ctx, self.chain))

    def test_an_add_on_that_is_damaged_inside_its_member_is_no_reason_to_stop(self):
        data = bytearray(self.path.read_bytes())
        with tarfile.open(self.path) as outer:
            member = next(m for m in outer.getmembers() if m.name.endswith(f'{hx.ODOO}.tar.gz'))
        start = member.offset_data + 16  # inside the add-on's own data, past its header: the outer layout is intact
        data[start:start + 32] = bytes(b ^ 0xFF for b in data[start:start + 32])
        self.path.write_bytes(bytes(data))
        self.assertFalse(hachain._outer_file_damaged(self.ctx, self.chain), 'same size, same layout: one member is that app\'s')

    def test_a_file_that_changed_is_one(self):
        self.path.write_bytes(self.path.read_bytes() + b'\0' * 512)
        self.assertTrue(hachain._outer_file_damaged(self.ctx, self.chain))
        self.path.write_bytes(self.path.read_bytes()[:-2048])
        self.assertTrue(hachain._outer_file_damaged(self.ctx, self.chain))

    def test_another_backup_in_its_place_is_one_although_it_opens(self):
        """haimport._open compares the size with what was uploaded: a valid HA file of another size is 'the file changed'."""
        other = hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member(extra=({'name': 'data/more.bin', 'data': random.Random(1).randbytes(30000)},)))],
                               hx.ha_doc(addons=(hx.ODOO,)))
        self.assertNotEqual(len(other), self.path.stat().st_size)
        self.path.write_bytes(other)
        with habackup.open_backup(self.path) as backup:  # it does open: only its size tells
            self.assertEqual(backup.layout.size, len(other))
        self.assertTrue(hachain._outer_file_damaged(self.ctx, self.chain))

    def test_a_file_that_is_no_longer_a_backup_is_one(self):
        self.path.write_bytes(b'x' * self.path.stat().st_size)
        self.assertTrue(hachain._outer_file_damaged(self.ctx, self.chain))

    def test_a_file_that_is_gone_is_one(self):
        self.path.unlink()
        self.assertTrue(hachain._outer_file_damaged(self.ctx, self.chain))
        self.assertTrue(hachain._outer_file_damaged(self.ctx, {'ha_backup_id': 'ha-' + '1' * 20}))
        self.assertTrue(hachain._outer_file_damaged(self.ctx, {'ha_backup_id': None}))


def hastore_path(paths, ha_id):
    from woowbackup import hastore
    return hastore.HaStore(paths).file_path(ha_id)


if __name__ == '__main__':
    unittest.main()
