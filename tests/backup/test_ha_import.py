"""HA import jobs (haimport.py, jobs.py; CONTRACT sections 7, 8, 9 "Home Assistant import"): job records and keys,
the space guard, ha-imports.json, and the check/convert orchestration with the app steps replaced by stubs (the
container steps themselves are covered by test_ha_odoo/test_ha_n8n/test_ha_tempctr and the dev-c lab run). Team E2."""
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import flows, ha_n8n, ha_odoo, haimport, jobs
from woowbackup.errors import BackupError
from woowbackup.paths import Paths
from woowbackup.storage import Storage

from . import hafixtures as hx
from .test_flows import HOST, FakeArchive, FakeKeys, FakeReporter
from .test_jobs import JobCase

GIB = 1024 ** 3
N8N_MEMBER = hx.addon_member('woow-n8n', image='ghcr.io/woowtech/woow-ha-n8n-amd64')


def two_addons(**doc):
    return hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member()), (f'{hx.N8N}.tar.gz', N8N_MEMBER)],
                          hx.ha_doc(addons=(hx.ODOO, hx.N8N), **doc))


class FakeHaAdapter:
    """What the HA jobs ask the app's adapter: probe() and import_manifest()."""

    def __init__(self, app, world):
        self.app, self.world = app, world
        self.runner = types.SimpleNamespace(home='/home/appowner', owner=app.owner, uid=1013)
        self.job_id = None

    def probe(self):
        return {'deployed': self.app.id not in self.world.undeployed, 'problems': [], 'units': []}

    def import_manifest(self, staging_dir, **items):
        self.world.imported[self.app.id] = items
        path = Path(staging_dir) / 'quadlet.txt'
        path.write_bytes(b'quadlet')
        from woowbackup.archive import Entry
        from woowbackup.adapters.quadlet_postgres import file_digest
        size, digest = file_digest(path)
        manifest = {'id': self.app.id, 'name': self.app.name, 'adapter': 'quadlet-postgres', 'adapter_version': 1,
                    'items': sorted(items)}
        return manifest, [Entry(path=f'apps/{self.app.id}/quadlet/q', source=path, size=size, sha256=digest)]


class HaWorld:
    def __init__(self):
        self.undeployed = set()
        self.imported = {}

    def factory(self, app, **_kwargs):
        return FakeHaAdapter(app, self)


def app(app_id, name):
    return types.SimpleNamespace(id=app_id, name=name, owner='appowner', postgres=[], volumes=[], data_dirs=[])


class FlowCase(unittest.TestCase):
    job_id = 'j20261118T120000Z-0123abcd'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.paths = Paths(base=self.root / 'sys')
        self.storage = Storage(self.paths, free_space=lambda path: 100 * GIB)
        self.storage.ensure_layout()
        self.keys = FakeKeys(self.root)
        self.archive = FakeArchive()
        self.world = HaWorld()
        self.catalog = {'odoo': app('odoo', 'Odoo 18'), 'n8n': app('n8n', 'n8n 工作流程')}
        self.deps = flows.Deps(storage=self.storage, keys=self.keys, archive=self.archive,
                               load_catalog=lambda: self.catalog, adapter_factory=self.world.factory,
                               host_info=lambda: dict(HOST), encrypt_by_default=lambda: True)
        self.reporter = FakeReporter()
        patcher = mock.patch.object(flows, 'running_reserve', lambda ctx: 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def upload(self, data):
        info = self.storage.begin_upload('ha.tar', len(data))
        Path(info['path']).write_bytes(data)
        return self.storage.finish_upload(info['upload_id'])['id']

    def ctx(self, key=None):
        self.reporter = FakeReporter()
        ctx = flows.FlowContext(self.paths, self.job_id, self.deps, self.reporter)
        ctx.ha_key = key
        return ctx


def odoo_found(ok=True):
    return {'target_version': '18.0-20260926', 'odoo': {'databases': [
        {'name': 'woowtest', 'ok': ok, 'blockers': [] if ok else ['缺模組'], 'warnings': [], 'partners': 5,
         'users': 2, 'attachments': 1, 'attachment_bytes': 10, 'modules': 26, 'custom_modules': [],
         'crons_active': 0, 'mail_servers_active': 0, 'size': 1}]}}


def n8n_found(blockers=()):
    return {'target_version': '2.43.6', 'blockers': list(blockers), 'warnings': [],
            'n8n': {'owner_email': 'ha-probe@probe.invalid', 'workflows': 3, 'workflows_active': 1, 'credentials': 1,
                    'executions': 1, 'users': 1, 'projects': 1, 'variables': 0, 'data_tables': 0,
                    'community_packages': [], 'workflows_to_fix': []}}


class CheckFlowTests(FlowCase):
    def run_check(self, ha_id, apps, key=None):
        return flows.run_verify(self.ctx(key), {'source': 'ha', 'ha_backup_id': ha_id, 'apps': apps,
                                                'key_provided': key is not None})

    def test_result_shape_and_phases(self):
        ha_id = self.upload(two_addons())
        with mock.patch.object(ha_odoo, 'check', return_value=odoo_found()) as odoo, \
                mock.patch.object(ha_n8n, 'check', return_value=n8n_found()) as n8n:
            result = self.run_check(ha_id, ['odoo', 'n8n'])
        self.assertTrue(odoo.called and n8n.called)
        check = result['ha_check']
        self.assertEqual(check['ha_backup_id'], ha_id)
        odoo_result, n8n_result = check['apps']
        self.assertEqual(set(odoo_result), {'app_id', 'slug', 'name', 'arch', 'version', 'target_version', 'ok',
                                            'blockers', 'warnings', 'odoo'})
        self.assertEqual((odoo_result['app_id'], odoo_result['slug'], odoo_result['arch'], odoo_result['version'],
                          odoo_result['ok']), ('odoo', hx.ODOO, 'amd64', '0.4.12', True))
        self.assertEqual((n8n_result['app_id'], n8n_result['ok'], n8n_result['n8n']['owner_email']),
                         ('n8n', True, 'ha-probe@probe.invalid'))
        self.assertEqual(self.reporter.phases(), ['prepare', 'decrypt', 'decrypt', 'check'])
        self.assertFalse((Path(self.paths.staging) / self.job_id).exists(), 'staging is removed')

    def test_blockers_without_running_anything(self):
        ha_id = self.upload(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member(
            image='ghcr.io/woowtech/woow-ha-odoo-aarch64')), (f'{hx.N8N}.tar.gz', N8N_MEMBER)],
            hx.ha_doc(addons=(hx.ODOO, hx.N8N))))
        del self.catalog['n8n']
        with mock.patch.object(ha_odoo, 'check') as odoo, mock.patch.object(ha_n8n, 'check') as n8n:
            result = self.run_check(ha_id, ['odoo', 'n8n'])
        self.assertFalse(odoo.called or n8n.called)
        odoo_result, n8n_result = result['ha_check']['apps']
        self.assertFalse(odoo_result['ok'])
        self.assertIn('ARM', odoo_result['blockers'][0])
        self.assertEqual(n8n_result['blockers'], ['請先到「應用軟體」安裝同版本的 n8n 工作流程，再匯入。'])

    def test_not_deployed_and_a_failing_app_step_are_blockers(self):
        ha_id = self.upload(two_addons())
        self.world.undeployed.add('odoo')
        with mock.patch.object(ha_n8n, 'check', side_effect=BackupError('incompatible', '這台的 n8n 設定不同。')):
            result = self.run_check(ha_id, ['odoo', 'n8n'])
        odoo_result, n8n_result = result['ha_check']['apps']
        self.assertIn('還沒有部署完成', odoo_result['blockers'][0])
        self.assertEqual(n8n_result['blockers'], ['這台的 n8n 設定不同。'])

    def test_no_movable_database(self):
        ha_id = self.upload(two_addons())
        with mock.patch.object(ha_odoo, 'check', return_value=odoo_found(ok=False)):
            result = self.run_check(ha_id, ['odoo'])
        self.assertFalse(result['ha_check']['apps'][0]['ok'])

    @hx.needs_crypto
    def test_key_required_and_wrong_key_fail_the_job(self):
        ha_id = self.upload(hx.fixture('v3_gzip.tar').read_bytes())
        with self.assertRaises(BackupError) as caught:
            self.run_check(ha_id, ['odoo'])
        self.assertEqual(caught.exception.code, 'key-required')
        with self.assertRaises(BackupError) as caught:
            self.run_check(ha_id, ['odoo'], key=hx.WRONG_PASSWORD)
        self.assertEqual(caught.exception.code, 'wrong-key')


class ConvertFlowTests(FlowCase):
    def convert(self, ha_id, apps, **params):
        base = {'source': 'ha', 'ha_backup_id': ha_id, 'apps': apps, 'odoo_database': 'woowtest' if 'odoo' in apps
                else None, 'test_mode': False, 'encrypt': True, 'key_provided': False}
        base.update(params)
        return flows.run_backup(self.ctx(), base)

    def stub_odoo(self, work, app_, database, test_mode, out_dir):
        (out_dir / 'volumes').mkdir(parents=True)
        path = out_dir / 'volumes' / 'odoo18-web-data.tar'
        path.write_bytes(b'volume')
        return {'volumes': {'odoo18-web-data': path}, 'dirs': {}, 'database': database,
                'custom_modules': [{'name': 'woow_import_probe', 'version': '18.0.1.0.0', 'from': 'data/addons'}]}

    def stub_n8n(self, work, app_, test_mode, out_dir):
        return {'volumes': {}, 'postgres': {}, 'owner_email': 'ha-probe@probe.invalid', 'packages': [],
                'workflows_to_fix': [{'name': 'fix', 'active': False, 'reasons': ['x']}], 'counts': {}}

    def test_one_manual_backup_with_its_origin(self):
        ha_id = self.upload(two_addons(name='WOOW匯入測試'))
        with mock.patch.object(ha_odoo, 'convert', self.stub_odoo), mock.patch.object(ha_n8n, 'convert', self.stub_n8n):
            result = self.convert(ha_id, ['odoo', 'n8n'])
        backup_id = result['backup_id']
        meta = self.storage.get(backup_id)
        self.assertEqual((meta['type'], meta['encrypted'], [a['id'] for a in meta['apps']]), ('manual', True,
                                                                                           ['odoo', 'n8n']))
        self.assertTrue(meta['note'].startswith('由 HA 備份轉換：WOOW匯入測試（2026-11-18 '), meta['note'])
        self.assertEqual(self.reporter.phases(), ['prepare', 'decrypt', 'decrypt', 'package', 'verify'])
        self.assertEqual(sorted(self.world.imported['odoo']), ['dirs', 'volumes'])
        self.assertEqual(sorted(self.world.imported['n8n']), ['postgres', 'volumes'])
        imp = result['ha_import']
        self.assertEqual(set(imp), {'ha_backup_id', 'name', 'date', 'apps', 'odoo_database', 'test_mode',
                                    'workflows_to_fix', 'reminders', 'addons'})
        self.assertEqual((imp['ha_backup_id'], imp['apps'], imp['odoo_database'], imp['test_mode']),
                         (ha_id, ['odoo', 'n8n'], 'woowtest', False))
        self.assertEqual([a['app_id'] for a in imp['addons']], ['odoo', 'n8n'])
        self.assertFalse(any('停掉' in r or 'MCP' in r for r in imp['reminders']), 'the page writes those')
        self.assertEqual(haimport.from_ha_views(self.paths)[backup_id], imp)
        self.assertEqual(self.reporter.partial.get('temp_owners', []), [])

    def test_a_failed_conversion_leaves_no_row(self):
        ha_id = self.upload(two_addons())
        with mock.patch.object(ha_odoo, 'convert', side_effect=BackupError('incompatible', '不能搬。')):
            with self.assertRaises(BackupError):
                self.convert(ha_id, ['odoo'])
        self.assertEqual(haimport.load_registry(self.paths), {})
        self.assertEqual(self.storage.list_backups(), [])

    def test_refusals_before_any_work(self):
        ha_id = self.upload(two_addons())
        self.keys.device = None
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['n8n'])
        self.assertEqual(caught.exception.code, 'no-device-key')
        self.keys = FakeKeys(self.root)
        self.deps.keys = self.keys
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo'], odoo_database=None)
        self.assertEqual(caught.exception.code, 'invalid-request')
        del self.catalog['odoo']
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo'])
        self.assertEqual(caught.exception.code, 'app-not-in-catalog')


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.paths = Paths(base=Path(self.tmp.name))
        Storage(self.paths).ensure_layout()

    def tearDown(self):
        self.tmp.cleanup()

    def row(self, **fields):
        row = {'ha_backup_id': 'ha-' + '1' * 20, 'name': 'WOOW', 'date': '2026-11-18T09:01:20Z', 'apps': ['odoo'],
               'odoo_database': 'woowtest', 'test_mode': False, 'workflows_to_fix': [], 'reminders': [],
               'addons': [{'app_id': 'odoo', 'slug': hx.ODOO, 'name': 'Woow Odoo 18'}],
               'job_id': 'j20261118T120000Z-0123abcd', 'created': '2026-11-18T12:00:00Z'}
        row.update(fields)
        return row

    def test_register_view_forget(self):
        bid = '20261118T120001Z-0123abcd'
        haimport.register(self.paths, bid, self.row(), now=1794994800)
        path = haimport.registry_path(self.paths)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(haimport.from_ha_views(self.paths)[bid]['name'], 'WOOW')
        self.assertTrue(haimport.forget(self.paths, bid))
        self.assertFalse(haimport.forget(self.paths, bid))
        self.assertEqual(haimport.load_registry(self.paths), {})

    def test_strict_rows_and_an_unreadable_file_is_kept(self):
        for bad in (self.row(extra=1), self.row(apps=['nextcloud']), self.row(test_mode='no'),
                    self.row(workflows_to_fix=[{'name': 'x'}]), self.row(name='a\nb')):
            with self.subTest(bad=bad), self.assertRaises(BackupError):
                haimport.register(self.paths, '20261118T120001Z-0123abcd', bad)
        path = haimport.registry_path(self.paths)
        path.write_text('{"schema": 2}')
        self.assertIsNone(haimport.load_registry(self.paths))
        self.assertEqual(haimport.from_ha_views(self.paths), {})
        with self.assertRaises(BackupError):
            haimport.register(self.paths, '20261118T120001Z-0123abcd', self.row())
        self.assertEqual(path.read_text(), '{"schema": 2}', 'never replaced')

    def test_rows_of_missing_backups_are_pruned_after_a_day(self):
        old = '20261101T000000Z-00000001'
        haimport.register(self.paths, old, self.row(created='2026-11-01T00:00:00Z'), now=1793491200)
        haimport.register(self.paths, '20261118T120001Z-0123abcd', self.row(), now=1794994800)
        self.assertEqual(sorted(haimport.load_registry(self.paths)), ['20261118T120001Z-0123abcd'])


class SmallPartsTests(unittest.TestCase):
    def test_space_guard(self):
        free = {'value': 10 * GIB}
        guard = haimport.SpaceGuard(['/x'], 2 * GIB,
                                    statvfs=lambda _p: types.SimpleNamespace(f_bavail=free['value'], f_frsize=1))
        guard.check(GIB)
        self.assertEqual(guard.budget(), 8 * GIB)
        free['value'] = 2 * GIB - 10
        guard.wrote(1)  # checked only every GUARD_STEP bytes
        with self.assertRaises(BackupError) as caught:
            guard.wrote(haimport.GUARD_STEP)
        self.assertEqual(caught.exception.code, 'insufficient-space')

    def test_note(self):
        note = haimport.note_for({'name': 'WOOW 測試', 'date': '2026-11-18T09:01:20Z'})
        self.assertTrue(note.startswith('由 HA 備份轉換：WOOW 測試（') and note.endswith('）'))
        self.assertEqual(haimport.note_for({'name': '', 'date': 'bad'}), '由 HA 備份轉換：（沒有名稱）（bad）')

    def test_key_file_is_raw_and_masked(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / 'key'
        path.write_bytes(' old password '.encode())
        self.addCleanup(jobs.unmask_secret, ' old password ')
        self.assertEqual(haimport.read_key_file(path), ' old password ')
        self.assertNotIn('old password', jobs.redact('the key is  old password  here'))
        path.write_bytes(b'\xff\xfe')
        with self.assertRaises(BackupError):
            haimport.read_key_file(path)


class HaJobTests(JobCase):
    params = {'source': 'ha', 'ha_backup_id': 'ha-' + '1' * 20, 'apps': ['odoo'], 'key_provided': True}

    def test_phases_live_in_the_record(self):
        record = self.store.create('verify', dict(self.params))
        self.assertEqual([(p['id'], p['label']) for p in record['phases']],
                         [('prepare', '準備'), ('decrypt', '解開 HA 備份'), ('check', '檢查內容與版本')])
        record = self.store.create('backup', dict(self.params, test_mode=False, encrypt=False))
        self.assertEqual([p['label'] for p in record['phases']], ['準備', '解開 HA 備份', '轉換資料', '封裝（未加密）',
                                                                  '驗證備份'])
        self.assertEqual(self.store.create('verify', {'backup_id': 'b'})['phases'][1]['label'], '解密並驗證檔案')

    def test_an_ha_key_is_stored_raw(self):
        key = ' AB12-CD34 typed key '
        job_id = self.start('verify', dict(self.params), key_text=key, key_kind='ha')['job_id']
        path = self.store.key_path(job_id)
        self.assertEqual(path.read_bytes(), key.encode('utf-8'), 'never trimmed or normalised')
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        for bad in ('', 'a\x00b'):
            with self.subTest(bad=bad), self.assertRaises(BackupError):
                self.start('verify', dict(self.params), key_text=bad, key_kind='ha', request_id='req-ha-bad-1')
        with self.assertRaises(BackupError):
            self.start('verify', dict(self.params), key_text='x', key_kind='rsa', request_id='req-ha-bad-2')

    def test_run_job_masks_the_key_before_the_first_line(self):
        key = 'Opaque Old Password'
        job_id = self.start('verify', dict(self.params), key_text=key, key_kind='ha')['job_id']
        self.addCleanup(jobs.unmask_secret, key)  # read_key_file keeps it masked for the rest of the job process
        seen = {}

        def handler(ctx, params):
            seen['key'] = ctx.ha_key
            ctx.log(f'logging {key} by mistake')
            raise BackupError('wrong-key', f'bad {key}')

        record = jobs.run_job(self.paths, job_id, deps=object(), handlers={'verify': handler})
        self.assertEqual(seen['key'], key)
        log = '\n'.join(self.store.read_log(job_id))
        self.assertNotIn(key, log)
        self.assertNotIn(key, json.dumps(record, ensure_ascii=False))
        self.assertEqual(record['error']['code'], 'wrong-key')
        self.assertFalse(self.store.key_path(job_id).exists())

    def test_recovery_sweeps_the_throwaway_objects_of_a_dead_job(self):
        record = self.store.create('backup', dict(self.params, test_mode=False))
        record.update(state='running', temp_owners=['appowner'])
        self.store.save(record)
        swept = []

        def sweep(job_id, owners):
            swept.append((job_id, owners))
            return []

        jobs.recover_interrupted(self.paths, unit_active=lambda _u: False, sweep_temp=sweep)
        after = self.store.get(record['id'])
        self.assertEqual(swept, [(record['id'], ['appowner'])])
        self.assertEqual((after['state'], after['temp_owners']), ('interrupted', []))
        self.assertIn('轉換 HA 備份的作業意外中斷', after['error']['message'])
        self.assertFalse(jobs.has_leftovers(after))

    def test_a_failed_sweep_is_retried(self):
        record = self.store.create('verify', dict(self.params))
        record.update(state='failed', temp_owners=['appowner'])
        self.store.save(record)
        jobs.recover_interrupted(self.paths, unit_active=lambda _u: False, sweep_temp=lambda _j, _o: ['podman 沒回應'])
        self.assertEqual(self.store.get(record['id'])['temp_owners'], ['appowner'])
        jobs.recover_interrupted(self.paths, unit_active=lambda _u: False, sweep_temp=lambda _j, _o: [])
        self.assertEqual(self.store.get(record['id'])['temp_owners'], [])


if __name__ == '__main__':
    unittest.main()
