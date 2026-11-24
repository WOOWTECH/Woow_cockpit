"""HA import jobs (haimport.py, jobs.py; CONTRACT sections 7, 8, 9 "Home Assistant import"): job records and keys,
the space guard, ha-imports.json, and the check/convert orchestration with the app steps replaced by stubs (the
container steps themselves are covered by test_ha_odoo/test_ha_n8n/test_ha_tempctr and the dev-c lab run). Team E2."""
import contextlib
import errno
import io
import json
import os
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import errors, flows, ha_n8n, ha_odoo, haapps, habackup, haimport, haissues, jobs, tempctr
from woowbackup.errors import BackupError
from woowbackup.haissues import Issue
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
        entries = [Entry(path=f'apps/{self.app.id}/quadlet/q', source=path, size=size, sha256=digest)]
        for name, source in sorted((items.get('volumes') or {}).items()):
            size, digest = file_digest(source)
            entries.append(Entry(path=f'apps/{self.app.id}/volumes/{name}.tar', source=Path(source), size=size,
                                 sha256=digest))
        return manifest, entries


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
        self.audit = []
        self.deps = flows.Deps(storage=self.storage, keys=self.keys, archive=self.archive,
                               load_catalog=lambda: self.catalog, adapter_factory=self.world.factory,
                               host_info=lambda: dict(HOST), encrypt_by_default=lambda: True, audit=self.audit.append)
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
        self.assertEqual(set(check), {'schema', 'ha_backup_id', 'shared', 'apps'})
        self.assertEqual((check['schema'], check['ha_backup_id'], check['shared']), (2, ha_id, []))
        odoo_result, n8n_result = check['apps']
        self.assertEqual(set(odoo_result), {'app_id', 'slug', 'name', 'arch', 'version', 'target_version', 'ok',
                                            'blockers', 'warnings', 'importable', 'issues', 'choices', 'odoo'})
        self.assertEqual((odoo_result['app_id'], odoo_result['slug'], odoo_result['arch'], odoo_result['version'],
                          odoo_result['ok'], odoo_result['importable']), ('odoo', hx.ODOO, 'amd64', '0.4.12', True, True))
        self.assertEqual(odoo_result['choices'], {'database': [{'value': 'woowtest', 'label': 'woowtest', 'ok': True,
                                                                'default': True}]})
        self.assertEqual((n8n_result['app_id'], n8n_result['ok'], n8n_result['n8n']['owner_email']),
                         ('n8n', True, 'ha-probe@probe.invalid'))
        self.assertNotIn('choices', n8n_result, 'nothing to choose')
        self.assertEqual(self.reporter.phases(), ['prepare', 'decrypt', 'decrypt', 'check'])
        self.assertFalse((Path(self.paths.staging) / self.job_id).exists(), 'staging is removed')

    def test_the_processor_is_never_guessed_from_the_image_name(self):
        """HA-06: no name of an image keeps an app out (multi-arch images, the architecture in the tag, a local build);
        the data decides, and what this device's database refuses to open is that app's stop."""
        for image, arch in (('ghcr.io/woowtech/woow-ha-odoo-amd64', 'amd64'),
                            ('ghcr.io/woowtech/woow-ha-odoo-aarch64', 'aarch64'),
                            ('ghcr.io/woowtech/woow-ha-odoo-riscv64', 'unknown'),
                            ('ghcr.io/woowtech/woow-ha-odoo:aarch64-0.4.12', 'unknown'), ('local/odoo', 'unknown')):
            ha_id = self.upload(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member(image=image))],
                                               hx.ha_doc(addons=(hx.ODOO,))))
            with self.subTest(image=image), mock.patch.object(ha_odoo, 'check', return_value=odoo_found()) as odoo:
                row = self.run_check(ha_id, ['odoo'])['ha_check']['apps'][0]
                self.assertEqual((odoo.called, row['arch'], row['importable'], row['ok'], row['issues']),
                                 (True, arch, True, True, []))
        with mock.patch.object(ha_odoo, 'check', side_effect=BackupError('job-failed', '暫用資料庫無法啟動。')):
            row = self.run_check(ha_id, ['odoo'])['ha_check']['apps'][0]
        self.assertEqual((row['importable'], row['blockers']), (False, ['暫用資料庫無法啟動。']))
        self.assertFalse(hasattr(haimport, '_arch_blocker'))

    def test_an_app_that_is_not_installed_here(self):
        ha_id = self.upload(two_addons())
        del self.catalog['n8n']
        with mock.patch.object(ha_odoo, 'check', return_value=odoo_found()), mock.patch.object(ha_n8n, 'check') as n8n:
            odoo_result, n8n_result = self.run_check(ha_id, ['odoo', 'n8n'])['ha_check']['apps']
        self.assertFalse(n8n.called)
        self.assertTrue(odoo_result['importable'])
        self.assertEqual(n8n_result['issues'][0]['id'], 'ha.not-installed')
        self.assertEqual(n8n_result['blockers'], [haimport.INSTALL_HINT.format(name='n8n 工作流程')])
        self.assertNotIn('應用軟體', n8n_result['blockers'][0], 'that page installs nothing (DESIGN H-b 16)')
        self.catalog = types.SimpleNamespace(get=lambda _id: None, problem_for=lambda app_id: {
            'code': 'owner-missing', 'message': f'應用 {app_id} 的擁有者帳號 odoo 不存在。'})
        row = self.run_check(ha_id, ['odoo'])['ha_check']['apps'][0]
        self.assertEqual((row['issues'][0]['id'], row['issues'][0]['message']),
                         ('ha.not-installed', '應用 odoo 的擁有者帳號 odoo 不存在。'), 'the catalog says why')

    def test_not_deployed_and_a_failing_app_step_are_blockers(self):
        ha_id = self.upload(two_addons())
        self.world.undeployed.add('odoo')
        with mock.patch.object(ha_n8n, 'check', side_effect=BackupError('incompatible', '這台的 n8n 設定不同。')):
            result = self.run_check(ha_id, ['odoo', 'n8n'])
        odoo_result, n8n_result = result['ha_check']['apps']
        self.assertIn('還沒有部署完成', odoo_result['blockers'][0])
        self.assertEqual(odoo_result['issues'][0]['id'], 'ha.not-deployed')
        self.assertEqual(n8n_result['blockers'], ['這台的 n8n 設定不同。'])
        self.assertEqual(n8n_result['issues'], [{'id': 'failure.incompatible', 'level': 'stop',
                                                 'message': '這台的 n8n 設定不同。', 'items': [], 'more': 0, 'action': ''}])

    def test_an_odd_add_on_is_a_blocker_and_the_other_app_is_still_checked(self):
        """Review C-09: addon.json that is not WOOWTECH's, the same add-on twice, an owner that is gone."""
        mismatched = hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member('something_else')),
                                     (f'{hx.N8N}.tar.gz', N8N_MEMBER)], hx.ha_doc(addons=(hx.ODOO, hx.N8N)))
        twice = hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member()), ('aaaa1111_odoo18ce.tar.gz',
                                                                         hx.addon_member()),
                                (f'{hx.N8N}.tar.gz', N8N_MEMBER)],
                               hx.ha_doc(addons=(hx.ODOO, 'aaaa1111_odoo18ce', hx.N8N)))
        for data, words in ((mismatched, 'addon.json 不符'), (twice, '兩個相同的附加元件')):
            ha_id = self.upload(data)
            with mock.patch.object(ha_n8n, 'check', return_value=n8n_found()) as n8n:
                result = self.run_check(ha_id, ['odoo', 'n8n'])
            odoo_result, n8n_result = result['ha_check']['apps']
            self.assertFalse(odoo_result['ok'])
            self.assertIn(words, odoo_result['blockers'][0])
            self.assertTrue(n8n.called and n8n_result['ok'])
        ha_id = self.upload(two_addons())
        with mock.patch.object(FakeHaAdapter, 'probe', side_effect=BackupError('owner-missing', '找不到應用擁有者帳號 odoo。')):
            result = self.run_check(ha_id, ['odoo'])
        self.assertEqual(result['ha_check']['apps'][0]['blockers'], ['找不到應用擁有者帳號 odoo。'])

    def test_no_movable_database(self):
        ha_id = self.upload(two_addons())
        with mock.patch.object(ha_odoo, 'check', return_value=odoo_found(ok=False)):
            result = self.run_check(ha_id, ['odoo'])
        row = result['ha_check']['apps'][0]
        self.assertEqual((row['ok'], row['importable']), (False, False))
        self.assertEqual([(i['id'], i['level'], i.get('database')) for i in row['issues']],
                         [('legacy.blocker', 'stop', None), ('legacy.blocker', 'stop', 'woowtest')])
        self.assertEqual(row['choices']['database'], [{'value': 'woowtest', 'label': 'woowtest', 'ok': False}])

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
        work.phase('convert')
        (out_dir / 'volumes').mkdir(parents=True)
        path = out_dir / 'volumes' / 'odoo18-web-data.tar'
        path.write_bytes(b'volume')
        return {'volumes': {'odoo18-web-data': path}, 'dirs': {}, 'database': database,
                'custom_modules': [{'name': 'woow_import_probe', 'version': '18.0.1.0.0', 'from': 'data/addons'}]}

    def stub_n8n(self, work, app_, test_mode, out_dir):
        work.phase('convert')
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
        self.assertEqual(self.reporter.phases(), ['prepare', 'decrypt', 'convert', 'decrypt', 'convert', 'package',
                                                  'verify'])
        self.assertEqual(sorted(self.world.imported['odoo']), ['dirs', 'volumes'])
        self.assertEqual(sorted(self.world.imported['n8n']), ['postgres', 'volumes'])
        self.assertEqual(result['results'], [
            {'app_id': app_id, 'status': 'converted', 'code': None, 'message': None, 'issues': []}
            for app_id in ('odoo', 'n8n')])
        imp = result['ha_import']
        self.assertEqual(set(imp), {'ha_backup_id', 'name', 'date', 'apps', 'odoo_database', 'test_mode',
                                    'workflows_to_fix', 'reminders', 'reminders_by_app', 'notes', 'addons', 'group',
                                    'results', 'left_databases', 'kept'})
        self.assertEqual((imp['group'], imp['results'], imp['left_databases'], imp['kept']), (None, [], [], None))
        self.assertEqual((imp['ha_backup_id'], imp['apps'], imp['odoo_database'], imp['test_mode']),
                         (ha_id, ['odoo', 'n8n'], 'woowtest', False))
        self.assertEqual([a['app_id'] for a in imp['addons']], ['odoo', 'n8n'])
        # To-dos per app, explanations apart (review P-05, UI-3); the page writes the HA add-on, MCP, test import and
        # delete-the-HA-file lines itself.
        self.assertEqual(imp['reminders'], [])
        self.assertEqual(sorted(imp['reminders_by_app']), ['n8n', 'odoo'])
        self.assertIn('ha-probe@probe.invalid', imp['reminders_by_app']['n8n'][0])
        self.assertTrue(any('woow_import_probe' in line for line in imp['notes']))
        self.assertTrue(imp['notes'][0].startswith('Odoo') and imp['notes'][-1].startswith('n8n'), imp['notes'])
        everything = imp['notes'] + [line for lines in imp['reminders_by_app'].values() for line in lines]
        self.assertFalse(any('停掉' in r or 'MCP' in r or '刪除' in r for r in everything), 'the page writes those')
        self.assertEqual(haimport.from_ha_views(self.paths)[backup_id], imp)
        self.assertEqual(self.reporter.partial.get('temp_owners', []), [])
        # One overall progress that never goes back while both apps go through 解開/轉換 (review UI-2).
        steps = [(event[2], event[3]) for event in self.reporter.events if event[0] == 'phase-progress']
        percents = [percent for percent, _message in steps]
        self.assertEqual(percents, sorted(percents))
        self.assertEqual(percents[:4], [20, 30, 40, 50])
        self.assertIn('（1/2）', steps[1][1])
        self.assertIn('（2/2）', steps[2][1])

    def test_a_failure_after_the_backup_is_listed_keeps_its_origin(self):
        ha_id = self.upload(two_addons())
        real = flows._package

        def package_then_fail(*args, **kwargs):
            real(*args, **kwargs)
            raise BackupError('job-failed', '寫入紀錄失敗。')

        with mock.patch.object(ha_odoo, 'convert', self.stub_odoo), \
                mock.patch.object(flows, '_package', package_then_fail):
            with self.assertRaises(BackupError):
                self.convert(ha_id, ['odoo'])
        listed = [b['id'] for b in self.storage.list_backups()]
        self.assertEqual(len(listed), 1)
        self.assertEqual(list(haimport.from_ha_views(self.paths)), listed, 'review C-10')

    def test_long_names_and_line_breaks_never_lose_the_origin(self):
        ha_id = self.upload(two_addons(name='WOOW 匯入'))
        modules = [{'name': f'odoo_ai_assistant_chatgpt_connector_{i:02d}', 'version': '18.0.1.0.0',
                    'from': 'data/addons'} for i in range(20)]

        def odoo(work, app_, database, test_mode, out_dir):
            result = self.stub_odoo(work, app_, database, test_mode, out_dir)
            result['custom_modules'] = modules
            return result

        def n8n(work, app_, test_mode, out_dir):
            result = self.stub_n8n(work, app_, test_mode, out_dir)
            result['workflows_to_fix'] = [{'name': 'a\nb\t' + 'x' * 400, 'active': True,
                                           'reasons': [f'讀寫本機檔案（/share/{"y" * 90}\n）：這台的資料夾和 HA 不同。'] * 12}]
            return result

        with mock.patch.object(ha_odoo, 'convert', odoo), mock.patch.object(ha_n8n, 'convert', n8n):
            result = self.convert(ha_id, ['odoo', 'n8n'])
        row = haimport.from_ha_views(self.paths)[result['backup_id']]
        self.assertEqual(row, result['ha_import'])
        self.assertEqual(row['name'], 'WOOW 匯入')
        item = row['workflows_to_fix'][0]
        self.assertTrue(item['name'].startswith('a b ') and len(item['name']) == 200)
        self.assertEqual(len(item['reasons']), 10)
        self.assertTrue(all('\n' not in reason for reason in item['reasons']))
        self.assertTrue(any('等 20 個' in line for line in row['notes']), 'review C-03')

    def test_a_failed_conversion_leaves_no_row(self):
        ha_id = self.upload(two_addons())
        with mock.patch.object(ha_odoo, 'convert', side_effect=BackupError('incompatible', '不能搬。')):
            with self.assertRaises(BackupError):
                self.convert(ha_id, ['odoo'])
        self.assertEqual(haimport.load_registry(self.paths), {})
        self.assertEqual(self.storage.list_backups(), [])

    def test_the_archive_must_fit_before_packaging(self):
        ha_id = self.upload(two_addons())

        def big_odoo(work, app_, database, test_mode, out_dir):
            result = self.stub_odoo(work, app_, database, test_mode, out_dir)
            result['volumes']['odoo18-web-data'].write_bytes(b'x' * (4 * 1024 * 1024))
            return result

        floor = haimport.WATCH_MARGIN
        free = {'value': floor + 2 * 1024 * 1024}  # the up-front 3 x members fits, a 4 MiB archive does not
        with mock.patch.object(ha_odoo, 'convert', big_odoo), \
                mock.patch.object(haimport.SpaceGuard, 'free', lambda guard: free['value']):
            with self.assertRaises(BackupError) as caught:
                self.convert(ha_id, ['odoo'])
        self.assertEqual(caught.exception.code, 'insufficient-space')
        self.assertEqual(self.storage.list_backups(), [])
        self.assertEqual(haimport.load_registry(self.paths), {})

    def test_refusals_before_any_work(self):
        ha_id = self.upload(two_addons())
        for database in ('', 'x' * 64, 'a\nb', '資' * 22):
            with self.subTest(database=database), self.assertRaises(BackupError) as caught:
                self.convert(ha_id, ['odoo'], odoo_database=database)
            self.assertEqual((caught.exception.code, caught.exception.details), ('invalid-request',
                                                                                  {'field': 'odoo_database'}))
        del self.catalog['odoo']
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo'])
        self.assertEqual(caught.exception.code, 'app-not-in-catalog')
        self.assertEqual(caught.exception.result['results'][0]['status'], 'skipped')

    def test_the_device_key_is_created_for_an_encrypted_conversion(self):
        """HA-13 (D11): no key on this device is no reason to refuse; the page asks to save it afterwards."""
        ha_id = self.upload(two_addons())
        self.keys.device = None
        with mock.patch.object(ha_n8n, 'convert', self.stub_n8n):
            result = self.convert(ha_id, ['n8n'])
        self.assertTrue(result['encrypted'])
        self.assertIsNotNone(self.keys.device)
        self.assertTrue(any('自動建立這台的加密金鑰' in line for line in self.reporter.logs))
        self.assertEqual(self.audit, [f'device-key-created key_id={self.keys.device.key_id} reason=ha-import '
                                      f'job={self.job_id}'])
        with mock.patch.object(ha_n8n, 'convert', self.stub_n8n):
            self.convert(ha_id, ['n8n'])
        self.assertEqual(len(self.audit), 1, 'only once')

    def test_a_device_key_that_cannot_be_created_stops_the_import(self):
        ha_id = self.upload(two_addons())
        self.keys.device = None
        for error in (BackupError('internal-error', '建立加密金鑰失敗。'), OSError(errno.EACCES, 'x')):
            with self.subTest(error=repr(error)), mock.patch.object(FakeKeys, 'ensure_device_key', side_effect=error), \
                    mock.patch.object(ha_n8n, 'convert') as convert, self.assertRaises(BackupError) as caught:
                self.convert(ha_id, ['n8n'])
            self.assertEqual((caught.exception.code, caught.exception.job_wide, convert.called),
                             ('no-device-key', True, False))
        with mock.patch.object(ha_n8n, 'convert', self.stub_n8n):
            self.assertFalse(self.convert(ha_id, ['n8n'], encrypt=False)['encrypted'], 'no key is needed then')
        self.assertIsNone(self.keys.device)

    def test_the_only_database_that_can_move_is_chosen(self):
        """HA-14: an import that names no database takes the only one that can move; with several the customer chooses."""
        ha_id = self.upload(two_addons())
        found = odoo_found()
        found['odoo']['databases'].append(dict(found['odoo']['databases'][0], name='broken', ok=False, blockers=['x']))
        seen = []

        def check(work, app_):
            (work.staging / 'odoo-work').mkdir()
            work.phase('check')
            return found

        def convert(work, app_, database, test_mode, out_dir):
            seen.append((database, sorted(os.listdir(work.staging)), work.sink(app_).database))
            return self.stub_odoo(work, app_, database, test_mode, out_dir)

        with mock.patch.object(ha_odoo, 'check', check), mock.patch.object(ha_odoo, 'convert', convert), \
                mock.patch.object(ha_n8n, 'convert', self.stub_n8n):
            result = self.convert(ha_id, ['n8n', 'odoo'], odoo_database=None)
            self.assertEqual(result['ha_import']['odoo_database'], 'woowtest')
            self.assertEqual(seen, [('woowtest', ['apps'], 'woowtest')], 'what the choice read is gone, the rest stays')
            found['odoo']['databases'][1].update(ok=True, blockers=[])
            with self.assertRaises(BackupError) as caught:
                self.convert(ha_id, ['odoo'], odoo_database=None)
            self.assertEqual((caught.exception.code, caught.exception.message),
                             ('invalid-request', haimport.CHOOSE_DATABASE))
            self.assertEqual(caught.exception.result['results'][0]['status'], 'skipped')
            for db in found['odoo']['databases']:
                db['ok'] = False
            with self.assertRaises(BackupError) as caught:
                self.convert(ha_id, ['odoo'], odoo_database=None)
            self.assertEqual(caught.exception.code, 'incompatible')
            found['odoo']['databases'][0].update(ok=True, name='客戶 a.b$c')
            self.assertEqual(self.convert(ha_id, ['odoo'], odoo_database=None)['ha_import']['odoo_database'],
                             '客戶 a.b$c', 'a name with other characters moves, too')

    def test_choices_name_the_database(self):
        ha_id = self.upload(two_addons())
        with mock.patch.object(ha_odoo, 'convert', self.stub_odoo):
            result = self.convert(ha_id, ['odoo'], odoo_database=None, choices={'odoo': {'database': 'prod'}})
        self.assertEqual(result['ha_import']['odoo_database'], 'prod')


class ConvertResultTests(FlowCase):
    """B5: what one app's conversion reports, and the confirmed lines."""

    convert = ConvertFlowTests.convert
    stub_n8n = ConvertFlowTests.stub_n8n

    def failed(self, error, code, status, issues):
        ha_id = self.upload(two_addons())
        with mock.patch.object(ha_n8n, 'convert', side_effect=error), contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['n8n'])
        row = caught.exception.result['results'][0]
        self.assertEqual(set(row), {'app_id', 'status', 'code', 'message', 'issues'})
        self.assertEqual((caught.exception.code, row['app_id'], row['code'], row['status'],
                          [i['id'] for i in row['issues']]), (code, 'n8n', code, status, issues))
        self.assertEqual((self.storage.list_backups(), haimport.load_registry(self.paths)), ([], {}))
        self.assertFalse((Path(self.paths.staging) / self.job_id).exists())
        return caught.exception, row

    def test_a_failure_half_way(self):
        self.failed(BackupError('corrupt-archive', '資料讀不出來。'), 'corrupt-archive', 'failed',
                    ['failure.corrupt-archive'])
        self.failed(BackupError('job-failed', '核對不一致。'), 'job-failed', 'failed', ['failure.job-failed'])

    def test_an_unexpected_error_is_generic_and_only_this_apps(self):
        error, row = self.failed(RuntimeError('secret detail'), 'internal-error', 'failed', ['failure.internal-error'])
        self.assertEqual(error.message, '作業發生未預期的內部錯誤，請查看系統日誌。')
        self.assertNotIn('secret detail', json.dumps(row, ensure_ascii=False))

    def test_a_full_disk(self):
        error, row = self.failed(OSError(errno.ENOSPC, 'No space left on device'), 'insufficient-space', 'failed',
                                 ['failure.insufficient-space'])
        self.assertTrue(error.job_wide)
        self.assertIn('沒有任何變更', row['message'])

    def test_a_stop_is_a_skip(self):
        issue = Issue('legacy.blocker', 'stop', '不能搬。')
        self.failed(haissues.stopped(issue), 'incompatible', 'skipped', ['legacy.blocker'])
        self.failed(BackupError('not-found', '沒有。'), 'not-found', 'skipped', ['failure.not-found'])

    def test_a_cancel_and_a_termination_stay_what_they_are(self):
        ha_id = self.upload(two_addons())
        for error in (flows.Cancelled(), jobs.Terminated(15)):
            with mock.patch.object(ha_n8n, 'convert', side_effect=error), self.assertRaises(type(error)) as caught:
                self.convert(ha_id, ['n8n'])
            self.assertFalse(hasattr(caught.exception, 'result'))

    def test_a_missing_add_on(self):
        ha_id = self.upload(hx.simple_backup())
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['n8n'])
        row = caught.exception.result['results'][0]
        self.assertEqual((row['status'], row['code'], row['issues'][0]['id']), ('skipped', 'not-found',
                                                                                'ha.addon-missing'))

    def test_several_apps_in_one_job_stay_as_they_were(self):
        ha_id = self.upload(two_addons())
        with mock.patch.object(ha_odoo, 'convert', side_effect=RuntimeError('x')), self.assertRaises(RuntimeError):
            self.convert(ha_id, ['odoo', 'n8n'])
        with mock.patch.object(ha_odoo, 'convert', side_effect=BackupError('incompatible', 'x')), \
                self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['odoo', 'n8n'])
        self.assertFalse(hasattr(caught.exception, 'result'))

    def stub_confirming(self, names):
        def convert(work, app_, test_mode, out_dir):
            sink = work.sink(app_)
            sink.auto('version.target-unknown', '自動處理的事')
            sink.confirm('legacy.warning', '憑證要重新輸入', names)
            sink.notice('legacy.warning', '提醒')
            return self.stub_n8n(work, app_, test_mode, out_dir)
        return convert

    def test_confirmed_lines(self):
        """G1: without the key only this app stops; with it the import goes on and the registry keeps what was
        confirmed; one more name needs another confirmation."""
        ha_id = self.upload(two_addons())
        key = Issue('legacy.warning', 'confirm', 'x', ['a', 'b']).key('n8n')
        with mock.patch.object(ha_n8n, 'convert', self.stub_confirming(['a', 'b'])):
            for acknowledged in (None, {}, {'n8n': []}, {'odoo': [key]}, {'_shared': [key]}):
                with self.subTest(acknowledged=acknowledged), self.assertRaises(BackupError) as caught:
                    self.convert(ha_id, ['n8n'], **({} if acknowledged is None else {'acknowledged': acknowledged}))
                row = caught.exception.result['results'][0]
                self.assertEqual((row['status'], row['code']), ('skipped', 'confirmation-required'))
                self.assertIn(key, [issue.get('key') for issue in row['issues']], 'what is to be confirmed')
            result = self.convert(ha_id, ['n8n'], acknowledged={'n8n': [key]}, group={'id': 'g0123456789abcdef'})
        self.assertEqual([i['level'] for i in result['results'][0]['issues']], ['confirm', 'auto', 'notice'])
        row = haimport.load_registry(self.paths)[result['backup_id']]
        self.assertEqual((row['confirmed'], row['group']), ([{'app_id': 'n8n', 'id': 'legacy.warning',
                                                             'items': ['a', 'b']}], 'g0123456789abcdef'))
        self.assertEqual(result['ha_import']['group'], 'g0123456789abcdef')
        self.assertNotIn('confirmed', result['ha_import'], 'the list stays small')
        self.assertIn('自動處理：自動處理的事', self.reporter.logs)
        with mock.patch.object(ha_n8n, 'convert', self.stub_confirming(['a', 'b', 'c'])), \
                self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['n8n'], acknowledged={'n8n': [key]})
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_what_stays_on_ha_is_registered(self):
        ha_id = self.upload(two_addons())

        def convert(work, app_, database, test_mode, out_dir):
            result = ConvertFlowTests.stub_odoo(self, work, app_, database, test_mode, out_dir)
            return dict(result, left_databases=['test', 'demo', 'a\nb', 7])

        with mock.patch.object(ha_odoo, 'convert', convert):
            result = self.convert(ha_id, ['odoo'])
        self.assertEqual(result['ha_import']['left_databases'], ['test', 'demo'])


class IsolationTests(FlowCase):
    """HA-12, DESIGN C1/C2: in a check nothing one app meets stops another, and what ends the whole job still hands over
    what was found."""

    def setUp(self):
        super().setUp()
        self.catalog = {importer.app_id: app(importer.app_id, importer.name) for importer in haapps.IMPORTERS}

    def all_addons(self):
        slugs = [f'aaaa1111_{importer.slug}' for importer in haapps.IMPORTERS]
        members = [(f'{slug}.tar.gz', hx.addon_member(importer.slug, image=f'ghcr.io/woowtech/{importer.slug}-amd64'))
                   for slug, importer in zip(slugs, haapps.IMPORTERS)]
        return hx.outer_bytes(members, hx.ha_doc(addons=slugs))

    def run_check(self, ha_id, apps, checks, ctx=None, **params):
        """Run the check of `apps`; `checks`: {app id: what its module's check does (an exception or a function)}, every
        other app's check succeeds."""
        ran = []

        def stub(importer):
            def check(work, app_):
                ran.append(importer.app_id)
                action = checks.get(importer.app_id)
                if isinstance(action, BaseException):
                    raise action
                if action is not None:
                    return action(work, app_)
                return {'target_version': '1', importer.app_id: {'facts': 1}}
            return check

        self.ran = ran
        with contextlib.ExitStack() as stack:
            for importer in haapps.IMPORTERS:
                stack.enter_context(mock.patch.object(importer.load(), 'check', stub(importer)))
            stack.enter_context(mock.patch.object(ha_odoo, 'check_blockers', lambda found: []))
            self.stderr = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            ctx = ctx or self.ctx()
            return flows.run_verify(ctx, {'source': 'ha', 'ha_backup_id': ha_id, 'apps': apps, 'key_provided': False,
                                          **params})['ha_check']

    def ids(self, row):
        return [issue['id'] for issue in row['issues']]

    def test_every_error_of_one_app_is_only_its_own(self):
        ha_id = self.upload(self.all_addons())
        failures = [BackupError(code, f'{code} 的原因。') for code in sorted(errors.CODES - {'busy'})]
        failures += [RuntimeError('boom'), OSError(errno.EIO, 'bad'), MemoryError(), KeyError('x'), ValueError('x')]
        for error in failures:
            with self.subTest(error=repr(error)):
                check = self.run_check(ha_id, ['odoo', 'n8n', 'hermes'], {'n8n': error})
                odoo, n8n, hermes = check['apps']
                self.assertEqual(self.ran, ['odoo', 'n8n', 'hermes'])
                self.assertTrue(odoo['importable'] and odoo['ok'] and hermes['importable'] and hermes['ok'])
                self.assertEqual((n8n['importable'], n8n['ok'], [i['level'] for i in n8n['issues']]),
                                 (False, False, ['stop']))
                code = error.code if isinstance(error, BackupError) else 'internal-error'
                self.assertEqual(self.ids(n8n), [f'failure.{code}'])
                self.assertNotIn('n8n', n8n, 'no section of an app whose check did not finish')
                self.assertNotIn('boom', json.dumps(check))

    def test_ten_apps_and_every_second_one_fails(self):
        ha_id = self.upload(self.all_addons())
        apps = [importer.app_id for importer in haapps.IMPORTERS]
        self.assertEqual(len(apps), 10)
        kinds = [BackupError('corrupt-archive', 'x'), RuntimeError('x'), BackupError('insufficient-space', 'x'),
                 BackupError('permission-denied', 'x'), BackupError('wrong-key', 'x')]
        for bad in (apps[::2], apps[1::2]):
            check = self.run_check(ha_id, apps, dict(zip(bad, kinds)))
            self.assertEqual(self.ran, apps, 'every app is looked at, in order')
            self.assertEqual([row['app_id'] for row in check['apps'] if not row['importable']], bad)
            self.assertEqual([row['app_id'] for row in check['apps'] if row['importable']],
                             [app_id for app_id in apps if app_id not in bad])
        self.assertFalse((Path(self.paths.staging) / self.job_id).exists(), 'staging is removed')

    def test_what_comes_before_the_apps_own_check_is_only_its_own_too(self):
        ha_id = self.upload(self.all_addons())
        with mock.patch.object(FakeHaAdapter, 'probe', side_effect=[RuntimeError('podman is gone'),
                                                                    {'deployed': True, 'problems': []}]):
            odoo, n8n = self.run_check(ha_id, ['odoo', 'n8n'], {})['apps']
        self.assertEqual((self.ids(odoo), n8n['importable']), (['failure.internal-error'], True))
        real = self.world.factory
        self.deps.adapter_factory = lambda app_, **kw: (_ for _ in ()).throw(OSError('x')) if app_.id == 'odoo' \
            else real(app_, **kw)
        odoo, n8n = self.run_check(ha_id, ['odoo', 'n8n'], {})['apps']
        self.assertEqual((self.ids(odoo), n8n['importable']), (['failure.internal-error'], True))
        with mock.patch.object(haimport.SpaceGuard, 'free', lambda guard: guard.floor + 10):
            row = self.run_check(ha_id, ['n8n'], {})['apps'][0]
        self.assertEqual((self.ids(row), self.ran), (['failure.insufficient-space'], []), "the app's own estimate")

    def test_a_module_that_answers_nonsense_is_only_its_own(self):
        ha_id = self.upload(self.all_addons())
        for answer in ({'target_version': '1'}, {'odoo': {}, 'choices': {'database': [{}]}}, None,
                       {'odoo': {}, 'issues': ['x']}, {'odoo': {'databases': [{'ok': True}]}}):
            with self.subTest(answer=answer):
                odoo, n8n = self.run_check(ha_id, ['odoo', 'n8n'], {'odoo': lambda w, a: answer})['apps']
                self.assertEqual((odoo['importable'], self.ids(odoo), n8n['importable']),
                                 (False, ['failure.internal-error'], True))

    def test_issues_found_before_the_failure_stay(self):
        ha_id = self.upload(self.all_addons())

        def check(work, app_):
            work.sink(app_).notice('legacy.warning', '提醒')
            work.sink(app_).stop('legacy.blocker', '第一個原因')
            raise BackupError('job-failed', '後來失敗。')

        row = self.run_check(ha_id, ['n8n'], {'n8n': check})['apps'][0]
        self.assertEqual(self.ids(row), ['legacy.blocker', 'failure.job-failed', 'legacy.warning'])

    def test_nothing_of_one_app_is_left_for_the_next(self):
        """Work.reset_app: open members, throwaway objects and staging of an app are gone before the next one starts."""
        ha_id = self.upload(self.all_addons())
        made, seen = [], {}

        class Temp:
            def __init__(self, runner, job_id, **kwargs):
                self.containers, self.volumes, self.left = [], [], []
                made.append(self)

            def cleanup(self):
                self.containers.clear()
                self.volumes.clear()
                return list(self.left)

            def kill_all(self):
                pass

        def failing(work, app_):
            tmp = work.temp(app_)
            tmp.containers.append('woowbk-x-hapg')
            tmp.volumes.append('woowbk-x-hapg')
            (work.staging / 'odoo-work' / 'deep').mkdir(parents=True)
            (work.staging / 'odoo-work' / 'deep' / 'plain.sqlite').write_text('x')
            (work.staging / 'loose').write_text('x')
            seen['stream'] = work.open(work.addon_member('odoo18ce'))
            raise RuntimeError('half way')

        def after(work, app_):
            tmp = work.temp(app_)
            seen.update(first=(made[0].containers, made[0].volumes), containers=list(tmp.containers),
                        staging=os.listdir(work.staging), closed=seen['stream'].closed)
            return {'target_version': '1', 'n8n': {}}

        with mock.patch.object(tempctr, 'TempObjects', Temp):
            self.run_check(ha_id, ['odoo', 'n8n'], {'odoo': failing, 'n8n': after})
        self.assertEqual(seen, {'stream': seen['stream'], 'first': ([], []), 'containers': [], 'staging': [],
                                'closed': True})
        self.assertEqual(self.reporter.partial['temp_owners'], [])
        # What could not be removed does not stand in the next app's way, and is tried again at the end.
        made.clear()

        def stuck(work, app_):
            work.temp(app_).left = ['woowbk-x-hapg']
            raise RuntimeError('half way')

        with mock.patch.object(tempctr, 'TempObjects', Temp):
            rows = self.run_check(ha_id, ['odoo', 'n8n'], {'odoo': stuck, 'n8n': after})['apps']
        self.assertEqual((rows[1]['importable'], len(made)), (True, 2))
        self.assertEqual(self.reporter.partial['temp_owners'], ['appowner'], 'left for the recovery')
        with mock.patch.object(tempctr, 'TempObjects', Temp), \
                mock.patch.object(Temp, 'cleanup', side_effect=RuntimeError('podman is gone')):
            rows = self.run_check(ha_id, ['odoo', 'n8n'], {'odoo': failing, 'n8n': after})['apps']
        self.assertTrue(rows[1]['importable'], 'a clean-up that fails costs no result')
        self.assertEqual(self.reporter.partial['temp_owners'], ['appowner'])

    def test_every_app_gets_throwaway_objects_of_its_own(self):
        """Once tempctr knows scopes (F3) each app's objects have names of their own: the app's place in the job."""
        ha_id = self.upload(self.all_addons())
        made = []

        def temp_objects(runner, job_id, **kwargs):
            made.append(kwargs.get('scope'))
            return types.SimpleNamespace(cleanup=lambda: [], kill_all=lambda: None)

        def check(work, app_):
            self.assertIs(work.temp(app_), work.temp(app_))
            return {'target_version': '1', app_.id: {}}

        checks = {app_id: check for app_id in ('odoo', 'n8n', 'hermes')}
        with mock.patch.object(tempctr, 'TempObjects', temp_objects):
            self.run_check(ha_id, list(checks), checks)
            self.assertEqual(made, [None, None, None])
            with mock.patch.object(tempctr, 'SCOPES', True, create=True):
                self.run_check(ha_id, list(checks), checks)
        self.assertEqual(made[3:], ['0', '1', '2'])

    def test_a_successful_app_is_reset_too(self):
        ha_id = self.upload(self.all_addons())
        seen = []

        def check(work, app_):
            seen.append(os.listdir(work.staging))
            (work.staging / f'{app_.id}-work').mkdir()
            return {'target_version': '1', app_.id: {}}

        self.run_check(ha_id, ['odoo', 'n8n'], {'odoo': check, 'n8n': check})
        self.assertEqual(seen, [[], []])

    def ended(self, error, apps=('odoo', 'n8n', 'hermes'), raises=None):
        ha_id = self.upload(self.all_addons())
        with self.assertRaises(raises or type(error)) as caught:
            self.run_check(ha_id, list(apps), {'n8n': error})
        self.assertEqual(self.ran, ['odoo', 'n8n'], 'the job ended')
        check = caught.exception.result['ha_check']
        self.assertEqual((check['schema'], [row['app_id'] for row in check['apps']]), (2, list(apps)))
        self.assertTrue(check['apps'][0]['importable'], 'what was found is handed over')
        self.assertFalse(check['apps'][1]['importable'] or check['apps'][2]['importable'])
        self.assertEqual(self.ids(check['apps'][2]), ['ha.not-checked'])
        return caught.exception, check['apps'][1]

    def test_what_ends_the_whole_job_hands_over_what_it_found(self):
        for error in (flows.Cancelled(), jobs.Terminated(15)):
            _error, row = self.ended(error)
            self.assertEqual(self.ids(row), ['ha.not-checked'])
        error, row = self.ended(haissues.job_wide(BackupError('insufficient-space', '看門狗停止了作業。')))
        self.assertEqual((self.ids(row), row['issues'][0]['message']), (['failure.insufficient-space'],
                                                                        '看門狗停止了作業。'))
        error, row = self.ended(OSError(errno.ENOSPC, 'No space left'), raises=BackupError)
        self.assertEqual((error.code, error.message, self.ids(row)),
                         ('insufficient-space', haissues.DISK_FULL, ['failure.insufficient-space']))
        self.ended(BackupError('busy', '另一個作業正在執行。'))

    def test_the_watchdog_ends_the_job_not_one_app(self):
        ha_id = self.upload(self.all_addons())
        with mock.patch.object(haimport.SpaceGuard, 'free', lambda guard: guard.floor - 1), \
                self.assertRaises(BackupError) as caught:
            self.run_check(ha_id, ['odoo', 'n8n'], {})
        self.assertEqual((caught.exception.code, caught.exception.job_wide), ('insufficient-space', True))
        self.assertEqual([self.ids(row) for row in caught.exception.result['ha_check']['apps']],
                         [['failure.insufficient-space'], ['ha.not-checked']])

    def test_a_cancel_between_two_apps(self):
        ha_id = self.upload(self.all_addons())
        ctx = self.ctx()

        def check(work, app_):
            ctx.reporter.cancel = True
            return {'target_version': '1', app_.id: {}}

        with self.assertRaises(flows.Cancelled) as caught:
            self.run_check(ha_id, ['odoo', 'n8n'], {'odoo': check}, ctx=ctx)
        rows = caught.exception.result['ha_check']['apps']
        self.assertEqual([row['importable'] for row in rows], [True, False])

    def test_run_job_keeps_what_was_found(self):
        """The result of a check that ended early is in the record (jobs.run_job reads error.result)."""
        ha_id = self.upload(self.all_addons())
        store = jobs.JobStore(self.paths)
        record = store.create('verify', {'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['odoo', 'n8n'],
                                         'key_provided': False})
        wide = haissues.job_wide(BackupError('insufficient-space', '看門狗停止了作業。'))
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(ha_odoo, 'check', lambda w, a: odoo_found()))
            stack.enter_context(mock.patch.object(ha_n8n, 'check', side_effect=wide))
            stack.enter_context(mock.patch.object(self.deps, 'sweep_temp', None))
            done = jobs.run_job(self.paths, record['id'], deps=self.deps)
        self.assertEqual((done['state'], done['error']['code']), ('failed', 'insufficient-space'))
        self.assertEqual([row['importable'] for row in done['result']['ha_check']['apps']], [True, False])

    def test_the_outer_file_still_fails_the_job(self):
        ha_id = self.upload(self.all_addons())
        path = Path(self.paths.data) / 'ha-backups' / f'{ha_id}.tar'
        path.write_bytes(path.read_bytes()[:-1024])
        with self.assertRaises(BackupError):
            self.run_check(ha_id, ['odoo'], {})

    def test_a_key_is_created_by_the_import_and_the_check_says_so(self):
        ha_id = self.upload(self.all_addons())
        self.keys.device = None
        check = self.run_check(ha_id, ['n8n'], {})
        self.assertEqual([(i['id'], i['level']) for i in check['shared']], [('shared.device-key', 'auto')])
        self.assertIsNone(self.keys.device, 'the check itself creates nothing')
        self.deps.encrypt_by_default = lambda: False
        self.assertEqual(self.run_check(ha_id, ['n8n'], {})['shared'], [])
        self.deps.encrypt_by_default = lambda: True
        with mock.patch.object(FakeKeys, 'device_key', side_effect=OSError('x')):
            self.assertEqual(self.run_check(ha_id, ['n8n'], {})['shared'], [])


class AddonTests(FlowCase):
    """HA-03, HA-04, HA-05: an add-on that is missing, there twice or not WOOWTECH's."""

    run_check = CheckFlowTests.run_check

    def twice(self):
        return hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member()),
                               ('aaaa1111_odoo18ce.tar.gz', hx.addon_member(image='ghcr.io/woowtech/woow-ha-odoo-aarch64')),
                               (f'{hx.N8N}.tar.gz', N8N_MEMBER)],
                              hx.ha_doc(addons=(hx.ODOO, 'aaaa1111_odoo18ce', hx.N8N)))

    def checked(self, ha_id, choices=None):
        with mock.patch.object(ha_odoo, 'check', return_value=odoo_found()) as odoo, \
                mock.patch.object(ha_n8n, 'check', return_value=n8n_found()):
            result = flows.run_verify(self.ctx(), {'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['odoo', 'n8n'],
                                                   'key_provided': False, **({'choices': choices} if choices else {})})
        row, other = result['ha_check']['apps']
        self.assertTrue(other['importable'], 'the other app is checked whatever happens')
        return odoo.called, row

    def test_a_missing_add_on_only_leaves_its_app_out(self):
        ha_id = self.upload(hx.outer_bytes([(f'{hx.N8N}.tar.gz', N8N_MEMBER)], hx.ha_doc(addons=(hx.N8N,))))
        called, row = self.checked(ha_id)
        self.assertEqual((called, row['importable'], row['issues'][0]['id']), (False, False, 'ha.addon-missing'))
        self.assertIn('請在 HA 建立備份時勾選', row['issues'][0]['action'])

    def test_two_stores_need_a_choice(self):
        ha_id = self.upload(self.twice())
        called, row = self.checked(ha_id)
        self.assertEqual((called, row['importable'], row['issues'][0]['id']), (False, False, 'ha.addon-choice'))
        self.assertEqual(row['choices']['addon'], [
            {'value': hx.ODOO, 'label': f'name of {hx.ODOO}（商店 5e12b5f3，1.0.0）'},
            {'value': 'aaaa1111_odoo18ce', 'label': 'name of aaaa1111_odoo18ce（商店 aaaa1111，1.0.0）'}])
        for slug, arch in ((hx.ODOO, 'amd64'), ('aaaa1111_odoo18ce', 'aarch64')):
            called, row = self.checked(ha_id, {'odoo': {'addon': slug}})
            self.assertEqual((called, row['importable'], row['slug'], row['arch']), (True, True, slug, arch))
            self.assertEqual(len(row['choices']['addon']), 2, 'the choice can be changed')
        called, row = self.checked(ha_id, {'odoo': {'addon': 'bbbb2222_odoo18ce'}})
        self.assertEqual((called, row['importable'], row['issues'][0]['message']),
                         (False, False, '選的附加元件不在這份 HA 備份裡，請重新選擇。'))

    def test_a_conversion_takes_the_chosen_one(self):
        ha_id = self.upload(self.twice())
        base = {'source': 'ha', 'ha_backup_id': ha_id, 'apps': ['odoo'], 'odoo_database': 'woowtest', 'test_mode': False,
                'encrypt': True, 'key_provided': False}
        with mock.patch.object(ha_odoo, 'convert', lambda *args: ConvertFlowTests.stub_odoo(self, *args)):
            with self.assertRaises(BackupError) as caught:
                flows.run_backup(self.ctx(), base)
            self.assertEqual(caught.exception.result['results'][0]['status'], 'skipped')
            result = flows.run_backup(self.ctx(), dict(base, choices={'odoo': {'addon': 'aaaa1111_odoo18ce'}}))
        self.assertEqual(result['ha_import']['addons'][0]['slug'], 'aaaa1111_odoo18ce')

    def test_an_add_on_that_is_not_ours_only_leaves_its_app_out(self):
        for member in (hx.addon_member('something_else'),
                       hx.tar_bytes([{'name': 'data', 'type': 'dir'}], compress=True),
                       hx.tar_bytes([{'name': './addon.json', 'data': b'{"system": 1}'}], compress=True)):
            ha_id = self.upload(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', member), (f'{hx.N8N}.tar.gz', N8N_MEMBER)],
                                               hx.ha_doc(addons=(hx.ODOO, hx.N8N))))
            called, row = self.checked(ha_id)
            self.assertEqual((called, row['importable']), (False, False))
            self.assertIn(row['issues'][0]['id'], ('ha.addon-other', 'failure.corrupt-archive'))


class KeyTests(unittest.TestCase):
    """HA-12, KEY-16: which members are opened with the key, and what a key that does not fit stops."""

    class Backup:
        def __init__(self, good=(), broken=()):
            self.good, self.broken, self.opened = good, broken, []

        def open_member(self, name, keys=None):
            self.opened.append(name)
            if name in self.broken:
                raise BackupError('corrupt-archive', '損毀')
            if name not in self.good:
                raise BackupError('wrong-key', '金鑰不正確')
            return contextlib.nullcontext()

    @staticmethod
    def member(name, encryption='v3', role='addon', slug=None):
        return habackup.Member(name, 0, 10, role, slug or name, encryption, True)

    def wanted(self, *names, plain=()):
        return [(name, self.member(name, 'none' if name in plain else 'v3')) for name in names]

    def test_nothing_encrypted_needs_no_key(self):
        backup = self.Backup()
        self.assertEqual(haimport.key_problems(backup, None, self.wanted('a', plain=('a',))), {})
        self.assertEqual(haimport.key_problems(backup, object(), self.wanted('a', plain=('a',))), {})
        self.assertEqual(backup.opened, [])

    def test_a_missing_key_ends_the_job(self):
        with self.assertRaises(BackupError) as caught:
            haimport.key_problems(self.Backup(), None, self.wanted('a', 'b', plain=('a',)))
        self.assertEqual((caught.exception.code, caught.exception.job_wide), ('key-required', True))

    def test_a_key_that_opens_nothing_ends_the_job(self):
        with self.assertRaises(BackupError) as caught:
            haimport.key_problems(self.Backup(), object(), self.wanted('a', 'b'))
        self.assertEqual((caught.exception.code, caught.exception.job_wide), ('wrong-key', True))
        with self.assertRaises(BackupError) as caught:
            haimport.key_problems(self.Backup(broken=('a',)), object(), self.wanted('a', 'b'))
        self.assertEqual(caught.exception.code, 'wrong-key')

    def test_one_member_that_does_not_open_stops_only_its_app(self):
        found = haimport.key_problems(self.Backup(good=('a',)), object(), self.wanted('a', 'b'))
        self.assertEqual({app_id: error.code for app_id, error in found.items()}, {'b': 'wrong-key'})
        self.assertFalse(found['b'].job_wide)
        found = haimport.key_problems(self.Backup(broken=('a', 'b')), object(), self.wanted('a', 'b'))
        self.assertEqual({app_id: error.code for app_id, error in found.items()}, {'a': 'corrupt-archive',
                                                                                   'b': 'corrupt-archive'})

    def test_a_member_two_apps_read_is_opened_once(self):
        share = self.member('share.tar.gz', role='folder', slug='share')
        backup = self.Backup(good=('share.tar.gz',))
        self.assertEqual(haimport.key_problems(backup, object(), [('odoo', share), ('nextcloud', share)]), {})
        self.assertEqual(backup.opened, ['share.tar.gz'])
        found = haimport.key_problems(self.Backup(good=('n8n',)), object(), [('odoo', share), ('n8n', self.member('n8n'))])
        self.assertEqual(list(found), ['odoo'])

    def test_the_share_folder_counts_for_the_apps_that_read_it(self):
        share = self.member('share.tar.gz', role='folder', slug='share')
        other = self.member('media.tar.gz', role='folder', slug='media')
        members = {app_id: self.member(app_id, 'none') for app_id in ('odoo', 'n8n', 'nextcloud', 'woow-code-server')}
        layout = types.SimpleNamespace(members=(*members.values(), other, share))
        wanted = haimport.needed_members(layout, members)
        self.assertEqual([app_id for app_id, member in wanted if member is share],
                         ['odoo', 'nextcloud', 'woow-code-server'])
        self.assertFalse(any(member is other for _app, member in wanted))
        bare = types.SimpleNamespace(members=tuple(members.values()))
        self.assertEqual(len(haimport.needed_members(bare, members)), 4)

    def test_every_importer_that_reads_the_share_folder_says_so(self):
        engine = Path(haimport.__file__).resolve().parent
        for importer in haapps.IMPORTERS:
            reads = 'share_member(' in (engine / f'{importer.module}.py').read_text(encoding='utf-8')
            self.assertEqual(importer.needs_share, reads, importer.app_id)


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
        for bad in (self.row(extra=1), self.row(apps=['wordpress']), self.row(test_mode='no')):
            with self.subTest(bad=bad), self.assertRaises(BackupError):
                haimport.register(self.paths, '20261118T120001Z-0123abcd', bad)
        # What a conversion writes is cleaned instead of refused (review C-03).
        haimport.register(self.paths, '20261118T120001Z-0123abcd',
                          self.row(workflows_to_fix=[{'name': 'x'}], name='a\nb', reminders=['r'] * 30,
                                   reminders_by_app={'odoo': ['n\x00'], 'wordpress': ['x']}))
        row = haimport.load_registry(self.paths)['20261118T120001Z-0123abcd']
        self.assertEqual((row['name'], row['workflows_to_fix']), ('a b', [{'name': 'x', 'active': False,
                                                                             'reasons': []}]))
        self.assertEqual((len(row['reminders']), row['reminders_by_app']), (20, {'odoo': ['n ']}))
        haimport.forget(self.paths, '20261118T120001Z-0123abcd')
        path = haimport.registry_path(self.paths)
        for text in ('{"schema": 2}', '{"schema": 3, "imports": {}}', '{"schema": true, "imports": {}}',
                     '{"schema": "2", "imports": {}}', '{"imports": {}}'):
            path.write_text(text)
            self.assertIsNone(haimport.load_registry(self.paths), text)
            self.assertEqual(haimport.from_ha_views(self.paths), {})
            with self.assertRaises(BackupError):
                haimport.register(self.paths, '20261118T120001Z-0123abcd', self.row())
            self.assertEqual(path.read_text(), text, 'never replaced')

    def test_rows_written_before_the_per_app_texts_still_count(self):
        bid = '20261118T120001Z-0123abcd'
        haimport.register(self.paths, bid, self.row())
        path = haimport.registry_path(self.paths)
        doc = json.loads(path.read_text())
        for key in ('reminders_by_app', 'notes'):
            del doc['imports'][bid][key]
        path.write_text(json.dumps(doc))
        view = haimport.from_ha_views(self.paths)[bid]
        self.assertEqual((view['reminders_by_app'], view['notes']), ({}, []))

    NEW_KEYS = {'group': None, 'results': [], 'confirmed': [], 'left_databases': [], 'kept': None}

    def test_a_schema_1_file_is_read_and_becomes_schema_2(self):
        """B8: the rows of an earlier engine get empty values and are kept by the next write."""
        bid, other = '20261118T120001Z-0123abcd', '20261118T120002Z-0123abcd'
        haimport.register(self.paths, bid, self.row(), now=1794994800)
        path = haimport.registry_path(self.paths)
        doc = json.loads(path.read_text())
        self.assertEqual((doc['schema'], {key: doc['imports'][bid][key] for key in self.NEW_KEYS}), (2, self.NEW_KEYS))
        doc['schema'] = 1
        for key in self.NEW_KEYS:
            del doc['imports'][bid][key]
        path.write_text(json.dumps(doc))
        self.assertEqual({key: haimport.load_registry(self.paths)[bid][key] for key in self.NEW_KEYS}, self.NEW_KEYS)
        self.assertEqual(json.loads(path.read_text())['schema'], 1, 'reading changes nothing')
        haimport.register(self.paths, other, self.row(), now=1794994800)
        doc = json.loads(path.read_text())
        self.assertEqual((doc['schema'], sorted(doc['imports'])), (2, [bid, other]))

    def test_an_older_engine_never_rewrites_a_schema_2_file(self):
        bid = '20261118T120001Z-0123abcd'
        haimport.register(self.paths, bid, self.row(group='g0123456789abcdef'), now=1794994800)
        path = haimport.registry_path(self.paths)
        before = path.read_bytes()
        with mock.patch.object(haimport, 'REGISTRY_READS', (1,)), mock.patch.object(haimport, 'REGISTRY_SCHEMA', 1):
            self.assertIsNone(haimport.load_registry(self.paths))
            with self.assertRaises(BackupError):
                haimport.register(self.paths, '20261118T120002Z-0123abcd', self.row(), now=1794994800)
            self.assertFalse(haimport.forget(self.paths, bid))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(haimport.load_registry(self.paths)[bid]['group'], 'g0123456789abcdef')

    def test_what_an_import_adds_to_a_row_is_cleaned_and_kept(self):
        bid = '20261118T120001Z-0123abcd'
        result = {'app_id': 'odoo', 'status': 'imported', 'convert_job_id': 'j20261118T120000Z-0123abcd',
                  'restore_job_id': 'bad', 'backup_id': bid, 'safety_backup_id': None, 'code': None, 'message': 'a\nb'}
        haimport.register(self.paths, bid, self.row(
            group='g0123456789abcdef', kept='kept-1', left_databases=['test', 'x' * 64, 'a\x00', 7, '客戶'],
            results=[result, dict(result, app_id='wordpress'), dict(result, status='maybe'), 'x', dict(result, app_id=[])],
            confirmed=[{'app_id': 'odoo', 'id': 'odoo.modules', 'items': ['m\n1'] + ['n' * 500] * 40},
                       {'app_id': '_shared', 'id': 'shared.pauses', 'items': 'x'}, {'app_id': 'x', 'id': 'odoo.x'},
                       {'app_id': 'odoo', 'id': 'BAD'}]), now=1794994800)
        row = haimport.load_registry(self.paths)[bid]
        self.assertEqual(row['results'], [dict(result, restore_job_id=None, message='a b')])
        self.assertEqual((row['group'], row['kept'], row['left_databases']), ('g0123456789abcdef', 'kept-1', ['test', '客戶']))
        self.assertEqual([(line['app_id'], line['id']) for line in row['confirmed']],
                         [('odoo', 'odoo.modules'), ('_shared', 'shared.pauses')])
        names = row['confirmed'][0]['items']
        self.assertEqual((names[0], len(names), {len(n) for n in names[1:]}), ('m 1', 20, {120}))
        self.assertEqual(set(haimport.view_row(row)), set(haimport.VIEW_KEYS))
        many = [{'app_id': 'odoo', 'id': 'odoo.modules', 'items': ['n' * 120] * 20}] * 60
        haimport.register(self.paths, bid, self.row(confirmed=many, group='bad', kept=7), now=1794994800)
        row = haimport.load_registry(self.paths)[bid]
        self.assertEqual((len(row['confirmed']), row['group'], row['kept']), (haimport.MAX_CONFIRMED, None, None))
        self.assertLessEqual(sum(len(n) for line in row['confirmed'] for n in line['items']),
                             haimport.MAX_CONFIRMED_TEXT)

    def test_a_row_with_anything_else_is_not_believed(self):
        bid = '20261118T120001Z-0123abcd'
        haimport.register(self.paths, bid, self.row(), now=1794994800)
        path = haimport.registry_path(self.paths)
        good = json.loads(path.read_text())
        for key, value in (('group', 'x'), ('group', 5), ('kept', ''), ('kept', 5), ('results', {}), ('results', [{}]),
                           ('results', [{'app_id': 'odoo', 'status': 'imported'}]), ('confirmed', None),
                           ('confirmed', [{'app_id': 'odoo', 'id': 'odoo.x', 'items': [], 'more': 1}]),
                           ('left_databases', ['']), ('left_databases', 'x'), ('extra', 1)):
            with self.subTest(key=key, value=value):
                doc = json.loads(json.dumps(good))
                doc['imports'][bid][key] = value
                path.write_text(json.dumps(doc))
                self.assertEqual(haimport.load_registry(self.paths), {})

    def test_the_file_never_grows_beyond_what_is_read(self):
        big = [{'name': 'n' * 200, 'active': True, 'reasons': ['理' * 300] * 10} for _ in range(200)]
        for index in range(8):
            haimport.register(self.paths, f'20261118T12000{index}Z-0123abcd',
                              self.row(workflows_to_fix=big, created=f'2026-11-18T12:00:0{index}Z'), now=1794994800)
        path = haimport.registry_path(self.paths)
        self.assertLess(os.stat(path).st_size, haimport.REGISTRY_MAX_BYTES)
        rows = haimport.load_registry(self.paths)
        self.assertIn('20261118T120007Z-0123abcd', rows, 'the newest stays')
        self.assertNotIn('20261118T120000Z-0123abcd', rows, 'the oldest goes')
        self.assertGreater(len(rows), 2)

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
        with self.assertRaises(BackupError) as caught:
            guard.check(9 * GIB)
        self.assertEqual((caught.exception.code, caught.exception.job_wide), ('insufficient-space', False),
                         "one app's own estimate")
        free['value'] = 2 * GIB - 10
        guard.wrote(1)  # checked only every GUARD_STEP bytes
        with self.assertRaises(BackupError) as caught:
            guard.wrote(haimport.GUARD_STEP)
        self.assertEqual((caught.exception.code, caught.exception.job_wide), ('insufficient-space', True),
                         'below the floor nothing else may start either')

    def test_database_names(self):
        for good in ('woowtest', 'a', '客戶資料庫', 'x' * 63, 'a b', 'db-1.2$', "o'brien", '-d', 'a=b', '資' * 21):
            self.assertTrue(haimport.valid_database(good), good)
        for bad in ('', 'x' * 64, '資' * 22, 'a\nb', 'a\x00', 'a\x7f', 'a\x85', None, 5, ['a'], '\ud800'):
            self.assertFalse(haimport.valid_database(bad), repr(bad))

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


class ImageVersionTests(FlowCase):
    """CM-06: a version that the label does not tell is read from the image's settings, then from its program; without
    any it stays unknown (told, no gate)."""

    def setUp(self):
        super().setUp()
        self.app = app('emqx', 'EMQX')
        self.answers = {}
        self.calls = []
        adapter = FakeHaAdapter(self.app, self.world)
        adapter.runner.podman = self.podman
        self.deps.adapter_factory = lambda _app, **_kw: adapter
        ctx = self.ctx()
        self.work = haimport.Work(ctx, None, None, self.root)
        self.work.guard.folders = []
        self.ran = []

    def podman(self, *args, **_kwargs):
        self.calls.append(args)
        answer = self.answers['labels' if 'Labels' in str(args) else 'env']
        if isinstance(answer, BaseException):
            raise answer
        code, stdout = answer
        return types.SimpleNamespace(returncode=code, stdout=stdout)

    def version(self, run=None, **kwargs):
        test = self

        class Temp:
            def __init__(self, *_args, **_kwargs):
                self.containers = []

            def name(self, role):
                return f'woowbk-x-{role}'

            def remove(self, role):
                self.containers.remove(self.name(role))

            def run(self, role, image, args=(), **options):
                test.ran.append((image, list(args), options['entrypoint'], options['read_only_root']))
                self.containers.append(self.name(role))
                if isinstance(run, BaseException):
                    raise run
                return types.SimpleNamespace(returncode=run[0], stdout=run[1])

            def cleanup(self):
                return list(self.containers)

        with mock.patch.object(tempctr, 'TempObjects', Temp):
            self.work._temps.clear()
            found = self.work.image_version(self.app, 'docker.io/emqx/emqx:5.8.9', **kwargs)
            self.assertEqual([c for tmp in self.work._temps.values() for c in tmp.containers], [])
        return found

    def test_the_label_is_enough(self):
        self.answers['labels'] = (0, b'{"org.opencontainers.image.version": "v5.8.9"}')
        self.assertEqual(self.version(env=('EMQX_VERSION',), command=('emqx', 'ctl')), '5.8.9')
        self.assertEqual((len(self.calls), self.ran), (1, []))

    def test_the_settings_then_the_program(self):
        for labels in ((0, b'null'), (0, b'not json'), (0, b'{"org.opencontainers.image.version": "latest"}')):
            self.answers['labels'] = labels
            self.answers['env'] = (0, b'["PATH=/usr/bin", "OTHER=1.2.3", "EMQX_VERSION=5.8.9"]')
            self.assertEqual(self.version(env=('EMQX_VERSION',)), '5.8.9')
        self.answers['env'] = (0, b'["EMQX_VERSION=latest"]')
        self.assertEqual(self.version(run=(0, b'EMQX v5.8.9 (Erlang 25)'), env=('EMQX_VERSION',),
                                      command=('/opt/emqx/bin/emqx', '--version')), '5.8.9')
        self.assertEqual(self.ran, [('docker.io/emqx/emqx:5.8.9', ['--version'], '/opt/emqx/bin/emqx', True)])

    def test_nothing_tells_it(self):
        self.answers['labels'] = (0, b'null')
        for env, run in (((1, b''), (1, b'5.8.9')), ((0, b'{}'), (0, b'no version here 1.2')),
                         (BackupError('job-failed', 'x'), BackupError('job-failed', 'timeout')),
                         ((0, b'not json'), (0, b''))):
            self.answers['env'] = env
            self.assertIsNone(self.version(run=run, env=('EMQX_VERSION',), command=('emqx', '--version')))
        self.assertTrue(any('讀不到映像' in line for line in self.reporter.logs))
        found = haissues.version_issues('EMQX', '5.9.1', '5.8.9', self.version())
        self.assertEqual([(i.id, i.level) for i in found], [('version.target-unknown', 'notice')])

    def test_what_is_not_a_missing_version_is_not_hidden(self):
        self.answers['labels'] = (125, b'')
        with self.assertRaises(BackupError) as caught:
            self.version()
        self.assertEqual(caught.exception.code, 'incompatible', 'the image is not here')
        self.answers['labels'] = (0, b'null')
        wide = haissues.job_wide(BackupError('insufficient-space', 'x'))
        with self.assertRaises(BackupError) as caught:
            self.version(run=wide, command=('emqx', '--version'))
        self.assertIs(caught.exception, wide)
        with self.assertRaises(flows.Cancelled):
            self.version(run=flows.Cancelled(), command=('emqx', '--version'))


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
        after = self.store.get(record['id'])
        self.assertEqual(after['temp_owners'], ['appowner'])
        self.assertGreater(after['temp_retry_at'], time.time() + jobs.TEMP_RETRY_SECONDS - 60)
        calls = []
        jobs.recover_interrupted(self.paths, unit_active=lambda _u: False,
                                 sweep_temp=lambda _j, _o: calls.append(1) or [])
        self.assertEqual(calls, [], 'review C-08: not again before the retry time')
        after['temp_retry_at'] = time.time() - 1
        self.store.save(after)
        jobs.recover_interrupted(self.paths, unit_active=lambda _u: False, sweep_temp=lambda _j, _o: [])
        after = self.store.get(record['id'])
        self.assertEqual(after['temp_owners'], [])
        self.assertNotIn('temp_retry_at', after)
        self.assertFalse(jobs.has_leftovers(after))

    def test_only_ha_jobs_sweep_at_their_start(self):
        """Review C-08: backups, restores and scheduled runs never wait for podman listings."""
        swept = []
        deps = types.SimpleNamespace(sweep_temp=lambda job_id, log: swept.append(job_id))
        for job_type, params in (('backup', {'apps': ['odoo']}), ('backup', dict(self.params, test_mode=False)),
                                 ('verify', dict(self.params))):
            ctx = types.SimpleNamespace(deps=deps, job_id='j1', log=lambda _t: None,
                                        reporter=types.SimpleNamespace(record={'type': job_type, 'params': params}))
            jobs._sweep_finished_temp(ctx)
        self.assertEqual(swept, ['j1', 'j1'])


if __name__ == '__main__':
    unittest.main()
