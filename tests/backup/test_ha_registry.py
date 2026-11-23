"""The one registry of HA importers (haapps.py): every list of importable apps comes from it, every importer's module
has the functions the jobs call, and the per-app texts are the modules' own (CONTRACT sections 5, 7, 9). Team E2."""
import inspect
import types
import unittest

from woowbackup import cli, haapps, haimport, hastore


class RegistryTests(unittest.TestCase):
    def test_every_list_is_derived_from_the_registry_in_order(self):
        ids = [importer.app_id for importer in haapps.IMPORTERS]
        self.assertEqual(ids[:2], ['odoo', 'n8n'], 'the first importers keep their place')
        self.assertEqual(list(haimport.APPS), ids)
        self.assertEqual(list(cli.HA_APP_IDS), ids)
        self.assertEqual([app_id for app_id, _name in hastore.IMPORTABLE.values()], ids)
        for importer in haapps.IMPORTERS:
            self.assertEqual(haimport.APPS[importer.app_id], importer.slug)
            self.assertEqual(hastore.importable_app(f'1b7b4ce7_{importer.slug}'), (importer.app_id, importer.name))
            self.assertIs(haapps.for_slug(importer.slug), importer)
            self.assertIs(haapps.get(importer.app_id), importer)
        self.assertEqual(len(set(ids)), len(ids))
        self.assertEqual(len({importer.slug for importer in haapps.IMPORTERS}), len(ids))

    def test_every_module_has_what_the_jobs_call(self):
        for importer in haapps.IMPORTERS:
            with self.subTest(app=importer.app_id):
                module = importer.load()
                for name in ('check', 'convert', 'import_texts'):
                    self.assertTrue(callable(getattr(module, name, None)), name)
                params = list(inspect.signature(module.convert).parameters)
                self.assertEqual(params, ['work', 'app', *(arg.replace('odoo_', '') for arg in importer.convert_args),
                                          'out_dir'])
                self.assertTrue(set(importer.convert_args) <= {'odoo_database', 'test_mode'})

    def test_cli_validation_follows_the_registry(self):
        for value in (list(cli.HA_APP_IDS), list(cli.HA_APP_IDS)[:1]):
            self.assertEqual(cli.v_ha_apps(value, 'apps'), value)
        for bad in ([], ['wordpress'], ['odoo', 'odoo'], list(cli.HA_APP_IDS) + ['x'], 'odoo'):
            with self.subTest(bad=bad), self.assertRaises(Exception) as caught:
                cli.v_ha_apps(bad, 'apps')
            self.assertIn(f'1 到 {len(cli.HA_APP_IDS)} 個', caught.exception.message)


class TextTests(unittest.TestCase):
    def test_odoo_and_n8n_texts_are_unchanged(self):
        notes, reminders, by_app = haimport.import_texts({
            'n8n': {'owner_email': 'a@b.invalid', 'packages': [{'name': 'x'}]},
            'odoo': {'custom_modules': [{'name': 'woow_probe'}], 'website_domains': ['https://shop.example']}})
        self.assertEqual(reminders, [])
        self.assertEqual(notes[0], 'Odoo 的使用者帳號和密碼會換成 HA 那邊的，這台原本的 Odoo 管理者密碼不再適用。')
        self.assertTrue(notes[-1].startswith('HA 的 n8n 社群節點'), notes)
        self.assertEqual(by_app['odoo'], ['匯入後請用 HA 那邊的 Odoo 帳號和密碼登入。'])
        self.assertEqual(by_app['n8n'], ['匯入後請用 HA 的 n8n 管理者帳號（a@b.invalid）登入。',
                                         '請確認 HA 的 n8n 社群節點能正常使用（必要時重新安裝）。'])
        self.assertFalse(any('MCP' in line for lines in by_app.values() for line in lines), 'the page writes those')

    def test_mcp_lines_only_for_the_apps_the_engine_speaks_for(self):
        importer = haapps.Importer('x', 'woow-x', 'X 應用', 'ha_x', mcp_admin='x-mcp-admin', mcp_addon='Woow X MCP Server',
                                   engine_mcp_lines=True)
        catalog = {'x-mcp-admin': types.SimpleNamespace(name='X MCP 管理（這台）')}
        lines = haimport.mcp_lines(importer, catalog)
        self.assertIn('「X MCP 管理（這台）」', lines[0])
        self.assertIn('「Woow X MCP Server」', lines[1])
        self.assertIn('claude.ai', lines[1])
        self.assertEqual(len(haimport.mcp_lines(importer, {})), 1, 'no admin app here: only the HA add-on line')
        broken = types.SimpleNamespace(get=lambda _id: (_ for _ in ()).throw(OSError('unreadable')))
        self.assertEqual(len(haimport.mcp_lines(importer, broken)), 1)
        self.assertEqual(haimport.mcp_lines(haapps.get('odoo'), catalog), [])


if __name__ == '__main__':
    unittest.main()
