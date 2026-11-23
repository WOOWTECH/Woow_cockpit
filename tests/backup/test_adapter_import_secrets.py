"""adapter.import_manifest `secrets` (HA import, LiteLLM: the salt key that belongs to the converted database): the
named secret comes from the conversion's file, every other secret is read live as in every backup; only a declared
secret, one regular file of a size podman takes. The restore re-creates every secret from the archive and the
pre-restore safety backup holds the live ones (tests.backup.test_adapter restore tests). Team E2."""
import os

from woowbackup.errors import BackupError

from .test_adapter import AdapterCase, APP_KEY, DB_PASSWORD


class ImportSecretsTests(AdapterCase):
    def items(self, name='dump'):
        dump = self.root / name
        dump.write_bytes(b'PGDMP-converted')
        files = self.root / 'files.tar'
        files.write_bytes(b'')
        return {'postgres': {'main': {'database': 'notes', 'server_version': '16.15', 'major': 16, 'file': dump}},
                'volumes': {'woowbk-demo-files': files}}

    def secret_sources(self, manifest, entries):
        by_path = {entry.path: entry.source for entry in entries}
        return {item['name']: by_path[item['entry']] for item in manifest['secrets']}

    def test_a_converted_secret_replaces_only_that_secret(self):
        moved = self.root / 'ha-salt'
        moved.write_bytes(b'sk-moved-salt-value')
        os.chmod(moved, 0o600)
        manifest, entries = self.adapter.import_manifest(self.staging, **self.items(),
                                                         secrets={'woowbk-demo-app-key': moved})
        sources = self.secret_sources(manifest, entries)
        self.assertEqual(sources['woowbk-demo-app-key'].read_bytes(), b'sk-moved-salt-value')
        self.assertEqual(sources['woowbk-demo-db-password'].read_bytes(), DB_PASSWORD)
        self.assertNotEqual(sources['woowbk-demo-app-key'].read_bytes(), APP_KEY)
        reads = [call['argv'] for call in self.owner.calls if call['argv'][:3] == ['podman', 'secret', 'inspect']
                 or call['argv'][1:4] == ['secret', 'inspect', '--showsecret']]
        self.assertFalse(any('woowbk-demo-app-key' in argv for argv in reads), 'the replaced secret is not read live')
        self.assertIn('應用機密 woowbk-demo-app-key 使用 HA 備份帶來的值（內容不記錄）', self.everything_logged())
        self.assertNotIn('sk-moved-salt-value', self.everything_logged())

    def test_without_secrets_every_secret_is_live(self):
        manifest, entries = self.adapter.import_manifest(self.staging, **self.items())
        sources = self.secret_sources(manifest, entries)
        self.assertEqual(sources['woowbk-demo-app-key'].read_bytes(), APP_KEY)
        reads = [call['argv'] for call in self.owner.calls if call['argv'][:3] == ['podman', 'secret', 'inspect']
                 or call['argv'][1:4] == ['secret', 'inspect', '--showsecret']]
        self.assertTrue(any('woowbk-demo-app-key' in argv for argv in reads), reads)

    def test_only_a_declared_secret_as_one_small_regular_file(self):
        moved = self.root / 'ha-salt'
        moved.write_bytes(b'x')
        with self.assertRaises(BackupError) as caught:
            self.adapter.import_manifest(self.staging, **self.items(), secrets={'litellm-salt-key': moved})
        self.assertEqual(caught.exception.code, 'internal-error')
        link = self.root / 'link'
        link.symlink_to(moved)
        empty = self.root / 'empty'
        empty.write_bytes(b'')
        big = self.root / 'big'
        big.write_bytes(b'x' * 512000)
        for path in (link, empty, big, self.root / 'missing'):
            staging = self.root / f'staging-{path.name}'
            staging.mkdir(mode=0o700)
            with self.subTest(path=path.name):
                with self.assertRaises(BackupError) as caught:
                    self.adapter.import_manifest(staging, **self.items(path.name + '.dump'),
                                                 secrets={'woowbk-demo-app-key': path})
                self.assertEqual(caught.exception.code, 'internal-error')
