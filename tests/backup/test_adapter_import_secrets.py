"""adapter.import_manifest for the HA import of LiteLLM. `secrets` (the salt key that belongs to the converted
database): the named secret comes from the conversion's file, every other secret is read live as in every backup; only a
declared secret, one regular file of a size podman takes. The restore re-creates every secret from the archive and the
pre-restore safety backup holds the live ones (tests.backup.test_adapter restore tests). And the table digest
(`postgres-digest`) the suggested LiteLLM entry has: nothing to compare at the import, exact at both rollbacks. Team
E2."""
import os

from woowbackup import flows
from woowbackup.errors import BackupError

from .test_adapter import AdapterCase, APP_KEY, DB_PASSWORD, extract_entries
from .test_strengthen import DB_SPEC, StrengthCase


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


class ImportDigestTests(StrengthCase):
    """An import into an app whose entry has a table digest, as the suggested LiteLLM entry has (suggest: `db-main`,
    `{"postgres": "main"}`): the converted backup carries no digest (this device cannot read HA's database the same way),
    so the import compares nothing -- a warning before it and 未比對 after it, never a failure --, while the safety
    backup it makes first records this device's own one, which the automatic and the manual rollback compare before the
    app starts."""

    def make_app(self, mutate=None):
        return super().make_app(lambda entry: entry.update(verify=[dict(DB_SPEC)]))

    def converted(self):
        dump, files = self.root / 'converted.dump', self.root / 'converted.tar'
        dump.write_bytes(b'PGDMP-rows-of-HA')
        files.write_bytes(self.owner.volumes['woowbk-demo-files'])
        staging = self.root / 'convert'
        staging.mkdir(mode=0o700)
        return self.adapter.import_manifest(staging, volumes={'woowbk-demo-files': files}, postgres={
            'main': {'database': 'notes', 'server_version': '16.15', 'major': 16, 'file': dump}})

    def extracted(self, entries, name):
        folder = self.root / name / 'extract'
        folder.mkdir(parents=True, mode=0o700)
        extract_entries(entries, folder)
        return folder

    def restore(self, manifest, folder, **kwargs):
        adapter = self.make_adapter()
        adapter.restore(manifest, folder, mode='inplace', **kwargs)
        return adapter

    def safety(self):
        manifest, entries = self.adapter.backup(self.staging / 'safety', include_images=False, keep_stopped=True)
        self.assertEqual([item['id'] for item in manifest['verify_digests']], ['db'])
        return manifest, self.extracted(entries, 'safety')

    def test_the_import_compares_nothing_and_both_rollbacks_compare_this_devices_data(self):
        own = self.owner.db['data']
        manifest, entries = self.converted()
        self.assertNotIn('verify_digests', manifest)
        self.assertFalse([e.path for e in entries if '/verify/' in e.path])
        checks = []
        self.adapter._preflight_digests(manifest, lambda *item: checks.append(item))
        self.assertEqual(checks, [('digests-missing', 'warn', '備份沒有資料摘要 db（或核對設定已變更），這些項目不會比對。')])
        safety, safety_folder = self.safety()

        imported = self.restore(manifest, self.extracted(entries, 'import'))
        self.assertEqual(self.owner.db['data'], b'PGDMP-rows-of-HA')
        self.assertEqual([(r['id'], r['match'], r['note']) for r in imported.digest_results],
                         [('db', None, '備份沒有這個項目的資料摘要（例如較舊的備份），未比對。')])
        entry = flows.verification_entry(self.app, imported, manifest)
        self.assertEqual((entry['match'], entry['checks'][0]['id']), (None, 'db'))

        for rollback in (True, False):  # the automatic rollback, then a manual restore of the safety backup
            with self.subTest(rollback=rollback):
                back = self.restore(safety, safety_folder, rollback=rollback)
                self.assertEqual(self.owner.db['data'], own)
                self.assertEqual([(r['id'], r['match']) for r in back.digest_results], [('db', True)])
                self.assertIs(flows.verification_entry(self.app, back, safety)['match'], True)

    def test_a_rollback_that_lost_rows_is_reported(self):
        safety, folder = self.safety()
        manifest, entries = self.converted()
        self.restore(manifest, self.extracted(entries, 'import'))
        self.owner.lose_rows = True
        with self.assertRaises(BackupError) as caught:
            self.restore(safety, folder, rollback=True)
        self.assertIn('還原後的資料與備份時不一致', caught.exception.message)
