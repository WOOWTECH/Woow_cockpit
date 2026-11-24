"""The store of uploaded Home Assistant backups (hastore.py) and the upload path into it (storage.py), team E1.

An HA file uploaded like any backup lands in ha-backups/ (never archives/ or the index), with a strict sidecar, the
same publish safety as a Cockpit upload (sidecar first, rename, (dev, ino) re-check, back to uploads/ on failure),
idempotent retries and re-uploads; retention and orphan adoption never see it.
"""
import hashlib
import json
import os
import stat
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import habackup, hastore, util
from woowbackup.errors import BackupError
from woowbackup.paths import Paths
from woowbackup.storage import Storage

from . import hafixtures as hx
from .test_archive import fake_archive_bytes

GIB = 1024 ** 3


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='woowbk-ha-store-')
        self.addCleanup(self.tmp.cleanup)
        self.paths = Paths(base=Path(self.tmp.name))
        self.storage = Storage(self.paths, free_space=lambda path: 100 * GIB)
        self.storage.ensure_layout()
        self.store = self.storage.ha_store
        self.root = Path(self.paths.data) / 'ha-backups'

    def begin(self, data, filename='WOOW匯入測試 加密.tar'):
        begun = self.storage.begin_upload(filename, len(data))
        temp = Path(begun['path']).parent / f'.{Path(begun["path"]).name}-x1y2z3'  # what cockpit's fsreplace1 does
        temp.write_bytes(data)
        os.rename(temp, begun['path'])
        return begun

    def upload(self, data, filename='WOOW匯入測試 加密.tar'):
        begun = self.begin(data, filename)
        return self.storage.finish_upload(begun['upload_id']), begun


class UploadTests(StoreCase):
    def test_an_ha_upload_goes_to_its_own_store(self):
        data = hx.fixture('v3_gzip.tar').read_bytes()
        rec, begun = self.upload(data)
        sha = hashlib.sha256(data).hexdigest()
        self.assertTrue(hastore.is_record(rec))
        self.assertEqual(set(rec), set(hastore.SIDECAR_KEYS))
        self.assertEqual({key: rec[key] for key in ('id', 'ha_slug', 'name', 'date', 'type', 'supervisor_version',
                                                    'protected', 'compressed', 'folders', 'size', 'sha256', 'filename')},
                         {'id': 'ha-' + sha[:20], 'ha_slug': 'f1x73a00', 'name': 'fixture v3_gzip',
                          'date': '2026-11-18T09:01:20Z', 'type': 'partial', 'supervisor_version': '2026.11.0',
                          'protected': True, 'compressed': True, 'folders': ['share'], 'size': len(data), 'sha256': sha,
                          'filename': 'WOOW匯入測試 加密.tar'})
        self.assertEqual(rec['addons'], [
            {'slug': hx.ODOO, 'name': 'Woow Odoo 18', 'version': '0.4.12', 'encrypted': True},
            {'slug': hx.N8N, 'name': 'Woow n8n', 'version': '2.43.6', 'encrypted': True}])
        self.assertTrue(util.is_iso_utc(rec['uploaded_at']))
        stored = self.root / f'{rec["id"]}.tar'
        self.assertEqual(stored.read_bytes(), data)
        self.assertEqual((mode(self.root), mode(stored), mode(self.root / f'{rec["id"]}.json')), (0o700, 0o600, 0o600))
        self.assertEqual(os.listdir(self.paths.archives), [])
        self.assertEqual(self.storage.list_backups(), [])
        self.assertEqual(os.listdir(self.paths.uploads), [f'{begun["upload_id"]}.done'])
        done = json.loads((self.paths.uploads / f'{begun["upload_id"]}.done').read_text())
        self.assertEqual(done['ha_backup_id'], rec['id'])
        self.assertEqual(self.storage.finish_upload(begun['upload_id']), rec, 'a retry returns the same record')
        again, begun_again = self.upload(data, 'copy.tar')
        self.assertEqual(again, rec, 'the same file again is the same record')
        self.assertEqual(sorted(os.listdir(self.paths.uploads)),
                         sorted([f'{begun["upload_id"]}.done', f'{begun_again["upload_id"]}.done']))
        self.assertEqual(self.store.list(), [rec])
        self.assertEqual(self.store.get(rec['id']), rec)
        # Retention and orphan adoption only know archives/.
        self.assertEqual(self.storage.adopt_orphans(now=time.time() + 7200), [])
        self.assertEqual(self.storage.list_backups(), [])

    def test_unencrypted_and_downloaded_backups(self):
        plain, _begun = self.upload(hx.fixture('plain_gzip.tar').read_bytes())
        self.assertEqual((plain['protected'], [a['encrypted'] for a in plain['addons']]), (False, [False, False]))
        downloaded, _begun = self.upload(hx.fixture('downloaded_gzip.tar').read_bytes())
        self.assertEqual((downloaded['protected'], [a['encrypted'] for a in downloaded['addons']]), (False, [False, False]))
        uncompressed, _begun = self.upload(hx.fixture('v1_plain.tar').read_bytes(), 'v1.tar')
        self.assertEqual((uncompressed['compressed'], uncompressed['addons'][0]['encrypted']), (False, True))
        self.assertEqual(len(self.store.list()), 3)

    def test_cockpit_uploads_are_unchanged(self):
        data = fake_archive_bytes(backup_id='20261101T080000Z-0123abcd')
        meta, _begun = self.upload(data, 'woowtech-backup-dev-a-20261101-0800.woowbackup')
        self.assertFalse(hastore.is_record(meta))
        self.assertEqual((meta['id'], meta['type']), ('20261101T080000Z-0123abcd', 'uploaded'))
        self.assertFalse(self.root.exists())

    def test_a_broken_ha_upload_is_refused_and_kept_for_abort(self):
        for broken in (hx.simple_backup(type='weekly'), hx.simple_backup(version=3),
                       hx.two_addons(extra=[('backup.json', json.dumps(hx.ha_doc()).encode())])):
            begun = self.begin(broken)
            with self.assertRaises(BackupError) as caught:
                self.storage.finish_upload(begun['upload_id'])
            self.assertEqual(caught.exception.code, 'corrupt-archive')
            self.assertEqual(sorted(os.listdir(self.paths.uploads)),
                             sorted([f'{begun["upload_id"]}.part', f'{begun["upload_id"]}.json']))
            self.assertTrue(self.storage.abort_upload(begun['upload_id']))
            self.assertEqual(self.store.list(), [])

    def test_one_bad_addon_no_longer_refuses_the_file(self):
        """UP-19, UP-34, UP-44 to UP-47, UP-50: it is listed with its problem, the others as ever."""
        head = b'SecureTar\x03' + bytes(6) + (100).to_bytes(8, 'big') + bytes(8)
        cases = {'not-an-archive': b'\x01' * 4096, 'size-mismatch': head + bytes(10),
                 'encryption-unsupported': b'SecureTar\x08' + bytes(600)}
        for problem, member in cases.items():
            with self.subTest(problem=problem):
                rec, _begun = self.upload(hx.two_addons(odoo=member, doc=hx.ha_doc([hx.ODOO, hx.N8N], slug=problem)))
                self.assertEqual([(a['slug'], a['encrypted'], a.get('problem')) for a in rec['addons']],
                                 [(hx.ODOO, False, problem), (hx.N8N, False, None)])
                self.assertEqual(self.store.get(rec['id']), rec)
                view = hastore.view(rec)
                self.assertEqual([(a['slug'], a.get('problem')) for a in view['importable_apps']],
                                 [(hx.ODOO, problem), (hx.N8N, None)])
                self.assertEqual(view['importable_apps'][0]['problem_text'], habackup.problem_text(problem))
                self.assertNotIn('problem_text', view['importable_apps'][1])
        doc = hx.ha_doc([hx.ODOO, hx.N8N, 'a0d7b954_vscode'])
        doc['addons'].append({'slug': '../x_odoo18ce', 'name': 'Evil', 'version': '9'})
        data = hx.outer_bytes([(f'{hx.ODOO}.tar.gz', b'1'), (f'{hx.ODOO}.tar.gz', b'2'),
                               ('a0d7b954_vscode.tar.gz', b'broken')], doc)
        rec, _begun = self.upload(data)
        self.assertEqual({a['slug']: a.get('problem') for a in rec['addons']},
                         {hx.ODOO: 'duplicate', hx.N8N: 'missing', 'a0d7b954_vscode': 'not-an-archive',
                          'invalid-1': 'bad-slug'})
        view = hastore.view(rec)
        self.assertEqual([a['slug'] for a in view['importable_apps']], [hx.ODOO, hx.N8N])
        self.assertEqual([(a['slug'], a['name'], a['problem']) for a in view['other_addons']],
                         [('a0d7b954_vscode', 'name of a0d7b954_vscode', 'not-an-archive'),
                          ('invalid-1', 'Evil', 'bad-slug')])
        self.assertTrue(all(a['problem_text'] for a in view['importable_apps'] + view['other_addons']))

    def test_texts_and_dates_that_cannot_be_shown(self):
        """UP-26 to UP-30, UP-36, UP-38, UP-42, X-UP-01: cleaned, and a date nobody can read sorts by the upload."""
        odd = {'empty': '', 'long': 'x' * 5000, 'control': 'a\nb\x00', 'bidi': 'a\u202eb', 'surrogate': '\ud800',
               'number': 7, 'list': ['x'], 'null': None}
        for label, value in odd.items():
            doc = hx.ha_doc(slug=value, name=value, date=value, supervisor_version=value, homeassistant=value)
            doc['addons'][0].update(name=value, version=value, size=value)
            with self.subTest(value=label):
                rec, _begun = self.upload(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member())], doc), 'a\nb\u202e')
                self.assertIsNone(rec['date'])
                self.assertEqual(self.store.get(rec['id']), rec)
                texts = [rec['ha_slug'], rec['name'], rec['supervisor_version'], rec['filename'],
                         rec['addons'][0]['name'], rec['addons'][0]['version']]
                self.assertTrue(all(isinstance(t, str) and (t.isprintable() or t == '') for t in texts), texts)
                self.assertTrue(rec['addons'][0]['name'])
                self.assertEqual(rec['filename'], 'a b')
        blank, _begun = self.upload(hx.simple_backup(date='?', slug='blank'), '\n')
        self.assertRegex(blank['filename'], r'^ha-backup-[0-9]{8}-[0-9]{6}\.tar$')
        self.assertEqual(blank['filename'][10:18], blank['uploaded_at'][:10].replace('-', ''))
        dated, _begun = self.upload(hx.simple_backup(date='2020-01-01T00:00:00+00:00', slug='dated'))
        future, _begun = self.upload(hx.simple_backup(date='2099-01-01T00:00:00+00:00', slug='future'))
        order = [r['id'] for r in self.store.list()]
        self.assertEqual((order[0], order[-1]), (future['id'], dated['id']))
        self.assertIn(blank['id'], order[1:-1])

    def test_the_largest_record_is_still_listed(self):
        """UP-32, UP-39: a record of as many add-ons and folders as a backup may list fits its sidecar's limit."""
        slugs = [f'{i:08x}_' + 's' * 91 for i in range(habackup.MAX_ADDONS)]
        doc = hx.ha_doc(slugs, folders=[f'{i:040}' for i in range(habackup.MAX_FOLDERS)], name='\U0001f600' * 200)
        for addon in doc['addons']:
            addon.update(name='\U0001f600' * 200, version='\U0001f600' * 64)
        rec, _begun = self.upload(hx.outer_bytes([], doc))
        self.assertEqual((len(rec['addons']), len(rec['folders'])), (1000, 256))
        self.assertEqual(self.store.list(), [rec])
        self.assertLess((self.root / f'{rec["id"]}.json').stat().st_size, hastore.MAX_SIDECAR // 2)
        self.assertEqual(len(hastore.view(rec)['other_addons']), 1000)

    def test_a_failure_while_publishing_puts_the_file_back(self):
        # The store directory is fsynced twice: after the sidecar is written and after the rename. A failure at either
        # leaves nothing in the store and the upload where a retry finds it (review SEC-4, like a Cockpit upload).
        for failing_call in (1, 2):
            data = hx.simple_backup(slug=f'fa11{failing_call:04d}')
            begun = self.begin(data)
            calls = []
            real = util.fsync_dir

            def failing(path):
                if Path(path) == self.root:
                    calls.append(path)
                    if len(calls) == failing_call:
                        raise KeyboardInterrupt
                return real(path)
            with self.subTest(failing_call=failing_call), mock.patch.object(util, 'fsync_dir', failing):
                with self.assertRaises(KeyboardInterrupt):
                    self.storage.finish_upload(begun['upload_id'])
            prefix = 'ha-' + hashlib.sha256(data).hexdigest()[:20]
            self.assertEqual([name for name in os.listdir(self.root) if prefix in name], [])
            self.assertEqual(Path(begun['path']).read_bytes(), data)
            rec = self.storage.finish_upload(begun['upload_id'])
            self.assertIn(rec, self.store.list())

    def test_a_file_swapped_during_the_check_is_refused(self):
        data = hx.simple_backup()
        begun = self.begin(data)
        real = hastore.HaStore.publish

        def swap(store, fd, st, part, *args, **kwargs):
            os.unlink(part)
            Path(part).write_bytes(data)  # same bytes, another inode
            return real(store, fd, st, part, *args, **kwargs)
        with mock.patch.object(hastore.HaStore, 'publish', swap):
            with self.assertRaises(BackupError) as caught:
                self.storage.finish_upload(begun['upload_id'])
        self.assertEqual(caught.exception.code, 'invalid-request')
        self.assertEqual(self.store.list(), [])
        self.assertEqual(sorted(p for p in os.listdir(self.root)), [])


class StoreTests(StoreCase):
    def test_list_order_validation_and_ids(self):
        older, _begun = self.upload(hx.simple_backup(date='2026-11-01T00:00:00+00:00', slug='aaaa0001'))
        newer, _begun = self.upload(hx.simple_backup(date='2026-11-17T00:00:00+00:00', slug='aaaa0002'))
        self.assertEqual([r['id'] for r in self.store.list()], [newer['id'], older['id']])
        side = self.root / f'{older["id"]}.json'
        record = json.loads(side.read_text())
        record['extra'] = 1
        side.write_text(json.dumps(record))
        self.assertEqual([r['id'] for r in self.store.list()], [newer['id']])
        self.assertEqual(self._code(self.store.get, older['id']), 'not-found')
        os.truncate(self.root / f'{newer["id"]}.tar', 10)
        self.assertEqual(self.store.list(), [], 'a file that changed size is not listed')
        for bad in ('ha-xyz', '20261101T080000Z-0123abcd', '../ha-0123', None):
            with self.subTest(bad=bad):
                self.assertEqual(self._code(self.store.get, bad), 'invalid-request')
                self.assertEqual(self._code(self.store.delete, bad), 'invalid-request')

    def _code(self, call, *args):
        try:
            call(*args)
        except BackupError as error:
            return error.code
        raise AssertionError('no error')

    def test_sidecars_with_and_without_a_problem(self):
        """Records written before `problem` existed are read as ever; a wrong one makes the sidecar unreadable."""
        rec, _begun = self.upload(hx.two_addons())
        side = self.root / f'{rec["id"]}.json'
        record = json.loads(side.read_text())
        self.assertEqual(set(record['addons'][0]), set(hastore.ADDON_KEYS))
        old_engine = dict(record, ha_slug='c0ffee00', supervisor_version='2026.11.0', date='2026-11-18T09:01:20Z')
        side.write_text(json.dumps(old_engine))
        self.assertEqual(self.store.get(rec['id']), old_engine)
        for problem, good in (('missing', True), ('a-code-of-a-newer-engine', True), ('', False), ('No!', False),
                              ('x' * 41, False), (None, False), (5, False)):
            record['addons'][0]['problem'] = problem
            side.write_text(json.dumps(record))
            with self.subTest(problem=problem):
                self.assertEqual(self.store.exists(rec['id']), good)
                if good:
                    self.assertTrue(hastore.view(record)['importable_apps'][0]['problem_text'])
        del record['addons'][0]['problem']
        for field, value, good in (('date', None, True), ('date', 'yesterday', False), ('date', '', False),
                                   ('ha_slug', '', True), ('ha_slug', 'x' * 65, False), ('ha_slug', 'a\nb', False),
                                   ('ha_slug', None, False), ('supervisor_version', '', True),
                                   ('supervisor_version', 'x' * 65, False), ('name', 'x' * 201, False),
                                   ('folders', ['a', 'a'], False), ('folders', [['a']], False),
                                   ('folders', [f'f{i}' for i in range(257)], False)):
            side.write_text(json.dumps(dict(record, **{field: value})))
            with self.subTest(field=field, value=value):
                self.assertEqual(self.store.exists(rec['id']), good)
        record['addons'][0]['extra'] = 1
        side.write_text(json.dumps(record))
        self.assertFalse(self.store.exists(rec['id']), 'an unknown key')
        record['addons'] = [{'slug': f's{i}', 'name': 'x', 'version': '1', 'encrypted': False} for i in range(1001)]
        side.write_text(json.dumps(record))
        self.assertFalse(self.store.exists(rec['id']), 'more add-ons than a backup may list')

    def test_publish_conflicts(self):
        data = hx.simple_backup()
        rec, _begun = self.upload(data)
        side = self.root / f'{rec["id"]}.json'
        # An unreadable sidecar (e.g. a newer engine's) is kept as it is.
        unreadable = dict(rec, newer_field=True)
        side.write_text(json.dumps(unreadable))
        before = side.read_bytes()
        begun = self.begin(data)
        with self.assertRaises(BackupError) as caught:
            self.storage.finish_upload(begun['upload_id'])
        self.assertEqual(caught.exception.code, 'invalid-request')
        self.assertIn('記錄無法讀取', caught.exception.message)
        self.assertEqual(side.read_bytes(), before)
        self.storage.abort_upload(begun['upload_id'])
        # The same id with different content is refused.
        other = rec['sha256'][:20] + ('0' if rec['sha256'][20] != '0' else '1') + rec['sha256'][21:]
        side.write_text(json.dumps(dict(rec, sha256=other)))
        begun = self.begin(data)
        with self.assertRaises(BackupError) as caught:
            self.storage.finish_upload(begun['upload_id'])
        self.assertIn('內容不同', caught.exception.message)
        self.storage.abort_upload(begun['upload_id'])
        # A file without its sidecar (a deletion cut in half) is replaced by the new upload.
        side.unlink()
        again, _begun = self.upload(data)
        self.assertEqual(self.store.list(), [again])
        # A sidecar without its file (a kill between the two publish steps) is completed by the next upload.
        (self.root / f'{rec["id"]}.tar').unlink()
        self.assertEqual(self.store.list(), [])
        again, _begun = self.upload(data)
        self.assertEqual(self.store.list(), [again])

    def test_delete(self):
        rec, _begun = self.upload(hx.simple_backup())
        self.store.delete(rec['id'])
        self.assertEqual(os.listdir(self.root), [])
        self.assertEqual(self._code(self.store.delete, rec['id']), 'not-found')
        self.assertEqual(self._code(self.store.get, rec['id']), 'not-found')
        rec, _begun = self.upload(hx.simple_backup())
        (self.root / f'{rec["id"]}.tar').unlink()
        self.store.delete(rec['id'])  # a sidecar without its file can still be deleted
        self.assertEqual(os.listdir(self.root), [])

    def test_stale_sidecars_and_temp_files_are_cleaned(self):
        rec, _begun = self.upload(hx.simple_backup(slug='aaaa0003'))
        (self.root / f'{rec["id"]}.tar').unlink()
        stale_temp = self.root / f'.{rec["id"]}.json.abcd.tmp'
        stale_temp.write_text('x')
        fresh, _begun = self.upload(hx.simple_backup(slug='aaaa0004'))
        fresh_orphan = self.root / f'{fresh["id"]}.json'
        (self.root / f'{fresh["id"]}.tar').unlink()
        old = time.time() - 7200
        os.utime(self.root / f'{rec["id"]}.json', (old, old))
        os.utime(stale_temp, (old, old))
        self.upload(hx.simple_backup(slug='aaaa0005'))
        names = os.listdir(self.root)
        self.assertNotIn(f'{rec["id"]}.json', names, 'stale record without file removed')
        self.assertNotIn(stale_temp.name, names)
        self.assertIn(fresh_orphan.name, names, 'a recent one may belong to a publish in progress')

    def test_a_replaced_store_directory_is_refused(self):
        self.store.ensure()
        os.rmdir(self.root)
        elsewhere = Path(self.tmp.name) / 'elsewhere'
        elsewhere.mkdir()
        os.symlink(elsewhere, self.root)
        self.assertEqual(self._code(self.store.list), 'internal-error')
        self.assertEqual(self._code(self.store.ensure), 'internal-error')
        begun = self.begin(hx.simple_backup())
        self.assertEqual(self._code(self.storage.finish_upload, begun['upload_id']), 'internal-error')
        self.assertEqual(os.listdir(elsewhere), [])

    def test_view_and_names(self):
        rec, _begun = self.upload(hx.fixture('plain_gzip.tar').read_bytes())
        rec = dict(rec, addons=rec['addons'] + [{'slug': 'core_mosquitto', 'name': 'Mosquitto', 'version': '6.4.1',
                                                 'encrypted': False}])
        catalog = {'odoo': types.SimpleNamespace(id='odoo', name='Odoo 18（這台）')}
        view = hastore.view(rec, catalog)
        self.assertEqual(view['importable_apps'], [
            {'slug': hx.ODOO, 'app_id': 'odoo', 'app_name': 'Odoo 18（這台）', 'installed': True},
            {'slug': hx.N8N, 'app_id': 'n8n', 'app_name': 'n8n 工作流程', 'installed': False}])
        self.assertEqual(view['other_addons'], [{'slug': 'core_mosquitto', 'name': 'Mosquitto', 'version': '6.4.1'}])
        self.assertEqual([a['installed'] for a in hastore.view(rec, None)['importable_apps']], [False, False])
        self.assertEqual(hastore.addon_suffix('local_woow-n8n'), 'woow-n8n')
        self.assertEqual(hastore.importable_app('odoo18ce'), ('odoo', 'Odoo 18'))
        self.assertIsNone(hastore.importable_app('1b7b4ce7_odoo17'))
        # UP-56: what has no app here is listed as not moving and never stops what has one.
        others = ['a0d7b954_cloudflared', 'core_mosquitto', 'local_odoo-mcp', 'core_configurator']
        rec, _begun = self.upload(hx.outer_bytes(
            [(f'{slug}.tar.gz', hx.addon_member()) for slug in [*others[:2], hx.ODOO, *others[2:]]],
            hx.ha_doc([*others[:2], hx.ODOO, *others[2:]])))
        view = hastore.view(rec, catalog)
        self.assertEqual([a['slug'] for a in view['other_addons']], others)
        self.assertEqual([a['app_id'] for a in view['importable_apps']], ['odoo'])
        for given, kept in (('WOOW匯入測試_加密_2026-11-18.tar', True), ('../evil.tar', False), ('a\\b.tar', False),
                            ('a\tb.tar', False), ('x' * 201, False), ('', False), (None, False)):
            with self.subTest(name=given):
                name = hastore.safe_filename(given, '2026-11-18T09:01:20Z')
                self.assertEqual(name == given, kept)
                if not kept:
                    self.assertEqual(name, 'ha-backup-20261118-090120.tar')


if __name__ == '__main__':
    unittest.main()
