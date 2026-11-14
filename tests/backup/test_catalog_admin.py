"""catalog-install / catalog-remove: validation, diff, conflicts, locking, history. Owner: catalog + retention engineer.

The trusted directories are created by the test user, who plays root (`trusted_uid`): the same ownership and mode
checks run as in production, against the real loader (`catalog.load_catalog`).
"""
import hashlib
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import catalog, catalog_admin, jobs
from woowbackup.errors import BackupError
from woowbackup.paths import Paths

USERS = {'appowner': 1001, 'otherowner': 1500}


def lookup(name):
    if name in USERS:
        return types.SimpleNamespace(pw_name=name, pw_uid=USERS[name], pw_gid=USERS[name], pw_dir=f'/home/{name}')
    raise KeyError(name)


def entry(app_id='notes', owner='appowner', **changes):
    data = {
        'schema': 1, 'id': app_id, 'name': '筆記', 'description': '', 'owner': owner, 'adapter': 'quadlet-postgres',
        'quadlet': {'files': [f'{app_id}.network', f'{app_id}-db.container', f'{app_id}-app.container']},
        'units': [f'{app_id}-db.service', f'{app_id}-app.service'],
        'writer_units': [f'{app_id}-app.service'],
        'postgres': [{'id': 'main', 'container': f'{app_id}-db', 'unit': f'{app_id}-db.service', 'database': 'notes',
                      'user': 'notes', 'data_volume': f'{app_id}-pgdata'}],
        'volumes': [{'name': f'{app_id}-files', 'label': '上傳檔案'}],
        'secrets': [{'name': f'{app_id}-db-password'}],
        'config_files': [{'path': f'.config/{app_id}/app.env', 'mode': '0600'}],
        'health': [{'type': 'http', 'url': 'http://127.0.0.1:18090/healthz', 'expect_status': 200,
                    'timeout_seconds': 90}],
        'verify': [],
    }
    data.update(changes)
    return data


class AdminCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.paths = Paths(base=Path(self.tmp.name))
        os.makedirs(self.paths.catalog, mode=0o755)
        os.chmod(self.paths.config, 0o755)
        os.chmod(self.paths.catalog, 0o755)
        self.uid = os.getuid()
        self.audit = []

    def tearDown(self):
        self.tmp.cleanup()

    def kwargs(self, **extra):
        return {'user_lookup': lookup, 'trusted_uid': self.uid, **extra}

    def install(self, data, expected=None, **extra):
        return catalog_admin.install(self.paths, data, expected, audit=self.audit.append, **self.kwargs(**extra))

    def loaded(self):
        return catalog.load_catalog(self.paths, trusted_uid=self.uid, user_lookup=lookup)

    def file(self, app_id):
        return Path(self.paths.catalog) / f'{app_id}.json'

    def history(self):
        folder = Path(self.paths.config) / 'apps-history'
        return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []


class DiffTests(unittest.TestCase):
    def test_structured_diff(self):
        old = entry()
        new = entry(name='筆記 2', volumes=[{'name': 'notes-files', 'label': '檔案'}, {'name': 'notes-cache'}],
                    secrets=[], units=['notes-app.service', 'notes-db.service'])
        del new['description']
        changes = catalog_admin.diff_entries(old, new)
        found = {(c['path'], c['op']) for c in changes}
        self.assertIn(('name', 'change'), found)
        self.assertIn(('description', 'remove'), found)
        self.assertIn(('volumes[name=notes-files].label', 'change'), found)
        self.assertIn(('volumes[name=notes-cache]', 'add'), found)
        self.assertIn(('secrets[name=notes-db-password]', 'remove'), found)
        self.assertIn(('units', 'order'), found)
        self.assertEqual(catalog_admin.diff_entries(old, json.loads(json.dumps(old))), [])
        scalars = catalog_admin.diff_entries({'a': [1, 2]}, {'a': [2, 3]})
        self.assertEqual(scalars, [{'path': 'a[]', 'op': 'add', 'new': 3}, {'path': 'a[]', 'op': 'remove', 'old': 1}])
        mixed = catalog_admin.diff_entries({'a': [1, {'x': 1}]}, {'a': [{'x': 2}]})
        self.assertEqual(mixed[0]['op'], 'change')
        text = catalog_admin.diff_text(old, new, 'notes.json')
        self.assertEqual(text[:2], ['--- notes.json（目前）', '+++ notes.json（新）'])
        self.assertTrue(any(line.startswith('-  "description"') for line in text))

    def test_compatibility_notes(self):
        old = entry()
        cold = entry(postgres=[], writer_units=['notes-db.service', 'notes-app.service'],
                     volumes=[{'name': 'notes-files'}, {'name': 'notes-pgdata'}], secrets=[], owner='otherowner')
        notes = catalog_admin.compat_notes(old, cold, backups=3)
        joined = '\n'.join(notes)
        self.assertIn('新增資料卷 notes-pgdata：之前建立的 3 份備份不含這些項目', joined)
        self.assertIn('不再備份密鑰 notes-db-password', joined)
        self.assertIn('資料庫改為冷備份', joined)
        self.assertIn('擁有者帳號改變', joined)
        self.assertEqual(catalog_admin.compat_notes(None, cold), [])
        reverse = catalog_admin.compat_notes(cold, old)
        self.assertTrue(any('改以匯出方式' in note for note in reverse))
        templated = entry(quadlet={'files': ['notes.network'], 'template_dir': '/x'})
        self.assertTrue(any('移除部署範本' in note for note in catalog_admin.compat_notes(templated, entry())))


class PreviewTests(AdminCase):
    def test_preview_of_a_new_entry_writes_nothing(self):
        result = catalog_admin.preview_install(self.paths, entry(), **self.kwargs())
        self.assertTrue(result['valid'], result['error'])
        self.assertEqual((result['id'], result['file'], result['current'], result['expected_sha256']),
                         ('notes', 'notes.json', None, None))
        data = catalog_admin.pretty(entry()).encode()
        self.assertEqual(result['new_sha256'], hashlib.sha256(data).hexdigest())
        self.assertTrue(result['diff'][2].startswith('@@'))
        self.assertIn('沒有部署範本', ''.join(result['warnings']))
        self.assertEqual(os.listdir(self.paths.catalog), [])

    def test_validation_feedback_names_the_field(self):
        bad = entry(volumes=[{'name': 'bad name'}])
        result = catalog_admin.preview_install(self.paths, bad, **self.kwargs())
        self.assertFalse(result['valid'])
        self.assertEqual(result['error']['code'], 'invalid-request')
        self.assertEqual(result['error']['details']['field'], 'volumes[0].name')
        self.assertEqual(result['id'], 'notes')  # the diff is still shown
        for value in (None, [], 'x', {'id': 'Bad Id'}):
            self.assertFalse(catalog_admin.preview_install(self.paths, value, **self.kwargs())['valid'])
        missing = catalog_admin.preview_install(self.paths, entry(owner='ghost'), **self.kwargs())
        self.assertEqual(missing['error']['code'], 'owner-missing')
        huge = entry(description='x' * 400, health=[])
        huge['units'] = [f'u{i}-{"x" * 190}.service' for i in range(32)]
        huge['writer_units'] = []
        huge['postgres'] = []
        huge['quadlet'] = {'files': [f'f{i}-{"y" * 180}.container' for i in range(32)]}
        huge['secrets'] = [{'name': f's{i}-{"z" * 190}'} for i in range(64)]
        huge['config_files'] = [{'path': f'.config/notes/{"c" * 200}/{i}', 'mode': '0600'} for i in range(64)]
        huge['volumes'] = [{'name': f'v{i}-{"w" * 120}', 'label': 'l' * 80} for i in range(32)]
        size = len(catalog_admin.pretty(huge).encode())
        result = catalog_admin.preview_install(self.paths, huge, **self.kwargs())
        if size > catalog.MAX_ENTRY_BYTES:
            self.assertEqual(result['error']['code'], 'limit-exceeded')

    def test_conflicts_with_other_entries_of_the_same_owner(self):
        self.install(entry('notes'))
        clash = entry('notes2', units=['notes-db.service', 'notes2-app.service'],
                      writer_units=['notes2-app.service'],
                      postgres=[{'id': 'main', 'container': 'notes2-db', 'unit': 'notes-db.service', 'database': 'n',
                                 'user': 'n', 'data_volume': 'notes2-pgdata'}],
                      config_files=[{'path': '.config/notes2/app.env', 'mode': '0600'}])
        result = catalog_admin.preview_install(self.paths, clash, **self.kwargs())
        self.assertFalse(result['valid'])
        self.assertIn('服務 notes-db.service 已屬於應用「notes」', result['error']['message'])
        shared = entry('notes3', secrets=[{'name': 'notes-db-password'}],
                       quadlet={'files': ['notes.network', 'notes3-db.container', 'notes3-app.container']},
                       config_files=[{'path': '.config/notes3/app.env', 'mode': '0600'}])
        result = catalog_admin.preview_install(self.paths, shared, **self.kwargs())
        self.assertTrue(result['valid'], result['error'])
        self.assertEqual(len(result['warnings']), 3)  # shared secret, shared Quadlet file, no template
        dirs = entry('notes4', config_files=[], data_dirs=[{'path': '.config/notes'}])
        result = catalog_admin.preview_install(self.paths, dirs, **self.kwargs())
        self.assertEqual(result['error']['message'], '主機資料夾 ~/.config/notes 與應用「notes」的 ~/.config/notes/app.env 重疊。')
        other_owner = entry('notes', owner='otherowner')
        self.assertTrue(catalog_admin.preview_install(self.paths, entry('notes5', owner='otherowner',
                                                                        config_files=[]), **self.kwargs())['valid'])
        # review M3: an installed id cannot move to another owner (its backups would restore into that account and
        # count toward its retention); the preview says so and install refuses until the entry is removed
        result = catalog_admin.preview_install(self.paths, other_owner, **self.kwargs())
        self.assertFalse(result['valid'])
        self.assertEqual((result['error']['details']['field'], result['error']['details']['reason']),
                         ('owner', 'owner-change'))
        self.assertIn('appowner', result['error']['message'])
        current = hashlib.sha256(self.file('notes').read_bytes()).hexdigest()
        with self.assertRaises(BackupError) as caught:
            self.install(other_owner, current)
        self.assertEqual(caught.exception.details.get('reason'), 'owner-change')
        self.assertIn('"owner": "appowner"', self.file('notes').read_text(), 'nothing was written')
        catalog_admin.remove(self.paths, 'notes', current, trusted_uid=self.uid, audit=self.audit.append)
        self.assertTrue(self.install(other_owner)['installed'], 'removed first: a new entry for the other owner')

    def test_preview_against_the_installed_entry(self):
        self.install(entry())
        current = hashlib.sha256(self.file('notes').read_bytes()).hexdigest()
        changed = entry(volumes=[{'name': 'notes-files'}, {'name': 'notes-media'}])
        result = catalog_admin.preview_install(self.paths, changed, backups=[
            {'id': 'b1', 'apps': [{'id': 'notes', 'name': 'x'}]}, {'id': 'b2', 'apps': []}], **self.kwargs())
        self.assertEqual(result['expected_sha256'], current)
        self.assertEqual(result['current']['entry'], entry())
        self.assertEqual(result['backups'], 1)
        self.assertIn(('volumes[name=notes-media]', 'add'), {(c['path'], c['op']) for c in result['changes']})
        self.assertTrue(any('之前建立的 1 份備份' in note for note in result['compat']))
        same = catalog_admin.preview_install(self.paths, entry(), **self.kwargs())
        self.assertIn('完全相同', ''.join(same['warnings']))
        self.assertEqual(same['history'], [])
        self.install(entry(name='b'), current)
        self.assertEqual(len(catalog_admin.preview_install(self.paths, entry(), **self.kwargs())['history']), 1)


class InstallTests(AdminCase):
    def test_install_writes_a_trusted_file_the_loader_accepts(self):
        result = self.install(entry())
        path = self.file('notes')
        st = os.stat(path)
        self.assertEqual((st.st_uid, st.st_mode & 0o7777), (self.uid, 0o644))
        self.assertEqual(path.read_bytes(), catalog_admin.pretty(entry()).encode())
        loaded = self.loaded()
        self.assertEqual(loaded['notes'].sha256, result['sha256'])
        self.assertEqual(loaded.problems, [])
        self.assertIsNone(result['previous'])
        self.assertEqual(len(self.audit), 1)
        self.assertTrue(self.audit[0].startswith('catalog-install id=notes owner=appowner sha256='))
        self.assertEqual([n for n in os.listdir(self.paths.catalog)], ['notes.json'])  # no temp file left

    def test_replace_needs_the_previewed_digest_and_keeps_the_previous_entry(self):
        first = self.install(entry())
        with self.assertRaises(BackupError) as caught:
            self.install(entry(name='新名稱'), None)
        self.assertEqual(caught.exception.details['reason'], 'entry-changed')
        with self.assertRaises(BackupError):
            self.install(entry(name='新名稱'), '0' * 64)
        result = self.install(entry(name='新名稱'), first['sha256'])
        self.assertEqual(result['previous']['sha256'], first['sha256'])
        self.assertEqual(self.history(), [result['previous']['backup']])
        kept = Path(self.paths.config) / 'apps-history' / result['previous']['backup']
        self.assertEqual(kept.read_bytes(), catalog_admin.pretty(entry()).encode())
        self.assertEqual(os.stat(kept).st_mode & 0o7777, 0o644)
        self.assertEqual(self.loaded()['notes'].name, '新名稱')
        self.assertEqual(result['changes'], [{'path': 'name', 'op': 'change', 'old': '筆記', 'new': '新名稱'}])

    def test_history_keeps_the_newest_versions_of_each_app(self):
        sha = None
        for i in range(catalog_admin.HISTORY_KEEP + 3):
            sha = self.install(entry(name=f'v{i}'), sha, now=1_800_000_000 + i)['sha256']
        names = self.history()
        self.assertEqual(len(names), catalog_admin.HISTORY_KEEP)
        newest = json.loads((Path(self.paths.config) / 'apps-history' / sorted(names)[-1]).read_text())
        self.assertEqual(newest['name'], f'v{catalog_admin.HISTORY_KEEP + 1}')
        self.assertEqual(len(catalog_admin.history(self.paths, 'notes', trusted_uid=self.uid)),
                         catalog_admin.HISTORY_KEEP)

    def test_two_versions_in_the_same_second_get_distinct_history_names(self):
        sha = self.install(entry(), now=1_800_000_000)['sha256']
        sha = self.install(entry(name='b'), sha, now=1_800_000_000)['sha256']
        self.install(entry(name='c'), sha, now=1_800_000_000)
        self.assertEqual(len(self.history()), 2)

    def test_refused_while_a_job_runs_or_recovery_work_is_left(self):
        store = jobs.JobStore(self.paths)
        record = store.create('backup', {'apps': ['notes']})
        with self.assertRaises(BackupError) as caught:
            self.install(entry())
        self.assertEqual((caught.exception.code, caught.exception.details['job_id']), ('busy', record['id']))
        record['state'] = 'interrupted'
        record['stopped_writers'] = {'notes': ['notes-app.service']}
        store.save(record)
        with self.assertRaises(BackupError) as caught:
            self.install(entry())
        self.assertEqual(caught.exception.code, 'busy')
        self.install(entry('other', config_files=[]))  # leftovers of another app do not block
        record['stopped_writers'] = {}
        record['dir_apps'] = ['notes']
        store.save(record)
        with self.assertRaises(BackupError):
            catalog_admin.remove(self.paths, 'other', None, trusted_uid=self.uid, audit=self.audit.append)
        self.assertFalse(self.file('notes').exists())

    def test_unsafe_directories_are_never_written(self):
        os.chmod(self.paths.catalog, 0o775)
        with self.assertRaises(BackupError) as caught:
            self.install(entry())
        self.assertEqual(caught.exception.code, 'permission-denied')
        os.chmod(self.paths.catalog, 0o755)
        target = Path(self.tmp.name) / 'elsewhere.json'
        target.write_text('{}')
        os.symlink(target, self.file('notes'))
        with self.assertRaises(BackupError) as caught:
            self.install(entry())
        self.assertEqual(caught.exception.code, 'permission-denied')
        self.assertEqual(target.read_text(), '{}')
        os.unlink(self.file('notes'))
        os.rmdir(self.paths.catalog)
        os.symlink(Path(self.tmp.name), self.paths.catalog)
        with self.assertRaises(BackupError) as caught:
            self.install(entry())
        self.assertEqual(caught.exception.code, 'permission-denied')

    def test_missing_catalog_directory_is_created_but_not_the_config_directory(self):
        os.rmdir(self.paths.catalog)
        self.install(entry())
        self.assertEqual(os.stat(self.paths.catalog).st_mode & 0o7777, 0o755)
        fresh = Paths(base=Path(self.tmp.name) / 'fresh')
        with self.assertRaises(BackupError) as caught:
            catalog_admin.install(fresh, entry(), None, audit=self.audit.append, **self.kwargs())
        self.assertEqual(caught.exception.code, 'internal-error')

    def test_a_reload_failure_puts_the_previous_entry_back(self):
        first = self.install(entry())
        real = catalog_admin._loaded
        calls = []

        def broken(*args):
            calls.append(1)
            result = real(*args)
            if len(calls) == 2:  # the reload after the write
                result.pop('notes')
            return result

        with mock.patch.object(catalog_admin, '_loaded', broken):
            with self.assertRaises(BackupError) as caught:
                self.install(entry(name='新'), first['sha256'])
        self.assertIn('已恢復原本的設定', caught.exception.message)
        self.assertEqual(self.file('notes').read_bytes(), catalog_admin.pretty(entry()).encode())
        with mock.patch.object(catalog_admin, '_loaded', lambda *args: catalog.Catalog()):
            with self.assertRaises(BackupError):
                self.install(entry('fresh', config_files=[]))
        self.assertFalse(self.file('fresh').exists())

    def test_install_validates_before_taking_any_lock(self):
        with self.assertRaises(BackupError) as caught:
            self.install(entry(writer_units=['nope.service']))
        self.assertEqual(caught.exception.details['field'], 'writer_units[0]')
        self.assertFalse(Path(self.paths.run).exists())


class RemoveTests(AdminCase):
    def test_preview_and_remove_keep_the_entry_in_history(self):
        with self.assertRaises(BackupError) as caught:
            catalog_admin.preview_remove(self.paths, 'notes', trusted_uid=self.uid)
        self.assertEqual(caught.exception.code, 'not-found')
        first = self.install(entry())
        preview = catalog_admin.preview_remove(self.paths, 'notes', trusted_uid=self.uid,
                                               backups=[{'id': 'b', 'apps': [{'id': 'notes', 'name': 'n'}]}])
        self.assertEqual((preview['expected_sha256'], preview['backups']), (first['sha256'], 1))
        self.assertIn('1 份備份會保留', preview['warnings'][0])
        with self.assertRaises(BackupError):
            catalog_admin.remove(self.paths, 'notes', 'f' * 64, trusted_uid=self.uid, audit=self.audit.append)
        self.assertTrue(self.file('notes').exists())
        result = catalog_admin.remove(self.paths, 'notes', first['sha256'], trusted_uid=self.uid,
                                      audit=self.audit.append)
        self.assertFalse(self.file('notes').exists())
        self.assertEqual(self.history(), [result['backup']])
        self.assertNotIn('notes', self.loaded())
        self.assertTrue(self.audit[-1].startswith('catalog-remove id=notes'))
        with self.assertRaises(BackupError) as caught:
            catalog_admin.remove(self.paths, 'notes', first['sha256'], trusted_uid=self.uid, audit=self.audit.append)
        self.assertEqual(caught.exception.code, 'not-found')
        for bad in ('', 'Bad', '../x', None):
            with self.assertRaises(BackupError):
                catalog_admin.remove(self.paths, bad, None, trusted_uid=self.uid, audit=self.audit.append)

    def test_an_unparsable_installed_entry_can_be_replaced_and_is_kept(self):
        self.file('notes').write_text('{not json')
        os.chmod(self.file('notes'), 0o644)
        preview = catalog_admin.preview_install(self.paths, entry(), **self.kwargs())
        self.assertIsNone(preview['current']['entry'])
        self.assertTrue(any('不是有效的 JSON' in w for w in preview['warnings']))
        self.install(entry(), preview['expected_sha256'])
        kept = Path(self.paths.config) / 'apps-history' / self.history()[0]
        self.assertEqual(kept.read_text(), '{not json')


if __name__ == '__main__':
    unittest.main()
