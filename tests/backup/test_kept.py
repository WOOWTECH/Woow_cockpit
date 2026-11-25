"""RESTORE lane (HAOS parity, 2026-11-25): the restore-side commands and the kept copies of a database service.

* X-PF-05: a key that comes with a backup that is not encrypted is left out, never refused;
* kept copies (S4: whole-volume copies of a PostgreSQL service with other databases; kept.py).
"""
import io
import json
import os
import time
import unittest
from unittest import mock

from woowbackup import cli, flows, haimport, jobs, kept, podman
from woowbackup.errors import BackupError
from woowbackup.haissues import Issue

from . import test_strengthen as strength
from .test_adapter import PODMAN, SYSTEMCTL, VOLUME_TAR, extract_entries
from .test_flows import ConvertedRestoreCase, FakeAdapter, FlowCase, ha_registry_row

SOME_KEY = 'AGE-SECRET-KEY-1' + 'Q' * 58


class CliCase(FlowCase):
    """The helper commands with the fakes of test_flows (the way test_format_choice runs them)."""

    def call(self, argv, request=None):
        out = io.StringIO()
        stdin = io.StringIO(json.dumps(request)) if request is not None else None
        services = cli.Services(self.paths, deps=self.deps, launcher=self.launched.append,
                                unit_active=lambda unit: False, trusted_uid=os.geteuid())
        cli.main(argv, stdin=stdin, stdout=out, services=services, require_root=False)
        return json.loads(out.getvalue())

    def setUp(self):
        super().setUp()
        self.launched = []
        os.makedirs(self.paths.config, mode=0o755, exist_ok=True)

    def params(self, job_id):
        return jobs.JobStore(self.paths).get(job_id)['params']


class PlainBackupKeyTests(CliCase):
    """X-PF-05 (remove): "這份備份沒有加密，不需要金鑰" was a refusal of `inspect`, `verify-start` and `restore-start`; HAOS asks for
    nothing it does not need. The key is left out -- not read, not saved, not handed to a job -- and the request goes on."""

    def setUp(self):
        super().setUp()
        self.backup_id = self.backup(encrypt=False)['backup_id']
        self.storage.index[self.backup_id]['type'] = 'uploaded'

    def test_inspect_goes_on_and_a_key_that_came_with_it_is_not_saved(self):
        before = list(self.keys.imported) if hasattr(self.keys, 'imported') else None
        got = self.call(['inspect'], {'backup_id': self.backup_id, 'key': SOME_KEY, 'save_key': True})
        self.assertNotIn('error', got)
        self.assertEqual(got['manifest']['encryption'], 'none')
        if before is not None:
            self.assertEqual(list(self.keys.imported), before, 'the key was not saved')

    def test_verify_start_goes_on_without_a_key_for_the_job(self):
        got = self.call(['verify-start'], {'backup_id': self.backup_id, 'key': SOME_KEY, 'request_id': 'req-00000011'})
        self.assertNotIn('error', got)
        self.assertEqual(self.params(got['job_id'])['key_provided'], False)

    def test_restore_start_goes_on_and_hands_no_key_to_the_job(self):
        request = {'backup_id': self.backup_id, 'apps': ['woowbk-demo'], 'confirm': True, 'accept_unauthenticated': True,
                   'key': SOME_KEY, 'save_key': True, 'request_id': 'req-00000012'}
        got = self.call(['restore-start'], request)
        self.assertNotIn('error', got)
        self.assertEqual(self.params(got['job_id'])['key_provided'], False)
        self.assertEqual(self.keys.imported if hasattr(self.keys, 'imported') else [], [])

    def test_the_unauthenticated_upload_still_needs_its_own_acceptance(self):
        got = self.call(['restore-start'], {'backup_id': self.backup_id, 'apps': ['woowbk-demo'], 'confirm': True,
                                            'key': SOME_KEY, 'request_id': 'req-00000013'})
        self.assertEqual(got['error']['details']['field'], 'accept_unauthenticated')

    def test_an_encrypted_backup_still_takes_its_key(self):
        encrypted = self.backup()['backup_id']
        got = self.call(['verify-start'], {'backup_id': encrypted, 'key': SOME_KEY, 'request_id': 'req-00000014'})
        self.assertNotIn('error', got)
        self.assertEqual(self.params(got['job_id'])['key_provided'], True)


class ConvertedBackupCliTests(CliCase):
    """The restore check and `restore-start` of a converted HA backup (D10, F1's hook `restore_issues`): the lines the adapter
    leaves are in `inspect`, an unconfirmed one refuses `restore-start` before anything starts, and an ordinary backup is not
    asked at all (H6)."""

    def setUp(self):
        super().setUp()
        self.backup_id = self.backup()['backup_id']
        self.world.restore_issues['woowbk-demo'] = [Issue('restore.pauses', 'confirm', '匯入時會先暫停這些服務。', ['woowbk-files'])]
        # like the real adapter: lines only for the restore of a converted backup, kept in an instance attribute too
        for name, value in (('restore_issues', ()), ('issues_only_for_ha', True)):
            patch = mock.patch.object(FakeAdapter, name, value, create=True)
            patch.start()
            self.addCleanup(patch.stop)

    def convert(self):
        os.makedirs(self.paths.data, mode=0o700, exist_ok=True)
        haimport.register(self.paths, self.backup_id, ha_registry_row(), now=time.time())

    def key(self):
        return Issue('restore.pauses', 'confirm', 'x', ['woowbk-files']).key('woowbk-demo')

    def request(self, **more):
        return dict({'backup_id': self.backup_id, 'apps': ['woowbk-demo'], 'confirm': True, 'request_id': 'req-00000021'},
                    **more)

    def test_inspect_lists_the_line_to_confirm(self):
        self.convert()
        got = self.call(['inspect'], {'backup_id': self.backup_id})
        (row,) = got['preflight']['apps'][0]['issues']
        self.assertEqual((row['id'], row['level'], row['items'], row['key']),
                         ('restore.pauses', 'confirm', ['woowbk-files'], self.key()))

    def test_an_unconfirmed_line_refuses_before_a_job_exists(self):
        self.convert()
        got = self.call(['restore-start'], self.request())
        self.assertEqual(got['error']['code'], 'confirmation-required')
        self.assertEqual(got['error']['details']['apps']['woowbk-demo'][0]['key'], self.key())
        self.assertEqual(self.launched, [])

    def test_the_confirmed_line_starts_the_restore_with_the_keys_in_the_job(self):
        self.convert()
        got = self.call(['restore-start'], self.request(acknowledged={'woowbk-demo': [self.key()]}))
        self.assertNotIn('error', got)
        self.assertEqual(self.params(got['job_id'])['acknowledged'], {'woowbk-demo': [self.key()]})

    def test_a_registry_that_cannot_be_read_gives_the_same_answer_as_the_job(self):
        """While ha-imports.json cannot be read the note of a converted backup tells (the rule the job and retention use): the
        command asks for the lines exactly like the job will, so a restore is not started only to stop at its first step."""
        self.storage.index[self.backup_id]['note'] = haimport.NOTE_PREFIX + '示範'
        with mock.patch.object(haimport, 'load_registry', return_value=None):
            got = self.call(['restore-start'], self.request())
        self.assertEqual(got['error']['code'], 'confirmation-required')
        self.assertEqual(self.launched, [])

    def test_an_ordinary_backup_is_not_asked(self):
        got = self.call(['restore-start'], self.request())
        self.assertNotIn('error', got)
        self.assertNotIn('acknowledged', self.params(got['job_id']))


class KeptCopyFlowTests(ConvertedRestoreCase):
    """S4 (X-AD-07, X-AD-08; owner decisions D7 and H4): the restore of a converted HA backup into a database service that holds
    other databases keeps a copy of the whole service first, rolls back from it, and puts the other databases back; nothing
    is deleted silently, and what cannot go back stays in the copy. An ordinary restore is unchanged (H6)."""

    DATABASES = ('nextcloud', 'grafana')

    def setUp(self):
        super().setUp()
        self.world.kept_wanted['woowbk-demo'] = ['main']
        self.world.kept_estimate = 1000

    def kept_backups(self):
        return [meta for meta in self.storage.list_backups() if kept.is_kept(meta)]

    def run_converted(self, **more):
        self.converted()
        return flows.run_restore(self.ctx(), dict({'backup_id': self.backup_id, 'apps': ['woowbk-demo']}, **more))

    def test_the_copy_is_made_after_the_pre_restore_copy_and_before_the_first_destructive_step(self):
        result = self.run_converted()
        names = [e[0] for e in self.world.events if e[0] in ('backup', 'keep', 'restore', 'put-back')]
        self.assertEqual(names, ['backup', 'keep', 'restore', 'put-back'])
        (copy,) = self.kept_backups()
        self.assertEqual((copy['type'], copy['encrypted']), ('safety', True))
        self.assertTrue(copy['note'].startswith(kept.NOTE_PREFIX))
        self.assertEqual(result['kept']['woowbk-demo']['backup_id'], copy['id'])
        self.assertEqual(result['kept']['woowbk-demo']['databases'], list(self.DATABASES))
        (write,) = [w for w in self.archive.writes if w['manifest']['note'].startswith(kept.NOTE_PREFIX)]
        self.assertEqual(write['manifest']['apps'][0]['volumes'], [{'name': 'pgdata', 'entry': 'apps/woowbk-demo/volumes/pgdata.tar'}])
        self.assertEqual(write['manifest']['type'], 'safety')

    def test_the_other_databases_are_put_back_after_the_restore_and_the_result_says_which(self):
        result = self.run_converted()
        self.assertEqual(result['kept']['woowbk-demo']['put_back'], list(self.DATABASES))
        self.assertEqual(result['kept']['woowbk-demo']['not_put_back'], [])
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v1')
        self.assertFalse(result['rolled_back'])

    def test_a_database_that_cannot_go_back_is_named_and_never_fails_the_restore(self):
        self.world.put_back_failed['woowbk-demo'] = [('grafana', '此設備的資料庫映像沒有備份使用的擴充功能')]
        result = self.run_converted()
        view = result['kept']['woowbk-demo']
        self.assertEqual((view['put_back'], view['not_put_back']),
                         (['nextcloud'], [{'name': 'grafana', 'reason': '此設備的資料庫映像沒有備份使用的擴充功能'}]))
        self.assertTrue(any('grafana' in note and view['backup_id'] in note for note in result['warnings']), result['warnings'])
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v1', 'the restore itself stands')

    def test_an_unexpected_error_while_putting_back_is_only_a_warning(self):
        self.world.put_back_raises['woowbk-demo'] = RuntimeError('boom')
        result = self.run_converted()
        self.assertEqual(result['kept']['woowbk-demo']['put_back'], [])
        self.assertEqual(len(result['kept']['woowbk-demo']['not_put_back']), 2)
        self.assertFalse(result['rolled_back'])

    def test_a_failed_restore_rolls_back_from_the_kept_copy_whole(self):
        self.world.fail_restore_after['woowbk-demo'] = 1
        self.converted()
        with self.assertRaises(flows.RolledBack) as caught:
            flows.run_restore(self.ctx(), {'backup_id': self.backup_id, 'apps': ['woowbk-demo']})
        self.assertIn(('kept-volumes', 'woowbk-demo', ('pgdata',)), self.world.events)
        rollback = self.world.events.index(('restore', 'woowbk-demo', 'inplace', 'rollback'))
        self.assertEqual(self.world.events[rollback + 1], ('kept-volumes', 'woowbk-demo', ('pgdata',)))
        self.assertNotIn('put-back', [e[0] for e in self.world.events], 'nothing is put back after a rollback')
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed')
        self.assertEqual(len(self.kept_backups()), 1, 'the copy stays: it is the administrator\'s to delete')
        self.assertIn(caught.exception.result['kept']['woowbk-demo']['backup_id'], [m['id'] for m in self.kept_backups()])

    def test_a_failure_while_keeping_stops_only_this_app_and_starts_its_units_again(self):
        self.world.fail_keep.add('woowbk-demo')
        self.converted()
        with self.assertRaises(BackupError) as caught:
            flows.run_restore(self.ctx(), {'backup_id': self.backup_id, 'apps': ['woowbk-demo']})
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertEqual([e for e in self.world.events if e[0] in ('restore', 'put-back')], [])
        self.assertTrue(any(e[0] == 'start_units' and e[1] == 'woowbk-demo' for e in self.world.events), 'units run again')
        self.assertEqual(self.kept_backups(), [])
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed')
        self.assertFalse(self.pending().exists(), 'the pre-restore copy is dropped, nothing changed')

    def test_too_little_space_refuses_before_anything_is_stopped(self):
        self.storage.free = 10 * 1024 ** 2
        self.world.kept_estimate = 100 * 1024 ** 2
        self.converted()
        with self.assertRaises(BackupError) as caught:
            flows.run_restore(self.ctx(), {'backup_id': self.backup_id, 'apps': ['woowbk-demo']})
        self.assertEqual(caught.exception.code, 'insufficient-space')
        self.assertIn('完整複本', caught.exception.message)
        self.assertEqual([e for e in self.world.events if e[0] in ('backup', 'keep', 'restore')], [])

    def test_the_room_is_checked_again_when_the_pre_restore_copy_has_used_some(self):
        """The first question (before anything stops) said yes; the pre-restore copy then used the room: the copy of the service
        is refused before its first service stops, the pre-restore copy is dropped and the app's units run again."""
        self.world.kept_estimate = 100 * 1024 ** 2
        reserve = self.paths.reserve_bytes
        self.world.hook_probe = lambda: setattr(self.storage, 'free', reserve + 100 * 1024 ** 2)
        self.converted()
        with self.assertRaises(BackupError) as caught:
            flows.run_restore(self.ctx(), {'backup_id': self.backup_id, 'apps': ['woowbk-demo']})
        self.assertEqual(caught.exception.code, 'insufficient-space')
        self.assertIn('保存還原前資料後', caught.exception.message)
        self.assertIn('完整複本', caught.exception.message)
        names = [e[0] for e in self.world.events]
        self.assertIn('backup', names)
        self.assertEqual([n for n in names if n in ('keep', 'restore', 'put-back')], [])
        self.assertTrue(any(e[0] == 'start_units' and e[1] == 'woowbk-demo' for e in self.world.events), 'units run again')
        self.assertEqual(self.kept_backups(), [])
        self.assertFalse(self.pending().exists())

    def test_no_other_database_means_no_copy(self):
        self.world.kept_wanted.clear()
        result = self.run_converted()
        self.assertNotIn('keep', [e[0] for e in self.world.events])
        self.assertNotIn('kept', result)
        self.assertEqual(self.kept_backups(), [])

    def test_an_ordinary_restore_keeps_nothing(self):
        result = flows.run_restore(self.ctx(), {'backup_id': self.backup_id, 'apps': ['woowbk-demo']})
        self.assertNotIn('keep', [e[0] for e in self.world.events])
        self.assertNotIn('kept', result)

    def test_a_kept_copy_is_never_pruned_with_the_three_newest_pre_restore_backups(self):
        self.run_converted()
        (copy,) = self.kept_backups()
        self.world.kept_wanted.clear()
        for _ in range(5):  # five more restores: each leaves a pre-restore backup, three are kept
            self.restore()
        self.assertIn(copy['id'], [m['id'] for m in self.storage.list_backups()])
        self.assertEqual(len([m for m in self.storage.list_backups() if m['type'] == 'safety' and not kept.is_kept(m)]), 3)

    def test_the_converted_backups_row_says_where_the_copy_is(self):
        result = self.run_converted()
        row = haimport.load_registry(self.paths)[self.backup_id]
        self.assertEqual(row['kept'], result['kept']['woowbk-demo']['backup_id'])

    def test_a_row_that_cannot_be_updated_does_not_unpin_the_copy(self):
        with mock.patch.object(haimport, 'update_row', side_effect=OSError('read-only')):
            result = self.run_converted()
        (copy,) = self.kept_backups()
        self.assertEqual(copy['id'], result['kept']['woowbk-demo']['backup_id'])
        self.assertTrue(kept.is_kept(copy), 'the note pins it, whatever the row says')


class PinnedPreRestoreBackupTests(ConvertedRestoreCase):
    """L-38 (the API LITELLM uses): a converted backup whose app section says `keep_safety` makes the restore write its pre-restore
    backup as a kept copy: pinned, never pruned, nothing else changes."""

    def test_the_pre_restore_backup_of_such_a_backup_is_kept(self):
        self.world.keep_safety.add('woowbk-demo')
        self.backup_id = self.backup(apps=['woowbk-demo'])['backup_id']
        self.converted()
        result = flows.run_restore(self.ctx(), {'backup_id': self.backup_id, 'apps': ['woowbk-demo']})
        meta = self.storage.get(result['safety_backup_id'])
        self.assertTrue(kept.is_kept(meta))
        self.assertIn(self.backup_id, meta['note'])
        for _ in range(5):
            self.world.keep_safety.discard('woowbk-demo')
            self.backup_id = self.backup(apps=['woowbk-demo'])['backup_id']
            flows.run_restore(self.ctx(), {'backup_id': self.backup_id, 'apps': ['woowbk-demo']})
        self.assertIn(result['safety_backup_id'], [m['id'] for m in self.storage.list_backups()])

    def test_an_ordinary_pre_restore_backup_is_not_pinned(self):
        result = self.restore()
        self.assertFalse(kept.is_kept(self.storage.get(result['safety_backup_id'])))


class KeptCopyListAndDeleteTests(CliCase):
    """The page needs no magic string to find a kept copy: the backup list says `kept` (derived from the note, only when true),
    and the converted backup stops pointing at a copy the administrator deleted."""

    def setUp(self):
        super().setUp()
        self.source = self.backup()['backup_id']
        self.copy = self.backup()['backup_id']
        self.storage.index[self.copy].update(type='safety', note=kept.NOTE_PREFIX + '示範（匯入前整個資料庫服務，含其他資料庫）')
        os.makedirs(self.paths.data, mode=0o700, exist_ok=True)
        haimport.register(self.paths, self.source, ha_registry_row(), now=time.time())
        haimport.update_row(self.paths, self.source, kept=self.copy)

    def listed(self):
        return {b['id']: b for b in self.call(['list'], {})['backups']}

    def test_the_list_marks_the_kept_copy_and_only_it(self):
        listed = self.listed()
        self.assertIs(listed[self.copy].get('kept'), True)
        self.assertNotIn('kept', listed[self.source])
        self.assertEqual(listed[self.source]['from_ha']['kept'], self.copy, 'the converted backup names its copy')

    def test_an_ordinary_pre_restore_backup_is_not_marked(self):
        self.storage.index[self.copy]['note'] = '還原前自動備份（還原來源 x）'
        self.assertNotIn('kept', self.listed()[self.copy])

    def test_a_pinned_pre_restore_backup_is_marked_too(self):
        self.storage.index[self.copy]['note'] = kept.note_for(None, source_note='還原前自動備份（還原來源 x）')
        self.assertIs(self.listed()[self.copy].get('kept'), True)

    def test_deleting_the_copy_clears_the_pointer_and_nothing_else_of_the_row(self):
        before = haimport.load_registry(self.paths)[self.source]
        got = self.call(['delete'], {'backup_id': self.copy})
        self.assertNotIn('error', got)
        row = haimport.load_registry(self.paths)[self.source]
        self.assertIsNone(row['kept'])
        self.assertEqual({k: v for k, v in row.items() if k != 'kept'}, {k: v for k, v in before.items() if k != 'kept'})
        self.assertIsNone(self.listed()[self.source]['from_ha']['kept'])

    def test_deleting_another_backup_leaves_the_pointer(self):
        other = self.backup()['backup_id']
        self.assertNotIn('error', self.call(['delete'], {'backup_id': other}))
        self.assertEqual(haimport.load_registry(self.paths)[self.source]['kept'], self.copy)

    def test_deleting_one_copy_leaves_the_pointer_of_another_converted_backup(self):
        second_source = self.backup()['backup_id']
        second_copy = self.backup()['backup_id']
        self.storage.index[second_copy].update(type='safety', note=kept.NOTE_PREFIX + '另一份')
        haimport.register(self.paths, second_source, ha_registry_row(), now=time.time())
        haimport.update_row(self.paths, second_source, kept=second_copy)
        self.assertNotIn('error', self.call(['delete'], {'backup_id': self.copy}))
        rows = haimport.load_registry(self.paths)
        self.assertIsNone(rows[self.source]['kept'])
        self.assertEqual(rows[second_source]['kept'], second_copy)

    def test_an_unreadable_registry_does_not_stop_the_delete(self):
        with mock.patch.object(haimport, 'load_registry', side_effect=OSError('unreadable')):
            got = self.call(['delete'], {'backup_id': self.copy})
        self.assertNotIn('error', got)
        self.assertNotIn(self.copy, self.listed())


class KeptModuleTests(unittest.TestCase):
    def test_only_a_safety_backup_with_the_note_is_a_kept_copy(self):
        good = {'id': 'a', 'type': 'safety', 'note': kept.NOTE_PREFIX + 'x'}
        self.assertTrue(kept.is_kept(good))
        for bad in (dict(good, type='manual'), dict(good, type='uploaded'), dict(good, note='還原前自動備份'),
                    dict(good, note=None), {}, None, 'x'):
            self.assertFalse(kept.is_kept(bad), bad)
        self.assertEqual(kept.kept_ids([good, dict(good, id='b', type='manual'), dict(good, id='c', note='x')]), {'a'})

    def test_the_view_of_a_copy_has_no_path_and_cuts_a_long_list(self):
        info = {'volumes': {'pg': '/tmp/secret/path.tar'}, 'logical': {}, 'databases': [f'db{i}' for i in range(30)],
                'notes': ['x']}
        view = kept.Kept('b1', info).view()
        self.assertEqual((len(view['databases']), view['more']), (kept.MAX_NAMES, 10))
        self.assertNotIn('/tmp', json.dumps(view))

    def test_a_rollback_gets_the_volumes_of_its_own_app_only(self):
        copy = kept.Kept('b1', {'volumes': {'pg': '/x.tar'}, 'logical': {}, 'databases': [], 'notes': []})
        self.assertEqual(kept.rollback_volumes({'app': copy}, 'app'), {'pg': '/x.tar'})
        self.assertEqual(kept.rollback_volumes({'app': copy}, 'other'), {})
        self.assertEqual(kept.rollback_volumes(None, 'app'), {})


class KeptOwner(strength.StrengthOwner):
    """The instance model of test_strengthen plus the one question put-back asks that no other test does."""

    def podman(self, args, data, stdout):
        if args[0] == 'exec' and 'pg_restore' in args and '--create' in args and self.instance is not None and data:
            name = bytes(data).split(b':', 2)[1].decode()
            if name in self.partial_restore:  # created, then failed: what is left is for put-back to drop again
                self.instance[name] = {'owner': 'restored', 'data': bytes(data), 'extensions': []}
                return podman.Result(1, b'', b'pg_restore: error: could not execute query')
        if args[0] == 'exec' and args[-2:-1] == ['-c'] and args[-1].startswith('DROP DATABASE IF EXISTS "'):
            name = args[-1][len('DROP DATABASE IF EXISTS "'):-1]
            if name not in (self.instance or {}):
                return podman.Result(0, b'', b'')
            args = [*args[:-1], f'DROP DATABASE "{name}"']
        if args[0] == 'exec' and args[-1].startswith('ALTER DATABASE "') and args[-1].endswith('" IS_TEMPLATE false'):
            if args[-1][len('ALTER DATABASE "'):-len('" IS_TEMPLATE false')] not in (self.instance or {}):
                return podman.Result(1, b'', b'ERROR:  database does not exist')
        return super().podman(args, data, stdout)

    cut_script = False  # a script arrives short: psql exits 0 but never reaches the end mark
    partial_restore = frozenset()  # databases whose `pg_restore --create` creates them and then fails half-way

    def psql_file(self, database, sql, stdout):
        if sql.startswith("SELECT coalesce(json_agg(rolname), '[]'::json) FROM pg_roles"):
            return self.json(['notes'], stdout)  # the new cluster has only what the image created
        if sql.startswith('BEGIN;\n') and '\\echo woowbk-sql-end-' in sql:
            # a script with its own transaction and an end mark psql prints after running it (pg-stdin follow-up F1); this
            # fake answers it itself, so these tests do not depend on test_strengthen.py's own fake being changed
            body, _, tail = sql.rpartition('COMMIT;\n')
            mark = tail.strip()[len('\\echo '):]
            done = super().psql_file(database, body[len('BEGIN;\n'):], stdout)
            return podman.Result(done.returncode, b'' if self.cut_script else (mark + '\n').encode(), done.stderr)
        return super().psql_file(database, sql, stdout)


class AdapterKeptCase(strength.StrengthCase):
    """A single-database app (database `notes`) whose database service holds other databases and roles (the instance model),
    restored as a converted HA backup (`adapter.ha_import`)."""

    def setUp(self):
        super().setUp()
        self.owner = KeptOwner(instance=True)
        self.owner.volumes['woowbk-demo-pgdata'] = VOLUME_TAR
        self.owner.db['databases'] = {'notes', 'nextcloud', 'tmpl_custom'}
        self.owner.db['roles'] = ['oc_admin', 'readonly']
        self.adapter = self.converted()
        self.work = self.root / 'kept-work'

    def converted(self, owner=None):
        adapter = self.make_adapter(owner or self.owner)
        adapter.ha_import = True
        adapter.job_id = 'j20261125T100000Z-aaaaaaaa'
        return adapter

    def manifest(self):
        return {'id': 'woowbk-demo', 'adapter': 'quadlet-postgres', 'adapter_version': 1, 'catalog_sha256': self.app.sha256,
                'owner': {'name': 'appowner', 'uid': 1001}, 'postgres': [], 'volumes': [], 'secrets': [], 'config_files': [],
                'quadlet_files': [], 'images': []}


class KeptClusterTests(AdapterKeptCase):
    def test_the_check_lists_the_other_databases_in_one_line_to_confirm(self):
        checks = self.adapter.preflight(self.manifest(), mode='inplace')
        found = [c for c in checks if c['id'] == 'woowbk-demo/databases']
        self.assertEqual([c['status'] for c in found], ['warn'], 'no longer a refusal')
        self.assertIn('完整複本', found[0]['message'])
        (issue,) = self.adapter.restore_issues
        self.assertEqual((issue.id, issue.level, sorted(issue.names)), ('restore.other-databases', 'confirm',
                                                                         ['nextcloud', 'tmpl_custom']))
        self.assertEqual(self.adapter.kept_wanted, ['main'])
        self.assertGreater(self.adapter.kept_estimate, 0)

    def test_a_service_that_cannot_be_listed_is_kept_too(self):
        self.owner.fail.append(('FROM pg_database WHERE datname NOT IN', 2))
        checks = self.adapter.preflight(self.manifest(), mode='inplace')
        self.assertEqual([c['status'] for c in checks if c['id'] == 'woowbk-demo/databases'], ['warn'])
        (issue,) = self.adapter.restore_issues
        self.assertEqual((issue.id, issue.names), ('restore.other-databases', ()))
        self.assertEqual(self.adapter.kept_wanted, ['main'])

    def test_a_stopped_service_is_kept_too_and_the_check_says_why(self):
        """A service that is not running cannot be asked what it holds: the same as "cannot tell" -- a copy of all of it."""
        self.owner.units['woowbk-demo-db.service'] = 'inactive'
        by_id = {c['id']: c for c in self.adapter.preflight(self.manifest(), mode='inplace')}
        self.assertEqual(by_id['woowbk-demo/database-down']['status'], 'warn')
        self.assertNotIn('未宣告', by_id['woowbk-demo/database-down']['message'],
                         'the promise of an ordinary restore (it refuses other databases) does not hold for an import')
        self.assertEqual(by_id['woowbk-demo/databases']['status'], 'warn')
        self.assertIn('目前未執行', by_id['woowbk-demo/databases']['message'])
        (issue,) = self.adapter.restore_issues
        self.assertEqual((issue.id, issue.level, list(issue.names)), ('restore.other-databases', 'confirm', []))
        self.assertIn('先啟動資料庫服務', issue.text)
        self.assertEqual(self.adapter.kept_wanted, ['main'])
        self.assertGreater(self.adapter.kept_estimate, 0)

    def test_an_ordinary_restore_with_a_stopped_service_keeps_its_old_way(self):
        self.owner.units['woowbk-demo-db.service'] = 'inactive'
        adapter = self.make_adapter(self.owner)
        by_id = {c['id']: c for c in adapter.preflight(self.manifest(), mode='inplace')}
        self.assertIn('未宣告', by_id['woowbk-demo/database-down']['message'])
        self.assertNotIn('woowbk-demo/databases', by_id)
        self.assertEqual((adapter.restore_issues, adapter.kept_wanted), ([], []))

    def test_a_stopped_service_whose_units_are_lost_is_the_units_problem_not_a_copy(self):
        del self.owner.units['woowbk-demo-db.service']
        adapter = self.converted()
        by_id = {c['id']: c for c in adapter.preflight(self.manifest(), mode='inplace')}
        self.assertEqual(by_id['woowbk-demo/units']['status'], 'fail')
        self.assertEqual((adapter.restore_issues, adapter.kept_wanted), ([], []))

    def test_the_copy_of_a_stopped_service_starts_it_before_it_reads_anything(self):
        self.owner.units['woowbk-demo-db.service'] = 'inactive'
        self.adapter.preflight(self.manifest(), mode='inplace')
        _section, _entries, info = self.adapter.keep_cluster(self.work)
        argvs = self.owner.argvs()
        started = argvs.index([SYSTEMCTL, '--user', 'start', '--', 'woowbk-demo-db.service'])
        self.assertLess(started, max(i for i, a in enumerate(argvs) if 'pg_dump' in a))
        self.assertEqual(sorted(info['databases']), ['nextcloud', 'tmpl_custom'])
        self.assertEqual(self.owner.units['woowbk-demo-db.service'], 'inactive', 'and stopped again for the cold copy')

    def test_an_ordinary_restore_still_refuses_and_keeps_nothing(self):
        adapter = self.make_adapter()
        checks = adapter.preflight(self.manifest(), mode='inplace')
        self.assertEqual([c['status'] for c in checks if c['id'] == 'woowbk-demo/databases'], ['fail'])
        self.assertEqual((adapter.restore_issues, adapter.kept_wanted), ([], []))

    def test_no_other_database_no_line(self):
        self.owner.db['databases'] = {'notes'}
        self.adapter.preflight(self.manifest(), mode='inplace')
        self.assertEqual((self.adapter.restore_issues, self.adapter.kept_wanted), ([], []))

    def test_the_copy_stops_the_service_and_takes_the_cold_copy_and_every_database(self):
        self.adapter.preflight(self.manifest(), mode='inplace')
        section, entries, info = self.adapter.keep_cluster(self.work)
        paths = {entry.path for entry in entries}
        self.assertIn('apps/woowbk-demo/volumes/woowbk-demo-pgdata.tar', paths)
        self.assertIn('apps/woowbk-demo/postgres/main.globals.sql', paths)
        self.assertEqual(section['volumes'], [{'name': 'woowbk-demo-pgdata',
                                               'entry': 'apps/woowbk-demo/volumes/woowbk-demo-pgdata.tar'}])
        self.assertEqual(section['postgres'][0]['scope'], 'instance')
        self.assertEqual(sorted(info['databases']), ['nextcloud', 'tmpl_custom'])
        self.assertEqual(info['volumes'], {'woowbk-demo-pgdata': self.work / 'volumes' / 'woowbk-demo-pgdata.tar'})
        self.assertEqual((self.owner.units['woowbk-demo-db.service'], self.owner.units['woowbk-demo-app.service']),
                         ('inactive', 'inactive'))
        self.assertTrue(self.adapter.kept_done)
        self.assertEqual(set(self.adapter.kept_stopped), {'woowbk-demo-app.service', 'woowbk-demo-db.service'})
        argvs = self.owner.argvs()
        dumped = max(i for i, a in enumerate(argvs) if 'pg_dump' in a)
        stopped = argvs.index([SYSTEMCTL, '--user', 'stop', '--', 'woowbk-demo-db.service'])
        exported = next(i for i, a in enumerate(argvs) if 'volume' in a and 'export' in a and 'woowbk-demo-pgdata' in a)
        self.assertLess(dumped, stopped, 'read while the database runs')
        self.assertLess(stopped, exported, 'the volume is exported only after the database stopped: a cold copy')

    def test_the_section_of_the_copy_is_one_the_real_archive_format_accepts(self):
        """The kept copy is packaged by the ordinary archive writer: its app section and entries pass the real validators."""
        from woowbackup import archive
        from .test_archive_v2 import small_inner
        self.adapter.preflight(self.manifest(), mode='inplace')
        section, entries, _info = self.adapter.keep_cluster(self.work)
        inner = small_inner('woowbk-demo', 'AAAA-BBBB-CCCC-DDDD', {'apps/woowbk-demo/secrets/x': b'x'})
        inner['app'] = section
        inner['entries'] = [{'path': entry.path, 'size': entry.size, 'sha256': entry.sha256} for entry in entries]
        archive.validate_app_manifest(inner)
        self.assertEqual(len({entry.path for entry in entries}), len(entries), 'no entry twice')
        self.assertEqual({entry.path.split('/')[2] for entry in entries}, {'postgres', 'volumes'})

    def test_the_other_databases_are_put_back_into_the_new_cluster_without_touching_what_is_there(self):
        self.adapter.preflight(self.manifest(), mode='inplace')
        _section, _entries, info = self.adapter.keep_cluster(self.work)
        dump = info['logical']['main']
        self.owner.reinit()  # the new cluster: what the image creates
        self.owner.units['woowbk-demo-db.service'] = 'active'
        done, failed = self.adapter.put_back_databases(self.app.postgres[0], dump)
        self.assertEqual((sorted(done), failed), (['nextcloud', 'tmpl_custom'], []))
        self.assertIn('nextcloud', self.owner.instance)
        script = self.owner.applied_globals[-1]
        self.assertIn('CREATE ROLE oc_admin;', script)
        self.assertNotIn('CREATE ROLE notes', script, 'the app\'s own account is never created again')
        self.assertNotIn('ALTER ROLE notes', script, 'and never altered: its password is the restored secret')
        creates = [a for a in self.owner.argvs() if 'pg_restore' in a and '--create' in a]
        self.assertEqual(len(creates), 2)
        self.assertTrue(all('template1' in a for a in creates))

    def test_a_database_that_fails_to_come_back_is_dropped_again_and_named(self):
        self.adapter.preflight(self.manifest(), mode='inplace')
        _section, _entries, info = self.adapter.keep_cluster(self.work)
        self.owner.reinit()
        self.owner.units['woowbk-demo-db.service'] = 'active'
        self.owner.fail.append(('pg_restore --create --exit-on-error --no-tablespaces -w -U notes -d template1', 1))
        done, failed = self.adapter.put_back_databases(self.app.postgres[0], info['logical']['main'])
        self.assertEqual(done, [])
        self.assertEqual(sorted(name for name, _reason in failed), ['nextcloud', 'tmpl_custom'])
        self.assertNotIn('nextcloud', self.owner.instance)

    def test_what_a_failed_put_back_half_created_is_dropped_again(self):
        """pg_restore --create makes the database first: when it then fails, the half-made database must not stay behind."""
        self.adapter.preflight(self.manifest(), mode='inplace')
        _section, _entries, info = self.adapter.keep_cluster(self.work)
        self.owner.reinit()
        self.owner.units['woowbk-demo-db.service'] = 'active'
        self.owner.partial_restore = frozenset({'nextcloud'})
        done, failed = self.adapter.put_back_databases(self.app.postgres[0], info['logical']['main'])
        self.assertEqual((done, [name for name, _reason in failed]), (['tmpl_custom'], ['nextcloud']))
        self.assertNotIn('nextcloud', self.owner.instance, 'the half-made database was dropped again')
        self.assertIn('tmpl_custom', self.owner.instance)

    def test_the_roles_script_needs_its_end_mark(self):
        """pg-stdin follow-up F1: one transaction and an end mark, so a script that arrived short is never half applied."""
        owner = self.owner
        adapter = self.converted()
        container = self.app.postgres[0]['container']
        adapter._run_sql(container, 'notes', 'template1', 'CREATE ROLE a;\n')
        self.assertEqual(owner.applied_globals[-1], 'CREATE ROLE a;\n')
        owner.cut_script = True
        with self.assertRaises(BackupError) as caught:
            adapter._run_sql(container, 'notes', 'template1', 'CREATE ROLE b;\n')
        self.assertIn('沒有完整送達', caught.exception.message)
        self.assertEqual(caught.exception.code, 'job-failed')


class KeptRestoreAndRollbackTests(AdapterKeptCase):
    """The adapter's restore of a service whose copy was kept: the refusal of the other databases is no longer needed, and a
    rollback puts the data volume back whole from the cold copy instead of rebuilding it from the dump."""

    def restore_case(self):
        manifest, entries = self.run_backup()
        extract = self.root / 'job' / 'extract'
        extract.mkdir(parents=True)
        extract_entries(entries, extract)
        return manifest, extract

    def test_a_restore_without_the_copy_refuses_the_other_databases_and_with_it_does_not(self):
        manifest, extract = self.restore_case()
        refusing = self.converted()
        with self.assertRaises(BackupError) as caught:
            refusing.restore(manifest, extract, mode='inplace')
        self.assertIn('還有應用設定未宣告的資料庫', caught.exception.message)
        self.assertEqual(self.owner.units['woowbk-demo-db.service'], 'active', 'refused before anything stopped')
        self.adapter.preflight(self.manifest(), mode='inplace')
        self.adapter.keep_cluster(self.work)
        self.adapter.restore(manifest, extract, mode='inplace')
        self.assertTrue(any(a[:3] == [PODMAN, 'volume', 'rm'] for a in self.owner.argvs()))

    def test_a_rollback_puts_the_cold_copy_back_whole_and_does_not_rebuild_the_database_from_the_dump(self):
        manifest, extract = self.restore_case()
        self.adapter.preflight(self.manifest(), mode='inplace')
        _section, _entries, info = self.adapter.keep_cluster(self.work)
        rollback = self.converted()
        self.owner.calls.clear()
        rollback.restore(manifest, extract, mode='inplace', rollback=True, kept_volumes=info['volumes'])
        argvs = self.owner.argvs()
        self.assertIn([PODMAN, 'volume', 'import', 'woowbk-demo-pgdata', '-'], argvs, 'the cold copy is imported')
        self.assertFalse(any('pg_restore' in a for a in argvs), 'nothing is rebuilt from the pre-restore dump')
        self.assertTrue(any('已用保留的完整複本整個放回' in line for line in self.logs), self.logs)
        ordinary = self.converted()
        ordinary.job_id = 'j20261125T100000Z-bbbbbbbb'
        self.owner.calls.clear()
        ordinary.restore(manifest, extract, mode='inplace', rollback=True)
        self.assertTrue(any('pg_restore' in a for a in self.owner.argvs()), 'without a copy the rollback uses the dump')


class KeepSafetyManifestTests(unittest.TestCase):
    """The L-38 pin API: the optional `keep_safety` key of an app section is `true` or the archive is invalid."""

    def test_only_true_is_accepted(self):
        from woowbackup import archive
        from .test_archive import APP
        from .test_archive_v2 import small_inner
        inner = small_inner(APP, 'AAAA-BBBB-CCCC-DDDD', {f'apps/{APP}/secrets/db-password': b'x'})
        archive.validate_app_manifest(inner)
        inner['app']['keep_safety'] = True
        archive.validate_app_manifest(inner)
        for bad in (False, 'yes', 1, None):
            with self.subTest(bad=bad), self.assertRaises(BackupError) as caught:
                inner['app']['keep_safety'] = bad
                archive.validate_app_manifest(inner)
            self.assertEqual(caught.exception.code, 'invalid-manifest')


if __name__ == '__main__':
    unittest.main()
