"""Storage usage per app, keep-last-N retention of manual backups, protections. Owner: catalog + retention engineer.

Backups are real index sidecars and archive files in a temporary `Storage`; job records are real `JobStore` records,
so the protections read exactly what the engine writes.
"""
import os
import tempfile
import types
import unittest
from pathlib import Path

from woowbackup import jobs, retention
from woowbackup.errors import BackupError
from woowbackup.paths import Paths
from woowbackup.storage import Storage

NAMES = {'n8n': 'n8n 工作流程', 'odoo': 'Odoo 18', 'litellm': 'LiteLLM'}


def backup_id(n):
    return f'202611{n // 24 + 1:02d}T{n % 24:02d}0000Z-{n:08x}'


def created(n):
    return f'2026-11-{n // 24 + 1:02d}T{n % 24:02d}:00:00Z'


class RetentionCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.paths = Paths(base=Path(self.tmp.name))
        os.makedirs(self.paths.config, mode=0o755)
        os.chmod(self.paths.config, 0o755)
        self.uid = os.getuid()
        self.storage = Storage(self.paths, free_space=lambda _path: 10 ** 12)
        self.storage.ensure_layout()
        self.audit = []
        self.logs = []

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, n, apps, kind='manual', size=1000):
        """A listed backup number `n` (higher = newer) of `apps` with an archive of `size` bytes."""
        bid = backup_id(n)
        path = Path(self.storage.archive_path(bid))
        path.write_bytes(b'x' * size)
        self.storage.register(bid, {
            'id': bid, 'type': kind, 'created': created(n), 'note': f'n{n}',
            'apps': [{'id': app, 'name': NAMES.get(app, app)} for app in apps], 'sha256': '0' * 64,
            'key_id': 'ABCD-EF01-2345-6789', 'include_images': False,
            'filename': f'woowtech-backup-dev-{created(n)[:10].replace("-", "")}-000000.woowbackup',
            'source': {'hostname': 'dev'}, 'verified': None, 'inspected': True})
        return bid

    def ids(self):
        return {b['id'] for b in self.storage.list_backups()}

    def save(self, policy):
        return retention.save_policy(self.paths, policy, trusted_uid=self.uid)

    def job(self, kind, params, state, **fields):
        """A job record; each one a second newer than the previous (records are ordered by their id's time)."""
        self.clock = getattr(self, 'clock', 1_800_000_000) + 1
        store = jobs.JobStore(self.paths)
        record = store.create(kind, params, now=self.clock)
        record['state'] = state
        record.update(fields)
        store.save(record)
        return record


class PolicyTests(RetentionCase):
    def test_validation_normalizes_and_rejects(self):
        self.assertEqual(retention.validate_policy({'apps': {'odoo': {'keep_last': 3}, 'n8n': {'keep_last': None}}}),
                         {'schema': 1, 'default_keep_last': None,
                          'apps': {'n8n': {'keep_last': None}, 'odoo': {'keep_last': 3}}})
        bad = [None, [], {'extra': 1}, {'schema': 2}, {'schema': True}, {'default_keep_last': 0},
               {'default_keep_last': 1001}, {'default_keep_last': True}, {'default_keep_last': '3'}, {'apps': []},
               {'apps': {'Bad Id': {'keep_last': 1}}}, {'apps': {'odoo': 3}}, {'apps': {'odoo': {}}},
               {'apps': {'odoo': {'keep_last': 1, 'x': 2}}},
               {'apps': {f'app{i}': {'keep_last': 1} for i in range(retention.MAX_APPS + 1)}}]
        for value in bad:
            with self.subTest(value=str(value)[:60]):
                with self.assertRaises(BackupError) as caught:
                    retention.validate_policy(value)
                self.assertEqual(caught.exception.code, 'invalid-request')

    def test_save_and_load_with_trust_checks(self):
        self.assertEqual(retention.load_policy(self.paths, trusted_uid=self.uid), (retention.default_policy(), None))
        saved = self.save({'default_keep_last': 5, 'apps': {'odoo': {'keep_last': 2}}})
        path = Path(self.paths.config) / 'retention.json'
        self.assertEqual(os.stat(path).st_mode & 0o7777, 0o644)
        self.assertEqual(retention.load_policy(self.paths, trusted_uid=self.uid), (saved, None))
        self.assertEqual(retention.keep_last(saved, 'odoo'), 2)
        self.assertEqual(retention.keep_last(saved, 'n8n'), 5)
        os.chmod(path, 0o666)
        policy, problem = retention.load_policy(self.paths, trusted_uid=self.uid)
        self.assertEqual(policy, retention.default_policy())
        self.assertIn('不可讓其他帳號寫入', problem)
        path.write_text('{"apps": {"odoo": {"keep_last": 0}}}')
        os.chmod(path, 0o644)
        self.assertIn('格式不正確', retention.load_policy(self.paths, trusted_uid=self.uid)[1])
        path.unlink()
        os.symlink(Path(self.tmp.name) / 'x.json', path)
        self.assertIsNotNone(retention.load_policy(self.paths, trusted_uid=self.uid)[1])
        os.chmod(self.paths.config, 0o777)
        policy, problem = retention.load_policy(self.paths, trusted_uid=self.uid)
        self.assertEqual(policy, retention.default_policy())
        self.assertIsNotNone(problem)
        with self.assertRaises(BackupError):
            self.save({'apps': {}})


class UsageTests(unittest.TestCase):
    def test_per_app_usage_splits_shared_backups(self):
        backups = [
            {'id': 'a', 'type': 'manual', 'created': '2026-11-13T02:00:00Z', 'size': 1001,
             'apps': [{'id': 'n8n', 'name': 'n8n'}, {'id': 'odoo', 'name': 'Odoo'}]},
            {'id': 'b', 'type': 'safety', 'created': '2026-11-12T02:00:00Z', 'size': 300,
             'apps': [{'id': 'odoo', 'name': 'Odoo'}]},
            {'id': 'c', 'type': 'manual', 'created': '2026-11-11T02:00:00Z', 'size': 900,
             'apps': [{'id': 'n8n', 'name': 'n8n', 'size': 100}, {'id': 'odoo', 'name': 'Odoo', 'size': 800}]},
            {'id': 'd', 'type': 'uploaded', 'created': None, 'size': 50, 'apps': []},
        ]
        catalog_apps = {'litellm': types.SimpleNamespace(id='litellm', name='LiteLLM'),
                        'odoo': types.SimpleNamespace(id='odoo', name='Odoo 18')}
        usage = retention.app_usage(backups, catalog_apps, {'schema': 1, 'default_keep_last': 4,
                                                            'apps': {'odoo': {'keep_last': None}}})
        rows = {row['id']: row for row in usage['apps']}
        self.assertEqual([row['id'] for row in usage['apps']], ['odoo', 'n8n', 'litellm'])
        self.assertEqual(rows['odoo']['bytes'], 500 + 300 + 800)
        self.assertEqual(rows['n8n']['bytes'], 501 + 100)
        self.assertTrue(rows['n8n']['estimated'] and rows['n8n']['shared'])
        self.assertEqual(rows['odoo']['types'], {'manual': 2, 'safety': 1, 'uploaded': 0})
        self.assertEqual((rows['odoo']['newest'], rows['odoo']['oldest']),
                         ('2026-11-13T02:00:00Z', '2026-11-11T02:00:00Z'))
        self.assertEqual((rows['odoo']['keep_last'], rows['n8n']['keep_last']), (None, 4))
        self.assertEqual(rows['odoo']['name'], 'Odoo 18')
        self.assertEqual(rows['litellm'], {'id': 'litellm', 'name': 'LiteLLM', 'in_catalog': True, 'backups': 0,
                                           'types': {'manual': 0, 'safety': 0, 'uploaded': 0}, 'bytes': 0,
                                           'estimated': False, 'shared': False, 'newest': None, 'oldest': None,
                                           'keep_last': 4})
        self.assertFalse(rows['n8n']['in_catalog'])
        self.assertEqual(usage['unassigned'], {'backups': 1, 'bytes': 50})
        self.assertEqual(usage['total'], {'backups': 4, 'bytes': 2251})
        self.assertEqual(sum(row['bytes'] for row in usage['apps']) + 50, 2251)


class PlanTests(RetentionCase):
    def test_keep_last_counts_per_app_and_keeps_backups_another_app_needs(self):
        both = self.make(1, ['n8n', 'odoo'])
        for n in range(2, 6):
            self.make(n, ['n8n'])
        for n in range(6, 8):
            self.make(n, ['odoo'])
        self.make(9, ['n8n'], kind='safety')
        self.make(10, ['n8n'], kind='uploaded')
        policy = retention.validate_policy({'apps': {'n8n': {'keep_last': 2}, 'odoo': {'keep_last': 3}}})
        result = retention.plan(self.storage.list_backups(), policy, {})
        self.assertEqual([c['id'] for c in result['candidates']], [backup_id(3), backup_id(2)])  # newest first
        self.assertEqual(result['freed_bytes'], 2000)
        self.assertIn('「n8n 工作流程」第 3 新（保留最新 2 份）', result['candidates'][0]['reason'])
        policy['apps']['odoo']['keep_last'] = 2  # odoo no longer needs its 3rd newest: the shared backup goes
        candidates = retention.plan(self.storage.list_backups(), policy, {})['candidates']
        self.assertEqual([c['id'] for c in candidates], [backup_id(3), backup_id(2), both])
        self.assertIn('「Odoo 18」第 3 新（保留最新 2 份）', candidates[2]['reason'])
        policy['apps']['odoo']['keep_last'] = None  # unlimited for odoo: its backups always stay
        ids = [c['id'] for c in retention.plan(self.storage.list_backups(), policy, {})['candidates']]
        self.assertNotIn(both, ids)

    def test_default_protection_and_app_filter(self):
        old = self.make(1, ['litellm'])
        self.make(2, ['litellm'])
        self.make(3, ['odoo'])
        self.make(4, ['odoo'])
        policy = retention.validate_policy({'default_keep_last': 1, 'apps': {}})
        result = retention.plan(self.storage.list_backups(), policy, {old: '正被進行中的作業使用。'})
        self.assertEqual([c['id'] for c in result['candidates']], [backup_id(3)])
        self.assertEqual(result['blocked'], [{**retention.brief(self.storage.get(old)), 'reason': '正被進行中的作業使用。'}])
        only = retention.plan(self.storage.list_backups(), policy, {}, only_apps={'odoo'})
        self.assertEqual([c['id'] for c in only['candidates']], [backup_id(3)])
        self.assertEqual(retention.plan(self.storage.list_backups(), retention.default_policy(), {})['candidates'], [])


    def test_a_backup_that_failed_verification_does_not_count_toward_n(self):
        # review M1: the newest two failed their deep verification; keep-last 2 keeps the two newest good ones and
        # offers the failed ones for deletion instead of the restorable older backups
        good_old = self.make(1, ['n8n'])
        good = [self.make(n, ['n8n']) for n in (2, 3)]
        bad = [self.make(n, ['n8n']) for n in (4, 5)]
        for bid in bad:
            self.storage.update(bid, verified={'at': '2026-11-14T00:00:00Z', 'ok': False, 'deep': True})
        policy = retention.validate_policy({'apps': {'n8n': {'keep_last': 2}}})
        result = retention.plan(self.storage.list_backups(), policy, {})
        self.assertEqual([c['id'] for c in result['candidates']], [bad[1], bad[0], good_old])
        self.assertIn('驗證未通過', result['candidates'][0]['reason'])
        self.assertNotIn(good[0], [c['id'] for c in result['candidates']])
        self.assertNotIn(good[1], [c['id'] for c in result['candidates']])
        unlimited = retention.validate_policy({'apps': {'n8n': {'keep_last': None}}})
        self.assertEqual(retention.plan(self.storage.list_backups(), unlimited, {})['candidates'], [],
                         'keep everything means everything, failed ones included')


class ProtectionTests(RetentionCase):
    def test_running_jobs_pin_their_backups_and_restores_pin_every_safety_backup(self):
        source = self.make(1, ['odoo'])
        safety_a = self.make(2, ['odoo'], kind='safety')
        safety_b = self.make(3, ['n8n'], kind='safety')
        verified = self.make(4, ['n8n'])
        self.job('verify', {'backup_id': verified}, 'running')
        self.assertEqual(retention.protected_backups(self.paths, self.storage.list_backups()),
                         {verified: '正被進行中的作業使用。'})
        self.job('restore', {'backup_id': source, 'apps': ['odoo']}, 'queued', safety_backup_id=safety_a)
        protected = retention.protected_backups(self.paths, self.storage.list_backups())
        self.assertEqual(set(protected), {verified, source, safety_a, safety_b})
        self.assertIn('還原前備份', protected[safety_a])

    def test_failed_restores_pin_their_safety_and_source_until_a_later_success(self):
        source = self.make(1, ['odoo'])
        safety = self.make(2, ['odoo'], kind='safety')
        rolled = self.make(3, ['n8n'], kind='safety')
        self.job('restore', {'backup_id': source, 'apps': ['odoo']}, 'failed',
                 result={'safety_backup_id': safety, 'rolled_back': False})
        self.job('restore', {'backup_id': source, 'apps': ['n8n']}, 'rolled-back',
                 result={'safety_backup_id': rolled, 'rolled_back': True})
        protected = retention.protected_backups(self.paths, self.storage.list_backups())
        self.assertEqual(set(protected), {source, safety})
        self.assertIn('失敗或中斷的還原', protected[safety])
        self.job('restore', {'backup_id': source, 'apps': ['odoo']}, 'succeeded')
        self.assertEqual(retention.protected_backups(self.paths, self.storage.list_backups()), {})

    def test_a_failed_restore_without_a_safety_backup_pins_its_source(self):
        # review M2: allow_no_safety (or restoring a safety backup) changed the app and failed: the source backup is
        # the only way back until a later restore of the app succeeds
        source = self.make(1, ['odoo'])
        other = self.make(2, ['n8n'])
        self.job('restore', {'backup_id': source, 'apps': ['odoo'], 'allow_no_safety': True}, 'failed',
                 result={'safety_backup_id': None, 'changed': True, 'rolled_back': False})
        self.job('restore', {'backup_id': other, 'apps': ['n8n']}, 'failed',
                 result={'safety_backup_id': None, 'changed': False, 'rolled_back': False})
        protected = retention.protected_backups(self.paths, self.storage.list_backups())
        self.assertEqual(set(protected), {source}, 'a restore refused before any change pins nothing')
        killed = self.make(3, ['litellm'])
        self.job('restore', {'backup_id': killed, 'apps': ['litellm']}, 'interrupted',
                 phases=[{'id': 'safety', 'state': 'skipped'}, {'id': 'stop', 'state': 'done'}])
        self.assertIn(killed, retention.protected_backups(self.paths, self.storage.list_backups()))
        self.job('restore', {'backup_id': source, 'apps': ['odoo']}, 'succeeded')
        self.assertEqual(set(retention.protected_backups(self.paths, self.storage.list_backups())), {killed})
        pinned = jobs.pinned_safety_records(jobs.JobStore(self.paths).list(limit=None))
        self.assertEqual(list(pinned.values()), [None], 'no safety backup, but the record is pinned (kept)')

    def test_a_restore_whose_pre_restore_copy_was_not_packaged_pins_its_source(self):
        # 2026.11.14.2: like a changed failed restore, whatever its state, until a later restore of the app succeeded
        source = self.make(1, ['odoo'])
        other = self.make(2, ['n8n'])
        self.job('restore', {'backup_id': source, 'apps': ['odoo']}, 'succeeded',
                 safety_pending_failed={'path': '/var/lib/woowtech-backup/pending/j1', 'message': '空間不足'})
        self.job('restore', {'backup_id': other, 'apps': ['n8n']}, 'rolled-back', safety_pending=True,
                 result={'safety_backup_id': None, 'rolled_back': True})
        protected = retention.protected_backups(self.paths, self.storage.list_backups())
        self.assertEqual(set(protected), {source, other})
        self.assertIn('還原前資料尚未封裝成還原前備份', protected[source])
        self.job('restore', {'backup_id': source, 'apps': ['odoo']}, 'succeeded')
        self.assertEqual(set(retention.protected_backups(self.paths, self.storage.list_backups())), {other})

    def test_a_damaged_record_protects_everything(self):
        # review F11: JobStore.list skips a record it cannot read; that record may be a failed restore's pin
        first = self.make(1, ['odoo'])
        second = self.make(2, ['n8n'])
        jobs.JobStore(self.paths).ensure()
        Path(self.paths.jobs, 'j20261114T000000Z-0000abcd.json').write_bytes(b'{not json')
        protected = retention.protected_backups(self.paths, self.storage.list_backups())
        self.assertEqual(set(protected), {first, second})
        self.assertEqual(set(protected.values()), {'無法讀取作業紀錄，暫不刪除。'})

    def test_unreadable_records_protect_everything(self):
        bid = self.make(1, ['odoo'])
        original = jobs.JobStore.list

        def broken(self, limit=50):
            raise OSError('boom')
        jobs.JobStore.list = broken
        try:
            protected = retention.protected_backups(self.paths, self.storage.list_backups())
        finally:
            jobs.JobStore.list = original
        self.assertEqual(list(protected), [bid])


class CommandTests(RetentionCase):
    def test_plan_command_reports_usage_policy_and_candidates(self):
        for n in range(1, 4):
            self.make(n, ['odoo'])
        pinned = self.make(4, ['odoo'], kind='safety')
        self.job('restore', {'backup_id': backup_id(1), 'apps': ['odoo']}, 'interrupted',
                 result={'safety_backup_id': pinned, 'rolled_back': False})
        result = retention.plan_command(self.paths, self.storage, None, {'apps': {'odoo': {'keep_last': 1}}},
                                        trusted_uid=self.uid)
        self.assertTrue(result['proposed'])
        self.assertEqual(result['saved_policy'], retention.default_policy())
        self.assertEqual([c['id'] for c in result['candidates']], [backup_id(2)])
        self.assertEqual([b['id'] for b in result['blocked']], [backup_id(1)])
        self.assertEqual({p['id'] for p in result['protected']}, {backup_id(1), pinned})
        self.assertEqual(result['usage']['apps'][0]['types'], {'manual': 3, 'safety': 1, 'uploaded': 0})
        saved = retention.plan_command(self.paths, self.storage, None, trusted_uid=self.uid)
        self.assertEqual((saved['proposed'], saved['candidates']), (False, []))
        with self.assertRaises(BackupError):
            retention.plan_command(self.paths, self.storage, None, {'apps': {'odoo': {'keep_last': -1}}},
                                   trusted_uid=self.uid)

    def test_apply_deletes_only_confirmed_unprotected_backups_and_saves_the_policy(self):
        keep = self.make(1, ['odoo'])
        gone = self.make(2, ['odoo'], size=2048)
        busy = self.make(3, ['odoo'])
        self.job('verify', {'backup_id': busy}, 'running')
        missing = backup_id(99)
        result = retention.apply_command(self.paths, self.storage, [gone, busy, missing],
                                         policy={'apps': {'odoo': {'keep_last': 1}}}, trusted_uid=self.uid,
                                         audit=self.audit.append)
        self.assertEqual([d['id'] for d in result['deleted']], [gone])
        self.assertEqual(result['freed_bytes'], 2048)
        self.assertEqual({s['id']: s['reason'] for s in result['skipped']},
                         {busy: '正被進行中的作業使用。', missing: '找不到這份備份（可能已被刪除）。'})
        self.assertEqual(self.ids(), {keep, busy})
        self.assertEqual(result['policy']['apps'], {'odoo': {'keep_last': 1}})
        self.assertTrue(self.audit[0].startswith('retention-policy default=None apps={"odoo":{"keep_last":1}}'))
        self.assertTrue(self.audit[1].startswith(f'retention-delete backup={gone} type=manual size=2048 apps=odoo'))
        for bad in ('x', [gone, gone], ['bad'], [None], [backup_id(n) for n in range(retention.MAX_IDS + 1)]):
            with self.assertRaises(BackupError):
                retention.apply_command(self.paths, self.storage, bad, trusted_uid=self.uid, audit=self.audit.append)
        with self.assertRaises(BackupError):
            retention.apply_command(self.paths, self.storage, [], policy={'apps': {'odoo': {'keep_last': 0}}},
                                    trusted_uid=self.uid, audit=self.audit.append)
        self.assertEqual(self.ids(), {keep, busy})

    def test_enforce_after_a_manual_backup(self):
        for n in range(1, 5):
            self.make(n, ['odoo'])
        for n in range(5, 8):
            self.make(n, ['n8n'])
        newest = self.make(8, ['odoo'])
        self.assertEqual(retention.enforce_after_backup(self.paths, self.storage, ['odoo'], exclude=[newest],
                                                        log=self.logs.append, audit=self.audit.append,
                                                        trusted_uid=self.uid), [])  # no policy: keep everything
        self.save({'default_keep_last': 2, 'apps': {}})
        deleted = retention.enforce_after_backup(self.paths, self.storage, ['odoo'], exclude=[newest],
                                                 log=self.logs.append, audit=self.audit.append, trusted_uid=self.uid)
        self.assertEqual(deleted, [backup_id(3), backup_id(2), backup_id(1)])
        self.assertEqual(self.ids(), {backup_id(4), newest} | {backup_id(n) for n in range(5, 8)})  # n8n untouched
        self.assertTrue(self.logs[-1].startswith(f'已依保留原則刪除較舊的手動備份 {backup_id(1)}'))
        self.assertTrue(all(line.endswith('reason=policy') for line in self.audit))
        (Path(self.paths.config) / 'retention.json').write_text('not json')
        self.assertEqual(retention.enforce_after_backup(self.paths, self.storage, ['n8n'], log=self.logs.append,
                                                        audit=self.audit.append, trusted_uid=self.uid), [])
        self.assertTrue(self.logs[-1].startswith('警告：'))


if __name__ == '__main__':
    unittest.main()
