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

from woowbackup import cli, haimport, jobs
from woowbackup.haissues import Issue

from .test_flows import FakeAdapter, FlowCase, ha_registry_row

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

    def test_an_ordinary_backup_is_not_asked(self):
        got = self.call(['restore-start'], self.request())
        self.assertNotIn('error', got)
        self.assertNotIn('acknowledged', self.params(got['job_id']))


if __name__ == '__main__':
    unittest.main()
