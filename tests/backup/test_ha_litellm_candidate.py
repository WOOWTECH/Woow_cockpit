"""Restricted LiteLLM preflight: real tar parser, synthetic data only."""
import io
import json
import unittest
from unittest.mock import Mock

from woowbackup import ha_litellm_candidate as candidate, haapps
from woowbackup.errors import BackupError
from . import hafixtures


class LiteLLMCandidateTests(unittest.TestCase):
    def member(self, *, addon='0.1.15', version='1.104.0', pg=b'18\n', salt=b'sk-0123456789abcdef0123456789abcdef',
               control=b'pgcontrol', salt_kind='file'):
        addon_info = {'system': {'slug': 'woow-litellm', 'name': 'LiteLLM'}, 'version': addon,
                      'user': {'image': 'ghcr.io/woowtech/woow-ha-litellm-amd64'}}
        entries = [{'name': 'addon.json', 'data': json.dumps(addon_info).encode()}]
        if version is not None:
            entries.append({'name': candidate.STATE, 'data': json.dumps({'litellm_version': version}).encode()})
        if pg is not None:
            entries.append({'name': candidate.PG_VERSION, 'data': pg})
        if control is not None:
            entries.append({'name': candidate.PG_CONTROL, 'data': control})
        if salt is not None:
            if salt_kind == 'file':
                entries.append({'name': candidate.SALT, 'data': salt})
            else:
                entries.append({'name': candidate.SALT, 'type': 'symlink', 'linkname': 'elsewhere'})
        return io.BytesIO(hafixtures.tar_bytes(entries))

    def test_complete_source_still_blocked_without_claiming_db_key_verified(self):
        secret = b'sk-0123456789abcdef0123456789abcdef'
        source = candidate.scan_member(self.member(salt=secret))
        self.assertTrue(source.salt_valid)
        result = candidate.assess(source, target_version='1.104.0', target_pg_major=18)
        self.assertEqual(result['blockers'], [candidate.GUARD])
        self.assertIn('尚未驗證', result['warnings'][0])
        self.assertNotIn(secret.decode(), repr((source, result)))

    def test_incompatible_versions_and_downgrade(self):
        source = candidate.scan_member(self.member())
        result = candidate.assess(source, target_version='1.105.0', target_pg_major=17)
        self.assertTrue(any('版本不同' in x for x in result['blockers']))
        self.assertTrue(any('降版' in x for x in result['blockers']))
        source = candidate.scan_member(self.member(addon='0.1.99', version='1.104.0', pg=b'17'))
        self.assertTrue(any('無法確認 HA' in x for x in candidate.assess(source, target_version=None, target_pg_major=None)['blockers']))
        source = candidate.scan_member(self.member(version='1.105.0', pg=b'17'))
        messages = candidate.assess(source, target_version='1.105.0', target_pg_major=17)['blockers']
        self.assertEqual(sum('不一致' in x for x in messages), 2)

    def test_missing_and_malformed_source(self):
        for kwargs in ({'salt': None}, {'salt': b'bad'}, {'salt_kind': 'symlink'},
                       {'pg': None}, {'control': None}, {'control': b''}, {'version': None}):
            with self.subTest(kwargs=kwargs):
                source = candidate.scan_member(self.member(**kwargs))
                messages = candidate.assess(source, target_version='1.104.0', target_pg_major=18)['blockers']
                self.assertGreater(len(messages), 1)

    def test_target_evidence_requires_exact_running_image_identity(self):
        image_id = 'sha256:' + 'a' * 64
        secret = 'SOME_SECRET=never-return-this-value'
        info = {'id': image_id, 'env': ['PG_MAJOR=17', secret]}
        evidence = candidate.target_evidence(running_db_image_id=image_id, inspected_db_image=info)
        self.assertEqual(evidence, {'target_version': None, 'target_pg_major': 17})
        self.assertNotIn(secret, repr(evidence))
        source = candidate.scan_member(self.member())
        messages = candidate.assess_target(source, evidence)['blockers']
        self.assertTrue(any('降版' in item for item in messages))
        self.assertTrue(any('目標 LiteLLM 版本' in item for item in messages))
        self.assertIn(candidate.GUARD, messages)
        for running, image in ((None, info), ('sha256:' + 'b' * 64, info),
                               (image_id, {'id': image_id, 'env': ['PG_MAJOR=17', 'PG_MAJOR=18']}),
                               (image_id, {'id': image_id, 'env': ['PG_MAJOR=17.11']}),
                               (image_id, {'id': image_id, 'env': 'PG_MAJOR=17'})):
            with self.subTest(running=running, image=image):
                facts = candidate.target_evidence(running_db_image_id=running, inspected_db_image=image)
                self.assertIsNone(facts['target_pg_major'])
                self.assertTrue(any('目標 PostgreSQL' in item for item in
                                    candidate.assess_target(source, facts)['blockers']))

    def test_probe_caller_accepts_only_ids_and_feeds_assessment(self):
        app_id = 'sha256:' + 'a' * 64
        pg_id = 'sha256:' + 'b' * 64
        tmp = Mock()
        tmp.run.side_effect = [Mock(stdout=b'1.104.0\n'), Mock(stdout=b'postgres (PostgreSQL) 17.11\n')]
        evidence = candidate.probe_target_images(tmp, running_app_image_id=app_id, running_db_image_id=pg_id)
        self.assertEqual(evidence, {'target_version': '1.104.0', 'target_pg_major': 17})
        for call in tmp.run.call_args_list:
            self.assertTrue(call.kwargs['read_only_root'])
            self.assertNotIn('volumes', call.kwargs)
            self.assertNotIn('secrets', call.kwargs)
            self.assertNotIn('env', call.kwargs)
            self.assertNotIn('network', call.kwargs)
        source = candidate.scan_member(self.member())
        blockers = candidate.assess_target(source, evidence)['blockers']
        self.assertTrue(any('降版' in item for item in blockers))
        self.assertIn(candidate.GUARD, blockers)
        tmp.reset_mock()
        evidence = candidate.probe_target_images(tmp, running_app_image_id='localhost/mutable:tag',
                                                 running_db_image_id=None)
        self.assertEqual(evidence, {'target_version': None, 'target_pg_major': None})
        tmp.run.assert_not_called()

    def test_probe_failures_and_malformed_output_are_unknown(self):
        image_id = 'sha256:' + 'a' * 64
        tmp = Mock()
        tmp.run.side_effect = [BackupError('job-failed', 'fail'), Mock(stdout=b'postgres 17.11')]
        facts = candidate.probe_target_images(tmp, running_app_image_id=image_id, running_db_image_id=image_id)
        self.assertEqual(facts, {'target_version': None, 'target_pg_major': None})

    def test_preservation_contract_is_disabled_and_transfers_no_secrets(self):
        plan = candidate.preservation_contract()
        self.assertEqual(plan['source_salt'], 'unverified_database_binding')
        self.assertEqual(plan['target_credentials'], 'preserve')
        self.assertEqual(plan['target_salt'], 'preserve_until_verified_secret_transfer_exists')
        self.assertEqual(plan['secret_transfer'], 'not_implemented')
        self.assertEqual(plan['rollback'], 'not_implemented')
        self.assertEqual(plan['conversion'], 'disabled')

    def test_no_registry_advertisement_and_conversion_is_guarded(self):
        self.assertNotIn('litellm', haapps.APP_IDS)
        for mode in (False, True):
            work = Mock()
            with self.assertRaises(BackupError) as caught:
                candidate.convert(work, Mock(id='litellm'), mode, Mock())
            self.assertEqual(caught.exception.code, 'incompatible')
            self.assertEqual(work.mock_calls, [])

    def test_duplicate_sensitive_entry_and_truncated_archive_rejected(self):
        duplicate = hafixtures.tar_bytes([
            {'name': 'addon.json', 'data': json.dumps({'system': {'slug': 'woow-litellm'}, 'version': '0.1.15'}).encode()},
            {'name': candidate.SALT, 'data': b'x' * 20}, {'name': candidate.SALT, 'data': b'y' * 20}])
        for data in (duplicate, self.member().getvalue()[:1024]):
            with self.subTest(size=len(data)), self.assertRaises(BackupError):
                candidate.scan_member(io.BytesIO(data))


if __name__ == '__main__':
    unittest.main()
