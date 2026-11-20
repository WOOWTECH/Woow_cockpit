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
