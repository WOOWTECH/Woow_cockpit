"""Job-log redaction of Home Assistant backup keys (jobs.redact, mask_secret, masked; CONTRACT section 8), team E2.

The HA key shape is masked everywhere (also by job-status, which never saw the key); the exact key a running job uses is
masked too, whatever its shape (older HA backups may use any password)."""
import json
import tempfile
import unittest
from pathlib import Path

from woowbackup import jobs
from woowbackup.paths import Paths


class RedactionTests(unittest.TestCase):
    def tearDown(self):
        jobs._MASK_COUNTS.clear()
        jobs._MASKED = ()

    def test_ha_key_pattern(self):
        key = 'ABCD-EFGH-JKLM-NPQR-STUV-WXY2-3456'
        self.assertEqual(jobs.redact(f'key={key}, again {key}.'), 'key=[已遮蔽], again [已遮蔽].')
        self.assertEqual(jobs.redact('AGE-SECRET-KEY-1QQQQ and ' + key), '[已遮蔽] and [已遮蔽]')
        for kept in ('金鑰 ABCD-EF01-2345-6789', 'job j20261118T090120Z-0123abcd', 'backup 20261118T090120Z-0123abcd',
                     'ABCD-EFGH-JKLM-NPQR-STUV-WXY2', 'uuid 12345678-1234-1234-1234-123456789abc'):
            with self.subTest(text=kept):
                self.assertEqual(jobs.redact(kept), kept)

    def test_the_exact_key_of_a_running_job(self):
        password = 'my old HA password'
        self.assertEqual(jobs.redact(f'x {password} y'), f'x {password} y')
        with jobs.masked(password):
            self.assertEqual(jobs.redact(f'x {password} y'), 'x [已遮蔽] y')
            with jobs.masked(password):
                pass
            self.assertEqual(jobs.redact(password), '[已遮蔽]', 'nested users of the same key')
        self.assertEqual(jobs.redact(password), password)
        jobs.mask_secret('  padded key  ')
        self.assertEqual(jobs.redact('a padded key b'), 'a [已遮蔽] b', 'the stripped form too')
        jobs.unmask_secret('  padded key  ')
        self.assertEqual(jobs.redact('padded key'), 'padded key')
        jobs.mask_secret(None)
        jobs.mask_secret('')
        self.assertEqual(jobs._MASKED, ())

    def test_logs_progress_and_errors_are_masked(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = Paths(base=Path(tmp))
            store = jobs.JobStore(paths)
            record = store.create('verify', {'source': 'ha'}, request_id='req-ha-000002')
            reporter = jobs.JobReporter(store, record)
            secret = 'not-an-ha-shaped-password'
            with jobs.masked(secret):
                reporter.log(f'檢查 {secret} ABCD-EFGH-JKLM-NPQR-STUV-WXY2-3456')
                reporter.progress(10, f'進度 {secret}', force=True)
                reporter.finish('failed', error={'code': 'wrong-key', 'message': f'金鑰 {secret} 錯誤'})
            saved = json.dumps(store.get(record['id']), ensure_ascii=False)
            log = '\n'.join(store.read_log(record['id']))
            for text in (saved, log):
                self.assertNotIn(secret, text)
                self.assertNotIn('WXY2-3456', text)
            self.assertIn('[已遮蔽]', log)


if __name__ == '__main__':
    unittest.main()
