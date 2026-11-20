"""Focused tests of EMQX target authentication read failures."""
import unittest
from unittest import mock
from woowbackup import ha_emqx
from woowbackup.errors import BackupError
from woowbackup.podman import Result
from .test_ha_emqx import counts_text


class TargetAuthenticationGuardTests(unittest.TestCase):
    def run_target(self, initial, after):
        work, tmp, target = mock.Mock(), mock.Mock(), mock.Mock()
        target.files, target.env, target.secrets = [], {}, []
        counts = counts_text({name: 0 for name in ha_emqx.TABLES}).decode()
        self.assertEqual(len(ha_emqx.parse_counts(counts)), len(ha_emqx.TABLES))
        self.assertEqual(ha_emqx.parse_strict("{deny,ignore}"), ("deny", "ignore"))
        values = [counts, "{deny,ignore}", initial, "{deny,ignore}", after, counts]
        ctl = mock.Mock(return_value=Result(0, b"data imported successfully", b""))
        with mock.patch.object(ha_emqx, "wait_ready"), mock.patch.object(ha_emqx, "evaluate", side_effect=values), mock.patch.object(ha_emqx, "ctl", ctl):
            try:
                result = ha_emqx.target_broker(work, tmp, target, "/tmp/input.tar.gz", (1000, 1000))
                return result, ctl
            except BackupError as error:
                return error, ctl

    def test_empty_before_import_refused(self):
        error, ctl = self.run_target("[]", "[]")
        self.assertIsInstance(error, BackupError)
        ctl.assert_not_called()

    def test_empty_after_import_refused(self):
        error, ctl = self.run_target("[{password_based,built_in_database,true,sha256,suffix}]", "[]")
        self.assertIsInstance(error, BackupError)
        self.assertIn("匯入後", error.message)
        self.assertTrue(ctl.called)

    def test_valid_authentication_passes_control(self):
        auth = "[{password_based,built_in_database,true,sha256,suffix}]"
        result, ctl = self.run_target(auth, auth)
        self.assertIsInstance(result, tuple)
        self.assertTrue(ctl.called)


if __name__ == "__main__":
    unittest.main()
