"""Focused tests of how the candidate reads the authenticators: an empty list is an answer (HA's own choice, S2), an
answer that is no list is not (E-62, E-81, E-82)."""
import unittest
from unittest import mock
from woowbackup import ha_emqx
from woowbackup.errors import BackupError
from woowbackup.podman import Result
from .test_ha_emqx import counts_text


class TargetAuthenticationGuardTests(unittest.TestCase):
    def run_target(self, initial, after, notes=None):
        work, tmp, target = mock.Mock(), mock.Mock(), mock.Mock()
        target.files, target.env, target.secrets = [], {}, []
        counts = counts_text({name: 0 for name in ha_emqx.TABLES}).decode()
        self.assertEqual(len(ha_emqx.parse_counts(counts)), len(ha_emqx.TABLES))
        self.assertEqual(ha_emqx.parse_strict("{deny,ignore}"), ("deny", "ignore"))
        after = after if isinstance(after, list) else [after]   # a list: what each read of the authenticators answers
        values = ["WOOWSYS:<0.1.0>:suspended\nok", counts, "{deny,ignore}", initial, "ticker_unchanged", "{deny,ignore}", *after, counts, "ticker_unchanged"]
        ctl = mock.Mock(return_value=Result(0, b"data imported successfully", b""))
        with mock.patch.object(ha_emqx, "wait_ready"), mock.patch.object(ha_emqx, "evaluate", side_effect=values), mock.patch.object(ha_emqx, "ctl", ctl), \
                mock.patch.object(ha_emqx, "check_export"):
            try:
                result = ha_emqx.target_broker(work, tmp, target, "/tmp/input.tar.gz", (1000, 1000), notes=notes)
                return result, ctl
            except BackupError as error:
                return error, ctl

    def test_a_device_without_any_authenticator_is_no_failure(self):
        """E-62: this device already allowed anonymous login; the import cannot make it worse and says nothing wrong."""
        notes = {}
        result, ctl = self.run_target("[]", "[]", notes)
        self.assertIsInstance(result, tuple)
        self.assertTrue(ctl.called)
        self.assertEqual((notes['device_authenticated'], notes['anonymous']), (False, True))

    def test_nobody_has_to_log_in_after_the_import_is_hAs_choice_for_the_confirmation(self):
        """E-82 (S2): the import went through; the candidate says nobody has to log in (the customer confirms it)."""
        notes = {}
        result, ctl = self.run_target("[{password_based,built_in_database,true,sha256,suffix}]", "[]", notes)
        self.assertIsInstance(result, tuple)
        self.assertEqual((notes['device_authenticated'], notes['anonymous']), (True, True))

    def test_an_answer_that_is_no_list_is_read_again_and_then_stops_the_app(self):
        """E-81: unreadable is not empty: one more try, then the app stops (the import has been made: nothing is changed)."""
        error, ctl = self.run_target("[{password_based,built_in_database,true,sha256,suffix}]", ["badrpc", "badrpc"])
        self.assertIsInstance(error, BackupError)
        self.assertIn("匯入後", error.message)

    def test_valid_authentication_passes_control(self):
        auth = "[{password_based,built_in_database,true,sha256,suffix}]"
        result, ctl = self.run_target(auth, auth)
        self.assertIsInstance(result, tuple)
        self.assertTrue(ctl.called)


if __name__ == "__main__":
    unittest.main()
