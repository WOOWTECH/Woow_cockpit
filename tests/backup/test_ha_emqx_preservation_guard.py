"""Regression guard until target EMQX settings and ACL preservation is implemented."""
import unittest
from types import SimpleNamespace

from woowbackup import ha_emqx
from woowbackup.errors import BackupError


class PreservationGuardTests(unittest.TestCase):
    def test_check_reports_blocker(self):
        source = SimpleNamespace(hocon="", plugins=set(), addon=SimpleNamespace(state="stopped"))
        blockers, _ = ha_emqx.analyse(source, None, addon_version="5.9.1", version="5.8.9")
        self.assertIn(ha_emqx.PRESERVATION_BLOCKER, blockers)

    def test_convert_refuses_before_any_work(self):
        with self.assertRaises(BackupError) as caught:
            ha_emqx.convert(None, SimpleNamespace(id="emqx"), False, None)
        self.assertEqual(caught.exception.code, "incompatible")
        self.assertEqual(caught.exception.message, ha_emqx.PRESERVATION_BLOCKER)
