"""The public PRESERVATION_BLOCKER is gone (owner decision 2026-11-23): the check and the conversion enforce the
protections themselves (test_ha_emqx_product.py). What stays here: no blanket blocker hides the real ones."""
import unittest
from types import SimpleNamespace

from woowbackup import ha_emqx


class PreservationGuardTests(unittest.TestCase):
    def source(self, state='stopped'):
        return SimpleNamespace(hocon="", plugins=set(), addon=SimpleNamespace(state=state))

    def test_the_blanket_guard_is_gone(self):
        self.assertFalse(hasattr(ha_emqx, 'PRESERVATION_BLOCKER'))
        blockers, warnings = ha_emqx.analyse(self.source(), None, addon_version="5.9.1", version="5.8.9")
        self.assertEqual((blockers, warnings), ([], []))

    def test_the_real_blockers_still_come(self):
        blockers, _ = ha_emqx.analyse(self.source(), None, addon_version="5.9.1", version="5.9.0")
        self.assertEqual(len(blockers), 1)
        self.assertIn('5.8.9', blockers[0])
        _, warnings = ha_emqx.analyse(self.source('started'), None, addon_version="5.9.1", version="5.8.9")
        self.assertTrue(any('執行中製作' in w for w in warnings), 'the hot-backup hint stays')
