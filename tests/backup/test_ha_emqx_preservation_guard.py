"""The public PRESERVATION_BLOCKER is gone (owner decision 2026-11-23): the check and the conversion enforce the
protections themselves (test_ha_emqx_product.py). What stays here: no blanket blocker hides the real ones, and the reminder
about a backup made while EMQX ran (HOT_HINT) is still said. HAOS parity: the versions only inform (haissues)."""
import unittest
from types import SimpleNamespace

from woowbackup import ha_emqx


class PreservationGuardTests(unittest.TestCase):
    def source(self, state='stopped'):
        return SimpleNamespace(hocon="", plugins=set(), addon=SimpleNamespace(state=state))

    def test_the_blanket_guard_is_gone(self):
        self.assertFalse(hasattr(ha_emqx, 'PRESERVATION_BLOCKER'))
        self.assertFalse(hasattr(ha_emqx, 'acl_blocker'), 'the owner decision 「C」 (HA ACL rows need this device built-in database) is superseded by D0')
        self.assertEqual(ha_emqx.check_warnings(self.source(), None), [])

    def test_the_hot_backup_hint_stays(self):
        warnings = ha_emqx.check_warnings(self.source('started'), None)
        self.assertTrue(any('執行中製作' in w for w in warnings), 'the hot-backup hint stays')

    def test_the_versions_inform_and_both_known_and_different_is_the_one_stop(self):
        found = ha_emqx.VERSIONS.issues('5.9.1', '5.8.9')
        self.assertEqual(found, [])
        different = ha_emqx.VERSIONS.issues('5.9.1', '5.9.0')
        self.assertEqual([(issue.id, issue.level) for issue in different], [('version.different', 'stop')])
        self.assertIn('5.8.9', different[0].message)
        self.assertEqual([(i.id, i.level) for i in ha_emqx.VERSIONS.issues('9.9.9', '5.8.9')],
                         [('version.addon-unknown', 'notice')])
        self.assertEqual([(i.id, i.level) for i in ha_emqx.VERSIONS.issues('5.9.1', None)],
                         [('version.target-unknown', 'notice')])
