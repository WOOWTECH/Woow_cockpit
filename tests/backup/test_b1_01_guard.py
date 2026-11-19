"""B1-01: conversion must fail before it can touch any containers or data."""
import unittest
from unittest.mock import Mock

from woowbackup import ha_omnigent
from woowbackup.errors import BackupError


class OmnigentSecurityHoldTest(unittest.TestCase):
    def test_convert_fails_before_any_work_for_both_modes(self):
        for test_mode in (False, True):
            with self.subTest(test_mode=test_mode):
                work = Mock()
                app = Mock(id='omnigent')
                with self.assertRaises(BackupError) as caught:
                    ha_omnigent.convert(work, app, test_mode, Mock())
                self.assertEqual(caught.exception.code, 'incompatible')
                self.assertIn(ha_omnigent.SECURITY_BLOCKER, str(caught.exception))
                work.assert_not_called()
                self.assertEqual(work.mock_calls, [])
