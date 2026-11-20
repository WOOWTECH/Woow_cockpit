"""Offline fail-closed checks for the dev-d acceptance driver."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

DRIVER = Path(__file__).with_name("ha_import_b1_e2e.py")


class DriverGuardTests(unittest.TestCase):
    def invoke(self, *args):
        with tempfile.TemporaryDirectory() as home:
            env = {**os.environ, "HOME": home}
            result = subprocess.run(
                [sys.executable, "-I", str(DRIVER), *args],
                env=env, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(list(Path(home).iterdir()), [], "offline invocation wrote to HOME")
            return result

    def test_self_check_compiles_embedded_programs(self):
        result = self.invoke("--self-check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("11 embedded Python programs compiled", result.stdout)

    def test_real_entry_points_fail_closed(self):
        # Keep this guard until outbound denial has been verified from nested
        # services and dynamically issued credentials are collected for scans.
        for args in ((), ("upload",), ("cleanup",), ("credentials",), ("runner",), ("--deploy", "/nonexistent", "--src", "/nonexistent")):
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("real lab runs disabled", result.stderr)


if __name__ == "__main__":
    unittest.main()
