"""Entry-boundary tests; no device mutation or credentials."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ha_driver', Path(__file__).with_name('ha_import_e2e.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class IsolationTests(unittest.TestCase):
    def test_rejects_before_secrets_or_state(self):
        for output, code in [(b'false none {}', 0), (b'true slirp4netns {}', 0),
                             (b'true none {"9090/tcp":[]}', 0), (b'true none {}', 1),
                             (b'', 0)]:
            with self.subTest(output=output, code=code), patch.object(driver.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], code, output, b'')), \
                    patch.object(driver.sys, 'argv', ['driver', 'restore']), \
                    patch.object(driver, 'Secrets') as secrets, \
                    patch.object(driver, 'load_state') as state:
                with self.assertRaises(SystemExit) as caught:
                    driver.main()
                self.assertEqual(caught.exception.code, 2)
                secrets.assert_not_called()
                state.assert_not_called()

    def test_accepts_exact_isolation(self):
        with patch.object(driver.subprocess, 'run', return_value=
                          subprocess.CompletedProcess([], 0, b'true none {}\n', b'')) as run:
            driver.require_isolated_device()
        self.assertEqual(run.call_args.args[0][:4], [driver.LP, 'container', 'inspect', driver.DEVICE])

    def test_timeout_is_closed(self):
        with patch.object(driver.subprocess, 'run', side_effect=subprocess.TimeoutExpired('inspect', 30)):
            with self.assertRaises(driver.Failed):
                driver.require_isolated_device()
