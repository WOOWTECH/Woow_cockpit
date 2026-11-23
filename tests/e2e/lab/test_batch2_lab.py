"""Offline checks of the dev-e (HA import batch 2) lab definition: no labpodman, no device, no network.

    PYTHONPATH=backup-engine:tests/e2e/lab python3 -m unittest tests/e2e/lab/test_batch2_lab.py
"""
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def device_vars(dev):
    """Source lib.sh with a stand-in labpodman and print what device_vars sets."""
    with tempfile.TemporaryDirectory() as lab:
        lp = Path(lab, 'bin', 'labpodman')
        lp.parent.mkdir()
        lp.write_text('#!/bin/sh\nexit 1\n')
        lp.chmod(0o755)
        script = (f'source {HERE / "lib.sh"}; device_vars {dev}; '
                  'echo "$DEV|$NAME|$PORT|$OWNER_UID|$DEVICE_MEMORY|$DEVICE_CPUS|$DEVICE_NETWORK|${DEVICE_RUN_ARGS[*]}|${VOLUMES[*]}"')
        proc = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                              env=dict(os.environ, WOOWBK_LAB_HOME=lab), timeout=30)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


class DeviceVarsTest(unittest.TestCase):
    def test_dev_e_is_network_none_without_a_port(self):
        rc, out, _ = device_vars('e')
        self.assertEqual(rc, 0)
        self.assertEqual(out, 'e|woowbk-dev-e||1025|3g|2|none||'
                              'woowbk-dev-e-home woowbk-dev-e-varlib woowbk-dev-e-containers')

    def test_other_devices_keep_their_settings(self):
        self.assertEqual(device_vars('d')[1], 'd|woowbk-dev-d|19094|1019|4g|2|||'
                                              'woowbk-dev-d-home woowbk-dev-d-varlib woowbk-dev-d-containers')
        self.assertEqual(device_vars('c')[1].split('|')[:8],
                         ['c', 'woowbk-dev-c', '19093', '1013', '3g', '2', '', '--add-host jcr-prod.woowtech.io:127.0.0.1'])
        self.assertEqual(device_vars('a')[1].split('|')[:7], ['a', 'woowbk-dev-a', '19091', '1001', '768m', '1.5', ''])

    def test_unknown_device_is_refused(self):
        rc, _, err = device_vars('f')
        self.assertNotEqual(rc, 0)
        self.assertIn("'a', 'b', 'c', 'd' or 'e'", err)


class CompareMaskTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('compare_batch2_src', HERE / 'compare_batch2.py')
        source = (HERE / 'compare_batch2.py').read_text()
        # Only the helpers: the module body below the definitions talks to labpodman.
        cls.ns = {}
        exec(compile(source.split('\napps = ')[0], str(spec.origin), 'exec'), cls.ns)

    def test_secret_like_lines_are_masked(self):
        masked = self.ns['masked']
        self.assertEqual(masked('+Environment=SMTP_PASSWORD=abc'), '+Environment=<masked>')
        self.assertEqual(masked('-ANTHROPIC_API_KEY=sk-123'), '-ANTHROPIC_API_KEY=<masked>')
        self.assertEqual(masked('+Secret=nextcloud-db-password,type=env,target=POSTGRES_PASSWORD'),
                         '+Secret=nextcloud-db-password,type=env,target=POSTGRES_PASSWORD')
        self.assertEqual(masked('+Image=docker.io/library/nginx:1.30.4-alpine'), '+Image=docker.io/library/nginx:1.30.4-alpine')

    def test_env_values_shown_only_for_tuning_keys(self):
        safe, secretish = self.ns['SAFE_KEYS'], self.ns['SECRETISH']
        shown = [k for k in ('HOST_BIND', 'PHP_MEMORY_LIMIT', 'HOST_DATA_DIR', 'WOOW_OD_MEMORY', 'NEXTCLOUD_PUBLIC_URL',
                             'OD_ALLOWED_ORIGINS', 'SMTP_PASSWORD', 'OPENAI_API_KEY', 'NEXTCLOUD_TRUSTED_DOMAINS')
                 if safe.search(k) and not secretish.search(k.replace('WOOW_OD_AUTH', ''))]
        self.assertEqual(shown, ['HOST_BIND', 'PHP_MEMORY_LIMIT', 'HOST_DATA_DIR', 'WOOW_OD_MEMORY'])


class Batch2ScriptsTest(unittest.TestCase):
    def test_shell_scripts_parse(self):
        for name in ('deploy-batch2.sh', 'lib.sh', 'up.sh', 'down.sh', 'status.sh', 'owner.sh', 'verify-device.sh',
                     'deploy-src.sh'):
            proc = subprocess.run(['bash', '-n', str(HERE / name)], capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, f'{name}: {proc.stderr}')

    def test_deploy_batch2_pins_the_production_commits_and_never_pulls(self):
        text = (HERE / 'deploy-batch2.sh').read_text()
        self.assertIn('declare -A REV=([nextcloud]=19a7609 [code-server]=e7dbbea [opendesign]=1067bc4)', text)
        self.assertNotIn('podman pull', text)
        self.assertIn('RD_SHA256=0639ab0e3413142a76334af20ca88cba0a351a11c9c07effa0f1eb7f05941f2c', text)
        self.assertIn('FLOOR_GIB=12', text)


if __name__ == '__main__':
    unittest.main()
