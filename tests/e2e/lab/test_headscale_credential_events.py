"""Local protocol and redaction tests; never access dev-d."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

PATH = Path(__file__).with_name('headscale-credential-events.py')
spec = importlib.util.spec_from_file_location('headscale_events', PATH)
events = importlib.util.module_from_spec(spec)
spec.loader.exec_module(events)

PRODUCER = r'''
import json,os,sys
fd=int(os.environ['HEADSCALE_EVENT_FD'])
def emit(obj):
 os.write(fd,(json.dumps(obj)+'\n').encode()); assert os.read(fd,3)==b'OK\n'
names=__import__('json').loads(os.environ['TEST_HEADSCALE_SOURCES'])
auth=['source_api','client_a_preauth','client_b_preauth','target_api']
values=['synthetic-secret-'+n for n in names]
for name,value in zip(names,values):
 if os.environ.get('OMIT')==name: continue
 if os.environ.get('EMPTY')==name: value=''
 emit({'source':name, 'credential' if name in auth else 'credentials': value if name in auth else [value]})
 if name == 'source_api': print('before evidence: '+value,flush=True)
for name in ['source_server','target_initial','target_converted','client_a','client_b']:
 if os.environ.get('OMIT_LOG')==name: continue
 emit({'source':name,'log': 'issued '+values[1] if os.environ.get('LEAK_LOG')==name else 'safe log'})
print(json.dumps({'evidence':values[names.index('target_api')]}),flush=True)
'''


class CredentialEventsTest(unittest.TestCase):
    def run_with(self, **overrides):
        env = dict(os.environ, TEST_HEADSCALE_SOURCES=json.dumps(events.EXPECTED), **overrides)
        with mock.patch.dict(os.environ, env, clear=True):
            return events.run([sys.executable, '-c', PRODUCER], timeout=5)

    def test_complete_stream_registers_before_output_and_masks_evidence(self):
        output = self.run_with()
        self.assertIn('<source_api>', output)
        self.assertIn('<target_api>', output)
        self.assertNotIn('synthetic-secret-source_api', output)
        self.assertNotIn('synthetic-secret-target_api', output)

    def test_each_missing_or_empty_source_fails(self):
        for source in events.EXPECTED:
            for mode in ('OMIT', 'EMPTY'):
                with self.subTest(source=source, mode=mode), self.assertRaises(Exception):
                    self.run_with(**{mode: source})

    def test_missing_log_or_secret_in_log_fails(self):
        for source in events.LOGS:
            with self.subTest(source=source), self.assertRaises(Exception):
                self.run_with(OMIT_LOG=source)
        with self.assertRaises(Exception):
            self.run_with(LEAK_LOG='source_server')

    def test_controller_suppresses_failure_output(self):
        env = dict(os.environ, OMIT='target_api', TEST_HEADSCALE_SOURCES=json.dumps(events.EXPECTED))
        result = subprocess.run([sys.executable, str(PATH), '--controller', '--', sys.executable, '-c', PRODUCER],
                                env=env, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(b'synthetic-secret-source_api', result.stderr)

    def test_raw_and_json_escaped_forms_are_scanned(self):
        values = ['synthetic-"\\\n-key']
        needles = events.scan_needles(values)
        self.assertIn(values[0].encode(), needles)
        self.assertIn(json.dumps(values[0])[1:-1].encode(), needles)

    def test_actual_register_helper_uses_private_acknowledged_pipe(self):
        producer = r'''
import os,subprocess,sys
path=sys.argv[1]
import json
for source in json.loads(os.environ['TEST_HEADSCALE_SOURCES']):
 value='synthetic-secret-'+source
 private=source not in ['source_api','client_a_preauth','client_b_preauth','target_api']
 subprocess.run([sys.executable,path,'--register-private' if private else '--register',source], input=(json.dumps([value]) if private else value).encode(),
                pass_fds=(int(os.environ['HEADSCALE_EVENT_FD']),),check=True)
for source in ['source_server','target_initial','target_converted','client_a','client_b']:
 subprocess.run([sys.executable,path,'--scan-log',source],input=b'safe log',
                pass_fds=(int(os.environ['HEADSCALE_EVENT_FD']),),check=True)
print('checked synthetic-secret-source_api')
'''
        with mock.patch.dict(os.environ, TEST_HEADSCALE_SOURCES=json.dumps(events.EXPECTED)):
            output = events.run([sys.executable, '-c', producer, str(PATH)], timeout=10)
        self.assertIn('<source_api>', output)
        self.assertNotIn('synthetic-secret-source_api', output)

    def test_bash_pipeline_inherits_private_event_channel(self):
        commands = ['set -euo pipefail']
        for name in events.EXPECTED:
            flag = '--register' if name in events.AUTH_SOURCES else '--register-private'
            value = 'synthetic-secret-' + name if name in events.AUTH_SOURCES else '["synthetic-secret-' + name + '"]'
            commands.append("printf '%s' '" + value + "' | python3 \"$1\" " + flag + ' ' + name)
        for name in events.LOGS:
            commands.append("printf '%s' safe-log | python3 \"$1\" --scan-log " + name)
        output = events.run(['bash', '-c', '\n'.join(commands), 'test', str(PATH)], timeout=10)
        self.assertEqual(output, '')

    def test_producer_failure_and_timeout_suppress_partial_secret(self):
        for suffix in ('raise RuntimeError("private data")', 'import time; time.sleep(5)'):
            script = PRODUCER.replace("print(json.dumps({'evidence':values[names.index('target_api')]}),flush=True)", suffix)
            with self.subTest(suffix=suffix):
                result = subprocess.run([sys.executable, str(PATH), '--controller', '--', sys.executable, '-c', script],
                    env=dict(os.environ, TEST_HEADSCALE_SOURCES=json.dumps(events.EXPECTED)), capture_output=True, timeout=8) if 'sleep' not in suffix else None
                if result:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b'')
                    self.assertNotIn(b'private data', result.stderr)
                else:
                    with mock.patch.dict(os.environ, TEST_HEADSCALE_SOURCES=json.dumps(events.EXPECTED)):
                        with self.assertRaises(Exception):
                            events.run([sys.executable, '-c', script], timeout=0.5)

    def test_real_bash_exit_cleanup_runs_on_timeout_and_protocol_error(self):
        for mode in ('timeout', 'protocol'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / 'cleaned'
                # Flood the pipe in EXIT: controller must drain and discard it,
                # or the shell blocks before it can create the marker.
                script = r'''
trap 'python3 -c "print(\"private-output\" * 20000)"; : > "$1"' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
if [[ "$2" == protocol ]]; then printf 'not-json\n' >&"$HEADSCALE_EVENT_FD"; fi
while :; do sleep 5; done
'''
                with self.assertRaisesRegex(events.CleanupUnverified, 'cleanup unverified'):
                    events.run(['bash', '-c', script, 'test', str(marker), mode], timeout=1)
                self.assertTrue(marker.is_file(), 'Bash EXIT cleanup did not complete')

    def test_forced_kill_reports_cleanup_unverified(self):
        script = "trap '' TERM; while :; do sleep 5; done"
        start = time.monotonic()
        with mock.patch.object(events, 'CLEANUP_GRACE', 0.3):
            with self.assertRaisesRegex(events.CleanupUnverified, 'forced termination'):
                events.run(['bash', '-c', script], timeout=0.5)
        self.assertLess(time.monotonic() - start, 5)

    def test_failed_acceptance_reports_only_fixed_outcomes_not_raw_output(self):
        script = "printf 'AUTO_RECONNECT=FAIL\\nAUTO_ELAPSED_SECONDS=71\\nAUTO_ATTEMPTS=3\\nMANUAL_RECOVERY=PASS\\nprivate-secret-value\\n'; exit 1"
        result = subprocess.run([sys.executable, str(PATH), '--controller', '--', 'bash', '-c', script],
                                capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'AUTO_RECONNECT=FAIL', result.stderr)
        self.assertIn(b'MANUAL_RECOVERY=PASS', result.stderr)
        self.assertIn(b'AUTO_ELAPSED_SECONDS=71', result.stderr)
        self.assertIn(b'cleanup unverified', result.stderr)
        self.assertNotIn(b'private-secret-value', result.stderr)


if __name__ == '__main__':
    unittest.main()
