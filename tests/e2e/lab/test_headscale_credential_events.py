"""Local protocol and redaction tests; never access dev-d."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
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
names=['source_api','client_a_preauth','client_b_preauth','target_api']
values=['source-secret-123','first-secret-123','second-secret-123','target-secret-123']
for name,value in zip(names,values):
 if os.environ.get('OMIT')==name: continue
 if os.environ.get('EMPTY')==name: value=''
 emit({'source':name,'credential':value})
 if name == 'source_api': print('before evidence: '+value,flush=True)
for name in ['source_server','target_initial','target_converted','client_a','client_b']:
 if os.environ.get('OMIT_LOG')==name: continue
 emit({'source':name,'log': 'issued '+values[1] if os.environ.get('LEAK_LOG')==name else 'safe log'})
print(json.dumps({'evidence':values[-1]}),flush=True)
'''


class CredentialEventsTest(unittest.TestCase):
    def run_with(self, **overrides):
        env = dict(os.environ, **overrides)
        with mock.patch.dict(os.environ, env, clear=True):
            return events.run([sys.executable, '-c', PRODUCER], timeout=5)

    def test_complete_stream_registers_before_output_and_masks_evidence(self):
        output = self.run_with()
        self.assertIn('<source_api>', output)
        self.assertIn('<target_api>', output)
        self.assertNotIn('source-secret-123', output)
        self.assertNotIn('target-secret-123', output)

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
        env = dict(os.environ, OMIT='target_api')
        result = subprocess.run([sys.executable, str(PATH), '--controller', '--', sys.executable, '-c', PRODUCER],
                                env=env, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(b'source-secret-123', result.stderr)

    def test_raw_and_json_escaped_forms_are_scanned(self):
        values = ['synthetic-"\\\n-key']
        needles = events.scan_needles(values)
        self.assertIn(values[0].encode(), needles)
        self.assertIn(json.dumps(values[0])[1:-1].encode(), needles)

    def test_actual_register_helper_uses_private_acknowledged_pipe(self):
        producer = r'''
import os,subprocess,sys
path=sys.argv[1]
for source,value in [('source_api','source-api-123'),('client_a_preauth','preauth-a-123'),
                     ('client_b_preauth','preauth-b-123'),('target_api','target-api-123')]:
 subprocess.run([sys.executable,path,'--register',source], input=value.encode(),
                pass_fds=(int(os.environ['HEADSCALE_EVENT_FD']),),check=True)
for source in ['source_server','target_initial','target_converted','client_a','client_b']:
 subprocess.run([sys.executable,path,'--scan-log',source],input=b'safe log',
                pass_fds=(int(os.environ['HEADSCALE_EVENT_FD']),),check=True)
print('checked source-api-123')
'''
        output = events.run([sys.executable, '-c', producer, str(PATH)], timeout=10)
        self.assertIn('<source_api>', output)
        self.assertNotIn('source-api-123', output)

    def test_bash_pipeline_inherits_private_event_channel(self):
        commands = ['set -euo pipefail']
        for name in events.EXPECTED:
            commands.append("printf '%s' synthetic-secret-" + name +
                            ' | python3 "$1" --register ' + name)
        for name in events.LOGS:
            commands.append("printf '%s' safe-log | python3 \"$1\" --scan-log " + name)
        output = events.run(['bash', '-c', '\n'.join(commands), 'test', str(PATH)], timeout=10)
        self.assertEqual(output, '')

    def test_producer_failure_and_timeout_suppress_partial_secret(self):
        for suffix in ('raise RuntimeError("private data")', 'import time; time.sleep(5)'):
            script = PRODUCER.replace("print(json.dumps({'evidence':values[-1]}),flush=True)", suffix)
            with self.subTest(suffix=suffix):
                result = subprocess.run([sys.executable, str(PATH), '--controller', '--', sys.executable, '-c', script],
                    env=dict(os.environ), capture_output=True, timeout=8) if 'sleep' not in suffix else None
                if result:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b'')
                    self.assertNotIn(b'private data', result.stderr)
                else:
                    with self.assertRaises(Exception):
                        events.run([sys.executable, '-c', script], timeout=0.5)


if __name__ == '__main__':
    unittest.main()
