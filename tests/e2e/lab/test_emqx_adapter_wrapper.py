"""Execute a copied wrapper against local stand-ins and disposable locks only."""
import fcntl
import json
import os
import re
import shlex
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest


def bundle_entries():
    script = Path(__file__).with_name('run_emqx_adapter_lab.sh').read_text()
    match = re.search(r'\ntar -C "\$REPO_ROOT" -cf - (.*?)\|', script, re.S)
    if match is None:
        raise AssertionError('missing actual wrapper archive command')
    return shlex.split(match[1].replace('\\\n', ' '))


class ExtractedBundleTests(unittest.TestCase):
    def test_actual_archive_imports_capability_closure_without_checkout_fallback(self):
        repository = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory(prefix='generated-adapter-bundle-') as directory:
            root = Path(directory)
            archive = root / 'code.tar'
            extracted = root / 'extracted'
            extracted.mkdir(mode=0o700)
            with archive.open('wb') as output:
                subprocess.run(['/usr/bin/tar', '-C', str(repository), '-cf', '-', *bundle_entries()],
                               stdout=output, stderr=subprocess.PIPE, check=True, timeout=15)
            subprocess.run(['/usr/bin/tar', '-xf', str(archive), '-C', str(extracted)],
                           check=True, capture_output=True, timeout=15)
            source = '''
import importlib, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve()
sys.path[:0] = [str(root / 'backup-engine'), str(root / 'tests/e2e/lab')]
modules = ('emqx_adapter_owner', 'emqx_adapter_driver', 'emqx_owner_fixture_files',
           'emqx_owner_vendor_files', 'emqx_bootstrap_csv', 'emqx_native_runtime',
           'emqx_semantic_readers', 'emqx_target_snapshots', 'emqx_runtime_credentials',
           'emqx_private_boundary', 'emqx_real_candidate', 'ha_real_fixture')
for name in modules:
    module = importlib.import_module(name)
    assert pathlib.Path(module.__file__).resolve().is_relative_to(root)
from emqx_owner_fixture_files import _issue, observe_fixture_files
from emqx_adapter_owner import OwnerProvision
assert callable(_issue) and callable(observe_fixture_files) and callable(OwnerProvision.create)
print('extracted-private-imports-pass')
'''
            args = [sys.executable, '-I', '-B', '-c', source, str(extracted)]
            result = subprocess.run(args, cwd=extracted, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, b'extracted-private-imports-pass\n')
            # Demonstrate no accidental import fallback to the developer checkout.
            (extracted / 'tests/e2e/lab/emqx_bootstrap_csv.py').unlink()
            missing = subprocess.run(args, cwd=extracted, capture_output=True, timeout=15)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn(b'No module named', missing.stderr)


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.lab = self.root / 'tests/e2e/lab'
        self.lab.mkdir(parents=True)
        (self.root / 'backup-engine/woowbackup').mkdir(parents=True)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.trace = self.root / 'trace.jsonl'
        self.locks = [self.root / 'mutation.lock', self.root / 'volume.lock']
        for lock in self.locks:
            lock.write_text('generated-existing-lock\n')
        script = Path(__file__).with_name('run_emqx_adapter_lab.sh').read_text()
        # Substitute before executing: never open or acquire a real shared lock.
        for live, local in zip(('/tmp/woowbk-dev-d-mutation.lock',
                                '/tmp/headscale-dev-d-private-volume.lock'), self.locks):
            self.assertEqual(script.count(live), 1)
            script = script.replace(live, str(local))
        script = script.replace('/tmp/woowbk-emqxcode-', str(self.root / 'woowbk-emqxcode-'))
        self.wrapper = self.lab / 'run_emqx_adapter_lab.sh'
        self.wrapper.write_text(script)
        (self.lab / 'lib.sh').write_text('''set -euo pipefail
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$LAB_DIR/../../.." && pwd)
device_vars() { :; }
die() { echo "$*" >&2; exit 1; }
''')
        self.executable(self.bin / 'git', '#!/bin/sh\ncase "$*" in *rev-parse*) echo generated-commit ;; esac\n')
        self.executable(self.bin / 'tar', '''#!/bin/sh
if [ "${ADAPTER_TEST_TAR_FAILURE:-}" = 1 ] && [ "$1" = -xf ]; then exit 2; fi
exec /usr/bin/tar "$@"
''')
        self.executable(self.lab / 'owner.sh', '''#!/usr/bin/python3
import fcntl, json, os, subprocess, sys
from pathlib import Path
trace = Path(os.environ['ADAPTER_TEST_TRACE'])
args = sys.argv[1:]
assert args[0] == 'd'
with trace.open('a') as f: f.write(json.dumps({'owner': args[1:]})+'\\n')
# Every owner entry must happen with BOTH disposable locks held by wrapper.
for name in ('mutation.lock','volume.lock'):
    with (trace.parent/name).open('r') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: pass
        else: sys.exit(91)
if args[1:] == ['--verify-isolation']:
    count = sum(1 for line in trace.read_text().splitlines()
                if json.loads(line).get('owner') == ['--verify-isolation'])
    sys.exit(1 if count == int(os.environ.get('ADAPTER_TEST_ISOLATION_FAILURE','0')) else 0)
if 'memory.current' in args[-1]:
    print(os.environ.get('ADAPTER_TEST_MEMORY','0 4294967296'))
    sys.exit(0)
sys.exit(subprocess.run(args[1:]).returncode)
''')
        for entry in bundle_entries():
            path = Path(entry)
            if path.parent == Path('tests/e2e/lab') and path.name != 'emqx_adapter_driver.py':
                (self.lab / path.name).write_text('# generated stand-in\n')
        (self.lab / 'emqx_adapter_driver.py').write_text('''import json, os, sys
from pathlib import Path
with open(os.environ['ADAPTER_TEST_TRACE'],'a') as f:
    f.write(json.dumps({'driver':sys.argv[1:],'code':str(Path(__file__).parents[3]),
                        'code_mode':Path(__file__).parents[3].stat().st_mode&0o777})+'\\n')
print('generated-driver-only')
sys.exit(int(os.environ.get('ADAPTER_TEST_DRIVER_EXIT','0')))
''')
        self.env = dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH'],
                        ADAPTER_TEST_TRACE=str(self.trace), PYTHONDONTWRITEBYTECODE='1')
        self.originals = [(lock.stat().st_ino, lock.read_bytes()) for lock in self.locks]

    def executable(self, path, content):
        path.write_text(content)
        path.chmod(0o700)

    def run_wrapper(self, **env):
        result = subprocess.run(['bash',str(self.wrapper)], env=dict(self.env,**env),
                                capture_output=True, timeout=15)
        self.assertEqual(list(self.root.glob('woowbk-emqxcode-*')), [])
        return result

    def events(self):
        return [json.loads(line) for line in self.trace.read_text().splitlines()] if self.trace.exists() else []

    def assert_lock_contents_unchanged(self):
        self.assertEqual([(p.stat().st_ino,p.read_bytes()) for p in self.locks], self.originals)

    def test_success_owner_staging_both_locks_postflight_and_owned_cleanup(self):
        sentinel = self.root / 'unrelated'
        sentinel.write_text('preserve')
        result = self.run_wrapper()
        self.assertEqual(result.returncode,0,result.stderr.decode())
        events = self.events()
        self.assertEqual(events[0], {'owner':['--verify-isolation']})
        self.assertEqual(events[-1], {'owner':['--verify-isolation']})
        driver = next(e for e in events if 'driver' in e)
        self.assertEqual(driver['code_mode'],0o700)
        self.assertFalse(Path(driver['code']).exists())
        self.assertIn('--image-id',driver['driver'])
        self.assertIn('--work',driver['driver'])
        self.assertIn(b'"wrapper_cleanup","result":"pass"',result.stdout)
        self.assertEqual(sentinel.read_text(),'preserve')
        self.assert_lock_contents_unchanged()

    def test_driver_and_extraction_failures_cleanup_preserve_exit_and_postflight(self):
        for changes in ({'ADAPTER_TEST_DRIVER_EXIT':'7'}, {'ADAPTER_TEST_TAR_FAILURE':'1'}):
            if self.trace.exists(): self.trace.unlink()
            result = self.run_wrapper(**changes)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.events()[-1],{'owner':['--verify-isolation']})
            self.assertIn(b'"wrapper_cleanup","result":"pass"',result.stdout)
            self.assert_lock_contents_unchanged()

    def test_each_busy_lock_refuses_before_owner_entry(self):
        for lock in self.locks:
            with lock.open('r') as held:
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                result = self.run_wrapper()
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.events(),[])
            self.assert_lock_contents_unchanged()

    def test_missing_symlink_and_hardlinked_existing_lock_refuse_without_creation(self):
        lock = self.locks[0]
        lock.unlink()
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(lock.exists())
        self.assertEqual(self.events(),[])
        original = self.root/'original-lock'
        original.write_text('preserve-lock')
        lock.symlink_to(original)
        self.assertNotEqual(self.run_wrapper().returncode,0)
        self.assertTrue(lock.is_symlink())
        lock.unlink()
        os.link(original,lock)
        self.assertNotEqual(self.run_wrapper().returncode,0)
        self.assertEqual(original.stat().st_nlink,2)
        self.assertEqual(original.read_text(),'preserve-lock')
        self.assertEqual(self.events(),[])

    def test_lock_replaced_after_open_refuses_bound_inode_before_owner_entry(self):
        # The mutation is solely inside this disposable fixture, performed by
        # the stand-in flock command to exercise the post-acquisition check.
        self.executable(self.bin / 'flock', '#!/bin/sh\n'
            'if [ "$2" = 9 ]; then\n'
            '  mv -- "' + str(self.locks[0]) + '" "' + str(self.locks[0]) + '.old"\n'
            '  printf "replacement" > "' + str(self.locks[0]) + '"\n'
            'fi\nexec /usr/bin/flock "$@"\n')
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'lock inode changed', result.stderr)
        self.assertEqual(self.events(),[])
        self.assertEqual(Path(str(self.locks[0])+'.old').read_bytes(), self.originals[0][1])

    def test_isolation_and_headroom_gates_and_postflight_failure(self):
        for changes in ({'ADAPTER_TEST_ISOLATION_FAILURE':'1'},
                        {'ADAPTER_TEST_MEMORY':'0 100'},
                        {'ADAPTER_TEST_MEMORY':'invalid max'},
                        {'ADAPTER_TEST_ISOLATION_FAILURE':'2'}):
            if self.trace.exists(): self.trace.unlink()
            result = self.run_wrapper(**changes)
            self.assertNotEqual(result.returncode,0)
            if changes != {'ADAPTER_TEST_ISOLATION_FAILURE':'2'}:
                self.assertFalse(any('driver' in e for e in self.events()))
            self.assert_lock_contents_unchanged()
