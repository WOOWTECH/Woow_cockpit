"""Execute the unmodified rendered root payload at a local device boundary.

No device or native commands. Actual module loading, dispatch, inventory,
native lock acquisition, Store, copy, hash and metadata code all execute.
Only root identity, absolute paths, pinned fixture bindings and readonly
command responses are supplied by the temporary device boundary.
"""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import io
import itertools
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import focus_n8n_instance_acceptance_ops as common
import focus_n8n_instance_acceptance_run as run
import focus_n8n_instance_acceptance_safeties_test as fixtures

NAME = fixtures.NAME

REAL_PATH = type(Path())
REAL_OPEN = os.open
REAL_EUID = os.geteuid()


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        archives = self.root/'var/lib/woowtech-backup/archives'
        archives.parent.mkdir(parents=True)
        self.obj, _ = fixtures.PreservationTests().setup_files(archives.parent)
        # Replace ONLY the expected trusted binding values with fixture values;
        # no operation, library function or rendered source is substituted.
        self.known = self.obj.known
        for bid in common.PROTECTED:
            p = archives/(bid+'.tar')
            if not p.exists(): common.atomic(p, b'original manual archive')
            common.atomic(archives/(bid+'.json'), b'{"type":"manual"}')
        self.make('/etc/woowtech-cockpit/backup/apps/n8n.json', json.dumps({
            'quadlet': {'files': ['n8n.container']},
            'config_files': [{'path': '.config/n8n/n8n.env'}]}).encode())
        self.make(common.QDIR+'n8n.container', b'[Container]\nImage=fixture\n')
        self.make(common.ENV, b'DB_TYPE=postgresdb\n')
        (self.root/'var/lib/woowtech-backup/jobs').mkdir(mode=0o700)
        for name in ('jobs.lock', 'engine.lock'): self.make('/run/woowtech-backup/'+name, b'')
        self.commands = []
        self.executions = 0
        self.payloads = []
        self.transport = SimpleNamespace(root=self.execute)
        lease = {'name': NAME, 'expires_utc': datetime.fromtimestamp(2000, timezone.utc).isoformat()}
        self.controller = run.Controller(SimpleNamespace(source=run.REPO, receipt=self.root/'receipt.json'),
            lease, self.transport, clock=lambda: 1000)

    def make(self, path, data):
        p = self.root/path.lstrip('/')
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        common.atomic(p, data)
        return p

    def command(self, argv, **kwargs):
        self.commands.append(tuple(argv))
        owner = argv[0] == common.OWNER
        actual = argv[1:] if owner else argv
        if actual[:3] == ['systemctl', '--user', 'show'] or actual[:2] == ['systemctl', 'show']:
            unit = actual[3] if owner else actual[2]
            self.assertEqual(actual[-1], '--property=ActiveState,SubState,UnitFileState')
            active = unit in ('n8n.target', 'woowtech-cockpit-backup-schedule.timer')
            out = ('ActiveState='+('active' if active else 'inactive')+
                '\nSubState='+('waiting' if active else 'dead')+'\nUnitFileState=generated\n').encode()
        elif actual == ['podman', 'images', '--no-trunc', '--format', '{{.ID}}']: out = b'fixture-image\n'
        elif actual == ['podman', 'volume', 'ls', '--format', '{{.Name}}']: out = b'original-volume\n'
        elif actual == ['podman', 'ps', '-q']: out = b''
        else: raise AssertionError('non-readonly or unknown command at fake device boundary')
        return SimpleNamespace(returncode=0, stdout=out, stderr=b'')

    def execute(self, *argv, input, timeout):
        self.assertEqual(argv[:4], ('python3', '-B', '-I', '-c'))
        script = argv[4]
        self.assertTrue(script.endswith(self.controller.ops_source))
        self.payloads.append(script)
        root = str(self.root)

        def mapped(path, *, ancestor=False):
            s = os.fsdecode(path)
            if s.startswith(root+'/') or s == root: return s
            if ancestor and s in map(str, REAL_PATH(root).parents): return s
            if s.startswith(('/var/lib/woowtech-backup/', '/run/woowtech-backup/',
                             '/etc/woowtech-cockpit/', '/home/appowner/')):
                return root+s
            raise AssertionError('path outside fake device boundary: '+s)

        class DevicePath(REAL_PATH):
            def __new__(cls, *parts): return object.__new__(cls)
            def __init__(self, *parts):
                s = str(REAL_PATH(*parts))
                super().__init__(mapped(s, ancestor=True) if s.startswith('/') else s)

        def load_helper(code, namespace):
            exec(code, namespace)
            self.assertEqual(namespace['__name__'], 'focus_n8n_instance_acceptance_safeties')
            namespace['PreservedSafeties'].__init__.__kwdefaults__['known'] = self.known

        out, err = io.StringIO(), io.StringIO()
        module_name = 'focus_n8n_instance_acceptance_safeties'
        old_module = sys.modules.get(module_name)
        cache = sys.pycache_prefix
        errors = []
        def trace(frame, event, value):
            if event == 'exception' and frame.f_code.co_filename in (
                    '<actual rendered root payload>', '<fixed safety preservation>') and value[0] is not SystemExit:
                errors.append((value[0].__name__, str(value[1])))
            return trace
        previous_trace = sys.gettrace()
        try:
            # The first identity query is dispatch's explicit root check.
            # Real local UID is used for every file/lock ownership check.
            with patch('pathlib.Path', DevicePath), patch('os.open', side_effect=lambda p,*a,**k: REAL_OPEN(mapped(p),*a,**k)), \
                    patch('os.geteuid', side_effect=itertools.chain([0], itertools.repeat(REAL_EUID))), \
                    patch('subprocess.run', side_effect=self.command), \
                    patch('sys.stdin', SimpleNamespace(buffer=io.BytesIO(input))), \
                    redirect_stdout(out), redirect_stderr(err):
                try:
                    sys.settrace(trace)
                    exec(compile(script, '<actual rendered root payload>', 'exec'),
                         {'__name__': '__main__', 'exec': load_helper})
                    rc = 0
                except SystemExit as e: rc = e.code
        finally:
            sys.settrace(previous_trace)
            sys.pycache_prefix = cache
            if old_module is None: sys.modules.pop(module_name, None)
            else: sys.modules[module_name] = old_module
        self.executions += 1
        if rc and json.loads(input)['op'] == 'preserved_safety_prepare':
            raise AssertionError('local fixture payload refusal: '+repr(errors[-3:]))
        return SimpleNamespace(returncode=rc, stdout=out.getvalue().encode(), stderr=err.getvalue().encode())

    def test_rendered_prepare_and_check_hash_inventory_over_old_128mib_bound(self):
        # Minimal sparse inventory above the actual failed aggregate boundary.
        # This still hashes every byte with real filesystem metadata.
        for i in range(11):
            p = self.obj.archives/f'20261127T020000Z-{i:08x}.tar'
            with p.open('wb') as f: f.truncate(12*1024**2)
            p.chmod(0o600)
        result = self.controller.op('preserved_safety_prepare')
        self.assertEqual(result['private_files'], 4)
        self.assertEqual(result['preexisting_managed_files'], 19)
        checked = self.controller.op('preserved_safety_check')
        self.assertEqual(checked, result)
        state = json.loads((self.root/'var/lib/woowtech-backup/focus-n8n-preserved-safety'/NAME/'state.json').read_bytes())
        self.assertEqual(len(state['before']), 19)
        self.assertGreater(sum(m['bytes'] for m in state['before'].values()), 128*1024**2)
        for p, meta in state['before'].items():
            data, independent = common.read_regular(p, 64*1024**2)
            self.assertEqual(dict(independent, bytes=len(data)), meta)
        for p, meta in state['original'].items():
            copy = self.root/'var/lib/woowtech-backup/focus-n8n-preserved-safety'/NAME/meta['copy']
            self.assertEqual(common.read_regular(copy)[1], {k:v for k,v in meta.items() if k!='copy'})
            self.assertEqual(common.read_regular(p)[1]['sha256'], meta['sha256'])
        self.assertEqual(self.executions, 2)
        self.assertEqual(self.payloads[0], self.payloads[1])

    def test_rendered_copy_corruption_refuses_and_saves_fixed_failure_record(self):
        self.controller.op('preserved_safety_prepare')
        folder = self.root/'var/lib/woowtech-backup/focus-n8n-preserved-safety'/NAME
        before = {str(p): common.read_regular(p)[1] for p in self.obj.archives.iterdir()}
        (folder/'original-0').write_bytes(b'corrupted private fixture')
        with self.assertRaises(RuntimeError): self.controller.op('preserved_safety_copies')
        self.assertEqual(self.controller.r['device_error_class'], 'ValueError')
        state = json.loads((folder/'state.json').read_bytes())
        self.assertEqual(state['failure'], {'operation': 'preserved_safety_copies',
            'error_class': 'ValueError', 'errno': None})
        self.assertEqual({str(p): common.read_regular(p)[1] for p in self.obj.archives.iterdir()}, before)


if __name__ == '__main__': unittest.main()
