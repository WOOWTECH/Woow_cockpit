"""Engine patch: exact old-to-new replacement of named engine files with a strict way back. Temp-dir fixtures, no device."""
from contextlib import redirect_stdout
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import io
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
import focus_n8n_instance_acceptance_engine_patch_ops as dev
import focus_n8n_instance_acceptance_engine_patch as drv

NAME = 'woowbk_focus_n8n_abcdef012345'
OLD, NEW = b'old probe bytes\n', b'new probe bytes that skip the probe itself\n'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def spec(old=OLD, new=NEW):
    return {'old_sha256': sha(old), 'new_sha256': sha(new), 'new_b64': base64.b64encode(new).decode()}


class DeviceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.lib, self.helper, self.jobs, self.locks = self.root / 'lib', self.root / 'helper', self.root / 'jobs', self.root / 'run'
        for folder in (self.lib, self.jobs, self.locks):
            folder.mkdir()
        for name in ('jobs.lock', 'engine.lock'):
            (self.locks / name).write_bytes(b'')
            (self.locks / name).chmod(0o600)
        (self.lib / 'ha_n8n.py').write_bytes(OLD)
        (self.lib / 'other.py').write_bytes(b'other\n')
        os.utime(self.lib / 'ha_n8n.py', ns=(1000000000, 1200000000))
        self.helper.write_bytes(b'helper\n')
        self.journal = self.root / 'journal'
        for target in (patch.object(dev, 'LIB', self.lib), patch.object(dev, 'HELPER', self.helper),
                       patch.object(dev, 'JOBS', self.jobs), patch.object(dev, 'PARENT', str(self.journal))):
            target.start()
            self.addCleanup(target.stop)
        real_open = os.open

        def local_open(path, *args, **kwargs):
            text = os.fspath(path)
            if text.startswith('/run/woowtech-backup/'):
                text = str(self.locks / Path(text).name)
            return real_open(text, *args, **kwargs)
        opener = patch('os.open', side_effect=local_open)
        opener.start()
        self.addCleanup(opener.stop)

    def request(self, **files):
        return {'op': 'engine-apply', 'case': NAME, 'files': files}

    def test_apply_replaces_only_the_named_file_keeps_attributes_and_journals_exact_copies(self):
        before = (self.lib / 'ha_n8n.py').stat()
        result = dev.apply(self.request(**{'ha_n8n.py': spec()}))
        self.assertEqual(result['applied'], ['ha_n8n.py'])
        self.assertEqual((self.lib / 'ha_n8n.py').read_bytes(), NEW)
        self.assertEqual((self.lib / 'other.py').read_bytes(), b'other\n')
        after = (self.lib / 'ha_n8n.py').stat()
        self.assertEqual((after.st_mode, after.st_uid, after.st_gid), (before.st_mode, before.st_uid, before.st_gid))
        store = common.Store(NAME, parent=str(self.journal))
        self.assertTrue(store.state['patch']['applied'])
        copy = store.path / store.state['original'][str(self.lib / 'ha_n8n.py')]['copy']
        self.assertEqual(copy.read_bytes(), OLD)
        self.assertEqual(copy.stat().st_mtime_ns, 1200000000)
        self.assertEqual(oct(store.path.stat().st_mode & 0o777), '0o700')

    def test_a_file_that_is_not_the_reviewed_old_version_is_refused_before_any_write_or_journal(self):
        (self.lib / 'ha_n8n.py').write_bytes(b'drifted\n')
        with self.assertRaisesRegex(ValueError, 'not-the-reviewed-old-file'):
            dev.apply(self.request(**{'ha_n8n.py': spec()}))
        self.assertEqual((self.lib / 'ha_n8n.py').read_bytes(), b'drifted\n')
        self.assertFalse(self.journal.exists())

    def test_an_active_job_or_a_busy_native_lock_refuses_before_any_write(self):
        (self.jobs / 'j20261127T000000Z-00000000.json').write_text(json.dumps({'state': 'running'}))
        with self.assertRaisesRegex(ValueError, 'active-job'):
            dev.apply(self.request(**{'ha_n8n.py': spec()}))
        (self.jobs / 'j20261127T000000Z-00000000.json').write_text(json.dumps({'state': 'succeeded'}))
        held = os.open(self.locks / 'engine.lock', os.O_RDWR)
        fcntl.flock(held, fcntl.LOCK_EX)
        self.addCleanup(os.close, held)
        with self.assertRaises(OSError):
            dev.apply(self.request(**{'ha_n8n.py': spec()}))
        self.assertEqual((self.lib / 'ha_n8n.py').read_bytes(), OLD)
        self.assertFalse(self.journal.exists())

    def test_names_specs_and_bytes_are_strictly_validated(self):
        good = spec()
        for rel in ('../x.py', 'a/b.py', 'Ha.py', 'x.txt', '', '.py', 'ha n8n.py'):
            with self.subTest(rel=rel), self.assertRaises(ValueError):
                dev.plan(self.request(**{rel: good}))
        for label, bad in (('extra key', dict(good, extra=1)), ('bytes do not match hash', dict(good, new_b64=base64.b64encode(b'x').decode())),
                           ('same hash', dict(good, new_sha256=good['old_sha256'])), ('short hash', dict(good, old_sha256='abc')),
                           ('not base64', dict(good, new_b64='@@@'))):
            with self.subTest(label=label), self.assertRaises(ValueError):
                dev.plan(self.request(**{'ha_n8n.py': bad}))
        with self.assertRaises(ValueError):
            dev.plan(self.request())
        with self.assertRaises(ValueError):
            dev.plan(self.request(**{'f%d.py' % i: good for i in range(dev.MAX_FILES + 1)}))
        self.assertTrue(dev.plan(self.request(**{dev.HELPER_KEY: spec(b'helper\n', NEW)})))

    def test_restore_returns_exact_bytes_mtime_and_mode_and_refuses_a_foreign_change(self):
        original = (self.lib / 'ha_n8n.py').stat()
        dev.apply(self.request(**{'ha_n8n.py': spec()}))
        self.assertEqual(dev.status({'case': NAME})['files'], {'ha_n8n.py': sha(NEW)})
        (self.lib / 'ha_n8n.py').write_bytes(b'someone else\n')
        with self.assertRaisesRegex(ValueError, 'foreign-change'):
            dev.restore({'case': NAME})
        self.assertEqual((self.lib / 'ha_n8n.py').read_bytes(), b'someone else\n')
        (self.lib / 'ha_n8n.py').write_bytes(NEW)
        self.assertEqual(dev.restore({'case': NAME}), {'restored': ['ha_n8n.py']})
        restored = (self.lib / 'ha_n8n.py').stat()
        self.assertEqual((self.lib / 'ha_n8n.py').read_bytes(), OLD)
        self.assertEqual((restored.st_mtime_ns, restored.st_mode), (original.st_mtime_ns, original.st_mode))
        self.assertTrue(dev.status({'case': NAME})['restored'])

    def test_a_failure_midway_leaves_a_journal_that_restores_every_file(self):
        calls = []
        real = common.Store.replace

        def replace(store, path, data, **kwargs):
            calls.append(path)
            if len(calls) == 2:
                raise OSError(28, 'no space')
            return real(store, path, data, **kwargs)
        with patch.object(common.Store, 'replace', autospec=True, side_effect=replace):
            with self.assertRaises(OSError):
                dev.apply(self.request(**{'ha_n8n.py': spec(), dev.HELPER_KEY: spec(b'helper\n', NEW)}))
        # The files are replaced in sorted path order: the first one is new, the one whose replacement failed is still old.
        first, second = Path(calls[0]), Path(calls[1])
        self.assertEqual(first.read_bytes(), NEW)
        self.assertEqual(second.read_bytes(), OLD if second.name == 'ha_n8n.py' else b'helper\n')
        self.assertFalse(common.Store(NAME, parent=str(self.journal)).state['patch']['applied'])
        dev.restore({'case': NAME})
        self.assertEqual({p.name: p.read_bytes() for p in (self.lib / 'ha_n8n.py', self.helper)},
                         {'ha_n8n.py': OLD, 'helper': b'helper\n'})

    def test_a_second_apply_with_the_same_case_is_refused_because_the_journal_is_one_shot(self):
        dev.apply(self.request(**{'ha_n8n.py': spec()}))
        with self.assertRaises(FileExistsError):   # the case root already exists: the Store refuses before any write
            dev.apply(self.request(**{'ha_n8n.py': spec(NEW, OLD)}))
        self.assertEqual((self.lib / 'ha_n8n.py').read_bytes(), NEW)

    def test_dispatch_needs_root_a_case_name_and_a_known_operation(self):
        with self.assertRaisesRegex(ValueError, 'case-root'):
            dev.dispatch({'op': 'engine-status', 'case': NAME})
        with patch('os.geteuid', return_value=0):
            with self.assertRaisesRegex(ValueError, 'case-root'):
                dev.dispatch({'op': 'engine-status', 'case': 'not-a-case'})
            with self.assertRaisesRegex(ValueError, 'operation'):
                dev.dispatch({'op': 'engine-other', 'case': NAME})

    def test_complete_rendered_program_loads_the_modules_and_dispatches(self):
        names, saved_modules, saved_prefix = [], dict(sys.modules), sys.pycache_prefix

        def load(code, namespace):
            exec(code, namespace)
            names.append(namespace['__name__'])
            if namespace['__name__'] == 'focus_n8n_instance_acceptance_engine_patch_ops':
                namespace.update(LIB=self.lib, HELPER=self.helper, JOBS=self.jobs, PARENT=str(self.journal))
        out = io.StringIO()
        try:
            with patch('os.geteuid', return_value=0), redirect_stdout(out), \
                    patch('sys.stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps({'op': 'engine-status', 'case': NAME}).encode()))):
                exec(compile(drv.dependencies() + drv.ENTRY, '<rendered>', 'exec'), {'__name__': '__main__', 'exec': load})
        finally:
            sys.pycache_prefix = saved_prefix
            for key in names:
                if key in saved_modules:
                    sys.modules[key] = saved_modules[key]
                else:
                    sys.modules.pop(key, None)
        self.assertEqual(json.loads(out.getvalue()), {'ok': True, 'result': {'journal': False, 'applied': None, 'restored': None, 'files': {}}})
        self.assertEqual(len(names), 3)


class DriverTests(unittest.TestCase):
    def source(self, root, files):
        engine = Path(root) / 'backup-engine'
        (engine / 'woowbackup').mkdir(parents=True)
        for name, data in files.items():
            (engine / ('woowtech-cockpit-backup' if name == 'helper' else 'woowbackup/' + name)).write_bytes(data)
        return root

    def test_changed_files_are_selected_by_content_and_added_or_removed_files_refuse(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            base = {'ha_n8n.py': OLD, 'other.py': b'o\n', 'helper': b'h\n'}
            self.source(a, base)
            self.source(b, dict(base, **{'ha_n8n.py': NEW}))
            old, new, names = drv.changed(a, b)
            self.assertEqual(names, ['ha_n8n.py'])
            self.assertEqual(drv.request_files(old, new, names), {'ha_n8n.py': spec()})
            self.assertEqual(set(drv.expected_hashes(new)), {'ha_n8n.py', 'other.py', '../woowtech-cockpit-backup'})
        for label, other in (('added', dict(base, **{'new.py': b'n\n'})), ('removed', {'ha_n8n.py': NEW, 'helper': b'h\n'}),
                             ('identical', base), ('too many', {f'f{i}.py': b'x%d' % i for i in range(9)} | {'helper': b'h\n'})):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
                self.source(a, {f'f{i}.py': b'y%d' % i for i in range(9)} | {'helper': b'h\n'} if label == 'too many' else base)
                self.source(b, other)
                with self.assertRaises(ValueError):
                    drv.changed(a, b)

    def test_lease_must_match_old_source_files_phase_bounds_and_the_frozen_product(self):
        lease = {'case': drv.CASE, 'phases': list(drv.PHASES), 'old_source_commit': 'o' * 40, 'files': ['ha_n8n.py'],
                 'bounds': drv.run.BOUNDS, 'image_policy': 'retain-for-case', 'granted': True, 'device': drv.run.plan.DEVICE,
                 'driver_commit': 'a' * 40, 'source_commit': drv.run.FROZEN_PRODUCT, 'catalog_sha256': drv.run.plan.FOUND_SHA,
                 'name': NAME, 'expires_utc': datetime.fromtimestamp(2000, timezone.utc).isoformat()}
        arguments = dict(driver='a' * 40, source_commit=drv.run.FROZEN_PRODUCT, old_commit='o' * 40, names=['ha_n8n.py'], now=1000)
        self.assertEqual(drv.validate(lease, 'engine-patch', **arguments), 2000)
        for key, value in (('old_source_commit', 'p' * 40), ('files', ['other.py']), ('phases', ['flow']),
                           ('bounds', {}), ('granted', False), ('source_commit', 'b' * 40), ('image_policy', None)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                drv.validate(dict(lease, **{key: value}), 'engine-patch', **arguments)
        with self.assertRaises(ValueError):
            drv.validate(lease, 'flow', **arguments)

    def test_offline_default_compiles_the_exact_device_program_without_touching_anything(self):
        with patch.object(drv.run, 'git', side_effect=AssertionError('no runtime')), redirect_stdout(io.StringIO()):
            self.assertEqual(drv.main([]), 0)


if __name__ == '__main__':
    unittest.main()
