"""Offline: odoo_cold_keep_preserve.py on real files in a temporary folder (no device, no root, no lock files): the move of
an older Odoo safety backup out of a stand-in archives folder and back, with the reused N8-01 primitives
(focus_n8n_instance_acceptance_ops.read_regular and atomic); the engine locks are a stand-in context manager."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
BID = '20261124T152230Z-5f41c20c'
OTHER = '20261124T152938Z-3b26976e'
CASE = 'odoo-ck-20261128T101500'


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


keep = module('odoo_cold_keep_preserve')
ops = module('focus_n8n_instance_acceptance_ops')       # the reused N8-01 primitives, as the device program loads them
safeties = module('focus_n8n_instance_acceptance_safeties')


class Locks:
    """Stand-in for safeties.native_locks: counts its holds (and can be busy for a while)."""

    def __init__(self, busy=0):
        self.busy, self.held, self.entered = busy, False, 0

    @contextlib.contextmanager
    def __call__(self):
        if self.busy:
            self.busy -= 1
            raise BlockingIOError('engine lock held')
        self.held, self.entered = True, self.entered + 1
        try:
            yield
        finally:
            self.held = False


def meta(path):
    st = os.lstat(path)
    return {'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest(), 'bytes': st.st_size,
            'mode': st.st_mode & 0o777, 'uid': st.st_uid, 'gid': st.st_gid, 'mtime_ns': st.st_mtime_ns, 'ino': st.st_ino}


class PreserveCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.archives = self.tmp / 'archives'
        self.archives.mkdir(mode=0o700)
        self.parent = self.tmp / 'preserved'
        self.sha = self.pair(BID, apps=['odoo', 'n8n'], size=200_000)
        self.other_sha = self.pair(OTHER, kind='manual', apps=['odoo'], size=3000)
        self.before = {p.name: meta(p) for p in self.archives.iterdir()}
        self.locks = Locks()

    def pair(self, bid, *, kind='safety', apps=('odoo',), size=1000, note='還原前備份', sidecar_sha=None, mode=0o600):
        data = os.urandom(size)
        archive = self.archives / (bid + '.tar')
        archive.write_bytes(data)
        sha = hashlib.sha256(data).hexdigest()
        record = {'id': bid, 'type': kind, 'created': '2026-11-24T15:22:30Z', 'note': note, 'size': size,
                  'apps': [{'id': app, 'name': app} for app in apps], 'sha256': sidecar_sha or sha}
        sidecar = self.archives / (bid + '.json')
        sidecar.write_text(json.dumps(record, ensure_ascii=False))
        for path, mtime in ((archive, 1795533865849123502), (sidecar, 1795533867143150283)):
            os.chmod(path, mode)
            os.utime(path, ns=(mtime, mtime))
        return sha

    def preserve(self, ids=None, expect=None, **kw):
        ids = [BID] if ids is None else ids
        return keep.preserve(ops, self.locks, kw.pop('case', CASE), ids, {BID: self.sha} if expect is None else expect,
                             archives=self.archives, parent=self.parent, **kw)

    def put_back(self, ids=None):
        return keep.put_back(ops, self.locks, CASE, [BID] if ids is None else ids, archives=self.archives, parent=self.parent)

    def folder(self):
        return self.parent / CASE


class RoundTripTests(PreserveCase):
    def test_out_of_view_whole_then_back_byte_for_byte_with_the_same_inode(self):
        result = self.preserve()
        self.assertEqual(result['phase'], 'moved')
        self.assertEqual(sorted(result['files']), [BID + '.json', BID + '.tar'])
        self.assertEqual(result['files'][BID + '.tar']['sha256'], self.sha)
        self.assertFalse(any((self.archives / name).exists() for name in (BID + '.tar', BID + '.json')))
        for name in (BID + '.tar', BID + '.json'):   # moved, not copied: the same inode, bytes and attributes
            self.assertEqual(meta(self.folder() / name), self.before[name])
        self.assertEqual(json.loads((self.folder() / 'state.json').read_text())['phase'], 'moved')
        self.assertEqual({p.name: meta(p) for p in self.archives.iterdir()},
                         {k: v for k, v in self.before.items() if k.startswith(OTHER)})   # the rest untouched
        back = self.put_back()
        self.assertEqual((back['phase'], back['restored_files']), ('returned', 2))
        self.assertEqual(back['files'], result['files'])
        self.assertEqual({p.name: meta(p) for p in self.archives.iterdir()}, self.before)
        self.assertFalse(self.parent.exists())   # the private folder and its parent are gone again
        self.assertEqual(self.locks.entered, 2)

    def test_a_second_put_back_finds_nothing_moved(self):
        self.preserve()
        self.put_back()
        again = self.put_back()
        self.assertEqual((again['phase'], again['restored_files']), ('none-moved', 0))
        self.assertEqual({p.name: meta(p) for p in self.archives.iterdir()}, self.before)


class RefusalTests(PreserveCase):
    def assert_untouched(self):
        self.assertEqual({p.name: meta(p) for p in self.archives.iterdir()}, self.before)
        self.assertFalse(self.folder().exists())

    def test_anything_but_the_listed_older_odoo_safety_backup_refuses_before_a_move(self):
        cases = {
            'another digest listed': lambda: self.preserve(expect={BID: '0' * 64}),
            'a manual backup': lambda: (self.pair(BID, kind='manual'), self.preserve(expect={BID: self.sha_of(BID)})),
            'not an Odoo backup': lambda: (self.pair(BID, apps=['n8n']), self.preserve(expect={BID: self.sha_of(BID)})),
            'a kept copy': lambda: (self.pair(BID, note=keep.KEPT_PREFIX + 'odoo'), self.preserve(expect={BID: self.sha_of(BID)})),
            'a sidecar of other bytes': lambda: (self.pair(BID, sidecar_sha='1' * 64), self.preserve(expect={BID: self.sha_of(BID)})),
            'not root 0600': lambda: (self.pair(BID, mode=0o640), self.preserve(expect={BID: self.sha_of(BID)})),
        }
        for label_text, attempt in cases.items():
            with self.subTest(label_text):
                with self.assertRaises(ValueError):
                    attempt()
                self.assertFalse(self.folder().exists())
                self.assertTrue((self.archives / (BID + '.tar')).exists() and (self.archives / (BID + '.json')).exists())

    def sha_of(self, bid):
        return hashlib.sha256((self.archives / (bid + '.tar')).read_bytes()).hexdigest()

    def test_a_format_one_twin_bad_requests_and_an_existing_folder_refuse(self):
        (self.archives / (BID + '.woowbackup')).write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'twin'):
            self.preserve()
        (self.archives / (BID + '.woowbackup')).unlink()
        self.before = {p.name: meta(p) for p in self.archives.iterdir()}
        for label_text, kw in (('case', {'case': 'odoo-ck-x'}), ('ids', {'ids': [BID, BID]}),
                               ('too many', {'ids': ['20261120T00000%dZ-0000000%d' % (n, n) for n in range(6)]})):
            with self.subTest(label_text):
                with self.assertRaises(ValueError):
                    self.preserve(**kw)
                self.assert_untouched()
        self.parent.mkdir(mode=0o700)
        self.folder().mkdir(mode=0o700)   # an earlier run's folder is never reused
        with self.assertRaises(FileExistsError):
            self.preserve()
        self.assertEqual({p.name: meta(p) for p in self.archives.iterdir()}, self.before)

    def test_the_engine_locks_are_held_for_the_move_and_a_busy_one_is_waited_for(self):
        self.locks = Locks(busy=2)
        with patch.object(keep.time, 'sleep', lambda _s: None):
            self.preserve()
        self.assertEqual(self.locks.entered, 1)
        self.locks = Locks(busy=keep.LOCK_ATTEMPTS)
        with patch.object(keep.time, 'sleep', lambda _s: None), self.assertRaises(BlockingIOError):
            self.put_back()
        self.assertTrue((self.folder() / (BID + '.tar')).exists())   # nothing returned without the locks

    def test_the_reused_lock_helper_is_n8_01s_own(self):
        self.assertTrue(callable(safeties.native_locks))
        program = keep.device_program(HERE)
        compile(program, '<device program>', 'exec')
        self.assertLess(len(program.encode()), 120 * 1024)
        for name in ('focus_n8n_instance_acceptance_ops', 'focus_n8n_instance_acceptance_safeties', 'odoo_cold_keep_preserve'):
            self.assertIn(repr((HERE / f'{name}.py').read_text(encoding='utf-8')), program)   # loaded as committed
        self.assertTrue(program.endswith('_m.main()\n'))
        with patch.object(keep.os, 'geteuid', lambda: 1000), self.assertRaisesRegex(SystemExit, 'device root'):
            keep.main()
        with self.assertRaisesRegex(ValueError, 'operation'):
            keep.dispatch({'op': 'delete'}, ops, self.locks)


class InterruptedTests(PreserveCase):
    def test_a_move_interrupted_between_its_link_and_its_unlink_is_completed_by_the_return(self):
        real = os.unlink
        calls = {'n': 0}

        def unlink(path, *a, **k):
            calls['n'] += 1
            if calls['n'] == 1:
                raise OSError('killed between link and unlink')
            return real(path, *a, **k)
        with patch.object(keep.os, 'unlink', unlink), self.assertRaises(OSError):
            self.preserve()
        record = json.loads((self.folder() / 'state.json').read_text())
        self.assertEqual(record['phase'], 'recorded')   # recorded before anything moved
        self.assertEqual(os.lstat(self.archives / (BID + '.tar')).st_ino, os.lstat(self.folder() / (BID + '.tar')).st_ino)
        self.assertTrue((self.archives / (BID + '.json')).exists())
        back = self.put_back()
        self.assertEqual((back['phase'], back['restored_files']), ('returned', 0))
        self.assertEqual({p.name: meta(p) for p in self.archives.iterdir()}, self.before)
        self.assertFalse(self.parent.exists())

    def test_a_stop_before_the_record_moved_nothing(self):
        self.parent.mkdir(mode=0o700)
        self.folder().mkdir(mode=0o700)
        back = self.put_back()
        self.assertEqual(back['phase'], 'none-moved')
        self.assertFalse(self.folder().exists())
        self.folder().mkdir(mode=0o700)
        (self.folder() / 'unknown').write_bytes(b'?')
        with self.assertRaisesRegex(ValueError, 'unknown contents'):
            self.put_back()

    def test_a_name_held_by_another_file_or_a_changed_private_file_refuses(self):
        self.preserve()
        (self.archives / (BID + '.json')).write_text('{"id": "someone else"}')
        with self.assertRaisesRegex(ValueError, 'another file holds the name'):
            self.put_back()
        self.assertEqual((self.archives / (BID + '.json')).read_text(), '{"id": "someone else"}')   # never replaced
        self.assertTrue((self.folder() / (BID + '.json')).exists() and (self.folder() / (BID + '.tar')).exists())
        (self.archives / (BID + '.json')).unlink()
        with open(self.folder() / (BID + '.tar'), 'r+b') as handle:   # the same inode, other bytes
            first = handle.read(1)
            handle.seek(0)
            handle.write(bytes([first[0] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.put_back()
        # The sidecar went back first; the changed archive stays private: an archive is never left without its sidecar,
        # and a sidecar without its archive is never listed.
        self.assertTrue((self.archives / (BID + '.json')).exists())
        self.assertFalse((self.archives / (BID + '.tar')).exists())
        self.assertEqual(keep.where(CASE, [BID], archives=self.archives, parent=self.parent)['files'],
                         {BID + '.tar': {'archives': False, 'private': True}, BID + '.json': {'archives': True, 'private': False}})


if __name__ == '__main__':
    unittest.main()
