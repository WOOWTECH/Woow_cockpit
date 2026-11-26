"""Offline tests of the real-HA Omnigent harness (services-a): its Quadlet/catalog target as the PRODUCT
discovers it, the lock, the private file summaries and the evidence vocabulary. No device, backup or credential."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / 'backup-engine'))

import omnigent_real_ha as real  # noqa: E402
from woowbackup import catalog, ha_omnigent  # noqa: E402
from woowbackup.paths import Paths  # noqa: E402

spec = importlib.util.spec_from_file_location('services_a_capture_o', HERE / 'services_a_capture.py')
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


def lookup(name):
    if name != 'appowner':
        raise KeyError(name)
    return SimpleNamespace(pw_uid=1019, pw_gid=1019, pw_dir='/home/appowner')


class TargetDiscoveryTest(unittest.TestCase):
    def app(self):
        with tempfile.TemporaryDirectory() as directory:
            return catalog.validate_entry(real.catalog_entry(), paths=Paths(base=Path(directory)), user_lookup=lookup)

    def test_catalog_entry_validates_and_declares_secret(self):
        app = self.app()
        self.assertEqual(list(app.units), real.UNITS)
        self.assertEqual([v['name'] for v in app.volumes], [real.DBVOL, real.SERVERVOL, real.PIVOL])
        self.assertEqual([s['name'] for s in app.secrets], [real.SECRET])

    def test_product_target_resolves_the_quadlets(self):
        app = self.app()
        files = {name: text.encode() for name, text in real.quadlets().items()}
        work = SimpleNamespace(quadlets=lambda _app: files, runner=lambda _app: SimpleNamespace(home='/home/appowner'))
        target = ha_omnigent.Target(work, app)
        self.assertEqual((target.db_volume, target.server_volume, target.pi_volume),
                         (real.DBVOL, real.SERVERVOL, real.PIVOL))
        self.assertEqual(target.db_container, real.DB)
        self.assertEqual(target.db_image, 'sha256:' + real.PG_IMAGE)
        self.assertEqual(target.database, 'omnigent')
        self.assertEqual(target.own_users, [real.TARGET_ADMIN])
        self.assertEqual(target.info_url, 'http://127.0.0.1:8000/v1/info')
        self.assertEqual(target.db_secrets, [])
        # Every Quadlet secret is registered in the catalog; the current import reports missing ones.
        work.quadlets = lambda _app: files
        self.assertEqual(ha_omnigent.unregistered_secrets(work, app), [])

    def test_server_keeps_its_log_and_runner_is_placeholder(self):
        texts = real.quadlets()
        self.assertNotIn('LogDriver=none', texts[real.FILES[1]])
        self.assertIn('LogDriver=none', texts[real.FILES[2]])
        self.assertIn('Exec=infinity', texts[real.FILES[2]])
        for text in texts.values():
            self.assertIn('Pull=never', text)
            self.assertNotIn('PublishPort', text)
        self.assertIn('Network=none', texts[real.FILES[0]])
        self.assertIn('Network=container:' + real.DB, texts[real.FILES[1]])


class LockTest(unittest.TestCase):
    def test_waits_for_the_holder_then_times_out(self):
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'lock')
            with mock.patch.object(real, 'LOCK', path), \
                    mock.patch.object(real, 'WAITING', os.path.join(directory, 'waiting')):
                with real.dev_d_lock(timeout=5):
                    pass
                fd = os.open(path, os.O_RDWR)
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    with mock.patch.object(real.time, 'sleep', lambda s: None):
                        with self.assertRaisesRegex(RuntimeError, 'dev_d_lock_timeout'):
                            with real.dev_d_lock(timeout=0):
                                pass
                finally:
                    os.close(fd)


class GuardsTest(unittest.TestCase):
    """services-a-2: the run names a clean commit and records dev-d's outer isolation before and after."""

    def test_dirty_tree_refuses_before_the_lock(self):
        events = []
        with mock.patch.object(real.guard, 'clean_tree', return_value=(False, ['backup-engine/x.py'])), \
                mock.patch.object(real.guard, 'head', return_value='a' * 40), \
                mock.patch.object(real, 'event', lambda stage, **v: events.append((stage, v))), \
                mock.patch('builtins.print'):
            with self.assertRaisesRegex(RuntimeError, 'engine_or_harness_changes_not_committed'):
                real.committed_source()
        self.assertEqual(events, [('source', {'clean_tree': False, 'changed_paths': 1})])

    def test_isolation_event_and_failure(self):
        events = []
        with mock.patch.object(real.guard, 'verify_isolation', return_value='dev-d isolation: true none {}'), \
                mock.patch.object(real, 'event', lambda stage, **v: events.append((stage, v))), \
                mock.patch('builtins.print') as printed:
            real.isolation('before')
        printed.assert_called_once_with('dev-d isolation: true none {}', flush=True)
        self.assertEqual(events, [('isolation', {'when': 'before', 'verified': True, 'running': True,
                                                 'network': 'none', 'published_ports': 0})])
        events.clear()
        with mock.patch.object(real.guard, 'verify_isolation', side_effect=real.guard.GuardError('x')), \
                mock.patch.object(real, 'event', lambda stage, **v: events.append((stage, v))):
            with self.assertRaisesRegex(RuntimeError, 'dev_d_isolation_failed'):
                real.isolation('after')
        self.assertEqual(events, [('isolation', {'when': 'after', 'verified': False})])

    def test_main_order_isolation_around_the_run(self):
        calls = []
        args = SimpleNamespace(run=True, arch='x86', outer_isolation_confirmed=True)

        @real.contextlib.contextmanager
        def lock():
            calls.append('lock')
            try:
                yield 0
            finally:
                calls.append('unlock')

        with mock.patch.object(real.argparse.ArgumentParser, 'parse_args', return_value=args), \
                mock.patch.object(real.util, 'find_tool', return_value='/usr/bin/x'), \
                mock.patch.object(real, 'committed_source', lambda: calls.append('source')), \
                mock.patch.object(real, 'dev_d_lock', lock), \
                mock.patch.object(real, 'isolation', lambda when: calls.append('isolation-' + when)), \
                mock.patch.object(real.chain, 'isolated_preflight', lambda: calls.append('preflight')), \
                mock.patch.object(real.chain, 'Runner', lambda: None), \
                mock.patch.object(real, 'inventory', lambda runner: ()), \
                mock.patch.object(real, 'run', side_effect=RuntimeError('boom')), \
                mock.patch.object(real, 'event', lambda *a, **k: None):
            with self.assertRaisesRegex(RuntimeError, 'boom'):
                real.main()
        self.assertEqual(calls, ['source', 'lock', 'isolation-before', 'preflight', 'isolation-after', 'unlock'])

    def test_capture_keeps_the_new_lines(self):
        self.assertEqual(capture.status_lines('dev-d isolation: true none {}\nsource commit ' + 'a' * 40 + '\n'
                                              '{"stage": "isolation", "when": "after", "verified": true}\n'),
                         ['dev-d isolation: true none {}', 'source commit ' + 'a' * 40,
                          '{"stage": "isolation", "when": "after", "verified": true}'])


class SummaryTest(unittest.TestCase):
    def test_tar_files_and_member(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'v.tar'
            with tarfile.open(path, 'w') as tar:
                for name, data, mode in (('auth.json', b'{"x": 1}\n', 0o600), ('dir/f', b'abc', 0o644)):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = len(data), mode
                    tar.addfile(info, io.BytesIO(data))
            files = real.tar_files(path)
            self.assertEqual(files['auth.json'][0], 0o600)
            self.assertEqual(files['dir/f'][1], 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
            self.assertEqual(real.tar_member(path, 'dir/f'), b'abc')
            self.assertIsNone(real.tar_member(path, 'missing'))

    def test_reporter_keeps_lines_private(self):
        reporter = real.Reporter()
        reporter.log('a', 'b')
        reporter.phase('x', percent=3)
        self.assertEqual(reporter.lines, ['a b'])
        self.assertFalse(reporter.set_cancellable(True))
        self.assertFalse(reporter.cancel_requested())


class ItemsTest(unittest.TestCase):
    def test_paginated_list_and_plain_shapes(self):
        self.assertEqual(real.items({'object': 'list', 'data': [{'id': 'a'}], 'has_more': False}, 'sessions'),
                         [{'id': 'a'}])
        self.assertEqual(real.items([{'id': 'b'}], 'users'), [{'id': 'b'}])
        self.assertEqual(real.items({'users': [{'id': 'c'}], 'data': []}, 'users'), [{'id': 'c'}])
        self.assertEqual(real.items({'detail': 'x'}, 'comments'), [])
        self.assertEqual(real.items(None), [])


class EventVocabularyTest(unittest.TestCase):
    def test_json_events(self):
        good = json.dumps({'stage': 'installed_app_verified', 'phase': 'installed', 'ha_admin_login': True,
                           'table_counts': 19})
        bad_text = json.dumps({'stage': 'failed', 'detail': 'password is hunter2'})
        bad_key = json.dumps({'stage': 'x', 'Bad Key': 1})
        frames = json.dumps({'stage': 'failed', 'error_type': 'RuntimeError', 'code': 'install_failed',
                             'frames': [{'file': 'omnigent_real_ha.py', 'line': 10, 'function': 'run'}]})
        lines = capture.status_lines('\n'.join([good, bad_text, bad_key, frames, '{"stage": 1}']))
        self.assertEqual(lines, [good, frames])


if __name__ == '__main__':
    unittest.main()
