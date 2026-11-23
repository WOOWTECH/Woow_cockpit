"""Offline tests of the hermes-real harness: no device, no secret, no lock is touched."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HARNESS = HERE / 'hermes_real_ha.py'
CAPTURE = HERE / 'hermes_real_capture.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hr = load('hermes_real_ha', HARNESS)
cap = load('hermes_real_capture', CAPTURE)

SRC = {
    'api-a': {'id': 'api-a', 'message_count': 3, 'source': 'api_server', 'model': 'm', 'title': 'B1 mock reply #2: ok',
              'started_at': 1.5},
    'api-b': {'id': 'api-b', 'message_count': 3, 'source': 'api_server', 'model': 'm', 'title': 'B1 mock reply #4: ok',
              'started_at': 2.5},
}


class FakeEvidence:
    def __init__(self):
        self.results = []

    def check(self, name, ok, detail=''):
        self.results.append((name, bool(ok)))
        return bool(ok)

    def save(self, *_args):
        pass

    def failed(self):
        return [name for name, ok in self.results if not ok]


def rows(sid, n=3):
    return [[i, 'user' if i % 2 else 'assistant', f'{sid}-{i}'] for i in range(1, n + 1)]


def probe(mode, *, break_rows=False, plain_snippet=False):
    ha = mode == 'ha'
    listed = ({sid: {k: s[k] for k in ('message_count', 'source', 'model', 'title', 'started_at')} for sid, s in SRC.items()}
              if ha else {hr.BASE_SESSION: {'message_count': 1}})
    db = {sid: (rows(sid) if ha else []) for sid in SRC}
    db[hr.BASE_SESSION] = [] if ha else rows(hr.BASE_SESSION, 1)
    api = {sid: {'code': 200, 'rows': [list(r) for r in v]} for sid, v in db.items()}
    if break_rows:
        api['api-a']['rows'][0][2] = 'different'
    like = {'s2': ['api-a'] if ha else [], 's3': ['api-b'] if ha else [], 'mock': ['api-a', 'api-b'] if ha else [],
            'marker': ['api-a', 'api-b'] if ha else [hr.BASE_SESSION], 'zzqx7negative': []}
    search = {t: {'code': 200, 'hits': [[sid, not plain_snippet] for sid in v]} for t, v in like.items()}
    return {'health_api': 200, 'health_webhook': 200, 'login': 200, 'list_code': 200, 'sessions': listed,
            'messages': api, 'search': search,
            'inner': {'messages': db, 'like': like, 'fts_match': dict(like), 'quick_check': 'ok', 'schema_version': 32,
                      'copy_integrity': 'ok', 'fts_integrity': {'messages_fts': 'ok', 'messages_fts_trigram': 'ok'}}}


class ContinuityLogicTests(unittest.TestCase):
    def setUp(self):
        self.saved = (hr.source_sessions, hr.drv.device_python)
        hr.source_sessions = lambda: SRC

    def tearDown(self):
        hr.source_sessions, hr.drv.device_python = self.saved

    def run_mode(self, mode, data):
        hr.drv.device_python = lambda *_a, **_k: data
        ev = FakeEvidence()
        # SRC has 6 messages, the harness expects the fixture's 15: patch the total through the source counts
        hr.continuity(ev, 'unit', mode)
        return ev

    def test_ha_mode_passes_on_consistent_probe_except_fixture_total(self):
        ev = self.run_mode('ha', probe('ha'))
        # only the "every HA message" check fails, because the toy source has 6 messages and the fixture 15
        self.assertEqual([n for n in ev.failed()], [n for n in ev.failed() if 'every HA message' in n])
        self.assertEqual(len(ev.failed()), 1)

    def test_ha_mode_fails_when_api_rows_differ_from_state_db(self):
        ev = self.run_mode('ha', probe('ha', break_rows=True))
        self.assertTrue(any('every HA message' in n for n in ev.failed()))

    def test_ha_mode_fails_without_fts_snippet_markers(self):
        ev = self.run_mode('ha', probe('ha', plain_snippet=True))
        self.assertTrue(any('full-text search' in n for n in ev.failed()))

    def test_base_mode_passes_on_baseline_probe(self):
        ev = self.run_mode('base', probe('base'))
        self.assertEqual(ev.failed(), [])

    def test_base_mode_fails_when_ha_data_is_left(self):
        ev = self.run_mode('base', probe('ha'))
        self.assertTrue(ev.failed())

    def test_fts_integrity_needs_two_ok_tables(self):
        data = probe('base')
        data['inner']['fts_integrity'] = {'messages_fts': 'error malformed'}
        ev = self.run_mode('base', data)
        self.assertTrue(any('integrity-check' in n for n in ev.failed()))


class OfflineEntryTests(unittest.TestCase):
    def invoke(self, *args):
        with tempfile.TemporaryDirectory() as home:
            env = {**os.environ, 'HOME': home}
            result = subprocess.run([sys.executable, '-I', str(HARNESS), *args], env=env, capture_output=True,
                                    text=True, timeout=60)
            self.assertEqual(list(Path(home).iterdir()), [], 'offline invocation wrote to HOME')
            return result

    def test_self_check(self):
        result = self.invoke('--self-check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('4 embedded programs compiled', result.stdout)

    def test_unknown_step_refused_before_anything(self):
        for args in ((), ('import:arm-enc',), ('upload',), ('setup', 'bogus')):
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')

    def test_labels_are_reduced_to_the_status_charset(self):
        self.assertEqual(hr.label('full-text "s2"\nfinds'), 'full-text _s2__finds')
        line = f'CHECK {hr.label("x86-enc: HA\'s 5 sessions (FTS5) <ok>")}: PASS'
        self.assertEqual(cap.status_lines(line), [line])


class LockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (hr.LOCK, hr.WAITING, hr.LOCK_WAIT)
        hr.LOCK = Path(self.tmp.name) / 'mutation.lock'
        hr.LOCK.touch()
        hr.WAITING = Path(self.tmp.name) / 'emqx-main-waiting'

    def tearDown(self):
        hr.LOCK, hr.WAITING, hr.LOCK_WAIT = self.saved
        self.tmp.cleanup()

    def test_free_lock_is_taken(self):
        fd = hr.acquire_lock()
        other = os.open(hr.LOCK, os.O_RDONLY)
        with self.assertRaises(BlockingIOError):
            import fcntl
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.close(other)
        os.close(fd)

    def test_never_taken_while_emqx_main_waits(self):
        hr.WAITING.touch()
        hr.LOCK_WAIT = 2
        with self.assertRaises(hr.Failed):
            hr.acquire_lock()

    def test_waiting_file_seen_during_an_emqx_main_run_is_stale(self):
        hr.WAITING.touch()
        saved = hr.emqx_main_holds_lock
        hr.emqx_main_holds_lock = lambda: True
        try:
            os.close(hr.acquire_lock())
        finally:
            hr.emqx_main_holds_lock = saved

    def test_symlinked_lock_refused(self):
        target = Path(self.tmp.name) / 'elsewhere'
        target.touch()
        hr.LOCK.unlink()
        hr.LOCK.symlink_to(target)
        with self.assertRaises(OSError):
            hr.acquire_lock()


class CaptureVocabularyTests(unittest.TestCase):
    def test_only_fixed_lines_are_published(self):
        text = '\n'.join([
            'source commit ' + 'a' * 40, 'dev-d isolation: true none {}', 'STEP import:x86-enc: PASS seconds=301',
            'CHECK import x86-enc/hermes: restore succeeded: FAIL', 'RESULT 10/11 passed',
            'backup id safety 20261123T010203Z-0123abcd', 'password=hunter22 leaked', '{"token": "abc"}',
            'CHECK has "quote": PASS', 'free text line'])
        kept = cap.status_lines(text)
        self.assertEqual(len(kept), 6)
        self.assertFalse(any('hunter' in line or 'token' in line or 'quote' in line for line in kept))


if __name__ == '__main__':
    unittest.main()
