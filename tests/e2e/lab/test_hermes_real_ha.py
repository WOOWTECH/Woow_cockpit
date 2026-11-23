"""Offline tests of the hermes-real harness: no device, no secret, no lock is touched."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import json

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
        self.secrets = object()

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
        self.saved = (hr.source_sessions, hr.drv.device_python, hr.drv.event_device_python)
        hr.source_sessions = lambda: SRC
        self.calls = []

    def tearDown(self):
        hr.source_sessions, hr.drv.device_python, hr.drv.event_device_python = self.saved
        hr.drv.ISSUED_SESSIONS.clear()

    def run_mode(self, mode, data):
        def event_probe(script, request, secrets, expected_auth, **_k):
            self.calls.append((script is hr.CONTINUITY, secrets, expected_auth))
            return data
        hr.drv.event_device_python = event_probe
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


def real_secrets(directory):
    """A real drv.Secrets over synthetic files (lane names, nothing from the lab)."""
    env = Path(directory) / 'synthetic-creds.env'
    env.write_text(''.join(f'{n}=synthetic-lane-{i:04d}\n' for i, n in enumerate(hr.LANE_SECRETS)), encoding='utf-8')
    markers = Path(directory) / 'synthetic-markers.json'
    markers.write_text('{}', encoding='utf-8')
    return hr.drv.Secrets([env], markers)


def jar_with(*cookies):
    import http.cookiejar
    jar = http.cookiejar.CookieJar()
    for name, value in cookies:
        jar.set_cookie(http.cookiejar.Cookie(0, name, value, None, False, '127.0.0.1', False, False, '/', True, False,
                                             None, False, None, None, {}))
    return jar


def fake_b1_source():
    """The keys verify_hermes reads from the b1 source summary (toy values; the real one lives in the lab)."""
    return {'hermes': {'created_by_b1': {'memory_markers': ['memory m1']}, 'messages_per_session': {},
                       'memories_sha256': {'MEMORY.md': 'toy', 'USER.md': 'toy'}, 'skills_SKILL_md': 0,
                       'cron_jobs': [{'id': 'j1', 'name': 'toy'}], 'config': {'model': {'base_url': 'x', 'default': 'm'}}}}


class IssuedCredentialTests(unittest.TestCase):
    """Dashboard session cookies issued by every dashboard login are registered and must reach the leak scan."""

    def tearDown(self):
        hr.drv.ISSUED_SESSIONS.clear()

    def test_continuity_runs_through_the_acknowledged_transport_and_declares_its_login(self):
        case = ContinuityLogicTests('test_base_mode_passes_on_baseline_probe')
        case.setUp()
        try:
            ev = case.run_mode('base', probe('base'))
            [(is_continuity, recorder, expected)] = case.calls
            self.assertTrue(is_continuity)
            self.assertIs(recorder.secrets, ev.secrets)
            self.assertEqual(expected, hr.ISSUED_AUTH)
            self.assertEqual([label for label, _v in hr.drv.ISSUED_SESSIONS], ['unit (continuity dashboard login)'])
            self.assertIs(hr.drv.ISSUED_SESSIONS[0][1], recorder.values)
        finally:
            case.tearDown()

    def run_issue(self, jar, code, tag):
        events = []
        scope = {'emit': lambda kind, **fields: events.append(dict(type=kind, **fields))}
        exec(compile(hr.drv.HERMES_ISSUE, 'HERMES_ISSUE', 'exec'), scope)
        return scope['issue_events'](jar, code, tag), events

    def test_issue_events_hands_over_both_cookies_in_order_with_prefixed_names(self):
        names, events = self.run_issue(jar_with(('__Host-hermes_session_rt', 'synthetic-refresh-0001'),
                                                ('hermes_session_at', 'synthetic-access-0001'),
                                                ('hermes_session_provider', 'basic')), 200, 'device-')
        self.assertEqual(names, ['hermes_session_at', 'hermes_session_rt'])
        self.assertEqual(events, [
            {'type': 'auth', 'source': '/auth/password-login#device-at', 'status': 200,
             'credentials': {'hermes_session_at': 'synthetic-access-0001'}},
            {'type': 'auth', 'source': '/auth/password-login#device-rt', 'status': 200,
             'credentials': {'hermes_session_rt': 'synthetic-refresh-0001'}}])

    def test_issue_events_reports_nothing_issued_as_404(self):
        names, events = self.run_issue(jar_with(), 401, 'ha-')
        self.assertEqual(names, [])
        self.assertEqual([(e['source'], e['status'], e['credentials']) for e in events],
                         [('/auth/password-login#ha-at', 404, {}), ('/auth/password-login#ha-rt', 404, {})])

    def test_programs_carry_the_issuer_and_end_through_finish(self):
        self.assertIn(hr.drv.HERMES_ISSUE, hr.CONTINUITY)
        self.assertIn(hr.drv.HERMES_ISSUE, hr.drv.HERMES_PROBE)
        self.assertTrue(hr.drv.HERMES_PROBE.rstrip().endswith('finish(out)'))
        self.assertIn('issue_events(jar, code, "device-")', hr.drv.HERMES_PROBE)
        self.assertIn('issue_events(jar_ha, code_ha, "ha-")', hr.drv.HERMES_PROBE)
        self.assertEqual([s for s, _f, _r in hr.drv.HERMES_AUTH],
                         ['/auth/password-login#device-at', '/auth/password-login#device-rt',
                          '/auth/password-login#ha-at', '/auth/password-login#ha-rt'])
        self.assertEqual([r for _s, _f, r in hr.drv.HERMES_AUTH], [True, False, False, False])

    def test_probe_children_never_read_the_acknowledgement_pipe(self):
        """In event mode the probe's stdin stays open for the owner's acks: a child that inherited it would block
        (or eat an ack). A fake podman that reads its stdin to EOF proves pexec() and secret() give it /dev/null."""
        transport = load('b1_event_transport', HERE / 'b1_event_transport.py')
        program = hr.drv.PROBE_COMMON + ('rc, so, se = pexec("hermes-agent", "find")\n'
                                         'value = secret("synthetic-name")\n'
                                         'finish({"rc": rc, "so": so.strip(), "secret": value})\n')
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'podman'
            fake.write_text('#!/bin/sh\ncat >/dev/null\necho child-saw-eof\n', encoding='utf-8')
            fake.chmod(0o700)
            argv = ['env', f'PATH={tmp}:/usr/bin:/bin', sys.executable, '-I', '-c', program]
            summary = transport.run_events(argv, {'__events': True}, lambda v: None, (), timeout=20)
        self.assertEqual(summary, {'rc': 0, 'so': 'child-saw-eof', 'secret': 'child-saw-eof'})

    def test_b1_probe_logins_are_declared_registered_and_checked(self):
        saved = (hr.drv.event_device_python, hr.drv.source)
        src = fake_b1_source()
        hr.drv.source = lambda _m: src
        seen = {}

        def event_probe(script, request, secrets, expected_auth, **_k):
            seen.update(script=script, expected=expected_auth, declared=len(hr.drv.ISSUED_SESSIONS))
            secrets.register_observed('synthetic-device-access-0001')
            return {'health_api': 200, 'health_webhook': 200, 'dashboard_login_device_password': [200, 200],
                    'dashboard_login_ha_password': [401, 401], 'issued_device': ['hermes_session_at'],
                    'issued_ha': []}
        hr.drv.event_device_python = event_probe
        try:
            with tempfile.TemporaryDirectory() as tmp:
                args = type('A', (), {})()
                args.secrets = real_secrets(tmp)
                ev = FakeEvidence()
                hr.drv.verify_hermes(ev, args, 'x86', 'unit')
                self.assertIs(seen['script'], hr.drv.HERMES_PROBE)
                self.assertEqual(seen['expected'], hr.drv.HERMES_AUTH)
                self.assertEqual(seen['declared'], 1)   # declared before the probe ran
                self.assertIn('synthetic-device-access-0001', args.secrets.secret_values())
                self.assertEqual(hr.drv.issued_session_gaps(args.secrets), [])
                passed = dict(ev.results)
                self.assertTrue(passed['unit: the dashboard login issued an access cookie that is registered for '
                                       'redaction and the leak scan'])
                self.assertTrue(passed['unit: the dashboard refuses HA\'s dashboard password (the device\'s secret '
                                       'wins)'])
        finally:
            hr.drv.event_device_python, hr.drv.source = saved

    def test_b1_probe_fails_the_refusal_check_when_ha_password_issues_a_cookie(self):
        saved = (hr.drv.event_device_python, hr.drv.source)
        src = fake_b1_source()
        hr.drv.source = lambda _m: src

        def event_probe(script, request, secrets, expected_auth, **_k):
            secrets.register_observed('synthetic-device-access-0002')
            secrets.register_observed('synthetic-ha-access-0002')
            return {'dashboard_login_device_password': [200, 200], 'dashboard_login_ha_password': [401, 200],
                    'issued_device': ['hermes_session_at'], 'issued_ha': ['hermes_session_at']}
        hr.drv.event_device_python = event_probe
        try:
            with tempfile.TemporaryDirectory() as tmp:
                args = type('A', (), {})()
                args.secrets = real_secrets(tmp)
                ev = FakeEvidence()
                hr.drv.verify_hermes(ev, args, 'x86', 'unit')
                self.assertIn('synthetic-ha-access-0002', args.secrets.secret_values())
                self.assertIn('unit: the dashboard refuses HA\'s dashboard password (the device\'s secret wins)',
                              ev.failed())
        finally:
            hr.drv.event_device_python, hr.drv.source = saved

    def test_gaps_name_a_declared_login_that_registered_nothing_or_an_unknown_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            secrets = real_secrets(tmp)
            ok = hr.drv.IssuedRecorder(secrets)
            ok.register_observed('synthetic-access-0003')
            hr.drv.ISSUED_SESSIONS.extend([('a', ok.values), ('b', []), ('c', ['synthetic-never-registered'])])
            self.assertEqual(hr.drv.issued_session_gaps(secrets), ['b', 'c'])

    def test_duplicate_issued_values_across_logins_are_not_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            secrets = real_secrets(tmp)
            first, second = hr.drv.IssuedRecorder(secrets), hr.drv.IssuedRecorder(secrets)
            first.register_observed('synthetic-same-0004')
            second.register_observed('synthetic-same-0004')
            hr.drv.ISSUED_SESSIONS.extend([('first', first.values), ('second', second.values)])
            self.assertEqual(hr.drv.issued_session_gaps(secrets), [])
            self.assertEqual(second.values, ['synthetic-same-0004'])

    def producer(self, events):
        code = ("import json,sys\nreq=json.loads(sys.stdin.readline())\n"
                "for e in json.loads(sys.argv[1]):\n print(json.dumps(e),flush=True)\n"
                " assert sys.stdin.readline()=='OK\\n'\n")
        return [sys.executable, '-I', '-c', code, json.dumps(events)]

    def stream(self, rt):
        events = [{'type': 'auth', 'sequence': 0, 'source': '/auth/password-login#at', 'status': 200,
                   'credentials': {'hermes_session_at': 'synthetic-access-0001'}},
                  {'type': 'auth', 'sequence': 1, 'source': '/auth/password-login#rt',
                   'status': 200 if rt else 404,
                   'credentials': {'hermes_session_rt': 'synthetic-refresh-0001'} if rt else {}},
                  {'type': 'summary', 'sequence': 2, 'data': {'login': 200}},
                  {'type': 'end', 'sequence': 3}]
        return events

    def test_event_shapes_continuity_emits_are_accepted_and_registered(self):
        transport = load('b1_event_transport', HERE / 'b1_event_transport.py')
        for rt in (True, False):
            got = []
            summary = transport.run_events(self.producer(self.stream(rt)), {'x': 1}, got.append, hr.ISSUED_AUTH,
                                           timeout=30)
            self.assertEqual(summary, {'login': 200})
            self.assertEqual(got, ['synthetic-access-0001'] + (['synthetic-refresh-0001'] if rt else []))

    def test_missing_access_cookie_breaks_coverage(self):
        transport = load('b1_event_transport', HERE / 'b1_event_transport.py')
        events = self.stream(False)
        events[0] = dict(events[0], status=404, credentials={})
        with self.assertRaises(transport.Incomplete):
            transport.run_events(self.producer(events), {}, lambda v: None, hr.ISSUED_AUTH, timeout=30)

    def b1_stream(self, *, device_at=True, ha_code=401, ha_cookie=False):
        def auth(seq, source, field, value, ok_code):
            present = value is not None
            return {'type': 'auth', 'sequence': seq, 'source': source, 'status': ok_code if present else 404,
                    'credentials': {field: value} if present else {}}
        events = [auth(0, '/auth/password-login#device-at', 'hermes_session_at',
                       'synthetic-device-0005' if device_at else None, 200),
                  auth(1, '/auth/password-login#device-rt', 'hermes_session_rt', None, 200),
                  auth(2, '/auth/password-login#ha-at', 'hermes_session_at',
                       'synthetic-ha-0005' if ha_cookie else None, ha_code),
                  auth(3, '/auth/password-login#ha-rt', 'hermes_session_rt', None, ha_code),
                  {'type': 'summary', 'sequence': 4, 'data': {'probe': 1}}, {'type': 'end', 'sequence': 5}]
        return events

    def test_b1_probe_event_shapes_through_the_real_transport(self):
        transport = load('b1_event_transport', HERE / 'b1_event_transport.py')
        got = []
        self.assertEqual(transport.run_events(self.producer(self.b1_stream()), {}, got.append, hr.drv.HERMES_AUTH,
                                              timeout=30), {'probe': 1})
        self.assertEqual(got, ['synthetic-device-0005'])
        got = []   # a wrongly accepted HA password: its cookie is still registered (the refusal check fails)
        transport.run_events(self.producer(self.b1_stream(ha_code=200, ha_cookie=True)), {}, got.append,
                             hr.drv.HERMES_AUTH, timeout=30)
        self.assertEqual(got, ['synthetic-device-0005', 'synthetic-ha-0005'])
        with self.assertRaises(transport.Incomplete):   # this device's login handed over no access cookie
            transport.run_events(self.producer(self.b1_stream(device_at=False)), {}, lambda v: None,
                                 hr.drv.HERMES_AUTH, timeout=30)

    def test_leak_scan_refuses_while_a_declared_login_source_is_missing(self):
        saved = (hr.load_kit, hr.drv.device_python, hr.drv.scan_host_evidence)
        hr.load_kit = lambda _args: None
        FakeEvidence.dir = Path(tempfile.gettempdir())
        seen = {}
        hr.drv.device_python = lambda script, request, **_k: seen.setdefault('request', request) and {
            'scanned': 1, 'names': 1, 'hits': 0}
        hr.drv.scan_host_evidence = lambda *_a: {'hits': 0}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                args = type('A', (), {})()
                args.secrets = real_secrets(tmp)
                registered = hr.drv.IssuedRecorder(args.secrets)
                registered.register_observed('synthetic-access-0006')
                missing = []
                hr.drv.ISSUED_SESSIONS.extend([('before (continuity dashboard login)', registered.values),
                                               ('after import (b1 probe dashboard login)', missing)])
                with self.assertRaises(hr.Failed):
                    hr.step_leaks(FakeEvidence(), args)
                self.assertNotIn('request', seen)   # refused before any scan
                hr.drv.IssuedRecorder(args.secrets).register_observed('synthetic-access-0007')
                with self.assertRaises(hr.Failed):   # registered elsewhere, but this source's own list is empty
                    hr.step_leaks(FakeEvidence(), args)
                missing.append('synthetic-access-0007')
                ev = FakeEvidence()
                hr.step_leaks(ev, args)
                values = set(seen['request']['secrets'].values())
                self.assertTrue({'synthetic-access-0006', 'synthetic-access-0007'} <= values)
                self.assertTrue(all(ok for _n, ok in ev.results))
                self.assertTrue(any('2 declared dynamic sources, 2 issued values' in n for n, _ok in ev.results))
        finally:
            hr.load_kit, hr.drv.device_python, hr.drv.scan_host_evidence = saved
            del FakeEvidence.dir


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

    def test_file_name_parts_never_hold_a_separator(self):
        self.assertEqual(hr.slug('import x86-enc/hermes after restore'), 'import-x86-enc-hermes-after-restore')
        self.assertNotIn('/', hr.slug('../../etc/passwd'))

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

    def _fake_emqx(self, lock):
        code = ('import fcntl, os, sys, time\n'
                'fd = os.open(sys.argv[2], os.O_RDONLY)\n'
                'if sys.argv[3] == "lock":\n    fcntl.flock(fd, fcntl.LOCK_EX)\n'
                'print("ready", flush=True)\ntime.sleep(30)\n')
        proc = subprocess.Popen([sys.executable, '-c', code, 'run_emqx_real_owner.sh', str(hr.LOCK), lock],
                                stdout=subprocess.PIPE, text=True)
        self.assertEqual(proc.stdout.readline().strip(), 'ready')
        return proc

    def test_an_emqx_process_that_only_opened_the_lock_is_not_holding_it(self):
        proc = self._fake_emqx('open')
        try:
            self.assertFalse(hr.emqx_main_holds_lock())
        finally:
            proc.kill()
            proc.wait()

    def test_an_emqx_process_holding_the_flock_is_detected(self):
        proc = self._fake_emqx('lock')
        try:
            self.assertTrue(hr.emqx_main_holds_lock())
        finally:
            proc.kill()
            proc.wait()

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
