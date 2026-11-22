"""Generated real Capture + target contracts + evidence IO; no native/lab/restore."""
import contextlib
import io
import json
import unittest
from unittest.mock import Mock, patch

import emqx_owner_source_capture as source_owner
from emqx_owner_preflight import owner_preflight
from emqx_private_boundary import PrivateFailure
from emqx_runtime_workflow import SOURCE_CATEGORIES
from emqx_target_capture import ObservedTargetReaders
from test_emqx_source_cold_capture import decoder, SECRET


class JoinTests(unittest.TestCase):
    def setUp(self):
        from test_emqx_owner_source_capture import OwnerHarnessTests
        from test_emqx_complete_target_capture import CompleteTargetTests
        # Real encrypted generated archive and source_binding; native contracts
        # are generated adapters only, never claims of native/broker validation.
        OwnerHarnessTests.fixture(self)
        self.parser = OwnerHarnessTests.hocon
        fixture = CompleteTargetTests()
        observation, inventory, exports = fixture.sources()
        self.readers = fixture.capture(observation, inventory, exports, [])
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir(mode=0o700)
        self.streams = []
        self.calls = []
        self.documents = {}
        for category in self.readers:
            with self.readers[category]() as stream:
                self.documents[category] = stream.read()
        self.tracked_readers()
        self.transport = Mock(side_effect=lambda username, password:
            (200, 'application/json', io.BytesIO(b'{"token":"generated-private-login-token"}')))

    def tracked_readers(self, late=None):
        class Stream(io.BytesIO):
            def finish(stream):
                stream.finished = True
                if stream.category == late:
                    raise RuntimeError('generated-private-finish-error')
        for category in self.readers:
            def opened(category=category):
                self.calls.append(category)
                stream = Stream(self.documents[category])
                stream.category, stream.finished = category, False
                self.streams.append(stream)
                return stream
            self.readers[category] = opened

    @contextlib.contextmanager
    def source(self):
        with patch.object(source_owner, 'native_hocon', self.parser), \
             patch.object(source_owner, 'native_cold_history', decoder):
            with source_owner.capture_owner_source(self.path, password=self.password,
                    expected_sha256=self.digest, spool_directory=self.spool,
                    required_encryption='v3') as result:
                yield result

    def join(self, captured, **overrides):
        kwargs = dict(captured=captured, target_readers=self.readers,
            target_generation='synthetic-generation', private_transport=self.transport,
            username=b'generated-login-user', password=b'generated-login-password',
            evidence_directory=self.evidence, evidence_name='joined-preflight.json')
        kwargs.update(overrides)
        return owner_preflight(**kwargs)

    def test_actual_capture_exact_target_bytes_seal_login_scanned_names_and_readonly_replay(self):
        with self.source() as (captured, binding):
            with self.assertRaises(PrivateFailure):
                captured.registry.summary()
            supply = captured.supply_target_documents
            def finished_before_supply(documents):
                self.assertEqual(self.calls, sorted(self.readers))
                self.assertTrue(all(s.closed and s.finished for s in self.streams))
                supply(documents)
            with patch.object(captured, 'supply_target_documents', side_effect=finished_before_supply) as supplied:
                session = self.join(captured)
                supplied.assert_called_once_with(self.documents)
            self.assertEqual(self.calls, sorted(self.readers))
            self.assertTrue(all(s.closed and s.finished for s in self.streams))
            self.transport.assert_called_once_with(b'generated-login-user', b'generated-login-password')
            summary = captured.registry.summary()
            self.assertEqual({key: session.coverage[key] for key in SOURCE_CATEGORIES},
                             {key: summary[key] for key in SOURCE_CATEGORIES})
            raw = (self.evidence / 'joined-preflight.json').read_bytes()
            self.assertEqual((self.evidence/'joined-preflight.json').stat().st_mode&0o777, 0o600)
            doc = json.loads(raw)
            self.assertEqual(doc['phase'], 'preflight')
            self.assertEqual(doc['result'], 'passed')
            self.assertIsInstance(doc['coverage'], list)
            self.assertEqual(len(doc['coverage']), 8)
            session.registry.scan(raw)
            for secret in (SECRET, b'generated-login-password', b'generated-private-login-token',
                           b'synthetic-private-emqx_admin_jwt', b'synthetic-private-emqx_acl',
                           b'synthetic-password'):
                with self.subTest(secret=secret), self.assertRaises(PrivateFailure):
                    session.registry.scan(secret)
                self.assertNotIn(secret, raw)
            with binding['open']('fedcba98_woow-emqx') as replay:
                self.assertEqual(replay.read(), self.raw)
                self.assertFalse(replay.writable())
                with self.assertRaises(io.UnsupportedOperation):
                    replay.write(b'changed')
            # Existing Capture is single-use; the join did not invoke it again.
            with self.assertRaises(PrivateFailure):
                captured(binding)
        self.assertEqual(list(self.spool.iterdir()), [])
        with self.assertRaises(PrivateFailure):
            with binding['open']('fedcba98_woow-emqx'):
                self.fail('closed replay escaped')

    def test_wrong_generation_or_missing_persisted_and_missing_category_emit_nothing(self):
        for change in ('generation', 'persisted', 'missing', 'plain-dict'):
            readers = ObservedTargetReaders(self.readers)
            readers.generation = self.readers.generation
            readers.persisted_values = self.readers.persisted_values
            if change == 'generation': readers.generation = 'wrong-generation'
            if change == 'persisted': readers.persisted_values = None
            if change == 'missing': del readers['tls']
            if change == 'plain-dict': readers = dict(readers)
            with self.subTest(change=change), self.source() as (captured, _):
                with self.assertRaisesRegex(PrivateFailure, '^private-preflight-refused$'):
                    self.join(captured, target_readers=readers)
                with self.assertRaises(PrivateFailure): captured.registry.summary()
            self.assertEqual(self.calls, [])
            self.transport.assert_not_called()
            self.assertEqual(list(self.evidence.iterdir()), [])

    def test_late_finish_oversize_and_invalid_snapshot_refuse_before_registration_or_login(self):
        for change in ('finish', 'oversize', 'incomplete'):
            self.calls.clear(); self.streams.clear()
            original = self.documents['api-keys']
            if change == 'oversize': self.documents['api-keys'] = b'x'*65537
            if change == 'incomplete': self.documents['api-keys'] = b'{"schema":1,"complete":false,"records":[]}'
            self.tracked_readers(late='api-keys' if change == 'finish' else None)
            with self.subTest(change=change), self.source() as (captured, _):
                with self.assertRaises(PrivateFailure): self.join(captured)
                self.assertFalse(captured._target_attempted)
                with self.assertRaises(PrivateFailure): captured.registry.summary()
            self.assertTrue(all(stream.closed for stream in self.streams))
            self.transport.assert_not_called()
            self.assertEqual(list(self.evidence.iterdir()), [])
            self.documents['api-keys'] = original

    def test_generation_changes_during_stream_finish_refuse_before_source_completion(self):
        original = self.readers['tls']
        def changed():
            stream = original()
            finish = stream.finish
            def changed_finish():
                finish()
                self.readers.generation = 'changed-during-read'
            stream.finish = changed_finish
            return stream
        self.readers['tls'] = changed
        with self.source() as (captured, _):
            with self.assertRaises(PrivateFailure): self.join(captured)
            self.assertFalse(captured._target_attempted)
        self.assertTrue(all(stream.closed for stream in self.streams))
        self.transport.assert_not_called()
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_cancellation_closes_partial_snapshot_and_no_fake_capture_is_accepted(self):
        class Cancelled(io.BytesIO):
            def read(self, maximum):
                raise KeyboardInterrupt('generated-private-cancel')
        stream = Cancelled(b'generated-only')
        self.readers['api-keys'] = lambda: stream
        with self.source() as (captured, _):
            with self.assertRaisesRegex(PrivateFailure, '^private-preflight-cancelled$'):
                self.join(captured)
            self.assertFalse(captured._target_attempted)
        self.assertTrue(stream.closed)
        with self.assertRaises(PrivateFailure): self.join(object())
        self.transport.assert_not_called()
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_failed_login_closes_response_and_emits_nothing(self):
        response = io.BytesIO(b'generated-private-login-error')
        self.transport.side_effect = None
        self.transport.return_value = (401, 'application/json', response)
        with self.source() as (captured, _):
            with self.assertRaises(PrivateFailure): self.join(captured)
            self.assertTrue(response.closed)
            self.assertTrue(all(stream.closed and stream.finished for stream in self.streams))
        self.assertEqual(list(self.evidence.iterdir()), [])
        self.assertEqual(list(self.spool.iterdir()), [])

    def test_full_persisted_scan_can_refuse_exact_evidence_without_file_creation(self):
        # A native captured string that collides with fixed output must refuse,
        # even though every category and login succeeded. No scanner exemption.
        companion = self.readers.persisted_values
        companion._values += (b'preflight',)
        with self.source() as (captured, _):
            with self.assertRaises(PrivateFailure): self.join(captured)
        self.transport.assert_called_once()
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_closed_capture_and_second_completion_refuse(self):
        with self.source() as (captured, _):
            self.join(captured)
            with self.assertRaises(PrivateFailure): self.join(captured, evidence_name='second.json')
        self.calls.clear()
        with self.assertRaises(PrivateFailure): self.join(captured, evidence_name='closed.json')
        self.assertEqual(self.calls, [])
        self.assertEqual(set(p.name for p in self.evidence.iterdir()), {'joined-preflight.json'})
