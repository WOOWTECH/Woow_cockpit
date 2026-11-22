"""Local fixture transport only: no actual suspension, broker or lab calls."""
import json
import unittest
from unittest.mock import patch

from woowbackup.ha_emqx import SUSPEND_SYS_EXPR, TICKER_STATUS_EXPR
import emqx_broker_owner_target as target
from emqx_runtime_live import IMAGE

BROKER = 'woowbk-emqx-workload-0123456789ab'
CID = 'a' * 64
PID = '<0.123.0>'


class FreshTickerTests(unittest.TestCase):
    def transport(self, calls, *, replace_at=None, bad_status_at=None):
        counts = {'inspect': 0, 'status': 0}
        def checked(*args):
            calls.append(args)
            if args == ('inspect', BROKER):
                counts['inspect'] += 1
                return json.dumps([{'Id': 'b' * 64 if counts['inspect'] == replace_at else CID,
                    'Image': IMAGE, 'State': {'Running': True}, 'Mounts': [],
                    'HostConfig': {'NetworkMode': 'none','PortBindings': {},
                                   'LogConfig': {'Type': 'none'}}}]).encode()
            self.assertEqual(args[:4], ('exec', BROKER, 'emqx', 'eval'))
            expr = args[4]
            if expr == SUSPEND_SYS_EXPR:
                return ('WOOWSYS:' + PID + ':suspended\nok').encode()
            if expr == TICKER_STATUS_EXPR.replace('{pid}', PID):
                counts['status'] += 1
                return b'changed' if counts['status'] == bad_status_at else b'ticker_unchanged'
            self.assertIn('[] = emqx_cm:all_channels()', expr)
            return b'OWNERNOCLIENTSok'
        return checked

    def test_fresh_identity_and_actual_ticker_status_surround_consumption(self):
        calls, checks = [], {}
        with patch.object(target, 'checked', self.transport(calls)):
            with target.fresh_target_quiescence(broker=BROKER, owned_container_id=CID,
                                               clients=[], checks=checks):
                self.assertTrue(checks['fresh_ticker_identity_suspended_before'])
                self.assertNotIn('fresh_ticker_identity_suspended_after', checks)
        self.assertTrue(checks['fresh_ticker_identity_suspended_after'])
        self.assertTrue(checks['no_clients_after_capture'])
        self.assertEqual(sum(call[-1] == SUSPEND_SYS_EXPR for call in calls), 1)
        self.assertEqual(sum(call[-1] == TICKER_STATUS_EXPR.replace('{pid}', PID) for call in calls), 2)
        self.assertNotIn(PID, json.dumps(checks))
        self.assertFalse(any('sys:resume' in str(call) for call in calls))

    def test_production_names_and_missing_owned_identity_never_suspend(self):
        for broker, cid in (('production', CID), ('emqx-new', CID), (BROKER, ''), (BROKER, None)):
            with patch.object(target, 'checked') as checked:
                with self.subTest(), self.assertRaises(RuntimeError):
                    with target.fresh_target_quiescence(broker=broker, owned_container_id=cid,
                                                       clients=[], checks={}):
                        pass
                checked.assert_not_called()

    def test_replaced_container_or_resumed_ticker_refuses(self):
        for options in ({'replace_at': 1}, {'replace_at': 3},
                        {'bad_status_at': 1}, {'bad_status_at': 2}):
            calls, checks = [], {}
            with patch.object(target, 'checked', self.transport(calls, **options)):
                with self.subTest(options=options), self.assertRaises(RuntimeError):
                    with target.fresh_target_quiescence(broker=BROKER, owned_container_id=CID,
                                                       clients=[], checks=checks):
                        pass
            self.assertNotIn('fresh_ticker_identity_suspended_after', checks)

    def test_own_fixture_writer_blocks_ticker_and_capture(self):
        calls = []
        with patch.object(target, 'checked', self.transport(calls)):
            with self.assertRaisesRegex(RuntimeError, '^fixture-writer-not-quiesced$'):
                with target.fresh_target_quiescence(broker=BROKER, owned_container_id=CID,
                                                   clients=['own-writer'], checks={}):
                    pass
        self.assertFalse(any(call[-1] == SUSPEND_SYS_EXPR for call in calls))

    def test_native_expression_enforces_receipts_and_ticker_not_python_assertion(self):
        from pathlib import Path
        source = Path(target.__file__).with_name('emqx_owner_target.expr').read_text()
        self.assertIn('case Count =:= N', source)
        self.assertIn('case N2 =:= N andalso CountAfter =:= N', source)
        self.assertIn('case ReceiptBefore =:= ReceiptAfter', source)
        self.assertIn('case SchemaBefore =:= SchemaAfter', source)
        self.assertIn('case Before =:= After', source)
        self.assertIn('case Providers =:= ProvidersAfter', source)
        self.assertEqual(source.count('sys:get_status(TickerPid,5000)'), 2)
        self.assertIn('case whereis(emqx_sys) =:= TickerPid', source)
