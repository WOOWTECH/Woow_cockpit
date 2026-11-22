"""Code-only local diagnostics integration; no broker/native runtime execution."""
from contextlib import contextmanager
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import emqx_broker_owner_target as adapter


class NativeDiagnosticTests(unittest.TestCase):
    def test_inner_stage_reason_frames_only_expose_fixed_enums(self):
        cases = (('table_storage','storage_null_copies'), ('table_storage','storage_external'),
            ('table_fragments','fragments_unsupported'), ('table_type','table_type_unsupported'),
            ('table_lock','no_exists'), ('table_fold','not_active'),
            ('table_row_terms','unsupported_term'), ('table_schema','bad_type'),
            ('schema_terms','function_clause'), ('native_tables','native_refused'))
        for stage, reason in cases:
            with self.subTest(stage=stage, reason=reason):
                result = adapter.fixed_native_diagnostic(
                    f'WOOWTARGETFAIL:{stage}:{reason}:ENDok\n'.encode())
                self.assertEqual(result, {'native_fixed_stage': stage, 'native_fixed_reason': reason})

    def test_raw_table_or_abort_payload_never_enters_diagnostics(self):
        for raw in (b'WOOWTARGETFAIL:emqx_admin_jwt:private_abort_value:ENDok',
                    b'WOOWTARGETFAIL:table_storage:private_password:ENDok'):
            result = adapter.fixed_native_diagnostic(raw)
            self.assertNotIn('private_', json.dumps(result))
            self.assertNotIn('emqx_admin_jwt', json.dumps(result))
            self.assertEqual(result['native_fixed_reason'], 'native_refused')
        for raw in (b'WOOWTARGETFAIL:table_fold:{no_exists,private_table}:ENDok',
                    b'WOOWTARGETFAIL:table_fold:no_exists:private_payload:ENDok',
                    b'WOOWTARGETFAIL:table_fold:no_exists:ENDok\nprivate_payload',
                    b'WOOWTARGETFAIL:' + b'a' * 161, b'\xff', None):
            self.assertIsNone(adapter.fixed_native_diagnostic(raw))

    def test_abort_frame_reaches_report_without_leaking_stderr_or_table(self):
        @contextmanager
        def fake_capture(*, broker, checked, quiesce):
            checked('exec', broker, 'emqx', 'eval', 'FixedPublicExpression')
            raise RuntimeError('fixture-stop-before-registration')
            yield
        report = {'checks': {}}
        response = SimpleNamespace(returncode=0,
            stdout=b'WOOWTARGETFAIL:table_storage:storage_external:ENDok',
            stderr=b'private-table-and-abort-payload')
        with patch.object(adapter, 'podman', return_value=response), \
             patch.object(adapter, 'broker_target_readers', fake_capture):
            with self.assertRaisesRegex(RuntimeError, '^fixture-stop-before-registration$'):
                adapter.run_owner_target(Path('/fixture-not-opened'), 'fixture-broker', [], report,
                                         owned_container_id='a' * 64)
        self.assertEqual(report['native_fixed_stage'], 'table_storage')
        self.assertEqual(report['native_fixed_reason'], 'storage_external')
        self.assertNotIn('private', json.dumps(report))
        self.assertNotIn('native_fixed_variable', report)
        self.assertNotIn('actual_native_expression_and_projection', report['checks'])

    def test_native_source_stage_allowlists_match_and_unknown_storage_still_refuses(self):
        expression = Path(adapter.__file__).with_name('emqx_owner_target.expr').read_text()
        stages = set(re.findall(r'put\(woow_target_stage, ([a-z_]+)\)', expression))
        self.assertEqual(stages, adapter.NATIVE_STAGES)
        source_stage_list = re.search(r'lists:member\(S,\[([^]]+)\]', expression)[1]
        self.assertEqual(set(re.findall(r'[a-z_]+', source_stage_list)), adapter.NATIVE_STAGES)
        source_reason_list = re.search(r'lists:member\(Code0,\[([^]]+)\]', expression)[1]
        self.assertEqual(set(re.findall(r'[a-z_]+', source_reason_list)), adapter.NATIVE_REASONS)
        storage = expression.split('case Storage of',1)[1].split('end,',1)[0]
        self.assertIn('ram_copies -> ok; disc_copies -> ok; disc_only_copies -> ok;', storage)
        self.assertIn('null_copies -> error(storage_null_copies)', storage)
        self.assertIn('{ext,_,_} -> error(storage_external)', storage)
        self.assertIn('put(woow_target_failure,{SafeStage(get(woow_target_stage)),ReasonCode(InnerReason,0)})', expression)
        self.assertIn('erlang:raise(InnerClass,InnerReason,InnerStack)', expression)
        self.assertIn('erase(woow_target_failure)', expression)
        self.assertNotIn('mnesia:abort(', expression)
        self.assertNotIn('{atomic,{Definitions,Rows}} = mnesia:transaction', expression)
        self.assertIn('{aborted,AbortReason} ->', expression)
        self.assertIn('ReasonCode(AbortReason,0)', expression)
        # The only diagnostic print formats stage/code, never abort/table values.
        diagnostic = expression.split('io:format("WOOWTARGETFAIL:',1)[1]
        self.assertIn('atom_to_binary(SafeStage(get(woow_target_stage))),atom_to_binary(Code)', diagnostic)
        for private in ('AbortReason','InnerReason','Storage','ReasonCode(Reason,0)'):
            self.assertNotIn(private, diagnostic)
