"""Count gate + build observer wiring only; no broker, lab or source values."""
from contextvars import copy_context
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from woowbackup import ha_emqx as product
from woowbackup.errors import BackupError
import emqx_candidate_stage as stages


class RowCountDiagnosticTests(unittest.TestCase):
    def test_gate_bounds_identical_with_observer_all_tables_and_edges(self):
        for table in product.TABLES:
            for source in (-1,0,2):
                for seed in (-1,0,1):
                    for target in (-1,0,1,2,3,4):
                        with self.subTest(table=table,source=source,seed=seed,target=target):
                            args=({table:source},{table:seed},{table:target})
                            expected=product.check_counts(*args);observed=[]
                            self.assertEqual(product.check_counts(*args,observe=lambda *v:observed.append(v)),expected)
                            allowed=source<0 or source<=target<=source+max(seed,0)
                            self.assertEqual(bool(expected),not allowed)
                            self.assertEqual(observed,[] if allowed else [(table,'underflow' if target<source else 'overflow')])

    def test_unknown_keys_and_source_absence_cannot_become_diagnostics(self):
        seen=[]
        product.check_counts({'generated-private-table':123456,'emqx_acl':-1},{},{},observe=lambda *v:seen.append(v))
        self.assertEqual(seen,[])
        self.assertEqual(product.check_counts({'emqx_acl':1},{},{},observe=lambda *v:seen.append(v)),
                         product.check_counts({'emqx_acl':1},{},{}))
        self.assertEqual(seen,[('emqx_acl','underflow')])

    def test_build_calls_actual_gate_and_fixed_stage_without_counts_or_error_text(self):
        work=SimpleNamespace(addon_info=lambda _:SimpleNamespace(version='5.9.0'),phase=lambda _:None,
                             _emqx_build_stage=lambda value:stages.mark('product_'+value))
        tmp=Mock();tmp.user_ids.return_value=(1000,1000)
        source=SimpleNamespace(addon={})
        readings={'counts':{'emqx_acl':8,'emqx_app':3},'export':'generated-private-export-path'}
        patches=[patch.object(product,'member_pass',return_value=source),
                 patch.object(product,'node_name',return_value=('generated-private-node',None)),
                 patch.object(product,'ha_broker',return_value=readings),
                 patch.object(product,'_source_analysis',return_value=([],[])),
                 patch.object(product,'take_export',return_value='generated-private-export'),
                 patch.object(product,'_clean'),patch.object(product,'hint_for',return_value='generated-private-hint'),
                 patch.object(product,'candidate_from_target',return_value=({}, {'emqx_acl':7,'emqx_app':4},None,None))]
        from contextlib import ExitStack
        with ExitStack() as stack:
            for item in patches:stack.enter_context(item)
            with patch.object(product,'check_counts',wraps=product.check_counts) as gate:
                with self.assertRaises(BackupError):
                    product._build_candidate(work,SimpleNamespace(id='emqx'),tmp,
                        SimpleNamespace(image='generated-image'),Path('/unused'),version='5.8.9')
                gate.assert_called_once()
        self.assertEqual(stages.current(),'product_row_counts_emqx_acl_underflow')
        self.assertEqual(stages.row_count_diagnostics(),(('emqx_acl','underflow'),('emqx_app','overflow')))
        self.assertNotIn('generated-private',repr(stages.row_count_diagnostics()))

    def test_successful_cleanup_restores_first_recorded_count_failure(self):
        stages.mark('product_row_counts')
        stages.mark('product_row_counts_emqx_acl_underflow')
        stages.mark('product_row_counts_emqx_app_overflow')
        failure=stages.current()
        stages.mark('temp_cleanup')
        stages.mark(failure)
        self.assertEqual(stages.current(),'product_row_counts_emqx_acl_underflow')
        self.assertEqual(stages.row_count_diagnostics(),(('emqx_acl','underflow'),('emqx_app','overflow')))

    def test_context_reset_isolation_and_enum_rejection(self):
        stages.mark('product_row_counts')
        stages.mark('product_row_counts_emqx_app_overflow')
        self.assertEqual(stages.row_count_diagnostics(),(('emqx_app','overflow'),))
        context=copy_context()
        context.run(stages.mark,'authorization')
        self.assertEqual(context.run(stages.row_count_diagnostics),())
        self.assertEqual(stages.row_count_diagnostics(),(('emqx_app','overflow'),))
        for unknown in ('product_row_counts_generated-private_overflow','product_row_counts_emqx_app_123456'):
            with self.assertRaises(ValueError):stages.mark(unknown)
        stages.mark('product_version');self.assertEqual(stages.row_count_diagnostics(),())

    def test_workflow_phase_allowlist_automatically_contains_fixed_diagnostics(self):
        from emqx_real_owner_workflow import PHASES
        for stage in stages.ROW_COUNT_STAGES:
            self.assertIn('build_'+stage+'_product',PHASES)
        self.assertNotIn('build_product_row_counts_generated-private_overflow_product',PHASES)


if __name__=='__main__':unittest.main()
