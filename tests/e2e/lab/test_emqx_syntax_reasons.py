"""Pinned public generated AST, fixed reason propagation, no lab/real input."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from emqx_hocon_context import register_syntax, SyntaxRefused, SYNTAX_PHASES, HTTP_PROFILE
from emqx_native_hocon import native_hocon_http_context
from emqx_semantic_readers import Values, read_hocon, SemanticRefused
from emqx_private_boundary import SOURCE_PHASES
from test_emqx_http_context import RAW
from test_emqx_hocon_context_native import BASE, ACTION, observe
import emqx_owner_file_hocon as vendor


class NativeSyntaxReasonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.encoded=native_hocon_http_context(RAW)
        cls.doc=json.loads(cls.encoded)

    def test_valid_native_contract_still_collects_and_all_enum_stages_are_bounded(self):
        with patch.object(vendor,'observe_vendor_acl',observe):
            values=read_hocon(RAW,lambda _:self.encoded,file_profile=HTTP_PROFILE,product_image=vendor.IMAGE)
        self.assertIn(b'before-${payload.body}-${clientid}-${.}-after',values.values)
        for phase in SYNTAX_PHASES:
            self.assertIn('HOCON_'+phase.upper(),SOURCE_PHASES)
        self.assertEqual(SyntaxRefused('generated-private').phase,'syntax_bindings')

    def test_multiplicity_shape_http_reference_and_key_reasons_from_native_receipt(self):
        cases=[]
        doc=copy.deepcopy(self.doc);doc['document']['string_bindings'].pop()
        cases.append((doc,'syntax_multiplicity'))
        doc=copy.deepcopy(self.doc);doc['document']['string_bindings'][0]['role']='unknown'
        cases.append((doc,'syntax_shape'))
        doc=copy.deepcopy(self.doc);doc['document']['parsed']['connectors']['http']={}
        cases.append((doc,'syntax_http_binding'))
        doc=copy.deepcopy(self.doc)
        reference=next(b for b in doc['document']['string_bindings'] if b['role']=='action-reference')
        doc['document']['string_bindings'].remove(reference);doc['document']['string_bindings'].insert(0,reference)
        doc['document']['parsed']['connectors']['http']={}
        cases.append((doc,'syntax_action_reference'))
        doc=copy.deepcopy(self.doc)
        target=next(b for b in doc['document']['string_bindings'] if b['role']=='http-body-value')
        target['role']='key';cases.append((doc,'syntax_key_literal'))
        with patch.object(vendor,'observe_vendor_acl') as observer:
            for doc,wanted in cases:
                with self.subTest(reason=wanted),self.assertRaises(SemanticRefused) as caught:
                    read_hocon(RAW,lambda _:json.dumps(doc).encode(),file_profile=HTTP_PROFILE,product_image=vendor.IMAGE)
                self.assertEqual(caught.exception.owner_phase,wanted)
                self.assertEqual(str(caught.exception),'emqx-semantic-source-unsupported')
            observer.assert_not_called()

    def test_realistic_native_republish_unknown_arg_and_qos_are_not_silently_allowed(self):
        cases=(
            (BASE+ACTION.replace(b'qos="${qos}"',b'qos="0"'),'syntax_republish_qos'),
            (BASE+ACTION.replace(b'payload="prefix-${payload.body}"',b'unknown="${payload.body}"'),'syntax_value_literal'),
            (RAW.replace(b'${payload.body}',b'${HOME}'),'syntax_republish_payload_unknown_root'),
        )
        with patch.object(vendor,'observe_vendor_acl') as observer:
            for raw,wanted in cases:
                encoded=native_hocon_http_context(raw)
                with self.subTest(reason=wanted),self.assertRaises(SemanticRefused) as caught:
                    read_hocon(raw,lambda _:encoded,file_profile=HTTP_PROFILE,product_image=vendor.IMAGE)
                self.assertEqual(caught.exception.owner_phase,wanted)
            observer.assert_not_called()

    def test_full_source_phase_boundary_keeps_new_reason_and_cleanup(self):
        import test_emqx_owner_source_capture as fixtures
        from test_emqx_source_cold_capture import decoder
        import emqx_owner_source_capture as owner
        from emqx_private_boundary import SourcePhaseFailure
        fixtures.OwnerHarnessTests.fixture(self)
        # Generated native receipt adapted only to the generated fixture input
        # binding: this is a phase propagation test, not a native-source claim.
        def contract(raw):
            doc=copy.deepcopy(self.doc)
            doc.update(input_sha256=hashlib.sha256(raw).hexdigest(),input_bytes=len(raw))
            target=next(b for b in doc['document']['string_bindings'] if b['role']=='http-body-value')
            target['role']='value'
            return json.dumps(doc).encode()
        with patch('emqx_native_hocon.native_hocon_http_context',contract), \
             patch.object(owner,'native_cold_history',decoder),patch.object(vendor,'observe_vendor_acl') as observer:
            with self.assertRaises(SourcePhaseFailure) as caught:
                with owner.capture_owner_source(self.path,password=self.password,expected_sha256=self.digest,
                     spool_directory=self.spool,file_dependency_profile=HTTP_PROFILE,product_image=vendor.IMAGE):pass
            self.assertEqual(caught.exception.phase,'HOCON_SYNTAX_VALUE_LITERAL')
            observer.assert_not_called()
        self.assertEqual(list(self.spool.iterdir()),[])
