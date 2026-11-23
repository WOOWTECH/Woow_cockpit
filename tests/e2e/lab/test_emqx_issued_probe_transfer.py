"""Generated framing only; no lab/owner invocation."""
import unittest
import emqx_issued_probe_transfer as m
class ProbeTransferTests(unittest.TestCase):
    def test_fixed_bootstrap_compiles_and_success_requires_exact_scanned_receipt(self):
        compile(m.BOOTSTRAP,'<fixed-probe-bootstrap>','exec')
        raw=m.evidence_frame(m.TARGET_RECEIPT)
        self.assertEqual(m.decode_result(raw,0),m.TARGET_RECEIPT)
        for bad in (raw+b'x',raw[:-1],m.evidence_frame(b'generated-private-payload')):
            with self.assertRaises(m.ProbeTransportRefused):m.decode_result(bad,0)
    def test_only_fixed_failure_phase_is_accepted_and_never_private_text(self):
        for phase in m.PHASES:
            with self.assertRaises(m.ProbeTransportRefused) as failure:
                m.decode_result(b'ISSUED-PROBE-REFUSED:'+phase.encode()+b'\n',1)
            self.assertEqual(failure.exception.phase,phase)
        with self.assertRaises(m.ProbeTransportRefused) as failure:
            m.decode_result(b'ISSUED-PROBE-REFUSED:generated-private\n',1)
        self.assertEqual(failure.exception.phase,'transport')
        self.assertNotIn('generated-private',str(failure.exception))
