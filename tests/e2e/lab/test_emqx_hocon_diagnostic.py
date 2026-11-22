"""Fixed diagnostic consumer boundary only; native producer is not simulated evidence."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from emqx_native_hocon import native_hocon_diagnostic
from emqx_semantic_readers import SemanticRefused

class DiagnosticTests(unittest.TestCase):
    def adapter(self,document,status=2):
        def run(directory,script,args,*,output):
            self.assertEqual(script,'parser.escript')
            self.assertEqual(args,('--diagnose',))
            path=Path(directory)/'source.hocon'
            self.assertEqual(path.read_bytes(),b'generated-private-configuration')
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            output.write(json.dumps(document).encode())
            return status
        return run

    def test_only_fixed_diagnostic_phase_can_escape(self):
        doc={'contract':'emqx-hocon-diagnostic-v1','phase':'syntax','result':'refused'}
        with patch('emqx_native_hocon.run_native',side_effect=self.adapter(doc)):
            self.assertEqual(native_hocon_diagnostic(b'generated-private-configuration'),'syntax')

    def test_extra_private_fields_unknown_phase_and_success_cannot_be_diagnostic(self):
        base={'contract':'emqx-hocon-diagnostic-v1','phase':'syntax','result':'refused'}
        for changes,status in (({'private':'generated-private-secret'},2),({'phase':'generated-private-secret'},2),({},0)):
            with self.subTest(changes=changes,status=status):
                doc=dict(base,**changes)
                with patch('emqx_native_hocon.run_native',side_effect=self.adapter(doc,status)):
                    with self.assertRaises(SemanticRefused) as caught:
                        native_hocon_diagnostic(b'generated-private-configuration')
                self.assertEqual(str(caught.exception),'emqx-semantic-source-unsupported')

    def test_invalid_input_never_reaches_native(self):
        with patch('emqx_native_hocon.run_native') as run:
            with self.assertRaises(SemanticRefused):native_hocon_diagnostic('not-bytes')
            run.assert_not_called()
