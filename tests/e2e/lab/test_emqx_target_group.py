"""Observed native global-chain atom groups, with independent expected identity."""
import json
import unittest
from test_emqx_semantic_readers import RAW, binary, term, mnesia
from emqx_target_capture import mqtt_password_table, TargetCaptureUnsupported


class NativeGroupTests(unittest.TestCase):
    def capture(self, group):
        doc = mnesia(rows=[term('tuple',[term('atom','user_info'),
            term('tuple',[group,binary(b'generated-user')]),
            binary(b'generated-hash'),binary(b''),term('atom','false')])])
        return json.loads(mqtt_password_table(RAW,exporter=lambda _:json.dumps(doc).encode(),
                                             username_group=b'mqtt:global'))

    def test_observed_atom_and_existing_binary_group_both_require_exact_match(self):
        for group in (term('atom','mqtt:global'),binary(b'mqtt:global')):
            self.assertEqual(self.capture(group)['records'][0]['username'],'generated-user')

    def test_other_atom_binary_and_non_group_terms_refuse(self):
        for group in (term('atom','other:global'),binary(b'other:global'),
                      term('integer',1),term('list',[])):
            with self.subTest(group_type=group['type']),self.assertRaises(TargetCaptureUnsupported):
                self.capture(group)

    def test_atom_does_not_coerce_username_or_binary_hash(self):
        doc = mnesia(rows=[term('tuple',[term('atom','user_info'),
            term('tuple',[term('atom','mqtt:global'),term('atom','generated-user')]),
            binary(b'generated-hash'),binary(b''),term('atom','false')])])
        with self.assertRaises(TargetCaptureUnsupported):
            mqtt_password_table(RAW,exporter=lambda _:json.dumps(doc).encode(),username_group=b'mqtt:global')


if __name__ == '__main__':
    unittest.main()
