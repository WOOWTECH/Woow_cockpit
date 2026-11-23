"""Declared credential sources: the scan fails while a source is missing; synthetic values only."""
import json
import os
import tempfile
import unittest

from credential_ledger import CoverageError, Ledger

A = 'synthetic-value-aaaa-1111'
B = 'synthetic/value"bbbbé-2222'


class LedgerTests(unittest.TestCase):
    def test_scan_refuses_while_a_declared_source_is_missing(self):
        ledger = Ledger(['ha.salt_key', 'issued.virtual_key'])
        ledger.register('ha.salt_key', A)
        with self.assertRaises(CoverageError) as caught:
            ledger.scan([b'nothing here'])
        self.assertIn('issued.virtual_key', str(caught.exception))
        self.assertNotIn(A, str(caught.exception))
        with self.assertRaises(CoverageError):
            ledger.require_clean([b'nothing here'])
        ledger.register('issued.virtual_key', B)
        self.assertEqual(ledger.require_clean([b'nothing here'])['matches'], 0)

    def test_undeclared_or_short_values_are_refused(self):
        ledger = Ledger(['target.master_key'])
        with self.assertRaises(CoverageError):
            ledger.register('target.other', A)
        with self.assertRaises(CoverageError):
            ledger.register('target.master_key', 'abc')
        with self.assertRaises(CoverageError):
            ledger.register('target.master_key', 12345678)
        for bad in ([], ['x'], ['a.b', 'a.b'], ['Upper.case']):
            with self.assertRaises(CoverageError):
                Ledger(bad)

    def test_raw_stripped_and_json_escaped_values_are_found(self):
        ledger = Ledger(['a.one', 'b.two'])
        ledger.register('a.one', A + '\n')
        ledger.register('b.two', B)
        self.assertEqual(ledger.scan([('x ' + A + ' y').encode()])['matches'], 1)
        for ascii_only in (False, True):
            doc = json.dumps({'v': B}, ensure_ascii=ascii_only).encode()
            self.assertGreaterEqual(ledger.scan([doc])['matches'], 1)
            self.assertTrue(ledger.contains(doc))
        self.assertFalse(ledger.contains(b'clean output'))
        with self.assertRaises(CoverageError):
            ledger.require_clean([A.encode()])

    def test_file_scan_finds_values_across_chunk_borders_without_double_counting(self):
        ledger = Ledger(['a.one'])
        ledger.register('a.one', A)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'f')
            with open(path, 'wb') as handle:
                handle.write(b'x' * (1024 * 1024 - 5) + A.encode() + b'y' * 100 + A.encode())
            self.assertEqual(ledger.scan(paths=[path])['matches'], 2)

    def test_repr_and_errors_hold_no_values(self):
        ledger = Ledger(['a.one'])
        ledger.register('a.one', A)
        self.assertNotIn(A, repr(ledger))
        try:
            ledger.require_clean([A.encode()])
        except CoverageError as exc:
            self.assertNotIn(A, str(exc))


if __name__ == '__main__':
    unittest.main()
