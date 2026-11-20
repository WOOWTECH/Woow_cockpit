"""Offline checks of synthetic PostgreSQL lab experiment guards; no lab containers."""
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

LAB = Path(__file__).resolve().parents[1] / 'e2e/lab'
sys.path.insert(0, str(LAB))
spec = importlib.util.spec_from_file_location('litellm_pg_experiment', LAB / 'litellm_pg18_pg17_candidate.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.path.pop(0)


class SyntheticLabContractTests(unittest.TestCase):
    def test_dump_shape_fixture_rejects_empty_large_and_ddl(self):
        valid = b"SET statement_timeout = 0;\nINSERT INTO public.synthetic_rows (id, label) VALUES (1, 'a');\n"
        self.assertTrue(module.synthetic_dump_ok(valid))
        for data in (b'', None, b'x' * (module.MAX_DUMP + 1), b'INSERT INTO public.other VALUES (1);',
                     valid + b'\nCREATE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE SQL;',
                     valid + b'\nALTER TABLE public.synthetic_rows ADD COLUMN bad int;',
                     valid + b'\nCOPY public.synthetic_rows FROM stdin;'):
            with self.subTest(kind=type(data)):
                self.assertFalse(module.synthetic_dump_ok(data))

    def test_postgres_major_requires_exact_integer(self):
        for actual in (None, '18', True, 17, 19):
            with self.subTest(actual=actual), self.assertRaises(RuntimeError):
                module.checked_major(mock.Mock(query_json=mock.Mock(return_value=actual)), 18)
        self.assertEqual(module.checked_major(mock.Mock(query_json=mock.Mock(return_value=18)), 18), 18)


if __name__ == '__main__':
    unittest.main()
