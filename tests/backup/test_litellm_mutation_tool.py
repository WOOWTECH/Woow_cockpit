"""litellm_product_mutations.py (which removed protection of the LiteLLM import a unit test notices): what it counts as
noticed, and that each entry disables one place of the sources as they are now. A module of its own on purpose: the tool
must never run these tests, they would fail for every removal and call each one caught."""
import importlib.util
import unittest
from pathlib import Path

from woowbackup import ha_litellm


class MutationToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('litellm_product_mutations',
                                                      Path(__file__).with_name('litellm_product_mutations.py'))
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def test_the_tool_never_runs_this_module(self):
        modules = set(self.tool.TESTS) | set(self.tool.SUGGEST_TESTS)
        for entry in self.tool.MUTATIONS:
            modules.update(*entry[6:])
        self.assertEqual(modules, {'tests.backup.test_ha_litellm', 'tests.backup.test_adapter_import_secrets',
                                   'tests.backup.test_ha_litellm_candidate', 'tests.backup.test_suggest'})

    def test_the_summary_is_read_wherever_unittest_printed_it(self):
        line = '-' * 70
        noise = ('Exception ignored in: <function _Stream.__del__ at 0x1>\nTraceback (most recent call last):\n'
                 'ValueError: write to closed file\n')
        for text, expected in (
                (f'{noise}F\n{line}\nRan 45 tests in 5.116s\n\nFAILED (failures=1)\n{noise}', (45, 1)),
                (f'E\n{line}\nRan 1 test in 0.101s\n\nFAILED (failures=2, errors=1, skipped=3, expected failures=4)\n',
                 (1, 3)),
                (f'....\n{line}\nRan 143 tests in 20.1s\n\nOK (skipped=2)\n{noise}', (143, 0)),
                ('FAILED (failures=3)\nRan 3 tests in 1.0s\n\nOK\n', (3, 0)),  # only a line after the count is the summary
                ('ModuleNotFoundError: x\n', (0, 0)), ('', (0, 0))):
            with self.subTest(text=text[-60:]):
                self.assertEqual(self.tool.outcome(text), expected)

    def test_every_removal_is_one_place_of_the_current_sources(self):
        engine = Path(ha_litellm.__file__).resolve().parents[1]
        sources = {}
        ids = [entry[0] for entry in self.tool.MUTATIONS]
        self.assertEqual(len(ids), len(set(ids)))
        for ident, _name, module, old, new, count, *_tests in self.tool.MUTATIONS:
            with self.subTest(ident):
                text = sources.setdefault(module, (engine / module).read_text(encoding='utf-8'))
                self.assertEqual((count, text.count(old)), (1, 1), 'one entry disables one place')
                self.assertNotEqual(old, new)
        # what the lane verifier's 26 removals of 2026-11-24 found unguarded, by the verifier's ids
        for ident in ('N01', 'N09', 'N10', 'N11', 'N12', 'N14', 'N16', 'N18', 'N19', 'N21', 'N28', 'N29', 'N30', 'N32',
                      'N33', 'N34'):
            self.assertIn(ident, ids)


if __name__ == '__main__':
    unittest.main()
