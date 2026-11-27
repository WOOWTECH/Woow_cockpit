"""Every helper request a lab driver writes as a literal carries only fields the product's schema accepts.

The product refuses a request with an unsupported field before doing anything ("請求含有不支援的欄位"). Two real
runs were lost to that: the Nextcloud R6 convert sent check_job_id (fullshare03, 2026-11-27) and the B1 cleanup sent
delete with confirm. Offline: the drivers are parsed, never imported or run.
"""
import ast
from pathlib import Path
import tempfile
import unittest

from woowbackup import cli

LAB = Path(__file__).resolve().parents[1] / 'e2e' / 'lab'
SENDERS = {'helper', 'ok', 'rpc_call'}


def literal_requests(path):
    """(line, command, field names) of calls like helper('cmd', {...}) whose request is a dict literal."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(), str(path))):
        if not isinstance(node, ast.Call) or len(node.args) < 2:
            continue
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, 'id', None)
        command, request = node.args[0], node.args[1]
        if (name in SENDERS and isinstance(command, ast.Constant) and isinstance(command.value, str)
                and isinstance(request, ast.Dict) and all(isinstance(k, ast.Constant) for k in request.keys)):
            found.append((node.lineno, command.value, {k.value for k in request.keys}))
    return found


class LabRequestShapeTests(unittest.TestCase):
    def test_literal_requests_use_only_schema_fields(self):
        checked, problems = 0, []
        for path in sorted(LAB.glob('*.py')):
            for line, command, fields in literal_requests(path):
                if command not in cli.SPECS:
                    continue
                checked += 1
                unknown = sorted(fields - set(cli.SPECS[command]))
                if unknown:
                    problems.append(f'{path.name}:{line} {command} {unknown}')
        self.assertGreater(checked, 20)
        self.assertEqual(problems, [])

    def test_the_scan_sees_an_unsupported_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / 'driver.py'
            sample.write_text("rc, reply = drv.helper('delete', {'backup_id': 'x', 'confirm': True})\n")
            [(line, command, fields)] = literal_requests(sample)
        self.assertEqual((line, command, fields - set(cli.SPECS[command])), (1, 'delete', {'confirm'}))


if __name__ == '__main__':
    unittest.main()
