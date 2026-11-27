"""Offline evidence redaction tests using synthetic values only."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ha_import_e2e', Path(__file__).with_name('ha_import_e2e.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class EvidenceRedactionTests(unittest.TestCase):
    def test_nested_keys_values_check_log_and_saved_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            creds = root / 'creds'
            creds.write_text('PASSWORD=synthetic"quoted\\value\n', encoding='utf-8')
            n8n = root / 'n8n'
            n8n.write_text('{"name":"HA probe header","value":"synthetic-n8n"}', encoding='utf-8')
            secrets = driver.Secrets(creds, n8n)
            secrets.values['MULTILINE'] = 'synthetic\nline\tsecret'
            password = secrets['PASSWORD']
            multiline = secrets['MULTILINE']
            detail = {password: ['prefix ' + password, {multiline: multiline}], 'credential': 'synthetic-n8n'}
            output = io.StringIO()
            with patch.object(driver, 'LAB', root), contextlib.redirect_stdout(output):
                evidence = driver.Evidence(secrets)
                evidence.check('failed ' + password, False, detail)
                evidence.save('probe.json', detail)
                evidence.finish()
            saved = json.loads((evidence.dir / 'probe.json').read_text())
            self.assertIn('<PASSWORD>', saved)
            self.assertEqual(saved['<PASSWORD>'][1]['<MULTILINE>'], '<MULTILINE>')
            for path in (evidence.dir / 'probe.json', evidence.dir / 'results.json', evidence.dir / 'run.log'):
                text = path.read_text(encoding='utf-8')
                for secret in (password, multiline, 'synthetic-n8n'):
                    self.assertNotIn(secret, text)
                    self.assertNotIn(json.dumps(secret, ensure_ascii=False)[1:-1], text)
            self.assertNotIn(password, output.getvalue())
            self.assertFalse(json.loads((evidence.dir / 'results.json').read_text())['results'][0]['ok'])

    def test_redacted_key_collision_fails_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            creds = root / 'creds'; creds.write_text('PASSWORD=synthetic-password\n')
            n8n = root / 'n8n'; n8n.write_text('{"name":"HA probe header","value":"synthetic-n8n"}')
            with patch.object(driver, 'LAB', root):
                evidence = driver.Evidence(driver.Secrets(creds, n8n))
                with self.assertRaises(ValueError):
                    evidence.save('collision.json', {'synthetic-password': 1, '<PASSWORD>': 2})
                self.assertFalse((evidence.dir / 'collision.json').exists())


if __name__ == '__main__':
    unittest.main()
