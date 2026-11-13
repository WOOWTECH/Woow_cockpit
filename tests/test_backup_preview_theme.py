"""The design-preview theme installer must not alter preview logic or data."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

INSTALLER = Path(__file__).resolve().parents[1] / 'backup-preview-theme' / 'install.py'

class BackupPreviewTheme(unittest.TestCase):
    def test_install_is_idempotent_and_preserves_preview(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); preview = root / 'preview'; preview.mkdir()
            index = preview / 'index.html'
            original = '<html><head><link rel="stylesheet" href="style.css"></head><body>Preview</body></html>'
            index.write_text(original)
            logic = preview / 'app.js'; logic.write_text('original logic')
            cmd = [sys.executable, str(INSTALLER), '--target', str(preview), '--backup', str(root / 'backups')]
            subprocess.run(cmd, check=True, capture_output=True)
            installed = index.read_text()
            self.assertEqual(installed.count('woowtech-backup-preview-theme'), 1)
            self.assertTrue((preview / 'woow-theme.js').is_file())
            self.assertTrue((preview / 'woow-dark.css').is_file())
            self.assertEqual(logic.read_text(), 'original logic')
            self.assertEqual(next((root/'backups').glob('*/index.html')).read_text(), original)
            subprocess.run(cmd, check=True, capture_output=True)
            self.assertEqual(index.read_text(), installed)

    def test_unknown_preview_is_not_changed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); index = root / 'index.html'; index.write_text('<html>unexpected</html>')
            result = subprocess.run([sys.executable, str(INSTALLER), '--target', str(root), '--backup', str(root/'backups')], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(index.read_text(), '<html>unexpected</html>')
            self.assertFalse((root/'woow-dark.css').exists())

if __name__ == '__main__': unittest.main()
