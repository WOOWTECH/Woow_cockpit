import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('pwa_render', ROOT / 'pwa-gateway/render.py')
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


class PwaBrandTests(unittest.TestCase):
    def test_brand_changes_presentation_but_keeps_pwa_identity_and_routes(self):
        original = json.loads((ROOT / 'pwa-gateway/assets/manifest.webmanifest').read_text())
        original_nginx = (ROOT / 'pwa-gateway/nginx.conf').read_text()
        with tempfile.TemporaryDirectory() as tmp:
            for brand, color in [('woowtech', '#6183fc'), ('apporo', '#8B6B24')]:
                out = Path(tmp) / brand
                renderer.render(brand, out)
                manifest = json.loads((out / 'assets/manifest.webmanifest').read_text())
                for key in ('id', 'start_url', 'scope', 'display', 'icons', 'description'):
                    self.assertEqual(manifest[key], original[key])
                self.assertEqual(manifest['theme_color'].lower(), color.lower())
                self.assertEqual(manifest['short_name'], brand)
                expected_nginx = original_nginx if brand == 'woowtech' else original_nginx.replace(
                    'content="#6183fc"', f'content="{color}"')
                self.assertEqual((out / 'nginx.conf').read_text(), expected_nginx)
                for size in (192, 512):
                    source = ROOT / (f'pwa-gateway/assets/icon-{size}.png' if brand == 'woowtech'
                                     else f'brands/apporo/assets/smart/pwa-icon-{size}.png')
                    self.assertEqual((out / f'assets/icon-{size}.png').read_bytes(), source.read_bytes())

    def test_unknown_brand_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'invalid'
            with self.assertRaises(ValueError):
                renderer.render('../apporo', out)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
