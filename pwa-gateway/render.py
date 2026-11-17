#!/usr/bin/env python3
"""Render one brand's PWA assets; never change proxy routes or service identity."""
import argparse
import json
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'scripts'))
from brand_profile import asset_mapping, load_profile


def render(brand, output):
    profile = load_profile(brand, source_root=ROOT)
    color = profile['colors']['light']['primary']
    manifest = json.loads((HERE / 'assets/manifest.webmanifest').read_text())
    nginx = (HERE / 'nginx.conf').read_text()
    # Keep URLs, scope and ID identical so installed applications retain their
    # identity and all Cockpit/Pi routes keep the same authentication boundary.
    if brand == 'apporo':
        manifest['name'] = profile['display_name']
        manifest['short_name'] = 'apporo'
        manifest['theme_color'] = color
        nginx = nginx.replace('content="#6183fc"', f'content="{color}"')
    mapped_assets = asset_mapping(profile, source_root=ROOT)
    assets = {f'icon-{size}.png': mapped_assets[f'pwa_icon_{size}'] for size in (192, 512)}
    # Validate all input assets before writing anything. Official icon bytes are
    # copied as-is, never recreated or stretched into another brand's outline.
    contents = {}
    for name, source in assets.items():
        data = source.read_bytes()
        size = int(name.split('-')[1].split('.')[0])
        if not data.startswith(b'\x89PNG\r\n\x1a\n') or len(data) < 24:
            raise ValueError(f'Invalid PNG: {source}')
        if tuple(int.from_bytes(data[n:n + 4], 'big') for n in (16, 20)) != (size, size):
            raise ValueError(f'Unexpected icon dimensions: {source}')
        contents[name] = data
    output = Path(output)
    (output / 'assets').mkdir(parents=True, exist_ok=True)
    for name, data in contents.items():
        (output / 'assets' / name).write_bytes(data)
    # The default brand's existing bytes are preserved for reproducibility.
    if brand == 'woowtech':
        shutil.copyfile(HERE / 'assets/manifest.webmanifest', output / 'assets/manifest.webmanifest')
    else:
        (output / 'assets/manifest.webmanifest').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    (output / 'nginx.conf').write_text(nginx)
    return {'brand': brand, 'output': str(output), 'routes_changed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--brand', choices=('woowtech', 'apporo'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(render(args.brand, args.output)))


if __name__ == '__main__':
    main()
