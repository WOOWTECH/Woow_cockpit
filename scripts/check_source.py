#!/usr/bin/env python3
"""Validate deployable asset references and keep runtime data out of source."""
from html.parser import HTMLParser
import gzip
import json
from pathlib import Path
import re
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import manage


class References(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('img', 'script') and 'src' in attrs:
            self.paths.append(attrs['src'])
        if tag == 'link' and 'href' in attrs:
            self.paths.append(attrs['href'])
        assert not any(k.startswith('on') or k == 'style' for k in attrs), 'Inline script/style violates package CSP'


def check():
    count = 0
    for parent in ('branding', 'preview', 'services', 'native'):
        for item in (ROOT / parent).rglob('*'):
            assert not item.is_symlink(), f'Symlink in payload: {item}'
    for css in (ROOT / 'branding/branding.css', ROOT / 'preview/gallery.css', ROOT / 'preview/layout-review.css'):
        for raw in re.findall(r'url\(([^)]+)\)', css.read_text()):
            rel = raw.strip('"\' ')
            assert not rel.startswith(('http:', 'https:')), f'Remote runtime asset: {rel}'
            if rel.startswith('data:'):
                continue
            path = css.parent / rel
            if not path.is_file() and css.parent.name == 'preview':
                path = ROOT / 'branding' / rel
            assert path.is_file(), f'Missing CSS asset: {rel}'
            count += 1
    for html in (ROOT / 'preview').glob('*.html'):
        parser = References()
        parser.feed(html.read_text())
        for raw in parser.paths:
            rel = raw.split('?')[0]
            if rel.startswith(('screenshots/', 'layout-images/')):
                if rel.startswith('screenshots/'):
                    assert Path(rel).stem in manage.SHOTS, f'Unknown capture: {rel}'
                continue
            assert not rel.startswith(('http:', 'https:')), f'Remote HTML asset: {rel}'
            candidates = (ROOT / 'preview' / rel, ROOT / 'branding' / rel)
            if rel == 'assets/favicon.ico':
                candidates += (ROOT / 'branding/favicon.ico',)
            assert any(p.is_file() for p in candidates), f'Missing HTML asset: {rel}'
            count += 1
    manifest = json.loads((ROOT / 'preview/manifest.json').read_text())
    assert manifest['tools']['index']['label'] == '畫面參考'
    assert manifest['requires']['cockpit'] == '362'
    assert 'content-security-policy' not in manifest, 'Keep the default restrictive CSP'
    service_manifest = json.loads((ROOT / 'services/manifest.json').read_text())
    assert service_manifest['menu']['index']['label'] == '服務管理'
    assert 'content-security-policy' not in service_manifest
    parser = References()
    parser.feed((ROOT / 'services/index.html').read_text())
    for rel in parser.paths:
        if rel in ('../../static/branding.css', '../base1/cockpit.js'):
            continue  # Cockpit-provided authenticated runtime dependencies.
        assert (ROOT / 'services' / rel).is_file(), f'Missing services asset: {rel}'
        count += 1
    assert (ROOT / 'services/service-manager.py').read_text().startswith('#!/usr/bin/python3 -I\n')
    css = (ROOT / 'branding/branding.css').read_text().lower()
    assert '#6183fc' in css and 'bg-frosted' not in css
    for path in (ROOT / 'branding/fonts').glob('*.ttf'):
        assert path.stat().st_size > 10000, f'Invalid font: {path.name}'
    native = ROOT / 'native/podman'
    bundle = gzip.decompress((native / 'dist/index.js.gz').read_bytes())
    assert b'/usr/local/libexec/woowtech-cockpit-services' in bundle
    assert b'woowManaged' in bundle
    assert (native / 'dist/licenses/LGPL-2.1.txt').is_file()
    with tarfile.open(native / 'source-124.tar.gz') as archive:
        members = archive.getmembers()
        for member in members:
            path = Path(member.name)
            assert not path.is_absolute() and '..' not in path.parts
            assert not member.issym() and not member.islnk()
            assert not {'.git', 'node_modules', '.local'} & set(path.parts)
        names = {member.name for member in members}
        for required in ('src/app.jsx', 'pkg/lib/cockpit.js', 'package-lock.json', 'build.js'):
            assert f'cockpit-podman-124/{required}' in names, f'Missing native build source: {required}'
    print(f'Source check passed: {count} asset references, manifest, local fonts, CSS, CSP and native source/bundle.')


if __name__ == '__main__':
    check()
