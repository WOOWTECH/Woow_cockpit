#!/usr/bin/env python3
"""Validate deployable asset references and keep runtime data out of source."""
import ast
from html.parser import HTMLParser
import gzip
import json
from pathlib import Path
import re
import sys
import tarfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import manage

COCKPIT_RUNTIME = ('../base1/cockpit.js', '../../static/branding.css')
BACKUP_PAGE = ('manifest.json', 'index.html', 'backup.css', 'backup.js')
ENGINE_MODULES = ('__init__', 'errors', 'paths', 'archive', 'keys', 'storage', 'util', 'catalog', 'podman',
                  'flows', 'jobs', 'cli', 'adapters/__init__', 'adapters/base', 'adapters/quadlet_postgres')
CATALOG_REQUIRED = ('schema', 'id', 'name', 'owner', 'adapter', 'quadlet', 'units')
# Process launchers that go through a shell; the engine must use fixed argv lists (CONTRACT section 10).
SHELL_CALLS = {'os.system', 'os.popen', 'subprocess.getoutput', 'subprocess.getstatusoutput'}
# DOM sinks that parse HTML; the page must build DOM with textContent (CONTRACT section 11).
HTML_SINKS = re.compile(r'\.(?:innerHTML|outerHTML)\b|\binsertAdjacentHTML\b|\bdocument\.write(?:ln)?\b'
                        r'|\beval\s*\(|\bnew\s+Function\b|\bcreateContextualFragment\b')
LOCAL_FILE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*')


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


class StrictPage(HTMLParser):
    """Every URL-bearing attribute of a page, plus anything Cockpit's default CSP would block."""

    URL_ATTRIBUTES = {'src', 'href', 'srcset', 'data', 'poster', 'action', 'formaction', 'xlink:href',
                      'background', 'manifest', 'ping', 'cite', 'longdesc', 'usemap'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls = []
        self.problems = []
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        for name, value in attrs:
            if name.startswith('on'):
                self.problems.append(f'inline event handler {name}= on <{tag}>')
            elif name == 'style':
                self.problems.append(f'inline style= on <{tag}>')
            if value and re.match(r'\s*(?:javascript|vbscript):', value, re.I):
                self.problems.append(f'script URL in {name}= on <{tag}>')
            if name in self.URL_ATTRIBUTES and value is not None:
                candidates = [part.strip().split()[0] for part in value.split(',') if part.strip()] if name == 'srcset' else [value.strip()]
                self.urls.extend((tag, url) for url in candidates)
        if tag == 'style':
            self.problems.append('inline <style> element')
        elif tag == 'base':
            self.problems.append('<base> element')
        elif tag == 'meta' and values.get('http-equiv', '').lower() not in ('', 'content-type', 'x-ua-compatible'):
            self.problems.append(f'<meta http-equiv="{values["http-equiv"]}">')
        elif tag == 'script':
            if not values.get('src'):
                self.problems.append('inline <script> without src=')
            self.in_script = True

    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_script = False

    def handle_data(self, data):
        if self.in_script and data.strip():
            self.problems.append('inline script code')


def json_strict(path):
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=manage.unique_keys)
    except ValueError as error:
        raise AssertionError(f'{path.relative_to(ROOT)} is not strict JSON: {error}') from None


def find_keys(value, wanted):
    if isinstance(value, dict):
        return [key for key in value if key.lower() == wanted] + [k for v in value.values() for k in find_keys(v, wanted)]
    if isinstance(value, list):
        return [k for v in value for k in find_keys(v, wanted)]
    return []


def check_backup_page():
    page = ROOT / 'backup'
    for name in BACKUP_PAGE:
        assert (page / name).is_file(), f'Missing backup page file: backup/{name}'
    manifest = json_strict(page / 'manifest.json')
    assert manifest['menu']['index']['label'] == '備份與還原', 'backup/manifest.json: menu label must be 備份與還原'
    assert manifest['menu']['index'].get('order') == 46, 'backup/manifest.json: menu order must be 46'
    assert manifest['requires']['cockpit'] == '362', 'backup/manifest.json: requires.cockpit must be "362"'
    assert not find_keys(manifest, 'content-security-policy'), 'backup/manifest.json: keep the default restrictive CSP'
    parser = StrictPage()
    parser.feed((page / 'index.html').read_text())
    parser.close()
    assert not parser.problems, f'backup/index.html violates the package CSP: {"; ".join(parser.problems)}'
    loaded, count = set(), 0
    for tag, url in parser.urls:
        if tag == 'a' and url.startswith('#'):
            continue  # In-page route (cockpit.location).
        if url in COCKPIT_RUNTIME:
            loaded.add(url)
            continue  # Cockpit-provided authenticated runtime dependencies.
        local = url.split('#', 1)[0].split('?', 1)[0]
        assert LOCAL_FILE.fullmatch(local) and '..' not in local.split('/'), \
            f'backup/index.html may only reference package files and Cockpit runtime: {url}'
        assert (page / local).is_file(), f'Missing backup page asset: {url}'
        loaded.add(local)
        count += 1
    missing = [name for name in COCKPIT_RUNTIME + ('backup.css', 'backup.js') if name not in loaded]
    assert not missing, f'backup/index.html must load {", ".join(missing)}'
    css = (page / 'backup.css').read_text()
    for raw in re.findall(r'url\(([^)]*)\)', css) + re.findall(r'@import\s+["\']([^"\']+)["\']', css):
        rel = raw.strip('"\' ')
        if rel.startswith('data:'):
            continue
        assert LOCAL_FILE.fullmatch(rel.split('#', 1)[0]), f'backup/backup.css: remote or out-of-package asset {rel}'
        assert (page / rel.split('#', 1)[0]).is_file(), f'backup/backup.css: missing asset {rel}'
        count += 1
    for number, line in enumerate((page / 'backup.js').read_text().splitlines(), 1):
        sink = HTML_SINKS.search(line)
        assert not sink, f'backup/backup.js:{number}: {sink.group(0)} parses HTML; build DOM with textContent'
    return count


def dotted(node):
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f'{base}.{node.attr}' if base else None
    return node.id if isinstance(node, ast.Name) else None


def check_engine():
    engine = ROOT / 'backup-engine'
    helper = engine / 'woowtech-cockpit-backup'
    assert helper.is_file(), 'Missing backup helper entrypoint: backup-engine/woowtech-cockpit-backup'
    first_line = helper.read_bytes().split(b'\n', 1)[0]
    assert first_line == manage.HELPER_SHEBANG.rstrip(b'\n'), \
        f'backup-engine/woowtech-cockpit-backup must start with "#!/usr/bin/python3 -I", found {first_line!r}'
    missing = [m for m in ENGINE_MODULES if not (engine / 'woowbackup' / f'{m}.py').is_file()]
    assert not missing, f'Missing backup engine modules: {", ".join(missing)}'
    sources = [helper] + sorted(p for p in (engine / 'woowbackup').rglob('*.py') if '__pycache__' not in p.parts)
    for path in sources:
        where = path.relative_to(ROOT)
        try:
            tree = ast.parse(path.read_bytes(), filename=str(where))  # syntax check without importing
        except SyntaxError as error:
            raise AssertionError(f'{where}:{error.lineno}: syntax error: {error.msg}') from None
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = dotted(node.func)
            assert name not in SHELL_CALLS, f'{where}:{node.lineno}: {name}() runs a shell; use a fixed argv list'
            for keyword in node.keywords:
                literal_false = isinstance(keyword.value, ast.Constant) and keyword.value.value is False
                assert keyword.arg != 'shell' or literal_false, f'{where}:{node.lineno}: shell= must stay False'
    return len(sources)


def check_demo_catalog():
    fixture = ROOT / 'catalog-examples' / manage.DEMO_APP
    entry = json_strict(fixture / 'catalog.json')
    missing = [key for key in CATALOG_REQUIRED if key not in entry]
    assert not missing, f'catalog-examples/{manage.DEMO_APP}/catalog.json: missing {", ".join(missing)}'
    assert entry['schema'] == 1 and entry['id'] == manage.DEMO_APP, 'Demo catalog must be schema 1, id woowbk-demo'
    template_dir = f'/{manage.DEMO_TEMPLATES}/quadlet'
    assert entry['quadlet'].get('template_dir') == template_dir, \
        f'Demo catalog quadlet.template_dir must be {template_dir} (installer --backup-demo-catalog target)'
    for name in entry['quadlet']['files']:
        assert manage.QUADLET_FILE.fullmatch(name) and (fixture / 'quadlet' / name).is_file(), \
            f'Demo catalog lists a Quadlet template that is not in the fixture: {name}'
    # The device engine validates strictly (unknown keys, names, loopback URLs); do the same here.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / 'backup-engine'))
    from woowbackup.catalog import validate_entry
    from woowbackup.errors import BackupError
    from woowbackup.paths import Paths
    try:
        app = validate_entry(entry, paths=Paths(), user_lookup=lambda name: SimpleNamespace(pw_name=name, pw_uid=1001))
    except BackupError as error:
        raise AssertionError(f'Demo catalog rejected by the engine validator ({error.code}): {error.message}') from None
    assert app.template_dir == template_dir
    return len(entry['quadlet']['files'])


def check():
    count = 0
    for parent in ('branding', 'preview', 'services', 'native', 'backup', 'backup-engine', 'catalog-examples'):
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
        if rel in COCKPIT_RUNTIME:
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
    count += check_backup_page()
    modules = check_engine()
    templates = check_demo_catalog()
    print(f'Source check passed: {count} asset references, manifest, local fonts, CSS, CSP and native source/bundle; '
          f'backup page (manifest, CSP, DOM sinks), {modules} engine sources (shebang, syntax, no shell), '
          f'demo catalog with {templates} Quadlet templates.')


if __name__ == '__main__':
    check()
