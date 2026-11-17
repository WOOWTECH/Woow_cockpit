"""Validated public brand profiles and bounded, install-time presentation rendering.

No runtime calls, source edits, authentication changes, or archive-format changes.
Paths in source profiles are relative to brands/<id>. The woowtech profile may
reference its existing assets elsewhere inside this repository, without copies.
"""
from __future__ import annotations

import html
import json
from pathlib import Path
import re
import struct
import xml.etree.ElementTree as ET

SOURCE_ROOT = Path(__file__).resolve().parents[1]
BRANDS = ('woowtech', 'apporo')
ASSET_TARGETS = {
    'logo_lockup_light': 'assets/logo-lockup-blue.svg',
    'logo_lockup_dark': 'assets/logo-lockup-dark.svg',
    'logo_wordmark_light': 'assets/logo-wordmark-blue.svg',
    'logo_wordmark_dark': 'assets/logo-wordmark-dark.svg',
    'logo_symbol': 'assets/logo-symbol-blue.svg',
    'favicon': 'favicon.ico',
    'apple_touch_icon': 'apple-touch-icon.png',
    'pwa_icon_192': 'assets/icon-192.png',
    'pwa_icon_512': 'assets/icon-512.png',
}
CSS_FILES = frozenset(('branding/branding.css', 'services/service.css', 'backup/backup.css',
                       'apps-catalog/apps.css', 'preview/gallery.css', 'preview/layout-review.css'))
HTML_FILES = frozenset(('services/index.html', 'backup/index.html', 'preview/index.html',
                        'preview/layout-review.html'))
COLOR = re.compile(r'#[0-9a-fA-F]{6}\Z')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate brand profile key: {key}')
        result[key] = value
    return result


def _text(value, name, *, empty=False):
    # Names are also used in reviewed Python/JS string literals; do not permit
    # code delimiters. HTML has its own escaping below.
    if not isinstance(value, str) or (not value and not empty) or len(value) > 160 or any(
            ord(c) < 32 or c in '\\"\'`<>{}$' for c in value):
        raise ValueError(f'Invalid brand {name}')
    return value


def _regular(path: Path, boundary: Path) -> Path:
    """Reject symlinks in every path component, even if they resolve in-tree."""
    import os
    path = Path(os.path.abspath(path))
    boundary = Path(os.path.abspath(boundary))
    try:
        relative = path.relative_to(boundary)
    except ValueError:
        raise ValueError('Brand asset path escapes its allowed source tree') from None
    cursor = boundary
    if cursor.is_symlink():
        raise ValueError('Brand source root is a symlink')
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(f'Brand asset is a symlink: {cursor.name}')
    if not cursor.is_file():
        raise ValueError(f'Missing official brand asset: {relative}; supply approved assets before installation')
    return cursor


def asset_mapping(profile: dict, *, source_root: Path | None = None) -> dict[str, Path]:
    """Resolve all required asset roles to regular, contained absolute files."""
    root = Path(source_root if source_root is not None else SOURCE_ROOT).absolute()
    brand = profile.get('id')
    if brand not in BRANDS:
        raise ValueError('Unknown brand')
    base = root / 'brands' / brand
    assets = profile.get('assets')
    if not isinstance(assets, dict):
        raise ValueError('Brand assets must be an object')
    result = {}
    for role in ASSET_TARGETS:
        raw = assets.get(role)
        if not isinstance(raw, str) or not raw or Path(raw).is_absolute() or '\\' in raw:
            raise ValueError(f'Missing or invalid official asset role: {role}')
        # Only the legacy woowtech profile can reference existing repo assets.
        boundary = root if brand == 'woowtech' else base
        if brand != 'woowtech' and '..' in Path(raw).parts:
            raise ValueError('Brand asset path escapes its allowed source tree')
        path = _regular(base / raw, boundary)
        data = path.read_bytes()
        if len(data) > 8 * 1024 * 1024 or not data:
            raise ValueError(f'Invalid asset size: {role}')
        if role.startswith('logo_'):
            try:
                node = ET.fromstring(data)
            except ET.ParseError:
                raise ValueError(f'Invalid SVG: {role}') from None
            if node.tag.rsplit('}', 1)[-1] != 'svg':
                raise ValueError(f'Invalid SVG: {role}')
        elif role == 'favicon':
            if not data.startswith(b'\x00\x00\x01\x00') or len(data) < 22:
                raise ValueError('favicon must be an official ICO file')
        else:
            if not data.startswith(b'\x89PNG\r\n\x1a\n') or len(data) < 24:
                raise ValueError(f'Invalid PNG: {role}')
            size = struct.unpack('>II', data[16:24])
            expected = {'pwa_icon_192': 192, 'pwa_icon_512': 512}.get(role)
            if expected and size != (expected, expected):
                raise ValueError(f'{role} must be {expected}x{expected}')
        result[role] = path
    return result


def load_profile(brand: str, *, source_root: Path | None = None) -> dict:
    """Load/validate a schema-1 profile; fail before installation if assets are absent.

    Returned asset paths remain relative to brands/<id>; use asset_mapping with
    the same source_root to obtain absolute paths. Unknown metadata is retained
    in the source profile but excluded from render_runtime_json.
    """
    if brand not in BRANDS:
        raise ValueError(f'Unknown brand: {brand!r}; expected woowtech or apporo')
    root = Path(source_root if source_root is not None else SOURCE_ROOT).absolute()
    path = _regular(root / 'brands' / brand / 'brand.json', root)
    if path.stat().st_size > 65536:
        raise ValueError('Brand profile is too large')
    profile = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_unique)
    if not isinstance(profile, dict) or type(profile.get('schema')) is not int or profile['schema'] != 1 or profile.get('id') != brand:
        raise ValueError('Invalid brand profile schema or id')
    _text(profile.get('display_name'), 'display_name')
    _text(profile.get('company'), 'company')
    _text(profile.get('tagline', ''), 'tagline', empty=True)
    colors = profile.get('colors')
    if not isinstance(colors, dict):
        raise ValueError('Brand colors must be an object')
    for mode in ('light', 'dark'):
        palette = colors.get(mode)
        if not isinstance(palette, dict):
            raise ValueError(f'Missing {mode} colors')
        for key in ('primary', 'hover', 'on_primary'):
            if key not in palette:
                raise ValueError(f'Missing {mode}.{key}')
        for key, value in palette.items():
            if not isinstance(value, str) or not COLOR.fullmatch(value):
                raise ValueError(f'Invalid color: {mode}.{key}')
    family = profile.get('typography', {}).get('family')
    if family is not None and (not isinstance(family, str) or not re.fullmatch(r'[A-Za-z0-9 ,"\-]+', family)):
        raise ValueError('Invalid font family')
    for key, value in profile.get('layout', {}).items():
        if key not in ('card_radius', 'control_radius') or type(value) is not int or not 0 <= value <= 32:
            raise ValueError('Invalid layout adaptation')
    asset_mapping(profile, source_root=root)
    return profile


def render_runtime_json(profile: dict) -> bytes:
    """Public, source-path-free JSON consumed by the Pi gateway at startup."""
    public = {key: profile[key] for key in ('schema', 'id', 'display_name', 'company', 'colors')}
    public['assets'] = dict(ASSET_TARGETS)
    return (json.dumps(public, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')


def _css_tokens(profile):
    family = profile.get('typography', {}).get('family', 'system-ui, sans-serif')
    result = ['\n/* Generated brand presentation; source assets are unchanged. */']
    for mode, selector in (('light', ':root'), ('dark', ':root.pf-v6-theme-dark')):
        p = profile['colors'][mode]
        primary = [int(p['primary'][i:i+2], 16) for i in (1, 3, 5)]
        page = p.get('page', '#FFFFFF' if mode == 'light' else '#18181B')
        background = [int(page[i:i+2], 16) for i in (1, 3, 5)]
        # Literal sRGB keeps existing browsers and contrast tools consistent.
        wash = '#' + ''.join(f'{int(a * .1 + b * .9 + .5):02X}' for a, b in zip(primary, background))
        rgb = ', '.join(map(str, primary))
        result.append(f'''{selector} {{
  --brand-primary: {p['primary']}; --brand-hover: {p['hover']}; --brand-on-primary: {p['on_primary']};
  --brand-primary-rgb: {rgb}; --brand-font: {family};
  --brand-page: {p.get('page', '#FFFFFF' if mode == 'light' else '#18181B')};
  --brand-surface: {p.get('surface', '#FAFAFA' if mode == 'light' else '#1F1F22')};
  --brand-subtle: {p.get('subtle', '#F4F4F5' if mode == 'light' else '#27272A')};
  --brand-text: {'#212121' if mode == 'light' else '#F1F2F5'};
  --brand-muted: {'#646262' if mode == 'light' else '#C1C5CE'};
  --brand-wash: {wash};
  --ww-blue: var(--brand-primary); --ww-blue-700: var(--brand-hover); --ww-blue-050: var(--brand-wash);
  --ww-page-background: var(--brand-page);
  --color-primary: var(--brand-primary); --color-primary-active: var(--brand-hover);
  --color-link: var(--brand-primary); --color-link-active: var(--brand-hover);
  --color-background: var(--brand-surface); --color-body-background: var(--brand-page);
  --color-text: var(--brand-text); --color-text-secondary: var(--brand-muted);
}}''')
    return '\n'.join(result) + '\n'


def _render_css(path, text, profile):
    # Bounded to authored presentation CSS. Status colors, terminal palettes,
    # app data and third-party bundles never enter this renderer.
    mapping = {'#6183fc':'var(--brand-primary)', '#4a6bd4':'var(--brand-hover)',
               '#3455bf':'var(--brand-primary)', '#8aa4ff':'var(--brand-primary)',
               '#eef2ff':'var(--brand-wash)', '#1b2131':'var(--brand-wash)',
               '#1d2333':'var(--brand-wash)', '#fafbff':'var(--brand-wash)',
               '#111a3a':'var(--brand-on-primary)', '#15171c':'var(--brand-page)',
               '#20232a':'var(--brand-surface)', '#292e37':'var(--brand-subtle)',
               '#2a2e36':'var(--brand-subtle)', '#1a1d23':'var(--brand-subtle)',
               '#fafbfc':'var(--brand-subtle)', '#f5f6f8':'var(--brand-subtle)'}
    text = re.sub(r'#[0-9a-fA-F]{6}\b', lambda m: mapping.get(m[0].lower(), m[0]), text)
    text = re.sub(r'rgba\(97,\s*131,\s*252,\s*([.\d]+)\)', r'rgba(var(--brand-primary-rgb), \1)', text)
    text = re.sub(r'@font-face\s*\{[^}]*\}', '', text)
    text = re.sub(r'(?:"?(?:Poppins|Outfit|Yellowtail)"?)(?:,\s*["\']Noto Sans TC["\'])?(?:,\s*system-ui)?(?:,\s*(?:sans-serif|cursive))?',
                  'var(--brand-font)', text)
    layout = profile.get('layout', {})
    card, control = layout.get('card_radius', 16), layout.get('control_radius', 8)
    text = re.sub(r'(border-radius\s*:\s*)20px\b', rf'\g<1>{card}px', text)
    text = re.sub(r'(border-radius\s*:\s*)12px\b', rf'\g<1>{control}px', text)
    text = re.sub(r'(--(?:radius|radius-sm|pf-t--global--border--radius--(?:small|medium|large))\s*:\s*)(12|20)px',
                  lambda m: m[1] + str(control if m[2] == '12' else card) + 'px', text)
    text += _css_tokens(profile)
    if path == 'branding/branding.css':
        text = text.replace('background-image: url("assets/logo-lockup-blue.svg")', 'background-image: url("assets/logo-lockup-dark.svg")')
        text = text.replace('background-image: url("assets/logo-wordmark-blue.svg")', 'background-image: url("assets/logo-wordmark-dark.svg")')
        text = text.replace('content: "裝置管理中心"', 'content: ' + json.dumps(profile['display_name'], ensure_ascii=False))
        label = json.dumps('apporo' if profile['id'] == 'apporo' else profile['display_name'])
        text += f'''
/* Official square lockup, and official mark plus a plain UI label in the sidebar.
 * White plates preserve the supplied gray artwork in either theme. */
.login-pf #badge {{ aspect-ratio: 1; inline-size: min(50%, 10rem); background-color: #fff;
  background-size: 80% auto; border-radius: {card}px; }}
#nav-system::before {{ content: {label}; background-size: 32px 32px; background-position: 8px center;
  background-color: #fff; padding: 12px 8px 12px 48px; border-radius: {control}px;
  color: #212121; font: 600 16px/24px var(--brand-font); letter-spacing: normal; }}
html.pf-v6-theme-dark #nav-system::before {{ color: #212121; }}
html body.login-pf {{ background: var(--brand-page); color: var(--brand-text); }}
html .login-pf .container {{ background: var(--brand-surface); }}
html .login-pf :is(.login-note,.container-footer) {{ color: var(--brand-muted); }}
html .login-pf .form-control {{ background-color: var(--brand-subtle); color: var(--brand-text); }}
html .login-pf .form-control::placeholder {{ color: var(--brand-muted); opacity: 1; }}
html .login-pf .form-control:focus:not([aria-invalid="true"]) {{ border-color: var(--brand-primary); }}
html .login-pf :is(button,input,select,a):focus-visible {{ outline: 2px solid var(--brand-primary); outline-offset: -3px; }}
html .login-pf #login-button {{ border-color: var(--brand-primary); }}
html .login-pf #login-button:hover, html .login-pf #login-button:active,
html .login-pf #login-button:focus {{ border-color: var(--brand-primary); }}
html:not(.pf-v6-theme-dark) .login-pf #login-button,
html:not(.pf-v6-theme-dark) .pf-v6-c-button.pf-m-primary:not(.pf-m-danger):not(:disabled):not(.pf-m-disabled):not([aria-disabled="true"]),
html.pf-v6-theme-dark .login-pf #login-button:not(:disabled) {{ color: var(--brand-on-primary); background: var(--brand-primary); }}
html .login-pf .login-button, html :is(.pf-v6-c-button.pf-m-primary,.pf-v6-c-button.pf-m-secondary) {{ border-radius: {control}px; }}
html:not(.pf-v6-theme-dark) .login-pf .container, html:not(.pf-v6-theme-dark) :is(.pf-v6-c-card,.ct-card) {{ background: var(--brand-surface); }}
'''
    else:
        text += f'''
:root {{ --surface-page: var(--brand-page); --surface-card: var(--brand-surface); --surface-muted: var(--brand-subtle);
  --page: var(--brand-page); --surface: var(--brand-surface); --subtle: var(--brand-subtle); }}
:root.pf-v6-theme-dark {{ --surface-page: var(--brand-page); --surface-card: var(--brand-surface); --surface-muted: var(--brand-subtle);
  --page: var(--brand-page); --surface: var(--brand-surface); --subtle: var(--brand-subtle); }}
:root :is(button,.button,.action,.secondary,.back-button) {{ border-radius: {control}px; }}
button.primary, .button.primary, .action.primary {{ color: var(--brand-on-primary); background: var(--brand-primary); }}
:root :is(button.primary,.button.primary,.action.primary):hover:not(:disabled) {{ color: var(--brand-on-primary); background: var(--brand-hover); }}
#backup-app a.button.primary {{ color: var(--brand-on-primary); background: var(--brand-primary); }}
#backup-app a.button.primary:hover {{ color: var(--brand-on-primary); background: var(--brand-hover); }}
'''
    return text


def render_file(relative_path: str, data: bytes, profile: dict) -> bytes:
    """Render only explicitly listed source files; all others are byte-identical.

    woowtech is byte-identical to the existing skin. No helper paths, unit names,
    package IDs, archive magic, or legacy key-title parser values are replaced.
    """
    if profile['id'] == 'woowtech':
        return data
    path = relative_path
    allowed = CSS_FILES | HTML_FILES | {'backup/backup.js'}
    if path not in allowed:
        return data
    text = data.decode('utf-8')
    name, company, brand = profile['display_name'], profile['company'], profile['id']
    if path in CSS_FILES:
        text = _render_css(path, text, profile)
    elif path in HTML_FILES:
        replacements = {'woowtech Cockpit': html.escape(name), '· woowtech': '· ' + html.escape(name),
            'woowtech｜Cockpit': html.escape(name), 'woowtech 官方標誌': html.escape(name) + ' 官方標誌',
            'alt="woowtech"': 'alt="' + html.escape(name, quote=True) + '"',
            'WOOWTECH 品牌化': html.escape(name), 'woowtech ·': html.escape(company) + ' ·',
            'The Smart Space Solution': html.escape(profile.get('tagline', '')),
            '官網藍 #6183FC': '品牌主色', '官網主題藍 #6183FC': '品牌主色',
            'Poppins／Outfit／Noto Sans TC': '系統字型', '20px 卡片、12px 輸入框與圓形按鈕': '16px 卡片、8px 輸入框與按鈕'}
        for old, new in replacements.items():
            text = text.replace(old, new)
        # Keep historical layout review explicitly historical; current gallery
        # must not claim the working backup package does not exist.
        if path == 'preview/index.html':
            text = text.replace('目前 Cockpit 尚未安裝專屬備份還原頁；這份圖集呈現現有頁面。新增頁面可沿用這套品牌樣式與導覽結構。',
                '備份與還原由獨立套件提供；此頁僅為畫面參考，不會執行備份操作。')
            text = text.replace('Outfit 是品牌指定字型；Poppins、Noto Sans TC 分別替代 Gira Sans、文鼎 UD 晶熙黑體。',
                '管理介面使用系統字型；標誌沿用正式素材，未重繪或改色。')
    elif path == 'backup/backup.js':
        text = text.replace('已安裝 woowtech 備份元件', '已安裝 ' + name + ' 備份元件')
        text = text.replace('尚未安裝 woowtech 備份元件', '尚未安裝 ' + name + ' 備份元件')
        text = text.replace('包括 woowtech', '包括 ' + company)
    return text.encode('utf-8')


def branding_assets(profile: dict, *, source_root: Path | None = None) -> dict[str, bytes]:
    """Stable installed asset paths for the existing Cockpit CSS and previews."""
    resolved = asset_mapping(profile, source_root=source_root)
    assets = {ASSET_TARGETS[role]: path.read_bytes() for role, path in resolved.items()}
    if profile['id'] != 'woowtech':
        # Replace every existing logo alias on a brand switch, without editing
        # or recoloring the original file bytes. No stale blue/white WOOW logo.
        for shape in ('lockup', 'wordmark'):
            assets[f'assets/logo-{shape}.svg'] = resolved[f'logo_{shape}_light'].read_bytes()
            assets[f'assets/logo-{shape}-white.svg'] = resolved[f'logo_{shape}_dark'].read_bytes()
        for suffix in ('-blue', '-white'):
            assets[f'assets/logo-symbol{suffix}.svg'] = resolved['logo_symbol'].read_bytes()
        assets['assets/logo-symbol.svg'] = resolved['logo_symbol'].read_bytes()
    return assets
