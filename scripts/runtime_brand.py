#!/usr/bin/env python3
"""Read-only brand preflight shared by the Pi and PWA installers."""
import argparse
import json
from pathlib import Path
import re
import sys

DEFAULT_PROFILE = Path('/etc/cockpit/branding/brand.json')
BRANDS = ('woowtech', 'apporo')


def _invalid_constant(value):
    raise ValueError('Invalid JSON constant in installed brand profile')


def validate_profile(profile):
    """Validate the runtime fields used by the gateway; allow additive metadata."""
    if (not isinstance(profile, dict) or type(profile.get('schema')) is not int
            or profile['schema'] != 1):
        raise ValueError('Invalid installed brand profile object or schema')
    if profile.get('id') not in BRANDS:
        raise ValueError('Invalid installed brand profile id')
    colors = profile.get('colors')
    if not isinstance(colors, dict):
        raise ValueError('Invalid installed brand colors')
    for mode in ('light', 'dark'):
        palette = colors.get(mode)
        if not isinstance(palette, dict):
            raise ValueError(f'Invalid installed brand palette: {mode}')
        for key in ('primary', 'hover', 'on_primary'):
            value = palette.get(key)
            if not isinstance(value, str) or not re.fullmatch(r'#[0-9a-fA-F]{6}', value):
                raise ValueError(f'Invalid installed brand color: {mode}.{key}')
    return profile['id']


def selected_brand(requested=None, *, path=DEFAULT_PROFILE):
    """Keep the installed brand; only an absent file permits the legacy default."""
    try:
        raw = Path(path).read_text(encoding='utf-8')
    except FileNotFoundError:
        installed = 'woowtech'
    else:
        # Match the gateway's 16384 UTF-16-code-unit limit (JavaScript length).
        if len(raw.encode('utf-16-le')) // 2 > 16384:
            raise ValueError('Installed brand profile is too large')
        installed = validate_profile(json.loads(raw, parse_constant=_invalid_constant))
    brand = requested or installed
    if brand not in BRANDS or brand != installed:
        raise ValueError('Install the matching Cockpit brand profile before installing its gateway')
    return brand


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--brand', help='Must match the installed brand; omission preserves it.')
    parser.add_argument('--profile', type=Path, default=DEFAULT_PROFILE,
                        help='Runtime JSON path, also usable for isolated fixture validation.')
    args = parser.parse_args()
    try:
        brand = selected_brand(args.brand, path=args.profile)
    except (OSError, ValueError) as error:
        print(f'Brand validation failed: {error}', file=sys.stderr)
        return 1
    print(brand)
    return 0


if __name__ == '__main__':
    sys.exit(main())
