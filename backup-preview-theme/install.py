#!/usr/bin/env python3
"""Add a theme overlay to the existing static backup design preview."""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import tempfile

HERE = Path(__file__).resolve().parent
MARK = '<!-- woowtech-backup-preview-theme -->'
TAGS = f'{MARK}\n<script src="woow-theme.js"></script>\n<link rel="stylesheet" href="woow-dark.css">\n'

def atomic(path, data):
    fd, tmp = tempfile.mkstemp(prefix='.woow-theme-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', type=Path, default=Path('/usr/local/share/cockpit/woowbackupdesign'))
    parser.add_argument('--backup', type=Path, default=Path('/var/backups/woowtech-cockpit-source'))
    args = parser.parse_args()
    if args.target.is_symlink() or not args.target.is_dir(): raise SystemExit('Backup preview package not found or is a symlink.')
    index = args.target / 'index.html'
    if index.is_symlink() or not index.is_file(): raise SystemExit('Backup preview index is missing or a symlink.')
    original = index.read_text(encoding='utf-8')
    if MARK not in original:
        marker = '<link rel="stylesheet" href="style.css">'
        if original.count(marker) != 1: raise SystemExit('Unrecognized preview index; no changes made.')
        updated = original.replace(marker, marker + '\n' + TAGS)
    else:
        updated = original
    for name in ('woow-theme.js','woow-dark.css'):
        target = args.target / name
        if target.is_symlink(): raise SystemExit('Theme file is a symlink; no changes made.')
    args.backup.mkdir(parents=True, mode=0o700, exist_ok=True)
    backup = args.backup / ('backup-preview-theme-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(mode=0o700)
    for name in ('index.html','woow-theme.js','woow-dark.css'):
        existing = args.target / name
        if existing.is_file(): shutil.copy2(existing, backup / name)
    atomic(args.target / 'woow-theme.js', (HERE / 'theme.js').read_bytes())
    atomic(args.target / 'woow-dark.css', (HERE / 'dark.css').read_bytes())
    atomic(index, updated.encode())
    print(f'Backup preview theme installed; previous files: {backup}')

if __name__ == '__main__': main()
