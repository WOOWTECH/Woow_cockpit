"""Fixed n8n case metadata scan; raw + one JSON encoding layer, fail closed.

Uses the reviewed R8 strict file-root/needle pattern. Encrypted archive payloads
are excluded by design; actual sidecars and both regular JSON roots are required.
Inputs remain on stdin, output is counts only. Importing performs no device I/O.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

BASE = '/var/lib/woowtech-backup/'
ROOTS = [BASE+p for p in ('jobs', 'ha-backups', 'ha-imports.json', 'requests.json',
    'archives', 'uploads', 'staging', 'pending', 'exports')] + ['/run/woowtech-backup']


def secret_scan_needles(values):
    needles = set()
    for value in values:
        raw = value if isinstance(value, bytes) else value.encode('utf-8')
        if not raw: continue
        needles.add(raw)
        try: decoded = raw.decode('utf-8')
        except UnicodeDecodeError: continue
        for ascii_only in (False, True):
            needles.add(json.dumps(decoded, ensure_ascii=ascii_only)[1:-1].encode('utf-8'))
    return needles


def scan_paths(root):
    if not os.path.exists(root) or os.path.islink(root): raise RuntimeError('fixed scan root unsafe')
    if os.path.isfile(root): return [str(root)]
    if not os.path.isdir(root): raise RuntimeError('fixed scan root nonregular')
    paths = []
    def walk_error(error): raise RuntimeError('fixed scan enumeration failed') from None
    for directory, dirs, files in os.walk(root, onerror=walk_error, followlinks=False):
        if any(os.path.islink(os.path.join(directory, name)) for name in dirs):
            raise RuntimeError('fixed scan directory symlink')
        paths.extend(os.path.join(directory, name) for name in files)
        if len(paths) > 10000: raise RuntimeError('fixed scan file bound')
    return paths


def scan(values, roots=ROOTS, *, base=BASE, journal=b''):
    needles = secret_scan_needles(values); hits = scanned = sidecars = json_roots = 0
    for root in roots:
        for p in scan_paths(root):
            if os.path.islink(p): raise RuntimeError('fixed scan file symlink')
            if p.endswith(('.tar', '.woowbackup')) and p.startswith((base+'archives/', base+'ha-backups/')):
                continue
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_size > 64*1024**2:
                    raise RuntimeError('fixed scan file unsafe or oversized')
                with os.fdopen(os.dup(fd), 'rb') as inp: data = inp.read(64*1024**2+1)
                after = os.fstat(fd)
                if len(data) != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise RuntimeError('fixed scan file changed')
            finally: os.close(fd)
            scanned += 1; hits += sum(data.count(n) for n in needles)
            if p in (base+'ha-imports.json', base+'requests.json'): json_roots += 1
            if p.startswith(base+'archives/') and p.endswith('.json'): sidecars += 1
    expected = len(list(Path(base+'archives').rglob('*.json')))
    if json_roots != 2 or sidecars != expected or sidecars == 0 or scanned == 0:
        raise RuntimeError('fixed scan coverage incomplete')
    if len(journal) > 64*1024**2: raise RuntimeError('fixed scan journal bound')
    hits += sum(journal.count(n) for n in needles)
    return {'hits':hits, 'scanned':scanned, 'archive_index_sidecars_scanned':sidecars,
        'actual_archive_index_sidecars_expected':expected, 'regular_json_roots_scanned':json_roots,
        'journal_bytes':len(journal)}


def main():
    request = json.load(sys.stdin); values = request['values']
    if (not isinstance(values, list) or len(values) > 110 or
            not all(isinstance(v, str) and v and len(v) <= 16384 for v in values)):
        raise ValueError('fixed scan value bound')
    for name in ('n8n-db-password', 'n8n-runners-auth-token', 'n8n-valkey-password'):
        p = subprocess.run(['/usr/local/bin/woowbk-owner', 'podman', 'secret', 'inspect',
            '--showsecret', '--format', '{{.SecretData}}', name], capture_output=True, check=True, timeout=60)
        value = p.stdout.rstrip(b'\n')
        if not value or len(value) > 16384: raise ValueError('fixed scan selected secret bound')
        values.append(value)
    if type(request['since']) is not int: raise ValueError('fixed scan timestamp')
    journal = subprocess.run(['journalctl', '--no-pager', '-o', 'cat', '--since', '@%d'%request['since']],
        capture_output=True, check=True, timeout=60).stdout
    print(json.dumps(scan(values, journal=journal)))


if __name__ == '__main__': main()
