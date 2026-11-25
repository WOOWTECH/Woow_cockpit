import sys, io, random, re
sys.path.insert(0, '/tmp/parity-read-20261125/backup-engine')
sys.path.insert(0, '/tmp/parity-read-20261125')
from woowbackup import habackup
from woowbackup.errors import BackupError
from tests.backup import hafixtures as hx

NAMES = ['a', 'a/b', 'a/../b', '../a', '/a', 'a//b', './a', 'a/.', 'a/', '', '.', '..', 'a\x01b', 'a\nb', 'data/options.json',
         'data/options.json/x', 'addon.json', 'x' * 5000, 'é', 'a/b/c', 'b', 'b/c', 'c/d/e', 'data/secrets/api_server_key', 'data', 'data/x', './', 'a/b/../c']
TYPES = [b'0', b'0', b'0', b'5', b'5', b'2', b'1', b'3', b'4', b'6', b'7', b'S', b'A', b'\0', b'D']
LINKS = ['a', 'b', '../a', '/etc/passwd', 'a/b', 'data/options.json', 'addon.json', '', '.', 'c/d/e', 'a/../b', 'x' * 100]
SELECTS = [habackup.Select(), habackup.Select(symlinks=('.',), hardlinks=True), habackup.Select(include=('a',)),
           habackup.Select(include=('a', 'b'), exclude=('a/b',), symlinks=('a',), absolute_symlinks=('/etc',)),
           habackup.Select(include=('c',), hardlinks=True, symlinks=('c',))]
rng = random.Random(778)
stats = {'refused': 0, 'ok': 0}
bad = 0
def build():
    out = []
    for _ in range(rng.randrange(1, 14)):
        name = rng.choice(NAMES) if rng.random() < 0.12 else rng.choice(['a', 'a/b', 'a/b/c', 'b', 'b/c', 'c/d/e', 'c', 'c/d', 'x1', 'x2', 'data/x', 'data/y']); typ = rng.choice(TYPES) if rng.random() < 0.3 else rng.choice([b'0', b'0', b'0', b'5', b'2', b'1'])
        data = rng.randbytes(rng.choice([0, 1, 10, 600])) if typ in (b'0', b'\0', b'7') else b''
        link = rng.choice(LINKS) if typ in (b'1', b'2') else ''
        try:
            if name == '' or '\x00' in name:
                raise ValueError
            out.append(hx.raw_member(name, data, typeflag=typ, linkname=link, magic=hx.USTAR if len(name.encode()) < 100 else hx.GNU) if len(name.encode()) < 100 else b'')
        except Exception:
            pass
    return b''.join(out) + hx.END
for round_ in range(6000):
    raw = build()
    for si, select in enumerate(SELECTS):
        for addon in (False, True):
            report = habackup.Report()
            seen = []
            try:
                for e in habackup.iter_entries(io.BytesIO(raw), select, report, addon=addon):
                    data = e.read_all(1 << 20) if e.kind == 'file' else None
                    seen.append((e.name, e.kind, e.linkname, data))
            except BackupError as error:
                stats['refused'] += 1
                continue
            except BaseException as error:
                bad += 1; print('RAISED', type(error).__name__, error, round_, si); continue
            stats['ok'] += 1
            names = [n for n, k, l, d in seen]
            # I2: normalised names
            for n, k, l, d in seen:
                if n.startswith('/') or any(p in ('', '..') for p in n.split('/')) and n != '.' or re.search(r'[\x00-\x1f\x7f]', n) or len(n.encode()) > 4096:
                    bad += 1; print('BAD NAME', repr(n)[:80], round_, si)
                if habackup.never_read(n) and k == 'file':
                    bad += 1; print('SECRET HANDED OUT', repr(n), round_, si)
                if addon and n == 'addon.json':
                    bad += 1; print('addon.json HANDED OUT', round_, si)
                if not select.wants(n) and n != '.':
                    bad += 1; print('NOT WANTED', repr(n), round_, si)
            # I4: unique names
            if len(set(names)) != len(names):
                bad += 1; print('DUPLICATE', names, round_, si)
            # I5: nothing below a non-directory (among what is handed out)
            kinds = {n: k for n, k, l, d in seen}
            for n in names:
                parts = n.split('/')
                for i in range(1, len(parts)):
                    if kinds.get('/'.join(parts[:i])) in ('file', 'symlink', 'hardlink'):
                        bad += 1; print('BELOW NON-DIR', n, round_, si)
print(stats, 'violations', bad)
