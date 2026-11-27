import sys, io, os, random, tarfile
sys.path.insert(0, '/tmp/parity-read-20261125/backup-engine')
from woowbackup import habackup
from woowbackup.errors import BackupError

rng = random.Random(4242)
ALPHA = ['a', 'b', 'é', '中', 'x y', 'd-1', '長'*30, 'n'*120, '.hid', 'file.tar.gz', 'ü']
def name(depth):
    return '/'.join(rng.choice(ALPHA) + str(rng.randrange(5)) for _ in range(depth))
bad = 0
for round_ in range(1500):
    fmt = rng.choice([tarfile.PAX_FORMAT, tarfile.GNU_FORMAT, tarfile.USTAR_FORMAT])
    buf = io.BytesIO()
    entries = []
    files, dirs, allnames = set(), set(), set()
    with tarfile.open(fileobj=buf, mode='w', format=fmt) as tf:
        for _ in range(rng.randrange(1, 25)):
            n = name(rng.randrange(1, 5))
            parts = n.split('/')
            kind = rng.choice(['file', 'file', 'file', 'dir', 'symlink'])
            if n in files or n in dirs:
                continue
            if any('/'.join(parts[:i]) in files for i in range(1, len(parts))):
                continue
            if kind != 'dir' and any(x.startswith(n + '/') for x in allnames):
                continue
            if fmt == tarfile.USTAR_FORMAT and (len(n.encode()) > 99 or not n.isascii()):
                continue
            info = tarfile.TarInfo(n)
            info.mode = rng.choice([0o644, 0o755, 0o600, 0o4755, 0o777])
            info.uid = rng.choice([0, 1000, 70000] + ([9_000_000] if fmt != tarfile.USTAR_FORMAT else []))
            info.gid = rng.choice([0, 100, 70000])
            info.mtime = rng.choice([0, 1794992487] + ([1794992487.25, 1e9 + 0.5] if fmt == tarfile.PAX_FORMAT else []))
            data = b''
            if kind == 'file':
                info.size = rng.choice([0, 1, 511, 512, 513, 4096, 70000])
                data = rng.randbytes(info.size)
                files.add(n)
            elif kind == 'dir':
                info.type = tarfile.DIRTYPE
                dirs.add(n)
            else:
                info.type = tarfile.SYMTYPE
                info.linkname = rng.choice(['target', 'a/b'])
                files.add(n)
            allnames.add(n)
            for i in range(1, len(parts)):
                allnames.add('/'.join(parts[:i]))
            tf.addfile(info, io.BytesIO(data) if kind == 'file' else None)
    raw = buf.getvalue()
    ref = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as tf:
        for m in tf.getmembers():
            kind = 'file' if m.isreg() else 'dir' if m.isdir() else 'symlink' if m.issym() else '?'
            ref.append((m.name, kind, m.mode & 0o7777, m.uid, m.gid, m.size if kind == 'file' else 0, float(m.mtime), m.linkname if kind == 'symlink' else None,
                        tf.extractfile(m).read() if kind == 'file' else None))
    got = []
    try:
        for e in habackup.iter_entries(io.BytesIO(raw), habackup.Select(symlinks=('.',), absolute_symlinks=()), habackup.Report(), addon=False):
            got.append((e.name, e.kind, e.mode, e.uid, e.gid, e.size, float(e.mtime), e.linkname if e.kind == 'symlink' else None,
                        e.read_all(1 << 20) if e.kind == 'file' else None))
    except BackupError as error:
        print('REFUSED', round_, fmt, error.code, error.details.get('reason')); bad += 1; continue
    # symlinks that leave the area are skipped by us: compare without them
    ref2 = list(ref)
    got2 = [g for g in got]
    # ours drops '.'-normalised names; compare as sets of tuples
    ref2 = [(r[0].rstrip('/'),) + r[1:] for r in ref2]
    if sorted(map(repr, ref2)) != sorted(map(repr, got2)):
        bad += 1
        missing = [r[:2] for r in ref2 if repr(r) not in set(map(repr, got2))][:3]
        extra = [g[:2] for g in got2 if repr(g) not in set(map(repr, ref2))][:3]
        print('DIFF', round_, fmt, 'missing', missing, 'extra', extra)
print('rounds 1500, differences', bad)
