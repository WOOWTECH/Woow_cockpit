"""READ on real HA backups, changed the ways the rows name (copies in a private scratch folder, removed at the end): counts and equality only."""
import gzip, hashlib, io, json, os, shlex, shutil, subprocess, sys, tarfile, tempfile, time
sys.path.insert(0, '/tmp/parity-read-20261125/backup-engine')
from woowbackup import habackup, hasecuretar
from woowbackup.errors import BackupError
B = os.path.expanduser('~/.woowbk-lab/ha-fixtures/')
PLAIN = B + '20261119-arm/woow-arm-plain/woow-arm-plain.tar'
ENC = B + '20261118/woow-import-test-enc/woow-import-test-enc.tar'
RAWENC = B + '20261118/woow-import-test-enc-uncompressed/woow-import-test-enc-uncompressed.tar'
def key():
    for line in open(os.path.expanduser('~/.woowbk-lab/secrets/ha-import-creds.env')):
        for tok in shlex.split(line, comments=True):
            if tok.startswith('HA_BACKUP_KEY='): return tok.split('=', 1)[1]
KEY = key()
def walk(path, keys):
    """{slug or role: digest | error code} of every member."""
    out = {}
    with habackup.open_backup(path) as ha:
        for m in ha.layout.members:
            h = hashlib.sha256(); n = 0
            try:
                with ha.open_member(m.name, keys) as st:
                    r = habackup.Report()
                    for e in habackup.iter_entries(st, habackup.Select(hardlinks=True, symlinks=('.',), absolute_symlinks=('/',)), r):
                        n += 1
                        h.update(repr((e.name, e.kind, e.mode, e.uid, e.gid, e.size, e.linkname)).encode('utf-8', 'surrogateescape'))
                        if e.kind == 'file':
                            while True:
                                d = e.read()
                                if not d: break
                                h.update(d)
                    assert r.complete
                out[m.slug or m.role] = h.hexdigest()
            except BackupError as e:
                out[m.slug or m.role] = 'error ' + e.code + (' member' if e.details.get('scope') == 'member' else '')
        out['problems'] = sorted(a['problem'] for a in ha.layout.summary()['addons'] if 'problem' in a)
    return out
def recognised(path):
    with open(path, 'rb') as fh: return habackup.looks_like_ha(fh.fileno())
def members(path):
    with tarfile.open(path, 'r:') as t:
        return [(m.name, m.offset_data, m.size) for m in t.getmembers()]
rows = []
def row(label, good, detail=''):
    rows.append({'check': label, 'ok': bool(good), 'detail': detail}); print('ok ' if good else 'BAD', label, detail, flush=True)
work = tempfile.mkdtemp(prefix='real-files-', dir=sys.argv[1])
try:
    for name, src in (('plain', PLAIN), ('encrypted v3', ENC)):
        keys = hasecuretar.Keys(KEY) if name != 'plain' else None
        base = walk(src, keys)
        row(f'{name}: the file as HA made it', not base['problems'] and not any(v.startswith('error') for v in base.values() if isinstance(v, str)), f'{len(base) - 1} members')
        folder = os.path.join(work, 'x'); shutil.rmtree(folder, ignore_errors=True); os.mkdir(folder)
        with tarfile.open(src, 'r:') as t:
            for m in t.getmembers():
                with open(os.path.join(folder, m.name.removeprefix('./')), 'wb') as fh: shutil.copyfileobj(t.extractfile(m), fh)
        for tool in ([['tar', f'--format={f}', '-cf', '../y.tar', '.'] for f in ('gnu', 'oldgnu', 'posix', 'ustar', 'v7')]
                     + [['busybox', 'tar', '-cf', '../y.tar', '.'], ['tar', '-b', '1', '--sort=name', '-cf', '../y.tar', '--transform=s,^\\./,,', '.']]):
            subprocess.run(tool, cwd=folder, check=True, capture_output=True)
            y = os.path.join(work, 'y.tar')
            row(f'{name}: repacked with {" ".join(tool[:2])}', recognised(y) and walk(y, keys) == base)
        y = os.path.join(work, 'y.tar'); shutil.copyfile(src, y)
        with open(y, 'ab') as fh: fh.write(os.urandom(100_000))
        row(f'{name}: rubbish behind the archive', recognised(y) and walk(y, keys) == base)
        slugs = [k for k in base if k not in ('problems', 'supervisor', 'homeassistant')]
        victim = next(m for m in members(src) if slugs[0] in m[0])
        for what, at in (('gzip or cipher header', victim[1] + 5), ('first', victim[1] + 300), ('middle', victim[1] + victim[2] // 2), ('last', victim[1] + victim[2] - 3)):
            shutil.copyfile(src, y)
            with open(y, 'r+b') as fh:
                fh.seek(at); b = fh.read(1); fh.seek(at); fh.write(bytes([b[0] ^ 0x20]))
            got = walk(y, keys)
            row(f'{name}: a bit of one add-on changed ({what})', (str(got[slugs[0]]).startswith('error') or what.startswith('gzip') and got[slugs[0]] == base[slugs[0]]) and all(got[k] == base[k] for k in base if k not in (slugs[0], 'problems')), str(got[slugs[0]]))
        # one add-on's archive cut / twice / gone / followed by other bytes, repacked by tarfile
        def rebuilt(change):
            with tarfile.open(src, 'r:') as t, tarfile.open(y, 'w', format=tarfile.PAX_FORMAT) as out:
                for m in t.getmembers():
                    data = t.extractfile(m).read()
                    for piece in (change(data) if slugs[0] in m.name else [data]):
                        info = tarfile.TarInfo(m.name); info.size = len(piece); info.mtime = m.mtime
                        out.addfile(info, io.BytesIO(piece))
            return walk(y, keys)
        others = lambda got: all(got.get(k) == base[k] for k in base if k not in (slugs[0], 'problems'))
        got = rebuilt(lambda d: [d[:-5000]]); row(f'{name}: one add-on cut off', str(got[slugs[0]]).startswith('error') and others(got), str(got[slugs[0]]))
        got = rebuilt(lambda d: [d, d]); row(f'{name}: one add-on twice', got['problems'] == ['duplicate'] and others(got))
        got = rebuilt(lambda d: []); row(f'{name}: one add-on gone', got['problems'] == ['missing'] and others(got))
        got = rebuilt(lambda d: [d + gzip.compress(b'more')])
        row(f'{name}: one add-on followed by another gzip', others(got) and (got[slugs[0]] == base[slugs[0]]))
        got = rebuilt(lambda d: [d + os.urandom(5000)])
        row(f'{name}: one add-on followed by rubbish', others(got) and (got[slugs[0]] == base[slugs[0]] if name != 'plain' else str(got[slugs[0]]).startswith('error')), 'kept' if got[slugs[0]] == base[slugs[0]] else str(got[slugs[0]]))
        shutil.rmtree(folder)
    with tarfile.open(PLAIN, 'r:') as t, tarfile.open(y, 'w', format=tarfile.PAX_FORMAT) as out:  # recompressed in parts
        for m in t.getmembers():
            data = t.extractfile(m).read()
            if m.name.endswith('.tar.gz'):
                raw = gzip.decompress(data); half = len(raw) // 3
                data = gzip.compress(raw[:half], 1) + gzip.compress(raw[half:], 1) + bytes(512)
            info = tarfile.TarInfo(m.name); info.size = len(data); info.mtime = m.mtime; out.addfile(info, io.BytesIO(data))
    row('plain: every add-on recompressed in two gzip parts and padded', walk(y, None) == walk(PLAIN, None))
finally:
    shutil.rmtree(work, ignore_errors=True)
json.dump({'rows': rows, 'ok': sum(r['ok'] for r in rows), 'of': len(rows)}, open(sys.argv[2], 'w'), indent=1, ensure_ascii=False)
print(sum(r['ok'] for r in rows), 'of', len(rows))
