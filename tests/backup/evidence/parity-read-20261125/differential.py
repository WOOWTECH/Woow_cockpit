"""Old reader (e7d687b) against the new one on real HA backups: every member, entry by entry, byte by byte.
Prints counts and equality only, never content, names or keys. usage: differential.py OUT.json file.tar..."""
import hashlib, importlib, json, os, shlex, sys, time, resource
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'old'))
import oldwoow.habackup as old
import oldwoow.hasecuretar as oldsec
sys.path.insert(0, '/tmp/parity-read-20261125/backup-engine')
import woowbackup.habackup as new
import woowbackup.hasecuretar as newsec
from oldwoow.errors import BackupError as OldError
from woowbackup.errors import BackupError as NewError

def key():
    with open(os.path.expanduser('~/.woowbk-lab/secrets/ha-import-creds.env')) as fh:
        for line in fh:
            for tok in shlex.split(line, comments=True):
                if tok.startswith('HA_BACKUP_KEY='):
                    return tok.split('=', 1)[1]

KEY = key()
KINDS = dict(symlinks=('.',), absolute_symlinks=('/',), hardlinks=True)

def walk(mod, sec, err, path, name):
    h = hashlib.sha256()
    counts = {}
    with mod.open_backup(path) as ha:
        with ha.open_member(name, sec.Keys(KEY)) as stream:
            report = mod.Report()
            for e in mod.iter_entries(stream, mod.Select(**KINDS), report):
                counts[e.kind] = counts.get(e.kind, 0) + 1
                h.update(repr((e.name, e.kind, e.mode, e.uid, e.gid, e.size, e.mtime, e.linkname)).encode('utf-8', 'surrogateescape'))
                if e.kind == 'file':
                    while True:
                        data = e.read()
                        if not data:
                            break
                        h.update(data)
            addon = report.addon.as_dict() if report.addon else None
            rest = (report.entries, report.files, report.dirs, report.symlinks, report.hardlinks, report.bytes,
                    report.skipped_symlinks, report.skipped_other, report.secret_files, report.complete, addon)
    return h.hexdigest(), rest, counts, getattr(report, 'skip_text', lambda: '')()

out, results = sys.argv[1], []
for path in sys.argv[2:]:
    t0 = time.time()
    row = {'file': os.path.basename(path)[:60], 'size': os.path.getsize(path), 'members': 0, 'equal': 0, 'wrong_key': 0, 'diff': [],
           'entries': 0, 'skips': []}
    with old.open_backup(path) as o, new.open_backup(path) as n:
        so, sn = o.layout.summary(), n.layout.summary()
        row['summary_equal'] = so == sn
        row['members_equal'] = [(m.name, m.offset, m.size, m.role, m.slug, m.encryption, m.compressed) for m in o.layout.members] == \
            [(m.name, m.offset, m.size, m.role, m.slug, m.encryption, m.compressed) for m in n.layout.members]
        row['problems'] = [m.problem for m in n.layout.members if m.problem]
        row['ignored'] = n.layout.ignored_count
        names = [m.name for m in o.layout.members]
    for index, name in enumerate(names):
        row['members'] += 1
        try:
            a = walk(old, oldsec, OldError, path, name)
        except OldError as e:
            a = ('error', e.code, e.details.get('reason'))
        try:
            b = walk(new, newsec, NewError, path, name)
        except NewError as e:
            b = ('error', e.code, e.details.get('reason'))
        if a[0] == 'error' and a[1] == 'wrong-key' and b[0] == 'error' and b[1] == 'wrong-key':
            row['wrong_key'] += 1
            continue
        if a[0] != 'error' and b[0] != 'error':
            row['entries'] += a[1][0]
            if b[3]:
                row['skips'].append(b[3])
        if a[:2] == b[:2] and (a[0] == 'error' or a[2] == b[2]):
            row['equal'] += 1
        else:
            row['diff'].append({'member': index, 'old': str(a[:2])[:120] if a[0] == 'error' else 'walked',
                                'new': str(b[:2])[:120] if b[0] == 'error' else 'walked'})
    row['seconds'] = round(time.time() - t0, 1)
    results.append(row)
    print(json.dumps(row, ensure_ascii=False), flush=True)
    with open(out, 'w') as fh:
        json.dump({'results': results, 'maxrss_mib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024}, fh, indent=1, ensure_ascii=False)
