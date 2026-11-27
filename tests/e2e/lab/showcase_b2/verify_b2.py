"""Runs INSIDE a network-none lab container (labpodman, woowbk-device:noble). Strictly walks one encrypted HA backup with
the product's own reader (backup-engine/woowbackup/habackup.py from R-COCKPIT feat/ha-import-batch1, read-only mount):
layout summary, addon.json facts, entry counts per kind, special entries, sha256 of the given marker paths.
The key arrives on stdin (one line) and is never printed. Prints one JSON object; names, counts and hashes only."""
import hashlib, json, sys
sys.path.insert(0, '/code/backup-engine'); sys.path.insert(0, '/hostdist')
from woowbackup import habackup, hasecuretar
from woowbackup.errors import BackupError

path, slug, markers = sys.argv[1], sys.argv[2], sys.argv[3:]
key = sys.stdin.readline().rstrip('\n')
out = {'file': path.rsplit('/', 1)[-1], 'addon_member_slug': slug}
try:
    with habackup.open_backup(path) as hb:
        s = hb.layout.summary()
        out['layout'] = {k: s[k] for k in ('name', 'date', 'type', 'supervisor_version', 'protected', 'compressed', 'folders', 'supervisor', 'size')}
        out['layout']['addons'] = [{k: a.get(k) for k in ('slug', 'version', 'size', 'encryption')} for a in s['addons']]
        out['members'] = [{'name': m.name, 'role': m.role, 'size': m.size, 'encryption': m.encryption} for m in hb.layout.members]
        keys = hasecuretar.Keys(key)
        report = habackup.Report()
        kinds, tops, found = {}, {}, {}
        sel = habackup.Select(include=None, symlinks=('.',), hardlinks=True)
        with hb.open_addon(slug, keys) as stream:
            for e in habackup.iter_entries(stream, sel, report):
                kinds[e.kind] = kinds.get(e.kind, 0) + 1
                parts = e.name.split('/')
                top = '/'.join(parts[:3]) if parts[0] == 'data' and len(parts) > 2 else '/'.join(parts[:2])
                t = tops.setdefault(top, [0, 0]); t[0] += 1; t[1] += e.size or 0
                if e.name in markers and e.kind == 'file':
                    h = hashlib.sha256()
                    while True:
                        b = e.read()
                        if not b: break
                        h.update(b)
                    found[e.name] = {'sha256_16': h.hexdigest()[:16], 'size': e.size, 'uid': e.uid, 'gid': e.gid, 'mode': oct(e.mode)}
        out['walk'] = {'complete': report.complete, 'entries': report.entries, 'kinds': kinds, 'bytes': report.bytes,
                       'skipped_symlinks': report.skipped_symlinks, 'skipped_fifos': report.skipped_other,
                       'never_read_skipped': report.secret_files,
                       'addon': report.addon.as_dict() if report.addon else None}
        out['top_dirs'] = {k: {'entries': v[0], 'bytes': v[1]} for k, v in sorted(tops.items(), key=lambda kv: -kv[1][1])[:14]}
        out['markers'] = {m: found.get(m, 'MISSING') for m in markers}
        out['result'] = 'ok'
except BackupError as exc:
    out['result'] = 'refused'
    out['error'] = {'code': getattr(exc, 'code', None), 'details': {k: str(v)[:200] for k, v in (getattr(exc, 'details', {}) or {}).items()}}
print(json.dumps(out, ensure_ascii=False))
