"""Runs INSIDE a network-none lab container (labpodman, woowbk-device:noble). Strictly walks the Nextcloud add-on
member AND the share folder member of one encrypted HA backup with the product's own reader (backup-engine/woowbackup/
habackup.py of this branch, read-only mount). Prints one JSON object: layout, per-member entry counts by kind, the
per-user file-manifest digests of the Nextcloud datadirectory and of the code-server workspace (same method as
ncs-inv.sh: sha256 over the `sha256sum` lines "<hex>  ./<path>" sorted bytewise by "./<path>"), and 16-char sha256
prefixes of the given marker paths (share-relative). The key arrives on stdin (one line) and is never printed; names
of the owner's files are never printed (counts, sizes and digests only)."""
import hashlib, json, sys
sys.path.insert(0, '/code/backup-engine'); sys.path.insert(0, '/hostdist')
from woowbackup import habackup, hasecuretar
from woowbackup.errors import BackupError

path, slug, datadir, markers = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
key = sys.stdin.readline().rstrip('\n')
out = {'file': path.rsplit('/', 1)[-1], 'addon_member_slug': slug, 'datadir_in_share': datadir}


def digest(items):
    """items: {'./rel': hexdigest} -> the sha256 of the sorted sha256sum lines (what ncs-inv.sh prints)."""
    lines = ''.join(f'{items[p]}  {p}\n' for p in sorted(items, key=lambda p: p.encode('utf-8', 'surrogateescape')))
    return hashlib.sha256(lines.encode('utf-8', 'surrogateescape')).hexdigest()


def walk(hb, member, keys, hashed, see=lambda e: None):
    report, kinds, tops, sums = habackup.Report(), {}, {}, {}
    sel = habackup.Select(include=None, symlinks=('.',), hardlinks=True)
    with hb.open_member(member.name, keys) as stream:
        for e in habackup.iter_entries(stream, sel, report):
            kinds[e.kind] = kinds.get(e.kind, 0) + 1
            parts = e.name.split('/')
            top = '/'.join(parts[:3]) if member.role == 'addon' and parts[0] == 'data' and len(parts) > 2 else parts[0]
            t = tops.setdefault(top, [0, 0]); t[0] += 1; t[1] += e.size or 0
            see(e)
            if e.kind == 'file' and hashed(e.name):
                h = hashlib.sha256()
                while True:
                    b = e.read()
                    if not b:
                        break
                    h.update(b)
                sums[e.name] = {'sha256': h.hexdigest(), 'size': e.size, 'uid': e.uid, 'gid': e.gid, 'mode': oct(e.mode)}
    info = {'complete': report.complete, 'entries': report.entries, 'kinds': kinds, 'bytes': report.bytes,
            'skipped_symlinks': report.skipped_symlinks, 'skipped_fifos': report.skipped_other,
            'never_read_skipped': report.secret_files, 'addon': report.addon.as_dict() if report.addon else None}
    return info, tops, sums


try:
    with habackup.open_backup(path) as hb:
        s = hb.layout.summary()
        out['layout'] = {k: s[k] for k in ('name', 'date', 'type', 'supervisor_version', 'protected', 'compressed', 'folders', 'supervisor', 'size')}
        out['layout']['addons'] = [{k: a.get(k) for k in ('slug', 'version', 'size', 'encryption')} for a in s['addons']]
        out['members'] = [{'name': m.name, 'role': m.role, 'size': m.size, 'encryption': m.encryption} for m in hb.layout.members]
        keys = hasecuretar.Keys(key)
        addon_member = hb.layout.addon(slug)
        info, tops, _ = walk(hb, addon_member, keys, lambda n: False)
        out['addon_walk'] = info
        out['addon_top_dirs'] = {k: {'entries': v[0], 'bytes': v[1]} for k, v in sorted(tops.items(), key=lambda kv: -kv[1][1])[:12]}
        share = [m for m in hb.layout.members if m.role == 'folder' and m.slug == 'share']
        if not share:
            out['share_walk'] = 'MISSING'
        else:
            pre = datadir.rstrip('/') + '/'
            def hashed(n):
                p = n.split('/')
                return (n.startswith(pre) and len(p) >= 4 and p[2] == 'files') or p[0] == 'projects' or n in markers
            extra = {'ncdata': False, 'versions': {}, 'trash': {}}
            def see(e):
                p = e.name.split('/')
                if e.name == pre + '.ncdata' and e.kind == 'file':
                    extra['ncdata'] = True
                if e.kind == 'file' and e.name.startswith(pre) and len(p) >= 4 and p[2] in ('files_versions', 'files_trashbin'):
                    d = extra['versions' if p[2] == 'files_versions' else 'trash']; d[p[1]] = d.get(p[1], 0) + 1
            info, tops, sums = walk(hb, share[0], keys, hashed, see)
            out['share_walk'] = info
            dd = tops.get(datadir.rstrip('/'), [0, 0]); pr = tops.get('projects', [0, 0])
            out['share_tops'] = {'top_level_entries': len(tops), 'datadir': {'entries': dd[0], 'bytes': dd[1]},
                                 'projects': {'entries': pr[0], 'bytes': pr[1]},
                                 'other': {'entries': sum(v[0] for k, v in tops.items() if k not in (datadir.rstrip('/'), 'projects')),
                                           'bytes': sum(v[1] for k, v in tops.items() if k not in (datadir.rstrip('/'), 'projects'))}}
            users = {}
            for n, v in sums.items():
                p = n.split('/')
                if n.startswith(pre) and len(p) >= 4 and p[2] == 'files':
                    users.setdefault(p[1], {})['./' + '/'.join(p[3:])] = v
            out['users'] = {u: {'files': len(f), 'bytes': sum(x['size'] for x in f.values()),
                                'digest': digest({k: x['sha256'] for k, x in f.items()}),
                                'odd_names': sum(1 for k in f if '\\' in k or '\n' in k)} for u, f in sorted(users.items())}
            for u in out['users']:
                out['users'][u]['versions'] = extra['versions'].get(u, 0)
                out['users'][u]['trash'] = extra['trash'].get(u, 0)
            proj = {'./' + n[len('projects/'):]: v['sha256'] for n, v in sums.items() if n.startswith('projects/')}
            out['projects'] = {'files': len(proj), 'bytes': sum(v['size'] for n, v in sums.items() if n.startswith('projects/')), 'digest': digest(proj)}
            out['ncdata'] = 'present' if extra['ncdata'] else 'MISSING'
            out['markers'] = {m: ({'sha256_16': sums[m]['sha256'][:16], 'size': sums[m]['size'], 'uid': sums[m]['uid'],
                                   'gid': sums[m]['gid'], 'mode': sums[m]['mode']} if m in sums else 'MISSING') for m in markers}
        out['result'] = 'ok'
except BackupError as exc:
    out['result'] = 'refused'
    out['error'] = {'code': getattr(exc, 'code', None), 'details': {k: str(v)[:200] for k, v in (getattr(exc, 'details', {}) or {}).items()}}
print(json.dumps(out, ensure_ascii=False))
