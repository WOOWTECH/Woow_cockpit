#!/usr/bin/env python3
"""Read-only scan of a real Nextcloud HA backup member with ha_nextcloud.scan_member, inside a throwaway lab container
(network none, read-only; the HA key on stdin). Prints only non-secret facts: names, versions, booleans. Lane
nextcloud-import, 2026-11-23; run command in tests/e2e/lab/evidence/nextcloud-import-20261123/noshare-member-scan.json."""
import json, sys
sys.path[:0] = ['/eng', '/nacl/usr/lib/python3/dist-packages']
from woowbackup import habackup, hasecuretar, hastore, ha_nextcloud as nc
key = sys.stdin.read().strip()
ha = habackup.open_backup('/fixture.tar')
members = [m for m in ha.layout.members if m.role == 'addon' and hastore.addon_suffix(m.slug) == nc.SLUG]
folders = sorted(m.slug for m in ha.layout.members if m.role == 'folder')
keys = hasecuretar.Keys(key)
report = habackup.Report()
with ha.open_member(members[0].name, keys) as stream:
    src = nc.scan_member(stream, report, pg=None, apps=None, machine=0x3E)
c = src.config if isinstance(src.config, dict) else {}
live = {'version': '35.0.1.1', 'installed': True, 'dbtableprefix': 'oc_', 'dbtype': 'pgsql', 'dbuser': 'oc_admin',
        'dbname': 'nextcloud', 'datadirectory': '/var/www/html/data', 'overwrite.cli.url': 'http://127.0.0.1:18081'}
out = {'folders': folders, 'addon': src.addon.as_dict() if src.addon else None, 'pg_version': src.pg_version,
       'pg_files': src.pg_files, 'pg_bytes': src.pg_bytes, 'config_found': src.config_found,
       'config_parsed': isinstance(src.config, dict), 'keys': sorted(str(k) for k in c),
       'plain': {k: c.get(k) for k in ('version', 'installed', 'dbtype', 'dbtableprefix', 'datadirectory', 'maintenance',
                                       'dbname', 'dbuser', 'overwrite.cli.url', 'twofactor_enforced', 'app_install_overwrite')
                 if k in c and not isinstance(c.get(k), (dict,))},
       'identity_ok': bool(c) and not any('身分資料' in b for b in nc.config_blockers(c, live, '35.0.1')),
       'config_blockers': nc.config_blockers(c if src.config_found else None, live, '35.0.1'),
       'datadir_source': nc.datadir_source(c.get('datadirectory')),
       'apps': {a: {k: v for k, v in i.items()} for a, i in sorted(src.apps.items())}, 'bad_apps': src.bad_apps,
       'app_warnings': nc.app_warnings(src.apps, nc_version_text='35.0.1.1', php_version='8.5.11'),
       'skipped_symlinks': report.skipped_symlinks, 'entries': report.entries, 'complete': report.complete}
if c:
    merged, carried, skipped = nc.merge_config(c, dict(live, instanceid='oclive123456', passwordsalt='x' * 30, secret='y' * 48))
    out['roundtrip'] = nc.parse_config(nc.render_config(merged)) == merged
    out['carried'], out['skipped'] = carried, skipped
    out['mail_keys'] = sorted(k for k in c if str(k).startswith('mail_'))
print(json.dumps(out, ensure_ascii=False, default=str))
