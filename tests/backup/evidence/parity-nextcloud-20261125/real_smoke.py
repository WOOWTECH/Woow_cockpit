#!/usr/bin/env python3
"""Pure-Python smoke of the new module code on a REAL encrypted HA backup (the no-share Nextcloud fixture of 2026-11-23, 248 MB):
scan_member + the config.php parser + config_issues + datadir_issues, no container, nothing written. The key is read in-process from the
lab creds file and never printed; only names, ids and booleans are."""
import json, shlex, sys
sys.path[:0] = ['/tmp/parity-nextcloud-verify-20261125/backup-engine']
from woowbackup import habackup, hasecuretar, hastore, haissues, ha_nextcloud as nc

def key():
    for line in open('/home/woowtechopenclaw/.woowbk-lab/secrets/ha-import-creds.env', encoding='utf-8'):
        for token in shlex.split(line, comments=True):
            name, _sep, value = token.partition('=')
            if name == 'HA_BACKUP_KEY' and value:
                return value
    raise SystemExit('no key')

path = '/home/woowtechopenclaw/.woowbk-lab/ha-fixtures/20261123-batch2/x86/woow-b2-nextcloud-x86-enc-noshare/woow-b2-nextcloud-x86-enc-noshare-20261123.tar'
ha = habackup.open_backup(path)
members = [m for m in ha.layout.members if m.role == 'addon' and hastore.addon_suffix(m.slug) == nc.SLUG]
report = habackup.Report(names=haissues.Names)
with ha.open_member(members[0].name, hasecuretar.Keys(key())) as stream:
    src = nc.scan_member(stream, report, pg=None, apps=None, machine=0x3E)
src.report = report
live = {'version': src.config.get('version') if isinstance(src.config, dict) else '35.0.1.1', 'installed': True,
        'dbtableprefix': 'oc_', 'dbtype': 'pgsql', 'dbuser': 'oc_admin', 'dbname': 'nextcloud',
        'datadirectory': '/var/www/html/data', 'overwrite.cli.url': 'http://127.0.0.1:18081', 'maintenance': False}
sink = haissues.Sink('nextcloud')
nc.config_issues(sink, src.config, live, '.'.join(str(live['version']).split('.')[:3]), found=src.config_found,
                 addon_version=src.addon.version if src.addon else None)
nc.datadir_issues(sink, src.config, 'no-share', nc.datadir_source((src.config or {}).get('datadirectory')))
print(json.dumps({'config_found': src.config_found, 'config_parsed': isinstance(src.config, dict),
                  'datadir_source': nc.datadir_source((src.config or {}).get('datadirectory')),
                  'issues': [(i.id, i.level) for i in sink.found], 'skipped': report.skip_count(), 'pg_files': src.pg_files,
                  'complete': report.complete}, ensure_ascii=False))
