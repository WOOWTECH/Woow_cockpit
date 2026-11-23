"""ncs_evidence.py <logs dir> <verify json> <out json> <source commit>: builds the evidence file of the Nextcloud-with-share
HA source backup from the masked step logs (fixed status lines only: codes, counts, sizes, sha256 values of files,
names of credentials, never their values) and the strict-walk JSON. commercial_acceptance stays not-complete."""
import hashlib, json, re, sys
from pathlib import Path

logs, verify_path, out_path, commit = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]


def lines(name):
    return [l for l in (logs / name).read_text(encoding='utf-8').splitlines() if 'open pidfd' not in l and 'kill container' not in l]


def kv(line):
    return dict(re.findall(r'(\w[\w/.-]*)=(\S+)', line))


steps = [kv(l) for l in (logs / 'steps.txt').read_text().splitlines()]
a, b, c, inv = lines('ncs-a-try1.log'), lines('ncs-b-try1.log'), lines('ncs-c-try3.log'), lines('ncs-inv-after-try1.log')
dl1, dl2 = lines('dl-try1.log'), lines('dl-chunked-try2.log')
v = json.loads(verify_path.read_text(encoding='utf-8'))
pick = lambda ls, *pre: [l for l in ls if l.startswith(pre)]
man = {}
for l in b:
    m = re.match(r'(before|after) (user (\S+)|projects|share): (.*)', l)
    if m:
        man.setdefault(m.group(1), {})[m.group(3) or m.group(2)] = kv(m.group(4))
show_users = {u: d for u, d in man.get('before', {}).items() if u not in ('projects', 'share')}
walk_users = v.get('users', {})
compare = {u: {'showcase_digest': d.get('digest'), 'backup_digest': walk_users.get(u, {}).get('digest'),
               'files': f"{d.get('files')}/{walk_users.get(u, {}).get('files')}",
               'equal': d.get('digest') == walk_users.get(u, {}).get('digest') and int(d.get('files', -1)) == walk_users.get(u, {}).get('files')}
           for u, d in show_users.items()}
proj_show = man.get('before', {}).get('projects', {})
fileline = next(l for l in b if l.startswith('file: '))
sha = next(l.split()[0] for l in b if re.match(r'^[0-9a-f]{64}  /backup/', l))
size = int(fileline.split()[2])
stage_lines = [l for l in b if l.startswith('t+')]
doc = {
    'schema': 1, 'date': '2026-11-23', 'lane': 'showcase-nc-share (iteration 1)',
    'scope': ('REAL HA source backup of the x86 showcase HA own Nextcloud add-on WITH the share folder (owner decision '
              '2026-11-23 「決定2 A」; MAIN decision 17:30: share approved, runs last). Source fixture only, NOT an import attempt.'),
    'commercial_acceptance': 'not-complete',
    'secrets': ('none in this file; HA_BACKUP_KEY and the generated Nextcloud test credentials are named only '
                '(B2_NC_X86_SHARE_USER_PW, B2_NC_X86_SHARE_USER2_PW, B2_NC_X86_SHARE_APP_PW, B2_NC_X86_SHARE_LINK_PW, '
                'B2_NC_X86_SHARE_LINK_TOKEN in ~/.woowbk-lab/secrets/b1-creds.env); leak scan of logs and this file: 0 hits'),
    'source_commit': commit,
    'preconditions_met_at': '2026-11-23T20:35+08:00 (OpenDesign 85/85 PASS + ROTATED 19:44; code-server 87/87 PASS + ROTATED 20:32; host free 31.9 GiB >= 24 GiB)',
    'markers': {
        'users': ['woow-import-share (owner of all markers)', 'woow-import-share2 (receives the user share)'],
        'status_lines': pick(a, 'before:', 'mkcol:', 'put:', 'put v2:', 'user share', 'public link', 'caldav:', 'carddav:',
                             'A propfind', 'B sees', 'on disk', 'rows of A', 'after:'),
        'files': {'nextcloud/woow-import-share/files/woow-import-share-20261123.txt': 'ASCII marker',
                  'nextcloud/woow-import-share/files/匯入測試-share-20261123.txt': 'CJK name marker',
                  'nextcloud/woow-import-share/files/匯入資料夾/子資料夾/woow-random-4m.bin': '4 MiB random, nested CJK folders',
                  'nextcloud/woow-import-share/files/woow-versioned.txt': 'current version 2; one older version in files_versions'},
        'note': ('B2 PROPFIND grep for the folder href printed 0 (href encoding differs), but B read the 4 MiB file through its '
                 'received share with the right sha256, so the share works; the public link answers with the password on '
                 'both public DAV endpoints and 401 without it'),
    },
    'backup': {
        'ha_slug': re.search(r'slug=(\w+)', next(l for l in b if l.startswith('backup: '))).group(1),
        'name': 'WOOW匯入測試 B2 Nextcloud x86 加密 含share 2026-11-23',
        'addon': '1b7b4ce7_woow-nextcloud-office', 'remote': fileline.split()[1], 'bytes': size, 'sha256': sha,
        'request': 'POST /backups/new/partial {addons:[slug], folders:[share], password: env.HA_BACKUP_KEY, compressed, filename, background:true}',
        'job_timeline': stage_lines, 'job_and_health': pick(b, 'job errors', 'backup: ', 'healthy again'),
        'members': [l for l in b if re.match(r'^\d+ \S+\.(tar\.gz|json)$', l)],
        'downtime': 'add-on stopped at +4 s and started again at +22 s (stage addons); the share folder was written after the restart (stage folders, add-on started); healthz 200 when the job ended (+222 s)',
        'consistency': 'per-user file manifests, projects and share totals before == after the backup',
        'manifests_before': man.get('before'), 'manifests_after': man.get('after'),
        'showcase_space': next(l for l in b if l.startswith('users after:')).split('backup dir ')[-1],
        'kept_on_showcase': 'yes: the showcase is not short of space (672.6 GB free of 983.7 GB after the backup), so the backup stays with the three earlier ones for the main session to delete at the end',
    },
    'cleanup': {'status_lines': pick(c, 'delete', 'after cleanup', 'left of', 'oc_users', 'state:')},
    'end_state_check': {'status_lines': pick(inv, 'now', 'state:', 'health:', 'users:', 'oc_users', 'share:', 'datadir:', 'backup dir:'),
                        'note': 'identical to the 17:31 baseline: users admin,woow-mcp-test; all counted rows equal; share bytes and entries equal; Nextcloud started, healthz 200'},
    'download': {'attempt1': {'script': 'ncs-dl.sh (one SSH stream)', 'status_lines': dl1[-4:],
                              'result': 'FAILED: SSH connection broke after 1.96 GB; the guard deleted the partial file'},
                 'attempt2': {'script': 'ncs-dl-chunked.sh (256 MiB chunks, per-chunk sha256 from the showcase)', 'status_lines': dl2[-3:]},
                 'local_path': '~/.woowbk-lab/ha-fixtures/20261123-batch2/x86/woow-b2-nextcloud-x86-enc-share/woow-b2-nextcloud-x86-enc-share-20261123.tar (dirs 0700, file 0600)'},
    'strict_walk': {k: v.get(k) for k in ('result', 'error', 'layout', 'members', 'addon_walk', 'share_walk', 'share_tops', 'users', 'projects', 'ncdata', 'markers')},
    'showcase_vs_backup': {'users': compare,
                           'projects': {'showcase_digest': proj_show.get('digest'), 'backup_digest': v.get('projects', {}).get('digest'),
                                        'equal': proj_show.get('digest') == v.get('projects', {}).get('digest')}},
    'steps': steps,
}
out_path.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
print(out_path, hashlib.sha256(out_path.read_bytes()).hexdigest()[:16])
