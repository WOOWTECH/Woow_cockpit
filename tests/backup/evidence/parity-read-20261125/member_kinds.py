"""Counts the members of the 27 real HA backups by encryption kind, from their layouts only (no key, no content read, nothing printed but counts).
usage: member_kinds.py LIST_OF_FILES.txt   (cwd: any; the lane's engine is imported from the worktree)"""
import collections, json, sys
sys.path.insert(0, '/tmp/parity-read-20261125/backup-engine')
import woowbackup.habackup as habackup
kinds = collections.Counter()
files = [line.strip() for line in open(sys.argv[1]) if line.strip()]
for path in files:
    with habackup.open_backup(path) as backup:
        kinds.update(member.encryption for member in backup.layout.members)
print(json.dumps(dict(kinds), sort_keys=True))
