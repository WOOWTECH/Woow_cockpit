#!/usr/bin/env python3
"""Lab-only dev-d journal vacuum: archived journal files older than 24h leave the tmpfs.

dev-d keeps /var/log/journal on tmpfs (tests/e2e/lab/README.md 'journal'), so old
archived journals are shmem charged to dev-d's 4GiB cgroup. Holds both dev-d locks
(non-blocking), records only counters (no log content), never touches services.
usage: dev_d_journal_vacuum.py <N>
"""
import fcntl, hashlib, json, os, pathlib, stat, subprocess, sys

assert len(sys.argv) == 2 and sys.argv[1].isdecimal() and 1 <= int(sys.argv[1]) <= 9
LP = '/home/woowtechopenclaw/.woowbk-lab/bin/labpodman'
root = pathlib.Path('/tmp/ha-real-fixture-candidate-20261121')
locks = []
for name in ('/tmp/woowbk-dev-d-mutation.lock', '/tmp/headscale-dev-d-private-volume.lock'):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW)
    st = os.fstat(fd); other = os.stat(name, follow_symlinks=False)
    assert stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1
    assert (st.st_dev, st.st_ino) == (other.st_dev, other.st_ino)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); locks.append(fd)


def snap():
    script = ('cat /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.max; '
              'grep -E "^(anon|file|shmem) " /sys/fs/cgroup/memory.stat; '
              'grep -E "^(oom|oom_kill|oom_group_kill) " /sys/fs/cgroup/memory.events; '
              'df -B1 --output=used /var/log/journal | tail -1; '
              'find /var/log/journal -type f -name "*.journal" | wc -l')
    out = subprocess.run([LP, 'exec', 'woowbk-dev-d', 'sh', '-c', script], capture_output=True, text=True,
                         check=True, timeout=30).stdout.split('\n')
    current, maximum = int(out[0]), int(out[1])
    stats = dict(line.split() for line in out[2:5])
    events = dict(line.split() for line in out[5:8])
    return {'current': current, 'max': maximum, **{k: int(v) for k, v in stats.items()},
            'events': {k: int(v) for k, v in events.items()},
            'journal_tmpfs_used_bytes': int(out[8]), 'journal_files': int(out[9])}


before = snap(); assert before['max'] == 4294967296
path = root / 'tests/e2e/lab/evidence' / ('emqx-dev-d-journal-vacuum-' + sys.argv[1] + '-20261123.json')
doc = {'scope': 'lab woowbk-dev-d only; archived journal files older than 24h on its tmpfs /var/log/journal',
       'operation': 'journalctl --vacuum-time=24h (no service, unit, config or container change)',
       'script_sha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(), 'before': before}
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
with os.fdopen(fd, 'w') as evidence:
    def publish():
        evidence.seek(0); json.dump(doc, evidence, indent=2); evidence.write('\n'); evidence.truncate()
        evidence.flush(); os.fsync(evidence.fileno())
    publish()
    result = subprocess.run([LP, 'exec', 'woowbk-dev-d', 'journalctl', '--vacuum-time=24h'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    after = snap()
    doc.update(exit=result.returncode, after=after, limits_unchanged=before['max'] == after['max'],
               oom_events_unchanged=before['events'] == after['events'])
    publish()
print(json.dumps({k: doc[k] for k in ('exit', 'limits_unchanged', 'oom_events_unchanged')},
                 sort_keys=True), 'headroom_mib', (before['max'] - before['current']) >> 20, '->',
      (after['max'] - after['current']) >> 20, 'journal_mib', before['journal_tmpfs_used_bytes'] >> 20, '->',
      after['journal_tmpfs_used_bytes'] >> 20)
assert result.returncode == 0 and doc['limits_unchanged'] and doc['oom_events_unchanged']
