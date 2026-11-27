#!/usr/bin/env python3
"""dev-e journal cleanup (first use: nextcloud-import REQUEST 2026-11-23 23:58, a dead test public-link token in access-log
journal entries).
    flock -w 3600 /tmp/woowbk-dev-e-mutation.lock python3 -I tests/e2e/lab/batch2_journal_cleanup.py <evidence.json> [reason]
Runs as the dev-e owner lane under the dev-e lock: journalctl --rotate, then --vacuum-time=1s (every archived file goes),
inside dev-e as root. Records sizes, file counts and the oldest entry's TIMESTAMP only (never log content) to the
evidence JSON given as argv[1] (never overwritten). Exit 0 only when the oldest remaining entry is newer than the start."""
import json, subprocess, sys, time, hashlib, os
from pathlib import Path
LP = str(Path.home() / '.woowbk-lab' / 'bin' / 'labpodman')
DEV = 'woowbk-dev-e'
target = Path(sys.argv[1])
REASON = sys.argv[2] if len(sys.argv) > 2 else (
    'nextcloud-import REQUEST 2026-11-23 23:58 (team/batch2-lab.md): the dead test public-link token of share '
    'attempt 1 in 18 access-log journal entries (nextcloud-gateway.service, nextcloud-app.service)')
if target.exists():
    raise SystemExit('evidence file exists; never overwrite an attempt')
def run(*cmd, timeout=300):
    p = subprocess.run([LP, 'exec', DEV, *cmd], capture_output=True, timeout=timeout)
    return p.returncode, p.stdout.decode(errors='replace').strip()
def usage():
    rc, out = run('journalctl', '--disk-usage')
    return out.rsplit('take up ', 1)[-1].split(' ')[0] if rc == 0 else f'rc={rc}'
def files():
    rc, out = run('sh', '-c', 'ls /var/log/journal/*/ | wc -l')
    return int(out) if rc == 0 and out.isdigit() else None
def oldest():
    """Epoch seconds of the oldest entry still in the journal (None when empty), from -o short-unix's first field only."""
    rc, out = run('sh', '-c', 'journalctl --no-pager -q -o short-unix 2>/dev/null | head -n 1 | cut -d" " -f1')
    try:
        return float(out) if rc == 0 and out else None
    except ValueError:
        return None
def entries():
    rc, out = run('sh', '-c', 'journalctl --no-pager -q 2>/dev/null | wc -l')
    return int(out) if rc == 0 and out.isdigit() else None
start_epoch = time.time()
start_wall, t0 = time.strftime('%Y-%m-%dT%H:%M:%S%z'), time.monotonic()
iso = subprocess.run([LP, 'inspect', DEV, '--format', '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'],
                     capture_output=True, timeout=60).stdout.decode().strip()
before = {'disk_usage': usage(), 'journal_files': files(), 'oldest_entry_epoch': oldest(), 'entries': entries()}
rc_rotate, _ = run('journalctl', '--rotate')
rc_vacuum, vac = run('journalctl', '--vacuum-time=1s')
time.sleep(2)
after = {'disk_usage': usage(), 'journal_files': files(), 'oldest_entry_epoch': oldest(), 'entries': entries()}
ok = (rc_rotate == 0 and rc_vacuum == 0 and after['entries'] is not None
      and (after['oldest_entry_epoch'] is None or after['oldest_entry_epoch'] >= start_epoch - 1))
doc_start_epoch = round(start_epoch, 3)
doc = {'schema_version': 1, 'kind': 'lab-device-journal-cleanup', 'device': DEV, 'when_start': start_wall,
       'start_epoch': doc_start_epoch,
       'reason': REASON,
       'isolation_before': iso, 'before': before, 'rotate_exit': rc_rotate, 'vacuum_exit': rc_vacuum,
       'vacuum_summary_sha256': hashlib.sha256(vac.encode()).hexdigest(), 'after': after,
       'elapsed_seconds': round(time.monotonic() - t0, 1), 'ok': ok,
       'what_this_is': 'lab hygiene: every archived journal file of dev-e deleted after rotation; log content never read or kept',
       'commercial_acceptance': 'not-complete'}
target.parent.mkdir(parents=True, exist_ok=True)
with open(target, 'x', encoding='utf-8') as fh:
    json.dump(doc, fh, indent=1, ensure_ascii=False); fh.write('\n')
print(json.dumps({k: doc[k] for k in ('before', 'rotate_exit', 'vacuum_exit', 'after', 'ok', 'elapsed_seconds')}))
sys.exit(0 if ok else 1)
