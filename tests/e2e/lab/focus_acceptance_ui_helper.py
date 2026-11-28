"""Only the direct three-selected R1 case; imports perform no I/O."""
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time
from datetime import datetime

APPS = ['emqx', 'omnigent', 'hermes']
JOB = re.compile(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')


def validate_lease(lease, driver_commit, source_commit, now):
    expiry = datetime.fromisoformat(lease['expires'])
    if (lease.get('granted') is not True or lease.get('case') != 'r1-three-selected-memory'
            or lease.get('phase') != 'helper-three-selected' or lease.get('helper_three_selected') is not True
            or lease.get('device') != 'woowbk-dev-d' or lease.get('driver_commit') != driver_commit
            or lease.get('source_commit') != source_commit
            or not re.fullmatch(r'[0-9a-f]{64}', lease.get('page_guard_sha256', ''))
            or expiry.tzinfo is None or expiry.timestamp()-now < 45*60):
        raise ValueError('exact fresh helper-three-selected lease required')


def check_ready(job, ha_id):
    result = (job.get('result') or {}).get('ha_check') or {}
    rows = result.get('apps', [])
    if (job.get('state') != 'succeeded' or result.get('schema') != 2
            or result.get('ha_backup_id') != ha_id or len(rows) != 3
            or {r.get('app_id') for r in rows} != set(APPS)):
        return False
    by_id = {r['app_id']: r for r in rows}
    return (by_id['emqx'].get('importable') is False
            and any(i.get('level') == 'stop' for i in by_id['emqx'].get('issues', []))
            and all(by_id[a].get('importable') is True for a in APPS[1:])
            and not any(i.get('level') == 'confirm' for issues in
                [result.get('shared', [])]+[r.get('issues', []) for r in rows] for i in issues))


def chain_complete(records):
    ids = [j.get('id') for j in records]
    return (len(records) == 5 and len(set(ids)) == 5
            and all(isinstance(j, str) and JOB.fullmatch(j) for j in ids)
            and [j.get('type') for j in records] == ['backup', 'backup', 'restore', 'backup', 'restore']
            and [j.get('state') for j in records] == ['failed', 'succeeded', 'succeeded', 'succeeded', 'succeeded']
            and [(j.get('params') or {}).get('apps') for j in records]
                == [['emqx'], ['omnigent'], ['omnigent'], ['hermes'], ['hermes']]
            and all(((j.get('result') or {}).get('group') or {}).get('next_job_id')
                    == (ids[n+1] if n < 4 else None) for n, j in enumerate(records))
            and {r.get('app_id'): r.get('status') for r in
                ((records[-1].get('result') or {}).get('group') or {}).get('results', [])}
                == {'emqx': 'failed', 'omnigent': 'imported', 'hermes': 'imported'})


def cleanup_ready(trace, receipt, report, host_hits):
    """No browser assertion is manufactured for a helper case."""
    memory = trace.get('memory', {})
    first = trace.get('first_job_id', '')
    return (trace.get('completed') is True and trace.get('browser_used') is False
            and trace.get('chain_verified') is True and trace.get('native_units_verified') is True
            and trace.get('live_data_verified') is True and trace.get('distinct_restore_safeties_verified') is True
            and trace.get('native_units') == ['woowtech-backup-'+first+'.service']*5
            and memory.get('unit') == 'woowtech-backup-'+first+'.service'
            and memory.get('through_terminal_chain') is True and memory.get('sampler_stopped') is True
            and memory.get('samples', 0) > 0 and 0 < memory.get('peak_bytes', 0) < 1024**3
            and trace.get('all_observed_marker_tokens_registered') is True
            and trace.get('observed_marker_tokens', 0) > 0
            and receipt.get('baseline_restored') is True and not receipt.get('inflight')
            and report.get('hits') == 0 and report.get('scanned', 0) > 0 and host_hits == 0
            and report.get('regular_json_roots_scanned') == 2
            and report.get('archive_index_sidecars_scanned', 0) > 0
            and report.get('archive_index_sidecars_scanned') == trace.get('actual_sidecars'))


def predecessor(lease, raw, guard_path, evidence_root):
    """Read only the exact lease-bound completed page recovery; never override it."""
    if (guard_path.is_symlink() or guard_path.resolve() != guard_path.absolute()
            or not guard_path.is_file() or guard_path.stat().st_uid != os.getuid()
            or guard_path.stat().st_mode & 0o077
            or hashlib.sha256(raw).hexdigest() != lease.get('page_guard_sha256')):
        raise ValueError('exact terminal page guard required')
    old = json.loads(raw)
    case = Path(old['evidence_dir'])
    if (old.get('phase') != 'complete' or old.get('baseline_restored') is not True
            or old.get('recovery_verified') is not True or old.get('inflight')
            or case.parent != evidence_root/'focus-acceptance-ui' or case.resolve() != case):
        raise ValueError('page recovery must be independently complete before R1 helper')
    protected = {str(guard_path): lease['page_guard_sha256']}
    docs = {}
    for name in ('summary.json', 'recovery.json', 'browser.json', 'results.json', 'leaks.json'):
        p = case/name
        if p.is_symlink() or not p.is_file() or p.stat().st_uid != os.getuid() or p.stat().st_mode & 0o077:
            raise ValueError('unsafe page recovery evidence')
        data = p.read_bytes(); protected[str(p)] = hashlib.sha256(data).hexdigest(); docs[name] = json.loads(data)
    summary, browser, scan = docs['summary.json'], docs['browser.json'], docs['leaks.json']
    if (summary.get('baseline_restored') is not True or summary.get('recovery_verified') is not True
            or browser.get('issued_values_scanned') is not True or scan.get('hits') != 0
            or scan.get('scanned', 0) <= 0 or scan.get('regular_json_roots_scanned') != 2
            or scan.get('archive_index_sidecars_scanned', 0) <= 0):
        raise ValueError('terminal page baseline and privacy proof missing')
    pruned = {p['id'] for p in old.get('prior_case_safety_pruning', [])}
    retained = set(old.get('protected_existing_backups', []))-pruned
    if pruned-set(old.get('protected_existing_backups', [])):
        raise ValueError('page prior-owned pruning accounting invalid')
    return old, {'path': str(guard_path), 'sha256': lease['page_guard_sha256'],
        'acceptance_passed': False, 'retained_case_archive_ids': sorted(retained)}, protected


class FirstUnitMemory:
    """Bounded read-only sampling of the actual first unit, never guessed children."""
    def __init__(self, first, root):
        if not JOB.fullmatch(first):
            raise ValueError('first job identity invalid')
        self.unit = 'woowtech-backup-'+first+'.service'
        self.root = root; self.stop = threading.Event(); self.rows = []; self.errors = 0
        self.thread = threading.Thread(target=self.sample, daemon=True)

    def sample(self):
        while not self.stop.is_set() and len(self.rows) < 600:
            try:
                p = self.root('systemctl', 'show', self.unit,
                    '--property=Id,MemoryPeak,MemoryMax,TasksMax,InvocationID', timeout=15)
                d = dict(line.split('=', 1) for line in p.stdout.decode().splitlines() if '=' in line)
                if (p.returncode == 0 and d.get('Id') == self.unit and d.get('MemoryPeak', '').isdigit()
                        and d.get('MemoryMax', '').isdigit() and int(d['MemoryMax']) > 0
                        and d.get('TasksMax') == '512' and re.fullmatch(r'[0-9a-f]{32}', d.get('InvocationID', ''))):
                    self.rows.append({'peak_bytes': int(d['MemoryPeak']), 'memory_max': int(d['MemoryMax']),
                        'tasks_max': 512, 'invocation_id': d['InvocationID']})
                else:
                    self.errors += 1
            except Exception:
                self.errors += 1
            self.stop.wait(2)

    def finish(self, terminal):
        self.stop.set(); self.thread.join(timeout=20)
        return {'unit': self.unit, 'samples': len(self.rows),
            'peak_bytes': max((r['peak_bytes'] for r in self.rows), default=0),
            'through_terminal_chain': terminal, 'sampler_stopped': not self.thread.is_alive(),
            'read_errors': self.errors, 'native_samples': self.rows}


RESOLVE = r'''
import json,re,sys
from pathlib import Path
q=json.load(sys.stdin);requests=json.loads(Path('/var/lib/woowtech-backup/requests.json').read_bytes())['requests'];out={}
for kind,rid in q['requests'].items():
 item=requests.get(rid)
 if item is None:continue
 jid=item['job_id'];assert re.fullmatch(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',jid)
 j=json.loads((Path('/var/lib/woowtech-backup/jobs')/(jid+'.json')).read_bytes())
 assert j['request_id']==rid and j['params']['ha_backup_id']==q['ha_id'] and j['type']==('verify' if kind=='check' else 'backup')
 out[kind]=jid
print(json.dumps(out))
'''
