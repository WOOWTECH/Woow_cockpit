#!/usr/bin/env python3
"""Live probe of the job-record race (release regression 16) on a lab device.

Inside the device, as root, exactly like the Cockpit page calls the installed helper: N short verify jobs of
the smallest local backup run back to back while P threads call `job-status` for the current job without a
pause, one thread calls `jobs` and one calls `status` (all three commands run the recovery). After a job
ends, the pollers keep going for `--settle` seconds: that is the window in which the old recovery overwrote a
finished job. A job is misclassified when its record state is not the state its own run-job wrote (the
`作業結束：<狀態>` line of its log), when the recovery judged it (`作業被判定為已中斷`), or when any poller saw
it as `interrupted`.

    python3 -I tests/e2e/lab/race_probe.py a                 # dev-a: verify of its smallest backup (succeeds)
    python3 -I tests/e2e/lab/race_probe.py b --jobs 110      # dev-b: no key on the device -> ends `failed`
    python3 -I tests/e2e/lab/race_probe.py a --census-only   # read-only record census (no helper call)

Also recorded: retention (records before/after, files per kind, the pinned safety backups before and after
must be equal, records ≤ 200 finished + the ones still needed), latency of every helper call, leftovers in
/run/woowtech-backup and staging. Evidence: ~/.woowbk-lab/evidence/race/<time>-probe-<dev>/. Only labpodman
is used; no key material is sent (dev-b's verify jobs fail with key-required on purpose).
"""
import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cli_e2e as e2e  # noqa: E402  (evidence and device helpers shared with the integration runner)
from cli_e2e import LAB, LP, dev_name  # noqa: E402

RACE = LAB / 'evidence' / 'race'
REPO = Path(__file__).resolve().parents[3]
ENGINE_LIB = '/usr/local/lib/woowtech-cockpit-backup/woowbackup'
MIN_AVAIL_MB = 1200
KEEP_TERMINAL = 200
EXPECTED = {'a': ('succeeded', None), 'b': ('failed', 'key-required')}

# Read-only: lists and parses the records with the installed library; never runs a helper command (so no
# recovery and no retention happen while counting).
CENSUS = r'''
import json, os, sys
sys.path.insert(0, '/usr/local/lib/woowtech-cockpit-backup')
from woowbackup import jobs
from woowbackup.paths import Paths
paths = Paths()
names = os.listdir(paths.jobs) if os.path.isdir(paths.jobs) else []
kinds = {}
for name in names:
    kind = name.rsplit('.', 1)[-1] if name.startswith('j') else 'other'
    kinds[kind] = kinds.get(kind, 0) + 1
records = jobs.JobStore(paths).list(limit=None)
states = {}
for record in records:
    states[record.get('state')] = states.get(record.get('state'), 0) + 1
pinned = jobs.pinned_safety_records(records)
print(json.dumps({'files_by_kind': kinds, 'records': len(records), 'states': states,
                  'pinned_restore_records': pinned, 'pinned_safety_backups': sorted(set(pinned.values())),
                  'leftover_records': [r['id'] for r in records if jobs.has_leftovers(r)],
                  'active_records': [r['id'] for r in records if r.get('state') in jobs.ACTIVE],
                  'finished_records': sum(1 for r in records if r.get('state') not in jobs.ACTIVE and not jobs.has_leftovers(r)),
                  'newest': records[0]['id'] if records else None, 'oldest': records[-1]['id'] if records else None,
                  'run_dir': sorted(os.listdir(paths.run)) if os.path.isdir(paths.run) else [],
                  'staging': sorted(os.listdir(paths.staging)) if os.path.isdir(paths.staging) else []}))
'''

PROBE = r'''
import json, os, re, subprocess, sys, threading, time, uuid
HELPER = '/usr/local/libexec/woowtech-cockpit-backup'
JOBS = '/var/lib/woowtech-backup/jobs'
N, P, SETTLE = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
END_RE = re.compile(r'作業結束：(已完成|失敗|已自動回復|已取消|已中斷)')
ENDED = {'已完成': 'succeeded', '失敗': 'failed', '已自動回復': 'rolled-back', '已取消': 'cancelled', '已中斷': 'interrupted'}
lock = threading.Lock()
lat = {'job-status': [], 'jobs': [], 'status': [], 'verify-start': []}
errors, seen = [], {}
spans = []  # (wall start, wall end) of every call that runs a recovery pass (job-status, jobs, status)
RECOVERING = ('job-status', 'jobs', 'status')

def say(**kw):
    print(json.dumps(kw, ensure_ascii=False), flush=True)

def call(cmd, req=None):
    t, wall = time.monotonic(), time.time()
    proc = subprocess.run([HELPER, cmd], input=json.dumps(req or {}).encode(), capture_output=True, timeout=600)
    took = time.monotonic() - t
    if cmd in RECOVERING:
        with lock:
            spans.append((wall, time.time()))
    lines = [l for l in proc.stdout.decode('utf-8', 'replace').splitlines() if l.strip()]
    try:
        reply = json.loads(lines[-1]) if len(lines) == 1 else None
    except ValueError:
        reply = None
    with lock:
        lat.setdefault(cmd, []).append(took)
        if reply is None or (proc.returncode == 0) != (reply.get('ok') is True):
            errors.append({'cmd': cmd, 'rc': proc.returncode, 'lines': len(lines), 'stderr': proc.stderr.decode('utf-8', 'replace')[-300:]})
            return None
    return reply

def note(job_id, state, who):
    with lock:
        seen.setdefault(job_id, {}).setdefault(state, set()).add(who)

backups = call('list')['backups']
target = min(backups, key=lambda b: b['size'])
current, stop = {'id': None}, threading.Event()

def status_poller(i):
    while not stop.is_set():
        job = current['id']
        if not job:
            time.sleep(0.01)
            continue
        reply = call('job-status', {'job_id': job})
        if reply and reply.get('ok'):
            note(job, reply['job']['state'], 'job-status')
        elif reply:
            with lock:
                errors.append({'cmd': 'job-status', 'error': reply.get('error')})

def jobs_poller():
    while not stop.is_set():
        reply = call('jobs')
        if reply and reply.get('ok'):
            for job in reply['jobs']:
                if job['id'] == current['id'] or job['state'] == 'interrupted':
                    note(job['id'], job['state'], 'jobs')

def overview_poller():
    while not stop.is_set():
        reply = call('status')
        if reply and reply.get('ok') and reply.get('active_job'):
            note(reply['active_job']['id'], reply['active_job']['state'], 'status')

threads = [threading.Thread(target=status_poller, args=(i,), daemon=True) for i in range(P)]
threads += [threading.Thread(target=jobs_poller, daemon=True), threading.Thread(target=overview_poller, daemon=True)]
for thread in threads:
    thread.start()
say(started=True, target=target['id'], target_size=target['size'], key_available=target.get('key_available'))
rows, busy_waits, t0 = [], 0, time.time()
for i in range(N):
    for attempt in range(600):
        reply = call('verify-start', {'backup_id': target['id'], 'request_id': str(uuid.uuid4())})
        if reply and reply.get('ok'):
            break
        busy_waits += 1
        time.sleep(0.2)
    else:
        say(aborted='verify-start kept failing', reply=reply)
        break
    job = reply['job_id']
    current['id'] = job
    while True:
        reply = call('job-status', {'job_id': job})
        if reply and reply.get('ok'):
            note(job, reply['job']['state'], 'main')
            if reply['job']['state'] not in ('queued', 'running'):
                break
        time.sleep(0.05)
    time.sleep(SETTLE)  # pollers keep running recoveries right after the end: the race window
    current['id'] = None
    time.sleep(0.2)
    record_path = os.path.join(JOBS, job + '.json')
    record = json.load(open(record_path, encoding='utf-8'))
    final_write = os.stat(record_path).st_mtime  # the job's own final write (nothing writes it after that)
    log = open(os.path.join(JOBS, job + '.log'), encoding='utf-8').read()
    ends = END_RE.findall(log)
    own = ENDED.get(ends[-1]) if ends else None
    with lock:
        polled = sorted(s for s in seen.get(job, {}))
        # Exposure: helper calls whose recovery pass could have listed the record before the job's final write
        # and decided after it, i.e. the old race window (an upper bound: the pass is inside the call).
        in_flight = sum(1 for start, end in spans if start < final_write < end)
    row = {'job': job, 'state': record['state'], 'own_end': own, 'error_code': (record.get('error') or {}).get('code'),
           'judged_interrupted': '作業被判定為已中斷' in log, 'states_seen': polled, 'calls_in_flight_at_end': in_flight,
           'lock_file': os.path.exists(os.path.join(JOBS, job + '.lock')),
           'cancel_file': os.path.exists(os.path.join(JOBS, job + '.cancel'))}
    row['misclassified'] = bool(row['judged_interrupted'] or own is None or record['state'] != own
                                or 'interrupted' in polled)
    rows.append(row)
    say(i=i + 1, job=job, state=row['state'], own_end=own, misclassified=row['misclassified'])
stop.set()
for thread in threads:
    thread.join(60)

def pct(values, q):
    values = sorted(values)
    return round(values[min(len(values) - 1, int(q * len(values)))], 3) if values else None

summary = {'target_backup': target['id'], 'target_size': target['size'], 'jobs': len(rows), 'pollers': P,
           'settle_s': SETTLE, 'seconds': round(time.time() - t0, 1), 'busy_waits': busy_waits,
           'states': {s: sum(1 for r in rows if r['state'] == s) for s in sorted({r['state'] for r in rows})},
           'error_codes': {c: sum(1 for r in rows if r['error_code'] == c) for c in sorted({str(r['error_code']) for r in rows})},
           'misclassified': [r for r in rows if r['misclassified']],
           'judged_interrupted': sum(1 for r in rows if r['judged_interrupted']),
           'seen_interrupted_by_a_poller': sum(1 for r in rows if 'interrupted' in r['states_seen']),
           'exposure': {'jobs_ending_while_a_recovering_call_was_in_flight':
                        sum(1 for r in rows if r['calls_in_flight_at_end']),
                        'recovering_calls_in_flight_at_job_ends': sum(r['calls_in_flight_at_end'] for r in rows)},
           'calls': {cmd: {'count': len(v), 'p50_s': pct(v, 0.5), 'p95_s': pct(v, 0.95), 'max_s': pct(v, 1.0)}
                     for cmd, v in lat.items()},
           'helper_errors': errors[:20], 'helper_error_count': len(errors),
           'jobs_without_lock_file': [r['job'] for r in rows if not r['lock_file']],
           'jobs_with_cancel_file': [r['job'] for r in rows if r['cancel_file']],
           'rows': rows}
print('SUMMARY ' + json.dumps(summary, ensure_ascii=False), flush=True)
'''


class Evidence(e2e.Evidence):
    def __init__(self, scenario):  # noqa: D107 - same as cli_e2e.Evidence, other directory
        stamp = time.strftime('%Y%m%dT%H%M%S')
        self.dir = RACE / f'{stamp}-{scenario}'
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.dir / 'driver.log'
        self.checks = []
        self.timings = {}
        self.t0 = time.monotonic()


def mem_available_mb():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) // 1024
    return 0


def device_python(dev, program, *args, timeout=600):
    proc = subprocess.run([LP, 'exec', '-i', dev_name(dev), 'python3', '-I', '-B', '-', *map(str, args)],
                          input=program.encode(), capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        raise e2e.Failed(f'in-device program failed rc={proc.returncode}: {proc.stderr.decode("utf-8", "replace")[-600:]}')
    return proc.stdout.decode('utf-8', 'replace')


def installed_engine(dev):
    """{module: (installed sha256, working tree sha256)} of the engine library on the device."""
    out = subprocess.run([LP, 'exec', dev_name(dev), 'sh', '-c', f'cd {ENGINE_LIB} && sha256sum *.py adapters/*.py'],
                         capture_output=True, text=True, check=True).stdout
    installed = {line.split(None, 1)[1].strip(): line.split()[0] for line in out.splitlines() if line.strip()}
    tree = REPO / 'backup-engine' / 'woowbackup'
    return {name: (digest, hashlib.sha256((tree / name).read_bytes()).hexdigest()) for name, digest in installed.items()}


def census(dev):
    return json.loads(device_python(dev, CENSUS).strip().splitlines()[-1])


def run_probe(dev, ev, jobs, pollers, settle):
    proc = subprocess.Popen([LP, 'exec', '-i', dev_name(dev), 'python3', '-I', '-B', '-', str(jobs), str(pollers),
                             str(settle)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(PROBE.encode())
    proc.stdin.close()
    summary = None
    for raw in proc.stdout:
        line = raw.decode('utf-8', 'replace').strip()
        if line.startswith('SUMMARY '):
            summary = json.loads(line[len('SUMMARY '):])
        elif line:
            event = json.loads(line)
            if 'i' in event and event['i'] % 10 and not event.get('misclassified'):
                continue
            ev.log(f'probe: {line}')
    stderr = proc.stderr.read().decode('utf-8', 'replace')
    proc.wait(timeout=60)
    if stderr.strip():
        ev.log(f'probe stderr tail: {stderr[-600:]}')
    if summary is None:
        raise e2e.Failed(f'probe ended without a summary (rc={proc.returncode})')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('dev', choices=['a', 'b'])
    parser.add_argument('--jobs', type=int, default=110)
    parser.add_argument('--pollers', type=int, default=3)
    parser.add_argument('--settle', type=float, default=0.5)
    parser.add_argument('--census-only', action='store_true')
    args = parser.parse_args()
    ev = Evidence(f'probe-{args.dev}' if not args.census_only else f'census-{args.dev}')
    try:
        engine = installed_engine(args.dev)
        stale = sorted(name for name, (got, want) in engine.items() if got != want)
        ev.save('installed-engine-vs-worktree', {'modules': len(engine), 'differ': stale})
        ev.require('installed engine equals the working tree', not stale, stale)
        before = census(args.dev)
        ev.save('census-before', before)
        ev.log(f'census before: {before["records"]} records {before["files_by_kind"]}, pinned {before["pinned_safety_backups"]}')
        if args.census_only:
            return 0 if ev.finish() else 1
        avail = mem_available_mb()
        ev.require(f'host MemAvailable >= {MIN_AVAIL_MB} MB before the probe', avail >= MIN_AVAIL_MB, f'{avail} MB')
        summary = run_probe(args.dev, ev, args.jobs, args.pollers, args.settle)
        ev.save('probe-summary', summary)
        after = census(args.dev)
        ev.save('census-after', after)
        want_state, want_code = EXPECTED[args.dev]
        ev.check(f'at least 100 short verify jobs ran ({args.pollers} job-status pollers + jobs + status pollers)',
                 summary['jobs'] >= min(100, args.jobs) and summary['jobs'] == args.jobs, summary['jobs'])
        ev.check('0 misclassified jobs (record state == the state the job wrote itself, never judged, never seen '
                 'interrupted by any poller)', summary['misclassified'] == [] and summary['judged_interrupted'] == 0
                 and summary['seen_interrupted_by_a_poller'] == 0,
                 {'misclassified': summary['misclassified'][:5], 'judged': summary['judged_interrupted']})
        ev.check(f'every job ended {want_state}' + (f' ({want_code})' if want_code else ''),
                 summary['states'] == {want_state: summary['jobs']}
                 and (want_code is None or summary['error_codes'] == {want_code: summary['jobs']}),
                 {'states': summary['states'], 'error_codes': summary['error_codes']})
        exposure = summary.get('exposure') or {}
        ev.check('the race window was exercised: jobs wrote their final record while recovering helper calls '
                 '(job-status/jobs/status) were in flight', exposure.get('jobs_ending_while_a_recovering_call_was_in_flight', 0) > 0,
                 exposure)
        ev.check('no helper call failed (every reply exactly one JSON object, exit code matching ok)',
                 summary['helper_error_count'] == 0, summary['helper_errors'][:3])
        ev.check('every job has its record lock file and no cancel request is left',
                 summary['jobs_without_lock_file'] == [] and summary['jobs_with_cancel_file'] == [],
                 {'no_lock': summary['jobs_without_lock_file'][:5], 'cancel': summary['jobs_with_cancel_file'][:5]})
        ev.check('retention: at most 200 finished records (+ active / unfinished recovery / pinned restores); '
                 'no log or lock file outlives its record',
                 after['finished_records'] <= KEEP_TERMINAL + len(after['pinned_restore_records'])
                 and after['files_by_kind'].get('log', 0) <= after['records']
                 and after['files_by_kind'].get('lock', 0) <= after['records'],
                 {'records': after['records'], 'finished': after['finished_records'], 'files': after['files_by_kind']})
        ev.check('retention keeps the pinned safety backups unchanged',
                 after['pinned_safety_backups'] == before['pinned_safety_backups'],
                 {'before': before['pinned_safety_backups'], 'after': after['pinned_safety_backups']})
        ev.check('no active job, no transient key file and no staging left',
                 after['active_records'] == [] and not any(n.startswith('key-') for n in after['run_dir'])
                 and after['staging'] == [], {'active': after['active_records'], 'run': after['run_dir'],
                                              'staging': after['staging']})
        ev.timings.update({f'{cmd}_{k}': v for cmd, stats in summary['calls'].items() for k, v in stats.items()})
        ev.timings['probe_seconds'] = summary['seconds']
        ev.log(f'probe: {summary["jobs"]} jobs in {summary["seconds"]}s, states {summary["states"]}, '
               f'misclassified {len(summary["misclassified"])}, exposure {exposure}, calls {summary["calls"]}')
        return 0 if ev.finish({'states': summary['states'], 'misclassified': len(summary['misclassified'])}) else 1
    except e2e.Failed as error:
        ev.log(f'ABORTED: {error}')
        ev.finish({'aborted': str(error)})
        return 1


if __name__ == '__main__':
    sys.exit(main())
