#!/usr/bin/env python3
"""dev-e baseline (deploy-batch2.sh): marker data in each catalog app, then per app an encrypted Cockpit backup (the
baseline that later HA-import tests restore) proved by an in-place restore of it.
    python3 -I tests/e2e/lab/batch2_baseline.py [nextcloud] [opendesign] [code-server]   # default: all three
Each app needs its catalog entry in dev-e: nextcloud and open-design are the host's files, woow-code-server is the lab
entry tests/e2e/lab/catalog/woow-code-server.json (the host has none; lane codeserver-import, owner decision D1 b).
Per app (batch2_markers.py, run inside dev-e, creates and reads the markers through the app's own interfaces):
  1. the "baseline" markers (woowbk-lab-baseline: a Nextcloud user with a WebDAV file, an OpenDesign project with a file,
     a code-server IDE snippet, pi skill and workspace file; code-server also gets the real login check here)
     are created where missing (seeding is idempotent); any other woowbk-lab-* marker means an earlier run stopped
     between its after marker and its restore: that app stops with a FAIL (restore its baseline backup first)
  2. an encrypted backup with the device key, without images (note 「dev-e 基準備份（<app>）」), inspect says it
     restores in place
  3. an "after" marker (woowbk-lab-after), then an in-place restore of that backup: the baseline markers must be there
     with the same content digests and the after marker gone, the restore made a safety backup, was not rolled back
     and every catalog health check passed; status shows the app running without problems; the health URLs answer;
     code-server: the real login again (session cookie, workbench page, wrong password refused)
The baseline markers stay, so the live data equals the baseline backup afterwards. The Nextcloud marker user's password
is generated once into ~/.woowbk-lab/secrets/dev-e-markers.json (0600) and never printed. Evidence (no keys, no
secrets) goes to ~/.woowbk-lab/evidence/batch2-lab/<stamp>-baseline/; result.json holds the checks and, per app, the
backup id, sizes, times and the safety backup id. The backups stay (lab data).
Host disk (the team keeps >= 12 GiB free on the host at every moment): before the backup and before the restore, the
host must keep FLOOR + RESERVE free after an estimated peak of 2.5 x the app's live data (measured in dev-e); otherwise
that app stops with "PAUSED: host disk" before writing anything. While a job runs, a watchdog cancels it (job-cancel)
when host free space falls to FLOOR + 0.25 GiB.
A failing app is recorded and the next one still runs; the exit status is 0 only when every app passed everything.
"""
import json
import os
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

LAB = Path.home() / '.woowbk-lab'
LP = str(LAB / 'bin' / 'labpodman')
HERE = Path(__file__).resolve().parent
ENGINE = str(HERE / 'engine.sh')
MARKERS = (HERE / 'batch2_markers.py').read_text()
DEV = 'woowbk-dev-e'
OWNER = '/usr/local/bin/woowbk-owner'
PASSWORDS = LAB / 'secrets' / 'dev-e-markers.json'
EVIDENCE = LAB / 'evidence' / 'batch2-lab' / (time.strftime('%Y%m%dT%H%M%S') + '-baseline')
ALL = ['nextcloud', 'opendesign', 'code-server']
CATALOG_ID = {'nextcloud': 'nextcloud', 'opendesign': 'open-design', 'code-server': 'woow-code-server'}
GIB = 1024 ** 3
FLOOR = 12 * GIB      # the team keeps >= 12 GiB free on the host at every moment
RESERVE = 1 * GIB     # what the other lanes may write meanwhile
WATCH = FLOOR + GIB // 4
APPS = sys.argv[1:] or ALL
if not set(APPS) <= set(ALL):
    raise SystemExit('usage: batch2_baseline.py [nextcloud] [opendesign] [code-server]')
checks = []
EVIDENCE.mkdir(parents=True, exist_ok=True)


def log(message):
    line = f'{time.strftime("%H:%M:%S")} {message}'
    print(line, flush=True)
    with open(EVIDENCE / 'driver.log', 'a', encoding='utf-8') as handle:
        handle.write(line + '\n')


def check(name, ok, detail=''):
    checks.append({'check': name, 'ok': bool(ok), 'detail': str(detail)[:800]})
    log(f'{"PASS" if ok else "FAIL"} {name}' + (f' -- {detail}' if detail and not ok else ''))
    return bool(ok)


def engine(command, request=None, timeout=120):
    proc = subprocess.run([ENGINE, 'e', command, '-'], input=json.dumps(request or {}).encode(),
                          capture_output=True, timeout=timeout)
    reply = json.loads(proc.stdout)
    if not reply.get('ok'):
        raise SystemExit(f'{command} failed: {reply.get("error")}')
    return reply


def passwords():
    """The marker accounts' passwords, generated once (0600)."""
    if not PASSWORDS.exists():
        PASSWORDS.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        data = {app: secrets.token_urlsafe(24) for app in ('nextcloud',)}
        fd = os.open(PASSWORDS, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(data, handle)
        log(f'generated the marker passwords in {PASSWORDS} (0600, not shown)')
    os.chmod(PASSWORDS, 0o600)
    return json.loads(PASSWORDS.read_text())


def markers(app, action, tag=None, stamp=None, password=None):
    argv = [LP, 'exec', '-i', DEV, OWNER, 'python3', '-I', '-c', MARKERS, app, action]
    if tag:
        argv += [tag, stamp]
    password = password or pw.get(app)
    proc = subprocess.run(argv, input=json.dumps({'password': password} if password else {}).encode(),
                          capture_output=True, timeout=600)
    if proc.returncode:
        raise SystemExit(f'markers {app} {action} {tag or ""} failed: {proc.stderr.decode(errors="replace")[-600:]}')
    return json.loads(proc.stdout.decode().strip().splitlines()[-1])


def names(app, found):
    """Every woowbk-lab-* marker name in a read() result, as '<kind>:<name>'."""
    out = set()
    for kind, value in found.items():
        if isinstance(value, dict):
            value = list(value)
        if not isinstance(value, list):
            continue
        for item in value:
            item = str(item)
            if 'woowbk-lab' in item:
                out.add(f'{kind}:{item.split(":")[0]}')
    return out


# What the baseline markers look like in a read() result (see batch2_markers.py).
BASELINE = {
    'nextcloud': {'users:woowbk-lab-baseline', 'files:woowbk-lab-baseline.txt'},
    'opendesign': {'projects:woowbk-lab-baseline', 'files:woowbk-lab-baseline.txt'},
    'code-server': {'snippets:woowbk-lab-baseline.code-snippets', 'skills:woowbk-lab-baseline', 'files:woowbk-lab-baseline.txt'},
}
# Apps with a real client login check (batch2_markers.py <app> login), before the backup and after the restore.
LOGIN = {'code-server'}
def digests(found):
    """The baseline markers with their content digests ('name:sha256'): files, and code-server's snippets and skills."""
    return sorted(f for kind in ('files', 'snippets', 'skills') for f in found.get(kind, [])
                  if f.startswith('woowbk-lab-baseline'))
def host_free():
    st = os.statvfs('/')
    return st.f_bavail * st.f_frsize


def wait_job(job_id, label, timeout=3600):
    start, phase = time.monotonic(), None
    while True:
        if host_free() < WATCH:
            engine('job-cancel', {'job_id': job_id})
            raise SystemExit(f'{label}: host free space fell to {host_free() >> 20} MiB (floor {FLOOR >> 30} GiB): job cancelled')
        reply = engine('job-status', {'job_id': job_id})
        job = reply['job']
        if job.get('phase') != phase:
            phase = job.get('phase')
            log(f'{label}: state={job["state"]} phase={phase} {job["progress"].get("percent")}%')
        if job['state'] not in ('queued', 'running'):
            log(f'{label}: {job["state"]} after {time.monotonic() - start:.1f}s')
            return job, reply.get('log') or [], time.monotonic() - start
        if time.monotonic() - start > timeout:
            raise SystemExit(f'{label} still running after {timeout}s')
        time.sleep(2)


def http_code(url):
    return subprocess.run([LP, 'exec', DEV, 'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '10', url],
                          capture_output=True, timeout=30).stdout.decode()


def catalog(app):
    raw = subprocess.run([LP, 'exec', DEV, 'cat', f'/etc/woowtech-cockpit/backup/apps/{app}.json'],
                         capture_output=True, check=True, timeout=30).stdout
    return json.loads(raw)


def live_bytes(app):
    """Bytes of the app's live data in dev-e: the catalog's data_dirs and volumes, as appowner sees them."""
    entry = catalog(CATALOG_ID[app])
    paths = [f'/home/appowner/{d["path"]}' for d in entry.get('data_dirs', [])]
    for volume in entry.get('volumes', []):
        mount = subprocess.run([LP, 'exec', '-i', DEV, OWNER, 'podman', 'volume', 'inspect', '--format', '{{.Mountpoint}}',
                                volume['name']], capture_output=True, timeout=60, check=True).stdout.decode().strip()
        paths.append(mount)
    out = subprocess.run([LP, 'exec', '-i', DEV, OWNER, 'podman', 'unshare', 'du', '-sb', '--', *paths],
                         capture_output=True, timeout=600, check=True).stdout.decode()
    return sum(int(line.split()[0]) for line in out.splitlines() if line.strip())


def disk_ok(app, step):
    data = live_bytes(app)
    need = int(2.5 * data) + GIB // 4
    free = host_free()
    detail = {'step': step, 'host_free_mib': free >> 20, 'live_data_mib': data >> 20, 'estimated_peak_mib': need >> 20,
              'floor_mib': FLOOR >> 20, 'reserve_mib': RESERVE >> 20}
    ok = free - need >= FLOOR + RESERVE
    check(f'{app}: host disk keeps the 12 GiB floor + 1 GiB reserve after the {step}'
          + ('' if ok else ' (PAUSED: host disk)'), ok, detail)
    return ok


pw = passwords()
summary = {}


def baseline(app):
    stamp = time.strftime('%Y%m%dT%H%M%S')
    found = markers(app, 'read')
    have = names(app, found)
    stray = {n for n in have if n not in BASELINE[app]}
    if stray:
        check(f'{app}: no leftover markers of an earlier run', False, sorted(stray))
        return
    if not BASELINE[app] <= have:
        created = markers(app, 'seed', 'baseline', stamp, pw.get(app))  # creates only what is missing
        log(f'{app}: baseline markers created: {json.dumps(created, ensure_ascii=False)}')
        found = markers(app, 'read')
        have = names(app, found)
    (EVIDENCE / f'{app}-markers-before-backup.json').write_text(json.dumps(found, ensure_ascii=False, indent=1))
    before_digests = digests(found)
    if not check(f'{app}: baseline markers present before the backup', BASELINE[app] <= have,
                 sorted(BASELINE[app] - have)):
        return
    if app in LOGIN:
        login = markers(app, 'login')
        if not check(f'{app}: real login before the backup (session cookie, workbench page, wrong password refused)',
                     login.get('ok'), login):
            return

    if not disk_ok(app, 'backup'):
        return
    request = {'apps': [CATALOG_ID[app]], 'include_images': False, 'note': f'dev-e 基準備份（{app}）', 'request_id': str(uuid.uuid4()),
               'encrypt': True}
    start = engine('backup-start', request)
    job, joblog, wall = wait_job(start['job_id'], f'backup {app}')
    (EVIDENCE / f'{app}-backup-job.json').write_text(json.dumps({'job': job, 'log': joblog}, ensure_ascii=False, indent=1))
    if not check(f'{app}: encrypted backup succeeded', job['state'] == 'succeeded', job.get('error')):
        return
    result = job['result']
    backup_id = result['backup_id']
    meta = next(b for b in engine('list')['backups'] if b['id'] == backup_id)
    status = engine('status')
    check(f'{app}: backup {backup_id} is encrypted with the device key, without images',
          meta['encrypted'] and meta['key_id'] == status['key']['key_id'] and not meta['include_images']
          and [a['id'] for a in meta['apps']] == [CATALOG_ID[app]], meta)
    inspect = engine('inspect', {'backup_id': backup_id})
    pre = next(a for a in inspect['preflight']['apps'] if a['id'] == CATALOG_ID[app])
    (EVIDENCE / f'{app}-inspect.json').write_text(json.dumps(inspect, ensure_ascii=False, indent=1))
    check(f'{app}: inspect preflight ok, in-place restorable', inspect['preflight']['ok'] and pre['restorable']
          and pre['mode'] == 'inplace', pre)

    if not disk_ok(app, 'restore'):  # before the after marker, so a pause leaves the baseline state
        return
    created = markers(app, 'seed', 'after', time.strftime('%Y%m%dT%H%M%S'), secrets.token_urlsafe(18))
    after = names(app, markers(app, 'read')) - BASELINE[app]
    check(f'{app}: "after" marker present before the restore', after, created)

    start = engine('restore-start', {'backup_id': backup_id, 'apps': [CATALOG_ID[app]], 'request_id': str(uuid.uuid4()),
                                     'confirm': True})
    rjob, rlog, rwall = wait_job(start['job_id'], f'restore {app}')
    (EVIDENCE / f'{app}-restore-job.json').write_text(json.dumps({'job': rjob, 'log': rlog}, ensure_ascii=False, indent=1))
    if not check(f'{app}: in-place restore succeeded', rjob['state'] == 'succeeded', rjob.get('error')):
        return
    rresult = rjob['result']
    check(f'{app}: restore made a safety backup, not rolled back, every health check ok',
          rresult.get('safety_backup_id') and rresult.get('rolled_back') is False
          and all(c['status'] == 'ok' for c in rresult.get('health') or []),
          {k: rresult.get(k) for k in ('safety_backup_id', 'rolled_back', 'health')})
    found = markers(app, 'read')
    (EVIDENCE / f'{app}-markers-after-restore.json').write_text(json.dumps(found, ensure_ascii=False, indent=1))
    have = names(app, found)
    check(f'{app}: baseline markers survived the restore', BASELINE[app] <= have, sorted(BASELINE[app] - have))
    check(f'{app}: baseline file content unchanged by the restore (sha256)', digests(found) == before_digests,
          {'before': before_digests, 'after': digests(found)})
    check(f'{app}: "after" marker is gone after the restore', not (have - BASELINE[app]), sorted(have - BASELINE[app]))
    status = engine('status')
    state = next(a for a in status['apps'] if a['id'] == CATALOG_ID[app])
    check(f'{app}: engine status running, no problems, after the restore', state['deployed'] and state['state'] == 'running'
          and not state['problems'], state)
    codes = {c['url']: (http_code(c['url']), str(c['expect_status'])) for c in catalog(CATALOG_ID[app])['health']}
    check(f'{app}: catalog health URLs answer as expected after the restore', all(a == e for a, e in codes.values()), codes)
    if app in LOGIN:
        login = markers(app, 'login')
        check(f'{app}: real login after the restore (session cookie, workbench page, wrong password refused)',
              login.get('ok'), login)
    summary[app] = {'backup_id': backup_id, 'backup_size': result['size'], 'backup_wall_s': round(wall, 1),
                    'backup_downtime_s': result.get('downtime_seconds'), 'restore_wall_s': round(rwall, 1),
                    'restore_downtime_s': rresult.get('downtime_seconds'), 'safety_backup_id': rresult.get('safety_backup_id'),
                    'health': rresult.get('health'), 'markers': sorted(BASELINE[app])}



for app in APPS:
    try:
        baseline(app)
    except SystemExit as error:  # one app failing must not hide the others' results
        check(f'{app}: baseline run', False, error)

passed = sum(c['ok'] for c in checks)
(EVIDENCE / 'result.json').write_text(json.dumps({'checks': checks, 'passed': passed, 'total': len(checks),
                                                  'summary': summary}, ensure_ascii=False, indent=1))
log(f'RESULT {passed}/{len(checks)} checks passed; evidence in {EVIDENCE}')
print(json.dumps(summary, ensure_ascii=False, indent=1))
sys.exit(0 if passed == len(checks) and set(summary) == set(APPS) else 1)
