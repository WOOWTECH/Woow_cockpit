#!/usr/bin/env python3
"""dev-c baseline (deploy-prodlike.sh): per app, an encrypted backup through engine.sh, then an in-place restore.

    python3 -I tests/e2e/lab/prodlike_baseline.py [odoo] [n8n]     # default: both, in this order

Before each backup a marker row goes into the app's database (Odoo `ir_config_parameter`, n8n `settings`,
key woowbk.lab.baseline.before); after the backup a second one (…after). The restore must keep the first and
remove the second, so a restore that silently left the data alone fails. Checks: the backup is encrypted with
the device key and without images, `inspect` says restorable in place, the restore made a safety backup, was
not rolled back and every catalog health check passed, `status` shows the app running without problems and the
catalog's health URLs answer 200. Evidence (no keys, no secrets) goes to
~/.woowbk-lab/evidence/prodlike/<stamp>-baseline/; the backups and safety backups are kept (lab data).
"""
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

LAB = Path.home() / '.woowbk-lab'
LP = str(LAB / 'bin' / 'labpodman')
ENGINE = str(Path(__file__).resolve().parent / 'engine.sh')
DEV = 'woowbk-dev-c'
OWNER = '/usr/local/bin/woowbk-owner'
EVIDENCE = LAB / 'evidence' / 'prodlike' / (time.strftime('%Y%m%dT%H%M%S') + '-baseline')
APPS = sys.argv[1:] or ['odoo', 'n8n']
if not set(APPS) <= {'odoo', 'n8n'}:
    raise SystemExit('usage: prodlike_baseline.py [odoo] [n8n]')
HEALTH = {'odoo': ['http://127.0.0.1:18069/web/health', 'http://127.0.0.1:18080/web/health'],
          'n8n': ['http://127.0.0.1:15678/healthz/readiness', 'http://127.0.0.1:15679/healthz']}
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
    proc = subprocess.run([ENGINE, 'c', command, '-'], input=json.dumps(request or {}).encode(),
                          capture_output=True, timeout=timeout)
    reply = json.loads(proc.stdout)
    if not reply.get('ok'):
        raise SystemExit(f'{command} failed: {reply.get("error")}')
    return reply


def owner(*argv, timeout=120):
    return subprocess.run([LP, 'exec', '-i', DEV, OWNER, *argv], capture_output=True, timeout=timeout, check=True,
                          stdin=subprocess.DEVNULL).stdout.decode().strip()


def sql(app, statement):
    if app == 'odoo':
        return owner('podman', 'exec', 'odoo18-db', 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'odoo', '-d', 'odoo',
                     '-Atc', statement)
    return owner('podman', 'exec', 'n8n-postgres', 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'n8n', '-d', 'n8n',
                 '-Atc', statement)


def set_marker(app, key, value):
    if app == 'odoo':
        sql(app, f"INSERT INTO ir_config_parameter(key, value) VALUES ('{key}', '{value}') "
                 "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
    else:
        sql(app, f"INSERT INTO settings(key, value, \"loadOnStartup\") VALUES ('{key}', '{value}', false) "
                 "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")


def get_marker(app, key):
    table = 'ir_config_parameter' if app == 'odoo' else 'settings'
    return sql(app, f"SELECT value FROM {table} WHERE key = '{key}'")


def wait_job(job_id, label, timeout=3600):
    start, phase = time.monotonic(), None
    while True:
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


summary = {}
for app in APPS:
    stamp = time.strftime('%Y%m%dT%H%M%S')
    key_a, key_b = 'woowbk.lab.baseline.before', 'woowbk.lab.baseline.after'
    set_marker(app, key_a, f'before-backup-{stamp}')
    sql(app, f"DELETE FROM {'ir_config_parameter' if app == 'odoo' else 'settings'} WHERE key = '{key_b}'")
    request = {'apps': [app], 'include_images': False, 'note': f'dev-c 基準備份（{app}）', 'request_id': str(uuid.uuid4()),
               'encrypt': True}
    start = engine('backup-start', request)
    job, joblog, wall = wait_job(start['job_id'], f'backup {app}')
    (EVIDENCE / f'{app}-backup-job.json').write_text(json.dumps({'job': job, 'log': joblog}, ensure_ascii=False, indent=1))
    if not check(f'{app}: encrypted backup succeeded', job['state'] == 'succeeded', job.get('error')):
        continue
    result = job['result']
    backup_id = result['backup_id']
    meta = next(b for b in engine('list')['backups'] if b['id'] == backup_id)
    status = engine('status')
    check(f'{app}: backup {backup_id} is encrypted with the device key, without images',
          meta['encrypted'] and meta['key_id'] == status['key']['key_id'] and not meta['include_images']
          and [a['id'] for a in meta['apps']] == [app], meta)
    inspect = engine('inspect', {'backup_id': backup_id})
    pre = next(a for a in inspect['preflight']['apps'] if a['id'] == app)
    (EVIDENCE / f'{app}-inspect.json').write_text(json.dumps(inspect, ensure_ascii=False, indent=1))
    check(f'{app}: inspect preflight ok, in-place restorable', inspect['preflight']['ok'] and pre['restorable']
          and pre['mode'] == 'inplace', pre)
    set_marker(app, key_b, f'after-backup-{stamp}')
    check(f'{app}: marker written after the backup is present before the restore', get_marker(app, key_b) != '')
    start = engine('restore-start', {'backup_id': backup_id, 'apps': [app], 'request_id': str(uuid.uuid4()),
                                     'confirm': True})
    rjob, rlog, rwall = wait_job(start['job_id'], f'restore {app}')
    (EVIDENCE / f'{app}-restore-job.json').write_text(json.dumps({'job': rjob, 'log': rlog}, ensure_ascii=False, indent=1))
    if not check(f'{app}: in-place restore succeeded', rjob['state'] == 'succeeded', rjob.get('error')):
        continue
    rresult = rjob['result']
    check(f'{app}: restore made a safety backup, not rolled back, every health check ok',
          rresult.get('safety_backup_id') and rresult.get('rolled_back') is False and rresult.get('health')
          and all(c['status'] == 'ok' for c in rresult['health']), {k: rresult.get(k) for k in ('safety_backup_id', 'rolled_back', 'health')})
    check(f'{app}: marker written before the backup survived the restore', get_marker(app, key_a) == f'before-backup-{stamp}')
    check(f'{app}: marker written after the backup is gone after the restore', get_marker(app, key_b) == '')
    sql(app, f"DELETE FROM {'ir_config_parameter' if app == 'odoo' else 'settings'} WHERE key = '{key_a}'")
    status = engine('status')
    state = next(a for a in status['apps'] if a['id'] == app)
    check(f'{app}: engine status running, no problems, after the restore', state['deployed'] and state['state'] == 'running'
          and not state['problems'], state)
    codes = {url: http_code(url) for url in HEALTH[app]}
    check(f'{app}: catalog health URLs answer 200 after the restore', all(c == '200' for c in codes.values()), codes)
    summary[app] = {'backup_id': backup_id, 'backup_size': result['size'], 'backup_wall_s': round(wall, 1),
                    'backup_downtime_s': result.get('downtime_seconds'), 'restore_wall_s': round(rwall, 1),
                    'restore_downtime_s': rresult.get('downtime_seconds'), 'safety_backup_id': rresult.get('safety_backup_id'),
                    'health': rresult.get('health')}

passed = sum(c['ok'] for c in checks)
(EVIDENCE / 'result.json').write_text(json.dumps({'checks': checks, 'passed': passed, 'total': len(checks),
                                                  'summary': summary}, ensure_ascii=False, indent=1))
log(f'RESULT {passed}/{len(checks)} checks passed; evidence in {EVIDENCE}')
print(json.dumps(summary, ensure_ascii=False, indent=1))
sys.exit(0 if passed == len(checks) else 1)
