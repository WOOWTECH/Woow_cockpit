#!/usr/bin/env python3
"""Promoted saved n8n real-app driver (historical34/34), prepared only.

Run after instance-source integration, exact helper deployment and a new dev-c
lease. Requires the existing n8n image/units, PG/Redis/gateway and original frozen
baseline. This case proves application import/data/decryption and baseline
recovery; extra databases/roles and full-instance acceptance are separate cases.
Use heavy.sh; this script takes the existing dev-c mutation lock. No deployment,
image pull, package installation or permission workflow is added here.
Default is an offline import/syntax check; it reads no credentials or device.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets as secrets_module
import subprocess
import sys
import time
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[3]
LOCK = '/tmp/woowbk-dev-c-mutation.lock'
ENGINE_HASHES = r'''
import hashlib,json,os
lib="/usr/local/lib/woowtech-cockpit-backup/woowbackup"
out={"lib":{},"helper":None}
for d,dirs,files in os.walk(lib):
    dirs[:]=[x for x in dirs if x!="__pycache__"]
    for f in files:
        if f.endswith(".py"):
            p=os.path.join(d,f)
            out["lib"][os.path.relpath(p,lib)]=hashlib.sha256(open(p,"rb").read()).hexdigest()
out["helper"]=hashlib.sha256(open("/usr/local/libexec/woowtech-cockpit-backup","rb").read()).hexdigest()
print(json.dumps(out))
'''


def _run():
    repo = REPO
    sys.path.insert(0, str(repo / 'tests/e2e/lab'))
    import ha_import_e2e as h
    h.DEVICE = 'woowbk-dev-c'
    h.require_isolated_device()  # before the historical body reads credentials
    original_wait = h.wait_job
    def bounded_wait(job_id, *, ev, timeout=600):
        return original_wait(job_id, ev=ev, timeout=min(timeout, 600))
    h.wait_job = bounded_wait
    BASELINE = '20261118T095520Z-33eb7474'
    FIXTURE = Path.home() / '.woowbk-lab/ha-fixtures/20261118/woow-import-test-enc/woow-import-test-enc.tar'
    PUBLIC = repo / 'tests/backup/evidence/focus-acceptance-20261127' / ('n8n-x86-' + time.strftime('%Y%m%dT%H%M%S') + '-' + secrets_module.token_hex(4) + '.json')
    secrets = h.Secrets(Path.home() / '.woowbk-lab/secrets/ha-import-creds.env',
                        Path.home() / '.woowbk-lab/secrets/ha-import-n8n-testdata.sh')
    ev = h.Evidence(secrets, 'focus-acceptance-n8n')
    created = set()
    ha_id = first_job = None
    chain_finished = False
    imported = False
    baseline_restored = False
    existing_uploads = set()


    def require(label, condition, detail=''):
        if not ev.check(label, condition, detail):
            raise h.Failed(label)


    def baseline_state(label):
        value = h.psql('n8n-postgres', 'n8n', 'n8n',
                       "SELECT (SELECT count(*) FROM settings WHERE key = 'woowbk.lab.baseline.before') || '|' || "
                       "(SELECT count(*) FROM settings WHERE key = 'woowbk.lab.baseline.after') || '|' || "
                       "(SELECT count(*) FROM workflow_entity);")
        require(label + ': baseline marker and no imported workflow', value == '1|0|0', value)
        require(label + ': both n8n health endpoints answer 200',
                h.http_code('http://127.0.0.1:15678/healthz/readiness') == '200'
                and h.http_code('http://127.0.0.1:15679/healthz') == '200')


    def follow(first):
        seen, records, current = set(), [], first
        while current and len(records) < 2:
            require('chain job id is new', current not in seen)
            seen.add(current)
            job = h.wait_job(current, ev=ev, timeout=3600)
            records.append(job)
            next_id = ((job.get('result') or {}).get('group') or {}).get('next_job_id')
            current = next_id
        require('one n8n import has at most two jobs', not current)
        return records


    def all_created(records):
        for job in records:
            result = job.get('result') or {}
            for key in ('backup_id', 'safety_backup_id'):
                value = result.get(key)
                if isinstance(value, str) and value != BASELINE:
                    created.add(value)


    def restore_baseline():
        job, took = h.restore(BASELINE, ['n8n'], ev=ev, tag='n8n-parity-baseline')
        all_created([job])
        require('cleanup: baseline restore succeeds', job.get('state') == 'succeeded', f'{took:.1f}s')
        baseline_state('cleanup')


    try:
        h.require_isolated_device()
        require('dev-c is isolated: network none, no published port', True)
        require('source checkout is clean', not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain', '--untracked-files=no'], text=True).strip())
        require('real HA fixture is present', FIXTURE.is_file() and FIXTURE.stat().st_size > 0)
        require('host reserve and memory are ready',
                os.statvfs(repo).f_bavail * os.statvfs(repo).f_frsize > 14 * 1024**3
                and next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines()
                         if x.startswith('MemAvailable:')) >= 1200 * 1024)
        memory = h.root('python3', '-I', '-c', "from pathlib import Path; s=Path('/sys/fs/cgroup/memory.stat').read_text().splitlines(); used=sum(int(x.split()[1]) for x in s if x.startswith(('anon ', 'kernel '))); print(int(Path('/sys/fs/cgroup/memory.max').read_text())-used)", timeout=60)
        require('device has at least one GiB memory headroom', memory.returncode == 0 and int(memory.stdout) >= 1024**3)
        probe = h.root('python3', '-I', '-c', ENGINE_HASHES, timeout=120)
        installed = json.loads(probe.stdout)
        source = repo / 'backup-engine/woowbackup'
        expected = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in source.rglob('*.py') if '__pycache__' not in p.parts}
        require('installed helper and all engine modules match this source',
                probe.returncode == 0 and installed.get('lib') == expected
                and installed.get('helper') == hashlib.sha256((repo/'backup-engine/woowtech-cockpit-backup').read_bytes()).hexdigest())
        baseline_state('before')
        pre = h.ok('inspect', {'backup_id': BASELINE}, ev=ev)
        preflight = pre.get('preflight') or {}
        require('baseline backup can restore n8n on this engine',
                pre.get('ok') is True and preflight.get('ok') is True and
                [x.get('id') for x in preflight.get('apps') or []] == ['n8n'] and
                not [x for x in preflight.get('checks') or [] if x.get('status') == 'fail'])

        existing_uploads = {x['id'] for x in h.ok('list', ev=ev).get('ha_backups', [])}
        rc, reply = h.upload(FIXTURE, ev=ev)
        ha_id = (reply.get('ha_backup') or {}).get('id') if rc == 0 else None
        require('real HA fixture uploaded', bool(ha_id and ha_id.startswith('ha-')))
        check = h.run_check(ha_id, ['n8n'], ev=ev, key=secrets['HA_BACKUP_KEY'], tag='n8n-parity-check')
        require('HA check job succeeded', check.get('state') == 'succeeded')
        apps = ((check.get('result') or {}).get('ha_check') or {}).get('apps') or []
        require('HA check has exactly n8n', len(apps) == 1 and apps[0].get('app_id') == 'n8n')
        app = apps[0]
        ev.save('checked-n8n.json', app)
        require('n8n is importable, no unreviewed issue or blocker',
                app.get('ok') is True and app.get('importable') is True and not app.get('issues')
                and not app.get('blockers'))
        section = app.get('n8n') or {}
        require('HA source has three workflows, one credential and executions',
                section.get('workflows') == 3 and section.get('credentials') == 1
                and section.get('executions', 0) >= 1)

        request = {'ha_backup_id': ha_id, 'apps': ['n8n'], 'request_id': h.request_id('n8n-parity-import'),
                   'confirm': True, 'test_mode': False, 'then_restore': True, 'overwrite': True,
                   'check_job_id': check['id'], 'key': secrets['HA_BACKUP_KEY']}
        response = h.ok('ha-import-start', request, ev=ev, timeout=300)
        first_job = response.get('job_id')
        require('one-action import started a group and first job', bool(first_job and response.get('group')))
        records = follow(first_job)
        chain_finished = True
        all_created(records)
        require('one-action import made convert then restore jobs',
                len(records) == 2 and [x.get('type') for x in records] == ['backup', 'restore'])
        require('both n8n jobs succeeded', all(x.get('state') == 'succeeded' for x in records))
        group = ((records[-1].get('result') or {}).get('group') or {})
        rows = group.get('results') or []
        require('group reports n8n imported', len(rows) == 1 and rows[0].get('app_id') == 'n8n'
                and rows[0].get('status') == 'imported')
        require('restore made a safety backup', bool((records[-1].get('result') or {}).get('safety_backup_id')))
        imported = True

        probe = h.device_probe({'n8n': {'email': h.OWNER_EMAIL, 'password': secrets['N8N_OWNER_PW'],
                                        'credential': h.CREDENTIAL, 'value': secrets['N8N_CREDENTIAL_VALUE']}})
        ev.save('imported-client.json', probe)
        require('imported n8n owner can log in', probe.get('n8n_login') is True)
        decrypted = h.credential_probe(h.CREDENTIAL, secrets['N8N_CREDENTIAL_VALUE'])
        require('imported credential decrypts to the HA test value', decrypted.get('match') is True)
        workflows = h.psql('n8n-postgres', 'n8n', 'n8n', 'SELECT name || \'|\' || active FROM workflow_entity ORDER BY name;')
        flows = dict(line.split('|', 1) for line in workflows.splitlines() if '|' in line)
        require('three workflows imported and scheduled workflow active',
                len(flows) == 3 and flows.get(h.SCHEDULED) == 'true')
        executions = h.psql('n8n-postgres', 'n8n', 'n8n', 'SELECT count(*) FROM execution_entity;')
        require('at least one execution imported', executions.isdigit() and int(executions) >= 1)
        require('both imported n8n health endpoints answer 200',
                h.http_code('http://127.0.0.1:15678/healthz/readiness') == '200'
                and h.http_code('http://127.0.0.1:15679/healthz') == '200')
    except Exception as error:
        ev.check('full import completed', False, type(error).__name__)
    finally:
        if first_job and not chain_finished:
            try:
                records = follow(first_job)
                chain_finished = True
                all_created(records)
            except Exception as error:
                ev.check('cleanup: import chain reached a terminal job', False, type(error).__name__)
        if chain_finished:
            try:
                restore_baseline()
                baseline_restored = True
            except Exception as error:
                ev.check('cleanup: baseline restore completed', False, type(error).__name__)
        elif not first_job:
            try:
                baseline_state('cleanup')
                baseline_restored = True
            except Exception as error:
                ev.check('cleanup: baseline stayed intact', False, type(error).__name__)
        if baseline_restored and (chain_finished or not first_job):
            for backup_id in sorted(created):
                try:
                    rc, _ = h.helper('delete', {'backup_id': backup_id})
                    ev.check('cleanup: test-created backup deleted', rc == 0)
                except Exception as error:
                    ev.check('cleanup: test-created backup deleted', False, type(error).__name__)
            if ha_id and ha_id not in existing_uploads:
                try:
                    rc, _ = h.helper('ha-delete', {'ha_backup_id': ha_id, 'confirm': True})
                    ev.check('cleanup: uploaded HA copy deleted', rc == 0)
                except Exception as error:
                    ev.check('cleanup: uploaded HA copy deleted', False, type(error).__name__)
        try:
            h.scenario_cleanup(ev, SimpleNamespace())
            h.scenario_leaks(ev, SimpleNamespace(secrets=secrets))
        except Exception as error:
            ev.check('cleanup: residue and leak checks completed', False, type(error).__name__)
        good = ev.finish()
        rows = ev.results
        public = {'source_commit': subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip(),
                  'device': 'woowbk-dev-c', 'passed': sum(x['ok'] for x in rows),
                  'failed': sum(not x['ok'] for x in rows),
                  'fixed_status': [('PASS ' if x['ok'] else 'FAIL ') + x['check'] for x in rows],
                  'evidence_dir': str(ev.dir), 'commercial_acceptance': 'not-complete',
                  'imported': imported, 'baseline_restored': baseline_restored,
                  'scope': 'reused-n8n-x86-app-flow-not-instance-acceptance'}
        with os.fdopen(os.open(PUBLIC, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:
            json.dump(public, out, indent=2, ensure_ascii=False)
        print('n8n full flow', f'{public["passed"]}/{len(rows)}', 'PASS' if good else 'FAIL')
    return 0 if good and baseline_restored else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args(argv)
    if not args.run:
        compile(ENGINE_HASHES, '<read-only installed hash check>', 'exec')
        print('n8n driver prepared: offline check PASS; real run needs integrated source and dev-c lease')
        return 0
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _run()
    finally:
        os.close(fd)


if __name__ == '__main__':
    sys.exit(main())
