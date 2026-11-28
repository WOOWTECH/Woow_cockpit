#!/usr/bin/env python3
"""Promoted saved n8n real-app driver (historical34/34), prepared only.

Run after instance-source integration, exact helper deployment and a new dev-c
lease. Requires the existing n8n image/units, PG/Redis/gateway and original frozen
baseline. This case proves application import/data/decryption and baseline
recovery; extra databases/roles and full-instance acceptance are separate cases.
Use heavy.sh; this script takes the existing dev-c mutation lock. No deployment,
image pull, package installation or permission workflow is added here.
Default is an offline import/syntax check; it reads no credentials or device.

--source DIR: the product checkout whose engine (and Cockpit page) dev-c runs, for the installed-engine check and the
page check (default: this checkout, exactly as before). dev-c's engine is moved commit by commit (bfe7b914 for N8-01):
point this at a clean checkout of that commit.

--via-page: the upload, the check and the one-action import go through dev-c's REAL Cockpit page instead of the helper
calls (focus_page_bridge.py, under this run's own lock hold): the page uploads the encrypted file, selects only n8n, takes
the HA key, shows the check and its one confirmation, ticks it once and starts the import (the conversion and its restore
as two linked jobs) - the same ha-import-start this flow sends itself. The check's and the chain's facts are then checked
on the page's own jobs exactly as below; the page adds its fixed browser checks, the expected outcome (n8n importable,
nothing stopped, every confirmation line keyed, read from the actual check), every key acknowledged exactly once, the chain
in one unit, nothing to choose and the issued Cockpit cookie scan. Everything after the import (owner login, credential
decryption, workflows, executions, health, baseline restore, cleanup, leaks) is unchanged; it also reads devadmin.pass
(the Cockpit login), redacts it and scans the device for it. Without --via-page the run is exactly the helper flow.
"""
import argparse
import fcntl
import hashlib
import importlib.util
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
# --via-page: the page's whole import (upload, check, conversion, restore) in one step: at most 25 minutes (the page's own
# 20 and reading its jobs); every later wait stays the flow's own.
PAGE_STEP_BUDGET = 25 * 60
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


def _load_bridge():
    """focus_page_bridge, only for --via-page (loaded next to this file)."""
    spec = importlib.util.spec_from_file_location('focus_page_bridge', Path(__file__).resolve().parent / 'focus_page_bridge.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(product=None, via_page=False, bridge=None):
    repo = REPO
    product = repo if product is None else Path(product).resolve()   # the engine and page dev-c runs (--source)
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
    if via_page:   # devadmin's Cockpit login (shared by every lab device): redacted like every other value
        secrets.values['COCKPIT_PASSWORD'] = (Path.home() / '.woowbk-lab/secrets/devadmin.pass').read_text().strip()
    ev = h.Evidence(secrets, 'focus-acceptance-n8n')
    page_summary = None
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


    def judge_check(check):
        """The facts of the check job (the helper's, or the page's own with --via-page): the same checks either way."""
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


    def judge_chain(records):
        """The import's two jobs (the helper's one-action import, or the page's): the same checks either way."""
        require('one-action import made convert then restore jobs',
                len(records) == 2 and [x.get('type') for x in records] == ['backup', 'restore'])
        require('both n8n jobs succeeded', all(x.get('state') == 'succeeded' for x in records))
        group = ((records[-1].get('result') or {}).get('group') or {})
        rows = group.get('results') or []
        require('group reports n8n imported', len(rows) == 1 and rows[0].get('app_id') == 'n8n'
                and rows[0].get('status') == 'imported')
        require('restore made a safety backup', bool((records[-1].get('result') or {}).get('safety_backup_id')))


    def root_json(script, request):
        proc = h.root('python3', '-I', '-c', script, input=json.dumps(request).encode(), timeout=300)
        if proc.returncode != 0:
            raise h.Failed('fixed read-only device program failed')
        return json.loads(proc.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])


    def page_checks(page):
        summary, gates = page.summary, page.gates
        for item in page.browser_checks:
            ev.check(f'page: {item.get("check")}', item.get('ok') is True)
        ev.check('page: bounded (20 min), the browser closed in order and every relay exec child reaped',
                 gates.get('page_bounded') and gates.get('cleanup'), json.dumps(summary.get('page')))
        ev.check('page: the uploaded HA record is the fixture (id and SHA-256)', gates.get('record'),
                 json.dumps({'ha_id': summary.get('ha_id'), 'existed_before': summary.get('ha_record_existed')}))
        ev.check('page: exactly the page\'s own check and import jobs, none left running, no other new backup',
                 gates.get('own_jobs') and gates.get('no_unexplained_backups'),
                 json.dumps({'check': summary.get('check_job_id'), 'chain': summary.get('chain_job_ids'),
                             'unexplained': summary.get('unexplained_new_backups'), 'reasons': summary.get('reasons')}))
        ev.check('page: the check calls n8n importable, stops nothing, and lists every confirmation line keyed '
                 '(read from the actual check)', gates.get('expected_outcome'),
                 json.dumps({'lines': summary.get('confirmation_lines'), 'reasons': summary.get('reasons')}))
        ev.check('page: the one acknowledgement, the import and its jobs carry every listed confirmation key exactly once',
                 gates.get('acknowledged_exact'))
        ev.check('page: one conversion and its restore succeeded as two linked jobs in the first job\'s unit',
                 gates.get('chain') and gates.get('native_units'), json.dumps({'jobs': summary.get('chain_job_ids')}))
        ev.check('page: nothing to choose: the check offers no choice and neither request nor the chain carries one',
                 gates.get('choices'), json.dumps(summary.get('chosen')))
        ev.check('page: every issued Cockpit session value is absent from the records, the journal and the private evidence',
                 gates.get('issued_scan'), json.dumps((summary.get('browser') or {}).get('issued_scan')))


    def password_scan():
        """The page logged in to Cockpit with devadmin's password: it is nowhere in the engine's files or the journal."""
        proc = h.root('python3', '-I', '-c', h.LEAK_SCAN, input=json.dumps([secrets['COCKPIT_PASSWORD']]).encode(),
                      timeout=600)
        try:
            report = json.loads(proc.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise h.Failed('Cockpit password scan failed') from None
        ev.save('leaks-cockpit-login.json', report)
        ev.check('no Cockpit login password in the engine\'s records, logs, index, registry or the device journal',
                 not report['hits'], f'{report["scanned"]} files, journal {report["journal_bytes"]} bytes')


    def restore_baseline():
        job, took = h.restore(BASELINE, ['n8n'], ev=ev, tag='n8n-parity-baseline')
        all_created([job])
        require('cleanup: baseline restore succeeds', job.get('state') == 'succeeded', f'{took:.1f}s')
        baseline_state('cleanup')


    try:
        h.require_isolated_device()
        require('dev-c is isolated: network none, no published port', True)
        require('source checkout is clean', not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain', '--untracked-files=no'], text=True).strip())
        if product != repo:
            require('product checkout (--source) is clean', not subprocess.check_output(['git', '-C', str(product), 'status', '--porcelain', '--untracked-files=no'], text=True).strip())
        require('real HA fixture is present', FIXTURE.is_file() and FIXTURE.stat().st_size > 0)
        require('host reserve and memory are ready',
                os.statvfs(repo).f_bavail * os.statvfs(repo).f_frsize > 14 * 1024**3
                and next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines()
                         if x.startswith('MemAvailable:')) >= 1200 * 1024)
        memory = h.root('python3', '-I', '-c', "from pathlib import Path; s=Path('/sys/fs/cgroup/memory.stat').read_text().splitlines(); used=sum(int(x.split()[1]) for x in s if x.startswith(('anon ', 'kernel '))); print(int(Path('/sys/fs/cgroup/memory.max').read_text())-used)", timeout=60)
        require('device has at least one GiB memory headroom', memory.returncode == 0 and int(memory.stdout) >= 1024**3)
        probe = h.root('python3', '-I', '-c', ENGINE_HASHES, timeout=120)
        installed = json.loads(probe.stdout)
        source = product / 'backup-engine/woowbackup'
        expected = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in source.rglob('*.py') if '__pycache__' not in p.parts}
        require('installed helper and all engine modules match this source',
                probe.returncode == 0 and installed.get('lib') == expected
                and installed.get('helper') == hashlib.sha256((product/'backup-engine/woowtech-cockpit-backup').read_bytes()).hexdigest())
        baseline_state('before')
        pre = h.ok('inspect', {'backup_id': BASELINE}, ev=ev)
        preflight = pre.get('preflight') or {}
        require('baseline backup can restore n8n on this engine',
                pre.get('ok') is True and preflight.get('ok') is True and
                [x.get('id') for x in preflight.get('apps') or []] == ['n8n'] and
                not [x for x in preflight.get('checks') or [] if x.get('status') == 'fail'])

        existing_uploads = {x['id'] for x in h.ok('list', ev=ev).get('ha_backups', [])}
        if via_page:
            # Upload, check and one-action import through the real page, under this run's own dev-c lock hold.
            bridge = bridge or _load_bridge()
            ops = bridge.Ops(helper=lambda command, request=None: h.ok(command, request, ev=ev),
                             wait_job=lambda job_id, timeout: h.wait_job(job_id, ev=ev, timeout=timeout),
                             root_json=root_json)
            try:
                page = bridge.import_via_page(device=h.DEVICE, lock=LOCK, apps=['n8n'], importable=['n8n'], stops=[],
                                              fixture=FIXTURE, key=secrets['HA_BACKUP_KEY'], choices={},
                                              password=secrets['COCKPIT_PASSWORD'], evidence=ev.dir / 'page',
                                              deadline=time.monotonic() + PAGE_STEP_BUDGET, ops=ops, source=product)
                summary = page.summary
            except bridge.BridgeError as error:
                page, summary = None, error.summary
            page_summary = summary
            # What the page made goes to this run's own cleanup at once: its backups, its chain, its upload.
            for backup_id in summary.get('created_backups') or []:
                if isinstance(backup_id, str) and backup_id != BASELINE:
                    created.add(backup_id)
            first_job = summary.get('root_job_id') or (summary.get('root_job_ids') or [None])[0]
            if summary.get('ha_id') and summary.get('phase') != 'refused' \
                    and summary['ha_id'] in {x['id'] for x in h.ok('list', ev=ev).get('ha_backups', [])}:
                ha_id = summary['ha_id']
            if page is None:
                ev.check('page import: refused before the page started (nothing changed)' if summary.get('phase') in
                         ('preconditions', 'refused') else 'page import: stopped by a signal (the browser closed in order, '
                         'the relay reaped)', False, json.dumps({'reasons': summary.get('reasons'), 'phase': summary.get('phase')}))
                raise h.Failed('page import did not run to the end')
            records = page.chain
            chain_finished = bool(records) and summary.get('inflight') is None and not (
                ((records[-1].get('result') or {}).get('group') or {}).get('next_job_id'))
            all_created(records)
            page_checks(page)
            require('page import passed every gate', page.passed)
            judge_check(page.check_job)
            judge_chain(records)
        else:
            rc, reply = h.upload(FIXTURE, ev=ev)
            ha_id = (reply.get('ha_backup') or {}).get('id') if rc == 0 else None
            require('real HA fixture uploaded', bool(ha_id and ha_id.startswith('ha-')))
            check = h.run_check(ha_id, ['n8n'], ev=ev, key=secrets['HA_BACKUP_KEY'], tag='n8n-parity-check')
            judge_check(check)

            request = {'ha_backup_id': ha_id, 'apps': ['n8n'], 'request_id': h.request_id('n8n-parity-import'),
                       'confirm': True, 'test_mode': False, 'then_restore': True, 'overwrite': True,
                       'check_job_id': check['id'], 'key': secrets['HA_BACKUP_KEY']}
            response = h.ok('ha-import-start', request, ev=ev, timeout=300)
            first_job = response.get('job_id')
            require('one-action import started a group and first job', bool(first_job and response.get('group')))
            records = follow(first_job)
            chain_finished = True
            all_created(records)
            judge_chain(records)
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
            if via_page:
                password_scan()
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
        if product != repo:
            public['product_commit'] = subprocess.check_output(['git', '-C', str(product), 'rev-parse', 'HEAD'], text=True).strip()
        if via_page:   # the import went through dev-c's real Cockpit page (gates only; the private summary stays private)
            public['import_path'] = 'page'
            public['page_gates'] = (page_summary or {}).get('gates')
        with os.fdopen(os.open(PUBLIC, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:
            json.dump(public, out, indent=2, ensure_ascii=False)
        print('n8n full flow', f'{public["passed"]}/{len(rows)}', 'PASS' if good else 'FAIL')
    return 0 if good and baseline_restored else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--via-page', action='store_true',
                        help='upload, check and import through dev-c\'s real Cockpit page (focus_page_bridge.py)')
    parser.add_argument('--source', type=Path,
                        help='product checkout whose engine and page dev-c runs (default: this checkout)')
    args = parser.parse_args(argv)
    if not args.run:
        compile(ENGINE_HASHES, '<read-only installed hash check>', 'exec')
        print('n8n driver prepared: offline check PASS; real run needs integrated source and dev-c lease')
        return 0
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _run(product=args.source, via_page=args.via_page) if (args.source or args.via_page) else _run()
    finally:
        os.close(fd)


if __name__ == '__main__':
    sys.exit(main())
