#!/usr/bin/env python3
"""R6 full-share acceptance using the saved 113-check client/rollback harness.

Default prints the offline plan. --run requires an exact reviewed lease, an
already recovered/woken original stack and a committed checkout. No deployment,
image recovery, package installation, key creation or catalog replacement here.
Separate conversion/restore lets the original 4.47GB upload be deleted before
restoring. The original source fixture and baseline archive are never deleted.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import secrets as nonce_source
import sys
import threading
import time
from types import SimpleNamespace

# Also works with python3 -I; imports are restricted to this committed directory.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from focus_nextcloud_r6_inventory import collect, ORIGINALS, FIXTURE, FIXTURE_SHA
from focus_nextcloud_r6_plan import (BASELINE, CASES, DEVICE_CAP, MARGIN, MIB, RESERVE,
                                      acceptance_budget, confirmation_keys, lease_check)

REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
FACTS = Path('/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/nc-import/share-facts.json')
RECEIPT = LAB / 'run/focus_nextcloud_r6.json'
INACTIVE_UNITS = ('nextcloud.target', 'nextcloud-app.service', 'nextcloud-db.service',
                  'nextcloud-redis.service', 'nextcloud-office.service', 'nextcloud-gateway.service',
                  'nextcloud-cron.timer', 'woowtech-backup-schedule.timer')


def baseline_verify():
    """Independent existing verifier, with private output (never argv/credentials)."""
    p = subprocess.run([sys.executable, '-I', str(HERE / 'batch2_baseline.py'), '--verify', 'nextcloud'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1200)
    return p.returncode == 0


def load_flow():
    spec = importlib.util.spec_from_file_location('focus_r6_original_flow', HERE / 'nextcloud_flow.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.FLOOR = mod.WATCH_FLOOR = RESERVE
    mod.drv.state_path = lambda: RECEIPT
    return mod


def validate_facts(facts, case):
    """Full-share uses the original exact file; derivative cases need separate provenance."""
    if case not in CASES:
        raise ValueError('fixed-case-refused')
    if not facts.get('digests') or not facts.get('files') or not facts.get('section', {}).get('datadir_in_backup'):
        raise ValueError('fixed-full-share-facts-required')
    if any(not str(facts.get(k, '')).startswith('B2_NC_')
           for k in ('user_pw', 'app_pw', 'user2_pw', 'link_pw', 'link_token')):
        raise ValueError('fixed-secret-name-facts-required')
    if case == 'fullshare' and (Path(facts['fixture']) != FIXTURE or facts['sha256'] != FIXTURE_SHA):
        raise ValueError('fixed-original-fixture-required')
    if case != 'fullshare':
        # These require separately reviewed real fixture construction and oracles.
        # No switch or synthetic database flag is accepted as an encryption proof.
        raise ValueError('fixed-derived-fixture-review-required')


def execute(args):
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO, text=True).strip():
        raise ValueError('fixed-committed-source-required')
    lease = json.loads(args.lease.read_text())
    lease_check(lease, commit, args.case)
    if sorted(lease.get('original_inactive_units', [])) != sorted(INACTIVE_UNITS):
        raise ValueError('fixed-original-inactive-unit-scope-required')
    facts = json.loads(args.facts.read_text())
    validate_facts(facts, args.case)
    # Nonblocking lock: queue outside heavy.sh via HEAVY_FREE; never take a heavy slot waiting.
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lease_check(lease, commit, args.case)
        if RECEIPT.exists():
            previous = json.loads(RECEIPT.read_text())
            if previous.get('pending'):
                raise ValueError('fixed-previous-recovery-receipt-pending')
        inventory = collect()
        if inventory['isolation']['memory_limit'] != DEVICE_CAP or inventory['root']['memory_max'] != str(DEVICE_CAP):
            raise ValueError('fixed-three-gib-cap-required')
        for row in inventory['owner']['images']:
            identity = row.get('identity') or {}
            if (not row['present'] or identity.get('id', '').removeprefix('sha256:') != ORIGINALS[row['ref']]
                    or identity.get('architecture') != 'amd64' or identity.get('os') != 'linux'):
                raise ValueError('fixed-original-device-image-required')
        if inventory['host_memory_available_mib'] < 2200:
            raise ValueError('fixed-host-memory-headroom-required')
        if DEVICE_CAP - inventory['root']['memory_current'] < 1536 * MIB:
            raise ValueError('fixed-device-memory-headroom-required')
        if not baseline_verify():
            raise ValueError('fixed-original-baseline-verification-failed')
        rc = run_locked(args, lease, commit, facts, inventory)
        if not json.loads(RECEIPT.read_text()).get('pending'):
            nc = load_flow()
            proc = nc.drv.owner('systemctl', '--user', 'stop', 'nextcloud-cron.timer',
                                'nextcloud-cron.service', 'nextcloud.target', *nc.UNITS, timeout=180)
            after = collect()
            if (proc.returncode or any(x.get('ActiveState') != 'inactive' for x in after['owner']['units'].values())
                    or after['owner']['quadlets'] != inventory['owner']['quadlets']
                    or after['root']['catalog_sha256'] != inventory['root']['catalog_sha256']
                    or any(after['owner']['units'][name].get('UnitFileState') !=
                           inventory['owner']['units'][name].get('UnitFileState') for name in INACTIVE_UNITS)):
                raise RuntimeError('fixed-original-inactive-unit-return-failed')
        return rc


def run_locked(args, lease, commit, facts, inventory):
    nc = load_flow()
    d = nc.drv
    secrets = d.Secrets(nc.SECRET_FILES, nc.MARKERS)
    ev = nc.Ev(secrets, area='focus-nextcloud-r6')
    d.STATE.clear()  # Only the NEW R6 receipt; legacy nextcloud_flow.json is untouched.
    d.STATE.update(pending=True, source_commit=commit, case=args.case, created_backups=[],
                   jobs={}, original_baseline_id=BASELINE, upload_id=None, ha_backup_id=None)
    d.save_state()
    nc.FIXTURE, nc.FIXTURE_SHA, nc.SECTION = Path(facts['fixture']), facts['sha256'], dict(facts['section'])
    nonce = nonce_source.token_hex(6)
    nc.DROPIN_REL = nc.DROPIN_DIR_REL + '/zz-focus-nextcloud-r6-' + nonce + '.conf'
    nc.FAIL_MARKER_REL = '.focus-nextcloud-r6-fail-' + nonce
    run_args = SimpleNamespace(run=True, candidate=False, draft_entry=False, facts=facts, secrets=secrets)
    original_wait = d.wait_job
    inflight = set()
    stop = threading.Event()
    tripped = threading.Event()

    def require(label, ok):
        if not ev.check(label, ok):
            raise nc.Failed(label)

    def record_job(job):
        row = d.STATE['jobs'].setdefault(job['id'], {})
        row.update(state=job.get('state'))
        for field in ('backup_id', 'safety_backup_id'):
            value = (job.get('result') or {}).get(field)
            if value and value != BASELINE:
                d.created_backup(value)
        d.save_state()

    # Record the pre-existing jobs so a lost start reply cannot make a writer
    # invisible to recovery. Unexpected running jobs block cleanup, not get cancelled.
    jobs_before = {x['id'] for x in d.ok('jobs', ev=ev).get('jobs') or []}
    require('preflight: no existing job is running', not any(
        x.get('state') in ('queued', 'running') for x in d.ok('jobs', ev=ev).get('jobs') or []))

    def wait(job_id, *, ev, timeout=5400):
        inflight.add(job_id)
        d.STATE['jobs'][job_id] = {'state': 'running'}
        d.save_state()  # Persist BEFORE waiting, including when the wait raises.
        job = original_wait(job_id, ev=ev, timeout=min(timeout, 3600))
        record_job(job)
        inflight.discard(job_id)
        return job

    d.wait_job = wait

    class Run(nc.Run):
        def budget(self, phase, need=0, *, timed=True):
            if timed:
                lease_check(lease, commit, args.case)
                if time.monotonic() - self.lock_started > 100 * 60 or tripped.is_set():
                    raise nc.Failed('fixed-case-budget-reached')
            if nc.host_free() < RESERVE + MARGIN + need:
                raise nc.Failed('fixed-reserve-preflight-refused')

        def setup(self):
            require('setup: installed engine equals committed source',
                    d.device_python(nc.ENGINE_HASHES, as_owner=False) == nc.tree_hashes())
            require('setup: original catalog hash retained',
                    inventory['root']['catalog_sha256'] ==
                    '3a7af03b966f90a172e417a3ea69d7b36bf98a23af8d27b0c074bd01b6f335d6')
            state = self.state()
            require('setup: five units active and Nextcloud healthy',
                    set(state.get('units', {})) == set(nc.UNITS)
                    and all(x == 'active' for x in state['units'].values())
                    and state.get('status', {}).get('installed') is True
                    and state['status'].get('version') == '35.0.1.1'
                    and state['status'].get('maintenance') is False)

        def before_state(self):
            super().before_state()
            sizes = self.before['sizes']
            require('before: fresh live directory sizes available',
                    all(isinstance(sizes.get(k), int) for k in ('html', 'postgres', 'data')))
            bound = acceptance_budget(sizes['html'], sizes['postgres'],
                                      max(sizes['data'], 234187031), 1024**3, 1024**3)
            ev.save('fresh-budget.json', bound)
            self.budget('fullshare admission', bound['additional_peak_bytes'])

        def upload(self):
            self.budget('upload', nc.FIXTURE.stat().st_size + 3 * 1024**3)
            require('upload: original fixture streaming SHA256 matches', nc.sha256_file(nc.FIXTURE) == nc.FIXTURE_SHA)
            begin = d.ok('upload-begin', {'filename': nc.FIXTURE.name, 'size': nc.FIXTURE.stat().st_size}, ev=ev)
            d.STATE['upload_id'] = begin['upload_id']
            d.save_state()
            program = ('import shutil,sys\nwith open(sys.argv[1],"wb") as f:'
                       '\n shutil.copyfileobj(sys.stdin.buffer,f,1<<20)')
            proc = subprocess.Popen([str(d.LP), 'exec', '-i', d.DEVICE, 'python3', '-I', '-c', program, begin['path']],
                                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                with nc.FIXTURE.open('rb') as source:
                    for chunk in iter(lambda: source.read(1 << 20), b''):
                        self.budget('upload stream')
                        proc.stdin.write(chunk)
                proc.stdin.close()
                require('upload: bounded stream completed', proc.wait(timeout=120) == 0)
            finally:
                if not proc.stdin.closed:
                    proc.stdin.close()  # EOF stops the exact upload writer, not unrelated jobs.
                if proc.poll() is None:
                    proc.wait(timeout=120)
            result = d.ok('upload-finish', {'upload_id': begin['upload_id']}, ev=ev, timeout=1800)
            self.created_store = result['ha_backup']['id']
            d.STATE.update(upload_id=None, ha_backup_id=self.created_store)
            d.save_state()

        def check(self):
            job, took = d.run_check(self.created_store, ['nextcloud'], ev=ev, key=secrets['HA_BACKUP_KEY'])
            self.check_id = job['id']
            self.keys = confirmation_keys(job, args.case)
            app = job['result']['ha_check']['apps'][0]
            self.section = app.get('nextcloud') or {}
            require('check: current facts match original full-share source',
                    all(self.section.get(k) == v for k, v in nc.SECTION.items()))
            require('check: original full-share needs no confirmation', self.keys == [])
            ev.time('check', args.case, 'nextcloud', took, job)

        def watch_host(self, stop, tripped):
            # A single whole-case watcher below owns cancellation.
            stop.wait()

        def inject(self, on):
            if on:
                require('rollback: new owned injection paths are absent', all(
                    d.owner('test', '-e', '/home/appowner/' + path, timeout=30).returncode == 1
                    for path in (nc.DROPIN_REL, nc.FAIL_MARKER_REL)))
                self.preexisting_dropin_dir = d.owner('test', '-d', '/home/appowner/' + nc.DROPIN_DIR_REL,
                                                     timeout=30).returncode == 0
                super().inject(True)
            else:
                d.owner('rm', '-f', '/home/appowner/' + nc.DROPIN_REL,
                        '/home/appowner/' + nc.FAIL_MARKER_REL, timeout=60)
                if not getattr(self, 'preexisting_dropin_dir', True):
                    d.owner('rmdir', '/home/appowner/' + nc.DROPIN_DIR_REL, timeout=60)
                d.owner('systemctl', '--user', 'daemon-reload', timeout=120)

        def manual_rollback(self, phase):
            self.restored_back = False
            first = len(ev.results)
            super().manual_rollback(phase)
            self.restored_back = False
            require('recovery: original baseline independently verified', baseline_verify())
            require('recovery: exact pre-import markers restored', self.markers() == self.before['markers'])
            require('recovery: all rollback checks passed', all(x['ok'] for x in ev.results[first:]))
            self.restored_back = True

    r = Run(run_args, ev)

    def convert(ha, apps, test_mode, *, ev, key, tag):
        request = {'ha_backup_id': ha, 'apps': apps, 'test_mode': test_mode, 'confirm': True,
                   'request_id': d.request_id('focus-r6-convert'), 'key': key,
                   'check_job_id': r.check_id, 'acknowledged': {'nextcloud': r.keys}}
        started = time.monotonic()
        reply = d.ok('ha-convert-start', request, ev=ev, timeout=300)
        return wait(reply['job_id'], ev=ev), time.monotonic() - started

    d.convert = convert

    def watchdog():
        while not stop.wait(1):
            if nc.host_free() >= RESERVE + MARGIN:
                continue
            tripped.set()
            # Cancel only this run's recorded jobs; leave other device jobs untouched.
            for job_id in tuple(inflight):
                d.helper('job-cancel', {'job_id': job_id}, timeout=30)
            return

    watcher = threading.Thread(target=watchdog, daemon=True)
    watcher.start()
    safe = False
    try:
        for step in (r.setup, r.before_state, r.upload, r.check, r.import_real,
                     lambda: r.verify('import'), r.restart, r.rollback, r.after_state):
            r.budget('next acceptance step')
            step()
        safe = r.restored_back
    except Exception as error:
        ev.check('case stopped; recovery required', False, type(error).__name__)
    finally:
        try:
            new_jobs = {x['id'] for x in d.ok('jobs', ev=ev).get('jobs') or []} - jobs_before
            require('recovery: every new job has a recorded ID', new_jobs <= set(d.STATE['jobs']))
            # No recovery/cleanup may race a timed-out job. Reconcile exact IDs first.
            for job_id in tuple(inflight):
                d.helper('job-cancel', {'job_id': job_id}, timeout=30)
                job = original_wait(job_id, ev=ev, timeout=900)
                record_job(job)
                inflight.discard(job_id)
            # Adopt a safety ID even if the original wait failed before returning it to Run.
            if not r.safety:
                for job_id in d.STATE['jobs']:
                    job = d.ok('job-status', {'job_id': job_id}, ev=ev)['job']
                    if (job.get('result') or {}).get('safety_backup_id'):
                        r.safety = job['result']['safety_backup_id']
                        break
            if r.safety and not r.restored_back:
                r.manual_rollback('recovery')
            safe = baseline_verify() and (not r.safety or r.restored_back) and not inflight
            require('cleanup gate: original baseline independently verified', safe)
            if r.before:
                r.after_state()
                require('cleanup gate: exact baseline state comparisons passed',
                        all(x['ok'] for x in ev.results if x['check'].startswith('after:')))
            r.cleanup()
            if d.STATE.get('upload_id'):
                d.ok('upload-abort', {'upload_id': d.STATE['upload_id']}, ev=ev)
            r.leaks()
            require('cleanup: all deletion and leak checks passed', all(
                x['ok'] for x in ev.results if x['check'].startswith(('cleanup:', 'leaks:'))))
            d.STATE['pending'] = False
            d.save_state()
        except Exception as error:
            safe = False
            ev.check('recovery copies retained; coordinator must reconcile receipt', False, type(error).__name__)
        stop.set()
        watcher.join(timeout=35)
    ev.save('scope.json', {'source_commit': commit, 'case': args.case, 'baseline_safe': safe,
                          'original_fixture_reused': True, 'image_pulls': 0,
                          'device_memory_cap_bytes': DEVICE_CAP, 'reserve_bytes': RESERVE})
    return 0 if ev.finish() and safe else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', action='store_true')
    p.add_argument('--lease', type=Path)
    p.add_argument('--facts', type=Path, default=FACTS)
    p.add_argument('--case', choices=tuple(CASES), default='fullshare')
    args = p.parse_args()
    if not args.run:
        print(json.dumps({'status': 'offline-preparation-only', 'prepared_case': 'fullshare',
                          'derivative_cases': 'require genuine fixtures and separate review',
                          'requires': ['original five images recovered and stack awake', 'frozen-source installed',
                                       'exact source/device/phase lease', 'heavy.sh', 'whole device mutex'],
                          'baseline_id': BASELINE, 'reserve_bytes': RESERVE, 'device_cap_bytes': DEVICE_CAP,
                          'mutations': 0}, indent=2))
        return 0
    if args.lease is None:
        p.error('--run requires a reviewed --lease')
    return execute(args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, BlockingIOError):
        print('fixed-r6-preflight-refused; no case mutation started', file=sys.stderr)
        sys.exit(2)
