#!/usr/bin/env python3
"""R3 D10: real HA code-server restore pauses consumers of an existing folder.

Default is an offline syntax check. Run only under an explicit coordinator dev-e
lease, heavy.sh and this script's /tmp/woowbk-dev-e-mutation.lock. No image pull,
package installation, networking change or public listener is made here.

The original encrypted HA fixture is converted through the installed helper.
Two temporary Quadlet services mount the existing Desktop and whole home. An
unacknowledged restore must refuse without a job; the confirmed restore must
stop/start both services and retain the exact Desktop contents. Consumers are
removed before ordinary safety rollback. Recovery copies survive any uncertainty.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
IMAGE = '7999790230ec6267ae55b82ab0e8d725add734658d15a8ec7a139a6d4087b0a1'
APP = 'woow-code-server'
BUDGET = 20 * 60


def base():
    spec = importlib.util.spec_from_file_location('focus_d10_base', HERE / 'codeserver_full_flow.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.drv.state_path = lambda: mod.LAB / 'run/focus_acceptance_d10.json'
    # The lease requires the larger reserve and host RAM floor for this case.
    mod.FLOOR = 13 * 1024 ** 3
    mod.MIN_HOST_AVAILABLE_KIB = 1200 * 1024
    return mod


def pause_keys(preflight, names):
    """Only the two reviewed consumers may be confirmed; extra findings stop us."""
    apps = preflight.get('apps') or []
    if preflight.get('ok') is not True or len(apps) != 1 or apps[0].get('id') != APP:
        raise ValueError('restore preflight is not ready')
    issues = apps[0].get('issues') or []
    if any(x.get('level') == 'stop' for x in issues):
        raise ValueError('restore has a stop issue')
    confirms = [x for x in issues if x.get('level') == 'confirm']
    if len(confirms) != 1 or confirms[0].get('id') != 'restore.pauses':
        raise ValueError('unexpected confirmation scope')
    issue = confirms[0]
    if sorted(issue.get('items') or []) != sorted(names) or issue.get('more', 0):
        raise ValueError('unexpected consumer names')
    if not re.fullmatch(r'restore\.pauses:[0-9a-f]{16}', issue.get('key', '')):
        raise ValueError('invalid confirmation key')
    return [issue['key']]


def consumer_unit(name, whole_home):
    if not re.fullmatch(r'woowbk-focus-d10-[0-9a-f]{12}-(home|desktop)', name):
        raise ValueError('invalid case resource name')
    source = '%h' if whole_home else '%h/Desktop'
    marker = '/watched/Desktop/woowbk-lab-baseline.txt' if whole_home else '/watched/woowbk-lab-baseline.txt'
    return ('[Unit]\nDescription=Temporary R3 D10 consumer\n[Container]\n'
            f'Image=sha256:{IMAGE}\nContainerName={name}\nNetwork=none\n'
            f'Volume={source}:/watched:rw\nUser=0\nReadOnly=true\nEntrypoint=/bin/sh\n'
            'PodmanArgs=--pull=never --cap-drop=all --security-opt=no-new-privileges --pids-limit=16 --memory=64m\n'
            f'Exec=-c "sha256sum {marker}; exec sleep infinity"\n'
            '[Service]\nTimeoutStartSec=60\nTimeoutStopSec=30\n')


FOLDER = r'''
import hashlib,json,os,stat
from pathlib import Path
p=Path.home()/'Desktop'
assert p.is_dir() and not p.is_symlink()
rows=[];total=0
for d,dirs,files in os.walk(p,followlinks=False):
    for n in sorted(dirs+files):
        f=Path(d)/n;s=f.lstat();rel=str(f.relative_to(p))
        mode=stat.S_IMODE(s.st_mode)
        if stat.S_ISREG(s.st_mode):
            total+=s.st_size
            assert total<=64*1024*1024 and len(rows)<2000
            h=hashlib.sha256()
            with f.open('rb') as inp:
                for chunk in iter(lambda:inp.read(1<<20),b''):h.update(chunk)
            payload=h.hexdigest()
        elif stat.S_ISLNK(s.st_mode):payload=os.readlink(f)
        elif stat.S_ISDIR(s.st_mode):payload=None
        else:raise ValueError('unexpected baseline file type')
        rows.append([rel,stat.S_IFMT(s.st_mode),mode,s.st_uid,s.st_gid,s.st_size if stat.S_ISREG(s.st_mode) else 0,payload])
assert any(x[0]=='woowbk-lab-baseline.txt' for x in rows)
print(json.dumps({'rows':sorted(rows),'bytes':total,'inode':p.stat().st_ino}))
'''

JOURNAL = r'''
import json,subprocess,sys
q=json.load(sys.stdin)
p=subprocess.run(['journalctl','--user','-u',q['unit'],'--since','@'+str(q['since']),
                  '-o','json','--no-pager'],capture_output=True,timeout=30,check=True)
events=[]
for line in p.stdout.splitlines():
    x=json.loads(line)
    kind={'9d1aaa27d60140bd96365438aad20286':'stopped',
          '39f53479d3a045ac8e11786248231fbf':'started'}.get(x.get('MESSAGE_ID'))
    if kind:events.append([int(x['__REALTIME_TIMESTAMP']),kind])
print(json.dumps({'events':events}))
'''


def ordered_restart(events):
    stopped = None
    for stamp, kind in sorted(events):
        if kind == 'stopped':
            stopped = stamp
        elif kind == 'started' and stopped is not None and stamp > stopped:
            return True
    return False


def run():
    cs = base()
    d = cs.drv
    if cs.isolation() != 'true none {}' or not cs.clean_tree():
        raise cs.Failed('isolated device and committed source required')
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise cs.Failed('dev-e is leased to another mutation phase') from None
    started = time.monotonic()
    tag = 'woowbk-focus-d10-' + secrets.token_hex(6)
    names = [tag + '-desktop', tag + '-home']
    args = SimpleNamespace(secrets=d.Secrets([d.SECRET_DIR / 'b1-creds.env', d.SECRET_DIR / 'ha-import-creds.env'],
                                           d.SECRET_DIR / 'dev-d-markers.json'), test_login='')
    ev = cs.Ev(args.secrets, area='focus-acceptance-d10')
    d.load_state()
    if d.STATE.get('created_backups'):
        os.close(fd)
        raise cs.Failed('previous D10 recovery backups remain; coordinator recovery required')
    d.STATE.clear()
    d.STATE['created_backups'] = []
    d.STATE['run_started'] = int(time.time()) - 1
    r = cs.Run(args, ev)
    owned = []
    inflight = None
    safe = False
    before = None
    original_unit = cs.unit_state()
    summary = {'source_commit': subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(),
               'case': 'R3-D10-code-server', 'device': d.DEVICE,
               'fixture_kind': 'original-encrypted-real-ha', 'commercial_acceptance': 'not-complete'}

    def check(label, ok):
        if not ev.check(label, ok):
            raise cs.Failed(label)

    def budget():
        if time.monotonic() - started > BUDGET:
            raise cs.Failed('case budget reached; recover baseline')
        r.headroom()

    def owner(*argv, input=None):
        p = d.owner(*argv, input=input, timeout=120)
        if p.returncode:
            raise cs.Failed('case owner command failed; output withheld')
        return d.out(p).strip()

    def folder():
        return json.loads(owner('python3', '-I', '-c', FOLDER))

    def invocation(name):
        return owner('systemctl', '--user', 'show', '-P', 'InvocationID', name + '.service')

    def receipt():
        ev.save('recovery.json', {'device': d.DEVICE, 'consumers': owned, 'inflight': inflight,
                                 'safety_backup': r.safety, 'converted_backup': r.converted,
                                 'created_upload': r.created_store, 'original_service': original_unit,
                                 'original_timer': r.timer_found, 'baseline_restored': safe})

    original_wait = d.wait_job

    def bounded_wait(job_id, *, ev, timeout=600):
        nonlocal inflight
        inflight = job_id
        receipt()
        remaining = max(1, int(BUDGET - (time.monotonic() - started)))
        job = original_wait(job_id, ev=ev, timeout=min(timeout, 600, remaining))
        inflight = None
        d.created_backup((job.get('result') or {}).get('backup_id'))
        receipt()
        return job

    d.wait_job = bounded_wait  # bound the reused source check/conversion, not product behavior

    def restore(backup, keys=None):
        nonlocal inflight
        req = {'backup_id': backup, 'apps': [APP], 'confirm': True, 'request_id': d.request_id('focus-d10')}
        if keys is not None:
            req['acknowledged'] = {APP: keys}
        restore_since = int(time.time()) - 1
        reply = d.ok('restore-start', req, ev=ev, timeout=300)
        inflight = reply['job_id']
        receipt()
        stopped = set()
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            reply = d.ok('job-status', {'job_id': inflight}, ev=ev, timeout=60)
            job = reply['job']
            if keys is not None:
                for name in names:
                    if cs.unit_state(name + '.service') == 'inactive':
                        stopped.add(name)
            if job['state'] not in ('queued', 'running'):
                break
            time.sleep(2)
        else:
            raise cs.Failed('restore still running; retain recovery artifacts')
        inflight = None
        result = job.get('result') or {}
        if backup == r.converted and result.get('safety_backup_id'):
            r.safety = result['safety_backup_id']
        d.created_backup(result.get('safety_backup_id'))
        receipt()
        if keys is not None:
            # A short pause can fall between samples. Ordered service-manager
            # journal events provide independent evidence of that real cycle.
            for name in names:
                p = d.owner('python3', '-I', '-c', JOURNAL,
                            input=json.dumps({'unit': name + '.service', 'since': restore_since}).encode(), timeout=60)
                events = json.loads(d.out(p))['events'] if p.returncode == 0 else []
                ev.save(name + '-cycle.json', {'events': events, 'sampled_inactive': name in stopped})
                check('D10: service pause and restart observed by sampling or ordered journal',
                      name in stopped or ordered_restart(events))
        return job

    try:
        check('setup: no previous private code-server needle directory exists',
              d.root('test', '-e', os.path.dirname(cs.NEEDLES), timeout=30).returncode == 1)
        check('setup: code-server is already active after independent baseline verification', original_unit == 'active')
        actual = owner('podman', 'container', 'inspect', '--format', '{{.Image}}', 'code-server')
        check('setup: running code-server has the exact reviewed image config', actual.removeprefix('sha256:') == IMAGE)
        budget()
        r.setup()  # existing guarded source deployment, hash check and timer preservation
        check('setup: all installed source and catalog checks passed', all(x['ok'] for x in ev.results))
        before = folder()
        ev.save('folder-before.json', before)
        check('baseline: existing Desktop baseline marker and bounded files present', bool(before['rows']))
        # Record the pre-existing baseline separately; this is not a seeded generated folder.
        r.step_upload()
        r.step_check()
        check('check: original encrypted HA fixture passes every required source check', all(x['ok'] for x in ev.results))
        budget()
        job, _ = d.convert(r.store_id, [APP], False, ev=ev, key=args.secrets['HA_BACKUP_KEY'], tag='focus-d10-convert')
        r.converted = (job.get('result') or {}).get('backup_id')
        d.created_backup(r.converted)
        meta = next((x for x in d.ok('list', ev=ev)['backups'] if x['id'] == r.converted), {})
        check('convert: real original HA produced an encrypted converted backup',
              job['state'] == 'succeeded' and bool(r.converted) and bool(meta.get('key_id'))
              and (meta.get('from_ha') or {}).get('ha_backup_id') == r.store_id)
        receipt()
        for i, name in enumerate(names):
            rel = '.config/containers/systemd/' + name + '.container'
            check('consumer: unique case unit does not already exist', not cs.owner_exists(rel))
            owned.append(name)  # record before writing so partial setup is recoverable
            receipt()
            cs.write_owner_file(rel, consumer_unit(name, bool(i)).encode())
        owner('systemctl', '--user', 'daemon-reload')
        owner('systemctl', '--user', 'start', *[n + '.service' for n in names])
        ids = {n: invocation(n) for n in names}
        check('consumer: both isolated mount consumers started', all(ids.values()))
        inspected = d.ok('inspect', {'backup_id': r.converted}, ev=ev, timeout=300)
        keys = pause_keys(inspected.get('preflight') or {}, names)
        check('D10: preflight names exactly Desktop and whole-home consumers', bool(keys))
        refused_rc, refused = d.helper('restore-start', {'backup_id': r.converted, 'apps': [APP], 'confirm': True,
                                                       'request_id': d.request_id('focus-d10-unconfirmed')})
        check('D10: without acknowledgement no restore job starts', refused_rc != 0 and not refused.get('job_id')
              and (refused.get('error') or {}).get('code') == 'confirmation-required')
        check('D10: refusal did not restart either consumer or replace Desktop',
              all(invocation(n) == ids[n] for n in names) and folder() == before)
        budget()
        job = restore(r.converted, keys)
        ev.save('confirmed-restore.json', job)
        check('D10: confirmed real restore succeeds with a safety backup', job['state'] == 'succeeded' and bool(r.safety))
        # Capture moved HA values while they are installed; after safety rollback
        # they are absent from the live app and cannot seed a complete leak scan.
        r.collect_needles()
        after = folder()
        check('D10: existing folder contents modes and owners preserved exactly', after['rows'] == before['rows'])
        check('D10: restore replaced the existing folder', after['inode'] != before['inode'])
        for i, name in enumerate(names):
            path = '/watched/Desktop/woowbk-lab-baseline.txt' if i else '/watched/woowbk-lab-baseline.txt'
            check('D10: consumer restarted automatically after folder replacement',
                  bool(invocation(name)) and invocation(name) != ids[name]
                  and cs.unit_state(name + '.service') == 'active')
            digest = owner('podman', 'exec', name, 'sha256sum', path).split()[0]
            expected = next(x[-1] for x in before['rows'] if x[0] == 'woowbk-lab-baseline.txt')
            check('D10: restarted consumer sees retained baseline through its new mount', digest == expected)
    except Exception as error:
        ev.check('D10: case completed', False, type(error).__name__)
    finally:
        try:
            if inflight:
                # Never race a job or discard its recovery artifacts.
                job = original_wait(inflight, ev=ev, timeout=600)
                inflight = None
                r.safety = r.safety or (job.get('result') or {}).get('safety_backup_id')
                d.created_backup(r.safety)
                if not r.converted:
                    r.converted = (job.get('result') or {}).get('backup_id')
                    d.created_backup(r.converted)
            for name in owned:
                owner('systemctl', '--user', 'stop', name + '.service')
                owner('rm', '-f', '/home/appowner/.config/containers/systemd/' + name + '.container')
            owner('systemctl', '--user', 'daemon-reload')
            check('cleanup: both temporary consumer containers removed',
                  all(d.owner('podman', 'container', 'exists', n, timeout=30).returncode == 1 for n in owned))
            if r.safety:
                restored = restore(r.safety)
                check('recovery: ordinary safety restore succeeded', restored['state'] == 'succeeded')
            safe = before is not None and folder()['rows'] == before['rows'] and cs.unit_state() == original_unit
            check('recovery: exact existing Desktop and original code-server service returned', safe)
            # This independent verifier checks the saved original baseline, real login,
            # device key, health and marker hashes. Never make a new baseline here.
            p = d.run([sys.executable, '-B', '-I', str(HERE / 'batch2_baseline.py'), '--verify', 'code-server'], timeout=300)
            ev.save('independent-baseline.log', d.out(p) + p.stderr.decode('utf-8', 'replace'))
            safe = safe and p.returncode == 0
            check('recovery: independent original baseline verification passes', safe)
            if not r.needles:
                r.collect_needles()
            r.step_leaks()
            check('recovery: secret scan completed without a failing check', all(x['ok'] for x in ev.results if x['check'].startswith('leaks:')))
            if safe:
                r.step_cleanup()  # deletes only this run's backups/upload after verified recovery
            else:
                ev.check('recovery: copies retained for coordinator', False)
        except Exception as error:
            safe = False
            ev.check('recovery: copies retained after uncertainty', False, type(error).__name__)
        finally:
            receipt()
            ev.check('after: outer network isolation preserved', cs.isolation() == 'true none {}')
            summary.update({'passed': sum(x['ok'] for x in ev.results), 'failed': sum(not x['ok'] for x in ev.results),
                            'baseline_restored': safe, 'elapsed_seconds': round(time.monotonic() - started, 1),
                            'fixed_status': [('PASS ' if x['ok'] else 'FAIL ') + x['check'] for x in ev.results]})
            ev.save('summary.json', summary)
            good = ev.finish()
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    print('R3 D10:', str(summary['passed']) + '/' + str(len(ev.results)), 'PASS' if good and safe else 'FAIL')
    return 0 if good and safe else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args(argv)
    if not args.run:
        compile(FOLDER, '<bounded existing folder snapshot>', 'exec')
        compile(JOURNAL, '<fixed service journal events>', 'exec')
        for i, suffix in enumerate(('desktop', 'home')):
            consumer_unit('woowbk-focus-d10-0123456789ab-' + suffix, bool(i))
        print('offline syntax check: PASS; no device or credentials accessed')
        return 0
    return run()


if __name__ == '__main__':
    sys.exit(main())
