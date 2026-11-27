"""Item C (lane arm54-2), between two engine attempts on .54 (runs as root): put the test owner's Headscale back to
its pre-import state through the PRODUCT (restore-start of the failed attempt's own safety backup, run-job with the
production OwnerRunner), check that state, and move that attempt's engine directory aside (kept in the 0700
workspace, removed with it) so the next attempt starts with a fresh engine exactly like the first one.

usage (through arm54_final_control.py run): arm54_final_owner_reset.py <workspace> headscale <safety backup id>

Nothing here prints a secret value; the result is fixed status keys and facts only."""
import io
import json
import os
import shutil
import subprocess
import sys
import time
import uuid

from arm54_final_runtime import ROOT, report
import arm54_final_owner_common as oc

from woowbackup import cli  # noqa: E402
from woowbackup.paths import Paths  # noqa: E402

APP = sys.argv[2] if len(sys.argv) > 2 else ''
SAFETY = sys.argv[3] if len(sys.argv) > 3 else ''
assert APP == 'headscale' and SAFETY, 'usage-refused'
PATHS = Paths(base=ROOT / 'engine')
RUNNER = '''import sys
sys.path.insert(0, %r)
from woowbackup import cli
from woowbackup.paths import Paths
sys.exit(cli.main(['run-job', sys.argv[1]], paths=Paths(base=%r)))
''' % (str(ROOT / 'source/backup-engine'), str(ROOT / 'engine'))
API_PROBE = r'''import json, sys, urllib.request, urllib.error
key = sys.stdin.read().strip()
req = urllib.request.Request('http://127.0.0.1:28080/api/v1/user', headers={'Authorization': 'Bearer ' + key})
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = json.loads(resp.read())
        print(json.dumps({'status': resp.status, 'users': sorted(u.get('name') for u in body.get('users', []))}))
except urllib.error.HTTPError as e:
    print(json.dumps({'status': e.code}))
'''

checks, facts = {}, {}
out = {'status': 'failed', 'phase': 'start', 'app': APP, 'owner': oc.OWNER, 'commercial_acceptance': 'not-complete',
       'checks': checks, 'facts': facts}
started = time.monotonic()
launched = []


def must(name, ok, **detail):
    checks[name] = bool(ok)
    if detail:
        facts[name] = detail
    if not ok:
        raise AssertionError(name)


def call(command, request=None):
    buf = io.StringIO()
    svc = cli.Services(PATHS, launcher=launched.append, unit_active=lambda unit: False)
    code = cli.main([command], stdin=io.StringIO(json.dumps(request or {})), stdout=buf, services=svc)
    reply = json.loads(buf.getvalue().strip().splitlines()[-1])
    if code != 0 or not reply.get('ok'):
        err = reply.get('error') or {}
        facts['cli_refusal'] = {'command': command, 'code': err.get('code'),
                                'message': oc.LONG_TOKEN.sub('<masked>', str(err.get('message')))[:300]}
        raise RuntimeError('cli-refused')
    return reply


def server_view():
    def cli_json(*args):
        return json.loads(oc.podman('exec', 'headscale', 'headscale', *args, '-o', 'json', timeout=60).stdout or b'null')
    return sorted(u.get('name') for u in cli_json('users', 'list') or []), len(cli_json('nodes', 'list') or [])


try:
    acct = oc.account()
    must('owner_present', acct is not None)
    pid = oc.manager_pid(acct.pw_uid)
    host_mnt, host_net = os.stat('/proc/1/ns/mnt').st_ino, oc.netns_inode(1)
    facts['engine_tools'] = oc.enter_tools_namespace(ROOT)
    oc.join_netns(pid)
    must('engine_in_private_mount_and_owner_netns', os.stat('/proc/self/ns/mnt').st_ino != host_mnt
         and oc.netns_inode(os.getpid()) == oc.netns_inode(pid) != host_net)
    listing = call('list')
    ids = [b.get('id') for b in listing.get('backups') or []]
    must('safety_backup_listed', SAFETY in ids, backups=len(ids))
    users, nodes = server_view()
    facts['before'] = {'users': len(users), 'nodes': nodes, 'target_only': users == ['target-only'] and not nodes}

    out['phase'] = 'product-rollback'
    reply = call('restore-start', {'backup_id': SAFETY, 'apps': [APP], 'confirm': True,
                                   'request_id': 'a54r-%s' % uuid.uuid4().hex[:12]})
    job_id = reply['job_id']
    must('launched_once', launched == [job_id])
    t0 = time.monotonic()
    proc = subprocess.run(['/usr/bin/python3', '-I', '-c', RUNNER, job_id], capture_output=True, timeout=1800,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    status = call('job-status', {'job_id': job_id})
    job = status['job']
    result = job.get('result') or {}
    facts['job'] = {'state': job.get('state'), 'run_job_exit': proc.returncode, 'seconds': round(time.monotonic() - t0, 1),
                    'error': (job.get('error') or {}).get('code'), 'changed': result.get('changed'),
                    'rolled_back': result.get('rolled_back'),
                    'health': [(c.get('id'), c.get('status')) for c in result.get('health') or []],
                    'verification': [(e.get('app'), e.get('match')) for e in result.get('verification') or []]}
    must('rollback_job_succeeded', job.get('state') == 'succeeded' and result.get('changed') is True
         and result.get('rolled_back') is False and all(c.get('status') == 'ok' for c in result.get('health') or []))

    out['phase'] = 'target-state'
    users, nodes = server_view()
    must('target_state_back', users == ['target-only'] and nodes == 0, users=len(users), nodes=nodes)
    probe = subprocess.run(['python3', '-I', '-c', API_PROBE], input=(ROOT / 'owner-state/target-api-key').read_bytes(),
                           capture_output=True, timeout=30)
    api = json.loads(probe.stdout.decode().strip().splitlines()[-1])
    must('target_api_key_works', api.get('status') == 200 and api.get('users') == ['target-only'])
    temp = oc.podman('ps', '-a', '--format', '{{.Names}}').stdout.decode().split()
    must('no_throwaway_containers_left', all(not n.startswith('woowbk-') for n in temp), containers=temp)

    out['phase'] = 'engine-aside'
    n = 1
    while (ROOT / ('engine-before-reset-%d' % n)).exists():
        n += 1
    os.rename(ROOT / 'engine', ROOT / ('engine-before-reset-%d' % n))
    facts['engine_moved_to'] = 'engine-before-reset-%d' % n
    must('engine_dir_free_for_next_attempt', not (ROOT / 'engine').exists())
    out['status'] = 'passed'
    out['phase'] = 'done'
except Exception as error:  # noqa: BLE001
    out['error'] = type(error).__name__
    out['error_detail'] = oc.safe_tail(str(error), 400)
finally:
    out['elapsed_seconds'] = round(time.monotonic() - started, 1)
    out['failed_check'] = next((k for k, v in checks.items() if not v), None)
    report(ROOT / 'owner-reset-result.json', out)
    print(json.dumps(out, sort_keys=True))
sys.exit(0 if out['status'] == 'passed' else 1)
