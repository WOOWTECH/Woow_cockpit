"""Item C probe (lane arm54-2, runs as root on .54): why the product's throwaway PostgreSQL cluster of the Omnigent
candidate failed with podman exit 126 under the test owner (owner-omnigent-attempt1), and that the tempctr fix
(a private tmpfs at /run/secrets for a read-only root with mounted secrets) makes the same product call work.

usage (through arm54_final_control.py run): arm54_final_owner_secret_probe.py <workspace>

Every container runs as the test owner (rootless Podman 6.1.1, runc 1.5.1, network none, --rm) with the owner's
existing secret omnigent-postgres-password (made by owner-omnigent-attempt1 from a generated value); only exit codes
and fixed predicates of podman's stderr are reported, never a value."""
import json
import subprocess
import sys
import time

from arm54_final_runtime import ROOT, report
import arm54_final_owner_common as oc

from woowbackup import podman as product_podman, tempctr  # noqa: E402

IMAGE = ('docker.io/library/postgres:16.15-alpine3.24'
         '@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139')
SECRET = 'omnigent-postgres-password,type=mount,target=/run/secrets/postgres-password,mode=0400'
BASE = ['run', '--rm', '--pull=never', '--log-driver', 'none', '--network', 'none', '--security-opt',
        'no-new-privileges', '--pids-limit', '512', '--memory', '512m']
checks, facts = {}, {}
out = {'status': 'failed', 'phase': 'start', 'owner': oc.OWNER, 'commercial_acceptance': 'not-complete',
       'checks': checks, 'facts': facts}
started = time.monotonic()


def must(name, ok, **detail):
    checks[name] = bool(ok)
    if detail:
        facts[name] = detail
    if not ok:
        raise AssertionError(name)


def variant(name, *args):
    p = oc.podman(*BASE, *args, IMAGE, 'true', check=False, timeout=180)
    low = (p.stderr or b'').lower()
    facts[name] = {'exit': p.returncode, 'read_only_fs': b'read-only file system' in low,
                   'mountpoint': b'make mountpoint' in low}
    return p.returncode


try:
    acct = oc.account()
    must('owner_present', acct is not None)
    runtime = oc.podman('info', '--format', '{{.Host.OCIRuntime.Name}} {{.Host.OCIRuntime.Version}}',
                        timeout=60).stdout.decode().split('\n')[0]
    facts['owner_runtime'] = oc.safe_tail(runtime, 120)
    must('secret_exists', oc.podman('secret', 'inspect', 'omnigent-postgres-password', check=False,
                                    stdout=subprocess.DEVNULL).returncode == 0)
    out['phase'] = 'bisect'
    must('plain_runs', variant('plain') == 0)
    must('read_only_alone_runs', variant('read_only', '--read-only') == 0)
    must('secret_alone_runs', variant('secret', '--secret', SECRET) == 0)
    must('read_only_with_secret_fails_126', variant('read_only_secret', '--read-only', '--secret', SECRET) == 126
         and facts['read_only_secret']['read_only_fs'] and facts['read_only_secret']['mountpoint'])
    must('read_only_with_secret_and_secrets_tmpfs_runs',
         variant('read_only_secret_tmpfs', '--read-only', '--tmpfs', tempctr.SECRETS_TMPFS, '--secret', SECRET) == 0)
    out['phase'] = 'product-call'
    # The product's own argv builder and OwnerRunner, as ha_omnigent builds its new cluster (read-only root + the
    # target's Quadlet secret), one-shot (--rm) with `true` instead of the server.
    runner = product_podman.OwnerRunner(oc.OWNER)
    tmp = tempctr.TempObjects(runner, 'j20261123T130000Z-a54b0b01', memory='512m', pids=512)
    argv = tmp.run_argv('probe', IMAGE, ['true'], remove=True, read_only_root=True, secrets=[SECRET])
    must('product_argv_has_secrets_tmpfs', argv[argv.index('--tmpfs') + 1] == tempctr.SECRETS_TMPFS)
    result = runner.podman(*argv, check=False, timeout=180)
    must('product_read_only_secret_call_runs', result.returncode == 0, exit=result.returncode)
    left = oc.podman('ps', '-a', '--format', '{{.Names}}').stdout.decode().split()
    must('no_probe_container_left', not any('a54b0b01' in n for n in left))
    out['status'] = 'passed'
    out['phase'] = 'done'
except Exception as error:  # noqa: BLE001
    out['error'] = type(error).__name__
    out['error_detail'] = oc.safe_tail(str(error), 300)
finally:
    out['elapsed_seconds'] = round(time.monotonic() - started, 1)
    out['failed_check'] = next((k for k, v in checks.items() if not v), None)
    report(ROOT / 'owner-secret-probe-result.json', out)
    print(json.dumps(out, sort_keys=True))
sys.exit(0 if out['status'] == 'passed' else 1)
