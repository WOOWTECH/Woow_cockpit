"""Lane arm54-2 iteration 3: does an INTERNAL Podman network still work on .54 after the 2026-11-23 21:02 kernel
oops (incident-54-kernel-oops-nft-masq), without touching what the oops left locked?

The oops (`modprobe -r nft_masq`) died in nf_conntrack_helper_unregister+0x28 (a write through a NULL hlist pprev,
right after the call that takes the conntrack helper mutex), called from nf_nat_masquerade_inet_unregister_notifiers:
until a reboot that helper mutex (and most likely the masquerade notifier mutex) stays locked and nft_masq stays
'going'. An internal network needs neither (no masquerade rule, no conntrack helper) and rtnl is free
(incident-54-followup-2120-2: the rtnl_trylock sysfs read answered in 8 ms). This probe shows it on the device before
any run that creates one: in a network namespace of its own (like arm54_final_n8n.py; .54's namespace never sees the
bridge), it creates ONE internal network in the private store, runs one throwaway container on it (the PostgreSQL
image of the n8n build, --pull=never; it only prints its own /proc/net/dev and /proc/net/route), removes both and
compares the kernel state before and after. No masquerade network, no published port, no module unload."""
import ctypes
import json
import os
import subprocess
import time

from arm54_final_runtime import DRIVER, LABEL, ROOT, Runner, kernel_state, report, store_objects

CLONE_NEWNET = 0x40000000
LIBC = ctypes.CDLL(None, use_errno=True)
NET = 'woow-arm54-netprobe'
IMAGE = 'docker.io/library/postgres:16.15-alpine'   # tagged by arm54_final_n8n_build.py (pinned index digest)

out = {'status': 'failed', 'phase': 'start', 'store_driver': DRIVER, 'commercial_acceptance': 'not-complete',
       'scope': 'internal Podman network in a private network namespace (rootful private store); no masquerade'}
checks = out['checks'] = {}
started = time.monotonic()
host_inode = os.stat('/proc/self/ns/net').st_ino
r = Runner()
created = False
try:
    out['kernel_before'] = before = kernel_state()
    if LIBC.unshare(CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), 'unshare')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, timeout=30, capture_output=True)
    checks['private_netns'] = os.stat('/proc/self/ns/net').st_ino != host_inode
    out['phase'] = 'network'
    r.podman('network', 'create', '--internal', '--label', LABEL, NET, timeout=120)
    created = True
    info = json.loads(r.podman('network', 'inspect', NET).stdout)[0]
    checks['network_internal'] = info.get('internal') is True
    out['facts'] = {'network_driver': info.get('driver'), 'subnets': len(info.get('subnets') or [])}
    out['phase'] = 'container'
    t0 = time.monotonic()
    text = r.podman('run', '--rm', '--pull=never', '--network', NET, '--label', LABEL, '--entrypoint', 'sh', IMAGE,
                    '-c', 'cat /proc/net/dev; echo ROUTES; cat /proc/net/route', timeout=180).stdout.decode()
    out['facts']['container_seconds'] = round(time.monotonic() - t0, 1)
    devices, routes = text.split('ROUTES', 1)
    names = sorted(line.split(':', 1)[0].strip() for line in devices.splitlines() if ':' in line)
    out['facts']['container_devices'] = names
    checks['container_has_eth0'] = 'eth0' in names
    checks['container_has_no_default_route'] = not any(
        len(line.split()) > 2 and line.split()[1] == '00000000' for line in routes.splitlines()[2:])
    out['phase'] = 'remove'
    r.podman('network', 'rm', NET, timeout=120)
    created = False
    checks['network_removed'] = r.podman('network', 'exists', NET, check=False).returncode != 0
    objects = store_objects(r)
    checks['no_lab_container_left'] = not objects['containers']
    out['kernel_after'] = after = kernel_state()
    checks['no_new_d_state_task'] = after['d_state'] <= before['d_state']
    checks['no_new_hung_task_report'] = after['hung_task_reports'] == before['hung_task_reports']
    checks['no_new_oops'] = after['oops_count'] == before['oops_count']
    checks['nft_masq_unchanged'] = after['nft_masq'] == before['nft_masq']
    checks['taint_unchanged'] = after['tainted'] == before['tainted']
    out['modules_loaded_by_probe'] = sorted(set(after['modules']) - set(before['modules']))
    for state in (before, after):
        state['modules'] = len(state['modules'])
    out['status'] = 'passed' if all(checks.values()) else 'failed'
    out['phase'] = 'done'
except Exception as error:  # the failure class and phase only; no command output is exported
    out['error'] = type(error).__name__
finally:
    if created:
        r.podman('network', 'rm', '--force', NET, check=False, timeout=120)
    out['elapsed_seconds'] = round(time.monotonic() - started, 1)
    report(ROOT / 'netprobe-result.json', out)
    print(json.dumps(out, sort_keys=True))
raise SystemExit(0 if out['status'] == 'passed' else 1)
