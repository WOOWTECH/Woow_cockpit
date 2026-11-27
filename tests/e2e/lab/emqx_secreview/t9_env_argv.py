"""T9 (SR-8): do the device's EnvironmentFile= values reach a process command line when the product starts the
candidate?  Real run in the lab store (labpodman, --network none), product code from SECREV_ROOT/<codebase>.

The value is a generated canary (never printed; only digests/booleans/counts are recorded). A sampler reads every
/proc/<pid>/cmdline while (a) the product's Target.candidate_env() + TempObjects.run('emqx-new', ...) start the
candidate exactly as target_broker does, and (b) the device's own way (`podman run --env-file`) starts a control.
"""
import json
import os
import secrets
import sys
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L  # noqa: E402

CODEBASE = sys.argv[1] if len(sys.argv) > 1 else 'tip'
OUT = os.path.join(L.SR, 'runs', f't9-{CODEBASE}.json')


class Sampler(threading.Thread):
    def __init__(self, needle, marker=b''):
        super().__init__(daemon=True)
        self.needle, self.stop, self.hits, self.samples = needle, threading.Event(), {}, 0
        self.marker, self.seen_run = marker, set()

    def run(self):
        while not self.stop.is_set():
            self.samples += 1
            for pid in os.listdir('/proc'):
                if not pid.isdigit():
                    continue
                try:
                    with open(f'/proc/{pid}/cmdline', 'rb') as handle:
                        data = handle.read()
                    if self.marker and self.marker in data and data.split(b'\0')[1:2] in ([b'run'], [b'--root']):
                        self.seen_run.add(pid)
                    if self.needle not in data:
                        continue
                    with open(f'/proc/{pid}/comm') as handle:
                        comm = handle.read().strip()
                    mode = oct(os.stat(f'/proc/{pid}/cmdline').st_mode & 0o777)
                    self.hits.setdefault(pid, {'comm': comm, 'cmdline_mode': mode})
                except OSError:
                    continue


class OwnerFiles:
    """The FILE_HELPER read the product's Target uses (rel path below the owner's home), on a scratch home."""

    def __init__(self, home):
        self.home = home

    def read_file(self, rel, max_bytes):
        fd = os.open(os.path.join(self.home, rel), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as handle:
            return handle.read(max_bytes)


def sample_during(needle, action, settle=2.0, marker=b''):
    sampler = Sampler(needle, marker)
    sampler.start()
    time.sleep(0.2)
    try:
        result = action()
        time.sleep(settle)
    finally:
        sampler.stop.set()
        sampler.join()
    return result, sampler


def main():
    ha_emqx = L.use(CODEBASE)
    canary = 'cnry' + secrets.token_hex(16)
    needle = canary.encode()
    home = os.path.join(L.SR, 'runs', 't9-home')
    os.makedirs(home, mode=0o700, exist_ok=True)
    env_path = os.path.join(home, 'emqx.env')
    with open(env_path, 'w') as handle:
        handle.write(f'# device env file\nEMQX_LOG__CONSOLE__LEVEL=warning\nEMQX_DASHBOARD__DEFAULT_PASSWORD={canary}\n')
    os.chmod(env_path, 0o600)
    record = {'test': 'T9 EnvironmentFile values on the candidate command line (SR-8)', 'codebase': CODEBASE,
              'canary_sha256': L.digest(canary), 'env_file_mode': '0600'}

    # (a) the product's way
    target = ha_emqx.Target.__new__(ha_emqx.Target)
    target.env = {'EMQX_NODE__NAME': 'emqx@127.0.0.1'}
    target.env_files = ['%h/emqx.env']
    target._runner = OwnerFiles(home)
    target.home = home
    target.image, target.secrets, target.files = L.IMAGE, [], []
    runner = L.make_runner()
    tmp = L.temp(runner, memory='768m')
    try:
        candidate = ha_emqx.Target.candidate_env(target)
        record['candidate_env_has_key'] = 'EMQX_DASHBOARD__DEFAULT_PASSWORD' in candidate
        files = getattr(target, 'candidate_env_files', None)
        tmp.volume('emqx-new')
        tmp.volume('emqx-new-log')
        kwargs = {}
        if isinstance(candidate, tuple):   # a fixed product may return (env, env files)
            candidate, kwargs['env_files'] = candidate
        def start():
            return tmp.run('emqx-new', L.IMAGE, [], detach=True, read_only_root=True, env=candidate, secrets=[],
                           volumes=[(tmp.name('emqx-new'), ha_emqx.DATA_TARGET, None),
                                    (tmp.name('emqx-new-log'), ha_emqx.LOG_TARGET, None)], **kwargs)
        _r, sampler = sample_during(needle, start, marker=tmp.name('emqx-new').encode())
        inside = tmp.exec('emqx-new', ['printenv', 'EMQX_DASHBOARD__DEFAULT_PASSWORD'], check=False, timeout=60)
        record['product'] = {'samples': sampler.samples, 'podman_run_cmdlines_seen': len(sampler.seen_run), 'processes_with_value_in_cmdline': len(sampler.hits),
                             'process_names': sorted({h['comm'] for h in sampler.hits.values()}),
                             'cmdline_modes': sorted({h['cmdline_mode'] for h in sampler.hits.values()}),
                             'container_got_value': (inside.stdout or b'').strip() == needle}
        del files
    finally:
        left = tmp.cleanup()
        record['product_cleanup_left'] = len(left)

    # (b) the device's way (Quadlet EnvironmentFile= -> podman --env-file), tmpfs on both image VOLUME paths
    name = 'woowbk-secrev-t9-control'
    def control():
        return L.lab('run', '-d', '--name', name, '--label', L.LABEL, '--network', 'none', '--pull=never',
                     '--memory', '768m', '--env-file', env_path, '--tmpfs', '/opt/emqx/data', '--tmpfs',
                     '/opt/emqx/log', L.IMAGE)
    try:
        _r, sampler = sample_during(needle, control, marker=name.encode())
        inside = L.lab('exec', name, 'printenv', 'EMQX_DASHBOARD__DEFAULT_PASSWORD', check=False)
        record['device_way'] = {'samples': sampler.samples, 'podman_run_cmdlines_seen': len(sampler.seen_run), 'processes_with_value_in_cmdline': len(sampler.hits),
                                'container_got_value': (inside.stdout or b'').strip() == needle}
    finally:
        L.lab('rm', '-f', '-t', '0', name, check=False)
    record['proc_hidepid'] = any('hidepid' in line for line in open('/proc/mounts') if line.startswith('proc '))
    dangling = L.lab('volume', 'ls', '--filter', 'dangling=true', '--format', '{{.Name}}').stdout.split()
    record['dangling_volumes_after'] = len(dangling)
    record['result'] = ('EXPOSED' if record['product']['processes_with_value_in_cmdline'] else 'NOT-EXPOSED')
    os.unlink(env_path)
    L.evidence(OUT, record)
    print(json.dumps({k: record[k] for k in ('result', 'product', 'device_way', 'proc_hidepid',
                                             'product_cleanup_left', 'dangling_volumes_after')}))


if __name__ == '__main__':
    main()
