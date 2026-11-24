"""Runs ON 192.168.2.54 as root (sent by `arm54_final_control.py run --script arm54_final_large_outer.py`).

Lane arm54-2 item A: the large-archive lane's incompressible >8GiB outer-archive probe
(tests/backup/bounded_incompressible_outer.py; the backup engine is the uploaded, unmodified code) on .54's own eMMC
instead of the production host (the host lacks the free space).

Tools: .54 has no age/age-keygen/zstd. The upload brings the Debian bookworm arm64 packages age 1.1.1-1+b3 and zstd
1.5.4+dfsg2-5 (sha256 pinned in DEBS; the coordinator verified InRelease -> Packages.xz -> .deb with .54's own Debian
archive keyrings, evidence large-tools-provenance). They are unpacked into the 0700 workspace only (dpkg-deb
--fsys-tarfile reads the package; the dpkg database is not touched, nothing is installed). The engine looks tools up
only in its fixed SAFE_PATH, so the probe runs in a private mount namespace (unshare --mount --propagation private)
in which the workspace tool directory is bind-mounted over /usr/local/sbin: that mount exists for the probe's
process tree only and is gone when it exits (checked: no mount line of this namespace names the workspace).

The probe runs with nice -n 19 + ionice -c3, its own 2-CPU affinity, the owner's .54 floor (--reserve-gib 4: the
probe's guard aborts and deletes before free space can go under 4GiB + 256MiB) and deletes everything it generates.
A sampler records the free bytes of the workspace disk every 2 s, MemAvailable and the load, and every 15 s one
unauthenticated GET of the local Home Assistant frontend manifest (status + latency; informational: shows whether the
original service stayed responsive under the I/O load). The original containers (default store, read-only listing)
and systemd services are compared before/after. ionice -c3 only acts on BFQ/CFQ; the device's scheduler is recorded.
argv: <workspace> [--mib N] [--deadline S] [--reserve-gib G]
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request

from arm54_final_runtime import ROOT

GIB = 1024 ** 3
FLOOR = 4 * GIB  # owner: keep at least 4 GiB free on .54 at every moment
DEBS = {  # file in input/ -> (sha256 pinned to the Debian bookworm arm64 Packages entry, members to unpack)
    'age.deb': ('d14f937ecb1cef9279879e779cf61fda682735dd9871cd7d60ba7a487608f4e6',
                ('./usr/bin/age', './usr/bin/age-keygen')),
    'zstd.deb': ('97a58383b0ad55cc8183e59cbb112f2eb55c3dc1e90de816fa5cfb983d5c2ff0', ('./usr/bin/zstd',)),
}
TOOLS = ROOT / 'tools' / 'sbin'
WORK = ROOT / 'work'
PROBE = ROOT / 'source' / 'tests' / 'backup' / 'bounded_incompressible_outer.py'
MASK_DIR = '/usr/local/sbin'
FRONTEND = 'http://127.0.0.1:8123/manifest.json'  # the original Home Assistant (host network), read-only GET
SH = 'mount --bind "$1" "$2" || exit 97; shift 2; exec "$@"'

parser = argparse.ArgumentParser()
parser.add_argument('workspace')
parser.add_argument('--mib', type=int, default=8193)
parser.add_argument('--deadline', type=int, default=7200)
parser.add_argument('--reserve-gib', type=int, default=4)
args = parser.parse_args(sys.argv[1:])
assert Path(args.workspace) == ROOT, 'workspace-mismatch'
assert args.reserve_gib >= FLOOR // GIB, 'reserve-below-owner-floor'
out = {'status': 'failed', 'phase': 'start', 'commercial_acceptance': 'not-complete', 'host': '192.168.2.54',
       'mib': args.mib, 'deadline_seconds': args.deadline, 'reserve_gib': args.reserve_gib,
       'owner_floor_bytes': FLOOR, 'tools_installed_system_wide': False, 'raw_stderr_exported': False}
started = time.monotonic()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def free_bytes(path=ROOT):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def mem_available():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    return None


def run(argv, timeout=60):
    p = subprocess.run(argv, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout.decode('utf-8', 'replace')


def originals():
    """Read-only listing of the default store and the running services (the identity proof is `audit`)."""
    code, text = run(['podman', 'ps', '-a', '--no-trunc', '--format', '{{.Names}} {{.State}} {{.StartedAt}}'])
    _, services = run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--plain'])
    return {'containers': sorted(text.splitlines()) if code == 0 else ['<exit %d>' % code],
            'services_running': sorted(l.split()[0] for l in services.splitlines() if l.strip())}


def unpack_tools():
    if TOOLS.exists():  # an earlier attempt in the same workspace: unpack fresh from the verified packages
        shutil.rmtree(TOOLS)
    TOOLS.mkdir(parents=True, mode=0o700)
    found = {}
    for deb, (want, members) in sorted(DEBS.items()):
        path = ROOT / 'input' / deb
        got = sha256_file(path)
        assert got == want, 'deb-digest-mismatch'
        proc = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(path)], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        with tarfile.open(fileobj=proc.stdout, mode='r|') as tar:
            for member in tar:
                if member.name in members:
                    assert member.isfile() and member.size < 64 * 1024 ** 2, 'unexpected-member'
                    dest = TOOLS / Path(member.name).name
                    with open(dest, 'xb') as handle:
                        handle.write(tar.extractfile(member).read())
                    os.chmod(dest, 0o755)
                    found[dest.name] = {'from': deb, 'deb_sha256': got, 'sha256': sha256_file(dest),
                                        'bytes': dest.stat().st_size}
        proc.stdout.close()
        assert proc.wait(timeout=60) == 0, 'dpkg-deb-failed'
    assert sorted(found) == ['age', 'age-keygen', 'zstd'], 'tools-missing'
    for name, row in found.items():
        code, text = run([str(TOOLS / name), '--version'], timeout=20)
        row['version_exit'], row['version'] = code, text.strip().splitlines()[0] if text.strip() else ''
        code, text = run(['ldd', str(TOOLS / name)], timeout=20)
        row['ldd_all_resolved'] = 'not found' not in text
        row['dynamically_linked'] = code == 0 and '=>' in text
    return found


class Sampler(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.stop = threading.Event()
        self.min_free = free_bytes()
        self.min_mem = mem_available()
        self.max_load = 0.0
        self.samples = 0
        self.frontend = {'every_seconds': 15, 'ok': 0, 'failed': 0, 'max_latency_seconds': 0.0,
                         'latencies_over_5s': 0}

    def frontend_probe(self):
        mark = time.monotonic()
        try:
            with urllib.request.urlopen(FRONTEND, timeout=10) as response:
                ok = response.status == 200
                response.read(65536)
        except Exception:  # noqa: BLE001 - informational sample only
            ok = False
        latency = time.monotonic() - mark
        self.frontend['ok' if ok else 'failed'] += 1
        self.frontend['max_latency_seconds'] = round(max(self.frontend['max_latency_seconds'], latency), 3)
        self.frontend['latencies_over_5s'] += latency > 5

    def run(self):
        ticks = 0
        while not self.stop.wait(2):
            try:
                self.min_free = min(self.min_free, free_bytes())
                mem = mem_available()
                if mem is not None:
                    self.min_mem = min(self.min_mem, mem)
                self.max_load = max(self.max_load, float(Path('/proc/loadavg').read_text().split()[0]))
                self.samples += 1
            except OSError:
                pass
            ticks += 1
            if ticks % 8 == 1:
                self.frontend_probe()


def mounts_naming(path):
    return sum(str(path) in line for line in Path('/proc/self/mountinfo').read_text().splitlines())


def disk_facts():
    code, text = run(['findmnt', '-no', 'SOURCE,FSTYPE', '--target', str(ROOT)])
    source = text.split()[0] if code == 0 and text.split() else ''
    dev = Path(source).name
    while dev and not Path('/sys/block', dev).exists() and dev[-1].isdigit():
        dev = dev[:-1]
    dev = dev[:-1] if dev.endswith('p') and not Path('/sys/block', dev).exists() else dev
    sched = Path('/sys/block', dev, 'queue/scheduler')
    flags = ''
    for line in Path('/proc/cpuinfo').read_text().splitlines():
        if line.startswith('Features'):
            flags = line.split(':', 1)[1].split()
            break
    active = sched.read_text().split('[', 1)[1].split(']', 1)[0] if sched.exists() and '[' in sched.read_text() else None
    return {'mount_source_fstype': text.strip(), 'block_device': dev,
            'io_scheduler': sched.read_text().strip() if sched.exists() else None,
            'ionice_class_honoured_by_scheduler': active in ('bfq', 'cfq'),
            'cpu_crypto_flags': sorted(set(flags) & {'aes', 'sha1', 'sha2', 'sha3', 'sha512', 'pmull'}),
            'cpus': os.cpu_count()}


try:
    out['phase'] = 'tools'
    out['tools'] = unpack_tools()
    out['phase'] = 'before'
    out['disk'] = disk_facts()
    out['free_bytes_before'] = free_bytes()
    out['mem_available_before'] = mem_available()
    out['load_before'] = Path('/proc/loadavg').read_text().split()[:3]
    out['originals_before'] = originals()
    probe_sampler = Sampler()
    probe_sampler.frontend_probe()
    out['frontend_manifest_before'] = probe_sampler.frontend
    out['mask_dir_listing_before'] = sorted(os.listdir(MASK_DIR))
    WORK.mkdir(mode=0o700, exist_ok=True)
    out['phase'] = 'probe'
    argv = ['unshare', '--mount', '--propagation', 'private', '--', '/bin/sh', '-c', SH, 'sh', str(TOOLS), MASK_DIR,
            'nice', '-n', '19', 'ionice', '-c3', sys.executable, '-I', '-B', str(PROBE), '--mib', str(args.mib),
            '--scratch-parent', str(WORK), '--reserve-gib', str(args.reserve_gib), '--deadline', str(args.deadline)]
    out['probe_argv'] = [a.replace(str(ROOT), '<workspace>') for a in argv]
    sampler = Sampler()
    sampler.start()
    mark = time.monotonic()
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=args.deadline + 900)
        out['probe_exit'] = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as timeout:
        out['probe_exit'] = 'timeout'
        stdout, stderr = timeout.stdout or b'', timeout.stderr or b''
    finally:
        sampler.stop.set()
        sampler.join(timeout=10)
    out['probe_seconds'] = round(time.monotonic() - mark, 1)
    out['probe_stdout_sha256'] = hashlib.sha256(stdout).hexdigest()
    out['probe_stderr'] = {'bytes': len(stderr), 'sha256': hashlib.sha256(stderr).hexdigest(),
                           'traceback': b'Traceback' in stderr}
    out['samples'] = {'every_seconds': 2, 'count': sampler.samples, 'min_free_bytes': sampler.min_free,
                      'min_free_minus_owner_floor_bytes': sampler.min_free - FLOOR,
                      'min_mem_available_bytes': sampler.min_mem, 'max_load_1m': sampler.max_load,
                      'frontend_manifest_informational': sampler.frontend}
    try:
        out['probe'] = json.loads(stdout.decode())
    except ValueError:
        out['probe'] = None
    out['phase'] = 'after'
    out['work_left'] = sorted(os.listdir(WORK))
    out['mounts_naming_workspace_in_host_namespace'] = mounts_naming(ROOT)
    out['mask_dir_listing_after'] = sorted(os.listdir(MASK_DIR))
    out['originals_after'] = originals()
    out['free_bytes_after'] = free_bytes()
    probe = out['probe'] or {}
    big = args.mib == 8193
    checks = {
        'probe_exit_0': out['probe_exit'] == 0,
        'probe_passed': probe.get('status') == 'passed',
        'tools_from_workspace': probe.get('dependency_paths') == {n: MASK_DIR + '/' + n
                                                                   for n in ('age', 'age-keygen', 'zstd')},
        'archive_over_8gib': probe.get('archive_over_8gib') is True if big else True,
        'ciphertext_over_ustar_limit': probe.get('ciphertext_over_ustar_limit') is True if big else True,
        'outer_pax_size_record': (probe.get('outer_member_header') or {}).get('pax_header') is True if big else True,
        'stream_hash_equals_writer': (probe.get('stream_hash') or {}).get('file_sha256_equals_writer') is True,
        'verify_passed': ((probe.get('cases') or {}).get('verify') or {}).get('status') == 'passed',
        'late_tail_refused_and_restored': (((probe.get('cases') or {}).get('flip-last-byte-in-place-verify') or {})
                                           .get('status') == 'passed' and probe.get('original_restored_bit_exact')
                                           is True),
        'keys_rejected': probe.get('key_rejections') == {'missing': 'key-required', 'wrong': 'wrong-key'},
        'probe_scratch_removed': probe.get('harness_removed_private_scratch_and_keys') is True,
        'no_tool_children': probe.get('tool_children_at_end') == 0,
        'owner_floor_kept_in_probe_samples': (probe.get('minimum_free_observed') or 0) >= FLOOR,
        'owner_floor_kept_in_2s_samples': sampler.min_free >= FLOOR,
        'work_dir_empty': out['work_left'] == [],
        'no_mount_leak': out['mounts_naming_workspace_in_host_namespace'] == 0,
        'mask_dir_unchanged': out['mask_dir_listing_after'] == out['mask_dir_listing_before'],
        'originals_unchanged': out['originals_after'] == out['originals_before'],
    }
    out['checks'] = checks
    out['failed_check'] = next((k for k, v in checks.items() if not v), None)
    out['status'] = 'passed' if all(checks.values()) else 'failed'
    out['phase'] = 'done'
except Exception as error:  # noqa: BLE001
    out['error_code'] = type(error).__name__
    out['error_hint'] = str(error)[:80] if isinstance(error, AssertionError) else None
finally:
    out['elapsed_seconds'] = round(time.monotonic() - started, 1)
    print(json.dumps(out, sort_keys=True))
    sys.exit(0 if out['status'] == 'passed' else 1)
