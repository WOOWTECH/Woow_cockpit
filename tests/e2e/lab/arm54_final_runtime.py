"""Remote helpers for the 2026-11-23 ARM54 final lane (runs on .54 as root).

Every Podman command goes to this run's private store (--root/--runroot under the
0700 workspace, vfs driver, file events). The default store, the original
containers and the host network stay untouched. Nothing here prints secret values.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

PREFIX = 'woow-arm54-final-20261123-'
ROOT = Path(sys.argv[1])
assert ROOT.parent == Path('/var/tmp') and ROOT.name.startswith(PREFIX), 'workspace-path-refused'
assert ROOT.is_dir() and not ROOT.is_symlink() and ROOT.stat().st_mode & 0o777 == 0o700, 'workspace-mode-refused'
sys.path.insert(0, str(ROOT / 'source/backup-engine'))
sys.path.insert(0, str(ROOT / 'source/tests/e2e/lab'))
# .54 has no python3-nacl/python3-cffi: an encrypted-backup run brings PyNaCl 1.5.0 + cffi 1.17.1 (PyPI aarch64
# wheels, sha256 recorded by `upload --pydeps`) inside this 0700 workspace only; nothing is installed system-wide.
if (ROOT / 'pydeps').is_dir():
    sys.path.insert(0, str(ROOT / 'pydeps'))
from woowbackup.podman import CommandError, Result  # noqa: E402

RESERVE = 12 * 1024 ** 3 + 128 * 1024 ** 2
LABEL = 'io.woowtech.test=arm54-final-20261123'
# The workspace's storage driver is fixed by `init` (file `store-driver`): vfs (default, the Headscale cycles) or
# overlay for large images (vfs copies every layer in full). Overlay never bind-mounts its home
# (skip_mount_home), so only running containers hold mounts and the cleanup proof stays "no mount names the workspace".
DRIVER = (ROOT / 'store-driver').read_text().strip() if (ROOT / 'store-driver').exists() else 'vfs'
assert DRIVER in ('vfs', 'overlay'), 'store-driver-refused'
DRIVER_ARGS = ['--storage-driver', DRIVER] + (['--storage-opt', 'overlay.skip_mount_home=true']
                                              if DRIVER == 'overlay' else [])
BASE = ['podman', '--root', str(ROOT / 'store'), '--runroot', str(ROOT / 'run'), *DRIVER_ARGS,
        '--events-backend', 'file', '--tmpdir', str(ROOT / 'tmp'), '--cgroup-manager', 'cgroupfs']
ENV = dict(os.environ, HOME=str(ROOT), XDG_CONFIG_HOME=str(ROOT / 'config'),
           REGISTRY_AUTH_FILE=str(ROOT / 'empty-auth.json'), TMPDIR=str(ROOT / 'tmp'),
           CONTAINERS_CONF_OVERRIDE=str(ROOT / 'containers-override.conf'), PYTHONDONTWRITEBYTECODE='1')
os.environ.update({k: v for k, v in ENV.items() if k in ('TMPDIR', 'PYTHONDONTWRITEBYTECODE')})
os.umask(0o077)


def free_bytes():
    return shutil.disk_usage(ROOT).free


class Runner:
    """The product's runner interface (podman/relay/read_file) bound to the private rootful store."""
    uid = 0
    home = str(ROOT)

    def __init__(self):
        self.commands = []
        self.free = []

    def capacity(self):
        free = free_bytes()
        self.free.append(free)
        if free < RESERVE:
            raise RuntimeError('capacity-reserve-refused')

    def podman(self, *args, input=None, stdout=None, timeout=60, max_output=None, check=True, abort=None):
        self.capacity()
        self.commands.append([str(a) for a in args])
        if abort is not None and abort() is not None:
            raise abort()
        stream = hasattr(input, 'read')
        with tempfile.TemporaryFile(dir=ROOT / 'tmp') as out, tempfile.TemporaryFile(dir=ROOT / 'tmp') as err:
            p = subprocess.run(BASE + [str(a) for a in args], env=ENV, stdin=input if stream else None,
                               input=None if stream else input, stdout=out, stderr=err, timeout=min(timeout, 900))
            size = out.tell()
            limit = max_output if max_output is not None else 8 * 1024 ** 2
            if size > limit:
                raise RuntimeError('capture-limit-refused')
            out.seek(0)
            err.seek(max(0, err.tell() - 8192))
            error = err.read()
            if stdout is not None:
                shutil.copyfileobj(out, stdout)
                data = b''
            else:
                data = out.read()
        self.capacity()
        if check and p.returncode:
            raise CommandError('isolated podman failed', returncode=p.returncode, stderr=b'suppressed')
        return Result(p.returncode, data, error)

    def relay(self, args, **kwargs):
        return self.podman(*args, **kwargs)

    def read_file(self, path, max_bytes):
        p = ROOT / path
        assert p.resolve().is_relative_to(ROOT) and '..' not in Path(path).parts
        assert p.stat().st_size <= max_bytes
        return p.read_bytes()


class RootfulRunner(Runner):
    """Rootful has no `podman unshare`: identity maps and owner stats are read directly, only for owned paths."""

    def podman(self, *args, **kwargs):
        if args[:1] == ('unshare',):
            command = [str(a) for a in args[1:]]
            allowed = command in (['cat', '/proc/self/uid_map'], ['cat', '/proc/self/gid_map'])
            volumes = (ROOT / 'store/volumes').resolve()
            if command[:5] == ['stat', '-c', '%u %g %a', '--', command[-1]]:
                allowed = Path(command[-1]).resolve().is_relative_to(volumes)
            # The product's restore applies a volume tar's top-directory entry (adapter _apply_volume_root).
            if len(command) == 5 and command[:2] == ['chown', '--no-dereference'] and command[3] == '--':
                allowed = Path(command[4]).resolve().is_relative_to(volumes)
            if len(command) == 4 and command[0] == 'chmod' and command[2] == '--':
                allowed = Path(command[3]).resolve().is_relative_to(volumes)
            assert allowed, 'rootful-namespace-command-refused'
            self.commands.append(['rootful-direct-namespace', *command])
            result = subprocess.run(command, capture_output=True, timeout=10, check=True)
            assert len(result.stdout) < 4096
            return Result(result.returncode, result.stdout, result.stderr)
        return super().podman(*args, **kwargs)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def report(path, doc):
    Path(path).write_text(json.dumps(doc, sort_keys=True, indent=2) + '\n')


def private_dir(*parts):
    path = ROOT.joinpath(*parts)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def kernel_state():
    """What the 2026-11-23 21:02 oops left (incident-54-kernel-oops-nft-masq), read only: tasks in uninterruptible
    sleep, hung-task and oops reports, the stuck nft_masq module, loaded modules and the taint (lane arm54-2 iter 3)."""
    import re
    import time

    def d_state():
        stats = []
        for pid in os.listdir('/proc'):
            if pid.isdigit():
                try:
                    stats.append(Path('/proc', pid, 'stat').read_text().rsplit(')', 1)[1].split()[0])
                except (OSError, IndexError):
                    pass
        return stats.count('D')
    samples = []
    for _ in range(3):  # a task in short I/O wait is not a stuck one: the least of three samples counts
        samples.append(d_state())
        time.sleep(0.5)
    dmesg = subprocess.run(['dmesg'], capture_output=True, timeout=30).stdout.decode('utf-8', 'replace')
    modules = sorted(line.split()[0] for line in Path('/proc/modules').read_text().splitlines() if line.strip())

    def module(name):
        try:
            return (Path('/sys/module', name, 'initstate').read_text().strip(),
                    Path('/sys/module', name, 'refcnt').read_text().strip())
        except OSError:
            return None
    return {'d_state': min(samples), 'hung_task_reports': len(re.findall(r'blocked for more than', dmesg)),
            'oops_count': len(re.findall(r'Internal error: Oops', dmesg)), 'nft_masq': module('nft_masq'),
            'tainted': int(Path('/proc/sys/kernel/tainted').read_text()), 'modules': modules}


def store_objects(runner):
    """Names of everything in the private store (for the cleanup proof)."""
    def lines(*args):
        return [x for x in runner.podman(*args).stdout.decode().splitlines() if x]
    return {'containers': lines('ps', '-a', '--format', '{{.Names}}'),
            'pods': lines('pod', 'ps', '--format', '{{.Name}}'),
            'volumes': lines('volume', 'ls', '--format', '{{.Name}}'),
            'images': lines('images', '--format', '{{.Id}}'),
            'secrets': lines('secret', 'ls', '--format', '{{.Name}}')}
