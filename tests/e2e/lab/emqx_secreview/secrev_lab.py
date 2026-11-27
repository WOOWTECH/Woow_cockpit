"""emqx-secreview lab harness (2026-11-23, lane emqx-secreview, SR-OWNER-1942).

Drives the product's OWN code (TempObjects, ha_emqx.ha_broker / target_broker / capture_target_seed ...) against the
separate lab Podman store (`labpodman`, its own --root), never /usr/bin/podman. Every `podman run` must carry
`--network none` (the runner refuses anything else). Only generated test values are used; nothing here prints a
credential (test values are compared by digest).
"""
import hashlib
import io
import json
import os
import pwd
import secrets
import subprocess
import sys
import tarfile
import time
from types import SimpleNamespace

# SECREV_ROOT holds <codebase>/backup-engine trees (e.g. final = a commit's backup-engine + a patch) and runs/.
SR = os.environ.get('SECREV_ROOT') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LP = '/home/woowtechopenclaw/.woowbk-lab/bin/labpodman'
IMAGE = 'docker.io/emqx/emqx:5.8.9'
LABEL = 'io.woowtech.secrev=1'
P = tempctr = ha_emqx = hacommon = BackupError = None


def use(codebase):
    """Import the product from SR/<codebase>/backup-engine (base = integration ae5420d, prodint = + product patch)."""
    global P, tempctr, ha_emqx, hacommon, BackupError
    sys.path.insert(0, os.path.join(SR, codebase, 'backup-engine'))
    sys.dont_write_bytecode = True
    from woowbackup import podman as _P, tempctr as _t, ha_emqx as _e, hacommon as _h
    from woowbackup.errors import BackupError as _B
    P, tempctr, ha_emqx, hacommon, BackupError = _P, _t, _e, _h, _B
    return ha_emqx


def lab_env():
    return {'PATH': '/usr/bin:/bin', 'HOME': pwd.getpwuid(os.getuid()).pw_dir,
            'XDG_RUNTIME_DIR': f'/run/user/{os.getuid()}', 'LANG': 'C.UTF-8'}


def make_runner():
    class LabRunner(P.OwnerRunner):
        def __init__(self):
            super().__init__(pwd.getpwuid(os.getuid()).pw_name, runner=self._exec)

        def _exec(self, argv, *, input=None, stdout=None, timeout=300, cwd=None, env=None, max_output=None,
                  abort=None):
            argv = list(argv[len(self.prefix()):])
            if not argv or argv[0] != P.PODMAN:
                raise RuntimeError('lab runner only runs podman')
            if len(argv) > 1 and argv[1] == 'run':
                i = argv.index('--network')
                if argv[i + 1] != 'none':
                    raise RuntimeError('lab runner: --network none only')
            argv[0] = LP
            extra = {} if max_output is None else {'max_output': max_output}
            if abort is not None:
                extra['abort'] = abort
            return P.default_runner(argv, input=input, stdout=stdout, timeout=timeout, cwd=cwd, env=lab_env(),
                                    **extra)

        def relay(self, podman_args, *, stdout, timeout=3600, check=True, max_output=None, abort=None):
            return self.run([P.PODMAN, *podman_args], stdout=stdout, timeout=timeout, check=check,
                            max_output=max_output, abort=abort)
    return LabRunner()


class Guard:
    def budget(self):
        return 4 * 1024 ** 3

    def wrote(self, _n):
        pass


class FakeWork:
    def __init__(self, runner):
        self._runner, self.logs, self.guard, self.abort = runner, [], Guard(), None
        self.stages = []

    def runner(self, _app):
        return self._runner

    def checkpoint(self):
        pass

    def log(self, text):
        self.logs.append(text)

    def phase(self, _name):
        pass


def job_id():
    return time.strftime('j%Y%m%dT%H%M%SZ-', time.gmtime()) + secrets.token_hex(4)


def temp(runner, job=None, memory='1g'):
    return tempctr.TempObjects(runner, job or job_id(), memory=memory, pids=1024, cpus=None)


def lab(*args, input=None, timeout=300, check=True):
    """labpodman for the lab-side fixtures (target device stand-in). Never production."""
    if args and args[0] == 'run' and ('--network' not in args or args[args.index('--network') + 1] != 'none'):
        raise RuntimeError('lab(): --network none only')
    r = subprocess.run([LP, *args], input=input, capture_output=True, timeout=timeout, env=lab_env())
    if check and r.returncode:
        raise RuntimeError(f'labpodman {args[0]} failed rc={r.returncode}: {r.stderr[-400:]!r}')
    return r


def tar_bytes(files, *, uid=0, gid=0, dmode=0o755, fmode=0o644):
    """files: {name: bytes | None (dir) | ('symlink', target) | ('hardlink', target) | ('mode', bytes, mode)}"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
        root = tarfile.TarInfo('.'); root.type = tarfile.DIRTYPE; root.mode = dmode; root.uid, root.gid = uid, gid
        tar.addfile(root)
        made = {'.'}
        for name in sorted(files):
            parts = name.split('/')
            for depth in range(1, len(parts)):
                parent = '/'.join(parts[:depth])
                if parent not in made and parent not in files:
                    info = tarfile.TarInfo(parent); info.type = tarfile.DIRTYPE; info.mode = dmode
                    info.uid, info.gid = uid, gid; tar.addfile(info); made.add(parent)
            value = files[name]
            info = tarfile.TarInfo(name); info.uid, info.gid = uid, gid; info.mtime = int(time.time())
            if value is None:
                info.type, info.mode = tarfile.DIRTYPE, dmode; tar.addfile(info)
            elif isinstance(value, tuple) and value[0] == 'symlink':
                info.type, info.linkname = tarfile.SYMTYPE, value[1]; tar.addfile(info)
            elif isinstance(value, tuple) and value[0] == 'hardlink':
                info.type, info.linkname = tarfile.LNKTYPE, value[1]; tar.addfile(info)
            else:
                mode = fmode
                if isinstance(value, tuple) and value[0] == 'mode':
                    value, mode = value[1], value[2]
                info.size, info.mode = len(value), mode
                tar.addfile(info, io.BytesIO(value))
            made.add(name)
    return buf.getvalue()


def cleanup():
    """Remove every lab object this harness labelled or named woowbk-secrev-* / woowbk-j... it created."""
    for kind, ls in (('container', ['ps', '-a', '--filter', 'label=' + LABEL, '--format', '{{.Names}}']),):
        names = lab(*ls, check=False).stdout.decode().split()
        for n in names:
            lab('rm', '-f', '-t', '0', n, check=False)
    vols = lab('volume', 'ls', '--filter', 'label=' + LABEL, '--format', '{{.Name}}', check=False).stdout.decode().split()
    for v in vols:
        lab('volume', 'rm', '-f', v, check=False)
    sec = lab('secret', 'ls', '--format', '{{.Name}}', check=False).stdout.decode().split()
    for s in sec:
        if s.startswith('secrev-'):
            lab('secret', 'rm', s, check=False)


class LabTarget:
    """A stand-in for this device's running `woow-emqx` (lab store, network none): a data volume seeded with
    `files` (uid/gid 1000 like the image user), optional read-only host files and podman secrets."""

    def __init__(self, tag, files, *, ro_files=(), secrets_spec=(), env=None, env_file=None):
        self.tag = tag
        self.container = f'woowbk-secrev-{tag}-emqx'
        self.data_volume = f'woowbk-secrev-{tag}-data'
        self.log_volume = f'woowbk-secrev-{tag}-log'
        self.image = IMAGE
        self.env = dict(env or {'EMQX_NODE__NAME': 'emqx@127.0.0.1'})
        self.node = self.env.get('EMQX_NODE__NAME', 'emqx@127.0.0.1')
        self.files = list(ro_files)        # [(host path, container path, 'ro')]
        self.secrets = list(secrets_spec)  # podman --secret specs
        for vol in (self.data_volume, self.log_volume):
            lab('volume', 'create', '--label', LABEL, vol)
        lab('volume', 'import', self.data_volume, '-', input=tar_bytes(files, uid=1000, gid=1000, dmode=0o755,
                                                                       fmode=0o644))
        argv = ['run', '-d', '--name', self.container, '--label', LABEL, '--network', 'none', '--pull=never',
                '--memory', '1g', '-v', f'{self.data_volume}:/opt/emqx/data', '-v', f'{self.log_volume}:/opt/emqx/log']
        for k, v in self.env.items():
            argv += ['-e', f'{k}={v}']
        if env_file is not None:   # the device's Quadlet EnvironmentFile= (podman reads it)
            argv += ['--env-file', env_file]
        for s, t, o in self.files:
            argv += ['-v', f'{s}:{t}:{o}']
        for spec in self.secrets:
            argv += ['--secret', spec]
        lab(*argv, IMAGE)
        self.wait()

    def execute(self, command, timeout=120):
        r = subprocess.run([LP, 'exec', self.container, *command], capture_output=True, timeout=timeout,
                           env=lab_env())
        return SimpleNamespace(returncode=r.returncode, stdout=r.stdout, stderr=r.stderr)

    def wait(self, timeout=240):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            r = self.execute(['emqx', 'ctl', 'status'], timeout=60)
            if r.returncode == 0 and b'is started' in r.stdout:
                return
            time.sleep(3)
        raise RuntimeError('lab target did not start')

    def remove(self):
        lab('rm', '-f', '-t', '0', self.container, check=False)
        for vol in (self.data_volume, self.log_volume):
            lab('volume', 'rm', '-f', vol, check=False)


def ha_src(tmp, files):
    """The HA broker's staged volume exactly as member_pass/scan_member write it (root, dirs 0755, files 0644)."""
    tmp.volume('emqx-src')
    data = tar_bytes(files, uid=0, gid=0)
    tmp.volume_import('emqx-src', lambda out: out.write(data))
    src = SimpleNamespace(addon=SimpleNamespace(state='stopped'), node_file=None, node_dirs=set(), files=len(files),
                          bytes=0, hocon=(files.get('configs/cluster.hocon') or b'').decode(), plugins=set())
    return src


def digest(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def evidence(path, record):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as handle:
        json.dump(record, handle, indent=1, sort_keys=True, ensure_ascii=False)
        handle.write('\n')


def dangling_names():
    return set(lab('volume', 'ls', '--filter', 'dangling=true', '--format', '{{.Name}}').stdout.decode().split())


def new_dangling(before):
    """New dangling volumes since `before`, by shape: EMQX data (configs/mnesia/patches), empty (EMQX log), other (for
    example another lane's PostgreSQL throwaway at the same time). Names only."""
    shapes = {'emqx': 0, 'empty': 0, 'other': 0}
    for name in dangling_names() - set(before):
        mp = lab('volume', 'inspect', '--format', '{{.Mountpoint}}', name).stdout.decode().strip()
        top = set(lab('unshare', 'ls', '-A', mp, check=False).stdout.decode().split())
        shapes['emqx' if top & {'configs', 'mnesia', 'patches'} else 'empty' if not top else 'other'] += 1
    return shapes
