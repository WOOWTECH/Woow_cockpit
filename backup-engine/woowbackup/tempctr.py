"""Throwaway Podman containers, volumes and internal networks of a job (CONTRACT section 8 "Throwaway containers";
used by the Home Assistant import, branch feat/ha-import). Owner: E2.

Some jobs rebuild an app's data in the app's own format before anything of the app changes (an HA import turns a
PostgreSQL 16 data directory into a PostgreSQL 17 cluster, an n8n SQLite file into a PostgreSQL dump). They do it in
containers of their own, made from images that are already on the device, and remove them again:

* everything runs as the app owner through OwnerRunner (rootless Podman, his storage, his limits);
* names are `woowbk-<job>-<role>` and every object carries the label `io.woowtech.backup.job=<job>`, so whatever a
  killed job left is found again (`sweep`, from the recovery and at every run-job start);
* containers run with `--network none` unless two of them must talk, then on an internal network made for the job
  (`podman network create --internal`: no route out); no published ports; `--security-opt no-new-privileges`, a pids
  and a memory limit, half the CPUs (`--cpus`, when the owner's user manager has the cpu controller), `--pull=never`
  (nothing is downloaded) and `--log-driver none` (nothing they print reaches the owner's journal; what a job needs it
  captures with the runner's budgets);
* `abort` (set by the job: its watchdog) is handed to every long podman call: a cancel or a disk running full stops
  the call within a second (the caller then removes the containers);
* an app secret is mounted exactly as the live Quadlet file mounts it (`--secret <its Secret= value>`); its value is
  never read into Python;
* `TempObjects` removes every object it created in `finally` (containers, then volumes, then networks), also when the
  job fails or is cancelled.

HAOS parity (2026-11-25, lane F3-helpers):

* `scope` (SCOPES): the objects of one app of a check are named `woowbk-<job>-<scope>-<role>` -- but only when the plain
  name `woowbk-<job>-<role>` is held by an object of another TempObjects of the same job and owner that is still there (what
  an earlier app could not remove, see `stuck`), so what one app could not remove never stands in the way of the next
  one's (X-TC-05); every other name stays as it was. The label stays the job id, so `sweep` and the recovery keep matching.
* An object that cannot be removed only takes space: `remove` / `remove_volume` say so in the log, keep it listed for
  `cleanup` and the sweeps and go on instead of stopping the app (X-TC-05). A list of objects that cannot be read stops
  nothing either (X-TC-07: `sweep` raises, its callers report it).
* `put_back_later(label, action)`: what a job changed on the device for its reading (a service it started) and puts
  back: run by `cleanup` first, retried while it fails (hatarget.ensure_running).
* `size` (bytes of the app's data, `scale_to`): every wait of a throwaway container grows with it -- the old value is the
  floor, nothing is cut -- so a big app is only slow, not "too late" (X-PD-05).
"""
import contextlib
import io
import json
import os
import re
import shlex
import tarfile
import threading
import weakref

from . import podman
from .errors import BackupError

LABEL = 'io.woowtech.backup.job'
ROOT_HEAD_BYTES = 64 * 1024   # enough for a top-directory entry and its pax header (tar_root)
PREFIX = 'woowbk-'
JOB_RE = re.compile(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
ROLE_RE = re.compile(r'[a-z0-9][a-z0-9-]{0,30}\Z')
NAME_RE = re.compile(r'woowbk-(j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})-([a-z0-9][a-z0-9-]{0,30})\Z')
IMAGE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}\Z')
ENV_KEY_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')
ENV_VALUE_RE = re.compile(r'[^\x00-\x1f\x7f]{0,1024}\Z')
TARGET_RE = re.compile(r'/[A-Za-z0-9_./-]{0,254}\Z')
USER_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,31})?\Z')
# `--add-host <name>:<IPv4>` (EMQX's node name of an HA backup must resolve inside a network-less container).
HOSTNAME_RE = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z')
IPV4_RE = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}\Z')
# A Quadlet `Secret=` value as podman's --secret takes it: the secret's name, then type/target/uid/gid/mode options.
SECRET_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}\Z')
SECRET_OPTION_RE = re.compile(r'(?:type=(?:mount|env)|target=[A-Za-z0-9_./-]{1,255}|uid=[0-9]{1,10}|gid=[0-9]{1,10}'
                              r'|mode=0?[0-7]{3,4})\Z')
SECRETS_TMPFS = '/run/secrets:rw,noexec,nosuid,nodev,mode=0755'
# TempObjects takes `scope`; haimport.Work.temp passes the app's place in the job while this is True. A scoped TempObjects only
# uses a scoped name where the plain one is stuck (see `stuck`): the importer tests' doubles read the role out of the name
# (hab1fakes.role_of, test_ha_flows, test_ha_omnigent) and keep working, nothing is renamed that does not have to be.
SCOPES = True
SCOPE_RE = re.compile(r'[0-9]{1,2}\Z')
_LIVE = weakref.WeakSet()     # every TempObjects of this process that is still referenced (the job keeps its leftovers' owners)
REMOVE_ARGS = {'container': ('rm', '--force', '--time', '10'), 'volume': ('volume', 'rm', '--force'),
               'network': ('network', 'rm', '--force')}
KIND_LABELS = {'container': '容器', 'volume': '資料卷', 'network': '網路'}


def secret_mount_path(spec):
    """Where a `--secret` spec puts its file inside the container ('' for an environment secret): podman mounts
    type=mount (the default) at `target`, relative targets and the default (the secret's name) under /run/secrets."""
    parts = str(spec).split(',')
    options = dict(part.split('=', 1) for part in parts[1:] if '=' in part)
    if options.get('type', 'mount') != 'mount':
        return ''
    target = options.get('target') or parts[0]
    return target if target.startswith('/') else '/run/secrets/' + target


def stuck(job_id, owner=None, exclude=None):
    """The names of this job's throwaway objects of `owner` (whose Podman storage they are in) that another TempObjects of
    this process still lists -- what it created and could not remove (an app that left something behind), or a sibling that
    is still working: a scoped TempObjects takes a name of its own instead of the same one."""
    prefix = f'{PREFIX}{job_id}-'
    names = set()
    for other in list(_LIVE):
        if other is not exclude and other._owner == owner:
            names.update(name for name in (*other.containers, *other.volumes, *other.networks) if name.startswith(prefix))
    return frozenset(names)


MEMORY = '2g'
PIDS = 1024
SHORT_TIMEOUT = 120
LIST_TIMEOUT = 30
LIST_OUTPUT = 32 * 1024 * 1024   # was 4 MiB: a long list of leftovers is read, not refused (X-PD-04); still bounded
STOP_TIMEOUT = 120
CONTROLLERS = '/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers'


def default_cpus(uid, *, controllers=CONTROLLERS, cpu_count=os.cpu_count):
    """Half the CPUs (at least 1) when the owner's user manager can limit CPU (cgroup v2 `cpu` delegated), else None
    (`--cpus` would make every run fail)."""
    if not isinstance(uid, int) or isinstance(uid, bool) or uid <= 0:
        return None
    try:
        with open(controllers.format(uid=uid), encoding='ascii') as handle:
            if 'cpu' not in handle.read(4096).split():
                return None
    except (OSError, ValueError):
        return None
    return str(max(1, (cpu_count() or 2) // 2))


def valid_role(role):
    return isinstance(role, str) and ROLE_RE.fullmatch(role) is not None


def object_name(job_id, role):
    """`woowbk-<job>-<role>` (the name of every throwaway object of a job)."""
    if not isinstance(job_id, str) or not JOB_RE.fullmatch(job_id) or not valid_role(role):
        raise BackupError('internal-error', '內部作業代號格式不正確。')
    return f'{PREFIX}{job_id}-{role}'


def parse_unit(text):
    """{section: [(key, value), ...]} of a systemd/Quadlet unit (continuation lines joined; comments skipped)."""
    sections, current, pending = {}, None, ''
    for raw in text.splitlines():
        line = pending + raw.strip()
        pending = ''
        if line.endswith('\\'):
            pending = line[:-1] + ' '
            continue
        if not line or line[0] in '#;':
            continue
        if line.startswith('[') and line.endswith(']'):
            current = line[1:-1]
            sections.setdefault(current, [])
            continue
        if current is not None and '=' in line:
            key, value = line.split('=', 1)
            sections[current].append((key.strip(), value.strip()))
    return sections


def _container_values(text, key):
    if isinstance(text, bytes):
        text = text.decode('utf-8', 'replace')
    return [value for name, value in parse_unit(text).get('Container', []) if name == key]


def quadlet_secrets(text):
    """The `Secret=` values of a `.container` file (in order), each checked to be exactly what podman's `--secret`
    takes: a secret name and type/target/uid/gid/mode options. Anything else is refused (incompatible)."""
    specs = []
    for value in _container_values(text, 'Secret'):
        parts = value.split(',')
        if not SECRET_NAME_RE.fullmatch(parts[0]) or not all(SECRET_OPTION_RE.fullmatch(p) for p in parts[1:]):
            raise BackupError('incompatible', f'Quadlet 檔中的 Secret= 設定格式不受支援：{value[:80]}')
        specs.append(value)
    return specs


def quadlet_image(text):
    """The last `Image=` of a `.container` file, checked like the adapter checks it (None when it has none)."""
    values = _container_values(text, 'Image')
    if not values:
        return None
    ref = values[-1]
    if not IMAGE_RE.fullmatch(ref) or ref.endswith(('.image', '.build')):
        raise BackupError('incompatible', f'Quadlet 檔的 Image= 設定不受支援：{ref[:120]}')
    return ref


def quadlet_environment(text, allowed):
    """{key: value} of the `Environment=` lines of a `.container` file whose key is in `allowed` (the caller names the
    keys a throwaway copy needs; anything else, which could hold a secret, is never passed on)."""
    env = {}
    for value in _container_values(text, 'Environment'):
        try:
            items = shlex.split(value)  # systemd's quoting: "KEY=a b" is one assignment
        except ValueError:
            raise BackupError('incompatible', 'Quadlet 檔中的 Environment= 設定格式不受支援。') from None
        for item in items:
            key, sep, val = item.partition('=')
            if not sep or key not in allowed:
                continue
            if not ENV_KEY_RE.fullmatch(key) or not ENV_VALUE_RE.fullmatch(val):
                raise BackupError('incompatible', f'Quadlet 檔中的 Environment= 設定格式不受支援：{key[:40]}')
            env[key] = val
    return env


def tar_root(head):
    """(uid, gid, mode) of a tar stream's top-directory entry when its first member is '.', else None (`head` = the
    stream's first bytes; pax headers are read like tarfile reads them)."""
    try:
        with tarfile.open(fileobj=io.BytesIO(head), mode='r|') as tar:
            first = tar.next()
    except (tarfile.TarError, EOFError, OSError, ValueError):
        return None
    if first is None or not first.isdir() or first.name not in ('.', './'):
        return None
    if type(first.uid) is not int or type(first.gid) is not int or first.uid < 0 or first.gid < 0:
        return None
    return first.uid, first.gid, first.mode & 0o7777


class TempObjects:
    """The throwaway objects of one job for one owner (`runner`, an OwnerRunner). Use as a context manager: every
    container, volume and network it created is removed on exit. `log(text)` receives short zh-TW notes."""

    def __init__(self, runner, job_id, *, log=None, memory=MEMORY, pids=PIDS, cpus='auto', abort=None, scope=None):
        object_name(job_id, 'x')  # checks the job id
        if scope is not None and (not isinstance(scope, str) or not SCOPE_RE.fullmatch(scope)):
            raise BackupError('internal-error', '暫用物件的範圍名稱格式不正確。')
        self.runner = runner
        self.job_id = job_id
        self.scope = scope     # None, or the app's place in the job: `woowbk-<job>-<scope>-<role>`
        self.log = log or (lambda _text: None)
        self.memory = memory
        self.pids = int(pids)
        self.cpus = default_cpus(getattr(runner, 'uid', None)) if cpus == 'auto' else cpus
        if self.cpus is not None and not re.fullmatch(r'[0-9]{1,3}(?:\.[0-9]{1,2})?', str(self.cpus)):
            raise BackupError('internal-error', 'CPU 限制格式不正確。')
        self.abort = abort     # None, or the job's watchdog (see the module notes)
        self.containers = []   # names, in creation order
        self.volumes = []
        self.networks = []
        self._noted = set()    # objects whose removal failed once (one log line each: X-TC-05)
        self._names = {}       # role -> the name this instance uses for it (chosen once, see name())
        self._owner = getattr(runner, 'owner', None)   # whose Podman storage the objects are in (a name only collides there)
        _LIVE.add(self)
        self._puts_back = []   # [(label, action)] what cleanup() puts back first (put_back_later)
        self.services = {}     # {container: unit} of the services this job started for its reading (hatarget.ensure_running)
        self.size = None       # bytes of the app's data when known (scale_to): the waits below grow with it

    def _long(self, kwargs):
        """kwargs of a long podman call: the job's abort hook when there is one."""
        if self.abort is not None:
            kwargs['abort'] = self.abort
        return kwargs

    def _stopped(self):
        """Never start anything new once the job's watchdog said stop."""
        error = self.abort() if self.abort is not None else None
        if error is not None:
            raise error

    def scale_to(self, nbytes):
        """The app's data is `nbytes` big: the waits of this job's throwaway containers grow with it (X-PD-05). Never shorter
        than the value a call asked for."""
        self.size = nbytes if isinstance(nbytes, (int, float)) and not isinstance(nbytes, bool) and nbytes > 0 else None

    def _wait(self, seconds):
        return podman.scaled_timeout(seconds, self.size)

    def name(self, role):
        """`woowbk-<job>-<role>`; with a scope and when that name is held by an object of an earlier app that could not be
        removed: `woowbk-<job>-<scope>-<role>`. Chosen once per role: the name of an object never changes under it."""
        chosen = self._names.get(role)
        if chosen is None:
            chosen = object_name(self.job_id, role)
            if self.scope is not None and chosen in stuck(self.job_id, self._owner, exclude=self):
                with contextlib.suppress(BackupError):   # a role too long for it keeps the plain name: the app stops there
                    chosen = object_name(self.job_id, f'{self.scope}-{role}')
            self._names[role] = chosen
        return chosen

    @property
    def label(self):
        return f'{LABEL}={self.job_id}'

    # ------------------------------------------------------------ objects
    def volume(self, role):
        """Create the volume `woowbk-<job>-<role>`; returns its name."""
        name = self.name(role)
        if name in self.volumes:
            self._free_name('volume', name, '暫用資料卷名稱重複。')
        self.volumes.append(name)
        self.runner.podman('volume', 'create', '--label', self.label, name, timeout=SHORT_TIMEOUT,
                           max_output=64 * 1024)
        return name

    def network(self, role):
        """Create the internal network `woowbk-<job>-<role>` (no route out, DNS between its containers)."""
        name = self.name(role)
        if name in self.networks:
            self._free_name('network', name, '暫用網路名稱重複。')
        self.networks.append(name)
        self.runner.podman('network', 'create', '--internal', '--label', self.label, name, timeout=SHORT_TIMEOUT,
                           max_output=64 * 1024)
        return name

    def run_argv(self, role, image, args=(), *, detach=False, network=None, volumes=(), secrets=(), env=None,
                 entrypoint=None, user=None, workdir=None, interactive=False, remove=False, read_only_root=False,
                 add_hosts=(), env_files=()):
        """The `podman run` argument list (without `podman`) of a throwaway container; every value is checked.
        `volumes`: (source, target, options|None); a source is a volume name or an absolute host path. `secrets`:
        Quadlet `Secret=` values (quadlet_secrets). `env`: {key: value} (never a secret value: it would be visible
        in the process list). `env_files`: absolute paths podman itself reads (`--env-file`, like a Quadlet's
        `EnvironmentFile=`): their values, which may be secret, never reach a command line; `env` wins over them.
        `add_hosts`: (name, IPv4) lines for the container's /etc/hosts (no network is opened by them)."""
        name = self.name(role)
        if not isinstance(image, str) or not IMAGE_RE.fullmatch(image):
            raise BackupError('internal-error', '映像名稱格式不正確。')
        argv = ['run', '--name', name, '--label', self.label, '--pull=never', '--log-driver', 'none',
                '--network', network or 'none', '--security-opt', 'no-new-privileges',
                '--pids-limit', str(self.pids), '--memory', self.memory]
        if self.cpus is not None:
            argv += ['--cpus', str(self.cpus)]
        if network is not None and network not in self.networks:
            raise BackupError('internal-error', '暫用容器只能連到這個作業建立的內部網路。')
        if detach:
            argv.append('--detach')
        if remove:
            argv.append('--rm')
        if interactive:
            argv.append('--interactive')
        if read_only_root:
            argv.append('--read-only')
        if user is not None:
            if not USER_RE.fullmatch(str(user)):
                raise BackupError('internal-error', '容器使用者格式不正確。')
            argv += ['--user', str(user)]
        if workdir is not None:
            if not TARGET_RE.fullmatch(workdir):
                raise BackupError('internal-error', '容器工作目錄格式不正確。')
            argv += ['--workdir', workdir]
        for host, address in add_hosts:
            if not isinstance(host, str) or not HOSTNAME_RE.fullmatch(host) or not isinstance(address, str) \
                    or not IPV4_RE.fullmatch(address):
                raise BackupError('internal-error', '容器主機名稱對應格式不正確。')
            argv += ['--add-host', f'{host}:{address}']
        if entrypoint is not None:
            if not isinstance(entrypoint, str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,255}', entrypoint):
                raise BackupError('internal-error', '容器進入點格式不正確。')
            argv += ['--entrypoint', entrypoint]
        for path in env_files:
            if (not isinstance(path, str) or not TARGET_RE.fullmatch(path) or path.endswith('/')
                    or {'', '.', '..'} & set(path[1:].split('/'))):
                raise BackupError('internal-error', '容器環境變數檔路徑格式不正確。')
            argv += ['--env-file', path]
        for key, value in sorted((env or {}).items()):
            if not ENV_KEY_RE.fullmatch(key) or not isinstance(value, str) or not ENV_VALUE_RE.fullmatch(value):
                raise BackupError('internal-error', '容器環境變數格式不正確。')
            argv += ['--env', f'{key}={value}']
        for source, target, options in volumes:
            if not isinstance(source, str) or not (source.startswith('/') and TARGET_RE.fullmatch(source)
                                                   or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', source)):
                raise BackupError('internal-error', '容器掛載來源格式不正確。')
            if not TARGET_RE.fullmatch(target) or (options is not None and not re.fullmatch(r'(ro|rw)(,[a-zA-Z]+)*',
                                                                                             options)):
                raise BackupError('internal-error', '容器掛載目標格式不正確。')
            argv += ['--volume', f'{source}:{target}' + (f':{options}' if options else '')]
        secrets = list(secrets)
        for spec in secrets:
            parts = str(spec).split(',')
            if not SECRET_NAME_RE.fullmatch(parts[0]) or not all(SECRET_OPTION_RE.fullmatch(p) for p in parts[1:]):
                raise BackupError('internal-error', '容器機密掛載格式不正確。')
        if read_only_root and any(secret_mount_path(spec).startswith('/run/secrets/') for spec in secrets):
            # A read-only root cannot take the mount point of a secret FILE: runc (1.5.1 under rootless Podman 6.1.1)
            # creates /run/secrets/<target> inside the image's read-only filesystem and fails ("read-only file
            # system", podman exit 126; crun 1.29.1 does not fail). A private tmpfs at /run/secrets holds the mount
            # points with either runtime; the secret files are mounted into it exactly as before.
            argv += ['--tmpfs', SECRETS_TMPFS]
        for spec in secrets:
            argv += ['--secret', spec]
        argv.append(image)
        for arg in args:
            if not isinstance(arg, str) or '\x00' in arg:
                raise BackupError('internal-error', '容器命令格式不正確。')
            argv.append(arg)
        return argv

    def run(self, role, image, args=(), *, detach=False, input=None, stdout=None, timeout=600, max_output=None,
            check=True, remove=None, **options):
        """Start a throwaway container (detached: returns once it runs; else waits for it, capturing its output
        with the runner's budgets). A container that ran to its end is removed with `--rm`."""
        name = self.name(role)
        if name in self.containers:
            self._free_name('container', name, '暫用容器名稱重複。')
        self._stopped()
        remove = (not detach) if remove is None else remove
        argv = self.run_argv(role, image, args, detach=detach, interactive=input is not None, remove=remove,
                             **options)
        self.containers.append(name)
        result = self.runner.podman(*argv, input=input, stdout=stdout, timeout=self._wait(timeout),
                                    max_output=max_output if max_output is not None else (64 * 1024 if detach else None),
                                    check=check, **self._long({}))
        if remove and not detach and result.returncode == 0:
            self.containers.remove(name)  # gone with --rm; the role can be used again
        return result

    def exec(self, role, argv, *, user=None, env=None, input=None, stdout=None, timeout=600, max_output=None,
             check=True, workdir=None):
        """`podman exec` in a running throwaway container of this job."""
        name = self.name(role)
        if name not in self.containers:
            raise BackupError('internal-error', '找不到這個作業的暫用容器。')
        command = ['exec']
        if input is not None:
            command.append('--interactive')
        if user is not None:
            if not USER_RE.fullmatch(str(user)):
                raise BackupError('internal-error', '容器使用者格式不正確。')
            command += ['--user', str(user)]
        if workdir is not None:
            if not TARGET_RE.fullmatch(workdir):
                raise BackupError('internal-error', '容器工作目錄格式不正確。')
            command += ['--workdir', workdir]
        for key, value in sorted((env or {}).items()):
            if not ENV_KEY_RE.fullmatch(key) or not isinstance(value, str) or not ENV_VALUE_RE.fullmatch(value):
                raise BackupError('internal-error', '容器環境變數格式不正確。')
            command += ['--env', f'{key}={value}']
        command.append(name)
        for arg in argv:
            if not isinstance(arg, str) or '\x00' in arg:
                raise BackupError('internal-error', '容器命令格式不正確。')
            command.append(arg)
        self._stopped()
        return self.runner.podman(*command, input=input, stdout=stdout, timeout=self._wait(timeout), max_output=max_output,
                                  check=check, **self._long({}))

    def stop(self, role, timeout=STOP_TIMEOUT):
        """Stop a container (its image's stop signal, then SIGKILL after `timeout` seconds); returns its exit code."""
        name = self.name(role)
        self.runner.podman('stop', '--time', str(int(timeout)), name, timeout=int(timeout) + 60,
                           max_output=64 * 1024)
        return self.exit_code(role)

    def exit_code(self, role):
        out = self.runner.podman('container', 'inspect', '--format', '{{.State.ExitCode}}', self.name(role),
                                 timeout=SHORT_TIMEOUT, max_output=64 * 1024).stdout or b''
        try:
            return int(out.decode('ascii', 'replace').strip())
        except ValueError:
            raise BackupError('job-failed', '無法讀取暫用容器的結束狀態。') from None

    def running(self, role):
        result = self.runner.podman('container', 'inspect', '--format', '{{.State.Running}}', self.name(role),
                                    timeout=SHORT_TIMEOUT, max_output=64 * 1024, check=False)
        return result.returncode == 0 and (result.stdout or b'').strip() == b'true'

    def remove(self, role):
        """Remove one container now (it is no longer needed); True when it is gone. One that cannot be removed only
        takes space (X-TC-05): it stays listed for cleanup() and the sweeps, the log says so once, and the job goes on."""
        return self._drop_or_note('container', self.name(role))

    def remove_volume(self, role):
        """Remove one volume now (frees its space before the job goes on); True when it is gone. Like `remove`: a
        volume that cannot be removed is no reason to stop the app."""
        return self._drop_or_note('volume', self.name(role))

    def _drop(self, kind, name):
        """Remove one object of this job now; True when it is gone (then it is no longer listed). Podman's own answer
        is only trusted when it says the object is not there (`_exists`)."""
        result = _quiet(self.runner, *REMOVE_ARGS[kind], name)
        if (result is None or result.returncode != 0) and _exists(self.runner, kind, name):
            return False
        with contextlib.suppress(ValueError):
            getattr(self, kind + 's').remove(name)
        return True

    def _drop_or_note(self, kind, name):
        if self._drop(kind, name):
            return True
        if (kind, name) not in self._noted:
            self._noted.add((kind, name))
            self.log(f'提示：有一個暫用{KIND_LABELS[kind]}暫時移除不了（它只佔用空間，不影響資料），作業結束時會再試一次。')
        return False

    def _free_name(self, kind, name, duplicate_message):
        """A role is used again while its object is still listed: fine when an earlier removal failed and works now; a
        leftover that stays stops the app that needs its name; a name that was never let go is a programming error."""
        if (kind, name) not in self._noted:
            raise BackupError('internal-error', duplicate_message)
        if not self._drop(kind, name):
            raise BackupError('job-failed', f'先前的暫用{KIND_LABELS[kind]}還沒能移除，無法再用同一個名稱建立新的。')

    def user_ids(self, role, image, user):
        """(uid, gid) of `user` in `image` (a throwaway `id` run)."""
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user):
            raise BackupError('internal-error', '容器使用者格式不正確。')
        out = self.run(role, image, ['-c', f'id -u {user} && id -g {user}'], entrypoint='sh', timeout=SHORT_TIMEOUT,
                       max_output=64 * 1024, read_only_root=True).stdout or b''
        parts = out.decode('ascii', 'replace').split()
        if len(parts) != 2 or not all(p.isdigit() and int(p) < 2 ** 31 for p in parts):
            raise BackupError('job-failed', f'無法讀取映像 {image[:80]} 中 {user} 帳號的 ID。')
        return int(parts[0]), int(parts[1])

    # ------------------------------------------------------------ data in and out of volumes
    def volume_import(self, role, produce, *, timeout=3 * 3600):
        """Fill the volume `woowbk-<job>-<role>` with the tar stream `produce(fileobj)` writes (a thread feeds
        `podman volume import <name> -` through a pipe, so nothing is staged). The producer's error wins over the
        import's (a broken pipe is only the symptom). A tar whose first member is the top directory ('.') gets that
        entry's owner, group and mode applied to the volume afterwards (_apply_root)."""
        name = self.name(role)
        if name not in self.volumes:
            raise BackupError('internal-error', '只能匯入這個作業建立的資料卷。')
        read_fd, write_fd = os.pipe()
        failure = []
        head = bytearray()

        class _Head:
            """Passes the stream on and keeps its first bytes (where a top-directory entry would be)."""

            def __init__(self, out):
                self.out = out

            def write(self, data):
                if len(head) < ROOT_HEAD_BYTES:
                    head.extend(bytes(data[:ROOT_HEAD_BYTES - len(head)]))
                return self.out.write(data)

            def flush(self):
                return self.out.flush()

        def feed():
            try:
                with os.fdopen(write_fd, 'wb', buffering=1024 * 1024) as out:
                    produce(_Head(out))
            except BaseException as exc:  # noqa: BLE001 - handed to the caller below
                failure.append(exc)

        self._stopped()
        writer = threading.Thread(target=feed, name='woowbackup-volume-import', daemon=True)
        reader = os.fdopen(read_fd, 'rb', buffering=0)
        writer.start()
        try:
            try:
                self.runner.podman('volume', 'import', name, '-', input=reader, timeout=self._wait(timeout), max_output=64 * 1024,
                                   **self._long({}))
            finally:
                reader.close()  # a producer still writing gets EPIPE and stops
                writer.join()
        except BackupError:
            # podman failed because the stream broke off: the producer's reason (wrong key, corrupt backup, space,
            # cancel) is the real one. A termination signal (not a BackupError) always wins.
            if failure and not isinstance(failure[0], (BrokenPipeError, ConnectionError)):
                raise failure[0] from None
            raise
        if failure:
            raise failure[0]
        self._apply_root(name, tar_root(bytes(head)))

    def _apply_root(self, name, root):
        """Owner, group and mode of the tar's top-directory entry on the imported volume. Podman 6.1.1
        (an ARM64 test machine, 2026-11-23) ignores a tar's '.' entry on `volume import` and keeps the top directory as `volume
        create` made it (root, 0755); a throwaway app running as its image user could not write its own data folder
        (EMQX's candidate on its seeded data volume exited at boot: emqx-real-arm-attempt1). Same commands as the
        adapter's _apply_volume_root (inside the owner's user namespace); None = left as Podman made it."""
        if root is None:
            return
        uid, gid, mode = root
        mount = (self.runner.podman('volume', 'inspect', '--format', '{{.Mountpoint}}', name, timeout=SHORT_TIMEOUT,
                                    max_output=64 * 1024).stdout or b'').decode('utf-8', 'replace').strip()
        if not mount.startswith('/') or '\n' in mount or len(mount) > 4096:
            raise BackupError('job-failed', '無法讀取暫用資料卷的位置。')
        self.runner.podman('unshare', 'chown', '--no-dereference', f'{uid}:{gid}', '--', mount, timeout=SHORT_TIMEOUT)
        self.runner.podman('unshare', 'chmod', format(mode, '04o'), '--', mount, timeout=SHORT_TIMEOUT)

    def volume_export(self, role, handle, *, timeout=3 * 3600, max_output=None):
        """`podman volume export` of a throwaway volume into the open binary file `handle` (through the owner-side
        relay, like the adapter's exports)."""
        name = self.name(role)
        if name not in self.volumes:
            raise BackupError('internal-error', '只能匯出這個作業建立的資料卷。')
        self._stopped()
        self.runner.relay(['volume', 'export', name], stdout=handle, timeout=self._wait(timeout), max_output=max_output,
                          **self._long({}))

    def kill_all(self):
        """SIGKILL every container of this job now (the job's watchdog: the disk is running full); never raises."""
        names = list(self.containers)
        if names:
            _quiet(self.runner, 'kill', '--signal', 'KILL', *names)

    # ------------------------------------------------------------ clean-up
    def put_back_later(self, label, action):
        """`action()` puts back something this job changed on the device for its reading (a service it started so a
        database could be read; hatarget.ensure_running): `cleanup` runs it before anything is removed, and again at the
        next `cleanup` while it raises. `label`: what it is, as a short name (it reaches the log)."""
        self._puts_back.append((str(label)[:120], action))

    def _put_back(self):
        """Run what is to be put back (newest first); returns the labels of what could not be (they stay listed)."""
        pending, failed = list(reversed(self._puts_back)), []
        self._puts_back = []
        for label, action in pending:
            try:
                action()
            except Exception:  # noqa: BLE001 - cleanup never raises; the label stays for the next try
                failed.append((label, action))
        self._puts_back = list(reversed(failed))
        return [label for label, _action in failed]

    def cleanup(self):
        """Remove every object this job created (never raises); returns the names that could not be removed (and
        `service:<label>` for what could not be put back)."""
        back = self._put_back()
        if back:
            self.log(f'警告：這個作業為了讀取資料而啟動的服務沒能恢復原狀：{"、".join(back[:5])}；請在匯入後確認它們的狀態。')
        left = []
        for name in reversed(self.containers):
            result = _quiet(self.runner, 'rm', '--force', '--time', '10', name)
            if result is None or (result.returncode != 0 and _exists(self.runner, 'container', name)):
                left.append(name)
        self.containers = list(reversed(left))
        volume_left = []
        for name in reversed(self.volumes):
            result = _quiet(self.runner, 'volume', 'rm', '--force', name)
            if result is None or (result.returncode != 0 and _exists(self.runner, 'volume', name)):
                volume_left.append(name)
        self.volumes = list(reversed(volume_left))
        left.extend(volume_left)
        network_left = []
        for name in reversed(self.networks):
            result = _quiet(self.runner, 'network', 'rm', '--force', name)
            if result is None or (result.returncode != 0 and _exists(self.runner, 'network', name)):
                network_left.append(name)
        self.networks = list(reversed(network_left))
        left.extend(network_left)
        if left:
            self.log(f'警告：有 {len(left)} 個暫用容器或資料卷沒有移除，下次作業開始時會再清除。')
        return left + [f'service:{label}' for label in back]

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.cleanup()


def _quiet(runner, *args):
    try:
        return runner.podman(*args, timeout=SHORT_TIMEOUT, max_output=64 * 1024, check=False)
    except BackupError:
        return None


def _exists(runner, kind, name):
    """True unless podman says the object does not exist (an unanswered question counts as existing)."""
    args = {'container': ('container', 'exists', name), 'volume': ('volume', 'exists', name),
            'network': ('network', 'exists', name)}[kind]
    result = _quiet(runner, *args)
    return result is None or result.returncode != 1


def _labelled(runner, kind):
    """[(name, job id)] of the owner's objects of `kind` that carry the job label (podman's JSON, checked)."""
    args = {'container': ('ps', '--all', '--filter', f'label={LABEL}', '--format', 'json'),
            'volume': ('volume', 'ls', '--filter', f'label={LABEL}', '--format', 'json'),
            'network': ('network', 'ls', '--filter', f'label={LABEL}', '--format', 'json')}[kind]
    out = runner.podman(*args, timeout=LIST_TIMEOUT, max_output=LIST_OUTPUT).stdout or b'[]'
    try:
        rows = json.loads(out.decode('utf-8'))
    except ValueError:
        raise BackupError('job-failed', '無法讀取暫用容器清單。') from None
    if rows is None:
        rows = []
    if not isinstance(rows, list):
        raise BackupError('job-failed', '無法讀取暫用容器清單。')
    found = []
    for row in rows[:10000]:
        if not isinstance(row, dict):
            continue
        if kind == 'container':
            names = row.get('Names') if isinstance(row.get('Names'), list) else []
            name = names[0] if names and isinstance(names[0], str) else None
            labels = row.get('Labels')
        elif kind == 'volume':
            name, labels = row.get('Name'), row.get('Labels')
        else:
            name, labels = row.get('name'), row.get('labels')
        job = labels.get(LABEL) if isinstance(labels, dict) else None
        match = NAME_RE.fullmatch(name) if isinstance(name, str) else None
        # Only objects this engine named for that job: a label alone (something the owner made) is not enough.
        if match and match.group(1) == job:
            found.append((name, job))
    return found


def sweep(runner, alive, *, log=None, only_job=None):
    """Remove the throwaway objects of jobs that no longer run: every labelled, `woowbk-<job>-…`-named container,
    volume and network of the owner whose job `alive(job_id)` says is not queued/running (`only_job`: just that
    job's). Returns (names removed, names that could not be removed: they are still there, the caller keeps them for
    the next sweep; review C-07); raises BackupError when podman cannot list them (the caller retries). One quick
    listing per kind (LIST_TIMEOUT)."""
    removed, left = [], []
    for kind in ('container', 'volume', 'network'):
        for name, job in _labelled(runner, kind):
            if (only_job is not None and job != only_job) or alive(job):
                continue
            args = {'container': ('rm', '--force', '--time', '10', name), 'volume': ('volume', 'rm', '--force', name),
                    'network': ('network', 'rm', '--force', name)}[kind]
            result = _quiet(runner, *args)
            if result is not None and result.returncode == 0 or not _exists(runner, kind, name):
                removed.append(name)
            else:
                left.append(name)
    if log is not None:
        if removed:
            log(f'已清除 {len(removed)} 個先前作業留下的暫用容器或資料卷')
        if left:
            log(f'警告：有 {len(left)} 個先前作業留下的暫用容器或資料卷無法移除，下次會再清除。')
    return removed, left
