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
"""
import contextlib
import json
import os
import re
import shlex
import threading

from .errors import BackupError

LABEL = 'io.woowtech.backup.job'
PREFIX = 'woowbk-'
JOB_RE = re.compile(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
ROLE_RE = re.compile(r'[a-z0-9][a-z0-9-]{0,30}\Z')
NAME_RE = re.compile(r'woowbk-(j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})-([a-z0-9][a-z0-9-]{0,30})\Z')
IMAGE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}\Z')
ENV_KEY_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')
ENV_VALUE_RE = re.compile(r'[^\x00-\x1f\x7f]{0,1024}\Z')
TARGET_RE = re.compile(r'/[A-Za-z0-9_./-]{0,254}\Z')
USER_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,31})?\Z')
# A Quadlet `Secret=` value as podman's --secret takes it: the secret's name, then type/target/uid/gid/mode options.
SECRET_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}\Z')
SECRET_OPTION_RE = re.compile(r'(?:type=(?:mount|env)|target=[A-Za-z0-9_./-]{1,255}|uid=[0-9]{1,10}|gid=[0-9]{1,10}'
                              r'|mode=0?[0-7]{3,4})\Z')
MEMORY = '2g'
PIDS = 1024
SHORT_TIMEOUT = 120
LIST_TIMEOUT = 30
LIST_OUTPUT = 4 * 1024 * 1024
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


class TempObjects:
    """The throwaway objects of one job for one owner (`runner`, an OwnerRunner). Use as a context manager: every
    container, volume and network it created is removed on exit. `log(text)` receives short zh-TW notes."""

    def __init__(self, runner, job_id, *, log=None, memory=MEMORY, pids=PIDS, cpus='auto', abort=None):
        object_name(job_id, 'x')  # checks the job id
        self.runner = runner
        self.job_id = job_id
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

    def name(self, role):
        return object_name(self.job_id, role)

    @property
    def label(self):
        return f'{LABEL}={self.job_id}'

    # ------------------------------------------------------------ objects
    def volume(self, role):
        """Create the volume `woowbk-<job>-<role>`; returns its name."""
        name = self.name(role)
        if name in self.volumes:
            raise BackupError('internal-error', '暫用資料卷名稱重複。')
        self.volumes.append(name)
        self.runner.podman('volume', 'create', '--label', self.label, name, timeout=SHORT_TIMEOUT,
                           max_output=64 * 1024)
        return name

    def network(self, role):
        """Create the internal network `woowbk-<job>-<role>` (no route out, DNS between its containers)."""
        name = self.name(role)
        if name in self.networks:
            raise BackupError('internal-error', '暫用網路名稱重複。')
        self.networks.append(name)
        self.runner.podman('network', 'create', '--internal', '--label', self.label, name, timeout=SHORT_TIMEOUT,
                           max_output=64 * 1024)
        return name

    def run_argv(self, role, image, args=(), *, detach=False, network=None, volumes=(), secrets=(), env=None,
                 entrypoint=None, user=None, workdir=None, interactive=False, remove=False, read_only_root=False):
        """The `podman run` argument list (without `podman`) of a throwaway container; every value is checked.
        `volumes`: (source, target, options|None); a source is a volume name or an absolute host path. `secrets`:
        Quadlet `Secret=` values (quadlet_secrets). `env`: {key: value} (never a secret value: it would be visible
        in the process list)."""
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
        if entrypoint is not None:
            if not isinstance(entrypoint, str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,255}', entrypoint):
                raise BackupError('internal-error', '容器進入點格式不正確。')
            argv += ['--entrypoint', entrypoint]
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
        for spec in secrets:
            parts = str(spec).split(',')
            if not SECRET_NAME_RE.fullmatch(parts[0]) or not all(SECRET_OPTION_RE.fullmatch(p) for p in parts[1:]):
                raise BackupError('internal-error', '容器機密掛載格式不正確。')
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
            raise BackupError('internal-error', '暫用容器名稱重複。')
        self._stopped()
        remove = (not detach) if remove is None else remove
        argv = self.run_argv(role, image, args, detach=detach, interactive=input is not None, remove=remove,
                             **options)
        self.containers.append(name)
        result = self.runner.podman(*argv, input=input, stdout=stdout, timeout=timeout,
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
        return self.runner.podman(*command, input=input, stdout=stdout, timeout=timeout, max_output=max_output,
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
        """Remove one container now (it is no longer needed)."""
        name = self.name(role)
        self.runner.podman('rm', '--force', '--time', '10', name, timeout=SHORT_TIMEOUT, max_output=64 * 1024,
                           check=False)
        with contextlib.suppress(ValueError):
            self.containers.remove(name)

    def remove_volume(self, role):
        """Remove one volume now (frees its space before the job goes on)."""
        name = self.name(role)
        self.runner.podman('volume', 'rm', '--force', name, timeout=SHORT_TIMEOUT, max_output=64 * 1024, check=False)
        with contextlib.suppress(ValueError):
            self.volumes.remove(name)

    def user_ids(self, role, image, user):
        """(uid, gid) of `user` in `image` (a throwaway `id` run)."""
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user):
            raise BackupError('internal-error', '容器使用者格式不正確。')
        out = self.run(role, image, ['-c', f'id -u {user} && id -g {user}'], entrypoint='sh', timeout=SHORT_TIMEOUT,
                       max_output=64 * 1024).stdout or b''
        parts = out.decode('ascii', 'replace').split()
        if len(parts) != 2 or not all(p.isdigit() and int(p) < 2 ** 31 for p in parts):
            raise BackupError('job-failed', f'無法讀取映像 {image[:80]} 中 {user} 帳號的 ID。')
        return int(parts[0]), int(parts[1])

    # ------------------------------------------------------------ data in and out of volumes
    def volume_import(self, role, produce, *, timeout=3 * 3600):
        """Fill the volume `woowbk-<job>-<role>` with the tar stream `produce(fileobj)` writes (a thread feeds
        `podman volume import <name> -` through a pipe, so nothing is staged). The producer's error wins over the
        import's (a broken pipe is only the symptom)."""
        name = self.name(role)
        if name not in self.volumes:
            raise BackupError('internal-error', '只能匯入這個作業建立的資料卷。')
        read_fd, write_fd = os.pipe()
        failure = []

        def feed():
            try:
                with os.fdopen(write_fd, 'wb', buffering=1024 * 1024) as out:
                    produce(out)
            except BaseException as exc:  # noqa: BLE001 - handed to the caller below
                failure.append(exc)

        self._stopped()
        writer = threading.Thread(target=feed, name='woowbackup-volume-import', daemon=True)
        reader = os.fdopen(read_fd, 'rb', buffering=0)
        writer.start()
        try:
            try:
                self.runner.podman('volume', 'import', name, '-', input=reader, timeout=timeout, max_output=64 * 1024,
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

    def volume_export(self, role, handle, *, timeout=3 * 3600, max_output=None):
        """`podman volume export` of a throwaway volume into the open binary file `handle` (through the owner-side
        relay, like the adapter's exports)."""
        name = self.name(role)
        if name not in self.volumes:
            raise BackupError('internal-error', '只能匯出這個作業建立的資料卷。')
        self._stopped()
        self.runner.relay(['volume', 'export', name], stdout=handle, timeout=timeout, max_output=max_output,
                          **self._long({}))

    def kill_all(self):
        """SIGKILL every container of this job now (the job's watchdog: the disk is running full); never raises."""
        names = list(self.containers)
        if names:
            _quiet(self.runner, 'kill', '--signal', 'KILL', *names)

    # ------------------------------------------------------------ clean-up
    def cleanup(self):
        """Remove every object this job created (never raises); returns the names that could not be removed."""
        left = []
        for name in reversed(self.containers):
            result = _quiet(self.runner, 'rm', '--force', '--time', '10', name)
            if result is None or (result.returncode != 0 and _exists(self.runner, 'container', name)):
                left.append(name)
        self.containers = []
        for name in reversed(self.volumes):
            result = _quiet(self.runner, 'volume', 'rm', '--force', name)
            if result is None or (result.returncode != 0 and _exists(self.runner, 'volume', name)):
                left.append(name)
        self.volumes = []
        for name in reversed(self.networks):
            result = _quiet(self.runner, 'network', 'rm', '--force', name)
            if result is None or (result.returncode != 0 and _exists(self.runner, 'network', name)):
                left.append(name)
        self.networks = []
        if left:
            self.log(f'警告：有 {len(left)} 個暫用容器或資料卷沒有移除，下次作業開始時會再清除。')
        return left

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
