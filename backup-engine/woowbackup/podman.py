"""Run commands as an application owner (rootless Podman + user systemd). Owner: E2.

Root never opens paths inside the owner's home: file I/O there is executed as the owner.

Every owner command is `runuser -u <owner> -- env -i <fixed environment> <fixed argv>` with the
owner's home as working directory. File access inside the home goes through FILE_HELPER, a fixed
Python snippet run as the owner that walks every path component with O_NOFOLLOW and moves data
over stdin/stdout only. Secrets and keys never appear in argv or in the environment.
"""
import json
import os
import pwd
import re
import signal
import subprocess
from dataclasses import dataclass

from .errors import BackupError

RUNUSER = '/usr/sbin/runuser'
ENV = '/usr/bin/env'
PODMAN = '/usr/bin/podman'
SYSTEMCTL = '/usr/bin/systemctl'
PYTHON = '/usr/bin/python3'
SAFE_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
ROOT_ENV = {'PATH': SAFE_PATH, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
OWNER_RE = re.compile(r'[a-z_][a-z0-9_-]{0,31}\Z')
REL_SEGMENT_RE = re.compile(r'[A-Za-z0-9._@+-]{1,255}\Z')
DEVNULL = subprocess.DEVNULL
MAX_FILE_BYTES = 16 * 1024 * 1024

# Exit codes of FILE_HELPER, mapped to BackupError codes by OwnerRunner.
HELPER_ERRORS = {3: 'not-found', 4: 'not-regular', 5: 'too-large', 6: 'bad-path', 7: 'bad-mode', 8: 'bad-command'}

# Executed as the owner with `python3 -I -c`. Operations:
#   read <rel> <max>          file bytes -> stdout
#   write <rel> <mode> <max>  stdin -> temp file (O_EXCL|O_NOFOLLOW) -> fchmod -> fsync -> rename
#   remove <rel>              unlink a non-directory ("removed"/"absent" on stdout)
#   stat <rel>...             JSON list of {path,type,size,mode}
#   relay /usr/bin/podman ... run podman with an owner-created stdout pipe and copy it to our stdout
#                             (podman volume export reopens /dev/stdout, which fails on root-owned fds)
FILE_HELPER = r'''
import errno, json, os, stat, subprocess, sys
CODES = {'not-found': 3, 'not-regular': 4, 'too-large': 5, 'bad-path': 6, 'bad-mode': 7, 'bad-command': 8}
def die(code):
    sys.stderr.write(code + '\n')
    sys.exit(CODES.get(code, 1))
def split(rel):
    parts = rel.split('/')
    if not rel or len(rel) > 1024 or rel.startswith('/') or '\0' in rel or any(p in ('', '.', '..') for p in parts):
        die('bad-path')
    return parts
def walk(rel, create=False):
    parts = split(rel)
    fd = os.open(os.environ['HOME'], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    for part in parts[:-1]:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            nfd = os.open(part, flags, dir_fd=fd)
        except FileNotFoundError:
            if not create:
                raise
            os.mkdir(part, 0o700, dir_fd=fd)
            nfd = os.open(part, flags, dir_fd=fd)
        os.close(fd)
        fd = nfd
    return fd, parts[-1]
def write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]
def op_read(rel, limit):
    dfd, name = walk(rel)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        die('not-regular')
    if st.st_size > limit:
        die('too-large')
    total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            die('too-large')
        write_all(1, chunk)
def op_write(rel, mode, limit):
    if mode & ~0o644:
        die('bad-mode')
    dfd, name = walk(rel, create=True)
    tmp = '.%s.woowbk-%s' % (name[:200], os.urandom(6).hex())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    try:
        total = 0
        while True:
            chunk = os.read(0, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                die('too-large')
            write_all(fd, chunk)
        os.fchmod(fd, mode)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        tmp = None
        os.fsync(dfd)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
def op_remove(rel):
    try:
        dfd, name = walk(rel)
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        sys.stdout.write('absent')
        return
    if stat.S_ISDIR(st.st_mode):
        die('not-regular')
    os.unlink(name, dir_fd=dfd)
    sys.stdout.write('removed')
def op_stat(rels):
    result = []
    for rel in rels:
        try:
            dfd, name = walk(rel)
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            result.append({'path': rel, 'type': 'missing'})
            continue
        except OSError:
            result.append({'path': rel, 'type': 'blocked'})
            continue
        kind = 'file' if stat.S_ISREG(st.st_mode) else 'dir' if stat.S_ISDIR(st.st_mode) else 'link' if stat.S_ISLNK(st.st_mode) else 'other'
        result.append({'path': rel, 'type': kind, 'size': st.st_size, 'mode': stat.S_IMODE(st.st_mode)})
    sys.stdout.write(json.dumps(result))
def op_relay(argv):
    if not argv or argv[0] != '/usr/bin/podman':
        die('bad-command')
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE)
    while True:
        chunk = os.read(proc.stdout.fileno(), 1 << 16)
        if not chunk:
            break
        write_all(1, chunk)
    sys.exit(proc.wait())
def main():
    op, args = sys.argv[1], sys.argv[2:]
    try:
        if op == 'read':
            op_read(args[0], int(args[1]))
        elif op == 'write':
            op_write(args[0], int(args[1], 8), int(args[2]))
        elif op == 'remove':
            op_remove(args[0])
        elif op == 'stat':
            op_stat(args)
        elif op == 'relay':
            op_relay(args)
        else:
            die('bad-command')
    except FileNotFoundError:
        die('not-found')
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.EISDIR, errno.ENXIO):
            die('not-regular')
        die('io-error')
main()
'''


@dataclass
class Result:
    returncode: int
    stdout: bytes | None
    stderr: bytes


class CommandError(BackupError):
    """A command run as the owner exited non-zero. `stderr` is kept for diagnostics only."""

    def __init__(self, message, *, returncode, stderr=b'', command=''):
        super().__init__('job-failed', message, command=command, returncode=returncode)
        self.returncode = returncode
        self.stderr = stderr or b''


def default_runner(argv, *, input=None, stdout=None, timeout=None, cwd=None, env=None):
    """Subprocess executor: no shell, own process group (killed as a whole on timeout)."""
    if input is not None and not isinstance(input, (bytes, bytearray)):
        try:
            input.fileno()
        except (AttributeError, OSError, ValueError):
            input = input.read()  # in-memory file object: feed its bytes through a pipe
    feed = isinstance(input, (bytes, bytearray))
    stdin = subprocess.PIPE if feed else (input if input is not None else subprocess.DEVNULL)
    proc = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.PIPE if stdout is None else stdout,
                            stderr=subprocess.PIPE, cwd=cwd, env=env, close_fds=True, start_new_session=True)
    try:
        out, err = proc.communicate(input=bytes(input) if feed else None, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        raise
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        raise
    return Result(proc.returncode, out, err or b'')


def describe(argv):
    """Short, secret-free description of a command for messages and logs."""
    argv = [str(a) for a in argv]
    if not argv:
        return ''
    name = os.path.basename(argv[0])
    if name.startswith('python3') and len(argv) > 4 and argv[1:3] == ['-I', '-c']:
        op, rest = argv[4], argv[5:]
        if op == 'relay':
            return describe(rest)
        return f'owner-file {op} {rest[0] if rest else ""}'.strip()
    words = [name] + [a for a in argv[1:] if not a.startswith('-')][:3]
    return ' '.join(words)[:200]


def stderr_tail(data, lines=3, width=200):
    """Last few stderr lines, without echoed SQL ("Command was:") — for job logs only."""
    text = (data or b'').decode('utf-8', 'replace')
    kept = []
    for line in text.splitlines():
        if line.strip().startswith('Command was:'):
            break
        if line.strip() and 'level=warning' not in line:
            kept.append(line.strip()[:width])
    return kept[-lines:]


def validate_rel_path(rel):
    if not isinstance(rel, str) or not rel or len(rel) > 1024 or rel.startswith('/'):
        raise BackupError('invalid-request', '檔案路徑不正確。')
    for segment in rel.split('/'):
        if segment in ('.', '..') or not REL_SEGMENT_RE.fullmatch(segment):
            raise BackupError('invalid-request', '檔案路徑不正確。')
    return rel


class OwnerRunner:
    def __init__(self, owner, *, runner=None, user_lookup=None):
        """`runner` injects a fake subprocess executor in tests."""
        if not isinstance(owner, str) or not OWNER_RE.fullmatch(owner) or owner == 'root':
            raise BackupError('invalid-request', '應用擁有者帳號名稱不正確。')
        lookup = user_lookup or pwd.getpwnam
        try:
            account = lookup(owner)
        except KeyError:
            raise BackupError('owner-missing', f'找不到應用擁有者帳號 {owner}。', owner=owner) from None
        if account.pw_uid == 0:
            raise BackupError('invalid-request', '不支援 root 擁有的應用。')
        home = account.pw_dir
        if not isinstance(home, str) or not home.startswith('/') or os.path.normpath(home) != home or '\n' in home:
            raise BackupError('owner-missing', f'帳號 {owner} 的家目錄設定不正確。', owner=owner)
        self.owner = owner
        self.uid = account.pw_uid
        self.gid = account.pw_gid
        self.home = home
        self._runner = runner or default_runner

    @property
    def runtime_dir(self):
        return f'/run/user/{self.uid}'

    def prefix(self):
        return [RUNUSER, '-u', self.owner, '--', ENV, '-i', f'PATH={SAFE_PATH}', f'HOME={self.home}', 'LANG=C.UTF-8',
                f'XDG_RUNTIME_DIR=/run/user/{self.uid}',
                f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{self.uid}/bus']

    def run(self, argv, *, input=None, stdout=None, timeout=300, check=True):
        """Run fixed `argv` as the owner. `input`: bytes or a readable file; `stdout`: None (capture),
        a writable file, or DEVNULL. Returns Result; raises CommandError when `check` and exit != 0."""
        argv = [str(arg) for arg in argv]
        if not argv or any('\0' in arg for arg in argv):
            raise BackupError('internal-error', '內部命令格式不正確。')
        what = describe(argv)
        try:
            result = self._runner(self.prefix() + argv, input=input, stdout=stdout, timeout=timeout,
                                  cwd=self.home, env=dict(ROOT_ENV))
        except subprocess.TimeoutExpired:
            raise BackupError('job-failed', f'{what} 執行逾時（{timeout} 秒）。', command=what) from None
        except FileNotFoundError:
            raise BackupError('owner-missing', f'無法以帳號 {self.owner} 執行命令（家目錄或工具不存在）。',
                              owner=self.owner) from None
        except OSError:
            raise BackupError('job-failed', f'無法執行 {what}。', command=what) from None
        if check and result.returncode != 0:
            raise CommandError(f'{what} 執行失敗（結束碼 {result.returncode}）。', returncode=result.returncode,
                               stderr=result.stderr, command=what)
        return result

    def podman(self, *args, **kwargs):
        return self.run([PODMAN, *args], **kwargs)

    def systemctl(self, *args, **kwargs):
        return self.run([SYSTEMCTL, '--user', *args], **kwargs)

    def relay(self, podman_args, *, stdout, timeout=3600, check=True):
        """`podman <args>` whose stdout is an owner-created pipe, copied to `stdout` by the helper."""
        return self.run([PYTHON, '-I', '-c', FILE_HELPER, 'relay', PODMAN, *podman_args], stdout=stdout,
                        timeout=timeout, check=check)

    def _helper(self, args, **kwargs):
        result = self.run([PYTHON, '-I', '-c', FILE_HELPER, *args], check=False, **kwargs)
        if result.returncode:
            code = HELPER_ERRORS.get(result.returncode, 'io-error')
            rel = args[1] if len(args) > 1 else ''
            if code == 'not-found':
                raise BackupError('not-found', f'找不到檔案 ~/{rel}。', path=rel)
            if code == 'not-regular':
                raise BackupError('permission-denied', f'~/{rel} 不是一般檔案，或路徑中含有符號連結。', path=rel)
            if code == 'too-large':
                raise BackupError('limit-exceeded', f'~/{rel} 超過大小上限。', path=rel)
            raise BackupError('job-failed', f'無法以擁有者身分存取 ~/{rel}。', path=rel)
        return result

    def read_file(self, rel_path, max_bytes=MAX_FILE_BYTES):
        validate_rel_path(rel_path)
        return self._helper(['read', rel_path, str(int(max_bytes))], timeout=120).stdout or b''

    def write_file(self, rel_path, data, mode):
        """`data`: bytes or a readable binary file; `mode`: int or octal string, subset of 0644."""
        validate_rel_path(rel_path)
        mode = int(mode, 8) if isinstance(mode, str) else int(mode)
        if mode & ~0o644:
            raise BackupError('invalid-request', '檔案權限不可超過 0644。')
        self._helper(['write', rel_path, format(mode, '04o'), str(MAX_FILE_BYTES)], input=data, timeout=120)

    def remove_file(self, rel_path):
        """Remove a regular file or symlink; returns True when something was removed."""
        validate_rel_path(rel_path)
        return (self._helper(['remove', rel_path], timeout=60).stdout or b'').strip() == b'removed'

    def stat_files(self, rel_paths):
        """{rel: {'type': 'file'|'dir'|'link'|'other'|'missing'|'blocked', 'size', 'mode'}}."""
        rel_paths = [validate_rel_path(rel) for rel in rel_paths]
        if not rel_paths:
            return {}
        out = self._helper(['stat', *rel_paths], timeout=60).stdout or b'[]'
        try:
            rows = json.loads(out.decode('utf-8'))
        except ValueError:
            raise BackupError('job-failed', '無法讀取擁有者檔案狀態。') from None
        return {row['path']: row for row in rows if isinstance(row, dict) and row.get('path') in rel_paths}
