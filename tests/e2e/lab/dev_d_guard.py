"""Shared guards of the dev-d real-run harnesses (lane services-a-2): the committed-tree check, dev-d's outer
isolation record and the dev-d mutation lock taken the way the team agreed.

* `clean_tree(repo)` -- every tracked and untracked change of the checkout, except evidence folders (records of
  earlier attempts waiting for their commit), refuses the run: the code that runs must be the commit it names.
* `verify_isolation(owner_sh)` -- `owner.sh d --verify-isolation` (read-only `labpodman inspect` of dev-d: running,
  network none, no published port); only its one fixed line is returned, anything else raises.
* `acquire(lock, waiting, timeout)` -- the dev-d mutation lock, waited for like `flock -w` (blocking in 30 s ticks,
  so a blocking waiter gets no head start), but never kept while emqx-main asks for the next turn (its waiting file
  exists): then it is released at once. A waiting file seen while an emqx-main run itself HOLDS the lock is not a
  request for the next turn (emqx-main removes it when its run starts; the same file left behind is stale).
"""
import fcntl
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

LOCK = Path('/tmp/woowbk-dev-d-mutation.lock')
WAITING = Path('/tmp/woowbk-dev-d-emqx-main-waiting')
ISOLATION_LINE = 'dev-d isolation: true none {}'
EVIDENCE_PREFIXES = ('tests/e2e/lab/evidence/', 'tests/backup/evidence/')
EMQX_MAIN_MARKERS = (b'run_emqx_real_owner.sh', b'emqx_real_owner_transport.py')


class GuardError(RuntimeError):
    """A fixed-word reason (never a value) why a real run may not continue."""


def changed_paths(repo, *, run=subprocess.run):
    proc = run(['git', '-C', str(repo), 'status', '--porcelain=v1', '-z', '--untracked-files=all'],
               capture_output=True, timeout=60)
    if proc.returncode != 0:
        raise GuardError('git_status_failed')
    paths = []
    fields = proc.stdout.split(b'\0')
    index = 0
    while index < len(fields):
        field = fields[index]
        index += 1
        if len(field) < 4:
            continue
        code, path = field[:2], field[3:].decode('utf-8', 'replace')
        paths.append(path)
        if code[:1] in (b'R', b'C'):
            # a rename/copy names its source in the next field: both sides are changes
            if index < len(fields) and fields[index]:
                paths.append(fields[index].decode('utf-8', 'replace'))
            index += 1
    return paths


def clean_tree(repo, *, run=subprocess.run, exclude=EVIDENCE_PREFIXES):
    """(clean, the changed paths outside the evidence folders)."""
    dirty = [p for p in changed_paths(repo, run=run) if not p.startswith(tuple(exclude))]
    return not dirty, dirty


def head(repo, *, run=subprocess.run):
    proc = run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], capture_output=True, timeout=60)
    commit = proc.stdout.decode().strip()
    if proc.returncode != 0 or len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
        raise GuardError('git_head_unreadable')
    return commit


def verify_isolation(owner_sh, *, run=subprocess.run):
    proc = run(['bash', str(owner_sh), 'd', '--verify-isolation'], capture_output=True, timeout=120)
    line = proc.stdout.decode('utf-8', 'replace').strip()
    if proc.returncode != 0 or line != ISOLATION_LINE:
        raise GuardError('dev_d_isolation_failed')
    return line


def waiting_mtime(waiting=WAITING):
    try:
        return os.stat(waiting).st_mtime_ns
    except FileNotFoundError:
        return None


def emqx_main_holds_lock(lock=LOCK, proc_root=Path('/proc')):
    """True only while an emqx-main run HOLDS the lock: one of its processes has the lock file open on a file
    description that carries the flock (a `lock:` line in its fdinfo). Opening the file alone is not holding it."""
    target = str(lock)
    for proc in proc_root.iterdir():
        if not proc.name.isdigit():
            continue
        try:
            cmd = (proc / 'cmdline').read_bytes()
            if not any(marker in cmd for marker in EMQX_MAIN_MARKERS):
                continue
            for fd in (proc / 'fd').iterdir():
                if os.readlink(fd) == target:
                    info = (proc / 'fdinfo' / fd.name).read_text()
                    if any(line.startswith('lock:') and 'FLOCK' in line for line in info.splitlines()):
                        return True
        except OSError:
            continue
    return False


class _Tick(Exception):
    pass


def _tick(_signum, _frame):
    raise _Tick()


def open_lock(lock=LOCK):
    fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CREAT, 0o664)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
        os.close(fd)
        raise GuardError('unsafe_dev_d_lock_file')
    return fd


def acquire(lock=LOCK, waiting=WAITING, timeout=3600, *, holds=emqx_main_holds_lock, sleep=time.sleep,
            clock=time.monotonic, tick=30):
    """Returns (fd holding the lock, seconds waited). The caller closes the fd to release it."""
    fd = open_lock(lock)
    previous = signal.signal(signal.SIGALRM, _tick)
    started = clock()
    stale = None
    try:
        while True:
            if clock() - started > timeout:
                raise GuardError('dev_d_lock_timeout')
            mtime = waiting_mtime(waiting)
            if mtime is not None and holds(lock):
                stale = mtime
            if mtime is not None and mtime != stale:
                sleep(5)
                continue
            signal.alarm(max(1, min(int(tick), int(timeout) or 1)))
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except _Tick:
                continue
            finally:
                signal.alarm(0)
            mtime = waiting_mtime(waiting)
            if mtime is not None and mtime != stale:
                fcntl.flock(fd, fcntl.LOCK_UN)
                sleep(5)
                continue
            return fd, int(clock() - started)
    except BaseException:
        os.close(fd)
        raise
    finally:
        signal.signal(signal.SIGALRM, previous)
