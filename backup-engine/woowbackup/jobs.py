"""Job records, systemd-run launcher, locks, recovery and retention (CONTRACT section 8). Owner: E2.

* `start_job` validates, deduplicates by request_id (24 h), refuses with `busy` while another job is
  queued/running, writes the record and launches `systemd-run … run-job <id>` (injectable).
* `run_job` holds an exclusive flock on `paths.lock` (the engine lock) for its lifetime, rewrites its
  record at every phase/progress change and always deletes the job key file. It writes its final state
  before it releases the engine lock.
* Locks, always taken in this order: `start_lock` (helper commands that decide: start, recover, cancel,
  delete) -> the engine lock -> a record lock (`jobs/<id>.lock`, re-entrant within a thread). Every write
  of an existing record happens under its record lock, and every decision that depends on what a record
  says (queued -> running, a failed launch, job-cancel, leaving the cancellable window, recovery,
  retention) re-reads the record under that lock. Readers take no lock: a record is only ever replaced
  whole, by rename.
* `recover_interrupted` decides only while it holds the start lock and, taken without waiting, the engine
  lock, so no job can be running or finishing meanwhile. For each candidate it probes the unit and then
  re-reads the record under its record lock: a record still queued/running whose unit is inactive is
  marked `interrupted`, and the writers / host directories / unfinished fresh deployment that this fresh record
  (never the earlier listing) still lists are restarted / settled / removed, each once. A job that finished while the
  records
  were listed therefore keeps its own final record (release regression 16). Nothing is ever replayed. It
  also deletes stale transient key files and staging folders of jobs that are not running.
* Retention: records of active jobs, records with recovery work left and failed/interrupted restores whose
  safety backup is still pinned are always kept; of the other (finished) records only the newest
  KEEP_TERMINAL are kept, with their logs. So status/jobs/job-status read a bounded number of records.
* Cancellation is a request file, accepted only while the record says the job is cancellable and honoured
  at the job's next checkpoint. Leaving the cancellable window is itself such a checkpoint, checked under
  the record lock, so an accepted cancel is never followed by a destructive step.
"""
import calendar
import contextlib
import fcntl
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

from .errors import BackupError

PHASES = {
    'backup': (('prepare', '準備'), ('check', '檢查空間與應用'), ('stop', '暫停應用寫入'), ('dump', '匯出資料庫'),
               ('export', '匯出資料卷與設定'), ('start', '恢復應用'), ('package', '加密封裝'), ('verify', '驗證備份')),
    # `stage`: host directories are written next to the current ones while the apps still run (nothing that exists
    # changes); the safety backup then keeps the writers stopped for the restore (CONTRACT section 9).
    'restore': (('prepare', '準備'), ('decrypt', '解密並驗證檔案'), ('preflight', '相容性檢查'),
                ('stage', '預先寫入主機資料夾'), ('safety', '建立還原前備份'), ('stop', '停止應用'), ('restore', '還原資料'),
                ('start', '啟動應用'), ('check', '健康與資料核對')),
    'verify': (('prepare', '準備'), ('decrypt', '解密並驗證檔案'), ('check', '核對結果')),
    # An unencrypted copy of an encrypted backup for one download (CONTRACT section 8); nothing on the device changes.
    'export': (('prepare', '準備'), ('decrypt', '解密並驗證檔案'), ('package', '封裝未加密副本'), ('verify', '驗證副本')),
}
PLAIN_PACKAGE_LABEL = '封裝（未加密）'  # the package phase of a backup made with 加密此備份 off encrypts nothing
ACTIVE = ('queued', 'running')
TERMINAL = ('succeeded', 'failed', 'rolled-back', 'interrupted', 'cancelled')
PUBLIC_KEYS = ('id', 'type', 'state', 'phase', 'phases', 'progress', 'created', 'started', 'finished', 'params',
               'result', 'error', 'cancellable')
JOB_ID_RE = re.compile(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
REQUEST_ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}\Z')
DEDUP_SECONDS = 24 * 3600
QUEUED_GRACE_SECONDS = 120
MAX_RECORD_BYTES = 1024 * 1024
MAX_LOG_LINE = 500
LOCK_WAIT_SECONDS = 120
KEY_FILE_MAX_AGE = 15 * 60  # an inspect takes seconds; older key-inspect-* files were left by a killed helper
KEEP_TERMINAL = 200  # finished records kept (with their logs) besides the ones that are still needed
ORPHAN_MAX_AGE = 3600  # a log / lock / cancel request / temp file without its record is removed after this
SIDE_FILE_RE = re.compile(r'(j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})\.(?:log|lock|cancel)\Z')
TEMP_FILE_RE = re.compile(r'\.j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.json\.[0-9a-f]+\.tmp\Z')
# The job unit is bounded independently of the containers it talks to (review finding SEC-3).
UNIT_LIMITS = ('--property=MemoryMax=50%', '--property=TasksMax=512')
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
SECRET_PATTERN = re.compile(r'AGE-SECRET-KEY-1[0-9A-Za-z]+')

INTERRUPTED_MESSAGE = {
    'backup': '備份作業意外中斷（例如系統重新開機或程序被終止）。請確認應用已恢復執行後再重新備份。',
    'restore': '還原作業意外中斷（例如系統重新開機或程序被終止），應用可能處於不完整狀態。請檢查應用狀態，'
               '必要時使用還原前備份再次還原。',
    'verify': '驗證作業意外中斷，請重新執行驗證。',
    'export': '建立未加密副本的作業意外中斷，請重新建立；未完成的副本已清除。',
}
FRESH_MESSAGE = '全新部署（{apps}）沒有完成；系統會清除未完成的部署，之後可再次還原同一份備份。'
FINISHING_MESSAGE = ('還原已完成並通過檢查，但在刪除主機資料夾被取代的舊內容時作業中斷（例如系統重新開機）。'
                     '系統會接手整理留下的資料夾；應用不需要再次還原。')


class Terminated(BaseException):
    """SIGTERM/SIGINT/SIGHUP during run-job; cleanup (finally blocks, rollback) still runs."""


# ---------------------------------------------------------------- small helpers

def utc_iso(ts=None):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() if ts is None else ts))


def parse_iso(text):
    try:
        return calendar.timegm(time.strptime(text, '%Y-%m-%dT%H:%M:%SZ'))
    except (TypeError, ValueError):
        return None


def new_job_id(now=None):
    return 'j' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(time.time() if now is None else now)) + '-' + \
        secrets.token_hex(4)


def valid_job_id(job_id):
    return isinstance(job_id, str) and JOB_ID_RE.fullmatch(job_id) is not None


def redact(text):
    return SECRET_PATTERN.sub('[已遮蔽]', str(text))


def _ensure_private_dir(path):
    path = Path(path)
    if not os.path.lexists(path):
        if not path.parent.exists():
            _ensure_private_dir(path.parent)
        with contextlib.suppress(FileExistsError):
            os.mkdir(path, 0o700)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise BackupError('internal-error', '備份作業目錄不安全（不是目錄或為符號連結）。')
    return path


def _json_bytes(obj):
    """UTF-8 JSON; text that cannot be UTF-8 (lone surrogates from hostile input) is \\u-escaped instead of
    failing, so a terminal record is always written (review finding SEC-5)."""
    try:
        return (json.dumps(obj, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
    except UnicodeEncodeError:
        return (json.dumps(obj, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii')


def atomic_write_json(path, obj, mode=0o600):
    path = Path(path)
    data = _json_bytes(obj)
    tmp = path.parent / f'.{path.name}.{secrets.token_hex(6)}.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fchmod(fd, mode)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    os.close(fd)
    try:
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def read_json(path, max_bytes=MAX_RECORD_BYTES):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
            raise ValueError('not a small regular file')
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return json.loads(b''.join(chunks).decode('utf-8'))
    finally:
        os.close(fd)


def public_job(record):
    return {key: record.get(key) for key in PUBLIC_KEYS}


def unit_name(job_id):
    return f'woowtech-backup-{job_id}.service'


def has_leftovers(record):
    """The record still lists writers a dead job left stopped, an unfinished fresh deployment, or apps whose host
    directories a dead restore may have left siblings of."""
    return bool(record.get('stopped_writers') or record.get('fresh_apps') or record.get('dir_apps'))


_THREAD = threading.local()


def _held_record_locks():
    """{lock path: depth} of the record locks this thread holds (record locks are re-entrant per thread)."""
    held = getattr(_THREAD, 'record_locks', None)
    if held is None:
        held = _THREAD.record_locks = {}
    return held


# ---------------------------------------------------------------- store

class JobStore:
    def __init__(self, paths):
        self.paths = paths

    def ensure(self):
        _ensure_private_dir(self.paths.data)
        _ensure_private_dir(self.paths.jobs)
        _ensure_private_dir(self.paths.run)

    def _check(self, job_id):
        if not valid_job_id(job_id):
            raise BackupError('invalid-request', '作業 ID 格式不正確。')
        return job_id

    def path(self, job_id):
        return Path(self.paths.jobs) / f'{self._check(job_id)}.json'

    def log_path(self, job_id):
        return Path(self.paths.jobs) / f'{self._check(job_id)}.log'

    def cancel_path(self, job_id):
        return Path(self.paths.jobs) / f'{self._check(job_id)}.cancel'

    def key_path(self, job_id):
        return Path(self.paths.run) / f'key-{self._check(job_id)}'

    def lock_path(self, job_id):
        return Path(self.paths.jobs) / f'{self._check(job_id)}.lock'

    @contextlib.contextmanager
    def locked(self, job_id):
        """Exclusive lock of one record (flock on `jobs/<id>.lock`) around a read-modify-write of it.

        Other threads and processes wait; the same thread may nest it. It is held for short sections only and
        never while waiting for the start or engine lock (those come first when they are taken at all).
        """
        path = str(self.lock_path(job_id))
        held = _held_record_locks()
        if path in held:
            held[path] += 1
            try:
                yield
            finally:
                held[path] -= 1
            return
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                held[path] = 1  # inside the try: a termination signal can never leave a stale entry behind
                yield
            finally:
                held.pop(path, None)
        finally:
            os.close(fd)

    def create(self, job_type, params, *, request_id=None, now=None):
        if job_type not in PHASES:
            raise BackupError('invalid-request', '不支援的作業類型。')
        now = time.time() if now is None else now
        self.ensure()
        job_id = new_job_id(now)
        plain = job_type == 'backup' and isinstance(params, dict) and params.get('encrypt') is False
        record = {
            'id': job_id, 'type': job_type, 'state': 'queued', 'phase': PHASES[job_type][0][0],
            'phases': [{'id': pid, 'label': PLAIN_PACKAGE_LABEL if plain and pid == 'package' else label,
                        'state': 'pending'} for pid, label in PHASES[job_type]],
            'progress': {'percent': 0, 'message': '等待開始'}, 'created': utc_iso(now), 'started': None,
            'finished': None, 'params': params, 'result': None, 'error': None, 'cancellable': True,
            'request_id': request_id, 'unit': unit_name(job_id),
        }
        self.save(record)
        return record

    def get(self, job_id):
        try:
            record = read_json(self.path(job_id))
        except FileNotFoundError:
            raise BackupError('not-found', '找不到指定的作業。', job_id=job_id) from None
        except (OSError, ValueError):
            raise BackupError('not-found', '作業紀錄無法讀取。', job_id=job_id) from None
        if not isinstance(record, dict) or record.get('id') != job_id:
            raise BackupError('not-found', '作業紀錄無法讀取。', job_id=job_id)
        return record

    def save(self, record):
        """Replace the whole record atomically, under its record lock (callers that read it first hold it)."""
        with self.locked(record['id']):
            atomic_write_json(self.path(record['id']), record)

    def ids(self):
        """Ids of the record files, newest first (a job id starts with its UTC creation time)."""
        try:
            names = os.listdir(self.paths.jobs)
        except FileNotFoundError:
            return []
        return sorted((name[:-5] for name in names if name.endswith('.json') and valid_job_id(name[:-5])),
                      reverse=True)

    def list(self, limit=50, *, unreadable=None):
        """Readable records, newest first; reads only as many record files as it returns (plus unreadable ones).
        `unreadable`: a list that receives the ids of record files that could not be read (retention protects every
        backup then; review F11)."""
        records = []
        for job_id in self.ids():
            if limit is not None and len(records) >= limit:
                break
            try:
                records.append(self.get(job_id))
            except BackupError:
                if unreadable is not None:
                    unreadable.append(job_id)
                continue
        return records

    def remove(self, job_id):
        """Delete a finished record with its log, cancel request and lock file (retention).

        Re-checked under the record lock: an active record, or one with recovery work left, is never deleted
        (returns False). The lock file goes last, while it is still held.
        """
        with self.locked(job_id):
            try:
                record = self.get(job_id)
            except BackupError:
                record = None  # unreadable (or already gone): nothing can use it
            if record is not None and (record.get('state') in ACTIVE or has_leftovers(record)):
                return False
            for path in (self.path(job_id), self.log_path(job_id), self.cancel_path(job_id), self.lock_path(job_id)):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path)
        return True

    def append_log(self, job_id, message, now=None):
        line = redact(message).replace('\r', ' ').replace('\n', ' ')[:MAX_LOG_LINE]
        fd = os.open(self.log_path(job_id), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600)
        try:
            os.write(fd, f'{utc_iso(now)} {line}\n'.encode('utf-8', 'backslashreplace'))
        finally:
            os.close(fd)

    def read_log(self, job_id, limit=200):
        try:
            fd = os.open(self.log_path(job_id), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return []
        with os.fdopen(fd, 'rb') as handle:
            size = os.fstat(handle.fileno()).st_size
            handle.seek(max(0, size - 256 * 1024))
            lines = handle.read().decode('utf-8', 'replace').splitlines()
        return [redact(line) for line in lines[-limit:]]

    def request_cancel(self, job_id):
        fd = os.open(self.cancel_path(job_id), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.close(fd)

    def cancel_requested(self, job_id):
        return os.path.lexists(self.cancel_path(job_id))

    def clear_cancel(self, job_id):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.cancel_path(job_id))


# ---------------------------------------------------------------- reporter

class JobReporter:
    """Writer of a running job's record: the whole record is rewritten (under the record lock) on every visible
    change. While the job holds the engine lock nothing else writes its record; the two steps that race with
    helper commands, starting (`begin`) and leaving the cancellable window (`set_cancellable(False)`),
    re-check the record and the cancel request under the record lock."""

    def __init__(self, store, record, *, clock=time.monotonic, min_interval=0.5):
        self.store = store
        self.record = record
        self.clock = clock
        self.min_interval = min_interval
        self._last_save = 0.0
        self._phase_index = 0

    @property
    def job_id(self):
        return self.record['id']

    @property
    def cancellable(self):
        return bool(self.record.get('cancellable'))

    def _save(self):
        self.store.save(self.record)
        self._last_save = self.clock()

    def _ids(self):
        return [p['id'] for p in self.record['phases']]

    def phase(self, phase_id):
        ids = self._ids()
        if phase_id not in ids:
            return
        index = ids.index(phase_id)
        for i, item in enumerate(self.record['phases']):
            if i < index and item['state'] in ('pending', 'active'):
                item['state'] = 'done'
            elif i == index:
                item['state'] = 'active'
            elif i > index and item['state'] in ('active', 'done'):
                item['state'] = 'pending'  # re-entered for the next app of a multi-app job
        self._phase_index = index
        self.record['phase'] = phase_id
        label = self.record['phases'][index]['label']
        self.record['progress'] = {'percent': min(99, int(100 * index / len(ids))), 'message': label}
        self._save()
        self.log(f'階段：{label}')

    def skip(self, phase_id):
        for item in self.record['phases']:
            if item['id'] == phase_id and item['state'] in ('pending', 'active'):
                item['state'] = 'skipped'
        self._save()

    def complete(self, phase_id):
        """Mark one phase done (it finished; the next phase has not started yet)."""
        for item in self.record['phases']:
            if item['id'] == phase_id and item['state'] in ('pending', 'active'):
                item['state'] = 'done'
        self._save()

    def add_phase(self, phase_id, label):
        for item in self.record['phases']:
            if item['state'] == 'active':
                item['state'] = 'failed'
            elif item['state'] == 'pending':
                item['state'] = 'skipped'
        if phase_id not in self._ids():
            self.record['phases'].append({'id': phase_id, 'label': label, 'state': 'pending'})
        self._save()

    def progress(self, percent=None, message=None, *, fraction=None, force=False):
        count = len(self.record['phases'])
        if fraction is not None:
            percent = int(100 * (self._phase_index + max(0.0, min(1.0, fraction))) / count)
        current = self.record['progress']
        if percent is not None:
            current['percent'] = max(0, min(99, int(percent)))
        if message is not None:
            current['message'] = redact(message)[:200]
        if force or self.clock() - self._last_save >= self.min_interval:
            self._save()

    def log(self, message):
        self.store.append_log(self.job_id, message)

    def set_cancellable(self, flag):
        """Open or close the cancellable window.

        Closing it while a cancel request is pending changes nothing and returns True: the caller must stop
        now. job-cancel accepts a request only while the record says cancellable, under the same record lock,
        so a request it accepted is never followed by a destructive step.
        """
        flag = bool(flag)
        with self.store.locked(self.job_id):
            if not flag and self.record.get('cancellable') and self.store.cancel_requested(self.job_id):
                return True
            if bool(self.record.get('cancellable')) != flag:
                self.record['cancellable'] = flag
                self._save()
        return False

    def cancel_requested(self):
        return self.store.cancel_requested(self.job_id)

    def set_partial(self, **fields):
        self.record.update(fields)
        self._save()

    def start(self):
        self.record['state'] = 'running'
        self.record['started'] = utc_iso()
        self._save()

    def begin(self):
        """queued -> running, decided on a fresh read under the record lock (so exactly one of run-job, a failed
        launch and job-cancel wins). Returns 'started', 'cancelled' (cancel requested before the start) or
        'not-queued' (finished, failed to launch, or already taken by another run-job)."""
        with self.store.locked(self.job_id):
            self.record = self.store.get(self.job_id)
            if self.record.get('state') != 'queued':
                return 'not-queued'
            if self.store.cancel_requested(self.job_id):
                self.finish('cancelled')
                return 'cancelled'
            self.start()
        return 'started'

    def finish(self, state, *, result=None, error=None):
        record = self.record
        for item in record['phases']:
            if state == 'succeeded' and item['state'] in ('pending', 'active'):
                item['state'] = 'done'
            elif state == 'rolled-back' and item['id'] == 'rollback' and item['state'] in ('pending', 'active'):
                item['state'] = 'done'
            elif state == 'cancelled' and item['state'] in ('pending', 'active'):
                item['state'] = 'skipped'
            elif state in ('failed', 'interrupted') and item['state'] == 'active':
                item['state'] = 'failed'
        record['state'] = state
        record['finished'] = utc_iso()
        record['cancellable'] = False
        record['result'] = result
        record['error'] = None if error is None else {'code': error['code'], 'message': redact(error['message'])}
        messages = {'succeeded': '已完成', 'failed': '失敗', 'rolled-back': '已自動回復', 'cancelled': '已取消',
                    'interrupted': '已中斷'}
        record['progress'] = {'percent': 100 if state == 'succeeded' else record['progress'].get('percent', 0),
                              'message': messages.get(state, state)}
        self._save()
        self.log(f'作業結束：{messages.get(state, state)}' + (f'（{record["error"]["message"]}）' if record['error'] else ''))


# ---------------------------------------------------------------- locks

@contextlib.contextmanager
def start_lock(paths):
    """Serialises start/recover/cancel decisions (short critical sections)."""
    _ensure_private_dir(paths.run)
    fd = os.open(Path(paths.run) / 'jobs.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def lock_is_free(paths):
    try:
        fd = os.open(paths.lock, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return True
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    finally:
        os.close(fd)
    return True


def acquire_engine_lock(paths, timeout=LOCK_WAIT_SECONDS, *, sleep=time.sleep, clock=time.monotonic):
    """Exclusive flock on paths.lock; returns the fd (keep it open) or None after `timeout`."""
    _ensure_private_dir(paths.run)
    fd = os.open(paths.lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    deadline = clock() + timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            if clock() >= deadline:
                os.close(fd)
                return None
            sleep(0.2)


def try_engine_lock(paths):
    """The engine lock if no job holds it right now (never waits); the fd to close, or None."""
    return acquire_engine_lock(paths, timeout=0)


# ---------------------------------------------------------------- launcher / units

def systemd_run_launcher(paths):
    def launch(job_id):
        argv = ['/usr/bin/systemd-run', f'--unit={unit_name(job_id)}', '--collect', '--quiet',
                '--property=KillMode=mixed', *UNIT_LIMITS, str(paths.helper), 'run-job', job_id]
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    env=dict(SAFE_ENV), timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise BackupError('internal-error', '無法啟動背景作業。') from None
        if result.returncode != 0:
            sys.stderr.write(result.stderr.decode('utf-8', 'replace')[-2000:])
            raise BackupError('internal-error', '無法啟動背景作業。')
    return launch


def systemd_unit_active(unit):
    try:
        result = subprocess.run(['/usr/bin/systemctl', 'show', '--property=ActiveState', '--value', '--', unit],
                                stdin=subprocess.DEVNULL, capture_output=True, env=dict(SAFE_ENV), timeout=20,
                                check=False)
    except (OSError, subprocess.TimeoutExpired):
        return True  # unknown: never declare a job dead on a failed probe
    state = result.stdout.decode('utf-8', 'replace').strip()
    if result.returncode != 0:
        return True
    return state in ('active', 'activating', 'deactivating', 'reloading', 'refreshing')


# ---------------------------------------------------------------- requests (dedup)

def _load_requests(paths, now):
    try:
        data = read_json(paths.requests)
    except FileNotFoundError:
        data = {}
    except (OSError, ValueError):
        data = {}
    entries = data.get('requests') if isinstance(data, dict) else None
    if not isinstance(entries, dict):
        entries = {}
    fresh = {}
    for rid, item in entries.items():
        if (isinstance(item, dict) and isinstance(item.get('created'), (int, float))
                and now - item['created'] < DEDUP_SECONDS and valid_job_id(item.get('job_id'))):
            fresh[rid] = item
    return fresh


def _save_requests(paths, entries):
    atomic_write_json(paths.requests, {'version': 1, 'requests': entries})


def _write_key_file(path, key_text):
    from .keys import normalize_secret
    secret = normalize_secret(key_text)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        data = memoryview((secret + '\n').encode('ascii'))
        while data:
            data = data[os.write(fd, data):]
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_key_file(store, job_id):
    with contextlib.suppress(FileNotFoundError, BackupError):
        os.unlink(store.key_path(job_id))


# ---------------------------------------------------------------- public API

def start_job(paths, job_type, params, request_id, *, key_text=None, launcher=None, unit_active=None, now=None,
              restart_writers=None, cleanup_fresh=None, settle_dirs=None):
    """Create and launch a job; returns {'job_id', 'deduplicated'}."""
    if job_type not in PHASES:
        raise BackupError('invalid-request', '不支援的作業類型。')
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise BackupError('invalid-request', '請求識別碼格式不正確。')
    if key_text is not None:
        from .keys import normalize_secret
        normalize_secret(key_text)  # validate before anything is written
    store = JobStore(paths)
    store.ensure()
    launcher = launcher or systemd_run_launcher(paths)
    now = time.time() if now is None else now
    with start_lock(paths):
        requests = _load_requests(paths, now)
        hit = requests.get(request_id)
        if hit:
            if hit.get('type') != job_type:
                raise BackupError('invalid-request', '此請求識別碼已用於其他類型的作業。')
            try:
                store.get(hit['job_id'])
                return {'job_id': hit['job_id'], 'deduplicated': True}
            except BackupError:
                pass
        _recover_locked(paths, store, unit_active or systemd_unit_active, now, restart_writers, cleanup_fresh,
                        settle_dirs)
        active = [r for r in store.list(limit=None) if r.get('state') in ACTIVE]
        if active:
            raise BackupError('busy', '已有備份或還原作業正在進行，請等它完成後再試。', job_id=active[0]['id'])
        record = store.create(job_type, params, request_id=request_id, now=now)
        job_id = record['id']
        try:
            if key_text is not None:
                _write_key_file(store.key_path(job_id), key_text)
            requests[request_id] = {'job_id': job_id, 'type': job_type, 'created': now}
            _save_requests(paths, requests)
            launcher(job_id)
        except BaseException as exc:
            error = exc if isinstance(exc, BackupError) else BackupError('internal-error', '無法啟動背景作業。')
            if not _fail_unlaunched(store, job_id, error) and isinstance(exc, Exception):
                # The unit started although the launcher reported an error (systemd-run timed out after starting
                # it): the job runs and owns its record, so the caller gets its id like for any started job.
                store.append_log(job_id, '啟動程式回報錯誤，但背景作業已開始執行')
                return {'job_id': job_id, 'deduplicated': False}
            if isinstance(exc, BackupError):
                raise
            raise error from None
        store.append_log(job_id, '作業已排入背景執行')
    return {'job_id': job_id, 'deduplicated': False}


def _fail_unlaunched(store, job_id, error):
    """Mark a job whose launch failed as failed, unless its run-job already took it from 'queued' (then it runs
    and owns the record, key file included). True when it was marked failed. Decided under the record lock,
    so run-job's own queued -> running step sees exactly one of the two."""
    with store.locked(job_id):
        try:
            reporter = JobReporter(store, store.get(job_id))
        except BackupError:
            reporter = None
        if reporter is not None:
            if reporter.record.get('state') != 'queued':
                return False
            reporter.finish('failed', error={'code': error.code, 'message': error.message})
    _remove_key_file(store, job_id)
    return True


def _destructive_phase_reached(record):
    return any(item.get('id') in ('stop', 'restore', 'start', 'check', 'rollback')
               and item.get('state') not in ('pending', 'skipped') for item in record.get('phases') or [])


def interrupted_details(record):
    """(zh-TW guidance, result|None) for a job that stopped without finishing."""
    message = INTERRUPTED_MESSAGE.get(record.get('type'), INTERRUPTED_MESSAGE['verify'])
    if record.get('type') != 'restore':
        return message, None
    safety = record.get('safety_backup_id')
    fresh = [str(app) for app in record.get('fresh_apps') or []]
    if record.get('finishing'):
        # The restore itself had succeeded; only deleting the replaced host-directory copies was cut short (L4).
        message = FINISHING_MESSAGE
    elif safety:
        message += f'還原前備份：{safety}。'
    if fresh:
        message += FRESH_MESSAGE.format(apps='、'.join(fresh))
    return message, {'apps': list((record.get('params') or {}).get('apps') or []), 'safety_backup_id': safety,
                     'health': [], 'verification': [], 'rolled_back': False,
                     'changed': _destructive_phase_reached(record), 'fresh_apps': fresh, 'safety_skipped': False,
                     'safety_failed': False, 'warnings': []}


def _remove_unfinished_fresh(store, record, cleanup_fresh):
    """Remove the partial fresh deployment of a dead restore (review CR-05); returns extra zh-TW guidance.

    `fresh_apps` lists only apps whose data import had not finished (review finding HD-04), and the clean-up keeps
    (and reports) a deployment whose units are unmasked or running anyway; either way it is attempted once."""
    fresh = [str(app) for app in record.get('fresh_apps') or []]
    if not fresh or cleanup_fresh is None:
        return ''
    try:
        problems = cleanup_fresh(fresh)
    except Exception:  # noqa: BLE001 - recovery must never break status/jobs
        traceback.print_exc(file=sys.stderr)
        problems = ['清除時發生未預期的錯誤']
    record['fresh_apps'] = []
    if problems:
        store.append_log(record['id'], f'無法完整清除未完成的全新部署：{"；".join(problems)[:300]}')
        return f'未完成的全新部署沒有完整清除，需人工處理：{"；".join(problems)[:300]}。'
    store.append_log(record['id'], f'已清除未完成的全新部署：{"、".join(fresh)}')
    return '已清除未完成的全新部署，可再次還原。'


def _settle_dirs(store, record, settle_dirs):
    """Settle the host-directory siblings a dead restore left (moved-aside copies back where a directory is missing,
    new copies removed, nothing that is the only copy deleted); returns extra zh-TW guidance. Attempted once."""
    apps = [str(app) for app in record.get('dir_apps') or []]
    if not apps or settle_dirs is None:
        return ''
    try:
        notes = [str(note) for note in settle_dirs(record['id'], apps) or []]
    except Exception:  # noqa: BLE001 - recovery must never break status/jobs
        traceback.print_exc(file=sys.stderr)
        notes = ['整理主機資料夾時發生未預期的錯誤，需人工確認']
    record['dir_apps'] = []
    if not notes:
        return ''
    text = '；'.join(notes)[:600]
    store.append_log(record['id'], f'主機資料夾：{text}')
    return f'主機資料夾：{text}。'


def _restart_stopped_writers(store, record, restart_writers):
    """Restart writers a dead backup left stopped; returns extra zh-TW guidance."""
    stopped = record.get('stopped_writers') or {}
    if not stopped or restart_writers is None:
        return ''
    try:
        failed = restart_writers(stopped)
    except Exception:  # noqa: BLE001 - recovery must never break status/jobs
        traceback.print_exc(file=sys.stderr)
        failed = [unit for units in stopped.values() for unit in units]
    record['stopped_writers'] = {}
    restarted = [u for units in stopped.values() for u in units if u not in failed]
    if restarted:
        store.append_log(record['id'], f'已自動重新啟動因中斷而暫停的服務：{", ".join(restarted)}')
    if failed:
        store.append_log(record['id'], f'無法自動重新啟動：{", ".join(failed)}')
        return f'以下服務未能自動重新啟動，請到服務頁檢查：{", ".join(failed)}。'
    return '被暫停的應用服務已自動重新啟動。'


def _remove_dead_staging(paths, job_id):
    """Staging holds plaintext (dumps, secrets); a killed job never ran its `finally`, so recovery removes it."""
    path = Path(paths.staging) / job_id
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(path, ignore_errors=True)
    else:
        os.unlink(path)
    return True


def _sweep_staging(paths, store):
    """Remove staging dirs of jobs that are no longer queued/running (or have no record at all)."""
    try:
        names = os.listdir(paths.staging)
    except (FileNotFoundError, NotADirectoryError):
        return
    for name in names:
        if not valid_job_id(name):
            continue
        try:
            state = store.get(name).get('state')
        except BackupError:
            state = None
        if state not in ACTIVE:
            _remove_dead_staging(paths, name)


def _sweep_key_files(paths, store, now):
    """Delete transient key files no running job needs: `key-<job>` of a finished job and `key-inspect-*` older
    than KEY_FILE_MAX_AGE (an inspect killed before its `finally` left the secret on tmpfs; review SEC-4)."""
    try:
        names = os.listdir(paths.run)
    except (FileNotFoundError, NotADirectoryError):
        return
    for name in names:
        if not name.startswith('key-'):
            continue
        path = Path(paths.run) / name
        job_id = name[4:]
        if valid_job_id(job_id):
            try:
                if store.get(job_id).get('state') in ACTIVE:
                    continue
            except BackupError:
                pass
        else:
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                continue
            if now - max(st.st_mtime, st.st_ctime) < KEY_FILE_MAX_AGE:
                continue
        with contextlib.suppress(FileNotFoundError, IsADirectoryError, PermissionError):
            os.unlink(path)


def _queued_grace(record, now):
    """A young queued record: its run-job may not have taken the engine lock yet."""
    created = parse_iso(record.get('created'))
    return record.get('state') == 'queued' and created is not None and now - created < QUEUED_GRACE_SECONDS


def _finish_leftovers(store, record, restart_writers, cleanup_fresh, settle_dirs=None):
    """Restart writers / settle host directories / remove the unfinished fresh deployment that a finished record
    still lists (writers a terminated backup left stopped, review CR-14; a restore cut by a shutdown, CR-05). The
    directories come first: a missing one gets its moved-aside copy back before a fresh deployment is removed.
    `record` is a fresh read and the caller holds its record lock and the engine lock."""
    extra = _restart_stopped_writers(store, record, restart_writers)
    extra += _settle_dirs(store, record, settle_dirs)
    extra += _remove_unfinished_fresh(store, record, cleanup_fresh)
    if extra and isinstance(record.get('error'), dict):
        record['error']['message'] = (record['error'].get('message') or '') + extra
    store.save(record)


def _mark_interrupted(paths, store, record, now, restart_writers, cleanup_fresh, settle_dirs=None):
    """Finish a dead job's fresh record as `interrupted`; the state is committed before any clean-up runs, so a
    helper killed during the clean-up leaves a finished record whose leftovers the next pass completes."""
    message, result = interrupted_details(record)
    if result is not None:
        record['result'] = result
    for item in record.get('phases') or []:
        if item.get('state') == 'active':
            item['state'] = 'failed'
    record.update({'state': 'interrupted', 'finished': utc_iso(now), 'cancellable': False,
                   'error': {'code': 'job-failed', 'message': message}})
    record['progress'] = {'percent': (record.get('progress') or {}).get('percent', 0), 'message': '已中斷'}
    store.save(record)
    store.append_log(record['id'], f'作業被判定為已中斷：{message}')
    if has_leftovers(record):
        _finish_leftovers(store, record, restart_writers, cleanup_fresh, settle_dirs)
    _remove_key_file(store, record['id'])
    if _remove_dead_staging(paths, record['id']):
        store.append_log(record['id'], '已清除中斷作業留下的暫存資料')


def _recover_one(paths, store, job_id, unit, unit_active, now, restart_writers, cleanup_fresh, settle_dirs=None):
    """Decide one candidate while the start and engine locks are held; True when it was marked interrupted.

    With the engine lock held no run-job is between taking and releasing it, and a run-job writes its final
    state before it releases it. So the record re-read here, after the unit probe and under the record lock,
    is what the job last wrote: still queued/running means the job died (a queued job still waiting for the
    engine lock has an active unit), and every side effect uses that fresh record, never the listing.
    """
    if unit_active(unit):
        return False
    with store.locked(job_id):
        try:
            record = store.get(job_id)
        except BackupError:
            return False
        if record.get('state') in TERMINAL:
            if has_leftovers(record):
                _finish_leftovers(store, record, restart_writers, cleanup_fresh, settle_dirs)
            return False
        if record.get('state') not in ACTIVE or _queued_grace(record, now):
            return False
        _mark_interrupted(paths, store, record, now, restart_writers, cleanup_fresh, settle_dirs)
    return True


def pinned_safety_records(records):
    """{restore record id: safety backup id or None} of the failed or interrupted (not rolled back) restores whose
    safety backup -- or, when the restore had none but changed the apps (allow_no_safety, or restoring a safety
    backup), whose source backup -- is still the only way back for one of their apps: no later restore of that app
    succeeded (review M2). `records` newest first. Used by safety-backup pruning and by retention (such records are
    never deleted; retention also keeps each pinning record's source backup)."""
    pinned, settled = {}, set()
    for record in records:
        if record.get('type') != 'restore':
            continue
        params = record.get('params') if isinstance(record.get('params'), dict) else {}
        listed = params.get('apps') if isinstance(params.get('apps'), list) else []
        apps = {app for app in listed if isinstance(app, str)}
        if record.get('state') == 'succeeded':
            settled |= apps
            continue
        result = record.get('result') if isinstance(record.get('result'), dict) else {}
        safety = result.get('safety_backup_id') or record.get('safety_backup_id')
        changed = result.get('changed') is True or (record.get('state') == 'interrupted'
                                                    and _destructive_phase_reached(record))
        if ((safety or changed) and record.get('state') in ('failed', 'interrupted') and not result.get('rolled_back')
                and apps - settled):
            pinned[record['id']] = safety or None
    return pinned


def _sweep_orphans(store, now):
    """Remove side files whose record is gone (a log, lock or cancel request) and temp files of interrupted
    writes, once they are ORPHAN_MAX_AGE old."""
    try:
        names = os.listdir(store.paths.jobs)
    except (FileNotFoundError, NotADirectoryError):
        return
    present = {name[:-5] for name in names if name.endswith('.json')}
    for name in names:
        side = SIDE_FILE_RE.fullmatch(name)
        if not (side and side.group(1) not in present) and not TEMP_FILE_RE.fullmatch(name):
            continue
        path = Path(store.paths.jobs) / name
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(st.st_mode) and now - st.st_mtime >= ORPHAN_MAX_AGE:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)


def _retain(store, records, now, keep=KEEP_TERMINAL):
    """Delete finished records (with their logs) beyond the newest `keep`. Never deleted: active records, records
    with recovery work left, and restore records that pin a safety backup (deleting one would let pruning remove
    the only way back). Unreadable records count as finished. `records`: the pass's listing, newest first."""
    by_id = {record['id']: record for record in records}
    pinned = None
    finished = 0
    for job_id in store.ids():
        record = by_id.get(job_id)
        if record is not None and (record.get('state') in ACTIVE or has_leftovers(record)):
            continue
        finished += 1
        if finished <= keep:
            continue
        if pinned is None:
            pinned = pinned_safety_records(records)
        if job_id not in pinned:
            store.remove(job_id)
    _sweep_orphans(store, now)


def _recover_locked(paths, store, unit_active, now, restart_writers=None, cleanup_fresh=None, settle_dirs=None):
    """One recovery pass (the caller holds the start lock); returns the ids marked interrupted.

    The listing only picks candidates: records queued/running (past the queued grace) and finished records
    with leftover work. Nothing is decided while a job holds the engine lock: its own record is alive, and the
    leftovers of an older job wait until it ends (they may name writers the running backup stopped on purpose).
    """
    records = store.list(limit=None)
    candidates = [(record['id'], record.get('unit') or unit_name(record['id'])) for record in records
                  if (record.get('state') in ACTIVE and not _queued_grace(record, now))
                  or (record.get('state') in TERMINAL and has_leftovers(record))]
    changed = []
    if candidates:
        engine_fd = try_engine_lock(paths)
        if engine_fd is not None:
            try:
                for job_id, unit in candidates:
                    if _recover_one(paths, store, job_id, unit, unit_active, now, restart_writers, cleanup_fresh,
                                    settle_dirs):
                        changed.append(job_id)
            finally:
                os.close(engine_fd)
    _sweep_staging(paths, store)
    _sweep_key_files(paths, store, now)
    try:
        _retain(store, records, now)
    except Exception:  # noqa: BLE001 - housekeeping never breaks status/jobs/job-status; retried next pass
        traceback.print_exc(file=sys.stderr)
    return changed


def recover_interrupted(paths, *, unit_active=None, now=None, restart_writers=None, cleanup_fresh=None,
                        settle_dirs=None):
    """Mark dead queued/running jobs as interrupted; returns the affected job ids.

    `restart_writers({app_id: [units]}) -> [failed units]` restarts writers a dead backup left stopped;
    `cleanup_fresh([app_id]) -> [problems]` removes an unfinished fresh deployment;
    `settle_dirs(job_id, [app_id]) -> [notes]` settles the host-directory siblings a dead restore left.
    """
    if not Path(paths.jobs).is_dir():
        return []
    store = JobStore(paths)
    with start_lock(paths):
        return _recover_locked(paths, store, unit_active or systemd_unit_active, time.time() if now is None else now,
                               restart_writers, cleanup_fresh, settle_dirs)


def active_job(paths):
    store = JobStore(paths)
    for record in store.list(limit=None):
        if record.get('state') in ACTIVE:
            return record
    return None


def cancel_job(paths, job_id, *, wait_seconds=3.0, sleep=time.sleep, clock=time.monotonic):
    """Request cancellation; honoured at the job's next safe checkpoint. Returns {'state'}.

    Checked and requested under the record lock: the job cannot close its cancellable window or finish in
    between, so an accepted request is honoured before any destructive step, and a finished job never keeps
    a request file.
    """
    store = JobStore(paths)
    with start_lock(paths):
        store.get(job_id)  # not-found before a lock file is created for an unknown id
        with store.locked(job_id):
            record = store.get(job_id)
            if record.get('state') in TERMINAL:
                return {'state': record['state']}
            if not record.get('cancellable'):
                raise BackupError('not-cancellable', '作業已進入不可中斷的階段，將繼續執行到完成或自動回復。',
                                  job_id=job_id)
            store.request_cancel(job_id)
        store.append_log(job_id, '已收到取消要求，將在安全的檢查點停止')
    deadline = clock() + wait_seconds
    while clock() < deadline:
        record = store.get(job_id)
        if record.get('state') in TERMINAL:
            break
        sleep(0.2)
    return {'state': record.get('state')}


def _adopt_orphans(ctx):
    """List archives a hard kill left unindexed (between publishing and indexing) instead of hiding them."""
    adopt = getattr(getattr(ctx.deps, 'storage', None), 'adopt_orphans', None)
    if adopt is None:
        return
    try:
        for backup_id in adopt():
            ctx.log(f'找到沒有索引的備份檔 {backup_id}（先前作業中斷時留下），已列為上傳的備份')
    except Exception:  # noqa: BLE001 - never block the job; details go to the journal
        traceback.print_exc(file=sys.stderr)


def _restart_after_termination(ctx):
    """A termination signal ended the job: start writers that are still recorded as stopped (review CR-14),
    unless the machine is shutting down (they start with the user manager at boot)."""
    from . import flows
    stopped = ctx.reporter.record.get('stopped_writers') or {}
    if not stopped or flows._shutting_down(ctx):
        return
    try:
        failed = set(flows.restart_writers(ctx.deps, stopped, log=ctx.log))
    except Exception:  # noqa: BLE001 - recovery retries on the next status call
        traceback.print_exc(file=sys.stderr)
        return
    ctx.reporter.record['stopped_writers'] = {app: [u for u in units if u in failed]
                                              for app, units in stopped.items() if set(units) & failed}


@contextlib.contextmanager
def signals_as_exceptions():
    previous = {}

    def handler(signum, _frame):
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)  # let cleanup and rollback finish undisturbed
        raise Terminated(signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        previous[sig] = signal.signal(sig, handler)
    try:
        yield
    finally:
        for sig, old in previous.items():
            signal.signal(sig, old)


def run_job(paths, job_id, *, deps=None, lock_timeout=LOCK_WAIT_SECONDS, handlers=None):
    """Execute a queued job in this process (the systemd-run unit). Never replays finished jobs."""
    from . import flows
    store = JobStore(paths)
    lock_fd = None
    try:
        store.ensure()
        store.get(job_id)  # not-found before waiting for the engine lock
        lock_fd = acquire_engine_lock(paths, lock_timeout)
        if lock_fd is None:
            with store.locked(job_id):
                reporter = JobReporter(store, store.get(job_id))
                if reporter.record.get('state') == 'queued':
                    reporter.finish('failed', error={'code': 'busy', 'message': '另一個作業仍在執行，此作業未啟動。'})
            return reporter.record
        os.ftruncate(lock_fd, 0)
        os.write(lock_fd, f'{job_id}\n'.encode())
        reporter = JobReporter(store, store.get(job_id))
        outcome = reporter.begin()
        if outcome == 'not-queued':
            store.append_log(job_id, '作業不是等待中的狀態，不重新執行')
        if outcome != 'started':
            return reporter.record
        key_file = store.key_path(job_id)
        ctx = flows.FlowContext(paths, job_id, deps or flows.default_deps(paths), reporter,
                                key_file=key_file if os.path.lexists(key_file) else None)
        _adopt_orphans(ctx)
        table = handlers or {'backup': flows.run_backup, 'restore': flows.run_restore, 'verify': flows.run_verify,
                             'export': flows.run_export}
        handler = table[reporter.record['type']]
        with signals_as_exceptions():
            try:
                result = handler(ctx, reporter.record.get('params') or {})
            except flows.Cancelled:
                reporter.finish('cancelled')
            except flows.RolledBack as rolled:
                reporter.finish('rolled-back', result=rolled.result, error=rolled.error.as_dict())
            except Terminated:
                _restart_after_termination(ctx)
                message, partial = interrupted_details(reporter.record)
                reporter.finish('interrupted', result=partial, error={'code': 'job-failed', 'message': message})
            except BackupError as error:
                reporter.finish('failed', result=getattr(error, 'result', None), error=error.as_dict())
            except Exception:  # noqa: BLE001 - recorded generically, details go to the journal only
                traceback.print_exc(file=sys.stderr)
                reporter.finish('failed', error={'code': 'internal-error', 'message': '作業發生未預期的內部錯誤，請查看系統日誌。'})
            else:
                reporter.finish('succeeded', result=result)
        return reporter.record
    finally:
        _remove_key_file(store, job_id)
        with contextlib.suppress(BackupError, OSError):
            store.clear_cancel(job_id)
        if lock_fd is not None:
            with contextlib.suppress(OSError):
                os.ftruncate(lock_fd, 0)
            os.close(lock_fd)


# Old private names, kept for callers and tests written against them.
_start_lock = start_lock
_signals_as_exceptions = signals_as_exceptions
