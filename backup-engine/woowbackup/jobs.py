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
  marked `interrupted`, and the writers / host directories / unfinished fresh deployment / pre-restore copy that this
  fresh record (never the earlier listing) still lists are restarted / settled / removed / packaged into its safety
  backup, each once. A job that finished while the records were listed therefore keeps its own final record (release
  regression 16). Nothing is ever replayed. It also deletes stale transient key files and staging folders of jobs that
  are not running; it never touches a pre-restore copy (`pending/<job>/`) except through its packaging.
* Retention: records of active jobs, records with recovery work left, failed/interrupted restores whose
  safety backup is still pinned and restores whose pre-restore copy is not (or could not be) packaged are always
  kept; of the other (finished) records only the newest KEEP_TERMINAL are kept, with their logs. So
  status/jobs/job-status read a bounded number of records.
* Cancellation is a request file, accepted only while the record says the job is cancellable and honoured
  at the job's next checkpoint. Leaving the cancellable window is itself such a checkpoint, checked under
  the record lock, so an accepted cancel is never followed by a destructive step.
* A Home Assistant import is a chain of jobs (hachain.py): `run_job` runs the job it is given and then, in the same
  process, under the same engine lock, every job the chain adds. The next job's record is written (queued, with the
  unit of the first job) before the finished job's record is, so the import never has a moment without an active job;
  `cancel_job` of any job of the import means its live job, and `after_this` asks the chain to stop after the app it is
  working on (a side file named after the import's group, `<group id>.stop`).
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

from . import util
from .errors import BackupError

PHASES = {
    'backup': (('prepare', '準備'), ('check', '檢查空間與應用'), ('stop', '暫停應用寫入'), ('dump', '匯出資料庫'),
               ('export', '匯出資料卷與設定'), ('start', '恢復應用'), ('package', '加密封裝'), ('verify', '驗證備份')),
    # `stage`: host directories are written next to the current ones while the apps still run (nothing that exists
    # changes); `safety` copies the data before the restore and keeps the writers stopped for it; `safety-package`
    # packages and verifies that copy into the safety backup once the apps run again (CONTRACT section 9).
    'restore': (('prepare', '準備'), ('decrypt', '解密並驗證檔案'), ('preflight', '相容性檢查'),
                ('stage', '預先寫入主機資料夾'), ('safety', '保存還原前資料'), ('stop', '停止應用'), ('restore', '還原資料'),
                ('start', '啟動應用'), ('check', '健康與資料核對'), ('safety-package', '封裝還原前備份')),
    'verify': (('prepare', '準備'), ('decrypt', '解密並驗證檔案'), ('check', '核對結果')),
    # An unencrypted copy of an encrypted backup for one download (CONTRACT section 8); nothing on the device changes.
    'export': (('prepare', '準備'), ('decrypt', '解密並驗證檔案'), ('package', '封裝未加密副本'), ('verify', '驗證副本')),
}
PLAIN_PACKAGE_LABEL = '封裝（未加密）'  # the package phase of a backup made with 加密此備份 off encrypts nothing
# Home Assistant import jobs (branch feat/ha-import; haimport.py): a `verify` / `backup` job with params.source 'ha'
# checks / converts an uploaded HA backup; known types keep older pages' job validation happy, the labels live in
# the records like every job's.
HA_PHASES = {
    'verify': (('prepare', '準備'), ('decrypt', '解開 HA 備份'), ('check', '檢查內容與版本')),
    'backup': (('prepare', '準備'), ('decrypt', '解開 HA 備份'), ('convert', '轉換資料'), ('package', '封裝備份'),
               ('verify', '驗證備份')),
}
KEY_KINDS = ('age', 'ha')
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
# A log line stays ONE line on the page: read_log splits on '\n' only, and append_log turns into a space every C0/C1
# control character and U+2028/U+2029 (str.splitlines() also splits on \x0b, \x0c, \x1c-\x1e, \x85, U+2028 and U+2029).
# Lines carry text an HA backup chose -- its name, its PG_VERSION -- which forged a line before (secreview SR-6).
# The Unicode bidirectional controls (PropList Bidi_Control: U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069)
# become a space too: inside one line they still reorder how the rest of it reads (the verifier's SR-6 gap).
LOG_CONTROL_RE = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]')
LOCK_WAIT_SECONDS = 120
KEY_FILE_MAX_AGE = 15 * 60  # an inspect takes seconds; older key-inspect-* files were left by a killed helper
KEEP_TERMINAL = 200  # finished records kept (with their logs) besides the ones that are still needed
ORPHAN_MAX_AGE = 3600  # a log / lock / cancel request / temp file without its record is removed after this
SIDE_FILE_RE = re.compile(r'(j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})\.(?:log|lock|cancel)\Z')
GROUP_ID_RE = re.compile(r'g[0-9a-f]{16}\Z')
STOP_FILE_RE = re.compile(r'(g[0-9a-f]{16})\.stop\Z')
TEMP_FILE_RE = re.compile(r'\.j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.json\.[0-9a-f]+\.tmp\Z')
# The job unit is bounded independently of the containers it talks to (review finding SEC-3).
UNIT_LIMITS = ('--property=MemoryMax=50%', '--property=TasksMax=512')
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
SECRET_PATTERN = re.compile(r'AGE-SECRET-KEY-1[0-9A-Za-z]+')
# A Home Assistant backup encryption key as HA shows it (7 groups of 4 of A-Z0-9): masked wherever it appears, also in
# processes that never saw the key (job-status reads the log); the exact key of a running job is masked as well
# (mask_secret).
HA_KEY_PATTERN = re.compile(r'[A-Z0-9]{4}(?:-[A-Z0-9]{4}){6}')
REDACTED = '[已遮蔽]'
_MASKED = ()  # exact secret texts of this process, longest first (mask_secret); replaced whole, never mutated
_MASK_COUNTS = {}  # text -> how many mask_secret calls hold it (nested users of the same key)
_MASK_LOCK = threading.Lock()

INTERRUPTED_MESSAGE = {
    'backup': '備份作業意外中斷（例如系統重新開機或程序被終止）。請確認應用已恢復執行後再重新備份。',
    'restore': '還原作業意外中斷（例如系統重新開機或程序被終止），應用可能處於不完整狀態。請檢查應用狀態，'
               '必要時使用還原前備份再次還原。',
    'verify': '驗證作業意外中斷，請重新執行驗證。',
    'export': '建立未加密副本的作業意外中斷，請重新建立；未完成的副本已清除。',
}
UNCHANGED_MESSAGE = ('還原作業在變更任何資料之前就中斷（例如系統重新開機或程序被終止），應用資料沒有被變更；'
                     '因還原而停止的服務會重新啟動。可以再次還原。')
FRESH_MESSAGE = '全新部署（{apps}）沒有完成；系統會清除未完成的部署，之後可再次還原同一份備份。'
FINISHING_MESSAGE = ('還原已完成並通過檢查，但在刪除主機資料夾被取代的舊內容時作業中斷（例如系統重新開機）。'
                     '系統會接手整理留下的資料夾；應用不需要再次還原。')
FINISHING_PACKAGE_MESSAGE = '還原已完成並通過檢查，但在封裝還原前備份時作業中斷（例如系統重新開機）。應用不需要再次還原。'
PENDING_MESSAGE = '還原前資料已保留，系統會把它封裝成還原前備份。'



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
    """`text` with every secret masked: the exact values registered by mask_secret (first, so a pattern cannot cut
    one apart), age secret keys and anything shaped like a Home Assistant backup key."""
    text = str(text)
    for secret in _MASKED:
        text = text.replace(secret, REDACTED)
    return HA_KEY_PATTERN.sub(REDACTED, SECRET_PATTERN.sub(REDACTED, text))


def mask_secret(value):
    """Mask this exact text (and its stripped form) in every log line, progress message and error this process writes
    through redact(): a job reading a Home Assistant backup calls it with the key it uses (an HA key need not have the
    usual shape: older backups may use any password)."""
    _change_masks(value, 1)


def unmask_secret(value):
    """Undo one mask_secret(value)."""
    _change_masks(value, -1)


def _change_masks(value, step):
    global _MASKED
    if not isinstance(value, str):
        return
    with _MASK_LOCK:
        for item in {value, value.strip()} - {''}:
            count = _MASK_COUNTS.get(item, 0) + step
            if count > 0:
                _MASK_COUNTS[item] = count
            else:
                _MASK_COUNTS.pop(item, None)
        _MASKED = tuple(sorted(_MASK_COUNTS, key=len, reverse=True))


@contextlib.contextmanager
def masked(value):
    """mask_secret(value) for the duration of the block."""
    mask_secret(value)
    try:
        yield
    finally:
        unmask_secret(value)


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


def is_ha_job(job_type, params):
    """A Home Assistant import job (check or convert): params.source 'ha'."""
    return job_type in HA_PHASES and isinstance(params, dict) and params.get('source') == 'ha'


def public_job(record):
    return {key: record.get(key) for key in PUBLIC_KEYS}


def unit_name(job_id):
    return f'woowtech-backup-{job_id}.service'


def has_leftovers(record):
    """The record still lists writers a dead job left stopped, an unfinished fresh deployment, apps whose host
    directories a dead restore may have left siblings of, owners whose throwaway containers a dead job may have left
    (`temp_owners`, tempctr.py), or a restore's pre-restore copy that is not packaged yet."""
    return bool(record.get('stopped_writers') or record.get('fresh_apps') or record.get('dir_apps')
                or record.get('temp_owners')
                or (record.get('type') == 'restore' and record.get('safety_pending')))


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

    def create(self, job_type, params, *, request_id=None, now=None, unit=None):
        """A queued record. `unit`: the systemd unit that runs it, when it is not the one named after this job (the next
        job of an import's chain runs in the unit of the first one; recovery asks that unit whether the job is alive)."""
        if job_type not in PHASES:
            raise BackupError('invalid-request', '不支援的作業類型。')
        now = time.time() if now is None else now
        self.ensure()
        job_id = new_job_id(now)
        plain = job_type == 'backup' and isinstance(params, dict) and params.get('encrypt') is False
        phases = (HA_PHASES[job_type] if is_ha_job(job_type, params) else PHASES[job_type])
        record = {
            'id': job_id, 'type': job_type, 'state': 'queued', 'phase': phases[0][0],
            'phases': [{'id': pid, 'label': PLAIN_PACKAGE_LABEL if plain and pid == 'package' else label,
                        'state': 'pending'} for pid, label in phases],
            'progress': {'percent': 0, 'message': '等待開始'}, 'created': utc_iso(now), 'started': None,
            'finished': None, 'params': params, 'result': None, 'error': None, 'cancellable': True,
            'request_id': request_id, 'unit': unit if isinstance(unit, str) and unit else unit_name(job_id),
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
        line = LOG_CONTROL_RE.sub(' ', redact(message))[:MAX_LOG_LINE]
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
            lines = handle.read().decode('utf-8', 'replace').split('\n')
        if lines and lines[-1] == '':
            lines.pop()
        return [redact(line) for line in lines[-limit:]]

    def request_cancel(self, job_id):
        fd = os.open(self.cancel_path(job_id), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.close(fd)

    def cancel_requested(self, job_id):
        return os.path.lexists(self.cancel_path(job_id))

    def clear_cancel(self, job_id):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.cancel_path(job_id))

    def stop_path(self, group_id):
        """The side file that asks an import's chain to stop after the app it is working on (named after the import's group,
        so any job of the import can reach it)."""
        if not isinstance(group_id, str) or not GROUP_ID_RE.fullmatch(group_id):
            raise BackupError('invalid-request', '匯入的識別碼格式不正確。')
        return Path(self.paths.jobs) / f'{group_id}.stop'

    def request_stop(self, group_id):
        fd = os.open(self.stop_path(group_id), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.close(fd)

    def stop_requested(self, group_id):
        return os.path.lexists(self.stop_path(group_id))

    def clear_stop(self, group_id):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.stop_path(group_id))


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
        self._marked = set()  # phases set by mark(): an earlier phase starting again leaves them as they are

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

    def phase(self, phase_id, *, percent=None, message=None):
        ids = self._ids()
        if phase_id not in ids:
            return
        index = ids.index(phase_id)
        for i, item in enumerate(self.record['phases']):
            if i < index and item['state'] in ('pending', 'active'):
                item['state'] = 'done'
            elif i == index:
                item['state'] = 'active'
            elif i > index and item['state'] in ('active', 'done') and item['id'] not in self._marked:
                item['state'] = 'pending'  # re-entered for the next app of a multi-app job
        self._phase_index = index
        self.record['phase'] = phase_id
        label = self.record['phases'][index]['label']
        value = int(100 * index / len(ids)) if percent is None else int(percent)
        self.record['progress'] = {'percent': max(0, min(99, value)),
                                   'message': label if message is None else redact(message)[:200]}
        self._save()
        self.log(f'階段：{label if message is None else redact(message)[:200]}')

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

    def fail(self, phase_id):
        """Mark one phase failed while the job goes on (a finished restore whose safety backup was not packaged)."""
        for item in self.record['phases']:
            if item['id'] == phase_id and item['state'] in ('pending', 'active'):
                item['state'] = 'failed'
        self._save()

    def mark(self, phase_id, state):
        """Set one phase's state whatever it is now, and keep it while earlier phases run (the pre-restore copy
        packaged in the downtime, before the restore's phases; the copy a rollback packaged after `rollback` skipped
        the phase; review 2026-11-14)."""
        self._marked.add(phase_id)
        for item in self.record['phases']:
            if item['id'] == phase_id:
                item['state'] = state
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


def _check_key(key_text, key_kind):
    """Validate a job key before anything is written: an age identity (keys.normalize_secret) or a Home Assistant
    backup key (any text HA accepts: hasecuretar.Keys, never trimmed or normalised)."""
    if key_kind not in KEY_KINDS:
        raise BackupError('invalid-request', '不支援的金鑰種類。')
    if key_kind == 'ha':
        from .hasecuretar import Keys
        Keys(key_text)
        return key_text.encode('utf-8')
    from .keys import normalize_secret
    return (normalize_secret(key_text) + '\n').encode('ascii')


def _write_key_file(path, key_text, key_kind='age'):
    data = _check_key(key_text, key_kind)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        data = memoryview(data)
        while data:
            data = data[os.write(fd, data):]
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_key_file(store, job_id):
    with contextlib.suppress(FileNotFoundError, BackupError):
        os.unlink(store.key_path(job_id))


# ---------------------------------------------------------------- public API

def start_job(paths, job_type, params, request_id, *, key_text=None, key_kind='age', launcher=None, unit_active=None,
              now=None, restart_writers=None, cleanup_fresh=None, settle_dirs=None, package_safety=None,
              sweep_temp=None):
    """Create and launch a job; returns {'job_id', 'deduplicated'}. `key_kind`: 'age' (an emergency key, normalised
    and written as an age identity file) or 'ha' (a Home Assistant backup key, written as the raw UTF-8 text; the job
    masks it in its logs before it writes the first line)."""
    if job_type not in PHASES:
        raise BackupError('invalid-request', '不支援的作業類型。')
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise BackupError('invalid-request', '請求識別碼格式不正確。')
    if key_text is not None:
        _check_key(key_text, key_kind)  # validate before anything is written
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
                        settle_dirs, package_safety, sweep_temp)
        active = [r for r in store.list(limit=None) if r.get('state') in ACTIVE]
        if active:
            raise BackupError('busy', '已有備份或還原作業正在進行，請等它完成後再試。', job_id=active[0]['id'])
        record = store.create(job_type, params, request_id=request_id, now=now)
        job_id = record['id']
        try:
            if key_text is not None:
                _write_key_file(store.key_path(job_id), key_text, key_kind)
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
    # Not safety-package: packaged in the downtime, it is done before the first destructive step; after the restore,
    # it follows check (review 2026-11-14).
    return any(item.get('id') in ('stop', 'restore', 'start', 'check', 'rollback')
               and item.get('state') not in ('pending', 'skipped') for item in record.get('phases') or [])


def interrupted_details(record):
    """(zh-TW guidance, result|None) for a job that stopped without finishing."""
    message = INTERRUPTED_MESSAGE.get(record.get('type'), INTERRUPTED_MESSAGE['verify'])
    if is_ha_job(record.get('type'), record.get('params')):
        from .haimport import interrupted_message
        return interrupted_message(record.get('type')), None
    if record.get('type') != 'restore':
        return message, None
    safety = record.get('safety_backup_id')
    changed = _destructive_phase_reached(record)
    pending = bool(record.get('safety_pending')) and not safety and (changed or bool(record.get('finishing')))
    fresh = [str(app) for app in record.get('fresh_apps') or []]
    if record.get('finishing'):
        # The restore itself had succeeded; only deleting the replaced host-directory copies (L4) or packaging the
        # pre-restore copy into the safety backup was cut short.
        message = (FINISHING_PACKAGE_MESSAGE if record.get('phase') == 'safety-package' and record.get('safety_pending')
                   else FINISHING_MESSAGE)
    elif not changed:
        # Cut short before its first destructive step (review 2026-11-14): nothing to restore again; a copy it kept
        # is deleted by the recovery, its data being unchanged where it came from.
        message = UNCHANGED_MESSAGE + (f'這次建立的還原前備份 {safety} 仍保留在備份列表中。' if safety else '')
    elif safety:
        message += f'還原前備份：{safety}。'
    if pending:
        message += PENDING_MESSAGE
    if fresh:
        message += FRESH_MESSAGE.format(apps='、'.join(fresh))
    return message, {'apps': list((record.get('params') or {}).get('apps') or []), 'safety_backup_id': safety,
                     'safety_pending': pending, 'finishing': bool(record.get('finishing')), 'health': [],
                     'verification': [], 'rolled_back': False,
                     'changed': changed, 'fresh_apps': fresh, 'safety_skipped': False,
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


def _sweep_pending(paths, store):
    """Remove pre-restore copies (`pending/<job>/`) that nothing needs: the record is finished and lists neither a copy
    to package (`safety_pending`) nor one that could not be (`safety_pending_failed`). Such a copy is either one a job
    was writing when it died (the flag is on disk before the restore's first destructive step, so the data it copied
    never changed) or one already packaged (the record named the backup before the copy was deleted). A copy whose
    record is running, flagged, or missing/unreadable is kept (it may be the only copy of the data before a restore)."""
    try:
        names = os.listdir(paths.pending)
    except (FileNotFoundError, NotADirectoryError):
        return
    for name in names:
        if not valid_job_id(name):
            continue
        try:
            record = store.get(name)
        except BackupError:
            continue
        if (record.get('state') in TERMINAL and not record.get('safety_pending')
                and not record.get('safety_pending_failed')):
            path = Path(paths.pending) / name
            with contextlib.suppress(FileNotFoundError):
                st = os.lstat(path)
                if stat.S_ISDIR(st.st_mode):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.unlink(path)


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


def _package_pending_copy(store, record, package_safety):
    """Package the pre-restore copy a restore kept in `pending/<job>/` (its own packaging failed, or the job died)
    into its safety backup; returns extra zh-TW guidance (empty when nothing new happened). The outcome is saved in the
    record before the copy is deleted (registration is the commit point; a copy a kill leaves behind is unflagged and
    the sweep removes it). Tried once: afterwards `safety_pending` is false, and a failure keeps the copy and records
    where it is (`safety_pending_failed`). Not enough free space is not a failure: nothing is written, the flag stays
    and a later pass tries again (`safety_pending_deferred` says why; the guidance is added once).

    This runs inside a helper call (status, jobs, job-status, a start command) under the recovery's locks: packaging
    and verifying a large copy takes about a minute, acceptable for this rare path. Termination signals are ignored
    meanwhile (a page timeout makes cockpit-bridge send SIGTERM; cut short, every later call would start over), and
    the outcome is saved before they apply again."""
    if record.get('type') != 'restore' or not record.get('safety_pending') or package_safety is None:
        return ''
    job_id = record['id']
    path = Path(store.paths.pending) / job_id
    result = record.get('result') if isinstance(record.get('result'), dict) else None
    if record.get('state') in ('interrupted', 'failed', 'cancelled') and not record.get('finishing') \
            and not _destructive_phase_reached(record) and (result or {}).get('changed') is not True:
        # Cut short before its first destructive step (review 2026-11-14): the data it copied is unchanged where it
        # came from, so the copy is not needed, as after a failure there. The flag goes first (a kill during the
        # deletion leaves an unflagged copy, which the sweep removes).
        record['safety_pending'] = False
        record.pop('safety_pending_deferred', None)
        if result is not None:
            result['safety_pending'] = False
        store.save(record)
        with contextlib.suppress(OSError):
            shutil.rmtree(path)
        store.append_log(job_id, '還原在變更任何資料之前就中斷，保留的還原前資料不再需要，已刪除')
        return ''
    with util.termination_ignored():
        deferred = False
        try:
            backup_id, problem, deferred = package_safety(job_id)
        except Exception:  # noqa: BLE001 - recovery must never break status/jobs
            backup_id, problem = None, '封裝時發生未預期的錯誤'
            with contextlib.suppress(Exception):  # stderr may be a closed pipe: the outcome is saved regardless
                traceback.print_exc(file=sys.stderr)
        if deferred:
            problem = str(problem or '空間不足').rstrip('。')[:300]
            if 'safety_pending_deferred' in record:
                # Said once (review 2026-11-14: the text names the free space, so a note per pass made the record
                # grow until it could not be read); the latest figures only replace the field.
                if record['safety_pending_deferred'] != problem:
                    record['safety_pending_deferred'] = problem
                    store.save(record)
                return ''
            record['safety_pending_deferred'] = problem
            note = f'還原前資料保留在 {path}，{problem}；有足夠空間後系統會自動封裝成還原前備份。'
            store.append_log(job_id, f'暫緩封裝還原前備份：{problem}')
        elif backup_id:
            record['safety_pending'] = False
            record.pop('safety_pending_deferred', None)
            record['safety_backup_id'] = backup_id
            for item in record.get('phases') or []:
                if item.get('id') == 'safety-package' and item.get('state') != 'done':
                    item['state'] = 'done'  # the step the job could not do (or reach) is done now
            if result is not None:
                result.update(safety_backup_id=backup_id, safety_pending=False)
            store.append_log(job_id, f'已將保留的還原前資料封裝成還原前備份 {backup_id}')
            note = f'已將保留的還原前資料封裝成還原前備份 {backup_id}，可用它再次還原。'
        else:
            problem = str(problem or '原因不明').rstrip('。')[:300]
            record['safety_pending'] = False
            record.pop('safety_pending_deferred', None)
            record['safety_pending_failed'] = {'path': str(path), 'message': problem}
            if result is not None:
                result.update(safety_pending=False, safety_pending_failed={'path': str(path), 'message': problem})
            store.append_log(job_id, f'無法把還原前資料封裝成還原前備份：{problem}；資料保留在 {path}')
            note = f'還原前資料保留在 {path}，無法封裝成還原前備份：{problem}；需人工處理。'
        warnings = result.get('warnings') if result is not None else None
        if not isinstance(record.get('error'), dict) and isinstance(warnings, list) and note not in warnings:
            warnings.append(note)  # a finished restore has no error message: its result says it
        if isinstance(record.get('error'), dict):
            record['error']['message'] = (record['error'].get('message') or '') + note
        store.save(record)
        if backup_id:
            with contextlib.suppress(OSError):
                shutil.rmtree(path)  # recorded above; what a failure here leaves, the sweep removes
    return note


TEMP_RETRY_SECONDS = 600


def _sweep_temp(store, record, sweep_temp, *, now=None):
    """Remove the throwaway containers, volumes and networks a dead (or finished) job may have left for the owners
    its record lists (`temp_owners`); forgotten once podman removed them (or the owner no longer exists). After a
    pass that could not remove everything the next try waits TEMP_RETRY_SECONDS (`temp_retry_at`): a podman that hangs
    must not slow down every status request (review C-08)."""
    owners = [o for o in record.get('temp_owners') or [] if isinstance(o, str)]
    if not owners:
        return ''
    now = time.time() if now is None else now
    retry_at = record.get('temp_retry_at')
    if isinstance(retry_at, (int, float)) and not isinstance(retry_at, bool) and now < retry_at:
        return ''
    if sweep_temp is None:
        from .haimport import sweep_job as sweep_temp
    try:
        problems = list(sweep_temp(record['id'], owners) or [])
    except Exception:  # noqa: BLE001 - retried on a later recovery pass
        traceback.print_exc(file=sys.stderr)
        problems = ['清除時發生未預期的錯誤']
    if problems:
        record['temp_retry_at'] = now + TEMP_RETRY_SECONDS
        store.append_log(record['id'], f'無法清除暫用容器：{"；".join(problems)[:300]}')
        return ''
    record['temp_owners'] = []
    record.pop('temp_retry_at', None)
    store.append_log(record['id'], '已清除這個作業留下的暫用容器與資料卷')
    return ''


def _finish_leftovers(store, record, restart_writers, cleanup_fresh, settle_dirs=None, package_safety=None,
                      sweep_temp=None):
    """Restart writers / settle host directories / remove the unfinished fresh deployment / package the pre-restore
    copy that a finished record still lists (writers a terminated backup left stopped, review CR-14; a restore cut by
    a shutdown, CR-05). The directories come first: a missing one gets its moved-aside copy back before a fresh
    deployment is removed; the packaging comes last (it changes nothing the apps use) and only after the other steps'
    outcome is saved (it may take a minute; a kill during it must not make them run again).
    `record` is a fresh read and the caller holds its record lock and the engine lock. Saved only when something
    changed (a copy waiting for space is looked at on every pass)."""
    before = json.dumps(record, sort_keys=True, default=str)
    extra = _restart_stopped_writers(store, record, restart_writers)
    extra += _settle_dirs(store, record, settle_dirs)
    extra += _remove_unfinished_fresh(store, record, cleanup_fresh)
    extra += _sweep_temp(store, record, sweep_temp)
    if extra and isinstance(record.get('error'), dict):
        record['error']['message'] = (record['error'].get('message') or '') + extra
    if json.dumps(record, sort_keys=True, default=str) != before:
        store.save(record)
    _package_pending_copy(store, record, package_safety)  # saves its own outcome


def _mark_interrupted(paths, store, record, now, restart_writers, cleanup_fresh, settle_dirs=None,
                      package_safety=None, sweep_temp=None):
    """Finish a dead job's fresh record as `interrupted`; the state is committed before any clean-up runs, so a
    helper killed during the clean-up leaves a finished record whose leftovers the next pass completes."""
    message, result = interrupted_details(record)
    from . import hachain
    message, result = hachain.interrupted(record, message, result)  # a job of an import's chain: which apps are done
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
        _finish_leftovers(store, record, restart_writers, cleanup_fresh, settle_dirs, package_safety, sweep_temp)
    _remove_key_file(store, record['id'])
    if _remove_dead_staging(paths, record['id']):
        store.append_log(record['id'], '已清除中斷作業留下的暫存資料')


def _recover_one(paths, store, job_id, unit, unit_active, now, restart_writers, cleanup_fresh, settle_dirs=None,
                 package_safety=None, sweep_temp=None):
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
                _finish_leftovers(store, record, restart_writers, cleanup_fresh, settle_dirs, package_safety,
                                  sweep_temp)
            return False
        if record.get('state') not in ACTIVE or _queued_grace(record, now):
            return False
        _mark_interrupted(paths, store, record, now, restart_writers, cleanup_fresh, settle_dirs, package_safety,
                          sweep_temp)
    return True


def pinned_safety_records(records):
    """{restore record id: safety backup id or None} of the failed or interrupted (not rolled back) restores whose
    safety backup -- or, when the restore had none but changed the apps (allow_no_safety, or restoring a safety
    backup), whose source backup -- is still the only way back for one of their apps: no later restore of that app
    succeeded (review M2). A restore whose pre-restore copy is not packaged yet (`safety_pending`) or could not be
    (`safety_pending_failed`) pins the same way, whatever its state: that copy is the data before it. `records` newest
    first. Used by safety-backup pruning and by retention (such records are never deleted; retention also keeps each
    pinning record's source backup)."""
    pinned, settled = {}, set()
    for record in records:
        if record.get('type') != 'restore':
            continue
        params = record.get('params') if isinstance(record.get('params'), dict) else {}
        listed = params.get('apps') if isinstance(params.get('apps'), list) else []
        apps = {app for app in listed if isinstance(app, str)}
        result = record.get('result') if isinstance(record.get('result'), dict) else {}
        safety = result.get('safety_backup_id') or record.get('safety_backup_id')
        if (record.get('safety_pending') or record.get('safety_pending_failed')) and apps - settled:
            pinned[record['id']] = safety or None
        if record.get('state') == 'succeeded':
            settled |= apps
            continue
        changed = result.get('changed') is True or (record.get('state') == 'interrupted'
                                                    and _destructive_phase_reached(record))
        if ((safety or changed) and record.get('state') in ('failed', 'interrupted') and not result.get('rolled_back')
                and apps - settled):
            pinned[record['id']] = safety or None
    return pinned


def _sweep_orphans(store, now, live_groups=frozenset()):
    """Remove side files whose record is gone (a log, lock or cancel request), the stop request of an import none of
    whose jobs is active (`live_groups`: the groups of the active records) and temp files of interrupted writes, once they
    are ORPHAN_MAX_AGE old."""
    try:
        names = os.listdir(store.paths.jobs)
    except (FileNotFoundError, NotADirectoryError):
        return
    present = {name[:-5] for name in names if name.endswith('.json')}
    for name in names:
        side = SIDE_FILE_RE.fullmatch(name)
        stop = STOP_FILE_RE.fullmatch(name)
        if not (side and side.group(1) not in present) and not (stop and stop.group(1) not in live_groups) \
                and not TEMP_FILE_RE.fullmatch(name):
            continue
        path = Path(store.paths.jobs) / name
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(st.st_mode) and now - st.st_mtime >= ORPHAN_MAX_AGE:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)


def _live_groups(records):
    """The ids of the imports that have a queued or running job (hachain.group_of; a stop request of any other is stale)."""
    from . import hachain
    groups = set()
    for record in records:
        if record.get('state') in ACTIVE:
            group = hachain.group_of(record.get('params'))
            if group is not None:
                groups.add(group['id'])
    return groups


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
        if os.path.lexists(Path(store.paths.pending) / job_id):
            continue  # the record names the pre-restore copy (e.g. one that could not be packaged): kept with it
        finished += 1
        if finished <= keep:
            continue
        if pinned is None:
            pinned = pinned_safety_records(records)
        if job_id not in pinned:
            store.remove(job_id)
    _sweep_orphans(store, now, _live_groups(records))


def _recover_locked(paths, store, unit_active, now, restart_writers=None, cleanup_fresh=None, settle_dirs=None,
                    package_safety=None, sweep_temp=None):
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
                                    settle_dirs, package_safety, sweep_temp):
                        changed.append(job_id)
            finally:
                os.close(engine_fd)
    _sweep_staging(paths, store)
    _sweep_pending(paths, store)
    _sweep_key_files(paths, store, now)
    try:
        _retain(store, records, now)
    except Exception:  # noqa: BLE001 - housekeeping never breaks status/jobs/job-status; retried next pass
        traceback.print_exc(file=sys.stderr)
    return changed


def recover_interrupted(paths, *, unit_active=None, now=None, restart_writers=None, cleanup_fresh=None,
                        settle_dirs=None, package_safety=None, sweep_temp=None):
    """Mark dead queued/running jobs as interrupted; returns the affected job ids.

    `restart_writers({app_id: [units]}) -> [failed units]` restarts writers a dead backup left stopped;
    `cleanup_fresh([app_id]) -> [problems]` removes an unfinished fresh deployment;
    `settle_dirs(job_id, [app_id]) -> [notes]` settles the host-directory siblings a dead restore left;
    `package_safety(job_id) -> (backup id | None, problem | None)` packages a restore's pre-restore copy;
    `sweep_temp(job_id, owners) -> [problems]` removes a job's throwaway containers (default haimport.sweep_job).
    """
    if not Path(paths.jobs).is_dir():
        return []
    store = JobStore(paths)
    with start_lock(paths):
        return _recover_locked(paths, store, unit_active or systemd_unit_active, time.time() if now is None else now,
                               restart_writers, cleanup_fresh, settle_dirs, package_safety, sweep_temp)


def active_job(paths):
    store = JobStore(paths)
    for record in store.list(limit=None):
        if record.get('state') in ACTIVE:
            return record
    return None


def cancel_job(paths, job_id, *, after_this=False, wait_seconds=3.0, sleep=time.sleep, clock=time.monotonic):
    """Request cancellation; honoured at the job's next safe checkpoint. Returns {'state'}.

    Checked and requested under the record lock: the job cannot close its cancellable window or finish in
    between, so an accepted request is honoured before any destructive step, and a finished job never keeps
    a request file.

    A job of a Home Assistant import (hachain.py) stands for the whole import: its live job, queued or running, is the one
    cancelled (also when `job_id` names a job of the import that is over already, a moment ago), and the import stops with
    it. `after_this` instead lets the app the import is working on finish -- its restore still follows its conversion --
    and stops the import after it (a side file named after the group; accepted also while the job cannot be cancelled any
    more); the answer then has `after_this: true`. A job that belongs to no import refuses `after_this`.
    """
    from . import hachain
    store = JobStore(paths)
    with start_lock(paths):
        record = store.get(job_id)  # not-found before a lock file is created for an unknown id
        group = hachain.group_of(record.get('params'))
        if after_this and group is None:
            raise BackupError('invalid-request', '只有匯入作業可以要求「做完這個應用就停止」。', field='after_this')
        if group is not None:
            member = hachain.active_member(store, group['id'])
            if member is None:
                return {'state': record.get('state')}  # the import is over: nothing to cancel or stop
            job_id = member['id']
            if after_this:
                store.request_stop(group['id'])
                store.append_log(job_id, hachain.STOP_REQUESTED_LOG)
                return {'state': member.get('state'), 'after_this': True}
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


def _ha_key(record, key_file):
    """The raw HA key text of an HA import job's key file (None for other jobs or without a key)."""
    if key_file is None or not is_ha_job(record.get('type'), record.get('params')):
        return None
    from .haimport import read_key_file
    try:
        return read_key_file(key_file)
    except (BackupError, OSError):
        return None  # the job itself reports the unusable key


def _sweep_finished_temp(ctx):
    """Throwaway objects of jobs that are not running any more (tempctr.py) are removed when an HA job starts (the
    only jobs that make them; other jobs never wait for podman listings: review C-08); never blocks the job
    (`deps.sweep_temp`, absent in tests). What a dead job left is the recovery's (`temp_owners`)."""
    sweep = getattr(ctx.deps, 'sweep_temp', None)
    record = ctx.reporter.record
    if sweep is None or not is_ha_job(record.get('type'), record.get('params')):
        return
    try:
        sweep(ctx.job_id, ctx.log)
    except Exception:  # noqa: BLE001 - housekeeping only; details go to the journal
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


class _Deferred:
    """What `_termination_deferred` noted: a termination signal that arrived inside its block."""
    pending = False
    signum = None


@contextlib.contextmanager
def _termination_deferred():
    """Inside the block SIGTERM, SIGINT and SIGHUP are only noted (`.pending`), nothing is raised and nothing is lost: the
    short section that writes the next job of a chain and finishes this one must not be cut in half, and the caller still
    ends the process once it is done. Main thread only; elsewhere nothing changes."""
    state = _Deferred()
    if threading.current_thread() is not threading.main_thread():
        yield state
        return
    previous = {}

    def note(signum, _frame):
        state.pending, state.signum = True, signum

    try:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[sig] = signal.signal(sig, note)
        yield state
    finally:
        for sig, old in previous.items():
            signal.signal(sig, old)


class _Run:
    """The jobs one run-job process executes: the one it was given and, for an import (hachain.py), every job the chain adds
    to it. They share the engine lock, the masks of the HA key and the key itself, which from the first job's end on lives
    in this memory and nowhere else (its file goes); a restore chain keeps its first job's key file (an age key) for the
    jobs that follow, until the run ends."""

    def __init__(self, paths, store, lock_fd, masks, deps, handlers, follow):
        self.paths, self.store, self.lock_fd, self.masks = paths, store, lock_fd, masks
        self.deps, self.handlers, self.follow = deps, handlers, follow
        self.ha_key = None
        self.key_file = None   # the first job's key file while a restore chain still needs it
        self.taken = []        # the ids of the jobs this run took: a cancel request of each is cleared at the end

    def go(self, job_id):
        """Run `job_id` and what follows it; returns the record of `job_id` (the job this process was started for)."""
        record, next_id = self.execute(job_id, first=True)
        first = record
        while next_id is not None:
            record, next_id = self.execute(next_id, first=False)
        return first

    def execute(self, job_id, *, first):
        """One job, from queued to finished: (its record, the id of the job that follows or None)."""
        from . import flows, hachain
        store = self.store
        os.ftruncate(self.lock_fd, 0)
        os.pwrite(self.lock_fd, f'{job_id}\n'.encode(), 0)
        reporter = JobReporter(store, store.get(job_id))
        outcome = reporter.begin()
        self.taken.append(job_id)
        if outcome == 'not-queued':
            store.append_log(job_id, '作業不是等待中的狀態，不重新執行')
        if outcome != 'started':
            if outcome == 'cancelled' and self.follow and hachain.in_chain(reporter.record):
                with contextlib.suppress(Exception):  # the record is finished: only what the import did so far is added
                    hachain.unstarted(self.paths, store, reporter.record)
            return reporter.record, None
        key_file = store.key_path(job_id) if first else self.key_file
        ctx = flows.FlowContext(self.paths, job_id, self.deps, reporter,
                                key_file=key_file if key_file is not None and os.path.lexists(key_file) else None)
        if first:
            # The HA key of an import job is masked before the job writes its first log line (haimport.py).
            self.ha_key = _ha_key(reporter.record, ctx.key_file)
            if self.ha_key is not None:
                self.masks.enter_context(masked(self.ha_key))
        if self.ha_key is not None:
            ctx.ha_key = self.ha_key
        if first:
            _adopt_orphans(ctx)
        _sweep_finished_temp(ctx)
        table = self.handlers or {'backup': flows.run_backup, 'restore': flows.run_restore, 'verify': flows.run_verify,
                                  'export': flows.run_export}
        handler = table[reporter.record['type']]
        chained = self.follow and hachain.in_chain(reporter.record)
        state, result, error, exc, next_id = 'succeeded', None, None, None, None
        with signals_as_exceptions():
            try:
                result = handler(ctx, reporter.record.get('params') or {})
            except flows.Cancelled as caught:
                state, exc = 'cancelled', caught
            except flows.RolledBack as rolled:
                state, result, error, exc = 'rolled-back', rolled.result, rolled.error.as_dict(), rolled
            except Terminated as caught:
                _restart_after_termination(ctx)
                message, partial = interrupted_details(reporter.record)
                state, result, error, exc = 'interrupted', partial, {'code': 'job-failed', 'message': message}, caught
            except BackupError as caught:
                state, result, error, exc = 'failed', getattr(caught, 'result', None), caught.as_dict(), caught
            except Exception as caught:  # noqa: BLE001 - recorded generically, details go to the journal only
                traceback.print_exc(file=sys.stderr)
                state, error, exc = 'failed', {'code': 'internal-error', 'message': '作業發生未預期的內部錯誤，請查看系統日誌。'}, caught
            if chained:
                next_id = self._finish_chained(ctx, reporter, state, result, error, exc, first)
            else:
                reporter.finish(state, result=result, error=error)
        return reporter.record, next_id

    def _finish_chained(self, ctx, reporter, state, result, error, exc, first):
        """Finish a job of an import's chain: decide what comes next, write that job (queued), and only then write this
        job's final record, all under this record's lock (a `job-cancel` is either seen here or finds the live next job)
        and with termination signals only noted. Returns the id of the next job or None."""
        from . import hachain
        created = None
        with _termination_deferred() as deferred, self.store.locked(reporter.job_id):
            try:
                final, created = hachain.conclude(ctx, reporter.record, hachain.Outcome(state, result, error, exc))
            except Exception:  # noqa: BLE001 - the job's own outcome is recorded all the same; the import ends here
                traceback.print_exc(file=sys.stderr)
                final, created = result, None
            reporter.finish(state, result=final, error=error)
        if first and self.key_file is None and hachain.group_of(reporter.record.get('params'))['kind'] == 'ha-restore':
            self.key_file = ctx.key_file
        elif first:
            _remove_key_file(self.store, reporter.job_id)  # the HA key lives in memory from here on
        if created is not None and deferred.pending:
            hachain.abandon(self.paths, self.store, created)  # told to end meanwhile: the next job never starts
            created = None
        return created['id'] if created is not None else None

    def cleanup(self):
        for job_id in self.taken:
            with contextlib.suppress(BackupError, OSError):
                self.store.clear_cancel(job_id)


def run_job(paths, job_id, *, deps=None, lock_timeout=LOCK_WAIT_SECONDS, handlers=None, chain=True):
    """Execute a queued job in this process (the systemd-run unit). Never replays finished jobs. Returns the record of
    `job_id`. A job of a Home Assistant import (`params.group`, hachain.py) is followed by the jobs its chain adds, in this
    process and under the same engine lock (`chain=False` runs only the given job: the tests of one step)."""
    from . import flows
    store = JobStore(paths)
    lock_fd = None
    masks = contextlib.ExitStack()
    run = None
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
        run = _Run(paths, store, lock_fd, masks, deps or flows.default_deps(paths), handlers, chain)
        return run.go(job_id)
    finally:
        _remove_key_file(store, job_id)
        with contextlib.suppress(BackupError, OSError):
            store.clear_cancel(job_id)
        if run is not None:
            run.cleanup()
        if lock_fd is not None:
            with contextlib.suppress(OSError):
                os.ftruncate(lock_fd, 0)
            os.close(lock_fd)
        masks.close()


# Old private names, kept for callers and tests written against them.
_start_lock = start_lock
_signals_as_exceptions = signals_as_exceptions
