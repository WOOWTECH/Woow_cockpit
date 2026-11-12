"""Job records, systemd-run launcher, lock and recovery (CONTRACT section 8). Owner: E2.

* `start_job` validates, deduplicates by request_id (24 h), refuses with `busy` while another job is
  queued/running, writes the record and launches `systemd-run … run-job <id>` (injectable).
* `run_job` holds an exclusive flock on `paths.lock` for its lifetime, updates the record
  atomically at every phase/progress change and always deletes the job key file.
* `recover_interrupted` marks queued/running records whose unit is inactive and whose lock is
  free as `interrupted`; nothing is ever replayed automatically.
* Cancellation is a request file honoured by the flow only at safe checkpoints.
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
import time
import traceback
from pathlib import Path

from .errors import BackupError

PHASES = {
    'backup': (('prepare', '準備'), ('check', '檢查空間與應用'), ('stop', '暫停應用寫入'), ('dump', '匯出資料庫'),
               ('export', '匯出資料卷與設定'), ('start', '恢復應用'), ('package', '加密封裝'), ('verify', '驗證備份')),
    'restore': (('prepare', '準備'), ('decrypt', '解密並驗證檔案'), ('preflight', '相容性檢查'),
                ('safety', '建立還原前備份'), ('stop', '停止應用'), ('restore', '還原資料'), ('start', '啟動應用'),
                ('check', '健康與資料核對')),
    'verify': (('prepare', '準備'), ('decrypt', '解密並驗證檔案'), ('check', '核對結果')),
}
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
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
SECRET_PATTERN = re.compile(r'AGE-SECRET-KEY-1[0-9A-Za-z]+')

INTERRUPTED_MESSAGE = {
    'backup': '備份作業意外中斷（例如系統重新開機或程序被終止）。請確認應用已恢復執行後再重新備份。',
    'restore': '還原作業意外中斷（例如系統重新開機或程序被終止），應用可能處於不完整狀態。請檢查應用狀態，'
               '必要時使用還原前備份再次還原。',
    'verify': '驗證作業意外中斷，請重新執行驗證。',
}


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


def atomic_write_json(path, obj, mode=0o600):
    path = Path(path)
    data = (json.dumps(obj, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
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

    def create(self, job_type, params, *, request_id=None, now=None):
        if job_type not in PHASES:
            raise BackupError('invalid-request', '不支援的作業類型。')
        now = time.time() if now is None else now
        self.ensure()
        job_id = new_job_id(now)
        record = {
            'id': job_id, 'type': job_type, 'state': 'queued', 'phase': PHASES[job_type][0][0],
            'phases': [{'id': pid, 'label': label, 'state': 'pending'} for pid, label in PHASES[job_type]],
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
        atomic_write_json(self.path(record['id']), record)

    def list(self, limit=50):
        try:
            names = os.listdir(self.paths.jobs)
        except FileNotFoundError:
            return []
        records = []
        for name in names:
            if not name.endswith('.json') or not valid_job_id(name[:-5]):
                continue
            try:
                records.append(self.get(name[:-5]))
            except BackupError:
                continue
        records.sort(key=lambda r: (r.get('created') or '', r['id']), reverse=True)
        return records if limit is None else records[:limit]

    def append_log(self, job_id, message, now=None):
        line = redact(message).replace('\r', ' ').replace('\n', ' ')[:MAX_LOG_LINE]
        fd = os.open(self.log_path(job_id), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600)
        try:
            os.write(fd, f'{utc_iso(now)} {line}\n'.encode('utf-8'))
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
    """Single writer of a running job's record (atomic rewrite on every visible change)."""

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
        if bool(self.record.get('cancellable')) != bool(flag):
            self.record['cancellable'] = bool(flag)
            self._save()

    def cancel_requested(self):
        return self.store.cancel_requested(self.job_id)

    def set_partial(self, **fields):
        self.record.update(fields)
        self._save()

    def start(self):
        self.record['state'] = 'running'
        self.record['started'] = utc_iso()
        self._save()

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
def _start_lock(paths):
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


# ---------------------------------------------------------------- launcher / units

def systemd_run_launcher(paths):
    def launch(job_id):
        argv = ['/usr/bin/systemd-run', f'--unit={unit_name(job_id)}', '--collect', '--quiet',
                '--property=KillMode=mixed', str(paths.helper), 'run-job', job_id]
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
              restart_writers=None):
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
    with _start_lock(paths):
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
        _recover_locked(paths, store, unit_active or systemd_unit_active, now, restart_writers)
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
            _remove_key_file(store, job_id)
            error = exc if isinstance(exc, BackupError) else BackupError('internal-error', '無法啟動背景作業。')
            reporter = JobReporter(store, record)
            reporter.finish('failed', error={'code': error.code, 'message': error.message})
            if isinstance(exc, BackupError):
                raise
            raise error from None
        store.append_log(job_id, '作業已排入背景執行')
    return {'job_id': job_id, 'deduplicated': False}


def interrupted_details(record):
    """(zh-TW guidance, result|None) for a job that stopped without finishing."""
    message = INTERRUPTED_MESSAGE.get(record.get('type'), INTERRUPTED_MESSAGE['verify'])
    safety = record.get('safety_backup_id')
    if record.get('type') == 'restore' and safety:
        message += f'還原前備份：{safety}。'
        return message, {'apps': list((record.get('params') or {}).get('apps') or []), 'safety_backup_id': safety,
                         'health': [], 'verification': [], 'rolled_back': False}
    return message, None


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


def _recover_locked(paths, store, unit_active, now, restart_writers=None):
    changed = []
    lock_free = None
    for record in store.list(limit=None):
        if record.get('state') not in ACTIVE:
            continue
        created = parse_iso(record.get('created'))
        if record['state'] == 'queued' and created is not None and now - created < QUEUED_GRACE_SECONDS:
            continue
        if unit_active(record.get('unit') or unit_name(record['id'])):
            continue
        if lock_free is None:
            lock_free = lock_is_free(paths)
        if not lock_free:
            continue
        message, result = interrupted_details(record)
        if result is not None:
            record['result'] = result
        message += _restart_stopped_writers(store, record, restart_writers)
        for item in record.get('phases') or []:
            if item.get('state') == 'active':
                item['state'] = 'failed'
        record.update({'state': 'interrupted', 'finished': utc_iso(now), 'cancellable': False,
                       'error': {'code': 'job-failed', 'message': message}})
        record['progress'] = {'percent': (record.get('progress') or {}).get('percent', 0), 'message': '已中斷'}
        store.save(record)
        store.append_log(record['id'], f'作業被判定為已中斷：{message}')
        _remove_key_file(store, record['id'])
        if _remove_dead_staging(paths, record['id']):
            store.append_log(record['id'], '已清除中斷作業留下的暫存資料')
        changed.append(record['id'])
    _sweep_staging(paths, store)
    return changed


def recover_interrupted(paths, *, unit_active=None, now=None, restart_writers=None):
    """Mark dead queued/running jobs as interrupted; returns the affected job ids.

    `restart_writers({app_id: [units]}) -> [failed units]` restarts writers a dead backup left stopped.
    """
    if not Path(paths.jobs).is_dir():
        return []
    store = JobStore(paths)
    with _start_lock(paths):
        return _recover_locked(paths, store, unit_active or systemd_unit_active, time.time() if now is None else now,
                               restart_writers)


def active_job(paths):
    store = JobStore(paths)
    for record in store.list(limit=None):
        if record.get('state') in ACTIVE:
            return record
    return None


def cancel_job(paths, job_id, *, wait_seconds=3.0, sleep=time.sleep, clock=time.monotonic):
    """Request cancellation; honoured at the job's next safe checkpoint. Returns {'state'}."""
    store = JobStore(paths)
    with _start_lock(paths):
        record = store.get(job_id)
        if record.get('state') in TERMINAL:
            return {'state': record['state']}
        if not record.get('cancellable'):
            raise BackupError('not-cancellable', '作業已進入不可中斷的階段，將繼續執行到完成或自動回復。', job_id=job_id)
        store.request_cancel(job_id)
        store.append_log(job_id, '已收到取消要求，將在安全的檢查點停止')
    deadline = clock() + wait_seconds
    while clock() < deadline:
        record = store.get(job_id)
        if record.get('state') in TERMINAL:
            break
        sleep(0.2)
    return {'state': record.get('state')}


@contextlib.contextmanager
def _signals_as_exceptions():
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
        record = store.get(job_id)
        lock_fd = acquire_engine_lock(paths, lock_timeout)
        reporter = JobReporter(store, store.get(job_id) if lock_fd is not None else record)
        if lock_fd is None:
            if reporter.record.get('state') == 'queued':
                reporter.finish('failed', error={'code': 'busy', 'message': '另一個作業仍在執行，此作業未啟動。'})
            return reporter.record
        os.ftruncate(lock_fd, 0)
        os.write(lock_fd, f'{job_id}\n'.encode())
        if reporter.record.get('state') != 'queued':
            store.append_log(job_id, '作業不是等待中的狀態，不重新執行')
            return reporter.record
        if store.cancel_requested(job_id):
            reporter.finish('cancelled')
            return reporter.record
        reporter.start()
        key_file = store.key_path(job_id)
        ctx = flows.FlowContext(paths, job_id, deps or flows.default_deps(paths), reporter,
                                key_file=key_file if os.path.lexists(key_file) else None)
        table = handlers or {'backup': flows.run_backup, 'restore': flows.run_restore, 'verify': flows.run_verify}
        handler = table[reporter.record['type']]
        with _signals_as_exceptions():
            try:
                result = handler(ctx, reporter.record.get('params') or {})
            except flows.Cancelled:
                reporter.finish('cancelled')
            except flows.RolledBack as rolled:
                reporter.finish('rolled-back', result=rolled.result, error=rolled.error.as_dict())
            except Terminated:
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
