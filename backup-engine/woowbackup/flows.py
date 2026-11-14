"""Backup / restore / verify orchestration used by jobs (CONTRACT section 9). Owner: E2.

The flows only talk to collaborators through `FlowContext` (storage, keys, archive, catalog,
adapters, reporter), so every step can be exercised with fakes. Key rules implemented here:
* space is checked before any writer is stopped;
* an archive is listed only after it was written atomically and fully verified;
* in-place restores take a verified `safety` backup first and roll back automatically after any
  failure that happens once the first destructive step started (fresh deployments are removed);
* the record lists a fresh deployment for the recovery of a dead job only until that app's data import
  finished (review finding HD-04); the recovery itself never removes a deployment whose units run;
* the safety backup of the running restore, and any safety backup a failed restore still needs, is
  never pruned; pruning happens only after a successful restore;
* staging (plaintext) is always removed in `finally`.

Format 2 (CONTRACT section 5, 2026-11-13): new backups are written as `.tar` files, encrypted or not as the job asks
(the per-backup choice defaults to the device setting `encrypt_by_default`; safety backups follow the setting). A
restore extracts only the selected apps' archives; the verify job checks every entry like a restore would (deep);
an export job writes an unencrypted download copy that expires (`run_export`).
"""
import contextlib
import hashlib
import json
import os
import platform
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from . import version as engine_version
from .errors import BackupError

TOOL_NAME = 'woowtech-cockpit-backup'
SAFETY_KEEP = 3
SPACE_FACTOR = 2.2
SNAPSHOT_VALUE_MAX = 2048  # bytes of JSON per compared value kept in a job record
OMITTED = '（內容過長，已省略）'
ARCHIVE_DEFECTS = frozenset({'corrupt-archive', 'invalid-manifest', 'limit-exceeded', 'not-a-backup',
                             'unsupported-format'})


class Cancelled(Exception):
    """Raised at a safe checkpoint after the user asked to cancel."""


class RolledBack(Exception):
    """A restore failed after a destructive step and was rolled back successfully."""

    def __init__(self, error, result):
        super().__init__(error.message)
        self.error = error
        self.result = result


@dataclass
class Deps:
    storage: object
    keys: object
    archive: object
    load_catalog: object      # () -> catalog.Catalog
    adapter_factory: object   # (app, *, log, phase, checkpoint, writers_hook, imported_hook) -> Adapter
    host_info: object         # () -> {'hostname','machine_id_sha256','arch','os','podman'}
    system_stopping: object = None  # () -> bool: the machine is shutting down / rebooting
    encrypt_by_default: object = None  # () -> bool: the device setting 預設加密備份 (default: settings.json)
    schedule_cleanup: object = None    # (seconds, export_id) -> None: a timer that deletes expired download copies
    audit: object = None               # (line) -> None: the system journal (catalog_admin.audit_log)
    # (app_ids, *, exclude, log) -> [deleted backup ids]: keep-last-N of manual backups after a manual backup
    # (default: retention.enforce_after_backup with the saved policy)
    enforce_retention: object = None


def human(n):
    n = float(n or 0)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if n < 1024 or unit == 'TiB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024
    return str(n)


def _read_text(path, limit=65536):
    try:
        with open(path, 'rb') as handle:
            return handle.read(limit).decode('utf-8', 'replace')
    except OSError:
        return ''


def _os_name():
    for line in _read_text('/etc/os-release').splitlines():
        if line.startswith('PRETTY_NAME='):
            return line.split('=', 1)[1].strip().strip('"')[:200]
    return platform.system()


def _podman_version():
    try:
        out = subprocess.run(['/usr/bin/podman', '--version'], stdin=subprocess.DEVNULL, capture_output=True,
                             env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}, timeout=15,
                             check=False).stdout.decode('utf-8', 'replace')
    except (OSError, subprocess.TimeoutExpired):
        return 'unknown'
    words = out.split()
    return words[-1][:64] if words else 'unknown'


def host_info():
    import socket
    machine_id = _read_text('/etc/machine-id').strip()
    return {'hostname': (socket.gethostname() or 'device')[:255],
            'machine_id_sha256': hashlib.sha256(machine_id.encode()).hexdigest() if machine_id else '',
            'arch': platform.machine()[:32], 'os': _os_name(), 'podman': _podman_version()}


def system_stopping():
    """True while systemd shuts the machine down (`systemctl is-system-running` says "stopping")."""
    try:
        out = subprocess.run(['/usr/bin/systemctl', 'is-system-running'], stdin=subprocess.DEVNULL,
                             capture_output=True, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'},
                             timeout=5, check=False).stdout.decode('utf-8', 'replace').strip()
    except (OSError, subprocess.TimeoutExpired):
        return False
    return out == 'stopping'


def default_adapter_factory(app, *, log, phase=None, checkpoint=None, writers_hook=None, imported_hook=None):
    from .adapters import get_adapter
    from .podman import OwnerRunner
    cls = get_adapter(app.adapter)
    if cls is None:
        raise BackupError('internal-error', '找不到此應用的轉接器。', app=app.id)
    return cls(app, OwnerRunner(app.owner), log, phase=phase, checkpoint=checkpoint, writers_hook=writers_hook,
               imported_hook=imported_hook)


def default_deps(paths):
    from . import archive, catalog, keys, storage
    return Deps(storage=storage.Storage(paths), keys=keys.KeyStore(paths), archive=archive,
                load_catalog=lambda: catalog.load_catalog(paths), adapter_factory=default_adapter_factory,
                host_info=host_info, system_stopping=system_stopping)


def _noop(*_args, **_kwargs):
    return None


class FlowContext:
    """What a flow may touch. `reporter` is the job record writer (see jobs.JobReporter)."""

    def __init__(self, paths, job_id, deps, reporter, *, key_file=None):
        self.paths = paths
        self.job_id = job_id
        self.deps = deps
        self.reporter = reporter
        self.key_file = Path(key_file) if key_file else None
        self._catalog = None
        self._stopped_writers = {}
        self._unfinished_fresh = []
        # A failed restore could not undo a host-directory step (a moved-aside copy not put back, a new copy not
        # removed): the record keeps `dir_apps`, so the next recovery pass settles the directories again.
        self.dirs_unsettled = False

    @property
    def storage(self):
        return self.deps.storage

    @property
    def keys(self):
        return self.deps.keys

    @property
    def archive(self):
        return self.deps.archive

    def catalog(self):
        if self._catalog is None:
            self._catalog = self.deps.load_catalog()
        return self._catalog

    def phase(self, phase_id):
        self.reporter.phase(phase_id)

    def skip(self, phase_id):
        self.reporter.skip(phase_id)

    def complete(self, phase_id):
        """Mark a phase done without starting the next one (e.g. the safety backup exists)."""
        done = getattr(self.reporter, 'complete', None)
        if done is not None:
            done(phase_id)

    def log(self, message):
        self.reporter.log(message)

    def cancellable(self, flag):
        """Open/close the cancellable window. Closing it is a checkpoint: a cancel request accepted while the job
        was still cancellable stops the job here, before the destructive step that follows."""
        if self.reporter.set_cancellable(flag) and not flag:
            raise Cancelled()

    def checkpoint(self):
        if self.reporter.cancellable and self.reporter.cancel_requested():
            raise Cancelled()

    def byte_progress(self, label):
        def callback(done, total):
            self.checkpoint()
            fraction = min(1.0, done / total) if total else 1.0
            self.reporter.progress(fraction=fraction, message=f'{label}（{human(done)} / {human(total)}）')
        return callback

    def note_writers(self, app_id, units):
        """Persist which writer units are stopped right now, so recovery can restart them after a crash."""
        self._stopped_writers[app_id] = list(units)
        self.reporter.set_partial(stopped_writers={k: v for k, v in self._stopped_writers.items() if v})

    def mark_fresh(self, app_ids):
        """Record the apps about to be deployed from templates, before the first fresh step: a job that dies leaves
        a partial deployment, which the recovery removes (review finding CR-05)."""
        self._unfinished_fresh = list(app_ids)
        self.reporter.set_partial(fresh_apps=list(self._unfinished_fresh))

    def note_imported(self, app_id):
        """An app's data import finished (its units start next): it is no longer an unfinished fresh deployment.
        Dropped from the record before its units are unmasked, so a recovery after a reboot never removes a
        deployment users may already have written to (review finding HD-04)."""
        if app_id in self._unfinished_fresh:
            self._unfinished_fresh.remove(app_id)
            self.reporter.set_partial(fresh_apps=list(self._unfinished_fresh))

    def note_removing(self, app_id):
        """A rollback is about to remove this fresh deployment: list it again, so a job killed half-way through
        the removal leaves it to the recovery."""
        if app_id not in self._unfinished_fresh:
            self._unfinished_fresh.append(app_id)
            self.reporter.set_partial(fresh_apps=list(self._unfinished_fresh))

    def mark_dirs(self, app_ids):
        """Record the apps whose host directories this restore is about to write (siblings named after the job),
        before the first copy is written: the recovery of a job that dies settles what it left."""
        self.reporter.set_partial(dir_apps=list(app_ids))

    def adapter(self, app, *, phases=True):
        adapter = self.deps.adapter_factory(app, log=self.log, phase=self.phase if phases else None,
                                            checkpoint=self.checkpoint,
                                            writers_hook=lambda units, app_id=app.id: self.note_writers(app_id, units),
                                            imported_hook=lambda app_id=app.id: self.note_imported(app_id))
        adapter.job_id = self.job_id  # names the restore's host-directory siblings
        return adapter

    def identities(self):
        """Decryption identities: KeyInfo objects held by this device plus the job's temporary key file."""
        items = list(self.keys.identities())
        if self.key_file is not None and self.key_file.exists():
            items.append(self.key_file)
        return items

    def tool_version(self):
        lib = Path(self.paths.lib)
        return engine_version(lib) if (lib / 'VERSION').exists() else engine_version()

    def encrypt_by_default(self):
        """The device setting 預設加密備份 (CONTRACT section 7); encrypted when it cannot be read."""
        read = getattr(self.deps, 'encrypt_by_default', None)
        if read is not None:
            return bool(read())
        from . import settings
        return settings.encrypt_by_default(self.paths)

    def audit(self, line):
        write = getattr(self.deps, 'audit', None)
        if write is None:
            from .catalog_admin import audit_log as write
        write(line)

    def enforce_retention(self, app_ids, *, exclude=()):
        """Apply the saved keep-last-N policy to the manual backups of `app_ids` (CONTRACT section 8). Never fails
        the backup: a problem is logged and nothing more is deleted."""
        enforce = getattr(self.deps, 'enforce_retention', None)
        try:
            if enforce is not None:
                return list(enforce(list(app_ids), exclude=list(exclude), log=self.log) or [])
            from . import retention
            return retention.enforce_after_backup(self.paths, self.storage, list(app_ids), exclude=list(exclude),
                                                  log=self.log, audit=self.audit)
        except Exception as error:  # noqa: BLE001 - retention never fails a backup that was made
            self.log(f'警告：無法套用備份保留原則（{getattr(error, "message", None) or type(error).__name__}）')
            return []


# ---------------------------------------------------------------- helpers

def resolve_apps(catalog, app_ids):
    apps = []
    for app_id in app_ids:
        app = catalog.get(app_id)
        if app is None:
            problem = catalog.problem_for(app_id) if hasattr(catalog, 'problem_for') else None
            if problem and problem.get('code') == 'owner-missing':
                raise BackupError('owner-missing', problem['message'], app=app_id)
            raise BackupError('app-not-in-catalog', f'此設備沒有設定應用 {app_id}，無法處理。', app=app_id)
        apps.append(app)
    if not apps:
        raise BackupError('invalid-request', '請至少選擇一個應用。')
    return apps


def created_from_id(backup_id):
    stamp = backup_id.split('-', 1)[0]
    return f'{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]}T{stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}Z'


def _now_iso():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


RUNNING_RESERVE_MIN = 2 * 1024 * 1024 * 1024
RUNNING_RESERVE_FRACTION = 20  # 5 % of the filesystem
RUNNING_RESERVE_MAX = 10 * 1024 * 1024 * 1024


def running_reserve(ctx):
    """Space a job that runs while the apps keep running (verify, export) leaves free: 5 % of the filesystem, at least
    2 GiB and at most 10 GiB (never less than the configured reserve), so the apps' own writes (a database's WAL)
    still fit (review M4)."""
    total = getattr(ctx.storage, 'total_bytes', None)
    try:
        share = int(total()) // RUNNING_RESERVE_FRACTION if total is not None else 0
    except (OSError, TypeError, ValueError):
        share = 0
    return max(int(ctx.paths.reserve_bytes), min(max(RUNNING_RESERVE_MIN, share), RUNNING_RESERVE_MAX))


def download_filename(hostname, created, fmt=2):
    from . import util
    return util.download_filename(hostname, created, fmt)


def _private_dir(path):
    path = Path(path)
    if os.path.lexists(path):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            os.unlink(path)
    os.mkdir(path, 0o700)
    os.chmod(path, 0o700)
    return path


def _unlink_quiet(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _publish(staged, dest):
    """Move a verified archive from staging into archives/ (atomic rename, never overwrites)."""
    if os.path.lexists(dest):
        raise BackupError('internal-error', '目標備份檔已存在。')
    os.rename(staged, dest)
    fd = os.open(Path(dest).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _cleanup_staging(ctx):
    try:
        ctx.storage.remove_staging(ctx.job_id)
    except Exception:  # noqa: BLE001 - never mask the job outcome; logged for the operator
        ctx.log('警告：無法完整清除暫存資料夾，請通知管理員檢查。')


def _require_key(ctx, header):
    if header.get('encryption') == 'none':
        return  # an unencrypted backup needs no key
    available = {info.key_id for info in ctx.keys.identities()}
    if header.get('key_id') not in available and (ctx.key_file is None or not ctx.key_file.exists()):
        raise BackupError('key-required', '此備份使用的金鑰不在這台設備，請輸入緊急金鑰。', key_id=header.get('key_id'))


def _http_specs(app):
    return [spec for spec in app.verify if spec.get('type', 'http-json') == 'http-json']


def compare_snapshots(app, before, after):
    """True/False on the catalog's `compare` keys; None when the backup carried no comparable snapshot."""
    if not before:
        return None
    compared = False
    for spec in _http_specs(app):
        old = before.get(spec['id'])
        new = (after or {}).get(spec['id']) or {}
        if not isinstance(old, dict):
            continue
        for key in spec['compare']:
            if key not in old:
                continue
            compared = True
            if old[key] != new.get(key):
                return False
    return True if compared else None


def bounded_snapshot(app, snapshot):
    """Only the catalog's compared keys, each value at most SNAPSHOT_VALUE_MAX bytes of JSON.

    The archive's snapshot is untrusted: copied whole into the job record, a large one made the record
    unreadable (> 1 MiB) and the job looked interrupted (review finding SEC-5).
    """
    bounded = {}
    for spec in _http_specs(app):
        values = (snapshot or {}).get(spec['id'])
        if not isinstance(values, dict):
            continue
        kept = {}
        for key in spec['compare']:
            if key in values:
                value = values[key]
                kept[key] = value if len(json.dumps(value, ensure_ascii=True)) <= SNAPSHOT_VALUE_MAX else OMITTED
        bounded[spec['id']] = kept
    return bounded


def _combine(matches):
    """False when any check differs, True when at least one matched and none differs, else None."""
    matches = list(matches)
    return False if False in matches else (True if True in matches else None)


def digest_entry(app, adapter, entry=None):
    """Add the digest checks the adapter compared during its restore (before the units started) to a verification
    entry (CONTRACT section 7): `checks[]`, and per check its summary under `before`/`after` (so a table of the
    compared values shows the counts). Returns the entry, or None when there is nothing to report."""
    checks = [dict(item) for item in getattr(adapter, 'digest_results', None) or [] if isinstance(item, dict)][:16]
    if not checks:
        return entry
    entry = entry or {'app': app.id, 'match': None, 'before': {}, 'after': {}}
    for check in checks:
        for side in ('before', 'after'):
            if isinstance(check.get(side), dict):
                entry[side][check['id']] = dict(check[side])
    entry['checks'] = checks
    entry['match'] = _combine([entry['match']] + [check.get('match') for check in checks])
    return entry


def verification_entry(app, adapter, app_manifest):
    """The data check of one restored app: the http-json snapshot compared after the health checks, plus the digest
    checks compared before the units started (digest_entry)."""
    entry = None
    if _http_specs(app):
        before = app_manifest.get('verify_snapshot') or {}
        after = adapter.verify_snapshot()
        entry = {'app': app.id, 'match': compare_snapshots(app, before, after), 'before': bounded_snapshot(app, before),
                 'after': bounded_snapshot(app, after)}
    return digest_entry(app, adapter, entry)


def timing_entry(app, adapter):
    """{'app', 'writer_pause_seconds', 'unavailable_seconds'} of an adapter's last backup or restore."""
    report = getattr(adapter, 'timing_report', None)
    data = report() if callable(report) else {}
    return {'app': app.id, 'writer_pause_seconds': data.get('writer_pause_seconds'),
            'unavailable_seconds': data.get('unavailable_seconds')}


def _seconds(value):
    return f'{value:.1f}' if isinstance(value, (int, float)) else '—'


def release_handover(ctx, plans, handover):
    """Start the writers a safety backup left stopped for a restore that will not come (a failure or a refusal before
    the restore's first destructive step). Units that do not start stay listed in the record (`stopped_writers`), so
    the recovery tries again. Returns the units that did not start."""
    failed_all = []
    for plan in plans:
        info = handover.pop(plan.app.id, None)
        units = list((info or {}).get('units') or [])
        if not units:
            continue
        try:
            failed = list(plan.adapter.start_units(units) or [])
        except BackupError as error:
            ctx.log(f'警告：{error.message}')
            failed = units
        ctx.note_writers(plan.app.id, failed)
        failed_all.extend(failed)
        if not failed:
            ctx.log(f'已恢復「{plan.app.name}」被還原前備份暫停的服務')
    return failed_all


def restart_writers(deps, stopped, *, log=None):
    """Start writer units a backup left stopped ({app_id: [units]}); returns the units that failed."""
    failed = []
    catalog = deps.load_catalog()
    for app_id, units in (stopped or {}).items():
        app = catalog.get(app_id)
        if app is None:
            failed.extend(units)
            continue
        try:
            adapter = deps.adapter_factory(app, log=log or _noop, phase=None, checkpoint=None)
            # Writers a backup stopped, or every unit an in-place restore stopped before it masked them (still
            # unchanged then): only units of the app's own catalog entry.
            failed.extend(adapter.start_units([u for u in units if u in app.units]))
            failed.extend(u for u in units if u not in app.units)
        except BackupError:
            failed.extend(units)
    return failed


def remove_fresh_apps(deps, app_ids, *, log=None):
    """Remove the unfinished fresh deployments of `app_ids` (recovery after a dead restore); returns problems.

    Only a deployment that is still unfinished is removed. Once an app's data import finished its units are
    unmasked and start (also at boot), and users may have written to it since, so it is kept and reported for
    manual confirmation instead (review finding HD-04). The restore drops such an app from `fresh_apps` itself;
    this check also covers records an older engine wrote and a state that cannot be read.
    """
    problems = []
    catalog = deps.load_catalog()
    for app_id in app_ids or []:
        app = catalog.get(app_id)
        if app is None:
            problems.append(f'找不到應用 {app_id} 的設定')
            continue
        try:
            adapter = deps.adapter_factory(app, log=log or _noop, phase=None, checkpoint=None)
            try:
                live = adapter.fresh_in_use()
            except Exception:  # noqa: BLE001 - unknown is never "unfinished": keep it
                problems.append(f'無法確認「{app.name}」的服務狀態，為避免刪除可能已有的新資料而沒有自動移除；'
                                '需人工確認是否保留這個部署')
                continue
            if live:
                problems.append(f'「{app.name}」的服務（{"、".join(live)}）已解除暫時停用或正在執行，可能已有新的資料，'
                                '因此沒有自動移除；需人工確認是否保留這個部署')
                continue
            adapter.remove_fresh()
        except BackupError as error:
            problems.append(error.message.rstrip('。'))
        except Exception:  # noqa: BLE001 - reported, never raised from recovery
            problems.append(f'移除「{app.name}」未完成的部署時發生未預期的錯誤')
    return problems


def settle_dirs(deps, job_id, app_ids, *, log=None):
    """Recovery of a dead restore `job_id`: bring the host directories of `app_ids` to a safe final state (a missing
    directory gets its moved-aside copy back, new copies are removed, the only copy of earlier content is never
    deleted). Returns zh-TW notes about what was done and what is left."""
    notes = []
    catalog = deps.load_catalog()
    for app_id in app_ids or []:
        app = catalog.get(app_id)
        if app is None:
            notes.append(f'找不到應用 {app_id} 的設定，沒有整理它的主機資料夾，需人工確認')
            continue
        try:
            adapter = deps.adapter_factory(app, log=log or _noop, phase=None, checkpoint=None)
            adapter.job_id = job_id
            recover = getattr(adapter, 'recover_dirs', None)
            notes.extend(note for note in (recover() if recover else []) if isinstance(note, str))
        except BackupError as error:
            notes.append(f'「{app.name}」的主機資料夾：{error.message.rstrip("。")}，需人工確認')
        except Exception:  # noqa: BLE001 - reported, never raised from recovery
            notes.append(f'整理「{app.name}」的主機資料夾時發生未預期的錯誤，需人工確認')
    return notes


# ---------------------------------------------------------------- backup

def run_backup(ctx, params):
    ctx.cancellable(True)
    ctx.phase('prepare')
    apps = resolve_apps(ctx.catalog(), params.get('apps') or [])
    # `encrypt` (format 2): the per-backup choice the page sent, defaulting to the device setting there; records
    # written before the choice existed have none and are encrypted. An unencrypted backup needs no device key.
    encrypt = params.get('encrypt', True) is not False
    key = ctx.keys.device_key() if encrypt else None
    if encrypt and key is None:
        raise BackupError('no-device-key', '這台設備尚未建立加密金鑰，請先完成金鑰設定。')
    if not encrypt:
        ctx.log('這份備份不加密：應用機密（資料庫密碼、API 金鑰、存取權杖）會以明文存放在備份檔中')
    ctx.storage.ensure_layout()
    staging = Path(ctx.storage.staging_dir(ctx.job_id))
    try:
        result = create_backup(ctx, apps, staging, include_images=bool(params.get('include_images')),
                               note=params.get('note') or '', backup_type='manual', key=key, phases=True)
        out = {key_: result[key_] for key_ in ('backup_id', 'size', 'apps', 'downtime_seconds', 'unavailable_seconds',
                                               'timing')}
        out['encrypted'] = key is not None
        # Keep-last-N of manual backups (清理備份): older manual backups of these apps beyond the saved policy go,
        # never the new one or a protected backup.
        out['retention_deleted'] = ctx.enforce_retention([app.id for app in apps], exclude=[result['backup_id']])
        return out
    finally:
        _cleanup_staging(ctx)


def _release_kept(ctx, adapters):
    """A backup that left writers stopped for a restore failed afterwards: start them again (CONTRACT section 9)."""
    for adapter in adapters:
        kept = list(getattr(adapter, 'kept_stopped', None) or [])
        if not kept:
            continue
        try:
            failed = list(adapter.start_units(kept) or [])
        except BaseException:  # noqa: BLE001 - the backup's own error is raised; the record keeps the units
            failed = kept
        adapter.kept_stopped = []
        adapter.writers_hook(failed)


def create_backup(ctx, apps, staging, *, include_images, note, backup_type, key, phases, start_databases=False,
                  keep_stopped=False):
    """Back up `apps` into a verified, registered archive. `phases=False` for nested safety backups. `key` None writes
    an unencrypted backup (format 2, encryption "none").

    `start_databases=True` (safety backups) first starts stopped database units so they can be dumped.
    `keep_stopped=True` (the safety backup of an in-place restore): the writers stay stopped once the archive is
    registered; `handover` in the result names them per app with the time they stopped. A failure restarts them.
    """
    phase = ctx.phase if phases else _noop
    phase('check')
    adapters = [ctx.adapter(app, phases=phases) for app in apps]
    if start_databases:
        for adapter in adapters:
            adapter.ensure_databases_running()
    estimate = 0
    for app, adapter in zip(apps, adapters):
        info = adapter.probe()
        if not info['deployed']:
            raise BackupError('not-deployed', f'應用「{app.name}」尚未部署在此設備，無法備份。', app=app.id)
        if info['problems']:
            raise BackupError('job-failed', f'應用「{app.name}」狀態異常：{info["problems"][0]}', app=app.id)
        estimate += int(adapter.estimate_bytes(include_images=include_images))
    free = int(ctx.storage.free_bytes())
    required = int(estimate * SPACE_FACTOR) + int(ctx.paths.reserve_bytes)
    ctx.log(f'預估資料量 {human(estimate)}，需要可用空間 {human(required)}，目前可用 {human(free)}')
    if free < required:
        raise BackupError('insufficient-space', f'備份空間不足：預估需要 {human(required)}，目前可用 {human(free)}。'
                                                '應用未被暫停。', required=required, free=free)
    if phases:
        ctx.checkpoint()
        ctx.cancellable(False)

    manifest_apps, entries, downtime, timing = [], [], 0.0, []
    extra = {'keep_stopped': True} if keep_stopped else {}
    try:
        for index, (app, adapter) in enumerate(zip(apps, adapters), 1):
            ctx.log(f'備份應用「{app.name}」（{index}/{len(apps)}）')
            app_dir = Path(staging) / 'apps' / app.id
            app_dir.mkdir(mode=0o700, parents=True)
            app_manifest, app_entries = adapter.backup(app_dir, include_images=include_images, **extra)
            downtime += float(adapter.last_downtime or 0)
            timing.append(timing_entry(app, adapter))
            manifest_apps.append(app_manifest)
            entries.extend(app_entries)
        if keep_stopped:
            pass
        elif downtime > 0:
            ctx.log(f'應用寫入暫停共 {downtime:.1f} 秒，服務已恢復')
            for item in timing:
                if item['unavailable_seconds'] is not None:
                    ctx.log(f'「{item["app"]}」暫停寫入 {_seconds(item["writer_pause_seconds"])} 秒，'
                            f'從停止到健康檢查通過共 {_seconds(item["unavailable_seconds"])} 秒')
        else:
            ctx.log('備份期間沒有暫停任何寫入服務（寫入服務原本未執行）')
        result = _package(ctx, apps, staging, include_images=include_images, note=note, backup_type=backup_type,
                          key=key, phases=phases, manifest_apps=manifest_apps, entries=entries, downtime=downtime)
    except BaseException:
        if keep_stopped:
            _release_kept(ctx, adapters)
        raise
    unavailable = [item['unavailable_seconds'] for item in timing if item['unavailable_seconds'] is not None]
    result.update(timing=timing, unavailable_seconds=round(sum(unavailable), 1) if unavailable else None)
    if keep_stopped:
        result['handover'] = {app.id: {'units': list(adapter.kept_stopped), 'first_stop': adapter.timing.get('first_stop')}
                              for app, adapter in zip(apps, adapters) if getattr(adapter, 'kept_stopped', None)}
    return result


def _package(ctx, apps, staging, *, include_images, note, backup_type, key, phases, manifest_apps, entries, downtime):
    """Write, verify, publish and register the archive of a backup whose data is staged."""
    phase = ctx.phase if phases else _noop

    if phases:
        ctx.cancellable(True)
    phase('package')
    host = ctx.deps.host_info()
    backup_id = ctx.storage.new_backup_id()
    created = created_from_id(backup_id)
    encrypted = key is not None
    key_id = key.key_id if encrypted else None
    encryption = 'age-x25519' if encrypted else 'none'
    # Format 2 (CONTRACT section 5): backup.json + README.txt + one archive per app, encrypted with the device key or
    # (the administrator's choice) not at all.
    header = {'format': 2, 'backup_id': backup_id, 'created': created, 'key_id': key_id, 'encryption': encryption,
              'compression': 'zstd' if encrypted else 'gzip'}
    manifest = {
        'format': 2, 'backup_id': backup_id, 'created': created, 'type': backup_type, 'note': note,
        'key_id': key_id, 'encryption': encryption, 'tool': {'name': TOOL_NAME, 'version': ctx.tool_version()},
        'source': {key_: host[key_] for key_ in ('hostname', 'machine_id_sha256', 'arch', 'os', 'podman')},
        'consistency': {'method': 'writers-stopped', 'downtime_seconds': int(round(downtime))},
        'apps': manifest_apps, 'entries': [],
    }
    dest = Path(ctx.storage.archive_path(backup_id))
    # Written and verified inside staging, then moved into archives/ (same filesystem). A job killed while
    # packaging or verifying (SIGKILL, power loss) therefore leaves its archive only in staging, which the
    # recovery removes, instead of an unlisted, never-cleaned file in archives/ (lab H4 finding).
    staged = Path(staging) / dest.name
    published = registered = False
    try:
        info = ctx.archive.write_archive(staged, header, manifest, entries, key.recipient if encrypted else None,
                                         tmp_dir=staging,
                                         progress=ctx.byte_progress('加密封裝' if encrypted else '封裝') if phases else None)
        phase('verify')
        if phases:
            ctx.checkpoint()
        checked = ctx.archive.verify_archive(staged, [key] if encrypted else [],
                                             progress=ctx.byte_progress('驗證備份') if phases else None)
        if (checked.get('manifest') or {}).get('backup_id') != backup_id:
            raise BackupError('corrupt-archive', '驗證備份時發現內容不一致，已捨棄此備份。')
        if phases:
            ctx.checkpoint()
        _publish(staged, dest)
        published = True
        sizes = {item.get('id'): item.get('size') for item in info.get('apps') or [] if isinstance(item, dict)}
        ctx.storage.register(backup_id, {
            'id': backup_id, 'type': backup_type, 'created': created, 'note': note,
            'apps': [dict({'id': app.id, 'name': app.name},
                          **({'size': int(sizes[app.id])} if isinstance(sizes.get(app.id), int) else {}))
                     for app in apps],
            'size': int(info['size']), 'sha256': info['sha256'], 'key_id': key_id,
            'include_images': bool(include_images), 'filename': download_filename(host['hostname'], created, 2),
            'source': {'hostname': host['hostname']}, 'verified': {'at': _now_iso(), 'ok': True}, 'inspected': True,
            'format': 2, 'encrypted': encrypted})
        registered = True
    finally:
        if not registered:
            _unlink_quiet(staged)
            if published:
                _unlink_quiet(dest)
    ctx.log(f'備份 {backup_id} 已建立並通過完整驗證（{human(info["size"])}{"" if encrypted else "，未加密"}）')
    return {'backup_id': backup_id, 'size': int(info['size']), 'apps': [app.id for app in apps],
            'downtime_seconds': int(round(downtime)), 'plain_bytes': sum(int(e.size) for e in entries),
            'encrypted': encrypted}


def pinned_safety(paths):
    """Safety backups a failed or interrupted restore still points to (newest restore record per app wins), or None
    when a job record cannot be read (it may be such a restore: nothing is pruned then; review F11).

    They are the only way back to the state before that restore, so pruning never deletes them, also
    when the user retries the failed restore several times (review finding CR-02).
    """
    from . import jobs
    unreadable = []
    try:
        records = jobs.JobStore(paths).list(limit=None, unreadable=unreadable)
    except Exception:  # noqa: BLE001 - unreadable records never block a restore; pruning waits instead
        return None
    if unreadable:
        return None
    # Job retention never deletes these restore records, so the pins survive it (release regression 16 fix).
    return {backup_id for backup_id in jobs.pinned_safety_records(records).values() if backup_id}


def prune_safety(ctx, app_ids, keep=SAFETY_KEEP, exclude=()):
    """Keep the `keep` newest safety backups per app; only backups touching `app_ids` are deleted.

    Backups in `exclude` (the archive being restored and the safety backup this restore took) and
    safety backups a failed or interrupted restore still needs are never deleted.
    """
    pinned = pinned_safety(ctx.paths)
    if pinned is None:
        ctx.log('注意：無法讀取部分作業紀錄，這次不刪除較舊的還原前備份')
        return
    exclude = set(exclude) | pinned
    backups = [b for b in ctx.storage.list_backups() if b.get('type') == 'safety']
    backups.sort(key=lambda b: (b.get('created') or '', b.get('id') or ''), reverse=True)
    keepers, per_app = set(), {}
    for backup in backups:
        for item in backup.get('apps') or []:
            kept = per_app.setdefault(item.get('id'), [])
            if len(kept) < keep:
                kept.append(backup['id'])
                keepers.add(backup['id'])
    targets = set(app_ids)
    for backup in backups:
        ids = {item.get('id') for item in backup.get('apps') or []}
        if backup['id'] in keepers or backup['id'] in exclude or not ids & targets:
            continue
        try:
            ctx.storage.delete(backup['id'])
            ctx.log(f'已刪除較舊的還原前備份 {backup["id"]}')
        except BackupError:
            ctx.log(f'警告：無法刪除較舊的還原前備份 {backup["id"]}')


# ---------------------------------------------------------------- verify

def run_verify(ctx, params):
    """Deep verification (CONTRACT section 5): every entry of every app is read and checked the way a restore checks it
    before it changes anything (volume, directory and image tars, digest listings, role scripts, dumps, secrets), one
    entry at a time in a private scratch directory. 已驗證 (`verified.ok` with `deep`) then means a restore of this
    backup would accept its content; the device-specific checks stay with the restore preflight."""
    from .deepcheck import DeepCheck
    ctx.cancellable(True)
    ctx.phase('prepare')
    backup_id = params['backup_id']
    ctx.storage.get(backup_id)
    path = Path(ctx.storage.archive_path(backup_id))
    header = ctx.archive.read_header(path)
    _require_key(ctx, header)
    ctx.storage.ensure_layout()
    staging = Path(ctx.storage.staging_dir(ctx.job_id))
    try:
        scratch = _private_dir(staging / 'scratch')
        deep = DeepCheck(log=ctx.log)
        ctx.phase('decrypt')
        # One entry at a time is copied to scratch while the apps keep running: the larger reserve applies (M4).
        from .archive import Limits
        try:
            checked = ctx.archive.verify_archive(path, ctx.identities(), progress=ctx.byte_progress('解密並檢查內容'),
                                                 deep=deep, scratch_dir=scratch,
                                                 limits=Limits(reserve_bytes=running_reserve(ctx)))
        except BackupError as error:
            if error.code in ARCHIVE_DEFECTS:
                ctx.storage.update(backup_id, verified={'at': _now_iso(), 'ok': False, 'deep': True})
                ctx.log(f'驗證失敗：{error.message}')
            raise
        ctx.phase('check')
        manifest = checked.get('manifest') or {}
        if manifest.get('backup_id') != header.get('backup_id'):
            ctx.storage.update(backup_id, verified={'at': _now_iso(), 'ok': False, 'deep': True})
            raise BackupError('corrupt-archive', '備份內容與檔頭不一致。')
        for note in deep.notes[:20]:
            ctx.log(f'注意：{note}')
        entries = checked.get('entries')
        count = entries if isinstance(entries, int) else len(entries or [])
        ctx.storage.update(backup_id, verified={'at': _now_iso(), 'ok': True, 'deep': True})
        ctx.log(f'備份 {backup_id} 驗證通過：{count} 個項目，{human(checked.get("bytes", 0))}；'
                f'已檢查內容（{deep.summary_text()}）')
        return {'ok': True, 'entries': count, 'bytes': int(checked.get('bytes') or 0), 'deep': True,
                'format': int(checked.get('format') or 1),
                'encrypted': checked.get('encryption', 'age-x25519') != 'none', 'apps': deep.report(),
                'notes': [str(note)[:1000] for note in deep.notes[:50]]}
    finally:
        _cleanup_staging(ctx)


def _unauthenticated(meta, header):
    """An unencrypted backup that did not come from this device's jobs (upload, adopted file): nothing in it is
    authenticated, so a restore needs `accept_unauthenticated` (CONTRACT section 7)."""
    plain = header.get('encryption') == 'none' or meta.get('encrypted') is False
    return plain and meta.get('type') not in ('manual', 'safety')


# ---------------------------------------------------------------- export (unencrypted download copy)

EXPORT_PHASES = ('prepare', 'decrypt', 'package', 'verify')


def default_schedule_cleanup(paths, seconds, export_id):
    """A transient systemd timer that runs `export-cleanup` once the copy expired (also when no page asks)."""
    argv = ['/usr/bin/systemd-run', f'--on-active={int(seconds)}', '--timer-property=AccuracySec=5s', '--collect',
            '--quiet', f'--unit=woowtech-backup-export-clean-{export_id}', str(paths.helper), 'export-cleanup']
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}, timeout=60, check=False)
    if result.returncode != 0:
        raise OSError(result.stderr.decode('utf-8', 'replace')[-300:])


def run_export(ctx, params):
    """Re-pack an encrypted backup (format 1 or 2) into an unencrypted format 2 copy for one download (CONTRACT
    sections 5 and 8): apps/<id>.tar.gz inner archives, root 0600 in exports/, deleted after storage.EXPORT_TTL
    seconds. Each app is decrypted and fully verified on its own (its plaintext is in staging only meanwhile), the copy
    is verified as a whole before it is published, and every step is audited in the journal."""
    from . import storage as storage_mod
    from . import util
    ctx.cancellable(True)
    ctx.phase('prepare')
    backup_id = params['backup_id']
    ctx.storage.get(backup_id)
    path = Path(ctx.storage.archive_path(backup_id))
    header = ctx.archive.read_header(path)
    if header.get('encryption') == 'none':
        raise BackupError('invalid-request', '這份備份沒有加密，可以直接下載，不需要建立未加密副本。')
    _require_key(ctx, header)
    ctx.storage.ensure_layout()
    staging = Path(ctx.storage.staging_dir(ctx.job_id))
    try:
        ctx.phase('decrypt')
        identities = ctx.identities()
        manifest = ctx.archive.read_manifest(path, identities)
        plain = [sum(int(e['size']) for e in manifest['entries'] if e['path'].startswith(f'apps/{app["id"]}/'))
                 for app in manifest['apps']]
        total = sum(plain)
        # One app's plaintext at a time plus the copy (deflate never grows data by more than a few bytes per block),
        # and the larger reserve of a job that runs while the apps keep running (review M4).
        required = max(plain or [0]) + total + total // 100 + running_reserve(ctx)
        free = int(ctx.storage.free_bytes())
        if free < required:
            raise BackupError('insufficient-space', f'空間不足，無法建立未加密副本：需要約 {human(required)}，'
                                                    f'目前可用 {human(free)}。', required=required, free=free)
        export_id = ctx.storage.new_export_id()
        filename = util.download_filename(manifest['source']['hostname'], manifest['created'], 2,
                                          unencrypted_copy=True)
        staged = staging / f'{export_id}.tar'
        head = dict(ctx.archive.head_of(manifest), encryption='none', key_id=None)
        ctx.phase('package')
        progress = ctx.byte_progress('解密並封裝未加密副本')
        done = [0]

        def app_progress(offset, share):
            # Each app is read twice (decrypt and verify, then pack): each pass counts for half of its bytes.
            return lambda count, app_total: progress(offset + (share * count // app_total if app_total else share),
                                                     total)

        with ctx.archive.ArchiveWriter(staged, head, manifest['apps'], None, tmp_dir=staging) as writer:
            for app, size in zip(manifest['apps'], plain):
                folder = _private_dir(staging / 'app')
                extracted = ctx.archive.extract_archive(path, identities, folder, apps=[app['id']],
                                                        progress=app_progress(done[0], size // 2))
                if extracted.get('apps') != [app] or extracted.get('backup_id') != manifest['backup_id']:
                    raise BackupError('corrupt-archive', '備份內容在讀取期間改變，已停止。', app=app['id'])
                entries = [ctx.archive.Entry(e['path'], folder / e['path'], int(e['size']), e['sha256'])
                           for e in extracted['entries']]
                writer.add_app(app, entries, progress=app_progress(done[0] + size // 2, size - size // 2))
                done[0] += size
                _remove_tree(folder)
                ctx.log(f'已封裝「{app["name"]}」的未加密副本')
            ctx.checkpoint()
            info = writer.finish()
        ctx.phase('verify')
        checked = ctx.archive.verify_archive(staged, [], progress=ctx.byte_progress('驗證未加密副本'))
        if (checked.get('manifest') or {}).get('backup_id') != manifest['backup_id']:
            raise BackupError('corrupt-archive', '驗證未加密副本時發現內容不一致，已捨棄。')
        ctx.checkpoint()
        ttl = storage_mod.EXPORT_TTL
        # The timer is set before the copy is published: a job that dies right after publishing still has its copy
        # deleted on time (review L1). After a reboot (transient timers are gone) the next status, list, export or
        # job command deletes an expired copy.
        try:
            schedule = getattr(ctx.deps, 'schedule_cleanup', None)
            if schedule is not None:
                schedule(ttl + 5, export_id)
            else:
                default_schedule_cleanup(ctx.paths, ttl + 5, export_id)
        except Exception:  # noqa: BLE001 - the next status/list/export command deletes it as well
            ctx.log('注意：無法排定自動刪除未加密副本的計時器；下次開啟備份頁面或執行作業時會刪除過期的副本')
        evicted = []
        record = ctx.storage.publish_export(export_id, staged, backup_id=backup_id, filename=filename,
                                            sha256=info['sha256'], ttl=ttl, evicted=evicted)
        for old_id in evicted:  # every deletion of a plaintext copy is in the journal (review F17)
            ctx.audit(f'export-unencrypted-deleted export={old_id} reason=evicted job={ctx.job_id}')
        ctx.audit(f'export-unencrypted-created backup={backup_id} export={export_id} size={record["size"]} '
                  f'sha256={record["sha256"]} job={ctx.job_id}')
        ctx.log(f'已建立未加密的下載副本（{human(record["size"])}），{ttl // 60} 分鐘後自動刪除')
        return {'export_id': export_id, 'backup_id': backup_id, 'filename': filename, 'size': record['size'],
                'expires': record['expires']}
    finally:
        _cleanup_staging(ctx)


# ---------------------------------------------------------------- restore

class Plan:
    def __init__(self, app, adapter, manifest, mode):
        self.app, self.adapter, self.manifest, self.mode = app, adapter, manifest, mode


def run_restore(ctx, params):
    ctx.cancellable(True)
    ctx.phase('prepare')
    backup_id = params['backup_id']
    meta = ctx.storage.get(backup_id)
    path = Path(ctx.storage.archive_path(backup_id))
    apps = resolve_apps(ctx.catalog(), params.get('apps') or [])
    header = ctx.archive.read_header(path)
    _require_key(ctx, header)
    if _unauthenticated(meta, header) and params.get('accept_unauthenticated') is not True:
        raise BackupError('invalid-request', '這份上傳的備份沒有加密，內容無法驗證來源與完整性；'
                                             '需要另外確認信任這個檔案才能還原。', field='accept_unauthenticated')
    # Safety backups follow the device setting 預設加密備份 (read once for the whole job).
    encrypt_safety = ctx.encrypt_by_default()
    ctx.storage.ensure_layout()
    staging = Path(ctx.storage.staging_dir(ctx.job_id))
    # changed: a destructive step started; fresh_apps: deployed from templates; safety_skipped: in-place apps
    # were restored without a new safety backup; safety_failed: refused because none could be created;
    # timing: per app, writers stopped -> units running again -> health checks passed (CONTRACT section 7).
    result = {'apps': [app.id for app in apps], 'safety_backup_id': None, 'health': [], 'verification': [],
              'rolled_back': False, 'changed': False, 'fresh_apps': [], 'safety_skipped': False,
              'safety_failed': False, 'warnings': [], 'timing': []}
    keep_fresh_marker = False
    dirs_marked = False
    plans, handover = [], {}
    try:
        ctx.phase('decrypt')
        extract_dir = _private_dir(staging / 'extract')
        # Only the selected apps: a format 2 backup reads (and decrypts) no other app's archive.
        manifest = ctx.archive.extract_archive(path, ctx.identities(), extract_dir,
                                               progress=ctx.byte_progress('解密並驗證'),
                                               apps=[app.id for app in apps])
        ctx.log(f'備份 {backup_id} 已解密並通過完整驗證')

        ctx.phase('preflight')
        plans = _preflight(ctx, apps, manifest, extract_dir)
        device_key = ctx.keys.device_key()
        inplace = [plan for plan in plans if plan.mode == 'inplace']
        if inplace and encrypt_safety and device_key is None:
            raise BackupError('no-device-key', '原位還原需要這台設備的加密金鑰來建立還原前備份，請先完成金鑰設定。')
        ctx.checkpoint()
        ctx.cancellable(False)

        dir_apps = [plan.app.id for plan in plans if getattr(plan.app, 'data_dirs', ())]
        try:
            if dir_apps:
                # Before the first host-directory copy is written: a job that dies leaves siblings named after it, which
                # the recovery settles (moved-aside copies back where a directory is missing, new copies removed).
                ctx.mark_dirs(dir_apps)
                dirs_marked = True
                # Written next to the current directories while the apps still run (CONTRACT section 9): the stop
                # that follows only has to swap them in. Nothing that exists changes.
                ctx.phase('stage')
                for plan in plans:
                    stage = getattr(plan.adapter, 'stage_dirs', None)
                    if stage is not None and getattr(plan.app, 'data_dirs', ()):
                        stage(plan.manifest, extract_dir, mode=plan.mode)
            else:
                ctx.skip('stage')
            ctx.phase('safety')
            if inplace:
                safety = _take_safety_backup(ctx, inplace, staging, backup_id, meta, params,
                                             device_key if encrypt_safety else None, result)
                if safety is not None:
                    handover.update(safety.get('handover') or {})
                    extracted = sum(int(e.get('size') or 0) for e in manifest.get('entries') or [] if isinstance(e, dict))
                    _require_rollback_space(ctx, safety, extracted)
            else:
                ctx.skip('safety')
        except BaseException:
            _undo_preparation(ctx, plans, handover)
            raise
        fresh = [plan.app.id for plan in plans if plan.mode == 'fresh']
        if fresh:
            # Recorded before the first fresh step: a job that dies now leaves a partial deployment, which the
            # recovery removes (review finding CR-05). Each app leaves the record once its import finished (HD-04);
            # result['fresh_apps'] keeps naming every app deployed from templates.
            result['fresh_apps'] = list(fresh)
            ctx.mark_fresh(fresh)

        touched = []
        try:
            for plan in plans:
                touched.append(plan)
                label = '原位還原' if plan.mode == 'inplace' else '全新部署'
                ctx.log(f'還原應用「{plan.app.name}」（{label}）')
                info = handover.get(plan.app.id)
                take_over = getattr(plan.adapter, 'take_over', None)
                if info and take_over is not None:
                    take_over(info.get('units') or [], info.get('first_stop'))
                plan.adapter.restore(plan.manifest, extract_dir, mode=plan.mode,
                                     unchecked_databases_ok=bool(result['safety_skipped']))
                handover.pop(plan.app.id, None)
                _collect_warnings(result, plan.adapter)
                ctx.phase('check')
                health = plan.adapter.health()
                result['health'].extend(health)
                failed = [check for check in health if check['status'] == 'fail']
                if failed:
                    raise BackupError('job-failed', f'應用「{plan.app.name}」還原後健康檢查未通過：{failed[0]["message"]}',
                                      app=plan.app.id)
                entry = verification_entry(plan.app, plan.adapter, plan.manifest)
                if entry is not None:
                    result['verification'].append(entry)
                    if entry['match'] is False:
                        raise BackupError('job-failed', f'應用「{plan.app.name}」還原後的資料與備份時不一致。',
                                          app=plan.app.id)
                    if entry['match'] is None:
                        ctx.log(f'備份未包含「{plan.app.name}」的資料核對快照，已略過資料比對。')
                    else:
                        ctx.log(f'應用「{plan.app.name}」資料核對一致')
                timing = timing_entry(plan.app, plan.adapter)
                result['timing'].append(timing)
                if timing['unavailable_seconds'] is not None:
                    ctx.log(f'「{plan.app.name}」從停止到健康檢查通過共 {_seconds(timing["unavailable_seconds"])} 秒')
        except BaseException as exc:  # noqa: BLE001 - includes termination signals
            for plan in touched:
                _collect_warnings(result, plan.adapter)
            _record_failed_checks(result, touched)
            if not any(plan.adapter.destructive_started for plan in touched):
                _undo_preparation(ctx, plans, handover)
                raise
            result['changed'] = True
            if not isinstance(exc, Exception) and _shutting_down(ctx):
                # Reboot/poweroff (lab H5): the owner's services and Podman are going away, so a rollback cannot
                # finish and only produced a misleading "需人工處理" error. The job ends interrupted instead, with
                # the safety backup named in its guidance; a partial fresh deployment is removed by the recovery after
                # boot, and so are the copies and stopped writers of the apps the restore had not reached.
                keep_fresh_marker = True
                ctx.log('系統正在關機或重新開機，未執行自動回復；開機後請使用還原前備份再次還原。')
                raise
            error = exc if isinstance(exc, BackupError) else BackupError(
                'internal-error', '還原過程發生未預期的錯誤。')
            _rollback(ctx, touched, result, staging, error, device_key,
                      untouched=[plan for plan in plans if plan not in touched], handover=handover)
        result['changed'] = True
        # The job succeeded: the host-directory copies its restore moved aside can go now, and only now. Recorded
        # first, so a job that dies while deleting them is reported as a finished restore (review L4).
        ctx.reporter.set_partial(finishing=True)
        _finish_dirs(ctx, [plan.adapter for plan in plans], result)
        # Only after a successful restore, and never the backups this restore depends on (review SEC-2, CR-02).
        if inplace:
            prune_safety(ctx, [plan.app.id for plan in inplace], exclude={backup_id, result['safety_backup_id']})
        ctx.log('還原完成')
        return result
    except BackupError as error:
        if not hasattr(error, 'result'):
            error.result = result
        raise
    finally:
        if result['fresh_apps'] and not keep_fresh_marker:
            ctx.reporter.set_partial(fresh_apps=[])
        if dirs_marked and not keep_fresh_marker and not getattr(ctx, 'dirs_unsettled', False):
            # Settled in this process (finished, rolled back or reported); a shutdown, or a directory step the
            # rollback could not undo, leaves it to the recovery (which only moves copies back and removes new ones).
            ctx.reporter.set_partial(dir_apps=[])
        _cleanup_staging(ctx)


def _undo_preparation(ctx, plans, handover):
    """A failure (or a signal) before the restore's first destructive step: remove the directory copies stage_dirs()
    wrote ahead and start the writers the safety backup left stopped. Nothing that existed was changed. A copy that
    cannot be removed keeps the record's `dir_apps` for the recovery."""
    for plan in plans:
        if getattr(plan.app, 'data_dirs', ()):
            for problem in _discard_dirs(ctx, plan.adapter):
                ctx.log(f'注意：{problem}')
    release_handover(ctx, plans, handover)


def _record_failed_checks(result, touched):
    """The digest checks of an app whose restore stopped (e.g. a difference found before its units started) still
    reach the result, so the page can show what differed."""
    reported = {entry.get('app') for entry in result['verification'] if isinstance(entry, dict)}
    for plan in touched:
        if plan.app.id in reported:
            continue
        entry = digest_entry(plan.app, plan.adapter)
        if entry is not None:
            result['verification'].append(entry)


def _add_warning(result, note):
    if isinstance(note, str) and note not in result['warnings'] and len(result['warnings']) < 50:
        result['warnings'].append(note[:1000])


def _finish_dirs(ctx, adapters, result):
    """Delete the host-directory copies that `adapters` moved aside (the job, or that app's rollback, succeeded).
    A termination signal here does not undo a finished restore: the copies left are reported instead."""
    stopped = False
    for adapter in adapters:
        finish = getattr(adapter, 'finish_dirs', None)
        if finish is None:
            continue
        try:
            notes = finish()
        except BaseException as exc:  # noqa: BLE001 - incl. a termination signal: the restore itself is complete
            notes = ['刪除被取代的主機資料夾內容時發生錯誤或作業被中止；資料夾旁名稱含「.woowbk-old-」或「.woowbk-del-」的資料夾'
                     '可能還在，確認應用正常後可手動刪除。']
            stopped = not isinstance(exc, Exception)
        for note in notes or []:
            ctx.log(f'注意：{note}')
            _add_warning(result, note)
        if stopped:
            break  # a termination signal: leave the remaining copies (reported above) and end quickly


def _discard_dirs(ctx, adapter):
    """Undo an adapter's unfinished host-directory step after a failure; returns zh-TW problems. A problem keeps the
    record's `dir_apps`, so the recovery settles those directories again later. The record keeps them from the start
    of the discard until it finished cleanly: a termination signal in between leaves them to the recovery (F14)."""
    discard = getattr(adapter, 'discard_dirs', None)
    if discard is None:
        return []
    previous = getattr(ctx, 'dirs_unsettled', False)
    ctx.dirs_unsettled = True
    try:
        problems = [str(problem) for problem in discard() or []]
    except Exception:  # noqa: BLE001 - never skips the rollback of the other apps (review M1)
        problems = [f'無法整理「{adapter.app.name}」的主機資料夾，需人工確認']
    if not problems:
        ctx.dirs_unsettled = previous
    return problems


def _collect_warnings(result, adapter):
    """Notes an adapter made about what a restore could not keep (e.g. setuid bits; review finding HD-09)."""
    for note in getattr(adapter, 'warnings', None) or []:
        if isinstance(note, str) and note not in result['warnings'] and len(result['warnings']) < 50:
            result['warnings'].append(note[:1000])


def _take_safety_backup(ctx, inplace, staging, backup_id, meta, params, device_key, result):
    """Create the verified pre-restore backup; returns its create_backup result, or None when skipped. `device_key`
    None writes it unencrypted (the device setting 預設加密備份 is off)."""
    ctx.log('建立還原前備份…' if device_key is not None else '建立還原前備份（依設定不加密）…')
    folder = staging / 'safety'
    try:
        # The writers stay stopped for the restore (CONTRACT section 9): the apps stop once, not twice.
        safety = create_backup(ctx, [plan.app for plan in inplace], _private_dir(folder),
                               include_images=False, note=f'還原前自動備份（還原來源 {backup_id}）',
                               backup_type='safety', key=device_key, phases=False, start_databases=True,
                               keep_stopped=True)
    except BackupError as error:
        source_is_safety = meta.get('type') == 'safety'
        if not source_is_safety and not params.get('allow_no_safety'):
            result['safety_failed'] = True
            raise BackupError('job-failed', f'無法建立還原前備份，未做任何變更：{error.message}'
                                            '若應用因先前的還原中斷或失敗而無法執行，請改為還原最近的「還原前備份」；'
                                            '沒有可用的還原前備份時，可選擇不建立還原前備份直接還原（失敗時無法自動回復）。',
                              original=error.code) from None
        # Recovering *to* a pre-restore backup, or the user explicitly accepted it (review CR-16): the current
        # state is the broken one being replaced.
        reason = '由於正在還原的就是還原前備份' if source_is_safety else '你已選擇不建立還原前備份'
        ctx.log(f'無法建立新的還原前備份（{error.message}）；{reason}，將直接還原，失敗時無法自動回復。')
        ctx.skip('safety')
        result['safety_skipped'] = True
        return None
    finally:
        # Plaintext of a backup that is already published: removed now, so a rollback has its space (CR-01).
        _remove_tree(folder)
    result['safety_backup_id'] = safety['backup_id']
    ctx.reporter.set_partial(safety_backup_id=safety['backup_id'])
    ctx.complete('safety')
    return safety


def _require_rollback_space(ctx, safety, extracted_bytes):
    """Refuse the restore (nothing changed yet) unless a rollback could extract the safety backup.

    The rollback deletes the extracted archive first, so its size counts as available (review CR-01).
    """
    need = int(safety.get('plain_bytes') or 0) + int(ctx.paths.reserve_bytes)
    free = int(ctx.storage.free_bytes()) + int(extracted_bytes)
    if free < need:
        raise BackupError('insufficient-space', f'空間不足以在還原失敗時自動回復：需要約 {human(need)}，'
                                                f'可用約 {human(free)}。已建立還原前備份，未做任何變更。',
                          required=need, free=free)


def _remove_tree(path):
    path = Path(path)
    if os.path.lexists(path):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)
        else:
            with contextlib.suppress(OSError):
                os.unlink(path)


def _shutting_down(ctx):
    check = getattr(ctx.deps, 'system_stopping', None)
    try:
        return bool(check and check())
    except Exception:  # noqa: BLE001 - unknown means "not shutting down": keep the rollback
        return False


def _preflight(ctx, apps, manifest, extract_dir=None):
    """Per-app preflight of the extracted archive; the nested image and volume tars are checked here already, so
    a backup that would be refused fails before the safety backup is taken (review finding HD-01)."""
    plans, failures = [], []
    entry_sizes = {e.get('path'): e.get('size', 0) for e in manifest.get('entries') or [] if isinstance(e, dict)}
    for app in apps:
        app_manifest = next((a for a in manifest.get('apps') or [] if a.get('id') == app.id), None)
        if app_manifest is None:
            raise BackupError('incompatible', f'此備份不包含應用「{app.name}」。', app=app.id)
        adapter = ctx.adapter(app)
        mode = adapter.detect_mode()
        checks = adapter.preflight(app_manifest, mode=mode, entry_sizes=entry_sizes, extracted_dir=extract_dir)
        for check in checks:
            if check['status'] == 'warn':
                ctx.log(f'注意：{check["message"]}')
        failed = [check for check in checks if check['status'] == 'fail']
        for check in failed:
            ctx.log(f'未通過：{check["message"]}')
        if failed:
            failures.extend(failed)
        plans.append(Plan(app, adapter, app_manifest, mode))
    if failures:
        raise BackupError('incompatible', '相容性檢查未通過：' + '；'.join(c['message'] for c in failures)[:800],
                          checks=failures[:20])
    return plans


def _rollback(ctx, touched, result, staging, error, device_key, *, untouched=(), handover=None):
    ctx.reporter.add_phase('rollback', '自動回復')
    ctx.phase('rollback')
    ctx.log(f'還原失敗：{error.message}')
    ctx.log('開始自動回復…')
    # The failed archive's plaintext is not needed any more; free its space before extracting the safety
    # backup (review finding CR-01).
    _remove_tree(Path(staging) / 'extract')
    problems = []
    # Apps the restore never reached are unchanged: their copies written ahead go, their writers start again.
    for plan in untouched:
        if getattr(plan.app, 'data_dirs', ()):
            problems.extend(_discard_dirs(ctx, plan.adapter))
    # A host-directory step the failure cut short: a directory moved aside but not replaced goes back, the new copy
    # being written is removed. Directories already swapped stay for the rollback (or the fresh removal) below.
    for plan in touched:
        problems.extend(_discard_dirs(ctx, plan.adapter))
    # An app whose restore was refused before its first destructive step is unchanged too: nothing to roll back.
    unchanged = list(untouched) + [plan for plan in touched if not plan.adapter.destructive_started]
    failed = release_handover(ctx, unchanged, handover if handover is not None else {})
    if failed:
        problems.append(f'無法重新啟動服務 {", ".join(failed)}')
    safety_id = result.get('safety_backup_id')
    inplace = [plan for plan in touched if plan.mode == 'inplace' and plan.adapter.destructive_started]
    if inplace:
        folder = safety_manifest = None
        try:
            if not safety_id:
                raise BackupError('job-failed', '沒有可用的還原前備份。')
            folder = _private_dir(Path(staging) / 'rollback')
            # An encrypted safety backup opens with the device key; an unencrypted one (setting off) needs none.
            safety_manifest = ctx.archive.extract_archive(ctx.storage.archive_path(safety_id),
                                                          [device_key] if device_key is not None else [], folder)
        except BackupError as rollback_error:
            problems.append(rollback_error.message.rstrip('。'))
        except Exception:  # noqa: BLE001
            problems.append('回復時發生未預期的錯誤')
        # Each app is rolled back on its own: one failing app must not leave the others in the failed
        # restore's state (review finding CR-03).
        for plan in inplace if safety_manifest is not None else []:
            name = plan.app.name
            adapter = None
            verified = False
            try:
                app_manifest = next((a for a in safety_manifest.get('apps') or [] if a.get('id') == plan.app.id), None)
                if app_manifest is None:
                    raise BackupError('job-failed', '還原前備份不含此應用')
                adapter = ctx.adapter(plan.app, phases=False)
                # The rollback owns the app's stopped units from here (they are stopped and masked): the safety backup's
                # hand-over entry must not make a later recovery start them on whatever the rollback leaves.
                (handover or {}).pop(plan.app.id, None)
                ctx.note_writers(plan.app.id, [])
                swapped = getattr(plan.adapter, 'swapped_dirs', None)
                adapter.restore(app_manifest, folder, mode='inplace', rollback=True,
                                replaced_dirs=swapped() if swapped else ())
                failed = [c for c in adapter.health() if c['status'] == 'fail']
                if failed:
                    problems.append(f'「{name}」回復後健康檢查未通過')
                else:
                    entry = verification_entry(plan.app, adapter, app_manifest)
                    if entry is not None and entry['match'] is False:
                        problems.append(f'「{name}」回復後資料與還原前不一致')
                    else:
                        verified = True
                        if entry is None or entry['match'] is None:
                            # Nothing to compare (no digest; the safety backup kept no http-json snapshot): the health
                            # checks passed, the data was not compared (review F16) -- said, not implied.
                            note = f'「{name}」已回復，回復後通過健康檢查；這次回復沒有可比對的資料核對值，未比對資料。'
                            ctx.log(f'注意：{note}')
                            _add_warning(result, note)
                        ctx.log(f'應用「{name}」已回復到還原前的狀態')
            except BackupError as rollback_error:
                problems.append(f'「{name}」：{rollback_error.message.rstrip("。")}')
            except Exception:  # noqa: BLE001
                problems.append(f'「{name}」回復時發生未預期的錯誤')
            if adapter is not None and verified:
                # This app's rollback is verified: the failed restore's directory data it moved aside can go; the
                # pre-restore content stays and is reported (never the only copy).
                _finish_dirs(ctx, [adapter], result)
            elif adapter is not None:
                problems.extend(_discard_dirs(ctx, adapter))
    for plan in touched:
        if plan.mode != 'fresh' or not plan.adapter.destructive_started:
            continue  # refused before its first step: nothing was deployed (its copies written ahead are gone)
        try:
            ctx.note_removing(plan.app.id)
            plan.adapter.remove_fresh()
        except BackupError as cleanup_error:
            problems.append(cleanup_error.message.rstrip('。'))
        except Exception:  # noqa: BLE001
            problems.append(f'移除「{plan.app.name}」新建立的項目時發生未預期的錯誤')
    if problems:
        result['rolled_back'] = False
        for plan in touched:  # where the copies of each host directory are now (nothing of them was deleted)
            leftovers = getattr(plan.adapter, 'dir_leftovers', None)
            try:
                notes = leftovers() if leftovers else []
            except Exception:  # noqa: BLE001 - a report only; the failure below is raised either way
                notes = [f'無法列出「{plan.app.name}」主機資料夾旁留下的資料夾，需人工確認']
            for note in notes:
                ctx.log(f'注意：{note}')
                _add_warning(result, note)
        message = f'還原失敗，且自動回復未完成，需人工處理：{"；".join(problems)[:400].rstrip("。")}。'
        if safety_id:
            message += f'可使用還原前備份 {safety_id} 再次還原。'
        ctx.log(message)
        failure = BackupError('job-failed', message, original=error.code, safety_backup_id=safety_id)
        failure.result = result
        raise failure
    result['rolled_back'] = True
    ctx.log('已自動回復到還原前的狀態')
    raise RolledBack(error, result)
