"""Backup / restore / verify orchestration used by jobs (CONTRACT section 9). Owner: E2.

The flows only talk to collaborators through `FlowContext` (storage, keys, archive, catalog,
adapters, reporter), so every step can be exercised with fakes. Key rules implemented here:
* space is checked before any writer is stopped;
* an archive is listed only after it was written atomically and fully verified;
* in-place restores take a verified `safety` backup first and roll back automatically after any
  failure that happens once the first destructive step started (fresh deployments are removed);
* staging (plaintext) is always removed in `finally`.
"""
import hashlib
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
    adapter_factory: object   # (app, *, log, phase, checkpoint) -> Adapter
    host_info: object         # () -> {'hostname','machine_id_sha256','arch','os','podman'}


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


def default_adapter_factory(app, *, log, phase=None, checkpoint=None, writers_hook=None):
    from .adapters import get_adapter
    from .podman import OwnerRunner
    cls = get_adapter(app.adapter)
    if cls is None:
        raise BackupError('internal-error', '找不到此應用的轉接器。', app=app.id)
    return cls(app, OwnerRunner(app.owner), log, phase=phase, checkpoint=checkpoint, writers_hook=writers_hook)


def default_deps(paths):
    from . import archive, catalog, keys, storage
    return Deps(storage=storage.Storage(paths), keys=keys.KeyStore(paths), archive=archive,
                load_catalog=lambda: catalog.load_catalog(paths), adapter_factory=default_adapter_factory,
                host_info=host_info)


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

    def log(self, message):
        self.reporter.log(message)

    def cancellable(self, flag):
        self.reporter.set_cancellable(flag)

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

    def adapter(self, app, *, phases=True):
        return self.deps.adapter_factory(app, log=self.log, phase=self.phase if phases else None,
                                         checkpoint=self.checkpoint,
                                         writers_hook=lambda units, app_id=app.id: self.note_writers(app_id, units))

    def identities(self):
        """Decryption identities: KeyInfo objects held by this device plus the job's temporary key file."""
        items = list(self.keys.identities())
        if self.key_file is not None and self.key_file.exists():
            items.append(self.key_file)
        return items

    def tool_version(self):
        lib = Path(self.paths.lib)
        return engine_version(lib) if (lib / 'VERSION').exists() else engine_version()


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


def download_filename(hostname, created):
    from . import util
    return util.download_filename(hostname, created)


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


def _cleanup_staging(ctx):
    try:
        ctx.storage.remove_staging(ctx.job_id)
    except Exception:  # noqa: BLE001 - never mask the job outcome; logged for the operator
        ctx.log('警告：無法完整清除暫存資料夾，請通知管理員檢查。')


def _require_key(ctx, header):
    available = {info.key_id for info in ctx.keys.identities()}
    if header.get('key_id') not in available and (ctx.key_file is None or not ctx.key_file.exists()):
        raise BackupError('key-required', '此備份使用的金鑰不在本設備，請輸入緊急金鑰。', key_id=header.get('key_id'))


def compare_snapshots(app, before, after):
    """True/False on the catalog's `compare` keys; None when the backup carried no comparable snapshot."""
    if not before:
        return None
    compared = False
    for spec in app.verify:
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


def verification_entry(app, adapter, app_manifest):
    if not app.verify:
        return None
    before = app_manifest.get('verify_snapshot') or {}
    after = adapter.verify_snapshot()
    return {'app': app.id, 'match': compare_snapshots(app, before, after), 'before': before, 'after': after}


# ---------------------------------------------------------------- backup

def run_backup(ctx, params):
    ctx.cancellable(True)
    ctx.phase('prepare')
    apps = resolve_apps(ctx.catalog(), params.get('apps') or [])
    key = ctx.keys.device_key()
    if key is None:
        raise BackupError('no-device-key', '尚未建立本設備的備份金鑰，請先完成金鑰設定。')
    ctx.storage.ensure_layout()
    staging = Path(ctx.storage.staging_dir(ctx.job_id))
    try:
        return create_backup(ctx, apps, staging, include_images=bool(params.get('include_images')),
                             note=params.get('note') or '', backup_type='manual', key=key, phases=True)
    finally:
        _cleanup_staging(ctx)


def create_backup(ctx, apps, staging, *, include_images, note, backup_type, key, phases, start_databases=False):
    """Back up `apps` into a verified, registered archive. `phases=False` for nested safety backups.

    `start_databases=True` (safety backups) first starts stopped database units so they can be dumped.
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

    manifest_apps, entries, downtime = [], [], 0.0
    for index, (app, adapter) in enumerate(zip(apps, adapters), 1):
        ctx.log(f'備份應用「{app.name}」（{index}/{len(apps)}）')
        app_dir = Path(staging) / 'apps' / app.id
        app_dir.mkdir(mode=0o700, parents=True)
        app_manifest, app_entries = adapter.backup(app_dir, include_images=include_images)
        downtime += float(adapter.last_downtime or 0)
        manifest_apps.append(app_manifest)
        entries.extend(app_entries)
    if downtime > 0:
        ctx.log(f'應用寫入暫停共 {downtime:.1f} 秒，服務已恢復')
    else:
        ctx.log('備份期間沒有暫停任何寫入服務（寫入服務原本未執行）')

    if phases:
        ctx.cancellable(True)
    phase('package')
    host = ctx.deps.host_info()
    backup_id = ctx.storage.new_backup_id()
    created = created_from_id(backup_id)
    header = {'format': 1, 'backup_id': backup_id, 'created': created, 'key_id': key.key_id,
              'encryption': 'age-x25519', 'compression': 'zstd'}
    manifest = {
        'format': 1, 'backup_id': backup_id, 'created': created, 'type': backup_type, 'note': note,
        'key_id': key.key_id, 'tool': {'name': TOOL_NAME, 'version': ctx.tool_version()},
        'source': {key_: host[key_] for key_ in ('hostname', 'machine_id_sha256', 'arch', 'os', 'podman')},
        'consistency': {'method': 'writers-stopped', 'downtime_seconds': int(round(downtime))},
        'apps': manifest_apps, 'entries': [],
    }
    dest = Path(ctx.storage.archive_path(backup_id))
    registered = False
    try:
        info = ctx.archive.write_archive(dest, header, manifest, entries, key.recipient, tmp_dir=staging,
                                         progress=ctx.byte_progress('加密封裝') if phases else None)
        phase('verify')
        if phases:
            ctx.checkpoint()
        checked = ctx.archive.verify_archive(dest, [key], progress=ctx.byte_progress('驗證備份') if phases else None)
        if (checked.get('manifest') or {}).get('backup_id') != backup_id:
            raise BackupError('corrupt-archive', '驗證備份時發現內容不一致，已捨棄此備份。')
        if phases:
            ctx.checkpoint()
        ctx.storage.register(backup_id, {
            'id': backup_id, 'type': backup_type, 'created': created, 'note': note,
            'apps': [{'id': app.id, 'name': app.name} for app in apps], 'size': int(info['size']),
            'sha256': info['sha256'], 'key_id': key.key_id, 'include_images': bool(include_images),
            'filename': download_filename(host['hostname'], created), 'source': {'hostname': host['hostname']},
            'verified': {'at': _now_iso(), 'ok': True}, 'inspected': True})
        registered = True
    finally:
        if not registered:
            _unlink_quiet(dest)
    ctx.log(f'備份 {backup_id} 已建立並通過完整驗證（{human(info["size"])}）')
    return {'backup_id': backup_id, 'size': int(info['size']), 'apps': [app.id for app in apps],
            'downtime_seconds': int(round(downtime))}


def prune_safety(ctx, app_ids, keep=SAFETY_KEEP, exclude=()):
    """Keep the `keep` newest safety backups per app; only backups touching `app_ids` are deleted.

    Backups in `exclude` (e.g. the archive being restored) are never deleted.
    """
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
    ctx.cancellable(True)
    ctx.phase('prepare')
    backup_id = params['backup_id']
    ctx.storage.get(backup_id)
    path = Path(ctx.storage.archive_path(backup_id))
    header = ctx.archive.read_header(path)
    _require_key(ctx, header)
    ctx.phase('decrypt')
    try:
        checked = ctx.archive.verify_archive(path, ctx.identities(), progress=ctx.byte_progress('解密並驗證'))
    except BackupError as error:
        if error.code in ARCHIVE_DEFECTS:
            ctx.storage.update(backup_id, verified={'at': _now_iso(), 'ok': False})
            ctx.log(f'驗證失敗：{error.message}')
        raise
    ctx.phase('check')
    manifest = checked.get('manifest') or {}
    if manifest.get('backup_id') != header.get('backup_id'):
        ctx.storage.update(backup_id, verified={'at': _now_iso(), 'ok': False})
        raise BackupError('corrupt-archive', '備份內容與檔頭不一致。')
    entries = checked.get('entries')
    count = entries if isinstance(entries, int) else len(entries or [])
    ctx.storage.update(backup_id, verified={'at': _now_iso(), 'ok': True})
    ctx.log(f'備份 {backup_id} 驗證通過：{count} 個項目，{human(checked.get("bytes", 0))}')
    return {'ok': True, 'entries': count, 'bytes': int(checked.get('bytes') or 0)}


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
    ctx.storage.ensure_layout()
    staging = Path(ctx.storage.staging_dir(ctx.job_id))
    result = {'apps': [app.id for app in apps], 'safety_backup_id': None, 'health': [], 'verification': [],
              'rolled_back': False}
    try:
        ctx.phase('decrypt')
        extract_dir = _private_dir(staging / 'extract')
        manifest = ctx.archive.extract_archive(path, ctx.identities(), extract_dir,
                                               progress=ctx.byte_progress('解密並驗證'))
        ctx.log(f'備份 {backup_id} 已解密並通過完整驗證')

        ctx.phase('preflight')
        plans = _preflight(ctx, apps, manifest)
        device_key = ctx.keys.device_key()
        inplace = [plan for plan in plans if plan.mode == 'inplace']
        if inplace and device_key is None:
            raise BackupError('no-device-key', '原位還原需要本設備的備份金鑰來建立還原前備份，請先完成金鑰設定。')
        ctx.checkpoint()
        ctx.cancellable(False)

        ctx.phase('safety')
        if inplace:
            ctx.log('建立還原前備份…')
            try:
                safety = create_backup(ctx, [plan.app for plan in inplace], _private_dir(staging / 'safety'),
                                       include_images=False, note=f'還原前自動備份（還原來源 {backup_id}）',
                                       backup_type='safety', key=device_key, phases=False, start_databases=True)
            except BackupError as error:
                if meta.get('type') != 'safety':
                    raise BackupError('job-failed', f'無法建立還原前備份，未做任何變更：{error.message}'
                                                    '若應用因先前的還原中斷或失敗而無法執行，請改為還原最近的「還原前備份」。',
                                      original=error.code) from None
                # Recovering *to* a pre-restore backup: the current state is the broken one we are replacing.
                ctx.log(f'無法建立新的還原前備份（{error.message}）；由於正在還原的就是還原前備份，將直接還原，'
                        '失敗時無法自動回復。')
            else:
                result['safety_backup_id'] = safety['backup_id']
                ctx.reporter.set_partial(safety_backup_id=safety['backup_id'])
            prune_safety(ctx, [plan.app.id for plan in inplace], exclude={backup_id})
        else:
            ctx.skip('safety')

        touched = []
        try:
            for plan in plans:
                touched.append(plan)
                label = '原位還原' if plan.mode == 'inplace' else '全新部署'
                ctx.log(f'還原應用「{plan.app.name}」（{label}）')
                plan.adapter.restore(plan.manifest, extract_dir, mode=plan.mode)
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
        except BaseException as exc:  # noqa: BLE001 - includes termination signals
            if not any(plan.adapter.destructive_started for plan in touched):
                raise
            error = exc if isinstance(exc, BackupError) else BackupError(
                'internal-error', '還原過程發生未預期的錯誤。')
            _rollback(ctx, touched, result, staging, error, device_key)
        ctx.log('還原完成')
        return result
    except BackupError as error:
        if not hasattr(error, 'result'):
            error.result = result if result['safety_backup_id'] else None
        raise
    finally:
        _cleanup_staging(ctx)


def _preflight(ctx, apps, manifest):
    plans, failures = [], []
    entry_sizes = {e.get('path'): e.get('size', 0) for e in manifest.get('entries') or [] if isinstance(e, dict)}
    for app in apps:
        app_manifest = next((a for a in manifest.get('apps') or [] if a.get('id') == app.id), None)
        if app_manifest is None:
            raise BackupError('incompatible', f'此備份不包含應用「{app.name}」。', app=app.id)
        adapter = ctx.adapter(app)
        mode = adapter.detect_mode()
        checks = adapter.preflight(app_manifest, mode=mode, entry_sizes=entry_sizes)
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


def _rollback(ctx, touched, result, staging, error, device_key):
    ctx.reporter.add_phase('rollback', '自動回復')
    ctx.phase('rollback')
    ctx.log(f'還原失敗：{error.message}')
    ctx.log('開始自動回復…')
    problems = []
    safety_id = result.get('safety_backup_id')
    inplace = [plan for plan in touched if plan.mode == 'inplace']
    if inplace:
        try:
            if not safety_id or device_key is None:
                raise BackupError('job-failed', '沒有可用的還原前備份。')
            folder = _private_dir(Path(staging) / 'rollback')
            safety_manifest = ctx.archive.extract_archive(ctx.storage.archive_path(safety_id), [device_key], folder)
            for plan in inplace:
                app_manifest = next(a for a in safety_manifest['apps'] if a.get('id') == plan.app.id)
                adapter = ctx.adapter(plan.app, phases=False)
                adapter.restore(app_manifest, folder, mode='inplace')
                failed = [c for c in adapter.health() if c['status'] == 'fail']
                if failed:
                    problems.append(f'「{plan.app.name}」回復後健康檢查未通過')
                    continue
                entry = verification_entry(plan.app, adapter, app_manifest)
                if entry is not None and entry['match'] is False:
                    problems.append(f'「{plan.app.name}」回復後資料與還原前不一致')
        except BackupError as rollback_error:
            problems.append(rollback_error.message)
        except Exception:  # noqa: BLE001
            problems.append('回復時發生未預期的錯誤')
    for plan in touched:
        if plan.mode != 'fresh':
            continue
        try:
            plan.adapter.remove_fresh()
        except BackupError as cleanup_error:
            problems.append(cleanup_error.message)
        except Exception:  # noqa: BLE001
            problems.append(f'移除「{plan.app.name}」新建立的項目時發生未預期的錯誤')
    if problems:
        result['rolled_back'] = False
        message = f'還原失敗，且自動回復未完成，需人工處理：{"；".join(problems)[:400]}'
        if safety_id:
            message += f'。可使用還原前備份 {safety_id} 再次還原。'
        ctx.log(message)
        failure = BackupError('job-failed', message, original=error.code, safety_backup_id=safety_id)
        failure.result = result
        raise failure
    result['rolled_back'] = True
    ctx.log('已自動回復到還原前的狀態')
    raise RolledBack(error, result)
