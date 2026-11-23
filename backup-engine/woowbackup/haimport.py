"""Home Assistant import jobs: check and convert (CONTRACT sections 7, 8 and 9 "Home Assistant import"; branch
feat/ha-import, part B). Owner: E2.

* `run_ha_check(ctx, params)` -- job type `verify` with `params.source == 'ha'` (phases 準備, 解開 HA 備份, 檢查內容與版本):
  decrypts only the selected add-ons' members, rebuilds what it must read in throwaway containers (tempctr.py), compares
  with this device's apps and returns `{ha_check}`. Nothing of the apps changes; they keep running.
* `run_ha_convert(ctx, params)` -- job type `backup` with `params.source == 'ha'` (phases 準備, 解開 HA 備份, 轉換資料,
  封裝備份, 驗證備份): rebuilds the selected apps' data in their own format (the importer modules of haapps.py:
  ha_odoo.py, ha_n8n.py, ...) and writes a normal
  format 2 backup of them -- the data items converted, everything else (secrets, config files, Quadlet files, images list,
  the installed settings) read live as the owner without stopping anything, exactly like a backup reads it -- of type
  `manual` with the note 「由 HA 備份轉換：<HA name>（<HA date>）」, encrypted with the device key when 預設加密備份 is on,
  verified and registered like any backup; the row in `ha-imports.json` tells `list` where it came from (`from_ha`).
  Importing it is the existing restore (pre-restore backup, rollback). No retention runs in this job.

The HA key the page sent is in the job's key file (raw UTF-8, written by jobs.start_job with key_kind 'ha'); run-job
masks it in every log line before the job starts and hands it over as `ctx.ha_key`. It is never written anywhere else.

`ha-imports.json` (`<data>/ha-imports.json`, root 0600, strict; written under the index lock): `{schema: 1, imports:
{<backup id>: ImportRow}}`, ImportRow = `{ha_backup_id, name, date, apps, odoo_database, test_mode, workflows_to_fix,
reminders, reminders_by_app, notes, addons, job_id, created}` (rows written before reminders_by_app and notes existed
get them empty). Every text is cleaned and cut when the row is written, so whatever a
conversion found is accepted (review C-03). A row is written before the backup is packaged (its id is chosen first)
and dropped when the job fails before the backup is in the index, when the backup is deleted, or later when its
backup no longer exists. Deleting the HA file never touches it: a converted backup keeps its origin.
"""
import contextlib
import fcntl
import os
import re
import sys
import threading
import time
import traceback
from pathlib import Path

from . import haapps, habackup, hasecuretar, hastore, tempctr, util
from .errors import BackupError

# catalog id -> add-on slug (after the repository prefix), from the one registry of importers (haapps.IMPORTERS)
APPS = {importer.app_id: importer.slug for importer in haapps.IMPORTERS}
ITEM_KEYS = ('volumes', 'postgres', 'dirs')  # what a module's convert hands to adapter.import_manifest
# A module's readback for the restore (CONTRACT section 5 `import_check`, section 9): {kind: app id}. The converted
# backup's app section carries it; the restore compares it after the units started (verify_import) and rolls back
# on a difference; another kind or app refuses the restore in its preflight (import_check_problem).
CHECK_KEY = 'import_check'
IMPORT_CHECKS = {'emqx-readback': 'emqx'}
REGISTRY = 'ha-imports.json'
REGISTRY_SCHEMA = 1
REGISTRY_MAX = 1000
ROW_KEYS = ('ha_backup_id', 'name', 'date', 'apps', 'odoo_database', 'test_mode', 'workflows_to_fix', 'reminders',
            'addons', 'job_id', 'created')
# Keys added after the first rows were written (a row without them gets the empty value; review UI-3, P-05).
ROW_EXTRA = {'reminders_by_app': dict, 'notes': list}
VIEW_KEYS = ('ha_backup_id', 'name', 'date', 'apps', 'odoo_database', 'test_mode', 'workflows_to_fix', 'reminders',
             'reminders_by_app', 'notes', 'addons')
MAX_LINES = 20
STALE_ROW_SECONDS = 24 * 3600
MAX_KEY_BYTES = 4096
GUARD_STEP = 64 * 1024 * 1024
# Free space the watchdog keeps on top of the running reserve: what containers may write between two of its looks.
WATCH_MARGIN = 512 * 1024 * 1024
WATCH_INTERVAL = 2.0
NOTE_PREFIX = '由 HA 備份轉換：'
FAILURE_CODES = frozenset({'incompatible', 'job-failed', 'not-found', 'unsupported-format', 'app-not-in-catalog',
                           'owner-missing', 'not-deployed', 'limit-exceeded'})
INSTALL_HINT = '請先到「應用軟體」安裝同版本的 {name}，再匯入。'


# ====================================================================== space

class SpaceGuard:
    """Free space while a job writes (staging on the data disk, throwaway volumes in the owner's Podman storage):
    every GUARD_STEP bytes the engine writes, before each large step (`check(need)`) and, for what containers
    write, every WATCH_INTERVAL seconds (Watchdog) the free space of every watched folder must stay above `floor`
    (the running reserve plus WATCH_MARGIN), else insufficient-space: the apps run meanwhile and their own writes
    (a database's WAL) must still fit (review HA-SEC-04, C-01)."""

    def __init__(self, folders, floor, *, statvfs=os.statvfs):
        self.folders = [str(f) for f in folders]
        self.floor = int(floor)
        self.statvfs = statvfs
        self._since = 0

    def free(self):
        values = []
        for folder in self.folders:
            try:
                st = self.statvfs(folder)
            except OSError:
                continue
            values.append(st.f_bavail * st.f_frsize)
        return min(values) if values else None

    def check(self, need=0):
        free = self.free()
        if free is not None and free - int(need) < self.floor:
            from .flows import human
            raise BackupError('insufficient-space', f'空間不足：轉換需要再保留 {human(self.floor + int(need), up=True)}，'
                                                    f'目前只剩 {human(free, down=True)}。這台的應用沒有任何變更。',
                              required=self.floor + int(need), free=free)

    def wrote(self, n):
        self._since += int(n)
        if self._since >= GUARD_STEP:
            self._since = 0
            self.check()

    def budget(self):
        """Bytes a streamed output may write before only the floor is left (the runner's file budget)."""
        free = self.free()
        return None if free is None else max(0, free - self.floor)


class Watchdog:
    """A thread that looks every WATCH_INTERVAL seconds at the free space (the guard's folders) and at the job's
    cancel request while the job runs. Space below the floor: every throwaway container of the job is killed at once
    (their writes stop) and the job fails with insufficient-space; a cancel request: the job stops (`cancelled`). The
    job's blocked podman call asks `abort()` every second and stops; the job's `finally` removes the objects (review
    HA-SEC-04, C-01, C-15)."""

    def __init__(self, work, *, interval=WATCH_INTERVAL):
        self.work = work
        self.interval = interval
        self.error = None
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name='woowbackup-ha-watchdog', daemon=True)
            self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None

    def _loop(self):
        while not self._stop.wait(self.interval):
            try:
                self.poll()
            except Exception:  # noqa: BLE001 - a broken look never stops the job; details go to the journal
                traceback.print_exc(file=sys.stderr)

    def poll(self):
        if self.error is not None:
            return
        guard = self.work.guard
        free = guard.free()
        if free is not None and free < guard.floor:
            from .flows import human
            self.error = BackupError('insufficient-space', f'空間不足：可用空間降到 {human(free, down=True)}，低於執行中的應用需要保留的 '
                                                           f'{human(guard.floor, up=True)}，已停止轉換並清除暫用資料。這台的應用沒有任何變更。',
                                     required=guard.floor, free=free)
            for tmp in list(self.work._temps.values()):
                tmp.kill_all()
            return
        reporter = self.work.ctx.reporter
        if getattr(reporter, 'cancellable', False) and reporter.cancel_requested():
            from .flows import Cancelled
            self.error = Cancelled()

    def abort(self):
        """The exception the job must stop with now, or None."""
        return self.error


# ====================================================================== the job's working set

class Work:
    """What the app modules (haapps.IMPORTERS) use: the open HA backup and its key, staging, a space guard and, per
    app, its adapter (live reads as the owner), runner and throwaway objects (registered in the job record as
    `temp_owners` before the first one exists, so a killed job's objects are swept by the recovery)."""

    def __init__(self, ctx, record, key, staging, *, phases=None):
        self.ctx = ctx
        self.job_id = ctx.job_id
        self.phases = phases          # (all phase ids, the ids each app goes through, {id: label}) or None
        self._app = None              # (index, count, label) of the app being worked on
        self._percent = 0
        self.record = record
        self.keys = hasecuretar.Keys(key) if key is not None else None
        self.staging = Path(staging)
        self.ha = None
        self._adapters = {}
        self._temps = {}
        self._addons = {}
        from .flows import running_reserve
        self.floor = running_reserve(ctx) + WATCH_MARGIN
        self.guard = SpaceGuard([self.staging], self.floor)
        self.watchdog = Watchdog(self)

    # ---------------------------------------------------------- job record
    def log(self, text):
        self.ctx.log(text)

    def checkpoint(self):
        self.ctx.checkpoint()
        error = self.watchdog.abort()
        if error is not None:
            raise error

    def abort(self):
        """The runner's abort hook for long commands (the watchdog's verdict)."""
        return self.watchdog.abort()

    def watch(self, apps):
        """Watch the owners' Podman storage from the start (not only once the first container exists) and start the
        watchdog."""
        for app in apps:
            try:
                folders = self.storage_folders(app)
            except BackupError:
                continue  # the app's own check reports it (owner missing, not deployed)
            for folder in folders:
                if folder not in self.guard.folders:
                    self.guard.folders.append(folder)
        self.watchdog.start()

    def storage_folders(self, app):
        home = self.runner(app).home
        storage = os.path.join(home, '.local/share/containers/storage')
        return [home] + ([storage] if os.path.isdir(storage) else [])

    def begin_app(self, index, count, label):
        self._app = (index, count, label)

    def end_apps(self):
        self._app = None

    def phase(self, phase_id):
        """The job's phase, with an overall progress that never goes back while the apps go through the same phases
        one after the other (review UI-2) and the app's name in the progress message."""
        if self.phases is None:
            self.ctx.phase(phase_id)
            return
        ids, per_app, labels = self.phases
        total = len(ids)
        message = None
        if self._app is not None and phase_id in per_app:
            index, count, label = self._app
            first = ids.index(per_app[0])
            step = len(per_app) * index + per_app.index(phase_id)
            percent = int(100 * (first + step / count) / total)
            message = f'{label}：{labels[phase_id]}' + (f'（{index + 1}/{count}）' if count > 1 else '')
        else:
            percent = int(100 * ids.index(phase_id) / total)
        self._percent = max(self._percent, min(99, percent))
        self.ctx.phase(phase_id, percent=self._percent, message=message)

    # ---------------------------------------------------------- the HA backup
    def open(self, member):
        return self.ha.open_member(member.name, self.keys)

    def addon_member(self, suffix):
        found = [m for m in self.ha.layout.members if m.role == 'addon' and hastore.addon_suffix(m.slug) == suffix]
        if not found:
            raise BackupError('not-found', '這份 HA 備份沒有這個附加元件。', slug=suffix)
        if len(found) > 1:
            raise BackupError('incompatible', '這份 HA 備份有兩個相同的附加元件（來自不同的附加元件商店），無法分辨要搬哪一個。',
                              slug=suffix)
        return found[0]

    def share_member(self):
        return next((m for m in self.ha.layout.members if m.role == 'folder' and m.slug == 'share'), None)

    def addon_info(self, suffix):
        """AddonInfo of the add-on's addon.json (its first entry; cached). The add-on is identified by `system.slug`."""
        if suffix not in self._addons:
            member = self.addon_member(suffix)
            with self.open(member) as stream:
                info = habackup.read_addon_info(stream)
            if info is None or info.slug != suffix:
                raise BackupError('incompatible', '這個附加元件不是 WOOWTECH 的版本（addon.json 不符），無法匯入。',
                                  slug=suffix)
            self._addons[suffix] = info
        return self._addons[suffix]

    # ---------------------------------------------------------- the target
    def adapter(self, app):
        if app.id not in self._adapters:
            self._adapters[app.id] = self.ctx.adapter(app, phases=False)
        return self._adapters[app.id]

    def runner(self, app):
        return self.adapter(app).runner

    def quadlets(self, app):
        return self.adapter(app).read_quadlets()

    def temp(self, app):
        owner = app.owner
        if owner not in self._temps:
            owners = sorted(set(self._temps) | {owner})
            self.ctx.reporter.set_partial(temp_owners=owners)
            self._temps[owner] = tempctr.TempObjects(self.runner(app), self.job_id, log=self.log,
                                                     abort=self.watchdog.abort)
            for folder in self.storage_folders(app):
                if folder not in self.guard.folders:
                    self.guard.folders.append(folder)
        return self._temps[owner]

    def close(self):
        """Remove every throwaway object; the record forgets the owners once nothing is left."""
        self.watchdog.stop()
        left = []
        for tmp in self._temps.values():
            left += tmp.cleanup()
        if self._temps and not left:
            with contextlib.suppress(Exception):
                self.ctx.reporter.set_partial(temp_owners=[])
        if self.ha is not None:
            self.ha.close()
            self.ha = None
        return left


def _phases(job_type, per_app):
    from .jobs import HA_PHASES
    return [pid for pid, _label in HA_PHASES[job_type]], list(per_app), dict(HA_PHASES[job_type])


CHECK_PHASES = _phases('verify', ('decrypt', 'check'))
CONVERT_PHASES = _phases('backup', ('decrypt', 'convert'))


def job_key(ctx):
    """The HA key text of this job: from run-job (`ctx.ha_key`, already masked) or read from the key file."""
    key = getattr(ctx, 'ha_key', None)
    if key is not None:
        return key
    path = getattr(ctx, 'key_file', None)
    if path is None or not os.path.lexists(path):
        return None
    return read_key_file(path)


def read_key_file(path):
    """Raw UTF-8 text of a job key file written for an HA key (O_NOFOLLOW, <= 4096 bytes); masked from now on."""
    from . import jobs
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        data = os.read(fd, MAX_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if not data or len(data) > MAX_KEY_BYTES:
        raise BackupError('invalid-request', hasecuretar.BAD_KEY_MESSAGE, field='key')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise BackupError('invalid-request', hasecuretar.BAD_KEY_MESSAGE, field='key') from None
    jobs.mask_secret(text)
    return text


def _catalog_app(ctx, app_id):
    catalog = ctx.catalog()
    return catalog.get(app_id)


def _app_label(app_id, app=None):
    return getattr(app, 'name', None) or haapps.get(app_id).name


def _base_result(app_id, member, addon):
    return {'app_id': app_id, 'slug': member.slug if member else APPS[app_id], 'name': '',
            'arch': addon.arch if addon else 'unknown', 'version': addon.version if addon else '',
            'target_version': '', 'ok': False, 'blockers': [], 'warnings': []}


def _arch_blocker(addon):
    if addon.arch in ('amd64', 'aarch64'):
        return None
    return '無法判斷這份 HA 備份來自哪一種處理器（只支援 x86 和 ARM 的 64 位元設備），所以無法匯入。'


def _deployed_blockers(work, app):
    """The app must be deployed here (its images, Quadlet files and secrets are read live)."""
    adapter = work.adapter(app)
    info = adapter.probe()
    if not info.get('deployed'):
        return [f'這台的「{app.name}」還沒有部署完成，請先到「應用軟體」安裝並啟動它。']
    if info.get('problems'):
        return [f'這台的「{app.name}」狀態異常：{info["problems"][0]}']
    return []


def _open(work, ctx, params):
    store = hastore.HaStore(ctx.paths)
    record = store.get(params['ha_backup_id'])
    work.ha = habackup.open_backup(store.file_path(record['id']))
    if work.ha.layout.size != record['size']:
        raise BackupError('corrupt-archive', hasecuretar.CORRUPT_MESSAGE, reason='the stored HA file changed')
    return record


def _members(work, app_ids):
    members = {}
    for app_id in app_ids:
        if app_id not in APPS:
            raise BackupError('invalid-request', '這個應用不能從 HA 備份匯入。', app=app_id)
        members[app_id] = work.addon_member(APPS[app_id])
    return members


def _require_key(work, members):
    """key-required when a selected member is encrypted and no key came; wrong-key (before any plaintext) when the
    key does not open it."""
    encrypted = [m for m in members.values() if m.encrypted]
    if encrypted and work.keys is None:
        raise hasecuretar.key_required(member=encrypted[0].name)
    for member in encrypted:
        with work.open(member):
            pass  # the decrypting reader checks the key when it opens


def _check_space(work, members):
    """Up front: three times the add-ons' members (a first, low estimate; the app steps check again with the sizes
    they measured while streaming, and the watchdog looks every few seconds)."""
    need = 3 * sum(m.size for m in members.values())
    work.guard.check(need)


def _watched_apps(ctx, app_ids):
    return [app for app in (_catalog_app(ctx, app_id) for app_id in app_ids) if app is not None]


# ====================================================================== check

def run_ha_check(ctx, params):
    """`verify` job with source ha: {ha_check: {ha_backup_id, apps[AppCheck]}} (CONTRACT section 7). An app that
    cannot move is a blocker of its own result, never a failed job (an add-on missing twice or not WOOWTECH's, an
    owner that is gone, an app not deployed; review C-09); a wrong or missing key fails the job."""
    ctx.cancellable(True)
    ctx.phase('prepare')
    app_ids = list(params.get('apps') or [])
    ctx.storage.ensure_layout()
    staging = Path(ctx.storage.staging_dir(ctx.job_id))
    key = job_key(ctx)
    work = Work(ctx, None, key, staging, phases=CHECK_PHASES)
    results = []
    try:
        work.record = _open(work, ctx, params)
        members, problems = _members_or_problems(work, app_ids)
        _require_key(work, members)
        ctx.log(f'檢查 HA 備份「{work.record["name"]}」：{"、".join(app_ids)}')
        work.watch(_watched_apps(ctx, app_ids))
        for index, app_id in enumerate(app_ids):
            member = members.get(app_id)
            app = _catalog_app(ctx, app_id)
            result = _base_result(app_id, member, None)
            result['name'] = _record_addon_name(work.record, member)
            results.append(result)
            work.begin_app(index, len(app_ids), result['name'] or _app_label(app_id, app))
            work.phase('decrypt')
            try:
                if app_id in problems:
                    raise problems[app_id]
                addon = work.addon_info(APPS[app_id])
                result.update(arch=addon.arch, version=addon.version, name=addon.name or result['name'])
                blocker = _arch_blocker(addon)
                if blocker:
                    result['blockers'].append(blocker)
                if app is None:
                    result['blockers'].append(INSTALL_HINT.format(name=_app_label(app_id)))
                elif not blocker:
                    result['blockers'] += _deployed_blockers(work, app)
                if result['blockers']:
                    ctx.log(f'「{result["name"] or app_id}」不能匯入：{result["blockers"][0]}')
                    continue
                work.guard.check(3 * member.size)
                module = haapps.get(app_id).load()
                found = module.check(work, app)
            except BackupError as error:
                if error.code not in FAILURE_CODES:
                    raise
                result['blockers'].append(error.message)
                ctx.log(f'「{result["name"] or app_id}」不能匯入：{error.message}')
                continue
            result['target_version'] = found.get('target_version') or ''
            result[app_id] = found[app_id]  # the app's own section (CONTRACT section 7 HaCheck)
            result['blockers'] += list(found.get('blockers') or [])
            result['warnings'] += list(found.get('warnings') or [])
            derived = getattr(module, 'check_blockers', None)
            if derived is not None:
                result['blockers'] += derived(found)
            result['ok'] = not result['blockers']
            ctx.log(f'「{result["name"] or app_id}」檢查完成：{"可以匯入" if result["ok"] else "不能匯入"}')
            work.checkpoint()
        work.end_apps()
        work.phase('check')
        return {'ha_check': {'ha_backup_id': work.record['id'], 'apps': results}}
    finally:
        work.close()
        _cleanup(ctx)


def _record_addon_name(record, member):
    if member is None:
        return ''
    return next((a['name'] for a in record['addons'] if a['slug'] == member.slug), '')


def _members_or_problems(work, app_ids):
    """({app id: member}, {app id: BackupError}) -- an add-on that is missing or there twice is that app's blocker."""
    members, problems = {}, {}
    for app_id in app_ids:
        if app_id not in APPS:
            raise BackupError('invalid-request', '這個應用不能從 HA 備份匯入。', app=app_id)
        try:
            members[app_id] = work.addon_member(APPS[app_id])
        except BackupError as error:
            if error.code not in FAILURE_CODES:
                raise
            problems[app_id] = error
    return members, problems


def _cleanup(ctx):
    try:
        ctx.storage.remove_staging(ctx.job_id)
    except Exception:  # noqa: BLE001 - never masks the job's outcome
        ctx.log('警告：無法完整清除暫存資料夾，請通知管理員檢查。')


# ====================================================================== convert

def note_for(record):
    """「由 HA 備份轉換：<HA name>（<HA date>）」 with the date as this device's local time."""
    try:
        when = util.parse_iso_utc(record['date']).astimezone().strftime('%Y-%m-%d %H:%M')
    except (ValueError, KeyError, OSError):
        when = str(record.get('date') or '')[:20]
    name = str(record.get('name') or '').strip() or '（沒有名稱）'
    return f'{NOTE_PREFIX}{name[:200]}（{when}）'


def mcp_lines(importer, catalog=None):
    """The MCP reminder lines the engine writes for an importer with `engine_mcp_lines` (haapps): log this device's MCP
    admin app in again when the catalog has it (its catalog name), and stop HA's MCP add-on of the product and
    re-create the MCP connectors (claude.ai and other clients) with this device's MCP address. The admin apps' state is
    never imported (facts mcp-admin.md, decision D1)."""
    if not importer.engine_mcp_lines:
        return []
    lines = []
    if importer.mcp_admin:
        entry = None
        if catalog is not None:
            with contextlib.suppress(Exception):  # an unreadable catalog only drops this line
                entry = catalog.get(importer.mcp_admin)
        if entry is not None:
            name = str(getattr(entry, 'name', '') or '').strip() or importer.mcp_admin
            lines.append(f'請到「{name}」確認或重新設定 {importer.name} 的連線資料（MCP 管理工具的設定不會從 HA 搬過來）。')
    if importer.mcp_addon:
        lines.append(f'如果 HA 上有「{importer.mcp_addon}」，請把它停掉，並把指向它的 MCP 連接器（例如 claude.ai）刪掉，'
                     '改用這台的 MCP 網址重新建立。')
    return lines


def import_texts(converted, catalog=None):
    """(notes, reminders, reminders_by_app) of a conversion (review UI-3, P-05), in the registry's order. `notes`: ONE
    list describing the whole converted backup, what the import moves or changes (shown before the restore; each line
    names its app); `reminders`: what to do afterwards that belongs to no app (none so far: the page writes the lines
    about stopping the HA add-on, the Odoo/n8n MCP admin apps, a test import and deleting the HA file);
    `reminders_by_app`: per app (each module's `import_texts`, then the MCP lines of `mcp_lines`)."""
    notes, reminders_by_app = [], {}
    for importer in haapps.IMPORTERS:
        if importer.app_id not in converted:
            continue
        app_notes, reminders = importer.load().import_texts(converted[importer.app_id])
        notes += list(app_notes)
        reminders = list(reminders) + mcp_lines(importer, catalog)
        if reminders:
            reminders_by_app[importer.app_id] = reminders
    return notes, [], reminders_by_app


def run_ha_convert(ctx, params):
    """`backup` job with source ha: {backup_id, size, apps, encrypted, ha_import} (CONTRACT section 7)."""
    return _run_ha_convert(ctx, params)


def _run_omnigent_candidate(ctx, params, *, schema_ddl_quiesced):
    """Internal Python entry only; never selected by request fields or public routing.

    Caller holds target-wide DDL quiescence through conversion (including migrations,
    extension/type/function/constraint changes and other sessions). Snapshot locks
    alone do not establish this. Installation is a separate restore job/context.
    """
    from . import ha_omnigent
    if list(params.get('apps') or []) != ['omnigent'] or schema_ddl_quiesced is not True:
        raise BackupError('incompatible', '內部候選僅限 Omnigent，且須保證目標結構變更已暫停。')

    def convert(work, app, test_mode, out_dir):
        ha_omnigent.require_registered_secrets(work, app)
        return ha_omnigent._convert_candidate(work, app, test_mode, out_dir,
                                              schema_ddl_quiesced=True)

    return _run_ha_convert(ctx, params, omnigent_candidate=convert)


def _install_omnigent_candidate(ctx, backup_id):
    """Install a locally registered candidate via the ordinary safety/rollback flow."""
    from . import flows
    row = (load_registry(ctx.paths) or {}).get(backup_id)
    if not row or row.get('apps') != ['omnigent']:
        raise BackupError('incompatible', '找不到內部 Omnigent 候選的轉換紀錄。')
    return flows.run_restore(ctx, {'backup_id': backup_id, 'apps': ['omnigent']})


def _run_ha_convert(ctx, params, *, omnigent_candidate=None):
    from . import ha_odoo
    from .flows import _package, resolve_apps
    ctx.cancellable(True)
    ctx.phase('prepare')
    app_ids = list(params.get('apps') or [])
    database = params.get('odoo_database')
    test_mode = params.get('test_mode') is True
    apps = resolve_apps(ctx.catalog(), app_ids)
    encrypt = params.get('encrypt', ctx.encrypt_by_default()) is not False
    device_key = ctx.keys.device_key() if encrypt else None
    if encrypt and device_key is None:
        raise BackupError('no-device-key', '這台設備尚未建立加密金鑰，請先完成金鑰設定。')
    if 'odoo' in app_ids and not (isinstance(database, str) and ha_odoo.DB_NAME_RE.fullmatch(database)):
        raise BackupError('invalid-request', '請選擇要匯入的 Odoo 資料庫。', field='odoo_database')
    ctx.storage.ensure_layout()
    staging = Path(ctx.storage.staging_dir(ctx.job_id))
    key = job_key(ctx)
    work = Work(ctx, None, key, staging, phases=CONVERT_PHASES)
    backup_id = None
    registered = False
    try:
        work.record = _open(work, ctx, params)
        members = _members(work, app_ids)
        _require_key(work, members)
        record = work.record
        ctx.log(f'轉換 HA 備份「{record["name"]}」：{"、".join(app_ids)}'
                + (f'（Odoo 資料庫 {database}）' if database else '') + ('，測試匯入' if test_mode else ''))
        if not encrypt:
            ctx.log('這份備份不加密：應用機密（資料庫密碼、API 金鑰、存取權杖）會以明文存放在備份檔中')
        for app in apps:
            addon = work.addon_info(APPS[app.id])
            blocker = _arch_blocker(addon) or next(iter(_deployed_blockers(work, app)), None)
            if blocker:
                raise BackupError('incompatible', blocker, app=app.id)
        work.watch(apps)
        _check_space(work, members)
        converted, manifest_apps, entries = {}, [], []
        addons = []
        for index, app in enumerate(apps):
            member = members[app.id]
            addon = work.addon_info(APPS[app.id])
            name = addon.name or _record_addon_name(record, member)
            work.begin_app(index, len(apps), app.name or name)
            work.phase('decrypt')
            addons.append({'app_id': app.id, 'slug': member.slug, 'name': name})
            out_dir = staging / 'apps' / app.id
            out_dir.mkdir(mode=0o700, parents=True)
            importer = haapps.get(app.id)
            values = {'odoo_database': database, 'test_mode': test_mode}
            converter = omnigent_candidate if app.id == 'omnigent' and omnigent_candidate else importer.load().convert
            data = converter(work, app, *[values[name] for name in importer.convert_args], out_dir)
            converted[app.id] = data
            item_args = {key: data[key] for key in ITEM_KEYS if key in data}
            work.checkpoint()
            app_manifest, app_entries = work.adapter(app).import_manifest(out_dir, **item_args)
            if data.get(CHECK_KEY) is not None:
                from .archive import validate_import_check
                validate_import_check(data[CHECK_KEY], app.id)
                app_manifest[CHECK_KEY] = data[CHECK_KEY]
            manifest_apps.append(app_manifest)
            entries.extend(app_entries)
        work.end_apps()
        work.close()  # no throwaway object is needed for the packaging
        plain = sum(int(entry.size) for entry in entries)
        work.guard.check(plain + plain // 100)  # the archive (at most the data plus 1 % for tar and age; review C-01)
        notes, reminders, reminders_by_app = import_texts(converted, _catalog_or_none(ctx))
        row = clean_row({'ha_backup_id': record['id'], 'name': record['name'], 'date': record['date'],
                         'apps': app_ids, 'odoo_database': database if 'odoo' in app_ids else None,
                         'test_mode': test_mode,
                         'workflows_to_fix': converted.get('n8n', {}).get('workflows_to_fix') or [],
                         'reminders': reminders, 'reminders_by_app': reminders_by_app, 'notes': notes,
                         'addons': addons, 'job_id': ctx.job_id,
                         'created': util.iso_utc()})
        backup_id = ctx.storage.new_backup_id()
        try:
            register(ctx.paths, backup_id, row)
            registered = True
        except Exception as error:  # noqa: BLE001 - the backup is still made; the list just shows no origin
            ctx.log(f'警告：無法記錄這份備份來自 HA（{getattr(error, "message", None) or type(error).__name__}）')
        result = _package(ctx, apps, staging, include_images=False, note=note_for(record), backup_type='manual',
                          key=device_key, phases=True, manifest_apps=manifest_apps, entries=entries, downtime=0,
                          backup_id=backup_id)
        return {'backup_id': result['backup_id'], 'size': result['size'], 'apps': result['apps'],
                'encrypted': result['encrypted'], 'ha_import': view_row(row)}
    finally:
        # The row goes only with a backup that was not made: once the backup is in the index (also when something
        # failed after its registration: a log line, a termination), it keeps its origin (review C-10).
        if registered and backup_id is not None and not _listed(ctx, backup_id):
            with contextlib.suppress(Exception):
                forget(ctx.paths, backup_id)
        work.close()
        _cleanup(ctx)


def import_check_problem(app, check):
    """The preflight's word on an app section's `import_check`: None when this engine can verify it for `app`."""
    kind = check.get('kind') if isinstance(check, dict) else None
    if IMPORT_CHECKS.get(kind) != app.id:
        return f'這份備份帶有這版備份元件不認得的「{app.name}」匯入核對資料，無法還原；請更新備份元件。'
    return None


def verify_import(app, adapter, check, *, log):
    """After the restore started `app` (its health checks passed): the importer compares the restored app with the
    conversion's readback. Raises BackupError on any difference: the restore then rolls back by itself."""
    problem = import_check_problem(app, check)
    if problem:
        raise BackupError('incompatible', problem, app=app.id)
    haapps.get(app.id).load().verify_restored(adapter, app, check, log=log)


def _catalog_or_none(ctx):
    try:
        return ctx.catalog()
    except Exception:  # noqa: BLE001 - the texts only lose the MCP admin app's line
        return None


def _listed(ctx, backup_id):
    try:
        ctx.storage.get(backup_id)
        return True
    except BackupError as error:
        return error.code != 'not-found'  # an index that cannot be read: keep the row (a day later it is pruned)
    except Exception:  # noqa: BLE001 - same
        return True


# ====================================================================== ha-imports.json

def registry_path(paths):
    return Path(paths.data) / REGISTRY


@contextlib.contextmanager
def _index_lock(paths):
    run = util.ensure_dir(paths.run, 0o700)
    fd = os.open(Path(run) / 'index.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _text(value, max_len):
    return isinstance(value, str) and len(value) <= max_len and not re.search(r'[\x00-\x1f\x7f]', value)


def _clean(value, max_len):
    """Text as a row keeps it: control characters as spaces, at most `max_len` characters (review C-03)."""
    text = value if isinstance(value, str) else '' if value is None else str(value)
    text = text.encode('utf-8', 'replace').decode('utf-8')
    return re.sub(r'[\x00-\x1f\x7f]', ' ', text)[:max_len]


def _lines(values):
    return [_clean(line, 500) for line in (values if isinstance(values, list) else [])][:MAX_LINES]


def clean_row(row):
    """The row as the registry keeps it: every text cleaned and cut, every list cut, so a row made from whatever a
    conversion found (long module or workflow names, names with line breaks...) is always accepted (review C-03)."""
    fix = []
    for item in (row.get('workflows_to_fix') or [])[:200]:
        if isinstance(item, dict):
            fix.append({'name': _clean(item.get('name'), 200), 'active': item.get('active') is True,
                        'reasons': [_clean(r, 300) for r in (item.get('reasons') or [])][:10]})
    addons = []
    for item in (row.get('addons') or [])[:len(APPS)]:
        if isinstance(item, dict) and item.get('app_id') in APPS:
            addons.append({'app_id': item['app_id'], 'slug': _clean(item.get('slug'), 100),
                           'name': _clean(item.get('name'), 200)})
    database = row.get('odoo_database')
    cleaned = dict(row, name=_clean(row.get('name'), 200),
                   odoo_database=_clean(database, 63) if database is not None else None,
                   workflows_to_fix=fix, addons=addons, reminders=_lines(row.get('reminders')),
                   notes=_lines(row.get('notes')))
    cleaned['reminders_by_app'] = {app_id: _lines(lines) for app_id, lines in (row.get('reminders_by_app') or {}).items()
                                   if app_id in APPS}
    return cleaned


def _upgrade(row):
    """A row of an earlier version of this file, with the keys added since (empty)."""
    if isinstance(row, dict):
        row = dict(row)
        for key, kind in ROW_EXTRA.items():
            row.setdefault(key, kind())
    return row


def _valid_lines(lines):
    return isinstance(lines, list) and len(lines) <= MAX_LINES and all(_text(line, 500) for line in lines)


def valid_row(row):
    if not isinstance(row, dict) or set(row) != set(ROW_KEYS) | set(ROW_EXTRA):
        return False
    value = row['reminders_by_app']
    if not isinstance(value, dict) or not all(app in APPS and _valid_lines(lines) for app, lines in value.items()):
        return False
    if not _valid_lines(row['notes']):
        return False
    if not hastore.valid_id(row['ha_backup_id']) or not _text(row['name'], 200) or not util.is_iso_utc(row['date']):
        return False
    apps = row['apps']
    if not isinstance(apps, list) or not 1 <= len(apps) <= len(APPS) or not all(a in APPS for a in apps) \
            or len(set(apps)) != len(apps):
        return False
    if row['odoo_database'] is not None and not (_text(row['odoo_database'], 63) and row['odoo_database']):
        return False
    if not isinstance(row['test_mode'], bool):
        return False
    fix = row['workflows_to_fix']
    if not isinstance(fix, list) or len(fix) > 200:
        return False
    for item in fix:
        if (not isinstance(item, dict) or set(item) != {'name', 'active', 'reasons'} or not _text(item['name'], 200)
                or not isinstance(item['active'], bool) or not isinstance(item['reasons'], list)
                or len(item['reasons']) > 10 or not all(_text(r, 300) for r in item['reasons'])):
            return False
    if not isinstance(row['reminders'], list) or len(row['reminders']) > 20 or \
            not all(_text(r, 500) for r in row['reminders']):
        return False
    addons = row['addons']
    if not isinstance(addons, list) or len(addons) > len(APPS):
        return False
    for item in addons:
        if (not isinstance(item, dict) or set(item) != {'app_id', 'slug', 'name'} or item['app_id'] not in APPS
                or not _text(item['slug'], 100) or not _text(item['name'], 200)):
            return False
    return (isinstance(row['job_id'], str) and re.fullmatch(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', row['job_id'])
            is not None and util.is_iso_utc(row['created']))


def load_registry(paths):
    """{backup id: row} of ha-imports.json; None when the file exists but cannot be read (it is then never
    replaced, like an unreadable sidecar), {} when there is none."""
    try:
        doc = util.load_json_file(registry_path(paths), max_bytes=8 * 1024 * 1024)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get('schema') != REGISTRY_SCHEMA or not isinstance(doc.get('imports'), dict):
        return None
    from .storage import valid_backup_id
    rows = {bid: _upgrade(row) for bid, row in doc['imports'].items()}
    return {bid: row for bid, row in rows.items() if valid_backup_id(bid) and valid_row(row)}


def _save_registry(paths, rows):
    util.atomic_write_json(registry_path(paths), {'schema': REGISTRY_SCHEMA, 'imports': rows}, 0o600)


def _prune(paths, rows, now):
    """Rows whose backup does not exist (deleted, retention, a failed job) and that are older than a day."""
    from .storage import Storage
    storage = Storage(paths)
    kept = {}
    for bid, row in rows.items():
        try:
            created = util.parse_iso_utc(row['created']).timestamp()
        except ValueError:
            created = 0
        if now - created < STALE_ROW_SECONDS or os.path.lexists(storage.archive_path(bid)):
            kept[bid] = row
    return kept


def register(paths, backup_id, row, *, now=None):
    row = clean_row(_upgrade(row))
    if not valid_row(row):
        raise BackupError('internal-error', 'HA 匯入紀錄的格式不正確。')
    with _index_lock(paths):
        rows = load_registry(paths)
        if rows is None:
            raise BackupError('internal-error', 'HA 匯入紀錄檔無法讀取，已保留原檔。')
        rows = _prune(paths, rows, time.time() if now is None else now)
        rows[backup_id] = row
        if len(rows) > REGISTRY_MAX:
            for bid in sorted(rows, key=lambda b: rows[b]['created'])[:len(rows) - REGISTRY_MAX]:
                if bid != backup_id:
                    rows.pop(bid)
        _save_registry(paths, rows)


def forget(paths, backup_id):
    """Drop the row of a deleted backup (no file or no row: nothing to do)."""
    with _index_lock(paths):
        rows = load_registry(paths)
        if not rows or backup_id not in rows:
            return False
        rows.pop(backup_id)
        _save_registry(paths, rows)
        return True


def view_row(row):
    """BackupMeta.from_ha / result.ha_import (CONTRACT section 7)."""
    row = _upgrade(row)
    return {key: row[key] for key in VIEW_KEYS}


def from_ha_views(paths):
    """{backup id: from_ha} for `list` ({} when the registry cannot be read)."""
    rows = load_registry(paths) or {}
    return {bid: view_row(row) for bid, row in rows.items()}


# ====================================================================== throwaway objects of finished jobs

def _importable_owners(paths):
    from .catalog import load_catalog
    try:
        catalog = load_catalog(paths)
    except Exception:  # noqa: BLE001 - nothing to sweep without a catalog
        return []
    return sorted({app.owner for app_id, app in catalog.items() if app_id in APPS})


def sweep_job(job_id, owners, *, log=None):
    """Remove every throwaway object of the (dead) job `job_id` for these owners; returns zh-TW problems (an object
    that could not be removed is one: the record keeps the owners for the next pass; review C-07)."""
    from .podman import OwnerRunner
    problems = []
    for owner in owners:
        try:
            _removed, left = tempctr.sweep(OwnerRunner(owner), lambda _job: False, log=log, only_job=job_id)
        except BackupError as error:
            if error.code == 'owner-missing':
                continue
            problems.append(f'{owner}：{error.message}')
            continue
        if left:
            problems.append(f'{owner}：{len(left)} 個暫用容器或資料卷無法移除（{"、".join(left[:3])}）')
    return problems


def sweep_finished(paths, *, log=None, current=None):
    """At the start of an HA job (review C-08: no other job pays for it): remove the throwaway objects of every job
    that is not queued/running, for the importable apps' owners and the owners a job record still lists. Never fails
    the job."""
    from . import jobs
    from .podman import OwnerRunner
    store = jobs.JobStore(paths)

    def alive(job_id):
        if job_id == current:
            return True
        try:
            return store.get(job_id).get('state') in jobs.ACTIVE
        except BackupError:
            return False

    owners = set(_importable_owners(paths))
    with contextlib.suppress(Exception):
        for record in store.list():
            owners.update(o for o in record.get('temp_owners') or [] if isinstance(o, str))
    for owner in sorted(owners):
        with contextlib.suppress(Exception):
            tempctr.sweep(OwnerRunner(owner), alive, log=log)


def interrupted_message(job_type):
    if job_type == 'verify':
        return '檢查 HA 備份的作業意外中斷（例如系統重新開機或程序被終止）。這台的應用沒有任何變更，請重新檢查。'
    return '轉換 HA 備份的作業意外中斷（例如系統重新開機或程序被終止）。這台的應用沒有任何變更，請重新開始匯入。'
