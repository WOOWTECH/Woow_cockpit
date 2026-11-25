"""Home Assistant import jobs: check and convert (CONTRACT sections 7, 8 and 9 "Home Assistant import"; branch
feat/ha-import, part B). Owner: E2.

* `run_ha_check(ctx, params)` -- job type `verify` with `params.source == 'ha'` (phases 準備, 解開 HA 備份, 檢查內容與版本):
  decrypts only the selected add-ons' members, rebuilds what it must read in throwaway containers (tempctr.py), compares
  with this device's apps and returns `{ha_check}` (schema 2: per app its issues, haissues.py). Nothing of the apps
  changes; they keep running. Every app is on its own: whatever goes wrong with one becomes a `stop` of that app and the
  others are checked (`haissues.app_failure`); only a cancel, a termination, a disk that runs full and a key that opens
  nothing end the job, which then still reports what it had found (`error.result`).
* `run_ha_convert(ctx, params)` -- job type `backup` with `params.source == 'ha'` (phases 準備, 解開 HA 備份, 轉換資料,
  封裝備份, 驗證備份): rebuilds the selected apps' data in their own format (the importer modules of haapps.py:
  ha_odoo.py, ha_n8n.py, ...) and writes a normal
  format 2 backup of them -- the data items converted, everything else (secrets, config files, Quadlet files, images list,
  the installed settings) read live as the owner without stopping anything, exactly like a backup reads it -- of type
  `manual` with the note 「由 HA 備份轉換：<HA name>（<HA date>）」, encrypted with the device key when 預設加密備份 is on,
  verified and registered like any backup; the row in `ha-imports.json` tells `list` where it came from (`from_ha`).
  Importing it is the existing restore (pre-restore backup, rollback). No retention runs in this job. A conversion of
  ONE app always reports `result.results[0]` (status converted, skipped or failed, with its issues), also when it fails
  (HAOS parity: an import of several apps is a chain of such jobs); one of several apps (the labs) fails as a whole.

The HA key the page sent is in the job's key file (raw UTF-8, written by jobs.start_job with key_kind 'ha'); run-job
masks it in every log line before the job starts and hands it over as `ctx.ha_key`. It is never written anywhere else.

`ha-imports.json` (`<data>/ha-imports.json`, root 0600, strict; written under the index lock): `{schema: 2, imports:
{<backup id>: ImportRow}}`, ImportRow = `{ha_backup_id, name, date, apps, odoo_database, test_mode, workflows_to_fix,
reminders, reminders_by_app, notes, addons, job_id, created, group, results, confirmed, left_databases, kept}` (what a
row written before a key existed does not have reads as empty; a schema 1 file is read and becomes schema 2 with the
next write: an older engine drops rows with keys it does not know, so it must not take the file for one of its own).
Every text is cleaned and cut when the row is written, so whatever a
conversion found is accepted (review C-03). A row is written before the backup is packaged (its id is chosen first)
and dropped when the job fails before the backup is in the index, when the backup is deleted, or later when its
backup no longer exists. Deleting the HA file never touches it: a converted backup keeps its origin.
"""
import contextlib
import fcntl
import json
import os
import re
import shutil
import sys
import threading
import time
import traceback
from pathlib import Path

from . import haapps, habackup, haissues, hasecuretar, hastore, hatarget, tempctr, util
from .errors import BackupError
from .haissues import Issue

# catalog id -> add-on slug (after the repository prefix), from the one registry of importers (haapps.IMPORTERS)
APPS = {importer.app_id: importer.slug for importer in haapps.IMPORTERS}
ITEM_KEYS = ('volumes', 'postgres', 'dirs', 'secrets')  # what a module's convert hands to adapter.import_manifest
# A module's readback for the restore (CONTRACT section 5 `import_check`, section 9): {kind: app id}. The converted
# backup's app section carries it; the restore compares it after the units started (verify_import) and rolls back
# on a difference; another kind or app refuses the restore in its preflight (import_check_problem).
CHECK_KEY = 'import_check'
IMPORT_CHECKS = {'emqx-readback': 'emqx'}
CHECK_SCHEMA = 2              # ha_check.schema: issues per app (older pages read ok/blockers/warnings)
CHECK_BYTES = 900 * 1024      # of the 1 MiB a job record takes (jobs.MAX_RECORD_BYTES); a larger one is never read again
REGISTRY = 'ha-imports.json'
REGISTRY_SCHEMA = 2           # what is written
REGISTRY_READS = (1, 2)       # what is understood (a row of an earlier schema gets the empty values)
REGISTRY_MAX = 1000
REGISTRY_MAX_BYTES = 8 * 1024 * 1024  # what load_registry reads; a write stays below it (oldest rows go first)
ROW_KEYS = ('ha_backup_id', 'name', 'date', 'apps', 'odoo_database', 'test_mode', 'workflows_to_fix', 'reminders',
            'addons', 'job_id', 'created')
# Keys added after the first rows were written (a row without them gets the empty value; review UI-3, P-05; HAOS parity:
# group ... kept).
ROW_EXTRA = {'reminders_by_app': dict, 'notes': list, 'group': lambda: None, 'results': list, 'confirmed': list,
             'left_databases': list, 'kept': lambda: None}
VIEW_KEYS = ('ha_backup_id', 'name', 'date', 'apps', 'odoo_database', 'test_mode', 'workflows_to_fix', 'reminders',
             'reminders_by_app', 'notes', 'addons', 'group', 'results', 'left_databases', 'kept')
GROUP_RE = re.compile(r'g[0-9a-f]{16}\Z')
# GroupResult (CONTRACT section 7): one app of an import's chain.
RESULT_KEYS = ('app_id', 'status', 'convert_job_id', 'restore_job_id', 'backup_id', 'safety_backup_id', 'code',
               'message')
RESULT_STATUS = ('imported', 'converted', 'rolled-back', 'failed', 'skipped', 'not-started')
MAX_LINES = 20
MAX_RESULTS = 10
MAX_CONFIRMED = 40
MAX_CONFIRMED_TEXT = 8000     # characters of all confirmed names of a row
MAX_LEFT_DATABASES = 100
MAX_DATABASE_BYTES = 63       # PostgreSQL's NAMEDATALEN - 1
STALE_ROW_SECONDS = 24 * 3600
MAX_KEY_BYTES = 4096
GUARD_STEP = 64 * 1024 * 1024
# Free space the watchdog keeps on top of the running reserve: what containers may write between two of its looks.
WATCH_MARGIN = 512 * 1024 * 1024
WATCH_INTERVAL = 2.0
NOTE_PREFIX = '由 HA 備份轉換：'
# This device has no settings for the app: the page 「應用軟體」 only lists software, it installs nothing (DESIGN H-b 16).
NOT_INSTALLED = '這台還沒有「{name}」的應用設定。'
INSTALL_ACTION = '請先用它的安裝套件在這台安裝並啟動 {name}，再到「應用設定」加入它，然後重新檢查。'
INSTALL_HINT = NOT_INSTALLED + INSTALL_ACTION
SETTINGS_ACTION = '請到「應用設定」修正或重新加入 {name} 的設定，再重新檢查。'  # it has settings that cannot be used
DEPLOY_ACTION = '請先用它的安裝套件完成安裝並啟動它，再重新檢查。'
ADDON_MISSING = '這份 HA 備份沒有這個附加元件。'
ADDON_MISSING_ACTION = '請在 HA 建立備份時勾選這個附加元件，再上傳新的備份檔。'
ADDON_TWICE = '這份 HA 備份有兩個相同的附加元件（來自不同的附加元件商店），請選擇要搬哪一個。'
ADDON_CHOICE_ACTION = '請選擇要搬的那一個附加元件，再重新檢查。'
ADDON_GONE = '選的附加元件不在這份 HA 備份裡，請重新選擇。'
ADDON_OTHER = '這個附加元件不是 WOOWTECH 的版本（addon.json 不符），無法匯入。'
ADDON_OTHER_ACTION = '請確認 HA 上裝的是 WOOWTECH 商店的附加元件，再重新備份；或不要匯入這個應用。'
PROBLEM_ACTION = '請先讓它恢復正常，再重新檢查。'
NOT_CHECKED = '檢查作業在檢查這個應用之前就停止了，這個應用還沒有結果。'
NOT_CHECKED_ACTION = '請先排除讓檢查停止的原因，再重新檢查。'
TOO_LARGE = '這個應用的檢查結果太大，作業紀錄放不下，無法匯入這個應用；這台的這個應用沒有任何變更。'
KEY_CREATED = '這台還沒有加密金鑰，匯入時會自動建立，用來加密匯入前備份和轉換出來的備份；完成後請到「加密金鑰」下載並保存。'
NO_KEY_CREATED = '無法自動建立這台的加密金鑰，匯入已停止，這台沒有任何變更。請到「加密金鑰」建立金鑰後，再重新匯入。'
UNEXPECTED_JOB = '作業發生未預期的內部錯誤，請查看系統日誌。'
CHOOSE_DATABASE = '請選擇要匯入的 Odoo 資料庫。'
NO_DATABASE = 'HA 的 Odoo 沒有可以搬的資料庫（原因見檢查結果）。請先在 HA 確認 Odoo 的資料庫，再重新檢查。'

ISSUES = {
    'ha.addon-missing': 'stop',      # HA-03, X-CLI-03
    'ha.addon-choice': 'stop',       # HA-04: until the customer chose one
    'ha.addon-other': 'stop',        # HA-05
    'ha.not-installed': 'stop',
    'ha.not-deployed': 'stop',
    'ha.app-problem': 'stop',
    'ha.not-checked': 'stop',        # the job ended before this app
    'shared.device-key': 'auto',     # HA-13 (D11)
}


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
            error = BackupError('insufficient-space', f'空間不足：轉換需要再保留 {human(self.floor + int(need), up=True)}，'
                                                      f'目前只剩 {human(free, down=True)}。這台的應用沒有任何變更。',
                                required=self.floor + int(need), free=free)
            # Below the floor already: nothing else may write either. Otherwise it is one app's own estimate.
            raise haissues.job_wide(error) if free < self.floor else error

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
            self.error = haissues.job_wide(BackupError(
                'insufficient-space', f'空間不足：可用空間降到 {human(free, down=True)}，低於執行中的應用需要保留的 '
                                      f'{human(guard.floor, up=True)}，已停止轉換並清除暫用資料。這台的應用沒有任何變更。',
                required=guard.floor, free=free))
            for tmp in [*self.work._temps.values(), *getattr(self.work, '_stale', ())]:
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
    `temp_owners` before the first one exists, so a killed job's objects are swept by the recovery).

    `choices` ({app id: {'addon'|'database'|'node': value}}): what the customer chose. `acknowledged` ({app id: [key]}):
    the confirmed lines of a conversion; None = a check, which only collects (`sink`)."""

    def __init__(self, ctx, record, key, staging, *, phases=None, choices=None, acknowledged=None):
        self.ctx = ctx
        self.job_id = ctx.job_id
        self.phases = phases          # (all phase ids, the ids each app goes through, {id: label}) or None
        self._app = None              # (index, count, label) of the app being worked on
        self._percent = 0
        self.record = record
        self.keys = hasecuretar.Keys(key) if key is not None else None
        self.staging = Path(staging)
        self.ha = None
        self.choices = {app_id: dict(values) for app_id, values in (choices or {}).items()}
        self.acknowledged = None if acknowledged is None else dict(acknowledged)
        self.database = None          # the Odoo database a conversion moves
        self._sinks = {}
        self._streams = []            # the members opened since the last reset_app
        self._adapters = {}
        self._temps = {}
        self._owners = set()          # every owner this job made throwaway objects for (the record's temp_owners)
        self._stale = []              # the TempObjects of an earlier app that could not remove everything yet
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
            except Exception:  # noqa: BLE001 - the app's own check reports it (owner missing, not deployed, ...)
                continue
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
        if phase_id not in ids:
            return  # a check's reading inside a conversion (_only_database)
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

    # ---------------------------------------------------------- what is found
    def sink(self, app):
        """The haissues.Sink of an app (its catalog entry or its id; haissues.SHARED in a check: what is no single app's):
        the check collects, the conversion refuses what the customer did not confirm. (Reads only what it has: lab
        harnesses bind this method to a stand-in.)"""
        app_id = app if isinstance(app, str) else app.id
        sinks = self.__dict__.setdefault('_sinks', {})
        if app_id not in sinks:
            acknowledged = getattr(self, 'acknowledged', None)
            sinks[app_id] = haissues.Sink(app_id, None if acknowledged is None else acknowledged.get(app_id) or (),
                                          database=getattr(self, 'database', None), log=self.log)
        return sinks[app_id]

    @contextlib.contextmanager
    def collecting(self, app):
        """Collecting sinks for the block (a conversion that runs the check's reading for a choice), the shared one, too;
        what they find is not the conversion's."""
        names = (app.id, haissues.SHARED)
        kept = {name: self._sinks.pop(name) for name in names if name in self._sinks}
        self._sinks.update({name: haissues.Sink(name, log=self.log) for name in names})
        try:
            yield self._sinks[app.id]
        finally:
            for name in names:
                self._sinks.pop(name, None)
            self._sinks.update(kept)

    def choice(self, app_id, kind):
        return (getattr(self, 'choices', None) or {}).get(app_id, {}).get(kind)

    # ---------------------------------------------------------- the HA backup
    def open(self, member):
        stream = self.ha.open_member(member.name, self.keys)
        streams = self.__dict__.setdefault('_streams', [])
        streams[:] = [item for item in streams if not getattr(item, 'closed', True)] + [stream]
        return stream

    def addon_member(self, suffix):
        """The member of the add-on called `suffix`; the same add-on from two stores needs a choice (HA-04)."""
        found = addon_members(self.ha.layout, suffix)
        if not found:
            for addon in (getattr(self.ha.layout, 'doc', None) or {}).get('addons') or ():
                # Listed without a member that can be used: the layout says why.
                if hastore.addon_suffix(addon['slug']) == suffix:
                    self.ha.layout.addon(addon['slug'])
            raise haissues.stopped(Issue('ha.addon-missing', 'stop', ADDON_MISSING, action=ADDON_MISSING_ACTION),
                                   'not-found', slug=suffix)
        importer = haapps.for_slug(suffix)
        wanted = Work.choice(self, importer.app_id, 'addon') if importer is not None else None
        if wanted is not None:
            member = next((m for m in found if m.slug == wanted), None)
            if member is None:
                raise haissues.stopped(Issue('ha.addon-choice', 'stop', ADDON_GONE, [m.slug for m in found],
                                             action=ADDON_CHOICE_ACTION), slug=suffix)
            return member
        if len(found) > 1:
            raise haissues.stopped(Issue('ha.addon-choice', 'stop', ADDON_TWICE, [m.slug for m in found],
                                         action=ADDON_CHOICE_ACTION), slug=suffix)
        return found[0]

    def addon_choices(self, suffix):
        """`choices.addon` of an add-on that is there more than once, else []."""
        found = addon_members(self.ha.layout, suffix)
        if len(found) < 2:
            return []
        rows = []
        for member in found:
            addon = next((a for a in self.record['addons'] if a['slug'] == member.slug), {})
            store = member.slug.split('_', 1)[0] if '_' in member.slug else member.slug
            rows.append({'value': member.slug, 'label': f'{addon.get("name") or suffix}（商店 {store}，'
                                                        f'{addon.get("version") or "版本不明"}）'})
        return rows

    def share_member(self):
        return next((m for m in self.ha.layout.members if m.role == 'folder' and m.slug == 'share'), None)

    def addon_info(self, suffix):
        """AddonInfo of the add-on's addon.json (its first entry; cached). The add-on is identified by `system.slug`."""
        if suffix not in self._addons:
            member = self.addon_member(suffix)
            with self.open(member) as stream:
                info = habackup.read_addon_info(stream)
            if info is None or info.slug != suffix:
                raise haissues.stopped(Issue('ha.addon-other', 'stop', ADDON_OTHER, action=ADDON_OTHER_ACTION),
                                       slug=suffix)
            self._addons[suffix] = info
        return self._addons[suffix]

    # ---------------------------------------------------------- the target
    def adapter(self, app):
        if app.id not in self._adapters:
            adapter = self.ctx.adapter(app, phases=False)
            # X-AD-01: the owner's user manager runs (linger is enabled when it did not), else nothing of the app can be read
            # and the adapter calls it "not deployed". Kept only once it works: the app's own step stops, with the reason.
            hatarget.ensure_user_manager(self, app, adapter.runner)
            self._adapters[app.id] = adapter
        return self._adapters[app.id]

    def runner(self, app):
        return self.adapter(app).runner

    def quadlets(self, app):
        return self.adapter(app).read_quadlets()

    def temp(self, app):
        owner = app.owner
        if owner not in self._temps:
            self._owners.add(owner)
            self.ctx.reporter.set_partial(temp_owners=sorted(self._owners))
            # A name of the app's own for every object it makes, once tempctr knows scopes (two apps of one check use the
            # same roles): what one app could not remove then never stands in the way of the next one's.
            scope = {'scope': str(self._app[0])} if self._app and getattr(tempctr, 'SCOPES', False) else {}
            self._temps[owner] = tempctr.TempObjects(self.runner(app), self.job_id, log=self.log,
                                                     abort=self.watchdog.abort, **scope)
            hatarget.scale_waits(self._temps[owner], self.ha)  # X-PD-05: a big backup is given the time it needs
            for folder in self.storage_folders(app):
                if folder not in self.guard.folders:
                    self.guard.folders.append(folder)
        return self._temps[owner]

    def image_version(self, app, ref, *, label='org.opencontainers.image.version', env=(), command=None,
                      role='version'):
        """The x.y.z version of a local image, None when nothing tells it (CM-06: then the version only goes unsaid,
        haissues.version_issues): its label, then the named variables of its configuration (`env`; a version is all that
        is kept of them), then its program's own answer (`command`: (entrypoint, args...), run in a throwaway container
        without a network and with a read-only root)."""
        from . import hacommon
        try:
            version = hacommon.semver(hacommon.image_labels(self, app, ref).get(label))
        except BackupError as error:
            if error.code != 'job-failed':  # an image that is not here (or a bad name) is the caller's to say
                raise
            version = None
        if version is None and env:
            version = self._env_version(app, ref, env)
        if version is None and command:
            version = self._program_version(app, ref, command, role)
        if version is None:
            self.log(f'讀不到映像 {str(ref)[:120]} 的版本（標籤、設定和程式都沒有）；這次不比對版本')
        return version

    def _program_version(self, app, ref, command, role):
        from . import hacommon
        tmp = self.temp(app)
        try:
            result = tmp.run(role, ref, list(command[1:]), entrypoint=command[0], read_only_root=True,
                             timeout=tempctr.SHORT_TIMEOUT, max_output=64 * 1024, check=False)
        except BackupError as error:
            if haissues.is_job_wide(error):
                raise
            return None
        finally:
            with contextlib.suppress(BackupError):
                if tmp.name(role) in tmp.containers:
                    tmp.remove(role)
        text = (result.stdout or b'').decode('utf-8', 'replace')
        match = re.search(r'(?<![0-9.])v?([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})(?![0-9.])', text)
        return hacommon.semver(match.group(1)) if result.returncode == 0 and match else None

    def _env_version(self, app, ref, names):
        from . import hacommon
        try:
            result = self.runner(app).podman('image', 'inspect', '--format', '{{json .Config.Env}}', ref,
                                             timeout=tempctr.SHORT_TIMEOUT, max_output=256 * 1024, check=False)
            lines = json.loads((result.stdout or b'null').decode('utf-8')) if result.returncode == 0 else None
        except (BackupError, ValueError):
            lines = None
        for line in lines if isinstance(lines, list) else ():
            key, sep, value = line.partition('=') if isinstance(line, str) else ('', '', '')
            if sep and key in names and hacommon.semver(value):
                return hacommon.semver(value)
        return None

    def reset_app(self, app=None, *, keep=()):
        """After an app of a check: the members it left open are closed, its throwaway objects removed and staging
        emptied (except the names in `keep`), so the next app starts clean whatever this one left (HA-12). Never raises:
        what could not be removed is logged and left to the job's end and the sweeps."""
        for stream in self._streams:
            with contextlib.suppress(Exception):
                stream.close()
        self._streams.clear()
        tmp = self._temps.pop(getattr(app, 'owner', None), None)  # the next app gets its own
        if tmp is not None:
            try:
                left = tmp.cleanup()
            except Exception:  # noqa: BLE001 - the job's end and the next job's sweep try again
                traceback.print_exc(file=sys.stderr)
                left = True
            if left:
                self._stale.append(tmp)
        try:
            names = [name for name in os.listdir(self.staging) if name not in keep]
        except OSError:
            names = []
        for name in names:
            path = self.staging / name
            try:
                shutil.rmtree(path) if path.is_dir() and not path.is_symlink() else os.unlink(path)
            except OSError:
                self.log('警告：有暫存檔沒有清除，作業結束時會再清除。')
                break

    def close(self):
        """Remove every throwaway object; the record forgets the owners once nothing is left."""
        self.watchdog.stop()
        left = []
        for tmp in [*self._temps.values(), *self._stale]:
            try:
                left += tmp.cleanup()
            except Exception:  # noqa: BLE001 - the result of the job stands; the record keeps the owners for the sweep
                traceback.print_exc(file=sys.stderr)
                left.append('?')
        if self._owners and not left:
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


def addon_members(layout, suffix):
    """The members of the add-on called `suffix`, whatever store it came from."""
    return [m for m in layout.members if m.role == 'addon' and hastore.addon_suffix(m.slug) == suffix]


def _catalog_app(ctx, app_id):
    catalog = ctx.catalog()
    return catalog.get(app_id)


def _app_label(app_id, app=None):
    return getattr(app, 'name', None) or haapps.get(app_id).name


def _base_result(app_id, member, addon):
    return {'app_id': app_id, 'slug': member.slug if member else APPS[app_id], 'name': '',
            'arch': addon.arch if addon else 'unknown', 'version': addon.version if addon else '',
            'target_version': '', 'importable': False, 'ok': False, 'blockers': [], 'warnings': [], 'issues': []}


def not_installed(catalog, app_id):
    """The issue of an app this device has no (usable) settings for."""
    problem = catalog.problem_for(app_id) if hasattr(catalog, 'problem_for') else None
    name = _app_label(app_id)
    if problem and problem.get('message'):
        action = SETTINGS_ACTION.format(name=name)
        if problem.get('code') == 'owner-missing':
            action = haissues.ACTIONS['owner-missing']
        return Issue('ha.not-installed', 'stop', problem['message'], action=action)
    return Issue('ha.not-installed', 'stop', NOT_INSTALLED.format(name=name), action=INSTALL_ACTION.format(name=name))


def _deployed_issue(work, app):
    """The app must be deployed here (its images, Quadlet files and secrets are read live): an Issue, else None."""
    adapter = work.adapter(app)
    info = adapter.probe()
    if not info.get('deployed'):
        return Issue('ha.not-deployed', 'stop', f'這台的「{app.name}」還沒有部署完成。', action=DEPLOY_ACTION)
    if info.get('problems'):
        return Issue('ha.app-problem', 'stop', f'這台的「{app.name}」狀態異常：{info["problems"][0]}',
                     action=PROBLEM_ACTION)
    return None


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


def needed_members(layout, members):
    """[(app id, member)] of every member the selected apps read: their add-ons and, for an importer that reads it
    (`needs_share`), HA's share folder (KEY-16: one key for the whole backup, asked for when any of them needs it)."""
    share = next((m for m in layout.members if m.role == 'folder' and m.slug == 'share'), None)
    wanted = [(app_id, member) for app_id, member in members.items()]
    wanted += [(app_id, share) for app_id in members if share is not None and haapps.get(app_id).needs_share]
    return wanted


def key_problems(ha, keys, wanted):
    """{app id: exception} of the encrypted members that cannot be opened, checked before any plaintext is read.
    `key-required` (no key came and something is encrypted) and a `wrong-key` that opens nothing at all end the whole
    job (DESIGN C1); one member that does not open while another does stops only its app."""
    encrypted = [(app_id, member) for app_id, member in wanted if member.encrypted]
    if not encrypted:
        return {}
    if keys is None:
        raise haissues.job_wide(hasecuretar.key_required(member=encrypted[0][1].name))
    tried, problems = {}, {}
    for app_id, member in encrypted:
        if member.name not in tried:
            try:
                with ha.open_member(member.name, keys):
                    pass  # the decrypting reader checks the key when it opens
                tried[member.name] = None
            except Exception as error:  # noqa: BLE001 - whatever keeps a member shut is its apps' (haissues.app_failure)
                if haissues.ends_job(error):
                    raise
                tried[member.name] = error
        if tried[member.name] is not None:
            problems.setdefault(app_id, tried[member.name])
    if all(error is not None for error in tried.values()):
        wrong = next((error for error in tried.values() if getattr(error, 'code', None) == 'wrong-key'), None)
        if wrong is not None:
            raise haissues.job_wide(wrong)
    return problems


def _require_key(work, members, *, grouped=False):
    """A conversion needs every selected member: key-required / wrong-key (or what else keeps one shut). `grouped`: one
    app of an import (ha-import-start opened at least one of the selected members with this key before it began): a
    member the key does not open is this app's alone and never ends the import (DESIGN C1)."""
    try:
        problems = key_problems(work.ha, work.keys, needed_members(work.ha.layout, members))
    except BackupError as error:
        if grouped and error.code == 'wrong-key':
            error.job_wide = False
        raise
    if problems:
        raise next(iter(problems.values()))


def _check_space(work, members):
    """Up front: three times the add-ons' members (a first, low estimate; the app steps check again with the sizes
    they measured while streaming, and the watchdog looks every few seconds)."""
    need = 3 * sum(m.size for m in members.values())
    work.guard.check(need)


def _watched_apps(ctx, app_ids):
    return [app for app in (_catalog_app(ctx, app_id) for app_id in app_ids) if app is not None]


def valid_database(name):
    """An Odoo database name HA may have: 1..63 bytes of text without control characters (HA-14; whether the importer
    can move it is the check's word)."""
    if not isinstance(name, str) or not name:
        return False
    try:
        data = name.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return len(data) <= MAX_DATABASE_BYTES and not re.search(r'[\x00-\x1f\x7f-\x9f]', name)


# ====================================================================== check

def run_ha_check(ctx, params):
    """`verify` job with source ha: {ha_check: {schema 2, ha_backup_id, shared[], apps[AppCheck]}} (CONTRACT section 7).
    Nothing one app meets stops the others (DESIGN C2): it becomes a `stop` of that app, and the job ends well. What
    ends the whole job (a cancel, a termination, a disk that runs full, a key that opens nothing) still hands over
    what was found until then (`error.result`; jobs.run_job keeps it)."""
    ctx.cancellable(True)
    ctx.phase('prepare')
    app_ids = list(params.get('apps') or [])
    ctx.storage.ensure_layout()
    staging = Path(ctx.storage.staging_dir(ctx.job_id))
    key = job_key(ctx)
    work = Work(ctx, None, key, staging, phases=CHECK_PHASES, choices=params.get('choices'))
    results, shared, started = [], [], False
    try:
        work.record = _open(work, ctx, params)
        members, problems = _members_or_problems(work, app_ids)
        for app_id, error in key_problems(work.ha, work.keys, needed_members(work.ha.layout, members)).items():
            problems.setdefault(app_id, error)
        shared = shared_issues(ctx)
        ctx.log(f'檢查 HA 備份「{work.record["name"]}」：{"、".join(app_ids)}')
        work.watch(_watched_apps(ctx, app_ids))
        started = True
        for index, app_id in enumerate(app_ids):
            results.append(_check_app(work, app_id, members.get(app_id), problems.get(app_id), index, len(app_ids)))
            work.checkpoint()
        work.end_apps()
        work.phase('check')
        return {'ha_check': _check_view(work, results, shared)}
    except BaseException as error:
        ended = haissues.out_of_space(error) or error
        if started:
            done = len(results)
            for app_id in app_ids[done:]:
                at_its_turn = ended if app_id == app_ids[done] else None
                results.append(_not_checked(work, app_id, members.get(app_id), at_its_turn))
            ended.result = {'ha_check': _check_view(work, results, shared)}
        if ended is not error:
            raise ended from error
        raise
    finally:
        work.close()
        _cleanup(ctx)


def shared_issues(ctx):
    """What belongs to no single app (HaCheck.shared)."""
    found = []
    with contextlib.suppress(Exception):  # a key store that cannot be read is the import's to report, not the check's
        if ctx.encrypt_by_default() and ctx.keys.device_key() is None:
            found.append(Issue('shared.device-key', 'auto', KEY_CREATED))
    return found


def _check_view(work, results, shared):
    """`shared` also holds what the apps' checks found that is no single app's (work.sink(haissues.SHARED)), once."""
    lines, seen = [], set()
    for issue in [*shared, *work.sink(haissues.SHARED).found]:
        line = (issue.id, issue.level, issue.text, issue.key(haissues.SHARED))
        if line not in seen:
            seen.add(line)
            lines.append(issue)
    return _fit_record(work, {'schema': CHECK_SCHEMA, 'ha_backup_id': work.record['id'],
                              'shared': haissues.views(haissues.SHARED, lines), 'apps': results})


def _fit_record(work, view):
    """The result as one job record can hold it, whatever a backup makes the checks say (a larger record could never be
    read again, and retention would keep everything because of it): while it is too large, the app with the most to
    say loses its own section (its issues and choices stay), then it becomes a stop of its own. The others stay."""
    from .jobs import _json_bytes
    for _step in range(2 * len(view['apps'])):
        if len(_json_bytes(view)) <= CHECK_BYTES:
            break
        row = max(view['apps'], key=lambda item: len(_json_bytes(item)))
        name = row['name'] or row['app_id']
        if row.pop(row['app_id'], None) is not None:
            work.log(f'「{name}」的檢查結果太大，只保留結論')
            continue
        row.pop('choices', None)
        row.update(haissues.check_fields(row['app_id'], [Issue('failure.limit-exceeded', 'stop', TOO_LARGE,
                                                               action=haissues.ACTIONS['limit-exceeded'])]))
        work.log(f'「{name}」不能匯入：{TOO_LARGE}')
    return view


def _check_app(work, app_id, member, problem, index, count):
    """One app's result. Whatever it meets becomes its own `stop` (haissues.app_failure); only an error that ends the
    whole job comes out. Afterwards nothing of it is left for the next app (Work.reset_app)."""
    ctx = work.ctx
    app, addons = None, []
    result = _base_result(app_id, member, None)
    try:
        try:
            result['name'] = _record_addon_name(work.record, member)
            app = _catalog_app(ctx, app_id)
            work.begin_app(index, count, result['name'] or _app_label(app_id, app))
            work.phase('decrypt')
            addons = work.addon_choices(APPS[app_id])
            choices = _examine(work, app_id, app, member, problem, result)
            issues = work.sink(app_id).found
            fields = haissues.check_fields(app_id, issues, {'addon': addons, **choices})
        except BaseException as error:
            stops = haissues.app_failure(error)
            if stops is None:
                raise
            result.pop(app_id, None)  # no section: the check did not get to its end
            issues = haissues.combine(work.sink(app_id).found, stops)
            fields = haissues.check_fields(app_id, issues, {'addon': addons})
    finally:
        work.reset_app(app)
    result.update(fields)
    name = result['name'] or app_id
    ctx.log(f'「{name}」檢查完成：{"可以匯入" if result["importable"] else "不能匯入"}')
    for issue in issues:
        if issue.level == 'stop' and issue.database is None:
            ctx.log(f'「{name}」不能匯入：{issue.message}')
    return result


def _examine(work, app_id, app, member, problem, result):
    """The app's own check; fills `result` and its sink, returns its choices."""
    if problem is not None:
        raise problem
    sink = work.sink(app_id)
    addon = work.addon_info(APPS[app_id])
    result.update(arch=addon.arch, version=addon.version, name=addon.name or result['name'])
    if addon.arch == 'unknown':  # HA-06: no gate; data of another processor is refused by the database that opens it
        work.log(f'「{result["name"] or app_id}」的附加元件沒有寫明處理器，改由資料本身判斷')
    if app is None:
        raise haissues.stopped(not_installed(work.ctx.catalog(), app_id), 'app-not-in-catalog')
    issue = _deployed_issue(work, app)
    if issue is not None:
        raise haissues.stopped(issue, 'not-deployed')
    work.guard.check(3 * member.size)
    module = haapps.get(app_id).load()
    found = module.check(work, app)
    result['target_version'] = found.get('target_version') or ''
    result[app_id] = found[app_id]  # the app's own section (CONTRACT section 7 HaCheck)
    return _collect(app_id, module, found, sink)


def _collect(app_id, module, found, sink):
    """What a module's check returned, into the app's sink (what it did not put there itself); returns its choices."""
    sink.extend(found.get('issues') or ())
    derived = getattr(module, 'check_blockers', None)
    blockers = list(found.get('blockers') or []) + (list(derived(found)) if derived is not None else [])
    sink.extend(haissues.from_legacy(blockers, found.get('warnings')))
    return _module_choices(app_id, found, sink)


def _module_choices(app_id, found, sink):
    """`choices` of the module; one that still describes its databases only in its section (Odoo) gets them from
    there, with each database's sentences as issues of that database."""
    choices = {kind: list(rows) for kind, rows in (found.get('choices') or {}).items()}
    section = found[app_id]
    databases = section.get('databases') if isinstance(section, dict) else None
    if 'database' in haapps.get(app_id).choices and 'database' not in choices and isinstance(databases, list):
        choices['database'] = []
        for db in databases:
            choices['database'].append({'value': db['name'], 'label': db['name'],
                                        'ok': db.get('ok') is True and valid_database(db['name'])})
            sink.extend(haissues.from_legacy(db.get('blockers'), db.get('warnings'), database=db['name']))
    return choices


def _not_checked(work, app_id, member, error):
    """The result of an app the job did not get to (`error`: the one the job ended at while it was this app's turn)."""
    result = _base_result(app_id, member, None)
    result['name'] = _record_addon_name(work.record, member)
    issues = []
    if isinstance(error, BackupError):
        issues = haissues.from_error(error)
    issues = issues or [Issue('ha.not-checked', 'stop', NOT_CHECKED, action=NOT_CHECKED_ACTION)]
    result.update(haissues.check_fields(app_id, issues))
    return result


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
        when = str(record.get('date') or '日期不明')[:20]  # a backup.json without a date that can be read (UP-26)
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
    """`backup` job with source ha: {backup_id, size, apps, encrypted, ha_import, results} (CONTRACT section 7)."""
    return _run_ha_convert(ctx, params)


def _run_omnigent_candidate(ctx, params, *, schema_ddl_quiesced):
    """Lab compatibility entry of the 2026-11-20..23 internal-candidate harnesses; never selected by request fields
    or public routing. It runs exactly the product conversion (`run_ha_convert`): Omnigent's `convert` enforces the
    trusted schema and the capture's stability itself (ha_omnigent.trusted_schema), so the flag only keeps those
    callers' contract (Omnigent alone, the flag exactly True)."""
    if list(params.get('apps') or []) != ['omnigent'] or schema_ddl_quiesced is not True:
        raise BackupError('incompatible', '內部候選僅限 Omnigent，且須保證目標結構變更已暫停。')
    return _run_ha_convert(ctx, params)


def _install_omnigent_candidate(ctx, backup_id):
    """Lab compatibility entry: the ordinary restore (safety backup, rollback) of a converted Omnigent backup."""
    from . import flows
    row = (load_registry(ctx.paths) or {}).get(backup_id)
    if not row or row.get('apps') != ['omnigent']:
        raise BackupError('incompatible', '找不到內部 Omnigent 候選的轉換紀錄。')
    return flows.run_restore(ctx, {'backup_id': backup_id, 'apps': ['omnigent']})


def _run_ha_convert(ctx, params):
    from .flows import Cancelled
    app_ids = list(params.get('apps') or [])
    sinks = {}
    try:
        return _convert_apps(ctx, params, app_ids, sinks)
    except BaseException as error:
        # One app (an import's chain): the result says what became of it, whatever went wrong (CONTRACT section 7).
        if len(app_ids) != 1 or not isinstance(error, Exception) or isinstance(error, Cancelled):
            raise
        full = haissues.out_of_space(error)
        issues = haissues.from_error(full or error)
        ended = full or (error if isinstance(error, BackupError) else BackupError('internal-error', UNEXPECTED_JOB))
        found = sinks[app_ids[0]].found if app_ids[0] in sinks else []
        ended.result = {'results': [convert_result(app_ids[0], ended, haissues.combine(found, issues))]}
        if ended is not error:
            raise ended from error
        raise


# What keeps an app out before anything of its conversion started (`skipped`; everything else is `failed`).
SKIP_CODES = frozenset({'not-found', 'app-not-in-catalog', 'owner-missing', 'not-deployed', 'key-required', 'wrong-key',
                        'confirmation-required', 'invalid-request'})


def convert_result(app_id, error, issues):
    """One app of `result.results` (CONTRACT section 7): converted (`error` None), skipped (its own check, a missing
    add-on or an unconfirmed line kept it out) or failed (it went wrong half way). This device is unchanged either
    way."""
    status, code, message = 'converted', None, None
    if error is not None:
        status = 'skipped' if error.issues or error.code in SKIP_CODES else 'failed'
        code, message = error.code, haissues.clean(_redact(error.message), haissues.MAX_MESSAGE)
    return {'app_id': app_id, 'status': status, 'code': code, 'message': message,
            'issues': haissues.views(app_id, issues)}


def _redact(text):
    from .jobs import redact
    return redact(text)


def device_key_for(ctx):
    """The device key an encrypted converted backup needs; created when this device has none (HA-13, D11: restoring a
    backup on HAOS needs no key of one's own). The page keeps asking to download it until it is confirmed."""
    key = ctx.keys.device_key()
    if key is not None:
        return key
    try:
        key, created = ctx.keys.ensure_device_key()
    except (BackupError, OSError) as error:
        raise haissues.job_wide(BackupError('no-device-key', NO_KEY_CREATED)) from error
    if created:
        ctx.log('已自動建立這台的加密金鑰；請到「加密金鑰」下載並保存，換機或重灌後要用它才能解開備份。')
        ctx.audit(f'device-key-created key_id={key.key_id} reason=ha-import job={ctx.job_id}')
    return key


def _only_database(work, app, module):
    """The Odoo database to move when the request names none (HA-14): the only one that can move. The check's reading
    finds it; nothing of it stays."""
    kept = os.listdir(work.staging)  # what the conversion wrote so far
    try:
        with work.collecting(app) as sink:
            choices = _collect(app.id, module, module.check(work, app), sink)
            rows = haissues.databases_ok(choices.get('database'), sink.found)
            stop = next((issue for issue in sink.found if issue.level == 'stop' and issue.database is None), None)
    finally:
        work.reset_app(app, keep=kept)
    if stop is not None:
        raise haissues.stopped(stop)  # what keeps the whole app out, whichever database it is
    movable = [row['value'] for row in rows if row['ok']]
    if len(movable) == 1:
        work.log(f'HA 的 Odoo 只有一個能搬的資料庫，自動選擇：{haissues.clean(movable[0], 63)}')
        return movable[0]
    if not movable:
        raise BackupError('incompatible', NO_DATABASE)
    raise BackupError('invalid-request', CHOOSE_DATABASE, field='odoo_database')


def _convert_apps(ctx, params, app_ids, sinks):
    from .flows import _package, resolve_apps
    ctx.cancellable(True)
    ctx.phase('prepare')
    choices = params.get('choices') or {}
    database = params.get('odoo_database')
    if database is None:
        database = (choices.get('odoo') or {}).get('database')
    test_mode = params.get('test_mode') is True
    apps = resolve_apps(ctx.catalog(), app_ids)
    encrypt = params.get('encrypt', ctx.encrypt_by_default()) is not False
    if 'odoo' in app_ids and database is not None and not valid_database(database):
        raise BackupError('invalid-request', CHOOSE_DATABASE, field='odoo_database')
    ctx.storage.ensure_layout()
    staging = Path(ctx.storage.staging_dir(ctx.job_id))
    key = job_key(ctx)
    work = Work(ctx, None, key, staging, phases=CONVERT_PHASES, choices=choices,
                acknowledged=params.get('acknowledged') or {})
    work._sinks = sinks
    backup_id = None
    registered = False
    try:
        work.record = _open(work, ctx, params)
        members = _members(work, app_ids)
        _require_key(work, members, grouped=_group_id(params) is not None)
        device_key = device_key_for(ctx) if encrypt else None
        record = work.record
        ctx.log(f'轉換 HA 備份「{record["name"]}」：{"、".join(app_ids)}'
                + (f'（Odoo 資料庫 {haissues.clean(database, 63)}）' if database else '')
                + ('，測試匯入' if test_mode else ''))
        if not encrypt:
            ctx.log('這份備份不加密：應用機密（資料庫密碼、API 金鑰、存取權杖）會以明文存放在備份檔中')
        for app in apps:
            work.addon_info(APPS[app.id])
            issue = _deployed_issue(work, app)
            if issue is not None:
                raise haissues.stopped(issue, 'not-deployed', app=app.id)
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
            if 'odoo_database' in importer.convert_args:
                if database is None:
                    database = _only_database(work, app, importer.load())
                work.database = database
            values = {'odoo_database': database, 'test_mode': test_mode}
            data = importer.load().convert(work, app, *[values[name] for name in importer.convert_args], out_dir)
            converted[app.id] = data
            item_args = {key: data[key] for key in ITEM_KEYS if key in data}
            work.checkpoint()
            hatarget.ensure_app_images(work, app)  # X-AD-60: an image of this device that is not there is downloaded first
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
                         'created': util.iso_utc(), 'group': _group_id(params),
                         'confirmed': [line for app in apps if app.id in sinks for line in sinks[app.id].confirmed()],
                         'left_databases': (converted.get('odoo') or {}).get('left_databases') or []})
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
                'encrypted': result['encrypted'], 'ha_import': view_row(row),
                'results': [convert_result(app.id, None, sinks[app.id].found if app.id in sinks else [])
                            for app in apps]}
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


def _group_id(params):
    group = params.get('group')
    value = group.get('id') if isinstance(group, dict) else None
    return value if isinstance(value, str) and GROUP_RE.fullmatch(value) else None


def _job_or_none(value):
    from .jobs import valid_job_id
    return value if valid_job_id(value) else None


def _backup_or_none(value):
    from .storage import valid_backup_id
    return value if isinstance(value, str) and valid_backup_id(value) else None


def _clean_results(values):
    """GroupResult rows as the registry keeps them (an unknown app or status is left out)."""
    rows = []
    for item in (values if isinstance(values, list) else [])[:MAX_RESULTS]:
        if not isinstance(item, dict) or item.get('app_id') not in tuple(APPS) \
                or item.get('status') not in RESULT_STATUS:
            continue
        rows.append({'app_id': item['app_id'], 'status': item['status'],
                     'convert_job_id': _job_or_none(item.get('convert_job_id')),
                     'restore_job_id': _job_or_none(item.get('restore_job_id')),
                     'backup_id': _backup_or_none(item.get('backup_id')),
                     'safety_backup_id': _backup_or_none(item.get('safety_backup_id')),
                     'code': _clean(item['code'], 40) if item.get('code') is not None else None,
                     'message': _clean(item['message'], haissues.MAX_MESSAGE) if item.get('message') is not None
                     else None})
    return rows


def _clean_confirmed(values):
    """What the customer confirmed ([{app_id, id, items}]): fixed ids, the names cut so that a row stays small."""
    rows, left = [], MAX_CONFIRMED_TEXT
    for item in (values if isinstance(values, list) else [])[:MAX_CONFIRMED]:
        if not isinstance(item, dict) or item.get('app_id') not in (*APPS, haissues.SHARED) \
                or not isinstance(item.get('id'), str) or not haissues.ID_RE.fullmatch(item['id']):
            continue
        names = []
        for name in (item.get('items') if isinstance(item.get('items'), list) else [])[:haissues.MAX_ITEMS]:
            name = _clean(name, haissues.MAX_ITEM)
            if len(name) <= left:
                names.append(name)
                left -= len(name)
        rows.append({'app_id': item['app_id'], 'id': item['id'], 'items': names})
    return rows


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
    cleaned['group'] = _group_id({'group': {'id': row.get('group')}})
    cleaned['results'] = _clean_results(row.get('results'))
    cleaned['confirmed'] = _clean_confirmed(row.get('confirmed'))
    cleaned['left_databases'] = [name for name in (row.get('left_databases') or ())
                                 if valid_database(name)][:MAX_LEFT_DATABASES]
    cleaned['kept'] = _clean(row['kept'], 100) if isinstance(row.get('kept'), str) and row['kept'] else None
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
    if not hastore.valid_id(row['ha_backup_id']) or not _text(row['name'], 200) \
            or not (row['date'] is None or util.is_iso_utc(row['date'])):
        return False
    apps = row['apps']
    if not isinstance(apps, list) or not 1 <= len(apps) <= len(APPS) or not all(a in APPS for a in apps) \
            or len(set(apps)) != len(apps):
        return False
    if row['odoo_database'] is not None and not (_text(row['odoo_database'], 63) and row['odoo_database']):
        return False
    if row['group'] is not None and not (isinstance(row['group'], str) and GROUP_RE.fullmatch(row['group'])):
        return False
    if row['kept'] is not None and not (_text(row['kept'], 100) and row['kept']):
        return False
    if not isinstance(row['results'], list) or _clean_results(row['results']) != row['results']:
        return False
    if not isinstance(row['confirmed'], list) or _clean_confirmed(row['confirmed']) != row['confirmed']:
        return False
    names = row['left_databases']
    if not isinstance(names, list) or len(names) > MAX_LEFT_DATABASES or not all(valid_database(n) for n in names):
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
        doc = util.load_json_file(registry_path(paths), max_bytes=REGISTRY_MAX_BYTES)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or isinstance(doc.get('schema'), bool) or doc.get('schema') not in REGISTRY_READS \
            or not isinstance(doc.get('imports'), dict):
        return None
    from .storage import valid_backup_id
    rows = {bid: _upgrade(row) for bid, row in doc['imports'].items()}
    return {bid: row for bid, row in rows.items() if valid_backup_id(bid) and valid_row(row)}


def _row_bytes(backup_id, row):
    """At least the bytes a row takes in the file (util.atomic_write_json indents it two levels deep)."""
    text = json.dumps({backup_id: row}, ensure_ascii=False, indent=2)
    return len(text.encode('utf-8', 'surrogatepass')) + 4 * (text.count('\n') + 1)


def _fit(rows, backup_id):
    """Drop the oldest rows (never `backup_id`'s) until the file is one load_registry reads: a larger one would lose
    every row."""
    sizes = {bid: _row_bytes(bid, item) for bid, item in rows.items()}
    for bid in sorted(rows, key=lambda b: rows[b]['created']):
        if sum(sizes.values()) <= REGISTRY_MAX_BYTES - 4096:
            break
        if bid != backup_id:
            rows.pop(bid)
            sizes.pop(bid)


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
        _fit(rows, backup_id)
        _save_registry(paths, rows)


# What may be added to a row after its backup was made (the import's chain, the restore's kept copy).
ROW_LATER = ('results', 'kept')


def update_row(paths, backup_id, **fields):
    """Set `results` (GroupResult rows) and/or `kept` (the id of a kept copy) of a converted backup's row, cleaned like
    every row; False when there is no such row or the file cannot be read (then nothing is written)."""
    if not fields or not set(fields) <= set(ROW_LATER):
        raise BackupError('internal-error', 'HA 匯入紀錄的欄位不正確。')
    with _index_lock(paths):
        rows = load_registry(paths)
        if not rows or backup_id not in rows:
            return False
        row = clean_row(dict(rows[backup_id], **fields))
        if not valid_row(row):
            raise BackupError('internal-error', 'HA 匯入紀錄的格式不正確。')
        rows[backup_id] = row
        _fit(rows, backup_id)
        _save_registry(paths, rows)
        return True


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
