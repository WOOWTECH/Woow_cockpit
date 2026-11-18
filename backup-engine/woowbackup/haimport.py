"""Home Assistant import jobs: check and convert (CONTRACT sections 7, 8 and 9 "Home Assistant import"; branch
feat/ha-import, part B). Owner: E2.

* `run_ha_check(ctx, params)` -- job type `verify` with `params.source == 'ha'` (phases 準備, 解開 HA 備份, 檢查內容與版本):
  decrypts only the selected add-ons' members, rebuilds what it must read in throwaway containers (tempctr.py), compares
  with this device's apps and returns `{ha_check}`. Nothing of the apps changes; they keep running.
* `run_ha_convert(ctx, params)` -- job type `backup` with `params.source == 'ha'` (phases 準備, 解開 HA 備份, 轉換資料,
  封裝備份, 驗證備份): rebuilds the selected apps' data in their own format (ha_odoo.py, ha_n8n.py) and writes a normal
  format 2 backup of them -- the data items converted, everything else (secrets, config files, Quadlet files, images list,
  the installed settings) read live as the owner without stopping anything, exactly like a backup reads it -- of type
  `manual` with the note 「由 HA 備份轉換：<HA name>（<HA date>）」, encrypted with the device key when 預設加密備份 is on,
  verified and registered like any backup; the row in `ha-imports.json` tells `list` where it came from (`from_ha`).
  Importing it is the existing restore (pre-restore backup, rollback). No retention runs in this job.

The HA key the page sent is in the job's key file (raw UTF-8, written by jobs.start_job with key_kind 'ha'); run-job
masks it in every log line before the job starts and hands it over as `ctx.ha_key`. It is never written anywhere else.

`ha-imports.json` (`<data>/ha-imports.json`, root 0600, strict; written under the index lock): `{schema: 1, imports:
{<backup id>: ImportRow}}`, ImportRow = `{ha_backup_id, name, date, apps, odoo_database, test_mode, workflows_to_fix,
reminders, addons, job_id, created}`. A row is written before the backup is packaged (its id is chosen first) and
dropped when the job fails, when the backup is deleted, or later when its backup no longer exists. Deleting the HA file
never touches it: a converted backup keeps its origin.
"""
import contextlib
import fcntl
import os
import re
import time
from pathlib import Path

from . import habackup, hasecuretar, hastore, tempctr, util
from .errors import BackupError

APPS = {'odoo': 'odoo18ce', 'n8n': 'woow-n8n'}  # catalog id -> add-on slug (after the repository prefix)
REGISTRY = 'ha-imports.json'
REGISTRY_SCHEMA = 1
REGISTRY_MAX = 1000
ROW_KEYS = ('ha_backup_id', 'name', 'date', 'apps', 'odoo_database', 'test_mode', 'workflows_to_fix', 'reminders',
            'addons', 'job_id', 'created')
STALE_ROW_SECONDS = 24 * 3600
MAX_KEY_BYTES = 4096
GUARD_STEP = 64 * 1024 * 1024
NOTE_PREFIX = '由 HA 備份轉換：'
FAILURE_CODES = frozenset({'incompatible', 'job-failed', 'not-found', 'unsupported-format', 'app-not-in-catalog',
                           'owner-missing', 'not-deployed', 'limit-exceeded'})
INSTALL_HINT = '請先到「應用軟體」安裝同版本的 {name}，再匯入。'


# ====================================================================== space

class SpaceGuard:
    """Free space while a conversion writes (staging on the data disk, throwaway volumes in the owner's storage):
    every GUARD_STEP bytes written the free space of each watched folder must stay above `floor`, else
    insufficient-space (the apps run meanwhile: their own writes must still fit)."""

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


# ====================================================================== the job's working set

class Work:
    """What the app modules (ha_odoo, ha_n8n) use: the open HA backup and its key, staging, a space guard and, per
    app, its adapter (live reads as the owner), runner and throwaway objects (registered in the job record as
    `temp_owners` before the first one exists, so a killed job's objects are swept by the recovery)."""

    def __init__(self, ctx, record, key, staging):
        self.ctx = ctx
        self.job_id = ctx.job_id
        self.record = record
        self.keys = hasecuretar.Keys(key) if key is not None else None
        self.staging = Path(staging)
        self.ha = None
        self._adapters = {}
        self._temps = {}
        self._addons = {}
        from .flows import running_reserve
        self.floor = running_reserve(ctx)
        self.guard = SpaceGuard([self.staging], self.floor)

    # ---------------------------------------------------------- job record
    def log(self, text):
        self.ctx.log(text)

    def checkpoint(self):
        self.ctx.checkpoint()

    def phase(self, phase_id):
        self.ctx.phase(phase_id)

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
            self._temps[owner] = tempctr.TempObjects(self.runner(app), self.job_id, log=self.log)
            home = self.runner(app).home
            if home not in self.guard.folders:
                self.guard.folders.append(home)
        return self._temps[owner]

    def close(self):
        """Remove every throwaway object; the record forgets the owners once nothing is left."""
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
    return getattr(app, 'name', None) or hastore.IMPORTABLE[APPS[app_id]][1]


def _base_result(app_id, member, addon):
    return {'app_id': app_id, 'slug': member.slug if member else APPS[app_id], 'name': '',
            'arch': addon.arch if addon else 'unknown', 'version': addon.version if addon else '',
            'target_version': '', 'ok': False, 'blockers': [], 'warnings': []}


def _arch_blocker(addon):
    if addon.arch == 'amd64':
        return None
    if addon.arch == 'aarch64':
        return '這份 HA 備份來自 ARM（aarch64）設備；目前只能匯入 x86（amd64）設備的 HA 備份。'
    return '無法判斷這份 HA 備份來自哪一種處理器；目前只能匯入 x86（amd64）設備的 HA 備份。'


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
    need = 3 * sum(m.size for m in members.values())
    work.guard.check(need)


# ====================================================================== check

def run_ha_check(ctx, params):
    """`verify` job with source ha: {ha_check: {ha_backup_id, apps[AppCheck]}} (CONTRACT section 7)."""
    from . import ha_n8n, ha_odoo
    ctx.cancellable(True)
    ctx.phase('prepare')
    app_ids = list(params.get('apps') or [])
    ctx.storage.ensure_layout()
    staging = Path(ctx.storage.staging_dir(ctx.job_id))
    key = job_key(ctx)
    work = Work(ctx, None, key, staging)
    results = []
    try:
        work.record = _open(work, ctx, params)
        members = _members(work, app_ids)
        _require_key(work, members)
        ctx.log(f'檢查 HA 備份「{work.record["name"]}」：{"、".join(app_ids)}')
        for app_id in app_ids:
            member = members[app_id]
            ctx.phase('decrypt')
            addon = work.addon_info(APPS[app_id])
            result = _base_result(app_id, member, addon)
            result['name'] = addon.name or next((a['name'] for a in work.record['addons'] if a['slug'] == member.slug),
                                                '')
            results.append(result)
            app = _catalog_app(ctx, app_id)
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
            try:
                work.guard.check(3 * member.size)
                module = ha_odoo if app_id == 'odoo' else ha_n8n
                found = module.check(work, app)
            except BackupError as error:
                if error.code not in FAILURE_CODES:
                    raise
                result['blockers'].append(error.message)
                ctx.log(f'「{result["name"] or app_id}」不能匯入：{error.message}')
                continue
            result['target_version'] = found.get('target_version') or ''
            if app_id == 'odoo':
                result['odoo'] = found['odoo']
                databases = found['odoo']['databases']
                if not databases:
                    result['blockers'].append('HA 的 Odoo 沒有任何資料庫。')
                elif not any(db['ok'] for db in databases):
                    result['blockers'].append('HA 的 Odoo 資料庫都不能搬過來（原因見各資料庫）。')
            else:
                result['n8n'] = found['n8n']
                result['blockers'] += found['blockers']
                result['warnings'] += found['warnings']
            result['ok'] = not result['blockers']
            ctx.log(f'「{result["name"] or app_id}」檢查完成：{"可以匯入" if result["ok"] else "不能匯入"}')
            ctx.checkpoint()
        ctx.phase('check')
        return {'ha_check': {'ha_backup_id': work.record['id'], 'apps': results}}
    finally:
        work.close()
        _cleanup(ctx)


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


def _reminders(app_ids, converted):
    """Extra reminders the page does not write itself (it writes: stop the HA add-on, log the MCP admin apps in
    again, the test import line)."""
    lines = []
    if 'odoo' in converted:
        lines.append('Odoo 的使用者帳號和密碼會換成 HA 那邊的：這台原本的 Odoo 管理者密碼不再適用，請用 HA 的帳號登入。')
        copied = converted['odoo'].get('custom_modules') or []
        if copied:
            lines.append(f'HA 的自訂模組 {"、".join(m["name"] for m in copied[:20])} 會一起放進這台的自訂模組資料夾。')
    if 'n8n' in converted:
        email = converted['n8n'].get('owner_email')
        lines.append(f'n8n 的登入帳號會換成 HA 的管理者帳號{f"（{email}）" if email else ""}。')
        if converted['n8n'].get('packages'):
            lines.append('HA 的 n8n 社群節點會一起搬過來，請在匯入後確認它們能正常使用。')
    return lines


def run_ha_convert(ctx, params):
    """`backup` job with source ha: {backup_id, size, apps, encrypted, ha_import} (CONTRACT section 7)."""
    from . import ha_n8n, ha_odoo
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
    work = Work(ctx, None, key, staging)
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
        _check_space(work, members)
        converted, manifest_apps, entries = {}, [], []
        addons = []
        for app in apps:
            ctx.phase('decrypt')
            member = members[app.id]
            addon = work.addon_info(APPS[app.id])
            addons.append({'app_id': app.id, 'slug': member.slug, 'name': addon.name or next(
                (a['name'] for a in record['addons'] if a['slug'] == member.slug), '')})
            out_dir = staging / 'apps' / app.id
            out_dir.mkdir(mode=0o700, parents=True)
            if app.id == 'odoo':
                data = ha_odoo.convert(work, app, database, test_mode, out_dir)
                converted['odoo'] = data
                item_args = {'volumes': data['volumes'], 'dirs': data['dirs']}
            else:
                data = ha_n8n.convert(work, app, test_mode, out_dir)
                converted['n8n'] = data
                item_args = {'volumes': data['volumes'], 'postgres': data['postgres']}
            ctx.checkpoint()
            app_manifest, app_entries = work.adapter(app).import_manifest(out_dir, **item_args)
            manifest_apps.append(app_manifest)
            entries.extend(app_entries)
        work.close()  # no throwaway object is needed for the packaging
        fix = converted.get('n8n', {}).get('workflows_to_fix') or []
        row = {'ha_backup_id': record['id'], 'name': record['name'], 'date': record['date'], 'apps': app_ids,
               'odoo_database': database if 'odoo' in app_ids else None, 'test_mode': test_mode,
               'workflows_to_fix': fix[:200], 'reminders': _reminders(app_ids, converted), 'addons': addons,
               'job_id': ctx.job_id, 'created': util.iso_utc()}
        backup_id = ctx.storage.new_backup_id()
        try:
            register(ctx.paths, backup_id, row)
            registered = True
        except Exception as error:  # noqa: BLE001 - the backup is still made; the list just shows no origin
            ctx.log(f'警告：無法記錄這份備份來自 HA（{getattr(error, "message", None) or type(error).__name__}）')
        result = _package(ctx, apps, staging, include_images=False, note=note_for(record), backup_type='manual',
                          key=device_key, phases=True, manifest_apps=manifest_apps, entries=entries, downtime=0,
                          backup_id=backup_id)
        registered = False  # the row now belongs to a listed backup
        return {'backup_id': result['backup_id'], 'size': result['size'], 'apps': result['apps'],
                'encrypted': result['encrypted'], 'ha_import': view_row(row)}
    finally:
        if registered and backup_id is not None:
            with contextlib.suppress(Exception):
                forget(ctx.paths, backup_id)
        work.close()
        _cleanup(ctx)


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


def valid_row(row):
    if not isinstance(row, dict) or set(row) != set(ROW_KEYS):
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
    return {bid: row for bid, row in doc['imports'].items() if valid_backup_id(bid) and valid_row(row)}


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
    return {key: row[key] for key in ('ha_backup_id', 'name', 'date', 'apps', 'odoo_database', 'test_mode',
                                      'workflows_to_fix', 'reminders', 'addons')}


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
    """Remove every throwaway object of the (dead) job `job_id` for these owners; returns zh-TW problems."""
    from .podman import OwnerRunner
    problems = []
    for owner in owners:
        try:
            tempctr.sweep(OwnerRunner(owner), lambda _job: False, log=log, only_job=job_id)
        except BackupError as error:
            if error.code == 'owner-missing':
                continue
            problems.append(f'{owner}：{error.message}')
    return problems


def sweep_finished(paths, *, log=None, current=None):
    """At run-job start: remove the throwaway objects of every job that is not queued/running (the importable apps'
    owners only). Never fails the job."""
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

    for owner in _importable_owners(paths):
        with contextlib.suppress(Exception):
            tempctr.sweep(OwnerRunner(owner), alive, log=log)


def interrupted_message(job_type):
    if job_type == 'verify':
        return '檢查 HA 備份的作業意外中斷（例如系統重新開機或程序被終止）。這台的應用沒有任何變更，請重新檢查。'
    return '轉換 HA 備份的作業意外中斷（例如系統重新開機或程序被終止）。這台的應用沒有任何變更，請重新開始匯入。'
