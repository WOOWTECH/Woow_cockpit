"""JSON command dispatcher for the Cockpit UI (CONTRACT section 7). Owner: E2.

`woowtech-cockpit-backup <command>`: request JSON on stdin (<= 1 MiB, strictly validated, unknown
keys rejected), exactly one JSON object on stdout, exit 0 (`{"ok": true, ...}`) or 1
(`{"ok": false, "error": {code, message, details}}`). Unexpected exceptions become
`internal-error` with a generic zh-TW message; the traceback goes to stderr (journal) only.
Key material is only ever accepted in the stdin field `key` and never echoed.
"""
import contextlib
import json
import os
import platform
import re
import secrets
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack

from . import flows, haapps, haissues, hastore
from . import jobs as jobmod
from . import version as engine_version
from .errors import BackupError
from .paths import Paths

MAX_STDIN = 1024 * 1024
BACKUP_ID_RE = re.compile(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
UPLOAD_ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z')
EXPORT_ID_RE = re.compile(r'x[0-9a-f]{16}\Z')
KEY_ID_RE = re.compile(r'[0-9A-F]{4}(?:-[0-9A-F]{4}){3}\Z')
APP_ID_RE = re.compile(r'[a-z0-9][a-z0-9-]{1,40}\Z')
SHA256_RE = re.compile(r'[0-9a-f]{64}\Z')
CONTROL_RE = re.compile(r'[\x00-\x1f\x7f-\x9f]')
GENERIC_ERROR = '發生未預期的內部錯誤，請查看系統日誌。'
STATUS_WORKERS = 8  # apps probed (and health-hinted) at the same time by `status`
ISSUES = {'restore.device-key': 'auto'}  # haissues: X-PF-03, FL-07 (D11)


# ---------------------------------------------------------------- request validation

def _bad(field, text):
    return BackupError('invalid-request', f'欄位 {field} {text}', field=field)


def v_backup_id(value, field):
    if not isinstance(value, str) or not BACKUP_ID_RE.fullmatch(value):
        raise _bad(field, '格式不正確。')
    return value


def v_job_id(value, field):
    if not jobmod.valid_job_id(value):
        raise _bad(field, '格式不正確。')
    return value


def v_upload_id(value, field):
    if not isinstance(value, str) or not UPLOAD_ID_RE.fullmatch(value):
        raise _bad(field, '格式不正確。')
    return value


def v_export_id(value, field):
    if not isinstance(value, str) or not EXPORT_ID_RE.fullmatch(value):
        raise _bad(field, '格式不正確。')
    return value


def v_ha_backup_id(value, field):
    if not hastore.valid_id(value):
        raise _bad(field, '格式不正確。')
    return value


HA_APP_IDS = haapps.APP_IDS  # the importers' catalog ids (haapps.IMPORTERS, in order)
HA_NODE_RE = re.compile(r'[A-Za-z0-9_.-]{1,64}@[A-Za-z0-9_.:-]{1,190}\Z')  # an Erlang node name (EMQX)


def v_ha_apps(value, field):
    if (not isinstance(value, list) or not 1 <= len(value) <= len(HA_APP_IDS) or len(set(map(str, value))) != len(value)
            or not all(isinstance(item, str) and item in HA_APP_IDS for item in value)):
        raise _bad(field, f'必須是 1 到 {len(HA_APP_IDS)} 個不重複的應用 ID（{"、".join(HA_APP_IDS)}）的陣列。')
    return value


def v_ha_database(value, field):
    from .haimport import valid_database
    if not valid_database(value):
        raise _bad(field, '不是有效的資料庫名稱。')
    return value


def v_acknowledged(value, field):
    """{app id or `_shared`: [confirmation keys]} (CONTRACT section 7 HaIssue): at most 80 keys each."""
    if not isinstance(value, dict) or len(value) > 33:
        raise _bad(field, '必須是 JSON 物件（應用 ID 對應確認鍵的陣列）。')
    for app_id, keys in value.items():
        if app_id != haissues.SHARED and not APP_ID_RE.fullmatch(app_id):
            raise _bad(field, '含有格式不正確的應用 ID。')
        if (not isinstance(keys, list) or len(keys) > haissues.MAX_ACKNOWLEDGED
                or not all(haissues.valid_key(key) for key in keys) or len(set(keys)) != len(keys)):
            raise _bad(field, f'的確認鍵必須是最多 {haissues.MAX_ACKNOWLEDGED} 個不重複確認鍵的陣列。')
    return value


def v_ha_choices(value, field):
    """{app id: {'addon'|'database'|'node': value}}: what the customer chose (only what the importer knows)."""
    if not isinstance(value, dict):
        raise _bad(field, '必須是 JSON 物件。')
    for app_id, kinds in value.items():
        if app_id not in HA_APP_IDS or not isinstance(kinds, dict):
            raise _bad(field, '含有不能從 HA 備份匯入的應用。')
        for kind, item in kinds.items():
            if kind not in haapps.get(app_id).choices:
                raise _bad(field, f'含有「{app_id}」不支援的選項。')
            if kind == 'database':
                v_ha_database(item, f'{field}.{app_id}.database')
            elif kind == 'addon':
                if not isinstance(item, str) or not hastore.ADDON_SLUG_RE.fullmatch(item):
                    raise _bad(f'{field}.{app_id}.addon', '格式不正確。')
            elif not isinstance(item, str) or not HA_NODE_RE.fullmatch(item):
                raise _bad(f'{field}.{app_id}.{kind}', '格式不正確。')
    return value


def v_key(value, field):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096 or '\x00' in value:
        raise _bad(field, '不是有效的金鑰。')
    return value


def v_bool(value, field):
    if not isinstance(value, bool):
        raise _bad(field, '必須是 true 或 false。')
    return value


def v_true(value, field):
    if value is not True:
        raise _bad(field, '必須為 true（需要明確確認）。')
    return value


def v_apps(value, field):
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise _bad(field, '必須是 1 到 32 個應用 ID 的陣列。')
    for item in value:
        if not isinstance(item, str) or not APP_ID_RE.fullmatch(item):
            raise _bad(field, '含有格式不正確的應用 ID。')
    if len(set(value)) != len(value):
        raise _bad(field, '含有重複的應用 ID。')
    return value


def v_note(value, field):
    if not isinstance(value, str) or len(value) > 200 or CONTROL_RE.search(value):
        raise _bad(field, '必須是 200 字以內且不含控制字元的文字。')
    return value


def v_request_id(value, field):
    if not isinstance(value, str) or not jobmod.REQUEST_ID_RE.fullmatch(value):
        raise _bad(field, '格式不正確（8–128 個英數字元）。')
    return value


def v_key_id(value, field):
    if not isinstance(value, str) or not KEY_ID_RE.fullmatch(value):
        raise _bad(field, '格式不正確。')
    return value


def v_filename(value, field):
    if (not isinstance(value, str) or not 1 <= len(value) <= 255 or CONTROL_RE.search(value)
            or '/' in value or '\\' in value):
        raise _bad(field, '不是有效的檔名。')
    return value


def v_size(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2 ** 44:
        raise _bad(field, '必須是正整數。')
    return value


def v_owner(value, field):
    from .catalog import OWNER_RE
    if not isinstance(value, str) or not OWNER_RE.fullmatch(value) or value == 'root':
        raise _bad(field, '格式不正確（不可為 root）。')
    return value


def v_app_id(value, field):
    if not isinstance(value, str) or not APP_ID_RE.fullmatch(value):
        raise _bad(field, '格式不正確。')
    return value


def v_object(value, field):
    if not isinstance(value, dict):
        raise _bad(field, '必須是 JSON 物件。')
    return value


def v_sha256_or_null(value, field):
    if value is not None and (not isinstance(value, str) or not SHA256_RE.fullmatch(value)):
        raise _bad(field, '必須是 64 個小寫十六進位字元或 null。')
    return value


def v_backup_ids(value, field):
    from .retention import MAX_IDS
    if (not isinstance(value, list) or len(value) > MAX_IDS
            or any(not isinstance(item, str) or not BACKUP_ID_RE.fullmatch(item) for item in value)
            or len(set(value)) != len(value)):
        raise _bad(field, f'必須是最多 {MAX_IDS} 個不重複備份 ID 的陣列。')
    return value


REQUIRED, OPTIONAL = True, False
SPECS = {
    'inspect': {'backup_id': (REQUIRED, v_backup_id), 'key': (OPTIONAL, v_key), 'save_key': (OPTIONAL, v_bool)},
    'key-confirm': {'key_id': (REQUIRED, v_key_id)},
    'key-import': {'key': (REQUIRED, v_key)},
    'backup-start': {'apps': (REQUIRED, v_apps), 'include_images': (OPTIONAL, v_bool), 'note': (OPTIONAL, v_note),
                     'request_id': (REQUIRED, v_request_id), 'encrypt': (OPTIONAL, v_bool),
                     'acknowledge_plaintext': (OPTIONAL, v_bool)},
    'verify-start': {'backup_id': (REQUIRED, v_backup_id), 'request_id': (REQUIRED, v_request_id),
                     'key': (OPTIONAL, v_key)},
    'restore-start': {'backup_id': (REQUIRED, v_backup_id), 'apps': (REQUIRED, v_apps),
                      'request_id': (REQUIRED, v_request_id), 'confirm': (REQUIRED, v_true),
                      'key': (OPTIONAL, v_key), 'save_key': (OPTIONAL, v_bool),
                      'allow_no_safety': (OPTIONAL, v_bool), 'accept_unauthenticated': (OPTIONAL, v_bool),
                      'acknowledged': (OPTIONAL, v_acknowledged)},
    'job-status': {'job_id': (REQUIRED, v_job_id)},
    'job-cancel': {'job_id': (REQUIRED, v_job_id)},
    'delete': {'backup_id': (REQUIRED, v_backup_id)},
    'upload-begin': {'filename': (REQUIRED, v_filename), 'size': (REQUIRED, v_size)},
    'upload-finish': {'upload_id': (REQUIRED, v_upload_id)},
    'upload-abort': {'upload_id': (REQUIRED, v_upload_id)},
    'download-info': {'backup_id': (REQUIRED, v_backup_id)},
    'settings-set': {'encrypt_by_default': (REQUIRED, v_bool), 'acknowledge_plaintext': (OPTIONAL, v_bool)},
    'export-start': {'backup_id': (REQUIRED, v_backup_id), 'request_id': (REQUIRED, v_request_id),
                     'confirm': (REQUIRED, v_true), 'key': (OPTIONAL, v_key)},
    'export-info': {'export_id': (REQUIRED, v_export_id)},
    'export-delete': {'export_id': (REQUIRED, v_export_id)},
    # 應用設定 and 清理備份 (CONTRACT section 4 "Catalog drafts" / "Installing and removing entries", 7, 8).
    'catalog-suggest': {'owner': (OPTIONAL, v_owner)},
    'catalog-install': {'entry': (REQUIRED, v_object), 'confirm': (OPTIONAL, v_bool),
                        'expected_sha256': (OPTIONAL, v_sha256_or_null)},
    'catalog-remove': {'id': (REQUIRED, v_app_id), 'confirm': (OPTIONAL, v_bool),
                       'expected_sha256': (OPTIONAL, v_sha256_or_null)},
    'retention-plan': {'policy': (OPTIONAL, v_object)},
    'retention-apply': {'confirm': (REQUIRED, v_true), 'backup_ids': (REQUIRED, v_backup_ids),
                        'policy': (OPTIONAL, v_object)},
    # 排程備份 (CONTRACT sections 7, 8 "Scheduled backups"); `schedule` is validated deeply by schedule.validate.
    'schedule-set': {'schedule': (REQUIRED, v_object), 'confirm': (OPTIONAL, v_bool)},
    'schedule-run-now': {'request_id': (REQUIRED, v_request_id)},
    # Home Assistant backups (CONTRACT section 7, branch feat/ha-import): uploaded HA files live in ha-backups/.
    'ha-delete': {'ha_backup_id': (REQUIRED, v_ha_backup_id), 'confirm': (REQUIRED, v_true)},
    # The HA import jobs (part B): `key` is the HA key exactly as typed (never trimmed or normalised).
    'ha-check-start': {'ha_backup_id': (REQUIRED, v_ha_backup_id), 'apps': (REQUIRED, v_ha_apps),
                       'request_id': (REQUIRED, v_request_id), 'key': (OPTIONAL, v_key),
                       'choices': (OPTIONAL, v_ha_choices)},
    'ha-convert-start': {'ha_backup_id': (REQUIRED, v_ha_backup_id), 'apps': (REQUIRED, v_ha_apps),
                         'test_mode': (REQUIRED, v_bool), 'request_id': (REQUIRED, v_request_id),
                         'confirm': (REQUIRED, v_true), 'odoo_database': (OPTIONAL, v_ha_database),
                         'key': (OPTIONAL, v_key), 'acknowledged': (OPTIONAL, v_acknowledged),
                         'choices': (OPTIONAL, v_ha_choices)},
    # The whole import of the selected apps, one after the other (HAOS parity; CONTRACT section 7).
    'ha-import-start': {'ha_backup_id': (REQUIRED, v_ha_backup_id), 'apps': (REQUIRED, v_ha_apps),
                        'request_id': (REQUIRED, v_request_id), 'confirm': (REQUIRED, v_true),
                        'test_mode': (REQUIRED, v_bool), 'then_restore': (REQUIRED, v_bool),
                        'overwrite': (OPTIONAL, v_bool), 'acknowledged': (OPTIONAL, v_acknowledged),
                        'choices': (OPTIONAL, v_ha_choices), 'check_job_id': (OPTIONAL, v_job_id),
                        'key': (OPTIONAL, v_key)},
}
NO_INPUT = frozenset({'status', 'list', 'key-init', 'key-kit', 'jobs', 'settings-get', 'schedule-get'})


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _no_constants(name):
    raise ValueError(f'unsupported constant {name}')


def _valid_text(value):
    """False when any string (or key) holds a lone surrogate (JSON "\\ud800"), which is not text."""
    if isinstance(value, str):
        try:
            value.encode('utf-8')
        except UnicodeEncodeError:
            return False
        return True
    if isinstance(value, dict):
        return all(_valid_text(key) and _valid_text(item) for key, item in value.items())
    if isinstance(value, list):
        return all(_valid_text(item) for item in value)
    return True


def read_request(stream):
    raw = stream.buffer.read(MAX_STDIN + 1) if hasattr(stream, 'buffer') else stream.read(MAX_STDIN + 1)
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    if len(raw) > MAX_STDIN:
        raise BackupError('invalid-request', '請求內容過大（上限 1 MiB）。')
    if not raw.strip():
        raise BackupError('invalid-request', '缺少請求內容。')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise BackupError('invalid-request', '請求內容不是有效的 JSON。') from None
    if not isinstance(data, dict):
        raise BackupError('invalid-request', '請求內容必須是 JSON 物件。')
    if not _valid_text(data):
        raise BackupError('invalid-request', '請求內容含有無效的文字。')
    return data


def validate(command, data):
    spec = SPECS[command]
    unknown = sorted(set(data) - set(spec))
    if unknown:
        raise BackupError('invalid-request', f'請求含有不支援的欄位：{", ".join(k[:40] for k in unknown[:5])}。',
                          fields=[k[:40] for k in unknown[:5]])
    for field, (required, check) in spec.items():
        if field in data:
            check(data[field], field)
        elif required:
            raise _bad(field, '為必填。')
    if data.get('save_key') and 'key' not in data:
        raise _bad('save_key', '需要同時提供 key。')
    if command == 'ha-import-start':
        if data['then_restore'] and data.get('overwrite') is not True:
            raise _bad('overwrite', '必須為 true（匯入會取代這台這些應用現在的資料，需要明確確認）。')
        for field, also in (('acknowledged', {haissues.SHARED}), ('choices', set())):
            if set(data.get(field) or {}) - set(data['apps']) - also:
                raise _bad(field, '含有沒有選擇的應用。')
    if command in ('catalog-install', 'catalog-remove') and data.get('confirm') and 'expected_sha256' not in data:
        # A confirmed change names the entry it previewed (null: none was installed).
        raise _bad('expected_sha256', '確認時為必填（預覽回傳的 expected_sha256，沒有安裝的設定時為 null）。')
    return data


# ---------------------------------------------------------------- services

class Services:
    """Dependencies of the commands; tests replace `deps`, `launcher`, `unit_active`, `clock` and `timer`."""

    def __init__(self, paths, *, deps=None, launcher=None, unit_active=None, trusted_uid=0, clock=None, timer=None,
                 sweep_temp=None):
        self.paths = paths
        self.sweep_temp = sweep_temp  # (job_id, owners) -> [problems]; None: haimport.sweep_job (recovery)
        self._deps = deps
        self.launcher = launcher
        self.unit_active = unit_active
        self.trusted_uid = trusted_uid  # owner of /etc/woowtech-cockpit/backup/settings.json (root; tests: themselves)
        self.clock = clock  # () -> schedule.Env; the device's clock, zone (/etc/localtime) and uptime otherwise
        self.timer = timer  # () -> {enabled, active} of the schedule's timer; `systemctl show` otherwise
        self._catalog = None

    @property
    def deps(self):
        if self._deps is None:
            self._deps = flows.default_deps(self.paths)
        return self._deps

    @property
    def storage(self):
        return self.deps.storage

    @property
    def keys(self):
        return self.deps.keys

    @property
    def ha_store(self):
        """Uploaded Home Assistant backups (hastore.HaStore of the storage, or of `paths` for a storage without one)."""
        store = getattr(self.storage, 'ha_store', None)
        return store if store is not None else hastore.HaStore(self.paths)

    @property
    def archive(self):
        return self.deps.archive

    def catalog(self):
        if self._catalog is None:
            self._catalog = self.deps.load_catalog()
        return self._catalog

    def adapter(self, app):
        return self.deps.adapter_factory(app, log=lambda _message: None, phase=None, checkpoint=None)

    def restart_writers(self, stopped):
        """Restart writer units an interrupted backup left stopped; returns the units that failed."""
        return flows.restart_writers(self.deps, stopped)

    def cleanup_fresh(self, app_ids):
        """Remove the unfinished fresh deployments a dead restore left; returns zh-TW problems."""
        return flows.remove_fresh_apps(self.deps, app_ids)

    def settle_dirs(self, job_id, app_ids):
        """Settle the host-directory siblings a dead restore left; returns zh-TW notes."""
        return flows.settle_dirs(self.deps, job_id, app_ids)

    def package_safety(self, job_id):
        """Package the pre-restore copy a restore kept (`pending/<job>/`) into its safety backup; returns (backup id,
        problem). Its log lines go to that job's log."""
        store = jobmod.JobStore(self.paths)
        return flows.package_pending_safety(self.paths, self.deps, job_id,
                                            log=lambda message: store.append_log(job_id, message))

    def recover(self):
        changed = jobmod.recover_interrupted(self.paths, unit_active=self.unit_active,
                                             restart_writers=self.restart_writers, cleanup_fresh=self.cleanup_fresh,
                                             settle_dirs=self.settle_dirs, package_safety=self.package_safety,
                                             sweep_temp=self.sweep_temp)
        # Every recovery pass also deletes expired unencrypted copies (after a reboot the transient timer is gone;
        # review L1).
        self.cleanup_exports()
        return changed

    def start(self, job_type, params, request_id, **kwargs):
        return jobmod.start_job(self.paths, job_type, params, request_id, launcher=self.launcher,
                                unit_active=self.unit_active, restart_writers=self.restart_writers,
                                cleanup_fresh=self.cleanup_fresh, settle_dirs=self.settle_dirs,
                                package_safety=self.package_safety, sweep_temp=self.sweep_temp, **kwargs)

    def key_ids(self):
        return {info.key_id for info in self.keys.identities()}

    def settings_view(self):
        from . import settings
        return settings.view(self.paths, trusted_uid=self.trusted_uid)

    def encrypt_by_default(self):
        read = getattr(self.deps, 'encrypt_by_default', None)
        if read is not None:
            return bool(read())
        from . import settings
        return settings.load(self.paths, trusted_uid=self.trusted_uid)[0]['encrypt_by_default']

    def audit(self, line):
        write = getattr(self.deps, 'audit', None)
        if write is None:
            from .catalog_admin import audit_log as write
        write(line)

    def journal(self, line, warning=False):
        """A schedule line for the journal: notice, or warning for failures (`deps.journal(line, warning)` or
        `deps.audit(line)` in tests)."""
        write = getattr(self.deps, 'journal', None)
        if write is not None:
            write(line, warning)
        elif getattr(self.deps, 'audit', None) is not None:
            self.deps.audit(line)
        else:
            from .schedule import journal
            journal(line, warning)

    # ------------------------------------------------------------ 排程備份

    def env(self):
        from . import schedule
        return self.clock() if self.clock is not None else schedule.system_env()

    def timer_view(self, env):
        """`timer` of the schedule views: {enabled, active, active_age (null when systemd cannot be asked),
        last_tick_age}."""
        from . import schedule
        try:
            if self.timer is not None:
                state = self.timer()
            else:  # a relocated layout (tests) has no timer of its own: unknown
                state = schedule.timer_state() if self.paths.base is None else {}
        except Exception:  # noqa: BLE001 - unknown, never a broken page
            traceback.print_exc(file=sys.stderr)
            state = {}
        return {'enabled': state.get('enabled'), 'active': state.get('active'), 'active_age': state.get('active_age'),
                'last_tick_age': schedule.last_tick_age(self.paths, env.now)}

    def schedule_settings(self):
        from . import schedule
        return schedule.load(self.paths, trusted_uid=self.trusted_uid)

    def scheduled_ids(self):
        """Ids of the scheduled backups (empty when the registry cannot be read; retention then protects them)."""
        from . import schedule
        return schedule.scheduled_ids(self.paths)[0]

    def job_record(self, job_id):
        try:
            return jobmod.JobStore(self.paths).get(job_id)
        except BackupError:
            return None

    def job_ended(self, job_id):
        """True when the job's record is readable and finished, or there is none (deleted with the oldest finished
        records); False while it is queued or running and when the record cannot be read (unknown is never ended)."""
        store = jobmod.JobStore(self.paths)
        try:
            return store.get(job_id).get('state') in jobmod.TERMINAL
        except BackupError:
            try:
                os.lstat(store.path(job_id))
            except FileNotFoundError:
                return True
            return False

    def backup_present(self, backup_id):
        """True while the backup's index or archive exists (listed or not): a registry entry stays that long."""
        present = getattr(self.storage, 'present', None)
        if present is not None:
            return bool(present(backup_id))
        return any(item.get('id') == backup_id for item in self.storage.list_backups())

    def cleanup_exports(self):
        """Delete expired unencrypted download copies (each status/list/export command does; CONTRACT section 8)."""
        cleanup = getattr(self.storage, 'cleanup_exports', None)
        if cleanup is None:
            return []
        try:
            removed = cleanup()
        except Exception:  # noqa: BLE001 - housekeeping never breaks the page; retried next time
            traceback.print_exc(file=sys.stderr)
            return []
        for export_id in removed:
            self.audit(f'export-unencrypted-deleted export={export_id} reason=expired')
        return removed


def _login_uid():
    from .catalog_admin import login_uid
    uid = login_uid()
    return '-' if uid is None else uid


def key_view(info):
    if info is None:
        return None
    return {'key_id': info.key_id, 'created': info.created, 'kit_confirmed': bool(info.kit_confirmed)}


def backup_view(meta, key_ids, scheduled=frozenset(), from_ha=None):
    """BackupMeta for the page: `format` (1|2), `encrypted`, `key_available` (always true without encryption),
    `unauthenticated` (an unencrypted upload: a restore needs `accept_unauthenticated`) and `scheduled` (a manual backup
    the schedule's registry lists: 排程備份; the index itself is unchanged); `from_ha` only for a manual backup converted
    from a Home Assistant backup (ha-imports.json; branch feat/ha-import)."""
    from .storage import unauthenticated
    view = dict(meta)
    view.setdefault('format', 1)
    view.setdefault('encrypted', True)
    view['key_available'] = (not view['encrypted']) or meta.get('key_id') in key_ids
    view['unauthenticated'] = unauthenticated(view)
    view['scheduled'] = view.get('type') == 'manual' and view.get('id') in scheduled
    origin = (from_ha or {}).get(view.get('id')) if view.get('type') == 'manual' else None
    if origin is not None:
        view['from_ha'] = origin
    return view


def ha_import_views(svc):
    """{backup id: from_ha} of converted backups ({} when ha-imports.json cannot be read)."""
    from . import haimport
    try:
        return haimport.from_ha_views(svc.paths)
    except Exception:  # noqa: BLE001 - never breaks the list
        traceback.print_exc(file=sys.stderr)
        return {}


def tool_version(paths):
    lib = paths.lib
    return engine_version(lib) if os.path.exists(os.path.join(str(lib), 'VERSION')) else engine_version()


def storage_usage(storage, backups):
    if hasattr(storage, 'usage'):
        return storage.usage()
    return {'path': '', 'free_bytes': storage.free_bytes(), 'total_bytes': 0,
            'backups_bytes': sum(b.get('size', 0) for b in backups), 'backup_count': len(backups)}


def app_view(svc, app, backups, converted=frozenset()):
    try:
        adapter = svc.adapter(app)
        info = adapter.probe()
        if info.get('state') == 'running' and hasattr(adapter, 'health_hint'):
            # Units can be active while the app is broken (lab H5): one quick health request.
            hint = adapter.health_hint()
            if hint:
                info = dict(info, state='error', problems=[*info.get('problems', []), hint])
    except BackupError as error:
        info = {'deployed': False, 'state': 'error', 'units': [{'name': u, 'active': False} for u in app.units],
                'problems': [error.message]}
    except Exception:  # noqa: BLE001 - one broken app must not break the whole page
        traceback.print_exc(file=sys.stderr)
        info = {'deployed': False, 'state': 'error', 'units': [{'name': u, 'active': False} for u in app.units],
                'problems': ['無法讀取應用狀態。']}
    # A backup converted from an HA backup holds HA's data, not this device's: never this app's "latest backup"
    # (review C-04).
    last = next(({'id': b['id'], 'created': b.get('created')} for b in backups
                 if b.get('type') in ('manual', 'safety') and b.get('id') not in converted
                 and app.id in {a.get('id') for a in b.get('apps') or []}), None)
    return {'id': app.id, 'name': app.name, 'description': app.description, 'owner': app.owner,
            'adapter': app.adapter, 'deployed': bool(info['deployed']), 'state': info['state'],
            'units': info['units'], 'last_backup': last, 'problems': list(info['problems'])}


def app_views(svc, apps, backups):
    """app_view of every app, several at a time: each quick health request is bounded (review finding HD-07), and
    running them side by side keeps `status` within the page's timeout with many apps."""
    apps = list(apps)
    converted = frozenset(ha_import_views(svc))
    if len(apps) <= 1:
        return [app_view(svc, app, backups, converted) for app in apps]
    with ThreadPoolExecutor(max_workers=min(STATUS_WORKERS, len(apps)), thread_name_prefix='woowbackup-status') as pool:
        return list(pool.map(lambda app: app_view(svc, app, backups, converted), apps))


def _postgres_summary(item):
    """One `postgres[]` item of a ManifestSummary: `scope` (database|instance); an instance also names its databases
    (name, owner) and how many roles it holds (never role names' passwords)."""
    summary = {'id': item['id'], 'database': item['database'], 'major': item['major'],
               'scope': item.get('scope', 'database')}
    if summary['scope'] == 'instance':
        summary['databases'] = [{'name': db['name'], 'owner': db.get('owner')} for db in item.get('databases') or []]
        summary['roles_count'] = len(item.get('roles') or [])
    return summary


def manifest_summary(manifest, catalog=None):
    """ManifestSummary (CONTRACT section 7). `data_dirs[]`: host directories in the backup, `path` relative to the
    owner's home, `size` of their tar entry, `label` from this device's catalog when it declares the same path."""
    sizes = {e.get('path'): e.get('size', 0) for e in manifest.get('entries') or [] if isinstance(e, dict)}
    apps = []
    for app in manifest.get('apps') or []:
        local = (catalog or {}).get(app['id'])
        labels = {d['path']: d.get('label', '') for d in getattr(local, 'data_dirs', ()) or ()}
        apps.append({
            'id': app['id'], 'name': app['name'], 'adapter': app['adapter'],
            'owner': {'name': app['owner']['name'], 'uid': app['owner']['uid']},
            'images': [{'ref': img['ref'], 'included': 'entry' in img} for img in app.get('images') or []],
            'postgres': [_postgres_summary(p) for p in app.get('postgres') or []],
            'volumes': [{'name': v['name']} for v in app.get('volumes') or []],
            'data_dirs': [{'path': d['path'], 'size': int(sizes.get(d['entry']) or 0), 'label': labels.get(d['path'], '')}
                          for d in app.get('data_dirs') or []],
            'secrets_count': len(app.get('secrets') or []), 'config_files_count': len(app.get('config_files') or []),
            'settings_included': isinstance(app.get('catalog_entry'), dict),
            'verify_snapshot': app.get('verify_snapshot') or {},
            # Built-in data verification recorded at backup time (CONTRACT section 7): what each digest covers.
            'verify_digests': [{'id': d['id'], 'type': d['type'], 'target': d['target'], 'summary': d['summary']}
                               for d in app.get('verify_digests') or []],
        })
    return {'backup_id': manifest['backup_id'], 'created': manifest['created'], 'type': manifest['type'],
            'note': manifest['note'], 'tool': manifest['tool'], 'source': manifest['source'],
            'consistency': manifest['consistency'],
            'total_size': sum(int(e.get('size', 0)) for e in manifest.get('entries') or []), 'apps': apps,
            'format': int(manifest.get('format') or 1), 'encryption': manifest.get('encryption', 'age-x25519')}


UNAUTHENTICATED_MESSAGE = ('這份上傳的備份沒有加密，內容無法驗證：無法確認它來自你的設備，也無法確認檔案在設備以外沒有被修改過。'
                           '只有在確定檔案來源可信時才還原；確認還原時需要另外勾選這一點。')


RESTORE_KEY_CREATED = ('這台還沒有加密金鑰，開始還原時會自動建立，用來加密還原前備份；完成後請到「加密金鑰」下載並保存。')


def adapter_issues(adapter):
    """The haissues.Issue objects an adapter's preflight left in `restore_issues` ([] for an adapter without them)."""
    found = getattr(adapter, 'restore_issues', None)
    return list(found) if isinstance(found, (list, tuple)) else []


def build_preflight(svc, manifest, meta=None):
    plain = manifest.get('encryption') == 'none'
    checks = [{'id': 'archive', 'status': 'ok',
               'message': ('備份檔格式檢查通過（未加密）；還原前會再完整驗證全部內容。' if plain
                           else '備份檔格式與金鑰檢查通過；還原前會再完整驗證全部內容。')}]
    if meta is not None and backup_view(meta, set())['unauthenticated']:
        checks.append({'id': 'unauthenticated', 'status': 'warn', 'message': UNAUTHENTICATED_MESSAGE})
    total = sum(int(e.get('size', 0)) for e in manifest.get('entries') or [])
    free = int(svc.storage.free_bytes())
    required = total + int(svc.paths.reserve_bytes)
    if free < required:
        checks.append({'id': 'space', 'status': 'fail',
                       'message': f'這台設備空間不足以解開備份：需要約 {flows.human(required)}，可用 {flows.human(free)}。'})
    else:
        checks.append({'id': 'space', 'status': 'ok', 'message': f'這台設備空間足夠（可用 {flows.human(free)}）。'})
    source_arch = (manifest.get('source') or {}).get('arch')
    if source_arch and source_arch != platform.machine():
        checks.append({'id': 'arch', 'status': 'warn',
                       'message': f'備份來源的 CPU 架構（{source_arch}）與這台設備（{platform.machine()}）不同。'})
    catalog = svc.catalog()
    entry_sizes = {e.get('path'): e.get('size', 0) for e in manifest.get('entries') or []}
    device_key = svc.keys.device_key()
    safety_encrypted = svc.encrypt_by_default()  # safety backups follow the setting 預設加密備份
    apps = []
    for app_manifest in manifest.get('apps') or []:
        app = catalog.get(app_manifest['id'])
        # The settings the backup was made with (2026.11.15.2), for the page to offer for review and installation.
        carried = app_manifest.get('catalog_entry') if isinstance(app_manifest.get('catalog_entry'), dict) else None
        if app is None:
            # No settings here, or a settings file that could not be loaded (`problem`): never promise more than the
            # catalog's own review can give (review 2026-11-15: an account that does not exist stays missing).
            problem = catalog.problem_for(app_manifest['id']) if hasattr(catalog, 'problem_for') else None
            if carried is None:
                message = problem['message'] if problem else ('此設備沒有設定這個應用，無法還原。請先在「應用設定」安裝'
                                                              '建立這份備份時使用的應用設定（這份備份沒有附上設定）。')
            elif problem is None:
                message = '此設備沒有這個應用的應用設定。這份備份附有建立時的設定，可以審查並安裝；安裝後會重新檢查能否還原。'
            elif problem.get('code') == 'owner-missing':
                owner = carried.get('owner') if isinstance(carried.get('owner'), str) else '—'
                message = (problem['message'] + f'這份備份附有建立時的應用設定（擁有者帳號 {owner[:32]}）；這台設備要有'
                           '該帳號才能安裝。建立帳號後請重新檢查。')
            else:
                message = (problem['message'] + '這份備份附有建立時的應用設定，可以審查後用它取代無法載入的設定檔；'
                           '安裝後會重新檢查能否還原。')
            item = {'id': app_manifest['id'], 'name': app_manifest['name'], 'restorable': False, 'mode': 'fresh',
                    'checks': [{'id': f'{app_manifest["id"]}/catalog', 'status': 'fail', 'message': message}]}
            if carried is not None:
                item['settings'] = {'state': 'unloadable' if problem else 'missing', 'entry': carried}
            apps.append(item)
            continue
        adapter = svc.adapter(app)
        mode = 'fresh'
        try:
            mode = adapter.detect_mode()
            app_checks = adapter.preflight(app_manifest, mode=mode, entry_sizes=entry_sizes)
        except BackupError as error:
            app_checks = [{'id': f'{app.id}/probe', 'status': 'fail', 'message': error.message}]
        issues = adapter_issues(adapter)
        if mode == 'inplace' and device_key is None and safety_encrypted:
            # Created by restore-start (D11, X-PF-03): no reason to refuse.
            app_checks.append({'id': f'{app.id}/device-key', 'status': 'warn', 'message': RESTORE_KEY_CREATED})
            issues.append(haissues.Issue('restore.device-key', 'auto', RESTORE_KEY_CREATED))
        item = {'id': app.id, 'name': app.name, 'mode': mode, 'checks': app_checks,
                'restorable': not any(c['status'] == 'fail' for c in app_checks)}
        if issues:
            item['issues'] = haissues.views(app.id, issues)
        if carried is not None:
            item['settings'] = {'state': 'same' if carried == app.raw else 'different', 'entry': carried}
        apps.append(item)
    ok = not any(c['status'] == 'fail' for c in checks) and any(a['restorable'] for a in apps)
    return {'ok': ok, 'checks': checks, 'apps': apps}


# ---------------------------------------------------------------- commands

def apps_usage(svc, backups, catalog):
    """`status.storage.apps`: bytes of each app's backups with its keep-last policy (retention.app_usage); no I/O
    beyond the index listing and the policy file. A problem here never breaks the status page."""
    from . import retention
    try:
        policy, _problem = retention.load_policy(svc.paths, trusted_uid=svc.trusted_uid)
        converted, _readable = retention.converted_ids(svc.paths)
        return retention.app_usage(backups, catalog, policy, svc.scheduled_ids(), converted)['apps']
    except Exception:  # noqa: BLE001 - the overview simply falls back to its own computation
        traceback.print_exc(file=sys.stderr)
        return []


def schedule_summary(svc):
    """`status.schedule` (schedule.summary); null when it cannot be computed (never a broken status page)."""
    from . import schedule
    try:
        env = svc.env()
        settings, problem, saved = svc.schedule_settings()
        state, state_problem = schedule.read_state(svc.paths)
        return schedule.summary(settings, problem, saved, state, state_problem, env, svc.timer_view(env),
                                svc.job_record)
    except Exception:  # noqa: BLE001 - the overview simply shows no schedule
        traceback.print_exc(file=sys.stderr)
        return None


def ha_usage(svc):
    """`status.storage.ha_backups_bytes` / `ha_backup_count`: uploaded HA backups (ha-backups/, branch feat/ha-import;
    not part of `backups_bytes`)."""
    try:
        records = svc.ha_store.list()
    except Exception:  # noqa: BLE001 - the overview still works
        traceback.print_exc(file=sys.stderr)
        records = []
    return {'ha_backups_bytes': sum(int(rec['size']) for rec in records), 'ha_backup_count': len(records)}


def cmd_status(svc, _req):
    svc.recover()
    svc.cleanup_exports()
    catalog = svc.catalog()
    backups = svc.storage.list_backups()
    host = svc.deps.host_info()
    identities = list(svc.keys.identities())
    active = jobmod.active_job(svc.paths)
    storage = storage_usage(svc.storage, backups)
    storage['apps'] = apps_usage(svc, backups, catalog)
    storage.update(ha_usage(svc))
    return {
        'version': tool_version(svc.paths),
        'host': {key: host.get(key) for key in ('hostname', 'arch', 'os', 'podman')},
        'storage': storage,
        'key': key_view(svc.keys.device_key()),
        'imported_keys': [{'key_id': k.key_id, 'created': k.created} for k in identities if k.kind == 'imported'],
        'apps': app_views(svc, catalog.values(), backups),
        'active_job': jobmod.public_job(active) if active else None,
        'warnings': [p['message'] for p in getattr(catalog, 'problems', [])],
        'settings': svc.settings_view(),
        'schedule': schedule_summary(svc),
    }


def ha_backup_view(svc, rec):
    """HaBackupMeta: the HA record plus `importable_apps` / `other_addons` against this device's catalog."""
    try:
        catalog = svc.catalog()
    except Exception:  # noqa: BLE001 - the apps then show as not installed; never a broken listing
        traceback.print_exc(file=sys.stderr)
        catalog = None
    return hastore.view(rec, catalog)


def ha_backups_view(svc):
    """`list.ha_backups` (newest first); [] when the HA store cannot be read (the backups list still works)."""
    try:
        return [ha_backup_view(svc, rec) for rec in svc.ha_store.list()]
    except Exception:  # noqa: BLE001 - one unreadable store never breaks the backup list
        traceback.print_exc(file=sys.stderr)
        return []


def cmd_list(svc, _req):
    svc.cleanup_exports()
    ids = svc.key_ids()
    scheduled = svc.scheduled_ids()
    exports = getattr(svc.storage, 'list_exports', lambda: [])()
    origins = ha_import_views(svc)
    return {'backups': [backup_view(meta, ids, scheduled, origins) for meta in svc.storage.list_backups()],
            'exports': [{key: rec[key] for key in ('export_id', 'backup_id', 'filename', 'size', 'expires')}
                        for rec in exports],
            'ha_backups': ha_backups_view(svc)}


def _refuse_key_for_plain(header, req):
    if header.get('encryption') == 'none' and req.get('key') is not None:
        raise BackupError('invalid-request', '這份備份沒有加密，不需要金鑰。', field='key')


def _member_sizes(svc, path):
    """{app id: bytes of its application archive} of a format 2 file (structural facts of the outer tar)."""
    describe = getattr(svc.archive, 'describe', None)
    if describe is None:
        return {}
    try:
        doc = describe(path).get('doc') or {}
    except BackupError:
        return {}
    return {app['id']: app['size'] for app in doc.get('apps') or []}


def cmd_inspect(svc, req):
    backup_id = req['backup_id']
    meta = svc.storage.get(backup_id)
    path = svc.storage.archive_path(backup_id)
    header = svc.archive.read_header(path)
    _refuse_key_for_plain(header, req)
    key_text = req.get('key')
    identities = list(svc.keys.identities())
    with ExitStack() as stack:
        if header.get('encryption') == 'none':
            identities = []
        elif key_text is not None:
            # Only the supplied key: a key that cannot open this backup fails with wrong-key here, before
            # anything is saved (review finding F4: a wrong key used to be imported permanently).
            identities = [stack.enter_context(svc.keys.temp_identity(key_text, f'key-inspect-{secrets.token_hex(8)}'))]
        elif header.get('key_id') not in {info.key_id for info in identities}:
            raise BackupError('key-required', '此備份使用的金鑰不在這台設備，請輸入緊急金鑰。', key_id=header.get('key_id'))
        manifest = svc.archive.read_manifest(path, identities)
    if key_text is not None and req.get('save_key'):
        svc.keys.import_key(key_text)
    summary = manifest_summary(manifest, svc.catalog())
    preflight = build_preflight(svc, manifest, meta)
    sizes = _member_sizes(svc, path) if int(manifest.get('format') or 1) == 2 else {}
    for app in summary['apps']:
        if app['id'] in sizes:
            app['archive_size'] = int(sizes[app['id']])
    meta = svc.storage.update(
        backup_id, created=manifest['created'], note=manifest['note'],
        apps=[dict({'id': a['id'], 'name': a['name']}, **({'size': int(sizes[a['id']])} if a['id'] in sizes else {}))
              for a in manifest['apps']],
        include_images=any('entry' in img for a in manifest['apps'] for img in a.get('images') or []),
        source={'hostname': manifest['source']['hostname']}, inspected=True)
    # `from_ha` exactly like `list` (review P-01): the page replaces the listed backup with this one.
    return {'backup': backup_view(meta, svc.key_ids(), svc.scheduled_ids(), ha_import_views(svc)), 'manifest': summary,
            'preflight': preflight}


def cmd_key_init(svc, _req):
    info, created = svc.keys.ensure_device_key()
    return {'key': key_view(info), 'created': bool(created)}


def cmd_key_kit(svc, _req):
    info = svc.keys.device_key()
    if info is None:
        raise BackupError('no-device-key', '這台設備尚未建立加密金鑰。')
    content = svc.keys.kit_text()
    filename = svc.keys.kit_filename() if hasattr(svc.keys, 'kit_filename') else f'woowtech-backup-key-{info.key_id}.txt'
    return {'key_id': info.key_id, 'filename': filename, 'content': content}


def cmd_key_confirm(svc, req):
    svc.keys.confirm_kit(req['key_id'])
    return {}


def cmd_key_import(svc, req):
    info = svc.keys.import_key(req['key'])
    return {'key': {'key_id': info.key_id, 'created': info.created}}


def cmd_backup_start(svc, req):
    """`encrypt` (加密此備份) defaults to the device setting 預設加密備份. An unencrypted backup needs no device key;
    while the setting is on, leaving one unencrypted needs `acknowledge_plaintext` (settings.PLAINTEXT_WARNING)."""
    flows.resolve_apps(svc.catalog(), req['apps'])
    default = svc.encrypt_by_default()
    encrypt = req.get('encrypt', default)
    if encrypt and svc.keys.device_key() is None:
        raise BackupError('no-device-key', '這台設備尚未建立加密金鑰，請先完成金鑰設定。')
    if not encrypt and default and req.get('acknowledge_plaintext') is not True:
        from .settings import PLAINTEXT_WARNING
        raise BackupError('invalid-request', f'建立未加密的備份前必須確認風險：{PLAINTEXT_WARNING}',
                          field='acknowledge_plaintext')
    params = {'apps': list(req['apps']), 'include_images': bool(req.get('include_images', False)),
              'note': req.get('note', ''), 'encrypt': bool(encrypt)}
    return svc.start('backup', params, req['request_id'])


def cmd_verify_start(svc, req):
    svc.storage.get(req['backup_id'])
    _refuse_key_for_plain(svc.archive.read_header(svc.storage.archive_path(req['backup_id'])), req)
    params = {'backup_id': req['backup_id'], 'key_provided': 'key' in req}
    return svc.start('verify', params, req['request_id'], key_text=req.get('key'))


def cmd_restore_start(svc, req):
    meta = svc.storage.get(req['backup_id'])
    flows.resolve_apps(svc.catalog(), req['apps'])
    header = svc.archive.read_header(svc.storage.archive_path(req['backup_id']))
    _refuse_key_for_plain(header, req)
    if backup_view(meta, set())['unauthenticated'] and req.get('accept_unauthenticated') is not True:
        raise BackupError('invalid-request', UNAUTHENTICATED_MESSAGE, field='accept_unauthenticated')
    key_text = req.get('key')
    if key_text is not None and req.get('save_key'):
        # Saved only after it opened this backup (review finding F4).
        path = svc.storage.archive_path(req['backup_id'])
        with svc.keys.temp_identity(key_text, f'key-check-{secrets.token_hex(8)}') as identity:
            svc.archive.read_manifest(path, [identity])
        svc.keys.import_key(key_text)
        key_text = None
    confirm_restore(svc, req, header, key_text)
    created = ensure_key(svc, 'restore') if _needs_safety_key(svc, req['apps']) else False
    params = {'backup_id': req['backup_id'], 'apps': list(req['apps']), 'key_provided': key_text is not None}
    if req.get('allow_no_safety'):
        params['allow_no_safety'] = True
    if req.get('accept_unauthenticated'):
        params['accept_unauthenticated'] = True
    acknowledged = {app_id: list(keys) for app_id, keys in (req.get('acknowledged') or {}).items() if keys}
    if acknowledged:
        params['acknowledged'] = acknowledged
    return dict(svc.start('restore', params, req['request_id'], key_text=key_text), key_created=created)


def _needs_safety_key(svc, app_ids):
    """The restore is going to encrypt a pre-restore copy and this device has no key yet (FL-07, X-PF-03): an app that
    is there is restored in place. One that cannot be asked counts as there (the job finds out)."""
    if not svc.encrypt_by_default() or svc.keys.device_key() is not None:
        return False
    catalog = svc.catalog()
    for app_id in app_ids:
        try:
            if svc.adapter(catalog.get(app_id)).detect_mode() == 'inplace':
                return True
        except Exception:  # noqa: BLE001 - the job's own preflight says what is wrong
            traceback.print_exc(file=sys.stderr)
            return True
    return False


def confirm_restore(svc, req, header, key_text):
    """Refuses a restore whose preflight has lines to confirm that the request does not confirm (`confirmation-required`,
    `details.apps`; nothing started). Only adapters that report such lines (`restore_issues`, a class attribute) are
    asked; one that cannot be made is the job's to report."""
    adapters = {}
    for app in flows.resolve_apps(svc.catalog(), req['apps']):
        with contextlib.suppress(BackupError):
            adapter = svc.adapter(app)
            if getattr(type(adapter), 'restore_issues', None) is not None:
                adapters[app.id] = adapter
    if not adapters:
        return
    path = svc.storage.archive_path(req['backup_id'])
    with ExitStack() as stack:
        identities = list(svc.keys.identities())
        if header.get('encryption') == 'none':
            identities = []
        elif key_text is not None:
            identities = [stack.enter_context(svc.keys.temp_identity(key_text, f'key-check-{secrets.token_hex(8)}'))]
        manifest = svc.archive.read_manifest(path, identities)
    sizes = {e.get('path'): e.get('size', 0) for e in manifest.get('entries') or []}
    missing = {}
    for app_manifest in manifest.get('apps') or []:
        adapter = adapters.get(app_manifest['id'])
        if adapter is None:
            continue
        adapter.preflight(app_manifest, mode=adapter.detect_mode(), entry_sizes=sizes)
        left = haissues.missing(app_manifest['id'], adapter_issues(adapter),
                                (req.get('acknowledged') or {}).get(app_manifest['id']))
        if left:
            missing[app_manifest['id']] = left
    if missing:
        names = '、'.join(haissues.clean(svc.catalog().get(app_id).name, 60) for app_id in missing)
        raise haissues.confirmation_required(missing, f'還原 {names} 前還有事情要確認。')


def cmd_job_status(svc, req):
    svc.recover()
    store = jobmod.JobStore(svc.paths)
    record = store.get(req['job_id'])
    return {'job': jobmod.public_job(record), 'log': store.read_log(req['job_id'], 200)}


def cmd_jobs(svc, _req):
    """`jobs` (≤ 50, newest first) and `schedule_events`: the schedule's recent events (slots that did not run, waits,
    results) with their slots in device time, [] when its state cannot be read."""
    from . import schedule
    svc.recover()
    state, _problem = schedule.read_state(svc.paths)
    try:
        zone = svc.env().zone
    except Exception:  # noqa: BLE001 - the activity list never fails over the zone; the events then have no local times
        traceback.print_exc(file=sys.stderr)
        zone = None
    return {'jobs': [jobmod.public_job(r) for r in jobmod.JobStore(svc.paths).list(50)],
            'schedule_events': schedule.events_view(state, zone)}


def cmd_job_cancel(svc, req):
    return jobmod.cancel_job(svc.paths, req['job_id'])


def cmd_delete(svc, req):
    """Refuses (busy) while a queued or running job uses the backup: as its source, as the safety backup a
    running restore just took, or any safety backup while a restore runs (it may be its rollback source;
    review finding CR-08). Checked under the start lock, so no job can start in between."""
    backup_id = req['backup_id']
    svc.recover()
    with jobmod.start_lock(svc.paths):
        meta = svc.storage.get(backup_id)
        for record in jobmod.JobStore(svc.paths).list(limit=None):
            if record.get('state') not in jobmod.ACTIVE:
                continue
            params = record.get('params') or {}
            if backup_id in (params.get('backup_id'), record.get('safety_backup_id')):
                raise BackupError('busy', '此備份正被進行中的作業使用，請等作業完成後再刪除。', job_id=record['id'])
            if meta.get('type') == 'safety' and record.get('type') == 'restore':
                raise BackupError('busy', '還原作業進行中時不能刪除還原前備份（還原失敗時可能需要它來自動回復），'
                                          '請等作業完成後再刪除。', job_id=record['id'])
        svc.storage.delete(backup_id)
    if meta.get('type') == 'manual':
        from . import haimport
        with contextlib.suppress(Exception):  # a converted backup's origin row goes with it (ha-imports.json)
            haimport.forget(svc.paths, backup_id)
    # Every deletion is journaled, like retention's (review L6).
    svc.audit(f'backup-delete backup={backup_id} type={meta.get("type")} '
              f'encrypted={"false" if meta.get("encrypted") is False else "true"} loginuid={_login_uid()}')
    return {}


def cmd_upload_begin(svc, req):
    info = svc.storage.begin_upload(req['filename'], req['size'])
    return {'upload_id': info['upload_id'], 'path': str(info['path']), 'max_size': int(info['max_size'])}


def cmd_upload_finish(svc, req):
    """`{backup}` for a Cockpit backup, `{ha_backup}` for a Home Assistant backup (stored in ha-backups/)."""
    meta = svc.storage.finish_upload(req['upload_id'])
    if hastore.is_record(meta):
        return {'ha_backup': ha_backup_view(svc, meta)}
    return {'backup': backup_view(meta, svc.key_ids(), svc.scheduled_ids())}


def cmd_ha_delete(svc, req):
    """Delete an uploaded HA backup. Refuses (busy) while a queued or running job reads it (`params.ha_backup_id`),
    checked under the start lock like `delete`; journaled."""
    ha_id = req['ha_backup_id']
    svc.recover()
    with jobmod.start_lock(svc.paths):
        svc.ha_store.get(ha_id)
        for record in jobmod.JobStore(svc.paths).list(limit=None):
            if record.get('state') in jobmod.ACTIVE and (record.get('params') or {}).get('ha_backup_id') == ha_id:
                raise BackupError('busy', '這份 HA 備份正被進行中的作業使用，請等作業完成後再刪除。', job_id=record['id'])
        svc.ha_store.delete(ha_id)
    svc.audit(f'ha-backup-delete ha_backup={ha_id} loginuid={_login_uid()}')
    return {}


def ensure_key(svc, reason):
    """True when the device key was created just now (D11: HAOS restores without a key of one's own, so an import or a
    restore that encrypts something creates it; the page then asks to download it until that is confirmed)."""
    if svc.keys.device_key() is not None:
        return False
    try:
        info, created = svc.keys.ensure_device_key()
    except (BackupError, OSError) as error:
        raise BackupError('no-device-key', '無法自動建立這台的加密金鑰，請到「加密金鑰」建立後再試一次。') from error
    if created:
        svc.audit(f'device-key-created key_id={info.key_id} reason={reason} loginuid={_login_uid()}')
    return bool(created)


def _ha_selection(svc, req):
    """(record, the key to hand to the job or None, selected apps the backup holds, selected apps it does not hold) of
    an HA import request. The key is checked before a job starts against every encrypted member the selection reads,
    the share folder included for an importer that reads it (KEY-16): key-required, or wrong-key when it opens none of
    them, both before any plaintext. A selection the backup holds nothing of is invalid-request; an app it does not hold
    is only left out (HA-03, X-CLI-03)."""
    from . import habackup, haimport, hasecuretar
    rec = svc.ha_store.get(req['ha_backup_id'])
    slugs = {}
    for addon in rec['addons']:
        slugs.setdefault(hastore.addon_suffix(addon['slug']), []).append(addon)
    present = [app_id for app_id in req['apps'] if haimport.APPS[app_id] in slugs]
    missing = [app_id for app_id in req['apps'] if app_id not in present]
    if not present:
        raise BackupError('invalid-request', f'這份 HA 備份沒有可以匯入「{missing[0]}」的附加元件。', field='apps',
                          app=missing[0])
    key = req.get('key')
    share = 'share' in rec['folders'] and any(haapps.get(app_id).needs_share for app_id in present)
    if not share and not any(addon['encrypted'] for app_id in present for addon in slugs[haimport.APPS[app_id]]):
        return rec, None, present, missing  # nothing to decrypt: the key is not kept
    choices = req.get('choices') or {}
    with habackup.open_backup(svc.ha_store.file_path(rec['id'])) as backup:
        wanted = []
        for app_id in present:
            members = haimport.addon_members(backup.layout, haimport.APPS[app_id])
            chosen = [m for m in members if m.slug == (choices.get(app_id) or {}).get('addon')]
            for member in chosen or members:
                wanted += haimport.needed_members(backup.layout, {app_id: member})
        if not any(member.encrypted for _app, member in wanted):
            return rec, None, present, missing
        if key is None:
            raise hasecuretar.key_required(ha_backup_id=rec['id'])
        haimport.key_problems(backup, hasecuretar.Keys(key), wanted)
    return rec, key, present, missing


def cmd_ha_check_start(svc, req):
    """An HA check job (type verify, params.source 'ha'; CONTRACT section 7). An app the backup does not hold stays in
    the job: its result says so."""
    rec, key, _present, _missing = _ha_selection(svc, req)
    params = {'source': 'ha', 'ha_backup_id': rec['id'], 'apps': list(req['apps']), 'key_provided': key is not None}
    if req.get('choices'):
        params['choices'] = req['choices']
    return svc.start('verify', params, req['request_id'], key_text=key, key_kind='ha')


def _convert_params(rec, apps, *, database, test_mode, encrypt, key, acknowledged, choices):
    params = {'source': 'ha', 'ha_backup_id': rec['id'], 'apps': list(apps), 'odoo_database': database,
              'test_mode': bool(test_mode), 'encrypt': bool(encrypt), 'key_provided': key is not None}
    acknowledged = {app_id: list(keys) for app_id, keys in (acknowledged or {}).items()
                    if keys and app_id in (*apps, haissues.SHARED)}
    choices = {app_id: dict(values) for app_id, values in (choices or {}).items() if values and app_id in apps}
    if acknowledged:
        params['acknowledged'] = acknowledged
    if choices:
        params['choices'] = choices
    return params


def cmd_ha_convert_start(svc, req):
    """An HA convert job (type backup, params.source 'ha'; CONTRACT section 7): the conversion alone. Without an Odoo
    database the only one that can move is taken (HA-14); without a device key one is created (HA-13)."""
    from . import haimport
    apps = list(req['apps'])
    database = req.get('odoo_database')
    if database is None:
        database = ((req.get('choices') or {}).get('odoo') or {}).get('database')
    if 'odoo' not in apps:
        database = None
    catalog = svc.catalog()
    for app_id in apps:
        if catalog.get(app_id) is None:
            issue = haimport.not_installed(catalog, app_id)
            raise BackupError('app-not-in-catalog', issue.message + issue.action, app=app_id)
    encrypt = svc.encrypt_by_default()
    rec, key, _present, missing = _ha_selection(svc, req)
    if missing:
        raise BackupError('invalid-request', f'這份 HA 備份沒有可以匯入「{missing[0]}」的附加元件。', field='apps',
                          app=missing[0])
    created = ensure_key(svc, 'ha-convert') if encrypt else False
    params = _convert_params(rec, apps, database=database, test_mode=req['test_mode'], encrypt=encrypt, key=key,
                             acknowledged=req.get('acknowledged'), choices=req.get('choices'))
    return dict(svc.start('backup', params, req['request_id'], key_text=key, key_kind='ha'), key_created=created)


def _group_result(app_id, status, code=None, message=None):
    """GroupResult (CONTRACT section 7): what became of one app of an import."""
    return {'app_id': app_id, 'status': status, 'convert_job_id': None, 'restore_job_id': None, 'backup_id': None,
            'safety_backup_id': None, 'code': code, 'message': message}


def _import_plan(svc, req):
    """(record, key, apps to import in order, GroupResults of the apps that are left out) of `ha-import-start`: an app
    the backup does not hold or this device has no settings for is left out with its reason while another one can be
    imported; with none left the request is refused."""
    from . import haimport
    rec, key, present, missing = _ha_selection(svc, req)
    skipped = [_group_result(app_id, 'skipped', 'not-found', haimport.ADDON_MISSING + haimport.ADDON_MISSING_ACTION)
               for app_id in missing]
    catalog = svc.catalog()
    apps, refusal = [], None
    for app_id in present:
        if catalog.get(app_id) is not None:
            apps.append(app_id)
            continue
        issue = haimport.not_installed(catalog, app_id)
        skipped.append(_group_result(app_id, 'skipped', 'app-not-in-catalog', issue.message + issue.action))
        refusal = refusal or BackupError('app-not-in-catalog', issue.message + issue.action, app=app_id)
    if not apps:
        raise refusal
    return rec, key, apps, skipped


def _confirmed_items(svc, req):
    """{(app id or `_shared`, key): how many names the confirmed line had} from the check the page showed (the audit
    lines only; nothing depends on it)."""
    record = svc.job_record(req['check_job_id']) if req.get('check_job_id') else None
    check = ((record or {}).get('result') or {}).get('ha_check') if isinstance(record, dict) else None
    counts = {}
    if isinstance(check, dict) and check.get('ha_backup_id') == req['ha_backup_id']:
        groups = [(haissues.SHARED, check.get('shared'))] + [(app.get('app_id'), app.get('issues'))
                                                              for app in check.get('apps') or []]
        for app_id, issues in groups:
            for issue in issues or []:
                if issue.get('key'):
                    counts[(app_id, issue['key'])] = len(issue.get('items') or []) + int(issue.get('more') or 0)
    return counts


def cmd_ha_import_start(svc, req):
    """The whole import of the selected apps, one after the other (CONTRACT section 7): the first app's conversion job
    starts here, with the import's group and what the rest of it needs (`params.chain`). The customer's one confirmation
    is in the request: every line with a consequence by its key (`acknowledged`) and that this device's data is
    replaced (`overwrite`, with `then_restore`). Each app's conversion checks its own lines again."""
    rec, key, apps, skipped = _import_plan(svc, req)
    encrypt = svc.encrypt_by_default()
    created = ensure_key(svc, 'ha-import') if encrypt else False
    group = 'g' + secrets.token_hex(8)
    first = apps[0]
    acknowledged, choices = req.get('acknowledged') or {}, req.get('choices') or {}
    database = (choices.get(first) or {}).get('database') if first == 'odoo' else None
    params = _convert_params(rec, [first], database=database, test_mode=req['test_mode'], encrypt=encrypt, key=key,
                             acknowledged=acknowledged, choices=choices)
    params['group'] = {'id': group, 'index': 0, 'count': len(apps), 'kind': 'ha-import', 'step': 'convert',
                       'app_id': first}
    params['chain'] = {'apps': apps, 'test_mode': bool(req['test_mode']), 'then_restore': bool(req['then_restore']),
                       'encrypt': bool(encrypt), 'acknowledged': {k: list(v) for k, v in acknowledged.items() if v},
                       'choices': {k: dict(v) for k, v in choices.items() if v}, 'results': skipped}
    started = svc.start('backup', params, req['request_id'], key_text=key, key_kind='ha')
    if started.get('deduplicated'):
        known = ((svc.job_record(started['job_id']) or {}).get('params') or {}).get('group') or {}
        if not known.get('id'):
            raise BackupError('invalid-request', '此請求識別碼已用於其他類型的作業。')
        group = known['id']
    else:
        counts = _confirmed_items(svc, req)
        for app_id, keys in acknowledged.items():
            for item in keys:
                svc.audit(f'ha-import-confirm ha_backup={rec["id"]} group={group} app={app_id} '
                          f'issue={item.rsplit(":", 1)[0]} items={counts.get((app_id, item), "-")} '
                          f'loginuid={_login_uid()}')
    return dict(started, group=group, key_created=created)


def cmd_upload_abort(svc, req):
    svc.storage.abort_upload(req['upload_id'])
    return {}


def cmd_download_info(svc, req):
    info = svc.storage.download_info(req['backup_id'])
    meta = svc.storage.get(req['backup_id'])
    if meta.get('encrypted') is False:
        # A plaintext backup leaves the device: journaled like an unencrypted copy's download (review L6).
        svc.audit(f'download-unencrypted backup={req["backup_id"]} loginuid={_login_uid()}')
    return {'path': str(info['path']), 'filename': info['filename'], 'size': int(info['size'])}


def cmd_settings_get(svc, _req):
    return {'settings': svc.settings_view()}


def cmd_settings_set(svc, req):
    """預設加密備份: turning it off needs `acknowledge_plaintext: true`; audited in the journal."""
    from . import settings
    view = settings.save(svc.paths, encrypt_by_default=req['encrypt_by_default'],
                         acknowledge_plaintext=req.get('acknowledge_plaintext') is True, trusted_uid=svc.trusted_uid,
                         audit=svc.audit)
    return {'settings': view}


def cmd_export_start(svc, req):
    """Start a job that writes an unencrypted copy of an encrypted backup for one download (admin, explicit
    confirmation of settings.PLAINTEXT_WARNING; audited). A backup that is not encrypted is downloaded as it is."""
    backup_id = req['backup_id']
    svc.cleanup_exports()
    svc.storage.get(backup_id)
    header = svc.archive.read_header(svc.storage.archive_path(backup_id))
    if header.get('encryption') == 'none':
        raise BackupError('invalid-request', '這份備份沒有加密，可以直接下載，不需要建立未加密副本。')
    key_text = req.get('key')
    if key_text is None and header.get('key_id') not in svc.key_ids():
        raise BackupError('key-required', '此備份使用的金鑰不在這台設備，請輸入緊急金鑰。', key_id=header.get('key_id'))
    started = svc.start('export', {'backup_id': backup_id, 'key_provided': key_text is not None}, req['request_id'],
                        key_text=key_text)
    if not started.get('deduplicated'):
        svc.audit(f'export-unencrypted-request backup={backup_id} job={started["job_id"]} loginuid={_login_uid()}')
    return started


def cmd_export_info(svc, req):
    """Path of an unencrypted download copy for the page's fsread1 download (only inside exports/, until it expires)."""
    removed = []
    try:
        info = svc.storage.export_info(req['export_id'], removed=removed)
    finally:
        for export_id in removed:  # expired copies it deleted on the way (review F17)
            svc.audit(f'export-unencrypted-deleted export={export_id} reason=expired')
    svc.audit(f'export-unencrypted-download export={req["export_id"]} backup={info["backup_id"]} '
              f'loginuid={_login_uid()}')
    return {'path': str(info['path']), 'filename': info['filename'], 'size': int(info['size']),
            'expires': int(info['expires']), 'backup_id': info['backup_id']}


def cmd_export_delete(svc, req):
    removed = svc.storage.delete_export(req['export_id'])
    if removed:
        svc.audit(f'export-unencrypted-deleted export={req["export_id"]} reason=request loginuid={_login_uid()}')
    return {'deleted': bool(removed)}


def cmd_catalog_suggest(svc, req):
    """Drafts of catalog entries from an owner's Quadlet files (read-only, everything in his home read as him);
    without `owner` only the accounts that can be scanned."""
    from . import suggest
    return suggest.suggest(req.get('owner'), paths=svc.paths, catalog=svc.catalog())


def cmd_catalog_install(svc, req):
    """Without `confirm` a preview (validation, conflicts, diff, compatibility notes); with it the entry is written
    under the start lock when it still is the previewed one (`expected_sha256`)."""
    from . import catalog_admin
    backups = svc.storage.list_backups()
    if not req.get('confirm'):
        return catalog_admin.preview_install(svc.paths, req['entry'], backups=backups, trusted_uid=svc.trusted_uid)
    svc.recover()  # dead jobs are marked interrupted (and their leftovers settled) before the busy check
    return catalog_admin.install(svc.paths, req['entry'], req['expected_sha256'], backups=backups,
                                 trusted_uid=svc.trusted_uid, audit=svc.audit)


def cmd_catalog_remove(svc, req):
    from . import catalog_admin
    backups = svc.storage.list_backups()
    if not req.get('confirm'):
        return catalog_admin.preview_remove(svc.paths, req['id'], backups=backups, trusted_uid=svc.trusted_uid)
    svc.recover()
    return catalog_admin.remove(svc.paths, req['id'], req['expected_sha256'], backups=backups,
                                trusted_uid=svc.trusted_uid, audit=svc.audit)


def cmd_retention_plan(svc, req):
    from . import retention
    svc.recover()
    return retention.plan_command(svc.paths, svc.storage, svc.catalog(), req.get('policy'),
                                  trusted_uid=svc.trusted_uid)


def cmd_retention_apply(svc, req):
    from . import retention
    svc.recover()
    return retention.apply_command(svc.paths, svc.storage, req['backup_ids'], policy=req.get('policy'),
                                   trusted_uid=svc.trusted_uid, audit=svc.audit)


# ---------------------------------------------------------------- 排程備份

def schedule_gate(svc):
    """What turning the schedule on needs (like Home Assistant): while 預設加密備份 is on, a device key and a saved
    emergency kit. `blocked`: null, 'no-device-key' or 'kit-unconfirmed'."""
    encrypt = bool(svc.encrypt_by_default())
    key = svc.keys.device_key()
    blocked = None
    if encrypt and key is None:
        blocked = 'no-device-key'
    elif encrypt and not key.kit_confirmed:
        blocked = 'kit-unconfirmed'
    return {'encrypt': encrypt, 'device_key': key is not None,
            'kit_confirmed': bool(key is not None and key.kit_confirmed), 'blocked': blocked}


def _runs(schedule, settings, env):
    if not settings['enabled']:
        return []
    return [schedule.instant_view(slot, env.zone) for slot in schedule.next_slots(settings, env.zone, env.now, 3)]


def cmd_schedule_get(svc, _req):
    """The saved schedule, the next 3 runs, the timer, the last run, the slot waiting for another job, the attention
    item, the recent events, the device's zone and what turning it on needs (`gate`)."""
    from . import schedule
    env = svc.env()
    settings, problem, saved = svc.schedule_settings()
    state, state_problem = schedule.read_state(svc.paths)
    view = schedule.summary(settings, problem, saved, state, state_problem, env, svc.timer_view(env), svc.job_record)
    # `defaults`: the form shows the defaults, not a saved file's (nothing saved, or the file cannot be used).
    return {'schedule': schedule.settings_view(settings, problem or state_problem, saved,
                                               defaults_shown=bool(problem) or not saved),
            'next_runs': _runs(schedule, settings, env) if view['enabled'] else [], 'timer': view['timer'],
            'last_run': view['last_run'], 'waiting': view['waiting'], 'attention': view['attention'],
            'events': schedule.events_view(state, env.zone), 'timezone': view['timezone'], 'gate': schedule_gate(svc)}


def cmd_schedule_set(svc, req):
    """Without `confirm` a preview (the settings as they would be saved, the next 3 runs, which scheduled backups the
    next successful run would delete); with it the settings are saved (root 0644) and audited. Turning the schedule on
    while 預設加密備份 is on needs a device key (`no-device-key`) and a saved emergency kit (`invalid-request`,
    `details.reason` 'kit-unconfirmed'). Saving never deletes anything."""
    from . import retention, schedule
    proposed = schedule.validate(req['schedule'])
    catalog = svc.catalog()
    if isinstance(proposed['apps'], list):
        flows.resolve_apps(catalog, proposed['apps'])  # each app must be in this device's catalog when saved
    if proposed['enabled']:
        gate = schedule_gate(svc)
        if gate['blocked'] == 'no-device-key':
            raise BackupError('no-device-key', '開啟排程備份前，請先到「加密金鑰」建立這台設備的加密金鑰，並保存緊急金鑰。')
        if gate['blocked'] == 'kit-unconfirmed':
            raise BackupError('invalid-request', '開啟排程備份前，請先保存緊急金鑰。', reason='kit-unconfirmed',
                              field='schedule.enabled')
    env = svc.env()
    previous, _problem, saved = svc.schedule_settings()
    if req.get('confirm'):
        record, previous = schedule.save(svc.paths, proposed, trusted_uid=svc.trusted_uid, now=env.now)
        svc.audit(schedule.audit_line(record, previous))
        saved = True
    else:
        record = schedule.prepared(previous, proposed, env.now)
    apps = [app_id for app_id in schedule.run_apps(record, list(catalog.keys())) if catalog.get(app_id) is not None]
    plan = retention.schedule_plan(svc.paths, svc.storage, apps, record['keep_last'])
    return {'saved': bool(req.get('confirm')), 'schedule': schedule.settings_view(record, None, saved),
            'next_runs': _runs(schedule, record, env),
            'retention': {'keep_last': record['keep_last'], 'apps': apps, 'delete': plan['candidates'],
                          'blocked': plan['blocked'], 'freed_bytes': plan['freed_bytes']},
            'timezone': schedule.timezone_view(env)}


def cmd_schedule_run_now(svc, req):
    """One scheduled run now with the saved settings (enabled or not; like a manual backup, not kit-gated): it counts
    as scheduled and the schedule's keep-last rule runs after it. Encrypted as 預設加密備份 says now."""
    from . import schedule
    settings, problem, saved = svc.schedule_settings()
    if problem:
        raise BackupError('invalid-request', problem, reason='settings-problem')
    if not saved:
        raise BackupError('invalid-request', '請先儲存排程設定，再立即執行一次。', reason='not-saved')
    _state, state_problem = schedule.read_state(svc.paths)
    if state_problem:
        raise BackupError('invalid-request', state_problem, reason='state-problem')
    catalog = svc.catalog()
    app_ids = schedule.run_apps(settings, list(catalog.keys()))
    if not [app_id for app_id in app_ids if catalog.get(app_id) is not None]:
        raise BackupError('invalid-request', '沒有可以備份的應用：排程包含的應用都不在這台設備的應用設定中。',
                          reason='no-apps')
    encrypt = bool(svc.encrypt_by_default())
    if encrypt and svc.keys.device_key() is None:
        raise BackupError('no-device-key', '這台設備尚未建立加密金鑰，請先完成金鑰設定。')
    started = svc.start('backup', schedule.job_params(settings, app_ids, encrypt, slot=None, trigger='run-now'),
                        req['request_id'])
    if not started.get('deduplicated'):
        try:
            schedule.record_run_now(svc.paths, started, settings, app_ids, encrypt, svc.job_record, svc.job_ended,
                                    svc.env(), svc.journal)
        except Exception:  # noqa: BLE001 - the job runs and registers itself; only the overview's last run lags
            traceback.print_exc(file=sys.stderr)
    return started


COMMANDS = {
    'status': cmd_status, 'list': cmd_list, 'inspect': cmd_inspect, 'key-init': cmd_key_init,
    'key-kit': cmd_key_kit, 'key-confirm': cmd_key_confirm, 'key-import': cmd_key_import,
    'backup-start': cmd_backup_start, 'verify-start': cmd_verify_start, 'restore-start': cmd_restore_start,
    'job-status': cmd_job_status, 'jobs': cmd_jobs, 'job-cancel': cmd_job_cancel, 'delete': cmd_delete,
    'upload-begin': cmd_upload_begin, 'upload-finish': cmd_upload_finish, 'upload-abort': cmd_upload_abort,
    'download-info': cmd_download_info, 'settings-get': cmd_settings_get, 'settings-set': cmd_settings_set,
    'export-start': cmd_export_start, 'export-info': cmd_export_info, 'export-delete': cmd_export_delete,
    'catalog-suggest': cmd_catalog_suggest, 'catalog-install': cmd_catalog_install,
    'catalog-remove': cmd_catalog_remove, 'retention-plan': cmd_retention_plan, 'retention-apply': cmd_retention_apply,
    'schedule-get': cmd_schedule_get, 'schedule-set': cmd_schedule_set, 'schedule-run-now': cmd_schedule_run_now,
    'ha-delete': cmd_ha_delete, 'ha-check-start': cmd_ha_check_start, 'ha-convert-start': cmd_ha_convert_start,
    'ha-import-start': cmd_ha_import_start,
}


def _dispatch(argv, paths, stdin, services, require_root):
    if require_root and os.geteuid() != 0:
        raise BackupError('permission-denied', '需要管理員權限，請先在 Cockpit 開啟管理員存取權限。')
    if not argv or not isinstance(argv[0], str):
        raise BackupError('invalid-request', '缺少指令。')
    command = argv[0]
    svc = services or Services(paths or Paths())
    if command == 'run-job':
        if len(argv) != 2 or not jobmod.valid_job_id(argv[1]):
            raise BackupError('invalid-request', 'run-job 需要一個有效的作業 ID。')
        svc.cleanup_exports()  # any job run also deletes expired unencrypted copies (review L1)
        record = jobmod.run_job(svc.paths, argv[1], deps=svc.deps)
        return {'state': record.get('state')}
    if command == 'export-cleanup':
        # Internal (the transient timer an export job schedules): delete expired unencrypted download copies.
        if len(argv) != 1:
            raise BackupError('invalid-request', 'export-cleanup 不需要參數。')
        return {'removed': svc.cleanup_exports()}
    if command == 'schedule-tick':
        # Internal (woowtech-cockpit-backup-schedule.timer every 5 minutes): argv only, no stdin.
        if len(argv) != 1:
            raise BackupError('invalid-request', 'schedule-tick 不需要參數。')
        from . import schedule
        return schedule.run_tick(svc)
    if command not in COMMANDS or len(argv) != 1:
        raise BackupError('invalid-request', '不支援的指令。')
    if command in NO_INPUT:
        request = {}
    else:
        request = validate(command, read_request(stdin if stdin is not None else sys.stdin))
    return COMMANDS[command](svc, request)


def _emit(stream, response):
    try:
        text = json.dumps(response, ensure_ascii=False, separators=(',', ':'), default=str)
        text.encode('utf-8')
    except ValueError:  # lone surrogates from hostile input: \\u escapes keep the one-JSON-object contract
        text = json.dumps(response, ensure_ascii=True, separators=(',', ':'), default=str)
    try:
        stream.write(text + '\n')
        stream.flush()
    except (BrokenPipeError, OSError):
        pass


def main(argv=None, *, paths=None, stdin=None, stdout=None, services=None, require_root=True):
    """Run one command; returns the exit code. Production passes nothing but argv."""
    argv = list(sys.argv[1:] if argv is None else argv)
    out = stdout if stdout is not None else sys.stdout
    try:
        # SIGTERM/SIGHUP/SIGINT (cockpit-bridge closing the channel, a page timeout) become an exception, so
        # every `finally` runs: a pasted key in /run/woowtech-backup is always deleted (review finding SEC-4).
        guard = (jobmod.signals_as_exceptions() if threading.current_thread() is threading.main_thread()
                 else contextlib.nullcontext())
        with guard:
            payload = _dispatch(argv, paths, stdin, services, require_root)
        response, code = {'ok': True, **(payload or {})}, 0
    except BackupError as error:
        response, code = {'ok': False, 'error': error.as_dict()}, 1
    except (Exception, KeyboardInterrupt, jobmod.Terminated):  # noqa: BLE001
        traceback.print_exc(file=sys.stderr)
        response = {'ok': False, 'error': {'code': 'internal-error', 'message': GENERIC_ERROR, 'details': {}}}
        code = 1
    _emit(out, response)
    return code


if __name__ == '__main__':
    sys.exit(main())
