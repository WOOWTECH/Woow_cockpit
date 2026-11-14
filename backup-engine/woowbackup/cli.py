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

from . import flows
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
                      'allow_no_safety': (OPTIONAL, v_bool), 'accept_unauthenticated': (OPTIONAL, v_bool)},
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
}
NO_INPUT = frozenset({'status', 'list', 'key-init', 'key-kit', 'jobs', 'settings-get'})


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
    if command in ('catalog-install', 'catalog-remove') and data.get('confirm') and 'expected_sha256' not in data:
        # A confirmed change names the entry it previewed (null: none was installed).
        raise _bad('expected_sha256', '確認時為必填（預覽回傳的 expected_sha256，沒有安裝的設定時為 null）。')
    return data


# ---------------------------------------------------------------- services

class Services:
    """Dependencies of the commands; tests replace `deps`, `launcher` and `unit_active`."""

    def __init__(self, paths, *, deps=None, launcher=None, unit_active=None, trusted_uid=0):
        self.paths = paths
        self._deps = deps
        self.launcher = launcher
        self.unit_active = unit_active
        self.trusted_uid = trusted_uid  # owner of /etc/woowtech-cockpit/backup/settings.json (root; tests: themselves)
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
                                             settle_dirs=self.settle_dirs, package_safety=self.package_safety)
        # Every recovery pass also deletes expired unencrypted copies (after a reboot the transient timer is gone;
        # review L1).
        self.cleanup_exports()
        return changed

    def start(self, job_type, params, request_id, **kwargs):
        return jobmod.start_job(self.paths, job_type, params, request_id, launcher=self.launcher,
                                unit_active=self.unit_active, restart_writers=self.restart_writers,
                                cleanup_fresh=self.cleanup_fresh, settle_dirs=self.settle_dirs,
                                package_safety=self.package_safety, **kwargs)

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


def backup_view(meta, key_ids):
    """BackupMeta for the page: `format` (1|2), `encrypted`, `key_available` (always true without encryption) and
    `unauthenticated` (an unencrypted upload: a restore needs `accept_unauthenticated`)."""
    from .storage import unauthenticated
    view = dict(meta)
    view.setdefault('format', 1)
    view.setdefault('encrypted', True)
    view['key_available'] = (not view['encrypted']) or meta.get('key_id') in key_ids
    view['unauthenticated'] = unauthenticated(view)
    return view


def tool_version(paths):
    lib = paths.lib
    return engine_version(lib) if os.path.exists(os.path.join(str(lib), 'VERSION')) else engine_version()


def storage_usage(storage, backups):
    if hasattr(storage, 'usage'):
        return storage.usage()
    return {'path': '', 'free_bytes': storage.free_bytes(), 'total_bytes': 0,
            'backups_bytes': sum(b.get('size', 0) for b in backups), 'backup_count': len(backups)}


def app_view(svc, app, backups):
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
    last = next(({'id': b['id'], 'created': b.get('created')} for b in backups
                 if b.get('type') in ('manual', 'safety') and app.id in {a.get('id') for a in b.get('apps') or []}),
                None)
    return {'id': app.id, 'name': app.name, 'description': app.description, 'owner': app.owner,
            'adapter': app.adapter, 'deployed': bool(info['deployed']), 'state': info['state'],
            'units': info['units'], 'last_backup': last, 'problems': list(info['problems'])}


def app_views(svc, apps, backups):
    """app_view of every app, several at a time: each quick health request is bounded (review finding HD-07), and
    running them side by side keeps `status` within the page's timeout with many apps."""
    apps = list(apps)
    if len(apps) <= 1:
        return [app_view(svc, app, backups) for app in apps]
    with ThreadPoolExecutor(max_workers=min(STATUS_WORKERS, len(apps)), thread_name_prefix='woowbackup-status') as pool:
        return list(pool.map(lambda app: app_view(svc, app, backups), apps))


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
        if app is None:
            problem = catalog.problem_for(app_manifest['id']) if hasattr(catalog, 'problem_for') else None
            message = problem['message'] if problem else '此設備沒有設定這個應用，無法還原。'
            apps.append({'id': app_manifest['id'], 'name': app_manifest['name'], 'restorable': False, 'mode': 'fresh',
                         'checks': [{'id': f'{app_manifest["id"]}/catalog', 'status': 'fail', 'message': message}]})
            continue
        adapter = svc.adapter(app)
        mode = 'fresh'
        try:
            mode = adapter.detect_mode()
            app_checks = adapter.preflight(app_manifest, mode=mode, entry_sizes=entry_sizes)
        except BackupError as error:
            app_checks = [{'id': f'{app.id}/probe', 'status': 'fail', 'message': error.message}]
        if mode == 'inplace' and device_key is None and safety_encrypted:
            app_checks.append({'id': f'{app.id}/device-key', 'status': 'fail',
                               'message': '原位還原需要先建立這台設備的加密金鑰（用於建立還原前備份）。'})
        apps.append({'id': app.id, 'name': app.name, 'mode': mode, 'checks': app_checks,
                     'restorable': not any(c['status'] == 'fail' for c in app_checks)})
    ok = not any(c['status'] == 'fail' for c in checks) and any(a['restorable'] for a in apps)
    return {'ok': ok, 'checks': checks, 'apps': apps}


# ---------------------------------------------------------------- commands

def apps_usage(svc, backups, catalog):
    """`status.storage.apps`: bytes of each app's backups with its keep-last policy (retention.app_usage); no I/O
    beyond the index listing and the policy file. A problem here never breaks the status page."""
    from . import retention
    try:
        policy, _problem = retention.load_policy(svc.paths, trusted_uid=svc.trusted_uid)
        return retention.app_usage(backups, catalog, policy)['apps']
    except Exception:  # noqa: BLE001 - the overview simply falls back to its own computation
        traceback.print_exc(file=sys.stderr)
        return []


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
    }


def cmd_list(svc, _req):
    svc.cleanup_exports()
    ids = svc.key_ids()
    exports = getattr(svc.storage, 'list_exports', lambda: [])()
    return {'backups': [backup_view(meta, ids) for meta in svc.storage.list_backups()],
            'exports': [{key: rec[key] for key in ('export_id', 'backup_id', 'filename', 'size', 'expires')}
                        for rec in exports]}


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
    return {'backup': backup_view(meta, svc.key_ids()), 'manifest': summary, 'preflight': preflight}


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
    params = {'backup_id': req['backup_id'], 'apps': list(req['apps']), 'key_provided': key_text is not None}
    if req.get('allow_no_safety'):
        params['allow_no_safety'] = True
    if req.get('accept_unauthenticated'):
        params['accept_unauthenticated'] = True
    return svc.start('restore', params, req['request_id'], key_text=key_text)


def cmd_job_status(svc, req):
    svc.recover()
    store = jobmod.JobStore(svc.paths)
    record = store.get(req['job_id'])
    return {'job': jobmod.public_job(record), 'log': store.read_log(req['job_id'], 200)}


def cmd_jobs(svc, _req):
    svc.recover()
    return {'jobs': [jobmod.public_job(r) for r in jobmod.JobStore(svc.paths).list(50)]}


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
    # Every deletion is journaled, like retention's (review L6).
    svc.audit(f'backup-delete backup={backup_id} type={meta.get("type")} '
              f'encrypted={"false" if meta.get("encrypted") is False else "true"} loginuid={_login_uid()}')
    return {}


def cmd_upload_begin(svc, req):
    info = svc.storage.begin_upload(req['filename'], req['size'])
    return {'upload_id': info['upload_id'], 'path': str(info['path']), 'max_size': int(info['max_size'])}


def cmd_upload_finish(svc, req):
    meta = svc.storage.finish_upload(req['upload_id'])
    return {'backup': backup_view(meta, svc.key_ids())}


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
