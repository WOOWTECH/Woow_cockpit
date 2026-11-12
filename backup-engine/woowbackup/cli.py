"""JSON command dispatcher for the Cockpit UI (CONTRACT section 7). Owner: E2.

`woowtech-cockpit-backup <command>`: request JSON on stdin (<= 1 MiB, strictly validated, unknown
keys rejected), exactly one JSON object on stdout, exit 0 (`{"ok": true, ...}`) or 1
(`{"ok": false, "error": {code, message, details}}`). Unexpected exceptions become
`internal-error` with a generic zh-TW message; the traceback goes to stderr (journal) only.
Key material is only ever accepted in the stdin field `key` and never echoed.
"""
import json
import os
import platform
import re
import secrets
import sys
import traceback
from contextlib import ExitStack

from . import flows
from . import jobs as jobmod
from . import version as engine_version
from .errors import BackupError
from .paths import Paths

MAX_STDIN = 1024 * 1024
BACKUP_ID_RE = re.compile(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
UPLOAD_ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z')
KEY_ID_RE = re.compile(r'[0-9A-F]{4}(?:-[0-9A-F]{4}){3}\Z')
APP_ID_RE = re.compile(r'[a-z0-9][a-z0-9-]{1,40}\Z')
CONTROL_RE = re.compile(r'[\x00-\x1f\x7f-\x9f]')
GENERIC_ERROR = '發生未預期的內部錯誤，請查看系統日誌。'


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


REQUIRED, OPTIONAL = True, False
SPECS = {
    'inspect': {'backup_id': (REQUIRED, v_backup_id), 'key': (OPTIONAL, v_key), 'save_key': (OPTIONAL, v_bool)},
    'key-confirm': {'key_id': (REQUIRED, v_key_id)},
    'key-import': {'key': (REQUIRED, v_key)},
    'backup-start': {'apps': (REQUIRED, v_apps), 'include_images': (OPTIONAL, v_bool), 'note': (OPTIONAL, v_note),
                     'request_id': (REQUIRED, v_request_id)},
    'verify-start': {'backup_id': (REQUIRED, v_backup_id), 'request_id': (REQUIRED, v_request_id),
                     'key': (OPTIONAL, v_key)},
    'restore-start': {'backup_id': (REQUIRED, v_backup_id), 'apps': (REQUIRED, v_apps),
                      'request_id': (REQUIRED, v_request_id), 'confirm': (REQUIRED, v_true),
                      'key': (OPTIONAL, v_key), 'save_key': (OPTIONAL, v_bool)},
    'job-status': {'job_id': (REQUIRED, v_job_id)},
    'job-cancel': {'job_id': (REQUIRED, v_job_id)},
    'delete': {'backup_id': (REQUIRED, v_backup_id)},
    'upload-begin': {'filename': (REQUIRED, v_filename), 'size': (REQUIRED, v_size)},
    'upload-finish': {'upload_id': (REQUIRED, v_upload_id)},
    'upload-abort': {'upload_id': (REQUIRED, v_upload_id)},
    'download-info': {'backup_id': (REQUIRED, v_backup_id)},
}
NO_INPUT = frozenset({'status', 'list', 'key-init', 'key-kit', 'jobs'})


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _no_constants(name):
    raise ValueError(f'unsupported constant {name}')


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
    return data


# ---------------------------------------------------------------- services

class Services:
    """Dependencies of the commands; tests replace `deps`, `launcher` and `unit_active`."""

    def __init__(self, paths, *, deps=None, launcher=None, unit_active=None):
        self.paths = paths
        self._deps = deps
        self.launcher = launcher
        self.unit_active = unit_active
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
        failed = []
        catalog = self.catalog()
        for app_id, units in stopped.items():
            app = catalog.get(app_id)
            if app is None:
                failed.extend(units)
                continue
            try:
                failed.extend(self.adapter(app).start_units([u for u in units if u in app.writer_units]))
            except BackupError:
                failed.extend(units)
        return failed

    def recover(self):
        return jobmod.recover_interrupted(self.paths, unit_active=self.unit_active,
                                          restart_writers=self.restart_writers)

    def key_ids(self):
        return {info.key_id for info in self.keys.identities()}


def key_view(info):
    if info is None:
        return None
    return {'key_id': info.key_id, 'created': info.created, 'kit_confirmed': bool(info.kit_confirmed)}


def backup_view(meta, key_ids):
    view = dict(meta)
    view['key_available'] = meta.get('key_id') in key_ids
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
        info = svc.adapter(app).probe()
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


def manifest_summary(manifest):
    apps = []
    for app in manifest.get('apps') or []:
        apps.append({
            'id': app['id'], 'name': app['name'], 'adapter': app['adapter'],
            'owner': {'name': app['owner']['name'], 'uid': app['owner']['uid']},
            'images': [{'ref': img['ref'], 'included': 'entry' in img} for img in app.get('images') or []],
            'postgres': [{'id': p['id'], 'database': p['database'], 'major': p['major']} for p in app.get('postgres') or []],
            'volumes': [{'name': v['name']} for v in app.get('volumes') or []],
            'secrets_count': len(app.get('secrets') or []), 'config_files_count': len(app.get('config_files') or []),
            'verify_snapshot': app.get('verify_snapshot') or {},
        })
    return {'backup_id': manifest['backup_id'], 'created': manifest['created'], 'type': manifest['type'],
            'note': manifest['note'], 'tool': manifest['tool'], 'source': manifest['source'],
            'consistency': manifest['consistency'],
            'total_size': sum(int(e.get('size', 0)) for e in manifest.get('entries') or []), 'apps': apps}


def build_preflight(svc, manifest):
    checks = [{'id': 'archive', 'status': 'ok', 'message': '備份檔格式與金鑰檢查通過；還原前會再完整驗證全部內容。'}]
    total = sum(int(e.get('size', 0)) for e in manifest.get('entries') or [])
    free = int(svc.storage.free_bytes())
    required = total + int(svc.paths.reserve_bytes)
    if free < required:
        checks.append({'id': 'space', 'status': 'fail',
                       'message': f'本設備空間不足以解開備份：需要約 {flows.human(required)}，可用 {flows.human(free)}。'})
    else:
        checks.append({'id': 'space', 'status': 'ok', 'message': f'本設備空間足夠（可用 {flows.human(free)}）。'})
    source_arch = (manifest.get('source') or {}).get('arch')
    if source_arch and source_arch != platform.machine():
        checks.append({'id': 'arch', 'status': 'warn',
                       'message': f'備份來源的 CPU 架構（{source_arch}）與本設備（{platform.machine()}）不同。'})
    catalog = svc.catalog()
    entry_sizes = {e.get('path'): e.get('size', 0) for e in manifest.get('entries') or []}
    device_key = svc.keys.device_key()
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
        if mode == 'inplace' and device_key is None:
            app_checks.append({'id': f'{app.id}/device-key', 'status': 'fail',
                               'message': '原位還原需要先建立本設備的備份金鑰（用於建立還原前備份）。'})
        apps.append({'id': app.id, 'name': app.name, 'mode': mode, 'checks': app_checks,
                     'restorable': not any(c['status'] == 'fail' for c in app_checks)})
    ok = not any(c['status'] == 'fail' for c in checks) and any(a['restorable'] for a in apps)
    return {'ok': ok, 'checks': checks, 'apps': apps}


# ---------------------------------------------------------------- commands

def cmd_status(svc, _req):
    svc.recover()
    catalog = svc.catalog()
    backups = svc.storage.list_backups()
    host = svc.deps.host_info()
    identities = list(svc.keys.identities())
    active = jobmod.active_job(svc.paths)
    return {
        'version': tool_version(svc.paths),
        'host': {key: host.get(key) for key in ('hostname', 'arch', 'os', 'podman')},
        'storage': storage_usage(svc.storage, backups),
        'key': key_view(svc.keys.device_key()),
        'imported_keys': [{'key_id': k.key_id, 'created': k.created} for k in identities if k.kind == 'imported'],
        'apps': [app_view(svc, app, backups) for app in catalog.values()],
        'active_job': jobmod.public_job(active) if active else None,
        'warnings': [p['message'] for p in getattr(catalog, 'problems', [])],
    }


def cmd_list(svc, _req):
    ids = svc.key_ids()
    return {'backups': [backup_view(meta, ids) for meta in svc.storage.list_backups()]}


def cmd_inspect(svc, req):
    backup_id = req['backup_id']
    svc.storage.get(backup_id)
    path = svc.storage.archive_path(backup_id)
    header = svc.archive.read_header(path)
    key_text = req.get('key')
    if key_text is not None and req.get('save_key'):
        svc.keys.import_key(key_text)
        key_text = None
    identities = list(svc.keys.identities())
    with ExitStack() as stack:
        if key_text is not None:
            identities.append(stack.enter_context(svc.keys.temp_identity(key_text, f'key-inspect-{secrets.token_hex(8)}')))
        elif header.get('key_id') not in {info.key_id for info in identities}:
            raise BackupError('key-required', '此備份使用的金鑰不在本設備，請輸入緊急金鑰。', key_id=header.get('key_id'))
        manifest = svc.archive.read_manifest(path, identities)
    summary = manifest_summary(manifest)
    preflight = build_preflight(svc, manifest)
    meta = svc.storage.update(
        backup_id, created=manifest['created'], note=manifest['note'],
        apps=[{'id': a['id'], 'name': a['name']} for a in manifest['apps']],
        include_images=any('entry' in img for a in manifest['apps'] for img in a.get('images') or []),
        source={'hostname': manifest['source']['hostname']}, inspected=True)
    return {'backup': backup_view(meta, svc.key_ids()), 'manifest': summary, 'preflight': preflight}


def cmd_key_init(svc, _req):
    info, created = svc.keys.ensure_device_key()
    return {'key': key_view(info), 'created': bool(created)}


def cmd_key_kit(svc, _req):
    info = svc.keys.device_key()
    if info is None:
        raise BackupError('no-device-key', '本設備尚未建立備份金鑰。')
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
    flows.resolve_apps(svc.catalog(), req['apps'])
    if svc.keys.device_key() is None:
        raise BackupError('no-device-key', '尚未建立本設備的備份金鑰，請先完成金鑰設定。')
    params = {'apps': list(req['apps']), 'include_images': bool(req.get('include_images', False)),
              'note': req.get('note', '')}
    return jobmod.start_job(svc.paths, 'backup', params, req['request_id'], launcher=svc.launcher,
                            unit_active=svc.unit_active, restart_writers=svc.restart_writers)


def cmd_verify_start(svc, req):
    svc.storage.get(req['backup_id'])
    params = {'backup_id': req['backup_id'], 'key_provided': 'key' in req}
    return jobmod.start_job(svc.paths, 'verify', params, req['request_id'], key_text=req.get('key'),
                            launcher=svc.launcher, unit_active=svc.unit_active,
                            restart_writers=svc.restart_writers)


def cmd_restore_start(svc, req):
    svc.storage.get(req['backup_id'])
    flows.resolve_apps(svc.catalog(), req['apps'])
    key_text = req.get('key')
    if key_text is not None and req.get('save_key'):
        svc.keys.import_key(key_text)
        key_text = None
    params = {'backup_id': req['backup_id'], 'apps': list(req['apps']), 'key_provided': key_text is not None}
    return jobmod.start_job(svc.paths, 'restore', params, req['request_id'], key_text=key_text,
                            launcher=svc.launcher, unit_active=svc.unit_active,
                            restart_writers=svc.restart_writers)


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
    active = jobmod.active_job(svc.paths)
    if active and (active.get('params') or {}).get('backup_id') == req['backup_id']:
        raise BackupError('busy', '此備份正被進行中的作業使用，請稍後再刪除。', job_id=active['id'])
    svc.storage.delete(req['backup_id'])
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
    return {'path': str(info['path']), 'filename': info['filename'], 'size': int(info['size'])}


COMMANDS = {
    'status': cmd_status, 'list': cmd_list, 'inspect': cmd_inspect, 'key-init': cmd_key_init,
    'key-kit': cmd_key_kit, 'key-confirm': cmd_key_confirm, 'key-import': cmd_key_import,
    'backup-start': cmd_backup_start, 'verify-start': cmd_verify_start, 'restore-start': cmd_restore_start,
    'job-status': cmd_job_status, 'jobs': cmd_jobs, 'job-cancel': cmd_job_cancel, 'delete': cmd_delete,
    'upload-begin': cmd_upload_begin, 'upload-finish': cmd_upload_finish, 'upload-abort': cmd_upload_abort,
    'download-info': cmd_download_info,
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
        record = jobmod.run_job(svc.paths, argv[1], deps=svc.deps)
        return {'state': record.get('state')}
    if command not in COMMANDS or len(argv) != 1:
        raise BackupError('invalid-request', '不支援的指令。')
    if command in NO_INPUT:
        request = {}
    else:
        request = validate(command, read_request(stdin if stdin is not None else sys.stdin))
    return COMMANDS[command](svc, request)


def _emit(stream, response):
    text = json.dumps(response, ensure_ascii=False, separators=(',', ':'), default=str)
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
