"""Install and remove trusted catalog entries from the page (`catalog-install`, `catalog-remove`).
Owner: catalog + retention engineer.

The catalog is the authority for every restore (CONTRACT section 4), so changing it is guarded like a restore:
* every entry passes `catalog.validate_entry` (the loader's own strict validator) plus checks across entries of the
  same owner (no unit, volume, database container, config file or host directory may belong to two apps);
* without `confirm` the commands only preview: validation result, a structured and a text diff against the
  installed entry, and zh-TW notes on what the change means for existing backups;
* with `confirm` the caller must send the sha256 of the entry it previewed (`expected_sha256`, null for "no entry
  yet"), so an entry changed meanwhile is never overwritten blindly;
* writes happen under the start lock while no job is queued or running, and never while a dead job still has
  recovery work for the app (its writers, fresh deployment or host directories are settled from this entry);
* the file is written root-owned 0644 via a temp file + rename in the root-owned catalog directory, the previous
  entry is kept in `apps-history/` (newest HISTORY_KEEP per app), and the catalog is reloaded afterwards: when the
  new entry (or an entry that loaded before) does not load, the previous state is put back and the call fails.
"""
import contextlib
import difflib
import errno
import hashlib
import json
import os
import re
import stat
import time

from . import catalog
from . import jobs
from .errors import BackupError

HISTORY_DIR = 'apps-history'
HISTORY_KEEP = 10
FILE_MODE = 0o644
DIR_MODE = 0o755
MAX_PREVIOUS_BYTES = 4 * catalog.MAX_ENTRY_BYTES
MAX_DIFF_LINES = 400
SHA256_RE = re.compile(r'[0-9a-f]{64}\Z')
HISTORY_RE = re.compile(r'(?P<id>[a-z0-9][a-z0-9-]{1,40})\.(?P<stamp>[0-9]{8}T[0-9]{6}Z)\.(?P<sha>[0-9a-f]{8})'
                        r'(?:-(?P<n>[0-9]{1,3}))?\.json\Z')
IDENTITY_KEYS = ('id', 'name', 'path', 'url')


# ---------------------------------------------------------------- diff

def _scalar(value):
    return value is None or isinstance(value, (str, int, float, bool))


def _identity(old, new):
    """The key that identifies the objects of two lists (`name` for volumes, `path` for directories...), or None."""
    items = list(old) + list(new)
    if not items or not all(isinstance(item, dict) for item in items):
        return None
    for key in IDENTITY_KEYS:
        if all(_scalar(item.get(key)) and key in item for item in items):
            if all(len({json.dumps(i[key]) for i in items_}) == len(items_) for items_ in (old, new)):
                return key
    return None


def diff_entries(old, new, path=''):
    """Structured differences between two JSON values: [{path, op: add|remove|change|order, old?, new?}].

    Objects are compared key by key, lists of objects by their identity key (`volumes[name=x].label`), lists of
    scalars as sets plus an `order` change."""
    changes = []
    if isinstance(old, dict) and isinstance(new, dict):
        for key in list(new) + [k for k in old if k not in new]:
            sub = f'{path}.{key}' if path else str(key)
            if key not in old:
                changes.append({'path': sub, 'op': 'add', 'new': new[key]})
            elif key not in new:
                changes.append({'path': sub, 'op': 'remove', 'old': old[key]})
            else:
                changes.extend(diff_entries(old[key], new[key], sub))
        return changes
    if isinstance(old, list) and isinstance(new, list):
        key = _identity(old, new)
        if key is not None:
            old_map = {json.dumps(item[key]): item for item in old}
            new_map = {json.dumps(item[key]): item for item in new}
            for ident, item in new_map.items():
                label = f'{path}[{key}={item[key]}]'
                if ident not in old_map:
                    changes.append({'path': label, 'op': 'add', 'new': item})
                else:
                    changes.extend(diff_entries(old_map[ident], item, label))
            for ident, item in old_map.items():
                if ident not in new_map:
                    changes.append({'path': f'{path}[{key}={item[key]}]', 'op': 'remove', 'old': item})
            common_old = [i for i in old_map if i in new_map]
            common_new = [i for i in new_map if i in old_map]
            if common_old != common_new:
                changes.append({'path': path, 'op': 'order', 'old': [old_map[i][key] for i in common_old],
                                'new': [new_map[i][key] for i in common_new]})
            return changes
        if all(_scalar(item) for item in old + new):
            added = [item for item in new if item not in old]
            removed = [item for item in old if item not in new]
            for item in added:
                changes.append({'path': f'{path}[]', 'op': 'add', 'new': item})
            for item in removed:
                changes.append({'path': f'{path}[]', 'op': 'remove', 'old': item})
            if not added and not removed and old != new:
                changes.append({'path': path, 'op': 'order', 'old': old, 'new': new})
            return changes
    if old != new or type(old) is not type(new):
        changes.append({'path': path, 'op': 'change', 'old': old, 'new': new})
    return changes


def pretty(entry):
    return json.dumps(entry, ensure_ascii=False, indent=2) + '\n'


def diff_text(old, new, name):
    """Unified diff of the pretty-printed entries (at most MAX_DIFF_LINES lines)."""
    before = pretty(old).splitlines() if old is not None else []
    after = pretty(new).splitlines() if new is not None else []
    lines = list(difflib.unified_diff(before, after, f'{name}（目前）', f'{name}（新）', lineterm='', n=3))
    if len(lines) > MAX_DIFF_LINES:
        lines = lines[:MAX_DIFF_LINES] + [f'…（還有 {len(lines) - MAX_DIFF_LINES} 行未顯示）']
    return lines


def _names(entry, key, ident):
    return [item.get(ident) for item in (entry or {}).get(key) or [] if isinstance(item, dict)]


def compat_notes(old, new, backups=0):
    """zh-TW notes on what replacing `old` by `new` means for the backups of this app (app-catalog.md
    "修改目錄項目的相容性"): items a backup must hold are added -> older backups cannot be restored under the new
    entry; removed items are skipped when an older backup is restored."""
    notes = []
    if old is None:
        return notes
    held = f'之前建立的 {backups} 份備份' if backups else '之前建立的備份'
    labels = (('volumes', 'name', '資料卷'), ('data_dirs', 'path', '主機資料夾'), ('secrets', 'name', '密鑰'),
              ('config_files', 'path', '設定檔'))
    for key, ident, label in labels:
        have, want = _names(old, key, ident), _names(new, key, ident)
        added = [item for item in want if item not in have]
        removed = [item for item in have if item not in want]
        if added:
            notes.append(f'新增{label} {"、".join(map(str, added[:5]))}：{held}不含這些項目，在新設定下無法還原此應用，'
                         '安裝後請重新備份。')
        if removed:
            notes.append(f'不再備份{label} {"、".join(map(str, removed[:5]))}；還原之前的備份時會略過這些項目。')
    old_pg = {json.dumps(item, sort_keys=True) for item in (old or {}).get('postgres') or []}
    new_pg = {json.dumps(item, sort_keys=True) for item in (new or {}).get('postgres') or []}
    if old_pg != new_pg:
        if not old_pg:
            notes.append(f'資料庫改以匯出方式備份（postgres 項目）：{held}以冷備份保存資料檔，在新設定下無法還原。')
        elif not new_pg:
            notes.append(f'資料庫改為冷備份：{held}只有資料庫匯出檔，在新設定下無法還原。')
        else:
            notes.append(f'資料庫的備份設定改變：{held}可能無法以新設定還原，安裝後請重新備份。')
    if (old or {}).get('owner') != (new or {}).get('owner'):
        notes.append('擁有者帳號改變：服務、資料卷與密鑰會以新的帳號操作。')
    if (old or {}).get('quadlet', {}).get('template_dir') and not (new or {}).get('quadlet', {}).get('template_dir'):
        notes.append('移除部署範本：之後只能原位還原，不能在尚未部署此應用的設備上還原。')
    return notes


# ---------------------------------------------------------------- trusted files

def _safe_dir(st, trusted_uid):
    return stat.S_ISDIR(st.st_mode) and st.st_uid == trusted_uid and not st.st_mode & 0o022


def open_trusted_dir(path, trusted_uid, *, create_in=None, name=None):
    """fd of a root-owned (`trusted_uid`), not group/world-writable directory that is not a symlink.

    With `create_in` (an fd of its trusted parent) and `name`, a missing directory is created there with 0755."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(name, flags, dir_fd=create_in) if create_in is not None else os.open(path, flags)
    except FileNotFoundError:
        if create_in is None:
            raise BackupError('internal-error', f'備份設定目錄 {path} 不存在，請重新安裝備份元件。', path=str(path)) from None
        with contextlib.suppress(FileExistsError):
            os.mkdir(name, DIR_MODE, dir_fd=create_in)
        fd = os.open(name, flags, dir_fd=create_in)
        st = os.fstat(fd)
        if st.st_uid == trusted_uid and stat.S_IMODE(st.st_mode) != DIR_MODE:
            os.fchmod(fd, DIR_MODE)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise BackupError('permission-denied', f'{path} 不是資料夾或是符號連結，已拒絕寫入。', path=str(path)) from None
        raise
    if not _safe_dir(os.fstat(fd), trusted_uid):
        os.close(fd)
        raise BackupError('permission-denied', f'{path} 必須由 root 擁有且不可讓其他帳號寫入，已拒絕寫入。', path=str(path))
    return fd


def read_trusted_file(dfd, name, *, max_bytes=MAX_PREVIOUS_BYTES):
    """{'data', 'sha256', 'mode', 'uid'} of a regular file in an open directory, or None when absent."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise BackupError('permission-denied', f'{name} 是符號連結；請先以 root 手動處理後再試。', file=name) from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise BackupError('permission-denied', f'{name} 不是一般檔案；請先以 root 手動處理後再試。', file=name)
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise BackupError('limit-exceeded', f'{name} 過大；請先以 root 手動處理後再試。', file=name)
            chunks.append(chunk)
    finally:
        os.close(fd)
    data = b''.join(chunks)
    return {'data': data, 'sha256': hashlib.sha256(data).hexdigest(), 'mode': stat.S_IMODE(st.st_mode),
            'uid': st.st_uid}


def write_trusted_file(dfd, name, data, *, mode=FILE_MODE):
    """Atomically replace `name` in the open directory: O_EXCL temp file (hidden, so the loader ignores it),
    fchmod, fsync, rename, fsync of the directory. Created by root, so it is root-owned."""
    tmp = f'.{name}.{os.urandom(6).hex()}.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fchmod(fd, mode)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        tmp = None
        os.fsync(dfd)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=dfd)


def unlink_trusted_file(dfd, name):
    os.unlink(name, dir_fd=dfd)
    os.fsync(dfd)


def _stamp(now=None):
    return time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(time.time() if now is None else now))


def keep_history(config_fd, app_id, previous, trusted_uid, now=None):
    """Copy the previous entry bytes to `apps-history/<id>.<stamp>.<sha8>.json` (0644); keep the newest
    HISTORY_KEEP of the app. Returns the file name."""
    hfd = open_trusted_dir(HISTORY_DIR, trusted_uid, create_in=config_fd, name=HISTORY_DIR)
    try:
        base = f'{app_id}.{_stamp(now)}.{previous["sha256"][:8]}'
        name, n = f'{base}.json', 1
        while _exists(hfd, name):
            n += 1
            name = f'{base}-{n}.json'
        write_trusted_file(hfd, name, previous['data'])
        _prune_history(hfd, app_id)
        return name
    finally:
        os.close(hfd)


def _exists(dfd, name):
    try:
        os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _prune_history(hfd, app_id):
    mine = []
    for name in os.listdir(hfd):
        match = HISTORY_RE.fullmatch(name)
        if match and match.group('id') == app_id:
            mine.append((match.group('stamp'), int(match.group('n') or 1), name))
    mine.sort(reverse=True)
    for _stamp_, _n, name in mine[HISTORY_KEEP:]:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name, dir_fd=hfd)


def history(paths, app_id, *, trusted_uid=0):
    """Names of the kept previous versions of an entry, newest first."""
    try:
        cfd = open_trusted_dir(paths.config, trusted_uid)
    except BackupError:
        return []
    try:
        try:
            hfd = os.open(HISTORY_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=cfd)
        except OSError:
            return []
        try:
            rows = [(m.group('stamp'), int(m.group('n') or 1), name) for name in os.listdir(hfd)
                    for m in [HISTORY_RE.fullmatch(name)] if m and m.group('id') == app_id]
        finally:
            os.close(hfd)
    finally:
        os.close(cfd)
    return [name for _s, _n, name in sorted(rows, reverse=True)]


# ---------------------------------------------------------------- validation

def serialize(entry):
    """The bytes installed for `entry`: pretty UTF-8 JSON, at most catalog.MAX_ENTRY_BYTES."""
    if not isinstance(entry, dict):
        raise BackupError('invalid-request', '應用設定必須是 JSON 物件。', field='')
    try:
        data = pretty(entry).encode('utf-8')
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        raise BackupError('invalid-request', '應用設定含有無法儲存的值。', field='') from None
    if len(data) > catalog.MAX_ENTRY_BYTES:
        raise BackupError('limit-exceeded', f'應用設定超過 {catalog.MAX_ENTRY_BYTES // 1024} KiB。', field='')
    return data


def validate(paths, entry, *, user_lookup=None):
    """(App, bytes) of an entry that the loader would accept; raises BackupError with `details.field`."""
    data = serialize(entry)
    try:
        parsed = catalog.parse_json_bytes(data)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise BackupError('invalid-request', '應用設定不是有效的 JSON。', field='') from None
    app = catalog.validate_entry(parsed, paths=paths, sha256=hashlib.sha256(data).hexdigest(), user_lookup=user_lookup)
    return app, data


def _app_items(app):
    """Everything of an app another app of the same owner must not also manage."""
    return {
        'units': set(app.units),
        'volumes': {v['name'] for v in app.volumes} | {p['data_volume'] for p in app.postgres},
        'containers': {p['container'] for p in app.postgres},
        'configs': {c['path'] for c in app.config_files},
        'dirs': {d['path'] for d in app.data_dirs},
        'secrets': {s['name'] for s in app.secrets},
        'files': set(app.quadlet_files),
    }


def conflicts(app, others):
    """(errors, warnings) zh-TW: what `app` would share with the other loaded apps of the same owner."""
    errors, warnings = [], []
    mine = _app_items(app)
    for other in sorted(others, key=lambda a: a.id):
        if other.id == app.id or other.owner != app.owner:
            continue
        theirs = _app_items(other)
        for key, label in (('units', '服務'), ('volumes', '資料卷'), ('containers', '資料庫容器'), ('configs', '設定檔')):
            for item in sorted(mine[key] & theirs[key])[:3]:
                errors.append(f'{label} {item} 已屬於應用「{other.id}」；同一個項目不可由兩個應用設定管理。')
        for mine_dir in sorted(mine['dirs']):
            for their in sorted(theirs['dirs'] | theirs['configs']):
                if catalog.paths_overlap(mine_dir, their):
                    errors.append(f'主機資料夾 ~/{mine_dir} 與應用「{other.id}」的 ~/{their} 重疊。')
        for config in sorted(mine['configs']):
            for their in sorted(theirs['dirs']):
                if catalog.paths_overlap(config, their):
                    errors.append(f'設定檔 ~/{config} 位於應用「{other.id}」的主機資料夾 ~/{their} 中。')
        for item in sorted(mine['secrets'] & theirs['secrets'])[:3]:
            warnings.append(f'密鑰 {item} 也屬於應用「{other.id}」：還原任一應用都會以備份內容重建它。')
        for item in sorted(mine['files'] & theirs['files'])[:3]:
            warnings.append(f'Quadlet 檔 {item} 也屬於應用「{other.id}」：全新部署或移除時會影響兩個應用。')
    return errors, warnings


def _loaded(paths, trusted_uid, user_lookup):
    return catalog.load_catalog(paths, trusted_uid=trusted_uid, user_lookup=user_lookup)


def _backups_of(backups, app_id):
    return sum(1 for b in backups or [] if app_id in {a.get('id') for a in b.get('apps') or [] if isinstance(a, dict)})


def _current(paths, app_id, trusted_uid):
    """Raw installed entry of `app_id` ({'data', 'sha256', 'entry'|None}) or None; read without following links."""
    try:
        cfd = open_trusted_dir(paths.catalog, trusted_uid)
    except BackupError as error:
        if error.code == 'internal-error':  # the directory does not exist yet: no entry
            return None
        raise
    try:
        current = read_trusted_file(cfd, f'{app_id}.json')
    finally:
        os.close(cfd)
    if current is None:
        return None
    try:
        current['entry'] = catalog.parse_json_bytes(current['data'])
    except (ValueError, UnicodeDecodeError, RecursionError):
        current['entry'] = None
    return current


def _current_view(current):
    if current is None:
        return None
    return {'sha256': current['sha256'], 'entry': current['entry'],
            'owner': current['entry'].get('owner') if isinstance(current['entry'], dict) else None}


# ---------------------------------------------------------------- commands

def preview_install(paths, entry, *, backups=None, user_lookup=None, trusted_uid=0):
    """`catalog-install` without confirm: validation, diff and notes; nothing is written."""
    result = {'preview': True, 'valid': False, 'error': None, 'id': None, 'file': None, 'current': None,
              'expected_sha256': None, 'new_sha256': None, 'changes': [], 'diff': [], 'compat': [], 'warnings': [],
              'backups': 0, 'history': []}
    app_id = entry.get('id') if isinstance(entry, dict) else None
    if isinstance(app_id, str) and catalog.ID_RE.fullmatch(app_id):
        result['id'], result['file'] = app_id, f'{app_id}.json'
        current = _current(paths, app_id, trusted_uid)
        result['current'] = _current_view(current)
        result['expected_sha256'] = current['sha256'] if current else None
        old = current['entry'] if current else None
        if isinstance(entry, dict):
            result['changes'] = diff_entries(old, entry) if isinstance(old, dict) else []
            result['diff'] = diff_text(old if isinstance(old, dict) else None, entry, result['file'])
        result['backups'] = _backups_of(backups, app_id)
        result['history'] = history(paths, app_id, trusted_uid=trusted_uid)
        if isinstance(old, dict) and isinstance(entry, dict):
            result['compat'] = compat_notes(old, entry, result['backups'])
        if current is not None and current['entry'] is None:
            result['warnings'].append('目前安裝的設定檔不是有效的 JSON（不會被載入）；安裝會取代它，舊檔案保留在 apps-history。')
    try:
        app, data = validate(paths, entry, user_lookup=user_lookup)
        refusal = owner_change(current if result['id'] else None, app)
        if refusal:
            raise BackupError('invalid-request', refusal, field='owner', reason='owner-change')
        errors, warnings = conflicts(app, _loaded(paths, trusted_uid, user_lookup).values())
        result['warnings'].extend(warnings)
        if errors:
            raise BackupError('invalid-request', errors[0], conflicts=errors[:10])
    except BackupError as error:
        result['error'] = error.as_dict()
        return result
    result.update(valid=True, new_sha256=hashlib.sha256(data).hexdigest())
    if app.template_dir is None:
        result['warnings'].append('沒有部署範本（quadlet.template_dir）：只能在已部署此應用的設備上原位還原。')
    elif not os.path.isdir(app.template_dir):
        result['warnings'].append(f'部署範本目錄 {app.template_dir} 不存在：全新部署還原會失敗。')
    if result['current'] and result['expected_sha256'] == result['new_sha256']:
        result['warnings'].append('與目前安裝的設定完全相同。')
    return result


def _refuse_busy(paths, app_id):
    """busy while a job is queued/running, or while a finished job still has recovery work for this app."""
    active = jobs.active_job(paths)
    if active is not None:
        raise BackupError('busy', '有備份或還原作業正在進行，請等作業完成後再變更應用設定。', job_id=active['id'])
    for record in jobs.JobStore(paths).list(limit=None):
        if not jobs.has_leftovers(record):
            continue
        apps = set(record.get('stopped_writers') or {}) | set(record.get('fresh_apps') or []) | \
            set(record.get('dir_apps') or [])
        if app_id in apps:
            raise BackupError('busy', '這個應用還有中斷作業的整理工作尚未完成（例如重新啟動服務或整理主機資料夾），'
                                      '請先開啟「備份與還原」頁讓系統完成整理後再變更它的設定。', job_id=record['id'])


def owner_change(current, app):
    """zh-TW refusal when `app` would move an installed entry of the same id to another owner, else None (review M3):
    the entry's backups (that owner's secrets, dumps and volumes) would then restore into the new owner's account and
    count toward its retention. The administrator removes the entry first (catalog-remove), then installs."""
    old = current.get('entry') if isinstance(current, dict) else None
    owner = old.get('owner') if isinstance(old, dict) else None
    if isinstance(owner, str) and owner != app.owner:
        return (f'應用「{app.id}」目前屬於帳號 {owner[:32]}，不能直接改成帳號 {app.owner}：它的備份會被還原到新的帳號。'
                '若確實要改，請先移除這個應用設定，再以新的帳號安裝（或改用其他 ID）。')
    return None


def _check_expected(current, expected):
    have = current['sha256'] if current else None
    if expected != have:
        raise BackupError('invalid-request', '應用設定在你檢視之後已被變更，請重新檢視差異後再確認。',
                          reason='entry-changed', current_sha256=have)


def audit_log(message):
    try:
        import syslog
        syslog.openlog('woowtech-cockpit-backup', 0, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_NOTICE, message)
    except Exception:  # noqa: BLE001 - auditing must never break the command
        pass


def login_uid():
    """Audit login uid of the Cockpit session that runs the helper (survives sudo), or None."""
    try:
        with open('/proc/self/loginuid', 'rb') as handle:
            value = int(handle.read(32).strip() or b'-1')
    except (OSError, ValueError):
        return None
    return None if value < 0 or value == 4294967295 else value


def _shown(value):
    return '-' if value is None else value


def install(paths, entry, expected_sha256, *, backups=None, user_lookup=None, trusted_uid=0, audit=None, now=None):
    """`catalog-install` with confirm: validate, check, write `<id>.json` (root 0644), keep the previous entry."""
    audit = audit or audit_log
    app, data = validate(paths, entry, user_lookup=user_lookup)
    new_sha = hashlib.sha256(data).hexdigest()
    with jobs.start_lock(paths):
        _refuse_busy(paths, app.id)
        before = _loaded(paths, trusted_uid, user_lookup)
        errors, warnings = conflicts(app, before.values())
        if errors:
            raise BackupError('invalid-request', errors[0], conflicts=errors[:10])
        cfd = open_trusted_dir(paths.config, trusted_uid)
        try:
            afd = open_trusted_dir(paths.catalog, trusted_uid, create_in=cfd, name=paths.catalog.name)
            try:
                name = f'{app.id}.json'
                current = read_trusted_file(afd, name)
                _check_expected(current, expected_sha256)
                old = None
                if current is not None:
                    with contextlib.suppress(ValueError, UnicodeDecodeError, RecursionError):
                        old = catalog.parse_json_bytes(current['data'])
                refusal = owner_change({'entry': old}, app)
                if refusal:
                    raise BackupError('invalid-request', refusal, field='owner', reason='owner-change')
                backup_name = keep_history(cfd, app.id, current, trusted_uid, now) if current is not None else None
                write_trusted_file(afd, name, data)
                try:
                    _verify_load(paths, app.id, new_sha, before, trusted_uid, user_lookup)
                except BackupError:
                    if current is not None:
                        write_trusted_file(afd, name, current['data'], mode=stat.S_IMODE(current['mode']) & 0o644)
                    else:
                        with contextlib.suppress(FileNotFoundError):
                            unlink_trusted_file(afd, name)
                    raise
            finally:
                os.close(afd)
        finally:
            os.close(cfd)
    count = _backups_of(backups, app.id)
    audit(f'catalog-install id={app.id} owner={app.owner} sha256={new_sha} '
          f'previous={current["sha256"] if current else "-"} loginuid={_shown(login_uid())}')
    return {'installed': True, 'id': app.id, 'file': f'{app.id}.json', 'sha256': new_sha,
            'previous': {'sha256': current['sha256'], 'backup': backup_name} if current else None,
            'changes': diff_entries(old, json.loads(data)) if isinstance(old, dict) else [],
            'compat': compat_notes(old, json.loads(data), count) if isinstance(old, dict) else [],
            'warnings': warnings, 'backups': count}


def _verify_load(paths, app_id, sha, before, trusted_uid, user_lookup):
    """The reloaded catalog holds the new entry with these bytes and every app that loaded before."""
    after = _loaded(paths, trusted_uid, user_lookup)
    app = after.get(app_id)
    if app is None or app.sha256 != sha:
        problem = after.problem_for(app_id) if hasattr(after, 'problem_for') else None
        reason = problem['message'] if problem else '新的應用設定沒有被載入'
        raise BackupError('invalid-request', f'安裝後重新載入失敗（{reason}），已恢復原本的設定。', app=app_id)
    lost = sorted(set(before) - set(after) - {app_id})
    if lost:
        raise BackupError('invalid-request', f'安裝後應用「{lost[0]}」無法再載入（例如主機資料夾重疊），已恢復原本的設定。',
                          app=app_id, lost=lost[:10])


def preview_remove(paths, app_id, *, backups=None, trusted_uid=0):
    """`catalog-remove` without confirm: what would be removed; nothing is changed."""
    _check_id(app_id)
    current = _current(paths, app_id, trusted_uid)
    if current is None:
        raise BackupError('not-found', f'沒有安裝應用「{app_id}」的設定。', app=app_id)
    count = _backups_of(backups, app_id)
    warnings = [f'這個應用的 {count} 份備份會保留，但在重新安裝它的應用設定之前無法還原。'] if count else []
    return {'preview': True, 'id': app_id, 'file': f'{app_id}.json', 'current': _current_view(current),
            'expected_sha256': current['sha256'], 'backups': count, 'warnings': warnings,
            'history': history(paths, app_id, trusted_uid=trusted_uid),
            'diff': diff_text(current['entry'] if isinstance(current['entry'], dict) else None, None, f'{app_id}.json')}


def _check_id(app_id):
    if not isinstance(app_id, str) or not catalog.ID_RE.fullmatch(app_id):
        raise BackupError('invalid-request', '應用 ID 格式不正確。', field='id')


def remove(paths, app_id, expected_sha256, *, backups=None, trusted_uid=0, audit=None, now=None):
    """`catalog-remove` with confirm: move `<id>.json` to `apps-history/` (the app's backups are kept)."""
    _check_id(app_id)
    audit = audit or audit_log
    with jobs.start_lock(paths):
        _refuse_busy(paths, app_id)
        cfd = open_trusted_dir(paths.config, trusted_uid)
        try:
            try:
                afd = open_trusted_dir(paths.catalog, trusted_uid)
            except BackupError as error:
                if error.code == 'internal-error':
                    raise BackupError('not-found', f'沒有安裝應用「{app_id}」的設定。', app=app_id) from None
                raise
            try:
                name = f'{app_id}.json'
                current = read_trusted_file(afd, name)
                if current is None:
                    raise BackupError('not-found', f'沒有安裝應用「{app_id}」的設定。', app=app_id)
                _check_expected(current, expected_sha256)
                backup_name = keep_history(cfd, app_id, current, trusted_uid, now)
                unlink_trusted_file(afd, name)
            finally:
                os.close(afd)
        finally:
            os.close(cfd)
    audit(f'catalog-remove id={app_id} sha256={current["sha256"]} loginuid={_shown(login_uid())}')
    count = _backups_of(backups, app_id)
    return {'removed': True, 'id': app_id, 'sha256': current['sha256'], 'backup': backup_name, 'backups': count}
