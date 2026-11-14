"""Storage usage per app and keep-last-N retention of manual backups (`retention-plan`, `retention-apply`).
Owner: catalog + retention engineer.

* Policy: `/etc/woowtech-cockpit/backup/retention.json` (root 0644, next to the catalog), schema 1:
  `{"schema": 1, "default_keep_last": null|N, "apps": {"<app id>": {"keep_last": null|N}}}`, N in 1..1000. An app
  without its own value uses the default; `null` keeps every manual backup. Only `manual` backups are counted and
  deleted: `safety` backups keep their own rule (3 newest per app after a successful restore, CONTRACT section 9)
  and `uploaded` backups are only ever deleted by an explicit selection.
* A manual backup is deleted by the policy only when it is outside the newest N manual backups of *every* app it
  holds (a backup of two apps stays while either app still needs it), and never while it is protected. A backup whose
  verification failed (`verified.ok` false) does not count toward N and is a candidate itself (review M1):
  - the source or safety backup of a queued/running job, and every safety backup while a restore is queued/running;
  - the safety backup a failed or interrupted (not rolled back) restore still pins (`jobs.pinned_safety_records`), and
    that restore's source backup (also when it had no safety backup but changed the apps; review M2, or when its
    pre-restore copy is not packaged yet or could not be, whatever its state), until a later restore of its apps
    succeeded;
  - everything, while a job record cannot be read (review F11).
* `retention-plan` previews (optionally with a proposed policy), `retention-apply` saves the policy and deletes
  exactly the backup ids the administrator confirmed that are still not protected, under the start lock (like
  `delete`); `enforce_after_backup` applies the saved policy to the apps of a manual backup that just succeeded.
  Every deletion and policy change is written to the system journal (audit).
"""
import json
import os
import re

from . import catalog
from . import jobs
from .catalog_admin import audit_log, login_uid, open_trusted_dir, pretty, read_trusted_file, write_trusted_file
from .errors import BackupError

POLICY_FILE = 'retention.json'
SCHEMA = 1
MAX_KEEP = 1000
MAX_APPS = 500
MAX_IDS = 500
BACKUP_ID_RE = re.compile(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
TYPES = ('manual', 'safety', 'uploaded')


# ---------------------------------------------------------------- policy

def default_policy():
    return {'schema': SCHEMA, 'default_keep_last': None, 'apps': {}}


def _bad(field, text):
    return BackupError('invalid-request', f'保留原則 {field} {text}', field=field)


def _keep(value, field):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_KEEP:
        raise _bad(field, f'必須是 1 到 {MAX_KEEP} 的整數，或 null（全部保留）。')
    return value


def validate_policy(data):
    """Strictly validated, normalized policy (unknown keys rejected)."""
    if not isinstance(data, dict):
        raise _bad('', '必須是 JSON 物件。')
    unknown = sorted(set(data) - {'schema', 'default_keep_last', 'apps'})
    if unknown:
        raise _bad('', f'含有不支援的欄位：{", ".join(str(k)[:40] for k in unknown[:5])}。')
    if 'schema' in data and (isinstance(data['schema'], bool) or data['schema'] != SCHEMA):
        raise _bad('schema', f'必須為 {SCHEMA}。')
    default = _keep(data.get('default_keep_last'), 'default_keep_last')
    apps = data.get('apps', {})
    if not isinstance(apps, dict) or len(apps) > MAX_APPS:
        raise _bad('apps', f'必須是最多 {MAX_APPS} 個應用的物件。')
    normalized = {}
    for app_id in sorted(apps):
        item = apps[app_id]
        where = f'apps.{str(app_id)[:41]}'
        if not isinstance(app_id, str) or not catalog.ID_RE.fullmatch(app_id):
            raise _bad(where, '的應用 ID 格式不正確。')
        if not isinstance(item, dict) or set(item) != {'keep_last'}:
            raise _bad(where, '必須是只有 keep_last 的物件。')
        normalized[app_id] = {'keep_last': _keep(item['keep_last'], f'{where}.keep_last')}
    return {'schema': SCHEMA, 'default_keep_last': default, 'apps': normalized}


def load_policy(paths, *, trusted_uid=0):
    """(policy, problem): the saved policy, or the default (keep everything) and a zh-TW problem when the file is
    unsafe or invalid -- an unreadable policy never deletes anything."""
    try:
        cfd = open_trusted_dir(paths.config, trusted_uid)
    except BackupError as error:
        return default_policy(), (None if error.code == 'internal-error' else error.message)
    try:
        current = read_trusted_file(cfd, POLICY_FILE, max_bytes=256 * 1024)
    except (BackupError, OSError):
        return default_policy(), '保留原則設定檔無法讀取，暫時全部保留。'
    finally:
        os.close(cfd)
    if current is None:
        return default_policy(), None
    if current['uid'] != trusted_uid or current['mode'] & 0o022:
        return default_policy(), '保留原則設定檔必須由 root 擁有且不可讓其他帳號寫入，暫時全部保留。'
    try:
        return validate_policy(catalog.parse_json_bytes(current['data'])), None
    except (BackupError, ValueError, UnicodeDecodeError, RecursionError):
        return default_policy(), '保留原則設定檔格式不正確，暫時全部保留；請重新儲存保留原則。'


def save_policy(paths, policy, *, trusted_uid=0):
    normalized = validate_policy(policy)
    cfd = open_trusted_dir(paths.config, trusted_uid)
    try:
        write_trusted_file(cfd, POLICY_FILE, pretty(normalized).encode('utf-8'))
    finally:
        os.close(cfd)
    return normalized


def keep_last(policy, app_id):
    item = (policy.get('apps') or {}).get(app_id)
    if item is not None:
        return item.get('keep_last')
    return policy.get('default_keep_last')


# ---------------------------------------------------------------- usage

def _apps_of(backup):
    return [a for a in backup.get('apps') or [] if isinstance(a, dict) and isinstance(a.get('id'), str)]


def _shares(backup, items):
    """(bytes per app, estimated): per-app sizes when the index records them, else an even split."""
    size = int(backup.get('size') or 0)
    sizes = [a.get('size') for a in items]
    if all(type(s) is int and s >= 0 for s in sizes) and sum(sizes) > 0:
        total = sum(sizes)
        shares = [size * s // total for s in sizes]
        shares[0] += size - sum(shares)
        return shares, False
    base = size // len(items)
    shares = [base] * len(items)
    shares[0] += size - base * len(items)
    return shares, len(items) > 1


def app_usage(backups, catalog_apps=None, policy=None):
    """Per-app storage: `apps` (largest first; catalog apps without backups included), `unassigned` (uploaded
    backups not inspected yet, whose apps are unknown) and `total`. A backup of several apps is split between them
    (by per-app size when the index has it, else evenly: `estimated`)."""
    policy = policy or default_policy()
    rows = {}

    def row(app_id, name):
        if app_id not in rows:
            rows[app_id] = {'id': app_id, 'name': name or app_id, 'in_catalog': False, 'backups': 0,
                            'types': {'manual': 0, 'safety': 0, 'uploaded': 0}, 'bytes': 0, 'estimated': False,
                            'shared': False, 'newest': None, 'oldest': None, 'keep_last': keep_last(policy, app_id)}
        return rows[app_id]

    for app in (catalog_apps or {}).values():
        row(app.id, app.name)['in_catalog'] = True
    unassigned = {'backups': 0, 'bytes': 0}
    total = {'backups': 0, 'bytes': 0}
    for backup in backups:
        size = int(backup.get('size') or 0)
        total['backups'] += 1
        total['bytes'] += size
        items = _apps_of(backup)
        if not items:
            unassigned['backups'] += 1
            unassigned['bytes'] += size
            continue
        shares, estimated = _shares(backup, items)
        created = backup.get('created')
        for item, share in zip(items, shares):
            entry = row(item['id'], item.get('name'))
            entry['backups'] += 1
            kind = backup.get('type')
            if kind in entry['types']:
                entry['types'][kind] += 1
            entry['bytes'] += share
            entry['estimated'] = entry['estimated'] or estimated
            entry['shared'] = entry['shared'] or len(items) > 1
            if isinstance(created, str):
                entry['newest'] = max(entry['newest'] or created, created)
                entry['oldest'] = min(entry['oldest'] or created, created)
    ordered = sorted(rows.values(), key=lambda r: (-r['bytes'], r['id']))
    return {'apps': ordered, 'unassigned': unassigned, 'total': total}


# ---------------------------------------------------------------- protection and plan

def protected_backups(paths, backups=()):
    """{backup id: zh-TW reason} of backups retention must never delete (see the module docstring)."""
    unreadable = []
    try:
        records = jobs.JobStore(paths).list(limit=None, unreadable=unreadable)
    except Exception:  # noqa: BLE001 - unreadable records: protect everything rather than guess
        unreadable.append('*')
    if unreadable:
        # A record that cannot be read may be a failed restore that still pins its backups (review F11).
        return {b['id']: '無法讀取作業紀錄，暫不刪除。' for b in backups if isinstance(b.get('id'), str)}
    reasons, restore_active = {}, False
    for record in records:
        if record.get('state') not in jobs.ACTIVE:
            continue
        params = record.get('params') if isinstance(record.get('params'), dict) else {}
        source = params.get('backup_id')
        if isinstance(source, str):
            reasons[source] = '正被進行中的作業使用。'
        result = record.get('result') if isinstance(record.get('result'), dict) else {}
        safety = record.get('safety_backup_id') or result.get('safety_backup_id')
        if isinstance(safety, str):
            reasons[safety] = '進行中的還原剛建立的還原前備份。'
        if record.get('type') == 'restore':
            restore_active = True
    by_id = {record.get('id'): record for record in records}
    for record_id, safety in jobs.pinned_safety_records(records).items():
        if isinstance(safety, str):
            reasons.setdefault(safety, '失敗或中斷的還原仍需要這份還原前備份才能回到還原前的狀態。')
        record = by_id.get(record_id) or {}
        params = record.get('params')
        source = params.get('backup_id') if isinstance(params, dict) else None
        if isinstance(source, str):
            reasons.setdefault(source, '還原前資料尚未封裝成還原前備份的還原使用這份備份；在該應用之後成功還原之前保留。'
                               if record.get('safety_pending') or record.get('safety_pending_failed')
                               else '失敗或中斷的還原使用這份備份；在該應用成功還原之前保留。')
    if restore_active:
        for backup in backups:
            if backup.get('type') == 'safety' and isinstance(backup.get('id'), str):
                reasons.setdefault(backup['id'], '還原作業進行中時不刪除還原前備份（失敗時可能需要它自動回復）。')
    return reasons


def brief(backup, reason=None):
    view = {'id': backup.get('id'), 'type': backup.get('type'), 'created': backup.get('created'),
            'size': int(backup.get('size') or 0), 'note': backup.get('note') or '',
            'apps': [{'id': a['id'], 'name': a.get('name') or a['id']} for a in _apps_of(backup)]}
    if reason is not None:
        view['reason'] = reason
    return view


def _sort_key(backup):
    return (backup.get('created') or '', backup.get('id') or '')


def failed_verification(backup):
    """True when the verify job found the backup's content unusable (`verified.ok` false)."""
    verified = backup.get('verified')
    return isinstance(verified, dict) and verified.get('ok') is False


def plan(backups, policy, protected, *, only_apps=None):
    """Manual backups the policy would delete (`candidates`, oldest last), with zh-TW reasons, and the candidates
    that are protected (`blocked`). `only_apps`: only backups holding one of these apps are considered.

    A backup whose verification failed does not count toward an app's newest N (it cannot be restored): it is a
    candidate itself, and the N kept are the newest backups that did not fail (review M1)."""
    manual = sorted((b for b in backups if b.get('type') == 'manual' and isinstance(b.get('id'), str)),
                    key=_sort_key, reverse=True)
    rank, positions = {}, {}
    for backup in manual:
        positions[backup['id']] = {}
        if failed_verification(backup):
            continue
        for item in _apps_of(backup):
            rank[item['id']] = rank.get(item['id'], 0) + 1
            positions[backup['id']][item['id']] = rank[item['id']]
    candidates, blocked = [], []
    for backup in manual:
        items = _apps_of(backup)
        if not items:
            continue
        if only_apps is not None and not {item['id'] for item in items} & set(only_apps):
            continue
        limits = {item['id']: keep_last(policy, item['id']) for item in items}
        if any(limit is None for limit in limits.values()):
            continue
        if failed_verification(backup):
            reason = '驗證未通過（這份備份無法還原），不計入保留份數。'
        else:
            place = positions[backup['id']]
            if not all(place[app_id] > limit for app_id, limit in limits.items()):
                continue
            reason = '超出保留份數：' + '、'.join(
                f'「{item.get("name") or item["id"]}」第 {place[item["id"]]} 新（保留最新 {limits[item["id"]]} 份）'
                for item in items)
        if backup['id'] in protected:
            blocked.append(brief(backup, protected[backup['id']]))
        else:
            candidates.append(brief(backup, reason))
    return {'candidates': candidates, 'blocked': blocked,
            'freed_bytes': sum(item['size'] for item in candidates)}


def plan_command(paths, storage, catalog_apps=None, proposed=None, *, trusted_uid=0):
    """`retention-plan`: usage per app, the saved policy, and what the (proposed or saved) policy would delete."""
    saved, problem = load_policy(paths, trusted_uid=trusted_uid)
    policy = validate_policy(proposed) if proposed is not None else saved
    backups = storage.list_backups()
    protected = protected_backups(paths, backups)
    result = plan(backups, policy, protected)
    listed = {b['id']: b for b in backups if isinstance(b.get('id'), str)}
    return {'policy': policy, 'saved_policy': saved, 'proposed': proposed is not None, 'policy_problem': problem,
            'usage': app_usage(backups, catalog_apps, policy), 'candidates': result['candidates'],
            'blocked': result['blocked'], 'freed_bytes': result['freed_bytes'],
            'protected': [brief(listed[backup_id], reason) for backup_id, reason in sorted(protected.items())
                          if backup_id in listed]}


def _check_ids(backup_ids):
    if not isinstance(backup_ids, list) or len(backup_ids) > MAX_IDS:
        raise BackupError('invalid-request', f'欄位 backup_ids 必須是最多 {MAX_IDS} 個備份 ID 的陣列。', field='backup_ids')
    for item in backup_ids:
        if not isinstance(item, str) or not BACKUP_ID_RE.fullmatch(item):
            raise BackupError('invalid-request', '欄位 backup_ids 含有格式不正確的備份 ID。', field='backup_ids')
    if len(set(backup_ids)) != len(backup_ids):
        raise BackupError('invalid-request', '欄位 backup_ids 含有重複的備份 ID。', field='backup_ids')
    return list(backup_ids)


def apply_command(paths, storage, backup_ids, *, policy=None, trusted_uid=0, audit=None):
    """`retention-apply` (confirmed): save `policy` when given, then delete the confirmed backups that are not
    protected now. Decided under the start lock, so no job can start in between (like `delete`)."""
    audit = audit or audit_log
    backup_ids = _check_ids(backup_ids)
    normalized = validate_policy(policy) if policy is not None else None
    deleted, skipped, freed = [], [], 0
    user = login_uid()
    with jobs.start_lock(paths):
        if normalized is not None:
            save_policy(paths, normalized, trusted_uid=trusted_uid)
            audit(f'retention-policy default={normalized["default_keep_last"]} '
                  f'apps={json.dumps(normalized["apps"], sort_keys=True, separators=(",", ":"))} '
                  f'loginuid={"-" if user is None else user}')
        backups = {b['id']: b for b in storage.list_backups() if isinstance(b.get('id'), str)}
        protected = protected_backups(paths, list(backups.values()))
        for backup_id in backup_ids:
            backup = backups.get(backup_id)
            if backup is None:
                skipped.append({'id': backup_id, 'reason': '找不到這份備份（可能已被刪除）。'})
                continue
            if backup_id in protected:
                skipped.append({'id': backup_id, 'reason': protected[backup_id]})
                continue
            try:
                storage.delete(backup_id)
            except BackupError as error:
                skipped.append({'id': backup_id, 'reason': error.message})
                continue
            deleted.append(brief(backup))
            freed += int(backup.get('size') or 0)
            audit(f'retention-delete backup={backup_id} type={backup.get("type")} size={int(backup.get("size") or 0)} '
                  f'apps={",".join(a["id"] for a in _apps_of(backup)) or "-"} loginuid={"-" if user is None else user}')
    saved, problem = load_policy(paths, trusted_uid=trusted_uid)
    return {'policy': saved, 'policy_problem': problem, 'deleted': deleted, 'skipped': skipped, 'freed_bytes': freed}


def enforce_after_backup(paths, storage, app_ids, *, exclude=(), log=None, audit=None, trusted_uid=0):
    """Apply the saved policy to the manual backups of `app_ids` after a manual backup of them succeeded (called
    by the backup job, which holds the engine lock; no other job can run). Returns the deleted backup ids; never
    raises for a deletion problem (it is logged) and deletes nothing when the policy cannot be read."""
    log = log or (lambda _message: None)
    audit = audit or audit_log
    policy, problem = load_policy(paths, trusted_uid=trusted_uid)
    if problem:
        log(f'警告：{problem}')
        return []
    if not any(keep_last(policy, app_id) is not None for app_id in app_ids):
        return []
    backups = storage.list_backups()
    protected = protected_backups(paths, backups)
    for backup_id in exclude or ():
        protected.setdefault(backup_id, '剛建立的備份。')
    deleted = []
    for item in plan(backups, policy, protected, only_apps=set(app_ids))['candidates']:
        try:
            storage.delete(item['id'])
        except BackupError as error:
            log(f'警告：無法依保留原則刪除備份 {item["id"]}（{error.message}）')
            continue
        deleted.append(item['id'])
        log(f'已依保留原則刪除較舊的手動備份 {item["id"]}（{item["reason"]}）')
        audit(f'retention-delete backup={item["id"]} type=manual size={item["size"]} '
              f'apps={",".join(a["id"] for a in item["apps"])} reason=policy')
    return deleted
