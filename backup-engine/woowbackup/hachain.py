"""One Home Assistant import is a chain of single-app jobs (HAOS parity, lane F2; DESIGN C3-C6, option S). Owner: E2.

`ha-import-start` writes the first job, the conversion of the first app (`params.group`, `params.chain`; cli.py).
`run-job` (jobs.run_job) runs it and, in the same process and under the same engine lock, every job that follows it:
convert A, restore A (when the import restores), convert B, restore B, ... Each job is the ordinary single-app job of today
(haimport.run_ha_convert, flows.run_restore), so a problem of one app stops that app only: its own safety backup and its
own automatic rollback are the restore job's, and the chain goes on with the next app.

Before a job's record is finished, `conclude` decides what comes next and writes the next job's record, queued; only then is
the finished job's record written. There is never a moment without a queued or running job of the import, so `start_job` of
anything else says `busy`, and a recovery pass cannot take the queued job for a dead one (it needs the engine lock to
decide, and every job of the import carries the unit of the first one). The HA key is handed from job to job in memory only
(`ctx.ha_key`, masked the whole time); the key file goes with the first job.

What ends the whole import (the apps not reached are `not-started`, with the reason): the customer's cancel (`job-cancel`,
also when it came a moment too late for the job it named), a termination signal, a key that opens nothing, an HA file that is
damaged itself, a disk that is still full after a job ran it full, the engine's own errors. "Stop after this app"
(`job-cancel` with `after_this`, a side file named after the group) lets the app that is being worked on finish: its restore
still follows its conversion. Everything else (a conversion that fails, a restore that is refused, rolled back, or cannot be
rolled back and needs a person) is that app's: its result says so and the next app goes on.

Every job of a chain has `params.group` (`{id, index, count, kind, step, app_id}`: `kind` `ha-import` | `ha-restore`, `step`
`convert` | `restore`, `index` the app's place in `params.chain.apps`) and `params.chain` (what the rest of the import
needs, and `results`: the GroupResults of the apps that are done or left out). The finished job's `result.group` is `{id,
index, count, step, next_job_id, results}` with every GroupResult known so far, so a page needs only the newest job (or
`jobs`, by `params.group.id`, after a reload). A process that is killed leaves records that recovery marks `interrupted`
(jobs._mark_interrupted -> `interrupted`): nothing is continued by itself, the results tell which apps are done.
"""
import contextlib
import re
import secrets
import sys
import time
import traceback

from . import haissues
from .errors import BackupError
from .storage import valid_backup_id

KINDS = ('ha-import', 'ha-restore')
STEPS = ('convert', 'restore')
GROUP_RE = re.compile(r'g[0-9a-f]{16}\Z')
APP_RE = re.compile(r'[a-z0-9][a-z0-9-]{1,40}\Z')
MAX_APPS = 16
MAX_RESULTS = 16
RESULT_KEYS = ('app_id', 'status', 'convert_job_id', 'restore_job_id', 'backup_id', 'safety_backup_id', 'code', 'message')
RESULT_STATUS = ('imported', 'converted', 'rolled-back', 'failed', 'skipped', 'not-started')
MAX_KEYS = haissues.MAX_ACKNOWLEDGED

# What the customer reads about an app the import did not reach (GroupResult.message of a `not-started` app): what
# happened, that nothing of the app changed on this device, and what to do.
NOTHING = '這台的這個應用沒有任何變更'
STOPPED = {
    'cancelled': f'你取消了匯入，這個應用沒有開始。{NOTHING}，需要時可以重新匯入。',
    'stopped': f'你要求做完上一個應用就停止，這個應用沒有開始。{NOTHING}，需要時可以重新匯入。',
    'interrupted': f'匯入被中斷了（例如系統重新開機或程序被終止），這個應用沒有開始。{NOTHING}，請重新匯入。',
    'key': f'HA 備份的加密金鑰有問題，匯入已停止，這個應用沒有開始。{NOTHING}。請確認金鑰後重新匯入。',
    'space': f'這台的磁碟空間不足，匯入已停止，這個應用沒有開始。{NOTHING}。請先清出空間（例如刪除不需要的備份）後重新匯入。',
    'file': f'上傳的 HA 備份檔本身有問題（不完整或被改過），匯入已停止，這個應用沒有開始。{NOTHING}。請重新上傳 HA 備份檔後再匯入。',
    'busy': f'另一個作業佔住了備份引擎，匯入已停止，這個應用沒有開始。{NOTHING}。請等它完成後重新匯入。',
    'next': f'無法建立匯入的下一個作業，匯入已停止，這個應用沒有開始。{NOTHING}。請查看系統日誌後重新匯入。',
    'other': f'備份引擎遇到無法繼續的問題，匯入已停止，這個應用沒有開始。{NOTHING}。請查看作業紀錄後重新匯入。',
}
STOP_TEXT = {'cancelled': 'cancelled', 'stopped': 'stopped', 'interrupted': 'interrupted', 'key-required': 'key',
             'wrong-key': 'key', 'insufficient-space': 'space', 'corrupt-archive': 'file', 'busy': 'busy'}
NOT_STARTED = ('匯入在這個應用開始之前就中斷了（例如系統重新開機或程序被終止）。這台的這個應用沒有任何變更，'
               '請重新匯入它；已經匯入的應用不受影響。')
INTERRUPTED_TAIL = '這次匯入的其餘應用沒有開始；已經匯入的應用不受影響。'
CONVERTED_KEPT = '已轉換成備份，但匯入被停止，這台的這個應用沒有任何變更。轉換好的備份還在備份列表，要匯入時可以還原它。'
CANCELLED_RESTORE = '你取消了匯入，這個應用已轉換成備份但還沒有匯入。這台的這個應用沒有任何變更，轉換好的備份還在備份列表，要匯入時可以還原它。'
ROLLED_BACK_TAIL = '這個應用已自動退回匯入前的狀態。'
UNCHANGED_TAIL = '這台的這個應用沒有變更；轉換好的備份還在備份列表，可以再試一次。'
NO_BACKUP = '轉換作業結束了，但找不到轉換出來的備份，這個應用沒有匯入。這台的這個應用沒有任何變更，請查看作業紀錄後重新匯入。'
STOP_REQUESTED_LOG = '已收到「做完這個應用就停止」的要求'


class Stop:
    """Why the import ends here: a GroupResult `code` (an error code, or `cancelled`, `stopped`, `interrupted`) and the
    text of the apps it leaves out."""

    def __init__(self, code, message=None):
        self.code = code
        self.message = message or STOPPED[STOP_TEXT.get(code, 'other')]


class Outcome:
    """How one job of a chain ended, before its record was finished: `state` (succeeded, failed, rolled-back, cancelled,
    interrupted), its `result`, `error` ({code, message}) and the exception that ended it (None when it succeeded)."""
    __slots__ = ('state', 'result', 'error', 'exc')

    def __init__(self, state, result=None, error=None, exc=None):
        self.state, self.result, self.error, self.exc = state, result, error, exc


# ====================================================================== what a record says

def _int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _text(value, limit):
    return value if isinstance(value, str) and len(value) <= limit else None


def new_group_id():
    return 'g' + secrets.token_hex(8)


def group_of(params):
    """The `params.group` of a chain job, checked (None for any other job or a group that does not make sense)."""
    group = params.get('group') if isinstance(params, dict) else None
    if not isinstance(group, dict):
        return None
    gid, kind, step, app_id = group.get('id'), group.get('kind'), group.get('step'), group.get('app_id')
    index, count = group.get('index'), group.get('count')
    if (not isinstance(gid, str) or not GROUP_RE.fullmatch(gid) or kind not in KINDS or step not in STEPS
            or not isinstance(app_id, str) or not APP_RE.fullmatch(app_id) or not _int(index) or not _int(count)
            or not 0 <= index < count <= MAX_APPS or (kind == 'ha-restore' and step != 'restore')):
        return None
    return {'id': gid, 'kind': kind, 'step': step, 'app_id': app_id, 'index': index, 'count': count}


def clean_result(item):
    """One GroupResult as this module writes it (None when it is not one)."""
    if not isinstance(item, dict) or item.get('status') not in RESULT_STATUS:
        return None
    app_id = item.get('app_id')
    if not isinstance(app_id, str) or not APP_RE.fullmatch(app_id):
        return None
    from .jobs import valid_job_id
    out = {'app_id': app_id, 'status': item['status']}
    for key in ('convert_job_id', 'restore_job_id'):
        value = item.get(key)
        out[key] = value if valid_job_id(value) else None
    for key in ('backup_id', 'safety_backup_id'):
        value = item.get(key)
        out[key] = value if valid_backup_id(value) else None
    out['code'] = _text(item.get('code'), 40)
    out['message'] = haissues.clean(item['message'], haissues.MAX_MESSAGE) if isinstance(item.get('message'), str) else None
    return {key: out[key] for key in RESULT_KEYS}


def _keys_of(value):
    """{app id or `_shared`: [confirmation keys]} as `acknowledged` carries them (what does not look like one is dropped)."""
    out = {}
    for app_id, keys in (value.items() if isinstance(value, dict) else ()):
        if not isinstance(app_id, str) or not (APP_RE.fullmatch(app_id) or app_id == haissues.SHARED) \
                or not isinstance(keys, list):
            continue
        keys = [key for key in keys if isinstance(key, str) and haissues.KEY_RE.fullmatch(key)][:MAX_KEYS]
        if keys:
            out[app_id] = keys
    return out


def _choices_of(value):
    out = {}
    for app_id, choice in (value.items() if isinstance(value, dict) else ()):
        if isinstance(app_id, str) and APP_RE.fullmatch(app_id) and isinstance(choice, dict) and choice:
            out[app_id] = {str(key): item for key, item in choice.items() if isinstance(item, str)}
    return out


def chain_of(params):
    """The `params.chain` of a chain job, checked and complete (None when the job has none or it does not fit its
    `params.group`): apps, test_mode, then_restore, encrypt, key_provided, ha_backup_id, acknowledged, choices,
    allow_no_safety, accept_unauthenticated, convert_job_id and results (clean GroupResults)."""
    group = group_of(params)
    chain = params.get('chain') if isinstance(params, dict) else None
    if group is None or not isinstance(chain, dict):
        return None
    apps = chain.get('apps')
    if (not isinstance(apps, list) or not 1 <= len(apps) <= MAX_APPS
            or not all(isinstance(app, str) and APP_RE.fullmatch(app) for app in apps) or len(set(apps)) != len(apps)
            or group['count'] != len(apps) or apps[group['index']] != group['app_id']):
        return None
    from .jobs import valid_job_id
    from .hastore import valid_id
    ha_id = chain.get('ha_backup_id', params.get('ha_backup_id'))
    results = [row for row in (clean_result(item) for item in (chain.get('results') if isinstance(
        chain.get('results'), list) else [])[:MAX_RESULTS]) if row is not None]
    return {'apps': list(apps), 'test_mode': chain.get('test_mode') is True, 'then_restore': chain.get('then_restore') is True,
            'encrypt': chain.get('encrypt') is not False,
            'key_provided': chain.get('key_provided', params.get('key_provided')) is True,
            'ha_backup_id': ha_id if valid_id(ha_id) else None, 'acknowledged': _keys_of(chain.get('acknowledged')),
            'choices': _choices_of(chain.get('choices')), 'allow_no_safety': chain.get('allow_no_safety') is True,
            'accept_unauthenticated': chain.get('accept_unauthenticated') is True,
            'convert_job_id': chain.get('convert_job_id') if valid_job_id(chain.get('convert_job_id')) else None,
            'results': results}


def in_chain(record):
    """True for a job record of an import's (or a split restore's) chain."""
    return chain_of(record.get('params') if isinstance(record, dict) else None) is not None


# ====================================================================== building jobs

def group_result(app_id, status, code=None, message=None, **ids):
    """GroupResult (CONTRACT section 7): what became of one app of an import."""
    row = {'app_id': app_id, 'status': status, 'convert_job_id': None, 'restore_job_id': None, 'backup_id': None,
           'safety_backup_id': None, 'code': code, 'message': message}
    row.update(ids)
    return row


def group_params(group_id, kind, step, app_id, index, count):
    return {'id': group_id, 'index': index, 'count': count, 'kind': kind, 'step': step, 'app_id': app_id}


def new_chain(apps, *, test_mode=False, then_restore=True, encrypt=True, key_provided=False, ha_backup_id=None,
              acknowledged=None, choices=None, results=(), allow_no_safety=False, accept_unauthenticated=False,
              convert_job_id=None):
    """`params.chain` in its one shape (what the rest of an import needs). Only what differs from the default is written for
    the restore options, so a record stays small."""
    chain = {'apps': list(apps), 'test_mode': bool(test_mode), 'then_restore': bool(then_restore),
             'encrypt': bool(encrypt), 'key_provided': bool(key_provided)}
    if ha_backup_id is not None:
        chain['ha_backup_id'] = ha_backup_id
    chain['acknowledged'] = {app_id: list(keys) for app_id, keys in (acknowledged or {}).items() if keys}
    chain['choices'] = {app_id: dict(values) for app_id, values in (choices or {}).items() if values}
    if allow_no_safety:
        chain['allow_no_safety'] = True
    if accept_unauthenticated:
        chain['accept_unauthenticated'] = True
    if convert_job_id is not None:
        chain['convert_job_id'] = convert_job_id
    chain['results'] = [dict(row) for row in results]
    return chain


def convert_params(ha_backup_id, apps, *, database, test_mode, encrypt, key_provided, acknowledged, choices):
    """The params of an HA conversion job (`ha-convert-start`, the first job of `ha-import-start`, every later conversion of a
    chain): `acknowledged` keeps only the lines of these apps and the shared ones, `choices` only these apps'."""
    params = {'source': 'ha', 'ha_backup_id': ha_backup_id, 'apps': list(apps), 'odoo_database': database,
              'test_mode': bool(test_mode), 'encrypt': bool(encrypt), 'key_provided': bool(key_provided)}
    acknowledged = {app_id: list(keys) for app_id, keys in (acknowledged or {}).items()
                    if keys and app_id in (*apps, haissues.SHARED)}
    choices = {app_id: dict(values) for app_id, values in (choices or {}).items() if values and app_id in apps}
    if acknowledged:
        params['acknowledged'] = acknowledged
    if choices:
        params['choices'] = choices
    return params


def restore_params(backup_id, app_id, *, acknowledged=None, allow_no_safety=False, accept_unauthenticated=False,
                   key_provided=False):
    """The params of one app's restore job in a chain: the ordinary restore of `backup_id` for this one app (no key: a
    converted backup is the device's own, and a restore chain's age key is a file of the run), with the app's own confirmed
    lines and the shared ones for the restore's check."""
    params = {'backup_id': backup_id, 'apps': [app_id], 'key_provided': bool(key_provided)}
    if allow_no_safety:
        params['allow_no_safety'] = True
    if accept_unauthenticated:
        params['accept_unauthenticated'] = True
    keys = {name: list(items) for name, items in (acknowledged or {}).items() if items and name in (app_id, haissues.SHARED)}
    if keys:
        params['acknowledged'] = keys
    return params


def _database(chain, app_id):
    return (chain['choices'].get(app_id) or {}).get('database') if app_id == 'odoo' else None


def _step_job(chain, group, record, step, app_id, finished, backup_id=None):
    """(job type, params) of the job that follows."""
    index = chain['apps'].index(app_id)
    if step == 'convert':
        if chain['ha_backup_id'] is None:
            raise BackupError('internal-error', '匯入作業缺少 HA 備份的資料，無法建立下一個作業。')
        params = convert_params(chain['ha_backup_id'], [app_id], database=_database(chain, app_id),
                                test_mode=chain['test_mode'], encrypt=chain['encrypt'], key_provided=chain['key_provided'],
                                acknowledged=chain['acknowledged'], choices=chain['choices'])
        convert_job_id = None
    else:
        params = restore_params(backup_id, app_id, acknowledged=chain['acknowledged'],
                                allow_no_safety=chain['allow_no_safety'],
                                accept_unauthenticated=chain['accept_unauthenticated'],
                                key_provided=chain['key_provided'] and group['kind'] == 'ha-restore')
        convert_job_id = record['id'] if group['kind'] == 'ha-import' and group['step'] == 'convert' else None
    if chain['ha_backup_id'] is not None and step == 'restore':
        params['ha_backup_id'] = chain['ha_backup_id']  # the HA file stays protected while any job of the import is queued
    params['group'] = group_params(group['id'], group['kind'], step, app_id, index, group['count'])
    params['chain'] = new_chain(chain['apps'], test_mode=chain['test_mode'], then_restore=chain['then_restore'],
                                encrypt=chain['encrypt'], key_provided=chain['key_provided'],
                                ha_backup_id=chain['ha_backup_id'], acknowledged=chain['acknowledged'],
                                choices=chain['choices'], results=finished, allow_no_safety=chain['allow_no_safety'],
                                accept_unauthenticated=chain['accept_unauthenticated'], convert_job_id=convert_job_id)
    return ('backup' if step == 'convert' else 'restore'), params


# ====================================================================== what became of an app

def _short(text, limit=haissues.MAX_MESSAGE):
    return haissues.clean(_redact(text), limit)


def _redact(text):
    from .jobs import redact
    return redact('' if text is None else text)


def _reason(error):
    """The text of a failure, as one GroupResult message may carry it (cut to leave room for what follows)."""
    return _short((error or {}).get('message') or '', 220).rstrip('。 ') + '。' if (error or {}).get('message') else ''


def _convert_row(result, app_id):
    rows = result.get('results') if isinstance(result, dict) else None
    row = rows[0] if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) else None
    return row if row is not None and row.get('app_id') == app_id and row.get('status') in ('converted', 'skipped', 'failed') \
        else None


def _entry(record, params, group, chain, outcome):
    """The GroupResult of the app this job worked on, as far as this job tells it."""
    app_id, step, state = group['app_id'], group['step'], outcome.state
    result = outcome.result if isinstance(outcome.result, dict) else {}
    error = outcome.error or {}
    entry = group_result(app_id, 'failed', error.get('code'), _short(error.get('message')))
    if step == 'convert':
        entry['convert_job_id'] = record['id']
        if state == 'succeeded':
            row = _convert_row(result, app_id)
            backup_id = result.get('backup_id') if valid_backup_id(result.get('backup_id')) else None
            entry.update(status='converted', code=None, message=None, backup_id=backup_id)
            if row is not None and row.get('status') != 'converted':
                entry.update(status=row['status'], code=row.get('code'), message=_short(row.get('message')))
            elif backup_id is None:  # a conversion that names no backup cannot be restored: say so, never guess
                entry.update(status='failed', code='internal-error', message=NO_BACKUP)
        elif state == 'cancelled':
            entry.update(status='not-started', code='cancelled', message=STOPPED['cancelled'])
        else:
            row = _convert_row(result, app_id)
            if row is not None:
                entry.update(status=row['status'], code=row.get('code'), message=_short(row.get('message')))
        return clean_result(entry) or entry
    entry.update(convert_job_id=chain.get('convert_job_id'), restore_job_id=record['id'],
                 backup_id=params.get('backup_id'), safety_backup_id=result.get('safety_backup_id'))
    if state == 'succeeded':
        entry.update(status='imported', code=None, message=None)
    elif state == 'rolled-back':
        entry.update(status='rolled-back', message=_short(f'{_reason(error)}{ROLLED_BACK_TAIL}'))
    elif state == 'cancelled':
        entry.update(status='converted', code='cancelled', message=CANCELLED_RESTORE)
    elif state == 'failed':
        if result.get('changed') is not True and error.get('message'):
            entry['message'] = _short(f'{_reason(error)}{UNCHANGED_TAIL}')
    return clean_result(entry) or entry


def _remaining(group, chain, stop):
    return [group_result(app_id, 'not-started', stop.code, stop.message) for app_id in chain['apps'][group['index'] + 1:]]


def _view(group, next_job_id, results):
    return {'id': group['id'], 'index': group['index'], 'count': group['count'], 'step': group['step'],
            'next_job_id': next_job_id, 'results': [dict(row) for row in results]}


def _with_group(result, view):
    out = dict(result) if isinstance(result, dict) else {}
    out['group'] = view
    return out




# ====================================================================== what ends the import

def _outer_file_damaged(ctx, chain):
    """The HA file itself cannot be opened or is not what was uploaded: no other app can be converted either."""
    from . import habackup, hastore
    try:
        store = hastore.HaStore(ctx.paths)
        record = store.get(chain['ha_backup_id'])
        with habackup.open_backup(store.file_path(record['id'])) as backup:
            return backup.layout.size != record['size']
    except Exception:  # noqa: BLE001 - what cannot be read is damaged enough: the import stops
        return True


def _space_recovered(ctx):
    """The disk that ran full has room again (the failed job cleaned up): the floor a job keeps free is there once more."""
    from . import flows, haimport
    try:
        free = ctx.storage.free_bytes()
        return free is not None and int(free) >= flows.running_reserve(ctx) + haimport.WATCH_MARGIN
    except Exception:  # noqa: BLE001 - not measurable is not enough room
        return False


def _stop_for(ctx, group, chain, outcome):
    """The Stop that ends the import after this job, or None when the next app goes on (DESIGN C1)."""
    if outcome.state == 'cancelled':
        return Stop('cancelled')
    if outcome.state == 'interrupted':
        return Stop('interrupted')
    if ctx.reporter.cancel_requested():
        return Stop('cancelled')  # asked for this job, a moment too late for it: the import is what the customer cancels
    exc = outcome.exc
    if exc is None:
        return None
    code = getattr(exc, 'code', None)
    if not haissues.ends_job(exc):
        if group['step'] == 'convert' and code == 'corrupt-archive' and _outer_file_damaged(ctx, chain):
            return Stop('corrupt-archive')
        return None
    if haissues.out_of_space(exc) is not None or code == 'insufficient-space':
        return None if _space_recovered(ctx) else Stop('insufficient-space')
    return Stop(code or 'internal-error')


# ====================================================================== after a job

def _create_next(store, record, group, chain, follow, finished, entry):
    """The record of the job that follows, queued, with the unit of the first job of the import."""
    step, app_id = follow
    backup_id = entry['backup_id'] if step == 'restore' and group['step'] == 'convert' else None
    if step == 'restore' and group['step'] == 'restore':
        backup_id = (record.get('params') or {}).get('backup_id')  # a restore chain: the same backup, the next app
    job_type, params = _step_job(chain, group, record, step, app_id, finished, backup_id)
    # Never earlier than the second after this job's: job ids sort by their second, and `jobs` lists the newest first.
    from . import jobs
    now = max(time.time(), (jobs.parse_iso(record.get('created')) or 0) + 1)
    return store.create(job_type, params, now=now, unit=record.get('unit'))


def _end(paths, store, log, group, results):
    """The import is over (finished, stopped or cut): a stop request has done its work, and the converted backups'
    rows say what became of the whole import (best effort: the job records have it all)."""
    with contextlib.suppress(OSError):
        store.clear_stop(group['id'])
    if group['kind'] != 'ha-import':
        return
    from . import haimport
    for row in results:
        if not row.get('backup_id'):
            continue
        try:
            haimport.update_row(paths, row['backup_id'], results=results)
        except Exception as error:  # noqa: BLE001 - the page has the job records
            log(f'警告：無法把匯入結果記到備份的來源紀錄（{getattr(error, "message", None) or type(error).__name__}）')


SAID = {'imported': '已匯入', 'converted': '已轉換成備份', 'rolled-back': '已退回匯入前的狀態', 'failed': '沒有成功',
        'skipped': '沒有匯入', 'not-started': '沒有開始'}


def _log_line(group, entry, created, stop, restoring):
    app = group['app_id']
    if restoring:
        return f'匯入進度：{app} 已轉換成備份，接著匯入它。'
    said = SAID.get(entry['status'], entry['status'])
    if created is not None:
        return f'匯入進度：{app}{said}；接著{"轉換" if created["type"] == "backup" else "匯入"}'\
               f' {created["params"]["group"]["app_id"]}。'
    if stop is not None:
        return f'匯入在 {app}（{said}）之後停止（{stop.code}），後面的應用沒有開始。'
    return f'匯入進度：{app}{said}；這次匯入的應用都處理完了。'


def conclude(ctx, record, outcome):
    """Decide what follows the job `record` that ended as `outcome`, and write that job (queued, same unit) before the
    caller finishes this one. Returns (the result to finish the job with: its own plus `group`, the next record or None).
    A job of no chain is returned as it is. A problem of this module's own never fails the job: the import then ends
    here, and says so."""
    from . import jobs
    params = record.get('params') or {}
    group, chain = group_of(params), chain_of(params)
    if group is None or chain is None:
        return outcome.result, None
    store = jobs.JobStore(ctx.paths)
    entry = _entry(record, params, group, chain, outcome)
    stop = _stop_for(ctx, group, chain, outcome)
    step, index, apps = group['step'], group['index'], chain['apps']
    finished = list(chain['results'])
    # The app's own restore follows its conversion, whatever "stop after this app" says; only a real stop ends it.
    inflight = (stop is None and step == 'convert' and outcome.state == 'succeeded' and chain['then_restore']
                and group['kind'] == 'ha-import' and entry['status'] == 'converted')
    follow = None
    if inflight:
        follow = ('restore', group['app_id'])
    else:
        if stop is not None and step == 'convert' and chain['then_restore'] and group['kind'] == 'ha-import' \
                and entry['status'] == 'converted':
            entry.update(code=stop.code, message=CONVERTED_KEPT)  # converted, and its restore will not follow
        finished.append(entry)
        if stop is None and index + 1 < len(apps):
            if store.stop_requested(group['id']):
                stop = Stop('stopped')
            else:
                follow = ('restore' if group['kind'] == 'ha-restore' else 'convert', apps[index + 1])
    created = None
    if follow is not None:
        try:
            created = _create_next(store, record, group, chain, follow, finished, entry)
        except Exception:  # noqa: BLE001 - this job is finished all the same; the import ends here and says so
            traceback.print_exc(file=sys.stderr)
            stop = Stop('internal-error', STOPPED['next'])
            if inflight:
                inflight = False
                entry.update(code='internal-error', message=CONVERTED_KEPT)
                finished.append(entry)
    shown = finished + ([entry] if inflight else [])
    if created is None:
        if stop is not None:
            shown = shown + _remaining(group, chain, stop)
        _end(ctx.paths, store, ctx.log, group, shown)
    try:
        ctx.log(_log_line(group, entry, created, stop, inflight))
        final = _with_group(outcome.result, _view(group, created['id'] if created else None, shown))
    except Exception:  # noqa: BLE001 - what is written must name the job that was created, whatever else goes wrong
        traceback.print_exc(file=sys.stderr)
        final = outcome.result
    return final, created


# ====================================================================== a job that never ran its end

def _dead_result(record, group, chain, started, message, stop):
    """(error message, result with `group`) of a chain job that a dead process left, or that was cancelled / abandoned
    before it started: its app and the apps after it are told apart by whether it had started."""
    params = record.get('params') or {}
    app_id, step = group['app_id'], group['step']
    entry = group_result(app_id, 'not-started', stop.code, NOT_STARTED if stop.code == 'interrupted' else stop.message)
    if step == 'convert':
        entry['convert_job_id'] = record['id'] if started else None
        if started:
            entry.update(status='failed', code='job-failed', message=_short(message))
    else:
        entry.update(convert_job_id=chain.get('convert_job_id'), restore_job_id=record['id'] if started else None,
                     backup_id=params.get('backup_id'))
        if started:
            entry.update(status='failed', code='job-failed', message=_short(message))
        else:
            entry.update(status='converted', message=CONVERTED_KEPT if stop.code != 'cancelled' else CANCELLED_RESTORE)
    entry = clean_result(entry) or entry
    shown = list(chain['results']) + [entry] + _remaining(group, chain, stop)
    return shown, entry


def interrupted(record, message, result):
    """(message, result) of a chain job a dead process left (jobs._mark_interrupted): the job's own words, what is left of the
    import and a result that says which apps are done. Any other job is returned as it is."""
    params = record.get('params') or {}
    group, chain = group_of(params), chain_of(params)
    if group is None or chain is None:
        return message, result
    started = bool(record.get('started'))
    stop = Stop('interrupted')
    shown, _entry_row = _dead_result(record, group, chain, started, message, stop)
    if not started:
        message = NOT_STARTED
    elif group['index'] + 1 < len(chain['apps']):
        message = f'{message}{INTERRUPTED_TAIL}'
    return message, _with_group(result, _view(group, None, shown))


def unstarted(paths, store, record):
    """A chain job that was cancelled before it began (the record is finished already): its result says what became of
    the import (nothing of this app, nothing of the rest). Returns True when the record was changed."""
    params = record.get('params') or {}
    group, chain = group_of(params), chain_of(params)
    if group is None or chain is None:
        return False
    shown, _row = _dead_result(record, group, chain, False, '', Stop('cancelled'))
    with store.locked(record['id']):
        fresh = store.get(record['id'])
        fresh['result'] = _with_group(fresh.get('result'), _view(group, None, shown))
        store.save(fresh)
    _end(paths, store, lambda text: store.append_log(record['id'], text), group, shown)
    return True


def abandon(paths, store, created):
    """The next job was written, but the process was told to end meanwhile: it never starts, so it is finished as
    interrupted at once (it would else keep every other job `busy` until recovery notices it)."""
    from . import jobs
    params = created.get('params') or {}
    group, chain = group_of(params), chain_of(params)
    message, result = NOT_STARTED, None
    if group is not None and chain is not None:
        message, result = interrupted(created, NOT_STARTED, None)
    jobs.JobReporter(store, created).finish('interrupted', result=result, error={'code': 'job-failed', 'message': message})
    if group is not None and chain is not None:
        _end(paths, store, lambda text: store.append_log(created['id'], text), group,
             ((result or {}).get('group') or {}).get('results') or [])


def active_member(store, group_id):
    """The queued or running job of the import `group_id` (at most one: nothing else may start meanwhile), or None."""
    from . import jobs
    for record in store.list(limit=None):
        if record.get('state') in jobs.ACTIVE:
            group = group_of(record.get('params'))
            if group is not None and group['id'] == group_id:
                return record
    return None
