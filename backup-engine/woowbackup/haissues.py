"""What an HA import found about an app, in one shape for the check, the conversion and the restore check (CONTRACT
section 7 "HaIssue"; "Revised 2026-11-25 (HAOS parity)"). Owner: E2.

An `Issue` has one of four levels:

* `stop`     this app (an Odoo issue with `database`: that database) cannot be imported; every other app goes on and
             this device stays as it is.
* `confirm`  the customer may lose something, or it has a consequence for security, another service or this device's
             settings: one line of the ONE confirmation before an import. A conversion stops only that app
             (`confirmation-required`) when a line was not confirmed with its exact names.
* `auto`     the system handles it (done or going to be done); one line in the job log.
* `notice`   a reminder; nothing depends on it.

Ids are fixed codes `<area>.<what>` and every id is declared with its level in the `ISSUES` table of the module that
uses it (shared ones here; tests/backup/test_ha_issues.py refuses an id that is declared twice, used without being
declared or declared without being used). A message is one plain zh-TW sentence, names go into `items`; neither ever
holds a secret value. Names come from a backup or from this device and are untrusted: every character that is invisible
or changes how the text around it reads is shown as a space, long ones are cut (`Issue.view`), and the page writes them
with textContent.

A confirmation key is `<id>:` and the first 16 hex digits of a sha256 over [app, id, database, ALL names sorted]: one
more name is another key, a changed number in the message is not. Numbers therefore belong into the message only.

How a module uses it (haapps): `sink = work.sink(app)`, then `sink.stop/confirm/auto/notice(...)` in `check` and the
same calls in `convert`. In the check everything is collected. In the conversion a `stop` raises at once and a `confirm`
raises unless the customer confirmed exactly it (`Sink`); issues of another Odoo database than the chosen one are
ignored there. What a module still returns the old way (`blockers`, `warnings`) becomes `stop` / `notice` issues
(`from_legacy`), so the importers can change over one by one.
"""
import errno
import hashlib
import json
import re
import sys
import traceback
import unicodedata

from .errors import CODES, BackupError

LEVELS = ('stop', 'confirm', 'auto', 'notice')
ID_RE = re.compile(r'[a-z0-9-]{2,24}\.[a-z0-9-]{2,40}\Z')
KEY_RE = re.compile(r'[a-z0-9.-]{4,70}:[0-9a-f]{16}\Z')
SHARED = '_shared'           # `acknowledged` / the keys of issues that belong to no single app (HaCheck.shared)
MAX_MESSAGE = 300
MAX_ACTION = 200
MAX_ITEMS = 20
MAX_ITEM = 120
MAX_ISSUES = 40              # per app; never at the cost of a stop or a confirm
MAX_BYTES = 40 * 1024        # per app, the JSON of its issues (a job record takes 1 MiB for 10 apps)
MAX_ACKNOWLEDGED = 80        # confirmation keys one app's request may carry
MAX_TEXT = 2000              # the text older pages get (`blockers` / `warnings`) is cut later than a message
MAX_TEXT_BYTES = 12 * 1024   # ... and all of an app's, per list
MAX_CHOICES = 100
# What a shown text never carries as it is: controls, format characters (the bidirectional controls, zero-width ones,
# the byte order mark, tag characters), lone surrogates, unassigned code points and the line / paragraph separators.
HIDDEN_CATEGORIES = frozenset(('Cc', 'Cf', 'Cs', 'Cn', 'Zl', 'Zp'))

# The ids of the shared parts (haimport, cli and this module); an importer's own ids are in its module's ISSUES.
ISSUES = {
    **{f'failure.{code}': 'stop' for code in sorted(CODES)},  # an app's BackupError (from_error)
    'legacy.blocker': 'stop',            # a sentence of an importer that still returns `blockers`
    'legacy.warning': 'notice',          # ... and `warnings`
    'shared.more-lines': 'notice',       # the list was too long: how many lines were left out
    'version.addon-unknown': 'notice',   # CM-01: the version table does not know the add-on's version
    'version.target-unknown': 'notice',  # CM-02, CM-06: this device's version cannot be read
    'version.different': 'stop',         # both are known and differ (installing HA's version is a later phase)
}

# What the customer can do about an app's failure, by error code ('' = the message says it).
ACTIONS = {
    'corrupt-archive': '請在 HA 重新備份，再上傳新的備份檔匯入這個應用。',
    'unsupported-format': '請先更新這台的 Cockpit；仍然不行時，請在 HA 重新備份後再匯入。',
    'limit-exceeded': '請在 HA 重新備份後再試一次；仍然不行時，請把作業紀錄交給工程人員。',
    'insufficient-space': '請先清出這台的磁碟空間，再匯入這個應用。',
    'permission-denied': '請把作業紀錄交給工程人員檢查這台設備。',
    'key-required': '請輸入 HA 備份金鑰後再試一次。',
    'wrong-key': '請確認 HA 備份金鑰後再試一次；金鑰沒有錯時，請在 HA 重新備份。',
    'owner-missing': '請先建立這個應用的擁有者帳號並安裝它，再匯入。',
    'invalid-manifest': '請在 HA 重新備份後再試一次。',
    'job-failed': '請再試一次；仍然不行時，請把作業紀錄交給工程人員。',
    'internal-error': '請再試一次；仍然不行時，請把作業紀錄交給工程人員。',
}
UNEXPECTED = '處理這個應用時發生未預期的錯誤（詳情在系統日誌）；這台的這個應用沒有任何變更。'
DISK_FULL = '這台的磁碟空間已經用完，作業已停止並清除暫用資料。這台的應用沒有任何變更。'
MORE_LINES = '另有 {count} 項沒有列出，請看作業紀錄。'
NOT_CONFIRMED = '匯入前還有事情要確認：{message}'
CHANGED = '這次匯入和檢查時看到的不同，請再確認一次：{message}'


# ====================================================================== text

def clean(text, limit):
    """`text` as it may be shown: cut at `limit` characters, every HIDDEN_CATEGORIES character as a space."""
    text = text if isinstance(text, str) else '' if text is None else str(text)
    return ''.join(' ' if unicodedata.category(ch) in HIDDEN_CATEGORIES else ch for ch in text[:limit])


def _redact(text):
    from .jobs import redact  # an HA key never reaches a job record, whatever text it came in (SEC: masked exactly)
    return redact(text)


class Names:
    """All names of one kind (skipped files, settings, ...) without keeping them all: how many, the first MAX_ITEMS and
    what identifies the whole list (the names themselves up to MAX_EXACT, above that an order-independent digest), for
    lists an untrusted backup can make arbitrarily long. Pass it as the `items` of an issue."""
    MAX_EXACT = 1000

    def __init__(self, names=()):
        self.count = 0
        self.first = []
        self._exact = []
        self._sum = 0
        for name in names:
            self.add(name)

    def add(self, name):
        name = str(name)
        self.count += 1
        if len(self.first) < MAX_ITEMS:
            self.first.append(name)
        if self.count <= self.MAX_EXACT:
            self._exact.append(name)
        digest = hashlib.sha256(name.encode('utf-8', 'surrogatepass')).digest()
        self._sum = (self._sum + int.from_bytes(digest, 'big')) % (1 << 256)

    def __len__(self):
        return self.count

    def key_items(self):
        """What the confirmation key is made of."""
        if self.count <= self.MAX_EXACT:
            return tuple(self._exact)
        return (f'count={self.count}', f'sum={self._sum:064x}')


def confirm_key(app_id, issue_id, items, database=None):
    """The confirmation key of a `confirm` issue with these (all) names."""
    body = json.dumps([app_id, issue_id, database, sorted(str(item) for item in items)], ensure_ascii=False,
                      separators=(',', ':'))
    return f'{issue_id}:{hashlib.sha256(body.encode("utf-8", "surrogatepass")).hexdigest()[:16]}'


# ====================================================================== one issue

class Issue:
    """One finding. `items`: the names it is about (an iterable of text, or `Names`); all of them make the key, the
    first MAX_ITEMS are shown. `action`: what the customer can do (stop only). `database`: the Odoo database it is
    about, None = the whole app. A wrong id or level is a programming error (ValueError)."""

    def __init__(self, issue_id, level, message, items=(), *, action='', database=None):
        if not isinstance(issue_id, str) or not ID_RE.fullmatch(issue_id):
            raise ValueError(f'bad issue id: {issue_id!r}')
        if level not in LEVELS:
            raise ValueError(f'bad issue level: {level!r}')
        self.id = issue_id
        self.level = level
        self.text = clean(message, MAX_TEXT)
        self.database = None if database is None else str(database)
        self.action = clean(action, MAX_ACTION) if level == 'stop' else ''
        names = items if isinstance(items, Names) else None
        items = (items,) if isinstance(items, str) else items
        values = tuple(str(item) for item in (names.first if names is not None else items))
        self.count = names.count if names is not None else len(values)
        self.names = values[:MAX_ITEMS]
        self._key_items = names.key_items() if names is not None else values

    @property
    def message(self):
        return self.text if len(self.text) <= MAX_MESSAGE else self.text[:MAX_MESSAGE - 1] + '…'

    def key(self, app_id):
        return confirm_key(app_id, self.id, self._key_items, self.database)

    def shown(self):
        return [clean(_redact(name), MAX_ITEM) for name in self.names]

    def view(self, app_id):
        """The JSON shape (CONTRACT section 7 HaIssue)."""
        items = self.shown()
        value = {'id': self.id, 'level': self.level, 'message': clean(_redact(self.message), MAX_MESSAGE),
                 'items': items, 'more': self.count - len(items)}
        if self.level == 'stop':
            value['action'] = clean(_redact(self.action), MAX_ACTION)
        if self.database is not None:
            value['database'] = self.database
        if self.level == 'confirm':
            value['key'] = self.key(app_id)
        return value

    def __repr__(self):  # never the names: a traceback goes to the journal
        return f'<Issue {self.id} {self.level} items={self.count}>'


def from_legacy(blockers=(), warnings=(), database=None):
    """The issues of an importer that still returns sentences: `blockers` stop, `warnings` remind."""
    return ([Issue('legacy.blocker', 'stop', text, database=database) for text in blockers or ()]
            + [Issue('legacy.warning', 'notice', text, database=database) for text in warnings or ()])


# ====================================================================== the list of one app

def _size(rows):
    return len(json.dumps(rows, ensure_ascii=False, separators=(',', ':')).encode('utf-8', 'surrogatepass'))


def _more(app_id, count):
    return Issue('shared.more-lines', 'notice', MORE_LINES.format(count=count)).view(app_id)


def _shrink(rows, levels, limit):
    for row in rows:
        if row['level'] in levels and len(row['items']) > limit:
            row['more'] += len(row['items']) - limit
            row['items'] = row['items'][:limit]


def views(app_id, issues):
    """The issues of one app as they are sent: stops first, then confirms, automatic ones and notices; at most
    MAX_ISSUES lines and MAX_BYTES. A stop or a confirm is never dropped (only its names are counted instead of
    listed; its key still covers all of them); what is dropped is counted in one line."""
    ordered = sorted(issues, key=lambda issue: LEVELS.index(issue.level))  # stable: the order they were found in
    rows = [issue.view(app_id) for issue in ordered]
    must = sum(1 for row in rows if row['level'] in ('stop', 'confirm'))
    dropped = 0
    if len(rows) > MAX_ISSUES:
        keep = max(must, MAX_ISSUES - 1)
        dropped = len(rows) - keep
        rows = rows[:keep]
    fits = False
    for limit in (None, 10, 5, 2, 0):
        for levels in (('auto', 'notice'), ('stop', 'confirm')):
            if limit is not None:
                _shrink(rows, levels, limit)
            fits = _size(rows + ([_more(app_id, dropped)] if dropped else [])) <= MAX_BYTES
            if fits:
                break
        if fits:
            break
    while not fits and len(rows) > must:
        rows.pop()
        dropped += 1
        fits = _size(rows + [_more(app_id, dropped)]) <= MAX_BYTES
    return rows + ([_more(app_id, dropped)] if dropped else [])


def choice_rows(rows):
    """`choices.<kind>` as it is sent: [{value, label, ok?, default?}], labels cleaned and cut, at most MAX_CHOICES (of a
    longer list those that can be chosen first)."""
    rows = list(rows or ())
    if len(rows) > MAX_CHOICES:
        rows.sort(key=lambda row: row.get('ok') is False)  # stable
    result = []
    for row in rows[:MAX_CHOICES]:
        item = {'value': str(row['value']), 'label': clean(_redact(str(row.get('label') or row['value'])), 200)}
        for flag in ('ok', 'default'):
            if flag in row:
                item[flag] = row[flag] is True
        result.append(item)
    return result


def databases_ok(rows, issues):
    """The `choices.database` rows with `ok` false for every database one of the issues stops; the only one that can
    move is the default (HA-14)."""
    stops = {issue.database for issue in issues if issue.level == 'stop' and issue.database is not None}
    rows = [dict(row, ok=row.get('ok', True) is True and row['value'] not in stops) for row in rows or ()]
    movable = [row for row in rows if row['ok']]
    if len(movable) == 1 and not any(row.get('default') is True for row in rows):
        movable[0]['default'] = True
    return rows


def importable(issues, databases=None):
    """No stop for the whole app and, for an app with databases to choose from, at least one that can move."""
    if any(issue.level == 'stop' and issue.database is None for issue in issues):
        return False
    return databases is None or any(row.get('ok') is True for row in databases)


def check_fields(app_id, issues, choices=None):
    """What HaCheck says about one app beside its own section: `importable`, `issues`, `choices` (only when there is
    something to choose) and the fields older pages read: `ok` (importable and nothing to confirm), `blockers` (stop and
    confirm sentences) and `warnings` (the others). Sentences about one Odoo database are in the section already; only
    a line to confirm is repeated here, so an older page never offers it."""
    issues = list(issues)
    choices = {kind: list(rows) for kind, rows in (choices or {}).items() if rows}
    if 'database' in choices:
        choices['database'] = databases_ok(choices['database'], issues)
    can = importable(issues, choices.get('database'))
    to_confirm = any(issue.level == 'confirm' for issue in issues)

    def sentences(levels):
        result, left = [], MAX_TEXT_BYTES
        for issue in issues:
            if issue.level not in levels or (issue.database is not None and issue.level != 'confirm'):
                continue
            text = clean(_redact(issue.text), MAX_TEXT)
            if issue.database is not None:
                text = f'{clean(issue.database, MAX_ITEM)}：{text}'
            if issue.action and not issue.id.startswith('failure.'):  # those pages show no action of their own
                text += clean(_redact(issue.action), MAX_ACTION)
            left -= len(text.encode('utf-8', 'replace'))
            if left < 0 and result:
                break
            result.append(text)
        return result

    fields = {'importable': can, 'issues': views(app_id, issues), 'ok': can and not to_confirm,
              'blockers': sentences(('stop', 'confirm')), 'warnings': sentences(('auto', 'notice'))}
    if choices:
        fields['choices'] = {kind: choice_rows(rows) for kind, rows in choices.items()}
    return fields


# ====================================================================== confirmations

def valid_key(value):
    return isinstance(value, str) and KEY_RE.fullmatch(value) is not None


def missing(app_id, issues, acknowledged):
    """The `confirm` issues whose key is not in `acknowledged` (an iterable of keys, None = nothing confirmed)."""
    keys = frozenset(acknowledged or ())
    return [issue for issue in issues if issue.level == 'confirm' and issue.key(app_id) not in keys]


def confirmation_required(by_app, message):
    """`confirmation-required` with the lines that still need confirming (`details.apps`: {app: [HaIssue]}) and the
    issues themselves (`error.issues`)."""
    error = BackupError('confirmation-required', message,
                        apps={app_id: views(app_id, issues) for app_id, issues in by_app.items() if issues})
    error.issues = [issue for issues in by_app.values() for issue in issues]
    return error


def stopped(issue, code='incompatible', **details):
    """The BackupError an issue that stops an app raises (`error.issues` keeps the issue)."""
    error = BackupError(code, issue.text, **details)
    error.issues = [issue]
    return error


def combine(found, extra):
    """`found` plus the issues of `extra` it does not hold yet (the same objects: an error carries those of its sink)."""
    return list(found) + [issue for issue in extra if not any(issue is known for known in found)]


class Sink:
    """The issues of one app. Without `acknowledged` (the check, the restore check) everything is collected. With the
    customer's confirmed keys (the conversion; an empty list confirms nothing) `stop` raises, and `confirm` raises
    `confirmation-required` unless its key is among them: only that app stops. `database`: the Odoo database a
    conversion moves; what concerns another one is left out there. `found` holds every issue, in order."""

    def __init__(self, app_id, acknowledged=None, *, database=None, log=None):
        self.app_id = app_id
        self.acknowledged = None if acknowledged is None else frozenset(acknowledged)
        self.database = database
        self.found = []
        self._log = log if log is not None else lambda _text: None

    @property
    def converting(self):
        return self.acknowledged is not None

    def add(self, issue):
        """Keep a ready Issue; raises like stop/confirm. Returns it, or None when it concerns another database."""
        if not isinstance(issue, Issue):
            raise TypeError('not an Issue')
        if self.converting and issue.database is not None and issue.database != self.database:
            return None
        self.found.append(issue)
        if issue.level == 'auto':
            self._log(f'自動處理：{issue.message}')
        if self.converting and issue.level == 'stop':
            raise stopped(issue)
        if self.converting and issue.level == 'confirm' and issue.key(self.app_id) not in self.acknowledged:
            text = CHANGED if self.acknowledged else NOT_CONFIRMED
            raise confirmation_required({self.app_id: [issue]}, text.format(message=issue.message))
        return issue

    def extend(self, issues):
        for issue in issues:
            self.add(issue)

    def stop(self, issue_id, message, *, action='', items=(), database=None):
        return self.add(Issue(issue_id, 'stop', message, items, action=action, database=database))

    def confirm(self, issue_id, message, items=(), *, database=None):
        return self.add(Issue(issue_id, 'confirm', message, items, database=database))

    def auto(self, issue_id, message, items=(), *, database=None):
        return self.add(Issue(issue_id, 'auto', message, items, database=database))

    def notice(self, issue_id, message, items=(), *, database=None):
        return self.add(Issue(issue_id, 'notice', message, items, database=database))

    def refuse(self, issue_id, message, *, action='', items=(), code='incompatible'):
        """Stop the app here, also in the check (nothing more can be found out about it). The raised error carries the
        issue."""
        raise stopped(Issue(issue_id, 'stop', message, items, action=action), code)

    def confirmed(self):
        """What the customer confirmed, for `ha-imports.json`: [{app_id, id, items}] (conversion only)."""
        return [{'app_id': self.app_id, 'id': issue.id, 'items': issue.shown()} for issue in self.found
                if issue.level == 'confirm']


# ====================================================================== one app's failure

def job_wide(error):
    """Mark an error that ends the whole job, whichever app it came up in (returns it)."""
    error.job_wide = True
    return error


def is_job_wide(error):
    return getattr(error, 'job_wide', False) is True


def out_of_space(error):
    """`insufficient-space` for the whole job when `error` is the engine's own disk running full, else None."""
    if isinstance(error, OSError) and error.errno in (errno.ENOSPC, errno.EDQUOT):
        return job_wide(BackupError('insufficient-space', DISK_FULL))
    return None


def ends_job(error):
    """True when an exception ends the whole job (DESIGN C1): a termination signal or anything that is not an ordinary
    exception, a cancel, a disk that ran full, another job holding the engine, and what the job itself marked
    (`job_wide`: the watchdog's verdict, a missing key or one that opens nothing)."""
    from .flows import Cancelled
    if not isinstance(error, Exception) or isinstance(error, Cancelled):
        return True
    if is_job_wide(error) or out_of_space(error) is not None:
        return True
    return isinstance(error, BackupError) and error.code == 'busy'


def from_error(error):
    """The issues an app's exception becomes (never its raw text unless it is a BackupError, whose message is written
    for the page; an unexpected exception's details go to the journal only)."""
    issues = list(getattr(error, 'issues', None) or ())
    if issues:
        return issues
    if isinstance(error, BackupError):
        return [Issue(f'failure.{error.code}', 'stop', error.message, action=ACTIONS.get(error.code, ''))]
    sys.stderr.write(_redact(''.join(traceback.format_exception(error))))
    return [Issue('failure.internal-error', 'stop', UNEXPECTED, action=ACTIONS['internal-error'])]


def app_failure(error):
    """The issues that stop one app when `error` came up while it was worked on, or None when the whole job must
    stop."""
    return None if ends_job(error) else from_error(error)


# ====================================================================== versions are no gate (CM-01, CM-02, CM-06)

def version_issues(product, addon_version, upstream, target):
    """What to say about versions: the table that maps add-on versions to product versions, and this device's version,
    only inform; whether HA's data fits is decided by the data itself (schema, migrations, modules). `upstream`: HA's
    product version (hacommon.VersionTable.upstream), None when the table does not know the add-on's version;
    `target`: this device's, None when it cannot be read. Both known and different: a stop (the wave that installs
    HA's version lifts it); an importer whose data may come from an older version decides that itself."""
    from .hacommon import semver
    found = []
    if upstream is None:
        found.append(Issue('version.addon-unknown', 'notice',
                           f'這台的版本對照表還不認得 HA 的 {product} 附加元件版本 {clean(addon_version, 40) or "（讀不到）"}，'
                           f'不用版本判斷能不能匯入，改看 {product} 的資料本身。'))
    if target is None:
        found.append(Issue('version.target-unknown', 'notice',
                           f'讀不到這台 {product} 的版本，這次不比對版本；匯入後請確認 {product} 能正常使用。'))
    if upstream is not None and target is not None and semver(upstream) != semver(target):
        found.append(Issue('version.different', 'stop',
                           f'版本不同：HA 的 {product} 是 {clean(upstream, 40)}（附加元件 {clean(addon_version, 40)}），'
                           f'這台是 {clean(target, 40)}。', action=f'請先讓兩邊的 {product} 版本一致，再匯入 {product}。'))
    return found
