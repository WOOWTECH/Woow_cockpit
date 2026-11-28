#!/usr/bin/env python3
"""Page import bridge: ONE HA import through the REAL Cockpit page of a lab device, for a full-flow driver.

A full-flow driver that otherwise sends the helper commands itself (upload-begin/finish, ha-check-start,
ha-convert-start, inspect, restore-start) calls import_via_page() instead. The page (focus_acceptance_ui_page.mjs) uploads
the fixture itself, selects exactly the given apps, takes the HA key, runs the check, shows the one confirmation, ticks
it once and starts the import chain (each importable app's conversion and restore, in the first job's unit). The
bridge only watches and judges:

  before  the caller holds the device's own mutation lock (/tmp/<device>-mutation.lock, held by this very process), the
          installed page equals the tree, cockpit.socket is active, devadmin exists, the device's hostname is its name,
          memory headroom on the host (the browser) and in the device (the jobs and the Cockpit session), no active job
  page    the page through focus_acceptance_ui_relay.Relay(device): one `labpodman exec -i --user devadmin <device>
          python3 -I -c <forwarder>` per browser connection to 127.0.0.1:9090 inside the device; the config, with the HA
          key and the Cockpit password, on the page's stdin only. Bounded (20 min); SIGTERM/SIGINT stop it in order
          (SIGTERM so the page finishes its scan and closes Chromium, its process group killed only after 15 s); the
          relay's exec children are reaped and no child process of this one is left
  judge   the page's own new jobs: exactly one check, judged against the expected outcome (the importable apps and the
          stopped ones; every confirmation line and key read from that check, never written here), the page's one
          request and the import's jobs carry each listed key exactly once, the chain (two linked jobs per importable
          app, all succeeded, in the first job's unit), the browser's fixed checks and its issued-value (cookie) scan

The bridge changes nothing itself: only status, list, jobs and job-status are sent (READ_ONLY), plus two fixed read-only
programs inside the device. What the page created (the HA record when it was new, the converted and safety backups, a
copy of a whole database service a restore kept first, e.g. Odoo's cold cluster) is reported (`created_backups`,
`ha_record_existed`) so the driver's own cleanup removes it. Imports perform no I/O;
`python3 focus_page_bridge.py` only compiles the device programs.

Three optional inputs (absent: exactly the earlier flow, the same page config byte for byte):
  key=None     an unencrypted HA backup: no key reaches the page; it checks that the wizard asks for none and that no
               request carries one; gate `unencrypted` also reads the engine's jobs (key_provided false)
  choices={}   what the run names of the choices a check may offer ({app: {kind: value}}: an Odoo database, an add-on,
               a node). The page picks exactly those, from what the check lists only (a recheck when an add-on or node
               pick needs it), and stops before the confirmation when the check offers something the run did not
               name; gate `choices`: the checks, both requests, the first conversion and the chain carry exactly them
  waits={...}  a large backup (the 4.47 GB Nextcloud full share): the page's own bounded waits in seconds, {upload,
               check, result} (the upload with its upload-finish, each check, the import's result; each from a minute up
               to the page's bound), which may then be up to LONG_PAGE_SECONDS instead of PAGE_SECONDS; the page config
               carries them as `waits_ms`. Nothing else changes: the same gates, reads and judgement
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PAGE = HERE / 'focus_acceptance_ui_page.mjs'
# The same browser the R8 and page-emqx runs used (focus_acceptance_ui.PLAYWRIGHT / CHROMIUM).
PLAYWRIGHT = Path('/home/woowtechopenclaw/Woow_cockpit/node_modules/playwright-core/index.mjs')
CHROMIUM = Path.home() / '.cache/ms-playwright/chromium-1208/chrome-linux64/chrome'
PAGE_SECONDS = 20 * 60                   # the page's bound, as in R8 and page-emqx
LONG_PAGE_SECONDS = 60 * 60              # the bound's ceiling when the caller names the page's own waits (a large backup)
WAIT_NAMES = ('upload', 'check', 'result')   # the page's bounded waits (focus_acceptance_ui_protocol.DEFAULT_WAITS_MS)
TERM_GRACE = 15                          # SIGTERM lets the page close Chromium; its process group is killed after this
RELAY_DRAIN = 15                         # the closed browser's connections finish (their exec children end) within this
MIN_START = 5 * 60                       # never start with less time than this before the caller's deadline
READ_RESERVE = 60                        # kept after the page to read its jobs
HOST_MIN_AVAILABLE_KIB = 1200 * 1024     # the browser on the host (focus_acceptance_ui resources())
DEVICE_HEADROOM = 1280 * 1024 ** 2       # the jobs' 1 GiB the drivers require plus the Cockpit session in the device
READ_ONLY = frozenset({'status', 'list', 'jobs', 'job-status'})
PAGE_FILES = ('backup.js', 'backup.css', 'index.html', 'manifest.json')
SHARED = '_shared'                                        # haissues.SHARED
LEVELS = ('stop', 'confirm', 'auto', 'notice')            # haissues.LEVELS
KEY = re.compile(r'[a-z0-9.-]{4,70}:[0-9a-f]{16}\Z')      # haissues.KEY_RE
JOB = re.compile(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
APP = re.compile(r'[a-z0-9][a-z0-9-]{1,40}\Z')            # the page protocol's APP_ID
TEXT = re.compile(r"[A-Za-z0-9 ,()/:'<>.=_-]{3,140}\Z")   # the page protocol's CHECK_TEXT
CHOICE_KINDS = ('addon', 'node', 'database')              # the page protocol's CHOICE_KINDS (haapps choices)
CHOICE_VALUE = re.compile(r'[A-Za-z0-9_.@:+-]{1,100}\Z')  # the page protocol's CHOICE_VALUE


def _sibling(name):
    # -I removes the script directory from sys.path: load the adjacent module explicitly.
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


relay = _sibling('focus_acceptance_ui_relay')


class BridgeError(Exception):
    """The bridge stopped; `summary` holds what is known (never a secret)."""

    def __init__(self, message, summary=None):
        super().__init__(message)
        self.summary = summary or {}


class Refused(BridgeError):
    """A precondition failed before the page started: nothing was changed by the page or the bridge."""


class Interrupted(BridgeError):
    """A soft stop (SIGTERM/SIGINT) while the page ran: the browser was stopped in order and the relay closed;
    `summary` names the page's own jobs found by one read (they may still run)."""


class _Stop(BaseException):
    """Raised once in the main thread by a soft stop while the page runs."""


# ---------------------------------------------------------------- devices and their locks

def lock_path(device):
    """The device's own mutation lock, as every driver of that device takes it (/tmp/woowbk-dev-e-mutation.lock)."""
    return f'/tmp/{relay.device_name(device)}-mutation.lock'


def lock_held(path, *, pid=None, locks=None):
    """True when process `pid` (this one) holds the exclusive flock of the file at `path` (/proc/locks: its device and
    inode). A waiter's line ("N: -> FLOCK ...") or another process's lock does not count."""
    try:
        st = os.stat(path)
    except OSError:
        return False
    ident = '%02x:%02x:%d' % (os.major(st.st_dev), os.minor(st.st_dev), st.st_ino)
    owner = str(os.getpid() if pid is None else pid)
    text = Path('/proc/locks').read_text() if locks is None else locks
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[1:4] == ['FLOCK', 'ADVISORY', 'WRITE'] and fields[4] == owner and fields[5] == ident:
            return True
    return False


# ---------------------------------------------------------------- what the page is told and how it is judged

def selection(apps, importable, stops):
    """(apps, importable, stops) in the selection's order: distinct app ids, every app either importable or stopped."""
    if not all(isinstance(value, (list, tuple)) for value in (apps, importable, stops)):
        raise ValueError('apps, importable and stops are lists')
    apps, importable, stops = list(apps), list(importable), list(stops)
    if (not apps or not all(isinstance(app, str) and APP.fullmatch(app) for app in apps) or len(set(apps)) != len(apps)
            or not importable or len(set(importable)) != len(importable) or len(set(stops)) != len(stops)
            or set(importable) & set(stops) or set(importable) | set(stops) != set(apps)):
        raise ValueError('every selected app must be expected either importable or stopped, at least one importable')
    return apps, [app for app in apps if app in importable], [app for app in apps if app in stops]


def normalized_choices(choices, importable):
    """The run's named choices {app: {kind: value}} (focus_acceptance_ui_protocol.validChoices): only importable selected
    apps, only the kinds a check can offer (a database for Odoo only), only plain safe values. {} is valid: nothing
    named, and any choice the check offers then stops the run."""
    if (not isinstance(choices, dict) or not all(isinstance(app, str) and APP.fullmatch(app) and app in importable
                                                     and isinstance(kinds, dict) and kinds for app, kinds in choices.items())
            or not all(kind in CHOICE_KINDS and (kind != 'database' or app == 'odoo')
                       and isinstance(value, str) and CHOICE_VALUE.fullmatch(value)
                       for app, kinds in choices.items() for kind, value in kinds.items())):
        raise ValueError('choices: {app: {kind: value}} of importable selected apps, kinds addon, node or (Odoo) database')
    return {app: dict(kinds) for app, kinds in choices.items()}


def normalized_waits(waits, page_seconds=None):
    """The page's own waits {upload, check, result} in seconds (focus_acceptance_ui_protocol.validWaits, there in ms): every
    one of them, each a whole number from 60 up to LONG_PAGE_SECONDS and, with `page_seconds` (the page's bound, then at
    most LONG_PAGE_SECONDS), none longer than that bound. Raises ValueError."""
    if (not isinstance(waits, dict) or set(waits) != set(WAIT_NAMES)
            or not all(isinstance(value, int) and not isinstance(value, bool) and 60 <= value <= LONG_PAGE_SECONDS
                       for value in waits.values())
            or (page_seconds is not None and (not isinstance(page_seconds, int) or isinstance(page_seconds, bool)
                                              or not 60 <= page_seconds <= LONG_PAGE_SECONDS
                                              or max(waits.values()) > page_seconds))):
        raise ValueError('waits: upload, check and result in seconds, each from 60 up to the page bound (at most 60 min)')
    return {name: waits[name] for name in WAIT_NAMES}


def page_settings(apps, importable, stops, *, encrypted=True, choices=None, waits=None):
    """What the page is told (focus_acceptance_ui_protocol.pageExpectations): select exactly `apps`; `importable`
    importable, `stops` stopped and excluded; exact mode compares the check's lines and keys with the one request. The
    page's check names say which apps. `encrypted` False (an unencrypted HA backup: no key step, no key), `choices`
    (what the run names of the check's offers) and `waits` (the page's own waits in seconds, as `waits_ms`) are added only
    when given, so an earlier call's settings are unchanged."""
    apps, importable, stops = selection(apps, importable, stops)
    extra = {}
    if encrypted is not True:
        if encrypted is not False:
            raise ValueError('encrypted is True or False')
        extra['encrypted'] = False
    if choices is not None:
        extra['choices'] = normalized_choices(choices, importable)
    if waits is not None:
        extra['waits_ms'] = {name: seconds * 1000 for name, seconds in normalized_waits(waits).items()}
    names = ', '.join
    texts = {'upload': 'UI uploaded the real fixture through the actual page',
             'select': f'UI selects exactly {names(apps)}',
             'view': f'UI check shows {names(importable)} importable' + (f' and {names(stops)} stopped' if stops else ''),
             'result': f'UI result shows {names(importable)} imported' + (f' and {names(stops)} excluded' if stops else ''),
             'intent': f'UI one click sends one real acknowledged import intent for {names(sorted(importable))} only',
             'lines': 'UI lists every confirmation line of the check',
             'keys': 'UI import carries every listed confirmation key exactly once'}
    if not all(TEXT.fullmatch(text) for text in texts.values()):
        raise ValueError('selection too long for the page check names')
    return {'apps': apps, 'importable': importable, 'blocked': stops,
            'result_rows': [[app, 'imported'] for app in importable] + [[app, 'excluded'] for app in stops],
            'exact': True, 'select_stage': 'select-apps', 'texts': texts, **extra}


# ---------------------------------------------------------------- the choices a check offers (CONTRACT section 7 HaCheck)

def choice_rows(row, kind):
    """`choices.<kind>` of one app as the page reads them (backup.js haChoicesOf): rows with a value; ok unless false."""
    source = row.get('choices') if isinstance(row, dict) and isinstance(row.get('choices'), dict) else {}
    rows = source.get(kind) if isinstance(source.get(kind), list) else []
    return [{'value': item['value'], 'ok': item.get('ok') is not False, 'default': item.get('default') is True}
            for item in rows if isinstance(item, dict) and isinstance(item.get('value'), str) and item['value']]


def _section_databases(odoo):
    section = (odoo.get('odoo') or {}) if isinstance(odoo.get('odoo'), dict) else {}
    return [db for db in section.get('databases') or [] if isinstance(db, dict) and isinstance(db.get('name'), str)]


def database_names(odoo):
    """Every database of an Odoo check (backup.js haOdooDatabasesV2): `choices.database`, then the section's."""
    names = [row['value'] for row in choice_rows(odoo, 'database')] + [db['name'] for db in _section_databases(odoo)]
    return list(dict.fromkeys(names))


def usable_databases(result):
    """The Odoo databases that can move (backup.js applyHaCheck / haDatabaseOk); none when Odoo is not importable."""
    odoo = next((row for row in result.get('apps') or [] if isinstance(row, dict) and row.get('app_id') == 'odoo'), None)
    if odoo is None or odoo.get('importable') is not True:
        return []
    rows, section = choice_rows(odoo, 'database'), _section_databases(odoo)
    names = list(dict.fromkeys([db['name'] for db in section] + [row['value'] for row in rows]))

    def ok(name):
        row = next((item for item in rows if item['value'] == name), None)
        return row['ok'] if row else any(db['name'] == name and db.get('ok') is True for db in section)
    return [name for name in names if ok(name)]


def plan_choices(result, named, picked=None):
    """What the page has to do so that exactly the run's named choices are imported, from what THIS check (`result`, its
    ha_check) offers; the same rules as focus_acceptance_ui_protocol.planChoices, which the page runs:
    {problems, clicks, database, import_choices, check_choices}. `picked`: the add-on/node picks already made (the
    params.choices a recheck carried)."""
    problems, clicks, import_choices, check_choices = [], [], {}, {}
    named, picked = named or {}, picked or {}
    apps = [row for row in result.get('apps') or [] if isinstance(row, dict) and isinstance(row.get('app_id'), str)]
    importable = [row for row in apps if row.get('importable') is True]
    ids = [row['app_id'] for row in importable]
    for app, kinds in named.items():
        if app not in ids:
            problems.append(f'{app}: a choice was named for an app the check does not import')
            continue
        for kind in kinds:
            if kind not in CHOICE_KINDS or (kind == 'database' and app != 'odoo'):
                problems.append(f'{app}: no {kind} choice')
    database = None
    for row in importable:
        app = row['app_id']
        for kind in ('addon', 'node'):
            rows, value = choice_rows(row, kind), (named.get(app) or {}).get(kind)
            already = (picked.get(app) or {}).get(kind) if isinstance(picked.get(app), dict) else None
            if len(rows) >= 2:
                if value is None:
                    problems.append(f'{app}: the check offers a {kind} choice and the run named none')
                    continue
                if not any(item['value'] == value and item['ok'] for item in rows):
                    problems.append(f'{app}: the named {kind} is not one the check offers')
                    continue
                current = already if already is not None else next((item['value'] for item in rows if item['default']), None)
                click = current != value
                if click:
                    clicks.append({'app': app, 'kind': kind, 'value': value})
                if click or already is not None:
                    import_choices.setdefault(app, {})[kind] = value
                    check_choices.setdefault(app, {})[kind] = value
            elif value is not None and not (len(rows) == 1 and rows[0]['value'] == value and rows[0]['ok']):
                problems.append(f'{app}: the named {kind} is not one the check offers')
        if app == 'odoo':
            usable, value = usable_databases(result), (named.get('odoo') or {}).get('database')
            if value is not None and value not in usable:
                problems.append('odoo: the named database is not one the check can move')
            elif value is None and len(usable) != 1:
                problems.append('odoo: the check offers several databases and the run named none')
            else:
                database = value if value is not None else usable[0]
                import_choices.setdefault('odoo', {})['database'] = database
    return {'problems': problems, 'clicks': clicks, 'database': database, 'import_choices': import_choices,
            'check_choices': check_choices}


def check_outcome(job, ha_id, apps, importable, stops, choices=None):
    """(expected acknowledgement {group: sorted distinct keys}, confirmation lines the page lists) of the one check of
    this import, which must be exactly the expected outcome: the check of exactly `apps`, every app of `importable`
    importable, every app of `stops` not importable with a stop line about the whole app. Every confirmation line of the
    shared part and of an importable app must carry a valid key: those keys, each once, are what the one acknowledgement
    sends. Without `choices` a line about one database refuses (the bridge chooses none). With `choices` (the run's named
    choices) the check must offer exactly what plan_choices can satisfy, have been made with the add-on/node picks
    (params.choices), and the lines are the ones the page lists for the chosen Odoo database: its own lines count, those
    of the other databases are not listed, and the page's line naming the databases left on HA is counted. Raises
    ValueError with the reason."""
    if choices is not None:
        return _check_outcome_chosen(job, ha_id, apps, importable, stops, choices)
    apps, importable, stops = selection(apps, importable, stops)
    job = job if isinstance(job, dict) else {}
    params = job.get('params') or {}
    result = (job.get('result') or {}).get('ha_check') or {}
    rows, shared = result.get('apps'), result.get('shared')
    if (job.get('type') != 'verify' or job.get('state') != 'succeeded' or params.get('source') != 'ha'
            or params.get('ha_backup_id') != ha_id or not isinstance(params.get('apps'), list)
            or sorted(params['apps']) != sorted(apps) or result.get('schema') != 2 or result.get('ha_backup_id') != ha_id
            or not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows)
            or sorted(str(row.get('app_id')) for row in rows) != sorted(apps) or not isinstance(shared, list)):
        raise ValueError('one current check of exactly the selected apps required')
    expected, lines = {}, 0

    def lines_of(group, issues, confirmed):
        nonlocal lines
        keys = []
        for issue in issues:
            if not isinstance(issue, dict) or issue.get('level') not in LEVELS:
                raise ValueError('unknown check line')
            if issue.get('database') is not None:
                raise ValueError('a line about one database (the bridge chooses no database)')
            if confirmed and issue['level'] == 'stop':
                raise ValueError('a stop line in the shared part or in an importable app')
            if confirmed and issue['level'] == 'confirm':
                if (not isinstance(issue.get('message'), str) or not issue['message']
                        or not isinstance(issue.get('key'), str) or not KEY.fullmatch(issue['key'])):
                    raise ValueError('confirmation line without a valid key')
                keys.append(issue['key'])
                lines += 1
        if keys:
            expected[group] = sorted(set(keys))

    lines_of(SHARED, shared, True)
    for row in rows:
        app, issues = row.get('app_id'), row.get('issues')
        if not isinstance(issues, list):
            raise ValueError('check lines unavailable')
        if row.get('importable') is True:
            if app not in importable:
                raise ValueError(f'{app} is importable, the run expected it stopped')
            lines_of(app, issues, True)
        else:
            if app not in stops:
                raise ValueError(f'{app} is not importable, the run expected it importable')
            lines_of(app, issues, False)
            if not any(isinstance(issue, dict) and issue.get('level') == 'stop' for issue in issues):
                raise ValueError(f'{app} is stopped without a stop line')
    return expected, lines


def _check_outcome_chosen(job, ha_id, apps, importable, stops, choices):
    apps, importable, stops = selection(apps, importable, stops)
    choices = normalized_choices(choices, importable)
    job = job if isinstance(job, dict) else {}
    params = job.get('params') or {}
    result = (job.get('result') or {}).get('ha_check') or {}
    rows, shared = result.get('apps'), result.get('shared')
    if (job.get('type') != 'verify' or job.get('state') != 'succeeded' or params.get('source') != 'ha'
            or params.get('ha_backup_id') != ha_id or not isinstance(params.get('apps'), list)
            or sorted(params['apps']) != sorted(apps) or result.get('schema') != 2 or result.get('ha_backup_id') != ha_id
            or not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows)
            or sorted(str(row.get('app_id')) for row in rows) != sorted(apps) or not isinstance(shared, list)):
        raise ValueError('one current check of exactly the selected apps required')
    picked = params.get('choices') if isinstance(params.get('choices'), dict) else {}
    plan = plan_choices(result, choices, picked)
    if plan['problems']:
        raise ValueError(plan['problems'][0])
    if plan['clicks']:
        raise ValueError('the current check was not made with the chosen add-on or node')
    database = plan['database']
    expected, listed = {}, []

    def lines_of(group, issues, confirmed, app=None):
        keys = []
        for issue in issues:
            if not isinstance(issue, dict) or issue.get('level') not in LEVELS:
                raise ValueError('unknown check line')
            if issue.get('database') is not None and not (app == 'odoo' and issue.get('database') == database):
                continue   # a line about another database (or of no chosen one) is not listed by the page
            if confirmed and issue['level'] == 'stop':
                raise ValueError('a stop line in the shared part, in an importable app or of the chosen database')
            if confirmed and issue['level'] == 'confirm':
                if (not isinstance(issue.get('message'), str) or not issue['message']
                        or not isinstance(issue.get('key'), str) or not KEY.fullmatch(issue['key'])):
                    raise ValueError('confirmation line without a valid key')
                keys.append(issue['key'])
                listed.append(issue)
        if keys:
            expected[group] = sorted(set(keys))

    lines_of(SHARED, shared, True)
    odoo = None
    for row in rows:
        app, issues = row.get('app_id'), row.get('issues')
        if not isinstance(issues, list):
            raise ValueError('check lines unavailable')
        if row.get('importable') is True:
            if app not in importable:
                raise ValueError(f'{app} is importable, the run expected it stopped')
            lines_of(app, issues, True, app)
            odoo = row if app == 'odoo' else odoo
        else:
            if app not in stops:
                raise ValueError(f'{app} is not importable, the run expected it importable')
            lines_of(app, issues, False, app)
            if not any(isinstance(issue, dict) and issue.get('level') == 'stop' for issue in issues):
                raise ValueError(f'{app} is stopped without a stop line')
    left = (odoo is not None and database is not None and len(database_names(odoo)) >= 2
            and not any(issue.get('id') == 'odoo.databases-left' for issue in listed))
    return expected, len(listed) + (1 if left else 0)


def choice_decision(checks, choices, importable):
    """The run's choices against the page's checks (one, or two when an add-on/node pick needed the check again):
    (current check, {database, import_choices, check_choices, checks}) or ValueError. The first check is the one made
    without params.choices; a second must carry exactly the picks the first one made necessary."""
    choices = normalized_choices(choices, importable)
    if not isinstance(checks, list) or len(checks) not in (1, 2) or not all(isinstance(job, dict) for job in checks):
        raise ValueError('one check, or two with a recheck')
    plain = [job for job in checks if not (job.get('params') or {}).get('choices')]
    again = [job for job in checks if (job.get('params') or {}).get('choices')]
    if len(plain) != 1:
        raise ValueError('exactly one check without choices')
    first = plan_choices((plain[0].get('result') or {}).get('ha_check') or {}, choices)
    if first['problems']:
        raise ValueError(first['problems'][0])
    if bool(first['clicks']) != bool(again) or len(again) > 1:
        raise ValueError('a recheck exactly when a named add-on or node was not what the first check showed')
    current = again[0] if again else plain[0]
    if again and (again[0].get('params') or {}).get('choices') != first['check_choices']:
        raise ValueError('the recheck did not carry exactly the picked add-on or node')
    final = plan_choices((current.get('result') or {}).get('ha_check') or {}, choices,
                         (current.get('params') or {}).get('choices') or {})
    if final['problems'] or final['clicks']:
        raise ValueError((final['problems'] or ['the recheck does not show the picked add-on or node'])[0])
    return current, {'database': final['database'], 'import_choices': final['import_choices'],
                     'check_choices': final['check_choices'], 'checks': len(checks)}


def chosen_exactly(decision, browser_choices, requests, first_params):
    """The page chose and sent exactly what the run named (choices only): its record, its requests, the import's first
    conversion (only its own app's choices and, for Odoo, odoo_database) and the chain (every app's choices)."""
    if not isinstance(decision, dict) or not isinstance(browser_choices, dict) or not isinstance(requests, dict):
        return False
    picks, wanted = decision['check_choices'], decision['import_choices']
    checks, sent = requests.get('check'), requests.get('import')
    chain = (first_params or {}).get('chain') if isinstance(first_params, dict) else None
    apps = (first_params or {}).get('apps') if isinstance(first_params, dict) else None
    if not isinstance(checks, list) or not isinstance(sent, dict) or not isinstance(chain, dict) \
            or not isinstance(apps, list) or len(apps) != 1:
        return False
    first_app = apps[0]
    own = {app: kinds for app, kinds in wanted.items() if app == first_app}
    return (browser_choices.get('problems') == [] and browser_choices.get('database') == decision['database']
            and browser_choices.get('import_choices') == wanted and browser_choices.get('check_choices') == picks
            and browser_choices.get('rechecks') == decision['checks'] - 1
            and len(checks) == decision['checks'] and all(isinstance(item, dict) for item in checks)
            and checks[0].get('choices') is None and (decision['checks'] == 1 or checks[-1].get('choices') == picks)
            and sent.get('choices') == (wanted or None)
            and (first_params.get('choices') or {}) == own
            and first_params.get('odoo_database') == (decision['database'] if first_app == 'odoo' else None)
            and (chain.get('choices') or {}) == wanted)


def unencrypted_exactly(checks, browser, first_params):
    """An unencrypted HA backup (no key): the engine was given no key for any check or the import, the wizard showed no
    key step or field and neither request carried a key."""
    if not isinstance(browser, dict) or not isinstance(checks, list) or not checks:
        return False
    step, requests = browser.get('key_step') or {}, browser.get('requests') or {}
    sent = requests.get('check') if isinstance(requests.get('check'), list) else []
    chain = (first_params.get('chain') or {}) if isinstance(first_params, dict) else {}
    return (all(isinstance(job, dict) and (job.get('params') or {}).get('key_provided') is False for job in checks)
            and isinstance(first_params, dict) and first_params.get('key_provided') is not True
            and chain.get('key_provided') is not True
            and step.get('stepper_key_steps') == 0 and step.get('key_fields_after_check') == 0
            and bool(sent) and all(isinstance(item, dict) and item.get('key') is False for item in sent)
            and isinstance(requests.get('import'), dict) and requests['import'].get('key') is False)


def keys_equal(expected, given):
    """`given` ({group: [keys]}; None = nothing sent) holds exactly the expected keys, each exactly once."""
    if given is None:
        given = {}
    if not isinstance(given, dict):
        return False
    seen = {}
    for group, keys in given.items():
        if (not isinstance(keys, list) or not keys or len(set(keys)) != len(keys)
                or not all(isinstance(key, str) and KEY.fullmatch(key) for key in keys)):
            return False
        seen[group] = sorted(keys)
    return seen == expected


def acknowledged_exactly(expected, first_params, sent):
    """The page's one request (`sent`, as the page observed it) and the import's chain carry every expected key exactly
    once and nothing else; the first conversion keeps exactly its own app's keys and the shared ones
    (hachain.convert_params)."""
    if not all(isinstance(value, dict) for value in (expected, first_params, sent)):
        return False
    chain, apps = first_params.get('chain'), first_params.get('apps')
    if not isinstance(chain, dict) or not isinstance(apps, list) or len(apps) != 1:
        return False
    own = {group: keys for group, keys in expected.items() if group in (apps[0], SHARED)}
    return (keys_equal(own, first_params.get('acknowledged')) and keys_equal(expected, chain.get('acknowledged'))
            and keys_equal(expected, sent))


def chain_complete(records, ha_id, importable):
    """Exactly the linked jobs of one import of `importable` (in the order the engine chose, params.chain.apps): per app
    its conversion and the restore of that converted backup, all succeeded and linked, the last one ending the group
    with every app imported."""
    want = sorted(importable)
    if not want or not isinstance(records, list) or len(records) != 2 * len(want) \
            or not all(isinstance(job, dict) for job in records):
        return False
    ids = [job.get('id') for job in records]
    if len(set(ids)) != len(ids) or not all(isinstance(job_id, str) and JOB.fullmatch(job_id) for job_id in ids):
        return False
    order = ((records[0].get('params') or {}).get('chain') or {}).get('apps')
    if not isinstance(order, list) or sorted(order) != want or len(set(order)) != len(order):
        return False
    for index, app in enumerate(order):
        convert, restore = records[2 * index], records[2 * index + 1]
        p1, p2 = convert.get('params') or {}, restore.get('params') or {}
        chain = p1.get('chain') or {}
        converted = (convert.get('result') or {}).get('backup_id')
        if (convert.get('type') != 'backup' or restore.get('type') != 'restore'
                or convert.get('state') != 'succeeded' or restore.get('state') != 'succeeded'
                or p1.get('source') != 'ha' or p1.get('ha_backup_id') != ha_id or p1.get('apps') != [app]
                or p1.get('test_mode') is not False or chain.get('apps') != order
                or chain.get('then_restore') is not True or chain.get('test_mode') is not False
                or not isinstance(converted, str) or not converted or p2.get('backup_id') != converted
                or p2.get('apps') != [app] or p2.get('ha_backup_id') != ha_id):
            return False
    for job, following in zip(records, ids[1:] + [None]):
        if ((job.get('result') or {}).get('group') or {}).get('next_job_id') != following:
            return False
    results = ((records[-1].get('result') or {}).get('group') or {}).get('results')
    return (isinstance(results, list) and len(results) == len(want) and all(isinstance(row, dict) for row in results)
            and sorted(str(row.get('app_id')) for row in results) == want
            and all(row.get('status') == 'imported' for row in results))


def created_by(records):
    """The backups the followed jobs made: each conversion's backup, each restore's safety backup and each copy of a
    whole database service a restore kept before it rebuilt that service (result.kept.<app>.backup_id, kept.py S4: an
    ordinary `safety` backup nothing prunes, e.g. Odoo's cold cluster). A chain without kept copies: exactly as before."""
    found = []
    for job in records:
        result = job.get('result') or {}
        values = [result.get('backup_id') if job.get('type') == 'backup' else result.get('safety_backup_id')]
        if job.get('type') == 'restore' and isinstance(result.get('kept'), dict):
            values += [item.get('backup_id') for item in result['kept'].values() if isinstance(item, dict)]
        for value in values:
            if isinstance(value, str) and value and value not in found:
                found.append(value)
    return found


def by_app(records, kind, field):
    """{app: result[field]} of the followed jobs of `kind` (each job is one app's)."""
    found = {}
    for job in records:
        apps = (job.get('params') or {}).get('apps')
        if job.get('type') == kind and isinstance(apps, list) and len(apps) == 1 and isinstance(apps[0], str):
            found[apps[0]] = (job.get('result') or {}).get(field)
    return found


# Read-only native job records of the chain (fixed program, as root in the device; ids on stdin).
NATIVE_UNITS = ('import json,re,sys; from pathlib import Path; ids=json.load(sys.stdin)["ids"]; '
                'assert 1<=len(ids)<=20 and all(re.fullmatch(r"j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}",x) for x in ids); '
                'p=Path("/var/lib/woowtech-backup/jobs"); rows=[json.loads((p/(x+".json")).read_bytes()) for x in ids]; '
                'print(json.dumps([{k:r.get(k) for k in ("id","unit","type","state")} for r in rows]))')


def native_units_ok(native, records):
    """Every job's own record agrees with the followed chain and runs in the first job's unit."""
    if not isinstance(native, list) or not records or len(native) != len(records):
        return False
    unit = 'woowtech-backup-' + str(records[0].get('id')) + '.service'
    return all(isinstance(n, dict) and n.get('id') == r.get('id') and n.get('type') == r.get('type')
               and n.get('state') == r.get('state') and n.get('unit') == unit for n, r in zip(native, records))


# Read-only facts of the device before the page (fixed program, as root in the device; values never leave it).
PRECONDITIONS = r'''
import hashlib, json, pwd, socket, subprocess
from pathlib import Path
page = Path("/usr/local/share/cockpit/woowtechbackup")
out = {"page": {n: hashlib.sha256((page / n).read_bytes()).hexdigest()
                for n in ("backup.js", "backup.css", "index.html", "manifest.json")}}
out["cockpit_socket"] = subprocess.run(["systemctl", "is-active", "--quiet", "cockpit.socket"], timeout=60).returncode == 0
out["hostname"] = socket.gethostname()
try:
    out["devadmin_uid"] = pwd.getpwnam("devadmin").pw_uid
except KeyError:
    out["devadmin_uid"] = None
stat = Path("/sys/fs/cgroup/memory.stat").read_text().splitlines()
used = sum(int(x.split()[1]) for x in stat if x.startswith(("anon ", "kernel ")))
limit = Path("/sys/fs/cgroup/memory.max").read_text().strip()
out["headroom"] = int(limit) - used if limit.isdigit() else None
print(json.dumps(out))
'''


def preconditions_failed(probe, source, device, headroom):
    """Names of the device preconditions the probe does not meet (empty: all met)."""
    probe = probe if isinstance(probe, dict) else {}
    try:
        tree = {name: hashlib.sha256((Path(source) / 'backup' / name).read_bytes()).hexdigest() for name in PAGE_FILES}
    except OSError:
        tree = None
    failed = []
    if tree is None or probe.get('page') != tree:
        failed.append('installed page differs from the tree')
    if probe.get('cockpit_socket') is not True:
        failed.append('cockpit.socket not active')
    if probe.get('hostname') != device:
        failed.append('device hostname is not its name')
    if not isinstance(probe.get('devadmin_uid'), int) or isinstance(probe.get('devadmin_uid'), bool):
        failed.append('no devadmin account')
    room = probe.get('headroom')
    if not isinstance(room, int) or isinstance(room, bool) or room < headroom:
        failed.append('device memory headroom below %d MiB' % (headroom >> 20))
    return failed


def host_available_kib():
    return next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                if line.startswith('MemAvailable:'))


def child_pids(pid=None):
    """Live or unreaped child processes of `pid` (this process), from /proc."""
    parent = str(os.getpid() if pid is None else pid)
    found = []
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        try:
            stat = Path('/proc', entry, 'stat').read_text()
        except OSError:
            continue
        fields = stat[stat.rfind(')') + 2:].split()   # "pid (comm) state ppid ...": comm may hold spaces
        if len(fields) > 1 and fields[1] == parent:
            found.append(int(entry))
    return sorted(found)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(8 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def issued_scan_summary(browser):
    """The browser's issued-value (cookie) scan as counts and flags only (never a value; digests stay in browser.json)."""
    counts = (browser or {}).get('issued_scan_counts') or {}
    return {'scanned': (browser or {}).get('issued_values_scanned') is True, 'scan_completed': counts.get('scan_completed'),
            'observed_values': counts.get('observed_values'), 'observations_complete': counts.get('observations_complete'),
            'credential_device_hits': counts.get('credential_device_hits'),
            'credential_host_hits': counts.get('credential_host_hits'), 'device_files': counts.get('device_files'),
            'host_files': counts.get('host_files'), 'archive_index_sidecars': counts.get('archive_index_sidecars'),
            'regular_json_roots': counts.get('regular_json_roots')}


# ---------------------------------------------------------------- the driver's device access (read-only here)

class Ops:
    """What the bridge needs from the driver: helper(command, request) -> reply (raises on a refusal),
    wait_job(job_id, timeout) -> the terminal job record, root_json(script, request) -> the JSON a root
    `python3 -I -c script` printed inside the device. Only READ_ONLY helper commands pass."""

    def __init__(self, helper, wait_job, root_json):
        self._helper, self._wait_job, self._root_json = helper, wait_job, root_json

    def helper(self, command, request=None):
        if command not in READ_ONLY:
            raise PermissionError('the page bridge sends read-only helper commands only')
        return self._helper(command, request)

    def wait_job(self, job_id, timeout):
        if not isinstance(job_id, str) or not JOB.fullmatch(job_id):
            raise ValueError('job id')
        return self._wait_job(job_id, timeout)

    def root_json(self, script, request):
        if script not in (PRECONDITIONS, NATIVE_UNITS):
            raise PermissionError('the page bridge runs its two read-only device programs only')
        return self._root_json(script, request)


class PageImport:
    """The judged page import: `summary` (JSON, no secret), the (current) check job record, the followed chain records
    and every check record the page made (two when a named add-on/node needed the check again)."""

    def __init__(self, summary, check_job, chain, check_jobs=None):
        self.summary, self.check_job, self.chain = summary, check_job, chain
        self.check_jobs = list(check_jobs or ([check_job] if check_job else []))

    @property
    def passed(self):
        return self.summary.get('passed') is True

    @property
    def gates(self):
        return dict(self.summary.get('gates') or {})

    @property
    def browser_checks(self):
        return list((self.summary.get('browser') or {}).get('checks') or [])


# ---------------------------------------------------------------- the page itself

def stop_browser(proc, grace=None):
    """SIGTERM lets the page finish its record and close Chromium; after `grace` (TERM_GRACE) seconds its own process
    group (node and Chromium: start_new_session) gets SIGKILL while node is still unreaped, so no other process is hit."""
    if proc.poll() is not None:
        return 'exited'
    proc.send_signal(signal.SIGTERM)
    try:
        proc.communicate(timeout=TERM_GRACE if grace is None else grace)
        return 'terminated'
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            proc.kill()
        proc.communicate()
        return 'killed'


def drain(channel, seconds=None):
    """Once the browser is gone its connections close by themselves: wait (bounded) until the relay has no connection
    and no exec child left, so that stopping it cancels nothing that is still closing."""
    deadline = time.monotonic() + (RELAY_DRAIN if seconds is None else seconds)
    while (getattr(channel, 'tasks', ()) or channel.children) and time.monotonic() < deadline:
        time.sleep(0.1)


def run_page(config, seconds, device):
    """Run the page once through the device's relay. Never raises for the page's own failure, a timeout, a soft stop or
    a relay that would not start or close: the outcome says so. The browser is always stopped and the relay closed."""
    outcome = {'started': False, 'start_error': None, 'exit': None, 'timed_out': False, 'interrupted': False,
               'stop': None, 'relay_clean': False, 'relay_error': None, 'children_left': None}
    state = {'armed': False, 'pending': False}

    def soft_stop(_signum, _frame):
        state['pending'] = True
        if state['armed']:           # only while the page runs; never inside the browser's own shutdown
            state['armed'] = False
            raise _Stop()

    previous = {}
    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, soft_stop)
    try:
        channel = relay.Relay(device)
        try:
            with channel:
                proc = None
                if not state['pending']:
                    try:
                        proc = subprocess.Popen(['node', str(PAGE), '--run'], stdin=subprocess.PIPE,
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                    except OSError as error:   # node missing or not runnable: nothing started
                        outcome['start_error'] = type(error).__name__
                if proc is not None:
                    outcome['started'] = True
                    try:
                        state['armed'] = True
                        if state['pending']:
                            raise _Stop()
                        proc.communicate(json.dumps(dict(config, base=channel.base)).encode(), timeout=seconds)
                        state['armed'] = False
                        outcome['stop'] = 'exited'
                    except (subprocess.TimeoutExpired, _Stop) as error:
                        state['armed'] = False
                        outcome['timed_out'] = isinstance(error, subprocess.TimeoutExpired)
                        outcome['stop'] = stop_browser(proc)
                    except BaseException:
                        state['armed'] = False
                        outcome['stop'] = stop_browser(proc)
                        raise
                    outcome['exit'] = proc.returncode
                drain(channel)
            outcome['relay_clean'] = not channel.children and not channel.thread.is_alive()
        except RuntimeError as error:   # the relay did not start, or its exec children were not all reaped
            outcome['relay_error'] = str(error)[:120]
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    outcome['interrupted'] = state['pending']
    outcome['children_left'] = child_pids()
    return outcome


# ---------------------------------------------------------------- the bridge

def _write(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w') as handle:
        json.dump(value, handle, indent=1)
        handle.write('\n')


def _read_browser(path):
    if path.is_symlink() or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def import_via_page(*, device, apps, importable, stops, fixture, password, evidence, deadline, ops, key=None,
                    choices=None, source=REPO, lock=None, playwright=None, chromium=None, page_seconds=PAGE_SECONDS,
                    device_headroom=DEVICE_HEADROOM, clock=time.monotonic, waits=None):
    """One import of the fixture through the device's real Cockpit page; returns PageImport (judged, never raises for a
    failed page or a failed gate). Raises Refused before the page when a precondition fails, Interrupted after a soft
    stop. `deadline` is a clock() value: the page gets at most `page_seconds` (20 min) of it, the rest reads its jobs.
    `evidence` is a new directory (created 0700): the page's screenshots, cookie metadata and browser.json, and the
    bridge's page-bridge.json. `key` (the HA key) and `password` (devadmin's Cockpit password) reach only the page's
    stdin.

    `key` None: an UNENCRYPTED HA backup. The page enters no key and checks that the wizard asks for none, that neither
    request carries one, and the engine's jobs say no key was provided (gate `unencrypted`).
    `choices` (None: none of this, exactly the earlier flow): {app: {kind: value}} - what the run names of the choices a
    check may offer (an Odoo database, an add-on, a node). The page picks exactly those, only from what the check lists,
    runs the check again when an add-on/node pick needs it, and stops before the confirmation when the check offers a
    choice the run did not name or does not offer a named one; {} names nothing (any offered choice then stops). Gate
    `choices`: the checks, the page's record, both requests, the first conversion and the chain carry exactly them.
    `waits` (None: the page's earlier 10, 10 and 20 minutes and a bound of at most PAGE_SECONDS): {upload, check, result}
    seconds for a large backup; `page_seconds` may then be up to LONG_PAGE_SECONDS, never shorter than a wait."""
    began = clock()
    summary = {'bridge': 'focus_page_bridge', 'phase': 'preconditions', 'device': device, 'passed': False}
    try:
        device = relay.device_name(device)
        apps, importable, stops = selection(apps, importable, stops)
        if waits is not None:
            waits = normalized_waits(waits, page_seconds)
        settings = page_settings(apps, importable, stops, encrypted=key is not None, choices=choices, waits=waits)
    except ValueError as error:
        raise Refused(str(error), summary) from None
    choosing, keyless = choices is not None, key is None
    choices = settings.get('choices')
    summary.update(apps=apps, importable=importable, stops=stops)
    if waits is not None:   # a large backup's own waits; an earlier call's summary has no such key
        summary['waits'] = waits
    fixture, evidence, source = Path(fixture), Path(evidence), Path(source)
    playwright, chromium = Path(playwright or PLAYWRIGHT), Path(chromium or CHROMIUM)
    lock = lock or lock_path(device)
    budget = min(int(page_seconds), int(deadline - began) - READ_RESERVE)
    reasons = []
    if not lock_held(lock):
        reasons.append(f'this process does not hold {lock}')
    if fixture.is_symlink() or not fixture.is_file():
        reasons.append('fixture is not a regular file')
    if (not keyless and (not isinstance(key, str) or len(key) < 16)) or not isinstance(password, str) or len(password) < 6:
        reasons.append('HA key or Cockpit password missing')
    if not 60 <= int(page_seconds) <= (PAGE_SECONDS if waits is None else LONG_PAGE_SECONDS) or deadline - began < MIN_START:
        reasons.append('not enough time before the deadline')
    if evidence.exists() or evidence.is_symlink() or not evidence.parent.is_dir():
        reasons.append('evidence must be a new directory in an existing one')
    if not playwright.is_file() or not chromium.is_file():
        reasons.append('browser package or Chromium missing')
    if reasons:
        raise Refused('; '.join(reasons), dict(summary, reasons=reasons))
    evidence.mkdir(mode=0o700)
    os.chmod(evidence, 0o700)
    fixture_sha = sha256_file(fixture)
    ha_id = 'ha-' + fixture_sha[:20]
    summary.update(ha_id=ha_id, fixture_sha256=fixture_sha, fixture_bytes=fixture.stat().st_size, budget_s=budget)

    def refuse(reasons):
        summary['reasons'] = reasons
        _write(evidence / 'page-bridge.json', dict(summary, phase='refused'))
        raise Refused('; '.join(reasons), dict(summary, phase='refused'))

    # Read-only facts before the page: nothing above changed the device, nothing here does.
    if host_available_kib() < HOST_MIN_AVAILABLE_KIB:
        refuse(['host available memory below 1200 MiB for the browser'])
    unread = None
    try:
        failed = preconditions_failed(ops.root_json(PRECONDITIONS, {}), source, device, device_headroom)
        if ops.helper('status').get('active_job'):
            failed.append('a job is active')
        listing = ops.helper('list')
        before_backups = {row.get('id') for row in listing.get('backups') or []}
        records = [row for row in listing.get('ha_backups') or [] if row.get('id') == ha_id]
        before_jobs = {row.get('id') for row in ops.helper('jobs').get('jobs') or []}
    except Exception as error:   # noqa: BLE001 - a read that fails before the page changed nothing
        unread = type(error).__name__
    if unread:
        refuse([f'precondition read failed ({unread})'])
    if len(records) > 1 or (records and records[0].get('sha256') != fixture_sha):
        failed.append('an HA record of this id with other bytes exists')
    if failed:
        refuse(failed)
    summary.update(ha_record_existed=bool(records), phase='page')

    config = {'ha_id': ha_id, 'fixture': str(fixture), 'password': password, 'key': key, 'evidence': str(evidence),
              'result': str(evidence / 'browser.json'), 'playwright': str(playwright), 'chromium': str(chromium),
              'since': int(time.time()) - 1, 'device': device, **settings}
    if keyless:
        del config['key']   # an unencrypted HA backup: the page has no key at all (settings say encrypted: false)
    page = run_page(config, budget, device)
    del config
    page['elapsed_s'] = round(clock() - began, 1)
    summary['page'] = page
    browser = _read_browser(evidence / 'browser.json')
    summary['browser'] = None if browser is None else {
        'completed': browser.get('completed') is True, 'stage': browser.get('stage'),
        'failure_kind': browser.get('failure_kind'), 'checks': browser.get('checks') if isinstance(browser.get('checks'), list) else [],
        'issued_values_scanned': browser.get('issued_values_scanned') is True, 'issued_scan': issued_scan_summary(browser),
        'confirmations': browser.get('confirmations'), 'wire': browser.get('wire')}
    if browser is not None and (choosing or keyless):   # the new modes' records: keys present or not, never a value
        summary['browser'].update({name: browser.get(name) for name in ('choices', 'key_step', 'requests')
                                   if name in browser})

    def own_jobs():
        rows = ops.helper('jobs').get('jobs') or []
        return [row for row in rows if row.get('id') not in before_jobs
                and (row.get('params') or {}).get('ha_backup_id') == ha_id]

    def roots_of(own):
        return [row for row in own if row.get('type') == 'backup' and (row.get('params') or {}).get('source') == 'ha'
                and ((row.get('params') or {}).get('group') or {}).get('kind') == 'ha-import'
                and ((row.get('params') or {}).get('group') or {}).get('index') == 0]

    if page['interrupted']:
        # One read of the page's own jobs for the driver's recovery; they may still run, nothing waits for them. The
        # backups their finished results name go to the driver's cleanup (the helper refuses one a running job uses).
        try:
            own = own_jobs()
            summary.update(check_job_ids=[row['id'] for row in own if row.get('type') == 'verify'],
                           root_job_ids=[row['id'] for row in roots_of(own)],
                           created_backups=created_by(sorted((row for row in own if row.get('type') in ('backup', 'restore')),
                                                             key=lambda row: str(row.get('id')))))
        except Exception as error:   # noqa: BLE001 - the stop is reported either way
            summary['read_error'] = type(error).__name__
        summary['phase'] = 'interrupted'
        _write(evidence / 'page-bridge.json', summary)
        raise Interrupted('page import interrupted; the browser was stopped and the relay closed', summary)

    gates, why = {}, {}
    check_job, chain, expected, lines, inflight = None, [], None, None, None
    checks, roots, own, check_jobs, decision = [], [], [], [], None
    try:
        own = own_jobs()
        checks = [row for row in own if row.get('type') == 'verify']
        roots = roots_of(own)
        if choosing and len(checks) in (1, 2):   # a second check only when a named add-on/node needed it
            check_jobs = [ops.wait_job(row['id'], max(1, int(deadline - clock()))) for row in checks]
        elif len(checks) == 1:
            check_job = ops.wait_job(checks[0]['id'], max(1, int(deadline - clock())))
            check_jobs = [check_job]
        if len(roots) == 1:
            current, seen = roots[0]['id'], set()
            while current:
                if current in seen or len(chain) >= 2 * len(importable):
                    raise ValueError('unexpected chain layout')
                seen.add(current)
                inflight = current
                if deadline - clock() <= 0:
                    raise TimeoutError('deadline reached while a job of the import runs')
                job = ops.wait_job(current, max(1, int(deadline - clock())))
                chain.append(job)
                inflight = None
                current = ((job.get('result') or {}).get('group') or {}).get('next_job_id')
    except Exception as error:   # noqa: BLE001 - a job that cannot be read fails its gate, never the driver's cleanup
        why['jobs'] = f'{type(error).__name__}: {str(error)[:160]}'
    if choosing:
        try:
            check_job, decision = choice_decision(check_jobs, choices, importable)
        except ValueError as error:
            why['choices'] = str(error)[:200]
    try:
        expected, lines = (check_outcome(check_job, ha_id, apps, importable, stops, choices) if choosing
                           else check_outcome(check_job, ha_id, apps, importable, stops))
    except ValueError as error:
        why['expected_outcome'] = str(error)[:200]
    confirmations = (browser or {}).get('confirmations') or {}
    gates['expected_outcome'] = (expected is not None and confirmations.get('expected_keys') == expected
                                 and confirmations.get('lines_expected') == lines == confirmations.get('lines_shown')
                                 and confirmations.get('check_importable') == sorted(importable))
    first = (chain[0].get('params') or {}) if chain else {}
    gates['acknowledged_exact'] = expected is not None and acknowledged_exactly(expected, first,
                                                                               confirmations.get('sent_keys'))
    gates['chain'] = chain_complete(chain, ha_id, importable)
    native = None
    if chain:
        try:
            native = ops.root_json(NATIVE_UNITS, {'ids': [job.get('id') for job in chain]})
        except Exception as error:   # noqa: BLE001
            why['native_units'] = type(error).__name__
    gates['native_units'] = native_units_ok(native, chain)
    created = created_by(chain)
    after_read, after_backups, present, active = False, set(), False, True
    try:
        listing = ops.helper('list')
        after_backups = {row.get('id') for row in listing.get('backups') or []}
        present = any(row.get('id') == ha_id and row.get('sha256') == fixture_sha for row in listing.get('ha_backups') or [])
        active = bool(ops.helper('status').get('active_job'))
        own = own_jobs()
        after_read = True
    except Exception as error:   # noqa: BLE001
        why['after'] = type(error).__name__
    accounted = {row.get('id') for row in checks[:2 if choosing else 1]} | {job.get('id') for job in chain}
    unexplained = sorted(after_backups - before_backups - set(created))
    # One check; with choices two exactly when a named add-on/node needed the check again (choice_decision).
    wanted_checks = (decision or {}).get('checks') if choosing else 1
    gates['own_jobs'] = (after_read and len(checks) == wanted_checks and len(roots) == 1 and not active
                         and inflight is None and {row.get('id') for row in own} <= accounted)
    gates['record'] = after_read and present
    gates['no_unexplained_backups'] = after_read and not unexplained
    gates['page_bounded'] = page['started'] and not page['timed_out'] and page['stop'] == 'exited'
    gates['cleanup'] = page['relay_clean'] and page['children_left'] == [] and page['stop'] in ('exited', 'terminated')
    gates['browser_flow'] = (page['exit'] == 0 and browser is not None and browser.get('completed') is True
                             and bool(summary['browser']['checks'])
                             and all(isinstance(item, dict) and item.get('ok') is True for item in summary['browser']['checks']))
    scan = issued_scan_summary(browser)
    gates['issued_scan'] = scan['scanned'] and scan['scan_completed'] is True
    if choosing:
        gates['choices'] = decision is not None and chosen_exactly(decision, (browser or {}).get('choices'),
                                                                   (browser or {}).get('requests'), first)
        summary.update(chosen=decision, check_job_ids=[job.get('id') for job in check_jobs if isinstance(job, dict)])
    if keyless:
        gates['unencrypted'] = unencrypted_exactly(check_jobs, browser, first)
        summary['unencrypted'] = True
    summary.update(phase='judged', check_job_id=check_job.get('id') if check_job else None,
                   root_job_id=roots[0].get('id') if len(roots) == 1 else None,
                   chain_job_ids=[job.get('id') for job in chain], inflight=inflight,
                   converted=by_app(chain, 'backup', 'backup_id'), safety=by_app(chain, 'restore', 'safety_backup_id'),
                   created_backups=created, unexplained_new_backups=unexplained, ha_record_present=present,
                   expected_acknowledged=expected, confirmation_lines=lines, native_units=native, gates=gates, reasons=why,
                   passed=all(gates.values()), elapsed_s=round(clock() - began, 1))
    _write(evidence / 'page-bridge.json', summary)
    return PageImport(summary, check_job, chain, check_jobs)


def self_check():
    for program in (PRECONDITIONS, NATIVE_UNITS):
        compile(program, '<device program>', 'exec')
    assert page_settings(['open-design'], ['open-design'], [])['exact'] is True
    assert page_settings(['headscale'], ['headscale'], [], encrypted=False, choices={})['encrypted'] is False
    assert page_settings(['nextcloud'], ['nextcloud'], [], waits={'upload': 1800, 'check': 600, 'result': 1500}
                         )['waits_ms'] == {'upload': 1800000, 'check': 600000, 'result': 1500000}
    print('page bridge prepared: offline syntax PASS (a library: a full-flow driver calls import_via_page)')
    return 0


if __name__ == '__main__':
    sys.exit(self_check())
