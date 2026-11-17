"""排程備份 (scheduled backups): settings, slots, the tick decision, the registry and its events (CONTRACT sections 3,
7, 8 "Scheduled backups"). Owner: E2 engine-ops.

* Settings: `/etc/woowtech-cockpit/backup/schedule.json` (root 0644, next to retention.json, at most 16 KiB, unknown
  keys rejected): `{"schema": 1, "enabled", "days", "time", "apps", "include_images", "keep_last", "updated",
  "armed_at"}`. Missing means off, with the defaults (every day at 03:00, all apps, no images, keep the newest 7
  scheduled backups). A file that is not root-owned, is group/world-writable, a symlink, too large or invalid turns the
  schedule off with a zh-TW `problem`; it never deletes anything. Changed only through `schedule-set` (audited).
* Slots: a slot is a local date and `time` on a scheduled weekday in the device's time zone (`/etc/localtime`; the
  caller's `TZ` is ignored, so a change of the zone applies at the next tick), as a UTC instant. A time that a DST
  change skips runs when the clock jumps past it; a time it repeats runs at its first occurrence. Slots before
  `armed_at` (the schedule was turned on, or its time or days changed) never run; while the clock is below
  `armed_at` (it went back) they start at the time of the first tick that saw that, kept as a floor.
* The tick (`schedule-tick`, run by woowtech-cockpit-backup-schedule.timer every 5 minutes) touches
  `/run/woowtech-backup/schedule-tick` and decides with `decide`, a pure function of the settings, the state, the clock,
  the zone and the uptime (since PID 1 started): the latest due slot that is not handled yet starts a job when it is
  less than 15 minutes late (`on-time`); a slot that waited for another job starts as soon as that job ended (`late`)
  and is recorded `skipped` when the next slot arrives first; a slot no tick saw in time (the device was off, the timer
  stopped) is caught up once, only the latest one, after 10 minutes of uptime (`catch-up`), unless the next slot is less
  than 3 hours away: then it is recorded `missed`. No run starts before 10 minutes of uptime. There is no automatic
  retry: a problem before the job starts (no device key while 預設加密備份 is on, no app) is an event, a problem inside it a
  failed job.
  `request_id` `schedule-<slot UTC>` keeps two ticks from starting two jobs for one slot; a tick lock serialises ticks.
* State: `/var/lib/woowtech-backup/schedule-state.json` (root 0600): the registry `{backup id: {job, slot, trigger}}`
  (a backup is a scheduled one only when its index type is `manual` and its id is listed: the archive and index
  formats are those of 2026.11.15.2), the last handled slot (and the one a clock reset put aside until the clock is
  past it again), the floor kept while the clock is below `armed_at`, the slot waiting for another job, the last run
  and the recent events (newest first, at most 50). The job writes its registry entry before any app pauses; an
  entry goes once its job ended (its record is readable and finished, or gone) and then its backup is gone (an
  unreadable record keeps it). The last run's outcome is recorded once its job ended the same way: an unreadable
  record is not an ended job, so no failure is recorded for it. A state file that cannot be read stops the schedule and
  every automatic deletion of manual and scheduled backups (retention cannot tell them apart then); it is never
  overwritten. Problems are worded for the device's owner, without file names (CONTRACT section 3 names the files).
* Journal (syslog ident woowtech-cockpit-backup, authpriv; notice, warning for failures), once per slot:
  `schedule-set`, `schedule-run`, `schedule-wait`, `schedule-skip`, `schedule-missed`, `schedule-result`,
  `schedule-clock` (the clock went back) and the scheduled retention's `retention-delete … reason=schedule`.
"""
import contextlib
import datetime
import fcntl
import os
import re
import subprocess
import time
import zoneinfo
import json
from dataclasses import dataclass
from pathlib import Path

from . import catalog
from . import jobs
from . import util
from .catalog_admin import login_uid, open_trusted_dir, pretty, read_trusted_file, write_trusted_file
from .errors import BackupError

FILE = 'schedule.json'
STATE_FILE = 'schedule-state.json'
TICK_FILE = 'schedule-tick'
TICK_LOCK = 'schedule-tick.lock'
STATE_LOCK = 'schedule.lock'
STATE_NOTE = 'schedule-state.reported'  # in /run: the unreadable state file is logged once per boot
TIMER = 'woowtech-cockpit-backup-schedule.timer'
SCHEMA = 1
MAX_BYTES = 16 * 1024
MAX_STATE_BYTES = 4 * 1024 * 1024
DAYS = ('mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun')
TIME_RE = re.compile(r'([01][0-9]|2[0-3]):[0-5][0-9]\Z')
APP_ID_RE = re.compile(r'[a-z0-9][a-z0-9-]{1,40}\Z')
BACKUP_ID_RE = re.compile(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
ZONE_NAME_RE = re.compile(r'[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*\Z')
MAX_APPS = 100
MAX_KEEP = 1000
FIELDS = ('enabled', 'days', 'time', 'apps', 'include_images', 'keep_last')
FILE_KEYS = ('schema', *FIELDS, 'updated', 'armed_at')
DEFAULTS = {'enabled': False, 'days': list(DAYS), 'time': '03:00', 'apps': 'all', 'include_images': False,
            'keep_last': 7}
NOTE = '排程備份'  # the note of every scheduled backup (archive and index; the type stays `manual`)
TRIGGERS = ('on-time', 'late', 'catch-up', 'run-now')
REQUEST_PREFIX = 'schedule-'
ON_TIME_SECONDS = 15 * 60
SETTLE_SECONDS = 10 * 60
CATCH_UP_GAP_SECONDS = 3 * 3600
CLOCK_BACK_SECONDS = 24 * 3600
OVERDUE_SECONDS = 30 * 60
TICK_STALE_SECONDS = 15 * 60
LOOKBACK_DAYS = 400
MAX_EVENTS = 50
EVENT_KINDS = ('waiting', 'missed', 'skipped', 'no-key', 'no-apps', 'settings-problem', 'failed', 'partial',
               'cancelled')
# Kinds of slots that did not run (the activity list shows them as 未執行).
NOT_RUN = ('missed', 'skipped', 'no-key', 'no-apps')
UTC = datetime.timezone.utc
STATE_PROBLEM = ('排程備份的紀錄檔無法讀取，排程備份已暫停；在修復之前，也不會依保留份數自動刪除手動或排程備份。'
                 '請通知工程人員檢查。')
ASK_ENGINEER = '請通知工程人員檢查。'
TIMER_MESSAGE = '排程檢查沒有在執行，排程備份不會自動開始。請重新執行備份元件的安裝程式來啟用它。'


# ---------------------------------------------------------------- settings

def defaults():
    return {**{key: (list(value) if isinstance(value, list) else value) for key, value in DEFAULTS.items()},
            'updated': None, 'armed_at': None}


def _bad(field_name, text):
    where = f'schedule.{field_name}' if field_name else 'schedule'
    return BackupError('invalid-request', f'排程設定{" " + field_name if field_name else ""} {text}', field=where)


def _normalize(data):
    """The six settings of `data`, validated and normalized (`days` in week order)."""
    if not isinstance(data['enabled'], bool):
        raise _bad('enabled', '必須是 true 或 false。')
    days = data['days']
    if (not isinstance(days, list) or not 1 <= len(days) <= len(DAYS) or any(day not in DAYS for day in days)
            or len(set(days)) != len(days)):
        raise _bad('days', '必須是 1 到 7 個不重複的星期（mon、tue、wed、thu、fri、sat、sun）。')
    value = data['time']
    if not isinstance(value, str) or not TIME_RE.fullmatch(value) or int(value[3:]) % 5:
        raise _bad('time', '必須是 HH:MM（00:00 到 23:55，以 5 分鐘為單位）。')
    apps = data['apps']
    if apps != 'all':
        if (not isinstance(apps, list) or not 1 <= len(apps) <= MAX_APPS
                or any(not isinstance(item, str) or not APP_ID_RE.fullmatch(item) for item in apps)):
            raise _bad('apps', f'必須是 "all" 或 1 到 {MAX_APPS} 個應用 ID 的陣列。')
        if len(set(apps)) != len(apps):
            raise _bad('apps', '含有重複的應用 ID。')
        apps = list(apps)
    if not isinstance(data['include_images'], bool):
        raise _bad('include_images', '必須是 true 或 false。')
    keep = data['keep_last']
    if keep is not None and (isinstance(keep, bool) or not isinstance(keep, int) or not 1 <= keep <= MAX_KEEP):
        raise _bad('keep_last', f'必須是 1 到 {MAX_KEEP} 的整數，或 null（全部保留）。')
    return {'enabled': data['enabled'], 'days': [day for day in DAYS if day in days], 'time': value, 'apps': apps,
            'include_images': data['include_images'], 'keep_last': keep}


def validate(data):
    """The `schedule` object of `schedule-set`: every one of FIELDS, nothing else (`updated`/`armed_at` are the
    engine's)."""
    if not isinstance(data, dict):
        raise _bad('', '必須是 JSON 物件。')
    unknown = sorted(set(data) - set(FIELDS))
    if unknown:
        raise _bad('', f'含有不支援的欄位：{", ".join(str(key)[:40] for key in unknown[:5])}。')
    for name in FIELDS:
        if name not in data:
            raise _bad(name, '為必填。')
    return _normalize(data)


def _from_file(data):
    if not isinstance(data, dict) or set(data) != set(FILE_KEYS):
        raise ValueError('keys')
    if isinstance(data['schema'], bool) or data['schema'] != SCHEMA:
        raise ValueError('schema')
    settings = _normalize(data)
    for name in ('updated', 'armed_at'):
        if data[name] is not None and not util.is_iso_utc(data[name]):
            raise ValueError(name)
    if settings['enabled'] and data['armed_at'] is None:
        raise ValueError('armed_at')
    return {**settings, 'updated': data['updated'], 'armed_at': data['armed_at']}


def _problem(text, advice=ASK_ENGINEER):
    """The zh-TW problem of a settings file the engine does not use (the page shows it as is)."""
    return f'排程備份的設定檔{text}，排程備份已暫停。{advice}'


def load(paths, *, trusted_uid=0):
    """(settings, problem, saved): the saved settings, or the defaults (off) with a zh-TW problem when the file is
    unsafe or invalid; `saved` is False when there is no file. Never raises for a bad file."""
    try:
        cfd = open_trusted_dir(paths.config, trusted_uid)
    except BackupError as error:
        if error.code == 'internal-error':  # no configuration directory yet: nothing was saved
            return defaults(), None, False
        return defaults(), _problem('所在的資料夾權限不安全'), False
    try:
        current = read_trusted_file(cfd, FILE, max_bytes=MAX_BYTES)
    except BackupError as error:
        text = '過大' if error.code == 'limit-exceeded' else '不是一般檔案'
        return defaults(), _problem(text), True
    except OSError:
        return defaults(), _problem('無法讀取'), True
    finally:
        os.close(cfd)
    if current is None:
        return defaults(), None, False
    if current['uid'] != trusted_uid or current['mode'] & 0o022:
        return defaults(), _problem('權限不安全（必須只有系統管理員能修改）'), True
    try:
        return _from_file(catalog.parse_json_bytes(current['data'])), None, True
    except (BackupError, ValueError, UnicodeDecodeError, RecursionError):
        return defaults(), _problem('內容不正確', '請重新儲存排程設定。'), True


def prepared(previous, schedule, now=None):
    """What `save` writes: `updated` now; `armed_at` now when the schedule is turned on or its time or days change
    while it is on (slots before it never run), else kept."""
    stamp = util.iso_utc(now)
    armed = previous.get('armed_at')
    if schedule['enabled'] and (not previous.get('enabled') or armed is None or previous.get('time') != schedule['time']
                                or previous.get('days') != schedule['days']):
        armed = stamp
    return {'schema': SCHEMA, **schedule, 'updated': stamp, 'armed_at': armed}


def save(paths, schedule, *, trusted_uid=0, now=None):
    """Write validated settings (root 0644, atomic); returns (saved record, previous settings)."""
    previous, _problem_text, _saved = load(paths, trusted_uid=trusted_uid)
    record = prepared(previous, schedule, now)
    cfd = open_trusted_dir(paths.config, trusted_uid)
    try:
        current = read_trusted_file(cfd, FILE, max_bytes=MAX_BYTES)
        if current is not None and current['uid'] != trusted_uid:
            raise BackupError('permission-denied', '排程備份的設定檔權限不正確，無法儲存；請通知工程人員處理後再試。',
                              file=FILE)
        write_trusted_file(cfd, FILE, pretty(record).encode('utf-8'))
    finally:
        os.close(cfd)
    return record, previous


def audit_line(record, previous):
    """`schedule-set …` for the journal (no secrets: settings only)."""
    uid = login_uid()
    apps = record['apps'] if record['apps'] == 'all' else ','.join(record['apps'])
    keep = 'null' if record['keep_last'] is None else record['keep_last']
    return (f'schedule-set enabled={str(record["enabled"]).lower()} days={",".join(record["days"])} '
            f'time={record["time"]} apps={apps} include_images={str(record["include_images"]).lower()} '
            f'keep_last={keep} previous_enabled={str(bool(previous.get("enabled"))).lower()} '
            f'loginuid={"-" if uid is None else uid}')


def settings_view(settings, problem, saved, *, defaults_shown=False):
    """`schedule` of `schedule-get`/`schedule-set`: the settings, `saved`, the problem (or null) and `defaults` (the
    fields are the defaults, not a saved file's: nothing was saved, or the saved file cannot be used)."""
    view = {key: settings[key] for key in (*FIELDS, 'updated', 'armed_at')}
    view['days'] = list(view['days'])
    if isinstance(view['apps'], list):
        view['apps'] = list(view['apps'])
    return {**view, 'saved': bool(saved), 'problem': problem, 'defaults': bool(defaults_shown)}


def run_apps(settings, catalog_ids):
    """App ids a run includes: every app of the catalog for "all", else the saved list (apps missing from the catalog
    are skipped by the job, which is then partial)."""
    return list(catalog_ids) if settings['apps'] == 'all' else list(settings['apps'])


def job_params(settings, app_ids, encrypt, *, slot, trigger):
    """Params of a scheduled backup job: a manual backup's, plus `schedule` {slot, trigger, keep_last}."""
    return {'apps': list(app_ids), 'include_images': bool(settings['include_images']), 'note': NOTE,
            'encrypt': bool(encrypt),
            'schedule': {'slot': None if slot is None else util.iso_utc(slot), 'trigger': trigger,
                         'keep_last': settings['keep_last']}}


def request_id(slot):
    return REQUEST_PREFIX + util.compact_utc(slot)


# ---------------------------------------------------------------- clock and zone

@dataclass(frozen=True)
class Env:
    """What a tick knows about time: `now` (UTC, aware), the device's zone and its name, seconds since PID 1 started
    (`uptime`)."""
    now: datetime.datetime
    zone: datetime.tzinfo
    zone_name: str
    uptime: float


def _zone_name(path='/etc/localtime'):
    try:
        target = os.readlink(path)
    except OSError:
        target = ''
    if '/zoneinfo/' in target:
        name = target.split('/zoneinfo/', 1)[1]
        if ZONE_NAME_RE.fullmatch(name) and len(name) <= 64:
            return name
    try:
        name = util.read_file_limited('/etc/timezone', 256).decode('utf-8').strip()
    except (OSError, ValueError, UnicodeDecodeError):
        name = ''
    return name if ZONE_NAME_RE.fullmatch(name) and len(name) <= 64 else 'localtime'


def local_zone():
    """The device's zone from /etc/localtime (what the C library uses once `TZ` is unset) and its name."""
    os.environ.pop('TZ', None)
    time.tzset()
    name = _zone_name()
    try:
        with open('/etc/localtime', 'rb') as handle:
            return zoneinfo.ZoneInfo.from_file(handle, key=name), name
    except (OSError, ValueError):  # no /etc/localtime: the C library uses UTC too
        return UTC, 'UTC'


def uptime(stat_path='/proc/1/stat', boottime=None):
    """Seconds since PID 1 started: the device's uptime, or the container's since it (re)started. CLOCK_BOOTTIME
    alone is the host's uptime inside a container without a time namespace, so a restarted container would never
    wait its 10 minutes; PID 1's start (field 22 of /proc/1/stat, clock ticks since boot) is subtracted. A stat that
    cannot be read or compared gives CLOCK_BOOTTIME (monotonic time without it)."""
    if boottime is None:
        try:
            boottime = time.clock_gettime(time.CLOCK_BOOTTIME)
        except (AttributeError, OSError):
            return time.monotonic()
    try:
        data = util.read_file_limited(stat_path, 4096)
        fields = data[data.rindex(b')') + 1:].split()  # the command name before it may hold spaces and parentheses
        started = int(fields[19]) / os.sysconf('SC_CLK_TCK')
    except (OSError, ValueError, IndexError):
        return boottime
    return boottime - started if 0 <= started <= boottime else boottime


def system_env():
    zone, name = local_zone()
    return Env(now=util.utc_now(), zone=zone, zone_name=name, uptime=uptime())


def offset_text(zone, instant):
    delta = instant.astimezone(zone).utcoffset() or datetime.timedelta(0)
    minutes = int(delta.total_seconds() // 60)
    sign = '-' if minutes < 0 else '+'
    minutes = abs(minutes)
    return f'{sign}{minutes // 60:02d}:{minutes % 60:02d}'


def timezone_view(env):
    return {'name': env.zone_name, 'utc_offset': offset_text(env.zone, env.now)}


def _when(instant, zone):
    """Device-local `YYYY-MM-DD HH:MM` for zh-TW messages."""
    return instant.astimezone(zone).strftime('%Y-%m-%d %H:%M')


def instant_view(instant, zone):
    """{at (UTC), local (device time, YYYY-MM-DDTHH:MM), utc_offset} of a slot."""
    return {'at': util.iso_utc(instant), 'local': local_text(instant, zone), 'utc_offset': offset_text(zone, instant)}


def parse_time(text):
    if text is None:
        return None
    try:
        return util.parse_iso_utc(text)
    except ValueError:
        return None


def local_text(value, zone):
    """Device time `YYYY-MM-DDTHH:MM` of an instant (or its ISO text) in `zone`, for the page: it shows the schedule's
    times as the device keeps them, whatever the browser's zone. None without an instant or a zone."""
    instant = value if isinstance(value, datetime.datetime) else parse_time(value) if isinstance(value, str) else None
    if instant is None or zone is None:
        return None
    return instant.astimezone(zone).strftime('%Y-%m-%dT%H:%M')


# ---------------------------------------------------------------- slots

def _local(instant, zone):
    return instant.astimezone(zone).replace(tzinfo=None)


def slot_instant(day, hhmm, zone):
    """The UTC instant of `hhmm` on local date `day`: its first occurrence; a time a DST change skips (it does not
    exist) is the moment the clock jumps past it."""
    wall = datetime.datetime(day.year, day.month, day.day, int(hhmm[:2]), int(hhmm[3:]))
    first = wall.replace(tzinfo=zone).astimezone(UTC)
    if _local(first, zone) == wall:
        return first
    other = wall.replace(tzinfo=zone, fold=1).astimezone(UTC)
    low, high = sorted((int(first.timestamp()), int(other.timestamp())))
    # The local clock shows less than `wall` at `low` and more at `high`: the jump lies between.
    while high - low > 1:
        middle = (low + high) // 2
        if _local(datetime.datetime.fromtimestamp(middle, UTC), zone) >= wall:
            high = middle
        else:
            low = middle
    return datetime.datetime.fromtimestamp(high, UTC)


def slots_between(settings, zone, start, end):
    """Slot instants in (start, end], ascending; at most LOOKBACK_DAYS of local dates are looked at."""
    if end <= start:
        return []
    first_day = _local(start, zone).date() - datetime.timedelta(days=1)
    last_day = _local(end, zone).date() + datetime.timedelta(days=1)
    first_day = max(first_day, last_day - datetime.timedelta(days=LOOKBACK_DAYS))
    found = set()
    day = first_day
    while day <= last_day:
        if DAYS[day.weekday()] in settings['days']:
            instant = slot_instant(day, settings['time'], zone)
            if start < instant <= end:
                found.add(instant)
        day += datetime.timedelta(days=1)
    return sorted(found)


def latest_slot(settings, zone, now):
    """The newest slot at or before `now` (a scheduled weekday comes at least once a week), or None."""
    found = slots_between(settings, zone, now - datetime.timedelta(days=8), now)
    return found[-1] if found else None


def next_slots(settings, zone, after, count=3):
    """The next `count` slots strictly after `after`."""
    found = []
    start = after
    for _week in range(8):
        end = start + datetime.timedelta(days=7)
        found.extend(slots_between(settings, zone, start, end))
        if len(found) >= count:
            break
        start = end
    return found[:count]


# ---------------------------------------------------------------- the decision

@dataclass
class Decision:
    """What one tick does (`decide`): `action` idle | settle (wait for 10 minutes of uptime) | start | missed."""
    action: str = 'idle'
    slot: datetime.datetime | None = None
    trigger: str | None = None
    skipped: dict | None = None    # {slot, first, count}: waiting slots the next slot superseded (another job ran)
    missed: dict | None = None     # {slot, first, count}: slots no tick saw in time that will not run
    handled: datetime.datetime | None = None  # the watermark once `skipped`/`missed` are recorded
    clear_pending: bool = False


def _range(slots):
    return {'slot': slots[-1], 'first': slots[0], 'count': len(slots)}


def _armed(settings, state, now):
    """Where the slots start: `armed_at`; while the clock is below it (it went back after the schedule was armed),
    the floor a tick kept for that `armed_at` (`_check_armed`), so the slots after it run instead of waiting until the
    clock passes `armed_at` again."""
    armed = parse_time(settings.get('armed_at'))
    if armed is None or now >= armed:
        return armed
    kept = (state or {}).get('armed_floor') or {}
    floor = parse_time(kept.get('floor')) if kept.get('armed_at') == settings.get('armed_at') else None
    return armed if floor is None else min(armed, floor)


def _handled(state, now):
    """The last handled slot; the one a clock reset put aside (`_check_clock`) counts again once the clock is past it
    (the clock came back: those slots ran)."""
    handled = parse_time(state.get('handled'))
    kept = parse_time(state.get('handled_before_reset'))
    if kept is not None and kept <= now and (handled is None or kept > handled):
        return kept
    return handled


def decide(settings, state, env):
    """The pure tick decision (module docstring). `state` holds `handled`, `pending`, `handled_before_reset` and
    `armed_floor` (ISO texts); nothing is written here."""
    now, zone = env.now, env.zone
    out = Decision()
    pending = parse_time((state.get('pending') or {}).get('slot'))
    if not settings['enabled']:
        out.clear_pending = pending is not None
        return out
    armed = _armed(settings, state, now) or now
    handled = _handled(state, now)
    if pending is not None and (pending < armed or (handled is not None and pending <= handled) or pending > now):
        out.clear_pending, pending = True, None
    latest = latest_slot(settings, zone, now)
    since = armed - datetime.timedelta(seconds=1)  # slots run when >= armed_at ...
    if handled is not None and handled > since:
        since = handled  # ... and after the last handled slot
    if latest is None or latest <= since:
        return out
    slot = latest
    if pending is not None and pending < slot:
        # The next slot arrived while the earlier one still waited for another job.
        superseded = [item for item in slots_between(settings, zone, since, slot) if item < slot and item >= pending]
        if not superseded:
            superseded = [pending]
        out.skipped = _range(superseded)
        out.handled = since = superseded[-1]
        out.clear_pending, pending = True, None
    earlier = [item for item in slots_between(settings, zone, since, slot) if item < slot]
    if pending is not None and pending == slot:
        out.slot = slot
        out.action, out.trigger = ('settle', None) if env.uptime < SETTLE_SECONDS else ('start', 'late')
        return out
    late = (now - slot).total_seconds()
    if late < ON_TIME_SECONDS:
        out.slot = slot
        if env.uptime < SETTLE_SECONDS:
            out.action = 'settle'
            return out
        out.action, out.trigger = 'start', 'on-time'
        if earlier:
            out.missed = _range(earlier)
            out.handled = earlier[-1]
        return out
    following = next_slots(settings, zone, now, 1)
    if following and (following[0] - now).total_seconds() < CATCH_UP_GAP_SECONDS:
        out.action, out.slot = 'missed', slot
        out.missed = _range(earlier + [slot])
        out.handled = slot
        return out
    out.slot = slot
    if env.uptime < SETTLE_SECONDS:
        out.action = 'settle'
        return out
    out.action, out.trigger = 'start', 'catch-up'
    if earlier:
        out.missed = _range(earlier)
        out.handled = earlier[-1]
    return out


# ---------------------------------------------------------------- state

def state_path(paths):
    return Path(paths.data) / STATE_FILE


def tick_path(paths):
    return Path(paths.run) / TICK_FILE


def empty_state():
    return {'schema': SCHEMA, 'registry': {}, 'handled': None, 'pending': None, 'last_run': None, 'events': [],
            'logged': {}, 'handled_before_reset': None, 'armed_floor': None}


def _iso_or_none(value):
    return value if value is None or util.is_iso_utc(value) else False


def _check_registry(registry):
    if not isinstance(registry, dict):
        raise ValueError('registry')
    checked = {}
    for backup_id, entry in registry.items():
        if (not isinstance(backup_id, str) or not BACKUP_ID_RE.fullmatch(backup_id) or not isinstance(entry, dict)
                or not jobs.valid_job_id(entry.get('job')) or entry.get('trigger') not in TRIGGERS
                or _iso_or_none(entry.get('slot')) is False):
            raise ValueError('registry entry')
        checked[backup_id] = {'job': entry['job'], 'slot': entry.get('slot'), 'trigger': entry['trigger']}
    return checked


def _check_last(last):
    if (not isinstance(last, dict) or not jobs.valid_job_id(last.get('job')) or last.get('trigger') not in TRIGGERS
            or _iso_or_none(last.get('slot')) is False or not util.is_iso_utc(last.get('started'))
            or not isinstance(last.get('recorded'), bool)):
        return None
    backup_id = last.get('backup_id')
    return {'slot': last.get('slot'), 'job': last['job'], 'trigger': last['trigger'], 'started': last['started'],
            'recorded': last['recorded'], 'result': last.get('result') if isinstance(last.get('result'), str) else None,
            'finished': last.get('finished') if util.is_iso_utc(last.get('finished')) else None,
            'backup_id': backup_id if isinstance(backup_id, str) and BACKUP_ID_RE.fullmatch(backup_id) else None}


def _check_event(event):
    if (not isinstance(event, dict) or event.get('kind') not in EVENT_KINDS or not util.is_iso_utc(event.get('at'))
            or not isinstance(event.get('message'), str)):
        return None
    count = event.get('count')
    job_id = event.get('job_id')
    return {'at': event['at'], 'kind': event['kind'],
            'slot': event.get('slot') if util.is_iso_utc(event.get('slot')) else None,
            'first': event.get('first') if util.is_iso_utc(event.get('first')) else None,
            'count': count if isinstance(count, int) and not isinstance(count, bool) and count >= 1 else 1,
            'job_id': job_id if jobs.valid_job_id(job_id) else None, 'message': event['message'][:600]}


def _check_state(data):
    """A readable state: the registry strictly (a damaged registry is a problem, never silently dropped: scheduled
    backups would become manual ones for retention); the rest leniently (display and bookkeeping only)."""
    if not isinstance(data, dict) or data.get('schema') != SCHEMA or isinstance(data.get('schema'), bool):
        raise ValueError('schema')
    state = empty_state()
    state['registry'] = _check_registry(data.get('registry', {}))
    handled = data.get('handled')
    state['handled'] = handled if util.is_iso_utc(handled) else None
    kept = data.get('handled_before_reset')
    state['handled_before_reset'] = kept if util.is_iso_utc(kept) else None
    floor = data.get('armed_floor')
    if isinstance(floor, dict) and util.is_iso_utc(floor.get('armed_at')) and util.is_iso_utc(floor.get('floor')):
        state['armed_floor'] = {'armed_at': floor['armed_at'], 'floor': floor['floor']}
    pending = data.get('pending')
    if isinstance(pending, dict) and util.is_iso_utc(pending.get('slot')) and util.is_iso_utc(pending.get('since')):
        state['pending'] = {'slot': pending['slot'], 'since': pending['since'],
                            'job_id': pending.get('job_id') if jobs.valid_job_id(pending.get('job_id')) else None}
    if data.get('last_run') is not None:
        state['last_run'] = _check_last(data['last_run'])
    events = data.get('events')
    if isinstance(events, list):
        state['events'] = [item for item in (_check_event(event) for event in events[:MAX_EVENTS]) if item]
    logged = data.get('logged')
    if isinstance(logged, dict):
        state['logged'] = {key: value for key, value in logged.items()
                           if isinstance(key, str) and isinstance(value, str) and len(key) <= 40}
    return state


def read_state(paths):
    """(state, None), or (None, zh-TW problem) when the file exists but cannot be read; missing is an empty state."""
    try:
        data = util.load_json_file(state_path(paths), max_bytes=MAX_STATE_BYTES)
    except FileNotFoundError:
        return empty_state(), None
    except (OSError, ValueError):
        return None, STATE_PROBLEM
    try:
        return _check_state(data), None
    except ValueError:
        return None, STATE_PROBLEM


def write_state(paths, state):
    util.ensure_dir(paths.data, 0o700)
    util.atomic_write_json(state_path(paths), state, 0o600)


@contextlib.contextmanager
def state_lock(paths):
    """Exclusive flock on `/run/woowtech-backup/schedule.lock` around one read-modify-write of the state file. A leaf
    lock: nothing else is taken while it is held (the tick starts its job outside it)."""
    run = util.ensure_dir(paths.run, 0o700)
    fd = os.open(Path(run) / STATE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def update_state(paths, change):
    """Apply `change(state)` under the state lock and save; refuses (internal-error) when the state cannot be read."""
    with state_lock(paths):
        state, problem = read_state(paths)
        if problem:
            raise BackupError('internal-error', problem)
        result = change(state)
        write_state(paths, state)
    return result


def register_run(paths, backup_id, job_id, slot, trigger):
    """List the backup a scheduled job is about to make (before any app pauses)."""
    if not BACKUP_ID_RE.fullmatch(backup_id) or not jobs.valid_job_id(job_id) or trigger not in TRIGGERS:
        raise BackupError('internal-error', '排程備份紀錄的內容不正確。')

    def change(state):
        state['registry'][backup_id] = {'job': job_id, 'slot': slot if util.is_iso_utc(slot) else None,
                                        'trigger': trigger}
    update_state(paths, change)


def scheduled_ids(paths):
    """(frozenset of the backup ids in the registry, zh-TW problem or None)."""
    state, problem = read_state(paths)
    if problem:
        return frozenset(), problem
    return frozenset(state['registry']), None


# ---------------------------------------------------------------- events and runs

EVENT_TEXT = {
    'waiting': '{when} 的排程備份等待其他作業完成後開始。',
    'missed': '{span}的排程備份沒有執行：設備當時沒有開機，或排程檢查沒有在執行。',
    'skipped': '{span}的排程備份沒有執行：當時有其他作業一直在進行。',
    'no-key': '{when} 的排程備份沒有執行：預設加密備份已開啟，但這台設備還沒有加密金鑰。',
    'no-apps': '{when} 的排程備份沒有執行：沒有可以備份的應用。',
}


def _span(item, zone):
    if item['count'] > 1:
        return f'{_when(item["first"], zone)} 到 {_when(item["slot"], zone)} 共 {item["count"]} 次'
    return f'{_when(item["slot"], zone)} '


def add_event(state, kind, env, *, slot=None, first=None, count=1, job_id=None, message=None):
    if message is None:
        item = {'slot': slot, 'first': first or slot, 'count': count}
        message = EVENT_TEXT[kind].format(when=_when(slot, env.zone) if slot else '', span=_span(item, env.zone))
    event = {'at': util.iso_utc(env.now), 'kind': kind, 'slot': None if slot is None else util.iso_utc(slot),
             'first': None if first is None else util.iso_utc(first), 'count': max(1, int(count)), 'job_id': job_id,
             'message': message[:600]}
    state['events'] = ([event] + list(state.get('events') or []))[:MAX_EVENTS]
    return event


def _run_label(last, zone):
    slot = parse_time(last.get('slot'))
    if slot is not None:
        return f'{_when(slot, zone)} 的排程備份'
    return '立即執行的排程備份'


def _skipped_apps(record):
    result = record.get('result') if isinstance(record.get('result'), dict) else {}
    items = result.get('skipped_apps') if isinstance(result.get('skipped_apps'), list) else []
    return [{'id': str(item.get('id'))[:64], 'name': str(item.get('name') or item.get('id'))[:200],
             'reason': str(item.get('reason') or '')[:300]} for item in items if isinstance(item, dict)][:MAX_APPS]


def outcome(record):
    """'queued'|'running'|'succeeded'|'partial'|'failed'|'interrupted'|'cancelled'|'unknown' of a scheduled job."""
    if record is None:
        return 'unknown'
    state = record.get('state')
    if state in jobs.ACTIVE:
        return state
    if state == 'succeeded':
        result = record.get('result') if isinstance(record.get('result'), dict) else {}
        return 'partial' if result.get('partial') else 'succeeded'
    if state in ('failed', 'interrupted', 'cancelled'):
        return state
    return 'failed' if state == 'rolled-back' else 'unknown'


def _error_text(record):
    error = record.get('error') if isinstance(record, dict) and isinstance(record.get('error'), dict) else {}
    return str(error.get('message') or '原因不明。')[:400]


def _names(items):
    return '、'.join(f'「{item["name"]}」' for item in items[:10]) + ('等' if len(items) > 10 else '')


def settle_last_run(state, job_lookup, job_ended, env, journal):
    """Record the outcome of the last run once its job ended (events, `schedule-result`); idempotent. Ended is what
    `job_ended` says (Services.job_ended, as for the registry): a record that exists but cannot be read is unknown,
    never ended, so nothing is recorded and a later tick looks again (a newer run replaces it without an event); a
    record that is gone settles as `unknown` (a `failed` event: the record no longer exists)."""
    last = state.get('last_run')
    if not last or last.get('recorded'):
        return
    record = job_lookup(last['job'])
    if record is None:
        if not job_ended(last['job']):
            return
        record = job_lookup(last['job'])  # readable again since the first read
    result = outcome(record)
    if result in jobs.ACTIVE:
        return
    slot = parse_time(last.get('slot'))
    label = _run_label(last, env.zone)
    backup_id = None
    if record is not None and isinstance(record.get('result'), dict):
        value = record['result'].get('backup_id')
        backup_id = value if isinstance(value, str) and BACKUP_ID_RE.fullmatch(value) else None
    last.update(recorded=True, result=result, backup_id=backup_id,
                finished=(record or {}).get('finished') if util.is_iso_utc((record or {}).get('finished')) else None)
    where = f'slot={last.get("slot") or "-"} job={last["job"]} trigger={last["trigger"]}'
    if result == 'succeeded':
        journal(f'schedule-result {where} result=succeeded backup={backup_id or "-"}', False)
    elif result == 'partial':
        skipped = _skipped_apps(record)
        add_event(state, 'partial', env, slot=slot, job_id=last['job'],
                  message=f'{label}部分完成：沒有包含{_names(skipped)}。')
        journal(f'schedule-result {where} result=partial backup={backup_id or "-"} '
                f'skipped={",".join(item["id"] for item in skipped) or "-"}', True)
    elif result == 'cancelled':
        add_event(state, 'cancelled', env, slot=slot, job_id=last['job'], message=f'{label}已取消。')
        journal(f'schedule-result {where} result=cancelled', False)
    else:
        error = (record or {}).get('error')
        code = error.get('code') if isinstance(error, dict) else None
        add_event(state, 'failed', env, slot=slot, job_id=last['job'],
                  message=f'{label}失敗：{_error_text(record)}' if record is not None else f'{label}的作業紀錄已不存在。')
        journal(f'schedule-result {where} result={result} code={code or "-"}', True)


def prune_registry(state, job_ended, backup_present):
    """Drop entries whose job ended (`job_ended`: its record is readable and finished, or there is none) and whose
    backup is gone (neither listed nor on disk). The job is read first: a job that publishes and ends between the two
    reads has ended before its backup is looked for, so the backup is found. Anything unknown keeps the entry."""
    for backup_id, entry in list(state['registry'].items()):
        try:
            if not job_ended(entry['job']) or backup_present(backup_id):
                continue
        except Exception:  # noqa: BLE001 - unknown: keep the entry (it decides how retention counts the backup)
            continue
        del state['registry'][backup_id]


def last_run_view(state, job_lookup, zone):
    """`last_run` of status/schedule-get, live from the job record: {slot, local, job_id, trigger, state, result,
    backup_id, started, started_local, finished, finished_local, skipped_apps[], error} (`*_local`: device time)."""
    last = (state or {}).get('last_run')
    if not last:
        return None
    record = job_lookup(last['job'])
    result = outcome(record) if record is not None or not last.get('recorded') else (last.get('result') or 'unknown')
    slot = parse_time(last.get('slot'))
    backup_id = last.get('backup_id')
    if record is not None and isinstance(record.get('result'), dict):
        value = record['result'].get('backup_id')
        backup_id = value if isinstance(value, str) and BACKUP_ID_RE.fullmatch(value) else backup_id
    error = record.get('error') if record is not None and isinstance(record.get('error'), dict) else None
    finished = (record or {}).get('finished') or last.get('finished')
    return {'slot': last.get('slot'), 'local': local_text(slot, zone),
            'job_id': last['job'], 'trigger': last['trigger'], 'state': (record or {}).get('state'), 'result': result,
            'backup_id': backup_id, 'started': last.get('started'),
            'started_local': local_text(last.get('started'), zone), 'finished': finished,
            'finished_local': local_text(finished, zone),
            'skipped_apps': _skipped_apps(record) if record is not None else [],
            'error': {'code': error.get('code'), 'message': error.get('message')} if error else None}


def events_view(state, zone):
    """`events` (schedule-get) / `schedule_events` (jobs): newest first, at most 50; `local`/`first_local` are the
    slots in device time (null without a slot or a zone); `not_run` marks a slot that did not run (未執行)."""
    return [dict(event, local=local_text(event['slot'], zone), first_local=local_text(event['first'], zone),
                 not_run=event['kind'] in NOT_RUN or (event['kind'] == 'failed' and not event['job_id']))
            for event in (state or {}).get('events') or []]


# ---------------------------------------------------------------- journal and timer

def journal(line, warning=False):
    """A schedule line in the system journal (ident woowtech-cockpit-backup, authpriv): notice, warning for failures.
    Never breaks the caller."""
    try:
        import syslog
        syslog.openlog('woowtech-cockpit-backup', 0, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_WARNING if warning else syslog.LOG_NOTICE, line)
    except Exception:  # noqa: BLE001 - logging must never break the command
        pass


def timer_state(monotonic=time.monotonic):
    """{enabled, active, active_age} of woowtech-cockpit-backup-schedule.timer (`systemctl show`, read-only, fixed
    argv); None values when systemd cannot be asked. `active_age`: seconds since the timer last became active
    (ActiveEnterTimestampMonotonic, CLOCK_MONOTONIC in microseconds like `time.monotonic()`), None while it is not
    active or when systemd does not say."""
    unknown = {'enabled': None, 'active': None, 'active_age': None}
    argv = ['/usr/bin/systemctl', 'show', '--property=UnitFileState', '--property=ActiveState',
            '--property=ActiveEnterTimestampMonotonic', '--', TIMER]
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, env=dict(jobs.SAFE_ENV),
                                timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return unknown
    if result.returncode != 0:
        return unknown
    values = dict(line.split('=', 1) for line in result.stdout.decode('utf-8', 'replace').splitlines() if '=' in line)
    active = values.get('ActiveState') == 'active'
    entered = values.get('ActiveEnterTimestampMonotonic', '').strip()
    age = None
    if active and entered.isdigit() and int(entered) > 0:
        age = max(0, int(monotonic() - int(entered) / 1e6))
    return {'enabled': values.get('UnitFileState') in ('enabled', 'enabled-runtime'), 'active': active,
            'active_age': age}


# ---------------------------------------------------------------- the tick

@contextlib.contextmanager
def tick_lock(paths):
    """Non-blocking flock on `/run/woowtech-backup/schedule-tick.lock`: yields False when another tick holds it."""
    run = util.ensure_dir(paths.run, 0o700)
    fd = os.open(Path(run) / TICK_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        yield True
    finally:
        os.close(fd)


def touch_tick(paths, now=None):
    """Mark that the timer ran (the page tells from its age whether the schedule checks still run)."""
    run = util.ensure_dir(paths.run, 0o700)
    fd = os.open(Path(run) / TICK_FILE, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        stamp = time.time() if now is None else now.timestamp()
        os.utime(fd, (stamp, stamp))
    finally:
        os.close(fd)


def last_tick_age(paths, now):
    try:
        st = os.lstat(tick_path(paths))
    except OSError:
        return None
    return max(0, int(now.timestamp() - st.st_mtime))


def _report_state_problem(paths, journal):
    """The unreadable state file is logged once per boot (a marker on the tmpfs run directory)."""
    marker = Path(paths.run) / STATE_NOTE
    if os.path.lexists(marker):
        return
    with contextlib.suppress(OSError):
        os.close(os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
    journal('schedule-skip reason=state-unreadable', True)


def _check_clock(state, settings, env, journal):
    """A handled slot more than a day ahead means the clock went back: start over from now (logged once). The handled
    slot is put aside (`handled_before_reset`, the latest of several resets) and counts as handled again once the clock
    is past it: when the clock comes back (a lost RTC that NTP fixes) the slots that ran are not reported missed."""
    handled = parse_time(state.get('handled'))
    kept = parse_time(state.get('handled_before_reset'))
    if kept is not None and kept <= env.now:
        if handled is None or handled < kept:
            handled = kept
            state['handled'] = util.iso_utc(kept)
        state['handled_before_reset'] = kept = None
    if handled is None or (handled - env.now).total_seconds() <= CLOCK_BACK_SECONDS:
        return
    latest = latest_slot(settings, env.zone, env.now) if settings.get('days') else None
    state['handled'] = None if latest is None else util.iso_utc(latest)
    state['handled_before_reset'] = util.iso_utc(handled if kept is None else max(handled, kept))
    state['pending'] = None
    journal(f'schedule-clock reset handled={util.iso_utc(handled)} now={util.iso_utc(env.now)}', True)


def _check_armed(state, settings, env):
    """`armed_at` above the clock (it went back after the schedule was armed): the first tick that sees it keeps its
    time as the floor of that `armed_at`, lowered when the clock goes back further and kept as the clock moves on, so
    the slots after the floor run (`_armed`). Dropped once the clock is past `armed_at`, and unused for another
    `armed_at` (saved again)."""
    armed_at = settings.get('armed_at') if settings.get('enabled') else None
    armed = parse_time(armed_at)
    if armed is None or env.now >= armed:
        state['armed_floor'] = None
        return
    kept = state.get('armed_floor') or {}
    floor = parse_time(kept.get('floor')) if kept.get('armed_at') == armed_at else None
    if floor is None or env.now < floor:
        state['armed_floor'] = {'armed_at': armed_at, 'floor': util.iso_utc(env.now)}


def run_tick(host):
    """One tick: `host` is the helper's Services (paths, env, schedule_settings, catalog, encrypt_by_default, keys,
    start, job_record, job_ended, recover, backup_present, journal). Returns {decision, slot?, job_id?} (stdout of the
    unit is discarded; a manual run of `schedule-tick` prints it)."""
    paths = host.paths
    env = host.env()
    touch_tick(paths, env.now)
    with tick_lock(paths) as held:
        if not held:
            return {'decision': 'tick-running'}
        return _tick(host, env)


def _tick(host, env):
    paths = host.paths
    journal = host.journal
    settings, problem, _saved = host.schedule_settings()
    state, state_problem = read_state(paths)
    if state_problem:
        _report_state_problem(paths, journal)
        return {'decision': 'state-problem'}
    last = state.get('last_run')
    if last and not last.get('recorded'):
        record = host.job_record(last['job'])
        if record is not None and record.get('state') in jobs.ACTIVE:
            host.recover()  # settles a scheduled job that died (it never judges a job that still runs)
    lines = []

    def log(line, warning=False):
        lines.append((line, warning))

    with state_lock(paths):
        state, state_problem = read_state(paths)
        if state_problem:
            return {'decision': 'state-problem'}
        before = json.dumps(state, sort_keys=True)
        settle_last_run(state, host.job_record, host.job_ended, env, log)
        prune_registry(state, host.job_ended, host.backup_present)
        _check_clock(state, settings, env, log)
        if problem:
            if state['logged'].get('settings') != problem:
                state['logged']['settings'] = problem
                add_event(state, 'settings-problem', env, message=problem)
                log('schedule-skip reason=settings-problem', True)
            state['pending'] = None
            if json.dumps(state, sort_keys=True) != before:
                write_state(paths, state)
            _emit(journal, lines)
            return {'decision': 'settings-problem'}
        state['logged'].pop('settings', None)
        _check_armed(state, settings, env)
        decision = decide(settings, state, env)
        if decision.clear_pending:
            state['pending'] = None
        if decision.skipped:
            item = decision.skipped
            add_event(state, 'skipped', env, slot=item['slot'], first=item['first'], count=item['count'])
            log(f'schedule-skip slot={util.iso_utc(item["slot"])} reason=busy count={item["count"]}')
        if decision.missed:
            item = decision.missed
            add_event(state, 'missed', env, slot=item['slot'], first=item['first'], count=item['count'])
            log(f'schedule-missed slot={util.iso_utc(item["slot"])} first={util.iso_utc(item["first"])} '
                f'count={item["count"]}')
        if decision.handled is not None:
            state['handled'] = util.iso_utc(decision.handled)
        if json.dumps(state, sort_keys=True) != before:  # a quiet tick writes nothing
            write_state(paths, state)
    _emit(journal, lines)
    if decision.action != 'start':
        summary = {'decision': decision.action}
        if decision.slot is not None:
            summary['slot'] = util.iso_utc(decision.slot)
        return summary
    return _start(host, env, settings, decision)


def _emit(journal, lines):
    for line, warning in lines:
        journal(line, warning)
    lines.clear()


def _start(host, env, settings, decision):
    """Start the run of `decision.slot` (outside the state lock), then record what happened."""
    paths, slot, trigger = host.paths, decision.slot, decision.trigger
    catalog_apps = host.catalog()
    app_ids = run_apps(settings, list(catalog_apps.keys()))
    encrypt = host.encrypt_by_default()
    kind, started, error = None, None, None
    if not [app_id for app_id in app_ids if catalog_apps.get(app_id) is not None]:
        kind = 'no-apps'
    elif encrypt and host.keys.device_key() is None:
        kind = 'no-key'
    else:
        try:
            started = host.start('backup', job_params(settings, app_ids, encrypt, slot=slot, trigger=trigger),
                                 request_id(slot))
        except BackupError as exc:
            error = exc
            kind = 'busy' if exc.code == 'busy' else 'start-failed'
    lines = []

    def log(line, warning=False):
        lines.append((line, warning))

    stamp = util.iso_utc(slot)

    def change(state):
        pending = state.get('pending') or {}
        if started is not None:
            state['handled'] = stamp
            state['pending'] = None
            last = state.get('last_run')
            if not last or last.get('job') != started['job_id']:
                settle_last_run(state, host.job_record, host.job_ended, env, log)
                state['last_run'] = {'slot': stamp, 'job': started['job_id'], 'trigger': trigger,
                                     'started': util.iso_utc(env.now), 'recorded': False, 'result': None,
                                     'finished': None, 'backup_id': None}
                log(f'schedule-run slot={stamp} job={started["job_id"]} trigger={trigger} '
                    f'apps={",".join(app_ids)} encrypted={str(bool(encrypt)).lower()}')
        elif kind == 'busy':
            if pending.get('slot') != stamp:
                busy_job = error.details.get('job_id') if isinstance(error.details, dict) else None
                state['pending'] = {'slot': stamp, 'since': util.iso_utc(env.now),
                                    'job_id': busy_job if jobs.valid_job_id(busy_job) else None}
                add_event(state, 'waiting', env, slot=slot, job_id=state['pending']['job_id'])
                log(f'schedule-wait slot={stamp} busy_job={state["pending"]["job_id"] or "-"}')
        elif kind in ('no-apps', 'no-key'):
            state['handled'] = stamp
            state['pending'] = None
            add_event(state, kind, env, slot=slot)
            log(f'schedule-skip slot={stamp} reason={kind}', True)
        else:  # the job could not be launched: no automatic retry
            state['handled'] = stamp
            state['pending'] = None
            add_event(state, 'failed', env, slot=slot,
                      message=f'{_when(slot, env.zone)} 的排程備份沒有開始：{error.message}')
            log(f'schedule-result slot={stamp} job=- trigger={trigger} result=failed code={error.code}', True)

    update_state(paths, change)
    _emit(host.journal, lines)
    summary = {'decision': 'started' if started else kind, 'slot': stamp, 'trigger': trigger}
    if started:
        summary.update(job_id=started['job_id'], deduplicated=bool(started.get('deduplicated')))
    return summary


def record_run_now(paths, started, settings, app_ids, encrypt, job_lookup, job_ended, env, journal):
    """Remember a `schedule-run-now` job as the last run (its outcome is recorded like a slot's)."""
    lines = []

    def log(line, warning=False):
        lines.append((line, warning))

    def change(state):
        last = state.get('last_run')
        if last and last.get('job') == started['job_id']:
            return
        settle_last_run(state, job_lookup, job_ended, env, log)
        state['last_run'] = {'slot': None, 'job': started['job_id'], 'trigger': 'run-now',
                             'started': util.iso_utc(env.now), 'recorded': False, 'result': None, 'finished': None,
                             'backup_id': None}
        log(f'schedule-run slot=- job={started["job_id"]} trigger=run-now apps={",".join(app_ids)} '
            f'encrypted={str(bool(encrypt)).lower()}')

    update_state(paths, change)
    _emit(journal, lines)


# ---------------------------------------------------------------- status

def timer_inactive(timer, env):
    """The schedule checks do not run: systemd says the timer is not active, or for 15 minutes nothing showed that
    they run: no tick touched the tick file and the timer has been active that long (a timer whose service fails
    before the engine runs, e.g. a helper that refuses its library, is active and never ticks). A timer that just
    became active (the installer's `enable --now`, a restart) is given its first ticks, whatever the device's uptime
    or the age of a tick file from before it stopped. When systemd cannot say since when it is active and there was
    no tick, PID 1's age stands in (`env.uptime`)."""
    if timer.get('active') is False:
        return True
    ages = [value for value in (timer.get('last_tick_age'), timer.get('active_age')) if value is not None]
    return min(ages or [env.uptime]) > TICK_STALE_SECONDS


def _overdue(settings, state, env):
    """The newest slot that should have started 30 minutes ago is neither handled nor waiting (the slots start where
    the tick's do: `_armed`, `_handled`)."""
    armed = _armed(settings, state, env.now)
    if armed is None:
        return None
    latest = latest_slot(settings, env.zone, env.now - datetime.timedelta(seconds=OVERDUE_SECONDS))
    if latest is None or latest < armed:
        return None
    handled = _handled(state, env.now)
    pending = parse_time((state.get('pending') or {}).get('slot'))
    if (handled is not None and latest <= handled) or (pending is not None and pending >= latest):
        return None
    return latest


def attention(settings, problem, state, state_problem, env, timer, last):
    """The one thing the page should say about the schedule, or None: {code, message, slot?, job_id?}."""
    if problem or state_problem:
        return {'code': 'settings-problem', 'message': problem or state_problem}
    if not settings['enabled']:
        return None
    if timer_inactive(timer, env):
        return {'code': 'timer-inactive', 'message': TIMER_MESSAGE}
    overdue = _overdue(settings, state, env)
    if overdue is not None:
        return {'code': 'overdue', 'message': f'排程備份已逾期：{_when(overdue, env.zone)} 的排程備份還沒有開始。',
                'slot': util.iso_utc(overdue)}
    event = next((item for item in state.get('events') or []
                  if item['kind'] in NOT_RUN or (item['kind'] == 'failed' and not item['job_id'])), None)
    run_key = None
    if last is not None:
        run_key = last.get('slot') or last.get('started')
    event_key = (event or {}).get('slot') or (event or {}).get('at')
    if event is not None and (run_key is None or event_key > run_key):
        if event['kind'] == 'failed':  # the job could not be launched
            return {'code': 'failed', 'message': f'上次排程備份失敗：{event["message"]}', 'slot': event.get('slot'),
                    'job_id': None}
        return {'code': 'missed' if event['kind'] == 'missed' else 'skipped', 'message': event['message'],
                'slot': event.get('slot'), 'reason': event['kind'] if event['kind'] != 'skipped' else 'busy'}
    if last is None:
        return None
    if last['result'] in ('failed', 'interrupted', 'unknown'):
        text = last['error']['message'] if last.get('error') else '作業紀錄已不存在。'
        return {'code': 'failed', 'message': f'上次排程備份失敗：{text}', 'slot': last.get('slot'),
                'job_id': last['job_id']}
    if last['result'] == 'partial':
        names = _names(last['skipped_apps'])
        return {'code': 'partial', 'message': f'部分完成：上次排程備份沒有包含{names}。請查看作業結果了解原因。',
                'slot': last.get('slot'), 'job_id': last['job_id']}
    return None


def summary(settings, problem, saved, state, state_problem, env, timer, job_lookup):
    """`status.schedule`: on/off, the saved choices, the next run, the last run, the slot waiting for another job, the
    attention item, the zone and the timer."""
    state = state or empty_state()
    last = last_run_view(state, job_lookup, env.zone)
    enabled = bool(settings['enabled']) and not problem and not state_problem
    following = next_slots(settings, env.zone, env.now, 1) if enabled else []
    pending = state.get('pending')
    waiting = None
    if enabled and pending:
        slot = parse_time(pending['slot'])
        waiting = {'slot': pending['slot'], 'local': instant_view(slot, env.zone)['local'], 'since': pending['since'],
                   'job_id': pending.get('job_id')}
    return {'enabled': enabled, 'saved': bool(saved), 'problem': problem or state_problem,
            'days': list(settings['days']), 'time': settings['time'],
            'apps': settings['apps'] if settings['apps'] == 'all' else list(settings['apps']),
            'include_images': settings['include_images'], 'keep_last': settings['keep_last'],
            'next_run': instant_view(following[0], env.zone) if following else None, 'last_run': last,
            'waiting': waiting,
            'attention': attention(settings, problem, state, state_problem, env, timer, last),
            'timezone': timezone_view(env), 'timer': dict(timer)}
