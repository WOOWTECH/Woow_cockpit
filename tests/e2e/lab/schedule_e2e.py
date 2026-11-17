#!/usr/bin/env python3
"""Lab scenarios of 排程備份 (scheduled backups, 2026.11.17.1) on the lab devices (integrator).

Every engine call is made the way the Cockpit page makes it (cli_e2e.py: the installed helper as root, request JSON on
stdin, one JSON object back; downloads and uploads through the device's real cockpit-bridge). The trigger is the real
one: systemd starts woowtech-cockpit-backup-schedule.service from its timer at every 5-minute boundary, or from
`systemctl start` for a fast tick. A fast tick makes a slot due without waiting for 03:00: root writes
/etc/woowtech-cockpit/backup/schedule.json (0644, exactly the documented keys) with `time` the latest 5-minute boundary
in device time (less than 15 minutes ago) and `armed_at` one minute before it; wherever no slot has to be due at once
the page's path (schedule-set) saves the settings, with a time whose slots lie before `armed_at`. Device commands run
directly (`labpodman exec <device> <argv>`, Python programs on stdin), never through a shell.

    python3 -I tests/e2e/lab/schedule_e2e.py install    # deploy-src a and b: units root 0644 equal to the source, the
                                                        # timer enabled and active (systemctl show/cat), verify
    python3 -I tests/e2e/lab/schedule_e2e.py timer      # dev-a: schedule-set for the next boundary; the timer runs it
    python3 -I tests/e2e/lab/schedule_e2e.py fast       # dev-a: due slot, two starts and a held tick lock -> one job;
                                                        # 排程 in list, note 排程備份, journal lines once per slot
    python3 -I tests/e2e/lab/schedule_e2e.py busy       # dev-a: a verify job runs -> the slot waits; then it runs late
    python3 -I tests/e2e/lab/schedule_e2e.py timezone   # dev-a: /etc/localtime relinked -> the next tick uses that zone
    python3 -I tests/e2e/lab/schedule_e2e.py run-now    # dev-a: schedule-run-now (not saved, bad file, dedup, busy)
    python3 -I tests/e2e/lab/schedule_e2e.py retention  # dev-a: 3 scheduled runs keep 2 + manual backups under a manual
                                                        # keep-last policy: only the oldest scheduled one is deleted
    python3 -I tests/e2e/lab/schedule_e2e.py partial    # dev-a: woowbk-demo stopped; an app gone from the catalog
    python3 -I tests/e2e/lab/schedule_e2e.py kit-gate   # dev-b: no key / kit not saved -> refused; saved -> on
    python3 -I tests/e2e/lab/schedule_e2e.py compat     # (after kit-gate) dev-b rolled back to c393dfb with the new files
                                                        # and job records; dev-a's scheduled backup uploaded, inspected,
                                                        # restored; dev-b back on the working tree
    python3 -I tests/e2e/lab/schedule_e2e.py noise      # dev-a: PID 1 lines per tick with LogLevelMax=notice + controls
    python3 -I tests/e2e/lab/schedule_e2e.py reboot     # dev-a: missed slots, overdue, timer stopped, the 10-minute wait
                                                        # (time namespace), restart -> catch-up (uptime caveat: README)
    python3 -I tests/e2e/lab/schedule_e2e.py cleanup    # test backups, schedule files, dev-b's lab key, demo entry
    python3 -I tests/e2e/lab/schedule_e2e.py all

Prerequisites: both devices running (`labpodman start`), woowbk-demo running on both, dev-a's device key with its kit
confirmed and the throwaway kit ~/.woowbk-lab/secrets/dev-a-kit.txt (cli_e2e.py s1), dev-b without a device key
(`kit-gate` creates a lab key there and `cleanup` removes it), host MemAvailable >= 1200 MB; `install` deploys the
working tree (deploy-src.sh) and must run first. Evidence: ~/.woowbk-lab/evidence/schedule/<time>-<scenario>/
(driver.log, result.json, job records, journal lines, systemctl output); backups and lab changes to undo are recorded
in evidence/schedule/state.json for `cleanup`. Keys never leave the devices except the dev-a kit secret, which only
travels in the stdin field `key`.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import zoneinfo
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cli_e2e as e2e  # noqa: E402  (shared helper/bridge/evidence code of the integration runner)
from cli_e2e import (DOWNLOADS, LAB, LP, SECRET_RE, Failed, bridge_download, dev_name, helper, kit_secret,  # noqa: E402
                     ok, redact, request_id, upload_file, wait_job)

e2e.EVIDENCE = LAB / 'evidence' / 'schedule'
EVIDENCE = e2e.EVIDENCE
STATE = EVIDENCE / 'state.json'
LAB_DIR = Path(__file__).resolve().parent
REPO = LAB_DIR.parents[2]
HELPER = '/usr/local/libexec/woowtech-cockpit-backup'
OWNER_WRAPPER = '/usr/local/bin/woowbk-owner'
SRC = '/opt/woow-cockpit-src'
TIMER = 'woowtech-cockpit-backup-schedule.timer'
SERVICE = 'woowtech-cockpit-backup-schedule.service'
UNIT_DIR = '/usr/local/lib/systemd/system'
WANTS = f'/etc/systemd/system/timers.target.wants/{TIMER}'
CONFIG = '/etc/woowtech-cockpit/backup'
CATALOG = f'{CONFIG}/apps'
KEYS = f'{CONFIG}/keys'
SCHEDULE_FILE = f'{CONFIG}/schedule.json'
SCHEDULE_TMP = f'{CONFIG}/.schedule.json.lab'
DATA = '/var/lib/woowtech-backup'
STATE_FILE = f'{DATA}/schedule-state.json'
RUN = '/run/woowtech-backup'
TICK_FILE = f'{RUN}/schedule-tick'
TICK_LOCK = f'{RUN}/schedule-tick.lock'
PARKED = '/root/woowbk-schedule-lab'  # a catalog entry parked by `partial` (root 0700, inside the device)
APP_URL = 'http://127.0.0.1:18090'
DEMO, DIRS = 'woowbk-demo', 'woowbk-dirs'
DEMO_UNITS = ('woowbk-demo-db.service', 'woowbk-demo-app.service')
DAYS = ('mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun')
FILE_KEYS = ('schema', 'enabled', 'days', 'time', 'apps', 'include_images', 'keep_last', 'updated', 'armed_at')
NOTE = '排程備份'
OLD = 'c393dfb'  # origin/main before this feature: 2026.11.15.2, the engine the lab devices ran
COMPARE = ('notes', 'files', 'digest', 'title', 'signatures_valid')
UTC = datetime.timezone.utc
JOB_ID_RE = re.compile(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
BACKUP_ID_RE = re.compile(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
TIMER_ON = {'load_state': 'loaded', 'unit_file_state': 'enabled', 'active_state': 'active', 'enabled': True,
            'active': True}
MIN_AVAILABLE_MB = 1200
BOUNDARY_MARGIN = 25  # seconds after a boundary: the timer's own tick there (AccuracySec=15s) has run


class Evidence(e2e.Evidence):
    """cli_e2e's evidence directory, under evidence/schedule/."""


# ------------------------------------------------------------------ state shared by the scenarios

def load_state():
    try:
        return json.loads(STATE.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


def save_state(**fields):
    state = load_state()
    state.update(fields)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(redact(state), ensure_ascii=False, indent=1) + '\n', encoding='utf-8')


def remember(dev, backup_id):
    """Backups this driver made (deleted by the scenario that made them, else by `cleanup`)."""
    if backup_id:
        created = load_state().get('created', [])
        if [dev, backup_id] not in created:
            created.append([dev, backup_id])
        save_state(created=created)


def undo(key, value=None):
    """A lab change `cleanup` must put back if a scenario stops half-way (value None: done)."""
    pending = load_state().get('undo', {})
    if value is None:
        pending.pop(key, None)
    else:
        pending[key] = value
    save_state(undo=pending)


def memory_ok():
    with open('/proc/meminfo', encoding='ascii') as handle:
        available = next(int(line.split()[1]) // 1024 for line in handle if line.startswith('MemAvailable:'))
    if available < MIN_AVAILABLE_MB:
        raise Failed(f'host MemAvailable {available} MB < {MIN_AVAILABLE_MB} MB')
    return available


# ------------------------------------------------------------------ device access (argv only, no shell)

def run(dev, *argv, input=b'', timeout=600, check=True, env=None, workdir=None):
    cmd = [LP, 'exec', '-i']
    for name, value in (env or {}).items():
        cmd += ['--env', f'{name}={value}']
    if workdir:
        cmd += ['--workdir', workdir]
    cmd += [dev_name(dev), *map(str, argv)]
    proc = subprocess.run(cmd, input=input, capture_output=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise Failed(f'dev-{dev}: `{" ".join(map(str, argv))[:160]}` rc={proc.returncode}: '
                     f'{redact(proc.stderr.decode("utf-8", "replace")[-400:])}')
    return proc


def out(dev, *argv, **kwargs):
    return run(dev, *argv, **kwargs).stdout.decode('utf-8', 'replace')


def as_owner(dev, *argv, **kwargs):
    return run(dev, OWNER_WRAPPER, *argv, **kwargs)


def py(dev, code, *args, timeout=600):
    """A Python program (code on stdin, `python3 -I -`) as root inside a device."""
    return run(dev, 'python3', '-I', '-', *args, input=code.encode('utf-8'), timeout=timeout)


def exists(dev, path):
    return run(dev, 'test', '-e', path, check=False).returncode == 0


def file_digest(dev, path):
    proc = run(dev, 'sha256sum', '--', path, check=False)
    return proc.stdout.decode().split()[0] if proc.returncode == 0 else None


def show(dev, unit, *props):
    argv = ['systemctl', 'show', '--timestamp=unix', *[f'--property={prop}' for prop in props], '--', unit]
    return dict(line.split('=', 1) for line in out(dev, *argv).splitlines() if '=' in line)


def unix_ts(value):
    """`@1794874196` (systemctl --timestamp=unix) as float seconds; None when unset."""
    value = (value or '').strip()
    try:
        return float(value[1:]) if value.startswith('@') else None
    except ValueError:
        return None


def timer_state(dev):
    """The timer as manage.py and the engine read it (systemctl show; read-only)."""
    values = show(dev, TIMER, 'LoadState', 'UnitFileState', 'ActiveState')
    return {'load_state': values.get('LoadState', ''), 'unit_file_state': values.get('UnitFileState', ''),
            'active_state': values.get('ActiveState', ''),
            'enabled': values.get('UnitFileState') in ('enabled', 'enabled-runtime'),
            'active': values.get('ActiveState') == 'active'}


def unit_layout(dev):
    """Unit files, the timers.target.wants link and the unit directory as the file system has them."""
    found = {}
    for name in (TIMER, SERVICE):
        proc = run(dev, 'stat', '-c', '%U:%G %a %s', f'{UNIT_DIR}/{name}', check=False)
        found[name] = proc.stdout.decode().strip() if proc.returncode == 0 else None
    link = run(dev, 'readlink', WANTS, check=False)
    found['wants'] = link.stdout.decode().strip() if link.returncode == 0 else None
    found['unit_dir'] = exists(dev, UNIT_DIR)
    return found


def tick_service(dev):
    """One tick as the timer starts it: `systemctl start` of the oneshot service returns once the tick finished."""
    run(dev, 'systemctl', 'start', SERVICE, timeout=960)
    return show(dev, SERVICE, 'InvocationID', 'Result', 'ExecMainStatus', 'ExecMainStartTimestamp', 'ActiveState')


def tick_by_hand(dev, ev):
    """The helper's tick run by hand: it prints its decision (the unit discards stdout)."""
    proc = run(dev, HELPER, 'schedule-tick', check=False, timeout=960)
    lines = [line for line in proc.stdout.decode('utf-8', 'replace').splitlines() if line.strip()]
    reply = json.loads(lines[-1]) if lines else {}
    ev.log(f'dev-{dev}: schedule-tick by hand (rc={proc.returncode}) -> {reply}')
    return reply


def job_record(dev, job_id):
    """The stored job record (job records never hold key material; `leaks` scenarios check it)."""
    if not JOB_ID_RE.fullmatch(job_id or ''):
        raise Failed(f'not a job id: {job_id!r}')
    return json.loads(out(dev, 'cat', f'{DATA}/jobs/{job_id}.json'))


def schedule_state(dev):
    proc = run(dev, 'cat', STATE_FILE, check=False)
    return json.loads(proc.stdout) if proc.returncode == 0 else None


def journal(dev, since, *match):
    argv = ['journalctl', '--no-pager', '--output=json', f'--since=@{int(since) - 1}', *match]
    return [json.loads(line) for line in out(dev, *argv, timeout=120).splitlines() if line.strip()]


def message(entry):
    value = entry.get('MESSAGE')
    if isinstance(value, list):
        value = bytes(value).decode('utf-8', 'replace')
    return value or ''


def engine_lines(dev, since, *prefixes):
    """(text, priority) of the helper's own syslog lines (ident woowtech-cockpit-backup) since `since`."""
    found = []
    for entry in journal(dev, since, '--identifier=woowtech-cockpit-backup'):
        text = message(entry)
        if not prefixes or text.startswith(prefixes):
            found.append((text, int(entry.get('PRIORITY', 6))))
    return found


def healthy(dev, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        proc = run(dev, 'curl', '-sS', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '5', f'{APP_URL}/healthz',
                   check=False, timeout=30)
        if proc.stdout.decode().strip() == '200':
            return True
        time.sleep(2)
    return False


def demo_summary(dev):
    data = json.loads(out(dev, 'curl', '-sS', '--max-time', '20', f'{APP_URL}/api/summary', timeout=60))
    return {key: data.get(key) for key in COMPARE}


# ------------------------------------------------------------------ clock, zone and slots

def utcnow():
    return datetime.datetime.now(UTC)


def iso(instant):
    return instant.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def compact(instant):
    return instant.astimezone(UTC).strftime('%Y%m%dT%H%M%SZ')


def parse_iso(text):
    return datetime.datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=UTC) if text else None


def floor5(instant, zone):
    local = instant.astimezone(zone)
    return local.replace(minute=local.minute - local.minute % 5, second=0, microsecond=0).astimezone(UTC)


def hhmm(instant, zone):
    return instant.astimezone(zone).strftime('%H:%M')


def local_text(instant, zone):
    return instant.astimezone(zone).strftime('%Y-%m-%dT%H:%M')


def device_zone(dev, ev):
    name = ok(dev, 'schedule-get', ev=ev)['timezone']['name']
    return zoneinfo.ZoneInfo(name), name


def handled_slot(dev):
    return parse_iso((schedule_state(dev) or {}).get('handled'))


def sleep_until(instant, ev, why):
    wait = (instant - utcnow()).total_seconds()
    if wait > 0:
        ev.log(f'waiting {wait:.0f}s ({why})')
        time.sleep(wait)


def due_slot(dev, ev, zone):
    """The latest 5-minute boundary that a fast tick can still start on time: later than the slot the state handled
    last, at least BOUNDARY_MARGIN seconds old (the timer's own tick at that boundary is over)."""
    handled = handled_slot(dev)
    while True:
        now = utcnow()
        slot = floor5(now, zone)
        if handled is not None and slot <= handled:
            sleep_until(slot + datetime.timedelta(minutes=5, seconds=BOUNDARY_MARGIN), ev,
                        f'the slot {iso(slot)} is handled already; next boundary')
        elif (now - slot).total_seconds() < BOUNDARY_MARGIN:
            sleep_until(slot + datetime.timedelta(seconds=BOUNDARY_MARGIN), ev, 'the timer tick at the boundary')
        else:
            return slot


def clear_of_boundary(ev, zone):
    """Return once no timer tick is due for a while (at least BOUNDARY_MARGIN s after the last boundary and 40 s
    before the next): a read right after a file write then sees no tick of the timer in between."""
    while True:
        now = utcnow()
        slot = floor5(now, zone)
        since = (now - slot).total_seconds()
        if since < BOUNDARY_MARGIN:
            sleep_until(slot + datetime.timedelta(seconds=BOUNDARY_MARGIN), ev, 'the timer tick at the boundary')
        elif since > 300 - 40:
            sleep_until(slot + datetime.timedelta(minutes=5, seconds=BOUNDARY_MARGIN), ev, 'the next timer tick')
        else:
            return now


def just_after_boundary(ev, zone):
    """Return BOUNDARY_MARGIN..60 s after a boundary (wait for the next one if needed): the most time before the
    next timer tick."""
    now = utcnow()
    slot = floor5(now, zone)
    if (now - slot).total_seconds() > 60:
        slot += datetime.timedelta(minutes=5)
    sleep_until(slot + datetime.timedelta(seconds=BOUNDARY_MARGIN), ev, 'a boundary, for the most time before the next tick')
    return utcnow()


def quiet_time(zone):
    """A time of day whose slot today lies before now (and so before the `armed_at` schedule-set writes): an
    enabled schedule with it runs nothing until tomorrow."""
    return hhmm(floor5(utcnow(), zone) - datetime.timedelta(minutes=30), zone)


# ------------------------------------------------------------------ schedule settings

def settings(enabled=True, *, time_='03:00', days=DAYS, apps=(DEMO,), images=False, keep=7):
    return {'enabled': enabled, 'days': list(days), 'time': time_, 'apps': apps if apps == 'all' else list(apps),
            'include_images': images, 'keep_last': keep}


def schedule_set(dev, ev, schedule, confirm=True):
    return ok(dev, 'schedule-set', {'schedule': schedule, 'confirm': confirm}, ev=ev)


def write_schedule(dev, ev, *, time_, armed_at, enabled=True, days=DAYS, apps=(DEMO,), images=False, keep=7):
    """Root writes schedule.json directly (0644, the documented keys) to make a slot due without waiting."""
    record = {'schema': 1, 'enabled': enabled, 'days': list(days), 'time': time_,
              'apps': apps if apps == 'all' else list(apps), 'include_images': images, 'keep_last': keep,
              'updated': iso(utcnow()), 'armed_at': None if armed_at is None else iso(armed_at)}
    if list(record) != list(FILE_KEYS):
        raise Failed('schedule.json keys drifted from the contract')
    data = (json.dumps(record, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    run(dev, 'install', '-o', 'root', '-g', 'root', '-m', '0644', '/dev/stdin', SCHEDULE_TMP, input=data)
    run(dev, 'mv', '-f', '-T', SCHEDULE_TMP, SCHEDULE_FILE)
    ev.log(f'dev-{dev}: wrote {SCHEDULE_FILE} (root 0644): enabled={enabled} time={time_} '
           f'armed_at={record["armed_at"]} apps={record["apps"]} keep_last={keep}')
    return record


def schedule_off(dev, ev):
    """Turn the schedule off through schedule-set (audited); a file the engine refuses is rewritten off."""
    try:
        view = ok(dev, 'schedule-get', ev=ev)['schedule']
        if view['saved'] and view['problem'] is None and not view['enabled']:
            return
        rc, reply = helper(dev, 'schedule-set', {'schedule': settings(False), 'confirm': True}, ev=ev)
        if rc == 0:
            return
    except Failed as error:
        ev.log(f'schedule-set off failed ({error}); writing the file off')
    write_schedule(dev, ev, time_='03:00', armed_at=None, enabled=False)


def slot_jobs(dev, ev, slot_iso):
    return [job for job in ok(dev, 'jobs', ev=ev)['jobs']
            if job['type'] == 'backup' and ((job.get('params') or {}).get('schedule') or {}).get('slot') == slot_iso]


def wait_last_run(dev, ev, *, slot_iso=None, trigger=None, timeout=120, not_job=None):
    """schedule-get until its last run is the expected one; returns that view."""
    deadline = time.monotonic() + timeout
    while True:
        view = ok(dev, 'schedule-get', ev=ev)
        last = view['last_run'] or {}
        if (last.get('job_id') and last.get('job_id') != not_job and (slot_iso is None or last.get('slot') == slot_iso)
                and (trigger is None or last.get('trigger') == trigger)):
            return view
        if time.monotonic() > deadline:
            raise Failed(f'no scheduled run for slot={slot_iso} trigger={trigger} within {timeout}s: {last}')
        time.sleep(3)


def backups(dev, ev):
    return ok(dev, 'list', ev=ev)['backups']


def meta_of(dev, ev, backup_id):
    return next((item for item in backups(dev, ev) if item['id'] == backup_id), None)


def delete_backups(dev, ev, ids):
    listed = {item['id'] for item in backups(dev, ev)}
    for backup_id in ids:
        if backup_id and backup_id in listed:
            ok(dev, 'delete', {'backup_id': backup_id}, ev=ev)
            ev.log(f'dev-{dev}: deleted test backup {backup_id}')


def run_now(dev, ev, label, *, rid=None):
    started = ok(dev, 'schedule-run-now', {'request_id': rid or request_id()}, ev=ev)
    job, log = wait_job(dev, started['job_id'], ev=ev, label=label)
    ev.save(label, {'job': job, 'log': log})
    remember(dev, (job.get('result') or {}).get('backup_id'))
    return job, log


def manual_backup(dev, ev, label, apps=(DEMO,)):
    started = ok(dev, 'backup-start', {'apps': list(apps), 'include_images': False, 'note': label,
                                       'request_id': request_id()}, ev=ev)
    job, log = wait_job(dev, started['job_id'], ev=ev, label=label)
    ev.save(label, {'job': job, 'log': log})
    remember(dev, (job.get('result') or {}).get('backup_id'))
    return job, log


def require_engine(ev, dev, *, idle=True):
    memory_ok()
    status = ok(dev, 'status', ev=ev)
    ev.require(f'dev-{dev} runs the scheduled-backup engine (status.schedule present)',
               status.get('schedule') is not None, status.get('version'))
    if idle:
        ev.require(f'dev-{dev} idle', status['active_job'] is None, status['active_job'])
    return status


def scheduled_job_checks(ev, tag, job, *, slot_iso, trigger, apps=(DEMO,), encrypted=True, keep=7):
    params = job.get('params') or {}
    ev.check(f'{tag}: job params are a manual backup\'s plus schedule {{slot, trigger, keep_last}}, note 排程備份',
             params.get('note') == NOTE and params.get('apps') == list(apps) and params.get('include_images') is False
             and params.get('encrypt') is encrypted
             and params.get('schedule') == {'slot': slot_iso, 'trigger': trigger, 'keep_last': keep}, params)
    result = job.get('result') or {}
    ev.check(f'{tag}: result scheduled, slot, trigger, not partial, encrypted={encrypted}',
             job['state'] == 'succeeded' and result.get('scheduled') is True and result.get('slot') == slot_iso
             and result.get('trigger') == trigger and result.get('partial') is False and result.get('skipped_apps') == []
             and result.get('encrypted') is encrypted and result.get('apps') == list(apps),
             {key: result.get(key) for key in ('scheduled', 'slot', 'trigger', 'partial', 'skipped_apps', 'encrypted',
                                                'apps', 'retention_deleted')})


def listed_as_scheduled(ev, dev, tag, backup_id, *, encrypted=True, apps=(DEMO,)):
    meta = meta_of(dev, ev, backup_id)
    ev.check(f'{tag}: list shows the backup as 排程 (scheduled, type manual, note 排程備份)',
             meta is not None and meta['scheduled'] is True and meta['type'] == 'manual' and meta['note'] == NOTE
             and meta['encrypted'] is encrypted and [a['id'] for a in meta['apps']] == list(apps), meta)
    return meta


# ------------------------------------------------------------------ scenarios

SCENARIOS = {}
ALL = ('install', 'timer', 'fast', 'busy', 'timezone', 'run-now', 'retention', 'partial', 'kit-gate', 'compat', 'noise',
       'reboot', 'cleanup')


def scenario(name):
    def register(func):
        SCENARIOS[name] = func
        return func
    return register


# ------------------------------------------------------------------ install: units and the timer

ENGINE_SUMS = r'''
import hashlib, json, os
root = '/usr/local/lib/woowtech-cockpit-backup'
out = {}
for base, dirs, names in os.walk(root):
    dirs[:] = [d for d in dirs if d != '__pycache__']
    for name in names:
        path = os.path.join(base, name)
        with open(path, 'rb') as handle:
            out[os.path.relpath(path, root)] = hashlib.sha256(handle.read()).hexdigest()
with open('/usr/local/libexec/woowtech-cockpit-backup', 'rb') as handle:
    out['libexec/woowtech-cockpit-backup'] = hashlib.sha256(handle.read()).hexdigest()
print(json.dumps(out, sort_keys=True))
'''


def installed_engine(dev):
    return json.loads(py(dev, ENGINE_SUMS).stdout)


def git_bytes(commit, path):
    return subprocess.run(['git', '-C', str(REPO), 'show', f'{commit}:{path}'], capture_output=True, check=True).stdout


def source_engine(commit=None):
    """Per-file sha256 of the engine at a commit (git show, read-only) or in the working tree, keyed like
    installed_engine."""
    if commit is None:
        names = sorted(str(path.relative_to(REPO)) for path in (REPO / 'backup-engine' / 'woowbackup').rglob('*.py'))
        read = lambda name: (REPO / name).read_bytes()  # noqa: E731
    else:
        listing = subprocess.run(['git', '-C', str(REPO), 'ls-tree', '-r', '--name-only', commit,
                                  'backup-engine/woowbackup'], capture_output=True, check=True, text=True).stdout
        names = sorted(name for name in listing.split() if name.endswith('.py'))
        read = lambda name: git_bytes(commit, name)  # noqa: E731
    sums = {'woowbackup/' + name[len('backup-engine/woowbackup/'):]: hashlib.sha256(read(name)).hexdigest()
            for name in names}
    sums['VERSION'] = hashlib.sha256(read('VERSION')).hexdigest()
    sums['libexec/woowtech-cockpit-backup'] = hashlib.sha256(read('backup-engine/woowtech-cockpit-backup')).hexdigest()
    return sums


def engine_is(dev, sums):
    installed = installed_engine(dev)
    differ = sorted(name for name in set(sums) | {k for k in installed if k.endswith('.py')}
                    if installed.get(name) != sums.get(name))
    return differ == [], differ


def deploy(dev, ev, label):
    """tests/e2e/lab/deploy-src.sh <dev>: the working tree to /opt/woow-cockpit-src and manage.py install."""
    memory_ok()
    proc = subprocess.run([str(LAB_DIR / 'deploy-src.sh'), dev], stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=1800)
    (ev.dir / f'{label}.log').write_text(redact(proc.stderr.decode('utf-8', 'replace')), encoding='utf-8')
    if proc.returncode != 0:
        raise Failed(f'deploy-src.sh {dev} rc={proc.returncode}: {redact(proc.stderr.decode()[-400:])}')
    result = json.loads(proc.stdout)
    ev.save(label, result)
    ev.log(f'dev-{dev}: manage.py install -> status={result.get("status")} systemctl={result.get("systemctl")} '
           f'timer={result.get("timer")}')
    return result


def manage(dev, *args):
    proc = run(dev, 'python3', f'{SRC}/scripts/manage.py', *args, workdir=SRC, check=False, timeout=900)
    try:
        result = json.loads(proc.stdout)
    except ValueError:
        result = {'raw': proc.stdout.decode('utf-8', 'replace')[-500:]}
    return proc.returncode, result, proc.stderr.decode('utf-8', 'replace')


TRANSACTIONS_PY = r'''
import json, os
base = '/var/backups/woowtech-cockpit-source'
found = []
for name in sorted(os.listdir(base)):
    try:
        with open(os.path.join(base, name, 'transaction.json'), encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        continue
    found.append({'id': name, 'status': data.get('status'), 'systemd': data.get('systemd'),
                  'units': [[rec.get('path'), rec.get('existed')] for rec in data.get('files', [])
                            if str(rec.get('path', '')).startswith('usr/local/lib/systemd/')],
                  'unit_dirs': [[rec.get('path'), rec.get('existed')] for rec in data.get('directories', [])
                                if str(rec.get('path', '')).startswith('usr/local/lib/systemd')],
                  'files': len(data.get('files', []))})
print(json.dumps(found))
'''


def transactions(dev):
    return json.loads(py(dev, TRANSACTIONS_PY).stdout)


def unit_checks(ev, dev, tag):
    """The installed units as systemd and the file system have them (systemctl show/cat, stat; never verify)."""
    timer = show(dev, TIMER, 'LoadState', 'UnitFileState', 'ActiveState', 'FragmentPath', 'TimersCalendar',
                 'AccuracyUSec', 'RandomizedDelayUSec', 'Persistent', 'Unit', 'WantedBy', 'NextElapseUSecRealtime')
    service = show(dev, SERVICE, 'LoadState', 'FragmentPath', 'Type', 'ExecStart', 'StandardInput', 'StandardOutput',
                   'SyslogLevel', 'LogLevelMax', 'TimeoutStartUSec', 'RemainAfterExit', 'ActiveState')
    cat = out(dev, 'systemctl', 'cat', '--', TIMER, SERVICE)
    layout = unit_layout(dev)
    ev.save(f'{tag}-units', {'timer': timer, 'service': service, 'cat': cat, 'layout': layout})
    ev.check(f'{tag}: timer loaded from {UNIT_DIR}, enabled, active, calendar *:0/5, AccuracySec 15s, not persistent, '
             f'starts the tick service, WantedBy timers.target',
             timer.get('LoadState') == 'loaded' and timer.get('UnitFileState') == 'enabled'
             and timer.get('ActiveState') == 'active' and timer.get('FragmentPath') == f'{UNIT_DIR}/{TIMER}'
             and 'OnCalendar=*-*-* *:00/5:00' in timer.get('TimersCalendar', '') and timer.get('AccuracyUSec') == '15s'
             and timer.get('Persistent') == 'no' and timer.get('Unit') == SERVICE
             and timer.get('WantedBy') == 'timers.target', timer)
    found = re.search(r'next_elapse=(@[0-9]+)', timer.get('TimersCalendar', ''))
    following = unix_ts(found.group(1)) if found else None
    ev.check(f'{tag}: next elapse on a 5-minute boundary within 5 minutes',
             following is not None and int(following) % 300 == 0 and 0 < following - time.time() <= 300,
             timer.get('TimersCalendar'))
    ev.check(f'{tag}: service oneshot, fixed argv `{HELPER} schedule-tick`, stdin/stdout null, SyslogLevel warning, '
             f'LogLevelMax notice, 15 min timeout',
             service.get('LoadState') == 'loaded' and service.get('FragmentPath') == f'{UNIT_DIR}/{SERVICE}'
             and service.get('Type') == 'oneshot'
             and f'argv[]={HELPER} schedule-tick ;' in service.get('ExecStart', '')
             and service.get('StandardInput') == 'null' and service.get('StandardOutput') == 'null'
             and service.get('SyslogLevel') == '4' and service.get('LogLevelMax') == '5'
             and service.get('TimeoutStartUSec') == '15min', service)
    ev.check(f'{tag}: systemctl cat shows exactly the source unit files (ConditionPathExists of the helper included)',
             cat.count('# /usr/local/lib/systemd/system/') == 2
             and (REPO / 'backup-engine/systemd' / TIMER).read_text(encoding='utf-8') in cat
             and (REPO / 'backup-engine/systemd' / SERVICE).read_text(encoding='utf-8') in cat
             and f'ConditionPathExists={HELPER}' in cat, cat[-300:])
    sums = {name: hashlib.sha256(run(dev, 'cat', f'{UNIT_DIR}/{name}').stdout).hexdigest() for name in (TIMER, SERVICE)}
    source = {name: hashlib.sha256((REPO / 'backup-engine/systemd' / name).read_bytes()).hexdigest()
              for name in (TIMER, SERVICE)}
    ev.check(f'{tag}: unit files root:root 0644 with the source sha256; timers.target.wants links the timer',
             layout[TIMER] is not None and layout[TIMER].startswith('root:root 644 ')
             and layout[SERVICE] is not None and layout[SERVICE].startswith('root:root 644 ') and sums == source
             and layout['wants'] == f'{UNIT_DIR}/{TIMER}', {'layout': layout, 'sha256_equal': sums == source})
    return timer, service


@scenario('install')
def scenario_install(ev):
    devices = [d for d in os.environ.get('SCHEDULE_DEVICES', 'a,b').split(',') if d]
    tree = source_engine()
    report = {}
    for dev in devices:
        before = timer_state(dev)
        ev.log(f'dev-{dev}: timer before the install: {before}')
        result = deploy(dev, ev, f'install-{dev}')
        steps = result.get('systemctl')
        if result.get('status') == 'installed':
            if before['load_state'] == 'not-found':
                ev.check(f'dev-{dev} install over an engine without the timer: daemon-reload, then enable --now of '
                         f'the timer (no stop: it was not running)', steps == ['daemon-reload', f'enable --now {TIMER}'],
                         steps)
            else:
                ev.check(f'dev-{dev} install over an engine with the timer: stopped while files change, running again',
                         steps and steps[0] == f'stop {TIMER}' and steps[-1] == f'enable --now {TIMER}', steps)
            chain = transactions(dev)
            latest = next(t for t in reversed(chain) if t['id'] == result.get('backup_id'))
            ev.save(f'install-{dev}-transaction', latest)
            ev.check(f'dev-{dev} transaction journal records the timer as it was before the install',
                     (latest.get('systemd') or {}).get('timer') == TIMER
                     and latest['systemd']['before'] == before and latest['systemd']['stopped'] is bool(before['active']),
                     latest.get('systemd'))
        else:
            ev.check(f'dev-{dev} install: already-current (the working tree was installed before)',
                     result.get('status') == 'already-current', result)
        ev.check(f'dev-{dev} install output: the timer is loaded, enabled and active', result.get('timer') == TIMER_ON,
                 result.get('timer'))
        unit_checks(ev, dev, f'dev-{dev}')
        rc, verified, _err = manage(dev, 'verify')
        ev.save(f'verify-{dev}', verified)
        ev.check(f'dev-{dev} manage.py verify: verified, timer reported enabled and active (never as drift)',
                 rc == 0 and verified.get('status') == 'verified' and verified.get('timer') == TIMER_ON, verified)
        rc, plan, _err = manage(dev, 'plan', '--backup-demo-catalog')
        ev.check(f'dev-{dev} manage.py plan afterwards: nothing to change, no systemctl step',
                 rc == 0 and plan.get('changed') == [] and plan.get('systemctl') == [],
                 {key: plan.get(key) for key in ('changed', 'directories', 'systemctl')})
        same, differ = engine_is(dev, tree)
        ev.check(f'dev-{dev}: installed engine, helper and VERSION equal the working tree (sha256 per file)', same,
                 differ[:10])
        view = ok(dev, 'schedule-get', ev=ev)
        ev.save(f'schedule-get-{dev}', view)
        ev.check(f'dev-{dev} schedule-get: engine sees the timer enabled and active; schedule off by default',
                 view['timer']['enabled'] is True and view['timer']['active'] is True and view['schedule']['enabled'] is False
                 and view['next_runs'] == [], view['timer'])
        version = out(dev, 'cat', '/usr/local/lib/woowtech-cockpit-backup/VERSION').strip()
        report[dev] = {'status': result.get('status'), 'systemctl': steps, 'version': version,
                       'transaction': result.get('backup_id')}
    return {'devices': report}


# ------------------------------------------------------------------ timer: a real timer-driven run

@scenario('timer')
def scenario_timer(ev):
    dev = 'a'
    require_engine(ev, dev)
    ev.require('dev-a woowbk-demo healthy', healthy(dev))
    ev.require('dev-a timer enabled and active', timer_state(dev) == TIMER_ON, timer_state(dev))
    zone, zone_name = device_zone(dev, ev)
    made = []
    try:
        # The next boundary that leaves time to save: at least 75 s ahead.
        target = floor5(utcnow() + datetime.timedelta(seconds=75), zone) + datetime.timedelta(minutes=5)
        handled = handled_slot(dev)
        ev.require('the target slot is later than the slot handled last', handled is None or target > handled,
                   {'target': iso(target), 'handled': handled and iso(handled)})
        wanted = settings(True, time_=hhmm(target, zone))
        before = file_digest(dev, SCHEDULE_FILE)
        preview = schedule_set(dev, ev, wanted, confirm=False)
        ev.save('timer-preview', preview)
        ev.check('schedule-set preview: not saved (file unchanged), next run at the target boundary, nothing to delete',
                 preview['saved'] is False and preview['next_runs'][0]['at'] == iso(target)
                 and preview['retention']['delete'] == [] and preview['retention']['apps'] == [DEMO]
                 and preview['timezone']['name'] == zone_name and file_digest(dev, SCHEDULE_FILE) == before,
                 {'next': preview['next_runs'][:1], 'retention': preview['retention']})
        t0 = time.time()
        saved = schedule_set(dev, ev, wanted)
        ev.save('timer-saved', saved)
        stored = json.loads(out(dev, 'cat', SCHEDULE_FILE))
        mode = out(dev, 'stat', '-c', '%U:%G %a', SCHEDULE_FILE).strip()
        ev.check('schedule-set confirm: saved; schedule.json root 0644 with exactly the documented keys; armed now',
                 saved['saved'] is True and mode == 'root:root 644' and list(stored) == list(FILE_KEYS)
                 and stored['enabled'] is True and stored['time'] == hhmm(target, zone)
                 and abs(parse_iso(stored['armed_at']).timestamp() - t0) < 30, {'mode': mode, 'stored': stored})
        audit = engine_lines(dev, t0, 'schedule-set ')
        ev.check('journal: schedule-set audited (settings only, previous_enabled)',
                 any(f'enabled=true days={",".join(DAYS)} time={hhmm(target, zone)} apps={DEMO} include_images=false '
                     f'keep_last=7 previous_enabled=false loginuid=' in text and prio == 5 for text, prio in audit), audit)
        view = ok(dev, 'schedule-get', ev=ev)
        ev.check('schedule-get: next run is the target, timer enabled/active',
                 view['next_runs'][0]['at'] == iso(target) and view['next_runs'][0]['local'] == local_text(target, zone)
                 and view['timer']['enabled'] and view['timer']['active'], view['next_runs'])
        # What an install leaves on a device that has been up for a while: the timer just started, no tick yet (the
        # tick file lives on /run). The first tick comes within 5 minutes; nothing is wrong meanwhile.
        run(dev, 'systemctl', 'restart', TIMER)
        run(dev, 'rm', '-f', '--', TICK_FILE)
        view = ok(dev, 'schedule-get', ev=ev)
        status = ok(dev, 'status', ev=ev)['schedule']
        ev.save('timer-before-first-tick', {'schedule_get': view, 'status_schedule': status,
                                            'timer': show(dev, TIMER, 'ActiveEnterTimestamp', 'TimersCalendar')})
        ev.check('timer just started (as by an install) and no tick yet: no attention (the page must not say '
                 '「排程檢查沒有在執行」 for the first 5 minutes on a device that has been up for long)',
                 view['attention'] is None and status['attention'] is None,
                 {'timer': view['timer'], 'attention': view['attention']})
        sleep_until(target, ev, f'the timer at {iso(target)}')
        view = wait_last_run(dev, ev, slot_iso=iso(target), timeout=180)
        job_id = view['last_run']['job_id']
        tick = show(dev, SERVICE, 'ExecMainStartTimestamp', 'InvocationID', 'Result')
        timer = show(dev, TIMER, 'LastTriggerUSec', 'NextElapseUSecRealtime')
        started = unix_ts(tick.get('ExecMainStartTimestamp'))
        ev.save('timer-tick', {'service': tick, 'timer': timer, 'schedule_get': view})
        ev.check('the timer started the tick within AccuracySec (15 s) of the boundary; nothing else started it',
                 started is not None and 0 <= started - target.timestamp() <= 16 and tick.get('Result') == 'success',
                 {'tick_started': started, 'boundary': target.timestamp(), 'timer': timer})
        record = job_record(dev, job_id)
        created = parse_iso(record['created'])
        ev.check('the job was created by that tick, request id schedule-<slot UTC>',
                 record['request_id'] == f'schedule-{compact(target)}'
                 and 0 <= (created - target).total_seconds() <= 30, {'request_id': record['request_id'],
                                                                     'created': record['created']})
        job, log = wait_job(dev, job_id, ev=ev, label='timer-run')
        ev.save('timer-job', {'job': job, 'log': log})
        backup_id = (job.get('result') or {}).get('backup_id')
        remember(dev, backup_id)
        made.append(backup_id)
        scheduled_job_checks(ev, 'timer run', job, slot_iso=iso(target), trigger='on-time')
        listed_as_scheduled(ev, dev, 'timer run', backup_id)
        lines = engine_lines(dev, t0, 'schedule-')
        ev.save('timer-journal', lines)
        ev.check('journal: one schedule-run line for the slot (notice)',
                 [p for t, p in lines if t.startswith(f'schedule-run slot={iso(target)} job={job_id} trigger=on-time '
                                                       f'apps={DEMO} encrypted=true')] == [5], lines)
        view = ok(dev, 'schedule-get', ev=ev)
        ev.check('schedule-get after the run: last run succeeded with the backup, next run tomorrow, tick seen',
                 view['last_run']['result'] == 'succeeded' and view['last_run']['backup_id'] == backup_id
                 and view['next_runs'][0]['at'] == iso(target + datetime.timedelta(days=1))
                 and view['timer']['last_tick_age'] is not None and view['timer']['last_tick_age'] < 330
                 and view['attention'] is None, {'last_run': view['last_run'], 'timer': view['timer']})
        return {'slot': iso(target), 'job': job_id, 'backup': backup_id,
                'tick_delay_s': None if started is None else round(started - target.timestamp(), 1)}
    finally:
        schedule_off(dev, ev)
        delete_backups(dev, ev, made)


# ------------------------------------------------------------------ fast: a due slot, two starts, one job

@scenario('fast')
def scenario_fast(ev):
    dev = 'a'
    require_engine(ev, dev)
    ev.require('dev-a woowbk-demo healthy', healthy(dev))
    zone, _name = device_zone(dev, ev)
    made = []
    try:
        # The tick lock: a tick while another holds it changes nothing.
        holder = subprocess.Popen([LP, 'exec', dev_name(dev), 'flock', '--exclusive', TICK_LOCK, 'sleep', '8'],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2.5)
        held = tick_by_hand(dev, ev)
        under_lock = tick_service(dev)
        holder.wait(timeout=60)
        ev.check('a tick while another tick holds schedule-tick.lock returns tick-running; the unit still succeeds',
                 held.get('decision') == 'tick-running' and under_lock.get('Result') == 'success', {'hand': held,
                                                                                                    'unit': under_lock})
        slot = due_slot(dev, ev, zone)
        t0 = time.time()
        write_schedule(dev, ev, time_=hhmm(slot, zone), armed_at=slot - datetime.timedelta(minutes=1))
        first = tick_service(dev)
        second = tick_service(dev)
        again = tick_by_hand(dev, ev)
        ev.save('fast-ticks', {'first': first, 'second': second, 'by_hand': again})
        jobs = slot_jobs(dev, ev, iso(slot))
        ev.check('two starts of the tick service (and a third tick by hand) make exactly one job for the slot',
                 len(jobs) == 1 and first['InvocationID'] != second['InvocationID']
                 and again.get('decision') == 'idle', {'jobs': [j['id'] for j in jobs], 'by_hand': again})
        ev.require('one scheduled job started', len(jobs) == 1)
        job_id = jobs[0]['id']
        ev.check('the job\'s request id is schedule-<slot UTC>',
                 job_record(dev, job_id)['request_id'] == f'schedule-{compact(slot)}')
        job, log = wait_job(dev, job_id, ev=ev, label='fast-run')
        ev.save('fast-job', {'job': job, 'log': log})
        backup_id = (job.get('result') or {}).get('backup_id')
        remember(dev, backup_id)
        made.append(backup_id)
        scheduled_job_checks(ev, 'fast run', job, slot_iso=iso(slot), trigger='on-time')
        ev.check('job log names the scheduled run and its backup id',
                 any('排程備份（依排程' in line and backup_id in line for line in log), [l for l in log if '排程' in l])
        listed_as_scheduled(ev, dev, 'fast run', backup_id)
        inspected = ok(dev, 'inspect', {'backup_id': backup_id}, ev=ev)
        ev.check('inspect: the archive itself is a manual backup with the note 排程備份 (formats unchanged)',
                 inspected['manifest']['type'] == 'manual' and inspected['manifest']['note'] == NOTE
                 and inspected['backup']['scheduled'] is True, {k: inspected['manifest'][k] for k in ('type', 'note')})
        state = schedule_state(dev)
        mode = out(dev, 'stat', '-c', '%U:%G %a', STATE_FILE).strip()
        ev.check('schedule-state.json (root 0600): registry lists the backup with job, slot, trigger; slot handled',
                 mode == 'root:root 600' and state['registry'].get(backup_id) == {'job': job_id, 'slot': iso(slot),
                                                                                  'trigger': 'on-time'}
                 and state['handled'] == iso(slot), {'mode': mode, 'handled': state.get('handled')})
        tick_service(dev)  # records the outcome
        tick_service(dev)
        lines = engine_lines(dev, t0, 'schedule-')
        ev.save('fast-journal', lines)
        ev.check('journal: schedule-run and schedule-result once each for the slot (notice), nothing else',
                 [p for t, p in lines if t.startswith(f'schedule-run slot={iso(slot)} job={job_id} trigger=on-time '
                                                       f'apps={DEMO} encrypted=true')] == [5]
                 and [p for t, p in lines if t == f'schedule-result slot={iso(slot)} job={job_id} trigger=on-time '
                                                   f'result=succeeded backup={backup_id}'] == [5]
                 and len(lines) == 2, lines)
        view = ok(dev, 'schedule-get', ev=ev)
        status = ok(dev, 'status', ev=ev)
        summary = status['schedule']
        ev.save('fast-views', {'schedule_get': view, 'status_schedule': summary})
        new_events = [e for e in view['events'] if parse_iso(e['at']).timestamp() >= t0 - 1]
        ev.check('schedule-get last run: slot, device-local time, on-time, succeeded, the backup; no event, no '
                 'attention', view['last_run'] == {**view['last_run'], 'slot': iso(slot), 'local': local_text(slot, zone),
                                                   'job_id': job_id, 'trigger': 'on-time', 'state': 'succeeded',
                                                   'result': 'succeeded', 'backup_id': backup_id, 'skipped_apps': [],
                                                   'error': None}
                 and view['attention'] is None and new_events == [], {'last_run': view['last_run'], 'new': new_events})
        ev.check('status.schedule: on, the same last run, next run tomorrow at that time, the zone, the timer',
                 summary['enabled'] is True and summary['last_run'] == view['last_run']
                 and summary['next_run']['at'] == iso(slot + datetime.timedelta(days=1))
                 and summary['timezone'] == view['timezone'] and summary['timer']['active'] is True
                 and summary['attention'] is None, {k: summary[k] for k in ('enabled', 'next_run', 'timer')})
        usage = next(a for a in status['storage']['apps'] if a['id'] == DEMO)
        ev.check('storage per app counts the backup as scheduled, not manual', usage['types']['scheduled'] >= 1, usage)
        jobs_view = ok(dev, 'jobs', ev=ev)
        ev.check('jobs: the scheduled job is listed as a backup job; no schedule event for a success',
                 any(j['id'] == job_id and j['type'] == 'backup' for j in jobs_view['jobs'])
                 and [e for e in jobs_view['schedule_events'] if parse_iso(e['at']).timestamp() >= t0 - 1] == [],
                 jobs_view['schedule_events'][:3])
        # Deleting the backup drops its registry entry at the next tick.
        delete_backups(dev, ev, [backup_id])
        tick_service(dev)
        ev.check('after the backup is deleted, the next tick drops its registry entry',
                 backup_id not in schedule_state(dev)['registry'])
        return {'slot': iso(slot), 'job': job_id, 'backup': backup_id}
    finally:
        schedule_off(dev, ev)
        delete_backups(dev, ev, made)


# ------------------------------------------------------------------ busy: another job first

@scenario('busy')
def scenario_busy(ev):
    dev = 'a'
    require_engine(ev, dev)
    ev.require('dev-a woowbk-demo healthy', healthy(dev))
    zone, _name = device_zone(dev, ev)
    made = []
    candidates = [b for b in backups(dev, ev) if b['key_available'] and b['type'] in ('manual', 'safety')]
    ev.require('a backup dev-a can verify', candidates)
    target = max(candidates, key=lambda b: b['size'])
    ev.log(f'verify job target {target["id"]} ({target["size"]} bytes, format {target.get("format")})')
    paused = None
    try:
        slot = due_slot(dev, ev, zone)
        t0 = time.time()
        write_schedule(dev, ev, time_=hhmm(slot, zone), armed_at=slot - datetime.timedelta(minutes=1))
        verify = ok(dev, 'verify-start', {'backup_id': target['id'], 'request_id': request_id()}, ev=ev)
        busy_job = verify['job_id']
        deadline = time.monotonic() + 60
        while helper(dev, 'job-status', {'job_id': busy_job})[1]['job']['state'] != 'running':
            if time.monotonic() > deadline:
                raise Failed('the verify job did not start running')
            time.sleep(0.3)
        # A deep verify of the largest lab backup takes ~15 s: its unit is paused (SIGSTOP; it stays an active unit
        # with a running record) so both ticks below see the job, and resumed afterwards.
        paused = f'woowtech-backup-{busy_job}.service'
        run(dev, 'systemctl', 'kill', '--signal=SIGSTOP', '--', paused)
        tick_service(dev)
        still = helper(dev, 'job-status', {'job_id': busy_job})[1]['job']['state']
        ev.require('the verify job was still running when the tick ran', still == 'running', still)
        view = ok(dev, 'schedule-get', ev=ev)
        ev.save('busy-waiting', view)
        ev.check('schedule-get: the slot waits for the verify job (waiting {slot, local, since, job_id}), no run yet',
                 view['waiting'] is not None and view['waiting']['slot'] == iso(slot)
                 and view['waiting']['local'] == local_text(slot, zone) and view['waiting']['job_id'] == busy_job
                 and (view['last_run'] or {}).get('slot') != iso(slot) and slot_jobs(dev, ev, iso(slot)) == [],
                 view['waiting'])
        event = (view['events'] or [{}])[0]
        ev.check('event waiting for the slot, with the job it waits for, shown as not a missed run',
                 event.get('kind') == 'waiting' and event.get('slot') == iso(slot) and event.get('job_id') == busy_job
                 and event.get('not_run') is False and '等待其他作業完成後開始' in event.get('message', ''), event)
        ev.check('status.schedule.waiting and jobs.schedule_events show the same',
                 ok(dev, 'status', ev=ev)['schedule']['waiting'] == view['waiting']
                 and ok(dev, 'jobs', ev=ev)['schedule_events'][0]['kind'] == 'waiting')
        again = tick_by_hand(dev, ev)
        ev.check('a tick while it still runs: busy (late), no second waiting event',
                 again.get('decision') == 'busy' and again.get('trigger') == 'late'
                 and [e['kind'] for e in ok(dev, 'schedule-get', ev=ev)['events']
                      if parse_iso(e['at']).timestamp() >= t0 - 1].count('waiting') == 1, again)
        run(dev, 'systemctl', 'kill', '--signal=SIGCONT', '--', paused)
        paused = None
        vjob, _vlog = wait_job(dev, busy_job, ev=ev, label='busy-verify')
        ev.check('the verify job succeeded', vjob['state'] == 'succeeded', vjob.get('error'))
        tick_service(dev)
        view = wait_last_run(dev, ev, slot_iso=iso(slot), timeout=60)
        job_id = view['last_run']['job_id']
        ev.check('the first tick after the verify job ended started the slot late; nothing waits any more',
                 view['last_run']['trigger'] == 'late' and view['waiting'] is None
                 and len(slot_jobs(dev, ev, iso(slot))) == 1, view['last_run'])
        job, log = wait_job(dev, job_id, ev=ev, label='busy-run')
        ev.save('busy-job', {'job': job, 'log': log})
        backup_id = (job.get('result') or {}).get('backup_id')
        remember(dev, backup_id)
        made.append(backup_id)
        scheduled_job_checks(ev, 'late run', job, slot_iso=iso(slot), trigger='late')
        listed_as_scheduled(ev, dev, 'late run', backup_id)
        tick_service(dev)
        lines = engine_lines(dev, t0, 'schedule-')
        ev.save('busy-journal', lines)
        ev.check('journal: schedule-wait once (naming the verify job), then schedule-run trigger=late and its result',
                 [p for t, p in lines if t == f'schedule-wait slot={iso(slot)} busy_job={busy_job}'] == [5]
                 and [p for t, p in lines if t.startswith(f'schedule-run slot={iso(slot)} job={job_id} trigger=late ')]
                 == [5]
                 and [p for t, p in lines if t.startswith(f'schedule-result slot={iso(slot)} job={job_id} trigger=late '
                                                           'result=succeeded')] == [5], lines)
        return {'slot': iso(slot), 'verify_job': busy_job, 'job': job_id, 'backup': backup_id}
    finally:
        if paused:
            run(dev, 'systemctl', 'kill', '--signal=SIGCONT', '--', paused, check=False)
        schedule_off(dev, ev)
        delete_backups(dev, ev, made)


# ------------------------------------------------------------------ timezone: /etc/localtime relinked

@scenario('timezone')
def scenario_timezone(ev):
    dev = 'a'
    require_engine(ev, dev)
    ev.require('dev-a woowbk-demo healthy', healthy(dev))
    original = out(dev, 'readlink', '/etc/localtime').strip()
    ev.require('/etc/localtime is a link into /usr/share/zoneinfo', original.startswith('/usr/share/zoneinfo/'), original)
    undo('localtime', ['a', original])
    made = []
    try:
        schedule_set(dev, ev, settings(True, time_='03:00'))
        first = ok(dev, 'schedule-get', ev=ev)
        name = original.split('/zoneinfo/', 1)[1]
        zone = zoneinfo.ZoneInfo(name)
        expected = [item for item in first['next_runs']]
        ev.check(f'schedule-get in {name}: zone name and offset, next runs at 03:00 device time',
                 first['timezone']['name'] == name and all(item['local'].endswith('T03:00') for item in expected)
                 and all(parse_iso(item['at']).astimezone(zone).strftime('%H:%M') == '03:00' for item in expected),
                 {'timezone': first['timezone'], 'next': expected})
        run(dev, 'ln', '-sfn', '/usr/share/zoneinfo/Asia/Taipei', '/etc/localtime')
        taipei = zoneinfo.ZoneInfo('Asia/Taipei')
        second = ok(dev, 'schedule-get', ev=ev)
        ev.save('timezone-taipei', second)
        ev.check('after relinking /etc/localtime to Asia/Taipei the next command uses it: +08:00, 03:00 Taipei = 19:00Z',
                 second['timezone'] == {'name': 'Asia/Taipei', 'utc_offset': '+08:00'}
                 and all(item['local'].endswith('T03:00') and item['utc_offset'] == '+08:00'
                         and item['at'].endswith('T19:00:00Z') for item in second['next_runs']), second['next_runs'])
        env_tz = json.loads(out(dev, HELPER, 'schedule-get', env={'TZ': 'America/New_York'}))
        ev.check('the caller\'s TZ is ignored (TZ=America/New_York in the environment): still Asia/Taipei',
                 env_tz['timezone'] == second['timezone'], env_tz['timezone'])
        ev.check('status.schedule shows the same zone', ok(dev, 'status', ev=ev)['schedule']['timezone']
                 == second['timezone'])
        # A due slot written in Taipei time: only a tick that reads the new zone finds it due.
        slot = due_slot(dev, ev, taipei)
        t0 = time.time()
        write_schedule(dev, ev, time_=hhmm(slot, taipei), armed_at=slot - datetime.timedelta(minutes=1))
        ev.log(f'slot {iso(slot)} = {local_text(slot, taipei)} Asia/Taipei (UTC reads {hhmm(slot, UTC)})')
        tick_service(dev)
        view = wait_last_run(dev, ev, slot_iso=iso(slot), timeout=60)
        job_id = view['last_run']['job_id']
        ev.check('the tick after the relink started the Taipei-time slot (the same HH:MM in UTC would not be due)',
                 view['last_run']['local'] == local_text(slot, taipei) and view['last_run']['trigger'] == 'on-time'
                 and hhmm(slot, taipei) != hhmm(slot, UTC), view['last_run'])
        job, log = wait_job(dev, job_id, ev=ev, label='timezone-run')
        ev.save('timezone-job', {'job': job, 'log': log})
        backup_id = (job.get('result') or {}).get('backup_id')
        remember(dev, backup_id)
        made.append(backup_id)
        scheduled_job_checks(ev, 'Taipei run', job, slot_iso=iso(slot), trigger='on-time')
        lines = engine_lines(dev, t0, 'schedule-run ')
        ev.check('journal: schedule-run with the slot as UTC', any(t.startswith(f'schedule-run slot={iso(slot)} ')
                                                                for t, _p in lines), lines)
        run(dev, 'ln', '-sfn', '/usr/share/zoneinfo/America/New_York', '/etc/localtime')
        third = ok(dev, 'schedule-get', ev=ev)
        ev.check('relinked to America/New_York: -05:00 in November, next run at the same local HH:MM there',
                 third['timezone'] == {'name': 'America/New_York', 'utc_offset': '-05:00'}
                 and third['next_runs'][0]['local'].endswith('T' + hhmm(slot, taipei)), third['next_runs'][:1])
        return {'slot': iso(slot), 'taipei': local_text(slot, taipei), 'job': job_id}
    finally:
        run(dev, 'ln', '-sfn', original, '/etc/localtime')
        undo('localtime')
        ev.check('/etc/localtime linked back', out(dev, 'readlink', '/etc/localtime').strip() == original)
        schedule_off(dev, ev)
        delete_backups(dev, ev, made)


# ------------------------------------------------------------------ run-now

@scenario('run-now')
def scenario_run_now(ev):
    dev = 'a'
    require_engine(ev, dev)
    ev.require('dev-a woowbk-demo healthy', healthy(dev))
    zone, _name = device_zone(dev, ev)
    made = []
    try:
        run(dev, 'rm', '-f', '--', SCHEDULE_FILE)
        rc, reply = helper(dev, 'schedule-run-now', {'request_id': request_id()}, ev=ev)
        ev.check('run-now without saved settings: invalid-request, reason not-saved',
                 rc == 1 and reply['error']['code'] == 'invalid-request'
                 and reply['error']['details'].get('reason') == 'not-saved', reply.get('error'))
        for bad in ({'request_id': 'short'}, {'request_id': request_id(), 'apps': [DEMO]}, {}):
            rc, reply = helper(dev, 'schedule-run-now', bad, ev=ev)
            ev.check(f'run-now request {sorted(bad)} refused strictly', rc == 1
                     and reply['error']['code'] == 'invalid-request', reply.get('error'))
        rc, reply = helper(dev, 'schedule-tick', {'schedule': {'enabled': True}}, ev=ev)
        extra = run(dev, HELPER, 'schedule-tick', 'x', check=False)
        ev.check('schedule-tick is argv only: stdin is never read (a request there changes nothing), an argument is '
                 'invalid-request', rc == 0 and reply.get('decision') == 'idle' and extra.returncode == 1
                 and json.loads(extra.stdout)['error']['code'] == 'invalid-request', reply)
        schedule_set(dev, ev, settings(False, time_=quiet_time(zone)))
        # A file the engine must not trust: group-writable.
        t0 = time.time()
        run(dev, 'chmod', '0664', SCHEDULE_FILE)
        view = ok(dev, 'schedule-get', ev=ev)
        rc, reply = helper(dev, 'schedule-run-now', {'request_id': request_id()}, ev=ev)
        ev.check('schedule.json group-writable: problem shown, run-now refused with reason settings-problem',
                 view['schedule']['problem'] and '排程備份已暫停' in view['schedule']['problem'] and rc == 1
                 and reply['error']['details'].get('reason') == 'settings-problem', view['schedule']['problem'])
        tick_service(dev)
        tick_service(dev)
        problem_events = [e for e in ok(dev, 'schedule-get', ev=ev)['events'] if e['kind'] == 'settings-problem']
        lines = engine_lines(dev, t0, 'schedule-skip ')
        ev.check('two ticks with the bad file: one settings-problem event, one warning line',
                 len([e for e in problem_events if parse_iso(e['at']).timestamp() >= t0 - 1]) == 1
                 and [p for t, p in lines if t == 'schedule-skip reason=settings-problem'] == [4], lines)
        ev.check('status.schedule names the problem', ok(dev, 'status', ev=ev)['schedule']['attention']['code']
                 == 'settings-problem')
        run(dev, 'chmod', '0644', SCHEDULE_FILE)
        tick_service(dev)
        ev.check('mode fixed: the problem is gone at the next command', ok(dev, 'schedule-get', ev=ev)['schedule']
                 ['problem'] is None)
        # Saved but off: one run now with the saved settings.
        t1 = time.time()
        rid = request_id()
        started = ok(dev, 'schedule-run-now', {'request_id': rid}, ev=ev)
        retry = ok(dev, 'schedule-run-now', {'request_id': rid}, ev=ev)
        rc, busy = helper(dev, 'schedule-run-now', {'request_id': request_id()}, ev=ev)
        ev.check('run-now while the schedule is off starts a job; the same request id returns it (deduplicated); '
                 'another request while it runs is busy with details.job_id',
                 started['deduplicated'] is False and retry == {**retry, 'job_id': started['job_id'],
                                                                 'deduplicated': True}
                 and rc == 1 and busy['error']['code'] == 'busy'
                 and busy['error']['details'].get('job_id') == started['job_id'], {'start': started, 'retry': retry})
        job, log = wait_job(dev, started['job_id'], ev=ev, label='run-now')
        ev.save('run-now-job', {'job': job, 'log': log})
        backup_id = (job.get('result') or {}).get('backup_id')
        remember(dev, backup_id)
        made.append(backup_id)
        scheduled_job_checks(ev, 'run-now', job, slot_iso=None, trigger='run-now')
        listed_as_scheduled(ev, dev, 'run-now', backup_id)
        view = ok(dev, 'schedule-get', ev=ev)
        ev.check('schedule-get last run: no slot, trigger run-now, succeeded, the backup; still off, no next run',
                 view['last_run']['slot'] is None and view['last_run']['local'] is None
                 and view['last_run']['trigger'] == 'run-now' and view['last_run']['result'] == 'succeeded'
                 and view['last_run']['backup_id'] == backup_id and view['schedule']['enabled'] is False
                 and view['next_runs'] == [] and view['attention'] is None, view['last_run'])
        tick_service(dev)
        tick_service(dev)
        lines = engine_lines(dev, t1, 'schedule-')
        ev.save('run-now-journal', lines)
        ev.check('journal: schedule-run slot=- trigger=run-now once, its schedule-result once',
                 [p for t, p in lines if t == f'schedule-run slot=- job={started["job_id"]} trigger=run-now apps={DEMO} '
                                               'encrypted=true'] == [5]
                 and [p for t, p in lines if t == f'schedule-result slot=- job={started["job_id"]} trigger=run-now '
                                                   f'result=succeeded backup={backup_id}'] == [5], lines)
        return {'job': started['job_id'], 'backup': backup_id}
    finally:
        run(dev, 'chmod', '0644', SCHEDULE_FILE, check=False)
        schedule_off(dev, ev)
        delete_backups(dev, ev, made)


# ------------------------------------------------------------------ retention: two pools

@scenario('retention')
def scenario_retention(ev):
    dev = 'a'
    require_engine(ev, dev)
    ev.require('dev-a woowbk-demo healthy', healthy(dev))
    zone, _name = device_zone(dev, ev)
    plan0 = ok(dev, 'retention-plan', {}, ev=ev)
    saved_policy = plan0['saved_policy'] if 'saved_policy' in plan0 else plan0['policy']
    ev.require('the manual keep-last policy is readable', plan0['policy_problem'] is None, plan0['policy_problem'])
    old_manual = sorted(b['id'] for b in backups(dev, ev) if b['type'] == 'manual' and not b['scheduled']
                        and DEMO in {a['id'] for a in b['apps']})
    ev.require('no scheduled woowbk-demo backup left from an earlier run (cleanup)',
               not [b for b in backups(dev, ev) if b['scheduled'] and DEMO in {a['id'] for a in b['apps']}])
    keep_manual = len(old_manual) + 2  # exactly what the manual backups of this scenario fill
    policy = {'schema': 1, 'default_keep_last': saved_policy.get('default_keep_last'),
              'apps': {**saved_policy.get('apps', {}), DEMO: {'keep_last': keep_manual}}}
    preview = ok(dev, 'retention-plan', {'policy': policy}, ev=ev)
    ev.require(f'manual policy keep {keep_manual} for {DEMO} would delete nothing now',
               preview['candidates'] == [] and preview['blocked'] == [], preview['candidates'][:3])
    undo('policy', ['a', saved_policy])
    made = []
    t0 = time.time()
    try:
        ok(dev, 'retention-apply', {'confirm': True, 'backup_ids': [], 'policy': policy}, ev=ev)
        schedule_set(dev, ev, settings(True, time_=quiet_time(zone), keep=2))
        s1, _log = run_now(dev, ev, 'retention-S1')
        m1, _log = manual_backup(dev, ev, 'retention-M1')
        s2, _log = run_now(dev, ev, 'retention-S2')
        preview = schedule_set(dev, ev, settings(True, time_=quiet_time(zone), keep=2), confirm=False)
        ids = {name: job['result']['backup_id'] for name, job in (('S1', s1), ('M1', m1), ('S2', s2))}
        made += list(ids.values())
        ev.check('schedule-set preview (keep 2): the next successful run would delete exactly the oldest scheduled '
                 'backup, no manual one', [item['id'] for item in preview['retention']['delete']] == [ids['S1']]
                 and preview['retention']['blocked'] == [] and all(item.get('scheduled') is True
                                                                  for item in preview['retention']['delete']),
                 preview['retention'])
        s3, _log = run_now(dev, ev, 'retention-S3')
        m2, _log = manual_backup(dev, ev, 'retention-M2')
        ids.update(S3=s3['result']['backup_id'], M2=m2['result']['backup_id'])
        made += [ids['S3'], ids['M2']]
        ev.save('retention-ids', ids)
        deleted = {name: job['result']['retention_deleted'] for name, job in (('S1', s1), ('M1', m1), ('S2', s2),
                                                                             ('S3', s3), ('M2', m2))}
        ev.check('only S3 (the third scheduled run, keep 2) deleted something: the oldest scheduled backup S1; the '
                 'manual backups under their keep-last policy deleted nothing',
                 deleted == {'S1': [], 'M1': [], 'S2': [], 'S3': [ids['S1']], 'M2': []}, deleted)
        listed = {b['id']: b for b in backups(dev, ev)}
        ev.check('list: S1 gone; S2, S3 scheduled; M1, M2 manual; every earlier manual woowbk-demo backup kept',
                 ids['S1'] not in listed and listed[ids['S2']]['scheduled'] and listed[ids['S3']]['scheduled']
                 and not listed[ids['M1']]['scheduled'] and not listed[ids['M2']]['scheduled']
                 and all(backup_id in listed for backup_id in old_manual),
                 {'missing_old_manual': [b for b in old_manual if b not in listed]})
        plan = ok(dev, 'retention-plan', {}, ev=ev)
        usage = next(a for a in plan['usage']['apps'] if a['id'] == DEMO)
        ev.check(f'retention-plan (manual policy keep {keep_manual}): no candidate; usage counts {keep_manual} manual '
                 'and 2 scheduled backups of the app', plan['candidates'] == [] and usage['types']['manual'] == keep_manual
                 and usage['types']['scheduled'] == 2 and usage['keep_last'] == keep_manual, usage)
        lines = engine_lines(dev, t0, 'retention-delete ')
        ev.save('retention-journal', lines)
        ev.check('journal: exactly one deletion, S1 with reason=schedule',
                 len(lines) == 1 and lines[0][0].startswith(f'retention-delete backup={ids["S1"]} type=manual size=')
                 and lines[0][0].endswith(f'apps={DEMO} reason=schedule'), lines)
        return {'ids': ids, 'retention_deleted': deleted, 'manual_keep_last': keep_manual}
    finally:
        ok(dev, 'retention-apply', {'confirm': True, 'backup_ids': [], 'policy': saved_policy}, ev=ev)
        undo('policy')
        schedule_off(dev, ev)
        delete_backups(dev, ev, made)


# ------------------------------------------------------------------ partial: apps that are not ready

def demo_units_active(dev):
    states = as_owner(dev, 'systemctl', '--user', 'is-active', *DEMO_UNITS, check=False).stdout.decode().split()
    return states == ['active', 'active'], states


def start_demo(dev, ev):
    as_owner(dev, 'systemctl', '--user', 'start', *DEMO_UNITS, check=False, timeout=300)
    ok_health = healthy(dev, 180)
    ev.log(f'dev-{dev}: woowbk-demo started again, healthy={ok_health}')
    return ok_health


def partial_checks(ev, dev, tag, job, skipped_id, t0):
    result = job.get('result') or {}
    skipped = [item.get('id') for item in result.get('skipped_apps') or []]
    ev.check(f'{tag}: the run succeeded as partial, without {skipped_id}',
             job['state'] == 'succeeded' and result.get('partial') is True and skipped == [skipped_id]
             and skipped_id not in (result.get('apps') or []) and bool(result.get('apps')),
             {'state': job['state'], 'error': job.get('error'),
              **{k: result.get(k) for k in ('partial', 'skipped_apps', 'apps')}})
    if job['state'] != 'succeeded':
        return
    tick_service(dev)
    view = ok(dev, 'schedule-get', ev=ev)
    event = (view['events'] or [{}])[0]
    ev.check(f'{tag}: next tick records a partial event naming the app', event.get('kind') == 'partial'
             and event.get('job_id') == job['id'] and '部分完成' in event.get('message', ''), event)
    attention = ok(dev, 'status', ev=ev)['schedule']['attention'] or {}
    ev.check(f'{tag}: status.schedule.attention partial: 「部分完成：上次排程備份沒有包含…」',
             attention.get('code') == 'partial' and attention.get('message', '').startswith('部分完成：上次排程備份沒有包含「')
             and attention.get('job_id') == job['id'], attention)
    lines = engine_lines(dev, t0, 'schedule-result ')
    ev.check(f'{tag}: journal warning schedule-result … result=partial … skipped={skipped_id}',
             [p for t, p in lines if t.startswith(f'schedule-result slot=- job={job["id"]} trigger=run-now result=partial '
                                                   f'backup={result["backup_id"]} skipped={skipped_id}')] == [4], lines)
    listed = meta_of(dev, ev, result['backup_id'])
    ev.check(f'{tag}: list: the partial backup is scheduled and holds the other apps only',
             listed and listed['scheduled'] and skipped_id not in [a['id'] for a in listed['apps']], listed)


@scenario('partial')
def scenario_partial(ev):
    dev = 'a'
    status = require_engine(ev, dev)
    ev.require('dev-a woowbk-demo healthy', healthy(dev))
    zone, _name = device_zone(dev, ev)
    others = [a['id'] for a in status['apps'] if a['id'] != DEMO and a['state'] == 'running']
    ev.require('other apps run on dev-a', others, [a['id'] for a in status['apps']])
    made = []
    try:
        # (a) woowbk-demo stopped by its owner: the schedule's apps "all" includes it.
        schedule_set(dev, ev, settings(True, time_=quiet_time(zone), apps='all'))
        undo('demo-stopped', 'a')
        as_owner(dev, 'systemctl', '--user', 'stop', *DEMO_UNITS, timeout=300)
        app = next(a for a in ok(dev, 'status', ev=ev)['apps'] if a['id'] == DEMO)
        ev.log(f'woowbk-demo after the stop: state={app["state"]} problems={app["problems"]}')
        t0 = time.time()
        job, log = run_now(dev, ev, 'partial-stopped')
        made.append((job.get('result') or {}).get('backup_id'))
        stopped_job = job['id']
        partial_checks(ev, dev, '(a) woowbk-demo stopped', job, DEMO, t0)
        ev.save('partial-stopped-app', {'app': app, 'job_error': job.get('error'), 'log_tail': log[-12:]})
        ev.require('woowbk-demo starts again', start_demo(dev, ev))
        undo('demo-stopped')
        # (b) an app the schedule lists was removed from this device's catalog.
        schedule_set(dev, ev, settings(True, time_=quiet_time(zone), apps=[DEMO, DIRS]))
        entry = f'{CATALOG}/{DIRS}.json'
        digest = out(dev, 'sha256sum', entry).split()[0]
        run(dev, 'install', '-d', '-m', '0700', PARKED)
        undo('parked-entry', ['a', DIRS, digest])
        run(dev, 'mv', '-f', '-T', entry, f'{PARKED}/{DIRS}.json')
        t0 = time.time()
        job, log = run_now(dev, ev, 'partial-not-in-catalog')
        made.append((job.get('result') or {}).get('backup_id'))
        reason = ((job.get('result') or {}).get('skipped_apps') or [{}])[0].get('reason')
        ev.check('(b) the skipped app\'s reason: 此設備沒有設定應用 woowbk-dirs。', reason == f'此設備沒有設定應用 {DIRS}。',
                 reason)
        partial_checks(ev, dev, f'(b) {DIRS} not in the catalog', job, DIRS, t0)
        return {'stopped_app_job': stopped_job, 'not_in_catalog_job': job['id']}
    finally:
        if load_state().get('undo', {}).get('parked-entry'):
            run(dev, 'mv', '-f', '-T', f'{PARKED}/{DIRS}.json', f'{CATALOG}/{DIRS}.json', check=False)
            back = out(dev, 'sha256sum', f'{CATALOG}/{DIRS}.json', check=False).split()
            ev.check(f'{DIRS} catalog entry back unchanged', back and back[0] == load_state()['undo']['parked-entry'][2])
            undo('parked-entry')
        if not demo_units_active(dev)[0]:
            start_demo(dev, ev)
        undo('demo-stopped')
        schedule_off(dev, ev)
        delete_backups(dev, ev, [m for m in made if m])


# ------------------------------------------------------------------ kit gate (dev-b, lab key)

@scenario('kit-gate')
def scenario_kit_gate(ev):
    dev = 'b'
    status = require_engine(ev, dev)
    ev.require('dev-b has no device key and 預設加密備份 is on', status['key'] is None
               and status['settings']['encrypt_by_default'] is True, {'key': status['key']})
    ev.require('dev-b woowbk-demo healthy', healthy(dev))
    zone, _name = device_zone(dev, ev)
    keys_before = out(dev, 'ls', '-A', KEYS).split()
    save_state(devb_keys_before=keys_before)
    view = ok(dev, 'schedule-get', ev=ev)
    ev.check('gate without a device key: blocked no-device-key', view['gate'] == {
        'encrypt': True, 'device_key': False, 'kit_confirmed': False, 'blocked': 'no-device-key'}, view['gate'])
    on = settings(True, time_=quiet_time(zone))
    for confirm in (False, True):
        rc, reply = helper(dev, 'schedule-set', {'schedule': on, 'confirm': confirm}, ev=ev)
        ev.check(f'turning it on without a device key (confirm={confirm}): no-device-key, nothing saved',
                 rc == 1 and reply['error']['code'] == 'no-device-key' and not exists(dev, SCHEDULE_FILE),
                 reply.get('error'))
    saved = schedule_set(dev, ev, settings(False, time_=quiet_time(zone)))
    ev.check('saving it off is never gated', saved['saved'] is True and saved['schedule']['enabled'] is False)
    rc, reply = helper(dev, 'schedule-run-now', {'request_id': request_id()}, ev=ev)
    ev.check('run-now while 預設加密備份 is on and there is no key: no-device-key', rc == 1
             and reply['error']['code'] == 'no-device-key', reply.get('error'))
    ok(dev, 'settings-set', {'encrypt_by_default': False, 'acknowledge_plaintext': True}, ev=ev)
    try:
        view = ok(dev, 'schedule-get', ev=ev)
        preview = helper(dev, 'schedule-set', {'schedule': on}, ev=ev)[1]
        ev.check('預設加密備份 off: nothing gates the schedule (no key needed)', view['gate']['blocked'] is None
                 and view['gate']['encrypt'] is False and preview.get('ok') is True and preview['saved'] is False,
                 view['gate'])
    finally:
        ok(dev, 'settings-set', {'encrypt_by_default': True}, ev=ev)
    created = ok(dev, 'key-init', ev=ev)
    key_id = created['key']['key_id']
    save_state(devb_key=key_id)
    ev.check('key-init on dev-b: a new lab key, kit not confirmed', created['created'] is True
             and created['key']['kit_confirmed'] is False, created['key'])
    view = ok(dev, 'schedule-get', ev=ev)
    ev.check('gate with the key but no saved kit: blocked kit-unconfirmed', view['gate'] == {
        'encrypt': True, 'device_key': True, 'kit_confirmed': False, 'blocked': 'kit-unconfirmed'}, view['gate'])
    before = out(dev, 'sha256sum', SCHEDULE_FILE).split()[0]
    for confirm in (False, True):
        rc, reply = helper(dev, 'schedule-set', {'schedule': on, 'confirm': confirm}, ev=ev)
        error = reply.get('error') or {}
        ev.check(f'turning it on before the kit is saved (confirm={confirm}): invalid-request, reason kit-unconfirmed, '
                 'field schedule.enabled, 「開啟排程備份前，請先保存緊急金鑰。」',
                 rc == 1 and error.get('code') == 'invalid-request'
                 and error.get('details', {}).get('reason') == 'kit-unconfirmed'
                 and error.get('details', {}).get('field') == 'schedule.enabled'
                 and error.get('message') == '開啟排程備份前，請先保存緊急金鑰。', error)
    ev.check('schedule.json unchanged by the refused requests', out(dev, 'sha256sum', SCHEDULE_FILE).split()[0] == before)
    job, log = run_now(dev, ev, 'kit-gate-run-now')
    ev.check('run-now is not kit-gated (like a manual backup): a scheduled backup with the unconfirmed key',
             job['state'] == 'succeeded' and job['result']['scheduled'] is True and job['result']['encrypted'] is True,
             job.get('error'))
    save_state(devb_scheduled={'backup': job['result'].get('backup_id'), 'job': job['id']})
    kit = ok(dev, 'key-kit', ev=ev)
    ev.check('key-kit: the kit names the key and holds one secret line (shown, never stored by this driver)',
             kit['key_id'] == key_id and len(SECRET_RE.findall(kit['content'])) == 1)
    del kit
    ok(dev, 'key-confirm', {'key_id': key_id}, ev=ev)
    view = ok(dev, 'schedule-get', ev=ev)
    ev.check('gate after the kit is confirmed: nothing blocks', view['gate'] == {
        'encrypt': True, 'device_key': True, 'kit_confirmed': True, 'blocked': None}, view['gate'])
    t0 = time.time()
    saved = schedule_set(dev, ev, on)
    ev.check('turning it on now succeeds: saved, enabled, armed', saved['saved'] is True
             and saved['schedule']['enabled'] is True and saved['schedule']['armed_at'] is not None, saved['schedule'])
    schedule_set(dev, ev, settings(False, time_=on['time']))
    lines = engine_lines(dev, t0, 'schedule-set ')
    ev.check('journal: schedule-set enabled=true previous_enabled=false, then enabled=false previous_enabled=true',
             len(lines) == 2 and 'enabled=true' in lines[0][0] and 'previous_enabled=false' in lines[0][0]
             and lines[1][0].startswith('schedule-set enabled=false') and 'previous_enabled=true' in lines[1][0], lines)
    return {'key_id': key_id, 'scheduled_backup': job['result'].get('backup_id')}


# ------------------------------------------------------------------ compat: 2026.11.15.2 reads scheduled backups

@scenario('compat')
def scenario_compat(ev):
    a, b = 'a', 'b'
    require_engine(ev, a)
    require_engine(ev, b)
    st = load_state()
    own = st.get('devb_scheduled') or {}
    ev.require('dev-b holds its own scheduled backup and job from kit-gate', own.get('backup') and own.get('job'), own)
    ev.require('dev-a woowbk-demo and dev-b woowbk-demo healthy', healthy(a) and healthy(b))
    zone, _name = device_zone(a, ev)
    old = source_engine(OLD)
    chain = transactions(b)
    adds = [t for t in chain if t['status'] == 'installed'
            and [f'usr/local/lib/systemd/system/{TIMER}', False] in t['units']]
    ev.require('dev-b: an installed transaction added the schedule units (deploy-src.sh over 2026.11.15.2)', adds,
               [t['id'] for t in chain][-3:])
    target = adds[-1]['id']
    newer = [t['id'] for t in chain if t['status'] == 'installed' and t['id'] > target]
    made_a = []
    try:
        # dev-a: a scheduled backup, downloaded through the bridge.
        schedule_set(a, ev, settings(False, time_=quiet_time(zone)))
        job, _log = run_now(a, ev, 'compat-source')
        ev.require('dev-a scheduled backup made', job['state'] == 'succeeded', job.get('error'))
        source_id = job['result']['backup_id']
        made_a.append(source_id)
        inspected = ok(a, 'inspect', {'backup_id': source_id}, ev=ev)
        snapshot = {k: v for k, v in inspected['manifest']['apps'][0]['verify_snapshot']['summary'].items()
                    if k in COMPARE}
        info = ok(a, 'download-info', {'backup_id': source_id}, ev=ev)
        DOWNLOADS.mkdir(parents=True, exist_ok=True)
        os.chmod(DOWNLOADS, 0o700)
        local = DOWNLOADS / f'schedule-{info["filename"]}'
        got = bridge_download(a, info['path'], local, ev=ev)
        ev.check('download through the bridge has the indexed size and sha256', got['bytes'] == info['size']
                 and got['sha256'] == meta_of(a, ev, source_id)['sha256'])
        save_state(download=str(local))
        _begin, (rc, again) = upload_file(a, local, ev=ev, filename=info['filename'])
        ev.check('uploading the same file to dev-a again returns the existing record (still scheduled, not uploaded)',
                 rc == 0 and again['backup']['id'] == source_id and again['backup']['type'] == 'manual'
                 and again['backup']['scheduled'] is True, again.get('backup') or again.get('error'))
        # dev-b down to the c393dfb engine with the installer's own rollback (the documented downgrade).
        ev.check('dev-b before the downgrade: schedule.json and schedule-state.json exist, its scheduled job is a '
                 'record with params.schedule', exists(b, SCHEDULE_FILE) and exists(b, STATE_FILE)
                 and 'schedule' in job_record(b, own['job'])['params'])
        steps = []
        for tid in reversed(newer):
            rc, rolled, err = manage(b, 'rollback', tid)
            steps.append([tid, rolled.get('status'), rolled.get('systemctl')])
            ev.require(f'dev-b rollback of the later transaction {tid}', rc == 0, err[-300:])
        rc, rolled, err = manage(b, 'rollback', target)
        ev.save('compat-rollback', {'later': steps, 'target': target, 'result': rolled})
        ev.require(f'dev-b rollback of {target} (the install that added the units)', rc == 0
                   and rolled.get('status') == 'rolled-back', err[-300:] or rolled)
        ev.check('rollback stopped and disabled the timer, reloaded systemd; it is no longer loaded',
                 rolled.get('systemctl', [])[:3] == [f'stop {TIMER}', f'disable {TIMER}', 'daemon-reload']
                 and (rolled.get('timer') or {}).get('load_state') == 'not-found'
                 and (rolled.get('timer') or {}).get('enabled') is False, rolled.get('systemctl'))
        layout = unit_layout(b)
        ev.check('dev-b after the rollback: no unit files, no timers.target.wants link, no unit directory',
                 layout == {TIMER: None, SERVICE: None, 'wants': None, 'unit_dir': False}
                 and timer_state(b)['load_state'] == 'not-found', layout)
        same, differ = engine_is(b, old)
        ev.check(f'dev-b runs exactly the {OLD} engine (2026.11.15.2, sha256 per file)', same, differ[:10])
        # The old engine with the new files and job records present.
        status = ok(b, 'status', ev=ev)
        ev.check('2026.11.15.2 status works with schedule.json, schedule-state.json and the new job records present',
                 status['version'] == '2026.11.15.2' and 'schedule' not in status and status['active_job'] is None,
                 status['version'])
        listed_jobs = ok(b, 'jobs', ev=ev)['jobs']
        record = next((j for j in listed_jobs if j['id'] == own['job']), None)
        ev.check('2026.11.15.2 jobs lists the scheduled job as a backup job (params.schedule kept)',
                 record is not None and record['type'] == 'backup' and record['state'] == 'succeeded'
                 and 'schedule' in record['params'], record and record['params'])
        ev.check('2026.11.15.2 job-status of the scheduled job', ok(b, 'job-status', {'job_id': own['job']}, ev=ev)
                 ['job']['result']['scheduled'] is True)
        mine = meta_of(b, ev, own['backup'])
        ev.check('2026.11.15.2 list: dev-b\'s scheduled backup is a manual backup with the note 排程備份 (no flag)',
                 mine is not None and mine['type'] == 'manual' and mine['note'] == NOTE and 'scheduled' not in mine, mine)
        ev.check('2026.11.15.2 inspect of it (dev-b key): manual, note 排程備份',
                 ok(b, 'inspect', {'backup_id': own['backup']}, ev=ev)['manifest']['type'] == 'manual')
        # dev-a's scheduled backup uploaded to the old engine, inspected with the kit and restored.
        _begin, (rc, uploaded) = upload_file(b, local, ev=ev, filename=info['filename'])
        ev.require('2026.11.15.2 upload-finish accepts the scheduled backup', rc == 0, uploaded.get('error'))
        remember(b, source_id)
        ev.check('it is listed as uploaded, key not on dev-b', uploaded['backup']['type'] == 'uploaded'
                 and uploaded['backup']['id'] == source_id and uploaded['backup']['key_available'] is False,
                 uploaded['backup'])
        rc, reply = helper(b, 'inspect', {'backup_id': source_id}, ev=ev)
        ev.check('inspect without a key: key-required', rc == 1 and reply['error']['code'] == 'key-required',
                 reply.get('error'))
        secret = kit_secret()
        looked = ok(b, 'inspect', {'backup_id': source_id, 'key': secret}, ev=ev)
        ev.save('compat-inspect', looked)
        papp = looked['preflight']['apps'][0]
        ev.check('2026.11.15.2 inspect with dev-a\'s kit: manual, note 排程備份, from woowbk-dev-a, restorable in place',
                 looked['manifest']['type'] == 'manual' and looked['manifest']['note'] == NOTE
                 and looked['manifest']['source']['hostname'] == 'woowbk-dev-a' and papp['restorable']
                 and papp['mode'] == 'inplace', {'type': looked['manifest']['type'], 'mode': papp['mode']})
        plain = status['key'] is None  # without a device key dev-b's safety backup can only be unencrypted
        if plain:
            ok(b, 'settings-set', {'encrypt_by_default': False, 'acknowledge_plaintext': True}, ev=ev)
        try:
            start = ok(b, 'restore-start', {'backup_id': source_id, 'apps': [DEMO], 'request_id': request_id(),
                                            'confirm': True, 'key': secret}, ev=ev)
            rjob, rlog = wait_job(b, start['job_id'], ev=ev, label='compat-restore', timeout=2400)
        finally:
            if plain:
                ok(b, 'settings-set', {'encrypt_by_default': True}, ev=ev)
        del secret
        ev.save('compat-restore', {'job': rjob, 'log': rlog})
        remember(b, (rjob.get('result') or {}).get('safety_backup_id'))
        ev.check('2026.11.15.2 restores dev-a\'s scheduled backup in place on dev-b: succeeded, data check matches',
                 rjob['state'] == 'succeeded' and [v['match'] for v in rjob['result']['verification']] == [True],
                 rjob.get('error'))
        ev.check('dev-b woowbk-demo now holds the data of dev-a\'s scheduled backup', healthy(b)
                 and demo_summary(b) == snapshot, {'after': demo_summary(b), 'snapshot': snapshot})
        # Back to the working tree.
        result = deploy(b, ev, 'compat-reinstall')
        ev.check('dev-b back on the working tree: installed, the timer enabled and active again',
                 result.get('status') == 'installed' and result.get('timer') == TIMER_ON
                 and result.get('systemctl') == ['daemon-reload', f'enable --now {TIMER}'], result.get('systemctl'))
        same, differ = engine_is(b, source_engine())
        ev.check('dev-b engine equals the working tree again', same, differ[:10])
        listed = {item['id']: item for item in backups(b, ev)}
        ev.check('new engine on dev-b: its own scheduled backup is 排程 again (registry kept), the upload is '
                 'uploaded and not scheduled', listed[own['backup']]['scheduled'] is True
                 and listed[source_id]['type'] == 'uploaded' and listed[source_id]['scheduled'] is False)
        preview = schedule_set(b, ev, settings(False, keep=1, time_='03:00'), confirm=False)
        ev.check('schedule-set preview keep 1 on dev-b: only its own scheduled backup would go; uploaded, safety '
                 'and manual backups are never in the schedule\'s pool',
                 [item['id'] for item in preview['retention']['delete']] == [own['backup']], preview['retention'])
        return {'source': source_id, 'rolled_back': [*[s[0] for s in steps], target], 'restore': start['job_id']}
    finally:
        schedule_off(a, ev)
        delete_backups(a, ev, made_a)


# ------------------------------------------------------------------ noise: PID 1 lines per tick

@scenario('noise')
def scenario_noise(ev):
    dev = 'a'
    require_engine(ev, dev)
    zone, _name = device_zone(dev, ev)
    schedule_off(dev, ev)
    t0 = time.time()
    suffix = os.urandom(3).hex()
    plain, filtered = f'woowbk-noise-plain-{suffix}', f'woowbk-noise-filtered-{suffix}'
    run(dev, 'systemd-run', '--wait', '--quiet', f'--unit={plain}', '--property=Type=oneshot', '/bin/true')
    run(dev, 'systemd-run', '--wait', '--quiet', f'--unit={filtered}', '--property=Type=oneshot',
        '--property=LogLevelMax=notice', '/bin/true')
    ticks = {}
    for _n in range(3):
        state = tick_service(dev)
        ticks[state['InvocationID']] = {'by': 'systemctl start', 'at': unix_ts(state['ExecMainStartTimestamp'])}
    boundaries = []
    for _n in range(2):
        boundary = floor5(utcnow(), zone) + datetime.timedelta(minutes=5)
        sleep_until(boundary + datetime.timedelta(seconds=BOUNDARY_MARGIN), ev, f'the timer tick at {iso(boundary)}')
        state = show(dev, SERVICE, 'InvocationID', 'ExecMainStartTimestamp')
        ticks.setdefault(state['InvocationID'], {'by': 'timer', 'at': unix_ts(state['ExecMainStartTimestamp'])})
        boundaries.append(iso(boundary))
    time.sleep(2)
    t1 = time.time()
    by_timer = [v for v in ticks.values() if v['by'] == 'timer' and v['at'] and v['at'] >= t0]
    ev.check('the window holds 3 started ticks and 2 timer ticks (distinct invocations)',
             len(ticks) == 5 and len(by_timer) == 2, ticks)
    entries = journal(dev, t0, '_PID=1')

    def kinds(unit):
        """PID 1 lines about `unit` by their first word (`<unit>: Deactivated …` counts as Deactivated)."""
        found = {}
        for entry in entries:
            text = message(entry)
            if entry.get('UNIT') == unit or (unit in text and entry.get('UNIT') in (None, unit)):
                text = text[len(unit) + 2:] if text.startswith(f'{unit}: ') else text
                word = text.split(' ', 1)[0]
                found[word] = found.get(word, 0) + 1
        return found
    tick_lines = kinds(SERVICE)
    report = {'ticks': len(ticks), 'timer_ticks': len(by_timer), 'boundaries': boundaries,
              'pid1_tick_service': tick_lines, 'pid1_timer': kinds(TIMER),
              'pid1_control_plain': kinds(f'{plain}.service'), 'pid1_control_logmax_notice': kinds(f'{filtered}.service'),
              'tick_process_lines': len(journal(dev, t0, f'_SYSTEMD_UNIT={SERVICE}')),
              'engine_lines': engine_lines(dev, t0), 'window_s': round(t1 - t0)}
    ev.save('noise-pid1', [{'unit': e.get('UNIT'), 'priority': e.get('PRIORITY'), 'message': message(e)}
                           for e in entries])
    ev.log(f'noise report: {report}')
    ev.check('control without LogLevelMax: PID 1 logs Starting, Deactivated and Finished (the journal captures them)',
             report['pid1_control_plain'].get('Starting') == 1 and report['pid1_control_plain'].get('Finished') == 1,
             report['pid1_control_plain'])
    ev.check('control with LogLevelMax=notice: no PID 1 line', report['pid1_control_logmax_notice'] == {},
             report['pid1_control_logmax_notice'])
    ev.check(f'the tick service (LogLevelMax=notice) over {len(ticks)} ticks: no PID 1 Starting/Finished line',
             tick_lines == {}, tick_lines)
    ev.check('the timer itself logs nothing per trigger; quiet ticks write no engine line and no process output',
             report['pid1_timer'] == {} and report['engine_lines'] == [] and report['tick_process_lines'] == 0,
             {k: report[k] for k in ('pid1_timer', 'engine_lines', 'tick_process_lines')})
    return report


# ------------------------------------------------------------------ reboot: missed slots and the catch-up

TIMENS_PY = r'''
import os, sys, time
# Run argv[2:] in a new time namespace whose CLOCK_BOOTTIME reads argv[1] seconds (util-linux 2.39 unshare cannot
# parse a negative --boottime offset).
offset = int(float(sys.argv[1]) - time.clock_gettime(time.CLOCK_BOOTTIME))
os.unshare(os.CLONE_NEWTIME)
with open('/proc/self/timens_offsets', 'w') as handle:
    handle.write(f'boottime {offset} 0\n')
pid = os.fork()
if pid == 0:
    os.execv(sys.argv[2], sys.argv[2:])
_pid, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
'''


def reset_state(dev, ev):
    """A device whose schedule never handled a slot: the state file goes (only when its registry names no backup
    that still exists; the scheduled backups of earlier scenarios are deleted by then)."""
    state = schedule_state(dev)
    if state is None:
        return
    present = {item['id'] for item in backups(dev, ev)}
    left = sorted(set(state.get('registry', {})) & present)
    if left:
        raise Failed(f'scheduled backups still listed in the registry: {left} (run cleanup first)')
    run(dev, 'rm', '-f', '--', STATE_FILE)
    ev.log(f'dev-{dev}: removed {STATE_FILE} (registry empty): a fresh schedule state')


def wait_device(dev, ev, uid=1001):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        proc = run(dev, 'systemctl', 'is-system-running', check=False, timeout=30)
        if proc.stdout.decode().strip() in ('running', 'degraded'):
            break
        time.sleep(2)
    if not healthy(dev, 90):
        ev.log(f'dev-{dev}: woowbk-demo not healthy after the restart: restarting user@{uid}.service (memory.max)')
        run(dev, 'systemctl', 'restart', f'user@{uid}.service', check=False, timeout=120)
    return healthy(dev, 180)


@scenario('reboot')
def scenario_reboot(ev):
    dev = 'a'
    require_engine(ev, dev)
    ev.require('dev-a woowbk-demo healthy', healthy(dev))
    zone, _name = device_zone(dev, ev)
    proc_uptime = float(out(dev, 'cat', '/proc/uptime').split()[0])
    host_uptime = float(Path('/proc/uptime').read_text().split()[0])
    ev.log(f'uptime inside dev-a {proc_uptime:.0f}s, host {host_uptime:.0f}s: the device sees the host kernel\'s '
           f'CLOCK_BOOTTIME')
    made = []
    reset_state(dev, ev)
    try:
        # (1) Missed: the latest slot is 22 h old and the next is 2 h away -> recorded, not run; 3 days collapse.
        now = clear_of_boundary(ev, zone)
        base = floor5(now, zone)
        missed_time = base + datetime.timedelta(hours=2)
        t0 = time.time()
        write_schedule(dev, ev, time_=hhmm(missed_time, zone), armed_at=now - datetime.timedelta(days=3, minutes=10))
        reply = tick_by_hand(dev, ev)
        latest = missed_time - datetime.timedelta(days=1)
        view = ok(dev, 'schedule-get', ev=ev)
        event = (view['events'] or [{}])[0]
        ev.save('reboot-missed', {'tick': reply, 'schedule_get': view})
        ev.check('three missed slots, the next one 2 h away: decision missed, one collapsed event (count 3), no job',
                 reply.get('decision') == 'missed' and reply.get('slot') == iso(latest) and event.get('kind') == 'missed'
                 and event.get('count') == 3 and event.get('slot') == iso(latest)
                 and event.get('first') == iso(missed_time - datetime.timedelta(days=3)) and event.get('not_run') is True
                 and '共 3 次的排程備份沒有執行：設備當時沒有開機，或排程檢查沒有在執行。' in event.get('message', '')
                 and view['last_run'] is None, event)
        ev.check('attention missed with the event\'s text; next run in 2 h', (view['attention'] or {}).get('code')
                 == 'missed' and view['attention']['message'] == event.get('message')
                 and view['next_runs'][0]['at'] == iso(missed_time), view['attention'])
        lines = engine_lines(dev, t0, 'schedule-')
        ev.check('journal: one schedule-missed line (notice) with first and count',
                 [(t, p) for t, p in lines] == [(f'schedule-missed slot={iso(latest)} '
                                                 f'first={iso(missed_time - datetime.timedelta(days=3))} count=3', 5)],
                 lines)
        # (2) A slot 35 minutes ago that no tick saw: overdue now; the timer stops ("device off").
        now = clear_of_boundary(ev, zone)
        slot = floor5(now, zone) - datetime.timedelta(minutes=35)
        while slot_jobs(dev, ev, iso(slot)):
            # An earlier scenario ran this instant: its request id schedule-<slot> would deduplicate the catch-up onto
            # that old job (the reset state no longer says the slot was handled).
            slot -= datetime.timedelta(minutes=5)
        write_schedule(dev, ev, time_=hhmm(slot, zone), armed_at=slot - datetime.timedelta(minutes=10))
        view = ok(dev, 'schedule-get', ev=ev)
        ev.check('a slot 35 minutes old, neither handled nor waiting: attention overdue (before the next tick)',
                 (view['attention'] or {}).get('code') == 'overdue' and view['attention'].get('slot') == iso(slot)
                 and '排程備份已逾期' in view['attention']['message'], view['attention'])
        run(dev, 'systemctl', 'stop', TIMER)
        view = ok(dev, 'schedule-get', ev=ev)
        ev.check('timer stopped: timer.active false, attention timer-inactive (it comes before overdue)',
                 view['timer']['active'] is False and (view['attention'] or {}).get('code') == 'timer-inactive',
                 {'timer': view['timer'], 'attention': view['attention']})
        before = schedule_state(dev)
        settle = json.loads(py(dev, TIMENS_PY, '120', HELPER, 'schedule-tick').stdout.decode().splitlines()[-1])
        after = schedule_state(dev)
        ev.check('a tick that sees 2 minutes of uptime (time namespace, CLOCK_BOOTTIME 120 s): settle, nothing '
                 'recorded, no job', settle.get('decision') == 'settle' and settle.get('slot') == iso(slot)
                 and {k: after.get(k) for k in ('handled', 'pending', 'events', 'last_run')}
                 == {k: before.get(k) for k in ('handled', 'pending', 'events', 'last_run')}
                 and not slot_jobs(dev, ev, iso(slot)), settle)
        # (3) Restart the device right after a boundary (the apps are up before the next tick); the timer comes back
        # by itself (enabled, timers.target).
        just_after_boundary(ev, zone)
        restarted = time.time()
        subprocess.run([LP, 'restart', dev_name(dev)], capture_output=True, timeout=180, check=True)
        ev.require('dev-a back: systemd running, woowbk-demo healthy', wait_device(dev, ev))
        state = timer_state(dev)
        view = ok(dev, 'schedule-get', ev=ev)
        ev.save('reboot-after-boot', {'timer': state, 'schedule_get': view})
        ev.check('after the restart the timer is active again without any command (enabled in timers.target)',
                 state == TIMER_ON, state)
        ev.log(f'after the restart, before the first tick: last_tick_age={view["timer"]["last_tick_age"]} '
               f'attention={view["attention"]} (lab: CLOCK_BOOTTIME is the host\'s, so "no tick for 15 minutes once '
               f'the device has been up that long" already holds)')
        first = floor5(utcnow(), zone) + datetime.timedelta(minutes=5)
        sleep_until(first, ev, f'the first timer tick after the restart at {iso(first)}')
        view = wait_last_run(dev, ev, slot_iso=iso(slot), trigger='catch-up', timeout=180)
        job_id = view['last_run']['job_id']
        tick = show(dev, SERVICE, 'ExecMainStartTimestamp')
        ev.check('the first timer tick after the restart caught the missed slot up (trigger catch-up)',
                 unix_ts(tick['ExecMainStartTimestamp']) is not None
                 and unix_ts(tick['ExecMainStartTimestamp']) >= first.timestamp() - 1, tick)
        job, log = wait_job(dev, job_id, ev=ev, label='reboot-catch-up')
        ev.save('reboot-job', {'job': job, 'log': log})
        backup_id = (job.get('result') or {}).get('backup_id')
        remember(dev, backup_id)
        made.append(backup_id)
        scheduled_job_checks(ev, 'catch-up run', job, slot_iso=iso(slot), trigger='catch-up')
        tick_service(dev)
        lines = engine_lines(dev, restarted, 'schedule-')
        ev.save('reboot-journal', lines)
        ev.check('journal after the restart: schedule-run trigger=catch-up and its result, once each',
                 [p for t, p in lines if t.startswith(f'schedule-run slot={iso(slot)} job={job_id} trigger=catch-up ')]
                 == [5] and [p for t, p in lines if t.startswith(f'schedule-result slot={iso(slot)} job={job_id} '
                                                                  'trigger=catch-up result=succeeded')] == [5], lines)
        view = ok(dev, 'schedule-get', ev=ev)
        ev.check('after the catch-up: no attention, the missed event of step 1 is still listed',
                 view['attention'] is None and any(e['kind'] == 'missed' for e in view['events']), view['attention'])
        return {'proc_uptime_s': round(proc_uptime), 'host_uptime_s': round(host_uptime), 'catch_up_job': job_id,
                'slot': iso(slot)}
    finally:
        if timer_state(dev)['active'] is False:
            run(dev, 'systemctl', 'start', TIMER, check=False)
        schedule_off(dev, ev)
        delete_backups(dev, ev, made)


# ------------------------------------------------------------------ cleanup

@scenario('cleanup')
def scenario_cleanup(ev):
    st = load_state()
    pending = st.get('undo', {})
    if 'localtime' in pending:
        dev, original = pending['localtime']
        run(dev, 'ln', '-sfn', original, '/etc/localtime')
        undo('localtime')
    if 'parked-entry' in pending:
        dev, app_id, _digest = pending['parked-entry']
        run(dev, 'mv', '-f', '-T', f'{PARKED}/{app_id}.json', f'{CATALOG}/{app_id}.json', check=False)
        undo('parked-entry')
    if 'demo-stopped' in pending:
        start_demo(pending['demo-stopped'], ev)
        undo('demo-stopped')
    if 'policy' in pending:
        dev, policy = pending['policy']
        ok(dev, 'retention-apply', {'confirm': True, 'backup_ids': [], 'policy': policy}, ev=ev)
        undo('policy')
    for dev in ('a', 'b'):
        if timer_state(dev)['load_state'] == 'loaded' and not timer_state(dev)['active']:
            run(dev, 'systemctl', 'start', TIMER)
        status = ok(dev, 'status', ev=ev)
        if status['active_job']:
            wait_job(dev, status['active_job']['id'], ev=ev, label=f'cleanup-wait-{dev}')
        if status.get('schedule') is not None:
            schedule_off(dev, ev)
        mine = [backup_id for d, backup_id in load_state().get('created', []) if d == dev]
        delete_backups(dev, ev, mine)
        save_state(created=[item for item in load_state().get('created', []) if item[0] != dev])
        present = {item['id'] for item in backups(dev, ev)}
        state = schedule_state(dev)
        left = sorted(set((state or {}).get('registry', {})) & present)
        ev.check(f'dev-{dev}: no scheduled backup left', left == [], left)
        if not left:
            run(dev, 'rm', '-f', '--', SCHEDULE_FILE, STATE_FILE, SCHEDULE_TMP)
            run(dev, 'rm', '-rf', '--', PARKED)
        run(dev, 'install', '-o', 'root', '-g', 'root', '-m', '0644',
            f'{SRC}/catalog-examples/woowbk-demo/catalog.json', f'{CATALOG}/woowbk-demo.json')
        ev.check(f'dev-{dev}: woowbk-demo entry is the fixture again',
                 run(dev, 'cmp', '-s', f'{SRC}/catalog-examples/woowbk-demo/catalog.json', f'{CATALOG}/woowbk-demo.json',
                     check=False).returncode == 0)
        view = ok(dev, 'schedule-get', ev=ev)
        ev.check(f'dev-{dev}: schedule files gone (off, defaults), timer enabled and active, no job',
                 not exists(dev, SCHEDULE_FILE) and not exists(dev, STATE_FILE) and view['schedule']['saved'] is False
                 and timer_state(dev) == TIMER_ON and ok(dev, 'status', ev=ev)['active_job'] is None, view['schedule'])
        ev.check(f'dev-{dev}: /etc/localtime is Etc/UTC', out(dev, 'readlink', '/etc/localtime').strip()
                 == '/usr/share/zoneinfo/Etc/UTC')
        ev.check(f'dev-{dev}: woowbk-demo running', healthy(dev, 120))
    # dev-b's lab key from kit-gate: the backups encrypted with it are gone above.
    key_id = load_state().get('devb_key')
    if key_id:
        before = set(load_state().get('devb_keys_before') or ['.lock'])
        names = out('b', 'ls', '-A', KEYS).split()
        extra = [name for name in names if name not in before]
        ev.check('dev-b keys directory: only the lab key file and keys.json were added', sorted(extra)
                 == sorted({f'device-{key_id}.key', 'keys.json'} - before), extra)
        for name in extra:
            if name in (f'device-{key_id}.key', 'keys.json'):
                run('b', 'rm', '-f', '--', f'{KEYS}/{name}')
        save_state(devb_key=None, devb_scheduled=None)
    status_b = ok('b', 'status', ev=ev)
    ev.check('dev-b ends without a device key', status_b['key'] is None and status_b['imported_keys'] == [],
             status_b['key'])
    download = load_state().get('download')
    if download and Path(download).exists():
        Path(download).unlink()
        save_state(download=None)
    leftovers = sorted(str(p) for p in DOWNLOADS.glob('schedule-*'))
    for path in leftovers:
        Path(path).unlink()
    hits = []
    secret = kit_secret()
    for base, _dirs, names in os.walk(EVIDENCE):
        for name in names:
            data = Path(base, name).read_bytes()
            if SECRET_RE.search(data.decode('utf-8', 'replace')) or secret.encode() in data:
                hits.append(str(Path(base, name)))
    ev.check('schedule evidence holds no key material', hits == [], hits)
    return {}


# ------------------------------------------------------------------ main

def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('scenario', nargs='+')
    args = parser.parse_args()
    names = []
    for name in args.scenario:
        if name == 'all':
            names += [n for n in ALL if n not in names]
        elif name in SCENARIOS:
            names.append(name)
        else:
            parser.error(f'unknown scenario {name} (one of {", ".join(SCENARIOS)}, all)')
    all_ok = True
    for name in names:
        ev = Evidence(name)
        try:
            extra = SCENARIOS[name](ev) or {}
        except Failed as error:
            ev.log(f'ABORTED: {error}')
            extra = {'aborted': str(error)}
        except Exception as error:  # noqa: BLE001 - record and continue to the summary
            ev.log(f'ABORTED with {type(error).__name__}: {redact(str(error))}')
            extra = {'aborted': f'{type(error).__name__}: {redact(str(error))}'}
        all_ok = ev.finish(extra) and 'aborted' not in extra and all_ok
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
