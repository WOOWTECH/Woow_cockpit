"""Home Assistant import: this device made ready for what an importer reads from it or converts with it (HAOS parity,
2026-11-25, DESIGN F-c; lane F3-helpers). Owner: E2.

HAOS restores onto a machine it sets up itself: it pulls the add-on's image, starts the add-on, goes on. This device was set up
by somebody else, so an import used to refuse whenever something it wants to read was not in the state it expected: an image
not downloaded, a database stopped, the owner's user manager not running. The helpers here put the device in that state, and
say what they did, instead of refusing; what they cannot do stops only the app that needed it (a BackupError that carries its
issue, which the isolation of haimport turns into that app's stop: every other app goes on, this device's app is unchanged).

What an app module uses. Every function takes `work` (haimport.Work) and `app` (the catalog entry); nothing here needs more of
`work` than `runner(app)`, and what is missing (`log`, `sink`, `temp`, `abort`, `guard`) is simply not used.

* ensure_image(work, app, ref)         the image is here: downloaded as the app's owner when it is not (CM-05, X-AD-60).
                                       `hacommon.image_labels` does it for the image it reads; `ensure_app_images(work, app)` for
                                       every image of the app's Quadlet files (call it before `adapter.import_manifest`).
* ensure_running(work, app, container, ready=...)
                                       the container (a database, a service) runs and is ready to be read: started when it was
                                       stopped, and put back when the app's throwaway objects are cleaned (TempObjects.cleanup:
                                       the end of the app's check, the end of the conversion; also when the job fails or is
                                       cancelled) (CM-07). `hacommon.live_json` calls it by itself when its read fails.
* ensure_user_manager(work, app)       the owner's user manager runs: linger enabled when it was not (X-AD-01).
* retry(action, ...), wait_until(condition, ...)
                                       a read that can fail for a moment is tried again with growing pauses; a wait ends when its
                                       condition holds, the deadline passes or the job is stopped.
* extras(app, handled_volumes, handled_dirs) and carry(work, app, out_dir, ids, volumes=..., dirs=...)
                                       this device's own volumes and folders an importer does not convert are copied into the
                                       backup as they are (OD-12/13, N8-02/27, O-07, HS-04, CS-04).
* not_deployed_error(app, info)        the error for an app the adapter calls not deployed, with the real reason (FL-11, HA-07).
* size_hint(ha), scale_waits(tmp, ha)  about how big the apps of an open HA backup are; the waits of an app's throwaway containers
                                       follow it (X-PD-05: haimport.Work.temp calls scale_waits; no wait ever gets shorter).

Nothing here weakens a protection: a throwaway container still never pulls (`--pull=never`; the pull is made here, before,
as the owner); an image is only ever pulled by the reference this device's own Quadlet file names; a service is only ever
started through the unit its own Quadlet file defines; the watchdog (free space, cancel) is asked during every pull and
wait; a copy of this device's data goes through the same checks as every converted volume (nested.check_volume).
"""
import contextlib
import dataclasses
import os
import re
import time
from pathlib import Path

from . import haissues, podman, tempctr
from .errors import BackupError
from .haissues import Issue

ISSUES = {
    'target.image-pulled': 'auto',      # CM-05, X-AD-60: the image was not on this device, it was downloaded
    'target.image-missing': 'stop',     # ... and could not be: this app only
    'target.service-started': 'auto',   # CM-07: a stopped service or database was started to be read, and is put back
    'target.service-failed': 'stop',    # ... and could not be started or did not become ready: this app only
    'target.linger-enabled': 'auto',    # X-AD-01: the owner's user manager was not running, linger was enabled
    'target.linger-failed': 'stop',     # ... and could not be: this app only
}

PULL_TIMEOUT = 1800        # one download (the old pick_pg16 gave the same)
PULL_ATTEMPTS = 2          # a download that failed for a reason that may pass is tried once more
PULL_PAUSE = 5.0
START_TIMEOUT = 600        # what the adapter gives a unit to start
STOP_TIMEOUT = 180
READY_TIMEOUT = 300        # a database that was stopped needs its recovery (the adapter's own wait is 180 s)
READY_POLL = 2.0
# Why a command failed that no second try helps with (podman.REASONS).
PERMANENT = frozenset({'pull-denied', 'image-missing', 'no-space', 'no-user-manager', 'permission', 'subid', 'memory',
                       'unit-masked', 'unit-missing', 'db-auth', 'db-missing', 'role-missing', 'no-program'})
CONTAINER_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
VOLUME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
_sleep = time.sleep        # tests replace it
_clock = time.monotonic


def _log(work):
    return getattr(work, 'log', None) or (lambda _text: None)


def _auto(work, app, issue_id, message, items=()):
    """One `auto` line of this app (its result, and the job log through the sink); a work that has no sink only logs."""
    sink = getattr(work, 'sink', None)
    if sink is None:
        _log(work)(message)
        return
    sink(app).auto(issue_id, message, items)


def _abort_of(work):
    abort = getattr(work, 'abort', None)
    return abort if callable(abort) else None


def _long(work):
    """The kwargs of a long podman call: the job's watchdog when there is one."""
    abort = _abort_of(work)
    return {} if abort is None else {'abort': abort}


def _name(value, limit=120):
    return haissues.clean(value, limit)


def _stop(app, issue_id, message, items=(), *, action='', code='job-failed'):
    return haissues.stopped(Issue(issue_id, 'stop', message, items, action=action), code, app=app.id)


def _watch_storage(work, app):
    """The owner's Podman storage is watched while this job fills it (a pull writes there before any throwaway object exists)."""
    guard = getattr(work, 'guard', None)
    folders = getattr(work, 'storage_folders', None)
    if guard is None or folders is None:
        return
    for folder in folders(app):
        if folder not in guard.folders:
            guard.folders.append(folder)
    guard.check(0)


# ====================================================================== waiting and trying again

def wait_until(condition, *, timeout, interval=1.0, abort=None, sleep=None, clock=None):
    """True as soon as `condition()` is true, False when `timeout` seconds pass first. `abort` (the job's watchdog: a
    callable that returns the exception to stop with, or None) is asked before every look and its exception raised."""
    sleep, clock = sleep or _sleep, clock or _clock
    deadline = clock() + max(0.0, float(timeout))
    while True:
        if abort is not None:
            stop = abort()
            if stop is not None:
                raise stop
        if condition():
            return True
        if clock() >= deadline:
            return False
        sleep(min(float(interval), max(0.0, deadline - clock())) or 0.0)


def pause(seconds, abort=None, sleep=None):
    """Wait `seconds` in slices of at most a second, asking `abort` (the job's watchdog) before every slice."""
    sleep = sleep or _sleep
    left = float(seconds)
    while True:
        if abort is not None:
            stop = abort()
            if stop is not None:
                raise stop
        if left <= 0:
            return
        step = min(1.0, left)
        sleep(step)
        left -= step


def transient(error):
    """Whether another try may help: a failure of the job's own command or read (job-failed) that is not the job's end and
    whose kind (podman.reason_code) is not one that stays."""
    return (isinstance(error, BackupError) and error.code == 'job-failed' and not haissues.is_job_wide(error)
            and podman.reason_code(error) not in PERMANENT)


def retry(action, *, attempts=3, pause_first=2.0, factor=2.0, longest=30.0, retry_if=None, abort=None, log=None,
          what='', sleep=None):
    """`action()`'s value, tried up to `attempts` times: after a failure `retry_if(error)` (default `transient`) says
    whether to try again, after `pause_first` seconds, then `factor` times as long (at most `longest`); `abort` is asked before
    every try and during the pauses. The last failure is raised as it came. `log(text)` gets one short line per pause (what
    `what` names). For a read that can fail for a moment: a snapshot of a running database, a file that changes while it is
    read (O-32.., L-36.., HS-24.., OP-15..)."""
    sleep = sleep or _sleep
    retry_if = retry_if or transient
    delay = float(pause_first)
    attempts = max(1, int(attempts))
    for attempt in range(1, attempts + 1):
        if abort is not None:
            stop = abort()
            if stop is not None:
                raise stop
        try:
            return action()
        except Exception as error:
            if attempt >= attempts or haissues.is_job_wide(error) or not retry_if(error):
                raise
            if log is not None:
                log(f'{what or "讀取"}這次沒有成功（第 {attempt} 次），{delay:g} 秒後再試一次。')
            pause(delay, abort, sleep)
            delay = min(delay * float(factor), float(longest))
    raise ValueError('attempts must be at least 1')  # pragma: no cover - the loop above runs at least once


# ====================================================================== images (CM-05, X-AD-60)

def image_present(work, app, ref):
    """Whether this device has the image (as the app's owner sees it)."""
    result = work.runner(app).podman('image', 'inspect', '--format', '{{.Id}}', ref, timeout=60, max_output=64 * 1024,
                                     check=False)
    return result.returncode == 0


def _pull_failed(app, ref, sentence):
    if ref.startswith('localhost/'):
        text = (f'這台的「{app.name}」需要的映像 {_name(ref)} 是在這台自己建置的，現在不在了，也沒有地方可以下載'
                '；請先在這台重新建置這個映像（或啟動一次這個應用），再匯入。這台的應用沒有任何變更。')
        return _stop(app, 'target.image-missing', text, [ref], action='請先在這台重新建置映像後，再匯入這個應用。',
                     code='incompatible')
    text = (f'這台的「{app.name}」需要的映像 {_name(ref)} 不在這台，自動下載也沒有成功'
            + (f'：{sentence}' if sentence else '。') + '這台的應用沒有任何變更。')
    return _stop(app, 'target.image-missing', text, [ref], code='incompatible',
                 action='請確認這台連得到映像倉庫（或先在這台啟動一次這個應用，讓它自己下載映像），再匯入這個應用。')


def ensure_image(work, app, ref):
    """Make sure this device has the image `ref` (the reference its own Quadlet file names): True when it had to be
    downloaded, False when it was there (CM-05, X-AD-60).

    The download is `podman pull` run as the app's owner, the way the app's own unit would at its next start; a throwaway
    container never pulls. It is tried a second time when it failed for a reason that may pass (a registry that did not
    answer, a storage that was busy). When it cannot be had, only this app stops (`target.image-missing`, the reason in
    words that cannot carry a password, nothing changed): a locally built image that is gone, a registry that refuses, no
    network, no space. The watchdog is asked while it downloads (a full disk or a cancel ends it at once, for the whole job)."""
    if not isinstance(ref, str) or not tempctr.IMAGE_RE.fullmatch(ref) or ref.endswith(('.image', '.build')):
        raise BackupError('incompatible', f'映像名稱格式不正確：{_name(ref, 120)}', app=app.id)
    if image_present(work, app, ref):
        return False
    _watch_storage(work, app)
    runner = work.runner(app)
    sentence = ''
    for attempt in range(1, PULL_ATTEMPTS + 1):
        if ref.startswith('localhost/'):
            break
        try:
            result = runner.podman('pull', '--quiet', ref, timeout=PULL_TIMEOUT, max_output=64 * 1024, check=False,
                                   **_long(work))
            reason, sentence = (podman.classify(getattr(result, 'stderr', b''), result.returncode) if result.returncode
                                else (None, ''))
            failed = result.returncode != 0
        except BackupError as error:
            if haissues.is_job_wide(error) or error.code in ('insufficient-space', 'busy', 'owner-missing'):
                raise
            reason = podman.reason_code(error)
            sentence = podman.SENTENCES.get(reason, '')
            failed = True
        if not failed:
            if image_present(work, app, ref):
                _auto(work, app, 'target.image-pulled', f'這台沒有「{app.name}」用的映像 {_name(ref)}，已自動下載。', [ref])
                return True
            failed, reason = True, None
        if reason in PERMANENT or attempt >= PULL_ATTEMPTS:
            break
        _log(work)(f'下載映像 {_name(ref)} 沒有成功，{PULL_PAUSE:g} 秒後再試一次。')
        pause(PULL_PAUSE, _abort_of(work))
    raise _pull_failed(app, ref, sentence)


def ensure_app_images(work, app):
    """`ensure_image` for every image the app's own containers use (the Quadlet files' Image=): the refs that were
    downloaded. Call it before `adapter.import_manifest`, which records every one of them (X-AD-60). An adapter that cannot
    list its images (a test double) has none to look for."""
    adapter = work.adapter(app)
    listing = getattr(adapter, 'container_images', None)
    if listing is None:
        return []
    return [ref for ref in dict.fromkeys(listing(work.quadlets(app)).values()) if ensure_image(work, app, ref)]


# ====================================================================== the owner's user manager (X-AD-01)

def ensure_user_manager(work, app, runner=None):
    """The app owner's user manager runs (every `systemctl --user` and every Podman unit needs it): linger is enabled when
    it was not (`OwnerRunner.ensure_user_manager`); True then. Where it cannot be enabled only this app stops
    (`target.linger-failed`, with what to do). A runner that is not the real one (every test double) does nothing.
    `runner`: the app owner's runner when the caller has it already (the adapter that is just being made)."""
    runner = runner or work.runner(app)
    ensure = getattr(runner, 'ensure_user_manager', None)
    if ensure is None:
        return False
    try:
        started = ensure()
    except BackupError as error:
        if haissues.is_job_wide(error):
            raise
        raise _stop(app, 'target.linger-failed', error.message, [runner.owner],
                    action='請在這台設備開啟這個帳號的 linger 後再匯入。') from None
    if started:
        _auto(work, app, 'target.linger-enabled',
              f'帳號 {runner.owner} 的使用者服務管理器沒有在執行，已自動開啟它（loginctl enable-linger）；'
              '這個設定會保留，讓這個帳號的應用在沒有人登入時也能執行。', [runner.owner])
    return bool(started)


# ====================================================================== waits that grow with the app (X-PD-05)

UNPACKED_PER_STORED = 4    # what an app's data may be unpacked, against the HA file it comes from (a guess: only a floor-raiser)


def size_hint(ha):
    """About how many bytes the apps of this open HA backup are: its size, four times (a guess of what it is unpacked; it
    only raises waits, never lowers one). None when `ha` (a test double, a closed backup) does not know."""
    size = getattr(getattr(ha, 'layout', None), 'size', None)
    return size * UNPACKED_PER_STORED if isinstance(size, int) and not isinstance(size, bool) and size > 0 else None


def scale_waits(tmp, ha):
    """The waits of the app's throwaway containers (TempObjects.scale_to) grow with the open HA backup (`size_hint`; X-PD-05).
    A `tmp` or `ha` that does not know a size (a test double): nothing changes."""
    scale = getattr(tmp, 'scale_to', None)
    size = size_hint(ha)
    if scale is not None and size is not None:
        scale(size)


# ====================================================================== a stopped service, read while it runs (CM-07)

@dataclasses.dataclass
class Service:
    """What `ensure_running` found: the container, the unit that runs it (None while nothing had to be started) and whether
    this call started it (`started`: it is put back by the app's throwaway objects' cleanup)."""
    container: str
    unit: str | None
    started: bool


def _running(runner, container):
    result = runner.podman('container', 'inspect', '--format', '{{.State.Running}}', container, timeout=60,
                           max_output=64 * 1024, check=False)
    return result.returncode == 0 and (result.stdout or b'').strip() == b'true'


def _unit_of(work, app, container):
    """The systemd unit of the Quadlet file whose ContainerName= is `container` (None when no file says so)."""
    from . import hacommon
    from .adapters.quadlet_postgres import quadlet_unit
    name = hacommon.container_file(work.quadlets(app), container)
    return quadlet_unit(name) if name else None


def _ready(work, app, runner, container, ready):
    if ready == 'running':
        return lambda: _running(runner, container)
    if ready == 'postgres':
        return lambda: (_running(runner, container)
                        and runner.podman('exec', container, 'pg_isready', '-q', '-t', '5', timeout=30, max_output=64 * 1024,
                                          check=False).returncode == 0)
    if callable(ready):
        return lambda: bool(ready(runner, container))
    raise BackupError('internal-error', '等待服務就緒的方式不正確。')


def ensure_running(work, app, container, *, ready='running', size=None, timeout=None):
    """The container `container` of this device's app runs and can be read: a stopped one is started (`systemctl --user
    start` of the unit its Quadlet file defines), then waited for until `ready` says it can be read, and put back (stopped)
    when the app's throwaway objects are cleaned up -- the end of the app's check, the end of the conversion, also when the
    job fails or is cancelled (TempObjects.put_back_later). Asking again for the same container changes nothing.

    `ready`: 'running' (the container runs), 'postgres' (it also accepts connections: `pg_isready`) or a callable
    `(runner, container) -> bool`. `size`: the app's bytes when known (a database that was stopped needs its recovery: the
    wait grows with it, X-PD-05). Raises, for this app only, `target.service-failed` when it cannot be started or is not ready
    in time (what was started is put back first). A service that is running is not touched. Returns a `Service`."""
    if not isinstance(container, str) or not CONTAINER_RE.fullmatch(container):
        raise BackupError('internal-error', '容器名稱格式不正確。', app=app.id)
    ensure_user_manager(work, app)
    runner = work.runner(app)
    temp = work.temp(app) if callable(getattr(work, 'temp', None)) else None
    services = getattr(temp, 'services', None)
    known = services.get(container) if services is not None else None
    started = False
    unit = known
    if not _running(runner, container):
        unit = _unit_of(work, app, container)
        if unit is None:
            raise _stop(app, 'target.service-failed',
                        f'這台的「{app.name}」現在沒有在執行它的容器 {_name(container)}，也找不到可以啟動它的設定檔。',
                        [container], action='請先在這台啟動這個應用，再匯入。')
        _auto(work, app, 'target.service-started',
              f'這台「{app.name}」的容器 {_name(container)} 原本停著，已暫時啟動它來讀取資料；讀完會恢復原狀（停止）。',
              [container])
        try:
            runner.systemctl('start', '--', unit, timeout=podman.scaled_timeout(START_TIMEOUT, size), max_output=64 * 1024,
                             **_long(work))
        except BackupError as error:
            if haissues.is_job_wide(error) or error.code in ('insufficient-space', 'busy'):
                raise
            sentence = podman.SENTENCES.get(podman.reason_code(error), '')
            raise _stop(app, 'target.service-failed',
                        f'無法啟動這台「{app.name}」停著的服務（容器 {_name(container)}）' + (f'：{sentence}' if sentence else '。')
                        + '這台的應用沒有任何變更。', [container],
                        action='請先在這台把這個應用啟動起來並確認它正常，再匯入。') from None
        started = True
        if services is not None:
            services[container] = unit
            temp.put_back_later(f'容器 {container}', lambda: _stop_again(runner, unit, services, container))
    limit = float(timeout) if timeout is not None else float(podman.scaled_timeout(READY_TIMEOUT, size))
    if not wait_until(_ready(work, app, runner, container, ready), timeout=limit, interval=READY_POLL,
                      abort=_abort_of(work)):
        if started:
            with contextlib.suppress(BackupError):   # put it back now; the registered put-back finds it stopped
                _stop_again(runner, unit, services if services is not None else {}, container)
        raise _stop(app, 'target.service-failed',
                    f'這台「{app.name}」的容器 {_name(container)} 在 {int(limit)} 秒內沒有準備好，無法讀取它的資料。'
                    + ('這台的應用已恢復原狀。' if started else '這台的應用沒有任何變更。'), [container],
                    action='請先在這台確認這個應用能正常啟動，再匯入。')
    return Service(container, unit if (started or known) else None, started)


def _stop_again(runner, unit, services, container):
    """Put back what `ensure_running` started. No watchdog hook: a cancel or a full disk must not stop the put-back."""
    runner.systemctl('stop', '--', unit, timeout=STOP_TIMEOUT, max_output=64 * 1024)
    services.pop(container, None)


# ====================================================================== this device's own data, carried as it is

def extras(app, handled_volumes=(), handled_dirs=()):
    """([volume names], [folder paths]) the app's catalog entry declares and the importer does not convert: what `carry`
    takes (OD-12, OD-13, N8-02, N8-27, O-07, HS-04, CS-04). Order as the catalog has them."""
    volumes, dirs = set(handled_volumes), set(handled_dirs)
    return ([item['name'] for item in getattr(app, 'volumes', ()) if item['name'] not in volumes],
            [item['path'] for item in getattr(app, 'data_dirs', ()) if item['path'] not in dirs])


def carry(work, app, out_dir, ids, *, volumes=(), dirs=(), report=None, size=None):
    """Copy this device's own volumes `volumes` and host folders `dirs` (catalog paths) into the backup that is being made,
    exactly as they are, so a restore puts back what is there: `{'volumes': {name: tar}, 'dirs': {path: tar}}`, the shape
    `convert()` hands to `adapter.import_manifest` (add it to the importer's own items). A volume is exported while the
    app runs, checked like every converted volume (nested.check_volume with the owner's `ids`); a customer's own symlink that
    leaves the volume, or hard link to a member that is not there, is left out and listed in `report` (X-NS-08: the
    importer asks once, `Sink.skipped(report)`) instead of making the restore refuse the whole volume; a folder is packed
    inside the owner's user namespace and checked with nested.check_dir. Space is counted by the job's guard (staging and
    the output); `size`: the bytes of data when known (the waits grow with it)."""
    from . import ha_odoo, hacommon
    out_dir = Path(out_dir)
    carried = {'volumes': {}, 'dirs': {}}
    for name in volumes:
        if not isinstance(name, str) or not VOLUME_RE.fullmatch(name):
            raise BackupError('internal-error', '資料卷名稱格式不正確。', app=app.id)
        (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
        live = Path(work.staging) / f'carry-{name}.tar'
        hacommon.live_export(work, app, name, live, size=size)
        path = out_dir / 'volumes' / f'{name}.tar'
        out = hacommon.FileTar(path, work.guard)
        try:
            hacommon.copy_live(live, out, what=f'這台的資料卷 {name}', report=report, label=f'{name}：')
        finally:
            out.close()
            try:
                os.unlink(live)
            except FileNotFoundError:
                pass
        ha_odoo.check_volume_tar(path, ids)
        carried['volumes'][name] = path
    for index, rel in enumerate(dirs):
        (out_dir / 'dirs').mkdir(mode=0o700, parents=True, exist_ok=True)
        path = out_dir / 'dirs' / f'carry-{index}.tar'
        with open(path, 'xb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            work.runner(app).dir_pack(rel, stdout=handle, timeout=podman.scaled_timeout(3600, size),
                                      max_output=work.guard.budget(), **_long(work))
            handle.flush()
            os.fsync(handle.fileno())
        ha_odoo.check_dir_tar(path, ids)
        carried['dirs'][rel] = path
    return carried


# ====================================================================== what the adapter says is not deployed (FL-11, HA-07)

def not_deployed_error(app, info):
    """The error for an app whose `adapter.probe()` says it is not deployed. When the adapter knows why (its user manager is
    not running: the account has no linger) that reason is told instead of "not deployed here" (FL-11, HA-07); without one
    it is what it always said."""
    problems = (info or {}).get('problems') or []
    if problems:
        return BackupError('job-failed', f'應用「{app.name}」現在無法備份：{problems[0]}', app=app.id)
    return BackupError('not-deployed', f'應用「{app.name}」尚未部署在此設備，無法備份。', app=app.id)
