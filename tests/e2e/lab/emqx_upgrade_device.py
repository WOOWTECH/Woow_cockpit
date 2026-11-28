"""EMQX upgrade after an HA import (emqx_upgrade_after_import.py): the DEVICE side.

Runs INSIDE the isolated lab device woowbk-dev-d as appowner, the way the package is installed there
(`woowbk-owner python3 -B -I -c <this file + ENTRY>`): one JSON request on stdin, one JSON line on stdout
({"ok": true, "result": ...}, or a fixed error without any value). Never as root, never a pull, never a value of a
secret in a reply: dev-d's EMQX secrets are read here only to blank them out of the package's own output.

What it may touch (and nothing else):
  * the run folder ~/woowbk-emqx-upgrade-<run id: 12 hex>/ (0700, created once by `capture`, removed by `cleanup`):
    capture/ + capture.json (exact private copies of the EMQX files below), Woow_podman_emqx/ (the throwaway package
    copy, `stage`), upgrade.log, upgrade.pid, upgrade.done
  * the EMQX files of the package, written back exactly as captured by `restore-files`: ~/.config/containers/systemd/
    emqx*, ~/.config/emqx/**, ~/.local/state/woow-quadlet/emqx/**, ~/.config/systemd/user/*emqx*
  * the folders the package's own scripts made in ~/.local/share/woow-backups/emqx during the run (`cleanup`, only
    names the package uses: backup-/upgrade-/pre-restore-<date>-<time>)

Operations (request field `op`; every request names the run id):
  facts          read-only: the EMQX files (SHA-256, mode, owner, size), the Image=/HealthCmd= lines of the two
                 Quadlets, the Quadlet manifest, image refs (ID, digest, tags, `podman image exists`), the containers
                 (image ID, image name, running), the units, the HA import marker in the data volume, dev-d's own
                 package copy (tree digest, lab-source, smoke.sh SHA-256), the package backup folder, the EMQX secret
                 and volume NAMES, every image and container of the owner, the run folder; optional line deltas of
                 captured files
  capture        the run folder and exact private copies of every EMQX file (refuses an existing run folder)
  stage          the throwaway package copy from a tar (regular files only), every file checked against the host's list
  upgrade        the copy's scripts/upgrade.sh, no option, as appowner, in its own session, output to upgrade.log;
                 bounded (TERM, then KILL of its whole process group); the output comes back without dev-d's secrets
  upgrade-log    the output so far (same blanking), whether the run ended
  stop-upgrade   a still running upgrade (recorded pid and start time) is stopped: TERM, then KILL of its group
  restore-files  every EMQX file back to its captured bytes and mode, every file or folder the run added removed,
                 `systemctl --user daemon-reload`; the files read again
  ready          the broker's own healthcheck and the Dashboard entrance answer (bounded wait)
  smoke          dev-d's OWN installed package (~/Woow_podman_emqx, ea5886c) tests/smoke.sh --quick, bounded
  cleanup        the package backup folders this run added and the run folder
"""
import base64
import collections
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import urllib.error
import urllib.request

RUN_PREFIX = 'woowbk-emqx-upgrade-'
RUN_ID = re.compile(r'[0-9a-f]{12}\Z')
PACKAGE = 'Woow_podman_emqx'                       # the throwaway copy's folder name inside the run folder
INSTALLED = 'Woow_podman_emqx'                     # dev-d's own copy (deploy-batch1.sh: git archive of ea5886c)
LAB_SOURCE = 'Woow_podman_emqx.lab-source'
BACKUP_ROOT = '.local/share/woow-backups/emqx'     # the package's BACKUP_ROOT (scripts/common.sh)
BACKUP_NAME = re.compile(r'(backup|upgrade|pre-restore)-[0-9]{8}-[0-9]{6}(-[0-9]+)?\Z')   # app_new_backup_dir
STATE_DIR = '.local/state/woow-quadlet/emqx'
SCOPES = (('.config/containers/systemd', 'prefix'), ('.config/emqx', 'all'), (STATE_DIR, 'all'),
          ('.config/systemd/user', 'contains'))
QUADLET_DIR = '.config/containers/systemd'
QUADLETS = ('emqx.container', 'emqx-entrance.container')
MARKER = '/opt/emqx/data/woow-ha-import.json'
MARKER_BODY = '{"kind":"woow-ha-import","version":1,"app":"emqx"}\n'    # ha_emqx.MARKER_BODY
DEVICE_SECRETS = ('woow-emqx-dashboard-password', 'woow-emqx-node-cookie', 'woow-emqx-mqtt-password',
                  'woow-emqx-mqtt-bootstrap')
BLANK = '<dev-d-secret>'
META = ('sha256', 'mode', 'uid', 'gid', 'size')
MAX_REQUEST = 8 * 1024 * 1024
MAX_TAR = 4 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
MAX_FILES = 600
MAX_LOG = 2 * 1024 * 1024
MAX_LINES = 4000
HOME_OVERRIDE = None                               # offline tests only


def run(argv, *, timeout=120, data=None):
    """(returncode, stdout) of a fixed command; stdin is never inherited, stderr never returned."""
    proc = subprocess.run(argv, input=data, stdin=None if data is not None else subprocess.DEVNULL,
                          capture_output=True, timeout=timeout)
    return proc.returncode, proc.stdout


RUN = run                                          # replaced by the offline tests


def fixed(word):
    return ValueError('fixed-emqx-upgrade-' + word)


def home():
    return Path(HOME_OVERRIDE) if HOME_OVERRIDE else Path.home()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_nofollow(path, limit=MAX_FILE):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise fixed('not-a-file')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            data = handle.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise fixed('file-too-large')
    return data


def write_new(path, data, mode):
    """A new private file (never an existing path, never through a link)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)
    os.chmod(path, mode)


def write_over(path, data, mode):
    """Atomic replace in the same folder (a temporary file, then rename)."""
    temp = path.with_name('.' + path.name + '.woowbk-restore')
    if os.path.lexists(temp):
        os.unlink(temp)
    write_new(temp, data, mode)
    os.replace(temp, path)


def lstat_or_none(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def run_dir(q):
    run_id = str(q.get('run_id', ''))
    if not RUN_ID.fullmatch(run_id):
        raise fixed('run-id')
    return home() / (RUN_PREFIX + run_id)


def existing_run_dir(q):
    path = run_dir(q)
    st = lstat_or_none(path)
    if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise fixed('no-run-dir')
    return path


# ---------------------------------------------------------------- the EMQX files of the package

def selected(rule, name):
    return rule == 'all' or (rule == 'prefix' and name.startswith('emqx')) or (rule == 'contains' and 'emqx' in name)


def file_meta(path):
    st = os.lstat(path)
    data = read_nofollow(path)
    return {'sha256': sha(data), 'mode': stat.S_IMODE(st.st_mode), 'uid': st.st_uid, 'gid': st.st_gid, 'size': len(data)}


def _collect(base, path, files, dirs):
    st = os.lstat(path)
    rel = str(path.relative_to(base))
    if stat.S_ISLNK(st.st_mode):
        raise fixed('symlink-in-scope')
    if stat.S_ISDIR(st.st_mode):
        dirs[rel] = stat.S_IMODE(st.st_mode)
        for name in sorted(os.listdir(path)):
            _collect(base, path / name, files, dirs)
    elif stat.S_ISREG(st.st_mode):
        if len(files) >= MAX_FILES or st.st_size > MAX_FILE:
            raise fixed('scope-too-large')
        files[rel] = file_meta(path)
    else:
        raise fixed('special-file-in-scope')


def walk():
    """({relative path: meta}, {relative folder: mode}) of every EMQX file of the package under the owner's home."""
    base = home()
    files, dirs = {}, {}
    for rel, rule in SCOPES:
        root = base / rel
        st = lstat_or_none(root)
        if st is None:
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise fixed('scope-not-a-folder')
        if rule == 'all':
            dirs[rel] = stat.S_IMODE(st.st_mode)
        for name in sorted(os.listdir(root)):
            if selected(rule, name):
                _collect(base, root / name, files, dirs)
    return files, dirs


def quadlet_lines(path):
    """The Image= and HealthCmd= values of an installed Quadlet (None when absent or not exactly one)."""
    try:
        lines = read_nofollow(path).decode('utf-8', 'replace').splitlines()
    except (OSError, ValueError):
        return {'image': None, 'health': None}
    found = {}
    for key, name in (('Image=', 'image'), ('HealthCmd=', 'health')):
        values = [line[len(key):] for line in lines if line.startswith(key)]
        found[name] = values[0] if len(values) == 1 else None
    return found


def manifest():
    """The Quadlet state's manifest ({absolute path: sha256}); None without one."""
    path = home() / STATE_DIR / 'manifest'
    try:
        text = read_nofollow(path).decode('utf-8', 'replace')
    except FileNotFoundError:
        return None
    out = {}
    for line in text.splitlines():
        digest, sep, name = line.partition('  ')
        if sep and re.fullmatch(r'[0-9a-f]{64}', digest):
            out[name] = digest
    return out


def line_delta(old, new):
    left, right = collections.Counter(old.splitlines()), collections.Counter(new.splitlines())
    return {'removed': sorted((left - right).elements()), 'added': sorted((right - left).elements())}


# ---------------------------------------------------------------- podman, systemd and the broker (as appowner)

def text(data):
    return data.decode('utf-8', 'replace').strip()


def image_info(ref):
    rc, out = RUN(['podman', 'image', 'inspect', '--format', '{{.Id}}|{{.Digest}}|{{json .RepoTags}}', ref], timeout=60)
    if rc != 0:
        return {'present': False}
    parts = text(out).split('|', 2)
    if len(parts) != 3:
        return {'present': False}
    try:
        tags = json.loads(parts[2]) or []
    except ValueError:
        tags = []
    exists, _ = RUN(['podman', 'image', 'exists', ref], timeout=60)
    return {'present': True, 'id': parts[0], 'digest': parts[1], 'tags': sorted(str(t) for t in tags),
            'exists': exists == 0}


def container_info(name):
    rc, out = RUN(['podman', 'container', 'inspect', '--format', '{{.Image}}|{{.ImageName}}|{{.State.Running}}', name],
                  timeout=60)
    parts = text(out).split('|') if rc == 0 else []
    if len(parts) != 3:
        return {'present': False}
    return {'present': True, 'image_id': parts[0], 'image_name': parts[1], 'running': parts[2] == 'true'}


def unit_states(units):
    if not units:
        return {}
    rc, out = RUN(['systemctl', '--user', 'show', '--property=Id,ActiveState,SubState', '--', *units], timeout=60)
    found = {}
    for block in text(out).split('\n\n') if rc == 0 else []:
        fields = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        if fields.get('Id') in units:
            found[fields['Id']] = [fields.get('ActiveState'), fields.get('SubState')]
    return {unit: found.get(unit) for unit in units}


def names(argv, prefix):
    rc, out = RUN(argv, timeout=60)
    if rc != 0:
        return None
    return sorted(line.strip() for line in text(out).splitlines() if line.strip().startswith(prefix))


def image_list():
    rc, out = RUN(['podman', 'image', 'ls', '--all', '--format', 'json'], timeout=120)
    if rc != 0:
        return None
    try:
        rows = json.loads(out or b'[]')
    except ValueError:
        return None
    return sorted([str(row.get('Id')), sorted(str(n) for n in row.get('Names') or []), str(row.get('Digest'))]
                  for row in rows if isinstance(row, dict))


def marker():
    """{'present': True|False|None, 'exact': ...} of the HA import marker in the running broker's data volume."""
    rc, _ = RUN(['podman', 'exec', 'woow-emqx', 'test', '-e', MARKER], timeout=60)
    if rc == 1:
        return {'present': False, 'exact': False}
    if rc != 0:
        return {'present': None, 'exact': False}
    rc, out = RUN(['podman', 'exec', 'woow-emqx', 'cat', MARKER], timeout=60)
    return {'present': True, 'exact': rc == 0 and out == MARKER_BODY.encode()}


def tree(path):
    """{files, digest, smoke_sha256} of a package folder (no link, no special file)."""
    st = lstat_or_none(path)
    if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return None
    entries = []
    for root, dirs, files in os.walk(path, followlinks=False):
        dirs.sort()
        for name in dirs:
            if os.path.islink(os.path.join(root, name)):
                raise fixed('symlink-in-package')
        for name in sorted(files):
            item = Path(root) / name
            st = os.lstat(item)
            if not stat.S_ISREG(st.st_mode):
                raise fixed('special-file-in-package')
            entries.append('%s\0%s\0%o' % (item.relative_to(path), sha(read_nofollow(item)), stat.S_IMODE(st.st_mode)))
    smoke = path / 'tests' / 'smoke.sh'
    return {'files': len(entries), 'digest': sha('\n'.join(sorted(entries)).encode()),
            'smoke_sha256': sha(read_nofollow(smoke)) if smoke.is_file() and not smoke.is_symlink() else None}


def listing(root):
    """[[name, kind]] of a folder's entries; None when the folder does not exist."""
    st = lstat_or_none(root)
    if st is None:
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise fixed('backup-folder-not-a-folder')
    out = []
    for name in sorted(os.listdir(root)):
        mode = os.lstat(root / name).st_mode
        out.append([name, 'link' if stat.S_ISLNK(mode) else 'dir' if stat.S_ISDIR(mode) else
                    'file' if stat.S_ISREG(mode) else 'other'])
    return out


def backup_root():
    return listing(home() / BACKUP_ROOT)


def backup_parent():
    return listing((home() / BACKUP_ROOT).parent)


def run_state(q):
    path = run_dir(q)
    st = lstat_or_none(path)
    if st is None:
        return {'exists': False}
    return {'exists': True, 'capture': (path / 'capture.json').is_file(), 'staged': (path / PACKAGE).is_dir(),
            'upgrade_started': os.path.lexists(path / 'upgrade.pid'),
            'upgrade_done': os.path.lexists(path / 'upgrade.done')}


def facts(q):
    files, dirs = walk()
    quadlets = home() / QUADLET_DIR
    out = {'files': files, 'dirs': dirs, 'manifest': manifest(),
           'quadlet': {name: quadlet_lines(quadlets / name) for name in QUADLETS},
           'images': {ref: image_info(ref) for ref in q.get('refs') or []},
           'containers': {name: container_info(name) for name in q.get('containers') or []},
           'units': unit_states(list(q.get('units') or [])),
           'marker': marker(), 'package': tree(home() / INSTALLED), 'backup_root': backup_root(),
           'backup_parent': backup_parent(),
           'secrets': names(['podman', 'secret', 'ls', '--format', '{{.Name}}'], 'woow-emqx-'),
           'volumes': names(['podman', 'volume', 'ls', '--format', '{{.Name}}'], 'woow_emqx_'),
           'container_names': names(['podman', 'ps', '-a', '--format', '{{.Names}}'], ''),
           'image_list': image_list(), 'run': run_state(q)}
    try:
        out['lab_source'] = text(read_nofollow(home() / LAB_SOURCE))
    except (OSError, ValueError):
        out['lab_source'] = None
    deltas = q.get('deltas') or []
    if deltas:
        record = json.loads(read_nofollow(existing_run_dir(q) / 'capture.json'))
        out['deltas'] = {}
        for rel in deltas:
            item = record['files'].get(rel)
            if item is None or rel not in files:
                out['deltas'][rel] = None
                continue
            old = read_nofollow(run_dir(q) / 'capture' / item['copy']).decode('utf-8', 'replace')
            new = read_nofollow(home() / rel).decode('utf-8', 'replace')
            out['deltas'][rel] = line_delta(old, new)
    return out


# ---------------------------------------------------------------- capture, stage, restore

def capture(q):
    path = run_dir(q)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        raise fixed('run-dir-exists') from None
    os.chmod(path, 0o700)
    os.mkdir(path / 'capture', 0o700)
    files, dirs = walk()
    record = {}
    for number, (rel, meta) in enumerate(sorted(files.items())):
        data = read_nofollow(home() / rel)
        if sha(data) != meta['sha256']:
            raise fixed('changed-while-copied')
        write_new(path / 'capture' / str(number), data, 0o600)
        record[rel] = dict(meta, copy=str(number))
    write_new(path / 'capture.json', json.dumps({'files': record, 'dirs': dirs}, sort_keys=True).encode(), 0o600)
    return {'files': files, 'dirs': dirs}


def _member_path(name):
    parts = PurePosixPath(name).parts
    if not parts or name.startswith('/') or any(part in ('', '.', '..') for part in parts) or len(parts) > 12:
        raise fixed('stage-member-name')
    return Path(*parts)


def stage(q):
    path = existing_run_dir(q)
    dest = path / PACKAGE
    if os.path.lexists(dest):
        raise fixed('stage-exists')
    raw = base64.b64decode(q.get('tar_b64') or '', validate=True)
    expected = q.get('files')
    if len(raw) > MAX_TAR or not isinstance(expected, dict) or not 0 < len(expected) <= MAX_FILES:
        raise fixed('stage-request')
    os.mkdir(dest, 0o700)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            if not member.isfile() or member.size > MAX_FILE:
                raise fixed('stage-member-type')
            rel = _member_path(member.name)
            target = dest / rel
            for parent in reversed(target.parents):
                if parent == dest or dest not in parent.parents:
                    continue
                if not os.path.lexists(parent):
                    os.mkdir(parent, 0o755)
                elif os.path.islink(parent) or not parent.is_dir():
                    raise fixed('stage-parent')
            write_new(target, archive.extractfile(member).read(), 0o755 if member.mode & 0o111 else 0o644)
    got = {}
    for root, _dirs, files in os.walk(dest, followlinks=False):
        for name in files:
            item = Path(root) / name
            got[str(item.relative_to(dest))] = [sha(read_nofollow(item)), bool(os.lstat(item).st_mode & 0o111)]
    differ = sorted(rel for rel in set(got) | set(expected) if got.get(rel) != expected.get(rel))
    return {'files': len(got), 'equal': not differ, 'differ': differ[:20]}


def restore_files(q):
    path = existing_run_dir(q)
    record = json.loads(read_nofollow(path / 'capture.json'))
    files, dirs = record['files'], record['dirs']
    base = home()
    now_files, now_dirs = walk()
    removed, written = [], []
    for rel in sorted(set(now_files) - set(files)):
        os.unlink(base / rel)
        removed.append(rel)
    for rel in sorted(set(now_dirs) - set(dirs), key=lambda item: -item.count('/')):
        shutil.rmtree(base / rel)            # (walk() saw no link in it)
        removed.append(rel + '/')
    for rel, mode in sorted(dirs.items(), key=lambda item: item[0].count('/')):
        target = base / rel
        if not os.path.lexists(target):
            os.makedirs(target, mode)
        os.chmod(target, mode)
    for rel, meta in sorted(files.items()):
        current = now_files.get(rel)
        if current and all(current[key] == meta[key] for key in ('sha256', 'mode')):
            continue
        data = read_nofollow(path / 'capture' / meta['copy'])
        if sha(data) != meta['sha256']:
            raise fixed('capture-damaged')
        write_over(base / rel, data, meta['mode'])
        written.append(rel)
    reload_rc, _ = RUN(['systemctl', '--user', 'daemon-reload'], timeout=180)
    after_files, after_dirs = walk()
    expected = {rel: {key: meta[key] for key in META} for rel, meta in files.items()}
    return {'written': written, 'removed': removed, 'reload_rc': reload_rc,
            'equal': after_files == expected and after_dirs == dirs, 'files': after_files, 'dirs': after_dirs}


# ---------------------------------------------------------------- the package's own scripts

def device_secret_values():
    values = []
    for name in DEVICE_SECRETS:
        rc, out = RUN(['podman', 'secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', name], timeout=60)
        value = out.decode('utf-8', 'replace').rstrip('\n') if rc == 0 else ''
        if len(value) >= 6:
            values.append(value)
    return sorted(set(values), key=len, reverse=True)


def blank(data, values):
    """(lines, hits, truncated): the output as text without any dev-d secret value."""
    truncated = len(data) > MAX_LOG
    content = data[:MAX_LOG].decode('utf-8', 'replace')
    hits = sum(content.count(value) for value in values)
    for value in values:
        content = content.replace(value, BLANK)
    lines = content.splitlines()
    return lines[:MAX_LINES], hits, truncated or len(lines) > MAX_LINES


def start_ticks(pid):
    """Field 22 of /proc/<pid>/stat (start time), None when the process is gone."""
    try:
        raw = Path('/proc/%d/stat' % pid).read_text()
    except OSError:
        return None
    fields = raw[raw.rindex(')') + 2:].split()
    return fields[19] if len(fields) > 19 and fields[0] != 'Z' else None


def alive(pid, ticks):
    return ticks is not None and start_ticks(pid) == ticks


def stop_group(pid, ticks, wait=None):
    """TERM to the whole process group (its leader is the recorded pid; the package's traps release its lock), up to
    30 s for the leader to end, then KILL to whatever of the group is left. `wait`: the leader is our own child."""
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if wait is not None:
            try:
                wait(1)
                break
            except subprocess.TimeoutExpired:
                continue
        if not alive(pid, ticks):
            break
        time.sleep(1)
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    if wait is not None:
        try:
            wait(15)
        except subprocess.TimeoutExpired:
            pass


def bounded(value, low, high):
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise fixed('bound')
    return value


def upgrade(q):
    path = existing_run_dir(q)
    script = path / PACKAGE / 'scripts' / 'upgrade.sh'
    st = lstat_or_none(script)
    if st is None or not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o100:
        raise fixed('no-staged-upgrade')
    if os.path.lexists(path / 'upgrade.pid'):
        raise fixed('upgrade-already-started')
    timeout = bounded(q.get('timeout'), 60, 3600)
    log = os.open(path / 'upgrade.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    started = time.monotonic()
    try:
        proc = subprocess.Popen([str(script)], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                cwd=str(home()), start_new_session=True)
    finally:
        os.close(log)
    ticks = start_ticks(proc.pid)
    write_new(path / 'upgrade.pid', ('%d %s\n' % (proc.pid, ticks)).encode(), 0o600)
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        stop_group(proc.pid, ticks, wait=lambda seconds: proc.wait(timeout=seconds))
        if proc.poll() is None:
            proc.wait()
    write_new(path / 'upgrade.done', str(proc.returncode).encode(), 0o600)
    lines, hits, truncated = blank(read_nofollow(path / 'upgrade.log', 64 * MAX_LOG), device_secret_values())
    return {'rc': proc.returncode, 'timed_out': timed_out, 'seconds': round(time.monotonic() - started, 1),
            'lines': lines, 'device_secret_hits': hits, 'truncated': truncated}


def upgrade_log(q):
    path = existing_run_dir(q)
    if not os.path.lexists(path / 'upgrade.log'):
        return {'started': False}
    lines, hits, truncated = blank(read_nofollow(path / 'upgrade.log', 64 * MAX_LOG), device_secret_values())
    done = path / 'upgrade.done'
    return {'started': True, 'done': os.path.lexists(done),
            'rc': int(read_nofollow(done)) if os.path.lexists(done) else None,
            'lines': lines, 'device_secret_hits': hits, 'truncated': truncated}


def recorded(path):
    try:
        pid, ticks = read_nofollow(path / 'upgrade.pid').decode().split()
        return int(pid), ticks
    except (OSError, ValueError):
        return None, None


def stop_upgrade(q):
    path = run_dir(q)
    if not os.path.lexists(path / 'upgrade.pid'):
        return {'started': False, 'running': False, 'was_running': False}
    if os.path.lexists(path / 'upgrade.done'):
        return {'started': True, 'running': False, 'was_running': False}
    pid, ticks = recorded(path)
    if pid is None:
        raise fixed('pid-record-unreadable')
    was = alive(pid, ticks)
    if was:
        stop_group(pid, ticks)
    return {'started': True, 'running': alive(pid, ticks), 'was_running': was}


def dashboard_url():
    port = '18083'
    try:
        for line in read_nofollow(home() / '.config/emqx/emqx.env').decode('utf-8', 'replace').splitlines():
            if line.startswith('WOOW_EMQX_PORT_DASHBOARD=') and re.fullmatch(r'[0-9]{1,5}', line.split('=', 1)[1]):
                port = line.split('=', 1)[1]
    except (OSError, ValueError):
        pass
    return 'http://127.0.0.1:%s/' % port


def http_code(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (urllib.error.URLError, OSError, ValueError):
        return 0


def ready(q):
    """The broker's own healthcheck passes, the entrance serves the Dashboard (200) and the API routes exist: an
    unauthenticated GET /api/v5/nodes answers 401 (a starting Dashboard answers 404 first; a login is never retried by the
    probes, emqx_product_real_ha attempt-05)."""
    timeout = bounded(q.get('timeout'), 10, 1800)
    started = time.monotonic()
    url = dashboard_url()
    while True:
        health, _ = RUN(['podman', 'healthcheck', 'run', 'woow-emqx'], timeout=60)
        code, api = http_code(url), http_code(url + 'api/v5/nodes')
        if health == 0 and code == 200 and api == 401:
            return {'ready': True, 'seconds': round(time.monotonic() - started, 1)}
        if time.monotonic() - started > timeout:
            return {'ready': False, 'seconds': round(time.monotonic() - started, 1), 'health_rc': health, 'code': code,
                    'api': api}
        time.sleep(3)


def smoke(q):
    """dev-d's own installed package's tests/smoke.sh --quick (the only script and the only option)."""
    script = home() / INSTALLED / 'tests' / 'smoke.sh'
    st = lstat_or_none(script)
    if st is None or not stat.S_ISREG(st.st_mode):
        raise fixed('no-installed-smoke')
    timeout = bounded(q.get('timeout'), 60, 1800)
    proc = subprocess.Popen(['bash', str(script), '--quick'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, cwd=str(home()), start_new_session=True)
    timed_out = False
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        stop_group(proc.pid, start_ticks(proc.pid), wait=lambda seconds: proc.wait(timeout=seconds))
        out, _ = proc.communicate()
    lines, hits, truncated = blank(out, device_secret_values())
    return {'rc': proc.returncode, 'timed_out': timed_out, 'lines': lines, 'device_secret_hits': hits,
            'truncated': truncated}


def cleanup(q):
    """The package's folders this run added (None before = the folder did not exist: it goes too once empty), then the
    run folder. Anything else that is new is only named (`unexplained`)."""
    before, parent_before = q.get('backup_root_before'), q.get('backup_parent_before')
    if not all(value is None or isinstance(value, list) for value in (before, parent_before)):
        raise fixed('cleanup-request')
    known = {row[0] for row in before or [] if isinstance(row, list) and row}
    root = home() / BACKUP_ROOT
    removed, unexplained = [], []
    if lstat_or_none(root) is not None:
        for name, kind in backup_root():
            if name in known:
                continue
            item = root / name
            if BACKUP_NAME.fullmatch(name) and kind == 'dir' and os.lstat(item).st_uid == os.getuid():
                shutil.rmtree(item)
                removed.append(name)
            else:
                unexplained.append(name)
        if before is None and not unexplained and not os.listdir(root):
            os.rmdir(root)
            removed.append(root.name + '/')
    parent = root.parent
    if parent_before is None and lstat_or_none(parent) is not None and not os.listdir(parent):
        os.rmdir(parent)
        removed.append(parent.name + '/')
    path = run_dir(q)
    if q.get('remove_run_dir') is True and lstat_or_none(path) is not None:
        existing_run_dir(q)
        if os.path.lexists(path / 'upgrade.pid') and not os.path.lexists(path / 'upgrade.done'):
            pid, ticks = recorded(path)
            if pid is None or alive(pid, ticks):
                raise fixed('upgrade-still-running')
        shutil.rmtree(path)
    return {'removed': removed, 'unexplained': unexplained, 'run_dir_removed': lstat_or_none(path) is None,
            'backup_root': backup_root(), 'backup_parent': backup_parent()}


OPS = {'facts': facts, 'capture': capture, 'stage': stage, 'upgrade': upgrade, 'upgrade-log': upgrade_log,
       'stop-upgrade': stop_upgrade, 'restore-files': restore_files, 'ready': ready, 'smoke': smoke, 'cleanup': cleanup}


def dispatch(q):
    if not isinstance(q, dict) or q.get('op') not in OPS:
        raise fixed('operation')
    if os.geteuid() == 0:
        raise fixed('owner-only')
    run_dir(q)
    return OPS[q['op']](q)


ENTRY = r'''
import json as _json, sys as _sys
_q = {}
try:
    _raw = _sys.stdin.buffer.read(MAX_REQUEST + 1)
    if len(_raw) > MAX_REQUEST:
        raise fixed('request-too-large')
    _q = _json.loads(_raw or b'{}')
    print(_json.dumps({'ok': True, 'result': dispatch(_q)}))
except Exception as _e:
    _code = str(_e) if isinstance(_e, ValueError) and str(_e).startswith('fixed-emqx-upgrade-') else None
    print(_json.dumps({'ok': False, 'op': _q.get('op') if isinstance(_q, dict) else None,
                       'error_class': type(_e).__name__, 'fixed_code': _code}))
    raise SystemExit(1)
'''
