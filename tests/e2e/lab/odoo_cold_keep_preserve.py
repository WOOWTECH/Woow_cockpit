"""Odoo cold keep: older Odoo safety backups kept out of the product's view while the run's restores could prune them,
then put back byte for byte. Importing this file performs no I/O.

The product keeps the 3 newest safety backups per app after every successful restore (flows.prune_safety; a kept
whole-cluster copy holds a keeper slot and is never deleted). An Odoo import plus the restore of the run's own baseline
add three (two safety backups and the kept copy), so every older Odoo safety backup would be deleted -- also one that
another case protects (N8-01 lists 20261124T152230Z-5f41c20c, odoo+n8n, under preserved_old_safeties). N8-01 copied
such backups privately and wrote them back after its own restores had pruned them (focus_n8n_instance_acceptance_
safeties). Here the same backups are taken out of the product's view BEFORE the first restore and returned after the
last one, so nothing prunes them at all; the N8-01 device primitives are reused as they are: the engine's own locks
(safeties.native_locks: jobs.lock and engine.lock, so no job runs or starts meanwhile) and the bounded regular-file read
and the atomic, fsynced state write (ops.read_regular, ops.atomic). The controller (odoo_cold_keep_flow.py) sends this
file together with those two committed modules to device Python as root (device_program), never installs anything.

  preserve  each named backup: its archive <id>.tar and its sidecar <id>.json read (regular, one link, root 0600, no
            format-1 twin, the sidecar a safety record of Odoo that is no kept copy and names the archive's SHA-256, the
            archive's SHA-256 the one the controller listed); the record (SHA-256, size, mode, owner, mtime, inode)
            written to <parent>/<case>/state.json BEFORE anything moves; then each file moved into <parent>/<case>/ by
            link + unlink (a name is never replaced; the same inode, so bytes, mode, owner and mtime stay), the archive
            first (the backup leaves the listing at once; a sidecar without its archive is never listed or adopted)
  put_back  every file checked against the record, then linked back under its own name, the sidecar first (an archive
            without its sidecar is never left behind); a name held by any other file refuses; an interrupted move (both
            names, one inode) is completed; once all are back and verified the private folder is removed
  where     read-only: where each recorded file is (for the controller's receipt when a return cannot be proven)
"""
import contextlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ARCHIVES = '/var/lib/woowtech-backup/archives'
PARENT = '/var/lib/woowtech-backup/focus-odoo-cold-keep-preserved'
CASE = re.compile(r'odoo-ck-[0-9]{8}T[0-9]{6}\Z')          # one run's private folder: odoo-ck-<evidence stamp>
BACKUP = re.compile(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
MAX_IDS = 5
ARCHIVE_BYTES = 64 * 1024 ** 2   # read bound per archive (the one on dev-c: 12,103,680 bytes)
SIDECAR_BYTES = 256 * 1024       # storage.MAX_SIDECAR
KEPT_PREFIX = '保留的複本：'       # kept.NOTE_PREFIX: a kept copy is never pruned, so never moved here
META = ('sha256', 'bytes', 'mode', 'uid', 'gid', 'mtime_ns')
LOCK_ATTEMPTS = 30               # a helper command may hold jobs.lock for a moment


def names_out(bid):
    return [bid + '.tar', bid + '.json']


def names_back(bid):
    return [bid + '.json', bid + '.tar']


def check_request(case, ids, expect=None):
    if not isinstance(case, str) or not CASE.fullmatch(case):
        raise ValueError('case')
    if (not isinstance(ids, list) or not 1 <= len(ids) <= MAX_IDS or len(set(ids)) != len(ids)
            or not all(isinstance(bid, str) and BACKUP.fullmatch(bid) for bid in ids)):
        raise ValueError('backup ids')
    if expect is not None and (not isinstance(expect, dict) or sorted(expect) != sorted(ids)
                               or not all(isinstance(v, str) and SHA.fullmatch(v) for v in expect.values())):
        raise ValueError('expected archive digests')


def held(locks, attempts=LOCK_ATTEMPTS, pause=1.0):
    """The engine's own locks (no job runs or starts while they are held); a short wait while a command holds one."""
    for attempt in range(attempts):
        stack = contextlib.ExitStack()
        try:
            stack.enter_context(locks())
            return stack
        except BlockingIOError:
            stack.close()
            if attempt + 1 == attempts:
                raise
            time.sleep(pause)
    raise BlockingIOError('engine locks')


def folder_of(parent, case, *, create=False):
    """<parent>/<case>, 0700 and owned by this user at both levels; created exclusively (never an earlier run's)."""
    parent = Path(parent)
    if create:
        parent.mkdir(mode=0o700, exist_ok=True)
    folder = parent / case
    if create:
        folder.mkdir(mode=0o700)
    for path in (parent, folder):
        st = path.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise ValueError('unsafe private folder')
    return folder


def describe(c, path, limit):
    """(bytes, {sha256, bytes, mode, uid, gid, mtime_ns, dev, ino}) of one regular, single-link file (ops.read_regular)."""
    data, meta = c.read_regular(path, limit)
    st = os.lstat(path)
    return data, dict(meta, bytes=len(data), dev=st.st_dev, ino=st.st_ino)


def limit_of(name):
    return SIDECAR_BYTES if name.endswith('.json') else ARCHIVE_BYTES


def fsync_dir(path):
    fd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def move(src, dst):
    """Link, then unlink: never replaces a name (FileExistsError), keeps the inode (bytes, mode, owner, mtime)."""
    os.link(src, dst, follow_symlinks=False)
    fsync_dir(dst.parent)
    os.unlink(src)
    fsync_dir(src.parent)


def save(c, folder, record):
    c.atomic(folder / 'state.json', json.dumps(record, sort_keys=True).encode(), uid=os.geteuid(), gid=os.getegid())


def verify(c, record, folder, archives, where):
    """Every recorded file is in `where` ('private' or 'archives') with its recorded bytes and attributes and inode, and
    its other name is free."""
    for name, meta in record['files'].items():
        here, other = (folder / name, archives / name) if where == 'private' else (archives / name, folder / name)
        _, now = describe(c, here, limit_of(name))
        if any(now[key] != meta[key] for key in (*META, 'dev', 'ino')) or os.path.lexists(other):
            raise ValueError('preserved file differs from its record')


def summary(record):
    """What the controller records (no content): per file its digest and attributes."""
    return {'case': record['case'], 'ids': list(record['ids']), 'phase': record['phase'],
            'files': {name: {key: meta[key] for key in META} for name, meta in sorted(record['files'].items())}}


def preserve(c, locks, case, ids, expect, *, archives=ARCHIVES, parent=PARENT):
    check_request(case, ids, expect)
    archives = Path(archives)
    with held(locks):
        record = {'case': case, 'ids': list(ids), 'files': {}, 'phase': 'recorded'}
        for bid in ids:
            if os.path.lexists(archives / (bid + '.woowbackup')):
                raise ValueError('a format-1 twin makes the archive ambiguous')
            _data, archive = describe(c, archives / (bid + '.tar'), ARCHIVE_BYTES)
            raw, sidecar = describe(c, archives / (bid + '.json'), SIDECAR_BYTES)
            meta = json.loads(raw)
            apps = {a.get('id') for a in meta.get('apps') or [] if isinstance(a, dict)}
            if (meta.get('id') != bid or meta.get('type') != 'safety' or 'odoo' not in apps
                    or str(meta.get('note') or '').startswith(KEPT_PREFIX) or meta.get('sha256') != archive['sha256']
                    or archive['sha256'] != expect[bid]):
                raise ValueError('not the listed older Odoo safety backup of this archive')
            if any(m['mode'] != 0o600 or m['uid'] != os.geteuid() for m in (archive, sidecar)):
                raise ValueError('unexpected archive owner or mode')
            record['files'][bid + '.tar'], record['files'][bid + '.json'] = archive, sidecar
        folder = folder_of(parent, case, create=True)
        save(c, folder, record)                       # the record is durable before anything moves
        for bid in ids:
            for name in names_out(bid):
                move(archives / name, folder / name)
        verify(c, record, folder, archives, 'private')
        record['phase'] = 'moved'
        save(c, folder, record)
    return summary(record)


def put_back(c, locks, case, ids, *, archives=ARCHIVES, parent=PARENT):
    check_request(case, ids)
    archives = Path(archives)
    with held(locks):
        folder = Path(parent) / case
        if not os.path.lexists(folder):
            return {'case': case, 'ids': list(ids), 'phase': 'none-moved', 'files': {}, 'restored_files': 0}
        folder = folder_of(parent, case)
        if not (folder / 'state.json').exists():   # stopped before the record: nothing was moved
            if any(folder.iterdir()):
                raise ValueError('unknown contents in the private folder')
            folder.rmdir()
            return {'case': case, 'ids': list(ids), 'phase': 'none-moved', 'files': {}, 'restored_files': 0}
        record = json.loads(c.read_regular(folder / 'state.json', SIDECAR_BYTES)[0])
        if record.get('case') != case or record.get('ids') != list(ids):
            raise ValueError('the private folder records another run')
        record['phase'] = 'returning'
        save(c, folder, record)
        restored = 0
        for bid in ids:
            for name in names_back(bid):
                meta, home, kept = record['files'][name], archives / name, folder / name
                if os.path.lexists(home):
                    st = os.lstat(home)
                    if (st.st_dev, st.st_ino) != (meta['dev'], meta['ino']):
                        raise ValueError('another file holds the name')
                    if os.path.lexists(kept):           # a move interrupted between its link and its unlink
                        os.unlink(kept)
                        fsync_dir(folder)
                    continue
                if not os.path.lexists(kept):
                    raise ValueError('a preserved file is missing')
                _, now = describe(c, kept, limit_of(name))
                if any(now[key] != meta[key] for key in META):
                    raise ValueError('a preserved file changed')
                move(kept, home)
                restored += 1
        verify(c, record, folder, archives, 'archives')
        record['phase'] = 'returned'
        save(c, folder, record)
        left = sorted(p.name for p in folder.iterdir())
        if left != ['state.json']:
            raise ValueError('unknown contents in the private folder')
        os.unlink(folder / 'state.json')
        folder.rmdir()
        fsync_dir(folder.parent)
        with contextlib.suppress(OSError):   # the parent too, once no run's folder is left in it
            folder.parent.rmdir()
    return dict(summary(record), restored_files=restored)


def where(case, ids, *, archives=ARCHIVES, parent=PARENT):
    """Read-only: per file whether it is under its own name and in the private folder (no content, no lock)."""
    check_request(case, ids)
    folder = Path(parent) / case
    return {'case': case, 'folder': folder.is_dir(), 'record': (folder / 'state.json').is_file(),
            'files': {name: {'archives': os.path.lexists(Path(archives) / name), 'private': os.path.lexists(folder / name)}
                      for bid in ids for name in names_out(bid)}}


def dispatch(q, c, locks, **paths):
    if q.get('op') == 'preserve':
        return preserve(c, locks, q.get('case'), q.get('ids'), q.get('expect'), **paths)
    if q.get('op') == 'put_back':
        return put_back(c, locks, q.get('case'), q.get('ids'), **paths)
    if q.get('op') == 'where':
        return where(q.get('case'), q.get('ids'), **paths)
    raise ValueError('operation')


def main():
    """The device program's entry (device_program): root only, the reused N8-01 modules already loaded."""
    if os.geteuid() != 0:
        raise SystemExit('device root required')
    try:
        request = json.loads(sys.stdin.buffer.read(64 * 1024))
        result = dispatch(request, sys.modules['focus_n8n_instance_acceptance_ops'],
                          sys.modules['focus_n8n_instance_acceptance_safeties'].native_locks)
    except Exception as error:   # noqa: BLE001 - only the class leaves the device
        print(json.dumps({'error_class': type(error).__name__}), file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result))


def device_program(here):
    """The fixed device program: the two committed N8-01 modules and this one, loaded from memory (as the N8-01
    controller loads its own), then main(). Nothing is written to the device; argv stays far below 128 KiB."""
    parts = [(name, (Path(here) / f'{name}.py').read_text(encoding='utf-8'))
             for name in ('focus_n8n_instance_acceptance_ops', 'focus_n8n_instance_acceptance_safeties',
                          'odoo_cold_keep_preserve')]
    lines = ['import sys, types', 'sys.dont_write_bytecode = True',
             'def _module(name, source):',
             '    m = types.ModuleType(name); sys.modules[name] = m',
             "    exec(compile(source, '<fixed ' + name + '>', 'exec'), m.__dict__)", '    return m']
    lines += [f'_m = _module({name!r}, {source!r})' for name, source in parts]
    lines.append('_m.main()')
    return '\n'.join(lines) + '\n'
