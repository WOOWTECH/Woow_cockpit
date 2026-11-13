"""Canonical listing of a host directory (woowbk-dirs backup/restore test fixture; stdlib only).

One implementation for every view of a data directory, so they can be compared byte for byte:
* the app (GET /api/tree, /api/summary) lists its bind mount from inside the container;
* tools/check.py and the lab driver tests/e2e/lab/dirs_e2e.py run this file inside the owner's user
  namespace (`podman unshare python3 -I - <dir>`), which shows the same ids as the container, also
  while the app is stopped or masked by an unfinished restore.

listing(root) walks `root` without following symlinks (children sorted by name, depth first) and
returns one dict per entry, the root itself first as ".":
  path    relative POSIX path ("." for the root); undecodable bytes as backslash escapes
  type    dir | file | symlink | fifo | other
  mode    permission bits incl. setuid/setgid/sticky, 4-digit octal string
  uid/gid numeric owner as seen in the current user namespace (container ids)
  size, sha256, mtime (whole seconds): regular files
  target  symlinks: readlink(), never followed
  xattrs  {name: sha256(value)} of user.* attributes (files and directories, where supported)
  link    second and later names of a hard-linked inode: the first name in walk order
Volatile names are skipped: app temporaries ('.healthz-*', '.tmp-*') and SQLite's '-wal', '-shm' and
'-journal' companions (their bytes change on every open). A SQLite main file ('*.sqlite') keeps only
type, mode and owner: the app compares its content through SQL. Directory mtimes are not recorded
(every create or remove inside changes them).

    python3 -I treelist.py <dir>         prints {"root", "count", "digest", "entries"} as JSON
"""
import errno
import hashlib
import json
import os
import stat
import sys

VOLATILE_PREFIXES = ('.healthz-', '.tmp-')
VOLATILE_SUFFIXES = ('-wal', '-shm', '-journal')
SQLITE_SUFFIX = '.sqlite'
XATTR_PREFIX = 'user.'
NO_XATTR = (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EPERM, errno.EACCES, errno.ENODATA)


def volatile(name):
    return name.startswith(VOLATILE_PREFIXES) or name.endswith(VOLATILE_SUFFIXES)


def _text(raw):
    return os.fsencode(raw).decode('utf-8', 'backslashreplace')


def _kind(mode):
    if stat.S_ISDIR(mode):
        return 'dir'
    if stat.S_ISREG(mode):
        return 'file'
    if stat.S_ISLNK(mode):
        return 'symlink'
    if stat.S_ISFIFO(mode):
        return 'fifo'
    return 'other'


def _sha256(path):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _xattrs(path):
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        if error.errno in NO_XATTR:
            return {}
        raise
    result = {}
    for name in sorted(n for n in names if n.startswith(XATTR_PREFIX)):
        try:
            value = os.getxattr(path, name, follow_symlinks=False)
        except OSError as error:
            if error.errno in NO_XATTR:
                continue
            raise
        result[name] = hashlib.sha256(value).hexdigest()
    return result


def _entry(path, rel, st, inodes):
    kind = _kind(st.st_mode)
    item = {'path': rel, 'type': kind, 'mode': '%04o' % stat.S_IMODE(st.st_mode), 'uid': st.st_uid, 'gid': st.st_gid}
    if kind == 'file':
        if not rel.endswith(SQLITE_SUFFIX):
            item['size'] = st.st_size
            item['mtime'] = int(st.st_mtime)
            try:
                item['sha256'] = _sha256(path)
            except OSError as error:
                item['sha256'] = None
                item['error'] = errno.errorcode.get(error.errno, str(error.errno))
    elif kind == 'symlink':
        item['target'] = _text(os.readlink(path))
    if kind in ('file', 'dir'):
        xattrs = _xattrs(path)
        if xattrs:
            item['xattrs'] = xattrs
    if kind != 'dir' and st.st_nlink > 1:
        key = (st.st_dev, st.st_ino)
        first = inodes.setdefault(key, rel)
        if first != rel:
            item['link'] = first
    return item


def listing(root):
    """Entries of `root` (see the module docstring); raises OSError when `root` is not a readable directory."""
    root = os.fspath(root)
    st = os.lstat(root)
    if not stat.S_ISDIR(st.st_mode):
        raise NotADirectoryError(errno.ENOTDIR, 'not a directory', root)
    inodes = {}
    entries = [_entry(root, '.', st, inodes)]

    def walk(path, prefix):
        with os.scandir(path) as handle:
            children = sorted(handle, key=lambda e: os.fsencode(e.name))
        for child in children:
            if volatile(child.name):
                continue
            rel = _text(child.name) if not prefix else prefix + '/' + _text(child.name)
            cst = os.lstat(child.path)
            entries.append(_entry(child.path, rel, cst, inodes))
            if stat.S_ISDIR(cst.st_mode):
                walk(child.path, rel)

    walk(root, '')
    return entries


def canonical(entries):
    """Bytes the digest is taken over: compact JSON, sorted keys, ASCII only (stable for any file name)."""
    return json.dumps(entries, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def digest(entries):
    return hashlib.sha256(canonical(entries)).hexdigest()


def report(root):
    entries = listing(root)
    return {'root': _text(os.fspath(root)), 'count': len(entries), 'digest': digest(entries), 'entries': entries}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: treelist.py <dir>')
    print(json.dumps(report(sys.argv[1]), ensure_ascii=False))
