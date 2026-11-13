"""Run commands as an application owner (rootless Podman + user systemd). Owner: E2.

Root never opens paths inside the owner's home: file I/O there is executed as the owner.

Every owner command is `runuser -u <owner> -- env -i <fixed environment> <fixed argv>` with the
owner's home as working directory. File access inside the home goes through FILE_HELPER, a fixed
Python snippet run as the owner that walks every path component with O_NOFOLLOW and moves data
over stdin/stdout only. Host directories (files of the owner's subordinate ids) go through DIR_HELPER, run
the same way but inside the owner's user namespace (`podman unshare`). Secrets and keys never appear in argv
or in the environment.
"""
import json
import os
import pwd
import re
import select
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass

from .errors import BackupError

RUNUSER = '/usr/sbin/runuser'
ENV = '/usr/bin/env'
PODMAN = '/usr/bin/podman'
SYSTEMCTL = '/usr/bin/systemctl'
PYTHON = '/usr/bin/python3'
SAFE_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
ROOT_ENV = {'PATH': SAFE_PATH, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
OWNER_RE = re.compile(r'[a-z_][a-z0-9_-]{0,31}\Z')
REL_SEGMENT_RE = re.compile(r'[A-Za-z0-9._@+-]{1,255}\Z')
DEVNULL = subprocess.DEVNULL
MAX_FILE_BYTES = 16 * 1024 * 1024
# Captured stdout is held in the root helper's memory: never more than this unless a caller asks for
# less (a hostile container can make psql, pg_isready or podman print gigabytes). stderr keeps a tail.
MAX_CAPTURE = MAX_FILE_BYTES + 64 * 1024
STDERR_TAIL = 64 * 1024
READ_CHUNK = 1024 * 1024
SMALL_JSON = 1024 * 1024          # stdout of the directory helper's small operations
SHORT_TIMEOUT = 60
# Sibling tokens: a job id (`j<stamp>-<hex>`), optionally with `-rollback`.
TOKEN_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')

# Exit codes of FILE_HELPER, mapped to BackupError codes by OwnerRunner.
HELPER_ERRORS = {3: 'not-found', 4: 'not-regular', 5: 'too-large', 6: 'bad-path', 7: 'bad-mode', 8: 'bad-command'}

# Executed as the owner with `python3 -I -c`. Operations:
#   read <rel> <max>          file bytes -> stdout
#   write <rel> <mode> <max>  stdin -> temp file (O_EXCL|O_NOFOLLOW) -> fchmod -> fsync -> rename
#   remove <rel>              unlink a non-directory ("removed"/"absent" on stdout)
#   stat <rel>...             JSON list of {path,type,size,mode}
#   relay /usr/bin/podman ... run podman with an owner-created stdout pipe and copy it to our stdout
#                             (podman volume export reopens /dev/stdout, which fails on root-owned fds)
FILE_HELPER = r'''
import errno, json, os, stat, subprocess, sys
CODES = {'not-found': 3, 'not-regular': 4, 'too-large': 5, 'bad-path': 6, 'bad-mode': 7, 'bad-command': 8}
def die(code):
    sys.stderr.write(code + '\n')
    sys.exit(CODES.get(code, 1))
def split(rel):
    parts = rel.split('/')
    if not rel or len(rel) > 1024 or rel.startswith('/') or '\0' in rel or any(p in ('', '.', '..') for p in parts):
        die('bad-path')
    return parts
def walk(rel, create=False):
    parts = split(rel)
    fd = os.open(os.environ['HOME'], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    for part in parts[:-1]:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            nfd = os.open(part, flags, dir_fd=fd)
        except FileNotFoundError:
            if not create:
                raise
            os.mkdir(part, 0o700, dir_fd=fd)
            nfd = os.open(part, flags, dir_fd=fd)
        os.close(fd)
        fd = nfd
    return fd, parts[-1]
def write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]
def op_read(rel, limit):
    dfd, name = walk(rel)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        die('not-regular')
    if st.st_size > limit:
        die('too-large')
    total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            die('too-large')
        write_all(1, chunk)
def op_write(rel, mode, limit):
    if mode & ~0o644:
        die('bad-mode')
    dfd, name = walk(rel, create=True)
    tmp = '.%s.woowbk-%s' % (name[:200], os.urandom(6).hex())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    try:
        total = 0
        while True:
            chunk = os.read(0, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                die('too-large')
            write_all(fd, chunk)
        os.fchmod(fd, mode)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        tmp = None
        os.fsync(dfd)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
def op_remove(rel):
    try:
        dfd, name = walk(rel)
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        sys.stdout.write('absent')
        return
    if stat.S_ISDIR(st.st_mode):
        die('not-regular')
    os.unlink(name, dir_fd=dfd)
    sys.stdout.write('removed')
def op_stat(rels):
    result = []
    for rel in rels:
        try:
            dfd, name = walk(rel)
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            result.append({'path': rel, 'type': 'missing'})
            continue
        except OSError:
            result.append({'path': rel, 'type': 'blocked'})
            continue
        kind = 'file' if stat.S_ISREG(st.st_mode) else 'dir' if stat.S_ISDIR(st.st_mode) else 'link' if stat.S_ISLNK(st.st_mode) else 'other'
        result.append({'path': rel, 'type': kind, 'size': st.st_size, 'mode': stat.S_IMODE(st.st_mode)})
    sys.stdout.write(json.dumps(result))
def op_relay(argv):
    if not argv or argv[0] != '/usr/bin/podman':
        die('bad-command')
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE)
    while True:
        chunk = os.read(proc.stdout.fileno(), 1 << 16)
        if not chunk:
            break
        write_all(1, chunk)
    sys.exit(proc.wait())
def main():
    op, args = sys.argv[1], sys.argv[2:]
    try:
        if op == 'read':
            op_read(args[0], int(args[1]))
        elif op == 'write':
            op_write(args[0], int(args[1], 8), int(args[2]))
        elif op == 'remove':
            op_remove(args[0])
        elif op == 'stat':
            op_stat(args)
        elif op == 'relay':
            op_relay(args)
        else:
            die('bad-command')
    except FileNotFoundError:
        die('not-found')
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.EISDIR, errno.ENXIO):
            die('not-regular')
        die('io-error')
main()
'''

# Host directories (catalog `data_dirs`). Executed as `podman unshare /usr/bin/python3 -I -c DIR_HELPER <op> ...`,
# i.e. as the owner inside his rootless user namespace (uid 0 there), so files of his subordinate ids (container
# users such as www-data or postgres) can be read, created with their owners, and removed. It never has more than
# the owner's own rights. The owner also controls that namespace (he can bind-mount over /usr/bin/python3 in it), so
# every answer is untrusted: OwnerRunner checks its shape and turns anything else into a BackupError (review M1).
# Every path component from $HOME down is opened with O_NOFOLLOW (a directory that is a symlink, or lies below one,
# is refused), the directory itself is reached through a directory fd (fchdir) before GNU tar runs, and renames use
# renameat2(RENAME_NOREPLACE). A directory must be on its parent's filesystem and hold no other mount (review M2):
# measure and mounts report mount points, pack stays on one filesystem, swap and revert refuse a mount point, and a
# removal checks every directory's device before deleting anything. Siblings are `<name>.woowbk-new-<token>` (being
# written), `<name>.woowbk-old-<token>` (the replaced copy) and `<name>.woowbk-del-<token>` (an old copy being
# deleted: renamed first, so an interrupted deletion is never taken for content worth keeping). Operations:
#   pack <rel>                     GNU tar (POSIX format, numeric owners, xattrs, one filesystem) of it -> stdout
#   measure <rel>                  {"bytes", "members", "acls", "mount_root", "mounts", "more_mounts"}: apparent size of
#                                  regular files (hard links once), entries, entries with POSIX ACLs, mount points
#   mounts <rel>                   {"mount_root", "mounts", "more_mounts"} (walks directories only)
#   unpack <rel> <token>           stdin tar -> new sibling (missing parents created 0700); {"created": [parents]}
#   swap <rel> <token> inplace|fresh  <name> -> old sibling (inplace) or rmdir an empty <name> (fresh), then
#                                  new sibling -> <name>; {"replaced", "removed_empty"}
#   revert <rel> <token> <rtoken>  a rollback without a copy: <name> -> old sibling of <rtoken>, then the old sibling
#                                  of <token> (the content before the restore) -> <name>; {"replaced"}
#   drop <rel> new|old|del|target <token>  remove a sibling (old: renamed to del first) or <name> itself ("target")
#                                  without following symlinks or crossing into another filesystem
#   back <rel> <token>             old sibling -> <name>, only while <name> is missing
#   state <tokens> <rel>...        JSON list of {path, type, empty, mount, dev, free, siblings: [{kind, token, type}],
#                                  more}; the siblings of the comma-separated <tokens> ("-": none) are always listed,
#                                  other siblings up to 50 (`more` counts the rest; review M4)
DIR_HELPER = r'''
import ctypes, errno, json, os, re, shutil, stat, subprocess, sys
TAR = '/usr/bin/tar'
CODES = {'not-found': 3, 'not-dir': 4, 'bad-path': 6, 'bad-command': 8, 'exists': 9, 'not-empty': 10, 'tar': 11,
         'mount': 12}
SEG = re.compile(r'[A-Za-z0-9._@+-]{1,255}\Z')
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')
SIBLING = re.compile(r'\.woowbk-(new|old|del)-([A-Za-z0-9][A-Za-z0-9._-]{0,63})\Z')
DIRFLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
ACLS = ('system.posix_acl_access', 'system.posix_acl_default')
MAX_SIBLINGS, MAX_MOUNTS = 50, 16
LIBC = ctypes.CDLL(None, use_errno=True)
def die(code, detail=''):
    sys.stderr.write(code + (': ' + detail if detail else '') + '\n')
    sys.exit(CODES.get(code, 1))
def split(rel):
    parts = rel.split('/')
    if not rel or len(rel) > 1024 or rel.startswith('/') or any(p in ('', '.', '..') or not SEG.fullmatch(p) for p in parts):
        die('bad-path')
    return parts
def check_token(value):
    if not TOKEN.fullmatch(value):
        die('bad-command')
    return value
def parent(rel, create=False):
    parts = split(rel)
    fd = os.open(os.environ['HOME'], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    created = []
    for i, part in enumerate(parts[:-1]):
        try:
            nfd = os.open(part, DIRFLAGS, dir_fd=fd)
        except FileNotFoundError:
            if not create:
                raise
            os.mkdir(part, 0o700, dir_fd=fd)
            created.append('/'.join(parts[:i + 1]))
            nfd = os.open(part, DIRFLAGS, dir_fd=fd)
        os.close(fd)
        fd = nfd
    return fd, parts[-1], created
def sibling(name, kind, token):
    value = '%s.woowbk-%s-%s' % (name, kind, check_token(token))
    if len(value) > 255:
        die('bad-path')
    return value
def kind_of(dfd, name):
    try:
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return 'missing'
    return 'dir' if stat.S_ISDIR(st.st_mode) else 'link' if stat.S_ISLNK(st.st_mode) else 'other'
def is_mount(dfd, name):
    return os.stat(name, dir_fd=dfd, follow_symlinks=False).st_dev != os.fstat(dfd).st_dev
def shown(path):
    return path.encode('utf-8', 'surrogateescape').decode('utf-8', 'replace')[:300]
def rename(dfd, old, new):
    try:
        fn = LIBC.renameat2
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    except AttributeError:
        fn = None
    if fn is not None:
        if fn(dfd, os.fsencode(old), dfd, os.fsencode(new), 1) == 0:
            return
        err = ctypes.get_errno()
        if err == errno.EEXIST:
            die('exists', new)
        if err not in (errno.EINVAL, errno.ENOSYS):
            raise OSError(err, os.strerror(err), new)
    if kind_of(dfd, new) != 'missing':
        die('exists', new)
    os.rename(old, new, src_dir_fd=dfd, dst_dir_fd=dfd)
def sync_fs(fd):
    # Only the filesystem being written (review L7): os.sync() waited for every mount, a hung NFS one included.
    try:
        fn = LIBC.syncfs
    except AttributeError:
        os.sync()
        return
    if fn(fd) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
def scan(dfd, files):
    """Walk the directory open at dfd without following symlinks; a mount point below it is reported and not
    entered. files=True also counts entries, bytes of regular files (hard links once) and entries with ACLs."""
    dev = os.fstat(dfd).st_dev
    out = {'mounts': [], 'more_mounts': 0, 'bytes': 0, 'members': 1, 'acls': 0}
    seen = set()
    for top, dirs, names, fd in os.fwalk('.', dir_fd=dfd, follow_symlinks=False):
        kept = []
        for name in dirs:
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if st.st_dev == dev:
                kept.append(name)
            elif len(out['mounts']) < MAX_MOUNTS:
                out['mounts'].append(shown(os.path.normpath(os.path.join(top, name))))
            else:
                out['more_mounts'] += 1
        dirs[:] = kept
        if not files:
            continue
        out['members'] += len(kept) + len(names)
        os.fchdir(fd)
        for name in kept + names + (['.'] if top == '.' else []):
            try:
                if any(attr in ACLS for attr in os.listxattr(name, follow_symlinks=False)):
                    out['acls'] += 1
            except OSError:
                pass
        for name in names:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISREG(st.st_mode) and (st.st_nlink < 2 or (st.st_dev, st.st_ino) not in seen):
                out['bytes'] += st.st_size
                if st.st_nlink > 1:
                    seen.add((st.st_dev, st.st_ino))
    os.chdir('/')
    return out
def one_filesystem(pfd, name):
    """Refuse, before anything is changed, a tree that is a mount point or holds one."""
    if is_mount(pfd, name):
        die('mount', name)
    dfd = os.open(name, DIRFLAGS, dir_fd=pfd)
    try:
        found = scan(dfd, False)['mounts']
    finally:
        os.close(dfd)
    if found:
        die('mount', found[0])
def remove(pfd, name, checked=False):
    if not checked:
        one_filesystem(pfd, name)
    shutil.rmtree(name, dir_fd=pfd)
    os.fsync(pfd)
def op_pack(rel):
    pfd, name, _ = parent(rel)
    dfd = os.open(name, DIRFLAGS, dir_fd=pfd)
    os.fchdir(dfd)
    os.execv(TAR, [TAR, '--create', '--file=-', '--format=posix', '--numeric-owner', '--xattrs', '--no-acls',
                   '--no-selinux', '--one-file-system', '.'])
def op_measure(rel, files):
    pfd, name, _ = parent(rel)
    dfd = os.open(name, DIRFLAGS, dir_fd=pfd)
    out = scan(dfd, files)
    out['mount_root'] = os.fstat(dfd).st_dev != os.fstat(pfd).st_dev
    if not files:
        out = {key: out[key] for key in ('mount_root', 'mounts', 'more_mounts')}
    sys.stdout.write(json.dumps(out))
def op_unpack(rel, token):
    pfd, name, created = parent(rel, create=True)
    new = sibling(name, 'new', token)
    try:
        os.mkdir(new, 0o700, dir_fd=pfd)
    except FileExistsError:
        die('exists', new)
    nfd = os.open(new, DIRFLAGS, dir_fd=pfd)
    os.fchdir(nfd)
    code = subprocess.run([TAR, '--extract', '--file=-', '--numeric-owner', '--preserve-permissions', '--xattrs',
                           '--xattrs-include=user.*', '--no-acls', '--no-selinux'], stdout=subprocess.DEVNULL).returncode
    os.chdir('/')
    if code != 0:
        try:
            shutil.rmtree(new, dir_fd=pfd)
        except OSError:
            pass
        die('tar', 'exit %d' % code)
    sync_fs(nfd)
    sys.stdout.write(json.dumps({'created': created}))
def op_swap(rel, token, mode):
    if mode not in ('inplace', 'fresh'):
        die('bad-command')
    pfd, name, _ = parent(rel)
    new, old = sibling(name, 'new', token), sibling(name, 'old', token)
    if kind_of(pfd, new) != 'dir':
        die('not-found', new)
    current, replaced, removed = kind_of(pfd, name), False, False
    if current == 'dir' and is_mount(pfd, name):
        die('mount', name)
    if current == 'dir' and mode == 'fresh':
        try:
            os.rmdir(name, dir_fd=pfd)
        except OSError as error:
            if error.errno in (errno.ENOTEMPTY, errno.EEXIST):
                die('not-empty', name)
            raise
        removed = True
    elif current == 'dir':
        rename(pfd, name, old)
        replaced = True
    elif current != 'missing':
        die('not-dir', name)
    rename(pfd, new, name)
    os.fsync(pfd)
    sys.stdout.write(json.dumps({'replaced': replaced, 'removed_empty': removed}))
def op_revert(rel, token, rtoken):
    pfd, name, _ = parent(rel)
    old, aside = sibling(name, 'old', token), sibling(name, 'old', rtoken)
    if kind_of(pfd, old) != 'dir':
        die('not-found', old)
    current, replaced = kind_of(pfd, name), False
    if current == 'dir':
        if is_mount(pfd, name):
            die('mount', name)
        rename(pfd, name, aside)
        replaced = True
    elif current != 'missing':
        die('not-dir', name)
    rename(pfd, old, name)
    os.fsync(pfd)
    sys.stdout.write(json.dumps({'replaced': replaced}))
def op_drop(rel, which, token):
    if which not in ('new', 'old', 'del', 'target'):
        die('bad-command')
    try:
        pfd, name, _ = parent(rel)
    except FileNotFoundError:
        sys.stdout.write('absent')
        return
    target = name if which == 'target' else sibling(name, which, token)
    kind = kind_of(pfd, target)
    if kind == 'missing':
        sys.stdout.write('absent')
        return
    if kind != 'dir':
        die('not-dir', target)
    one_filesystem(pfd, target)
    if which == 'old':
        doomed = sibling(name, 'del', token)
        left = kind_of(pfd, doomed)
        if left == 'dir':
            remove(pfd, doomed)  # an earlier deletion of this token was cut short
        elif left != 'missing':
            die('not-dir', doomed)
        rename(pfd, target, doomed)
        os.fsync(pfd)
        target = doomed
    remove(pfd, target, checked=True)
    sys.stdout.write('removed')
def op_back(rel, token):
    pfd, name, _ = parent(rel)
    old = sibling(name, 'old', token)
    if kind_of(pfd, name) != 'missing':
        die('exists', name)
    if kind_of(pfd, old) != 'dir':
        die('not-found', old)
    rename(pfd, old, name)
    os.fsync(pfd)
    sys.stdout.write('restored')
def op_state(tokens, rels):
    wanted = set() if tokens == '-' else {check_token(token) for token in tokens.split(',')}
    rows = []
    for rel in rels:
        row = {'path': rel, 'type': 'missing', 'empty': None, 'mount': False, 'dev': None, 'free': None,
               'siblings': [], 'more': 0}
        rows.append(row)
        try:
            pfd, name, _ = parent(rel)
        except FileNotFoundError:
            continue
        except OSError:
            row['type'] = 'blocked'
            continue
        found = []
        try:
            vfs = os.fstatvfs(pfd)
            row['dev'], row['free'] = os.fstat(pfd).st_dev, vfs.f_bavail * vfs.f_frsize
            row['type'] = kind_of(pfd, name)
            if row['type'] == 'dir':
                try:
                    row['mount'] = is_mount(pfd, name)
                    dfd = os.open(name, DIRFLAGS, dir_fd=pfd)
                    with os.scandir(dfd) as entries:
                        row['empty'] = next(entries, None) is None
                    os.close(dfd)
                except OSError:
                    row['type'], row['empty'] = 'blocked', None
            prefix = name + '.woowbk-'
            with os.scandir(pfd) as entries:
                for entry in entries:
                    match = SIBLING.fullmatch(entry.name[len(name):]) if entry.name.startswith(prefix) else None
                    if match:
                        found.append({'kind': match.group(1), 'token': match.group(2),
                                      'type': 'dir' if entry.is_dir(follow_symlinks=False) else 'other'})
        finally:
            os.close(pfd)
        found.sort(key=lambda item: (item['token'], item['kind']))
        others = [item for item in found if item['token'] not in wanted]
        row['siblings'] = [item for item in found if item['token'] in wanted] + others[:MAX_SIBLINGS]
        row['more'] = max(0, len(others) - MAX_SIBLINGS)
    sys.stdout.write(json.dumps(rows))
def main():
    op, args = sys.argv[1], sys.argv[2:]
    try:
        if op == 'pack' and len(args) == 1:
            op_pack(args[0])
        elif op in ('measure', 'mounts') and len(args) == 1:
            op_measure(args[0], op == 'measure')
        elif op == 'unpack' and len(args) == 2:
            op_unpack(args[0], args[1])
        elif op == 'swap' and len(args) == 3:
            op_swap(*args)
        elif op == 'revert' and len(args) == 3:
            op_revert(*args)
        elif op == 'drop' and len(args) == 3:
            op_drop(*args)
        elif op == 'back' and len(args) == 2:
            op_back(*args)
        elif op == 'state' and len(args) >= 2:
            op_state(args[0], args[1:])
        else:
            die('bad-command')
    except FileNotFoundError:
        die('not-found')
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            die('not-dir')
        if error.errno in (errno.ENOTEMPTY, errno.EEXIST):
            die('not-empty')
        if error.errno in (errno.EBUSY, errno.EXDEV):
            die('mount', os.strerror(error.errno))
        die('io-error', os.strerror(error.errno or 0))
main()
'''
DIR_HELPER_ERRORS = {3: 'not-found', 4: 'not-dir', 6: 'bad-path', 8: 'bad-command', 9: 'exists', 10: 'not-empty',
                     11: 'tar', 12: 'mount'}


@dataclass
class Result:
    returncode: int
    stdout: bytes | None
    stderr: bytes


class CommandError(BackupError):
    """A command run as the owner exited non-zero. `stderr` is kept for diagnostics only."""

    def __init__(self, message, *, returncode, stderr=b'', command=''):
        super().__init__('job-failed', message, command=command, returncode=returncode)
        self.returncode = returncode
        self.stderr = stderr or b''


class OutputLimitExceeded(Exception):
    """A child produced more output than its byte budget allowed; its process group was killed.

    `to_file` tells a file budget (disk space) from a capture limit (helper memory) apart.
    """

    def __init__(self, limit, *, to_file):
        super().__init__(f'output exceeded {limit} bytes')
        self.limit = limit
        self.to_file = to_file


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _write_out(target, data):
    if hasattr(target, 'write'):
        view = memoryview(data)
        while view:
            written = target.write(view)
            view = view[written if written is not None else len(view):]
    else:
        view = memoryview(data)
        while view:
            view = view[os.write(target, view):]


def default_runner(argv, *, input=None, stdout=None, timeout=None, cwd=None, env=None, max_output=None):
    """Subprocess executor: no shell, own process group (killed as a whole on timeout or overflow).

    `stdout`: None captures (at most `max_output`, default MAX_CAPTURE bytes), DEVNULL discards, a
    writable file receives the output through a pipe copied here, so `max_output` (when given) is a
    byte budget for that file. stderr keeps only its last STDERR_TAIL bytes. Nothing the child
    prints can grow this process without bound (CONTRACT section 10, review finding SEC-3).
    """
    if input is not None and not isinstance(input, (bytes, bytearray)):
        try:
            input.fileno()
        except (AttributeError, OSError, ValueError):
            input = input.read()  # in-memory file object: feed its bytes through a pipe
    feed = isinstance(input, (bytes, bytearray))
    stdin = subprocess.PIPE if feed else (input if input is not None else subprocess.DEVNULL)
    discard = stdout is subprocess.DEVNULL
    to_file = stdout is not None and not discard
    limit = max_output if max_output is not None else (None if to_file else MAX_CAPTURE)
    proc = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.DEVNULL if discard else subprocess.PIPE,
                            stderr=subprocess.PIPE, cwd=cwd, env=env, close_fds=True, start_new_session=True)
    deadline = None if timeout is None else time.monotonic() + timeout
    chunks, size, err = [], 0, bytearray()
    pending = memoryview(bytes(input)) if feed else None
    selector = selectors.DefaultSelector()
    try:
        if proc.stdout is not None:
            selector.register(proc.stdout, selectors.EVENT_READ)
        selector.register(proc.stderr, selectors.EVENT_READ)
        if feed:
            if pending:
                selector.register(proc.stdin, selectors.EVENT_WRITE)
            else:
                proc.stdin.close()
        while selector.get_map():
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            for key, _events in selector.select(remaining):
                if key.fileobj is proc.stdin:
                    try:
                        written = os.write(proc.stdin.fileno(), pending[:select.PIPE_BUF])
                    except BrokenPipeError:
                        written, pending = 0, pending[:0]
                    pending = pending[written:]
                    if not pending:
                        selector.unregister(proc.stdin)
                        proc.stdin.close()
                    continue
                data = os.read(key.fd, READ_CHUNK)
                if not data:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if key.fileobj is proc.stderr:
                    err += data
                    if len(err) > STDERR_TAIL:
                        del err[:-STDERR_TAIL]
                    continue
                size += len(data)
                if limit is not None and size > limit:
                    raise OutputLimitExceeded(limit, to_file=to_file)
                if to_file:
                    _write_out(stdout, data)
                else:
                    chunks.append(data)
        remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
        proc.wait(timeout=remaining)
    except BaseException:
        _kill_group(proc)
        proc.wait()
        raise
    finally:
        selector.close()
        for handle in (proc.stdin, proc.stdout, proc.stderr):
            if handle is not None and not handle.closed:
                handle.close()
    return Result(proc.returncode, None if to_file else b''.join(chunks) if not discard else None, bytes(err))


def describe(argv):
    """Short, secret-free description of a command for messages and logs."""
    argv = [str(a) for a in argv]
    if not argv:
        return ''
    name = os.path.basename(argv[0])
    if name.startswith('python3') and len(argv) > 4 and argv[1:3] == ['-I', '-c']:
        op, rest = argv[4], argv[5:]
        if op == 'relay':
            return describe(rest)
        return f'owner-file {op} {rest[0] if rest else ""}'.strip()
    if (name == 'podman' and len(argv) > 6 and argv[1] == 'unshare' and os.path.basename(argv[2]).startswith('python3')
            and argv[3:5] == ['-I', '-c']):
        op, rest = argv[6], argv[7:]
        return f'owner-dir {op} {rest[0] if rest else ""}'.strip()
    words = [name] + [a for a in argv[1:] if not a.startswith('-')][:3]
    return ' '.join(words)[:200]


def stderr_tail(data, lines=3, width=200):
    """Last few stderr lines, without echoed SQL ("Command was:") — for job logs only."""
    text = (data or b'').decode('utf-8', 'replace')
    kept = []
    for line in text.splitlines():
        if line.strip().startswith('Command was:'):
            break
        if line.strip() and 'level=warning' not in line:
            kept.append(line.strip()[:width])
    return kept[-lines:]


def validate_rel_path(rel):
    if not isinstance(rel, str) or not rel or len(rel) > 1024 or rel.startswith('/'):
        raise BackupError('invalid-request', '檔案路徑不正確。')
    for segment in rel.split('/'):
        if segment in ('.', '..') or not REL_SEGMENT_RE.fullmatch(segment):
            raise BackupError('invalid-request', '檔案路徑不正確。')
    return rel


class OwnerRunner:
    def __init__(self, owner, *, runner=None, user_lookup=None):
        """`runner` injects a fake subprocess executor in tests."""
        if not isinstance(owner, str) or not OWNER_RE.fullmatch(owner) or owner == 'root':
            raise BackupError('invalid-request', '應用擁有者帳號名稱不正確。')
        lookup = user_lookup or pwd.getpwnam
        try:
            account = lookup(owner)
        except KeyError:
            raise BackupError('owner-missing', f'找不到應用擁有者帳號 {owner}。', owner=owner) from None
        if account.pw_uid == 0:
            raise BackupError('invalid-request', '不支援 root 擁有的應用。')
        home = account.pw_dir
        if not isinstance(home, str) or not home.startswith('/') or os.path.normpath(home) != home or '\n' in home:
            raise BackupError('owner-missing', f'帳號 {owner} 的家目錄設定不正確。', owner=owner)
        self.owner = owner
        self.uid = account.pw_uid
        self.gid = account.pw_gid
        self.home = home
        self._runner = runner or default_runner

    @property
    def runtime_dir(self):
        return f'/run/user/{self.uid}'

    def prefix(self):
        return [RUNUSER, '-u', self.owner, '--', ENV, '-i', f'PATH={SAFE_PATH}', f'HOME={self.home}', 'LANG=C.UTF-8',
                f'XDG_RUNTIME_DIR=/run/user/{self.uid}',
                f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{self.uid}/bus']

    def run(self, argv, *, input=None, stdout=None, timeout=300, check=True, max_output=None):
        """Run fixed `argv` as the owner. `input`: bytes or a readable file; `stdout`: None (capture),
        a writable file, or DEVNULL. `max_output` caps captured bytes or, with a file, is its byte
        budget (the child is killed when it is exceeded). Returns Result; raises CommandError when
        `check` and exit != 0."""
        argv = [str(arg) for arg in argv]
        if not argv or any('\0' in arg for arg in argv):
            raise BackupError('internal-error', '內部命令格式不正確。')
        what = describe(argv)
        extra = {} if max_output is None else {'max_output': int(max_output)}
        try:
            result = self._runner(self.prefix() + argv, input=input, stdout=stdout, timeout=timeout,
                                  cwd=self.home, env=dict(ROOT_ENV), **extra)
        except OutputLimitExceeded as exceeded:
            if exceeded.to_file:
                raise BackupError('insufficient-space', f'{what} 的輸出超過可用空間（保留 512 MiB 後的上限），已停止。',
                                  command=what) from None
            raise BackupError('limit-exceeded', f'{what} 的輸出超過上限，已停止。', command=what) from None
        except subprocess.TimeoutExpired:
            raise BackupError('job-failed', f'{what} 執行逾時（{timeout} 秒）。', command=what) from None
        except FileNotFoundError:
            raise BackupError('owner-missing', f'無法以帳號 {self.owner} 執行命令（家目錄或工具不存在）。',
                              owner=self.owner) from None
        except OSError:
            raise BackupError('job-failed', f'無法執行 {what}。', command=what) from None
        if check and result.returncode != 0:
            raise CommandError(f'{what} 執行失敗（結束碼 {result.returncode}）。', returncode=result.returncode,
                               stderr=result.stderr, command=what)
        return result

    def podman(self, *args, **kwargs):
        return self.run([PODMAN, *args], **kwargs)

    def systemctl(self, *args, **kwargs):
        return self.run([SYSTEMCTL, '--user', *args], **kwargs)

    def relay(self, podman_args, *, stdout, timeout=3600, check=True, max_output=None):
        """`podman <args>` whose stdout is an owner-created pipe, copied to `stdout` by the helper."""
        return self.run([PYTHON, '-I', '-c', FILE_HELPER, 'relay', PODMAN, *podman_args], stdout=stdout,
                        timeout=timeout, check=check, max_output=max_output)

    def _helper(self, args, **kwargs):
        result = self.run([PYTHON, '-I', '-c', FILE_HELPER, *args], check=False, **kwargs)
        if result.returncode:
            code = HELPER_ERRORS.get(result.returncode, 'io-error')
            rel = args[1] if len(args) > 1 else ''
            if code == 'not-found':
                raise BackupError('not-found', f'找不到檔案 ~/{rel}。', path=rel)
            if code == 'not-regular':
                raise BackupError('permission-denied', f'~/{rel} 不是一般檔案，或路徑中含有符號連結。', path=rel)
            if code == 'too-large':
                raise BackupError('limit-exceeded', f'~/{rel} 超過大小上限。', path=rel)
            raise BackupError('job-failed', f'無法以擁有者身分存取 ~/{rel}。', path=rel)
        return result

    def read_file(self, rel_path, max_bytes=MAX_FILE_BYTES):
        validate_rel_path(rel_path)
        return self._helper(['read', rel_path, str(int(max_bytes))], timeout=120,
                            max_output=int(max_bytes) + 64 * 1024).stdout or b''

    def write_file(self, rel_path, data, mode):
        """`data`: bytes or a readable binary file; `mode`: int or octal string, subset of 0644."""
        validate_rel_path(rel_path)
        mode = int(mode, 8) if isinstance(mode, str) else int(mode)
        if mode & ~0o644:
            raise BackupError('invalid-request', '檔案權限不可超過 0644。')
        self._helper(['write', rel_path, format(mode, '04o'), str(MAX_FILE_BYTES)], input=data, timeout=120)

    def remove_file(self, rel_path):
        """Remove a regular file or symlink; returns True when something was removed."""
        validate_rel_path(rel_path)
        return (self._helper(['remove', rel_path], timeout=60).stdout or b'').strip() == b'removed'

    def stat_files(self, rel_paths):
        """{rel: {'type': 'file'|'dir'|'link'|'other'|'missing'|'blocked', 'size', 'mode'}}."""
        rel_paths = [validate_rel_path(rel) for rel in rel_paths]
        if not rel_paths:
            return {}
        out = self._helper(['stat', *rel_paths], timeout=60, max_output=1024 * 1024).stdout or b'[]'
        try:
            rows = json.loads(out.decode('utf-8'))
        except ValueError:
            raise BackupError('job-failed', '無法讀取擁有者檔案狀態。') from None
        return {row['path']: row for row in rows if isinstance(row, dict) and row.get('path') in rel_paths}

    # ---------------------------------------------------------------- host directories (DIR_HELPER)
    def _dir_argv(self, op, *args):
        return [PODMAN, 'unshare', PYTHON, '-I', '-c', DIR_HELPER, op, *args]

    @staticmethod
    def _check_token(token):
        if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
            raise BackupError('internal-error', '內部作業代號格式不正確。')
        return token

    def _dir_failure(self, result, rel, what):
        """BackupError for a failed DIR_HELPER call (the relay passes the helper's exit status through podman)."""
        code = DIR_HELPER_ERRORS.get(result.returncode)
        detail = (result.stderr or b'').decode('utf-8', 'replace').strip().splitlines()
        detail = _printable(detail[-1][:200]) if detail else ''
        if code == 'not-found':
            return BackupError('not-found', f'找不到主機資料夾 ~/{rel}（或它的上層資料夾）。', path=rel)
        if code == 'not-dir':
            return BackupError('permission-denied', f'~/{rel} 不是資料夾，或路徑中含有符號連結；不會跟隨符號連結。', path=rel)
        if code == 'exists':
            return BackupError('job-failed', f'~/{rel} 旁已有同名的資料夾（{detail.split(": ", 1)[-1]}），'
                                             '可能是先前中斷的還原留下的；請先確認後再試。', path=rel)
        if code == 'not-empty':
            return BackupError('incompatible', f'~/{rel} 已存在且不是空的資料夾，為避免覆寫既有資料而停止。', path=rel)
        if code == 'mount':
            return BackupError('incompatible', f'~/{rel} 是掛載點或其中有其他檔案系統的掛載；為避免移動或刪除其他檔案系統的內容，'
                                               f'無法{what}這個主機資料夾。', path=rel)
        return CommandError(f'無法以擁有者身分{what}主機資料夾 ~/{rel}（結束碼 {result.returncode}）。',
                            returncode=result.returncode, stderr=result.stderr, command=f'owner-dir {what}')

    @staticmethod
    def _dir_answer(result, rel, what, check):
        """The JSON a DIR_HELPER call printed, once `check(value)` accepts its shape. The helper runs in the owner's
        namespace, so the answer is untrusted: undecodable or deeply nested JSON and any other shape are a
        BackupError, never a TypeError that would skip a rollback (review M1)."""
        try:
            value = json.loads((result.stdout or b'').decode('utf-8'))
            ok = check(value)
        except (ValueError, RecursionError, TypeError, KeyError, AttributeError):
            ok = False
        if not ok:
            raise BackupError('job-failed', f'主機資料夾 ~/{rel} 的{what}結果格式不正確，已停止。', path=rel)
        return value

    def dir_pack(self, rel_path, *, stdout, timeout=3 * 3600, max_output=None):
        """GNU tar of ~/<rel_path>, read as the owner inside his user namespace, through the owner-side relay."""
        validate_rel_path(rel_path)
        result = self.run([PYTHON, '-I', '-c', FILE_HELPER, 'relay', *self._dir_argv('pack', rel_path)],
                          stdout=stdout, timeout=timeout, check=False, max_output=max_output)
        if result.returncode:
            raise self._dir_failure(result, rel_path, '讀取')

    def dir_measure(self, rel_path):
        """{'bytes', 'members', 'acls', 'mount_root', 'mounts', 'more_mounts'} of ~/<rel_path>: apparent bytes of the
        regular files, entries, entries with POSIX ACLs (not kept), and mount points at or below it."""
        validate_rel_path(rel_path)
        result = self.run(self._dir_argv('measure', rel_path), timeout=1800, check=False, max_output=SMALL_JSON)
        if result.returncode:
            raise self._dir_failure(result, rel_path, '讀取')
        data = self._dir_answer(result, rel_path, '大小估算', lambda d: isinstance(d, dict) and _mounts_ok(d) and all(
            _count(d[key]) for key in ('bytes', 'members', 'acls')))
        return {key: data[key] for key in ('bytes', 'members', 'acls', 'mount_root', 'mounts', 'more_mounts')}

    def dir_mounts(self, rel_path):
        """{'mount_root', 'mounts', 'more_mounts'}: whether ~/<rel_path> is a mount point, and mount points below it."""
        validate_rel_path(rel_path)
        result = self.run(self._dir_argv('mounts', rel_path), timeout=1800, check=False, max_output=SMALL_JSON)
        if result.returncode:
            raise self._dir_failure(result, rel_path, '讀取')
        data = self._dir_answer(result, rel_path, '掛載檢查', lambda d: isinstance(d, dict) and _mounts_ok(d))
        return {key: data[key] for key in ('mount_root', 'mounts', 'more_mounts')}

    def dir_unpack(self, rel_path, token, *, input, timeout=3 * 3600):
        """Extract a (canonical) tar from `input` into ~/<rel_path>.woowbk-new-<token>, creating missing parents as
        the owner; returns the parent directories it created (relative paths)."""
        validate_rel_path(rel_path)
        result = self.run(self._dir_argv('unpack', rel_path, self._check_token(token)), input=input, timeout=timeout,
                          check=False, max_output=SMALL_JSON)
        if result.returncode:
            raise self._dir_failure(result, rel_path, '寫入')
        parents = {'/'.join(rel_path.split('/')[:i]) for i in range(1, rel_path.count('/') + 1)}
        data = self._dir_answer(result, rel_path, '寫入', lambda d: isinstance(d, dict) and isinstance(
            d['created'], list) and len(set(d['created'])) == len(d['created']) and all(
                isinstance(item, str) and item in parents for item in d['created']))
        return list(data['created'])

    def dir_swap(self, rel_path, token, *, fresh=False):
        """Move ~/<rel_path> aside (`.woowbk-old-<token>`; fresh: remove it when empty) and the new sibling in."""
        validate_rel_path(rel_path)
        result = self.run(self._dir_argv('swap', rel_path, self._check_token(token), 'fresh' if fresh else 'inplace'),
                          timeout=SHORT_TIMEOUT, check=False, max_output=SMALL_JSON)
        if result.returncode:
            raise self._dir_failure(result, rel_path, '替換')
        data = self._dir_answer(result, rel_path, '替換', lambda d: isinstance(d, dict) and set(d) == {
            'replaced', 'removed_empty'} and all(type(value) is bool for value in d.values()))
        return {'replaced': data['replaced'], 'removed_empty': data['removed_empty']}

    def dir_revert(self, rel_path, token, rollback_token):
        """Rollback without a copy: ~/<rel_path> (the failed restore's data) moves to `.woowbk-old-<rollback_token>`,
        and `.woowbk-old-<token>` (what the directory held before the restore) moves back; {'replaced'}."""
        validate_rel_path(rel_path)
        result = self.run(self._dir_argv('revert', rel_path, self._check_token(token),
                                         self._check_token(rollback_token)),
                          timeout=SHORT_TIMEOUT, check=False, max_output=SMALL_JSON)
        if result.returncode:
            raise self._dir_failure(result, rel_path, '移回')
        data = self._dir_answer(result, rel_path, '移回', lambda d: isinstance(d, dict) and set(d) == {'replaced'}
                                and type(d['replaced']) is bool)
        return {'replaced': data['replaced']}

    def dir_drop(self, rel_path, which, token='-'):
        """Remove `<rel>.woowbk-new|old|del-<token>`, or ~/<rel_path> itself ('target'); True if removed. An old copy
        is renamed to `del` first, so an interrupted deletion leaves a name the recovery deletes."""
        validate_rel_path(rel_path)
        if which not in ('new', 'old', 'del', 'target'):
            raise BackupError('internal-error', '內部命令格式不正確。')
        if which != 'target':
            self._check_token(token)
        result = self.run(self._dir_argv('drop', rel_path, which, token if which != 'target' else '-'),
                          timeout=3600, check=False, max_output=SMALL_JSON)
        if result.returncode:
            raise self._dir_failure(result, rel_path, '刪除')
        return (result.stdout or b'').strip() == b'removed'

    def dir_back(self, rel_path, token):
        """Move `<rel>.woowbk-old-<token>` back to ~/<rel_path>, which must be missing."""
        validate_rel_path(rel_path)
        result = self.run(self._dir_argv('back', rel_path, self._check_token(token)), timeout=SHORT_TIMEOUT,
                          check=False, max_output=SMALL_JSON)
        if result.returncode:
            raise self._dir_failure(result, rel_path, '移回')

    def dir_states(self, rel_paths, tokens=()):
        """{rel: {'type': 'dir'|'missing'|'link'|'other'|'blocked', 'empty': bool|None, 'mount': bool,
        'dev': int|None, 'free': int|None, 'siblings': [{'kind': 'new'|'old'|'del', 'token', 'type'}], 'more': int}}
        of host directories, read inside the namespace. The siblings of `tokens` are always listed, others up to 50."""
        rel_paths = [validate_rel_path(rel) for rel in rel_paths]
        if not rel_paths:
            return {}
        tokens = [self._check_token(token) for token in tokens]
        result = self.run(self._dir_argv('state', ','.join(tokens) or '-', *rel_paths), timeout=SHORT_TIMEOUT,
                          check=False, max_output=SMALL_JSON)
        if result.returncode:
            raise self._dir_failure(result, rel_paths[0], '讀取')
        rows = self._dir_answer(result, rel_paths[0], '狀態讀取', lambda d: isinstance(d, list) and sorted(
            row['path'] for row in d) == sorted(rel_paths) and all(_state_ok(row) for row in d))
        return {row['path']: row for row in rows}


def _printable(text):
    """Owner-controlled text (helper stderr, paths) for a message: no control characters."""
    return ''.join(ch if ch.isprintable() else '?' for ch in text)


def _count(value):
    return type(value) is int and value >= 0


def _mounts_ok(data):
    mounts = data['mounts']
    return (type(data['mount_root']) is bool and _count(data['more_mounts']) and isinstance(mounts, list)
            and len(mounts) <= 16 and all(isinstance(item, str) and 0 < len(item) <= 300 for item in mounts))


STATE_TYPES = ('dir', 'missing', 'link', 'other', 'blocked')
STATE_KEYS = {'path', 'type', 'empty', 'mount', 'dev', 'free', 'siblings', 'more'}


def _state_ok(row):
    """One row of the `state` answer, checked field by field (review M1)."""
    if not isinstance(row, dict) or set(row) != STATE_KEYS or row['type'] not in STATE_TYPES:
        return False
    if not (row['empty'] is None or type(row['empty']) is bool) or type(row['mount']) is not bool \
            or not _count(row['more']):
        return False
    if not all(row[key] is None or _count(row[key]) for key in ('dev', 'free')):
        return False
    siblings = row['siblings']
    return isinstance(siblings, list) and len(siblings) <= 64 and all(
        isinstance(item, dict) and set(item) == {'kind', 'token', 'type'} and item['kind'] in ('new', 'old', 'del')
        and isinstance(item['token'], str) and TOKEN_RE.fullmatch(item['token']) and item['type'] in ('dir', 'other')
        for item in siblings)
