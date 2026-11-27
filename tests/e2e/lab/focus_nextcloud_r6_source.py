#!/usr/bin/env python3
"""Source-only R6 engine transaction. Import/default performs no lab I/O.

Stream only the frozen engine/helper/VERSION, never invoke manage.py or apt.
Prior installations move intact into new root-protected SAME-filesystem leaves.
No extraction API, links, foreign destinations, repeated names or loose hashes.
The caller holds the device mutex and owns the lease and cold-unit gates.
"""
import contextlib
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import time

# The integrated engine (PR #23 head): ha_nextcloud.py is byte-identical to the fix 6daaa15c
FROZEN = Path('/tmp/parity-focus-nc-product-5168f1ec')
PRODUCT_COMMIT = '5168f1ecf68e3a22b6909f3c516c4a41e77e3cc2'
NC_SHA = 'bcc39687e4828c25c4f336f527e57cc7ca13429d35870bbed88abcee4d817d1c'
MAX_FILE = 2 * 1024**2
MAX_TOTAL = 16 * 1024**2
FLOOR = 13 * 1024**3 + 512 * 1024**2
LIBNAME = 'woowtech-cockpit-backup'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()


def manifest_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def allowed(name):
    return (name in ('VERSION', 'helper') or
            re.fullmatch(r'woowbackup/(?:[a-z_][a-z_0-9]*/)*[a-z_][a-z_0-9]*\.py', name) is not None)


def validate_manifest(rows):
    if not isinstance(rows, dict) or not 3 <= len(rows) <= 512:
        raise ValueError('fixed-source-manifest-refused')
    for name, row in rows.items():
        if (not allowed(name) or not isinstance(row, dict) or set(row) != {'size', 'sha256'}
                or type(row['size']) is not int or not 0 < row['size'] <= MAX_FILE
                or not isinstance(row['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['sha256'])):
            raise ValueError('fixed-source-manifest-entry-refused')
    if not {'helper', 'VERSION', 'woowbackup/__init__.py', 'woowbackup/cli.py'} <= set(rows):
        raise ValueError('fixed-source-manifest-incomplete')
    if sum(row['size'] for row in rows.values()) > MAX_TOTAL:
        raise ValueError('fixed-source-payload-bound-refused')


def frozen_manifest(source=FROZEN):
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=source, text=True).strip()
    if commit != PRODUCT_COMMIT or dirty:
        raise ValueError('fixed-frozen-clean-product-required')
    paths = {'helper': source / 'backup-engine/woowtech-cockpit-backup', 'VERSION': source / 'VERSION'}
    package = source / 'backup-engine/woowbackup'
    for p in sorted(package.rglob('*')):
        if '__pycache__' in p.parts:
            continue
        if p.is_symlink():
            raise ValueError('fixed-source-link-refused')
        if p.is_file():
            paths['woowbackup/' + p.relative_to(package).as_posix()] = p
    rows = {}
    for name, p in paths.items():
        s = p.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
            raise ValueError('fixed-source-regular-file-required')
        rows[name] = {'size': s.st_size, 'sha256': digest(p)}
    validate_manifest(rows)
    if rows['woowbackup/ha_nextcloud.py']['sha256'] != NC_SHA:
        raise ValueError('fixed-frozen-nextcloud-sha-required')
    return paths, rows


def secure_dir(path, uid=0):
    for p in [path, *path.parents]:
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != uid or s.st_mode & 0o022:
            raise ValueError('fixed-source-trusted-parent-required')


def tree_snapshot(path, uid=0):
    """All bytes/attributes, including prior VERSION and any existing pycache."""
    out = {}
    for p in [path, *sorted(path.rglob('*'))]:
        s = p.lstat()
        if s.st_uid != uid or s.st_mode & 0o022 or os.listxattr(p):
            raise ValueError('fixed-source-prior-ownership-refused')
        row = {'uid': s.st_uid, 'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode), 'mtime_ns': s.st_mtime_ns}
        if stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= MAX_FILE:
            row.update(size=s.st_size, sha256=digest(p))
        elif stat.S_ISDIR(s.st_mode):
            row['directory'] = True
        else:
            raise ValueError('fixed-source-prior-link-or-type-refused')
        out[p.relative_to(path).as_posix()] = row
    if sum(x.get('size', 0) for x in out.values()) > MAX_TOTAL:
        raise ValueError('fixed-source-prior-bound-refused')
    return out


def receive(stream, manifest, newlib, newhelper, check):
    """Caller passes new empty protected directories, tar streams bounded members."""
    validate_manifest(manifest)
    seen = set()
    with tarfile.open(fileobj=stream, mode='r|') as archive:
        for member in archive:
            name = member.name
            if (name not in manifest or name in seen or not member.isreg() or member.pax_headers
                    or member.linkname or member.size != manifest[name]['size']):
                raise ValueError('fixed-source-tar-member-refused')
            seen.add(name)
            target = newhelper if name == 'helper' else newlib / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            parent=target.parent
            while parent!=newlib and parent!=newhelper.parent:
                os.chmod(parent,0o755);parent=parent.parent
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755 if name == 'helper' else 0o644)
            h = hashlib.sha256(); count = 0
            os.fchmod(fd,0o755 if name=='helper' else 0o644)
            with os.fdopen(fd, 'wb') as out, archive.extractfile(member) as source:
                while True:
                    check()
                    block = source.read(min(1024**2, member.size - count + 1))
                    if not block:
                        break
                    count += len(block)
                    if count > member.size:
                        raise ValueError('fixed-source-member-bound-refused')
                    h.update(block); out.write(block)
                out.flush(); os.fsync(out.fileno())
            if count != member.size or h.hexdigest() != manifest[name]['sha256']:
                raise ValueError('fixed-source-byte-hash-refused')
    if seen != set(manifest):
        raise ValueError('fixed-source-missing-member-refused')
    with newhelper.open('rb') as f:
        if f.readline(128) != b'#!/usr/bin/python3 -I\n':
            raise ValueError('fixed-source-isolated-helper-required')


@contextlib.contextmanager
def mutation_locks(run=Path('/run/woowtech-backup'), jobs=Path('/var/lib/woowtech-backup/jobs'), uid=0):
    secure_dir(run,uid=uid)
    held=[]
    try:
        # Same native order as jobs.start_lock -> acquire_engine_lock, NEVER wait on a live writer.
        for name in ('jobs.lock','engine.lock'):
            fd=os.open(run/name,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
            held.append(fd);st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_uid!=uid or st.st_mode&0o022:
                raise ValueError('fixed-source-native-lock-file-refused')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        p=subprocess.run(['/usr/local/bin/woowbk-owner','systemctl','--user','show',
                          'woowtech-backup-schedule.timer','woowtech-backup-schedule.service','--property=ActiveState','--value'],
                         stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
        if p.returncode or p.stdout.split()!=[b'inactive',b'inactive']:
            raise ValueError('fixed-source-original-schedule-not-inactive')
        count=0
        for p in jobs.glob('j*.json'):
            st=p.lstat();count+=1
            if count>1000 or not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>1048576:
                raise ValueError('fixed-source-job-record-refused')
            with p.open() as f: row=json.load(f)
            if row.get('state') in ('queued','running'):
                raise ValueError('fixed-source-native-job-active')
        yield
    finally:
        for fd in reversed(held):os.close(fd)


def device_transaction(action, nonce, manifest, expires, libparent=Path('/usr/local/lib'),
                       helperparent=Path('/usr/local/libexec')):
    import shutil
    if not re.fullmatch('[0-9a-f]{16}', nonce):
        raise ValueError('fixed-source-transaction-name-refused')
    secure_dir(libparent); secure_dir(helperparent)
    lib = libparent / LIBNAME; helper = helperparent / LIBNAME
    own = libparent / ('.focus-nextcloud-r6-' + nonce)
    helperown = helperparent / ('.focus-nextcloud-r6-' + nonce)
    def check():
        if time.time() >= expires or min(shutil.disk_usage('/home').free, shutil.disk_usage('/var/lib').free) < FLOOR:
            raise ValueError('fixed-source-resource-or-expiry-refused')
    def save(row):
        p = own / 'transaction.json'
        with (own / 'transaction.new').open('x') as f:
            json.dump(row, f, sort_keys=True); f.flush(); os.fsync(f.fileno())
        os.replace(own / 'transaction.new', p)
        fd=os.open(own,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        try:os.fsync(fd)
        finally:os.close(fd)
    if action == 'install':
        check(); validate_manifest(manifest)
        prior = {'library': tree_snapshot(lib), 'helper': tree_snapshot(helper)}
        # These parents are on each destination's filesystem. NEVER rename across /var/lib mounts.
        own.mkdir(mode=0o700); helperown.mkdir(mode=0o700)
        newlib = own / 'new-library'; newlib.mkdir(mode=0o755);newlib.chmod(0o755)
        newhelper = helperown / 'new-helper'
        row = {'nonce': nonce, 'state': 'preparing', 'prior': prior, 'manifest_sha256': manifest_hash(manifest)}
        save(row)
        receive(sys.stdin.buffer, manifest, newlib, newhelper, check)
        new = {'library': tree_snapshot(newlib), 'helper': tree_snapshot(newhelper)}
        row = {'nonce': nonce, 'state': 'prepared', 'prior': prior, 'new': new,
               'manifest_sha256': manifest_hash(manifest)}
        save(row); check()
        with mutation_locks():
            if tree_snapshot(lib) != prior['library'] or tree_snapshot(helper) != prior['helper']:
                raise ValueError('fixed-source-prior-changed-before-rename')
            # Journal is durable BEFORE each potential partial rename. A failure never deletes either copy.
            row['state'] = 'installing'; save(row)
            os.rename(lib, own / 'prior-library')
            os.rename(newlib, lib)
            os.rename(helper, helperown / 'prior-helper')
            os.rename(newhelper, helper)
            if tree_snapshot(lib) != new['library'] or tree_snapshot(helper) != new['helper']:
                raise ValueError('fixed-source-installed-hash-mismatch')
            row['state'] = 'installed'; save(row)
    else:
        if action not in ('restore', 'inspect'):
            raise ValueError('fixed-source-action-refused')
        secure_dir(own); secure_dir(helperown)
        with (own / 'transaction.json').open() as f:
            row = json.load(f)
        if row['nonce'] != nonce or row['state'] not in ('preparing', 'prepared', 'installing', 'installed', 'restoring', 'restored'):
            raise ValueError('fixed-source-journal-state-refused')
        if action == 'restore':
            with mutation_locks():
                if action == 'restore' and row['state'] in ('preparing','prepared'):
                    if tree_snapshot(lib) != row['prior']['library'] or tree_snapshot(helper) != row['prior']['helper']:
                        raise ValueError('fixed-source-unprepared-current-changed')
                    row['state'] = 'restored'; save(row)
                if action == 'restore' and row['state'] != 'restored':
                    # Handle interrupted installs/restores only when every existing path matches a proven copy.
                    for current, original, unused, prior, new in (
                            (lib, own/'prior-library', own/'restored-new-library', row['prior']['library'], row['new']['library']),
                            (helper, helperown/'prior-helper', helperown/'restored-new-helper', row['prior']['helper'], row['new']['helper'])):
                        if original.exists():
                            if tree_snapshot(original) != prior:
                                raise ValueError('fixed-source-prior-copy-changed')
                            if current.exists() and tree_snapshot(current) != new:
                                raise ValueError('fixed-source-current-foreign-edit')
                            if unused.exists() and (current.exists() or tree_snapshot(unused) != new):
                                raise ValueError('fixed-source-restore-destination-exists')
                        elif not current.exists() or tree_snapshot(current) != prior:
                            raise ValueError('fixed-source-prior-location-ambiguous')
                    row['state'] = 'restoring'; save(row)
                    for current, original, unused in ((lib,own/'prior-library',own/'restored-new-library'),
                                                      (helper,helperown/'prior-helper',helperown/'restored-new-helper')):
                        if original.exists():
                            if current.exists(): os.rename(current, unused)
                            os.rename(original, current)
                    row['state'] = 'restored'; save(row)
                if action == 'restore' and (tree_snapshot(lib) != row['prior']['library'] or tree_snapshot(helper) != row['prior']['helper']):
                    raise ValueError('fixed-source-exact-prior-return-failed')
    return {'status': row['state'], 'manifest_sha256': row['manifest_sha256'],
            'prior_sha256': manifest_hash(row['prior']), 'transaction_leaf': str(own),
            'helper_transaction_leaf': str(helperown), 'prior_copies_or_restored_originals_retained': True}


def program():
    header = ('import contextlib,fcntl,hashlib,json,os,pathlib,re,stat,subprocess,sys,tarfile,time\nfrom pathlib import Path\n'
              + repr_constants() + '\n')
    funcs = (digest, manifest_hash, allowed, validate_manifest, secure_dir, tree_snapshot, receive, mutation_locks, device_transaction)
    return header + '\n'.join(inspect.getsource(f) for f in funcs) + '''
try:
 action,nonce,expires,encoded=sys.argv[1:]
 result=device_transaction(action,nonce,json.loads(encoded),float(expires))
 print(json.dumps(result))
except Exception as error:
 reason=str(error) if isinstance(error,ValueError) and str(error).startswith('fixed-source-') else 'fixed-source-transaction-failed'
 print(json.dumps({'status':'failed','fixed_failure':reason}));sys.exit(2)
'''


def repr_constants():
    return '\n'.join(k + '=' + repr(v) for k,v in (('MAX_FILE',MAX_FILE),('MAX_TOTAL',MAX_TOTAL),('FLOOR',FLOOR),('LIBNAME',LIBNAME)))


def transact(action, nonce, paths, manifest, expires):
    lp = Path.home()/'.woowbk-lab/bin/labpodman'
    argv = [str(lp),'exec','-i','woowbk-dev-e','python3','-I','-c',program(),
            action,nonce,str(expires),json.dumps(manifest,separators=(',',':'))]
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        if action == 'install':
            with tarfile.open(fileobj=p.stdin,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
                for name in sorted(manifest):
                    info=tarfile.TarInfo(name);info.size=manifest[name]['size'];info.mode=0o644
                    with paths[name].open('rb') as f: archive.addfile(info,f)
        p.stdin.close();p.stdin=None
        out,_=p.communicate(timeout=300)
        if len(out)>65536: raise RuntimeError('fixed-source-result-bound-refused')
        result=json.loads(out)
        if p.returncode: raise RuntimeError(result.get('fixed_failure','fixed-source-transaction-failed'))
        return result
    finally:
        if p.stdin is not None: p.stdin.close()
        if p.poll() is None:
            # Closing stdin lets the bounded inside-device writer finish/refuse first.
            p.wait(timeout=330)


if __name__=='__main__':
    print('offline source transaction preparation; no devices or credentials accessed')
