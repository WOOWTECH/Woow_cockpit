#!/usr/bin/env python3
"""CODE ONLY until separately leased: build a genuine, small Nextcloud server-side-encryption (SSE) source fixture.

S5-A of the Nextcloud R6 lane: a generated HA-shaped TEST fixture, never an HAOS export, never S5 import acceptance.
Inside woowbk-dev-e, from the three already loaded original images (Nextcloud 35.0.1, pgvector PG16, Redis 8.10.1), a
NEW owned Nextcloud is installed by the image's own entrypoint; one file is written through WebDAV while encryption does
not exist yet, the shipped encryption app is enabled in its default master-key mode, two files are written encrypted, all
three are read back before and after a restart, the cluster is stopped cleanly and the cold source is packed. Default
invocation prints the contract, --lease-template the lease fields this checkout binds; --run needs an exact fresh lease,
the heavy seat and the whole dev-e mutex. No target install, wake, restore or import; no pulls.

What it relies on in Nextcloud (nextcloud/server tag v35.0.1 unless named otherwise):
- nextcloud/docker docker-entrypoint.sh 226-228, 262-267: the data directory is only handed to `occ maintenance:install
  --data-dir` (run as www-data through run_as/su), never created or chowned, and Setup.php:352 needs it writable: the
  owned /share/nextcloud and /var/www/html are given to the image's own www-data before the first start (no :U).
- Setup.php:489-500 + apps/files/lib/Listener/UserFirstTimeLoggedInListener.php:38-40: the installer's admin login copies
  the skeleton (example-files stable35: 63 files, 35,234,605 bytes) before encryption exists: plaintext, and the reason
  the data cap is 128 MiB.
- apps/encryption/lib/Util.php:66-67: master-key mode is the default (useMasterKey unset = true); Command/
  EnableMasterKey.php:39-43 then prints only "Master key already enabled" and writes nothing (stdin is not a terminal, so
  a confirmation would be declined): exactly that output is required, useMasterKey may stay unset.
- KeyManager.php:42-62, Users/Setup.php:44-48, AppInfo/Application.php:71-75: masterKeyId ('master_' + 8 hex) and the
  master and public-share key pairs appear when the key manager is first built: read only after the first encrypted write.
- Crypto/Encryption.php:173-181, 215-244, lib/private/Encryption/Util.php:97-112, Crypto/Crypt.php:45,60: a new file gets
  an 8192-byte '-'-padded header (HEADER below), one share key per recipient (master-key mode: <masterKeyId>.shareKey)
  and no fileKey (deleteLegacyFileKey).
- lib/private/Encryption/Keys/Storage.php:194-197,330, Encryption/Util.php:357-368, Security/Crypto.php:100: system keys
  are files_encryption/OC_DEFAULT_MODULE/<id>.<publicKey|privateKey>, share keys <user>/files_encryption/keys/files/
  <path>/OC_DEFAULT_MODULE/<id>.shareKey, and every key file is "hex ciphertext|hex iv|hex hmac|3".
- lib/private/Files/Storage/Wrapper/Encryption.php:326-381: a file without a header that is not marked encrypted is read
  as it is: the file written before encryption stays plaintext and readable (a mixed source).
"""
import argparse
import base64
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import traceback

GIB, MIB = 1024**3, 1024**2
PHASE = 's5-source-fixture-build'
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
RESERVE = 13*GIB
FLOOR = RESERVE+512*MIB                 # the watch stops below this much free space
DEVICE_CAP = 3*GIB
MEMORY_WATCH = DEVICE_CAP-512*MIB       # ... and above this device memory.current
CAPS = {'nc': 900*MIB, 'pg': 256*MIB, 'redis': 64*MIB}
HELPER_MEMORY = 64*MIB                  # the www-data id probe and the read-only pg_controldata run (never together)
DISK_CAPS = {'html': 2*GIB, 'pg': 512*MIB, 'data': 128*MIB}   # apparent bytes of each owned source dir
OWNED_CAP = 7*GIB                       # everything this run allocates (source, members, fixture, records)
FIXTURE_CAP = GIB
START_FREE = 20*GIB
CLEANUP_GRACE = 600
HEADROOM = 1800                         # lease seconds still left once the dev-e mutex is held
PROBE_TRIES = 3                         # failed or timed-out probes in a row before the watch stops (fullshare04)
DU_EVERY, DU_TIMEOUT = 10, 15
# --cpus only when the owner's user manager has the cgroup v2 cpu controller (the product's tempctr.default_cpus rule:
# without it every podman run with --cpus fails).
CONTROLLERS = '/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers'
IMAGES = {
    'nc': 'e80170f48ac2534abd0960be4838dbe9fcdc498da924a62f2436cd470dab4165',
    'pg': '9b05db12a35460fff0587e009f9326e414a53e9484555547f96d214a2ba98ef7',
    'redis': 'd1e21a26915a35a6eb5d820018cd55adfcda02e02f7d629e1f42df397d5494ad',
}
# The engine dev-e runs: deploy-src.sh (OpenDesign flow) installed commit 4cf97c25. Its expected bytes come from this
# repository's git objects (engine_manifest), never from a device.
ENGINE_COMMIT = '4cf97c2507d5c0fc28905717efe387ee4d6b19f7'
PRODUCT_LIB = '/usr/local/lib/woowtech-cockpit-backup'   # device only: the installed engine, proven equal to ENGINE_COMMIT
SLUG = 'woow-nextcloud-office'
PROFILE = '0.2.3'  # envelope compatibility profile, NOT an installed add-on version
VERSION = '35.0.1.1'
MAX_MEMBERS = 50000
USER = 's5owner'
ROOT_RE = r'/var/lib/woowbk-nextcloud-s5-[0-9a-f]{16}'
MODULE = 'OC_DEFAULT_MODULE'
HEADER_SIZE = 8192
HEADER = {'oc_encryption_module': MODULE, 'cipher': 'AES-256-CTR', 'signed': 'true', 'useLegacyFileKey': 'false',
          'encoding': 'binary'}
MASTER_RE = r'master_[0-9a-f]{8}'
KEY_RE = re.compile(rb'(?:[0-9a-f]{2})+\|[0-9a-f]{32}\|[0-9a-f]+\|3')
OWNED_LEAVES = ('html', 'pg', 'data', 'artifact', 'credentials.private.json')
# The reviewed shape of every occ command this builder runs: what `occ help --format=json <command>` (Symfony's
# JsonDescriptor) must say, taken from the v35.0.1 sources (core/Command/Status.php:31-41, App/ListApps.php:25-50,
# App/Enable.php:39-57, Config/App/GetConfig.php:24-53, Encryption/{Enable,Status,ListModules,SetDefaultModule}.php,
# apps/encryption/lib/Command/EnableMasterKey.php:33-34; the output option: core/Command/Base.php:37-43). Arguments are
# [required, array], options [shortcut, accepts a value, value required, multiple, default]. The console's own options
# (Symfony's and lib/private/Console/Application.php:60-68 no-warnings) are left out by name.
OCC_GLOBAL = frozenset({'help', 'silent', 'quiet', 'verbose', 'version', 'ansi', 'no-ansi', 'no-interaction',
                        'no-warnings'})
_OUTPUT = ['', True, False, False, 'plain']
_FLAG = ['', False, False, False, False]
OCC_CONTRACT = {
    'status': {'description': 'show some status information', 'arguments': {},
               'options': {'output': _OUTPUT, 'exit-code': ['-e', False, False, False, False]}},
    'app:list': {'description': 'List all available apps', 'arguments': {},
                 'options': {'output': _OUTPUT, 'shipped': ['', True, True, False, None], 'enabled': _FLAG,
                             'disabled': _FLAG}},
    'app:enable': {'description': 'enable an app', 'arguments': {'app-id': [True, True]},
                   'options': {'groups': ['-g', True, True, True, []], 'force': ['-f', False, False, False, False]}},
    'config:app:get': {'description': 'Get an app config value', 'arguments': {'app': [True, False], 'name': [True, False]},
                       'options': {'output': _OUTPUT, 'details': _FLAG, 'key-details': _FLAG,
                                   'default-value': ['', True, False, False, None]}},
    'encryption:list-modules': {'description': 'List all available encryption modules', 'arguments': {},
                                'options': {'output': _OUTPUT}},
    'encryption:set-default-module': {'description': 'Set the encryption default module',
                                      'arguments': {'module': [True, False]}, 'options': {}},
    'encryption:status': {'description': 'Lists the current status of encryption', 'arguments': {},
                          'options': {'output': _OUTPUT}},
    'encryption:enable': {'description': 'Enable encryption', 'arguments': {}, 'options': {}},
    'encryption:enable-master-key': {
        'description': ('Enable the master key. Only available for fresh installations with no existing encrypted data! '
                        'There is also no way to disable it again.'),
        'arguments': {}, 'options': {}},
}
OCC_AFTER_APP = ('encryption:enable-master-key',)   # shipped by the encryption app: there only once it is enabled
OCC_BEFORE_APP = tuple(c for c in OCC_CONTRACT if c not in OCC_AFTER_APP)

STORE_SNAPSHOT = r'''
import json,subprocess
commands={'containers':['ps','-a','--no-trunc','--format','{{.ID}} {{.Names}} {{.ImageID}} {{.State}}'],
 'volumes':['volume','ls','--format','{{.Name}}'],
 'networks':['network','ls','--no-trunc','--format','{{.ID}} {{.Name}}'],
 'secrets':['secret','ls','--format','{{.ID}} {{.Name}}']}
out={}
for key,args in commands.items():
 p=subprocess.run(['podman',*args],capture_output=True,timeout=30)
 assert p.returncode==0 and len(p.stdout)<=262144
 out[key]=sorted(p.stdout.decode().splitlines())
print(json.dumps(out))
'''
# As root: the installed engine, as the same {name: sha256} engine_manifest computes from git.
ENGINE_PROGRAM = r'''
import hashlib,json,os,stat
from pathlib import Path
def regular(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==0 and not s.st_mode&0o022 and s.st_size<=2097152
  raw=f.read(2097153)
 assert len(raw)==s.st_size
 return hashlib.sha256(raw).hexdigest()
lib=Path('/usr/local/lib/woowtech-cockpit-backup');out={}
for directory,dirs,files in os.walk(lib/'woowbackup'):
 dirs[:]=sorted(d for d in dirs if d!='__pycache__')
 for name in sorted(files):
  p=Path(directory)/name;out['lib/'+p.relative_to(lib).as_posix()]=regular(p)
out['lib/VERSION']=regular(lib/'VERSION')
out['helper']=regular(Path('/usr/local/libexec/woowtech-cockpit-backup'))
assert len(out)<=256
print(json.dumps(out,sort_keys=True))
'''
# As root: every entry of the backup store's own folders (identity only). Equal before and after = untouched.
TARGET_STATE = r'''
import json,stat
from pathlib import Path
out={}
for name in ('archives','ha-backups','uploads','jobs'):
 root=Path('/var/lib/woowtech-backup')/name;rows=[]
 if root.exists():
  s=root.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
  for number,p in enumerate(sorted(root.iterdir())):
   assert number<2000
   t=p.lstat();rows.append([p.name,t.st_mode,t.st_uid,t.st_gid,t.st_nlink,t.st_size,t.st_mtime_ns,t.st_ctime_ns,t.st_ino])
 out[name]=rows
print(json.dumps(out))
'''
PROVISION = r'''
import json,os,pathlib,pwd,stat,sys
q=json.load(sys.stdin);p=pathlib.Path(q['root']);s=p.parent.lstat()
assert p.parent==pathlib.Path('/var/lib') and stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
assert not p.exists() and not p.is_symlink()
p.mkdir(mode=0o711);owner=pwd.getpwnam('appowner');d=p/'owned';d.mkdir(mode=0o700);os.chown(d,owner.pw_uid,owner.pw_gid)
print(json.dumps({'status':'created'}))
'''
# As appowner: what is left in the owned work dir (names only).
OWNED_LISTING = r'''
import json,os,re,sys
q=json.load(sys.stdin);assert re.fullmatch(r'/var/lib/woowbk-nextcloud-s5-[0-9a-f]{16}',q['root'])
names=sorted(os.listdir(q['root']+'/owned'))
art=q['root']+'/owned/artifact'
print(json.dumps({'leaves':[n for n in names if not n.startswith('command-')],
 'command_records':sum(n.startswith('command-') for n in names),
 'artifact':sorted(os.listdir(art)) if os.path.isdir(art) else None}))
'''


def require(ok, reason):
    if not ok:
        raise ValueError('fixed-s5-'+reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def manifest_hash(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def digest(path, check=lambda: None, limit=GIB):
    h = hashlib.sha256(); count = 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
                'regular-bounded-file-required')
        for block in iter(lambda: f.read(MIB), b''):
            check(); count += len(block); require(count <= limit, 'file-bound'); h.update(block)
        require(count == before.st_size and identity(os.fstat(f.fileno())) == identity(before)
                and identity(Path(path).lstat()) == identity(before), 'file-changed')
    return h.hexdigest()


def private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, sort_keys=True); f.flush(); os.fsync(f.fileno())


def small(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= limit, 'small-file-bound')
        value = f.read(limit+1)
        require(len(value) <= limit and identity(os.fstat(f.fileno())) == identity(st), 'small-file-changed')
        return value


def bounded(argv, timeout, limit=4096):
    """A short probe in its own session; on a timeout the whole group is killed and reaped (TimeoutExpired is raised)."""
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL); p.communicate(); raise
    require(len(out) <= limit, 'probe-output-bound')
    return p.returncode, out


def native_program(code):
    # A -c program otherwise has __name__ == '__main__' and would run the host CLI.
    return "__name__='focus_nextcloud_r6_s5_native'\n"+code+'\ninternal_main(json.load(sys.stdin))\n'


def plaintexts():
    """The known files: one written while encryption does not exist yet, two written once it is enabled."""
    return {'before': {'s5-before-encryption.txt': ('S5 plaintext written before server-side encryption was enabled\n'
                                                    * 400).encode()},
            'encrypted': {'s5-binary.bin': bytes(range(256))*4096, 's5-utf8.txt': ('真實加密來源驗證\n'*2048).encode()}}


def product(lib=PRODUCT_LIB):
    # DEVICE ONLY: the installed reader (proven equal to ENGINE_COMMIT before and after) as a library. Offline tests pass
    # this repository's engine to build_fixture instead. No bytecode anywhere.
    sys.dont_write_bytecode = True
    sys.path.insert(0, lib)
    from woowbackup import habackup, ha_nextcloud, ha_odoo
    return habackup, ha_nextcloud, ha_odoo


def tree(root, check=lambda: None, limit=GIB):
    """Cold owned tree; reject links, special files, hardlinks and changing paths."""
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), 'source-root')
    rows = {}; total = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs+files):
            check(); p = Path(directory)/name; s = p.lstat(); rel = p.relative_to(root).as_posix()
            require(all(x not in ('', '.', '..') for x in rel.split('/')) and len(rel) <= 4096
                    and not any(ord(c) < 32 for c in rel), 'source-name')
            require(stat.S_ISDIR(s.st_mode) or (stat.S_ISREG(s.st_mode) and s.st_nlink == 1), 'source-link-or-special')
            total += s.st_size if stat.S_ISREG(s.st_mode) else 0
            require(len(rows) < MAX_MEMBERS and total <= limit, 'source-tree-bound')
            rows[rel] = {'stat': list(identity(s)), 'bytes': s.st_size if p.is_file() else 0,
                         'sha256': digest(p, check, limit) if p.is_file() else None}
    return rows


class HashedReader:
    """tarfile may request arbitrary sizes; never read more than one MiB."""
    def __init__(self, stream, check):
        self.stream, self.check, self.hash = stream, check, hashlib.sha256()

    def read(self, size):
        require(0 <= size <= MIB, 'stream-read-bound')
        self.check(); block = self.stream.read(size); self.hash.update(block)
        return block


def pack_tree(out, root, prefix, rows, check):
    for rel, row in sorted(rows.items()):
        check(); p = root/rel; require(list(identity(p.lstat())) == row['stat'], 'cold-source-changed')
        s = p.lstat(); m = tarfile.TarInfo(prefix+'/'+rel)
        m.uid, m.gid, m.mode, m.mtime = s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_mtime
        if stat.S_ISDIR(s.st_mode):
            m.type = tarfile.DIRTYPE; out.add_member(m)
        else:
            m.size = row['bytes']; fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as f:
                require(list(identity(os.fstat(f.fileno()))) == row['stat'], 'cold-source-changed')
                reader = HashedReader(f, check); out.add_member(m, reader)
                require(reader.hash.hexdigest() == row['sha256'] and
                        list(identity(os.fstat(f.fileno()))) == row['stat'], 'cold-source-changed')
        require(list(identity(p.lstat())) == row['stat'], 'cold-source-changed')


def add_json(out, name, value):
    raw = json.dumps(value, sort_keys=True).encode(); m = tarfile.TarInfo(name)
    m.mode, m.size = 0o600, len(raw); out.add_member(m, io.BytesIO(raw))


def build_fixture(work, proof, check=lambda: None, libraries=None):
    """Run in podman unshare after all source containers stopped cleanly.

    Actual config/custom_apps/PG/data are copied byte-for-byte. No rewritten PHP,
    SQL, encryption flags, paths inside config, fabricated app or synthetic key.
    All data (including every generated key file) goes into the share member.
    `libraries`: (habackup, ha_nextcloud, ha_odoo); the device uses the installed engine (product()).
    """
    ha, nc, od = (libraries or product)(); work = Path(work); out = work/'artifact'
    out.mkdir(mode=0o700, exist_ok=False)
    mappings = {'config': ('html/config', 'data/nextcloud/config', 'addon'),
                'apps': ('html/custom_apps', 'data/nextcloud/custom_apps', 'addon'),
                'pg': ('pg', 'data/postgres', 'addon'), 'data': ('data', 'nextcloud', 'share')}
    rows = {role: tree(work/src, check) for role, (src, _, _) in mappings.items()}
    require(sum(r['bytes'] for rs in rows.values() for r in rs.values()) < GIB-4*MIB, 'fixture-input-bound')
    require(all(proof.get(k) is True for k in ('webdav_before', 'webdav_after_restart', 'plaintext_before_encryption',
                                               'master_key_mode', 'pg_shutdown')), 'native-source-proof-incomplete')
    for name, value in proof['cipher_and_keys'].items():
        require(name in rows['data'] and rows['data'][name]['sha256'] == value['sha256']
                and rows['data'][name]['bytes'] == value['bytes'] > 0, 'cipher-key-source-binding')
    require(rows['pg'].get('PG_VERSION', {}).get('sha256') == sha(b'16\n'), 'pg16-required')
    require('postmaster.pid' not in rows['pg'] and '.ncdata' in rows['data'], 'cold-pg-and-ncdata-required')
    provenance = {'kind': 'generated-ha-shaped-test-fixture', 'haos_export': False,
                  'compatibility_profile': {'slug': SLUG, 'addon_version': PROFILE},
                  'actual_components': {'nextcloud': VERSION, 'postgres_major': '16',
                                        'images': IMAGES, 'architecture': 'amd64'},
                  'native_proof': proof, 'mappings': mappings, 'source_files': rows}
    metadata = {'version': PROFILE, 'state': 'stopped',
                'system': {'slug': SLUG, 'name': 'Generated Nextcloud SSE test fixture'},
                # Actual cached image identity; unknown HA image-name architecture is truthful.
                'user': {'image': 'sha256:'+IMAGES['nc'], 'options': {}},
                'generated_fixture': {'haos_export': False, 'compatibility_profile_only': True}}
    members = {}
    for kind, name in (('addon', SLUG+'.tar'), ('share', 'share.tar')):
        member = out/name; writer = od.FileTar(member)
        try:
            if kind == 'addon': add_json(writer, 'addon.json', metadata)
            for role, (src, prefix, component) in mappings.items():
                if component == kind: pack_tree(writer, work/src, prefix, rows[role], check)
        finally:
            writer.close()
        require(member.stat().st_size <= GIB, 'member-bound')
        members[name] = {'bytes': member.stat().st_size, 'sha256': digest(member, check)}
    source_mapping_sha = sha(json.dumps(provenance, sort_keys=True).encode())
    doc = {'version': 2, 'slug': 'generated-s5-source', 'name': 'Generated SSE source test fixture (not HAOS export)',
           'date': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'type': 'partial',
           'compressed': False, 'protected': False, 'repositories': [], 'folders': ['share'],
           'addons': [{'slug': SLUG, 'name': metadata['system']['name'], 'version': PROFILE}],
           'extra': {'generated_test_fixture': True, 'haos_export': False,
                     'source_mapping_sha256': source_mapping_sha}}
    dest = out/'generated-s5-source.tar'; writer = od.FileTar(dest)
    try:
        for name, row in members.items():
            check(); m = tarfile.TarInfo(name); m.mode, m.size = 0o600, row['bytes']
            with (out/name).open('rb') as f: writer.add_member(m, HashedReader(f, check))
        add_json(writer, './backup.json', doc)
    finally:
        writer.close()
    require(dest.stat().st_size <= FIXTURE_CAP, 'fixture-bound')
    # Strict product reader verifies all headers/trailers and the exact full mapping.
    with ha.open_backup(dest) as opened:
        require(len(opened.layout.members) == 2 and all(not m.problem for m in opened.layout.members), 'outer-layout')
        for kind, member in (('addon', SLUG), ('share', 'share')):
            report = ha.Report(); seen = {}
            with opened.open_addon(member) if kind == 'addon' else opened.open_member('share.tar') as stream:
                for e in ha.iter_entries(stream, ha.Select(max_bytes=GIB, max_members=MAX_MEMBERS), report,
                                         checkpoint=check):
                    if e.kind == 'file':
                        h = hashlib.sha256()
                        while True:
                            block = e.read(MIB)
                            if not block: break
                            check(); h.update(block)
                        seen[e.name] = h.hexdigest()
                    else: require(e.kind == 'dir', 'unexpected-packed-type')
            expected = {prefix+'/'+rel: r['sha256'] for role, (_, prefix, component) in mappings.items()
                        if component == kind for rel, r in rows[role].items() if r['sha256'] is not None}
            require(report.complete and not report.skipped_symlinks and not report.skipped_other
                    and seen == expected, 'packed-mapping-mismatch')
        with opened.open_addon(SLUG) as stream:
            report = ha.Report(); source = nc.scan_member(stream, report, machine=0x3e, checkpoint=check)
        require(report.complete and source.pg_version == '16' and source.recovery_files == 0
                and source.config and source.config.get('version') == VERSION
                and source.config.get('datadirectory') == '/share/nextcloud'
                and source.config.get('installed') is True and source.config.get('dbtype') == 'pgsql'
                and source.config.get('dbtableprefix') == 'oc_', 'native-config-layout')
        with opened.open_member('share.tar') as stream:
            report = ha.Report(); data = nc.scan_datadir(stream, report, 'nextcloud', addon=False,
                                                       instanceid=source.config.get('instanceid'), checkpoint=check)
        require(report.complete and data.present and data.ncdata and data.encryption and not data.symlinks
                and not data.htaccess, 'native-data-layout')
    # A cold source must still be the same after every consuming pass.
    for role, (src, _, _) in mappings.items(): require(tree(work/src, check) == rows[role], 'source-changed-after-pack')
    provenance['source_mapping_sha256'] = source_mapping_sha
    provenance['members'] = members
    provenance['archive'] = {'bytes': dest.stat().st_size, 'sha256': digest(dest, check)}
    private(out/'provenance.private.json', provenance)
    # Exact owned temporary members only. Keep the one fixture + immutable provenance.
    for name, row in members.items():
        require(digest(out/name, check) == row['sha256'], 'member-changed-before-unlink'); (out/name).unlink()
    return {'status': 'passed', 'kind': provenance['kind'], 'haos_export': False,
            'archive': str(dest), **provenance['archive'],
            'provenance_sha256': digest(out/'provenance.private.json', check),
            'source_files': sum(len(rs) for rs in rows.values()), 's5_import_acceptance': False}


def native_header(block):
    """The fields of Nextcloud's encrypted-file header (lib/private/Encryption/Util.php:97-112: 'HBEGIN:' key:value
    pairs ':HEND', '-'-padded to 8192 bytes), or None for a file that does not start with one."""
    if not block.startswith(b'HBEGIN:'):
        return None
    end = block.find(b':HEND')
    require(len(block) == HEADER_SIZE and end > 0 and not block[end+5:].strip(b'-'), 'native-header-layout')
    try:
        fields = block[7:end].decode('ascii').split(':')
    except UnicodeDecodeError:
        raise ValueError('fixed-s5-native-header-layout') from None
    values = dict(zip(fields[::2], fields[1::2]))
    require(len(fields) % 2 == 0 and len(values) == len(fields)//2, 'native-header-fields')
    return values


def classify_source(data, before, encrypted, master, check=lambda: None):
    """The owned data directory after the encrypted writes, read independently (as userns root): which of the user's files
    carry the native header and every key file in its native layout. Exact expectations: the new files are the only
    ciphertext, each with exactly <masterKeyId>.shareKey (master-key mode, no fileKey, no user key pair); the file written
    before encryption is byte for byte its plaintext with no keys; the system keys are the master pair (and the public-
    share pair). `before`/`encrypted`: {name: {bytes, sha256}} of the plaintexts. Hashes only, never key bytes."""
    require(re.fullmatch(MASTER_RE, master) is not None, 'master-key-id')
    data = Path(data); rows = tree(data, check, limit=DISK_CAPS['data'])
    home, files, keys = USER+'/files/', {}, {}
    for rel, row in rows.items():
        if row['sha256'] is None:
            continue
        parts = rel.split('/')
        if 'files_encryption' in parts[:2]:      # where ha_nextcloud.scan_datadir looks for keys too
            require(KEY_RE.fullmatch(small(data/rel, MIB)) is not None, 'key-file-not-native-layout')
            keys[rel] = {'bytes': row['bytes'], 'sha256': row['sha256']}
        elif rel.startswith(home):
            fd = os.open(data/rel, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as f:
                header = native_header(f.read(HEADER_SIZE))
            require(header is None or header == HEADER, 'native-header-not-the-installed-module')
            files[rel] = {'bytes': row['bytes'], 'sha256': row['sha256'], 'encrypted': header is not None}
    system = 'files_encryption/'+MODULE+'/'
    expected = {system+master+'.publicKey', system+master+'.privateKey'}
    expected |= {USER+'/files_encryption/keys/files/'+name+'/'+MODULE+'/'+master+'.shareKey' for name in encrypted}
    pattern = re.escape(system)+r'pubShare_[0-9a-f]{8}\.(?:publicKey|privateKey)'
    public_share = {rel for rel in keys if re.fullmatch(pattern, rel)}
    require(set(keys)-public_share == expected, 'key-storage-not-master-key-mode')
    for name, plain in encrypted.items():
        row = files.get(home+name)
        require(row is not None and row['encrypted'] and row['bytes'] > plain['bytes']
                and row['sha256'] != plain['sha256'], 'native-ciphertext')
    for name, plain in before.items():
        row = files.get(home+name)
        require(row is not None and not row['encrypted'] and row['bytes'] == plain['bytes']
                and row['sha256'] == plain['sha256'], 'plaintext-before-encryption')
    ciphertext = sorted(rel for rel, row in files.items() if row['encrypted'])
    require(ciphertext == sorted(home+name for name in encrypted), 'unexpected-encrypted-files')
    binding = {rel: {'bytes': files[rel]['bytes'], 'sha256': files[rel]['sha256']}
               for rel in ciphertext+[home+name for name in before]}
    binding.update(keys)
    return {'master_key_id': master, 'header': HEADER, 'encrypted': ciphertext,
            'plaintext': sorted(rel for rel, row in files.items() if not row['encrypted']),
            'files': files, 'keys': keys, 'public_share_keys': len(public_share), 'cipher_and_keys': binding}


def prepare_owned(work, uid, gid, owner=0):
    """Give the two owned dirs Nextcloud writes as www-data (/var/www/html, /share/nextcloud) to the image's www-data:
    the entrypoint never chowns the data dir and the installer needs it writable (see the module notes). Only empty, real
    dirs of this run; mode 0750 (nothing for others, as Nextcloud's data dir check wants)."""
    require(type(uid) is int and type(gid) is int and 0 < uid < 65536 and 0 < gid < 65536, 'prepare-ids')
    work = Path(work); top = work.lstat()
    for name in ('html', 'data'):
        p = work/name; s = p.lstat()
        with os.scandir(p) as entries:
            empty = next(entries, None) is None
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == owner and s.st_dev == top.st_dev and empty,
                'prepare-owned-empty-dir')
        os.chown(p, uid, gid, follow_symlinks=False); os.chmod(p, 0o750)
    return {'status': 'prepared', 'www_data': [uid, gid]}


def discard_owned(work, names, check=lambda: None):
    """Remove exactly the named direct children of this run's own work dir, nothing else: each must be one of
    OWNED_LEAVES, a real dir (walked first: no link followed, nothing on another filesystem) or a single-link file."""
    work = Path(work); top = work.lstat()
    require(stat.S_ISDIR(top.st_mode), 'discard-owned-work')
    removed = []
    for name in names:
        require(name in OWNED_LEAVES, 'discard-name-not-owned')
        p = work/name
        try:
            s = p.lstat()
        except FileNotFoundError:
            continue
        require(s.st_dev == top.st_dev, 'discard-other-filesystem')
        if stat.S_ISDIR(s.st_mode):
            for directory, dirs, files in os.walk(p, followlinks=False):
                for entry in dirs+files:
                    check(); require((Path(directory)/entry).lstat().st_dev == top.st_dev, 'discard-other-filesystem')
            shutil.rmtree(p)   # fd-based on Linux: never follows a link
        else:
            require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'discard-owned-file')
            p.unlink()
        removed.append(name)
    return removed


def remove_source(work, provenance_sha, check):
    """After the host proved the original target exact: the cold owned source goes; the fixture, its provenance and the
    S5-B credentials stay. The packed bytes and the cold trees must still be the proven ones first."""
    work = Path(work); provenance = work/'artifact/provenance.private.json'
    require(digest(provenance, check) == provenance_sha, 'cleanup-provenance')
    doc = json.loads(small(provenance, 64*MIB))
    require(digest(work/'artifact/generated-s5-source.tar', check) == doc['archive']['sha256'], 'cleanup-artifact')
    for role, (src, _, _) in doc['mappings'].items():
        require(src in ('html/config', 'html/custom_apps', 'pg', 'data')
                and tree(work/src, check) == doc['source_files'][role], 'cleanup-cold-tree-changed')
    return {'status': 'owned-source-removed', 'removed': discard_owned(work, ('html', 'pg', 'data'), check),
            'fixture_retained': True}


def occ_shape(doc):
    """The reviewed part of `occ help --format=json <command>`: name, description, every argument [required, array] and
    every option that is not one of the console's own [shortcut, accepts a value, value required, multiple, default].
    Returns (shape, the console option names found)."""
    try:
        definition = doc['definition']
        arguments = definition['arguments'] or {}   # PHP encodes an empty map as []
        require(isinstance(arguments, dict), 'occ-help-unreadable')
        shape = {'name': doc['name'], 'description': doc['description'], 'options': {},
                 'arguments': {name: [row['is_required'], row['is_array']] for name, row in arguments.items()}}
        common = []
        for row in definition['options'].values():
            name = row['name'].removeprefix('--')
            if name in OCC_GLOBAL:
                common.append(name); continue
            shape['options'][name] = [row['shortcut'], row['accept_value'], row['is_value_required'], row['is_multiple'],
                                      row['default']]
        return shape, sorted(common)
    except (KeyError, TypeError, AttributeError):
        raise ValueError('fixed-s5-occ-help-unreadable') from None


# PHP/cURL follows the existing native Nextcloud client probe: private stdin auth,
# real HTTP/WebDAV inside the NC container; no published port or credential argv.
DAV = r'''$q=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$c=curl_init('http://localhost/remote.php/dav/files/s5owner/'.rawurlencode($q['name']));
curl_setopt_array($c,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_USERPWD=>'s5owner:'.$q['password'],
 CURLOPT_CUSTOMREQUEST=>$q['method'],CURLOPT_TIMEOUT=>90,CURLOPT_HTTPAUTH=>CURLAUTH_BASIC]);
if($q['method']==='PUT')curl_setopt($c,CURLOPT_POSTFIELDS,base64_decode($q['data'],true));
$b=curl_exec($c);if($b===false)exit(2);
echo json_encode(['status'=>curl_getinfo($c,CURLINFO_RESPONSE_CODE),'bytes'=>strlen($b),'sha256'=>hash('sha256',$b)]);'''


class Native:
    """In-device supervisor; every subprocess is bounded, watched and reaped."""
    def __init__(self, q):
        self.q = q; self.root = Path(q['proof_root']); self.work = self.root/'owned'
        self.deadline = q['deadline']; self.count = 0; self.stage = 'preflight'
        self.created = []; self.network = None; self.secret_ids = []
        self.lowest = 2**63; self.peak = 0; self.watch_failure = None
        self.next_basic = self.next_disk = 0.0
        self.failures = {'basic': 0, 'disk': 0}; self.probe_failures = 0
        self.help_hashes = {}; self.facts = {}

    # ------------------------------------------------------------------ the watch
    def stop(self, reason):
        self.watch_failure = reason
        raise ValueError('fixed-s5-watch-'+reason)

    def probe_failed(self, kind, error):
        self.failures[kind] += 1; self.probe_failures += 1
        if self.failures[kind] >= PROBE_TRIES:
            self.stop('%s-probe-failed-%d-in-a-row-%s' % (kind, self.failures[kind], type(error).__name__))

    def basic_probe(self):
        return shutil.disk_usage(self.root).free, int(Path('/sys/fs/cgroup/memory.current').read_text())

    def check(self):
        """A breach (lease end, reserve, memory, owned disk) stops at once; a failed or timed-out probe only after
        PROBE_TRIES in a row (fullshare04 lost a passing case to ONE slow probe on a host at load 26)."""
        if time.time() >= self.deadline:
            self.stop('expired')
        if time.monotonic() >= self.next_basic:
            self.next_basic = time.monotonic()+1
            try:
                free, memory = self.basic_probe()
            except (OSError, ValueError) as error:
                self.probe_failed('basic', error)
            else:
                self.failures['basic'] = 0
                self.lowest = min(self.lowest, free); self.peak = max(self.peak, memory)
                if free < FLOOR: self.stop('reserve')
                if memory > MEMORY_WATCH: self.stop('memory')
                if self.q['start_free']-free > OWNED_CAP: self.stop('combined-disk')
        if self.q['action'] == 'build' and time.monotonic() >= self.next_disk:
            try:
                sizes = self.owned_sizes()
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                self.next_disk = time.monotonic()+DU_EVERY
                self.probe_failed('disk', error)
            else:
                self.next_disk = time.monotonic()+DU_EVERY
                self.failures['disk'] = 0
                if sizes['owned'] > OWNED_CAP: self.stop('owned-disk-cap')
                for name, cap in DISK_CAPS.items():
                    if sizes.get(name, 0) > cap: self.stop('component-disk-cap-'+name)

    def du(self, paths, apparent=False):
        argv = ['podman', 'unshare', 'du', '-s', '-B1', *(['--apparent-size'] if apparent else []), *map(str, paths)]
        code, out = bounded(argv, DU_TIMEOUT)
        lines = out.decode('utf-8', 'replace').splitlines()
        require(code == 0 and len(lines) == len(paths), 'du-probe-unreadable')
        values = []
        for line, path in zip(lines, paths):
            size, _, name = line.partition('\t')
            require(size.isdigit() and name == str(path), 'du-probe-unreadable')
            values.append(int(size))
        return values

    def owned_sizes(self):
        """Allocated bytes of the whole owned work dir and the apparent bytes of each source dir."""
        sizes = {'owned': self.du([self.work])[0]}
        present = [name for name in DISK_CAPS if os.path.lexists(self.work/name)]
        if present:
            sizes.update(zip(present, self.du([self.work/name for name in present], apparent=True)))
        return sizes

    # ------------------------------------------------------------------ bounded commands
    def call(self, argv, data=None, timeout=180, allowed=(0,), cleanup=False):
        self.count += 1; base = self.work/('command-%04d'%self.count)
        with base.with_suffix('.stdout.private').open('xb') as out, base.with_suffix('.stderr.private').open('xb') as err:
            os.chmod(out.name, 0o600); os.chmod(err.name, 0o600)
            p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=out, stderr=err, start_new_session=True)
            error = None
            try:
                if data is not None:
                    # Inputs here are <= 2MiB; written in slices without blocking the watch loop.
                    os.set_blocking(p.stdin.fileno(), False); pending = memoryview(data)
                else: pending = memoryview(b'')
                until = time.monotonic()+timeout
                while p.poll() is None:
                    if cleanup: require(time.time() < self.deadline+CLEANUP_GRACE, 'cleanup-grace-expired')
                    if not cleanup: self.check()
                    require(time.monotonic() < until, 'command-timeout')
                    require(os.fstat(out.fileno()).st_size <= 4*MIB and os.fstat(err.fileno()).st_size <= MIB,
                            'command-output-bound')
                    if pending:
                        try: n = os.write(p.stdin.fileno(), pending[:65536]); pending = pending[n:]
                        except BlockingIOError: pass
                    elif not p.stdin.closed: p.stdin.close()
                    time.sleep(0.1)
                require(not pending, 'command-stdin-incomplete')
            except BaseException as exc:
                error = exc
                if p.poll() is None:
                    os.killpg(p.pid, signal.SIGTERM)
                    try: p.wait(timeout=10)
                    except subprocess.TimeoutExpired: os.killpg(p.pid, signal.SIGKILL); p.wait(timeout=10)
            finally:
                p.stdin.close()
        out_path, err_path = base.with_suffix('.stdout.private'), base.with_suffix('.stderr.private')
        oversized = out_path.stat().st_size > 4*MIB or err_path.stat().st_size > MIB
        raw = small(out_path, 4*MIB) if not oversized else b''
        private(base.with_suffix('.json'), {'stage': self.stage, 'returncode': p.returncode,
                'stdout_sha256': sha(raw) if not oversized else None,
                'stderr_sha256': digest(err_path, limit=MIB) if not oversized else None,
                'output_bound_exceeded': oversized,
                'exception_class': type(error).__name__ if error else None, 'errno': getattr(error, 'errno', None),
                'watch_failure': self.watch_failure})
        if error: raise error
        require(not oversized and p.returncode in allowed, 'native-command-refused')
        return p.returncode, raw

    def pod(self, *argv, **kw): return self.call(['podman', *argv], **kw)[1]

    def name(self, role): return 'woowbk-s5-'+self.q['nonce']+'-'+role

    def unshare(self, action, cleanup=False, **extra):
        request = dict(self.q, action=action, **extra)
        body = native_program(self.q['builder_source'])
        return json.loads(self.call(['podman', 'unshare', 'python3', '-I', '-c', body],
                                    json.dumps(request).encode(), timeout=900, cleanup=cleanup)[1])

    # ------------------------------------------------------------------ occ
    def occ(self, *args, allowed=(0,)):
        # No stdin: occ is non-interactive, so a question would take its default (a refusal), never an invented yes.
        return self.call(['podman', 'exec', '-u', 'www-data', self.name('nc'), 'php', '/var/www/html/occ', *args],
                         allowed=allowed)

    def occ_text(self, *args):
        return self.occ(*args)[1].decode('utf-8')

    def occ_json(self, *args):
        """Every occ JSON reply used here is one object (core/Command/Base.php writeArrayInOutputFormat)."""
        raw = self.occ(*args)[1]
        try:
            value = json.loads(raw)
        except ValueError:
            raise ValueError('fixed-s5-occ-json-unreadable') from None
        require(isinstance(value, dict), 'occ-json-unreadable')
        return value

    def occ_names(self):
        return {line.split()[0] for line in self.occ_text('list', '--raw').splitlines() if line.strip()}

    def occ_help(self, command):
        """The installed command must be the reviewed one (OCC_CONTRACT); any difference stops the run for review, with
        what was found kept privately next to the other records."""
        _, raw = self.occ('help', '--format=json', command)
        self.help_hashes[command] = sha(raw)
        try:
            doc = json.loads(raw)
        except ValueError:
            raise ValueError('fixed-s5-occ-help-unreadable') from None
        shape, common = occ_shape(doc)
        expected = dict(OCC_CONTRACT[command], name=command)
        if shape != expected:
            private(self.work/('occ-help-differs-%s.private.json' % command.replace(':', '-')),
                    {'expected': expected, 'found': shape, 'console_options': common})
            raise ValueError('fixed-s5-occ-help-differs-stop-for-review')

    def occ_gate_before(self):
        """The fresh install before any encryption: reviewed commands, installed state, encryption app off."""
        names = self.occ_names()
        require(set(OCC_BEFORE_APP) <= names and not set(OCC_AFTER_APP) & names, 'occ-commands-before-encryption-app')
        for command in OCC_BEFORE_APP:
            self.occ_help(command)
        status = self.occ_json('status', '--output=json')
        require(status.get('installed') is True and status.get('version') == VERSION
                and status.get('maintenance') is False and status.get('needsDbUpgrade') is False, 'occ-status')
        apps = self.occ_json('app:list', '--output=json')
        require('encryption' in (apps.get('disabled') or {}) and 'encryption' not in (apps.get('enabled') or {}),
                'encryption-app-not-initially-disabled')
        state = self.occ_json('encryption:status', '--output=json')
        require(state.get('enabled') is False and state.get('defaultModule') in ('', MODULE),
                'unexpected-initial-encryption')

    def enable_encryption(self):
        """The installed, supported procedure only: enable the shipped app, select OC_DEFAULT_MODULE, enable encryption,
        confirm master-key mode with the command's native output. No appconfig flag, key folder or key is written here."""
        out = self.occ_text('app:enable', 'encryption')
        require(re.search(r'^encryption [0-9][0-9A-Za-z.+-]* enabled$', out, re.M) is not None, 'app-enable-output')
        names = self.occ_names()
        require(set(OCC_AFTER_APP) <= names, 'occ-encryption-app-commands')
        for command in OCC_AFTER_APP:
            self.occ_help(command)
        apps = self.occ_json('app:list', '--output=json')
        require('encryption' in (apps.get('enabled') or {}), 'encryption-app-not-enabled')
        self.facts['encryption_app_version'] = apps['enabled']['encryption']
        modules = self.occ_json('encryption:list-modules', '--output=json')
        require(isinstance(modules, dict) and MODULE in modules, 'default-module-not-listed')
        out = self.occ_text('encryption:set-default-module', MODULE).strip()
        # SetDefaultModule.php:53/55 (the doubled quote is the source's own).
        require(out in ('"%s"" is already the default module' % MODULE, 'Set default module to "%s"' % MODULE),
                'set-default-module-output')
        self.facts['default_module_selection'] = out
        require(self.occ_json('encryption:status', '--output=json') == {'enabled': False, 'defaultModule': MODULE},
                'module-selected-state')
        code, raw = self.occ('config:app:get', 'encryption', 'useMasterKey', allowed=(0, 1))
        # Util.php:66-67: unset means true (the default); an explicit value must say true (AppConfig.php:462).
        require((code == 1 and not raw.strip()) or (code == 0 and raw.strip().lower() in (b'1', b'true', b'yes', b'on')),
                'master-key-not-the-default')
        self.facts['use_master_key'] = 'unset-default-true' if code == 1 else raw.strip().decode('ascii', 'replace')
        out = self.occ_text('encryption:enable')
        require(out.splitlines() == ['Encryption enabled', '', 'Default module: '+MODULE], 'encryption-enable-output')
        out = self.occ_text('encryption:enable-master-key')
        require(out == 'Master key already enabled\n', 'master-key-procedure-differs-stop-for-review')
        self.facts['master_key_command_output'] = out.strip()
        require(self.occ_json('encryption:status', '--output=json') == {'enabled': True, 'defaultModule': MODULE},
                'encryption-state')
        details = self.occ_json('config:app:get', 'core', 'encryption_enabled', '--details', '--output=json')
        # What HA's database will hold: Enable.php:41 writes it with setValueBool (AppConfig.php:774 stores '1').
        self.facts['core_encryption_enabled'] = {k: details.get(k) for k in ('value', 'type')}

    def master_key_id(self):
        """Read only after the first encrypted write (KeyManager.php:42-62 creates it when the key manager is built)."""
        master = self.occ_text('config:app:get', 'encryption', 'masterKeyId').strip()
        require(re.fullmatch(MASTER_RE, master) is not None, 'master-key-id')
        return master

    # ------------------------------------------------------------------ WebDAV
    def dav(self, password, name, method, value=None):
        q = {'password': password, 'name': name, 'method': method}
        if value is not None: q['data'] = base64.b64encode(value).decode()
        try:
            return json.loads(self.pod('exec', '-i', '-u', 'www-data', self.name('nc'), 'php', '-r', DAV,
                                       data=json.dumps(q).encode()))
        except ValueError as error:
            if str(error).startswith('fixed-s5-'): raise
            raise ValueError('fixed-s5-webdav-reply-unreadable') from None

    def put_get(self, password, name, value):
        require(self.dav(password, name, 'PUT', value)['status'] == 201, 'webdav-put')
        require(self.dav(password, name, 'GET') == {'status': 200, 'bytes': len(value), 'sha256': sha(value)},
                'webdav-plaintext')
        require(self.dav(password+'-wrong', name, 'GET')['status'] == 401, 'webdav-wrong-auth')

    # ------------------------------------------------------------------ owned containers
    def source_args(self, role):
        """podman run arguments of each owned source container. No :U anywhere: :U gives a bind source to the container's
        own user, which for the Nextcloud image is root (its entrypoint starts as root and installs as www-data), so the
        0700 /share/nextcloud would stay unwritable for the installer; prepare_owned gives html and data to www-data once,
        and the postgres entrypoint gives PGDATA to postgres itself."""
        env = ['--env=POSTGRES_USER=nextcloud', '--env=POSTGRES_DB=nextcloud',
               '--secret='+self.name('dbpass')+',type=env,target=POSTGRES_PASSWORD']
        if role == 'pg':   # the image's entrypoint, as container root, gives PGDATA to postgres
            return env+['-v', str(self.work/'pg')+':/var/lib/postgresql/data', 'sha256:'+IMAGES['pg']]
        if role == 'redis':
            return ['sha256:'+IMAGES['redis'], 'redis-server', '--save', '', '--appendonly', 'no']
        require(role == 'nc', 'source-role')
        return env+['--env=POSTGRES_HOST='+self.name('pg'), '--env=REDIS_HOST='+self.name('redis'),
                    '--env=NEXTCLOUD_ADMIN_USER='+USER, '--env=NEXTCLOUD_TRUSTED_DOMAINS=localhost',
                    '--env=NEXTCLOUD_DATA_DIR=/share/nextcloud', '--env=PHP_MEMORY_LIMIT=512M',
                    '--secret='+self.name('admin')+',type=env,target=NEXTCLOUD_ADMIN_PASSWORD',
                    '-v', str(self.work/'html')+':/var/www/html', '-v', str(self.work/'data')+':/share/nextcloud',
                    'sha256:'+IMAGES['nc']]

    def cpu_limit(self, controllers=CONTROLLERS):
        """['--cpus=1'] when the cpu controller is delegated to this user, else [] (recorded in the facts)."""
        try:
            with open(controllers.format(uid=os.getuid()), encoding='ascii') as handle:
                delegated = 'cpu' in handle.read(4096).split()
        except (OSError, ValueError):
            delegated = False
        self.facts['cpu_controller_delegated'] = delegated
        return ['--cpus=1'] if delegated else []

    def run_container(self, role, args):
        # Name is registered BEFORE the request: interrupted create is reconciled by label+ID.
        self.created.append(role)
        raw = self.pod('run', '-d', '--pull=never', '--image-volume=ignore', '--name', self.name(role),
                      '--label', 'woowbk.s5='+self.q['nonce'], '--network', self.network,
                      '--memory', str(CAPS[role]), '--memory-swap', str(CAPS[role]), '--pids-limit=256',
                      *self.cpu_limit(), '--log-driver=k8s-file', '--log-opt=max-size=4mb', *args)
        require(re.fullmatch(rb'[0-9a-f]{64}\n?', raw) is not None, 'container-id')
        inspect = json.loads(self.pod('inspect', '--format',
                            '{"id":"{{.Id}}","image":"{{.Image}}","ports":{{json .HostConfig.PortBindings}},'
                            '"mounts":{{json .Mounts}}}', self.name(role)))
        require(inspect['id'] == raw.decode().strip() and inspect['image'].removeprefix('sha256:') == IMAGES[role]
                and inspect['ports'] in ({}, None), 'container-image-or-ports')
        expected = {'pg': {str(self.work/'pg'): '/var/lib/postgresql/data'}, 'redis': {},
                    'nc': {str(self.work/'html'): '/var/www/html', str(self.work/'data'): '/share/nextcloud'}}[role]
        require({x['Source']: x['Destination'] for x in inspect['mounts']} == expected
                and all(x['Type'] == 'bind' for x in inspect['mounts']), 'owned-mounts-only')
        private(self.work/(role+'-identity.json'), inspect)

    def www_ids(self):
        """(uid, gid) of www-data in the pinned Nextcloud image: a throwaway, owned, network-less run (the product's own
        tempctr.user_ids reads them the same way)."""
        self.created.append('ids')
        raw = self.pod('run', '--rm', '--pull=never', '--image-volume=ignore', '--name', self.name('ids'),
                       '--label', 'woowbk.s5='+self.q['nonce'], '--network=none', '--read-only',
                       '--memory', str(HELPER_MEMORY), '--memory-swap', str(HELPER_MEMORY), '--pids-limit=64',
                       '--entrypoint', 'sh', 'sha256:'+IMAGES['nc'], '-c', 'id -u www-data && id -g www-data')
        parts = raw.decode('ascii', 'replace').split()
        require(len(parts) == 2 and all(p.isdigit() and 0 < int(p) < 65536 for p in parts), 'www-data-ids')
        return int(parts[0]), int(parts[1])

    def wait_nc(self, limit):
        until = min(self.deadline, time.time()+limit)
        while time.time() < until:
            # curl: 7 refused (Apache starts after the install), 22 HTTP error, 28 timeout, 52/56 empty or reset.
            code, raw = self.call(['podman', 'exec', self.name('nc'), 'curl', '-fsS', '-m', '10',
                                   'http://localhost/status.php'], allowed=(0, 7, 22, 28, 52, 56), timeout=30)
            if code == 0:
                state = json.loads(raw)
                if state.get('installed') is True:
                    require(state.get('version') == VERSION and state.get('maintenance') is False
                            and state.get('needsDbUpgrade') is False, 'nc-version-state')
                    return
            self.check(); time.sleep(2)
        raise ValueError('fixed-s5-bootstrap-timeout')

    # ------------------------------------------------------------------ the build
    def execute(self):
        require(self.q['images'] == IMAGES and sum(CAPS.values()) == 1220*MIB, 'pin-cap-contract')
        for role, ident in IMAGES.items():
            raw = self.pod('image', 'inspect', '--format', '{{.Id}} {{.Architecture}} {{.Os}}', 'sha256:'+ident)
            require(raw.decode().strip().removeprefix('sha256:') == ident+' amd64 linux', 'source-image-identity')
        require(self.q['start_free'] >= START_FREE, 'start-free'); self.check()
        for name in ('html', 'pg', 'data'): (self.work/name).mkdir(mode=0o700)
        self.stage = 'new-source-bootstrap'
        uid, gid = self.www_ids(); self.facts['www_data'] = [uid, gid]
        self.unshare('prepare', uid=uid, gid=gid)
        # New generated secrets only through stdin and podman secrets, never argv or public output. The database password
        # is never written to a file; the admin password is kept (privately) only after a successful build, for S5-B.
        password, dbpass = secrets.token_hex(24), secrets.token_hex(24)
        for role, value in (('admin', password), ('dbpass', dbpass)):
            name = self.name(role); self.secret_ids.append(name)
            self.pod('secret', 'create', '--label', 'woowbk.s5='+self.q['nonce'], name, '-', data=value.encode())
        self.network = self.name('net')
        self.pod('network', 'create', '--internal', '--label', 'woowbk.s5='+self.q['nonce'], self.network)
        net = json.loads(self.pod('network', 'inspect', self.network))[0]
        require(net.get('internal') is True and net.get('labels', {}).get('woowbk.s5') == self.q['nonce'],
                'internal-network')
        self.run_container('pg', self.source_args('pg'))
        self.run_container('redis', self.source_args('redis'))
        until = min(self.deadline, time.time()+120)
        while time.time() < until:
            code, _ = self.call(['podman', 'exec', self.name('pg'), 'pg_isready', '-U', 'nextcloud', '-d', 'nextcloud'],
                                allowed=(0, 1, 2))
            if code == 0: break
            self.check(); time.sleep(1)
        else: raise ValueError('fixed-s5-postgres-bootstrap-timeout')
        require(self.pod('exec', self.name('redis'), 'redis-cli', 'ping').strip() == b'PONG', 'redis-readiness')
        pg_banner = self.pod('exec', self.name('pg'), 'postgres', '--version')
        redis_banner = self.pod('exec', self.name('redis'), 'redis-server', '--version')
        require(re.match(rb'postgres \(PostgreSQL\) 16\.[0-9]+', pg_banner) is not None
                and re.match(rb'Redis server v=8\.10\.1\b', redis_banner) is not None, 'actual-component-versions')
        self.run_container('nc', self.source_args('nc'))
        self.wait_nc(900)
        self.stage = 'occ-help-and-state-before-encryption'
        self.occ_gate_before()
        known = plaintexts()
        self.stage = 'webdav-plaintext-before-encryption'
        for name, value in known['before'].items(): self.put_get(password, name, value)
        self.stage = 'enable-native-encryption'
        self.enable_encryption()
        self.stage = 'webdav-encrypted-put-and-get'
        for name, value in known['encrypted'].items(): self.put_get(password, name, value)
        self.stage = 'master-key-after-first-encrypted-write'
        master = self.master_key_id()
        digests = {kind: {n: {'bytes': len(v), 'sha256': sha(v)} for n, v in rows.items()} for kind, rows in known.items()}
        self.stage = 'independent-ciphertext-and-key-read'
        source = self.unshare('cipher', before=digests['before'], encrypted=digests['encrypted'], master=master)
        private(self.work/'occ-gate.private.json', {'help_sha256': self.help_hashes, 'facts': self.facts,
                                                    'master_key_id': master})
        proof = {'webdav_before': True, 'plaintext_before_encryption': True, 'master_key_mode': True,
                 'master_key_id': master, 'occ_contract_sha256': manifest_hash(OCC_CONTRACT),
                 'occ_gate_sha256': digest(self.work/'occ-gate.private.json'), 'facts': self.facts,
                 'component_version_output_sha256': {'pg': sha(pg_banner), 'redis': sha(redis_banner)},
                 'plaintext': digests, 'encrypted_files': source['encrypted'], 'plaintext_files': source['plaintext'],
                 'key_files': len(source['keys']), 'public_share_keys': source['public_share_keys'],
                 'cipher_and_keys': source['cipher_and_keys']}
        self.stage = 'source-nc-restart-and-plaintext'
        self.pod('restart', '--time=60', self.name('nc')); self.wait_nc(300)
        for rows in known.values():
            for name, value in rows.items():
                require(self.dav(password, name, 'GET') == {'status': 200, 'bytes': len(value), 'sha256': sha(value)},
                        'restart-plaintext')
        proof['webdav_after_restart'] = True
        self.stage = 'source-cold-shutdown'
        for role in ('nc', 'redis', 'pg'): self.pod('stop', '--time=60', self.name(role))
        for role in ('nc', 'redis', 'pg'):
            state = json.loads(self.pod('inspect', '--format', '{{json .State}}', self.name(role)))
            require(state.get('Running') is False and state.get('OOMKilled') is False
                    and state.get('ExitCode') in (0, 143), 'source-stop-state')
        # A separate read-only, network-none PG helper verifies the actual cold cluster.
        self.created.append('control')
        raw = self.pod('run', '--pull=never', '--image-volume=ignore', '--name', self.name('control'),
                      '--label', 'woowbk.s5='+self.q['nonce'], '--network=none', '--read-only',
                      '--memory='+str(HELPER_MEMORY), '--pids-limit=64', '-v', str(self.work/'pg')+':/cluster:ro',
                      '--user=postgres', '--entrypoint=pg_controldata', 'sha256:'+IMAGES['pg'], '/cluster')
        require(re.search(rb'Database cluster state:\s+shut down\s*\n', raw) is not None, 'pg-not-cleanly-shut-down')
        proof['pg_shutdown'] = True; proof['pg_controldata_sha256'] = sha(raw)
        self.stage = 'cold-source-packaging'
        result = self.unshare('package', proof=proof)
        self.stage = 'packaged-source-proof'
        private(self.work/'credentials.private.json', {'user': USER, 'password': password,
                                                       'use': 'S5-B WebDAV reads; removed with the owned root'})
        private(self.work/'source-result.json', result)
        return result

    def save_logs(self):
        """Bounded logs of this run's own containers, kept privately BEFORE anything is removed."""
        for role in self.created:
            try:
                code, _ = self.call(['podman', 'container', 'exists', self.name(role)], allowed=(0, 1), cleanup=True)
                if code == 0:
                    self.call(['podman', 'logs', '--tail', '400', self.name(role)], cleanup=True)
            except Exception:
                pass   # diagnostics only: the cleanup still runs

    def cleanup(self):
        """Only registered names with this run's exact label."""
        for role in reversed(self.created):
            code, _ = self.call(['podman', 'container', 'exists', self.name(role)], allowed=(0, 1), cleanup=True)
            if code == 1: continue
            raw = self.pod('inspect', '--format', '{{json .Config.Labels}}', self.name(role), cleanup=True)
            require(json.loads(raw).get('woowbk.s5') == self.q['nonce'], 'cleanup-container-ownership')
            path = self.work/(role+'-identity.json')
            if path.exists():
                ident = json.loads(path.read_text())['id']
                require(self.pod('inspect', '--format', '{{.Id}}', self.name(role), cleanup=True).decode().strip() == ident,
                        'cleanup-container-id')
            self.pod('rm', '-f', '--time=60', self.name(role), cleanup=True)
        if self.network:
            code, _ = self.call(['podman', 'network', 'exists', self.network], allowed=(0, 1), cleanup=True)
            if code == 1: self.network = None
        if self.network:
            row = json.loads(self.pod('network', 'inspect', self.network, cleanup=True))[0]
            require(row.get('labels', {}).get('woowbk.s5') == self.q['nonce'] and row.get('internal') is True,
                    'cleanup-network-ownership')
            self.pod('network', 'rm', self.network, cleanup=True)
        for name in self.secret_ids:
            code, _ = self.call(['podman', 'secret', 'exists', name], allowed=(0, 1), cleanup=True)
            if code == 1: continue
            row = json.loads(self.pod('secret', 'inspect', name, cleanup=True))[0]
            require(row.get('Spec', {}).get('Labels', {}).get('woowbk.s5') == self.q['nonce'], 'cleanup-secret-ownership')
            self.pod('secret', 'rm', name, cleanup=True)


def supervise(native, work):
    """The build and its own cleanup. On failure, in this order: the diagnostics (failure record, container logs), the
    owned containers/network/secrets, and only when those are gone the owned source, any half-made fixture and the
    credentials (discard_owned: literal names under this run's own work dir). Diagnostics stay."""
    result = failure = discarded = None
    try:
        result = native.execute()
    except BaseException as exc:
        failure = exc
        private(work/'failure.private.json', {'stage': native.stage, 'exception_class': type(exc).__name__,
                'errno': getattr(exc, 'errno', None), 'traceback': traceback.format_exc(),
                'watch_failure': native.watch_failure})
        native.save_logs()
    finally:
        cleaned = False
        try:
            native.cleanup(); cleaned = True
        except BaseException as exc:
            private(work/'cleanup-failure.private.json', {'exception_class': type(exc).__name__,
                    'traceback': traceback.format_exc()}); failure = failure or exc
        if failure is not None and cleaned:
            try:
                discarded = native.unshare('discard', cleanup=True)
            except BaseException as exc:
                private(work/'discard-failure.private.json', {'exception_class': type(exc).__name__,
                        'traceback': traceback.format_exc()})
        fixed = {'status': 'failed' if failure else 'passed', 'phase': native.stage,
                 'watch_failure': native.watch_failure, 'probe_failures': native.probe_failures,
                 'minimum_free_bytes': native.lowest, 'peak_memory_bytes': native.peak, 'fixture': result,
                 'owned_containers_removed': cleaned, 'owned_source_discarded': discarded,
                 's5_import_acceptance': False, 'target_mutation': False, 'pulls': 0}
        private(work/'fixed-result.json', fixed); print(json.dumps(fixed))
    return failure


def internal_main(q):
    """Only reached by the separately leased host launcher or its owned unshare worker."""
    sys.dont_write_bytecode = True; os.umask(0o077)
    require(re.fullmatch(ROOT_RE, q['proof_root']) is not None and q['proof_root'].endswith(q['nonce']), 'root-binding')
    require(sha(q['builder_source'].encode()) == q['builder_sha256'], 'builder-binding')
    cleanup_action = q['action'] in ('discard', 'remove-source')
    limit = q['deadline']+(CLEANUP_GRACE if cleanup_action else 0)
    require(time.time() < limit, 'native-expired')
    work = Path(q['proof_root'])/'owned'
    require(work.is_dir() and not work.is_symlink(), 'owned-work')
    if q['action'] != 'build':
        # Root within podman unshare can read and remove container UID-mapped source bytes.
        require(os.getuid() == 0, 'unshare-worker-required')
        guard = (lambda: require(time.time() < limit, 'cleanup-grace-expired')) if cleanup_action else Native(q).check
        if q['action'] == 'prepare': result = prepare_owned(work, q['uid'], q['gid'])
        elif q['action'] == 'cipher': result = classify_source(work/'data', q['before'], q['encrypted'], q['master'], guard)
        elif q['action'] == 'package': result = build_fixture(work, q['proof'], guard)
        elif q['action'] == 'discard':
            result = {'status': 'owned-discarded', 'removed': discard_owned(work, OWNED_LEAVES, guard)}
        elif q['action'] == 'remove-source': result = remove_source(work, q['provenance_sha256'], guard)
        else: raise ValueError('fixed-s5-action-refused')
        print(json.dumps(result)); return
    require(os.getuid() != 0, 'owner-only-build')
    if supervise(Native(q), work) is not None:
        raise SystemExit(2)


def contract():
    return {'phase': PHASE, 'code_only_until_leased': True, 'images': IMAGES, 'component_caps': CAPS,
            'disk_caps': DISK_CAPS, 'minimum_start_free_bytes': START_FREE, 'additional_disk_cap_bytes': OWNED_CAP,
            'fixture_cap_bytes': FIXTURE_CAP, 'reserve_bytes': RESERVE, 'watch_floor_bytes': FLOOR,
            'device_memory_cap_bytes': DEVICE_CAP, 'memory_watch_bytes': MEMORY_WATCH, 'probe_tries': PROBE_TRIES,
            'engine_commit': ENGINE_COMMIT, 'occ_contract_sha256': manifest_hash(OCC_CONTRACT),
            's5_import_acceptance': False, 'target_wake': False, 'target_source_install': False, 'pulls': 0}


# ---------------------------------------------------------------------- host side
def engine_manifest(repo, commit=ENGINE_COMMIT):
    """{installed name: sha256} of the engine of `commit` -- every file of backup-engine/woowbackup under the library (what
    manage.py install copies), VERSION and the helper -- from this repository's git objects, never from a device."""
    git = ['git', '-C', str(repo)]
    listing = subprocess.check_output(git+['ls-tree', '-r', '-z', '--full-tree', commit, '--', 'backup-engine/woowbackup',
                                           'backup-engine/woowtech-cockpit-backup', 'VERSION'])
    rows = {}
    for record in listing.split(b'\0'):
        if not record:
            continue
        meta, _, path = record.partition(b'\t')
        mode, kind, obj = meta.split()
        path = path.decode('utf-8')
        require(kind == b'blob' and mode in (b'100644', b'100755'), 'engine-tree-entry')
        if path.startswith('backup-engine/woowbackup/'):
            name = 'lib/woowbackup/'+path[len('backup-engine/woowbackup/'):]
        elif path == 'backup-engine/woowtech-cockpit-backup':
            name = 'helper'
        elif path == 'VERSION':
            name = 'lib/VERSION'
        else:
            continue
        rows[name] = sha(subprocess.check_output(git+['cat-file', 'blob', obj.decode('ascii')]))
    require({'helper', 'lib/VERSION', 'lib/woowbackup/__init__.py', 'lib/woowbackup/cli.py',
             'lib/woowbackup/ha_nextcloud.py'} <= set(rows)
            and all(n in ('helper', 'lib/VERSION') or n.endswith('.py') for n in rows), 'engine-manifest')
    return rows


def engine_differs(installed, expected):
    """The names whose installed bytes are not the bound checkout's (missing, extra or changed), for the record."""
    return sorted(n for n in set(installed) | set(expected) if installed.get(n) != expected.get(n))


def checkout(repo):
    commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    clean = not subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain'], text=True).strip()
    return commit, clean


def lease_template(repo):
    """The lease fields this checkout binds; the time window and the new proof root are the coordinator's."""
    repo = Path(repo); commit, clean = checkout(repo)
    code = (repo/'tests/e2e/lab/focus_nextcloud_r6_s5.py').read_text()
    return {'lane': 'nextcloud-r6', 'device': 'woowbk-dev-e', 'phases': [PHASE],
            'source_commit': commit if clean else 'REQUIRES_A_CLEAN_COMMITTED_CHECKOUT',
            'builder_sha256': sha(code.encode()), 'engine_commit': ENGINE_COMMIT,
            'engine_manifest_sha256': manifest_hash(engine_manifest(repo)),
            'occ_contract_sha256': manifest_hash(OCC_CONTRACT),
            'proof_root': 'REQUIRES_NEW_/var/lib/woowbk-nextcloud-s5-<16 lowercase hex>',
            'not_before_utc': 'REQUIRES_GRANTED_START', 'expires_utc': 'REQUIRES_GRANTED_START_PLUS_45_MINUTES',
            'reserve_bytes': RESERVE, 'memory_cap_bytes': DEVICE_CAP, 'images': IMAGES, 'component_caps': CAPS,
            'disk_caps': DISK_CAPS, 'minimum_start_free_bytes': START_FREE, 'additional_disk_cap_bytes': OWNED_CAP,
            'fixture_cap_bytes': FIXTURE_CAP, 'cleanup_grace_seconds': CLEANUP_GRACE, 'target_wake': False,
            'target_source_install': False, 'target_restore': False, 'image_operations': []}


def admit_lease(lease, commit, code, engine, *, lease_check, now=None):
    """The exact lease of this checkout: scope and window (lease_check), every bound value, HEADROOM left."""
    lease_check(lease, commit, PHASE)
    require(lease.get('builder_sha256') == sha(code.encode()) and lease.get('engine_commit') == ENGINE_COMMIT
            and lease.get('engine_manifest_sha256') == manifest_hash(engine)
            and lease.get('occ_contract_sha256') == manifest_hash(OCC_CONTRACT)
            and lease.get('images') == IMAGES and lease.get('component_caps') == CAPS
            and lease.get('disk_caps') == DISK_CAPS and lease.get('minimum_start_free_bytes') == START_FREE
            and lease.get('additional_disk_cap_bytes') == OWNED_CAP and lease.get('fixture_cap_bytes') == FIXTURE_CAP
            and lease.get('cleanup_grace_seconds') == CLEANUP_GRACE and lease.get('target_wake') is False
            and lease.get('target_source_install') is False and lease.get('target_restore') is False
            and lease.get('image_operations') == [], 'lease-builder-contract')
    require(isinstance(lease.get('proof_root'), str) and re.fullmatch(ROOT_RE, lease['proof_root']) is not None,
            'lease-root')
    deadline = datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z', '+00:00')).timestamp()
    require(deadline-(time.time() if now is None else now) >= HEADROOM, 'lease-headroom')
    return deadline


def locked_admission(lease, commit, deadline, *, lease_check, now=None):
    """Right after the BLOCKING dev-e lock: the wait may have been long, so the lease must still hold and keep HEADROOM."""
    lease_check(lease, commit, PHASE)
    require(deadline-(time.time() if now is None else now) >= HEADROOM, 'lease-headroom-after-lock')


def run_locked(lease, commit, code, deadline, engine):
    """Caller holds the dev-e mutex. Reuses the R6 read-only probes; never reads the 4.47 GB fixture."""
    import focus_nextcloud_r6_case as case
    import focus_nextcloud_r6_wake as wake
    from focus_nextcloud_r6_inventory import collect, LP, DEVICE
    from focus_nextcloud_r6_plan import lease_check
    from focus_nextcloud_r6_upload import Evidence
    lab = Path.home()/'.woowbk-lab'
    before = collect(); case.admission(before)
    require(min(before['host_free_bytes'], before['root']['varlib_free_bytes']) >= START_FREE, 'fresh-start-disk')
    require(wake.device(case.QUIESCENT, root=True)['active_jobs'] == 0, 'native-jobs')
    installed = wake.device(ENGINE_PROGRAM, root=True)
    ev = Evidence(lab/'evidence/focus-nextcloud-r6-s5'/time.strftime('%Y%m%dT%H%M%S'))
    lease_sha = manifest_hash(lease)
    ev.save('binding.json', {'source_commit': commit, 'builder_sha256': sha(code.encode()), 'lease_sha256': lease_sha,
                             'engine_commit': ENGINE_COMMIT, 'engine_manifest_sha256': manifest_hash(engine),
                             'installed_engine_differs': engine_differs(installed, engine),
                             'occ_contract_sha256': manifest_hash(OCC_CONTRACT)})
    require(installed == engine, 'installed-engine-is-not-the-bound-checkout')
    marker = lab/'run/focus-nextcloud-r6-s5-leases'
    marker.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(marker/(lease_sha+'.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)  # one attempt
    with os.fdopen(fd, 'w') as f:
        json.dump({'source_commit': commit, 'private_receipt_dir': str(ev.path)}, f); f.flush(); os.fsync(f.fileno())

    def snapshot():
        return {'engine': wake.device(ENGINE_PROGRAM, root=True), 'target': wake.device(TARGET_STATE, root=True),
                'units': wake.device(wake.unit_program(), {'action': 'snapshot'}),
                'baseline': wake.device(wake.BASELINE_HASH, root=True, timeout=600), 'store': wake.device(STORE_SNAPSHOT)}
    prior = snapshot()
    ev.save('before.private.json', {'inventory': before, **prior})
    lease_check(lease, commit, PHASE)
    fresh = collect(); case.admission(fresh)
    require(before['owner'] == fresh['owner'] and before['isolation'] == fresh['isolation']
            and min(fresh['host_free_bytes'], fresh['root']['varlib_free_bytes']) >= START_FREE
            and wake.device(case.QUIESCENT, root=True)['active_jobs'] == 0, 'fresh-before-first-write')
    root = lease['proof_root']
    q = {'action': 'build', 'proof_root': root, 'nonce': root[-16:], 'deadline': deadline,
         'start_free': fresh['root']['varlib_free_bytes'], 'images': IMAGES,
         'builder_source': code, 'builder_sha256': sha(code.encode())}
    wake.device(PROVISION, {'root': root}, root=True)
    body = native_program(code)
    result = failure = None
    try:
        with (ev.path/'native.stdout.private').open('xb') as out, (ev.path/'native.stderr.private').open('xb') as err:
            proc = subprocess.Popen([str(LP), 'exec', '-i', DEVICE, '/usr/local/bin/woowbk-owner', 'python3', '-I', '-c',
                                     body], stdin=subprocess.PIPE, stdout=out, stderr=err)
            try:
                proc.communicate(json.dumps(q).encode(), timeout=max(1, deadline-time.time()+CLEANUP_GRACE))
            except BaseException as exc:
                ev.save('transport-failure.private.json', {'exception_class': type(exc).__name__,
                        'errno': getattr(exc, 'errno', None), 'native_cleanup_deadline': deadline+CLEANUP_GRACE})
                # The in-device supervisor keeps authority over its own containers and cleanup: never race it.
                proc.wait(timeout=60); raise
        result = json.loads(small(ev.path/'native.stdout.private', MIB))
        ev.save('native-result.private.json', result)
    except BaseException as exc:
        failure = exc
    after = collect(); later = snapshot()
    exact = (before['owner'] == after['owner'] and before['isolation'] == after['isolation']
             and before['root']['installed_hashes'] == after['root']['installed_hashes']
             and before['root']['catalog_sha256'] == after['root']['catalog_sha256']
             and before['fixture'] == after['fixture'] and prior == later and later['engine'] == engine
             and wake.device(case.QUIESCENT, root=True)['active_jobs'] == 0)
    ev.save('final-target-proof.private.json', {'original_target_exact': exact, 'inventory': after, **later})
    passed = failure is None and proc.returncode == 0 and isinstance(result, dict) and result.get('status') == 'passed'

    def owned(action, request, prefix):
        with (ev.path/(prefix+'.stdout.private')).open('xb') as out, (ev.path/(prefix+'.stderr.private')).open('xb') as err:
            p = subprocess.run([str(LP), 'exec', '-i', DEVICE, '/usr/local/bin/woowbk-owner', 'podman', 'unshare',
                                'python3', '-I', '-c', body], input=json.dumps(dict(request, action=action)).encode(),
                               stdout=out, stderr=err, timeout=CLEANUP_GRACE)
        require(p.returncode == 0, prefix+'-failed-retained')
        return json.loads(small(ev.path/(prefix+'.stdout.private'), MIB))
    removal = None
    if passed and exact:
        request = dict(q, provenance_sha256=result['fixture']['provenance_sha256'])
        removal = owned('remove-source', request, 'source-removal')
        require(removal.get('status') == 'owned-source-removed', 'owned-source-cleanup-failed-retained')
    elif passed:
        # The original target changed while the build passed: the run fails; its own source, fixture and credentials go
        # (the before/after snapshots are the evidence), the records stay.
        removal = owned('discard', q, 'owned-discard')
    leftovers = wake.device(OWNED_LISTING, {'root': root})
    record = {'status': 'passed' if passed and exact else 'failed', 'phase': PHASE, 'source_commit': commit,
              'native_status': result.get('status') if isinstance(result, dict) else None,
              'original_target_exact': exact, 'owned_removal': removal, 'owned_leftovers': leftovers,
              'fixture': result.get('fixture') if passed and exact else None, 'engine_commit': ENGINE_COMMIT,
              'runtime_s5_import_acceptance': False, 'private_receipt_dir': str(ev.path)}
    ev.save('fixed-result.json', record); print(json.dumps(record))
    if failure is not None:
        raise failure
    require(passed, 'native-build-failed')
    require(exact, 'original-target-changed-owned-discarded')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true'); parser.add_argument('--lease', type=Path)
    parser.add_argument('--lease-template', action='store_true')
    args = parser.parse_args(argv)
    here = Path(__file__).resolve(); repo = here.parents[3]
    if args.lease_template:
        print(json.dumps(lease_template(repo), indent=2, sort_keys=True)); return 0
    if not args.run:
        print(json.dumps(contract(), sort_keys=True)); return 0
    require(args.lease is not None, 'lease-required')
    sys.path.insert(0, str(here.parent))   # python3 -I does not put the script's directory on the path
    from focus_nextcloud_r6_plan import lease_check
    commit, clean = checkout(repo)
    require(clean, 'clean-checkout')
    code = here.read_text(); lease = json.loads(args.lease.read_text())
    engine = engine_manifest(repo)
    deadline = admit_lease(lease, commit, code, engine, lease_check=lease_check)
    require(os.environ.get('HEAVY_FREE') == LOCK, 'heavy-seat-required')
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)   # blocking: heavy.sh only waited for the lock to be free
        locked_admission(lease, commit, deadline, lease_check=lease_check)
        return run_locked(lease, commit, code, deadline, engine)


if __name__ == '__main__':
    sys.exit(main())
