#!/usr/bin/env python3
"""CODE ONLY until separately leased: build a genuine, small SSE source fixture.

This is a generated HA-shaped TEST fixture, not an HAOS export or S5 acceptance.
Default invocation only prints the contract. --run needs an exact fresh lease,
the global heavy seat and the whole E mutex. No target install/wake/import occurs.
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
FLOOR = 13*GIB+512*MIB
CAPS = {'nc': 900*MIB, 'pg': 256*MIB, 'redis': 64*MIB}
IMAGES = {
    'nc': 'e80170f48ac2534abd0960be4838dbe9fcdc498da924a62f2436cd470dab4165',
    'pg': '9b05db12a35460fff0587e009f9326e414a53e9484555547f96d214a2ba98ef7',
    'redis': 'd1e21a26915a35a6eb5d820018cd55adfcda02e02f7d629e1f42df397d5494ad',
}
SLUG = 'woow-nextcloud-office'
PROFILE = '0.2.3'  # envelope compatibility profile, NOT an installed add-on version
VERSION = '35.0.1.1'
MAX_MEMBERS = 50000
USER = 's5owner'
ROOT_RE = r'/var/lib/woowbk-nextcloud-s5-[0-9a-f]{16}'
OCC_HELP = ('app:enable', 'app:list', 'status', 'encryption:enable',
            'encryption:status', 'encryption:list-modules', 'encryption:set-default-module',
            'encryption:enable-master-key', 'config:app:get')

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


def require(ok, reason):
    if not ok:
        raise ValueError('fixed-s5-'+reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


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


def native_program(code):
    # A -c program otherwise has __name__ == '__main__' and would run the host CLI.
    return "__name__='focus_nextcloud_r6_s5_native'\n"+code+'\ninternal_main(json.load(sys.stdin))\n'


def product():
    # The original installed reader is used only as a library. No bytecode anywhere.
    sys.dont_write_bytecode = True
    sys.path.insert(0, '/usr/local/lib/woowtech-cockpit-backup')
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


def build_fixture(work, proof, check=lambda: None):
    """Run in podman unshare after all source containers stopped cleanly.

    Actual config/custom_apps/PG/data are copied byte-for-byte. No rewritten PHP,
    SQL, encryption flags, paths inside config, fabricated app or synthetic key.
    All data (including every generated key file) goes into the share member.
    """
    ha, nc, od = product(); work = Path(work); out = work/'artifact'
    out.mkdir(mode=0o700, exist_ok=False)
    mappings = {'config': ('html/config', 'data/nextcloud/config', 'addon'),
                'apps': ('html/custom_apps', 'data/nextcloud/custom_apps', 'addon'),
                'pg': ('pg', 'data/postgres', 'addon'), 'data': ('data', 'nextcloud', 'share')}
    rows = {role: tree(work/src, check) for role, (src, _, _) in mappings.items()}
    require(sum(r['bytes'] for rs in rows.values() for r in rs.values()) < GIB-4*MIB, 'fixture-input-bound')
    require(proof.get('webdav_before') is True and proof.get('webdav_after_restart') is True
            and proof.get('master_key_enabled') is True and proof.get('pg_shutdown') is True,
            'native-source-proof-incomplete')
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
    require(dest.stat().st_size <= GIB, 'fixture-bound')
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
        self.next_disk = 0

    def check(self):
        free = shutil.disk_usage(self.root).free
        mem = int(Path('/sys/fs/cgroup/memory.current').read_text())
        self.lowest = min(self.lowest, free); self.peak = max(self.peak, mem)
        reason = ('expired' if time.time() >= self.deadline else 'reserve' if free < FLOOR else
                  'memory' if mem > 2560*MIB else 'combined-disk' if self.q['start_free']-free > 7*GIB else None)
        if reason: self.watch_failure = reason
        require(reason is None, 'watch-'+str(reason))
        if self.q['action'] == 'build' and time.monotonic() >= self.next_disk:
            self.next_disk = time.monotonic()+5
            # Apparent sizes + allocated blocks are both bounded, not just net free
            # space (another lane freeing disk cannot grant this case more bytes).
            for apparent in ([], ['--apparent-size']):
                p = subprocess.run(['podman', 'unshare', 'du', '-s', '-B1', *apparent, str(self.work)],
                                   capture_output=True, timeout=15)
                require(p.returncode == 0 and len(p.stdout) < 4096
                        and int(p.stdout.split()[0]) <= 7*GIB, 'owned-disk-cap')
            for name, cap in (('html', 2*GIB), ('pg', 512*MIB), ('data', 32*MIB)):
                path = self.work/name
                if path.exists():
                    p = subprocess.run(['podman', 'unshare', 'du', '-s', '-B1', '--apparent-size', str(path)],
                                       capture_output=True, timeout=15)
                    require(p.returncode == 0 and len(p.stdout) < 4096
                            and int(p.stdout.split()[0]) <= cap, 'component-disk-cap')

    def call(self, argv, data=None, timeout=180, allowed=(0,), cleanup=False):
        self.count += 1; base = self.work/('command-%04d'%self.count)
        with base.with_suffix('.stdout.private').open('xb') as out, base.with_suffix('.stderr.private').open('xb') as err:
            os.chmod(out.name, 0o600); os.chmod(err.name, 0o600)
            p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=out, stderr=err, start_new_session=True)
            error = None
            try:
                if data is not None:
                    # Inputs here are <= 2MiB; communicate drains stdin without blocking the watch loop.
                    os.set_blocking(p.stdin.fileno(), False); pending = memoryview(data)
                else: pending = memoryview(b'')
                until = time.monotonic()+timeout
                while p.poll() is None:
                    if cleanup: require(time.time() < self.deadline+600, 'cleanup-grace-expired')
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

    def occ(self, *args, data=None, allowed=(0,)):
        return self.call(['podman', 'exec', '-i', '-u', 'www-data', self.name('nc'),
                          'php', '/var/www/html/occ', *args], data=data, allowed=allowed)

    def unshare(self, action, **extra):
        request = dict(self.q, action=action, **extra)
        body = native_program(self.q['builder_source'])
        return json.loads(self.call(['podman', 'unshare', 'python3', '-I', '-c', body],
                                    json.dumps(request).encode(), timeout=900)[1])

    def run_container(self, role, args):
        # Name is registered BEFORE the request: interrupted create is reconciled by label+ID.
        self.created.append(role)
        raw = self.pod('run', '-d', '--pull=never', '--image-volume=ignore', '--name', self.name(role),
                      '--label', 'woowbk.s5='+self.q['nonce'], '--network', self.network,
                      '--memory', str(CAPS[role]), '--memory-swap', str(CAPS[role]), '--pids-limit=256', '--cpus=1',
                      '--log-driver=k8s-file', '--log-opt=max-size=4mb', *args)
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

    def wait_nc(self):
        until = min(self.deadline, time.time()+600)
        while time.time() < until:
            code, raw = self.call(['podman', 'exec', self.name('nc'), 'curl', '-fsS', '-m', '5',
                                  'http://localhost/status.php'], allowed=(0, 22, 7), timeout=15)
            if code == 0:
                state = json.loads(raw)
                if state.get('installed'):
                    require(state.get('version') == VERSION and state.get('maintenance') is False
                            and state.get('needsDbUpgrade') is False, 'nc-version-state'); return
            self.check(); time.sleep(2)
        raise ValueError('fixed-s5-bootstrap-timeout')

    def encryption(self):
        self.stage = 'occ-help-and-master-key-before-put'
        _, commands = self.occ('list', '--raw'); names = {l.split()[0] for l in commands.decode().splitlines() if l.strip()}
        require({'app:enable', 'app:list', 'status', 'config:app:get'} <= names, 'occ-base-commands')
        # App activation is native; no appconfig SQL or fabricated key files.
        for cmd in ('app:enable', 'app:list', 'status', 'config:app:get'):
            _, raw = self.occ('help', cmd); require(cmd.encode() in raw, 'occ-help-command')
        self.occ('app:enable', 'encryption')
        _, commands = self.occ('list', '--raw'); names = {l.split()[0] for l in commands.decode().splitlines() if l.strip()}
        require(set(OCC_HELP) <= names, 'occ-encryption-commands')
        help_hashes = {}
        for cmd in OCC_HELP:
            _, raw = self.occ('help', cmd); require(cmd.encode() in raw, 'occ-help-command'); help_hashes[cmd] = sha(raw)
            if cmd in ('app:list', 'status', 'encryption:status'): require(b'--output' in raw, 'occ-json-help')
        _, raw = self.occ('status', '--output=json'); status = json.loads(raw)
        require(status.get('installed') is True and status.get('version') == VERSION
                and status.get('maintenance') is False, 'occ-status')
        _, raw = self.occ('app:list', '--output=json'); apps = json.loads(raw)
        require('encryption' in apps.get('enabled', {}), 'encryption-app-not-enabled')
        _, raw = self.occ('encryption:status', '--output=json'); initial = json.loads(raw)
        require(initial.get('enabled') is False and initial.get('defaultModule') in ('', 'OC_DEFAULT_MODULE'),
                'unexpected-initial-encryption')
        code, raw = self.occ('config:app:get', 'encryption', 'useMasterKey', allowed=(0, 1))
        require((code == 1 and not raw.strip()) or (code == 0 and raw.strip() in (b'', b'0')), 'unexpected-initial-master-key')
        self.occ('encryption:list-modules')
        self.occ('encryption:set-default-module', 'OC_DEFAULT_MODULE')
        self.occ('encryption:enable')
        # Native command + native confirmation stdin. No invented --force/--yes option.
        self.occ('encryption:enable-master-key', data=b'yes\n')
        _, raw = self.occ('encryption:status', '--output=json'); state = json.loads(raw)
        require(state.get('enabled') is True and state.get('defaultModule') == 'OC_DEFAULT_MODULE', 'encryption-state')
        _, raw = self.occ('config:app:get', 'encryption', 'useMasterKey'); require(raw.strip() == b'1', 'master-key-state')
        _, raw = self.occ('config:app:get', 'encryption', 'masterKeyId'); master = raw.decode().strip()
        require(re.fullmatch(r'master_[A-Za-z0-9_-]{4,100}', master) is not None, 'master-key-id')
        private(self.work/'occ-gate.private.json', {'help_sha256': help_hashes, 'state': state, 'master_key_id': master})
        return master

    def dav(self, password, name, method, value=None):
        q = {'password': password, 'name': name, 'method': method}
        if value is not None: q['data'] = base64.b64encode(value).decode()
        return json.loads(self.pod('exec', '-i', '-u', 'www-data', self.name('nc'), 'php', '-r', DAV,
                                   data=json.dumps(q).encode()))

    def execute(self):
        require(self.q['images'] == IMAGES and sum(CAPS.values()) == 1220*MIB, 'pin-cap-contract')
        for role, ident in IMAGES.items():
            raw = self.pod('image', 'inspect', '--format', '{{.Id}} {{.Architecture}} {{.Os}}', 'sha256:'+ident)
            require(raw.decode().strip().removeprefix('sha256:') == ident+' amd64 linux', 'source-image-identity')
        require(self.q['start_free'] >= 20*GIB, 'start-free'); self.check()
        for name in ('html', 'pg', 'data'): (self.work/name).mkdir(mode=0o700)
        self.stage = 'new-source-bootstrap'
        # No original files are cloned. Own generated secrets never enter argv or public output.
        password, dbpass = secrets.token_hex(24), secrets.token_hex(24)
        private(self.work/'credentials.private.json', {'admin': password, 'database': dbpass})
        for role, value in (('admin', password), ('dbpass', dbpass)):
            name = self.name(role); self.secret_ids.append(name)
            self.pod('secret', 'create', '--label', 'woowbk.s5='+self.q['nonce'], name, '-', data=value.encode())
        self.network = self.name('net')
        self.pod('network', 'create', '--internal', '--label', 'woowbk.s5='+self.q['nonce'], self.network)
        net = json.loads(self.pod('network', 'inspect', self.network))[0]
        require(net.get('internal') is True and net.get('labels', {}).get('woowbk.s5') == self.q['nonce'], 'internal-network')
        env = ['--env=POSTGRES_USER=nextcloud', '--env=POSTGRES_DB=nextcloud',
               '--secret='+self.name('dbpass')+',type=env,target=POSTGRES_PASSWORD']
        self.run_container('pg', env+['-v', str(self.work/'pg')+':/var/lib/postgresql/data:U', 'sha256:'+IMAGES['pg']])
        self.run_container('redis', ['sha256:'+IMAGES['redis'], 'redis-server', '--save', '', '--appendonly', 'no'])
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
        self.run_container('nc', env+['--env=POSTGRES_HOST='+self.name('pg'), '--env=REDIS_HOST='+self.name('redis'),
                           '--env=NEXTCLOUD_ADMIN_USER='+USER, '--env=NEXTCLOUD_TRUSTED_DOMAINS=localhost',
                           '--env=NEXTCLOUD_DATA_DIR=/share/nextcloud', '--env=PHP_MEMORY_LIMIT=512M',
                           '--secret='+self.name('admin')+',type=env,target=NEXTCLOUD_ADMIN_PASSWORD',
                           '-v', str(self.work/'html')+':/var/www/html:U',
                           '-v', str(self.work/'data')+':/share/nextcloud:U', 'sha256:'+IMAGES['nc']])
        self.wait_nc(); master = self.encryption()
        self.stage = 'native-webdav-put-and-get'
        # Two tiny deterministic plaintexts; no copy of any existing fixture.
        files = {'s5-binary.bin': bytes(range(256))*4096,
                 's5-utf8.txt': ('真實加密來源驗證\n'*2048).encode()}
        require(sum(map(len, files.values())) <= 2*MIB, 'plaintext-bound')
        for name, value in files.items():
            require(self.dav(password, name, 'PUT', value)['status'] == 201, 'webdav-put')
            require(self.dav(password, name, 'GET') == {'status': 200, 'bytes': len(value), 'sha256': sha(value)}, 'webdav-plaintext')
            require(self.dav(password+'-wrong', name, 'GET')['status'] == 401, 'webdav-wrong-auth')
        proof = {'webdav_before': True, 'master_key_enabled': True,
                 'occ_gate_sha256': digest(self.work/'occ-gate.private.json'),
                 'component_version_output_sha256': {'pg': sha(pg_banner), 'redis': sha(redis_banner)},
                 'plaintext': {n: {'bytes': len(v), 'sha256': sha(v)} for n, v in files.items()}}
        proof['cipher_and_keys'] = self.unshare('cipher', plaintext=proof['plaintext'], master=master)
        self.stage = 'source-nc-restart-and-plaintext'
        self.pod('restart', '--time=60', self.name('nc')); self.wait_nc()
        for name, value in files.items():
            require(self.dav(password, name, 'GET') == {'status': 200, 'bytes': len(value), 'sha256': sha(value)}, 'restart-plaintext')
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
                      '--label', 'woowbk.s5='+self.q['nonce'], '--network=none', '--read-only', '--memory=67108864',
                      '--pids-limit=64', '-v', str(self.work/'pg')+':/cluster:ro', '--user=postgres',
                      '--entrypoint=pg_controldata', 'sha256:'+IMAGES['pg'], '/cluster')
        require(re.search(rb'Database cluster state:\s+shut down\s*\n', raw) is not None, 'pg-not-cleanly-shut-down')
        proof['pg_shutdown'] = True; proof['pg_controldata_sha256'] = sha(raw)
        self.stage = 'cold-source-packaging'
        result = self.unshare('package', proof=proof)
        self.stage = 'packaged-source-proof'; private(self.work/'source-result.json', result)
        return result

    def cleanup(self):
        """Only registered names with this run's exact label; data retained on failure."""
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
            row = json.loads(self.pod('secret', 'inspect', name, cleanup=True))[0]
            require(row.get('Spec', {}).get('Labels', {}).get('woowbk.s5') == self.q['nonce'], 'cleanup-secret-ownership')
            self.pod('secret', 'rm', name, cleanup=True)


def internal_main(q):
    """Only reached by the separately leased host launcher or its owned unshare worker."""
    sys.dont_write_bytecode = True; os.umask(0o077)
    require(re.fullmatch(ROOT_RE, q['proof_root']) is not None and q['proof_root'].endswith(q['nonce']), 'root-binding')
    require(sha(q['builder_source'].encode()) == q['builder_sha256'], 'builder-binding')
    require(time.time() < q['deadline'], 'native-expired')
    work = Path(q['proof_root'])/'owned'
    require(work.is_dir() and not work.is_symlink(), 'owned-work')
    if q['action'] in ('cipher', 'package', 'remove-source'):
        # Root within podman unshare can read container UID-mapped source bytes.
        guard = Native(q).check
        if q['action'] == 'package': result = build_fixture(work, q['proof'], guard)
        elif q['action'] == 'remove-source':
            provenance = work/'artifact/provenance.private.json'
            require(digest(provenance, guard) == q['provenance_sha256'], 'cleanup-provenance')
            doc = json.loads(small(provenance, 64*MIB))
            require(digest(work/'artifact/generated-s5-source.tar', guard) == doc['archive']['sha256'], 'cleanup-artifact')
            for role, (src, _, _) in doc['mappings'].items():
                require(src in ('html/config', 'html/custom_apps', 'pg', 'data')
                        and tree(work/src, guard) == doc['source_files'][role], 'cleanup-cold-tree-changed')
            # Only the exact newly allocated source leaves, after parent-side
            # original-target proof. Nothing in /home/appowner is removed.
            for name in ('html', 'pg', 'data'): shutil.rmtree(work/name)
            result = {'status': 'owned-source-removed', 'fixture_retained': True}
        else:
            rows = tree(work/'data', guard, limit=32*MIB); result = {}
            for name, plain in q['plaintext'].items():
                rel = USER+'/files/'+name; row = rows.get(rel)
                require(row and row['bytes'] > plain['bytes'] and row['sha256'] != plain['sha256'], 'native-ciphertext')
                with (work/'data'/rel).open('rb') as f: head = f.read(8192)
                require(head.startswith(b'HBEGIN:') and b':HEND' in head
                        and b'oc_encryption_module:OC_DEFAULT_MODULE' in head, 'native-cipher-header')
                result[rel] = {'bytes': row['bytes'], 'sha256': row['sha256']}
            keyrows = {n: r for n, r in rows.items() if 'files_encryption' in n.split('/') and r['sha256'] is not None}
            require(keyrows and all(0 < r['bytes'] < MIB for r in keyrows.values()), 'actual-key-material')
            for suffix in (q['master']+'.privateKey', q['master']+'.publicKey'):
                require(any(n.endswith('/'+suffix) for n in keyrows), 'native-master-key-files')
            for name in q['plaintext']:
                require(any('/files/'+name+'/OC_DEFAULT_MODULE/' in n and n.endswith('/fileKey') for n in keyrows),
                        'native-file-key')
                require(any('/files/'+name+'/OC_DEFAULT_MODULE/' in n and n.endswith('/'+q['master']+'.shareKey')
                            for n in keyrows), 'native-share-key')
            result.update({n: {'bytes': r['bytes'], 'sha256': r['sha256']} for n, r in keyrows.items()})
        print(json.dumps(result)); return
    require(q['action'] == 'build' and os.getuid() != 0, 'owner-only-build')
    native = Native(q); result = None; failure = None
    try:
        result = native.execute()
    except BaseException as exc:
        failure = exc
        private(work/'failure.private.json', {'stage': native.stage, 'exception_class': type(exc).__name__,
                'errno': getattr(exc, 'errno', None), 'traceback': traceback.format_exc(),
                'watch_failure': native.watch_failure})
    finally:
        try: native.cleanup()
        except BaseException as exc:
            private(work/'cleanup-failure.private.json', {'exception_class': type(exc).__name__,
                    'traceback': traceback.format_exc()}); failure = failure or exc
        fixed = {'status': 'failed' if failure else 'passed', 'phase': native.stage,
                 'watch_failure': native.watch_failure, 'minimum_free_bytes': native.lowest,
                 'peak_memory_bytes': native.peak, 'fixture': result,
                 's5_import_acceptance': False, 'target_mutation': False, 'pulls': 0}
        private(work/'fixed-result.json', fixed); print(json.dumps(fixed))
    if failure: raise SystemExit(2)


def contract():
    return {'phase': 's5-source-fixture-build', 'code_only_until_leased': True, 'images': IMAGES,
            'component_caps': CAPS, 'minimum_start_free_bytes': 20*GIB, 'additional_disk_cap_bytes': 7*GIB,
            'fixture_cap_bytes': GIB, 'reserve_bytes': 13*GIB, 'watch_floor_bytes': FLOOR,
            'device_memory_cap_bytes': 3*GIB, 's5_import_acceptance': False,
            'target_wake': False, 'target_source_install': False, 'pulls': 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true'); parser.add_argument('--lease', type=Path)
    args = parser.parse_args(argv)
    if not args.run: print(json.dumps(contract(), sort_keys=True)); return 0
    require(args.lease is not None, 'lease-required')
    # Reuse existing exact prior-source/baseline/unit/image probes. Never read the 4.47GB fixture.
    import focus_nextcloud_r6_case as case
    import focus_nextcloud_r6_wake as wake
    import focus_nextcloud_r6_upload as upload
    from focus_nextcloud_r6_inventory import collect, LP, DEVICE
    from focus_nextcloud_r6_plan import lease_check
    here = Path(__file__).resolve(); repo = here.parents[3]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=repo), 'clean-checkout')
    code = here.read_text(); lease = json.loads(args.lease.read_text())
    lease_check(lease, commit, 's5-source-fixture-build')
    require(lease.get('builder_sha256') == sha(code.encode()) and lease.get('images') == IMAGES
            and lease.get('component_caps') == CAPS and lease.get('minimum_start_free_bytes') == 20*GIB
            and lease.get('additional_disk_cap_bytes') == 7*GIB and lease.get('fixture_cap_bytes') == GIB
            and lease.get('cleanup_grace_seconds') == 600 and lease.get('target_wake') is False
            and lease.get('target_source_install') is False and lease.get('target_restore') is False
            and lease.get('image_operations') == [], 'lease-builder-contract')
    root = lease['proof_root']; require(re.fullmatch(ROOT_RE, root) is not None, 'lease-root')
    deadline = datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z', '+00:00')).timestamp()
    require(deadline-time.time() >= 1800, 'lease-headroom')
    require(os.environ.get('HEAVY_FREE') == '/tmp/woowbk-dev-e-mutation.lock', 'heavy-seat-required')
    with open('/tmp/woowbk-dev-e-mutation.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = collect(); case.admission(before)
        require(min(before['host_free_bytes'], before['root']['varlib_free_bytes']) >= 20*GIB, 'fresh-start-disk')
        require(wake.device(case.QUIESCENT, root=True)['active_jobs'] == 0, 'native-jobs')
        ev = upload.Evidence(Path.home()/'.woowbk-lab/evidence/focus-nextcloud-r6-s5'/time.strftime('%Y%m%dT%H%M%S'))
        qmeta = {'deadline': deadline, 'ha_id': upload.HA_ID, 'prior_sha256': upload.PRIOR_SHA,
                 'helper_sha256': upload.HELPER_SHA, 'version_sha256': upload.VERSION_SHA}
        meta = wake.device(upload.meta_program(), qmeta, root=True)
        units = wake.device(wake.unit_program(), {'action': 'snapshot'})
        baseline = wake.device(wake.BASELINE_HASH, root=True, timeout=600)
        store = wake.device(STORE_SNAPSHOT)
        ev.save('before.private.json', {'inventory': before, 'metadata': meta, 'units': units, 'baseline': baseline, 'store': store})
        lease_check(lease, commit, 's5-source-fixture-build')
        fresh = collect(); case.admission(fresh)
        require(before['owner'] == fresh['owner'] and before['isolation'] == fresh['isolation']
                and min(fresh['host_free_bytes'], fresh['root']['varlib_free_bytes']) >= 20*GIB
                and wake.device(case.QUIESCENT, root=True)['active_jobs'] == 0, 'fresh-before-first-write')
        q = {'action': 'build', 'proof_root': root, 'nonce': root[-16:], 'deadline': deadline,
             'start_free': fresh['root']['varlib_free_bytes'], 'images': IMAGES,
             'builder_source': code, 'builder_sha256': sha(code.encode())}
        provision = """import json,os,pathlib,pwd,stat,sys
q=json.load(sys.stdin);p=pathlib.Path(q['root']);s=p.parent.lstat()
assert p.parent==pathlib.Path('/var/lib') and stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
assert not p.exists() and not p.is_symlink()
p.mkdir(mode=0o711);owner=pwd.getpwnam('appowner');d=p/'owned';d.mkdir(mode=0o700);os.chown(d,owner.pw_uid,owner.pw_gid)
print(json.dumps({'status':'created'}))
"""
        wake.device(provision, {'root': root}, root=True)
        result = None
        try:
            body = native_program(code)
            with (ev.path/'native.stdout.private').open('xb') as out, (ev.path/'native.stderr.private').open('xb') as err:
                proc = subprocess.Popen([str(LP), 'exec', '-i', DEVICE, '/usr/local/bin/woowbk-owner',
                                         'python3', '-I', '-c', body], stdin=subprocess.PIPE, stdout=out, stderr=err)
                try: proc.communicate(json.dumps(q).encode(), timeout=max(1, deadline-time.time()+600))
                except BaseException as exc:
                    ev.save('transport-failure.private.json', {'exception_class': type(exc).__name__,
                            'errno': getattr(exc, 'errno', None), 'native_cleanup_deadline': deadline+600})
                    # The in-device supervisor retains authority to stop its own
                    # containers; never race it by launching a second build.
                    proc.wait(timeout=60); raise
            raw = small(ev.path/'native.stdout.private', MIB)
            result = json.loads(raw); ev.save('native-result.private.json', result)
            require(proc.returncode == 0 and result.get('status') == 'passed', 'native-build-failed')
        finally:
            after = collect()
            after_meta = wake.device(upload.meta_program(), qmeta, root=True)
            after_units = wake.device(wake.unit_program(), {'action': 'snapshot'})
            after_baseline = wake.device(wake.BASELINE_HASH, root=True, timeout=600)
            after_store = wake.device(STORE_SNAPSHOT)
            exact = (before['owner'] == after['owner'] and before['isolation'] == after['isolation']
                     and before['root']['installed_hashes'] == after['root']['installed_hashes']
                     and before['root']['catalog_sha256'] == after['root']['catalog_sha256']
                     and before['fixture'] == after['fixture']
                     and meta == after_meta and units == after_units and baseline == after_baseline and store == after_store
                     and wake.device(case.QUIESCENT, root=True)['active_jobs'] == 0)
            ev.save('final-target-proof.private.json', {'original_target_exact': exact, 'inventory': after,
                    'metadata': after_meta, 'units': after_units, 'baseline': after_baseline})
            require(exact, 'original-target-changed-stop-retain')
        cleanup_q = dict(q, action='remove-source', provenance_sha256=result['fixture']['provenance_sha256'])
        body = native_program(code)
        with (ev.path/'source-cleanup.stdout.private').open('xb') as out, (ev.path/'source-cleanup.stderr.private').open('xb') as err:
            p = subprocess.run([str(LP), 'exec', '-i', DEVICE, '/usr/local/bin/woowbk-owner',
                                'podman', 'unshare', 'python3', '-I', '-c', body],
                               input=json.dumps(cleanup_q).encode(), stdout=out, stderr=err, timeout=600)
        require(p.returncode == 0, 'owned-source-cleanup-failed-retained')
        print(json.dumps({'status': 'passed', 'fixture': result['fixture'], 'original_target_exact': True,
                          'runtime_s5_import_acceptance': False})); return 0


if __name__ == '__main__':
    sys.exit(main())
