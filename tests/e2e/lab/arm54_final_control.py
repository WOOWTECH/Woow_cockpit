"""Local coordinator for the 2026-11-23 ARM54 final lane.

Targets only the owner-authorized test machines: 192.168.2.54 (sole owner, private
store mutations) and 192.168.2.34 (read-only). The password is never an argument,
file or log line: ssh reads it through SSH_ASKPASS (ARM54_ASKPASS names the helper,
which only prints $ARMHA_PW from this process environment).

  python3 tests/e2e/lab/arm54_final_control.py access     # SSH cause check (.54)
  python3 tests/e2e/lab/arm54_final_control.py attest     # .34 read-only provenance
  python3 tests/e2e/lab/arm54_final_control.py init       # .54 baseline + workspace
  python3 tests/e2e/lab/arm54_final_control.py upload     # code, real archive, client state
  python3 tests/e2e/lab/arm54_final_control.py run --script S --output O [--arg A ...]
  python3 tests/e2e/lab/arm54_final_control.py tools-provenance --debs D --output O   # Debian chain for age/zstd
  python3 tests/e2e/lab/arm54_final_control.py upload-large --debs D --output O       # code + the two .deb files
  python3 tests/e2e/lab/arm54_final_control.py audit --output O   # read-only compare
"""
import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time

REPO = Path(__file__).resolve().parents[3]
LAB = REPO / 'tests/e2e/lab'
EVIDENCE = LAB / 'evidence/arm54-final-20261123'
STATE = Path('/tmp/arm54-final-20261123-state.json')
KNOWN = '/tmp/ha-test-54-known-hosts'
HOST54 = '192.168.2.54'
HOST34 = '192.168.2.34'
FIXTURES = Path.home() / '.woowbk-lab/ha-fixtures'
ARCHIVE = FIXTURES / '20261119-b1/arm/woow-b1-arm-plain/woow-b1-arm-plain.tar'
# Real RPi5 backups this lane restores (slug -> encrypted?); bytes are attested against the RPi5 by `attest`.
RESTORE_SOURCES = {'plain': ('45670371', False), 'enc': ('a2dc9bfd', True)}
CLIENT_STATE = Path.home() / '.woowbk-lab/storage/volumes/b1-ts-alice-state/_data'
CLIENT_RECORD = Path.home() / '.woowbk-lab/evidence/b1-source/arm/tailscale-client-alice.json'
# The four B1 backups the RPi5 made on 2026-11-19 (slug -> file name in /backup there).
SOURCE_BACKUPS = {
    '45670371': 'woow-b1-arm-plain',
    'b6cbc980': 'woow-b1-arm-emqx-stopped-enc',
    'a2dc9bfd': 'woow-b1-arm-enc',
    '79278485': 'woow-b1-arm-enc-uncompressed',
}
SECRET_WORDS = ('PWD', 'PASS', 'KEY', 'TOKEN', 'SECRET', 'CRED', 'AUTH', 'SIG')
FIXED_PREDICATES = (
    ('authentication_denied', b'permission denied'),
    ('host_key_verification_failed', b'host key verification failed'),
    ('connection_refused', b'connection refused'),
    ('connection_timed_out', b'connection timed out'),
    ('no_route_to_host', b'no route to host'),
)


def ssh_argv(host, *, strict=True):
    return ['ssh', '-o', 'StrictHostKeyChecking=' + ('yes' if strict else 'accept-new'),
            '-o', 'UserKnownHostsFile=' + KNOWN, '-o', 'ConnectTimeout=10', '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'LogLevel=ERROR',
            'root@' + host]


def ssh_env(with_password=True):
    env = dict(os.environ)
    helper = env.get('ARM54_ASKPASS')
    if not helper or not Path(helper).is_file():
        raise SystemExit('ARM54_ASKPASS must name the askpass helper')
    env.update(SSH_ASKPASS=helper, SSH_ASKPASS_REQUIRE='force', DISPLAY=env.get('DISPLAY', ':0'))
    if not with_password:
        env.pop('ARMHA_PW', None)
    elif not env.get('ARMHA_PW'):
        raise SystemExit('ARMHA_PW is not set in this command environment')
    return env


def fixed_diagnostics(stderr):
    low = (stderr or b'').lower()
    return {name: token in low for name, token in FIXED_PREDICATES}


def remote(host, code, *, timeout=600, with_password=True, strict=True):
    """Run python3 code on `host` as root; returns CompletedProcess (stderr is never exported raw)."""
    return subprocess.run(ssh_argv(host, strict=strict) + ['python3 -'], input=code.encode(), capture_output=True,
                          env=ssh_env(with_password), timeout=timeout, start_new_session=True)


def source_commit():
    head = subprocess.run(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(['git', '-C', str(REPO), 'status', '--porcelain', '--untracked-files=no'],
                           capture_output=True, text=True).stdout.strip()
    return head, bool(dirty)


def write_result(output, *, source, result, elapsed, extra=None):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    head, dirty = source_commit()
    (EVIDENCE / (output + '.source.txt')).write_text(source)
    stdout = result.stdout or b''
    (EVIDENCE / (output + '.json')).write_bytes(stdout)
    meta = {'exit': result.returncode, 'elapsed_seconds': round(elapsed, 1),
            'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'source_commit': head, 'tree_dirty': dirty,
            'commercial_acceptance': 'not-complete'}
    if result.returncode:
        meta['fixed_diagnostics'] = fixed_diagnostics(result.stderr)
        meta['raw_stderr_exported'] = False
    meta.update(extra or {})
    (EVIDENCE / (output + '.exit.json')).write_text(json.dumps(meta, sort_keys=True) + '\n')
    return meta


def require_clean():
    head, dirty = source_commit()
    if dirty:
        raise SystemExit('commit tested code before a real lab run (tracked files are dirty)')
    return head


# ------------------------------------------------------------------ access cause (.54)

def access():
    """One deliberately password-less attempt (askpass prints an empty value) and one normal attempt."""
    code = 'import platform; print(platform.machine())'
    start = time.monotonic()
    without = remote(HOST54, code, timeout=60, with_password=False)
    with_pw = remote(HOST54, code, timeout=60)
    doc = {'host': HOST54, 'known_hosts': KNOWN,
           'without_password_env': {'ssh_exit': without.returncode, 'fixed_diagnostics': fixed_diagnostics(without.stderr)},
           'with_password_env': {'ssh_exit': with_pw.returncode, 'machine': with_pw.stdout.decode().strip()},
           'raw_stderr_exported': False}
    doc['cause'] = ('askpass-without-ARMHA_PW-gives-empty-password' if without.returncode == 255
                    and doc['without_password_env']['fixed_diagnostics']['authentication_denied']
                    and with_pw.returncode == 0 else 'unexplained')
    result = subprocess.CompletedProcess([], 0 if doc['cause'] != 'unexplained' else 1,
                                         (json.dumps(doc, sort_keys=True) + '\n').encode(), b'')
    print(json.dumps(write_result('ssh-access-cause', source=code, result=result,
                                  elapsed=time.monotonic() - start)))
    return result.returncode


# ------------------------------------------------------------------ provenance (.34, read-only)

ATTEST = r'''import hashlib, json, subprocess, tarfile
FILES = FILES_MAP
def sha(path):
    d = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            d.update(b)
    return d.hexdigest()
listing = json.loads(subprocess.check_output(['ha', 'backups', 'list', '--raw-json'], timeout=40))
rows = {}
for b in listing.get('data', {}).get('backups', []):
    rows[b.get('slug')] = b
out = {'ha_result': listing.get('result'), 'backup_count': len(rows), 'backups': {}}
for slug, name in sorted(FILES.items()):
    info = json.loads(subprocess.check_output(['ha', 'backups', 'info', slug, '--raw-json'], timeout=40))
    data = info.get('data') or {}
    path = '/backup/' + name + '.tar'
    with tarfile.open(path) as t:
        doc = t.extractfile('./backup.json').read()
    out['backups'][slug] = {
        'listed': slug in rows, 'info_result': info.get('result'),
        'name': data.get('name'), 'date': data.get('date'), 'type': data.get('type'),
        'protected': data.get('protected'), 'compressed': data.get('compressed'),
        'size_bytes': data.get('size_bytes'), 'location': data.get('location'),
        'addons': sorted((a.get('slug'), a.get('version')) for a in data.get('addons') or []),
        'file': path, 'file_bytes': __import__('os').stat(path).st_size, 'file_sha256': sha(path),
        'backup_json_sha256': hashlib.sha256(doc).hexdigest()}
print(json.dumps(out, sort_keys=True))
'''


def local_fixture(slug):
    name = SOURCE_BACKUPS[slug]
    path = FIXTURES / '20261119-b1/arm' / name / (name + '.tar')
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    with tarfile.open(path) as tar:
        doc = tar.extractfile('./backup.json').read()
    meta = json.loads(doc)
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest.hexdigest(),
            'backup_json_sha256': hashlib.sha256(doc).hexdigest(), 'slug': meta.get('slug'),
            'date': meta.get('date'), 'protected': meta.get('protected'), 'compressed': meta.get('compressed'),
            'addons': sorted((a.get('slug'), a.get('version')) for a in meta.get('addons') or [])}


def compare_provenance(remote_doc, local_docs):
    """Pure comparison (unit tested): exact bytes, sha256, slug, date and add-on list per backup."""
    verdicts = {}
    for slug, local in sorted(local_docs.items()):
        seen = (remote_doc.get('backups') or {}).get(slug) or {}
        checks = {
            'listed_on_source': seen.get('listed') is True and seen.get('info_result') == 'ok',
            'slug_equal': local.get('slug') == slug,
            'size_equal': seen.get('file_bytes') == local['bytes'] == seen.get('size_bytes'),
            'sha256_equal': seen.get('file_sha256') == local['sha256'],
            'backup_json_equal': seen.get('backup_json_sha256') == local['backup_json_sha256'],
            'date_equal': bool(seen.get('date')) and str(seen.get('date')) == str(local.get('date')),
            'addons_equal': [list(x) for x in seen.get('addons') or []] == [list(x) for x in local['addons']],
        }
        verdicts[slug] = {'checks': checks, 'verified': all(checks.values())}
    return verdicts


def attest(output='source-provenance-34'):
    code = ATTEST.replace('FILES_MAP', repr(SOURCE_BACKUPS))
    start = time.monotonic()
    result = remote(HOST34, code, timeout=600)
    elapsed = time.monotonic() - start
    doc = {'source_host': HOST34, 'read_only_commands': ['ha backups list --raw-json', 'ha backups info <slug> --raw-json',
                                                         'sha256 + stat of /backup/<name>.tar', 'read backup.json']}
    if result.returncode == 0:
        seen = json.loads(result.stdout)
        local = {slug: local_fixture(slug) for slug in SOURCE_BACKUPS}
        doc.update(source=seen, local={k: {x: v[x] for x in v if x != 'path'} | {'path': v['path']}
                                         for k, v in local.items()},
                   verdicts=compare_provenance(seen, local))
        doc['source_backup_origin_verified'] = all(v['verified'] for v in doc['verdicts'].values())
        doc['scope'] = ('bytes on the RPi5 now equal the local fixtures; it does not prove who created them '
                        'originally beyond the RPi5 HA supervisor record')
    out = subprocess.CompletedProcess([], result.returncode if result.returncode else
                                      (0 if doc.get('source_backup_origin_verified') else 1),
                                      (json.dumps(doc, sort_keys=True) + '\n').encode(), result.stderr)
    meta = write_result(output, source=code, result=out, elapsed=elapsed)
    print(json.dumps({'exit': meta['exit'], 'verified': doc.get('source_backup_origin_verified')}))
    return out.returncode


# ------------------------------------------------------------------ .54 baseline, upload, run, audit

INVENTORY = r'''import hashlib, json, os, pathlib, shutil, subprocess
def run(args, timeout=60):
    p = subprocess.run(args, capture_output=True, timeout=timeout)
    return p.stdout.decode('utf-8', 'replace').splitlines() if p.returncode == 0 else ['<exit %d>' % p.returncode]
def sha(path):
    try:
        return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    except OSError as e:
        return '<%s>' % type(e).__name__
inv = {}
inv['containers'] = run(['podman', 'ps', '-a', '--no-trunc', '--format', '{{.ID}} {{.Names}} {{.Image}} {{.State}} {{.Ports}}'])
inv['container_started'] = {}
for cid in run(['podman', 'ps', '-aq', '--no-trunc']):
    d = json.loads(subprocess.check_output(['podman', 'inspect', cid], timeout=30))[0]
    inv['container_started'][d['Name']] = [d['State']['Running'], d['State']['StartedAt'], d['State']['Pid']]
inv['images'] = run(['podman', 'images', '-a', '--no-trunc', '--format', '{{.ID}} {{.Repository}}:{{.Tag}}'])
inv['volumes'] = run(['podman', 'volume', 'ls', '--format', '{{.Name}}'])
inv['networks'] = run(['podman', 'network', 'ls', '--format', '{{.Name}}'])
inv['pods'] = run(['podman', 'pod', 'ps', '--format', '{{.Name}}'])
inv['etc_containers_networks'] = sorted(os.listdir('/etc/containers/networks')) if os.path.isdir('/etc/containers/networks') else []
inv['account_files'] = {p: sha(p) for p in ('/etc/passwd', '/etc/group', '/etc/subuid', '/etc/subgid')}
inv['linger'] = sorted(os.listdir('/var/lib/systemd/linger')) if os.path.isdir('/var/lib/systemd/linger') else []
# item C (OwnerRunner rootless): account backups, homes, the user@ drop-ins and the uidmap binaries must come back too
inv['account_backup_files'] = {p: sha(p) for p in ('/etc/passwd-', '/etc/group-', '/etc/subuid-', '/etc/subgid-')}
inv['home_dirs'] = sorted(os.listdir('/home'))
inv['etc_systemd_system'] = sorted(n + ('/' + ','.join(sorted(os.listdir('/etc/systemd/system/' + n))) if n.endswith('.d') and os.path.isdir('/etc/systemd/system/' + n) else '') for n in os.listdir('/etc/systemd/system'))
inv['uidmap_binaries'] = [os.path.exists('/usr/bin/newuidmap'), os.path.exists('/usr/bin/newgidmap')]
inv['services_running'] = sorted(l.split()[0] for l in run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--plain']) if l.strip())
inv['service_started'] = {u: run(['systemctl', 'show', '-p', 'ActiveEnterTimestampMonotonic', '--value', u]) for u in ('tailscaled.service', 'ssh.service', 'podman.socket')}
inv['pi_user_units'] = sorted(l.split()[0] for l in run(['systemctl', '--machine=pi@.host', '--user', 'list-units', '--type=service', '--state=running', '--no-legend', '--plain']) if l.strip())
inv['pi_web_started'] = run(['systemctl', '--machine=pi@.host', '--user', 'show', '-p', 'ActiveEnterTimestampMonotonic', '--value', 'pi-web.service'])
inv['links'] = sorted(' '.join(l.split()[:2]) for l in run(['ip', '-br', 'link']))
inv['addresses'] = sorted(run(['ip', '-br', 'addr']))
inv['listening'] = sorted(set(' '.join(l.split()[0:1] + l.split()[4:5]) for l in run(['ss', '-H', '-lntu'])))
inv['modules'] = sorted(l.split()[0] for l in run(['lsmod'])[1:])
inv['packages_sha256'] = hashlib.sha256('\n'.join(run(['dpkg-query', '-W', '-f', '${Package} ${Version} ${Status}\n'])).encode()).hexdigest()
nft = subprocess.run(['nft', '-s', 'list', 'ruleset'], capture_output=True, timeout=30) if shutil.which('nft') else None
# -s (stateless): packet/byte counters change with traffic and must not decide identity.
inv['nft_ruleset_stateless_sha256'] = hashlib.sha256(nft.stdout).hexdigest() if nft is not None and nft.returncode == 0 else None
inv['nft_tables_chains'] = sorted(l.strip().rstrip('{').strip() for l in nft.stdout.decode().splitlines() if l.strip().startswith(('table ', 'chain '))) if nft is not None and nft.returncode == 0 else None
inv['var_tmp_woow'] = sorted(n for n in os.listdir('/var/tmp') if n.startswith('woow'))
mounts = pathlib.Path('/proc/self/mountinfo').read_text().splitlines()
inv['mounts_naming_var_tmp_woow'] = sum('/var/tmp/woow' in m for m in mounts)
inv['run_netns'] = sorted(os.listdir('/run/netns')) if os.path.isdir('/run/netns') else []
inv['cgroup_libpod_parent'] = sorted(os.listdir('/sys/fs/cgroup/libpod_parent')) if os.path.isdir('/sys/fs/cgroup/libpod_parent') else []
inv['cgroup_top'] = sorted(n for n in os.listdir('/sys/fs/cgroup') if os.path.isdir('/sys/fs/cgroup/' + n))
EXTRA
print(json.dumps(inv, sort_keys=True))
'''

# Listening sockets of the originals (Home Assistant integrations, tailscaled) may move on their own; they are
# reported, not part of the identity verdict. Everything else must be byte-for-byte equal.
INFORMATIONAL = frozenset({'listening'})
SAMPLES = frozenset({'free_bytes', 'workspace', 'started_epoch', 'store_driver'})
DRIVERS = ('vfs', 'overlay')


def inventory_code(extra=''):
    return INVENTORY.replace('EXTRA', extra or 'pass')


def compare_inventory(before, after):
    """Pure comparison (unit tested): every strict key equal; informational keys only reported."""
    keys = sorted((set(before) | set(after)) - SAMPLES)
    strict = [k for k in keys if k not in INFORMATIONAL]
    diff = [k for k in strict if before.get(k) != after.get(k)]
    info = [k for k in keys if k in INFORMATIONAL and before.get(k) != after.get(k)]
    return {'compared_keys': strict, 'differing_keys': diff, 'informational_differences': info,
            'identical': not diff}


INIT_EXTRA = r'''
import tempfile, time
os.umask(0o077)
free = shutil.disk_usage('/var/tmp').free
assert free >= 12 * 1024 ** 3 + 2 * 1024 ** 3, 'reserve-refused'
root = pathlib.Path(tempfile.mkdtemp(prefix='woow-arm54-final-20261123-', dir='/var/tmp'))
for name in ('source', 'store', 'run', 'tmp', 'config', 'networks', 'input', 'work'):
    (root / name).mkdir(mode=0o700)
(root / 'empty-auth.json').write_text('{"auths":{}}')
(root / 'containers-override.conf').write_text('[network]\nnetwork_config_dir = "%s"\n[engine]\nevents_logger = "file"\n' % (root / 'networks'))
(root / 'store-driver').write_text(DRIVER_VALUE + '\n')
(root / 'baseline.json').write_text(json.dumps(inv, sort_keys=True))
inv['workspace'] = str(root)
inv['store_driver'] = DRIVER_VALUE
inv['free_bytes'] = shutil.disk_usage(root).free
inv['started_epoch'] = time.time()
'''


def init(output='baseline-before', driver='vfs'):
    if driver not in DRIVERS:
        raise SystemExit('unknown store driver')
    code = inventory_code(INIT_EXTRA.replace('DRIVER_VALUE', repr(driver)))
    start = time.monotonic()
    result = remote(HOST54, code, timeout=300)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start)
    if result.returncode == 0:
        doc = json.loads(result.stdout)
        STATE.write_text(json.dumps({'workspace': doc['workspace'], 'baseline': output}) + '\n')
        STATE.chmod(0o600)
    print(json.dumps({'exit': meta['exit'], 'workspace': json.loads(result.stdout).get('workspace') if result.returncode == 0 else None}))
    return result.returncode


def workspace():
    return json.loads(STATE.read_text())['workspace']


def scp(local, remote_path, *, timeout=600):
    argv = ['scp', '-q', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + KNOWN,
            '-o', 'ConnectTimeout=10', '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'LogLevel=ERROR',
            str(local), 'root@' + HOST54 + ':' + remote_path]
    return subprocess.run(argv, capture_output=True, env=ssh_env(), timeout=timeout, start_new_session=True)


CODE_FILES = ('arm54_final_runtime.py', 'arm54_final_build.py', 'arm54_final_headscale.py', 'arm54_final_cleanup.py',
              'arm54_final_sandbox_probe.py', 'arm54_final_omni_build.py', 'arm54_final_omnigent.py',
              'arm54_final_n8n_sandbox_probe.py', 'arm54_final_large_outer.py', 'arm54_final_n8n_build.py',
              'arm54_final_n8n.py', 'arm54_final_n8n_volume_probe.py', 'arm54_final_owner_common.py',
              'arm54_final_owner_setup.py', 'arm54_final_owner_headscale.py', 'arm54_final_owner_cleanup.py',
              'arm54_final_owner_images.py', 'arm54_final_owner_reset.py', 'arm54_final_owner_omnigent.py',
              'arm54_final_owner_secret_probe.py', 'arm54_final_netprobe.py', 'arm54_final_odoo_build.py',
              'arm54_final_odoo.py', 'arm54_final_emqx_build.py', 'arm54_final_emqx_lib.py',
              'arm54_final_emqx.py', 'arm54_final_emqx_volume_probe.py', 'arm54_final_owner_n8n.py',
              'arm54_final_owner_emqx.py', 'arm54_final_native_probe.py', 'arm54_final_owner_omnigent_public.py',
              'arm54_final_owner_odoo.py')
# Item D (EMQX on .54): the dev-d product harness's probe and acceptance function are READ from these sources by
# arm54_final_emqx.py (ast, never executed as modules); bundled and hash-checked like the code, never runnable.
PROBE_SOURCES = ('emqx_product_real_ha.py', 'ha_import_b1_e2e.py')
# Item C (lane arm54-2, owner approved 2026-11-23): Debian bookworm main uidmap for the OwnerRunner rootless runs
# (its digest equals the entry of the gpgv-verified bookworm Packages.xz; installed by arm54_final_owner_setup.py
# with dpkg -i and purged by arm54_final_owner_cleanup.py).
OWNER_DEB = ('uidmap_4.13+dfsg1-1+deb12u2_arm64.deb',
             '123d156d17ec56fd1cdc481c0e25531373bdb27d282803dd518df3bf59eecd82')
RECIPE = LAB / 'evidence/arm54-service-20261122/package.Containerfile'
PLATFORM = LAB / 'evidence/arm54-service-20261122/arm-platform-inputs.json'
OMNI_PACKAGE = EVIDENCE / 'omnigent-package-6e4f0c0'
N8N_PACKAGE = EVIDENCE / 'n8n-package-2ac1ae2'
ODOO_PACKAGE = EVIDENCE / 'odoo-package-c578b8a'  # Woow_podman_odoo quadlets for item B Odoo (substitute images)
# Lane arm54-2 item B: the RPi5 backups of 2026-11-19 with Odoo + n8n (no longer on .34). Owner decision 2026-11-23
# (「Odoo/n8n 用 A」): the 2026-11-19 records are the provenance -- dev-c's catalog holds conversions made on
# 2026-11-19 whose from_ha.ha_backup_id is 'ha-' + the archive's sha256[:20] (with HA's name and date).
ARM_FIXTURES = FIXTURES / '20261119-arm'
ARM_RECORDS = Path.home() / '.woowbk-lab/evidence/odoo-capture-20261121/list.json'
ARM_SOURCES = {  # kind -> (file stem, slug, sha256, encrypted)
    'arm-plain': ('woow-arm-plain', '8e51e2ed', '546aecf3be5a13642603bd901d49ee4de01313049d4cddf8805ef8c2b973be44',
                  False),
    'arm-enc': ('woow-arm-enc', '4f5c7337', 'a5fb626820a0947482a394094cd004715eb348fc92cec760c0dc7d9546f420e5', True),
    'arm-unc': ('woow-arm-enc-uncompressed', 'ba72ee84',
                '77ea8165e987260692da73aa4cd6ac9bdcb63807da743e1f25eb95650aba3033', True),
    # the same RPi5 and day, with code built for ARM only (an n8n community package and an Odoo module)
    'arm-native': ('woow-arm-native', 'e10f1abc', '7fc768a38011acd8681292b62ee9750014ac25137712738442eb616fd1023e29',
                   False),
}
# Lane arm54-2 item D (EMQX on .54): the B1 batch's two COLD EMQX backups (HA's EMQX add-on stopped; 2026-11-19), as
# recorded in b1-source/backups.json; the RPi5's b6cbc980 is also attested against the RPi5 (source-provenance-34).
EMQX_SOURCES = {  # kind -> (machine, file stem, slug, sha256)
    'b1-arm-cold': ('arm', 'woow-b1-arm-emqx-stopped-enc', 'b6cbc980',
                    'b6eb257cc5790bee30500f929d51ade66bfa8354dbe5bb61ba7c4bc08582f664'),
    'b1-x86-cold': ('x86', 'woow-b1-x86-emqx-stopped-enc', '5fb6f348',
                    '0a53e93888209316040af505484bba3ee3891c2ad2df7ae689bc0d4fd02690f9'),
}
B1_BACKUPS = Path.home() / '.woowbk-lab/evidence/b1-source/backups.json'
EMQX_PACKAGE = EVIDENCE / 'emqx-package-ea5886c'  # Woow_podman_emqx ea5886c quadlets + config (item D)
# The RPi5's B1 Omnigent facts recorded when the backup was made (b1-source summary, machine arm). Only ids, names,
# counts and digests travel; no credential is in this record.
B1_SUMMARY = Path.home() / '.woowbk-lab/evidence/b1-source/summary.json'
EXPECT_KEYS = ('server_version', 'alembic', 'pg', 'users', 'agent', 'scheduled_task', 'admin_session', 'attachment',
               'member_sessions', 'db_counts')


def omni_expect(summary):
    """The non-secret expectation subset for the Omnigent restore (unit tested). The summary's free-text `admin` and
    `member` notes are left out (they name the lab secret variables); the user ids come from `users`."""
    doc = {k: summary[k] for k in EXPECT_KEYS}
    admins = [u['id'] for u in doc['users'] if u['is_admin']]
    members = [u['id'] for u in doc['users'] if not u['is_admin']]
    if len(admins) != 1 or len(members) != 1:
        raise SystemExit('expected one HA admin and one HA member in the recorded source')
    doc['admin'], doc['member'] = admins[0], members[0]
    text = json.dumps(doc, sort_keys=True)
    for word in ('password', 'refresh_token', '"token"', 'cookie'):
        if word in text.lower():
            raise SystemExit('expectation subset would carry a credential field')
    return doc


def omni_creds(path):
    """HA's Omnigent test logins (b1-creds.env through the existing lab reader) into a new 0600 file; never printed,
    never hashed into evidence."""
    import ha_import_b1_e2e as b1
    secrets = b1.Secrets([b1.SECRET_DIR / 'b1-creds.env'], b1.SECRET_DIR / 'dev-d-markers.json')
    doc = {'admin': [secrets['B1_OMNI_ADMIN_USER'], secrets['B1_OMNI_ADMIN_PW']],
           'member': [secrets['B1_OMNI_MEMBER_USER'], secrets['B1_OMNI_MEMBER_PW']]}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(doc, handle)
    return doc['admin'][0], doc['member'][0]


def code_bundle(path, large=False):
    files = [p for p in (REPO / 'backup-engine').rglob('*')
             if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc']
    if large:  # the large-archive probe and its helpers (tests/backup/*.py; no evidence files)
        files += [REPO / 'tests/__init__.py'] + sorted((REPO / 'tests/backup').glob('*.py'))
    files += [LAB / name for name in CODE_FILES + PROBE_SOURCES if (LAB / name).exists()]
    files += [RECIPE, PLATFORM]
    files += sorted(p for p in (EVIDENCE / 'package-0afdfa4').rglob('*') if p.is_file())
    files += sorted(p for p in (EVIDENCE / 'hasqlite-variants').rglob('*') if p.is_file())
    files += sorted(p for p in (EVIDENCE / 'n8n-variants').rglob('*') if p.is_file())
    files += sorted(p for p in OMNI_PACKAGE.rglob('*') if p.is_file())
    files += sorted(p for p in N8N_PACKAGE.rglob('*') if p.is_file())
    files += sorted(p for p in ODOO_PACKAGE.rglob('*') if p.is_file())
    files += sorted(p for p in EMQX_PACKAGE.rglob('*') if p.is_file())
    with tarfile.open(path, 'w:gz') as tar:
        for item in sorted(files):
            tar.add(item, arcname=str(item.relative_to(REPO)))
    return {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


VERIFY_EXTRACT = r'''import hashlib, json, os, pathlib, tarfile
root = pathlib.Path(ROOT); os.umask(0o077)
def sha(p):
    d = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            d.update(b)
    return d.hexdigest()
out = {}
for name, want in sorted(WANT.items()):
    out[name] = sha(root / 'input' / name) == want
with tarfile.open(root / 'input' / 'code.tar.gz') as tar:
    for m in tar:
        p = pathlib.PurePosixPath(m.name)
        assert m.isfile() and m.size <= 8 * 1024 ** 2 and not p.is_absolute() and '..' not in p.parts
        dest = root / 'source' / m.name
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with dest.open('xb') as handle:
            handle.write(tar.extractfile(m).read())
if (root / 'input' / 'pydeps.tar').exists():
    with tarfile.open(root / 'input' / 'pydeps.tar') as tar:
        for m in tar:
            p = pathlib.PurePosixPath(m.name)
            assert m.isfile() and m.size <= 16 * 1024 ** 2 and not p.is_absolute() and '..' not in p.parts
            assert p.parts[0] == 'pydeps'
            dest = root / m.name
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with dest.open('xb') as handle:
                handle.write(tar.extractfile(m).read())
    out['pydeps_extracted'] = True
if (root / 'input' / 'client-state.tar').exists():
    os.chmod(root / 'input' / 'client-state.tar', 0o600)
for name, label in (('ha-key', 'staged_backup_unlock_file_private'), ('omni-creds.json', 'staged_login_file_private'),
                    ('n8n-creds.json', 'staged_n8n_login_file_private'),
                    ('emqx-creds.json', 'staged_emqx_login_file_private')):
    path = root / 'input' / name
    out[label] = (not path.exists()) or (path.stat().st_mode & 0o777 == 0o600 and path.stat().st_size > 0)
out['extracted'] = True
print(json.dumps(out, sort_keys=True))
'''


WHEELS = {  # PyPI digests checked against https://pypi.org/pypi/<project>/<version>/json on 2026-11-23
    'PyNaCl-1.5.0-cp36-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl':
        'a36d4a9dda1f19ce6e03c9a784a2921a4b726b02e1c736600ca9c22029474394',
    'cffi-1.17.1-cp311-cp311-manylinux_2_17_aarch64.manylinux2014_aarch64.whl':
        'a1ed2dd2972641495a3ec98445e09766f077aee98a1c896dcb4ad0d303628e41',
}


def pydeps_tar(wheel_dir, path):
    """The two pinned wheels unpacked under pydeps/ (a wheel is a zip of its install tree); refuses any other
    file or digest. Returns {wheel: sha256}."""
    import zipfile
    digests = {}
    with tarfile.open(path, 'w') as tar:
        for name, want in sorted(WHEELS.items()):
            data = (Path(wheel_dir) / name).read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest != want:
                raise SystemExit('wheel digest differs from the pinned PyPI digest: ' + name)
            digests[name] = digest
            with zipfile.ZipFile(io.BytesIO(data)) as wheel:
                for info in wheel.infolist():
                    parts = Path(info.filename).parts
                    if info.is_dir():
                        continue
                    if info.filename.startswith('/') or '..' in parts:
                        raise SystemExit('unsafe wheel member')
                    blob = wheel.read(info)
                    member = tarfile.TarInfo('pydeps/' + info.filename)
                    member.size, member.mode, member.mtime = len(blob), 0o600, 0
                    tar.addfile(member, io.BytesIO(blob))
    return digests


def client_state_tar(path):
    """The real B1 client (node b1-ts-alice) state copy; secret bytes, written 0600, never printed."""
    with tarfile.open(path, 'w') as tar:
        for item in sorted(CLIENT_STATE.rglob('*')):
            rel = item.relative_to(CLIENT_STATE)
            if rel.parts[0].startswith('tailscaled.log'):
                continue
            tar.add(item, arcname=str(rel), recursive=False)


def ha_backup_key(path):
    """The B1 HA backup key through the existing lab harness reader; written 0600, never printed or hashed."""
    import ha_import_b1_e2e as b1
    secrets = b1.Secrets([b1.SECRET_DIR / 'b1-creds.env', b1.SECRET_DIR / 'ha-import-creds.env'],
                         b1.SECRET_DIR / 'dev-d-markers.json')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(secrets['HA_BACKUP_KEY'])


def arm_fixture(kind):
    """(fixture, encrypted) of a 2026-11-19 ARM backup; refuses bytes that differ from the record."""
    stem, slug, recorded, encrypted = ARM_SOURCES[kind]
    path = ARM_FIXTURES / stem / (stem + '.tar')
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    if digest.hexdigest() != recorded:
        raise SystemExit('fixture bytes differ from the 2026-11-19 record: ' + stem)
    return {'path': str(path), 'sha256': recorded, 'slug': slug}, encrypted


def n8n_creds(path):
    """HA's n8n owner password and the probe credential's value (ha-import-creds.env + ha-import-n8n-testdata.sh
    through the existing ha_import_e2e reader) into a new 0600 file; never printed, never hashed into evidence."""
    import ha_import_e2e as e2e
    secrets = e2e.Secrets(e2e.SECRET_DIR / 'ha-import-creds.env', e2e.SECRET_DIR / 'ha-import-n8n-testdata.sh')
    doc = {'owner_password': secrets['N8N_OWNER_PW'], 'credential_value': secrets['N8N_CREDENTIAL_VALUE']}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(doc, handle)


def odoo_creds(path):
    """HA's Odoo admin and ha-probe passwords (ha-import-creds.env through the existing ha_import_e2e reader) into a
    new 0600 file; never printed, never hashed into evidence (item B Odoo, substitute images)."""
    import ha_import_e2e as e2e
    secrets = e2e.Secrets(e2e.SECRET_DIR / 'ha-import-creds.env', e2e.SECRET_DIR / 'ha-import-n8n-testdata.sh')
    doc = {'admin_password': secrets['ODOO_ADMIN_PW'], 'probe_password': secrets['ODOO_PROBE_PW']}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(doc, handle)


def emqx_fixture(kind):
    """(fixture, encrypted) of a B1 cold EMQX backup; refuses a record or bytes that differ from the B1 record."""
    machine, stem, slug, recorded = EMQX_SOURCES[kind]
    record = [b for b in json.loads(B1_BACKUPS.read_text())[machine] if b['slug'] == slug]
    if len(record) != 1 or record[0]['sha256'] != recorded or record[0]['file'] != stem + '.tar' \
            or record[0]['protected'] is not True or record[0]['apps'][0].split('_', 1)[1] != 'woow-emqx':
        raise SystemExit('B1 record differs: ' + stem)
    path = FIXTURES / '20261119-b1' / machine / stem / (stem + '.tar')
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    if digest.hexdigest() != recorded:
        raise SystemExit('fixture bytes differ from the B1 record: ' + stem)
    return {'path': str(path), 'sha256': recorded, 'slug': slug, 'machine': machine}, True


def emqx_expect(kind):
    """The recorded B1 EMQX facts of the source machine (names, counts, topics; no credential) + the provenance."""
    machine, _stem, slug, _sha = EMQX_SOURCES[kind]
    provenance = ('RPi5 HAOS 192.168.2.34 backup b6cbc980 (2026-11-19 07:01Z), bytes attested against the RPi5 on '
                  '2026-11-23 (source-provenance-34)' if machine == 'arm' else
                  'x86 HA backup 5fb6f348 of the B1 batch (2026-11-19 07:03Z), the b1-source/backups.json record')
    return {'machine': machine, 'slug': slug, 'provenance': provenance,
            'emqx': json.loads(B1_SUMMARY.read_text())['machines'][machine]['emqx']}


def emqx_creds(path, kind):
    """HA's EMQX Dashboard users, MQTT users and API key of the B1 batch (b1-creds.env + ha-import-creds.env through
    the existing ha_import_b1_e2e reader) into a new 0600 file; returns the MQTT user names only (never a value)."""
    import ha_import_b1_e2e as b1
    secrets = b1.Secrets([b1.SECRET_DIR / 'b1-creds.env', b1.SECRET_DIR / 'ha-import-creds.env'],
                         b1.SECRET_DIR / 'dev-d-markers.json')
    prefix = 'B1_ARM' if EMQX_SOURCES[kind][0] == 'arm' else 'B1_X86'
    doc = {'ha_admin_password': secrets['B1_EMQX_ADMIN_PW'], 'user2': secrets['B1_EMQX_USER2'],
           'user2_password': secrets['B1_EMQX_USER2_PW'],
           'mqtt': [[secrets['B1_MQTT_USER%d' % i], secrets['B1_MQTT_PW%d' % i]] for i in (1, 2, 3)],
           'api_key': secrets[prefix + '_EMQX_API_KEY'], 'api_secret': secrets[prefix + '_EMQX_API_SECRET']}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(doc, handle)
    return [user for user, _password in doc['mqtt']]


def provenance_arm(output):
    """The owner-accepted provenance of the 2026-11-19 ARM backups, checked locally (read-only): bytes and sha256,
    backup.json (slug, name, date, add-ons) and the 2026-11-19 conversion records in dev-c's catalog listing."""
    start = time.monotonic()
    listing = json.loads(ARM_RECORDS.read_text())
    doc = {'records_file': str(ARM_RECORDS), 'decision': 'owner 2026-11-23: Odoo/n8n use A (historical records)',
           'fixtures': {}}
    for kind, (stem, slug, recorded, encrypted) in sorted(ARM_SOURCES.items()):
        fixture, _enc = arm_fixture(kind)
        with tarfile.open(fixture['path']) as tar:
            raw = tar.extractfile('./backup.json').read()
        meta = json.loads(raw)
        wanted = 'ha-' + recorded[:20]
        rows = [b for b in listing.get('backups', []) if (b.get('from_ha') or {}).get('ha_backup_id') == wanted]
        day = [b for b in rows if str(b.get('created', '')).startswith('2026-11-19')]
        same = [b for b in day if b['from_ha'].get('name') == meta.get('name')
                and str(b['from_ha'].get('date', ''))[:19] == str(meta.get('date', ''))[:19]]
        checks = {'sha256_equals_pinned_record': fixture['sha256'] == recorded,
                  'slug_equals_backup_json': meta.get('slug') == slug,
                  'protected_matches': bool(meta.get('protected')) == encrypted,
                  'recorded_2026_11_19_with_same_name_and_date': bool(same)}
        doc['fixtures'][kind] = {
            'file': fixture['path'], 'bytes': Path(fixture['path']).stat().st_size, 'sha256': recorded,
            'backup_json_sha256': hashlib.sha256(raw).hexdigest(), 'slug': meta.get('slug'), 'name': meta.get('name'),
            'date': meta.get('date'), 'protected': meta.get('protected'), 'compressed': meta.get('compressed'),
            'addons': sorted((a.get('slug'), a.get('version')) for a in meta.get('addons') or []),
            'records_2026_11_19': sorted((b.get('id'), b.get('created')) for b in same),
            'checks': checks, 'verified': all(checks.values())}
    doc['verified'] = all(f['verified'] for f in doc['fixtures'].values())
    doc['scope'] = ('the bytes equal the 2026-11-19 records; .34 no longer holds these backups, so the RPi5 itself '
                    'cannot re-attest them (owner accepted this)')
    code = 0 if doc['verified'] else 1
    result = subprocess.CompletedProcess([], code, (json.dumps(doc, sort_keys=True, ensure_ascii=False) + '\n').encode(),
                                         b'')
    meta = write_result(output, source='provenance_arm() in arm54_final_control.py (local, read-only)', result=result,
                        elapsed=time.monotonic() - start)
    print(json.dumps({'exit': meta['exit'], 'verified': doc['verified']}))
    return code


def upload(kind='plain', output=None, app='headscale', pydeps=None, owner_debs=None):
    root = workspace()
    owner_deb = None
    if owner_debs:  # refuse other bytes before any transfer
        owner_deb = Path(owner_debs) / OWNER_DEB[0]
        if hashlib.sha256(owner_deb.read_bytes()).hexdigest() != OWNER_DEB[1]:
            raise SystemExit('uidmap deb digest differs from the pinned Debian digest')
    if kind in ARM_SOURCES:
        fixture, encrypted = arm_fixture(kind)
        slug = fixture['slug']
    elif kind in EMQX_SOURCES:
        fixture, encrypted = emqx_fixture(kind)
        slug = fixture['slug']
    else:
        slug, encrypted = RESTORE_SOURCES[kind]
        fixture = local_fixture(slug)
    start = time.monotonic()
    extra = {}
    with tempfile.TemporaryDirectory(prefix='arm54-final-upload-') as tmp:
        tmp = Path(tmp)
        os.chmod(tmp, 0o700)
        code_hashes = code_bundle(tmp / 'code.tar.gz')
        (tmp / 'chain.json').write_text(json.dumps({'slug': slug, 'archive': 'ha-backup.tar', 'sha256': fixture['sha256'],
                                                    'key_file': 'ha-key' if encrypted else None}) + '\n')
        want = {'code.tar.gz': hashlib.sha256((tmp / 'code.tar.gz').read_bytes()).hexdigest(),
                'chain.json': hashlib.sha256((tmp / 'chain.json').read_bytes()).hexdigest(),
                'ha-backup.tar': fixture['sha256']}
        files = [(tmp / 'code.tar.gz', 'code.tar.gz'), (tmp / 'chain.json', 'chain.json'),
                 (Path(fixture['path']), 'ha-backup.tar')]
        if app in ('headscale', 'both'):
            client_state_tar(tmp / 'client-state.tar')
            want['client-state.tar'] = hashlib.sha256((tmp / 'client-state.tar').read_bytes()).hexdigest()
            files.append((tmp / 'client-state.tar', 'client-state.tar'))
        if app == 'n8n':
            n8n_creds(tmp / 'n8n-creds.json')
            files.append((tmp / 'n8n-creds.json', 'n8n-creds.json'))
            extra = {'login_file_staged': True, 'login_file_hash_recorded': False}
        if app == 'emqx':
            if kind not in EMQX_SOURCES:
                raise SystemExit('--app emqx takes a B1 cold EMQX backup')
            expect = emqx_expect(kind)
            (tmp / 'emqx-expect.json').write_text(json.dumps(expect, sort_keys=True, ensure_ascii=False) + '\n')
            want['emqx-expect.json'] = hashlib.sha256((tmp / 'emqx-expect.json').read_bytes()).hexdigest()
            users = emqx_creds(tmp / 'emqx-creds.json', kind)
            if users != [u['user_id'] for u in expect['emqx']['mqtt_users']]:
                raise SystemExit('lab MQTT user names differ from the recorded B1 source')
            files += [(tmp / 'emqx-expect.json', 'emqx-expect.json'), (tmp / 'emqx-creds.json', 'emqx-creds.json')]
            extra = {'login_file_staged': True, 'login_file_hash_recorded': False}
        if app == 'odoo':
            odoo_creds(tmp / 'odoo-creds.json')
            files.append((tmp / 'odoo-creds.json', 'odoo-creds.json'))
            extra = {'login_file_staged': True, 'login_file_hash_recorded': False}
        if app in ('omnigent', 'both'):
            expect = omni_expect(json.loads(B1_SUMMARY.read_text())['machines']['arm']['omnigent'])
            (tmp / 'omni-expect.json').write_text(json.dumps(expect, sort_keys=True) + '\n')
            want['omni-expect.json'] = hashlib.sha256((tmp / 'omni-expect.json').read_bytes()).hexdigest()
            admin, member = omni_creds(tmp / 'omni-creds.json')
            if admin != expect['admin'] or member != expect['member']:
                raise SystemExit('lab login names differ from the recorded B1 source')
            files += [(tmp / 'omni-expect.json', 'omni-expect.json'), (tmp / 'omni-creds.json', 'omni-creds.json')]
            extra = {'login_file_staged': True, 'login_file_hash_recorded': False}
        if encrypted:
            ha_backup_key(tmp / 'ha-key')
            files.append((tmp / 'ha-key', 'ha-key'))
        if owner_deb is not None:
            want['uidmap.deb'] = OWNER_DEB[1]
            files.append((owner_deb, 'uidmap.deb'))
        if pydeps:
            extra['wheels_sha256'] = pydeps_tar(pydeps, tmp / 'pydeps.tar')
            want['pydeps.tar'] = hashlib.sha256((tmp / 'pydeps.tar').read_bytes()).hexdigest()
            files.append((tmp / 'pydeps.tar', 'pydeps.tar'))
        for local, name in files:
            done = scp(local, root + '/input/' + name)
            if done.returncode:
                print(json.dumps({'upload_failed': name, 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
                return 1
    code = VERIFY_EXTRACT.replace('ROOT', repr(root)).replace('WANT', repr(want))
    result = remote(HOST54, code, timeout=300)
    record = {k: v for k, v in want.items() if k != 'client-state.tar'}
    meta = write_result(output or ('upload-' + kind), source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'sha256': record, 'client_state_sha256_recorded': False, 'key_hash_recorded': False,
                               'source_slug': slug, 'encrypted': encrypted, 'code_files': code_hashes, 'app': app,
                               **extra})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


STAGED_CHECK = r'''import json, os
p = os.path.join(ROOT, 'input', 'omni-creds.json')
st = os.stat(p)
print(json.dumps({'staged_login_file_private': st.st_mode & 0o777 == 0o600 and st.st_size > 0}))
'''


def stage_logins(output):
    """Stage HA's Omnigent test logins again for a new attempt in the same workspace (each run unlinks them)."""
    root = workspace()
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='arm54-final-stage-') as tmp:
        os.chmod(tmp, 0o700)
        omni_creds(Path(tmp) / 'omni-creds.json')
        done = scp(Path(tmp) / 'omni-creds.json', root + '/input/omni-creds.json')
        if done.returncode:
            print(json.dumps({'upload_failed': 'logins', 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
            return 1
    code = STAGED_CHECK.replace('ROOT', repr(root))
    result = remote(HOST54, code, timeout=120)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'login_file_hash_recorded': False})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


OMNI_STAGED_CHECK = r'''import hashlib, json, os
p = os.path.join(ROOT, 'input', 'omni-creds.json')
st = os.stat(p)
e = os.path.join(ROOT, 'input', 'omni-expect.json')
print(json.dumps({'staged_login_file_private': st.st_mode & 0o777 == 0o600 and st.st_size > 0,
                  'expectation_sha256_equal': hashlib.sha256(open(e, 'rb').read()).hexdigest() == WANT}))
'''


def stage_omni(output):
    """Item C (OwnerRunner, Omnigent) in an existing workspace: the non-secret expectation of the recorded B1 source
    (omni_expect) and HA's test logins (omni_creds, 0600, unlinked by the run; never hashed into evidence)."""
    root = workspace()
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='arm54-final-stage-') as tmp:
        tmp = Path(tmp)
        os.chmod(tmp, 0o700)
        expect = omni_expect(json.loads(B1_SUMMARY.read_text())['machines']['arm']['omnigent'])
        (tmp / 'omni-expect.json').write_text(json.dumps(expect, sort_keys=True) + '\n')
        digest = hashlib.sha256((tmp / 'omni-expect.json').read_bytes()).hexdigest()
        admin, member = omni_creds(tmp / 'omni-creds.json')
        if admin != expect['admin'] or member != expect['member']:
            raise SystemExit('lab login names differ from the recorded B1 source')
        for name in ('omni-expect.json', 'omni-creds.json'):
            done = scp(tmp / name, root + '/input/' + name)
            if done.returncode:
                print(json.dumps({'upload_failed': name, 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
                return 1
    code = OMNI_STAGED_CHECK.replace('ROOT', repr(root)).replace('WANT', repr(digest))
    result = remote(HOST54, code, timeout=120)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'login_file_hash_recorded': False, 'expectation_sha256': digest})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


KEY_CHECK = r'''import json, os
p = os.path.join(ROOT, 'input', 'ha-key')
st = os.stat(p)
print(json.dumps({'staged_backup_unlock_file_private': st.st_mode & 0o777 == 0o600 and st.st_size > 0}))
'''


def stage_key(output):
    """Stage the B1 HA backup key again (each encrypted run reads and unlinks it); never printed or hashed."""
    root = workspace()
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='arm54-final-stage-') as tmp:
        os.chmod(tmp, 0o700)
        ha_backup_key(Path(tmp) / 'ha-key')
        done = scp(Path(tmp) / 'ha-key', root + '/input/ha-key')
        if done.returncode:
            print(json.dumps({'upload_failed': 'backup-unlock', 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
            return 1
    code = KEY_CHECK.replace('ROOT', repr(root))
    result = remote(HOST54, code, timeout=120)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'key_hash_recorded': False})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


N8N_STAGED_CHECK = STAGED_CHECK.replace('omni-creds.json', 'n8n-creds.json')


def stage_n8n_logins(output):
    """Stage HA's n8n owner password and credential value again for a new attempt (each run unlinks them)."""
    root = workspace()
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='arm54-final-stage-') as tmp:
        os.chmod(tmp, 0o700)
        n8n_creds(Path(tmp) / 'n8n-creds.json')
        done = scp(Path(tmp) / 'n8n-creds.json', root + '/input/n8n-creds.json')
        if done.returncode:
            print(json.dumps({'upload_failed': 'n8n-logins', 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
            return 1
    code = N8N_STAGED_CHECK.replace('ROOT', repr(root))
    result = remote(HOST54, code, timeout=120)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'login_file_hash_recorded': False})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


STAGED_ARCHIVE_CHECK = r'''import hashlib, json, os, pathlib
root = pathlib.Path(ROOT)
def sha(p):
    d = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            d.update(b)
    return d.hexdigest()
out = {name: sha(root / 'input' / name) == want for name, want in sorted(WANT.items())}
for name, label in (('ha-key', 'staged_backup_unlock_file_private'), ('n8n-creds.json', 'staged_n8n_login_file_private'),
                    ('emqx-creds.json', 'staged_emqx_login_file_private')):
    path = root / 'input' / name
    out[label] = (not path.exists()) or (path.stat().st_mode & 0o777 == 0o600 and path.stat().st_size > 0)
print(json.dumps(out, sort_keys=True))
assert all(out.values()), 'staged-archive-differs'
'''


def stage_archive(kind, output):
    """Another 2026-11-19 ARM backup for the n8n OwnerRunner run in an existing workspace: ha-backup-<kind>.tar and
    chain-<kind>.json (digests checked on .54), HA's n8n logins and, for an encrypted backup, the B1 HA backup key
    (0600, unlinked by the run; never printed, never hashed into evidence)."""
    root = workspace()
    fixture, encrypted = arm_fixture(kind)
    name = 'ha-backup-%s.tar' % kind
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='arm54-final-stage-') as tmp:
        tmp = Path(tmp)
        os.chmod(tmp, 0o700)
        chain = 'chain-%s.json' % kind
        (tmp / chain).write_text(json.dumps({'slug': fixture['slug'], 'archive': name, 'sha256': fixture['sha256'],
                                             'key_file': 'ha-key' if encrypted else None}) + '\n')
        want = {chain: hashlib.sha256((tmp / chain).read_bytes()).hexdigest(), name: fixture['sha256']}
        n8n_creds(tmp / 'n8n-creds.json')
        files = [(tmp / chain, chain), (Path(fixture['path']), name), (tmp / 'n8n-creds.json', 'n8n-creds.json')]
        if encrypted:
            ha_backup_key(tmp / 'ha-key')
            files.append((tmp / 'ha-key', 'ha-key'))
        for local, target in files:
            done = scp(local, root + '/input/' + target)
            if done.returncode:
                print(json.dumps({'upload_failed': target, 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
                return 1
    code = STAGED_ARCHIVE_CHECK.replace('ROOT', repr(root)).replace('WANT', repr(want))
    result = remote(HOST54, code, timeout=300)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'sha256': want, 'source_slug': fixture['slug'], 'encrypted': encrypted,
                               'login_file_hash_recorded': False, 'key_hash_recorded': False})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


def stage_emqx(kind, output):
    """A B1 cold EMQX backup for the EMQX OwnerRunner run in an existing workspace: ha-backup-<kind>.tar,
    chain-<kind>.json, emqx-expect-<kind>.json (recorded B1 facts, no credential; digests checked on .54), HA's EMQX
    logins and the B1 HA backup key (0600, unlinked by the run; never printed, never hashed into evidence)."""
    root = workspace()
    fixture, _encrypted = emqx_fixture(kind)
    name = 'ha-backup-%s.tar' % kind
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='arm54-final-stage-') as tmp:
        tmp = Path(tmp)
        os.chmod(tmp, 0o700)
        chain, expect_name = 'chain-%s.json' % kind, 'emqx-expect-%s.json' % kind
        (tmp / chain).write_text(json.dumps({'slug': fixture['slug'], 'archive': name, 'sha256': fixture['sha256'],
                                             'key_file': 'ha-key'}) + '\n')
        expect = emqx_expect(kind)
        (tmp / expect_name).write_text(json.dumps(expect, sort_keys=True, ensure_ascii=False) + '\n')
        want = {chain: hashlib.sha256((tmp / chain).read_bytes()).hexdigest(), name: fixture['sha256'],
                expect_name: hashlib.sha256((tmp / expect_name).read_bytes()).hexdigest()}
        users = emqx_creds(tmp / 'emqx-creds.json', kind)
        if users != [u['user_id'] for u in expect['emqx']['mqtt_users']]:
            raise SystemExit('lab MQTT user names differ from the recorded B1 source')
        ha_backup_key(tmp / 'ha-key')
        files = [(tmp / chain, chain), (Path(fixture['path']), name), (tmp / expect_name, expect_name),
                 (tmp / 'emqx-creds.json', 'emqx-creds.json'), (tmp / 'ha-key', 'ha-key')]
        for local, target in files:
            done = scp(local, root + '/input/' + target)
            if done.returncode:
                print(json.dumps({'upload_failed': target, 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
                return 1
    code = STAGED_ARCHIVE_CHECK.replace('ROOT', repr(root)).replace('WANT', repr(want))
    result = remote(HOST54, code, timeout=300)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'sha256': want, 'source_slug': fixture['slug'], 'encrypted': True,
                               'login_file_hash_recorded': False, 'key_hash_recorded': False})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


B1_KINDS = {'b1-plain': 'plain', 'b1-enc': 'enc'}  # staged name -> RESTORE_SOURCES
B1_STAGED_CHECK = STAGED_ARCHIVE_CHECK.replace("(('ha-key', 'staged_backup_unlock_file_private'),",
                                               "(('omni-creds.json', 'staged_login_file_private'), "
                                               "('ha-key', 'staged_backup_unlock_file_private'),")


def stage_b1(kind, output):
    """An RPi5 B1 backup (Headscale + Omnigent + EMQX add-ons) for the Omnigent OwnerRunner run in an existing workspace:
    ha-backup-<kind>.tar and chain-<kind>.json (bytes equal to the ones attested against the RPi5, checked again on .54),
    the recorded non-secret Omnigent expectation, HA's Omnigent logins and, for the encrypted backup, the B1 HA backup key
    (0600, unlinked by the run; never printed, never hashed into evidence)."""
    root = workspace()
    slug, encrypted = RESTORE_SOURCES[B1_KINDS[kind]]
    fixture = local_fixture(slug)
    attested = json.loads((EVIDENCE / 'source-provenance-34.json').read_text())
    if attested['verdicts'][slug]['verified'] is not True or attested['source']['backups'][slug]['file_sha256'] != fixture['sha256']:
        raise SystemExit('fixture bytes differ from the bytes attested against the RPi5: ' + slug)
    name = 'ha-backup-%s.tar' % kind
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='arm54-final-stage-') as tmp:
        tmp = Path(tmp)
        os.chmod(tmp, 0o700)
        chain = 'chain-%s.json' % kind
        (tmp / chain).write_text(json.dumps({'slug': slug, 'archive': name, 'sha256': fixture['sha256'],
                                             'key_file': 'ha-key' if encrypted else None}) + '\n')
        expect = omni_expect(json.loads(B1_SUMMARY.read_text())['machines']['arm']['omnigent'])
        (tmp / 'omni-expect.json').write_text(json.dumps(expect, sort_keys=True) + '\n')
        admin, member = omni_creds(tmp / 'omni-creds.json')
        if admin != expect['admin'] or member != expect['member']:
            raise SystemExit('lab login names differ from the recorded B1 source')
        want = {chain: hashlib.sha256((tmp / chain).read_bytes()).hexdigest(), name: fixture['sha256'],
                'omni-expect.json': hashlib.sha256((tmp / 'omni-expect.json').read_bytes()).hexdigest()}
        files = [(tmp / chain, chain), (Path(fixture['path']), name), (tmp / 'omni-expect.json', 'omni-expect.json'),
                 (tmp / 'omni-creds.json', 'omni-creds.json')]
        if encrypted:
            ha_backup_key(tmp / 'ha-key')
            files.append((tmp / 'ha-key', 'ha-key'))
        for local, target in files:
            done = scp(local, root + '/input/' + target)
            if done.returncode:
                print(json.dumps({'upload_failed': target, 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
                return 1
    code = B1_STAGED_CHECK.replace('ROOT', repr(root)).replace('WANT', repr(want))
    result = remote(HOST54, code, timeout=300)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'sha256': want, 'source_slug': slug, 'encrypted': encrypted,
                               'login_file_hash_recorded': False, 'key_hash_recorded': False})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


def stage_odoo_logins(output):
    """Stage HA's Odoo admin and ha-probe passwords again for a new attempt (each run unlinks them)."""
    root = workspace()
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='arm54-final-stage-') as tmp:
        os.chmod(tmp, 0o700)
        odoo_creds(Path(tmp) / 'odoo-creds.json')
        done = scp(Path(tmp) / 'odoo-creds.json', root + '/input/odoo-creds.json')
        if done.returncode:
            print(json.dumps({'upload_failed': 'odoo-logins', 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
            return 1
    code = N8N_STAGED_CHECK.replace('ROOT', repr(root)).replace('n8n-creds.json', 'odoo-creds.json')
    result = remote(HOST54, code, timeout=120)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'login_file_hash_recorded': False})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


def stage_emqx_logins(output, kind):
    """Stage HA's EMQX passwords and API key again for a new attempt (each run unlinks them)."""
    root = workspace()
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='arm54-final-stage-') as tmp:
        os.chmod(tmp, 0o700)
        emqx_creds(Path(tmp) / 'emqx-creds.json', kind)
        done = scp(Path(tmp) / 'emqx-creds.json', root + '/input/emqx-creds.json')
        if done.returncode:
            print(json.dumps({'upload_failed': 'emqx-logins', 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
            return 1
    code = N8N_STAGED_CHECK.replace('ROOT', repr(root)).replace('n8n-creds.json', 'emqx-creds.json')
    result = remote(HOST54, code, timeout=120)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'login_file_hash_recorded': False, 'source_kind': kind})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


REMOTE_CODE_CHECK = r'''import hashlib as _h, pathlib as _p
_want = WANT
_bad = sorted(k for k, v in _want.items() if not (_p.Path(ROOT) / 'source' / k).is_file()
              or _h.sha256((_p.Path(ROOT) / 'source' / k).read_bytes()).hexdigest() != v)
assert not _bad, 'remote-code-differs-from-commit: %s' % _bad[:3]
del _h, _p, _want, _bad
'''


def committed_code_hashes():
    """sha256 of the engine's .py files and the lab's CODE_FILES at HEAD (the run's source commit)."""
    files = sorted(p for p in (REPO / 'backup-engine').rglob('*.py') if '__pycache__' not in p.parts)
    files += [LAB / name for name in CODE_FILES + PROBE_SOURCES if (LAB / name).exists()]
    return {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def run(script, output, timeout, script_args=()):
    require_clean()
    root = workspace()
    source = (LAB / script).read_text()
    prefix = 'import sys\nsys.argv = %r\nsys.path.insert(0, %r)\n' % ([script, root, *script_args],
                                                                       root + '/source/tests/e2e/lab')
    # The workspace's code must be the committed code of this run (refresh-code after every commit).
    prefix += REMOTE_CODE_CHECK.replace('WANT', repr(committed_code_hashes())).replace('ROOT', repr(root))
    start = time.monotonic()
    result = remote(HOST54, prefix + source, timeout=timeout)
    meta = write_result(output, source=source, result=result, elapsed=time.monotonic() - start,
                        extra={'script_args': list(script_args)} if script_args else None)
    print(json.dumps({k: meta[k] for k in ('exit', 'elapsed_seconds', 'stdout_sha256', 'source_commit')}))
    try:
        doc = json.loads(result.stdout.decode().strip().splitlines()[-1])
        print(json.dumps({k: doc.get(k) for k in ('status', 'phase', 'error_code', 'product_error_code', 'failed_check')}))
    except (ValueError, IndexError):
        pass
    return result.returncode


# ------------------------------------------------------------------ item A: large archive on .54 (lane arm54-2)

# .54 has no age/age-keygen/zstd. Debian bookworm arm64 packages, sha256 = their entries in the bookworm
# main/binary-arm64 Packages index (checked by `tools-provenance` through the InRelease signature with .54's own
# Debian archive keyrings). Uploaded into the 0700 workspace and unpacked there only; never installed.
DEBS = {
    'age_1.1.1-1+b3_arm64.deb': ('age.deb', 'd14f937ecb1cef9279879e779cf61fda682735dd9871cd7d60ba7a487608f4e6',
                                 'pool/main/a/age/age_1.1.1-1+b3_arm64.deb'),
    'zstd_1.5.4+dfsg2-5_arm64.deb': ('zstd.deb', '97a58383b0ad55cc8183e59cbb112f2eb55c3dc1e90de816fa5cfb983d5c2ff0',
                                     'pool/main/libz/libzstd/zstd_1.5.4+dfsg2-5_arm64.deb'),
}
KEYRINGS = ('debian-archive-bookworm-automatic', 'debian-archive-bookworm-stable', 'debian-archive-trixie-automatic')
PACKAGES_INDEX = 'main/binary-arm64/Packages.xz'
KEYRING_READ = r'''import base64, hashlib, json
out = {}
for name in NAMES:
    data = open('/usr/share/keyrings/%s.gpg' % name, 'rb').read()
    out[name] = {'b64': base64.b64encode(data).decode(), 'sha256': hashlib.sha256(data).hexdigest()}
print(json.dumps(out, sort_keys=True))
'''


def packages_entries(text):
    """Pure parser (unit tested): {Filename: {'sha256', 'size', 'package', 'version'}} of a Debian Packages file."""
    rows = {}
    for stanza in text.split('\n\n'):
        fields = {}
        for line in stanza.splitlines():
            if line and not line[0].isspace() and ':' in line:
                key, value = line.split(':', 1)
                fields[key] = value.strip()
        if 'Filename' in fields:
            rows[fields['Filename']] = {'sha256': fields.get('SHA256'), 'size': int(fields.get('Size', -1)),
                                        'package': fields.get('Package'), 'version': fields.get('Version')}
    return rows


def inrelease_sha256(text, index):
    """sha256 + size the signed InRelease lists for `index` (pure, unit tested); None when absent."""
    section = text.split('SHA256:', 1)[1] if 'SHA256:' in text else ''
    for line in section.splitlines()[1:]:
        if not line.startswith(' '):
            break
        parts = line.split()
        if len(parts) == 3 and parts[2] == index:
            return parts[0], int(parts[1])
    return None


def tools_provenance(debs, output):
    """InRelease (signature checked with gpgv against the Debian archive keyrings read from .54 itself) ->
    Packages.xz sha256 -> the pinned .deb digests. Network fetches were done beforehand into `debs`."""
    import base64
    import lzma
    start = time.monotonic()
    debs = Path(debs)
    keys = remote(HOST54, KEYRING_READ.replace('NAMES', repr(KEYRINGS)), timeout=120)
    doc = {'keyrings_read_from': HOST54 + ':/usr/share/keyrings', 'inrelease_url':
           'https://deb.debian.org/debian/dists/bookworm/InRelease', 'packages_url':
           'https://deb.debian.org/debian/dists/bookworm/' + PACKAGES_INDEX}
    if keys.returncode == 0:
        rings = json.loads(keys.stdout)
        with tempfile.TemporaryDirectory(prefix='arm54-keyrings-') as tmp:
            argv = ['gpgv', '--status-fd', '1']
            for name in KEYRINGS:
                path = Path(tmp) / (name + '.gpg')
                path.write_bytes(base64.b64decode(rings[name]['b64']))
                argv += ['--keyring', str(path)]
            gpgv = subprocess.run(argv + [str(debs / 'InRelease')], capture_output=True, text=True, timeout=60)
        status = [l.split(' ', 2) for l in gpgv.stdout.splitlines() if l.startswith('[GNUPG:] ')]
        doc['keyring_sha256'] = {name: rings[name]['sha256'] for name in KEYRINGS}
        doc['gpgv_exit'] = gpgv.returncode
        doc['good_signatures'] = sorted(l[2] for l in status if len(l) == 3 and l[1] == 'GOODSIG')
        doc['bad_signatures'] = sum(1 for l in status if len(l) >= 2 and l[1] == 'BADSIG')
        inrelease = (debs / 'InRelease').read_text()
        doc['inrelease_fields'] = {k: v for k, v in (l.split(': ', 1) for l in inrelease.splitlines()
                                                     if l.split(': ', 1)[0] in ('Suite', 'Codename', 'Version',
                                                                                'Date') and ': ' in l)}
        listed = inrelease_sha256(inrelease, PACKAGES_INDEX)
        packed = (debs / 'Packages.xz').read_bytes()
        doc['packages_xz'] = {'sha256': hashlib.sha256(packed).hexdigest(), 'bytes': len(packed),
                              'listed_in_inrelease': list(listed) if listed else None}
        entries = packages_entries(lzma.decompress(packed).decode('utf-8', 'replace'))
        doc['debs'] = {}
        for name, (_, want, pool) in sorted(DEBS.items()):
            data = (debs / name).read_bytes()
            row = entries.get(pool) or {}
            doc['debs'][name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data), 'pool': pool,
                                 'packages_entry': row, 'pinned': want}
        checks = {
            'gpgv_ok': gpgv.returncode == 0 and doc['bad_signatures'] == 0 and len(doc['good_signatures']) >= 1,
            'packages_xz_listed_in_signed_inrelease': listed == (doc['packages_xz']['sha256'], len(packed)),
            'debs_equal_packages_entries': all(r['sha256'] == r['packages_entry'].get('sha256') == r['pinned']
                                               and r['bytes'] == r['packages_entry'].get('size')
                                               for r in doc['debs'].values()),
        }
        doc['checks'] = checks
        doc['verified'] = all(checks.values())
    code = 0 if doc.get('verified') else 1
    result = subprocess.CompletedProcess([], code, (json.dumps(doc, sort_keys=True) + '\n').encode(), keys.stderr)
    meta = write_result(output, source=KEYRING_READ, result=result, elapsed=time.monotonic() - start)
    print(json.dumps({'exit': meta['exit'], 'verified': doc.get('verified')}))
    return code


def upload_large(debs, output):
    """Code bundle (engine + tests/backup probe) and the two pinned .deb files; no HA archive, no secret."""
    root = workspace()
    start = time.monotonic()
    want, files = {}, []
    for name, (target, digest, _) in sorted(DEBS.items()):  # refuse other bytes before any work or transfer
        path = Path(debs) / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SystemExit('deb digest differs from the pinned Debian digest: ' + name)
        want[target] = digest
        files.append((path, target))
    with tempfile.TemporaryDirectory(prefix='arm54-final-upload-') as tmp:
        tmp = Path(tmp)
        os.chmod(tmp, 0o700)
        code_hashes = code_bundle(tmp / 'code.tar.gz', large=True)
        want['code.tar.gz'] = hashlib.sha256((tmp / 'code.tar.gz').read_bytes()).hexdigest()
        files.insert(0, (tmp / 'code.tar.gz', 'code.tar.gz'))
        for local, name in files:
            done = scp(local, root + '/input/' + name)
            if done.returncode:
                print(json.dumps({'upload_failed': name, 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
                return 1
    code = VERIFY_EXTRACT.replace('ROOT', repr(root)).replace('WANT', repr(want))
    result = remote(HOST54, code, timeout=300)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'sha256': want, 'code_files': code_hashes, 'app': 'large'})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


REFRESH = r'''import hashlib, json, os, pathlib, shutil, tarfile
root = pathlib.Path(ROOT); os.umask(0o077)
src = root / 'input' / NAME
assert hashlib.sha256(src.read_bytes()).hexdigest() == WANT, 'code-bundle-digest-differs'
shutil.rmtree(root / 'source')
count = 0
with tarfile.open(src) as tar:
    for m in tar:
        p = pathlib.PurePosixPath(m.name)
        assert m.isfile() and m.size <= 8 * 1024 ** 2 and not p.is_absolute() and '..' not in p.parts
        dest = root / 'source' / m.name
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with dest.open('xb') as handle:
            handle.write(tar.extractfile(m).read())
        count += 1
src.unlink()
print(json.dumps({'refreshed': True, 'files': count}))
'''


def refresh_code(output):
    """Replace the workspace's source tree with HEAD's code bundle (no HA archive, no secret)."""
    require_clean()
    root = workspace()
    start = time.monotonic()
    name = 'code-refresh-%d.tar.gz' % int(time.time())
    with tempfile.TemporaryDirectory(prefix='arm54-final-refresh-') as tmp:
        tmp = Path(tmp)
        os.chmod(tmp, 0o700)
        code_hashes = code_bundle(tmp / name)
        digest = hashlib.sha256((tmp / name).read_bytes()).hexdigest()
        done = scp(tmp / name, root + '/input/' + name)
        if done.returncode:
            print(json.dumps({'upload_failed': name, 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
            return 1
    code = REFRESH.replace('ROOT', repr(root)).replace('NAME', repr(name)).replace('WANT', repr(digest))
    result = remote(HOST54, code, timeout=300)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'sha256': {name: digest}, 'code_files': code_hashes})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


TOOLS_CHECK = r'''import hashlib, json, pathlib
root = pathlib.Path(ROOT)
same = {name: hashlib.sha256((root / 'input' / name).read_bytes()).hexdigest() == want
        for name, want in sorted(WANT.items())}
print(json.dumps(same, sort_keys=True))
assert all(same.values()), 'uploaded-tool-digest-differs'
'''


def upload_tools(debs, output):
    """The pinned age/zstd (engine tools, as item A) and uidmap packages into the current workspace's input/."""
    root = workspace()
    start = time.monotonic()
    want = {}
    pinned = [(name, target, digest) for name, (target, digest, _pool) in sorted(DEBS.items())]
    pinned.append((OWNER_DEB[0], 'uidmap.deb', OWNER_DEB[1]))
    for name, target, digest in pinned:
        path = Path(debs) / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SystemExit('deb digest differs from the pinned Debian digest: ' + name)
        done = scp(path, root + '/input/' + target)
        if done.returncode:
            print(json.dumps({'upload_failed': target, 'fixed_diagnostics': fixed_diagnostics(done.stderr)}))
            return 1
        want[target] = digest
    code = TOOLS_CHECK.replace('ROOT', repr(root)).replace('WANT', repr(want))
    result = remote(HOST54, code, timeout=120)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start, extra={'sha256': want})
    print(json.dumps({'exit': meta['exit']}))
    return result.returncode


def cgroup_cleanup(baseline, output):
    """Cycle c10's workspace was already gone when its empty cgroup leftover was found: the committed cleanup function
    (arm54_final_cleanup.py remove_own_cgroup_parent, its exact source) runs against the cycle's committed baseline."""
    require_clean()
    tree = ast.parse((LAB / 'arm54_final_cleanup.py').read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'remove_own_cgroup_parent')
    top = json.loads((EVIDENCE / (baseline + '.json')).read_text())['cgroup_top']
    code = ('import json, os\nfrom pathlib import Path\n\n\n' + ast.unparse(node)
            + '\n\n\nprint(json.dumps(remove_own_cgroup_parent(%r), sort_keys=True))\n' % (top,))
    start = time.monotonic()
    result = remote(HOST54, code, timeout=60)
    meta = write_result(output, source=code, result=result, elapsed=time.monotonic() - start,
                        extra={'baseline': baseline})
    print(json.dumps({'exit': meta['exit']}))
    if result.returncode == 0:
        print(result.stdout.decode().strip()[:300])
    return result.returncode


def audit(output, baseline=None, ignore=()):
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    root = state.get('workspace')
    baseline = baseline or state.get('baseline', 'baseline-before')
    extra = ("inv['workspace_absent'] = not os.path.exists(%r)\n" % root) if root else ''
    code = inventory_code(extra)
    start = time.monotonic()
    result = remote(HOST54, code, timeout=300)
    elapsed = time.monotonic() - start
    if result.returncode == 0:
        after = json.loads(result.stdout)
        before = json.loads((EVIDENCE / (baseline + '.json')).read_text())
        before.pop('workspace', None)
        skip = set(ignore) | {'workspace_absent'}
        verdict = compare_inventory({k: v for k, v in before.items() if k not in skip},
                                    {k: v for k, v in after.items() if k not in skip})
        verdict.update(baseline=baseline, ignored_keys=sorted(ignore))
        verdict['workspace_absent'] = after.get('workspace_absent')
        doc = {'after': after, 'comparison': verdict}
        out = subprocess.CompletedProcess([], 0 if verdict['identical'] and after.get('workspace_absent', True) else 1,
                                          (json.dumps(doc, sort_keys=True) + '\n').encode(), b'')
    else:
        out = result
    meta = write_result(output, source=code, result=out, elapsed=elapsed)
    print(json.dumps({'exit': meta['exit']}))
    if out.returncode == 0 or result.returncode == 0:
        print(json.dumps(json.loads(out.stdout)['comparison']['differing_keys']))
    return out.returncode


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('access')
    p = sub.add_parser('attest')
    p.add_argument('--output', default='source-provenance-34')
    p = sub.add_parser('init')
    p.add_argument('--output', default='baseline-before')
    p.add_argument('--driver', choices=DRIVERS, default='vfs')
    p = sub.add_parser('upload')
    p.add_argument('--archive', choices=sorted(RESTORE_SOURCES) + sorted(ARM_SOURCES) + sorted(EMQX_SOURCES),
                   default='plain')
    p.add_argument('--output', help='evidence name; never reuse a committed one')
    p.add_argument('--app', choices=('headscale', 'omnigent', 'both', 'n8n', 'odoo', 'emqx'), default='headscale')
    p.add_argument('--pydeps', help='directory with the two pinned aarch64 wheels (encrypted backups on .54)')
    p.add_argument('--owner-debs', help='directory with the pinned uidmap .deb (item C, OwnerRunner rootless)')
    p = sub.add_parser('upload-tools')
    p.add_argument('--debs', required=True)
    p.add_argument('--output', required=True)
    p = sub.add_parser('refresh-code')
    p.add_argument('--output', required=True)
    p = sub.add_parser('stage-omni')
    p.add_argument('--output', required=True)
    p = sub.add_parser('stage-logins')
    p.add_argument('--output', required=True)
    p = sub.add_parser('stage-key')
    p.add_argument('--output', required=True)
    p = sub.add_parser('stage-n8n-logins')
    p.add_argument('--output', required=True)
    p = sub.add_parser('stage-archive')
    p.add_argument('--archive', choices=sorted(ARM_SOURCES), required=True)
    p.add_argument('--output', required=True)
    p = sub.add_parser('stage-b1')
    p.add_argument('--archive', choices=sorted(B1_KINDS), required=True)
    p.add_argument('--output', required=True)
    p = sub.add_parser('stage-emqx')
    p.add_argument('--archive', choices=sorted(EMQX_SOURCES), required=True)
    p.add_argument('--output', required=True)
    p = sub.add_parser('stage-odoo-logins')
    p.add_argument('--output', required=True)
    p = sub.add_parser('stage-emqx-logins')
    p.add_argument('--output', required=True)
    p.add_argument('--archive', required=True, choices=sorted(EMQX_SOURCES))
    p = sub.add_parser('provenance-arm')
    p.add_argument('--output', required=True)
    p = sub.add_parser('run')
    p.add_argument('--script', required=True, choices=CODE_FILES[1:])
    p.add_argument('--output', required=True)
    p.add_argument('--timeout', type=int, default=3600)
    p.add_argument('--arg', action='append', default=[], help='extra argv for the remote script (recorded)')
    p = sub.add_parser('tools-provenance')
    p.add_argument('--debs', required=True, help='directory with InRelease, Packages.xz and the two .deb files')
    p.add_argument('--output', required=True)
    p = sub.add_parser('upload-large')
    p.add_argument('--debs', required=True)
    p.add_argument('--output', required=True)
    p = sub.add_parser('cgroup-cleanup')
    p.add_argument('--baseline', required=True)
    p.add_argument('--output', required=True)
    p = sub.add_parser('audit')
    p.add_argument('--output', required=True)
    p.add_argument('--baseline')
    p.add_argument('--ignore', action='append', default=[], help='key not comparable between the two baselines')
    args = parser.parse_args(argv)
    if args.command == 'access':
        return access()
    if args.command == 'attest':
        return attest(args.output)
    if args.command == 'init':
        return init(args.output, args.driver)
    if args.command == 'upload':
        return upload(args.archive, args.output, args.app, args.pydeps, args.owner_debs)
    if args.command == 'upload-tools':
        return upload_tools(args.debs, args.output)
    if args.command == 'refresh-code':
        return refresh_code(args.output)
    if args.command == 'stage-omni':
        return stage_omni(args.output)
    if args.command == 'stage-logins':
        return stage_logins(args.output)
    if args.command == 'stage-key':
        return stage_key(args.output)
    if args.command == 'stage-n8n-logins':
        return stage_n8n_logins(args.output)
    if args.command == 'stage-archive':
        return stage_archive(args.archive, args.output)
    if args.command == 'stage-b1':
        return stage_b1(args.archive, args.output)
    if args.command == 'stage-emqx':
        return stage_emqx(args.archive, args.output)
    if args.command == 'stage-odoo-logins':
        return stage_odoo_logins(args.output)
    if args.command == 'stage-emqx-logins':
        return stage_emqx_logins(args.output, args.archive)
    if args.command == 'provenance-arm':
        return provenance_arm(args.output)
    if args.command == 'run':
        return run(args.script, args.output, args.timeout, args.arg)
    if args.command == 'tools-provenance':
        return tools_provenance(args.debs, args.output)
    if args.command == 'upload-large':
        return upload_large(args.debs, args.output)
    if args.command == 'cgroup-cleanup':
        return cgroup_cleanup(args.baseline, args.output)
    return audit(args.output, args.baseline, args.ignore)


if __name__ == '__main__':
    sys.exit(main())
