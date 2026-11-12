"""`.woowbackup` v1 format tests (team E1): round trip, header variants, keys, truncation, bit flips.

Tests that need the real `age`/`zstd` binaries are skipped visibly when the tools are missing
(the woowbk test-runner image and CI install them).
"""
import copy
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2] / 'backup-engine'
if str(ENGINE) not in sys.path:
    sys.path.insert(0, str(ENGINE))

from woowbackup import archive, util  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402
from woowbackup.keys import KeyStore  # noqa: E402
from woowbackup.paths import Paths  # noqa: E402

HAVE_AGE = bool(shutil.which('age') and shutil.which('age-keygen') and shutil.which('zstd'))
needs_age = unittest.skipUnless(HAVE_AGE, 'needs age, age-keygen and zstd (installed in CI / woowbk test runner)')

BACKUP_ID = '20261113T020000Z-a1b2c3d4'
CREATED = '2026-11-13T02:00:00Z'
APP = 'woowbk-demo'
LONG_SECRET = 'woowbk-demo-' + 'x' * 140  # > 100 chars member name: exercises PAX 'path' records


# ---------------------------------------------------------------------------- helpers (shared)

def fake_archive_bytes(backup_id=BACKUP_ID, created=CREATED, key_id='ABCD-EF01-2345-6789', payload=None, **extra):
    """Syntactically valid outer header + age header (no real ciphertext): enough for read_header()."""
    header = {'format': 1, 'backup_id': backup_id, 'created': created, 'key_id': key_id,
              'encryption': 'age-x25519', 'compression': 'zstd'}
    header.update(extra)
    age = (b'age-encryption.org/v1\n-> X25519 ' + b'A' * 43 + b'\n' + b'B' * 43 + b'\n--- ' + b'C' * 43 + b'\n')
    return (archive.MAGIC + json.dumps(header, separators=(',', ':')).encode() + b'\n' + age
            + (payload if payload is not None else bytes(range(64))))


def demo_app(app_id=APP):
    base = f'apps/{app_id}'
    return {
        'id': app_id, 'name': '示範筆記應用', 'adapter': 'quadlet-postgres', 'adapter_version': 1,
        'catalog_sha256': 'b' * 64, 'owner': {'name': 'appowner', 'uid': 1001},
        'images': [{'ref': 'docker.io/library/postgres:16-alpine', 'id': 'sha256:' + 'c' * 64,
                    'digest': 'sha256:' + 'd' * 64, 'arch': 'amd64', 'entry': f'{base}/images/0.oci.tar'},
                   {'ref': 'localhost/woowbk-demo-app:1', 'id': 'e' * 64, 'digest': '', 'arch': 'amd64'}],
        'postgres': [{'id': 'main', 'database': 'notes', 'server_version': '16.4', 'major': 16,
                      'entry': f'{base}/postgres/main.dump'}],
        'volumes': [{'name': 'woowbk-demo-files', 'entry': f'{base}/volumes/woowbk-demo-files.tar'}],
        'secrets': [{'name': 'woowbk-demo-db-password', 'entry': f'{base}/secrets/woowbk-demo-db-password'},
                    {'name': LONG_SECRET, 'entry': f'{base}/secrets/{LONG_SECRET}'}],
        'config_files': [{'path': '.config/woowbk-demo/app.env', 'mode': '0600', 'entry': f'{base}/config/0'},
                         {'path': '.local/share/woowbk-demo/empty.env', 'mode': '0644', 'entry': f'{base}/config/1'}],
        'quadlet_files': [{'name': 'woowbk-demo-app.container',
                           'entry': f'{base}/quadlet/woowbk-demo-app.container'}],
        'verify_snapshot': {'summary': {'notes': 12, 'files': 4, 'digest': 'f' * 64, 'title': '我的筆記',
                                        'signatures_valid': True}},
    }


def demo_manifest(key_id, backup_id=BACKUP_ID, created=CREATED, apps=None):
    return {
        'format': 1, 'backup_id': backup_id, 'created': created, 'type': 'manual', 'note': '測試備份',
        'key_id': key_id, 'tool': {'name': 'woowtech-cockpit-backup', 'version': '2026.11.13.1'},
        'source': {'hostname': 'dev-a', 'machine_id_sha256': '0' * 64, 'arch': 'x86_64',
                   'os': 'Ubuntu 24.04.3 LTS', 'podman': '4.9.3'},
        'consistency': {'method': 'writers-stopped', 'downtime_seconds': 7},
        'apps': apps if apps is not None else [demo_app()],
        'entries': [],
    }


def demo_payloads(big=6 * 1024 * 1024):
    """Entry contents for demo_app(): a multi-MB incompressible image, small files and an empty one."""
    base = f'apps/{APP}'
    return {
        f'{base}/images/0.oci.tar': os.urandom(big),
        f'{base}/postgres/main.dump': b'PGDMP' + os.urandom(70000),
        f'{base}/volumes/woowbk-demo-files.tar': b'volume-tar-bytes' * 4096,
        f'{base}/secrets/woowbk-demo-db-password': b's3cr3t-value\n',
        f'{base}/secrets/{LONG_SECRET}': b'long-name-secret',
        f'{base}/config/0': 'TITLE=我的筆記\n'.encode(),
        f'{base}/config/1': b'',
        f'{base}/quadlet/woowbk-demo-app.container': b'[Container]\nImage=localhost/woowbk-demo-app:1\n',
    }


def stage(directory, payloads):
    """Write payloads below `directory`; return archive.Entry list in manifest reference order."""
    entries = []
    for index, (path, data) in enumerate(payloads.items()):
        source = Path(directory) / f'{index:03d}.bin'
        source.write_bytes(data)
        entries.append(archive.entry_from_file(path, source))
    return entries


def file_tree(root):
    """{relative path: (kind, mode, bytes-or-None)} snapshot of everything below root."""
    out = {}
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            st = os.lstat(path)
            rel = str(path.relative_to(root))
            if stat.S_ISREG(st.st_mode):
                out[rel] = ('file', stat.S_IMODE(st.st_mode), path.read_bytes())
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ('dir', stat.S_IMODE(st.st_mode), None)
            else:
                out[rel] = ('other', stat.S_IMODE(st.st_mode), None)
    return out


def tool_children():
    """PIDs of age/zstd children of this process (running or zombie). Other tests' children are ignored."""
    me = str(os.getpid())
    found = []
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            with open(f'/proc/{pid}/stat', 'rb') as handle:
                raw = handle.read()
        except OSError:
            continue
        comm = raw[raw.index(b'(') + 1:raw.rindex(b')')]
        if raw.rsplit(b')', 1)[1].split()[1].decode() == me and comm in (b'age', b'zstd', b'age-keygen'):
            found.append(int(pid))
    return found


def open_fds():
    """Pipes and anonymous temp files held by this process (what the archive code creates)."""
    count = 0
    for fd in os.listdir('/proc/self/fd'):
        try:
            target = os.readlink(f'/proc/self/fd/{fd}')
        except OSError:
            continue
        if target.startswith('pipe:') or target.endswith('(deleted)'):
            count += 1
    return count


def seal(dest, header, tar_data, recipient):
    """Encrypt arbitrary (possibly hostile) tar bytes exactly like the engine: zstd | age -r."""
    compressed = subprocess.run(['zstd', '-q', '-c', '-3'], input=tar_data, stdout=subprocess.PIPE,
                                check=True).stdout
    encrypted = subprocess.run(['age', '-e', '-r', recipient], input=compressed, stdout=subprocess.PIPE,
                               check=True).stdout
    Path(dest).write_bytes(archive.header_bytes(header) + encrypted)
    return Path(dest)


def decrypt_tar(path, identity):
    """Independent decrypt with the CLI tools (to inspect what the writer produced)."""
    data = Path(path).read_bytes()
    first = data.index(b'\n') + 1
    second = data.index(b'\n', first) + 1
    plain = subprocess.run(['age', '-d', '-i', str(identity)], input=data[second:], stdout=subprocess.PIPE,
                           check=True).stdout
    return subprocess.run(['zstd', '-d', '-c', '-q'], input=plain, stdout=subprocess.PIPE, check=True).stdout


class Workspace:
    """Temp dir with Paths(base=…), a device key and staging/archives dirs."""

    def __init__(self, testcase, with_key=True):
        self.tmp = tempfile.TemporaryDirectory(prefix='woowbk-e1-')
        testcase.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.paths = Paths(base=self.base)
        self.keys = KeyStore(self.paths)
        self.staging = self.base / 'staging'
        self.staging.mkdir(mode=0o700)
        self.out = self.base / 'out'
        self.out.mkdir(mode=0o700)
        if with_key:
            self.key, _ = self.keys.ensure_device_key()

    def dest(self, name='extract'):
        path = self.base / name
        path.mkdir(mode=0o700)
        return path

    def write(self, payloads=None, manifest=None, name='a.woowbackup', progress=None):
        payloads = payloads if payloads is not None else demo_payloads()
        entries = stage(self.staging, payloads)
        manifest = manifest if manifest is not None else demo_manifest(self.key.key_id)
        dest = self.out / name
        result = archive.write_archive(dest, None, manifest, entries, self.key.recipient,
                                       tmp_dir=self.out, progress=progress)
        return dest, result, entries


# ---------------------------------------------------------------------------- header (no age needed)

class HeaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='woowbk-e1-')
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def file(self, data, name='x.woowbackup'):
        path = self.dir / name
        path.write_bytes(data)
        return path

    def code(self, data):
        with self.assertRaises(BackupError) as ctx:
            archive.read_header(self.file(data))
        return ctx.exception.code

    def test_valid_header(self):
        header = archive.read_header(self.file(fake_archive_bytes()))
        self.assertEqual(header, {'format': 1, 'backup_id': BACKUP_ID, 'created': CREATED,
                                  'key_id': 'ABCD-EF01-2345-6789', 'encryption': 'age-x25519',
                                  'compression': 'zstd'})

    def test_other_version_is_unsupported(self):
        data = fake_archive_bytes().replace(b'WOOWTECH-BACKUP/1\n', b'WOOWTECH-BACKUP/2\n', 1)
        self.assertEqual(self.code(data), 'unsupported-format')
        self.assertEqual(self.code(b'WOOWTECH-BACKUP/17\nwhatever'), 'unsupported-format')

    def test_json_format_or_algorithms_unsupported(self):
        self.assertEqual(self.code(fake_archive_bytes(format=2)), 'unsupported-format')
        self.assertEqual(self.code(fake_archive_bytes(encryption='age-scrypt')), 'unsupported-format')
        self.assertEqual(self.code(fake_archive_bytes(compression='xz')), 'unsupported-format')

    def test_not_a_backup(self):
        for data in (b'', b'\x89PNG\r\n\x1a\n' + os.urandom(200), os.urandom(4096), b'hello world\n',
                     b'WOOWTECH-BACKUP/x\n{}', b'WOOWTECH-BACKUP/1\r\n{}\n', b'WOOW'):
            with self.subTest(data=data[:20]):
                self.assertEqual(self.code(data), 'not-a-backup')

    def test_not_regular_or_symlink(self):
        target = self.file(fake_archive_bytes(), 'real.woowbackup')
        link = self.dir / 'link.woowbackup'
        link.symlink_to(target)
        with self.assertRaises(BackupError) as ctx:
            archive.read_header(link)
        self.assertEqual(ctx.exception.code, 'not-a-backup')
        fifo = self.dir / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(BackupError) as ctx:
            archive.read_header(fifo)
        self.assertEqual(ctx.exception.code, 'not-a-backup')
        with self.assertRaises(BackupError) as ctx:
            archive.read_header(self.dir / 'missing')
        self.assertEqual(ctx.exception.code, 'not-found')

    def test_header_defects_are_corrupt(self):
        good = fake_archive_bytes()
        line_end = good.index(b'\n', len(archive.MAGIC))
        cases = {
            'bad json': archive.MAGIC + b'{"format":1,\n' + good[line_end + 1:],
            'unknown key': fake_archive_bytes(extra_field=1),
            'missing key': archive.MAGIC + b'{"format":1,"backup_id":"%s","created":"%s","key_id":"ABCD-EF01-2345-6789",'
                                            b'"encryption":"age-x25519"}\n' % (BACKUP_ID.encode(), CREATED.encode())
                           + good[line_end + 1:],
            'bad backup id': fake_archive_bytes(backup_id='../../etc/passwd'),
            'impossible date': fake_archive_bytes(backup_id='20261399T250000Z-a1b2c3d4'),
            'bad created': fake_archive_bytes(created='yesterday'),
            'bad key id': fake_archive_bytes(key_id='abcd-ef01-2345-6789'),
            'key id newline': fake_archive_bytes(key_id='ABCD-EF01-2345-6789\n'),
            'backup id newline': fake_archive_bytes(backup_id=BACKUP_ID + '\n'),
            'fullwidth digits': fake_archive_bytes(backup_id='２０２６１１１３T020000Z-a1b2c3d4'),
            'format bool': fake_archive_bytes(format=True),
            'duplicate keys': archive.MAGIC + b'{"format":1,"format":1}\n' + good[line_end + 1:],
            'header too long': archive.MAGIC + b'{"pad":"' + b'a' * 5000 + b'"}\n' + good[line_end + 1:],
            'not age': good[:line_end + 1] + b'-----BEGIN AGE ENCRYPTED FILE-----\n' + b'x' * 100,
            'age without mac': good[:line_end + 1] + b'age-encryption.org/v1\n-> X25519 abc\n' + b'Q' * 20000,
            'no stanza': good[:line_end + 1] + b'age-encryption.org/v1\n--- ' + b'C' * 43 + b'\n' + bytes(64),
            'too many stanzas': good[:line_end + 1] + b'age-encryption.org/v1\n' + b'-> X25519 abc\nAAAA\n' * 40
                                + b'--- ' + b'C' * 43 + b'\n' + bytes(64),
            'payload too short': fake_archive_bytes(payload=b'tiny'),
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.assertEqual(self.code(data), 'corrupt-archive')

    def test_truncated_header_is_corrupt(self):
        data = fake_archive_bytes()
        header_end = data.index(b'\n', len(archive.MAGIC)) + 1
        for cut in (8, 12, len(archive.MAGIC) - 1, len(archive.MAGIC), len(archive.MAGIC) + 30,
                    header_end - 1, header_end, header_end + 10, header_end + 60, len(data) - 40):
            with self.subTest(cut=cut):
                self.assertEqual(self.code(data[:cut]), 'corrupt-archive')
        self.assertEqual(self.code(data[:4]), 'not-a-backup')


# ---------------------------------------------------------------------------- manifest schema (no age)

class ManifestValidationTests(unittest.TestCase):
    def manifest(self):
        manifest = demo_manifest('ABCD-EF01-2345-6789')
        manifest['entries'] = [{'path': path, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                               for path, data in demo_payloads(big=16).items()]
        return manifest

    def test_valid(self):
        manifest = self.manifest()
        self.assertIs(archive.validate_manifest(manifest), manifest)

    def test_rejections(self):
        app = f'apps/{APP}'

        def m(fn):
            manifest = self.manifest()
            fn(manifest)
            return manifest

        def drop_entry_ref(x):
            x['apps'][0]['quadlet_files'] = []

        cases = {
            'not object': lambda x: None,
            'unknown top key': lambda x: x.update(extra=1),
            'missing top key': lambda x: x.pop('note'),
            'format 2': lambda x: x.update(format=2),
            'format bool': lambda x: x.update(format=True),
            'bad backup id': lambda x: x.update(backup_id='2026-11-13'),
            'bad created': lambda x: x.update(created='2026-11-13 02:00:00'),
            'bad type': lambda x: x.update(type='uploaded'),
            'note too long': lambda x: x.update(note='a' * 1001),
            'note NUL': lambda x: x.update(note='a\x00b'),
            'bad key id': lambda x: x.update(key_id='ABCD'),
            'tool extra': lambda x: x['tool'].update(url='x'),
            'source missing': lambda x: x['source'].pop('arch'),
            'machine id': lambda x: x['source'].update(machine_id_sha256='zz'),
            'downtime negative': lambda x: x['consistency'].update(downtime_seconds=-1),
            'downtime bool': lambda x: x['consistency'].update(downtime_seconds=True),
            'no apps': lambda x: x.update(apps=[]),
            'app unknown key': lambda x: x['apps'][0].update(script='rm -rf /'),
            'app id': lambda x: x['apps'][0].update(id='Bad_ID'),
            'duplicate app': lambda x: x['apps'].append(copy.deepcopy(x['apps'][0])),
            'owner root': lambda x: x['apps'][0]['owner'].update(name='root'),
            'owner uid 0': lambda x: x['apps'][0]['owner'].update(uid=0),
            'owner uid str': lambda x: x['apps'][0]['owner'].update(uid='1001'),
            'adapter version bool': lambda x: x['apps'][0].update(adapter_version=True),
            'image id': lambda x: x['apps'][0]['images'][0].update(id='sha256:xyz'),
            'image ref space': lambda x: x['apps'][0]['images'][0].update(ref='a b'),
            'pg major': lambda x: x['apps'][0]['postgres'][0].update(major='16'),
            'pg missing entry': lambda x: x['apps'][0]['postgres'][0].pop('entry'),
            'volume name': lambda x: x['apps'][0]['volumes'][0].update(name='../vol'),
            'secret name': lambda x: x['apps'][0]['secrets'][0].update(name='-flag'),
            'quadlet name': lambda x: x['apps'][0]['quadlet_files'][0].update(name='evil.service'),
            'config abs': lambda x: x['apps'][0]['config_files'][0].update(path='/etc/shadow'),
            'config dotdot': lambda x: x['apps'][0]['config_files'][0].update(path='.config/../../.ssh/authorized_keys'),
            'config outside': lambda x: x['apps'][0]['config_files'][0].update(path='.ssh/authorized_keys'),
            'config empty segment': lambda x: x['apps'][0]['config_files'][0].update(path='.config//a'),
            'config mode exec': lambda x: x['apps'][0]['config_files'][0].update(mode='0755'),
            'config mode group write': lambda x: x['apps'][0]['config_files'][0].update(mode='0660'),
            'config mode format': lambda x: x['apps'][0]['config_files'][0].update(mode='600'),
            'entry traversal': lambda x: x['entries'][0].update(path=f'{app}/images/../../../etc/passwd'),
            'entry absolute': lambda x: x['entries'][0].update(path='/etc/passwd'),
            'entry trailing newline': lambda x: (x['entries'][0].update(path=x['entries'][0]['path'] + '\n'),
                                                 x['apps'][0]['images'][0].update(entry=x['entries'][0]['path'])),
            'app id trailing newline': lambda x: x['apps'][0].update(id=APP + '\n'),
            'key id trailing newline': lambda x: x.update(key_id='ABCD-EF01-2345-6789\n'),
            'created fullwidth digits': lambda x: x.update(created='２０２６-11-13T02:00:00Z'),
            'entry bad category': lambda x: x['entries'][0].update(path=f'{app}/scripts/run.sh'),
            'entry size negative': lambda x: x['entries'][0].update(size=-1),
            'entry size float': lambda x: x['entries'][0].update(size=1.5),
            'entry sha': lambda x: x['entries'][0].update(sha256='A' * 64),
            'entry extra key': lambda x: x['entries'][0].update(mode='0777'),
            'duplicate entry': lambda x: x['entries'].append(dict(x['entries'][0])),
            'orphan entry': drop_entry_ref,
            'ref not in entries': lambda x: x['entries'].pop(),
            'ref wrong section': lambda x: x['apps'][0]['volumes'][0].update(entry=f'{app}/secrets/woowbk-demo-db-password'),
            'ref other app': lambda x: x['apps'][0]['postgres'][0].update(entry='apps/other-app/postgres/main.dump'),
            'ref twice': lambda x: x['apps'][0]['images'][1].update(entry=f'{app}/images/0.oci.tar'),
            'snapshot not object': lambda x: x['apps'][0].update(verify_snapshot=[]),
            'snapshot deep': lambda x: x['apps'][0]['verify_snapshot']['summary'].update(
                deep={'a': {'b': {'c': {'d': {'e': 1}}}}}),
            'too many entries': lambda x: x.update(entries=[x['entries'][0]] * 4000),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                value = 'not a manifest' if name == 'not object' else m(mutate)
                with self.assertRaises(BackupError) as ctx:
                    archive.validate_manifest(value)
                self.assertEqual(ctx.exception.code, 'invalid-manifest')
                self.assertTrue(ctx.exception.message)


# ---------------------------------------------------------------------------- real encryption

@needs_age
class RoundTripTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace(self)

    def test_round_trip_multi_mb(self):
        payloads = demo_payloads()
        calls = []
        dest, result, entries = self.ws.write(payloads, progress=lambda done, total: calls.append((done, total)))
        total = sum(len(v) for v in payloads.values())
        self.assertEqual(result['size'], dest.stat().st_size)
        self.assertEqual(result['sha256'], util.sha256_file(dest))
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o600)
        self.assertEqual(calls[-1], (total, total))
        self.assertEqual([p.name for p in self.ws.out.iterdir()], [dest.name], 'no temp files left behind')

        header = archive.read_header(dest)
        self.assertEqual(header['backup_id'], BACKUP_ID)
        self.assertEqual(header['key_id'], self.ws.key.key_id)
        raw = dest.read_bytes()
        self.assertTrue(raw.startswith(archive.MAGIC))
        self.assertEqual(json.loads(raw.split(b'\n')[1]), header)

        ids = self.ws.keys.identities()
        manifest = archive.read_manifest(dest, ids)
        self.assertEqual([e['path'] for e in manifest['entries']], list(payloads))
        self.assertEqual(manifest['apps'][0]['verify_snapshot']['summary']['title'], '我的筆記')
        self.assertEqual(manifest['note'], '測試備份')

        seen = []
        verified = archive.verify_archive(dest, [k.path for k in ids], progress=lambda d, t: seen.append((d, t)))
        self.assertEqual(verified['entries'], len(payloads))
        self.assertEqual(verified['bytes'], total)
        self.assertEqual(seen[-1], (total, total))

        target = self.ws.dest()
        extracted = archive.extract_archive(dest, ids, target)
        self.assertEqual(extracted, manifest)
        tree = file_tree(target)
        for path, data in payloads.items():
            self.assertEqual(tree[path], ('file', 0o600, data), path)
        for rel, (kind, mode, _) in tree.items():
            if kind == 'dir':
                self.assertEqual(mode, 0o700, rel)
        self.assertEqual({k for k, v in tree.items() if v[0] == 'file'}, set(payloads))
        self.assertEqual(tool_children(), [], 'age/zstd children reaped')

    def test_member_layout_matches_contract(self):
        payloads = demo_payloads(big=4096)
        dest, _, _ = self.ws.write(payloads)
        plain = decrypt_tar(dest, self.ws.key.path)
        with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as tar:
            members = tar.getmembers()
            names = [m.name for m in members]
            self.assertEqual(names, ['manifest.json'] + list(payloads))
            for member in members:
                self.assertTrue(member.isreg(), member.name)
                self.assertEqual((member.mode, member.uid, member.gid), (0o600, 0, 0), member.name)
            manifest = json.loads(tar.extractfile('manifest.json').read())
        self.assertEqual(manifest['entries'], [{'path': p, 'size': len(d), 'sha256': hashlib.sha256(d).hexdigest()}
                                               for p, d in payloads.items()])

    def test_progress_throttled_for_large_entries(self):
        payloads = demo_payloads(big=20 * 1024 * 1024)
        calls = []
        self.ws.write(payloads, progress=lambda d, t: calls.append(d))
        self.assertGreaterEqual(len(calls), 2)
        self.assertLess(len(calls), 20)
        self.assertEqual(calls, sorted(calls))

    def test_wrong_key_and_key_required(self):
        dest, _, _ = self.ws.write(demo_payloads(big=1024))
        other = Workspace(self)
        for call in (lambda ids: archive.read_manifest(dest, ids),
                     lambda ids: archive.verify_archive(dest, ids),
                     lambda ids: archive.extract_archive(dest, ids, other.dest(f'x{time.monotonic_ns()}'))):
            with self.assertRaises(BackupError) as ctx:
                call(other.keys.identities())
            self.assertEqual(ctx.exception.code, 'wrong-key')
            self.assertEqual(ctx.exception.details['key_id'], self.ws.key.key_id)
            with self.assertRaises(BackupError) as ctx:
                call([])
            self.assertEqual(ctx.exception.code, 'key-required')
        # The right key among several identities works, in any order.
        both = other.keys.identities() + self.ws.keys.identities()
        self.assertEqual(archive.verify_archive(dest, both)['entries'], 8)
        self.assertEqual(archive.verify_archive(dest, [k.path for k in both])['entries'], 8)

    def test_missing_identity_files_are_skipped(self):
        dest, _, _ = self.ws.write(demo_payloads(big=1024))
        ghost = self.ws.base / 'run' / 'key-vanished'
        self.assertEqual(archive.verify_archive(dest, [ghost] + self.ws.keys.identities())['entries'], 8)
        with self.assertRaises(BackupError) as ctx:
            archive.verify_archive(dest, [ghost])
        self.assertEqual(ctx.exception.code, 'key-required')

    def test_malformed_user_key_file(self):
        # age aborts on ANY unreadable identity, so a typo'd emergency key must not hide the device key
        # and must be reported as a key problem, not as a damaged backup.
        dest, _, _ = self.ws.write(demo_payloads(big=1024))
        secret = next(line for line in Path(self.ws.key.path).read_text().splitlines()
                      if line.startswith('AGE-SECRET-KEY-1'))
        typo = self.ws.base / 'key-typo'
        typo.write_text(secret[:-1] + ('Q' if secret[-1] != 'Q' else 'P') + '\n')
        garbage = self.ws.base / 'key-garbage'
        garbage.write_text('AGE-PLUGIN-FOO-1QQQQ\n')
        for bad in (typo, garbage):
            with self.subTest(bad.name):
                with self.assertRaises(BackupError) as ctx:
                    archive.verify_archive(dest, [bad])
                self.assertEqual(ctx.exception.code, 'wrong-key')
                self.assertEqual(archive.verify_archive(dest, [bad] + self.ws.keys.identities())['entries'], 8)
        good_path = self.ws.base / 'key-good'
        good_path.write_text(secret + '\n')
        self.assertEqual(archive.read_manifest(dest, [good_path])['backup_id'], BACKUP_ID)

    def test_damaged_key_file_does_not_hide_other_keys(self):
        other = Workspace(self)
        dest, _, _ = other.write(demo_payloads(big=1024))  # encrypted to the other device's key
        secret = next(line for line in Path(other.key.path).read_text().splitlines()
                      if line.startswith('AGE-SECRET-KEY-1'))
        self.ws.keys.import_key(secret)
        Path(self.ws.key.path).write_text('# damaged on disk\nAGE-SECRET-KEY-1QQQQ\n')
        ids = self.ws.keys.identities()
        self.assertEqual(len(ids), 2, 'metadata still lists the damaged device key')
        self.assertEqual(archive.verify_archive(dest, ids)['entries'], 8)

    def test_cancel_from_progress_callback_cleans_up(self):
        class Cancelled(Exception):
            pass

        def cancel(done, total):
            if done:
                raise Cancelled()

        payloads = demo_payloads(big=20 * 1024 * 1024)
        with self.assertRaises(Cancelled):
            self.ws.write(payloads, progress=cancel)
        self.assertEqual(list(self.ws.out.iterdir()), [], 'temp archive discarded')
        self.assertEqual(tool_children(), [])
        dest, _, _ = self.ws.write(payloads)
        target = self.ws.dest()
        with self.assertRaises(Cancelled):
            archive.extract_archive(dest, self.ws.keys.identities(), target, progress=cancel)
        self.assertEqual(os.listdir(target), [], 'partial extraction removed')
        with self.assertRaises(Cancelled):
            archive.verify_archive(dest, self.ws.keys.identities(), progress=cancel)
        self.assertEqual(tool_children(), [], 'no age/zstd child left (running or zombie)')

    def test_write_rejections_leave_nothing(self):
        payloads = demo_payloads(big=2048)
        entries = stage(self.ws.staging, payloads)
        manifest = demo_manifest(self.ws.key.key_id)
        recipient = self.ws.key.recipient
        dest = self.ws.out / 'r.woowbackup'
        bad_sha = [archive.Entry(e.path, e.source, e.size, '0' * 64) if i == 3 else e for i, e in enumerate(entries)]
        bad_size = [archive.Entry(e.path, e.source, e.size + 1, e.sha256) if i == 1 else e
                    for i, e in enumerate(entries)]
        cases = {
            'recipient': (None, manifest, entries, 'age1notvalid', 'internal-error'),
            'header mismatch': ({'backup_id': '20261113T020000Z-00000000'}, manifest, entries, recipient,
                                'internal-error'),
            'manifest key id': (None, dict(manifest, key_id='0000-0000-0000-0000'), entries, recipient,
                                'internal-error'),
            'invalid manifest': (None, dict(manifest, type='nightly'), entries, recipient, 'invalid-manifest'),
            'size mismatch': (None, manifest, bad_size, recipient, 'internal-error'),
            'sha mismatch': (None, manifest, bad_sha, recipient, 'internal-error'),
        }
        for name, (header, man, ents, rcpt, code) in cases.items():
            with self.subTest(name):
                with self.assertRaises(BackupError) as ctx:
                    archive.write_archive(dest, header, man, ents, rcpt, tmp_dir=self.ws.out)
                self.assertEqual(ctx.exception.code, code)
                self.assertEqual(list(self.ws.out.iterdir()), [], 'no partial or temp file')
        dest.write_bytes(b'existing')
        with self.assertRaises(BackupError):
            archive.write_archive(dest, None, manifest, entries, recipient, tmp_dir=self.ws.out)
        self.assertEqual(dest.read_bytes(), b'existing')


@needs_age
class DamageTests(unittest.TestCase):
    """Truncation and flipped bytes must never verify, and must never leave extracted files."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='woowbk-e1-')
        base = Path(cls.tmp.name)
        cls.paths = Paths(base=base / 'root')
        cls.keys = KeyStore(cls.paths)
        cls.key, _ = cls.keys.ensure_device_key()
        staging = base / 'staging'
        staging.mkdir()
        cls.payloads = demo_payloads(big=300 * 1024)  # > several 64 KiB age chunks
        entries = stage(staging, cls.payloads)
        cls.archive = base / 'good.woowbackup'
        archive.write_archive(cls.archive, None, demo_manifest(cls.key.key_id), entries, cls.key.recipient,
                              tmp_dir=base)
        cls.data = cls.archive.read_bytes()
        first = cls.data.index(b'\n') + 1
        cls.header_end = cls.data.index(b'\n', first) + 1
        mac_line = cls.data.index(b'\n--- ', cls.header_end) + 1  # start of age's '--- <MAC>' line
        cls.mac_end = cls.data.index(b'\n', mac_line) + 1  # first byte of the binary payload (nonce)
        assert cls.mac_end - mac_line == 48, cls.mac_end - mac_line
        cls.stanza = cls.data.index(b'\n-> X25519 ', cls.header_end) + 15
        cls.base = base

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def check_rejected(self, data, allowed):
        path = self.base / f'damaged-{time.monotonic_ns()}.woowbackup'
        path.write_bytes(data)
        ids = self.keys.identities()
        for name, call in (('verify', lambda: archive.verify_archive(path, ids)),
                           ('extract', None)):
            if call is None:
                dest = self.base / f'dest-{time.monotonic_ns()}'
                dest.mkdir(mode=0o700)
                with self.assertRaises(BackupError) as ctx:
                    archive.extract_archive(path, ids, dest)
                self.assertEqual(list(dest.iterdir()), [], 'partial output removed')
            else:
                with self.assertRaises(BackupError) as ctx:
                    call()
            self.assertIn(ctx.exception.code, allowed, f'{name}: {ctx.exception.details}')
        self.assertEqual(tool_children(), [], 'no zombie/leftover age or zstd process')
        path.unlink()

    def test_truncation_at_many_offsets(self):
        size = len(self.data)
        offsets = {
            'empty': 0, 'inside magic': 10, 'end of magic': len(archive.MAGIC),
            'inside header json': len(archive.MAGIC) + 25, 'end of header': self.header_end,
            'inside age header': self.header_end + 30, 'end of age header': self.mac_end,
            'inside nonce': self.mac_end + 8, 'first chunk': self.mac_end + 1000,
            'chunk boundary': self.mac_end + 16 + 65536 + 16, 'mid stream': size // 2,
            'last 17 bytes': size - 17, 'last byte': size - 1,
        }
        for name, cut in offsets.items():
            with self.subTest(name, cut=cut):
                allowed = {'not-a-backup'} if cut == 0 else {'corrupt-archive'}
                self.check_rejected(self.data[:cut], allowed)

    def test_flipped_bytes(self):
        size = len(self.data)
        offsets = {
            'magic': 0, 'format line digit': len(archive.MAGIC) - 2,
            'header backup id digit': self.data.index(BACKUP_ID.encode()) + 3,
            'header key id': self.data.index(self.key.key_id.encode()) + 1,
            'header structure': len(archive.MAGIC),
            'age intro': self.header_end + 3, 'stanza share': self.stanza + 5,
            'stanza body': self.stanza + 50, 'header mac': self.mac_end - 10,
            'nonce': self.mac_end + 2, 'first chunk': self.mac_end + 500, 'mid payload': size // 2,
            'last chunk': size - 40, 'last byte': size - 1,
        }
        for name, offset in offsets.items():
            for mask in (0x01, 0x80):
                with self.subTest(name, offset=offset, mask=mask):
                    damaged = bytearray(self.data)
                    damaged[offset] ^= mask
                    allowed = {'corrupt-archive', 'not-a-backup', 'unsupported-format'} if offset < len(
                        archive.MAGIC) else {'corrupt-archive'}
                    self.check_rejected(bytes(damaged), allowed)

    def test_appended_garbage(self):
        self.check_rejected(self.data + b'trailing', {'corrupt-archive'})
        self.check_rejected(self.data + self.data, {'corrupt-archive'})

    def test_good_archive_still_verifies(self):
        result = archive.verify_archive(self.archive, self.keys.identities())
        self.assertEqual(result['bytes'], sum(len(v) for v in self.payloads.values()))


@needs_age
class EarlyStopTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace(self)

    def test_read_manifest_stops_early_without_leaks(self):
        dest, _, _ = self.ws.write(demo_payloads(big=24 * 1024 * 1024))
        ids = self.ws.keys.identities()
        archive.read_manifest(dest, ids)  # warm-up (imports, page cache)
        fds = open_fds()
        result = {}

        def target():
            started = time.monotonic()
            result['manifest'] = archive.read_manifest(dest, ids)
            result['seconds'] = time.monotonic() - started

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(60)
        self.assertFalse(thread.is_alive(), 'read_manifest deadlocked')
        self.assertEqual(result['manifest']['backup_id'], BACKUP_ID)
        self.assertEqual(open_fds(), fds, 'file descriptors leaked')
        self.assertEqual(tool_children(), [], 'age/zstd not reaped')
        self.assertEqual(tool_children(), [], 'no age/zstd child left (running or zombie)')

    def test_error_paths_reap_children(self):
        dest, _, _ = self.ws.write(demo_payloads(big=4 * 1024 * 1024))
        fds = open_fds()
        damaged = self.ws.out / 'damaged.woowbackup'
        data = bytearray(dest.read_bytes())
        data[len(data) // 2] ^= 0xFF
        damaged.write_bytes(bytes(data))
        other = Workspace(self)
        for path, ids in ((damaged, self.ws.keys.identities()), (dest, other.keys.identities())):
            with self.assertRaises(BackupError):
                archive.verify_archive(path, ids)
        self.assertEqual(open_fds(), fds)
        self.assertEqual(tool_children(), [], 'no age/zstd child left (running or zombie)')


if __name__ == '__main__':
    unittest.main()
