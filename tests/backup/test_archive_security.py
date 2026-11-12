"""Hostile archives encrypted with a VALID key (team E1).

Anyone holding the public recipient can produce archives that decrypt fine, so the decrypted tar is
treated as hostile: traversal, absolute names, links, devices, directories, extra/missing/duplicate
members, size lies, manifest not first, oversize manifest, too many members, smuggled PAX/GNU
headers and trailing data must all be rejected - and nothing may be written outside the
destination (which must also be left empty).
"""
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2] / 'backup-engine'
if str(ENGINE) not in sys.path:
    sys.path.insert(0, str(ENGINE))

from woowbackup import archive  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402
from woowbackup.keys import KeyStore  # noqa: E402
from woowbackup.paths import Paths  # noqa: E402

try:
    from .test_archive import BACKUP_ID, CREATED, file_tree, needs_age, seal, tool_children
except ImportError:  # executed as a top-level module
    from test_archive import BACKUP_ID, CREATED, file_tree, needs_age, seal, tool_children

APP = 'woowbk-demo'
SECRET_ENTRY = f'apps/{APP}/secrets/woowbk-demo-db-password'
CONFIG_ENTRY = f'apps/{APP}/config/0'
SECRET = b'hunter2-but-longer\n'
CONFIG = b'TITLE=demo\n'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def small_manifest(key_id, files=None, backup_id=BACKUP_ID):
    """A schema-valid manifest declaring `files` ({entry path: bytes}, secrets/config only)."""
    files = files if files is not None else {SECRET_ENTRY: SECRET, CONFIG_ENTRY: CONFIG}
    secrets, configs = [], []
    for index, path in enumerate(files):
        category, name = path.split('/')[2], path.split('/')[3]
        if category == 'secrets':
            secrets.append({'name': name, 'entry': path})
        else:
            configs.append({'path': f'.config/{APP}/f{index}.env', 'mode': '0600', 'entry': path})
    app = {'id': APP, 'name': '示範', 'adapter': 'quadlet-postgres', 'adapter_version': 1,
           'catalog_sha256': 'a' * 64, 'owner': {'name': 'appowner', 'uid': 1001}, 'images': [], 'postgres': [],
           'volumes': [], 'secrets': secrets, 'config_files': configs, 'quadlet_files': [], 'verify_snapshot': {}}
    return {'format': 1, 'backup_id': backup_id, 'created': CREATED, 'type': 'manual', 'note': '',
            'key_id': key_id, 'tool': {'name': 'woowtech-cockpit-backup', 'version': 'test'},
            'source': {'hostname': 'attacker', 'machine_id_sha256': '', 'arch': 'x86_64', 'os': 'x', 'podman': 'x'},
            'consistency': {'method': 'writers-stopped', 'downtime_seconds': 0}, 'apps': [app],
            'entries': [{'path': p, 'size': len(d), 'sha256': sha(d)} for p, d in files.items()]}


def reg(name, data, size=None):
    info = tarfile.TarInfo(name)
    info.size = len(data) if size is None else size
    info.mode = 0o600
    return info, data


def special(name, kind, linkname=''):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = linkname
    info.mode = 0o777
    if kind in (tarfile.CHRTYPE, tarfile.BLKTYPE):
        info.devmajor, info.devminor = 1, 3
    return info, None


def build_tar(members, fmt=tarfile.PAX_FORMAT):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=fmt) as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def raw_block(name, size, typeflag, magic=b'ustar\x0000'):
    """Hand-made ustar header block (for headers tarfile refuses to produce)."""
    block = bytearray(512)
    block[0:len(name)] = name
    block[100:108] = b'0000600\x00'
    block[108:116] = b'0000000\x00'
    block[116:124] = b'0000000\x00'
    block[124:136] = (b'%011o' % size) + b'\x00'
    block[136:148] = b'00000000000\x00'
    block[156:157] = typeflag
    block[257:265] = magic
    block[148:156] = b'        '
    block[148:156] = b'%06o\x00 ' % sum(block)
    return bytes(block)


def manifest_member(manifest):
    return reg('manifest.json', json.dumps(manifest).encode())


def header_offset(tar_data, name):
    """Offset of the 512-byte header block whose name field is exactly `name` (not data that contains it)."""
    raw = name.encode()
    for offset in range(0, len(tar_data), 512):
        if tar_data[offset:offset + len(raw)] == raw and tar_data[offset + len(raw)] == 0:
            return offset
    raise AssertionError(f'no header block for {name}')


def padded(size):
    return (size + 511) // 512 * 512


def typed(name, data, kind):
    info, data = reg(name, data)
    info.type = kind
    return info, data


def resum(block):
    block[148:156] = b'        '
    block[148:156] = b'%06o\x00 ' % sum(block)
    return block


@needs_age
class HostileArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='woowbk-e1-sec-')
        cls.base = Path(cls.tmp.name)
        cls.keys = KeyStore(Paths(base=cls.base / 'keyroot'))
        cls.key, _ = cls.keys.ensure_device_key()
        cls.header = {'format': 1, 'backup_id': BACKUP_ID, 'created': CREATED, 'key_id': cls.key.key_id,
                      'encryption': 'age-x25519', 'compression': 'zstd'}
        cls.outside_target = Path('/tmp') / f'woowbk-e1-evil-{os.getpid()}'

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        # sandbox/dest is the extraction root; sandbox/outside holds a sentinel that must never change.
        self.sandbox = self.base / f'sandbox-{time.monotonic_ns()}'
        self.sandbox.mkdir(mode=0o700)
        self.dest = self.sandbox / 'dest'
        self.dest.mkdir(mode=0o700)
        (self.sandbox / 'outside').mkdir()
        (self.sandbox / 'outside' / 'sentinel').write_bytes(b'keep')
        self.before = file_tree(self.sandbox)

    def tar(self, members, manifest=None, fmt=tarfile.PAX_FORMAT):
        manifest = manifest if manifest is not None else small_manifest(self.key.key_id)
        return build_tar([manifest_member(manifest)] + members, fmt)

    def assert_rejected(self, tar_data, code='corrupt-archive', header=None, limits=None):
        path = seal(self.sandbox.parent / f'hostile-{time.monotonic_ns()}.woowbackup', header or self.header,
                    tar_data, self.key.recipient)
        ids = self.keys.identities()
        with self.assertRaises(BackupError) as ctx:
            archive.extract_archive(path, ids, self.dest, limits=limits)
        self.assertEqual(ctx.exception.code, code, ctx.exception.details)
        with self.assertRaises(BackupError) as ctx2:
            archive.verify_archive(path, ids, limits=limits)
        self.assertEqual(ctx2.exception.code, code, ctx2.exception.details)
        self.assertEqual(file_tree(self.sandbox), self.before, 'nothing written outside dest, dest left empty')
        self.assertFalse(self.outside_target.exists())
        self.assertEqual(tool_children(), [], 'age/zstd reaped')
        return ctx.exception

    def test_control_valid_archive_extracts(self):
        path = seal(self.base / 'control.woowbackup', self.header,
                    self.tar([reg(SECRET_ENTRY, SECRET), reg(CONFIG_ENTRY, CONFIG)]), self.key.recipient)
        archive.extract_archive(path, self.keys.identities(), self.dest)
        self.assertEqual((self.dest / SECRET_ENTRY).read_bytes(), SECRET)
        self.assertEqual((self.dest / CONFIG_ENTRY).read_bytes(), CONFIG)

    def test_traversal_member_name(self):
        for name in ('../evil', f'apps/{APP}/secrets/../../../../evil', '../outside/sentinel',
                     f'{SECRET_ENTRY}/../../../evil', './' + SECRET_ENTRY):
            with self.subTest(name):
                self.assert_rejected(self.tar([reg(name, SECRET), reg(CONFIG_ENTRY, CONFIG)]))
        self.assertFalse((self.sandbox / 'evil').exists())

    def test_absolute_member_name(self):
        self.assert_rejected(self.tar([reg(str(self.outside_target), SECRET), reg(CONFIG_ENTRY, CONFIG)]))

    def test_traversal_or_absolute_in_manifest(self):
        for bad in ('../../evil', '/tmp/evil', f'apps/{APP}/secrets/../../evil', f'apps/{APP}/secrets/.hidden'):
            with self.subTest(bad):
                manifest = small_manifest(self.key.key_id)
                manifest['entries'][0]['path'] = bad
                manifest['apps'][0]['secrets'][0]['entry'] = bad
                self.assert_rejected(self.tar([reg(bad, SECRET), reg(CONFIG_ENTRY, CONFIG)], manifest),
                                     code='invalid-manifest')

    def test_links_devices_dirs_fifos(self):
        kinds = {
            'symlink': special(SECRET_ENTRY, tarfile.SYMTYPE, '/etc/shadow'),
            'symlink to outside': special(SECRET_ENTRY, tarfile.SYMTYPE, '../../outside/sentinel'),
            'hardlink': special(SECRET_ENTRY, tarfile.LNKTYPE, 'manifest.json'),
            'char device': special(SECRET_ENTRY, tarfile.CHRTYPE),
            'block device': special(SECRET_ENTRY, tarfile.BLKTYPE),
            'directory': special(SECRET_ENTRY, tarfile.DIRTYPE),
            'fifo': special(SECRET_ENTRY, tarfile.FIFOTYPE),
            'contiguous': typed(SECRET_ENTRY, SECRET, tarfile.CONTTYPE),
            'old-style regular (AREGTYPE)': typed(SECRET_ENTRY, SECRET, tarfile.AREGTYPE),
        }
        for name, member in kinds.items():
            with self.subTest(name):
                self.assert_rejected(self.tar([member, reg(CONFIG_ENTRY, CONFIG)]))

    def test_link_then_write_through_it(self):
        # Classic two-step attack: a symlink member followed by a file "inside" it.
        manifest = small_manifest(self.key.key_id)
        self.assert_rejected(self.tar([special(f'apps/{APP}/secrets', tarfile.SYMTYPE, str(self.sandbox / 'outside')),
                                       reg(SECRET_ENTRY, SECRET), reg(CONFIG_ENTRY, CONFIG)], manifest))

    def test_extra_member(self):
        self.assert_rejected(self.tar([reg(SECRET_ENTRY, SECRET), reg(CONFIG_ENTRY, CONFIG),
                                       reg(f'apps/{APP}/secrets/smuggled', b'x')]))

    def test_missing_member(self):
        self.assert_rejected(self.tar([reg(SECRET_ENTRY, SECRET)]))

    def test_duplicate_member(self):
        self.assert_rejected(self.tar([reg(SECRET_ENTRY, SECRET), reg(SECRET_ENTRY, SECRET),
                                       reg(CONFIG_ENTRY, CONFIG)]))
        self.assert_rejected(self.tar([reg(SECRET_ENTRY, SECRET), reg(CONFIG_ENTRY, CONFIG),
                                       reg(CONFIG_ENTRY, CONFIG)]))

    def test_wrong_order(self):
        self.assert_rejected(self.tar([reg(CONFIG_ENTRY, CONFIG), reg(SECRET_ENTRY, SECRET)]))

    def test_size_lies(self):
        # Tar header size differs from the manifest (bigger and smaller).
        self.assert_rejected(self.tar([reg(SECRET_ENTRY, SECRET + b'more'), reg(CONFIG_ENTRY, CONFIG)]))
        self.assert_rejected(self.tar([reg(SECRET_ENTRY, SECRET[:-3]), reg(CONFIG_ENTRY, CONFIG)]))
        # Same size, different content.
        self.assert_rejected(self.tar([reg(SECRET_ENTRY, b'X' * len(SECRET)), reg(CONFIG_ENTRY, CONFIG)]))

    def test_size_lie_while_streaming(self):
        # The manifest and the tar header both claim 50 MB but the plaintext ends after 100 kB.
        big = {SECRET_ENTRY: b'A' * 50_000_000}
        manifest = small_manifest(self.key.key_id, big)
        tar_data = bytearray(build_tar([manifest_member(manifest), reg(SECRET_ENTRY, b'A' * 100_000)]))
        start = header_offset(bytes(tar_data), SECRET_ENTRY)
        block = bytearray(tar_data[start:start + 512])
        block[124:136] = b'%011o\x00' % 50_000_000
        tar_data[start:start + 512] = resum(block)
        self.assert_rejected(bytes(tar_data[:start + 512 + 100_000]))

    def test_manifest_not_first(self):
        data = build_tar([reg(SECRET_ENTRY, SECRET), manifest_member(small_manifest(self.key.key_id)),
                          reg(CONFIG_ENTRY, CONFIG)])
        self.assert_rejected(data)

    def test_no_members(self):
        self.assert_rejected(build_tar([]))

    def test_oversize_manifest(self):
        manifest = small_manifest(self.key.key_id)
        manifest['note'] = ''
        blob = json.dumps(manifest).encode()
        padded = blob[:-1] + b',"pad":"' + b' ' * (archive.MAX_MANIFEST + 1 - len(blob)) + b'"}'
        self.assertGreater(len(padded), archive.MAX_MANIFEST)
        self.assert_rejected(build_tar([reg('manifest.json', padded), reg(SECRET_ENTRY, SECRET)]),
                             code='limit-exceeded')

    def test_too_many_members(self):
        manifest = small_manifest(self.key.key_id)
        manifest['entries'] = [{'path': f'apps/{APP}/secrets/s{i}', 'size': 1, 'sha256': '0' * 64}
                               for i in range(archive.MAX_MEMBERS)]
        self.assertLess(len(json.dumps(manifest)), archive.MAX_MANIFEST)
        self.assert_rejected(self.tar([], manifest), code='limit-exceeded')

    def test_declared_total_over_limits(self):
        exc = self.assert_rejected(self.tar([reg(SECRET_ENTRY, SECRET), reg(CONFIG_ENTRY, CONFIG)]),
                                   code='limit-exceeded', limits=archive.Limits(max_total_bytes=10))
        self.assertEqual(exc.details['total'], len(SECRET) + len(CONFIG))

    def test_declared_total_over_free_space(self):
        path = seal(self.base / f'space-{time.monotonic_ns()}.woowbackup', self.header,
                    self.tar([reg(SECRET_ENTRY, SECRET), reg(CONFIG_ENTRY, CONFIG)]), self.key.recipient)
        asked = []

        def free(p):
            asked.append(Path(p))
            return 512 * 1024 * 1024 + 10  # reserve + 10 bytes: less than the 30 declared bytes

        with self.assertRaises(BackupError) as ctx:
            archive.extract_archive(path, self.keys.identities(), self.dest, limits=archive.Limits(free_bytes=free))
        self.assertEqual(ctx.exception.code, 'insufficient-space')
        self.assertEqual(asked, [self.dest])
        self.assertEqual(list(self.dest.iterdir()), [])
        # Same archive fits when the free space allows it; verify never needs space.
        archive.extract_archive(path, self.keys.identities(), self.dest,
                                limits=archive.Limits(free_bytes=lambda p: 512 * 1024 * 1024 + 30))
        self.assertEqual((self.dest / SECRET_ENTRY).read_bytes(), SECRET)

    def manifest_only_tar(self):
        manifest = small_manifest(self.key.key_id)
        data = build_tar([manifest_member(manifest)])
        return data, 512 + padded(len(json.dumps(manifest).encode()))

    def test_smuggled_pax_and_gnu_headers(self):
        sym_pax = reg(SECRET_ENTRY, SECRET)
        sym_pax[0].pax_headers = {'linkpath': '/etc/shadow'}
        sparse = reg(SECRET_ENTRY, SECRET)
        sparse[0].pax_headers = {'GNU.sparse.size': '100000'}
        charset = reg(SECRET_ENTRY, SECRET)
        charset[0].pax_headers = {'hdrcharset': 'BINARY'}
        manifest_tar, end = self.manifest_only_tar()
        long_name = f'apps/{APP}/secrets/' + 'a' * 120
        gnu_long = raw_block(b'././@LongLink', len(long_name) + 1, b'L') + long_name.encode().ljust(512, b'\x00')
        cases = {
            'pax linkpath': self.tar([sym_pax, reg(CONFIG_ENTRY, CONFIG)]),
            'pax sparse': self.tar([sparse, reg(CONFIG_ENTRY, CONFIG)]),
            'pax hdrcharset': self.tar([charset, reg(CONFIG_ENTRY, CONFIG)]),
            'global pax header': manifest_tar[:end] + raw_block(b'pax_global_header', 0, b'g') + manifest_tar[end:],
            'gnu longname block': manifest_tar[:end] + gnu_long + manifest_tar[end:],
            'gnu format archive': build_tar([manifest_member(small_manifest(self.key.key_id)),
                                             reg(SECRET_ENTRY, SECRET), reg(CONFIG_ENTRY, CONFIG)],
                                            fmt=tarfile.GNU_FORMAT),
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.assert_rejected(data)

    def test_oversized_pax_header_is_bounded(self):
        manifest_tar, end = self.manifest_only_tar()
        huge = raw_block(b'././@PaxHeader', 2 ** 33 - 1, b'x')  # ~8 GiB of "pax records"
        self.assert_rejected(manifest_tar[:end] + huge + bytes(4096))

    def test_pax_size_record_must_match(self):
        honest = reg(SECRET_ENTRY, SECRET)
        honest[0].pax_headers = {'size': str(len(SECRET))}
        path = seal(self.base / 'pax-size.woowbackup', self.header,
                    self.tar([honest, reg(CONFIG_ENTRY, CONFIG)]), self.key.recipient)
        archive.verify_archive(path, self.keys.identities())  # accepted: pax size equals manifest size
        lying = reg(SECRET_ENTRY, SECRET)
        lying[0].pax_headers = {'size': str(len(SECRET) + 512)}
        self.assert_rejected(self.tar([lying, reg(CONFIG_ENTRY, CONFIG)]))

    def test_bad_tar_checksum_and_magic(self):
        good = self.tar([reg(SECRET_ENTRY, SECRET), reg(CONFIG_ENTRY, CONFIG)])
        start = header_offset(good, SECRET_ENTRY)
        broken = bytearray(good)
        broken[start + 100] ^= 0x01  # mode field changed: checksum no longer matches
        self.assert_rejected(bytes(broken))
        old_v7 = bytearray(good)
        block = bytearray(old_v7[start:start + 512])
        block[257:265] = bytes(8)  # pre-POSIX header without ustar magic
        old_v7[start:start + 512] = resum(block)
        self.assert_rejected(bytes(old_v7))
        base256 = bytearray(good)
        block = bytearray(base256[start:start + 512])
        block[124:136] = b'\x80' + bytes(10) + bytes([len(SECRET)])  # GNU base-256 size encoding
        base256[start:start + 512] = resum(block)
        self.assert_rejected(bytes(base256))

    def test_trailing_data_after_end_marker(self):
        good = self.tar([reg(SECRET_ENTRY, SECRET), reg(CONFIG_ENTRY, CONFIG)])
        self.assert_rejected(good + b'\x00' * 512 + b'hidden payload')
        self.assert_rejected(good + b'\x00' * (2 * 1024 * 1024))  # beyond the 1 MiB zero-padding allowance
        last = header_offset(good, CONFIG_ENTRY) + 512 + padded(len(CONFIG))
        self.assert_rejected(good[:last])  # no end-of-archive marker at all
        self.assert_rejected(good[:last + 512])  # only one of the two zero blocks
        second = bytearray(good)
        second[last + 512 + 7] = 0x41  # garbage inside the second zero block
        self.assert_rejected(bytes(second))

    def test_manifest_json_tricks(self):
        manifest = small_manifest(self.key.key_id)
        text = json.dumps(manifest)
        dup = text[:-1] + ', "type": "safety"}'
        nan = text.replace('"downtime_seconds": 0', '"downtime_seconds": NaN')
        for name, blob in (('duplicate key', dup.encode()), ('NaN', nan.encode()),
                           ('not utf-8', text.encode()[:-2] + b'\xff"}'), ('not object', b'[1,2,3]')):
            with self.subTest(name):
                self.assert_rejected(build_tar([reg('manifest.json', blob), reg(SECRET_ENTRY, SECRET),
                                                reg(CONFIG_ENTRY, CONFIG)]), code='invalid-manifest')

    def test_outer_header_must_match_manifest(self):
        for field, value in (('backup_id', '20261113T020000Z-ffffffff'), ('created', '2026-11-13T03:00:00Z')):
            with self.subTest(field):
                header = dict(self.header, **{field: value})
                self.assert_rejected(self.tar([reg(SECRET_ENTRY, SECRET), reg(CONFIG_ENTRY, CONFIG)]),
                                     header=header)

    def test_destination_must_be_private_and_empty(self):
        path = seal(self.base / 'dest-check.woowbackup', self.header,
                    self.tar([reg(SECRET_ENTRY, SECRET), reg(CONFIG_ENTRY, CONFIG)]), self.key.recipient)
        ids = self.keys.identities()
        (self.dest / 'leftover').write_bytes(b'x')
        with self.assertRaises(BackupError):
            archive.extract_archive(path, ids, self.dest)
        self.assertEqual(os.listdir(self.dest), ['leftover'], 'pre-existing content untouched')
        open_dir = self.sandbox / 'open'
        open_dir.mkdir()
        open_dir.chmod(0o755)
        with self.assertRaises(BackupError):
            archive.extract_archive(path, ids, open_dir)
        link = self.sandbox / 'link'
        link.symlink_to(self.sandbox / 'outside')
        with self.assertRaises(BackupError):
            archive.extract_archive(path, ids, link)
        self.assertEqual(os.listdir(self.sandbox / 'outside'), ['sentinel'])
        with self.assertRaises(BackupError):
            archive.extract_archive(path, ids, self.sandbox / 'missing')


if __name__ == '__main__':
    unittest.main()
