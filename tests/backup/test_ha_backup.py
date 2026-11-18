"""Home Assistant backup files (habackup.py, team E1): recognition, the strict outer description, member streams
(decrypt + gunzip), the strict inner-tar walk and addon.json -- on real-securetar fixtures and crafted hostile tars.

RealBackupTests reads the real HA backups made for this feature when WOOWBK_HA_FIXTURES names their directory (and
WOOWBK_HA_KEY holds their key); they are never committed.
"""
import gzip
import hashlib
import io
import json
import os
import struct
import tarfile
import tempfile
import unittest
import zlib
from pathlib import Path

from woowbackup import habackup, hasecuretar
from woowbackup.errors import BackupError

from . import hafixtures as hx
from .test_archive import fake_archive_bytes


def code_of(callable_, *args, **kwargs):
    try:
        callable_(*args, **kwargs)
    except BackupError as error:
        return error.code, error
    raise AssertionError('no BackupError')


class TempFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='woowbk-ha-')
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.count = 0

    def write(self, data):
        self.count += 1
        path = self.dir / f'file{self.count}.tar'
        path.write_bytes(data)
        return path

    def fd(self, data_or_path):
        path = data_or_path if isinstance(data_or_path, Path) else self.write(data_or_path)
        fd = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        return fd

    def describe(self, data):
        return habackup.describe(self.fd(data))

    def describe_code(self, data):
        return code_of(habackup.describe, self.fd(data))


class RecognitionTests(TempFiles):
    def test_ha_backups_are_recognised(self):
        for name in hx.META['fixtures']:
            with self.subTest(fixture=name):
                self.assertTrue(habackup.looks_like_ha(self.fd(hx.fixture(name))))
        self.assertTrue(habackup.looks_like_ha(self.fd(hx.simple_backup())))
        old_name = hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member())], hx.ha_doc(), json_name='backup.json',
                                  json_first=True)
        self.assertTrue(habackup.looks_like_ha(self.fd(old_name)), 'backup.json first and without ./ (older backups)')

    def test_other_files_are_not(self):
        cockpit_v2 = hx.tar_bytes([{'name': 'backup.json', 'data': json.dumps({'format': 2}).encode()},
                                   {'name': 'README.txt', 'data': b'x'}])
        no_json = hx.tar_bytes([{'name': f'{hx.ODOO}.tar.gz', 'data': hx.addon_member()}])
        ha_like_doc = json.dumps({'slug': 'x', 'name': 'x'}).encode()
        without_version = hx.outer_bytes([], json_raw=ha_like_doc)
        for label, data in (('cockpit format 2', cockpit_v2), ('cockpit format 1', fake_archive_bytes()),
                            ('random', os.urandom(4096)), ('gzip outer', gzip.compress(hx.simple_backup())),
                            ('no backup.json', no_json), ('no supervisor_version', without_version),
                            ('empty', b''), ('zeros', bytes(10240))):
            with self.subTest(case=label):
                self.assertFalse(habackup.looks_like_ha(self.fd(data)))

    def test_a_directory_or_unreadable_input_is_not_ha(self):
        fd = os.open(self.dir, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        self.assertFalse(habackup.looks_like_ha(fd))


class DescribeTests(TempFiles):
    def test_fixture_summaries(self):
        for name, fixture in hx.META['fixtures'].items():
            with self.subTest(fixture=name):
                layout = self.describe(hx.fixture(name))
                summary = layout.summary()
                self.assertEqual(summary['date'], '2026-11-18T09:01:20Z')
                self.assertEqual(summary['type'], 'partial')
                compressed = not name.endswith('_plain.tar')
                self.assertEqual(summary['compressed'], compressed)
                self.assertEqual(summary['protected'], not name.startswith(('plain', 'downloaded')))
                self.assertTrue(summary['supervisor'])
                self.assertEqual([a['slug'] for a in summary['addons']], [hx.ODOO, hx.N8N] if compressed else [hx.ODOO])
                self.assertEqual({m.name: m.encryption for m in layout.members},
                                 {member: info['encryption'] for member, info in fixture['members'].items()})
                self.assertEqual(summary['size'], fixture['size'])

    def test_a_decrypted_download_says_unprotected_but_keeps_supervisor_encrypted(self):
        layout = self.describe(hx.fixture('downloaded_gzip.tar'))
        self.assertFalse(layout.doc['protected'])
        self.assertEqual([(m.role, m.encryption) for m in layout.members],
                         [('addon', 'none'), ('addon', 'none'), ('folder', 'none'), ('supervisor', 'v3')])
        self.assertEqual(layout.addon(hx.ODOO).name, f'{hx.ODOO}.tar.gz')

    def test_members_backup_json_implies(self):
        odoo = (f'{hx.ODOO}.tar.gz', hx.addon_member())
        share = ('share.tar.gz', hx.tar_bytes([{'name': '.', 'type': 'dir'}], compress=True))
        core = ('homeassistant.tar.gz', hx.tar_bytes([{'name': '.', 'type': 'dir'}], compress=True))
        legacy = ('addons_local.tar.gz', hx.tar_bytes([{'name': '.', 'type': 'dir'}], compress=True))
        apps = ('apps_local.tar.gz', hx.tar_bytes([{'name': '.', 'type': 'dir'}], compress=True))
        good = [
            ([odoo, share], hx.ha_doc(folders=['share'])),
            ([core, odoo], hx.ha_doc(homeassistant={'version': '2026.7.4', 'exclude_database': False, 'size': 0.0})),
            ([odoo, legacy], hx.ha_doc(folders=['addons/local'])),
            ([odoo, apps], hx.ha_doc(folders=['apps/local'])),
            ([odoo], hx.ha_doc(folders=['homeassistant'])),  # a v1 artefact Supervisor drops
        ]
        for members, doc in good:
            with self.subTest(members=[m[0] for m in members]):
                self.assertEqual(len(self.describe(hx.outer_bytes(members, doc)).members), len(members))
        bad = [
            ([odoo, share], hx.ha_doc(), 'member that backup.json does not list'),
            ([], hx.ha_doc(), 'member that backup.json lists is missing'),
            ([odoo], hx.ha_doc(folders=['share']), 'member that backup.json lists is missing'),
            ([odoo, core], hx.ha_doc(), 'member that backup.json does not list'),
            ([odoo, legacy, apps], hx.ha_doc(folders=['apps/local']), 'a folder has two members'),
            ([(f'{hx.ODOO}.tar', hx.addon_member(compress=False))], hx.ha_doc(), 'member that backup.json does not list'),
        ]
        for members, doc, reason in bad:
            with self.subTest(reason=reason, members=[m[0] for m in members]):
                code, error = self.describe_code(hx.outer_bytes(members, doc))
                self.assertEqual((code, error.details['reason']), ('corrupt-archive', reason))

    def test_backup_json_schema(self):
        odoo = [(f'{hx.ODOO}.tar.gz', hx.addon_member())]
        cases = {
            'type': {'type': 'weekly'}, 'slug': {'slug': '../x'}, 'name': {'name': 'x' * 201},
            'control': {'name': 'a\nb'}, 'date': {'date': 'yesterday'}, 'protected': {'protected': 'yes'},
            'compressed': {'compressed': None}, 'supervisor': {'supervisor_version': None},
            'folders': {'folders': ['../etc']}, 'addons': {'addons': 'all'}, 'extra': {'extra': []},
            'homeassistant': {'homeassistant': 'yes'}, 'repositories': {'repositories': [1]},
        }
        for label, override in cases.items():
            with self.subTest(field=label):
                self.assertEqual(self.describe_code(hx.outer_bytes(odoo, hx.ha_doc(**override)))[0], 'corrupt-archive')
        doc = hx.ha_doc()
        doc['addons'].append(dict(doc['addons'][0]))
        self.assertEqual(self.describe_code(hx.outer_bytes(odoo, doc))[0], 'corrupt-archive')
        old = hx.ha_doc()
        del old['version']
        code, error = self.describe_code(hx.outer_bytes(odoo, old))
        self.assertEqual((code, error.details['version']), ('unsupported-format', 1))
        self.assertEqual(self.describe_code(hx.outer_bytes(odoo, hx.ha_doc(version=3)))[0], 'corrupt-archive')
        self.assertEqual(self.describe_code(hx.outer_bytes(odoo, json_raw=b'{"slug": "a", "slug": "b"}'))[0],
                         'corrupt-archive')
        self.assertEqual(self.describe_code(hx.outer_bytes(odoo, json_raw=b'[1, 2]'))[0], 'corrupt-archive')
        self.assertEqual(self.describe_code(hx.outer_bytes(odoo, json_raw=b' ' * (1024 * 1024 + 1)))[0],
                         'limit-exceeded')
        tolerant = hx.ha_doc(future_key={'x': 1}, crypto='aes128')
        tolerant['addons'][0]['future'] = True
        self.assertEqual(self.describe(hx.outer_bytes(odoo, tolerant)).doc['name'], 'crafted')

    def test_dates_are_normalised_to_utc(self):
        odoo = [(f'{hx.ODOO}.tar.gz', hx.addon_member())]
        for given, expected in (('2026-11-18T17:01:20.5+08:00', '2026-11-18T09:01:20Z'),
                                ('2026-11-18T09:01:20', '2026-11-18T09:01:20Z')):
            self.assertEqual(self.describe(hx.outer_bytes(odoo, hx.ha_doc(date=given))).doc['date'], expected)

    def test_hostile_outer_tars(self):
        member = hx.addon_member()
        self.assertTrue(len(member) % 512, 'the padding case needs padding after the member')
        valid = hx.outer_bytes([(f'{hx.ODOO}.tar.gz', member)])
        (_pax, _name, _t), (odoo_header, odoo_name, _t2) = hx.header_offsets(valid)[:2]
        self.assertEqual(odoo_name, f'{hx.ODOO}.tar.gz')
        broken = bytearray(valid)
        broken[odoo_header + 10] ^= 1  # checksum no longer matches
        trailing = valid + b'\x01' + bytes(511)
        padding = bytearray(valid)
        padding[odoo_header + 512 + len(member)] = 1  # inside the zero padding after the member data
        cases = [
            ('checksum', bytes(broken), 'tar header checksum mismatch'),
            ('trailing data', trailing, 'data after the end-of-archive marker'),
            ('truncated', valid[:odoo_header + 600], 'the backup file is truncated'),
            ('padding', bytes(padding), 'tar padding is not zero'),
            ('directory member', hx.outer_bytes([(f'{hx.ODOO}.tar.gz', member), ('data', b'')],
                                                types={'data': tarfile.DIRTYPE}), 'outer member is not a regular file'),
            ('symlink member', hx.outer_bytes([(f'{hx.ODOO}.tar.gz', member), ('link', b'')],
                                              types={'link': tarfile.SYMTYPE}), 'outer member is not a regular file'),
            ('path', hx.outer_bytes([(f'x/{hx.ODOO}.tar.gz', member)]), 'unexpected member name in the outer tar'),
            ('dotdot', hx.outer_bytes([('../evil.tar.gz', member)]), 'unexpected member name in the outer tar'),
            ('absolute', hx.outer_bytes([('/evil.tar.gz', member)]), 'unexpected member name in the outer tar'),
            ('duplicate', hx.outer_bytes([(f'{hx.ODOO}.tar.gz', member), (f'./{hx.ODOO}.tar.gz', member)]),
             'duplicate member in the outer tar'),
            ('gnu format', hx.outer_bytes([(f'{hx.ODOO}.tar.gz', member)], fmt=tarfile.GNU_FORMAT),
             'outer tar header is not POSIX ustar'),
            ('global header', hx.outer_bytes([(f'{hx.ODOO}.tar.gz', member)], pax_headers={'comment': 'x'}),
             'outer member is not a regular file'),
            ('pax key', hx.outer_bytes([(f'{hx.ODOO}.tar.gz', member)],
                                       member_pax={f'{hx.ODOO}.tar.gz': {'SCHILY.xattr.user.x': 'y'}}),
             'pax record not allowed here'),
            ('sparse', hx.outer_bytes([(f'{hx.ODOO}.tar.gz', member)],
                                      member_pax={f'{hx.ODOO}.tar.gz': {'GNU.sparse.major': '1'}}),
             'sparse files are not supported'),
            ('compressed outer', gzip.compress(valid), 'the outer file is compressed (HA backups are plain tar files)'),
        ]
        for label, data, reason in cases:
            with self.subTest(case=label):
                code, error = self.describe_code(data)
                self.assertEqual((code, error.details['reason']), ('corrupt-archive', reason))
        self.assertEqual(self.describe(valid).members[0].size, len(member))

    def test_member_limits(self):
        many = [(f'{i}.tar.gz', b'x') for i in range(habackup.MAX_OUTER_MEMBERS + 1)]
        code, error = self.describe_code(hx.outer_bytes(many))
        self.assertEqual((code, error.details['reason']), ('limit-exceeded', 'too many members in the outer tar'))

    def test_member_heads_decide_encryption(self):
        plain = hx.addon_member()
        tar_member = hx.addon_member(compress=False)
        v3 = hx.v3_encrypt(plain) if hx.HAVE_NACL else None
        cases = [
            ('gzip in an uncompressed backup', [(f'{hx.ODOO}.tar', plain)], hx.ha_doc(compressed=False), None),
            ('tar in a compressed backup', [(f'{hx.ODOO}.tar.gz', tar_member)], hx.ha_doc(), None),
            ('garbage, unprotected', [(f'{hx.ODOO}.tar.gz', b'\x01' * 4096)], hx.ha_doc(), None),
            ('garbage, protected: v1', [(f'{hx.ODOO}.tar.gz', b'\x01' * 4096)], hx.ha_doc(protected=True), 'v1'),
            ('v1 without whole blocks', [(f'{hx.ODOO}.tar.gz', b'\x01' * 4097)], hx.ha_doc(protected=True), None),
            ('plain, protected', [(f'{hx.ODOO}.tar.gz', plain)], hx.ha_doc(protected=True), 'none'),
        ]
        if v3 is not None:
            cases += [('v3, unprotected', [(f'{hx.ODOO}.tar.gz', v3)], hx.ha_doc(), 'v3'),
                      ('v3 cut', [(f'{hx.ODOO}.tar.gz', v3[:-1])], hx.ha_doc(protected=True), None)]
        for label, members, doc, expected in cases:
            with self.subTest(case=label):
                data = hx.outer_bytes(members, doc)
                if expected is None:
                    self.assertEqual(self.describe_code(data)[0], 'corrupt-archive')
                else:
                    self.assertEqual(self.describe(data).members[0].encryption, expected)
        unsupported = hx.outer_bytes([(f'{hx.ODOO}.tar.gz', b'SecureTar\x07' + bytes(600))], hx.ha_doc(protected=True))
        self.assertEqual(self.describe_code(unsupported)[0], 'unsupported-format')


class MemberStreamTests(TempFiles):
    def walk(self, ha, name, keys=None, select=None):
        with ha.open_member(name, keys) as stream:
            report = habackup.Report()
            names = [entry.name for entry in habackup.iter_entries(stream, select, report)]
            return names, report

    @hx.needs_crypto
    def test_keys(self):
        with habackup.open_backup(hx.fixture('v3_gzip.tar')) as ha:
            self.assertEqual(code_of(ha.open_member, f'{hx.ODOO}.tar.gz')[0], 'key-required')
            self.assertEqual(code_of(ha.open_member, f'{hx.ODOO}.tar.gz', hasecuretar.Keys(hx.WRONG_PASSWORD))[0],
                             'wrong-key')
            names, report = self.walk(ha, f'{hx.ODOO}.tar.gz', hasecuretar.Keys(hx.PASSWORD))
            self.assertTrue(report.complete)
            self.assertIn('data/postgres/PG_VERSION', names)
        with habackup.open_backup(hx.fixture('downloaded_gzip.tar')) as ha:
            names, report = self.walk(ha, f'{hx.ODOO}.tar.gz')  # decrypted add-on: no key needed
            self.assertTrue(report.complete)
            self.assertEqual(code_of(ha.open_member, 'supervisor.tar.gz')[0], 'key-required')
            self.assertEqual(self.walk(ha, 'supervisor.tar.gz', hasecuretar.Keys(hx.PASSWORD))[0],
                             ['mounts.json', 'docker.json'])
        self.assertEqual(code_of(habackup.open_backup, self.dir / 'missing.tar')[0], 'not-found')
        link = self.dir / 'link.tar'
        link.symlink_to(hx.fixture('plain_gzip.tar'))
        self.assertEqual(code_of(habackup.open_backup, link)[0], 'corrupt-archive')

    @hx.needs_crypto
    def test_every_fixture_reads_completely_with_what_was_written(self):
        select = habackup.Select(symlinks=('config/.n8n/nodes', 'data'), hardlinks=True)
        for name, fixture in hx.META['fixtures'].items():
            keys = hasecuretar.Keys(hx.PASSWORD)
            with habackup.open_backup(hx.fixture(name)) as ha:
                for member in ha.layout.members:
                    with self.subTest(fixture=name, member=member.name), ha.open_member(member.name, keys) as stream:
                        report = habackup.Report()
                        got = []
                        for entry in habackup.iter_entries(stream, select, report):
                            data = entry.read_all(1 << 20) if entry.kind == 'file' else None
                            got.append([entry.name, entry.kind, entry.mode, entry.uid, entry.gid, entry.size,
                                        hashlib.sha256(data).hexdigest() if data is not None else None,
                                        entry.linkname])
                        want = [[habackup.normalize(row[0]), *row[1:]] for row in fixture['members'][member.name]['entries']
                                if habackup.normalize(row[0]) not in habackup.NEVER_READ
                                and not (member.role == 'addon' and habackup.normalize(row[0]) == 'addon.json')
                                and row[0] != 'config/.n8n/nodes/node_modules/escape']
                        self.assertEqual(got, want)
                        self.assertTrue(report.complete)
                        if member.role == 'addon':
                            self.assertEqual(report.addon.arch, 'amd64')
                            self.assertEqual(report.secret_files, 2)
                            self.assertIn(report.addon.slug, ('odoo18ce', 'woow-n8n'))

    @hx.needs_crypto
    def test_secrets_never_leave_the_reader(self):
        for name in ('v3_gzip.tar', 'plain_gzip.tar'):
            keys = hasecuretar.Keys(hx.PASSWORD)
            with habackup.open_backup(hx.fixture(name)) as ha:
                for slug in (hx.ODOO, hx.N8N):
                    with ha.open_addon(slug, keys) as stream:
                        report = habackup.Report()
                        seen = []
                        for entry in habackup.iter_entries(stream, None, report):
                            seen.append(entry.name.encode())
                            if entry.kind == 'file':
                                seen.append(entry.read_all(1 << 20))
                        text = repr(report.addon) + json.dumps(report.addon.as_dict()) + repr(report.warnings())
                        blob = b''.join(seen) + text.encode()
                        for secret in hx.SECRETS:
                            self.assertNotIn(secret.encode(), blob, (name, slug, secret))
                        self.assertNotIn(b'data/options.json', b'\n'.join(seen))

    @hx.needs_crypto
    def test_legacy_v1_gzip_trailer(self):
        """securetar <= 2024.11 padded the CRC and ISIZE writes: zlib refuses the plaintext, the reader checks it."""
        data, _info = hx.member_bytes(hx.fixture('v1_gzip.tar'), f'{hx.ODOO}.tar.gz')
        reader = hasecuretar.DecryptReader(io.BytesIO(data), len(data), hasecuretar.Keys(hx.PASSWORD))
        plaintext = b''.join(iter(lambda: reader.read(1 << 20), b''))
        with self.assertRaises((zlib.error, EOFError, OSError)):
            gzip.decompress(plaintext)
        gunzip = habackup._Gunzip(io.BytesIO(plaintext), legacy=True)
        gunzip.finish()
        # The same trailer in a member that is not v1 is refused.
        self.assertEqual(code_of(habackup._Gunzip(io.BytesIO(plaintext), legacy=False).finish)[0], 'corrupt-archive')

    def test_gzip_layer(self):
        raw = hx.tar_bytes([{'name': 'a.txt', 'data': b'hello' * 1000}])
        good = gzip.compress(raw, mtime=0)

        def read(data, legacy=False):
            gunzip = habackup._Gunzip(io.BytesIO(data), legacy=legacy)
            parts = []
            while True:
                part = gunzip.read(4096)
                if not part:
                    return b''.join(parts)
                self.assertLessEqual(len(part), 4096)
                parts.append(part)

        self.assertEqual(read(good), raw)
        bad_crc = good[:-8] + struct.pack('<I', zlib.crc32(raw) ^ 1) + good[-4:]
        bad_size = good[:-4] + struct.pack('<I', len(raw) + 1)
        header = b'\x1f\x8b\x08' + bytes([0x08 | 0x02]) + bytes(6) + b'name.tar\x00'
        header += struct.pack('<H', zlib.crc32(header) & 0xffff)
        body = good[10:]
        self.assertEqual(read(header + body), raw)
        cases = {
            'crc': bad_crc, 'isize': bad_size, 'truncated': good[:-3], 'trailing': good + b'\x00' * 100,
            'not gzip': b'\x1f\x8c' + good[2:], 'reserved flags': good[:3] + b'\xe0' + good[4:],
            'deflate': good[:20] + b'\xff' * 40 + good[60:], 'header crc': header[:-2] + b'\x00\x00' + body,
            'empty': b'',
        }
        for label, data in cases.items():
            with self.subTest(case=label):
                self.assertEqual(code_of(read, data)[0], 'corrupt-archive')

    def test_decompression_is_bounded(self):
        bomb = gzip.compress(hx.tar_bytes([{'name': 'zeros', 'data': bytes(64 * 1024 * 1024)}]), mtime=0)
        self.assertLess(len(bomb), 200_000)
        gunzip = habackup._Gunzip(io.BytesIO(bomb))
        self.assertLessEqual(len(gunzip.read(10 ** 9)), habackup.CHUNK)


class EntryTests(unittest.TestCase):
    def walk(self, entries, select=None, *, addon=False, fmt=tarfile.PAX_FORMAT, raw=None):
        data = raw if raw is not None else hx.tar_bytes(entries, fmt=fmt)
        report = habackup.Report()
        out = []
        for entry in habackup.iter_entries(io.BytesIO(data), select, report, addon=addon):
            out.append((entry.name, entry.kind, entry.linkname, entry.read_all(1 << 20) if entry.kind == 'file' else None))
        return out, report

    def refused(self, entries, select=None, **kwargs):
        try:
            self.walk(entries, select, **kwargs)
        except BackupError as error:
            return error.code, error.details.get('reason')
        raise AssertionError('accepted')

    def test_names_are_normalised(self):
        out, report = self.walk([{'name': '.', 'type': 'dir'}, {'name': './data/', 'type': 'dir'},
                                 {'name': './data/a.txt', 'data': b'a'}, {'name': 'data/b.txt', 'data': b'b'}])
        self.assertEqual([row[0] for row in out], ['.', 'data', 'data/a.txt', 'data/b.txt'])
        self.assertTrue(report.complete)
        self.assertEqual((report.files, report.dirs, report.bytes), (2, 2, 2))

    def test_hostile_names_and_types(self):
        cases = {
            'absolute': [{'name': '/etc/passwd', 'data': b'x'}],
            'dotdot': [{'name': 'data/../../x', 'data': b'x'}],
            'inner dot': [{'name': 'data/./x', 'data': b'x'}],
            'empty component': [{'name': 'data//x', 'data': b'x'}],
            'control': [{'name': 'data/a\nb', 'data': b'x'}],
            'char device': [{'name': 'dev', 'type': 'chr'}],
            'block device': [{'name': 'disk', 'type': 'blk'}],
            'contiguous': [{'name': 'c', 'type': tarfile.CONTTYPE, 'data': b'x'}],
            'sparse pax': [{'name': 's', 'data': b'x', 'pax': {'GNU.sparse.major': '1', 'GNU.sparse.minor': '0'}}],
            'duplicate': [{'name': 'a', 'data': b'1'}, {'name': './a', 'data': b'2'}],
            'below a file': [{'name': 'a', 'data': b'1'}, {'name': 'a/b', 'data': b'2'}],
            'below a symlink': [{'name': 'l', 'type': 'symlink', 'linkname': 'x'}, {'name': 'l/b', 'data': b'2'}],
            'file replaces a directory': [{'name': 'd/x', 'data': b'1'}, {'name': 'd', 'data': b'2'}],
            'root is a file': [{'name': './', 'data': b'x'}],
            'dir with data': [{'name': 'd', 'type': tarfile.DIRTYPE, 'data': b'x' * 10}],
        }
        for label, entries in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.refused(entries)[0], 'corrupt-archive', label)
        self.assertEqual(self.refused([{'name': 'a', 'data': b'x'}], raw=hx.tar_bytes(
            [{'name': 'a', 'data': b'x'}], pax_headers={'comment': 'global'})), ('corrupt-archive',
                                                                               'global pax headers are not supported'))

    def test_structure_errors_in_the_tar_itself(self):
        good = hx.tar_bytes([{'name': 'a', 'data': b'x' * 600}])
        broken = bytearray(good)
        broken[1024 + 3] ^= 1  # the ustar header after the PAX header
        self.assertEqual(self.refused([], raw=bytes(broken)), ('corrupt-archive', 'tar header checksum mismatch'))
        self.assertEqual(self.refused([], raw=good[:1500]), ('corrupt-archive', 'the inner tar is truncated'))
        self.assertEqual(self.refused([], raw=good[:1024 + 512 + 100]), ('corrupt-archive', 'the inner tar is truncated'))
        without_end = good[:1024 + 512 + 1024]
        self.assertEqual(self.refused([], raw=without_end), ('corrupt-archive', 'the inner tar is truncated'))
        self.assertEqual(self.refused([], raw=good + b'\x01'), ('corrupt-archive', 'data after the end-of-archive marker'))
        self.assertEqual(self.refused([], raw=good + bytes(habackup.MAX_TRAILER + 512)),
                         ('corrupt-archive', 'data after the end-of-archive marker'))
        end = 1024 + 512 + 1024  # PAX header + data, the ustar header, 600 bytes of data padded to 1024
        not_double = good[:end] + bytes(512) + b'\x01' + bytes(511)
        self.assertEqual(self.refused([], raw=not_double), ('corrupt-archive', 'data after the end-of-archive marker'))
        v7 = bytearray(hx.tar_bytes([{'name': 'a', 'data': b'x'}], fmt=tarfile.USTAR_FORMAT))
        v7[257:265] = bytes(8)
        self.assertEqual(self.refused([], raw=hx.fix_checksum(v7[:512]) + bytes(v7[512:])),
                         ('corrupt-archive', 'inner tar header is neither POSIX nor GNU ustar'))

    def test_pax_and_gnu_records(self):
        long_name = 'data/' + 'n' * 150 + '/file.txt'
        for fmt in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT):
            with self.subTest(format=fmt):
                out, _report = self.walk([{'name': 'data', 'type': 'dir'},
                                          {'name': 'data/' + 'n' * 150, 'type': 'dir'},
                                          {'name': long_name, 'data': b'long', 'uid': 3_000_000, 'gid': 70},
                                          {'name': 'data/ünicode.txt', 'data': b'u'}])
                self.assertEqual([row[0] for row in out][-2:], [long_name, 'data/ünicode.txt'])
        entries = []
        report = habackup.Report()
        for entry in habackup.iter_entries(io.BytesIO(hx.tar_bytes(
                [{'name': 'big-uid', 'data': b'x', 'uid': 9_000_000, 'gid': 8_000_000, 'mtime': 1794992487.75}],
                fmt=tarfile.GNU_FORMAT)), None, report):
            entries.append((entry.uid, entry.gid, int(entry.mtime)))
        self.assertEqual(entries, [(9_000_000, 8_000_000, 1794992487)])

    def test_symlink_policy(self):
        entries = [{'name': 'nodes', 'type': 'dir'}, {'name': 'nodes/pkg', 'type': 'dir'},
                   {'name': 'nodes/pkg/index.js', 'data': b'js'},
                   {'name': 'nodes/.bin', 'type': 'dir'},
                   {'name': 'nodes/.bin/tool', 'type': 'symlink', 'linkname': '../pkg/index.js'},
                   {'name': 'nodes/escape', 'type': 'symlink', 'linkname': '../outside'},
                   {'name': 'nodes/abs', 'type': 'symlink', 'linkname': '/etc/passwd'},
                   {'name': 'other', 'type': 'symlink', 'linkname': 'nodes/pkg'}]
        out, report = self.walk(entries, habackup.Select(symlinks=('nodes',)))
        self.assertIn(('nodes/.bin/tool', 'symlink', '../pkg/index.js', None), out)
        self.assertEqual(report.skipped_symlinks, 3)
        self.assertEqual(report.skipped_symlink_samples, ['nodes/escape', 'nodes/abs', 'other'])
        self.assertIn('3 個符號連結', report.warnings()[0])
        out, report = self.walk(entries)  # no symlink area: every link is skipped
        self.assertFalse([row for row in out if row[1] == 'symlink'])
        self.assertEqual(report.skipped_symlinks, 4)
        out, _report = self.walk(entries, habackup.Select(symlinks=('.',)))
        self.assertEqual(sorted(row[0] for row in out if row[1] == 'symlink'),
                         ['nodes/.bin/tool', 'nodes/escape', 'other'])  # '.': anything that stays inside the tar

    def test_hardlink_policy(self):
        entries = [{'name': 'a', 'data': b'1'}, {'name': 'b', 'type': 'hardlink', 'linkname': 'a'}]
        self.assertEqual(self.refused(entries), ('corrupt-archive', 'hard link to an entry outside the selection'))
        out, report = self.walk(entries, habackup.Select(hardlinks=True))
        self.assertEqual(out[1], ('b', 'hardlink', 'a', None))
        self.assertEqual(report.hardlinks, 1)
        self.assertEqual(self.refused(entries, habackup.Select(include=('b',), hardlinks=True))[0], 'corrupt-archive')
        later = [{'name': 'b', 'type': 'hardlink', 'linkname': 'a'}, {'name': 'a', 'data': b'1'}]
        self.assertEqual(self.refused(later, habackup.Select(hardlinks=True))[0], 'corrupt-archive')
        escaping = [{'name': 'a', 'data': b'1'}, {'name': 'b', 'type': 'hardlink', 'linkname': '../a'}]
        self.assertEqual(self.refused(escaping, habackup.Select(hardlinks=True))[0], 'corrupt-archive')
        out, _report = self.walk(entries, habackup.Select(include=('a',)))  # an unselected link is ignored
        self.assertEqual([row[0] for row in out], ['a'])

    def test_selection_fifos_and_budgets(self):
        entries = [{'name': 'data', 'type': 'dir'}, {'name': 'data/postgres', 'type': 'dir'},
                   {'name': 'data/postgres/PG_VERSION', 'data': b'16\n'}, {'name': 'data/postgresql.conf', 'data': b'x'},
                   {'name': 'data/postgres/log', 'type': 'dir'}, {'name': 'data/postgres/log/a', 'data': b'l'},
                   {'name': 'data/pipe', 'type': 'fifo'}, {'name': 'config', 'type': 'dir'}]
        out, report = self.walk(entries, habackup.Select(include=('data/postgres',), exclude=('data/postgres/log',)))
        self.assertEqual([row[0] for row in out], ['data/postgres', 'data/postgres/PG_VERSION'])
        self.assertEqual((report.entries, report.skipped_other), (8, 0))
        out, report = self.walk(entries)
        self.assertEqual(report.skipped_other, 1)
        self.assertNotIn('data/pipe', [row[0] for row in out])
        self.assertEqual(self.refused(entries, habackup.Select(max_members=5)),
                         ('limit-exceeded', 'too many entries in an inner tar'))
        self.assertEqual(self.refused(entries, habackup.Select(max_bytes=4)),
                         ('limit-exceeded', 'the selected files are too large'))
        self.assertEqual(self.walk(entries, habackup.Select(include=()))[0], [])

    def test_metadata_files(self):
        addon = json.dumps({'user': {'image': 'ghcr.io/woowtech/woow-ha-n8n-amd64', 'options': {'pw': 'fixture-admin-secret'}},
                            'system': {'slug': 'woow-n8n', 'name': 'n8n'}, 'version': '2.43.6'}).encode()
        entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': addon}, {'name': 'data', 'type': 'dir'},
                   {'name': 'data/options.json', 'data': b'{"pw": "fixture-admin-secret"}'},
                   {'name': 'data/odoo.conf', 'data': b'admin_passwd = fixture-admin-secret'},
                   {'name': 'data/n8n-runners-auth-token', 'data': b'fixture-runner-token'},
                   {'name': 'data/keep.txt', 'data': b'keep'}]
        out, report = self.walk(entries, addon=True)
        self.assertEqual([row[0] for row in out], ['.', 'data', 'data/keep.txt'])
        self.assertEqual(report.secret_files, 3)
        self.assertEqual(report.addon, habackup.AddonInfo('woow-n8n', '2.43.6', 'ghcr.io/woowtech/woow-ha-n8n-amd64',
                                                          'amd64', 'n8n'))
        self.assertNotIn('fixture-admin-secret', repr(report.addon) + repr(out))
        out, report = self.walk(entries, addon=False)  # e.g. the share folder: a file called addon.json is data
        self.assertEqual([row[0] for row in out], ['.', 'addon.json', 'data', 'data/keep.txt'])
        self.assertIsNone(report.addon)
        self.assertEqual(self.refused([{'name': 'data/options.json', 'type': 'dir'}])[0], 'corrupt-archive')
        self.assertEqual(self.refused([{'name': 'addon.json', 'data': b'{"system": 1}'}], addon=True)[0],
                         'corrupt-archive')
        raw = hx.tar_bytes(entries)
        self.assertEqual(habackup.read_addon_info(io.BytesIO(raw)).slug, 'woow-n8n')
        self.assertIsNone(habackup.read_addon_info(io.BytesIO(hx.tar_bytes([{'name': 'x', 'data': b'1'}]))))

    def test_entry_data_ends_with_the_walk(self):
        walk = habackup.iter_entries(io.BytesIO(hx.tar_bytes([{'name': 'a', 'data': b'abc'}, {'name': 'b', 'data': b'd'}])))
        first = next(walk)
        self.assertEqual(first.read(2), b'ab')
        second = next(walk)
        self.assertEqual(second.read_all(10), b'd')
        with self.assertRaises(ValueError):
            first.read(1)
        self.assertEqual(code_of(second.read_all, 0)[0], 'limit-exceeded')
        walk.close()
        self.assertEqual(first.fileobj, first)
        out = io.BytesIO()
        walk = habackup.iter_entries(io.BytesIO(hx.tar_bytes([{'name': 'a', 'data': b'x' * 3_000_000}])))
        self.assertEqual(next(walk).copy_to(out), 3_000_000)

    def test_addon_json_fields(self):
        cases = {
            'ghcr.io/woowtech/woow-ha-odoo-amd64': 'amd64', 'ghcr.io/woowtech/woow-ha-odoo-aarch64': 'aarch64',
            'ghcr.io/woowtech/woow-ha-odoo-amd64:0.4.12': 'amd64', 'ghcr.io/home-assistant/aarch64-addon-x': 'aarch64',
            'ghcr.io/home-assistant/amd64-addon-x@sha256:' + 'a' * 64: 'amd64', 'local/addon-x': 'unknown',
            'ghcr.io/x/armv7-addon': 'unknown', None: 'unknown',
        }
        for image, arch in cases.items():
            with self.subTest(image=image):
                self.assertEqual(habackup.image_arch(image), arch)
        info = habackup.parse_addon_json(json.dumps({'system': {'slug': 'odoo18ce'}, 'user': {'version': '0.4.12'}}).encode())
        self.assertEqual((info.slug, info.version, info.image, info.arch, info.name), ('odoo18ce', '0.4.12', None, 'unknown', ''))
        for bad in (b'[]', b'{"system": {}}', b'{"system": {"slug": "../x"}, "version": "1"}',
                    b'{"system": {"slug": "x"}}', b'{"system": {"slug": "x"}, "version": "1", "user": {"image": "a b"}}',
                    b'not json'):
            with self.subTest(bad=bad[:30]):
                self.assertEqual(code_of(habackup.parse_addon_json, bad)[0], 'corrupt-archive')


@unittest.skipUnless(os.environ.get('WOOWBK_HA_FIXTURES'), 'set WOOWBK_HA_FIXTURES (and WOOWBK_HA_KEY) to read the '
                     'real HA backups made for this feature')
class RealBackupTests(unittest.TestCase):
    """The three backups Supervisor 2026.11.0 made of the WOOWTECH test add-ons (never committed)."""

    NAMES = {'woow-import-test-enc': (True, True), 'woow-import-test-plain': (False, True),
             'woow-import-test-enc-uncompressed': (True, False)}

    @hx.needs_crypto
    def test_members_addons_and_a_full_read(self):
        base = Path(os.environ['WOOWBK_HA_FIXTURES'])
        password = os.environ.get('WOOWBK_HA_KEY')
        for name, (protected, compressed) in self.NAMES.items():
            path = base / name / f'{name}.tar'
            if protected and not password:
                self.skipTest('WOOWBK_HA_KEY is not set')
            with self.subTest(backup=name), habackup.open_backup(path) as ha:
                fd = os.open(path, os.O_RDONLY)
                try:
                    self.assertTrue(habackup.looks_like_ha(fd))
                finally:
                    os.close(fd)
                summary = ha.layout.summary()
                self.assertEqual((summary['protected'], summary['compressed']), (protected, compressed))
                self.assertEqual([m.role for m in ha.layout.members], ['addon', 'addon', 'supervisor'])
                ext = '.tar.gz' if compressed else '.tar'
                self.assertEqual([m.name for m in ha.layout.members],
                                 [f'5e12b5f3_odoo18ce{ext}', f'4b6d58cd_woow-n8n{ext}', f'supervisor{ext}'])
                keys = hasecuretar.Keys(password) if password else None
                slugs = {}
                for member in ha.layout.members:
                    with ha.open_member(member.name, keys) as stream:
                        report = habackup.Report()
                        for entry in habackup.iter_entries(stream, habackup.Select(hardlinks=True), report):
                            if entry.kind == 'file':
                                while entry.read():
                                    pass
                        self.assertTrue(report.complete, member.name)
                        if member.role == 'addon':
                            slugs[report.addon.slug] = (report.addon.arch, report.addon.version)
                            self.assertEqual(report.secret_files, 2)
                self.assertEqual(slugs, {'odoo18ce': ('amd64', '0.4.12'), 'woow-n8n': ('amd64', '2.43.6')})


if __name__ == '__main__':
    unittest.main()
