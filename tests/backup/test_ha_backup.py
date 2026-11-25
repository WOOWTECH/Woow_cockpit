"""Home Assistant backup files (habackup.py, team E1): recognition, the outer description, member streams (decrypt +
gunzip), the inner-tar walk and addon.json -- on real-securetar fixtures and crafted hostile tars.

The reader takes what HAOS takes (HAOS parity 2026-11-25, DESIGN section D; row ids as in the block inventory): one bad
entry is skipped, one bad member stops one app, only an unusable outer tar or backup.json stops the file. What protects
against hostile and damaged files stays and is tested here too.

RealBackupTests reads the real HA backups made for this feature when WOOWBK_HA_FIXTURES names their directory (and
WOOWBK_HA_KEY holds their key); they are never committed.
"""
import gzip
import hashlib
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zlib
from pathlib import Path
from unittest import mock

from woowbackup import habackup, hasecuretar, hastore
from woowbackup.errors import BackupError

from . import hafixtures as hx
from .test_archive import fake_archive_bytes


def code_of(callable_, *args, **kwargs):
    try:
        callable_(*args, **kwargs)
    except BackupError as error:
        return error.code, error
    raise AssertionError('no BackupError')


MEMBER_MESSAGES = {'corrupt-archive': hasecuretar.MEMBER_MESSAGE, 'limit-exceeded': habackup.MEMBER_LIMIT_MESSAGE}
FILE_MESSAGES = {'corrupt-archive': hasecuretar.CORRUPT_MESSAGE, 'limit-exceeded': habackup.LIMIT_MESSAGE}


def say_member(test, error):
    """The problem of one member says so (detail `scope`, the zh-TW text of one member that is left out) and does not
    end the job: only the app of that member stops (DESIGN C1)."""
    test.assertEqual((error.details['scope'], error.message), ('member', MEMBER_MESSAGES[error.code]))
    test.assertIsNot(getattr(error, 'job_wide', False), True)


def say_file(test, error):
    """A problem of the whole file has no scope and the text of a file that is refused."""
    test.assertEqual((error.details.get('scope'), error.message), (None, FILE_MESSAGES[error.code]))


def count_lines(function, *args):
    """(result, the number of source lines `function` executed while it ran): a cost that does not depend on the machine,
    for code whose cost is the point (a crafted input must not make it loop once per byte)."""
    code, lines = function.__code__, [0]

    def local(_frame, event, _arg):
        lines[0] += event == 'line'
        return local

    def trace(frame, _event, _arg):
        return local if frame.f_code is code else None
    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        result = function(*args)
    finally:
        sys.settrace(previous)
    return result, lines[0]


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

    def refused(self, data, code, reason):
        got, error = self.describe_code(data)
        self.assertEqual((got, error.details['reason']), (code, reason))
        say_file(self, error)

    def problems(self, data):
        """{add-on slug: problem} of a backup that is taken."""
        return {addon['slug']: addon.get('problem') for addon in self.describe(data).summary()['addons']}

    def read_addon(self, data, slug, keys=None):
        """(names, report) of a whole walk over one add-on."""
        with habackup.open_backup(data if isinstance(data, Path) else self.write(data)) as ha:
            with ha.open_addon(slug, keys) as stream:
                report = habackup.Report()
                names = [entry.name for entry in habackup.iter_entries(stream, habackup.Select(hardlinks=True), report)]
                return names, report


class RecognitionTests(TempFiles):
    def test_ha_backups_are_recognised(self):
        for name in hx.META['fixtures']:
            with self.subTest(fixture=name):
                self.assertTrue(habackup.looks_like_ha(self.fd(hx.fixture(name))))
        self.assertTrue(habackup.looks_like_ha(self.fd(hx.simple_backup())))
        old_name = hx.outer_bytes([(f'{hx.ODOO}.tar.gz', hx.addon_member())], hx.ha_doc(), json_name='backup.json',
                                  json_first=True)
        self.assertTrue(habackup.looks_like_ha(self.fd(old_name)), 'backup.json first and without ./ (older backups)')

    def test_what_supervisor_takes_is_recognised(self):
        """UP-30 (no supervisor_version before 2022.08), UP-03 (repacked), UP-24 (snapshot.json)."""
        doc = hx.ha_doc()
        del doc['supervisor_version']
        odoo = [(f'{hx.ODOO}.tar.gz', hx.addon_member())]
        for label, data in (('no supervisor_version', hx.outer_bytes(odoo, doc)),
                            ('GNU tar', hx.outer_bytes(odoo, fmt=tarfile.GNU_FORMAT)),
                            ('snapshot.json', hx.outer_bytes(odoo, doc, json_name='./snapshot.json')),
                            ('an older doc before the real one', hx.outer_bytes(
                                [*odoo, ('snapshot.json', b'{"mine": 1}')])),
                            ('backup.json of 2 MiB', hx.outer_bytes(odoo, hx.ha_doc(extra={'x': 'y' * 2 ** 21})))):
            with self.subTest(case=label):
                self.assertTrue(habackup.looks_like_ha(self.fd(data)))
                self.describe(data)

    def test_other_files_are_not(self):
        cockpit_v2 = hx.tar_bytes([{'name': 'backup.json', 'data': json.dumps({'format': 2}).encode()},
                                   {'name': 'README.txt', 'data': b'x'}])
        no_json = hx.tar_bytes([{'name': f'{hx.ODOO}.tar.gz', 'data': hx.addon_member()}])
        ha_like_doc = json.dumps({'slug': 'x', 'name': 'x'}).encode()
        without_version = hx.outer_bytes([], json_raw=ha_like_doc)
        cockpit_doc = json.dumps({'backup_id': 'x', 'slug': 'x', 'name': 'x', 'date': 'x', 'type': 'full'}).encode()
        too_large = hx.outer_bytes([], hx.ha_doc((), extra={'x': 'y' * habackup.MAX_BACKUP_JSON}))
        for label, data in (('cockpit format 2', cockpit_v2), ('cockpit format 1', fake_archive_bytes()),
                            ('random', os.urandom(4096)), ('gzip outer', gzip.compress(hx.simple_backup())),
                            ('no backup.json', no_json), ('not enough of a doc', without_version),
                            ('a doc with a Cockpit backup_id', hx.outer_bytes([], json_raw=cockpit_doc)),
                            ('backup.json too large', too_large),
                            ('a snapshot.json that is none', hx.outer_bytes([], json_raw=b'{"mine": 1}',
                                                                            json_name='snapshot.json')),
                            ('empty', b''), ('zeros', bytes(10240))):
            with self.subTest(case=label):
                self.assertFalse(habackup.looks_like_ha(self.fd(data)))

    def test_what_is_no_regular_file(self):
        """UP-01 (kept): a folder, a pipe or a device is no backup and is never read."""
        pipe = self.dir / 'pipe'
        os.mkfifo(pipe)
        for path, flags in ((self.dir, os.O_RDONLY), (pipe, os.O_RDWR), ('/dev/zero', os.O_RDONLY)):
            fd = os.open(path, flags)
            self.addCleanup(os.close, fd)
            with self.subTest(path=str(path)), mock.patch.object(os, 'pread', side_effect=AssertionError('read')):
                self.assertFalse(habackup.looks_like_ha(fd))
                code, error = code_of(habackup.describe, fd)
                self.assertEqual((code, error.details['reason']), ('corrupt-archive', 'not a regular file'))

    def test_a_description_that_is_too_large_is_never_read(self):
        """UP-21: a name is no reason to read a member of any size into memory."""
        for name in ('./backup.json', './snapshot.json'):
            path = self.write(hx.raw_header(name, size=habackup.MAX_BACKUP_JSON + 1))
            os.truncate(path, 512 + habackup.MAX_BACKUP_JSON + 512 + 1024)  # (sparse)
            reads = []
            real = os.pread

            def pread(fd, n, offset):
                reads.append(n)
                return real(fd, n, offset)
            fd = self.fd(path)
            with self.subTest(name=name), mock.patch.object(os, 'pread', pread):
                self.assertFalse(habackup.looks_like_ha(fd))
                code, error = code_of(habackup.describe, fd)
                self.assertEqual((code, error.details['reason']), ('limit-exceeded', 'backup.json too large'))
                say_file(self, error)
                self.assertLess(sum(reads), 10_000)

    def test_a_description_of_too_many_pieces_is_never_parsed(self):
        """UP-21: a few bytes of JSON take many times as much memory; commas and brackets are counted first."""
        doc = json.dumps(dict(hx.ha_doc([]), extra={'x': [[], {}] * 50})).encode()
        items = doc.count(b',') + doc.count(b'[') + doc.count(b'{')
        fd = self.fd(hx.outer_bytes([], json_raw=doc))
        with mock.patch.object(habackup, 'MAX_JSON_ITEMS', items):
            self.assertTrue(habackup.looks_like_ha(fd))
            self.assertEqual(habackup.describe(fd).doc['name'], 'crafted')
        with mock.patch.object(habackup, 'MAX_JSON_ITEMS', items - 1), \
                mock.patch.object(habackup.util, 'loads_strict', side_effect=AssertionError('parsed')):
            self.assertFalse(habackup.looks_like_ha(fd))
            code, error = code_of(habackup.describe, fd)
            self.assertEqual((code, error.details['reason']), ('limit-exceeded', 'backup.json too large'))
            say_file(self, error)
            addon = b'{"system":{"slug":"x"},"version":"1"}'
            code, error = code_of(habackup.parse_addon_json, addon[:-1] + b',"y":[' + b','.join([b'[]'] * items) + b']}')
            self.assertEqual((code, error.details['reason']), ('limit-exceeded', 'addon.json too large'))
            say_member(self, error)  # an add-on's own file: only that add-on
        self.assertTrue(1000 * 400 < habackup.MAX_JSON_ITEMS <= 10 ** 6, 'the largest real one has 400')

    def test_positions_beyond_the_file(self):
        fd = self.fd(b'x' * 1000)
        for call in (lambda o: o.skip(1001), lambda o: o.read_exact(1001), lambda o: (o.skip(1000), o.skip(1))):
            with self.assertRaises(habackup._Truncated):
                call(habackup._Outer(fd, 1000))
        outer = habackup._Outer(fd, 1000)
        outer.skip(999)
        self.assertEqual(outer.read_exact(1), b'x')


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
                self.assertFalse([a for a in summary['addons'] if 'problem' in a])
                self.assertEqual({m.name: m.encryption for m in layout.members},
                                 {member: info['encryption'] for member, info in fixture['members'].items()})
                self.assertEqual((summary['size'], layout.ignored_count), (fixture['size'], 0))

    def test_a_decrypted_download_says_unprotected_but_keeps_supervisor_encrypted(self):
        layout = self.describe(hx.fixture('downloaded_gzip.tar'))
        self.assertFalse(layout.doc['protected'])
        self.assertEqual([(m.role, m.encryption) for m in layout.members],
                         [('addon', 'none'), ('addon', 'none'), ('folder', 'none'), ('supervisor', 'v3')])
        self.assertEqual(layout.addon(hx.ODOO).name, f'{hx.ODOO}.tar.gz')

    def test_members_backup_json_lists(self):
        """UP-48, UP-49, UP-50: what is not listed is stepped over, what is missing stops only itself."""
        odoo = (f'{hx.ODOO}.tar.gz', hx.addon_member())
        empty = hx.tar_bytes([{'name': '.', 'type': 'dir'}], compress=True)
        share, core = ('share.tar.gz', empty), ('homeassistant.tar.gz', empty)
        legacy, apps = ('addons_local.tar.gz', empty), ('apps_local.tar.gz', empty)
        cases = [  # (members, doc, the members taken, what was stepped over)
            ([odoo, share], hx.ha_doc(folders=['share']), [odoo[0], share[0]], []),
            ([core, odoo], hx.ha_doc(homeassistant={'version': '2026.7.4', 'exclude_database': False, 'size': 0.0}),
             [core[0], odoo[0]], []),
            ([odoo, legacy], hx.ha_doc(folders=['addons/local']), [odoo[0], legacy[0]], []),
            ([odoo, apps], hx.ha_doc(folders=['apps/local']), [odoo[0], apps[0]], []),
            ([odoo], hx.ha_doc(folders=['homeassistant']), [odoo[0]], []),  # a v1 artefact Supervisor drops
            ([odoo, share], hx.ha_doc(), [odoo[0]], [('unlisted', share[0])]),
            ([odoo, core], hx.ha_doc(), [odoo[0]], [('unlisted', core[0])]),
            ([odoo, ('media.tar.gz', b'anything')], hx.ha_doc(), [odoo[0]], [('unlisted', 'media.tar.gz')]),
            ([odoo, legacy, apps], hx.ha_doc(folders=['apps/local']), [odoo[0], legacy[0]], [('second-folder', apps[0])]),
            ([odoo, apps, legacy], hx.ha_doc(folders=['apps/local']), [odoo[0], apps[0]], [('second-folder', legacy[0])]),
            ([odoo], hx.ha_doc(folders=['share', 'media']), [odoo[0]], []),
            ([odoo], hx.ha_doc(homeassistant={'version': '2026.7.4'}), [odoo[0]], []),
        ]
        for members, doc, taken, ignored in cases:
            with self.subTest(members=[m[0] for m in members], folders=doc['folders']):
                layout = self.describe(hx.outer_bytes(members, doc))
                self.assertEqual([m.name for m in layout.members], taken)
                self.assertEqual((list(layout.ignored), layout.ignored_count), (ignored, len(ignored)))
                self.assertEqual([m.problem for m in layout.members], [None] * len(taken))

    def test_an_addon_without_its_member(self):
        """UP-50: only that add-on is left out."""
        plain_name = [(f'{hx.ODOO}.tar', hx.addon_member(compress=False)), (f'{hx.N8N}.tar.gz', hx.addon_member('woow-n8n'))]
        for label, data in (('gone', hx.outer_bytes([(f'{hx.N8N}.tar.gz', hx.addon_member('woow-n8n'))],
                                                    hx.ha_doc([hx.ODOO, hx.N8N]))),
                            ('the other suffix', hx.outer_bytes(plain_name, hx.ha_doc([hx.ODOO, hx.N8N]))),
                            ('nothing but backup.json', hx.outer_bytes([], hx.ha_doc([hx.ODOO])))):
            with self.subTest(case=label):
                layout = self.describe(data)
                odoo = layout.summary()['addons'][0]
                self.assertEqual((odoo['slug'], odoo['problem'], odoo['member'], odoo['size'], odoo['encryption']),
                                 (hx.ODOO, 'missing', None, 0, 'none'))
                code, error = code_of(layout.addon, hx.ODOO)
                self.assertEqual((code, error.details['problem']), ('not-found', 'missing'))
                self.assertEqual(code_of(layout.addon, 'x_y')[1].message, '這份 HA 備份沒有這個附加元件。')
        self.assertEqual(self.read_addon(hx.outer_bytes(plain_name, hx.ha_doc([hx.ODOO, hx.N8N])), hx.N8N)[1].addon.slug,
                         'woow-n8n', 'the other add-on is read as ever')

    def test_a_name_there_twice(self):
        """UP-19: which one is real is not known, so the add-on is not used; backup.json twice refuses the file."""
        odoo, n8n = (f'{hx.ODOO}.tar.gz', hx.addon_member()), (f'{hx.N8N}.tar.gz', hx.addon_member('woow-n8n'))
        for second in (odoo[0], f'./{odoo[0]}'):
            with self.subTest(second=second):
                data = hx.outer_bytes([odoo, n8n, (second, b'other')], hx.ha_doc([hx.ODOO, hx.N8N]))
                self.assertEqual(self.problems(data), {hx.ODOO: 'duplicate', hx.N8N: None})
                code, error = code_of(self.read_addon, data, hx.ODOO)
                self.assertEqual((code, error.details['scope'], error.details['problem']),
                                 ('corrupt-archive', 'member', 'duplicate'))
                self.assertTrue(self.read_addon(data, hx.N8N)[1].complete)
        share = hx.outer_bytes([odoo, ('share.tar.gz', b'a'), ('share.tar.gz', b'b')], hx.ha_doc(folders=['share']))
        self.assertEqual([(m.name, m.problem) for m in self.describe(share).members],
                         [(odoo[0], None), ('share.tar.gz', 'duplicate')])
        unlisted = hx.outer_bytes([odoo, ('x', b'a'), ('x', b'b')])
        self.assertEqual(self.describe(unlisted).ignored, (('unlisted', 'x'),))
        twice = hx.outer_bytes([odoo, ('backup.json', json.dumps(hx.ha_doc()).encode())])
        self.refused(twice, 'corrupt-archive', 'backup.json is in the file twice')

    def test_backup_json_that_cannot_be_used(self):
        """The rows that keep refusing the whole file (HAOS refuses them too, or the list cannot be trusted)."""
        odoo = [(f'{hx.ODOO}.tar.gz', hx.addon_member())]
        reasons = {
            'type': ({'type': 'weekly'}, 'backup.json type is invalid'),
            'type of another kind': ({'type': ['full']}, 'backup.json type is invalid'),
            'version 3': ({'version': 3}, 'backup.json version is not supported'),
            'version 0': ({'version': 0}, 'backup.json version is not supported'),
            'version text': ({'version': 'two'}, 'backup.json version is not supported'),
            'version null': ({'version': None}, 'backup.json version is not supported'),
            'version list': ({'version': [2]}, 'backup.json version is not supported'),
            'version infinite': ({'version': 1e999}, None),
            'folder name': ({'folders': ['../etc']}, 'backup.json folder is invalid'),
            'folder type': ({'folders': [1]}, 'backup.json folder is invalid'),
            'folder twice': ({'folders': ['share', 'share']}, 'backup.json lists a folder twice'),
            'folder twice by its old name': ({'folders': ['apps/local', 'addons/local']},
                                             'backup.json lists a folder twice'),
            'folders no list': ({'folders': 'share'}, 'backup.json folders must be a list'),
            'addons no list': ({'addons': 'all'}, 'backup.json addons must be a list'),
            'addons null': ({'addons': None}, 'backup.json addons must be a list'),
            'addon no object': ({'addons': ['x']}, 'backup.json addon is not an object'),
            'extra': ({'extra': []}, 'backup.json extra must be an object'),
            'repositories': ({'repositories': [1]}, 'backup.json repositories must be a list of text'),
        }
        for label, (override, reason) in reasons.items():
            with self.subTest(field=label):
                self.refused(hx.outer_bytes(odoo, dict(hx.ha_doc(), **override)), 'corrupt-archive',
                             reason or 'backup.json is not strict JSON')  # None: Infinity is not strict JSON
        doc = hx.ha_doc()
        doc['addons'].append(dict(doc['addons'][0]))
        self.refused(hx.outer_bytes(odoo, doc), 'corrupt-archive', 'backup.json lists an add-on twice')
        for raw in (b'{"slug": "a", "slug": "b"}', b'not json', b'\xff\xfe{}', b'{"version": NaN}',
                    json.dumps(hx.ha_doc()).encode('utf-16')):
            with self.subTest(raw=raw[:20]):
                self.refused(hx.outer_bytes(odoo, json_raw=raw), 'corrupt-archive', 'backup.json is not strict JSON')
        self.refused(hx.outer_bytes(odoo, json_raw=b'[1, 2]'), 'corrupt-archive', 'backup.json is not an object')
        self.refused(hx.tar_bytes([{'name': odoo[0][0], 'data': odoo[0][1]}]), 'corrupt-archive', 'backup.json is missing')
        tolerant = hx.ha_doc(future_key={'x': 1}, crypto='aes128')
        tolerant['addons'][0]['future'] = True
        self.assertEqual(self.describe(hx.outer_bytes(odoo, tolerant)).doc['name'], 'crafted')

    ODD = {'empty': '', 'long': 'x' * 5000, 'control': 'a\nb\x00c\x7f', 'bidi': 'a\u202eb\u2066c\u200fd\ufeff',
           'surrogate': '\ud800x', 'number': 7, 'float': 1.5, 'list': ['x'], 'object': {'x': 1}, 'null': None, 'true': True}

    def test_display_fields_never_refuse(self):
        """UP-26, UP-27, UP-28, UP-30, UP-36, UP-37, UP-38, UP-42: shown only, so cleaned and cut."""
        odoo, n8n = (f'{hx.ODOO}.tar.gz', hx.addon_member()), (f'{hx.N8N}.tar.gz', hx.addon_member('woow-n8n'))
        limits = {'slug': 64, 'name': 200, 'date': None, 'supervisor_version': 64, 'homeassistant': None}
        for field, limit in limits.items():
            for label, value in self.ODD.items():
                with self.subTest(field=field, value=label):
                    layout = self.describe(hx.outer_bytes([odoo, n8n], hx.ha_doc([hx.ODOO, hx.N8N], **{field: value})))
                    self.assertEqual([m.problem for m in layout.members], [None, None])
                    got = layout.doc[field]
                    if limit is None:
                        self.assertIsNone(got)
                    else:
                        self.assertLessEqual(len(got), limit)
                        self.assertTrue(got.isprintable() or got == '', repr(got))
                        self.assertEqual(got, {'empty': '', 'long': 'x' * limit, 'control': 'a b c',
                                               'bidi': 'a b c d', 'surrogate': 'x',
                                               'number': '7' if field == 'supervisor_version' else '',
                                               'float': '1.5' if field == 'supervisor_version' else ''}.get(label, ''))
        for field in ('slug', 'name', 'date', 'supervisor_version', 'homeassistant'):
            doc = hx.ha_doc()
            del doc[field]
            with self.subTest(absent=field):
                self.assertFalse(self.describe(hx.outer_bytes([odoo], doc)).doc[field])
        for field, limit in (('name', 200), ('version', 64), ('size', None)):
            for label, value in self.ODD.items():
                with self.subTest(addon_field=field, value=label):
                    doc = hx.ha_doc([hx.ODOO, hx.N8N])
                    doc['addons'][1][field] = value
                    addons = self.describe(hx.outer_bytes([odoo, n8n], doc)).summary()['addons']
                    self.assertEqual([a['slug'] for a in addons], [hx.ODOO, hx.N8N])
                    self.assertNotIn('problem', addons[1])
                    if limit:
                        self.assertLessEqual(len(addons[1][field]), limit)
                        self.assertTrue(addons[1][field].isprintable())
                    if field == 'name':
                        self.assertTrue(addons[1]['name'], 'a name that cannot be shown: the slug')
        self.assertEqual(self.describe(hx.outer_bytes([odoo], hx.ha_doc(homeassistant={'version': '2026.7.4\n'})))
                         .doc['homeassistant'], {'version': '2026.7.4'})

    def test_dates(self):
        """UP-28: UTC, else None (the page says so and sorts by the upload time)."""
        odoo = [(f'{hx.ODOO}.tar.gz', hx.addon_member())]
        for given, expected in (('2026-11-18T17:01:20.5+08:00', '2026-11-18T09:01:20Z'),
                                ('2026-11-18T09:01:20', '2026-11-18T09:01:20Z'), ('2026-11-18', '2026-11-18T00:00:00Z'),
                                ('yesterday', None), ('2026-13-40T00:00:00', None), ('0001-01-01T00:00:00+14:00', None),
                                ('0001-01-01T00:00:00', None), ('9999-12-31T23:59:59-14:00', None),
                                ('2026-11-18T09:01:20\n', None), ('2' * 65, None)):
            with self.subTest(date=given):
                self.assertEqual(self.describe(hx.outer_bytes(odoo, hx.ha_doc(date=given))).doc['date'], expected)

    def test_an_addon_whose_slug_names_nothing(self):
        """UP-34: only that add-on is left out, and under its made-up slug it can never pass for an app of ours."""
        odoo = (f'{hx.ODOO}.tar.gz', hx.addon_member())
        for label, slug in {**self.ODD, 'path': '../x_odoo18ce', 'app': 'x/y_odoo18ce', 'space': 'x y_odoo18ce',
                            'dash': '-x_odoo18ce'}.items():
            if label == 'long':
                slug = 'x' * 101
            with self.subTest(slug=label):
                doc = hx.ha_doc([hx.ODOO])
                doc['addons'].insert(0, {'slug': slug, 'name': 'Other', 'version': '1'})
                layout = self.describe(hx.outer_bytes([odoo], doc))
                bad, good = layout.summary()['addons']
                self.assertEqual((bad['slug'], bad['name'], bad['problem'], bad['member']),
                                 ('invalid-1', 'Other', 'bad-slug', None))
                self.assertEqual((good['slug'], good.get('problem')), (hx.ODOO, None))
                self.assertIsNone(hastore.importable_app(bad['slug']))
                self.assertEqual(code_of(layout.addon, 'invalid-1')[1].details['problem'], 'bad-slug')
        doc = hx.ha_doc([hx.ODOO])
        doc['addons'].append({'slug': '../x_odoo18ce', 'name': 'Other', 'version': '1'})
        layout = self.describe(hx.outer_bytes([odoo, ('invalid-1.tar.gz', hx.addon_member())], doc))
        self.assertEqual(([m.name for m in layout.members], layout.ignored), ([odoo[0]], (('unlisted', 'invalid-1.tar.gz'),)))
        doc = hx.ha_doc([hx.ODOO, 'invalid-1'])
        doc['addons'] += [{'slug': '/a\n', 'name': '', 'version': ''}, {'slug': None}, {'slug': '/a\n'}, {}]
        addons = self.describe(hx.outer_bytes([odoo], doc)).summary()['addons']
        self.assertEqual([(a['slug'], a['name'], a['problem']) for a in addons[1:]],
                         [('invalid-1', 'name of invalid-1', 'missing'), ('invalid-2', '/a', 'bad-slug'),
                          ('invalid-3', '（沒有名稱的附加元件）', 'bad-slug'), ('invalid-4', '/a', 'bad-slug'),
                          ('invalid-5', '（沒有名稱的附加元件）', 'bad-slug')])

    def test_an_addon_cannot_take_the_place_of_home_assistants_parts(self):
        empty = hx.tar_bytes([{'name': '.', 'type': 'dir'}], compress=True)
        members = [(f'{stem}.tar.gz', empty) for stem in ('share', 'homeassistant', 'supervisor')]
        doc = hx.ha_doc(['share', 'homeassistant', 'supervisor'], folders=['share'], homeassistant={'version': '1'})
        data = hx.outer_bytes(members, doc)
        self.assertEqual([m.role for m in self.describe(data).members], ['folder', 'homeassistant', 'supervisor'])
        self.assertEqual(set(self.problems(data).values()), {'missing'})

    def test_protected_and_compressed_that_are_no_booleans(self):
        """UP-31, like Supervisor's validate.py (v1_protected, the defaults); the members' first bytes still decide."""
        packed = [(f'{hx.ODOO}.tar.gz', hx.addon_member()), (f'{hx.N8N}.tar.gz', hx.addon_member('woow-n8n'))]
        plain = [(f'{hx.ODOO}.tar', hx.addon_member(compress=False)),
                 (f'{hx.N8N}.tar', hx.addon_member('woow-n8n', compress=False))]
        for value in ('yes', 'sha256$abc', 1, 0, None, [], 'absent'):
            doc = hx.ha_doc([hx.ODOO, hx.N8N], protected=value)
            if value == 'absent':
                del doc['protected']
            with self.subTest(protected=value):
                self.assertEqual(self.describe(hx.outer_bytes(packed, doc)).doc['protected'], value != 'absent')
        legacy = [(f'{hx.ODOO}.tar.gz', b'\x01' * 4096)]
        self.assertEqual(self.describe(hx.outer_bytes(legacy, hx.ha_doc(protected='old'))).members[0].encryption, 'v1')
        for value in ('yes', 1, 0, None, [], 'absent'):
            for members, expected in ((packed, True), (plain, False), (packed[:1] + plain[1:], True), ([], True)):
                doc = hx.ha_doc([hx.ODOO, hx.N8N], compressed=value)
                if value == 'absent':
                    del doc['compressed']
                with self.subTest(compressed=value, members=[m[0] for m in members]):
                    layout = self.describe(hx.outer_bytes(members, doc))
                    self.assertIs(layout.doc['compressed'], expected)
                    self.assertEqual([m.problem for m in layout.members], [None] * len(layout.members))

    def test_version_1(self):
        """UP-24: the rules of Supervisor's validate.py; the add-ons' archives are the same as in version 2."""
        doc = {'slug': 'abcd1234', 'name': 'Old snapshot', 'date': '2021-03-01T01:02:03.000000+00:00', 'type': 'full',
               'homeassistant': {'version': '2021.2.3', 'ssl': False, 'port': 8123}, 'protected': 'sha256$2$x',
               'crypto': 'aes128',
               'addons': [{'slug': hx.ODOO, 'name': 'Odoo', 'version': '0.1', 'size': 1.5}],
               'folders': ['share', 'homeassistant', 'ssl', 'addons/local'], 'repositories': ['https://example.com/x']}
        empty = hx.tar_bytes([{'name': '.', 'type': 'dir'}], compress=True)
        members = [(f'./{stem}.tar.gz', empty) for stem in ('homeassistant', 'share', 'ssl', 'addons_local')]
        members.append((f'./{hx.ODOO}.tar.gz', hx.addon_member()))
        for name in ('./snapshot.json', './backup.json'):
            with self.subTest(name=name):
                data = hx.outer_bytes(members, doc, json_name=name)
                layout = self.describe(data)
                self.assertEqual((layout.doc['version'], layout.doc['protected'], layout.doc['compressed'],
                                  layout.doc['supervisor_version'], layout.doc['folders']),
                                 (1, True, True, '', ['share', 'ssl', 'apps/local']))
                self.assertEqual([(m.role, m.slug, m.problem) for m in layout.members],
                                 [('homeassistant', None, None), ('folder', 'share', None), ('folder', 'ssl', None),
                                  ('folder', 'apps/local', None), ('addon', hx.ODOO, None)])
                self.assertEqual(self.read_addon(data, hx.ODOO)[1].addon.slug, 'odoo18ce')
        for value, version in ((1, 1), (2, 2), ('1', 1), ('2', 2), (2.0, 2), (True, 1)):
            with self.subTest(version=value):
                self.assertEqual(self.describe(hx.outer_bytes(members, dict(doc, version=value))).doc['version'], version)
        both = hx.outer_bytes([*members, ('./snapshot.json', json.dumps(dict(doc, name='second')).encode())], doc)
        self.assertEqual(self.describe(both).doc['name'], 'Old snapshot', 'backup.json wins')

    @hx.needs_cryptography
    def test_a_version_1_backup_with_a_password(self):
        """The oldest encrypted members (no header), described by a version 1 snapshot.json."""
        raw, _info = hx.member_bytes(hx.fixture('v1_gzip.tar'), f'{hx.ODOO}.tar.gz')
        doc = {'slug': 'abcd1234', 'name': 'Old', 'date': '2021-03-01T01:02:03+00:00', 'type': 'partial',
               'protected': 'sha256$x', 'addons': [{'slug': hx.ODOO, 'name': 'Odoo', 'version': '0.1'}]}
        data = hx.outer_bytes([(f'./{hx.ODOO}.tar.gz', raw)], doc, json_name='./snapshot.json')
        self.assertEqual(self.describe(data).members[0].encryption, 'v1')
        self.assertEqual(code_of(self.read_addon, data, hx.ODOO)[0], 'key-required')
        names, report = self.read_addon(data, hx.ODOO, hasecuretar.Keys(hx.PASSWORD))
        self.assertIn('data/postgres/PG_VERSION', names)
        self.assertTrue(report.complete)


class OuterTarTests(TempFiles):
    """The outer tar: any dialect is read, what is not a member is stepped over, nothing is ever followed or written."""

    def setUp(self):
        super().setUp()
        self.member = hx.addon_member()
        self.doc = json.dumps(hx.ha_doc()).encode()

    def backup(self, *before, member=None, doc=None, after=hx.END, name=f'{hx.ODOO}.tar.gz'):
        """Raw blocks, then the Odoo add-on and backup.json (POSIX headers), then the end of the archive."""
        return b''.join([*before, hx.raw_member(name, self.member) if member is None else member,
                         hx.raw_member('./backup.json', self.doc if doc is None else doc), after])

    def taken(self, data, ignored=()):
        layout = self.describe(data)
        self.assertEqual([(m.name, m.problem) for m in layout.members], [(f'{hx.ODOO}.tar.gz', None)])
        self.assertEqual(list(layout.ignored), list(ignored))
        self.assertTrue(habackup.looks_like_ha(self.fd(data)))
        names, report = self.read_addon(data, hx.ODOO)
        self.assertTrue(report.complete)
        self.assertIn('data/hello.txt', names)

    def test_every_dialect(self):
        """UP-03: POSIX, GNU, v7 and tarfile's formats; a regular file by any of its types; UP-14: a link name."""
        name, member, doc = f'{hx.ODOO}.tar.gz', self.member, self.doc
        for magic in (hx.USTAR, hx.GNU, hx.V7, b'ustar\x00  ', b'ustar\x00\x00\x00'):
            for typeflag in (b'0', b'\0', b'7'):
                with self.subTest(magic=magic, typeflag=typeflag):
                    self.taken(hx.raw_member(name, member, magic=magic, typeflag=typeflag)
                               + hx.raw_member('./backup.json', doc, magic=magic, typeflag=typeflag) + hx.END)
        for fmt in (tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
            with self.subTest(format=fmt):
                self.taken(hx.outer_bytes([(name, member)], fmt=fmt))
        self.taken(self.backup(member=hx.raw_member(name, member, linkname='/etc/passwd')))
        self.refused(self.backup(hx.raw_member('x', b'', magic=b'abcdefgh')), 'corrupt-archive',
                     'tar header is neither POSIX, GNU nor v7')

    def test_long_names_and_unknown_pax_records(self):
        """UP-08: GNU tar, bsdtar and macOS tar write more records than tarfile does; they are ignored."""
        slug = '5e12b5f3_' + 'x' * 91
        name = f'{slug}.tar.gz'
        doc = json.dumps(hx.ha_doc([slug])).encode()
        for label, head in (
                ('GNU long name', hx.raw_member('././@LongLink', name.encode() + b'\0', typeflag=b'L', magic=hx.GNU)),
                ('PAX path', hx.pax_member({'path': name})), ('Solaris PAX', hx.pax_member({'path': name}, typeflag=b'X')),
                ('libarchive', hx.pax_member({'path': name, 'LIBARCHIVE.creationtime': '1794992487.25',
                                              'SCHILY.dev': '66306', 'SCHILY.ino': '42', 'SCHILY.nlink': '1',
                                              'LIBARCHIVE.xattr.com.apple.quarantine': 'MDA4MTs='})),
                ('both links', hx.raw_member('././@LongLink', b'/etc/passwd\0', typeflag=b'K', magic=hx.GNU)
                 + hx.pax_member({'path': name, 'linkpath': '/etc/shadow'}))):
            with self.subTest(case=label):
                data = head + hx.raw_member('short', self.member) + hx.raw_member('./backup.json', doc) + hx.END
                self.assertEqual([(m.name, m.slug, m.problem) for m in self.describe(data).members], [(name, slug, None)])
        size = hx.pax_member({'size': str(len(self.member))})
        member = size + hx.raw_header(f'{hx.ODOO}.tar.gz', size=0) + hx.padded(self.member)
        self.taken(self.backup(member=member))

    def test_what_is_not_a_member_is_stepped_over(self):
        """UP-10, UP-13: folders, links, devices and names with a path -- macOS' `._` files too -- are never followed."""
        cases = [
            (hx.raw_member('data/', typeflag=b'5'), [('not-a-file', 'data/')]),
            (hx.raw_member('data', typeflag=b'5', size=0), [('not-a-file', 'data')]),
            (hx.raw_member('old/', typeflag=b'\0', magic=hx.V7), [('not-a-file', 'old/')]),
            (hx.raw_member('l', typeflag=b'2', linkname='/etc/passwd'), [('not-a-file', 'l')]),
            (hx.raw_member('h', typeflag=b'1', linkname=f'{hx.ODOO}.tar.gz'), [('not-a-file', 'h')]),
            (hx.raw_member('c', typeflag=b'3'), [('not-a-file', 'c')]),
            (hx.raw_member('b', typeflag=b'4'), [('not-a-file', 'b')]),
            (hx.raw_member('p', typeflag=b'6'), [('not-a-file', 'p')]),
            (hx.raw_member('vol', typeflag=b'V', magic=hx.GNU), [('not-a-file', 'vol')]),
            (hx.raw_member('dump', b'Yx\0', typeflag=b'D', magic=hx.GNU), [('not-a-file', 'dump')]),
            (hx.raw_member('x/y', b'data'), [('name', 'x/y')]),
            (hx.raw_member('../evil.tar.gz', b'data'), [('name', '../evil.tar.gz')]),
            (hx.raw_member('/evil.tar.gz', b'data'), [('name', '/evil.tar.gz')]),
            (hx.raw_member('a\nb', b'data'), [('name', 'a b')]),
            (hx.raw_member('', b'data'), [('name', '（空白檔名）')]),
            (hx.raw_member('..', b'data'), [('name', '..')]),
            (hx.pax_member({'path': 'n' * 300}) + hx.raw_member('s', b'data'), [('name', 'n' * 120)]),
            (hx.raw_member(f'x/{hx.ODOO}.tar.gz', b'data'), [('name', f'x/{hx.ODOO}.tar.gz')]),
            (hx.raw_member('./._backup.json', b'Mac OS X'), [('unlisted', '._backup.json')]),
            (hx.raw_member(f'{hx.ODOO}.tar.gz', typeflag=b'5'), [('not-a-file', f'{hx.ODOO}.tar.gz')]),
            (hx.raw_member('./backup.json', typeflag=b'2', linkname='/etc/passwd'), [('not-a-file', './backup.json')]),
        ]
        for blocks, ignored in cases:
            with self.subTest(ignored=ignored):
                self.taken(self.backup(blocks), ignored)
        everything = self.backup(*[blocks for blocks, _ignored in cases])
        layout = self.describe(everything)
        self.assertEqual((layout.ignored_count, len(layout.ignored)), (len(cases), habackup.SAMPLES))
        # A link or folder whose header announces data has none, as tarfile reads it: what follows is the next header.
        self.taken(self.backup(hx.raw_header('d/', typeflag=b'5', size=4096)), [('not-a-file', 'd/')])
        self.refused(self.backup(hx.raw_member('d/', b'x' * 600, typeflag=b'5')), 'corrupt-archive',
                     'tar header checksum mismatch')

    def test_padding_and_what_follows_the_end(self):
        """UP-17, UP-18: neither is data."""
        dirty = hx.raw_member(f'{hx.ODOO}.tar.gz', self.member)
        self.assertTrue(len(self.member) % 512, 'there is padding')
        dirty = dirty[:-1] + b'\x01'
        self.taken(self.backup(member=dirty))
        pax = bytearray(hx.pax_member({'comment': 'x'}))
        pax[-1] = 1
        self.taken(self.backup(bytes(pax)))
        for after in (hx.END + b'\x01' + bytes(511), hx.END + os.urandom(5000), hx.END + gzip.compress(b'more'),
                      hx.END + hx.raw_member('late.tar.gz', b'x') + hx.END, bytes(512), bytes(512) + b'\x01' * 512,
                      bytes(512) + b'x', hx.END + bytes(2 * 1024 * 1024)):
            with self.subTest(after=after[:520][-8:]):
                self.taken(self.backup(after=after))

    def test_nothing_behind_the_end_is_read(self):
        """UP-18: a gigabyte of rubbish after the archive costs nothing (the file here is sparse)."""
        path = self.write(self.backup(after=hx.END + b'rubbish'))
        end = path.stat().st_size - len(b'rubbish')
        os.truncate(path, 1024 ** 3)
        reads = []
        real = os.pread

        def pread(fd, n, offset):
            reads.append((offset, n))
            return real(fd, n, offset)
        fd = self.fd(path)
        with mock.patch.object(os, 'pread', pread):
            self.assertTrue(habackup.looks_like_ha(fd))
            self.assertEqual(len(habackup.describe(fd).members), 1)
        self.assertLessEqual(max(offset + n for offset, n in reads), end)

    def test_global_headers(self):
        """One that only comments (git archive writes it) is ignored; one that would move names or sizes is refused."""
        for records in ({'comment': 'x'}, {'mtime': '1', 'uid': '0'}):
            self.taken(self.backup(hx.pax_member(records, typeflag=b'g')))
        self.taken(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', self.member)], pax_headers={'comment': 'x'}))
        for records in ({'path': 'x'}, {'size': '1'}, {'linkpath': 'x'}, {'comment': 'x', 'size': '0'}):
            with self.subTest(records=records):
                self.refused(self.backup(hx.pax_member(records, typeflag=b'g')), 'corrupt-archive',
                             'a global pax header changes the members after it')
        between = hx.pax_member({'path': 'x'}) + hx.pax_member({'comment': 'x'}, typeflag=b'g')
        self.refused(self.backup(between), 'corrupt-archive', 'global pax headers are not supported')

    def test_what_still_refuses_the_file(self):
        """Damage in the outer tar itself: positions, names or sizes cannot be trusted any more."""
        valid = hx.outer_bytes([(f'{hx.ODOO}.tar.gz', self.member)])
        (_pax, _name, _t), (odoo_header, odoo_name, _t2) = hx.header_offsets(valid)[:2]
        self.assertEqual(odoo_name, f'{hx.ODOO}.tar.gz')
        broken = bytearray(valid)
        broken[odoo_header + 10] ^= 1  # checksum no longer matches
        cases = [
            ('checksum', bytes(broken), 'tar header checksum mismatch'),
            ('truncated in a member', valid[:odoo_header + 600], 'the backup file is truncated'),
            ('truncated in padding', self.backup()[:512 + len(self.member)], 'the backup file is truncated'),
            ('no end of archive', self.backup(after=b''), 'the backup file is truncated'),
            ('half an end', self.backup(after=bytes(511)), 'the backup file is truncated'),
            ('sparse records', self.backup(hx.pax_member({'GNU.sparse.major': '1'}) + hx.raw_member('s', b'x')),
             'sparse files are not supported'),
            ('sparse type', self.backup(hx.raw_member('s', b'x', typeflag=b'S', magic=hx.GNU)),
             'sparse files are not supported'),
            ('compressed outer', gzip.compress(valid), 'the outer file is compressed (HA backups are plain tar files)'),
            ('pax without a member', self.backup(after=hx.pax_member({'path': 'x'}) + hx.END),
             'extended header without a member'),
            ('two pax headers', self.backup(hx.pax_member({'path': 'x'}) * 2), 'consecutive pax headers'),
            ('two long names', self.backup(hx.raw_member('L', b'a\0', typeflag=b'L') * 2),
             'consecutive long name records'),
            ('two long links', self.backup(hx.raw_member('K', b'a\0', typeflag=b'K') * 2),
             'consecutive long link records'),
            ('pax record', self.backup(hx.pax_member(b'9999 path=x\n')), 'malformed pax record'),
            ('pax key twice', self.backup(hx.pax_member(hx.pax_records({'path': 'x'}) * 2)),
             'malformed or repeated pax record'),
            ('pax after its zeros', self.backup(hx.pax_member(hx.pax_records({'path': 'x'}) + b'\0\0x')), 'malformed pax header'),
            ('pax size', self.backup(hx.pax_member({'size': 'many'}) + hx.raw_member('x')), 'pax size is not a number'),
            ('size field', self.backup(hx.fix_checksum(hx.raw_header('x')[:124] + b'9' * 11 + b'\0' + hx.raw_header('x')[136:])),
             'tar number field is not octal'),
            ('negative size', self.backup(hx.fix_checksum(hx.raw_header('x')[:124] + b'\xff' * 12 + hx.raw_header('x')[136:])),
             'tar number field is negative or invalid'),
            ('a member beyond the file', self.backup(hx.raw_header('x', size=10 ** 9)), 'the backup file is truncated'),
        ]
        for label, data, reason in cases:
            with self.subTest(case=label):
                self.refused(data, 'corrupt-archive', reason)
        self.assertEqual(self.describe(valid).members[0].size, len(self.member))

    def test_limits(self):
        """UP-12, UP-15, UP-21, UP-32, UP-39: far above any backup, and still there."""
        def pax(size):
            return hx.pax_member({'comment': 'x' * (size - len('1048576 comment=\n'))}) + hx.raw_member('x', b'')
        self.assertEqual(len(hx.pax_records({'comment': 'x' * (habackup.MAX_PAX - len('1048576 comment=\n'))})),
                         habackup.MAX_PAX)
        self.taken(self.backup(pax(habackup.MAX_PAX)), [('unlisted', 'x')])
        self.refused(self.backup(pax(habackup.MAX_PAX + 1)), 'limit-exceeded', 'extended header too large')
        self.refused(self.backup(hx.raw_member('L', b'n' * (habackup.MAX_LONG_NAME + 1), typeflag=b'L')),
                     'limit-exceeded', 'extended header too large')
        self.taken(self.backup(hx.pax_member(hx.pax_records({'comment': 'x'}) + bytes(9)) + hx.raw_member('x')),
                   [('unlisted', 'x')])  # zeros behind the records are padding
        filler = hx.raw_member('d/', typeflag=b'5')
        self.assertEqual(self.describe(self.backup(filler * (habackup.MAX_OUTER_MEMBERS - 2))).ignored_count,
                         habackup.MAX_OUTER_MEMBERS - 2)
        for blocks in (filler, hx.raw_member('f', b'x'), hx.pax_member({'comment': 'x'}, typeflag=b'g')):
            with self.subTest(blocks=blocks[:5]):
                self.refused(self.backup(blocks * (habackup.MAX_OUTER_MEMBERS - 1)), 'limit-exceeded',
                             'too many members in the outer tar')
        self.assertEqual((habackup.MAX_OUTER_MEMBERS, habackup.MAX_PAX, habackup.MAX_BACKUP_JSON, habackup.MAX_ADDONS,
                          habackup.MAX_FOLDERS), (4096, 1 << 20, 16 << 20, 1000, 256))
        room = habackup.MAX_BACKUP_JSON - len(json.dumps(hx.ha_doc(extra={'x': ''})))
        self.taken(self.backup(doc=json.dumps(hx.ha_doc(extra={'x': 'y' * room})).encode()))
        self.refused(self.backup(doc=json.dumps(hx.ha_doc(extra={'x': 'y' * (room + 1)})).encode()), 'limit-exceeded',
                     'backup.json too large')
        many = [f'{i:08x}_x' for i in range(habackup.MAX_ADDONS)]
        self.assertEqual(len(self.describe(self.backup(doc=json.dumps(hx.ha_doc(many)).encode())).doc['addons']), 1000)
        self.refused(self.backup(doc=json.dumps(hx.ha_doc([*many, 'one_more'])).encode()), 'limit-exceeded',
                     'too many add-ons in backup.json')
        folders = [f'f{i}' for i in range(habackup.MAX_FOLDERS)]
        self.assertEqual(len(self.describe(self.backup(doc=json.dumps(hx.ha_doc(folders=folders)).encode()))
                             .doc['folders']), 256)
        self.refused(self.backup(doc=json.dumps(hx.ha_doc(folders=[*folders, 'f'])).encode()), 'limit-exceeded',
                     'too many folders in backup.json')


    def test_extended_header_records_are_counted(self):
        """UP-12: the records of all the extended headers of the outer tar are counted, the global ones too."""
        one = hx.pax_member({'a': '1', 'b': '2'}) + hx.raw_member('x', b'')
        glob = hx.pax_member({'comment': 'x'}, typeflag=b'g')
        with mock.patch.object(habackup, 'MAX_PAX_RECORDS', 10):
            self.assertEqual([m.name for m in self.describe(self.backup(one * 5)).members], [f'{hx.ODOO}.tar.gz'])
            self.refused(self.backup(one * 6), 'limit-exceeded', 'too many extended header records')
            self.assertEqual(len(self.describe(self.backup(glob * 10)).members), 1)
            self.refused(self.backup(glob * 11), 'limit-exceeded', 'too many extended header records')
            self.assertFalse(habackup.looks_like_ha(self.fd(self.backup(glob * 11))), 'an upload is not taken for one')
        self.assertEqual(self.describe(self.backup(one * 6)).size, len(self.backup(one * 6)))


class MemberProblemTests(TempFiles):
    """UP-44 to UP-47, KEY-05 to KEY-12, IN-01 to IN-15: one member that cannot be read stops one app; the other add-on
    of the same file is read completely."""

    def check_other(self, data, keys=None):
        names, report = self.read_addon(data, hx.N8N, keys)
        self.assertTrue(report.complete)
        self.assertEqual(report.addon.slug, 'woow-n8n')
        self.assertIn('data/hello.txt', names)

    def test_members_that_are_never_opened(self):
        plain = hx.addon_member()
        head = b'SecureTar\x03' + bytes(6) + struct.pack('!Q8x', 100)
        cases = [  # (member, doc overrides, problem, error code)
            (b'SecureTar\x07' + bytes(600), {'protected': True}, 'encryption-unsupported', 'unsupported-format'),
            (b'SecureTar\x03' + b'\x01' + bytes(600), {'protected': True}, 'encryption-unsupported', 'unsupported-format'),
            (head + bytes(50), {'protected': True}, 'size-mismatch', 'corrupt-archive'),
            (b'SecureTar\x02' + bytes(6) + struct.pack('!Q8x', 2 ** 62) + bytes(600), {}, 'size-mismatch',
             'corrupt-archive'),
            (b'SecureTar\x03' + bytes(6), {}, 'size-mismatch', 'corrupt-archive'),
            (b'SecureTar', {}, 'encryption-unsupported', 'unsupported-format'),
            (b'\x01' * 4097, {'protected': True}, 'partial-ciphertext', 'corrupt-archive'),
            (b'', {'protected': True}, 'partial-ciphertext', 'corrupt-archive'),
            (b'', {}, 'not-an-archive', 'corrupt-archive'),
            (b'\x01' * 4096, {}, 'not-an-archive', 'corrupt-archive'),
            (hx.addon_member(compress=False), {}, 'not-an-archive', 'corrupt-archive'),
        ]
        for member, override, problem, code in cases:
            with self.subTest(problem=problem, member=member[:12]):
                data = hx.two_addons(odoo=member, doc=hx.ha_doc([hx.ODOO, hx.N8N], **override))
                self.assertEqual(self.problems(data), {hx.ODOO: problem, hx.N8N: None})
                with habackup.open_backup(self.write(data)) as ha:
                    bad = ha.layout.addon(hx.ODOO)
                    self.assertEqual((bad.problem, bad.encrypted), (problem, False), 'no key is ever asked for it')
                    for keys in (None, hasecuretar.Keys(hx.PASSWORD)):
                        got, error = code_of(ha.open_addon, hx.ODOO, keys)
                        self.assertEqual((got, error.details['scope'], error.details['problem']), (code, 'member', problem))
                        self.assertEqual(error.message, habackup.problem_text(problem))
                        self.assertEqual(code_of(ha.open_member, f'{hx.ODOO}.tar.gz', keys)[0], code)
                self.check_other(data)
        uncompressed = hx.outer_bytes([(f'{hx.ODOO}.tar', plain), (f'{hx.N8N}.tar', hx.addon_member(
            'woow-n8n', compress=False))], hx.ha_doc([hx.ODOO, hx.N8N], compressed=False))
        self.assertEqual(self.problems(uncompressed), {hx.ODOO: 'not-an-archive', hx.N8N: None})
        self.check_other(uncompressed)

    def test_members_that_are_fine(self):
        self.assertEqual(self.problems(hx.two_addons(doc=hx.ha_doc([hx.ODOO, hx.N8N], protected=True))),
                         {hx.ODOO: None, hx.N8N: None}, 'plain members of a protected backup')
        data = hx.two_addons(odoo=b'\x01' * 4096, doc=hx.ha_doc([hx.ODOO, hx.N8N], protected=True))
        self.assertEqual([m.encryption for m in self.describe(data).members], ['v1', 'none'])
        zeros = hx.outer_bytes([(f'{hx.ODOO}.tar', bytes(10240))], hx.ha_doc(compressed=False))
        self.assertEqual(self.problems(zeros), {hx.ODOO: None}, 'an empty tar')

    def test_a_plain_v7_member(self):
        """IN-23: no magic tells an uncompressed tar from before POSIX; its first header's checksum does."""
        info = json.dumps({'system': {'slug': 'odoo18ce'}, 'version': '0.4.12'}).encode()
        v7 = (hx.raw_member('./addon.json', info, magic=hx.V7, typeflag=b'\0')
              + hx.raw_member('data/hello.txt', b'hello', magic=hx.V7, typeflag=b'\0') + hx.END)
        for protected in (False, True):
            doc = hx.ha_doc(compressed=False, protected=protected)
            data = hx.outer_bytes([(f'{hx.ODOO}.tar', v7)], doc)
            with self.subTest(protected=protected):
                self.assertEqual(self.problems(data), {hx.ODOO: None})
                with habackup.open_backup(self.write(data)) as ha, ha.open_addon(hx.ODOO) as stream:
                    report = habackup.Report()
                    self.assertEqual([e.name for e in habackup.iter_entries(stream, None, report)], ['data/hello.txt'])
                    self.assertEqual((report.addon.slug, report.complete), ('odoo18ce', True))
        for label, member, compressed in (('checksum', b'X' + v7[1:], False), ('short', v7[:500], False),
                                          ('said to be gzip', v7, True)):
            with self.subTest(case=label):
                data = hx.outer_bytes([(f'{hx.ODOO}.tar' + '.gz' * compressed, member)], hx.ha_doc(compressed=compressed))
                self.assertEqual(self.problems(data), {hx.ODOO: 'not-an-archive'})

    def test_other_members_have_no_say(self):
        """UP-44 to UP-47 for Home Assistant, a folder or supervisor: the add-ons are read as ever."""
        doc = hx.ha_doc([hx.ODOO, hx.N8N], folders=['share', 'media'], homeassistant={'version': '1'})
        extra = [('homeassistant.tar.gz', b''), ('share.tar.gz', b'SecureTar\x09' + bytes(100)),
                 ('media.tar.gz', b'junk'), ('supervisor.tar.gz', b'SecureTar\x03' + bytes(100))]
        data = hx.two_addons(doc=doc, extra=extra)
        layout = self.describe(data)
        self.assertEqual({m.name: m.problem for m in layout.members if m.problem},
                         {'homeassistant.tar.gz': 'not-an-archive', 'share.tar.gz': 'encryption-unsupported',
                          'media.tar.gz': 'not-an-archive', 'supervisor.tar.gz': 'size-mismatch'})
        self.check_other(data)
        with habackup.open_backup(self.write(data)) as ha:
            self.assertEqual(code_of(ha.open_member, 'share.tar.gz')[0], 'unsupported-format')

    @hx.needs_crypto
    def test_damaged_and_changed_members(self):
        """KEY-05 to KEY-12: every kind of damage to one encrypted add-on, the other one and the key are fine."""
        fixtures = {'v1': 'v1_gzip.tar', 'v2': 'v2_gzip.tar', 'v3': 'v3_gzip.tar'}
        for kind, fixture in fixtures.items():
            odoo, _info = hx.member_bytes(hx.fixture(fixture), f'{hx.ODOO}.tar.gz')
            n8n, _info = hx.member_bytes(hx.fixture(fixture), f'{hx.N8N}.tar.gz')
            doc = hx.ha_doc([hx.ODOO, hx.N8N], protected=True)

            def flipped(offset, raw=odoo):
                raw = bytearray(raw)
                raw[offset] ^= 0x10
                return bytes(raw)
            cases = {'cut': odoo[:-16], 'cut to its header': odoo[:40], 'a bit in the middle': flipped(len(odoo) // 2),
                     'a bit at the end': flipped(len(odoo) - 20)}
            if kind == 'v2':
                cases['padding'] = flipped(len(odoo) - 17)
            if kind == 'v3':
                cases['validated bytes'] = flipped(140)
            if kind != 'v1':
                size = int.from_bytes(odoo[16:24], 'big')
                cases['plaintext size smaller'] = odoo[:16] + (size - 16).to_bytes(8, 'big') + odoo[24:]
            for label, damaged in cases.items():
                with self.subTest(kind=kind, case=label):
                    data = hx.two_addons(odoo=damaged, n8n=n8n, doc=doc)
                    keys = hasecuretar.Keys(hx.PASSWORD)
                    code, error = code_of(self.read_addon, data, hx.ODOO, keys)
                    self.assertEqual((code, error.details['scope']), ('corrupt-archive', 'member'))
                    self.assertEqual(error.message, hasecuretar.MEMBER_MESSAGE)
                    with habackup.open_backup(self.write(data)) as ha, ha.open_addon(hx.N8N, keys) as stream:
                        report = habackup.Report()
                        self.assertTrue([e.name for e in habackup.iter_entries(stream, None, report)])
                        self.assertTrue(report.complete, 'the other add-on')
                        self.assertEqual(report.addon.slug, 'woow-n8n')

    @hx.needs_crypto
    def test_bytes_after_an_encrypted_member(self):
        """KEY-13: never read; the content itself must still be whole."""
        for fixture, tails in (('v2_gzip.tar', (b'x', os.urandom(1000), gzip.compress(b'more'), bytes(2 ** 20))),
                               ('v3_gzip.tar', (b'x', os.urandom(1000), gzip.compress(b'more'), bytes(2 ** 20))),
                               ('v3_plain.tar', (b'x', os.urandom(1000)))):
            ext = '.tar' if fixture.endswith('_plain.tar') else '.tar.gz'
            odoo, _info = hx.member_bytes(hx.fixture(fixture), f'{hx.ODOO}{ext}')
            for tail in tails:
                with self.subTest(fixture=fixture, tail=tail[:4]):
                    doc = hx.ha_doc([hx.ODOO], protected=True, compressed=ext == '.tar.gz')
                    data = hx.outer_bytes([(f'{hx.ODOO}{ext}', odoo + tail)], doc)
                    names, report = self.read_addon(data, hx.ODOO, hasecuretar.Keys(hx.PASSWORD))
                    self.assertTrue(report.complete)
                    self.assertEqual(report.entries, hx.META['fixtures'][fixture]['members'][f'{hx.ODOO}{ext}'] and
                                     len(hx.META['fixtures'][fixture]['members'][f'{hx.ODOO}{ext}']['entries']))

    def test_damaged_plain_members(self):
        """IN-01, IN-03, IN-06, IN-08, IN-13 to IN-15, IN-18, IN-22: the same for members without encryption."""
        raw = hx.addon_member(compress=False)
        packed = gzip.compress(raw, mtime=0)
        head = next(offset for offset, name, _type in hx.header_offsets(raw) if name == './addon.json') + 5

        def addon(text):
            return hx.tar_bytes([{'name': './addon.json', 'data': text}], compress=True)
        cases = {'cut gzip': packed[:-10], 'half a gzip': packed[:len(packed) // 2], 'crc': packed[:-8] + b'\0' * 8,
                 'a bit': packed[:60] + bytes([packed[60] ^ 1]) + packed[61:], 'only a gzip header': packed[:10],
                 'cut tar': gzip.compress(raw[:2000]), 'tar without an end': gzip.compress(raw[:512 * 3]),
                 'header checksum': gzip.compress(raw[:head] + bytes([raw[head] ^ 1]) + raw[head + 1:]),
                 'addon.json': addon(b'{"system"'), 'addon.json twice a key': addon(b'{"system": {}, "system": {}}'),
                 'no system': addon(b'{"user": {}}'), 'slug': addon(b'{"system": {"slug": "A b"}, "version": "1"}')}
        for label, member in cases.items():
            with self.subTest(case=label):
                data = hx.two_addons(odoo=member)
                code, error = code_of(self.read_addon, data, hx.ODOO)
                self.assertEqual((code, error.details.get('scope')), ('corrupt-archive', 'member'))
                self.check_other(data)


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

    def gunzip(self, data, legacy=False, size=4096):
        gunzip = habackup._Gunzip(io.BytesIO(data), legacy=legacy)
        parts = []
        while True:
            part = gunzip.read(size)
            if not part:
                return b''.join(parts)
            self.assertLessEqual(len(part), size)
            parts.append(part)

    def gzip_refused(self, data, reason, code='corrupt-archive', **kwargs):
        got, error = code_of(self.gunzip, data, **kwargs)
        self.assertEqual((got, error.details['reason']), (code, reason))
        say_member(self, error)

    def test_gzip_layer(self):
        """IN-01 to IN-08: a damaged or unclear gzip stream stops its member."""
        raw = hx.tar_bytes([{'name': 'a.txt', 'data': b'hello' * 1000}])
        good = gzip.compress(raw, mtime=0)
        self.assertEqual(self.gunzip(good), raw)
        bad_crc = good[:-8] + struct.pack('<I', zlib.crc32(raw) ^ 1) + good[-4:]
        bad_size = good[:-4] + struct.pack('<I', len(raw) + 1)
        header = b'\x1f\x8b\x08' + bytes([0x04 | 0x08 | 0x10 | 0x02]) + bytes(6) + b'\x05\x00extra' + b'name.tar\x00comment\x00'
        header += struct.pack('<H', zlib.crc32(header) & 0xffff)
        body = good[10:]
        self.assertEqual(self.gunzip(header + body), raw)
        cases = {
            'crc': (bad_crc, 'gzip checksum mismatch'), 'isize': (bad_size, 'gzip checksum mismatch'),
            'cut trailer': (good[:-3], 'gzip trailer is invalid'), 'no trailer': (good[:-8], 'gzip trailer is invalid'),
            'cut data': (good[:-20], 'gzip stream is truncated'), 'cut header': (good[:7], 'gzip stream is truncated'),
            'cut name': (header[:22], 'gzip stream is truncated'), 'empty': (b'', 'gzip stream is truncated'),
            'not gzip': (b'\x1f\x8c' + good[2:], 'member data is not gzip'),
            'reserved flags': (good[:3] + b'\xe0' + good[4:], 'gzip header has reserved flags'),
            'deflate': (good[:20] + b'\xff' * 40 + good[60:], None),
            'header crc': (header[:-2] + b'\x00\x00' + body, 'gzip header checksum mismatch'),
            'rubbish behind it': (good + os.urandom(16).replace(b'\0', b'x') + b'x', 'data after the gzip stream'),
            'half a magic behind it': (good + b'\x1f\x8b', 'data after the gzip stream'),
        }
        for label, (data, reason) in cases.items():
            for chunk in (1, 4096):
                with self.subTest(case=label, chunk=chunk):
                    if reason is None:
                        code, error = code_of(self.gunzip, data, size=chunk)
                        self.assertEqual((code, error.details['scope']), ('corrupt-archive', 'member'))
                    else:
                        self.gzip_refused(data, reason, size=chunk)

    def test_several_gzip_members_and_padding(self):
        """IN-07: recompressed in several parts (pigz, bgzip, `cat a.gz b.gz`), padded to a tape block: every part is
        checked like the first."""
        raw = bytes(random.Random(7).randbytes(300_000))
        pieces = [raw[:1], raw[1:100_000], b'', raw[100_000:]]
        parts = [gzip.compress(piece, mtime=0) for piece in pieces]
        for padding in (b'', b'\0', bytes(10240)):
            for size in (1000, habackup.CHUNK):
                with self.subTest(padding=len(padding), size=size):
                    self.assertEqual(self.gunzip(b''.join(parts) + padding, size=size), raw)
                    self.assertEqual(self.gunzip(padding.join(parts) + padding, size=size), raw)
        for index in range(len(parts)):
            broken = list(parts)
            broken[index] = broken[index][:-8] + bytes([broken[index][-8] ^ 1]) + broken[index][-7:]
            with self.subTest(part=index):
                self.gzip_refused(b''.join(broken), 'gzip checksum mismatch')
        self.gzip_refused(b''.join(parts)[:-1], 'gzip trailer is invalid')
        self.gzip_refused(parts[0] + bytes(5) + b'x', 'data after the gzip stream')
        self.gzip_refused(parts[0] + b'\x1f\x8b\x08\xe0' + bytes(6), 'gzip header has reserved flags')
        member = hx.addon_member(compress=False)
        split = gzip.compress(member[:1000], mtime=0) + gzip.compress(member[1000:], mtime=0)
        data = hx.outer_bytes([(f'{hx.ODOO}.tar.gz', split)])
        names, report = self.read_addon(data, hx.ODOO)
        self.assertEqual((report.complete, names[-1]), (True, 'config'))

    def test_gzip_limits(self):
        """IN-02: header fields up to 1 MiB; the number of gzip members is limited too."""
        raw = hx.tar_bytes([{'name': 'a.txt', 'data': b'hello'}])
        body = gzip.compress(raw, mtime=0)[10:]
        head = b'\x1f\x8b\x08\x08' + bytes(6)
        self.assertEqual(habackup.MAX_GZIP_FIELD, 1 << 20)
        self.assertEqual(self.gunzip(head + b'n' * (habackup.MAX_GZIP_FIELD - 1) + b'\0' + body), raw)
        self.gzip_refused(head + b'n' * habackup.MAX_GZIP_FIELD + b'\0' + body, 'gzip header field too long')
        self.gzip_refused(head + b'n' * (3 * habackup.CHUNK), 'gzip header field too long')
        empty = gzip.compress(b'', mtime=0)
        with mock.patch.object(habackup, 'MAX_GZIP_MEMBERS', 100):
            self.assertEqual(self.gunzip(empty * 99 + gzip.compress(b'x')), b'x')
            self.gzip_refused(empty * 100 + gzip.compress(b'x'), 'too many gzip members', 'limit-exceeded')
        fed = []

        class Inflate:  # what zlib gets at a time: what is left over of it is copied for every member
            def __init__(self, wbits, real=zlib.decompressobj):
                self.real = real(wbits)

            def decompress(self, data, n):
                fed.append(len(data))
                return self.real.decompress(data, n)

            def __getattr__(self, name):
                return getattr(self.real, name)
        with mock.patch.object(zlib, 'decompressobj', Inflate):
            self.assertEqual(self.gunzip(empty * 10_000), b'')
        self.assertEqual((len(fed), max(fed)), (10_000, habackup.GZIP_FEED))
        self.assertEqual(habackup.GZIP_FEED, 64 << 10)

    def test_decompression_is_bounded(self):
        bomb = gzip.compress(hx.tar_bytes([{'name': 'zeros', 'data': bytes(64 * 1024 * 1024)}]), mtime=0)
        self.assertLess(len(bomb), 200_000)
        gunzip = habackup._Gunzip(io.BytesIO(bomb))
        self.assertLessEqual(len(gunzip.read(10 ** 9)), habackup.CHUNK)

    def test_a_file_cut_off_while_it_is_read(self):
        """The whole file is at fault then, not one add-on: the job ends (`job_wide`, DESIGN C1)."""
        path = self.write(hx.two_addons(odoo=hx.tar_bytes([{'name': 'big', 'data': os.urandom(4 << 20)}], compress=True)))
        with habackup.open_backup(path) as ha, ha.open_addon(hx.ODOO) as stream:
            os.truncate(path, 1 << 20)
            with self.assertRaises(BackupError) as caught:
                list(habackup.iter_entries(stream, habackup.Select(include=())))
        self.assertEqual((caught.exception.code, caught.exception.job_wide, caught.exception.details),
                         ('corrupt-archive', True, {'reason': 'the backup file is truncated'}))
        self.assertFalse(hasattr(hasecuretar.broken('x'), 'job_wide'))

    def test_a_zip_bomb_stops_at_the_budget(self):
        """IN-20: 256 MiB of zeros in 260 KB, in an entry and behind the archive; nothing of it is kept in memory."""
        for label, raw in (('entry', hx.tar_bytes([{'name': 'zeros', 'data': bytes(64 << 20)}])),
                           ('behind the archive', hx.tar_bytes([{'name': 'a', 'data': b'x'}]) + bytes(64 << 20))):
            data = hx.outer_bytes([(f'{hx.ODOO}.tar.gz', gzip.compress(raw, mtime=0))])
            with self.subTest(case=label), mock.patch.object(habackup, 'INFLATE_FLOOR', 8 << 20), \
                    mock.patch.object(habackup, 'INFLATE_RATIO', 100):
                code, error = code_of(self.read_addon, data, hx.ODOO)
                self.assertEqual((code, error.details['reason']), ('limit-exceeded', 'the add-on archive inflates too much'))
                self.assertLess(error.details['limit'], 16 << 20)
                say_member(self, error)
            with self.subTest(case=label, floor='as it is'):
                self.assertTrue(self.read_addon(data, hx.ODOO)[1].complete, 'below the floor it is only large')

    @hx.needs_crypto
    def test_the_end_of_real_members(self):
        """IN-09, IN-41: what a checksum or authentication covers may go on behind the tar's end (it is dropped); a
        stream that nothing covers may not, because zeros in its middle would look like its end."""
        tar = hx.addon_member(compress=False)
        more = tar + hx.tar_bytes([{'name': 'late', 'data': b'x'}])
        for label, member, compressed, protected, checked in (
                ('gzip', gzip.compress(more, mtime=0), True, False, True),
                ('v3', hx.v3_encrypt(more), False, True, True), ('v3 gzip', hx.v3_encrypt(gzip.compress(more)), True, True, True),
                ('plain', more, False, False, False)):
            data = hx.outer_bytes([(f'{hx.ODOO}.tar' + '.gz' * compressed, member)],
                                  hx.ha_doc(compressed=compressed, protected=protected))
            with self.subTest(member=label), habackup.open_backup(self.write(data)) as ha, \
                    ha.open_addon(hx.ODOO, hasecuretar.Keys(hx.PASSWORD)) as stream:
                self.assertIs(stream.checked_to_the_end, checked)
                report = habackup.Report()
                walk = habackup.iter_entries(stream, None, report)
                if checked:
                    self.assertEqual([e.name for e in walk][-1], 'config')
                else:
                    code, error = code_of(list, walk)
                    self.assertEqual(error.details['reason'], 'the inner tar goes on after its end-of-archive marker')
                self.assertIs(report.complete, checked)

    @hx.needs_crypto
    def test_finish_alone_runs_every_check(self):
        tar = hx.addon_member(compress=False)
        packed = gzip.compress(tar, mtime=0)
        for label, member, compressed, protected, reason in (
                ('gzip trailer', packed[:-8] + bytes(8), True, False, 'gzip checksum mismatch'),
                ('gzip cut', packed[:-30], True, False, 'gzip stream is truncated'),
                ('v3 tag', hx.v3_encrypt(tar, tags=[0]), False, True, 'unexpected secretstream tag or chunk size'),
                ('v3 gzip trailer', hx.v3_encrypt(packed[:-4] + bytes(4)), True, True, 'gzip checksum mismatch')):
            data = hx.outer_bytes([(f'{hx.ODOO}.tar' + '.gz' * compressed, member)],
                                  hx.ha_doc(compressed=compressed, protected=protected))
            with self.subTest(case=label), habackup.open_backup(self.write(data)) as ha, \
                    ha.open_addon(hx.ODOO, hasecuretar.Keys(hx.PASSWORD)) as stream:
                code, error = code_of(stream.finish)
                self.assertEqual((code, error.details['reason'], error.details['scope']), ('corrupt-archive', reason, 'member'))

    def test_a_stream_can_be_opened_again(self):
        data = hx.two_addons()
        with habackup.open_backup(self.write(data)) as ha, ha.open_addon(hx.ODOO) as first:
            half = first.read(100)
            with first.reopen() as second:
                self.assertEqual(second.read(100), half)
                self.assertEqual(second.read(), first.read())
        owner = habackup.open_member(self.write(data), f'{hx.ODOO}.tar.gz')
        with owner, owner.reopen() as second:
            self.assertEqual(second.read(1000), owner.read(1000))


class WalkCase(unittest.TestCase):
    def walk(self, entries, select=None, *, addon=False, fmt=tarfile.PAX_FORMAT, raw=None, report=None, stream=None):
        data = raw if raw is not None else hx.tar_bytes(entries, fmt=fmt)
        report = report if report is not None else habackup.Report()
        out = []
        for entry in habackup.iter_entries(stream or io.BytesIO(data), select, report, addon=addon):
            out.append((entry.name, entry.kind, entry.linkname, entry.read_all(1 << 22) if entry.kind == 'file' else None))
        self.assertTrue(report.complete)
        return out, report

    def refused(self, entries, select=None, **kwargs):
        try:
            self.walk(entries, select, **kwargs)
        except BackupError as error:
            if error.code in MEMBER_MESSAGES:
                say_member(self, error)
            return error.code, error.details.get('reason')
        raise AssertionError('accepted')


class EntryTests(WalkCase):
    def test_peek_leaves_the_file_to_be_read_from_its_start(self):
        data = hx.tar_bytes([{'name': 'a.bin', 'data': b'0123456789'}, {'name': 'short', 'data': b'xy'}])
        seen = [(entry.name, entry.peek(4), entry.peek(2), entry.read_all(1 << 20))
                for entry in habackup.iter_entries(io.BytesIO(data), None, habackup.Report(), addon=False)]
        self.assertEqual(seen, [('a.bin', b'0123', b'01', b'0123456789'), ('short', b'xy', b'xy', b'xy')])

    def test_a_walk_is_cancellable_where_nothing_is_selected_and_bounded(self):
        """IN-20: the walk may read 100 times the stored size (256 GiB at least), in the tail behind the archive too."""
        entries = [{'name': '.', 'type': 'dir'}, {'name': 'big.bin', 'data': b'\0' * (256 * 1024)}]
        entries += [{'name': f'f{i}', 'data': b''} for i in range(40)]
        data = hx.tar_bytes(entries)
        calls = []
        old = (habackup.CHECK_BYTES, habackup.CHECK_ENTRIES)
        habackup.CHECK_BYTES, habackup.CHECK_ENTRIES = 32 * 1024, 16
        try:
            for _entry in habackup.iter_entries(io.BytesIO(data), habackup.Select(include=()), habackup.Report(),
                                                addon=False, checkpoint=lambda: calls.append(1)):
                pass
        finally:
            habackup.CHECK_BYTES, habackup.CHECK_ENTRIES = old
        self.assertGreaterEqual(len(calls), 2, 'called while unselected data is skipped and every few headers')

        class Stream(io.BytesIO):
            member = type('M', (), {'size': 1000})()

        small = hx.tar_bytes([{'name': 'a', 'data': b'x'}])
        old = (habackup.INFLATE_FLOOR, habackup.INFLATE_RATIO)
        habackup.INFLATE_FLOOR, habackup.INFLATE_RATIO = 64 * 1024, 2
        try:
            for label, stream in (('entries', Stream(data)), ('tail', Stream(small + os.urandom(1 << 20)))):
                with self.subTest(case=label), self.assertRaises(BackupError) as caught:
                    for _entry in habackup.iter_entries(stream, habackup.Select(include=()), habackup.Report(),
                                                        addon=False):
                        pass
                self.assertEqual(caught.exception.code, 'limit-exceeded')
        finally:
            habackup.INFLATE_FLOOR, habackup.INFLATE_RATIO = old
        self.assertEqual(habackup.inflate_budget(Stream(b'')), habackup.INFLATE_FLOOR)
        self.assertIsNone(habackup.inflate_budget(io.BytesIO(b'')))
        self.assertEqual((habackup.INFLATE_FLOOR, habackup.INFLATE_RATIO), (256 * 1024 ** 3, 100))
        big = type('S', (io.BytesIO,), {'member': type('M', (), {'size': 4 * 1024 ** 3})()})
        self.assertEqual(habackup.inflate_budget(big(b'')), 400 * 1024 ** 3)

    def test_names_are_normalised(self):
        out, report = self.walk([{'name': '.', 'type': 'dir'}, {'name': './data/', 'type': 'dir'},
                                 {'name': './data/a.txt', 'data': b'a'}, {'name': 'data/b.txt', 'data': b'b'}])
        self.assertEqual([row[0] for row in out], ['.', 'data', 'data/a.txt', 'data/b.txt'])
        self.assertEqual((report.files, report.dirs, report.bytes), (2, 2, 2))
        for given, expected in (('.', '.'), ('./', '.'), ('./.', '.'), ('././a/', 'a'), ('a/b', 'a/b'), ('./a/./b', None),
                                ('', None), ('/', None), ('/a', None), ('.//', None), ('a//', None), ('a//b', None),
                                ('..', None), ('a/..', None), ('./..', None), ('a\tb', None), ('a' * 4097, None),
                                ('a' * 4096, 'a' * 4096), ('./' * 300_000 + 'a', 'a'), (5, None), (None, None)):
            with self.subTest(name=str(given)[:20]):
                if expected is None:
                    self.assertEqual(code_of(habackup.normalize, given)[0], 'corrupt-archive')
                else:
                    self.assertEqual(habackup.normalize(given), expected)

    def test_hostile_names_and_types(self):
        """IN-29 to IN-33, IN-35 to IN-37: what could lead outside or cannot be read for sure stops the app."""
        cases = {
            'absolute': ([{'name': '/etc/passwd', 'data': b'x'}], 'absolute entry name'),
            'dotdot': ([{'name': 'data/../../x', 'data': b'x'}], 'entry name with an empty, "." or ".." component'),
            'inner dot': ([{'name': 'data/./x', 'data': b'x'}], 'entry name with an empty, "." or ".." component'),
            'empty component': ([{'name': 'data//x', 'data': b'x'}], 'entry name with an empty, "." or ".." component'),
            'contiguous': ([{'name': 'c', 'type': tarfile.CONTTYPE, 'data': b'x'}], 'entry type not allowed'),
            'sparse pax': ([{'name': 's', 'data': b'x', 'pax': {'GNU.sparse.major': '1', 'GNU.sparse.minor': '0'}}],
                           'sparse files are not supported'),
            'duplicate': ([{'name': 'a', 'data': b'1'}, {'name': './a', 'data': b'2'}], 'duplicate entry'),
            'duplicate folder': ([{'name': 'a', 'type': 'dir'}, {'name': 'a/', 'type': 'dir'}], 'duplicate entry'),
            'below a file': ([{'name': 'a', 'data': b'1'}, {'name': 'a/b', 'data': b'2'}], 'entry below a file or link'),
            'deep below a file': ([{'name': 'a', 'data': b'1'}, {'name': 'a/b/c/d', 'data': b'2'}],
                                  'entry below a file or link'),
            'below a symlink': ([{'name': 'l', 'type': 'symlink', 'linkname': 'x'}, {'name': 'l/b', 'data': b'2'}],
                                'entry below a file or link'),
            'below a hard link': ([{'name': 'a', 'data': b'1'}, {'name': 'l', 'type': 'hardlink', 'linkname': 'a'},
                                   {'name': 'l/b', 'data': b'2'}], 'entry below a file or link'),
            'below a device': ([{'name': 'l', 'type': 'chr'}, {'name': 'l/b', 'data': b'2'}], 'entry below a file or link'),
            'below a FIFO': ([{'name': 'l', 'type': 'fifo'}, {'name': 'l/b', 'data': b'2'}], 'entry below a file or link'),
            'file replaces a directory': ([{'name': 'd/x', 'data': b'1'}, {'name': 'd', 'data': b'2'}],
                                          'a non-directory replaces a directory'),
            'link replaces a directory': ([{'name': 'd/e/x', 'data': b'1'},
                                           {'name': 'd/e', 'type': 'symlink', 'linkname': '/'}],
                                          'a non-directory replaces a directory'),
            'root is a file': ([{'name': './', 'data': b'x'}], 'the root entry is not a directory'),
            'root is a link': ([{'name': '.', 'type': 'symlink', 'linkname': '/'}], 'the root entry is not a directory'),
            'dir with data': ([{'name': 'd', 'type': tarfile.DIRTYPE, 'data': b'x' * 10}], 'a non-file entry carries data'),
            'link with data': ([{'name': 'd', 'type': 'symlink', 'linkname': 'x', 'data': b'x'}],
                               'a non-file entry carries data'),
            'device with data': ([{'name': 'd', 'type': 'chr', 'data': b'x'}], 'a non-file entry carries data'),
        }
        for label, (entries, reason) in cases.items():
            for select in (None, habackup.Select(include=()), habackup.Select(include=('elsewhere',))):
                with self.subTest(case=label, include=select and select.include):
                    code, got = self.refused(entries, select)
                    self.assertEqual((code, got[:len(reason)]), ('corrupt-archive', reason))
        for typeflag in (b'S', b'7', b'D', b'M', b'V', b'X', b'N', b'A', b'z'):
            with self.subTest(typeflag=typeflag):
                code, got = self.refused([], raw=hx.raw_member('x', typeflag=typeflag, magic=hx.GNU) + hx.END)
                self.assertEqual((code, got), ('corrupt-archive', 'entry type not allowed (sparse, contiguous or unknown)'))
        self.assertEqual(self.refused([{'name': 'a', 'data': b'x'}], raw=hx.tar_bytes(
            [{'name': 'a', 'data': b'x'}], pax_headers={'comment': 'global'})), ('corrupt-archive',
                                                                               'global pax headers are not supported'))

    def test_structure_errors_in_the_tar_itself(self):
        """IN-18, IN-21, IN-22, IN-25: the rest of the tar cannot be found or understood."""
        good = hx.tar_bytes([{'name': 'a', 'data': b'x' * 600}])
        broken = bytearray(good)
        broken[1024 + 3] ^= 1  # the ustar header after the PAX header
        self.assertEqual(self.refused([], raw=bytes(broken)), ('corrupt-archive', 'tar header checksum mismatch'))
        self.assertEqual(self.refused([], raw=good[:1500]), ('corrupt-archive', 'the inner tar is truncated'))
        self.assertEqual(self.refused([], raw=good[:1024 + 512 + 100]), ('corrupt-archive', 'the inner tar is truncated'))
        without_end = good[:1024 + 512 + 1024]
        self.assertEqual(self.refused([], raw=without_end), ('corrupt-archive', 'the inner tar is truncated'))
        self.assertEqual(self.refused([], raw=b''), ('corrupt-archive', 'the inner tar is truncated'))
        for label, blocks, reason in (
                ('pax at the end', hx.pax_member({'path': 'x'}), 'extended header without a member'),
                ('long name at the end', hx.raw_member('L', b'x\0', typeflag=b'L'), 'extended header without a member'),
                ('two pax', hx.pax_member({'path': 'x'}) * 2, 'consecutive pax headers'),
                ('two names', hx.raw_member('L', b'x\0', typeflag=b'L') * 2, 'consecutive long name records'),
                ('two links', hx.raw_member('K', b'x\0', typeflag=b'K') * 2, 'consecutive long link records'),
                ('pax twice a key', hx.pax_member(hx.pax_records({'path': 'x'}) * 2), 'malformed or repeated pax record'),
                ('pax size', hx.pax_member({'size': '-1'}) + hx.raw_member('x'), 'pax size is not a number'),
                ('pax uid', hx.pax_member({'uid': 'me'}) + hx.raw_member('x'), 'pax uid is not a number'),
                ('pax time', hx.pax_member({'mtime': 'now'}) + hx.raw_member('x'), 'pax mtime is not a time'),
                ('mode', hx.fix_checksum(hx.raw_header('x')[:100] + b'rwxrwxr\0' + hx.raw_header('x')[108:]),
                 'tar number field is not octal'),
                ('another magic', hx.raw_member('x', magic=b'ustar\x0100'), 'tar header is neither POSIX, GNU nor v7')):
            with self.subTest(case=label):
                self.assertEqual(self.refused([], raw=blocks + hx.END), ('corrupt-archive', reason))

    def test_what_follows_the_end(self):
        """IN-09, IN-41: not read -- unless the tar itself goes on: zeros in the middle of a plain tar are no end."""
        good = hx.tar_bytes([{'name': 'a', 'data': b'x' * 600}])
        end = 1024 + 512 + 1024  # PAX header + data, the ustar header, 600 bytes of data padded to 1024
        for label, tail in (('one zero block', bytes(512)), ('a byte', hx.END + b'\x01'),
                            ('one zero block and more', bytes(512) + b'\x01' + bytes(511)),
                            ('rubbish', hx.END + os.urandom(9999)),
                            ('many zeros', bytes(3 << 20)), ('a gzip stream', hx.END + gzip.compress(good)),
                            ('a tar out of step', hx.END + b'x' + good), ('half a header', hx.END + good[1024:1400]),
                            ('a word', hx.END + b'ustar' * 1000), ('a bad header', hx.END + b'x' + good[1025:1536])):
            with self.subTest(tail=label):
                out, _report = self.walk([], raw=good[:end] + tail)
                self.assertEqual([row[0] for row in out], ['a'])
        for label, tail in (('another tar', hx.END + good), ('one zero block', bytes(512) + good),
                            ('far behind', hx.END + bytes(5 << 20) + good), ('a lone header', hx.END + good[1024:1536]),
                            ('gnu', hx.END + hx.raw_member('b', b'y', magic=hx.GNU))):
            with self.subTest(goes_on=label):
                self.assertEqual(self.refused([], raw=good[:end] + tail),
                                 ('corrupt-archive', 'the inner tar goes on after its end-of-archive marker'))
        zeroed = bytearray(hx.tar_bytes([{'name': f'f{i}', 'data': b'x' * 512} for i in range(20)]))
        zeroed[1536 * 4:1536 * 4 + 4096] = bytes(4096)  # a damaged stretch of the file
        self.assertEqual(self.refused([], raw=bytes(zeroed))[0], 'corrupt-archive')

    @staticmethod
    def probe_of_iteration_two(reader):
        """The probe behind a plain tar as it was until the cost fix: every 'ustar' of the data looked at, aligned or not.
        It is the reference for 'the same answers'."""
        block, magic_at = habackup.BLOCK, habackup.TAR_MAGIC_AT
        while True:
            reader._fill(block)
            end = reader.off + reader._avail() // block * block
            if end == reader.off:
                return False
            at = reader.buf.find(b'ustar', reader.off, end)
            while at >= 0:
                head = at - magic_at
                if head >= reader.off and (head - reader.off) % block == 0 \
                        and habackup._checksum_ok(reader.buf[head:head + block]):
                    return True
                at = reader.buf.find(b'ustar', at + 1, end)
            reader.off = end

    def test_the_probe_behind_a_plain_tar_answers_as_before(self):
        """IN-41: looking only where a header can begin changes no answer: random data with good and damaged headers, words
        and zeros at any offset, a reader that has read some bytes already, a tail that is no whole block, buffers of any
        size -- the same answer as the probe that looked at every word."""
        rng = random.Random(20261125)
        headers = [hx.raw_header('a'), hx.raw_header('b' * 90, magic=hx.GNU), hx.raw_header('c', typeflag=b'5', mode=0o755),
                   hx.raw_header('d', size=9999999), hx.raw_header('e', magic=hx.V7)]
        word_block = bytes(habackup.TAR_MAGIC_AT) + b'ustar' + bytes(habackup.BLOCK - habackup.TAR_MAGIC_AT - 5)
        answers = {True: 0, False: 0}
        for round_ in range(600):
            skip = rng.randrange(0, 700)
            data = bytearray(rng.randbytes(skip))
            for _ in range(rng.randrange(1, 10)):
                if rng.random() < 0.6:  # the next piece starts where a header may
                    data += bytes(-(len(data) - skip) % habackup.BLOCK)
                kind = rng.randrange(8)
                if kind == 0:
                    data += bytes(rng.randrange(0, 2200))
                elif kind == 1:
                    data += rng.randbytes(rng.randrange(0, 1300))
                elif kind == 2:
                    data += b'ustar' * rng.randrange(1, 400)
                elif kind == 3:
                    data += rng.choice(headers)
                elif kind == 4:  # a damaged header: one bit differs, the checksum no longer fits
                    block = bytearray(rng.choice(headers))
                    block[rng.randrange(512)] ^= 1 << rng.randrange(8)
                    data += block
                elif kind == 5:
                    data += word_block * rng.randrange(1, 4)  # the word in the right place of a block, nothing else
                elif kind == 6:
                    data += rng.choice(headers)[:rng.randrange(1, 512)]  # a header cut off
                else:
                    data += bytes(rng.randrange(0, 600)) + rng.choice(headers)
            data = bytes(data)
            for chunk in (300, 512, 513, 1000, 4096, 1 << 20):
                with mock.patch.object(habackup, 'CHUNK', chunk):
                    new, old = habackup._Reader(io.BytesIO(data)), habackup._Reader(io.BytesIO(data))
                    new.read_exact(skip)
                    old.read_exact(skip)
                    expected = self.probe_of_iteration_two(old)
                    got = new.another_header()
                if got != expected:
                    self.fail(f'round {round_}, buffers of {chunk}: the probe says {got}, it used to say {expected}')
            answers[expected] += 1
        self.assertGreater(min(answers.values()), 60, 'both answers are given often enough to mean something')

    def test_the_checksum_of_a_header_says_what_it_said(self):
        """IN-41 (cost): the signed sum is counted in C now; it is the same sum -- against the sums written out byte by byte,
        on blocks with and without bytes of 128 or more, whose field holds the unsigned sum, the signed one, or neither."""
        rng = random.Random(1125)
        counts = {'unsigned': 0, 'signed': 0, 'neither': 0, 'not a number': 0}
        for _ in range(4000):
            block = bytearray(rng.randbytes(512) if rng.random() < 0.6 else bytes(512))
            for _ in range(rng.randrange(0, 40) if rng.random() < 0.5 else 0):
                block[rng.randrange(512)] = rng.randrange(256)
            block[148:156] = b' ' * 8
            unsigned = sum(block)
            signed = sum(b - 256 if b > 127 else b for b in block)
            field, kind = rng.choice([(unsigned, 'unsigned'), (signed, 'signed'), (unsigned + 1, 'neither'),
                                      (rng.randrange(0, 99999), 'neither')])
            if field < 0:
                field, kind = 0, 'neither'
            block[148:156] = b'%06o\0 ' % field
            if rng.random() < 0.05:
                block[148 + rng.randrange(8)] = rng.choice((0x38, 0x41, 0x80, 0xff))  # not an octal digit
                kind = 'not a number'
            block = bytes(block)
            try:
                stored = habackup._number(block[148:156])
            except BackupError:
                written_out = False
            else:
                written_out = stored == sum(block[:148]) + 256 + sum(block[156:]) or stored == (
                    sum(b - 256 if b > 127 else b for b in block[:148]) + 256 + sum(b - 256 if b > 127 else b for b in block[156:]))
            self.assertIs(habackup._checksum_ok(block), written_out, kind)
            counts[kind] += 1
        self.assertGreater(min(counts.values()), 40, counts)
        self.assertTrue(habackup._checksum_ok(hx.raw_header('a')))
        self.assertTrue(habackup._checksum_ok(hx.raw_header('é' * 20)), 'bytes above 127: the signed sum')
        high = bytearray(hx.raw_header('é' * 20))
        high[148:156] = b'%06o\0 ' % (sum(high[:148]) + 256 + sum(high[156:]) - 256 * 40)  # what a signed-char tar wrote
        self.assertTrue(habackup._checksum_ok(bytes(high)))

    def test_a_filler_of_words_costs_a_few_steps_per_block(self):
        """IN-41 (cost): a crafted tail of 'ustar' made the probe run its loop once per word -- 140 s of Python for a gigabyte
        of it; now a few steps per block whatever the filler is. Counted (lines of the probe, checksums), not timed."""
        blocks, block = 2048, habackup.BLOCK
        in_step = bytes(habackup.TAR_MAGIC_AT) + b'ustar' + bytes(block - habackup.TAR_MAGIC_AT - 5)
        for label, filler, checksums in (('words', b'ustar' * (blocks * block // 5), None),
                                         ('a word in every block', in_step * blocks, blocks),
                                         ('a word in half of the blocks', (in_step + bytes(block)) * (blocks // 2), blocks // 2),
                                         ('zeros', bytes(blocks * block), 0), ('rubbish', os.urandom(blocks * block), 0)):
            with self.subTest(filler=label), mock.patch.object(habackup, '_checksum_ok',
                                                                wraps=habackup._checksum_ok) as checked:
                answer, lines = count_lines(habackup._Reader.another_header, habackup._Reader(io.BytesIO(filler)))
                self.assertIs(answer, False, 'no header in it')
                self.assertLessEqual(lines, 16 * blocks + 100, 'a few steps per block')
                if checksums is not None:
                    self.assertEqual(checked.call_count, checksums, 'a checksum for each place a header can begin, once')
                self.assertLessEqual(checked.call_count, blocks)

    def test_the_end_of_a_member_with_checks(self):
        """A stream with a checksum or authentication is read to its end for that check; what is behind the tar in it is
        dropped, and a gzip trailer that does not fit stops the app wherever the tar ended."""
        raw = hx.addon_member(compress=False)
        for tail in (os.urandom(5000), hx.tar_bytes([{'name': 'late', 'data': b'x'}]), bytes(2 << 20)):
            packed = gzip.compress(raw + tail, mtime=0)
            for member, good in ((packed, True), (packed[:-8] + bytes(8), False), (packed[:-1], False)):
                with self.subTest(tail=tail[:4], good=good):
                    stream = habackup._Gunzip(io.BytesIO(member))
                    if good:
                        self.assertEqual([row[0] for row in self.walk([], stream=stream, addon=True)[0]][-1], 'config')
                    else:
                        self.assertEqual(self.refused([], stream=stream, addon=True)[0], 'corrupt-archive')

    def test_the_checks_of_any_stream(self):
        """A stream with a `finish` is read to its end and finished, once, before the walk is complete."""
        calls = []

        class Stream(io.BytesIO):
            good = True

            def finish(self):
                calls.append(len(self.read()))
                if not self.good:
                    raise hasecuretar.broken('the check failed')
        data = hx.tar_bytes([{'name': 'a', 'data': b'x'}]) + bytes(3 << 20)
        self.assertEqual([row[0] for row in self.walk([], stream=Stream(data))[0]], ['a'])
        self.assertEqual(calls, [0], 'once, and nothing was left to read')
        Stream.good, report = False, habackup.Report()
        self.assertEqual(self.refused([], stream=Stream(data), report=report), ('corrupt-archive', 'the check failed'))
        self.assertEqual((calls, report.complete), ([0, 0], False))

    def test_v7_and_mixed_headers(self):
        """IN-23: a tar from before POSIX (no magic)."""
        raw = (hx.raw_member('data/', typeflag=b'\0', magic=hx.V7)
               + hx.raw_member('data/a', b'a' * 700, typeflag=b'\0', magic=hx.V7)
               + hx.raw_member('data/l', typeflag=b'2', linkname='a', magic=hx.V7)
               + hx.raw_member('data/h', typeflag=b'1', linkname='data/a', magic=hx.V7)
               + hx.raw_member('b', b'b', prefix='data', magic=hx.USTAR) + hx.raw_member('data/c', b'c', prefix='x', magic=hx.GNU)
               + hx.END)
        out, _report = self.walk([], habackup.Select(symlinks=('data',), hardlinks=True), raw=raw)
        self.assertEqual(out, [('data', 'dir', None, None), ('data/a', 'file', None, b'a' * 700),
                               ('data/l', 'symlink', 'a', None), ('data/h', 'hardlink', 'data/a', None),
                               ('data/b', 'file', None, b'b'), ('data/c', 'file', None, b'c')])
        bad = bytearray(raw)
        bad[3] ^= 1
        self.assertEqual(self.refused([], raw=bytes(bad)), ('corrupt-archive', 'tar header checksum mismatch'))

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
        raw = hx.pax_member({'path': 'real', 'SCHILY.xattr.user.x': 'y', 'LIBARCHIVE.creationtime': '1'})
        self.assertEqual(self.walk([], raw=raw + hx.raw_member('short', b'x') + hx.END)[0], [('real', 'file', None, b'x')])

    def test_extended_header_limits(self):
        """IN-24: records up to 1 MiB, long names up to 64 KiB (an entry name stays at 4096 bytes)."""
        comment = 'x' * (habackup.MAX_PAX - len('1048576 comment=\n'))
        for records, code in ((comment, None), (comment + 'x', 'limit-exceeded')):
            raw = hx.pax_member({'comment': records}) + hx.raw_member('a', b'x') + hx.END
            with self.subTest(pax=len(records)):
                if code is None:
                    self.assertEqual(self.walk([], raw=raw)[0], [('a', 'file', None, b'x')])
                else:
                    self.assertEqual(self.refused([], raw=raw), (code, 'extended header too large'))
        for typeflag in (b'L', b'K'):
            for size in (habackup.MAX_LONG_NAME, habackup.MAX_LONG_NAME + 1):
                raw = hx.raw_member('x', b'n' * size, typeflag=typeflag, magic=hx.GNU) + hx.raw_member('a', b'x') + hx.END
                with self.subTest(typeflag=typeflag, size=size):
                    if size > habackup.MAX_LONG_NAME:
                        self.assertEqual(self.refused([], raw=raw), ('limit-exceeded', 'extended header too large'))
                    else:
                        out, report = self.walk([], raw=raw)
                        self.assertEqual(([row[0] for row in out], report.skip_count('name')),
                                         (['a'], 0) if typeflag == b'K' else ([], 1))
        self.assertEqual((habackup.MAX_PAX, habackup.MAX_LONG_NAME, habackup.MAX_NAME), (1 << 20, 64 << 10, 4096))

    def test_extended_header_records_are_counted(self):
        """IN-24: the megabyte of one header is not the limit of the work: the records of all the extended headers of a
        tar are counted (262,000 headers of 88,000 records each would keep a job busy for 18 hours)."""
        def tar(headers, per=2):
            return b''.join(hx.pax_member({f'k{j}': 'v' for j in range(per)}) + hx.raw_member(f'x{i}', b'x')
                            for i in range(headers)) + hx.END

        def records(data):
            reader = habackup._Reader(io.BytesIO(data))
            while (header := habackup._inner_header(reader)) is not None:
                reader.skip(header.size + (-header.size) % habackup.BLOCK)
            return reader.records
        self.assertEqual((records(tar(5)), records(tar(1, per=11))), (10, 11))
        with mock.patch.object(habackup, 'MAX_PAX_RECORDS', 10):
            self.assertEqual(len(self.walk([], raw=tar(5))[0]), 5, 'ten records are as many as there may be')
            self.assertEqual(self.refused([], raw=tar(6)), ('limit-exceeded', 'too many extended header records'))
            self.assertEqual(self.refused([], raw=tar(1, per=11)), ('limit-exceeded', 'too many extended header records'))
            names = b''.join(hx.raw_member('L', b'long%d\0' % i, typeflag=b'L', magic=hx.GNU) + hx.raw_member(f'x{i}', b'x')
                             for i in range(50)) + hx.END
            self.assertEqual(len(self.walk([], raw=names)[0]), 50, 'a long name is no record')
        self.assertEqual(habackup.MAX_PAX_RECORDS, 50_000_000)
        # every pass over a member counts for itself
        entries = [{'name': 'x/a', 'data': b'1'}, {'name': 'y/b', 'type': 'hardlink', 'linkname': 'x/a'}]
        per_pass = records(hx.tar_bytes(entries))
        self.assertGreater(per_pass, 0)
        for limit, expected in ((per_pass, [('y/b', 'file', None, b'1')]), (per_pass - 1, 'too many extended header records')):
            with self.subTest(limit=limit), mock.patch.object(habackup, 'MAX_PAX_RECORDS', limit):
                if isinstance(expected, str):
                    self.assertEqual(self.refused(entries, habackup.Select(include=('y',))), ('limit-exceeded', expected))
                else:
                    self.assertEqual(self.walk(entries, habackup.Select(include=('y',)))[0], expected)

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
        self.assertEqual((report.skip_count('symlink'), report.skip_names('symlink')),
                         (3, ['nodes/escape', 'nodes/abs', 'other']))
        self.assertIn('3 個符號連結', report.warnings()[0])
        out, report = self.walk(entries)  # no symlink area: every link is skipped
        self.assertFalse([row for row in out if row[1] == 'symlink'])
        self.assertEqual(report.skipped_symlinks, 4)
        out, _report = self.walk(entries, habackup.Select(symlinks=('.',)))
        self.assertEqual(sorted(row[0] for row in out if row[1] == 'symlink'),
                         ['nodes/.bin/tool', 'nodes/escape', 'other'])  # '.': anything that stays inside the tar

    def test_skipped_symlinks_are_sampled_in_every_area(self):
        """OD-26, O-04, NC-34 look for tablespace links among the samples: links elsewhere must not use them up."""
        entries = [{'name': f'modules/l{i}', 'type': 'symlink', 'linkname': '/x'} for i in range(100)]
        entries += [{'name': f'data/postgres/pg_tblspc/{i}', 'type': 'symlink', 'linkname': '/x'} for i in range(100)]
        _out, report = self.walk(entries, habackup.Select(include=('modules', 'data/postgres')))
        self.assertEqual((report.skipped_symlinks, report.skip_count()), (200, 200))
        self.assertEqual(len([n for n in report.skipped_symlink_samples if n.startswith('data/postgres/')]),
                         habackup.SAMPLES)
        self.assertEqual(len(report.skipped_symlink_samples), 2 * habackup.SAMPLES)
        self.assertEqual((len(report.skips['symlink'].key_items()), len(report.skip_names())), (200, habackup.SAMPLES))
        self.assertEqual(report.warnings()[0].count('modules/l'), 5, 'a log line names five')

    def test_link_chains_cannot_climb_out_in_any_order(self):
        """Review HA-SEC-03 (probe P1): each link is lexically inside `nodes`, the kernel resolves the chain upwards."""
        chain = [{'name': 'nodes/a', 'type': 'symlink', 'linkname': '.'},
                 {'name': 'nodes/b', 'type': 'symlink', 'linkname': 'a/..'},
                 {'name': 'nodes/c', 'type': 'symlink', 'linkname': 'b/..'},
                 {'name': 'nodes/d', 'type': 'symlink', 'linkname': 'c/../x'}]
        base = [{'name': 'nodes', 'type': 'dir'}, {'name': 'nodes/pkg', 'type': 'dir'},
                {'name': 'nodes/pkg/bin', 'type': 'dir'}]
        good = [{'name': 'nodes/pkg/bin/tool', 'type': 'symlink', 'linkname': '../../pkg/./index.js'},
                {'name': 'nodes/pkg/sub', 'type': 'symlink', 'linkname': 'bin'}]
        for order in (chain, list(reversed(chain))):
            out, report = self.walk(base + order + good, habackup.Select(symlinks=('nodes',)))
            links = sorted(row[0] for row in out if row[1] == 'symlink')
            self.assertEqual(links, ['nodes/a', 'nodes/pkg/bin/tool', 'nodes/pkg/sub'])
            self.assertEqual(report.skipped_symlinks, 3)
        self.assertFalse(habackup._symlink_ok('nodes/x', 'pkg/../..', 'nodes'))
        self.assertTrue(habackup._symlink_ok('nodes/x/y', '../../nodes/pkg', '.'))

    def test_selection_fifos_and_budgets(self):
        """IN-34, IN-40: four million entries, 16 TiB."""
        entries = [{'name': 'data', 'type': 'dir'}, {'name': 'data/postgres', 'type': 'dir'},
                   {'name': 'data/postgres/PG_VERSION', 'data': b'16\n'}, {'name': 'data/postgresql.conf', 'data': b'x'},
                   {'name': 'data/postgres/log', 'type': 'dir'}, {'name': 'data/postgres/log/a', 'data': b'l'},
                   {'name': 'data/pipe', 'type': 'fifo'}, {'name': 'config', 'type': 'dir'}]
        out, report = self.walk(entries, habackup.Select(include=('data/postgres',), exclude=('data/postgres/log',)))
        self.assertEqual([row[0] for row in out], ['data/postgres', 'data/postgres/PG_VERSION'])
        self.assertEqual((report.entries, report.skipped_other, report.skip_count()), (8, 0, 0))
        out, report = self.walk(entries)
        self.assertEqual((report.skipped_other, report.skip_names('fifo')), (1, ['data/pipe']))
        self.assertNotIn('data/pipe', [row[0] for row in out])
        self.assertEqual(self.refused(entries, habackup.Select(max_members=7)),
                         ('limit-exceeded', 'too many entries in an inner tar'))
        self.walk(entries, habackup.Select(max_members=8))
        self.assertEqual(self.refused(entries, habackup.Select(max_bytes=4)),
                         ('limit-exceeded', 'the selected files are too large'))
        self.walk(entries, habackup.Select(max_bytes=5))
        self.assertEqual(self.walk(entries, habackup.Select(include=()))[0], [])
        self.assertEqual((habackup.Select().max_members, habackup.Select().max_bytes), (4_000_000, 16 * 1024 ** 4))
        huge = [{'name': 'a', 'pax': {'size': '1'}, 'data': b'x'}]
        raw = hx.pax_member({'size': str(16 * 1024 ** 4 + 1)}) + hx.raw_header('a')
        self.assertEqual(self.refused(huge, raw=raw), ('limit-exceeded', 'the selected files are too large'))

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
        self.assertEqual((report.secret_files, report.skip_count()), (3, 0))
        self.assertEqual(report.addon, habackup.AddonInfo('woow-n8n', '2.43.6', 'ghcr.io/woowtech/woow-ha-n8n-amd64',
                                                          'amd64', 'n8n'))
        self.assertNotIn('fixture-admin-secret', repr(report.addon) + repr(out))
        out, report = self.walk(entries, addon=False)  # e.g. the share folder: a file called addon.json is data
        self.assertEqual([row[0] for row in out], ['.', 'addon.json', 'data', 'data/keep.txt'])
        self.assertIsNone(report.addon)
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
        code, error = code_of(second.read_all, 0)
        self.assertEqual((code, error.details['reason']), ('limit-exceeded', 'file too large to read'))
        say_member(self, error)
        walk.close()
        self.assertEqual(first.fileobj, first)
        out = io.BytesIO()
        walk = habackup.iter_entries(io.BytesIO(hx.tar_bytes([{'name': 'a', 'data': b'x' * 3_000_000}])))
        self.assertEqual(next(walk).copy_to(out), 3_000_000)

    def test_addon_json_fields(self):
        """IN-12 to IN-17: only what tells which add-on it is must be right."""
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
        for bad, reason in ((b'[]', 'addon.json has no system section'), (b'{"user": {}}', 'addon.json has no system section'),
                            (b'{"system": []}', 'addon.json has no system section'),
                            (b'{"system": {}}', 'addon.json system.slug is invalid'),
                            (b'{"system": {"slug": "../x"}, "version": "1"}', 'addon.json system.slug is invalid'),
                            (b'{"system": {"slug": 5}, "version": "1"}', 'addon.json system.slug is invalid'),
                            (b'not json', 'addon.json is not strict JSON'),
                            (b'{"system": {"slug": "x"}, "version": "1", "version": "2"}', 'addon.json is not strict JSON')):
            with self.subTest(bad=bad[:30]):
                code, error = code_of(habackup.parse_addon_json, bad)
                self.assertEqual((code, error.details['reason'], error.details['scope']), ('corrupt-archive', reason, 'member'))
        for label, value in DescribeTests.ODD.items():
            doc = {'system': {'slug': 'x', 'name': value}, 'version': value, 'state': value,
                   'user': {'image': value, 'version': '9'}}
            with self.subTest(odd=label):
                info = habackup.parse_addon_json(json.dumps(doc).encode())
                self.assertEqual((info.slug, info.version, info.arch, info.state), ('x', '', 'unknown', ''))
                self.assertIn(info.image, (None, 'x' * 512))
                self.assertIsNone(info.image)
                self.assertTrue(info.name.isprintable() and len(info.name) <= 200)
        for version in ('1 2', '1.0 (beta)', 'v:1', '', 'x' * 65):
            with self.subTest(version=version[:10]):
                info = habackup.parse_addon_json(json.dumps({'system': {'slug': 'x'}, 'version': version}).encode())
                self.assertEqual(info.version, '')
        room = habackup.MAX_ADDON_JSON - len(json.dumps({'system': {'slug': 'x'}, 'x': ''}))
        doc = json.dumps({'system': {'slug': 'x'}, 'x': 'y' * room}).encode()
        self.assertEqual((len(doc), habackup.MAX_ADDON_JSON), (32 << 20, 32 << 20))
        self.assertEqual(habackup.parse_addon_json(doc).slug, 'x')
        code, error = code_of(habackup.parse_addon_json, doc + b' ')
        self.assertEqual((code, error.details['reason']), ('limit-exceeded', 'addon.json too large'))
        say_member(self, error)
        with mock.patch.object(habackup, 'MAX_ADDON_JSON', 100):
            entries = [{'name': 'addon.json', 'data': b' ' * 60 + b'{"system": {"slug": "x"}}' + b' ' * 15}]
            self.assertEqual(self.walk(entries, addon=True)[1].addon.slug, 'x')
            entries[0]['data'] += b' '
            self.assertEqual(self.refused(entries, addon=True), ('limit-exceeded', 'addon.json too large'))
            self.assertEqual(self.refused([], raw=hx.raw_header('addon.json', size=101), addon=True),
                             ('limit-exceeded', 'addon.json too large'), 'without reading it')


class SkippedEntryTests(WalkCase):
    """IN-19, IN-27, IN-28, IN-35, IN-38: one entry that cannot be moved is left out and listed, everything else moves."""

    def test_names_no_file_can_have(self):
        long_name = 'd/' + 'n' * 4095
        flaws = [hx.raw_member('', b'1'), hx.raw_member('d/a\nb', b'2'), hx.raw_member('d/a\tb/', typeflag=b'5'),
                 hx.raw_member('d/a\tb/c', b'3'), hx.raw_member('d/\x7f', typeflag=b'2', linkname='x'),
                 hx.pax_member({'path': long_name}) + hx.raw_member('s', b'4' * 600),
                 hx.pax_member({'path': b'd/nul\0l'}) + hx.raw_member('s', b'5')]
        raw = (hx.raw_member('d/', typeflag=b'5') + b''.join(flaws) + hx.raw_member('d/good', b'good')
               + hx.pax_member({'path': 'd/' + 'n' * 4094}) + hx.raw_member('s', b'ok') + hx.END)
        out, report = self.walk([], raw=raw)
        self.assertEqual([(row[0][:8], row[3]) for row in out], [('d', None), ('d/good', b'good'), ('d/nnnnnn', b'ok')])
        self.assertEqual(report.skip_count('name'), len(flaws))
        self.assertEqual(report.skip_names('name'), ['（空白檔名）', 'd/a b', 'd/a b', 'd/a b/c', 'd/', 'd/' + 'n' * 118,
                                                     'd/nul l'])
        self.assertTrue(all(name.isprintable() for name in report.skip_names()))
        self.assertEqual((report.files, report.bytes), (2, 6))
        # Outside what the caller takes nothing is lost: not listed (nothing at all selected: a walk for addon.json).
        for include, count in ((('e',), 1), ((), 0), (('d',), len(flaws))):
            with self.subTest(include=include):
                self.assertEqual(self.walk([], habackup.Select(include=include), raw=raw)[1].skip_count(), count)
        self.assertEqual(self.walk([], habackup.Select(exclude=('d',)), raw=raw)[1].skip_count(), 1)

    def test_they_still_obey_the_structure(self):
        """A bad name hides nothing: absolute, `..`, twice, below a link -- the app is stopped."""
        for label, blocks, reason in (
                ('absolute', hx.raw_member('/a\nb'), 'absolute entry name'),
                ('dotdot', hx.raw_member('a\n/../b'), 'entry name with an empty, "." or ".." component'),
                ('long dotdot', hx.pax_member({'path': 'n/' * 3000 + '../x'}) + hx.raw_member('s'),
                 'entry name with an empty, "." or ".." component'),
                ('twice', hx.raw_member('a\nb') * 2, 'duplicate entry'),
                ('below', hx.raw_member('a\nb') + hx.raw_member('a\nb/c'), 'entry below a file or link'),
                ('replaces', hx.raw_member('a\nb/c') + hx.raw_member('a\nb'), 'a non-directory replaces a directory'),
                ('type', hx.raw_member('a\nb', typeflag=b'S'), 'entry type not allowed (sparse, contiguous or unknown)'),
                ('data', hx.raw_member('a\nb', b'x', typeflag=b'5'), 'a non-file entry carries data')):
            with self.subTest(case=label):
                self.assertEqual(self.refused([], raw=blocks + hx.END), ('corrupt-archive', reason))

    def test_device_nodes(self):
        entries = [{'name': 'dev', 'type': 'dir'}, {'name': 'dev/sda', 'type': 'blk'}, {'name': 'dev/mem', 'type': 'chr'},
                   {'name': 'dev/x', 'data': b'x'}, {'name': 'null', 'type': 'chr'}]
        out, report = self.walk(entries)
        self.assertEqual([row[:2] for row in out], [('dev', 'dir'), ('dev/x', 'file')])
        self.assertEqual(report.skip_names('device'), ['dev/sda', 'dev/mem', 'null'])
        self.assertEqual(report.skip_text(), '裝置檔 3 個')
        self.assertEqual(self.walk(entries, habackup.Select(include=('dev',)))[1].skip_names(), ['dev/sda', 'dev/mem'])
        self.assertEqual(self.refused([*entries, {'name': 'null', 'data': b'x'}]), ('corrupt-archive', 'duplicate entry'))

    def test_a_secrets_place(self):
        """Never read: whatever stands in the place of a secret file, and whatever lies below it."""
        for kind in ('dir', 'symlink', 'hardlink', 'fifo', 'chr'):
            for name in ('data/options.json', 'data/secrets/api_server_key', 'data/pi-agent/claude/.credentials.json'):
                entries = [{'name': 'a', 'data': b'x'}, {'name': name, 'type': kind, 'linkname': 'a'},
                           {'name': 'z', 'data': b'z'}]
                with self.subTest(kind=kind, name=name):
                    out, report = self.walk(entries, habackup.Select(symlinks=('.',), hardlinks=True))
                    self.assertEqual([row[0] for row in out], ['a', 'z'])
                    self.assertEqual((report.skip_names('secret'), report.secret_files, report.skip_count()), ([name], 0, 1))
                    self.assertEqual(self.walk(entries, habackup.Select(include=('a', 'z')))[1].skip_count(), 0)
        below = [{'name': 'data/options.json', 'type': 'dir'}, {'name': 'data/options.json/x', 'data': b'fixture-secret'},
                 {'name': 'data/odoo.conf/y/z', 'data': b'fixture-secret'},
                 {'name': 'data/pi-agent/codex/auth.json/deep/er', 'data': b'fixture-secret'},
                 {'name': 'data/odoo.conf.bak', 'data': b'kept'}, {'name': 'data/options.jsonx', 'data': b'kept'}]
        out, report = self.walk(below)
        self.assertEqual([row[0] for row in out], ['data/odoo.conf.bak', 'data/options.jsonx'])
        self.assertEqual((report.secret_files, report.skip_names()), (3, ['data/options.json']))
        self.assertNotIn(b'fixture-secret', repr(out).encode())
        self.assertFalse(habackup.never_read('data'))
        self.assertTrue(all(habackup.never_read(name) and habackup.never_read(name + '/a/b/c')
                            for name in habackup.NEVER_READ))

    def test_addon_json_in_another_shape_stops_the_app(self):
        for kind in ('dir', 'symlink', 'hardlink', 'fifo', 'chr'):
            with self.subTest(kind=kind):
                entries = [{'name': 'x', 'data': b'x'}, {'name': 'addon.json', 'type': kind, 'linkname': 'x'}]
                self.assertEqual(self.refused(entries, addon=True),
                                 ('corrupt-archive', 'unexpected entry type for a metadata file'))

    def test_files_too_large_for_the_caller(self):
        """IN-19: a caller that reads a whole file may leave a too large one out instead of stopping."""
        entries = [{'name': 'm1/__manifest__.py', 'data': b'x' * 101}, {'name': 'm2/__manifest__.py', 'data': b'y' * 100}]
        report = habackup.Report()
        got = {}
        for entry in habackup.iter_entries(io.BytesIO(hx.tar_bytes(entries)), None, report, addon=False):
            got[entry.name] = entry.read_or_skip(100)
        self.assertEqual(got, {'m1/__manifest__.py': None, 'm2/__manifest__.py': b'y' * 100})
        self.assertTrue(report.complete)
        self.assertEqual((report.skip_names('large'), report.skip_text('large')),
                         (['m1/__manifest__.py'], '大小超出上限的設定檔 1 個'))

    def test_the_list_for_the_confirmation(self):
        """What a confirmation is made of covers every name, however many there are: another name, another key."""
        def skips(count, last='last', **kwargs):
            raw = b''.join(hx.raw_member(f'd{i:05}', typeflag=b'3') for i in range(count - 1))
            raw += hx.raw_member(last, typeflag=b'3') + hx.raw_member('a\nb', b'x') + hx.END
            return self.walk([], raw=raw, report=habackup.Report(**kwargs))[1]
        few, many = habackup.MAX_KEPT_NAMES, habackup.MAX_KEPT_NAMES + 1
        for count in (3, few, many):
            report, other, more = skips(count), skips(count, 'lost'), skips(count + 1)
            with self.subTest(count=count):
                self.assertEqual((report.skip_count('device'), report.skip_count()), (count, count + 1))
                names = report.skips['device']
                self.assertEqual((len(names), names.count, len(names.first)), (count, count, min(count, 20)))
                self.assertEqual(len(names.key_items()), count if count <= few else 2)
                self.assertLessEqual(len(names._names), few, 'never more in memory')
                keys = {tuple(sorted(r.skips['device'].key_items())) for r in (report, other, more)}
                self.assertEqual(len(keys), 3)
                self.assertEqual(names.key_items(), skips(count).skips['device'].key_items(), 'the same file, the same key')
        report = skips(many)
        self.assertEqual(report.skip_names(), ['a b', *(f'd{i:05}' for i in range(20))], 'kind by kind')
        self.assertEqual(report.skip_text(), '檔名空白、太長或含控制字元的項目 1 個、裝置檔 1001 個')
        self.assertEqual((report.skip_text('fifo'), report.skip_names('fifo'), report.skip_count('fifo')), ('', [], 0))
        self.assertEqual(len(report.warnings()), 2)
        self.assertTrue(all(line.isprintable() for line in report.warnings()))
        backwards = habackup.SkipList()
        for name in reversed(['last', *(f'd{i:05}' for i in range(many - 1))]):
            backwards.add(name)
        self.assertEqual(backwards.key_items(), report.skips['device'].key_items(), 'in any order')

        class Names(habackup.SkipList):  # an importer's own collector (haissues.Names)
            pass
        self.assertIsInstance(skips(3, names=Names).skips['device'], Names)

    def test_log_lines_cannot_be_forged(self):
        raw = hx.raw_member('a\n2026-11-25 fake line', b'x') + hx.raw_member('b\u202eevil', typeflag=b'3') + hx.END
        lines = self.walk([], raw=raw)[1].warnings()
        self.assertEqual(len(lines), 2)
        self.assertFalse([c for line in lines for c in line if c in '\n\r\u202e'])


class HardLinkTests(WalkCase):
    """IN-39: a hard link is the same file under another name -- handed out as a link when the caller takes links and
    has that file, else as a file with its content; left out (and listed) only when there is no content to take."""

    def files(self, entries, select=None, **kwargs):
        out, report = self.walk(entries, select, **kwargs)
        return {row[0]: row[3] if row[1] == 'file' else (row[1], row[2]) for row in out if row[1] != 'dir'}, report

    def test_a_link_for_a_caller_that_takes_links(self):
        entries = [{'name': 'a', 'data': b'1'}, {'name': 'b', 'type': 'hardlink', 'linkname': './a'}]
        out, report = self.walk(entries, habackup.Select(hardlinks=True))
        self.assertEqual(out[1], ('b', 'hardlink', 'a', None))
        self.assertEqual((report.hardlinks, report.files, report.copied_links, report.bytes), (1, 1, 0, 1))

    def test_a_copy_for_every_other_caller(self):
        entries = [{'name': 'a', 'data': b'one' * 1000, 'mode': 0o640, 'uid': 33, 'gid': 44},
                   {'name': 'b', 'type': 'hardlink', 'linkname': 'a', 'mode': 0o600, 'uid': 7, 'gid': 8},
                   {'name': 'c', 'type': 'hardlink', 'linkname': 'a'}, {'name': 'd', 'data': b'two'}]
        files, report = self.files(entries)
        self.assertEqual(files, {'a': b'one' * 1000, 'b': b'one' * 1000, 'c': b'one' * 1000, 'd': b'two'})
        self.assertEqual((report.files, report.hardlinks, report.copied_links, report.bytes, report.skip_count()),
                         (4, 0, 2, 9003, 0))
        out, _report = self.walk(entries)
        self.assertEqual([row[0] for row in out], ['a', 'd', 'b', 'c'], 'after the walk')
        seen = {}
        for entry in habackup.iter_entries(io.BytesIO(hx.tar_bytes(entries)), None, habackup.Report(), addon=False):
            seen[entry.name] = (entry.kind, entry.mode, entry.uid, entry.gid, entry.size, entry.linkname)
        self.assertEqual(seen['b'], ('file', 0o600, 7, 8, 3000, None))

    def test_links_to_what_is_not_taken(self):
        cases = [
            ('not selected', [{'name': 'x/a', 'data': b'1'}, {'name': 'y/b', 'type': 'hardlink', 'linkname': 'x/a'}]),
            ('later, not selected', [{'name': 'y/b', 'type': 'hardlink', 'linkname': 'x/a'}, {'name': 'x/a', 'data': b'1'}]),
            ('through an unselected link', [{'name': 'x/a', 'data': b'1'}, {'name': 'x/l', 'type': 'hardlink', 'linkname': 'x/a'},
                                            {'name': 'y/b', 'type': 'hardlink', 'linkname': 'x/l'}]),
            ('through several links', [{'name': 'y/b', 'type': 'hardlink', 'linkname': 'x/m'},
                                       {'name': 'x/m', 'type': 'hardlink', 'linkname': 'x/l'},
                                       {'name': 'x/l', 'type': 'hardlink', 'linkname': 'x/a'}, {'name': 'x/a', 'data': b'1'}]),
            ('a name no file can have', [{'name': 'y/a\tb', 'data': b'1'},
                                         {'name': 'y/b', 'type': 'hardlink', 'linkname': 'y/a\tb'}]),
        ]
        for label, entries in cases:
            for hardlinks in (False, True):
                with self.subTest(case=label, hardlinks=hardlinks):
                    files, report = self.files(entries, habackup.Select(include=('y',), hardlinks=hardlinks))
                    self.assertEqual(files, {'y/b': b'1'})
                    self.assertEqual((report.skip_count('hardlink'), report.copied_links), (0, 1))
        later = [{'name': 'b', 'type': 'hardlink', 'linkname': 'a'}, {'name': 'a', 'data': b'1'}]
        self.assertEqual(self.files(later)[0], {'a': b'1', 'b': b'1'})
        out, report = self.walk(later, habackup.Select(hardlinks=True))
        self.assertEqual(out, [('a', 'file', None, b'1'), ('b', 'hardlink', 'a', None)], 'a link after all')
        self.assertEqual((report.hardlinks, report.copied_links), (1, 0))
        out, _report = self.walk([{'name': 'a', 'data': b'1'}, {'name': 'b', 'type': 'hardlink', 'linkname': 'a'}],
                                 habackup.Select(include=('a',)))  # an unselected link is ignored
        self.assertEqual([row[0] for row in out], ['a'])

    def test_links_to_nothing_are_listed(self):
        base = [{'name': 'a', 'data': b'1'}, {'name': 'd', 'type': 'dir'}, {'name': 's', 'type': 'symlink', 'linkname': 'a'},
                {'name': 'f', 'type': 'fifo'}, {'name': 'c', 'type': 'chr'}]
        for target in ('missing', 'd', 's', 'f', 'c', 'b', '../a', '/a', '/etc/shadow', 'a/../a', '', '.', 'a\0x', 'a/x', './/a'):
            entries = [*base, {'name': 'b', 'type': 'hardlink', 'linkname': target.replace('\0', ' '),
                               'pax': {'linkpath': target} if '\0' in target else None}, {'name': 'z', 'data': b'z'}]
            for hardlinks in (False, True):
                with self.subTest(target=target, hardlinks=hardlinks):
                    files, report = self.files(entries, habackup.Select(hardlinks=hardlinks, symlinks=('.',)))
                    self.assertEqual(set(files), {'a', 's', 'z'})
                    self.assertEqual((report.skip_names('hardlink'), report.hardlinks), (['b'], 0))
                    self.assertIn('取不到內容的硬連結 1 個', report.skip_text())
        circle = [{'name': 'a', 'type': 'hardlink', 'linkname': 'b'}, {'name': 'b', 'type': 'hardlink', 'linkname': 'a'}]
        self.assertEqual(self.files(circle)[1].skip_names(), ['a', 'b'])

    def test_a_secret_is_never_copied(self):
        """A second name must not hand out what is never read: a secret file, addon.json, what the caller excludes."""
        secret = b'fixture-admin-secret'
        for target, select, addon in (
                ('data/options.json', habackup.Select(), True),
                ('data/odoo.conf', habackup.Select(include=('data/x', 'data/y')), True),
                ('data/options.json/below', habackup.Select(), True), ('addon.json', habackup.Select(), True),
                ('data/.ssh/id', habackup.Select(exclude=('data/.ssh',)), False),
                ('data/.ssh/id', habackup.Select(include=('data',), exclude=('data/.ssh',), hardlinks=True), False)):
            doc = json.dumps({'system': {'slug': 'x'}, 'version': '1', 'user': {'options': {'pw': secret.decode()}}}).encode()
            for order in (0, 1):
                entries = [{'name': target, 'data': doc if target == 'addon.json' else secret},
                           {'name': 'data/x', 'type': 'hardlink', 'linkname': target}]
                entries = entries[::-1] if order else entries
                entries += [{'name': 'data/y', 'type': 'hardlink', 'linkname': 'data/x'}]  # through the first link
                with self.subTest(target=target, include=select.include, order=order):
                    files, report = self.files(entries, select, addon=addon)
                    self.assertEqual(report.skip_names('hardlink'), ['data/x', 'data/y'])
                    self.assertNotIn(secret, repr(files).encode())
                    self.assertFalse({'data/x', 'data/y'} & set(files))
        files, _report = self.files([{'name': 'addon.json', 'data': b'share data'},
                                     {'name': 'b', 'type': 'hardlink', 'linkname': 'addon.json'}], addon=False)
        self.assertEqual(files['b'], b'share data', 'in a folder it is a file like any other')
        for middle, select in (('data/options.json', habackup.Select()), ('data/.ssh/l', habackup.Select(exclude=('data/.ssh',)))):
            entries = [{'name': 'data/plain', 'data': b'plain'}, {'name': middle, 'type': 'hardlink', 'linkname': 'data/plain'},
                       {'name': 'x', 'type': 'hardlink', 'linkname': middle}, {'name': 'y', 'type': 'hardlink', 'linkname': 'x'}]
            for order in (entries, entries[::-1]):
                with self.subTest(middle=middle, first=order[0]['name']):
                    files, report = self.files(order, select)
                    self.assertEqual((files, report.skip_names('hardlink').sort()), ({'data/plain': b'plain'}, None))
                    self.assertEqual(sorted(report.skip_names('hardlink')), ['x', 'y'])

    def test_a_caller_can_ask_for_the_content(self):
        """Entry.copy_later: a module that did not keep the linked file (CM-11, H-01, OP-11)."""
        entries = [{'name': 'a', 'data': b'1'}, {'name': 'b', 'type': 'hardlink', 'linkname': 'a'},
                   {'name': 'c', 'type': 'hardlink', 'linkname': 'a'}, {'name': 'e', 'type': 'hardlink', 'linkname': 'd'},
                   {'name': 'd', 'data': b'2'}]
        report, seen = habackup.Report(), []
        for entry in habackup.iter_entries(io.BytesIO(hx.tar_bytes(entries)), habackup.Select(hardlinks=True), report,
                                           addon=False):
            seen.append((entry.name, entry.kind, entry.read_all(10) if entry.kind == 'file' else entry.linkname))
            if entry.kind == 'hardlink' and entry.name in ('b', 'e'):
                entry.copy_later()
        self.assertEqual(seen, [('a', 'file', b'1'), ('b', 'hardlink', 'a'), ('c', 'hardlink', 'a'), ('d', 'file', b'2'),
                                ('e', 'hardlink', 'd'), ('b', 'file', b'1'), ('e', 'file', b'2')])
        self.assertEqual((report.files, report.hardlinks, report.copied_links, report.complete), (4, 1, 2, True))
        with self.assertRaises(StopIteration):
            walk = habackup.iter_entries(io.BytesIO(hx.tar_bytes(entries[:1])), None, None, addon=False)
            next(walk).copy_later()  # a file has nothing to copy
            next(walk)

    def test_several_links_to_one_file(self):
        big, small = b'B' * (habackup.LINK_MEMORY + 1), b's' * 10
        entries = [{'name': 'x/big', 'data': big}, {'name': 'x/small', 'data': small}]
        entries += [{'name': f'y/b{i}', 'type': 'hardlink', 'linkname': 'x/big'} for i in range(habackup.MAX_LINK_PASSES + 2)]
        entries += [{'name': f'y/s{i}', 'type': 'hardlink', 'linkname': 'x/small'} for i in range(50)]
        files, report = self.files(entries, habackup.Select(include=('y',)))
        copied = [name for name, data in files.items() if data == big]
        self.assertEqual(copied, [f'y/b{i}' for i in range(habackup.MAX_LINK_PASSES)], 'one pass over the member each')
        self.assertEqual(report.skip_names(), [f'y/b{habackup.MAX_LINK_PASSES}', f'y/b{habackup.MAX_LINK_PASSES + 1}'])
        self.assertEqual([name for name, data in files.items() if data == small], [f'y/s{i}' for i in range(50)])
        files, report = self.files(entries, habackup.Select(include=('y',), hardlinks=True))
        self.assertEqual((files['y/b0'], files['y/b1'], files['y/b5']), (big, ('hardlink', 'y/b0'), ('hardlink', 'y/b0')))
        self.assertEqual((report.files, report.hardlinks, report.skip_count()), (2, 54, 0), 'the content once')

    def test_copies_count(self):
        entries = [{'name': 'x/a', 'data': b'1' * 100}, {'name': 'y/b', 'type': 'hardlink', 'linkname': 'x/a'},
                   {'name': 'y/c', 'type': 'hardlink', 'linkname': 'x/a'}]
        self.files(entries, habackup.Select(include=('y',), max_bytes=200))
        self.assertEqual(self.refused(entries, habackup.Select(include=('y',), max_bytes=199)),
                         ('limit-exceeded', 'the selected files are too large'))
        with mock.patch.object(habackup, 'MAX_LINK_COPIES', 1):
            files, report = self.files(entries, habackup.Select(include=('y',)))
            self.assertEqual((files, report.skip_names()), ({'y/b': b'1' * 100}, ['y/c']))

    def test_the_second_pass_reads_the_same_member(self):
        """The real member streams: decrypted and gunzipped again; a stream that cannot be read again lists the link."""
        entries = [{'name': './addon.json', 'data': json.dumps({'system': {'slug': 'x'}, 'version': '1'}).encode()},
                   {'name': 'x/a', 'data': os.urandom(2 << 20)}, {'name': 'y/b', 'type': 'hardlink', 'linkname': 'x/a'}]
        member = hx.tar_bytes(entries, compress=True)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'b.tar'
            path.write_bytes(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', member)]))
            with habackup.open_backup(path) as ha, ha.open_addon(hx.ODOO) as stream:
                report, calls = habackup.Report(), []
                got = {e.name: e.read_all(4 << 20) for e in habackup.iter_entries(
                    stream, habackup.Select(include=('y',)), report, checkpoint=lambda: calls.append(1))}
            self.assertEqual(got, {'y/b': entries[1]['data']})
            self.assertTrue(report.complete)

        class Once(io.RawIOBase):
            def __init__(self, data):
                super().__init__()
                self.data = io.BytesIO(data)

            def read(self, n=-1):
                return self.data.read(n)
        out, report = self.walk([], habackup.Select(include=('y',)), stream=Once(gzip.decompress(member)), addon=True)
        self.assertEqual((out, report.skip_names()), ([], ['y/b']))

    def test_random_trees(self):
        """Files and links in any order, number and format against a plain model: every selected name that has content
        comes exactly once, with that content; every other selected link is listed; nothing else is handed out."""
        rng = random.Random(20261125)
        for round_ in range(150):
            names = [f'{rng.choice("ab")}/n{i}' for i in range(rng.randrange(2, 12))]
            files = {name: rng.randbytes(rng.randrange(0, 40)) for name in names if rng.random() < 0.5}
            links = {name: rng.choice([*names, 'b/none', '../x']) for name in names if name not in files}
            order = list(names)
            rng.shuffle(order)
            entries = [{'name': name, 'data': files[name]} if name in files else
                       {'name': name, 'type': 'hardlink', 'linkname': links[name]} for name in order]

            def content(name, hops=0):
                return files[name] if name in files else content(links[name], hops + 1) if name in links and hops < 8 else None
            for hardlinks in (False, True):
                select = habackup.Select(include=('a',), exclude=('a/n1',), hardlinks=hardlinks)
                out, report = self.walk(entries, select, fmt=rng.choice([tarfile.PAX_FORMAT, tarfile.GNU_FORMAT,
                                                                         tarfile.USTAR_FORMAT]))
                got = {}
                for name, kind, linkname, data in out:
                    self.assertNotIn(name, got, 'once')
                    if kind == 'hardlink':
                        self.assertIn(linkname, got, 'the file it names came before')
                    got[name] = got[linkname] if kind == 'hardlink' else data
                chosen = [name for name in names if name.startswith('a/') and name != 'a/n1']
                resolved = {name: content(name) for name in chosen}

                def withheld(name, hops=0):  # at any step of the chain
                    return name == 'a/n1' or name in links and hops < 8 and withheld(links[name], hops + 1)
                expected = {name: data for name, data in resolved.items() if data is not None and not withheld(name)}
                with self.subTest(round=round_, hardlinks=hardlinks):
                    self.assertEqual(got, expected)
                    self.assertEqual(report.skip_count('hardlink'), len(chosen) - len(expected))
                    self.assertEqual(report.bytes, sum(len(row[3]) for row in out if row[1] == 'file'))

    @hx.needs_crypto
    def test_the_second_pass_of_an_encrypted_member(self):
        entries = [{'name': 'x/a', 'data': os.urandom(3 << 20)}, {'name': 'y/b', 'type': 'hardlink', 'linkname': 'x/a'}]
        member = hx.v3_encrypt(hx.tar_bytes(entries, compress=True))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'b.tar'
            path.write_bytes(hx.outer_bytes([(f'{hx.ODOO}.tar.gz', member)], hx.ha_doc(protected=True)))
            with habackup.open_backup(path) as ha, ha.open_addon(hx.ODOO, hasecuretar.Keys(hx.PASSWORD)) as stream:
                got = {e.name: e.read_all(4 << 20) for e in habackup.iter_entries(stream, habackup.Select(include=('y',)))}
        self.assertEqual(got, {'y/b': entries[0]['data']})

    def test_a_damaged_member_gives_no_copies(self):
        entries = [{'name': 'x/a', 'data': os.urandom(5000)}, {'name': 'y/b', 'type': 'hardlink', 'linkname': 'x/a'}]
        packed = gzip.compress(hx.tar_bytes(entries), mtime=0)
        stream = habackup._Gunzip(io.BytesIO(packed[:-8] + bytes(8)))
        stream.reopen = lambda: self.fail('the first pass was not complete')
        self.assertEqual(self.refused([], habackup.Select(include=('y',)), stream=stream, addon=False)[0], 'corrupt-archive')


    def second(self, entries, again, select=None):
        """Walk a gzip member of `entries` whose second pass reads the bytes `again` instead; what was handed out, the
        error's reason, the passes and how many of them were closed."""
        passes, closed = [], []

        def stream(data):
            result = habackup._Gunzip(io.BytesIO(data))

            def reopen():
                passes.append(1)
                return stream(again)
            result.reopen, result.close = reopen, lambda: closed.append(1)
            return result
        report, got, reason = habackup.Report(), {}, None
        try:
            for entry in habackup.iter_entries(stream(gzip.compress(hx.tar_bytes(entries), mtime=0)), select, report, addon=False):
                got[entry.name] = entry.read_all(1 << 22) if entry.kind == 'file' else entry.linkname
        except BackupError as error:
            reason = error.details['reason']
        return got, reason, len(passes), len(closed), report

    def test_the_second_pass_is_checked_like_the_first(self):
        """What a copy is made of was read again: the member's checksum must hold for that reading too, to its end."""
        entries = [{'name': 'x/a', 'data': b'first'}, {'name': 'y/b', 'type': 'hardlink', 'linkname': 'x/a'},
                   {'name': 'z', 'data': os.urandom(3 << 20)}]
        packed = gzip.compress(hx.tar_bytes(entries), mtime=0)
        select = habackup.Select(include=('y',))
        got, reason, passes, closed, report = self.second(entries, packed, select)
        self.assertEqual((got, reason, passes, closed, report.complete), ({'y/b': b'first'}, None, 1, 1, True))
        for label, again, reason in (('trailer', packed[:-8] + bytes(8), 'gzip checksum mismatch'),
                                     ('cut', packed[:-2000], 'gzip stream is truncated'),
                                     ('cut early', packed[:len(packed) // 2], 'gzip stream is truncated')):
            with self.subTest(again=label):
                result = self.second(entries, again, select)
                self.assertEqual((result[1:4], result[4].complete), ((reason, 1, 1), False))
        # the same where the link names nothing: that pass ends at the end of the archive, not at what it looked for, and
        # the rest of the stream (more than one read) still has to hold its checksum
        gone = [{'name': 'x/a', 'data': b'first'}, {'name': 'y/b', 'type': 'hardlink', 'linkname': 'x/gone'}]
        padded = gzip.compress(hx.tar_bytes(gone) + bytes(3 << 20), mtime=0)
        got, reason, passes, closed, report = self.second(gone, padded, select)
        self.assertEqual((got, reason, passes, closed, report.skip_names('hardlink'), report.complete),
                         ({}, None, 1, 1, ['y/b'], True))
        for label, again, reason in (('trailer', padded[:-8] + bytes(8), 'gzip checksum mismatch'),
                                     ('cut', padded[:-2000], 'gzip stream is truncated')):
            with self.subTest(again=label, names='nothing'):
                result = self.second(gone, again, select)
                self.assertEqual((result[1:4], result[4].complete), ((reason, 1, 1), False))

    def test_no_second_pass_for_nothing(self):
        """Links that are known to have no content are listed at once: the member is not read again for them."""
        secret = [{'name': 'data/options.json', 'data': b'{}'}, {'name': 'x', 'type': 'hardlink', 'linkname': 'data/options.json'},
                  {'name': 'y', 'type': 'hardlink', 'linkname': 'x'}, {'name': 'z', 'type': 'hardlink', 'linkname': 'y'}]
        circle = [{'name': 'a', 'type': 'hardlink', 'linkname': 'b'}, {'name': 'b', 'type': 'hardlink', 'linkname': 'c'},
                  {'name': 'c', 'type': 'hardlink', 'linkname': 'a'}]
        for label, entries, listed in (('withheld', secret, ['x', 'y', 'z']), ('circle', circle, ['a', 'b', 'c']),
                                       ('hostile', [{'name': 'a', 'type': 'hardlink', 'linkname': '../b'}], ['a'])):
            with self.subTest(case=label):
                _got, reason, passes, _closed, report = self.second(entries, b'')
                self.assertEqual((reason, passes, sorted(report.skip_names('hardlink'))), (None, 0, listed))
        chain = [{'name': 'f', 'data': b'1'}] + [{'name': f'l{i}', 'type': 'hardlink', 'linkname': f'l{i - 1}' if i else 'f'}
                                                 for i in range(8)]
        files, report = self.files(chain, habackup.Select(include=('l6', 'l7')))
        self.assertEqual(files, {'l6': b'1', 'l7': b'1'}, 'links through links, up to eight')
        chain.append({'name': 'l8', 'type': 'hardlink', 'linkname': 'l7'})
        chain.append({'name': 'l9', 'type': 'hardlink', 'linkname': 'l8'})
        _files, report = self.files(chain, habackup.Select(include=('l9',)))
        self.assertEqual(report.skip_names(), ['l9'])

    def test_the_notes_about_chains_are_bounded(self):
        """What a link names is noted for the chains behind it, as many notes as MAX_LINK_COPIES: a crafted tar of millions of
        links must not make the table grow without end; a chain longer than the notes reach is listed, not followed."""
        entries = [{'name': 'x/a', 'data': b'1'}, {'name': 'x/l1', 'type': 'hardlink', 'linkname': 'x/a'},
                   {'name': 'x/l2', 'type': 'hardlink', 'linkname': 'x/l1'}, {'name': 'y/b', 'type': 'hardlink', 'linkname': 'x/l2'}]
        for limit, expected in ((2, {'y/b': b'1'}), (1, {})):
            with self.subTest(limit=limit), mock.patch.object(habackup, 'MAX_LINK_COPIES', limit):
                files, report = self.files(entries, habackup.Select(include=('y',)))
                self.assertEqual(files, expected)
                self.assertEqual(report.skip_names('hardlink'), [] if expected else ['y/b'])

    def test_the_names_of_waiting_links_are_bounded(self):
        """A few MiB of compressed headers must not hold gigabytes of names in memory."""
        entries = [{'name': 'x/a', 'data': b'1'}]
        entries += [{'name': f'y/{i:03d}', 'type': 'hardlink', 'linkname': 'x/a'} for i in range(5)]
        each = len('y/000') + len('x/a')
        with mock.patch.object(habackup, 'MAX_LINK_CHARS', 3 * each):
            files, report = self.files(entries, habackup.Select(include=('y',)))
        self.assertEqual((sorted(files), report.skip_names()), (['y/000', 'y/001', 'y/002'], ['y/003', 'y/004']))
        with mock.patch.object(habackup, 'MAX_LINK_CHARS', 3 * each - 1):
            files, report = self.files(entries, habackup.Select(include=('y',)))
        self.assertEqual((sorted(files), report.skip_count()), (['y/000', 'y/001'], 3))
        self.assertGreaterEqual(habackup.MAX_LINK_CHARS, 300 * habackup.MAX_LINK_COPIES, 'names of 150 characters')
        self.assertFalse(hasattr(habackup._Link('a', 'b', 1, 0, 0, 0, 0.0), '__dict__'))


class NamesTests(unittest.TestCase):
    """IN-34: the table of names four million entries need."""

    def test_it_is_small(self):
        names = habackup._Names(10 ** 6)
        for i in range(100_000):
            names.admit(f'data/filestore/db/{i % 256:02x}/{i:040x}', 'file')
        self.assertEqual(names.used, 100_000 + 256 + 3)
        self.assertLessEqual((len(names.keys) * names.keys.itemsize + len(names.states)) / names.used, 36)
        self.assertGreaterEqual(len(names.keys), 2 * names.used, 'at most half full')

    def test_it_keeps_every_rule_while_it_grows(self):
        names = habackup._Names(10 ** 6)
        keys = {}
        for i in range(5000):
            keys[f'd{i % 50}/f{i}'] = names.admit(f'd{i % 50}/f{i}', 'file')
            if i % 3 == 0:
                names.hand_out(keys[f'd{i % 50}/f{i}'])
        for i in range(5000):
            name = f'd{i % 50}/f{i}'
            self.assertEqual(names.handed_out(keys[name]), i % 3 == 0)
            for call in ((name, 'file'), (name, 'dir'), (f'{name}/x', 'file')):
                self.assertEqual(code_of(names.admit, *call)[0], 'corrupt-archive')
        self.assertFalse(names.handed_out(names.digest('never seen')))
        self.assertEqual(code_of(names.admit, 'd1', 'symlink')[1].details['reason'], 'a non-directory replaces a directory')
        names.admit('d1', 'dir')
        self.assertEqual(code_of(names.admit, 'd1', 'dir')[1].details['reason'], 'duplicate entry')
        names.admit('d1/g', 'fifo')
        self.assertEqual(code_of(names.admit, 'd1/g/h', 'file')[1].details['reason'], 'entry below a file or link')

    def test_an_entry_costs_its_missing_folders_only(self):
        """IN-34: the folders above an entry are looked at from the bottom: once one is in the table everything above it
        is known to be a folder. Entries of two deep paths, one after the other, must not cost the depth every time."""
        names = habackup._Names(10 ** 6)
        deep = ['/'.join(f'{tag}{i}' for i in range(200)) for tag in 'ab']
        calls, real = [], names.digest
        names.digest = lambda name: (calls.append(len(name)), real(name))[1]
        for i in range(10):
            for parent in deep:
                names.admit(f'{parent}/f{i}', 'file')
        self.assertLess(len(calls), 2 * 201 + 18 * 2 + 10, 'two chains once, then the entry and its folder')
        calls.clear()
        names.admit(f'{deep[0]}/new/f', 'file')  # a new folder below a known chain: its own name and the known one
        self.assertEqual(len(calls), 1 + 2)
        names = habackup._Names(10 ** 6)
        names.admit('a/b/c', 'file')
        self.assertEqual(code_of(names.admit, 'a/b/c/d/e', 'file')[1].details['member'], 'a/b/c/d')

    @staticmethod
    def plain_admit(model, name, kind):
        """The structure rules written the plain way: every folder above the entry looked at, the kinds in a dict."""
        state = model.get(name)
        if state and state != 'implied':
            return 'duplicate entry'
        if state and kind != 'dir':
            return 'a non-directory replaces a directory'
        parts = name.split('/')
        for depth in range(1, len(parts)):
            prefix = '/'.join(parts[:depth])
            if model.get(prefix, 'implied') not in ('dir', 'implied'):
                return 'entry below a file or link'
            model.setdefault(prefix, 'implied')
        model[name] = kind
        return None

    def test_it_agrees_with_the_plain_rules(self):
        """Any order of files, folders, links and devices over a few names: the same entries are refused for the same
        reason as by the rules written the plain way (and the same ones are accepted)."""
        rng = random.Random(20261125)
        refused = 0
        for round_ in range(400):
            names, model = habackup._Names(10 ** 4), {}
            for step in range(rng.randrange(1, 60)):
                name = '/'.join(rng.choice('abc') for _ in range(rng.randrange(1, 6)))
                kind = rng.choice(['file', 'dir', 'dir', 'symlink', 'hardlink', 'fifo', 'device'])
                expected = self.plain_admit(model, name, kind)
                try:
                    names.admit(name, kind)
                    got = None
                except BackupError as error:
                    got = error.details['reason']
                with self.subTest(round=round_, step=step, name=name, kind=kind):
                    self.assertEqual(got, expected)
                if got is not None:
                    refused += 1
                    break  # a refused walk ends
        self.assertGreater(refused, 100, 'the sample refuses often enough to mean something')

    def test_implied_folders_are_limited(self):
        """A name of many folders costs a place each: as many as there may be entries twice over."""
        names = habackup._Names(1000)
        names.admit('/'.join('a' * 900), 'file')
        code, error = code_of(names.admit, '/'.join('b' * 200), 'file')
        self.assertEqual((code, error.details['reason']), ('limit-exceeded', 'too many names in an inner tar'))
        say_member(self, error)
        deep = [{'name': '/'.join([f'{i:x}'] + ['a'] * 40), 'data': b''} for i in range(10)]
        with self.assertRaises(BackupError) as caught:
            list(habackup.iter_entries(io.BytesIO(hx.tar_bytes(deep)), habackup.Select(max_members=100), addon=False))
        self.assertEqual((caught.exception.code, caught.exception.details['reason']),
                         ('limit-exceeded', 'too many names in an inner tar'))
        say_member(self, caught.exception)


def haos_doc(doc):
    """Does Supervisor take this backup.json? backups/validate.py SCHEMA_BACKUP (git e610ca81, 2026-11-16), by hand; it
    gave the same answers as the real schema (voluptuous 0.16) for every document of HaosParityTests."""
    def text(value):
        return isinstance(value, str)

    def number(value):
        try:
            return float(value) is not None
        except (TypeError, ValueError):
            return False

    def boolean(value):
        return not text(value) or value.lower() in ('1', 'true', 'yes', 'on', 'enable', '0', 'false', 'no', 'off', 'disable')
    try:
        if int(doc.get('version', 1)) not in (1, 2):
            return False
    except (TypeError, ValueError, OverflowError):
        return False
    core = doc.get('homeassistant') or None
    folders = doc.get('folders', [])
    addons = doc.get('addons', [])
    repositories = doc.get('repositories', [])
    if core is not None and (not isinstance(core, dict) or core.get('version') is not None and not (
            number(core.get('size', 0)) and boolean(core.get('exclude_database', False)))):
        return False
    if not isinstance(folders, list) and folders != '' or not all(text(f) for f in folders):
        return False  # (v1_folderlist turns an empty text into an empty list)
    folders = [{'addons/local': 'apps/local'}.get(f, f) for f in folders if f != 'homeassistant']
    if not isinstance(addons, list) or not all(isinstance(a, dict) and text(a.get('slug')) and text(a.get('name'))
                                               and 'version' in a and number(a.get('size', 0)) for a in addons):
        return False
    return (text(doc.get('slug')) and text(doc.get('name')) and text(doc.get('date'))
            and doc.get('type') in ('full', 'partial') and boolean(doc.get('compressed', True))
            and set(folders) <= {'share', 'apps/local', 'ssl', 'media'} and len(set(folders)) == len(folders)
            and len({a['slug'] for a in addons}) == len(addons) and isinstance(repositories, list)
            and all(text(r) and r.startswith(('https://', 'core', 'local')) for r in repositories)
            and isinstance(doc.get('extra', {}), dict))


def haos_takes(data):
    """Does Supervisor load this file and open it for a restore? backups/backup.py load() and open(), by hand."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tar:
            members = tar.getmembers()
            name = './snapshot.json' if './snapshot.json' in [m.name for m in members] else './backup.json'
            doc = json.loads(tar.extractfile(name).read())
            for member in members:
                tarfile.tar_filter(member, '/tmp')
            return isinstance(doc, dict) and haos_doc(doc)
    except (tarfile.TarError, KeyError, ValueError, OverflowError):
        return False


class HaosParityTests(TempFiles):
    """What HAOS takes, this device takes -- or the reason why not stands here."""

    STRICT_JSON = 'UP-22 (kept): one key with two values, NaN or another encoding leaves open what is meant'
    DAMAGED = 'UP-04, UP-16 (kept): the file is damaged or cut off; tarfile silently stops there and loses the rest'
    EXTENDED = 'UP-06, UP-11 (kept): which name or size belongs to which member is open'
    MOVED = 'a global header that moves names or sizes: they cannot be trusted for any member'
    SPARSE = 'UP-07 (kept): HA writes no sparse members, expanding them wrongly would corrupt data'
    NUMBERS = 'UP-05, UP-09 (kept): a size or owner that is no number puts every member out of place'
    LIMITS = 'UP-12, UP-15, UP-21, UP-32, UP-39, UP-43: limits far above any backup'
    TWICE = 'UP-19: two descriptions, which one is meant is open'
    REFUSED_DOCUMENTS = {'folders empty': 'UP-39: what is no list is refused (HAOS takes an empty text by accident)'}

    def ours(self, data):
        try:
            self.describe(data)
        except BackupError:
            return False
        return True

    def documents(self):
        """(label, document) of every field in every odd shape, and whole documents."""
        for field in ('slug', 'name', 'date', 'supervisor_version', 'homeassistant', 'protected', 'compressed', 'type', 'version',
                      'folders', 'addons', 'repositories', 'extra', 'crypto', 'something'):
            doc = hx.ha_doc()
            doc.pop(field, None)
            yield f'{field} absent', doc
            for label, value in {**DescribeTests.ODD, 'zero': 0, 'false': False, 'two': '2', 'no': 'no', 'one': 1,
                                 'dict list': [{}], 'text list': ['share']}.items():
                yield f'{field} {label}', dict(hx.ha_doc(), **{field: value})
        for field in ('slug', 'name', 'version', 'size'):
            for label, value in {**DescribeTests.ODD, 'absent': None}.items():
                doc = hx.ha_doc([hx.ODOO, hx.N8N])
                doc['addons'][1][field] = value
                if label == 'absent':
                    del doc['addons'][1][field]
                yield f'add-on {field} {label}', doc
        for label, override in {
                'core': {'homeassistant': {'version': '1'}}, 'core without a version': {'homeassistant': {'size': 1}},
                'core with odd fields': {'homeassistant': {'version': [1], 'size': '1.5', 'exclude_database': 'yes'}},
                'every folder': {'folders': ['share', 'ssl', 'media', 'apps/local', 'homeassistant']},
                'old folder': {'folders': ['addons/local']}, 'both folders': {'folders': ['addons/local', 'apps/local']},
                'another folder': {'folders': ['data']}, 'a folder twice': {'folders': ['ssl', 'ssl']},
                'repositories': {'repositories': ['https://github.com/woowtech/x', 'core', 'local']},
                'a newer key': {'newer': {'x': [1]}}, 'version 1': {'version': 1}, 'version text': {'version': '1'},
                'version 2.9': {'version': 2.9}, 'version true': {'version': True}, 'version 3': {'version': 3}}.items():
            yield label, dict(hx.ha_doc(), **override)
        doc = hx.ha_doc()
        doc['addons'] *= 2
        yield 'an add-on twice', doc

    def test_documents(self):
        odoo, n8n = (f'{hx.ODOO}.tar.gz', hx.addon_member()), (f'{hx.N8N}.tar.gz', hx.addon_member('woow-n8n'))
        seen = {True: 0, False: 0}
        for label, doc in self.documents():
            with self.subTest(document=label):
                data = hx.outer_bytes([odoo, n8n], doc)
                haos = haos_takes(data)
                self.assertEqual(haos, haos_doc(json.loads(json.dumps(doc))))
                seen[haos] += 1
                if haos:
                    self.assertEqual(self.ours(data), label not in self.REFUSED_DOCUMENTS,
                                     'HAOS takes it and so does this device')
        self.assertGreater(min(seen.values()), 60, 'both answers are well covered')

    def test_files(self):
        """(label, file, HAOS takes it, this device takes it, why not)."""
        name, member, doc = f'{hx.ODOO}.tar.gz', hx.addon_member(), json.dumps(hx.ha_doc()).encode()
        addon, info = hx.raw_member(name, member), hx.raw_member('./backup.json', doc)
        whole = addon + info + hx.END

        def with_(blocks):
            return blocks + whole
        table = [
            ('as Supervisor writes it', hx.outer_bytes([(name, member)]), True, True, None),
            ('GNU tar', hx.outer_bytes([(name, member)], fmt=tarfile.GNU_FORMAT), True, True, None),
            ('ustar', hx.outer_bytes([(name, member)], fmt=tarfile.USTAR_FORMAT), True, True, None),
            ('v7', hx.raw_member(name, member, magic=hx.V7) + hx.raw_member('./backup.json', doc, magic=hx.V7) + hx.END,
             True, True, None),
            ('an unknown PAX record', with_(hx.pax_member({'SCHILY.ino': '1'}) + hx.raw_member('x')), True, True, None),
            ('a folder', with_(hx.raw_member('d/', typeflag=b'5')), True, True, None),
            ('a link', with_(hx.raw_member('l', typeflag=b'2', linkname='x')), True, True, None),
            ('a device', with_(hx.raw_member('n', typeflag=b'3')), True, True, None),
            ('another file', with_(hx.raw_member('mine.txt', b'x')), True, True, None),
            ('a file in a folder', with_(hx.raw_member('a/b', b'x')), True, True, None),
            ('an absolute name', with_(hx.raw_member('/a', b'x')), True, True, None),
            ('a name outside', with_(hx.raw_member('../a', b'x')), False, True, None),
            ('a link name', hx.raw_member(name, member, linkname='x') + info + hx.END, True, True, None),
            ('a member twice', with_(hx.raw_member(name, b'other')), True, True, None),
            ('a listed member missing', info + hx.END, True, True, None),
            ('bytes after the end', whole + b'x' * 700, True, True, None),
            ('one zero block', addon + info + bytes(512), True, True, None),
            ('dirty padding', (addon[:-1] + b'x') + info + hx.END, True, True, None),
            ('backup.json without ./', addon + hx.raw_member('backup.json', doc) + hx.END, False, True, None),
            ('a comment for all', with_(hx.pax_member({'comment': 'x'}, typeflag=b'g')), True, True, None),
            ('backup.json twice', whole[:-1024] + info + hx.END, True, False, self.TWICE),
            ('a second one without ./', whole[:-1024] + hx.raw_member('backup.json', b'x') + hx.END, True, False, self.TWICE),
            ('one key twice', addon + hx.raw_member('./backup.json', doc[:-1] + b', "name": "x"}') + hx.END, True, False,
             self.STRICT_JSON),
            ('NaN', addon + hx.raw_member('./backup.json', doc[:-1] + b', "x": NaN}') + hx.END, True, False,
             self.STRICT_JSON),
            ('UTF-16', addon + hx.raw_member('./backup.json', doc.decode().encode('utf-16')) + hx.END, True, False,
             self.STRICT_JSON),
            ('a BOM', addon + hx.raw_member('./backup.json', b'\xef\xbb\xbf' + doc) + hx.END, True, False, self.STRICT_JSON),
            ('no end', addon + info, True, False, self.DAMAGED),
            ('a bad header after backup.json', addon + info + b'\1' * 512 + hx.END, True, False, self.DAMAGED),
            ('cut off in a member', whole[:900], False, False, None),
            ('two PAX headers', with_(hx.pax_member({'comment': 'x'}) * 2 + hx.raw_member('x')), True, False, self.EXTENDED),
            ('a PAX key twice', with_(hx.pax_member(hx.pax_records({'comment': 'x'}) * 2) + hx.raw_member('x')), True, False,
             self.EXTENDED),
            ('a PAX key that is no ASCII', with_(hx.pax_member({'é': 'x'}) + hx.raw_member('x')), True, False, self.EXTENDED),
            ('a name for all', with_(hx.pax_member({'gname': 'x', 'path': 'y'}, typeflag=b'g')), None, False, self.MOVED),
            ('sparse', with_(hx.raw_member('s', bytes(512), typeflag=b'S', magic=hx.GNU)), None, False, self.SPARSE),
            ('a size that is none', with_(hx.pax_member({'size': 'x'}) + hx.raw_member('x')), None, False, self.NUMBERS),
            ('too many entries', hx.raw_member('d/', typeflag=b'5') * 5000 + whole, True, False, self.LIMITS),
            ('too many add-ons', hx.outer_bytes([], hx.ha_doc([f'a{i}' for i in range(1001)])), True, False, self.LIMITS),
            ('too many repositories', hx.outer_bytes([], hx.ha_doc([], repositories=['core'] * 501)), True, False,
             self.LIMITS),
            ('a large PAX header', with_(hx.pax_member({'comment': 'x' * (2 << 20)}) + hx.raw_member('x')), True, False,
             self.LIMITS),
            ('compressed', gzip.compress(whole), False, False, None),
        ]
        for label, data, haos, ours, reason in table:
            with self.subTest(file=label):
                if haos is not None:  # None: tarfile versions differ
                    self.assertEqual(haos_takes(data), haos, 'what HAOS does')
                self.assertEqual(self.ours(data), ours, 'what this device does')
                self.assertEqual(bool(reason), haos is not False and not ours, 'a refusal of its own needs a reason')

    def test_members_home_assistant_would_find(self):
        """`_get_inner_tar`: `<slug>.tar[.gz]` by its normalised name, else only that one is missing."""
        member, doc = hx.addon_member(), hx.ha_doc()
        for name, found in ((f'{hx.ODOO}.tar.gz', True), (f'./{hx.ODOO}.tar.gz', True), (f'././{hx.ODOO}.tar.gz', True),
                            (f'{hx.ODOO}.tar', False), (f'{hx.ODOO}.TAR.GZ', False), (f'x/{hx.ODOO}.tar.gz', False)):
            with self.subTest(name=name):
                data = hx.outer_bytes([(name, member)], doc)
                with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                    names = {os.path.normpath(m.name) for m in tar.getmembers() if m.isreg()}
                self.assertEqual(f'{hx.ODOO}.tar.gz' in names, found, 'what HAOS does')
                self.assertEqual(self.problems(data), {hx.ODOO: None if found else 'missing'})


class RepackedTests(TempFiles):
    """UP-03, UP-08, UP-10, UP-13, UP-17: a customer unpacked the backup and packed it again (to take out media, to
    rename something) -- with the tools of this machine, else as those tools write it."""

    FORMATS = ('gnu', 'oldgnu', 'posix', 'ustar', 'v7')

    def unpack(self, data):
        folder = Path(tempfile.mkdtemp(dir=self.dir))
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            for member in tar.getmembers():
                (folder / member.name.removeprefix('./')).write_bytes(tar.extractfile(member).read())
        return folder

    def check(self, data, whole=True):
        path = self.write(data)
        with open(path, 'rb') as handle:
            self.assertTrue(habackup.looks_like_ha(handle.fileno()))
        with habackup.open_backup(path) as ha:
            self.assertEqual({a['slug']: a.get('problem') for a in ha.layout.summary()['addons']},
                             {hx.ODOO: None, hx.N8N: None if whole else 'missing'})
            for slug in (hx.ODOO, hx.N8N) if whole else (hx.ODOO,):
                with ha.open_addon(slug) as stream:
                    report = habackup.Report()
                    self.assertTrue(list(habackup.iter_entries(stream, None, report)))
                    self.assertTrue(report.complete)

    def run_tool(self, tool, *args, cwd):
        found = shutil.which(tool)
        if found is None:
            self.skipTest(f'no {tool} here')
        subprocess.run([found, *args], cwd=cwd, check=True, capture_output=True, timeout=60)
        return (Path(cwd).parent / 'again.tar').read_bytes()

    def test_gnu_tar(self):
        folder = self.unpack(hx.two_addons())
        (folder / 'media').mkdir()
        (folder / 'a link').symlink_to('/etc/passwd')
        for fmt in self.FORMATS:
            for names in (['.'], sorted(p.name for p in folder.iterdir())):
                with self.subTest(format=fmt, names=names[0]):
                    self.check(self.run_tool('tar', f'--format={fmt}', '-cf', '../again.tar', '--', *names, cwd=folder))
        (folder / f'{hx.N8N}.tar.gz').unlink()
        self.check(self.run_tool('tar', '--format=gnu', '-b', '1', '-cf', '../again.tar', '.', cwd=folder), whole=False)
        encrypted = self.run_tool('tar', '-cf', '../again.tar', '.', cwd=self.unpack(hx.fixture('v3_gzip.tar').read_bytes()))
        self.assertEqual({m.name: m.encryption for m in self.describe(encrypted).members},
                         {name: info['encryption'] for name, info in hx.META['fixtures']['v3_gzip.tar']['members'].items()})

    def test_busybox_tar(self):
        folder = self.unpack(hx.two_addons())
        if shutil.which('busybox') is None:
            self.skipTest('no busybox here')
        self.check(self.run_tool('busybox', 'tar', '-cf', '../again.tar', '.', cwd=folder))

    def test_bsdtar_and_macos(self):
        """Not on this machine: their PAX records, AppleDouble files, the folder entry and the padding to 10 KiB."""
        member, n8n, doc = hx.addon_member(), hx.addon_member('woow-n8n'), json.dumps(hx.ha_doc([hx.ODOO, hx.N8N])).encode()

        def mac(name, data):
            extra = {'LIBARCHIVE.xattr.com.apple.provenance': 'AQIAvA==', 'SCHILY.xattr.com.apple.provenance': b'\x01\x02',
                     'LIBARCHIVE.creationtime': '1794992487.1234567', 'mtime': '1794992487.123456789',
                     'SCHILY.dev': '16777231', 'SCHILY.ino': '8652412', 'SCHILY.nlink': '1'}
            double = hx.pax_member(extra, name=f'./PaxHeader/._{name}') + hx.raw_member(f'./._{name}', b'\0\5\x16\7Mac OS X')
            return double + hx.pax_member(extra, name=f'./PaxHeader/{name}') + hx.raw_member(f'./{name}', data)
        data = (hx.pax_member({'mtime': '1794992487.1'}, name='./PaxHeader/.') + hx.raw_member('./', typeflag=b'5')
                + mac(f'{hx.ODOO}.tar.gz', member) + mac('backup.json', doc) + mac(f'{hx.N8N}.tar.gz', n8n) + hx.END)
        self.check(data + bytes(-len(data) % 10240))
        layout = self.describe(data)
        self.assertEqual(layout.ignored_count, 4, 'the folder and the three AppleDouble files')


class FuzzTests(TempFiles):
    """Damage anywhere: a BackupError or the same content as before, never another exception, never other content.
    Fixed seed; ROUNDS always, more while SECONDS last (the time one kind of member may take)."""

    ROUNDS, SECONDS = 40, 3

    def entries(self, path, keys=None):
        result = {}
        with habackup.open_backup(path) as ha:
            for member in ha.layout.members:
                with ha.open_member(member.name, keys) as stream:
                    report = habackup.Report()
                    rows = []
                    for entry in habackup.iter_entries(stream, habackup.Select(symlinks=('.',), hardlinks=True), report):
                        data = entry.read_all(1 << 22) if entry.kind == 'file' else None
                        rows.append((entry.name, entry.kind, entry.mode, entry.uid, entry.gid, entry.linkname, data))
                    self.assertTrue(report.complete)
                    result[member.name] = rows
        return result

    def damage(self, rng, data):
        data = bytearray(data)
        kind = rng.randrange(5)
        at = rng.randrange(len(data))
        if kind == 0:
            data[at] ^= 1 << rng.randrange(8)
        elif kind == 1:
            data[at:at + rng.randrange(1, 600)] = bytes(rng.randrange(1, 600))
        elif kind == 2:
            del data[at:at + rng.randrange(1, 2000)]
        elif kind == 3:
            data[at:at] = rng.randbytes(rng.randrange(1, 2000))
        else:
            del data[at:]
        return bytes(data)

    def fuzz(self, data, keys=None, *, checked=True):
        rng = random.Random(20261125)
        good = self.entries(self.write(data), keys)
        outcomes, until = {}, time.monotonic() + self.SECONDS
        path = self.dir / 'fuzz.tar'
        for round_ in range(400):
            if round_ >= self.ROUNDS and time.monotonic() > until:
                break
            path.write_bytes(self.damage(rng, data))
            try:
                got = self.entries(path, keys)
            except BackupError as error:
                self.assertIn(error.code, ('corrupt-archive', 'limit-exceeded', 'unsupported-format', 'not-found',
                                           'wrong-key', 'key-required'))
                outcomes[error.code] = outcomes.get(error.code, 0) + 1
                continue
            outcomes['read'] = outcomes.get('read', 0) + 1
            if checked:  # a checksum or authentication covers every byte of a member
                for name, rows in got.items():
                    self.assertEqual(rows, good.get(name), 'what is read is what was written')
        self.assertGreaterEqual(sum(outcomes.values()), self.ROUNDS, outcomes)
        self.assertGreater(outcomes.get('corrupt-archive', 0), 10, outcomes)

    def test_gzip_members(self):
        self.fuzz(hx.two_addons(doc=hx.ha_doc([hx.ODOO, hx.N8N])))

    def test_plain_members(self):
        """No checksum covers these: content may change, but nothing else goes wrong."""
        self.fuzz(hx.outer_bytes([(f'{hx.ODOO}.tar', hx.addon_member(compress=False))], hx.ha_doc(compressed=False)),
                  checked=False)

    @hx.needs_crypto
    def test_encrypted_members(self):
        self.fuzz(hx.fixture('v3_gzip.tar').read_bytes(), hasecuretar.Keys(hx.PASSWORD))
        self.fuzz(hx.fixture('v2_gzip.tar').read_bytes(), hasecuretar.Keys(hx.PASSWORD))


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
