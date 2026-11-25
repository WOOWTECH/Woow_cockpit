"""HA import, Odoo part (ha_odoo.py; CONTRACT section 9 "Home Assistant import"): module versions and the verdict, the
strict pass over the add-on tar (cluster, filestore, custom modules), the rewritten data dir and custom modules folder,
the restore list filter, settings and marker handling, and the live Quadlet parsing. Team E2."""
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import types

from woowbackup import ha_odoo, habackup, haissues, jobs, tempctr
from woowbackup.errors import BackupError

from woowbackup.podman import CommandError

from . import hafakes
from . import hafixtures as hx

ADDON_JSON = json.dumps({'user': {'version': '0.4.12', 'image': 'ghcr.io/woowtech/woow-ha-odoo-amd64',
                                  'options': {'admin_passwd': 'secret'}},
                         'system': {'slug': 'odoo18ce', 'name': 'Woow Odoo 18', 'arch': ['amd64']},
                         'version': '0.4.12'}).encode()
MANIFEST = b"{'name': 'Probe', 'version': '18.0.1.0.0', 'depends': ['base'], " \
           b"'external_dependencies': {'python': ['lxml'], 'bin': ['wkhtmltopdf']}}"


def odoo_tar(extra=()):
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': ADDON_JSON},
               {'name': 'data', 'type': 'dir'},
               {'name': 'data/options.json', 'data': b'{"admin_passwd": "secret"}'},
               {'name': 'data/postgres', 'type': 'dir', 'mode': 0o700, 'uid': 100, 'gid': 102},
               {'name': 'data/postgres/PG_VERSION', 'data': b'16\n', 'uid': 100, 'gid': 102, 'mode': 0o600},
               {'name': 'data/postgres/pg_hba.conf', 'data': b'host all all 0.0.0.0/0 trust\n', 'uid': 100, 'gid': 102},
               {'name': 'data/postgres/postmaster.pid', 'data': b'123\n', 'uid': 100, 'gid': 102},
               {'name': 'data/postgres/base', 'type': 'dir', 'uid': 100, 'gid': 102, 'mode': 0o700},
               {'name': 'data/postgres/base/1', 'data': b'x' * 3000, 'uid': 100, 'gid': 102, 'mode': 0o600},
               {'name': 'data/odoo', 'type': 'dir', 'uid': 101, 'gid': 103},
               {'name': 'data/odoo/filestore', 'type': 'dir', 'uid': 101, 'gid': 103},
               {'name': 'data/odoo/filestore/woowtest', 'type': 'dir', 'uid': 101, 'gid': 103},
               {'name': 'data/odoo/filestore/woowtest/ab', 'type': 'dir', 'uid': 101, 'gid': 103},
               {'name': 'data/odoo/filestore/woowtest/ab/' + 'c' * 40, 'data': b'attachment', 'uid': 101, 'gid': 103},
               {'name': 'data/odoo/filestore/other', 'type': 'dir', 'uid': 101, 'gid': 103},
               {'name': 'data/odoo/filestore/other/f', 'data': b'zz', 'uid': 101, 'gid': 103},
               {'name': 'data/addons', 'type': 'dir'},
               {'name': 'data/addons/woow_import_probe', 'type': 'dir', 'mode': 0o775},
               {'name': 'data/addons/woow_import_probe/__manifest__.py', 'data': MANIFEST, 'mode': 0o664},
               {'name': 'data/addons/woow_import_probe/__init__.py', 'data': b'', 'mode': 0o664},
               {'name': 'data/addons/woow_import_probe/__pycache__', 'type': 'dir'},
               {'name': 'data/addons/woow_import_probe/__pycache__/x.pyc', 'data': b'bytecode'},
               {'name': 'data/odoo.conf', 'data': b'admin_passwd = secret\n'},
               *extra, {'name': 'config', 'type': 'dir'}]
    return hx.tar_bytes(entries)


def members_of(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tar:
        return {m.name: (m, tar.extractfile(m).read() if m.isfile() else None) for m in tar.getmembers()}


class VersionTests(unittest.TestCase):
    def test_adapt_and_compare_like_odoo(self):
        self.assertEqual(ha_odoo.adapt_version('1.3'), '18.0.1.3')
        self.assertEqual(ha_odoo.adapt_version('18.0.1.3'), '18.0.1.3')
        self.assertEqual(ha_odoo.adapt_version('18.0'), '18.0.18.0')
        self.assertTrue(ha_odoo.same_version('18.0.1.3', '18.0.1.3.0'))
        self.assertFalse(ha_odoo.same_version('18.0.1.3', '18.0.1.4'))
        self.assertFalse(ha_odoo.same_version('18.0.x', '18.0.x'))
        self.assertIsNone(ha_odoo.version_key('1'))

    def test_manifest_is_read_never_run(self):
        info = ha_odoo.parse_manifest(MANIFEST)
        self.assertEqual(info, {'version': '18.0.1.0.0', 'installable': True, 'python': ['lxml'],
                                'bin': ['wkhtmltopdf']})
        self.assertEqual(ha_odoo.parse_manifest(b"{'version': '2.1', 'installable': False}")['installable'], False)
        for data in (b"__import__('os').system('id')", b'[1, 2]', b'{', b'\xff\xfe', b"{'version': []}",
                     b'x' * (ha_odoo.MAX_MANIFEST + 1)):
            with self.subTest(data=data[:30]):
                self.assertIsNone(ha_odoo.parse_manifest(data))


def details(modules, **counts):
    base = {'modules': modules, 'partners': 1, 'users': 1, 'attachments': 0, 'attachment_bytes': 0,
            'crons_active': 0, 'mail_servers_active': 0, 'size': 1, 'extensions': ['plpgsql'], 'base_url': None}
    base.update(counts)
    return base


def target(modules, python=None, binaries=None):
    return {'version': '18.0-20260926', 'paths': [], 'modules': modules, 'python': python or {}, 'bin': binaries or {}}


CORE = '/usr/lib/python3/dist-packages/odoo/addons'
EXTRA = '/mnt/extra-addons'


def elf(machine, ident=b'\x7fELF\x02\x01\x01'):
    return ident + bytes(16 - len(ident)) + b'\x03\0' + machine.to_bytes(2, 'little') + bytes(40)


class NativeFileTests(unittest.TestCase):
    def test_foreign_native(self):
        self.assertTrue(ha_odoo.foreign_native(elf(0xB7)), 'aarch64')
        self.assertTrue(ha_odoo.foreign_native(elf(0x3E, b'\x7fELF\x01\x01\x01')), '32-bit')
        self.assertFalse(ha_odoo.foreign_native(elf(0x3E)), 'x86-64')
        for head in (b'', b'\x7fELF', b'#!/bin/sh\n' + bytes(40), b'import os\n' * 5):
            self.assertFalse(ha_odoo.foreign_native(head), head[:8])

    def test_foreign_native_follows_the_devices_processor(self):
        with mock.patch.object(ha_odoo, 'host_elf_machine', lambda: 0xB7):  # an ARM64 device (lane arm54-2, .54)
            self.assertFalse(ha_odoo.foreign_native(elf(0xB7)), 'aarch64 code runs on an ARM64 device')
            self.assertTrue(ha_odoo.foreign_native(elf(0x3E)), 'x86-64 code does not')
            self.assertTrue(ha_odoo.foreign_native(elf(0xB7, b'\x7fELF\x01\x01\x01')), '32-bit')
        with mock.patch.object(ha_odoo, 'host_elf_machine', lambda: None):  # unknown: as before, x86-64
            self.assertFalse(ha_odoo.foreign_native(elf(0x3E)))
            self.assertTrue(ha_odoo.foreign_native(elf(0xB7)))

    def test_the_machine_table(self):
        for name, machine in (('x86_64', 0x3E), ('amd64', 0x3E), ('aarch64', 0xB7), ('ARM64', 0xB7), ('riscv64', None)):
            with mock.patch.object(ha_odoo.os, 'uname', lambda name=name: mock.Mock(machine=name)):
                self.assertEqual(ha_odoo.host_elf_machine(), machine, name)

    def test_the_scan_names_the_file_and_still_copies_it_whole(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        modules = ha_odoo.FileTar(Path(tmp.name) / 'modules.tar')
        native = elf(0xB7) + b'payload' * 100
        extra = [{'name': 'data/addons/woow_import_probe/lib', 'type': 'dir'},
                 {'name': 'data/addons/woow_import_probe/lib/arm.so', 'data': native},
                 {'name': 'data/addons/woow_import_probe/lib/x86.so', 'data': elf(0x3E)}]
        src = ha_odoo.scan_member(io.BytesIO(odoo_tar(extra)), habackup.Report(), modules=modules)
        modules.close()
        self.assertEqual(src.modules['woow_import_probe']['foreign'], ['lib/arm.so'])
        copied = members_of((Path(tmp.name) / 'modules.tar').read_bytes())
        self.assertEqual(copied['data/addons/woow_import_probe/lib/arm.so'][1], native)

    def test_a_module_without_native_code_is_not_marked(self):
        src = ha_odoo.scan_member(io.BytesIO(odoo_tar()), habackup.Report())
        self.assertNotIn('foreign', src.modules['woow_import_probe'])


class VerdictTests(unittest.TestCase):
    """What an HA database gets said about it (`database_issues`, HAOS parity: the data is taken as it is where it stays
    whole; a line to confirm where the customer loses something; a stop only where the data itself cannot move)."""

    def verdict(self, det, tgt, candidates=None, ha_major=16, target_major=17, **kwargs):
        return ha_odoo.database_issues('woowtest', det, tgt, candidates or {}, ha_major=ha_major,
                                       target_major=target_major, **kwargs)

    def candidate(self, version='18.0.1.0.0', python=(), binaries=(), installable=True):
        return {'from': 'data/addons', 'manifest': {'version': version, 'installable': installable,
                                                     'python': list(python), 'bin': list(binaries)}}

    @staticmethod
    def found(issues):
        return {issue.id: (issue.level, list(issue.names)) for issue in issues}

    def test_same_versions_move(self):
        issues, copy, unavailable = self.verdict(details([('base', '18.0.1.3', 'installed')]),
                                                 target({'base': ('18.0.1.3', True, CORE)}))
        self.assertEqual((issues, copy, unavailable), ([], {}, set()))

    def test_a_missing_module_is_a_line_to_confirm_and_says_what_the_next_update_does(self):
        """OD-37: HA has the module, the backup does not: the customer agrees that its functions stop; the data stays."""
        issues, copy, unavailable = self.verdict(details([('base', '18.0.1.3', 'installed'),
                                                          ('x_custom', '18.0.1.0', 'installed')]),
                                                 target({'base': ('18.0.1.3', True, CORE)}))
        self.assertEqual(self.found(issues), {'odoo.modules-missing': ('confirm', ['x_custom'])})
        line = issues[0]
        self.assertEqual((line.database, copy, unavailable), ('woowtest', {}, {'x_custom'}))
        self.assertIn('upgrade-gate.sh', line.text)
        self.assertIn('結束碼 4', line.text)
        self.assertIn('/share/odoo_addons', line.text)
        self.assertLessEqual(len(line.text), haissues.MAX_MESSAGE)

    def test_a_custom_module_of_the_backup_is_copied(self):
        issues, copy, _u = self.verdict(details([('woow_import_probe', '18.0.1.0.0', 'installed')]),
                                        target({}, python={'lxml': True}),
                                        {'woow_import_probe': self.candidate(python=['lxml'])})
        self.assertEqual((issues, list(copy)), ([], ['woow_import_probe']))

    def test_a_custom_module_built_for_another_processor_is_copied_with_a_reminder_only_when_it_would_be_copied(self):
        """OD-46."""
        cand = {'probe': {**self.candidate(), 'foreign': ['lib/native.so']}}
        issues, copy, _u = self.verdict(details([('probe', '18.0.1.0.0', 'installed')]), target({}), cand)
        self.assertEqual(self.found(issues), {'odoo.module-foreign-native': ('notice', ['probe'])})
        self.assertIn('其他處理器（例如 ARM）', issues[0].text)
        self.assertEqual(list(copy), ['probe'], 'copied all the same')
        issues, copy, _u = self.verdict(details([('probe', '18.0.1.0.0', 'installed')]),
                                        target({'probe': ('18.0.1.0.0', True, CORE)}), cand)
        self.assertEqual((issues, copy), ([], {}), 'this device has its own copy: nothing moves')

    def test_a_custom_copy_replaces_another_version_only_in_the_custom_folder(self):
        cand = {'probe': self.candidate('18.0.2.0')}
        issues, _c, _u = self.verdict(details([('probe', '18.0.2.0', 'installed')]),
                                      target({'probe': ('18.0.1.0', True, EXTRA)}), cand)
        self.assertEqual(issues, [])
        issues, copy, _u = self.verdict(details([('probe', '18.0.2.0', 'installed')]),
                                        target({'probe': ('18.0.1.0', True, '/opt/woow/addons')}), cand)
        self.assertEqual(self.found(issues), {'odoo.module-version-different': ('stop', ['probe（HA 18.0.2.0，這台 18.0.1.0）'])})
        self.assertEqual(copy, {})

    def test_modules_waiting_for_an_installation_or_upgrade_are_a_reminder(self):
        """OD-36: they move in the state HA has them in; the customer is told to apply or cancel them."""
        issues, _c, _u = self.verdict(details([('base', '18.0.1.3', 'to upgrade'), ('x', '', 'to install')]),
                                      target({'base': ('18.0.1.3', True, CORE)}))
        self.assertEqual(self.found(issues), {'odoo.modules-pending': ('notice', ['base（to upgrade）', 'x（to install）'])})
        self.assertIn('應用程式', issues[0].text)

    def test_the_data_itself_decides_what_stops(self):
        issues, _c, _u = self.verdict(details([]), target({}), ha_major=18, target_major=17)
        self.assertEqual(self.found(issues), {'odoo.pg-newer': ('stop', [])})
        self.assertIn('18 版', issues[0].text)
        self.assertTrue(issues[0].action)
        issues, _c, _u = self.verdict(details([]), target({}), ha_major=16, target_major=None)
        self.assertEqual(list(self.found(issues)), ['odoo.pg-newer'])

    def test_a_custom_module_that_needs_a_package_the_device_lacks_stays_out_and_is_a_line_to_confirm(self):
        """OD-44: only that module stays behind; the database moves, its other modules are copied."""
        cand = {'m': self.candidate('18.0.1.0', python=['zeep', 'lxml']), 'ok': self.candidate('18.0.1.0', python=['lxml'])}
        issues, copy, unavailable = self.verdict(
            details([('m', '18.0.1.0', 'installed'), ('ok', '18.0.1.0', 'installed')]), target({}, python={'lxml': True}),
            cand)
        self.assertEqual(self.found(issues), {'odoo.modules-skipped-deps': ('confirm', ['m（缺 zeep）'])})
        self.assertEqual((list(copy), unavailable), (['ok'], {'m'}))

    def test_a_package_spelling_the_device_cannot_read_is_only_said(self):
        """OD-44, the second half: `lxml; python_version < '3.12'` was taken for a missing package."""
        cand = {'m': self.candidate('18.0.1.0', python=["lxml; python_version < '3.12'"])}
        issues, copy, unavailable = self.verdict(details([('m', '18.0.1.0', 'installed')]), target({}), cand)
        self.assertEqual(self.found(issues), {'odoo.dependency-unreadable': ('notice', ["lxml; python_version < '3.12'（模組 m）"])})
        self.assertEqual((list(copy), unavailable), (['m'], set()))

    def test_modules_that_cannot_be_installed_or_need_a_program_are_copied_with_a_reminder(self):
        """OD-43, OD-45."""
        cand = {'m': self.candidate('18.0.1.0', binaries=['wkhtmltopdf', 'antiword'], installable=False)}
        issues, copy, _u = self.verdict(details([('m', '18.0.1.0', 'installed')]), target({}, binaries={'wkhtmltopdf': True}),
                                        cand)
        self.assertEqual(self.found(issues), {'odoo.module-not-installable': ('notice', ['m']),
                                              'odoo.program-missing': ('notice', ['antiword（模組 m）'])})
        self.assertEqual(list(copy), ['m'])

    def test_warnings_for_mail_and_crons(self):
        issues, _c, _u = self.verdict(details([], mail_servers_active=1, crons_active=3), target({}))
        self.assertEqual(sorted(self.found(issues)), ['odoo.crons-active', 'odoo.mail-servers-active'])
        self.assertTrue(all(issue.level == 'notice' for issue in issues))

    def test_the_extensions_the_device_has_and_postgresql_trusts_are_allowed(self):
        """OD-39: pgcrypto is neither on the fixed list nor missing: this device's image has it and calls it trusted."""
        offered = {'pg_trgm': True, 'unaccent': True, 'vector': True, 'pgcrypto': True, 'dblink': False}
        det = details([], extensions=['plpgsql', 'pg_trgm', 'pgcrypto'])
        issues, _c, _u = self.verdict(det, target({}, ) | {'extensions': offered})
        self.assertEqual(issues, [])
        for ext, why in (('dblink', 'has it but does not trust it'), ('postgis', 'does not have it')):
            with self.subTest(ext=ext, why=why):
                issues, _c, _u = self.verdict(details([], extensions=['plpgsql', ext]), target({}) | {'extensions': offered})
                self.assertEqual(self.found(issues), {'odoo.extension-unsupported': ('stop', [ext])})
                self.assertTrue(issues[0].action)

    def test_an_extension_name_of_a_hostile_backup_never_reaches_a_statement(self):
        """OD-39: a name is created only when this device's own catalog lists it (and it is trusted); the identifier is
        quoted by a strict rule on top."""
        offered = {'pg_trgm': True, 'pgcrypto': True}
        for name in ('x"; DROP SCHEMA public; --', "pgcrypto'; --", 'pgcrypto' + ' ' * 56 + 'x', 'PGCRYPTO', '../x', ''):
            for known in (offered, None):
                with self.subTest(name=name[:20], known=known is not None):
                    issues, _c, _u = self.verdict(details([], extensions=['plpgsql', name]),
                                                  target({}) | ({'extensions': known} if known is not None else {}))
                    self.assertEqual([i.id for i in issues], ['odoo.extension-unsupported'])
        self.assertEqual(ha_odoo.ext_ident('uuid-ossp'), '"uuid-ossp"')
        for bad in ('a"b', 'a b', "a'b", '1abc', 'a;b', 'a' * 64):
            with self.subTest(bad=bad), self.assertRaises(BackupError):
                ha_odoo.ext_ident(bad)

    def test_when_the_device_cannot_be_asked_the_fixed_list_is_used(self):
        det = details([], extensions=['plpgsql', 'pgcrypto'])
        issues, _c, _u = self.verdict(det, target({}))
        self.assertEqual(self.found(issues), {'odoo.extension-unsupported': ('stop', ['pgcrypto'])})
        self.assertEqual(self.verdict(details([], extensions=['plpgsql', 'unaccent', 'vector']), target({}))[0], [])

    def test_vector_needs_the_image_that_can_read_it(self):
        """OD-40: without it only the databases that use vector stop; the check downloads the image first."""
        det = details([], extensions=['plpgsql', 'vector'])
        issues, _c, _u = self.verdict(det, target({}), vector_ok=False)
        self.assertEqual(self.found(issues), {'odoo.vector-image-missing': ('stop', [])})
        self.assertIn(ha_odoo.PG16_IMAGES[0], issues[0].text)
        self.assertEqual(self.verdict(det, target({}), vector_ok=True)[0], [])

    def test_objects_only_a_superuser_can_create_are_a_line_to_confirm(self):
        """OD-41: they are left out, the rest moves."""
        det = details([], superuser_objects=['EVENT TRIGGER', 'CAST'])
        issues, _c, _u = self.verdict(det, target({}))
        self.assertEqual(self.found(issues), {'odoo.superuser-objects': ('confirm', ['CAST', 'EVENT TRIGGER'])})
        self.assertIn('略過', issues[0].text)

    def test_the_databases_that_stay_on_ha_are_a_line_to_confirm_of_the_one_that_moves(self):
        """UI-20, S6."""
        issues, _c, _u = self.verdict(details([]), target({}), others=['test', 'demo'])
        self.assertEqual(self.found(issues), {'odoo.databases-left': ('confirm', ['demo', 'test'])})
        self.assertIn('woowtest', issues[0].text)
        self.assertIn('以後再匯入另一個會取代這次的', issues[0].text)
        self.assertEqual(self.verdict(details([]), target({}), others=[])[0], [])

    def test_every_line_to_confirm_is_confirmed_by_exactly_its_names(self):
        """DESIGN G1 for the five lines of this importer: not confirmed -> only this app stops; confirmed -> goes on; one
        more name -> confirm again."""
        cases = {
            'odoo.modules-missing': lambda extra: self.verdict(
                details([('base', '18.0.1.3', 'installed'), ('a', '1', 'installed')] + extra), target({'base': ('18.0.1.3', True, CORE)})),
            'odoo.modules-skipped-deps': lambda extra: self.verdict(
                details([('m', '18.0.1.0', 'installed')] + extra), target({}),
                {'m': self.candidate('18.0.1.0', python=['zeep']), 'n': self.candidate('18.0.1.0', python=['zeep'])}),
            'odoo.superuser-objects': lambda extra: self.verdict(
                details([], superuser_objects=['CAST'] + [k for k, _v, _s in extra]), target({})),
            'odoo.databases-left': lambda extra: self.verdict(details([]), target({}),
                                                               others=['test'] + [k for k, _v, _s in extra]),
        }
        for issue_id, make in cases.items():
            with self.subTest(issue_id):
                line = next(i for i in make([])[0] if i.id == issue_id)
                key = line.key('odoo')
                converting = haissues.Sink('odoo', [], database='woowtest')
                with self.assertRaises(BackupError) as caught:
                    converting.add(line)
                self.assertEqual(caught.exception.code, 'confirmation-required')
                confirmed = haissues.Sink('odoo', [key], database='woowtest')
                self.assertIs(confirmed.add(line), line)
                more = make([('n', '18.0.1.0', 'installed')] if issue_id == 'odoo.modules-skipped-deps'
                            else [('zz', '1', 'installed')])[0]
                changed = next(i for i in more if i.id == issue_id)
                self.assertNotEqual(changed.key('odoo'), key)
                with self.assertRaises(BackupError) as caught:
                    confirmed.add(changed)
                self.assertEqual(caught.exception.code, 'confirmation-required')


class ScanTests(unittest.TestCase):
    def test_one_pass_routes_cluster_filestore_and_modules(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        pg_out = io.BytesIO()
        sink = ha_odoo.PgSink(pg_out, 70, 70)
        web = ha_odoo.FileTar(root / 'web.tar')
        web.ids = (100, 101)
        modules = ha_odoo.FileTar(root / 'modules.tar')
        report = habackup.Report()
        src = ha_odoo.scan_member(io.BytesIO(odoo_tar()), report, pg=sink, filestore_db='woowtest', filestore=web,
                                  modules=modules)
        sink.close()
        web.close()
        modules.close()
        self.assertTrue(report.complete)
        self.assertEqual(report.secret_files, 2, 'options.json and odoo.conf are never read')
        self.assertEqual((src.addon.slug, src.addon.arch, src.pg_version), ('odoo18ce', 'amd64', '16'))
        self.assertEqual(src.filestore, {'woowtest': [1, 10], 'other': [1, 2]})
        self.assertEqual(set(src.modules), {'woow_import_probe'})
        self.assertEqual(src.modules['woow_import_probe']['manifest']['version'], '18.0.1.0.0')
        pg = members_of(pg_out.getvalue())
        self.assertNotIn('postmaster.pid', pg)
        self.assertEqual(pg['pg_hba.conf'][1], ha_odoo.PG_HBA)
        self.assertEqual({(m.uid, m.gid) for m, _d in pg.values()}, {(70, 70)})
        self.assertEqual(pg['base'][0].mode, 0o700)
        self.assertEqual(pg['base/1'][0].mode, 0o600)
        self.assertEqual(pg['.'][0].mode, 0o700)
        fs = members_of((root / 'web.tar').read_bytes())
        self.assertEqual(set(fs), {'filestore/odoo', 'filestore/odoo/ab', 'filestore/odoo/ab/' + 'c' * 40})
        self.assertEqual({(m.uid, m.gid, m.mode) for m, _d in fs.values() if m.isfile()}, {(100, 101, 0o600)})
        mods = members_of((root / 'modules.tar').read_bytes())
        self.assertIn('data/addons/woow_import_probe/__manifest__.py', mods)
        self.assertFalse(any('__pycache__' in name for name in mods))

    def test_tablespaces_are_refused(self):
        extra = [{'name': 'data/postgres/pg_tblspc', 'type': 'dir'},
                 {'name': 'data/postgres/pg_tblspc/16400', 'type': 'symlink', 'linkname': '/mnt/space'}]
        with self.assertRaises(BackupError) as caught:
            ha_odoo.scan_member(io.BytesIO(odoo_tar(extra)), habackup.Report())
        self.assertEqual(caught.exception.code, 'incompatible')


class RewriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, entries):
        path = self.root / name
        path.write_bytes(hx.tar_bytes(entries))
        return path

    def test_web_data_keeps_the_rest_and_empties_sessions(self):
        live = self.write('live.tar', [
            {'name': './', 'type': 'dir', 'uid': 100, 'gid': 101, 'mode': 0o750},
            {'name': 'addons', 'type': 'dir', 'uid': 100, 'gid': 101, 'mode': 0o700},
            {'name': 'addons/18.0', 'type': 'dir', 'uid': 100, 'gid': 101, 'mode': 0o500},
            {'name': 'filestore', 'type': 'dir', 'uid': 100, 'gid': 101},
            {'name': 'filestore/odoo', 'type': 'dir', 'uid': 100, 'gid': 101},
            {'name': 'filestore/odoo/aa/old', 'data': b'old', 'uid': 100, 'gid': 101},
            {'name': 'sessions', 'type': 'dir', 'uid': 100, 'gid': 101, 'mode': 0o700},
            {'name': 'sessions/werkzeug_x.sess', 'data': b'session', 'uid': 100, 'gid': 101}])
        out = ha_odoo.FileTar(self.root / 'out.tar')
        ha_odoo.web_data_tar(live, out, sessions_ids=(1, 1))
        out.close()
        names = members_of((self.root / 'out.tar').read_bytes())
        self.assertEqual(set(names), {'.', 'addons', 'addons/18.0', 'filestore', 'sessions'})
        self.assertEqual((names['sessions'][0].uid, names['sessions'][0].gid, names['sessions'][0].mode),
                         (100, 101, 0o700))

    def test_an_unreadable_live_export_fails_the_job(self):
        garbage = self.root / 'garbage.tar'
        garbage.write_bytes(b'\x1f\x8b' + b'not a tar' * 100)
        for call in (lambda out: ha_odoo.web_data_tar(garbage, out, sessions_ids=(100, 101)),
                     lambda out: ha_odoo.addons_dir_tar(garbage, garbage, out, copy={})):
            out = ha_odoo.FileTar(self.root / f'out-{id(call)}.tar')
            with self.subTest(call=call), self.assertRaises(BackupError) as caught:
                call(out)
            out.close()
            self.assertEqual(caught.exception.code, 'job-failed')

    def test_a_link_of_this_devices_own_data_that_the_restore_would_refuse_is_left_out_and_listed(self):
        """X-NS-08, CM-11 (F3's rows, this importer's call site): with a report the links the restore refuses are listed and
        the rest is copied; without one nothing changes."""
        entries = [
            {'name': './', 'type': 'dir', 'uid': 100, 'gid': 101}, {'name': 'addons', 'type': 'dir', 'uid': 100, 'gid': 101},
            {'name': 'addons/real', 'data': b'x', 'uid': 100, 'gid': 101},
            {'name': 'addons/inside', 'type': 'symlink', 'linkname': 'real', 'uid': 100, 'gid': 101},
            {'name': 'addons/out', 'type': 'symlink', 'linkname': '../../../etc/passwd', 'uid': 100, 'gid': 101},
            {'name': 'addons/abs', 'type': 'symlink', 'linkname': '/etc/shadow', 'uid': 100, 'gid': 101},
            {'name': 'addons/hard-ok', 'type': 'hardlink', 'linkname': 'addons/real', 'uid': 100, 'gid': 101},
            {'name': 'filestore', 'type': 'dir', 'uid': 100, 'gid': 101},
            {'name': 'filestore/odoo', 'type': 'dir', 'uid': 100, 'gid': 101},
            {'name': 'filestore/odoo/aa', 'data': b'dropped', 'uid': 100, 'gid': 101},
            {'name': 'addons/hard-gone', 'type': 'hardlink', 'linkname': 'filestore/odoo/aa', 'uid': 100, 'gid': 101}]
        live = self.write('live.tar', entries)
        report = habackup.Report(names=haissues.Names)
        out = ha_odoo.FileTar(self.root / 'out.tar')
        ha_odoo.web_data_tar(live, out, sessions_ids=(1, 1), report=report)
        out.close()
        names = set(members_of((self.root / 'out.tar').read_bytes()))
        # (an absolute target counts as below the volume for the restore: podman joins it, nested._escapes: kept)
        self.assertEqual(names, {'.', 'addons', 'addons/real', 'addons/inside', 'addons/abs', 'addons/hard-ok', 'filestore',
                                 'sessions'})
        self.assertEqual({kind: list(skipped.first) for kind, skipped in report.skips.items()},
                         {'symlink': ['odoo-web-data：addons/out'], 'hardlink': ['odoo-web-data：addons/hard-gone']})
        out = ha_odoo.FileTar(self.root / 'plain.tar')
        ha_odoo.web_data_tar(live, out, sessions_ids=(1, 1))
        out.close()
        self.assertIn('addons/out', members_of((self.root / 'plain.tar').read_bytes()), 'no report: as before')
        folder = self.write('folder.tar', [{'name': './', 'type': 'dir'}, {'name': './mine', 'data': b'x'},
                                           {'name': './esc', 'type': 'symlink', 'linkname': '../../x'},
                                           {'name': './ok', 'type': 'symlink', 'linkname': 'mine'}])
        report = habackup.Report(names=haissues.Names)
        out = ha_odoo.FileTar(self.root / 'folder-out.tar')
        ha_odoo.addons_dir_tar(folder, self.write('none.tar', []), out, copy={}, report=report)
        out.close()
        self.assertEqual(set(members_of((self.root / 'folder-out.tar').read_bytes())), {'.', './mine', './ok'})
        self.assertEqual(list(report.skips['symlink'].first), ['自訂模組資料夾：esc'])

    def test_custom_modules_folder(self):
        live = self.write('live-dir.tar', [
            {'name': './', 'type': 'dir', 'mode': 0o755},
            {'name': './mine', 'type': 'dir'}, {'name': './mine/__init__.py', 'data': b''},
            {'name': './woow_import_probe', 'type': 'dir'}, {'name': './woow_import_probe/old.py', 'data': b'old'}])
        modules = self.write('mods.tar', [
            {'name': 'data/addons/woow_import_probe', 'type': 'dir', 'mode': 0o775, 'uid': 101, 'gid': 103},
            {'name': 'data/addons/woow_import_probe/__init__.py', 'data': b'', 'mode': 0o664, 'uid': 101},
            {'name': 'data/addons/woow_import_probe/run.sh', 'data': b'#!/bin/sh', 'mode': 0o775},
            {'name': 'data/addons/other/x.py', 'data': b'not selected'}])
        out = ha_odoo.FileTar(self.root / 'dir.tar')
        ha_odoo.addons_dir_tar(live, modules, out, copy={'woow_import_probe': 'data/addons'})
        out.close()
        names = members_of((self.root / 'dir.tar').read_bytes())
        self.assertEqual(set(names), {'.', './mine', './mine/__init__.py', './woow_import_probe',
                                      './woow_import_probe/__init__.py', './woow_import_probe/run.sh'})
        self.assertEqual((names['./woow_import_probe'][0].mode, names['./woow_import_probe/__init__.py'][0].mode,
                          names['./woow_import_probe/run.sh'][0].mode), (0o755, 0o644, 0o755))
        self.assertEqual({(m.uid, m.gid) for n, (m, _d) in names.items() if 'probe' in n}, {(0, 0)})


class SqlTests(unittest.TestCase):
    def test_restore_list_keeps_everything_but_extensions(self):
        toc = (';\n; Archive created at 2026-11-18\n'
               '3; 3079 16385 EXTENSION - pg_trgm \n'
               '4; 0 0 COMMENT - EXTENSION pg_trgm \n'
               '210; 1259 16390 TABLE public res_partner odoo\n'
               '211; 1259 16391 TABLE public x EXTENSION y odoo\n')
        kept = ha_odoo.filter_toc(toc)
        self.assertNotIn('EXTENSION - pg_trgm', kept)
        self.assertNotIn('COMMENT - EXTENSION', kept)
        self.assertIn('TABLE public res_partner odoo', kept)
        self.assertIn('TABLE public x EXTENSION y odoo', kept, 'only the entry type field decides')

    def test_literals_and_role(self):
        self.assertEqual(ha_odoo.sql_literal("it's"), "'it''s'")
        with self.assertRaises(BackupError):
            ha_odoo.sql_literal('a\x00b')
        verifier = 'SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy'
        self.assertTrue(ha_odoo.VERIFIER_RE.fullmatch(verifier))
        self.assertFalse(ha_odoo.VERIFIER_RE.fullmatch("SCRAM-SHA-256$4096:a$b:c'; DROP ROLE x; --"))
        sql = ha_odoo.role_sql({'password': verifier, 'login': True, 'createdb': False, 'connlimit': -1})
        self.assertTrue(sql.startswith('CREATE ROLE odoo LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION '
                                       'NOBYPASSRLS PASSWORD '))
        self.assertIn(f"'{verifier}'", sql)

    def test_settings_marker_and_carried_parameters(self):
        marker = json.dumps({'digest': 'sha256:' + 'a' * 64, 'core_date': '18.0.20260926'}, separators=(',', ':'))
        self.assertTrue(ha_odoo.marker_ok(marker, 'sha256:' + 'a' * 64))
        self.assertFalse(ha_odoo.marker_ok(marker, 'sha256:' + 'b' * 64))
        self.assertFalse(ha_odoo.marker_ok('not json', 'sha256:' + 'a' * 64))
        sql = ha_odoo.settings_sql({'base_url': 'https://odoo.example', 'freeze': None, 'marker': marker})
        self.assertIn("'web.base.url', 'https://odoo.example'", sql)
        self.assertIn("DELETE FROM ir_config_parameter WHERE key = 'web.base.url.freeze'", sql)
        self.assertIn("DELETE FROM ir_config_parameter WHERE key = 'woow_paas_platform.upgrade_attempt'", sql)
        live = [['work_mem', '8192', 'configuration file', 'user'], ['port', '5433', 'configuration file', 'postmaster'],
                ['archive_command', 'x', 'configuration file', 'sighup'], ['max_connections', '100',
                                                                           'configuration file', 'postmaster'],
                ['timezone', 'UTC', 'environment variable', 'user']]
        new = [['work_mem', '4096', 'default', 'user'], ['max_connections', '100', 'configuration file', 'postmaster']]
        self.assertEqual(ha_odoo.settings_to_carry(live, new), [('work_mem', '8192')])


QUADLETS = {
    'odoo-db.container': b"""[Container]
ContainerName=odoo18-db
Image=jcr-prod.woowtech.io/woow-paas-docker-local/paas-postgres:17.11-20260928.1549@sha256:7a47
Volume=odoo-db-data.volume:/var/lib/postgresql/data
Environment=POSTGRES_USER=postgres
Environment=POSTGRES_DB=postgres
Environment=POSTGRES_INITDB_ARGS=--data-checksums
Environment=POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
Secret=odoo18-postgres-super-password,type=mount,target=postgres_password,uid=999,gid=999,mode=0400
""",
    'odoo.container': b"""[Container]
ContainerName=odoo18-web
Image=localhost/woow-odoo-tenant-ha:20261101.1152-51856b0@sha256:b128
Volume=odoo-web-data.volume:/var/lib/odoo
Volume=%h/.local/share/odoo18/addons:/mnt/extra-addons:ro,Z
Secret=odoo18-odoo-conf,type=mount,target=/etc/odoo/odoo.conf,uid=100,gid=101,mode=0400
""",
    'odoo-db-data.volume': b'[Volume]\nVolumeName=odoo18-db-data-isolated\n',
    'odoo-web-data.volume': b'[Volume]\nVolumeName=odoo18-web-data\n',
    'odoo.network': b'[Network]\nNetworkName=odoo18-network\n',
}


class LiveTests(unittest.TestCase):
    def test_the_live_odoo_as_its_quadlets_say(self):
        live = ha_odoo.Live(QUADLETS, '/home/appowner')
        self.assertEqual((live.db_file, live.web_file, live.db_container), ('odoo-db.container', 'odoo.container',
                                                                           'odoo18-db'))
        self.assertEqual((live.db_volume, live.db_target), ('odoo18-db-data-isolated', '/var/lib/postgresql/data'))
        self.assertEqual(live.db_env['POSTGRES_INITDB_ARGS'], '--data-checksums')
        self.assertTrue(live.conf_secret.startswith('odoo18-odoo-conf,'))
        self.assertEqual(live.web_mounts, [('odoo18-web-data', '/var/lib/odoo', 'ro'),
                                           ('/home/appowner/.local/share/odoo18/addons', '/mnt/extra-addons', 'ro')])

    def test_not_a_tenant_odoo(self):
        with self.assertRaises(BackupError):
            ha_odoo.Live({'odoo.container': b'[Container]\nImage=x:1\n'}, '/home/appowner')
        for where in (b'/etc/../root', b'%h/../../etc'):
            broken = dict(QUADLETS)
            broken['odoo.container'] = broken['odoo.container'].replace(b'%h/.local/share/odoo18/addons', where)
            with self.subTest(where=where):
                live = ha_odoo.Live(broken, '/home/appowner')   # OD-08, OD-09: left out, no longer a refusal
                self.assertEqual(live.skipped_mounts, [('odoo.container', '/mnt/extra-addons')])
                self.assertEqual(live.web_mounts, [('odoo18-web-data', '/var/lib/odoo', 'ro')])


class MountTests(unittest.TestCase):
    """OD-05, OD-08, OD-09: what the Quadlet files mount that is no data of Odoo is left out, never mounted anywhere."""

    def quadlets(self, web='', db=''):
        found = dict(QUADLETS)
        found['odoo.container'] = QUADLETS['odoo.container'] + web.encode()
        found['odoo-db.container'] = QUADLETS['odoo-db.container'] + db.encode()
        return found

    def test_the_other_importers_still_get_a_refusal(self):
        """EMQX and code-server read the same function and rely on the refusal: the default did not change."""
        for source in ('/etc/localtime', '%h/../x', '%t/x', '/mnt/data'):
            with self.subTest(source=source), self.assertRaises(BackupError) as caught:
                ha_odoo.quadlet_mounts(self.quadlets(f'Volume={source}:/x:ro\n'), 'odoo.container', '/home/appowner')
            self.assertEqual(caught.exception.code, 'incompatible')

    def test_a_list_collects_what_is_left_out_and_nothing_else(self):
        skipped = []
        mounts = ha_odoo.quadlet_mounts(self.quadlets('Volume=/etc/localtime:/etc/localtime:ro\nVolume=%h/../x:/y\n'
                                                       'Volume=%t/sock:/z\nVolume=named:/data\n'),
                                        'odoo.container', '/home/appowner', skipped=skipped)
        self.assertEqual(skipped, [('odoo.container', '/etc/localtime'), ('odoo.container', '/y'), ('odoo.container', '/z')])
        self.assertEqual([m[1] for m in mounts], ['/var/lib/odoo', '/mnt/extra-addons', '/data'])

    def test_a_mount_that_is_no_data_is_left_out_of_the_live_target(self):
        live = ha_odoo.Live(self.quadlets('Volume=/etc/localtime:/etc/localtime:ro\n',
                                          'Volume=/etc/localtime:/etc/localtime:ro\n'), '/home/appowner')
        self.assertEqual(live.skipped_mounts, [('odoo-db.container', '/etc/localtime'), ('odoo.container', '/etc/localtime')])
        self.assertEqual(live.db_volume, 'odoo18-db-data-isolated')
        self.assertFalse([m for m in live.web_mounts if m[1] == '/etc/localtime'])

    def test_the_data_volume_is_the_mount_that_holds_the_cluster(self):
        quadlets = self.quadlets(db='')
        quadlets['odoo-db.container'] = QUADLETS['odoo-db.container'].replace(
            b'Volume=odoo-db-data.volume:/var/lib/postgresql/data\n',
            b'Volume=/etc/localtime:/etc/localtime:ro\nVolume=odoo-extra.volume:/backup\n'
            b'Volume=odoo-db-data.volume:/var/lib/postgresql/data\n')
        quadlets['odoo-extra.volume'] = b'[Volume]\nVolumeName=extra\n'
        live = ha_odoo.Live(quadlets, '/home/appowner')
        self.assertEqual((live.db_volume, live.db_target), ('odoo18-db-data-isolated', '/var/lib/postgresql/data'))

    def test_a_cluster_in_a_mount_that_was_left_out_stops_the_app_with_what_to_do(self):
        """Never another mount taken for the data volume."""
        for text in (b'Volume=/srv/pg:/var/lib/postgresql/data\n',
                     b'Volume=/srv/pg:/var/lib/postgresql/data\nVolume=odoo-extra.volume:/backup\n'):
            quadlets = dict(QUADLETS)
            quadlets['odoo-extra.volume'] = b'[Volume]\nVolumeName=extra\n'
            quadlets['odoo-db.container'] = QUADLETS['odoo-db.container'].replace(
                b'Volume=odoo-db-data.volume:/var/lib/postgresql/data\n', text)
            with self.subTest(text=text), self.assertRaises(BackupError) as caught:
                ha_odoo.Live(quadlets, '/home/appowner')
            self.assertEqual([(i.id, i.level) for i in caught.exception.issues], [('odoo.layout-unsupported', 'stop')])
            self.assertTrue(caught.exception.issues[0].action)

    def test_a_superuser_password_in_an_environment_file_is_said_at_once_not_as_a_cluster_that_does_not_start(self):
        """OD-57, the part that cannot be made safely: only this app, with what to do; the standard layout is untouched."""
        for text in (b'EnvironmentFile=%h/.config/odoo18/db.env\n', b'Environment=POSTGRES_PASSWORD=not-for-a-log\n',
                     b'Environment=A=1 POSTGRES_PASSWORD=x\n'):
            quadlets = dict(QUADLETS)
            quadlets['odoo-db.container'] = QUADLETS['odoo-db.container'].replace(
                b'Environment=POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password\n', text)
            with self.subTest(text=text[:20]), self.assertRaises(BackupError) as caught:
                ha_odoo.Live(quadlets, '/home/appowner')
            self.assertEqual([(i.id, i.level) for i in caught.exception.issues], [('odoo.layout-unsupported', 'stop')])
            self.assertIn('POSTGRES_PASSWORD_FILE', caught.exception.issues[0].action)
            self.assertNotIn('not-for-a-log', repr(caught.exception.issues[0].view('odoo')))
        quadlets = dict(QUADLETS)
        quadlets['odoo-db.container'] += b'EnvironmentFile=%h/.config/odoo18/other.env\n'   # next to the standard secret: fine
        self.assertEqual(ha_odoo.Live(quadlets, '/home/appowner').db_user, 'postgres')

    def test_the_superuser_name_may_hold_any_character_but_a_control_one(self):
        """OD-05: it is one argument, never a shell word or SQL."""
        for name in ('my admin$1', "o'brien", '資料庫管理員', 'a=b', '-x', 'x' * 63):
            quadlets = dict(QUADLETS)
            quadlets['odoo-db.container'] = QUADLETS['odoo-db.container'].replace(
                b'Environment=POSTGRES_USER=postgres', f'Environment="POSTGRES_USER={name}"'.encode())
            with self.subTest(name=name):
                self.assertEqual(ha_odoo.Live(quadlets, '/home/appowner').db_user, name)
        for name in ('x' * 64, '資' * 22):
            quadlets = dict(QUADLETS)
            quadlets['odoo-db.container'] = QUADLETS['odoo-db.container'].replace(
                b'Environment=POSTGRES_USER=postgres', f'Environment="POSTGRES_USER={name}"'.encode())
            with self.subTest(name=name[:5], length=len(name.encode())), self.assertRaises(BackupError):
                ha_odoo.Live(quadlets, '/home/appowner')


class DatabaseNameTests(unittest.TestCase):
    """OD-31: the name of an HA database goes to PostgreSQL through PGDATABASE, never as the argument of -d."""

    def test_plain_names_keep_the_old_command_line_and_others_use_the_environment(self):
        self.assertEqual(ha_odoo.database_arguments('odoo'), (['-d', 'odoo'], None))
        self.assertEqual(ha_odoo.database_arguments('woow-test.1_x'), (['-d', 'woow-test.1_x'], None))
        for name in ('a b', 'a=b', 'host=evil dbname=x', 'postgresql://x/y', '資料庫', 'db$1', "o'brien", '-d', 'x;y'):
            with self.subTest(name=name):
                self.assertEqual(ha_odoo.database_arguments(name), ([], {'PGDATABASE': name}))
        self.assertEqual(ha_odoo.database_arguments('odoo', by_env=True), ([], {'PGDATABASE': 'odoo'}))

    def test_a_name_postgresql_cannot_have_is_refused_before_anything_runs(self):
        for name in ('', None, 5, 'a\nb', 'a\x00b', 'x' * 64, '資' * 22, 'a\x85b'):
            with self.subTest(name=name), self.assertRaises(BackupError) as caught:
                ha_odoo.database_arguments(name)
            self.assertEqual(caught.exception.code, 'internal-error')

    def test_a_cluster_asks_by_the_environment_when_it_is_told_to_or_the_name_is_odd(self):
        tmp = hafakes.FakeTmp()
        seen = []
        original = tmp.exec

        def exec_(role, argv, **kwargs):
            seen.append((list(argv), kwargs.get('env')))
            return original(role, argv, **kwargs)

        tmp.exec = exec_
        cluster = ha_odoo.Cluster(tmp, 'hapg')
        cluster.query_json('SELECT 1', 'odoo')
        cluster.query_json('SELECT 1', 'ha=prod', )
        cluster.query_json('SELECT 1', 'odoo', by_env=True)
        cluster.script("SELECT 2;\n", 'my db')
        cluster.statement('CHECKPOINT;', 'x y', by_env=True)
        (plain, plain_env), (odd, odd_env), (forced, _e1), (script, script_env), (statement, _e2) = seen
        self.assertEqual((plain[plain.index('-U'):plain.index('-c')], plain_env), (['-U', 'postgres', '-d', 'odoo'], None))
        for argv, env, name in ((odd, odd_env, 'ha=prod'), (forced, _e1, 'odoo'), (script, script_env, 'my db'),
                                (statement, _e2, 'x y')):
            self.assertNotIn('-d', argv)
            self.assertEqual(env, {'PGDATABASE': name})
            self.assertFalse([part for part in argv if name in part], 'the name is in no argument')

    def test_what_is_asked_of_an_ha_database_never_carries_its_name_in_the_command(self):
        tmp = hafakes.FakeTmp(hafakes.Psql(lambda sql, db: [True] * 7 if sql == ha_odoo.IS_ODOO_SQL else None))
        calls = []
        original = tmp.exec

        def exec_(role, argv, **kwargs):
            calls.append((list(argv), kwargs.get('env')))
            return original(role, argv, **kwargs)

        tmp.exec = exec_
        cluster = ha_odoo.Cluster(tmp, 'hapg')
        with self.assertRaises(BackupError):   # the answers of the double are no document: it stops after the first
            ha_odoo.database_details(cluster, 'a b=1')
        self.assertTrue(calls)
        for argv, env in calls:
            self.assertNotIn('-d', argv)
            self.assertEqual(env, {'PGDATABASE': 'a b=1'})


class TargetTests(unittest.TestCase):
    """OD-12, OD-13, OD-72: what the app settings hold beyond the tenant Odoo goes along; what they do not list is not used."""

    def target(self, volumes=('odoo18-db-data-isolated', 'odoo18-web-data'), dirs=('.local/share/odoo18/addons',),
               postgres=()):
        sink = haissues.Sink('odoo')
        runner = types.SimpleNamespace(home='/home/appowner')
        work = types.SimpleNamespace(runner=lambda _app: runner, quadlets=lambda _app: dict(QUADLETS))
        app = types.SimpleNamespace(id='odoo', name='Odoo 18', volumes=[{'name': n} for n in volumes],
                                    data_dirs=[{'path': d} for d in dirs], postgres=list(postgres))
        return ha_odoo.Target(work, app, sink), sink

    def test_the_tenant_layout_has_nothing_extra(self):
        target, sink = self.target()
        self.assertEqual((target.extra_volumes, target.extra_dirs, target.addons_rel, target.addons_index),
                         ([], [], '.local/share/odoo18/addons', 0))
        self.assertEqual(sink.found, [])

    def test_other_volumes_and_folders_of_the_settings_are_carried_and_said(self):
        target, sink = self.target(volumes=('odoo18-db-data-isolated', 'extra', 'odoo18-web-data'),
                                   dirs=('other/dir', '.local/share/odoo18/addons'))
        self.assertEqual((target.extra_volumes, target.extra_dirs, target.addons_index), (['extra'], ['other/dir'], 1))
        (line,) = sink.found
        self.assertEqual((line.id, line.level, list(line.names)), ('odoo.extras-carried', 'auto', ['extra', 'other/dir']))

    def test_a_modules_folder_the_settings_do_not_list_is_left_alone_and_said(self):
        target, sink = self.target(dirs=('other/dir',))
        self.assertEqual((target.addons_rel, target.addons_index, target.extra_dirs), (None, None, ['other/dir']))
        self.assertEqual([(i.id, i.level) for i in sink.found], [('odoo.addons-folder-undeclared', 'notice'),
                                                                 ('odoo.extras-carried', 'auto')])

    def test_what_the_import_cannot_place_stops_this_app_only(self):
        for kwargs in ({'volumes': ('odoo18-db-data-isolated',)}, {'volumes': ('odoo18-web-data',)},
                       {'postgres': [{'id': 'main'}]}):
            with self.subTest(kwargs=kwargs), self.assertRaises(BackupError) as caught:
                self.target(**kwargs)
            self.assertEqual([(i.id, i.level) for i in caught.exception.issues], [('odoo.layout-unsupported', 'stop')])
            self.assertEqual(caught.exception.code, 'incompatible')
            self.assertTrue(caught.exception.issues[0].action)


class ConfTests(unittest.TestCase):
    """OD-15, OD-20, OD-21: this device's own configuration says its database, its account and the password."""

    def tmp_with(self, doc):
        calls = []

        class Tmp:
            def run(self, role, image, args, **kwargs):
                calls.append((role, image, list(args), kwargs))
                return hafakes.Result(0, json.dumps(doc).encode() if not isinstance(doc, bytes) else doc, b'')

        return Tmp(), calls

    def read(self, doc):
        tmp, calls = self.tmp_with(doc)
        live = types.SimpleNamespace(web_image='localhost/odoo:1', conf_secret='odoo18-odoo-conf,type=mount,'
                                     'target=/etc/odoo/odoo.conf,uid=100,gid=101,mode=0400')
        work = types.SimpleNamespace(temp=lambda _app: tmp)
        return ha_odoo.read_conf(work, types.SimpleNamespace(id='odoo'), live), calls

    def test_the_three_settings_are_read_in_a_container_without_a_network_and_the_password_is_masked(self):
        password = 'Conf-Pw-for-the-test-0123456789'
        self.addCleanup(jobs.unmask_secret, password)
        conf, calls = self.read({'db_name': 'prod', 'db_user': 'odoo18', 'db_password': password})
        self.assertEqual(conf, {'db_name': 'prod', 'db_user': 'odoo18', 'db_password': password})
        (role, image, args, kwargs), = calls
        self.assertEqual((role, image, args[-1]), ('conf', 'localhost/odoo:1', ha_odoo.CONF_PATH))
        self.assertEqual((kwargs['secrets'], kwargs['read_only_root'], kwargs['entrypoint']),
                         (['odoo18-odoo-conf,type=mount,target=/etc/odoo/odoo.conf,uid=100,gid=101,mode=0400'], True,
                          'python3'))
        self.assertNotIn('volumes', kwargs, 'no host folder is mounted')
        self.assertNotIn(password, jobs.redact(f'a line with {password} in it'))
        self.assertNotIn(password, repr(args))

    def test_what_cannot_be_read_gives_nothing_and_the_tenants_own_names(self):
        for doc in ({'error': 'FileNotFoundError'}, b'not json', {'db_password': 'x\x01y', 'db_name': 5}, [], {}):
            with self.subTest(doc=doc):
                self.assertEqual(self.read(doc)[0], {})
        live = ha_odoo.Live(QUADLETS, '/home/appowner')
        live.apply_conf({})
        self.assertEqual((live.db_name, live.db_role), ('odoo', 'odoo'))
        live.apply_conf({'db_name': 'prod', 'db_user': 'odoo18'})
        self.assertEqual((live.db_name, live.db_role), ('prod', 'odoo18'))

    def test_a_name_the_tools_cannot_take_stops_this_app(self):
        live = ha_odoo.Live(QUADLETS, '/home/appowner')
        for conf in ({'db_name': 'a b'}, {'db_name': '資料'}, {'db_user': 'odoo-18'}, {'db_user': 'o"x'}):
            with self.subTest(conf=conf), self.assertRaises(BackupError) as caught:
                live.apply_conf(conf)
            self.assertEqual([(i.id, i.level) for i in caught.exception.issues], [('odoo.layout-unsupported', 'stop')])
        self.assertEqual((live.db_name, live.db_role), ('odoo', 'odoo'))

    def test_the_role_statement_names_the_role_of_the_configuration(self):
        role = {'password': 'SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy', 'login': True}
        self.assertTrue(ha_odoo.role_sql(role).startswith('CREATE ROLE odoo LOGIN'))
        self.assertTrue(ha_odoo.role_sql(role, 'odoo18').startswith('CREATE ROLE "odoo18" LOGIN'))
        with self.assertRaises(BackupError):
            ha_odoo.role_sql(role, 'a"b')
        self.assertIn("rolname = 'odoo18'", ha_odoo.live_role_sql('odoo18'))
        self.assertIn("rolname = 'a''b'", ha_odoo.live_role_sql("a'b"))
        self.assertEqual(ha_odoo.LIVE_ROLE_SQL, ha_odoo.live_role_sql('odoo'))


class ConfScriptTests(unittest.TestCase):
    """The script that reads this device's odoo.conf in the container, run here by a real Python on the committed template
    of the tenant install (rendered with test values): only the three settings come out, in any of the shapes the file has."""

    TEMPLATE = (Path(__file__).resolve().parents[1] / 'e2e' / 'lab' / 'evidence' / 'arm54-final-20261123'
                / 'odoo-package-c578b8a' / 'config' / 'odoo.conf.template')

    def run_script(self, text):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'odoo.conf'
            path.write_text(text, encoding='utf-8')
            done = subprocess.run([sys.executable, '-I', '-', str(path)], input=ha_odoo.CONF_SCRIPT.encode(),
                                  capture_output=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stderr, b'', 'nothing on stderr: a value never reaches it')
        return json.loads(done.stdout)

    def rendered(self, **values):
        base = {'POSTGRES_PASSWORD': 'Pw-from-the-template-0123', 'ODOO_ADMIN_PASSWORD': 'Master-0123456789',
                'WOOW_ODOO_LIST_DB': 'False', 'DB_NAME_LINE': 'db_name = odoo', 'DB_FILTER_LINE': 'dbfilter = ^odoo$',
                'WOOW_ODOO_WORKERS': '0', 'WOOW_ODOO_MAX_CRON_THREADS': '2', 'WOOW_ODOO_DB_MAXCONN': '8',
                'WOOW_ODOO_LIMIT_TIME_CPU': '600', 'WOOW_ODOO_LIMIT_TIME_REAL': '1200',
                'WOOW_ODOO_LIMIT_TIME_REAL_CRON': '600', 'WOOW_ODOO_LIMIT_REQUEST': '65536', 'SMTP_LINES': ''}
        base.update(values)
        text = self.TEMPLATE.read_text(encoding='utf-8')
        for key, value in base.items():
            text = text.replace(f'@@{key}@@', value)
        return text

    def test_the_tenants_own_template_gives_its_database_account_and_password_and_nothing_else(self):
        doc = self.run_script(self.rendered())
        self.assertEqual(doc, {'db_name': 'odoo', 'db_user': 'odoo', 'db_password': 'Pw-from-the-template-0123'})
        self.assertNotIn('Master-0123456789', json.dumps(doc), 'the master password is never printed')

    def test_other_shapes_of_the_file(self):
        self.assertEqual(self.run_script(self.rendered(DB_NAME_LINE='db_name = prod,other')).get('db_name'), 'prod')
        self.assertNotIn('db_name', self.run_script(self.rendered(DB_NAME_LINE='')), 'no database named: the tenant default')
        self.assertNotIn('db_name', self.run_script(self.rendered(DB_NAME_LINE='db_name = False')))
        self.assertEqual(self.run_script(self.rendered(POSTGRES_PASSWORD='p%w=d $x'))['db_password'], 'p%w=d $x')
        self.assertNotIn('db_password', self.run_script(self.rendered(POSTGRES_PASSWORD='False')))
        self.assertEqual(self.run_script('[other]\ndb_user = x\n'), {})
        self.assertEqual(self.run_script(''), {})

    def test_a_file_that_does_not_parse_says_only_what_kind_of_error_it_was(self):
        doc = self.run_script('this is = not a config file\nno section at all db_password = LeakMe-0123\n')
        self.assertEqual(set(doc), {'error'})
        self.assertNotIn('LeakMe', json.dumps(doc))


class InventoryTests(unittest.TestCase):
    """OD-35, OD-73: one module that cannot be read is skipped; the wait and the room grow with the data."""

    def inventory(self, doc, **kwargs):
        runs = []

        class Tmp:
            def run(self, role, image, args, **options):
                runs.append(options)
                return hafakes.Result(0, json.dumps(doc).encode(), b'')

        live = types.SimpleNamespace(web_image='localhost/odoo:1', conf_secret='s', web_mounts=[])
        return ha_odoo.target_inventory(Tmp(), live, **kwargs), runs

    ROWS = [['base', '18.0.1.3', True, CORE], ['x', '18.0.1.0', False, EXTRA]]

    def test_the_modules_that_could_not_be_read_are_named_and_the_others_listed(self):
        found, _runs = self.inventory({'version': '18.0', 'modules': self.ROWS, 'broken': ['bad', 'bad', 'not valid']})
        self.assertEqual(sorted(found['modules']), ['base', 'x'])
        self.assertEqual(found['broken'], ['bad'])

    def test_only_a_list_without_any_module_stops(self):
        for doc in ({'modules': []}, {'error': 'ImportError', 'modules': self.ROWS}, {'modules': [['bad row']]},
                    {'modules': 'x'}, []):
            with self.subTest(doc=doc), self.assertRaises(BackupError) as caught:
                self.inventory(doc)
            self.assertEqual(caught.exception.code, 'job-failed')
            self.assertIn('模組清單', caught.exception.message)

    def test_an_answer_over_the_room_is_still_refused(self):
        """OD-73: a bigger room is not no room: a listing over the ceiling (or over the floor without a size) stops this app."""
        rows = [[f'm{i}', '18.0.1.0', True, CORE] for i in range(2000)]
        small = {'modules': rows, 'padding': 'x' * (ha_odoo.SCAN_OUTPUT + 1)}
        with self.assertRaises(BackupError) as caught:
            self.inventory(small)
        self.assertEqual(caught.exception.code, 'job-failed')
        found, _runs = self.inventory(small, size=500 * 1024 ** 3)       # a big backup gets room for it
        self.assertEqual(len(found['modules']), 2000)
        huge = {'modules': rows, 'padding': 'x' * (ha_odoo.SQL_OUTPUT_CEILING + 1)}
        with self.assertRaises(BackupError):
            self.inventory(huge, size=500 * 1024 ** 3)

    def test_the_wait_and_the_room_for_the_list_grow_with_the_data(self):
        _found, (plain,) = self.inventory({'modules': self.ROWS})
        _found, (big,) = self.inventory({'modules': self.ROWS}, size=500 * 1024 ** 3)
        self.assertEqual((plain['timeout'], plain['max_output']), (600, ha_odoo.SCAN_OUTPUT))
        self.assertGreater(big['timeout'], 600)
        self.assertGreater(big['max_output'], ha_odoo.SCAN_OUTPUT)
        self.assertLessEqual(big['timeout'], 24 * 3600)


class WaitTests(unittest.TestCase):
    """OD-28: the wait for a throwaway PostgreSQL grows with the data; a server that is gone still ends it at once."""

    def work(self):
        return types.SimpleNamespace(log=lambda _t: None, checkpoint=lambda: None)

    def start(self, size):
        recorded = {}

        class Fake(ha_odoo.Cluster):
            def wait_ready(self, **kwargs):
                recorded.update(kwargs)

        calls = []

        class Runner:
            uid = None

            def podman(self, *args, **kwargs):
                calls.append(args)
                return hafakes.Result(0, b'', b'')

        tmp = tempctr.TempObjects(Runner(), 'j20261118T120000Z-0123abcd', cpus=None)
        tmp.volume('hapg')
        with mock.patch.object(ha_odoo, 'Cluster', Fake):
            ha_odoo.start_ha_cluster(self.work(), tmp, 'docker.io/library/postgres:16.15-alpine', size=size)
        return recorded

    def test_the_wait_for_ha_cluster_grows_with_its_size(self):
        self.assertEqual(self.start(None)['timeout'], ha_odoo.PG_READY_TIMEOUT)
        self.assertEqual(self.start(1024)['timeout'], ha_odoo.PG_READY_TIMEOUT)
        self.assertGreater(self.start(200 * 1024 ** 3)['timeout'], ha_odoo.PG_READY_TIMEOUT)

    def test_a_server_that_is_gone_ends_the_wait_at_once_however_long_it_may_be(self):
        class Gone(hafakes.FakeTmp):
            def exec(self, *args, **kwargs):
                return hafakes.Result(2, b'', b'')

            def running(self, role):
                return False

        waited = []
        cluster = ha_odoo.Cluster(Gone(), 'hapg', sleep=waited.append)
        with self.assertRaises(BackupError) as caught:
            cluster.wait_ready(timeout=10 ** 6)
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertEqual(waited, [], 'it did not wait at all')


class LimitTests(unittest.TestCase):
    """OD-73: the room for an answer grows with the data, but never without an end (HA's server and dump are untrusted)."""

    def test_the_room_for_a_modules_list_grows_with_the_database_up_to_a_ceiling(self):
        seen = []

        class Cluster:
            def query_json(self, sql, database='postgres', **kwargs):
                seen.append((kwargs['max_output'], kwargs['by_env']))
                return [False]

        for size in (None, 1024, 10 * 1024 ** 3, 10 * 1024 ** 4):
            ha_odoo.database_details(Cluster(), 'x', size)
        rooms = [room for room, _env in seen]
        self.assertEqual(rooms[:2], [ha_odoo.SQL_OUTPUT, ha_odoo.SQL_OUTPUT])
        self.assertGreater(rooms[2], ha_odoo.SQL_OUTPUT)
        self.assertEqual(rooms[3], ha_odoo.SQL_OUTPUT_CEILING)
        self.assertTrue(all(env is True for _room, env in seen), 'an HA name is always handed over by the environment')

    def test_the_room_for_the_dump_list_and_the_time_to_read_it_grow_with_the_dump(self):
        calls = []

        class Tmp(hafakes.FakeTmp):
            def exec(self, role, argv, **kwargs):
                calls.append((list(argv), kwargs.get('timeout'), kwargs.get('max_output')))
                return super().exec(role, argv, **kwargs)

        def listing(role, argv, data, stdout):
            return hafakes.Result(0, hx.toc_listing([b'3456; 1259 16400 TABLE public res_partner odoo']), b'')

        tmp = Tmp(handlers={'pg_restore': listing})
        with tempfile.TemporaryDirectory() as folder:
            dump = Path(folder) / 'odoo.dump'
            dump.write_bytes(b'x' * 1000)
            with mock.patch.object(ha_odoo.os.path, 'getsize', lambda _p: 400 * 1024 ** 3):
                ha_odoo.restore_dump(types.SimpleNamespace(log=lambda _t: None), tmp, dump, 'woowtest')
        (_a, list_timeout, list_room), = [c for c in calls if c[0][:2] == ['pg_restore', '-l']]
        (_b, restore_timeout, _r), = [c for c in calls if c[0][:1] == ['pg_restore'] and '-d' in c[0]]
        self.assertGreater(list_timeout, ha_odoo.DUMP_TIMEOUT)
        self.assertGreater(restore_timeout, ha_odoo.DUMP_TIMEOUT)
        self.assertEqual(list_room, ha_odoo.TOC_OUTPUT_CEILING)


class SmallPieceTests(unittest.TestCase):
    def test_the_list_filter_leaves_out_kinds_and_their_comments_but_nothing_that_only_looks_like_them(self):
        toc = (b'1; 0 0 ENCODING - ENCODING\n3500; 3466 16500 EVENT TRIGGER - grab postgres\n'
               b'3501; 0 0 COMMENT - EVENT TRIGGER grab postgres\n3502; 0 0 SECURITY LABEL - EVENT TRIGGER grab postgres\n'
               b'3503; 1259 16501 TABLE public EVENT TRIGGER odoo\n3504; 1259 16502 FOREIGN TABLE public ft odoo\n'
               b'3505; 0 0 COMMENT - EXTENSION pg_trgm\n3506; 3079 1 EXTENSION - pg_trgm\n').decode()
        lines = ha_odoo.filter_toc(toc, skip=['EVENT TRIGGER']).splitlines()
        self.assertEqual(lines, ['1; 0 0 ENCODING - ENCODING', ';3500; 3466 16500 EVENT TRIGGER - grab postgres',
                                 ';3501; 0 0 COMMENT - EVENT TRIGGER grab postgres',
                                 ';3502; 0 0 SECURITY LABEL - EVENT TRIGGER grab postgres',
                                 '3503; 1259 16501 TABLE public EVENT TRIGGER odoo',
                                 '3504; 1259 16502 FOREIGN TABLE public ft odoo'])
        self.assertNotIn('EXTENSION - pg_trgm', ha_odoo.filter_toc(toc), 'the extensions are always left out')

    def test_a_result_without_choices_still_gets_the_old_blockers_and_one_with_them_gets_none(self):
        found = {'odoo': {'databases': []}}
        self.assertEqual(ha_odoo.check_blockers(found), ['HA 的 Odoo 沒有任何資料庫。'])
        found['odoo']['databases'] = [{'name': 'x', 'ok': False}]
        self.assertEqual(ha_odoo.check_blockers(found), ['HA 的 Odoo 資料庫都不能搬過來（原因見各資料庫）。'])
        self.assertEqual(ha_odoo.check_blockers({**found, 'choices': {'database': []}}), [])

    def test_the_databases_that_stay_on_ha_are_a_note_of_the_conversion(self):
        notes, _reminders = ha_odoo.import_texts({'custom_modules': [], 'left_databases': ['a', 'b']})
        self.assertTrue(any('會留在 HA' in note and 'a、b' in note for note in notes))
        self.assertFalse(any('會留在 HA' in note for note in ha_odoo.import_texts({})[0]))


class EntryStub:
    def __init__(self, kind='file', data=b'', mtime=0):
        self.kind, self.data, self.mtime, self.size = kind, data, mtime, len(data)
        self.pos = 0

    def read(self, n):
        chunk = self.data[self.pos:self.pos + n]
        self.pos += len(chunk)
        return chunk


class CheckCleanupTests(unittest.TestCase):
    def test_failure_in_member_pass_cleans_temporary_cluster(self):
        temp = mock.Mock()
        work = mock.Mock()
        work.temp.return_value = temp
        target = types.SimpleNamespace(live=mock.Mock(), addons_rel='.local/share/odoo18/addons')
        with mock.patch.object(ha_odoo, 'Target', return_value=target), \
             mock.patch.object(ha_odoo, 'read_conf', return_value={}), \
             mock.patch.object(ha_odoo.hatarget, 'ensure_image'), \
             mock.patch.object(ha_odoo, 'live_image_id'), \
             mock.patch.object(ha_odoo, 'live_settings'), \
             mock.patch.object(ha_odoo, 'live_role'), \
             mock.patch.object(ha_odoo, 'pick_pg16', return_value='image'), \
             mock.patch.object(ha_odoo, 'member_pass', side_effect=ValueError('invalid backup')):
            with self.assertRaisesRegex(ValueError, 'invalid backup'):
                ha_odoo.check(work, object())
        temp.remove.assert_called_once_with('hapg')
        temp.remove_volume.assert_called_once_with('hapg')


class HaClusterTests(unittest.TestCase):
    """HA's PostgreSQL is untrusted (review HA-SEC-01)."""

    def test_the_configuration_and_recovery_files_never_reach_the_server(self):
        out = io.BytesIO()
        sink = ha_odoo.PgSink(out, 70, 70)
        sink.add('.', EntryStub('dir'))
        sink.add('PG_VERSION', EntryStub(data=b'16\n'), b'16\n')
        sink.add('postgresql.conf', EntryStub(data=b"shared_preload_libraries = '/var/lib/postgresql/data/evil.so'\n"))
        sink.add('postgresql.auto.conf', EntryStub(data=b'restore_command = \'sh -c "id > /tmp/pwned"\'\n'))
        sink.add('recovery.signal', EntryStub())
        sink.add('standby.signal', EntryStub())
        sink.add('pg_ident.conf', EntryStub('dir'))           # whatever kind HA has there
        sink.add('pg_ident.conf/x', EntryStub(data=b'x'))
        sink.add('postmaster.pid', EntryStub(data=b'1\n'))
        sink.add('evil.so', EntryStub(data=b'\x7fELF'))
        sink.close()
        out.seek(0)
        with tarfile.open(fileobj=out, mode='r') as tar:
            files = {m.name: (tar.extractfile(m).read() if m.isfile() else None) for m in tar}
        self.assertNotIn('recovery.signal', files)
        self.assertNotIn('standby.signal', files)
        self.assertNotIn('postmaster.pid', files)
        self.assertNotIn('pg_ident.conf/x', files)
        self.assertEqual(files['postgresql.conf'], ha_odoo.PG_CONF)
        self.assertNotIn(b'restore_command', files['postgresql.auto.conf'])
        self.assertEqual(files['pg_hba.conf'], ha_odoo.PG_HBA)   # added when HA has none
        self.assertEqual(files['pg_ident.conf'], b'')
        self.assertEqual(files['evil.so'], b'\x7fELF')         # data stays data: the volume is mounted noexec

    def test_the_server_starts_with_every_library_and_command_setting_overridden(self):
        args = ha_odoo.ha_server_args()
        settings = dict(arg.split('=', 1) for arg in args[2::2])
        for name in ('shared_preload_libraries', 'session_preload_libraries', 'local_preload_libraries',
                     'archive_command', 'restore_command', 'archive_library', 'primary_conninfo', 'listen_addresses'):
            self.assertEqual(settings[name], '', name)
        self.assertEqual((settings['archive_mode'], settings['ssl'], settings['jit']), ('off', 'off', 'off'))
        self.assertEqual(settings['dynamic_library_path'], '$libdir')
        self.assertEqual(settings['hba_file'], '/var/lib/postgresql/data/pg_hba.conf')
        runner_calls = []

        class Runner:
            uid = None

            def podman(self, *args, **kwargs):
                runner_calls.append(args)
                return hafakes.Result(0, b'', b'')

        tmp = tempctr.TempObjects(Runner(), 'j20261118T120000Z-0123abcd', cpus=None)
        tmp.volume('hapg')
        work = types.SimpleNamespace(log=lambda _t: None, checkpoint=lambda: None)
        ha_odoo.start_ha_cluster(work, tmp, 'docker.io/library/postgres:16.15-alpine')
        run = next(call for call in runner_calls if call[0] == 'run')
        self.assertIn('--read-only', run)
        self.assertIn(f'{tmp.name("hapg")}:/var/lib/postgresql/data:rw,noexec,nosuid,nodev', run)
        self.assertEqual(run[run.index('--network') + 1], 'none')

    TOC_LINES = [b'5; 2615 2200 SCHEMA - public pg_database_owner', b'2; 3079 16385 EXTENSION - pg_trgm ',
                 b'3456; 1259 16400 TABLE public res_partner odoo', b'3457; 0 16400 TABLE DATA public res_partner odoo']
    BAD_LINES = [b'3500; 3466 16500 EVENT TRIGGER - grab postgres', b'3501; 0 0 COMMENT - EVENT TRIGGER grab postgres',
                 b'3502; 1255 16501 FUNCTION public f() odoo']

    def restore(self, listing, *, sink=None, restore_error=None, new_db='odoo', role='odoo'):
        def pg_restore(role_, argv, data, stdout):
            if argv[:2] == ['pg_restore', '-l']:
                return hafakes.Result(0, listing, b'')
            if restore_error is not None:
                raise restore_error
            return hafakes.Result(0, b'', b'')
        tmp = hafakes.FakeTmp(handlers={'pg_restore': pg_restore})
        logged = []
        with tempfile.TemporaryDirectory() as folder:
            dump = Path(folder) / 'odoo.dump'
            dump.write_bytes(b'PGDMP-data')
            ha_odoo.restore_dump(types.SimpleNamespace(log=logged.append), tmp, dump, 'woowtest', sink=sink,
                                 new_db=new_db, role=role)
        return tmp, logged

    def test_the_superuser_kinds_of_the_list_are_found(self):
        bad = hx.toc_listing(self.TOC_LINES + self.BAD_LINES)
        self.assertEqual(ha_odoo.superuser_kinds(bad.decode()), ['EVENT TRIGGER'])
        self.assertEqual(ha_odoo.superuser_kinds(hx.toc_listing(self.TOC_LINES).decode()), [])

    def test_a_dump_with_objects_only_a_superuser_can_create_is_restored_without_them_as_the_role(self):
        """OD-41, OD-58: the entries (and their comments) are commented out of the list, named in a reminder, the rest is
        restored as the role itself; the old way (no sink) still refuses."""
        sink = haissues.Sink('odoo', [], database='woowtest')
        tmp, _log = self.restore(hx.toc_listing(self.TOC_LINES + self.BAD_LINES), sink=sink)
        restore = next(argv for _role, argv, _data in tmp.calls if argv[0] == 'pg_restore' and '-d' in argv)
        self.assertEqual(restore[:3], ['pg_restore', '-U', 'odoo'])
        self.assertNotIn('--role=odoo', restore)
        self.assertIn('--single-transaction', restore)
        self.assertEqual(next(data for _r, argv, data in tmp.calls if argv is restore), b'PGDMP-data')  # on stdin
        written = next(data for _r, argv, data in tmp.calls if argv[0] == 'sh').decode()
        self.assertNotIn('EXTENSION', written)
        lines = written.splitlines()
        self.assertIn(';3500; 3466 16500 EVENT TRIGGER - grab postgres', lines)
        self.assertIn(';3501; 0 0 COMMENT - EVENT TRIGGER grab postgres', lines)
        self.assertIn('3502; 1255 16501 FUNCTION public f() odoo', lines, 'a function is not a kind that can be left out')
        self.assertIn('3456; 1259 16400 TABLE public res_partner odoo', lines)
        (note,) = [i for i in sink.found if i.id == 'odoo.superuser-skipped']
        self.assertEqual((note.level, list(note.names), note.database), ('notice', ['EVENT TRIGGER'], 'woowtest'))
        with self.assertRaises(BackupError) as caught:
            self.restore(hx.toc_listing(self.TOC_LINES + self.BAD_LINES))
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('EVENT TRIGGER', caught.exception.message)

    def test_a_dump_without_such_objects_is_restored_whole_into_the_names_of_this_device(self):
        tmp, _log = self.restore(hx.toc_listing(self.TOC_LINES), new_db='prod', role='odoo18')
        restore = next(argv for _role, argv, _data in tmp.calls if argv[0] == 'pg_restore' and '-d' in argv)
        self.assertEqual((restore[:3], restore[-2:]), (['pg_restore', '-U', 'odoo18'], ['-d', 'prod']))
        written = next(data for _r, argv, data in tmp.calls if argv[0] == 'sh').decode()
        self.assertFalse([line for line in written.splitlines() if line.startswith(';') and line[1:2].isdigit()])

    def test_what_cannot_be_restored_without_those_objects_stops_only_this_app(self):
        """OD-58: 'only if it does not fit': the restore failing is this app's stop, nothing changed."""
        error = CommandError('podman exec 執行失敗（結束碼 1）。', returncode=1)
        sink = haissues.Sink('odoo', [], database='woowtest')
        with self.assertRaises(BackupError) as caught:
            self.restore(hx.toc_listing(self.TOC_LINES), sink=sink, restore_error=error)
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertEqual([(i.id, i.level) for i in caught.exception.issues], [('odoo.restore-failed', 'stop')])
        self.assertTrue(caught.exception.issues[0].action)
        with self.assertRaises(BackupError) as caught:
            self.restore(hx.toc_listing(self.TOC_LINES), restore_error=error)
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('超級使用者', caught.exception.message)


class SettingsCarryTests(unittest.TestCase):
    """The live cluster's own settings reach the new cluster with ALTER SYSTEM, outside any transaction (C-19), list
    settings element by element (C-06)."""

    LIVE = [['work_mem', '8192', 'configuration file', 'user'],
            ['search_path', '"$user", public, extra', 'configuration file', 'user'],
            ['log_line_prefix', '%m [%p]; ', 'configuration file', 'sighup'],
            ['port', '5433', 'configuration file', 'postmaster']]
    NEW = [['work_mem', '4096', 'default', 'user']]

    def carry(self):
        psql = hafakes.Psql()

        def answer(sql, _database):
            if sql.startswith('SELECT coalesce(json_agg(json_build_array(name, setting, source'):
                return self.NEW
            if 'pg_file_settings' in sql:
                return [[name, value, ''] for name, value in psql.auto_conf.items()]
            return None

        psql.answer = answer
        live_calls = []

        class Runner:
            def podman(self, *args, **kwargs):
                live_calls.append(args)
                return hafakes.Result(0, json.dumps(SettingsCarryTests.LIVE).encode(), b'')

        work = types.SimpleNamespace(runner=lambda _app: Runner(), log=lambda _text: None)
        live = types.SimpleNamespace(db_container='odoo18-db', db_user='postgres')
        tmp = hafakes.FakeTmp(psql)
        cluster = ha_odoo.Cluster(tmp, 'odoo-db')
        carried = ha_odoo.carry_settings(work, types.SimpleNamespace(id='odoo'), live, cluster)
        return carried, psql, tmp, live_calls

    def test_alter_system_runs_one_statement_per_psql_call_outside_a_transaction(self):
        carried, psql, tmp, live_calls = self.carry()
        self.assertEqual(carried, ['log_line_prefix', 'search_path', 'work_mem'])
        alters = [(statement, in_tx) for _db, statement, in_tx in psql.executed if statement.startswith('ALTER SYSTEM')]
        self.assertEqual(len(alters), 3)
        self.assertFalse(any(in_tx for _s, in_tx in alters))
        for _role, argv, data in tmp.calls:
            if data and b'ALTER SYSTEM' in data:
                self.assertNotIn('-1', argv)
                self.assertEqual(len(hafakes.split_sql(data.decode())), 1)
        self.assertEqual(psql.auto_conf['search_path'], "'$user', 'public', 'extra'")
        self.assertEqual(psql.auto_conf['log_line_prefix'], "'%m [%p]; '")
        self.assertTrue(any('pg_reload_conf' in statement for _db, statement, _tx in psql.executed))
        self.assertEqual(live_calls[0][:2], ('exec', 'odoo18-db'))  # read from the live cluster, read only

    def test_the_emulator_refuses_the_old_single_transaction_shape(self):
        cluster = ha_odoo.Cluster(hafakes.FakeTmp(), 'odoo-db')
        with self.assertRaises(BackupError):
            cluster.script("ALTER SYSTEM SET work_mem TO '8192';\n")
        with self.assertRaises(BackupError):
            cluster.statement("ALTER SYSTEM SET work_mem TO '1'; ALTER SYSTEM SET x TO '2';")

    def test_a_setting_that_did_not_land_goes_back_to_the_default_and_is_listed(self):
        """OD-69: a setting the new cluster refuses is taken out again (ALTER SYSTEM RESET); the data is not touched and the
        customer is told which settings were not carried."""
        def answer(sql, _db):
            if 'pg_file_settings' in sql:     # (its WHERE says `sourcefile`: ask for it before the settings of the cluster)
                reset = any(s.startswith('ALTER SYSTEM RESET') for _d, s, _t in psql.executed)
                return [] if reset else [['work_mem', '8192', 'invalid value']]
            if 'source' in sql:
                return self.NEW
            return None

        psql = hafakes.Psql(answer)
        tmp = hafakes.FakeTmp(psql)
        live_calls = []

        class Runner:
            def podman(self, *args, **kwargs):
                live_calls.append(args)
                return hafakes.Result(0, json.dumps([['work_mem', '8192', 'configuration file', 'user']]).encode(), b'')

        sink = haissues.Sink('odoo')
        work = types.SimpleNamespace(runner=lambda _app: Runner(), log=lambda _text: None, sink=lambda _app: sink)
        live = types.SimpleNamespace(db_container='odoo18-db', db_user='postgres')
        carried = ha_odoo.carry_settings(work, types.SimpleNamespace(id='odoo'), live, ha_odoo.Cluster(tmp, 'odoo-db'))
        self.assertEqual(carried, [])
        self.assertIn('ALTER SYSTEM RESET work_mem', [s for _db, s, _tx in psql.executed])
        (note,) = sink.found
        self.assertEqual((note.id, note.level, list(note.names)), ('odoo.settings-not-carried', 'notice', ['work_mem']))

    def test_a_setting_that_still_has_an_error_after_the_reset_fails_the_job(self):
        psql = hafakes.Psql(lambda sql, _db: [['work_mem', '8192', 'invalid value']] if 'pg_file_settings' in sql
                            else self.NEW if 'source' in sql else None)
        tmp = hafakes.FakeTmp(psql)

        class Runner:
            def podman(self, *args, **kwargs):
                return hafakes.Result(0, json.dumps([['work_mem', '8192', 'configuration file', 'user']]).encode(), b'')

        work = types.SimpleNamespace(runner=lambda _app: Runner(), log=lambda _text: None)
        live = types.SimpleNamespace(db_container='odoo18-db', db_user='postgres')
        with self.assertRaises(BackupError) as caught:
            ha_odoo.carry_settings(work, None, live, ha_odoo.Cluster(tmp, 'odoo-db'))
        self.assertIn('work_mem', caught.exception.message)
        self.assertIn('ALTER SYSTEM RESET work_mem', [s for _db, s, _tx in psql.executed], 'it was tried first')

    def test_list_settings_are_split_like_postgresql_prints_them(self):
        self.assertEqual(ha_odoo.split_list_setting('"$user", public'), ['$user', 'public'])
        self.assertEqual(ha_odoo.split_list_setting('"a ""b"", c",d'), ['a "b", c', 'd'])
        self.assertEqual(ha_odoo.split_list_setting('public'), ['public'])
        for bad in ('', '"open', 'a,,b', '"a"b'):
            self.assertIsNone(ha_odoo.split_list_setting(bad), bad)
        self.assertIsNone(ha_odoo.alter_system_sql('search_path', '"open'))
        self.assertEqual(ha_odoo.alter_system_sql('work_mem', "8'MB"), "ALTER SYSTEM SET work_mem TO '8''MB';")


class PgdataTests(unittest.TestCase):
    def test_a_pgdata_folder_of_the_volume_is_where_the_cluster_lives(self):
        quadlets = dict(QUADLETS)
        quadlets['odoo-db.container'] += b'Environment=PGDATA=/var/lib/postgresql/data/pgdata\n'
        live = ha_odoo.Live(quadlets, '/home/appowner')
        self.assertEqual((live.pgdata, live.db_target), ('/var/lib/postgresql/data/pgdata', '/var/lib/postgresql/data'))
        self.assertEqual(ha_odoo.Live(QUADLETS, '/home/appowner').pgdata, '/var/lib/postgresql/data')
        quadlets['odoo-db.container'] = QUADLETS['odoo-db.container'] + b'Environment=PGDATA=/srv/pg\n'
        with self.assertRaises(BackupError):
            ha_odoo.Live(quadlets, '/home/appowner')


class DatabaseVerdictExtraTests(unittest.TestCase):
    def test_the_website_domains_are_a_reminder_and_the_converted_database_keeps_none(self):
        issues, _c, _u = ha_odoo.database_issues('woowtest', details_base(website_domains=['https://ha.example.com']),
                                                 target({'base': ('18.0.1.3', True, CORE)}), {}, ha_major=16, target_major=17)
        self.assertEqual([(i.id, i.level, list(i.names)) for i in issues],
                         [('odoo.website-domains', 'notice', ['https://ha.example.com'])])
        self.assertEqual(ha_odoo.PG16_IMAGES[0], 'docker.io/pgvector/pgvector:0.8.6-pg16')
        marker = 'm'
        live_values = {'base_url': 'https://cockpit.example', 'marker': marker}
        doc = {'modules': [['base', '18.0.1.3', 'installed']], 'partners': 1, 'attachments': 0, 'marker': marker,
               'attempt': 0, 'base_url': 'https://cockpit.example', 'uuid': 'u', 'website_domains': []}
        details = details_base(partners=1)
        args = dict(test_mode=False, old_uuid='u')
        self.assertEqual(ha_odoo.verify_converted(doc, details, target({'base': ('18.0.1.3', True, CORE)}), {}, live_values, **args), [])
        self.assertEqual(ha_odoo.converted_notes(doc, details, live_values), [])
        doc['website_domains'] = ['https://ha.example.com']
        self.assertEqual(ha_odoo.verify_converted(doc, details, target({'base': ('18.0.1.3', True, CORE)}), {}, live_values, **args),
                         [], 'OD-67: a reminder, no longer a stop')
        (issue_id, _text, names), = ha_odoo.converted_notes(doc, details, live_values)
        self.assertEqual((issue_id, names), ('odoo.website-domain-kept', ['https://ha.example.com']))
        self.assertIn('UPDATE website SET domain = NULL', ha_odoo.CLEAR_WEBSITE_DOMAINS_SQL)


def details_base(**extra):
    base = details([('base', '18.0.1.3', 'installed')])
    base.update(extra)
    return base


if __name__ == '__main__':
    unittest.main()
