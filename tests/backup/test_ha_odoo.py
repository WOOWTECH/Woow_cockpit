"""HA import, Odoo part (ha_odoo.py; CONTRACT section 9 "Home Assistant import"): module versions and the verdict, the
strict pass over the add-on tar (cluster, filestore, custom modules), the rewritten data dir and custom modules folder,
the restore list filter, settings and marker handling, and the live Quadlet parsing. Team E2."""
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from woowbackup import ha_odoo, habackup
from woowbackup.errors import BackupError

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


class VerdictTests(unittest.TestCase):
    def verdict(self, det, tgt, candidates=None, ha_major=16, target_major=17):
        return ha_odoo.database_verdict(det, tgt, candidates or {}, ha_major=ha_major, target_major=target_major)

    def candidate(self, version='18.0.1.0.0', python=(), binaries=(), installable=True):
        return {'from': 'data/addons', 'manifest': {'version': version, 'installable': installable,
                                                     'python': list(python), 'bin': list(binaries)}}

    def test_same_versions_move(self):
        ok, blockers, warnings, copy = self.verdict(details([('base', '18.0.1.3', 'installed')]),
                                                    target({'base': ('18.0.1.3', True, CORE)}))
        self.assertEqual((ok, blockers, copy), (True, [], {}))
        self.assertEqual(warnings, [])

    def test_missing_module_names_it_and_the_share_hint(self):
        ok, blockers, _w, _c = self.verdict(details([('base', '18.0.1.3', 'installed'),
                                                     ('x_custom', '18.0.1.0', 'installed')]),
                                            target({'base': ('18.0.1.3', True, CORE)}))
        self.assertFalse(ok)
        self.assertIn('x_custom', blockers[0])
        self.assertIn('/share/odoo_addons', blockers[0])

    def test_a_custom_module_of_the_backup_is_copied(self):
        ok, blockers, _w, copy = self.verdict(details([('woow_import_probe', '18.0.1.0.0', 'installed')]),
                                              target({}, python={'lxml': True}),
                                              {'woow_import_probe': self.candidate(python=['lxml'])})
        self.assertEqual((ok, blockers, list(copy)), (True, [], ['woow_import_probe']))

    def test_a_custom_copy_replaces_another_version_only_in_the_custom_folder(self):
        cand = {'probe': self.candidate('18.0.2.0')}
        ok, _b, _w, copy = self.verdict(details([('probe', '18.0.2.0', 'installed')]),
                                        target({'probe': ('18.0.1.0', True, EXTRA)}), cand)
        self.assertTrue(ok and 'probe' in copy)
        ok, blockers, _w, copy = self.verdict(details([('probe', '18.0.2.0', 'installed')]),
                                              target({'probe': ('18.0.1.0', True, '/opt/woow/addons')}), cand)
        self.assertFalse(ok)
        self.assertIn('probe（HA 18.0.2.0，這台 18.0.1.0）', blockers[0])
        self.assertEqual(copy, {})

    def test_other_blockers(self):
        cases = [
            (details([('base', '18.0.1.3', 'to upgrade')]), '尚未完成'),
            (details([('base', '18.0.1.3', 'installed')], extensions=['plpgsql', 'postgis']), 'postgis'),
        ]
        for det, text in cases:
            with self.subTest(text=text):
                ok, blockers, _w, _c = self.verdict(det, target({'base': ('18.0.1.3', True, CORE)}))
                self.assertFalse(ok)
                self.assertTrue(any(text in b for b in blockers), blockers)
        ok, blockers, _w, _c = self.verdict(details([]), target({}), ha_major=18, target_major=17)
        self.assertFalse(ok)
        self.assertIn('18 版', blockers[0])
        ok, blockers, _w, _c = self.verdict(details([('m', '18.0.1.0', 'installed')]), target({}, python={}),
                                            {'m': self.candidate('18.0.1.0', python=['zeep'], binaries=['wkhtmltopdf'])})
        self.assertFalse(ok)
        self.assertIn('Python 套件 zeep（模組 m）', blockers[0])
        self.assertIn('程式 wkhtmltopdf（模組 m）', blockers[0])

    def test_warnings_for_mail_and_crons(self):
        _ok, _b, warnings, _c = self.verdict(details([], mail_servers_active=1, crons_active=3), target({}))
        self.assertEqual(len(warnings), 2)


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
        broken = dict(QUADLETS)
        broken['odoo.container'] = broken['odoo.container'].replace(b'%h/.local', b'/etc/../root')
        with self.assertRaises(BackupError):
            ha_odoo.Live(broken, '/home/appowner')


if __name__ == '__main__':
    unittest.main()
