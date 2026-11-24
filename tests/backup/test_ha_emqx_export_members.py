"""Unit tests for the pre-import EMQX export-member check (B1-03 hardening, fix/emqx-export-members-20261124).

check_export_members refuses a tampered EMQX `data export` before `emqx ctl data import` runs in the candidate: only
<name>/META.hocon, <name>/cluster.hocon and <name>/mnesia/<table in TABLES> are allowed, and cluster.hocon may hold
only DATA_ROOTS. No podman: synthetic .tar.gz fixtures shaped like emqx_mgmt_data_backup's output.
"""
import gzip
import io
import os
import tarfile
import tempfile
import unittest

from woowbackup import ha_emqx
from woowbackup.errors import BackupError

NAME = 'emqx-export-2026-11-24-00-00-00.000'
HEALTHY_HOCON = (
    'authentication = [\n  {\n    backend = built_in_database\n    mechanism = password_based\n'
    '    password_hash_algorithm {name = sha256, salt_position = suffix}\n  }\n]\n'
    'authorization {\n  no_match = deny\n  sources = [{enable = true, path = "/opt/emqx/etc/acl.conf", type = file}]\n}\n'
    'retainer {enable = true}\n'
    'rule_engine {\n  rules {\n    "rule_0" {\n      sql = """~\n        SELECT * FROM "t/#" WHERE a = "x {y} = z [w]"\n      ~"""\n    }\n  }\n}\n'
)


def build_export(members, *, compress=True):
    """members: {rel_path: bytes | ('dir',) | ('link', target) }, under <NAME>/. Returns a .tar.gz path."""
    buf = io.BytesIO()
    mode = 'w:gz' if compress else 'w'
    with tarfile.open(fileobj=buf, mode=mode, format=tarfile.PAX_FORMAT) as tar:
        top = tarfile.TarInfo(NAME); top.type = tarfile.DIRTYPE; top.mode = 0o755
        tar.addfile(top)
        for rel, value in members.items():
            info = tarfile.TarInfo(f'{NAME}/{rel}')
            if value == ('dir',):
                info.type = tarfile.DIRTYPE; info.mode = 0o755; tar.addfile(info)
            elif isinstance(value, tuple) and value[0] == 'link':
                info.type = tarfile.SYMTYPE; info.linkname = value[1]; tar.addfile(info)
            else:
                info.size = len(value); info.mode = 0o644; tar.addfile(info, io.BytesIO(value))
    fd, path = tempfile.mkstemp(suffix='.tar.gz'); os.write(fd, buf.getvalue()); os.close(fd)
    return path


def healthy_members(hocon=HEALTHY_HOCON):
    return {'META.hocon': b'{version = "5.8.9", edition = ce}\n', 'cluster.hocon': hocon.encode(),
            'mnesia': ('dir',), 'mnesia/emqx_authn_mnesia': b'x', 'mnesia/emqx_acl': b'y',
            'mnesia/emqx_admin': b'z', 'mnesia/emqx_app': b'w'}


class ExportMembersTests(unittest.TestCase):
    def tearDown(self):
        for p in getattr(self, '_paths', []):
            try: os.unlink(p)
            except OSError: pass

    def check(self, members):
        p = build_export(members)
        self._paths = getattr(self, '_paths', []) + [p]
        return ha_emqx.check_export_members(p)

    def test_healthy_export_passes(self):
        self.assertIsNone(self.check(healthy_members()))

    def test_export_without_cluster_hocon_passes(self):
        m = healthy_members(); del m['cluster.hocon']
        self.assertIsNone(self.check(m))

    def test_empty_cluster_hocon_passes(self):
        self.assertIsNone(self.check(healthy_members('\n# nothing to migrate\n')))

    def test_extra_non_data_root_is_refused(self):
        with self.assertRaises(BackupError) as cm:
            self.check(healthy_members(HEALTHY_HOCON + 'listeners {tcp {default {bind = "0.0.0.0:1883"}}}\n'))
        self.assertIn('listeners', cm.exception.message)
        self.assertIn('設定根', cm.exception.message)

    def test_dashboard_and_node_roots_are_refused(self):
        with self.assertRaises(BackupError) as cm:
            self.check(healthy_members(HEALTHY_HOCON + 'dashboard {}\nnode {name = "emqx@x"}\n'))
        self.assertTrue('dashboard' in cm.exception.message and 'node' in cm.exception.message)

    def test_dotted_cluster_root_is_refused(self):
        with self.assertRaises(BackupError) as cm:
            self.check(healthy_members(HEALTHY_HOCON + 'cluster.links = []\n'))
        self.assertIn('cluster', cm.exception.message)

    def test_wrapped_cluster_hocon_is_refused(self):
        with self.assertRaises(BackupError):
            self.check(healthy_members('{\n' + HEALTHY_HOCON + '}\n'))

    def test_unexpected_mnesia_table_is_refused(self):
        m = healthy_members(); m['mnesia/emqx_not_a_table'] = b'bad'
        with self.assertRaises(BackupError) as cm:
            self.check(m)
        self.assertIn('資料表', cm.exception.message)

    def test_unexpected_top_level_member_is_refused(self):
        m = healthy_members(); m['evil.sh'] = b'#!/bin/sh\n'
        with self.assertRaises(BackupError) as cm:
            self.check(m)
        self.assertIn('非預期的項目', cm.exception.message)

    def test_symlink_member_is_refused(self):
        m = healthy_members(); m['mnesia/emqx_acl'] = ('link', '/etc/passwd')
        with self.assertRaises(BackupError) as cm:
            self.check(m)
        self.assertIn('非一般檔案', cm.exception.message)   # a non-regular member, not the generic catch-all

    def test_second_top_directory_is_refused(self):
        p = build_export(healthy_members())
        # append a second top-dir member by rebuilding with an extra out-of-tree name
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz', format=tarfile.PAX_FORMAT) as tar:
            with tarfile.open(p, 'r:gz') as src:
                for m in src:
                    tar.addfile(m, src.extractfile(m) if m.isfile() else None)
            evil = tarfile.TarInfo('other-top/x'); evil.size = 1; tar.addfile(evil, io.BytesIO(b'x'))
        os.unlink(p)
        fd, p2 = tempfile.mkstemp(suffix='.tar.gz'); os.write(fd, buf.getvalue()); os.close(fd)
        self._paths = getattr(self, '_paths', []) + [p2]
        with self.assertRaises(BackupError):
            ha_emqx.check_export_members(p2)

    def test_all_TABLES_are_allowed_as_mnesia_members(self):
        m = {'META.hocon': b'{}', 'mnesia': ('dir',)}
        for t in ha_emqx.TABLES:
            m[f'mnesia/{t}'] = b'x'
        self.assertIsNone(self.check(m))


class RootScanTests(unittest.TestCase):
    def test_triple_quoted_value_with_braces_is_not_a_root(self):
        text = 'rule_engine {\n  rules {\n    r {\n      sql = """~\n        a {b} = c [d] listeners {x}\n      ~"""\n    }\n  }\n}\n'
        self.assertEqual(ha_emqx.export_cluster_roots(text), {'rule_engine'})

    def test_scalar_values_are_not_roots(self):
        self.assertEqual(ha_emqx.export_cluster_roots('retainer = true\nrewrite = []\n'), {'retainer', 'rewrite'})

    def test_unbalanced_raises(self):
        with self.assertRaises(BackupError):
            ha_emqx.export_cluster_roots('rule_engine {\n')


if __name__ == '__main__':
    unittest.main()


class WiringTests(unittest.TestCase):
    def test_target_broker_checks_the_export_before_import(self):
        import inspect
        src = inspect.getsource(ha_emqx.target_broker)
        self.assertIn('check_export_members(export)', src)
        # it must run before the export is placed into the candidate's input volume / imported
        self.assertLess(src.index('check_export_members(export)'), src.index("tmp.volume_import('emqx-in'"))
