"""Target-volume snapshot and candidate seeding (fixtures only). HAOS parity (lane EMQX-B, E-29, E-30, E-50): the snapshot takes
every data-volume file the settings name wherever it is (not only authz/, configs/ and certs/); what stays refused is what the
archive protections always refused (a link, a double, a too large file, an unsafe name) and the places that are not settings'
files (the database, what the converted volume leaves out anyway)."""
import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from woowbackup import ha_emqx
from woowbackup.errors import BackupError


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name)
        self.source = self.path / 'volume.tar'
        self.snapshot = self.path / 'private.tar'
        self.files = {
            'configs/cluster.hocon': b'authorization { sources = [{type = file, path = "authz/custom.acl"}] }\n',
            'authz/custom.acl': b'{allow, {user, "lab"}, publish, ["custom/#"]}.\n',
            'certs/lab.pem': b'fixture certificate\n',
        }
        self.required = set(self.files)

    def archive(self, entries):
        with tarfile.open(self.source, 'w') as tar:
            for name, data in entries:
                info = tarfile.TarInfo(name)
                if data is None:
                    info.type = tarfile.SYMTYPE
                    info.linkname = '/etc/passwd'
                    tar.addfile(info)
                else:
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))

    def test_custom_files_seed_candidate_unchanged_and_private(self):
        self.archive(list(self.files.items()) + [('unrelated', b'do not copy')])
        self.assertEqual(ha_emqx.target_config_snapshot(self.source, self.snapshot, self.required), self.required)
        self.assertEqual(os.stat(self.snapshot).st_mode & 0o777, 0o600)
        class Candidate:
            def volume_import(self, role, producer):
                self.role = role
                out = io.BytesIO()
                producer(out)
                self.data = out.getvalue()
        candidate = Candidate()
        ha_emqx.import_target_snapshot(candidate, self.snapshot, (1000, 1000))
        self.assertEqual(candidate.role, 'emqx-new')
        with tarfile.open(fileobj=io.BytesIO(candidate.data)) as tar:
            self.assertEqual({m.name for m in tar if m.isfile()}, self.required)
            self.assertEqual({m.name for m in tar if m.isdir()}, {'.', 'configs', 'authz', 'certs'})
            for member in tar:
                self.assertEqual((member.uid, member.gid), (1000, 1000))
                if member.isdir():
                    self.assertEqual(member.mode, 0o700)
            for name, data in self.files.items():
                self.assertEqual(tar.extractfile(name).read(), data)
                self.assertEqual(tar.getmember(name).mode, 0o600)

    def test_missing_required_reference_fails_and_leaves_no_snapshot(self):
        self.archive([('configs/cluster.hocon', self.files['configs/cluster.hocon'])])
        with self.assertRaises(BackupError):
            ha_emqx.target_config_snapshot(self.source, self.snapshot, self.required)
        self.assertFalse(self.snapshot.exists())

    def test_unsafe_reference_fails(self):
        self.archive(list(self.files.items()))
        with self.assertRaises(BackupError):
            ha_emqx.target_config_snapshot(self.source, self.snapshot, self.required | {'../outside'})
        self.assertFalse(self.snapshot.exists())

    def test_symlink_duplicate_and_size_limit_fail(self):
        for entries, limit in [
            ([('configs/cluster.hocon', b'x'), ('authz/custom.acl', None)], 100),
            ([('configs/cluster.hocon', b'x'), ('configs/cluster.hocon', b'y'), ('authz/custom.acl', b'z')], 100),
            ([('configs/cluster.hocon', b'x'), ('authz/custom.acl', b'yz')], 2),
        ]:
            with self.subTest(entries=entries, limit=limit):
                self.archive(entries)
                with self.assertRaises(BackupError):
                    ha_emqx.target_config_snapshot(self.source, self.snapshot,
                        {'configs/cluster.hocon', 'authz/custom.acl'}, limit=limit)
                self.assertFalse(self.snapshot.exists())

    def test_a_name_anywhere_in_the_data_volume_is_carried_with_its_folders(self):
        """E-29: the files of a setting in a folder the old list never allowed (authz/, configs/, certs/ only)."""
        extra = {'tls/clients/ca.pem': b'ca', 'custom/acl-2.conf': b'{allow, all}.\n', 'a/b/c/d/e.txt': b'deep'}
        self.archive(list(self.files.items()) + list(extra.items()) + [('unrelated', b'do not copy')])
        required = self.required | set(extra)
        self.assertEqual(ha_emqx.target_config_snapshot(self.source, self.snapshot, required), required)

        class Candidate:
            def volume_import(self, role, producer):
                out = io.BytesIO()
                producer(out)
                self.data = out.getvalue()
        candidate = Candidate()
        ha_emqx.import_target_snapshot(candidate, self.snapshot, (1000, 1000))
        with tarfile.open(fileobj=io.BytesIO(candidate.data)) as tar:
            self.assertEqual({m.name for m in tar if m.isfile()}, required)
            self.assertEqual({m.name for m in tar if m.isdir()},
                             {'.', 'configs', 'authz', 'certs', 'tls', 'tls/clients', 'custom', 'a', 'a/b', 'a/b/c', 'a/b/c/d'})
            for member in tar:
                self.assertEqual((member.uid, member.gid), (1000, 1000))
                self.assertEqual(member.mode, 0o700 if member.isdir() else 0o600)
            self.assertEqual(tar.extractfile('a/b/c/d/e.txt').read(), b'deep')

    def test_the_database_and_what_the_converted_volume_drops_are_no_files_to_carry(self):
        """E-29: only normalised names that are neither the Mnesia database nor generated configs, backups and traces."""
        for name in ('configs/cluster.hocon', 'authz/acl.conf', 'certs/a.pem', 'tls/clients/ca.pem', 'a', 'x/y.z'):
            self.assertTrue(ha_emqx.snapshot_name_ok(name), name)
        for name in ('mnesia/emqx@127.0.0.1/schema.DAT', 'mnesia', 'backup/x.tar.gz', 'trace/t.log', 'configs/app.1.config',
                     'configs/vm.1.args', 'configs/cluster.hocon.2026.bak', '../x', '/abs', 'a//b', 'a/./b', 'a/../b', '',
                     None, 5, b'x'):
            self.assertFalse(ha_emqx.snapshot_name_ok(name), name)
        for name in ('mnesia/emqx@127.0.0.1/schema.DAT', 'backup/x.tar.gz', 'configs/app.1.config'):
            self.archive(list(self.files.items()) + [(name, b'x')])
            with self.assertRaises(BackupError):
                ha_emqx.target_config_snapshot(self.source, self.snapshot, self.required | {name})
            self.assertFalse(self.snapshot.exists())

    def test_the_candidate_is_not_seeded_with_what_is_no_setting_file(self):
        """The same predicate guards the seed: a snapshot that holds the database or a link is refused."""
        for name in ('mnesia/x', 'backup/x.tar.gz', 'configs/vm.1.args'):
            with tarfile.open(self.snapshot, 'w') as tar:
                info = tarfile.TarInfo(name)
                info.size = 1
                tar.addfile(info, io.BytesIO(b'x'))

            class Candidate:
                def volume_import(self, role, producer):
                    producer(io.BytesIO())
            with self.subTest(name=name), self.assertRaises(BackupError):
                ha_emqx.import_target_snapshot(Candidate(), self.snapshot, (1000, 1000))


class ProvenAbsenceSnapshotTests(unittest.TestCase):
    setUp=SnapshotTests.setUp
    archive=SnapshotTests.archive

    def test_absent_override_does_not_invent_file_or_skip_other_dependencies(self):
        self.archive([(k,v) for k,v in self.files.items() if k!='configs/cluster.hocon'])
        found=ha_emqx.target_config_snapshot(self.source,self.snapshot,self.required,absent={'configs/cluster.hocon'})
        self.assertEqual(found,self.required-{'configs/cluster.hocon'})
        with tarfile.open(self.snapshot) as captured:
            self.assertNotIn('configs/cluster.hocon',captured.getnames())
            self.assertEqual(captured.extractfile('authz/custom.acl').read(),self.files['authz/custom.acl'])
        self.snapshot.unlink()
        self.archive([('certs/lab.pem',self.files['certs/lab.pem'])])
        with self.assertRaises(BackupError):
            ha_emqx.target_config_snapshot(self.source,self.snapshot,self.required,absent={'configs/cluster.hocon'})
        self.assertFalse(self.snapshot.exists())

    def test_declared_absent_override_appearing_or_symlink_parent_refuses(self):
        for entries in (list(self.files.items()),[('configs',None)]):
            with self.subTest(case=len(entries)):
                self.archive(entries)
                with self.assertRaises(BackupError):
                    ha_emqx.target_config_snapshot(self.source,self.snapshot,{'configs/cluster.hocon'},absent={'configs/cluster.hocon'})
                self.assertFalse(self.snapshot.exists())

    def test_other_paths_cannot_be_declared_absent(self):
        self.archive(list(self.files.items()))
        with self.assertRaises(BackupError):
            ha_emqx.target_config_snapshot(self.source,self.snapshot,self.required,absent={'authz/custom.acl'})
        self.assertFalse(self.snapshot.exists())
