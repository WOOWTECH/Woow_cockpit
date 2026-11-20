"""Restricted target-volume snapshot and candidate seeding (fixtures only)."""
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
        ha_emqx.import_target_snapshot(candidate, self.snapshot)
        self.assertEqual(candidate.role, 'emqx-new')
        with tarfile.open(fileobj=io.BytesIO(candidate.data)) as tar:
            self.assertEqual(set(tar.getnames()), self.required)
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
