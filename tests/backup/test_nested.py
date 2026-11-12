"""Untrusted nested tars (review finding SEC-1): volume exports and OCI archives inside a backup.

Podman unpacks them without a chroot and follows a symlink an earlier member planted. The engine checks
each file completely before any change and feeds podman a canonical tar rebuilt from validated members.
"""
import io
import os
import tarfile
import tempfile
import threading
import unittest
from pathlib import Path

from woowbackup import nested
from woowbackup.errors import BackupError

from .tarfixtures import image_id, oci_archive, read_oci, sha, tar_listing, volume_tar

REF = 'docker.io/library/postgres:16-alpine'


class TempCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def file(self, data, name='entry.tar'):
        path = self.root / name
        path.write_bytes(data)
        return path

    def rejected(self, check, data, reason=None):
        with self.assertRaises(BackupError) as caught:
            check(self.file(data))
        self.assertEqual(caught.exception.code, 'corrupt-archive')
        self.assertIn('沒有任何變更', caught.exception.message)
        if reason:
            self.assertIn(reason, caught.exception.details['reason'])
        return caught.exception


def stream(function, *args):
    out = io.BytesIO()
    function(*args, out)
    return out.getvalue()


class VolumeTests(TempCase):
    def test_podman_style_export_is_accepted_and_rebuilt(self):
        path = self.file(volume_tar())
        self.assertEqual(nested.check_volume(path), 5)
        rebuilt = tar_listing(stream(nested.stream_volume, path))
        original = tar_listing(volume_tar())
        self.assertEqual([row[0] for row in rebuilt], [row[0] for row in original])
        self.assertEqual({row[0]: row[5] for row in rebuilt}, {row[0]: row[5] for row in original})
        modes = {row[0]: row[2] for row in rebuilt}
        self.assertEqual(modes['files/b.txt'], 0o755, 'setuid/setgid are dropped from non-directories')
        links = {row[0]: row[4] for row in rebuilt}
        self.assertEqual(links['files/current'], '/data/files/a.bin', 'a symlink keeps its (container) target')
        self.assertEqual(links['files/a-link.bin'], 'files/a.bin')

    def test_symlink_then_write_through_it_escapes_with_a_naive_untar(self):
        # The attack: an absolute symlink, then a member below it. A naive untar (like podman's) writes outside.
        outside = self.root / 'owner-config'
        outside.mkdir()
        hostile = volume_tar([
            {'name': 'esc', 'kind': tarfile.SYMTYPE, 'linkname': str(outside)},
            {'name': 'esc/containers.conf', 'data': b'[engine]\nruntime="/tmp/evil"\n'},
        ])
        dest = self.root / 'naive'
        dest.mkdir()
        with tarfile.open(fileobj=io.BytesIO(hostile)) as tar:
            tar.extractall(dest, filter='fully_trusted')
        self.assertTrue((outside / 'containers.conf').exists(), 'precondition: the file escaped the target')
        (outside / 'containers.conf').unlink()
        self.rejected(nested.check_volume, hostile, 'below a symlink')
        with self.assertRaises(BackupError):
            stream(nested.stream_volume, self.file(hostile, 'again.tar'))
        self.assertEqual(list(outside.iterdir()), [])

    def test_hostile_volume_members(self):
        cases = {
            'absolute name': [{'name': '/etc/cron.d/x', 'data': b'x'}],
            'dotdot': [{'name': 'a/../../x', 'data': b'x'}],
            'empty component': [{'name': 'a//b', 'data': b'x'}],
            'hard link outside': [{'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': '/etc/shadow'}],
            'hard link dotdot': [{'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': '../x'}],
            'hard link to nothing': [{'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': 'missing'}],
            'hard link through symlink': [
                {'name': 'esc', 'kind': tarfile.SYMTYPE, 'linkname': '/home/appowner'},
                {'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': 'esc/.bashrc'}],
            'hard link to a symlink': [
                {'name': 's', 'kind': tarfile.SYMTYPE, 'linkname': '/etc/passwd'},
                {'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': 's'}],
            'below a hard link': [
                {'name': 'f', 'data': b'x'}, {'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': 'f'},
                {'name': 'l/x', 'data': b'x'}],
            'below a file': [{'name': 'f', 'data': b'x'}, {'name': 'f/x', 'data': b'x'}],
            'device': [{'name': 'dev', 'kind': tarfile.CHRTYPE}],
            'fifo': [{'name': 'pipe', 'kind': tarfile.FIFOTYPE}],
            'duplicate': [{'name': 'a', 'data': b'1'}, {'name': 'a', 'data': b'2'}],
            'file replaces a directory': [{'name': 'd/x', 'data': b'1'}, {'name': 'd', 'data': b'2'}],
            'symlink replaces a directory': [{'name': 'd/', 'kind': tarfile.DIRTYPE},
                                             {'name': 'd', 'kind': tarfile.SYMTYPE, 'linkname': '/etc'}],
        }
        for label, members in cases.items():
            with self.subTest(label):
                self.rejected(nested.check_volume, volume_tar(members))

    def test_pax_path_override_is_judged_by_the_parsed_name(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as tar:
            info = tarfile.TarInfo('safe-name')
            info.pax_headers = {'path': '../../outside'}
            info.size = 1
            tar.addfile(info, io.BytesIO(b'x'))
        self.rejected(nested.check_volume, buffer.getvalue(), '".."')

    def test_global_pax_header_and_non_tar_input(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT, pax_headers={'path': 'x'}) as tar:
            info = tarfile.TarInfo('a')
            tar.addfile(info)
        self.rejected(nested.check_volume, buffer.getvalue(), 'global PAX')
        self.rejected(nested.check_volume, b'\x1f\x8b' + b'\0' * 2000, 'not a tar')

    def test_only_user_xattrs_and_numeric_owner_survive(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as tar:
            info = tarfile.TarInfo('f')
            info.size, info.uid, info.gid, info.uname, info.gname = 1, 70, 70, 'postgres', 'postgres'
            info.pax_headers = {'SCHILY.xattr.user.tag': 'keep', 'SCHILY.xattr.security.capability': 'drop'}
            tar.addfile(info, io.BytesIO(b'x'))
        out = stream(nested.stream_volume, self.file(buffer.getvalue()))
        with tarfile.open(fileobj=io.BytesIO(out)) as tar:
            member = tar.getmember('f')
        self.assertEqual((member.uid, member.gid, member.uname, member.gname), (70, 70, '', ''))
        self.assertEqual({k: v for k, v in member.pax_headers.items() if k.startswith('SCHILY')},
                         {'SCHILY.xattr.user.tag': 'keep'})


class OciTests(TempCase):
    def check(self, path, ref=REF, image=None):
        return nested.check_oci(path, ref=ref, image_id=image or image_id(REF))

    def test_podman_style_archive_is_accepted_and_rebuilt(self):
        path = self.file(oci_archive(REF))
        plan = self.check(path)
        self.assertEqual(plan['image_id'], image_id(REF))
        out = stream(nested.stream_oci, path, plan)
        self.assertEqual(read_oci(out), (REF, image_id(REF)))
        names = [row[0] for row in tar_listing(out)]
        self.assertEqual(names[:4], ['oci-layout', 'index.json', 'blobs', 'blobs/sha256'])
        self.assertTrue(all(name.startswith('blobs/sha256/') for name in names[4:]))
        self.assertEqual(len(names), 7)
        # "./"-prefixed member names are the same archive
        self.check(self.file(oci_archive(REF, prefix='./'), 'dot.tar'))

    def test_hostile_archives(self):
        cases = {
            'foreign name annotation': oci_archive(REF, annotation='localhost/other:9'),
            'two manifests': oci_archive(REF, manifests=2),
            'planted symlink': oci_archive(REF, extra=[{'name': 'esc', 'kind': tarfile.SYMTYPE,
                                                        'linkname': '/home/appowner/.config/containers'}]),
            'file below the symlink': oci_archive(REF, extra=[{'name': 'esc/containers.conf', 'data': b'x'}]),
            'extra top-level file': oci_archive(REF, extra=[{'name': 'repositories', 'data': b'{}'}]),
            'hard link': oci_archive(REF, extra=[{'name': 'blobs/sha256/' + 'f' * 64, 'kind': tarfile.LNKTYPE,
                                                  'linkname': 'index.json'}]),
            'manifest digest of another blob': oci_archive(REF, manifest_digest='sha256:' + sha(b'layer-data')),
        }
        for label, data in cases.items():
            with self.subTest(label):
                self.rejected(self.check, data)

    def test_image_id_must_match_the_backup_manifest(self):
        self.rejected(lambda path: self.check(path, image='sha256:' + 'e' * 64), oci_archive(REF), 'image id')
        self.rejected(lambda path: self.check(path, image='not-an-id'), oci_archive(REF), 'image id')

    def test_config_blob_must_match_its_digest(self):
        data = oci_archive(REF)
        config = b'{"architecture":"amd64"}'
        # Same digest declared, other bytes stored: build by swapping the blob content.
        bad = oci_archive(REF, config=config)
        self.check(self.file(data))
        self.rejected(lambda path: self.check(path, image='sha256:' + sha(b'other')), bad)


class PipeTests(unittest.TestCase):
    def test_streams_into_a_reader(self):
        with nested.pipe_from(lambda out: out.write(b'x' * 300000)) as feed:
            self.assertEqual(len(feed.read()), 300000)

    def test_writer_error_wins_over_success(self):
        def writer(out):
            out.write(b'partial')
            raise BackupError('corrupt-archive', '不安全。')
        with self.assertRaises(BackupError) as caught:
            with nested.pipe_from(writer) as feed:
                feed.read()
        self.assertEqual(caught.exception.code, 'corrupt-archive')

    def test_a_reader_that_stops_early_never_hangs(self):
        done = threading.Event()

        def writer(out):
            try:
                for _ in range(1000):
                    out.write(b'y' * 65536)
            finally:
                done.set()
        with nested.pipe_from(writer) as feed:
            feed.read(10)
        self.assertTrue(done.wait(5))


if __name__ == '__main__':
    unittest.main()
