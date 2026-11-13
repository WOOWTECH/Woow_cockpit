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
        report = nested.check_volume(path)
        self.assertEqual(report.members, 5)
        self.assertEqual((report.special_modes, report.special_mode_samples), (1, ['files/b.txt']))
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
            'hard link to a directory': [
                {'name': 'd/', 'kind': tarfile.DIRTYPE}, {'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': 'd'}],
            'below a hard link': [
                {'name': 'f', 'data': b'x'}, {'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': 'f'},
                {'name': 'l/x', 'data': b'x'}],
            'below a file': [{'name': 'f', 'data': b'x'}, {'name': 'f/x', 'data': b'x'}],
            'device': [{'name': 'dev', 'kind': tarfile.CHRTYPE}],
            'block device': [{'name': 'disk', 'kind': tarfile.BLKTYPE}],
            'below a fifo': [{'name': 'pipe', 'kind': tarfile.FIFOTYPE}, {'name': 'pipe/x', 'data': b'x'}],
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


LAB_MAP = '         0       1001          1\n         1      10000      55000\n'  # appowner:10000:55000 (lab devices)


def lab_ids():
    return nested.IdMap(LAB_MAP), nested.IdMap(LAB_MAP)


class DeltaReviewVolumeTests(TempCase):
    """Delta review findings HD-02, HD-03 and HD-09 (volume tars); each case was a podman 4.9.3 lab run."""

    def test_hd02_a_symlink_leaving_the_volume_is_refused_like_podman_refuses_it(self):
        # `podman volume import` aborts on `dir/rel-escape-link -> ../../etc/passwd` after `volume rm` + `create`,
        # with only the members before it written; the check now refuses it before any change.
        for label, target in {'relative': '../../etc/passwd', 'absolute with ..': '/../../etc'}.items():
            with self.subTest(label):
                data = volume_tar([{'name': 'dir/', 'kind': tarfile.DIRTYPE},
                                   {'name': 'dir/rel-escape-link', 'kind': tarfile.SYMTYPE, 'linkname': target},
                                   {'name': 'z/after.txt', 'data': b'z'}])
                error = self.rejected(nested.check_volume, data, 'symlink pointing outside the volume')
                self.assertIn('指向資料卷外的符號連結', error.message)
                with self.assertRaises(BackupError):
                    stream(nested.stream_volume, self.file(data, 'again.tar'))
        # What podman imports stays accepted: absolute targets, relative ones that stay inside, the volume root.
        fine = volume_tar([{'name': 'dir/', 'kind': tarfile.DIRTYPE},
                           {'name': 'dir/abs-link', 'kind': tarfile.SYMTYPE, 'linkname': '/etc/passwd'},
                           {'name': 'dir/rel-inside-link', 'kind': tarfile.SYMTYPE, 'linkname': '../z/after.txt'},
                           {'name': 'dir/root-link', 'kind': tarfile.SYMTYPE, 'linkname': '..'},
                           {'name': 'top-link', 'kind': tarfile.SYMTYPE, 'linkname': 'dir/../z'},
                           {'name': 'z/after.txt', 'data': b'z'}])
        self.assertEqual(nested.check_volume(self.file(fine, 'fine.tar')).members, 6)

    def test_hd02_member_owners_must_fit_the_owners_user_namespace(self):
        ids = lab_ids()
        self.assertEqual([70000 in ids[0], 55000 in ids[0], 0 in ids[0], 65534 in ids[0]], [False, True, True, False])
        self.assertEqual(ids[0].describe(), '0–0、1–55000')
        data = volume_tar([{'name': 'ok.txt', 'data': b'a', 'uid': 70, 'gid': 70},
                           {'name': 'big-uid.txt', 'data': b'b', 'uid': 70000, 'gid': 70000},
                           {'name': 'z.txt', 'data': b'z'}])
        path = self.file(data)
        self.assertEqual(nested.check_volume(path).members, 3, 'no map given: not checked')
        for check in (lambda: nested.check_volume(path, ids=ids),
                      lambda: stream(lambda p, out: nested.stream_volume(p, out, ids), path)):
            with self.assertRaises(BackupError) as caught:
                check()
            self.assertEqual(caught.exception.code, 'incompatible')
            self.assertEqual((caught.exception.details['member'], caught.exception.details['uid']), ('big-uid.txt', 70000))
            self.assertIn('沒有任何變更', caught.exception.message)
        gid_only = volume_tar([{'name': 'g.txt', 'data': b'g', 'uid': 0, 'gid': 65534}])  # the overflow gid
        with self.assertRaises(BackupError):
            nested.check_volume(self.file(gid_only, 'gid.tar'), ids=ids)

    def test_hd03_fifos_and_second_names_of_symlinks_and_fifos_are_kept(self):
        # What `podman volume export` wrote for `mkfifo public/pickup` and `ln -P data/sym data/sym-hardlink`.
        data = volume_tar([
            {'name': 'public/', 'kind': tarfile.DIRTYPE, 'mode': 0o710},
            {'name': 'public/pickup', 'kind': tarfile.FIFOTYPE, 'mode': 0o622, 'uid': 90, 'gid': 90},
            {'name': 'public/pickup-2', 'kind': tarfile.LNKTYPE, 'linkname': 'public/pickup'},
            {'name': 'data/', 'kind': tarfile.DIRTYPE},
            {'name': 'data/sym', 'kind': tarfile.SYMTYPE, 'linkname': '/etc/hostname'},
            {'name': 'data/sym-hardlink', 'kind': tarfile.LNKTYPE, 'linkname': 'data/sym'},
            {'name': 'data/f', 'data': b'f'},
            {'name': 'data/f-2', 'kind': tarfile.LNKTYPE, 'linkname': 'data/f'},
            {'name': 'data/f-3', 'kind': tarfile.LNKTYPE, 'linkname': 'data/f-2'},
        ])
        path = self.file(data)
        self.assertEqual(nested.check_volume(path, ids=lab_ids()).members, 9)
        rebuilt = {row[0]: row for row in tar_listing(stream(lambda p, out: nested.stream_volume(p, out, lab_ids()), path))}
        self.assertEqual(rebuilt['public/pickup'][1:3], (tarfile.FIFOTYPE, 0o622), 'a FIFO is re-emitted as a FIFO')
        self.assertEqual(rebuilt['public/pickup'][3], 0)
        self.assertEqual(rebuilt['data/sym-hardlink'][1], tarfile.LNKTYPE)
        self.assertEqual(rebuilt['data/sym-hardlink'][4], 'data/sym')
        self.assertEqual((rebuilt['data/f-3'][1], rebuilt['data/f-3'][4]), (tarfile.LNKTYPE, 'data/f-2'))
        # Still refused: a member below a FIFO, a hard link to a directory or to something not yet seen.
        for members in ([{'name': 'p', 'kind': tarfile.FIFOTYPE}, {'name': 'p/x', 'data': b'x'}],
                        [{'name': 'd/', 'kind': tarfile.DIRTYPE}, {'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': 'd'}],
                        [{'name': 'l', 'kind': tarfile.LNKTYPE, 'linkname': 'later'}, {'name': 'later', 'data': b'x'}]):
            self.rejected(nested.check_volume, volume_tar(members))

    def test_hd03_member_cap_and_bounded_memory(self):
        import tracemalloc
        members = [{'name': f'previews/{i // 100:05d}/p{i:07d}-preview-256x256.jpg', 'data': b''} for i in range(4)]
        path = self.file(volume_tar(members))
        original = nested.MAX_VOLUME_MEMBERS
        nested.MAX_VOLUME_MEMBERS = 3
        try:
            error = self.rejected(nested.check_volume, volume_tar(members), 'too many members')
            self.assertIn('上限', error.message)
        finally:
            nested.MAX_VOLUME_MEMBERS = original
        self.assertEqual(nested.check_volume(path).members, 4)
        # Names are remembered as fixed-size digests: the cost per member no longer grows with the name (a str per
        # member cost 167 bytes for these 93-character names, the digest 89; finding HD-03 measured ~215 B/member).
        count = 30000
        infos = []
        for i in range(count):
            info = tarfile.TarInfo(f'appdata_ocb2c3d4e5f6/preview/{i // 100:05d}/{i:07d}-4096-4096-max-and-crop-preview-'
                                   'file-of-a-photo.jpg')
            info.size = 0
            infos.append(info)
        policy = nested._VolumePolicy()
        tracemalloc.start()
        try:
            before = tracemalloc.get_traced_memory()[0]
            for info in infos:
                policy.admit(info)
            retained = tracemalloc.get_traced_memory()[0] - before
        finally:
            tracemalloc.stop()
        self.assertLess(retained / count, 120, f'{retained / count:.0f} bytes per member')

    def test_hd09_dropped_setuid_bits_and_capabilities_are_reported(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as tar:
            for name, mode, pax in (('bin/suid', 0o4755, {}), ('bin/sgid', 0o2755, {}),
                                    ('bin/capfile', 0o755, {'SCHILY.xattr.security.capability': '\x01\x00\x00\x02'}),
                                    ('etc/tagged', 0o644, {'SCHILY.xattr.user.tag': 'keep'}), ('dir', 0o2775, None)):
                info = tarfile.TarInfo(name)
                info.mode = mode
                if pax is None:
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
                    continue
                info.size, info.pax_headers = 1, pax
                tar.addfile(info, io.BytesIO(b'x'))
        path = self.file(buffer.getvalue())
        report = nested.check_volume(path)
        self.assertEqual((report.special_modes, report.special_mode_samples), (2, ['bin/suid', 'bin/sgid']))
        self.assertEqual((report.dropped_xattrs, report.dropped_xattr_names, report.dropped_xattr_samples),
                         (1, ['security.capability'], ['bin/capfile']))
        notes = report.warnings('woowbk-demo-files')
        self.assertEqual(len(notes), 2)
        self.assertIn('setuid／setgid', notes[0])
        self.assertIn('bin/suid', notes[0])
        self.assertIn('security.capability', notes[1])
        rebuilt = {row[0]: row[2] for row in tar_listing(stream(nested.stream_volume, path))}
        self.assertEqual((rebuilt['bin/suid'], rebuilt['bin/sgid'], rebuilt['dir']), (0o755, 0o755, 0o2775),
                         'the canonical copy still drops them (CONTRACT section 5); only the silence was the defect')
        self.assertEqual(nested.check_volume(self.file(volume_tar([{'name': 'a', 'data': b'a'}]), 'plain.tar'))
                         .warnings('v'), [])


def gnu_dir_tar(members):
    """A host directory tar as GNU tar writes it inside the owner's namespace: `./` root entry with the directory's
    own owner and mode, `./`-prefixed names, namespace owners, nanosecond PAX mtimes (checked in the lab)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for item in members:
            item = dict(item)
            data = item.pop('data', b'')
            info = tarfile.TarInfo(item.pop('name'))
            info.type = item.pop('type', tarfile.REGTYPE)
            info.size = len(data) if info.type == tarfile.REGTYPE else 0
            info.pax_headers = item.pop('pax', {})
            for key, value in item.items():
                setattr(info, key, value)
            tar.addfile(info, io.BytesIO(data) if info.size else None)
    return buffer.getvalue()


DIR_MEMBERS = [
    {'name': '.', 'type': tarfile.DIRTYPE, 'mode': 0o750, 'uid': 33, 'gid': 33, 'pax': {'mtime': '1700000000.123456789'}},
    {'name': './pg', 'type': tarfile.DIRTYPE, 'mode': 0o700, 'uid': 70, 'gid': 70},
    {'name': './pg/PG_VERSION', 'data': b'16\n', 'mode': 0o600, 'uid': 70, 'gid': 70},
    {'name': './www', 'type': tarfile.DIRTYPE, 'mode': 0o2775, 'uid': 33, 'gid': 33},
    {'name': './www/config.php', 'data': b'<?php\n', 'mode': 0o640, 'uid': 33, 'gid': 33},
    {'name': './www/second-name.php', 'type': tarfile.LNKTYPE, 'linkname': './www/config.php', 'uid': 33, 'gid': 33},
    {'name': './www/abs-link', 'type': tarfile.SYMTYPE, 'linkname': '/etc/hostname', 'mode': 0o777},
    {'name': './secrets.yaml', 'type': tarfile.SYMTYPE, 'linkname': '../secrets.yaml', 'mode': 0o777},
    {'name': './fifo', 'type': tarfile.FIFOTYPE, 'mode': 0o640},
    {'name': './tool', 'data': b'#!/bin/sh\n', 'mode': 0o4755},
    {'name': './x', 'data': b'x', 'mode': 0o644, 'uid': 54999, 'gid': 54998,
     'pax': {'SCHILY.xattr.user.tag': 'v', 'SCHILY.xattr.security.capability': 'c'}},
]
LAB_IDS = (nested.IdMap('0 1001 1\n1 10000 55000\n'), nested.IdMap('0 1001 1\n1 10000 55000\n'))


class HostDirectoryTests(TempCase):
    """Host directory tars: the volume rules, a root entry, symlinks that may point outside (kept, never followed)."""

    def test_gnu_tar_layout_is_accepted_and_reported(self):
        path = self.file(gnu_dir_tar(DIR_MEMBERS))
        report = nested.check_dir(path, LAB_IDS)
        self.assertEqual(report.members, len(DIR_MEMBERS))
        self.assertEqual((report.max_uid, report.max_gid), (54999, 54998))
        self.assertEqual((report.outside_links, report.outside_link_samples), (2, ['www/abs-link', 'secrets.yaml']))
        notes = report.warnings('~/homeassistant/config')
        self.assertEqual(len(notes), 2)
        self.assertTrue(notes[0].startswith('主機資料夾 ~/homeassistant/config 有 1 個檔案的 setuid'), notes)
        self.assertIn('security.capability', notes[1])
        self.assertIn('2 個符號連結指向資料夾以外', report.link_note('~/homeassistant/config'))
        with self.assertRaises(BackupError) as caught:  # a volume would refuse the same links (podman's import rule)
            nested.check_volume(path, LAB_IDS)
        self.assertEqual(caught.exception.details['reason'], 'symlink pointing outside the volume')

    def test_canonical_copy_keeps_owners_modes_links_and_exact_mtimes(self):
        path = self.file(gnu_dir_tar(DIR_MEMBERS))
        out = stream(lambda source, target: nested.stream_dir(source, target, LAB_IDS), path)
        with tarfile.open(fileobj=io.BytesIO(out), mode='r:') as tar:
            members = {m.name: m for m in tar.getmembers()}
        self.assertEqual(list(members), ['.', 'pg', 'pg/PG_VERSION', 'www', 'www/config.php', 'www/second-name.php',
                                         'www/abs-link', 'secrets.yaml', 'fifo', 'tool', 'x'])
        root = members['.']
        self.assertEqual((root.type, root.mode, root.uid, root.gid), (tarfile.DIRTYPE, 0o750, 33, 33))
        self.assertEqual(root.pax_headers.get('mtime'), '1700000000.123456789', 'nanoseconds kept verbatim')
        self.assertEqual(members['www'].mode, 0o2775, 'setgid directories keep their mode')
        self.assertEqual(members['tool'].mode, 0o755, 'setuid dropped from a file')
        self.assertEqual(members['www/second-name.php'].linkname, 'www/config.php')
        self.assertEqual(members['secrets.yaml'].linkname, '../secrets.yaml', 'kept verbatim, never followed')
        self.assertEqual((members['x'].uid, members['x'].gid), (54999, 54998))
        self.assertEqual({k for k in members['x'].pax_headers if k.startswith('SCHILY')}, {'SCHILY.xattr.user.tag'})
        self.assertTrue(all(not m.uname and not m.gname for m in members.values()))

    def test_owner_outside_the_target_namespace_is_incompatible(self):
        small = (nested.IdMap('0 1007 1\n1 10500 1000\n'), nested.IdMap('0 1007 1\n1 10500 1000\n'))
        with self.assertRaises(BackupError) as caught:
            nested.check_dir(self.file(gnu_dir_tar(DIR_MEMBERS)), small)
        error = caught.exception
        self.assertEqual(error.code, 'incompatible')
        self.assertTrue(error.message.startswith('主機資料夾中的 x 屬於 UID 54999／GID 54998'), error.message)
        self.assertIn('無法以應用帳號還原', error.message)
        self.assertEqual(error.details['reason'], 'owner id outside the user namespace')

    def test_hostile_directory_members(self):
        base = [{'name': '.', 'type': tarfile.DIRTYPE, 'mode': 0o755}]
        cases = {
            'absolute member name': [{'name': '/etc/passwd', 'data': b'x'}],
            'member name with an empty, "." or ".." component': [{'name': './a/../../etc', 'data': b'x'}],
            'member below a symlink, hard link or file': [
                {'name': './link', 'type': tarfile.SYMTYPE, 'linkname': '/home/appowner/.ssh'},
                {'name': './link/authorized_keys', 'data': b'ssh-ed25519 AAAA'}],
            'member type not allowed (device, sparse or unknown)': [
                {'name': './sda', 'type': tarfile.BLKTYPE, 'devmajor': 8, 'devminor': 0}],
            'duplicate member': [{'name': './a', 'data': b'1'}, {'name': 'a', 'data': b'2'}],
            'hard link to something other than an earlier non-directory member': [
                {'name': './h', 'type': tarfile.LNKTYPE, 'linkname': './nowhere'}],
            'the volume root is not a directory': [{'name': '.', 'type': tarfile.SYMTYPE, 'linkname': '/'}],
        }
        for reason, members in cases.items():
            with self.subTest(reason):
                data = gnu_dir_tar((base if members[0]['name'] != '.' else []) + members)
                error = self.rejected(nested.check_dir, data, reason)
                self.assertIn('主機資料夾', error.message)
                with self.assertRaises(BackupError):
                    stream(nested.stream_dir, self.file(data, 'again.tar'))


class DeltaReviewImageNameTests(TempCase):
    """Delta review finding HD-01: podman saves an image under the name its ref resolved to."""

    def test_names_podman_writes_for_a_ref_are_accepted_and_the_load_name_comes_from_the_ref(self):
        cases = [  # (Image= in the Quadlet file, name podman 4.9.3 wrote into index.json, local name for the load)
            ('ubuntu:24.04', 'docker.io/library/ubuntu:24.04', 'localhost/ubuntu:24.04'),
            ('docker.io/ubuntu:24.04', 'docker.io/library/ubuntu:24.04', 'docker.io/library/ubuntu:24.04'),
            ('docker.io/library/ubuntu:24.04', 'docker.io/library/ubuntu:24.04', 'docker.io/library/ubuntu:24.04'),
            ('woowbk-testrunner:noble', 'localhost/woowbk-testrunner:noble', 'localhost/woowbk-testrunner:noble'),
            ('postgres', 'docker.io/library/postgres:latest', 'localhost/postgres:latest'),
            ('foo/bar:1', 'quay.io/foo/bar:1', 'localhost/foo/bar:1'),  # resolved through another search registry
            ('registry.example:5000/team/app:2', 'registry.example:5000/team/app:2', 'registry.example:5000/team/app:2'),
        ]
        for ref, saved, local in cases:
            with self.subTest(ref):
                path = self.file(oci_archive(saved), 'image.tar')
                plan = nested.check_oci(path, ref=ref, image_id=image_id(saved))
                self.assertEqual(plan['name'], local)
                self.assertEqual(nested.local_name(ref), local)
                out = stream(nested.stream_oci, path, plan)
                self.assertEqual(read_oci(out), (local, image_id(saved)), 'podman load names it like `podman tag <id> <ref>`')

    def test_another_image_name_is_still_refused(self):
        for ref, saved in (('postgres:16-alpine', 'localhost/woowbk-sec-probe-other:9'),
                           ('postgres:16', 'docker.io/library/postgres:15'),
                           ('postgres:16', 'docker.io/library/redis:16'),
                           ('postgres:16', 'evil.example/library/postgres:16'),
                           ('docker.io/library/postgres:16', 'quay.io/library/postgres:16'),
                           ('localhost/app:1', 'docker.io/library/app:1'),
                           ('app@sha256:' + 'a' * 64, 'docker.io/library/app:latest')):
            with self.subTest(f'{ref} <- {saved}'):
                error = self.rejected(lambda path, ref=ref, saved=saved: nested.check_oci(path, ref=ref, image_id=image_id(saved)),
                                      oci_archive(saved), 'differs from the name the app needs')
                self.assertEqual(error.details['saved'], saved)
        self.assertFalse(nested.same_image_name('', 'postgres:16'))
        self.assertFalse(nested.same_image_name(None, 'postgres:16'))


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
