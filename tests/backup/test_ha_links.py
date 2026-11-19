"""Links in an HA app tree (habackup.Select.absolute_symlinks, hard links) and what the restore accepts of them
(nested.check_volume / stream_volume): a Python venv keeps its absolute interpreter link and uv's hard-linked files
stay hard links, while nothing is ever followed (CONTRACT section 5 "Home Assistant backups", section 10 rule 18).
Team E1/E2."""
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from woowbackup import habackup, nested
from woowbackup.errors import BackupError

from . import hafixtures as hx

ABS = ('/opt/data', '/opt/hermes', '/usr')


def walk(entries, select):
    report = habackup.Report()
    out = [(entry.name, entry.kind, entry.linkname)
           for entry in habackup.iter_entries(io.BytesIO(hx.tar_bytes(entries)), select, report, addon=False)]
    return out, report


class AbsoluteSymlinkTests(unittest.TestCase):
    entries = [{'name': 'config', 'type': 'dir'}, {'name': 'config/venv', 'type': 'dir'},
               {'name': 'config/venv/bin', 'type': 'dir'},
               {'name': 'config/venv/bin/python', 'type': 'symlink', 'linkname': '/opt/data/uv/python/bin/python3.12'},
               {'name': 'config/venv/bin/hermes', 'type': 'symlink', 'linkname': '/opt/hermes/.venv/bin/hermes'},
               {'name': 'config/venv/bin/sys', 'type': 'symlink', 'linkname': '/usr/bin/python3'},
               {'name': 'config/venv/bin/etc', 'type': 'symlink', 'linkname': '/etc/shadow'},
               {'name': 'config/venv/bin/climb', 'type': 'symlink', 'linkname': '/opt/data/../../etc/shadow'},
               {'name': 'config/venv/bin/dot', 'type': 'symlink', 'linkname': '/opt/data/./x'},
               {'name': 'config/venv/bin/slash', 'type': 'symlink', 'linkname': '/opt/data//x'},
               {'name': 'config/venv/bin/prefix', 'type': 'symlink', 'linkname': '/opt/database/x'},
               {'name': 'config/venv/bin/rel', 'type': 'symlink', 'linkname': 'python'},
               {'name': 'outside', 'type': 'symlink', 'linkname': '/opt/data/x'}]

    def test_only_clean_targets_below_the_allowed_prefixes(self):
        out, report = walk(self.entries, habackup.Select(symlinks=('config',), absolute_symlinks=ABS))
        links = {name: target for name, kind, target in out if kind == 'symlink'}
        self.assertEqual(links, {'config/venv/bin/python': '/opt/data/uv/python/bin/python3.12',
                                 'config/venv/bin/hermes': '/opt/hermes/.venv/bin/hermes',
                                 'config/venv/bin/sys': '/usr/bin/python3', 'config/venv/bin/rel': 'python'})
        self.assertEqual(report.absolute_symlinks, 3)
        self.assertEqual(report.skipped_symlinks, 6)  # /etc, a `..`, a `.`, an empty component, a near prefix, outside

    def test_without_the_option_every_absolute_link_is_skipped_as_before(self):
        out, report = walk(self.entries, habackup.Select(symlinks=('config',)))
        self.assertEqual([name for name, kind, _t in out if kind == 'symlink'], ['config/venv/bin/rel'])
        self.assertEqual((report.absolute_symlinks, report.skipped_symlinks), (0, 9))

    def test_nothing_may_lie_below_a_handed_out_link(self):
        entries = [{'name': 'config', 'type': 'dir'},
                   {'name': 'config/l', 'type': 'symlink', 'linkname': '/opt/data'},
                   {'name': 'config/l/x', 'data': b'x'}]
        with self.assertRaises(BackupError) as caught:
            walk(entries, habackup.Select(symlinks=('config',), absolute_symlinks=ABS))
        self.assertEqual(caught.exception.details['reason'], 'entry below a file or link')

    def test_the_helper(self):
        ok = habackup._absolute_ok
        self.assertTrue(ok('/opt/data', ABS))
        self.assertFalse(ok('/opt/data/', ABS), 'an empty component')
        self.assertFalse(ok('/opt/data/a\nb', ABS))
        self.assertFalse(ok('/opt/data/' + 'x' * 5000, ABS))
        self.assertFalse(ok('/opt/data/x', ()))
        self.assertFalse(ok('opt/data/x', ABS))


def volume_tar(members):
    """A volume tar like the converters write (owner ids, PAX)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for item in members:
            info = tarfile.TarInfo(item['name'])
            info.type = {'dir': tarfile.DIRTYPE, 'file': tarfile.REGTYPE, 'symlink': tarfile.SYMTYPE,
                         'link': tarfile.LNKTYPE}[item.get('type', 'file')]
            info.uid = info.gid = 1000
            info.mode = 0o755 if info.type == tarfile.DIRTYPE else 0o644
            info.linkname = item.get('linkname', '')
            data = item.get('data')
            info.size = len(data) if data is not None else 0
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


class RestoreAcceptsTests(unittest.TestCase):
    """What the import produces is what the existing restore takes: absolute targets are joined below the link's
    folder (podman's own rule), hard links name an earlier non-directory member."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ids = (nested.IdMap('0 1013 1\n1 100000 65536\n'), nested.IdMap('0 1013 1\n1 100000 65536\n'))

    def check(self, members):
        path = Path(self.tmp.name) / 'v.tar'
        path.write_bytes(volume_tar(members))
        report = nested.check_volume(path, ids=self.ids)
        out = io.BytesIO()
        nested.stream_volume(path, out, ids=self.ids)
        with tarfile.open(fileobj=io.BytesIO(out.getvalue())) as tar:
            return report, {m.name: (m.type, m.linkname) for m in tar.getmembers()}

    def test_venv_links_and_uv_hard_links(self):
        members = [{'name': '.', 'type': 'dir'}, {'name': 'uv', 'type': 'dir'}, {'name': 'uv/a.so', 'data': b'elf'},
                   {'name': 'venv', 'type': 'dir'}, {'name': 'venv/lib', 'type': 'dir'},
                   {'name': 'venv/lib/a.so', 'type': 'link', 'linkname': 'uv/a.so'},
                   {'name': 'venv/python', 'type': 'symlink', 'linkname': '/opt/data/uv/python3.12'},
                   {'name': 'venv/hermes', 'type': 'symlink', 'linkname': '/opt/hermes/.venv/bin/hermes'}]
        report, kept = self.check(members)
        self.assertEqual(report.members, len(members))
        self.assertEqual(kept['venv/lib/a.so'], (tarfile.LNKTYPE, 'uv/a.so'))
        self.assertEqual(kept['venv/python'], (tarfile.SYMTYPE, '/opt/data/uv/python3.12'))

    def test_what_the_restore_refuses(self):
        for members, reason in (
                ([{'name': 'l', 'type': 'link', 'linkname': 'later'}, {'name': 'later', 'data': b'x'}],
                 'hard link to something other than an earlier non-directory member'),
                ([{'name': 'l', 'type': 'symlink', 'linkname': '/../../etc'}], 'symlink pointing outside the volume'),
                ([{'name': 'l', 'type': 'symlink', 'linkname': '/opt/data'}, {'name': 'l/x', 'data': b'x'}],
                 'member below a symlink, hard link or file')):
            with self.subTest(reason=reason), self.assertRaises(BackupError) as caught:
                self.check(members)
            self.assertEqual(caught.exception.details['reason'], reason)


if __name__ == '__main__':
    unittest.main()
