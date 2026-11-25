"""Links in an HA app tree (habackup.Select.absolute_symlinks, hard links) and what the restore accepts of them
(nested.check_volume / stream_volume): a Python venv keeps its absolute interpreter link and uv's hard-linked files
stay hard links, while nothing is ever followed (CONTRACT section 5 "Home Assistant backups", section 10 rule 18).
Team E1/E2."""
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from woowbackup import habackup, hacommon, haissues, nested
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

    def test_what_the_reader_hands_out_is_what_the_restore_takes(self):
        """Whatever an add-on's data holds (HAOS parity): links as copies, nothing the restore would refuse -- no device
        node, no link out of the volume, no name with control characters -- and the list of what was left out."""
        entries = [{'name': 'v', 'type': 'dir'}, {'name': 'v/a', 'data': b'a' * 600}, {'name': 'x/cache', 'data': b'cached'},
                   {'name': 'v/copy', 'type': 'hardlink', 'linkname': 'x/cache'},
                   {'name': 'v/again', 'type': 'hardlink', 'linkname': 'v/a'},
                   {'name': 'v/gone', 'type': 'hardlink', 'linkname': '../etc/shadow'},
                   {'name': 'v/dev', 'type': 'chr'}, {'name': 'v/pipe', 'type': 'fifo'}, {'name': 'v/bad\nname', 'data': b'x'},
                   {'name': 'v/in', 'type': 'symlink', 'linkname': 'a'}, {'name': 'v/out', 'type': 'symlink', 'linkname': '/etc'},
                   {'name': 'v/up', 'type': 'symlink', 'linkname': '../x/cache'}]
        for hardlinks in (False, True):
            report, members = habackup.Report(), []
            for entry in habackup.iter_entries(io.BytesIO(hx.tar_bytes(entries)), habackup.Select(
                    include=('v',), symlinks=('v',), hardlinks=hardlinks), report, addon=False):
                kind = {'hardlink': 'link'}.get(entry.kind, entry.kind)
                name = entry.name[2:] or '.'
                members.append({'name': name, 'type': kind, 'linkname': (entry.linkname or '').removeprefix('v/'),
                                'data': entry.read_all(1 << 20) if entry.kind == 'file' else None})
            with self.subTest(hardlinks=hardlinks):
                _checked, kept = self.check(members)
                again = (tarfile.LNKTYPE, 'a') if hardlinks else (tarfile.REGTYPE, '')
                self.assertEqual({name: kept[name] for name in ('a', 'copy', 'again', 'in')},
                                 {'a': (tarfile.REGTYPE, ''), 'copy': (tarfile.REGTYPE, ''), 'again': again,
                                  'in': (tarfile.SYMTYPE, 'a')})
                self.assertEqual(sorted(kept), ['.', 'a', 'again', 'copy', 'in'])
                self.assertEqual({kind: names.first for kind, names in report.skips.items()},
                                 {'device': ['v/dev'], 'fifo': ['v/pipe'], 'name': ['v/bad name'], 'hardlink': ['v/gone'],
                                  'symlink': ['v/out', 'v/up']})

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


IDS = (nested.IdMap('0 1013 1\n1 100000 65536\n'), nested.IdMap('0 1013 1\n1 100000 65536\n'))


class LeftOutLinksTests(unittest.TestCase):
    """HAOS parity (lane F3): a hard link whose file does not move is copied (CM-11), what cannot be copied and a customer's
    own link out of the volume are left out and listed with their full count (X-NS-08), and the customer is asked once
    (`Sink.skipped`); the rest of the volume goes on. What the restore refuses never reaches it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def convert(self, entries, *, move, report=None, copy=True):
        """What an importer does: walk the tree, keep what `move(name)` says, ask for a hard link's content."""
        report = report if report is not None else habackup.Report(names=haissues.Names)
        out = hacommon.TreeTar(self.dir / 'v.tar', 1000, 1000, report=report)
        out.root(0o755)
        select = habackup.Select(include=('v',), symlinks=('v',), hardlinks=True)
        for entry in habackup.iter_entries(io.BytesIO(hx.tar_bytes(entries)), select, report, addon=False):
            name = entry.name[2:] or '.'
            if name == '.':
                continue
            if entry.kind == 'dir':
                out.dir(name, entry.mode, entry.mtime)
            elif entry.kind == 'file' and move(name):
                out.file(name, entry, entry.mode)
            elif entry.kind == 'hardlink':
                out.hardlink(name, entry.linkname[2:], entry.mtime, entry=entry if copy else None)
            elif entry.kind == 'symlink':
                out.symlink(name, entry.linkname, entry.mtime)
        out.close()
        return out, report

    def members(self, path=None):
        with tarfile.open(path or self.dir / 'v.tar') as tar:
            return {m.name: (m.type, m.linkname, tar.extractfile(m).read() if m.isfile() else None) for m in tar.getmembers()}

    ENTRIES = [{'name': 'v', 'type': 'dir'}, {'name': 'v/run.pid', 'data': b'4242'},
               {'name': 'v/pid-link', 'type': 'hardlink', 'linkname': 'v/run.pid'}, {'name': 'v/keep', 'data': b'k'},
               {'name': 'v/keep-link', 'type': 'hardlink', 'linkname': 'v/keep'}]

    def test_a_hard_link_to_a_file_that_does_not_move_is_copied(self):
        out, report = self.convert(self.ENTRIES, move=lambda name: name != 'run.pid')
        kept = self.members()
        self.assertNotIn('run.pid', kept)
        self.assertEqual(kept['pid-link'], (tarfile.REGTYPE, '', b'4242'), 'the content, as a file of its own')
        self.assertEqual(kept['keep-link'][:2], (tarfile.LNKTYPE, 'keep'), 'a link to a file that moves stays a link')
        self.assertEqual((out.copied, report.skip_count()), (1, 0))
        self.assertEqual(out.counts['hardlinks'], 1)
        self.assertEqual(nested.check_volume(self.dir / 'v.tar', ids=IDS).members, 4)

    def test_without_an_entry_to_copy_from_the_link_is_left_out_and_listed_not_half_moved(self):
        out, report = self.convert(self.ENTRIES, move=lambda name: name != 'run.pid', copy=False)
        self.assertNotIn('pid-link', self.members())
        self.assertEqual(report.skips['hardlink'].first, ['pid-link'])
        self.assertEqual(out.copied, 0)
        nested.check_volume(self.dir / 'v.tar', ids=IDS)

    def test_without_a_report_a_hard_link_without_its_file_still_stops_the_import(self):
        out = hacommon.TreeTar(self.dir / 'old.tar', 1000, 1000)
        out.root(0o755)
        with self.assertRaises(BackupError) as caught:
            out.hardlink('pid-link', 'run.pid', 0)
        self.assertEqual(caught.exception.code, 'incompatible')
        out.close()

    def customer_volume(self, links):
        """A live export of this device's volume: some files and `links` customer-made symlinks that leave it."""
        path = self.dir / 'live.tar'
        members = [{'name': '.', 'type': 'dir', 'uid': 1000, 'gid': 1000}, {'name': 'data', 'data': b'd', 'uid': 1000, 'gid': 1000},
                   {'name': 'ok', 'type': 'symlink', 'linkname': 'data', 'uid': 1000, 'gid': 1000},
                   {'name': 'gone', 'data': b'g', 'uid': 1000, 'gid': 1000},
                   {'name': 'gone-link', 'type': 'hardlink', 'linkname': 'gone', 'uid': 1000, 'gid': 1000}]
        members += [{'name': f'out{i:02d}', 'type': 'symlink', 'linkname': '../' * (1 + i % 3) + 'etc', 'uid': 1000, 'gid': 1000}
                    for i in range(links)]
        path.write_bytes(hx.tar_bytes(members))
        return path

    def copy_live(self, links, report):
        self.copies = getattr(self, 'copies', 0) + 1
        path = self.dir / f'out{self.copies}.tar'
        out = hacommon.FileTar(path)
        hacommon.copy_live(self.customer_volume(links), out, drop=lambda name: name == 'gone', report=report, label='n8n-data：')
        out.close()
        return path

    def test_a_customers_link_out_of_a_live_volume_is_left_out_and_the_restore_takes_the_rest(self):
        report = habackup.Report(names=haissues.Names)
        path = self.copy_live(3, report)
        kept = self.members(path)
        self.assertEqual(sorted(kept), ['.', 'data', 'ok'])
        self.assertEqual(report.skips['symlink'].first, ['n8n-data：out00', 'n8n-data：out01', 'n8n-data：out02'])
        self.assertEqual(report.skips['hardlink'].first, ['n8n-data：gone-link'], 'a link to a file that was dropped')
        self.assertEqual(nested.check_volume(path, ids=IDS).members, 3, 'what the restore refuses never reaches it')
        # without a report everything is copied as before, and the restore refuses it
        plain = self.dir / 'plain.tar'
        out = hacommon.FileTar(plain)
        hacommon.copy_live(self.customer_volume(3), out, drop=lambda name: name == 'gone')
        out.close()
        with self.assertRaises(BackupError) as caught:
            nested.check_volume(plain, ids=IDS)
        self.assertEqual(caught.exception.details['reason'], 'hard link to something other than an earlier non-directory member')

    def test_every_link_is_counted_and_twenty_are_shown(self):
        report = habackup.Report(names=haissues.Names)
        self.copy_live(31, report)
        self.assertEqual(report.skip_count('symlink'), 31)
        self.assertEqual(len(report.skips['symlink'].first), 20)
        sink = haissues.Sink('n8n')
        issue = sink.skipped(report, 'symlink')
        self.assertIn('31 個', issue.message)
        self.assertEqual((issue.id, issue.level, issue.count, len(issue.names)), ('files.skipped', 'confirm', 31, 20))
        self.assertEqual(len(issue.view('n8n')['items']), 20)
        self.assertEqual(issue.view('n8n')['more'], 11)

    def asked(self, links, acknowledged):
        report = habackup.Report(names=haissues.Names)
        self.copy_live(links, report)
        sink = haissues.Sink('n8n', acknowledged)
        return sink, sink.skipped(report, 'symlink')

    def test_a_link_that_was_left_out_and_not_confirmed_stops_only_that_app(self):
        with self.assertRaises(BackupError) as caught:
            self.asked(2, [])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(list(caught.exception.details['apps']), ['n8n'], 'only the app that left something out')
        # the check only collects: the customer sees the line and confirms it
        _sink, issue = self.asked(2, None)
        self.assertEqual(issue.level, 'confirm')

    def test_a_confirmed_line_goes_on_and_one_more_name_asks_again(self):
        _sink, issue = self.asked(2, None)
        key = issue.key('n8n')
        sink, issue = self.asked(2, [key])
        self.assertEqual((issue.key('n8n'), sink.confirmed()[0]['id']), (key, 'files.skipped'))
        with self.assertRaises(BackupError) as caught:
            self.asked(3, [key])               # the customer confirmed two names; a third link is another line
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertIn('請再確認一次', caught.exception.message)

    def test_a_link_inside_the_tree_that_goes_out_is_left_out_by_the_tree_tar_too(self):
        out, report = self.convert([{'name': 'v', 'type': 'dir'}, {'name': 'v/a', 'data': b'a'},
                                    {'name': 'v/in', 'type': 'symlink', 'linkname': 'a'}], move=lambda _name: True)
        self.assertEqual(self.members()['in'][:2], (tarfile.SYMTYPE, 'a'))
        report = habackup.Report(names=haissues.Names)
        out = hacommon.TreeTar(self.dir / 'direct.tar', 1000, 1000, report=report)
        out.root(0o755)
        self.assertTrue(out.symlink('x', 'a', 0))
        self.assertFalse(out.symlink('deep/x', '../../../etc', 0), 'a link that leaves the volume')
        out.close()
        self.assertEqual(report.skips['symlink'].first, ['deep/x'])
        self.assertEqual(sorted(self.members(self.dir / 'direct.tar')), ['.', 'x'])
        plain = hacommon.TreeTar(self.dir / 'plain.tar', 1000, 1000)
        plain.root(0o755)
        self.assertTrue(plain.symlink('deep/x', '../../../etc', 0), 'without a report: written as before')
        plain.close()

    def test_a_link_is_judged_as_the_restore_judges_it(self):
        cases = (('a', 'b', False), ('a/b', '../c', False), ('a/b', '../../c', True), ('a', '../c', True), ('a', '/etc/x', False),
                 ('a/b', '/../../x', True), ('a', '.', False), ('a', '..', True), ('a/b/c', '../../..', True),
                 ('a/b/c', '../..', False))
        for name, target, escapes in cases:
            with self.subTest(name=name, target=target):
                self.assertEqual(hacommon.link_escapes(name, target), escapes)
                members = [{'name': 'a', 'type': 'dir'}, {'name': 'a/b', 'type': 'dir'}, {'name': 'a/b/c', 'type': 'dir'}]
                parts = name.split('/')
                members = [m for m in members if m['name'] != name]
                members.append({'name': name, 'type': 'symlink', 'linkname': target})
                path = self.dir / 'judge.tar'
                tar = io.BytesIO()
                with tarfile.open(fileobj=tar, mode='w', format=tarfile.PAX_FORMAT) as handle:
                    for folder in ('.', *('/'.join(parts[:i]) for i in range(1, len(parts)))):
                        item = tarfile.TarInfo(folder)
                        item.type, item.mode, item.uid, item.gid = tarfile.DIRTYPE, 0o755, 1000, 1000
                        handle.addfile(item)
                    item = tarfile.TarInfo(name)
                    item.type, item.linkname, item.uid, item.gid, item.mode = tarfile.SYMTYPE, target, 1000, 1000, 0o777
                    handle.addfile(item)
                path.write_bytes(tar.getvalue())
                if escapes:
                    with self.assertRaises(BackupError):
                        nested.check_volume(path, ids=IDS)
                else:
                    nested.check_volume(path, ids=IDS)


if __name__ == '__main__':
    unittest.main()
