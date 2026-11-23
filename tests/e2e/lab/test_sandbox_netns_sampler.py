"""sandbox_netns_sampler against a fake /proc tree (no device, no real processes)."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

import sandbox_netns_sampler as sampler

PROGRAM = b'import os\nos.unshare(os.CLONE_NEWNET)\n'
EXPECT = {'n8n': hashlib.sha256(PROGRAM).hexdigest()}


class SamplerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.proc = Path(self.directory.name)
        self.events = []

    def process(self, pid, argv, euid, netns, root):
        base = self.proc / str(pid)
        if base.exists():
            for name in ('status', 'cmdline'):
                (base / name).unlink(missing_ok=True)
            for link in (base / 'ns' / 'net', base / 'root'):
                if link.is_symlink():
                    link.unlink()
        (base / 'ns').mkdir(parents=True, exist_ok=True)
        (base / 'cmdline').write_bytes(b'\0'.join(argv) + b'\0')
        (base / 'status').write_text(f'Name:\tpython3\nUid:\t{euid}\t{euid}\t{euid}\t{euid}\n', encoding='ascii')
        os.symlink(netns, base / 'ns' / 'net')
        os.symlink(root, base / 'root')

    def scan(self, pending, done):
        sampler.scan(str(self.proc), EXPECT, 'net:[1]', pending, done, self.events.append, now=lambda: 'T')

    def test_dropped_child_in_its_own_namespace_is_reported_once(self):
        argv = [b'/usr/bin/python3', b'-I', b'-S', b'-c', PROGRAM, b'65534', b'65534', b'9']
        self.process(40, argv, 0, 'net:[1]', '/')          # just started: still root, host namespace
        pending, done = {}, set()
        self.scan(pending, done)
        self.assertEqual(self.events, [])
        self.assertIn('40', pending)
        self.process(40, argv, 65534, 'net:[2]', '/var/lib/x')
        self.scan(pending, done)
        self.scan(pending, done)
        self.assertEqual(self.events, [{'t': 'T', 'child': 'n8n', 'args': 3, 'euid': 65534,
                                        'netns_isolated': True, 'chrooted': True}])

    def test_a_dropped_child_left_in_the_device_namespace_is_reported_not_isolated(self):
        self.process(41, [b'python3', b'-I', b'-S', b'-c', PROGRAM], 65534, 'net:[1]', '/')
        self.scan({}, set())
        self.assertEqual(self.events[0]['netns_isolated'], False)
        self.assertEqual(self.events[0]['chrooted'], False)

    def test_a_child_that_ends_before_it_drops_is_reported(self):
        argv = [b'python3', b'-I', b'-S', b'-c', PROGRAM]
        self.process(42, argv, 0, 'net:[1]', '/')
        pending, done = {}, set()
        self.scan(pending, done)
        for name in ('status', 'cmdline'):
            (self.proc / '42' / name).unlink()
        (self.proc / '42' / 'ns' / 'net').unlink()
        (self.proc / '42' / 'root').unlink()
        (self.proc / '42' / 'ns').rmdir()
        (self.proc / '42').rmdir()
        self.scan(pending, done)
        self.assertEqual(self.events, [{'t': 'T', 'child': 'n8n', 'args': 0, 'ended_before_drop': True}])

    def test_other_programs_are_ignored(self):
        self.process(43, [b'python3', b'-I', b'-S', b'-c', b'print(1)'], 65534, 'net:[1]', '/')
        self.process(44, [b'postgres', b'-D', b'/data'], 70, 'net:[1]', '/')
        (self.proc / 'self').mkdir()
        self.scan({}, set())
        self.assertEqual(self.events, [])


if __name__ == '__main__':
    unittest.main()
