"""What the batch 1 importers share (hacommon.py) and the throwaway containers' host lines (tempctr). Team E2."""
import io
import tarfile
import tempfile
import types
import unittest
from pathlib import Path

from woowbackup import habackup, hacommon, nested, tempctr
from woowbackup.errors import BackupError

from . import hafixtures as hx


class ScanTests(unittest.TestCase):
    def test_ha_only_hosts(self):
        text = ('base_url: http://homeassistant:8123/api\nllm: http://a0d7b954-litellm:4000/v1\n'
                'x: https://api.example.com/v1  y: http://localhost:8642  z: ws://172.30.32.1:8123/api/websocket\n'
                'w: mqtt://core-mosquitto:1883 v: http://my-ha.local:8123 u: http://supervisor/core')
        self.assertEqual(hacommon.ha_hosts(text), ['172.30.32.1', 'a0d7b954-litellm', 'core-mosquitto',
                                                   'homeassistant', 'my-ha.local', 'supervisor'])

    def test_simple_yaml_scalars(self):
        text = ('server_url: "http://homeassistant.local:28080"\nprefixes:\n  v4: "100.64.0.0/10"\n'
                '  v6: fd7a:115c:a1e0::/48  # comment\n  allocation: sequential\nderp:\n  urls:\n    - https://x\n'
                '  paths: []\ndns:\n  base_domain: ts.local\n  extra_records_path: /etc/headscale/dns_records.json\n'
                '# policy: x\npolicy:\n  mode: file\n  path: ""\n_config_version: 51\n')
        values = hacommon.scalars(text)
        self.assertEqual(values['server_url'], 'http://homeassistant.local:28080')
        self.assertEqual((values['prefixes.v4'], values['prefixes.v6']), ('100.64.0.0/10', 'fd7a:115c:a1e0::/48'))
        self.assertEqual(values['dns.extra_records_path'], '/etc/headscale/dns_records.json')
        self.assertEqual((values['policy.mode'], values['policy.path'], values['_config_version']), ('file', '', '51'))
        self.assertNotIn('derp.paths', values)
        self.assertEqual(hacommon.scalars('x' * (2 * 1024 * 1024)), {})

    def test_versions(self):
        table = hacommon.VersionTable('Headscale', {'0.1.0': '0.29.3', '0.1.3': '0.29.4'})
        self.assertIsNone(table.blocker('0.1.3', '0.29.4'))
        self.assertIsNone(table.blocker('0.1.3', 'v0.29.4'))
        self.assertIn('HA 的 Headscale 是 0.29.3', table.blocker('0.1.0', '0.29.4'))
        self.assertIn('還不認得', table.blocker('0.2.0', '0.29.4'))
        self.assertIn('無法讀取這台', table.blocker('0.1.3', None))
        self.assertEqual((hacommon.semver('v5.8.9'), hacommon.semver('5.8.9-rc1'), hacommon.semver(None)),
                         ('5.8.9', None, None))

    def test_foreign_programs(self):
        x86 = b'\x7fELF\x02\x01\x01' + bytes(11) + b'\x3e\x00'
        arm = b'\x7fELF\x02\x01\x01' + bytes(11) + b'\xb7\x00'
        self.assertFalse(hacommon.foreign_elf(x86, 0x3E))
        self.assertTrue(hacommon.foreign_elf(arm, 0x3E))
        self.assertFalse(hacommon.foreign_elf(b'#!/bin/sh\n' * 3, 0x3E))
        self.assertFalse(hacommon.foreign_elf(arm, None))


class TreeTarTests(unittest.TestCase):
    def test_links_owner_and_modes(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / 'v.tar'
        source = hx.tar_bytes([{'name': 'a', 'data': b'abc', 'mode': 0o4755}, {'name': 'b', 'data': b'b'}])
        out = hacommon.TreeTar(path, 1000, 1000)
        out.root(0o755, 0, 0)
        for entry in habackup.iter_entries(io.BytesIO(source), None, habackup.Report(), addon=False):
            out.file(entry.name, entry, entry.mode)
        out.dir('d', 0o2775, 0)
        out.symlink('d/python', '/opt/data/uv/python3', 0)
        out.hardlink('d/a', 'a', 0)
        with self.assertRaises(BackupError) as caught:
            out.hardlink('d/c', 'skipped', 0)
        self.assertEqual(caught.exception.code, 'incompatible')
        out.close()
        with tarfile.open(path) as tar:
            members = {m.name: m for m in tar.getmembers()}
        self.assertEqual((members['a'].mode, members['a'].uid), (0o755, 1000), 'no setuid')
        self.assertEqual(members['d'].mode, 0o775, 'no setgid either')
        self.assertEqual((members['d/a'].type, members['d/a'].linkname), (tarfile.LNKTYPE, 'a'))
        self.assertEqual(members['.'].uid, 0)
        ids = (nested.IdMap('0 1013 1\n1 100000 65536\n'), nested.IdMap('0 1013 1\n1 100000 65536\n'))
        self.assertEqual(nested.check_volume(path, ids=ids).members, 6)
        self.assertEqual(out.counts, {'files': 2, 'dirs': 1, 'symlinks': 1, 'hardlinks': 1, 'bytes': 4})

    def test_a_live_export_is_copied_without_what_is_dropped(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        live = Path(tmp.name) / 'live.tar'
        live.write_bytes(hx.tar_bytes([{'name': '.', 'type': 'dir', 'uid': 0}, {'name': 'artifacts', 'type': 'dir'},
                                       {'name': 'artifacts/accounts-cookie-secret', 'data': b'live'},
                                       {'name': 'sharing_mode', 'data': b'off'}]))
        out = hacommon.FileTar(Path(tmp.name) / 'out.tar')
        dirs = hacommon.copy_live(live, out, drop=lambda name: hacommon._under(name, 'artifacts'))
        out.close()
        with tarfile.open(Path(tmp.name) / 'out.tar') as tar:
            self.assertEqual(sorted(m.name for m in tar.getmembers()), ['.', 'sharing_mode'])
        self.assertEqual(sorted(dirs), ['.', 'artifacts'])
        live.write_bytes(b'not a tar' * 100)
        with self.assertRaises(BackupError):
            hacommon.copy_live(live, hacommon.FileTar(Path(tmp.name) / 'out2.tar'))


class LabelTests(unittest.TestCase):
    def work(self, stdout, code=0):
        runner = types.SimpleNamespace(podman=lambda *a, **k: types.SimpleNamespace(returncode=code, stdout=stdout))
        return types.SimpleNamespace(runner=lambda _app: runner)

    def test_labels(self):
        app = types.SimpleNamespace(id='emqx', name='EMQX')
        labels = hacommon.image_labels(self.work(b'{"org.opencontainers.image.version": "5.8.9", "n": 1}\n'), app,
                                       'docker.io/emqx/emqx:5.8.9')
        self.assertEqual(labels, {'org.opencontainers.image.version': '5.8.9'})
        self.assertEqual(hacommon.image_labels(self.work(b'null\n'), app, 'x:1'), {})
        with self.assertRaises(BackupError):
            hacommon.image_labels(self.work(b'', code=125), app, 'x:1')
        with self.assertRaises(BackupError):
            hacommon.image_labels(self.work(b''), app, 'bad ref')


class AddHostTests(unittest.TestCase):
    def test_host_lines_are_checked(self):
        tmp = tempctr.TempObjects(types.SimpleNamespace(uid=None), 'j20261118T120000Z-0123abcd', cpus=None)
        argv = tmp.run_argv('emqx-ha', 'docker.io/emqx/emqx:5.8.9', [], add_hosts=[('homeassistant.local',
                                                                                     '127.0.0.1')])
        self.assertIn('--add-host', argv)
        self.assertIn('homeassistant.local:127.0.0.1', argv)
        self.assertEqual(argv[argv.index('--network') + 1], 'none')
        for bad in (('-x', '127.0.0.1'), ('a b', '127.0.0.1'), ('host', '::1'), ('host', '127.0.0.1;x')):
            with self.subTest(bad=bad), self.assertRaises(BackupError):
                tmp.run_argv('emqx-ha', 'docker.io/emqx/emqx:5.8.9', [], add_hosts=[bad])


if __name__ == '__main__':
    unittest.main()
