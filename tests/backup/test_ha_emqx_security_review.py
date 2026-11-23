"""EMQX HA import security review 2026-11-23 (lane emqx-secreview), regression tests.

SR-1 (B1-06, port of e848015): a crafted HA backup's cluster.hocon named a plugin staged under certs/ and HA's broker
loaded and started it (EMQX 5.8.9 emqx_plugins_app.erl:31-33, emqx_plugins.erl:310-321,1023-1066). HA's broker now
pins `plugins.states = []` and the image's plugin folder through the environment (which wins over cluster.hocon) and
mounts every writable volume noexec,nosuid,nodev.

SR-2 (B1-02 reopened once the public guard goes): this device's file ACL in the data volume
(/opt/emqx/data/authz/acl.conf, where the Dashboard writes edited rules) was overwritten by HA's file ACL during the
import (emqx_authz_file.erl:64-75,120-121) while every configuration comparison stayed equal. Every data-volume file
the device's configuration names must now reach the candidate byte for byte, else the conversion refuses.
"""
import copy
import hashlib
import io
import tarfile
import unittest

from woowbackup import ha_emqx
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import test_ha_emqx as base
from . import test_ha_emqx_candidate_flow as flow

DEVICE_ACL = b'{allow, {username, "woow"}, all, ["#"]}.\n{deny, all}.\n'
HA_ACL = b'{allow, all}.\n'
DATA_ACL = '/opt/emqx/data/authz/acl.conf'


def with_acl(raw):
    """The fake volume export plus authz/acl.conf (the device's file, uid 1000 like the image user)."""
    out = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw)) as source, tarfile.open(fileobj=out, mode='w',
                                                                         format=tarfile.PAX_FORMAT) as dest:
        for member in source:
            dest.addfile(member, source.extractfile(member) if member.isfile() else None)
        folder = tarfile.TarInfo('authz'); folder.type = tarfile.DIRTYPE; folder.mode = 0o755
        folder.uid = folder.gid = 1000
        dest.addfile(folder)
        acl = tarfile.TarInfo('authz/acl.conf'); acl.size = len(DEVICE_ACL); acl.mode = 0o644
        acl.uid = acl.gid = 1000
        dest.addfile(acl, io.BytesIO(DEVICE_ACL))
    return out.getvalue()


class DataAclWorld(base.World):
    """This device keeps its file ACL in the data volume; `candidate_acl` is what the candidate's file holds after
    HA's import (HA_ACL = the vendor overwrote it)."""

    def __init__(self):
        super().__init__()
        self.target_config = {'authorization': {'no_match': 'deny', 'deny_action': 'ignore',
                                                'sources': [{'type': 'file', 'enable': True, 'path': DATA_ACL}]}}
        self.current_config = copy.deepcopy(self.target_config)
        self.candidate_acl = DEVICE_ACL
        self.hashed = []

    def exec(self, role, command, data, stdout):
        if role == 'emqx-new' and command == ['sha256sum', DATA_ACL]:
            self.hashed.append(command[1])
            line = hashlib.sha256(self.candidate_acl).hexdigest().encode() + b'  ' + DATA_ACL.encode() + b'\n'
            return Result(0, line, b'')
        return super().exec(role, command, data, stdout)

    def export(self, volume):
        raw = super().export(volume)
        return raw if volume.endswith('emqx-xfer') else with_acl(raw)


class PluginPinTests(base.EmqxCase):
    """SR-1: HA's broker never loads a plugin HA's cluster.hocon names, and nothing it can write is executable."""

    def test_check_pins_plugins_and_mounts_noexec(self):
        self.check(self.upload_emqx(), ['emqx'])
        options = self.runs('emqx-ha')[0][3]
        self.assertIn('EMQX_PLUGINS__STATES=[]', options['--env'])
        self.assertIn('EMQX_PLUGINS__INSTALL_DIR=/opt/emqx/plugins', options['--env'])
        self.assertIn('--read-only', options)
        volumes = options['--volume']
        self.assertTrue(any(v.endswith(':/data/emqx/data:rw,noexec,nosuid,nodev') for v in volumes))
        self.assertTrue(any(v.endswith(':/opt/emqx/log:rw,noexec,nosuid,nodev') for v in volumes))
        self.assertFalse([v for v in volumes if not v.endswith(':rw,noexec,nosuid,nodev')], volumes)

    def test_conversion_mounts_the_transfer_volume_noexec(self):
        self.internal_candidate(self.upload_emqx())
        volumes = self.runs('emqx-ha')[0][3]['--volume']
        self.assertTrue(any(v.endswith(':/work:rw,noexec,nosuid,nodev') for v in volumes), volumes)
        self.assertFalse([v for v in volumes if not v.endswith(':rw,noexec,nosuid,nodev')], volumes)
        self.assertIn('EMQX_PLUGINS__STATES=[]', self.runs('emqx-ha')[0][3]['--env'])


class DataVolumeAclTests(base.EmqxCase):
    """SR-2: the device's data-volume ACL file must be byte-identical in the finished candidate."""
    world_class = DataAclWorld

    def test_an_import_that_rewrites_the_device_acl_is_refused(self):
        self.world.candidate_acl = HA_ACL
        with self.assertRaises(BackupError) as caught:
            self.internal_candidate(self.upload_emqx())
        self.assertEqual(caught.exception.message, ha_emqx.SNAPSHOT_CHANGED)
        self.assertEqual(self.world.hashed, [DATA_ACL])

    def test_an_import_that_keeps_the_device_acl_passes(self):
        result = self.internal_candidate(self.upload_emqx())
        self.assertIn('woow_emqx_data', result['volumes'])
        self.assertEqual(self.world.hashed, [DATA_ACL], 'the digest check ran on the finished candidate')


class SnapshotDigestUnitTests(unittest.TestCase):
    def snapshot(self, tmpdir, files):
        path = f'{tmpdir}/snapshot.tar'
        with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as tar:
            for name, data in files.items():
                info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o600
                tar.addfile(info, io.BytesIO(data))
        return path

    def test_digests_skip_only_the_override_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.snapshot(tmpdir, {'configs/cluster.hocon': b'x', 'authz/acl.conf': DEVICE_ACL,
                                          'certs/key.pem': b'k'})
            self.assertEqual(ha_emqx.snapshot_file_digests(path),
                             {'authz/acl.conf': hashlib.sha256(DEVICE_ACL).hexdigest(),
                              'certs/key.pem': hashlib.sha256(b'k').hexdigest()})

    def test_every_unexpected_answer_refuses(self):
        want = hashlib.sha256(DEVICE_ACL).hexdigest()
        good = want.encode() + b'  ' + DATA_ACL.encode() + b'\n'
        answers = [Result(1, good, b''),                                      # sha256sum failed
                   Result(0, hashlib.sha256(HA_ACL).hexdigest().encode() + good[64:], b''),   # content changed
                   Result(0, want.encode() + b'  /opt/emqx/data/authz/other.conf\n', b''),   # another file
                   Result(0, good + b'extra\n', b''),                           # trailing output
                   Result(0, good.upper(), b''),                                # not sha256sum's format
                   Result(0, b'', b'')]
        for answer in answers:
            with self.subTest(answer=answer.stdout[:20]):
                with self.assertRaises(BackupError) as caught:
                    ha_emqx.check_snapshot_files(lambda _c, a=answer: a, {'authz/acl.conf': want})
                self.assertEqual(caught.exception.message, ha_emqx.SNAPSHOT_CHANGED)
        calls = []
        ha_emqx.check_snapshot_files(lambda c: calls.append(c) or Result(0, good, b''), {'authz/acl.conf': want})
        self.assertEqual(calls, [['sha256sum', DATA_ACL]])


class CaptureFlowDigestTests(unittest.TestCase):
    """SR-2 through the capture -> seed -> import -> restore path (candidate_from_target) with the shared transport:
    the device's data-volume ACL and certificate are hashed in the finished candidate; a rewritten one refuses."""

    def test_untouched_files_pass_and_are_hashed_after_the_restore(self):
        transport = flow.Transport()
        flow.CandidateFlowTests().invoke(transport)
        digests = [e for e in transport.events if e.startswith('digest:')]
        self.assertEqual(sorted(digests), ['digest:authz/custom.acl', 'digest:certs/lab.pem'])
        self.assertGreater(transport.events.index(digests[0]), transport.events.index('restore'))

    def test_a_rewritten_device_acl_refuses(self):
        transport = flow.Transport()
        transport.overwritten = {'authz/custom.acl': HA_ACL}
        with self.assertRaises(BackupError) as caught:
            flow.CandidateFlowTests().invoke(transport)
        self.assertEqual(caught.exception.message, ha_emqx.SNAPSHOT_CHANGED)


class FileSecretWorld(base.World):
    """HA's import brings an MQTT connector whose password is `password` (SR-3)."""
    password = 'file:///opt/emqx/etc/woow-mqtt-bootstrap.csv'

    def exec(self, role, command, data, stdout):
        result = super().exec(role, command, data, stdout)
        if command[:4] == ['emqx', 'ctl', 'data', 'import']:
            self.current_config['connectors'] = {'mqtt': {'ha': {'server': 'broker.example:1883',
                                                                  'password': self.password}}}
        return result


class FileSecretTests(base.EmqxCase):
    """SR-3: a migrated value using EMQX's file:// secret loader would read THIS device's files on this device."""
    world_class = FileSecretWorld

    def test_a_file_secret_in_migrated_settings_refuses(self):
        with self.assertRaises(BackupError) as caught:
            self.internal_candidate(self.upload_emqx())
        self.assertEqual(caught.exception.message, ha_emqx.FILE_SECRET.format(roots='connectors'))

    def test_a_plain_password_passes(self):
        self.world.password = 'typed-in-ha'
        result = self.internal_candidate(self.upload_emqx())
        self.assertIn('woow_emqx_data', result['volumes'])


class FileSecretUnitTests(unittest.TestCase):
    def test_every_shape_is_found_and_only_ha_roots_count(self):
        roots = ha_emqx.file_secret_roots
        self.assertEqual(roots({'connectors': {'mqtt': {'a': {'password': 'file:///proc/self/environ'}}}}),
                         ['connectors'])
        self.assertEqual(roots({'authentication': [{'backend': 'redis', 'password': '  FILE:///x'}]}),
                         ['authentication'])
        self.assertEqual(roots({'bridges': {'x': {'servers': [{'p': list(b'file:///etc/x')}]}}}), ['bridges'])
        self.assertEqual(roots({'exhook': {'servers': [{'file:///k': 1}]}}), ['exhook'])
        self.assertEqual(roots({'authorization': {'sources': [{'path': 'file:///x'}]},
                                'dashboard': {'default_password': 'file:///x'}}), [],
                         "this device's own roots are restored from its configuration")
        self.assertEqual(roots({'connectors': {'http': {'a': {'url': 'http://h/file://x', 'password': 'p'}}}}), [])


if __name__ == '__main__':
    unittest.main()
