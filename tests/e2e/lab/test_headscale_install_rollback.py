"""Local fixture tests only: no containers, no real restore acceptance."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('hs_install', Path(__file__).with_name('headscale_install_rollback.py'))
hs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hs)


class RestoreTests(unittest.TestCase):
    def exercise(self, mode):
        state = {'enabled': False, 'count': 0}
        calls = []
        runner = Mock()
        def restore(bid):
            calls.append(('restore', bid))
            hs.arm_once(runner, 'marker', state)
            if state['enabled']:
                if mode == 'exception':
                    raise RuntimeError('not rollback')
                if mode == 'missing_arm':
                    state['count'] = 0
                if mode != 'success_instead':
                    raise hs.flows.RolledBack(hs.flows.BackupError('job-failed', 'synthetic'), {'rolled_back': True, 'safety_backup_id': 'second'})
            return {'changed': True, 'rolled_back': False, 'safety_backup_id': 'first'}
        verify = lambda phase: calls.append(('verify', phase))
        safety = lambda bid: calls.append(('safety', bid))
        mutate = lambda: calls.append('mutate')
        hs.restore_pair(restore, 'candidate', state, verify, safety, mutate)
        return calls, runner

    def test_real_flow_orchestration_contract_fixture(self):
        calls, runner = self.exercise('rollback')
        self.assertEqual(calls, [('restore', 'candidate'), ('safety', 'first'), ('verify', 'installed'), 'mutate',
                                 ('restore', 'candidate'), ('safety', 'second'), ('verify', 'rolled_back')])
        runner.write_file.assert_called_once_with('marker', b'fail-once\n', 0o600)

    def test_failed_install_continuity_prevents_rollback_exercise(self):
        state = {'enabled': False, 'count': 0}
        restore = Mock(return_value={'changed': True, 'rolled_back': False, 'safety_backup_id': 'first'})
        verify = Mock(side_effect=RuntimeError('continuity_deadline'))
        mutate = Mock()
        with self.assertRaisesRegex(RuntimeError, 'continuity_deadline'):
            hs.restore_pair(restore, 'candidate', state, verify, Mock(), mutate)
        verify.assert_called_once_with('installed')
        mutate.assert_not_called()
        self.assertFalse(state['enabled'])
        restore.assert_called_once()

    def test_success_without_injected_failure_is_not_rollback(self):
        with self.assertRaisesRegex(RuntimeError, 'injected_failure_not_observed'):
            self.exercise('success_instead')

    def test_unrelated_failure_is_not_rollback(self):
        with self.assertRaisesRegex(RuntimeError, 'not rollback'):
            self.exercise('exception')

    def test_rollback_without_one_shot_evidence_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'rollback_not_automatic'):
            self.exercise('missing_arm')

    def test_marker_is_never_rearmed_during_automatic_recovery(self):
        r = Mock()
        state = {'enabled': True, 'count': 0}
        hs.arm_once(r, 'marker', state)
        hs.arm_once(r, 'marker', state)
        self.assertEqual(state['count'], 1)
        r.write_file.assert_called_once()

    def test_host_identity_rejected_before_owner_commands(self):
        with patch.object(hs.os, 'getuid', return_value=1000), patch.object(hs.podman, 'OwnerRunner') as owner:
            with self.assertRaisesRegex(RuntimeError, 'controlled_lab_owner_required'):
                hs.local_owner()
            owner.assert_not_called()


class QuadletTests(unittest.TestCase):
    def test_endpoint_uses_supported_podman_arguments(self):
        source = '[Container]\nNetwork=none\nPodmanArgs=--memory=384m --cpus=1 --pids-limit=256\n'
        connected = hs.connected_quadlet(source, 'hs-test-abcd1234', '10.89.0.10')
        self.assertIn('Network=hs-test-abcd1234\n', connected)
        self.assertIn('PodmanArgs=--network-alias=headscale.lab --ip=10.89.0.10 --memory=384m --cpus=1 --pids-limit=256\n', connected)
        self.assertNotIn('\nNetworkAlias=', connected)
        self.assertNotIn('\nIP=', connected)
        self.assertNotIn('PublishPort=', connected)


class InputTests(unittest.TestCase):
    def setUp(self):
        # Fixed-shape random synthetic path; never contains production credentials.
        self.root = Path('/tmp/headscale-internal.' + os.urandom(4).hex())
        self.root.mkdir(mode=0o700)
        self.addCleanup(__import__('shutil').rmtree, self.root)
        suffix = self.root.name.rsplit('.', 1)[1]
        self.target, self.plane = 'hs-target-' + suffix, 'hs-plane-' + suffix
        for rel in ('target-initial-private.tar', 'config/config.yaml',
                    'converted-output/volumes/' + self.target + '.tar',
                    'converted-output/volumes/' + self.plane + '.tar'):
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture')

    def test_synthetic_paths_valid(self):
        self.assertEqual(len(hs.inputs(self.root, self.target, self.plane)), 4)

    def test_original_volume_name_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'unexpected_source_names'):
            hs.inputs(self.root, 'headscale-data', self.plane)

    def test_missing_candidate_rejected(self):
        (self.root / 'converted-output/volumes' / (self.target + '.tar')).unlink()
        with self.assertRaisesRegex(RuntimeError, 'invalid_candidate_file'):
            hs.inputs(self.root, self.target, self.plane)

    def test_symlink_candidate_rejected(self):
        path = self.root / 'target-initial-private.tar'
        path.unlink()
        path.symlink_to(self.root / 'config/config.yaml')
        with self.assertRaisesRegex(RuntimeError, 'invalid_candidate_file'):
            hs.inputs(self.root, self.target, self.plane)

    def test_nonprivate_root_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, 'private_root_required'):
            hs.inputs(self.root, self.target, self.plane)


class IdentityTests(unittest.TestCase):
    def make_tar(self, root, *, key='node-a', noise=b'synthetic-noise', mode=0o640, uid=0, gid=0):
        import sqlite3, tarfile, io
        db = root / 'db.sqlite'
        db.unlink(missing_ok=True)
        with sqlite3.connect(db) as c:
            c.execute('CREATE TABLE nodes(id INTEGER,node_key TEXT,machine_key TEXT,ipv4 TEXT,ipv6 TEXT)')
            c.executemany('INSERT INTO nodes VALUES(?,?,?,?,?)',
                          [(1,key,'machine-a','100.64.0.1','fd00::1'),
                           (2,'node-b','machine-b','100.64.0.2','fd00::2')])
        out = root / ('archive-' + os.urandom(4).hex() + '.tar')
        with tarfile.open(out, 'w') as tar:
            for name, data in [('db.sqlite', db.read_bytes()), ('noise.key', noise), ('plane-marker', b'marker')]:
                item = tarfile.TarInfo(name)
                item.size, item.mode, item.uid, item.gid = len(data), mode, uid, gid
                tar.addfile(item, io.BytesIO(data))
        return out

    def test_two_nodes_with_different_identity_are_not_equal(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            before = hs.archive_summary(self.make_tar(root), headscale=True)
            after = hs.archive_summary(self.make_tar(root, key='replacement'), headscale=True)
            self.assertNotEqual(before, after)

    def test_noise_change_is_detected_without_disclosing_it(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            before = hs.archive_summary(self.make_tar(root), headscale=True)
            after = hs.archive_summary(self.make_tar(root, noise=b'changed-noise'), headscale=True)
            self.assertNotEqual(before, after)
            self.assertNotIn('synthetic-noise', repr(before))

    def test_plane_mode_owner_group_and_content_participate(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            before = hs.archive_summary(self.make_tar(root))
            for kw in ({'mode':0o600}, {'uid':1}, {'gid':1}, {'noise':b'changed'}):
                self.assertNotEqual(before, hs.archive_summary(self.make_tar(root, **kw)))

    def test_same_identity_is_stable(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.assertEqual(hs.archive_summary(self.make_tar(root), headscale=True),
                             hs.archive_summary(self.make_tar(root), headscale=True))


if __name__ == '__main__':
    unittest.main()
