"""Effective ACL source classification; no real host files or broker are accessed."""
import unittest
from woowbackup import ha_emqx
from woowbackup.errors import BackupError

class EffectiveAclTests(unittest.TestCase):
    def test_volume_acl_and_existing_readonly_file_mount(self):
        auth = {'sources': [{'type': 'file', 'path': '/opt/emqx/data/authz/custom.acl'},
                            {'type': 'file', 'path': '/opt/emqx/etc/acl.conf'}]}
        mounts = [('/fixture/acl.conf', '/opt/emqx/etc/acl.conf', 'ro')]
        self.assertEqual(ha_emqx.authorization_file_references(auth, mounts),
                         {'configs/cluster.hocon', 'authz/custom.acl'})

    def test_unresolved_unsafe_and_unsupported_sources_fail_closed(self):
        for source, mounts in [
            ({'type': 'file', 'path': '/opt/emqx/data/authz/../escape'}, []),
            ({'type': 'file', 'path': '/opt/emqx/etc/acl.conf'}, []),
            ({'type': 'file', 'path': '/opt/emqx/etc/acl.conf'}, [('/fixture/acl', '/opt/emqx/etc/acl.conf', 'rw')]),
            ({'type': 'file', 'path': 'authz/custom.acl'}, []),
            ({'type': 'redis'}, []),
            ({'type': 'file', 'path': ''}, []),
        ]:
            with self.subTest(source=source, mounts=mounts):
                with self.assertRaises(BackupError):
                    ha_emqx.authorization_file_references({'sources': [source]}, mounts)

class CandidateWiringTests(unittest.TestCase):
    def test_effective_acl_drives_snapshot_before_candidate(self):
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        target = SimpleNamespace(data_volume='fixture-volume', files=[])
        auth = {'sources': [{'type': 'file', 'path': '/opt/emqx/data/authz/custom.acl'}]}
        snapshot = Path('/fixture/private-snapshot.tar')
        with patch.object(ha_emqx, 'snapshot_target_volume', return_value=snapshot) as stage, \
             patch.object(ha_emqx, 'target_broker', return_value='candidate') as broker:
            result = ha_emqx.candidate_with_effective_acl('work', 'app', 'tmp', target, Path('/fixture'),
                                                           'export', (1, 2), auth)
        self.assertEqual(result, 'candidate')
        self.assertEqual(stage.call_args.args[-1], {'configs/cluster.hocon', 'authz/custom.acl'})
        self.assertEqual(broker.call_args.kwargs['target_snapshot'], snapshot)

    def test_unresolved_reference_stops_before_snapshot_and_broker(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        target = SimpleNamespace(data_volume='fixture-volume', files=[])
        auth = {'sources': [{'type': 'file', 'path': '/outside/acl'}]}
        with patch.object(ha_emqx, 'snapshot_target_volume') as stage, \
             patch.object(ha_emqx, 'target_broker') as broker:
            with self.assertRaises(BackupError):
                ha_emqx.candidate_with_effective_acl(None, None, None, target, None, None, None, auth)
        stage.assert_not_called()
        broker.assert_not_called()
