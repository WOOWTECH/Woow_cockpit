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
        """E-25's rule: a file source without a path, with a path that is no text or with an absurd one is an answer that
        cannot be read."""
        for source, mounts in [
            ({'type': 'file', 'path': ''}, []),
            ({'type': 'file', 'path': [47, 0, 120]}, []),
            ({'type': 'file', 'path': list(range(1, 128)) * 40}, []),
        ]:
            with self.subTest(source=source, mounts=mounts):
                with self.assertRaises(BackupError):
                    ha_emqx.authorization_file_references({'sources': [source]}, mounts)

    def test_a_path_that_is_not_in_the_data_volume_is_no_longer_a_stop(self):
        """E-29, E-30 (HAOS parity, EMQX-B): the generic scan names what it cannot place (a `..`) and leaves the rest -- a mount,
        the image's own place, a relative path of the broker's working folder -- to the candidate, which has them as this device
        has."""
        for path, mounts, named in [
            ('/opt/emqx/data/authz/../escape', [], {'authorization.sources.path'}),
            ('/opt/emqx/etc/acl.conf', [], set()),
            ('/opt/emqx/etc/acl.conf', [('/fixture/acl', '/opt/emqx/etc/acl.conf', 'rw')], set()),
            ('authz/custom.acl', [], set()),
        ]:
            with self.subTest(path=path, mounts=mounts):
                found = {}
                self.assertEqual(ha_emqx.authorization_file_references({'sources': [{'type': 'file', 'path': path}]}, mounts,
                                                                       found=found), {'configs/cluster.hocon'})
                self.assertEqual(found['not_carried'], named)

    def test_sources_of_other_types_carry_no_file_of_their_own(self):
        """E-26, E-27: HA's authorization replaces this device's; a source that is no file names nothing to snapshot."""
        for source in ({'type': 'redis'}, {'type': 'built_in_database', 'enable': True, 'max_rules': 7}, {'type': 'http'}):
            self.assertEqual(ha_emqx.authorization_file_references({'sources': [source]}, []), {'configs/cluster.hocon'})
        for bad in ({'sources': 'x'}, {'sources': [1]}, {}, None):
            with self.subTest(bad=bad), self.assertRaises(BackupError):
                ha_emqx.authorization_file_references(bad, [])

    def test_a_path_EMQX_made_of_character_codes_is_the_same_path(self):
        """E-28: a path the broker holds as a list of ASCII codes (an ACL file written from the Dashboard)."""
        path = [ord(char) for char in '/opt/emqx/data/authz/acl.conf']
        self.assertEqual(ha_emqx.ascii_path(path), '/opt/emqx/data/authz/acl.conf')
        self.assertEqual(ha_emqx.authorization_file_references({'sources': [{'type': 'file', 'path': path}]}, []),
                         {'configs/cluster.hocon', 'authz/acl.conf'})
        for other in (None, 5, [], [0], [200], ['x'], {}):
            self.assertIsNone(ha_emqx.ascii_path(other))


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
        """A file source that has no path (an answer that cannot be read) stops before anything is snapshotted or started."""
        from types import SimpleNamespace
        from unittest.mock import patch
        target = SimpleNamespace(data_volume='fixture-volume', files=[])
        auth = {'sources': [{'type': 'file', 'path': ''}]}
        with patch.object(ha_emqx, 'snapshot_target_volume') as stage, \
             patch.object(ha_emqx, 'target_broker') as broker:
            with self.assertRaises(BackupError):
                ha_emqx.candidate_with_effective_acl(None, None, None, target, None, None, None, auth)
        stage.assert_not_called()
        broker.assert_not_called()
