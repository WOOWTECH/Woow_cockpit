"""Roots the engine used to review by lists (alarm, slow_subs, trace, crl_cache, telemetry, delayed, overload_protection, and
every root it had never heard of) through the internal candidate, using fixture transport. HAOS parity (lane EMQX-B, rows E-32,
E-33, E-34, E-50): an unlisted field, a field of an unusual shape or a root of a kind the engine has no list for stops nothing;
the candidate starts with this device's configuration as it is and the settings come back unchanged (the comparison after
the import proves it), and every setting is scanned for the files it names (ha_emqx.file_scan): one in the data volume is
carried wherever it is, one in the image or on a mount needs nothing, one nobody can place is only said."""
import copy
import io
import tarfile
import unittest
from woowbackup.errors import BackupError
from . import test_ha_emqx_candidate_flow as flow


class FilesTransport(flow.Transport):
    """The generated transport whose export of this device's data volume also holds `extra_files` ({name: bytes})."""
    extra_files = {}

    def relay(self, args, stdout, **kwargs):
        assert args == ['volume', 'export', 'fixture-data']
        self.events.append('export')
        files = {'configs/cluster.hocon': b'custom target configuration', 'authz/custom.acl': b'{deny, all}.',
                 'certs/lab.pem': b'fixture-only'}
        files.update(self.extra_files)
        with tarfile.open(fileobj=stdout, mode='w|') as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))


class FilelessRootsTests(unittest.TestCase):
    def invoke(self, transport, notes=None):
        return flow.CandidateFlowTests.invoke(self, transport, notes=notes)

    def test_reviewed_roots_survive_import_and_restore(self):
        class ChangedRoot(flow.Transport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['alarm']['size_limit'] = 1
                    self.running_config['rule_engine'] = {'rules': {'ha': {}}}
                return result
        transport = ChangedRoot()
        roots = {'alarm': {'actions': ['log'], 'size_limit': 200, 'validity_period': '24h'},
                 'slow_subs': {'enable': False, 'threshold': '500ms', 'expire_interval': '300s',
                               'top_k_num': 10, 'stats_type': 'whole'},
                 'trace': {'payload_encode': 'hidden'}}
        transport.config.update(roots)
        transport.running_config = copy.deepcopy(transport.config)
        self.invoke(transport)
        for root in roots:
            self.assertEqual(transport.running_config[root], roots[root])
        self.assertIn('ha', transport.running_config['rule_engine']['rules'])

    def test_an_unlisted_field_or_shape_is_no_reason_to_stop(self):
        """E-33, E-34: the old lists of fields (alarm, slow_subs, trace, crl_cache, telemetry, delayed, overload_protection)
        refused a field they did not know or a value of another shape; the settings are this device's own, they come back
        exactly as they were and the comparison after the import says whether they did."""
        cases = {'alarm': {'path': '/outside/file', 'actions': ['shell']},
                 'trace': {'payload_encode': {'file': '/outside', 'nested': [1, {'x': None}]}},
                 'slow_subs': {'enable': False, 'something_new': {'a': [1, 2, 3]}},
                 'telemetry': {'enable': False, 'file': '/outside/unreviewed'},
                 'delayed': {'enable': True, 'max_delayed_messages': [1]},
                 'overload_protection': {'enable': False, 'backoff_new_conn': 'maybe', 'extra': True},
                 'crl_cache': {'refresh_interval': '15m', 'capacity': 100, 'url': 'http://crl.example/'}}
        for root, value in cases.items():
            with self.subTest(root=root):
                transport = flow.Transport()
                transport.config[root] = value
                transport.running_config = copy.deepcopy(transport.config)
                notes = {}
                self.assertEqual(len(self.invoke(transport, notes=notes)), 4)
                self.assertIn('export', transport.events)
                self.assertIn('import', transport.events)
                self.assertEqual(transport.running_config[root], value, 'this device\'s setting is back as it was')
                self.assertEqual(notes['unreached'], [], 'nothing it names is a file nobody can place')

    def test_additional_default_roots_are_restored(self):
        class ChangedDefault(flow.Transport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['delayed']['max_delayed_messages'] = 999
                return result
        transport = ChangedDefault()
        roots = {'telemetry': {'enable': False}, 'delayed': {'enable': True, 'max_delayed_messages': 10},
                 'overload_protection': {'enable': False, 'backoff_delay': 1, 'backoff_gc': False,
                                         'backoff_hibernation': True, 'backoff_new_conn': True}}
        transport.config.update(roots)
        transport.running_config = copy.deepcopy(transport.config)
        self.invoke(transport)
        for key, value in roots.items():
            self.assertEqual(transport.running_config[key], value)

    def test_a_root_the_engine_never_heard_of_goes_through_and_its_file_in_the_data_volume_is_carried(self):
        """E-32, E-50: no list of roots any more; whatever root names a file in the data volume gets it into the candidate."""
        transport = FilesTransport()
        transport.extra_files = {'certs/otel/ca.pem': b'ca', 'extra/keys/client.key': b'key'}
        transport.config['opentelemetry'] = {'exporter': {'endpoint': 'http://collector:4317',
                                                           'ssl_options': {'cacertfile': '/opt/emqx/data/certs/otel/ca.pem'}}}
        transport.config['future_root'] = {'deep': [{'keyfile': 'data/extra/keys/client.key'}]}
        transport.running_config = copy.deepcopy(transport.config)
        notes = {}
        self.invoke(transport, notes=notes)
        self.assertEqual(transport.seed['certs/otel/ca.pem'], b'ca')
        self.assertEqual(transport.seed['extra/keys/client.key'], b'key', 'a place the old lists never allowed')
        for root in ('opentelemetry', 'future_root'):
            self.assertEqual(transport.running_config[root], transport.config[root])
        self.assertEqual((notes['missing'], notes['unreached']), ([], []))

    def test_a_file_in_the_image_or_on_a_mount_is_the_candidates_too_and_said_nowhere(self):
        """E-50: found automatically; nothing to carry, nothing to say."""
        transport = FilesTransport()
        transport.config['alarm'] = {'actions': ['log'], 'cacertfile': '/etc/ssl/certs/ca-certificates.crt',
                                     'init_file': '${EMQX_ETC_DIR}/psk.txt', 'filename': '/opt/emqx/etc/acl.conf'}
        transport.running_config = copy.deepcopy(transport.config)
        notes = {}
        self.invoke(transport, notes=notes)
        self.assertEqual(notes['unreached'], [])
        self.assertNotIn('etc/ssl/certs/ca-certificates.crt', transport.seed)
        self.assertEqual(set(transport.seed), {'configs/cluster.hocon', 'authz/custom.acl', 'certs/lab.pem'})

    def test_a_file_nobody_can_place_is_named_and_the_import_goes_on(self):
        """E-50: an environment variable the broker would not resolve, a `..`, a place that exists only while a broker runs: the
        setting is named in the notes (setting names, never a path), nothing is refused."""
        transport = FilesTransport()
        transport.config['alarm'] = {'actions': ['log'], 'cacertfile': '${NOT_SET_ANYWHERE}/ca.pem',
                                     'keyfile': '/opt/emqx/data/../outside/key.pem', 'certfile': '/proc/self/environ',
                                     'init_file': '/tmp/runtime.txt'}
        transport.running_config = copy.deepcopy(transport.config)
        notes = {}
        self.assertEqual(len(self.invoke(transport, notes=notes)), 4)
        self.assertEqual(notes['unreached'], ['alarm.cacertfile', 'alarm.certfile', 'alarm.init_file', 'alarm.keyfile'])
        self.assertIn('import', transport.events)
        self.assertNotIn('/proc', ' '.join(notes['unreached']), 'names of settings, not the paths')

    def test_a_file_the_volume_lacks_is_said_not_refused(self):
        """E-50 with E-55: a data-volume file the settings name that is not in the volume is this device's own hole."""
        transport = FilesTransport()
        transport.config['alarm'] = {'actions': ['log'], 'certfile': '/opt/emqx/data/certs/never-uploaded.pem'}
        transport.running_config = copy.deepcopy(transport.config)
        notes = {}
        self.assertEqual(len(self.invoke(transport, notes=notes)), 4)
        self.assertEqual(notes['missing'], ['certs/never-uploaded.pem'])

    def test_what_stays_a_stop_stops_only_this_app_before_anything_is_exported(self):
        """The scan's own limit (nesting deeper than 32 levels) and a configuration that is no authorization stay stops."""
        deep = value = {}
        for _ in range(40):
            value['x'] = {}
            value = value['x']
        transport = flow.Transport()
        transport.config['alarm'] = {'actions': ['log'], 'nested': deep}
        transport.running_config = copy.deepcopy(transport.config)
        with self.assertRaises(BackupError) as caught:
            self.invoke(transport)
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertNotIn('export', transport.events)
        self.assertNotIn('start', transport.events)

    def test_new_roots_accept_unreviewed_fields(self):
        for root in ('telemetry', 'delayed', 'overload_protection'):
            with self.subTest(root=root):
                transport = flow.Transport()
                transport.config[root] = {'file': '/outside/unreviewed'}
                transport.running_config = copy.deepcopy(transport.config)
                self.invoke(transport)
                self.assertIn('export', transport.events)
                self.assertEqual(transport.running_config[root], {'file': '/outside/unreviewed'})


if __name__ == '__main__':
    unittest.main()
