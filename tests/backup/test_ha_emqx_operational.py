"""Operational preservation through candidate entry (fixture transport)."""
import copy
import unittest
from woowbackup.errors import BackupError
from woowbackup import ha_emqx
from . import test_ha_emqx_candidate_flow as flow


def operational():
    return {'node': {'name': 'emqx@127.0.0.1', 'data_dir': '/opt/emqx/data',
                     'config_files': ['/opt/emqx/etc/emqx.conf'], 'crash_dump_file': '${EMQX_LOG_DIR}/erl_crash.dump'},
            'rpc': {'protocol': 'tcp', 'mode': 'async'},
            'cluster': {'discovery_strategy': 'manual', 'proto_dist': 'inet_tcp'},
            'log': {'console': {'enable': True}, 'file': {'default': {'enable': True, 'path': '${EMQX_LOG_DIR}/emqx.log'}}},
            'banned': {}}


class OperationalTests(unittest.TestCase):
    def invoke(self, transport):
        transport.config.update(operational())
        transport.running_config = copy.deepcopy(transport.config)
        return flow.CandidateFlowTests.invoke(self, transport)

    def test_operational_roots_retained(self):
        transport = flow.Transport()
        self.invoke(transport)
        for root, value in operational().items():
            self.assertEqual(transport.running_config[root], value)
        self.assertFalse(set(transport.restore) & {'node', 'rpc', 'cluster'})

    def test_log_changes_restore_without_writing_immutable_roots(self):
        class ChangeLog(flow.Transport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['log']['console']['enable'] = False
                return result
        transport = ChangeLog()
        self.invoke(transport)
        self.assertEqual(transport.restore['log'], operational()['log'])
        self.assertFalse(set(transport.restore) & {'node', 'rpc', 'cluster'})

    def test_immutable_change_stops_before_restore_command(self):
        for root in ('node', 'rpc', 'cluster'):
            class ChangeImmutable(flow.Transport):
                def exec(self, role, command, **kwargs):
                    result = super().exec(role, command, **kwargs)
                    if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                        self.running_config[root]['unexpected'] = True
                    return result
            with self.subTest(root=root):
                transport = ChangeImmutable()
                with self.assertRaises(BackupError):
                    self.invoke(transport)
                self.assertNotIn('restore', transport.events)

    def test_unreviewed_paths_discovery_and_tls_refused(self):
        cases = [('node', {'data_dir': '/outside'}),
                 ('node', {'data_dir': 'data', 'config_files': ['/outside/config']}),
                 ('cluster', {'discovery_strategy': 'k8s'}),
                 ('rpc', {'protocol': 'ssl'}),
                 ('log', {'file': {'default': {'path': '/opt/emqx/log/../../outside'}}}),
                 ('banned', {'bootstrap_file': '/outside/banned.csv'})]
        for root, value in cases:
            with self.subTest(root=root):
                config = {'authorization': {'sources': []}, root: value}
                with self.assertRaises(BackupError):
                    ha_emqx.configuration_references(config, [])

    def test_banned_file_collected_and_mount_resolved(self):
        config = {'authorization': {'sources': []}, 'banned': {'bootstrap_file': '/opt/emqx/data/configs/banned.csv'}}
        self.assertIn('configs/banned.csv', ha_emqx.configuration_references(config, []))
        config['banned']['bootstrap_file'] = '/opt/emqx/etc/banned.csv'
        mounts = [('/fixture/banned.csv', '/opt/emqx/etc/banned.csv', 'ro')]
        self.assertEqual(ha_emqx.configuration_references(config, mounts), {'configs/cluster.hocon'})

    def test_passive_targets_allow_ha_data_roots_to_arrive(self):
        class ImportData(flow.Transport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['rule_engine']['rules'] = {'from-ha': {'enable': True}}
                return result
        transport = ImportData()
        values = {key: {} for key in ('actions', 'sources', 'connectors', 'bridges', 'gateway')}
        values.update({'rewrite': [], 'topic_metrics': [], 'auto_subscribe': {'topics': []},
                       'exhook': {'servers': []}, 'psk_authentication': {'enable': False},
                       'plugins': {'states': [], 'install_dir': 'plugins'}, 'rule_engine': {'rules': {}},
                       'crl_cache': {'refresh_interval': '15m', 'http_timeout': '15s', 'capacity': 100}})
        transport.config.update(values)
        self.invoke(transport)
        self.assertIn('from-ha', transport.running_config['rule_engine']['rules'])
        self.assertNotIn('rule_engine', transport.restore)

    def test_active_unreviewed_targets_remain_blocked(self):
        values = {'connectors': {'http': {'active': {}}}, 'gateway': {'mqttsn': {}},
                  'plugins': {'states': [{'name_vsn': 'plugin'}], 'install_dir': 'plugins'},
                  'psk_authentication': {'enable': True}, 'exhook': {'servers': [{'url': 'example'}]},
                  'rule_engine': {'rules': {'active': {}}}}
        for root, value in values.items():
            with self.subTest(root=root):
                with self.assertRaises(BackupError):
                    ha_emqx.configuration_references({'authorization': {'sources': []}, root: value}, [])

    def test_local_monitoring_retained_through_candidate(self):
        transport = flow.Transport()
        values = {'limiter': {'bytes': {'rate': 'infinity', 'burst': '0'}},
                  'prometheus': {'push_gateway': {'enable': False}},
                  'sysmon': {'top': {'db_hostname': ''}},
                  'durable_sessions': {'enable': False, 'force_persistence': False},
                  'durable_storage': {'messages': {'backend': 'builtin_local',
                     'layout': {'type': 'wildcard_optimized_v2'}}}, 'api_key': {'bootstrap_file': ''}}
        transport.config.update(values)
        self.invoke(transport)
        for key, value in values.items():
            self.assertEqual(transport.running_config[key], value)

    def test_monitoring_unknown_files_and_active_backends_refused(self):
        values = [('limiter', {'client': {}}), ('prometheus', {'enable': True}),
                  ('prometheus', {'push_gateway': {'enable': True}}),
                  ('sysmon', {'top': {'db_hostname': 'outside'}}),
                  ('durable_sessions', {'enable': True}),
                  ('durable_storage', {'messages': {'backend': 'builtin_raft'}}),
                  ('durable_storage', {'messages': {'backend': 'builtin_local', 'data_dir': '/outside'}}),
                  ('api_key', {'bootstrap_file': '/outside/keys'})]
        for root, value in values:
            with self.subTest(root=root, fields=list(value)):
                config = {'authorization': {'sources': []}, 'durable_sessions': {'enable': False}, root: value}
                with self.assertRaises(BackupError):
                    ha_emqx.configuration_references(config, [])

    def test_api_key_bootstrap_reference_is_required(self):
        config = {'authorization': {'sources': []}, 'api_key': {'bootstrap_file': '/opt/emqx/data/configs/api.txt'}}
        self.assertIn('configs/api.txt', ha_emqx.configuration_references(config, []))

    def test_internal_entry_refuses_unknown_version_before_creating_resources(self):
        from types import SimpleNamespace
        work = SimpleNamespace(addon_info=lambda slug: SimpleNamespace(version='unreviewed'))
        with self.assertRaises(BackupError) as caught:
            ha_emqx._build_candidate(work, SimpleNamespace(id='emqx'), None, None, None, version='5.8.9')
        self.assertEqual(caught.exception.code, 'incompatible')

    def test_disabled_durable_storage_accepts_absent_lazy_defaults(self):
        config = {'authorization': {'sources': []}, 'durable_sessions': {'enable': False}, 'durable_storage': {}}
        self.assertEqual(ha_emqx.configuration_references(config, []), {'configs/cluster.hocon'})
        config['durable_sessions']['enable'] = True
        with self.assertRaises(BackupError):
            ha_emqx.configuration_references(config, [])

    def test_image_tls_matches_before_and_after_candidate_import(self):
        class TLS(flow.Transport):
            def podman(self, *args, **kwargs):
                if args[2] == 'sha256sum':
                    return flow.Result(0, b'a' * 64 + b'  ' + args[3].encode() + b'\n', b'')
                return super().podman(*args, **kwargs)
            def exec(self, role, command, **kwargs):
                if command[0] == 'sha256sum':
                    self.events.append('tls-candidate')
                    return flow.Result(0, b'a' * 64 + b'  ' + command[1].encode() + b'\n', b'')
                return super().exec(role, command, **kwargs)
        transport = TLS()
        transport.config['dashboard'] = {'listeners': {'https': {'keyfile': '${EMQX_ETC_DIR}/certs/key.pem'}}}
        self.invoke(transport)
        self.assertEqual(transport.events.count('tls-candidate'), 2)
        self.assertLess(transport.events.index('tls-candidate'), transport.events.index('import'))
        self.assertGreater(len(transport.events) - 1 - transport.events[::-1].index('tls-candidate'),
                           transport.events.index('import'))

    def test_changed_image_tls_blocks_before_import(self):
        class TLS(flow.Transport):
            def podman(self, *args, **kwargs):
                if args[2] == 'sha256sum':
                    return flow.Result(0, b'a' * 64 + b'  ' + args[3].encode() + b'\n', b'')
                return super().podman(*args, **kwargs)
            def exec(self, role, command, **kwargs):
                if command[0] == 'sha256sum':
                    return flow.Result(0, b'b' * 64 + b'  ' + command[1].encode() + b'\n', b'')
                return super().exec(role, command, **kwargs)
        transport = TLS()
        transport.config['dashboard'] = {'listeners': {'https': {'certfile': '${EMQX_ETC_DIR}/certs/cert.pem'}}}
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertNotIn('import', transport.events)

    def test_image_tls_arbitrary_substitutions_and_paths_refused(self):
        for path in ('${OTHER}/certs/key.pem', '${EMQX_ETC_DIR}/certs/../key.pem',
                     '${EMQX_ETC_DIR}/certs/custom.pem'):
            config = {'authorization': {'sources': []}, 'dashboard': {'keyfile': path}}
            with self.assertRaises(BackupError):
                ha_emqx.configuration_references(config, [])

    def test_import_changed_tls_refused_at_readback(self):
        class TLS(flow.Transport):
            def podman(self, *args, **kwargs):
                if args[2] == 'sha256sum':
                    return flow.Result(0, b'a' * 64 + b'  ' + args[3].encode() + b'\n', b'')
                return super().podman(*args, **kwargs)
            def exec(self, role, command, **kwargs):
                if command[0] == 'sha256sum':
                    digest = b'b' if 'import' in self.events else b'a'
                    return flow.Result(0, digest * 64 + b'  ' + command[1].encode() + b'\n', b'')
                return super().exec(role, command, **kwargs)
        transport = TLS()
        transport.config['dashboard'] = {'listeners': {'https': {'certfile': '${EMQX_ETC_DIR}/certs/cert.pem'}}}
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertIn('import', transport.events)
