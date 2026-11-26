"""Operational preservation through candidate entry (fixture transport). HAOS parity (lane EMQX-B): this device's own settings
are no longer judged against reviewed lists (E-23, E-24, E-29, E-30, E-32..E-37, E-39, E-40, E-45, E-46, E-50): the candidate
starts with them as they are, every setting is scanned for the files it names, a data directory that is not the image's (E-36)
and a place for logs the candidate cannot be given (E-35) are what is left to stop one app; what this device has of its own
that HA's import is mixed with -- rules, connectors, rewrite, PSK, plugins, durable sessions -- is named in the one
confirmation (E-41, E-42, E-43, E-44, E-47)."""
import copy
import hashlib
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from woowbackup.errors import BackupError
from woowbackup import ha_emqx, ha_emqx_settings, haissues
from woowbackup.podman import Result
from . import test_ha_emqx as base
from . import test_ha_emqx_candidate_flow as flow
from . import test_ha_emqx_parity as parity


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
        self.assertFalse(set(getattr(transport, 'restore', {})) & {'node', 'rpc', 'cluster'})

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
        self.assertFalse(set(getattr(transport, 'restore', {})) & {'node', 'rpc', 'cluster'})

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

    def test_the_data_directory_is_the_images_in_every_form_it_is_written(self):
        """E-36: `data` (relative to /opt/emqx), its absolute form, with or without a slash or a leading `./`; nothing else."""
        for value in ('data', 'data/', './data', './data/', ' data ', '/opt/emqx/data', '/opt/emqx/data/'):
            self.assertTrue(ha_emqx_settings.is_data_dir(value), value)
        for value in ('/data', 'data2', 'elsewhere/data', '', '../data', '/opt/emqx/data/sub', '/opt/emqx', None, 5, ['data']):
            self.assertFalse(ha_emqx_settings.is_data_dir(value), value)

    def test_the_lab_harness_can_still_call_the_old_validators_and_none_of_them_refuses(self):
        """tests/e2e/lab/emqx_synthetic_preservation.py calls validate, validate_passive and validate_monitoring on the real
        device's roots: they exist, return and refuse nothing of what they refused (a clustered broker, E-38, is the one thing)."""
        config = {'node': {'data_dir': '/outside', 'unlisted': 1}, 'rpc': {'protocol': 'quic'}, 'log': {'file': 5},
                  'connectors': {'http': {'x': {}}}, 'prometheus': {'enable': True}, 'durable_sessions': {'enable': True}}
        self.assertIsNone(ha_emqx_settings.validate(config, []))
        self.assertEqual(ha_emqx_settings.validate_passive(config)['integrations'], ['connectors.http.x'])
        self.assertEqual(ha_emqx_settings.validate_monitoring(config)['durable'], ['durable_sessions'])
        with self.assertRaises(BackupError):
            ha_emqx_settings.validate({'cluster': {'discovery_strategy': 'etcd'}}, [])

    def test_what_the_old_lists_refused_goes_through_but_the_data_dir_and_the_cluster(self):
        """E-34, E-36, E-37, E-39, E-40, E-35, E-30: every one of these was a refusal ("超出已核對的支援範圍"); only a data
        directory that is not the image's (its own words and advice) and a clustered broker (E-38, not this lane's) stop."""
        for root, value in [('node', {'data_dir': 'data', 'config_files': ['/outside/config'], 'applications': ['x'],
                                      'etc_dir': '/custom/etc', 'shard_transports': {'a': 'new_transport'}, 'unlisted': 1,
                                      'cluster_call': {'retry_interval': '1s', 'future': True}}),
                            ('node', {'data_dir': '/opt/emqx/data/', 'crash_dump_file': '/opt/emqx/log/../../outside'}),
                            ('rpc', {'protocol': 'ssl'}), ('rpc', {'protocol': 'quic', 'unlisted': 1}),
                            ('log', {'file': {'default': {'path': '/opt/emqx/log/../../outside'}}}),
                            ('log', {'file': [], 'console': {'enable': True, 'unlisted': 1}}),
                            ('log', {'file': {'default': {'enable': True}}, 'throttling': {'msgs': 1, 'new': 2}}),
                            ('cluster', {'discovery_strategy': 'manual', 'static': {'seeds': [], 'new': 1}, 'unlisted': 2}),
                            ('banned', {'bootstrap_file': '/outside/banned.csv'}), ('banned', {'bootstrap_file': 7, 'x': 1}),
                            ('api_key', {'bootstrap_file': ['x'], 'extra': 1})]:
            with self.subTest(root=root, value=value):
                config = {'authorization': {'sources': []}, root: value}
                self.assertEqual(ha_emqx.configuration_references(config, []), {'configs/cluster.hocon'})
        for root, value, issue in [('node', {'data_dir': '/outside'}, 'emqx.data-dir-moved'),
                                   ('node', {'data_dir': 'elsewhere/data'}, 'emqx.data-dir-moved'),
                                   ('node', {'data_dir': None}, 'emqx.data-dir-moved'),
                                   ('cluster', {'discovery_strategy': 'k8s'}, None),
                                   ('cluster', {'discovery_strategy': 'manual', 'proto_dist': 'inet_tls'}, None)]:
            with self.subTest(root=root, value=value):
                with self.assertRaises(BackupError) as caught:
                    ha_emqx.configuration_references({'authorization': {'sources': []}, root: value}, [])
                self.assertEqual(caught.exception.code, 'incompatible')
                if issue:
                    [found] = caught.exception.issues
                    self.assertEqual((found.id, found.level), (issue, 'stop'))
                    self.assertIn('/opt/emqx/data', found.action)

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
        self.assertNotIn('rule_engine', getattr(transport, 'restore', {}))

    def test_this_devices_own_integrations_are_listed_by_name_not_refused(self):
        """E-41, E-42, E-43, E-44: what refused the import ("active, unreviewed") is named for the one confirmation."""
        values = {'connectors': {'http': {'active': {}}}, 'gateway': {'mqttsn': {}},
                  'plugins': {'states': [{'name_vsn': 'plugin-1.0.0'}], 'install_dir': 'plugins'},
                  'psk_authentication': {'enable': True}, 'exhook': {'servers': [{'url': 'example', 'name': 'hook'}]},
                  'rule_engine': {'rules': {'active': {}}}}
        for root, value in values.items():
            with self.subTest(root=root):
                config = {'authorization': {'sources': []}, root: value}
                self.assertEqual(ha_emqx.configuration_references(config, []), {'configs/cluster.hocon'})
        own = ha_emqx_settings.own_items({'authorization': {'sources': []}, **values})
        self.assertEqual(own['integrations'], ['connectors.http.active', 'gateway.mqttsn', 'rule_engine.rules.active'])
        self.assertEqual(own['routing'], ['exhook.hook'])
        self.assertEqual(own['psk'], ['psk_authentication'])
        self.assertEqual(own['plugins'], ['plugins.plugin-1.0.0'])
        self.assertEqual(own['durable'], [])

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

    def test_monitoring_settings_are_never_judged(self):
        """E-45, E-46, E-47, E-34: exporters, the system monitor's database, unlisted limiter fields and any storage backend
        are this device's own settings; the candidate (no network) cannot reach what they point to, which harms no data."""
        values = [('limiter', {'client': {}}), ('prometheus', {'enable': True}),
                  ('prometheus', {'push_gateway': {'enable': True, 'url': 'http://gateway:9091'}}),
                  ('sysmon', {'top': {'db_hostname': 'outside'}}),
                  ('durable_sessions', {'enable': True}),
                  ('durable_storage', {'messages': {'backend': 'builtin_raft'}}),
                  ('durable_storage', {'messages': {'backend': 'builtin_local', 'data_dir': '/outside'}})]
        for root, value in values:
            with self.subTest(root=root, fields=list(value)):
                config = {'authorization': {'sources': []}, 'durable_sessions': {'enable': False}, root: value}
                self.assertIsNotNone(ha_emqx.configuration_references(config, []))
        for root, value in (('limiter', {'client': {}}), ('prometheus', {'enable': True}),
                            ('sysmon', {'top': {'db_hostname': 'outside'}})):
            own = ha_emqx_settings.own_items({root: value})
            self.assertEqual([own[kind] for kind in ('integrations', 'routing', 'psk', 'plugins', 'durable')], [[]] * 5,
                             'nothing to confirm for them')

    def test_an_exporter_that_pushes_somewhere_does_not_stop_the_candidate(self):
        """E-45, E-46: Prometheus push and a system monitor database through the whole candidate; they come back as they were."""
        transport = flow.Transport()
        values = {'prometheus': {'enable': True, 'push_gateway': {'enable': True, 'url': 'http://gateway:9091'}},
                  'sysmon': {'top': {'db_hostname': 'metrics.example', 'db_port': 5432}}}
        transport.config.update(values)
        transport.running_config = copy.deepcopy(transport.config)
        self.invoke(transport)
        self.assertIn('import', transport.events)
        for key, value in values.items():
            self.assertEqual(transport.running_config[key], value)

    def test_api_key_bootstrap_reference_is_required(self):
        config = {'authorization': {'sources': []}, 'api_key': {'bootstrap_file': '/opt/emqx/data/configs/api.txt'}}
        self.assertIn('configs/api.txt', ha_emqx.configuration_references(config, []))

    def test_a_build_with_nothing_to_stage_creates_nothing_for_a_node_that_is_unsupported(self):
        """The version is judged before the build (version_lines: it only informs, HAOS parity); the build itself refuses
        what the data cannot do without -- a node name EMQX would not take -- before it creates any resource."""
        from types import SimpleNamespace
        from unittest.mock import patch
        src = ha_emqx.Source()
        src.node_dirs = {'bad node@127.0.0.1'}
        work = SimpleNamespace(phase=lambda _: None, choice=lambda *_: None, sink=lambda app: haissues.Sink(app.id))
        with patch.object(ha_emqx, 'member_pass', return_value=src), patch.object(ha_emqx, 'ha_broker') as broker:
            with self.assertRaises(BackupError) as caught:
                ha_emqx._build_candidate(work, SimpleNamespace(id='emqx'), None, None, None, version='5.8.9')
        self.assertEqual(caught.exception.code, 'incompatible')
        broker.assert_not_called()

    def test_durable_storage_in_any_shape_is_no_refusal_and_enabled_sessions_are_named(self):
        """E-47: the lazy defaults of a disabled durable storage and an enabled one pass; the enabled sessions are what the
        customer confirms (their queued messages are not in HA's export)."""
        config = {'authorization': {'sources': []}, 'durable_sessions': {'enable': False}, 'durable_storage': {}}
        self.assertEqual(ha_emqx.configuration_references(config, []), {'configs/cluster.hocon'})
        self.assertEqual(ha_emqx_settings.own_items(config)['durable'], [])
        config['durable_sessions']['enable'] = True
        self.assertEqual(ha_emqx.configuration_references(config, []), {'configs/cluster.hocon'})
        self.assertEqual(ha_emqx_settings.own_items(config)['durable'], ['durable_sessions'])
        self.assertEqual(ha_emqx_settings.own_items({'durable_sessions': {'force_persistence': True}})['durable'],
                         ['durable_sessions'])

    def test_image_tls_matches_before_and_after_candidate_import(self):
        class TLS(flow.Transport):
            def podman(self, *args, **kwargs):
                if args[2] == 'sha256sum':
                    return flow.Result(0, b'a' * 64 + b'  ' + args[3].encode() + b'\n', b'')
                return super().podman(*args, **kwargs)
            def exec(self, role, command, **kwargs):
                if command[0] == 'sha256sum' and not command[1].startswith('/opt/emqx/data/'):
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
                if command[0] == 'sha256sum' and not command[1].startswith('/opt/emqx/data/'):
                    return flow.Result(0, b'b' * 64 + b'  ' + command[1].encode() + b'\n', b'')
                return super().exec(role, command, **kwargs)
        transport = TLS()
        transport.config['dashboard'] = {'listeners': {'https': {'certfile': '${EMQX_ETC_DIR}/certs/cert.pem'}}}
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertNotIn('import', transport.events)

    def test_image_tls_arbitrary_substitutions_and_paths_are_named_not_refused(self):
        """E-30: a variable the broker would not resolve, a `..`, another file of the image: none is a certificate this engine
        fingerprints (only the image's three are: IMAGE_TLS_FILES) and none stops anything; the ones nobody can place are
        named, the rest is the candidate's the way it is this device's."""
        found = {}
        for path in ('${OTHER}/certs/key.pem', '${EMQX_ETC_DIR}/certs/../key.pem'):
            config = {'authorization': {'sources': []}, 'dashboard': {'keyfile': path}}
            found.clear()
            self.assertEqual(ha_emqx.configuration_references(config, [], found=found), {'configs/cluster.hocon'}, path)
            self.assertEqual(found['not_carried'], {'dashboard.keyfile'}, path)
        config = {'authorization': {'sources': []}, 'dashboard': {'keyfile': '${EMQX_ETC_DIR}/certs/custom.pem'}}
        found.clear()
        self.assertEqual(ha_emqx.configuration_references(config, [], found=found), {'configs/cluster.hocon'})
        self.assertEqual(found['not_carried'], set())
        self.assertEqual(ha_emqx.image_tls_references(config), set(), 'a certificate that is not one of the three is not fingerprinted')

    def test_import_changed_tls_refused_at_readback(self):
        class TLS(flow.Transport):
            def podman(self, *args, **kwargs):
                if args[2] == 'sha256sum':
                    return flow.Result(0, b'a' * 64 + b'  ' + args[3].encode() + b'\n', b'')
                return super().podman(*args, **kwargs)
            def exec(self, role, command, **kwargs):
                if command[0] == 'sha256sum' and not command[1].startswith('/opt/emqx/data/'):
                    digest = b'b' if 'import' in self.events else b'a'
                    return flow.Result(0, digest * 64 + b'  ' + command[1].encode() + b'\n', b'')
                return super().exec(role, command, **kwargs)
        transport = TLS()
        transport.config['dashboard'] = {'listeners': {'https': {'certfile': '${EMQX_ETC_DIR}/certs/cert.pem'}}}
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertIn('import', transport.events)


class ResolvePathTests(unittest.TestCase):
    """E-24, E-29, E-30, E-50: the ways a setting writes the place of a file, and what none of them can tell."""

    def test_the_ways_a_path_is_written(self):
        chars = [ord(char) for char in '/opt/emqx/data/authz/acl.conf']
        for value, want in [
                ('/opt/emqx/etc/acl.conf', '/opt/emqx/etc/acl.conf'), ('${EMQX_ETC_DIR}/acl.conf', '/opt/emqx/etc/acl.conf'),
                ('$EMQX_ETC_DIR/certs/cert.pem', '/opt/emqx/etc/certs/cert.pem'), ('${EMQX_ETC_DIR}', '/opt/emqx/etc'),
                ('${EMQX_ETC_DIR}//acl.conf', '/opt/emqx/etc/acl.conf'), ('${EMQX_LOG_DIR}/emqx.log', '/opt/emqx/log/emqx.log'),
                ('data/authz/acl.conf', '/opt/emqx/data/authz/acl.conf'), ('./data/authz/acl.conf', '/opt/emqx/data/authz/acl.conf'),
                ('etc//certs/./a.pem', '/opt/emqx/etc/certs/a.pem'), ('file:///opt/emqx/data/secret', '/opt/emqx/data/secret'),
                ('file://data/secret', '/opt/emqx/data/secret'), (chars, '/opt/emqx/data/authz/acl.conf'),
                ('/var/log/emqx/', '/var/log/emqx')]:
            with self.subTest(value=value):
                self.assertEqual(ha_emqx.resolve_path(value), want)

    def test_this_devices_own_folders_and_variables(self):
        self.assertEqual(ha_emqx.resolve_path('${EMQX_ETC_DIR}/acl.conf', etc_dir='/custom/etc'), '/custom/etc/acl.conf')
        self.assertEqual(ha_emqx.resolve_path('${EMQX_LOG_DIR}/x.log', log_dir='/var/log/emqx/'), '/var/log/emqx/x.log')
        self.assertEqual(ha_emqx.resolve_path('${MY_DIR}/f', env={'MY_DIR': '/srv/x'}), '/srv/x/f')
        for value in ('${EMQX_ETC_DIR}/acl.conf', '${MY_DIR}/f'):
            self.assertIsNone(ha_emqx.resolve_path(value, etc_dir=None, env={'MY_DIR': 'relative'}), 'a variable that is no folder')
        self.assertIsNone(ha_emqx.resolve_path('${MY_DIR}/f', env={'MY_DIR': '/srv/$X'}))

    def test_what_nobody_can_tell(self):
        for value in ('', '$', '${}', '${EMQX_ETC_DIR', '${NOPE}/x', '$NOPE/x', '/opt/emqx/data/../x', '..', '/', 'a\x00b',
                      'a\\b', 'a\nb', '/' + 'x' * 5000, None, 5, [], [0], [200], ['x'], {}, b'/x'):
            with self.subTest(value=value):
                self.assertIsNone(ha_emqx.resolve_path(value))

    def test_the_etc_folder_of_the_running_broker_is_whatever_it_says_when_it_is_a_plain_folder(self):
        """E-24: it was `/opt/emqx/etc` or a stop; now the broker's own answer is the one `${EMQX_ETC_DIR}` means."""
        from woowbackup.podman import Result
        answer = lambda raw, code=0: (lambda _command: Result(code, raw, b''))
        self.assertEqual(ha_emqx.target_etc_dir(answer(b'WOOWETC:/opt/emqx/etc:ENDok\n')), '/opt/emqx/etc')
        self.assertEqual(ha_emqx.target_etc_dir(answer(b'WOOWETC:/custom/etc/:ENDok\n')), '/custom/etc')
        self.assertEqual(ha_emqx.target_etc_dir(answer(b'WOOWETC::ENDok\n')), '/opt/emqx/etc', 'not set: the image\'s')
        for raw, code in ((b'garbage', 0), (b'WOOWETC:/custom/etc:ENDok', 1), (b'', 0), (b'WOOWETC:relative/etc:ENDok', 0),
                          (b'WOOWETC:/a/../etc:ENDok', 0), (b'WOOWETC:/a/$HOME:ENDok', 0), (b'WOOWETC:/a\nb:ENDok', 0),
                          (b'WOOWETC:/' + b'x' * 2000 + b':ENDok', 0)):
            with self.subTest(raw=raw[:30]), self.assertRaises(BackupError) as caught:
                ha_emqx.target_etc_dir(answer(raw, code))
            self.assertEqual(caught.exception.code, 'incompatible')


class FileScanTests(unittest.TestCase):
    """E-29, E-30, E-32, E-35, E-36, E-50: every setting of every root is looked at for the files it names."""
    CONFIG = {
        'authorization': {'sources': [{'type': 'file', 'path': 'data/authz/acl.conf'},
                                      {'type': 'http', 'url': 'http://acl.example/', 'path': '/api/acl'}]},
        'listeners': {'ssl': {'default': {'ssl_options': {'certfile': '${EMQX_ETC_DIR}/certs/cert.pem',
                                                           'keyfile': 'data/certs/listeners/ssl/default/key.pem'}}}},
        'node': {'config_files': ['/opt/emqx/etc/emqx.conf', '/etc/extra.conf'], 'data_dir': 'data',
                 'crash_dump_file': '${EMQX_LOG_DIR}/erl_crash.dump'},
        'log': {'file': {'default': {'path': '/var/log/emqx/emqx.log', 'enable': True}}},
        'rule_engine': {'rules': {'r1': {'sql': 'SELECT * FROM "data/topic"', 'actions': []}}},
        'rewrite': [{'source_topic': 'data/#', 'dest_topic': 'x/#'}],
        'connectors': {'http': {'erp': {'url': 'http://erp/path', 'password': 'file:///opt/emqx/data/secrets/erp.txt',
                                         'ssl': {'cacertfile': '/opt/emqx/data/certs/connectors/http/erp/ca.pem'}}}},
        'authentication': [{'mechanism': 'password_based', 'backend': 'built_in_database',
                            'bootstrap_file': '${EMQX_ETC_DIR}/boot.csv'}],
        'gateway': {'stomp': {'authentication': {'bootstrap_file': '/opt/emqx/data/configs/stomp.csv'}}},
        'api_key': {'bootstrap_file': ''}, 'psk_authentication': {'enable': False, 'init_file': ''},
        'actions': {'http': {'ingest': {'parameters': {'method': 'post', 'path': 'data/ingest'}}}}}

    def test_a_setting_is_a_file_by_its_name_or_by_an_absolute_data_path(self):
        found = ha_emqx.file_scan(copy.deepcopy(self.CONFIG))
        self.assertEqual(found['data'], {'authz/acl.conf', 'certs/listeners/ssl/default/key.pem', 'secrets/erp.txt',
                                         'certs/connectors/http/erp/ca.pem', 'configs/stomp.csv'})
        self.assertEqual(found['outputs'], {'/opt/emqx/log/erl_crash.dump', '/var/log/emqx/emqx.log'})
        self.assertEqual(found['not_carried'], set(), 'topics, URLs, SQL, empty settings and the authenticators\' own bootstrap '
                                                    'files (bootstrap_references\') are no files of this scan')
        odd = {'authentication': [{'mechanism': 'password_based', 'backend': 'built_in_database',
                                   'bootstrap_file': '../bootstrap.csv'}], 'authorization': {'sources': []}}
        self.assertEqual(ha_emqx.file_scan(odd), {'data': set(), 'outputs': set(), 'not_carried': set()},
                         'an authenticator\'s own bootstrap file is bootstrap_references\' (E-48, E-49), whatever it looks like')

    def test_a_log_handler_that_is_switched_off_writes_nowhere(self):
        """E-35: only the paths of handlers that run are places the candidate has to be able to write."""
        config = {'log': {'file': {'default': {'enable': True, 'path': '${EMQX_LOG_DIR}/emqx.log'},
                                   'old': {'enable': False, 'path': '/opt/emqx/etc/old.log'},
                                   'audit': {'path': '/var/log/audit/emqx.log'}}},
                  'node': {'crash_dump_file': '${EMQX_LOG_DIR}/erl_crash.dump'}}
        self.assertEqual(ha_emqx.file_scan(config)['outputs'],
                         {'/opt/emqx/log/emqx.log', '/var/log/audit/emqx.log', '/opt/emqx/log/erl_crash.dump'})

    def test_a_certificate_or_key_given_as_content_is_no_file_to_carry_or_to_name(self):
        """E-30, E-50: the setting holds the PEM itself (no path): nothing to carry, nothing to say."""
        pem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'
        config = {'listeners': {'ssl': {'default': {'ssl_options': {'certfile': pem, 'keyfile': '  -----BEGIN PRIVATE KEY-----',
                                                                     'cacertfile': 'two\nlines'}}}}}
        self.assertEqual(ha_emqx.file_scan(config), {'data': set(), 'outputs': set(), 'not_carried': set()})

    def test_mounts_and_secrets_are_the_candidates_too_and_runtime_places_and_unknown_variables_are_named(self):
        config = {'authorization': {'sources': []}, 'a': {'certfile': '/opt/emqx/certs/a.pem', 'keyfile': '/opt/emqx/etc/k.pem',
                                                          'cacertfile': '/run/secrets/ca', 'init_file': '/run/other',
                                                          'filename': '/tmp/x', 'file': '${NOPE}/x', 'path': '/outside'}}
        found = ha_emqx.file_scan(config, mounts=[('/h/certs', '/opt/emqx/certs', 'ro'), ('/h/k.pem', '/opt/emqx/etc/k.pem', 'ro')],
                                  secrets=['ca,type=mount'])
        self.assertEqual(found['data'], set())
        self.assertEqual(found['not_carried'], {'a.init_file', 'a.filename', 'a.file'})
        self.assertEqual(ha_emqx.file_scan(config)['not_carried'], {'a.cacertfile', 'a.init_file', 'a.filename', 'a.file'})

    def test_a_place_the_database_or_the_converted_volume_drops_is_not_carried(self):
        config = {'x': {'certfile': '/opt/emqx/data/mnesia/emqx@127.0.0.1/a', 'keyfile': 'data/backup/b.tar.gz',
                        'cacertfile': 'data/configs/vm.1.args'}}
        found = ha_emqx.file_scan(config)
        self.assertEqual((found['data'], found['not_carried']), (set(), {'x.certfile', 'x.keyfile', 'x.cacertfile'}))

    def test_the_etc_and_log_folders_of_this_device_decide_what_the_templates_mean(self):
        config = {'x': {'certfile': '${EMQX_ETC_DIR}/a.pem', 'keyfile': '${EMQX_LOG_DIR}/k.pem', 'path': '/opt/emqx/data/p'},
                  'log': {'file': {'default': {'path': '${EMQX_LOG_DIR}/emqx.log'}}}}
        found = ha_emqx.file_scan(config, etc_dir='/opt/emqx/data/etc', log_dir='/var/log/emqx')
        self.assertEqual(found['data'], {'etc/a.pem', 'p'}, 'an etc folder in the data volume is carried like any file in it; '
                                                           'an absolute path into the data directory is a file by its value')
        self.assertEqual(found['outputs'], {'/var/log/emqx/emqx.log'})

    def test_an_authorization_object_alone_is_scanned_and_garbage_is_refused(self):
        """authorization_file_references: the same scan; what is no authorization at all still stops (E-25's rule)."""
        auth = {'sources': [{'type': 'file', 'path': [ord(char) for char in 'data/authz/acl.conf']},
                            {'type': 'file', 'path': '/elsewhere/acl.conf'}, {'type': 'built_in_database'}]}
        found = {}
        self.assertEqual(ha_emqx.authorization_file_references(auth, [], found=found), {'configs/cluster.hocon', 'authz/acl.conf'})
        self.assertEqual(found['not_carried'], set())
        for bad in ({'sources': 'x'}, {'sources': [1]}, {}, None, {'sources': [{'type': 'file', 'path': ''}]},
                    {'sources': [{'type': 'file', 'path': [47, 0, 120]}]}, {'sources': [{'type': 'file'}]}):
            with self.subTest(bad=bad), self.assertRaises(BackupError):
                ha_emqx.authorization_file_references(bad, [])

    def test_nesting_deeper_than_the_scan_reads_stops_the_app(self):
        deep = value = {}
        for _ in range(40):
            value['x'] = {}
            value = value['x']
        with self.assertRaises(BackupError) as caught:
            ha_emqx.file_scan({'authorization': {'sources': []}, 'future': deep})
        self.assertEqual(caught.exception.code, 'incompatible')


class ScratchPlanTests(unittest.TestCase):
    """E-23, E-35: where the candidate has to be able to write besides its data and log volumes."""
    plan = staticmethod(ha_emqx.scratch_plan)

    def test_the_images_own_log_folder_and_the_tmpfs_places_need_nothing(self):
        self.assertEqual(self.plan({'/opt/emqx/log/emqx.log', '/opt/emqx/log/sub/erl_crash.dump', '/tmp/x.log',
                                    '/opt/emqx/data/log/x.log'}, '/opt/emqx/log'), ([], [], []))
        self.assertEqual(self.plan(set(), None), ([], [], []))

    def test_a_log_folder_elsewhere_gets_scratch_space(self):
        self.assertEqual(self.plan({'/var/log/emqx/emqx.log', '/srv/dumps/erl_crash.dump', '/opt/other/logs/x.log'},
                                   '/opt/emqx/log'), (['/opt/other/logs', '/srv/dumps', '/var/log/emqx'], [], []))
        self.assertEqual(self.plan(set(), '/srv/emqx-logs'), (['/srv/emqx-logs'], [], []), 'EMQX_LOG_DIR itself')

    def test_this_devices_own_mount_of_a_log_folder_gives_way_and_is_never_mounted_for_writing(self):
        mounts = [('/home/u/logs', '/var/log/emqx', 'ro')]
        self.assertEqual(self.plan({'/var/log/emqx/emqx.log'}, '/opt/emqx/log', mounts),
                         (['/var/log/emqx'], ['/var/log/emqx'], []))
        self.assertEqual(self.plan({'/var/log/emqx/sub/emqx.log'}, '/opt/emqx/log', mounts), ([], [], ['/var/log/emqx/sub']),
                         'a folder below a mount cannot be mounted in it')

    def test_a_place_that_holds_the_images_own_files_cannot_be_given(self):
        for path in ('/opt/emqx/etc/e.log', '/opt/emqx/bin/e.log', '/opt/emqx/lib/x/e.log', '/opt/emqx/e.log', '/e.log',
                     '/opt/emqx/log2/e.log', '/opt/emqx/erts-14.2/bin/e.log', '/opt/emqx/plugins/e.log',
                     '/etc/emqx/e.log', '/usr/local/e.log', '/var/e.log', '/var/log/em qx/e.log', '/proc/e.log'):
            with self.subTest(path=path):
                extra, give_way, bad = self.plan({path}, '/opt/emqx/log')
                self.assertEqual((extra, give_way, len(bad)), ([], [], 1), path)


class OwnItemsTests(unittest.TestCase):
    """E-41, E-42, E-43, E-44, E-47: the names of what this device has of its own, and what the import did with them."""

    def test_names_by_kind_and_nothing_else(self):
        config = {'connectors': {'http': {'erp': {'url': 'http://erp/', 'password': 'secret-value'}}, 'mqtt': {}},
                  'actions': {'http': {'act1': {}}}, 'sources': {}, 'bridges': {'webhook': {'old': {}}},
                  'gateway': {'stomp': {'enable': True}}, 'rule_engine': {'rules': {'r1': {'sql': 'x'}, 'r2': {}}},
                  'rewrite': [{'source_topic': 'a'}], 'topic_metrics': [{'topic': 'sensors/t'}, {'topic': ''}],
                  'auto_subscribe': {'topics': [{'topic': 't'}]}, 'exhook': {'servers': [{'name': 'h1'}, {'url': 'x'}]},
                  'psk_authentication': {'enable': True}, 'plugins': {'states': [{'name_vsn': 'p-1.0.0', 'enable': True}],
                                                                        'install_dir': '/data/plugins'},
                  'durable_sessions': {'enable': True}}
        own = ha_emqx_settings.own_items(config)
        self.assertEqual(own['integrations'], ['actions.http.act1', 'bridges.webhook.old', 'connectors.http.erp',
                                               'gateway.stomp', 'rule_engine.rules.r1', 'rule_engine.rules.r2'])
        self.assertEqual(own['routing'], ['auto_subscribe', 'exhook.2', 'exhook.h1', 'rewrite', 'topic_metrics.2',
                                          'topic_metrics.sensors/t'])
        self.assertEqual((own['psk'], own['durable']), (['psk_authentication'], ['durable_sessions']))
        self.assertEqual(own['plugins'], ['plugins.install_dir', 'plugins.p-1.0.0'])
        self.assertNotIn('secret-value', repr(own), 'names only, never a value')
        kinds = ('integrations', 'routing', 'psk', 'plugins', 'durable')
        self.assertEqual(ha_emqx_settings.own_items({}), {'integrations': [], 'routing': [], 'psk': [], 'plugins': [], 'durable': [],
                                                         'replaced': {k: 0 for k in kinds}, 'mixed': {k: True for k in kinds}},
                         'without the candidate\'s final configuration it is assumed that HA brought something')

    def test_empty_disabled_and_default_settings_are_no_own_items(self):
        config = {'connectors': {}, 'actions': {'http': {}}, 'gateway': {}, 'rule_engine': {'rules': {}}, 'rewrite': [],
                  'topic_metrics': [], 'auto_subscribe': {'topics': []}, 'exhook': {'servers': []},
                  'psk_authentication': {'enable': False, 'init_file': ''}, 'plugins': {'states': [], 'install_dir': 'plugins'},
                  'durable_sessions': {'enable': False, 'force_persistence': False}}
        own = ha_emqx_settings.own_items(config)
        self.assertEqual([own[kind] for kind in ('integrations', 'routing', 'psk', 'plugins', 'durable')], [[]] * 5)
        self.assertEqual(ha_emqx_settings.own_items(config, config)['replaced'], {k: 0 for k in own['replaced']})

    def test_what_the_import_changed_of_them_is_counted(self):
        device = {'connectors': {'http': {'erp': {'url': 'http://erp'}, 'keep': {'url': 'http://keep'}}},
                  'rule_engine': {'rules': {'r1': {'sql': 'a'}}}, 'rewrite': [{'source_topic': 'a'}]}
        after = copy.deepcopy(device)
        after['connectors']['http']['erp'] = {'url': 'http://ha-erp'}
        after['connectors']['http']['ha-only'] = {'url': 'http://ha'}
        after['rule_engine']['rules']['ha-rule'] = {'sql': 'b'}
        after['rewrite'] = [{'source_topic': 'ha'}]
        own = ha_emqx_settings.own_items(device, after)
        self.assertEqual(own['integrations'], ['connectors.http.erp', 'connectors.http.keep', 'rule_engine.rules.r1'],
                         "HA's own entries are not this device's")
        self.assertEqual(own['replaced'], {'integrations': 1, 'routing': 1, 'psk': 0, 'plugins': 0, 'durable': 0})
        self.assertEqual(own['mixed'], {'integrations': True, 'routing': True, 'psk': False, 'plugins': False, 'durable': False})

    def test_what_this_device_has_is_not_mixed_when_ha_brought_nothing_of_the_kind(self):
        """E-41, E-42: nothing of HA's came in, so nothing of this device's is replaced or runs next to anything: no question."""
        device = {'connectors': {'http': {'erp': {'url': 'http://erp'}}}, 'rewrite': [{'source_topic': 'a'}],
                  'topic_metrics': [{'topic': 't'}]}
        same = copy.deepcopy(device)
        self.assertEqual(ha_emqx_settings.own_items(device, same)['mixed'],
                         {'integrations': False, 'routing': False, 'psk': False, 'plugins': False, 'durable': False})
        for change in (lambda c: c['connectors']['http'].update({'ha': {'url': 'http://ha'}}),
                       lambda c: c['connectors']['http']['erp'].update(url='http://other'),
                       lambda c: c.update(rewrite=[]), lambda c: c['topic_metrics'].append({'topic': 'ha/t'}),
                       lambda c: c.update(rule_engine={'rules': {'ha-rule': {'sql': 'x'}}})):
            after = copy.deepcopy(device)
            change(after)
            mixed = ha_emqx_settings.own_items(device, after)['mixed']
            with self.subTest(after=after):
                self.assertTrue(mixed['integrations'] or mixed['routing'])

    def test_a_setting_of_an_unexpected_shape_is_still_one_name_and_never_a_crash(self):
        for config in ({'connectors': 5, 'rule_engine': {'rules': [1]}, 'topic_metrics': 'x', 'exhook': {'servers': 3},
                        'plugins': {'states': 'x'}, 'durable_sessions': 'x', 'gateway': 'g', 'auto_subscribe': 'a',
                        'psk_authentication': 'p', 'actions': {'http': 'x'}}, {'rule_engine': None, 'plugins': []}):
            own = ha_emqx_settings.own_items(config, config)
            self.assertTrue(any(own[kind] for kind in ('integrations', 'routing', 'psk', 'plugins')) or not any(config.values()))


def levels(issues):
    return {issue.id: issue.level for issue in issues}


class DeviceFoldersTests(unittest.TestCase):
    """E-23: this device's own EMQX_LOG_DIR; the places of its mounts; the bootstrap files of the banned list and the API keys."""

    def test_the_log_folder_is_the_quadlets_or_the_images(self):
        for env, want in (({}, '/opt/emqx/log'), ({'EMQX_LOG_DIR': ''}, '/opt/emqx/log'), ({'EMQX_LOG_DIR': '/var/log/emqx/'}, '/var/log/emqx'),
                          ({'EMQX_LOG_DIR': 'relative/log'}, None), ({'EMQX_LOG_DIR': '/a/../b'}, None),
                          ({'EMQX_LOG_DIR': '/a/$HOME'}, '/a/$HOME'), (None, '/opt/emqx/log')):
            with self.subTest(env=env):
                got = ha_emqx.device_log_dir(SimpleNamespace(env=env))
                self.assertEqual(got, want if want != '/a/$HOME' else got)
        self.assertEqual(ha_emqx.device_log_dir(SimpleNamespace()), '/opt/emqx/log')

    def test_mounts_and_mounted_secrets_are_the_places_the_candidate_has_as_this_device_does(self):
        self.assertEqual(ha_emqx.mount_targets([('/h/a', '/opt/emqx/etc/a.conf', 'ro'), ('/h/d', '/srv/certs/', 'ro'), ('x',), ('/h/z', 5, 'ro')],
                                               ['s1,type=mount,target=/opt/emqx/etc/boot.csv,uid=1,gid=1,mode=0400', 's2,type=env,target=X',
                                                'plain']),
                         {'/opt/emqx/etc/a.conf', '/srv/certs', '/opt/emqx/etc/boot.csv', '/run/secrets/plain'})

    @staticmethod
    def candidate(readable=True):
        calls = []

        def execute(role, command, **kwargs):
            calls.append(command)
            return Result(0 if readable else 1, b'', b'')
        return SimpleNamespace(exec=execute), calls

    def test_the_bootstrap_files_of_the_banned_list_and_the_keys_are_read_where_the_broker_means_them(self):
        tmp, calls = self.candidate()
        target = SimpleNamespace(files=[], secrets=[], env={})
        config = {'banned': {'bootstrap_file': 'data/configs/banned.csv'}, 'api_key': {'bootstrap_file': '${EMQX_ETC_DIR}/keys.csv'},
                  'authentication': []}
        ha_emqx.check_candidate_bootstrap(tmp, target, config, lost=[], etc_dir='/custom/etc')
        self.assertEqual([call[2] for call in calls], ['/custom/etc/keys.csv', '/opt/emqx/data/configs/banned.csv'])
        self.assertTrue(all(call[:2] == ['test', '-f'] for call in calls))

    def test_one_the_candidate_cannot_read_or_nobody_can_place_is_said_and_without_a_list_it_stops(self):
        target = SimpleNamespace(files=[], secrets=[], env={})
        for config, readable in (({'banned': {'bootstrap_file': '${NOPE}/b.csv'}}, True),
                                 ({'api_key': {'bootstrap_file': '/srv/keys.csv'}}, False)):
            with self.subTest(config=config):
                tmp, _calls = self.candidate(readable)
                lost = []
                ha_emqx.check_candidate_bootstrap(tmp, target, config, lost=lost)
                self.assertEqual(len(lost), 1)
                tmp, _calls = self.candidate(readable)
                with self.assertRaises(BackupError):
                    ha_emqx.check_candidate_bootstrap(tmp, target, config)

    def test_a_root_that_is_no_dictionary_or_a_path_that_is_no_text_is_ignored(self):
        tmp, calls = self.candidate()
        target = SimpleNamespace(files=[], secrets=[], env={})
        ha_emqx.check_candidate_bootstrap(tmp, target, {'banned': 5, 'api_key': {'bootstrap_file': 7}, 'x': {'bootstrap_file': ''}}, lost=[])
        self.assertEqual(calls, [])


class EnvironmentFileTests(unittest.TestCase):
    """E-23: this device's EMQX_LOG_DIR may be set in an `EnvironmentFile=` instead of the Quadlet itself."""

    @staticmethod
    def target(files, env_files):
        def read_file(rel, max_bytes):
            if rel not in files:
                raise BackupError('not-found', 'no such file')
            return files[rel]
        target = ha_emqx.Target.__new__(ha_emqx.Target)
        target.env, target.env_files, target._runner = {}, env_files, SimpleNamespace(read_file=read_file)
        return target

    def test_the_last_file_that_sets_it_wins_and_only_plain_values_count(self):
        files = {'.config/a.env': b'# c\nEMQX_LOG_DIR=/var/log/a\nOTHER=1\n', '.config/b.env': b'EMQX_LOG_DIR="/var/log/b"\r\n',
                 '.config/c.env': b"EMQX_LOG_DIR='/var/log/c'\n", '.config/d.env': b'EMQX_LOG_DIR=/var/log/$HOME\n',
                 '.config/e.env': b'  EMQX_LOG_DIR=/var/log/e  \n', '.config/f.env': b'XEMQX_LOG_DIR=/x\nEMQX_LOG_DIR_MORE=/y\n'}
        for names, want in ((['.config/a.env'], '/var/log/a'), (['.config/a.env', '.config/b.env'], '/var/log/b'),
                            (['.config/c.env'], '/var/log/c'), (['.config/d.env'], None), (['.config/e.env'], '/var/log/e'),
                            (['.config/f.env'], None), (['.config/a.env', '.config/f.env'], '/var/log/a'), ([], None)):
            with self.subTest(files=names):
                got = self.target(files, [f'%h/{name}' for name in names]).file_env('EMQX_LOG_DIR')
                self.assertEqual(got, want)

    def test_a_file_outside_the_home_or_that_cannot_be_read_is_skipped(self):
        files = {'.config/a.env': b'EMQX_LOG_DIR=/var/log/a\n'}
        target = self.target(files, ['/etc/emqx.env', '-%h/.config/missing.env', '%h/../x.env', '%h/.config/a.env', '%h/bad name.env'])
        self.assertEqual(target.file_env('EMQX_LOG_DIR'), '/var/log/a')
        self.assertEqual(ha_emqx.device_log_dir(target), '/var/log/a')
        target.env = {'EMQX_LOG_DIR': '/var/log/quadlet'}
        self.assertEqual(ha_emqx.device_log_dir(target), '/var/log/quadlet', 'the Quadlet\'s own setting is the stronger one')


class OwnLinesTests(base.EmqxCase):
    """E-41, E-42, E-43, E-44, E-47 through the whole candidate of the generated device: each line to confirm has its three steps
    (not confirmed: only this app stops; confirmed: it goes on; one more name: confirm again), the plugins are a notice."""
    world_class = base.World

    def set_own(self, **roots):
        self.world.target_config.update(copy.deepcopy(roots))
        self.world.current_config = copy.deepcopy(self.world.target_config)

    def three(self, issue_id, make, more=None):
        return parity.ThreeStepsTests.three(self, issue_id, make, more=more)

    def ha_adds_a_connector(self):
        """HA's import brings a connector of its own: what this device has runs next to it (the import is a merge)."""
        merged = copy.deepcopy(self.world.target_config['connectors'])
        merged['http']['from-ha'] = {'url': 'http://from-ha.example/'}
        self.world.import_changes = {'connectors': merged}

    def test_this_devices_own_integrations_are_a_line_to_confirm(self):
        """E-41: rules, connectors, actions, sources, bridges and gateways of this device, by name."""
        own = {'connectors': {'http': {'erp': {'url': 'http://erp.example/hook'}}},
               'rule_engine': {'rules': {'r1': {'sql': 'SELECT 1', 'actions': []}}}}

        def make():
            self.set_own(**own)
            self.ha_adds_a_connector()

        def more():
            self.world.target_config['connectors']['http']['second'] = {'url': 'http://second.example/'}
            self.world.current_config = copy.deepcopy(self.world.target_config)
            self.ha_adds_a_connector()
        line = self.three('emqx.device-integrations', make, more=more)
        self.assertEqual(line.names, ('connectors.http.erp', 'rule_engine.rules.r1'))
        self.assertIn('2 項', line.message)
        self.assertNotIn('erp.example', repr(line.view('emqx')), 'names, never a value')
        self.assertNotIn('以 HA 的為準（其中', line.message, 'nothing of it was replaced')

    def test_the_line_says_how_many_of_them_the_import_replaced(self):
        """E-41: a same-named entry of HA's wins; the others stay next to HA's (the import is a merge)."""
        self.set_own(connectors={'http': {'erp': {'url': 'http://erp.example/hook'}, 'keep': {'url': 'http://keep.example/'}}})
        self.world.import_changes = {'connectors': {'http': {'erp': {'url': 'http://ha.example/'},
                                                             'keep': {'url': 'http://keep.example/'},
                                                             'ha-only': {'url': 'http://ha-only.example/'}}}}
        result = self.internal_candidate(self.upload_emqx(state='stopped'))
        [line] = [issue for issue in result['issues'] if issue.id == 'emqx.device-integrations']
        self.assertEqual(line.names, ('connectors.http.erp', 'connectors.http.keep'))
        self.assertIn('（其中 1 個已經換成 HA 的）', line.message)

    def test_this_devices_own_routing_is_a_line_to_confirm(self):
        """E-42: topic rewrite, topic metrics, auto-subscribe and ExHook servers of this device, by name."""
        own = {'rewrite': [{'action': 'publish', 'source_topic': 'x/#', 'dest_topic': 'y/#'}],
               'topic_metrics': [{'topic': 'sensors/t'}],
               'exhook': {'servers': [{'name': 'hook1', 'url': 'http://hook.example', 'enable': False}]}}

        def ha_adds_a_topic():
            self.world.import_changes = {'topic_metrics': self.world.target_config['topic_metrics'] + [{'topic': 'from/ha'}]}

        def make():
            self.set_own(**own)
            ha_adds_a_topic()

        def more():
            self.world.target_config['topic_metrics'].append({'topic': 'sensors/h'})
            self.world.current_config = copy.deepcopy(self.world.target_config)
            ha_adds_a_topic()
        line = self.three('emqx.device-routing', make, more=more)
        self.assertEqual(line.names, ('exhook.hook1', 'rewrite', 'topic_metrics.sensors/t'))
        self.assertNotIn('hook.example', repr(line.view('emqx')))

    def test_nothing_of_ha_s_kind_means_no_question_about_this_devices_own(self):
        """E-41, E-42: HA brought no connector, rule or rewrite of its own: this device's stay exactly as they are and nothing is
        asked about them; what is not about HA's content (PSK, durable sessions, plugins) is told all the same."""
        self.set_own(connectors={'http': {'erp': {'url': 'http://erp.example/hook'}}}, rewrite=[{'source_topic': 'a'}],
                     psk_authentication={'enable': True}, durable_sessions={'enable': True},
                     plugins={'states': [{'name_vsn': 'p-1.0.0'}], 'install_dir': 'plugins'})
        found = levels(self.internal_candidate(self.upload_emqx(state='stopped'))['issues'])
        self.assertNotIn('emqx.device-integrations', found)
        self.assertNotIn('emqx.device-routing', found)
        self.assertEqual([found[i] for i in ('emqx.device-psk', 'emqx.durable-sessions', 'emqx.device-plugins')],
                         ['confirm', 'confirm', 'notice'])

    def test_this_devices_psk_is_a_line_to_confirm(self):
        """E-43: PSK authentication (or a PSK file): HA's keys replace this device's."""
        own = {'psk_authentication': {'enable': True, 'init_file': '', 'separator': ':'}}
        line = self.three('emqx.device-psk', lambda: self.set_own(**own))
        self.assertEqual(line.names, ('psk_authentication',))
        self.assertIn('重新設定', line.message)
        self.world.again()
        self.set_own(psk_authentication={'enable': False, 'init_file': '/opt/emqx/etc/psk.txt'})
        found = [issue.id for issue in self.internal_candidate(self.upload_emqx(state='stopped'))['issues']]
        self.assertIn('emqx.device-psk', found, 'a PSK file alone is enough')

    def test_this_devices_durable_sessions_are_a_line_to_confirm(self):
        """E-47: the messages queued for offline devices are not in HA's export and the restore replaces the data volume."""
        line = self.three('emqx.durable-sessions', lambda: self.set_own(durable_sessions={'enable': True}))
        self.assertEqual(line.names, ('durable_sessions',))
        self.assertIn('排隊', line.message)
        self.world.again()
        self.set_own(durable_sessions={'enable': False, 'force_persistence': False},
                     durable_storage={'messages': {'backend': 'builtin_raft'}})
        found = [issue.id for issue in self.internal_candidate(self.upload_emqx(state='stopped'))['issues']]
        self.assertNotIn('emqx.durable-sessions', found, 'durable sessions that are off queue nothing')

    def test_plugins_are_a_notice_and_nothing_is_cleared(self):
        """E-44: the plugin files live in the container, not in the data; the records stay (vendor emqx_plugins.erl only logs a
        plugin that is not installed), the customer is told once."""
        own = {'plugins': {'states': [{'name_vsn': 'my_plugin-1.0.0', 'enable': True}], 'install_dir': 'plugins'}}
        self.set_own(**own)
        result = self.internal_candidate(self.upload_emqx(state='stopped'), acknowledged=[])
        self.assertEqual(levels(result['issues']).get('emqx.device-plugins'), 'notice')
        [line] = [issue for issue in result['issues'] if issue.id == 'emqx.device-plugins']
        self.assertEqual(line.names, ('plugins.my_plugin-1.0.0',))
        self.assertIn('重新安裝', line.message)
        self.assertTrue(result['volumes'], 'a notice needs no confirmation')
        self.assertEqual(self.world.current_config['plugins'], own['plugins'], 'the records are this device\'s and stay')

    def test_nothing_of_its_own_nothing_to_confirm(self):
        found = levels(self.internal_candidate(self.upload_emqx(state='stopped'))['issues'])
        for issue_id in ('emqx.device-integrations', 'emqx.device-routing', 'emqx.device-psk', 'emqx.durable-sessions',
                         'emqx.device-plugins', 'emqx.dirs-follow-device', 'emqx.files-not-carried'):
            self.assertNotIn(issue_id, found)

    def test_the_check_lists_them_and_leaves_the_device_alone(self):
        self.set_own(connectors={'http': {'erp': {'url': 'http://erp.example/hook'}}}, durable_sessions={'enable': True})
        self.ha_adds_a_connector()
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(result['importable'])
        confirm = {issue['id']: issue for issue in result['issues'] if issue['level'] == 'confirm'}
        self.assertEqual(sorted(confirm), ['emqx.device-integrations', 'emqx.durable-sessions'])
        self.assertTrue(all(issue['key'] for issue in confirm.values()))
        self.assertFalse(result['ok'], 'a line to confirm is asked for before the import')
        self.assertNotIn('woow_emqx_data', self.world.imported, 'no volume of this device is written')


class OwnWorld(base.World):
    """The generated device with more of its own: `own` roots in its configuration, `volume_files` in its data volume, and the
    etc folder its broker (`woow-emqx`) and the candidate (`emqx-new`) answer."""
    own = {}
    volume_files = {}
    etc = {}

    def __init__(self):
        super().__init__()
        self.target_config.update(copy.deepcopy(self.own))
        self.current_config = copy.deepcopy(self.target_config)

    def evaluate(self, role, expression):
        if expression == ha_emqx.ETC_EXPR:
            return f'WOOWETC:{self.etc.get(role, "/opt/emqx/etc")}:ENDok\n'.encode()
        return super().evaluate(role, expression)

    def exec(self, role, command, data, stdout):
        if role == 'emqx-new' and command[:1] == ['sha256sum'] and len(command) == 2 and command[1].startswith('/opt/emqx/data/'):
            # the candidate's copy of a file of this device's data volume is the very bytes that were exported
            body = self.volume_files.get(command[1][len('/opt/emqx/data/'):])
            if body is not None:
                return Result(0, hashlib.sha256(body).hexdigest().encode() + b'  ' + command[1].encode() + b'\n', b'')
        return super().exec(role, command, data, stdout)

    def export(self, volume):
        data = super().export(volume)
        if volume.endswith('emqx-xfer') or not self.volume_files:
            return data
        import io
        import tarfile
        entries = []
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            for member in tar.getmembers():
                entries.append({'name': member.name, 'type': 'dir', 'uid': member.uid} if member.isdir() else
                               {'name': member.name, 'data': tar.extractfile(member).read(), 'uid': member.uid})
        entries += [{'name': name, 'data': body, 'uid': 1000} for name, body in sorted(self.volume_files.items())]
        return base.fk.tar_of(entries)


def quadlet(*, env=(), volumes=(), swap=()):
    """The generated device's Quadlet files with more `Environment=` and `Volume=` lines and `swap` ((old, new) pairs)."""
    text = base.QUADLETS['emqx.container']
    for old, new in swap:
        assert old in text, old
        text = text.replace(old, new)
    lines = ''.join(f'Environment={line}\n' for line in env) + ''.join(f'Volume={line}\n' for line in volumes)
    text = text.replace(b'Volume=emqx-data.volume', lines.encode() + b'Volume=emqx-data.volume')
    return {'emqx': {**base.QUADLETS, 'emqx.container': text}}


class FoldersAndFilesInTheRealFlowTests(base.EmqxCase):
    """E-23, E-24, E-29, E-30, E-35, E-36 through check and conversion of the generated device: its own folders and files."""
    world_class = OwnWorld

    def result(self, **world):
        for name, value in world.items():
            setattr(self.world, name, value)
        return self.check(self.upload_emqx(), ['emqx'])[0]

    def candidate_volumes(self):
        [run] = self.runs('emqx-new')
        return [value.split(':') for value in run[3]['--volume']]

    def test_a_log_folder_elsewhere_is_given_to_the_candidate_as_scratch(self):
        """E-23, E-35: EMQX_LOG_DIR and the log handler and the crash dump point to /var/log/emqx; the candidate runs with the
        same environment and its own log volume there (logs are never carried)."""
        self.world.quadlets = quadlet(env=['EMQX_LOG_DIR=/var/log/emqx'])
        self.world.target_config.update({'node': {'name': 'emqx@127.0.0.1', 'data_dir': 'data',
                                                  'crash_dump_file': '${EMQX_LOG_DIR}/erl_crash.dump'},
                                         'log': {'file': {'default': {'enable': True, 'path': '${EMQX_LOG_DIR}/emqx.log'}}}})
        self.world.current_config = copy.deepcopy(self.world.target_config)
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        [auto] = [issue for issue in result['issues'] if issue['id'] == 'emqx.dirs-follow-device']
        self.assertEqual((auto['level'], auto['items']), ('auto', ['/var/log/emqx']))
        volumes = self.candidate_volumes()
        scratch = [v for v in volumes if v[1] == '/var/log/emqx']
        self.assertEqual(len(scratch), 1)
        self.assertEqual(scratch[0][0], [v for v in volumes if v[1] == '/opt/emqx/log'][0][0], 'the candidate\'s own log volume')
        [run] = self.runs('emqx-new')
        self.assertIn('EMQX_LOG_DIR=/var/log/emqx', run[3]['--env'])

    def test_a_log_folder_set_in_the_environment_file_is_found_too(self):
        """E-23: EMQX_LOG_DIR is in the Quadlet's EnvironmentFile=, not in the Quadlet: podman gives it to the candidate, the scan
        finds where it points, the candidate gets scratch space there."""
        self.world.files['.config/emqx/emqx.env'] = b'# woow emqx\nEMQX_LOG__CONSOLE__LEVEL=warning\nEMQX_LOG_DIR=/var/log/emqx\n'
        self.world.target_config.update({'log': {'file': {'default': {'enable': True, 'path': '${EMQX_LOG_DIR}/emqx.log'}}}})
        self.world.current_config = copy.deepcopy(self.world.target_config)
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        self.assertTrue([v for v in self.candidate_volumes() if v[1] == '/var/log/emqx'])
        [run] = self.runs('emqx-new')
        self.assertFalse([e for e in run[3]['--env'] if e.startswith('EMQX_LOG_DIR')], 'podman reads the file, nothing is copied')
        self.assertTrue(run[3]['--env-file'])

    def test_a_log_folder_that_is_one_of_this_devices_mounts_is_never_mounted_for_the_candidate(self):
        """E-35: this device's real folder stays untouched; the candidate gets scratch space at its place."""
        self.world.quadlets = quadlet(volumes=['%h/emqx-logs:/var/log/emqx:Z'])
        self.world.target_config.update({'log': {'file': {'default': {'enable': True, 'path': '/var/log/emqx/emqx.log'}}}})
        self.world.current_config = copy.deepcopy(self.world.target_config)
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        volumes = self.candidate_volumes()
        self.assertEqual([v[0] for v in volumes if v[1] == '/var/log/emqx'], [[x[0] for x in volumes if x[1] == '/opt/emqx/log'][0]])
        self.assertFalse([v for v in volumes if 'emqx-logs' in v[0]], 'the host folder is not in the candidate')

    def test_a_log_place_that_cannot_be_given_stops_only_this_app_before_the_candidate_exists(self):
        """E-35: a log file in the image's own etc folder, or below one of this device's mounts."""
        for path, mounted in (('/opt/emqx/etc/emqx.log', False), ('/var/log/emqx/sub/emqx.log', True)):
            with self.subTest(path=path):
                self.world = OwnWorld()
                self.world.quadlets = quadlet(volumes=['%h/emqx-logs:/var/log/emqx:Z'] if mounted else [])
                self.world.target_config.update({'log': {'file': {'default': {'enable': True, 'path': path}}}})
                self.world.current_config = copy.deepcopy(self.world.target_config)
                self.deps.adapter_factory = self.world.factory
                result = self.check(self.upload_emqx(), ['emqx'])[0]
                self.assertFalse(result['importable'])
                [stop] = [issue for issue in result['issues'] if issue['level'] == 'stop']
                self.assertEqual(stop['id'], 'emqx.output-dir-unusable')
                self.assertTrue(stop['items'] and stop['action'])
                self.assertEqual(self.runs('emqx-new'), [], 'nothing of the candidate was started')

    def test_this_devices_own_etc_folder_is_the_candidates_too(self):
        """E-24: EMQX_ETC_DIR is /custom/etc; the ACL file `${EMQX_ETC_DIR}/acl.conf` is looked for there (on this device's
        mount), the candidate starts with the same environment and the same mount, and the customer is told."""
        self.world.quadlets = quadlet(env=['EMQX_ETC_DIR=/custom/etc'], swap=[
            (b'/opt/emqx/etc/acl.conf:ro,Z', b'/custom/etc/acl.conf:ro,Z')])
        self.world.etc = {'woow-emqx': '/custom/etc', 'emqx-new': '/custom/etc'}
        self.world.target_config['authorization'] = {'no_match': 'deny', 'deny_action': 'ignore', 'sources': [
            {'type': 'file', 'enable': True, 'path': '${EMQX_ETC_DIR}/acl.conf'}]}
        self.world.current_config = copy.deepcopy(self.world.target_config)
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        [auto] = [issue for issue in result['issues'] if issue['id'] == 'emqx.dirs-follow-device']
        self.assertEqual(auto['items'], ['/custom/etc'])
        [run] = self.runs('emqx-new')
        self.assertIn('EMQX_ETC_DIR=/custom/etc', run[3]['--env'])
        self.assertTrue([v for v in self.candidate_volumes() if v[1] == '/custom/etc/acl.conf'])
        self.assertEqual([i['id'] for i in result['issues'] if i['id'] == 'emqx.target-file-missing'], [])

    def test_the_running_brokers_etc_template_carries_a_file_in_its_data_volume(self):
        """E-24: preflight resolves the template with the running broker's directory before selecting snapshot files."""
        import io
        import tarfile

        etc = '/opt/emqx/data/device-etc'
        self.world.quadlets = quadlet(env=[f'EMQX_ETC_DIR={etc}'])
        self.world.etc = {'woow-emqx': etc, 'emqx-new': etc}
        self.world.volume_files = {'device-etc/cert.pem': b'fixture certificate bytes'}
        self.world.target_config['listeners'] = {'ssl': {'default': {'ssl_options': {
            'certfile': '${EMQX_ETC_DIR}/cert.pem'}}}}
        self.world.current_config = copy.deepcopy(self.world.target_config)

        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        with tarfile.open(fileobj=io.BytesIO(self.world.imported['emqx-new'])) as archive:
            carried = {member.name for member in archive if member.isfile()}
        self.assertIn('device-etc/cert.pem', carried)
        self.assertNotIn('emqx.target-file-missing', [issue['id'] for issue in result['issues']])

    def test_an_etc_folder_that_the_candidate_does_not_have_stops_only_this_app(self):
        """E-24: this device says /custom/etc and the candidate something else: the candidate is not this device's replica."""
        self.world.etc = {'woow-emqx': '/custom/etc'}
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['importable'])
        [stop] = [i for i in result['issues'] if i['level'] == 'stop']
        self.assertEqual((stop['id'], stop['message']), ('failure.incompatible', ha_emqx.ETC_DIFFERS))
        self.assertIn('重新啟動這台 EMQX', stop['message'], 'it says what to do')
        self.assertEqual([c for c in self.world.ctl_calls if c[1][:2] == ['data', 'import']], [], 'nothing was imported')

    def test_an_etc_folder_the_broker_cannot_tell_stops_only_this_app(self):
        self.world.etc = {'woow-emqx': 'relative/etc'}
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['importable'])
        self.assertEqual(self.runs('emqx-new'), [])

    def test_an_acl_the_dashboard_wrote_is_found_by_its_relative_path_and_carried(self):
        """E-29, E-30: `data/authz/acl.conf` (or the list of its character codes) is in the data volume, not on a mount."""
        for path in ('data/authz/acl.conf', [ord(char) for char in 'data/authz/acl.conf'], 'data/other/acl2.conf'):
            with self.subTest(path=path if isinstance(path, str) else 'character codes'):
                self.world = OwnWorld()
                self.world.volume_files = {'authz/acl.conf': b'{allow, all}.\n', 'other/acl2.conf': b'{deny, all}.\n'}
                self.world.target_config['authorization'] = {'no_match': 'deny', 'deny_action': 'ignore', 'sources': [
                    {'type': 'file', 'enable': True, 'path': path}]}
                self.world.current_config = copy.deepcopy(self.world.target_config)
                self.deps.adapter_factory = self.world.factory
                result = self.check(self.upload_emqx(), ['emqx'])[0]
                self.assertTrue(result['importable'], result['blockers'])
                import io
                import tarfile
                with tarfile.open(fileobj=io.BytesIO(self.world.imported['emqx-new'])) as tar:
                    names = {m.name for m in tar.getmembers() if m.isfile()}
                self.assertIn('authz/acl.conf' if 'acl2' not in str(path) else 'other/acl2.conf', names)
                self.assertNotIn('emqx.target-file-missing', [i['id'] for i in result['issues']])

    def test_a_file_in_the_data_volume_that_is_not_there_is_a_notice_not_a_stop(self):
        """E-29, E-50 with E-55: this device's own hole."""
        self.world.target_config['listeners'] = {'ssl': {'default': {'ssl_options': {'certfile': 'data/certs/never.pem'}}}}
        self.world.current_config = copy.deepcopy(self.world.target_config)
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        [missing] = [i for i in result['issues'] if i['id'] == 'emqx.target-file-missing']
        self.assertEqual((missing['level'], missing['items']), ('notice', ['certs/never.pem']))

    def test_files_nobody_can_place_are_one_notice_with_the_names_of_the_settings(self):
        """E-50: setting names, never a path."""
        self.world.target_config['alarm'] = {'actions': ['log'], 'cacertfile': '${NOT_SET}/ca.pem', 'keyfile': '/proc/self/x'}
        self.world.current_config = copy.deepcopy(self.world.target_config)
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        [line] = [i for i in result['issues'] if i['id'] == 'emqx.files-not-carried']
        self.assertEqual((line['level'], line['items']), ('notice', ['alarm.cacertfile', 'alarm.keyfile']))
        self.assertTrue(result['ok'], 'a notice asks nothing')

    def test_a_data_directory_that_is_not_the_images_stops_only_this_app_with_its_advice(self):
        """E-36: HA's data would land in the wrong place; every other node setting is this device's own."""
        self.world.target_config['node'] = {'name': 'emqx@127.0.0.1', 'data_dir': '/var/lib/emqx'}
        self.world.current_config = copy.deepcopy(self.world.target_config)
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['importable'])
        [stop] = [i for i in result['issues'] if i['level'] == 'stop']
        self.assertEqual(stop['id'], 'emqx.data-dir-moved')
        self.assertIn('/opt/emqx/data', stop['action'])
        self.assertEqual(self.runs('emqx-new'), [])

    def test_the_other_node_settings_are_this_devices_own_and_come_back(self):
        """E-36: extra applications, configuration files, shard transports, the etc folder name, unlisted fields."""
        node = {'name': 'emqx@127.0.0.1', 'data_dir': 'data', 'applications': ['my_app'], 'etc_dir': '/custom/etc',
                'config_files': ['/opt/emqx/etc/emqx.conf', '/custom.conf'], 'shard_transports': {'a': 'new'}, 'unlisted': 1,
                'cluster_call': {'retry_interval': '1s', 'future': True}}
        self.world.target_config['node'] = node
        self.world.current_config = copy.deepcopy(self.world.target_config)
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        self.assertEqual(self.world.current_config['node'], node)


class OwnDocsTests(unittest.TestCase):
    """The docs quote the engine's own sentences of this lane's lines (the EMQX-B snippets of CONTRACT.md and docs/backup.md)."""
    ROOT = Path(__file__).resolve().parents[2]

    @staticmethod
    def texts():
        plain = dict(count='N', replaced='')
        return [ha_emqx.DIRS_FOLLOW, ha_emqx.FILES_NOT_CARRIED.format(**plain), ha_emqx.DEVICE_INTEGRATIONS.format(**plain),
                ha_emqx.DEVICE_ROUTING.format(**plain), ha_emqx.DEVICE_PSK, ha_emqx.DEVICE_PLUGINS.format(**plain),
                ha_emqx.DURABLE_SESSIONS, ha_emqx.OUTPUT_DIR_UNUSABLE, ha_emqx.OUTPUT_DIR_ACTION, ha_emqx.DATA_DIR_MOVED,
                ha_emqx.DATA_DIR_ACTION, ha_emqx.ETC_DIFFERS]

    def test_the_docs_quote_the_engine(self):
        guide = (self.ROOT / 'docs' / 'backup.md').read_text(encoding='utf-8')
        if self.texts()[2] not in guide:
            self.skipTest('docs/backup.md does not hold the EMQX-B text yet: the lane\'s snippets are not merged')
        for text in self.texts():
            self.assertIn(text, guide)

        def bare(text):
            return re.sub(r'\s+', '', text)
        contract = bare((self.ROOT / 'docs' / 'backup' / 'CONTRACT.md').read_text(encoding='utf-8'))
        if bare(self.texts()[2]) not in contract:
            self.skipTest('CONTRACT.md does not hold the EMQX-B text yet: the lane\'s snippets are not merged')
        for text in self.texts():
            self.assertIn(bare(text), contract)


if __name__ == '__main__':
    unittest.main()
