"""Operational preservation through candidate entry (fixture transport). HAOS parity (lane EMQX-B): this device's own settings
are no longer judged against reviewed lists (E-23, E-24, E-29, E-30, E-32..E-37, E-39, E-40, E-45, E-46, E-50): the candidate
starts with them as they are, every setting is scanned for the files it names, a data directory that is not the image's (E-36)
and a place for logs the candidate cannot be given (E-35) are what is left to stop one app; what this device has of its own
that HA's import is mixed with -- rules, connectors, rewrite, PSK, plugins, durable sessions -- is named in the one
confirmation (E-41, E-42, E-43, E-44, E-47)."""
import copy
import unittest
from types import SimpleNamespace
from woowbackup.errors import BackupError
from woowbackup import ha_emqx, ha_emqx_settings, haissues
from . import test_ha_emqx as base
from . import test_ha_emqx_candidate_flow as flow
from . import test_ha_emqx_parity as parity
from .test_ha_emqx_fileless_roots import FilesTransport


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
        'api_key': {'bootstrap_file': ''}, 'psk_authentication': {'enable': False, 'init_file': ''}}

    def test_a_setting_is_a_file_by_its_name_or_by_an_absolute_data_path(self):
        found = ha_emqx.file_scan(copy.deepcopy(self.CONFIG))
        self.assertEqual(found['data'], {'authz/acl.conf', 'certs/listeners/ssl/default/key.pem', 'secrets/erp.txt',
                                         'certs/connectors/http/erp/ca.pem', 'configs/stomp.csv'})
        self.assertEqual(found['outputs'], {'/opt/emqx/log/erl_crash.dump', '/var/log/emqx/emqx.log'})
        self.assertEqual(found['not_carried'], set(), 'topics, URLs, SQL, empty settings and the authenticators\' own bootstrap '
                                                    'files (bootstrap_references\') are no files of this scan')

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
        self.assertEqual(self.plan({'/var/log/emqx/emqx.log', '/srv/dumps/erl_crash.dump'}, '/opt/emqx/log'),
                         (['/srv/dumps', '/var/log/emqx'], [], []))
        self.assertEqual(self.plan(set(), '/srv/emqx-logs'), (['/srv/emqx-logs'], [], []), 'EMQX_LOG_DIR itself')

    def test_this_devices_own_mount_of_a_log_folder_gives_way_and_is_never_mounted_for_writing(self):
        mounts = [('/home/u/logs', '/var/log/emqx', 'ro')]
        self.assertEqual(self.plan({'/var/log/emqx/emqx.log'}, '/opt/emqx/log', mounts),
                         (['/var/log/emqx'], ['/var/log/emqx'], []))
        self.assertEqual(self.plan({'/var/log/emqx/sub/emqx.log'}, '/opt/emqx/log', mounts), ([], [], ['/var/log/emqx/sub']),
                         'a folder below a mount cannot be mounted in it')

    def test_a_place_that_holds_the_images_own_files_cannot_be_given(self):
        for path in ('/opt/emqx/etc/e.log', '/opt/emqx/bin/e.log', '/opt/emqx/lib/x/e.log', '/opt/emqx/e.log', '/e.log',
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
        self.assertEqual(ha_emqx_settings.own_items({}), {'integrations': [], 'routing': [], 'psk': [], 'plugins': [], 'durable': [],
                                                         'replaced': {k: 0 for k in ('integrations', 'routing', 'psk', 'plugins', 'durable')}})

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

    def test_a_setting_of_an_unexpected_shape_is_still_one_name_and_never_a_crash(self):
        for config in ({'connectors': 5, 'rule_engine': {'rules': [1]}, 'topic_metrics': 'x', 'exhook': {'servers': 3},
                        'plugins': {'states': 'x'}, 'durable_sessions': 'x', 'gateway': 'g', 'auto_subscribe': 'a',
                        'psk_authentication': 'p', 'actions': {'http': 'x'}}, {'rule_engine': None, 'plugins': []}):
            own = ha_emqx_settings.own_items(config, config)
            self.assertTrue(any(own[kind] for kind in ('integrations', 'routing', 'psk', 'plugins')) or not any(config.values()))


if __name__ == '__main__':
    unittest.main()
