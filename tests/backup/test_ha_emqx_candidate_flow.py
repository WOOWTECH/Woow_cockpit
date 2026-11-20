"""Internal conversion chain with fixture Podman transport, never a real broker."""
import base64
import copy
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from woowbackup import ha_emqx as emqx
from woowbackup.errors import BackupError
from woowbackup.podman import Result


def response(config):
    return Result(0, b'WOOWCFG:' + base64.b64encode(json.dumps(config).encode()) + b':END\nok\n', b'')


class Transport:
    def __init__(self):
        self.config = {'authorization': {'no_match': 'deny', 'deny_action': 'ignore',
            'sources': [{'type': 'file', 'path': '/opt/emqx/data/authz/custom.acl'},
                        {'type': 'file', 'path': '/opt/emqx/etc/acl.conf'}]},
            'listeners': {'ssl': {'default': {'ssl_options': {'certfile': '/opt/emqx/data/certs/lab.pem'}}}}}
        self.events, self.seed = [], {}
        self.running_config = copy.deepcopy(self.config)
        self.live_response = None
        self.missing = False
        self.restore_bad = False
        self.logs = []

    def podman(self, *args, **kwargs):
        assert args[:2] == ('exec', 'lab-target')
        assert args[2:] == ('emqx', 'eval', emqx.CONFIG_EXPR)
        assert kwargs['max_output'] == emqx.MAX_HOCON
        self.events.append('read-live')
        return self.live_response or response(self.config)

    def relay(self, args, stdout, **kwargs):
        assert args == ['volume', 'export', 'fixture-data']
        self.events.append('export')
        files = {'configs/cluster.hocon': b'custom target configuration',
                 'authz/custom.acl': b'{deny, all}.', 'certs/lab.pem': b'fixture-only'}
        if self.missing:
            del files['authz/custom.acl']
        with tarfile.open(fileobj=stdout, mode='w|') as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

    def volume(self, role):
        self.events.append('volume:' + role)

    def volume_import(self, role, produce):
        out = io.BytesIO()
        produce(out)
        if role == 'emqx-new':
            with tarfile.open(fileobj=io.BytesIO(out.getvalue())) as archive:
                self.seed = {m.name: archive.extractfile(m).read() for m in archive if m.isfile()}
            self.events.append('seed')

    def name(self, role):
        return role

    def run(self, *args, **kwargs):
        assert 'authz/custom.acl' in self.seed
        assert 'certs/lab.pem' in self.seed
        self.events.append('start')

    def exec(self, role, command, **kwargs):
        if command == ['emqx', 'eval', emqx.CONFIG_EXPR]:
            self.events.append('read-candidate')
            return response(self.running_config)
        if command[:2] == ['emqx', 'eval']:
            expression = command[2]
            value = {emqx.COUNT_EXPR: '[' + ','.join('{%s,0}' % t for t in emqx.TABLES) + ']',
                     emqx.STRICT_EXPR: '{deny,ignore}',
                     emqx.AUTHN_EXPR: '[{password_based,built_in_database,true,sha256,suffix}]'}[expression]
            return Result(0, value.encode(), b'')
        if command[:3] == ['emqx', 'ctl', 'status']:
            return Result(0, b'is started', b'')
        if command[:4] == ['emqx', 'ctl', 'data', 'import']:
            self.events.append('import')
            self.running_config['authorization']['sources'] = []
            return Result(0, b'imported successfully', b'')
        if command[:2] == ['sh', '-c']:
            assert 'umask 077' in command[2]
            self.restore = json.loads(kwargs['input'])
            return Result(0, b'', b'')
        if command[:4] == ['emqx', 'ctl', 'conf', 'load']:
            self.events.append('restore')
            if not self.restore_bad:
                self.running_config.update(self.restore)
            return Result(0, b'', b'')
        raise AssertionError('unexpected command')


class CandidateFlowTests(unittest.TestCase):
    def invoke(self, transport):
        with tempfile.TemporaryDirectory() as directory:
            staging = Path(directory)
            export = staging / 'source.tar.gz'
            export.write_bytes(b'fixture export')
            work = SimpleNamespace(runner=lambda app: transport, abort=None,
                guard=SimpleNamespace(budget=lambda: 1000000), checkpoint=lambda: None,
                log=transport.logs.append)
            target = SimpleNamespace(container='lab-target', data_volume='fixture-data', image='fixture',
                env={}, secrets=[], files=[('/fixture/acl.conf', '/opt/emqx/etc/acl.conf', 'ro')])
            return emqx.candidate_from_target(work, 'app', transport, target, staging, export, (1000, 1000))

    def test_acquisition_snapshot_seed_import_restore_readback(self):
        transport = Transport()
        self.assertEqual(len(self.invoke(transport)), 4)
        self.assertEqual(transport.running_config, transport.config)
        self.assertEqual(transport.seed['authz/custom.acl'], b'{deny, all}.')
        for first, second in [('export', 'seed'), ('seed', 'start'), ('start', 'import'), ('import', 'restore')]:
            self.assertLess(transport.events.index(first), transport.events.index(second))
        self.assertEqual(transport.events[-1], 'read-candidate')

    def test_missing_reference_stops_before_start(self):
        transport = Transport()
        transport.missing = True
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertNotIn('start', transport.events)

    def test_bad_transport_and_json_never_leak_body(self):
        for body in [b'', b'secret-fixture-invalid', b'WOOWCFG:e30=:END\nok', b'WOOWCFG:!!!!:END']:
            with self.subTest(body=body):
                transport = Transport()
                transport.live_response = Result(0, body, b'secret-stderr')
                with self.assertRaises(BackupError) as caught:
                    self.invoke(transport)
                self.assertNotIn('secret', str(caught.exception))
                self.assertEqual(transport.logs, [])
                self.assertNotIn('export', transport.events)

    def test_unsupported_root_stops_before_export(self):
        transport = Transport()
        transport.config['connectors'] = {'unreviewed': {}}
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertNotIn('export', transport.events)

    def test_failed_restore_is_rejected(self):
        transport = Transport()
        transport.restore_bad = True
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertIn('restore', transport.events)

    def test_changed_live_config_stops_before_candidate_start(self):
        class MovingTarget(Transport):
            def relay(self, *args, **kwargs):
                super().relay(*args, **kwargs)
                self.config['authorization']['deny_action'] = 'disconnect'
        transport = MovingTarget()
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertNotIn('start', transport.events)

    def test_changed_candidate_config_stops_before_import(self):
        transport = Transport()
        transport.running_config['authorization']['deny_action'] = 'disconnect'
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertIn('start', transport.events)
        self.assertNotIn('import', transport.events)

    def test_transport_failure_stops_without_disclosing_output(self):
        transport = Transport()
        transport.live_response = Result(1, b'secret-stdout', b'secret-stderr')
        with self.assertRaises(BackupError) as caught:
            self.invoke(transport)
        self.assertNotIn('secret', str(caught.exception))
        self.assertNotIn('export', transport.events)

    def test_non_acl_settings_restored_without_erasing_ha_data_roots(self):
        class ImportChangesSettings(Transport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['mqtt'] = {'max_packet_size': '9MB', 'injected_field': True}
                    self.running_config['rule_engine'] = {'rules': {'ha-rule': {'enable': True}}}
                if command[:4] == ['emqx', 'ctl', 'conf', 'load']:
                    self.load_mode = command[4]
                return result
        transport = ImportChangesSettings()
        transport.config['mqtt'] = {'max_packet_size': '1MB'}
        transport.running_config = copy.deepcopy(transport.config)
        self.invoke(transport)
        self.assertEqual(transport.load_mode, '--replace')
        self.assertEqual(transport.running_config['mqtt'], {'max_packet_size': '1MB'})
        self.assertIn('ha-rule', transport.running_config['rule_engine']['rules'])
        self.assertNotIn('rule_engine', transport.restore)

    def test_unexpected_operational_root_refused_without_guessing_defaults(self):
        class ExtraRoot(Transport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['unknown_operational_root'] = {'enabled': True}
                return result
        transport = ExtraRoot()
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertNotIn('restore', transport.events)

    def test_restore_command_failure_suppresses_sensitive_error_body(self):
        class FailedLoad(Transport):
            def exec(self, role, command, **kwargs):
                if command[:4] == ['emqx', 'ctl', 'conf', 'load']:
                    return Result(1, b'secret-config', b'secret-error')
                return super().exec(role, command, **kwargs)
        with self.assertRaises(BackupError) as caught:
            self.invoke(FailedLoad())
        self.assertNotIn('secret', str(caught.exception))
