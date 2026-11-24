"""Internal conversion chain with fixture Podman transport, never a real broker."""
import base64
import copy
import hashlib
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

from .test_ha_emqx import export_listing


def response(config):
    return Result(0, b'WOOWCFG:' + base64.b64encode(json.dumps(config).encode()) + b':END\nok\n', b'')


ETC_REPLY = b'WOOWETC:/opt/emqx/etc:ENDok\n'
RECEIPT_REPLY = ('WOOWTAB:' + ''.join(f'{t}:0:{"A" * 64};' for t in emqx.STABLE_TABLES) + ':ENDok').encode()


class Transport:
    def __init__(self):
        # One file source: EMQX 5.8.9 refuses two sources of one type (emqx_authz.erl:145-148, 386-408
        # check_dup_types), so a running broker never has two file ACLs.
        self.config = {'authorization': {'no_match': 'deny', 'deny_action': 'ignore',
            'sources': [{'type': 'file', 'path': '/opt/emqx/data/authz/custom.acl'}]},
            'listeners': {'ssl': {'default': {'ssl_options': {'certfile': '/opt/emqx/data/certs/lab.pem'}}}}}
        self.events, self.seed = [], {}
        self.running_config = copy.deepcopy(self.config)
        self.live_response = None
        self.missing = False
        self.restore_bad = False
        self.override_absent = False
        self.override_states = ['present']
        self.override_reads = 0
        self.logs = []

    def podman(self, *args, **kwargs):
        if args == ('container', 'inspect', '--format', '{{.State.Running}}', 'lab-target'):
            self.events.append('inspect-live')
            return Result(0, b'true\n', b'')
        assert args[:2] == ('exec', 'lab-target')
        if args[2:] == ('emqx', 'eval', emqx.ETC_EXPR):
            return Result(0, ETC_REPLY, b'')
        if args[2:] == ('emqx','eval',emqx.OVERRIDE_STATE_EXPR):
            state=self.override_states[min(self.override_reads,len(self.override_states)-1)]
            self.override_reads+=1
            return Result(0,b'WOOWOVERRIDE:'+state.encode()+b':ENDok\n',b'')
        if args[2:] == ('emqx', 'eval', emqx.BOOT_CONFIG_EXPR):   # no schema defaults here: same answer, no event
            assert kwargs['max_output'] == emqx.MAX_HOCON
            return self.live_response or response(self.config)
        if args[2:] == ('emqx', 'eval', emqx.VM_EXPR):   # this device's schedulers (total, online); no event
            return Result(0, b'WOOWVM:4:4:END\nok\n', b'')
        assert args[2:] == ('emqx', 'eval', emqx.CONFIG_EXPR)
        assert kwargs['max_output'] == emqx.MAX_HOCON
        self.events.append('read-live')
        return self.live_response or response(self.config)

    def relay(self, args, stdout, **kwargs):
        assert args == ['volume', 'export', 'fixture-data']
        self.events.append('export')
        files = {'configs/cluster.hocon': b'custom target configuration',
                 'authz/custom.acl': b'{deny, all}.', 'certs/lab.pem': b'fixture-only'}
        if self.override_absent:del files['configs/cluster.hocon']
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
        self.run_env = dict(kwargs.get('env') or {})
        self.events.append('start')

    def exec(self, role, command, **kwargs):
        if command == ['emqx', 'eval', emqx.VM_EXPR]:
            # The candidate's VM: half the CPUs (tempctr --cpus) give 2 online schedulers unless ERL_AFLAGS sets them.
            flags = getattr(self, 'run_env', {}).get('ERL_AFLAGS', '')
            counts = flags[3:].encode() if flags.startswith('+S ') else b'4:2'
            return Result(0, b'WOOWVM:' + counts + b':END\nok\n', b'')
        if command == ['emqx', 'eval', emqx.BOOT_CONFIG_EXPR]:
            # The generated transport has no schema defaults: its boot form is its raw configuration (no event, so
            # the recorded read sequences stay those of the plain reads).
            return response(self.running_config)
        if command == ['emqx', 'eval', emqx.CONFIG_EXPR]:
            self.events.append('read-candidate')
            return response(self.running_config)
        if command == ['emqx', 'eval', emqx.export_expression('source.tar.gz')]:
            self.events.append('check-export')
            return Result(0, export_listing('source.tar.gz'), b'')
        if command == ['emqx', 'eval', emqx.ETC_EXPR]:
            return Result(0, ETC_REPLY, b'')
        if command == ['emqx', 'eval', emqx.TABLES_RECEIPT_EXPR]:
            self.events.append('receipt')
            return Result(0, RECEIPT_REPLY, b'')
        if command[:2] == ['emqx', 'eval']:
            expression = command[2]
            value = {emqx.SUSPEND_SYS_EXPR: 'WOOWSYS:<0.1.0>:suspended\nok',
                     emqx.TICKER_STATUS_EXPR.replace('{pid}', '<0.1.0>'): 'ticker_unchanged', emqx.COUNT_EXPR: '[' + ','.join('{%s,0}' % t for t in emqx.TABLES) + ']',
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
        if command[:1] == ['sha256sum'] and len(command) == 2 and command[1].startswith('/opt/emqx/data/'):
            # Security review SR-2 (2026-11-23): an untouched data-volume file answers its seeded bytes' digest;
            # `overwritten` models the vendor import rewriting it (emqx_authz_file.erl:69-75).
            name = command[1][len('/opt/emqx/data/'):]
            self.events.append('digest:' + name)
            data = getattr(self, 'overwritten', {}).get(name, self.seed.get(name))
            if data is None:
                return Result(1, b'', b'No such file or directory')
            return Result(0, hashlib.sha256(data).hexdigest().encode() + b'  ' + command[1].encode() + b'\n', b'')
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
                env={}, secrets=getattr(transport, 'secret_specs', []), files=[('/fixture/acl.conf', '/opt/emqx/etc/acl.conf', 'ro')])
            return emqx.candidate_from_target(work, 'app', transport, target, staging, export, (1000, 1000))

    def test_acquisition_snapshot_seed_import_restore_readback(self):
        transport = Transport()
        self.assertEqual(len(self.invoke(transport)), 4)
        self.assertEqual(transport.running_config, transport.config)
        self.assertEqual(transport.seed['authz/custom.acl'], b'{deny, all}.')
        for first, second in [('export', 'seed'), ('seed', 'start'), ('start', 'check-export'), ('check-export', 'import'),
                              ('import', 'restore')]:
            self.assertLess(transport.events.index(first), transport.events.index(second))
        self.assertEqual(transport.events[-1], 'read-candidate')

    def test_imported_retainer_storage_and_expiry_survive_operational_restore(self):
        source = {'backend': {'type': 'built_in_database', 'storage_type': 'disc'},
                  'msg_expiry_interval': '2h', 'msg_clear_interval': '1m'}
        class RetainerTransport(Transport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['retainer'] = copy.deepcopy(source)
                return result
        transport = RetainerTransport()
        transport.config.update({'retainer': {'backend': {'storage_type': 'ram'}},
                                 'node': {'name': 'target@localhost', 'data_dir': '/opt/emqx/data'},
                                 'listeners': {**transport.config['listeners'], 'tcp': {'default': {'bind': 1883}}}})
        transport.running_config = copy.deepcopy(transport.config)
        self.invoke(transport)
        self.assertIn('retainer', emqx.DATA_ROOTS)
        self.assertNotIn('retainer', transport.restore)
        self.assertEqual(transport.running_config['retainer'], source)
        for root in ('authorization', 'node', 'listeners'):
            self.assertEqual(transport.running_config[root], transport.config[root])

    def test_retainer_raw_omissions_and_ram_are_not_rewritten_as_disc(self):
        for source in ({}, {'backend': {'storage_type': 'ram'}},
                       {'msg_expiry_interval': '0s'}):
            config = {'retainer': source, 'node': {'name': 'target@localhost'}}
            self.assertEqual(emqx.preserved_settings(config), {'node': config['node']})
            self.assertEqual(config['retainer'], source)

    def test_actual_entry_preserves_known_mount_config_when_override_is_absent(self):
        transport=Transport();transport.override_absent=True;transport.override_states=['absent']
        self.assertEqual(len(self.invoke(transport)),4)
        self.assertEqual(transport.running_config,transport.config)
        self.assertNotIn('configs/cluster.hocon',transport.seed)
        self.assertEqual(transport.seed['authz/custom.acl'],b'{deny, all}.')
        self.assertEqual(transport.override_reads,2)

    def test_absence_does_not_skip_explicit_cluster_reference_or_moving_state(self):
        for changed in ('explicit','moving','missing-acl','unexpected-present'):
            transport=Transport();transport.override_absent=True;transport.override_states=['absent']
            if changed=='explicit':transport.config['authorization']['sources'][0]['path']='/opt/emqx/data/configs/cluster.hocon'
            if changed=='moving':transport.override_states=['absent','present']
            if changed=='missing-acl':transport.missing=True
            if changed=='unexpected-present':transport.override_absent=False
            with self.subTest(changed=changed),self.assertRaises(BackupError):self.invoke(transport)
            self.assertNotIn('start',transport.events)

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

class FixedBuildStageTests(unittest.TestCase):
    def test_version_refusal_still_precedes_member_or_broker_with_observer(self):
        from unittest.mock import patch
        events=[]
        work=SimpleNamespace(addon_info=lambda _:SimpleNamespace(version='unsupported'),
                             _emqx_build_stage=events.append)
        with patch.object(emqx,'member_pass') as member,patch.object(emqx,'ha_broker') as broker:
            with self.assertRaises(BackupError):
                emqx._build_candidate(work,SimpleNamespace(id='emqx'),object(),object(),Path('/unused'),version='5.8.9')
            member.assert_not_called();broker.assert_not_called()
        self.assertEqual(events,['version'])

    def test_real_node_guard_refuses_identically_and_observer_never_receives_values(self):
        from unittest.mock import patch
        src=emqx.Source();src.node_file='generated-private-invalid-node';src.node_dirs={'emqx@127.0.0.1'}
        errors=[]
        for observed in (False,True):
            events=[]
            work=SimpleNamespace(addon_info=lambda _:SimpleNamespace(version='5.9.1'),phase=lambda _:None)
            if observed:work._emqx_build_stage=events.append
            with patch.object(emqx,'member_pass',return_value=src),patch.object(emqx,'ha_broker') as broker:
                with self.assertRaises(BackupError) as failure:
                    emqx._build_candidate(work,SimpleNamespace(id='emqx'),object(),object(),Path('/unused'),version='5.8.9')
                broker.assert_not_called()
            errors.append(str(failure.exception))
            self.assertEqual(events,['version','member_pass','node_name'] if observed else [])
            self.assertNotIn('generated-private-invalid-node',' '.join(events))
        self.assertEqual(errors[0],errors[1])
