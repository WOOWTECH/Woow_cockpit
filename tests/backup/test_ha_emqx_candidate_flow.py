"""Internal conversion chain with fixture Podman transport, never a real broker. HAOS parity (D0): HA's authorization and
authentication are what the candidate holds after the import (`ha_authorization`, `readings`); this device's other
settings are loaded back; what changed in the settings the old protections refused is now listed or applied."""
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
from woowbackup import haissues
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from .test_ha_emqx import export_listing


def response(config):
    return Result(0, b'WOOWCFG:' + base64.b64encode(json.dumps(config).encode()) + b':END\nok\n', b'')


ETC_REPLY = b'WOOWETC:/opt/emqx/etc:ENDok\n'
RECEIPT_REPLY = ('WOOWTAB:' + ''.join(f'{t}:0:{"A" * 64};' for t in emqx.STABLE_TABLES) + ':ENDok').encode()
HA_AUTHORIZATION = {'no_match': 'allow', 'deny_action': 'ignore',
                    'sources': [{'type': 'file', 'enable': True, 'path': '/opt/emqx/data/authz/acl.conf'}]}


def ha_readings(**changes):
    """What HA's broker answered (ha_broker's readings) as far as the candidate needs it."""
    readings = {'default_admin': False, 'counts': {t: 0 for t in emqx.TABLES}, 'roots': set(),
                'authn': [{'mechanism': 'password_based', 'backend': 'built_in_database', 'enable': True,
                           'algorithm': 'sha256', 'salt': 'suffix'}],
                'authz': [{'type': 'file', 'enable': True}], 'strict': ('allow', 'ignore'), 'hashing': None, 'plain': None,
                'hash_unreadable': False, 'ticker': True}
    readings.update(changes)
    return readings


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
        self.ha_authorization = copy.deepcopy(HA_AUTHORIZATION)
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
        names_acl = any(isinstance(s, dict) and s.get('path') == '/opt/emqx/data/authz/custom.acl'
                        for s in self.config['authorization']['sources'])
        assert self.missing or not names_acl or 'authz/custom.acl' in self.seed
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
                     emqx.STRICT_EXPR: '{%s,%s}' % (self.running_config['authorization'].get('no_match', 'allow'),
                                                    self.running_config['authorization'].get('deny_action', 'ignore')),
                     emqx.AUTHN_EXPR: '[{password_based,built_in_database,true,sha256,suffix}]'}[expression]
            return Result(0, value.encode(), b'')
        if command[:3] == ['emqx', 'ctl', 'status']:
            return Result(0, b'is started', b'')
        if command[:4] == ['emqx', 'ctl', 'data', 'import']:
            self.events.append('import')
            self.running_config['authorization'] = copy.deepcopy(self.ha_authorization)
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
    def invoke(self, transport, readings=True, notes=None):
        """The conversion's candidate from a generated transport. `readings`: HA's broker's (True: ha_readings())."""
        readings = ha_readings() if readings is True else readings
        with tempfile.TemporaryDirectory() as directory:
            staging = Path(directory)
            export = staging / 'source.tar.gz'
            export.write_bytes(b'fixture export')
            work = SimpleNamespace(runner=lambda app: transport, abort=None,
                guard=SimpleNamespace(budget=lambda: 1000000), checkpoint=lambda: None,
                log=transport.logs.append)
            target = SimpleNamespace(container='lab-target', data_volume='fixture-data', image='fixture',
                env={}, secrets=getattr(transport, 'secret_specs', []), files=[('/fixture/acl.conf', '/opt/emqx/etc/acl.conf', 'ro')])
            return emqx.candidate_from_target(work, 'app', transport, target, staging, export, (1000, 1000),
                                              readings=readings, notes=notes)

    def test_acquisition_snapshot_seed_import_restore_readback(self):
        """HA's authorization is what the candidate holds after the import (D0); this device's other roots are its own."""
        transport = Transport()
        self.assertEqual(len(self.invoke(transport)), 4)
        self.assertEqual(transport.running_config['authorization'], HA_AUTHORIZATION)
        self.assertEqual({k: v for k, v in transport.running_config.items() if k != 'authorization'},
                         {k: v for k, v in transport.config.items() if k != 'authorization'})
        self.assertEqual(transport.seed['authz/custom.acl'], b'{deny, all}.')
        for first, second in [('export', 'seed'), ('seed', 'start'), ('start', 'check-export'), ('check-export', 'import')]:
            self.assertLess(transport.events.index(first), transport.events.index(second))
        self.assertNotIn('restore', transport.events, 'nothing of this device had to be loaded back: no settings were lost')
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
        self.assertNotIn('retainer', getattr(transport, 'restore', {}))
        self.assertEqual(transport.running_config['retainer'], source)
        for root in ('node', 'listeners'):
            self.assertEqual(transport.running_config[root], transport.config[root])
        self.assertEqual(transport.running_config['authorization'], HA_AUTHORIZATION)

    def test_retainer_raw_omissions_and_ram_are_not_rewritten_as_disc(self):
        for source in ({}, {'backend': {'storage_type': 'ram'}},
                       {'msg_expiry_interval': '0s'}):
            config = {'retainer': source, 'node': {'name': 'target@localhost'}}
            self.assertEqual(emqx.preserved_settings(config), {'node': config['node']})
            self.assertEqual(config['retainer'], source)

    def test_actual_entry_preserves_known_mount_config_when_override_is_absent(self):
        transport=Transport();transport.override_absent=True;transport.override_states=['absent']
        self.assertEqual(len(self.invoke(transport)),4)
        self.assertEqual(transport.running_config['listeners'],transport.config['listeners'])
        self.assertNotIn('configs/cluster.hocon',transport.seed)
        self.assertEqual(transport.seed['authz/custom.acl'],b'{deny, all}.')
        self.assertEqual(transport.override_reads,2)

    def test_absence_does_not_skip_explicit_cluster_reference_or_moving_state(self):
        for changed in ('explicit','moving','unexpected-present'):
            transport=Transport();transport.override_absent=True;transport.override_states=['absent']
            if changed=='explicit':transport.config['authorization']['sources'][0]['path']='/opt/emqx/data/configs/cluster.hocon'
            if changed=='moving':transport.override_states=['absent','present']
            if changed=='unexpected-present':transport.override_absent=False
            with self.subTest(changed=changed),self.assertRaises(BackupError):self.invoke(transport)
            self.assertNotIn('start',transport.events)

    def test_a_file_the_settings_name_that_is_not_there_is_said_not_refused(self):
        """E-55: this device's own broker has the same hole; the candidate starts without the file and the notes say so."""
        transport = Transport()
        transport.missing = True
        notes = {}
        self.assertEqual(len(self.invoke(transport, notes=notes)), 4)
        self.assertEqual(notes['missing'], ['authz/custom.acl'])
        self.assertIn('start', transport.events)

    def test_a_hole_stays_a_stop_for_every_other_unsafe_thing(self):
        """E-55 relaxes only the missing file: a link, a double or a too large file still stops (target_config_snapshot)."""
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as archive:
            link = tarfile.TarInfo('authz/custom.acl')
            link.type, link.linkname = tarfile.SYMTYPE, '/etc/passwd'
            archive.addfile(link)
            data = b'x'
            info = tarfile.TarInfo('configs/cluster.hocon')
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'volume.tar'
            source.write_bytes(raw.getvalue())
            with self.assertRaises(BackupError):
                emqx.target_config_snapshot(source, Path(directory) / 'snapshot.tar', {'configs/cluster.hocon', 'authz/custom.acl'},
                                            missing=[])

    def test_a_missing_override_file_that_metadata_says_is_there_still_stops(self):
        transport = Transport()
        transport.override_absent = True
        transport.override_states = ['present']
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

    class ImportMovesAnOperationalRoot(Transport):
        """HA's import changed one of this device's own roots: the candidate must load it back (E-72)."""
        def exec(self, role, command, **kwargs):
            result = super().exec(role, command, **kwargs)
            if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                self.running_config['mqtt'] = {'max_packet_size': '9MB'}
            return result

    def moved(self, **fields):
        transport = self.ImportMovesAnOperationalRoot()
        transport.config['mqtt'] = {'max_packet_size': '1MB'}
        transport.running_config = copy.deepcopy(transport.config)
        for name, value in fields.items():
            setattr(transport, name, value)
        return transport

    def test_failed_restore_is_rejected(self):
        transport = self.moved(restore_bad=True)
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertIn('restore', transport.events)

    def test_a_live_config_that_changes_while_it_is_read_is_read_again(self):
        """E-58: the whole read is made again; the app goes on and the notes say it did."""
        class MovesOnce(Transport):
            moved = False

            def relay(self, *args, **kwargs):
                super().relay(*args, **kwargs)
                if not self.moved:
                    self.moved = True
                    self.config['authorization']['deny_action'] = 'disconnect'
        transport = MovesOnce()
        notes = {}
        self.assertEqual(len(self.invoke(transport, notes=notes)), 4)
        self.assertEqual(notes['rereads'], 1)
        self.assertIn('start', transport.events)

    def test_a_live_config_that_never_stops_changing_stops_only_this_app(self):
        class NeverStops(Transport):
            count = 0

            def relay(self, *args, **kwargs):
                super().relay(*args, **kwargs)
                NeverStops.count += 1
                self.config['authorization']['cache'] = {'max_size': 10 + NeverStops.count}
        transport = NeverStops()
        with self.assertRaises(BackupError) as caught:
            self.invoke(transport)
        self.assertEqual([issue.id for issue in caught.exception.issues], ['emqx.config-changing'])
        self.assertIn('不要', caught.exception.issues[0].action)
        self.assertNotIn('start', transport.events)
        self.assertEqual(NeverStops.count, emqx.CAPTURE_ATTEMPTS)

    def test_a_candidate_that_boots_unlike_the_live_config_is_listed_not_refused(self):
        """E-60: a setting changed and not yet restarted: the roots are said, what the files give is the baseline."""
        transport = Transport()
        transport.running_config['authorization']['deny_action'] = 'disconnect'
        notes = {}
        self.assertEqual(len(self.invoke(transport, notes=notes)), 4)
        self.assertEqual(notes['differs'], ['authorization'])
        self.assertIn('import', transport.events)

    def test_only_another_node_name_stops_the_candidate(self):
        transport = Transport()
        transport.config['node'] = {'name': 'emqx@127.0.0.1', 'data_dir': '/opt/emqx/data'}
        transport.running_config = copy.deepcopy(transport.config)
        transport.running_config['node'] = {'name': 'other@127.0.0.1', 'data_dir': '/opt/emqx/data'}
        with self.assertRaises(BackupError) as caught:
            self.invoke(transport)
        self.assertIn('節點名稱', caught.exception.message)
        self.assertNotIn('import', transport.events)
        other = Transport()
        other.config['node'] = {'name': 'emqx@127.0.0.1', 'data_dir': '/opt/emqx/data', 'process_limit': 2097152}
        other.running_config = copy.deepcopy(other.config)
        other.running_config['node'] = {'name': 'emqx@127.0.0.1', 'data_dir': '/opt/emqx/data', 'process_limit': 1000}
        notes = {}
        self.invoke(other, notes=notes)
        self.assertEqual(notes['differs'], ['node'])

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
        class FailedLoad(self.ImportMovesAnOperationalRoot):
            def exec(self, role, command, **kwargs):
                if command[:4] == ['emqx', 'ctl', 'conf', 'load']:
                    return Result(1, b'secret-config', b'secret-error')
                return super().exec(role, command, **kwargs)
        transport = FailedLoad()
        transport.config['mqtt'] = {'max_packet_size': '1MB'}
        transport.running_config = copy.deepcopy(transport.config)
        with self.assertRaises(BackupError) as caught:
            self.invoke(transport)
        self.assertNotIn('secret', str(caught.exception))

class FixedBuildStageTests(unittest.TestCase):
    def work(self, observer=None, **fields):
        work = SimpleNamespace(addon_info=lambda _: SimpleNamespace(version='5.9.1'), phase=lambda _: None,
                               choice=lambda *_: None, sink=lambda app: haissues.Sink(app.id), **fields)
        if observer is not None:
            work._emqx_build_stage = observer
        return work

    def test_real_node_guard_refuses_identically_and_observer_never_receives_values(self):
        """A database whose node name EMQX would not take is refused before HA's broker starts (E-06..E-09: the name is the
        one thing the data cannot do without); the observer never sees the name."""
        from unittest.mock import patch
        src=emqx.Source();src.node_file='generated-private-invalid-node';src.node_dirs={'generated private@127.0.0.1'}
        errors=[]
        for observed in (False,True):
            events=[]
            work=self.work(events.append if observed else None)
            with patch.object(emqx,'member_pass',return_value=src),patch.object(emqx,'ha_broker') as broker:
                with self.assertRaises(BackupError) as failure:
                    emqx._build_candidate(work,SimpleNamespace(id='emqx'),object(),object(),Path('/unused'),version='5.8.9')
                broker.assert_not_called()
            errors.append(str(failure.exception))
            self.assertEqual(events,['version','member_pass','node_name'] if observed else [])
            self.assertEqual([issue.id for issue in failure.exception.issues], ['emqx.node-gone'])
            self.assertNotIn('generated-private',' '.join(events))
        self.assertEqual(errors[0],errors[1])
