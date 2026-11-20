"""Bootstrap integration through candidate entry; fixture transport, no real secrets."""
import copy
import unittest
from woowbackup import ha_emqx as emqx
from woowbackup.errors import BackupError
from woowbackup.podman import Result
from . import test_ha_emqx_candidate_flow as flow

PATH = '/opt/emqx/etc/woow-mqtt-bootstrap.csv'
SPEC = 'fixture-bootstrap,type=mount,target=' + PATH + ',uid=1000,gid=1000,mode=0400'

class BootstrapTransport(flow.Transport):
    def __init__(self):
        super().__init__()
        self.config['authentication'] = [{'mechanism': 'password_based', 'backend': 'built_in_database',
            'bootstrap_file': PATH, 'bootstrap_type': 'plain'}]
        self.running_config = copy.deepcopy(self.config)
        self.secret_specs = [SPEC]
        self.readable = True

    def run(self, *args, **kwargs):
        self.started_secrets = kwargs['secrets']
        super().run(*args, **kwargs)

    def exec(self, role, command, **kwargs):
        if command == ['test', '-f', PATH, '-a', '-r', PATH]:
            self.events.append('bootstrap-readable')
            return Result(0 if self.readable else 1, b'', b'')
        return super().exec(role, command, **kwargs)


class BootstrapFlowTests(unittest.TestCase):
    def invoke(self, transport):
        return flow.CandidateFlowTests.invoke(self, transport)

    def test_secret_stays_mounted_and_never_enters_snapshot(self):
        transport = BootstrapTransport()
        self.invoke(transport)
        self.assertEqual(transport.started_secrets, [SPEC])
        self.assertFalse(any('bootstrap' in name for name in transport.seed))
        self.assertLess(transport.events.index('bootstrap-readable'), transport.events.index('import'))
        self.assertFalse(any(SPEC in line for line in transport.logs))

    def test_unreadable_mount_blocks_before_import(self):
        transport = BootstrapTransport()
        transport.readable = False
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertNotIn('import', transport.events)

    def test_missing_duplicate_env_and_public_mode_block_before_export(self):
        for specs in [[], [SPEC, SPEC], [SPEC.replace('type=mount', 'type=env')],
                      [SPEC.replace('0400', '0644')], [SPEC + ',mode=0400']]:
            with self.subTest(specs=specs):
                transport = BootstrapTransport()
                transport.secret_specs = specs
                with self.assertRaises(BackupError):
                    self.invoke(transport)
                self.assertNotIn('export', transport.events)

    def test_relative_interpolated_and_unknown_schema_block(self):
        for key, value in [('bootstrap_file', '${EMQX_ETC_DIR}/bootstrap.csv'),
                           ('bootstrap_file', '../bootstrap.csv'), ('backend', 'redis'),
                           ('bootstrap_type', 'unknown')]:
            with self.subTest(key=key, value=value):
                transport = BootstrapTransport()
                transport.config['authentication'][0][key] = value
                with self.assertRaises(BackupError):
                    self.invoke(transport)
                self.assertNotIn('export', transport.events)

    def test_explicit_readonly_file_supported_but_shadowing_rejected(self):
        config = BootstrapTransport().config
        mounts = [('/fixture/bootstrap.csv', PATH, 'ro')]
        self.assertEqual(emqx.bootstrap_references(config, mounts, []), {PATH})
        with self.assertRaises(BackupError):
            emqx.bootstrap_references(config, mounts, [SPEC])

    def test_ha_import_cannot_leave_unresolved_bootstrap_for_restart(self):
        class ChangedBootstrap(BootstrapTransport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['authentication'][0]['bootstrap_file'] = '/data/ha-only.csv'
                return result
        transport = ChangedBootstrap()
        with self.assertRaises(BackupError):
            self.invoke(transport)
        self.assertIn('import', transport.events)
        self.assertIn('restore', transport.events)
