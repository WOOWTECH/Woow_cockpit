"""Bootstrap integration through candidate entry; fixture transport, no real secrets. HAOS parity: this device's own
pre-created MQTT accounts (the bootstrap file) stay attached to HA's built-in database authenticator when they can; when
they cannot (E-48, E-49, E-61, E-68, E-69) the import goes on and says so."""
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
    def invoke(self, transport, notes=None, readings=True):
        return flow.CandidateFlowTests.invoke(self, transport, readings=readings, notes=notes)

    def test_secret_stays_mounted_and_never_enters_snapshot(self):
        transport = BootstrapTransport()
        self.invoke(transport)
        self.assertEqual(transport.started_secrets, [SPEC])
        self.assertFalse(any('bootstrap' in name for name in transport.seed))
        self.assertLess(transport.events.index('bootstrap-readable'), transport.events.index('import'))
        self.assertFalse(any(SPEC in line for line in transport.logs))

    def test_an_unreadable_mount_is_said_and_the_import_goes_on(self):
        """E-61: the candidate cannot read the bootstrap file: the pre-created accounts may have to be made again."""
        transport = BootstrapTransport()
        transport.readable = False
        notes = {}
        self.invoke(transport, notes)
        self.assertIn('import', transport.events)
        self.assertEqual(notes['lost'], [PATH])
        self.assertNotIn('bootstrap_file', transport.running_config['authentication'][0])

    def test_missing_duplicate_env_and_public_mode_are_said_and_the_import_goes_on(self):
        """E-49: a bootstrap file that is not one unique restricted mount cannot follow the import."""
        for specs in [[], [SPEC, SPEC], [SPEC.replace('type=mount', 'type=env')],
                      [SPEC.replace('0400', '0644')], [SPEC + ',mode=0400']]:
            with self.subTest(specs=specs):
                transport = BootstrapTransport()
                transport.secret_specs = specs
                notes = {}
                self.invoke(transport, notes)
                self.assertIn('export', transport.events)
                self.assertIn('import', transport.events)
                self.assertEqual(notes['lost'][0], PATH)

    def test_relative_interpolated_and_unknown_schema_are_said_and_the_import_goes_on(self):
        """E-48: a bootstrap file of a kind or at a place this engine cannot follow."""
        for key, value, lost in [('bootstrap_file', '${EMQX_ETC_DIR}/bootstrap.csv', '${EMQX_ETC_DIR}/bootstrap.csv'),
                                 ('bootstrap_file', '../bootstrap.csv', '../bootstrap.csv'), ('backend', 'redis', PATH),
                                 ('bootstrap_type', 'unknown', PATH)]:
            with self.subTest(key=key, value=value):
                transport = BootstrapTransport()
                transport.config['authentication'][0][key] = value
                transport.running_config = copy.deepcopy(transport.config)
                notes = {}
                self.invoke(transport, notes)
                self.assertIn('export', transport.events)
                self.assertEqual(notes['lost'][0], lost)

    def test_a_lost_bootstrap_path_is_not_reattached_to_ha_authentication(self):
        """E-48: the imported HA authenticator cannot revive this device's unsupported bootstrap path."""
        class ImportWithoutBootstrap(BootstrapTransport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['authentication'][0].pop('bootstrap_file', None)
                    self.running_config['authentication'][0].pop('bootstrap_type', None)
                return result

        transport = ImportWithoutBootstrap()
        transport.config['authentication'][0]['bootstrap_file'] = '../bootstrap.csv'
        transport.running_config = copy.deepcopy(transport.config)
        notes = {}
        self.invoke(transport, notes)
        self.assertIn('../bootstrap.csv', notes['lost'])
        self.assertNotIn('bootstrap_file', transport.running_config['authentication'][0])

        retained = BootstrapTransport()   # EMQX may merge HA's row without removing this device's file field.
        retained.config['authentication'][0]['bootstrap_file'] = '../bootstrap.csv'
        retained.running_config = copy.deepcopy(retained.config)
        notes = {}
        self.invoke(retained, notes)
        self.assertIn('../bootstrap.csv', notes['lost'])
        self.assertNotIn('bootstrap_file', retained.running_config['authentication'][0])

    def test_explicit_readonly_file_supported_but_shadowing_rejected(self):
        config = BootstrapTransport().config
        mounts = [('/fixture/bootstrap.csv', PATH, 'ro')]
        self.assertEqual(emqx.bootstrap_references(config, mounts, []), {PATH})
        with self.assertRaises(BackupError):
            emqx.bootstrap_references(config, mounts, [SPEC])
        lost = []   # E-48/E-49: asked to collect, the same shadowing is only said
        self.assertEqual(emqx.bootstrap_references(config, mounts, [SPEC], lost=lost), set())
        self.assertEqual(lost, [PATH])

    def test_ha_import_restores_target_bootstrap_before_restart(self):
        class ChangedBootstrap(BootstrapTransport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['authentication'][0]['bootstrap_file'] = '/data/ha-only.csv'
                return result
        transport = ChangedBootstrap()
        self.invoke(transport)
        self.assertEqual(transport.running_config['authentication'][0]['bootstrap_file'], PATH)
        self.assertIn('import', transport.events)
        self.assertIn('restore', transport.events)

    def test_plain_bootstrap_keeps_source_password_algorithm(self):
        class Changed(BootstrapTransport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    row = self.running_config['authentication'][0]
                    row['bootstrap_file'] = '${EMQX_ETC_DIR}/auth-built-in-db-bootstrap.csv'
                    row['password_hash_algorithm'] = {'name': 'bcrypt'}
                return result
        transport = Changed()
        self.invoke(transport)
        row = transport.running_config['authentication'][0]
        self.assertEqual(row['bootstrap_file'], PATH)
        self.assertEqual(row['password_hash_algorithm'], {'name': 'bcrypt'})

    def test_a_hash_bootstrap_file_of_another_hashing_is_said_not_attached(self):
        """E-69: HA hashes differently than this device's `hash` bootstrap file: the import goes on, the accounts are said."""
        class Changed(BootstrapTransport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    row = self.running_config['authentication'][0]
                    row['password_hash_algorithm'] = {'name': 'bcrypt'}
                    row.pop('bootstrap_file')
                    row.pop('bootstrap_type')
                return result
        transport = Changed()
        transport.config['authentication'][0].update(bootstrap_type='hash', password_hash_algorithm={'name': 'sha256'})
        transport.running_config = copy.deepcopy(transport.config)
        notes = {}
        self.invoke(transport, notes)
        self.assertEqual(notes['bootstrap'], ['hash'])
        self.assertNotIn('bootstrap_file', transport.running_config['authentication'][0])

    def test_bootstrap_readback_mismatch_is_rejected(self):
        class Changed(BootstrapTransport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] in (['emqx', 'ctl', 'data', 'import'], ['emqx', 'ctl', 'conf', 'load']):
                    self.running_config['authentication'][0]['bootstrap_file'] = '/unresolved/bootstrap.csv'
                return result
        with self.assertRaises(BackupError):
            self.invoke(Changed())

    def test_a_ha_authenticator_that_does_not_match_the_bootstrap_identity_is_said(self):
        """E-68: HA's built-in database authenticator takes the client id as the account (this device's takes the user
        name): this device's pre-created accounts have no authenticator to live in; the import goes on."""
        class Changed(BootstrapTransport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    row = self.running_config['authentication'][0]
                    row['user_id_type'] = 'clientid'
                    row.pop('bootstrap_file')
                return result
        transport = Changed()
        notes = {}
        self.invoke(transport, notes)
        self.assertEqual(notes['bootstrap'], ['ha-authn'])
        self.assertNotIn('bootstrap_file', transport.running_config['authentication'][0])

    def test_a_ha_authenticator_that_is_switched_off_leaves_the_accounts_unattached(self):
        class Off(BootstrapTransport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['authentication'][0].update(enable=False)
                    self.running_config['authentication'][0].pop('bootstrap_file')
                return result
        transport = Off()
        notes = {}
        self.invoke(transport, notes)
        self.assertEqual(notes['bootstrap'], ['ha-authn'])
