"""Actual internal product entry, generated transport only; no broker/lab. HAOS parity (D0): HA's authorization sources
replace this device's after the import, so this device's own sources are no longer judged (E-26, E-27, E-31) and a built-in
database source HA does not have is switched off before it is removed (EMQX clears the ACL rules of a source it destroys)."""
import copy
import json
import unittest

from woowbackup import ha_emqx as emqx
from woowbackup.errors import BackupError
from . import test_ha_emqx_candidate_flow as flow


class BuiltinProductFlowTests(unittest.TestCase):
    def invoke(self, transport, readings=True, notes=None):
        return flow.CandidateFlowTests.invoke(self, transport, readings=readings, notes=notes)

    def fixture(self, source):
        transport = flow.Transport()
        transport.config['authorization']['sources'].append(source)
        transport.running_config = copy.deepcopy(transport.config)
        return transport

    def test_this_devices_own_sources_of_any_shape_are_no_longer_refused(self):
        """E-26, E-27, E-31: a disabled source, an extra field, a limit other than 100, another type: HA's replace them."""
        for source in ({'type': 'built_in_database', 'enable': True}, {'type': 'built_in_database', 'enable': False},
                       {'type': 'built_in_database', 'enable': True, 'max_rules': 101},
                       {'type': 'built_in_database', 'enable': True, 'loader': {}}, {'type': 'built_in_database'},
                       {'type': 'redis', 'enable': True}, {'type': 'http', 'enable': True, 'url': 'http://auth.invalid/'}):
            transport = self.fixture(source)
            with self.subTest(source=sorted(source)):
                self.assertEqual(len(self.invoke(transport)), 4)
                self.assertIn('import', transport.events)
                self.assertEqual(transport.running_config['authorization'], flow.HA_AUTHORIZATION)

    def test_a_file_reference_of_an_unknown_kind_is_found_by_the_generic_scan(self):
        """E-50 (HAOS parity, EMQX-B): a `path` field of a built-in source is no file setting to the scan (only a file source's
        is) and stops nothing; the file settings of every source are scanned wherever they are."""
        transport = self.fixture({'type': 'built_in_database', 'enable': False, 'path': '/fixture/loader'})
        self.assertEqual(len(self.invoke(transport)), 4)
        self.assertIn('export', transport.events)

    def test_a_list_of_sources_that_cannot_be_read_still_stops(self):
        for sources in (None, 'x', [1]):
            transport = flow.Transport()
            transport.config['authorization']['sources'] = sources
            transport.running_config = copy.deepcopy(transport.config)
            with self.subTest(sources=sources), self.assertRaises(BackupError):
                self.invoke(transport)
            self.assertNotIn('export', transport.events)

    def test_builtin_does_not_hide_a_file_in_either_order(self):
        """E-29, E-30 (HAOS parity, EMQX-B): where a file source's file is decides nothing about the import (HA's authorization
        replaces it); one in the data volume is carried in either order, one elsewhere is the candidate's the way it is this
        device's."""
        for reverse in (False, True):
            for path, carried in (('/outside/unmounted.acl', None), ('/opt/emqx/data/authz/custom.acl', 'authz/custom.acl')):
                t = self.fixture({'type': 'built_in_database', 'enable': True})
                t.config['authorization']['sources'][0]['path'] = path
                if reverse:
                    t.config['authorization']['sources'].reverse()
                t.running_config = copy.deepcopy(t.config)
                with self.subTest(reverse=reverse, path=path):
                    self.assertEqual(len(self.invoke(t)), 4)
                    self.assertIn('export', t.events)
                    if carried:
                        self.assertIn(carried, t.seed)

    def test_raw_reader_never_expands_or_drops_fields(self):
        self.assertIn('emqx:get_raw_config([])', emqx.CONFIG_EXPR)
        self.assertNotIn('emqx:get_config(', emqx.CONFIG_EXPR)
        for source in ({'type': 'built_in_database', 'enable': True},
                       {'type': 'built_in_database', 'enable': True, 'max_rules': 100}):
            config = self.fixture(source).config
            commands = []

            def execute(command):
                commands.append(command)
                return flow.response(config)
            self.assertEqual(emqx.read_effective_config(execute), config)
            self.assertEqual(commands, [['emqx', 'eval', emqx.CONFIG_EXPR]])

    def merging(self, device_sources, ha_sources, **fields):
        """A transport whose import MERGES (as EMQX does): HA's sources by type, what only this device has stays."""
        class Merge(flow.Transport):
            def __init__(self):
                super().__init__()
                self.loads = []

            def exec(self, role, command, **kwargs):
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    ha = copy.deepcopy(self.ha_authorization)
                    mine = copy.deepcopy(self.running_config['authorization'])
                    kinds = {s['type'] for s in ha['sources']}
                    ha['sources'] += [s for s in mine['sources'] if s['type'] not in kinds]
                    self.events.append('import')
                    self.running_config['authorization'] = ha
                    self.merge_ha_authentication()
                    return flow.Result(0, b'imported successfully', b'')
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'conf', 'load']:
                    self.loads.append(copy.deepcopy(self.restore))
                return result
        transport = Merge()
        transport.config['authorization']['sources'] = copy.deepcopy(device_sources)
        transport.running_config = copy.deepcopy(transport.config)
        transport.ha_authorization = {'no_match': 'allow', 'deny_action': 'ignore', 'sources': copy.deepcopy(ha_sources)}
        for name, value in fields.items():
            setattr(transport, name, value)
        return transport

    FILE = {'type': 'file', 'enable': True, 'path': '/opt/emqx/data/authz/custom.acl'}
    BUILTIN = {'type': 'built_in_database', 'enable': True}

    def test_ha_authorization_is_what_the_candidate_holds_in_ha_order(self):
        """D0, E-21: HA asks its built-in database (and its ACL rules count), this device only had a file."""
        ha = [dict(self.BUILTIN), dict(self.FILE)]
        transport = self.merging([self.FILE], ha)
        readings = flow.ha_readings(authz=[{'type': 'built_in_database', 'enable': True}, {'type': 'file', 'enable': True}])
        self.invoke(transport, readings=readings)
        self.assertEqual([s['type'] for s in transport.running_config['authorization']['sources']],
                         ['built_in_database', 'file'])
        self.assertEqual(transport.running_config['authorization']['no_match'], 'allow')

    def test_what_only_this_device_has_goes_and_a_built_in_source_is_switched_off_before_it_is_removed(self):
        """The corner: HA has no built-in source, this device's enabled one survives the merge. EMQX clears the ACL rules of a
        source it destroys, not of a disabled one: the load is made in two steps and the rows are counted afterwards."""
        transport = self.merging([self.FILE, self.BUILTIN], [self.FILE])
        self.invoke(transport)
        self.assertEqual(transport.running_config['authorization']['sources'], [self.FILE])
        self.assertEqual(len(transport.loads), 2)
        first, last = (load['authorization']['sources'] for load in transport.loads)
        self.assertIn({'type': 'built_in_database', 'enable': False}, first)
        self.assertEqual(last, [self.FILE])

    def test_the_no_match_rule_is_explicitly_ha_s_even_when_this_device_had_its_own(self):
        """D0, E-80: HA's 'allow' replaces this device's 'deny' (the merge would have kept a value only this device set)."""
        class KeepsDeny(flow.Transport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['authorization']['no_match'] = 'deny'   # the merge kept this device's value
                return result
        transport = KeepsDeny()
        self.invoke(transport)
        self.assertEqual(transport.running_config['authorization']['no_match'], 'allow')
        self.assertEqual(transport.restore['authorization']['no_match'], 'allow')

    def test_ha_disabled_source_stays_disabled_if_the_import_left_it_enabled(self):
        """A successful data import can leave a source's old enable flag; HA's reading decides the final flag."""
        transport = flow.Transport()
        readings = flow.ha_readings(authz=[{'type': 'file', 'enable': False}])
        self.invoke(transport, readings=readings)
        sources = transport.running_config['authorization']['sources']
        self.assertEqual(sources, [{'type': 'file', 'enable': False,
                                    'path': '/opt/emqx/data/authz/acl.conf'}])
        self.assertEqual(transport.restore['authorization']['sources'], sources)

    def test_an_authorization_that_does_not_become_ha_s_stops_the_app(self):
        """E-80: right after applying it, the setting must really be HA's."""
        class Ignores(flow.Transport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                    self.running_config['authorization']['no_match'] = 'deny'
                if command[:4] == ['emqx', 'ctl', 'conf', 'load']:
                    self.running_config['authorization']['no_match'] = 'deny'   # the load did not take
                return result
        with self.assertRaises(BackupError) as caught:
            self.invoke(Ignores())
        self.assertEqual(caught.exception.code, 'incompatible',
                         'the apply step must stop before later candidate checks')
        self.assertIn('帳號驗證或授權沒有成為 HA 的設定', caught.exception.message)

    def test_a_ha_without_any_authenticator_is_an_explicit_empty_list(self):
        """D5: left alone, the merge would keep this device's authenticators and nobody could reach HA's open broker."""
        transport = flow.Transport()
        transport.config['authentication'] = [{'mechanism': 'password_based', 'backend': 'built_in_database'}]
        transport.running_config = copy.deepcopy(transport.config)
        notes = {}
        self.invoke(transport, readings=flow.ha_readings(authn=[]), notes=notes)
        self.assertEqual(transport.running_config['authentication'], [])
        self.assertEqual(json.loads(json.dumps(transport.restore)), {'authentication': []})
