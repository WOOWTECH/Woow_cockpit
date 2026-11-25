"""EMQX HA import security review 2026-11-23 (lane emqx-secreview), regression tests.

SR-1 (B1-06, port of e848015): a crafted HA backup's cluster.hocon named a plugin staged under certs/ and HA's broker
loaded and started it (EMQX 5.8.9 emqx_plugins_app.erl:31-33, emqx_plugins.erl:310-321,1023-1066). HA's broker now
pins `plugins.states = []` and the image's plugin folder through the environment (which wins over cluster.hocon) and
mounts every writable volume noexec,nosuid,nodev.

SR-2 (B1-02 reopened once the public guard goes): this device's file ACL in the data volume
(/opt/emqx/data/authz/acl.conf, where the Dashboard writes edited rules) was overwritten by HA's file ACL during the
import (emqx_authz_file.erl:64-75,120-121) while every configuration comparison stayed equal. The conversion refused it.
HAOS parity (D3, E-75): HAOS replaces the folder, so HA's ACL file replaces this device's: a notice names the file, nothing is
written back; every other data-volume file (a certificate, a key) must still reach the candidate byte for byte.

SR-3, SR-6, SR-7 (E-76, E-77, E-78, E-79; owner decision D4 = S1): what can read this device's files or environment or receive
client credentials is no longer refused: HA's settings run as they are and the customer confirms the NAMES (one line each).
"""
import copy
import hashlib
import io
import tarfile
import unittest

from woowbackup import ha_emqx
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import test_ha_emqx as base
from . import test_ha_emqx_candidate_flow as flow

DEVICE_ACL = b'{allow, {username, "woow"}, all, ["#"]}.\n{deny, all}.\n'
HA_ACL = b'{allow, all}.\n'
DATA_ACL = '/opt/emqx/data/authz/acl.conf'


def with_acl(raw):
    """The fake volume export plus authz/acl.conf (the device's file, uid 1000 like the image user)."""
    out = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw)) as source, tarfile.open(fileobj=out, mode='w',
                                                                         format=tarfile.PAX_FORMAT) as dest:
        for member in source:
            dest.addfile(member, source.extractfile(member) if member.isfile() else None)
        folder = tarfile.TarInfo('authz'); folder.type = tarfile.DIRTYPE; folder.mode = 0o755
        folder.uid = folder.gid = 1000
        dest.addfile(folder)
        acl = tarfile.TarInfo('authz/acl.conf'); acl.size = len(DEVICE_ACL); acl.mode = 0o644
        acl.uid = acl.gid = 1000
        dest.addfile(acl, io.BytesIO(DEVICE_ACL))
    return out.getvalue()


class DataAclWorld(base.World):
    """This device keeps its file ACL in the data volume; `candidate_acl` is what the candidate's file holds after
    HA's import (HA_ACL = the vendor overwrote it)."""

    def __init__(self):
        super().__init__()
        self.target_config = {'authorization': {'no_match': 'deny', 'deny_action': 'ignore',
                                                'sources': [{'type': 'file', 'enable': True, 'path': DATA_ACL}]}}
        self.current_config = copy.deepcopy(self.target_config)
        self.candidate_acl = DEVICE_ACL
        self.hashed = []

    def exec(self, role, command, data, stdout):
        if role == 'emqx-new' and command == ['sha256sum', DATA_ACL]:
            self.hashed.append(command[1])
            line = hashlib.sha256(self.candidate_acl).hexdigest().encode() + b'  ' + DATA_ACL.encode() + b'\n'
            return Result(0, line, b'')
        return super().exec(role, command, data, stdout)

    def export(self, volume):
        raw = super().export(volume)
        return raw if volume.endswith('emqx-xfer') else with_acl(raw)


class PluginPinTests(base.EmqxCase):
    """SR-1: HA's broker never loads a plugin HA's cluster.hocon names, and nothing it can write is executable."""

    def test_check_pins_plugins_and_mounts_noexec(self):
        self.check(self.upload_emqx(), ['emqx'])
        options = self.runs('emqx-ha')[0][3]
        self.assertIn('EMQX_PLUGINS__STATES=[]', options['--env'])
        self.assertIn('EMQX_PLUGINS__INSTALL_DIR=/opt/emqx/plugins', options['--env'])
        self.assertIn('--read-only', options)
        volumes = options['--volume']
        self.assertTrue(any(v.endswith(':/data/emqx/data:rw,noexec,nosuid,nodev') for v in volumes))
        self.assertTrue(any(v.endswith(':/opt/emqx/log:rw,noexec,nosuid,nodev') for v in volumes))
        self.assertFalse([v for v in volumes if not v.endswith(':rw,noexec,nosuid,nodev')], volumes)

    def test_conversion_mounts_the_transfer_volume_noexec(self):
        self.internal_candidate(self.upload_emqx())
        volumes = self.runs('emqx-ha')[0][3]['--volume']
        self.assertTrue(any(v.endswith(':/work:rw,noexec,nosuid,nodev') for v in volumes), volumes)
        self.assertFalse([v for v in volumes if not v.endswith(':rw,noexec,nosuid,nodev')], volumes)
        self.assertIn('EMQX_PLUGINS__STATES=[]', self.runs('emqx-ha')[0][3]['--env'])


class DataVolumeAclTests(base.EmqxCase):
    """D3: the device's data-volume ACL file is replaced by HA's, said in a notice; nothing is written back."""
    world_class = DataAclWorld

    def test_an_import_that_rewrites_the_device_acl_is_a_notice_not_a_refusal(self):
        self.world.candidate_acl = HA_ACL
        result = self.internal_candidate(self.upload_emqx())
        self.assertIn('woow_emqx_data', result['volumes'])
        line = next(issue for issue in result['issues'] if issue.id == 'emqx.acl-replaced')
        self.assertEqual((line.level, line.names), ('notice', ('authz/acl.conf',)))
        self.assertIn('ACL', line.message)
        self.assertNotIn('conf load', ' '.join(' '.join(call[1]) for call in self.world.ctl_calls if call[1][:2] == ['conf', 'load']),
                         'nothing of this device\'s ACL is written back')
        self.assertEqual(self.world.hashed, [DATA_ACL])

    def test_an_import_that_keeps_the_device_acl_passes_without_a_notice(self):
        result = self.internal_candidate(self.upload_emqx())
        self.assertIn('woow_emqx_data', result['volumes'])
        self.assertEqual(self.world.hashed, [DATA_ACL], 'the digest check ran on the finished candidate')
        self.assertNotIn('emqx.acl-replaced', [issue.id for issue in result['issues']])


class SnapshotDigestUnitTests(unittest.TestCase):
    def snapshot(self, tmpdir, files):
        path = f'{tmpdir}/snapshot.tar'
        with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as tar:
            for name, data in files.items():
                info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o600
                tar.addfile(info, io.BytesIO(data))
        return path

    def test_digests_skip_only_the_override_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.snapshot(tmpdir, {'configs/cluster.hocon': b'x', 'authz/acl.conf': DEVICE_ACL,
                                          'certs/key.pem': b'k'})
            self.assertEqual(ha_emqx.snapshot_file_digests(path),
                             {'authz/acl.conf': hashlib.sha256(DEVICE_ACL).hexdigest(),
                              'certs/key.pem': hashlib.sha256(b'k').hexdigest()})

    def test_every_unexpected_answer_for_a_certificate_refuses(self):
        want = hashlib.sha256(b'k').hexdigest()
        path = '/opt/emqx/data/certs/key.pem'
        good = want.encode() + b'  ' + path.encode() + b'\n'
        answers = [Result(1, good, b''),                                      # sha256sum failed
                   Result(0, hashlib.sha256(HA_ACL).hexdigest().encode() + good[64:], b''),   # content changed
                   Result(0, want.encode() + b'  /opt/emqx/data/certs/other.pem\n', b''),   # another file
                   Result(0, good + b'extra\n', b''),                           # trailing output
                   Result(0, good.upper(), b''),                                # not sha256sum's format
                   Result(0, b'', b'')]
        for answer in answers:
            with self.subTest(answer=answer.stdout[:20]):
                with self.assertRaises(BackupError) as caught:
                    ha_emqx.check_snapshot_files(lambda _c, a=answer: a, {'certs/key.pem': want})
                self.assertEqual(caught.exception.message, ha_emqx.SNAPSHOT_CHANGED)
        calls = []
        self.assertEqual(ha_emqx.check_snapshot_files(lambda c: calls.append(c) or Result(0, good, b''),
                                                      {'certs/key.pem': want}), [])
        self.assertEqual(calls, [['sha256sum', path]])

    def test_an_acl_file_that_differs_in_any_way_is_replaced_by_HAs(self):
        """D3: the same answers for the ACL file are a notice's names (HA's file replaced it), never a refusal."""
        want = hashlib.sha256(DEVICE_ACL).hexdigest()
        good = want.encode() + b'  ' + DATA_ACL.encode() + b'\n'
        for answer in (Result(1, good, b''), Result(0, hashlib.sha256(HA_ACL).hexdigest().encode() + good[64:], b''),
                       Result(0, b'', b'')):
            with self.subTest(answer=answer.stdout[:20]):
                self.assertEqual(ha_emqx.check_snapshot_files(lambda _c, a=answer: a, {'authz/acl.conf': want}),
                                 ['authz/acl.conf'])
        self.assertEqual(ha_emqx.check_snapshot_files(lambda _c: Result(0, good, b''), {'authz/acl.conf': want}), [])


class CaptureFlowDigestTests(unittest.TestCase):
    """SR-2 through the capture -> seed -> import -> restore path (candidate_from_target) with the shared transport:
    the device's data-volume ACL and certificate are hashed in the finished candidate; HA's ACL replaces the ACL file (D3)."""

    def test_untouched_files_pass_and_are_hashed_after_the_import(self):
        transport = flow.Transport()
        flow.CandidateFlowTests().invoke(transport)
        digests = [e for e in transport.events if e.startswith('digest:')]
        self.assertEqual(sorted(digests), ['digest:authz/custom.acl', 'digest:certs/lab.pem'])
        self.assertGreater(transport.events.index(digests[0]), transport.events.index('import'))

    def test_a_rewritten_device_acl_is_replaced_and_said(self):
        transport = flow.Transport()
        transport.overwritten = {'authz/custom.acl': HA_ACL}
        notes = {}
        flow.CandidateFlowTests().invoke(transport, notes=notes)
        self.assertEqual(notes['acl_replaced'], ['authz/custom.acl'])

    def test_a_rewritten_certificate_still_refuses(self):
        transport = flow.Transport()
        transport.overwritten = {'certs/lab.pem': b'from-ha'}
        with self.assertRaises(BackupError) as caught:
            flow.CandidateFlowTests().invoke(transport)
        self.assertEqual(caught.exception.message, ha_emqx.SNAPSHOT_CHANGED)


def confirm_lines(result, issue_id):
    return [issue for issue in result['issues'] if issue.id == issue_id]


class S1Case(base.EmqxCase):
    """The same three steps for every S1 line: the check collects it, a conversion without its key stops only this app
    (`confirmation-required`), with the key it goes on, and one more name is another key."""

    def collect(self, issue_id):
        ha_id = self.upload_emqx()
        [line] = confirm_lines(self.internal_candidate(ha_id), issue_id)
        self.assertEqual(line.level, 'confirm')
        return ha_id, line

    def conversion(self, ha_id, keys):
        self.world.again()
        return self.internal_candidate(ha_id, acknowledged=keys)

    def assert_three_steps(self, issue_id):
        ha_id, line = self.collect(issue_id)
        with self.assertRaises(BackupError) as caught:
            self.conversion(ha_id, [])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertIn(line.message, caught.exception.message)
        self.assertIn('woow_emqx_data', self.conversion(ha_id, [line.key('emqx')])['volumes'])
        return ha_id, line


class FileSecretWorld(base.World):
    """HA's import brings an MQTT connector whose password is `password` (SR-3)."""
    password = 'file:///opt/emqx/etc/woow-mqtt-bootstrap.csv'
    name = 'ha'

    def exec(self, role, command, data, stdout):
        result = super().exec(role, command, data, stdout)
        if command[:4] == ['emqx', 'ctl', 'data', 'import']:
            self.current_config['connectors'] = {'mqtt': {self.name: {'server': 'broker.example:1883',
                                                                       'password': self.password}}}
        return result


class FileSecretTests(S1Case):
    """SR-3, E-76: a migrated value using EMQX's file:// secret loader would read THIS device's files on this device; HA's
    settings run as they are and the customer confirms the settings by name."""
    world_class = FileSecretWorld

    def test_a_file_secret_in_migrated_settings_is_a_confirmation_by_name(self):
        ha_id, line = self.assert_three_steps('emqx.file-secret')
        self.assertEqual(line.names, ('connectors.mqtt.ha',))
        self.assertIn('file://', line.message)
        self.assertNotIn('woow-mqtt-bootstrap', line.message + ' '.join(line.names), 'never the value')
        self.world.name = 'other'   # another name: another key
        with self.assertRaises(BackupError) as caught:
            self.conversion(ha_id, [line.key('emqx')])
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_a_plain_password_passes_without_a_line(self):
        self.world.password = 'typed-in-ha'
        result = self.internal_candidate(self.upload_emqx())
        self.assertIn('woow_emqx_data', result['volumes'])
        self.assertEqual(confirm_lines(result, 'emqx.file-secret'), [])


class FileSecretUnitTests(unittest.TestCase):
    def test_every_shape_is_found_and_only_ha_roots_count(self):
        items = ha_emqx.file_secret_items
        self.assertEqual(items({'connectors': {'mqtt': {'a': {'password': 'file:///proc/self/environ'}}}}),
                         ['connectors.mqtt.a'])
        self.assertEqual(items({'authentication': [{'mechanism': 'password_based', 'backend': 'redis',
                                                    'password': '  FILE:///x'}]}),
                         ['authentication.password_based:redis.password'])
        self.assertEqual(items({'bridges': {'x': {'servers': [{'p': list(b'file:///etc/x')}]}}}), ['bridges.x.servers'])
        self.assertEqual(items({'exhook': {'servers': [{'file:///k': 1}]}}), ['exhook.servers.0'])
        self.assertEqual(items({'authorization': {'sources': [{'path': 'file:///x'}]},
                                'dashboard': {'default_password': 'file:///x'}}), [],
                         "this device's own roots are restored from its configuration")
        self.assertEqual(items({'connectors': {'http': {'a': {'url': 'http://h/file://x', 'password': 'p'}}}}), [])
        self.assertEqual(ha_emqx.file_secret_roots({'connectors': {'mqtt': {'a': {'password': 'file:///x'}}},
                                                    'bridges': {'x': 'file:///y'}}), ['bridges', 'connectors'])

    def test_a_setting_too_deep_to_look_at_counts_as_found(self):
        deep = value = {}
        for _ in range(70):
            value['x'] = {}
            value = value['x']
        self.assertEqual(ha_emqx.file_secret_items({'connectors': {'deep': deep}}), ['connectors.deep.x'])


class JqRuleWorld(base.World):
    """HA's import brings a rule with `sql` (SR-6)."""
    sql = 'SELECT jq(\'env.EMQX_DASHBOARD__DEFAULT_PASSWORD\', \'{}\') as leak FROM "t/#"'
    rule = 'ha_rule'

    def exec(self, role, command, data, stdout):
        result = super().exec(role, command, data, stdout)
        if command[:4] == ['emqx', 'ctl', 'data', 'import']:
            self.current_config['rule_engine'] = {'rules': {self.rule: {'sql': self.sql, 'actions': []}}}
        return result


class JqRuleTests(S1Case):
    """SR-6, E-77: EMQX's jq reads the broker's environment, i.e. this device's env secrets: the rules are named."""
    world_class = JqRuleWorld

    def test_a_migrated_jq_rule_is_a_confirmation_by_rule_id(self):
        ha_id, line = self.assert_three_steps('emqx.jq-rule')
        self.assertEqual(line.names, ('ha_rule',))
        self.world.rule = 'second'
        with self.assertRaises(BackupError) as caught:
            self.conversion(ha_id, [line.key('emqx')])
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_a_rule_without_jq_passes_without_a_line(self):
        self.world.sql = 'SELECT payload.temp as t FROM "jquery/sensor"'
        result = self.internal_candidate(self.upload_emqx())
        self.assertIn('woow_emqx_data', result['volumes'])
        self.assertEqual(confirm_lines(result, 'emqx.jq-rule'), [])


class JqRuleUnitTests(unittest.TestCase):
    def test_every_spelling_counts_once_per_rule(self):
        count = ha_emqx.jq_rule_count
        rules = lambda *sqls: {'rule_engine': {'rules': {f'r{i}': {'sql': q} for i, q in enumerate(sqls)}}}
        self.assertEqual(count(rules('SELECT JQ (payload.p, payload) FROM "a"')), 1)
        self.assertEqual(count(rules('SELECT jq(\'.a\', payload), jq(\'env\', \'{}\') FROM "a"')), 1)
        self.assertEqual(count(rules('SELECT jq/**/(\'$ENV\', payload) FROM "a"', 'SELECT 1 FROM "b"')), 1)
        self.assertEqual(count({'rule_engine': {'rules': {'r': {'sql': list(b'select jq(1,2) from "a"')}}}}), 1)
        self.assertEqual(count(rules('SELECT payload FROM "jquery/x"', 'SELECT jq_x FROM "y"')), 0)
        self.assertEqual(count({'rule_engine': {'rules': {}}}), 0)
        self.assertEqual(count({'rule_engine': {'rules': {}, 'jq_implementation_module': 'jq_nif',
                                                'jq_function_default_timeout': '10s'}}), 0)
        self.assertEqual(count({}), 0)

    def test_the_names_are_the_rule_ids(self):
        rules = {'rule_engine': {'rules': {'a': {'sql': 'select jq(1) from "x"'}, 'b': {'sql': 'select 1 from "y"'},
                                           'c': {'description': 'uses JQ', 'sql': 'select 2 from "z"'}}}}
        self.assertEqual(ha_emqx.jq_rule_items(rules), ['a', 'c'])


class ReceiverWorld(base.World):
    """HA's import brings `authentication` / `exhook` / `authorization` sources (SR-7, D0)."""
    authentication = None
    exhook = None

    def __init__(self):
        super().__init__()
        self.extra_authz = None

    def exec(self, role, command, data, stdout):
        result = super().exec(role, command, data, stdout)
        if command[:4] == ['emqx', 'ctl', 'data', 'import']:
            if self.authentication is not None:
                self.current_config['authentication'] = self.authentication
            if self.exhook is not None:
                self.current_config['exhook'] = self.exhook
            if self.extra_authz is not None:
                self.current_config['authorization']['sources'].append(self.extra_authz)
        return result


BUILTIN = {'mechanism': 'password_based', 'backend': 'built_in_database', 'enable': True}
HTTP = {'mechanism': 'password_based', 'backend': 'http', 'url': 'http://ha.example/auth',
        'body': {'username': '${username}', 'password': '${password}'}}


class CredentialReceiverTests(S1Case):
    """SR-7, E-78, E-79: migrated external authenticators, ExHook servers and authorization sources receive this device's
    service logins: the customer confirms them by name; HA's authentication is what the candidate holds (D0)."""
    world_class = ReceiverWorld

    def test_an_http_authenticator_before_the_builtin_database_is_a_confirmation(self):
        self.world.ha_authn = ('[{password_based,http,true,none,none},'
                               '{password_based,built_in_database,true,sha256,suffix}]')
        self.world.authentication = [HTTP, BUILTIN]
        ha_id, line = self.assert_three_steps('emqx.external-authn')
        self.assertEqual(line.names, ('HTTP',))
        self.assertIn('帳號與密碼', line.message)
        self.assertEqual([r['backend'] for r in self.world.current_config['authentication']], ['http', 'built_in_database'],
                         'D0: HA\'s authenticators as they are, in HA\'s order (E-74: no false stop for an HTTP one)')

    def test_an_enabled_exhook_is_a_confirmation(self):
        self.world.exhook = {'servers': [{'name': 'x', 'url': 'http://ha.example:9000'}]}
        ha_id, line = self.assert_three_steps('emqx.exhook')
        self.assertEqual(line.names, ('x',))

    def test_an_external_authorization_source_is_a_confirmation(self):
        self.world.ha_authz = '[{file,true},{built_in_database,true},{http,true}]'
        self.world.extra_authz = {'type': 'http', 'enable': True, 'url': 'http://ha.example/acl'}
        ha_id, line = self.assert_three_steps('emqx.external-authz')
        self.assertEqual(line.names, ('HTTP',))
        self.assertIn('主題', line.message)

    def test_builtin_only_and_disabled_leftovers_pass(self):
        self.world.ha_authn = ('[{password_based,built_in_database,true,sha256,suffix},'
                               '{password_based,http,false,none,none}]')
        self.world.authentication = [BUILTIN, dict(HTTP, enable=False)]
        self.world.exhook = {'servers': [{'name': 'x', 'url': 'http://ha.example:9000', 'enable': False}]}
        result = self.internal_candidate(self.upload_emqx())
        self.assertIn('woow_emqx_data', result['volumes'])
        self.assertEqual([i.id for i in result['issues'] if i.level == 'confirm'], [])


class CredentialReceiverUnitTests(unittest.TestCase):
    def test_shapes(self):
        f = ha_emqx.credential_receivers
        self.assertEqual(f({}), [])
        self.assertEqual(f({'authentication': [BUILTIN, {'mechanism': 'scram', 'backend': 'built_in_database'}]}), [])
        self.assertEqual(f({'authentication': [{'mechanism': 'jwt', 'secret': 'x'}]}), ['外部帳號驗證（JWT）'])
        self.assertEqual(f({'authentication': [{'mechanism': 'password_based', 'backend': 'redis'},
                                               {'mechanism': 'password_based', 'backend': 'ldap'}]}),
                         ['外部帳號驗證（LDAP、Redis）'])
        self.assertEqual(f({'authentication': [{'mechanism': 'password_based', 'backend': 'evil$name'}]}),
                         ['外部帳號驗證（未知的帳號驗證）'])
        self.assertEqual(f({'authentication': 'oops'}), ['外部帳號驗證（未知的帳號驗證）'])
        self.assertEqual(f({'exhook': {'servers': 'oops'}}), ['ExHook'])
        self.assertEqual(f({'exhook': {'servers': []}}), [])

    def test_the_names(self):
        items = ha_emqx.credential_receiver_items
        self.assertEqual(items({'exhook': {'servers': [{'name': 'a'}, {'enable': False, 'name': 'b'}, {}]}})['exhook'],
                         ['a', 'server3'])
        self.assertEqual(ha_emqx.external_authz_items({'authorization': {'sources': [
            {'type': 'file'}, {'type': 'built_in_database'}, {'type': 'http'}, {'type': 'redis', 'enable': False},
            {'type': 'evil$'}, 5]}}), ['HTTP', '未知的授權來源'])
        self.assertEqual(ha_emqx.security_items({})['external_authz'], [])


if __name__ == '__main__':
    unittest.main()
