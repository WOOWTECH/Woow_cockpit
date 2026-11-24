"""The export check before `emqx ctl data import` (ha_emqx.check_export; security review B1-03).

HA's broker writes the export from HA's own data; the candidate lists it with the vendor's own erl_tar and hocon
(ha_emqx.EXPORT_EXPR) and only META.hocon, cluster.hocon with DATA_ROOTS and the backup files of TABLES may be in it.
These tests give fixed answers to that expression. The expression itself runs on EMQX 5.8.9's own libraries in
tests/e2e/lab/emqx_secreview/t14_export_check.py and in real brokers in t11_profile_real.py and t13_forged_export.py.
"""
import base64
import json
import unittest
from types import SimpleNamespace

from woowbackup import ha_emqx
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import test_ha_emqx as conversion
from . import test_ha_emqx_candidate_flow as candidate_flow

NAME = conversion.EXPORT.rsplit('/', 1)[1]
BASE = NAME[:-len('.tar.gz')]
META = [f'{BASE}/META.hocon', 'regular', 40]
HOCON = [f'{BASE}/cluster.hocon', 'regular', 900]
# Roots of an EMQX 5.8.9 broker that belong to the device.
DEVICE_ROOTS = ('listeners', 'dashboard', 'node', 'cluster', 'rpc', 'log', 'mqtt', 'broker', 'sysmon', 'alarm', 'api_key',
                'zones', 'limiter', 'flapping_detect', 'force_gc', 'force_shutdown', 'sys_topics', 'slow_subs', 'plugins',
                'prometheus', 'telemetry', 'opentelemetry', 'durable_sessions', 'durable_storage', 'delayed')
listing = conversion.export_listing


def table(name, kind='regular', size=512):
    return [f'{BASE}/mnesia/{name}', kind, size]


def answer(body, returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=body)


def encoded(doc):
    return b'WOOWEXP:' + base64.b64encode(doc if isinstance(doc, bytes) else json.dumps(doc).encode()) + b':END\nok\n'


class CheckTests(unittest.TestCase):
    def check(self, body, *, returncode=0, hint=''):
        commands = []

        def execute(command):
            commands.append(command)
            return answer(body, returncode)
        outcome = ha_emqx.check_export(execute, NAME, hint=hint)
        self.assertEqual(commands, [['emqx', 'eval', ha_emqx.export_expression(NAME)]])
        return outcome

    def refused(self, body, **kwargs):
        with self.assertRaises(BackupError) as caught:
            self.check(body, **kwargs)
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('這台沒有任何改變', caught.exception.message)
        return caught.exception.message

    def test_a_healthy_export_passes(self):
        self.assertIsNone(self.check(listing(NAME)))
        self.assertIsNone(self.check(listing(NAME, roots=ha_emqx.DATA_ROOTS)))
        self.assertIsNone(self.check(listing(NAME, roots=(), members=[META])), 'no configuration to export')
        for tail in (b':END', b':ENDok\n', b':END\n', b':END\nok\n'):
            self.assertIsNone(self.check(listing(NAME).split(b':END')[0] + tail))

    def test_every_table_the_export_asks_for_is_allowed(self):
        self.assertIsNone(self.check(listing(NAME, members=[META, HOCON, *map(table, ha_emqx.TABLES)])))

    def test_a_root_of_this_device_is_refused_by_name(self):
        for root in DEVICE_ROOTS:
            with self.subTest(root):
                self.assertNotIn(root, ha_emqx.DATA_ROOTS)
                message = self.refused(listing(NAME, roots=('authentication', root, 'retainer')))
                self.assertIn(f'設定 {root}）', message)
                self.assertNotIn('authentication', message, 'only what is not allowed is named')
        message = self.refused(listing(NAME, roots=('listeners', 'dashboard', 'rule_engine')))
        self.assertIn('設定 dashboard、listeners）', message)

    def test_a_root_is_compared_whole(self):
        for root in ('Authentication', 'authentication ', 'authentication.x', '', 'rule_engine\n', 'retainers'):
            with self.subTest(root):
                self.refused(listing(NAME, roots=(root,)))

    def test_an_unexpected_file_is_refused_by_name(self):
        for member in (f'{BASE}/mnesia/emqx_other', f'{BASE}/authz/acl.conf', f'{BASE}/plugins/x.beam', 'other/META.hocon',
                       f'{BASE}/../META.hocon', f'/{BASE}/META.hocon', f'{BASE}/META.hocon/', f'{BASE}', f'{BASE}/mnesia',
                       f'{BASE}/mnesia/', f'{BASE}/mnesia/emqx_acl/x', f'{BASE}/MNESIA/emqx_acl', 'META.hocon', ''):
            with self.subTest(member):
                message = self.refused(listing(NAME, members=[META, HOCON, [member, 'regular', 1]]))
                self.assertIn('檔案 ' + member[:60], message)

    def test_only_regular_files_once(self):
        for kind in ('symlink', 'link', 'directory', 'char', 'block', 'fifo', 'reserved', 'unknown', ''):
            with self.subTest(kind):
                for row in (table('emqx_acl', kind), [HOCON[0], kind, 0], [META[0], kind, 0]):
                    self.refused(listing(NAME, members=[row]))
        for twice in (META, HOCON, table('emqx_acl')):
            with self.subTest(twice[0]):
                self.refused(listing(NAME, members=[META, HOCON, table('emqx_acl'), twice]))

    def test_sizes_are_bounded(self):
        for member, limit in ((META[0], ha_emqx.MAX_HOCON), (HOCON[0], ha_emqx.MAX_HOCON),
                              (table('emqx_retainer_message')[0], ha_emqx.MAX_EXPORT)):
            with self.subTest(member):
                self.assertIsNone(self.check(listing(NAME, members=[[member, 'regular', limit]])))
                for size in (limit + 1, -1):
                    self.refused(listing(NAME, members=[[member, 'regular', size]]))

    def test_names_reach_the_message_without_control_characters(self):
        for text in ('x‮y', 'x y', 'x\ny', 'x\x1b[31my', 'x\x85y'):
            with self.subTest(text):
                for body in (listing(NAME, roots=(text,)), listing(NAME, members=[[text, 'regular', 1]])):
                    message = self.refused(body)
                    self.assertNotIn(text, message)
                    self.assertIn('x?', message)

    def test_an_answer_that_is_not_the_listing_is_refused(self):
        good = {'roots': ['rule_engine'], 'members': [META, HOCON]}
        bad = {'empty': b'', 'no prefix': listing(NAME)[1:], 'a line before it': b'x\n' + listing(NAME),
               'no end': listing(NAME).split(b':END')[0], 'more after it': listing(NAME) + b'x',
               'an error': b'RPC to emqx@127.0.0.1 failed: x\n', 'not base64': b'WOOWEXP:!!:END\nok\n',
               'a stray character in the base64': encoded(good).replace(b'WOOWEXP:', b'WOOWEXP:!'),
               'not json': encoded(b'{'), 'not utf-8': encoded(b'\xff'), 'a list': encoded([good]), 'a string': encoded('x'),
               'null': encoded(None), 'no roots': encoded({'members': [META]}), 'no members': encoded({'roots': []}),
               'one field more': encoded(dict(good, x=1)), 'roots not a list': encoded(dict(good, roots={'rule_engine': 1})),
               'roots a string': encoded(dict(good, roots='rule_engine')), 'a root not text': encoded(dict(good, roots=[1])),
               'members not a list': encoded(dict(good, members={})), 'a member not a row': encoded(dict(good, members=['x'])),
               'a short row': encoded(dict(good, members=[META[:2]])), 'a long row': encoded(dict(good, members=[META + [1]])),
               'a size not a number': encoded(dict(good, members=[[META[0], 'regular', '40']])),
               'a size true': encoded(dict(good, members=[[META[0], 'regular', True]])),
               'a name not text': encoded(dict(good, members=[[None, 'regular', 1]])),
               'a kind not text': encoded(dict(good, members=[[META[0], None, 1]])),
               'a key twice': encoded(b'{"roots": ["listeners"], "members": [], "roots": []}'),
               'too large': encoded(b'{"roots": [], "members": []' + b' ' * ha_emqx.MAX_LISTING + b'}')}
        self.assertIsNone(self.check(encoded(good)))
        for label, body in bad.items():
            with self.subTest(label):
                message = self.refused(body, hint='提示')
                self.assertEqual(message, ha_emqx.EXPORT_UNREADABLE + '提示', 'nothing of the answer is shown')
        self.assertEqual(self.refused(encoded(good), returncode=1), ha_emqx.EXPORT_UNREADABLE)
        with self.assertRaises(BackupError):
            ha_emqx.check_export(lambda command: answer(None), NAME)

    def test_a_failing_exec_keeps_its_own_error(self):
        def execute(_command):
            raise BackupError('insufficient-space', '空間不足。')   # the job's watchdog
        with self.assertRaises(BackupError) as caught:
            ha_emqx.check_export(execute, NAME)
        self.assertEqual(caught.exception.code, 'insufficient-space')


class ExpressionTests(unittest.TestCase):
    def test_it_is_fixed_but_for_the_file_name(self):
        text = ha_emqx.export_expression(NAME)
        self.assertEqual(text.replace(NAME, 'N'), ha_emqx.export_expression('a.tar.gz').replace('a.tar.gz', 'N'))
        self.assertIn(f'F = "/work/in/{NAME}", ', text)
        self.assertIn('when Z =< 8388608 ->', text)
        self.assertNotIn('{path}', text)
        self.assertNotIn('{limit}', text)
        # the functions `emqx ctl data import` itself uses (vendor emqx_mgmt_data_backup.erl:880-912)
        for call in ('erl_tar:table(F, [compressed, verbose])', 'erl_tar:extract(F, [compressed, memory, {files, [C]}])',
                     'hocon:binary(B)', 'hocon_scanner:string(', 'false = lists:keymember(include, 1, K)', '[{regular, Z}]'):
            self.assertIn(call, text)

    def test_only_a_plain_export_file_name_reaches_the_command(self):
        self.assertTrue(ha_emqx.EXPORT_RE.search(b'exported to ' + conversion.EXPORT.encode()), 'ha_broker accepts it')
        for name in ('x".tar.gz', 'x/y.tar.gz', '../x.tar.gz', 'x\n.tar.gz', 'x.tar.gz\n', 'x.tar', '.tar.gz', 'x y.tar.gz',
                     'x\\.tar.gz', 'x{path}.tar.gz', 'é.tar.gz', 'a' * 81 + '.tar.gz', ''):
            with self.subTest(name):
                with self.assertRaises(BackupError) as caught:
                    ha_emqx.export_expression(name)
                self.assertEqual(caught.exception.code, 'internal-error')
                with self.assertRaises(BackupError):
                    ha_emqx.check_export(lambda command: answer(listing('a.tar.gz')), name)


class FlowTests(unittest.TestCase):
    """candidate_from_target: the check stands between the candidate's start and the import."""

    def run_with(self, body, returncode=0):
        class Forged(candidate_flow.Transport):
            def exec(self, role, command, **kwargs):
                result = super().exec(role, command, **kwargs)
                if command == ['emqx', 'eval', ha_emqx.export_expression('source.tar.gz')]:
                    assert role == 'emqx-new'
                    return Result(returncode, body, b'')
                return result
        transport = Forged()
        try:
            return transport, candidate_flow.CandidateFlowTests('invoke').invoke(transport)
        except BackupError as error:
            return transport, error

    def test_a_healthy_export_is_imported(self):
        transport, result = self.run_with(listing('source.tar.gz'))
        self.assertNotIsInstance(result, BackupError)
        self.assertEqual(transport.events.count('check-export'), 1)
        self.assertLess(transport.events.index('start'), transport.events.index('check-export'))
        self.assertLess(transport.events.index('check-export'), transport.events.index('import'))

    def test_nothing_is_imported_from_a_refused_export(self):
        for body, returncode in ((listing('source.tar.gz', roots=('rule_engine', 'listeners')), 0),
                                 (listing('source.tar.gz', members=[['x', 'regular', 1]]), 0), (b'', 0),
                                 (listing('source.tar.gz'), 1)):
            transport, error = self.run_with(body, returncode)
            self.assertIsInstance(error, BackupError)
            self.assertEqual(error.code, 'incompatible')
            self.assertIn('check-export', transport.events)
            self.assertNotIn('import', transport.events)
            self.assertNotIn('restore', transport.events)


class ConversionTests(conversion.EmqxCase):
    """The conversion's build: refused before the import, nothing stored, a hot backup's advice named."""

    def forge(self, body):
        real = self.world.evaluate
        self.world.evaluate = lambda role, expression: (
            body if expression == ha_emqx.export_expression(NAME) else real(role, expression))

    def test_a_forged_export_stops_the_conversion(self):
        self.forge(listing(NAME, roots=('authentication', 'listeners')))
        with self.assertRaises(BackupError) as caught:
            self.internal_candidate(self.upload_emqx())
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('設定 listeners）', caught.exception.message)
        self.assertNotIn(['data', 'import'], [call[1][:2] for call in self.world.ctl_calls])
        self.assertEqual(self.storage.list_backups(), [])

    def test_an_unreadable_export_of_a_hot_backup_names_the_advice(self):
        for state, named in (('stopped', False), ('started', True)):
            with self.subTest(state):
                self.forge(b'')
                with self.assertRaises(BackupError) as caught:
                    self.internal_candidate(self.upload_emqx(state=state))
                self.assertIn('匯入前無法檢查', caught.exception.message)
                self.assertEqual(ha_emqx.HOT_HINT in caught.exception.message, named)


if __name__ == '__main__':
    unittest.main()
