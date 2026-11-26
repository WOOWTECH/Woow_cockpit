"""HA import, EMQX as a product import (owner decision 2026-11-23, 「決定1 做」): the protections the lab proved are
enforced by the public check, convert and restore path itself. Generated transports only: no broker, no podman.

HAOS parity (2026-11-25, D0): HA's authentication and authorization replace this device's, so what replaced the public
PRESERVATION_BLOCKER is smaller; what stays, each with tests that fail when the protection is removed:
* this device's broker is read first (a stopped one is started for the read and put back, E-22), EMQX_ETC_DIR must be
  /opt/emqx/etc before the vendor template `${EMQX_ETC_DIR}/acl.conf` is resolved -- its authorization sources are no longer
  judged (E-26, E-27, E-31); HA's ACL rows come with HA's own authorization (E-21: the owner decision 「C」 is superseded);
* the readback's configuration digests never contain this device's secret values (security review SR-4);
* the conversion records a readback (every configuration root, the administrator tables) in the backup and the
  restore compares it with the restored broker, rolling back when accounts, rules or keys differ (E-90: a difference in the
  settings alone is reminded); a readback this engine does not know is skipped after the restore (E-89) and refused
  before it by the restore's preflight.
"""
import base64
import copy
import json
import unittest
from types import SimpleNamespace
from unittest import mock

from woowbackup import archive, flows, ha_emqx, haimport, haissues, hatarget
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import hab1fakes as fk
from . import test_flows as tf
from . import test_ha_emqx as base
from . import test_ha_emqx_candidate_flow as flow

MOUNT = [('/home/appowner/.config/emqx/acl.conf', '/opt/emqx/etc/acl.conf', 'ro')]
FILE = {'type': 'file', 'enable': True, 'path': '${EMQX_ETC_DIR}/acl.conf'}
BUILTIN = {'type': 'built_in_database', 'enable': True}
TABLES = {t: [0, 'a' * 64] for t in ha_emqx.STABLE_TABLES}


def answer(raw, code=0):
    return lambda _command: Result(code, raw, b'')


class TemplatePathTests(unittest.TestCase):
    def references(self, path, mounts=MOUNT, etc_dir=ha_emqx.ETC_DIR):
        return ha_emqx.authorization_file_references({'sources': [dict(FILE, path=path)]}, mounts,
                                                     include_cluster=False, etc_dir=etc_dir)

    def test_the_vendor_template_resolves_to_the_etc_dir_this_devices_broker_reports(self):
        """E-24, E-30 (HAOS parity, EMQX-B): `${EMQX_ETC_DIR}` is where the running broker says (a plain folder); the file is then a
        mount, the image's own or the data volume's like any other, and none of that stops the import."""
        self.assertEqual(self.references('${EMQX_ETC_DIR}/acl.conf'), set(), 'the read-only mount is the ACL')
        for etc_dir in (None, '/etc/emqx'):   # None: the image's default
            with self.subTest(etc_dir=etc_dir):
                self.assertEqual(self.references('${EMQX_ETC_DIR}/acl.conf', etc_dir=etc_dir), set())
        self.assertEqual(self.references('${EMQX_ETC_DIR}/acl.conf', mounts=[]), set(), 'not a mount: the image\'s place')
        self.assertEqual(self.references('${EMQX_ETC_DIR}/acl.conf', etc_dir='/opt/emqx/data/etc'), {'etc/acl.conf'},
                         'an etc folder in the data volume is carried like any file in it')
        other = MOUNT + [('/home/appowner/.config/emqx/other.conf', '/opt/emqx/etc/other.conf', 'ro')]
        for path in ('$EMQX_ETC_DIR/acl.conf', '${EMQX_ETC_DIR}/other.conf', '${EMQX_ETC_DIR}/../etc/acl.conf',
                     '${OTHER_DIR}/acl.conf', '${EMQX_ETC_DIR}//acl.conf'):
            with self.subTest(path=path):
                self.assertEqual(self.references(path, mounts=other), set(), 'none of them is a data-volume file')


class TargetReadTests(unittest.TestCase):
    def test_the_etc_dir_is_the_one_the_broker_reports(self):
        """E-24 (HAOS parity, EMQX-B): any plain absolute folder is the answer; only what is no answer stops."""
        self.assertEqual(ha_emqx.target_etc_dir(answer(b'WOOWETC:/opt/emqx/etc:ENDok\n')), '/opt/emqx/etc')
        self.assertEqual(ha_emqx.target_etc_dir(answer(b'WOOWETC:/etc/emqx:ENDok\n')), '/etc/emqx')
        for raw, code in ((b'garbage', 0), (b'WOOWETC:/opt/emqx/etc:ENDok', 1), (b'', 0)):
            with self.subTest(raw=raw), self.assertRaises(BackupError) as caught:
                ha_emqx.target_etc_dir(answer(raw, code))
            self.assertNotIn('EMQX_ETC_DIR', caught.exception.message)

    def test_the_conversion_reads_the_etc_dir_of_target_and_candidate(self):
        class OtherEtc(flow.Transport):
            def __init__(self, side):
                super().__init__()
                self.side = side

            def podman(self, *args, **kwargs):
                if self.side == 'target' and args[2:] == ('emqx', 'eval', ha_emqx.ETC_EXPR):
                    return Result(0, b'WOOWETC:/etc/emqx:ENDok\n', b'')
                return super().podman(*args, **kwargs)

            def exec(self, role, command, **kwargs):
                if self.side == 'candidate' and command == ['emqx', 'eval', ha_emqx.ETC_EXPR]:
                    return Result(0, b'WOOWETC:/etc/emqx:ENDok\n', b'')
                return super().exec(role, command, **kwargs)
        for side in ('target', 'candidate'):
            transport = OtherEtc(side)
            with self.subTest(side=side), self.assertRaises(BackupError):
                flow.CandidateFlowTests.invoke(self, transport)
            self.assertNotIn('import', transport.events)
        self.assertNotIn('export', OtherEtc('target').events)

    def test_this_devices_authorization_sources_of_any_combination_are_read_not_judged(self):
        """E-26, E-27: the order, the number and the types of this device's sources no longer stop the import (HA's replace them)."""
        for sources in (['file', 'built_in_database'], ['built_in_database', 'file'], ['built_in_database'], [],
                        ['file', 'http'], ['http', 'redis']):
            transport = flow.Transport()
            transport.config['authorization']['sources'] = [
                {'file': dict(FILE, path='/opt/emqx/data/authz/custom.acl'), 'built_in_database': dict(BUILTIN)}.get(
                    kind, {'type': kind, 'enable': True}) for kind in sources]
            transport.running_config = copy.deepcopy(transport.config)
            with self.subTest(sources=sources):
                self.assertEqual(len(flow.CandidateFlowTests.invoke(self, transport)), 4)
                self.assertIn('import', transport.events)

    def test_a_stopped_target_that_cannot_be_started_is_named(self):
        class Stopped(flow.Transport):
            def podman(self, *args, **kwargs):
                if args[:2] == ('container', 'inspect'):
                    return Result(0, b'false\n', b'')
                return super().podman(*args, **kwargs)
        transport = Stopped()
        transport.live_response = Result(125, b'', b'Error: container is not running')
        with self.assertRaises(BackupError) as caught:
            flow.CandidateFlowTests.invoke(self, transport)
        self.assertEqual(caught.exception.message, ha_emqx.NOT_RUNNING)
        running = flow.Transport()
        running.live_response = Result(0, b'garbage', b'')
        with self.assertRaises(BackupError) as caught:
            flow.CandidateFlowTests.invoke(self, running)
        self.assertNotEqual(caught.exception.message, ha_emqx.NOT_RUNNING, 'a running broker gets the read error')


class TargetWorld(base.World):
    """test_ha_emqx's World with this device's broker reading as `sources` and optionally stopped."""
    stopped = False

    def podman(self, args, data, stdout):
        if self.stopped and args[:2] == ['container', 'inspect'] and args[-1] == 'woow-emqx':
            return Result(0, b'false\n', b'')
        return super().podman(args, data, stdout)

    def exec(self, role, command, data, stdout):
        if self.stopped and role == 'woow-emqx':
            return Result(125, b'', b'Error: container is not running')
        return super().exec(role, command, data, stdout)


class CheckPreflightTests(base.EmqxCase):
    world_class = TargetWorld

    def target(self, *sources):
        self.world.target_config['authorization']['sources'] = [copy.deepcopy(s) for s in sources]
        self.world.current_config = copy.deepcopy(self.world.target_config)

    def test_an_unusual_target_is_no_longer_the_apps_blocker(self):
        """E-26: a source of another type next to the ACL file: HA's authorization replaces it."""
        self.target(dict(FILE, path='/opt/emqx/etc/acl.conf'), {'type': 'http', 'enable': True})
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        self.assertEqual(result['emqx']['mqtt_users'], 3)
        self.assertEqual(result['emqx']['target_authorization'], [])

    def test_a_stopped_target_is_started_to_be_read_and_the_check_says_so(self):
        """E-22 (CM-07): a stopped EMQX of this device is started for the read (hatarget.ensure_running puts it back)."""
        self.world.stopped = True
        calls = []

        def start(work, app, container, *, ready='running', **_options):
            calls.append((container, ready))
            self.world.stopped = False
            work.sink(app).auto('target.service-started', '這台「EMQX」的容器 woow-emqx 原本停著，已暫時啟動它來讀取資料。', [container])
        with mock.patch.object(hatarget, 'ensure_running', start):
            result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        self.assertEqual(calls, [('woow-emqx', ha_emqx.broker_ready)])
        self.assertIn('target.service-started', [issue['id'] for issue in result['issues']])

    def test_a_stopped_target_that_cannot_be_started_stops_only_this_app(self):
        self.world.stopped = True

        def cannot(work, app, container, **_options):
            raise haissues.stopped(haissues.Issue('target.service-failed', 'stop', '無法啟動這台「EMQX」停著的服務。',
                                                  [container], action='請先在這台把這個應用啟動起來。'))
        with mock.patch.object(hatarget, 'ensure_running', cannot):
            result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertFalse(result['importable'])
        self.assertEqual([i['id'] for i in result['issues'] if i['level'] == 'stop'], ['target.service-failed'])
        self.assertFalse(self.runs('emqx-ha'), 'HA\'s broker never started')

    def test_a_stopped_target_the_engine_cannot_restart_is_named(self):
        """Without the start (a double that has no temporary objects) the read fails with the old, plain sentence."""
        self.world.stopped = True
        with mock.patch.object(ha_emqx, 'ensure_target_running', lambda *a: None):
            result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertFalse(result['importable'])
        self.assertIn(ha_emqx.NOT_RUNNING, result['blockers'])

    def test_the_broker_is_ready_when_it_answers_status(self):
        runner = SimpleNamespace(podman=lambda *a, **k: Result(0, b"Node 'emqx@127.0.0.1' 5.8.9 is started\n", b''))
        self.assertTrue(ha_emqx.broker_ready(runner, 'woow-emqx'))
        for result in (Result(0, b'Node is not running!\n', b''), Result(1, b'is started', b'')):
            self.assertFalse(ha_emqx.broker_ready(SimpleNamespace(podman=lambda *a, r=result, **k: r), 'woow-emqx'))
        called = []
        work = SimpleNamespace()
        with mock.patch.object(hatarget, 'ensure_running', lambda *a, **k: called.append(a)):
            ha_emqx.ensure_target_running(work, 'app', SimpleNamespace(container='woow-emqx'))
        self.assertEqual(called, [], 'a double without throwaway objects starts nothing')

    def test_the_vendor_template_target_of_the_product_package_is_supported(self):
        self.target(FILE, BUILTIN)   # Woow_podman_emqx base.hocon: path = "${EMQX_ETC_DIR}/acl.conf"
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertTrue(result['ok'], result['blockers'])
        self.target(FILE)
        with mock.patch.dict(base.HA_COUNTS, {'emqx_acl': 0}):
            result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertTrue(result['ok'], result['blockers'])


class HaAuthorizationTests(base.EmqxCase):
    """D0, E-21 (replaces the owner decision 「C」 of 2026-11-23): HA's ACL rows come with HA's own authorization -- a device
    that only had the ACL file takes HA's built-in database source with the rows; nothing is refused for it."""
    world_class = TargetWorld

    def target(self, *sources):
        self.world.target_config['authorization']['sources'] = [copy.deepcopy(s) for s in sources]
        self.world.current_config = copy.deepcopy(self.world.target_config)

    def test_the_old_refusal_and_its_text_are_gone(self):
        self.assertFalse(hasattr(ha_emqx, 'ACL_NEEDS_BUILTIN'))
        self.assertFalse(hasattr(ha_emqx, 'acl_blocker'))
        self.assertFalse(hasattr(ha_emqx, 'source_profile'))

    def test_a_file_only_target_takes_has_acl_rows_with_has_authorization(self):
        self.target(dict(FILE, path='/opt/emqx/etc/acl.conf'))   # [file] target, HA has 2 ACL rows
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertTrue(result['ok'], result['blockers'])
        self.assertEqual(result['emqx']['acl_rules'], 2)
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertTrue(done['backup_id'])
        self.assertEqual([s['type'] for s in self.world.current_config['authorization']['sources']],
                         ['file', 'built_in_database'], 'HA\'s sources, so HA\'s ACL rows are asked')
        section = next(app for app in self.archive.writes[-1]['manifest']['apps'] if app['id'] == 'emqx')
        self.assertEqual(section['import_check']['tables']['emqx_acl'][0], 2)

    def test_a_target_with_the_builtin_source_and_a_backup_without_rows_pass(self):
        self.target(dict(FILE, path='/opt/emqx/etc/acl.conf'), BUILTIN)
        with mock.patch.dict(base.HA_COUNTS, {'emqx_acl': 0}):
            result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
            self.assertTrue(result['ok'], result['blockers'])
            done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertTrue(done['backup_id'])
        self.assertFalse([n for n in done['ha_import']['notes'] if '不會生效' in n])

    def test_the_conversion_reads_this_devices_broker_before_it_builds_anything(self):
        """The preflight is still read-only: a device whose EMQX_ETC_DIR the candidate does not have (E-24: its own etc folder is
        the candidate's too, here it is not) stops this app before anything is imported or packaged."""
        self.world.stopped = False
        real = self.world.evaluate

        def evaluate(role, expression):
            if role == 'woow-emqx' and expression == ha_emqx.ETC_EXPR:
                return b'WOOWETC:/etc/emqx:ENDok\n'
            return real(role, expression)
        self.world.evaluate = evaluate
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertEqual(caught.exception.message, ha_emqx.ETC_DIFFERS)
        self.assertEqual([c for c in self.world.ctl_calls if c[1][:2] == ['data', 'import'] and c[0] == 'emqx-new'], [])
        self.assertEqual(self.storage.list_backups(), [])


class DashboardChangedWorld(TargetWorld):
    """dev-d 2026-11-23 attempt-05: this device's built-in database source was added in the Dashboard (REST API) since
    the last restart, so its running broker's RAW configuration lacks the schema default `max_rules` that every boot
    fills in; the candidate, booted from the snapshot, reads it. `target_config` is the boot form. Under D0 the
    authorization root is HA's; the same thing happens to this device's own roots (`mqtt` here)."""

    @staticmethod
    def filled(config):
        config = copy.deepcopy(config)
        for source in (config.get('authorization') or {}).get('sources') or []:
            if source.get('type') == 'built_in_database':
                source.setdefault('max_rules', 100)
        if isinstance(config.get('mqtt'), dict):
            config['mqtt'].setdefault('retry_interval', '30s')
        return config

    @staticmethod
    def runtime(config):
        config = copy.deepcopy(config)
        for source in (config.get('authorization') or {}).get('sources') or []:
            source.pop('max_rules', None)
        if isinstance(config.get('mqtt'), dict):
            config['mqtt'].pop('retry_interval', None)
        return config

    def boot_view(self, role, config):
        return self.filled(config)

    def exec(self, role, command, data, stdout):
        """`emqx ctl conf load` stores what it loads with the schema defaults filled (emqx_conf_cli.erl:541-546)."""
        result = super().exec(role, command, data, stdout)
        if command[:4] == ['emqx', 'ctl', 'conf', 'load']:
            self.current_config = self.filled(self.current_config)
        return result

    def evaluate(self, role, expression):
        if role == 'woow-emqx' and expression == ha_emqx.CONFIG_EXPR:
            return b'WOOWCFG:' + base64.b64encode(json.dumps(self.runtime(self.target_config)).encode()) + b':ENDok\n'
        if role == 'woow-emqx' and expression == ha_emqx.BOOT_CONFIG_EXPR:
            return b'WOOWCFG:' + base64.b64encode(json.dumps(self.target_config).encode()) + b':ENDok\n'
        return super().evaluate(role, expression)


class DashboardChangedTargetTests(base.EmqxCase):
    """The customer changes this device's settings in the Dashboard and imports without restarting EMQX: the candidate is
    compared with this device's configuration in its BOOT form (BOOT_CONFIG_EXPR) and the readback holds that form, so
    the restored broker (which boots) compares equal. HAOS parity (E-60): a root where the two differ is listed, no
    longer refused; only another node name stops."""
    world_class = DashboardChangedWorld

    def setUp(self):
        super().setUp()
        self.world.target_config['mqtt'] = {'max_packet_size': '1MB', 'retry_interval': '30s'}
        self.world.target_config['authorization']['sources'] = [
            dict(FILE, path='/opt/emqx/etc/acl.conf'), dict(BUILTIN, max_rules=100)]
        self.world.current_config = self.world.runtime(self.world.target_config)

    def test_the_conversion_compares_and_records_boot_forms(self):
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertTrue(result['ok'], result['blockers'])
        self.assertNotIn('emqx.config-differs', [issue['id'] for issue in result['issues']])
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertTrue(done['backup_id'])
        section = next(app for app in self.archive.writes[-1]['manifest']['apps'] if app['id'] == 'emqx')
        self.assertEqual(section['import_check']['config_roots']['mqtt'],
                         ha_emqx.config_roots(self.world.target_config)['mqtt'],
                         'the readback holds the boot form (retry_interval filled), as the restored broker boots')
        self.assertEqual(section['import_check']['config_roots']['authorization'],
                         ha_emqx.config_roots(self.world.filled(self.world.current_config))['authorization'],
                         'and HA\'s authorization in its boot form (D0)')

    def test_a_candidate_that_differs_is_listed_and_the_conversion_goes_on(self):
        """E-60: a root the candidate boots differently is named in a notice; the app is not refused."""
        real = self.world.boot_view
        self.world.boot_view = lambda role, config: (dict(real(role, config), log={'console': {'level': 'notice'}})
                                                     if role == 'emqx-new' else real(role, config))
        result = self.internal_candidate(self.upload_emqx(state='stopped'))
        line = next(issue for issue in result['issues'] if issue.id == 'emqx.config-differs')
        self.assertEqual((line.level, line.names), ('notice', ('log',)))
        self.assertIn('log', line.message)
        self.assertTrue(result['volumes'])
        record = result['built'].readback
        self.assertIn('log', record['config_roots'], 'what the candidate booted with is the baseline of the readback')

    def test_the_loaded_settings_must_equal_this_devices_boot_form(self):
        """dev-d 2026-11-24 attempt-11: this device's own roots are loaded back with `conf load`, which fills defaults; that
        equals its boot form (the conversion goes on). A loaded value that is not this device's is still refused, naming the
        root."""
        self.world.import_changes = {'mqtt': {'max_packet_size': '9MB'}}
        self.assertTrue(self.convert(self.upload_emqx(state='stopped'), ['emqx'])['backup_id'])
        self.assertEqual(self.world.current_config['mqtt'], {'max_packet_size': '1MB', 'retry_interval': '30s'})
        real = self.world.exec

        def exec(role, command, data, stdout):
            result = real(role, command, data, stdout)
            if command[:4] == ['emqx', 'ctl', 'conf', 'load']:
                self.world.current_config['mqtt']['max_packet_size'] = '7MB'
            return result
        self.world.exec = exec
        self.world.again()
        self.world.current_config = self.world.runtime(self.world.target_config)
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertEqual(caught.exception.message, 'EMQX 匯入後未能保留目標有效設定（mqtt），已停止。')
        self.assertEqual(len(self.storage.list_backups()), 1, 'only the first conversion made a backup')

    def test_the_readback_records_the_boot_form_of_roots_the_import_changed(self):
        """HA's import changes roots at runtime (rules, connectors, …): the running candidate's plain raw configuration
        then lacks schema defaults a boot fills in, and the restored broker boots. The readback holds the boot form of
        every root (a plain one would fail every restore of such a backup)."""
        real_exec, real_view = self.world.exec, self.world.boot_view

        def exec(role, command, data, stdout):
            result = real_exec(role, command, data, stdout)
            if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                self.world.current_config['rule_engine'] = {'rules': {}}   # runtime form, as the import stored it
            return result

        def boot_view(role, config):
            config = copy.deepcopy(real_view(role, config))
            if 'rule_engine' in config:
                config['rule_engine'].setdefault('ignore_sys_message', True)   # what a boot fills in
            return config
        self.world.exec, self.world.boot_view = exec, boot_view
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertTrue(done['backup_id'])
        section = next(app for app in self.archive.writes[-1]['manifest']['apps'] if app['id'] == 'emqx')
        self.assertEqual(section['import_check']['config_roots']['rule_engine'],
                         ha_emqx.config_roots({'rule_engine': {'rules': {}, 'ignore_sys_message': True}})['rule_engine'],
                         'the readback holds the boot form of a root HA\'s import changed')


class EnvironmentFileTests(unittest.TestCase):
    """dev-d 2026-11-23 attempt-06: the product package sets EMQX_LOG__CONSOLE__LEVEL in the Quadlet's EnvironmentFile=;
    the candidate must get it like the running broker (podman --env-file: plain KEY=VALUE, value literal)."""

    def target(self, line, files):
        quadlets = dict(base.QUADLETS)
        text = base.QUADLETS['emqx.container'].replace(b'EnvironmentFile=%h/.config/emqx/emqx.env\n', line.encode())
        quadlets['emqx.container'] = text
        def read_file(rel, max_bytes=None):   # the owner runner's contract: a missing file is a BackupError
            if rel not in files:
                raise BackupError('not-found', 'missing')
            return files[rel]
        runner = SimpleNamespace(home='/home/appowner', read_file=read_file)
        work = SimpleNamespace(quadlets=lambda _app: quadlets, runner=lambda _app: runner)
        app = fk.app('emqx', 'EMQX MQTT 代理', volumes=[{'name': 'woow_emqx_data'}, {'name': 'woow_emqx_log'}])
        return ha_emqx.Target(work, app)

    def test_the_env_file_settings_reach_the_candidate(self):
        files = {'.config/emqx/emqx.env': b'# c\n  EMQX_LOG__CONSOLE__LEVEL=warning\nWOOW_EMQX_BIND=0.0.0.0\n\n'}
        env, env_files = self.target('EnvironmentFile=%h/.config/emqx/emqx.env\n', files).candidate_env()
        self.assertEqual(env_files, ['/home/appowner/.config/emqx/emqx.env'], 'podman reads the file for the candidate')
        self.assertNotIn('EMQX_LOG__CONSOLE__LEVEL', env, 'an EnvironmentFile value never reaches a command line '
                         '(security review SR-8: --env values are in world-readable /proc/<pid>/cmdline)')
        self.assertEqual(env['EMQX_NODE__NAME'], 'emqx@127.0.0.1', 'the Quadlet\'s own settings stay')
        self.assertNotIn('WOOW_EMQX_BIND', env)
        self.assertEqual(self.target('', files).candidate_env()[1], [])
        self.assertEqual(self.target('EnvironmentFile=-%h/.config/emqx/missing.env\n', {}).candidate_env()[1], [],
                         'an optional missing file is skipped')

    def test_what_podman_reads_differently_is_no_longer_judged_here(self):
        """E-53: quotes, escapes, `$`, doubles, blanks and a conflicting node name: the candidate gets the file as podman
        reads it, and what that changes shows in the comparison of its settings (E-60; another node name still stops)."""
        line = 'EnvironmentFile=%h/.config/emqx/emqx.env\n'
        for content in (b'EMQX_LOG__CONSOLE__LEVEL="warning"\n', b"EMQX_LOG__CONSOLE__LEVEL='warning'\n",
                        b'EMQX_LOG__CONSOLE__LEVEL=$LEVEL\n', b'EMQX_LOG__CONSOLE__LEVEL=warn\\\n',
                        b'EMQX_LOG__CONSOLE__LEVEL=warning \n', b'EMQX_LOG__CONSOLE__LEVEL=\n', b'EMQX_LOG__CONSOLE__LEVEL\n',
                        b'EMQX_NODE__NAME=emqx@10.0.0.1\n'):
            with self.subTest(content=content):
                env, files = self.target(line, {'.config/emqx/emqx.env': content}).candidate_env()
                self.assertEqual(files, ['/home/appowner/.config/emqx/emqx.env'])
                self.assertNotIn('EMQX_LOG__CONSOLE__LEVEL', env)

    def test_a_file_the_candidate_cannot_get_is_left_out_and_logged_not_refused(self):
        for other in ('EnvironmentFile=/etc/emqx.env\n', 'EnvironmentFile=%h/../x.env\n', 'EnvironmentFile=emqx.env\n'):
            with self.subTest(line=other):
                target = self.target(other, {})
                self.assertEqual(target.candidate_env()[1], [])
                self.assertEqual(len(target.skipped_env), 1)
        target = self.target('EnvironmentFile=%h/.config/emqx/emqx.env\n', {})   # required, not there
        self.assertEqual(target.candidate_env()[1], [])
        self.assertEqual(target.skipped_env, ['%h/.config/emqx/emqx.env'])
        optional = self.target('EnvironmentFile=-%h/.config/emqx/emqx.env\n', {})
        self.assertEqual(optional.candidate_env()[1], [])
        self.assertEqual(optional.skipped_env, [], 'an optional file that is not there is nothing to say')

    def test_the_names_of_the_settings_that_decide_access_are_kept_never_their_values(self):
        """H1: this device's EMQX_AUTHORIZATION__* / EMQX_AUTHENTICATION__* win over HA's after a restart: a notice names them."""
        files = {'.config/emqx/emqx.env': b'EMQX_AUTHORIZATION__NO_MATCH=allow-secret-value\n  EMQX_AUTHENTICATION__1__X=y\n'
                                          b'EMQX_LOG__CONSOLE__LEVEL=warning\n# EMQX_AUTHORIZATION__COMMENTED=1\n'}
        target = self.target('EnvironmentFile=%h/.config/emqx/emqx.env\nEnvironment=EMQX_AUTHENTICATION__2__Z=1\n', files)
        target.candidate_env()
        self.assertEqual(target.access_env, ['EMQX_AUTHENTICATION__1__X', 'EMQX_AUTHENTICATION__2__Z',
                                             'EMQX_AUTHORIZATION__NO_MATCH'])
        self.assertNotIn('secret-value', json.dumps(target.access_env))
        none = self.target('EnvironmentFile=%h/.config/emqx/emqx.env\n', {'.config/emqx/emqx.env': b'EMQX_LOG__X=1\n'})
        none.candidate_env()
        self.assertEqual(none.access_env, [])


class SchedulerWorld(base.World):
    """dev-d 2026-11-24 attempt-08: EMQX 5.8.9 fills dashboard.listeners.{http,https}.num_acceptors at boot from the
    VM's online schedulers (emqx_dashboard_schema.erl:125-131) and keeps it in the raw configuration; the throwaway
    candidate runs with half the CPUs (tempctr --cpus) and so has fewer of them than this device (World.schedulers)."""
    candidate_obeys_flags = True

    def schedulers(self, role):
        if role == 'emqx-new' and not self.candidate_obeys_flags:
            return 4, 2
        return super().schedulers(role)

    def evaluate(self, role, expression):
        answer = super().evaluate(role, expression)
        if role not in ('woow-emqx', 'emqx-new') or expression not in (ha_emqx.CONFIG_EXPR, ha_emqx.BOOT_CONFIG_EXPR):
            return answer
        config = json.loads(base64.b64decode(answer[8:].split(b':END')[0]))
        online = self.schedulers(role)[1]   # a dashboard root written at runtime (cluster.hocon) keeps its own value
        config.setdefault('dashboard', {'listeners': {kind: {'num_acceptors': online} for kind in ('http', 'https')}})
        return b'WOOWCFG:' + base64.b64encode(json.dumps(config).encode()) + b':ENDok\n'


class SchedulerTests(base.EmqxCase):
    """The candidate starts with this device's scheduler counts (ha_emqx.VM_EXPR -> ERL_AFLAGS "+S total:online"), so
    the defaults EMQX derives from them are this device's; a candidate that does not answer them is refused."""
    world_class = SchedulerWorld

    def setUp(self):
        super().setUp()

    def test_the_candidate_runs_with_this_devices_schedulers(self):
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertTrue(done['backup_id'])
        env = self.runs('emqx-new')[0][3].get('--env', [])
        self.assertIn('ERL_AFLAGS=+S 4:4', env)
        self.assertEqual([e for e in env if e.startswith('ERL_')], ['ERL_AFLAGS=+S 4:4'], 'one Erlang flag, no other')
        self.assertNotIn('dashboard', self.world.current_config,
                         'the candidate already had this device\'s dashboard settings: nothing of it was written '
                         '(its raw root carries dashboard.default_password from the env)')
        section = next(app for app in self.archive.writes[-1]['manifest']['apps'] if app['id'] == 'emqx')
        device = {'dashboard': {'listeners': {kind: {'num_acceptors': 4} for kind in ('http', 'https')}}}
        self.assertEqual(section['import_check']['config_roots']['dashboard'],
                         ha_emqx.config_roots(device)['dashboard'], 'the readback holds this device\'s values')
        for role in ('woow-emqx', 'emqx-new'):
            self.assertIn((role, ['emqx', 'eval', ha_emqx.VM_EXPR]), [(r, c) for r, c, _d in self.world.execs])

    def test_a_candidate_with_other_schedulers_is_logged_not_refused(self):
        """E-57: the CPU count itself is no danger; the roots it changes show in the comparison (E-60, E-90)."""
        self.world.candidate_obeys_flags = False
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertTrue(done['backup_id'])
        self.assertTrue([line for line in self.reporter.logs if '排程器數量' in str(line)])

    def test_a_device_answer_that_is_not_exact_refuses(self):
        self.assertEqual(ha_emqx.schedulers(answer(b'WOOWVM:4:4:END\nok\n')), (4, 4))
        self.assertEqual(ha_emqx.schedulers(answer(b'WOOWVM:6:2:ENDok\n')), (6, 2))
        self.assertEqual(ha_emqx.schedulers(answer(b'WOOWVM:1024:1:END\n')), (1024, 1))
        for raw, code in ((b'WOOWVM:2:4:END\nok\n', 0), (b'WOOWVM:0:0:END\nok\n', 0), (b'WOOWVM:2048:4:END\nok\n', 0),
                          (b'WOOWVM:04:4:END\nok\n', 0), (b'WOOWVM:4:4:END\nnot ok\n', 0), (b'WOOWVM:4:4\nok\n', 0),
                          (b'WOOWVM:4:x:END\nok\n', 0), (b'WOOWVM:4:4:4:END\nok\n', 0), (b'ok\n', 0),
                          (b'WOOWVM:4:4:END\nok\n', 1)):
            with self.subTest(raw=raw, code=code):
                with self.assertRaises(BackupError) as caught:
                    ha_emqx.schedulers(answer(raw, code))
                self.assertEqual(caught.exception.message, '無法安全取得 EMQX 的執行環境（排程器數量），已停止。')
                self.assertIsNone(ha_emqx.read_schedulers(answer(raw, code)), 'E-57: the conversion goes on without the flag')

    def test_a_device_without_a_scheduler_answer_starts_the_candidate_without_the_flag(self):
        real = self.world.evaluate
        self.world.evaluate = lambda role, expression: (b'ok\n' if expression == ha_emqx.VM_EXPR
                                                        else real(role, expression))
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertTrue(done['backup_id'])
        env = self.runs('emqx-new')[0][3].get('--env', [])
        self.assertEqual([e for e in env if e.startswith('ERL_')], [], 'no flag to give')


class ImageVolumeTests(base.EmqxCase):
    """dev-d 2026-11-24: the EMQX image declares VOLUME /opt/emqx/data and /opt/emqx/log; HA's broker mounted only the
    log path, so every check and every conversion left an anonymous volume on this device (`podman rm` keeps it). Each
    throwaway broker mounts both paths with this job's own volumes (removed with the job's other objects)."""
    IMAGE_VOLUMES = ('/opt/emqx/data', '/opt/emqx/log')

    def setUp(self):
        super().setUp()

    def mounts(self, role):
        runs = self.runs(role)
        self.assertTrue(runs, role)
        for _role, _image, _command, options in runs:
            mounts = {}
            for spec in options.get('--volume', []):
                source, target, *opts = spec.split(':')
                mounts[target] = (source, opts)
            yield mounts

    def test_every_throwaway_broker_covers_the_image_volume_paths(self):
        self.check(self.upload_emqx(state='stopped'), ['emqx'])
        self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        for role in ('emqx-ha', 'emqx-new'):
            for mounts in self.mounts(role):
                for path in self.IMAGE_VOLUMES:
                    with self.subTest(role=role, path=path):
                        self.assertIn(path, mounts)
                        self.assertTrue(mounts[path][0].startswith('woowbk-j'), 'this job\'s own named volume')
        for mounts in self.mounts('emqx-ha'):   # security review SR-1: nothing of HA's broker may be executable
            self.assertEqual(mounts['/opt/emqx/data'][1], ['rw,noexec,nosuid,nodev'])


class ConvertReadbackTests(base.EmqxCase):
    def setUp(self):
        super().setUp()
        # HA's backup has ACL rows: the import target asks its built-in database too (OWNER DECISION 「C」).

    def test_the_public_conversion_carries_the_readback_into_the_app_section(self):
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        written = self.archive.writes[-1]['manifest']
        section = next(app for app in written['apps'] if app['id'] == 'emqx')
        check = section['import_check']
        archive.validate_import_check(check, 'emqx')
        self.assertEqual(check['kind'], 'emqx-readback')
        self.assertEqual(check['tables'], {t: [n, h.lower()] for t, (n, h) in base.RECEIPT.items()})
        self.assertIn('authorization', check['config_roots'])
        self.assertEqual(check['config_roots']['authorization'],
                         ha_emqx.config_roots(self.world.current_config)['authorization'],
                         'the readback holds HA\'s authorization (D0: HAOS restores HA\'s settings)')
        self.assertNotEqual(check['config_roots']['authorization'],
                            ha_emqx.config_roots(self.world.target_config)['authorization'])
        notes = done['ha_import']['notes']
        self.assertTrue(any('還原後會再核對' in n for n in notes), notes)
        options = self.runs('emqx-new')[0][3]
        env = list(options.get('--env', [])) + list(options.get('-e', []))
        self.assertEqual(options.get('--env-file'), ['/home/appowner/.config/emqx/emqx.env'],
                         'the candidate runs with the EnvironmentFile settings: podman reads the device\'s file itself, '
                         'as for the device\'s broker')
        self.assertFalse([e for e in env if e.startswith(('EMQX_LOG__CONSOLE__LEVEL=', 'WOOW_'))],
                         'no value of the file is on the command line (security review SR-8)')

    def test_a_receipt_that_cannot_be_read_is_recorded_as_not_read_and_said(self):
        """E-84: the rows were counted in the conversion; the receipt of the administrator tables is skipped and a notice
        says so; the backup keeps the one shape the archive knows for "no such table" for every table."""
        real = self.world.evaluate

        def evaluate(role, expression):
            if expression == ha_emqx.TABLES_RECEIPT_EXPR:
                return b'WOOWTAB:REFUSED'
            return real(role, expression)
        self.world.evaluate = evaluate
        result = self.internal_candidate(self.upload_emqx(state='stopped'))
        self.assertIn('emqx.receipt-unreadable', [issue.id for issue in result['issues']])
        record = result['built'].readback
        archive.validate_import_check(record, 'emqx')
        self.assertEqual(set(map(tuple, record['tables'].values())), {(-1, None)})
        self.assertFalse(ha_emqx.tables_recorded(record))
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertTrue(done['backup_id'])


class ReadbackTests(unittest.TestCase):
    def config(self):
        return {'authorization': {'no_match': 'deny', 'deny_action': 'ignore', 'sources': [FILE, BUILTIN]},
                'log': {'console': {'level': 'warning', 'enable': True}}, 'node': {'name': 'emqx@127.0.0.1'}}

    def test_the_record_and_its_comparison_name_what_differs(self):
        config = self.config()
        record = ha_emqx.readback_record(config, copy.deepcopy(TABLES))
        archive.validate_import_check(record, 'emqx')
        self.assertEqual(ha_emqx.compare_readback(record, copy.deepcopy(record)), [])
        reordered = {'node': config['node'], 'log': {'console': {'enable': True, 'level': 'warning'}},
                     'authorization': config['authorization']}
        self.assertEqual(ha_emqx.compare_readback(record, ha_emqx.readback_record(reordered, TABLES)), [],
                         'key order never matters')
        cases = []
        changed = self.config(); changed['log']['console']['level'] = 'debug'; cases.append((changed, TABLES, ['設定（log）']))
        changed = self.config(); changed['authorization']['sources'].reverse()
        cases.append((changed, TABLES, ['設定（authorization）']))
        changed = self.config(); del changed['node']; cases.append((changed, TABLES, ['設定（node）']))
        changed = self.config(); changed['extra'] = {}; cases.append((changed, TABLES, ['設定（extra）']))
        tables = copy.deepcopy(TABLES); tables['emqx_acl'] = [1, 'b' * 64]
        cases.append((self.config(), tables, ['內建資料庫（emqx_acl）']))
        for config, tables, problems in cases:
            with self.subTest(problems=problems):
                self.assertEqual(ha_emqx.compare_readback(record, ha_emqx.readback_record(config, tables)), problems)

    def test_secret_values_never_enter_the_digests_but_everything_else_is_compared(self):
        """Security review SR-4: the raw configuration holds this device's Dashboard password and Erlang cookie (from
        the environment); the readback travels in the converted backup, so their values are redacted before hashing."""
        def device():
            return {'dashboard': {'default_password': 'device-pass-1', 'listeners': {'http': {'bind': 18083}}},
                    'node': {'name': 'emqx@127.0.0.1', 'cookie': 'device-cookie-1'},
                    'authentication': [{'mechanism': 'password_based', 'backend': 'built_in_database',
                                        'password_hash_algorithm': {'name': 'sha256', 'salt_position': 'suffix'}}],
                    'connectors': {'http': {'c1': {'url': 'http://user:pw-1@host:80/x', 'pool_size': 8,
                                                   'headers': {'authorization': 'Bearer tok-1'},
                                                   'ssl': {'password': 'k-1', 'enable': False}}}}}
        base_roots = ha_emqx.config_roots(device())
        shown = json.dumps(ha_emqx.redacted(device()))
        for secret in ('device-pass-1', 'device-cookie-1', 'pw-1', 'tok-1', 'k-1'):
            self.assertNotIn(secret, shown)
        same = (lambda c: c['dashboard'].update(default_password='other'),
                lambda c: c['node'].update(cookie='other'),
                lambda c: c['connectors']['http']['c1'].update(url='http://user:other@host:80/x'),
                lambda c: c['connectors']['http']['c1']['headers'].update(authorization='Bearer other'),
                lambda c: c['connectors']['http']['c1']['ssl'].update(password='other'))
        differs = ((lambda c: c['dashboard']['listeners']['http'].update(bind=18084), 'dashboard'),
                   (lambda c: c['node'].update(name='emqx@10.0.0.1'), 'node'),
                   (lambda c: c['authentication'][0]['password_hash_algorithm'].update(name='bcrypt'), 'authentication'),
                   (lambda c: c['connectors']['http']['c1'].update(url='http://user:pw-1@other:80/x'), 'connectors'),
                   (lambda c: c['connectors']['http']['c1'].update(pool_size=9), 'connectors'),
                   (lambda c: c['connectors']['http']['c1']['ssl'].update(enable=True), 'connectors'))
        for change in same:
            config = device(); change(config)
            self.assertEqual(ha_emqx.config_roots(config), base_roots)
        for change, root in differs:
            with self.subTest(root=root):
                config = device(); change(config)
                roots = ha_emqx.config_roots(config)
                self.assertNotEqual(roots[root], base_roots[root])
                self.assertEqual({k: v for k, v in roots.items() if k != root},
                                 {k: v for k, v in base_roots.items() if k != root})

    def test_the_receipt_answer_is_parsed_strictly(self):
        good = ('WOOWTAB:' + ''.join(f'{t}:{i}:{"F" * 64};' for i, t in enumerate(ha_emqx.STABLE_TABLES))
                + ':ENDok\n').encode()
        found = ha_emqx.table_receipts(answer(good))
        self.assertEqual(found['emqx_acl'], [2, 'f' * 64])
        absent = good.replace(b'emqx_psk:5:' + b'F' * 64, b'emqx_psk:-1:-')
        self.assertEqual(ha_emqx.table_receipts(answer(absent))['emqx_psk'], [-1, None])
        for raw, code in ((b'WOOWTAB:REFUSED', 0), (good, 1), (good.replace(b'emqx_acl', b'emqx_other'), 0),
                          (good.replace(b'emqx_banned_rules:6:' + b'F' * 64 + b';', b''), 0),
                          (good.replace(b'F' * 64, b'not-hex', 1), 0), (b'', 0)):
            with self.subTest(raw=raw[:40]), self.assertRaises(BackupError):
                ha_emqx.table_receipts(answer(raw, code))

    def adapter(self, config, tables, *, started_after=0, boot=None):
        calls = {'status': 0}

        class Runner:
            home = '/home/appowner'

            def podman(self, *args, **kwargs):
                if args[:2] != ('exec', 'woow-emqx'):
                    return Result(0, b'true\n', b'')   # container inspect: it runs
                command = list(args[2:])
                if args[:3] == ('container', 'inspect', '--format'):
                    return Result(0, b'true\n', b'')
                if command == ['emqx', 'ctl', 'status']:
                    calls['status'] += 1
                    started = calls['status'] > started_after
                    return Result(0 if started else 1, b"Node 'emqx@127.0.0.1' 5.8.9 is started\n" if started else b'',
                                  b'')
                if command == ['emqx', 'eval', ha_emqx.BOOT_CONFIG_EXPR]:
                    return flow.response(config if boot is None else boot)
                if command == ['emqx', 'eval', ha_emqx.CONFIG_EXPR]:
                    return flow.response(config)
                if command == ['emqx', 'eval', ha_emqx.TABLES_RECEIPT_EXPR]:
                    return Result(0, base.receipt_text({t: (n, h.upper() if h else None)
                                                        for t, (n, h) in tables.items()}), b'')
                raise AssertionError(command)
        adapter = SimpleNamespace(runner=Runner(), read_quadlets=lambda: base.QUADLETS)
        return adapter, calls

    def app(self):
        return fk.app('emqx', 'EMQX MQTT 代理', volumes=[{'name': 'woow_emqx_data'}, {'name': 'woow_emqx_log'}])

    def test_verify_restored_waits_for_the_broker_then_compares_the_tables(self):
        record = ha_emqx.readback_record(self.config(), TABLES)
        adapter, calls = self.adapter(self.config(), TABLES, started_after=2)
        logs = []
        ha_emqx.verify_restored(adapter, self.app(), record, log=logs.append, sleep=lambda _s: None)
        self.assertEqual(calls['status'], 3)
        self.assertEqual(len(logs), 1)
        self.assertIn('EMQX 還原後核對一致', logs[0])
        tables = copy.deepcopy(TABLES); tables['emqx_admin'] = [3, 'c' * 64]
        adapter, _ = self.adapter(self.config(), tables)
        with self.assertRaises(BackupError) as caught:
            ha_emqx.verify_restored(adapter, self.app(), record, log=logs.append, sleep=lambda _s: None)
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('內建資料庫（emqx_admin）', caught.exception.message)
        self.assertEqual(len(logs), 1, 'only an equal readback logs the success line')

    def test_a_difference_in_the_settings_alone_is_reminded_not_rolled_back(self):
        """E-90: a setting changed after the conversion, or the CPU count: accounts, ACL rules and keys are the same."""
        record = ha_emqx.readback_record(self.config(), TABLES)
        changed = self.config(); changed['authorization']['no_match'] = 'allow'
        adapter, _ = self.adapter(changed, TABLES)
        logs = []
        ha_emqx.verify_restored(adapter, self.app(), record, log=logs.append, sleep=lambda _s: None)   # no raise
        self.assertEqual(len(logs), 1)
        self.assertIn('提醒', logs[0])
        self.assertIn('設定（authorization）', logs[0])
        self.assertIn('沒有回復', logs[0])
        both = copy.deepcopy(TABLES); both['emqx_acl'] = [9, 'd' * 64]
        adapter, _ = self.adapter(changed, both)
        with self.assertRaises(BackupError) as caught:   # the rows differ as well: that rolls back
            ha_emqx.verify_restored(adapter, self.app(), record, log=logs.append, sleep=lambda _s: None)
        self.assertIn('內建資料庫（emqx_acl）', caught.exception.message)

    def test_the_restored_broker_is_compared_in_its_boot_form(self):
        """A boot fills schema defaults into the raw configuration (EMQX 5.8.9 emqx_config.erl:341,345); a runtime change
        does not. The record holds the boot form, so the restored broker's BOOT form is compared, never its plain read."""
        boot = copy.deepcopy(self.config())
        boot['authorization']['sources'][1]['max_rules'] = 100
        plain = copy.deepcopy(self.config())
        record = ha_emqx.readback_record(boot, TABLES)
        adapter, _ = self.adapter(plain, TABLES, boot=boot)
        logs = []
        ha_emqx.verify_restored(adapter, self.app(), record, log=logs.append, sleep=lambda _s: None)
        self.assertEqual(len(logs), 1)
        self.assertIn('核對一致', logs[0])
        adapter, _ = self.adapter(boot, TABLES, boot=plain)   # the plain read would be equal, the boot form is not
        ha_emqx.verify_restored(adapter, self.app(), record, log=logs.append, sleep=lambda _s: None)
        self.assertIn('設定（authorization）', logs[-1], 'compared in the boot form: the difference is reminded')

    def test_a_receipt_that_cannot_be_read_or_was_not_recorded_skips_the_row_comparison_and_says_so(self):
        """E-84: after the restore."""
        record = ha_emqx.readback_record(self.config(), TABLES)
        adapter, _ = self.adapter(self.config(), TABLES)

        def refused(*args, **kwargs):
            raise BackupError('job-failed', 'x')
        logs = []
        with mock.patch.object(ha_emqx, 'table_receipts', refused):
            ha_emqx.verify_restored(adapter, self.app(), record, log=logs.append, sleep=lambda _s: None)
        self.assertEqual(len(logs), 1)
        self.assertIn('略過帳號與 ACL 規則的核對', logs[0])
        unrecorded = ha_emqx.readback_record(self.config(), None)
        adapter, _ = self.adapter(self.config(), {t: [9, 'e' * 64] for t in ha_emqx.STABLE_TABLES})
        logs = []
        ha_emqx.verify_restored(adapter, self.app(), unrecorded, log=logs.append, sleep=lambda _s: None)
        self.assertIn('略過帳號與 ACL 規則的核對', logs[0])

    def test_a_slow_broker_that_still_runs_is_waited_for_and_one_that_ended_fails_at_once(self):
        """E-88: still starting -> keep waiting (more than the 300 s); really ended -> the restore rolls back by itself."""
        record = ha_emqx.readback_record(self.config(), TABLES)
        adapter, calls = self.adapter(self.config(), TABLES, started_after=400)   # 400 polls of 2 s: 800 s, past the 300 s
        logs = []
        ha_emqx.verify_restored(adapter, self.app(), record, log=logs.append, sleep=lambda _s: None)
        self.assertEqual(calls['status'], 401)
        adapter, calls = self.adapter(self.config(), TABLES, started_after=10 ** 6)
        original = adapter.runner.podman

        def ended(*args, **kwargs):
            if args[:3] == ('container', 'inspect', '--format'):
                return Result(0, b'false\n', b'')
            return original(*args, **kwargs)
        adapter.runner.podman = ended
        with self.assertRaises(BackupError) as caught:
            ha_emqx.verify_restored(adapter, self.app(), record, log=lambda _l: None, sleep=lambda _s: None)
        self.assertIn('結束', caught.exception.message)
        self.assertLessEqual(calls['status'], 2)

    def test_the_wait_grows_with_the_data_and_ends_at_the_cap(self):
        ticks = iter(range(0, 10 ** 6, 100))
        probe = lambda _command: Result(1, b'', b'')
        with self.assertRaises(BackupError) as caught:
            ha_emqx.wait_live_ready(probe, sleep=lambda _s: None, clock=lambda: next(ticks), running=lambda: True)
        self.assertIn(str(ha_emqx.READY_TIMEOUT + ha_emqx.READY_EXTENDED), caught.exception.message)
        ticks = iter(range(0, 10 ** 6, 100))
        with self.assertRaises(BackupError) as caught:   # without a way to tell whether it still runs: the plain limit
            ha_emqx.wait_live_ready(probe, sleep=lambda _s: None, clock=lambda: next(ticks))
        self.assertIn(f'{ha_emqx.READY_TIMEOUT} 秒', caught.exception.message)
        bigger = ha_emqx.podman.scaled_timeout(ha_emqx.READY_TIMEOUT, 500 * 1024 ** 3)
        self.assertGreater(bigger, ha_emqx.READY_TIMEOUT)

    def test_a_broker_that_never_starts_fails_and_an_unknown_record_is_skipped_with_a_reminder(self):
        record = ha_emqx.readback_record(self.config(), TABLES)
        adapter, _ = self.adapter(self.config(), TABLES, started_after=10 ** 6)
        ticks = iter(range(0, 10 ** 6, 50))
        with self.assertRaises(BackupError) as caught:
            ha_emqx.verify_restored(adapter, self.app(), record, log=lambda _l: None, sleep=lambda _s: None,
                                    clock=lambda: next(ticks))
        self.assertIn('沒有啟動完成', caught.exception.message)
        for bad in (dict(record, kind='other'), dict(record, version=2), None):
            logs = []
            with self.subTest(bad=bool(bad)):
                ha_emqx.verify_restored(self.adapter(self.config(), TABLES)[0], self.app(), bad, log=logs.append)
                self.assertEqual(len(logs), 1)   # E-89: the restored data is not undone for it
                self.assertIn('不認得', logs[0])


class ManifestFormatTests(unittest.TestCase):
    def test_the_archive_accepts_exactly_the_readback_shape(self):
        good = ha_emqx.readback_record({'node': {}, 'authorization': {}}, copy.deepcopy(TABLES))
        archive.validate_import_check(good, 'emqx')
        bad = []
        bad.append(('another app', good, 'odoo'))
        bad.append(('unknown kind', dict(good, kind='other'), 'emqx'))
        bad.append(('version', dict(good, version=2), 'emqx'))
        bad.append(('extra key', dict(good, extra=1), 'emqx'))
        bad.append(('no roots', dict(good, config_roots={}), 'emqx'))
        bad.append(('bad digest', dict(good, config_roots={'node': 'x'}), 'emqx'))
        bad.append(('bad root name', dict(good, config_roots={'Node!': 'a' * 64}), 'emqx'))
        tables = copy.deepcopy(TABLES); del tables['emqx_acl']
        bad.append(('missing table', dict(good, tables=tables), 'emqx'))
        tables = copy.deepcopy(TABLES); tables['emqx_acl'] = [-1, 'a' * 64]
        bad.append(('missing table with digest', dict(good, tables=tables), 'emqx'))
        tables = copy.deepcopy(TABLES); tables['emqx_acl'] = [True, 'a' * 64]
        bad.append(('bool rows', dict(good, tables=tables), 'emqx'))
        for name, item, app_id in bad:
            with self.subTest(name), self.assertRaises(BackupError) as caught:
                archive.validate_import_check(item, app_id)
            self.assertEqual(caught.exception.code, 'invalid-manifest')

    def test_the_restore_knows_exactly_the_readback_kinds_the_archive_accepts(self):
        self.assertEqual({kind: app for kind, (app, _tables) in archive.IMPORT_CHECK_KINDS.items()},
                         haimport.IMPORT_CHECKS)
        self.assertEqual(archive.IMPORT_CHECK_KINDS['emqx-readback'][1], ha_emqx.STABLE_TABLES)
        app = SimpleNamespace(id='emqx', name='EMQX MQTT 代理')
        self.assertIsNone(haimport.import_check_problem(app, {'kind': 'emqx-readback'}))
        for check in ({'kind': 'other'}, {}, None, 'emqx-readback'):
            with self.subTest(check=check):
                self.assertIn('匯入核對資料', haimport.import_check_problem(app, check))
        self.assertIn('匯入核對資料', haimport.import_check_problem(SimpleNamespace(id='odoo', name='Odoo'),
                                                                 {'kind': 'emqx-readback'}))

    def test_verify_import_dispatches_only_a_known_kind_to_its_importer(self):
        app = SimpleNamespace(id='emqx', name='EMQX MQTT 代理')
        calls = []
        with mock.patch.object(ha_emqx, 'verify_restored', lambda *a, **k: calls.append(a[2])):
            haimport.verify_import(app, object(), {'kind': 'emqx-readback'}, log=lambda _l: None)
            with self.assertRaises(BackupError) as caught:
                haimport.verify_import(app, object(), {'kind': 'other'}, log=lambda _l: None)
        self.assertEqual(calls, [{'kind': 'emqx-readback'}])
        self.assertEqual(caught.exception.code, 'incompatible')


class RestoreReadbackTests(tf.RestoreCase):
    """flows.run_restore of a backup whose app section carries an import_check (the fake world's app)."""

    def mark(self, check):
        path = self.storage.archive_path(self.backup_id)
        data = json.loads(path.read_text())
        for app in data['manifest']['apps']:
            if app['id'] == 'woowbk-demo':
                app['import_check'] = check
        path.write_text(json.dumps(data))

    def test_the_readback_runs_after_the_health_checks(self):
        calls = []
        self.mark({'kind': 'lab'})
        with mock.patch.object(haimport, 'import_check_problem', lambda app, check: None), \
                mock.patch.object(haimport, 'verify_import',
                                  lambda app, adapter, check, log: calls.append((app.id, check, adapter.app.id))):
            result = self.restore()
        self.assertEqual(calls, [('woowbk-demo', {'kind': 'lab'}, 'woowbk-demo')])
        self.assertIs(result['rolled_back'], False)
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v1')

    def test_a_difference_rolls_the_restore_back(self):
        def differs(app, adapter, check, log):
            raise BackupError('job-failed', 'EMQX 還原後的設定（log）和轉換時核對的不同，已停止。', app=app.id)
        self.mark({'kind': 'lab'})
        with mock.patch.object(haimport, 'import_check_problem', lambda app, check: None), \
                mock.patch.object(haimport, 'verify_import', differs):
            with self.assertRaises(flows.RolledBack) as caught:
                self.restore()
        self.assertTrue(caught.exception.result['rolled_back'])
        self.assertIn('設定（log）', caught.exception.error.message)
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed', 'the pre-restore state is back')

    def test_an_unknown_readback_refuses_before_anything_changes(self):
        self.mark({'kind': 'other'})
        with self.assertRaises(BackupError) as caught:
            self.restore()
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('匯入核對資料', caught.exception.message)
        self.assertEqual(self.world.data['woowbk-demo'], b'notes-v2-changed')
        self.assertEqual(self.safety_ids(), [])

    def test_a_section_without_a_readback_is_not_compared(self):
        with mock.patch.object(haimport, 'verify_import', mock.Mock(side_effect=AssertionError('not expected'))):
            result = self.restore()
        self.assertIs(result['rolled_back'], False)


if __name__ == '__main__':
    unittest.main()
