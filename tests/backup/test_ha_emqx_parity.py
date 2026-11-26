"""HAOS parity of the EMQX import (lane EMQX-A, 2026-11-25): what the other EMQX test modules do not say -- each issue the module
makes with its level and its names, the three steps of every line to confirm (not confirmed: only this app stops;
confirmed: it goes on; another name: confirm again), what the automatic rows do when they work and when they cannot, and
the small readings behind them (published ports, node databases, image downloads, version asked of the running broker,
waits, export size, TLS fingerprints, the owner of the candidate's files). Generated transports only: no broker, no podman,
no device. Rows: E-02 E-04 E-12 E-13 E-54 E-56 E-64 E-73a-c and the lines of D0-D5 / S1 / S2 (E-16..E-20, E-67, E-75..E-79, E-82)."""
import copy
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from woowbackup import ha_emqx, haissues, tempctr
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import hab1fakes as fk
from . import test_ha_emqx as base
from . import test_ha_emqx_candidate_flow as flow


def levels(issues):
    return {issue.id: issue.level for issue in issues}


class IssueTableTests(unittest.TestCase):
    def test_every_declared_issue_has_a_level_the_module_uses_it_with(self):
        for issue_id, level in ha_emqx.ISSUES.items():
            self.assertRegex(issue_id, haissues.ID_RE)
            self.assertIn(level, haissues.LEVELS)
            self.assertTrue(issue_id.startswith('emqx.'), issue_id)
        self.assertEqual({i for i, lv in ha_emqx.ISSUES.items() if lv == 'confirm'},
                         {'emqx.file-secret', 'emqx.jq-rule', 'emqx.external-authn', 'emqx.external-authz', 'emqx.exhook',
                          'emqx.no-authentication', 'emqx.import-partial', 'emqx.default-dashboard-exposed',
                          'emqx.device-integrations', 'emqx.device-routing', 'emqx.device-psk', 'emqx.durable-sessions'})
        self.assertEqual({i for i, lv in ha_emqx.ISSUES.items() if lv == 'stop'},
                         {'emqx.no-database', 'emqx.node-gone', 'emqx.config-changing', 'emqx.data-dir-moved',
                          'emqx.output-dir-unusable'})

    def test_the_old_protections_of_the_owner_decisions_that_are_superseded_are_gone(self):
        """E-73a, E-73b, E-73c: nothing of this device's authorization is preserved, switched off or written back any more."""
        for name in ('ha_emqx_acl_preservation', 'ha_emqx_acl_path_proof', 'ha_emqx_authorizers'):
            self.assertIsNone(importlib.util.find_spec(f'woowbackup.{name}'), name)
        for name in ('disabled_intermediate', 'candidate_acl_receipt', 'observe_generated_path', 'preserved_bootstrap_authn',
                     'source_profile', 'acl_blocker', 'plain_blocker', 'analyse'):
            self.assertFalse(hasattr(ha_emqx, name), name)
        self.assertEqual(ha_emqx.preserved_settings({'authorization': {}, 'authentication': [], 'node': {'name': 'n'},
                                                     'rule_engine': {}, 'listeners': {}}),
                         {'node': {'name': 'n'}, 'listeners': {}},
                         'only the roots HA does not bring are this device\'s own')


class PublishedPortTests(unittest.TestCase):
    """S2, H3: what the installed Quadlet files publish (already rendered to real addresses)."""

    def test_the_forms_podman_reads(self):
        parse = ha_emqx.parse_publish
        self.assertEqual(parse('127.0.0.1:1883:1883'), ('127.0.0.1', '1883', '1883'))
        self.assertEqual(parse('0.0.0.0:18083:18083/tcp'), ('0.0.0.0', '18083', '18083'))
        self.assertEqual(parse('[::1]:1883:1883'), ('::1', '1883', '1883'))
        self.assertEqual(parse('1883:1883'), ('', '1883', '1883'))
        self.assertEqual(parse('"192.168.2.5:8883:8883"'), ('192.168.2.5', '8883', '8883'))
        for bad in ('', 'bad', '1:2:3:4:5', '127.0.0.1:x:1883', None):
            self.assertIsNone(parse(bad), bad)
        self.assertEqual(ha_emqx.exposure(SimpleNamespace(publish=[parse('${BIND}:1883:1883')], other_publish=[], tunnels=[]),
                                          ha_emqx.MQTT_PORTS), 'network', 'an address that is not the loopback is the wide case')

    def target(self, publish=(), other=(), tunnels=()):
        return SimpleNamespace(publish=[ha_emqx.parse_publish(p) for p in publish],
                               other_publish=[ha_emqx.parse_publish(p) for p in other], tunnels=list(tunnels))

    def test_exposure_is_the_widest_address_of_the_ports_asked_about(self):
        mqtt, dashboard = ha_emqx.MQTT_PORTS, ha_emqx.DASHBOARD_PORTS
        self.assertEqual(ha_emqx.exposure(self.target(), mqtt), 'closed')
        self.assertEqual(ha_emqx.exposure(self.target(['127.0.0.1:1883:1883']), mqtt), 'local')
        self.assertEqual(ha_emqx.exposure(self.target(['127.0.0.1:1883:1883', '0.0.0.0:8883:8883']), mqtt), 'network')
        self.assertEqual(ha_emqx.exposure(self.target(['1883:1883']), mqtt), 'network', 'no address = every interface')
        self.assertEqual(ha_emqx.exposure(self.target(['0.0.0.0:18083:18083']), mqtt), 'closed', 'another port')
        self.assertEqual(ha_emqx.exposure(self.target(['127.0.0.1:18083:18083']), dashboard), 'local')
        self.assertEqual(ha_emqx.exposure(self.target(['127.0.0.1:18083:18083'], other=['0.0.0.0:8080:80']), dashboard),
                         'network', 'an entrance of the app may front the Dashboard')
        self.assertEqual(ha_emqx.exposure(self.target(['127.0.0.1:1883:1883'], other=['0.0.0.0:8080:80']), mqtt), 'local')


class NodePickTests(unittest.TestCase):
    def source(self, dirs, record=None, written=None):
        src = ha_emqx.Source()
        src.node_dirs, src.node_file, src.node_written = set(dirs), record, dict(written or {})
        return src

    def test_the_record_wins_the_only_database_is_next_the_last_written_is_the_default(self):
        a, b = 'emqx@old.local', 'emqx@new.local'
        self.assertEqual(ha_emqx.pick_node(self.source([a, b], record=a)), (a, [], None))
        name, rows, said = ha_emqx.pick_node(self.source([a, b], written={a: 100, b: 2_000_000_000}))
        self.assertEqual((name, [r['value'] for r in rows], [r['default'] for r in rows]), (b, [b, a], [True, False]))
        self.assertIn(b, said)
        name, rows, said = ha_emqx.pick_node(self.source([a, b], written={a: 7, b: 7}))
        self.assertEqual(name, max(a, b), 'a tie goes to the name that sorts last, always the same one')
        self.assertEqual(ha_emqx.pick_node(self.source([a], record='emqx@other.local'))[0], a)
        self.assertEqual(ha_emqx.pick_node(self.source([a], record=None)), (a, [], None))
        self.assertEqual(ha_emqx.pick_node(self.source([a, b]), chosen=a), (a, [], None), 'the customer\'s choice wins')
        self.assertIn('最後寫入時間不明', ha_emqx.pick_node(self.source([a, b]))[1][0]['label'])

    def test_what_cannot_be_used_stops_only_this_app_with_its_id(self):
        a = 'emqx@old.local'
        for src, chosen, issue in ((self.source([]), None, 'emqx.no-database'), (self.source([a]), 'emqx@gone', 'emqx.node-gone'),
                                   (self.source(['bad node@x']), None, 'emqx.node-gone'),
                                   (self.source([a, 'bad node@x'], record=None, written={'bad node@x': 5}), None, 'emqx.node-gone')):
            with self.subTest(issue=issue, chosen=chosen), self.assertRaises(BackupError) as caught:
                ha_emqx.pick_node(src, chosen)
            self.assertEqual([i.id for i in caught.exception.issues], [issue])
            self.assertEqual(caught.exception.issues[0].level, 'stop')
        self.assertIn('請', caught.exception.issues[0].action)


class WaitTests(unittest.TestCase):
    """E-12 (HA's and the candidate's broker), E-88 (the restored one): the wait grows with the data and goes on while the
    broker runs; only an ended broker, the cap or a cancel stops it."""

    def tmp(self, answers, running=lambda role: True):
        calls = []

        class Transport:
            def exec(self, role, command, **kwargs):
                calls.append(command)
                return Result(*next(answers))

            def running(self, role):
                return running(role)
        return Transport(), calls

    def test_a_slow_broker_is_waited_for_and_a_big_backup_is_given_more_time(self):
        answers = iter([(1, b'', b'')] * 400 + [(0, b'is started', b'')])
        tmp, calls = self.tmp(answers)
        ticks = iter(range(0, 10 ** 6, 2))
        ha_emqx.wait_ready(tmp, 'emqx-ha', checkpoint=None, sleep=lambda _s: None, clock=lambda: next(ticks))
        self.assertEqual(len(calls), 401, 'past the 300 s, while it still runs')
        self.assertGreater(ha_emqx.podman.scaled_timeout(ha_emqx.READY_TIMEOUT, 800 * 1024 ** 3), ha_emqx.READY_TIMEOUT)

    def test_an_ended_broker_stops_the_app_at_once_with_the_advice(self):
        tmp, calls = self.tmp(iter([(1, b'', b'')] * 5), running=lambda role: False)
        with self.assertRaises(BackupError) as caught:
            ha_emqx.wait_ready(tmp, 'emqx-ha', checkpoint=None, hint='請重新備份。', sleep=lambda _s: None)
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('請重新備份。', caught.exception.message)
        self.assertEqual(len(calls), 1)

    def test_a_broker_that_never_answers_ends_at_the_cap_and_a_cancel_ends_it_sooner(self):
        tmp, calls = self.tmp(iter([(1, b'', b'')] * 10 ** 5))
        ticks = iter(range(0, 10 ** 7, 50))
        with self.assertRaises(BackupError) as caught:
            ha_emqx.wait_ready(tmp, 'emqx-ha', checkpoint=None, sleep=lambda _s: None, clock=lambda: next(ticks))
        self.assertIn(str(ha_emqx.READY_TIMEOUT + ha_emqx.READY_EXTENDED), caught.exception.message)
        tmp, calls = self.tmp(iter([(1, b'', b'')] * 10 ** 5))

        def cancelled():
            if len(calls) >= 3:
                raise BackupError('busy', 'cancel')
        with self.assertRaises(BackupError) as caught:
            ha_emqx.wait_ready(tmp, 'emqx-ha', checkpoint=cancelled, sleep=lambda _s: None)
        self.assertEqual(caught.exception.code, 'busy')
        self.assertEqual(len(calls), 3)


class DownloadsAndVersionWorld(base.World):
    """The image of this device is not here until it is pulled (E-02); it carries no version label (E-04)."""

    def __init__(self):
        super().__init__()
        self.pulled = self.pull_fails = False
        self.labelled = True
        self.said_version = '5.8.9'
        self.pulls = []

    def podman(self, args, data, stdout):
        if args[:1] == ['pull']:
            self.pulls.append(args[-1])
            if self.pull_fails:
                return Result(125, b'', b'Error: initializing source docker://x: pinging container registry: dial tcp: lookup x')
            self.pulled = True
            return Result(0, b'sha256:abc\n', b'')
        if args[:2] == ['image', 'inspect'] and not self.pulled:
            return Result(1, b'', b'Error: no such image')
        return super().podman(args, data, stdout)

    def labels(self, image):
        return {'org.opencontainers.image.version': self.version} if self.labelled else {}

    def evaluate(self, role, expression):
        if expression == ha_emqx.VERSION_EXPR:
            return f'WOOWVER:{self.said_version}:END\nok\n'.encode() if self.said_version else b'badrpc\n'
        return super().evaluate(role, expression)


class TargetImageTests(base.EmqxCase):
    world_class = DownloadsAndVersionWorld

    def test_an_image_that_is_not_here_is_downloaded_as_the_owner_and_said(self):
        """E-02: auto -- it works, and says it did."""
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        self.assertEqual(self.world.pulls, ['docker.io/emqx/emqx:5.8.9'])
        self.assertIn('target.image-pulled', [i['id'] for i in result['issues'] if i['level'] == 'auto'])

    def test_an_image_that_cannot_be_downloaded_stops_only_this_app(self):
        """E-02: auto -- and what it cannot do stops this app, with the reason; nothing of this device changed."""
        self.world.pull_fails = True
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertFalse(result['importable'])
        self.assertEqual([i['id'] for i in result['issues'] if i['level'] == 'stop'], ['target.image-missing'])
        self.assertFalse(self.runs('emqx-ha'), 'HA\'s broker never started')

    def test_a_quadlet_that_names_no_image_is_the_one_case_that_still_stops(self):
        quadlets = dict(base.QUADLETS)
        quadlets['emqx.container'] = base.QUADLETS['emqx.container'].replace(b'Image=docker.io/emqx/emqx:5.8.9\n', b'')
        self.world.quadlets = {'emqx': quadlets}
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertFalse(result['importable'])
        self.assertIn('Quadlet 設定缺少映像', result['blockers'][0])

    def test_an_image_without_a_version_label_asks_the_running_broker(self):
        """E-04: auto -- the version the running EMQX says is used and said; nothing said: tried anyway, as a notice."""
        self.world.labelled = False
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        self.assertEqual(result['target_version'], '5.8.9')
        self.assertIn('emqx.version-asked', [i['id'] for i in result['issues'] if i['level'] == 'auto'])
        self.assertIn('5.8.9', json.dumps(result['issues'], ensure_ascii=False))

    def test_a_running_broker_that_says_nothing_is_tried_anyway(self):
        self.world.labelled = False
        self.world.said_version = None
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        self.assertEqual(result['target_version'], '')
        self.assertIn('version.target-unknown', [i['id'] for i in result['issues'] if i['level'] == 'notice'])
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertTrue(done['backup_id'])


class TickerWorld(base.World):
    """The system-message ticker of the throwaway brokers cannot be paused (E-13)."""
    pause = True

    def evaluate(self, role, expression):
        if expression == ha_emqx.SUSPEND_SYS_EXPR and not self.pause:
            return b'badrpc\n'
        return super().evaluate(role, expression)


class TickerTests(base.EmqxCase):
    world_class = TickerWorld

    def test_a_ticker_that_cannot_be_paused_is_said_and_the_conversion_goes_on(self):
        """E-13: auto/notice -- the retained messages may differ by a few rows, which the row check allows."""
        self.world.pause = False
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        self.assertIn('emqx.sys-ticker', [i['id'] for i in result['issues'] if i['level'] == 'notice'])
        self.assertTrue(self.convert(self.upload_emqx(state='stopped'), ['emqx'])['backup_id'])

    def test_a_ticker_that_was_paused_needs_no_notice_and_no_slack(self):
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertNotIn('emqx.sys-ticker', [i['id'] for i in result['issues']])

    def test_the_slack_never_hides_a_lost_account(self):
        self.world.pause = False
        self.world.import_lost = 'emqx_authn_mnesia'
        with self.assertRaises(BackupError) as caught:
            self.internal_candidate(self.upload_emqx(state='stopped'))
        self.assertIn('emqx_authn_mnesia', caught.exception.message)


class SmallReadingTests(unittest.TestCase):
    def test_an_image_certificate_that_cannot_be_read_is_left_out_not_refused(self):
        """E-54: remove -- no check of the image's own certificate when it cannot be read; the log says so."""
        path = '/opt/emqx/etc/certs/cert.pem'
        good = b'a' * 64 + b'  ' + path.encode() + b'\n'
        answers = {'ok': Result(0, good, b''), 'failed': Result(1, b'', b''), 'other file': Result(0, b'a' * 64 + b'  /x\n', b''),
                   'long': Result(0, good * 40, b'')}
        self.assertEqual(ha_emqx.tls_fingerprints(lambda _c: answers['ok'], {path}), {path: b'a' * 64})
        for name in ('failed', 'other file', 'long'):
            self.assertEqual(ha_emqx.tls_fingerprints(lambda _c, n=name: answers[n], {path}), {}, name)
        with self.assertRaises(BackupError):   # a path that is not one of the image's files is still refused
            ha_emqx.tls_fingerprints(lambda _c: answers['ok'], {'/etc/passwd'})

    def test_the_files_of_the_candidate_may_belong_to_root(self):
        """E-56: remove -- an image whose emqx user is root is no reason to stop (the files are made root's)."""
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / 'snapshot.tar'
            with tarfile.open(snapshot, 'w') as archive_:
                info = tarfile.TarInfo('configs/cluster.hocon')
                info.size = 1
                archive_.addfile(info, io.BytesIO(b'x'))
            imported = []
            tmp = SimpleNamespace(volume_import=lambda role, produce: (lambda out: (produce(out), imported.append(out.getvalue())))(io.BytesIO()))
            ha_emqx.import_target_snapshot(tmp, snapshot, (0, 0))
            with tarfile.open(fileobj=io.BytesIO(imported[0])) as seeded:
                self.assertEqual({(m.uid, m.gid) for m in seeded.getmembers()}, {(0, 0)})
            for bad in ((-1, 0), (0,), (0, 0, 0), ('0', 0), (True, 0)):
                with self.subTest(ids=bad), self.assertRaises(BackupError):
                    ha_emqx.import_target_snapshot(tmp, snapshot, bad)

    def test_the_export_is_bounded_by_the_disk_not_by_two_gibibytes(self):
        """E-64: remove -- the old 2 GiB cap and its wrong sentence ("not found"); the room for the copy decides."""
        self.assertGreater(ha_emqx.MAX_EXPORT, 2 * 1024 ** 3)
        checked = []
        with tempfile.TemporaryDirectory() as directory:
            staging = Path(directory)

            def exporter(role, handle, max_output=None):
                with tarfile.open(fileobj=handle, mode='w') as archive_:
                    info = tarfile.TarInfo('out/emqx-export-2026-11-19-10-11-12.345.tar.gz')
                    info.size = 3 * 1024 ** 2
                    archive_.addfile(info, io.BytesIO(b'x' * info.size))
            tmp = SimpleNamespace(volume_export=exporter)
            guard = SimpleNamespace(budget=lambda: 10 ** 9, check=lambda need: checked.append(need))
            work = SimpleNamespace(guard=guard)
            path = ha_emqx.take_export(work, tmp, '/work/out/emqx-export-2026-11-19-10-11-12.345.tar.gz', staging)
            self.assertEqual(path.stat().st_size, 3 * 1024 ** 2)
            self.assertEqual(checked, [3 * 1024 ** 2], 'the room for the copy is asked for, the size is not capped')
            for name in ('two', 'three'):
                (staging / name).mkdir()
            full = SimpleNamespace(guard=SimpleNamespace(budget=lambda: 10 ** 9, check=lambda need: (_ for _ in ()).throw(
                BackupError('insufficient-space', '空間不足'))))
            with self.assertRaises(BackupError) as caught:
                ha_emqx.take_export(full, tmp, '/work/out/emqx-export-2026-11-19-10-11-12.345.tar.gz', staging / 'two')
            self.assertEqual(caught.exception.code, 'insufficient-space')
            ha_emqx_cap = ha_emqx.MAX_EXPORT
            try:
                ha_emqx.MAX_EXPORT = 1024
                with self.assertRaises(BackupError) as caught:
                    ha_emqx.take_export(work, tmp, '/work/out/emqx-export-2026-11-19-10-11-12.345.tar.gz', staging / 'three')
                self.assertNotIn('找不到', caught.exception.message, 'a size that is too much is not "not found"')
            finally:
                ha_emqx.MAX_EXPORT = ha_emqx_cap

    def test_a_missing_export_is_still_not_found(self):
        with tempfile.TemporaryDirectory() as directory:
            def exporter(role, handle, max_output=None):
                with tarfile.open(fileobj=handle, mode='w') as archive_:
                    pass
            work = SimpleNamespace(guard=SimpleNamespace(budget=lambda: 10 ** 9, check=lambda need: None))
            with self.assertRaises(BackupError) as caught:
                ha_emqx.take_export(work, SimpleNamespace(volume_export=exporter),
                                    '/work/out/emqx-export-2026-11-19-10-11-12.345.tar.gz', Path(directory))
            self.assertIn('找不到', caught.exception.message)

    def test_what_import_names_as_failed_is_roots_and_tables_only(self):
        text = b'[error] failed: rule_engine rules r1 password=hunter2; table emqx_acl: badmatch connectors'
        self.assertEqual(ha_emqx.partial_items(text), ['rule_engine', 'connectors', 'emqx_acl'])
        self.assertEqual(ha_emqx.partial_items(b'nothing it names'), [])
        self.assertNotIn('hunter2', ' '.join(ha_emqx.partial_items(text)))
        self.assertEqual(ha_emqx.partial_items(b'sources_x authentication2'), [], 'a root name inside another word is none')


class ThreeStepsTests(base.EmqxCase):
    """G1: every line to confirm: not confirmed -> only this app stops (`confirmation-required`); confirmed -> it goes on;
    one more name -> confirm again (a line without names has no such step: its key is the same whatever the numbers say)."""
    world_class = base.World

    def three(self, issue_id, make, *, more=None):
        """`make()` sets the World up; `more()` adds one name to what HA brought."""
        make()
        ha_id = self.upload_emqx(state='stopped')
        found = [i for i in self.internal_candidate(ha_id)['issues'] if i.id == issue_id]
        self.assertEqual(len(found), 1, issue_id)
        line = found[0]
        self.assertEqual(line.level, 'confirm')
        self.world.again()
        make()
        with self.assertRaises(BackupError) as caught:
            self.internal_candidate(ha_id, acknowledged=[])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertTrue(caught.exception.issues and caught.exception.issues[0].id == issue_id)
        self.world.again()
        make()
        self.assertTrue(self.internal_candidate(ha_id, acknowledged=[line.key('emqx')])['volumes'])
        if more is not None:
            self.world.again()
            make()
            more()
            with self.assertRaises(BackupError) as caught:
                self.internal_candidate(ha_id, acknowledged=[line.key('emqx')])
            self.assertEqual(caught.exception.code, 'confirmation-required', 'another name is another line')
        return line

    def test_nobody_has_to_log_in(self):
        def make():
            self.world.ha_authn = '[{password_based,built_in_database,false,sha256,suffix}]'
        line = self.three('emqx.no-authentication', make)
        self.assertEqual(line.names, ())
        self.assertIn('MQTT 埠', line.message)

    def test_an_import_that_is_partial(self):
        self.three('emqx.import-partial', lambda: setattr(self.world, 'import_output', b'imported, but errors in rule_engine\n'),
                   more=lambda: setattr(self.world, 'import_output', b'imported, but errors in rule_engine connectors\n'))

    def test_the_default_dashboard_account_where_the_network_can_reach_it(self):
        def make():
            self.world.default_admin = True
            exposed = dict(base.QUADLETS)
            exposed['emqx.container'] = base.QUADLETS['emqx.container'].replace(
                b'Volume=emqx-data', b'PublishPort=0.0.0.0:18083:18083\nVolume=emqx-data')
            self.world.quadlets = {'emqx': exposed}
        line = self.three('emqx.default-dashboard-exposed', make)
        self.assertIn('admin／public', line.message)
        self.assertIn('開在區網上', line.message)

    def test_the_default_dashboard_account_on_this_machine_only_is_a_notice(self):
        self.world.default_admin = True
        result = self.internal_candidate(self.upload_emqx(state='stopped'))
        self.assertEqual(levels(result['issues']).get('emqx.default-dashboard'), 'notice')
        self.assertNotIn('emqx.default-dashboard-exposed', levels(result['issues']))
        self.world.again()
        self.assertTrue(self.internal_candidate(self.upload_emqx(state='stopped'), acknowledged=[])['volumes'],
                        'a notice needs no confirmation')


class NoticeLinesTests(unittest.TestCase):
    """The lines the candidate's notes become, one by one (candidate_lines, source_lines, account_lines): ids, levels, names
    only -- never a value -- and the numbers in the message."""

    def sink(self):
        return haissues.Sink('emqx')

    def target(self):
        return SimpleNamespace(publish=[], other_publish=[], tunnels=[])

    def lines(self, notes, readings=None, device=None, target=None):
        sink = self.sink()
        ha_emqx.candidate_lines(sink, target or self.target(), readings, notes, device)
        return {issue.id: issue for issue in sink.found}

    def test_every_note_has_its_line(self):
        notes = {'rereads': 1, 'access_env': ['EMQX_AUTHORIZATION__NO_MATCH'], 'differs': ['log', 'dashboard'],
                 'missing': ['authz/custom.acl'], 'partial': ['rule_engine'], 'acl_replaced': ['authz/acl.conf'],
                 'bootstrap': ['ha-authn', 'hash'], 'lost': ['/opt/emqx/etc/woow-mqtt-bootstrap.csv'], 'ticker': False,
                 'receipt_unreadable': True,
                 'security': {'file_secret': ['connectors.http.erp'], 'jq_rule': ['rule_abc'], 'external_authn': ['HTTP'],
                              'external_authz': ['Redis'], 'exhook': ['default']},
                 'anonymous': True, 'device_authenticated': True}
        found = self.lines(notes, device={'names': ['woow', 'sensor-01'], 'count': 2})
        self.assertEqual({i: lv.level for i, lv in found.items()},
                         {'emqx.config-reread': 'auto', 'emqx.env-wins': 'notice', 'emqx.config-differs': 'notice',
                          'emqx.target-file-missing': 'notice', 'emqx.import-partial': 'confirm', 'emqx.file-secret': 'confirm',
                          'emqx.jq-rule': 'confirm', 'emqx.external-authn': 'confirm', 'emqx.external-authz': 'confirm',
                          'emqx.exhook': 'confirm', 'emqx.no-authentication': 'confirm', 'emqx.acl-replaced': 'notice',
                          'emqx.bootstrap-lost': 'notice', 'emqx.sys-ticker': 'notice', 'emqx.receipt-unreadable': 'notice'})
        self.assertEqual(found['emqx.bootstrap-lost'].names, ('woow', 'sensor-01'))
        for text in ('bootstrap 帳號檔', 'clientid', 'hash'):
            self.assertIn(text, found['emqx.bootstrap-lost'].message)
        self.assertEqual(found['emqx.env-wins'].names, ('EMQX_AUTHORIZATION__NO_MATCH',))
        self.assertIn('HA 的設定', found['emqx.env-wins'].message)
        self.assertEqual(self.lines({}), {}, 'nothing noted, nothing said')

    def test_no_authentication_is_said_only_when_it_changes_who_can_connect(self):
        self.assertIn('emqx.no-authentication', self.lines({'anonymous': True, 'device_authenticated': True}))
        self.assertNotIn('emqx.no-authentication', self.lines({'anonymous': True, 'device_authenticated': False}),
                         'this device already let everybody in')
        self.assertNotIn('emqx.no-authentication', self.lines({'anonymous': False, 'device_authenticated': True}))

    def test_the_port_and_the_tunnel_are_in_the_sentence_not_in_the_key(self):
        local = SimpleNamespace(publish=[ha_emqx.parse_publish('127.0.0.1:1883:1883')], other_publish=[], tunnels=[])
        wide = SimpleNamespace(publish=[ha_emqx.parse_publish('0.0.0.0:1883:1883')], other_publish=[], tunnels=['emqx-ngrok'])
        notes = {'anonymous': True, 'device_authenticated': True}
        one, two = self.lines(notes, target=local)['emqx.no-authentication'], self.lines(notes, target=wide)['emqx.no-authentication']
        self.assertIn('只有本機能連', one.message)
        self.assertIn('整個區網都能連', two.message)
        self.assertIn('emqx-ngrok', two.message)
        self.assertEqual(one.key('emqx'), two.key('emqx'), 'a sentence that can change must not ask the customer again')

    def test_many_names_are_counted_and_the_key_covers_them_all(self):
        names = [f'rule{i:02d}' for i in range(25)]
        issue = self.lines({'security': {'jq_rule': names}})['emqx.jq-rule']
        self.assertEqual(len(issue.names), haissues.MAX_ITEMS)
        self.assertIn('25 條', issue.message)
        other = self.lines({'security': {'jq_rule': names[:-1] + ['another']}})['emqx.jq-rule']
        self.assertNotEqual(issue.key('emqx'), other.key('emqx'))

    def test_source_lines_say_how_ha_stores_the_passwords_and_the_dashboard(self):
        sink = self.sink()
        readings = {'default_admin': False, 'hashing': None, 'plain': None, 'hash_unreadable': False, 'strict': ('allow', 'ignore')}
        ha_emqx.source_lines(sink, self.target(), readings)
        self.assertEqual(levels(sink.found), {'emqx.access-from-ha': 'auto'})
        self.assertIn('允許', sink.found[0].message)
        sink = self.sink()
        ha_emqx.source_lines(sink, self.target(), dict(readings, strict=('deny', 'disconnect')))
        self.assertIn('拒絕', sink.found[0].message)

    def test_account_lines(self):
        device = {'hashing': {'enable': True, 'name': 'sha256', 'salt': 'suffix', 'mac_fun': None, 'iterations': None,
                              'dk_length': None}, 'count': 2, 'names': ['woow', 'sensor-01']}
        readings = {'hashing': {'enable': True, 'name': 'bcrypt', 'salt': None, 'mac_fun': None, 'iterations': None,
                                'dk_length': None}}
        sink = self.sink()
        ha_emqx.account_lines(sink, readings, device, False)
        self.assertEqual(levels(sink.found), {'emqx.accounts-reset': 'notice'})
        self.assertEqual(sink.found[0].names, ('woow', 'sensor-01'))
        sink = self.sink()
        ha_emqx.account_lines(sink, {'hashing': None}, device, False)
        self.assertEqual(levels(sink.found), {'emqx.accounts-reset': 'notice'}, 'HA has no built-in database: DB_OFF')
        sink = self.sink()
        ha_emqx.account_lines(sink, readings, None, True)
        self.assertEqual(levels(sink.found), {'emqx.accounts-unknown': 'notice'})
        sink = self.sink()
        ha_emqx.account_lines(sink, readings, dict(device, hashing=readings['hashing']), False)
        self.assertEqual(sink.found, [], 'the same hashing changes nothing')

    def test_no_value_is_in_any_line(self):
        secret = 'sup3r-s3cret-value'
        config = {'connectors': {'mqtt': {'ha': {'password': 'file:///opt/emqx/etc/' + secret}}},
                  'rule_engine': {'rules': {'r1': {'sql': 'select jq(\'env\', payload) from "t" -- ' + secret}}},
                  'authentication': [{'mechanism': 'password_based', 'backend': 'http', 'password': secret}],
                  'exhook': {'servers': [{'name': 'x', 'url': 'http://h/' + secret}]}}
        items = ha_emqx.security_items(config)
        self.assertNotIn(secret, json.dumps(items))
        found = self.lines({'security': items})
        self.assertNotIn(secret, json.dumps([i.view('emqx') for i in found.values()]))


class HaReadingTests(base.EmqxCase):
    """S2, D0: what HA's broker says about who may log in and who may do what is read exactly or not at all. An empty list is
    an answer (nobody has to log in: HA's own choice, restored as it is); an answer that is not the list must never be taken
    for it, or this device's own authenticators would go on a misreading. Stops only this app, before anything is imported."""

    def stopped(self, field, text, words):
        setattr(self.world, field, text)
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['ok'], text)
        self.assertIn(words, result['blockers'][0], text)
        self.assertEqual([c for c in self.world.ctl_calls if c[1][:2] == ['data', 'import']], [], 'nothing was imported')

    def test_an_authenticator_list_that_cannot_be_read_stops_the_app(self):
        for garbage in ('{badrpc,nodedown}', '', '[{password_based,built_in_database,true}]',
                        '[{password_based,built_in_database,true,sha256,suffix},{broken}]', 'error: nope',
                        '[{password_based,built_in_database,maybe,sha256,suffix}]'):
            with self.subTest(garbage):
                self.stopped('ha_authn', garbage, '無法讀取 HA 的 EMQX 帳號驗證設定')

    def test_an_authorization_list_that_cannot_be_read_stops_the_app(self):
        for garbage in ('{badrpc,nodedown}', '[{file,true},{broken}]', ''):
            with self.subTest(garbage):
                self.stopped('ha_authz', garbage, '無法讀取 HA 的 EMQX 授權設定')

    def test_the_lists_as_the_shell_prints_them_are_read(self):
        """Whitespace, line breaks and the trailing ok of `emqx eval` are not a reason to stop; an empty list is an answer."""
        for text in ('[{password_based,built_in_database,true,sha256,suffix}]\nok\n',
                     '[{password_based,built_in_database,true,\n   sha256,suffix},\n {jwt,none,true,none,none}]\n', '[]', ' [ ]\nok'):
            with self.subTest(text):
                self.world.ha_authn = text
                result = self.check(self.upload_emqx(), ['emqx'])[0]
                self.assertTrue(result['importable'], text)
                self.assertNotIn('無法讀取 HA 的 EMQX 帳號驗證設定', ' '.join(result['blockers']))


class AccessMustBeWholeTests(base.EmqxCase):
    """D0, S2: this device's authenticators and authorization sources are cut to HA's -- and only when everything HA has is in
    the candidate. An import that did not bring one of them (it said so or not: E-67 skips rules and connectors, not access
    control) must not end with a list that is not HA's, which could leave nobody able to log in or everybody in."""

    def no_load_of_access(self):
        loads = [c for c in self.world.ctl_calls if c[1][:2] == ['conf', 'load']]
        self.assertEqual(loads, [], 'nothing of the candidate was changed after the import')

    def test_an_authenticator_of_ha_that_the_import_did_not_bring_stops_the_app(self):
        self.world.import_changes = {'authentication': []}
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['ok'])
        self.assertIn('沒有出現在暫用的 EMQX 裡', result['blockers'][0])
        self.assertIn('password_based／built_in_database', result['blockers'][0])
        self.no_load_of_access()

    def test_a_source_of_ha_that_the_import_did_not_bring_stops_the_app(self):
        self.world.import_changes = {'authorization': {'no_match': 'allow', 'deny_action': 'ignore', 'sources': [
            {'type': 'file', 'enable': True, 'path': '/opt/emqx/data/authz/acl.conf'}]}}
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['ok'])
        self.assertIn('沒有出現在暫用的 EMQX 裡', result['blockers'][0])
        self.assertIn('built_in_database', result['blockers'][0])
        self.no_load_of_access()

    def test_a_partial_import_that_lost_the_access_settings_is_no_line_to_confirm_but_a_stop(self):
        self.world.import_output = b'imported, but errors in authentication\n'
        self.world.import_changes = {'authentication': []}
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['ok'])
        self.assertNotIn('emqx.import-partial', ids_of(result))
        self.assertIn('沒有出現在暫用的 EMQX 裡', result['blockers'][0])

    def test_a_partial_import_of_something_else_still_goes_on_as_a_line_to_confirm(self):
        self.world.import_output = b'imported, but errors in rule_engine\n'
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(result['importable'])
        self.assertIn('emqx.import-partial', ids_of(result))

    def test_access_roots_names_what_is_absent_and_ha_with_nothing_is_not_absent(self):
        readings = {'authn': [{'mechanism': 'password_based', 'backend': 'built_in_database', 'enable': True},
                              {'mechanism': 'jwt', 'backend': 'none', 'enable': True}],
                    'authz': [{'type': 'file', 'enable': True}, {'type': 'http', 'enable': True}], 'strict': ('allow', 'ignore')}
        after = {'authentication': [{'mechanism': 'password_based', 'backend': 'built_in_database'}],
                 'authorization': {'no_match': 'deny', 'deny_action': 'ignore', 'sources': [{'type': 'file', 'enable': True}]}}
        _changed, facts = ha_emqx.access_roots(after, {}, readings, [])
        self.assertEqual(facts['absent'], ['jwt／none', 'http'])
        empty = {'authn': [], 'authz': [], 'strict': ('deny', 'ignore')}   # HA asks nobody and has no source: nothing is absent
        _changed, facts = ha_emqx.access_roots(after, {}, empty, [])
        self.assertEqual(facts['absent'], [])


def ids_of(result):
    return [issue['id'] for issue in result['issues']]


class NeverGuessedTests(base.EmqxCase):
    """What the coverage run of the lane showed no test ran: the places that stop only this app (with a sentence that says what
    to do) when a reading of either broker is not what it must be, and the conversion's own choice of HA's database."""

    def answers(self, role, expression, text, after_import=False):
        real = self.world.evaluate

        def evaluate(role_, expression_):
            if role_ == role and expression_ == expression and (self.world.imported_into or not after_import):
                return text.encode()
            return real(role_, expression_)
        self.world.evaluate = evaluate

    def test_the_rule_the_candidate_answers_after_applying_must_be_ha_s(self):
        """E-80, second reading: the raw configuration says HA's rule but the broker's own answer is another."""
        self.answers('emqx-new', ha_emqx.STRICT_EXPR, '{deny,ignore}', after_import=True)
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['ok'])
        self.assertIn('無法確認匯入後的 EMQX 存取政策', result['blockers'][0])

    def test_this_devices_rule_that_cannot_be_read_stops_the_app(self):
        self.answers('emqx-new', ha_emqx.STRICT_EXPR, '{badrpc,nodedown}')
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['ok'])
        self.assertIn('無法讀取這台 EMQX 的設定', result['blockers'][0])

    def test_ha_s_row_counts_that_cannot_be_read_stop_the_app_with_the_advice(self):
        self.answers('emqx-ha', ha_emqx.COUNT_EXPR, '[]')
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['ok'])
        self.assertIn('無法讀取 HA 的 EMQX 資料筆數', result['blockers'][0])
        self.assertIn('停止 EMQX 附加元件', result['blockers'][0])

    def test_a_broker_that_cannot_be_started_with_ha_s_node_name_is_said_with_the_name(self):
        real = self.world.run

        def run(role, image, command, options, data):
            if role == 'emqx-ha':
                raise BackupError('job-failed', 'podman said no')
            return real(role, image, command, options, data)
        self.world.run = run
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['ok'])
        self.assertIn('無法以 HA 的 EMQX 節點名稱', result['blockers'][0])
        self.assertIn(base.NODE, result['blockers'][0])

    def test_the_file_the_settings_are_written_to_that_cannot_be_written_stops_the_app(self):
        real = self.world.exec

        def exec_(role, command, data, stdout):
            if role == 'emqx-new' and command[:2] == ['sh', '-c'] and 'target-settings.hocon' in command[2]:
                return Result(1, b'', b'read-only')
            return real(role, command, data, stdout)
        self.world.exec = exec_
        # a setting of this device's own that the import changed has to be loaded back: that is what writes the file
        self.world.target_config['mqtt'] = {'max_packet_size': '1MB'}
        self.world.current_config = copy.deepcopy(self.world.target_config)
        self.world.import_changes = {'mqtt': {'max_packet_size': '9MB'}}
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['ok'])
        self.assertIn('無法恢復 EMQX 目標設定', result['blockers'][0])

    def test_the_conversion_uses_the_database_the_customer_chose_and_else_the_last_written_one(self):
        other = 'emqx@127.0.0.1'

        def node_of_ha_broker():
            options = self.runs('emqx-ha')[-1][3]
            return [value for value in options['--env'] if value.startswith('EMQX_NODE__NAME=')][0].split('=', 1)[1]
        ha_id = self.upload_emqx(node_file=None, nodes=(base.NODE, other), state='stopped')
        self.convert(ha_id, ['emqx'], choices={'emqx': {'node': other}})
        self.assertEqual(node_of_ha_broker(), other, "the customer's choice")
        self.world.again()
        self.convert(self.upload_emqx(node_file=None, nodes=(base.NODE, other), state='stopped'), ['emqx'])
        self.assertIn(node_of_ha_broker(), (base.NODE, other))   # the last written one: said in the job, never asked again

    def test_a_ticker_that_cannot_be_asked_again_is_a_notice_never_a_stop(self):
        """E-13: the broker's answer about its paused system process fails midway: the retained messages may differ by a few rows
        (said), the app goes on; a full disk or a busy host still stops the job."""
        class Tmp:
            def __init__(self, error):
                self.error = error

            def exec(self, role, command, **kwargs):
                raise self.error
        self.assertFalse(ha_emqx.assert_system_ticker(Tmp(BackupError('job-failed', 'x')), 'emqx-new', '<0.1.0>'))
        for code in ('insufficient-space', 'busy'):
            with self.assertRaises(BackupError):
                ha_emqx.assert_system_ticker(Tmp(BackupError(code, 'x')), 'emqx-new', '<0.1.0>')
        self.assertFalse(ha_emqx.assert_system_ticker(Tmp(BackupError('job-failed', 'x')), 'emqx-ha', None), 'nothing was paused')

    def test_a_probe_that_fails_while_the_restored_broker_starts_is_not_ready_yet_and_not_an_end(self):
        """E-88: a status call that raises is waited past (the deadline and the container's life decide)."""
        calls = []

        def execute(command):
            calls.append(command)
            if len(calls) < 3:
                raise BackupError('job-failed', 'timed out')
            return Result(0, b"Node 'emqx@127.0.0.1' 5.8.9 is started\n", b'')
        ticks = iter(range(0, 1000, 2))
        ha_emqx.wait_live_ready(execute, sleep=lambda _s: None, clock=lambda: next(ticks), running=lambda: True)
        self.assertEqual(len(calls), 3)


class ImportTextsTests(unittest.TestCase):
    """D0 (4), DESIGN H-c: HA's add-on options (env_vars) are never read, so the customer is told once, after the import, that
    they did not move -- whatever else the conversion found, and without a value of any kind."""

    def test_the_add_on_options_that_did_not_move_are_one_reminder_in_every_result(self):
        for data in ({}, {'anonymous': True}, {'hash_change': {'ha': 'bcrypt', 'mine': 'sha256', 'names': 'woow'}},
                     {'ha_hosts': ['homeassistant'], 'plugins': ['p1'], 'api_keys': 2}):
            _notes, reminders = ha_emqx.import_texts(data)
            self.assertEqual(reminders.count(ha_emqx.OPTIONS_NOT_MOVED), 1, data)
        self.assertIn('env_vars', ha_emqx.OPTIONS_NOT_MOVED)
        self.assertIn('沒有搬過來', ha_emqx.OPTIONS_NOT_MOVED)
        self.assertIn('請在匯入後', ha_emqx.OPTIONS_NOT_MOVED)   # what to do, not only what happened


class MarkerTests(base.EmqxCase):
    """H-2: the data volume says its access settings are HA's, so the package's smoke test can tell (and upgrade.sh does not
    roll every upgrade back)."""

    def test_the_candidate_gets_one_fixed_marker_with_no_value(self):
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertTrue(done['backup_id'])
        writes = [command for role, command, _data in self.world.execs
                  if role == 'emqx-new' and command[:2] == ['sh', '-c'] and ha_emqx.MARKER in command[2]]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][2], "umask 077; printf '%s' '{\"kind\":\"woow-ha-import\",\"version\":1,\"app\":\"emqx\"}' > "
                                       "/opt/emqx/data/woow-ha-import.json")
        self.assertEqual(json.loads(ha_emqx.MARKER_BODY), {'kind': 'woow-ha-import', 'version': 1, 'app': 'emqx'})

    def test_a_marker_that_cannot_be_written_stops_only_this_app_before_anything_is_packaged(self):
        real = self.world.exec

        def exec_(role, command, data, stdout):
            if role == 'emqx-new' and command[:2] == ['sh', '-c'] and ha_emqx.MARKER in command[2]:
                return Result(1, b'', b'read-only')
            return real(role, command, data, stdout)
        self.world.exec = exec_
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertIn('匯入標記', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])


class ConversionLogTests(base.EmqxCase):
    """The job log names the no-match rule of HA, not the one this device had before the import (the real run on dev-d,
    2026-11-25, printed this device's own: 「deny」 for an HA broker that allows)."""

    def done_line(self):
        lines = [line for line in self.reporter.logs if '資料匯入完成' in line]
        self.assertEqual(len(lines), 1, lines)
        return lines[0]

    def test_ha_allows_this_device_denied(self):
        self.assertEqual(self.world.ha_strict, '{allow,ignore}')
        self.assertEqual(self.world.target_config['authorization']['no_match'], 'deny')
        self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        line = self.done_line()
        self.assertIn('HA 的「允許」', line)
        self.assertNotIn('拒絕', line)
        self.assertNotIn('deny', line)

    def test_ha_denies_this_device_allowed(self):
        self.world.ha_strict = '{deny,ignore}'
        self.world.target_config['authorization']['no_match'] = 'allow'
        self.world.current_config = copy.deepcopy(self.world.target_config)
        self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        line = self.done_line()
        self.assertIn('HA 的「拒絕」', line)
        self.assertNotIn('允許', line)


class TunnelReadingTests(unittest.TestCase):
    def target(self, files):
        quadlets = dict(base.QUADLETS)
        quadlets.update(files)
        runner = SimpleNamespace(home='/home/appowner', read_file=lambda rel, max_bytes=None: b'')
        work = SimpleNamespace(quadlets=lambda _app: quadlets, runner=lambda _app: runner)
        return ha_emqx.Target(work, fk.app('emqx', 'EMQX', volumes=[{'name': 'woow_emqx_data'}, {'name': 'woow_emqx_log'}]))

    def test_a_tunnel_is_told_by_the_file_its_container_or_its_image_not_by_a_comment(self):
        self.assertEqual(self.target({}).tunnels, [])
        comment = b'[Container]\n# the PROXY protocol listener of the ngrok tunnel is in the broker\nContainerName=woow-emqx-entrance\nImage=docker.io/nginx:1\n'
        self.assertEqual(self.target({'emqx-entrance.container': comment}).tunnels, [])
        self.assertEqual(self.target({'emqx-ngrok.container': b'[Container]\nContainerName=x\nImage=docker.io/y:1\n'}).tunnels, ['emqx-ngrok'])
        self.assertEqual(self.target({'emqx-out.container': b'[Container]\nContainerName=woow-cloudflared\nImage=docker.io/y:1\n'}).tunnels, ['emqx-out'])
        self.assertEqual(self.target({'emqx-out.container': b'[Container]\nContainerName=out\nImage=docker.io/ngrok/ngrok:3\n'}).tunnels, ['emqx-out'])
        found = self.target({'emqx-entrance.container': b'[Container]\nContainerName=e\nImage=i:1\nPublishPort=0.0.0.0:8080:80\n'})
        self.assertEqual(found.other_publish, [('0.0.0.0', '8080', '80')])


class DeviceAccessWorld(base.World):
    """This device keeps its settings in an EnvironmentFile that also holds access settings (H1)."""

    def __init__(self):
        super().__init__()
        self.files['.config/emqx/emqx.env'] = (b'EMQX_LOG__CONSOLE__LEVEL=warning\n'
                                               b'EMQX_AUTHORIZATION__NO_MATCH=deny\n')


class AccessEnvTests(base.EmqxCase):
    world_class = DeviceAccessWorld

    def test_the_variables_that_win_are_named_in_the_check_and_the_conversion_goes_on(self):
        """H1: this device's own environment wins with a notice, never a stop; the name only, never the value."""
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertTrue(result['importable'], result['blockers'])
        notice = next(i for i in result['issues'] if i['id'] == 'emqx.env-wins')
        self.assertEqual(notice['items'], ['EMQX_AUTHORIZATION__NO_MATCH'])
        self.assertNotIn('deny', json.dumps(notice))
        self.assertTrue(self.convert(self.upload_emqx(state='stopped'), ['emqx'])['backup_id'])


if __name__ == '__main__':
    unittest.main()
