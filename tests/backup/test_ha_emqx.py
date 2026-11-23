"""HA import, EMQX part (ha_emqx.py): HA's broker files staged without the cookie, generated configs, plugins or
patches; HA's broker in a throwaway of the live image (network none, read-only root, root, HA's node name mapped to
127.0.0.1) exports the data; this device's broker imports it, gets its strict settings back and is checked; versions,
the default Dashboard account and the volumes (CONTRACT section 9). Team E2."""
import gzip
import base64
import copy
import io
import json
import tarfile
import unittest
from pathlib import Path

from woowbackup import ha_emqx, haimport, ha_n8n, hacommon
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import hab1fakes as fk
from . import hafixtures as hx

SLUG = '1b7b4ce7_woow-emqx'
NODE = 'emqx@homeassistant.local'
EXPORT = '/work/out/emqx-export-2026-11-19-10-11-12.345.tar.gz'
HOCON = (b'connectors {http {ha {url = "http://homeassistant:8123/api/webhook/x"}}}\n'
         b'listeners.ssl.default {ssl_options {certfile = "/ssl/fullchain.pem"}}\n')
QUADLETS = {
    'emqx.container': b'[Container]\nContainerName=woow-emqx\nImage=docker.io/emqx/emqx:5.8.9\n'
                      b'Environment=EMQX_NODE__NAME=emqx@127.0.0.1\n'
                      b'Environment=EMQX_DASHBOARD__DEFAULT_USERNAME=admin\n'
                      b'Environment=EMQX_LISTENERS__TCP__NGROK__BIND=127.0.0.1:1884\n'
                      b'EnvironmentFile=%h/.config/emqx/emqx.env\n'
                      b'Secret=woow-emqx-dashboard-password,type=env,target=EMQX_DASHBOARD__DEFAULT_PASSWORD\n'
                      b'Secret=woow-emqx-node-cookie,type=env,target=EMQX_NODE__COOKIE\n'
                      b'Secret=woow-emqx-mqtt-bootstrap,type=mount,target=/opt/emqx/etc/woow-mqtt-bootstrap.csv,'
                      b'uid=1000,gid=1000,mode=0400\n'
                      b'Volume=%h/.config/emqx/base.hocon:/opt/emqx/etc/base.hocon:ro,Z\n'
                      b'Volume=%h/.config/emqx/acl.conf:/opt/emqx/etc/acl.conf:ro,Z\n'
                      b'Volume=emqx-data.volume:/opt/emqx/data\nVolume=emqx-log.volume:/opt/emqx/log\n',
    'emqx-entrance.container': b'[Container]\nContainerName=woow-emqx-entrance\n'
                               b'Image=docker.io/nginxinc/nginx-unprivileged:1.27-alpine\n'
                               b'Volume=%h/.config/emqx/entrance.conf:/etc/nginx/nginx.conf:ro,Z\n',
    'emqx-data.volume': b'[Volume]\nVolumeName=woow_emqx_data\n',
    'emqx-log.volume': b'[Volume]\nVolumeName=woow_emqx_log\n',
    'emqx.network': b'[Network]\nNetworkName=woow_emqx_network\n',
}
HA_COUNTS = {'emqx_authn_mnesia': 3, 'emqx_authn_scram_mnesia': 0, 'emqx_acl': 2, 'emqx_banned': 1,
             'emqx_banned_rules': 0, 'emqx_admin': 2, 'emqx_app': 1, 'emqx_psk': 0, 'emqx_retainer_message': -1}
SEED = {'emqx_authn_mnesia': 1, 'emqx_authn_scram_mnesia': 0, 'emqx_acl': 0, 'emqx_banned': 0, 'emqx_banned_rules': 0,
        'emqx_admin': 1, 'emqx_app': 0, 'emqx_psk': 0, 'emqx_retainer_message': 0}


def addon_tar(*, version='5.9.1', node_file=NODE, nodes=(NODE,), state='started'):
    addon = {'user': {'version': version, 'image': '1b7b4ce7/amd64-addon-woow-emqx',
                      'options': {'ngrok_authtoken': 'ha-ngrok-secret'}},
             'system': {'slug': 'woow-emqx', 'name': 'Woow EMQX'}, 'version': version, 'state': state}
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': json.dumps(addon).encode()},
               {'name': './image.tar', 'data': b'docker save' * 50},
               {'name': 'data', 'type': 'dir'}, {'name': 'data/options.json', 'data': b'{}'},
               {'name': 'data/emqx', 'type': 'dir'}, {'name': 'data/emqx/node.cookie', 'data': b'ha-cookie-secret'},
               {'name': 'data/emqx/data', 'type': 'dir'}, {'name': 'data/emqx/data/mnesia', 'type': 'dir'}]
    if node_file is not None:
        entries.append({'name': 'data/emqx/node.name', 'data': node_file.encode()})
    for node in nodes:
        entries += [{'name': f'data/emqx/data/mnesia/{node}', 'type': 'dir'},
                    {'name': f'data/emqx/data/mnesia/{node}/schema.DAT', 'data': b'schema'},
                    {'name': f'data/emqx/data/mnesia/{node}/emqx_admin.DCD', 'data': b'admins'}]
    entries += [{'name': 'data/emqx/data/configs', 'type': 'dir'},
                {'name': 'data/emqx/data/configs/cluster.hocon', 'data': HOCON},
                {'name': 'data/emqx/data/configs/app.2026.11.19.config', 'data': b'generated'},
                {'name': 'data/emqx/data/configs/vm.2026.11.19.args', 'data': b'-setcookie ha-cookie-secret'},
                {'name': 'data/emqx/data/certs', 'type': 'dir'},
                {'name': 'data/emqx/data/certs/key.pem', 'data': b'-----BEGIN PRIVATE KEY-----'},
                {'name': 'data/emqx/data/patches', 'type': 'dir'},
                {'name': 'data/emqx/data/patches/evil.beam', 'data': b'code'},
                {'name': 'data/emqx/plugins', 'type': 'dir'}, {'name': 'data/emqx/plugins/my_plugin-1.0.0', 'type': 'dir'},
                {'name': 'data/emqx/plugins/my_plugin-1.0.0/x.beam', 'data': b'code'},
                {'name': 'config', 'type': 'dir'}, {'name': 'config/log', 'type': 'dir'},
                {'name': 'config/log/emqx.log.1', 'data': b'log'}]
    return gzip.compress(hx.tar_bytes(entries), mtime=0)


def counts_text(counts):
    return ('[' + ',\n '.join(f'{{{t},{n}}}' for t, n in counts.items()) + ']\n').encode()


def receipt_text(tables):
    """The answer of ha_emqx.TABLES_RECEIPT_EXPR: {table: (rows, sha256 hex upper | None)}."""
    return ('WOOWTAB:' + ''.join(f'{t}:{n}:{h or "-"};' for t, (n, h) in tables.items()) + ':ENDok\n').encode()


RECEIPT = {t: (n, (t.encode().hex().upper() * 8)[:64]) for t, n in
           (('emqx_authn_mnesia', 4), ('emqx_authn_scram_mnesia', 0), ('emqx_acl', 2), ('emqx_admin', 2),
            ('emqx_app', 1), ('emqx_psk', 0), ('emqx_banned_rules', 0))}


class World(fk.World):
    def __init__(self):
        super().__init__()
        self.quadlets = {'emqx': QUADLETS}
        self.version = '5.8.9'
        self.default_admin = False
        self.ha_authn = '[{password_based,built_in_database,true,sha256,suffix}]'
        self.live_authn = '[{password_based,built_in_database,true,sha256,suffix}]'
        self.ha_strict = '{allow,ignore}'
        self.imported_into = False
        self.restored = False
        self.import_lost = None
        self.ctl_calls = []
        self.snippet = None
        # The Quadlet's EnvironmentFile= (QUADLETS) as the product package ships it: one EMQX setting, other programs'.
        self.files['.config/emqx/emqx.env'] = b'# woow emqx\nEMQX_LOG__CONSOLE__LEVEL=warning\nWOOW_EMQX_BIND=0.0.0.0\n'
        self.target_config = {'authorization': {'no_match': 'deny', 'deny_action': 'ignore',
            'sources': [{'type': 'file', 'enable': True, 'path': '/opt/emqx/etc/acl.conf'}]}}
        self.current_config = copy.deepcopy(self.target_config)

    def labels(self, image):
        return {'org.opencontainers.image.version': self.version}

    def boot_view(self, role, config):
        """The boot form (ha_emqx.BOOT_CONFIG_EXPR) of `config` as `role` answers it: no schema defaults here."""
        return config

    def user_ids(self, user):
        return b'1000\n1000\n'

    def exec(self, role, command, data, stdout):
        if command[:2] == ['emqx', 'ctl']:
            self.ctl_calls.append((role, command[2:]))
            if command[2] == 'status':
                return Result(0, f"Node '{NODE if role == 'emqx-ha' else 'emqx@127.0.0.1'}' 5.8.9 is started\n".encode(),
                              b'')
            if command[2:4] == ['data', 'export']:
                return Result(0, f'Exporting data to "{EXPORT}"...\nData has been successfully exported to {EXPORT}.\n'
                              .encode(), b'')
            if command[2:4] == ['data', 'import']:
                self.imported_into = True
                self.current_config['authorization'] = {'no_match': 'allow', 'deny_action': 'ignore', 'sources': []}
                return Result(0, b'Importing data...\nData has been imported successfully.\n', b'')
            if command[2:4] == ['conf', 'load']:
                self.restored = True
                if self.snippet and self.snippet.startswith(b'{'):
                    self.current_config.update(json.loads(self.snippet))
            return Result(0, b'', b'')
        if command[:2] == ['emqx', 'eval']:
            return Result(0, self.evaluate(role, command[2]), b'')
        if command[:2] == ['sh', '-c']:
            self.snippet = data
        return Result(0, b'', b'')

    def evaluate(self, role, expression):
        if expression == ha_emqx.ETC_EXPR:
            return b'WOOWETC:/opt/emqx/etc:ENDok\n'
        if expression == ha_emqx.TABLES_RECEIPT_EXPR:
            return receipt_text(RECEIPT)
        if expression == ha_emqx.CONFIG_EXPR:
            return b'WOOWCFG:' + base64.b64encode(json.dumps(self.current_config).encode()) + b':ENDok\n'
        if expression == ha_emqx.BOOT_CONFIG_EXPR:
            return b'WOOWCFG:' + base64.b64encode(json.dumps(self.boot_view(role, self.current_config)).encode()) + b':ENDok\n'
        if expression == ha_emqx.OVERRIDE_STATE_EXPR:
            return b'WOOWOVERRIDE:present:ENDok\n'
        if expression == ha_emqx.SUSPEND_SYS_EXPR:
            return b'WOOWSYS:<0.1.0>:suspended\nok\n'
        if expression == ha_emqx.TICKER_STATUS_EXPR.replace('{pid}', '<0.1.0>'):
            return b'ticker_unchanged\n'
        if expression == ha_emqx.DEFAULT_ADMIN_EXPR:
            return b'default\n' if self.default_admin else b'changed\n'
        if expression == ha_emqx.ROOTS_EXPR:
            return b'[<<"alarm">>,<<"authentication">>,<<"authorization">>,<<"rule_engine">>,\n <<"connectors">>]\n'
        if expression == ha_emqx.AUTHN_EXPR:
            if role == 'emqx-ha':
                return self.ha_authn.encode()
            return (self.ha_authn if self.imported_into and self.ha_authn != '[]' else self.live_authn).encode()
        if expression == ha_emqx.STRICT_EXPR:
            if role == 'emqx-ha' or (self.imported_into and not self.restored):
                return self.ha_strict.encode()
            return b'{deny,ignore}\n'
        if expression == ha_emqx.COUNT_EXPR:
            if role == 'emqx-ha':
                return counts_text(HA_COUNTS)
            if not self.imported_into:
                return counts_text(SEED)
            merged = {t: max(HA_COUNTS[t], 0) + (SEED[t] if t != 'emqx_admin' else 0) for t in SEED}
            if self.import_lost:
                merged[self.import_lost] = 0
            return counts_text(merged)
        return b'ok\n'

    def export(self, volume):
        if volume.endswith('emqx-xfer'):
            return fk.tar_of([{'name': '.', 'type': 'dir'}, {'name': 'out', 'type': 'dir'},
                              {'name': EXPORT[len('/work/'):], 'data': b'export-tarball'}])
        return fk.tar_of([{'name': '.', 'type': 'dir', 'uid': 1000, 'gid': 1000},
                          {'name': 'mnesia', 'type': 'dir', 'uid': 1000},
                          {'name': 'mnesia/emqx@127.0.0.1', 'type': 'dir', 'uid': 1000},
                          {'name': 'mnesia/emqx@127.0.0.1/emqx_admin.DCD', 'data': b'merged', 'uid': 1000},
                          {'name': 'configs', 'type': 'dir', 'uid': 1000},
                          {'name': 'configs/cluster.hocon', 'data': b'merged conf', 'uid': 1000},
                          {'name': 'configs/cluster.hocon.2026.bak', 'data': b'old', 'uid': 1000},
                          {'name': 'configs/app.2026.config', 'data': b'gen', 'uid': 1000},
                          {'name': 'configs/vm.2026.args', 'data': b'-setcookie live-cookie', 'uid': 1000},
                          {'name': 'backup', 'type': 'dir', 'uid': 1000},
                          {'name': 'backup/x.tar.gz', 'data': b'x', 'uid': 1000},
                          {'name': 'trace', 'type': 'dir', 'uid': 1000}])


class EmqxCase(fk.ConversionCase):
    world_class = World

    def setUp(self):
        super().setUp()
        patcher = __import__('unittest').mock.patch.object(ha_emqx.time, 'sleep', lambda _s: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def catalog_apps(self):
        return {'emqx': fk.app('emqx', 'EMQX MQTT 代理', volumes=[{'name': 'woow_emqx_data'}, {'name': 'woow_emqx_log'}])}

    def upload_emqx(self, **kwargs):
        return self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar(**kwargs))], hx.ha_doc(addons=(SLUG,))))

    def staged(self):
        with tarfile.open(fileobj=io.BytesIO(self.world.imported['emqx-src'])) as tar:
            return {m.name: m for m in tar.getmembers()}

    def internal_candidate(self, ha_id):
        """Actual internal build/package with generated transport, never public convert.

        Public preservation tests remain separate. No target-policy helper or
        preservation gate is patched out here; the fixture answers its native
        config/volume protocol just as it answers counts and import outcomes.
        """
        ctx = self.ctx()
        ctx.storage.ensure_layout()
        staging = Path(ctx.storage.staging_dir(ctx.job_id))
        staging.mkdir(parents=True, exist_ok=True)
        work = haimport.Work(ctx, None, None, staging)
        try:
            work.record = haimport._open(work, ctx, {'ha_backup_id': ha_id})
            app = self.catalog['emqx']
            target, version = ha_emqx._prepare(work, app)
            tmp = work.temp(app)
            private = staging / 'internal-emqx-work'
            private.mkdir(mode=0o700)
            built = ha_emqx._build_candidate(work, app, tmp, target, private, version=version)
            paths = ha_emqx._package_candidate(work, tmp, target, private, staging / 'internal-emqx-output',
                built[3], ids=work.adapter(app).owner_ids(),
                log_root=ha_n8n.volume_root(work, app, target.log_volume))
            data = {'ha_hosts': hacommon.ha_hosts(built[0].hocon), 'plugins': sorted(built[0].plugins),
                    'api_keys': max(built[2]['counts'].get('emqx_app', 0), 0)}
            notes, _, reminders = haimport.import_texts({'emqx': data}, self.catalog)
            return {'volumes': paths, 'notes': notes, 'reminders': reminders['emqx']}
        finally:
            self.assertEqual(work.close(), [])


BUILTIN_TARGET = [{'type': 'file', 'enable': True, 'path': '/opt/emqx/etc/acl.conf'},
                  {'type': 'built_in_database', 'enable': True}]


class CheckTests(EmqxCase):
    def setUp(self):
        super().setUp()
        # HA's backup has ACL rows (HA_COUNTS): the import target is one that asks its built-in database too (OWNER
        # DECISION 2026-11-23 「C」; a file-only target refuses them: test_ha_emqx_product.AclNeedsBuiltinTests).
        self.world.target_config['authorization']['sources'] = copy.deepcopy(BUILTIN_TARGET)
        self.world.current_config = copy.deepcopy(self.world.target_config)

    def test_a_clean_backup(self):
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertEqual((result['ok'], result['blockers'], result['target_version']),
                         (True, [], '5.8.9'))
        self.assertEqual(result['emqx']['target_authorization'], ['file', 'built_in_database'])
        section = result['emqx']
        self.assertEqual((section['node_name'], section['mqtt_users'], section['acl_rules'], section['api_keys'],
                          section['retained_messages'], section['default_dashboard_password']),
                         (NODE, 3, 2, 1, 0, False))
        self.assertEqual(section['plugins'], ['my_plugin-1.0.0'])
        joined = '\n'.join(result['warnings'])
        for words in ('homeassistant', '/ssl/fullchain.pem', 'my_plugin', 'API 金鑰會取代', '未符合規則的主題'):
            self.assertIn(words, joined)
        run = self.runs('emqx-ha')[0]
        options = run[3]
        self.assertEqual((run[1], options['--user'], options['--network']), ('docker.io/emqx/emqx:5.8.9', ['0'], ['none']))
        self.assertIn('--read-only', options)
        self.assertEqual(options['--add-host'], ['homeassistant.local:127.0.0.1'])
        self.assertIn('EMQX_DASHBOARD__DEFAULT_PASSWORD=', options['--env'])
        self.assertFalse([e for e in options['--env'] if e.startswith('EMQX_NODE__COOKIE')])
        self.assertTrue(any(v.endswith(':/data/emqx/data:rw,noexec,nosuid,nodev') for v in options['--volume']))
        staged = self.staged()
        self.assertIn(f'mnesia/{NODE}/schema.DAT', staged)
        self.assertIn('configs/cluster.hocon', staged)
        self.assertEqual(staged['certs/key.pem'].mode, 0o600)
        for never in ('configs/app.2026.11.19.config', 'configs/vm.2026.11.19.args', 'patches/evil.beam'):
            self.assertNotIn(never, staged)
        self.assertFalse([n for n in staged if 'cookie' in n or 'plugins' in n or 'log' in n])
        self.assertFalse(self.runs('emqx-new'), 'a check changes nothing')
        self.assertFalse([c for c in self.world.ctl_calls if c[1][:2] == ['data', 'export']])

    def test_blockers(self):
        self.world.default_admin = True
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(any('admin／public' in b for b in result['blockers']))
        self.world.default_admin = False
        for kwargs, words in (({'version': '5.9.2'}, '還不認得'),
                              ({'node_file': None, 'nodes': (NODE, 'emqx@127.0.0.1')}, '2 個內建資料庫'),
                              ({'nodes': ()}, '沒有 EMQX 的內建資料庫')):
            with self.subTest(words=words):
                result = self.check(self.upload_emqx(**kwargs), ['emqx'])[0]
                self.assertFalse(result['ok'])
                self.assertTrue(any(words in b for b in result['blockers']), result['blockers'])
        self.world.version = '5.9.0'
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(any('HA 的 EMQX 是 5.8.9' in blocker for blocker in result['blockers']))
        self.assertEqual(len(result['blockers']), 1, 'the version is the only blocker (no blanket guard any more)')

    def test_a_hot_backup_is_tried_and_named(self):
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(result['ok'], 'a hot backup whose database loaded completely is importable, with the warning')
        self.assertTrue(result['emqx']['hot_backup'])
        self.assertTrue(any('執行中製作' in w for w in result['warnings']))
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertFalse(result['emqx']['hot_backup'])
        self.assertFalse(any('執行中製作' in w for w in result['warnings']))

    def test_a_half_loaded_database_is_refused_with_the_advice(self):
        real = self.world.evaluate

        def evaluate(role, expression):
            if role == 'emqx-ha' and expression == ha_emqx.COUNT_EXPR:
                return counts_text(dict(HA_COUNTS, emqx_acl=-1))
            return real(role, expression)

        self.world.evaluate = evaluate
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['ok'])
        self.assertIn('沒有完整載入（缺少 emqx_acl）', result['blockers'][0])
        self.assertIn('停止 EMQX 附加元件', result['blockers'][0])

    def test_a_broker_that_does_not_start_is_refused_with_the_advice(self):
        real = self.world.exec

        def exec_(role, command, data, stdout):
            if role == 'emqx-ha' and command[:3] == ['emqx', 'ctl', 'status']:
                return Result(1, b'Node is not running!\n', b'')
            return real(role, command, data, stdout)

        self.world.exec = exec_
        real_podman = self.world.podman

        def podman(args, data, stdout):
            if args[:2] == ['container', 'inspect'] and args[-1].endswith('emqx-ha') and 'Running' in args[3]:
                return Result(0, b'false\n', b'')
            return real_podman(args, data, stdout)

        self.world.podman = podman
        result = self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]
        self.assertIn('暫用的 EMQX 無法開啟這份資料', result['blockers'][0])
        self.assertNotIn('執行中製作', result['blockers'][0], 'a cold backup gets no hot-backup advice')
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertIn('停止 EMQX 附加元件', result['blockers'][0])

    def test_an_ip_node_name_needs_no_host_line(self):
        result = self.check(self.upload_emqx(node_file='emqx@127.0.0.1', nodes=('emqx@127.0.0.1',)), ['emqx'])[0]
        self.assertTrue(result['ok'])
        self.assertNotIn('--add-host', self.runs('emqx-ha')[0][3])


class ConvertTests(EmqxCase):
    def test_the_whole_conversion(self):
        result = self.internal_candidate(self.upload_emqx())
        export = [c for c in self.world.ctl_calls if c[1][:2] == ['data', 'export']][0][1]
        self.assertEqual(export[export.index('--root-keys') + 1], 'authentication,authorization,rule_engine,connectors')
        self.assertEqual(export[export.index('--table-sets') + 1].split(','), list(ha_emqx.TABLE_SETS))
        new = self.runs('emqx-new')[0]
        options = new[3]
        self.assertNotIn('--user', options, "this device's broker runs as the image's user")
        self.assertIn('EMQX_NODE__NAME=emqx@127.0.0.1', options['--env'])
        self.assertIn('woow-emqx-node-cookie,type=env,target=EMQX_NODE__COOKIE', options['--secret'])
        self.assertIn('/home/appowner/.config/emqx/base.hocon:/opt/emqx/etc/base.hocon:ro', options['--volume'])
        self.assertFalse([v for v in options['--volume'] if 'woow_emqx_data' in v])
        incoming = tarfile.open(fileobj=io.BytesIO(self.world.imported['emqx-in']))
        self.assertEqual(incoming.extractfile('in/' + EXPORT.rsplit('/', 1)[1]).read(), b'export-tarball')
        self.assertEqual({(m.uid, m.gid) for m in incoming.getmembers()}, {(1000, 1000)})
        self.assertIn(['data', 'import', '/work/in/' + EXPORT.rsplit('/', 1)[1]], [c[1] for c in self.world.ctl_calls])
        self.assertEqual(json.loads(self.world.snippet)['authorization'], self.world.target_config['authorization'])
        self.assertIn(['conf', 'load', '--replace', '/work/in/target-settings.hocon'], [c[1] for c in self.world.ctl_calls])
        with tarfile.open(result['volumes']['woow_emqx_data']) as archive:
            data = {member.name: member for member in archive}
        self.assertIn('mnesia/emqx@127.0.0.1/emqx_admin.DCD', data)
        self.assertIn('configs/cluster.hocon', data)
        for gone in ('configs/vm.2026.args', 'configs/app.2026.config', 'configs/cluster.hocon.2026.bak',
                     'backup/x.tar.gz'):
            self.assertNotIn(gone, data)
        self.assertIn('backup', data)
        with tarfile.open(result['volumes']['woow_emqx_log']) as archive:
            self.assertEqual(archive.getnames(), ['.'])
        reminders = result['reminders']
        self.assertTrue(any('Woow EMQX MCP Server' in line for line in reminders))
        self.assertTrue(any('homeassistant' in line for line in reminders))

    def test_a_failed_export_stops_the_conversion_with_the_advice(self):
        real = self.world.exec

        def exec_(role, command, data, stdout):
            if command[:4] == ['emqx', 'ctl', 'data', 'export']:
                return Result(0, b'[error] Data export failed, reason: badmatch.\n', b'')
            return real(role, command, data, stdout)

        self.world.exec = exec_
        with self.assertRaises(BackupError) as caught:
            self.internal_candidate(self.upload_emqx())
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('EMQX 無法匯出 HA 的資料', caught.exception.message)
        self.assertIn('停止 EMQX 附加元件', caught.exception.message)
        self.assertFalse(self.runs('emqx-new'), 'nothing is imported from a failed export')
        self.assertEqual(self.storage.list_backups(), [])

    def test_a_partial_import_stops_the_conversion(self):
        real = self.world.exec

        def exec_(role, command, data, stdout):
            if command[:4] == ['emqx', 'ctl', 'data', 'import']:
                return Result(0, b'Data has been imported, but some errors occurred, see the log above.\n', b'')
            return real(role, command, data, stdout)

        self.world.exec = exec_
        with self.assertRaises(BackupError) as caught:
            self.internal_candidate(self.upload_emqx())
        self.assertIn('部分資料無法匯入', caught.exception.message)

    def test_lost_rows_stop_the_conversion(self):
        self.world.import_lost = 'emqx_acl'
        with self.assertRaises(BackupError) as caught:
            self.internal_candidate(self.upload_emqx())
        self.assertIn('emqx_acl', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])

    def test_an_import_that_would_open_anonymous_login_is_refused(self):
        self.world.ha_authn = '[{password_based,built_in_database,false,sha256,suffix}]'
        with self.assertRaises(BackupError) as caught:
            self.internal_candidate(self.upload_emqx())
        self.assertIn('匿名登入', caught.exception.message)

    def test_the_strict_settings_must_come_back(self):
        real = self.world.exec

        def exec_(role, command, data, stdout):
            if command[:4] == ['emqx', 'ctl', 'conf', 'load']:
                return Result(0, b'', b'')  # the load silently did nothing
            return real(role, command, data, stdout)

        self.world.exec = exec_
        with self.assertRaises(BackupError) as caught:
            self.internal_candidate(self.upload_emqx())
        self.assertIn('未能保留目標有效設定', caught.exception.message)


class ParseTests(unittest.TestCase):
    def test_eval_answers(self):
        text = '[{emqx_authn_mnesia,3},\n {emqx_acl, -1},\n {other,9}]'
        self.assertEqual(ha_emqx.parse_counts(text), {'emqx_authn_mnesia': 3, 'emqx_acl': -1})
        self.assertEqual(ha_emqx.parse_authn('[{password_based,built_in_database,true,\n   sha256,suffix}]'),
                         [{'mechanism': 'password_based', 'backend': 'built_in_database', 'enable': True,
                           'algorithm': 'sha256', 'salt': 'suffix'}])
        self.assertEqual(ha_emqx.parse_strict('{deny,ignore}\n'), ('deny', 'ignore'))
        self.assertIsNone(ha_emqx.parse_strict('{badrpc,nodedown}'))
        self.assertEqual(ha_emqx.check_counts({'emqx_acl': 2, 'emqx_psk': -1}, {'emqx_acl': 1}, {'emqx_acl': 3}), [])
        self.assertTrue(ha_emqx.check_counts({'emqx_acl': 2}, {'emqx_acl': 0}, {'emqx_acl': 3}))


if __name__ == '__main__':
    unittest.main()
