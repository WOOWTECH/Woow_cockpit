"""HA import, EMQX part (ha_emqx.py): HA's broker files staged without the cookie, generated configs, plugins or
patches; HA's broker in a throwaway of the live image (network none, read-only root, root, HA's node name mapped to
127.0.0.1) exports the data; this device's broker imports it, HA's authentication and authorization are what it holds
after that (HAOS parity, D0) and this device's other settings come back; versions, the default Dashboard account and the
volumes (CONTRACT section 9). The check builds the same candidate (H7). Team E2; HAOS parity lane EMQX-A."""
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


def export_listing(name, *, roots=('authentication', 'authorization', 'rule_engine'), members=None):
    """The candidate's answer to ha_emqx.export_expression(name): EMQX's own listing of HA's export (a healthy one)."""
    base = name[:-len('.tar.gz')]
    if members is None:
        members = [[f'{base}/META.hocon', 'regular', 40], [f'{base}/cluster.hocon', 'regular', 900],
                   *([f'{base}/mnesia/{table}', 'regular', 512] for table in ha_emqx.TABLES)]
    doc = json.dumps({'roots': list(roots), 'members': members}).encode()
    return b'WOOWEXP:' + base64.b64encode(doc) + b':END\nok\n'


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
        self.ha_authz = '[{file,true},{built_in_database,true}]'
        self.import_changes = {}
        self.import_output = b'Importing data...\nData has been imported successfully.\n'
        self.live_authn = '[{password_based,built_in_database,true,sha256,suffix}]'
        # SR-5: the built-in password database's hashing (ha_emqx.HASH_EXPR) of HA's broker and of this device, and this
        # device's user ids there (ha_emqx.USERS_EXPR): its bootstrap user woow, as the product package seeds it.
        self.ha_hashing = '[{true,sha256,suffix,none,none,none}]'
        self.live_hashing = '[{true,sha256,suffix,none,none,none}]'
        self.live_users = 'WOOWUSERS:1:d29vdw==:ENDok\n'
        # SR-5 re-review (iteration 7): HA's other `plain` built-in password databases and rows in clear text
        # (ha_emqx.PLAIN_EXPR, HA's broker only): none.
        self.ha_plain = 'WOOWPLAIN:0:0::ENDok\n'
        self.device_reads = []
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

    def again(self):
        """This device's broker as it was before the last conversion (a test that converts twice)."""
        self.imported_into = self.restored = False
        self.current_config = copy.deepcopy(self.target_config)

    def merged_authentication(self):
        """This device's authenticators with HA's merged in (emqx_utils:merge_lists: by mechanism and backend)."""
        rows = copy.deepcopy(self.current_config.get('authentication') or [])
        for item in ha_emqx.parse_authn(self.ha_authn):
            for row in rows:
                if (row.get('mechanism'), row.get('backend')) == (item['mechanism'], item['backend']):
                    row['enable'] = item['enable']
                    break
            else:
                rows.append({'mechanism': item['mechanism'], 'backend': item['backend'], 'enable': item['enable']})
        return rows

    def labels(self, image):
        return {'org.opencontainers.image.version': self.version}

    def boot_view(self, role, config):
        """The boot form (ha_emqx.BOOT_CONFIG_EXPR) of `config` as `role` answers it: no schema defaults here."""
        return config

    def schedulers(self, role):
        """(total, online) as `role`'s VM answers ha_emqx.VM_EXPR: this device 4/4; a throwaway runs with half the CPUs
        (tempctr --cpus) and so 2 online, unless its last `podman run` gave ERL_AFLAGS "+S total:online"."""
        if role == 'woow-emqx':
            return 4, 4
        flags = [value[len('ERL_AFLAGS='):] for run_role, _image, _command, options in self.runs if run_role == role
                 for value in options.get('--env', []) if value.startswith('ERL_AFLAGS=')]
        if flags and flags[-1].startswith('+S '):
            total, online = flags[-1][3:].split(':')
            return int(total), int(online)
        return 4, 2

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
                # HA's authorization comes with the import (D0): its sources as HA's broker answers AUTHZ_EXPR (the file source
                # is HA's own ACL file, which the export carries); HA's authenticators are merged into this device's by
                # mechanism and backend, so every one of them is in the candidate (a test that wants them gone says so in
                # `import_changes`).
                self.current_config['authorization'] = {'no_match': 'allow', 'deny_action': 'ignore', 'sources': [
                    {'type': 'file', 'enable': True, 'path': '/opt/emqx/data/authz/acl.conf'} if item['type'] == 'file' else
                    {'type': item['type'], 'enable': item['enable']} for item in ha_emqx.parse_authz(self.ha_authz) or []]}
                self.current_config['authentication'] = self.merged_authentication()
                self.current_config.update(copy.deepcopy(self.import_changes))
                return Result(0, self.import_output, b'')
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
        if expression == ha_emqx.export_expression(EXPORT.rsplit('/', 1)[1]):
            return export_listing(EXPORT.rsplit('/', 1)[1])
        if expression == ha_emqx.ETC_EXPR:
            return b'WOOWETC:/opt/emqx/etc:ENDok\n'
        if expression == ha_emqx.VM_EXPR:
            return 'WOOWVM:{}:{}:END\nok\n'.format(*self.schedulers(role)).encode()
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
        if expression == ha_emqx.PLAIN_EXPR:
            if role != 'emqx-ha':
                self.device_reads.append((role, 'plain'))
            return self.ha_plain.encode()
        if expression in (ha_emqx.HASH_EXPR, ha_emqx.USERS_EXPR):
            if role != 'emqx-ha':
                self.device_reads.append((role, 'hash' if expression == ha_emqx.HASH_EXPR else 'users'))
            if expression == ha_emqx.USERS_EXPR:
                return self.live_users.encode()
            return (self.ha_hashing if role == 'emqx-ha' else self.live_hashing).encode()
        if expression == ha_emqx.AUTHZ_EXPR:
            return self.ha_authz.encode() if role == 'emqx-ha' else b'[{file,true},{built_in_database,true}]'
        if expression == ha_emqx.STRICT_EXPR:
            if role == 'emqx-ha' or self.imported_into:
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

    def internal_candidate(self, ha_id, *, acknowledged=None):
        """Actual internal build/package with generated transport, never public convert. `acknowledged`: None collects what
        the customer would be asked (the check's way), a list of keys converts the way a confirmed import does.

        Public preservation tests remain separate. No target-policy helper or preservation gate is patched out here; the
        fixture answers its native config/volume protocol just as it answers counts and import outcomes."""
        ctx = self.ctx()
        ctx.storage.ensure_layout()
        staging = Path(ctx.storage.staging_dir(ctx.job_id))
        staging.mkdir(parents=True, exist_ok=True)
        work = haimport.Work(ctx, None, None, staging, acknowledged=None if acknowledged is None else {'emqx': acknowledged})
        try:
            work.record = haimport._open(work, ctx, {'ha_backup_id': ha_id})
            app = self.catalog['emqx']
            target, version = ha_emqx._prepare(work, app)
            tmp = work.temp(app)
            private = staging / 'internal-emqx-work'
            private.mkdir(mode=0o700)
            built = ha_emqx._build_candidate(work, app, tmp, target, private, version=version)
            paths = ha_emqx._package_candidate(work, tmp, target, private, staging / 'internal-emqx-output',
                built.export, ids=work.adapter(app).owner_ids(),
                log_root=ha_n8n.volume_root(work, app, target.log_volume))
            data = {'ha_hosts': hacommon.ha_hosts(built.src.hocon), 'plugins': sorted(built.src.plugins),
                    'api_keys': max(built.readings['counts'].get('emqx_app', 0), 0)}
            notes, _, reminders = haimport.import_texts({'emqx': data}, self.catalog)
            return {'volumes': paths, 'notes': notes, 'reminders': reminders['emqx'], 'issues': work.sink(app).found,
                    'built': built}
        finally:
            self.assertEqual(work.close(), [])


def ids(result, level=None):
    """The issue ids of one app's check result (optionally of one level)."""
    return [issue['id'] for issue in result['issues'] if level is None or issue['level'] == level]


class CheckTests(EmqxCase):
    def test_a_clean_backup(self):
        """A clean backup is importable with nothing to confirm; this device's authorization is no longer judged (D0)."""
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertEqual((result['ok'], result['blockers'], result['target_version']),
                         (True, [], '5.8.9'))
        self.assertEqual(result['emqx']['target_authorization'], [])
        self.assertEqual(ids(result, 'confirm'), [])
        self.assertIn('emqx.access-from-ha', ids(result, 'auto'))
        section = result['emqx']
        self.assertEqual((section['node_name'], section['mqtt_users'], section['acl_rules'], section['api_keys'],
                          section['retained_messages'], section['default_dashboard_password']),
                         (NODE, 3, 2, 1, 0, False))
        self.assertEqual(section['plugins'], ['my_plugin-1.0.0'])
        joined = '\n'.join(result['warnings'])
        for words in ('homeassistant', '/ssl/fullchain.pem', 'my_plugin', 'API 金鑰會取代', '沒有符合規則的主題時允許'):
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
        # H7: the check builds the candidate the conversion builds, in throwaway objects; nothing of this device changes
        self.assertEqual(len(self.runs('emqx-new')), 1)
        self.assertEqual(len([c for c in self.world.ctl_calls if c[1][:2] == ['data', 'export']]), 1)
        self.assertEqual(len([c for c in self.world.ctl_calls if c[1][:2] == ['data', 'import']]), 1)
        self.assertNotIn('woow_emqx_data', self.world.imported, 'no volume of this device is written')

    def test_the_default_dashboard_account_is_a_notice_and_a_confirmation_when_the_network_reaches_it(self):
        """D2, E-20, H3: HA's admin/public is restored; when this device's Dashboard is reachable from the network or a tunnel
        reaches it, the customer confirms it."""
        self.world.default_admin = True
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertTrue(result['importable'])
        self.assertIn('emqx.default-dashboard', ids(result, 'notice'))
        self.assertTrue(result['ok'], 'a notice asks nothing')
        for line in ('PublishPort=0.0.0.0:18083:18083\n', 'PublishPort=192.168.2.5:18083:18083\n'):
            exposed = dict(QUADLETS)
            exposed['emqx.container'] = QUADLETS['emqx.container'].replace(b'Volume=emqx-data', line.encode() + b'Volume=emqx-data')
            self.world.quadlets = {'emqx': exposed}
            result = self.check(self.upload_emqx(), ['emqx'])[0]
            self.assertTrue(result['importable'])
            self.assertEqual(ids(result, 'confirm'), ['emqx.default-dashboard-exposed'])
            self.assertFalse(result['ok'])
            self.assertTrue(result['issues'][[i['id'] for i in result['issues']].index('emqx.default-dashboard-exposed')]['key'])
        local = dict(QUADLETS)
        local['emqx.container'] = QUADLETS['emqx.container'].replace(b'Volume=emqx-data', b'PublishPort=127.0.0.1:18083:18083\nVolume=emqx-data')
        self.world.quadlets = {'emqx': local}
        self.assertEqual(ids(self.check(self.upload_emqx(), ['emqx'])[0], 'confirm'), [])

    def test_the_default_dashboard_account_behind_a_tunnel_is_a_confirmation(self):
        self.world.default_admin = True
        tunnel = dict(QUADLETS)
        tunnel['emqx-ngrok.container'] = b'[Container]\nContainerName=woow-emqx-ngrok\nImage=docker.io/ngrok/ngrok:3\n'
        self.world.quadlets = {'emqx': tunnel}
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertEqual(ids(result, 'confirm'), ['emqx.default-dashboard-exposed'])
        self.assertIn('emqx-ngrok', json.dumps(result['issues'], ensure_ascii=False))

    def test_versions_inform_and_the_data_decides(self):
        """CM-01, E-03: an add-on version the table does not know is a notice, no stop."""
        result = self.check(self.upload_emqx(version='5.9.2'), ['emqx'])[0]
        self.assertTrue(result['importable'])
        self.assertIn('version.addon-unknown', ids(result, 'notice'))
        self.world.version = '5.9.0'
        result = self.check(self.upload_emqx(), ['emqx'])[0]
        self.assertFalse(result['importable'], 'both versions are known and differ: E-05 stays (wave 2 lifts it)')
        self.assertEqual(ids(result, 'stop'), ['version.different'])
        self.assertTrue(any('HA 的 EMQX 是 5.8.9' in blocker for blocker in result['blockers']))

    def test_no_database_in_the_backup_stops_only_this_app(self):
        """E-06: nothing to move; this device's EMQX is not replaced by an empty one."""
        result = self.check(self.upload_emqx(nodes=()), ['emqx'])[0]
        self.assertFalse(result['importable'])
        self.assertEqual(ids(result, 'stop'), ['emqx.no-database'])
        self.assertIn('沒有 EMQX 的內建資料庫', result['blockers'][0])
        self.assertFalse(self.runs('emqx-ha'), 'HA\'s broker is not even started')
        self.assertFalse(self.runs('emqx-new'))

    def test_several_databases_without_a_record_use_the_last_written_one_and_can_be_chosen(self):
        """E-07: the last written database is the default (named), `choices.node` lets the customer pick another."""
        other = 'emqx@127.0.0.1'
        result = self.check(self.upload_emqx(node_file=None, nodes=(NODE, other)), ['emqx'])[0]
        self.assertTrue(result['importable'])
        self.assertIn('emqx.node-chosen', ids(result, 'auto'))
        rows = result['choices']['node']
        self.assertEqual({row['value'] for row in rows}, {NODE, other})
        self.assertEqual([row['value'] for row in rows if row.get('default')], [result['emqx']['node_name']])
        self.assertIn('最後寫入', rows[0]['label'])

    def test_a_recorded_node_without_its_database_uses_the_only_one_there_is(self):
        """E-09: the record names a node the backup has no database for, and there is just one: it is used."""
        result = self.check(self.upload_emqx(node_file='emqx@gone.local', nodes=(NODE,)), ['emqx'])[0]
        self.assertTrue(result['importable'])
        self.assertEqual(result['emqx']['node_name'], NODE)
        self.assertIn('emqx.node-chosen', ids(result, 'auto'))
        self.assertNotIn('choices', result)

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
        # D0: HA's authorization is what the candidate holds after the import; nothing of this device's is loaded back
        self.assertEqual([i for i in self.world.current_config['authorization']['sources']],
                         [{'type': 'file', 'enable': True, 'path': '/opt/emqx/data/authz/acl.conf'},
                          {'type': 'built_in_database', 'enable': True}])
        self.assertEqual(self.world.current_config['authorization']['no_match'], 'allow')
        self.assertNotIn(['conf', 'load', '--replace', '/work/in/target-settings.hocon'],
                         [c[1] for c in self.world.ctl_calls])
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

    def test_a_partial_import_is_a_line_to_confirm_not_a_stop(self):
        """E-67: what EMQX could not import is listed in the one confirmation (the check knows it: H7); the rest goes on."""
        self.world.import_output = b'Data has been imported, but some errors occurred, see the log above.\n'
        result = self.internal_candidate(self.upload_emqx())
        line = next(issue for issue in result['issues'] if issue.id == 'emqx.import-partial')
        self.assertEqual(line.level, 'confirm')
        self.assertIn('部分設定無法匯入', line.message)
        ha_id = self.upload_emqx()
        self.world.again()
        with self.assertRaises(BackupError) as caught:   # the conversion of a customer who did not confirm it
            self.internal_candidate(ha_id, acknowledged=[])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.world.again()
        confirmed = self.internal_candidate(ha_id, acknowledged=[line.key('emqx')])
        self.assertTrue(confirmed['volumes'])

    def test_lost_rows_stop_the_conversion(self):
        self.world.import_lost = 'emqx_acl'
        with self.assertRaises(BackupError) as caught:
            self.internal_candidate(self.upload_emqx())
        self.assertIn('emqx_acl', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])

    def test_has_authentication_is_restored_as_it_is_even_when_nobody_has_to_log_in(self):
        """D5, E-82 (S2): HA's disabled authentication is restored; the customer confirms it, no refusal."""
        self.world.ha_authn = '[{password_based,built_in_database,false,sha256,suffix}]'
        ha_id = self.upload_emqx()
        result = self.internal_candidate(ha_id)
        line = next(issue for issue in result['issues'] if issue.id == 'emqx.no-authentication')
        self.assertEqual(line.level, 'confirm')
        self.assertIn('不用帳號就能連線', line.message)
        self.assertIn('MQTT 埠目前', line.message)   # says whether the port is open (here: not published at all)
        self.assertIn('公開網址', line.message)       # a public address cannot be told from here: the sentence always says it
        self.world.again()
        with self.assertRaises(BackupError) as caught:
            self.internal_candidate(ha_id, acknowledged=[])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.world.again()
        self.assertTrue(self.internal_candidate(ha_id, acknowledged=[line.key('emqx')])['volumes'])

    def test_settings_of_this_device_that_the_import_changed_are_loaded_back_and_must_come_back(self):
        """E-72/E-74 stay: this device's own roots are loaded back (`conf load --replace`) and read again."""
        self.world.target_config['mqtt'] = {'max_packet_size': '1MB'}
        self.world.current_config = copy.deepcopy(self.world.target_config)
        self.world.import_changes = {'mqtt': {'max_packet_size': '9MB'}}
        result = self.internal_candidate(self.upload_emqx())
        self.assertEqual(self.world.current_config['mqtt'], {'max_packet_size': '1MB'})
        self.assertIn(['conf', 'load', '--replace', '/work/in/target-settings.hocon'], [c[1] for c in self.world.ctl_calls])
        self.assertTrue(result['volumes'])

    def test_the_settings_of_this_device_must_come_back(self):
        real = self.world.exec

        def exec_(role, command, data, stdout):
            if command[:4] == ['emqx', 'ctl', 'conf', 'load']:
                return Result(0, b'', b'')  # the load silently did nothing
            return real(role, command, data, stdout)

        self.world.target_config['mqtt'] = {'max_packet_size': '1MB'}
        self.world.current_config = copy.deepcopy(self.world.target_config)
        self.world.import_changes = {'mqtt': {'max_packet_size': '9MB'}}
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
