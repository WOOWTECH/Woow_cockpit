"""HA import, Nextcloud part (ha_nextcloud.py): HA's PostgreSQL database, config.php identity, custom apps and the
user files of the share folder move; the target keeps its URLs, database credentials, Office (Collabora) settings and
secrets; a backup without the share folder is refused (CONTRACT section 9 "Batch 2: Nextcloud"). Team E2."""
import gzip
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from woowbackup import ha_nextcloud as nc
from woowbackup import habackup, haimport, jobs
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import hab1fakes as fk
from . import hafixtures as hx

SLUG = '1b7b4ce7_woow-nextcloud-office'
HOME = '/home/appowner/'
DIRS = ['.local/share/nextcloud-office/postgres', '.local/share/nextcloud-office/redis',
        '.local/share/nextcloud-office/html', '.local/share/nextcloud-office/data']
VERIFIER = 'SCRAM-SHA-256$4096:c2FsdHNhbHQ=$c3RvcmVka2V5:c2VydmVya2V5'
LIVE_CONFIG = b"""<?php
$CONFIG = array (
  'htaccess.RewriteBase' => '/',
  'memcache.local' => '\\\\OC\\\\Memcache\\\\APCu',
  'apps_paths' =>
  array (
    0 =>
    array (
      'path' => '/var/www/html/apps',
      'url' => '/apps',
      'writable' => false,
    ),
  ),
  'instanceid' => 'oclive123456',
  'passwordsalt' => 'livesaltlivesaltlivesalt',
  'secret' => 'livesecretlivesecretlivesecret',
  'trusted_domains' =>
  array (
    0 => '127.0.0.1:18081',
  ),
  'datadirectory' => '/var/www/html/data',
  'dbtype' => 'pgsql',
  'version' => '35.0.1.1',
  'overwrite.cli.url' => 'http://127.0.0.1:18081',
  'dbname' => 'nextcloud',
  'dbhost' => 'nextcloud-db',
  'dbport' => '',
  'dbtableprefix' => 'oc_',
  'dbuser' => 'oc_admin',
  'dbpassword' => 'live-db-password-0001',
  'installed' => true,
  'maintenance' => false,
  'maintenance_window_start' => 1,
  'data-fingerprint' => '00000000000000000000000000000001',
);
"""
HA_CONFIG = b"""<?php
// written by Nextcloud
$CONFIG = array (
  'instanceid' => 'ochaabcdef12',
  'passwordsalt' => 'hasaltHAsalt+/=hasalt',
  'secret' => 'hasecretHAsecret/+hasecretHAsecret',
  'trusted_domains' => array (0 => 'woowtech-nextcloud.woowtech.io', 1 => 'localhost'),
  'datadirectory' => '/share/nextcloud',
  'dbtype' => 'pgsql',
  'version' => '35.0.1.1',
  'overwrite.cli.url' => 'https://woowtech-nextcloud.woowtech.io',
  'dbname' => 'nextcloud',
  'dbhost' => '/run/postgresql',
  'dbport' => '',
  'dbtableprefix' => 'oc_',
  'dbuser' => 'nextcloud',
  'dbpassword' => 'ha-db-password-0002',
  'installed' => true,
  'twofactor_enforced' => 'true',
  'mail_smtpmode' => 'smtp',
  'mail_smtppassword' => 'ha-mail-password',
  'theme' => '',
  'enable_previews' => true,
  'preview_max_x' => 2048,
  'ratio' => 1.5,
  'data-fingerprint' => '0000000000000000000000000000000a',
);
"""
INFO_NOTES = b'<?xml version="1.0"?><info><id>notes</id><version>4.12.0</version><dependencies>' \
             b'<php min-version="8.1" max-version="8.5"/><nextcloud min-version="30" max-version="35"/></dependencies></info>'
INFO_RD = b'<?xml version="1.0"?><info><id>richdocuments</id><version>9.0.3</version><dependencies>' \
          b'<php min-version="8.1" max-version="8.4"/><nextcloud min-version="33" max-version="35"/></dependencies></info>'
QUADLETS = {
    'nextcloud.network': b'[Network]\n',
    'nextcloud-db.container': b'[Container]\nContainerName=nextcloud-db\nImage=docker.io/pgvector/pgvector:0.8.6-pg16\n'
                              b'Volume=%h/.local/share/nextcloud-office/postgres:/var/lib/postgresql/data\n'
                              b'Environment=POSTGRES_USER=nextcloud\nEnvironment=POSTGRES_DB=nextcloud\n'
                              b'Secret=nextcloud-db-password,type=env,target=POSTGRES_PASSWORD\n',
    'nextcloud-redis.container': b'[Container]\nContainerName=nextcloud-redis\nImage=docker.io/library/redis:8.10.1-alpine\n'
                                 b'Volume=%h/.local/share/nextcloud-office/redis:/data\n',
    'nextcloud-app.container': b'[Container]\nContainerName=nextcloud-app\nImage=localhost/woow-nextcloud:35.0.1-office2\n'
                               b'Volume=%h/.local/share/nextcloud-office/html:/var/www/html\n'
                               b'Volume=%h/.local/share/nextcloud-office/data:/var/www/html/data\n'
                               b'Environment=POSTGRES_HOST=nextcloud-db\n'
                               b'Secret=nextcloud-db-password,type=env,target=POSTGRES_PASSWORD\n',
    'nextcloud-office.container': b'[Container]\nContainerName=nextcloud-office\nImage=docker.io/collabora/code:26.04.4.2.1\n',
    'nextcloud-gateway.container': b'[Container]\nContainerName=nextcloud-gateway\n'
                                   b'Image=docker.io/nginxinc/nginx-unprivileged:1.29.3-alpine\n'
                                   b'Volume=%h/.config/nextcloud/gateway.conf:/etc/nginx/conf.d/default.conf:ro\n',
}
LIVE_APPCONFIG = [{'appid': 'core', 'configkey': 'backgroundjobs_mode', 'configvalue': 'cron', 'type': 2, 'lazy': 0},
                  {'appid': 'richdocuments', 'configkey': 'public_wopi_url', 'configvalue': 'http://127.0.0.1:18081',
                   'type': 2, 'lazy': 0},
                  {'appid': 'richdocuments', 'configkey': 'wopi_url', 'configvalue': 'http://nextcloud-office:9980',
                   'type': 2, 'lazy': 0}]
LIVE_DB = {'role': {'password': VERIFIER, 'super': False, 'login': True, 'createdb': True, 'createrole': False,
                    'replication': False, 'bypassrls': False, 'connlimit': -1},
           'roles': ['nextcloud', 'oc_admin'], 'extensions': ['plpgsql', 'vector'],
           'datacl': '{nextcloud=CTc/nextcloud,oc_admin=c/nextcloud}',
           'nspacl': '{pg_database_owner=UC/pg_database_owner,=U/pg_database_owner,oc_admin=C/pg_database_owner}',
           'appconfig': LIVE_APPCONFIG}
HA_COUNTS = {'users': 3, 'files': 300, 'shares': 1, 'tokens': 125, 'calendar_objects': 2, 'contacts': 3, 'storages': 3,
             'mounts': 2}
# dev-e's Nextcloud 35.0.1 (2026-11-24): nothing beyond tables, sequences and indexes; these default shapes.
CLEAN_SHAPE = {**{key: 0 for key, _label in nc.SHAPE_LABELS}, 'role_settings': 0,
               'defaults': ["''::character varying", "''::text", "'-1'::integer", "'0'::double precision", '0', '1',
                            "'OCA\\WorkflowEngine\\Entity\\File'::character varying", 'false',
                            "NULL::character varying", 'NULL::timestamp without time zone',
                            "nextval('public.oc_accounts_data_id_seq'::regclass)"]}
TABLES = ['oc_appconfig', 'oc_authtoken', 'oc_calendarobjects', 'oc_cards', 'oc_filecache', 'oc_mounts', 'oc_share',
          'oc_storages', 'oc_users']


def addon_tar(*, config=HA_CONFIG, pg_version=b'16\n', apps=True, extra=()):
    addon = {'user': {'version': '0.2.3', 'image': 'ghcr.io/woowtech/woow-ha-nextcloud-office-amd64',
                      'options': {'ADMIN_PASS': 'ha-admin-secret'}},
             'system': {'slug': 'woow-nextcloud-office', 'name': 'Woow Nextcloud Office'}, 'version': '0.2.3'}
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': json.dumps(addon).encode()},
               {'name': 'data', 'type': 'dir'}, {'name': 'data/options.json', 'data': b'{"ADMIN_PASS": "x"}'},
               {'name': 'data/postgres', 'type': 'dir', 'mode': 0o700, 'uid': 102, 'gid': 104},
               {'name': 'data/postgres/PG_VERSION', 'data': pg_version, 'uid': 102, 'gid': 104},
               {'name': 'data/postgres/postgresql.conf', 'data': b"shared_preload_libraries = 'evil'\n"},
               {'name': 'data/postgres/base/1/1259', 'data': b'p' * 100},
               {'name': 'data/nextcloud', 'type': 'dir'}, {'name': 'data/nextcloud/config', 'type': 'dir'},
               {'name': 'data/nextcloud/config/apps.config.php', 'data': b'<?php $CONFIG = [];'},
               {'name': 'data/redis', 'type': 'dir'}, {'name': 'data/redis/dump.rdb', 'data': b'REDIS'},
               {'name': 'data/coolwsd-jail', 'type': 'dir'}, {'name': 'data/coolwsd-jail/lo', 'data': b'x'}]
    if config is not None:
        entries.append({'name': 'data/nextcloud/config/config.php', 'data': config, 'mode': 0o640, 'uid': 33,
                        'gid': 33})
    if apps:
        entries += [{'name': 'data/nextcloud/custom_apps', 'type': 'dir'},
                    {'name': 'data/nextcloud/custom_apps/notes', 'type': 'dir'},
                    {'name': 'data/nextcloud/custom_apps/notes/appinfo/info.xml', 'data': INFO_NOTES},
                    {'name': 'data/nextcloud/custom_apps/notes/lib/Notes.php', 'data': b'<?php // notes'},
                    {'name': 'data/nextcloud/custom_apps/richdocuments', 'type': 'dir'},
                    {'name': 'data/nextcloud/custom_apps/richdocuments/appinfo/info.xml', 'data': INFO_RD},
                    {'name': 'data/nextcloud/custom_apps/richdocuments/appinfo/routes.php', 'data': b'<?php // HA'}]
    entries += list(extra)
    return gzip.compress(hx.tar_bytes(entries), mtime=0)


def share_tar(*, ncdata=True, extra=()):
    entries = [{'name': 'nextcloud', 'type': 'dir', 'mode': 0o770, 'uid': 33, 'gid': 33},
               {'name': 'nextcloud/admin', 'type': 'dir'}, {'name': 'nextcloud/admin/files', 'type': 'dir'},
               {'name': 'nextcloud/admin/files/hello.txt', 'data': b'hello from HA', 'uid': 33, 'gid': 33},
               {'name': 'nextcloud/admin/files/中文.txt', 'data': '測試'.encode(), 'uid': 33, 'gid': 33},
               {'name': 'nextcloud/appdata_ochaabcdef12', 'type': 'dir'},
               {'name': 'nextcloud/appdata_ochaabcdef12/preview/1.png', 'data': b'PNG'},
               {'name': 'nextcloud/appdata_ochaabcdef12/richdocuments/remoteData', 'type': 'dir'},
               {'name': 'nextcloud/appdata_ochaabcdef12/richdocuments/remoteData/discovery', 'data': b'<xml/>'},
               {'name': 'nextcloud/updater-ochaabcdef12/backups/old.zip', 'data': b'z' * 50},
               {'name': 'nextcloud/nextcloud.log', 'data': b'{}\n'},
               {'name': 'woowtechbot-image-test', 'type': 'dir'},
               {'name': 'woowtechbot-image-test/big.bin', 'data': b'b' * 500}]
    if ncdata:
        entries.append({'name': 'nextcloud/.ncdata', 'data': b'# Nextcloud data directory\n'})
    entries += list(extra)
    return gzip.compress(hx.tar_bytes(entries), mtime=0)


def live_html():
    entries = [{'name': './', 'type': 'dir', 'uid': 33, 'gid': 33, 'mode': 0o700},
               {'name': './config/', 'type': 'dir', 'uid': 33, 'gid': 33, 'mode': 0o750},
               {'name': './config/config.php', 'data': LIVE_CONFIG, 'uid': 33, 'gid': 33, 'mode': 0o640},
               {'name': './config/redis.config.php', 'data': b'<?php // image', 'uid': 33, 'gid': 33},
               {'name': './custom_apps/', 'type': 'dir', 'uid': 33, 'gid': 33},
               {'name': './custom_apps/richdocuments/', 'type': 'dir', 'uid': 33, 'gid': 33},
               {'name': './custom_apps/richdocuments/appinfo/info.xml', 'data': b'<info>live 12.0.1</info>',
                'uid': 33, 'gid': 33},
               {'name': './custom_apps/liveonly/', 'type': 'dir', 'uid': 33, 'gid': 33},
               {'name': './apps/', 'type': 'dir', 'uid': 33, 'gid': 33},
               {'name': './apps/files/appinfo/info.xml', 'data': b'<info/>', 'uid': 33, 'gid': 33},
               {'name': './version.php', 'data': b'<?php $OC_Version = array(35,0,1,1);', 'uid': 33, 'gid': 33},
               {'name': './data/', 'type': 'dir', 'uid': 0, 'gid': 0}]
    return hx.tar_bytes(entries)


def members(data):
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return {m.name: (m, tar.extractfile(m).read() if m.isfile() else None) for m in tar.getmembers()}


class Owner(fk.Owner):
    def dir_pack(self, rel, *, stdout, timeout=None, max_output=None, abort=None):
        self.calls.append(('dir_pack', rel))
        stdout.write(live_html())

    def dir_measure(self, rel):
        return {'bytes': 4096, 'members': 12, 'acls': 0, 'mount_root': False, 'mounts': [], 'more_mounts': 0}


class Adapter(fk.Adapter):
    def import_manifest(self, staging_dir, **items):
        self.world.dirs = {rel: Path(path).read_bytes() for rel, path in (items.get('dirs') or {}).items()}
        return super().import_manifest(staging_dir, **items)


class World(fk.World):
    def __init__(self):
        super().__init__()
        self.owner = Owner(self)
        self.quadlets = {'nextcloud': QUADLETS}
        self.images = {'docker.io/pgvector/pgvector:0.8.6-pg16'}
        self.ha_details = {'extensions': ['plpgsql'], 'schemas': [], 'local_storages': ['local::/share/nextcloud/'],
                           'enabled': ['dav', 'files', 'notes', 'richdocuments', 'gone_app'], 'encryption': None}
        self.verify = None
        self.catalog = None
        self.shape = {'hapg': dict(CLEAN_SHAPE), 'nc-db': dict(CLEAN_SHAPE)}
        self.toc = b';\n; Archive\n201; 1259 16390 TABLE public oc_users nextcloud\n'
        self.sessions = []
        self.php = []
        self.dirs = {}

    def podman(self, args, data, stdout):
        if args[0] == 'exec':
            env, i = {}, 1
            while args[i].startswith('--'):
                if args[i] == '--env':
                    key, _sep, value = args[i + 1].partition('=')
                    env[key] = value
                i += 2 if args[i] in ('--user', '--workdir', '--env') else 1
            command = list(args[i + 1:])
            sql = command[command.index('-c') + 1] if '-c' in command[:-1] else (
                data.decode('utf-8', 'replace') if isinstance(data, bytes) and command[:1] == ['psql'] else '')
            self.sessions.append({'role': fk.role_of(args[i]), 'tool': command[0], 'env': env, 'sql': sql,
                                  'pg_user': command[command.index('-U') + 1] if '-U' in command[:-1] else None})
        return super().podman(args, data, stdout)

    def factory(self, app, **_kwargs):
        return Adapter(app, self)

    def image_info(self, image):
        return {'id': 'sha256:' + 'c' * 64, 'digest': '', 'arch': 'amd64', 'size': 1, 'names': [],
                'env': ['PG_MAJOR=16', 'NEXTCLOUD_VERSION=35.0.1', 'PHP_VERSION=8.5.11']}

    def user_ids(self, user):
        return {'postgres': b'999\n999\n', 'www-data': b'33\n33\n'}.get(user, b'1000\n1000\n')

    def run(self, role, image, command, options, data):
        if role == 'controldata':
            return Result(0, b'Database cluster state:               shut down\n', b'')
        if role == 'nc-php':
            self.php.append(data)
            return Result(0, json.dumps(nc.jsonable(nc.parse_config(data))).encode(), b'')
        return Result(0, b'', b'')

    def exec(self, role, command, data, stdout):
        if role == 'nextcloud-app' and command[:1] == ['cat']:
            return Result(0, LIVE_CONFIG, b'')
        if command[:1] == ['ls']:
            return Result(0, b'files\ndav\nsettings\n' if command[-1].endswith('/apps') else b'richdocuments\nliveonly\n',
                          b'')
        if command[:1] == ['stat']:
            return Result(0, {'nextcloud-db': b'999 0 700\n', 'nextcloud-redis': b'999 1000 755\n'}
                          .get(role, b'33 33 770\n'), b'')
        if role == 'hapg' and command[0] == 'pg_dump':
            stdout.write(b'PGDMP-ha-nextcloud')
            return Result(0, None, b'')
        if role == 'nc-db' and command[:2] == ['pg_restore', '-l']:
            return Result(0, self.toc, b'')
        return Result(0, b'', b'')

    def answer(self, role, sql, database):
        if sql.startswith('SELECT coalesce(json_agg(json_build_array(datname'):
            return [['nextcloud', 1000, 'C.UTF-8', 'C.UTF-8']]
        if sql == nc.TABLES_SQL:
            return TABLES
        if sql == nc.HA_SQL:
            return self.ha_details
        if sql == nc.SHAPE_SQL:
            return self.shape.get(role)
        if sql.startswith("SELECT json_build_object('users'"):
            return HA_COUNTS
        if sql.startswith("SELECT json_build_object(\n 'role'"):
            return LIVE_DB
        if sql.startswith('SELECT count(*) FROM public.oc_filecache'):
            return 2
        if sql.startswith("SELECT json_build_object(\n 'counts'"):
            return self.verify if self.verify is not None else {
                'counts': {**HA_COUNTS, 'files': 298}, 'root': 1, 'old': 0, 'appconfig': LIVE_DB['appconfig']}
        if sql.startswith("SELECT json_build_object(\n 'owners'"):
            return self.catalog if self.catalog is not None else {
                'owners': ['oc_admin'], 'verifier_md5': hashlib.md5(VERIFIER.encode()).hexdigest(),
                'role': {k: v for k, v in LIVE_DB['role'].items() if k != 'password'}, 'role_settings': 0,
                **{key: LIVE_DB[key] for key in ('roles', 'extensions', 'datacl', 'nspacl')}}
        if 'FROM pg_settings' in sql or 'pg_file_settings' in sql:
            return []
        return None

    def export(self, volume):
        return fk.tar_of([{'name': '.', 'type': 'dir', 'uid': 999, 'gid': 999, 'mode': 0o700},
                          {'name': 'PG_VERSION', 'data': b'16\n', 'uid': 999, 'gid': 999, 'mode': 0o600},
                          {'name': 'base', 'type': 'dir', 'uid': 999, 'gid': 999, 'mode': 0o700},
                          {'name': 'base/1', 'type': 'dir', 'uid': 999, 'gid': 999, 'mode': 0o700},
                          {'name': 'base/1/1259', 'data': b'n' * 10, 'uid': 999, 'gid': 999, 'mode': 0o600}])


class NextcloudCase(fk.ConversionCase):
    world_class = World

    def setUp(self):
        super().setUp()
        for value in (VERIFIER, 'hasecretHAsecret/+hasecretHAsecret', 'hasaltHAsalt+/=hasalt', 'ha-db-password-0002',
                      'ha-mail-password', 'livesecretlivesecretlivesecret', 'livesaltlivesaltlivesalt',
                      'live-db-password-0001'):
            self.addCleanup(jobs.unmask_secret, value)

    def catalog_apps(self):
        return {'nextcloud': fk.app('nextcloud', 'Nextcloud', data_dirs=[{'path': p} for p in DIRS])}

    def upload_nextcloud(self, *, share=True, **kwargs):
        items = [(f'{SLUG}.tar.gz', addon_tar(**kwargs))]
        if share is not None:
            items.append(('share.tar.gz', share if isinstance(share, bytes) else share_tar()))
        folders = ('share',) if share is not None else ()
        return self.upload(hx.outer_bytes(items, hx.ha_doc(addons=(SLUG,), folders=folders)))


# ====================================================================== config.php

class ConfigTests(unittest.TestCase):
    def test_parses_what_nextcloud_writes_and_renders_it_back(self):
        config = nc.parse_config(LIVE_CONFIG)
        self.assertEqual(config['memcache.local'], '\\OC\\Memcache\\APCu')
        self.assertEqual(config['apps_paths'][0]['writable'], False)
        self.assertEqual((config['installed'], config['maintenance_window_start']), (True, 1))
        self.assertEqual(nc.parse_config(nc.render_config(config)), config)
        ha = nc.parse_config(HA_CONFIG)
        self.assertEqual((ha['trusted_domains'], ha['ratio']), ({0: 'woowtech-nextcloud.woowtech.io', 1: 'localhost'},
                                                                nc.Float('1.5')))
        self.assertEqual(nc.parse_config(nc.render_config(ha)), ha)
        self.assertEqual(nc.jsonable(ha)['trusted_domains'], ['woowtech-nextcloud.woowtech.io', 'localhost'])
        self.assertEqual(nc.parse_config(b"<?php\n$CONFIG = ['a' => \"x\" ];\n".replace(b'"x"', b"'it\\'s'")),
                         {'a': "it's"})

    def test_refuses_anything_that_is_not_data(self):
        for text in (b"<?php $CONFIG = array('a' => \"$x\");", b"<?php $CONFIG = array('a' => getenv('X'));",
                     b"<?php $CONFIG = array('a' => 'x' . 'y');", b"<?php $CONFIG = array(); $CONFIG = array();",
                     b"<?php $CONFIG = array('a' => PHP_EOL);", b"<?php system('id'); $CONFIG = array();",
                     b"<?php $CONFIG = array('a' => 1, 'a' => 2);", b"$CONFIG = array();", b"<?php $X = array();",
                     b"<?php $CONFIG = 'x';", b'\xff\xfe'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                nc.parse_config(text)

    def test_merge_keeps_the_target_and_takes_identity_and_policy_from_ha(self):
        live, ha = nc.parse_config(LIVE_CONFIG), nc.parse_config(HA_CONFIG)
        merged, carried, skipped = nc.merge_config(ha, live)
        self.assertEqual([merged[k] for k in nc.FROM_HA], [ha[k] for k in nc.FROM_HA])
        for key in ('dbpassword', 'dbuser', 'dbhost', 'datadirectory', 'trusted_domains', 'overwrite.cli.url'):
            self.assertEqual(merged[key], live[key], key)
        self.assertEqual((carried, merged['twofactor_enforced']), (['twofactor_enforced'], 'true'))
        self.assertEqual(skipped, ['theme', 'enable_previews', 'preview_max_x', 'ratio'])
        self.assertNotIn('mail_smtppassword', merged)
        strict = dict(live, twofactor_enforced='true')
        merged, carried, _ = nc.merge_config(dict(ha, twofactor_enforced='false'), strict)
        self.assertEqual((merged['twofactor_enforced'], carried), ('true', []), 'never weaker than the target')

    def test_blockers(self):
        live, ha = nc.parse_config(LIVE_CONFIG), nc.parse_config(HA_CONFIG)
        self.assertEqual(nc.config_blockers(ha, live, '35.0.1'), [])
        cases = ((dict(ha, version='35.0.3.1'), '版本不同'), (dict(ha, maintenance=True), '維護模式'),
                 (dict(ha, installed=False), '還沒有安裝完成'), (dict(ha, dbtype='mysql'), 'PostgreSQL'),
                 (dict(ha, dbtableprefix='nc_'), '前綴'), (dict(ha, objectstore={'class': 'S3'}), '物件儲存'),
                 ({k: v for k, v in ha.items() if k != 'secret'}, '身分資料'))
        for config, text in cases:
            with self.subTest(text=text):
                self.assertTrue(any(text in b for b in nc.config_blockers(config, live, '35.0.1')))
        self.assertIn('映像版本', nc.config_blockers(ha, live, '35.0.3')[0])
        self.assertIn('無法解讀', nc.config_blockers(None, live, '35.0.1')[0])

    def test_storage_id_and_datadir_location(self):
        self.assertEqual(nc.storage_id('/share/nextcloud'), 'local::/share/nextcloud/')
        self.assertEqual(nc.storage_id('/var/www/html//data/'), 'local::/var/www/html/data/')
        long = '/share/' + 'x' * 70
        self.assertRegex(nc.storage_id(long), r'\A[0-9a-f]{32}\Z')
        self.assertEqual(nc.datadir_source('/share/nextcloud'), ('share', 'nextcloud'))
        self.assertEqual(nc.datadir_source('/share/nc/data/'), ('share', 'nc/data'))
        self.assertEqual(nc.datadir_source('/data/userfiles'), ('addon', 'data/userfiles'))
        self.assertEqual(nc.datadir_source('/data/nextcloud/data'), ('addon', 'data/nextcloud/data'))
        for path in ('/media/nc', '/mnt/nas', '/data/postgres', '/data/nextcloud', '/data', '/share',
                     '/share/../etc', 'share/nextcloud', None):
            self.assertIsNone(nc.datadir_source(path), path)


class AppTests(unittest.TestCase):
    def test_info_xml_and_versions(self):
        info = nc.parse_info_xml(INFO_RD)
        self.assertEqual((info['id'], info['version'], info['php']), ('richdocuments', '9.0.3', ('8.1', '8.4')))
        self.assertFalse(nc.parse_info_xml(b'<!DOCTYPE x [<!ENTITY a "b">]><info/>')['info_ok'])
        self.assertTrue(nc._fits('35.0.1', '30', '35'))
        self.assertFalse(nc._fits('35.0.1', '36', ''))
        self.assertFalse(nc._fits('8.5.11', '8.1', '8.4'))
        self.assertTrue(nc._fits('8.5.11', '8.1', '8.5'))
        warnings = nc.app_warnings({'richdocuments': {**info, 'foreign': []}, 'notes': {**nc.parse_info_xml(INFO_NOTES),
                                                                                       'foreign': ['bin/arm']}},
                                   nc_version_text='35.0.1.1', php_version='8.5.11')
        self.assertTrue(any('richdocuments' in w and 'PHP 8.5.11' in w for w in warnings))
        self.assertTrue(any('notes' in w and '其他處理器' in w for w in warnings))


class DataDirTests(unittest.TestCase):
    def walk(self, data, **kwargs):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = nc.DirTar(Path(tmp.name) / 'd.tar')
        out.add('.', 'dir', mode=0o770, uid=33, gid=33, mtime=0)
        try:
            found = nc.scan_datadir(io.BytesIO(gzip.decompress(data)), habackup.Report(), 'nextcloud', addon=False,
                                    instanceid='ochaabcdef12', out=out, ids=(33, 33), **kwargs)
        finally:
            out.close()
        return found, members(out.path.read_bytes())

    def test_writes_the_data_directory_without_updater_and_cached_discovery(self):
        found, tar = self.walk(share_tar())
        self.assertTrue((found.present, found.ncdata, found.encryption) == (True, True, False))
        self.assertEqual(found.users, {'admin'})
        self.assertIn('./admin/files/中文.txt', tar)
        self.assertEqual(tar['./admin/files/hello.txt'][1], b'hello from HA')
        self.assertEqual((tar['./admin/files/hello.txt'][0].uid, tar['.'][0].mode), (33, 0o770))
        self.assertIn('./appdata_ochaabcdef12/preview/1.png', tar)
        self.assertFalse([n for n in tar if 'updater-' in n or 'remoteData' in n or 'woowtechbot' in n])
        self.assertEqual(found.skipped_files, 2)

    def test_encryption_symlinks_and_missing_marker(self):
        found, _tar = self.walk(share_tar(ncdata=False, extra=[
            {'name': 'nextcloud/admin/files_encryption/keys', 'data': b'k'},
            {'name': 'nextcloud/admin/files/link', 'type': 'symlink', 'linkname': 'hello.txt'}]))
        self.assertEqual((found.ncdata, found.encryption, found.symlinks), (False, True, 1))

    def test_hard_link_to_a_skipped_file_stops(self):
        with self.assertRaises(BackupError):
            self.walk(share_tar(extra=[{'name': 'nextcloud/admin/files/again', 'type': 'hardlink',
                                        'linkname': 'nextcloud/updater-ochaabcdef12/backups/old.zip'}]))


# ====================================================================== whole jobs

class CheckTests(NextcloudCase):
    def test_a_backup_with_the_share_folder(self):
        result = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
        self.assertEqual((result['ok'], result['blockers'], result['target_version']), (True, [], '35.0.1.1'))
        section = result['nextcloud']
        self.assertEqual((section['users'], section['files'], section['datadir'], section['datadir_in_backup'],
                          section['custom_apps'], section['office']),
                         (3, 300, '/share/nextcloud', True, ['notes', 'richdocuments'], True))
        self.assertEqual((section['ha_url'], section['target_url']),
                         ('https://woowtech-nextcloud.woowtech.io', 'http://127.0.0.1:18081'))
        warnings = '\n'.join(result['warnings'])
        self.assertIn('gone_app', warnings)
        self.assertIn('PHP 8.5.11', warnings)
        self.assertIn('theme', warnings)
        pg = self.world.imported['hapg']
        names = members(pg)
        self.assertEqual(names['postgresql.conf'][1], nc.ha_odoo.PG_CONF)
        self.assertEqual(names['PG_VERSION'][0].uid, 999)

    def test_without_the_share_folder_it_is_refused(self):
        result = self.check(self.upload_nextcloud(share=None), ['nextcloud'])[0]
        self.assertFalse(result['ok'])
        self.assertIn('沒有包含 share 資料夾', result['blockers'][0])
        self.assertIn('/share/nextcloud', result['blockers'][0])

    def test_a_share_folder_without_the_data_directory_is_refused(self):
        empty = gzip.compress(hx.tar_bytes([{'name': 'other', 'type': 'dir'}]), mtime=0)
        result = self.check(self.upload_nextcloud(share=empty), ['nextcloud'])[0]
        self.assertIn('找不到 Nextcloud 的使用者檔案資料夾', result['blockers'][0])

    def test_other_blockers(self):
        self.world.ha_details = dict(self.world.ha_details, encryption='yes', extensions=['plpgsql', 'pg_trgm'])
        result = self.check(self.upload_nextcloud(config=HA_CONFIG.replace(b"'35.0.1.1'", b"'35.0.3.1'")),
                            ['nextcloud'])[0]
        text = '\n'.join(result['blockers'])
        for part in ('版本不同', '伺服器端加密', 'pg_trgm'):
            self.assertIn(part, text)

    def test_unreadable_config_and_wrong_postgres(self):
        result = self.check(self.upload_nextcloud(config=b"<?php $CONFIG = array('a' => getenv('X'));"),
                            ['nextcloud'])[0]
        self.assertIn('無法解讀', result['blockers'][0])
        result = self.check(self.upload_nextcloud(pg_version=b'17\n'), ['nextcloud'])[0]
        self.assertTrue(any('只支援 16 版' in b for b in result['blockers']))
        self.assertFalse(self.runs('hapg')[1:], 'the PostgreSQL 17 cluster is never started')

    def test_a_database_with_objects_nextcloud_never_creates_is_refused_unread(self):
        # A trigger function, a trojan aggregate in public and a default that reads a server file: refused from the
        # catalogs alone; none of HA's tables is read (no view or function of HA's runs, even in the throwaway cluster).
        self.world.shape['hapg'] = dict(CLEAN_SHAPE, functions=2, triggers=1,
                                        defaults=CLEAN_SHAPE['defaults'] + ["pg_read_file('/etc/passwd'::text)"])
        result = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
        self.assertFalse(result['ok'])
        self.assertEqual(len(result['blockers']), 1, result['blockers'])
        for part in ('Nextcloud 不會建立的資料庫物件', '函式', '觸發程序', '不是固定值的欄位預設值', '無法安全地搬過來'):
            self.assertIn(part, result['blockers'][0])
        ha = [x for x in self.world.sessions if x['role'] == 'hapg' and x['tool'] == 'psql']
        self.assertTrue(ha and all(x['env'].get('PGOPTIONS') == '-c search_path=pg_catalog' for x in ha))
        self.assertFalse([x for x in ha if 'public.oc_' in x['sql']], 'no table of HA is read')

    def test_an_unreadable_database_shape_is_refused(self):
        for shape in (None, dict(CLEAN_SHAPE, triggers='1'), {k: v for k, v in CLEAN_SHAPE.items() if k != 'rules'}):
            self.world.shape['hapg'] = shape
            result = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
            self.assertEqual(result['blockers'], [nc.MSG_SHAPE_UNREAD], shape)


class ConvertTests(NextcloudCase):
    def test_conversion_builds_the_four_folders(self):
        result = self.convert(self.upload_nextcloud(), ['nextcloud'])
        self.assertEqual(set(self.world.dirs), set(DIRS))
        html = members(self.world.dirs[DIRS[2]])
        merged = nc.parse_config(html['./config/config.php'][1])
        self.assertEqual((merged['instanceid'], merged['dbpassword'], merged['overwrite.cli.url']),
                         ('ochaabcdef12', 'live-db-password-0001', 'http://127.0.0.1:18081'))
        self.assertEqual((html['./config/config.php'][0].mode, html['./config/config.php'][0].uid), (0o640, 33))
        self.assertEqual(html['./custom_apps/richdocuments/appinfo/info.xml'][1], INFO_RD)
        self.assertIn('./custom_apps/liveonly', html)
        self.assertIn('./custom_apps/notes/lib/Notes.php', html)
        self.assertIn('./config/redis.config.php', html)
        self.assertEqual(self.world.php, [html['./config/config.php'][1]])
        # A new data fingerprint, as the package's restore sets with occ maintenance:data-fingerprint.
        self.assertRegex(merged['data-fingerprint'], r'\A[0-9a-f]{32}\Z')
        self.assertNotIn(merged['data-fingerprint'], ('00000000000000000000000000000001', '0000000000000000000000000000000a'))
        data = members(self.world.dirs[DIRS[3]])
        self.assertEqual((data['.'][0].uid, data['.'][0].mode), (33, 0o770))
        self.assertEqual(data['./admin/files/hello.txt'][1], b'hello from HA')
        pg = members(self.world.dirs[DIRS[0]])
        self.assertEqual(((pg['.'][0].uid, pg['.'][0].gid, pg['.'][0].mode), pg['./PG_VERSION'][1]),
                         ((999, 0, 0o700), b'16\n'))
        self.assertEqual(list(members(self.world.dirs[DIRS[1]])), ['.'])
        scripts = [s for db, s, _tx in self.world.psql['nc-db'].executed]
        joined = '\n'.join(scripts)
        self.assertIn('CREATE ROLE "oc_admin" LOGIN NOSUPERUSER CREATEDB', joined)
        self.assertIn('REVOKE ALL PRIVILEGES ON DATABASE "nextcloud" FROM PUBLIC', joined)
        self.assertIn('GRANT CREATE ON SCHEMA public TO "oc_admin"', joined)
        self.assertIn('CREATE EXTENSION IF NOT EXISTS "vector"', joined)
        self.assertIn("UPDATE public.oc_storages SET id = 'local::/var/www/html/data/' WHERE id = "
                      "'local::/share/nextcloud/'", joined)
        self.assertIn('http://nextcloud-office:9980', joined)
        self.assertIn("appdata_ochaabcdef12/richdocuments/remoteData", joined)
        restore = [c for r, c, _d in self.world.execs if r == 'nc-db' and c[:1] == ['pg_restore'] and '-U' in c]
        self.assertEqual(restore[0][:3], ['pg_restore', '-U', 'oc_admin'])
        self.assert_sessions_pinned()
        row = result['ha_import']
        self.assertTrue(any('Collabora' in line for line in row['notes']))
        reminders = '\n'.join(row['reminders_by_app']['nextcloud'])
        for part in ('永久停用', 'http://127.0.0.1:18081', 'SMTP', 'Woow Nextcloud MCP Server'):
            self.assertIn(part, reminders)

    def assert_sessions_pinned(self):
        """HA's cluster: every session pinned. The new cluster: the setup before HA's dump runs as its superuser
        unpinned (CREATE EXTENSION needs the default search path); from the restore on every session is pinned, the
        superuser reads catalogs only and every statement on HA's tables runs as the live Nextcloud role."""
        sessions = self.world.sessions
        ha = [x for x in sessions if x['role'] == 'hapg' and x['tool'] in ('psql', 'pg_dump')]
        self.assertTrue(ha)
        self.assertTrue(all(x['env'].get('PGOPTIONS') == '-c search_path=pg_catalog' for x in ha), ha)
        new = [x for x in sessions if x['role'] == 'nc-db' and x['tool'] in ('psql', 'pg_restore')]
        start = next(i for i, x in enumerate(new) if x['tool'] == 'pg_restore' and x['pg_user'] == 'oc_admin')
        self.assertTrue(all('PGOPTIONS' not in x['env'] for x in new[:start]), new[:start])
        after = [x for x in new[start + 1:] if x['tool'] == 'psql']
        self.assertTrue(after and all(x['env'].get('PGOPTIONS') == '-c search_path=pg_catalog' for x in after), after)
        for x in after:
            touches = 'public.oc_' in x['sql']
            self.assertEqual(x['pg_user'], 'oc_admin' if touches else 'nextcloud', x['sql'][:120])
        owner = '\n'.join(x['sql'] for x in after if x['pg_user'] == 'oc_admin')
        for part in ('UPDATE public.oc_storages', 'DELETE FROM public.oc_appconfig', 'INSERT INTO public.oc_appconfig',
                     'DELETE FROM public.oc_filecache', "'counts'"):
            self.assertIn(part, owner)

    def test_a_failed_verification_stops_the_conversion(self):
        self.world.verify = {'counts': HA_COUNTS, 'root': 0, 'old': 1, 'appconfig': []}
        self.world.catalog = {'owners': ['nextcloud'], 'verifier_md5': 'x'}
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(), ['nextcloud'])
        self.assertIn('檢查沒有通過', caught.exception.message)
        self.assertIn('密碼設定和這台的不同', caught.exception.message)

    def test_a_dump_with_kinds_nextcloud_never_creates_is_refused_before_the_restore(self):
        for toc, kinds in (
                (b'201; 1259 16390 TABLE public oc_users nextcloud\n'
                 b'202; 1255 16400 FUNCTION public woow_t() nextcloud\n'
                 b'203; 2620 16401 TRIGGER public oc_storages woow_t nextcloud\n', ('FUNCTION', 'TRIGGER')),
                (b'201; 1259 16390 TABLE public oc_users nextcloud\n'
                 b'204; 1259 16402 VIEW public oc_storages2 nextcloud\n', ('VIEW',)),
                (b'205; 2617 16403 OPERATOR public = nextcloud\n', ('OPERATOR',)),
                (b'206; 0 0 WHATEVER public x nextcloud\n', ('UNKNOWN WHATEVER',))):
            with self.subTest(kinds=kinds):
                self.world.toc = b';\n; Archive\n' + toc
                seen = len(self.world.execs)
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_nextcloud(), ['nextcloud'])
                self.assertEqual(caught.exception.code, 'incompatible')
                self.assertIn('Nextcloud 不會建立的物件', caught.exception.message)
                for kind in kinds:
                    self.assertIn(kind, caught.exception.message)
                restores = [c for r, c, _d in self.world.execs[seen:]
                            if r == 'nc-db' and c[:1] == ['pg_restore'] and '-U' in c]
                self.assertEqual(restores, [], 'nothing of HA is restored')

    def test_objects_found_after_the_restore_stop_before_any_fix_up(self):
        self.world.shape['nc-db'] = dict(CLEAN_SHAPE, triggers=1)
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(), ['nextcloud'])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('觸發程序', caught.exception.message)
        sql = '\n'.join(x['sql'] for x in self.world.sessions if x['role'] == 'nc-db')
        self.assertNotIn('UPDATE public.oc_storages', sql)
        self.assertNotIn('public.oc_appconfig', sql)

    def test_a_role_or_database_setting_in_the_new_cluster_is_refused(self):
        self.world.shape['nc-db'] = dict(CLEAN_SHAPE, role_settings=1)
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(), ['nextcloud'])
        self.assertIn('角色或資料庫層級的設定', caught.exception.message)

    def test_a_role_that_gained_rights_fails_the_verification(self):
        good = {'owners': ['oc_admin'], 'verifier_md5': hashlib.md5(VERIFIER.encode()).hexdigest(),
                'role': {k: v for k, v in LIVE_DB['role'].items() if k != 'password'}, 'role_settings': 0,
                **{key: LIVE_DB[key] for key in ('roles', 'extensions', 'datacl', 'nspacl')}}
        for change, text in (({'role': dict(good['role'], super=True)}, 'oc_admin 角色的權限和這台的不同'),
                             ({'role': dict(good['role'], createrole=True)}, 'oc_admin 角色的權限和這台的不同'),
                             ({'role': None}, 'oc_admin 角色的權限和這台的不同'),
                             ({'role_settings': 1}, '出現了角色或資料庫層級的設定')):
            with self.subTest(change=change):
                self.world.catalog = dict(good, **change)
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_nextcloud(), ['nextcloud'])
                self.assertEqual(caught.exception.code, 'job-failed')
                self.assertIn(text, caught.exception.message)

    def test_no_share_is_refused_before_anything_is_built(self):
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(share=None), ['nextcloud'])
        self.assertIn('沒有包含 share 資料夾', caught.exception.message)
        self.assertFalse(self.runs('nc-db') or self.runs('hapg'), 'no cluster is started')


class ShapeTests(unittest.TestCase):
    def test_toc_kinds(self):
        text = ('; Archive created at 2026-11-24\n;\n'
                '201; 1259 16390 TABLE public oc_users oc_admin\n'
                '202; 0 16390 TABLE DATA public oc_users oc_admin\n'
                '203; 1259 16391 SEQUENCE public oc_users_id_seq oc_admin\n'
                '204; 0 0 SEQUENCE OWNED BY public oc_users_id_seq oc_admin\n'
                '205; 0 0 SEQUENCE SET public oc_users_id_seq oc_admin\n'
                '206; 2604 16392 DEFAULT public oc_users id oc_admin\n'
                '207; 2606 16393 CONSTRAINT public oc_users oc_users_pkey oc_admin\n'
                '208; 2606 16394 FK CONSTRAINT public oc_x oc_x_fk oc_admin\n'
                '209; 1259 16395 INDEX public oc_users_uid oc_admin\n'
                '210; 0 0 ACL - SCHEMA public pg_database_owner\n'
                '211; 1255 16396 FUNCTION public f() oc_admin\n'
                '212; 1255 16397 AGGREGATE public json_agg(name) oc_admin\n'
                '213; 2618 16398 RULE public oc_users r oc_admin\n'
                '214; 0 0 COMMENT public COLUMN oc_users.uid oc_admin\n'
                '215; 1259 16399 MATERIALIZED VIEW public mv oc_admin\n')
        self.assertEqual(nc.toc_kinds(text), ['TABLE', 'TABLE DATA', 'SEQUENCE', 'SEQUENCE OWNED BY', 'SEQUENCE SET',
                                              'DEFAULT', 'CONSTRAINT', 'FK CONSTRAINT', 'INDEX', 'ACL', 'FUNCTION',
                                              'AGGREGATE', 'RULE', 'COMMENT', 'MATERIALIZED VIEW'])
        self.assertEqual([k for k in nc.toc_kinds(text) if k not in nc.TOC_ALLOWED],
                         ['FUNCTION', 'AGGREGATE', 'RULE', 'MATERIALIZED VIEW'])

    def test_defaults_nextcloud_writes_and_others(self):
        # dev-e's Nextcloud 35.0.1 (2026-11-24, pg_get_expr with search_path=pg_catalog).
        for text in CLEAN_SHAPE['defaults'] + ["'0'::character varying", "'[]'::text", '2', '9', 'true',
                                               "'1.0'::character varying", "nextval('oc_x_seq'::regclass)",
                                               "'{}'::text[]", "'it''s'::text"]:
            self.assertTrue(nc.DEFAULT_RE.fullmatch(text), text)
        for text in ("pg_read_file('/etc/passwd'::text)", "'a'::text || pg_read_file('x')", 'now()',
                     "lo_export(1, '/tmp/x')", "nextval('oc_x_seq'::regclass) + public.f()", 'CURRENT_TIMESTAMP',
                     "('x'::text)::regclass", "'x'::text; DROP TABLE y"):
            self.assertIsNone(nc.DEFAULT_RE.fullmatch(text), text)
        self.assertEqual(nc.shape_problems(CLEAN_SHAPE), [])
        self.assertEqual(nc.shape_problems(dict(CLEAN_SHAPE, role_settings=2)), [])
        self.assertEqual(nc.shape_problems(dict(CLEAN_SHAPE, role_settings=2), converted=True), ['角色或資料庫層級的設定'])
        self.assertEqual(nc.shape_problems(dict(CLEAN_SHAPE, relations=1, defaults=['now()'])),
                         ['檢視表或其他特殊資料表', '不是固定值的欄位預設值'])
        for bad in (None, [], dict(CLEAN_SHAPE, defaults=None), dict(CLEAN_SHAPE, checks=True),
                    dict(CLEAN_SHAPE, others=-1)):
            self.assertIsNone(nc.shape_problems(bad), bad)


class TargetTests(unittest.TestCase):
    def test_shape_checks(self):
        app = fk.app('nextcloud', 'Nextcloud', data_dirs=[{'path': p} for p in DIRS])
        live = nc.Live(QUADLETS, '/home/appowner', app)
        self.assertEqual((live.db_container, live.db_user, live.db_name, live.rels['data']),
                         ('nextcloud-db', 'nextcloud', 'nextcloud', DIRS[3]))
        with self.assertRaises(BackupError):
            nc.Live(QUADLETS, '/home/appowner', fk.app('nextcloud', 'Nextcloud', data_dirs=[{'path': DIRS[0]}]))
        odd = dict(QUADLETS, **{'nextcloud-app.container': QUADLETS['nextcloud-app.container'] + b'UserNS=keep-id\n'})
        with self.assertRaises(BackupError):
            nc.Live(odd, '/home/appowner', app)

    def test_registry(self):
        self.assertEqual(haimport.APPS['nextcloud'], 'woow-nextcloud-office')
        lines = haimport.mcp_lines(nc_importer())
        self.assertTrue(any('Woow Nextcloud MCP Server' in line for line in lines))


def nc_importer():
    from woowbackup import haapps
    return haapps.get('nextcloud')


if __name__ == '__main__':
    unittest.main()
