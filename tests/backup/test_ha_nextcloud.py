"""HA import, Nextcloud part (ha_nextcloud.py): HA's PostgreSQL database, config.php identity, custom apps and the
user files of the share folder move; the target keeps its URLs, database credentials, Office (Collabora) settings and
secrets; a backup without the share folder is refused (CONTRACT section 9 "Batch 2: Nextcloud"). Team E2."""
import gzip
import hashlib
import io
import json
import re
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import ha_nextcloud as nc
from woowbackup import habackup, haimport, haissues, jobs
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
  'trusted_domains' => array (0 => 'nextcloud.example.com', 1 => 'localhost'),
  'datadirectory' => '/share/nextcloud',
  'dbtype' => 'pgsql',
  'version' => '35.0.1.1',
  'overwrite.cli.url' => 'https://nextcloud.example.com',
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
           'available': ['btree_gin', 'pg_trgm', 'plpgsql', 'uuid-ossp', 'vector'],
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
TABLES = ['oc_appconfig', 'oc_authtoken', 'oc_calendarobjects', 'oc_cards', 'oc_filecache', 'oc_jobs', 'oc_mimetypes',
          'oc_mounts', 'oc_share', 'oc_storages', 'oc_users']
# This device's Office cache (richdocuments reads Collabora's answers only from there).
OFFICE_CACHE = {'discovery': b'<wopi-discovery>this device</wopi-discovery>', 'capabilities': b'{"productName": "here"}'}


def toc_of(*lines):
    """A `pg_restore -l` listing of these entry lines with the header's `TOC Entries:` that fits them."""
    text = ''.join(f'{line}\n' for line in lines)
    entries = len([line for line in lines if re.match(r'\d+; ', line)])
    return f';\n; Archive created at 2026-11-24\n;     TOC Entries: {entries + 3}\n;\n'.encode() + text.encode()


def issue_of(row, issue_id):
    """The issue `issue_id` of one app's check result (a row of HaCheck), or None."""
    return next((issue for issue in row['issues'] if issue['id'] == issue_id), None)


def ack(row, *issue_ids):
    """`acknowledged` for the conversion: the keys of these lines of the check result."""
    return {'nextcloud': [issue_of(row, issue_id)['key'] for issue_id in issue_ids]}


def lists(*files):
    """FILES_SQL's answer for (user, path, size) rows: the digest as PostgreSQL gives it (a signed bigint)."""
    data = nc.DataDir()
    for user, path, size in files:
        data.listed(user, path, size)
    return [[user, n, size, digest - 2 ** 64 if digest >= 2 ** 63 else digest]
            for user, (n, size, digest) in sorted(data.lists.items())]


# What share_tar() holds below `<user>/files`.
HA_LISTS = lists(('admin', 'files/hello.txt', 13), ('admin', 'files/中文.txt', 6))


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


def strings(value):
    """Every text of a JSON value."""
    if isinstance(value, dict):
        return [text for key, item in value.items() for text in [key] + strings(item)]
    if isinstance(value, list):
        return [text for item in value for text in strings(item)]
    return [value] if isinstance(value, str) else []


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
        self.objects = {'functions': [], 'triggers': []}
        self.lists = HA_LISTS
        self.tables = TABLES
        self.office_cache = dict(OFFICE_CACHE)
        self.toc = toc_of('201; 1259 16390 TABLE public oc_users nextcloud')
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
        if role == 'nextcloud-app' and command[:2] == ['sh', '-c']:
            folder, _sep, name = command[-1].rpartition('/')
            assert folder == '/var/www/html/data/appdata_oclive123456/richdocuments/remoteData', command
            return Result(0, self.office_cache.get(name, b''), b'')
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
            return self.tables
        if sql == nc.HA_SQL:
            return self.ha_details
        if sql == nc.SHAPE_SQL:
            return self.shape.get(role)
        if sql == nc.OBJECTS_SQL:
            return self.objects
        if sql == nc.FILES_SQL:
            return self.lists
        if sql.startswith("SELECT json_build_object('users'"):
            return HA_COUNTS
        if sql.startswith("SELECT json_build_object(\n 'role'"):
            return LIVE_DB
        if sql.startswith('SELECT count(*) FROM public.oc_filecache'):
            return 2
        if sql.startswith("SELECT json_build_object(\n 'counts'"):
            moved = re.search(r"'moved', \(SELECT count\(\*\) FROM public\.oc_storages WHERE id IN \((.*)\)\),", sql).group(1)
            return self.verify if self.verify is not None else {
                'counts': {**HA_COUNTS, 'files': 298}, 'root': 1, 'moved': moved.count("'") // 2, 'old': 0,
                'appconfig': LIVE_DB['appconfig']}
        if sql.startswith("SELECT json_build_object(\n 'owners'"):
            return self.catalog if self.catalog is not None else {
                'owners': ['oc_admin'], 'verifier_md5': hashlib.md5(VERIFIER.encode()).hexdigest(),
                'role': {k: v for k, v in LIVE_DB['role'].items() if k != 'password'}, 'role_settings': 0,
                'grants': 0, 'databases': ['nextcloud', 'postgres', 'template0', 'template1'],
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
        self.assertEqual((ha['trusted_domains'], ha['ratio']), ({0: 'nextcloud.example.com', 1: 'localhost'},
                                                                nc.Float('1.5')))
        self.assertEqual(nc.parse_config(nc.render_config(ha)), ha)
        self.assertEqual(nc.jsonable(ha)['trusted_domains'], ['nextcloud.example.com', 'localhost'])
        self.assertEqual(nc.parse_config(b"<?php\n$CONFIG = ['a' => \"x\" ];\n".replace(b'"x"', b"'it\\'s'")),
                         {'a': "it's"})

    def test_refuses_anything_that_is_not_data(self):
        for text in (b"<?php $CONFIG = array('a' => \"$x\");", b"<?php $CONFIG = array('a' => getenv('X'));",
                     b"<?php $CONFIG = array(); $CONFIG = array();",
                     b"<?php $CONFIG = array('a' => 1, 'a' => 2);", b"$CONFIG = array();", b"<?php $X = array();",
                     b"<?php system('id'); $CONFIG = array();", b"<?php $CONFIG = array('a' => FOO_CONSTANT);",
                     b"<?php $CONFIG = array('a' => \\OCP\\ILogger::WARN);", b"<?php $CONFIG = array('a' => 'x' . getenv('Y'));",
                     b"<?php $CONFIG = array('a' => 'x' . 1);", b"<?php $CONFIG = array('a' => 1 . 'x');",
                     b"<?php $CONFIG = array('a' => \"{$x}\");", b"<?php $CONFIG = array('a' => \"${x}\");",
                     b"<?php $CONFIG = array('a' => \"{\\$x}\");", b"<?php $CONFIG = array('a' => \"\\x41\");",
                     b"<?php $CONFIG = array('a' => \"\\u{41}\");", b"<?php $CONFIG = array('a' => \"\\101\");",
                     b"<?php $CONFIG = array('a' => <<<EOT\nx\nEOT\n);", b"<?php $CONFIG = 'x';", b'\xff\xfe'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                nc.parse_config(text)

    def test_other_ways_to_write_a_value_are_still_values(self):
        # NC-12: a hand-edited config.php writes a text in double quotes, joins two with a dot or names a constant. Still
        # only values: the file is never run, so nothing that needs running is accepted (the test above).
        text = (b"<?php\n$CONFIG = array (\n  'a' => \"plain text\",\n  \"b\" => 'it\\'s' . \" more\\n\" . 'x',\n"
                b"  'c' => PHP_EOL,\n  'd' => DIRECTORY_SEPARATOR . 'tmp',\n  'e' => array(0 => \"a\\\\b\", 1 => \"q\\\"q\\$\"),\n"
                b"  'f' => PHP_INT_MAX,\n  'g' => E_ALL,\n  'h' => \"\",\n);\n")
        config = nc.parse_config(text)
        self.assertEqual(config, {'a': 'plain text', 'b': "it's more\nx", 'c': '\n', 'd': '/tmp',
                                  'e': {0: 'a\\b', 1: 'q"q$'}, 'f': 2 ** 63 - 1, 'g': 32767, 'h': ''})
        self.assertEqual(nc.parse_config(nc.render_config(config)), config, 'written back the way Nextcloud writes it')

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

    def test_the_two_factor_keys_are_one_policy(self):
        # lib/private/Authentication/TwoFactorAuth/MandatoryTwoFactor.php: only the string 'true' enforces; a list of
        # groups narrows it, an excluded group too. The groups belong to the users the policy came with.
        live, ha = nc.parse_config(LIVE_CONFIG), nc.parse_config(HA_CONFIG)
        ha.pop('twofactor_enforced')
        everyone = {'twofactor_enforced': 'true', 'twofactor_enforced_groups': {}, 'twofactor_enforced_excluded_groups': {}}
        some = {'twofactor_enforced': 'true', 'twofactor_enforced_groups': {0: 'staff'}}
        other = {'twofactor_enforced': 'true', 'twofactor_enforced_groups': {0: 'family'},
                 'twofactor_enforced_excluded_groups': {0: 'guests'}}
        excluded = {'twofactor_enforced': 'true', 'twofactor_enforced_excluded_groups': {0: 'guests'}}
        off = {'twofactor_enforced': 'false', 'twofactor_enforced_groups': {0: 'x'}}
        boolean = {'twofactor_enforced': True}  # not the string 'true': Nextcloud does not enforce it
        for of_ha, of_live, kept in (({}, {}, {}), ({}, some, some), (some, {}, some), (some, other, some),
                                     (everyone, some, everyone), (some, everyone, everyone), (excluded, everyone, everyone),
                                     (off, some, some), (off, {}, off), (off, off, off), (boolean, some, some),
                                     (boolean, everyone, everyone), (some, off, some), (some, boolean, some),
                                     ({'twofactor_enforced': 'true'}, other, {'twofactor_enforced': 'true'})):
            with self.subTest(ha=of_ha, live=of_live):
                merged, carried, _ = nc.merge_config({**ha, **of_ha}, {**live, **of_live})
                self.assertEqual({k: merged[k] for k in nc.TWOFACTOR if k in merged}, kept)
                self.assertEqual(carried, [k for k in nc.TWOFACTOR if k in of_ha] if kept == of_ha and of_ha else [])
        merged, carried, _ = nc.merge_config(dict(ha, app_install_overwrite={0: 'notes'}), {**live, **some})
        self.assertEqual((merged['app_install_overwrite'], carried, merged['twofactor_enforced_groups']),
                         ({0: 'notes'}, ['app_install_overwrite'], {0: 'staff'}))

    def issues(self, ha, live=None, image='35.0.1', **kwargs):
        sink = haissues.Sink('nextcloud')
        nc.config_issues(sink, ha, live or nc.parse_config(LIVE_CONFIG), image, **kwargs)
        return [(issue.id, issue.level) for issue in sink.found]

    def test_the_issues_of_the_two_config_files(self):
        live, ha = nc.parse_config(LIVE_CONFIG), nc.parse_config(HA_CONFIG)
        self.assertEqual(self.issues(ha), [])
        cases = ((dict(ha, version='35.0.3.1'), 'nextcloud.version-different'),
                 (dict(ha, installed=False), 'nextcloud.not-installed'), (dict(ha, dbtype='mysql'), 'nextcloud.not-postgres'),
                 (dict(ha, dbtableprefix='nc_'), 'nextcloud.table-prefix'),
                 (dict(ha, objectstore={'class': 'S3'}), 'nextcloud.object-storage'),
                 ({k: v for k, v in ha.items() if k != 'secret'}, 'nextcloud.no-identity'),
                 (dict(ha, dbname='Bad Name'), 'nextcloud.no-dbname'))
        for config, issue_id in cases:
            with self.subTest(issue=issue_id):
                self.assertIn((issue_id, 'stop'), self.issues(config))
        self.assertEqual(self.issues(ha, image='35.0.3'), [('nextcloud.image-version', 'stop')])
        self.assertEqual(self.issues(ha, live=dict(live, installed=False)), [('nextcloud.live-not-installed', 'stop')])
        self.assertEqual(self.issues(None, found=True), [('nextcloud.config-unreadable', 'stop')])
        self.assertEqual(self.issues(None, found=False), [('nextcloud.config-missing', 'stop')])

    def test_maintenance_mode_is_a_reminder_unless_an_upgrade_may_have_been_half_done(self):
        # NC-14: the same version on both sides: maintenance was only forgotten; the version of this device's config.php
        # (maintenance false) is what the merged file keeps.
        live, ha = nc.parse_config(LIVE_CONFIG), nc.parse_config(HA_CONFIG)
        self.assertEqual(self.issues(dict(ha, maintenance=True)), [('nextcloud.maintenance-mode', 'notice')])
        merged, _carried, _skipped = nc.merge_config(dict(ha, maintenance=True), live)
        self.assertEqual(merged['maintenance'], False)
        self.assertEqual(self.issues(dict(ha, maintenance=True, version='35.0.3.1')),
                         [('nextcloud.version-different', 'stop'), ('nextcloud.maintenance-upgrading', 'stop')])
        self.assertEqual(self.issues(dict(ha, maintenance=False)), [])

    def test_an_unreadable_version_of_ha_is_taken_from_the_add_on(self):
        # NC-20: the add-on 0.2.3 ships Nextcloud 35.0.1 (VERSIONS): the same as this device's; unknown or another one is
        # said or stops as every version issue does (haissues.version_issues).
        ha = {k: v for k, v in nc.parse_config(HA_CONFIG).items() if k != 'version'}
        self.assertEqual(self.issues(ha, addon_version='0.2.3'), [('nextcloud.version-unreadable', 'notice')])
        self.assertEqual(self.issues(dict(ha, version='not a version'), addon_version='0.2.3'),
                         [('nextcloud.version-unreadable', 'notice')])
        self.assertEqual(self.issues(ha, addon_version='0.9.9'),
                         [('nextcloud.version-unreadable', 'notice'), ('version.addon-unknown', 'notice')])
        self.assertEqual(self.issues(ha, addon_version=None),
                         [('nextcloud.version-unreadable', 'notice'), ('version.addon-unknown', 'notice')])
        self.assertEqual(self.issues(ha, addon_version='0.2.1'),
                         [('nextcloud.version-unreadable', 'notice'), ('version.different', 'stop')])
        self.assertEqual(self.issues(dict(ha, maintenance=True), addon_version='0.2.3'),
                         [('nextcloud.version-unreadable', 'notice'), ('nextcloud.maintenance-mode', 'notice')])
        self.assertEqual(self.issues(dict(ha, maintenance=True), addon_version='0.9.9'),
                         [('nextcloud.version-unreadable', 'notice'), ('version.addon-unknown', 'notice'),
                          ('nextcloud.maintenance-upgrading', 'stop')])

    def test_storage_id_and_datadir_location(self):
        self.assertEqual(nc.storage_id('/share/nextcloud'), 'local::/share/nextcloud/')
        self.assertEqual(nc.storage_id('/var/www/html//data/'), 'local::/var/www/html/data/')
        long = '/share/' + 'x' * 70
        self.assertRegex(nc.storage_id(long), r'\A[0-9a-f]{32}\Z')
        fits = '/share/' + 'x' * 49  # 64 bytes is still stored as it is (Cache/Storage.php adjustStorageId: > 64)
        self.assertEqual((nc.storage_id(fits), len(nc.storage_id(fits))), (f'local::{fits}/', 64))
        self.assertEqual(nc.storage_id(fits + 'x'), hashlib.md5(f'local::{fits}x/'.encode()).hexdigest())
        self.assertEqual(nc.datadir_source('/share/nextcloud'), ('share', 'nextcloud'))
        self.assertEqual(nc.datadir_source('/share/nc/data/'), ('share', 'nc/data'))
        self.assertEqual(nc.datadir_source('/data/userfiles'), ('addon', 'data/userfiles'))
        self.assertEqual(nc.datadir_source('/data/nextcloud/data'), ('addon', 'data/nextcloud/data'))
        for path in ('/media/nc', '/mnt/nas', '/data/postgres', '/data/nextcloud', '/data', '/share',
                     '/share/../etc', 'share/nextcloud', None):
            self.assertIsNone(nc.datadir_source(path), path)

    def test_the_storages_below_the_data_directory_move_with_it(self):
        # The Team folders app (groupfolders 23) keeps one local storage per folder below the data directory and names it
        # by its number: a row left on HA's path would be another storage here (new file numbers).
        root = ('local::/share/nextcloud/', 'local::/var/www/html/data/')
        ids = ['local::/share/nextcloud/', 'local::/share/nextcloud/__groupfolders/1/',
               'local::/share/nextcloud/__groupfolders/12/', 'local::/share/nextcloud2/', 'local::/share/media/']
        self.assertEqual(nc.storage_moves('/share/nextcloud', '/var/www/html/data', ids), [
            root, ('local::/share/nextcloud/__groupfolders/1/', 'local::/var/www/html/data/__groupfolders/1/'),
            ('local::/share/nextcloud/__groupfolders/12/', 'local::/var/www/html/data/__groupfolders/12/')])
        self.assertEqual(nc.storage_moves('/share//nextcloud/', '/var/www/html/data/', ids[:1]), [root])
        self.assertEqual(nc.storage_moves('/share/nextcloud', '/var/www/html/data', [], ['1']), [root])
        self.assertEqual(nc.storage_moves('/var/www/html/data', '/var/www/html/data',
                                          ['local::/var/www/html/data/', 'local::/var/www/html/data/__groupfolders/1/']), [])
        # Ids longer than 64 bytes are stored as their md5: recognised by the folder names of the backup.
        far = '/share/' + 'x' * 40
        stored = hashlib.md5(f'local::{far}/__groupfolders/7/'.encode()).hexdigest()
        self.assertEqual(nc.storage_moves(far, '/var/www/html/data', [f'local::{far}/', stored], ['7', '8', 'trash']), [
            (f'local::{far}/', 'local::/var/www/html/data/'), (stored, 'local::/var/www/html/data/__groupfolders/7/')])
        deep = 'local::/share/nextcloud/' + 'd' * 39 + '/'
        self.assertEqual(len(deep), 64)
        self.assertRegex(nc.storage_moves('/share/nextcloud', '/var/www/html/data', [deep])[1][1], r'\A[0-9a-f]{32}\Z')


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

    def test_only_the_web_updaters_own_folder_is_skipped(self):
        # Nextcloud refuses some user names (lib/private/User/Manager.php verifyUid) but not `updater-...`; the web
        # updater's folder is exactly `updater-<instanceid>` (BackgroundCleanupUpdaterBackupsJob.php).
        found, tar = self.walk(share_tar(extra=[
            {'name': 'nextcloud/updater-team/files/plan.txt', 'data': b'plan'},
            {'name': 'nextcloud/updater-ochaabcdef1/files/a.txt', 'data': b'a'}]))
        self.assertEqual(tar['./updater-team/files/plan.txt'][1], b'plan')
        self.assertIn('./updater-ochaabcdef1/files/a.txt', tar)
        self.assertFalse([n for n in tar if n.startswith('./updater-ochaabcdef12')])
        self.assertEqual((found.users, found.lists['updater-team'][:2], found.skipped_files),
                         ({'admin', 'updater-team', 'updater-ochaabcdef1'}, [1, 4], 2))

    def test_team_folders_and_links_far_down_are_seen(self):
        found, _tar = self.walk(share_tar(extra=[
            {'name': 'nextcloud/__groupfolders', 'type': 'dir'}, {'name': 'nextcloud/__groupfolders/1', 'type': 'dir'},
            {'name': 'nextcloud/__groupfolders/12/files/a.txt', 'data': b'a'},
            {'name': 'nextcloud/admin/__groupfolders/3/files', 'type': 'dir'}]))
        self.assertEqual((found.team_folders, found.users), ({'1', '12'}, {'admin'}))
        prefix = 'n/' * 110 + 'nextcloud'  # a sample of a refused link is cut at 200 characters
        entries = [{'name': prefix, 'type': 'dir'}, {'name': f'{prefix}/admin/files/link', 'type': 'symlink', 'linkname': 'x'}]
        found = nc.scan_datadir(io.BytesIO(hx.tar_bytes(entries)), habackup.Report(), prefix, addon=False)
        self.assertEqual((found.symlinks, len(found.symlink_samples)), (1, 1))

    def test_encryption_symlinks_and_missing_marker(self):
        found, _tar = self.walk(share_tar(ncdata=False, extra=[
            {'name': 'nextcloud/admin/files_encryption/keys', 'data': b'k'},
            {'name': 'nextcloud/admin/files/link', 'type': 'symlink', 'linkname': 'hello.txt'}]))
        self.assertEqual((found.ncdata, found.encryption, found.symlinks), (False, True, 1))

    def test_htaccess_at_the_top_is_not_copied_and_any_other_is_counted(self):
        # The data dir is inside Apache's web root here: HA's own .htaccess never moves, one further down could publish
        # the folder or run files as programs (the caller refuses it). The web updater's folder is skipped as a whole.
        found, tar = self.walk(share_tar(extra=[
            {'name': 'nextcloud/.htaccess', 'data': b'Require all granted\n'},
            {'name': 'nextcloud/updater-ochaabcdef12/backups/nc/.htaccess', 'data': b'Require all granted\n'}]))
        self.assertEqual((found.htaccess, found.htaccess_samples), (0, []))
        self.assertNotIn('./.htaccess', tar)
        found, tar = self.walk(share_tar(extra=[
            {'name': 'nextcloud/admin/files/site/.htaccess', 'data': b'Require all granted\n'},
            {'name': 'nextcloud/appdata_ochaabcdef12/.htaccess', 'data': b'x'},
            {'name': 'nextcloud/admin/files/.htaccess', 'type': 'dir'},
            {'name': 'nextcloud/admin/files/.htaccess/x', 'data': b'x'},
            {'name': 'nextcloud/admin/files/again/.htaccess', 'type': 'hardlink',
             'linkname': 'nextcloud/admin/files/hello.txt'}]))
        self.assertEqual((found.htaccess, found.htaccess_samples[0]), (5, 'admin/files/site/.htaccess'))
        self.assertFalse([n for n in tar if '.htaccess' in n])
        found, tar = self.walk(share_tar(extra=[{'name': 'nextcloud/.htaccess', 'type': 'dir'}]))
        self.assertEqual((found.htaccess, './.htaccess' in tar), (1, False))
        found, tar = self.walk(share_tar(extra=[{'name': 'nextcloud/admin/files/x.htaccess', 'data': b'x'},
                                                {'name': 'nextcloud/admin/files/.htaccess.bak', 'data': b'x'}]))
        self.assertEqual((found.htaccess, './admin/files/.htaccess.bak' in tar), (0, True))

    def test_the_users_file_lists(self):
        found, _tar = self.walk(share_tar(extra=[
            {'name': 'nextcloud/admin/files_versions/hello.txt.v1', 'data': b'old'},
            {'name': 'nextcloud/admin/cache/x', 'data': b'x'},
            {'name': 'nextcloud/appdata_ochaabcdef12/files/x', 'data': b'x'},
            {'name': 'nextcloud/__groupfolders/files/1', 'data': b'x'}]))
        self.assertEqual(nc.lists_differ(found, {'lists': HA_LISTS}), [])
        # The same numbers PostgreSQL gives: md5('<size>:<path>'), its first 16 digits as a (signed) bigint, XORed.
        digest = 0
        for text in ('13:files/hello.txt', '6:files/中文.txt'):
            digest ^= int(hashlib.md5(text.encode('utf-8')).hexdigest()[:16], 16)
        self.assertEqual(found.lists, {'admin': [2, 19, digest]})
        signs = set()
        for i in range(16):
            name = f'files/{i}'
            value = int.from_bytes(hashlib.md5(f'1:{name}'.encode('ascii')).digest()[:8], 'big', signed=True)
            signs.add(value < 0)
            data = nc.DataDir()
            data.listed('u', name, 1)
            self.assertEqual(nc.lists_differ(data, {'lists': [['u', 1, 1, value]]}), [], name)
            self.assertEqual(nc.lists_differ(data, {'lists': [['u', 1, 2, value]]}), ['u'], 'another size')
        self.assertEqual(signs, {True, False})
        for rows in (lists(('admin', 'files/hello.txt', 13)), lists(('admin', 'files/hello.txt', 13),
                                                                  ('admin', 'files/中文.txt', 7)),
                     lists(('admin', 'files/hello.txt', 6), ('admin', 'files/中文.txt', 13)), []):
            self.assertEqual(nc.lists_differ(found, {'lists': rows}), ['admin'], rows)
        self.assertEqual(nc.lists_differ(found, {'lists': HA_LISTS + lists(('bob', 'files/a', 1))}), ['bob'])
        for rows in (None, 'x', [['admin', 2, 19]], [['admin', 2, 19, True]], [[1, 2, 3, 4]]):
            self.assertEqual(nc.lists_differ(found, {'lists': rows}), [], rows)
        found, _tar = self.walk(share_tar(extra=[{'name': 'nextcloud/admin/files/again', 'type': 'hardlink',
                                                  'linkname': 'nextcloud/admin/files/hello.txt'}]))
        self.assertEqual(nc.lists_differ(found, {'lists': []}), [], 'a hard link has no size of its own')

    def test_a_hard_link_to_a_file_that_is_not_moved_is_copied(self):
        # NC-29: the web updater's backup (not moved) has a link in a user's folder; the file comes under the link's name.
        link = {'name': 'nextcloud/admin/files/again', 'type': 'hardlink',
                'linkname': 'nextcloud/updater-ochaabcdef12/backups/old.zip'}
        found, tar = self.walk(share_tar(extra=[link]))
        self.assertEqual(tar['./admin/files/again'][1], b'z' * 50)
        self.assertTrue(tar['./admin/files/again'][0].isfile() and not tar['./admin/files/again'][0].islnk())
        self.assertEqual((found.hardlinks_copied, found.hardlinks, found.skipped_files), (1, 0, 2))
        self.assertEqual(found.lists['admin'][:2], [3, 19 + 50], 'the copy is a file of the user like any other')
        self.assertFalse([n for n in tar if 'updater-' in n])
        # the check reads it the same way (no folder written)
        found = nc.scan_datadir(io.BytesIO(gzip.decompress(share_tar(extra=[link]))), habackup.Report(), 'nextcloud',
                                addon=False, instanceid='ochaabcdef12')
        self.assertEqual((found.hardlinks_copied, found.files), (1, 6))
        # a link to a file that is moved stays a link; one to an .htaccess that is left out is copied too
        found, tar = self.walk(share_tar(extra=[
            {'name': 'nextcloud/.htaccess', 'data': b'Require all granted\n'},
            {'name': 'nextcloud/admin/files/same', 'type': 'hardlink', 'linkname': 'nextcloud/admin/files/hello.txt'},
            {'name': 'nextcloud/admin/files/ht', 'type': 'hardlink', 'linkname': 'nextcloud/.htaccess'}]))
        self.assertTrue(tar['./admin/files/same'][0].islnk())
        self.assertEqual((found.hardlinks, found.hardlinks_copied), (1, 1))
        self.assertEqual(tar['./admin/files/ht'][1], b'Require all granted\n', 'a file under another name: no rule of Apache')
        self.assertEqual(found.htaccess, 0)

    def test_a_link_to_a_file_outside_the_folder_or_a_secret_is_not_copied_in(self):
        # what the reader cannot hand out (not a file of the member, or never read) is listed, not made up
        found, tar = self.walk(share_tar(extra=[
            {'name': 'nextcloud/admin/files/gone', 'type': 'hardlink', 'linkname': 'nextcloud/admin/files/nothing'}]))
        self.assertNotIn('./admin/files/gone', tar)
        self.assertEqual(found.report.skips['hardlink'].first, ['nextcloud/admin/files/gone'])


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
                         ('https://nextcloud.example.com', 'http://127.0.0.1:18081'))
        warnings = '\n'.join(result['warnings'])
        self.assertIn('gone_app', warnings)
        self.assertIn('PHP 8.5.11', warnings)
        self.assertIn('theme', warnings)
        pg = self.world.imported['hapg']
        names = members(pg)
        self.assertEqual(names['postgresql.conf'][1], nc.ha_odoo.PG_CONF)
        self.assertEqual(names['PG_VERSION'][0].uid, 999)

    def confirm_flow(self, issue_id, backup, *, items, spoken, clusters=('nc-db', 'hapg'), **convert_params):
        """The three steps of a line to confirm (DESIGN G1): the check lists it with its names, a conversion without its key
        stops only this app before anything is built, with it the import goes on. Returns the check row and the result."""
        row = self.check(backup, ['nextcloud'])[0]
        issue = issue_of(row, issue_id)
        self.assertEqual((row['importable'], row['ok'], issue['level'], issue['items']), (True, False, 'confirm', items))
        self.assertIn(spoken, issue['message'])
        self.assertLessEqual(len(issue['message']), 300)
        self.assertEqual([i['id'] for i in row['issues'] if i['level'] == 'stop'], [], 'nothing stops the app')
        seen = len(self.world.runs)
        for acknowledged in (None, {}, {'nextcloud': []}, {'odoo': [issue['key']]}):
            with self.subTest(acknowledged=acknowledged), self.assertRaises(BackupError) as caught:
                self.convert(backup, ['nextcloud'], **({} if acknowledged is None else {'acknowledged': acknowledged}),
                             **convert_params)
            self.assertEqual(caught.exception.code, 'confirmation-required')
            self.assertEqual([run[0] for run in self.world.runs[seen:] if run[0] in clusters], [], 'no cluster is built')
        return row, self.convert(backup, ['nextcloud'], acknowledged=ack(row, issue_id), **convert_params)

    def test_without_the_share_folder_the_users_files_stay_behind(self):
        # NC-22 (owner rule 3): the accounts, shares and settings move, the users' files cannot; one line to confirm, then the
        # import goes on with an empty data folder (the marker and Nextcloud's own .htaccess in it).
        backup = self.upload_nextcloud(share=None)
        row, result = self.confirm_flow('nextcloud.no-share', backup, items=['/share/nextcloud'], spoken='使用者檔案不會搬')
        data = members(self.world.dirs[DIRS[3]])
        self.assertEqual(data['./.ncdata'][1], nc.NCDATA)
        self.assertEqual((data['./.ncdata'][0].uid, data['./.ncdata'][0].mode), (33, 0o644))
        self.assertEqual(data['./.htaccess'][1], nc.DATA_HTACCESS)
        self.assertEqual((data['.'][0].uid, data['.'][0].mode), (33, 0o770))
        self.assertFalse([n for n in data if 'admin' in n or 'hello' in n], 'no file of HA is in it')
        self.assertIn('./appdata_ochaabcdef12/richdocuments/remoteData/discovery', data, "this device's Office answers stay")
        reminders = '\n'.join(result['ha_import']['reminders_by_app']['nextcloud'])
        for part in ('使用者檔案沒有搬過來', 'podman exec -u www-data nextcloud-app php occ files:scan --all'):
            self.assertIn(part, reminders)
        self.assertEqual((result['ha_import']['group'], result['results'][0]['status']), (None, 'converted'))
        registered = haimport.load_registry(self.paths)[result['backup_id']]
        self.assertEqual([(c['app_id'], c['id'], c['items']) for c in registered['confirmed']],
                         [('nextcloud', 'nextcloud.no-share', ['/share/nextcloud'])])
        # one more name (the data folder is another one) asks again
        config = HA_CONFIG.replace(b"'/share/nextcloud'", b"'/share/nextcloud2'")
        self.world.ha_details = dict(self.world.ha_details, local_storages=['local::/share/nextcloud2/'])
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(share=None, config=config), ['nextcloud'], acknowledged=ack(row, 'nextcloud.no-share'))
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_a_share_folder_without_the_data_directory_or_its_marker_leaves_the_files_behind(self):
        # NC-23: no folder, or a folder that is not marked as Nextcloud's data directory (not mounted when HA made the backup)
        empty = gzip.compress(hx.tar_bytes([{'name': 'other', 'type': 'dir'}]), mtime=0)
        row, _result = self.confirm_flow('nextcloud.no-datadir', self.upload_nextcloud(share=empty),
                                         items=['/share/nextcloud'], spoken='找不到 Nextcloud 的使用者檔案資料夾')
        self.assertEqual(members(self.world.dirs[DIRS[3]])['./.ncdata'][1], nc.NCDATA)
        unmarked = self.upload_nextcloud(share=share_tar(ncdata=False))
        self.world.dirs = {}
        row, result = self.confirm_flow('nextcloud.no-datadir', unmarked, items=['/share/nextcloud'], spoken='缺少 .ncdata 標記')
        data = members(self.world.dirs[DIRS[3]])
        self.assertEqual(data['./.ncdata'][1], nc.NCDATA, 'the marker is made here')
        self.assertFalse([n for n in data if 'hello' in n or 'admin' in n or 'preview' in n], 'the folder is not moved')
        with tarfile.open(fileobj=io.BytesIO(self.world.dirs[DIRS[3]])) as tar:
            names = tar.getnames()
        self.assertEqual(len(names), len(set(names)), 'the folder was started again: nothing twice')
        self.assertTrue(any('使用者檔案沒有搬過來' in line for line in result['ha_import']['reminders_by_app']['nextcloud']))

    def test_users_files_in_a_place_a_backup_never_holds_are_left_behind(self):
        # NC-25 (the half that is a real loss): a network disk or another path is not in any HA backup
        config = HA_CONFIG.replace(b"'/share/nextcloud'", b"'/media/nc disk'")
        self.world.ha_details = dict(self.world.ha_details, local_storages=['local::/media/nc disk/'])
        row, _result = self.confirm_flow('nextcloud.datadir-elsewhere', self.upload_nextcloud(config=config),
                                         items=['/media/nc disk'], spoken='HA 備份不會包含的位置')
        self.assertEqual(row['nextcloud']['datadir'], '/media/nc disk')
        self.assertEqual(members(self.world.dirs[DIRS[3]])['./.ncdata'][1], nc.NCDATA)
        sql = '\n'.join(x['sql'] for x in self.world.sessions if x['pg_user'] == 'oc_admin')
        self.assertIn("UPDATE public.oc_storages SET id = 'local::/var/www/html/data/' WHERE id = 'local::/media/nc disk/'", sql)

    def test_a_path_with_spaces_or_chinese_is_found_in_the_backup(self):
        # NC-25 (the wrongly refused half): the files are in the backup, only the name of their folder is unusual
        for path in ('/share/我的 雲端', '/share/Nextcloud Data/user files', '/share/nc-2026.11 (copy)'):
            with self.subTest(path=path):
                top = path[len('/share/'):]
                config = HA_CONFIG.replace(b"'/share/nextcloud'", f"'{path}'".encode())
                entries = [{'name': top, 'type': 'dir'}, {'name': f'{top}/.ncdata', 'data': b'# Nextcloud data directory\n'},
                           {'name': f'{top}/admin/files/hello.txt', 'data': b'hello from HA'},
                           {'name': f'{top}/admin/files/中文.txt', 'data': '測試'.encode()}]
                share = gzip.compress(hx.tar_bytes(entries), mtime=0)
                self.world.ha_details = dict(self.world.ha_details, local_storages=[nc.storage_id(path)])
                row = self.check(self.upload_nextcloud(config=config, share=share), ['nextcloud'])[0]
                self.assertEqual((row['ok'], row['blockers'], row['nextcloud']['datadir_in_backup']), (True, [], True))
                self.convert(self.upload_nextcloud(config=config, share=share), ['nextcloud'])
                data = members(self.world.dirs[DIRS[3]])
                self.assertEqual(data['./admin/files/hello.txt'][1], b'hello from HA')
        for path in ('/share/..', '/share/a/../b', '/share/a\x00b'):
            self.assertIsNone(nc.datadir_source(path), path)
        self.assertEqual(nc.datadir_source('/share/我的 雲端'), ('share', '我的 雲端'))

    def test_htaccess_files_of_the_users_are_left_out_and_listed(self):
        # NC-27: this device's data directory is in the web root: such a file could publish the folder or run files as
        # programs. They are not moved (the others are), Nextcloud's own rules are written, the line lists every one.
        share = share_tar(extra=[{'name': 'nextcloud/.htaccess', 'data': b'Require all denied\n'},
                                 {'name': 'nextcloud/admin/files/site/.htaccess', 'data': b'Require all granted\n'},
                                 {'name': 'nextcloud/admin/files/site/index.html', 'data': b'<p>hi</p>'}])
        row, result = self.confirm_flow('nextcloud.htaccess-skipped', self.upload_nextcloud(share=share),
                                        items=['admin/files/site/.htaccess'], spoken='1 個網站伺服器設定檔 .htaccess')
        data = members(self.world.dirs[DIRS[3]])
        self.assertEqual(data['./.htaccess'][1], nc.DATA_HTACCESS)
        self.assertFalse([n for n in data if n.endswith('.htaccess') and n != './.htaccess'])
        self.assertEqual(data['./admin/files/site/index.html'][1], b'<p>hi</p>')
        self.assertEqual(data['./admin/files/hello.txt'][1], b'hello from HA')
        # one more of them is one more name: it asks again
        more = share_tar(extra=[{'name': 'nextcloud/admin/files/site/.htaccess', 'data': b'x'},
                                {'name': 'nextcloud/admin/files/other/.htaccess', 'data': b'x'}])
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(share=more), ['nextcloud'], acknowledged=ack(row, 'nextcloud.htaccess-skipped'))
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(issue_of(self.check(self.upload_nextcloud(share=more), ['nextcloud'])[0],
                                  'nextcloud.htaccess-skipped')['items'],
                         ['admin/files/site/.htaccess', 'admin/files/other/.htaccess'])

    def test_symlinks_of_the_users_are_left_out_and_listed(self):
        # NC-26: a link may point outside this device's data directory; Nextcloud follows none by default
        share = share_tar(extra=[{'name': 'nextcloud/admin/files/link', 'type': 'symlink', 'linkname': 'hello.txt'},
                                 {'name': 'nextcloud/admin/files/up', 'type': 'symlink', 'linkname': '../../../etc/passwd'}])
        row, _result = self.confirm_flow('nextcloud.symlinks-skipped', self.upload_nextcloud(share=share),
                                         items=['nextcloud/admin/files/link', 'nextcloud/admin/files/up'], spoken='2 個符號連結')
        data = members(self.world.dirs[DIRS[3]])
        self.assertEqual(data['./admin/files/hello.txt'][1], b'hello from HA')
        self.assertFalse([n for n in data if n.endswith(('/link', '/up'))], 'no link is written')
        more = share_tar(extra=[{'name': 'nextcloud/admin/files/link', 'type': 'symlink', 'linkname': 'hello.txt'}])
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(share=more), ['nextcloud'], acknowledged=ack(row, 'nextcloud.symlinks-skipped'))
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_server_side_encryption_is_a_line_to_confirm_not_a_refusal(self):
        # NC-28 (owner decision D8, special case S5): the keys and the files move together; this has never been tested
        self.world.ha_details = dict(self.world.ha_details, encryption='yes')
        row, result = self.confirm_flow('nextcloud.server-side-encryption', self.upload_nextcloud(),
                                        items=['encryption_enabled'], spoken='還沒有實測過', clusters=('nc-db',))
        self.assertIn('用匯入前自動做的備份退回', issue_of(row, 'nextcloud.server-side-encryption')['message'])
        self.assertEqual(result['results'][0]['status'], 'converted')
        # also when only the files say so (the keys folder), and the two together are one line with both names
        self.world.ha_details = dict(self.world.ha_details, encryption=None)
        share = share_tar(extra=[{'name': 'nextcloud/files_encryption/keys/files/a/OC_DEFAULT_MODULE/a.publicKey', 'data': b'k'}])
        row = self.check(self.upload_nextcloud(share=share), ['nextcloud'])[0]
        self.assertEqual(issue_of(row, 'nextcloud.server-side-encryption')['items'], ['files_encryption'])
        self.world.ha_details = dict(self.world.ha_details, encryption='yes')
        row2 = self.check(self.upload_nextcloud(share=share), ['nextcloud'])[0]
        self.assertEqual(issue_of(row2, 'nextcloud.server-side-encryption')['items'], ['files_encryption', 'encryption_enabled'])
        self.assertNotEqual(issue_of(row, 'nextcloud.server-side-encryption')['key'],
                            issue_of(row2, 'nextcloud.server-side-encryption')['key'])

    def test_storages_below_the_data_directory_are_not_external_ones(self):
        team = 'local::/share/nextcloud/__groupfolders/1/'
        self.world.ha_details = dict(self.world.ha_details, local_storages=['local::/share/nextcloud/', team])
        result = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
        self.assertTrue(result['ok'], result['blockers'])
        self.assertFalse([w for w in result['warnings'] if '外部儲存' in w], result['warnings'])
        self.world.ha_details = dict(self.world.ha_details, local_storages=[
            'local::/share/nextcloud/', team, 'local::/share/media/', 'f' * 32])
        result = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
        warning = [w for w in result['warnings'] if '本機外部儲存空間' in w]
        self.assertEqual(len(warning), 1, result['warnings'])
        self.assertIn('1 個本機外部儲存空間（例如 /share/media/）', warning[0])

    def test_a_row_of_this_devices_data_dir_in_has_database_is_refused(self):
        # E.g. an HA Nextcloud that was moved from a container before: the rename would meet a taken id.
        for taken in ('local::/var/www/html/data/', 'local::/var/www/html/data/__groupfolders/1/'):
            self.world.ha_details = dict(self.world.ha_details, local_storages=[
                'local::/share/nextcloud/', 'local::/share/nextcloud/__groupfolders/1/', taken])
            result = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
            self.assertEqual(len(result['blockers']), 1, result['blockers'])
            self.assertIn('已經有這台使用者檔案資料夾（/var/www/html/data）的儲存空間記錄', result['blockers'][0])
            with self.assertRaises(BackupError) as caught:
                self.convert(self.upload_nextcloud(), ['nextcloud'])
            self.assertEqual(caught.exception.code, 'incompatible')

    def test_a_data_directory_whose_storage_id_is_stored_as_its_md5(self):
        far = '/share/' + 'x' * 60
        config = HA_CONFIG.replace(b"'/share/nextcloud'", f"'{far}'".encode())
        entries = [{'name': 'x' * 60, 'type': 'dir'}, {'name': 'x' * 60 + '/.ncdata', 'data': b'# Nextcloud data directory\n'},
                   {'name': 'x' * 60 + '/admin/files/hello.txt', 'data': b'hello from HA'},
                   {'name': 'x' * 60 + '/admin/files/中文.txt', 'data': '測試'.encode()}]
        share = gzip.compress(hx.tar_bytes(entries), mtime=0)
        self.world.ha_details = dict(self.world.ha_details, local_storages=[nc.storage_id(far)])
        result = self.check(self.upload_nextcloud(config=config, share=share), ['nextcloud'])[0]
        self.assertEqual((result['ok'], result['blockers']), (True, []))
        self.assertIn("id ~ '^[0-9a-f]{32}$'", nc.HA_SQL)
        self.convert(self.upload_nextcloud(config=config, share=share), ['nextcloud'])
        sql = '\n'.join(x['sql'] for x in self.world.sessions if x['role'] == 'nc-db')
        self.assertIn(f"UPDATE public.oc_storages SET id = 'local::/var/www/html/data/' WHERE id = '{nc.storage_id(far)}'", sql)

    def test_a_fifo_is_named_in_the_log(self):
        share = share_tar(extra=[{'name': 'nextcloud/admin/files/pipe', 'type': 'fifo'}])
        self.check(self.upload_nextcloud(share=share), ['nextcloud'])
        self.assertTrue(any('1 個特殊檔案（FIFO）沒有搬過來' in line for line in self.reporter.logs), self.reporter.logs)

    def test_file_lists_that_differ_are_a_warning(self):
        result = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
        self.assertFalse([w for w in result['warnings'] if '檔案清單' in w], 'the same files: no warning')
        self.world.lists = lists(('admin', 'files/hello.txt', 13))
        result = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
        self.assertTrue(result['ok'])
        warning = [w for w in result['warnings'] if '檔案清單' in w]
        self.assertEqual(len(warning), 1, result['warnings'])
        for part in ('1 位 Nextcloud 使用者', 'admin', 'podman exec -u www-data nextcloud-app php occ files:scan --all'):
            self.assertIn(part, warning[0])

    def test_the_live_database_is_read_pinned(self):
        # The live superuser's session: nothing the Nextcloud role could create in `public` stands in for a built-in.
        self.check(self.upload_nextcloud(), ['nextcloud'])
        live = [x for x in self.world.sessions if x['role'] == 'nextcloud-db' and 'rolpassword' in x['sql']]
        self.assertEqual(len(live), 1)
        self.assertTrue(live[0]['sql'].startswith('SET search_path = pg_catalog; SELECT '), live[0]['sql'][:80])
        self.assertIn('FROM public.oc_appconfig a', live[0]['sql'])
        self.assertNotIn('FROM oc_appconfig', live[0]['sql'])

    def test_other_blockers(self):
        self.world.ha_details = dict(self.world.ha_details, extensions=['plpgsql', 'postgis'])
        result = self.check(self.upload_nextcloud(config=HA_CONFIG.replace(b"'35.0.1.1'", b"'35.0.3.1'")),
                            ['nextcloud'])[0]
        self.assertIn('版本不同', '\n'.join(result['blockers']))
        self.assertEqual(issue_of(result, 'nextcloud.extension-missing')['items'], ['postgis'])

    def test_texts_of_has_backup_are_shown_safely(self):
        # A path, a version or a URL of HA's is text on the page and in the job log: no control character (a forged
        # line, a terminal escape) and no bidirectional control (text that reads in another order) gets through.
        self.assertEqual(nc.shown('a\n\u202e\x1b[2J\u2028x'), 'a???[2J?x')
        self.assertEqual(nc.shown('x' * 300, 200), 'x' * 200)
        info = INFO_RD.replace(b'9.0.3', b'9.0&#x202e;3')
        warnings = nc.app_warnings({'richdocuments': {**nc.parse_info_xml(info), 'foreign': ['a\u2066b']}},
                                   nc_version_text='35.0.1.1', php_version='8.5.11')
        self.assertTrue(any('9.0?3' in w for w in warnings) and any('a?b' in w for w in warnings), warnings)
        url = HA_CONFIG.replace(b"'https://nextcloud.example.com'", b"'https://h\n\xe2\x80\xaeio'")
        media = HA_CONFIG.replace(b"'/share/nextcloud'", b"'/media/\n\xe2\x80\xaenc'")
        self.assertTrue(HA_CONFIG not in (url, media))
        link = {'name': 'nextcloud/admin/files/l\u202el', 'type': 'symlink', 'linkname': 'hello.txt'}
        storages = dict(self.world.ha_details, local_storages=['local::/share/nextcloud/', 'local::/mnt/\x9b\u202e/'])
        cases = ((dict(config=url), None, ('ha_url', 'https://h??io')),
                 (dict(config=media), '/media/??nc', ('datadir', '/media/??nc')),
                 (dict(pg_version=b'17\x1b[2J\n'), None, ('pg_version', '17?[2J')),
                 (dict(share=share_tar(extra=[{'name': 'nextcloud/admin/files/a\u202eb/.htaccess', 'data': b'x'}])),
                  'admin/files/a b/.htaccess', None),
                 (dict(share=share_tar(extra=[link])), 'admin/files/l', None),
                 (dict(extra=[{'name': 'data/nextcloud/custom_apps/A\u202eB/x', 'data': b'x'}]), 'A?B', None))
        for kwargs, text, item in cases:
            with self.subTest(text=text, item=item):
                result = self.check(self.upload_nextcloud(**kwargs), ['nextcloud'])[0]
                self.assertEqual([x for x in strings(result) if nc.hacommon.CONTROL_RE.search(x)], [])
                if text is not None:
                    names = [name for issue in result['issues'] for name in issue['items']]
                    self.assertIn(text, '\n'.join(result['blockers'] + result['warnings'] + names))
                if item is not None:
                    self.assertEqual(result['nextcloud'][item[0]], item[1])
        self.world.ha_details = storages
        result = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
        self.assertIn('/mnt/??/', '\n'.join(result['warnings']))
        self.assertEqual([x for x in strings(result) if nc.hacommon.CONTROL_RE.search(x)], [])

    def test_files_of_an_online_backup_are_refused_unstarted(self):
        # A cold add-on backup has neither; tablespace_map makes PostgreSQL create the tablespace links itself.
        for name in ('backup_label', 'tablespace_map'):
            extra = [{'name': f'data/postgres/{name}', 'data': b'START WAL LOCATION: 0/2000028\n'}]
            runs = len(self.runs('hapg'))
            result = self.check(self.upload_nextcloud(extra=extra), ['nextcloud'])[0]
            self.assertEqual((result['ok'], result['blockers']), (False, [nc.MSG_ONLINE]))
            self.assertNotIn(name, members(self.world.imported['hapg']), 'never streamed into the volume')
            with self.assertRaises(BackupError) as caught:
                self.convert(self.upload_nextcloud(extra=extra), ['nextcloud'])
            self.assertEqual((caught.exception.code, caught.exception.message), ('incompatible', nc.MSG_ONLINE))
            self.assertEqual(len(self.runs('hapg')), runs, 'the cluster is never started')

    def test_unreadable_config_and_wrong_postgres(self):
        result = self.check(self.upload_nextcloud(config=b"<?php $CONFIG = array('a' => getenv('X'));"),
                            ['nextcloud'])[0]
        self.assertIn('無法解讀', result['blockers'][0])
        result = self.check(self.upload_nextcloud(pg_version=b'17\n'), ['nextcloud'])[0]
        self.assertTrue(any('只支援 16 版' in b for b in result['blockers']))
        self.assertFalse(self.runs('hapg')[1:], 'the PostgreSQL 17 cluster is never started')

    def test_what_cannot_be_left_out_is_refused_unread(self):
        # A type, a view, a rule, a check or a default that reads a server file: refused from the catalogs alone (the
        # tables of HA's are not read: no view or function of HA's runs, even in the throwaway cluster). Functions and
        # triggers beside them do not change that.
        self.world.shape['hapg'] = dict(CLEAN_SHAPE, functions=2, triggers=1, types=1, relations=1,
                                        defaults=CLEAN_SHAPE['defaults'] + ["pg_read_file('/etc/passwd'::text)"])
        row = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
        self.assertFalse(row['importable'])
        stops = [i for i in row['issues'] if i['level'] == 'stop']
        self.assertEqual([i['id'] for i in stops], ['nextcloud.db-objects'])
        for part in ('Nextcloud 不會建立、這台也無法略過的資料庫物件', '自訂資料型別', '檢視表或其他特殊資料表',
                     '不是固定值的欄位預設值', '無法安全地搬過來'):
            self.assertIn(part, stops[0]['message'])
        for part in ('函式', '觸發程序'):
            self.assertNotIn(part, stops[0]['message'], 'they alone would be left out')
        self.assertIsNone(issue_of(row, 'nextcloud.db-objects-skipped'), 'nothing is moved: nothing to confirm')
        ha = [x for x in self.world.sessions if x['role'] == 'hapg' and x['tool'] == 'psql']
        self.assertTrue(ha and all(x['env'].get('PGOPTIONS') == '-c search_path=pg_catalog' for x in ha))
        self.assertFalse([x for x in ha if 'public.oc_' in x['sql']], 'no table of HA is read')
        self.assertFalse([x for x in ha if x['sql'] == nc.OBJECTS_SQL], 'the names are only read when they are left out')
        for key in ('rules', 'policies', 'operators', 'checks', 'generated', 'inherits', 'others', 'tablespaces',
                    'event_triggers'):
            with self.subTest(key=key):
                self.world.shape['hapg'] = dict(CLEAN_SHAPE, functions=1, **{key: 1})
                row = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
                self.assertFalse(row['importable'], key)
                self.assertEqual([i['id'] for i in row['issues'] if i['level'] == 'stop'], ['nextcloud.db-objects'])

    def test_functions_and_triggers_of_other_apps_are_left_out_and_listed(self):
        # NC-38 and NC-45: Memories makes a function and a trigger. Programs are not moved (they would run as Nextcloud's
        # database role), the tables and their data are, and the customer is told which; the second gate (the list of the
        # dump) leaves out exactly the kinds that were confirmed.
        self.world.shape['hapg'] = dict(CLEAN_SHAPE, functions=1, triggers=1)
        self.world.objects = {'functions': ['public.memories_f'], 'triggers': ['oc_filecache.memories_t']}
        self.world.toc = toc_of('201; 1259 16390 TABLE public oc_users nextcloud',
                                '202; 1255 16400 FUNCTION public memories_f() nextcloud',
                                '203; 2620 16401 TRIGGER public oc_filecache memories_t nextcloud',
                                '204; 0 0 COMMENT public FUNCTION memories_f() nextcloud',
                                '205; 0 0 COMMENT public TRIGGER memories_t ON oc_filecache nextcloud',
                                '206; 0 0 COMMENT public COLUMN oc_users.uid nextcloud',
                                '207; 0 16390 TABLE DATA public oc_users nextcloud')
        row, result = self.confirm_flow('nextcloud.db-objects-skipped', self.upload_nextcloud(),
                                        items=['函式 public.memories_f', '觸發程序 oc_filecache.memories_t'], spoken='不會搬過來',
                                        clusters=('nc-db',))
        self.assertTrue(row['importable'])
        self.assertIn('Memories', issue_of(row, 'nextcloud.db-objects-skipped')['message'])
        listing = self.world.container_files.files[('nc-db', '/tmp/woowbk-nc.toc')].decode()
        self.assertEqual([line.split(' ', 3)[3].split(' ')[0] for line in listing.splitlines() if line[:1].isdigit()],
                         ['TABLE', 'COMMENT', 'TABLE'], 'the tables, the comment on a column and the data stay')
        self.assertNotIn('memories', listing)
        self.assertEqual(result['results'][0]['status'], 'converted')
        # one more program is one more name: it asks again
        self.world.objects = {'functions': ['public.memories_f', 'public.other_f'], 'triggers': ['oc_filecache.memories_t']}
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(), ['nextcloud'], acknowledged=ack(row, 'nextcloud.db-objects-skipped'))
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_the_dump_may_not_hold_more_than_was_confirmed(self):
        # NC-45, second gate: confirmed are the kinds the check showed; any other kind that Nextcloud never creates stops
        self.world.shape['hapg'] = dict(CLEAN_SHAPE, functions=1)
        self.world.objects = {'functions': ['public.f'], 'triggers': []}
        for lines, kinds in ((('201; 1259 16390 TABLE public oc_users nextcloud', '202; 1255 16400 FUNCTION public f() nextcloud',
                               '205; 2617 16403 OPERATOR public = nextcloud'), ('OPERATOR',)),
                             (('201; 1259 16390 TABLE public oc_users nextcloud', '204; 1259 16402 VIEW public v nextcloud'),
                              ('VIEW',))):
            with self.subTest(kinds=kinds):
                self.world.toc = toc_of(*lines)
                row = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
                seen = len(self.world.execs)
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_nextcloud(), ['nextcloud'], acknowledged=ack(row, 'nextcloud.db-objects-skipped'))
                self.assertEqual(caught.exception.code, 'incompatible')
                self.assertIn(kinds[0], caught.exception.message)
                self.assertFalse([c for r, c, _d in self.world.execs[seen:] if c[:1] == ['pg_restore'] and '-U' in c])

    def test_a_program_that_stays_in_the_new_cluster_stops_the_conversion(self):
        # the shape of the NEW cluster is read again after the restore: nothing of HA's may be left there
        self.world.shape['hapg'] = dict(CLEAN_SHAPE, functions=1)
        self.world.objects = {'functions': ['public.f'], 'triggers': []}
        row = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
        self.world.shape['nc-db'] = dict(CLEAN_SHAPE, functions=1)
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(), ['nextcloud'], acknowledged=ack(row, 'nextcloud.db-objects-skipped'))
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('函式', caught.exception.message)
        sql = '\n'.join(x['sql'] for x in self.world.sessions if x['role'] == 'nc-db')
        self.assertNotIn('UPDATE public.oc_storages', sql)

    def test_an_extension_this_devices_image_has_is_enabled_first(self):
        # NC-39
        self.world.ha_details = dict(self.world.ha_details, extensions=['plpgsql', 'pg_trgm', 'uuid-ossp'])
        row = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
        issue = issue_of(row, 'nextcloud.extension-enabled')
        self.assertEqual((row['ok'], issue['level'], issue['items']), (True, 'auto', ['pg_trgm', 'uuid-ossp']))
        self.world.catalog = {'owners': ['oc_admin'], 'verifier_md5': hashlib.md5(VERIFIER.encode()).hexdigest(),
                              'role': {k: v for k, v in LIVE_DB['role'].items() if k != 'password'}, 'role_settings': 0,
                              'grants': 0, 'databases': ['nextcloud', 'postgres', 'template0', 'template1'],
                              **{key: LIVE_DB[key] for key in ('roles', 'datacl', 'nspacl')},
                              'extensions': ['pg_trgm', 'plpgsql', 'uuid-ossp', 'vector']}
        self.convert(self.upload_nextcloud(), ['nextcloud'])
        joined = '\n'.join(script for _db, script, _tx in self.world.psql['nc-db'].executed)
        for name in ('"vector"', '"pg_trgm"', '"uuid-ossp"'):
            self.assertIn(f'CREATE EXTENSION IF NOT EXISTS {name}', joined)
        self.assertLess(joined.index('CREATE EXTENSION IF NOT EXISTS "pg_trgm"'), joined.index('UPDATE public.oc_storages'))
        # the catalog says the extension is not there afterwards: the verification stops it
        self.world.catalog = dict(self.world.catalog, extensions=['plpgsql', 'vector'])
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(), ['nextcloud'])
        self.assertIn('擴充功能和這台的不同', caught.exception.message)

    def test_an_extension_this_devices_image_does_not_have_stops_only_nextcloud(self):
        # NC-39: the columns that need it could not be put in: refused, the name is shown
        self.world.ha_details = dict(self.world.ha_details, extensions=['plpgsql', 'pg_trgm', 'postgis'])
        row = self.check(self.upload_nextcloud(), ['nextcloud'])[0]
        issue = issue_of(row, 'nextcloud.extension-missing')
        self.assertEqual((row['importable'], issue['level'], issue['items']), (False, 'stop', ['postgis']))
        self.assertEqual(issue_of(row, 'nextcloud.extension-enabled')['items'], ['pg_trgm'])
        self.assertTrue(issue['action'])
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(), ['nextcloud'])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertFalse(self.runs('nc-db'))

    def test_only_the_schema_public_is_moved(self):
        # NC-40: another schema is left out and listed; the dump is of public only. Without one the dump is the plain one.
        def dump_args():
            return [c for r, c, _d in self.world.execs if r == 'hapg' and c[:1] == ['pg_dump']][-1]

        self.convert(self.upload_nextcloud(), ['nextcloud'])
        self.assertNotIn('-n', dump_args())
        self.world.ha_details = dict(self.world.ha_details, schemas=['memories', 'x y'])
        row, result = self.confirm_flow('nextcloud.schemas-skipped', self.upload_nextcloud(), items=['memories', 'x y'],
                                        spoken='只搬 public', clusters=('nc-db',))
        self.assertEqual(dump_args()[-2:], ['-n', 'public'])
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.world.ha_details = dict(self.world.ha_details, schemas=['memories', 'x y', 'more'])
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(), ['nextcloud'], acknowledged=ack(row, 'nextcloud.schemas-skipped'))
        self.assertEqual(caught.exception.code, 'confirmation-required')

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
        # Nextcloud's own protection of a data dir inside the web root, also when HA's data directory has none.
        protect = data['./.htaccess']
        self.assertEqual((protect[1], protect[0].uid, protect[0].gid, protect[0].mode),
                         (nc.DATA_HTACCESS, 33, 33, 0o644))
        self.assertIn(b'\n  Require all denied\n', protect[1])
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

    def test_office_gets_this_devices_collabora_answers(self):
        # The Office app never fetches Collabora's discovery on demand (CachedRequestService.php get()): without its two
        # cached files every document is an HTTP 500 until an hourly job runs. HA's are replaced by this device's.
        self.convert(self.upload_nextcloud(), ['nextcloud'])
        folder = './appdata_ochaabcdef12/richdocuments/remoteData'
        data = members(self.world.dirs[DIRS[3]])
        self.assertEqual({n.rsplit('/', 1)[1]: d for n, (_m, d) in data.items() if n.startswith(folder + '/')},
                         OFFICE_CACHE)
        for name in (folder, folder + '/discovery'):
            self.assertEqual((data[name][0].uid, data[name][0].gid), (33, 33), name)
        self.assertEqual((data[folder][0].mode, data[folder + '/discovery'][0].mode), (0o755, 0o644))
        self.assertIn('./appdata_ochaabcdef12/richdocuments', data)
        with tarfile.open(fileobj=io.BytesIO(self.world.dirs[DIRS[3]])) as tar:
            names = tar.getnames()
        self.assertEqual(len(names), len(set(names)), 'nothing twice')
        sql = '\n'.join(x['sql'] for x in self.world.sessions if x['pg_user'] == 'oc_admin')
        self.assertIn("UPDATE public.oc_jobs SET last_run = 0, last_checked = 0, reserved_at = 0 WHERE class = "
                      "'OCA\\Richdocuments\\Backgroundjobs\\ObtainCapabilities'", sql)

    def test_office_cache_without_has_app_data_or_this_devices_answers(self):
        bare = [{'name': 'nextcloud', 'type': 'dir'}, {'name': 'nextcloud/.ncdata', 'data': b'# Nextcloud data directory\n'},
                {'name': 'nextcloud/admin/files/hello.txt', 'data': b'hello from HA'},
                {'name': 'nextcloud/admin/files/中文.txt', 'data': '測試'.encode()}]
        share = gzip.compress(hx.tar_bytes(bare), mtime=0)
        self.world.tables = [t for t in TABLES if t != 'oc_jobs']
        result = self.convert(self.upload_nextcloud(share=share), ['nextcloud'])
        data = members(self.world.dirs[DIRS[3]])
        for name in ('./appdata_ochaabcdef12', './appdata_ochaabcdef12/richdocuments',
                     './appdata_ochaabcdef12/richdocuments/remoteData'):
            self.assertTrue(data[name][0].isdir() and data[name][0].uid == 33, name)
        self.assertNotIn('oc_jobs', '\n'.join(x['sql'] for x in self.world.sessions if x['role'] == 'nc-db'))
        self.assertFalse(any('activate-config' in line for line in result['ha_import']['reminders_by_app']['nextcloud']))
        for cache in ({}, {'capabilities': b'{}'}):
            self.world.office_cache = cache
            result = self.convert(self.upload_nextcloud(), ['nextcloud'])
            data = members(self.world.dirs[DIRS[3]])
            self.assertNotIn('./appdata_ochaabcdef12/richdocuments/remoteData/discovery', data)
            lines = [line for line in result['ha_import']['reminders_by_app']['nextcloud'] if 'activate-config' in line]
            self.assertEqual(len(lines), 1, cache)
            self.assertIn('podman exec -u www-data nextcloud-app php occ richdocuments:activate-config', lines[0])
        self.world.ha_details = dict(self.world.ha_details, enabled=['files'])
        result = self.convert(self.upload_nextcloud(), ['nextcloud'])
        lines = '\n'.join(result['ha_import']['reminders_by_app']['nextcloud'])
        self.assertNotIn('activate-config', lines)
        self.assertIn('沒有啟用 Office', lines)

    def test_the_protection_file_replaces_has_own(self):
        share = share_tar(extra=[{'name': 'nextcloud/.htaccess', 'data': b'Require all granted\n'}])
        result = self.convert(self.upload_nextcloud(share=share), ['nextcloud'])
        data = members(self.world.dirs[DIRS[3]])
        self.assertEqual(data['./.htaccess'][1], nc.DATA_HTACCESS)
        self.assertFalse(any('檔案掃描' in line for line in result['ha_import']['reminders_by_app']['nextcloud']))

    def test_team_folders_keep_their_storages(self):
        team = [f'local::/share/nextcloud/__groupfolders/{n}/' for n in (1, 12)]
        self.world.ha_details = dict(self.world.ha_details, local_storages=['local::/share/nextcloud/', *team])
        share = share_tar(extra=[{'name': 'nextcloud/__groupfolders/1/files/plan.txt', 'data': b'plan'}])
        self.convert(self.upload_nextcloud(share=share), ['nextcloud'])
        sql = '\n'.join(x['sql'] for x in self.world.sessions if x['pg_user'] == 'oc_admin')
        for n in (1, 12):
            self.assertIn(f"UPDATE public.oc_storages SET id = 'local::/var/www/html/data/__groupfolders/{n}/' WHERE id = "
                          f"'local::/share/nextcloud/__groupfolders/{n}/'", sql)
        verify = [x['sql'] for x in self.world.sessions if x['pg_user'] == 'oc_admin' and "'counts'" in x['sql']]
        self.assertIn("'moved', (SELECT count(*) FROM public.oc_storages WHERE id IN ('local::/var/www/html/data/', "
                      "'local::/var/www/html/data/__groupfolders/1/', 'local::/var/www/html/data/__groupfolders/12/'))", verify[0])
        self.assertIn("'old', (SELECT count(*) FROM public.oc_storages WHERE id IN ('local::/share/nextcloud/', "
                      "'local::/share/nextcloud/__groupfolders/1/', 'local::/share/nextcloud/__groupfolders/12/'))", verify[0])
        self.assertEqual(members(self.world.dirs[DIRS[3]])['./__groupfolders/1/files/plan.txt'][1], b'plan')
        self.assertTrue(any('2 個資料夾（團隊資料夾）' in line for line in self.reporter.logs), self.reporter.logs)
        good = {'counts': {**HA_COUNTS, 'files': 298}, 'root': 1, 'moved': 3, 'old': 0, 'appconfig': LIVE_DB['appconfig']}
        for change in ({'moved': 2}, {'old': 1}, {'root': 0}, {'moved': None}):
            self.world.verify = dict(good, **change)
            with self.assertRaises(BackupError) as caught:
                self.convert(self.upload_nextcloud(share=share), ['nextcloud'])
            self.assertIn('儲存空間記錄沒有改成這台的路徑', caught.exception.message, change)
        self.world.verify = good
        self.convert(self.upload_nextcloud(share=share), ['nextcloud'])

    def test_a_reminder_to_scan_when_the_file_lists_differ(self):
        self.world.lists = lists(('admin', 'files/hello.txt', 13))
        result = self.convert(self.upload_nextcloud(), ['nextcloud'])
        lines = [line for line in result['ha_import']['reminders_by_app']['nextcloud'] if '檔案掃描' in line]
        self.assertEqual(len(lines), 1)
        self.assertIn('podman exec -u www-data nextcloud-app php occ files:scan --all', lines[0])

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
        for lines, kinds in (
                (('201; 1259 16390 TABLE public oc_users nextcloud', '202; 1255 16400 FUNCTION public woow_t() nextcloud',
                  '203; 2620 16401 TRIGGER public oc_storages woow_t nextcloud'), ('FUNCTION', 'TRIGGER')),
                (('201; 1259 16390 TABLE public oc_users nextcloud', '204; 1259 16402 VIEW public oc_storages2 nextcloud'),
                 ('VIEW',)),
                (('205; 2617 16403 OPERATOR public = nextcloud',), ('OPERATOR',)),
                (('206; 0 0 WHATEVER public x nextcloud',), ('UNKNOWN WHATEVER',))):
            with self.subTest(kinds=kinds):
                self.world.toc = toc_of(*lines)
                seen = len(self.world.execs)
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_nextcloud(), ['nextcloud'])
                self.assertEqual(caught.exception.code, 'incompatible')
                self.assertIn('Nextcloud 不會建立', caught.exception.message)
                for kind in kinds:
                    self.assertIn(kind, caught.exception.message)
                restores = [c for r, c, _d in self.world.execs[seen:]
                            if r == 'nc-db' and c[:1] == ['pg_restore'] and '-U' in c]
                self.assertEqual(restores, [], 'nothing of HA is restored')

    def test_a_listing_that_came_back_short_stops_the_conversion(self):
        # pg-stdin follow-up F4: the listing must have as many entries as its own header says the archive has
        good = toc_of('201; 1259 16390 TABLE public oc_users nextcloud', '202; 0 16390 TABLE DATA public oc_users nextcloud')
        self.assertEqual(nc.check_listing(good.decode()), 2)
        for text in (good.decode().replace('202; 0 16390 TABLE DATA public oc_users nextcloud\n', ''),
                     good.decode().replace('TOC Entries: 5', 'TOC Entries: 6'),
                     ''.join(line for line in good.decode().splitlines(True) if 'TOC Entries' not in line), ''):
            with self.subTest(text=text), self.assertRaises(BackupError) as caught:
                nc.check_listing(text)
            self.assertEqual(caught.exception.code, 'job-failed')
        # the archive settings a plain listing may show count as the entries they are
        shown = good.decode() + '1; 0 0 ENCODING - ENCODING\n'
        self.assertEqual(nc.check_listing(shown), 3)
        self.world.toc = good[:-len(b'202; 0 16390 TABLE DATA public oc_users nextcloud\n')]
        seen = len(self.world.execs)
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_nextcloud(), ['nextcloud'])
        self.assertEqual(caught.exception.message, nc.INCOMPLETE_LIST)
        self.assertEqual([c for r, c, _d in self.world.execs[seen:] if r == 'nc-db' and c[:1] == ['pg_restore'] and '-U' in c], [])

    def test_the_retry_note_of_the_listing_file_reaches_the_job_log(self):
        # pg-stdin follow-up F3: Cluster(..., log=work.log); the first write of the file comes up short once
        wrote, calls = self.world.container_files.wrote, []

        def short_once(key, argv, data, result):
            if list(argv[:2]) == ['sh', '-c'] and 'cat >' in argv[2]:
                calls.append(key)
                return wrote(key, argv, (data or b'')[:-5] if len(calls) == 1 else data, result)
            return wrote(key, argv, data, result)

        self.world.container_files.wrote = short_once
        with mock.patch.object(nc.ha_odoo, 'WRITE_RETRY_PAUSE', 0):
            self.convert(self.upload_nextcloud(), ['nextcloud'])
        self.assertEqual(len(calls), 2, 'written again')
        self.assertTrue(any('暫用容器裡的暫存檔沒有完整寫入' in line for line in self.reporter.logs), self.reporter.logs[-6:])

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
                'grants': 0, 'databases': ['nextcloud', 'postgres', 'template0', 'template1'],
                **{key: LIVE_DB[key] for key in ('roles', 'extensions', 'datacl', 'nspacl')}}
        for change, text in (({'role': dict(good['role'], super=True)}, 'oc_admin 角色的權限和這台的不同'),
                             ({'role': dict(good['role'], createrole=True)}, 'oc_admin 角色的權限和這台的不同'),
                             ({'role': None}, 'oc_admin 角色的權限和這台的不同'),
                             ({'role_settings': 1}, '出現了角色或資料庫層級的設定'),
                             ({'grants': 2}, '資料表或欄位多了權限設定'), ({'grants': None}, '資料表或欄位多了權限設定'),
                             # The role may create databases (CREATEDB): SQL hidden in HA's dump could leave one behind.
                             ({'databases': ['evil', 'nextcloud', 'postgres', 'template0', 'template1']}, '有其他資料庫'),
                             ({'databases': None}, '有其他資料庫')):
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
        self.assertEqual(nc.shape_problems(dict(CLEAN_SHAPE, tablespaces=1)), ['另外的表空間（tablespace）'])
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
