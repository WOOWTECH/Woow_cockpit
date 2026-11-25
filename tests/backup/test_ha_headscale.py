"""HA import, Headscale part (ha_headscale.py): HA's database, Noise identity and DNS records move; HA's API keys are
replaced by this device's in the sandboxed child; the live image's `headscale configtest` opens the result before it is
packaged (CONTRACT section 9). Team E2.

HAOS parity (2026-11-25, lane HERMES-HEADSCALE; rows HS-02 .. HS-40 of the owner's list): nothing in HA's data or in this device's
own setup keeps the import from happening. Versions only inform (the database is opened by configtest); no size refuses it; HA's
IP ranges replace this device's in the converted configuration folder (HS-22), devices outside the range are listed (HS-19);
an identity key that cannot be used makes this device's stay (HS-20, HS-38); a DNS file that is invalid or whose path would
overwrite the database or the key is not moved (HS-23, HS-34); a copy of this device's database that was being written is read
again (HS-24, HS-26, HS-29), a Headscale that never ran is started once (HS-27); the access policy follows the owner's decision S3
(HA's replaces this device's, none from HA: this device's stays). What is left out or changed is one line of the ONE
confirmation (`confirm`); only what makes the data itself unusable stops Headscale, and then only Headscale."""
import gzip
import io
import json
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import habackup, haissues, ha_headscale, hacommon, hasqlite, hatarget, jobs
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import hab1fakes as fk
from . import hafixtures as hx

SLUG = '1b7b4ce7_woow-headscale'
NOISE = 'privkey:' + 'ab' * 32
LIVE_NOISE = 'privkey:' + 'cd' * 32
RECORDS = b'[{"name": "nas.ts.local", "type": "A", "value": "100.64.0.9"}]'
QUADLETS = {
    'headscale.container': b'[Container]\nContainerName=headscale\nImage=localhost/woow-headscale:0.29.4-r1\nExec=serve\n'
                           b'Volume=headscale-data.volume:/var/lib/headscale\n'
                           b'Volume=headscale-run.volume:/var/run/headscale\n'
                           b'Volume=%h/.config/headscale/headscale:/etc/headscale:ro,Z\n',
    'headplane.container': b'[Container]\nContainerName=headplane\nImage=localhost/woow-headplane:0.7.1-woow2\n'
                           b'Volume=headplane-data.volume:/var/lib/headplane\n'
                           b'Volume=headscale-data.volume:/var/lib/headscale\n',
    'headscale-data.volume': b'[Volume]\nVolumeName=headscale-data\n',
    'headplane-data.volume': b'[Volume]\nVolumeName=headplane-data\n',
    'headscale-run.volume': b'[Volume]\nVolumeName=headscale-run\n',
    'headscale.network': b'[Network]\n',
}
LIVE_CONFIG = (b'server_url: https://woow-hs-podman-46.ngrok.app\nprefixes:\n  v4: 100.64.0.0/10\n'
               b'  v6: fd7a:115c:a1e0::/48\n  allocation: sequential\ndns:\n  base_domain: ts.local\n'
               b'  extra_records_path: /var/lib/headscale/extra_records.json\npolicy:\n  mode: database\n')
HA_CONFIG = (b'server_url: "http://homeassistant.local:28080"\nprefixes:\n  v4: "100.64.0.0/10"\n'
             b'  v6: "fd7a:115c:a1e0::/48"\n  allocation: sequential\ndns:\n  base_domain: "ts.local"\n'
             b'  extra_records_path: /etc/headscale/dns_records.json\npolicy:\n  mode: file\n  path: ""\n')


def populate(conn, *, prefixes, version='v0.29.4', ips=('100.64.0.1', 'fd7a:115c:a1e0::1'), migrations=None,
             trigger=False, policies=()):
    conn.executescript("""
        CREATE TABLE migrations(id text, PRIMARY KEY(id));
        CREATE TABLE users(id integer PRIMARY KEY AUTOINCREMENT, name text, deleted_at datetime);
        CREATE TABLE pre_auth_keys(id integer PRIMARY KEY AUTOINCREMENT, prefix text, hash blob, user_id integer);
        CREATE TABLE api_keys(id integer PRIMARY KEY AUTOINCREMENT, prefix text, hash blob, expiration datetime,
                              last_seen datetime, created_at datetime);
        CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix);
        CREATE TABLE nodes(id integer PRIMARY KEY AUTOINCREMENT, ipv4 text, ipv6 text, user_id integer);
        CREATE TABLE policies(id integer PRIMARY KEY AUTOINCREMENT, data text);
        CREATE TABLE database_versions(id integer PRIMARY KEY, version text NOT NULL, updated_at datetime);
        INSERT INTO users(name) VALUES ('alice');
        INSERT INTO pre_auth_keys(prefix, hash, user_id) VALUES ('pak', x'00', 1);
    """)
    conn.execute('INSERT INTO nodes(ipv4, ipv6, user_id) VALUES (?, ?, 1)', ips)
    conn.execute('INSERT INTO database_versions VALUES (1, ?, ?)', (version, '2026-11-01'))
    conn.executemany('INSERT INTO migrations VALUES (?)',
                     [(m,) for m in (migrations or sorted(ha_headscale.MIGRATIONS['0.29.4']))])
    conn.executemany('INSERT INTO api_keys(prefix, hash, created_at) VALUES (?, ?, ?)',
                     [(p, b'hash-of-' + p.encode(), '2026-11-01') for p in prefixes])
    conn.executemany('INSERT INTO policies(data) VALUES (?)', [(text,) for text in policies])
    if trigger:
        conn.execute('CREATE TRIGGER t AFTER DELETE ON api_keys BEGIN SELECT 1; END')
    conn.commit()


def database(**kwargs):
    tmp = tempfile.TemporaryDirectory()
    try:
        path = Path(tmp.name) / 'db.sqlite'
        conn = sqlite3.connect(path)
        populate(conn, **kwargs)
        conn.close()
        return path.read_bytes()
    finally:
        tmp.cleanup()


def wal_only_database(**kwargs):
    """(db, wal) like the RPi5's backup after Docker killed the add-on: a 4 KiB db.sqlite (the header page only) and
    every table and row in the -wal, never checkpointed."""
    tmp = tempfile.TemporaryDirectory()
    try:
        path = Path(tmp.name) / 'db.sqlite'
        conn = sqlite3.connect(path)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA wal_autocheckpoint=0')
        populate(conn, **kwargs)
        data = path.read_bytes(), (Path(tmp.name) / 'db.sqlite-wal').read_bytes()
        conn.close()
        return data
    finally:
        tmp.cleanup()


def addon_tar(*, version='0.1.3', db=None, noise=NOISE, records=RECORDS, config=HA_CONFIG, wal=None, extra=(), noise_data=None):
    addon = {'user': {'version': version, 'image': '1b7b4ce7/amd64-addon-woow-headscale',
                      'options': {'ngrok_authtoken': 'ha-ngrok-secret'}},
             'system': {'slug': 'woow-headscale', 'name': 'Woow Headscale VPN'}, 'version': version}
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': json.dumps(addon).encode()},
               {'name': './image.tar', 'data': b'docker save' * 100},
               {'name': 'data', 'type': 'dir'}, {'name': 'data/options.json', 'data': b'{}'},
               *([{'name': 'data/db.sqlite-wal', 'data': wal}] if wal is not None else []),
               {'name': 'data/db.sqlite', 'data': db if db is not None else database(prefixes=['ha-key-1', 'ha-key-2'])},
               {'name': 'data/db.sqlite-shm', 'data': b'shm-of-a-killed-server' * 100},
               {'name': 'data/.headplane_api_key', 'data': b'hskey-api-ha-secret'},
               {'name': 'data/.headplane_cookie_secret', 'data': b'ha-cookie-secret'},
               {'name': 'data/headplane', 'type': 'dir'}, {'name': 'data/headplane/hp_persist.db', 'data': b'hp'},
               {'name': 'config', 'type': 'dir'}, {'name': 'config/config.yaml', 'data': config}]
    if noise_data is not None:
        entries.append({'name': 'data/noise_private.key', 'data': noise_data, 'mode': 0o600})
    elif noise is not None:
        entries.append({'name': 'data/noise_private.key', 'data': noise.encode(), 'mode': 0o600})
    if records is not None:
        entries.append({'name': 'config/dns_records.json', 'data': records})
    return gzip.compress(hx.tar_bytes(entries + list(extra)), mtime=0)


CONFIG_DIR = '.config/headscale/headscale'


def config_dir_tar(config=LIVE_CONFIG, extra=()):
    return fk.tar_of([{'name': '.', 'type': 'dir', 'mode': 0o755}, {'name': 'config.yaml', 'data': config, 'mode': 0o644},
                      {'name': 'policy.json', 'data': b'{}', 'mode': 0o644}, *extra])


class HsOwner(fk.Owner):
    """The owner's runner with what the Headscale import asks of it beyond the other importers': a service that can be started,
    a configuration file that can be a link."""

    def systemctl(self, *args, **kwargs):
        self.calls.append(('systemctl', *args))
        self.world.systemctl(args)
        return Result(0, b'', b'')

    def stat_files(self, rels):
        return {rel: {'path': rel, 'type': 'link' if rel in self.world.links else 'file', 'size': 1, 'mode': 0o644}
                for rel in rels}

    def dir_pack(self, rel, *, stdout, timeout=None, max_output=None, abort=None):
        pack = self.world.dirs.get(rel)
        if isinstance(pack, list):   # one answer per call; the last one stays
            self.world.dirs[rel] = pack[1:] if len(pack) > 1 else pack
            pack = pack[0]
        self.calls.append(('dir_pack', rel))
        if pack is None:
            raise BackupError('not-found', f'找不到資料夾 ~/{rel}。')
        stdout.write(pack)

    def read_file(self, rel, max_bytes=None):
        if rel in self.world.links:
            raise BackupError('job-failed', '不是一般檔案。')
        data = super().read_file(rel, max_bytes)
        if max_bytes is not None and len(data) > max_bytes:
            raise BackupError('job-failed', '檔案太大。')
        return data


class World(fk.World):
    def __init__(self):
        super().__init__()
        self.owner = HsOwner(self)
        self.quadlets = {'headscale': QUADLETS}
        self.files = {'.config/headscale/headscale/config.yaml': LIVE_CONFIG}
        self.version = '0.29.4'
        self.live_db = database(prefixes=['live-headplane', 'live-mcp'])
        self.live_db_path = 'db.sqlite'
        self.live_dbs = []              # databases handed out one per export of the data volume, before `live_db`
        self.live_noise = LIVE_NOISE
        self.garbage_exports = 0        # this many exports are no tar at all
        self.exported = 0
        self.running = True             # the server container
        self.started = []
        self.db_after_start = None      # the database a started server makes
        self.links = {}                 # path of a config.yaml that is a link -> its text
        self.configtest = 0
        self.checked_volume = None
        self.checked_config = None

    def labels(self, image):
        return {'org.opencontainers.image.version': self.version} if self.version else {}

    def podman(self, args, data, stdout):
        if args[:2] == ['container', 'inspect'] and 'State.Running' in args[3]:
            return Result(0, b'true\n' if self.running else b'false\n', b'')
        if args[:3] == ['unshare', 'readlink', '--']:
            for rel, text in self.links.items():
                if args[3] == f'/home/appowner/{rel}':
                    return Result(0, text.encode() + b'\n', b'')
            return Result(1, b'', b'readlink: no link')
        return super().podman(args, data, stdout)

    def systemctl(self, args):
        if args[0] == 'start':
            self.running = True
            self.started.append(args[-1])
            if self.db_after_start is not None:
                self.live_db = self.db_after_start
        elif args[0] == 'stop':
            self.running = False

    def run(self, role, image, command, options, data):
        if role == 'hs-configtest':
            self.checked_volume = self.imported.get('hs-check')
            self.checked_config = self.imported.get('hs-config')
            return Result(self.configtest, b'', b'')
        return Result(0, b'', b'')

    def export(self, volume):
        if volume == 'headscale-data':
            self.exported += 1
            if self.exported <= self.garbage_exports:
                return b'this is no tar at all' * 100
            db = self.live_dbs.pop(0) if self.live_dbs else self.live_db
            entries = [{'name': '.', 'type': 'dir'}]
            if db is not None:
                entries.append({'name': self.live_db_path, 'data': db})
            entries += [{'name': 'noise_private.key', 'data': self.live_noise.encode(), 'mode': 0o600},
                        {'name': 'extra_records.json', 'data': b'[]'}]
            return fk.tar_of(entries)
        return fk.tar_of([{'name': '.', 'type': 'dir'}, {'name': 'hp_persist.db', 'data': b'live headplane'}])


class Clock:
    """A clock that only moves when the code waits: no test sleeps."""

    def __init__(self):
        self.now = 0.0

    def sleep(self, seconds):
        self.now += seconds

    def time(self):
        self.now += 0.01
        return self.now


class HeadscaleCase(fk.ConversionCase):
    world_class = World

    def setUp(self):
        super().setUp()
        self.addCleanup(jobs.unmask_secret, NOISE)
        self.addCleanup(jobs.unmask_secret, 'not a key')
        self.addCleanup(jobs.unmask_secret, LIVE_NOISE)
        clock = Clock()
        for name, value in (('_sleep', clock.sleep), ('_clock', clock.time)):
            patcher = mock.patch.object(hatarget, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def catalog_apps(self):
        return {'headscale': fk.app('headscale', 'Headscale VPN 控制伺服器',
                                    volumes=[{'name': 'headscale-data'}, {'name': 'headplane-data'}])}

    def upload_headscale(self, **kwargs):
        return self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar(**kwargs))], hx.ha_doc(addons=(SLUG,))))

    def live_config(self, **replace):
        text = LIVE_CONFIG
        for old, new in replace.items():
            text = text.replace(old.encode(), new.encode())
        self.world.files['.config/headscale/headscale/config.yaml'] = text

    def keys_of(self, data):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / 'db.sqlite'
        path.write_bytes(data)
        conn = sqlite3.connect(path)
        try:
            return ([row[0] for row in conn.execute('SELECT prefix FROM api_keys ORDER BY id')],
                    [row[0] for row in conn.execute('SELECT name FROM users')])
        finally:
            conn.close()

    def checked(self, ha_id):
        return self.check(ha_id, ['headscale'])[0]

    def issues(self, result, level=None):
        return {issue['id']: issue for issue in result['issues'] if level in (None, issue['level'])}

    def confirmations(self, result):
        return [issue['key'] for issue in result['issues'] if issue['level'] == 'confirm']

    def convert_confirmed(self, ha_id, **params):
        keys = self.confirmations(self.checked(ha_id))
        return self.convert(ha_id, ['headscale'], acknowledged={'headscale': keys}, **params)

    def refused(self, ha_id, code, **params):
        """The conversion that stops only this app, with nothing made."""
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['headscale'], **params)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.storage.list_backups(), [])
        return caught.exception


class CheckTests(HeadscaleCase):
    def test_a_clean_backup(self):
        result = self.checked(self.upload_headscale())
        self.assertEqual((result['ok'], result['importable'], result['blockers'], result['target_version']), (True, True, [], '0.29.4'))
        section = result['headscale']
        self.assertEqual((section['users'], section['nodes'], section['api_keys'], section['db_version'],
                          section['dns_records']), (1, 1, 2, 'v0.29.4', 1))
        self.assertEqual((section['server_url'], section['target_server_url']),
                         ('http://homeassistant.local:28080', 'https://woow-hs-podman-46.ngrok.app'))
        self.assertTrue(any('API 金鑰不會搬過來' in w for w in result['warnings']))
        self.assertFalse(self.world.runs, 'the check needs no container')
        self.assertEqual(self.world.started, [], 'a running Headscale is not touched')

    def test_what_makes_the_data_unusable_stops_only_headscale(self):
        cases = (
            ({'version': '0.1.0'}, 'version.different', 'HA 的 Headscale 是 0.29.3'),   # wave 2 (HS-12): unchanged
            ({'db': database(prefixes=[], trigger=True)}, 'headscale.db-extra-objects', '觸發程序'),   # HS-15
            ({'db': b'SQLite format 3\x00' + b'\xff' * 4000}, 'headscale.db-unusable', '已損毀'))   # HS-14
        for kwargs, issue_id, words in cases:
            with self.subTest(issue=issue_id):
                result = self.checked(self.upload_headscale(**kwargs))
                self.assertFalse(result['importable'])
                line = self.issues(result, 'stop')[issue_id]
                self.assertIn(words, line['message'] + line['action'])
                self.assertTrue(line['action'] or issue_id == 'version.different')

    def test_the_older_pages_still_read_the_sentences(self):
        result = self.checked(self.upload_headscale(noise=None))
        self.assertTrue(any('noise_private.key' in b for b in result['blockers']), result['blockers'])
        self.assertTrue(any('API 金鑰不會搬過來' in w for w in result['warnings']))


class VersionTests(HeadscaleCase):
    """HS-10, HS-11, HS-16, HS-17, HS-18: neither the add-on's version table, nor this device's version, nor what the database
    records, nor the list of migrations decides whether the data can be moved: this device's own `headscale configtest` does."""

    def test_an_addon_version_the_table_does_not_know_is_a_notice_and_the_data_moves(self):   # HS-10
        ha_id = self.upload_headscale(version='0.1.4')
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertIn('version.addon-unknown', self.issues(result, 'notice'))
        self.convert(ha_id, ['headscale'])
        self.assertEqual(self.keys_of(self.volume('headscale-data')['db.sqlite'][1])[1], ['alice'])

    def test_a_version_of_this_device_that_cannot_be_read_is_a_notice_and_the_data_moves(self):   # HS-11
        self.world.version = None
        ha_id = self.upload_headscale()
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok'], result['target_version']), (True, True, ''))
        self.assertIn('version.target-unknown', self.issues(result, 'notice'))
        self.convert(ha_id, ['headscale'])
        self.assertTrue(self.runs('hs-configtest'), 'configtest still opens the converted database')

    def test_a_database_of_another_version_is_a_notice_and_configtest_decides(self):   # HS-16
        ha_id = self.upload_headscale(db=database(prefixes=['ha'], version='v0.29.3'))
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertIn('v0.29.3', self.issues(result, 'notice')['headscale.db-version-differs']['message'])
        self.convert(ha_id, ['headscale'])

    def test_a_database_this_devices_headscale_cannot_open_stops_only_headscale(self):   # HS-16, HS-37
        self.world.configtest = 1
        error = self.refused(self.upload_headscale(db=database(prefixes=['ha'], version='v0.31.0')), 'job-failed')
        self.assertIn('configtest', error.message)
        self.assertEqual(self.world.manifests, {})

    def test_a_release_without_a_list_of_migrations_is_no_reason_to_stop(self):   # HS-17
        self.world.version = '0.29.3'
        ha_id = self.upload_headscale(version='0.1.0', db=database(prefixes=['ha'], version='v0.29.3'))
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.convert(ha_id, ['headscale'])
        self.assertTrue(self.runs('hs-configtest'))

    def test_migrations_this_release_does_not_know_are_a_notice_and_configtest_decides(self):   # HS-18
        ha_id = self.upload_headscale(db=database(prefixes=[], migrations=['999999999999-future']))
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        line = self.issues(result, 'notice')['headscale.db-version-differs']
        self.assertEqual(line['items'], ['SCHEMA_INIT'][:0] + ['999999999999-future'])
        self.convert(ha_id, ['headscale'])


class DatabaseTests(HeadscaleCase):
    def test_a_backup_without_a_database_stops_only_headscale(self):   # HS-13, HS-28
        ha_id = self.upload_headscale(db=b'')
        # an empty file is no database at all; the add-on without any file for it is the same story
        result = self.checked(ha_id)
        self.assertFalse(result['importable'])
        line = self.issues(result, 'stop')['headscale.no-database']
        self.assertIn('這台的 Headscale 不會變', line['message'])
        self.assertTrue(line['action'])
        error = self.refused(ha_id, 'incompatible')
        self.assertIn('這台的 Headscale 不會變', error.message)

    def test_a_database_that_is_only_the_header_page_is_no_database(self):   # HS-13
        db, _wal = wal_only_database(prefixes=['ha-key-1'])
        self.assertLessEqual(len(db), 4096)
        result = self.checked(self.upload_headscale(db=db))
        self.assertFalse(result['importable'], 'the header page alone is no Headscale database')
        self.assertIn('headscale.no-database', self.issues(result, 'stop'))

    def test_a_database_without_the_basic_tables_is_no_headscale_database(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / 'other.sqlite'
        conn = sqlite3.connect(path)
        conn.executescript('CREATE TABLE other(id integer); INSERT INTO other VALUES (1);')
        conn.close()
        result = self.checked(self.upload_headscale(db=path.read_bytes()))
        self.assertFalse(result['importable'])
        self.assertIn('users', self.issues(result, 'stop')['headscale.db-unusable']['message'])

    def test_this_devices_own_tables_are_not_extra_ones(self):   # HS-15: compared with this device's tables, not a list of eight
        def with_table(extra_table):
            tmp = tempfile.TemporaryDirectory()
            self.addCleanup(tmp.cleanup)
            path = Path(tmp.name) / 'db.sqlite'
            conn = sqlite3.connect(path)
            populate(conn, prefixes=['ha'])
            conn.execute(f'CREATE TABLE {extra_table}(id integer)')
            conn.commit()
            conn.close()
            return path.read_bytes()
        self.world.live_db = with_table('newer_table')   # a newer Headscale of this device has a table the constant does not know
        same = self.checked(self.upload_headscale(db=with_table('newer_table')))
        self.assertEqual((same['importable'], same['ok']), (True, True), same['issues'])
        other = self.checked(self.upload_headscale(db=with_table('foreign_table')))
        self.assertFalse(other['importable'])
        line = self.issues(other, 'stop')['headscale.db-extra-objects']
        self.assertEqual(line['items'], ['foreign_table'])
        self.assertTrue(line['action'])

    def test_a_database_larger_than_the_old_limit_is_no_refusal(self):   # HS-02
        class Big:
            kind, name, size = 'file', ha_headscale.DB, 5 * 1024 ** 3   # 5 GiB: over the four GiB of before

            def copy_to(self, out):
                out.write(b'x' * 100)
                return 100

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(habackup, 'iter_entries', return_value=[Big()]):
            src = ha_headscale.scan_member(io.BytesIO(b''), habackup.Report(), Path(tmp))
            self.assertEqual(src.db.stat().st_size, 100, 'staged whatever its size (the job watches the free space)')

    def test_this_devices_database_larger_than_the_old_limit_is_no_refusal(self):   # HS-02
        class Big:
            name, size = 'db.sqlite', 5 * 1024 ** 3
            isfile = staticmethod(lambda: True)

        class Tar:
            members = []

            def __iter__(self):
                return iter([Big()])

            def extractfile(self, member):
                return io.BytesIO(b'live database')

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        work = self.world.owner
        work.world = self.world
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(ha_headscale.hacommon, 'live_export',
                                                                     return_value=Path(tmp) / 'live-data.tar'), \
                mock.patch.object(ha_headscale.ha_odoo, '_live_tar', return_value=Tar()):
            (Path(tmp) / 'live-data.tar').write_bytes(b'')
            target = type('T', (), {'data_volume': 'headscale-data'})()
            found, _noise = ha_headscale._export_live(object(), type('A', (), {'id': 'headscale'})(), target, Path(tmp), 'db.sqlite', None)
            self.assertEqual(found['live.sqlite'].read_bytes(), b'live database')


class LayoutTests(HeadscaleCase):
    """HS-03, HS-04, HS-06: this device's own setup is no reason to refuse: the server is found by what it mounts, Headplane may
    be missing, other volumes and folders go along as they are, a configuration file that is a link into the home folder or a large
    one is read."""

    def test_the_server_is_found_by_what_it_mounts(self):   # HS-03
        quadlets = dict(QUADLETS)
        quadlets['headscale.container'] = QUADLETS['headscale.container'].replace(b'ContainerName=headscale', b'ContainerName=hs-server')
        self.world.quadlets['headscale'] = quadlets
        ha_id = self.upload_headscale()
        self.assertEqual((self.checked(ha_id)['importable']), True)
        self.convert(ha_id, ['headscale'])
        self.assertEqual(self.keys_of(self.volume('headscale-data')['db.sqlite'][1])[0], ['live-headplane', 'live-mcp'])

    def test_a_setup_without_a_server_container_stops_only_headscale(self):   # HS-03
        self.world.quadlets['headscale'] = {k: v for k, v in QUADLETS.items() if k != 'headscale.container'}
        ha_id = self.upload_headscale()
        result = self.checked(ha_id)
        self.assertFalse(result['importable'])
        line = self.issues(result, 'stop')['headscale.layout-unsupported']
        self.assertIn('找不到 Headscale 伺服器的容器', line['message'])
        self.assertTrue(line['action'])
        self.refused(ha_id, 'incompatible')

    def test_without_headplane_only_headscale_moves(self):   # HS-04
        self.world.quadlets['headscale'] = {k: v for k, v in QUADLETS.items() if 'headplane' not in k}
        self.catalog['headscale'].volumes = [{'name': 'headscale-data'}]
        ha_id = self.upload_headscale()
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertIn('headscale.headplane-absent', self.issues(result, 'auto'))
        self.convert(ha_id, ['headscale'])
        self.assertEqual(sorted(self.world.manifests['headscale']['volumes']), ['headscale-data'])

    def test_other_volumes_and_folders_are_carried_as_they_are(self):   # HS-04
        self.catalog['headscale'].volumes.append({'name': 'extra-data'})
        self.catalog['headscale'].data_dirs = [{'path': '.local/share/hs-extra'}]
        self.world.dirs['.local/share/hs-extra'] = fk.tar_of([{'name': '.', 'type': 'dir'}, {'name': 'mine.txt', 'data': b'mine'}])
        ha_id = self.upload_headscale()
        result = self.checked(ha_id)
        self.assertEqual(sorted(self.issues(result, 'auto')['headscale.extras-carried']['items']), ['.local/share/hs-extra', 'extra-data'])
        self.convert(ha_id, ['headscale'])
        items = self.world.manifests['headscale']
        self.assertEqual(sorted(items['volumes']), ['extra-data', 'headplane-data', 'headscale-data'])
        self.assertEqual(sorted(items['dirs']), ['.local/share/hs-extra'])
        self.assertEqual(self.volume('extra-data')['hp_persist.db'][1], b'live headplane', "this device's own data, as it is")

    def test_an_entry_with_a_database_export_stops_only_headscale(self):   # HS-04: what the import cannot take at all
        self.catalog['headscale'].postgres = [{'id': 'main', 'container': 'x', 'database': 'x', 'user': 'x'}]
        ha_id = self.upload_headscale()
        self.assertFalse(self.checked(ha_id)['importable'])
        self.refused(ha_id, 'incompatible')

    def test_a_config_that_is_a_link_into_the_home_folder_is_read(self):   # HS-06
        rel = '.config/headscale/headscale/config.yaml'
        self.world.links[rel] = '../real/config.yaml'
        self.world.files['.config/headscale/real/config.yaml'] = LIVE_CONFIG
        ha_id = self.upload_headscale()
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertIn('headscale.config-link-followed', self.issues(result, 'auto'))
        self.convert(ha_id, ['headscale'])
        self.assertIn(('unshare', 'readlink', '--', f'/home/appowner/{rel}'), self.world.owner.calls)

    def test_a_config_that_is_a_link_out_of_the_home_folder_or_missing_stops_only_headscale(self):   # HS-06
        rel = '.config/headscale/headscale/config.yaml'
        for name, links, files in (('out', {rel: '/etc/passwd'}, {rel: b'x'}), ('up', {rel: '../../../../etc/passwd'}, {rel: b'x'}),
                                   ('missing', {}, {})):
            with self.subTest(name=name):
                self.world.links, self.world.files = links, files
                ha_id = self.upload_headscale()
                result = self.checked(ha_id)
                self.assertFalse(result['importable'])
                line = self.issues(result, 'stop')['headscale.config-unreadable']
                self.assertTrue(line['action'])
                self.refused(ha_id, 'incompatible')

    def test_a_config_larger_than_one_mib_is_read(self):   # HS-06
        self.world.files['.config/headscale/headscale/config.yaml'] = LIVE_CONFIG + b'# ' + b'x' * (2 * 1024 * 1024) + b'\n'
        ha_id = self.upload_headscale()
        self.assertEqual((self.checked(ha_id)['importable']), True)
        self.convert(ha_id, ['headscale'])

    def test_a_path_with_spaces_or_other_letters_is_no_error(self):   # HS-08
        self.live_config()
        self.world.files['.config/headscale/headscale/config.yaml'] = LIVE_CONFIG + (
            b'database:\n  sqlite:\n    path: /var/lib/headscale/my data/\xe6\x95\xb8\xe6\x93\x9a.db\n')
        self.world.live_db_path = 'my data/數據.db'
        ha_id = self.upload_headscale()
        self.assertEqual(self.checked(ha_id)['importable'], True)
        self.convert(ha_id, ['headscale'])
        data = self.volume('headscale-data')
        self.assertEqual(self.keys_of(data['my data/數據.db'][1])[0], ['live-headplane', 'live-mcp'])

    def test_a_path_that_leaves_the_data_volume_still_stops_only_headscale(self):   # HS-08 keeps '..'
        for path in ('/var/lib/headscale/../etc/db', '/etc/headscale/db.sqlite'):
            with self.subTest(path=path):
                self.world.files['.config/headscale/headscale/config.yaml'] = LIVE_CONFIG + (
                    f'database:\n  sqlite:\n    path: {path}\n').encode()
                ha_id = self.upload_headscale()
                result = self.checked(ha_id)
                self.assertFalse(result['importable'])
                self.assertTrue(self.issues(result, 'stop')['headscale.data-path']['action'])
                self.refused(ha_id, 'incompatible')


class PrefixTests(HeadscaleCase):
    """HS-19, HS-21, HS-22: HA's IP ranges replace this device's in the converted configuration folder; without that folder the
    range stays and the devices outside it are listed; a range that cannot be read is no refusal."""
    HA_V4 = '100.200.0.0/16'

    def setUp(self):
        super().setUp()
        self.world.dirs[CONFIG_DIR] = config_dir_tar()
        self.catalog['headscale'].data_dirs = [{'path': CONFIG_DIR}]

    def upload_different(self, v6=False, **kwargs):
        config = HA_CONFIG.replace(b'100.64.0.0/10', self.HA_V4.encode())
        ips = ('100.200.0.1', 'fd7a:115c:a1e0::1')
        if v6:
            config = config.replace(b'fd7a:115c:a1e0::/48', b'fd7a:1234:5678::/48')
            ips = ('100.200.0.1', 'fd7a:1234:5678::1')
        return self.upload_headscale(config=config, db=database(prefixes=['ha'], ips=ips), **kwargs)

    def carried_config(self):
        carried = {}
        seen = fk.Adapter.import_manifest

        def import_manifest(adapter, staging_dir, **items):
            carried.update({rel: Path(path).read_bytes() for rel, path in items['dirs'].items()})
            return seen(adapter, staging_dir, **items)

        return carried, mock.patch.object(fk.Adapter, 'import_manifest', import_manifest)

    def test_the_prefixes_become_has_in_the_converted_folder(self):   # HS-22
        ha_id = self.upload_different()
        result = self.checked(ha_id)
        self.assertEqual(result['importable'], True)
        line = self.issues(result, 'confirm')['headscale.prefixes-replaced']
        self.assertEqual(line['items'], ['prefixes.v4'])
        self.assertIn(self.HA_V4, line['message'])
        self.assertNotIn('headscale.devices-outside-range', self.issues(result), 'inside the range that will be there')
        carried, patch = self.carried_config()
        with patch:
            self.convert_confirmed(ha_id)
        with tarfile.open(fileobj=io.BytesIO(carried[CONFIG_DIR])) as tar:
            members = {m.name.removeprefix('./'): tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}
        want = {**hacommon.scalars(LIVE_CONFIG.decode()), 'prefixes.v4': self.HA_V4}
        self.assertEqual(hacommon.scalars(members['config.yaml'].decode()), want, 'only the range changed')
        self.assertEqual(members['policy.json'], b'{}')
        run = self.runs('hs-configtest')[0]
        self.assertNotIn('/home/appowner/.config/headscale/headscale:/etc/headscale:ro', run[3]['--volume'])
        self.assertTrue(any(v.endswith(':/etc/headscale:ro') and 'hs-config' in v for v in run[3]['--volume']), run[3]['--volume'])
        self.assertEqual(self.world.checked_config, carried[CONFIG_DIR], 'configtest read the converted folder')

    def test_not_confirmed_stops_only_headscale_and_one_more_range_needs_the_confirmation_again(self):   # HS-22
        ha_id = self.upload_different()
        self.refused(ha_id, 'confirmation-required')
        keys = self.confirmations(self.checked(ha_id))
        both = self.upload_different(v6=True)
        with self.assertRaises(BackupError) as caught:
            self.convert(both, ['headscale'], acknowledged={'headscale': keys})
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(sorted(self.issues(self.checked(both), 'confirm')['headscale.prefixes-replaced']['items']),
                         ['prefixes.v4', 'prefixes.v6'])

    def test_an_unchanged_range_is_not_touched(self):   # HS-22
        carried, patch = self.carried_config()
        with patch:
            self.convert(self.upload_headscale(), ['headscale'])
        self.assertEqual(carried[CONFIG_DIR], config_dir_tar(), 'the folder as it is, byte for byte')
        self.assertFalse(self.world.checked_config, 'configtest read this device\'s own folder')

    def test_a_config_whose_range_cannot_be_written_stops_only_headscale(self):   # HS-22: nothing is changed that cannot be checked
        ha_id = self.upload_different()
        keys = self.confirmations(self.checked(ha_id))
        with mock.patch.object(ha_headscale, 'edit_prefixes', side_effect=ValueError('no')):
            with self.assertRaises(BackupError) as caught:
                self.convert(ha_id, ['headscale'], acknowledged={'headscale': keys})
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('prefixes', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])

    def test_without_the_folder_the_range_stays_and_the_devices_outside_it_are_listed(self):   # HS-22, HS-19
        self.catalog['headscale'].data_dirs = []
        ha_id = self.upload_different()
        result = self.checked(ha_id)
        self.assertTrue(result['importable'])
        self.assertIn(self.HA_V4, self.issues(result, 'notice')['headscale.prefixes-kept']['message'])
        self.assertNotIn('headscale.prefixes-replaced', self.issues(result))
        line = self.issues(result, 'confirm')['headscale.devices-outside-range']
        self.assertEqual(line['items'], ['100.200.0.1'])

    def test_devices_outside_the_range_are_one_line_to_confirm(self):   # HS-19
        self.catalog['headscale'].data_dirs = []
        db = database(prefixes=[], ips=('10.0.0.5', None))
        ha_id = self.upload_headscale(db=db)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, False))
        self.assertIn('不在匯入後這台的 IP 位址範圍內', self.issues(result, 'confirm')['headscale.devices-outside-range']['message'])
        self.refused(ha_id, 'confirmation-required')
        keys = self.confirmations(result)
        self.convert(ha_id, ['headscale'], acknowledged={'headscale': keys})   # confirmed: it goes on
        more = self.upload_headscale(db=database(prefixes=[], ips=('10.0.0.5', '10.0.0.6')))
        with self.assertRaises(BackupError) as caught:   # one more device is another line to confirm
            self.convert(more, ['headscale'], acknowledged={'headscale': keys})
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_a_range_that_cannot_be_read_is_no_refusal(self):   # HS-21
        self.catalog['headscale'].data_dirs = []
        ha_id = self.upload_headscale(config=b'')
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertIn('headscale.prefixes-unknown', self.issues(result, 'notice'))
        self.convert(ha_id, ['headscale'])

    def test_an_installation_with_ipv4_only_is_no_error(self):   # HS-21
        v4_only = LIVE_CONFIG.replace(b'  v6: fd7a:115c:a1e0::/48\n', b'')
        self.world.files['.config/headscale/headscale/config.yaml'] = v4_only
        self.world.dirs[CONFIG_DIR] = config_dir_tar(v4_only)
        ha_config = HA_CONFIG.replace(b'  v6: "fd7a:115c:a1e0::/48"\n', b'')
        ha_id = self.upload_headscale(config=ha_config, db=database(prefixes=['ha'], ips=('100.64.0.1', None)))
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True), result['issues'])
        self.convert(ha_id, ['headscale'])
