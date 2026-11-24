"""HA import, Headscale part (ha_headscale.py): HA's database, Noise identity and DNS records move; HA's API keys are
replaced by this device's in the sandboxed child; prefixes, versions and migrations are checked; the live image's
`headscale configtest` opens the result before it is packaged (CONTRACT section 9). Team E2."""
import gzip
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import ha_headscale, jobs
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
             trigger=False):
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


def addon_tar(*, version='0.1.3', db=None, noise=NOISE, records=RECORDS, config=HA_CONFIG, wal=None):
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
    if noise is not None:
        entries.append({'name': 'data/noise_private.key', 'data': noise.encode(), 'mode': 0o600})
    if records is not None:
        entries.append({'name': 'config/dns_records.json', 'data': records})
    return gzip.compress(hx.tar_bytes(entries), mtime=0)


class World(fk.World):
    def __init__(self):
        super().__init__()
        self.quadlets = {'headscale': QUADLETS}
        self.files = {'.config/headscale/headscale/config.yaml': LIVE_CONFIG}
        self.version = '0.29.4'
        self.live_db = database(prefixes=['live-headplane', 'live-mcp'])
        self.live_db_path = 'db.sqlite'
        self.configtest = 0
        self.checked_volume = None

    def labels(self, image):
        return {'org.opencontainers.image.version': self.version}

    def run(self, role, image, command, options, data):
        if role == 'hs-configtest':
            self.checked_volume = self.imported.get('hs-check')
            return Result(self.configtest, b'', b'')
        return Result(0, b'', b'')

    def export(self, volume):
        if volume == 'headscale-data':
            return fk.tar_of([{'name': '.', 'type': 'dir'}, {'name': self.live_db_path, 'data': self.live_db},
                              {'name': 'noise_private.key', 'data': LIVE_NOISE.encode(), 'mode': 0o600},
                              {'name': 'extra_records.json', 'data': b'[]'}])
        return fk.tar_of([{'name': '.', 'type': 'dir'}, {'name': 'hp_persist.db', 'data': b'live headplane'}])


class HeadscaleCase(fk.ConversionCase):
    world_class = World

    def setUp(self):
        super().setUp()
        self.addCleanup(jobs.unmask_secret, NOISE)
        self.addCleanup(jobs.unmask_secret, 'not a key')

    def catalog_apps(self):
        return {'headscale': fk.app('headscale', 'Headscale VPN 控制伺服器',
                                    volumes=[{'name': 'headscale-data'}, {'name': 'headplane-data'}])}

    def upload_headscale(self, **kwargs):
        return self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar(**kwargs))], hx.ha_doc(addons=(SLUG,))))

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


class CheckTests(HeadscaleCase):
    def test_a_clean_backup(self):
        result = self.check(self.upload_headscale(), ['headscale'])[0]
        self.assertEqual((result['ok'], result['blockers'], result['target_version']), (True, [], '0.29.4'))
        section = result['headscale']
        self.assertEqual((section['users'], section['nodes'], section['api_keys'], section['db_version'],
                          section['dns_records']), (1, 1, 2, 'v0.29.4', 1))
        self.assertEqual((section['server_url'], section['target_server_url']),
                         ('http://homeassistant.local:28080', 'https://woow-hs-podman-46.ngrok.app'))
        self.assertTrue(any('API 金鑰不會搬過來' in w for w in result['warnings']))
        self.assertFalse(self.world.runs, 'the check needs no container')

    def test_blockers(self):
        cases = (
            ({'version': '0.1.0'}, 'HA 的 Headscale 是 0.29.3'),
            ({'db': database(prefixes=[], version='v0.29.3')}, '資料庫記錄的版本是 v0.29.3'),
            ({'db': database(prefixes=[], migrations=['999999999999-future'])}, '不認得的升級紀錄'),
            ({'db': database(prefixes=[], trigger=True)}, '觸發程序'),
            ({'db': database(prefixes=[], ips=('10.0.0.5', None))}, '不在這台的 IP 位址範圍內'),
            ({'db': b'SQLite format 3\x00' + b'\xff' * 4000}, '已損毀'),
            ({'noise': None}, 'noise_private.key'),
            ({'noise': 'not a key'}, 'noise_private.key'),
            ({'records': b'{"name": "x"}'}, 'DNS 額外記錄'),
            ({'config': HA_CONFIG.replace(b'100.64.0.0/10', b'100.100.0.0/16')}, 'IP 位址範圍不同'),
            ({'config': b''}, '無法讀取 HA Headscale 的 IP 位址範圍'))
        for kwargs, words in cases:
            with self.subTest(words=words):
                result = self.check(self.upload_headscale(**kwargs), ['headscale'])[0]
                self.assertFalse(result['ok'])
                self.assertTrue(any(words in b for b in result['blockers']), result['blockers'])


class ConvertTests(HeadscaleCase):
    def test_the_whole_conversion(self):
        result = self.convert(self.upload_headscale(), ['headscale'])
        data = self.volume('headscale-data')
        self.assertEqual(sorted(data), ['.', 'db.sqlite', 'extra_records.json', 'noise_private.key'])
        self.assertEqual(data['noise_private.key'][1], (NOISE + '\n').encode(), "HA's identity moves")
        self.assertEqual(data['noise_private.key'][0].mode, 0o600)
        self.assertEqual(data['extra_records.json'][1], RECORDS)
        keys, users = self.keys_of(data['db.sqlite'][1])
        self.assertEqual(keys, ['live-headplane', 'live-mcp'], "only this device's API keys")
        self.assertEqual(users, ['alice'], "HA's tailnet")
        self.assertEqual(self.volume('headplane-data')['hp_persist.db'][1], b'live headplane')
        run = self.runs('hs-configtest')[0]
        self.assertEqual((run[1], run[2]), ('localhost/woow-headscale:0.29.4-r1', ['configtest']))
        self.assertEqual(run[3]['--network'], ['none'])
        self.assertIn('--read-only', run[3])
        self.assertIn('/home/appowner/.config/headscale/headscale:/etc/headscale:ro', run[3]['--volume'])
        self.assertEqual(self.world.checked_volume, self.world.volume_data['headscale-data'], 'the tested copy')
        imp = result['ha_import']
        reminders = imp['reminders_by_app']['headscale']
        self.assertIn('https://woow-hs-podman-46.ngrok.app', reminders[0])
        self.assertIn('http://homeassistant.local:28080', reminders[0])
        self.assertTrue(any('永久停用' in line for line in reminders))
        self.assertTrue(any('Woow Headscale MCP Server' in line for line in reminders))
        self.assertNotIn(NOISE, '\n'.join(self.reporter.logs))
        self.assertNotIn(NOISE, jobs.redact(f'a {NOISE} b'))

    def test_a_database_whose_data_is_only_in_the_wal(self):
        """The RPi5 add-on was killed before it checkpointed: db.sqlite is the header page, all data in the -wal. The
        WAL is carried and applied in the sandboxed child (never HA's -shm) and one checkpointed file moves."""
        db, wal = wal_only_database(prefixes=['ha-key-1'])
        self.assertLessEqual(len(db), 4096)
        self.assertGreater(len(wal), 8 * 4096)
        result = self.check(self.upload_headscale(db=db, wal=wal), ['headscale'])[0]
        self.assertEqual((result['ok'], result['headscale']['users'], result['headscale']['nodes']), (True, 1, 1))
        self.convert(self.upload_headscale(db=db, wal=wal), ['headscale'])
        data = self.volume('headscale-data')
        self.assertNotIn('db.sqlite-wal', data)
        self.assertNotIn('db.sqlite-shm', data)
        self.assertGreater(len(data['db.sqlite'][1]), len(db), 'the WAL was checkpointed into the file')
        keys, users = self.keys_of(data['db.sqlite'][1])
        self.assertEqual((keys, users), (['live-headplane', 'live-mcp'], ['alice']))
        without = self.check(self.upload_headscale(db=db), ['headscale'])[0]
        self.assertFalse(without['ok'], 'the header page alone is no Headscale database')

    def test_nondefault_identity_paths_are_used(self):
        self.world.live_db_path = 'nested/custom.db'
        self.world.files['.config/headscale/headscale/config.yaml'] = LIVE_CONFIG + (
            b'database:\n  sqlite:\n    path: /var/lib/headscale/nested/custom.db\n'
            b'noise:\n  private_key_path: /var/lib/headscale/keys/noise.key\n')
        self.convert(self.upload_headscale(), ['headscale'])
        data = self.volume('headscale-data')
        self.assertEqual(self.keys_of(data['nested/custom.db'][1])[0], ['live-headplane', 'live-mcp'])
        self.assertEqual(data['keys/noise.key'][1], (NOISE + '\n').encode())
        self.assertNotIn('db.sqlite', data)

    def test_live_policy_blocks_check_and_convert(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'db'
            path.write_bytes(self.world.live_db)
            conn = sqlite3.connect(path)
            conn.execute("INSERT INTO policies(data) VALUES ('restricted')")
            conn.commit()
            conn.close()
            self.world.live_db = path.read_bytes()
        result = self.check(self.upload_headscale(), ['headscale'])[0]
        self.assertFalse(result['ok'])
        self.assertTrue(any('存取政策' in b for b in result['blockers']))
        with self.assertRaises(BackupError):
            self.convert(self.upload_headscale(), ['headscale'])
        self.assertEqual(self.storage.list_backups(), [])

    def test_tampered_output_is_rejected_by_fresh_reader(self):
        run = ha_headscale.hasqlite.run

        def tamper(*args, **kwargs):
            answers = run(*args, **kwargs)
            if kwargs.get('outputs'):
                conn = sqlite3.connect(answers[None]['ha.sqlite'])
                conn.execute("UPDATE api_keys SET prefix='attacker' WHERE id=(SELECT min(id) FROM api_keys)")
                conn.commit()
                conn.close()
            return answers

        with mock.patch.object(ha_headscale.hasqlite, 'run', side_effect=tamper):
            with self.assertRaises(BackupError) as caught:
                self.convert(self.upload_headscale(), ['headscale'])
        self.assertIn('驗證失敗', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])

    def test_a_failed_configtest_changes_nothing(self):
        self.world.configtest = 1
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_headscale(), ['headscale'])
        self.assertIn('configtest', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])

    def test_a_damaged_live_copy_stops_the_conversion(self):
        self.world.live_db = b'SQLite format 3\x00' + b'\xff' * 4000
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_headscale(), ['headscale'])
        self.assertIn('請稍後再試一次', caught.exception.message)

    def test_records_outside_the_volume_are_a_warning(self):
        self.world.files['.config/headscale/headscale/config.yaml'] = LIVE_CONFIG.replace(
            b'/var/lib/headscale/extra_records.json', b'/etc/headscale/extra_records.json')
        result = self.check(self.upload_headscale(), ['headscale'])[0]
        self.assertTrue(result['ok'])
        self.assertTrue(any('資料卷以外' in w for w in result['warnings']))
        self.convert(self.upload_headscale(), ['headscale'])
        self.assertNotIn('extra_records.json', self.volume('headscale-data'))


CONFIG_DIR = '.config/headscale/headscale'


def config_dir_tar(config=LIVE_CONFIG, extra=()):
    return fk.tar_of([{'name': '.', 'type': 'dir', 'mode': 0o755}, {'name': 'config.yaml', 'data': config, 'mode': 0o644},
                      {'name': 'policy.json', 'data': b'{}', 'mode': 0o644}, *extra])


class ConfigFolderTests(HeadscaleCase):
    """The entry catalog-suggest drafts for the package names its read-only configuration folder as the app's host folder:
    the import carries this device's own folder instead of refusing that entry (found on an ARM64 test machine)."""
    dirs = [{'path': CONFIG_DIR}]

    def setUp(self):
        super().setUp()
        self.world.dirs[CONFIG_DIR] = config_dir_tar()

    def catalog_apps(self):
        app = super().catalog_apps()['headscale']
        app.data_dirs = list(self.dirs)
        return {'headscale': app}

    def packs(self):
        return [c for c in self.world.owner.calls if c[0] == 'dir_pack']

    def test_the_drafted_entry_is_importable_and_carries_this_devices_folder(self):
        result = self.check(self.upload_headscale(), ['headscale'])[0]
        self.assertEqual((result['ok'], result['blockers']), (True, []))
        self.assertEqual(self.packs(), [], 'the check packs nothing')
        carried = {}
        seen = fk.Adapter.import_manifest

        def import_manifest(adapter, staging_dir, **items):
            carried.update({rel: Path(path).read_bytes() for rel, path in items['dirs'].items()})
            carried['modes'] = {Path(path).stat().st_mode & 0o777 for path in items['dirs'].values()}
            return seen(adapter, staging_dir, **items)

        with mock.patch.object(fk.Adapter, 'import_manifest', import_manifest):
            self.convert(self.upload_headscale(), ['headscale'])
        self.assertEqual(self.packs(), [('dir_pack', CONFIG_DIR)])
        self.assertEqual(carried, {CONFIG_DIR: config_dir_tar(), 'modes': {0o600}}, "this device's folder, byte for byte")
        self.assertEqual(sorted(self.volume('headscale-data')),
                         ['.', 'db.sqlite', 'extra_records.json', 'noise_private.key'])

    def test_an_entry_without_the_folder_hands_over_no_folder(self):
        self.catalog['headscale'].data_dirs = []
        self.convert(self.upload_headscale(), ['headscale'])
        self.assertNotIn('dirs', self.world.manifests['headscale'])
        self.assertEqual(self.packs(), [])

    def test_any_other_folder_is_refused(self):
        for dirs in (['.config/headscale'], [CONFIG_DIR + '/sub'], [CONFIG_DIR, '.config/other'], ['.config/other'],
                     [CONFIG_DIR, CONFIG_DIR]):
            with self.subTest(dirs=dirs):
                self.catalog['headscale'].data_dirs = [{'path': d} for d in dirs]
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_headscale(), ['headscale'])
                self.assertEqual(caught.exception.code, 'incompatible')
                self.assertIn('和 Quadlet 檔不一致', caught.exception.message)
                self.assertEqual(self.packs(), [])
                self.assertEqual(self.storage.list_backups(), [])

    def test_a_config_that_changed_during_the_conversion_stops_it(self):
        for tar in (config_dir_tar(LIVE_CONFIG.replace(b'ts.local', b'other.local')),
                    fk.tar_of([{'name': '.', 'type': 'dir'}, {'name': 'sub', 'type': 'dir'},
                               {'name': 'sub/config.yaml', 'data': LIVE_CONFIG}])):
            with self.subTest(size=len(tar)):
                self.world.dirs[CONFIG_DIR] = tar
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_headscale(), ['headscale'])
                self.assertIn('設定檔在轉換期間改變了', caught.exception.message)
                self.assertEqual(self.storage.list_backups(), [])

    def test_a_folder_a_restore_would_refuse_stops_it(self):
        self.world.dirs[CONFIG_DIR] = config_dir_tar(extra=[{'name': '../escape', 'data': b'x'}])
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_headscale(), ['headscale'])
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('設定資料夾無法還原', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])


class RecordTests(unittest.TestCase):
    def test_identity_paths_reject_escapes_and_collisions(self):
        for value in ('/etc/headscale/db', '/var/lib/headscale/../db', '/var/lib/headscale/a//b'):
            with self.subTest(value=value), self.assertRaises(BackupError):
                ha_headscale.data_paths({'database.sqlite.path': value})
        with self.assertRaises(BackupError):
            ha_headscale.data_paths({'database.sqlite.path': '/var/lib/headscale/noise_private.key'})

    def test_valid_records(self):
        self.assertEqual(ha_headscale.valid_records(RECORDS), 1)
        self.assertEqual(ha_headscale.valid_records(b'[]'), 0)
        for bad in (b'{}', b'[{"name": "a", "type": "A", "value": "1", "extra": "x"}]', b'[{"name": 1}]',
                    b'[{"Name": "a", "name": "b"}]', b'not json'):
            self.assertIsNone(ha_headscale.valid_records(bad), bad)
        self.assertEqual(ha_headscale.records_rel({'dns.extra_records_path': '/var/lib/headscale/x.json'}), 'x.json')
        for path in ('/etc/headscale/x.json', '/var/lib/headscale/../x', '/var/lib/headscale/db.sqlite', ''):
            self.assertIsNone(ha_headscale.records_rel({'dns.extra_records_path': path}))


if __name__ == '__main__':
    unittest.main()
