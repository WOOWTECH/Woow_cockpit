"""HA import, Hermes part (ha_hermes.py): the tree moves as it is with this device's owner, venv links and uv hard
links, the runtime files, wal-indexes, browser profiles and this device's managed .env lines left out, the SQLite
files checked by the sandboxed child, versions, and the texts (CONTRACT section 9). Team E2."""
import gzip
import io
import json
import sqlite3
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import habackup, hacommon, ha_hermes, nested
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import hab1fakes as fk
from . import hafixtures as hx

SLUG = '1b7b4ce7_woow-hermes'
BASE = 'docker.io/nousresearch/hermes-agent:v0.22.5@' + ha_hermes.BASE_DIGESTS['0.22.5']
QUADLETS = {
    'hermes-agent.container': b'[Container]\nContainerName=hermes-agent\nImage=localhost/woow-hermes-agent:v0.22.5-woow4\n'
                              b'Volume=hermes-data.volume:/opt/data\nEnvironment=HERMES_UID=1000\n'
                              b'Environment=HERMES_GID=1000\nEnvironmentFile=%h/.config/hermes/hermes.env\n'
                              b'Secret=hermes-api-server-key,type=env,target=API_SERVER_KEY\n',
    'hermes-postgres.container': b'[Container]\nContainerName=hermes-postgresql\nImage=docker.io/library/postgres:15.19\n'
                                 b'Volume=hermes-postgres-data.volume:/var/lib/postgresql/data\n'
                                 b'Environment=POSTGRES_USER=hermes\n',
    'hermes-redis.container': b'[Container]\nContainerName=hermes-redis\nImage=docker.io/library/redis:7.4.11-alpine\n'
                              b'Volume=hermes-redis-data.volume:/data\n',
    'hermes-data.volume': b'[Volume]\nVolumeName=hermes-data\n',
    'hermes-postgres-data.volume': b'[Volume]\nVolumeName=hermes-postgres-data\n',
    'hermes-redis-data.volume': b'[Volume]\nVolumeName=hermes-redis-data\n',
    'hermes.network': b'[Network]\n',
}
ENV = (b'OPENROUTER_API_KEY=ha-openrouter\nAPI_SERVER_KEY=ha-api-key\nexport WEBHOOK_SECRET=ha-webhook\n'
       b'HERMES_DASHBOARD_BASIC_AUTH_PASSWORD=ha-dash\nOPENAI_BASE_URL=http://a0d7b954-litellm:4000/v1\n')
CONFIG = (b'_config_version: 51\nmodel:\n  provider: custom\n  base_url: http://homeassistant:8123/api\n'
          b'tools:\n  output: /media/hermes\n')
ARM_ELF = b'\x7fELF\x02\x01\x01' + bytes(11) + b'\xb7\x00' + bytes(40)


def sqlite_bytes(schema=32, sessions=2, messages=3):
    tmp = tempfile.TemporaryDirectory()
    try:
        path = Path(tmp.name) / 'state.db'
        conn = sqlite3.connect(path)
        conn.executescript('CREATE TABLE sessions(id TEXT); CREATE TABLE messages(id TEXT); '
                           'CREATE TABLE schema_version(version INTEGER);')
        conn.executemany('INSERT INTO sessions VALUES (?)', [(f's{i}',) for i in range(sessions)])
        conn.executemany('INSERT INTO messages VALUES (?)', [(f'm{i}',) for i in range(messages)])
        conn.execute('INSERT INTO schema_version VALUES (?)', (schema,))
        conn.commit()
        conn.close()
        return path.read_bytes()
    finally:
        tmp.cleanup()


def addon_tar(*, version='0.1.14', image_version='0.1.14', state=None, extra=()):
    addon = {'user': {'version': version, 'image': 'ghcr.io/woowtech/woow-ha-hermes-amd64',
                      'options': {'dashboard_password': 'ha-option-secret'}},
             'system': {'slug': 'woow-hermes', 'name': 'Woow Hermes Agent'}, 'version': version}
    own = {'uid': 10000, 'gid': 10000}
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': json.dumps(addon).encode()},
               {'name': 'data', 'type': 'dir'}, {'name': 'data/options.json', 'data': b'{}'},
               {'name': 'data/secrets', 'type': 'dir'},
               {'name': 'data/secrets/dashboard_password', 'data': b'ha-generated-secret'},
               {'name': 'config', 'type': 'dir', **own},
               {'name': 'config/state.db', 'data': state if state is not None else sqlite_bytes(), 'mode': 0o600, **own},
               {'name': 'config/state.db-shm', 'data': b'shm', **own},
               {'name': 'config/.env', 'data': ENV, 'mode': 0o600, **own},
               {'name': 'config/config.yaml', 'data': CONFIG, **own},
               {'name': 'config/gateway.pid', 'data': b'123', **own},
               {'name': 'config/cron', 'type': 'dir', **own},
               {'name': 'config/cron/jobs.json', 'data': b'{"jobs": [{"id": "a"}, {"id": "b"}]}', **own},
               {'name': 'config/skills', 'type': 'dir', **own}, {'name': 'config/skills/demo', 'type': 'dir', **own},
               {'name': 'config/skills/demo/SKILL.md', 'data': b'see /media/notes', **own},
               {'name': 'config/plugins', 'type': 'dir', **own},
               {'name': 'config/plugins/omnigent-plugin', 'type': 'dir', **own},
               {'name': 'config/omnigent-plugin', 'type': 'dir', **own},
               {'name': 'config/omnigent-plugin/uv', 'type': 'dir', **own},
               {'name': 'config/omnigent-plugin/uv/lib.so', 'data': b'\x7fELF\x02\x01\x01' + bytes(11) + b'\x3e\x00',
                'mode': 0o4755, **own},
               {'name': 'config/omnigent-plugin/venv', 'type': 'dir', **own},
               {'name': 'config/omnigent-plugin/venv/lib.so', 'type': 'hardlink',
                'linkname': 'config/omnigent-plugin/uv/lib.so', **own},
               {'name': 'config/omnigent-plugin/venv/python', 'type': 'symlink',
                'linkname': '/opt/data/omnigent-plugin/uv/python/bin/python3.12', **own},
               {'name': 'config/omnigent-plugin/venv/rel', 'type': 'symlink', 'linkname': '../uv/lib.so', **own},
               {'name': 'config/omnigent-plugin/venv/evil', 'type': 'symlink', 'linkname': '/etc/shadow', **own},
               {'name': 'config/browser-profile', 'type': 'dir', **own},
               {'name': 'config/browser-profile/Cookies', 'data': b'session cookies', **own}]
    if image_version is not None:
        entries.append({'name': 'config/.woow-image-version', 'data': image_version.encode() + b'\n', **own})
    return gzip.compress(hx.tar_bytes(entries + list(extra)), mtime=0)


class World(fk.World):
    def __init__(self):
        super().__init__()
        self.quadlets = {'hermes': QUADLETS}
        self.base = BASE

    def labels(self, image):
        return {'io.woowtech.hermes.base': self.base} if self.base else {}


class HermesCase(fk.ConversionCase):
    world_class = World

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hacommon, 'host_elf_machine', lambda: 0x3E)
        patcher.start()
        self.addCleanup(patcher.stop)

    def catalog_apps(self):
        return {'hermes': fk.app('hermes', 'Hermes 代理', volumes=[{'name': 'hermes-data'}, {'name': 'hermes-redis-data'}],
                                 postgres=[{'id': 'main', 'container': 'hermes-postgresql', 'database': 'hermes',
                                            'user': 'hermes'}])}

    def upload_hermes(self, **kwargs):
        return self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar(**kwargs))], hx.ha_doc(addons=(SLUG,))))


class CheckTests(HermesCase):
    def test_a_clean_backup(self):
        result = self.check(self.upload_hermes(), ['hermes'])[0]
        self.assertEqual((result['ok'], result['blockers'], result['target_version']), (True, [], '0.22.5'))
        section = result['hermes']
        self.assertEqual((section['sessions'], section['messages'], section['schema_version'], section['config_version']),
                         (2, 3, 32, 51))
        self.assertEqual((section['absolute_symlinks'], section['hardlinks'], section['skills'], section['cron_jobs']),
                         (1, 1, 1, 2))
        self.assertEqual(section['plugins'], ['omnigent-plugin'])
        self.assertEqual(section['ha_urls'], ['.env：a0d7b954-litellm', 'config.yaml：homeassistant'])
        self.assertEqual(section['media_refs'], 2)
        self.assertEqual(sorted(section['skipped']), ['.woow-image-version', 'gateway.pid', 'state.db-shm'])
        joined = '\n'.join(result['warnings'])
        for words in ('homeassistant', '/media', 'omnigent-plugin', '1 個指向資料以外的符號連結'):
            self.assertIn(words, joined)
        self.assertFalse(self.world.runs, 'no container is needed for Hermes')

    def test_blockers(self):
        cases = (({'version': '0.1.9', 'image_version': '0.1.9'}, 'HA 的 Hermes 是 2026.8.31'),
                 ({'image_version': '0.1.13'}, '附加元件 0.1.13 留下的'),
                 ({'state': b'SQLite format 3\x00' + b'\xff' * 4000}, '已損毀'),
                 ({'state': sqlite_bytes(schema=33)}, '比這台的 Hermes 新'),
                 ({'extra': [{'name': 'config/arm.so', 'data': ARM_ELF}]}, '其他處理器的程式'),
                 ({'extra': [{'name': 'config/pid-link', 'type': 'hardlink', 'linkname': 'config/gateway.pid'}]},
                  '硬連結'))
        for kwargs, words in cases:
            with self.subTest(words=words):
                result = self.check(self.upload_hermes(**kwargs), ['hermes'])[0]
                self.assertFalse(result['ok'])
                self.assertTrue(any(words in b for b in result['blockers']), result['blockers'])
        self.world.base = None
        result = self.check(self.upload_hermes(), ['hermes'])[0]
        self.assertIn('無法讀取這台 Hermes 的版本', result['blockers'][0])

    def test_a_missing_version_record_is_a_warning(self):
        result = self.check(self.upload_hermes(image_version=None), ['hermes'])[0]
        self.assertTrue(result['ok'])
        self.assertTrue(any('.woow-image-version' in w for w in result['warnings']))


class ConvertTests(HermesCase):
    def test_the_whole_conversion(self):
        result = self.convert(self.upload_hermes(), ['hermes'])
        self.assertEqual(sorted(self.world.manifests['hermes']), ['postgres', 'volumes'])
        self.assertEqual(self.world.live_dumps, ['main'], 'the unused database stays as it is here')
        data = self.volume('hermes-data')
        names = set(data)
        for gone in ('gateway.pid', 'state.db-shm', '.woow-image-version', 'browser-profile', 'browser-profile/Cookies',
                     'omnigent-plugin/venv/evil'):
            self.assertNotIn(gone, names)
        self.assertEqual(data['state.db'][1], sqlite_bytes(), 'the database moves unchanged')
        env = data['.env'][1]
        self.assertIn(b'OPENROUTER_API_KEY=ha-openrouter', env)
        for managed in (b'API_SERVER_KEY', b'WEBHOOK_SECRET', b'HERMES_DASHBOARD_BASIC_AUTH_PASSWORD'):
            self.assertNotIn(managed, env)
        self.assertEqual(data['.env'][0].mode, 0o600)
        link = data['omnigent-plugin/venv/lib.so'][0]
        self.assertEqual((link.islnk(), link.linkname), (True, 'omnigent-plugin/uv/lib.so'))
        venv = data['omnigent-plugin/venv/python'][0]
        self.assertEqual((venv.issym(), venv.linkname), (True, '/opt/data/omnigent-plugin/uv/python/bin/python3.12'))
        self.assertEqual(data['omnigent-plugin/uv/lib.so'][0].mode, 0o755, 'no setuid')
        owners = {(m.uid, m.gid) for name, (m, _d) in data.items() if name != '.'}
        self.assertEqual(owners, {(1000, 1000)})
        self.assertEqual((data['.'][0].uid, data['.'][0].mode), (0, 0o755), 'the live top folder')
        self.assertEqual(list(self.volume('hermes-redis-data')), ['.'])
        imp = result['ha_import']
        reminders = imp['reminders_by_app']['hermes']
        self.assertTrue(any('Omnigent 與 Paseo' in line for line in reminders))
        self.assertTrue(any('homeassistant' in line for line in reminders))
        self.assertTrue(any('Woow Hermes MCP Server' in line for line in reminders))
        self.assertTrue(imp['notes'][0].startswith('Hermes'))

    def test_the_mcp_admin_line_names_this_devices_app(self):
        self.catalog['hermes-mcp-admin'] = fk.app('hermes-mcp-admin', 'Hermes MCP 管理（這台）')
        result = self.convert(self.upload_hermes(), ['hermes'])
        self.assertTrue(any('「Hermes MCP 管理（這台）」' in line
                            for line in result['ha_import']['reminders_by_app']['hermes']))

    def test_a_hard_link_to_a_file_that_does_not_move_stops_the_conversion(self):
        extra = [{'name': 'config/pid-link', 'type': 'hardlink', 'linkname': 'config/gateway.pid'}]
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_hermes(extra=extra), ['hermes'])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertEqual(self.storage.list_backups(), [])


class EnvTests(unittest.TestCase):
    def test_strip(self):
        data, keys = ha_hermes.strip_env(b'A=1\n  export HERMES_PASEO_ORIGIN=x\nHERMES_BASE_URL=y\n# c\nB=2')
        self.assertEqual(data, b'A=1\n# c\nB=2')
        self.assertEqual(keys, ['A', 'B'])

    def test_names(self):
        self.assertEqual(ha_hermes.flat('cron/executions.db-wal'), 'cron.executions.db-wal')
        self.assertEqual(ha_hermes._known_db('cron/notepad.db-journal'), 'cron/notepad.db')
        self.assertIsNone(ha_hermes._known_db('plugins/x/state.db'))


if __name__ == '__main__':
    unittest.main()
