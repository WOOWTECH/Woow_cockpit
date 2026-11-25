"""HA import, Hermes part (ha_hermes.py): the tree moves as it is with this device's owner, venv links and uv hard
links, the runtime files, wal-indexes, browser profiles and this device's managed .env lines left out, the SQLite
files checked by the sandboxed child, versions, and the texts (CONTRACT section 9). Team E2.

HAOS parity (2026-11-25, lane HERMES-HEADSCALE; rows H-01 .. H-21 of the owner's list): nothing in HA's data keeps the import
from happening -- a version the table does not know, a link or a folder where a file must be, a damaged secondary database,
an index structure the sandbox does not know, a hard link to a file that does not move, a settings file of a newer Hermes, a
program of another processor and every size limit are no refusal any more. What cannot be moved is left out and listed in the
ONE confirmation (`confirm`), the rest is noted; only what makes the data itself unusable (no or a damaged state.db, a newer
database structure, a version both known and different) stops Hermes, and then only Hermes."""
import gzip
import io
import json
import sqlite3
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import habackup, hacommon, haimport, haissues, ha_hermes, hatarget, jobs, nested
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
EVIL = 'config/omnigent-plugin/venv/evil'   # a link that leaves the data: the reader leaves it out


def sqlite_bytes(schema=32, sessions=2, messages=3, virtual=False):
    tmp = tempfile.TemporaryDirectory()
    try:
        path = Path(tmp.name) / 'state.db'
        conn = sqlite3.connect(path)
        conn.executescript('CREATE TABLE sessions(id TEXT); CREATE TABLE messages(id TEXT); '
                           'CREATE TABLE schema_version(version INTEGER);')
        if virtual:   # an FTS5 layout Hermes does not declare: the sandbox does not read such a database
            conn.execute('CREATE VIRTUAL TABLE unknown_index USING fts5(text)')
        conn.executemany('INSERT INTO sessions VALUES (?)', [(f's{i}',) for i in range(sessions)])
        conn.executemany('INSERT INTO messages VALUES (?)', [(f'm{i}',) for i in range(messages)])
        conn.execute('INSERT INTO schema_version VALUES (?)', (schema,))
        conn.commit()
        conn.close()
        return path.read_bytes()
    finally:
        tmp.cleanup()


def addon_entries(*, version='0.1.14', image_version='0.1.14', state=None, evil=True, env=ENV, config=CONFIG):
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
               {'name': 'config/.env', 'data': env, 'mode': 0o600, **own},
               {'name': 'config/config.yaml', 'data': config, **own},
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
               {'name': 'config/browser-profile', 'type': 'dir', **own},
               {'name': 'config/browser-profile/Cookies', 'data': b'session cookies', **own}]
    if evil:
        entries.append({'name': EVIL, 'type': 'symlink', 'linkname': '/etc/shadow', **own})
    if image_version is not None:
        entries.append({'name': 'config/.woow-image-version', 'data': image_version.encode() + b'\n', **own})
    return entries


def addon_tar(*, extra=(), without=(), **kwargs):
    """HA's Hermes add-on member; `without`: names of entries to leave out (they are then usually put back, changed, in `extra`)."""
    entries = [item for item in addon_entries(**kwargs) if item['name'] not in without]
    return gzip.compress(hx.tar_bytes(entries + list(extra)), mtime=0)


OWN = {'uid': 10000, 'gid': 10000}


class World(fk.World):
    def __init__(self):
        super().__init__()
        self.quadlets = {'hermes': QUADLETS}
        self.base = BASE
        self.root_owner = b'0 0 755\n'       # `podman unshare stat` of a volume's top folder
        self.exports = {}                    # a volume's export, when a test wants one

    def labels(self, image):
        return {'io.woowtech.hermes.base': self.base} if self.base else {}

    def volume_root(self, mount):
        return self.root_owner

    def export(self, volume):
        return self.exports.get(volume) or super().export(volume)


class HermesCase(fk.ConversionCase):
    world_class = World

    def setUp(self):
        super().setUp()
        for value in ('ha-openrouter', 'http://a0d7b954-litellm:4000/v1'):
            self.addCleanup(jobs.unmask_secret, value)
        patcher = mock.patch.object(hacommon, 'host_elf_machine', lambda: 0x3E)
        patcher.start()
        self.addCleanup(patcher.stop)

    def catalog_apps(self):
        return {'hermes': fk.app('hermes', 'Hermes 代理', volumes=[{'name': 'hermes-data'}, {'name': 'hermes-redis-data'}],
                                 postgres=[{'id': 'main', 'container': 'hermes-postgresql', 'database': 'hermes',
                                            'user': 'hermes'}])}

    def upload_hermes(self, **kwargs):
        return self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar(**kwargs))], hx.ha_doc(addons=(SLUG,))))

    def checked(self, ha_id):
        return self.check(ha_id, ['hermes'])[0]

    def issues(self, result, level=None):
        """{id: issue} of a check result's lines (of one level)."""
        return {issue['id']: issue for issue in result['issues'] if level in (None, issue['level'])}

    def confirmations(self, result):
        return [issue['key'] for issue in result['issues'] if issue['level'] == 'confirm']

    def convert_confirmed(self, ha_id, **params):
        """The conversion with every line of the check's own confirmation confirmed."""
        keys = self.confirmations(self.checked(ha_id))
        return self.convert(ha_id, ['hermes'], acknowledged={'hermes': keys}, **params)


class CheckTests(HermesCase):
    def test_a_clean_backup(self):
        result = self.checked(self.upload_hermes(evil=False))
        self.assertEqual((result['ok'], result['importable'], result['blockers'], result['target_version']),
                         (True, True, [], '0.22.5'))
        self.assertEqual([i['level'] for i in result['issues'] if i['level'] in ('stop', 'confirm')], [])
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
        for words in ('homeassistant', '/media', 'omnigent-plugin'):
            self.assertIn(words, joined)
        self.assertFalse(self.world.runs, 'no container is needed for Hermes')

    def test_a_link_that_leaves_the_data_is_one_line_to_confirm(self):
        result = self.checked(self.upload_hermes())
        self.assertEqual((result['importable'], result['ok']), (True, False))
        line = self.issues(result, 'confirm')['files.skipped']
        self.assertEqual(len(line['items']), 1)
        self.assertIn('omnigent-plugin/venv/evil', line['items'][0])
        self.assertIn('指到資料以外的符號連結', line['message'])

    def test_programs_for_another_processor_are_listed_and_move(self):   # H-16
        ha_id = self.upload_hermes(extra=[{'name': 'config/arm.so', 'data': ARM_ELF, **OWN}], evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        line = self.issues(result, 'notice')['hermes.foreign-programs']
        self.assertEqual(line['items'], ['arm.so'])
        self.assertIn('跑不起來', line['message'])
        self.convert(ha_id, ['hermes'])
        self.assertEqual(self.volume('hermes-data')['arm.so'][1], ARM_ELF, 'moved as it is')

    def test_a_missing_version_record_is_a_notice(self):
        result = self.checked(self.upload_hermes(image_version=None, evil=False))
        self.assertTrue(result['ok'])
        self.assertIn('hermes.image-version-missing', self.issues(result, 'notice'))
        self.assertTrue(any('.woow-image-version' in w for w in result['warnings']))

    def test_the_older_pages_still_read_the_sentences(self):
        """`blockers` holds what stops or must be confirmed, `warnings` the rest (the pages that do not know the lines)."""
        result = self.checked(self.upload_hermes(image_version='0.1.13'))
        self.assertTrue(any('指到資料以外的符號連結' in b for b in result['blockers']), result['blockers'])
        self.assertTrue(any('附加元件 0.1.13 留下的' in w for w in result['warnings']), result['warnings'])


class VersionTests(HermesCase):
    """H-06, H-07, H-09: neither the add-on's version table nor the version of this device's image nor the version record in the
    data decides whether HA's data can be moved; the data's own structure does (H-12, H-13, H-14)."""

    def test_an_addon_version_the_table_does_not_know_is_a_notice_and_the_data_moves(self):   # H-06
        ha_id = self.upload_hermes(version='0.1.15', image_version='0.1.15', evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertIn('version.addon-unknown', self.issues(result, 'notice'))
        self.assertNotIn('version.different', self.issues(result))
        self.convert(ha_id, ['hermes'])
        self.assertEqual(self.volume('hermes-data')['state.db'][1], sqlite_bytes(), 'the data moved')

    def test_a_version_of_this_device_that_cannot_be_read_is_a_notice_and_the_data_moves(self):   # H-07
        self.world.base = None
        ha_id = self.upload_hermes(evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok'], result['target_version']), (True, True, ''))
        self.assertIn('version.target-unknown', self.issues(result, 'notice'))
        self.convert(ha_id, ['hermes'])
        self.assertIn('state.db', self.volume('hermes-data'))

    def test_a_version_record_that_differs_from_the_addon_is_a_notice_and_the_data_moves(self):   # H-09
        ha_id = self.upload_hermes(image_version='0.1.13', evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertIn('0.1.13', self.issues(result, 'notice')['hermes.image-version-differs']['message'])
        self.convert(ha_id, ['hermes'])
        self.assertIn('state.db', self.volume('hermes-data'))

    def test_both_known_and_different_still_stops_only_hermes(self):   # H-08 is wave 2: unchanged
        ha_id = self.upload_hermes(version='0.1.9', image_version='0.1.9', evil=False)
        result = self.checked(ha_id)
        self.assertEqual(result['importable'], False)
        line = self.issues(result, 'stop')['version.different']
        self.assertIn('HA 的 Hermes 是 2026.8.31', line['message'])
        self.assertTrue(line['action'])
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['hermes'])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertEqual(self.storage.list_backups(), [])

    def test_a_newer_settings_file_is_a_notice_and_moves_as_it_is(self):   # H-14
        config = CONFIG.replace(b'_config_version: 51', b'_config_version: 99')
        ha_id = self.upload_hermes(config=config, evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertIn('99', self.issues(result, 'notice')['hermes.config-newer']['message'])
        self.convert(ha_id, ['hermes'])
        self.assertEqual(self.volume('hermes-data')['config.yaml'][1], config)

    def test_a_newer_database_structure_still_stops_only_hermes(self):   # H-13 (kept)
        result = self.checked(self.upload_hermes(state=sqlite_bytes(schema=33), evil=False))
        self.assertFalse(result['importable'])
        self.assertIn('比這台的 Hermes 新', self.issues(result, 'stop')['hermes.schema-newer']['message'])
        self.assertIn('更新這台的 Hermes', self.issues(result, 'stop')['hermes.schema-newer']['action'])


BAD_DB = b'SQLite format 3\x00' + b'\xff' * 4000


class DatabaseTests(HermesCase):
    """H-10, H-11 and the databases of H-02: a missing or damaged state.db stops only Hermes; a secondary database that is
    damaged or stands where a link is stays out with its WAL, listed in the one confirmation; an index structure the sandbox does
    not know is moved unchecked."""

    def secondary(self, name='kanban.db', data=BAD_DB, wal=b'wal-bytes'):
        return [{'name': f'config/{name}', 'data': data, **OWN}, {'name': f'config/{name}-wal', 'data': wal, **OWN}]

    def test_a_backup_without_state_db_stops_only_hermes(self):   # H-10
        ha_id = self.upload_hermes(without=('config/state.db',), evil=False)
        result = self.checked(ha_id)
        self.assertFalse(result['importable'])
        line = self.issues(result, 'stop')['hermes.no-state-db']
        self.assertIn('這台的 Hermes 不會變', line['message'])
        self.assertTrue(line['action'])
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['hermes'])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertEqual(self.storage.list_backups(), [], 'nothing was made')
        self.assertEqual(self.world.manifests, {})

    def test_a_damaged_main_database_stops_only_hermes(self):   # H-11
        ha_id = self.upload_hermes(state=BAD_DB, evil=False)
        result = self.checked(ha_id)
        self.assertFalse(result['importable'])
        self.assertIn('已損毀', self.issues(result, 'stop')['hermes.state-db-unusable']['message'])
        with self.assertRaises(BackupError):
            self.convert(ha_id, ['hermes'])
        self.assertEqual(self.storage.list_backups(), [])

    def test_a_main_database_that_stands_where_a_link_is_stops_only_hermes(self):   # H-02: the main one is a link
        link = [{'name': 'config/state.db', 'type': 'symlink', 'linkname': '/opt/data/other.db', **OWN}]
        result = self.checked(self.upload_hermes(without=('config/state.db',), extra=link, evil=False))
        self.assertFalse(result['importable'])
        self.assertIn('不是一般檔案', self.issues(result, 'stop')['hermes.state-db-unusable']['message'])

    def test_a_damaged_secondary_database_is_left_out_with_its_wal(self):   # H-11
        ha_id = self.upload_hermes(extra=self.secondary(), evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, False))
        line = self.issues(result, 'confirm')['hermes.databases-skipped']
        self.assertEqual(line['items'], ['kanban.db'])
        with self.assertRaises(BackupError) as caught:   # not confirmed: only Hermes stops, nothing is made
            self.convert(ha_id, ['hermes'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(self.storage.list_backups(), [])
        self.convert_confirmed(ha_id)   # confirmed: it goes on
        names = set(self.volume('hermes-data'))
        self.assertTrue({'state.db'} <= names)
        self.assertFalse({'kanban.db', 'kanban.db-wal'} & names, 'the database and its WAL stay out together')
        # one more database that stays out is another line to confirm
        two = self.upload_hermes(extra=self.secondary() + self.secondary('projects.db'), evil=False)
        with self.assertRaises(BackupError) as caught:
            self.convert(two, ['hermes'], acknowledged={'hermes': self.confirmations(result)})
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_a_secondary_database_whose_wal_is_a_link_stays_out_whole(self):   # H-02: a group with a member that is no file
        link = {'name': 'config/kanban.db-wal', 'type': 'symlink', 'linkname': '/opt/data/other', **OWN}
        extra = [{'name': 'config/kanban.db', 'data': sqlite_bytes(), **OWN}, link]
        ha_id = self.upload_hermes(extra=extra, evil=False)
        result = self.checked(ha_id)
        confirms = self.issues(result, 'confirm')
        self.assertEqual(confirms['hermes.databases-skipped']['items'], ['kanban.db'])
        self.assertEqual(confirms['hermes.entries-skipped']['items'], ['kanban.db-wal'])
        self.convert_confirmed(ha_id)
        self.assertFalse({'kanban.db', 'kanban.db-wal'} & set(self.volume('hermes-data')))

    def test_an_index_structure_the_sandbox_does_not_know_moves_unchecked(self):   # H-11
        state = sqlite_bytes(virtual=True)
        ha_id = self.upload_hermes(state=state, evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        line = self.issues(result, 'notice')['hermes.db-unchecked']
        self.assertEqual(line['items'], ['state.db'])
        self.convert(ha_id, ['hermes'])
        self.assertEqual(self.volume('hermes-data')['state.db'][1], state, 'moved as it is')

    def test_the_other_parts_of_a_damaged_group_do_not_reach_the_sandbox(self):
        seen = []
        run = ha_hermes.hasqlite.run

        def spy(specs, files, *args, **kwargs):
            seen.append(sorted(files))
            return run(specs, files, *args, **kwargs)

        link = {'name': 'config/kanban.db-wal', 'type': 'symlink', 'linkname': '/opt/data/other', **OWN}
        with mock.patch.object(ha_hermes.hasqlite, 'run', side_effect=spy):
            self.checked(self.upload_hermes(extra=[{'name': 'config/kanban.db', 'data': sqlite_bytes(), **OWN}, link],
                                            evil=False))
        self.assertEqual(seen, [['state.db']])


class EntryTests(HermesCase):
    """H-02, H-15: a link or a folder where a file must be is left out and listed -- the one confirmation -- and nothing else
    stops."""

    def test_every_special_file_that_is_a_link_is_left_out_and_listed(self):
        for name in ('.env', 'config.yaml', 'cron/jobs.json', '.woow-image-version'):
            with self.subTest(name=name):
                link = {'name': f'config/{name}', 'type': 'symlink', 'linkname': '/opt/data/elsewhere', **OWN}
                ha_id = self.upload_hermes(without=(f'config/{name}',), extra=[link], evil=False)
                result = self.checked(ha_id)
                self.assertTrue(result['importable'], result['issues'])
                self.assertEqual(self.issues(result, 'confirm')['hermes.entries-skipped']['items'], [name])
                self.assertEqual(self.issues(result, 'stop'), {})
                with self.assertRaises(BackupError) as caught:
                    self.convert(ha_id, ['hermes'])
                self.assertEqual(caught.exception.code, 'confirmation-required')
                self.convert_confirmed(ha_id)
                self.assertNotIn(name, self.volume('hermes-data'))
                self.assertIn('state.db', self.volume('hermes-data'))

    def test_an_env_that_is_a_link_is_no_refusal(self):   # H-15: the old refusal could not even be reached
        link = {'name': 'config/.env', 'type': 'symlink', 'linkname': '/opt/data/elsewhere', **OWN}
        result = self.checked(self.upload_hermes(without=('config/.env',), extra=[link], evil=False))
        self.assertTrue(result['importable'])
        self.assertFalse([i for i in result['issues'] if 'symbolic' in i['message'] or '會拒絕啟動' in i['message']])
        self.assertEqual(self.issues(result, 'stop'), {})

    def test_a_folder_where_a_file_must_be_goes_with_what_lies_below_it(self):
        entries = [{'name': 'config/config.yaml', 'type': 'dir', **OWN},
                   {'name': 'config/config.yaml/inner.txt', 'data': b'inner', **OWN}]
        ha_id = self.upload_hermes(without=('config/config.yaml',), extra=entries, evil=False)
        result = self.checked(ha_id)
        self.assertEqual(self.issues(result, 'confirm')['hermes.entries-skipped']['items'], ['config.yaml'])
        self.convert_confirmed(ha_id)
        names = set(self.volume('hermes-data'))
        self.assertFalse({'config.yaml', 'config.yaml/inner.txt'} & names)

    def test_a_cron_that_is_a_file_is_left_out(self):
        entries = [{'name': 'config/cron', 'data': b'not a folder', **OWN}]
        ha_id = self.upload_hermes(without=('config/cron', 'config/cron/jobs.json'), extra=entries, evil=False)
        result = self.checked(ha_id)
        self.assertEqual(self.issues(result, 'confirm')['hermes.entries-skipped']['items'], ['cron'])
        self.convert_confirmed(ha_id)
        self.assertNotIn('cron', self.volume('hermes-data'))

    def test_one_more_entry_is_another_line_to_confirm(self):
        link = lambda name: {'name': f'config/{name}', 'type': 'symlink', 'linkname': '/opt/data/x', **OWN}   # noqa: E731
        first = self.upload_hermes(without=('config/.env',), extra=[link('.env')], evil=False)
        keys = self.confirmations(self.checked(first))
        second = self.upload_hermes(without=('config/.env', 'config/config.yaml'),
                                    extra=[link('.env'), link('config.yaml')], evil=False)
        self.convert(first, ['hermes'], acknowledged={'hermes': keys})
        with self.assertRaises(BackupError) as caught:
            self.convert(second, ['hermes'], acknowledged={'hermes': keys})
        self.assertEqual(caught.exception.code, 'confirmation-required')


class LinkTests(HermesCase):
    """H-01: a hard link to a file that does not move (a runtime file) is copied as a file; one the reader may never copy is left
    out and listed."""
    PID_LINK = {'name': 'config/pid-link', 'type': 'hardlink', 'linkname': 'config/gateway.pid', **OWN}
    COOKIE_LINK = {'name': 'config/cookie-link', 'type': 'hardlink', 'linkname': 'config/browser-profile/Cookies', **OWN}

    def test_a_hard_link_to_a_runtime_file_is_copied_as_a_file(self):
        ha_id = self.upload_hermes(extra=[self.PID_LINK], evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertIn('1 個硬連結', self.issues(result, 'auto')['hermes.links-copied']['message'])
        self.convert(ha_id, ['hermes'])
        data = self.volume('hermes-data')
        member, content = data['pid-link']
        self.assertEqual((member.isreg(), member.islnk(), content), (True, False, b'123'))
        self.assertNotIn('gateway.pid', data, 'the runtime file itself is still left out')

    def test_a_hard_link_to_a_file_that_may_never_be_copied_is_left_out_and_listed(self):
        ha_id = self.upload_hermes(extra=[self.COOKIE_LINK], evil=False)
        result = self.checked(ha_id)
        line = self.issues(result, 'confirm')['files.skipped']
        self.assertIn('取不到內容的硬連結', line['message'])
        self.assertEqual(self.issues(result, 'auto'), {})
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['hermes'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(self.storage.list_backups(), [])
        self.convert_confirmed(ha_id)
        data = self.volume('hermes-data')
        self.assertNotIn('cookie-link', data)
        self.assertFalse([name for name, (_m, content) in data.items() if content and b'session cookies' in content],
                         'the browser login profile is never copied, also not through a link')

    def test_one_more_hard_link_that_stays_out_is_another_line_to_confirm(self):
        first = self.upload_hermes(extra=[self.COOKIE_LINK], evil=False)
        keys = self.confirmations(self.checked(first))
        second = self.upload_hermes(extra=[self.COOKIE_LINK, {**self.COOKIE_LINK, 'name': 'config/cookie-link-2'}], evil=False)
        self.convert(first, ['hermes'], acknowledged={'hermes': keys})
        with self.assertRaises(BackupError) as caught:
            self.convert(second, ['hermes'], acknowledged={'hermes': keys})
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_the_check_and_the_conversion_judge_a_link_the_same_way(self):
        report = habackup.Report(names=haissues.Names)
        with tempfile.TemporaryDirectory() as tmp:
            member = hx.tar_bytes([{'name': 'config', 'type': 'dir', **OWN}, {'name': 'config/gateway.pid', 'data': b'1'},
                                   {'name': 'config/a', 'type': 'hardlink', 'linkname': 'config/gateway.pid'}])
            count = ha_hermes._Count(report)
            src = ha_hermes.scan_member(io.BytesIO(member), report, Path(tmp), count)
        self.assertEqual((count.copied, src.copied, count.counts['files']), (1, 1, 1))


class SizeTests(HermesCase):
    """H-18, H-19, H-20, H-21: no size refuses Hermes. A file that does not move is only read at its start, a `.env` is filtered up
    to MAX_ENV (a larger one is left out and listed: it cannot be filtered in memory), a settings file, a job list and a skill are
    copied as they are and read for what they say up to SCAN_MAX."""
    MIB = 1024 * 1024

    def test_a_version_record_over_one_kib_is_read_at_its_start_only(self):   # H-18
        ha_id = self.upload_hermes(image_version='9' * 5000, evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertEqual(self.issues(result, 'stop'), {})
        self.assertIn('.woow-image-version', result['hermes']['skipped'])
        self.convert(ha_id, ['hermes'])
        self.assertNotIn('.woow-image-version', self.volume('hermes-data'))

    def test_an_env_over_the_old_limit_moves_filtered(self):   # H-19
        env = ENV + b'# ' + b'x' * (self.MIB + 100) + b'\n'
        ha_id = self.upload_hermes(env=env, evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.convert(ha_id, ['hermes'])
        moved = self.volume('hermes-data')['.env'][1]
        self.assertIn(b'OPENROUTER_API_KEY=ha-openrouter', moved)
        self.assertNotIn(b'API_SERVER_KEY', moved)
        self.assertGreater(len(moved), self.MIB)

    def test_an_env_too_large_to_filter_is_left_out_and_listed(self):   # H-19
        env = ENV + b'# ' + b'x' * 5000 + b'\n'
        ha_id = self.upload_hermes(env=env, evil=False)
        with mock.patch.object(ha_hermes, 'MAX_ENV', 4096):
            result = self.checked(ha_id)
            line = self.issues(result, 'confirm')['files.skipped']
            self.assertIn('大小超出上限的設定檔', line['message'])
            self.assertTrue(result['importable'])
            with self.assertRaises(BackupError) as caught:
                self.convert(ha_id, ['hermes'])
            self.assertEqual(caught.exception.code, 'confirmation-required')
            self.convert_confirmed(ha_id)
        self.assertNotIn('.env', self.volume('hermes-data'), 'never moved unfiltered')

    def test_a_settings_file_and_a_job_list_over_the_old_limit_move_and_are_read(self):   # H-20
        config = CONFIG + b'# ' + b'y' * (9 * self.MIB) + b'\n'
        jobs_json = b'{"jobs": [' + b','.join(b'{"id": "j%d"}' % n for n in range(520000)) + b']}'
        self.assertGreater(len(jobs_json), 8 * self.MIB)
        ha_id = self.upload_hermes(config=config, evil=False,
                                   without=('config/cron/jobs.json',),
                                   extra=[{'name': 'config/cron/jobs.json', 'data': jobs_json, **OWN}])
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertEqual((result['hermes']['config_version'], result['hermes']['cron_jobs']), (51, 520000))
        self.convert(ha_id, ['hermes'])
        self.assertEqual(self.volume('hermes-data')['config.yaml'][1], config)

    def test_a_text_file_larger_than_what_is_read_is_copied_unread(self):   # H-20
        config = CONFIG + b'# ' + b'y' * 20000 + b'\n'
        ha_id = self.upload_hermes(config=config, evil=False)
        with mock.patch.object(ha_hermes, 'SCAN_MAX', 4096):
            result = self.checked(ha_id)
            self.assertEqual((result['importable'], result['ok']), (True, True))
            line = self.issues(result, 'notice')['hermes.text-unread']
            self.assertIn('config.yaml', line['items'])
            self.assertIsNone(result['hermes']['config_version'], 'its content was not read')
            self.convert(ha_id, ['hermes'])
        self.assertEqual(self.volume('hermes-data')['config.yaml'][1], config, 'copied as it is')

    def test_a_skill_over_the_old_limit_is_copied(self):   # H-21
        skill = b'see /media/notes\n' + b'z' * (5 * self.MIB)
        extra = [{'name': 'config/skills/big', 'type': 'dir', **OWN},
                 {'name': 'config/skills/big/SKILL.md', 'data': skill, **OWN}]
        ha_id = self.upload_hermes(extra=extra, evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertEqual(result['hermes']['skills'], 2)
        self.convert(ha_id, ['hermes'])
        self.assertEqual(self.volume('hermes-data')['skills/big/SKILL.md'][1], skill)
        with mock.patch.object(ha_hermes, 'SCAN_MAX', 1024):   # and beyond what is read: copied unread, still counted
            again = self.checked(ha_id)
            self.assertEqual(again['hermes']['skills'], 2)
            self.assertIn('skills/big/SKILL.md', self.issues(again, 'notice')['hermes.text-unread']['items'])

    def test_a_hostile_env_registers_a_bounded_number_of_secrets(self):
        before = dict(jobs._MASK_COUNTS)
        env = b''.join(b'KEY%d=value-of-key-%08d\n' % (n, n) for n in range(5000))
        data, _keys, values = ha_hermes.strip_env(env)
        ha_hermes._mask_values(values)
        added = {value: count for value, count in jobs._MASK_COUNTS.items() if count != before.get(value, 0)}
        for value, count in added.items():
            for _ in range(count - before.get(value, 0)):
                jobs.unmask_secret(value)
        self.assertLessEqual(len(added), ha_hermes.MAX_MASKED)
        self.assertEqual(len(values), 5000)


class LayoutTests(HermesCase):
    """H-03, H-05: this device's own entry is no reason to refuse: other volumes and folders go along as they are, a cold database
    too; an owner that the settings do not say is the live folder's."""

    def cold(self):
        app = self.catalog['hermes']
        app.volumes = [{'name': 'hermes-data'}, {'name': 'hermes-redis-data'}, {'name': 'hermes-postgres-data'}]
        app.postgres = []
        app.data_dirs = [{'path': '.local/share/hermes-work'}]
        self.world.exports['hermes-postgres-data'] = fk.tar_of([{'name': '.', 'type': 'dir'},
                                                                {'name': 'PG_VERSION', 'data': b'15\n'}])
        self.world.dirs['.local/share/hermes-work'] = fk.tar_of([{'name': '.', 'type': 'dir'},
                                                                 {'name': 'notes.md', 'data': b'mine'}])

    def test_a_cold_entry_and_a_folder_are_carried_as_they_are(self):   # H-03
        self.cold()
        ha_id = self.upload_hermes(evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        line = self.issues(result, 'auto')['hermes.extras-carried']
        self.assertEqual(sorted(line['items']), ['.local/share/hermes-work', 'hermes-postgres-data'])
        self.assertFalse(self.world.owner.calls and [c for c in self.world.owner.calls if c[0] == 'dir_pack'],
                         'the check packs nothing')
        self.convert(ha_id, ['hermes'])
        items = self.world.manifests['hermes']
        self.assertEqual(sorted(items['volumes']), ['hermes-data', 'hermes-postgres-data', 'hermes-redis-data'])
        self.assertEqual(items['postgres'], {})
        self.assertEqual(sorted(items['dirs']), ['.local/share/hermes-work'])
        self.assertEqual(self.world.live_dumps, [], 'a cold entry has no dump')
        self.assertEqual(self.volume('hermes-postgres-data')['PG_VERSION'][1], b'15\n', "this device's own data, as it is")
        self.assertIn('state.db', self.volume('hermes-data'))

    def test_two_database_entries_are_both_dumped(self):   # H-03
        self.catalog['hermes'].postgres.append({'id': 'second', 'container': 'hermes-postgresql', 'database': 'other',
                                                'user': 'hermes'})
        ha_id = self.upload_hermes(evil=False)
        self.convert(ha_id, ['hermes'])
        self.assertEqual(sorted(self.world.live_dumps), ['main', 'second'])
        self.assertEqual(sorted(self.world.manifests['hermes']['postgres']), ['main', 'second'])

    def test_an_entry_that_dumps_a_whole_instance_stops_only_hermes(self):   # H-03: what the import cannot take at all
        self.catalog['hermes'].postgres[0]['scope'] = 'instance'
        ha_id = self.upload_hermes(evil=False)
        result = self.checked(ha_id)
        self.assertFalse(result['importable'])
        line = self.issues(result, 'stop')['hermes.layout-unsupported']
        self.assertIn('整個執行個體', line['message'])
        self.assertIn('單一資料庫', line['action'])
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['hermes'])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertEqual(self.storage.list_backups(), [])

    def test_an_entry_without_the_data_folder_stops_only_hermes(self):   # H-03
        self.catalog['hermes'].volumes = [{'name': 'hermes-redis-data'}]
        result = self.checked(self.upload_hermes(evil=False))
        self.assertFalse(result['importable'])
        self.assertIn('/opt/data', self.issues(result, 'stop')['hermes.layout-unsupported']['message'])

    def test_a_redis_volume_that_is_not_there_is_no_reason_to_stop(self):   # H-03
        self.catalog['hermes'].volumes = [{'name': 'hermes-data'}]
        ha_id = self.upload_hermes(evil=False)
        self.assertTrue(self.checked(ha_id)['importable'])
        self.convert(ha_id, ['hermes'])
        self.assertEqual(sorted(self.world.manifests['hermes']['volumes']), ['hermes-data'])

    def test_an_owner_the_settings_do_not_say_is_the_live_folders(self):   # H-05
        quadlets = dict(QUADLETS)
        quadlets['hermes-agent.container'] = QUADLETS['hermes-agent.container'].replace(b'HERMES_UID=1000', b'HERMES_UID=%U')
        self.world.quadlets['hermes'] = quadlets
        self.world.root_owner = b'1234 5678 700\n'
        ha_id = self.upload_hermes(evil=False)
        result = self.checked(ha_id)
        self.assertEqual((result['importable'], result['ok']), (True, True))
        self.assertIn('HERMES_UID', self.issues(result, 'auto')['hermes.owner-from-folder']['message'])
        self.convert(ha_id, ['hermes'])
        data = self.volume('hermes-data')
        self.assertEqual({(m.uid, m.gid) for name, (m, _d) in data.items()}, {(1234, 5678)})
        self.assertEqual((data['.'][0].uid, data['.'][0].mode), (1234, 0o700))

    def test_an_owner_that_cannot_be_read_stops_only_hermes(self):   # H-05
        quadlets = dict(QUADLETS)
        quadlets['hermes-agent.container'] = QUADLETS['hermes-agent.container'].replace(b'HERMES_GID=1000', b'HERMES_GID=abc')
        self.world.quadlets['hermes'] = quadlets
        self.world.root_owner = b'not numbers\n'
        ha_id = self.upload_hermes(evil=False)
        self.assertTrue(self.checked(ha_id)['importable'], 'the check does not need the folder')
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['hermes'])
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertEqual(self.storage.list_backups(), [])


class ConvertTests(HermesCase):
    def test_the_whole_conversion(self):
        result = self.convert_confirmed(self.upload_hermes())
        self.assertEqual(sorted(self.world.manifests['hermes']), ['postgres', 'volumes'])
        self.assertEqual(self.world.live_dumps, ['main'], 'the unused database stays as it is here')
        data = self.volume('hermes-data')
        names = set(data)
        for gone in ('gateway.pid', 'state.db-shm', '.woow-image-version', 'browser-profile', 'browser-profile/Cookies',
                     'omnigent-plugin/venv/evil'):
            self.assertNotIn(gone, names)
        self.assertEqual(data['state.db'][1], sqlite_bytes(), 'the database moves unchanged')
        self.assertEqual((data['state.db'][0].mode, data['state.db'][0].uid), (0o600, 1000))
        env = data['.env'][1]
        self.assertIn(b'OPENROUTER_API_KEY=ha-openrouter', env)
        for managed in (b'API_SERVER_KEY', b'WEBHOOK_SECRET', b'HERMES_DASHBOARD_BASIC_AUTH_PASSWORD'):
            self.assertNotIn(managed, env)
        self.assertEqual(data['.env'][0].mode, 0o600)
        self.assertNotIn('ha-openrouter', jobs.redact('key ha-openrouter'), 'kept provider keys are masked')
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
        row = haimport.load_registry(self.paths)[result['backup_id']]
        self.assertEqual([c['id'] for c in row['confirmed']], ['files.skipped'], 'what the customer confirmed is recorded')

    def test_the_databases_are_written_after_the_checks_and_in_the_trees_order(self):
        self.convert(self.upload_hermes(evil=False), ['hermes'])
        with __import__('tarfile').open(fileobj=io.BytesIO(self.world.volume_data['hermes-data'])) as tar:
            names = tar.getnames()
        self.assertEqual(names.count('state.db'), 1)
        self.assertGreater(names.index('state.db'), names.index('config.yaml'), 'the databases come last')

    def test_the_mcp_admin_line_names_this_devices_app(self):
        self.catalog['hermes-mcp-admin'] = fk.app('hermes-mcp-admin', 'Hermes MCP 管理（這台）')
        result = self.convert_confirmed(self.upload_hermes())
        self.assertTrue(any('「Hermes MCP 管理（這台）」' in line
                            for line in result['ha_import']['reminders_by_app']['hermes']))

    def test_a_conversion_that_is_not_confirmed_makes_nothing(self):
        ha_id = self.upload_hermes()
        with self.assertRaises(BackupError) as caught:
            self.convert(ha_id, ['hermes'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertIn('指到資料以外的符號連結', caught.exception.message)
        self.assertEqual(self.storage.list_backups(), [])
        self.assertEqual(self.world.manifests, {})


class EnvTests(unittest.TestCase):
    def test_strip(self):
        data, keys, values = ha_hermes.strip_env(b'A=1\n  export HERMES_PASEO_ORIGIN=x\nHERMES_BASE_URL=y\n# c\nB="2"')
        self.assertEqual(data, b'A=1\n# c\nB="2"')
        self.assertEqual((keys, values), (['A', 'B'], ['1', '2']))

    def test_quoted_keys_are_filtered_and_maskable(self):
        data, keys, values = ha_hermes.strip_env(b"'API_SERVER_KEY'=secret\nexport 'WEBHOOK_SECRET'=x\n'PROVIDER_KEY'=provider-secret\n")
        self.assertEqual(data, b"'PROVIDER_KEY'=provider-secret\n")
        self.assertEqual(keys, ['PROVIDER_KEY'])
        self.assertEqual(values, ['provider-secret'])

    def test_special_entries_are_left_out_and_listed_not_refused(self):
        for name in ('.env', 'config.yaml', 'cron/jobs.json', 'state.db', 'state.db-wal', 'cron'):
            for kind in ('hardlink', 'symlink'):
                with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as tmp:
                    entries = [{'name': 'config', 'type': 'dir'},
                               {'name': 'config/target', 'data': b'content'},
                               {'name': 'config/' + name, 'type': kind,
                                'linkname': 'config/target' if kind == 'hardlink' else '/opt/data/target'}]
                    report = habackup.Report(names=haissues.Names)
                    count = ha_hermes._Count(report)
                    src = ha_hermes.scan_member(io.BytesIO(hx.tar_bytes(entries)), report, Path(tmp), count)
                    self.assertEqual(list(src.specials.first), [name])
                    self.assertNotIn(name, count.files)

    def test_unknown_schema_stops(self):
        src = ha_hermes.Source()
        src.report = habackup.Report()
        src.dbs['state.db'] = 'placeholder'
        src.db_meta['state.db'] = ('state.db', 0o600, 0)
        for value in (None, '32', True, -1):
            with self.subTest(value=value):
                answers = {'state.db': {'ok': True, 'values': {'hermes.schema_version': value}}}
                blockers, _, _ = ha_hermes.analyse(src, answers, addon_version='0.1.14', release='0.22.5', digest=None)
                self.assertTrue(any('無法判讀' in b for b in blockers), blockers)

    def test_names(self):
        self.assertEqual(ha_hermes.flat('cron/executions.db-wal'), 'cron.executions.db-wal')
        self.assertEqual(ha_hermes._known_db('cron/notepad.db-journal'), 'cron/notepad.db')
        self.assertIsNone(ha_hermes._known_db('plugins/x/state.db'))


if __name__ == '__main__':
    unittest.main()
