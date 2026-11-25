"""HA import, OpenDesign part (ha_opendesign.py): HA's daemon data moves with this device's owner, this device's agent
logins, Omnigent and Paseo identities, installation id and MCP volume stay, HA's preferences are merged and its paths
remapped, the database is checked by the sandboxed child, versions, blockers and the texts (CONTRACT section 9).
Team E2. HAOS parity (2026-11-25, lane OPENDESIGN-CODESERVER): OP-01 .. OP-16 (the versions only inform, what is left out
is one line to confirm, a hard link gets the content, a read that fails is tried again and then done with the app's own
containers paused) -- see the classes ParityCheckTests .. ParityLiveTests."""
import gzip
import io
import json
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import habackup, haissues, hacommon, ha_opendesign as od, hasqlite, hatarget
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import hab1fakes as fk
from . import hafixtures as hx

SLUG = '1b7b4ce7_woow_ha_opendesign'
REV = od.VERSIONS['0.2.15'][1]
DATA = 'open-design_open_design_data'
MCP = 'open-design_mcp_data'
QUADLETS = {
    'open-design.container': b'[Container]\nContainerName=open-design\nImage=localhost/woow-open-design:4.2.1\n'
                             b'UserNS=keep-id:uid=1001,gid=1001\nVolume=open-design-data.volume:/app/.od\n'
                             b'Secret=open-design-api-token,type=env,target=OD_API_TOKEN\n',
    'open-design-terminal.container': b'[Container]\nContainerName=open-design-terminal\n'
                                      b'Image=localhost/woow-open-design:4.2.1\n'
                                      b'Volume=open-design-data.volume:/app/.od\n',
    'open-design-mcp.container': b'[Container]\nContainerName=open-design-mcp\nImage=localhost/woow-open-design:4.2.1\n'
                                 b'User=10001:10001\nVolume=open-design-mcp-data.volume:/data/mcp:U\n'
                                 b'Volume=open-design-mcp-run.volume:/run/od-mcp:U\n',
    'open-design-nginx.container': b'[Container]\nContainerName=open-design-nginx\n'
                                   b'Image=docker.io/library/nginx:1.30.4-alpine\n'
                                   b'Volume=open-design-mcp-run.volume:/run/od-mcp:ro\n',
    'open-design-data.volume': b'[Volume]\nVolumeName=open-design_open_design_data\n',
    'open-design-mcp-data.volume': b'[Volume]\nVolumeName=open-design_mcp_data\n',
    'open-design-mcp-run.volume': b'[Volume]\nVolumeName=open-design_mcp_run\n',
    'open-design.network': b'[Network]\nNetworkName=open-design\n',
}
HA_PREFS = {'onboardingCompleted': True, 'agentId': 'claude', 'installationId': 'ha-install-id',
            'agentCliEnv': {'claude': {'ANTHROPIC_API_KEY': 'ha-anthropic-key'}}, 'agentCliEnvIntent': {'claude': 'ha'},
            'customInstructions': 'HA 的指示', 'projectLocations': [
                {'id': 'ws', 'name': 'shared', 'path': '/data/opendesign/shared/workspaces/team'},
                {'id': 'tmp', 'name': 'tmp', 'path': '/tmp/elsewhere'}],
            'defaultProjectLocationId': 'tmp', 'recentLinkedDirs': ['/data/opendesign/shared/workspaces', '/share/x']}
LIVE_PREFS = {'onboardingCompleted': True, 'installationId': 'target-install-id',
              'agentCliEnv': {'codex': {'OPENAI_BASE_URL': 'http://litellm:4000/v1'}}, 'agentId': 'codex'}
MCP_CONFIG = {'servers': [{'id': 'files', 'transport': 'stdio', 'enabled': True, 'command': 'node',
                           'args': ['/data/opendesign/shared/mcp/files.js', '--root=/data/opendesign/projects'],
                           'env': {'TOKEN': 'ha-mcp-server-token'}},
                          {'id': 'ha', 'transport': 'http', 'enabled': True,
                           'url': 'http://homeassistant:8123/api/mcp'},
                          {'id': 'woow-paseo', 'transport': 'stdio', 'enabled': True, 'command': '/usr/local/bin/node',
                           'args': ['/opt/paseo-runtime/bin/mcp.mjs'], 'env': {'HOME': '/data/opendesign/home'}}]}
LIVE_MCP_CONFIG = {'servers': [{'id': 'target-own', 'transport': 'http', 'enabled': True, 'url': 'http://x.invalid/mcp'},
                               {'id': 'woow-paseo', 'transport': 'stdio', 'enabled': True, 'command': '/usr/bin/node',
                                'args': ['/app/paseo/bin/mcp.mjs'], 'env': {'HOME': '/app/.od/home'}}]}
ARM_ELF = b'\x7fELF\x02\x01\x01' + bytes(11) + b'\xb7\x00' + bytes(40)


def sqlite_bytes(*, projects=2, conversations=3, messages=5, folders=(), routines=(1, 0), tables=True):
    tmp = tempfile.TemporaryDirectory()
    try:
        path = Path(tmp.name) / 'app.sqlite'
        conn = sqlite3.connect(path)
        if tables:
            conn.executescript('CREATE TABLE projects(id TEXT PRIMARY KEY, name TEXT, metadata_json TEXT); '
                               'CREATE TABLE conversations(id TEXT PRIMARY KEY, project_id TEXT); '
                               'CREATE TABLE messages(id TEXT PRIMARY KEY, conversation_id TEXT); '
                               'CREATE TABLE routines(id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1);')
            conn.executemany('INSERT INTO projects VALUES (?, ?, ?)',
                             [(f'p{i}', f'專案 {i}', None) for i in range(projects)]
                             + [(f'f{i}', 'folder', json.dumps({'baseDir': base})) for i, base in enumerate(folders)]
                             + [('bad', 'bad json', '{not json')])
            conn.executemany('INSERT INTO conversations VALUES (?, ?)', [(f'c{i}', 'p0') for i in range(conversations)])
            conn.executemany('INSERT INTO messages VALUES (?, ?)', [(f'm{i}', 'c0') for i in range(messages)])
            conn.executemany('INSERT INTO routines VALUES (?, ?)', [(f'r{i}', e) for i, e in enumerate(routines)])
        else:
            conn.execute('CREATE TABLE other(x)')
        conn.commit()
        conn.close()
        return path.read_bytes()
    finally:
        tmp.cleanup()


def addon_tar(*, version='0.2.15', db=None, prefs=HA_PREFS, extra=(), without=()):
    addon = {'user': {'version': version, 'image': 'ghcr.io/woowtech/woow-ha-opendesign-amd64', 'options': {}},
             'system': {'slug': 'woow_ha_opendesign', 'name': 'Woow HA OpenDesign'}, 'version': version,
             'state': 'started'}
    own = {'uid': 1001, 'gid': 1001}
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': json.dumps(addon).encode()},
               {'name': 'data', 'type': 'dir'}, {'name': 'data/options.json', 'data': b'{}'},
               {'name': 'data/mcp', 'type': 'dir', 'uid': 10001, 'gid': 10001, 'mode': 0o700},
               {'name': 'data/mcp/state.json', 'data': b'{"token": "ha-mcp-bearer"}', 'uid': 10001, 'gid': 10001},
               {'name': 'data/opendesign', 'type': 'dir', **own},
               {'name': 'data/opendesign/app.sqlite', 'data': db if db is not None else sqlite_bytes(), **own},
               {'name': 'data/opendesign/app.sqlite-wal', 'data': b'', **own},
               {'name': 'data/opendesign/app.sqlite-shm', 'data': b'shm', **own},
               {'name': 'data/opendesign/mcp-config.json', 'data': json.dumps(MCP_CONFIG).encode(), 'mode': 0o600, **own},
               {'name': 'data/opendesign/mcp-tokens.json', 'data': b'{"files": "ha-oauth-token"}', 'mode': 0o600, **own},
               {'name': 'data/opendesign/media-config.json', 'data': b'{"openai": {"apiKey": "x"}}', 'mode': 0o600,
                **own},
               {'name': 'data/opendesign/installation.json', 'data': b'{"installationId": "ha-install-id"}', **own},
               {'name': 'data/opendesign/projects', 'type': 'dir', **own},
               {'name': 'data/opendesign/projects/p0', 'type': 'dir', **own},
               {'name': 'data/opendesign/projects/p0/index.html', 'data': '<h1>WOOW 匯入測試</h1>'.encode(), **own},
               {'name': 'data/opendesign/projects/p0/run.sh', 'data': b'#!/bin/sh\n', 'mode': 0o4755, **own},
               {'name': 'data/opendesign/projects/p0/latest', 'type': 'symlink', 'linkname': 'index.html', **own},
               {'name': 'data/opendesign/projects/p0/out', 'type': 'symlink', 'linkname': '/etc/passwd', **own},
               {'name': 'data/opendesign/projects/p0/copy.html', 'type': 'hardlink',
                'linkname': 'data/opendesign/projects/p0/index.html', **own},
               {'name': 'data/opendesign/runs', 'type': 'dir', **own},
               {'name': 'data/opendesign/runs/r1.log', 'data': b'cwd /data/opendesign/projects/p0', **own},
               {'name': 'data/opendesign/connectors', 'type': 'dir', 'mode': 0o700, **own},
               {'name': 'data/opendesign/connectors/credentials.json', 'data': b'{"github": "ha-connector-secret"}',
                'mode': 0o600, **own},
               {'name': 'data/opendesign/home', 'type': 'dir', **own},
               {'name': 'data/opendesign/home/.claude', 'type': 'dir', 'mode': 0o700, **own},
               {'name': 'data/opendesign/home/.claude/.credentials.json', 'data': b'{"oauth": "ha-claude-login"}',
                'mode': 0o600, **own},
               {'name': 'data/opendesign/paseo', 'type': 'dir', 'mode': 0o700, **own},
               {'name': 'data/opendesign/paseo/pairing.private.json', 'data': b'ha-paseo-pairing', **own},
               {'name': 'data/opendesign/integrations', 'type': 'dir', 'mode': 0o700, **own},
               {'name': 'data/opendesign/integrations/omnigent', 'type': 'dir', **own},
               {'name': 'data/opendesign/integrations/omnigent/state.json', 'data': b'ha-omnigent-host', **own},
               {'name': 'data/opendesign/diagnostics', 'type': 'dir', **own},
               {'name': 'data/opendesign/diagnostics/outbox.sqlite', 'data': b'x', **own},
               {'name': 'data/opendesign/.backup', 'type': 'dir', **own},
               {'name': 'data/opendesign/.backup/omnigent-1', 'data': b'retired', **own},
               {'name': 'data/opendesign/shared', 'type': 'dir', **own},
               {'name': 'data/opendesign/shared/workspaces', 'type': 'dir', **own},
               {'name': 'data/opendesign/shared/workspaces/README.md', 'data': b'# Shared', **own},
               {'name': 'data/opendesign/shared/mcp', 'type': 'dir', **own},
               {'name': 'data/opendesign/shared/mcp/servers.json', 'data': b'{"servers": []}', **own},
               {'name': 'data/opendesign/new-empty-feature', 'type': 'dir', **own}]
    if prefs is not None:
        entries.append({'name': 'data/opendesign/app-config.json',
                        'data': prefs if isinstance(prefs, bytes) else json.dumps(prefs).encode(), **own})
    entries = [e for e in entries if e['name'] not in without]
    return gzip.compress(hx.tar_bytes(entries + list(extra)), mtime=0)


def live_data(prefs=LIVE_PREFS, extra=()):
    entries = [{'name': '.', 'type': 'dir'},
               {'name': 'app.sqlite', 'data': b'target-db'}, {'name': 'app.sqlite-wal', 'data': b'target-wal'},
               {'name': 'installation.json', 'data': b'{"installationId": "target-install-id"}'},
               {'name': 'home', 'type': 'dir'}, {'name': 'home/.codex', 'type': 'dir', 'mode': 0o700},
               {'name': 'home/.codex/auth.json', 'data': b'target-codex-login', 'mode': 0o600},
               {'name': 'home/.bun', 'type': 'dir'}, {'name': 'home/.bun/cache.bin', 'data': b'cache'},
               {'name': 'home/.bun/cache2.bin', 'type': 'hardlink', 'linkname': 'home/.bun/cache.bin'},
               {'name': 'paseo', 'type': 'dir', 'mode': 0o700},
               {'name': 'paseo/pairing.private.json', 'data': b'target-pairing', 'mode': 0o600},
               {'name': 'integrations', 'type': 'dir', 'mode': 0o700},
               {'name': 'integrations/omnigent', 'type': 'dir'},
               {'name': 'integrations/omnigent/state.json', 'data': b'target-omnigent'},
               {'name': 'export-render', 'type': 'dir'}, {'name': 'export-pdf', 'type': 'dir'},
               {'name': 'projects', 'type': 'dir'}, {'name': 'projects/target-only', 'type': 'dir'},
               {'name': 'projects/target-only/a.html', 'data': b'target project'},
               {'name': 'diagnostics', 'type': 'dir'},
               {'name': 'mcp-config.json', 'data': json.dumps(LIVE_MCP_CONFIG).encode()}]
    if prefs is not None:
        entries.append({'name': 'app-config.json', 'data': json.dumps(prefs).encode()})
    return fk.tar_of(entries + list(extra))


LIVE_MCP = fk.tar_of([{'name': '.', 'type': 'dir', 'uid': 10001, 'gid': 10001, 'mode': 0o700},
                      {'name': 'state', 'type': 'dir', 'uid': 10001, 'gid': 10001, 'mode': 0o700},
                      {'name': 'state/token', 'data': b'target-mcp-token', 'uid': 10001, 'gid': 10001, 'mode': 0o600}])


class Owner(fk.Owner):
    """The app owner's runner with systemctl, and an export that fails, is torn or only works while the writers are stopped."""

    def __init__(self, world):
        super().__init__(world)
        self.systemd = []

    def systemctl(self, *args, timeout=None, max_output=None, check=True, abort=None):
        verb, unit = args[0], args[-1]
        self.calls.append(('systemctl', verb, unit))
        self.systemd.append((verb, unit))
        if self.world.start_fails and verb == 'start':
            self.world.start_fails -= 1
            raise BackupError('job-failed', 'systemctl start 執行失敗（結束碼 1）。')
        return Result(0, b'', b'')

    def stopped(self):
        state = {}
        for verb, unit in self.systemd:
            state[unit] = verb
        return {unit for unit, verb in state.items() if verb == 'stop'}

    def relay(self, args, *, stdout, timeout=None, max_output=None, check=True, abort=None):
        volume = args[-1]
        self.calls.append(('relay', *args))
        plan = self.world.export_plan.get(volume)
        step = plan.pop(0) if plan else 'ok'
        if self.world.needs_stopped and volume == DATA and not self.world.needs_stopped <= self.stopped():
            step = 'fail'
        if step == 'fail':
            raise BackupError('job-failed', 'podman volume export 執行失敗（結束碼 125）。')
        data = self.world.export(volume)
        stdout.write(data[:len(data) // 2 + 5] if step == 'torn' else data)
        return Result(0, None, b'')


class World(fk.World):
    def __init__(self):
        super().__init__()
        self.owner = Owner(self)
        self.quadlets = {'open-design': QUADLETS}
        self.revision = REV
        self.app_version = '0.24.1'
        self.live_prefs = LIVE_PREFS
        self.live_extra = ()
        self.export_plan = {}          # volume -> ['fail' | 'torn' | 'ok', ...] one per export call
        self.needs_stopped = set()     # units that must be stopped before the data volume can be exported
        self.start_fails = 0
        self.pulled = True             # False: the image is not on this device until `podman pull`
        self.pull_fails = False
        self.pulls = []
        self.label_text = None         # a label output that is not JSON

    def podman(self, args, data, stdout):
        if args[:1] == ['pull']:
            self.pulls.append(args[-1])
            if self.pull_fails:
                return Result(125, b'', b'Error: initializing source docker://x: pinging container registry: dial tcp: lookup x')
            self.pulled = True
            return Result(0, b'sha256:abc\n', b'')
        if args[:2] == ['image', 'inspect'] and not self.pulled:
            return Result(1, b'', b'Error: no such image')
        if args[:2] == ['image', 'inspect'] and self.label_text is not None:
            return Result(0, self.label_text, b'')
        return super().podman(args, data, stdout)

    def labels(self, image):
        return {od.SOURCE_LABEL: self.revision} if self.revision else {}

    def image_info(self, image):
        return dict(super().image_info(image), env=['PATH=/usr/bin', f'OD_APP_VERSION={self.app_version}',
                                                   'OD_DATA_DIR=/app/.od'])

    def export(self, volume):
        if volume == DATA:
            return live_data(self.live_prefs, self.live_extra)
        if volume == MCP:
            return LIVE_MCP
        raise AssertionError(volume)


class OpenDesignCase(fk.ConversionCase):
    world_class = World

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hacommon, 'host_elf_machine', lambda: 0x3E)
        patcher.start()
        self.addCleanup(patcher.stop)

    def catalog_apps(self):
        return {'open-design': fk.app('open-design', 'OpenDesign', volumes=[{'name': DATA}, {'name': MCP}])}

    def upload_od(self, **kwargs):
        return self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', addon_tar(**kwargs))], hx.ha_doc(addons=(SLUG,))))


class CheckTests(OpenDesignCase):
    def test_a_clean_backup(self):
        result = self.check(self.upload_od(), ['open-design'])[0]
        self.assertEqual((result['ok'], result['blockers'], result['target_version']), (True, [], '0.24.1'))
        section = result['open-design']
        self.assertEqual((section['open-design_version'], section['source_revision'], section['target_revision']),
                         ('0.24.1', REV[:8], REV[:8]))
        self.assertEqual((section['projects'], section['conversations'], section['messages'], section['routines']),
                         (3, 3, 5, 2))
        self.assertEqual((section['routines_active'], section['project_folders'], section['mcp_servers'],
                          section['mcp_integration_entries']), (1, 0, 2, 1))
        self.assertEqual((section['symlinks'], section['hardlinks'], section['skipped_symlinks']), (1, 1, 1))
        self.assertEqual(section['left_out'], {'.backup': 2, 'app.sqlite-shm': 1, 'diagnostics': 2, 'home': 3,
                                               'installation.json': 1, 'integrations': 3, 'paseo': 2})
        self.assertEqual(section['ha_urls'], ['mcp-config.json：homeassistant'])
        self.assertEqual(section['shared'], 2)
        joined = '\n'.join(result['warnings'])
        for words in ('homeassistant', '1 個指向資料以外的符號連結', '1 個啟用中的 OpenDesign 例行工作',
                      '2 個專案位置或最近使用的資料夾', 'shared/mcp'):
            self.assertIn(words, joined)
        self.assertFalse(self.world.runs, 'no container is needed for OpenDesign')
        self.assertFalse([c for c in self.world.owner.calls if c[0] == 'relay'], 'the check exports no volume')

    def test_folder_projects_are_counted(self):
        db = sqlite_bytes(folders=('/data/opendesign/shared/workspaces/a', '/home/user/b', '/data/opendesignx'))
        result = self.check(self.upload_od(db=db), ['open-design'])[0]
        self.assertTrue(result['ok'], result['blockers'])
        self.assertEqual(result['open-design']['project_folders'], 3)
        self.assertTrue(any('3 個從資料夾匯入的專案' in w and '其中 1 個' in w for w in result['warnings']))

    def test_blockers(self):
        # what still stops OpenDesign (and only OpenDesign); the old stops that became notices or lines to confirm
        # (a version the table does not know, an entry it does not know, a hard link to a login) are in the Parity classes
        cases = (({'db': b'SQLite format 3\x00' + b'\xff' * 4000}, '已損毀'),
                 ({'db': sqlite_bytes(tables=False)}, '沒有專案資料表'),
                 ({'without': ('data/opendesign/app.sqlite',)}, '沒有 OpenDesign 的資料庫'),
                 ({'extra': [{'name': 'data/opendesign/media-config.json', 'type': 'symlink',
                              'linkname': 'projects/p0/index.html'}],
                   'without': ('data/opendesign/media-config.json',)}, '不是一般檔案'))
        for kwargs, words in cases:
            with self.subTest(words=words):
                result = self.check(self.upload_od(**kwargs), ['open-design'])[0]
                self.assertFalse(result['ok'])
                self.assertFalse(result['importable'])
                self.assertTrue(any(words in b for b in result['blockers']), result['blockers'])
        arm = [{'name': 'data/opendesign/projects/p0/arm.node', 'data': ARM_ELF}]
        result = self.check(self.upload_od(extra=arm), ['open-design'])[0]
        self.assertTrue(result['ok'], 'programs for another processor in projects are a warning')
        self.assertTrue(any('其他處理器的程式' in w for w in result['warnings']))

    def test_the_core_revision_must_be_the_same(self):
        # OP-03 stays: both revisions known and different stops OpenDesign (installing HA's core is a later phase)
        self.world.revision = 'c8cd57f0' + 'a' * 32
        result = self.check(self.upload_od(), ['open-design'])[0]
        self.assertIn('版本不同', result['blockers'][0])
        self.assertIn('c8cd57f0', result['blockers'][0])
        self.assertEqual([i['id'] for i in result['issues'] if i['level'] == 'stop'], ['opendesign.core-different'])
        self.world.revision = REV[:12]  # a short label of the same revision
        self.assertTrue(self.check(self.upload_od(), ['open-design'])[0]['ok'])


class ConvertTests(OpenDesignCase):
    def test_the_whole_conversion(self):
        result = self.convert(self.upload_od(), ['open-design'])
        self.assertEqual(sorted(self.world.manifests['open-design']), ['volumes'])
        data = self.volume(DATA)
        names = set(data)
        for gone in ('app.sqlite-shm', 'diagnostics', 'diagnostics/outbox.sqlite', '.backup', 'shared/mcp',
                     'shared/mcp/servers.json', 'projects/target-only', 'projects/p0/out', 'new-empty-feature'):
            self.assertNotIn(gone, names)
        self.assertEqual(data['app.sqlite'][1], sqlite_bytes(), 'the database moves unchanged')
        self.assertIn('app.sqlite-wal', names)
        self.assertEqual(data['projects/p0/index.html'][1], '<h1>WOOW 匯入測試</h1>'.encode())
        self.assertEqual(data['projects/p0/run.sh'][0].mode, 0o755, 'no setuid')
        link = data['projects/p0/copy.html'][0]
        self.assertEqual((link.islnk(), link.linkname), (True, 'projects/p0/index.html'))
        self.assertEqual(data['projects/p0/latest'][0].linkname, 'index.html')
        self.assertEqual(data['shared/workspaces/README.md'][1], b'# Shared')
        # this device's logins, identities and installation id stay
        self.assertEqual(data['home/.codex/auth.json'][1], b'target-codex-login')
        self.assertEqual(data['paseo/pairing.private.json'][1], b'target-pairing')
        self.assertEqual(data['integrations/omnigent/state.json'][1], b'target-omnigent')
        self.assertEqual(data['installation.json'][1], b'{"installationId": "target-install-id"}')
        self.assertNotIn('home/.claude/.credentials.json', names)
        self.assertEqual(data['home/.bun/cache2.bin'][0].linkname, 'home/.bun/cache.bin')
        self.assertTrue(data['export-render'][0].isdir())
        prefs = json.loads(data['app-config.json'][1])
        self.assertEqual(prefs['installationId'], 'target-install-id')
        self.assertEqual(prefs['agentCliEnv'], LIVE_PREFS['agentCliEnv'])
        self.assertNotIn('agentCliEnvIntent', prefs)
        self.assertEqual((prefs['agentId'], prefs['customInstructions']), ('claude', 'HA 的指示'))
        self.assertEqual(prefs['projectLocations'], [{'id': 'ws', 'name': 'shared', 'path': '/app/.od/shared/workspaces/team'}])
        self.assertIsNone(prefs['defaultProjectLocationId'])
        self.assertEqual(prefs['recentLinkedDirs'], ['/app/.od/shared/workspaces'])
        servers = json.loads(data['mcp-config.json'][1])['servers']
        self.assertEqual([item['id'] for item in servers], ['files', 'ha', 'woow-paseo'],
                         'HA\'s servers move, the target-only one is replaced, the Paseo entry is this device\'s')
        self.assertEqual(servers[0]['args'], ['/app/.od/shared/mcp/files.js', '--root=/app/.od/projects'])
        self.assertEqual(servers[0]['env'], {'TOKEN': 'ha-mcp-server-token'}, 'HA\'s third-party settings move')
        self.assertEqual(servers[2], LIVE_MCP_CONFIG['servers'][1], 'this device\'s own Paseo MCP entry stays')
        self.assertEqual(data['mcp-tokens.json'][1], b'{"files": "ha-oauth-token"}')
        self.assertEqual(data['connectors/credentials.json'][1], b'{"github": "ha-connector-secret"}')
        ha_owned = [n for n, (m, _d) in data.items() if (m.uid, m.gid) != (0, 0)]
        self.assertEqual(ha_owned, [], 'every member owned like the live top folder (0:0)')
        self.assertEqual(data['.'][0].mode, 0o755)
        self.assertEqual(self.world.volume_data[MCP], LIVE_MCP, 'the MCP volume is this device\'s, unchanged')
        imp = result['ha_import']
        self.assertTrue(imp['notes'][0].startswith('OpenDesign'))
        reminders = imp['reminders_by_app']['open-design']
        for words in ('open-design', '代理程式', 'Omnigent 與 Paseo', '內建的 MCP 伺服器', 'BYOK', 'homeassistant',
                      '例行工作'):
            self.assertTrue(any(words in line for line in reminders), words)

    def test_the_mcp_admin_line_names_this_devices_app(self):
        self.catalog['opendesign-mcp-admin'] = fk.app('opendesign-mcp-admin', 'OpenDesign MCP 管理')
        result = self.convert(self.upload_od(), ['open-design'])
        self.assertTrue(any('「OpenDesign MCP 管理」' in line
                            for line in result['ha_import']['reminders_by_app']['open-design']))

    def test_this_devices_preferences_stay_when_ha_has_none_usable(self):
        for prefs in (None, b'[1, 2]'):
            with self.subTest(prefs=prefs):
                self.world.volume_data.clear()
                self.convert(self.upload_od(prefs=prefs), ['open-design'])
                self.assertEqual(json.loads(self.volume(DATA)['app-config.json'][1]), LIVE_PREFS)

    def test_a_target_of_another_shape_is_refused(self):
        self.catalog['open-design'] = fk.app('open-design', 'OpenDesign', volumes=[{'name': DATA}])
        result = self.check(self.upload_od(), ['open-design'])[0]
        self.assertIn('Quadlet 檔不一致', result['blockers'][0])


class UnitTests(unittest.TestCase):
    def test_remap(self):
        self.assertEqual(od.remap('/data/opendesign'), '/app/.od')
        self.assertEqual(od.remap('/data/opendesign/projects/a'), '/app/.od/projects/a')
        for other in ('/data/opendesignx', '/data/opendesign/../etc', '/share/x', 'relative', None, 3):
            self.assertIsNone(od.remap(other), other)

    def test_rewrite_strings(self):
        counter = [0]
        doc = od.rewrite_strings({'a': ['/data/opendesign/x', 'cd /data/opendesign/y && run', 'keep'], 'n': 1},
                                 counter)
        self.assertEqual(doc, {'a': ['/app/.od/x', 'cd /app/.od/y && run', 'keep'], 'n': 1})
        self.assertEqual(counter, [2])

    def test_merge_mcp(self):
        doc, refs, owned = od.merge_mcp(json.loads(json.dumps(MCP_CONFIG)), None)
        self.assertEqual(([s['id'] for s in doc['servers']], refs, owned), (['files', 'ha'], 2, 1))
        doc, refs, owned = od.merge_mcp({}, LIVE_MCP_CONFIG)
        self.assertEqual(([s['id'] for s in doc['servers']], refs, owned), (['woow-paseo'], 0, 0))

    def test_merge_prefs_without_a_live_file(self):
        doc, dropped = od.merge_prefs(dict(HA_PREFS), None)
        for key in od.TARGET_PREFS:
            self.assertNotIn(key, doc)
        self.assertEqual(dropped, 2)

    def test_special_entries_must_be_regular(self):
        for name, kind in (('app.sqlite', 'symlink'), ('app.sqlite-wal', 'hardlink'), ('app-config.json', 'symlink'),
                           ('projects', 'file'), ('shared', 'symlink')):
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as tmp:
                entries = [{'name': 'data/opendesign', 'type': 'dir'},
                           {'name': 'data/opendesign/target', 'data': b'content'}]
                entry = {'name': f'data/opendesign/{name}', 'type': kind}
                if kind != 'file':
                    entry['linkname'] = 'data/opendesign/target' if kind == 'hardlink' else 'target'
                entries.append(entry)
                with self.assertRaises(BackupError):
                    od.scan_member(io.BytesIO(hx.tar_bytes(entries)), habackup.Report(), Path(tmp), od._Count())

    def test_areas(self):
        self.assertEqual([od._area(n) for n in ('projects', 'projects/a', 'app.sqlite', 'app.sqlite-shm', 'home/x',
                                                'shared', 'shared/skills/a', 'shared/plugins', 'mystery', 'mystery/x')],
                         ['move', 'move', 'move', 'left', 'left', 'shared', 'shared-move', 'shared-left', 'unknown',
                          'unknown'])

    def test_registry(self):
        from woowbackup import haapps, hastore
        importer = haapps.get('open-design')
        self.assertEqual((importer.slug, importer.module, importer.mcp_admin, importer.mcp_addon),
                         ('woow_ha_opendesign', 'ha_opendesign', 'opendesign-mcp-admin', None))
        self.assertEqual(hastore.importable_app('1b7b4ce7_woow_ha_opendesign')[0], 'open-design')
        self.assertEqual(hastore.importable_app('local_woow_ha_opendesign')[0], 'open-design')


def _names(data):
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return [m.name for m in tar.getmembers()]


if __name__ == '__main__':
    unittest.main()
