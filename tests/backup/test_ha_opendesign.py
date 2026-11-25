"""HA import, OpenDesign part (ha_opendesign.py): HA's daemon data moves with this device's owner, this device's agent
logins, Omnigent and Paseo identities, installation id and MCP volume stay, HA's preferences are merged and its paths
remapped, the database is checked by the sandboxed child, versions, blockers and the texts (CONTRACT section 9).
Team E2. HAOS parity (2026-11-25, lane OPENDESIGN-CODESERVER): OP-01 .. OP-16 (the versions only inform, what is left out
is one line to confirm, a hard link gets the content, a read that fails is tried again and then done with the app's own
containers paused) -- see the classes ParityCheckTests .. ParityLiveTests."""
import gzip
import io
import json
import os
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import habackup, haimport, haissues, hacommon, ha_opendesign as od, hasecuretar, hasqlite, hatarget, jobs
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
    entries = [e for e in entries if not any(e['name'] == w or (w.endswith('/*') and e['name'].startswith(w[:-1]))
                                             for w in without)]
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
        need = self.world.needs_stopped.get(volume)
        if need and not need <= self.stopped():
            step = 'fail'
        if step == 'limit':
            raise BackupError('limit-exceeded', '匯出的輸出超過上限，已停止。')
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
        self.needs_stopped = {}        # volume -> units that must be stopped before it can be exported
        self.start_fails = 0
        self.pulled = True             # False: the image is not on this device until `podman pull`
        self.pull_fails = False
        self.pulls = []
        self.label_text = None         # a label output that is not JSON
        self.not_running = set()       # containers `podman container inspect` says are stopped

    def podman(self, args, data, stdout):
        if args[:1] == ['pull']:
            self.pulls.append(args[-1])
            if self.pull_fails:
                return Result(125, b'', b'Error: initializing source docker://x: pinging container registry: dial tcp: lookup x')
            self.pulled = True
            return Result(0, b'sha256:abc\n', b'')
        if args[:2] == ['container', 'inspect'] and 'State.Running' in args[3] and args[-1] in self.not_running:
            return Result(0, b'false\n', b'')
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


# ====================================================================== HAOS parity (OPENDESIGN-CODESERVER lane)

def issue_of(row, issue_id):
    return next(item for item in row['issues'] if item['id'] == issue_id)


def levels(row, level):
    return [item['id'] for item in row['issues'] if item['level'] == level]


def ack(row, *issue_ids):
    """`acknowledged` of the lines of a check result (all of them, or those named)."""
    return {'open-design': [item['key'] for item in row['issues']
                            if item['level'] == 'confirm' and (not issue_ids or item['id'] in issue_ids)]}


def sleepless(test):
    """No real pause between the tries of a read."""
    patcher = mock.patch.object(hatarget, '_sleep', lambda _seconds: None)
    patcher.start()
    test.addCleanup(patcher.stop)


class ParityCase(OpenDesignCase):
    def setUp(self):
        super().setUp()
        sleepless(self)

    def row(self, backup):
        return self.check(backup, ['open-design'])[0]

    def stops_only_this_app(self, backup, issue_id):
        """The check says importable false with this stop, and a conversion stops with it before anything is made."""
        row = self.row(backup)
        self.assertEqual((row['importable'], row['ok']), (False, False))
        self.assertIn(issue_id, levels(row, 'stop'))
        with self.assertRaises(BackupError) as caught:
            self.convert(backup, ['open-design'])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertEqual([item.id for item in caught.exception.issues if item.level == 'stop'], [issue_id])
        self.assertEqual((self.storage.list_backups(), self.world.manifests), ([], {}))
        return row

    # ---- the three steps of a line to confirm (DESIGN G1): not confirmed -> only this app stops and nothing is handed on;
    # confirmed -> it goes on; one more name -> it asks again
    def assert_not_confirmed(self, backup, issue_id, items, spoken):
        row = self.row(backup)
        issue = issue_of(row, issue_id)
        self.assertEqual((row['importable'], row['ok'], issue['level'], issue['items']), (True, False, 'confirm', items))
        self.assertIn(spoken, issue['message'])
        self.assertLessEqual(len(issue['message']), 300)
        self.assertEqual(levels(row, 'stop'), [], 'nothing stops the app')
        for acknowledged in (None, {}, {'open-design': []}, {'n8n': [issue['key']]},
                             {'open-design': ['legacy.warning:0123456789abcdef']}):
            with self.subTest(acknowledged=acknowledged), self.assertRaises(BackupError) as caught:
                self.convert(backup, ['open-design'], **({} if acknowledged is None else {'acknowledged': acknowledged}))
            self.assertEqual(caught.exception.code, 'confirmation-required')
            self.assertEqual((self.storage.list_backups(), self.world.manifests), ([], {}), 'nothing is handed to the restore')
        return row

    def assert_confirmed(self, backup, issue_id, items):
        row = self.row(backup)
        result = self.convert(backup, ['open-design'], acknowledged=ack(row))
        self.assertEqual(result['results'][0]['status'], 'converted')
        registered = haimport.load_registry(self.paths)[result['backup_id']]
        self.assertEqual([(c['app_id'], c['id'], c['items']) for c in registered['confirmed'] if c['id'] == issue_id],
                         [('open-design', issue_id, items)])
        return result

    def assert_one_more_name_asks_again(self, backup, more, issue_id):
        row = self.row(backup)
        with self.assertRaises(BackupError) as caught:
            self.convert(more, ['open-design'], acknowledged=ack(row))
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertNotEqual(issue_of(self.row(more), issue_id)['key'], issue_of(row, issue_id)['key'])


class ParityCheckTests(ParityCase):
    """OP-01, OP-02, OP-05, OP-06, OP-07: what the versions say, the image of this device, nothing to move."""

    def test_op01_a_version_the_table_does_not_know_is_a_notice_and_the_import_goes_on(self):
        for version in ('0.2.14', '0.3.0'):      # older and newer than the one the table knows
            with self.subTest(version=version):
                backup = self.upload_od(version=version)
                row = self.row(backup)
                self.assertEqual((row['importable'], row['ok'], levels(row, 'stop')), (True, True, []))
                notice = issue_of(row, 'opendesign.core-unknown')
                self.assertEqual(notice['level'], 'notice')
                self.assertIn(version, notice['message'])
                self.assertEqual((row['open-design']['open-design_version'], row['open-design']['source_revision']), ('', ''))
                result = self.convert(backup, ['open-design'])
                self.assertEqual(result['results'][0]['status'], 'converted')
                self.assertIn('opendesign.core-unknown', [i['id'] for i in result['results'][0]['issues']])
                self.assertIn('app.sqlite', self.volume(DATA))

    def test_op01_what_it_cannot_handle_stops_only_this_app_a_core_that_is_known_and_different(self):
        self.world.revision = 'c8cd57f0' + 'a' * 32
        row = self.stops_only_this_app(self.upload_od(), 'opendesign.core-different')
        self.assertIn('c8cd57f0', issue_of(row, 'opendesign.core-different')['message'])
        self.assertIn('請先把這台的 OpenDesign 換成同一個核心版本', issue_of(row, 'opendesign.core-different')['action'])

    def test_op02_an_image_without_the_core_label_is_a_notice_and_the_import_goes_on(self):
        self.world.revision = None
        backup = self.upload_od()
        row = self.row(backup)
        self.assertEqual((row['importable'], row['ok'], levels(row, 'stop')), (True, True, []))
        self.assertEqual(issue_of(row, 'opendesign.target-core-unknown')['level'], 'notice')
        self.assertEqual(row['open-design']['target_revision'], '')
        result = self.convert(backup, ['open-design'])
        self.assertEqual(result['results'][0]['status'], 'converted')

    def test_op02_a_label_that_is_not_a_revision_is_not_a_revision(self):
        self.world.revision = 'not-a-hash!'
        row = self.row(self.upload_od())
        self.assertTrue(row['importable'])
        self.assertEqual(issue_of(row, 'opendesign.target-core-unknown')['level'], 'notice')

    REGISTRY = 'ghcr.io/woowtech/woow-open-design:4.2.1'

    def registry_image(self):
        """The Quadlet files with an image of a registry (the package's own is built on the device: localhost/...)."""
        self.world.quadlets = {'open-design': {name: text.replace(b'localhost/woow-open-design:4.2.1', self.REGISTRY.encode())
                                               for name, text in QUADLETS.items()}}

    def test_op05_an_image_that_is_not_here_is_downloaded_as_the_owner_and_the_import_goes_on(self):
        self.registry_image()
        self.world.pulled = False
        backup = self.upload_od()
        row = self.row(backup)
        self.assertEqual((row['importable'], levels(row, 'stop')), (True, []))
        self.assertEqual(self.world.pulls, [self.REGISTRY], 'once, by the reference of this device\'s own Quadlet file')
        self.assertIn('target.image-pulled', levels(row, 'auto'))
        self.world.pulled = True
        self.assertEqual(self.convert(backup, ['open-design'])['results'][0]['status'], 'converted')

    def test_op05_an_image_that_cannot_be_downloaded_stops_only_this_app_with_the_reason(self):
        self.registry_image()
        self.world.pulled = False
        self.world.pull_fails = True
        backup = self.upload_od()
        row = self.row(backup)
        self.assertFalse(row['importable'])
        self.assertEqual(levels(row, 'stop'), ['target.image-missing'])
        self.assertEqual(len(self.world.pulls), hatarget.PULL_ATTEMPTS)
        with self.assertRaises(BackupError) as caught:
            self.convert(backup, ['open-design'])
        self.assertEqual([item.id for item in caught.exception.issues], ['target.image-missing'])
        self.assertEqual((self.storage.list_backups(), self.world.manifests), ([], {}))

    def test_op05_an_image_built_on_this_device_that_is_gone_stops_only_this_app_and_says_to_build_it_again(self):
        self.world.pulled = False                   # the Quadlet names localhost/woow-open-design:4.2.1
        row = self.row(self.upload_od())
        self.assertFalse(row['importable'])
        self.assertEqual(levels(row, 'stop'), ['target.image-missing'])
        self.assertIn('自己建置', issue_of(row, 'target.image-missing')['message'])
        self.assertEqual(self.world.pulls, [], 'a local image has nowhere to be downloaded from')

    def test_op05_a_label_that_cannot_be_read_is_an_unknown_core_not_a_stop(self):
        self.world.label_text = b'this is not json'
        row = self.row(self.upload_od())
        self.assertEqual((row['importable'], levels(row, 'stop')), (True, []))
        self.assertEqual(issue_of(row, 'opendesign.target-core-unknown')['level'], 'notice')

    def test_op05_a_quadlet_that_names_no_image_is_the_one_case_that_still_stops(self):
        quadlets = dict(QUADLETS)
        quadlets['open-design.container'] = QUADLETS['open-design.container'].replace(
            b'Image=localhost/woow-open-design:4.2.1\n', b'', 1)
        self.world.quadlets = {'open-design': quadlets}
        row = self.row(self.upload_od())
        self.assertFalse(row['importable'])
        self.assertIn('Quadlet 設定缺少映像', row['blockers'][0])
        self.assertEqual(self.world.pulls, [], 'nothing to download')

    def test_op06_no_opendesign_folder_stops_only_this_app_and_says_what_to_do(self):
        backup = self.upload_od(without=('data/opendesign', 'data/opendesign/*'))
        row = self.stops_only_this_app(backup, 'opendesign.no-folder')
        self.assertIn('沒有可搬的資料', issue_of(row, 'opendesign.no-folder')['message'])
        self.assertIn('重新備份', issue_of(row, 'opendesign.no-folder')['action'])

    def test_op07_no_database_stops_only_this_app_and_never_makes_this_device_empty(self):
        backup = self.upload_od(without=('data/opendesign/app.sqlite', 'data/opendesign/app.sqlite-wal'))
        row = self.stops_only_this_app(backup, 'opendesign.no-database')
        self.assertIn('app.sqlite', issue_of(row, 'opendesign.no-database')['message'])
        self.assertIn('不會被換成空的', issue_of(row, 'opendesign.no-database')['action'])
        self.assertEqual(self.world.volume_data, {}, 'no volume was handed to the restore')


class ParityConfirmTests(ParityCase):
    """OP-10 and OP-13: what is left in HA is one line of the ONE confirmation, with its three steps."""

    UNKNOWN = [{'name': 'data/opendesign/mystery', 'type': 'dir'}, {'name': 'data/opendesign/mystery/x', 'data': b'?'},
               {'name': 'data/opendesign/only-a-folder', 'type': 'dir'}]
    MORE = [{'name': 'data/opendesign/mystery2', 'type': 'dir'}, {'name': 'data/opendesign/mystery2/y', 'data': b'?'}]

    def test_op10_entries_this_importer_does_not_know_not_confirmed_stop_only_this_app(self):
        row = self.assert_not_confirmed(self.upload_od(extra=self.UNKNOWN), 'opendesign.unknown-entries', ['mystery'],
                                        '1 個這台的匯入程式還不認得的項目')
        self.assertNotIn('mystery', issue_of(row, 'opendesign.unknown-entries')['message'], 'names are items, not text')

    def test_op10_confirmed_goes_on_and_what_it_does_not_know_stays_in_ha(self):
        self.assert_confirmed(self.upload_od(extra=self.UNKNOWN), 'opendesign.unknown-entries', ['mystery'])
        names = set(self.volume(DATA))
        self.assertTrue({'mystery', 'mystery/x', 'only-a-folder'}.isdisjoint(names))
        self.assertIn('projects/p0/index.html', names, 'everything it knows moved')

    def test_op10_one_more_name_asks_again(self):
        self.assert_one_more_name_asks_again(self.upload_od(extra=self.UNKNOWN), self.upload_od(extra=self.UNKNOWN + self.MORE),
                                             'opendesign.unknown-entries')

    def test_op10_a_crafted_backup_with_very_many_unknown_names_is_counted_not_kept(self):
        many = [{'name': f'data/opendesign/u{i}/f', 'data': b'x'} for i in range(od.MAX_UNKNOWN + 25)]
        row = self.row(self.upload_od(extra=many))
        issue = issue_of(row, 'opendesign.unknown-entries')
        self.assertEqual(len(issue['items']), haissues.MAX_ITEMS)
        self.assertIn('還有更多', issue['message'])

    BIG = json.dumps({'padding': 'x' * 3000}).encode()

    def big_prefs(self):
        patcher = mock.patch.object(od, 'MAX_CONFIG', 2000)
        patcher.start()
        self.addCleanup(patcher.stop)
        return self.upload_od(prefs=self.BIG)

    def test_op13_a_settings_file_too_large_to_read_not_confirmed_stops_only_this_app(self):
        self.assert_not_confirmed(self.big_prefs(), 'files.skipped', ['data/opendesign/app-config.json'],
                                  '大小超出上限的設定檔 1 個')

    def test_op13_confirmed_goes_on_and_this_devices_own_preferences_stay(self):
        backup = self.big_prefs()
        row = self.row(backup)
        self.assertEqual(row['open-design']['config_skipped'], ['app-config.json'])
        self.assertEqual(issue_of(row, 'opendesign.config-kept')['level'], 'notice')
        result = self.assert_confirmed(backup, 'files.skipped', ['data/opendesign/app-config.json'])
        self.assertEqual(json.loads(self.volume(DATA)['app-config.json'][1]), LIVE_PREFS)
        self.assertTrue(any('設定檔 app-config.json' in line and '太大' in line
                            for line in result['ha_import']['reminders_by_app']['open-design']))

    def test_op13_one_more_name_asks_again(self):
        patcher = mock.patch.object(od, 'MAX_CONFIG', 2000)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.assert_one_more_name_asks_again(
            self.upload_od(prefs=self.BIG),
            self.upload_od(prefs=self.BIG, without=('data/opendesign/mcp-config.json',),
                           extra=[{'name': 'data/opendesign/mcp-config.json', 'data': self.BIG, 'mode': 0o600}]),
            'files.skipped')

    def test_op13_a_mcp_settings_file_too_large_keeps_this_devices_whole_file(self):
        patcher = mock.patch.object(od, 'MAX_CONFIG', 2000)
        patcher.start()
        self.addCleanup(patcher.stop)
        backup = self.upload_od(without=('data/opendesign/mcp-config.json',),
                                extra=[{'name': 'data/opendesign/mcp-config.json', 'data': self.BIG, 'mode': 0o600}])
        row = self.row(backup)
        self.assertEqual(issue_of(row, 'files.skipped')['items'], ['data/opendesign/mcp-config.json'])
        self.assert_confirmed(backup, 'files.skipped', ['data/opendesign/mcp-config.json'])
        self.assertEqual(json.loads(self.volume(DATA)['mcp-config.json'][1]), LIVE_MCP_CONFIG,
                         "this device's own MCP servers are not replaced by nothing")
        self.assertEqual(json.loads(self.volume(DATA)['app-config.json'][1])['customInstructions'], 'HA 的指示',
                         "the other file of HA still moves")

    def test_op13_a_file_below_the_limit_is_read_as_before(self):
        with mock.patch.object(od, 'MAX_CONFIG', len(json.dumps(HA_PREFS)) + 10):
            row = self.row(self.upload_od())
        self.assertNotIn('files.skipped', [item['id'] for item in row['issues']])
        self.assertEqual(row['open-design']['config_skipped'], [])


class ParityLinksTests(ParityCase):
    """OP-11 (a moved file that is a hard link to a file that does not move) and OP-16 (this device's own kept links)."""

    BUN = [{'name': 'data/opendesign/home/.bun', 'type': 'dir'},
           {'name': 'data/opendesign/home/.bun/cache.bin', 'data': b'bun-cache-bytes'},
           {'name': 'data/opendesign/projects/p0/node_modules', 'type': 'dir'},
           {'name': 'data/opendesign/projects/p0/node_modules/lib.js', 'type': 'hardlink',
            'linkname': 'data/opendesign/home/.bun/cache.bin'}]

    def link(self, name, target):
        return {'name': f'data/opendesign/{name}', 'type': 'hardlink', 'linkname': f'data/opendesign/{target}'}

    def test_op11_a_link_into_a_package_cache_gets_the_content_not_a_stop(self):
        backup = self.upload_od(extra=self.BUN)
        row = self.row(backup)
        self.assertEqual((row['importable'], row['ok'], levels(row, 'stop')), (True, True, []))
        self.assertEqual(issue_of(row, 'opendesign.links-copied')['level'], 'auto')
        self.assertEqual((row['open-design']['links_copied'], row['open-design']['skipped']), (1, 0))
        result = self.convert(backup, ['open-design'])
        data = self.volume(DATA)
        member, content = data['projects/p0/node_modules/lib.js']
        self.assertEqual((member.isfile(), member.islnk(), content), (True, False, b'bun-cache-bytes'))
        self.assertEqual(data['home/.bun/cache.bin'][1], b'cache', "the cache itself stays this device's")
        self.assertTrue(any('硬連結' in note and '複製' in note for note in result['ha_import']['notes']))

    def test_op11_what_it_cannot_copy_is_left_out_and_listed_not_a_stop_and_not_a_leak(self):
        # a login, the Paseo pairing, the rewritten preferences, a folder it does not know, HA's MCP token: never copied
        cases = {'login': ('home/.claude/.credentials.json', b'ha-claude-login'),
                 'pairing': ('paseo/pairing.private.json', b'ha-paseo-pairing'),
                 'identity': ('integrations/omnigent/state.json', b'ha-omnigent-host'),
                 'preferences': ('app-config.json', b'ha-anthropic-key'),
                 'shared-left': ('shared/mcp/servers.json', b'"servers": []')}
        for label, (target, secret) in cases.items():
            with self.subTest(label=label):
                self.world.volume_data.clear()
                backup = self.upload_od(extra=[self.link('projects/p0/copy-of-it', target)])
                row = self.row(backup)
                self.assertEqual((row['importable'], levels(row, 'stop')), (True, []))
                self.assertEqual(issue_of(row, 'files.skipped')['items'], ['projects/p0/copy-of-it'])
                self.convert(backup, ['open-design'], acknowledged=ack(row))
                self.assertNotIn('projects/p0/copy-of-it', self.volume(DATA))
                if secret != b'"servers": []':   # shared/mcp is HA's own and not secret: only not copied
                    self.assertNotIn(secret, self.world.volume_data[DATA], 'the content of HA\'s secret is nowhere in the volume')

    def test_op11_a_link_to_the_mcp_token_of_ha_is_never_copied_by_the_reader_either(self):
        extra = [{'name': 'data/opendesign/projects/p0/mcp-leak', 'type': 'hardlink', 'linkname': 'data/mcp/state.json'}]
        backup = self.upload_od(extra=extra)
        row = self.row(backup)
        self.assertEqual((row['importable'], levels(row, 'stop')), (True, []))
        self.assertEqual(issue_of(row, 'files.skipped')['items'], ['data/opendesign/projects/p0/mcp-leak'])
        self.convert(backup, ['open-design'], acknowledged=ack(row))
        self.assertNotIn('projects/p0/mcp-leak', self.volume(DATA))
        self.assertNotIn(b'ha-mcp-bearer', self.world.volume_data[DATA])

    def secret_link(self, more=False):
        extra = [self.link('projects/p0/key', 'home/.claude/.credentials.json')]
        if more:
            extra.append(self.link('projects/p0/key2', 'home/.claude/.credentials.json'))
        return self.upload_od(extra=extra)

    def test_op11_several_links_to_one_file_cost_one_copy(self):
        extra = [{'name': 'data/opendesign/home/.bun/big.bin', 'data': b'bun-cache-bytes'}] + [
            self.link(f'projects/p0/l{i}', 'home/.bun/big.bin') for i in range(8)]
        backup = self.upload_od(extra=extra)
        self.assertEqual(self.row(backup)['open-design']['links_copied'], 1)
        self.convert(backup, ['open-design'])
        data = self.volume(DATA)
        self.assertEqual((data['projects/p0/l0'][0].isfile(), data['projects/p0/l0'][1]), (True, b'bun-cache-bytes'))
        for i in range(1, 8):
            self.assertEqual((data[f'projects/p0/l{i}'][0].islnk(), data[f'projects/p0/l{i}'][0].linkname), (True, 'projects/p0/l0'))

    def test_op11_what_is_copied_still_counts_against_the_readers_budget(self):
        # four cache files with a link each: without copies the walk is 4 MiB, with them 8 MiB; the budget of the reader is 5 MiB
        size = 1 << 20
        extra = []
        for i in range(4):
            extra += [{'name': f'data/opendesign/home/.bun/f{i}.bin', 'data': bytes([65 + i]) * size},
                      self.link(f'projects/p0/l{i}', f'home/.bun/f{i}.bin')]
        real = habackup.Select
        with mock.patch.object(od.habackup, 'Select', lambda **kwargs: real(**kwargs, max_bytes=5 * size)):
            row = self.row(self.upload_od(extra=extra))
            self.assertEqual((row['importable'], levels(row, 'stop')), (False, ['failure.limit-exceeded']))
            row = self.row(self.upload_od(extra=extra[:2]))     # one file, one link: 2 MiB
            self.assertEqual((row['importable'], row['open-design']['links_copied']), (True, 1))

    def test_op11_a_link_that_is_left_out_not_confirmed_stops_only_this_app(self):
        self.assert_not_confirmed(self.secret_link(), 'files.skipped', ['projects/p0/key'], '取不到內容的硬連結 1 個')

    def test_op11_a_link_that_is_left_out_confirmed_goes_on(self):
        self.assert_confirmed(self.secret_link(), 'files.skipped', ['projects/p0/key'])
        self.assertNotIn('projects/p0/key', self.volume(DATA))
        self.assertNotIn(b'ha-claude-login', self.world.volume_data[DATA])

    def test_op11_a_link_that_is_left_out_one_more_name_asks_again(self):
        self.assert_one_more_name_asks_again(self.secret_link(), self.secret_link(more=True), 'files.skipped')

    def test_op11_the_check_and_the_conversion_decide_alike(self):
        # the names of the check are the names of the conversion (the key of a confirmation): a mix of all three outcomes
        extra = self.BUN + [self.link('projects/p0/key', 'home/.claude/.credentials.json'),
                            self.link('projects/p0/early', 'projects/p0/index.html')]
        backup = self.upload_od(extra=extra)
        row = self.row(backup)
        self.assertEqual(issue_of(row, 'files.skipped')['items'], ['projects/p0/key'])
        result = self.convert(backup, ['open-design'], acknowledged=ack(row))
        data = self.volume(DATA)
        self.assertTrue(data['projects/p0/early'][0].islnk(), 'a link to a file that moves stays a link')
        self.assertTrue(data['projects/p0/node_modules/lib.js'][0].isfile())
        self.assertEqual([i['id'] for i in result['results'][0]['issues'] if i['level'] == 'confirm'], ['files.skipped'])

    def test_op16_a_kept_link_to_a_replaced_file_keeps_its_own_content(self):
        self.world.live_extra = [{'name': 'home/db-link', 'type': 'hardlink', 'linkname': 'app.sqlite'}]
        result = self.convert(self.upload_od(), ['open-design'])
        data = self.volume(DATA)
        member, content = data['home/db-link']
        self.assertEqual((member.isfile(), content), (True, b'target-db'), "this device's old content, not HA's")
        self.assertEqual(data['app.sqlite'][1], sqlite_bytes(), "the database itself is HA's")
        self.assertIn('opendesign.kept-links-copied', [i['id'] for i in result['results'][0]['issues'] if i['level'] == 'auto'])

    def test_op16_several_kept_links_to_one_file_stay_links_of_each_other(self):
        self.world.live_extra = [{'name': 'home/db-link', 'type': 'hardlink', 'linkname': 'app.sqlite'},
                                 {'name': 'home/db-link2', 'type': 'hardlink', 'linkname': 'app.sqlite'}]
        self.convert(self.upload_od(), ['open-design'])
        data = self.volume(DATA)
        self.assertEqual((data['home/db-link'][0].isfile(), data['home/db-link'][1]), (True, b'target-db'))
        self.assertEqual((data['home/db-link2'][0].islnk(), data['home/db-link2'][0].linkname), (True, 'home/db-link'))

    def test_op16_a_kept_link_whose_file_is_not_in_the_export_is_left_out_and_asks_once_more(self):
        self.world.live_extra = [{'name': 'home/ghost', 'type': 'hardlink', 'linkname': 'nothing-here'}]
        backup = self.upload_od()
        self.assertTrue(self.row(backup)['ok'], 'the check cannot know it: it does not read this device\'s data')
        with self.assertRaises(BackupError) as caught:
            self.convert(backup, ['open-design'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        line = caught.exception.issues[0]
        self.assertEqual((line.id, line.names), ('files.skipped', ('這台：home/ghost',)))
        self.assertEqual((self.storage.list_backups(), self.world.manifests), ([], {}))
        result = self.convert(backup, ['open-design'], acknowledged={'open-design': [line.key('open-design')]})
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertNotIn('home/ghost', self.volume(DATA))

    def test_a_link_decision_is_the_same_in_the_check_and_in_the_tar(self):
        class Entry:
            copied = 0

            def copy_later(self):
                Entry.copied += 1

        with tempfile.TemporaryDirectory() as tmp:
            for make in (lambda report: od._Count(report),
                         lambda report: hacommon.TreeTar(Path(tmp) / f'{id(report)}.tar', 0, 0, None, report=report)):
                report = habackup.Report(names=haissues.Names)
                out = make(report)
                try:
                    out.file('a', mock.Mock(size=1, mtime=1, read=lambda n=-1: b'x'), 0o644) if isinstance(out, od._Count) else None
                    out.files.add('a')
                    self.assertEqual(out.hardlink('b', 'a', 1), 'link')
                    self.assertEqual(out.hardlink('c', 'zzz', 1, entry=Entry()), 'copy')
                    self.assertEqual(out.hardlink('d', 'zzz', 1), 'skip')
                    self.assertEqual(report.skips['hardlink'].first, ['d'])
                    self.assertEqual(out.symlink('l', 'ok', 1), True)
                    self.assertEqual(out.symlink('l2', '../../outside', 1), False)
                    self.assertEqual(report.skips['symlink'].first, ['l2'])
                finally:
                    if hasattr(out, 'close'):
                        out.close()

    def test_which_targets_may_be_copied(self):
        yes = ('projects/p0/index.html', 'app.sqlite', 'shared/workspaces/a', 'connectors/credentials.json',
               'home/.bun/install/cache/x', 'home/.npm/_cacache/y', 'home/.cache/pnpm/z', 'home/.local/share/pnpm/store/v3/f',
               'home/.pnpm-store/v3/f', 'home/.yarn/cache/x')
        no = ('app-config.json', 'mcp-config.json', 'home/.claude/.credentials.json', 'home/.codex/auth.json', 'home/.ssh/id',
              'home/.config/gh/hosts.yml', 'home/.local/share/opencode/auth.json', 'home/.bunker/x', 'home/.cachey/x',
              'paseo/pairing.private.json', 'integrations/omnigent/state.json', 'installation.json', 'credentials',
              '.backup/omnigent-1', 'shared/mcp/servers.json', 'shared/plugins/x', 'mystery/x', 'diagnostics/outbox.sqlite')
        for target in yes:
            self.assertTrue(od._copy_ok(target), target)
        for target in no:
            self.assertFalse(od._copy_ok(target), target)


class ParityLiveTests(ParityCase):
    """OP-14 (the sandboxed reader of the database) and OP-15 (the read of this device's own volumes)."""

    UNITS = {'open-design.service', 'open-design-terminal.service'}

    def flaky(self, failures, make_error):
        """(a hasqlite.run that raises make_error() the first `failures` times, the list of its calls)."""
        calls = []
        real = hasqlite.run

        def run(*args, **kwargs):
            calls.append(1)
            if len(calls) <= failures:
                raise make_error()
            return real(*args, **kwargs)

        return run, calls

    def timeout(self):
        return BackupError('job-failed', '讀取 HA 備份中的OpenDesign 資料庫逾時。')

    def test_op14_a_reader_that_fails_once_is_started_again_and_the_import_goes_on(self):
        run, calls = self.flaky(1, self.timeout)
        backup = self.upload_od()
        with mock.patch.object(hasqlite, 'run', run):
            row = self.row(backup)
            self.assertEqual((row['importable'], levels(row, 'stop'), len(calls)), (True, [], 2))
            self.assertEqual((row['open-design']['projects'], row['open-design']['messages']), (3, 5))
        run, calls = self.flaky(0, self.timeout)
        with mock.patch.object(hasqlite, 'run', run):
            self.assertEqual(self.convert(backup, ['open-design'])['results'][0]['status'], 'converted')
            self.assertEqual(len(calls), 1, 'a reader that works is asked once')

    def test_op14_a_reader_that_does_not_finish_stops_only_this_app_and_nothing_is_changed(self):
        network = '無法替讀取 HA 備份中的OpenDesign 資料庫的程序切斷網路（隔離失敗），已停止，沒有讀取任何資料。'
        for label, make_error in (('time', self.timeout), ('network', lambda: BackupError('job-failed', network)),
                                  ('died', lambda: BackupError('corrupt-archive', 'HA 備份中的OpenDesign 資料庫無法讀取。'))):
            run, calls = self.flaky(99, make_error)
            with self.subTest(label=label), mock.patch.object(hasqlite, 'run', run):
                backup = self.upload_od()
                row = self.stops_only_this_app(backup, 'opendesign.database-unreadable')
                self.assertEqual(len(calls), 4, 'two tries in the check, two in the conversion')
                self.assertIn('這台的 OpenDesign 沒有任何變更', issue_of(row, 'opendesign.database-unreadable')['message'])
                self.assertIn('不忙', issue_of(row, 'opendesign.database-unreadable')['action'])

    def test_op14_what_ends_the_whole_job_is_not_swallowed(self):
        run, _calls = self.flaky(99, lambda: haissues.job_wide(BackupError('insufficient-space', '磁碟空間不足。')))
        with mock.patch.object(hasqlite, 'run', run), self.assertRaises(BackupError) as caught:
            self.check(self.upload_od(), ['open-design'])
        self.assertEqual(caught.exception.code, 'insufficient-space')

    def test_op14_a_failure_that_is_no_trouble_of_the_reader_is_its_own_stop(self):
        run, calls = self.flaky(99, lambda: BackupError('internal-error', 'SQLite 讀取要求的格式不正確。'))
        with mock.patch.object(hasqlite, 'run', run):
            row = self.row(self.upload_od())
        self.assertEqual((row['importable'], levels(row, 'stop'), len(calls)), (False, ['failure.internal-error'], 1))

    # ---- OP-15
    def export_calls(self, volume=DATA):
        return [call for call in self.world.owner.calls if call[0] == 'relay' and call[-1] == volume]

    def test_op15_a_torn_export_is_read_again_and_nothing_is_paused(self):
        self.world.export_plan[DATA] = ['torn']
        result = self.convert(self.upload_od(), ['open-design'])
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertEqual((len(self.export_calls()), self.world.owner.systemd), (2, []))
        self.assertEqual(self.volume(DATA)['home/.codex/auth.json'][1], b'target-codex-login')

    def test_op15_an_export_that_fails_every_time_is_read_once_with_the_apps_own_containers_paused(self):
        self.world.needs_stopped = {DATA: self.UNITS}
        result = self.convert(self.upload_od(), ['open-design'])
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertEqual(len(self.export_calls()), od.READ_TRIES + 1, 'the tries, then the read with the containers paused')
        self.assertEqual(self.world.owner.systemd,
                         [('stop', 'open-design-terminal.service'), ('stop', 'open-design.service'),
                          ('start', 'open-design.service'), ('start', 'open-design-terminal.service')],
                         'only the containers that mount the data volume; started again, each once')
        line = next(i for i in result['results'][0]['issues'] if i['id'] == 'opendesign.service-paused')
        self.assertEqual((line['level'], line['items']), ('auto', ['open-design-terminal', 'open-design']))
        self.assertEqual(self.volume(DATA)['home/.codex/auth.json'][1], b'target-codex-login')

    def test_op15_the_mcp_volume_is_read_the_same_way_with_its_own_container(self):
        self.world.needs_stopped = {MCP: {'open-design-mcp.service'}}
        self.convert(self.upload_od(), ['open-design'])
        self.assertEqual(self.world.owner.systemd, [('stop', 'open-design-mcp.service'), ('start', 'open-design-mcp.service')])
        self.assertEqual(self.world.volume_data[MCP], LIVE_MCP)

    def test_op15_what_still_fails_when_paused_stops_only_this_app_and_the_containers_run_again(self):
        self.world.export_plan[DATA] = ['fail'] * 10
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_od(), ['open-design'])
        self.assertEqual((caught.exception.code, list(caught.exception.issues)), ('job-failed', []))
        self.assertEqual(len(self.export_calls()), od.READ_TRIES + 1)
        self.assertEqual(self.world.owner.stopped(), set(), 'everything that was paused runs again')
        self.assertEqual(sorted(unit for verb, unit in self.world.owner.systemd if verb == 'start'), sorted(self.UNITS))
        self.assertEqual((self.storage.list_backups(), self.world.manifests), ([], {}))

    def test_op15_a_failure_that_does_not_pass_is_neither_tried_again_nor_paused(self):
        self.world.export_plan[DATA] = ['limit']
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_od(), ['open-design'])
        self.assertEqual(caught.exception.code, 'limit-exceeded')
        self.assertEqual((len(self.export_calls()), self.world.owner.systemd), (1, []))

    def test_a_conversion_that_stops_early_leaves_no_file_open(self):
        class Tracking(hacommon.FileTar):
            made = []

            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                Tracking.made.append(self)

        self.world.live_extra = [{'name': 'home/ghost', 'type': 'hardlink', 'linkname': 'nothing-here'}]   # stops after the tar is made
        with mock.patch.object(hacommon, 'FileTar', Tracking), self.assertRaises(BackupError) as caught:
            self.convert(self.upload_od(), ['open-design'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertTrue(Tracking.made and all(item.handle.closed for item in Tracking.made))

    def test_op15_nothing_is_paused_when_no_container_of_the_app_runs(self):
        self.world.export_plan[DATA] = ['fail'] * 10
        self.world.not_running = {'open-design', 'open-design-terminal'}
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_od(), ['open-design'])
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertEqual((len(self.export_calls()), self.world.owner.systemd), (od.READ_TRIES, []))

    def test_op15_a_container_that_does_not_start_at_once_is_started_by_the_clean_up(self):
        self.world.needs_stopped = {DATA: self.UNITS}
        self.world.start_fails = 1
        result = self.convert(self.upload_od(), ['open-design'])
        self.assertEqual(result['results'][0]['status'], 'converted')
        starts = [unit for verb, unit in self.world.owner.systemd if verb == 'start']
        self.assertEqual(sorted(starts), ['open-design-terminal.service', 'open-design.service', 'open-design.service'],
                         'the first start failed, the clean-up tried again; the other unit once')
        self.assertEqual(self.world.owner.stopped(), set())

    def test_op15_a_cancel_while_paused_still_starts_the_containers(self):
        self.world.needs_stopped = {DATA: self.UNITS}
        real = od.hacommon.live_export
        calls = []

        def cancelled(work, app, volume, path, **kwargs):
            calls.append(1)
            if len(calls) > od.READ_TRIES:
                raise KeyboardInterrupt()
            return real(work, app, volume, path, **kwargs)

        with mock.patch.object(od.hacommon, 'live_export', cancelled), self.assertRaises(KeyboardInterrupt):
            self.convert(self.upload_od(), ['open-design'])
        self.assertEqual(self.world.owner.stopped(), set())

    def test_op15_a_tar_cut_at_a_header_is_no_whole_read(self):
        # tarfile itself reads a tar that is cut between two members as one that ended: the end marker tells the difference
        whole = fk.tar_of([{'name': '.', 'type': 'dir'}, {'name': 'a', 'data': b'x' * 700}, {'name': 'b', 'data': b'y' * 10}])
        with tempfile.TemporaryDirectory() as tmp:
            cases = {'whole': (whole, True), 'cut-at-a-header': (whole[:512 * 3 + 5], False), 'cut-at-a-member': (whole[:512 * 4], False),
                     'cut-in-data': (whole[:700], False), 'empty': (b'', False), 'no-end-blocks': (whole[:-1024 - 9216 + 512], False)}
            for name, (data, ok) in cases.items():
                with self.subTest(name=name):
                    path = Path(tmp) / name
                    path.write_bytes(data)
                    if ok:
                        od.validate_live_tar(path, '測試')
                    else:
                        with self.assertRaises(BackupError) as caught:
                            od.validate_live_tar(path, '測試')
                        self.assertEqual(caught.exception.code, 'job-failed')

    def test_op15_nothing_of_the_check_reads_this_devices_volumes_so_nothing_is_paused(self):
        self.world.needs_stopped = {DATA: self.UNITS}
        self.assertTrue(self.row(self.upload_od())['importable'])
        self.assertEqual((self.export_calls(), self.world.owner.systemd), ([], []))


@unittest.skipUnless(os.environ.get('WOOWBK_HA_B2_FIXTURES') and os.environ.get('WOOWBK_HA_KEY'),
                     'set WOOWBK_HA_B2_FIXTURES (the folder with x86/) and WOOWBK_HA_KEY to read the real OpenDesign backup')
class RealOpenDesignBackupTests(unittest.TestCase):
    """The real x86 OpenDesign add-on (0.2.15, encrypted, made 2026-11-23 by Supervisor 2026.11.0) through the walk and the
    issue collection of this module: no device, no container; what is checked is what the file says. Nothing is printed."""

    def test_the_real_backup_is_walked_and_says_what_a_check_would_say(self):
        path = Path(os.environ['WOOWBK_HA_B2_FIXTURES']) / 'x86' / 'woow-b2-opendesign-x86-enc' / 'woow-b2-opendesign-x86-enc-20261123.tar'
        if not path.exists():
            self.skipTest('the real OpenDesign backup is not in WOOWBK_HA_B2_FIXTURES')
        keys = hasecuretar.Keys(os.environ['WOOWBK_HA_KEY'])
        before = dict(jobs._MASK_COUNTS)
        with habackup.open_backup(path) as backup, tempfile.TemporaryDirectory() as tmp:
            member = next(m for m in backup.layout.members if m.role == 'addon' and m.slug.split('_', 1)[-1] == 'woow_ha_opendesign')
            report = habackup.Report(names=haissues.Names)
            out = od._Count(report)
            with backup.open_member(member.name, keys) as stream:
                src = od.scan_member(stream, report, Path(tmp), out, machine=0x3E)
            od.finish_configs(src, out, None)
            self.assertTrue(report.complete)
            self.assertEqual(src.addon.version, '0.2.15')
            answers = od.hasqlite.run([{'db': od.DATABASE, 'check': 'quick', 'counts': list(od.COUNTS),
                                        'queries': ['opendesign.project_folders', 'opendesign.routines_active']}],
                                      dict(src.dbs), Path(tmp) / 'sqlite')
            sink = haissues.Sink('open-design')
            sink.extend(od.version_issues(src.addon.version, od.VERSIONS['0.2.15'][1], '0.24.1'))
            details = od.collect(sink, src, {k: v for k, v in answers.items() if k is not None}, report)
            od.skip_line(sink, report)
        for value, count in list(jobs._MASK_COUNTS.items()):
            for _ in range(count - before.get(value, 0)):
                self.addCleanup(jobs.unmask_secret, value)
        self.assertTrue(src.tree and od.DATABASE in src.dbs)
        self.assertGreater(out.counts['files'], 10)
        self.assertGreater(details['projects'], 0)
        self.assertEqual([item.id for item in sink.found if item.level == 'stop'], [], 'the real backup is importable')
        self.assertEqual(report.skip_count('device', 'fifo', 'secret', 'large', 'name'), 0)
        self.assertEqual(src.configs_skipped, set())
        self.assertTrue(set(src.left_out) >= {'home'}, 'the agents\' home stays in HA')


def _names(data):
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return [m.name for m in tar.getmembers()]


if __name__ == '__main__':
    unittest.main()
