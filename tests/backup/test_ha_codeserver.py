"""HA import, code-server part (ha_codeserver.py): HA's VS Code settings (merged), snippets, global storage and
extensions, the agents' history and skills and the shared MCP servers move with this device's owner; this device's
agent logins, connector identities, programs and own files stay; the versions of the four programs must be the same;
the workspace goes into a new folder of this device's workspace (CONTRACT section 9 "Batch 2: code-server"). Team E2."""
import gzip
import io
import json
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from woowbackup import habackup, hacommon, ha_codeserver as cs
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import hab1fakes as fk
from . import hafixtures as hx

SLUG = '1b7b4ce7_woow_ha_code_server'
PI, IDE, EXT = 'woow-code-server-pi-data', 'woow-code-server-ide', 'woow-code-server-extensions'
IMAGE = 'ghcr.io/woowtech/woow-code-server-amd64:4.139.1-8@sha256:' + 'f' * 64
CONTAINER = (b'[Container]\nContainerName=code-server\nImage=' + IMAGE.encode() + b'\nPull=never\n'
             b'PublishPort=127.0.0.1:18443:8080\nVolume=%h/Desktop:/workspace:rw\n'
             b'Volume=%h/.ssh:/home/coder/.ssh:ro\nVolume=%h/.gitconfig:/etc/gitconfig:ro\n'
             b'Volume=%h/.local/bin:/mnt/host-local-bin:ro\nVolume=woow-code-server-pi.volume:/data/pi-agent\n'
             b'Volume=woow-code-server-ide.volume:/home/coder/.local/share/code-server/User\n'
             b'Volume=woow-code-server-extensions.volume:/home/coder/.local/share/code-server/extensions\n'
             b'UserNS=keep-id:uid=1000,gid=1000\n'
             b'Secret=code-server-config,type=mount,target=/run/secrets/code-server-config.yaml,uid=1000,gid=1000,'
             b'mode=0400\n')
QUADLETS = {'code-server.container': CONTAINER,
            'woow-code-server-pi.volume': b'[Volume]\nVolumeName=woow-code-server-pi-data\n',
            'woow-code-server-ide.volume': b'[Volume]\nVolumeName=woow-code-server-ide\n',
            'woow-code-server-extensions.volume': b'[Volume]\nVolumeName=woow-code-server-extensions\n'}
VERSIONS = (b'code-server=4.139.1 0d8c1b4c with Code 1.139.1\npi=0.99.1\nclaude=2.1.285 (Claude Code)\n'
            b'codex=codex-cli 0.167.0\n')
ARM_ELF = b'\x7fELF\x02\x01\x01' + bytes(11) + b'\xb7\x00' + bytes(40)
HA_SETTINGS = (b'{\n  // HA\'s own comment\n  "editor.fontSize": 15,\n  "terminal.integrated.defaultProfile.linux": "zsh",\n'
               b'  "terminal.integrated.profiles.linux": {"zsh": {"path": "/usr/bin/zsh"}},\n'
               b'  "editor.defaultFormatter": "esbenp.prettier-vscode",\n'
               b'  "[home-assistant]": {"editor.tabSize": 2},\n  "[yaml]": {"editor.tabSize": 2, '
               b'"editor.defaultFormatter": "esbenp.prettier-vscode"},\n'
               b'  "files.associations": {"*.yaml": "home-assistant", "*.dash": "yaml"},\n'
               b'  "security.workspace.trust.enabled": true,\n'
               b'  "acp.agents": {"pi": {"command": "ha-pi"}, "mine": {"command": "my-agent"}},\n'
               b'  "url.example": "http://not // a comment",\n}\n')
LIVE_SETTINGS = {'acp.agents': {'pi': {'command': 'pi-code'}, 'claude': {'command': 'claude-agent-acp'},
                                'codex': {'command': 'codex-code'}},
                 'workbench.colorTheme': 'Default Dark Modern', 'terminal.integrated.defaultProfile.linux': 'bash',
                 'security.workspace.trust.enabled': False, 'extensions.autoUpdate': 'off'}
HA_MCP = {'mcpServers': {'docs': {'url': 'https://docs.example/mcp'},
                         'ha-core': {'url': 'http://supervisor/core/api/mcp'},
                         'secret-one': {'command': 'node', 'args': ['x.js'], 'env': {'TOKEN': 'ha-mcp-token-value'}},
                         'shared-name': {'url': 'https://ha.example/mcp'}}}
LIVE_MCP = {'mcpServers': {'shared-name': {'url': 'https://target.example/mcp'},
                           'target-own': {'url': 'https://target-own.example/mcp'}}}


def sqlite_bytes():
    tmp = tempfile.TemporaryDirectory()
    try:
        path = Path(tmp.name) / 'agent-host.db'
        conn = sqlite3.connect(path)
        conn.executescript('CREATE TABLE items(key TEXT PRIMARY KEY, value BLOB); INSERT INTO items VALUES ("a", "b");')
        conn.commit()
        conn.close()
        return path.read_bytes()
    finally:
        tmp.cleanup()


def history(*stamps, project='/share/projects'):
    return b''.join(json.dumps({'display': f'prompt {s}', 'timestamp': s, 'project': project}).encode() + b'\n'
                    for s in stamps)


def ext_entry(ident, version, platform=None, base='/data/vscode/extensions'):
    rel = f'{ident}-{version}' + (f'-{platform}' if platform else '')
    meta = {'installedTimestamp': 1}
    if platform:
        meta['targetPlatform'] = platform
    return {'identifier': {'id': ident}, 'version': version, 'location': {'$mid': 1, 'path': f'{base}/{rel}',
                                                                          'scheme': 'file'},
            'relativeLocation': rel, 'metadata': meta}


HA_EXTS = [ext_entry('woowtech.paseo', '0.1.6'), ext_entry('streetsidesoftware.code-spell-checker', '4.5.6'),
           ext_entry('rust-lang.rust-analyzer', '0.4.1', 'linux-arm64'), ext_entry('redhat.vscode-yaml', '1.24.0')]
LIVE_EXTS = [ext_entry('redhat.vscode-yaml', '1.24.0', base=cs.EXT_TARGET)]


def addon_tar(*, version='0.1.14', extra=(), without=(), settings=HA_SETTINGS, exts=HA_EXTS):
    addon = {'user': {'version': version, 'image': 'ghcr.io/woowtech/woow-ha-code-server-amd64', 'options': {}},
             'system': {'slug': 'woow_ha_code_server', 'name': 'Woow Code Server'}, 'version': version,
             'state': 'started'}
    d = lambda name, **kw: {'name': name, 'type': 'dir', **kw}  # noqa: E731
    f = lambda name, data, **kw: {'name': name, 'data': data, **kw}  # noqa: E731
    P, U, X = 'data/pi-agent', 'data/vscode/User', 'data/vscode/extensions'
    entries = [d('.'), f('./addon.json', json.dumps(addon).encode()), d('data'),
               f('data/options.json', b'{"direct_password": "ha-direct-pw"}'),
               d('data/.ssh', mode=0o700), f('data/.ssh/id_ed25519', b'ha-ssh-private-key', mode=0o600),
               d('data/git'), f('data/git/.gitconfig', b'[user]\n name = ha\n'),
               f('data/.zsh_history', b'ha typed commands'), d('data/claude'), f('data/claude/x.json', b'legacy'),
               d('data/woow-connectors-primary'), d('data/woow-connectors-primary/omnigent'),
               f('data/woow-connectors-primary/omnigent/state.json', b'ha-omnigent-host-id'),
               d(P), f(f'{P}/auth.json', b'{"ha": "pi-oauth"}', mode=0o600),
               f(f'{P}/mcp-auth.json', b'{"ha": "mcp-oauth"}', mode=0o600),
               f(f'{P}/settings.json', b'{"defaultProvider": "ha"}'), f(f'{P}/models.json', b'{"ha": "models"}'),
               f(f'{P}/mcp.json', b'{"mcpServers": {}}'), f(f'{P}/trust.json', b'{"/share/projects": true}'),
               d(f'{P}/sessions'), d(f'{P}/sessions/--share-projects--'),
               f(f'{P}/sessions/--share-projects--/2026-11-20_a.jsonl', b'{"type":"session"}\n'),
               f(f'{P}/sessions/--share-projects--/run.sh', b'#!/bin/sh\n', mode=0o4755),
               {'name': f'{P}/sessions/--share-projects--/latest', 'type': 'symlink',
                'linkname': '2026-11-20_a.jsonl'},
               {'name': f'{P}/sessions/--share-projects--/out', 'type': 'symlink', 'linkname': '/etc/passwd'},
               {'name': f'{P}/sessions/--share-projects--/copy.jsonl', 'type': 'hardlink',
                'linkname': f'{P}/sessions/--share-projects--/2026-11-20_a.jsonl'},
               d(f'{P}/skills'), d(f'{P}/skills/ha-skill'), f(f'{P}/skills/ha-skill/SKILL.md', b'# HA skill'),
               d(f'{P}/skills/same'), f(f'{P}/skills/same/SKILL.md', b'# HA version'),
               f(f'{P}/skills/same/extra.md', b'HA extra'),
               d(f'{P}/claude'), f(f'{P}/claude/.credentials.json', b'ha-claude-login', mode=0o600),
               f(f'{P}/claude/.claude.json', b'{"oauthAccount": "ha"}'),
               f(f'{P}/claude/history.jsonl', history(100, 300)),
               d(f'{P}/claude/projects'), d(f'{P}/claude/projects/-share-projects'),
               f(f'{P}/claude/projects/-share-projects/s1.jsonl', b'{"claude":"session"}\n'),
               d(f'{P}/claude/cache'), f(f'{P}/claude/cache/x.bin', b'cache'),
               d(f'{P}/codex'), f(f'{P}/codex/auth.json', b'ha-codex-login', mode=0o600),
               f(f'{P}/codex/config.toml', b'model = "ha"'), f(f'{P}/codex/state_5.sqlite', sqlite_bytes()),
               d(f'{P}/codex/sessions'), d(f'{P}/codex/sessions/2026'),
               f(f'{P}/codex/sessions/2026/rollout-1.jsonl', b'{"codex":"rollout"}\n'),
               d(f'{P}/home'), d(f'{P}/home/.pi'), d(f'{P}/home/.pi/pi-acp'),
               f(f'{P}/home/.pi/pi-acp/session-map.json', b'{"map": {}}'), d(f'{P}/home/.npm'),
               f(f'{P}/home/.npm/cache.json', b'{}'),
               d(f'{P}/shared'), f(f'{P}/shared/mcp.json', json.dumps(HA_MCP).encode()),
               f(f'{P}/shared/managed.json', b'{"servers": {}}'),
               d(f'{P}/bin'), f(f'{P}/bin/rg', b'\x7fELF' + bytes(60), mode=0o755),
               d(f'{P}/connectors'), f(f'{P}/connectors/qa.bin', b'qa leftovers'),
               d(f'{P}/codex-bootstrap'), f(f'{P}/codex-bootstrap/package.json', b'{}'),
               d('data/vscode'), d(U), f(f'{U}/keybindings.json', b'[{"key": "ctrl+h"}]'),
               d(f'{U}/snippets'), f(f'{U}/snippets/woow-import-test.code-snippets', b'{"ha": {}}'),
               d(f'{U}/globalStorage'), f(f'{U}/globalStorage/agent-host.db', sqlite_bytes()),
               f(f'{U}/globalStorage/agent-host.db-wal', b''), f(f'{U}/globalStorage/agent-host.db-shm', b'shm'),
               f(f'{U}/globalStorage/agent-host-config.json', b'{"x": "http://homeassistant:8123/api"}'),
               d(f'{U}/globalStorage/woowtech.omnigent'),
               f(f'{U}/globalStorage/woowtech.omnigent/state.json', b'ha-connector-ext-state'),
               d(f'{U}/workspaceStorage'), d(f'{U}/workspaceStorage/abc'),
               f(f'{U}/workspaceStorage/abc/workspace.json', b'{"folder": "file:///share/projects"}'),
               f(f'{U}/machineid', b'ha-machine'), d(f'{U}/History'), d(f'{U}/History/1a2b'),
               f(f'{U}/History/1a2b/entries.json', b'{}'),
               d(X), f(f'{X}/.woow-connector-seed.json', b'{}')]
    if settings is not None:
        entries.append(f(f'{U}/settings.json', settings))
    if exts is not None:
        entries.append(f(f'{X}/extensions.json', json.dumps(exts).encode()))
    for item in (exts or []):
        rel = item['relativeLocation']
        entries += [d(f'{X}/{rel}'), f(f'{X}/{rel}/package.json', json.dumps({'name': rel}).encode())]
        if 'arm64' in rel:
            entries.append(f(f'{X}/{rel}/server/ra', ARM_ELF, mode=0o755))
    entries = [e for e in entries if e['name'] not in without]
    return gzip.compress(hx.tar_bytes(entries + list(extra)), mtime=0)


def share_tar(*, projects=True):
    entries = [{'name': '.', 'type': 'dir'}, {'name': 'other-addon', 'type': 'dir'},
               {'name': 'other-addon/big.bin', 'data': b'not ours'}]
    if projects:
        entries += [{'name': 'projects', 'type': 'dir'}, {'name': 'projects/t1', 'type': 'dir'},
                    {'name': 'projects/t1/讀我　說明.md', 'data': '# 測試'.encode()},
                    {'name': 'projects/t1/link', 'type': 'symlink', 'linkname': '讀我　說明.md'},
                    {'name': 'projects/t1/.git', 'type': 'dir'},
                    {'name': 'projects/t1/.git/HEAD', 'data': b'ref: refs/heads/main\n'}]
    return gzip.compress(hx.tar_bytes(entries), mtime=0)


def live_pi(extra=()):
    return fk.tar_of([{'name': '.', 'type': 'dir'},
                      {'name': 'auth.json', 'data': b'target-pi-login', 'mode': 0o600},
                      {'name': 'settings.json', 'data': b'{"defaultProvider": "target"}'},
                      {'name': 'mcp.json', 'data': b'{"mcpServers": {"target": {}}}'},
                      {'name': 'connectors-primary', 'type': 'dir', 'mode': 0o700},
                      {'name': 'connectors-primary/omnigent', 'type': 'dir'},
                      {'name': 'connectors-primary/omnigent/state.json', 'data': b'target-omnigent-host'},
                      {'name': 'skills', 'type': 'dir'}, {'name': 'skills/same', 'type': 'dir'},
                      {'name': 'skills/same/SKILL.md', 'data': b'# target version'},
                      {'name': 'skills/target-only', 'type': 'dir'},
                      {'name': 'skills/target-only/SKILL.md', 'data': b'# target only'},
                      {'name': 'claude', 'type': 'dir', 'mode': 0o700},
                      {'name': 'claude/.credentials.json', 'data': b'target-claude-login', 'mode': 0o600},
                      {'name': 'claude/history.jsonl', 'data': history(200, project='/workspace')},
                      {'name': 'codex', 'type': 'dir'}, {'name': 'codex/auth.json', 'data': b'target-codex-login'},
                      {'name': 'shared', 'type': 'dir'}, {'name': 'shared/mcp.json', 'data': json.dumps(LIVE_MCP).encode()},
                      {'name': 'bin', 'type': 'dir'}, {'name': 'bin/rg', 'data': b'target rg', 'mode': 0o755},
                      {'name': 'bin/rg2', 'type': 'hardlink', 'linkname': 'bin/rg'}, *extra])


def live_ide(extra=()):
    return fk.tar_of([{'name': '.', 'type': 'dir'},
                      {'name': 'settings.json', 'data': json.dumps(LIVE_SETTINGS).encode()},
                      {'name': 'keybindings.json', 'data': b'[{"key": "target"}]'},
                      {'name': 'snippets', 'type': 'dir'},
                      {'name': 'snippets/target.code-snippets', 'data': b'{"target": {}}'},
                      {'name': 'workspaceStorage', 'type': 'dir'}, {'name': 'workspaceStorage/t', 'type': 'dir'},
                      {'name': 'workspaceStorage/t/workspace.json', 'data': b'{"folder": "file:///workspace"}'},
                      {'name': 'machineid', 'data': b'target-machine'},
                      {'name': 'globalStorage', 'type': 'dir'},
                      {'name': 'globalStorage/woowtech.omnigent', 'type': 'dir'},
                      {'name': 'globalStorage/woowtech.omnigent/state.json', 'data': b'target-connector-ext-state'},
                      *extra])


def live_ext(exts=LIVE_EXTS):
    entries = [{'name': '.', 'type': 'dir'}]
    if exts is not None:
        entries.append({'name': 'extensions.json', 'data': json.dumps(exts).encode()})
    for item in exts or []:
        entries += [{'name': item['relativeLocation'], 'type': 'dir'},
                    {'name': f'{item["relativeLocation"]}/package.json', 'data': b'{"target": true}'}]
    entries += [{'name': 'woowtech.paseo-0.1.6', 'type': 'dir'},
                {'name': 'woowtech.paseo-0.1.6/package.json', 'data': b'{"seeded": "target"}'}]
    return fk.tar_of(entries)


def live_desktop():
    return fk.tar_of([{'name': './', 'type': 'dir', 'mode': 0o755},
                      {'name': './notes.txt', 'data': b'target desktop file'},
                      {'name': './proj', 'type': 'dir'}, {'name': './proj/a.py', 'data': b'print(1)'}])


class Owner(fk.Owner):
    def dir_measure(self, rel):
        assert rel == 'Desktop', rel
        return {'bytes': 100, 'members': 4, 'acls': 0, 'mount_root': False, 'mounts': [], 'more_mounts': False}

    def dir_pack(self, rel, *, stdout, timeout=None, max_output=None, abort=None):
        assert rel == 'Desktop', rel
        self.calls.append(('dir_pack', rel))
        stdout.write(self.world.desktop)


class Adapter(fk.Adapter):
    def _volume_size(self, name):
        return len(self.world.export(name))

    def import_manifest(self, staging_dir, **items):
        self.world.dir_data.update({path: Path(source).read_bytes() for path, source in (items.get('dirs') or {}).items()})
        return super().import_manifest(staging_dir, **items)


class World(fk.World):
    def __init__(self):
        super().__init__()
        self.owner = Owner(self)
        self.quadlets = {'woow-code-server': QUADLETS}
        self.versions = VERSIONS
        self.version_exit = 0
        self.desktop = live_desktop()
        self.dir_data = {}
        self.live = {PI: live_pi(), IDE: live_ide(), EXT: live_ext()}

    def factory(self, app, **_kwargs):
        return Adapter(app, self)

    def run(self, role, image, command, options, data):
        assert role == 'cs-versions', role
        return Result(self.version_exit, self.versions, b'')

    def export(self, volume):
        return self.live[volume]


class CodeServerCase(fk.ConversionCase):
    world_class = World
    data_dirs = [{'path': 'Desktop', 'label': '工作區'}]

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hacommon, 'host_elf_machine', lambda: 0x3E)
        patcher.start()
        self.addCleanup(patcher.stop)

    def catalog_apps(self):
        return {'woow-code-server': fk.app('woow-code-server', 'code-server 開發環境',
                                           volumes=[{'name': PI}, {'name': IDE}, {'name': EXT}],
                                           data_dirs=list(self.data_dirs))}

    def upload_cs(self, share=None, **kwargs):
        members = [(f'{SLUG}.tar.gz', addon_tar(**kwargs))]
        folders = ()
        if share is not None:
            members.append(('share.tar.gz', share))
            folders = ('share',)
        return self.upload(hx.outer_bytes(members, hx.ha_doc(addons=(SLUG,), folders=folders)))

    def desktop(self):
        with tarfile.open(fileobj=io.BytesIO(self.world.dir_data['Desktop'])) as tar:
            return {m.name: (m, tar.extractfile(m).read() if m.isfile() else None) for m in tar.getmembers()}


class CheckTests(CodeServerCase):
    def test_a_clean_backup(self):
        result = self.check(self.upload_cs(), ['woow-code-server'])[0]
        self.assertEqual((result['ok'], result['blockers'], result['target_version']), (True, [], '4.139.1'))
        section = result['woow-code-server']
        self.assertEqual(section['woow-code-server_version'], '4.139.1')
        self.assertEqual(section['pins'], {'code-server': '4.139.1', 'pi': '0.99.1', 'claude': '2.1.285',
                                           'codex': '0.167.0'})
        self.assertEqual(section['target_pins'], section['pins'])
        self.assertEqual((section['sessions'], section['claude_projects'], section['codex_sessions']), (1, 1, 1))
        self.assertEqual((section['skills'], section['snippets'], section['extensions'], section['mcp_servers']),
                         (2, 1, 3, 4))
        self.assertEqual((section['workspace'], section['share'], section['settings']), (False, False, True))
        self.assertEqual(section['unknown'], ['codex-bootstrap'])
        left = section['left_out']
        self.assertNotIn('pi:logins', left, 'the login files are never handed out (habackup.NEVER_READ)')
        for label in ('pi:programs', 'pi:own', 'pi:state', 'user:workspaceStorage', 'user:machineid',
                      'user:globalStorage', 'ext:own'):
            self.assertIn(label, left)
        self.assertEqual(section['ha_urls'], ['globalStorage/agent-host-config.json：homeassistant',
                                              'shared/mcp.json：supervisor'])
        joined = '\n'.join(result['warnings'])
        for words in ('沒有包含 share 資料夾', 'codex-bootstrap', '其他處理器專用的（rust-lang.rust-analyzer-0.4.1-linux-arm64）',
                      '1 個指向資料以外的符號連結', 'homeassistant', '帶有標頭或環境變數（secret-one）'):
            self.assertIn(words, joined)
        run = self.runs('cs-versions')[0]
        self.assertEqual((run[1], run[3]['--network'], run[3]['--entrypoint']), (IMAGE, ['none'], ['/bin/sh']))
        self.assertFalse([c for c in self.world.owner.calls if c[0] in ('relay', 'dir_pack')],
                         'the check exports nothing of this device')

    def test_versions(self):
        cases = (({'version': '0.1.99'}, VERSIONS, '還不認得它'),
                 ({}, VERSIONS.replace(b'pi=0.99.1', b'pi=0.98.0'), '版本不同：HA 的 Pi 是 0.99.1（附加元件 0.1.14），這台是 0.98.0'),
                 ({}, VERSIONS.replace(b'codex=codex-cli 0.167.0', b'codex='), '無法讀取這台的 Codex 版本'),
                 ({}, VERSIONS.replace(b'4.139.1 0d8c1b4c', b'4.140.0 1234567'), 'HA 的 code-server 是 4.139.1'))
        for kwargs, versions, words in cases:
            with self.subTest(words=words):
                self.world.versions = versions
                result = self.check(self.upload_cs(**kwargs), ['woow-code-server'])[0]
                self.assertFalse(result['ok'])
                self.assertTrue(any(words in b for b in result['blockers']), result['blockers'])
        # 0.1.7 shipped no Codex: an image without one has nothing to compare
        self.world.versions = VERSIONS.replace(b'codex=codex-cli 0.167.0', b'codex=')
        self.assertTrue(self.check(self.upload_cs(version='0.1.7'), ['woow-code-server'])[0]['ok'])
        self.world.version_exit = 1
        result = self.check(self.upload_cs(), ['woow-code-server'])[0]
        self.assertIn('無法讀取這台 code-server 映像中的程式版本', result['blockers'][0])

    def test_workspace_in_the_share_folder(self):
        result = self.check(self.upload_cs(share=share_tar()), ['woow-code-server'])[0]
        self.assertTrue(result['ok'], result['blockers'])
        section = result['woow-code-server']
        self.assertEqual((section['workspace'], section['share'], section['workspace_files']), (True, True, 2))
        self.assertFalse(any('share 資料夾' in w or 'projects 資料夾' in w for w in result['warnings']))
        result = self.check(self.upload_cs(share=share_tar(projects=False)), ['woow-code-server'])[0]
        self.assertTrue(any('沒有 projects 資料夾' in w for w in result['warnings']))

    def test_a_catalog_without_the_workspace_folder(self):
        self.data_dirs = []
        self.catalog = self.catalog_apps()
        result = self.check(self.upload_cs(share=share_tar()), ['woow-code-server'])[0]
        self.assertTrue(result['ok'], result['blockers'])
        self.assertTrue(any('應用設定沒有列出工作區資料夾' in w for w in result['warnings']))
        self.data_dirs = [{'path': 'Documents', 'label': 'x'}]
        self.catalog = self.catalog_apps()
        result = self.check(self.upload_cs(), ['woow-code-server'])[0]
        self.assertIn('主機資料夾設定和它的工作區（/workspace）不一致', result['blockers'][0])

    def test_quadlet_mismatch_and_nothing_to_move(self):
        self.world.quadlets['woow-code-server'] = dict(QUADLETS, **{'code-server.container': CONTAINER.replace(
            b'Volume=woow-code-server-pi.volume:/data/pi-agent\n', b'')})
        result = self.check(self.upload_cs(), ['woow-code-server'])[0]
        self.assertIn('應用設定和 Quadlet 檔不一致', result['blockers'][0])
        self.world.quadlets['woow-code-server'] = QUADLETS
        empty = [{'name': '.', 'type': 'dir'}, {'name': 'data', 'type': 'dir'}]
        addon = {'user': {'version': '0.1.14', 'image': 'ghcr.io/woowtech/woow-ha-code-server-amd64'},
                 'system': {'slug': 'woow_ha_code_server', 'name': 'Woow Code Server'}, 'version': '0.1.14'}
        member = gzip.compress(hx.tar_bytes([*empty, {'name': './addon.json', 'data': json.dumps(addon).encode()}]),
                               mtime=0)
        ha_id = self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', member)], hx.ha_doc(addons=(SLUG,))))
        result = self.check(ha_id, ['woow-code-server'])[0]
        self.assertTrue(any('沒有可搬的資料' in b for b in result['blockers']), result['blockers'])

    def test_problems_that_are_warnings_or_blockers(self):
        arm = [{'name': 'data/pi-agent/sessions/--share-projects--/pty.node', 'data': ARM_ELF}]
        result = self.check(self.upload_cs(extra=arm), ['woow-code-server'])[0]
        self.assertTrue(result['ok'], 'programs for another processor are a warning')
        self.assertTrue(any('其他處理器的程式' in w for w in result['warnings']))
        bad_db = [{'name': 'data/vscode/User/globalStorage/broken.vscdb', 'data': b'SQLite format 3\x00' + b'\xff' * 4000}]
        result = self.check(self.upload_cs(extra=bad_db), ['woow-code-server'])[0]
        self.assertTrue(result['ok'])
        self.assertTrue(any('損毀或無法讀取的資料庫（globalStorage/broken.vscdb）' in w for w in result['warnings']),
                        result['warnings'])
        link = [{'name': 'data/pi-agent/sessions/--share-projects--/key', 'type': 'hardlink',
                 'linkname': 'data/pi-agent/claude/cache/x.bin'}]
        result = self.check(self.upload_cs(extra=link), ['woow-code-server'])[0]
        self.assertTrue(any('硬連結' in b for b in result['blockers']), result['blockers'])


class ConvertTests(CodeServerCase):
    def test_the_whole_conversion(self):
        result = self.convert(self.upload_cs(share=share_tar()), ['woow-code-server'])
        self.assertEqual(sorted(self.world.manifests['woow-code-server']), ['dirs', 'volumes'])
        pi = self.volume(PI)
        names = set(pi)
        # HA's history and skills move; this device's logins, identities, programs and own files stay
        self.assertEqual(pi['sessions/--share-projects--/2026-11-20_a.jsonl'][1], b'{"type":"session"}\n')
        self.assertEqual(pi['sessions/--share-projects--/run.sh'][0].mode, 0o755, 'no setuid')
        self.assertEqual(pi['sessions/--share-projects--/latest'][0].linkname, '2026-11-20_a.jsonl')
        self.assertEqual(pi['sessions/--share-projects--/copy.jsonl'][0].linkname,
                         'sessions/--share-projects--/2026-11-20_a.jsonl')
        self.assertNotIn('sessions/--share-projects--/out', names, 'a link out of the tree is skipped')
        self.assertEqual(pi['skills/ha-skill/SKILL.md'][1], b'# HA skill')
        self.assertEqual(pi['skills/same/SKILL.md'][1], b'# target version', 'a skill of the same name stays')
        self.assertNotIn('skills/same/extra.md', names, 'never half of HA\'s skill')
        self.assertEqual(pi['skills/target-only/SKILL.md'][1], b'# target only')
        self.assertEqual(pi['auth.json'][1], b'target-pi-login')
        self.assertEqual(pi['settings.json'][1], b'{"defaultProvider": "target"}', 'this device\'s settings win')
        self.assertEqual(pi['models.json'][1], b'{"ha": "models"}', 'HA\'s models when this device has none')
        self.assertEqual(pi['mcp.json'][1], b'{"mcpServers": {"target": {}}}')
        self.assertEqual(pi['connectors-primary/omnigent/state.json'][1], b'target-omnigent-host')
        self.assertEqual(pi['claude/.credentials.json'][1], b'target-claude-login')
        self.assertEqual(pi['codex/auth.json'][1], b'target-codex-login')
        self.assertEqual(pi['bin/rg'][1], b'target rg')
        self.assertEqual(pi['bin/rg2'][0].linkname, 'bin/rg')
        self.assertEqual(pi['claude/projects/-share-projects/s1.jsonl'][1], b'{"claude":"session"}\n')
        self.assertEqual(pi['codex/sessions/2026/rollout-1.jsonl'][1], b'{"codex":"rollout"}\n')
        self.assertEqual(pi['home/.pi/pi-acp/session-map.json'][1], b'{"map": {}}')
        stamps = [json.loads(line)['timestamp'] for line in pi['claude/history.jsonl'][1].splitlines()]
        self.assertEqual(stamps, [100, 200, 300], 'prompt history merged by time')
        for gone in ('trust.json', 'codex-bootstrap', 'codex-bootstrap/package.json', 'connectors',
                     'connectors/qa.bin', 'claude/cache', 'claude/.claude.json', 'codex/config.toml',
                     'codex/state_5.sqlite', 'home/.npm', 'shared/managed.json', 'mcp-auth.json'):
            self.assertNotIn(gone, names)
        servers = json.loads(pi['shared/mcp.json'][1])['mcpServers']
        self.assertEqual(sorted(servers), ['docs', 'ha-core', 'secret-one', 'shared-name', 'target-own'])
        self.assertEqual(servers['shared-name'], LIVE_MCP['mcpServers']['shared-name'], 'the same name stays')
        self.assertEqual(servers['secret-one']['env'], {'TOKEN': 'ha-mcp-token-value'}, 'D4 a: HA\'s servers move')
        ha_written = ('sessions', 'skills/ha-skill', 'claude/projects', 'codex/sessions', 'models.json')
        self.assertEqual([n for n, (m, _d) in pi.items() if n.startswith(ha_written) and (m.uid, m.gid) != (0, 0)], [])
        self.assertEqual(pi['connectors-primary'][0].mode, 0o700, 'a live folder keeps its mode')

        ide = self.volume(IDE)
        settings = json.loads(ide['settings.json'][1])
        self.assertEqual(settings['editor.fontSize'], 15)
        self.assertEqual(settings['terminal.integrated.defaultProfile.linux'], 'bash', 'HA\'s zsh default dropped')
        self.assertNotIn('terminal.integrated.profiles.linux', settings)
        self.assertNotIn('editor.defaultFormatter', settings)
        self.assertNotIn('[home-assistant]', settings)
        self.assertEqual(settings['[yaml]'], {'editor.tabSize': 2})
        self.assertEqual(settings['files.associations'], {'*.dash': 'yaml'})
        self.assertIs(settings['security.workspace.trust.enabled'], False, 'this device\'s trust key wins')
        self.assertEqual(settings['acp.agents']['pi'], {'command': 'pi-code'})
        self.assertEqual(settings['acp.agents']['mine'], {'command': 'my-agent'})
        self.assertEqual(settings['url.example'], 'http://not // a comment')
        self.assertEqual(settings['workbench.colorTheme'], 'Default Dark Modern')
        self.assertEqual(ide['keybindings.json'][1], b'[{"key": "ctrl+h"}]', 'HA\'s file wins in the IDE folder')
        self.assertEqual(ide['snippets/woow-import-test.code-snippets'][1], b'{"ha": {}}')
        self.assertEqual(ide['snippets/target.code-snippets'][1], b'{"target": {}}')
        self.assertEqual(ide['globalStorage/agent-host.db'][1], sqlite_bytes())
        self.assertIn('globalStorage/agent-host.db-wal', ide)
        self.assertNotIn('globalStorage/agent-host.db-shm', ide)
        self.assertEqual(ide['globalStorage/woowtech.omnigent/state.json'][1], b'target-connector-ext-state')
        self.assertEqual(ide['workspaceStorage/t/workspace.json'][1], b'{"folder": "file:///workspace"}')
        self.assertNotIn('workspaceStorage/abc', ide)
        self.assertEqual(ide['machineid'][1], b'target-machine')
        self.assertIn('History/1a2b/entries.json', ide)

        ext = self.volume(EXT)
        doc = json.loads(ext['extensions.json'][1])
        self.assertEqual([item['identifier']['id'] for item in doc],
                         ['redhat.vscode-yaml', 'streetsidesoftware.code-spell-checker'])
        self.assertEqual(doc[1]['location']['path'], f'{cs.EXT_TARGET}/streetsidesoftware.code-spell-checker-4.5.6')
        self.assertIn('streetsidesoftware.code-spell-checker-4.5.6/package.json', ext)
        self.assertEqual(ext['redhat.vscode-yaml-1.24.0/package.json'][1], b'{"target": true}')
        self.assertEqual(ext['woowtech.paseo-0.1.6/package.json'][1], b'{"seeded": "target"}')
        self.assertNotIn('rust-lang.rust-analyzer-0.4.1-linux-arm64', ext)

        desk = self.desktop()
        folder = 'ha-projects-20261118'
        self.assertEqual(desk['./notes.txt'][1], b'target desktop file')
        self.assertEqual(desk['./proj/a.py'][1], b'print(1)')
        self.assertEqual(desk[f'./{folder}/t1/讀我　說明.md'][1], '# 測試'.encode())
        self.assertEqual(desk[f'./{folder}/t1/link'][0].linkname, '讀我　說明.md')
        self.assertIn(f'./{folder}/t1/.git/HEAD', desk)
        self.assertNotIn(f'./{folder}/other-addon', desk)
        self.assertEqual({(m.uid, m.gid) for m, _d in desk.values()}, {(0, 0)})

        everything = b''.join(self.world.volume_data[v] for v in (PI, IDE, EXT)) + self.world.dir_data['Desktop']
        for secret in (b'ha-ssh-private-key', b'pi-oauth', b'mcp-oauth', b'ha-claude-login', b'ha-codex-login',
                       b'ha-omnigent-host-id', b'ha-direct-pw', b'ha typed commands', b'qa leftovers',
                       b'ha-connector-ext-state', b'ha-machine'):
            self.assertNotIn(secret, everything)
        imp = result['ha_import']
        self.assertTrue(imp['notes'][0].startswith('code-server'))
        self.assertTrue(any(folder in note for note in imp['notes']))
        self.assertTrue(any('同名的技能（same）' in note for note in imp['notes']))
        reminders = imp['reminders_by_app']['woow-code-server']
        for words in ('pi 的 /login', '只能查看', 'Omnigent 與 Paseo', 'SSH 金鑰', 'rust-lang.rust-analyzer',
                      '自訂的 ACP 代理程式（mine）', 'secret-one', 'supervisor', 'codex-bootstrap'):
            self.assertTrue(any(words in line for line in reminders), words)

    def test_without_share_and_without_workspace_folder(self):
        self.convert(self.upload_cs(), ['woow-code-server'])
        desk = self.desktop()
        self.assertEqual(sorted(desk), ['.', './notes.txt', './proj', './proj/a.py'], 'the workspace stays as it is')
        self.data_dirs = []
        self.catalog = self.catalog_apps()
        self.world.dir_data.clear()
        self.world.owner.calls.clear()
        result = self.convert(self.upload_cs(share=share_tar()), ['woow-code-server'])
        self.assertEqual(sorted(self.world.manifests['woow-code-server']), ['volumes'])
        self.assertFalse([c for c in self.world.owner.calls if c[0] == 'dir_pack'])
        self.assertEqual(result['ha_import']['apps'], ['woow-code-server'])

    def test_refusals(self):
        self.world.versions = VERSIONS.replace(b'claude=2.1.285', b'claude=2.1.300')
        with self.assertRaises(BackupError) as ctx:
            self.convert(self.upload_cs(), ['woow-code-server'])
        self.assertIn('Claude Code', ctx.exception.message)
        self.assertFalse([c for c in self.world.owner.calls if c[0] == 'relay'], 'refused before any export')
        self.world.versions = VERSIONS
        self.world.live[PI] = live_pi(extra=[{'name': 'models2.json', 'type': 'hardlink', 'linkname': 'settings.json'}])
        self.world.live[PI] = fk.tar_of([{'name': '.', 'type': 'dir'}, {'name': 'models.json', 'data': b'live'},
                                         {'name': 'm2.json', 'type': 'hardlink', 'linkname': 'models.json'}])
        result = self.convert(self.upload_cs(), ['woow-code-server'])
        pi = self.volume(PI)
        self.assertEqual(pi['models.json'][1], b'live', 'this device\'s file wins; its link stays whole')
        self.assertEqual(result['apps'], ['woow-code-server'])
        self.world.live[IDE] = live_ide(extra=[{'name': 'kb2.json', 'type': 'hardlink', 'linkname': 'keybindings.json'}])
        with self.assertRaises(BackupError) as ctx:
            self.convert(self.upload_cs(), ['woow-code-server'])
        self.assertIn('硬連結', ctx.exception.message)

    def test_an_unreadable_extension_list_moves_no_extension(self):
        self.world.live[EXT] = fk.tar_of([{'name': '.', 'type': 'dir'}, {'name': 'extensions.json', 'data': b'{bad'}])
        result = self.convert(self.upload_cs(), ['woow-code-server'])
        ext = self.volume(EXT)
        self.assertEqual(ext['extensions.json'][1], b'{bad', 'this device\'s list stays as it is')
        self.assertFalse([n for n in ext if n.startswith('streetsidesoftware')])
        reminders = result['ha_import']['reminders_by_app']['woow-code-server']
        self.assertTrue(any('streetsidesoftware.code-spell-checker' in line for line in reminders))


class PureTests(unittest.TestCase):
    def test_parse_versions(self):
        self.assertEqual(cs.parse_versions(VERSIONS.decode()), cs.PINS['0.1.14'])
        self.assertEqual(cs.parse_versions('code-server=\npi=v0.99.1 (x)\nclaude=\nrubbish\n')['pi'], '0.99.1')
        self.assertIsNone(cs.parse_versions('codex=codex-cli 10.167.0.1\n')['codex'])

    def test_pins_cover_every_release(self):
        self.assertEqual(sorted(cs.PINS, key=lambda v: tuple(map(int, v.split('.')))),
                         [f'0.1.{n}' for n in range(6, 16)])
        self.assertIsNone(cs.PINS['0.1.7']['codex'])
        self.assertEqual(cs.PINS['0.1.15'], cs.PINS['0.1.14'])

    def test_jsonc(self):
        doc, comments = cs.jsonc_loads(b'{"a": "x // y", /* c */ "b": [1, 2,], // d\n "c": {"e": 1,},}')
        self.assertEqual((doc, comments), ({'a': 'x // y', 'b': [1, 2], 'c': {'e': 1}}, True))
        self.assertEqual(cs.jsonc_loads(b'{"a": "\\" // "}'), ({'a': '" // '}, False))
        for bad in (b'[1]', b'{"a": 1', b'/* open', b'\xff', b'{"a": 1, "a": 2}'):
            self.assertEqual(cs.jsonc_loads(bad), (None, False), bad)

    def test_merge_history(self):
        merged = cs.merge_history(history(5, 1), history(3, 5))
        self.assertEqual([json.loads(line)['timestamp'] for line in merged.splitlines()], [1, 3, 5])
        self.assertIsNone(cs.merge_history(b'not json\n', history(1)))
        with mock.patch.object(cs, 'MAX_HISTORY', 10):
            self.assertIsNone(cs.merge_history(history(1), history(2)))

    def test_merge_mcp_and_review(self):
        merged, added, same = cs.merge_mcp(HA_MCP, LIVE_MCP)
        self.assertEqual((sorted(added), same), (['docs', 'ha-core', 'secret-one'], ['shared-name']))
        self.assertEqual(merged['mcpServers']['target-own'], LIVE_MCP['mcpServers']['target-own'])
        merged, added, _same = cs.merge_mcp(HA_MCP, None)
        self.assertEqual(merged, HA_MCP)
        self.assertEqual(cs.mcp_review(HA_MCP), (['secret-one'], ['supervisor']))

    def test_choose_extensions(self):
        ha = cs.extension_entries(HA_EXTS + [{'bad': 1}, {'identifier': {'id': 'x'}, 'relativeLocation': '../x'}])
        live = cs.extension_entries(LIVE_EXTS)
        move, skipped = cs.choose_extensions(ha, live, {'streetsidesoftware.code-spell-checker-4.5.6'}, 0x3E)
        self.assertEqual(move, [])
        self.assertEqual(skipped, {'streetsidesoftware.code-spell-checker-4.5.6': 'foreign',
                                   'rust-lang.rust-analyzer-0.4.1-linux-arm64': 'platform',
                                   'redhat.vscode-yaml-1.24.0': 'same'})
        move, _skipped = cs.choose_extensions(ha, live, set(), 0xB7)
        self.assertEqual(move, ['rust-lang.rust-analyzer-0.4.1-linux-arm64', 'streetsidesoftware.code-spell-checker-4.5.6'])

    def test_never_read_covers_the_logins(self):
        for name in ('data/pi-agent/auth.json', 'data/pi-agent/mcp-auth.json', 'data/pi-agent/claude/.credentials.json',
                     'data/pi-agent/codex/auth.json', 'data/options.json'):
            self.assertIn(name, habackup.NEVER_READ)
        for name in ('data/.ssh', 'data/git', 'data/.zsh_history', 'data/claude', 'data/woow-connectors-primary',
                     'data/pi-agent/connectors'):
            self.assertIn(name, cs.EXCLUDE)


if __name__ == '__main__':
    unittest.main()
