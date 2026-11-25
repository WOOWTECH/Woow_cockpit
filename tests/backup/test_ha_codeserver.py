"""HA import, code-server part (ha_codeserver.py): HA's VS Code settings (merged), snippets, global storage and
extensions, the agents' history and skills and the shared MCP servers move with this device's owner; this device's
agent logins, connector identities, programs and own files stay; the versions of the four programs must be the same;
the workspace goes into a new folder of this device's workspace (CONTRACT section 9 "Batch 2: code-server"). Team E2.
HAOS parity (2026-11-25, lane OPENDESIGN-CODESERVER): CS-01 .. CS-17 -- the versions only inform, what is left out is one line
to confirm, a hard link gets the content, a read that fails is tried again and then done once with the app's own container
paused, the extra volumes of this device are carried -- see the classes Parity*."""
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

from woowbackup import habackup, haimport, haissues, hacommon, ha_codeserver as cs, hasecuretar, hasqlite, hatarget, jobs
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


def share_tar(*, projects=True, extra=()):
    entries = [{'name': '.', 'type': 'dir'}, {'name': 'other-addon', 'type': 'dir'},
               {'name': 'other-addon/big.bin', 'data': b'not ours'}, *extra]
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
    """The app owner's runner with systemctl, and reads that fail, are torn or only work while the container is stopped."""

    def __init__(self, world):
        super().__init__(world)
        self.systemd = []

    def dir_measure(self, rel):
        return {'bytes': 100, 'members': 4, 'acls': 0, 'mount_root': False, 'mounts': [], 'more_mounts': False}

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

    def step(self, plan, need):
        step = plan.pop(0) if plan else 'ok'
        if need and not need <= self.stopped():
            step = 'fail'
        if step == 'limit':
            raise BackupError('limit-exceeded', '匯出的輸出超過上限，已停止。')
        if step == 'fail':
            raise BackupError('job-failed', 'podman 執行失敗（結束碼 125）。')
        return step

    def relay(self, args, *, stdout, timeout=None, max_output=None, check=True, abort=None):
        volume = args[-1]
        self.calls.append(('relay', *args))
        step = self.step(self.world.export_plan.get(volume), self.world.needs_stopped.get(volume))
        data = self.world.export(volume)
        stdout.write(data[:len(data) // 2 + 5] if step == 'torn' else data)
        return Result(0, None, b'')

    def dir_pack(self, rel, *, stdout, timeout=None, max_output=None, abort=None):
        self.calls.append(('dir_pack', rel))
        step = self.step(self.world.dir_plan.get(rel), self.world.dir_needs_stopped.get(rel))
        data = self.world.desktop if rel == 'Desktop' else self.world.dirs[rel]
        stdout.write(data[:len(data) // 2 + 5] if step == 'torn' else data)


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
        self.export_plan = {}        # volume -> ['fail' | 'torn' | 'ok', ...] one per export call
        self.needs_stopped = {}      # volume -> units that must be stopped before it can be exported
        self.dir_plan = {}           # folder -> the same for the pack of a host folder
        self.dir_needs_stopped = {}
        self.start_fails = 0
        self.not_running = set()     # containers `podman container inspect` says are stopped
        self.pulled = True           # False: the image is not on this device until `podman pull`
        self.pull_fails = False
        self.pulls = []
        self.dirs = {}               # other host folders of the catalog (carried as they are)

    def factory(self, app, **_kwargs):
        return Adapter(app, self)

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
        return super().podman(args, data, stdout)

    def run(self, role, image, command, options, data):
        assert role == 'cs-versions', role
        return Result(self.version_exit, self.versions, b'')

    def export(self, volume):
        return self.live[volume]


def issue_of(row, issue_id):
    return next(item for item in row['issues'] if item['id'] == issue_id)


def levels(row, level):
    return [item['id'] for item in row['issues'] if item['level'] == level]


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
        self.assertEqual(issue_of(result, 'codeserver.unknown-entries')['items'], ['codex-bootstrap'])
        for words in ('沒有包含 share 資料夾', '其他處理器專用的（rust-lang.rust-analyzer-0.4.1-linux-arm64）',
                      '1 個指向資料以外的符號連結', 'homeassistant', '帶有標頭或環境變數（secret-one）'):
            self.assertIn(words, joined)
        run = self.runs('cs-versions')[0]
        self.assertEqual((run[1], run[3]['--network'], run[3]['--entrypoint']), (IMAGE, ['none'], ['/bin/sh']))
        self.assertFalse([c for c in self.world.owner.calls if c[0] in ('relay', 'dir_pack')],
                         'the check exports nothing of this device')

    def test_versions(self):
        # CS-01, CS-02, CS-03, CS-07: the versions only inform; nothing of them stops the import
        cases = (({'version': '0.1.99'}, VERSIONS, 'codeserver.addon-unknown', []),
                 ({}, VERSIONS.replace(b'pi=0.99.1', b'pi=0.98.0'), 'codeserver.versions-differ', ['Pi（HA 0.99.1，這台 0.98.0）']),
                 ({}, VERSIONS.replace(b'codex=codex-cli 0.167.0', b'codex='), 'codeserver.target-versions-unknown', ['Codex']),
                 ({}, VERSIONS.replace(b'4.139.1 0d8c1b4c', b'4.140.0 1234567'), 'codeserver.versions-differ',
                  ['code-server（HA 4.139.1，這台 4.140.0）']))
        for kwargs, versions, issue_id, items in cases:
            with self.subTest(issue=issue_id, items=items):
                self.world.versions = versions
                result = self.check(self.upload_cs(**kwargs), ['woow-code-server'])[0]
                self.assertEqual((result['importable'], result['ok'], levels(result, 'stop')), (True, True, []))
                issue = issue_of(result, issue_id)
                self.assertEqual((issue['level'], issue['items']), ('notice', items))
        # 0.1.7 shipped no Codex: an image without one has nothing to compare
        self.world.versions = VERSIONS.replace(b'codex=codex-cli 0.167.0', b'codex=')
        result = self.check(self.upload_cs(version='0.1.7'), ['woow-code-server'])[0]
        self.assertTrue(result['ok'])
        self.assertEqual([i['id'] for i in result['issues'] if i['id'].startswith('codeserver.') and 'version' in i['id']], [])
        # the command did not run at all (CS-07)
        self.world.versions = VERSIONS
        self.world.version_exit = 1
        result = self.check(self.upload_cs(), ['woow-code-server'])[0]
        self.assertEqual((result['importable'], levels(result, 'stop')), (True, []))
        self.assertEqual(issue_of(result, 'codeserver.version-command-failed')['level'], 'notice')
        self.assertEqual(result['target_version'], '')

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
        result = self.check(self.upload_cs(), ['woow-code-server'])[0]    # CS-05: no stop any more, one line to confirm
        self.assertEqual((result['importable'], result['ok'], levels(result, 'stop')), (True, False, []))
        self.assertEqual((issue_of(result, 'codeserver.workspace-not-moved')['level'],
                          issue_of(result, 'codeserver.workspace-not-moved')['items']), ('confirm', ['Documents']))

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
        issue = issue_of(result, 'codeserver.databases-skipped')
        self.assertEqual((issue['level'], issue['items']), ('notice', ['globalStorage/broken.vscdb']))
        link = [{'name': 'data/pi-agent/sessions/--share-projects--/key', 'type': 'hardlink',
                 'linkname': 'data/pi-agent/claude/cache/x.bin'}]
        result = self.check(self.upload_cs(extra=link), ['woow-code-server'])[0]
        # a link to a file that does not move and is no cache: left out and listed (CS-10), no stop
        self.assertEqual((result['importable'], result['ok']), (True, False))
        self.assertEqual(issue_of(result, 'files.skipped')['items'], ['sessions/--share-projects--/key'])


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

    def test_versions_do_not_refuse_and_a_kept_link_to_a_replaced_file_keeps_its_content(self):
        self.world.versions = VERSIONS.replace(b'claude=2.1.285', b'claude=2.1.300')
        result = self.convert(self.upload_cs(), ['woow-code-server'])        # CS-03: a notice, not a refusal
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertIn('codeserver.versions-differ', [i['id'] for i in result['results'][0]['issues']])
        self.assertTrue([c for c in self.world.owner.calls if c[0] == 'relay'], 'it went on and read this device')
        self.world.versions = VERSIONS
        self.world.live[PI] = live_pi(extra=[{'name': 'models2.json', 'type': 'hardlink', 'linkname': 'settings.json'}])
        self.world.live[PI] = fk.tar_of([{'name': '.', 'type': 'dir'}, {'name': 'models.json', 'data': b'live'},
                                         {'name': 'm2.json', 'type': 'hardlink', 'linkname': 'models.json'}])
        result = self.convert(self.upload_cs(), ['woow-code-server'])
        pi = self.volume(PI)
        self.assertEqual(pi['models.json'][1], b'live', 'this device\'s file wins; its link stays whole')
        self.assertEqual(result['apps'], ['woow-code-server'])
        # CS-15: a kept link to a file that HA's data replaces keeps its own content (it was a stop)
        self.world.live[IDE] = live_ide(extra=[{'name': 'kb2.json', 'type': 'hardlink', 'linkname': 'keybindings.json'}])
        result = self.convert(self.upload_cs(), ['woow-code-server'])
        ide = self.volume(IDE)
        self.assertEqual((ide['kb2.json'][0].isfile(), ide['kb2.json'][1]), (True, b'[{"key": "target"}]'))
        self.assertNotEqual(ide['keybindings.json'][1], ide['kb2.json'][1], 'HA\'s file replaced the other one')

    def test_an_unreadable_extension_list_moves_no_extension(self):
        self.world.live[EXT] = fk.tar_of([{'name': '.', 'type': 'dir'}, {'name': 'extensions.json', 'data': b'{bad'}])
        result = self.convert(self.upload_cs(), ['woow-code-server'])
        ext = self.volume(EXT)
        self.assertEqual(ext['extensions.json'][1], b'{bad', 'this device\'s list stays as it is')
        self.assertFalse([n for n in ext if n.startswith('streetsidesoftware')])
        reminders = result['ha_import']['reminders_by_app']['woow-code-server']
        self.assertTrue(any('streetsidesoftware.code-spell-checker' in line for line in reminders))


# ====================================================================== HAOS parity (OPENDESIGN-CODESERVER lane)

def ack(row, *issue_ids):
    """`acknowledged` of the lines of a check result (all of them, or those named)."""
    return {'woow-code-server': [item['key'] for item in row['issues']
                                 if item['level'] == 'confirm' and (not issue_ids or item['id'] in issue_ids)]}


APP = 'woow-code-server'
UNIT = 'code-server.service'
P_TREE, U_TREE = 'data/pi-agent', 'data/vscode/User'


def pi_link(name, target):
    return {'name': f'{P_TREE}/{name}', 'type': 'hardlink', 'linkname': f'{P_TREE}/{target}'}


class ParityCase(CodeServerCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(hatarget, '_sleep', lambda _seconds: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def row(self, backup):
        return self.check(backup, [APP])[0]

    def reads(self, kind='relay'):
        return [call for call in self.world.owner.calls if call[0] == kind]

    def stops_only_this_app(self, backup, issue_id):
        row = self.row(backup)
        self.assertEqual((row['importable'], row['ok']), (False, False))
        self.assertIn(issue_id, levels(row, 'stop'))
        with self.assertRaises(BackupError) as caught:
            self.convert(backup, [APP])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertEqual([item.id for item in caught.exception.issues if item.level == 'stop'], [issue_id])
        self.assertEqual((self.storage.list_backups(), self.world.manifests), ([], {}))
        return row

    # ---- the three steps of a line to confirm (DESIGN G1)
    def assert_not_confirmed(self, backup, issue_id, items, spoken, *, nothing_read=False):
        row = self.row(backup)
        issue = issue_of(row, issue_id)
        self.assertEqual((row['importable'], row['ok'], issue['level'], issue['items']), (True, False, 'confirm', items))
        self.assertIn(spoken, issue['message'])
        self.assertLessEqual(len(issue['message']), 300)
        self.assertEqual(levels(row, 'stop'), [], 'nothing stops the app')
        for acknowledged in (None, {}, {APP: []}, {'n8n': [issue['key']]}, {APP: ['legacy.warning:0123456789abcdef']}):
            seen = len(self.reads())
            with self.subTest(acknowledged=acknowledged), self.assertRaises(BackupError) as caught:
                self.convert(backup, [APP], **({} if acknowledged is None else {'acknowledged': acknowledged}))
            self.assertEqual(caught.exception.code, 'confirmation-required')
            self.assertEqual((self.storage.list_backups(), self.world.manifests), ([], {}), 'nothing is handed to the restore')
            if nothing_read:
                self.assertEqual(len(self.reads()), seen, 'it stopped before this device was read')
        return row

    def assert_confirmed(self, backup, issue_id, items):
        row = self.row(backup)
        result = self.convert(backup, [APP], acknowledged=ack(row))
        self.assertEqual(result['results'][0]['status'], 'converted')
        registered = haimport.load_registry(self.paths)[result['backup_id']]
        self.assertEqual([(c['app_id'], c['id'], c['items']) for c in registered['confirmed'] if c['id'] == issue_id],
                         [(APP, issue_id, items)])
        return result

    def assert_one_more_name_asks_again(self, backup, more, issue_id):
        row = self.row(backup)
        with self.assertRaises(BackupError) as caught:
            self.convert(more, [APP], acknowledged=ack(row))
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertNotEqual(issue_of(self.row(more), issue_id)['key'], issue_of(row, issue_id)['key'])

    def catalog_with(self, *, volumes=(), dirs=None, **fields):
        self.catalog = {APP: fk.app(APP, 'code-server 開發環境', volumes=[{'name': name} for name in (PI, IDE, EXT, *volumes)],
                                    data_dirs=list(self.data_dirs if dirs is None else dirs), **fields)}


class ParityCheckTests(ParityCase):
    """CS-01 .. CS-08 as far as the check and the shape of this device go."""

    EXTRA = 'woow-code-server-extra'

    def extra_volume(self):
        self.world.live[self.EXTRA] = fk.tar_of([{'name': '.', 'type': 'dir', 'uid': 1000, 'gid': 1000},
                                                 {'name': 'note.txt', 'data': b'this device only', 'uid': 1000, 'gid': 1000}])
        self.catalog_with(volumes=[self.EXTRA])

    def test_cs01_cs03_what_the_versions_say_never_stops_the_conversion_either(self):
        self.world.versions = VERSIONS.replace(b'pi=0.99.1', b'pi=0.98.0')
        result = self.convert(self.upload_cs(version='0.1.99'), [APP])
        self.assertEqual(result['results'][0]['status'], 'converted')
        found = [i['id'] for i in result['results'][0]['issues']]
        self.assertIn('codeserver.addon-unknown', found)       # the table does not know 0.1.99: nothing to compare against
        self.world.versions = VERSIONS.replace(b'pi=0.99.1', b'pi=0.98.0')
        result = self.convert(self.upload_cs(), [APP])
        self.assertIn('codeserver.versions-differ', [i['id'] for i in result['results'][0]['issues']])
        self.assertEqual(self.volume(PI)['sessions/--share-projects--/2026-11-20_a.jsonl'][1], b'{"type":"session"}\n')

    def test_cs02_cs07_a_version_that_cannot_be_read_is_a_notice_in_the_conversion_too(self):
        self.world.version_exit = 1
        result = self.convert(self.upload_cs(), [APP])
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertIn('codeserver.version-command-failed', [i['id'] for i in result['results'][0]['issues']])
        self.world.version_exit = 0
        self.world.versions = VERSIONS.replace(b'claude=2.1.285 (Claude Code)', b'claude=')
        result = self.convert(self.upload_cs(), [APP])
        issue = next(i for i in result['results'][0]['issues'] if i['id'] == 'codeserver.target-versions-unknown')
        self.assertEqual(issue['items'], ['Claude Code'])

    def test_cs02_a_command_that_cannot_even_be_started_is_a_notice_not_a_stop(self):
        real = hatarget.ensure_image
        with mock.patch.object(cs.hatarget, 'ensure_image', real):
            original = self.world.run

            def broken(role, image, command, options, data):
                raise BackupError('job-failed', 'podman run 執行失敗（結束碼 126）。')
            self.world.run = broken
            row = self.row(self.upload_cs())
            self.world.run = original
        self.assertEqual((row['importable'], levels(row, 'stop')), (True, []))
        self.assertEqual(issue_of(row, 'codeserver.version-command-failed')['level'], 'notice')

    def test_cm05_an_image_that_is_not_here_is_downloaded_and_the_import_goes_on(self):
        self.world.pulled = False
        row = self.row(self.upload_cs())
        self.assertEqual((row['importable'], levels(row, 'stop')), (True, []))
        self.assertEqual(self.world.pulls, [IMAGE])
        self.assertIn('target.image-pulled', levels(row, 'auto'))

    def test_cm05_an_image_that_cannot_be_downloaded_stops_only_this_app_with_the_reason(self):
        self.world.pulled = False
        self.world.pull_fails = True
        row = self.row(self.upload_cs())
        self.assertEqual((row['importable'], levels(row, 'stop')), (False, ['target.image-missing']))

    def test_cs04_more_volumes_than_the_three_are_carried_as_they_are_and_said(self):
        self.extra_volume()
        backup = self.upload_cs()
        row = self.row(backup)
        self.assertEqual((row['importable'], row['ok'], levels(row, 'stop')), (True, True, []))
        self.assertEqual((issue_of(row, 'codeserver.extras-carried')['level'], issue_of(row, 'codeserver.extras-carried')['items']),
                         ('auto', [self.EXTRA]))
        result = self.convert(backup, [APP])
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertEqual(sorted(self.world.manifests[APP]['volumes']), sorted([PI, IDE, EXT, self.EXTRA]))
        carried = self.volume(self.EXTRA)
        self.assertEqual((sorted(carried), carried['note.txt'][1]), (['.', 'note.txt'], b'this device only'))
        self.assertEqual(self.volume(PI)['settings.json'][1], b'{"defaultProvider": "target"}', 'the three still convert')

    def test_cs04_a_link_of_this_devices_own_volume_that_the_restore_would_refuse_is_left_out_and_asks_once_more(self):
        self.world.live[self.EXTRA] = fk.tar_of([{'name': '.', 'type': 'dir', 'uid': 1000, 'gid': 1000},
                                                 {'name': 'note.txt', 'data': b'this device only', 'uid': 1000, 'gid': 1000},
                                                 {'name': 'out', 'type': 'symlink', 'linkname': '../../etc/passwd', 'uid': 1000, 'gid': 1000},
                                                 {'name': 'ghost', 'type': 'hardlink', 'linkname': 'nothing-here', 'uid': 1000, 'gid': 1000}])
        self.catalog_with(volumes=[self.EXTRA])
        backup = self.upload_cs()
        self.assertTrue(self.row(backup)['ok'], "the check does not read this device's volumes")
        with self.assertRaises(BackupError) as caught:
            self.convert(backup, [APP])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        line = caught.exception.issues[0]
        self.assertEqual((line.id, sorted(line.names)), ('files.skipped', [f'{self.EXTRA}：ghost', f'{self.EXTRA}：out']))
        result = self.convert(backup, [APP], acknowledged={APP: [line.key(APP)]})
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertEqual(sorted(self.volume(self.EXTRA)), ['.', 'note.txt'], 'the rest of the volume is carried as it is')

    def test_cs04_what_it_cannot_carry_stops_only_this_app(self):
        # no container, a missing one of the three volumes: as it was; a database in this device's entry: its own stop
        self.world.quadlets[APP] = dict(QUADLETS, **{'code-server.container': CONTAINER.replace(
            b'Volume=woow-code-server-pi.volume:/data/pi-agent\n', b'')})
        row = self.row(self.upload_cs())
        self.assertFalse(row['importable'])
        self.assertIn('Quadlet 檔不一致', row['blockers'][0])
        self.world.quadlets[APP] = QUADLETS
        self.catalog_with(postgres=[{'id': 'db', 'database': 'x'}])
        self.stops_only_this_app(self.upload_cs(), 'codeserver.target-has-database')

    def conflict(self, *names):
        self.world.dirs.update({name: fk.tar_of([{'name': './', 'type': 'dir', 'mode': 0o755},
                                                 {'name': f'./{name}.txt', 'data': f'this device {name}'.encode()}])
                                for name in names})
        self.catalog_with(dirs=[{'path': name, 'label': name} for name in names])

    def test_cs05_a_folder_setting_that_is_not_the_workspace_not_confirmed_stops_only_this_app(self):
        self.conflict('Documents')
        self.assert_not_confirmed(self.upload_cs(share=share_tar()), 'codeserver.workspace-not-moved', ['Documents'],
                                  '不是同一個資料夾', nothing_read=True)

    def test_cs05_confirmed_goes_on_without_the_workspace_and_this_devices_folder_stays(self):
        self.conflict('Documents')
        result = self.assert_confirmed(self.upload_cs(share=share_tar()), 'codeserver.workspace-not-moved', ['Documents'])
        self.assertEqual(sorted(self.world.manifests[APP]), ['dirs', 'volumes'])
        self.assertEqual(list(self.world.manifests[APP]['dirs']), ['Documents'], 'carried as it is, the workspace is not built')
        self.assertEqual(self.world.dir_data['Documents'], self.world.dirs['Documents'])
        self.assertFalse([c for c in self.reads('dir_pack') if c[1] == 'Desktop'])
        reminders = result['ha_import']['reminders_by_app'][APP]
        self.assertTrue(any('沒有搬過來' in line and '工作區' in line for line in reminders))
        self.assertEqual(self.volume(PI)['sessions/--share-projects--/2026-11-20_a.jsonl'][1], b'{"type":"session"}\n',
                         'the settings and conversations of HA move as always')

    def test_cs05_one_more_name_asks_again(self):
        self.conflict('Documents')
        backup = self.upload_cs()
        row = self.row(backup)
        self.conflict('Documents', 'Music')
        with self.assertRaises(BackupError) as caught:
            self.convert(backup, [APP], acknowledged=ack(row))
        self.assertEqual(caught.exception.code, 'confirmation-required')

    def test_cs08_no_data_stops_only_this_app_and_never_makes_this_device_empty(self):
        addon = {'user': {'version': '0.1.14', 'image': 'ghcr.io/woowtech/woow-ha-code-server-amd64'},
                 'system': {'slug': 'woow_ha_code_server', 'name': 'Woow Code Server'}, 'version': '0.1.14'}
        member = gzip.compress(hx.tar_bytes([{'name': '.', 'type': 'dir'}, {'name': 'data', 'type': 'dir'},
                                             {'name': './addon.json', 'data': json.dumps(addon).encode()}]), mtime=0)
        backup = self.upload(hx.outer_bytes([(f'{SLUG}.tar.gz', member)], hx.ha_doc(addons=(SLUG,))))
        row = self.stops_only_this_app(backup, 'codeserver.no-data')
        self.assertIn('沒有可搬的資料', issue_of(row, 'codeserver.no-data')['message'])
        self.assertIn('重新備份', issue_of(row, 'codeserver.no-data')['action'])
        self.assertEqual(self.world.volume_data, {})


class ParityConfirmTests(ParityCase):
    """CS-11: a file of HA that is too large to read is left out and listed (the one line of files.skipped)."""

    PAD = b' ' * 3000

    def small_limits(self, json_limit=2500, history_limit=None):
        patcher = mock.patch.object(cs, 'MAX_JSON', json_limit)
        patcher.start()
        self.addCleanup(patcher.stop)
        if history_limit is not None:
            patcher = mock.patch.object(cs, 'MAX_HISTORY', history_limit)
            patcher.start()
            self.addCleanup(patcher.stop)

    def big_settings(self, more=False):
        extra = [{'name': f'{P_TREE}/shared/mcp.json', 'data': json.dumps(HA_MCP).encode() + self.PAD}] if more else []
        return self.upload_cs(settings=HA_SETTINGS + self.PAD, extra=extra,
                              without=(f'{P_TREE}/shared/mcp.json',) if more else ())

    def test_cs11_a_settings_file_too_large_to_read_not_confirmed_stops_only_this_app(self):
        self.small_limits()
        self.assert_not_confirmed(self.big_settings(), 'files.skipped', [f'{U_TREE}/settings.json'], '大小超出上限的設定檔 1 個')

    def test_cs11_confirmed_goes_on_and_this_devices_own_file_stays(self):
        self.small_limits()
        result = self.assert_confirmed(self.big_settings(), 'files.skipped', [f'{U_TREE}/settings.json'])
        self.assertEqual(json.loads(self.volume(IDE)['settings.json'][1]), LIVE_SETTINGS)
        self.assertEqual(self.volume(IDE)['keybindings.json'][1], b'[{"key": "ctrl+h"}]', 'the other files of HA move')
        self.assertTrue(any('settings.json' in line and '太大' in line
                            for line in result['ha_import']['reminders_by_app'][APP]))

    def test_cs11_one_more_name_asks_again(self):
        self.small_limits()
        self.assert_one_more_name_asks_again(self.big_settings(), self.big_settings(more=True), 'files.skipped')

    def test_cs11_the_prompt_history_and_the_mcp_servers_of_ha_too_large_leave_this_devices_files(self):
        self.small_limits(json_limit=2500, history_limit=100)
        backup = self.big_settings(more=True)
        row = self.row(backup)
        self.assertEqual(sorted(issue_of(row, 'files.skipped')['items']),
                         [f'{P_TREE}/claude/history.jsonl', f'{P_TREE}/shared/mcp.json', f'{U_TREE}/settings.json'])
        self.assertEqual(sorted(row[APP]['files_kept']), ['claude/history.jsonl', 'settings.json', 'shared/mcp.json'])
        self.assertEqual((issue_of(row, 'codeserver.files-kept')['level'], len(issue_of(row, 'codeserver.files-kept')['items'])), ('notice', 3))
        self.convert(backup, [APP], acknowledged=ack(row))
        self.assertEqual(json.loads(self.volume(PI)['shared/mcp.json'][1]), LIVE_MCP, 'HA\'s servers were not added')
        self.assertEqual(self.volume(PI)['claude/history.jsonl'][1], history(200, project='/workspace'), 'not merged')

    def test_cs11_an_extension_list_too_large_leaves_the_extensions_of_ha_out_and_says_so(self):
        self.small_limits()
        backup = self.upload_cs(without=('data/vscode/extensions/extensions.json',),
                                extra=[{'name': 'data/vscode/extensions/extensions.json',
                                        'data': json.dumps(HA_EXTS).encode() + self.PAD}])
        row = self.row(backup)
        self.assertEqual(issue_of(row, 'files.skipped')['items'], ['data/vscode/extensions/extensions.json'])
        self.assertEqual(issue_of(row, 'codeserver.extensions-skipped')['level'], 'notice')
        result = self.convert(backup, [APP], acknowledged=ack(row))
        ext = self.volume(EXT)
        self.assertEqual(json.loads(ext['extensions.json'][1]), LIVE_EXTS, 'this device\'s list is not touched')
        self.assertFalse([n for n in ext if n.startswith('streetsidesoftware')])
        self.assertEqual(result['results'][0]['status'], 'converted')

    def test_cs11_what_the_reader_leaves_out_of_the_share_folder_is_a_line_of_its_own(self):
        # the workspace is walked from another member: its device files, FIFOs ... are listed the same way (a second line)
        share = share_tar(extra=[{'name': 'projects/t1/pipe', 'type': 'fifo'}])
        backup = self.upload_cs(share=share)
        row = self.row(backup)
        self.assertEqual(issue_of(row, 'files.skipped')['items'], ['projects/t1/pipe'])
        with self.assertRaises(BackupError) as caught:
            self.convert(backup, [APP])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        result = self.convert(backup, [APP], acknowledged=ack(row))
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertFalse([n for n in self.desktop() if n.endswith('/pipe')])

    def test_cs11_a_file_below_the_limit_is_read_as_before(self):
        row = self.row(self.upload_cs())
        self.assertNotIn('files.skipped', [item['id'] for item in row['issues']])
        self.assertEqual(row[APP]['files_kept'], [])


class ParityLinksTests(ParityCase):
    """CS-10 and CS-13 (hard links of HA that get the content), CS-15 (this device's own kept links)."""

    LINK = 'sessions/--share-projects--/copy-of-it'

    def test_cs10_a_link_to_a_file_this_device_keeps_gets_the_content_not_a_stop(self):
        # HA's settings.json of Pi is the file this device keeps (its own wins): a link to it gets HA's content
        backup = self.upload_cs(extra=[pi_link(self.LINK, 'settings.json')])
        row = self.row(backup)
        self.assertEqual((row['importable'], row['ok'], levels(row, 'stop')), (True, True, []))
        # (the check does not read this device's files: that its own settings.json wins is known in the conversion)
        result = self.convert(backup, [APP])
        self.assertIn('codeserver.links-copied', [i['id'] for i in result['results'][0]['issues'] if i['level'] == 'auto'])
        pi = self.volume(PI)
        member, content = pi[self.LINK]
        self.assertEqual((member.isfile(), member.islnk(), content), (True, False, b'{"defaultProvider": "ha"}'))
        self.assertEqual(pi['settings.json'][1], b'{"defaultProvider": "target"}', "this device's file still wins")

    def test_cs10_a_link_into_a_package_cache_gets_the_content(self):
        extra = [{'name': f'{P_TREE}/home/.npm/pkg.tgz', 'data': b'npm-cache-bytes'}, pi_link(self.LINK, 'home/.npm/pkg.tgz')]
        backup = self.upload_cs(extra=extra)
        row = self.row(backup)
        self.assertEqual((row['importable'], levels(row, 'stop')), (True, []))
        self.assertNotIn('files.skipped', [item['id'] for item in row['issues']])
        self.convert(backup, [APP])
        pi = self.volume(PI)
        self.assertEqual(pi[self.LINK][1], b'npm-cache-bytes')
        self.assertNotIn('home/.npm/pkg.tgz', pi, 'the cache itself stays in HA')

    def test_cs10_what_it_cannot_copy_is_left_out_and_listed_not_a_stop_and_not_a_leak(self):
        cases = {'account': ('claude/.claude.json', b'"oauthAccount"'), 'own-file': ('codex/config.toml', b'model = "ha"'),
                 'trust': ('trust.json', b'"/share/projects": true'), 'login': ('claude/.credentials.json', b'ha-claude-login'),
                 'programs': ('bin/rg', b'\x7fELF'), 'state': ('claude/cache/x.bin', None),
                 'unknown-folder': ('codex-bootstrap/package.json', None), 'home': ('home/.pi/state.json', b'ha-pi-private-state')}
        for label, (target, secret) in cases.items():
            with self.subTest(label=label):
                self.world.volume_data.clear()
                backup = self.upload_cs(extra=[{'name': f'{P_TREE}/home/.pi/state.json', 'data': b'ha-pi-private-state'},
                                               pi_link(self.LINK, target)])
                row = self.row(backup)
                self.assertEqual((row['importable'], levels(row, 'stop')), (True, []))
                items = issue_of(row, 'files.skipped')['items']
                self.assertEqual(len(items), 1)
                self.assertTrue(items[0].endswith('copy-of-it'), items)
                self.convert(backup, [APP], acknowledged=ack(row))
                self.assertNotIn(self.LINK, self.volume(PI))
                if secret is not None:
                    self.assertNotIn(secret, self.world.volume_data[PI], 'the content of what stays in HA is nowhere in the volume')

    def secret_link(self, more=False):
        extra = [pi_link('sessions/--share-projects--/key', 'claude/.claude.json')]
        if more:
            extra.append(pi_link('sessions/--share-projects--/key2', 'claude/.claude.json'))
        return self.upload_cs(extra=extra)

    def test_cs10_several_links_to_one_file_cost_one_copy(self):
        extra = [{'name': f'{P_TREE}/home/.npm/big.bin', 'data': b'npm-cache-bytes'}] + [
            pi_link(f'sessions/--share-projects--/l{i}', 'home/.npm/big.bin') for i in range(8)]
        backup = self.upload_cs(extra=extra)
        self.assertEqual(self.row(backup)[APP]['links_copied'], 1)
        self.convert(backup, [APP])
        pi = self.volume(PI)
        self.assertEqual((pi['sessions/--share-projects--/l0'][0].isfile(), pi['sessions/--share-projects--/l0'][1]),
                         (True, b'npm-cache-bytes'))
        for i in range(1, 8):
            link = pi[f'sessions/--share-projects--/l{i}'][0]
            self.assertEqual((link.islnk(), link.linkname), (True, 'sessions/--share-projects--/l0'))

    def test_cs10_what_is_copied_still_counts_against_the_readers_budget(self):
        size = 1 << 20
        extra = []
        for i in range(4):
            extra += [{'name': f'{P_TREE}/home/.npm/f{i}.bin', 'data': bytes([65 + i]) * size},
                      pi_link(f'sessions/--share-projects--/l{i}', f'home/.npm/f{i}.bin')]
        real = habackup.Select
        with mock.patch.object(cs.habackup, 'Select', lambda **kwargs: real(**kwargs, max_bytes=5 * size)):
            row = self.row(self.upload_cs(extra=extra))
            self.assertEqual((row['importable'], levels(row, 'stop')), (False, ['failure.limit-exceeded']))
            row = self.row(self.upload_cs(extra=extra[:2]))
            self.assertEqual((row['importable'], row[APP]['links_copied']), (True, 1))

    def test_cs10_a_link_that_is_left_out_not_confirmed_stops_only_this_app(self):
        self.assert_not_confirmed(self.secret_link(), 'files.skipped', ['sessions/--share-projects--/key'], '取不到內容的硬連結 1 個')

    def test_cs10_a_link_that_is_left_out_confirmed_goes_on(self):
        self.assert_confirmed(self.secret_link(), 'files.skipped', ['sessions/--share-projects--/key'])
        self.assertNotIn('sessions/--share-projects--/key', self.volume(PI))
        self.assertNotIn(b'"oauthAccount"', self.world.volume_data[PI])

    def test_cs10_a_link_that_is_left_out_one_more_name_asks_again(self):
        self.assert_one_more_name_asks_again(self.secret_link(), self.secret_link(more=True), 'files.skipped')

    def test_cs10_a_link_between_two_moved_trees_gets_the_content_and_one_to_the_connector_does_not(self):
        extra = [{'name': f'{U_TREE}/snippets/from-pi', 'type': 'hardlink', 'linkname': f'{P_TREE}/sessions/--share-projects--/2026-11-20_a.jsonl'},
                 {'name': f'{U_TREE}/snippets/from-connector', 'type': 'hardlink',
                  'linkname': f'{U_TREE}/globalStorage/woowtech.omnigent/state.json'}]
        backup = self.upload_cs(extra=extra)
        row = self.row(backup)
        self.assertEqual(issue_of(row, 'files.skipped')['items'], ['snippets/from-connector'])
        self.convert(backup, [APP], acknowledged=ack(row))
        ide = self.volume(IDE)
        self.assertEqual(ide['snippets/from-pi'][1], b'{"type":"session"}\n')
        self.assertNotIn('snippets/from-connector', ide)
        self.assertNotIn(b'ha-connector-ext-state', self.world.volume_data[IDE])

    def test_cs13_a_workspace_link_to_a_file_outside_projects_gets_the_content(self):
        share = share_tar(extra=[{'name': '.pnpm-store', 'type': 'dir'}, {'name': '.pnpm-store/f1', 'data': b'pnpm-file'},
                                 {'name': 'projects/t1/dep.js', 'type': 'hardlink', 'linkname': '.pnpm-store/f1'}])
        backup = self.upload_cs(share=share)
        row = self.row(backup)
        self.assertEqual((row['importable'], row['ok'], levels(row, 'stop')), (True, True, []))
        self.assertEqual(row[APP]['links_copied'], 1)
        self.assertEqual(issue_of(row, 'codeserver.links-copied')['level'], 'auto')
        self.convert(backup, [APP])
        desk = self.desktop()
        name = next(n for n in desk if n.endswith('/t1/dep.js'))
        self.assertEqual((desk[name][0].isfile(), desk[name][1]), (True, b'pnpm-file'))
        self.assertFalse([n for n in desk if '.pnpm-store' in n], 'the store itself is not moved')

    def test_cs13_the_walk_copies_a_link_whose_file_the_folder_does_not_hold(self):
        class Out:
            folder = 'f'

            def __init__(self):
                self.files, self.added = set(), []

            def add(self, rel, kind, **kwargs):
                self.added.append((rel, kind, kwargs.get('linkname')))

        entries = [{'name': 'projects', 'type': 'dir'}, {'name': 'projects/a', 'data': b'A'},
                   {'name': 'projects/b', 'type': 'hardlink', 'linkname': 'projects/a'}]
        out, report = Out(), habackup.Report(names=haissues.Names)
        ws = cs.scan_share(io.BytesIO(hx.tar_bytes(entries)), report, out)
        self.assertEqual([item for item in out.added if item[0] == 'f/b'], [('f/b', 'file', None)])
        self.assertEqual((ws.links_copied, report.copied_links), (1, 1))

    def test_cs15_several_kept_links_to_a_replaced_file_share_one_copy_of_its_content(self):
        self.world.live[IDE] = live_ide(extra=[{'name': 'kb2.json', 'type': 'hardlink', 'linkname': 'keybindings.json'},
                                               {'name': 'kb3.json', 'type': 'hardlink', 'linkname': 'keybindings.json'}])
        result = self.convert(self.upload_cs(), [APP])
        ide = self.volume(IDE)
        self.assertEqual((ide['kb2.json'][0].isfile(), ide['kb2.json'][1]), (True, b'[{"key": "target"}]'))
        self.assertEqual((ide['kb3.json'][0].islnk(), ide['kb3.json'][0].linkname), (True, 'kb2.json'))
        self.assertEqual(ide['keybindings.json'][1], b'[{"key": "ctrl+h"}]', "HA's file replaced this device's")
        self.assertIn('codeserver.kept-links-copied', [i['id'] for i in result['results'][0]['issues'] if i['level'] == 'auto'])

    def test_cs15_a_kept_link_whose_file_is_not_in_the_export_is_left_out_and_asks_once_more(self):
        self.world.live[IDE] = live_ide(extra=[{'name': 'ghost.json', 'type': 'hardlink', 'linkname': 'nothing-here'}])
        backup = self.upload_cs()
        self.assertTrue(self.row(backup)['ok'], "the check does not read this device's data")
        with self.assertRaises(BackupError) as caught:
            self.convert(backup, [APP])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        line = caught.exception.issues[0]
        self.assertEqual((line.id, line.names), ('files.skipped', ('這台：ghost.json',)))
        self.assertEqual((self.storage.list_backups(), self.world.manifests), ([], {}))
        result = self.convert(backup, [APP], acknowledged={APP: [line.key(APP)]})
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertNotIn('ghost.json', self.volume(IDE))

    def test_a_volume_decides_a_link_like_this(self):
        class Entry:
            copied = 0

            def copy_later(self):
                Entry.copied += 1

        report = habackup.Report(names=haissues.Names)
        volume = cs.Volume(None, (0, 0), {'live.txt': cs.LiveItem('file', 0, 0, 0o644, 1)}, 'x', report)
        volume.files.add('a')
        volume.written['a'] = 'file'
        self.assertEqual(volume.hardlink('l1', 'a', 1, prefer='ha'), 'link')
        self.assertEqual(volume.hardlink('l2', 'zzz', 1, prefer='ha', entry=Entry()), 'copy')
        self.assertEqual(volume.hardlink('l3', 'zzz', 1, prefer='ha'), 'skip')
        self.assertEqual(report.skips['hardlink'].first, ['l3'])
        self.assertIsNone(volume.hardlink('live.txt', 'a', 1, prefer='live'), "this device's own entry stays: nothing is written")
        self.assertEqual(Entry.copied, 1, 'a link that is not written is not copied either')
        with self.assertRaises(BackupError):
            cs.Volume(None, (0, 0), {}, 'x').hardlink('l4', 'zzz', 1, prefer='ha')   # no report, no entry: as it was

    def test_which_targets_may_be_copied(self):
        yes = (('pi', 'sessions/a/b.jsonl'), ('pi', 'settings.json'), ('pi', 'shared/mcp.json'), ('pi', 'claude/history.jsonl'),
               ('pi', 'skills/x/SKILL.md'), ('pi', 'home/.npm/x'), ('pi', 'home/.cache/x'), ('pi', 'home/.local/share/pnpm/s/f'),
               ('user', 'snippets/a'), ('user', 'settings.json'), ('user', 'globalStorage/state.vscdb'),
               ('ext', 'redhat.vscode-yaml-1.24.0/package.json'))
        no = (('pi', 'auth.json'), ('pi', 'mcp-auth.json'), ('pi', 'claude/.credentials.json'), ('pi', 'codex/auth.json'),
              ('pi', 'claude/.claude.json'), ('pi', 'codex/config.toml'), ('pi', 'trust.json'), ('pi', 'bin/rg'),
              ('pi', 'npm-global/x'), ('pi', 'home/.ssh/id'), ('pi', 'home/.cachey/x'), ('pi', 'home/.bunker/x'),
              ('pi', 'claude/cache/x.bin'), ('pi', 'mystery/x'), ('pi', 'connectors/x'),
              ('user', 'globalStorage/woowtech.omnigent/state.json'), ('user', 'workspaceStorage/a'), ('user', 'machineid'),
              ('user', 'sync/x'), ('ext', 'woowtech.paseo-0.1.6/package.json'), ('ext', '.woow-connector-seed.json'),
              ('ext', 'extensions.json'))
        for key, target in yes:
            self.assertTrue(cs._copy_ok(key, target), (key, target))
        for key, target in no:
            self.assertFalse(cs._copy_ok(key, target), (key, target))


class ParityLiveTests(ParityCase):
    """CS-12 (the sandboxed reader of the databases), CS-14 and CS-16 (reads of this device's own data), CS-17."""

    def relays(self, volume):
        return [call for call in self.reads() if call[-1] == volume]

    def flaky(self, failures, make_error):
        calls, real = [], hasqlite.run

        def run(*args, **kwargs):
            calls.append(1)
            if len(calls) <= failures:
                raise make_error()
            return real(*args, **kwargs)

        return run, calls

    def timeout(self):
        return BackupError('job-failed', '讀取 HA 備份中的VS Code 的資料庫逾時。')

    def test_cs12_a_reader_that_fails_once_is_started_again_and_the_databases_are_checked(self):
        run, calls = self.flaky(1, self.timeout)
        with mock.patch.object(hasqlite, 'run', run):
            row = self.row(self.upload_cs())
        self.assertEqual((row['importable'], row['ok'], len(calls)), (True, True, 2))
        self.assertNotIn('codeserver.databases-skipped', [item['id'] for item in row['issues']])

    def reader_that_never_finishes(self, make_error=None):
        run, calls = self.flaky(99, make_error or self.timeout)
        patcher = mock.patch.object(hasqlite, 'run', run)
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls


    def two_databases(self):
        return self.upload_cs(extra=[{'name': 'data/vscode/User/globalStorage/second.db', 'data': sqlite_bytes()}])

    def test_cs12_a_reader_that_does_not_finish_not_confirmed_stops_only_this_app(self):
        for label, make_error in (('time', self.timeout), ('died', lambda: BackupError('corrupt-archive', 'HA 備份中的VS Code 的資料庫無法讀取。'))):
            with self.subTest(label=label), mock.patch.object(hasqlite, 'run', self.flaky(99, make_error)[0]):
                self.assert_not_confirmed(self.upload_cs(), 'codeserver.databases-unchecked', ['globalStorage/agent-host.db'],
                                          '無法確認 HA 的 VS Code 資料中有 1 個資料庫是否完好')

    def test_cs12_confirmed_goes_on_without_those_databases_and_the_rest_moves(self):
        calls = self.reader_that_never_finishes()
        row = self.row(self.upload_cs())
        self.assertEqual((row['importable'], levels(row, 'stop'), len(calls)), (True, [], 2), 'two tries, then it counts as unchecked')
        result = self.assert_confirmed(self.upload_cs(), 'codeserver.databases-unchecked', ['globalStorage/agent-host.db'])
        self.assertNotIn('globalStorage/agent-host.db', self.volume(IDE))
        self.assertIn('sessions/--share-projects--/2026-11-20_a.jsonl', self.volume(PI), 'everything else moved')
        self.assertEqual(result['results'][0]['status'], 'converted')

    def test_cs12_one_more_name_asks_again(self):
        self.reader_that_never_finishes()
        self.assert_one_more_name_asks_again(self.upload_cs(), self.two_databases(), 'codeserver.databases-unchecked')

    def test_cs12_a_damaged_database_is_still_only_a_reminder(self):
        bad = [{'name': 'data/vscode/User/globalStorage/broken.vscdb', 'data': b'SQLite format 3\x00' + b'\xff' * 4000}]
        row = self.row(self.upload_cs(extra=bad))
        self.assertEqual((row['ok'], issue_of(row, 'codeserver.databases-skipped')['level']), (True, 'notice'))
        self.assertNotIn('codeserver.databases-unchecked', [item['id'] for item in row['issues']])

    def test_cs12_what_ends_the_whole_job_is_not_swallowed(self):
        run, _calls = self.flaky(99, lambda: haissues.job_wide(BackupError('insufficient-space', '磁碟空間不足。')))
        with mock.patch.object(hasqlite, 'run', run), self.assertRaises(BackupError) as caught:
            self.row(self.upload_cs())
        self.assertEqual(caught.exception.code, 'insufficient-space')

    def test_cs14_a_torn_export_is_read_again_and_nothing_is_paused(self):
        self.world.export_plan[IDE] = ['torn']
        result = self.convert(self.upload_cs(), [APP])
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertEqual((len(self.relays(IDE)), len(self.relays(PI)), self.world.owner.systemd), (2, 1, []))

    def test_cs14_a_volume_that_fails_every_time_is_read_once_with_the_container_paused(self):
        self.world.needs_stopped = {IDE: {UNIT}}
        result = self.convert(self.upload_cs(), [APP])
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertEqual((len(self.relays(PI)), len(self.relays(IDE)), len(self.relays(EXT))), (1, cs.od.READ_TRIES + 1, 1),
                         'what was read stays read; the one that failed and the next one are read with the container paused')
        self.assertEqual(self.world.owner.systemd, [('stop', UNIT), ('start', UNIT)])
        line = next(i for i in result['results'][0]['issues'] if i['id'] == 'codeserver.service-paused')
        self.assertEqual((line['level'], line['items']), ('auto', ['code-server']))
        self.assertEqual(self.volume(IDE)['keybindings.json'][1], b'[{"key": "ctrl+h"}]')
        self.assertEqual(self.volume(EXT)['extensions.json'][1].count(b'redhat.vscode-yaml') >= 1, True)

    def test_cs14_what_still_fails_when_paused_stops_only_this_app_and_the_container_runs_again(self):
        self.world.export_plan[EXT] = ['fail'] * 10
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_cs(), [APP])
        self.assertEqual((caught.exception.code, list(caught.exception.issues)), ('job-failed', []))
        self.assertEqual(self.world.owner.systemd, [('stop', UNIT), ('start', UNIT)])
        self.assertEqual(self.world.owner.stopped(), set())
        self.assertEqual((self.storage.list_backups(), self.world.manifests), ([], {}))

    def test_cs14_a_failure_that_does_not_pass_is_neither_tried_again_nor_paused(self):
        self.world.export_plan[EXT] = ['limit']
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_cs(), [APP])
        self.assertEqual(caught.exception.code, 'limit-exceeded')
        self.assertEqual((len(self.relays(EXT)), self.world.owner.systemd), (1, []))

    def test_a_conversion_that_stops_early_leaves_no_file_open(self):
        class Tracking(cs.ha_odoo.FileTar):
            made = []

            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                Tracking.made.append(self)

        backup = self.upload_cs(extra=[pi_link('sessions/--share-projects--/key', 'claude/.claude.json')])   # asks once more
        with mock.patch.object(cs.ha_odoo, 'FileTar', Tracking), self.assertRaises(BackupError) as caught:
            self.convert(backup, [APP])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertTrue(len(Tracking.made) >= 3 and all(item.handle.closed for item in Tracking.made))

    def test_cs14_nothing_is_paused_when_the_container_does_not_run(self):
        self.world.export_plan[PI] = ['fail'] * 10
        self.world.not_running = {'code-server'}
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_cs(), [APP])
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertEqual((len(self.relays(PI)), self.world.owner.systemd), (cs.od.READ_TRIES, []))

    def test_cs14_a_container_that_does_not_start_at_once_is_started_by_the_clean_up(self):
        self.world.needs_stopped = {IDE: {UNIT}}
        self.world.start_fails = 1
        result = self.convert(self.upload_cs(), [APP])
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertEqual([item for item in self.world.owner.systemd if item[0] == 'start'], [('start', UNIT)] * 2)
        self.assertEqual(self.world.owner.stopped(), set())

    def test_cs14_the_check_reads_nothing_of_this_device_so_nothing_is_paused(self):
        self.world.needs_stopped = {IDE: {UNIT}}
        self.world.dir_needs_stopped = {'Desktop': {UNIT}}
        self.assertTrue(self.row(self.upload_cs(share=share_tar()))['importable'])
        self.assertEqual((self.reads(), self.reads('dir_pack'), self.world.owner.systemd), ([], [], []))

    def test_cs16_a_torn_pack_of_the_workspace_is_read_again(self):
        self.world.dir_plan['Desktop'] = ['torn']
        result = self.convert(self.upload_cs(share=share_tar()), [APP])
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertEqual((len(self.reads('dir_pack')), self.world.owner.systemd), (2, []))
        self.assertIn('./notes.txt', self.desktop())

    def test_cs16_a_pack_that_fails_every_time_is_read_once_with_the_container_paused(self):
        self.world.dir_needs_stopped = {'Desktop': {UNIT}}
        result = self.convert(self.upload_cs(share=share_tar()), [APP])
        self.assertEqual(result['results'][0]['status'], 'converted')
        self.assertEqual(len(self.reads('dir_pack')), cs.od.READ_TRIES + 1)
        self.assertEqual(self.world.owner.systemd, [('stop', UNIT), ('start', UNIT)], 'once: the volumes were read before')
        desk = self.desktop()
        self.assertEqual(desk['./notes.txt'][1], b'target desktop file')
        self.assertTrue([n for n in desk if n.endswith('/t1/讀我　說明.md')])
        self.assertIn('codeserver.service-paused', [i['id'] for i in result['results'][0]['issues']])

    def test_cs16_a_pack_that_cannot_be_read_stops_only_this_app_and_replaces_nothing(self):
        self.world.dir_plan['Desktop'] = ['fail'] * 10
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_cs(share=share_tar()), [APP])
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertEqual(self.world.owner.stopped(), set())
        self.assertEqual((self.storage.list_backups(), self.world.manifests, self.world.dir_data), ([], {}, {}))

    def test_cs17_an_unreadable_staging_of_the_extensions_leaves_out_only_the_extensions(self):
        with mock.patch.object(cs, '_staging_readable', return_value=False):
            result = self.convert(self.upload_cs(), [APP])
        self.assertEqual(result['results'][0]['status'], 'converted')
        ext = self.volume(EXT)
        self.assertEqual(json.loads(ext['extensions.json'][1]), LIVE_EXTS, "this device's list is not touched")
        self.assertFalse([n for n in ext if n.startswith('streetsidesoftware')])
        self.assertEqual(self.volume(IDE)['keybindings.json'][1], b'[{"key": "ctrl+h"}]', 'everything else moves')
        self.assertIn('sessions/--share-projects--/2026-11-20_a.jsonl', self.volume(PI))
        reminders = result['ha_import']['reminders_by_app'][APP]
        self.assertTrue(any('延伸模組' in line and '重新安裝' in line for line in reminders))

    def test_cs17_the_staging_is_read_to_its_end_before_anything_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = fk.tar_of([{'name': '.', 'type': 'dir'}, {'name': 'a/b', 'data': b'x' * 3000}])
            files = {'good': good, 'torn': good[:len(good) // 2 + 5], 'garbage': b'not a tar' * 100}
            for name, data in files.items():
                Path(tmp, name).write_bytes(data)
            self.assertEqual({name: cs._staging_readable(Path(tmp) / name) for name in (*files, 'missing')},
                             {'good': True, 'torn': False, 'garbage': False, 'missing': False})


@unittest.skipUnless(os.environ.get('WOOWBK_HA_B2_FIXTURES') and os.environ.get('WOOWBK_HA_KEY'),
                     'set WOOWBK_HA_B2_FIXTURES (the folder with x86/) and WOOWBK_HA_KEY to read the real code-server backup')
class RealCodeServerBackupTests(unittest.TestCase):
    """The real x86 code-server add-on (0.1.14, encrypted, without share, made 2026-11-23) through the walk and the issue
    collection of this module: no device, no container; what is checked is what the file says. Nothing is printed."""

    def test_the_real_backup_is_walked_and_says_what_a_check_would_say(self):
        path = Path(os.environ['WOOWBK_HA_B2_FIXTURES']) / 'x86' / 'woow-b2-codeserver-x86-enc' / 'woow-b2-codeserver-x86-enc-20261123.tar'
        if not path.exists():
            self.skipTest('the real code-server backup is not in WOOWBK_HA_B2_FIXTURES')
        keys = hasecuretar.Keys(os.environ['WOOWBK_HA_KEY'])
        before = dict(jobs._MASK_COUNTS)
        stub = mock.Mock(checkpoint=lambda: None, abort=lambda: None, log=lambda _text: None)
        with habackup.open_backup(path) as backup, tempfile.TemporaryDirectory() as tmp:
            member = next(m for m in backup.layout.members if m.role == 'addon' and m.slug.split('_', 1)[-1] == 'woow_ha_code_server')
            report = habackup.Report(names=haissues.Names)
            outs = {key: cs.Volume(None, (0, 0), {}, key, report) for key in ('pi', 'ide', 'ext')}
            with backup.open_member(member.name, keys) as stream:
                src = cs.scan_member(stream, report, Path(tmp), outs, machine=0x3E)
            problems = cs.check_dbs(stub, src, Path(tmp)) if src.dbs else {}
            sink = haissues.Sink('woow-code-server')
            target = mock.Mock(workspace='Desktop', conflict=[])
            cs.collect(sink, src, cs.Workspace(), target, problems)
            cs.skip_line(sink, report)
        for value, count in list(jobs._MASK_COUNTS.items()):
            for _ in range(count - before.get(value, 0)):
                self.addCleanup(jobs.unmask_secret, value)
        self.assertTrue(report.complete)
        self.assertEqual(src.addon.version, '0.1.14')
        self.assertTrue({'pi', 'user', 'ext'} <= src.trees)
        self.assertEqual([item.id for item in sink.found if item.level == 'stop'], [], 'the real backup is importable')
        self.assertEqual([item.id for item in sink.found if item.level == 'confirm'], [], 'and asks for nothing')
        self.assertEqual(report.skip_count(*cs.od.SKIPS), 0)
        self.assertEqual(src.large, [])
        self.assertNotIn('pi:logins', src.left, 'the login files are never handed out')


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
        merged_settings, _dropped, extra = cs.merge_settings({'acp.agents': {'pi': {}, 'claude': {}, 'mine': {}}}, None)
        self.assertEqual((extra, sorted(merged_settings['acp.agents'])), (['mine'], ['claude', 'mine', 'pi']))
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
