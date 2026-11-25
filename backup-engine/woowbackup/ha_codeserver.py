"""Home Assistant import, code-server part: the WOOWTECH add-on `woow_ha_code_server` -> this device's app
`woow-code-server` (CONTRACT section 9 "Batch 2: code-server"; facts phase3/facts/code-server.md). Owner: E2.

The add-on keeps everything below /data: VS Code's user folder `data/vscode/User` and its extensions
`data/vscode/extensions`, the agents' home `data/pi-agent` (Pi, and Claude Code and Codex below it), the upstream
add-on's `.ssh`, `git/.gitconfig`, `.zsh_history` and legacy `claude/`, the connector state `woow-connectors-primary/`
and HA's options `data/options.json` (never read). The workspace is `/share/projects` (the HA folder `share`, member
`share.tar.gz`, `projects/**`), present only when the backup included `share`. The target is the Podman package: the
container `code-server` (`keep-id:uid=1000`, so the owner's namespace root is the image's `coder`) with the volumes
`woow-code-server-pi-data` at /data/pi-agent, `woow-code-server-ide` at ~coder/.local/share/code-server/User and
`woow-code-server-extensions` at ~coder/.local/share/code-server/extensions, and, when this device's catalog lists it
(owner decision D1 b), the workspace folder bound at /workspace (the owner's `Desktop`). There is no database server;
the only SQLite files that move are VS Code's (`globalStorage`), checked by the sandboxed child (hasqlite).

Versions (D6, HAOS parity 2026-11-25: CS-01, CS-02, CS-03, CS-07): the add-on version maps to the four programs that write
the data (code-server, Pi, Claude Code, Codex; PINS, from the add-on's Dockerfile and build.yaml at each release tag) and
this device's image prints what it has (`--version` in a throwaway container of the live image, no network). The table and
the comparison only inform: an add-on version the table does not know, a program whose version cannot be read, a command that
does not run, and a program that differs are notices (what moves is settings, conversations, skills and extensions: text; a
newer format of HA that this device cannot read leaves those few conversations closed, never the login). A Codex the add-on
did not ship has nothing to compare.

What moves (owner decisions 2026-11-23 「決定2 A」 = the facts' recommended answers): VS Code's settings (merged: HA's
keys over this device's, without the HA-only ones that break here -- zsh as the default shell, the Prettier formatter,
the Home Assistant YAML languages -- and with this device's ACP agents, workspace-trust and extension-update keys),
keybindings, tasks, snippets, global storage, local history, profiles and prompts (HA's file wins where both have
one); HA's own extensions that this device lacks, built for any platform or this processor (extensions.json rebuilt
with this device's paths); the agents' history -- Pi sessions, Claude Code projects, file history and prompt history
(merged by time), Codex sessions and archived sessions -- and skills, Pi's session map, settings and models (this
device's file wins where both have one; a skill folder of the same name stays this device's), and the shared MCP
servers (D4 a: HA's servers added to this device's, the same name stays this device's; entries with headers,
environment values or HA-only hosts are listed for review); the workspace into `ha-projects-<date>/` of this device's
workspace folder (D1 b). What stays this device's: the agents' logins (D2 a: `auth.json`, `mcp-auth.json`, Claude's
`.credentials.json` and `.claude.json`, Codex's `auth.json` and `config.toml`), the connector identities (D3:
Omnigent host and Paseo pairing), installed programs (`bin/`, `npm-global/`), the agents' caches, locks and state
databases, the password secret, `woow-code-server.env`, units and the host's `.ssh`, `.gitconfig` and `.local/bin`.
Never read: `options.json` and the logins above (habackup.NEVER_READ), `.ssh`, `git/`, `.zsh_history`, the legacy
`claude/` and every connector folder (excluded from the walk).

Every moved entry is owned like the live volume's top folder (0:0 in the owner's namespace = `coder`), permission bits
without setuid/setgid; relative symlinks that stay inside their own area are link entries, others are skipped and
counted. A hard link to a file that does not move is written as a file with the content (the reader hands it out again:
CS-10, CS-13; never one to a login or an identity: those are left out and listed, default-deny); one this device keeps to
a file that HA's data replaces keeps its own content (CS-15). The rest of each volume is copied from a live export (read
while the app runs, like Odoo's web data; a read that fails is tried again and then done once with the app's own container
paused: CS-14, CS-16) with its live owners. What this device's catalog entry has beyond the three volumes and the
workspace folder is carried as it is (CS-04); what the reader or this importer had to leave out is one line of the ONE
confirmation (`files.skipped`), the workspace that does not move is another (`codeserver.workspace-not-moved`, CS-05).
"""
import contextlib
import io
import json
import os
import posixpath
import re
import tarfile
import time

from . import habackup, haissues, hacommon, hasqlite, hatarget, ha_n8n, ha_odoo, nested, tempctr, util
from .errors import BackupError
from . import ha_opendesign as od
from .ha_opendesign import links_as_files, read_live, reader_failed, skip_line
from .haissues import Issue

SLUG = 'woow_ha_code_server'
APP_ID = 'woow-code-server'
CONTAINER = 'code-server'           # ContainerName= of the package's code-server.container
PI_TARGET = '/data/pi-agent'
IDE_TARGET = '/home/coder/.local/share/code-server/User'
EXT_TARGET = '/home/coder/.local/share/code-server/extensions'
WORKSPACE_TARGET = '/workspace'
HA_EXT_DIR = '/data/vscode/extensions'
TREE_PI = 'data/pi-agent'
TREE_USER = 'data/vscode/User'
TREE_EXT = 'data/vscode/extensions'
SHARE_PROJECTS = 'projects'         # the add-on's default workspace /share/projects (option config_path)

# Add-on version -> the programs that write the data: code-server (base ghcr.io/hassio-addons/vscode 7.2.0 =
# code-server v4.139.1, upstream addon-vscode Dockerfile:23), Pi, Claude Code and Codex (Woow_ha_code_server_add_on
# Dockerfile ARG PI_CODING_AGENT_VERSION / CLAUDE_CODE_VERSION / CODEX_CLI_VERSION at each tag; build.yaml build_from).
# No Codex before 0.1.8. 0.1.15 changed no pin (its CHANGELOG: "the data layout [is] unchanged"). Extend per release.
_PINS_0_1_6 = {'code-server': '4.139.1', 'pi': '0.99.1', 'claude': '2.1.285', 'codex': None}
_PINS = {'code-server': '4.139.1', 'pi': '0.99.1', 'claude': '2.1.285', 'codex': '0.167.0'}
PINS = {'0.1.6': _PINS_0_1_6, '0.1.7': _PINS_0_1_6,
        **{f'0.1.{n}': _PINS for n in range(8, 16)}}
PROGRAMS = (('code-server', 'code-server'), ('pi', 'Pi'), ('claude', 'Claude Code'), ('codex', 'Codex'))
VERSION_SCRIPT = ('for c in code-server pi claude codex; do printf "%s=" "$c"; '
                  'if command -v "$c" >/dev/null 2>&1; then "$c" --version 2>/dev/null | head -n 1; else echo; fi; '
                  'done')
SEMVER_RE = re.compile(r'(?<![0-9.])v?([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})(?!\.?[0-9])')

# The agents' home (`data/pi-agent`, names below it). Trees and files that move; this device's entry wins where both
# have one (a skill folder as a whole). Their parent folders are written as folders only.
PI_TREES = ('sessions', 'skills', 'claude/projects', 'claude/file-history', 'codex/sessions', 'codex/archived_sessions')
PI_FILES = ('settings.json', 'models.json', 'claude/history.jsonl', 'codex/session_index.jsonl',
            'home/.pi/pi-acp/session-map.json')
PI_MERGED = ('shared/mcp.json', 'claude/history.jsonl')   # read and merged with this device's at the end
PI_WHOLE = ('skills',)                                    # a folder below these is kept or moved as a whole
# What the walk never hands out (with habackup.NEVER_READ for the login files): login keys, git identity, shell
# history, the legacy Claude folder with its credentials and every connector identity.
EXCLUDE = ('data/.ssh', 'data/git', 'data/.zsh_history', 'data/claude', 'data/woow-connectors-primary',
           'data/pi-agent/connectors', 'data/pi-agent/connectors-primary', 'data/pi-agent/omnigent',
           'data/vscode/logs', 'data/vscode/CachedProfilesData', 'data/vscode/Machine')
# Left in HA, by what they are (top-level names below data/pi-agent): the page lists them.
PI_LOGINS = frozenset({'auth.json', 'mcp-auth.json'})
PI_PROGRAMS = frozenset({'bin', 'npm-global'})
PI_LOGIN_FILES = frozenset({'claude/.credentials.json', 'codex/auth.json'})
PI_OWN = frozenset({'mcp.json', 'trust.json', '.woow-pi-store', 'models-store.json'})   # this device's own state
# Claude Code's account and settings file and Codex's configuration: this device's (woow-agent-sync rewrites their MCP
# servers from shared/mcp.json at every start).
PI_OWN_FILES = frozenset({'claude/.claude.json', 'codex/config.toml'})

# VS Code's user folder (`data/vscode/User`): moved (HA's wins where both have one), merged, left in HA.
USER_TREES = ('snippets', 'globalStorage', 'History', 'profiles', 'prompts')
USER_FILES = ('keybindings.json', 'tasks.json', 'mcp.json', 'chatLanguageModels.json')
USER_MERGED = 'settings.json'
USER_LEFT = frozenset({'workspaceStorage', 'caches', 'machineid', 'customBuiltinExtensionsCache.json',
                       'systemExtensionsCache.json', 'sync', 'logs'})
# The connector extensions' state is part of their identity (D3): this device's stays.
USER_OWN = ('globalStorage/woowtech.paseo', 'globalStorage/woowtech.omnigent')
CONNECTOR_PUBLISHER = 'woowtech.'   # the connector VSIX the add-on seeds itself (never HA's user extensions)
EXT_PLATFORMS = {0x3E: frozenset({'linux-x64'}), 0xB7: frozenset({'linux-arm64'})}
NEUTRAL_PLATFORMS = frozenset({None, '', 'universal', 'undefined', 'web'})

# HA-only settings that break here (upstream addon-vscode rootfs/root/.code-server/settings.json:2-101): no zsh in this
# device's image, no Prettier, no Home Assistant / ESPHome language extensions.
BROKEN_DEFAULTS = {'terminal.integrated.defaultProfile.linux': 'zsh', 'editor.defaultFormatter': 'esbenp.prettier-vscode'}
HA_LANGUAGES = frozenset({'home-assistant', 'esphome'})
# This device's keys win (Woow_podman_code_server_package rootfs/etc/skel/.local/share/code-server/User/
# settings.json:2-31): its ACP agents (HA's other agents are kept), workspace trust and extension updates.
PINNED_SETTINGS = ('security.workspace.trust.enabled', 'security.workspace.trust.startupPrompt',
                   'security.workspace.trust.banner', 'security.workspace.trust.emptyWindow', 'extensions.autoUpdate')
ACP_AGENTS = 'acp.agents'
STANDARD_AGENTS = frozenset({'pi', 'claude', 'codex'})   # both sides ship these three ACP agents

SQLITE_HEAD = b'SQLite format 3\x00'
SIDECARS = ('-wal', '-journal')
MAX_JSON = 16 * 1024 * 1024         # was 4 MiB (CS-11): a larger settings file is left out and listed, this device's stays
MAX_HISTORY = 64 * 1024 * 1024      # was 32 MiB
MAX_SCAN = 1024 * 1024
MAX_DBS_PER_RUN = 32
MAX_LIST = 1000
# Below the agents' `home/`: the package managers' caches. A project file that is a hard link into one of them gets the content;
# a hard link into any other place that does not move (a login, an identity, an account) never does.
CACHE_ROOTS = ('home/.bun', 'home/.npm', 'home/.cache', 'home/.pnpm-store', 'home/.yarn', 'home/.local/share/pnpm')
PAUSE_ID = 'codeserver.service-paused'

# Every issue id of this module, with its level (haissues; tests/backup/test_ha_issues.py keeps it exact).
ISSUES = {
    'codeserver.no-data': 'stop',                 # CS-08: nothing to move (no VS Code settings, no agent data)
    'codeserver.target-has-database': 'stop',     # CS-04: this device's catalog entry has a database (carrying it is not built)
    'codeserver.addon-unknown': 'notice',         # CS-01: the table does not know HA's add-on version
    'codeserver.target-versions-unknown': 'notice',  # CS-02: a program of this device's image says no version
    'codeserver.version-command-failed': 'notice',   # CS-07: the version command did not run in this device's image
    'codeserver.versions-differ': 'notice',       # CS-03: a program differs between HA and this device
    'codeserver.workspace-not-moved': 'confirm',  # CS-05: this device's folder settings do not name the workspace folder
    'codeserver.extras-carried': 'auto',          # CS-04: volumes and folders of this device beyond what is converted
    'codeserver.links-copied': 'auto',            # CS-10, CS-13: hard links to files that do not move got the content
    'codeserver.kept-links-copied': 'auto',       # CS-15: this device's kept links to replaced files got the content
    'codeserver.service-paused': 'auto',          # CS-14, CS-16: the app's container was paused for one read
    'codeserver.databases-skipped': 'notice',     # CS-12 (and damaged ones): VS Code databases that are not moved
    'codeserver.extensions-skipped': 'notice',    # CS-17, CS-11: HA's extensions are not moved (list too large, staging unreadable)
    'codeserver.files-kept': 'notice',            # CS-11: a settings file of HA is too large, this device's stays
    'codeserver.no-workspace-folder': 'notice',
    'codeserver.no-share': 'notice',
    'codeserver.no-projects': 'notice',
    'codeserver.unknown-entries': 'notice',
    'codeserver.foreign-programs': 'notice',
    'codeserver.symlinks-skipped': 'notice',
    'codeserver.ha-addresses': 'notice',
    'codeserver.mcp-review': 'notice',
    'codeserver.extensions-other-processor': 'notice',
}


def _rel(name, tree):
    return name[len(tree) + 1:] if name.startswith(tree + '/') else ('' if name == tree else None)


def _under(rel, prefix):
    return rel == prefix or rel.startswith(prefix + '/')


def _ancestors(rel):
    parts = rel.split('/')
    return ['/'.join(parts[:i]) for i in range(1, len(parts))]


def names(items, limit=8):
    return hacommon.names(sorted(items), limit)


# ====================================================================== versions

def parse_versions(text):
    """{program: x.y.z or None} of VERSION_SCRIPT's output (`name=<first line of its --version>`)."""
    found = {program: None for program, _label in PROGRAMS}
    for line in text.splitlines():
        key, sep, rest = line.partition('=')
        if sep and key in found and found[key] is None:
            match = SEMVER_RE.search(rest)
            found[key] = match.group(1) if match else None
    return found


ADDON_UNKNOWN = ('這台的版本對照表還不認得 HA 的 code-server 附加元件版本 {version}，不用版本判斷能不能匯入；'
                 '搬的是設定、對話記錄、技能與延伸模組（文字檔），匯入後請確認 code-server 能正常使用。')
TARGET_UNKNOWN = ('讀不到這台映像裡這些程式的版本（映像裡沒有它，或它沒有回應版本），這次不比對它們的版本；'
                  '匯入後請確認 code-server 與代理程式能正常使用。')
COMMAND_FAILED = ('無法在這台的映像裡讀出 code-server 與代理程式的版本（執行 --version 沒有成功），這次不比對版本；'
                  '匯入後請確認 code-server 與代理程式能正常使用。')
VERSIONS_DIFFER = ('HA 和這台的程式版本不一樣：搬的多半是設定與對話記錄，不會弄壞這台的登入；HA 較新時，'
                   '少數對話可能在這台打不開。')


def version_issues(addon_version, target, failed=False):
    """The notices about versions (CS-01, CS-02, CS-03, CS-07): none of them stops the import. `target`: parse_versions of
    this device's image; `failed`: the command that prints them did not run."""
    pins = PINS.get(addon_version)
    found = []
    if pins is None:
        found.append(Issue('codeserver.addon-unknown', 'notice',
                           ADDON_UNKNOWN.format(version=haissues.clean(addon_version, 40) or '（讀不到）')))
        return found if not failed else found + [Issue('codeserver.version-command-failed', 'notice', COMMAND_FAILED)]
    if failed:
        found.append(Issue('codeserver.version-command-failed', 'notice', COMMAND_FAILED))
        return found
    unreadable, differ = [], []
    for program, label in PROGRAMS:
        mine = pins.get(program)
        if mine is None:
            continue  # the add-on did not ship it: nothing of it to compare
        theirs = target.get(program)
        if theirs is None:
            unreadable.append(label)
        elif theirs != mine:
            differ.append(f'{label}（HA {mine}，這台 {theirs}）')
    if unreadable:
        found.append(Issue('codeserver.target-versions-unknown', 'notice', TARGET_UNKNOWN, unreadable))
    if differ:
        found.append(Issue('codeserver.versions-differ', 'notice', VERSIONS_DIFFER, differ))
    return found


# ====================================================================== JSON settings

def jsonc_loads(data, max_bytes=MAX_JSON):
    """(document, had_comments) of a VS Code settings file (JSON with // and /* */ comments and trailing commas), or
    (None, False) when it is not one. Strings are kept as they are; the result is parsed strictly."""
    try:
        text = bytes(data).decode('utf-8')
    except UnicodeDecodeError:
        return None, False
    if len(data) > max_bytes:
        return None, False
    out, i, n, in_str, comments = [], 0, len(text), False, False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == '\\' and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif text.startswith('//', i):
            end = text.find('\n', i)
            i = n if end < 0 else end
            comments = True
            continue
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            if end < 0:
                return None, False
            i = end + 2
            comments = True
            continue
        elif c in '}]':
            k = len(out) - 1
            while k >= 0 and out[k] in ' \t\r\n':
                k -= 1
            if k >= 0 and out[k] == ',':
                del out[k]
        out.append(c)
        i += 1
    doc = hacommon.strict_json(''.join(out).encode('utf-8'), max_bytes)
    return (doc, comments) if isinstance(doc, dict) else (None, False)


def clean_settings(doc):
    """(HA's settings without the HA-only values that break here, the keys dropped)."""
    clean, dropped = {}, []
    for key, value in doc.items():
        if key in BROKEN_DEFAULTS and value == BROKEN_DEFAULTS[key]:
            dropped.append(key)
            continue
        if key.startswith('[') and key.endswith(']') and key[1:-1] in HA_LANGUAGES:
            dropped.append(key)
            continue
        if key == 'terminal.integrated.profiles.linux' and isinstance(value, dict):
            kept = {name: item for name, item in value.items()
                    if not (isinstance(item, dict) and str(item.get('path', '')).endswith('/zsh'))}
            if len(kept) != len(value):
                dropped.append(key)
            if kept:
                clean[key] = kept
            continue
        if key == 'files.associations' and isinstance(value, dict):
            kept = {pattern: lang for pattern, lang in value.items() if lang not in HA_LANGUAGES}
            if len(kept) != len(value):
                dropped.append(key)
            if kept:
                clean[key] = kept
            continue
        if key.startswith('[') and isinstance(value, dict) \
                and value.get('editor.defaultFormatter') == BROKEN_DEFAULTS['editor.defaultFormatter']:
            value = {k: v for k, v in value.items() if k != 'editor.defaultFormatter'}
            dropped.append(f'{key}.editor.defaultFormatter')
        clean[key] = value
    return clean, dropped


def merge_settings(ha_doc, live_doc):
    """(merged settings, keys dropped, HA's extra ACP agents): this device's settings, HA's cleaned keys over them,
    this device's PINNED_SETTINGS and ACP agents kept (HA's other agents added)."""
    live_doc = live_doc if isinstance(live_doc, dict) else {}
    clean, dropped = clean_settings(ha_doc)
    merged = dict(live_doc)
    merged.update(clean)
    for key in PINNED_SETTINGS:
        if key in live_doc:
            merged[key] = live_doc[key]
    extra = []
    ha_agents, live_agents = ha_doc.get(ACP_AGENTS), live_doc.get(ACP_AGENTS)
    if isinstance(live_agents, dict):
        agents = dict(live_agents)
        if isinstance(ha_agents, dict):
            for name, item in ha_agents.items():
                if name not in agents:
                    agents[name] = item
                    extra.append(name)
        merged[ACP_AGENTS] = agents
    elif isinstance(ha_agents, dict):
        extra = sorted(name for name in ha_agents if name not in STANDARD_AGENTS)
    return merged, dropped, extra


def mcp_servers(doc):
    servers = doc.get('mcpServers') if isinstance(doc, dict) else None
    return servers if isinstance(servers, dict) else {}


def merge_mcp(ha_doc, live_doc):
    """(merged shared MCP document, HA's servers added, HA's servers left out because this device has the name)."""
    live_doc = live_doc if isinstance(live_doc, dict) else {}
    merged = dict(live_doc) if live_doc else {key: value for key, value in ha_doc.items() if key != 'mcpServers'}
    servers = dict(mcp_servers(live_doc))
    added, same = [], []
    for name, item in mcp_servers(ha_doc).items():
        if name in servers:
            same.append(name)
            continue
        servers[name] = item
        added.append(name)
    merged['mcpServers'] = servers
    return merged, added, same


def mcp_review(doc):
    """(names of HA's MCP servers that carry headers or environment values -- they may hold tokens --, HA-only hosts
    their URLs name). Names and host names only; never a value."""
    review, hosts = [], set()
    for name, item in mcp_servers(doc).items():
        if not isinstance(item, dict):
            continue
        if item.get('headers') or item.get('env'):
            review.append(str(name)[:60])
        for key in ('url', 'serverUrl', 'httpUrl'):
            if isinstance(item.get(key), str):
                hosts.update(hacommon.ha_hosts(item[key]))
    return sorted(review), sorted(hosts)


def merge_history(live, ha):
    """Claude Code's prompt history (JSON lines) of both sides by time (`timestamp`), each line once; None when a side
    is not JSON lines or the result would be larger than MAX_HISTORY (this device's file then stays)."""
    if len(live) + len(ha) > MAX_HISTORY:
        return None
    rows, seen = [], set()
    for order, data in enumerate((live, ha)):
        for index, line in enumerate(data.splitlines()):
            if not line.strip():
                continue
            doc = hacommon.strict_json(line, MAX_HISTORY)
            if not isinstance(doc, dict):
                return None
            if line in seen:
                continue
            seen.add(line)
            stamp = doc.get('timestamp')
            rows.append((stamp if isinstance(stamp, (int, float)) and not isinstance(stamp, bool) else 0,
                         order, index, line))
    rows.sort()
    return b''.join(line + b'\n' for _s, _o, _i, line in rows)


def json_bytes(doc):
    return (json.dumps(doc, ensure_ascii=False, indent=4) + '\n').encode('utf-8')


# ====================================================================== extensions

def extension_entries(doc):
    """{relativeLocation: entry} of an extensions.json list (entries without a usable location are skipped)."""
    found = {}
    if not isinstance(doc, list):
        return found
    for item in doc[:MAX_LIST]:
        if not isinstance(item, dict):
            continue
        rel = item.get('relativeLocation')
        ident = item.get('identifier') if isinstance(item.get('identifier'), dict) else {}
        if isinstance(rel, str) and rel and '/' not in rel and rel not in ('.', '..') and isinstance(ident.get('id'), str):
            found[rel] = item
    return found


def extension_id(item):
    return str((item.get('identifier') or {}).get('id', '')).lower()


def extension_platform(item):
    meta = item.get('metadata') if isinstance(item.get('metadata'), dict) else {}
    value = meta.get('targetPlatform')
    return value if isinstance(value, str) or value is None else ''


def relocate_extension(item, rel):
    """A copy of an extensions.json entry pointing at this device's extensions folder."""
    item = json.loads(json.dumps(item))
    location = item.get('location') if isinstance(item.get('location'), dict) else {}
    path = f'{EXT_TARGET}/{rel}'
    location = dict(location, path=path, scheme=location.get('scheme', 'file'))
    for key in ('fsPath', 'external', '_fsPath'):
        if key in location:
            location[key] = path if key != 'external' else f'file://{path}'
    item['location'] = location
    item['relativeLocation'] = rel
    return item


def choose_extensions(ha_entries, live_entries, foreign, machine):
    """(rels to move, {rel: reason} not moved): HA's user extensions this device lacks (by id), built for any platform
    or this processor, with no program for another processor."""
    have = {extension_id(item) for item in live_entries.values()}
    platforms = EXT_PLATFORMS.get(machine, frozenset())
    move, skipped = [], {}
    for rel, item in sorted(ha_entries.items()):
        ident = extension_id(item)
        if ident.startswith(CONNECTOR_PUBLISHER):
            continue  # the add-on's own connector VSIX: this device seeds its own
        if ident in have:
            skipped[rel] = 'same'
        elif extension_platform(item) not in NEUTRAL_PLATFORMS and extension_platform(item) not in platforms:
            skipped[rel] = 'platform'
        elif rel in foreign:
            skipped[rel] = 'foreign'
        else:
            move.append(rel)
    return move, skipped


# ====================================================================== writing a volume from both sides

class LiveItem:
    __slots__ = ('kind', 'uid', 'gid', 'mode', 'mtime')

    def __init__(self, kind, uid, gid, mode, mtime):
        self.kind, self.uid, self.gid, self.mode, self.mtime = kind, uid, gid, mode, mtime


def live_index(path, what, *, read=()):
    """({name: LiveItem} of a live volume export (the root '.' included), {name: bytes} of the regular files named in
    `read` (at most MAX_JSON / MAX_HISTORY each))."""
    index, contents = {}, {}
    try:
        with ha_odoo._live_tar(path, what) as tar:
            for member in tar:
                name = ha_odoo._norm(member.name)
                if name is None:
                    raise BackupError('job-failed', f'{what}的匯出內容格式不正確。')
                kind = ('dir' if member.isdir() else 'file' if member.isfile() else 'symlink' if member.issym()
                        else 'hardlink' if member.islnk() else 'other')
                index[name] = LiveItem(kind, member.uid, member.gid, member.mode & 0o7777, member.mtime)
                if name in read and member.isfile() and member.size <= MAX_HISTORY:
                    contents[name] = tar.extractfile(member).read()
                tar.members.clear()
    except tarfile.TarError:
        raise BackupError('job-failed', f'{what}的匯出內容無法讀取。') from None
    return index, contents


class Volume:
    """One volume tar (`tar` a FileTar, or None to count only): HA's entries first, then the live export's entries
    nothing of HA's replaced. `live` = live_index of the volume ({} when the target is not read: the check job). HA's
    entries are owned by `owner` (the live top folder's uid/gid); a folder both sides have keeps the live owner and
    mode. `prefer`: 'ha' (HA's entry replaces the live one) or 'live' (the live one stays, HA's is skipped)."""

    def __init__(self, tar, owner, live, what, report=None):
        self.tar = tar
        self.uid, self.gid = owner
        self.live = live
        self.what = what
        self.report = report      # the walk's habackup.Report: what cannot be written is listed there (CS-10)
        self.written = {}         # name -> kind, of HA's entries written
        self.files = set()        # names of regular files written (hard link targets)
        self.skipped = set()      # HA folders whose subtree is skipped (the live one stays)
        self.kept = []            # names where this device's entry stayed instead of HA's
        self.counts = {'files': 0, 'dirs': 0, 'symlinks': 0, 'hardlinks': 0, 'bytes': 0}
        root = live.get('.')
        if tar is not None:
            uid, gid, mode = (root.uid, root.gid, root.mode) if root else (self.uid, self.gid, 0o755)
            tar.add_member(hacommon.info('.', 'dir', mode=mode & 0o1777, uid=uid, gid=gid,
                                         mtime=root.mtime if root else time.time()))

    def _blocked(self, rel):
        return any(a in self.skipped for a in _ancestors(rel)) or any(
            self.written.get(a, 'dir') != 'dir' for a in _ancestors(rel))

    def blocked(self, rel):
        """True when HA's entry `rel` lies below a folder that stays this device's (or below a non-folder)."""
        return rel in self.skipped or self._blocked(rel)

    def ensure_dirs(self, rel, mode=0o755, mtime=None):
        """Write the missing parent folders of `rel` (the live owner and mode where this device has the folder)."""
        if self.blocked(rel):
            return
        for parent in _ancestors(rel):
            if parent in self.written:
                continue
            self.dir(parent, mode, mtime if mtime is not None else time.time(), prefer='live')

    def dir(self, rel, mode, mtime, *, prefer):
        if self.blocked(rel) or rel in self.written:
            return False
        live = self.live.get(rel)
        if live is not None and live.kind != 'dir':
            if prefer == 'live':
                self.skipped.add(rel)
                self.kept.append(rel)
                return False
        if live is not None and live.kind == 'dir':
            uid, gid, mode, mtime = live.uid, live.gid, live.mode, live.mtime
        else:
            uid, gid = self.uid, self.gid
        self._add(hacommon.info(rel, 'dir', mode=mode & 0o1777, uid=uid, gid=gid, mtime=mtime))
        self.written[rel] = 'dir'
        self.counts['dirs'] += 1
        return True

    def _take(self, rel, prefer):
        """True when HA's non-folder entry `rel` is written (False: skipped, this device's entry stays)."""
        if self.blocked(rel) or rel in self.written:
            return False
        if rel in self.live and prefer == 'live':
            self.kept.append(rel)
            return False
        return True

    def file(self, rel, entry, mode, *, prefer):
        if not self._take(rel, prefer):
            return False
        self._add(hacommon.info(rel, 'file', mode=mode & 0o777, uid=self.uid, gid=self.gid, mtime=entry.mtime,
                                size=entry.size), hacommon._Exact(entry))
        self._wrote(rel, 'file', entry.size)
        return True

    def data(self, rel, data, mode, mtime, *, prefer):
        if not self._take(rel, prefer):
            return False
        self._add(hacommon.info(rel, 'file', mode=mode & 0o777, uid=self.uid, gid=self.gid, mtime=mtime,
                                size=len(data)), io.BytesIO(data))
        self._wrote(rel, 'file', len(data))
        return True

    def symlink(self, rel, target, mtime, *, prefer):
        if not self._take(rel, prefer):
            return False
        self._add(hacommon.info(rel, 'symlink', mode=0o777, uid=self.uid, gid=self.gid, mtime=mtime, linkname=target))
        self.written[rel] = 'symlink'
        self.counts['symlinks'] += 1
        return True

    def hardlink(self, rel, target, mtime, *, prefer, entry=None):
        """A hard link of HA's tree. Returns None when this device's own entry stays (nothing is written), 'link' (written as a
        link to a file this volume holds), 'copy' (the file is not here: the reader hands the same name out again as a file with
        the content, `entry.copy_later()`: CS-10) or 'skip' (left out and listed in the report). Pass `entry` only for a link
        whose file may be copied (`_copy_ok`); without a report and an entry the import stops, as it did."""
        if not self._take(rel, prefer):
            return None
        if target in self.files:
            self._add(hacommon.info(rel, 'hardlink', mode=0o644, uid=self.uid, gid=self.gid, mtime=mtime, linkname=target))
            self.written[rel] = 'hardlink'
            self.counts['hardlinks'] += 1
            return 'link'
        copy_later = getattr(entry, 'copy_later', None)
        if copy_later is not None:
            copy_later()
            return 'copy'
        if self.report is not None:
            self.report.skip('hardlink', rel)
            return 'skip'
        raise BackupError('incompatible', f'HA 備份中的 {rel[:200]} 是另一個沒有搬過來的檔案的硬連結，無法只搬一半；'
                                          '已停止。', member=rel[:200], target=target[:200])

    def stream(self, rel, size, mode, mtime, fileobj, *, prefer):
        """A regular file from another tar (`fileobj` reads exactly `size` bytes), owned like HA's entries."""
        if not self._take(rel, prefer):
            return False
        self._add(hacommon.info(rel, 'file', mode=mode & 0o777, uid=self.uid, gid=self.gid, mtime=mtime, size=size),
                  fileobj)
        self._wrote(rel, 'file', size)
        return True

    def _wrote(self, rel, kind, size):
        self.written[rel] = kind
        self.files.add(rel)
        self.counts['files'] += 1
        self.counts['bytes'] += size

    def _add(self, info, fileobj=None):
        if self.tar is not None:
            self.tar.add_member(info, fileobj)

    def _shadowed(self, name):
        if name in self.written:
            return True
        return any(self.written.get(a, 'dir') != 'dir' for a in _ancestors(name))

    def finish(self, live_path):
        """Copy the live export's entries HA did not replace (their owners and modes as they are). A kept hard link to a file
        that HA's data replaced (or that is not kept) gets its content (CS-15); returns how many did."""
        if self.tar is None or live_path is None:
            return 0
        copied, pending = set(), {}
        try:
            with ha_odoo._live_tar(live_path, self.what) as tar:
                for member in tar:
                    name = ha_odoo._norm(member.name)
                    if name is None:
                        raise BackupError('job-failed', f'{self.what}的匯出內容格式不正確。')
                    if name == '.' or self._shadowed(name):
                        tar.members.clear()
                        continue
                    if member.islnk():
                        target = ha_odoo._norm(member.linkname)
                        if target not in copied:
                            pending.setdefault(target, []).append((name, member))
                            tar.members.clear()
                            continue
                    self.tar.add_member(ha_odoo._copy_info(member, name),
                                        tar.extractfile(member) if member.isfile() else None)
                    if member.isfile():
                        copied.add(name)
                    tar.members.clear()
        except tarfile.TarError:
            raise BackupError('job-failed', f'{self.what}的匯出內容無法讀取。') from None
        return links_as_files(live_path, self.tar, pending, self.what, report=self.report, label='這台：') if pending else 0

    def close(self):
        if self.tar is not None:
            self.tar.close()


# ====================================================================== the add-on member

class Source:
    def __init__(self):
        self.addon = None
        self.trees = set()            # 'pi', 'user', 'ext' seen
        self.settings = None          # HA's settings.json bytes
        self.mcp = None               # HA's shared/mcp.json bytes
        self.history = None           # HA's claude/history.jsonl bytes
        self.extensions = None        # HA's extensions.json document
        self.ext_foreign = set()      # extension folders with a program for another processor
        self.ext_bytes = {}           # extension folder -> bytes
        self.dbs = {}                 # (area, rel) -> staged path of moved SQLite files and their sidecars
        self.left = {}                # what stays in HA: label -> entries
        self.unknown = {}             # unknown top-level names below data/pi-agent / data/vscode/User -> entries
        self.foreign = []             # programs for another processor in moved trees
        self.ha_urls = set()
        self.large = []               # HA files too large to read (CS-11): left out and listed, this device's own stays
        self.links_copied = 0         # hard links of HA that got the content of the file they name (CS-10)
        self.sessions = self.claude_projects = self.codex_sessions = 0
        self.skills = set()
        self.snippets = 0
        self.counts = {}


def pi_route(rel):
    """'move' | 'merged' | 'parent' | ('left', label) | ('unknown', top) for a name below data/pi-agent."""
    if not rel:
        return 'parent'
    if rel in PI_MERGED:
        return 'merged'
    if any(_under(rel, tree) for tree in PI_TREES) or rel in PI_FILES:
        return 'move'
    if any(tree.startswith(rel + '/') for tree in PI_TREES + PI_FILES + PI_MERGED):
        return 'parent'
    top = rel.split('/', 1)[0]
    if top in PI_LOGINS or rel in PI_LOGIN_FILES:
        return ('left', 'logins')
    if top in PI_PROGRAMS:
        return ('left', 'programs')
    if top in PI_OWN or rel in PI_OWN_FILES or '.before-' in rel.split('/')[-1]:
        return ('left', 'own')
    if top in ('claude', 'codex', 'home', 'shared'):
        return ('left', 'state')
    return ('unknown', top)


def user_route(rel):
    """'move' | 'merged' | 'parent' | 'left' | 'own' | ('unknown', top) for a name below data/vscode/User."""
    if not rel:
        return 'parent'
    if rel == USER_MERGED:
        return 'merged'
    if any(_under(rel, own) for own in USER_OWN):
        return 'own'
    top = rel.split('/', 1)[0]
    if top in USER_TREES or rel in USER_FILES:
        return 'move'
    if top in USER_LEFT:
        return 'left'
    return ('unknown', top)


def _stage(entry, path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        entry.copy_to(handle)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def _is_db(rel, head):
    return head[:16] == SQLITE_HEAD or rel.endswith(SIDECARS)


def _locate(name):
    """(`pi` | `user` | `ext`, name below that tree) of a name of the add-on member, (None, None) elsewhere."""
    for tree, key in ((TREE_PI, 'pi'), (TREE_USER, 'user'), (TREE_EXT, 'ext')):
        rel = _rel(name, tree)
        if rel:
            return key, rel
    return None, None


def _ext_left(rel):
    """True for what of the extension tree is not HA's own extension (the add-on's connector, dot files, top-level files)."""
    top = rel.split('/', 1)[0]
    return top.lower().startswith(CONNECTOR_PUBLISHER) or top.startswith('.') or '/' not in rel


def _copy_ok(key, target):
    """True when the content of `target` (a name below the tree `key`) may be written where a hard link to it is, although the
    file itself does not move (CS-10). Default-deny: a file that moves (its content is moved anyway) or lies in a package
    manager's cache; never the agents' logins, the accounts and own files of this device, the connectors' identity, a folder this
    importer does not know."""
    if key == 'ext':
        return not _ext_left(target)
    route = pi_route(target) if key == 'pi' else user_route(target)
    if route in ('move', 'merged', 'parent'):
        return True
    if key == 'pi' and isinstance(route, tuple) and route[0] == 'left':
        return any(target == root or target.startswith(root + '/') for root in CACHE_ROOTS)
    return False


def _hardlink(src, out, key, rel, entry, prefer):
    """A hard link of HA's tree: a link to a file this volume holds, else (`_copy_ok`) the same name handed out again as a
    file with the content, else left out and listed."""
    target_key, target = _locate(entry.linkname)
    ok = target_key is not None and _copy_ok(target_key, target)
    how = out.hardlink(rel, target if target_key == key else '', entry.mtime, prefer=prefer, entry=entry if ok else None)
    if how == 'copy':
        src.links_copied += 1


def scan_member(stream, report, staging, outs, *, machine=None, checkpoint=None):
    """One strict pass over the add-on member into `outs` {'pi', 'ide', 'ext'} (Volume objects; `ext` writes into a
    staging tar of HA's extension folders, chosen at the end). SQLite files of the moved trees and their sidecars are
    staged (written at the end when their check passes); the merged JSON files are kept in memory. Returns a Source."""
    select = habackup.Select(include=(TREE_PI, TREE_USER, TREE_EXT), exclude=EXCLUDE,
                             symlinks=(TREE_PI, TREE_USER, TREE_EXT), hardlinks=True)
    src = Source()
    staged = 0
    count = 0
    for entry in habackup.iter_entries(stream, select, report, checkpoint=checkpoint):
        count += 1
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        for tree, key in ((TREE_PI, 'pi'), (TREE_USER, 'user'), (TREE_EXT, 'ext')):
            rel = _rel(entry.name, tree)
            if rel is not None:
                break
        else:
            continue  # not below the three trees (the selection never hands one out)
        if rel == '':
            if entry.kind != 'dir':
                raise BackupError('incompatible', 'HA 的 code-server 資料夾不是一般目錄，無法安全匯入。', member=entry.name)
            src.trees.add(key)
            continue
        if key == 'ext':
            _ext_entry(src, rel, entry, outs['ext'], machine)
            continue
        route = pi_route(rel) if key == 'pi' else user_route(rel)
        out = outs['pi'] if key == 'pi' else outs['ide']
        prefer = 'live' if key == 'pi' else 'ha'
        if isinstance(route, tuple) or route in ('left', 'own'):
            kind, label = route if isinstance(route, tuple) else (route, rel.split('/', 1)[0])
            bucket = src.unknown if kind == 'unknown' else src.left
            label = f'{key}:{label}'
            if kind != 'unknown' or entry.kind != 'dir':
                bucket[label] = bucket.get(label, 0) + 1
            elif label not in bucket:
                bucket[label] = 0
            continue
        if out.blocked(rel):
            continue  # below a folder that stays this device's (a skill of the same name)
        if route == 'parent':
            if entry.kind != 'dir':
                raise BackupError('incompatible', f'HA 的 code-server 資料 {rel[:200]} 不是一般目錄，無法安全匯入。',
                                  member=rel[:200])
            out.dir(rel, entry.mode, entry.mtime, prefer='live')
            continue
        if route == 'merged':
            if entry.kind != 'file':
                continue
            data = entry.read_or_skip(MAX_HISTORY if rel == 'claude/history.jsonl' else MAX_JSON)
            if data is None:
                src.large.append(rel)   # CS-11: too large to read; listed (files.skipped), this device's own file stays
                continue
            src.ha_urls.update(f'{rel}：{host}' for host in hacommon.ha_hosts(data.decode('utf-8', 'replace')))
            if key == 'user':
                src.settings = data
            elif rel == 'shared/mcp.json':
                src.mcp = data
            else:
                src.history = data
            continue
        _count(src, key, rel, entry)
        if key == 'pi' and any(rel.startswith(whole + '/') and rel.count('/') == 1 for whole in PI_WHOLE):
            # a skill folder as a whole: this device's stays when it has one of the same name
            if entry.kind == 'dir' and rel in out.live:
                out.skipped.add(rel)
                out.kept.append(rel)
                continue
        if entry.kind == 'dir':
            out.ensure_dirs(rel)
            out.dir(rel, entry.mode, entry.mtime, prefer=prefer)
            continue
        out.ensure_dirs(rel)
        if entry.kind == 'symlink':
            out.symlink(rel, entry.linkname, entry.mtime, prefer=prefer)
            continue
        if entry.kind == 'hardlink':
            _hardlink(src, out, key, rel, entry, prefer)
            continue
        head = entry.peek(20)
        if machine is not None and len(src.foreign) < MAX_LIST and hacommon.foreign_elf(head, machine):
            src.foreign.append(f'{key}:{rel}')
        if rel.endswith('-shm'):
            continue  # SQLite's wal-index: rebuilt by SQLite, never moved
        if _is_db(rel, head):
            if prefer == 'live' and rel in out.live:
                out.kept.append(rel)
                continue
            staged += 1
            src.dbs[(key, rel)] = (_stage(entry, staging / f'db{staged}'), entry.mode, entry.mtime)
            continue
        if entry.size <= MAX_SCAN and rel.endswith(('.json', '.jsonc', '.md', '.toml', '.yaml', '.yml')):
            data = entry.read_all(MAX_SCAN)
            src.ha_urls.update(f'{rel}：{host}' for host in hacommon.ha_hosts(data.decode('utf-8', 'replace')))
            out.data(rel, data, entry.mode, entry.mtime, prefer=prefer)
            continue
        out.file(rel, entry, entry.mode, prefer=prefer)
    src.addon = report.addon
    src.counts = {'pi': dict(outs['pi'].counts), 'ide': dict(outs['ide'].counts),
                  'skipped_symlinks': report.skipped_symlinks}
    return src


def _count(src, key, rel, entry):
    if entry.kind != 'file':
        if key == 'pi' and rel.startswith('skills/') and rel.count('/') == 1 and not rel.startswith('skills/.'):
            src.skills.add(rel.split('/', 1)[1])
        return
    if key == 'pi':
        if rel.startswith('sessions/') and rel.endswith('.jsonl'):
            src.sessions += 1
        elif rel.startswith('claude/projects/') and rel.endswith('.jsonl'):
            src.claude_projects += 1
        elif rel.startswith(('codex/sessions/', 'codex/archived_sessions/')) and rel.endswith('.jsonl'):
            src.codex_sessions += 1
    elif rel.startswith('snippets/'):
        src.snippets += 1


def _ext_entry(src, rel, entry, out, machine):
    """An entry below data/vscode/extensions: extensions.json is read, extension folders are staged (all of them; the
    choice needs extensions.json, which may come later), the rest stays in HA."""
    top = rel.split('/', 1)[0]
    if rel == 'extensions.json':
        if entry.kind == 'file':
            data = entry.read_or_skip(MAX_JSON)
            if data is None:
                src.large.append(rel)   # CS-11: without the list no extension of HA can be chosen
            else:
                src.extensions = hacommon.strict_json(data, MAX_JSON)
        return
    if top.lower().startswith(CONNECTOR_PUBLISHER) or top.startswith('.') or (entry.kind != 'dir' and '/' not in rel):
        src.left['ext:own'] = src.left.get('ext:own', 0) + 1
        return
    src.ext_bytes[top] = src.ext_bytes.get(top, 0) + (entry.size if entry.kind == 'file' else 0)
    if entry.kind == 'dir':
        out.dir(rel, entry.mode, entry.mtime, prefer='ha')
    elif entry.kind == 'symlink':
        out.symlink(rel, entry.linkname, entry.mtime, prefer='ha')
    elif entry.kind == 'hardlink':
        _hardlink(src, out, 'ext', rel, entry, 'ha')
    else:
        if machine is not None and hacommon.foreign_elf(entry.peek(20), machine):
            src.ext_foreign.add(top)
        out.file(rel, entry, entry.mode, prefer='ha')


# ====================================================================== the workspace (HA's share folder)

class Workspace:
    def __init__(self):
        self.present = False          # the backup has a share folder
        self.projects = False         # ... with a projects/ folder
        self.files = self.dirs = self.bytes = 0
        self.foreign = []
        self.skipped_symlinks = 0
        self.links_copied = 0


class DirOut:
    """A host directory tar in the folder pack's naming (`./`, `./<name>`): HA's projects below `folder`, then the
    live folder's entries; hard links only to a regular file written before."""

    def __init__(self, path, guard, root, folder):
        self.tar = ha_odoo.FileTar(path, guard)
        self.uid, self.gid, mode, mtime = root
        self.folder = folder
        self.files = set()
        self.tar.add_member(hacommon.info('./', 'dir', mode=mode & 0o1777, uid=self.uid, gid=self.gid, mtime=mtime))

    @staticmethod
    def name(rel):
        return f'./{rel}'

    def add(self, rel, kind, *, mode, mtime, size=0, fileobj=None, linkname=None):
        if kind == 'hardlink' and linkname not in self.files:
            raise BackupError('incompatible', f'HA 備份中的 {rel[:200]} 是另一個沒有搬過來的檔案的硬連結，無法只搬一半；'
                                              '已停止。', member=rel[:200])
        mode = mode & (0o1777 if kind == 'dir' else 0o777)
        self.tar.add_member(hacommon.info(self.name(rel), kind, mode=mode, uid=self.uid, gid=self.gid, mtime=mtime,
                                          size=size, linkname=self.name(linkname) if kind == 'hardlink' else linkname),
                            fileobj)
        if kind == 'file':
            self.files.add(rel)

    def copy_live(self, live_path, what):
        try:
            with ha_odoo._live_tar(live_path, what) as tar:
                for member in tar:
                    name = ha_odoo._norm(member.name)
                    if name is None:
                        raise BackupError('job-failed', f'{what}的匯出內容格式不正確。')
                    if name == '.':
                        tar.members.clear()
                        continue
                    info = ha_odoo._copy_info(member, self.name(name))
                    if member.islnk():
                        info.linkname = self.name(ha_odoo._norm(member.linkname) or '')
                    self.tar.add_member(info, tar.extractfile(member) if member.isfile() else None)
                    tar.members.clear()
        except tarfile.TarError:
            raise BackupError('job-failed', f'{what}的匯出內容無法讀取。') from None

    def close(self):
        self.tar.close()


def scan_share(stream, report, out=None, *, machine=None, checkpoint=None):
    """Walk HA's share member for `projects/**` (with `out`, a DirOut: written below out.folder)."""
    select = habackup.Select(include=(SHARE_PROJECTS,), symlinks=(SHARE_PROJECTS,), hardlinks=True)
    ws = Workspace()
    ws.present = True
    count = 0
    for entry in habackup.iter_entries(stream, select, report, addon=False, checkpoint=checkpoint):
        count += 1
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        if entry.name == SHARE_PROJECTS:
            if entry.kind != 'dir':
                raise BackupError('incompatible', 'HA 的 code-server 工作區（/share/projects）不是一般目錄，無法安全匯入。')
            ws.projects = True
            if out is not None:
                out.add(out.folder, 'dir', mode=entry.mode, mtime=entry.mtime)
            continue
        rel = entry.name[len(SHARE_PROJECTS) + 1:]
        dest = f'{out.folder}/{rel}' if out is not None else rel
        if entry.kind == 'dir':
            ws.dirs += 1
            if out is not None:
                out.add(dest, 'dir', mode=entry.mode, mtime=entry.mtime)
        elif entry.kind == 'symlink':
            if out is not None:
                out.add(dest, 'symlink', mode=0o777, mtime=entry.mtime, linkname=entry.linkname)
        elif entry.kind == 'hardlink':
            target = entry.linkname[len(SHARE_PROJECTS) + 1:] if entry.linkname.startswith(SHARE_PROJECTS + '/') else ''
            if out is None:
                pass    # the reader only hands a link out when its file came earlier: the conversion writes a link
            elif target and f'{out.folder}/{target}' in out.files:
                out.add(dest, 'hardlink', mode=0o644, mtime=entry.mtime, linkname=f'{out.folder}/{target}')
            else:   # CS-13: the file is not in the folder that is written: the reader hands this name out again as a file
                entry.copy_later()
                ws.links_copied += 1
        else:
            ws.files += 1
            ws.bytes += entry.size
            if machine is not None and len(ws.foreign) < MAX_LIST and hacommon.foreign_elf(entry.peek(20), machine):
                ws.foreign.append(rel)
            if out is not None:
                out.add(dest, 'file', mode=entry.mode, mtime=entry.mtime, size=entry.size,
                        fileobj=hacommon._Exact(entry))
    ws.skipped_symlinks = report.skipped_symlinks
    return ws


# ====================================================================== the live target

class Target:
    """The woow-code-server app's catalog items the import fills, resolved against the live Quadlet files. What the catalog
    has beyond the three volumes and the workspace folder (`extra_volumes`, `extra_dirs`) is carried as it is (CS-04); a
    folder setting that does not name the workspace folder (`conflict`) leaves the workspace out (CS-05)."""

    def __init__(self, work, app):
        quadlets = work.quadlets(app)
        home = work.runner(app).home.rstrip('/')
        declared = [v['name'] for v in app.volumes]
        container = hacommon.container_file(quadlets, CONTAINER)
        mounts = {}
        if container is not None:
            for source, target, _o in ha_odoo.quadlet_mounts(quadlets, container, home):
                mounts[target.rstrip('/')] = source
        self.pi, self.ide, self.ext = mounts.get(PI_TARGET), mounts.get(IDE_TARGET), mounts.get(EXT_TARGET)
        volumes = [self.pi, self.ide, self.ext]
        if container is None or any(v not in declared for v in volumes) or len(set(volumes)) != 3:
            raise BackupError('incompatible', '這台的 code-server 應用設定和 Quadlet 檔不一致，無法匯入。', app=app.id)
        if app.postgres:
            raise haissues.stopped(Issue('codeserver.target-has-database', 'stop', TARGET_HAS_DATABASE,
                                         action='請先在這台重新安裝標準的 code-server 應用，再匯入。'), 'incompatible', app=app.id)
        workspace = mounts.get(WORKSPACE_TARGET)
        rel = workspace[len(home) + 1:] if isinstance(workspace, str) and workspace.startswith(home + '/') else None
        dirs = [d['path'] for d in app.data_dirs]
        self.workspace_path = workspace if isinstance(workspace, str) else None
        self.workspace = rel if dirs and dirs == [rel] else None   # the catalog's workspace folder (decision D1 b), else not imported
        self.conflict = dirs if dirs and dirs != [rel] else []     # CS-05: the catalog names other folders than the workspace's
        self.extra_volumes, self.extra_dirs = hatarget.extras(app, handled_volumes=(self.pi, self.ide, self.ext),
                                                              handled_dirs=(self.workspace,) if self.workspace else ())
        self.image = tempctr.quadlet_image(quadlets[container])
        if not self.image:
            raise BackupError('incompatible', '這台 code-server 的 Quadlet 設定缺少映像。', app=app.id)


TARGET_HAS_DATABASE = '這台的 code-server 應用設定多了一個資料庫，匯入程式不知道怎麼搬它，為了不弄壞它，這次不匯入 code-server。'
WORKSPACE_NOT_MOVED = ('這台 code-server 的主機資料夾設定和它的工作區（/workspace）不是同一個資料夾，HA 的工作區專案（/share/projects）'
                       '不會搬過來，這台的資料夾維持原樣；其他設定與對話照常搬。需要 HA 的專案時，請在匯入後自行複製。')
EXTRAS_CARRIED = '這台的 code-server 應用設定還有其他資料卷或資料夾，匯入時照原樣保留，匯入後內容不變。'
NO_DATA = 'HA 備份裡沒有 code-server 的使用者設定或代理程式資料（data/vscode/User、data/pi-agent），沒有可搬的資料。'
NO_DATA_ACTION = '請確認 HA 的 code-server 有資料後重新備份，再匯入；這台的 code-server 不會有任何變更。'


def target_versions(work, app, target):
    """({program: x.y.z or None}, failed) of what the live image prints (a throwaway container, no network, the image's own
    user). The image is downloaded first when it is not here (CM-05; this app stops, with the reason, only when that cannot be
    done). `failed`: the command did not run in it (CS-07): no version is known, which is a notice, not a stop."""
    hatarget.ensure_image(work, app, target.image)
    tmp = work.temp(app)
    unknown = {program: None for program, _label in PROGRAMS}
    try:
        result = tmp.run('cs-versions', target.image, ['-c', VERSION_SCRIPT], entrypoint='/bin/sh',
                         env={'PI_TELEMETRY': '0', 'PI_SKIP_VERSION_CHECK': '1', 'DISABLE_AUTOUPDATER': '1'},
                         timeout=300, max_output=64 * 1024, check=False)
    except BackupError as error:
        if haissues.is_job_wide(error) or error.code in ('insufficient-space', 'busy'):
            raise
        return unknown, True
    if result.returncode != 0:
        return unknown, True
    return parse_versions((result.stdout or b'').decode('utf-8', 'replace')), False


def target_issues(sink, target):
    """What this device's catalog entry says about the import (check and conversion): the folders it names that the
    workspace is not (CS-05, one line to confirm) and what it carries beyond what is converted (CS-04)."""
    if target.conflict:
        sink.confirm('codeserver.workspace-not-moved', WORKSPACE_NOT_MOVED, target.conflict)
    extras = [*target.extra_volumes, *target.extra_dirs]
    if extras:
        sink.auto('codeserver.extras-carried', EXTRAS_CARRIED, extras)


# ====================================================================== checks and texts

READER_FAILED = '讀取沒有完成'


def check_dbs(work, src, staging):
    """{(area, rel): problem or None} of the staged SQLite files (sidecars ride along with their database). The sandboxed reader
    is started once more when it does not finish; then the databases of that batch count as damaged, not moved (CS-12)."""
    dbs = {key: value for key, value in src.dbs.items() if not key[1].endswith(SIDECARS)}
    results = {}
    keys = sorted(dbs)
    for start in range(0, len(keys), MAX_DBS_PER_RUN):
        batch = keys[start:start + MAX_DBS_PER_RUN]
        files, specs, names_ = {}, [], {}
        for index, key in enumerate(batch):
            name = f'd{start + index}'
            names_[name] = key
            files[name] = dbs[key][0]
            for suffix in SIDECARS:
                side = src.dbs.get((key[0], key[1] + suffix))
                if side is not None:
                    files[name + suffix] = side[0]
            specs.append({'db': name, 'check': 'quick'})

        def read(files=files, specs=specs, start=start):
            return hasqlite.run(specs, files, staging / f'sqlite-{start}', checkpoint=work.checkpoint, what='VS Code 的資料庫')

        try:
            answers = hatarget.retry(read, attempts=2, pause_first=3, retry_if=reader_failed, abort=work.abort, log=work.log,
                                     what='讀取 VS Code 的資料庫')
        except BackupError as error:
            if not reader_failed(error):
                raise
            results.update({key: READER_FAILED for key in names_.values()})
            continue
        for name, key in names_.items():
            answer = answers.get(name) or {'error': 'no answer'}
            results[key] = hasqlite.problem(answer)
    return results


def collect(sink, src, ws, target, db_problems):
    """What HA's code-server says about itself, as issues (the check and the conversion call it the same way). `ws`, `target`:
    the workspace walk and the catalog entry in a check (the conversion walks the workspace at its end: None)."""
    if not src.trees & {'pi', 'user'}:
        sink.stop('codeserver.no-data', NO_DATA, action=NO_DATA_ACTION)
    if target is not None and ws is not None:
        if target.workspace is None:
            if not target.conflict:
                sink.notice('codeserver.no-workspace-folder',
                            '這台的 code-server 應用設定沒有列出工作區資料夾，HA 的工作區專案（/share/projects）不會搬過來，'
                            '需要時請自行複製。')
        elif not ws.present:
            sink.notice('codeserver.no-share',
                        '這份 HA 備份沒有包含 share 資料夾，HA 的工作區專案（/share/projects）不會搬過來；'
                        '要一起搬，請在 HA 建立備份時勾選 share，或自行複製。')
        elif not ws.projects:
            sink.notice('codeserver.no-projects', 'HA 備份的 share 資料夾裡沒有 projects 資料夾（HA 的工作區可能設在別處），工作區不會搬過來。')
    bad = sorted(rel for (_area, rel), why in db_problems.items() if why)
    if bad:
        sink.notice('codeserver.databases-skipped',
                    f'HA 的 VS Code 資料中有 {len(bad)} 個資料庫損毀或讀取沒有完成，不會搬過來（多半只是畫面狀態，少了也能用）。', bad)
    unknown = unknown_names(src)
    if unknown:
        sink.notice('codeserver.unknown-entries',
                    f'HA 的 code-server 資料中有 {len(unknown)} 個這台不認得的項目，不會搬過來；需要時請自行複製。', unknown)
    foreign = [item.split(':', 1)[-1] for item in src.foreign] + (ws.foreign if ws is not None else [])
    if foreign:
        sink.notice('codeserver.foreign-programs',
                    f'HA 的資料中有其他處理器的程式（{len(foreign)} 個，例如 {names(foreign, 3)}），搬過來後無法執行，'
                    '需要時請在這台重新安裝或重新建置（例如 node_modules、.venv）。')
    if src.counts.get('skipped_symlinks'):
        sink.notice('codeserver.symlinks-skipped',
                    f'HA 的 code-server 資料中有 {src.counts["skipped_symlinks"]} 個指向資料以外的符號連結沒有搬過來'
                    '（這台的代理程式有自己的連結）。')
    if src.ha_urls:
        sink.notice('codeserver.ha-addresses',
                    f'HA 的 code-server 設定連到 HA 內部的位址（{names(src.ha_urls, 6)}），這台連不到，搬過來後請改成實際位址。')
    review, _hosts = mcp_review(hacommon.strict_json(src.mcp, MAX_JSON) if src.mcp else {})
    if review:
        sink.notice('codeserver.mcp-review',
                    f'HA 的共用 MCP 伺服器中有 {len(review)} 個帶有標頭或環境變數（{names(review, 5)}），可能含有權杖，搬過來後請確認。')
    kept = [rel for rel in src.large if rel != 'extensions.json']
    if kept:
        sink.notice('codeserver.files-kept',
                    f'HA 的 {names(kept, 4)} 太大，這次沒有搬過來；這台原有的同名檔案維持不變。', kept)
    if 'extensions.json' in src.large:
        sink.notice('codeserver.extensions-skipped',
                    'HA 的延伸模組清單（extensions.json）太大，這次沒有讀它，HA 自己安裝的延伸模組不會搬過來；需要時請在這台重新安裝。')
    links = src.links_copied + (ws.links_copied if ws is not None else 0)
    if links:
        sink.auto('codeserver.links-copied',
                  f'HA 的 code-server 資料有 {links} 個硬連結的檔案，這台不能把它們連在一起，已改成各自複製檔案內容'
                  '（磁碟用量會比 HA 大一些）。')


def unknown_names(src):
    """Top-level names HA has that this importer does not know, with something but folders in them."""
    return sorted(label.split(':', 1)[1] for label, count in src.unknown.items() if count)


def section(src, ws, report, ws_report, *, versions):
    pins = PINS.get(src.addon.version) if src.addon else None
    ha_ext = extension_entries(src.extensions)
    user_ext = [rel for rel, item in ha_ext.items() if not extension_id(item).startswith(CONNECTOR_PUBLISHER)]
    mcp_doc = hacommon.strict_json(src.mcp, MAX_JSON) if src.mcp else {}
    return {f'{APP_ID}_version': (pins or {}).get('code-server') or '',
            'pins': {program: (pins or {}).get(program) or '' for program, _l in PROGRAMS},
            'target_pins': {program: versions.get(program) or '' for program, _l in PROGRAMS},
            'files': src.counts.get('pi', {}).get('files', 0) + src.counts.get('ide', {}).get('files', 0),
            'bytes': src.counts.get('pi', {}).get('bytes', 0) + src.counts.get('ide', {}).get('bytes', 0),
            'sessions': src.sessions, 'claude_projects': src.claude_projects, 'codex_sessions': src.codex_sessions,
            'skills': len(src.skills), 'snippets': src.snippets, 'settings': src.settings is not None,
            'extensions': len(user_ext), 'mcp_servers': len(mcp_servers(mcp_doc)),
            'workspace': ws.projects, 'share': ws.present, 'workspace_files': ws.files, 'workspace_bytes': ws.bytes,
            'skipped_symlinks': src.counts.get('skipped_symlinks', 0),
            'links_copied': report.copied_links + ws_report.copied_links,
            'skipped': report.skip_count(*od.SKIPS) + ws_report.skip_count(*od.SKIPS), 'files_kept': sorted(src.large),
            'ha_urls': sorted(src.ha_urls)[:20],
            'left_out': {label: count for label, count in sorted(src.left.items())},
            'unknown': unknown_names(src)[:20]}


# ====================================================================== the job steps

def _pass(work, app, staging, outs, report):
    member = work.addon_member(SLUG)
    with work.open(member) as stream:
        src = scan_member(stream, report, staging, outs, machine=hacommon.host_elf_machine(),
                          checkpoint=work.checkpoint)
    for note in report.warnings():
        work.log(note)
    left = sum(src.left.values())
    work.log(f'HA 的 code-server：{src.counts["pi"]["files"] + src.counts["ide"]["files"]} 個檔案要搬，'
             f'{left} 個項目（代理程式登入、連接器、程式與快取）留在 HA')
    return src


def _share_pass(work, report, out=None):
    member = work.share_member()
    if member is None:
        return Workspace()
    with work.open(member) as stream:
        ws = scan_share(stream, report, out, machine=hacommon.host_elf_machine(), checkpoint=work.checkpoint)
    work.log(f'HA 的工作區：{ws.files} 個檔案' if ws.projects else 'HA 的 share 資料夾裡沒有工作區（projects）')
    return ws


def check(work, app):
    sink = work.sink(app)
    target = Target(work, app)
    versions, failed = target_versions(work, app, target)
    addon = work.addon_info(SLUG)
    sink.extend(version_issues(addon.version, versions, failed))
    target_issues(sink, target)
    staging = work.staging / 'codeserver-work'
    staging.mkdir(mode=0o700)
    report = habackup.Report(names=haissues.Names)
    ws_report = habackup.Report(names=haissues.Names)
    outs = {key: Volume(None, (0, 0), {}, key, report) for key in ('pi', 'ide', 'ext')}
    src = _pass(work, app, staging, outs, report)
    ws = _share_pass(work, ws_report) if target.workspace is not None else Workspace()
    work.phase('check')
    db_problems = check_dbs(work, src, staging) if src.dbs else {}
    collect(sink, src, ws, target, db_problems)
    ext = extension_entries(src.extensions)
    _move, skipped = choose_extensions(ext, {}, src.ext_foreign, hacommon.host_elf_machine())
    other = sorted(rel for rel, why in skipped.items() if why in ('platform', 'foreign'))
    if other:
        sink.notice('codeserver.extensions-other-processor',
                    f'HA 的延伸模組中有 {len(other)} 個是其他處理器專用的（{names(other, 4)}），不會搬過來，需要時請在這台重新安裝。',
                    other)
    skip_line(sink, report)
    skip_line(sink, ws_report)
    return {'target_version': versions.get('code-server') or '', APP_ID: section(src, ws, report, ws_report, versions=versions)}


def _root(work, app, volume):
    uid, gid, _mode = ha_n8n.volume_root(work, app, volume)
    return uid, gid


def _volume_reader(work, app, volume, path, what, read):
    """A read of one live volume that makes sure it is whole (its export is read to its end: `live_index`) -> (path, index, files)."""
    def attempt():
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        hacommon.live_export(work, app, volume, path)
        index, contents = live_index(path, what, read=read)
        return path, index, contents

    return attempt


def convert(work, app, test_mode, out_dir):
    """Build `out_dir/volumes/<volume>.tar` for the three volumes (HA's data + this device's), what the catalog has beyond them
    (carried as it is) and, when the catalog lists the workspace, `out_dir/dirs/0.tar` (this device's workspace + HA's projects)."""
    del test_mode  # a test import changes nothing else of code-server (it runs no scheduled work)
    adapter = work.adapter(app)
    runner = work.runner(app)
    sink = work.sink(app)
    target = Target(work, app)
    versions, failed = target_versions(work, app, target)
    addon = work.addon_info(SLUG)
    sink.extend(version_issues(addon.version, versions, failed))
    target_issues(sink, target)       # a line that was not confirmed ends this app here, before anything of this device is read
    ids = adapter.owner_ids()
    staging = work.staging / 'codeserver-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    sizes = {name: adapter._volume_size(name) for name in (target.pi, target.ide, target.ext)}
    work.guard.check(2 * sum(sizes.values()))
    work.log('讀取這台 code-server 的資料卷（代理程式登入、連接器與這台自己的設定會保留）')
    what = {'pi': '這台 code-server 的代理程式資料卷', 'ide': '這台 code-server 的 VS Code 設定資料卷',
            'ext': '這台 code-server 的延伸模組資料卷'}
    plan = (('pi', target.pi, ('shared/mcp.json', 'claude/history.jsonl')), ('ide', target.ide, (USER_MERGED,)),
            ('ext', target.ext, ('extensions.json',)))
    read = read_live(work, app, sink, [_volume_reader(work, app, volume, staging / f'live-{key}.tar', what[key], files)
                                       for key, volume, files in plan],
                     sources=(target.pi, target.ide, target.ext), what='這台 code-server 的資料卷', issue_id=PAUSE_ID)
    live, indexes = {}, {}
    for (key, _volume, _files), (path, index, contents) in zip(plan, read):
        live[key], indexes[key] = path, (index, contents)
    (pi_index, pi_files), (ide_index, ide_files), (ext_index, ext_files) = indexes['pi'], indexes['ide'], indexes['ext']
    paths = {key: out_dir / 'volumes' / f'{volume}.tar'
             for key, volume, _files in plan}
    report = habackup.Report(names=haissues.Names)
    outs = {'pi': Volume(ha_odoo.FileTar(paths['pi'], work.guard), _root(work, app, target.pi), pi_index, what['pi'], report),
            'ide': Volume(ha_odoo.FileTar(paths['ide'], work.guard), _root(work, app, target.ide), ide_index, what['ide'], report),
            'ext': Volume(ha_odoo.FileTar(staging / 'ha-ext.tar', work.guard), (0, 0), {}, 'HA 的延伸模組', report)}
    try:
        src = _pass(work, app, staging, outs, report)
    finally:
        outs['ext'].close()
    work.phase('convert')
    db_problems = check_dbs(work, src, staging) if src.dbs else {}
    collect(sink, src, None, None, db_problems)      # a stop raises here: nothing of this device was copied yet
    seen = skip_line(sink, report)                    # ... and so does a line that was not confirmed
    details, kept_links = {}, 0
    try:
        for part in (_finish_pi(src, outs['pi'], pi_files, db_problems, live['pi']),
                     _finish_ide(src, outs['ide'], ide_files, db_problems, live['ide'])):
            kept_links += part.pop('kept_links', 0)
            details.update(part)
    finally:
        outs['pi'].close()
        outs['ide'].close()
    ext_out = Volume(ha_odoo.FileTar(paths['ext'], work.guard), _root(work, app, target.ext), ext_index, what['ext'], report)
    try:
        part = _finish_ext(src, ext_out, ext_files, staging / 'ha-ext.tar', live['ext'])
        kept_links += part.pop('kept_links', 0)
        details.update(part)
    finally:
        ext_out.close()
    for key in live:
        os.unlink(live[key])
    result = {'volumes': {target.pi: paths['pi'], target.ide: paths['ide'], target.ext: paths['ext']}}
    ws, ws_report = Workspace(), habackup.Report(names=haissues.Names)
    if target.workspace is not None:
        ws, dir_path, folder = _workspace(work, app, runner, target, staging, out_dir, sink, ws_report)
        result['dirs'] = {target.workspace: dir_path}
        details['workspace_folder'] = folder if ws.projects else ''
        skip_line(sink, ws_report)
    if target.extra_volumes or target.extra_dirs:          # CS-04: what this device has beyond them stays as it is
        carried = hatarget.carry(work, app, out_dir, ids, volumes=target.extra_volumes, dirs=target.extra_dirs, report=report,
                                 size=sum(sizes.values()))
        result['volumes'].update(carried['volumes'])
        result.setdefault('dirs', {}).update(carried['dirs'])
    if kept_links:
        sink.auto('codeserver.kept-links-copied',
                  f'這台 code-server 有 {kept_links} 個保留下來的硬連結，它指到的檔案會被 HA 的資料取代，'
                  '已改成各自保留原本的檔案內容。')
    skip_line(sink, report, seen)   # this device's own links that could not be kept (rare): a line of its own
    for path in result['volumes'].values():
        ha_odoo.check_volume_tar(path, ids)
    for path in result.get('dirs', {}).values():
        _check_dir_tar(path, ids)
    work.log(f'code-server 資料整理完成：{src.sessions} 個 Pi 對話、{src.claude_projects} 個 Claude Code 對話、'
             f'{src.codex_sessions} 個 Codex 對話、{len(src.skills)} 個技能')
    review, hosts = mcp_review(hacommon.strict_json(src.mcp, MAX_JSON) if src.mcp else {})
    result.update(details, sessions=src.sessions, claude_projects=src.claude_projects, codex_sessions=src.codex_sessions,
                  skills=len(src.skills), snippets=src.snippets, workspace=ws.projects, share=ws.present,
                  workspace_files=ws.files, workspace_target=target.workspace or '', ha_urls=sorted(src.ha_urls),
                  mcp_review=review, mcp_hosts=hosts, unknown=unknown_names(src),
                  foreign=len(src.foreign) + len(ws.foreign), links_copied=report.copied_links + ws_report.copied_links,
                  files_kept=sorted(src.large), workspace_conflict=list(target.conflict))
    return result


def _finish_pi(src, out, live_files, db_problems, live_path):
    details = {'mcp_added': [], 'mcp_same': [], 'history': 'none'}
    if src.mcp is not None:
        ha_doc = hacommon.strict_json(src.mcp, MAX_JSON)
        live_doc = hacommon.strict_json(live_files['shared/mcp.json'], MAX_JSON) \
            if 'shared/mcp.json' in live_files else None
        if isinstance(ha_doc, dict):
            merged, added, same = merge_mcp(ha_doc, live_doc)
            details.update(mcp_added=added, mcp_same=same)
            if added or live_doc is None:
                out.ensure_dirs('shared/mcp.json', mode=0o700)
                out.data('shared/mcp.json', json_bytes(merged), 0o600, int(time.time()), prefer='ha')
        else:
            details['mcp_unreadable'] = True
    if src.history is not None:
        live_history = live_files.get('claude/history.jsonl')
        if live_history is None:
            out.ensure_dirs('claude/history.jsonl', mode=0o700)
            if out.data('claude/history.jsonl', src.history, 0o600, int(time.time()), prefer='live'):
                details['history'] = 'moved'
        else:
            merged = merge_history(live_history, src.history)
            if merged is None:
                details['history'] = 'kept'
            else:
                out.data('claude/history.jsonl', merged, 0o600, int(time.time()), prefer='ha')
                details['history'] = 'merged'
    _write_dbs(src, 'pi', out, db_problems)
    details['kept_links'] = out.finish(live_path)
    details['pi_kept'] = sorted(rel.split('/', 1)[1] for rel in out.kept
                                if rel.startswith('skills/') and rel.count('/') == 1)
    details['pi_conflicts'] = len([rel for rel in out.kept if rel not in ('settings.json', 'models.json')])
    return details


def _finish_ide(src, out, live_files, db_problems, live_path):
    details = {'settings': 'none', 'settings_dropped': [], 'acp_agents_added': []}
    if src.settings is not None:
        ha_doc, comments = jsonc_loads(src.settings)
        if ha_doc is None:
            details['settings'] = 'unreadable'
        else:
            live_doc, _c = jsonc_loads(live_files[USER_MERGED]) if USER_MERGED in live_files else (None, False)
            merged, dropped, extra = merge_settings(ha_doc, live_doc)
            out.data(USER_MERGED, json_bytes(merged), 0o644, int(time.time()), prefer='ha')
            details.update(settings='merged', settings_dropped=dropped, acp_agents_added=extra,
                           settings_comments=comments)
    _write_dbs(src, 'user', out, db_problems)
    details['kept_links'] = out.finish(live_path)
    return details


def _write_dbs(src, area, out, problems):
    for (key, rel), (path, mode, mtime) in sorted(src.dbs.items()):
        if key != area:
            continue
        base = rel
        for suffix in SIDECARS:
            if rel.endswith(suffix) and (key, rel[:-len(suffix)]) in src.dbs:
                base = rel[:-len(suffix)]
        if problems.get((key, base)):
            continue
        with open(path, 'rb') as handle:
            data = handle.read()
        out.ensure_dirs(rel)
        out.data(rel, data, mode, mtime, prefer='live' if area == 'pi' else 'ha')
        os.unlink(path)


def _staging_readable(ha_tar):
    """True when the staged folders of HA's extensions can be read to their end. This job wrote them: a failure here is a problem of
    the staging, not of HA's data, so only the extensions are left out (CS-17)."""
    try:
        with ha_odoo._live_tar(ha_tar, 'HA 的延伸模組') as tar:
            for _member in tar:
                tar.members.clear()
    except (tarfile.TarError, BackupError, OSError):
        return False
    return True


def _finish_ext(src, out, live_files, ha_tar, live_path):
    """HA's chosen extension folders (from the staging tar) and extensions.json with them, then the live volume."""
    ha_entries = extension_entries(src.extensions)
    if 'extensions.json' in live_files:
        live_doc = hacommon.strict_json(live_files['extensions.json'], MAX_JSON)
    else:
        live_doc = [] if 'extensions.json' not in out.live else None
    live_entries = extension_entries(live_doc)
    move, skipped = choose_extensions(ha_entries, live_entries, src.ext_foreign, hacommon.host_elf_machine())
    if not isinstance(live_doc, list):
        skipped.update({rel: 'unreadable' for rel in move})  # this device's list cannot be extended safely
        move = []
    moved, unreadable = set(), False
    if move and not _staging_readable(ha_tar):
        skipped.update({rel: 'unreadable' for rel in move})     # CS-17: only the extensions are left out, everything else moves
        move, unreadable = [], True
    if move:
        try:
            with ha_odoo._live_tar(ha_tar, 'HA 的延伸模組') as tar:
                for member in tar:
                    name = ha_odoo._norm(member.name)
                    top = (name or '').split('/', 1)[0]
                    if name in (None, '.') or top not in move:
                        tar.members.clear()
                        continue
                    if member.isdir():
                        out.dir(name, member.mode, member.mtime, prefer='ha')
                    elif member.issym():
                        out.symlink(name, member.linkname, member.mtime, prefer='ha')
                    elif member.islnk():
                        out.hardlink(name, ha_odoo._norm(member.linkname) or '', member.mtime, prefer='ha')
                    elif member.isfile():
                        out.stream(name, member.size, member.mode, member.mtime, tar.extractfile(member), prefer='ha')
                    moved.add(top)
                    tar.members.clear()
        except tarfile.TarError:
            raise BackupError('job-failed', 'HA 的延伸模組暫存內容無法讀取。') from None
        doc = list(live_doc) + [relocate_extension(ha_entries[rel], rel) for rel in move if rel in moved]
        out.data('extensions.json', json_bytes(doc), 0o644, int(time.time()), prefer='ha')
    os.unlink(ha_tar)
    kept_links = out.finish(live_path)
    return {'kept_links': kept_links, 'extensions_unreadable': unreadable,
            'extensions_moved': sorted(extension_id(ha_entries[rel]) for rel in moved),
            'extensions_skipped': sorted(extension_id(ha_entries[rel]) for rel, why in skipped.items()
                                         if why != 'same'),
            'extensions_same': sorted(extension_id(ha_entries[rel]) for rel, why in skipped.items() if why == 'same')}


def _workspace(work, app, runner, target, staging, out_dir, sink, report):
    """(Workspace, dir tar, folder name): this device's workspace folder plus HA's projects in a new subfolder. The pack of this
    device's folder is read to its end; it is tried again and, when that does not help, done once with the app's own container
    paused (CS-16); what still does not work stops this app (the restore would replace the folder by one that lacks files)."""
    (out_dir / 'dirs').mkdir(mode=0o700, parents=True, exist_ok=True)
    measured = runner.dir_measure(target.workspace)
    member = work.share_member()
    work.guard.check(2 * measured['bytes'])  # HA's projects are counted while they are written (the space guard)
    live_dir = staging / 'live-workspace.tar'
    what = '這台 code-server 的工作區'

    def attempt():
        with contextlib.suppress(FileNotFoundError):
            os.unlink(live_dir)
        with open(live_dir, 'xb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            runner.dir_pack(target.workspace, stdout=handle, timeout=3 * 3600, max_output=work.guard.budget(),
                            abort=work.abort)
        root, top_names = None, set()
        try:
            with ha_odoo._live_tar(live_dir, what) as tar:
                for item in tar:
                    name = ha_odoo._norm(item.name)
                    if name == '.':
                        root = (item.uid, item.gid, item.mode & 0o7777, item.mtime)
                    elif name:
                        top_names.add(name.split('/', 1)[0])
                    tar.members.clear()
        except tarfile.TarError:
            raise BackupError('job-failed', f'{what}的匯出內容無法讀取。') from None
        if root is None:
            raise BackupError('job-failed', f'{what}的匯出內容格式不正確。', app=app.id)
        return root, top_names

    root, top_names = read_live(work, app, sink, [attempt], sources=(target.workspace_path,), what=what,
                                issue_id=PAUSE_ID)[0]
    stamp = _date_stamp(work)
    folder, n = f'ha-projects-{stamp}', 1
    while folder in top_names:
        n += 1
        folder = f'ha-projects-{stamp}-{n}'
    path = out_dir / 'dirs' / '0.tar'
    out = DirOut(path, work.guard, root, folder)
    try:
        ws = _share_pass(work, report, out) if member is not None else Workspace()
        out.copy_live(live_dir, what)
    finally:
        out.close()
    os.unlink(live_dir)
    return ws, path, folder


def _date_stamp(work):
    record = getattr(work, 'record', None) or {}
    try:
        return util.parse_iso_utc(record.get('date')).astimezone().strftime('%Y%m%d')
    except (ValueError, TypeError, OSError, AttributeError):
        return time.strftime('%Y%m%d')


def _check_dir_tar(path, ids):
    try:
        return nested.check_dir(path, ids=ids)
    except BackupError as error:
        raise BackupError('job-failed', f'轉換後的 code-server 工作區無法還原（{error.message}）。',
                          reason=(error.details or {}).get('reason')) from None


# ====================================================================== texts

def import_texts(data):
    notes = ['code-server 的 VS Code 設定（合併）、快捷鍵、程式碼片段、全域狀態與本機記錄，HA 自己安裝的延伸模組，'
             'Pi、Claude Code 與 Codex 的對話記錄和技能，以及共用的 MCP 伺服器會搬過來；這台的密碼、代理程式的登入、'
             'Omnigent 與 Paseo 連接器、已安裝的程式、woow-code-server.env，以及主機的 .ssh、.gitconfig 保持不變。',
             '還原會用轉換時讀到的這台資料（加上 HA 的資料）取代 code-server 的資料卷'
             + ('與工作區' if data.get('workspace_target') else '')
             + '：轉換之後才在這台新增的對話或檔案不會保留（還原前備份裡有）。']
    if data.get('links_copied'):
        notes.append(f'HA 有 {data["links_copied"]} 個硬連結的檔案（例如 pnpm 安裝過的套件），已改成各自複製檔案內容。')
    if data.get('workspace'):
        notes.append(f'HA 的工作區專案（/share/projects，{data.get("workspace_files", 0)} 個檔案）會放進這台工作區的'
                     f'「{data.get("workspace_folder") or "ha-projects"}」資料夾，這台原有的檔案保持不變。')
    if data.get('pi_kept'):
        notes.append(f'這台已有同名的技能（{names(data["pi_kept"], 5)}）：保留這台的版本，HA 的不會搬過來。')
    reminders = ['代理程式（Pi、Claude Code、Codex）沿用這台原本的登入，HA 上登入的帳號不會搬過來；需要時請在 code-server 的'
                 '終端機重新登入（pi 的 /login、claude auth login、codex login --device-auth）。',
                 'HA 的對話記錄搬過來後只能查看：它們的工作目錄是 HA 的 /share/projects，這台是 /workspace，無法直接接續。',
                 'Omnigent 與 Paseo 連接器沿用這台原本的連線與配對；如果 HA 的 code-server 也連過，請在 Omnigent 上移除 HA 那台主機。',
                 'HA 的 SSH 金鑰、git 身分與 zsh 指令記錄不會搬過來；需要時請把金鑰放進這台主機的 ~/.ssh，並確認 git 的使用者設定。']
    if data.get('extensions_skipped'):
        reminders.append(f'HA 的延伸模組 {names(data["extensions_skipped"], 6)} 沒有搬過來（其他處理器專用），需要時請在這台重新安裝。')
    if data.get('acp_agents_added'):
        reminders.append(f'HA 自訂的 ACP 代理程式（{names(data["acp_agents_added"], 5)}）已搬過來，請確認這台有對應的程式。')
    if data.get('mcp_review'):
        reminders.append(f'共用 MCP 伺服器 {names(data["mcp_review"], 5)} 帶有標頭或環境變數（可能含權杖），請確認它們在這台仍然正確。')
    if data.get('ha_urls') or data.get('mcp_hosts'):
        items = list(data.get('ha_urls') or []) + list(data.get('mcp_hosts') or [])
        reminders.append(f'HA 的 code-server 設定連到 HA 內部的位址（{names(items, 6)}），請改成這台連得到的位址。')
    if data.get('workspace') and data.get('foreign'):
        reminders.append('HA 工作區的 node_modules、.venv 等安裝結果可能是其他處理器的程式，請在這台重新安裝或建置。')
    if data.get('unknown'):
        reminders.append(f'HA 的 code-server 資料中這台不認得的項目（{names(data["unknown"], 6)}）沒有搬過來，需要時請自行複製。')
    if data.get('workspace_target') and not data.get('workspace'):
        reminders.append('HA 的工作區專案（/share/projects）不在這份備份裡，沒有搬過來；需要時請自行複製到這台的工作區。')
    if data.get('workspace_conflict'):
        reminders.append('這台 code-server 的主機資料夾設定和它的工作區不是同一個資料夾，HA 的工作區專案（/share/projects）沒有搬過來；'
                         '需要時請自行複製到這台的工作區。')
    if data.get('files_kept'):
        reminders.append(f'HA 的 {names(data["files_kept"], 4)} 太大，沒有搬過來；這台原有的同名檔案維持不變。')
    if data.get('extensions_unreadable'):
        reminders.append('HA 的延伸模組在轉換時暫存失敗，沒有搬過來；請在這台重新安裝需要的延伸模組。')
    return notes, reminders
