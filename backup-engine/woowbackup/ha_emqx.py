"""Home Assistant import, EMQX part: the WOOWTECH add-on `woow-emqx` -> this device's app `emqx` (CONTRACT section 9
"Home Assistant import"; facts phase3/facts/emqx.md). Owner: E2.

The add-on runs EMQX 5.8.9 as root with its data dir at /data/emqx/data (`data/emqx/data/` in the member: the Mnesia
database in `mnesia/<node name>/`, the Dashboard's `configs/cluster.hocon`, `certs/`, `authz/`) and pins its node name
in `data/emqx/node.name` (an install made before add-on 5.9.1 is `emqx@<HA host>.local`, a newer one `emqx@127.0.0.1`).
Mnesia is tied to the node name and the Podman broker's is fixed (`emqx@127.0.0.1`), so the files are never copied:
EMQX's own data export and import move the data, node-name independent, in two throwaway brokers of the live image
(network none, read-only root, labelled, the job's watchdog):

1. HA's broker: HA's staged files (never its cookie, generated configs, logs, plugins or hot patches) in a
   `noexec,nosuid,nodev` volume at /data/emqx/data, HA's node name (its host mapped to 127.0.0.1 with `--add-host`),
   root like on HA, an empty default dashboard password (nothing is created at boot). It answers the default-account
   check (admin/public still valid: a blocker), the row counts, its root names and authenticators, then
   `emqx ctl data export` of the data roots (DATA_ROOTS; never listeners, dashboard, node, log or other settings) and
   the table sets (TABLE_SETS: MQTT users, ACL rules, banned, Dashboard users, API keys, PSK, retained messages).
2. This device's broker (the candidate). First this device's running broker is read (target_static): its effective
   RAW configuration, EMQX_ETC_DIR, the override state; it must be inside the proven profile (authorization sources
   exactly [file] or [file, built_in_database]; reviewed roots and file references only), else the check and the
   conversion refuse with a message naming what. HA's ACL rows only take effect through a built-in database source
   and the import never adds or changes this device's sources (OWNER DECISION 2026-11-23 「C」): a target that
   authorizes with the ACL file only refuses a backup with ACL rows (acl_blocker: the check's blocker, and the
   conversion stops as soon as HA's rows are counted). Its cluster.hocon and the data-volume files it names are
   snapshotted. The candidate: the live environment and secret mounts, the live base.hocon/acl.conf read-only, the
   snapshot in an otherwise empty data volume, `emqx ctl data import`; then every setting root of this device
   (authorization among them) is loaded back exactly as it was, its bootstrap file stays attached, HA's ACL rows are
   kept through the switch of the authorization sources (native receipts), an enabled authenticator must remain (no
   anonymous login); every table must hold at least HA's rows and at most HA's plus what the empty broker seeded.
   HA's API keys replace this device's (the EMQX MCP admin must log in again).
3. Readback: the finished candidate's configuration (a SHA-256 per root, this device's secret values redacted first)
   and the administrator tables (rows and a row-hash receipt) go into the converted backup (`import_check`); after the
   restore started the units, verify_restored reads the same from the restored broker and any difference fails the
   restore, which then rolls back by itself.

`woow_emqx_data` is that broker's volume without its generated configs (one holds the cookie), backups of
cluster.hocon, data exports and traces; `woow_emqx_log` is only its top folder. Versions: the add-on version maps to
the EMQX version it pins (VERSIONS), which must equal the live image's `org.opencontainers.image.version`.
"""
import io
import hashlib
import base64
import json
import os
import re
import tarfile
import time

from . import habackup, hacommon, ha_n8n, ha_odoo, tempctr, util, ha_emqx_settings
from .errors import BackupError

SLUG = 'woow-emqx'
APP_ID = 'emqx'
STATE = 'data/emqx'
DATA = 'data/emqx/data'
NODE_FILE = 'data/emqx/node.name'
PLUGINS = 'data/emqx/plugins'
STAGED = ('mnesia', 'configs/cluster.hocon', 'certs', 'authz')
HA_DATA_DIR = '/data/emqx/data'
DATA_TARGET = '/opt/emqx/data'
LOG_TARGET = '/opt/emqx/log'
WORK = '/work'
# Add-on version -> the EMQX release its Dockerfile pins (Woow_ha_emqx CHANGELOG.md, Dockerfile EMQX_VERSION).
VERSIONS = hacommon.VersionTable('EMQX', {'5.8.9': '5.8.9', '5.9.0': '5.8.9', '5.9.1': '5.8.9'})
# Retainer backend/storage/expiry belong to HA message data. Import them before
# Mnesia keep_tables; restoring target RAM settings would lose rows at packaging stop.
DATA_ROOTS = ('authentication', 'authorization', 'rule_engine', 'connectors', 'actions', 'sources', 'bridges',
              'rewrite', 'auto_subscribe', 'exhook', 'gateway', 'psk_authentication', 'topic_metrics',
              'retainer')
TABLE_SETS = ('builtin_authn', 'builtin_authz', 'banned', 'dashboard_users', 'api_keys', 'psk', 'builtin_retainer')
TABLES = ('emqx_authn_mnesia', 'emqx_authn_scram_mnesia', 'emqx_acl', 'emqx_banned', 'emqx_banned_rules', 'emqx_admin',
          'emqx_app', 'emqx_psk', 'emqx_retainer_message')
# Tables a running EMQX 5.8.9 always has: one missing in HA's broker means its database did not load completely.
REQUIRED_TABLES = ('emqx_authn_mnesia', 'emqx_acl', 'emqx_banned', 'emqx_admin', 'emqx_app')
# This device's broker: the image's etc dir (vendor rel/emqx_vars:16 + rebar.config.erl:407: "$BASE_RUNNER_ROOT_DIR/etc"
# in the tgz/docker build, exported by bin/emqx:269-273), proven in the running broker before its template is resolved.
ETC_DIR = '/opt/emqx/etc'
ACL_TEMPLATE = '${EMQX_ETC_DIR}/acl.conf'
ETC_EXPR = 'io:format("WOOWETC:~s:END", [os:getenv("EMQX_ETC_DIR", "")]).'
# The authorization source combinations proven end to end (2026-11-23: real ARM and x86 HA backups, EMQX 5.8.9).
PROFILES = {(('file', True),): ('file',), (('file', True), ('built_in_database', True)): ('file', 'built_in_database')}
SOURCE_NAMES = {'file': 'ACL 檔案', 'built_in_database': '內建資料庫', 'http': 'HTTP', 'redis': 'Redis', 'mysql': 'MySQL',
                'postgresql': 'PostgreSQL', 'mongodb': 'MongoDB', 'ldap': 'LDAP', 'client_info': '用戶端資訊'}
# One plain `EMQX_KEY=value` line of an EnvironmentFile (podman --env-file keeps the value literal): no quotes,
# backslashes, `$` or surrounding blanks, so the candidate gets exactly what the running broker got.
ENV_FILE_LINE = re.compile(r'(EMQX_[A-Z0-9_]{1,100})=([^\s"\'\\$](?:[^"\'\\$]{0,4094}[^\s"\'\\$])?)')
NOT_RUNNING = '這台的 EMQX 沒有在執行，無法讀取它的設定；請先到「應用軟體」啟動 EMQX 後再試一次。'
# OWNER DECISION 2026-11-23 「C」 (EMQX 權限): the owner's text, verbatim (acl_blocker).
ACL_NEEDS_BUILTIN = ('Podman 上的 EMQX 沒有開啟『內建資料庫』權限，HA 的裝置權限搬過去不會生效，裝置會被拒絕。'
                     '請先在 Podman EMQX 的管理頁「存取控制 → 授權」新增「內建資料庫」（排在檔案規則之後），再匯入。')
HOT_HINT = ('這份備份是在 EMQX 執行中製作的，內建資料庫可能只寫了一半；請先在 HA 停止 EMQX 附加元件，再重新製作備份後匯入'
            '（附加元件停止時製作的備份最可靠）。')
NODE_RE = re.compile(r'([A-Za-z][A-Za-z0-9_-]{0,63})@([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)\Z')
IPV4_RE = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}\Z')
EXPORT_RE = re.compile(rb'exported to (/work/out/emqx-export-[0-9.-]{10,40}\.tar\.gz)')
READY_TIMEOUT = 300
MAX_HOCON = 8 * 1024 * 1024
MAX_EXPORT = 2 * 1024 ** 3
DROPPED = re.compile(r'(?:configs/(?:app\.[^/]*\.config|vm\.[^/]*\.args|[^/]*\.bak)|backup/.+|trace/.+)\Z')

DEFAULT_ADMIN_EXPR = ('case emqx_dashboard_admin:check(<<"admin">>, <<"public">>) of {ok, _} -> default; '
                      '_ -> changed end.')
COUNT_EXPR = ('[{T, case catch mnesia:table_info(T, size) of N when is_integer(N) -> N; _ -> -1 end} || T <- ['
              + ', '.join(TABLES) + ']].')
SUSPEND_SYS_EXPR = ('P = whereis(emqx_sys), ok = sys:suspend(P, 5000), '
                    '{status, P, _, [_, suspended | _]} = sys:get_status(P, 5000), '
                    'P = whereis(emqx_sys), io:format("WOOWSYS:~s:suspended~n", [pid_to_list(P)]).')
TICKER_STATUS_EXPR = ('P = whereis(emqx_sys), true = (pid_to_list(P) =:= "{pid}"), '
                     '{status, P, _, [_, suspended | _]} = sys:get_status(P, 5000), ticker_unchanged.')
ROOTS_EXPR = 'emqx_config:get_root_names().'
AUTHN_EXPR = ('[{maps:get(mechanism, A, none), maps:get(backend, A, none), maps:get(enable, A, true), '
              'maps:get(name, maps:get(password_hash_algorithm, A, #{}), none), '
              'maps:get(salt_position, maps:get(password_hash_algorithm, A, #{}), none)} '
              '|| A <- emqx:get_config([authentication], [])].')
STRICT_EXPR = '{emqx:get_config([authorization, no_match]), emqx:get_config([authorization, deny_action])}.'


# ====================================================================== the add-on member

class Source:
    def __init__(self):
        self.addon = None
        self.node_file = None
        self.node_dirs = set()
        self.files = 0
        self.bytes = 0
        self.hocon = ''
        self.plugins = set()


def scan_member(stream, report, out=None, *, checkpoint=None):
    """One strict pass: HA's data dir items (STAGED) into `out` (a FileTar for the throwaway volume: names relative to
    the data dir, root-owned like on HA, dirs 0755, files 0644, nothing executable), cluster.hocon kept as text, the
    node name file read; the cookie, generated configs, plugins, patches, backups, traces and logs never."""
    select = habackup.Select(include=tuple(f'{DATA}/{item}' for item in STAGED) + (NODE_FILE, PLUGINS), symlinks=(),
                             hardlinks=False)
    src = Source()
    count = 0
    for entry in habackup.iter_entries(stream, select, report, checkpoint=checkpoint):
        count += 1
        if checkpoint is not None and count % 256 == 0:
            checkpoint()
        name = entry.name
        if name == NODE_FILE:
            if entry.kind == 'file':
                src.node_file = entry.read_all(1024).decode('ascii', 'replace').strip()[:300]
            continue
        if ha_odoo._under(name, PLUGINS):
            rest = name[len(PLUGINS) + 1:]
            if rest and '/' not in rest:
                src.plugins.add(rest[:100])
            continue
        rel = name[len(DATA) + 1:]
        parts = rel.split('/')
        if parts[0] == 'mnesia' and (len(parts) >= 3 or len(parts) == 2 and entry.kind == 'dir'):
            src.node_dirs.add(parts[1][:300])
        if out is not None and len(parts) > 1:
            for depth in range(1, len(parts)):  # the folders above a selected file (configs/ has no entry of its own)
                parent = '/'.join(parts[:depth])
                if parent not in out.names:
                    out.add_member(hacommon.info(parent, 'dir', mode=0o755, uid=0, gid=0, mtime=entry.mtime))
        if entry.kind == 'dir':
            if out is not None and rel not in out.names:
                out.add_member(hacommon.info(rel, 'dir', mode=0o755, uid=0, gid=0, mtime=entry.mtime))
            continue
        src.files += 1
        src.bytes += entry.size
        if rel == 'configs/cluster.hocon':
            data = entry.read_all(MAX_HOCON)
            src.hocon = data.decode('utf-8', 'replace')
            if out is not None:
                out.add_member(hacommon.info(rel, 'file', mode=0o644, uid=0, gid=0, mtime=entry.mtime, size=len(data)),
                               io.BytesIO(data))
            continue
        if out is not None:
            out.add_entry(rel, entry, mode=0o600 if parts[0] == 'certs' else 0o644, uid=0, gid=0)
    src.addon = report.addon
    return src


def node_name(src):
    """(HA's node name, None) or (None, zh-TW blocker)."""
    dirs = sorted(d for d in src.node_dirs if '@' in d)
    name = src.node_file or (dirs[0] if len(dirs) == 1 else None)
    if not dirs:
        return None, 'HA 備份裡沒有 EMQX 的內建資料庫（mnesia），可能從來沒有啟動過；沒有可搬的資料。'
    if name is None:
        return None, (f'HA 的 EMQX 有 {len(dirs)} 個內建資料庫（{hacommon.names(dirs, 3)}）且沒有記錄使用哪一個；'
                      '請先在 HA 設定 EMQX_NODE__NAME 選定後重新備份。')
    if not NODE_RE.fullmatch(name):
        return None, 'HA 的 EMQX 節點名稱格式不受支援。'
    if name not in dirs:
        return None, f'HA 的 EMQX 節點 {name} 沒有對應的內建資料庫。'
    return name, None


def hocon_notes(text):
    """Warnings about HA's cluster.hocon: HA-only hosts of connectors/bridges and files outside the data dir."""
    notes = []
    hosts = hacommon.ha_hosts(text)
    if hosts:
        notes.append(f'HA 的 EMQX 規則、連接器或橋接連到 HA 內部的位址（{hacommon.names(hosts, 8)}），這台連不到，'
                     '搬過來後請改成實際位址。')
    paths = sorted({m.group(0)[:80] for m in re.finditer(r'"(?:/ssl|/share|/config)/[^"\s]{1,200}"', text[:MAX_HOCON])})
    if paths:
        notes.append(f'HA 的 EMQX 設定引用了資料夾以外的檔案（{hacommon.names(paths, 3)}），這些檔案不會搬過來。')
    return notes


# ====================================================================== the live target

class Target:
    """The emqx app's catalog items the import fills, resolved against the live Quadlet files."""

    def __init__(self, work, app):
        quadlets = work.quadlets(app)
        home = work.runner(app).home
        declared = [v['name'] for v in app.volumes]
        broker, data_volume = hacommon.mounted(quadlets, home, DATA_TARGET)
        _b, log_volume = hacommon.mounted(quadlets, home, LOG_TARGET, files=[broker] if broker else None)
        if (broker is None or sorted(declared) != sorted({data_volume, log_volume} - {None}) or len(declared) != 2
                or app.postgres or app.data_dirs):
            raise BackupError('incompatible', '這台的 EMQX 應用設定和 Quadlet 檔不一致，無法匯入。', app=app.id)
        text = quadlets[broker]
        self.container = hacommon.quadlet_container_name(quadlets, broker)
        self.data_volume, self.log_volume = data_volume, log_volume
        self.image = tempctr.quadlet_image(text)
        if not self.image:
            raise BackupError('incompatible', '這台 EMQX 的 Quadlet 設定缺少映像。', app=app.id)
        keys = set(re.findall(r'(?m)^\s*Environment\s*=\s*"?(EMQX_[A-Z0-9_]{1,100})=',
                              text.decode('utf-8', 'replace') if isinstance(text, bytes) else str(text)))
        self.env = tempctr.quadlet_environment(text, keys)
        self.secrets = tempctr.quadlet_secrets(text)
        self.files = [(s, t, 'ro') for s, t, _o in ha_odoo.quadlet_mounts(quadlets, broker, home)
                      if s.startswith('/') and t not in (DATA_TARGET, LOG_TARGET)]
        self.node = self.env.get('EMQX_NODE__NAME', 'emqx@127.0.0.1')
        body = text.decode('utf-8', 'replace') if isinstance(text, bytes) else str(text)
        self.env_files = [value for key, value in tempctr.parse_unit(body).get('Container', [])
                          if key == 'EnvironmentFile']
        self._runner = work.runner(app)

    def candidate_env(self):
        """The environment this device's broker runs with, for the candidate: the Quadlet's `Environment=` EMQX_*
        settings plus those of its `EnvironmentFile=` files (podman --env-file: KEY=VALUE lines, values literal;
        dev-d's product package sets EMQX_LOG__CONSOLE__LEVEL there, 2026-11-23 attempt-06). Only plain values in the
        owner's home are supported; anything else refuses, naming the file. Values are never logged."""
        env = dict(self.env)
        for value in self.env_files:
            optional = value.startswith('-')
            path = value.lstrip('-')
            rel = path[3:] if path.startswith('%h/') else None
            if rel is None or not re.fullmatch(r'[A-Za-z0-9._/-]{1,200}', rel) or '..' in rel.split('/'):
                raise BackupError('incompatible', f'EMQX 不能搬過來：這台 EMQX 的 EnvironmentFile（{path[:120]}）不在'
                                                  '應用擁有者的家目錄下，尚未支援。')
            try:
                data = self._runner.read_file(rel, max_bytes=256 * 1024)
            except BackupError:
                if optional:
                    continue
                raise BackupError('incompatible', f'EMQX 不能搬過來：無法讀取這台 EMQX 的 EnvironmentFile（~/{rel}）。') from None
            for line in data.decode('utf-8', 'replace').splitlines():
                stripped = line.lstrip()   # podman trims leading blanks only; a trailing blank refuses below
                if not stripped.startswith('EMQX_'):
                    continue   # comments, blank lines, other programs' settings: not EMQX configuration
                match = ENV_FILE_LINE.fullmatch(stripped)
                if match is None or (match.group(1) in env and env[match.group(1)] != match.group(2)):
                    raise BackupError('incompatible', f'EMQX 不能搬過來：這台 EMQX 的 EnvironmentFile（~/{rel}）有無法安全'
                                                      '重現的 EMQX 設定（引號、跳脫字元、變數或重複的設定），尚未支援。')
                env[match.group(1)] = match.group(2)
        return env


# ====================================================================== the brokers

def ctl(tmp, role, args, *, timeout=600, check=True):
    return tmp.exec(role, ['emqx', 'ctl', *args], timeout=timeout, max_output=4 * 1024 * 1024, check=check)


def evaluate(tmp, role, expression):
    """`emqx eval` of a fixed expression; its printed value."""
    out = tmp.exec(role, ['emqx', 'eval', expression], timeout=300, max_output=4 * 1024 * 1024).stdout or b''
    return out.decode('utf-8', 'replace')


def quiesce_system_ticker(tmp, role):
    """Freeze status publication only in isolated job brokers during row validation.

    EMQX's ticker adds three retained $SYS records asynchronously. Suspending this
    process keeps all rows counted and imported without rewriting settings or
    ignoring any topic. Stopping/restarting the temporary broker ends the pause.
    """
    if role not in ('emqx-ha', 'emqx-new'):
        raise BackupError('internal-error', '只能暫停隔離匯入容器的系統訊息。')
    value = evaluate(tmp, role, SUSPEND_SYS_EXPR)
    match = re.fullmatch(r'WOOWSYS:(<[0-9]+\.[0-9]+\.[0-9]+>):suspended\s*(?:ok\s*)?', value)
    if not match:
        raise BackupError('job-failed', '無法暫停暫用 EMQX 的系統訊息，已停止。')
    return match.group(1)


def assert_system_ticker(tmp, role, pid):
    if role not in ('emqx-ha', 'emqx-new') or not re.fullmatch(r'<[0-9]+\.[0-9]+\.[0-9]+>', pid):
        raise BackupError('internal-error', '暫用 EMQX 的系統程序識別不正確。')
    if evaluate(tmp, role, TICKER_STATUS_EXPR.replace('{pid}', pid)).strip() != 'ticker_unchanged':
        raise BackupError('job-failed', '暫用 EMQX 的系統程序已改變，已停止。')


def wait_ready(tmp, role, *, checkpoint, hint='', sleep=time.sleep, clock=time.monotonic, timeout=READY_TIMEOUT):
    deadline = clock() + timeout
    while True:
        if checkpoint is not None:
            checkpoint()
        result = ctl(tmp, role, ['status'], timeout=60, check=False)
        if result.returncode == 0 and b'is started' in (result.stdout or b''):
            return
        if not tmp.running(role):
            raise BackupError('incompatible', '暫用的 EMQX 無法開啟這份資料（設定或資料可能不完整或不相容）。' + hint)
        if clock() > deadline:
            raise BackupError('incompatible', f'暫用的 EMQX 在 {timeout} 秒內沒有就緒。' + hint)
        sleep(2)


def hint_for(addon):
    """The advice for a failure on HA's data: a backup made while EMQX ran may hold a half-written database."""
    return HOT_HINT if addon is None or addon.state != 'stopped' else ''


def parse_counts(text):
    counts = {name: int(value) for name, value in re.findall(r'\{\s*([a-z_]+)\s*,\s*(-?[0-9]{1,12})\s*\}', text)
              if name in TABLES}
    if any(value < -1 for value in counts.values()):
        raise BackupError('job-failed', 'EMQX 資料筆數無法穩定讀取，已停止。')
    return counts


def parse_authn(text):
    rows = re.findall(r'\{\s*([a-z_]+)\s*,\s*([a-z_]+)\s*,\s*(true|false)\s*,\s*([a-z0-9_]+)\s*,'
                      r'\s*([a-z_]+)\s*\}', text)
    return [{'mechanism': m, 'backend': b, 'enable': e == 'true', 'algorithm': a, 'salt': s} for m, b, e, a, s in rows]


def parse_strict(text):
    match = re.search(r'\{\s*(allow|deny)\s*,\s*(ignore|disconnect)\s*\}', text)
    return (match.group(1), match.group(2)) if match else None


def ha_broker(work, tmp, target, src, node, *, out_dir=None):
    """Start HA's broker on its staged data; returns its readings (and, with `out_dir`, the export file's path in
    `out_dir`). The caller removes the objects. Anything that shows HA's database did not load completely -- the broker
    does not start, a table every 5.8.9 broker has is missing, EMQX's own export fails -- refuses the import with the
    advice to back up again with the add-on stopped: a result is never silently incomplete."""
    hint = hint_for(src.addon)
    host = node.split('@', 1)[1]
    hosts = [] if IPV4_RE.fullmatch(host) else [(host, '127.0.0.1')]
    # No cookie is set: the image's default only guards the distribution port inside a container without a network.
    # An empty default password: no Dashboard user is created at boot (emqx_dashboard_admin:add_default_user), so the
    # export holds HA's users only.
    # HA's cluster.hocon may name plugins and the folder they load from: EMQX 5.8.9 loads and starts every enabled
    # plugin at boot (emqx_plugins_app.erl:31-33, emqx_plugins.erl:310-321,1023-1066; `noexec` does not stop BEAM
    # loading), so a crafted backup staging one under certs/ ran its code here (security review SR-1, B1-06 port of
    # e848015). Environment overrides win over cluster.hocon: no plugin, the image's own empty plugin folder.
    env = {'EMQX_NODE__NAME': node, 'EMQX_NODE__DATA_DIR': HA_DATA_DIR, 'EMQX_DASHBOARD__DEFAULT_PASSWORD': '',
           'EMQX_PLUGINS__STATES': '[]', 'EMQX_PLUGINS__INSTALL_DIR': '/opt/emqx/plugins'}
    volumes = [(tmp.name('emqx-src'), HA_DATA_DIR, 'rw,noexec,nosuid,nodev')]
    if out_dir is not None:
        tmp.volume('emqx-xfer')
        tmp.volume_import('emqx-xfer', lambda out: _folder_tar(out, 'out', 0, 0))
        volumes.append((tmp.name('emqx-xfer'), WORK, 'rw,noexec,nosuid,nodev'))
    tmp.volume('emqx-ha-log')
    volumes.append((tmp.name('emqx-ha-log'), LOG_TARGET, 'rw,noexec,nosuid,nodev'))
    try:
        tmp.run('emqx-ha', target.image, [], detach=True, user='0', read_only_root=True, add_hosts=hosts, env=env,
                volumes=volumes)
    except BackupError as error:
        if error.code != 'job-failed':
            raise
        raise BackupError('incompatible', f'無法以 HA 的 EMQX 節點名稱 {node} 啟動暫用的 EMQX。') from None
    wait_ready(tmp, 'emqx-ha', checkpoint=work.checkpoint, hint=hint)
    ticker_pid = quiesce_system_ticker(tmp, 'emqx-ha')
    readings = {'default_admin': 'default' in evaluate(tmp, 'emqx-ha', DEFAULT_ADMIN_EXPR).split(),
                'counts': parse_counts(evaluate(tmp, 'emqx-ha', COUNT_EXPR)),
                'roots': set(re.findall(r'<<"([a-z_]+)">>', evaluate(tmp, 'emqx-ha', ROOTS_EXPR))),
                'authn': parse_authn(evaluate(tmp, 'emqx-ha', AUTHN_EXPR)),
                'strict': parse_strict(evaluate(tmp, 'emqx-ha', STRICT_EXPR))}
    if len(readings['counts']) != len(TABLES):
        raise BackupError('incompatible', '無法讀取 HA 的 EMQX 資料筆數。' + hint)
    missing = [t for t in REQUIRED_TABLES if readings['counts'].get(t, -1) < 0]
    if missing:
        raise BackupError('incompatible', f'HA 的 EMQX 內建資料庫沒有完整載入（缺少 {hacommon.names(missing)}）。' + hint)
    assert_system_ticker(tmp, 'emqx-ha', ticker_pid)
    if out_dir is not None:
        roots = [root for root in DATA_ROOTS if root in readings['roots']]
        out = ctl(tmp, 'emqx-ha', ['data', 'export', '--root-keys', ','.join(roots), '--table-sets',
                                   ','.join(TABLE_SETS), '--dir', f'{WORK}/out'], timeout=1800).stdout or b''
        match = EXPORT_RE.search(out)
        if not match:
            raise BackupError('incompatible', 'EMQX 無法匯出 HA 的資料。' + hint)
        readings['export'] = match.group(1).decode('ascii')
    assert_system_ticker(tmp, 'emqx-ha', ticker_pid)
    return readings


def _folder_tar(out, folder, uid, gid, files=()):
    """A tar of one folder (and `files` [(name, path)]) for `podman volume import`."""
    tar = tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT)
    tar.addfile(hacommon.info('.', 'dir', mode=0o755, uid=uid, gid=gid, mtime=time.time()))
    tar.addfile(hacommon.info(folder, 'dir', mode=0o755, uid=uid, gid=gid, mtime=time.time()))
    for name, path in files:
        with open(path, 'rb') as handle:
            tar.addfile(hacommon.info(f'{folder}/{name}', 'file', mode=0o644, uid=uid, gid=gid, mtime=time.time(),
                                      size=os.fstat(handle.fileno()).st_size), handle)
    tar.close()


def take_export(work, tmp, path, staging):
    """The export file out of the transfer volume (a strict, bounded read of `podman volume export`)."""
    xfer = staging / 'xfer.tar'
    with open(xfer, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        tmp.volume_export('emqx-xfer', handle, max_output=work.guard.budget())
    wanted = path[len(WORK) + 1:]
    dest = staging / os.path.basename(path)
    found = False
    try:
        with ha_odoo._live_tar(xfer, 'EMQX 的匯出資料') as tar:
            for member in tar:
                if ha_odoo._norm(member.name) == wanted and member.isfile() and member.size <= MAX_EXPORT:
                    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                    with os.fdopen(fd, 'wb') as out:
                        source = tar.extractfile(member)
                        while True:
                            data = source.read(habackup.CHUNK)
                            if not data:
                                break
                            out.write(data)
                    found = True
                tar.members.clear()
    except tarfile.TarError:
        raise BackupError('job-failed', 'EMQX 的匯出資料無法讀取。') from None
    os.unlink(xfer)
    if not found:
        raise BackupError('job-failed', '找不到 HA 的 EMQX 匯出資料。')
    return dest


def target_config_snapshot(volume_tar, snapshot_path, required, *, limit=MAX_HOCON, absent=()):
    """Stage named target config/ACL files from a volume export. Callers must enumerate effective references.

    This deliberately does not discover HOCON references or merge HA settings: the public import stays blocked until
    those operations and effective read-back are implemented. Missing, duplicate, linked or unsafe paths fail closed.
    """
    names = set(required)
    absent=set(absent)
    if absent - {'configs/cluster.hocon'} or absent - names:
        raise BackupError('incompatible', '不允許略過目標 EMQX 的必要設定參照。')
    if not names or 'configs/cluster.hocon' not in names:
        raise BackupError('incompatible', '缺少目標 EMQX 設定快照所需的檔案清單。')
    for name in names:
        if (not isinstance(name, str) or ha_odoo._norm(name) != name or
                not name.startswith(('configs/', 'authz/', 'certs/'))):
            raise BackupError('incompatible', '目標 EMQX 設定參照了不允許的路徑。')
    found, total = set(), 0
    out = hacommon.FileTar(snapshot_path)
    try:
        with ha_odoo._live_tar(volume_tar, '目標 EMQX 設定') as source:
            for member in source:
                name = ha_odoo._norm(member.name)
                if name is None:
                    raise BackupError('incompatible', '目標 EMQX 資料卷含有不安全的路徑。')
                if name in absent:
                    raise BackupError('incompatible', 'EMQX 原本不存在的覆寫檔於快照期間出現，已停止。')
                if any(required.startswith(name + '/') for required in names) and not member.isdir():
                    raise BackupError('incompatible', 'EMQX 設定檔的上層不是一般目錄，已停止。')
                if name in names:
                    if name in found or not member.isfile() or member.size < 0:
                        raise BackupError('incompatible', '目標 EMQX 設定檔重複或不是一般檔案。')
                    total += member.size
                    if total > limit:
                        raise BackupError('incompatible', '目標 EMQX 設定檔超過大小限制。')
                    info = ha_odoo._copy_info(member, name)
                    info.mode = 0o600
                    out.add_member(info, source.extractfile(member))
                    found.add(name)
                source.members.clear()
        if found != names - absent:
            raise BackupError('incompatible', '目標 EMQX 設定參照的檔案不存在，已停止。')
    except Exception:
        out.close()
        os.unlink(snapshot_path)
        raise
    else:
        out.close()
    return found


def authorization_file_references(authorization, mounts, *, include_cluster=True, observe=None, etc_dir=None):
    """Resolve an already-decoded effective authorization object; reject unsupported sources.

    This covers file ACL sources and exact raw builtin database source objects,
    not other EMQX configuration roots. Host paths are never read here. Exact
    existing read-only file mounts may satisfy an external reference. Builtin
    objects are checked without default expansion or unknown-field stripping.
    The vendor's own template `${EMQX_ETC_DIR}/acl.conf` (EMQX 5.8.9 resolves it with
    naive_env_interpolation: emqx_authz_file.erl:116-117, emqx_schema.erl:3466-3503) is
    accepted only when the caller proved `etc_dir` == ETC_DIR in the running broker
    (target_etc_dir); it must then be the same unique read-only mount as the plain path.
    """
    if not isinstance(authorization, dict) or not isinstance(authorization.get('sources'), list):
        raise BackupError('incompatible', '無法取得目標 EMQX 的有效授權來源。')
    references = {'configs/cluster.hocon'} if include_cluster else set()
    for source in authorization['sources']:
        if type(source) is dict and source.get('type') == 'built_in_database':
            from .ha_emqx_authorizers import builtin_database_references, builtin_database_shape
            if observe is not None:
                observe('target_references_builtin_'+builtin_database_shape(source))
            references.update(builtin_database_references(source))
            if observe is not None: observe('target_references')
            continue
        if not isinstance(source, dict) or source.get('type') != 'file':
            raise BackupError('incompatible', '目標 EMQX 使用尚未支援的授權來源。')
        path = source.get('path')
        if not isinstance(path, str) or not path or '\x00' in path:
            raise BackupError('incompatible', '目標 EMQX 的 ACL 路徑無效。')
        if path == ACL_TEMPLATE and etc_dir == ETC_DIR:
            path = ETC_DIR + '/acl.conf'   # resolved exactly as the broker does, then the same mount rule
        prefix = DATA_TARGET + '/'
        if path.startswith(prefix):
            relative = path[len(prefix):]
            if ha_odoo._norm(relative) != relative or not relative.startswith(('authz/', 'configs/', 'certs/')):
                raise BackupError('incompatible', '目標 EMQX 的 ACL 路徑不受支援。')
            references.add(relative)
        else:
            matches = [m for m in mounts if len(m) == 3 and m[1] == path and m[2] == 'ro']
            if (not path.startswith('/') or ha_odoo._norm(path[1:]) != path[1:] or len(matches) != 1
                    or not isinstance(matches[0][0], str) or not matches[0][0].startswith('/')):
                raise BackupError('incompatible', '目標 EMQX 的 ACL 未對應至唯一的唯讀掛載。')
    return references


def snapshot_target_volume(work, app, volume, staging, required, *, absent=()):
    """Export the target volume and stage only explicitly enumerated configuration references.

    A caller must first establish the complete effective reference list. This helper is not an
    authorization to import: the public preservation blocker remains in place.
    """
    raw = staging / 'emqx-target-config-source.tar'
    snapshot = staging / 'emqx-target-config-snapshot.tar'
    try:
        hacommon.live_export(work, app, volume, raw)
        target_config_snapshot(raw, snapshot, required, absent=absent)
    finally:
        if raw.exists():
            raw.unlink()
    return snapshot


def import_target_snapshot(tmp, snapshot_path, ids):
    """Seed private files AND writable parent directories for the verified image user.

    Podman otherwise creates implicit tar parents as root, preventing the broker from
    writing generated config even when cluster.hocon itself has the correct owner.
    """
    if len(ids) != 2 or any(type(value) is not int or value <= 0 for value in ids):
        raise BackupError('incompatible', '無法確認 EMQX 候選的檔案擁有者。')
    def produce(out):
        parents = {'.'}
        with tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT) as dest:
            dest.addfile(hacommon.info('.', 'dir', mode=0o700, uid=ids[0], gid=ids[1], mtime=0))
            with ha_odoo._live_tar(snapshot_path, '目標 EMQX 設定快照') as source:
                for member in source:
                    name = ha_odoo._norm(member.name)
                    if (not name or not member.isfile() or name != member.name or
                            not name.startswith(('configs/', 'authz/', 'certs/'))):
                        raise BackupError('incompatible', 'EMQX 設定快照含有不支援的項目。')
                    parts = name.split('/')
                    for depth in range(1, len(parts)):
                        parent = '/'.join(parts[:depth])
                        if parent not in parents:
                            dest.addfile(hacommon.info(parent, 'dir', mode=0o700, uid=ids[0], gid=ids[1], mtime=0))
                            parents.add(parent)
                    info = ha_odoo._copy_info(member, name)
                    info.uid, info.gid, info.mode = ids[0], ids[1], 0o600
                    info.uname = info.gname = ''
                    dest.addfile(info, source.extractfile(member))
    tmp.volume_import('emqx-new', produce)


# Fixed expression: no configuration or credential is interpolated into argv.
CONFIG_EXPR = ('io:format("WOOWCFG:~s:END~n", '
               '[base64:encode(emqx_utils_json:encode(emqx:get_raw_config([])))]).')
# The same configuration in the form a boot of the same files gives it. EMQX 5.8.9 stores
# fill_defaults_for_all_roots(...) as the raw configuration at boot (emqx_config.erl:341,345) but a change made at
# runtime (the Dashboard, the REST API, `conf load`) stores the new raw value without defaults: a built-in database
# source added in the Dashboard reads `max_rules` only after a restart. fill_defaults/1 (exported, :32, :487-505) is
# not idempotent on every root (`retainer`), so comparisons across a boot compare THIS form on both sides (boot_form).
BOOT_CONFIG_EXPR = ('io:format("WOOWCFG:~s:END~n", '
                    '[base64:encode(emqx_utils_json:encode(emqx_config:fill_defaults(emqx:get_raw_config([]))))]).')


def read_effective_config(execute, *, allow_authz_omission=False, _native_digest=None, _expr=CONFIG_EXPR):
    """Read merged RAW broker config, not cooked schema-expanded defaults.

    CONFIG_EXPR calls get_raw_config; retain every returned field unchanged so
    restricted source validators can reject unknown/expanded shapes. Never expose
    the body in errors.
    """
    try:
        if _expr not in (CONFIG_EXPR, BOOT_CONFIG_EXPR):
            raise ValueError()
        result = execute(['emqx', 'eval', _expr])
        body = result.stdout or b''
        if result.returncode or len(body) > MAX_HOCON or not body.startswith(b'WOOWCFG:'):
            raise ValueError()
        encoded, tail = body[8:].split(b':END', 1)
        if tail.strip() not in (b'', b'ok'):
            raise ValueError()
        native_json = base64.b64decode(encoded, validate=True)
        config = util.loads_strict(native_json, max_bytes=MAX_HOCON)
        if not isinstance(config, dict) or not config or not isinstance(config.get('authorization'), dict):
            raise ValueError()
        auth = config['authorization']
        if type(allow_authz_omission) is not bool:
            raise ValueError()
        for key, allowed in (('no_match', ('allow','deny')), ('deny_action', ('ignore','disconnect'))):
            if key not in auth and allow_authz_omission:
                continue
            if auth.get(key) not in allowed:
                raise ValueError()
        if _native_digest is not None:
            if type(_native_digest) is not list or _native_digest: raise ValueError()
            _native_digest.append(hashlib.sha256(native_json).hexdigest().upper())
        return config
    except (BackupError, ValueError, TypeError, RecursionError):
        raise BackupError('incompatible', '無法安全取得 EMQX 有效設定，已停止。') from None


def boot_form(execute):
    """A running broker's configuration as a boot of the same files gives it (BOOT_CONFIG_EXPR): compared on both sides
    wherever a boot stands between them (this device -> the candidate booted from its snapshot; the conversion's
    candidate -> the restored broker). Every other check keeps the plain raw configuration."""
    return read_effective_config(execute, _expr=BOOT_CONFIG_EXPR)


def bootstrap_references(config, mounts, secrets):
    """Only built-in password database bootstrap files from existing explicit mounts.

    Podman mounts secret payloads directly. Never export them into staging or evidence.
    Relative paths and environment interpolation are intentionally unsupported here.
    """
    authn = config.get('authentication', [])
    if not isinstance(authn, list):
        raise BackupError('incompatible', 'EMQX 帳號驗證設定格式不受支援。')
    paths = set()
    for authenticator in authn:
        if not isinstance(authenticator, dict):
            raise BackupError('incompatible', 'EMQX 帳號驗證設定格式不受支援。')
        path = authenticator.get('bootstrap_file', '')
        if path == '':
            continue
        if (authenticator.get('mechanism') != 'password_based' or
                authenticator.get('backend') != 'built_in_database' or
                authenticator.get('bootstrap_type', 'plain') not in ('plain', 'hash') or
                not isinstance(path, str) or not path.startswith('/') or
                ha_odoo._norm(path[1:]) != path[1:] or '$' in path):
            raise BackupError('incompatible', 'EMQX bootstrap 類型或路徑不受支援。')
        matches = 0
        for source, target, options in mounts:
            if target == path:
                if options != 'ro' or not source.startswith('/'):
                    raise BackupError('incompatible', 'EMQX bootstrap 必須使用既有唯讀掛載。')
                matches += 1
        for spec in secrets:
            parts = spec.split(',')
            if not tempctr.SECRET_NAME_RE.fullmatch(parts[0]):
                raise BackupError('incompatible', 'EMQX secret 宣告無效。')
            options = {}
            for part in parts[1:]:
                key, sep, value = part.partition('=')
                if not sep or key in options or not tempctr.SECRET_OPTION_RE.fullmatch(part):
                    raise BackupError('incompatible', 'EMQX secret 宣告無效或重複。')
                options[key] = value
            if options.get('target') != path:
                continue
            if options.get('type', 'mount') != 'mount' or options.get('mode') not in ('0400', '0440', '400', '440'):
                raise BackupError('incompatible', 'EMQX bootstrap secret 必須是限權檔案掛載。')
            matches += 1
        if matches != 1:
            raise BackupError('incompatible', 'EMQX bootstrap 未對應唯一的既有掛載。')
        paths.add(path)
    return paths


# EMQX v5.8.9: emqx_schema fields(alarm/trace), emqx_slow_subs_schema fields(slow_subs).
# These roots have no file dependencies. Reject additional fields rather than assuming that
# a future schema version shares that property.
FILELESS_ROOT_FIELDS = {
    'alarm': {'actions', 'size_limit', 'validity_period'},
    'slow_subs': {'enable', 'threshold', 'expire_interval', 'top_k_num', 'stats_type'},
    'trace': {'payload_encode'},
    'crl_cache': {'refresh_interval', 'http_timeout', 'capacity'},
    'telemetry': {'enable'},
    'delayed': {'enable', 'max_delayed_messages'},
    'overload_protection': {'enable', 'backoff_delay', 'backoff_gc', 'backoff_hibernation', 'backoff_new_conn'},
}


def validate_fileless_roots(config):
    for root, fields in FILELESS_ROOT_FIELDS.items():
        if root not in config:
            continue
        value = config[root]
        if not isinstance(value, dict) or set(value) - fields:
            raise BackupError('incompatible', 'EMQX 設定超出已核對版本的欄位範圍。')
        for key, item in value.items():
            if root == 'alarm' and key == 'actions':
                if not isinstance(item, list) or any(action not in ('log', 'publish') for action in item):
                    raise BackupError('incompatible', 'EMQX alarm actions 格式不受支援。')
            elif type(item) not in (str, int, bool):
                raise BackupError('incompatible', 'EMQX 無檔案設定欄位格式不受支援。')


SUPPORTED_CONFIGURATION_ROOTS = frozenset({
    'authorization', 'authentication', 'listeners', 'dashboard', 'mqtt', 'zones',
    'flapping_detect', 'force_shutdown', 'force_gc', 'conn_congestion', 'stats',
    'sys_topics', 'broker', 'retainer', *FILELESS_ROOT_FIELDS, *ha_emqx_settings.ROOTS,
    *ha_emqx_settings.PASSIVE_ROOTS, *ha_emqx_settings.MONITOR_ROOTS,
})


# Exact files named by emqx_schema:cert_file/2 in 5.8.9. Other substitutions are rejected.
IMAGE_TLS_FILES = {prefix + name: '/opt/emqx/etc/certs/' + name
                   for prefix in ('${EMQX_ETC_DIR}/certs/', '/opt/emqx/etc/certs/')
                   for name in ('cacert.pem', 'cert.pem', 'key.pem')}


def image_tls_references(config):
    paths = set()
    def visit(value, depth=0):
        if depth > 32:
            raise BackupError('incompatible', 'EMQX 設定巢狀層級超過限制。')
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ('certfile', 'keyfile', 'cacertfile', 'dhfile') and isinstance(item, str):
                    if item in IMAGE_TLS_FILES:
                        paths.add(IMAGE_TLS_FILES[item])
                visit(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                visit(item, depth + 1)
    visit(config)
    return paths


def tls_fingerprints(execute, paths):
    result = {}
    for path in sorted(paths):
        if path not in IMAGE_TLS_FILES.values():
            raise BackupError('incompatible', 'EMQX 映像憑證路徑不受支援。')
        response = execute(['sha256sum', path])
        raw = response.stdout or b''
        if response.returncode or len(raw) > 1024 or not re.fullmatch(
                rb'[0-9a-f]{64}  ' + re.escape(path.encode()) + rb'\n', raw):
            raise BackupError('incompatible', '無法核對 EMQX 映像憑證。')
        result[path] = raw[:64]
    return result


def configuration_references(config, mounts, secrets=(), *, include_cluster=True, observe=None, etc_dir=None):
    """Resolve file ACL and explicit TLS file fields in supported configuration roots.

    Unknown roots are rejected until their schema/file dependencies have been reviewed.
    This intentionally restrictive candidate is not a universal EMQX schema parser.
    """
    validate_fileless_roots(config)
    ha_emqx_settings.validate(config, mounts)
    ha_emqx_settings.validate_passive(config)
    ha_emqx_settings.validate_monitoring(config)
    if set(config) - SUPPORTED_CONFIGURATION_ROOTS:
        raise BackupError('incompatible', 'EMQX 含有尚未完成檔案參照審查的設定類型。')
    bootstrap_references(config, mounts, secrets)
    required = authorization_file_references(config['authorization'], mounts, include_cluster=False, observe=observe,
                                             etc_dir=etc_dir)
    for key in ('banned', 'api_key'):
        bootstrap_path = config.get(key, {}).get('bootstrap_file')
        if bootstrap_path:
            required.update(authorization_file_references(
                {'sources': [{'type': 'file', 'path': bootstrap_path}]}, mounts, include_cluster=False))
    def visit(value, depth=0):
        if depth > 32:
            raise BackupError('incompatible', 'EMQX 設定巢狀層級超過限制。')
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ('certfile', 'keyfile', 'cacertfile', 'dhfile') and item:
                    if isinstance(item, str) and item in IMAGE_TLS_FILES:
                        continue
                    required.update(authorization_file_references(
                        {'sources': [{'type': 'file', 'path': item}]}, mounts, include_cluster=False))
                elif key == 'bootstrap_file':
                    if not any(value is entry for entry in config.get('authentication', [])):
                        raise BackupError('incompatible', 'EMQX bootstrap 出現在不支援的設定位置。')
                elif key in ('filename', 'file', 'path'):
                    # ACL paths are already resolved, but resolving again keeps this walk uniform.
                    if key != 'path' or value.get('type') != 'file':
                        raise BackupError('incompatible', 'EMQX 含有尚未支援的檔案參照。')
                visit(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                visit(item, depth + 1)
    visit({key: value for key, value in config.items() if key not in ('node', 'cluster', 'log', 'banned', 'api_key')})
    return required | ({'configs/cluster.hocon'} if include_cluster else set())


OVERRIDE_STATE_EXPR = ('D=file:read_link_info("/opt/emqx/data/configs"), '
    'F=file:read_link_info("/opt/emqx/data/configs/cluster.hocon"), '
    'S=case {D,F} of {{error,enoent},{error,enoent}} -> <<"parent-absent">>; '
    '{{ok,Dir},{error,enoent}} when element(3,Dir)=:=directory -> <<"absent">>; '
    '{{ok,Dir},{ok,File}} when element(3,Dir)=:=directory, element(3,File)=:=regular, '
    'element(9,File)=:=1, element(2,File)=<8388608 -> <<"present">>; _ -> <<"refused">> end, '
    'io:format("WOOWOVERRIDE:~s:END",[S]).')


def target_override_state(execute):
    """Fixed no-follow metadata proof; never read or invent override contents."""
    result=execute(['emqx','eval',OVERRIDE_STATE_EXPR])
    raw=(result.stdout or b'').strip()
    if result.returncode==0:
        for state in ('present','absent','parent-absent'):
            if raw==b'WOOWOVERRIDE:'+state.encode()+b':ENDok':return state
    raise BackupError('incompatible', '無法驗證 EMQX 原始覆寫設定檔，已停止。')


def target_etc_dir(execute):
    """EMQX_ETC_DIR of a running broker (fixed eval, nothing interpolated). Only ETC_DIR is supported: the vendor
    resolves `${EMQX_ETC_DIR}` with os:getenv (emqx_schema.erl:3466-3503)."""
    result = execute(['emqx', 'eval', ETC_EXPR])
    raw = (result.stdout or b'').strip()
    if result.returncode == 0 and raw in (b'WOOWETC:' + ETC_DIR.encode() + b':ENDok', b'WOOWETC:' + ETC_DIR.encode() + b':END'):
        return ETC_DIR
    if result.returncode == 0 and raw.startswith(b'WOOWETC:') and len(raw) <= 4096:
        raise BackupError('incompatible', 'EMQX 不能搬過來：這台 EMQX 的設定目錄（EMQX_ETC_DIR）不是 /opt/emqx/etc，尚未支援。')
    raise BackupError('incompatible', '無法安全取得 EMQX 有效設定，已停止。')


def source_profile(config):
    """This device's authorization source combination: one of PROFILES (the order matters: EMQX asks the sources in
    turn), else a refusal that names the combination. Returns the source types, e.g. ('file', 'built_in_database')."""
    auth = config.get('authorization') if isinstance(config, dict) else None
    sources = auth.get('sources') if isinstance(auth, dict) else None
    kinds = None
    if isinstance(sources, list) and all(isinstance(s, dict) for s in sources):
        kinds = tuple((s.get('type'), s.get('enable', True)) for s in sources)
    if kinds in PROFILES:
        return PROFILES[kinds]
    names = []
    for kind, enable in kinds or ():
        name = SOURCE_NAMES.get(kind) if isinstance(kind, str) else None
        if name is None:
            name = kind if isinstance(kind, str) and re.fullmatch(r'[a-z_]{1,32}', kind) else '未知的來源'
        names.append(name + ('' if enable is True else '（停用）'))
    shown = '＋'.join(names) if names else '沒有任何來源'
    raise BackupError('incompatible', f'EMQX 不能搬過來：這台 EMQX 的授權來源組合（{shown}）還沒有經過驗證；'
                                      '目前只支援「ACL 檔案」或「ACL 檔案＋內建資料庫」。')


def target_running(work, app, target):
    result = work.runner(app).podman('container', 'inspect', '--format', '{{.State.Running}}', target.container,
                                     timeout=60, max_output=1024, check=False)
    return result.returncode == 0 and (result.stdout or b'').strip() == b'true'


def target_static(work, app, target, execute, *, observe=None):
    """The read-only part of this device's preflight, shared by the check and the conversion: the effective RAW
    configuration, its file references, the override state and the authorization profile. Every refusal names what is
    not supported; nothing is changed."""
    def stage(name):
        if observe is not None:observe(name)
    if (target.env.get('EMQX_LOG_DIR', LOG_TARGET) != LOG_TARGET or
            target.env.get('EMQX_ETC_DIR', ETC_DIR) != ETC_DIR):
        raise BackupError('incompatible', 'EMQX 自訂日誌目錄尚未支援。')
    stage('target_config')
    try:
        original=read_effective_config(execute)
    except BackupError:
        if not target_running(work, app, target):
            raise BackupError('incompatible', NOT_RUNNING) from None
        raise
    profile=source_profile(original)
    etc=target_etc_dir(execute)
    stage('target_references')
    explicit=configuration_references(original,target.files,target.secrets,include_cluster=False,observe=observe,
                                      etc_dir=etc)
    state=target_override_state(execute)
    return original,explicit,state,profile


def capture_target_seed(work, app, target, staging):
    """Exact product target preflight, including explicitly proven absence.

    A missing cluster override is permitted only when no effective dependency
    references it and no-follow metadata plus COMPLETE volume traversal prove
    its absence. No empty override file is fabricated. All other files remain
    mandatory; effective configuration/state are re-read before candidate boot.
    """
    observe=getattr(work,'_emqx_build_stage',None)
    def stage(name):
        if observe is not None:observe(name)
    def execute(command):
        return work.runner(app).podman('exec', target.container, *command, timeout=120,
                                      max_output=MAX_HOCON, check=False)
    original,explicit,state,_profile=target_static(work,app,target,execute,observe=observe)
    absent=({'configs/cluster.hocon'} if state in ('absent','parent-absent')
            and 'configs/cluster.hocon' not in explicit else set())
    required=explicit | {'configs/cluster.hocon'}
    stage('target_tls');fingerprints=tls_fingerprints(execute,image_tls_references(original))
    stage('target_snapshot')
    snapshot=snapshot_target_volume(work,app,target.data_volume,staging,required,absent=absent)
    stage('target_consistency')
    if target_override_state(execute)!=state or read_effective_config(execute)!=original:
        raise BackupError('incompatible', 'EMQX 設定於快照期間改變，已停止。')
    return original,snapshot,fingerprints


def candidate_from_target(work, app, tmp, target, staging, export, ids, *, hint=''):
    """This device's capture (capture_target_seed) and the candidate built from it: the public conversion's path."""
    original,snapshot,fingerprints=capture_target_seed(work,app,target,staging)
    # This device's configuration as its next boot will read it (a source added in the Dashboard since the last
    # restart reads its defaults only then): the candidate, booted from the snapshot, must equal THIS form.
    target_boot=boot_form(lambda command: work.runner(app).podman('exec', target.container, *command, timeout=120,
                                                                   max_output=MAX_HOCON, check=False))
    observe=getattr(work,'_emqx_build_stage',None)
    if observe is not None:observe('target_runtime')
    return target_broker(work,tmp,target,export,ids,hint=hint,
        target_snapshot=snapshot,target_config=original,image_fingerprints=fingerprints,target_boot=target_boot)

def candidate_with_effective_acl(work, app, tmp, target, staging, export, ids, authorization, *, hint=''):
    """Stage known file ACL references and seed a candidate; not a complete preservation check.

    The caller must obtain a trusted effective authorization object and independently account
    for references in every other configuration root before using this in a conversion.
    """
    required = authorization_file_references(authorization, target.files)
    snapshot = snapshot_target_volume(work, app, target.data_volume, staging, required)
    return target_broker(work, tmp, target, export, ids, hint=hint, target_snapshot=snapshot)


def preserved_settings(config):
    """Target operational settings stay; HA data roots migrate, except target authorization policy."""
    return {key: value for key, value in config.items()
            if key not in DATA_ROOTS or key == 'authorization'}


def preserved_bootstrap_authn(original, imported):
    """Retain only target bootstrap metadata; HA authenticator/hash and users remain authoritative."""
    targets = [row for row in original.get('authentication', []) if row.get('bootstrap_file')]
    if not targets:
        return None
    rows = imported.get('authentication')
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise BackupError('incompatible', 'EMQX 匯入後的認證器格式無法保留 bootstrap。')
    rows = [dict(row) for row in rows]
    def identity(row):
        return row.get('mechanism'), row.get('backend'), row.get('user_id_type', 'username')
    seen = set()
    for target in targets:
        key = identity(target)
        matches = [row for row in rows if identity(row) == key]
        if key in seen or len(matches) != 1 or matches[0].get('enable', True) is not True:
            raise BackupError('incompatible', 'EMQX 來源認證器無法唯一對應目標 bootstrap。')
        seen.add(key)
        row = matches[0]
        if (target.get('bootstrap_type', 'plain') == 'hash' and
                row.get('password_hash_algorithm') != target.get('password_hash_algorithm')):
            raise BackupError('incompatible', 'EMQX 來源雜湊設定與目標 bootstrap hash 不相容。')
        row['bootstrap_file'] = target['bootstrap_file']
        row['bootstrap_type'] = target.get('bootstrap_type', 'plain')
    return rows


def restore_target_settings(tmp, original, read_candidate, *, observe=None):
    """Replace changed target setting roots, not merge stale/imported fields into them.

    Roots absent on the target cannot be restored by guessing an empty/default value.
    Any such extra operational root remains a failure until removal is implemented.
    """
    before_digest=[]
    before = read_effective_config(read_candidate, allow_authz_omission=True,_native_digest=before_digest)
    expected = preserved_settings(original)
    actual = preserved_settings(before)
    if set(actual) - set(expected):
        raise BackupError('incompatible', 'EMQX 匯入新增了無法安全移除的目標設定，已停止。')
    changed = {key: value for key, value in expected.items() if key not in actual or actual[key] != value}
    authn = preserved_bootstrap_authn(original, before)
    if authn is not None and authn != before.get('authentication'):
        changed['authentication'] = authn
    if set(changed) & ha_emqx_settings.IMMUTABLE_ROOTS:
        raise BackupError('incompatible', 'EMQX 唯讀啟動設定在匯入後改變，已停止。')
    from .ha_emqx_acl_preservation import (disabled_intermediate, candidate_acl_receipt, refuse,
        imported_acl_profile_stage, uses_generated_acl_charlist)
    from .ha_emqx_acl_path_proof import observe_generated_path, verify_generated_path, disable_generated_path
    if observe is not None:
        observe('acl_profile')
        observe(imported_acl_profile_stage(before))
    path_proof=None
    original_sources=original['authorization'].get('sources')
    original_file_only=(type(original_sources) is list and original_sources
        and all(type(source) is dict and source.get('type')=='file' for source in original_sources))
    imported_sources=before['authorization'].get('sources')
    enabled_builtin=(type(imported_sources) is list and any(type(source) is dict
        and source.get('type')=='built_in_database' and source.get('enable') is True for source in imported_sources))
    if original_file_only and enabled_builtin and uses_generated_acl_charlist(before):
        if observe is not None: observe('acl_path_proof')
        path_proof=observe_generated_path(tmp,before,before_digest[0],observe=observe)
    # The capture proved ETC_DIR in this device's broker and target_broker in the candidate before this point.
    intermediate = disabled_intermediate(original, before, observe=observe,path_proof=path_proof,target_etc_dir=ETC_DIR)
    def load_settings(settings):
        snippet = json.dumps(settings, ensure_ascii=True).encode()
        try:
            written = tmp.exec('emqx-new', ['sh', '-c', f'umask 077; cat > {WORK}/in/target-settings.hocon'],
                               input=snippet, timeout=120, max_output=64 * 1024, check=False)
            if written.returncode:
                raise ValueError()
            loaded = ctl(tmp, 'emqx-new', ['conf', 'load', '--replace', f'{WORK}/in/target-settings.hocon'],
                         timeout=600, check=False)
            if loaded.returncode:
                raise ValueError()
        except (BackupError, ValueError):
            raise BackupError('incompatible', '無法恢復 EMQX 目標設定，已停止。') from None
    baseline = None
    if intermediate is not None:
        if observe is not None: observe('acl_baseline')
        baseline = candidate_acl_receipt(tmp)
        if read_effective_config(read_candidate, allow_authz_omission=True) != before:
            refuse()
        if observe is not None: observe('acl_disable')
        if uses_generated_acl_charlist(before):
            disable_generated_path(tmp,path_proof,observe=observe)
        else:
            load_settings({'authorization': intermediate['authorization']})
        if observe is not None: observe('acl_afterdisable')
        if (read_effective_config(read_candidate, allow_authz_omission=True) != intermediate
                or candidate_acl_receipt(tmp) != baseline
                or read_effective_config(read_candidate, allow_authz_omission=True) != intermediate):
            refuse()
        if path_proof is not None:
            if observe is not None: observe('acl_path_afterdisable')
            verify_generated_path(tmp,path_proof,observe=observe)
    if changed:
        if intermediate is not None and observe is not None: observe('acl_restore')
        load_settings(changed)
    if intermediate is not None and observe is not None: observe('acl_final')
    after_digest=[]
    after = read_effective_config(read_candidate,_native_digest=after_digest)
    if intermediate is not None:
        final_expected = dict(intermediate)
        final_expected.update(changed)
        if (after != final_expected or candidate_acl_receipt(tmp) != baseline
                or read_effective_config(read_candidate) != final_expected):
            refuse()
        if path_proof is not None:
            if observe is not None: observe('acl_path_final')
            verify_generated_path(tmp,path_proof,after_digest[0],observe=observe)
    if preserved_settings(after) != expected or (authn is not None and after.get('authentication') != authn):
        raise BackupError('incompatible', 'EMQX 匯入後未能保留目標有效設定，已停止。')


FILE_SECRET = ('EMQX 不能搬過來：HA 的 EMQX 設定（{roots}）用「file://」讀取本機檔案當作密碼；搬過來後這台的 EMQX 會讀取'
               '這台自己的檔案（例如 MQTT 帳號檔或環境變數）並送到這些設定指定的伺服器，為保護這台的機密已停止。'
               '請先在 HA 把這些密碼改成直接填寫，再重新備份後匯入。')


def file_secret_roots(config):
    """The roots HA's import brought (DATA_ROOTS except this device's authorization) holding a value that EMQX 5.8.9
    loads with its `file://` secret loader (emqx_schema_secret.erl:74-77, emqx_secret_loader.erl:28-45: the file is
    read on THIS device at use time, its path even env-interpolated). A migrated connector or authenticator would read
    this device's bootstrap credential mount or /proc/self/environ (its env secrets) and send it to the server HA's
    settings name (security review SR-3, 2026-11-23). Conservative: any string or ASCII charlist that starts with
    `file://` after leading blanks, any case."""
    found = set()

    def text(value):
        if isinstance(value, str):
            return value
        if (isinstance(value, list) and value and len(value) <= 4096
                and all(type(v) is int and 0 < v < 128 for v in value)):
            return ''.join(map(chr, value))
        return None

    def visit(root, value, depth=0):
        if depth > 64:
            found.add(root)
            return
        candidate = text(value)
        if candidate is not None:
            if candidate.lstrip().lower().startswith('file://'):
                found.add(root)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                visit(root, key, depth + 1)
                visit(root, item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                visit(root, item, depth + 1)

    for root in DATA_ROOTS:
        if root != 'authorization' and root in config:
            visit(root, config[root])
    return sorted(found)


JQ_RULE = ('EMQX 不能搬過來：HA 的 EMQX 規則（{count} 條）使用 jq 函式；EMQX 的 jq 能讀取這台 EMQX 的環境變數（其中有 Dashboard '
           '密碼與節點 cookie 等機密），搬過來的規則可以把它們發布或送出去，為保護這台的機密已停止。'
           '請先在 HA 移除或改寫這些規則，再重新備份後匯入。')
JQ_CALL = re.compile(r'(?<![A-Za-z0-9_])jq(?![A-Za-z0-9_])', re.IGNORECASE)


def jq_rule_count(config):
    """How many migrated rules name EMQX's jq function. jq runs with the broker's process environment
    (emqx_rule_funcs.erl:957-980 -> jq:process_json; jq('env'), jq('$ENV'), jq('env.NAME') return it, proven in a
    throwaway 5.8.9 broker), i.e. this device's env secrets, and its program may even come from a message at run
    time, so any use counts (security review SR-6, 2026-11-23). Every string under rule_engine is scanned."""
    rules = config.get('rule_engine')
    if not isinstance(rules, dict):
        return 0
    found = set()

    def visit(path, value, depth=0):
        if depth > 64:
            found.add(path[:1])
            return
        if isinstance(value, str) or (isinstance(value, list) and value and len(value) <= 65536
                                      and all(type(v) is int and 0 < v < 0x110000 for v in value)):
            text = value if isinstance(value, str) else ''.join(map(chr, value))
            if JQ_CALL.search(text):
                found.add(path[:2])
            return
        if isinstance(value, dict):
            for key, item in value.items():
                visit(path + (str(key)[:200],), item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                visit(path, item, depth + 1)

    visit((), rules)
    return len(found)


CREDENTIAL_RECEIVER = ('EMQX 不能搬過來：HA 的 EMQX 設定有{what}，它會收到每個連線用戶端的帳號與密碼（包括這台自己服務的帳號）；'
                       '搬過來會把這台的帳號密碼送到 HA 設定的伺服器，為保護這台的帳號已停止。'
                       '目前只支援「內建資料庫」帳號驗證，且不能有啟用的 ExHook；請先在 HA 移除或停用它們，再重新備份後匯入。')
BUILTIN_AUTHN = frozenset({('password_based', 'built_in_database'), ('scram', 'built_in_database')})
AUTHN_NAMES = {'http': 'HTTP', 'mysql': 'MySQL', 'postgresql': 'PostgreSQL', 'redis': 'Redis', 'mongodb': 'MongoDB',
               'ldap': 'LDAP', 'jwt': 'JWT', 'cinfo': '用戶端資訊', 'gcp_device': 'GCP 裝置', 'kerberos': 'Kerberos'}


def credential_receivers(config):
    """What the settings HA's import brought would hand client credentials to: an enabled authenticator that is not
    the built-in database (an HTTP one posts `${password}`, JWT/LDAP/SQL/Redis ones query outside), or an enabled
    ExHook server (its client.authenticate hook carries the password: emqx_exhook_handler.erl:104,318-333). This
    device's own services log in through the same chain with the bootstrap users' passwords (security review SR-7,
    2026-11-23). Returns display names, [] when only built-in database authenticators and no ExHook remain."""
    found = []
    authn = config.get('authentication', [])
    names = set()
    for authenticator in authn if isinstance(authn, list) else [None]:
        if not isinstance(authenticator, dict):
            names.add('未知的帳號驗證')
            continue
        if authenticator.get('enable', True) is False:
            continue
        kind = (authenticator.get('mechanism'), authenticator.get('backend'))
        if kind not in BUILTIN_AUTHN:
            raw = kind[1] if isinstance(kind[1], str) else kind[0]
            names.add(AUTHN_NAMES.get(raw) or (raw if isinstance(raw, str) and re.fullmatch(r'[a-z_]{1,32}', raw)
                                                else '未知的帳號驗證'))
    if names:
        found.append('外部帳號驗證（' + '、'.join(sorted(names)) + '）')
    exhook = config.get('exhook')
    servers = exhook.get('servers', []) if isinstance(exhook, dict) else []
    if not isinstance(servers, list) or any(not isinstance(server, dict) or server.get('enable', True) is not False
                                            for server in servers):
        found.append('ExHook')
    return found


SNAPSHOT_CHANGED = ('EMQX 不能搬過來：這台 EMQX 的 ACL 或憑證檔案放在資料卷裡（例如在 Dashboard 編輯過授權規則），'
                    '匯入 HA 的資料會改寫這個檔案；為避免改變這台的存取權限，已停止。')


def snapshot_file_digests(snapshot_path):
    """{name: sha256 hex} of the target snapshot's data-volume files except the override file (EMQX rewrites
    configs/cluster.hocon on every settings change; every other one must reach the candidate byte for byte)."""
    digests = {}
    with ha_odoo._live_tar(snapshot_path, '目標 EMQX 設定快照') as source:
        for member in source:
            name = ha_odoo._norm(member.name)
            if name and member.isfile() and name != 'configs/cluster.hocon':
                digest = hashlib.sha256()
                handle = source.extractfile(member)
                for chunk in iter(lambda: handle.read(habackup.CHUNK), b''):
                    digest.update(chunk)
                digests[name] = digest.hexdigest()
            source.members.clear()
    return digests


def check_snapshot_files(read_candidate, digests):
    """Every data-volume file this device's effective configuration names (its ACL, certificates, ...) must be
    byte-identical in the finished candidate. HA's export inlines HA's file ACL and the import writes it to
    <data_dir>/authz/acl.conf (EMQX 5.8.9 emqx_authz_file.erl:64-75,120-121), which IS this device's ACL once the
    Dashboard edited it: the settings come back with the same path, so only the content shows the change (security
    review SR-2, 2026-11-23). Digests only; contents never leave the candidate."""
    for name, want in sorted(digests.items()):
        path = f'{DATA_TARGET}/{name}'
        result = read_candidate(['sha256sum', path])
        raw = result.stdout or b''
        if (result.returncode or len(raw) > 4096
                or not re.fullmatch(rb'[0-9a-f]{64}  ' + re.escape(path.encode()) + rb'\n', raw)
                or raw[:64].decode('ascii') != want):
            raise BackupError('incompatible', SNAPSHOT_CHANGED)


def check_candidate_bootstrap(tmp, target, config):
    paths = bootstrap_references(config, target.files, target.secrets)
    for key in ('banned', 'api_key'):
        path = config.get(key, {}).get('bootstrap_file')
        if path:
            authorization_file_references({'sources': [{'type': 'file', 'path': path}]}, target.files)
            paths.add(path)
    for path in sorted(paths):
        checked = tmp.exec('emqx-new', ['test', '-f', path, '-a', '-r', path],
                           timeout=30, max_output=1024, check=False)
        if checked.returncode:
            raise BackupError('incompatible', 'EMQX 候選無法讀取 bootstrap 掛載，已停止。')


def target_broker(work, tmp, target, export, ids, *, hint='', target_snapshot=None, target_config=None,
                  image_fingerprints=None, target_boot=None):
    """This device's broker on an empty volume: import HA's export, load the strict settings back, verify.

    `target_boot`: this device's configuration in its boot form (boot_form); the candidate, just booted from the
    snapshot, must equal it. Without it the plain raw configuration must be equal (callers that read no boot form)."""
    name = os.path.basename(export)
    snapshot_digests = snapshot_file_digests(target_snapshot) if target_snapshot is not None else None
    tmp.volume('emqx-in')
    tmp.volume_import('emqx-in', lambda out: _folder_tar(out, 'in', ids[0], ids[1], [(name, export)]))
    tmp.volume('emqx-new')
    if target_snapshot is not None:
        import_target_snapshot(tmp, target_snapshot, ids)
    tmp.volume('emqx-new-log')
    # The product's Target adds its EnvironmentFile= settings; internal callers' target objects carry their env as given.
    env = target.candidate_env() if isinstance(target, Target) else target.env
    tmp.run('emqx-new', target.image, [], detach=True, read_only_root=True, env=env, secrets=target.secrets,
            volumes=[(tmp.name('emqx-new'), DATA_TARGET, None), (tmp.name('emqx-new-log'), LOG_TARGET, None),
                     (tmp.name('emqx-in'), WORK, None)] + target.files)
    wait_ready(tmp, 'emqx-new', checkpoint=work.checkpoint)
    ticker_pid = quiesce_system_ticker(tmp, 'emqx-new')
    read_candidate = lambda command: tmp.exec('emqx-new', command, timeout=120,
                                               max_output=MAX_HOCON, check=False)
    if image_fingerprints is not None and tls_fingerprints(read_candidate, image_fingerprints) != image_fingerprints:
        raise BackupError('incompatible', 'EMQX 候選憑證與目標不一致，已停止。')
    if target_config is not None:
        if target_etc_dir(read_candidate) != ETC_DIR:
            raise BackupError('incompatible', 'EMQX 候選啟動後設定與目標不一致，已停止。')
        want = target_boot if target_boot is not None else target_config
        got = boot_form(read_candidate) if target_boot is not None else read_effective_config(read_candidate)
        differ = sorted(root for root in set(want) | set(got) if want.get(root) != got.get(root))
        if differ:   # root names only (schema keys), never values
            raise BackupError('incompatible', f'EMQX 候選啟動後設定與目標不一致（{hacommon.names(differ, 8)}），已停止。')
    if target_config is not None:
        check_candidate_bootstrap(tmp, target, target_config)
    seeded = parse_counts(evaluate(tmp, 'emqx-new', COUNT_EXPR))
    strict = parse_strict(evaluate(tmp, 'emqx-new', STRICT_EXPR))
    authn = parse_authn(evaluate(tmp, 'emqx-new', AUTHN_EXPR))
    if strict is None or len(seeded) != len(TABLES) or not authn:
        raise BackupError('job-failed', '無法讀取這台 EMQX 的設定。')
    assert_system_ticker(tmp, 'emqx-new', ticker_pid)
    work.log('把 HA 的 EMQX 資料匯入暫用的 EMQX（這台的映像與設定）')
    out = ctl(tmp, 'emqx-new', ['data', 'import', f'{WORK}/in/{name}'], timeout=1800).stdout or b''
    if b'imported successfully' not in out:
        raise BackupError('incompatible', 'HA 的 EMQX 資料匯入時發生錯誤（部分資料無法匯入），已停止。' + hint)
    if target_config is not None:
        restore_target_settings(tmp, target_config, read_candidate,
                                observe=getattr(work, '_emqx_build_stage', None))
        if image_fingerprints is not None and tls_fingerprints(read_candidate, image_fingerprints) != image_fingerprints:
            raise BackupError('incompatible', 'EMQX 匯入後憑證與目標不一致，已停止。')
        if snapshot_digests:   # after every settings change; the remaining checks only read
            check_snapshot_files(read_candidate, snapshot_digests)
        final = read_effective_config(read_candidate)
        roots = file_secret_roots(final)
        if roots:
            raise BackupError('incompatible', FILE_SECRET.format(roots=hacommon.names(roots)))
        count = jq_rule_count(final)
        if count:
            raise BackupError('incompatible', JQ_RULE.format(count=count))
        receivers = credential_receivers(final)
        if receivers:
            raise BackupError('incompatible', CREDENTIAL_RECEIVER.format(what='、'.join(receivers)))
        check_candidate_bootstrap(tmp, target, final)
    else:
        # Legacy internal test path only; public convert remains blocked.
        snippet = f'authorization {{\n  no_match = {strict[0]}\n  deny_action = {strict[1]}\n  sources = []\n}}\n'.encode()
        tmp.exec('emqx-new', ['sh', '-c', f'umask 077; cat > {WORK}/in/strict.hocon'], input=snippet,
                 timeout=120, max_output=64 * 1024)
        ctl(tmp, 'emqx-new', ['conf', 'load', '--merge', f'{WORK}/in/strict.hocon'], timeout=600)
    after = parse_strict(evaluate(tmp, 'emqx-new', STRICT_EXPR))
    if after != strict:
        raise BackupError('job-failed', '無法恢復這台 EMQX 的存取政策（未符合規則的主題拒絕），已停止。')
    after_authn = parse_authn(evaluate(tmp, 'emqx-new', AUTHN_EXPR))
    if not after_authn:
        raise BackupError('job-failed', '無法確認匯入後的 EMQX 帳號驗證設定，已停止。')
    enabled = [a for a in after_authn if a['enable']]
    if any(a['enable'] for a in authn) and not enabled:
        raise BackupError('incompatible', 'HA 的 EMQX 設定會停用這台的帳號驗證（允許匿名登入），已停止；請先在 HA 啟用帳號驗證再備份。')
    counts = parse_counts(evaluate(tmp, 'emqx-new', COUNT_EXPR))
    assert_system_ticker(tmp, 'emqx-new', ticker_pid)
    return seeded, counts, strict, authn


def check_counts(ha, seeded, counts, *, observe=None):
    """Tables where the import lost or invented rows (HA's rows must all be there, at most plus the seed)."""
    problems = []
    for table in TABLES:
        mine, theirs, seed = counts.get(table, -1), ha.get(table, -1), max(seeded.get(table, 0), 0)
        if theirs < 0:
            continue
        if not theirs <= mine <= theirs + seed:
            if observe is not None:
                observe(table, 'underflow' if mine < theirs else 'overflow')
            problems.append(f'{table}（HA {theirs}，匯入後 {mine}）')
    return problems


def data_volume(src_path, out):
    """woow_emqx_data from the broker's volume export without generated configs, cluster.hocon backups, exports and
    traces."""
    return hacommon.copy_live(src_path, out, drop=lambda name: DROPPED.fullmatch(name) is not None,
                              what='暫用 EMQX 的資料卷')


# ====================================================================== readback after the restore

READBACK_KIND = 'emqx-readback'
READBACK_VERSION = 1
# The tables only an administrator changes (clients, expiry and the broker itself move the retained messages and the
# banned list at any time; those are counted by the conversion, never compared after the restore).
STABLE_TABLES = ('emqx_authn_mnesia', 'emqx_authn_scram_mnesia', 'emqx_acl', 'emqx_admin', 'emqx_app', 'emqx_psk',
                 'emqx_banned_rules')
# Fixed expression, one read-locked transaction per table: the row count and the SHA-256 of the sorted SHA-256s of the
# rows' external terms (order independent). A table this broker does not have answers -1. Values never leave it.
TABLES_RECEIPT_EXPR = ' '.join(('''
try
 <<"5.8.9">> = iolist_to_binary(emqx_release:version()),
 One = fun(T) ->
   case catch mnesia:table_info(T, size) of
     N0 when is_integer(N0) ->
       {atomic, {N, H}} = mnesia:transaction(fun() ->
           ok = mnesia:read_lock_table(T),
           {K, Hs} = mnesia:foldl(fun(Row, {C, Acc}) -> {C + 1, [crypto:hash(sha256, term_to_binary(Row)) | Acc]} end,
                                  {0, []}, T),
           K = mnesia:table_info(T, size),
           {K, crypto:hash(sha256, term_to_binary(lists:sort(Hs)))}
         end),
       io_lib:format("~s:~B:~s;", [T, N, binary:encode_hex(H)]);
     _ -> io_lib:format("~s:-1:-;", [T])
   end
 end,
 io:format("WOOWTAB:~s:END", [lists:flatten([One(T) || T <- [''' + ', '.join(STABLE_TABLES) + ''']])])
catch _:_ -> io:put_chars("WOOWTAB:REFUSED") end.
''').split())
RECEIPT_RE = re.compile(rb'WOOWTAB:((?:[a-z_]{1,64}:(?:-1:-|[0-9]{1,10}:[0-9A-F]{64});){1,32}):END(?:ok)?')


def table_receipts(execute):
    """{table: [rows, sha256 hex lowercase | None]} of STABLE_TABLES, from one fixed `emqx eval`."""
    result = execute(['emqx', 'eval', TABLES_RECEIPT_EXPR])
    raw = (result.stdout or b'').strip()
    match = RECEIPT_RE.fullmatch(raw) if result.returncode == 0 and len(raw) <= 16384 else None
    if match is None:
        raise BackupError('job-failed', '無法讀取 EMQX 內建資料庫的核對資料，已停止。')
    found = {}
    for item in match[1].decode('ascii').split(';')[:-1]:
        name, rows, digest = item.split(':')
        found[name] = [int(rows), None if digest == '-' else digest.lower()]
    if set(found) != set(STABLE_TABLES):
        raise BackupError('job-failed', '無法讀取 EMQX 內建資料庫的核對資料，已停止。')
    return found


# Security review SR-4 (2026-11-23): the RAW configuration also holds this device's own secrets that a converted
# backup does not otherwise carry (dashboard.default_password and node.cookie come from the environment, a 5.8.9 broker
# answers them in emqx:get_raw_config/1). The readback travels in the converted backup, so before hashing every value
# under a secret-named key, every HTTP header value and the user part of a URL become one fixed marker (both sides:
# the conversion and verify_restored); a changed secret is then not compared, every other value still is.
SECRET_WORDS = ('password', 'passwd', 'secret', 'cookie', 'token', 'key')
REDACTED = '<redacted>'
URL_USER_RE = re.compile(r'(?<=//)[^/@\s]+@')


def _secret_name(name):
    return isinstance(name, str) and any(word in name.lower() for word in SECRET_WORDS)


def redacted(value, secret=False, everything=False):
    """`value` with its secret leaves replaced by REDACTED: a scalar under a secret-named key (also inside a list
    there), every scalar below a `headers` key, the user part of `scheme://user[:password]@host`. Containers stay; below
    a secret-named key a map's own keys decide again (e.g. password_hash_algorithm.name is still compared)."""
    if isinstance(value, dict):
        return {key: redacted(item, everything or _secret_name(key), everything or key == 'headers')
                for key, item in value.items()}
    if isinstance(value, list):
        return [redacted(item, secret, everything) for item in value]
    if secret or everything:
        return REDACTED
    if isinstance(value, str) and '@' in value:
        return URL_USER_RE.sub(REDACTED + '@', value)
    return value


def config_roots(config):
    """{root: sha256 hex} of an effective RAW configuration (canonical JSON per root: key order never matters, list
    order does), secrets redacted first (SR-4). Derived from what the backup itself holds; never logged."""
    return {root: hashlib.sha256(json.dumps(redacted(value), sort_keys=True, ensure_ascii=True,
                                            separators=(',', ':')).encode('ascii')).hexdigest()
            for root, value in config.items()}


def readback_record(config, tables):
    return {'kind': READBACK_KIND, 'version': READBACK_VERSION, 'config_roots': config_roots(config), 'tables': tables}


def candidate_readback(tmp):
    """(readback record, authorization profile) of the finished candidate: read after this device's settings came back
    and its rows were counted; the profile is this device's again (restore_target_settings proved it)."""
    read = lambda command: tmp.exec('emqx-new', command, timeout=120, max_output=MAX_HOCON, check=False)
    config = read_effective_config(read)
    # The restored broker reads these settings at its boot: the record holds their boot form (boot_form).
    return readback_record(boot_form(read), table_receipts(read)), source_profile(config)


def compare_readback(expected, actual):
    """What differs between two readback records, as names only (roots, tables); [] when equal."""
    problems = []
    want, have = expected.get('config_roots') or {}, actual.get('config_roots') or {}
    roots = sorted(name for name in set(want) | set(have) if want.get(name) != have.get(name))
    if roots:
        problems.append(f'設定（{hacommon.names(roots, 8)}）')
    want, have = expected.get('tables') or {}, actual.get('tables') or {}
    tables = sorted(name for name in set(want) | set(have) if want.get(name) != have.get(name))
    if tables:
        problems.append(f'內建資料庫（{hacommon.names(tables, 8)}）')
    return problems


def wait_live_ready(execute, *, sleep=time.sleep, clock=time.monotonic, timeout=READY_TIMEOUT):
    deadline = clock() + timeout
    while True:
        try:
            result = execute(['emqx', 'ctl', 'status'])
            if result.returncode == 0 and b'is started' in (result.stdout or b''):
                return
        except BackupError:
            pass   # a timed-out probe is "not ready yet"; the deadline still holds
        if clock() >= deadline:
            raise BackupError('job-failed', f'還原後的 EMQX 在 {timeout} 秒內沒有啟動完成，已停止。')
        sleep(2)


def verify_restored(adapter, app, check, *, log, sleep=time.sleep, clock=time.monotonic):
    """After a restore of a converted backup started the units: the restored broker must hold exactly the readback the
    conversion verified (every configuration root, this device's authorization among them, and the administrator
    tables). Raises BackupError (the restore then rolls back by itself); logs one line when everything is equal."""
    if (not isinstance(check, dict) or check.get('kind') != READBACK_KIND
            or check.get('version') != READBACK_VERSION):
        raise BackupError('incompatible', '這份備份的 EMQX 核對資料格式不受支援，無法還原。', app=app.id)
    quadlets = adapter.read_quadlets()
    shim = type('LiveWork', (), {'quadlets': lambda self, _app: quadlets, 'runner': lambda self, _app: adapter.runner})()
    target = Target(shim, app)

    def execute(command):
        return adapter.runner.podman('exec', target.container, *command, timeout=120, max_output=MAX_HOCON,
                                     check=False)
    wait_live_ready(execute, sleep=sleep, clock=clock)
    actual = readback_record(boot_form(execute), table_receipts(execute))
    problems = compare_readback(check, actual)
    if problems:
        raise BackupError('job-failed', f'EMQX 還原後的{"、".join(problems)}和轉換時核對的不同，已停止；'
                                        '通常是轉換之後這台 EMQX 的設定改過，請重新檢查與轉換後再還原。', app=app.id)
    log('EMQX 還原後核對一致：設定（含授權來源、ACL 檔案路徑、節點與叢集）和內建資料庫的帳號與 ACL 規則都和轉換時相同')


# ====================================================================== analysis

def acl_blocker(readings, profile):
    """OWNER DECISION 2026-11-23 「C」: HA's ACL rows live in the built-in database (emqx_acl); this device's
    authorization sources stay as they are (restore_target_settings) and the import never adds or changes a source
    itself. Without an enabled built-in database source the rows would never be asked (EMQX asks only the configured
    sources, emqx_authz.erl), so HA's devices would be denied: a backup with ACL rows is refused, at the check and again
    in the conversion before anything is built. None when `profile` is unknown (that refusal is a blocker of its own),
    holds the built-in database, or HA has no ACL rows."""
    rows = ((readings or {}).get('counts') or {}).get('emqx_acl', 0)
    if profile is None or 'built_in_database' in profile or type(rows) is not int or rows <= 0:
        return None
    return ACL_NEEDS_BUILTIN


def _source_analysis(src, readings, *, addon_version, version, live_authn=None):
    blockers, warnings = [], []
    blocker = VERSIONS.blocker(addon_version, version)
    if blocker:
        blockers.append(blocker)
    if readings is not None:
        if readings['default_admin']:
            blockers.append('HA 的 EMQX Dashboard 仍在使用預設帳號密碼（admin／public），搬過來會讓這台的 Dashboard 也用這組密碼；'
                            '請先在 HA 修改密碼後再備份。')
        if not any(a['enable'] for a in readings['authn']):
            warnings.append('HA 的 EMQX 允許匿名連線；這台不允許，HA 上沒有帳號的裝置搬過來後需要建立 MQTT 帳號。')
        if readings['strict'] and readings['strict'][0] == 'allow':
            warnings.append('HA 的 EMQX 允許未符合規則的主題；這台會拒絕，搬過來後請確認 ACL 規則涵蓋裝置使用的主題。')
        if hash_differs(readings['authn'], live_authn):
            warnings.append('HA 的 MQTT 帳號驗證使用不同的密碼雜湊方式，搬過來後以 HA 的設定為準，這台原本的 MQTT 帳號可能無法登入。')
        if readings['counts'].get('emqx_app', 0) > 0:
            warnings.append('HA 的 EMQX API 金鑰會取代這台的，EMQX MCP 管理需要重新登入。')
    warnings += hocon_notes(src.hocon)
    if src.plugins:
        warnings.append(f'HA 的 EMQX 外掛（{hacommon.names(sorted(src.plugins))}）不會搬過來，需要時請在這台重新安裝。')
    if hint_for(src.addon):
        warnings.append('這份 HA 備份是在 EMQX 執行中製作的；最近的變更可能還沒寫進內建資料庫。最可靠的做法是先在 HA 停止 EMQX '
                        '附加元件再製作備份。')
    return blockers, warnings


def analyse(src, readings, *, addon_version, version, live_authn=None, profile=None):
    """The check's blockers and warnings. `profile`: this device's authorization sources (target_static), or None when
    they could not be read (that refusal is a blocker of its own)."""
    blockers, warnings = _source_analysis(src, readings, addon_version=addon_version,
                                          version=version, live_authn=live_authn)
    blocker = acl_blocker(readings, profile)
    if blocker:
        blockers.append(blocker)
    return blockers, warnings


def hash_differs(ha_authn, live_authn):
    """True when an authenticator both sides have (mechanism, backend) hashes passwords differently."""
    mine = {(a['mechanism'], a['backend']): a for a in ha_authn}
    for row in live_authn or []:
        other = mine.get((row['mechanism'], row['backend']))
        if other and (other['algorithm'], other['salt']) != (row['algorithm'], row['salt']):
            return True
    return False


def section(src, node, readings, *, version, profile=None):
    counts = (readings or {}).get('counts') or {}

    def rows(*tables):
        return sum(max(counts.get(t, 0), 0) for t in tables)

    return {'emqx_version': VERSIONS.upstream(src.addon.version) if src.addon else '', 'target_version': version or '',
            'node_name': node or '', 'files': src.files, 'bytes': src.bytes,
            'mqtt_users': rows('emqx_authn_mnesia', 'emqx_authn_scram_mnesia'), 'acl_rules': rows('emqx_acl'),
            'dashboard_users': rows('emqx_admin'), 'api_keys': rows('emqx_app'),
            'banned': rows('emqx_banned', 'emqx_banned_rules'), 'psk': rows('emqx_psk'),
            'retained_messages': rows('emqx_retainer_message'),
            'default_dashboard_password': bool((readings or {}).get('default_admin')),
            'anonymous': readings is not None and not any(a['enable'] for a in readings['authn']),
            'hot_backup': bool(hint_for(src.addon)), 'plugins': sorted(src.plugins),
            'ha_hosts': hacommon.ha_hosts(src.hocon)[:20], 'target_authorization': list(profile or ())}


# ====================================================================== the job steps

def _prepare(work, app):
    target = Target(work, app)
    version = hacommon.semver(hacommon.image_labels(work, app, target.image).get('org.opencontainers.image.version'))
    return target, version


def member_pass(work, tmp):
    member = work.addon_member(SLUG)
    report = habackup.Report()
    holder = {}

    def produce(out):
        tar = tarfile.open(fileobj=out, mode='w|', format=tarfile.PAX_FORMAT, encoding=habackup.ENCODING,
                           errors=habackup.ERRORS)
        sink = _Sink(tar, work.guard)
        sink.add_member(hacommon.info('.', 'dir', mode=0o755, uid=0, gid=0, mtime=time.time()))
        with work.open(member) as stream:
            holder['src'] = scan_member(stream, report, sink, checkpoint=work.checkpoint)
        tar.close()

    tmp.volume('emqx-src')
    tmp.volume_import('emqx-src', produce)
    for note in report.warnings():
        work.log(note)
    return holder['src']


class _Sink:
    """FileTar's interface over a stream tar (the throwaway volume's import)."""

    def __init__(self, tar, guard):
        self.tar, self.guard, self.names = tar, guard, set()

    def add_member(self, info, fileobj=None):
        if info.name in self.names:
            raise BackupError('corrupt-archive', 'HA 備份中有重複的項目。', member=info.name[:200])
        self.names.add(info.name)
        self.tar.addfile(info, fileobj)
        if self.guard is not None and info.isfile():
            self.guard.wrote(info.size)

    def add_entry(self, name, entry, *, mode, uid, gid):
        self.add_member(hacommon.info(name, 'file', mode=mode, uid=uid, gid=gid, mtime=entry.mtime, size=entry.size),
                        hacommon._Exact(entry))


def _clean(tmp, *roles, volumes=()):
    for role in roles:
        tmp.remove(role)
    for role in volumes:
        tmp.remove_volume(role)


def target_profile(work, app, target):
    """This device's authorization profile from a read-only look at its running broker (target_static); raises the
    refusal that names what is not supported. Nothing is changed."""
    def execute(command):
        return work.runner(app).podman('exec', target.container, *command, timeout=120,
                                      max_output=MAX_HOCON, check=False)
    _original, _explicit, _state, profile = target_static(work, app, target, execute)
    return profile


def target_preflight(work, app, target):
    """The check's read-only look at this device's broker: (profile, blocker). A target outside the proven profile is
    the app's blocker with the conversion's own message, so the page says it before anything is converted."""
    try:
        return target_profile(work, app, target), None
    except BackupError as error:
        return None, error.message


def check(work, app):
    tmp = work.temp(app)
    target, version = _prepare(work, app)
    profile, target_blocker = target_preflight(work, app, target)
    src = member_pass(work, tmp)
    work.phase('check')
    node, blocker = node_name(src)
    readings = None
    if blocker is None:
        readings = ha_broker(work, tmp, target, src, node)
        _clean(tmp, 'emqx-ha', volumes=('emqx-src', 'emqx-ha-log'))
    blockers, warnings = analyse(src, readings, addon_version=work.addon_info(SLUG).version, version=version,
                                 profile=profile)
    if blocker:
        blockers.insert(0, blocker)
    if target_blocker:
        blockers.append(target_blocker)
    return {'target_version': version or '', 'blockers': blockers, 'warnings': warnings,
            'emqx': section(src, node, readings, version=version, profile=profile)}


def _build_candidate(work, app, tmp, target, staging, *, version, profile=None):
    """The conversion's build (also driven by the lab harnesses); never replaces live volumes.

    `profile`: this device's authorization profile read before the build (the public conversion always passes it):
    HA's ACL rows on a target without the built-in database stop the build as soon as HA's rows are counted
    (acl_blocker), and the finished candidate must hold that same profile.
    Returns (src, node, readings, export, counts, strict, live_authn, readback, profile): `readback` is the finished
    candidate's readback record (read after this device's settings came back and every row was counted), `profile`
    this device's authorization sources it holds again.
    """
    expected_profile = profile
    # Internal test-owner diagnostics receive fixed stages only, never source
    # values or exception text. Ordinary product callers have no observer.
    observe=getattr(work,'_emqx_build_stage',None)
    def stage(name):
        if observe is not None:observe(name)
    stage('version')
    blocker = VERSIONS.blocker(work.addon_info(SLUG).version, version)
    if blocker:
        raise BackupError('incompatible', blocker, app=app.id)
    stage('member_pass')
    src = member_pass(work, tmp)
    work.phase('convert')
    stage('node_name')
    node, blocker = node_name(src)
    if blocker:
        raise BackupError('incompatible', f'EMQX 不能搬過來：{blocker}', app=app.id)
    stage('source_broker')
    readings = ha_broker(work, tmp, target, src, node, out_dir=staging)
    stage('source_analysis')
    blockers, _warnings = _source_analysis(src, readings, addon_version=work.addon_info(SLUG).version, version=version)
    if blockers:
        raise BackupError('incompatible', f'EMQX 不能搬過來：{blockers[0]}', app=app.id)
    blocker = acl_blocker(readings, expected_profile)
    if blocker:
        raise BackupError('incompatible', f'EMQX 不能搬過來：{blocker}', app=app.id)
    tmp.stop('emqx-ha', timeout=60)
    tmp.remove('emqx-ha')
    stage('source_export')
    export = take_export(work, tmp, readings['export'], staging)
    _clean(tmp, volumes=('emqx-src', 'emqx-xfer', 'emqx-ha-log'))
    emqx_ids = tmp.user_ids('ids-emqx', target.image, 'emqx')
    stage('target_candidate')
    seeded, counts, strict, live_authn = candidate_from_target(
        work, app, tmp, target, staging, export, emqx_ids, hint=hint_for(src.addon))
    stage('row_counts')
    problems = check_counts(readings['counts'], seeded, counts,
        observe=(lambda table, direction: stage('row_counts_'+table+'_'+direction)) if observe is not None else None)
    if problems:
        raise BackupError('job-failed', f'EMQX 匯入後的資料筆數和 HA 不同，已停止：{"、".join(problems[:10])}。')
    readback, profile = candidate_readback(tmp)
    if expected_profile is not None and profile != expected_profile:
        raise BackupError('incompatible', 'EMQX 設定於轉換期間改變，已停止。', app=app.id)
    return src, node, readings, export, counts, strict, live_authn, readback, profile


def _package_candidate(work, tmp, target, staging, out_dir, export, *, ids, log_root):
    """Package isolated candidate volumes; does not install or modify target volumes."""
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    code = tmp.stop('emqx-new', timeout=120)
    if code not in (0, 143):
        raise BackupError('job-failed', f'暫用的 EMQX 沒有正常關閉（結束碼 {code}）。')
    tmp.remove('emqx-new')
    raw = staging / 'emqx-new.tar'
    with open(raw, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        tmp.volume_export('emqx-new', handle, max_output=work.guard.budget())
    data_path = out_dir / 'volumes' / f'{target.data_volume}.tar'
    out = hacommon.FileTar(data_path, work.guard)
    try:
        data_volume(raw, out)
    finally:
        out.close()
    os.unlink(raw)
    os.unlink(export)
    log_path = out_dir / 'volumes' / f'{target.log_volume}.tar'
    tar = hacommon.FileTar(log_path, work.guard)
    try:
        hacommon.top_only(tar, log_root)
    finally:
        tar.close()
    for path in (data_path, log_path):
        ha_odoo.check_volume_tar(path, ids)
    _clean(tmp, volumes=('emqx-new', 'emqx-new-log', 'emqx-in'))
    return {target.data_volume: data_path, target.log_volume: log_path}


def convert(work, app, test_mode, out_dir):
    """This device's volumes from HA's data, with this device's settings and authorization preserved and verified
    (_build_candidate); the result carries the readback the restore compares (`import_check`, CONTRACT section 9)."""
    adapter = work.adapter(app)
    tmp = work.temp(app)
    target, version = _prepare(work, app)
    ids = adapter.owner_ids()
    staging = work.staging / 'emqx-work'
    staging.mkdir(mode=0o700)
    (out_dir / 'volumes').mkdir(mode=0o700, parents=True, exist_ok=True)
    blocker = VERSIONS.blocker(work.addon_info(SLUG).version, version)
    if blocker:
        raise BackupError('incompatible', f'EMQX 不能搬過來：{blocker}', app=app.id)
    try:   # the check's own read-only preflight: an unsupported or stopped target stops before anything is built
        before = target_profile(work, app, target)
    except BackupError as error:
        raise BackupError(error.code, error.message, app=app.id) from None
    src, node, readings, export, counts, strict, live_authn, readback, profile = _build_candidate(
        work, app, tmp, target, staging, version=version, profile=before)
    work.log(f'EMQX 資料匯入完成：{len(TABLES)} 個資料表的筆數都符合 HA；未符合規則的主題維持「{strict[0]}」')
    work.log('EMQX 這台的設定與授權來源（' + '＋'.join(SOURCE_NAMES[kind] for kind in profile) + '）已核對保留')
    volumes = _package_candidate(work, tmp, target, staging, out_dir, export, ids=ids,
                                 log_root=ha_n8n.volume_root(work, app, target.log_volume))
    return {'volumes': volumes, 'node': node,
            'ha_hosts': hacommon.ha_hosts(src.hocon), 'plugins': sorted(src.plugins),
            'anonymous': not any(a['enable'] for a in readings['authn']),
            'hash_differs': hash_differs(readings['authn'], live_authn),
            'api_keys': max(readings['counts'].get('emqx_app', 0), 0),
            'import_check': readback}


# ====================================================================== texts

def import_texts(data):
    notes = ['EMQX 的 MQTT 帳號、ACL 規則、Dashboard 帳號、API 金鑰、封鎖名單、PSK、保留訊息與規則、連接器設定會換成 HA 的；'
             '這台的節點名稱、連接埠、匿名登入限制與「未符合規則的主題拒絕」設定保持不變。',
             '這台 EMQX 的授權設定（ACL 檔案、授權來源與順序）與 bootstrap 帳號檔保持不變；還原後會再核對設定與內建資料庫'
             '都和轉換時相同，不同就自動回復。']
    reminders = ['請把 MQTT 裝置與服務（例如 Home Assistant 的 MQTT 整合、Zigbee2MQTT）改連到這台的 EMQX。',
                 '匯入後請用 HA 那邊的 EMQX Dashboard 帳號和密碼登入。']
    if data.get('anonymous'):
        reminders.append('HA 允許匿名連線，這台不允許：原本匿名連線的裝置需要建立 MQTT 帳號。')
    if data.get('hash_differs'):
        notes.append('HA 的 MQTT 帳號驗證使用不同的密碼雜湊方式，匯入後以 HA 的設定為準，這台原本的 MQTT 帳號（例如 woow）可能無法登入。')
    if data.get('ha_hosts'):
        reminders.append(f'HA 的 EMQX 規則或連接器連到 HA 內部的位址（{hacommon.names(data["ha_hosts"], 8)}），請改成這台連得到的位址。')
    if data.get('plugins'):
        reminders.append(f'HA 的 EMQX 外掛（{hacommon.names(data["plugins"])}）沒有搬過來，需要時請在這台重新安裝。')
    if data.get('api_keys'):
        reminders.append('HA 的 EMQX API 金鑰已取代這台的，使用這台 EMQX API 的工具需要換成新的金鑰。')
    return notes, reminders
