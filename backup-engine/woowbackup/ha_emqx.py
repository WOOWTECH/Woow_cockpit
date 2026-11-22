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
2. This device's broker: the live environment and secret mounts, the live base.hocon/acl.conf read-only, an empty
   data volume (so it boots with this device's admin password and bootstrap MQTT user, the node name and cookie),
   `emqx ctl data import`; then this device's `authorization.no_match` / `deny_action` are loaded back (HA's
   authorization root would replace them) and checked, and an enabled authenticator must remain (no anonymous login
   where this device has none); every table must hold at least HA's rows and at most HA's plus what the empty broker
   seeded. HA's API keys arrive and nothing else of the target's survives in an empty volume: they replace this
   device's (the EMQX MCP admin must log in again).

`woow_emqx_data` is that broker's volume without its generated configs (one holds the cookie), backups of
cluster.hocon, data exports and traces; `woow_emqx_log` is only its top folder. Versions: the add-on version maps to
the EMQX version it pins (VERSIONS), which must equal the live image's `org.opencontainers.image.version`.
"""
import io
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
DATA_ROOTS = ('authentication', 'authorization', 'rule_engine', 'connectors', 'actions', 'sources', 'bridges',
              'rewrite', 'auto_subscribe', 'exhook', 'gateway', 'psk_authentication', 'topic_metrics')
TABLE_SETS = ('builtin_authn', 'builtin_authz', 'banned', 'dashboard_users', 'api_keys', 'psk', 'builtin_retainer')
TABLES = ('emqx_authn_mnesia', 'emqx_authn_scram_mnesia', 'emqx_acl', 'emqx_banned', 'emqx_banned_rules', 'emqx_admin',
          'emqx_app', 'emqx_psk', 'emqx_retainer_message')
# Tables a running EMQX 5.8.9 always has: one missing in HA's broker means its database did not load completely.
REQUIRED_TABLES = ('emqx_authn_mnesia', 'emqx_acl', 'emqx_banned', 'emqx_admin', 'emqx_app')
PRESERVATION_BLOCKER = ('目前無法確認匯入後仍保留這台 EMQX 的授權規則與叢集設定，為避免變更存取權限或遺失設定，已停止匯入。')
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
    env = {'EMQX_NODE__NAME': node, 'EMQX_NODE__DATA_DIR': HA_DATA_DIR, 'EMQX_DASHBOARD__DEFAULT_PASSWORD': ''}
    volumes = [(tmp.name('emqx-src'), HA_DATA_DIR, 'rw,noexec,nosuid,nodev')]
    if out_dir is not None:
        tmp.volume('emqx-xfer')
        tmp.volume_import('emqx-xfer', lambda out: _folder_tar(out, 'out', 0, 0))
        volumes.append((tmp.name('emqx-xfer'), WORK, None))
    tmp.volume('emqx-ha-log')
    volumes.append((tmp.name('emqx-ha-log'), LOG_TARGET, None))
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


def target_config_snapshot(volume_tar, snapshot_path, required, *, limit=MAX_HOCON):
    """Stage named target config/ACL files from a volume export. Callers must enumerate effective references.

    This deliberately does not discover HOCON references or merge HA settings: the public import stays blocked until
    those operations and effective read-back are implemented. Missing, duplicate, linked or unsafe paths fail closed.
    """
    names = set(required)
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
        if found != names:
            raise BackupError('incompatible', '目標 EMQX 設定參照的檔案不存在，已停止。')
    except Exception:
        out.close()
        os.unlink(snapshot_path)
        raise
    else:
        out.close()
    return found


def authorization_file_references(authorization, mounts):
    """Resolve an already-decoded effective authorization object; reject unsupported sources.

    This covers file ACL sources only, not other EMQX configuration roots. Host paths are
    never read here. Exact existing read-only file mounts may satisfy an external reference.
    """
    if not isinstance(authorization, dict) or not isinstance(authorization.get('sources'), list):
        raise BackupError('incompatible', '無法取得目標 EMQX 的有效授權來源。')
    references = {'configs/cluster.hocon'}
    for source in authorization['sources']:
        if not isinstance(source, dict) or source.get('type') != 'file':
            raise BackupError('incompatible', '目標 EMQX 使用尚未支援的授權來源。')
        path = source.get('path')
        if not isinstance(path, str) or not path or '\x00' in path:
            raise BackupError('incompatible', '目標 EMQX 的 ACL 路徑無效。')
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


def snapshot_target_volume(work, app, volume, staging, required):
    """Export the target volume and stage only explicitly enumerated configuration references.

    A caller must first establish the complete effective reference list. This helper is not an
    authorization to import: the public preservation blocker remains in place.
    """
    raw = staging / 'emqx-target-config-source.tar'
    snapshot = staging / 'emqx-target-config-snapshot.tar'
    try:
        hacommon.live_export(work, app, volume, raw)
        target_config_snapshot(raw, snapshot, required)
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


def read_effective_config(execute):
    """Read merged broker configuration with bounded output; never expose its body in errors."""
    try:
        result = execute(['emqx', 'eval', CONFIG_EXPR])
        body = result.stdout or b''
        if result.returncode or len(body) > MAX_HOCON or not body.startswith(b'WOOWCFG:'):
            raise ValueError()
        encoded, tail = body[8:].split(b':END', 1)
        if tail.strip() not in (b'', b'ok'):
            raise ValueError()
        config = util.loads_strict(base64.b64decode(encoded, validate=True), max_bytes=MAX_HOCON)
        if not isinstance(config, dict) or not config or not isinstance(config.get('authorization'), dict):
            raise ValueError()
        auth = config['authorization']
        if auth.get('no_match') not in ('allow', 'deny') or auth.get('deny_action') not in ('ignore', 'disconnect'):
            raise ValueError()
        return config
    except (BackupError, ValueError, TypeError, RecursionError):
        raise BackupError('incompatible', '無法安全取得 EMQX 有效設定，已停止。') from None


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


def configuration_references(config, mounts, secrets=()):
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
    required = authorization_file_references(config['authorization'], mounts)
    for key in ('banned', 'api_key'):
        bootstrap_path = config.get(key, {}).get('bootstrap_file')
        if bootstrap_path:
            required.update(authorization_file_references(
                {'sources': [{'type': 'file', 'path': bootstrap_path}]}, mounts))
    def visit(value, depth=0):
        if depth > 32:
            raise BackupError('incompatible', 'EMQX 設定巢狀層級超過限制。')
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ('certfile', 'keyfile', 'cacertfile', 'dhfile') and item:
                    if isinstance(item, str) and item in IMAGE_TLS_FILES:
                        continue
                    required.update(authorization_file_references(
                        {'sources': [{'type': 'file', 'path': item}]}, mounts))
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
    return required


def candidate_from_target(work, app, tmp, target, staging, export, ids, *, hint=''):
    """Internal candidate entry: live structured read -> validated snapshot -> broker.

    The public convert guard still prevents this candidate from performing a real import.
    """
    def execute(command):
        return work.runner(app).podman('exec', target.container, *command, timeout=120,
                                      max_output=MAX_HOCON, check=False)
    if (target.env.get('EMQX_LOG_DIR', LOG_TARGET) != LOG_TARGET or
            target.env.get('EMQX_ETC_DIR', '/opt/emqx/etc') != '/opt/emqx/etc'):
        raise BackupError('incompatible', 'EMQX 自訂日誌目錄尚未支援。')
    original = read_effective_config(execute)
    required = configuration_references(original, target.files, target.secrets)
    fingerprints = tls_fingerprints(execute, image_tls_references(original))
    snapshot = snapshot_target_volume(work, app, target.data_volume, staging, required)
    # Reject a moving configuration rather than mixing two generations of files/settings.
    if read_effective_config(execute) != original:
        raise BackupError('incompatible', 'EMQX 設定於快照期間改變，已停止。')
    return target_broker(work, tmp, target, export, ids, hint=hint,
                         target_snapshot=snapshot, target_config=original, image_fingerprints=fingerprints)


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


def restore_target_settings(tmp, original, read_candidate):
    """Replace changed target setting roots, not merge stale/imported fields into them.

    Roots absent on the target cannot be restored by guessing an empty/default value.
    Any such extra operational root remains a failure until removal is implemented.
    """
    before = read_effective_config(read_candidate)
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
    if changed:
        snippet = json.dumps(changed, ensure_ascii=True).encode()
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
    after = read_effective_config(read_candidate)
    if preserved_settings(after) != expected or (authn is not None and after.get('authentication') != authn):
        raise BackupError('incompatible', 'EMQX 匯入後未能保留目標有效設定，已停止。')


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
                  image_fingerprints=None):
    """This device's broker on an empty volume: import HA's export, load the strict settings back, verify."""
    name = os.path.basename(export)
    tmp.volume('emqx-in')
    tmp.volume_import('emqx-in', lambda out: _folder_tar(out, 'in', ids[0], ids[1], [(name, export)]))
    tmp.volume('emqx-new')
    if target_snapshot is not None:
        import_target_snapshot(tmp, target_snapshot, ids)
    tmp.volume('emqx-new-log')
    tmp.run('emqx-new', target.image, [], detach=True, read_only_root=True, env=target.env, secrets=target.secrets,
            volumes=[(tmp.name('emqx-new'), DATA_TARGET, None), (tmp.name('emqx-new-log'), LOG_TARGET, None),
                     (tmp.name('emqx-in'), WORK, None)] + target.files)
    wait_ready(tmp, 'emqx-new', checkpoint=work.checkpoint)
    ticker_pid = quiesce_system_ticker(tmp, 'emqx-new')
    read_candidate = lambda command: tmp.exec('emqx-new', command, timeout=120,
                                               max_output=MAX_HOCON, check=False)
    if image_fingerprints is not None and tls_fingerprints(read_candidate, image_fingerprints) != image_fingerprints:
        raise BackupError('incompatible', 'EMQX 候選憑證與目標不一致，已停止。')
    if target_config is not None and read_effective_config(read_candidate) != target_config:
        raise BackupError('incompatible', 'EMQX 候選啟動後設定與目標不一致，已停止。')
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
        restore_target_settings(tmp, target_config, read_candidate)
        if image_fingerprints is not None and tls_fingerprints(read_candidate, image_fingerprints) != image_fingerprints:
            raise BackupError('incompatible', 'EMQX 匯入後憑證與目標不一致，已停止。')
        check_candidate_bootstrap(tmp, target, read_effective_config(read_candidate))
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


def check_counts(ha, seeded, counts):
    """Tables where the import lost or invented rows (HA's rows must all be there, at most plus the seed)."""
    problems = []
    for table in TABLES:
        mine, theirs, seed = counts.get(table, -1), ha.get(table, -1), max(seeded.get(table, 0), 0)
        if theirs < 0:
            continue
        if not theirs <= mine <= theirs + seed:
            problems.append(f'{table}（HA {theirs}，匯入後 {mine}）')
    return problems


def data_volume(src_path, out):
    """woow_emqx_data from the broker's volume export without generated configs, cluster.hocon backups, exports and
    traces."""
    return hacommon.copy_live(src_path, out, drop=lambda name: DROPPED.fullmatch(name) is not None,
                              what='暫用 EMQX 的資料卷')


# ====================================================================== analysis

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


def analyse(src, readings, *, addon_version, version, live_authn=None):
    blockers, warnings = _source_analysis(src, readings, addon_version=addon_version,
                                          version=version, live_authn=live_authn)
    return [PRESERVATION_BLOCKER, *blockers], warnings


def hash_differs(ha_authn, live_authn):
    """True when an authenticator both sides have (mechanism, backend) hashes passwords differently."""
    mine = {(a['mechanism'], a['backend']): a for a in ha_authn}
    for row in live_authn or []:
        other = mine.get((row['mechanism'], row['backend']))
        if other and (other['algorithm'], other['salt']) != (row['algorithm'], row['salt']):
            return True
    return False


def section(src, node, readings, *, version):
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
            'ha_hosts': hacommon.ha_hosts(src.hocon)[:20]}


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


def check(work, app):
    tmp = work.temp(app)
    target, version = _prepare(work, app)
    src = member_pass(work, tmp)
    work.phase('check')
    node, blocker = node_name(src)
    readings = None
    if blocker is None:
        readings = ha_broker(work, tmp, target, src, node)
        _clean(tmp, 'emqx-ha', volumes=('emqx-src', 'emqx-ha-log'))
    blockers, warnings = analyse(src, readings, addon_version=work.addon_info(SLUG).version, version=version)
    if blocker:
        blockers.insert(0, blocker)
    return {'target_version': version or '', 'blockers': blockers, 'warnings': warnings,
            'emqx': section(src, node, readings, version=version)}


def _build_candidate(work, app, tmp, target, staging, *, version):
    """Internal build only. Public convert/analyse remain blocked; never replaces live volumes.

    Used by the isolated synthetic integration harness and the guarded conversion body.
    """
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
    problems = check_counts(readings['counts'], seeded, counts)
    if problems:
        raise BackupError('job-failed', f'EMQX 匯入後的資料筆數和 HA 不同，已停止：{"、".join(problems[:10])}。')
    return src, node, readings, export, counts, strict, live_authn


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
    """Build target volumes only when target ACL and settings preservation is verified."""
    raise BackupError('incompatible', PRESERVATION_BLOCKER, app=app.id)
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
    src, node, readings, export, counts, strict, live_authn = _build_candidate(
        work, app, tmp, target, staging, version=version)
    work.log(f'EMQX 資料匯入完成：{len(TABLES)} 個資料表的筆數都符合 HA；未符合規則的主題維持「{strict[0]}」')
    volumes = _package_candidate(work, tmp, target, staging, out_dir, export, ids=ids,
                                 log_root=ha_n8n.volume_root(work, app, target.log_volume))
    return {'volumes': volumes, 'node': node,
            'ha_hosts': hacommon.ha_hosts(src.hocon), 'plugins': sorted(src.plugins),
            'anonymous': not any(a['enable'] for a in readings['authn']),
            'hash_differs': hash_differs(readings['authn'], live_authn),
            'api_keys': max(readings['counts'].get('emqx_app', 0), 0)}


# ====================================================================== texts

def import_texts(data):
    notes = ['EMQX 的 MQTT 帳號、ACL 規則、Dashboard 帳號、API 金鑰、封鎖名單、PSK、保留訊息與規則、連接器設定會換成 HA 的；'
             '這台的節點名稱、連接埠、匿名登入限制與「未符合規則的主題拒絕」設定保持不變。']
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
