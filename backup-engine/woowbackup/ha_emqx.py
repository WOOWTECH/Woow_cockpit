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
import os
import re
import tarfile
import time

from . import habackup, hacommon, ha_n8n, ha_odoo, tempctr
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


def wait_ready(tmp, role, *, checkpoint, sleep=time.sleep, clock=time.monotonic, timeout=READY_TIMEOUT):
    deadline = clock() + timeout
    while True:
        if checkpoint is not None:
            checkpoint()
        result = ctl(tmp, role, ['status'], timeout=60, check=False)
        if result.returncode == 0 and b'is started' in (result.stdout or b''):
            return
        if not tmp.running(role):
            raise BackupError('incompatible', '暫用的 EMQX 無法開啟 HA 的資料（版本、設定或資料可能不相容）。')
        if clock() > deadline:
            raise BackupError('incompatible', f'暫用的 EMQX 在 {timeout} 秒內沒有就緒。')
        sleep(2)


def parse_counts(text):
    return {name: int(value) for name, value in re.findall(r'\{\s*([a-z_]+)\s*,\s*(-?[0-9]{1,12})\s*\}', text)
            if name in TABLES}


def parse_authn(text):
    rows = re.findall(r'\{\s*([a-z_]+)\s*,\s*([a-z_]+)\s*,\s*(true|false)\s*,\s*([a-z0-9_]+)\s*,\s*([a-z_]+)\s*\}', text)
    return [{'mechanism': m, 'backend': b, 'enable': e == 'true', 'algorithm': a, 'salt': s} for m, b, e, a, s in rows]


def parse_strict(text):
    match = re.search(r'\{\s*(allow|deny)\s*,\s*(ignore|disconnect)\s*\}', text)
    return (match.group(1), match.group(2)) if match else None


def ha_broker(work, tmp, target, src, node, *, out_dir=None):
    """Start HA's broker on its staged data; returns its readings (and, with `out_dir`, the export file's path in
    `out_dir`). The caller removes the objects."""
    host = node.split('@', 1)[1]
    hosts = [] if IPV4_RE.fullmatch(host) else [(host, '127.0.0.1')]
    # No cookie is set: the image's default only guards the distribution port inside a container without a network.
    env = {'EMQX_NODE__NAME': node, 'EMQX_NODE__DATA_DIR': HA_DATA_DIR, 'EMQX_DASHBOARD__DEFAULT_PASSWORD': '',
           'EMQX_LOG__FILE__DEFAULT__ENABLE': 'false'}
    tmp.volume('emqx-xfer')
    tmp.volume_import('emqx-xfer', lambda out: _folder_tar(out, 'out', 0, 0))
    tmp.volume('emqx-ha-log')
    try:
        tmp.run('emqx-ha', target.image, [], detach=True, user='0', read_only_root=True, add_hosts=hosts, env=env,
                volumes=[(tmp.name('emqx-src'), HA_DATA_DIR, 'rw,noexec,nosuid,nodev'),
                         (tmp.name('emqx-xfer'), WORK, None), (tmp.name('emqx-ha-log'), LOG_TARGET, None)])
    except BackupError as error:
        if error.code != 'job-failed':
            raise
        raise BackupError('incompatible', f'無法以 HA 的 EMQX 節點名稱 {node} 啟動暫用的 EMQX。') from None
    wait_ready(tmp, 'emqx-ha', checkpoint=work.checkpoint)
    readings = {'default_admin': 'default' in evaluate(tmp, 'emqx-ha', DEFAULT_ADMIN_EXPR).split(),
                'counts': parse_counts(evaluate(tmp, 'emqx-ha', COUNT_EXPR)),
                'roots': set(re.findall(r'<<"([a-z_]+)">>', evaluate(tmp, 'emqx-ha', ROOTS_EXPR))),
                'authn': parse_authn(evaluate(tmp, 'emqx-ha', AUTHN_EXPR)),
                'strict': parse_strict(evaluate(tmp, 'emqx-ha', STRICT_EXPR))}
    if len(readings['counts']) != len(TABLES):
        raise BackupError('job-failed', '無法讀取 HA 的 EMQX 資料筆數。')
    if out_dir is not None:
        roots = [root for root in DATA_ROOTS if root in readings['roots']]
        out = ctl(tmp, 'emqx-ha', ['data', 'export', '--root-keys', ','.join(roots), '--table-sets',
                                   ','.join(TABLE_SETS), '--dir', f'{WORK}/out'], timeout=1800).stdout or b''
        match = EXPORT_RE.search(out)
        if not match:
            raise BackupError('job-failed', 'HA 的 EMQX 資料匯出失敗。')
        readings['export'] = match.group(1).decode('ascii')
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


def target_broker(work, tmp, target, export, ids):
    """This device's broker on an empty volume: import HA's export, load the strict settings back, verify."""
    name = os.path.basename(export)
    tmp.volume('emqx-in')
    tmp.volume_import('emqx-in', lambda out: _folder_tar(out, 'in', ids[0], ids[1], [(name, export)]))
    tmp.volume('emqx-new')
    tmp.volume('emqx-new-log')
    tmp.run('emqx-new', target.image, [], detach=True, read_only_root=True, env=target.env, secrets=target.secrets,
            volumes=[(tmp.name('emqx-new'), DATA_TARGET, None), (tmp.name('emqx-new-log'), LOG_TARGET, None),
                     (tmp.name('emqx-in'), WORK, None)] + target.files)
    wait_ready(tmp, 'emqx-new', checkpoint=work.checkpoint)
    seeded = parse_counts(evaluate(tmp, 'emqx-new', COUNT_EXPR))
    strict = parse_strict(evaluate(tmp, 'emqx-new', STRICT_EXPR))
    authn = parse_authn(evaluate(tmp, 'emqx-new', AUTHN_EXPR))
    if strict is None or len(seeded) != len(TABLES):
        raise BackupError('job-failed', '無法讀取這台 EMQX 的設定。')
    work.log('把 HA 的 EMQX 資料匯入暫用的 EMQX（這台的映像與設定）')
    out = ctl(tmp, 'emqx-new', ['data', 'import', f'{WORK}/in/{name}'], timeout=1800).stdout or b''
    if b'imported successfully' not in out:
        raise BackupError('job-failed', 'HA 的 EMQX 資料匯入時發生錯誤，已停止。')
    snippet = f'authorization {{\n  no_match = {strict[0]}\n  deny_action = {strict[1]}\n  sources = []\n}}\n'.encode()
    tmp.exec('emqx-new', ['sh', '-c', f'cat > {WORK}/in/strict.hocon'], input=snippet, timeout=120,
             max_output=64 * 1024)
    ctl(tmp, 'emqx-new', ['conf', 'load', '--merge', f'{WORK}/in/strict.hocon'], timeout=600)
    after = parse_strict(evaluate(tmp, 'emqx-new', STRICT_EXPR))
    if after != strict:
        raise BackupError('job-failed', '無法恢復這台 EMQX 的存取政策（未符合規則的主題拒絕），已停止。')
    enabled = [a for a in parse_authn(evaluate(tmp, 'emqx-new', AUTHN_EXPR)) if a['enable']]
    if any(a['enable'] for a in authn) and not enabled:
        raise BackupError('incompatible', 'HA 的 EMQX 設定會停用這台的帳號驗證（允許匿名登入），已停止；請先在 HA 啟用帳號驗證再備份。')
    counts = parse_counts(evaluate(tmp, 'emqx-new', COUNT_EXPR))
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

def analyse(src, readings, *, addon_version, version, live_authn=None):
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
    warnings.append('HA 的 EMQX 備份是在執行中製作的；如果匯入失敗，請先停掉 HA 的 EMQX 再重新備份。')
    return blockers, warnings


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
            'plugins': sorted(src.plugins), 'ha_hosts': hacommon.ha_hosts(src.hocon)[:20]}


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
        _clean(tmp, 'emqx-ha', volumes=('emqx-src', 'emqx-xfer', 'emqx-ha-log'))
    blockers, warnings = analyse(src, readings, addon_version=work.addon_info(SLUG).version, version=version)
    if blocker:
        blockers.insert(0, blocker)
    return {'target_version': version or '', 'blockers': blockers, 'warnings': warnings,
            'emqx': section(src, node, readings, version=version)}


def convert(work, app, test_mode, out_dir):
    """Build `out_dir/volumes/<woow_emqx_data>.tar` and `<woow_emqx_log>.tar`."""
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
    src = member_pass(work, tmp)
    work.phase('convert')
    node, blocker = node_name(src)
    if blocker:
        raise BackupError('incompatible', f'EMQX 不能搬過來：{blocker}', app=app.id)
    readings = ha_broker(work, tmp, target, src, node, out_dir=staging)
    blockers, _warnings = analyse(src, readings, addon_version=work.addon_info(SLUG).version, version=version)
    if blockers:
        raise BackupError('incompatible', f'EMQX 不能搬過來：{blockers[0]}', app=app.id)
    tmp.stop('emqx-ha', timeout=60)
    tmp.remove('emqx-ha')
    export = take_export(work, tmp, readings['export'], staging)
    _clean(tmp, volumes=('emqx-src', 'emqx-xfer', 'emqx-ha-log'))
    emqx_ids = tmp.user_ids('ids-emqx', target.image, 'emqx')
    seeded, counts, strict, live_authn = target_broker(work, tmp, target, export, emqx_ids)
    problems = check_counts(readings['counts'], seeded, counts)
    if problems:
        raise BackupError('job-failed', f'EMQX 匯入後的資料筆數和 HA 不同，已停止：{"、".join(problems[:10])}。')
    work.log(f'EMQX 資料匯入完成：{len(TABLES)} 個資料表的筆數都符合 HA；未符合規則的主題維持「{strict[0]}」')
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
    _clean(tmp, volumes=('emqx-new', 'emqx-new-log', 'emqx-in'))
    log_path = out_dir / 'volumes' / f'{target.log_volume}.tar'
    tar = hacommon.FileTar(log_path, work.guard)
    try:
        hacommon.top_only(tar, ha_n8n.volume_root(work, app, target.log_volume))
    finally:
        tar.close()
    for path in (data_path, log_path):
        ha_odoo.check_volume_tar(path, ids)
    return {'volumes': {target.data_volume: data_path, target.log_volume: log_path}, 'node': node,
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
