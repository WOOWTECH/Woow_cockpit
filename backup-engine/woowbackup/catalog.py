"""Trusted application catalog (CONTRACT section 4). Owner: E2 engine-ops.

Catalog entries live in a root-owned directory and are the *authority* for every restore: an
archive can only supply bytes for items declared here. Validation is strict: unknown keys,
wrong types, unsafe names, non-loopback URLs and unsafe file metadata are all rejected.
"""
import errno
import hashlib
import json
import os
import pwd
import re
import stat
from dataclasses import dataclass, field

from .errors import BackupError

SCHEMA = 1
MAX_ENTRY_BYTES = 256 * 1024
KNOWN_ADAPTERS = frozenset({'quadlet-postgres'})

ID_RE = re.compile(r'[a-z0-9][a-z0-9-]{1,40}\Z')
OWNER_RE = re.compile(r'[a-z_][a-z0-9_-]{0,31}\Z')
UNIT_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,200}\.service\Z')
CONTAINER_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
VOLUME_RE = CONTAINER_RE
SECRET_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,200}\Z')
QUADLET_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,190}\.(container|network|volume|pod)\Z')
PG_ID_RE = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}\Z')
PG_IDENT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,62}\Z')
CHECK_ID_RE = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}\Z')
COMPARE_KEY_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z')
SEGMENT_RE = re.compile(r'[A-Za-z0-9._@+-]{1,255}\Z')
MODE_RE = re.compile(r'0[0-7]{3}\Z')
URL_RE = re.compile(r"http://(?:127\.0\.0\.1|localhost):([0-9]{1,5})(/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)\Z")
CONTROL_RE = re.compile(r'[\x00-\x1f\x7f-\x9f]')

# A config file lives in the app's own directory: `.config/<id>/` or `.local/share/<id>/` (an allowlist).
CONFIG_ROOTS = ('.config/', '.local/share/')
# Unit definitions, the user manager's environment and the Podman configuration must only ever come from
# trusted templates, never from archive bytes; these stay forbidden even for an app id that collides
# with such a directory name (review finding SEC-8).
FORBIDDEN_CONFIG_PREFIXES = ('.config/systemd/', '.config/containers/', '.config/environment.d/', '.config/autostart/',
                             '.config/dbus-1/', '.config/user-tmpfiles.d/', '.local/share/systemd/',
                             '.local/share/containers/', '.local/share/dbus-1/', '.local/share/applications/')
# Host directories (`data_dirs`) may lie anywhere in the owner's home except these trees: login keys, unit
# definitions, the user manager's environment, programs and shell start-up files his logins run, user tmpfiles
# (which can write any file of his at the next login) and the Podman storage and configuration must never be
# replaced by archive bytes (review L1). A data directory may be neither one of them, nor inside one, nor contain one
# (`.config` would contain `.config/systemd`); compared without regard to case (case-insensitive filesystems).
FORBIDDEN_DATA_DIRS = ('.ssh', '.gnupg', '.config/systemd', '.config/containers', '.local/share/containers',
                       '.config/environment.d', '.config/autostart', '.config/dbus-1', '.config/user-tmpfiles.d',
                       '.local/share/systemd', '.local/share/dbus-1', '.local/share/applications',
                       '.local/share/user-tmpfiles.d', '.local/bin', '.local/lib', 'bin', '.bashrc.d', '.config/fish')
MAX_DATA_DIRS = 16
# The last segment leaves room for the restore's sibling `<name>.woowbk-old-<job id>-rollback` within NAME_MAX (255).
MAX_DATA_DIR_NAME = 200

TOP_REQUIRED = ('schema', 'id', 'name', 'owner', 'adapter', 'quadlet', 'units')
TOP_OPTIONAL = ('description', 'writer_units', 'postgres', 'volumes', 'data_dirs', 'secrets', 'config_files', 'health',
                'verify')


@dataclass(frozen=True)
class App:
    id: str
    name: str
    description: str
    owner: str
    adapter: str
    quadlet_files: tuple
    template_dir: str | None
    units: tuple
    writer_units: tuple
    postgres: tuple
    volumes: tuple
    secrets: tuple
    config_files: tuple
    health: tuple
    verify: tuple
    sha256: str
    data_dirs: tuple = ()  # ({'path': <relative to the owner's home>, 'label': str}, ...)
    raw: dict = field(compare=False, repr=False, default_factory=dict)


class Catalog(dict):
    """`{id: App}` plus `problems`: entries that were found but not loaded.

    Each problem is `{'file', 'id', 'code', 'message'}` (zh-TW message, never file content).
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.problems = []

    def problem_for(self, app_id):
        return next((p for p in self.problems if p.get('id') == app_id), None)


def _fail(where, text, code='invalid-request'):
    raise BackupError(code, f'應用設定 {where} {text}', field=where)


def _object(value, where, required, optional=()):
    if not isinstance(value, dict):
        _fail(where, '必須是 JSON 物件。')
    unknown = sorted(set(value) - set(required) - set(optional))
    if unknown:
        _fail(where, f'含有不支援的欄位：{", ".join(unknown)[:200]}。')
    missing = [key for key in required if key not in value]
    if missing:
        _fail(where, f'缺少必要欄位：{", ".join(missing)}。')
    return value


def _string(value, where, regex=None, *, max_len=200, allow_empty=False):
    if not isinstance(value, str):
        _fail(where, '必須是字串。')
    if not value and not allow_empty:
        _fail(where, '不可為空白。')
    if len(value) > max_len:
        _fail(where, f'長度不可超過 {max_len} 個字元。')
    if regex is not None and not regex.fullmatch(value):
        _fail(where, '格式不正確。')
    if regex is None and CONTROL_RE.search(value):
        _fail(where, '不可包含控制字元。')
    return value


def _int(value, where, low, high):
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(where, '必須是整數。')
    if not low <= value <= high:
        _fail(where, f'必須介於 {low} 與 {high} 之間。')
    return value


def _list(value, where, max_items, *, min_items=0):
    if not isinstance(value, list):
        _fail(where, '必須是陣列。')
    if not min_items <= len(value) <= max_items:
        _fail(where, f'項目數量必須介於 {min_items} 與 {max_items} 之間。')
    return value


def _unique(values, where):
    seen = set()
    for value in values:
        if value in seen:
            _fail(where, f'含有重複項目：{value}。')
        seen.add(value)


def _url(value, where):
    _string(value, where, max_len=500)
    match = URL_RE.fullmatch(value)
    if not match or not 1 <= int(match.group(1)) <= 65535:
        _fail(where, '只能使用本機回送位址（http://127.0.0.1:<埠>/… 或 http://localhost:<埠>/…）。')
    return value


def _config_path(value, where, app_id):
    _string(value, where, max_len=1024)
    allowed = tuple(f'{root}{app_id}/' for root in CONFIG_ROOTS)
    if value.startswith('/') or not value.startswith(allowed):
        _fail(where, f'必須位於應用自己的設定目錄 .config/{app_id}/ 或 .local/share/{app_id}/ 之下。')
    for segment in value.split('/'):
        if segment in ('', '.', '..') or not SEGMENT_RE.fullmatch(segment):
            _fail(where, '含有不允許的路徑片段。')
    if value.startswith(FORBIDDEN_CONFIG_PREFIXES):
        _fail(where, '不可指向 systemd、Podman、使用者環境或自動啟動的設定目錄。')
    return value


def paths_overlap(a, b):
    """True when one relative path equals the other or lies below it (`a/b` and `a`, never `ab` and `a`)."""
    return a == b or a.startswith(b + '/') or b.startswith(a + '/')


def _data_dir_path(value, where):
    """A directory in the owner's home: normalized relative POSIX path, safe segments, outside forbidden trees."""
    _string(value, where, max_len=1024)
    if value.startswith('/') or value.endswith('/'):
        _fail(where, '必須是相對於擁有者家目錄的資料夾路徑，不可以 / 開頭或結尾。')
    segments = value.split('/')
    for segment in segments:
        if segment in ('', '.', '..') or not SEGMENT_RE.fullmatch(segment):
            _fail(where, '含有不允許的路徑片段（只能用 A-Z a-z 0-9 . _ @ + -，不可為空、. 或 ..）。')
    if len(segments[-1]) > MAX_DATA_DIR_NAME:
        _fail(where, f'最後一段名稱不可超過 {MAX_DATA_DIR_NAME} 個字元。')
    if any('.woowbk-' in segment.lower() for segment in segments):
        # Names like the restore's own siblings (`<dir>.woowbk-new-<job>`) would be taken for its copies (review L3).
        _fail(where, '名稱不可包含「.woowbk-」（保留給還原時的暫存資料夾）。')
    for forbidden in FORBIDDEN_DATA_DIRS:
        if paths_overlap(value.lower(), forbidden):
            _fail(where, f'不可等於、位於或包含 ~/{forbidden}（登入金鑰、systemd、Podman 或使用者環境的設定）。')
    return value


def _mode(value, where):
    _string(value, where, MODE_RE, max_len=4)
    if int(value, 8) & ~0o644:
        _fail(where, '權限不可超過 0644（不可執行，群組與其他人不可寫入）。')
    return value


def _template_dir(value, where, paths):
    if value is None:
        return None
    _string(value, where, max_len=1024)
    root = str(paths.templates).rstrip('/') + '/'
    if not value.startswith('/') or os.path.normpath(value) != value or not value.startswith(root):
        _fail(where, f'必須位於受信任範本目錄 {root} 之內。')
    for segment in value[len(root):].split('/'):
        if not SEGMENT_RE.fullmatch(segment) or segment in ('.', '..'):
            _fail(where, '含有不允許的路徑片段。')
    return value


def validate_entry(data, *, paths, sha256=None, user_lookup=None):
    """Strictly validate one catalog dict; return App or raise BackupError('invalid-request').

    `owner-missing` is raised when the owner account does not exist on this device.
    `sha256` is the digest of the raw file bytes (computed from canonical JSON when omitted).
    """
    lookup = user_lookup or pwd.getpwnam
    _object(data, '', TOP_REQUIRED, TOP_OPTIONAL)
    if isinstance(data['schema'], bool) or data['schema'] != SCHEMA:
        _fail('schema', f'必須為 {SCHEMA}。')
    app_id = _string(data['id'], 'id', ID_RE, max_len=41)
    name = _string(data['name'], 'name', max_len=80)
    description = _string(data.get('description', ''), 'description', max_len=500, allow_empty=True)
    owner = _string(data['owner'], 'owner', OWNER_RE, max_len=32)
    if owner == 'root':
        _fail('owner', '不可為 root；只支援一般帳號擁有的 rootless 應用。')
    adapter = _string(data['adapter'], 'adapter', max_len=64)
    if adapter not in KNOWN_ADAPTERS:
        _fail('adapter', '不是此版本支援的轉接器。')

    quadlet = _object(data['quadlet'], 'quadlet', ('files',), ('template_dir',))
    files = _list(quadlet['files'], 'quadlet.files', 32, min_items=1)
    for i, name_ in enumerate(files):
        _string(name_, f'quadlet.files[{i}]', QUADLET_RE, max_len=200)
    _unique(files, 'quadlet.files')
    template_dir = _template_dir(quadlet.get('template_dir'), 'quadlet.template_dir', paths)

    units = _list(data['units'], 'units', 32, min_items=1)
    for i, unit in enumerate(units):
        _string(unit, f'units[{i}]', UNIT_RE, max_len=210)
    _unique(units, 'units')
    writers = _list(data.get('writer_units', []), 'writer_units', 32)
    for i, unit in enumerate(writers):
        _string(unit, f'writer_units[{i}]', UNIT_RE, max_len=210)
        if unit not in units:
            _fail(f'writer_units[{i}]', '必須同時列在 units 之中。')
    _unique(writers, 'writer_units')

    postgres = []
    for i, item in enumerate(_list(data.get('postgres', []), 'postgres', 8)):
        where = f'postgres[{i}]'
        _object(item, where, ('id', 'container', 'unit', 'database', 'user', 'data_volume'))
        entry = {
            'id': _string(item['id'], f'{where}.id', PG_ID_RE, max_len=32),
            'container': _string(item['container'], f'{where}.container', CONTAINER_RE, max_len=128),
            'unit': _string(item['unit'], f'{where}.unit', UNIT_RE, max_len=210),
            'database': _string(item['database'], f'{where}.database', PG_IDENT_RE, max_len=63),
            'user': _string(item['user'], f'{where}.user', PG_IDENT_RE, max_len=63),
            'data_volume': _string(item['data_volume'], f'{where}.data_volume', VOLUME_RE, max_len=128),
        }
        if entry['unit'] not in units:
            _fail(f'{where}.unit', '必須列在 units 之中。')
        if entry['unit'] in writers:
            _fail(f'{where}.unit', '資料庫服務在備份期間必須保持執行，不可列為 writer_units。')
        postgres.append(entry)
    _unique([p['id'] for p in postgres], 'postgres[].id')
    _unique([p['container'] for p in postgres], 'postgres[].container')
    _unique([p['data_volume'] for p in postgres], 'postgres[].data_volume')

    volumes = []
    for i, item in enumerate(_list(data.get('volumes', []), 'volumes', 32)):
        where = f'volumes[{i}]'
        _object(item, where, ('name',), ('label',))
        volumes.append({'name': _string(item['name'], f'{where}.name', VOLUME_RE, max_len=128),
                        'label': _string(item.get('label', ''), f'{where}.label', max_len=80, allow_empty=True)})
    _unique([v['name'] for v in volumes], 'volumes[].name')
    for v in volumes:
        if v['name'] in {p['data_volume'] for p in postgres}:
            _fail('volumes', f'{v["name"]} 是資料庫資料卷，請只列在 postgres.data_volume。')

    secrets = []
    for i, item in enumerate(_list(data.get('secrets', []), 'secrets', 64)):
        _object(item, f'secrets[{i}]', ('name',))
        secrets.append({'name': _string(item['name'], f'secrets[{i}].name', SECRET_RE, max_len=201)})
    _unique([s['name'] for s in secrets], 'secrets[].name')

    config_files = []
    for i, item in enumerate(_list(data.get('config_files', []), 'config_files', 64)):
        where = f'config_files[{i}]'
        _object(item, where, ('path', 'mode'))
        config_files.append({'path': _config_path(item['path'], f'{where}.path', app_id),
                             'mode': _mode(item['mode'], f'{where}.mode')})
    _unique([c['path'] for c in config_files], 'config_files[].path')

    data_dirs = []
    for i, item in enumerate(_list(data.get('data_dirs', []), 'data_dirs', MAX_DATA_DIRS)):
        where = f'data_dirs[{i}]'
        _object(item, where, ('path',), ('label',))
        path = _data_dir_path(item['path'], f'{where}.path')
        for earlier in data_dirs:
            if paths_overlap(path, earlier['path']):
                _fail(f'{where}.path', f'與 data_dirs 中的 {earlier["path"]} 重疊（一個資料夾不可位於另一個之內）。')
        for config in config_files:
            if paths_overlap(path, config['path']):
                _fail(f'{where}.path', f'與設定檔 {config["path"]} 重疊。')
        data_dirs.append({'path': path,
                          'label': _string(item.get('label', ''), f'{where}.label', max_len=80, allow_empty=True)})

    health = []
    for i, item in enumerate(_list(data.get('health', []), 'health', 8)):
        where = f'health[{i}]'
        _object(item, where, ('type', 'url'), ('expect_status', 'timeout_seconds'))
        if item['type'] != 'http':
            _fail(f'{where}.type', '只支援 http。')
        health.append({'type': 'http', 'url': _url(item['url'], f'{where}.url'),
                       'expect_status': _int(item.get('expect_status', 200), f'{where}.expect_status', 100, 599),
                       'timeout_seconds': _int(item.get('timeout_seconds', 60), f'{where}.timeout_seconds', 1, 600)})

    verify = []
    for i, item in enumerate(_list(data.get('verify', []), 'verify', 8)):
        where = f'verify[{i}]'
        _object(item, where, ('id', 'type', 'url', 'compare'))
        if item['type'] != 'http-json':
            _fail(f'{where}.type', '只支援 http-json。')
        compare = _list(item['compare'], f'{where}.compare', 32, min_items=1)
        for j, key in enumerate(compare):
            _string(key, f'{where}.compare[{j}]', COMPARE_KEY_RE, max_len=64)
        _unique(compare, f'{where}.compare')
        verify.append({'id': _string(item['id'], f'{where}.id', CHECK_ID_RE, max_len=32), 'type': 'http-json',
                       'url': _url(item['url'], f'{where}.url'), 'compare': list(compare)})
    _unique([v['id'] for v in verify], 'verify[].id')

    try:
        account = lookup(owner)
    except KeyError:
        raise BackupError('owner-missing', f'應用「{name}」的擁有者帳號 {owner} 不存在於此設備。',
                          app=app_id, owner=owner) from None
    if account.pw_uid == 0:
        _fail('owner', '對應到 root（UID 0），不支援。')

    if sha256 is None:
        sha256 = hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return App(id=app_id, name=name, description=description, owner=owner, adapter=adapter,
               quadlet_files=tuple(files), template_dir=template_dir, units=tuple(units),
               writer_units=tuple(writers), postgres=tuple(postgres), volumes=tuple(volumes),
               secrets=tuple(secrets), config_files=tuple(config_files), health=tuple(health),
               verify=tuple(verify), sha256=sha256, data_dirs=tuple(data_dirs), raw=data)


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _reject_constant(name):
    raise ValueError(f'unsupported constant {name}')


def parse_json_bytes(data):
    """Strict JSON: UTF-8, no duplicate keys, no NaN/Infinity."""
    return json.loads(data.decode('utf-8'), object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)


def _safe_dir_stat(st, trusted_uid):
    return stat.S_ISDIR(st.st_mode) and st.st_uid == trusted_uid and not st.st_mode & 0o022


def load_catalog(paths, *, trusted_uid=0, user_lookup=None):
    """Load all root-owned, non-writable, non-symlink entries; returns {id: App}. Invalid files are reported, not loaded.

    `trusted_uid` is the required owner of catalog files and directories. It is 0 in production;
    only tests pass their own uid explicitly.
    """
    catalog = Catalog()
    directory = paths.catalog
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        parent = os.lstat(paths.config)
    except FileNotFoundError:
        return catalog
    if stat.S_ISLNK(parent.st_mode) or not _safe_dir_stat(parent, trusted_uid):
        catalog.problems.append({'file': str(paths.config), 'id': None, 'code': 'permission-denied',
                                 'message': '備份設定目錄必須由 root 擁有、不可為符號連結且不可讓其他帳號寫入；已略過所有應用設定。'})
        return catalog
    try:
        dfd = os.open(directory, flags)
    except FileNotFoundError:
        return catalog
    except OSError:
        catalog.problems.append({'file': str(directory), 'id': None, 'code': 'permission-denied',
                                 'message': '應用設定目錄不可為符號連結；已略過所有應用設定。'})
        return catalog
    try:
        if not _safe_dir_stat(os.fstat(dfd), trusted_uid):
            catalog.problems.append({'file': str(directory), 'id': None, 'code': 'permission-denied',
                                     'message': '應用設定目錄必須由 root 擁有且不可讓其他帳號寫入；已略過所有應用設定。'})
            return catalog
        for name in sorted(os.listdir(dfd)):
            if not name.endswith('.json') or name.startswith('.'):
                continue
            problem = _load_one(catalog, dfd, name, paths, trusted_uid, user_lookup)
            if problem:
                catalog.problems.append(problem)
    finally:
        os.close(dfd)
    _drop_shared_data_dirs(catalog)
    return catalog


def _drop_shared_data_dirs(catalog):
    """Two apps of one owner must not declare overlapping host directories, nor a host directory that holds the
    other's config file (review L2): restoring one would replace the other's data. The later entry (file name order)
    is reported and not loaded."""
    kept = []
    for app_id in list(catalog):
        app = catalog[app_id]
        clash = None
        for other in kept:
            if other.owner != app.owner:
                continue
            pairs = [('主機資料夾', mine['path'], '', theirs['path']) for mine in app.data_dirs for theirs in other.data_dirs]
            pairs += [('主機資料夾', mine['path'], '設定檔', config['path']) for mine in app.data_dirs
                      for config in other.config_files]
            pairs += [('設定檔', config['path'], '主機資料夾', theirs['path']) for config in app.config_files
                      for theirs in other.data_dirs]
            clash = next(((other, *pair) for pair in pairs if paths_overlap(pair[1], pair[3])), None)
            if clash:
                break
        if clash is None:
            kept.append(app)
            continue
        other, my_kind, mine, their_kind, theirs = clash
        del catalog[app_id]
        catalog.problems.append({'file': f'{app_id}.json', 'id': app_id, 'code': 'invalid-request',
                                 'message': f'應用 {app_id} 的{my_kind} ~/{mine} 與應用 {other.id} 的{their_kind} ~/{theirs} '
                                            f'重疊（同一個擁有者），已略過 {app_id}.json。'})


def _load_one(catalog, dfd, name, paths, trusted_uid, user_lookup):
    guess = name[:-5]
    problem = {'file': name, 'id': guess if ID_RE.fullmatch(guess) else None}
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except OSError as error:
        if error.errno == errno.ELOOP:
            return {**problem, 'code': 'permission-denied', 'message': f'應用設定 {name} 不可為符號連結，已略過。'}
        return {**problem, 'code': 'permission-denied', 'message': f'無法讀取應用設定 {name}，已略過。'}
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return {**problem, 'code': 'invalid-request', 'message': f'應用設定 {name} 不是一般檔案，已略過。'}
        if st.st_uid != trusted_uid or st.st_mode & 0o022:
            return {**problem, 'code': 'permission-denied',
                    'message': f'應用設定 {name} 必須由 root 擁有且不可讓其他帳號寫入，已略過。'}
        if st.st_size > MAX_ENTRY_BYTES:
            return {**problem, 'code': 'limit-exceeded', 'message': f'應用設定 {name} 過大，已略過。'}
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ENTRY_BYTES:
                return {**problem, 'code': 'limit-exceeded', 'message': f'應用設定 {name} 過大，已略過。'}
            chunks.append(chunk)
    finally:
        os.close(fd)
    raw = b''.join(chunks)
    try:
        data = parse_json_bytes(raw)
    except (ValueError, UnicodeDecodeError):
        return {**problem, 'code': 'invalid-request', 'message': f'應用設定 {name} 不是有效的 JSON，已略過。'}
    try:
        app = validate_entry(data, paths=paths, sha256=hashlib.sha256(raw).hexdigest(), user_lookup=user_lookup)
    except BackupError as error:
        return {**problem, 'code': error.code, 'message': f'{name}：{error.message}'}
    if name != f'{app.id}.json':
        return {**problem, 'code': 'invalid-request', 'message': f'應用設定 {name} 的檔名必須是 {app.id}.json，已略過。'}
    if app.id in catalog:
        return {**problem, 'code': 'invalid-request', 'message': f'應用 {app.id} 重複定義，已略過 {name}。'}
    catalog[app.id] = app
    return None
