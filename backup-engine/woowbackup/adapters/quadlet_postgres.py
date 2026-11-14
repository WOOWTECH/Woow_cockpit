"""Quadlet + PostgreSQL + named volumes + Podman secrets + config files. Owner: E2.

Facts this adapter relies on (verified with Podman 4.9 rootless + systemd --user):
* `podman secret inspect --showsecret --format {{.SecretData}}` prints the exact secret bytes plus
  one trailing newline (binary-safe); the JSON form mangles non-UTF-8 bytes. Empty secrets and
  secrets >= 512000 bytes are rejected by `podman secret create`.
* `podman volume export` re-opens /dev/stdout and fails with EACCES on a root-owned fd, so exports
  run through the owner-side relay. `podman volume import` *merges* into a non-empty volume and
  accepts a truncated tar with exit 0 (integrity comes from the archive digests).
* Quadlet adds `--replace --rm` and `ExecStop=podman rm -v -f`; named volumes survive unit stops.
* The postgres image's first-start init server only listens on the Unix socket, so readiness is
  tested over TCP 127.0.0.1 inside the container.
* `systemctl --user mask` links the unit to /dev/null in ~/.config/systemd/user, which overrides the
  Quadlet generator's output, so a half-restored app cannot start at boot; `unmask` undoes it.
* `systemctl --user stop` of a unit that was never loaded exits 5; `podman image exists` exits 1
  for a missing image and 125 for an error.
* `podman load` and `podman volume import` follow symlinks planted in their input tar; both are
  only ever fed canonical tars written by `woowbackup.nested` (review finding SEC-1).
* `podman volume import` aborts half-way (exit 125, after `volume rm` + `create`) on a relative symlink that
  leaves the volume and on a member owner outside the owner's user namespace; `podman volume export` writes
  FIFOs and second names of a symlink (hard links) that the import accepts (review findings HD-02, HD-03).
* `podman save` names an image after the name a short ref resolves to (`postgres:16` ->
  `docker.io/library/postgres:16`); `podman load` and `podman tag` name a short ref `localhost/<ref>`, which a
  short-name lookup tries first (review finding HD-01) -- except for a short name with an alias
  (`/etc/containers/registries.conf.d/shortnames.conf`: ubuntu, python, node, alpine, ...): an existing image under
  the alias target (`docker.io/library/ubuntu:24.04`) wins over `localhost/ubuntu:24.04` (verified in the lab).
* Host directories (`data_dirs`, bind mounts `Volume=%h/<dir>:<path>`) hold files of the owner's subordinate ids
  (container users). Inside `podman unshare` the owner is uid 0 of his namespace: GNU tar (`--numeric-owner
  --xattrs`) then reads them with their namespace owners (33 for www-data, 70 for alpine's postgres), extracts them
  with those owners, modes (setgid directories included), nanosecond mtimes, hard links, symlinks, FIFOs, long and
  non-UTF-8 names and `user.*` xattrs; `trusted.*` xattrs cannot be set there; sockets are skipped with exit 0;
  `podman unshare` keeps HOME and passes the command's exit status and stdin through (all checked in the lab,
  podman 4.9.3, GNU tar 1.35). A restore extracts into `<dir>.woowbk-new-<job>` and swaps it in; the replaced copy
  `<dir>.woowbk-old-<job>` is deleted only after the job succeeded (CONTRACT section 9).
"""
import contextlib
import http.client
import json
import os
import platform
import re
import secrets
import socket
import stat
import time
import urllib.parse
from pathlib import Path

from .. import digests, nested
from ..archive import Entry
from ..catalog import DB_NAME_RE, digest_target, paths_overlap
from ..errors import BackupError
from ..podman import DEVNULL, CommandError, stderr_tail
from .base import Adapter

QUADLET_DIR = '.config/containers/systemd'
MAX_QUADLET_BYTES = 1024 * 1024
MAX_SECRET_BYTES = 511999  # podman: "secret data must be larger than 0 and less than 512000 bytes"
MAX_HTTP_BODY = 1024 * 1024
IMAGE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}\Z')
NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
ENTRY_RE = re.compile(r'apps/([a-z0-9][a-z0-9-]{1,40})/(images|postgres|volumes|dirs|secrets|config|quadlet|verify)/'
                      r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,200}\Z')
TOKEN_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,54}\Z')
CONTAINER_ID_RE = re.compile(r'[0-9a-f]{12,64}\Z')
ROLLBACK_SUFFIX = '-rollback'
ARCH = {'x86_64': 'amd64', 'aarch64': 'arm64', 'armv7l': 'arm', 'ppc64le': 'ppc64le', 's390x': 's390x'}

STOP_TIMEOUT = 180
START_TIMEOUT = 600
DUMP_TIMEOUT = 3 * 3600
EXPORT_TIMEOUT = 3 * 3600
IMAGE_TIMEOUT = 3600
RESTORE_TIMEOUT = 3 * 3600
SHORT_TIMEOUT = 60
PG_READY_TIMEOUT = 180
DB_SETTLE_TIMEOUT = 30
HEALTH_INTERVAL = 2.0
HINT_TIMEOUT = 3
SPACE_RESERVE = 512 * 1024 * 1024
SMALL_OUTPUT = 1024 * 1024        # psql, pg_isready, systemctl show, podman load --quiet
INSPECT_OUTPUT = 4 * 1024 * 1024  # podman image inspect
TAR_OVERHEAD = 1024               # per member of a volume export: 512-byte header + up to 511 bytes padding
# Per member of a host directory tar (GNU tar --format=posix): a PAX extended header (two blocks: its header and
# the atime/ctime/mtime records) before every member header, plus padding. Measured in the lab: 1,759 bytes per
# member for 33,662 small files.
DIR_TAR_OVERHEAD = 2048
# User objects in a database: relations and routines outside the system schemas, plus extensions besides plpgsql.
MAINTENANCE_OBJECTS_SQL = (
    "SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
    "AND n.nspname !~ '^pg_(toast|temp)') + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON "
    "n.oid = p.pronamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')) + "
    "(SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql')")
SNAPSHOT_CHANGED = ('資料核對快照在備份期間有變動（例如仍有寫入進行中，或設定在服務重新啟動時才生效）；'
                    '這份備份不含資料核對快照，還原後會略過資料比對。')
DIGEST_TYPES = ('postgres-digest', 'files-digest')
DIGEST_TIMEOUT = 3 * 3600
DIGEST_OUTPUT = 32 * 1024 * 1024  # psql's JSON answer of a digest query (about 120 bytes per table)
# A files-digest listing the owner side writes: at most this much, whatever the free space (review M4). 2,000,000
# entries (digests.MAX_ENTRIES) of about 300 bytes each fit; an owner cannot fill the disk through it.
DIGEST_LISTING_MAX = 1024 * 1024 * 1024
GLOBALS_MAX = 16 * 1024 * 1024    # a pg_dumpall --globals-only script
PG_ROLE_NAME_MAX = 63
# Database facts recorded for an instance-mode backup (names checked against catalog.DB_NAME_RE).
DATABASES_JSON_SQL = (
    "SELECT coalesce(json_agg(json_build_object('name', d.datname, 'owner', pg_get_userbyid(d.datdba), 'encoding', "
    "pg_encoding_to_char(d.encoding), 'template', d.datistemplate, 'connect', d.datallowconn, 'row', row_to_json(d)) "
    "ORDER BY d.datname), '[]'::json) FROM pg_database d")
EXTENSIONS_SQL = ("SELECT coalesce(json_agg(json_build_array(extname, extversion) ORDER BY extname), '[]'::json) "
                  "FROM pg_extension WHERE extname <> 'plpgsql'")
AVAILABLE_EXTENSIONS_SQL = "SELECT coalesce(json_agg(name ORDER BY name), '[]'::json) FROM pg_available_extensions"
ROLE_FLAGS_SQL = ("SELECT coalesce(json_agg(json_build_array(rolname, rolsuper, rolcanlogin) ORDER BY rolname), "
                  "'[]'::json) FROM pg_roles WHERE rolname !~ '^pg_'")
SUPERUSER_SQL = 'SELECT rolsuper FROM pg_roles WHERE rolname = current_user'
# The bootstrap superuser (the role initdb created, oid 10) next to the connecting role: an instance restore runs in
# a cluster the image just created, where only the bootstrap superuser exists (review F5).
BOOTSTRAP_SQL = 'SELECT json_build_array((SELECT rolname FROM pg_roles WHERE oid = 10), current_user)'
# Every database of an instance besides template0/template1: [name, template, accepts connections].
INSTANCE_CATALOG_SQL = ("SELECT coalesce(json_agg(json_build_array(datname, datistemplate, datallowconn) ORDER BY "
                        "datname), '[]'::json) FROM pg_database WHERE datname NOT IN ('template0', 'template1')")
# initdb time of the running cluster (the high 32 bits of its system identifier are the seconds of initdb).
CLUSTER_ID_SQL = "SELECT json_build_array((SELECT system_identifier FROM pg_control_system())::text)"
# The restore's own role after the roles script: still a superuser that can log in, sessions not read-only (L2, F8).
SESSION_STATE_SQL = ("SELECT json_build_array((SELECT rolsuper AND rolcanlogin FROM pg_roles WHERE rolname = "
                     "current_user), current_setting('default_transaction_read_only'))")
INSTANCE_MAINTENANCE_DB = 'template1'
LOCALE_RE = re.compile(r'[A-Za-z0-9_.@-]{0,100}\Z')
ENCODING_RE = re.compile(r'[A-Za-z0-9_]{1,32}\Z')
# Statements a pg_dumpall --globals-only script may hold (CONTRACT section 9, instance mode).
GLOBAL_STATEMENT_RE = re.compile(r'(SET|CREATE ROLE|ALTER ROLE|GRANT|REVOKE|COMMENT ON ROLE)\b')
SAFE_SETTINGS = frozenset({'SET default_transaction_read_only = off', "SET client_encoding = 'UTF8'",
                           'SET standard_conforming_strings = on'})
RESTRICT_RE = re.compile(r'\\(?:un)?restrict [A-Za-z0-9]{1,128}\Z')
# Role names a pg_dumpall script never uses as the target of CREATE/ALTER ROLE (they would hide which role changes).
RESERVED_ROLE_NAMES = frozenset({'CURRENT_USER', 'SESSION_USER', 'CURRENT_ROLE', 'ALL', 'PUBLIC'})
# Role settings that load server-side code at every session of that role.
LIBRARY_SETTINGS = frozenset({'session_preload_libraries', 'local_preload_libraries', 'shared_preload_libraries',
                              'dynamic_library_path', 'jit_provider'})


def _unprintable(text):
    return any(not ch.isprintable() for ch in text)


def _unquote_ident(text):
    """The role name of a (possibly double-quoted) SQL identifier, or None."""
    if text.startswith('"'):
        if len(text) < 2 or not text.endswith('"') or '"' in text[1:-1].replace('""', ''):
            return None
        return text[1:-1].replace('""', '"')
    return text.lower() if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_$]*', text) else None


def globals_statements(data, *, session_user=None):
    """The statements of a `pg_dumpall --globals-only` script, checked before psql ever reads it (instance mode).

    The archive's bytes are untrusted: a psql meta-command (`\\!`) would run a shell in the database container. So the
    script is scanned the way psql scans it: only standard string literals ('' escapes, after whitespace, `(`, `,` or
    `=`), double-quoted identifiers and `--` comments; a backslash outside them, block comments, dollar quoting and
    E''/U&'' strings are refused; the `\\restrict`/`\\unrestrict` lines PostgreSQL >= 16.10 writes are dropped (an older
    psql does not know them). Every statement must be SET (the three pg_dumpall writes), CREATE/ALTER ROLE, GRANT,
    REVOKE or COMMENT ON ROLE. With `session_user` (the restore's own superuser, already created by the image):
    its CREATE ROLE is dropped (reconciled by the ALTER ROLE that follows) and an ALTER ROLE that would take away its
    SUPERUSER or LOGIN is refused. Returns [statement text]; raises BackupError('incompatible')."""
    def refuse(reason):
        raise BackupError('incompatible', f'備份中的資料庫角色定義（pg_dumpall）無法安全執行：{reason}。')

    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        refuse('不是 UTF-8 文字')
    text = '\n'.join(line for line in text.split('\n') if not RESTRICT_RE.fullmatch(line))

    def quoted(start, quote, what):
        end = start + 1
        while True:
            end = text.find(quote, end)
            if end < 0:
                refuse(f'{what}沒有結束')
            if text[end + 1:end + 2] == quote:
                end += 2
                continue
            return end + 1

    statements, verbatim, tokens, word, i, n = [], [], [], [], 0, len(text)

    def flush():
        if word:
            tokens.append(''.join(word))
            word.clear()

    while i < n:
        ch = text[i]
        if ch == "'":
            if i and not (text[i - 1].isspace() or text[i - 1] in '(,='):
                refuse('含有不支援的字串寫法')  # E'', U&'' or another prefix: psql would read it differently
            end = quoted(i, "'", '字串')
            flush()
            tokens.append(text[i:end])
            verbatim.append(text[i:end])
            i = end
        elif ch == '"':
            end = quoted(i, '"', '名稱')
            if '\n' in text[i:end] or '\0' in text[i:end]:
                refuse('名稱含有控制字元')
            word.append(text[i:end])
            verbatim.append(text[i:end])
            i = end
        elif text.startswith('--', i):
            end = text.find('\n', i)
            i = n if end < 0 else end
        elif text.startswith('/*', i) or ch in '\\$\0&':
            # `&` only appears in U&"..." identifiers, which name a role the checks below would not recognize (L2)
            refuse('含有不支援的語法（註解區塊、反斜線命令、U& 名稱或特殊字串）')
        elif ch == ';':
            flush()
            if tokens:
                statements.append((''.join(verbatim).strip(), list(tokens)))
            verbatim, tokens = [], []
            i += 1
        else:
            verbatim.append(ch)
            if ch.isspace():
                flush()
            elif ch in '(),=':
                flush()
                tokens.append(ch)
            else:
                word.append(ch)
            i += 1
    flush()
    if tokens:
        refuse('最後一個敘述沒有結束')
    kept = []
    for statement, words in statements:
        # Keywords compare without regard to case, as PostgreSQL reads them (review L2, F8); quoted parts stay as written.
        upper = [word if word.startswith(("'", '"')) else word.upper() for word in words]
        head = ' '.join(upper)
        if not GLOBAL_STATEMENT_RE.match(head):
            refuse(f'含有角色以外的敘述（{words[0][:20]}）')
        if upper[0] == 'SET' and ' '.join(words) not in SAFE_SETTINGS:
            refuse('含有不支援的連線設定')
        if upper[0] in ('CREATE', 'ALTER') and len(words) > 2:
            target = words[2]
            if not target.startswith('"') and target.upper() in RESERVED_ROLE_NAMES:
                refuse('含有以 CURRENT_USER、SESSION_USER、ALL 等特殊名稱指定的角色')  # pg_dumpall names every role
            if upper[0] == 'ALTER' and 'RENAME' in upper[3:]:
                refuse('含有重新命名角色的敘述')
            if 'SET' in upper[3:]:
                at = upper.index('SET', 3)
                raw = words[at + 1] if len(words) > at + 1 else ''
                setting = _unquote_ident(raw) or raw.strip('"').lower()
                if setting in LIBRARY_SETTINGS:
                    refuse('含有載入程式庫的角色設定')  # e.g. session_preload_libraries runs code at every login
            name = _unquote_ident(target)
            if session_user is not None and name == session_user:
                if upper[0] == 'CREATE' and len(words) == 3:
                    continue  # the image created it; the ALTER ROLE that follows sets its attributes and password
                if any(word in ('NOSUPERUSER', 'NOLOGIN') for word in upper[3:]):
                    raise BackupError('incompatible', f'備份中的資料庫角色 {session_user} 不是可登入的超級使用者；以它還原整個'
                                                      '資料庫執行個體會失去管理權限，未做任何變更。')
        kept.append(statement)
    return kept


def globals_script(data, *, session_user=None):
    """The checked statements as a psql script (one per line)."""
    return ''.join(f'{statement};\n' for statement in globals_statements(data, session_user=session_user)).encode()


class _DeadlineSocket(socket.socket):
    """A socket whose every receive waits at most `per_op` seconds and never past `deadline` (monotonic):
    a peer that sends one byte at a time can no longer stretch one request without bound (review HD-07)."""

    per_op = 3.0
    deadline = 0.0

    def _arm(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('loopback request deadline exceeded')
        self.settimeout(min(self.per_op, remaining))

    def recv_into(self, buffer, nbytes=0, flags=0):
        self._arm()
        return super().recv_into(buffer, nbytes, flags)

    def recv(self, bufsize, flags=0):
        self._arm()
        return super().recv(bufsize, flags)


class _LoopbackConnection(http.client.HTTPConnection):
    def __init__(self, host, port, *, per_op, deadline):
        super().__init__(host, port, timeout=per_op)
        self._per_op, self._deadline = per_op, deadline

    def connect(self):
        error = OSError('no address')
        for family, kind, proto, _name, address in socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM):
            sock = _DeadlineSocket(family, kind, proto)
            sock.per_op, sock.deadline = self._per_op, self._deadline
            try:
                remaining = self._deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('loopback request deadline exceeded')
                sock.settimeout(min(self._per_op, remaining))
                sock.connect(address)
            except OSError as exc:
                sock.close()
                error = exc
                continue
            self.sock = sock
            return
        raise error


def loopback_get(url, timeout, *, read_body=True):
    """GET a catalog URL on the loopback interface only: no proxies, no redirects, bounded body, and at most
    `timeout` seconds in total (connect, headers and body; review finding HD-07). Non-2xx statuses come back
    with an empty body; `read_body=False` returns as soon as the status line and headers arrived."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != 'http' or parts.hostname not in ('127.0.0.1', 'localhost') or parts.username or parts.password:
        raise ValueError('only loopback http URLs are allowed')
    timeout = max(0.1, float(timeout))
    connection = _LoopbackConnection(parts.hostname, parts.port or 80, per_op=timeout,
                                     deadline=time.monotonic() + timeout)
    target = (parts.path or '/') + (f'?{parts.query}' if parts.query else '')
    try:
        connection.request('GET', target, headers={'User-Agent': 'woowtech-cockpit-backup', 'Accept': 'application/json',
                                                   'Connection': 'close'})
        response = connection.getresponse()
        if not 200 <= response.status < 300 or not read_body:
            return response.status, b''
        body = response.read(MAX_HTTP_BODY + 1)
        if len(body) > MAX_HTTP_BODY:
            raise ValueError('response too large')
        return response.status, body
    finally:
        connection.close()


def parse_unit_file(text):
    """Minimal systemd/Quadlet parser: {section: [(key, value), ...]} with continuation lines."""
    sections, current, pending = {}, None, ''
    for raw in text.splitlines():
        line = pending + raw.strip()
        pending = ''
        if line.endswith('\\'):
            pending = line[:-1] + ' '
            continue
        if not line or line[0] in '#;':
            continue
        if line.startswith('[') and line.endswith(']'):
            current = line[1:-1]
            sections.setdefault(current, [])
            continue
        if current is not None and '=' in line:
            key, value = line.split('=', 1)
            sections[current].append((key.strip(), value.strip()))
    return sections


def last_value(sections, section, key):
    values = [v for k, v in sections.get(section, []) if k == key]
    return values[-1] if values else None


def quadlet_unit(file_name):
    stem, kind = file_name.rsplit('.', 1)
    return f'{stem}.service' if kind == 'container' else f'{stem}-{kind}.service'


def _create(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    return os.fdopen(fd, 'wb')


def _write_private(path, data):
    with _create(path) as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def file_digest(path):
    import hashlib
    digest, size = hashlib.sha256(), 0
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _human(n):
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if n < 1024 or unit == 'TiB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024
    return str(n)


def pg_major(version_num):
    """Major version from `server_version_num` (160015 -> 16; 90624 -> 9, i.e. any 9.x is 9)."""
    return int(version_num) // 10000


def unsupported_major(major):
    """PostgreSQL before 10 (and the 906-style numbers older engines recorded for 9.6) is not supported."""
    return isinstance(major, int) and (major < 10 or major >= 100)


class QuadletPostgresAdapter(Adapter):
    name = 'quadlet-postgres'
    version = 1

    def __init__(self, app, runner, log, *, phase=None, checkpoint=None, writers_hook=None, imported_hook=None,
                 http_get=None, clock=None, sleep=None, runtime_ready=None, templates_uid=0, statvfs=None):
        super().__init__(app, runner, log, phase=phase, checkpoint=checkpoint, writers_hook=writers_hook,
                         imported_hook=imported_hook)
        self.http_get = http_get or loopback_get
        self.clock = clock or time.monotonic
        self.wall = time.time  # wall clock (an instance restore compares it with the cluster's initdb time)
        self.sleep = sleep or time.sleep
        self._runtime_ready_fn = runtime_ready
        self.templates_uid = templates_uid
        self.statvfs = statvfs or os.statvfs
        self._owner_ids = None
        self._nested_checked = {}  # nested tars already checked by this adapter (preflight, then restore)
        self._previous_tags = {}   # image name -> image id it pointed at before this restore moved it
        # Host directories: the job id names the restore's siblings (`<dir>.woowbk-new-<job>`, `-old-<job>`; a
        # rollback appends `-rollback`), so the recovery of a dead job finds exactly its own. flows sets it.
        self.job_id = None
        self._local_token = 'x' + secrets.token_hex(8)  # without a job (tests, direct use)
        self._dir_run = None      # 'restore' or 'rollback' once restore() touched host directories
        self._dir_new = set()     # directories whose new sibling this adapter may have left (being written)
        self._dir_reverting = set()  # directories a rollback is moving back (`revert`), until it returned
        self._measured = {}       # directory -> dir_measure() result of this backup (mount points refused)
        self._dir_space = {}      # directory -> (device, free bytes) of its parent, from the preflight
        self._dir_swapped = {}    # directory -> True when its previous copy was moved to the old sibling
        self._dirs_tracked = False  # restore() ran here: _dir_swapped names every directory it put in place
        self._staged = set()      # directories stage_dirs() wrote ahead (restore() only swaps them in)
        # Service availability (CONTRACT section 9): monotonic times of the first stop, of the moment every unit ran
        # again and of the first passing health check; the units a safety backup left stopped for the restore.
        self.timing = {}
        self.kept_stopped = []
        self._taken_over = []
        self.digest_results = []  # per digest check of the last restore: CONTRACT section 7 `verification[].checks`
        self.unstable_digests = []  # digest checks the last backup dropped because two reads differed (H2, F3)

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def qrel(name):
        return f'{QUADLET_DIR}/{name}'

    def runtime_ready(self):
        if self._runtime_ready_fn is not None:
            return bool(self._runtime_ready_fn())
        return os.path.exists(f'/run/user/{self.runner.uid}/bus')

    def _log_command_error(self, error):
        if isinstance(error, CommandError):
            for line in stderr_tail(error.stderr):
                self.log(f'  {line}')

    def unit_states(self, units):
        units = list(units)
        out = self.runner.systemctl('show', '--property=Id,LoadState,ActiveState,SubState', '--', *units,
                                    timeout=SHORT_TIMEOUT, max_output=SMALL_OUTPUT).stdout or b''
        blocks = [b for b in out.decode('utf-8', 'replace').split('\n\n') if b.strip()]
        states = {}
        for unit, block in zip(units, blocks):
            states[unit] = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        for unit in units:
            states.setdefault(unit, {'LoadState': 'not-found', 'ActiveState': 'inactive'})
        return states

    def aux_units(self):
        """Oneshot units Quadlet generates for .network/.volume/.pod files (RemainAfterExit=yes)."""
        return [quadlet_unit(name) for name in self.app.quadlet_files if not name.endswith('.container')]

    def _reset_aux_units(self):
        # A oneshot network unit stays "active (exited)" after its network was removed; stopping it makes
        # the next start of a dependent unit re-run `podman network create --ignore`.
        for unit in self.aux_units():
            self.runner.systemctl('stop', '--', unit, timeout=STOP_TIMEOUT, check=False)

    # ----------------------------------------------------------------- unit groups (CONTRACT section 9)
    def _unit_after(self, units):
        """{unit: units it waits for} for `units`, or None when that cannot be read: the units it is ordered after
        (systemd After=) and the units it requires (Requires=, BindsTo=). systemd starts a required unit side by side
        with its dependent unless After= orders them, and Quadlet does not add After= for Requires= (review L7); the
        engine used to start them one after the other, so it keeps waiting for them."""
        try:
            out = self.runner.systemctl('show', '--property=Id,After,Requires,BindsTo', '--', *units,
                                        timeout=SHORT_TIMEOUT, max_output=SMALL_OUTPUT).stdout or b''
        except BackupError:
            return None
        blocks = [block for block in out.decode('utf-8', 'replace').split('\n\n') if block.strip()]
        if len(blocks) != len(units):
            return None
        result = {}
        for unit, block in zip(units, blocks):
            fields = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
            if fields.get('Id') != unit:
                return None
            result[unit] = set(' '.join(fields.get(key, '') for key in ('After', 'Requires', 'BindsTo')).split())
        return result

    def start_groups(self, units):
        """`units` (any order) as consecutive groups that may start together, in catalog order.

        A unit whose Quadlet file orders it after other units of this app (After=) or requires them (Requires=,
        BindsTo=) waits only for those of them that are started here; a unit that names none of them waits for every
        unit before it in the catalog order (the catalog order is the fallback, as before). A catalog order that
        contradicts them, or dependencies that cannot be read, start one unit at a time."""
        wanted = set(units)
        order = [unit for unit in self.app.units if unit in wanted]
        if len(order) < 2:
            return [order] if order else []
        after = self._unit_after(order)
        if after is None:
            return [[unit] for unit in order]
        ours_all = set(self.app.units)
        levels = {}
        for index, unit in enumerate(order):
            ours = after.get(unit, set()) & ours_all
            if ours & set(order[index + 1:]):
                return [[item] for item in order]
            prerequisites = (ours & set(order[:index])) if ours else order[:index]
            levels[unit] = 1 + max((levels[item] for item in prerequisites), default=-1)
        groups = [[] for _ in range(max(levels.values()) + 1)]
        for unit in order:
            groups[levels[unit]].append(unit)
        return groups

    def _stop_units(self, units, *, label):
        """Stop `units` with one `systemctl --user stop`: systemd stops them side by side, dependents first."""
        wanted = set(units)
        order = [unit for unit in reversed(self.app.units) if unit in wanted]
        if not order:
            return
        for unit in order:
            self.log(f'{label} {unit}')
        self.runner.systemctl('stop', '--', *order, timeout=STOP_TIMEOUT + 60 * (len(order) - 1))

    def _start_units(self, units, *, attempts=1, before=None, after=None, failed_note=None, keep_going=True):
        """Start `units` group by group (start_groups), one `systemctl --user start` per group. With `attempts=2` a
        unit that did not start is tried once more on its own. A termination signal still starts the remaining groups
        (review CR-14). `keep_going=False` (a restore, which fails and rolls back anyway) stops after the first group
        with a unit that did not start. Returns (units that did not start, the termination exception or None) -- the
        caller raises."""
        failed, interrupted = [], None
        for group in self.start_groups(units):
            if failed and not keep_going:
                break
            if before:
                for unit in group:
                    self.log(f'{before} {unit}')
            try:
                result = self.runner.systemctl('start', '--', *group, timeout=START_TIMEOUT + 60 * (len(group) - 1),
                                               check=False)
                if result.returncode == 0:
                    pending = []
                else:
                    self._log_command_error(CommandError('systemctl start', returncode=result.returncode,
                                                         stderr=result.stderr))
                    pending = list(group) if len(group) == 1 else [
                        unit for unit, state in self.unit_states(group).items() if state.get('ActiveState') != 'active']
            except BaseException as exc:  # noqa: BLE001 - a signal or an error of the call itself
                if not isinstance(exc, BackupError):
                    interrupted = interrupted or exc
                    failed.extend(group)
                    continue
                self._log_command_error(exc)
                pending = list(group)
            for unit in pending:
                started = False
                for _attempt in range(attempts - 1):
                    try:
                        self.sleep(2)
                        self.runner.systemctl('start', '--', unit, timeout=START_TIMEOUT)
                        started = True
                        break
                    except BackupError as error:
                        self._log_command_error(error)
                    except BaseException as exc:  # termination signal: go on with the other units (CR-14)
                        interrupted = interrupted or exc
                        break
                if not started:
                    failed.append(unit)
                    if failed_note:
                        self.log(f'{failed_note} {unit}')
            if after:
                for unit in group:
                    if unit not in failed:
                        self.log(f'{after} {unit}')
        return failed, interrupted

    def take_over(self, units, first_stop):
        """The safety backup left `units` stopped for this restore (CONTRACT section 9); `first_stop` is when they
        stopped (monotonic), the start of the app's unavailability."""
        self._taken_over = [unit for unit in self.app.units if unit in set(units or ())]
        if first_stop is not None:
            self.timing['first_stop'] = first_stop

    def timing_report(self):
        """{'writer_pause_seconds', 'unavailable_seconds'} of the last backup or restore (None when not measured):
        writers stopped -> every unit running again, and first stop -> every health check passed."""
        first = self.timing.get('first_stop')
        started, healthy = self.timing.get('started'), self.timing.get('healthy')
        pause = round(max(0.0, started - first), 1) if first is not None and started is not None else None
        down = round(max(0.0, healthy - first), 1) if first is not None and healthy is not None else None
        return {'writer_pause_seconds': pause, 'unavailable_seconds': down}

    def _quadlet_presence(self):
        rels = {name: self.qrel(name) for name in self.app.quadlet_files}
        stats = self.runner.stat_files(list(rels.values()))
        return {name: stats.get(rel, {}).get('type', 'missing') for name, rel in rels.items()}

    def _read_owner_quadlets(self):
        return {name: self.runner.read_file(self.qrel(name), MAX_QUADLET_BYTES) for name in self.app.quadlet_files}

    def read_templates(self):
        """Trusted templates read by root from the root-owned template dir (never from an archive)."""
        app = self.app
        if not app.template_dir:
            raise BackupError('incompatible', f'應用「{app.name}」沒有部署範本，無法在尚未部署的設備上還原。', app=app.id)
        try:
            dfd = os.open(app.template_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise BackupError('incompatible', f'找不到應用「{app.name}」的部署範本目錄。', app=app.id) from None
        try:
            st = os.fstat(dfd)
            if st.st_uid != self.templates_uid or st.st_mode & 0o022:
                raise BackupError('permission-denied', '部署範本目錄必須由 root 擁有且不可讓其他帳號寫入。', app=app.id)
            result = {}
            for name in app.quadlet_files:
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
                except OSError:
                    raise BackupError('incompatible', f'部署範本缺少 {name}（或為符號連結）。', app=app.id) from None
                with os.fdopen(fd, 'rb') as handle:
                    fst = os.fstat(handle.fileno())
                    if not stat.S_ISREG(fst.st_mode) or fst.st_uid != self.templates_uid or fst.st_mode & 0o022:
                        raise BackupError('permission-denied', f'部署範本 {name} 必須是 root 擁有的一般檔案。', app=app.id)
                    data = handle.read(MAX_QUADLET_BYTES + 1)
                if len(data) > MAX_QUADLET_BYTES:
                    raise BackupError('limit-exceeded', f'部署範本 {name} 過大。', app=app.id)
                result[name] = data
            return result
        finally:
            os.close(dfd)

    def container_images(self, sources):
        """{unit: image ref} from `.container` sources; refs are validated before any use in argv."""
        images = {}
        for name in self.app.quadlet_files:
            if not name.endswith('.container') or name not in sources:
                continue
            sections = parse_unit_file(sources[name].decode('utf-8', 'replace'))
            ref = last_value(sections, 'Container', 'Image')
            if ref is None:
                continue
            if not IMAGE_RE.fullmatch(ref) or ref.endswith(('.image', '.build')):
                raise BackupError('incompatible', f'{name} 的 Image= 設定不受支援：{ref[:120]}', app=self.app.id)
            images[quadlet_unit(name)] = ref
        return images

    def _named_objects(self, sources):
        """Networks, volumes and pods that Quadlet creates for this app (for fresh-mode cleanup)."""
        found = {'network': [], 'volume': [], 'pod': []}
        for name, data in sources.items():
            stem, kind = name.rsplit('.', 1)
            if kind not in found:
                continue
            sections = parse_unit_file(data.decode('utf-8', 'replace'))
            key = {'network': 'NetworkName', 'volume': 'VolumeName', 'pod': 'PodName'}[kind]
            value = last_value(sections, kind.capitalize(), key) or f'systemd-{stem}'
            if NAME_RE.fullmatch(value):
                found[kind].append(value)
        return found

    def image_inspect(self, ref):
        result = self.runner.podman('image', 'inspect', ref, timeout=SHORT_TIMEOUT, check=False,
                                    max_output=INSPECT_OUTPUT)
        if result.returncode != 0:
            return None
        try:
            data = json.loads((result.stdout or b'[]').decode('utf-8'))[0]
        except (ValueError, IndexError, KeyError):
            return None
        image_id = str(data.get('Id') or '')
        if image_id and not image_id.startswith('sha256:'):
            image_id = 'sha256:' + image_id
        config = data.get('Config') or {}
        names = [name for name in data.get('RepoTags') or [] if isinstance(name, str) and 0 < len(name) <= 512][:64]
        return {'id': image_id, 'digest': str(data.get('Digest') or ''), 'arch': str(data.get('Architecture') or ''),
                'size': int(data.get('Size') or 0), 'env': list(config.get('Env') or []), 'names': names}

    @staticmethod
    def _bare_id(image_id):
        return image_id.split(':', 1)[1] if image_id.startswith('sha256:') else image_id

    def _image_exists(self, ref_or_id):
        """True/False from `podman image exists` (exit 0/1); any other exit status is an error, never "absent"."""
        result = self.runner.podman('image', 'exists', ref_or_id, timeout=SHORT_TIMEOUT, check=False)
        if result.returncode in (0, 1):
            return result.returncode == 0
        self._log_command_error(CommandError('image exists', returncode=result.returncode, stderr=result.stderr))
        raise BackupError('job-failed', f'無法確認映像 {ref_or_id[:120]} 是否存在（podman 結束碼 {result.returncode}）。',
                          app=self.app.id)

    def _image_pullable(self, ref):
        if ref.startswith('localhost/'):
            return False
        return self.runner.podman('manifest', 'inspect', ref, stdout=DEVNULL, timeout=90, check=False).returncode == 0

    @staticmethod
    def _env_pg_major(info):
        for item in (info or {}).get('env', []):
            if isinstance(item, str) and item.startswith('PG_MAJOR='):
                try:
                    return int(item.split('=', 1)[1].split('.')[0])
                except ValueError:
                    return None
        return None

    def psql_scalar(self, pg, sql, database=None):
        out = self.runner.podman('exec', pg['container'], 'psql', '-X', '-w', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                                 '-U', pg['user'], '-d', database or pg['database'], '-c', sql,
                                 timeout=SHORT_TIMEOUT, max_output=SMALL_OUTPUT).stdout or b''
        return out.decode('utf-8', 'replace').strip()

    def undeclared(self, pg):
        """(databases, roles) of the instance beyond the catalog's database, `postgres` and template0/template1, or
        None when the instance cannot be queried. An in-place restore rebuilds the whole data volume from one
        `pg_dump -d <database>`, so anything listed here would be lost (review finding CR-07).

        The shared catalogs are read through the catalog's own database, the one `pg_dump` uses (review finding
        HD-06: `-d postgres` failed where that database was dropped or closed to the app user, and the guard then
        let the restore delete every other database). Template-flagged databases count too, only template0 and
        template1 are skipped, by name.
        """
        try:
            databases = self.psql_scalar(pg, "SELECT datname FROM pg_database WHERE datname NOT IN ('template0', "
                                             "'template1') ORDER BY 1").splitlines()
            roles = self.psql_scalar(pg, "SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' "
                                         'AND rolname <> current_user ORDER BY 1').splitlines()
        except BackupError:
            return None
        extra = [name for name in databases if name and name not in (pg['database'], 'postgres')]
        return extra, [name for name in roles if name]

    def maintenance_objects(self, pg):
        """Number of tables, views, sequences, functions and extensions (besides plpgsql) stored in the instance's
        `postgres` database, which an in-place restore does not keep (e.g. pg_cron jobs; review finding HD-06);
        0 when that database does not exist, None when it cannot be read."""
        try:
            if 'postgres' not in self.psql_scalar(pg, 'SELECT datname FROM pg_database ORDER BY 1').splitlines():
                return 0
            value = self.psql_scalar(pg, MAINTENANCE_OBJECTS_SQL, database='postgres')
            return int(value or 0)
        except (BackupError, ValueError):
            return None

    def owner_ids(self):
        """(uid IdMap, gid IdMap) of the owner's rootless user namespace, read inside it (cached). Volume members
        must be owned by IDs in it, or `podman volume import` stops half-way (review finding HD-02)."""
        if self._owner_ids is None:
            maps = []
            for name in ('uid_map', 'gid_map'):
                out = self.runner.podman('unshare', 'cat', f'/proc/self/{name}', timeout=SHORT_TIMEOUT,
                                         max_output=SMALL_OUTPUT).stdout or b''
                ids = nested.IdMap(out.decode('utf-8', 'replace'))
                if not ids.ranges:
                    raise BackupError('job-failed', f'無法讀取帳號 {self.runner.owner} 的使用者命名空間 ID 對應。',
                                      app=self.app.id)
                maps.append(ids)
            self._owner_ids = tuple(maps)
        return self._owner_ids

    def _check_volume_entry(self, name, path, *, log=True):
        """Check one volume tar (cached per path); returns its nested.VolumeReport. Notes about what the canonical
        copy drops are kept in `self.warnings` (and logged unless the caller reports them; finding HD-09)."""
        key = ('volume', str(path))
        report = self._nested_checked.get(key)
        if report is None:
            report = nested.check_volume(path, ids=self.owner_ids())
            self._nested_checked[key] = report
            for note in report.warnings(name):
                if note not in self.warnings:
                    self.warnings.append(note)
                    if log:
                        self.log(f'注意：{note}')
        return report

    def _output_budget(self, folder):
        """Bytes a command may write into `folder` before only the reserve would be left (review finding SEC-3)."""
        try:
            st = self.statvfs(folder)
        except OSError:
            return None
        return max(0, st.f_bavail * st.f_frsize - SPACE_RESERVE)

    # ----------------------------------------------------------------- probe
    def probe(self):
        app = self.app
        units = [{'name': unit, 'active': False} for unit in app.units]
        if not self.runtime_ready():
            return {'deployed': False, 'state': 'error', 'units': units,
                    'problems': [f'帳號 {self.runner.owner} 的使用者服務管理器未啟動，請為此帳號啟用 linger。']}
        problems = []
        presence = self._quadlet_presence()
        present = [name for name, kind in presence.items() if kind == 'file']
        for name, kind in presence.items():
            if kind not in ('file', 'missing'):
                problems.append(f'Quadlet 設定檔 {name} 不是一般檔案或路徑含有符號連結。')
        if not present and not problems:
            return {'deployed': False, 'state': 'not-deployed', 'units': units, 'problems': []}
        missing = [name for name, kind in presence.items() if kind == 'missing']
        if missing:
            problems.append(f'部分 Quadlet 設定檔不存在：{", ".join(missing)}。')
        states = self.unit_states(app.units)
        units = [{'name': unit, 'active': states[unit].get('ActiveState') == 'active'} for unit in app.units]
        for unit in app.units:
            load = states[unit].get('LoadState')
            if load in ('not-found', 'error', 'bad-setting'):
                problems.append(f'找不到服務 {unit}；請確認 Quadlet 已載入（systemctl --user daemon-reload）。')
            elif load == 'masked':
                problems.append(f'服務 {unit} 已被暫時停用，表示先前的還原沒有完成；請使用還原前備份或同一份備份再次還原。')
        if problems:
            state = 'error'
        elif all(u['active'] for u in units):
            state = 'running'
        elif not any(u['active'] for u in units):
            state = 'stopped'
        else:
            state = 'partial'
        return {'deployed': True, 'state': state, 'units': units, 'problems': problems}

    def health_hint(self, timeout=HINT_TIMEOUT):
        """One quick health request per catalog check, for the status page: None when healthy, else zh-TW text.

        A unit can be active while the app is broken (lab H5: units active, /healthz 503).
        """
        for spec in self.app.health:
            try:
                # The status line is all the hint needs; the body is never read (review finding HD-07).
                status, _body = self.http_get(spec['url'], min(timeout, spec['timeout_seconds']), read_body=False)
            except Exception:  # noqa: BLE001 - any transport error means "not answering"
                return f'服務已啟動，但健康檢查沒有回應（{spec["url"]}）。'
            if status != spec['expect_status']:
                return f'服務已啟動，但健康檢查未通過（{spec["url"]}，HTTP {status}）。'
        return None

    def detect_mode(self):
        presence = self._quadlet_presence()
        kinds = set(presence.values())
        if kinds == {'file'}:
            return 'inplace'
        if kinds == {'missing'}:
            return 'fresh'
        raise BackupError('incompatible', f'應用「{self.app.name}」的 Quadlet 設定檔不完整或含有符號連結，'
                                          '無法判斷還原方式；請先修復部署。', app=self.app.id)

    def ensure_databases_running(self):
        """Start inactive database units (needed to dump a pre-restore safety backup); raises if they cannot run."""
        states = self.unit_states(self.app.units)
        started = []
        for pg in self.app.postgres:
            if states[pg['unit']].get('ActiveState') != 'active':
                self.log(f'啟動資料庫服務 {pg["unit"]}，以便建立還原前備份')
                self.runner.systemctl('start', '--', pg['unit'], timeout=START_TIMEOUT)
                started.append(pg['unit'])
            self._wait_for_postgres(pg)
        return started

    def estimate_bytes(self, *, include_images=False):
        total = 1024 * 1024
        for pg in self.app.postgres:
            try:
                if pg['scope'] == 'instance':
                    total += int(self.psql_scalar(pg, 'SELECT coalesce(sum(pg_database_size(datname)), 0) FROM pg_database '
                                                      "WHERE datname NOT IN ('template0', 'template1') AND datallowconn",
                                                  database=self._connect_db(pg['container'], pg['user'])) or 0)
                else:
                    total += int(self.psql_scalar(pg, 'SELECT pg_database_size(current_database())') or 0)
            except (BackupError, ValueError):
                raise BackupError('job-failed', f'無法讀取資料庫 {pg["id"]} 的大小；請確認資料庫服務正在執行。',
                                  app=self.app.id) from None
        for volume in self.app.volumes:
            total += self._volume_size(volume['name'])
        for item in self.app.data_dirs:
            # Read inside the owner's namespace without following links; a missing directory, one that is a symlink
            # or lies below one, and one that is or holds a mount point fail the backup here, before any writer stops.
            info = self._measure_dir(item['path'])
            total += info['bytes'] + DIR_TAR_OVERHEAD * info['members'] + 2 * 512
        if include_images:
            for ref in dict.fromkeys(self.container_images(self._read_owner_quadlets()).values()):
                info = self.image_inspect(ref)
                total += info['size'] if info else 0
        return total

    def _volume_size(self, name):
        """Size of the volume's export tar: file data plus a header and padding per member (review finding CR-15:
        `du --apparent-size` alone was ~10x too small for many small files)."""
        result = self.runner.podman('volume', 'inspect', '--format', '{{.Mountpoint}}', name,
                                    timeout=SHORT_TIMEOUT, check=False, max_output=SMALL_OUTPUT)
        mountpoint = (result.stdout or b'').decode('utf-8', 'replace').strip()
        if result.returncode != 0 or not mountpoint.startswith('/'):
            raise BackupError('not-deployed', f'找不到資料卷 {name}。', app=self.app.id, volume=name)
        values = []
        for options in (('-B1', '--apparent-size'), ('--inodes',)):
            du = self.runner.podman('unshare', 'du', '-s', *options, '--', mountpoint, timeout=600, check=False,
                                    max_output=SMALL_OUTPUT)
            try:
                values.append(int((du.stdout or b'').split()[0]))
            except (IndexError, ValueError):
                raise BackupError('job-failed', f'無法估算資料卷 {name} 的大小。', app=self.app.id) from None
        apparent, members = values
        return apparent + TAR_OVERHEAD * members + 2 * 512

    # ----------------------------------------------------------------- host directories
    def _dir_token(self, rollback=False):
        """Sibling token of this job's restore (or of its rollback)."""
        job = self.job_id if isinstance(self.job_id, str) and TOKEN_RE.fullmatch(self.job_id) else self._local_token
        return job + ROLLBACK_SUFFIX if rollback else job

    def _dir_tokens(self):
        return [self._dir_token(False), self._dir_token(True)]

    def swapped_dirs(self):
        """Directories whose content this adapter's restore replaced (for the rollback after a failure)."""
        return set(self._dir_swapped)

    def _running_mounts(self):
        """[(container, unit, [mount dicts])] of the owner's running containers, whatever started them (Quadlet
        Volume= or Mount=, a pod, PodmanArgs, by hand); review M5. A container that stopped between the listing and
        the inspection fails the inspection, which is retried once."""
        for attempt in (1, 2):
            listed = self.runner.podman('ps', '--format', '{{.ID}}', timeout=SHORT_TIMEOUT, check=False,
                                        max_output=SMALL_OUTPUT)
            ids = [line for line in (listed.stdout or b'').decode('ascii', 'replace').split()
                   if CONTAINER_ID_RE.fullmatch(line)]
            if listed.returncode != 0:
                continue
            if not ids:
                return []
            result = self.runner.podman('container', 'inspect', '--format',
                                        '{{json .Name}}\t{{json .Config.Labels}}\t{{json .Mounts}}', *ids,
                                        timeout=SHORT_TIMEOUT, check=False, max_output=INSPECT_OUTPUT)
            if result.returncode == 0:
                break
        else:
            raise BackupError('job-failed', '無法列出執行中的容器及其掛載，無法確認資料沒有被其他容器使用。',
                              app=self.app.id)
        containers = []
        try:
            for line in (result.stdout or b'').decode('utf-8').splitlines():
                if not line.strip():
                    continue
                name, labels, items = (json.loads(part) for part in line.split('\t'))
                unit = (labels or {}).get('PODMAN_SYSTEMD_UNIT') if isinstance(labels, dict) else None
                containers.append((str(name)[:128], unit if isinstance(unit, str) else None,
                                   [item for item in items or [] if isinstance(item, dict)]))
        except (ValueError, RecursionError, TypeError, AttributeError):
            raise BackupError('job-failed', '無法讀取執行中容器的掛載資訊，無法確認資料沒有被其他容器使用。',
                              app=self.app.id) from None
        return containers

    def _running_bind_mounts(self):
        """[(container, unit, path relative to the owner's home or '' for all of it, read-write)] of the bind mounts
        of the owner's running containers that reach into his home (review M5)."""
        home = self.runner.home.rstrip('/')
        mounts = []
        for name, unit, items in self._running_mounts():
            for item in items:
                if item.get('Type') != 'bind' or not isinstance(item.get('Source'), str):
                    continue
                source = os.path.normpath(item['Source'])
                if source == home or (home + '/').startswith(source.rstrip('/') + '/'):
                    rel = ''  # the whole home (or a directory above it)
                elif source.startswith(home + '/'):
                    rel = source[len(home) + 1:]
                else:
                    continue
                mounts.append((name, unit, rel, item.get('RW') is not False))
        return mounts

    def _require_unused_volumes(self, *, exclude):
        """A backup refuses a running container that the backup does not stop (its unit is not one of `exclude`) and
        that mounts one of the app's volumes read-write: it could write while the volume is exported, and the copy
        (and its files digest) would not match (review H2, F3; the host-directory rule is M5)."""
        names = {volume['name'] for volume in self.app.volumes}
        if not names:
            return
        problems = []
        for name, unit, items in self._running_mounts():
            if unit in exclude:
                continue
            for item in items:
                if item.get('Type') == 'volume' and item.get('Name') in names and item.get('RW') is not False:
                    owner = f'服務 {unit} 的容器 {name}' if unit else f'容器 {name}'
                    problems.append(f'{owner} 以可寫入方式掛載了資料卷 {item["Name"]}')
                    break
        if problems:
            raise BackupError('incompatible', f'{"；".join(problems[:4])}，備份時不會停止它；為避免資料不一致，已停止備份。'
                                              '請先停止它，或把它的服務加入這個應用的 writer_units（不寫入的容器可改為唯讀掛載 :ro）。',
                              app=self.app.id)

    def _dir_users(self, *, exclude=(), writable_only=False):
        """zh-TW problems naming the running containers, except those of the `exclude` units, that bind-mount one of
        the app's host directories (or a directory above it): they would keep writing while a backup reads, or keep
        the replaced copy open after a restore swapped the directory (review M5)."""
        if not self.app.data_dirs:
            return []
        problems = []
        for name, unit, rel, rw in self._running_bind_mounts():
            if unit in exclude or (writable_only and not rw):
                continue
            for item in self.app.data_dirs:
                if rel == '' or paths_overlap(rel, item['path']):
                    if rel == item['path']:
                        what = f'主機資料夾 ~/{rel}'
                    elif rel == '':
                        what = f'整個家目錄（包含主機資料夾 ~/{item["path"]}）'
                    else:
                        what = f' ~/{rel}（與主機資料夾 ~/{item["path"]} 重疊）'
                    owner = f'服務 {unit} 的容器 {name}' if unit else f'容器 {name}'
                    problems.append(f'{owner} {"以可寫入方式" if rw else ""}掛載了{what}')
                    break
        return problems

    def _require_unused_dirs(self, *, exclude, writable_only, when):
        problems = self._dir_users(exclude=exclude, writable_only=writable_only)
        if problems:
            advice = '請先停止它，或把它的服務加入這個應用的 writer_units' if when == '備份' else '請先停止它'
            raise BackupError('incompatible', f'{"；".join(problems[:4])}，{when}時不會停止它；為避免資料不一致或遺失，'
                                              f'已停止{when}。{advice}。', app=self.app.id)

    def _measure_dir(self, rel):
        """Measure a directory before a backup: refuse one that is a mount point or holds one (the restore swaps the
        directory as a whole within its parent; a mount point cannot be renamed, and content of another filesystem
        must neither be skipped silently nor be deleted with the replaced copy; review M2)."""
        info = self.runner.dir_measure(rel)
        if info['mount_root']:
            raise BackupError('incompatible', f'主機資料夾 ~/{rel} 是掛載點（另外掛載的檔案系統或 bind mount）；還原需要在同一個'
                                              '掛載中替換整個資料夾，這份備份將無法原位還原，因此沒有建立。請改為列出掛載點之內的資料夾。',
                              app=self.app.id, path=rel)
        if info['mounts']:
            more = f'等 {len(info["mounts"]) + info["more_mounts"]} 處' if info['more_mounts'] else ''
            raise BackupError('incompatible', f'主機資料夾 ~/{rel} 中有掛載點（~/{rel}/{info["mounts"][0]}{more}）；'
                                              '備份不會跨越掛載，還原也無法安全替換，因此沒有建立備份。'
                                              '請把掛載點之內的資料夾另外列為主機資料夾，或移除該掛載。',
                              app=self.app.id, path=rel)
        if info['acls']:
            self.log(f'注意：主機資料夾 ~/{rel} 有 {info["acls"]} 個項目設定了 POSIX ACL 權限；備份不包含 ACL，'
                     '還原後只有一般的擁有者與權限。')
        self._measured[rel] = info
        return info

    def _export_dir(self, index, item, staging):
        rel = item['path']
        dest = staging / 'dirs' / f'{index}.tar'
        self.log(f'匯出主機資料夾 ~/{rel}')
        with _create(dest) as handle:
            self.runner.dir_pack(rel, stdout=handle, timeout=EXPORT_TIMEOUT, max_output=self._output_budget(staging))
            handle.flush()
            os.fsync(handle.fileno())
        if dest.stat().st_size < 1024:
            raise BackupError('job-failed', f'主機資料夾 ~/{rel} 匯出結果不完整。', app=self.app.id, path=rel)
        return {'path': rel, 'index': index, 'file': dest}

    def _check_dir_entry(self, rel, path, *, log=True):
        """Check one host directory tar (cached per path) with the owner's ID map; returns its nested.VolumeReport.
        What the canonical copy drops is kept in `self.warnings` (and logged unless the caller reports it)."""
        key = ('dir', str(path))
        report = self._nested_checked.get(key)
        if report is None:
            report = nested.check_dir(path, ids=self.owner_ids())
            self._nested_checked[key] = report
            for note in report.warnings(f'~/{rel}'):
                if note not in self.warnings:
                    self.warnings.append(note)
                    if log:
                        self.log(f'注意：{note}')
        return report

    def _check_exported_dir(self, item):
        """A directory export is checked the way a restore checks it (like a volume export, review HD-02/HD-03)."""
        self.owner_ids()  # a failure to read the ID map keeps its own message
        try:
            report = self._check_dir_entry(item['path'], item['file'])
        except BackupError as error:
            details = error.details or {}
            if 'reason' not in details:
                raise
            label = details.get('label') or '格式不符'
            member = details.get('member')
            code = 'limit-exceeded' if details.get('reason') == 'too many members' else 'job-failed'
            raise BackupError(code, f'主機資料夾 ~/{item["path"]} 含有還原時無法寫入的內容（{label}'
                                    f'{"：" + str(member) if member else ""}），這份備份無法還原，因此沒有建立；'
                                    '應用已恢復執行。', app=self.app.id, path=item['path'],
                              reason=details.get('reason')) from None
        note = report.link_note(f'~/{item["path"]}')
        if note:
            self.log(f'注意：{note}')

    def _check_dir_targets(self, mode):
        """Before any change (also when a caller skipped the preflight): no directory may be a symlink, lie below
        one or be a mount point, and a fresh deployment never replaces a directory that holds something."""
        if not self.app.data_dirs:
            return
        states = self.runner.dir_states([item['path'] for item in self.app.data_dirs])
        for item in self.app.data_dirs:
            state = states.get(item['path']) or {}
            if state.get('type') not in ('dir', 'missing'):
                raise BackupError('incompatible', f'~/{item["path"]} 不是資料夾，或路徑中含有符號連結；未做任何變更。',
                                  app=self.app.id, path=item['path'])
            if state.get('mount'):
                raise BackupError('incompatible', f'~/{item["path"]} 是掛載點，無法以替換資料夾的方式還原；未做任何變更。',
                                  app=self.app.id, path=item['path'])
            if mode == 'fresh' and state.get('type') == 'dir' and not state.get('empty'):
                raise BackupError('incompatible', f'此設備已存在主機資料夾 ~/{item["path"]} 且不是空的；為避免覆寫既有資料，'
                                                  '未做任何變更。', app=self.app.id, path=item['path'])

    def _rollback_dir_plan(self, replaced):
        """For a rollback: {directory: 'revert' | 'extract' | 'keep'}. A directory the failed restore swapped still has
        its previous content next to it (`-old-<job>`), which simply moves back (review M3: no third copy, no space);
        one it replaced without such a copy is extracted from the safety backup; any other was never changed."""
        rels = [item['path'] for item in self.app.data_dirs]
        states = self.runner.dir_states(rels, tokens=self._dir_tokens())
        restore_token = self._dir_token(False)
        plan = {}
        for rel in rels:
            state = states.get(rel) or {}
            if {'kind': 'old', 'token': restore_token, 'type': 'dir'} in state.get('siblings') or []:
                plan[rel] = 'revert'
            elif rel in replaced or state.get('type') == 'missing':
                plan[rel] = 'extract'
            else:
                plan[rel] = 'keep'
        return plan

    def _unpack_dir(self, rel, path, *, rollback):
        """Write the canonical copy of a checked directory tar into `<rel>.woowbk-new-<token>` as the owner inside his
        namespace (missing parents are created). Nothing that exists changes."""
        token = self._dir_token(rollback)
        ids = self.owner_ids()
        self._dir_run = 'rollback' if rollback else 'restore'
        self._dir_new.add(rel)  # listed first: a failure part-way leaves a partial copy to remove
        self.log(f'寫入主機資料夾 ~/{rel}（先寫到 ~/{rel}.woowbk-new-{token}）')
        with nested.pipe_from(lambda out: nested.stream_dir(path, out, ids)) as feed:
            created = self.runner.dir_unpack(rel, token, input=feed, timeout=EXPORT_TIMEOUT)
        for parent in created:
            self.log(f'已以擁有者身分建立資料夾 ~/{parent}')

    def _swap_dir(self, rel, *, fresh, rollback):
        """Swap the written copy in: the current directory moves to `<rel>.woowbk-old-<token>` (fresh: an empty one is
        removed), the new one takes its name."""
        token = self._dir_token(rollback)
        swap = self.runner.dir_swap(rel, token, fresh=fresh)
        self._dir_new.discard(rel)
        self._dir_swapped[rel] = swap['replaced']
        if swap['replaced']:
            self.log(f'已還原主機資料夾 ~/{rel}；原內容暫時保留在 ~/{rel}.woowbk-old-{token}，作業成功後才刪除')
        else:
            self.log(f'已還原主機資料夾 ~/{rel}')

    def _revert_dir(self, rel):
        """Rollback: what the directory held before the failed restore moves back from `-old-<job>`; the failed
        restore's data moves to `-old-<job>-rollback` and is deleted once the rollback is verified."""
        self._dir_run = 'rollback'
        self._dir_reverting.add(rel)
        swap = self.runner.dir_revert(rel, self._dir_token(False), self._dir_token(True))
        self._dir_reverting.discard(rel)
        self._dir_swapped[rel] = swap['replaced']
        self.log(f'已把主機資料夾 ~/{rel} 還原前的內容移回（不需要重新寫入）')

    def finish_dirs(self):
        """Delete the copies this adapter's restore moved aside, once the job succeeded (or, for a rollback, once
        the rollback was verified: what it moved aside is the failed restore's data). Never the only copy of what a
        directory held before the job: such a copy that is still there is kept and reported. Returns zh-TW notes."""
        if not self._dir_swapped:
            return []
        rollback = self._dir_run == 'rollback'
        token, restore_token = self._dir_token(rollback), self._dir_token(False)
        notes = []
        for rel, replaced in self._dir_swapped.items():
            if replaced:
                notes.extend(self._drop_old(rel, token, '還原失敗時寫入的內容' if rollback else '原內容'))
        if rollback:
            try:
                states = self.runner.dir_states(list(self._dir_swapped), tokens=[restore_token])
            except BackupError:
                states = {}
            for rel in self._dir_swapped:
                if {'kind': 'old', 'token': restore_token, 'type': 'dir'} in (states.get(rel) or {}).get('siblings', []):
                    notes.append(f'主機資料夾 ~/{rel} 在還原前的原內容保留在 ~/{rel}.woowbk-old-{restore_token}；'
                                 '回復已改用還原前備份的內容，確認應用正常後可刪除這份。')
        self._dir_swapped = {}
        return notes

    def _drop_old(self, rel, token, what):
        try:
            self.runner.dir_drop(rel, 'old', token)
            self.log(f'已刪除 ~/{rel}.woowbk-old-{token}（{what}）')
            return []
        except BackupError as error:
            self._log_command_error(error)
            return [f'無法刪除 ~/{rel}.woowbk-old-{token}（{what}，{error.message.rstrip("。")}；刪除前會先改名為 '
                    f'~/{rel}.woowbk-del-{token}）；確認後可手動刪除。']

    def discard_dirs(self):
        """After a failure: put back a directory that was moved aside but not replaced (the content before the
        restore first), and remove the new copies this adapter was writing. Swapped directories stay (a rollback
        moves them back). Returns zh-TW problems."""
        rels = sorted(self._dir_new | self._dir_reverting)
        if not rels:
            return []
        token, restore_token = self._dir_token(self._dir_run == 'rollback'), self._dir_token(False)
        try:
            states = self.runner.dir_states(rels, tokens=self._dir_tokens())
        except BackupError as error:
            self._log_command_error(error)
            return [f'無法檢查主機資料夾 {"、".join("~/" + rel for rel in rels)}（{error.message.rstrip("。")}）']
        problems = []
        for rel in rels:
            state = states.get(rel) or {}
            siblings = {(item['kind'], item['token']) for item in state.get('siblings') or [] if item['type'] == 'dir'}
            try:
                for back in dict.fromkeys((restore_token, token)):
                    if state.get('type') == 'missing' and ('old', back) in siblings:
                        self.runner.dir_back(rel, back)
                        state = {**state, 'type': 'dir'}
                        self.log(f'已把 ~/{rel}.woowbk-old-{back} 移回 ~/{rel}')
                if ('new', token) in siblings:
                    self.runner.dir_drop(rel, 'new', token)
                    self.log(f'已移除沒寫完的 ~/{rel}.woowbk-new-{token}')
                self._dir_new.discard(rel)
                self._dir_reverting.discard(rel)
            except BackupError as error:
                self._log_command_error(error)
                problems.append(f'主機資料夾 ~/{rel}：{error.message.rstrip("。")}')
        return problems

    @staticmethod
    def _sibling_note(rel, item, restore_token):
        name = f'~/{rel}.woowbk-{item["kind"]}-{item["token"]}'
        if item['kind'] == 'new':
            return f'{name}（沒有換上的新內容，可刪除）'
        if item['kind'] == 'del':
            return f'{name}（刪除到一半的舊內容，可刪除）'
        if item['token'] == restore_token:
            return f'{name}（還原前的原內容，處理完成前請勿刪除）'
        return f'{name}（還原失敗時寫入的內容）'

    def dir_leftovers(self):
        """zh-TW notes naming the copies this job left next to the app's directories (after a failed rollback)."""
        if not self.app.data_dirs:
            return []
        tokens = self._dir_tokens()
        try:
            states = self.runner.dir_states([item['path'] for item in self.app.data_dirs], tokens=tokens)
        except BackupError:
            return []
        notes = []
        for item in self.app.data_dirs:
            rel = item['path']
            names = [self._sibling_note(rel, s, tokens[0]) for s in (states.get(rel) or {}).get('siblings') or []
                     if s['token'] in tokens]
            if names:
                notes.append(f'主機資料夾 ~/{rel} 旁留有這次還原的資料夾：{"、".join(names)}')
        return notes

    def recover_dirs(self):
        """Recovery of a dead job (`self.job_id`): bring every directory of this app to a safe final state.

        Per directory: deletions cut short (`-del-`) are finished; a missing directory gets a moved-aside copy back,
        the content before the restore (`-old-<job>`) before the failed restore's data (`-old-<job>-rollback`);
        new copies (being written, or written but never swapped in) are removed; moved-aside copies of a directory
        that exists are kept and reported by what they hold -- the only copy of earlier content is never deleted.
        Returns zh-TW notes (also problems)."""
        if not self.app.data_dirs:
            return []
        restore_token, rollback_token = self._dir_tokens()
        try:
            states = self.runner.dir_states([item['path'] for item in self.app.data_dirs],
                                            tokens=[restore_token, rollback_token])
        except BackupError as error:
            return [f'無法檢查「{self.app.name}」的主機資料夾（{error.message.rstrip("。")}），需人工確認']
        notes = []
        for item in self.app.data_dirs:
            rel = item['path']
            state = states.get(rel) or {}
            siblings = {(s['kind'], s['token']) for s in state.get('siblings') or [] if s['type'] == 'dir'}
            missing = state.get('type') == 'missing'
            try:
                for token in (restore_token, rollback_token):
                    if ('del', token) in siblings:
                        self.runner.dir_drop(rel, 'del', token)
                        notes.append(f'已刪除先前沒刪完的 ~/{rel}.woowbk-del-{token}（已不需要的舊內容）')
                for token in (restore_token, rollback_token):
                    if missing and ('old', token) in siblings:
                        self.runner.dir_back(rel, token)
                        siblings.discard(('old', token))
                        missing = False
                        what = '還原前的原內容' if token == restore_token else '還原失敗時寫入的內容（沒有找到還原前的原內容）'
                        notes.append(f'已把 ~/{rel} 移回{what}（~/{rel}.woowbk-old-{token}）')
                    if ('new', token) in siblings:
                        self.runner.dir_drop(rel, 'new', token)
                        notes.append(f'已移除沒寫完或未換上的 ~/{rel}.woowbk-new-{token}')
            except BackupError as error:
                notes.append(f'無法整理主機資料夾 ~/{rel}（{error.message.rstrip("。")}），需人工確認')
                continue
            if ('old', restore_token) in siblings:
                notes.append(f'~/{rel} 被還原取代前的原內容保留在 ~/{rel}.woowbk-old-{restore_token}，確認應用正常後可刪除')
            if ('old', rollback_token) in siblings:
                notes.append(f'~/{rel} 還原失敗時寫入的內容保留在 ~/{rel}.woowbk-old-{rollback_token}，確認不需要後可刪除')
        return notes

    # ----------------------------------------------------------------- data digests (CONTRACT sections 4, 5, 9)
    def digest_specs(self, kind=None):
        return [spec for spec in self.app.verify if spec['type'] in DIGEST_TYPES and (kind is None or spec['type'] == kind)]

    def _psql_json(self, container, user, database, sql, what):
        """One JSON value from psql, with the session settings that make `row::text` deterministic; the query goes on
        stdin (a list of relation ids can be long)."""
        result = self.runner.podman('exec', '-i', '-e', f'PGOPTIONS={digests.PG_OPTIONS}', '-e', 'PGCLIENTENCODING=UTF8',
                                    container, 'psql', '-X', '-w', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U', user,
                                    '-d', database, '-f', '-', input=sql.encode(), timeout=DIGEST_TIMEOUT,
                                    max_output=DIGEST_OUTPUT)
        return digests.parse_psql_json(result.stdout, what)

    def _connect_db(self, container, user):
        """`postgres`, or `template1` where that database was dropped: the database instance-wide statements use."""
        key = (container, user)
        cache = self.__dict__.setdefault('_connect_dbs', {})
        if key not in cache:
            for name in ('postgres', 'template1'):
                result = self.runner.podman('exec', container, 'psql', '-X', '-w', '-A', '-t', '-U', user, '-d', name,
                                            '-c', 'SELECT 1', timeout=SHORT_TIMEOUT, check=False,
                                            max_output=SMALL_OUTPUT)
                if result.returncode == 0:
                    cache[key] = name
                    break
            else:
                raise BackupError('job-failed', f'無法連線到容器 {container} 的資料庫（postgres、template1）。', app=self.app.id)
        return cache[key]

    def _digest_source(self, spec):
        """(container, user, scope) a postgres-digest reads: a pg_dump entry (`database`/`instance`) or a cold
        database container (`cold`)."""
        if spec['postgres']:
            pg = next(p for p in self.app.postgres if p['id'] == spec['postgres'])
            return pg['container'], pg['user'], pg['scope']
        return spec['container'], spec['user'], 'cold'

    def _instance_databases(self, container, user, connect, what):
        names = self._psql_json(container, user, connect, "SELECT coalesce(json_agg(datname ORDER BY datname), "
                                "'[]'::json) FROM pg_database WHERE NOT datistemplate AND datallowconn", what)
        if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
            raise digests.DigestError(f'{what}的資料庫清單格式不正確。')
        for name in names:
            if not DB_NAME_RE.fullmatch(name):
                raise BackupError('incompatible', f'資料庫名稱「{name[:63]}」含有不支援的字元（只支援英數字與 _ . $ -），'
                                                  '無法計算摘要或備份整個執行個體。', app=self.app.id)
        return names

    def _capture_pg_digest(self, spec, dest, *, databases=None, roles=None):
        """Write the postgres-digest listing of `spec` to `dest`; returns {databases, roles, summary, digest}.
        `databases`/`roles`: what the backup recorded (a restore reads the same; None: decide as at backup time)."""
        container, user, scope = self._digest_source(spec)
        what = f'資料庫摘要 {spec["id"]}'
        connect = self._connect_db(container, user) if scope != 'database' else None
        if databases is None:
            databases = (self._instance_databases(container, user, connect, what) if spec['databases'] == 'all'
                         else list(spec['databases']))
        tables = {}
        for name in databases:
            sql = digests.tables_sql()
            if spec['exclude_tables']:
                listed = self._psql_json(container, user, name, digests.LIST_SQL, what)
                if not isinstance(listed, list) or not all(isinstance(row, list) and len(row) == 3 and isinstance(
                        row[0], int) and isinstance(row[1], str) and isinstance(row[2], str) for row in listed):
                    raise digests.DigestError(f'{what}的資料表清單格式不正確。')
                sql = digests.tables_sql([row[0] for row in listed
                                          if not digests.excluded_table(spec['exclude_tables'], row[1], row[2])])
            tables[name] = self._psql_json(container, user, name, digests.in_snapshot(sql), what)
        if roles is None:
            # Roles are compared where a restore brings them back: a whole instance, or a cold copy read by a superuser.
            roles = scope == 'instance' or (scope == 'cold' and self._psql_json(
                container, user, connect, f'SELECT json_build_array(({SUPERUSER_SQL}))', what) == [True])
        role_rows = self._psql_json(container, user, connect or databases[0], digests.ROLES_SQL, what) if roles else None
        major = self._psql_json(container, user, connect or databases[0],
                                "SELECT json_build_array(current_setting('server_version_num'))", what)
        try:
            major = pg_major(major[0])
        except (TypeError, ValueError, IndexError, KeyError):
            raise digests.DigestError(f'{what}無法讀取 PostgreSQL 版本。') from None
        digests.write_lines(dest, digests.pg_lines(tables, role_rows))
        summary, digest = digests.read_pg_detail(dest, what=what)
        return {'databases': list(databases), 'roles': bool(roles), 'summary': summary, 'digest': digest,
                'server_major': major}

    def _volume_mountpoint(self, name):
        result = self.runner.podman('volume', 'inspect', '--format', '{{.Mountpoint}}', name,
                                    timeout=SHORT_TIMEOUT, check=False, max_output=SMALL_OUTPUT)
        mountpoint = (result.stdout or b'').decode('utf-8', 'replace').strip()
        if result.returncode != 0 or not mountpoint.startswith('/'):
            raise BackupError('not-deployed', f'找不到資料卷 {name}。', app=self.app.id, volume=name)
        return mountpoint

    def _listing_budget(self, folder):
        budget = self._output_budget(folder)
        return DIGEST_LISTING_MAX if budget is None else min(budget, DIGEST_LISTING_MAX)

    def _capture_files_digest(self, spec, dest, budget_dir):
        """Write the files-digest listing of `spec` to `dest` (read as the owner inside his namespace)."""
        what = f'資料卷 {spec["volume"]}' if spec['volume'] else f'主機資料夾 ~/{spec["data_dir"]}'
        budget = self._listing_budget(budget_dir)
        with _create(dest) as handle:
            try:
                if spec['volume']:
                    # Setuid/setgid of files are not compared: a volume restore drops them (CONTRACT section 5); the
                    # volume's top directory is not listed: `podman volume import` creates it anew.
                    self.runner.volume_digest(self._volume_mountpoint(spec['volume']), stdout=handle, nosetid=True,
                                              exclude=spec['exclude'], timeout=DIGEST_TIMEOUT, max_output=budget)
                else:
                    self.runner.dir_digest(spec['data_dir'], stdout=handle, root=True, exclude=spec['exclude'],
                                           timeout=DIGEST_TIMEOUT, max_output=budget)
            except BackupError as error:
                if error.code == 'insufficient-space' and budget == DIGEST_LISTING_MAX:
                    raise BackupError('limit-exceeded', f'{what}的資料摘要清單超過 1 GiB 的上限；請以 exclude 排除大量的小檔案'
                                                        '（例如快取），或移除這項資料摘要。', app=self.app.id) from None
                raise
            handle.flush()
            os.fsync(handle.fileno())
        summary, digest = digests.read_files_detail(dest, what=what)
        return {'summary': summary, 'digest': digest}

    def _capture_digests(self, specs, folder, suffix=''):
        """Backup: {check id: record} for `specs`, listings written to `folder/<id><suffix>.txt`."""
        records = {}
        for spec in specs:
            dest = Path(folder) / f'{spec["id"]}{suffix}.txt'
            if spec['type'] == 'files-digest':
                info = self._capture_files_digest(spec, dest, folder)
            else:
                info = self._capture_pg_digest(spec, dest)
            info['file'] = dest
            records[spec['id']] = info
            if not suffix:
                self.log(f'已計算資料摘要 {spec["id"]}（{digests.summary_text(spec["type"], info["summary"])}）')
        return records

    def _confirm_digests(self, specs, first, folder, reason):
        """Read `specs` a second time; keep the checks whose digest did not change since `first` (review H2, F3).

        A digest is read at a different moment than the dump or the copy it vouches for. Equal reads before and after
        that copy prove it holds the same data; when they differ (a writer the catalog does not stop, a job inside the
        database), the backup keeps no digest for the check -- otherwise every restore of the backup, and the rollback
        of a failed restore that depends on it, would fail the comparison. The backup itself is still made."""
        second = self._capture_digests(specs, folder)
        kept = {}
        for spec in specs:
            before, after = first.get(spec['id']), second.get(spec['id'])
            with contextlib.suppress(OSError):
                os.unlink(before['file'])
            if before['digest'] == after['digest'] and before.get('databases') == after.get('databases'):
                kept[spec['id']] = after
                continue
            with contextlib.suppress(OSError):
                os.unlink(after['file'])
            self.log(f'警告：資料摘要 {spec["id"]} 兩次讀取的結果不同（{reason}，例如有應用設定未停止的服務或排程仍在寫入）；'
                     '這份備份不含這項資料摘要，還原時不會比對它。請把寫入的服務加入 writer_units，或把變動的資料表或檔案排除。')
            self.unstable_digests.append(spec['id'])
        return kept

    def _digest_manifest(self, spec, record, entry):
        item = {'id': spec['id'], 'type': spec['type'], 'target': digest_target(spec),
                'exclude': list(spec['exclude'] if spec['type'] == 'files-digest' else spec['exclude_tables']),
                'summary': record['summary'], 'digest': record['digest'], 'entry': entry}
        if spec['type'] == 'postgres-digest':
            item.update(databases=record['databases'], roles=record['roles'])
            if isinstance(record.get('server_major'), int):
                item['server_major'] = record['server_major']
        return item

    def _verify_digests(self, app_manifest, root, work, kind):
        """After a restore, before the units that use the data start: read each `kind` digest again and compare it with
        the backup's. Appends to `digest_results`; raises BackupError on a difference (the caller rolls back)."""
        archived = {item.get('id'): item for item in app_manifest.get('verify_digests') or [] if isinstance(item, dict)}
        mismatches = []
        for spec in self.digest_specs(kind):
            result = {'id': spec['id'], 'type': kind, 'target': digest_target(spec), 'label': spec.get('label') or '',
                      'match': None, 'before': None, 'after': None, 'differences': None, 'note': None}
            self.digest_results.append(result)
            item = archived.get(spec['id'])
            exclude = spec['exclude'] if kind == 'files-digest' else spec['exclude_tables']
            if item is None or not isinstance(item.get('entry'), str):
                result['note'] = '備份沒有這個項目的資料摘要（例如較舊的備份），未比對。'
                continue
            if item.get('type') != kind or item.get('target') != digest_target(spec) or item.get('exclude') != exclude:
                result['note'] = '此設備的核對設定與備份時不同，未比對。'
                continue
            before_path = self.entry_path(root, item['entry'])
            read = digests.read_files_detail if kind == 'files-digest' else digests.read_pg_detail
            before, before_digest = read(before_path, what=f'備份中的資料摘要 {spec["id"]}')
            if before_digest != item.get('digest'):
                raise BackupError('corrupt-archive', f'備份中的資料摘要 {spec["id"]} 與記錄不符。', app=self.app.id)
            dest = Path(work) / f'{spec["id"]}.txt'
            if kind == 'files-digest':
                after = self._capture_files_digest(spec, dest, work)
            else:
                names = item.get('databases')
                if not isinstance(names, list) or not all(isinstance(n, str) and DB_NAME_RE.fullmatch(n) for n in names):
                    raise BackupError('corrupt-archive', f'備份中的資料摘要 {spec["id"]} 記錄格式不正確。', app=self.app.id)
                # Exactly the databases the backup read (also for "all"): a missing one fails, one the image created
                # at its first start that the backup never had is not part of the comparison.
                after = self._capture_pg_digest(spec, dest, databases=names, roles=bool(item.get('roles')))
                source = item.get('server_major')
                if (isinstance(source, int) and not isinstance(source, bool) and source < digests.FLOAT_TEXT_MAJOR
                        <= after['server_major']):
                    # Float values print differently from 12 on (review L4/F7): an exact comparison would fail.
                    result.update(before=before, after=after['summary'],
                                  note=f'備份來自 PostgreSQL {source}，此設備是 {after["server_major"]}；兩者的浮點數文字格式不同，'
                                       '這項資料摘要未比對。')
                    self.log(f'注意：資料摘要 {spec["id"]} 跨越 PostgreSQL 11 與 12 的格式差異，未比對')
                    continue
            result.update(before=before, after=after['summary'], match=after['digest'] == before_digest)
            if result['match']:
                self.log(f'資料摘要 {spec["id"]} 與備份時一致（{digests.summary_text(kind, before)}）')
                continue
            # A difference is read once more: data that is still changing (a writer the catalog does not stop, e.g. a
            # client of the running database between pg_restore and this read) makes the comparison meaningless, not
            # failed -- a rollback would meet the same writer and leave the app stopped and masked (lab 2026-11-14,
            # review H2). Equal reads that differ from the backup are a real difference.
            again_path = Path(work) / f'{spec["id"]}.again.txt'
            if kind == 'files-digest':
                again = self._capture_files_digest(spec, again_path, work)
            else:
                again = self._capture_pg_digest(spec, again_path, databases=item['databases'],
                                                roles=bool(item.get('roles')))
            if again['digest'] != after['digest']:
                note = (f'資料摘要 {spec["id"]} 在比對期間仍在變動（有應用設定未停止的寫入者，例如其他容器或排程），無法比對，'
                        '這一項未比對；請把寫入者加入 writer_units。')
                result.update(match=None, after=again['summary'], note=note)
                self.log(f'警告：{note}')
                if note not in self.warnings:
                    self.warnings.append(note)
                continue
            result['differences'] = digests.diff(kind, before_path, dest)
            counts = result['differences']
            sample = counts['samples'][0] if counts['samples'] else None
            text = (f'{spec["id"]}：遺失 {counts["missing"]}、多出 {counts["extra"]}、不同 {counts["changed"]}'
                    + (f'（例如 {sample["item"]}：{sample["detail"]}）' if sample else ''))
            self.log(f'資料摘要不一致：{text}')
            mismatches.append(text)
        if mismatches:
            raise BackupError('job-failed', f'應用「{self.app.name}」還原後的資料與備份時不一致：{"；".join(mismatches)[:600]}',
                              app=self.app.id)

    # ----------------------------------------------------------------- backup
    def backup(self, staging_dir, *, include_images, keep_stopped=False):
        """Back up the app into `staging_dir`; returns (manifest app section, [Entry]).

        The writers stop with one `systemctl --user stop` (a cold database whose digest is read stops in a second one,
        right after its digest); dumps, exports and digests are taken while they are stopped. `keep_stopped` (a
        pre-restore safety backup): the writers stay stopped for the restore that follows (`kept_stopped`), so the
        http-json snapshot cannot be confirmed and is not stored -- the digests are exact anyway."""
        app = self.app
        staging = Path(staging_dir)
        staging.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.timing, self.kept_stopped, self.unstable_digests = {}, [], []
        info = self.probe()
        if not info['deployed']:
            raise BackupError('not-deployed', f'應用「{app.name}」尚未部署在此設備，無法備份。', app=app.id)
        if info['problems']:
            raise BackupError('job-failed', f'應用「{app.name}」狀態異常：{info["problems"][0]}', app=app.id)
        active = {u['name']: u['active'] for u in info['units']}
        was_running = all(active.get(unit) for unit in app.units)
        for pg in app.postgres:
            if not active.get(pg['unit']):
                raise BackupError('job-failed', f'資料庫服務 {pg["unit"]} 未執行，無法匯出資料庫。', app=app.id)
        quadlets = self._read_owner_quadlets()
        images = []
        for ref in dict.fromkeys(self.container_images(quadlets).values()):
            image = self.image_inspect(ref)
            if image is None:
                raise BackupError('job-failed', f'找不到應用使用的映像 {ref}。', app=app.id)
            images.append({'ref': ref, **image})
        for pg in app.postgres:
            if pg['scope'] == 'instance':
                continue  # every database and every role of the instance is in the backup
            found = self.undeclared(pg)
            if found and found[0]:
                self.log(f'注意：資料庫執行個體中還有應用設定未宣告的資料庫（{", ".join(found[0][:10])}），不會包含在備份中。')
            if found and found[1]:
                self.log(f'注意：資料庫角色 {", ".join(found[1][:10])} 不會包含在備份中。')
            objects = self.maintenance_objects(pg)
            if objects:
                self.log(f'注意：資料庫執行個體的 postgres 資料庫中有 {objects} 個資料表、函式或擴充功能（例如排程工作），'
                         '不會包含在備份中。')
        writers = [unit for unit in app.units if unit in app.writer_units and active.get(unit)]
        for item in app.data_dirs:
            if item['path'] not in self._measured:  # estimate_bytes() measured it in a backup job already
                self._measure_dir(item['path'])
        # A running container that writes into a host directory and is not stopped would make its copy inconsistent
        # (also a SQLite database or a PostgreSQL data directory read while it changes): refused (review M5).
        self._require_unused_dirs(exclude=set(writers), writable_only=True, when='備份')
        self._require_unused_volumes(exclude=set(writers))
        snapshot = self._snapshot_for_backup()
        cold = [spec for spec in self.digest_specs('postgres-digest') if spec['container']]
        for spec in cold:
            if not active.get(spec['unit']):
                self.log(f'注意：資料庫服務 {spec["unit"]} 未執行，這份備份不含資料摘要 {spec["id"]}。')
        cold = [spec for spec in cold if active.get(spec['unit'])]
        cold_units = {spec['unit'] for spec in cold}
        for sub in ('postgres', 'volumes', 'dirs', 'secrets', 'config', 'quadlet', 'images', 'verify'):
            (staging / sub).mkdir(mode=0o700, exist_ok=True)

        stopped, records = [], {}
        self.phase('stop')
        if writers:
            self.writers_hook(list(writers))
            self.timing['first_stop'] = self.clock()
        started_at = self.clock()
        try:
            first = [unit for unit in writers if unit not in cold_units]
            # Listed before the stop: a signal while systemd stops them must still restart them (review CR-14).
            stopped.extend(first)
            self._stop_units(first, label='暫停寫入服務')
            verify_dir = staging / 'verify'
            if cold_units:
                # A cold database is read while the apps that use it are stopped, right before it stops itself: the
                # files copied next hold that state. It is read twice; a database that changed in between (a client
                # or a job the catalog does not stop) keeps no digest (review H2, F3).
                first_read = self._capture_digests(cold, verify_dir, suffix='.first')
                records.update(self._confirm_digests(cold, first_read, verify_dir, '資料庫在讀取摘要期間有變動'))
                second = [unit for unit in writers if unit in cold_units]
                stopped.extend(second)
                self._stop_units(second, label='暫停寫入服務')
            self.phase('dump')
            exported_pg = [spec for spec in self.digest_specs('postgres-digest') if spec['postgres']]
            # Read before and after the dumps: equal digests prove the dumps in between hold that exact data; a
            # database something else wrote to meanwhile keeps no digest instead of failing every restore (H2, F3).
            first_read = self._capture_digests(exported_pg, verify_dir, suffix='.first')
            dumps = [self._dump_instance(pg, staging) if pg['scope'] == 'instance' else self._dump_database(pg, staging)
                     for pg in app.postgres]
            records.update(self._confirm_digests(exported_pg, first_read, verify_dir, '資料庫在匯出期間有變動'))
            self.phase('export')
            file_specs = self.digest_specs('files-digest')
            first_read = self._capture_digests(file_specs, verify_dir, suffix='.first')
            volumes = [self._export_volume(v['name'], staging) for v in app.volumes]
            dirs = [self._export_dir(i, item, staging) for i, item in enumerate(app.data_dirs)]
            secrets = [self._read_secret(s['name'], staging) for s in app.secrets]
            configs = [self._read_config(i, c, staging) for i, c in enumerate(app.config_files)]
            for name in app.quadlet_files:
                _write_private(staging / 'quadlet' / name, quadlets[name])
            records.update(self._confirm_digests(file_specs, first_read, verify_dir, '檔案在匯出期間有變動'))
        except BaseException as error:
            self._log_command_error(error)
            # The job's active phase stays the one that failed (e.g. dump); moving on to 'start' here made the
            # page show "恢復應用" as the failed step while the writers were in fact restarted (lab H3).
            self._restart_writers(stopped, started_at, raise_errors=False, report_phase=False)
            if isinstance(error, Exception):  # not on termination signals: the system may be going down
                self._restart_lost_databases(active, stopped)
            raise
        if keep_stopped:
            # Handed over to the restore that follows (CONTRACT section 9): stopped once for both.
            self.kept_stopped = list(stopped)
            self.last_downtime = 0.0
            if stopped:
                self.log(f'寫入服務 {", ".join(stopped)} 維持停止，由接下來的還原接手')
        else:
            self._restart_writers(stopped, started_at, raise_errors=True)
        # Each export is checked the way a restore checks it, once the writers run again: content podman cannot
        # import, or more members than a restore accepts, fails this backup now instead of every restore of it
        # (review findings HD-02, HD-03).
        for volume in volumes:
            self._check_exported_volume(volume)
        for item in dirs:
            self._check_exported_dir(item)
        if keep_stopped:
            if snapshot:
                # Without a digest the rollback compares no data: the preflight says so before the restore starts
                # (`rollback-unverified`, review F16); the downtime of a second stop is not traded for it.
                self.log('應用維持停止，無法再次確認資料核對快照；這份還原前備份不含資料核對快照'
                         + ('，回復時以資料摘要核對。' if records else '，還原失敗而回復時只以健康檢查確認，不比對資料。'))
            snapshot = {}
        elif was_running:
            self._log_health_after_backup()
            snapshot = self._confirm_snapshot(snapshot)
        else:
            # Waiting out the catalog health timeout for an app that was already down only delays the job
            # (e.g. the safety backup taken before restoring an app a killed restore left stopped). The snapshot
            # is still confirmed (review finding HD-05), retried while the restarted writers come up.
            self.log('備份前應用並未完整執行，略過備份後的健康檢查。')
            snapshot = self._confirm_snapshot(snapshot, wait=True)

        if include_images:
            for i, image in enumerate(images):
                image['file'] = self._save_image(i, image, staging)

        entries = []

        def entry(kind, name, path):
            size, digest = file_digest(path)
            item = Entry(path=f'apps/{app.id}/{kind}/{name}', source=Path(path), size=size, sha256=digest)
            entries.append(item)
            return item.path

        manifest = {
            'id': app.id, 'name': app.name, 'adapter': self.name, 'adapter_version': self.version,
            'catalog_sha256': app.sha256, 'owner': {'name': self.runner.owner, 'uid': self.runner.uid},
            'images': [], 'postgres': [], 'volumes': [], 'secrets': [], 'config_files': [], 'quadlet_files': [],
            'verify_snapshot': snapshot,
        }
        for dump in dumps:
            if dump.get('scope') == 'instance':
                manifest['postgres'].append(self._instance_manifest(dump, entry))
                continue
            manifest['postgres'].append({'id': dump['id'], 'database': dump['database'],
                                         'server_version': dump['server_version'], 'major': dump['major'],
                                         'entry': entry('postgres', f'{dump["id"]}.dump', dump['file'])})
        for volume in volumes:
            manifest['volumes'].append({'name': volume['name'],
                                        'entry': entry('volumes', f'{volume["name"]}.tar', volume['file'])})
        if app.data_dirs:
            # Only apps with host directories carry the key: other archives stay readable by older engines.
            manifest['data_dirs'] = [{'path': item['path'], 'entry': entry('dirs', f'{item["index"]}.tar', item['file'])}
                                     for item in dirs]
        for secret in secrets:
            manifest['secrets'].append({'name': secret['name'], 'entry': entry('secrets', secret['name'], secret['file'])})
        for i, config in enumerate(configs):
            manifest['config_files'].append({'path': config['path'], 'mode': config['mode'],
                                             'entry': entry('config', str(i), config['file'])})
        for name in app.quadlet_files:
            manifest['quadlet_files'].append({'name': name, 'entry': entry('quadlet', name, staging / 'quadlet' / name)})
        if records:
            # Only apps with digest checks carry the key (like data_dirs): other manifests keep their shape.
            manifest['verify_digests'] = [
                self._digest_manifest(spec, records[spec['id']],
                                      entry('verify', f'{spec["id"]}.txt', records[spec['id']]['file']))
                for spec in self.digest_specs() if spec['id'] in records]
        for i, image in enumerate(images):
            item = {'ref': image['ref'], 'id': image['id'], 'digest': image['digest'], 'arch': image['arch']}
            if image.get('file'):
                item['entry'] = entry('images', f'{i}.oci.tar', image['file'])
            manifest['images'].append(item)
        return manifest, entries

    def _snapshot_for_backup(self):
        if not self.http_specs():
            return {}
        try:
            return self.verify_snapshot()
        except BackupError as error:
            self.log(f'警告：無法取得備份時的資料核對快照（{error.message}）；還原後將無法比對資料。')
            return {}

    def _confirm_snapshot(self, first, *, wait=False):
        """Keep the pre-stop snapshot only if the app reports the same values once it runs again.

        The snapshot is read from the running app before the writers stop, so a write committed in
        between (or a setting applied only at restart) is in the dump but not in the snapshot, and every
        restore of that backup would fail its data check (review finding CR-04). Equal snapshots before
        the stop and after the restart prove the dump in between has the same values. This holds for an app
        that was only partly running too (review finding HD-05); its health was not awaited, so with `wait` the
        second read is retried up to the catalog's health timeout.
        """
        if not first:
            return first
        limit = max((spec['timeout_seconds'] for spec in self.app.health), default=60) if wait else 0
        deadline = self.clock() + limit
        while True:
            try:
                second = self.verify_snapshot()
                break
            except BackupError as error:
                if self.clock() >= deadline:
                    self.log(f'警告：無法在服務恢復後再次取得資料核對快照（{error.message}）；這份備份不含資料核對快照。')
                    return {}
                self.sleep(HEALTH_INTERVAL)
        if second != first:
            self.log(SNAPSHOT_CHANGED)
            return {}
        return first

    def _restart_writers(self, stopped, started_at, *, raise_errors, report_phase=True):
        if report_phase:
            self.phase('start')
        # Side by side where the units' dependencies allow (start_groups); a unit that does not start is tried once
        # more on its own, and a termination signal still starts the remaining writers (review CR-14).
        failed, interrupted = self._start_units(stopped, attempts=2, after='已恢復服務', failed_note='無法重新啟動服務')
        # Downtime caused by the backup: none when no writer had to be stopped (it was not running).
        now = self.clock()
        self.last_downtime = max(0.0, now - started_at) if stopped else 0.0
        if stopped:
            self.timing['started'] = now
            self.writers_hook(failed)
        if interrupted is not None:
            raise interrupted
        if failed and raise_errors:
            raise BackupError('job-failed', f'備份後無法重新啟動服務：{", ".join(failed)}；請到服務頁檢查。',
                              app=self.app.id, units=failed)

    def _restart_lost_databases(self, was_active, writers):
        """After a failed backup: start a database unit that ran before the backup but stopped during it.

        Lab H3: the database shut down while pg_dump ran; the writer restart raced the container's exit, so
        the app came back without its database. Waits (bounded) until the unit settles, starts it when it
        is down and then restarts the writers so they reconnect. Never raises: the backup error stands.
        """
        restarted = False
        for pg in self.app.postgres:
            unit = pg['unit']
            if not was_active.get(unit):
                continue
            deadline = self.clock() + DB_SETTLE_TIMEOUT
            try:
                while True:
                    state = self.unit_states([unit])[unit].get('ActiveState')
                    if state in ('inactive', 'failed'):
                        self.log(f'資料庫服務 {unit} 在備份過程中停止，正在重新啟動')
                        self.runner.systemctl('start', '--', unit, timeout=START_TIMEOUT)
                        self._wait_for_postgres(pg)
                        self.log(f'已重新啟動資料庫服務 {unit}')
                        restarted = True
                        break
                    if state == 'active' and self._postgres_ready(pg):
                        break
                    if self.clock() >= deadline:
                        self.log(f'警告：資料庫服務 {unit} 目前狀態為 {state}，請到服務頁檢查。')
                        break
                    self.sleep(1)
            except BackupError as error:
                self._log_command_error(error)
                self.log(f'警告：無法重新啟動資料庫服務 {unit}，請到服務頁檢查。')
        if restarted:
            for unit in [u for u in self.app.units if u in writers]:
                try:
                    self.runner.systemctl('restart', '--', unit, timeout=START_TIMEOUT)
                    self.log(f'已重新啟動服務 {unit}，以便重新連線資料庫')
                except BackupError as error:
                    self._log_command_error(error)
                    self.log(f'警告：無法重新啟動服務 {unit}，請到服務頁檢查。')

    def _log_health_after_backup(self):
        for check in self.health():
            if check['status'] != 'ok':
                self.log(f'警告：{check["message"]}')

    def _dump_database(self, pg, staging):
        version, major = self._server_version(pg, pg['database'])
        dest = staging / 'postgres' / f'{pg["id"]}.dump'
        self.log(f'匯出資料庫 {pg["id"]}（{pg["database"]}，PostgreSQL {version}）')
        self._pg_dump(pg, pg['database'], dest, staging)
        return {'id': pg['id'], 'database': pg['database'], 'server_version': version, 'major': major, 'file': dest}

    def _pg_dump(self, pg, database, dest, staging):
        """`pg_dump -Fc` of one database into `dest`, then a full read of it."""
        with _create(dest) as handle:
            self.runner.podman('exec', pg['container'], 'pg_dump', '-w', '-U', pg['user'], '-d', database, '-Fc',
                               stdout=handle, timeout=DUMP_TIMEOUT, max_output=self._output_budget(staging))
            handle.flush()
            os.fsync(handle.fileno())
        if dest.stat().st_size == 0:
            raise BackupError('job-failed', f'資料庫 {pg["id"]}（{database}）匯出結果為空。', app=self.app.id)
        # A full read (SQL script to /dev/null) decompresses every data block. `pg_restore --list` only reads
        # the table of contents and accepted a dump cut in half with exit status 0 (lab H3): the backup was
        # listed as verified and its restore failed.
        with open(dest, 'rb') as handle:
            self.runner.podman('exec', '-i', pg['container'], 'pg_restore', '-f', '/dev/null', input=handle,
                               stdout=DEVNULL, timeout=DUMP_TIMEOUT)
        self.log(f'資料庫 {pg["id"]}（{database}）匯出完成並通過完整讀取檢查（{_human(dest.stat().st_size)}）')

    def _server_version(self, pg, database):
        number = self.psql_scalar(pg, 'SHOW server_version_num', database=database)
        version = self.psql_scalar(pg, 'SHOW server_version', database=database).split(' ')[0][:32]
        try:
            major = pg_major(number)
        except ValueError:
            raise BackupError('job-failed', f'無法判斷資料庫 {pg["id"]} 的版本。', app=self.app.id) from None
        if unsupported_major(major):
            raise BackupError('incompatible', f'資料庫 {pg["id"]} 是 PostgreSQL {version}；PostgreSQL 10 以前的版本不受支援。',
                              app=self.app.id)
        return version, major

    def _dump_instance(self, pg, staging):
        """Instance mode (CONTRACT section 9): the roles with their password hashes (`pg_dumpall --globals-only
        --no-tablespaces`, checked like a restore checks it) and every database that accepts connections
        (`pg_dump -Fc` each, while the writers are stopped and the database keeps running)."""
        what = f'資料庫 {pg["id"]}'
        container, user = pg['container'], pg['user']
        connect = self._connect_db(container, user)
        version, major = self._server_version(pg, connect)
        if self._psql_json(container, user, connect, f'SELECT json_build_array(({SUPERUSER_SQL}))', what) != [True]:
            raise BackupError('incompatible', f'資料庫 {pg["id"]} 設定為備份整個執行個體，但帳號 {user} 不是資料庫超級使用者'
                                              '（讀取角色與密碼需要）。', app=self.app.id)
        bootstrap = self._bootstrap_user(container, user, connect, what)
        if bootstrap != user:
            raise BackupError('incompatible', self._bootstrap_message(pg, bootstrap), app=self.app.id)
        rows = self._psql_json(container, user, connect, DATABASES_JSON_SQL, what)
        if not isinstance(rows, list) or len(rows) > 1000 or not all(isinstance(row, dict) for row in rows):
            raise digests.DigestError(f'{what}的資料庫清單格式不正確。')
        databases = []
        for row in rows:
            name, raw = row.get('name'), row.get('row') if isinstance(row.get('row'), dict) else {}
            if not isinstance(name, str):
                raise digests.DigestError(f'{what}的資料庫清單格式不正確。')
            if name in ('template0', 'template1'):
                continue  # created by initdb on every cluster
            if row.get('connect') is not True:
                # pg_dump cannot read it, and an in-place restore replaces the whole cluster: it would be lost for good,
                # the safety backup included (review F1).
                raise BackupError('incompatible', f'資料庫 {name[:63]} 不接受連線（ALLOW_CONNECTIONS false），無法備份整個執行個體：'
                                                  '它無法匯出，原位還原後會永久遺失。請先允許連線（ALTER DATABASE … '
                                                  'ALLOW_CONNECTIONS true），或改用冷備份模式。', app=self.app.id)
            if not DB_NAME_RE.fullmatch(name):
                raise BackupError('incompatible', f'資料庫名稱「{name[:63]}」含有不支援的字元（只支援英數字與 _ . $ -），'
                                                  '無法備份整個執行個體。', app=self.app.id)
            owner, encoding = row.get('owner'), row.get('encoding')
            provider = {'c': 'libc', 'i': 'icu', 'b': 'builtin'}.get(raw.get('datlocprovider') or 'c')
            locales = [raw.get('datcollate') or '', raw.get('datctype') or '',
                       raw.get('daticulocale') or raw.get('datlocale') or '']
            if (not isinstance(owner, str) or not 0 < len(owner) <= PG_ROLE_NAME_MAX or _unprintable(owner)
                    or not isinstance(encoding, str) or not ENCODING_RE.fullmatch(encoding) or provider is None
                    or not all(isinstance(value, str) and LOCALE_RE.fullmatch(value) for value in locales)):
                raise BackupError('incompatible', f'資料庫 {name} 的擁有者、編碼或語系設定不受支援，無法備份整個執行個體。',
                                  app=self.app.id)
            extensions = self._psql_json(container, user, name, EXTENSIONS_SQL, what)
            if not isinstance(extensions, list) or not all(
                    isinstance(item, list) and len(item) == 2 and all(isinstance(v, str) and 0 < len(v) <= 63 for v in item)
                    for item in extensions):
                raise digests.DigestError(f'{what}的擴充功能清單格式不正確。')
            # A template database (e.g. one an image's init script made) is kept too: pg_restore --create marks it
            # a template again (review F1).
            databases.append({'name': name, 'owner': owner, 'encoding': encoding, 'collate': locales[0],
                              'ctype': locales[1], 'locale_provider': provider, 'icu_locale': locales[2] or None,
                              'template': row.get('template') is True,
                              'extensions': [{'name': n, 'version': v} for n, v in extensions]})
        if not databases or len(databases) > 64:
            raise BackupError('limit-exceeded', f'{what}有 {len(databases)} 個資料庫；整個執行個體的備份支援 1 到 64 個。',
                              app=self.app.id)
        roles = self._psql_json(container, user, connect, ROLE_FLAGS_SQL, what)
        if not isinstance(roles, list) or len(roles) > 1000 or not all(
                isinstance(r, list) and len(r) == 3 and isinstance(r[0], str) and 0 < len(r[0]) <= PG_ROLE_NAME_MAX
                and not _unprintable(r[0]) and isinstance(r[1], bool) and isinstance(r[2], bool) for r in roles):
            raise digests.DigestError(f'{what}的角色清單格式不正確。')
        self.log(f'匯出資料庫 {pg["id"]} 的整個執行個體（PostgreSQL {version}，{len(databases)} 個資料庫、'
                 f'{len(roles)} 個角色）')
        customized = self._template1_objects(container, user)
        if customized:
            self.log(f'注意：template1 中有 {customized} 個自訂的資料表、函式或擴充功能；整個執行個體的還原以映像新建的 '
                     'template1 為準，不會保留它們。')
        globals_file = staging / 'postgres' / f'{pg["id"]}.globals.sql'
        with _create(globals_file) as handle:
            self.runner.podman('exec', container, 'pg_dumpall', '-w', '-U', user, '-l', connect, '--globals-only',
                               '--no-tablespaces', stdout=handle, timeout=DUMP_TIMEOUT, max_output=GLOBALS_MAX)
            handle.flush()
            os.fsync(handle.fileno())
        # Checked now the way the restore checks it: a backup whose roles a restore would refuse is not made.
        globals_statements(globals_file.read_bytes(), session_user=user)
        for index, item in enumerate(databases):
            item['file'] = staging / 'postgres' / f'{pg["id"]}.db{index}.dump'
            self._pg_dump(pg, item['name'], item['file'], staging)
        return {'id': pg['id'], 'scope': 'instance', 'database': connect, 'server_version': version, 'major': major,
                'globals': globals_file, 'databases': databases, 'bootstrap_user': bootstrap,
                'roles': [{'name': r[0], 'superuser': r[1], 'login': r[2]} for r in roles]}

    def _bootstrap_user(self, container, user, connect, what):
        answer = self._psql_json(container, user, connect, BOOTSTRAP_SQL, what)
        if (not isinstance(answer, list) or len(answer) != 2 or not all(isinstance(v, str) for v in answer)
                or not 0 < len(answer[0]) <= PG_ROLE_NAME_MAX or _unprintable(answer[0])):
            raise digests.DigestError(f'{what}的初始超級使用者格式不正確。')
        return answer[0]

    @staticmethod
    def _bootstrap_message(pg, bootstrap):
        return (f'資料庫 {pg["id"]} 設定以帳號 {pg["user"]} 備份整個執行個體，但這個執行個體的初始超級使用者是 {bootstrap[:63]}；'
                '還原時映像新建的執行個體只有初始超級使用者（映像的 POSTGRES_USER），以其他帳號將無法還原。'
                f'請在應用設定中把 user 改為 {bootstrap[:63]}。')

    def _template1_objects(self, container, user):
        """User objects in template1 (an instance restore keeps the image's own template1); 0 when unknown."""
        try:
            value = self._psql_json(container, user, 'template1', f'SELECT json_build_array(({MAINTENANCE_OBJECTS_SQL}))',
                                    'template1')
            return int(value[0]) if isinstance(value, list) and value and isinstance(value[0], int) else 0
        except (BackupError, ValueError, TypeError):
            return 0

    def _instance_catalog(self, container, user, connect, what):
        """[(name, template, accepts connections)] of every database besides template0/template1."""
        rows = self._psql_json(container, user, connect, INSTANCE_CATALOG_SQL, what)
        if not isinstance(rows, list) or len(rows) > 10000 or not all(
                isinstance(row, list) and len(row) == 3 and isinstance(row[0], str) and isinstance(row[1], bool)
                and isinstance(row[2], bool) for row in rows):
            raise digests.DigestError(f'{what}的資料庫清單格式不正確。')
        return [(row[0], row[1], row[2]) for row in rows]

    def _instance_manifest(self, dump, entry):
        return {'id': dump['id'], 'scope': 'instance', 'database': dump['database'],
                'server_version': dump['server_version'], 'major': dump['major'],
                'bootstrap_user': dump['bootstrap_user'],
                'entry': entry('postgres', f'{dump["id"]}.globals.sql', dump['globals']),
                'databases': [{**{key: value for key, value in item.items() if key != 'file'},
                               'entry': entry('postgres', f'{dump["id"]}.db{index}.dump', item['file'])}
                              for index, item in enumerate(dump['databases'])],
                'roles': dump['roles']}

    def _export_volume(self, name, staging):
        dest = staging / 'volumes' / f'{name}.tar'
        self.log(f'匯出資料卷 {name}')
        with _create(dest) as handle:
            self.runner.relay(['volume', 'export', name], stdout=handle, timeout=EXPORT_TIMEOUT,
                              max_output=self._output_budget(staging))
            handle.flush()
            os.fsync(handle.fileno())
        if dest.stat().st_size < 1024:
            raise BackupError('job-failed', f'資料卷 {name} 匯出結果不完整。', app=self.app.id)
        return {'name': name, 'file': dest}

    def _check_exported_volume(self, volume):
        self.owner_ids()  # a failure to read the ID map keeps its own message
        try:
            self._check_volume_entry(volume['name'], volume['file'])
        except BackupError as error:
            details = error.details or {}
            if 'reason' not in details:
                raise
            label = details.get('label') or '格式不符'
            member = details.get('member')
            code = 'limit-exceeded' if details.get('reason') == 'too many members' else 'job-failed'
            raise BackupError(code, f'資料卷 {volume["name"]} 含有還原時無法匯入的內容（{label}'
                                    f'{"：" + str(member) if member else ""}），這份備份無法還原，因此沒有建立；'
                                    '應用已恢復執行。', app=self.app.id, volume=volume['name'],
                              reason=details.get('reason')) from None

    def _read_secret(self, name, staging):
        result = self.runner.podman('secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', name,
                                    timeout=SHORT_TIMEOUT, max_output=MAX_SECRET_BYTES + 2)
        data = result.stdout or b''
        result.stdout = None
        if not data.endswith(b'\n') or len(data) < 2:
            raise BackupError('job-failed', f'無法讀取應用機密 {name}。', app=self.app.id)
        dest = staging / 'secrets' / name
        _write_private(dest, data[:-1])
        self.log(f'已讀取應用機密 {name}（內容不記錄）')
        return {'name': name, 'file': dest}

    def _read_config(self, index, config, staging):
        data = self.runner.read_file(config['path'])
        dest = staging / 'config' / str(index)
        _write_private(dest, data)
        return {'path': config['path'], 'mode': config['mode'], 'file': dest}

    def _save_image(self, index, image, staging):
        dest = staging / 'images' / f'{index}.oci.tar'
        self.log(f'匯出映像 {image["ref"]}')
        with _create(dest) as handle:
            self.runner.podman('save', '--quiet', '--format', 'oci-archive', image['ref'], stdout=handle,
                               timeout=IMAGE_TIMEOUT, max_output=self._output_budget(staging))
            handle.flush()
            os.fsync(handle.fileno())
        after = self.image_inspect(image['ref'])
        if not after or after['id'] != image['id']:
            raise BackupError('job-failed', f'映像 {image["ref"]} 在備份期間變更，請重新備份。', app=self.app.id)
        return dest

    # ----------------------------------------------------------------- restore
    def match_items(self, app_manifest):
        """Local catalog is the authority: returns (found {kind: {key: entry}}, missing [str], extra [str])."""
        app = self.app

        def index(key, field):
            return {x.get(field): x for x in app_manifest.get(key) or [] if isinstance(x, dict)}

        archive = {'postgres': index('postgres', 'id'), 'volumes': index('volumes', 'name'),
                   'dirs': index('data_dirs', 'path'), 'secrets': index('secrets', 'name'),
                   'config': index('config_files', 'path')}
        local = {'postgres': [p['id'] for p in app.postgres], 'volumes': [v['name'] for v in app.volumes],
                 'dirs': [d['path'] for d in app.data_dirs], 'secrets': [s['name'] for s in app.secrets],
                 'config': [c['path'] for c in app.config_files]}
        labels = {'postgres': '資料庫', 'volumes': '資料卷', 'dirs': '主機資料夾', 'secrets': '應用機密', 'config': '設定檔'}

        def shown(kind, key):
            return f'{labels[kind]} ~/{key}' if kind == 'dirs' else f'{labels[kind]} {key}'

        found, missing, extra = {}, [], []
        for kind, keys in local.items():
            found[kind] = {}
            for key in keys:
                item = archive[kind].get(key)
                if item is None or not isinstance(item.get('entry'), str):
                    missing.append(shown(kind, key))
                else:
                    found[kind][key] = item
            for key in archive[kind]:
                if key not in keys:
                    extra.append(shown(kind, key))
        return found, missing, extra

    def entry_path(self, root, entry):
        match = ENTRY_RE.fullmatch(entry or '')
        if not match or match.group(1) != self.app.id:
            raise BackupError('corrupt-archive', '備份內容的項目路徑不正確。', app=self.app.id)
        path = Path(root) / entry
        try:
            st = os.lstat(path)
        except OSError:
            raise BackupError('corrupt-archive', f'備份內容缺少項目 {entry}。', app=self.app.id) from None
        if not stat.S_ISREG(st.st_mode):
            raise BackupError('corrupt-archive', f'備份內容的項目 {entry} 不是一般檔案。', app=self.app.id)
        return path

    def preflight(self, app_manifest, *, mode, entry_sizes=None, extracted_dir=None):
        """Checks for restoring `app_manifest` here. With `extracted_dir` (the restore job, after the archive was
        extracted) the nested image and volume tars are checked too, before the safety backup: a backup whose
        image or volume would be refused fails here (review finding HD-01) and restore() reuses the results."""
        app = self.app
        checks = []
        seen = {}

        def add(check_id, status, message):
            seen[check_id] = seen.get(check_id, 0) + 1
            suffix = f'-{seen[check_id]}' if seen[check_id] > 1 else ''
            checks.append({'id': f'{app.id}/{check_id}{suffix}', 'status': status, 'message': message})

        add('owner', 'ok', f'將以此設備帳號 {self.runner.owner}（UID {self.runner.uid}）還原。')
        archived_owner = app_manifest.get('owner') if isinstance(app_manifest.get('owner'), dict) else {}
        source_owner = archived_owner.get('name')
        if isinstance(source_owner, str) and source_owner != self.runner.owner:
            # An entry re-owned to another account, or a move between accounts: the backup's data, secrets and config
            # files will belong to this account (review M3).
            add('owner-changed', 'warn', f'這份備份來自帳號 {source_owner[:32]} 的應用；還原後它的資料、應用機密與設定檔'
                                         f'會屬於此設備的帳號 {self.runner.owner}。請確認這是你要的（例如搬到另一個帳號）。')
        if not self.runtime_ready():
            add('runtime', 'fail', f'帳號 {self.runner.owner} 的使用者服務管理器未啟動，請先啟用 linger。')
        if app_manifest.get('adapter') != self.name:
            add('adapter', 'fail', '備份使用的應用轉接器與此設備不同。')
        elif not isinstance(app_manifest.get('adapter_version'), int) or app_manifest['adapter_version'] > self.version:
            add('adapter', 'fail', '備份由較新版本的轉接器建立，請先更新此設備的備份元件。')
        if app_manifest.get('catalog_sha256') != app.sha256:
            add('catalog', 'warn', '此設備的應用設定與備份時不同；將以此設備的設定為準。')
        _found, missing, extra = self.match_items(app_manifest)
        if missing:
            add('items', 'fail', f'備份缺少此設備設定需要的項目：{", ".join(missing)}。')
        else:
            add('items', 'ok', '備份包含此設備設定需要的所有資料、應用機密與設定檔。')
        if extra:
            add('extra', 'warn', f'備份中有此設備未設定的項目，將略過：{", ".join(extra)}。')
        for pg in app.postgres:
            item = _found['postgres'].get(pg['id'])
            if isinstance(item, dict) and item.get('scope', 'database') != pg['scope']:
                add('postgres-scope', 'fail', f'備份中的資料庫 {pg["id"]} 是'
                                              f'{"整個執行個體" if item.get("scope") == "instance" else "單一資料庫"}，'
                                              f'此設備設定為{"整個執行個體" if pg["scope"] == "instance" else "單一資料庫"}；'
                                              '請以相同的設定還原。')
            elif pg['scope'] == 'instance' and mode == 'fresh':
                self._preflight_instance(pg, item, add, running=False)
        self._preflight_digests(app_manifest, add)

        sources = None
        if mode == 'fresh':
            try:
                sources = self.read_templates()
                add('templates', 'ok', '此應用尚未部署，將以這台設備的受信任範本建立。')
            except BackupError as error:
                add('templates', 'fail', error.message)
            if self.runtime_ready():
                self._preflight_leftovers(sources or {}, add)
        else:
            try:
                sources = self._read_owner_quadlets()
            except BackupError as error:
                add('quadlet', 'fail', error.message)
            if self.runtime_ready():
                states = self.unit_states(app.units)
                lost = [u for u in app.units if states[u].get('LoadState') in ('not-found', 'error', 'bad-setting')]
                if lost:
                    add('units', 'fail', f'找不到服務：{", ".join(lost)}。')
                masked = [u for u in app.units if states[u].get('LoadState') == 'masked']
                if masked:
                    add('units-masked', 'warn', f'服務 {", ".join(masked)} 因先前的還原沒有完成而被暫時停用；這次還原完成後會恢復。')
                down = [p['unit'] for p in app.postgres if states[p['unit']].get('ActiveState') != 'active']
                if down and not lost:
                    add('database-down', 'warn', f'資料庫服務 {", ".join(down)} 目前未執行；建立還原前備份時會先嘗試啟動它，'
                                                 '並確認執行個體中沒有應用設定未宣告的資料庫。')
                for pg in app.postgres:
                    if pg['scope'] == 'instance':
                        self._preflight_instance(pg, _found['postgres'].get(pg['id']), add,
                                                 running=pg['unit'] not in down)
                        continue
                    if pg['unit'] in down:
                        continue
                    found = self.undeclared(pg)
                    if found is None:
                        # Review finding HD-06: unknown is not "none"; the restore would delete whatever is there.
                        add('databases', 'fail', f'無法列出資料庫 {pg["id"]} 執行個體中的資料庫與角色。原位還原會重建整個資料庫資料卷，'
                                                 '無法確認沒有其他資料庫時不會還原；請確認資料庫可以連線後再試。')
                        continue
                    databases, roles = found
                    if databases:
                        add('databases', 'fail', f'資料庫執行個體中還有應用設定未宣告的資料庫：{", ".join(databases[:10])}。'
                                                 '原位還原會重建整個資料庫資料卷，這些資料庫會遺失；請先移出後再還原。')
                    if roles:
                        add('roles', 'warn', f'還原後不會保留這些資料庫角色與權限設定：{", ".join(roles[:10])}。')
                    objects = self.maintenance_objects(pg)
                    if objects is None:
                        add('maintenance-db', 'warn', '無法讀取資料庫執行個體中 postgres 資料庫的內容；其中若有資料表或排程工作，'
                                                      '原位還原後不會保留。')
                    elif objects:
                        add('maintenance-db', 'warn', f'資料庫執行個體的 postgres 資料庫中有 {objects} 個資料表、函式或擴充功能'
                                                      '（例如排程工作）；原位還原會重建整個資料庫資料卷，這些內容不會保留。')
            add('safety', 'ok', '還原前會先建立並驗證此應用的還原前備份；失敗時會自動回復。')
            if self.http_specs() and not self.digest_specs():
                # The safety backup keeps the units stopped for the restore, so its http-json snapshot cannot be
                # confirmed and is not stored: a rollback is then checked by the health checks only (review F16).
                add('rollback-unverified', 'warn', '這個應用沒有資料摘要（postgres-digest／files-digest）：還原失敗而自動回復時，'
                                                   '只以健康檢查確認回復結果，不比對資料（還原前備份讓服務維持停止交給還原，無法保存'
                                                   '應用回報的核對值）。需要回復時也比對資料，請在應用設定加入資料摘要。')

        if self.runtime_ready():
            self._preflight_dirs(mode, add)
        if sources is not None and self.runtime_ready():
            self._preflight_images(app_manifest, sources, add)
            if extracted_dir is not None:
                self._preflight_nested(app_manifest, Path(extracted_dir), sources, add)
        if extracted_dir is None and self.app.data_dirs and self.runtime_ready():
            try:
                uids, gids = self.owner_ids()
                add('dir-ids', 'ok', f'還原前會先確認主機資料夾中的檔案擁有者都在帳號 {self.runner.owner} 可用的 ID 範圍內'
                                     f'（UID {uids.describe()}；GID {gids.describe()}）。')
            except BackupError as error:
                add('dir-ids', 'fail', error.message)
        self._preflight_space(app_manifest, entry_sizes, add, mode=mode)
        return checks

    def _preflight_instance(self, pg, item, add, *, running):
        """Instance mode: the restore's own superuser must stay one, the image must have every extension the backup
        uses, and databases that exist now but not in the backup are named (they go; the safety backup keeps them)."""
        if not isinstance(item, dict) or item.get('scope') != 'instance':
            return
        archived = [db.get('name') for db in item.get('databases') or [] if isinstance(db, dict)
                    and isinstance(db.get('name'), str)]
        roles = {role.get('name'): role for role in item.get('roles') or [] if isinstance(role, dict)}
        role = roles.get(pg['user'])
        if role is not None and not (role.get('superuser') is True and role.get('login') is True):
            add('roles', 'fail', f'備份中的資料庫角色 {pg["user"]} 不是可登入的超級使用者，無法以它還原整個資料庫執行個體。')
        bootstrap = item.get('bootstrap_user')
        if isinstance(bootstrap, str) and bootstrap != pg['user']:
            add('bootstrap', 'fail', f'備份時執行個體的初始超級使用者是 {bootstrap[:63]}，此設備的應用設定以 {pg["user"]} 還原；'
                                     '映像新建的執行個體只有初始超級使用者，請先把應用設定的 user 改成相同的帳號。')
        add('instance', 'ok', f'將還原資料庫 {pg["id"]} 的整個執行個體：{len(archived)} 個資料庫（'
                              f'{"、".join(name[:63] for name in archived[:6])}{"…" if len(archived) > 6 else ""}）與 '
                              f'{len(roles)} 個角色（含密碼）；{pg["user"]} 由此設備的映像建立，只更新它的屬性與密碼。')
        needed = sorted({ext.get('name') for db in item.get('databases') or [] if isinstance(db, dict)
                         for ext in db.get('extensions') or [] if isinstance(ext, dict) and isinstance(ext.get('name'), str)})
        if not running:
            if needed:
                add('extensions', 'warn', f'還原時會在建立新的執行個體後確認映像具備擴充功能 {", ".join(needed[:10])}；'
                                          '缺少時會停止並自動回復。')
            return
        what = f'資料庫 {pg["id"]}'
        try:
            connect = self._connect_db(pg['container'], pg['user'])
            current = self._instance_catalog(pg['container'], pg['user'], connect, what)
            available = self._psql_json(pg['container'], pg['user'], connect, AVAILABLE_EXTENSIONS_SQL, what)
            bootstrap_now = self._bootstrap_user(pg['container'], pg['user'], connect, what)
        except BackupError as error:
            add('instance-current', 'warn', f'無法讀取目前的資料庫執行個體（{error.message.rstrip("。")}）；還原時會再確認擴充功能。')
            return
        if bootstrap_now != pg['user']:
            add('bootstrap-current', 'fail', self._bootstrap_message(pg, bootstrap_now))
        closed = [name for name, _template, connects in current if not connects]
        if closed:
            # pg_dump cannot read them: neither this backup nor the safety backup has them (review F1).
            add('databases-closed', 'fail', f'目前的執行個體中有不接受連線的資料庫：{"、".join(closed[:10])}；還原前備份無法保留它們，'
                                            '原位還原會讓它們永久遺失。請先允許連線（ALTER DATABASE … ALLOW_CONNECTIONS true）'
                                            '或移除它們後再還原。')
        gone = [name for name, _template, connects in current if connects and name not in archived]
        if gone:
            add('databases', 'warn', f'目前的執行個體中有備份時沒有的資料庫：{"、".join(gone[:10])}；還原後會被移除'
                                     '（還原前備份會保留它們）。')
        customized = self._template1_objects(pg['container'], pg['user'])
        if customized:
            add('template1', 'warn', f'目前執行個體的 template1 中有 {customized} 個自訂的資料表、函式或擴充功能；還原後以映像新建的 '
                                     'template1 為準，這些不會保留。')
        missing = [name for name in needed if name not in (available if isinstance(available, list) else [])]
        if missing:
            add('extensions', 'fail', f'此設備的資料庫映像沒有備份使用的擴充功能：{", ".join(missing[:10])}；請改用含有'
                                      '這些擴充功能的映像後再還原。')
        elif needed:
            add('extensions', 'ok', f'資料庫映像具備備份使用的擴充功能（{", ".join(needed[:10])}）。')

    def _preflight_digests(self, app_manifest, add):
        """Which data digests the restore will compare (exactly, before the app starts)."""
        specs = self.digest_specs()
        if not specs:
            return
        archived = {item.get('id'): item for item in app_manifest.get('verify_digests') or [] if isinstance(item, dict)}
        compared = [spec['id'] for spec in specs if isinstance(archived.get(spec['id']), dict)
                    and archived[spec['id']].get('target') == digest_target(spec)]
        skipped = [spec['id'] for spec in specs if spec['id'] not in compared]
        if compared:
            add('digests', 'ok', f'還原後、應用啟動前會核對資料摘要：{", ".join(compared)}；不一致時會自動回復。')
        if skipped:
            add('digests-missing', 'warn', f'備份沒有資料摘要 {", ".join(skipped)}（或核對設定已變更），這些項目不會比對。')

    def _preflight_dirs(self, mode, add):
        """Target state of every host directory: in place it is replaced (a missing one is created), fresh it must be
        missing or empty. A symlink anywhere on its path, a mount point at or below it (review M2), an overlap with
        the owner's Podman storage (L1) or a running container of another unit that mounts it (M5) refuses the
        restore. Leftover siblings are reported."""
        rels = [item['path'] for item in self.app.data_dirs]
        self._dir_space = {}
        if not rels:
            return
        try:
            states = self.runner.dir_states(rels)
        except BackupError as error:
            add('dir-target', 'fail', f'無法檢查主機資料夾的狀態：{error.message}')
            return
        for rel in rels:
            state = states[rel]
            kind = state['type']
            self._dir_space[rel] = (state['dev'], state['free'])
            if kind in ('blocked', 'link', 'other'):
                add('dir-target', 'fail', f'~/{rel} 不是資料夾，或路徑中含有符號連結；無法還原到這裡。')
            elif state['mount']:
                add('dir-target', 'fail', f'~/{rel} 是掛載點（另外掛載的檔案系統或 bind mount）；還原需要在同一個掛載中替換'
                                          '整個資料夾，無法還原到這裡。')
            elif mode == 'fresh' and kind == 'dir' and not state['empty']:
                add('dir-conflict', 'fail', f'此設備已存在主機資料夾 ~/{rel} 且不是空的；為避免覆寫既有資料，請先移走後再還原'
                                            '（沒有刪除任何東西）。')
            elif mode == 'fresh' and kind == 'dir':
                add('dir-target', 'ok', f'主機資料夾 ~/{rel} 已存在且是空的，還原時會以備份內容取代。')
            elif mode == 'fresh':
                add('dir-target', 'ok', f'還原時會建立主機資料夾 ~/{rel}（上層資料夾不存在時以應用擁有者身分建立）。')
            elif kind == 'dir':
                add('dir-target', 'ok', f'還原時會以備份內容整個取代主機資料夾 ~/{rel}（不合併）；原內容保留到還原成功後才刪除，'
                                        '失敗時直接移回。')
            else:
                add('dir-target', 'warn', f'主機資料夾 ~/{rel} 目前不存在，還原時會建立；建立還原前備份時需要讀取它，'
                                          '因此還原前備份可能無法建立。')
            if kind == 'dir' and not state['mount']:
                try:
                    found = self.runner.dir_mounts(rel)
                except BackupError as error:
                    add('dir-mounts', 'fail', f'無法檢查主機資料夾 ~/{rel} 中的掛載點：{error.message}')
                else:
                    if found['mounts']:
                        add('dir-mounts', 'fail', f'主機資料夾 ~/{rel} 中有掛載點（~/{rel}/{found["mounts"][0]}）；'
                                                  '替換資料夾會連同它一起移走並在成功後刪除，因此無法還原到這裡。請先移除該掛載。')
            leftovers = [f'~/{rel}.woowbk-{item["kind"]}-{item["token"]}' for item in state['siblings']]
            if leftovers:
                more = f'等 {len(leftovers) + state["more"]} 個' if len(leftovers) > 4 or state['more'] else ''
                add('dir-leftover', 'warn', f'主機資料夾 ~/{rel} 旁有先前還原留下的資料夾（{"、".join(leftovers[:4])}{more}）；'
                                            '不影響這次還原，確認不需要後可刪除。')
        try:
            for rel, path in self._storage_overlaps(rels):
                add('dir-target', 'fail', f'主機資料夾 ~/{rel} 與 Podman 的儲存位置 {path} 重疊；不能以備份內容取代容器儲存區。')
            for problem in self._dir_users(exclude=set(self.app.units)):
                add('dir-in-use', 'fail', f'{problem}；還原替換資料夾後它仍會使用被取代的內容，請先停止它。')
        except BackupError as error:
            add('dir-in-use', 'fail', error.message)

    def _storage_overlaps(self, rels):
        """[(directory, path)] of host directories that overlap the owner's Podman storage or volume path; a
        storage.conf may move them out of ~/.local/share/containers, which the catalog forbids already (review L1)."""
        result = self.runner.podman('info', '--format', '{{.Store.GraphRoot}}\t{{.Store.VolumePath}}',
                                    timeout=SHORT_TIMEOUT, check=False, max_output=SMALL_OUTPUT)
        if result.returncode != 0:
            raise BackupError('job-failed', '無法讀取 Podman 的儲存位置，無法確認主機資料夾不在其中。', app=self.app.id)
        home = self.runner.home.rstrip('/')
        found = []
        for path in (result.stdout or b'').decode('utf-8', 'replace').strip().split('\t'):
            path = os.path.normpath(path.strip()) if path.strip().startswith('/') else ''
            if not path:
                continue
            if path == home or (home + '/').startswith(path.rstrip('/') + '/'):
                inside = ''
            elif path.startswith(home + '/'):
                inside = path[len(home) + 1:]
            else:
                continue
            found.extend((rel, path) for rel in rels if (inside == '' or paths_overlap(rel, inside))
                         and rel not in [seen for seen, _path in found])
        return found

    def _preflight_nested(self, app_manifest, root, sources, add):
        """Check the extracted image and volume tars now (cached for restore()); see preflight()."""
        try:
            self._check_image_entries(app_manifest, root, self.container_images(sources))
        except BackupError as error:
            add('image-archive', 'fail', error.message)
        found, _missing, _extra = self.match_items(app_manifest)
        for volume in self.app.volumes:
            item = found['volumes'].get(volume['name'])
            if item is None:
                continue  # reported as a missing item already
            try:
                report = self._check_volume_entry(volume['name'], self.entry_path(root, item['entry']), log=False)
            except BackupError as error:
                add('volume-archive', 'fail', error.message)
                continue
            for note in report.warnings(volume['name']):
                add('volume-attributes', 'warn', note)
        for directory in self.app.data_dirs:
            rel = directory['path']
            item = found['dirs'].get(rel)
            if item is None:
                continue  # reported as a missing item already
            try:
                report = self._check_dir_entry(rel, self.entry_path(root, item['entry']), log=False)
            except BackupError as error:
                # Owners the target namespace cannot map ("capacity"), unsafe members: nothing has changed yet.
                add('dir-archive', 'fail', error.message)
                continue
            uids, gids = self.owner_ids()
            add('dir-ids', 'ok', f'主機資料夾 ~/{rel} 的檔案擁有者（最大 UID {report.max_uid}／GID {report.max_gid}）都在帳號 '
                                 f'{self.runner.owner} 可用的範圍內（UID {uids.describe()}；GID {gids.describe()}）。')
            for note in report.warnings(f'~/{rel}'):
                add('dir-attributes', 'warn', note)

    def _preflight_leftovers(self, sources, add):
        """Fresh mode: anything the restore would create must not exist yet. A failed fresh restore removes what
        it created, so a pre-existing secret, config file or volume of the same name would be destroyed with it
        (review findings SEC-6, CR-13)."""
        app = self.app
        volumes = [v['name'] for v in app.volumes] + [p['data_volume'] for p in app.postgres]
        volumes += [name for name in self._named_objects(sources)['volume'] if name not in volumes]
        for name in volumes:
            if self.runner.podman('volume', 'exists', name, timeout=SHORT_TIMEOUT, check=False).returncode == 0:
                add('volume-conflict', 'fail', f'此設備已存在同名資料卷 {name}；為避免覆寫既有資料，請先處理後再還原。')
        for secret in app.secrets:
            if self.runner.podman('secret', 'exists', secret['name'], timeout=SHORT_TIMEOUT, check=False).returncode == 0:
                add('secret-existing', 'fail', f'此設備已存在同名的應用機密 {secret["name"]}（可能是先前移除應用時留下的）；'
                                               '為避免還原失敗時一併刪除它，請先移除後再還原。')
        if app.config_files:
            stats = self.runner.stat_files([c['path'] for c in app.config_files])
            for config in app.config_files:
                if stats.get(config['path'], {}).get('type', 'missing') != 'missing':
                    add('config-existing', 'fail', f'此設備已存在設定檔 ~/{config["path"]}；'
                                                   '為避免還原失敗時一併刪除它，請先移除後再還原。')

    def _preflight_images(self, app_manifest, sources, add):
        try:
            needed = self.container_images(sources)
        except BackupError as error:
            add('images', 'fail', error.message)
            return
        archived = {img.get('ref'): img for img in app_manifest.get('images') or [] if isinstance(img, dict)}
        local_arch = ARCH.get(platform.machine(), platform.machine())
        majors = {}
        for unit, ref in needed.items():
            image = archived.get(ref)
            if image and image.get('entry'):
                if image.get('arch') and image['arch'] != local_arch:
                    add('image', 'fail', f'備份中的映像 {ref} 架構為 {image["arch"]}，與此設備（{local_arch}）不同。')
                else:
                    add('image', 'ok', f'映像 {ref} 已包含在備份中。')
                majors[unit] = 'archive'
            elif self._image_exists(ref):
                add('image', 'ok', f'使用此設備現有的映像 {ref}。')
                majors[unit] = self._env_pg_major(self.image_inspect(ref))
            elif self._image_pullable(ref):
                add('image', 'warn', f'映像 {ref} 不在此設備，還原時將自動下載。')
                majors[unit] = None
            else:
                add('image', 'fail', f'缺少映像 {ref}：備份未包含，且此設備無法取得。')
                majors[unit] = None
        archived_pg = {p.get('id'): p for p in app_manifest.get('postgres') or [] if isinstance(p, dict)}
        for pg in self.app.postgres:
            source = archived_pg.get(pg['id'], {}).get('major')
            target = majors.get(pg['unit'])
            if not isinstance(source, int):
                continue
            if unsupported_major(source) or unsupported_major(target):
                add('postgres-version', 'fail', 'PostgreSQL 10 以前的版本不受支援，無法還原。')
                continue
            if target == 'archive':
                continue
            if target is None:
                add('postgres-version', 'warn', f'無法事先確認資料庫 {pg["id"]} 的目標版本，還原時會再檢查。')
            elif source > target:
                add('postgres-version', 'fail', f'備份的 PostgreSQL 主版本 {source} 高於此設備的 {target}，無法還原。')
            else:
                add('postgres-version', 'ok', f'PostgreSQL 主版本相容（備份 {source}，此設備 {target}）。')

    def _preflight_space(self, app_manifest, entry_sizes, add, mode='inplace'):
        """Free space where the app's data lives: twice what the archive holds for it (the extracted archive and the
        restored data). A host directory is written next to the current copy, which stays until the job succeeded
        and moves back after a failure (no third copy, review M3); a directory on another filesystem than the home
        counts there (the device and free space the preflight read inside the owner's namespace)."""
        if not entry_sizes:
            return
        prefix = f'apps/{self.app.id}/'
        try:
            st = self.statvfs(self.runner.home)
            free = st.f_bavail * st.f_frsize
        except OSError:
            add('space', 'warn', '無法確認應用擁有者家目錄的可用空間。')
            return
        try:
            home_dev = os.stat(self.runner.home).st_dev
        except OSError:
            home_dev = None  # every directory then counts with the home
        found, _missing, _extra = self.match_items(app_manifest)
        elsewhere = {item['entry']: rel for rel, item in found['dirs'].items() if home_dev is not None
                     and self._dir_space.get(rel, (None,))[0] not in (None, home_dev)}
        need, devices = 0, {}
        for path, size in entry_sizes.items():
            if not path.startswith(prefix):
                continue
            if path in elsewhere:
                dev, avail = self._dir_space[elsewhere[path]]
                devices.setdefault(dev, [0, avail, []])
                devices[dev][0] += size
                devices[dev][2].append(f'~/{elsewhere[path]}')
            else:
                need += size
        problems = []
        required = 2 * need + SPACE_RESERVE
        if free < required:
            problems.append(f'家目錄所在磁碟需要約 {_human(required)}，可用 {_human(free)}')
        for size, avail, rels in devices.values():
            if avail is None or avail < size + SPACE_RESERVE:
                problems.append(f'{"、".join(rels)} 所在磁碟需要約 {_human(size + SPACE_RESERVE)}，'
                                f'可用 {_human(avail or 0)}')
        if problems:
            add('space', 'fail', f'應用資料所在磁碟空間不足：{"；".join(problems)}。')
        else:
            add('space', 'ok', f'應用資料所在磁碟空間足夠（可用 {_human(free)}）。')

    def stage_dirs(self, app_manifest, extracted_dir, *, mode):
        """Write every host directory of the archive to its `<dir>.woowbk-new-<job>` sibling before anything stops
        (before the pre-restore safety backup; CONTRACT section 9): nothing that exists changes, and restore() then
        only swaps them in while the units are stopped. After a failure before the restore's first destructive step
        the caller removes them again (discard_dirs)."""
        app = self.app
        if not app.data_dirs:
            return
        found, missing, _extra = self.match_items(app_manifest)
        if missing:
            raise BackupError('incompatible', f'備份缺少此設備設定需要的項目：{", ".join(missing)}。', app=app.id)
        root = Path(extracted_dir)
        paths = {item['path']: self.entry_path(root, found['dirs'][item['path']]['entry']) for item in app.data_dirs}
        for rel, path in paths.items():  # same rules as restore(), with the target owner's ID map ("capacity")
            self._check_dir_entry(rel, path)
        self._check_dir_targets(mode)
        for rel, path in paths.items():
            self._unpack_dir(rel, path, rollback=False)
            self._staged.add(rel)

    def _instance_item(self, pg, item, root):
        """The archive's instance-mode item for `pg`, checked: [(database dict, dump path)] and the globals path."""
        if not isinstance(item, dict) or item.get('scope') != 'instance':
            raise BackupError('incompatible', f'備份中的資料庫 {pg["id"]} 只有單一資料庫，此設備設定為還原整個執行個體；'
                                              '請以相同的設定還原。', app=self.app.id)
        databases = item.get('databases')
        if not isinstance(databases, list) or not 0 < len(databases) <= 64:
            raise BackupError('corrupt-archive', f'備份中的資料庫 {pg["id"]} 記錄格式不正確。', app=self.app.id)
        result, seen = [], set()
        for db in databases:
            if (not isinstance(db, dict) or not isinstance(db.get('name'), str) or not DB_NAME_RE.fullmatch(db['name'])
                    or db['name'] in seen or db['name'] in ('template0', 'template1')
                    or not isinstance(db.get('template', False), bool) or not isinstance(db.get('extensions', []), list)
                    or not all(isinstance(ext, dict) and isinstance(ext.get('name'), str) and 0 < len(ext['name']) <= 63
                               for ext in db.get('extensions', []))):
                raise BackupError('corrupt-archive', f'備份中的資料庫 {pg["id"]} 記錄格式不正確。', app=self.app.id)
            seen.add(db['name'])
            result.append((db, self.entry_path(root, db.get('entry'))))
        return result, self.entry_path(root, item.get('entry'))

    def restore(self, app_manifest, extracted_dir, *, mode, rollback=False, unchecked_databases_ok=False,
                replaced_dirs=()):
        """Restore one app from an extracted archive. `rollback=True` (restoring the pre-restore safety backup
        after a failure) never pulls an image: the exact pre-restore image must still be here, and host directories
        move back from the failed restore's `-old-` copies (`replaced_dirs`: the directories it swapped, extracted
        from the safety backup when that copy is gone).
        `unchecked_databases_ok`: the restore runs without a safety backup that the user accepted (or it restores a
        safety backup), so an instance that cannot be queried at all may be rebuilt (review finding HD-06).

        Order (CONTRACT section 9): every unit stops with one `systemctl --user stop` (units a safety backup already
        stopped stay stopped), the data is put in place (directories stage_dirs() wrote are only swapped), the
        files digests are compared before anything starts, then the database units start alone (pg_restore, the
        SQL digests), and only then the other units, in groups where their dependencies allow."""
        app = self.app
        root = Path(extracted_dir)
        self.destructive_started = False
        self.digest_results = []
        found, missing, _extra = self.match_items(app_manifest)
        if missing:
            raise BackupError('incompatible', f'備份缺少此設備設定需要的項目：{", ".join(missing)}。', app=app.id)
        files = {kind: {key: self.entry_path(root, item['entry']) for key, item in items.items()}
                 for kind, items in found.items()}
        instances = {pg['id']: self._instance_item(pg, found['postgres'][pg['id']], root)
                     for pg in app.postgres if pg['scope'] == 'instance'}
        for pg in app.postgres:
            if pg['scope'] == 'database' and found['postgres'][pg['id']].get('scope', 'database') != 'database':
                raise BackupError('incompatible', f'備份中的資料庫 {pg["id"]} 是整個執行個體，此設備設定為單一資料庫；'
                                                  '請以相同的設定還原。', app=app.id)
        templates = self.read_templates() if mode == 'fresh' else None
        sources = templates if mode == 'fresh' else self._read_owner_quadlets()
        needed = self.container_images(sources)
        # Nested tars from the archive are checked completely before anything changes (review finding SEC-1); the
        # job's preflight usually did so already, before the safety backup (HD-01), and the results are reused.
        loads = self._check_image_entries(app_manifest, root, needed)
        for volume in app.volumes:
            self._check_volume_entry(volume['name'], files['volumes'][volume['name']])
        if rollback and app.data_dirs:
            dir_plan = self._rollback_dir_plan(set(replaced_dirs))
        else:
            dir_plan = {item['path']: 'extract' for item in app.data_dirs}
        for rel, how in dir_plan.items():  # same rules, with the target owner's ID map ("capacity")
            if how == 'extract' and rel not in self._staged:
                self._check_dir_entry(rel, files['dirs'][rel])
        self._dirs_tracked = True
        self._check_dir_targets(mode)
        if mode == 'inplace' and not rollback:
            # A rollback rebuilds the volume the failed restore itself created from the archive: nothing else is in it.
            self._refuse_undeclared_databases(unchecked_ok=unchecked_databases_ok)
        self._remember_tags(needed)
        try:
            self._prepare_images(app_manifest, root, needed, loads, allow_pull=not rollback)
        except BaseException:
            self._restore_tags()  # loads and retags happen before the first destructive step (review CR-10)
            raise
        self.checkpoint()

        self.phase('stop')
        self.destructive_started = True
        work = Path(extracted_dir).parent / f'digests-{app.id}-{self._dir_token(rollback)}'
        try:
            if mode == 'inplace':
                self.timing.setdefault('first_stop', self.clock())
                if not rollback:
                    # Listed first: should the job die before the mask, the recovery starts them again (nothing has
                    # changed yet). A rollback finds them stopped and masked already.
                    self.writers_hook(list(app.units))
                self._stop_units(app.units, label='停止服務')
            else:
                for name in app.quadlet_files:
                    self.runner.write_file(self.qrel(name), templates[name], 0o644)
                self.log('已安裝部署範本')
                self.runner.systemctl('daemon-reload', timeout=SHORT_TIMEOUT)
            self._mask_units()
            if mode == 'inplace' and not rollback:
                self.writers_hook([])  # masked: from here on the restore (or its rollback) owns the stopped state
            self._reset_aux_units()

            self.phase('restore')
            # Host directories are written next to the current ones first (stage_dirs() usually did so before the
            # stop): nothing that exists changes, and a failure here leaves everything else as it was (review M3).
            for rel, how in dir_plan.items():
                if how == 'extract' and rel not in self._staged:
                    self._unpack_dir(rel, files['dirs'][rel], rollback=rollback)
            for secret in app.secrets:
                self._recreate_secret(secret['name'], files['secrets'][secret['name']])
            for config in app.config_files:
                with open(files['config'][config['path']], 'rb') as handle:
                    self.runner.write_file(config['path'], handle, config['mode'])
                self.log(f'已寫入設定檔 ~/{config["path"]}')
            for volume in app.volumes:
                self._recreate_volume(volume['name'], files['volumes'][volume['name']])
            removed_at = {}
            for pg in app.postgres:
                removed_at[pg['id']] = self.wall()  # an instance restore checks that the cluster is newer (F4)
                self.runner.podman('volume', 'rm', '-f', pg['data_volume'], timeout=STOP_TIMEOUT)
            if app.data_dirs:
                # Right before the swap: a container still running with a directory mounted would keep using (and
                # writing into) the replaced copy, which is deleted once the job succeeded (review M5).
                self._require_unused_dirs(exclude=(), writable_only=False, when='還原')
            for rel, how in dir_plan.items():
                if how == 'extract':
                    self._swap_dir(rel, fresh=mode == 'fresh', rollback=rollback)
                elif how == 'revert':
                    self._revert_dir(rel)
                else:
                    self.log(f'主機資料夾 ~/{rel} 沒有被失敗的還原變更，保留原內容')
            if self.digest_specs():
                work.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Every file is in place and nothing that uses it runs yet: the comparison is exact.
            self._verify_digests(app_manifest, root, work, 'files-digest')

            self.phase('start')
            started = []
            for pg in sorted(app.postgres, key=lambda p: app.units.index(p['unit'])):
                if pg['unit'] not in started:
                    self._start(pg['unit'])
                    started.append(pg['unit'])
                self._wait_for_postgres(pg)
                self._check_target_major(pg, app_manifest)
                if pg['scope'] == 'instance':
                    self._restore_instance(pg, *instances[pg['id']], removed_at=removed_at.get(pg['id']))
                else:
                    self._ensure_database(pg)
                    self._restore_database(pg, files['postgres'][pg['id']])
            for spec in self.digest_specs('postgres-digest'):
                # A cold database starts alone (its data is a volume or a host directory) so its digest is read before
                # the apps that use it start.
                if spec['container'] and spec['unit'] not in started:
                    self.runner.systemctl('unmask', '--', spec['unit'], timeout=SHORT_TIMEOUT)
                    self._start(spec['unit'])
                    started.append(spec['unit'])
                    self._wait_for_postgres({'id': spec['id'], 'container': spec['container'], 'user': spec['user'],
                                             'database': 'postgres'})
            self._verify_digests(app_manifest, root, work, 'postgres-digest')
            # The data import is complete: from now on the app may hold new data (its units start, also at boot), so
            # a recovery must never remove it as an unfinished fresh deployment (review finding HD-04).
            self.imported_hook()
            self._unmask_units()
            failed, interrupted = self._start_units([unit for unit in app.units if unit not in started],
                                                    before='啟動服務', keep_going=False)
            if interrupted is not None:
                raise interrupted
            if failed:
                raise BackupError('job-failed', f'無法啟動服務：{", ".join(failed)}。', app=app.id, units=failed)
            self.timing['started'] = self.clock()
        except BackupError as error:
            self._log_command_error(error)
            raise

    def _restore_instance(self, pg, databases, globals_path, *, removed_at=None):
        """Instance mode into the fresh cluster the image just initialized (CONTRACT section 9): the cluster must be
        newer than the removal of the data volume, extension preflight, the roles (the bootstrap superuser reconciled,
        never recreated; it must stay a superuser that can log in), then every database of the backup created as it
        was (`pg_restore --create`: owner, encoding, locale, settings, grants, comment, template flag) and restored
        with its owners and privileges. A database of the backup that the image already created (POSTGRES_DB, an init
        script's template, `postgres` itself) is dropped first, whatever its init scripts put into it: the cluster is
        new (review F4). Everything runs from `template1`, which no backup holds."""
        container, user = pg['container'], pg['user']
        what = f'資料庫 {pg["id"]}'
        maint = INSTANCE_MAINTENANCE_DB
        self._require_new_cluster(pg, maint, removed_at, what)
        available = self._psql_json(container, user, maint, AVAILABLE_EXTENSIONS_SQL, what)
        if not isinstance(available, list):
            raise digests.DigestError(f'{what}的擴充功能清單格式不正確。')
        missing = sorted({ext['name'] for db, _path in databases for ext in db.get('extensions', [])} - set(available))
        if missing:
            raise BackupError('incompatible', f'此設備的資料庫映像沒有備份使用的擴充功能：{", ".join(missing[:10])}；'
                                              '請改用含有這些擴充功能的映像（例如 pgvector/pgvector）後再還原。', app=self.app.id)
        fd = os.open(globals_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as handle:
            data = handle.read(GLOBALS_MAX + 1)
        if len(data) > GLOBALS_MAX:
            raise BackupError('limit-exceeded', f'備份中資料庫 {pg["id"]} 的角色定義超過 16 MiB。', app=self.app.id)
        script = globals_script(data, session_user=user)
        self.log(f'還原資料庫 {pg["id"]} 的角色與密碼設定（{user} 為此設備映像建立的管理帳號，只更新它的屬性與密碼）')
        self.runner.podman('exec', '-i', container, 'psql', '-X', '-w', '-q', '-v', 'ON_ERROR_STOP=1', '-U', user, '-d',
                           maint, '-f', '-', input=script, stdout=DEVNULL, timeout=RESTORE_TIMEOUT)
        # A new session of the restore's role: still a superuser that can log in, and not read-only. The script was
        # checked statement by statement; this catches every other way it could have taken that away (L2, F8).
        state = self._psql_json(container, user, maint, SESSION_STATE_SQL, what)
        if state != [True, 'off']:
            raise BackupError('incompatible', f'套用備份中的資料庫角色定義後，帳號 {user} 不再是可登入、可寫入的超級使用者；'
                                              '還原已停止並會自動回復。', app=self.app.id)
        existing = {name: template for name, template, _connects in self._instance_catalog(container, user, maint, what)}
        for db, path in databases:
            name = db['name']
            if name in existing:
                # Created by the image at the cluster's first start: recreated exactly as the backup has it.
                if existing[name]:
                    self._psql_command(container, user, maint, f'ALTER DATABASE "{name}" IS_TEMPLATE false')
                self._psql_command(container, user, maint, f'DROP DATABASE "{name}"')
            self.log(f'還原資料庫 {pg["id"]}：{name}（擁有者 {db.get("owner", "?")}）')
            with open(path, 'rb') as handle:
                self.runner.podman('exec', '-i', container, 'pg_restore', '--create', '--exit-on-error',
                                   '--no-tablespaces', '-w', '-U', user, '-d', maint, input=handle,
                                   timeout=RESTORE_TIMEOUT)

    def _psql_command(self, container, user, database, sql):
        self.runner.podman('exec', container, 'psql', '-X', '-w', '-q', '-v', 'ON_ERROR_STOP=1', '-U', user, '-d', database,
                           '-c', sql, timeout=SHORT_TIMEOUT, max_output=SMALL_OUTPUT)

    def _require_new_cluster(self, pg, maint, removed_at, what):
        """The cluster was initialized after the data volume was removed (its system identifier holds the initdb
        time): otherwise the volume was not rebuilt and the restore would write over existing data (review F4)."""
        if removed_at is None:
            return
        answer = self._psql_json(pg['container'], pg['user'], maint, CLUSTER_ID_SQL, what)
        try:
            initialized = int(answer[0]) >> 32
        except (TypeError, ValueError, IndexError, KeyError):
            raise digests.DigestError(f'{what}無法讀取執行個體的識別碼。') from None
        if initialized < int(removed_at) - 5:
            raise BackupError('job-failed', f'資料庫 {pg["id"]} 的執行個體不是這次還原新建立的（資料庫資料卷沒有重建）；'
                                            '為避免覆寫，已停止還原。', app=self.app.id)

    def _maskable_units(self):
        databases = {pg['unit'] for pg in self.app.postgres}
        return [unit for unit in self.app.units if unit not in databases]

    def _mask_units(self):
        """Keep the app's non-database units from starting (also at boot, via linger) until the restore finished.

        An interrupted in-place restore otherwise left enabled units that started on half-restored data at the
        next boot while the overview showed the app as running (review finding CR-06). Database units stay
        startable: the restore itself starts them.
        """
        units = self._maskable_units()
        if units:
            self.runner.systemctl('mask', '--', *units, timeout=SHORT_TIMEOUT)
            self.log(f'已暫時停用 {", ".join(units)}，還原完成前不會自動啟動')

    def _unmask_units(self, check=True):
        units = self._maskable_units()
        if units:
            self.runner.systemctl('unmask', '--', *units, timeout=SHORT_TIMEOUT, check=check)

    def _refuse_undeclared_databases(self, unchecked_ok=False):
        for pg in self.app.postgres:
            if pg['scope'] == 'instance':
                # The whole instance comes from the archive, but a database that accepts no connections is in neither
                # it nor the safety backup: the volume is removed only when there is none (review F1).
                try:
                    closed = [name for name, _template, connects in self._instance_catalog(
                        pg['container'], pg['user'], self._connect_db(pg['container'], pg['user']), f'資料庫 {pg["id"]}')
                        if not connects]
                except BackupError:
                    if not unchecked_ok:
                        raise BackupError('incompatible', f'無法列出資料庫 {pg["id"]} 執行個體中的資料庫（資料庫沒有執行或無法連線）。'
                                                          '原位還原會重建整個資料庫資料卷，無法確認時不會還原；未做任何變更。',
                                          app=self.app.id) from None
                    note = (f'無法列出資料庫 {pg["id"]} 執行個體中的資料庫；這次還原沒有還原前備份，會重建整個資料庫資料卷，'
                            '其中不在備份中的資料庫將會遺失。')
                    self.log(f'注意：{note}')
                    self.warnings.append(note)
                    continue
                if closed:
                    raise BackupError('incompatible', f'資料庫執行個體中有不接受連線的資料庫：{", ".join(closed[:10])}。原位還原會重建'
                                                      '整個資料庫資料卷，它們不在任何備份中，會永久遺失；未做任何變更。', app=self.app.id)
                continue
            found = self.undeclared(pg)
            if found is None:
                if not unchecked_ok:
                    raise BackupError('incompatible', f'無法確認資料庫 {pg["id"]} 的執行個體中是否還有應用設定未宣告的資料庫'
                                                      '（資料庫沒有執行或無法連線）。原位還原會重建整個資料庫資料卷，'
                                                      '為避免遺失其他資料庫，未做任何變更。', app=self.app.id)
                note = (f'無法確認資料庫 {pg["id"]} 的執行個體中是否還有其他資料庫（資料庫沒有執行或無法連線）；這次還原沒有'
                        '還原前備份（已確認直接還原，或還原的就是還原前備份），會重建整個資料庫資料卷，其中若有其他資料庫將會遺失。')
                self.log(f'注意：{note}')
                self.warnings.append(note)
                continue
            if found[0]:
                raise BackupError('incompatible', f'資料庫執行個體中還有應用設定未宣告的資料庫：{", ".join(found[0][:10])}。'
                                                  '原位還原會重建整個資料庫資料卷，這些資料庫會遺失；未做任何變更。', app=self.app.id)

    def _start(self, unit):
        self.log(f'啟動服務 {unit}')
        self.runner.systemctl('start', '--', unit, timeout=START_TIMEOUT)

    def _check_image_entries(self, app_manifest, root, needed):
        """{ref: (path, plan)} for every included image the trusted templates need, each validated by nested
        (cached per ref and path)."""
        archived = {img.get('ref'): img for img in app_manifest.get('images') or [] if isinstance(img, dict)}
        loads = {}
        for ref in dict.fromkeys(needed.values()):
            image = archived.get(ref)
            if image and image.get('entry'):
                path = self.entry_path(root, image['entry'])
                key = ('image', ref, str(path))
                plan = self._nested_checked.get(key)
                if plan is None:
                    plan = nested.check_oci(path, ref=ref, image_id=image.get('id'))
                    self._nested_checked[key] = plan
                loads[ref] = (path, plan)
        return loads

    def _remember_tags(self, needed):
        """Record where every name this restore may move points now: the local name a load or tag gives a ref
        (`localhost/<short ref>`, put back first) and the ref itself as it resolves (review findings CR-10, HD-01)."""
        self._previous_tags = {}
        for ref in dict.fromkeys(needed.values()):
            for name in dict.fromkeys((nested.local_name(ref), ref)):
                if name not in self._previous_tags:
                    info = self.image_inspect(name)
                    self._previous_tags[name] = info['id'] if info else None

    def _restore_tags(self):
        """Point every image name this restore loaded, retagged or pulled back at its previous image.

        Only full names are tagged back: `podman tag <id> <short ref>` would create `localhost/<short ref>`, which has
        a key of its own, and an alias name this restore moved was recorded under its full name (`_resolve_to`)."""
        previous, self._previous_tags = getattr(self, '_previous_tags', None) or {}, {}
        for ref, old in previous.items():
            if nested.is_short_ref(ref):
                continue
            try:
                info = self.image_inspect(ref)
                current = info['id'] if info else None
                if current == old:
                    continue
                if old and self._image_exists(self._bare_id(old)):
                    self.runner.podman('tag', self._bare_id(old), ref, timeout=SHORT_TIMEOUT)
                    self.log(f'已將映像 {ref} 改回還原前的版本')
                elif old is None and current is not None:
                    self.runner.podman('untag', ref, ref, timeout=SHORT_TIMEOUT, check=False)
                    self.log(f'已移除這次還原加上的映像名稱 {ref}')
            except BackupError as error:
                self._log_command_error(error)
                self.log(f'警告：無法把映像 {ref} 改回還原前的版本，請檢查。')

    def _prepare_images(self, app_manifest, root, needed, loads, *, allow_pull=True):
        archived = {img.get('ref'): img for img in app_manifest.get('images') or [] if isinstance(img, dict)}
        for ref in dict.fromkeys(needed.values()):
            image = archived.get(ref)
            if ref in loads:
                path, plan = loads[ref]
                self.log(f'載入映像 {ref}')
                with nested.pipe_from(lambda out, path=path, plan=plan: nested.stream_oci(path, plan, out)) as feed:
                    self.runner.podman('load', '--quiet', input=feed, timeout=IMAGE_TIMEOUT, max_output=SMALL_OUTPUT)
                if not self._resolve_to(ref, plan['image_id']):
                    raise BackupError('corrupt-archive', f'載入的映像 {ref} 與備份記錄的版本不符。', app=self.app.id)
                continue
            if image and image.get('id'):
                if self._image_exists(self._bare_id(image['id'])):
                    self._ensure_tag(image['id'], ref)
                    continue
                if not allow_pull:
                    raise BackupError('incompatible', f'回復需要的映像 {ref}（{image["id"][:19]}…）已不在此設備。',
                                      app=self.app.id)
            if self._image_exists(ref):
                continue
            if not allow_pull or ref.startswith('localhost/'):
                raise BackupError('incompatible', f'缺少映像 {ref}：備份未包含，且此設備無法取得。', app=self.app.id)
            self.log(f'下載映像 {ref}')
            self.runner.podman('pull', '--quiet', ref, stdout=DEVNULL, timeout=IMAGE_TIMEOUT)

    def _ensure_tag(self, image_id, ref):
        if not isinstance(image_id, str) or not re.fullmatch(r'(sha256:)?[0-9a-f]{64}', image_id):
            return
        full_id = image_id if image_id.startswith('sha256:') else 'sha256:' + image_id
        current = self.image_inspect(ref)
        if current and current['id'] == full_id:
            return
        if not self._image_exists(self._bare_id(image_id)):
            raise BackupError('incompatible', f'映像 {ref} 載入後找不到預期的版本。', app=self.app.id)
        self.runner.podman('tag', self._bare_id(image_id), ref, timeout=SHORT_TIMEOUT)
        self.log(f'已將 {ref} 指向備份時的映像版本')
        if not self._resolve_to(ref, full_id):
            raise BackupError('incompatible', f'無法讓映像名稱 {ref} 指向備份時的版本（{full_id[:19]}…）。', app=self.app.id)

    def _resolve_to(self, ref, image_id):
        """Make the trusted `ref` resolve to `image_id` here (after a load or tag named it `local_name(ref)`); True
        when it does.

        A short name with an alias (shortnames.conf: ubuntu, python, node, ...) resolves to an existing image under
        the alias target before `localhost/<ref>`. Then the names of the image `ref` resolves to that mean the image
        `ref` names (`nested.same_image_name`, e.g. `docker.io/library/node:20` for `node:20`) are moved to `image_id`
        too: names this device already uses for `ref`, never a name from the archive. Each is remembered first, so a
        failure puts it back (review finding HD-01; a re-pulled `node:20` no longer fails a restore as corrupt)."""
        current = self.image_inspect(ref)
        if current is None or current['id'] == image_id or not nested.is_short_ref(ref):
            return current is not None and current['id'] == image_id
        for name in current.get('names') or []:
            if name == nested.local_name(ref) or not nested.same_image_name(name, ref):
                continue
            self._previous_tags.setdefault(name, current['id'])
            self.runner.podman('tag', self._bare_id(image_id), name, timeout=SHORT_TIMEOUT)
            self.log(f'已將 {name}（{ref} 的別名目標）指向備份時的映像版本')
        current = self.image_inspect(ref)
        return current is not None and current['id'] == image_id

    def _check_target_major(self, pg, app_manifest):
        source = next((p.get('major') for p in app_manifest.get('postgres') or []
                       if isinstance(p, dict) and p.get('id') == pg['id']), None)
        try:
            target = pg_major(self.psql_scalar(pg, 'SHOW server_version_num', database='postgres'))
        except (BackupError, ValueError):
            return
        if unsupported_major(source) or unsupported_major(target):
            raise BackupError('incompatible', 'PostgreSQL 10 以前的版本不受支援，無法還原。', app=self.app.id)
        if isinstance(source, int) and source > target:
            raise BackupError('incompatible', f'備份的 PostgreSQL 主版本 {source} 高於此設備的 {target}。', app=self.app.id)

    def _recreate_secret(self, name, path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as handle:
            data = handle.read(MAX_SECRET_BYTES + 1)
        if not data or len(data) > MAX_SECRET_BYTES:
            raise BackupError('incompatible', f'應用機密 {name} 的大小不受 Podman 支援。', app=self.app.id)
        if self.runner.podman('secret', 'exists', name, timeout=SHORT_TIMEOUT, check=False).returncode == 0:
            self.runner.podman('secret', 'rm', name, timeout=SHORT_TIMEOUT)
        # `podman secret create NAME -` insists on a pipe: a regular-file stdin is rejected, so feed bytes.
        self.runner.podman('secret', 'create', name, '-', input=data, timeout=SHORT_TIMEOUT)
        self.log(f'已重建應用機密 {name}（內容不記錄）')

    def _recreate_volume(self, name, path):
        self.runner.podman('volume', 'rm', '-f', name, timeout=STOP_TIMEOUT)
        self.runner.podman('volume', 'create', name, timeout=SHORT_TIMEOUT)
        # podman only ever reads a canonical tar of the validated members (review finding SEC-1).
        ids = self.owner_ids()
        with nested.pipe_from(lambda out: nested.stream_volume(path, out, ids)) as feed:
            self.runner.podman('volume', 'import', name, '-', input=feed, timeout=EXPORT_TIMEOUT)
        self.log(f'已重建資料卷 {name}')

    def _postgres_ready(self, pg):
        result = self.runner.podman('exec', pg['container'], 'pg_isready', '-h', '127.0.0.1', '-p', '5432',
                                    '-U', pg['user'], '-d', pg['database'], '-t', '5', timeout=30, check=False,
                                    max_output=SMALL_OUTPUT)
        return result.returncode == 0

    def _wait_for_postgres(self, pg):
        deadline = self.clock() + PG_READY_TIMEOUT
        while True:
            if self._postgres_ready(pg):
                return
            if self.clock() >= deadline:
                raise BackupError('job-failed', f'資料庫 {pg["id"]} 未在 {PG_READY_TIMEOUT} 秒內就緒。', app=self.app.id)
            self.sleep(1)

    def _ensure_database(self, pg):
        # Identifiers are validated against ^[A-Za-z_][A-Za-z0-9_]{0,62}$ by the catalog.
        exists = self.psql_scalar(pg, f"SELECT 1 FROM pg_database WHERE datname = '{pg['database']}'",
                                  database='postgres')
        if exists != '1':
            self.runner.podman('exec', pg['container'], 'createdb', '-w', '-U', pg['user'], pg['database'],
                               timeout=SHORT_TIMEOUT)

    def _restore_database(self, pg, path):
        self.log(f'還原資料庫 {pg["id"]}（{pg["database"]}）')
        with open(path, 'rb') as handle:
            self.runner.podman('exec', '-i', pg['container'], 'pg_restore', '--exit-on-error', '--single-transaction',
                               '--no-owner', '--no-privileges', '-w', '-U', pg['user'], '-d', pg['database'],
                               input=handle, timeout=RESTORE_TIMEOUT)

    def start_units(self, units):
        """Start `units` of this app (the recovery of a dead job), in groups where their dependencies allow."""
        failed, interrupted = self._start_units([u for u in self.app.units if u in units], attempts=2,
                                                before='啟動服務', failed_note='無法啟動服務')
        if interrupted is not None:
            raise interrupted
        return failed

    def fresh_in_use(self):
        """Units showing that a fresh deployment may already hold new data, for the recovery of a dead restore
        (review finding HD-04): a non-database unit that is not masked (restore() masks them right after the
        templates are installed and unmasks them once the data import finished) or that is running; for an app
        without such units, any running unit. [] means the deployment is still unfinished and may be removed."""
        states = self.unit_states(self.app.units)
        maskable = self._maskable_units()
        running = ('active', 'activating', 'deactivating', 'reloading', 'refreshing')
        live = []
        for unit in self.app.units:
            load, active = states[unit].get('LoadState'), states[unit].get('ActiveState')
            if unit in maskable and (load not in ('masked', 'not-found') or active in running):
                live.append(unit)
            elif not maskable and active in running:
                live.append(unit)
        return live

    def remove_fresh(self):
        """Undo a fresh deployment. Pre-existing secrets, config files and volumes of the same names fail the
        fresh preflight, so everything removed here was created by the restore; networks and pods are removed
        without force, so an object another app still uses stays."""
        app = self.app
        errors = []
        for unit in reversed(app.units):
            result = self.runner.systemctl('stop', '--', unit, timeout=STOP_TIMEOUT, check=False)
            if result.returncode not in (0, 5):  # 5: never loaded (the failure came before daemon-reload)
                self._log_command_error(CommandError('systemctl stop', returncode=result.returncode,
                                                     stderr=result.stderr))
                errors.append(unit)
        self._unmask_units(check=False)
        self._reset_aux_units()
        try:
            sources = self.read_templates()
        except BackupError:
            sources = {}
        for name in app.quadlet_files:
            try:
                self.runner.remove_file(self.qrel(name))
            except BackupError:
                errors.append(name)
        try:
            self.runner.systemctl('daemon-reload', timeout=SHORT_TIMEOUT)
        except BackupError:
            errors.append('daemon-reload')
        for unit in [*app.units, *self.aux_units()]:
            self.runner.systemctl('reset-failed', '--', unit, timeout=SHORT_TIMEOUT, check=False)
        for name in [p['data_volume'] for p in app.postgres] + [v['name'] for v in app.volumes]:
            try:
                self.runner.podman('volume', 'rm', '-f', name, timeout=STOP_TIMEOUT)
            except BackupError:
                errors.append(name)
        for secret in app.secrets:
            if self.runner.podman('secret', 'exists', secret['name'], timeout=SHORT_TIMEOUT, check=False).returncode == 0:
                try:
                    self.runner.podman('secret', 'rm', secret['name'], timeout=SHORT_TIMEOUT)
                except BackupError:
                    errors.append(secret['name'])
        for config in app.config_files:
            try:
                self.runner.remove_file(config['path'])
            except BackupError:
                errors.append(config['path'])
        for item in app.data_dirs:
            # The fresh preflight required the directory to be missing or empty, so what is there now was written by
            # the restore; new copies are archive data. A moved-aside `-old-` copy is never touched here. Undoing
            # this adapter's own restore, only the directories it put in place are removed: one it never reached
            # is not its data (the recovery of a dead job has no such memory and relies on the preflight alone).
            rel = item['path']
            ours = not self._dirs_tracked or rel in self._dir_swapped
            try:
                tokens = self._dir_tokens()
                state = self.runner.dir_states([rel], tokens=tokens).get(rel) or {}
                for sibling in state.get('siblings') or []:
                    # Only this job's copies (review L3): a folder of the user named like a sibling stays.
                    if sibling['kind'] in ('new', 'del') and sibling['type'] == 'dir' and sibling['token'] in tokens:
                        self.runner.dir_drop(rel, sibling['kind'], sibling['token'])
                if state.get('type') == 'dir' and ours:
                    self.runner.dir_drop(rel, 'target')
                    self.log(f'已移除還原建立的主機資料夾 ~/{rel}')
                elif state.get('type') == 'dir':
                    self.log(f'主機資料夾 ~/{rel} 不是這次還原寫入的，保留不動')
                elif state.get('type') not in ('missing', None):
                    errors.append(f'~/{rel}')
            except BackupError as error:
                self._log_command_error(error)
                errors.append(f'~/{rel}')
        self._dir_new.clear()
        self._dir_swapped = {}
        objects = self._named_objects(sources)
        for pod in objects['pod']:
            if self.runner.podman('pod', 'rm', pod, timeout=STOP_TIMEOUT, check=False).returncode != 0:
                self.log(f'注意：Pod {pod} 未移除（可能仍被其他容器使用或不存在）。')
        for volume in objects['volume']:
            self.runner.podman('volume', 'rm', '-f', volume, timeout=STOP_TIMEOUT, check=False)
        for network in objects['network']:
            if self.runner.podman('network', 'rm', network, timeout=SHORT_TIMEOUT, check=False).returncode != 0:
                self.log(f'注意：網路 {network} 未移除（可能仍被其他容器使用或不存在）。')
        self._restore_tags()
        if errors:
            raise BackupError('job-failed', f'無法完整移除新部署的項目：{", ".join(errors[:6])}；需人工處理。',
                              app=app.id)
        self.log(f'已移除應用「{app.name}」新建立的所有項目')

    # ----------------------------------------------------------------- checks
    def health(self):
        checks = []
        for i, spec in enumerate(self.app.health, 1):
            ok, detail = self._poll(spec)
            message = (f'健康檢查通過（{spec["url"]}）' if ok
                       else f'健康檢查未通過（{spec["url"]}）：{detail}')
            checks.append({'id': f'{self.app.id}/health-{i}', 'status': 'ok' if ok else 'fail', 'message': message})
        if all(check['status'] == 'ok' for check in checks):
            # The end of the app's unavailability (CONTRACT section 9); without health checks, the moment its units ran.
            self.timing['healthy'] = self.clock() if checks else self.timing.get('started')
        return checks

    def _poll(self, spec):
        deadline = self.clock() + spec['timeout_seconds']
        last = '沒有回應'
        while True:
            try:
                status, _body = self.http_get(spec['url'], min(10, spec['timeout_seconds']), read_body=False)
                if status == spec['expect_status']:
                    return True, f'HTTP {status}'
                last = f'HTTP {status}'
            except Exception:  # noqa: BLE001 - any transport error is "not healthy yet"
                last = '無法連線'
            if self.clock() >= deadline:
                return False, last
            self.sleep(HEALTH_INTERVAL)

    def http_specs(self):
        return [spec for spec in self.app.verify if spec['type'] == 'http-json']

    def verify_snapshot(self):
        """The http-json checks' values (the digest checks are compared inside restore())."""
        snapshot = {}
        for spec in self.http_specs():
            try:
                status, body = self.http_get(spec['url'], 15)
            except Exception:  # noqa: BLE001
                raise BackupError('job-failed', f'無法取得資料核對結果（{spec["url"]}）。', app=self.app.id) from None
            if status != 200:
                raise BackupError('job-failed', f'無法取得資料核對結果（{spec["url"]}，HTTP {status}）。', app=self.app.id)
            try:
                data = json.loads(body.decode('utf-8'))
            except (ValueError, UnicodeDecodeError):
                data = None
            if not isinstance(data, dict):
                raise BackupError('job-failed', f'資料核對結果不是 JSON 物件（{spec["url"]}）。', app=self.app.id)
            values = {key: data.get(key) for key in spec['compare']}
            if len(json.dumps(values, ensure_ascii=False)) > 16384:
                raise BackupError('job-failed', '資料核對結果過大。', app=self.app.id)
            snapshot[spec['id']] = values
        return snapshot
