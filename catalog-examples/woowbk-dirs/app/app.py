#!/usr/bin/env python3
"""woowbk-dirs: host-directory backup/restore test fixture (mirrors Nextcloud and Home Assistant).

The app runs as container uid 33 (www-data in Debian images, like Nextcloud), so what it writes into
its bind-mounted HOST directory is owned by one of the owner's subordinate ids on the host. Its state
lives in places a restore has to bring back together:
* PostgreSQL 16 whose data directory is a host directory too (~/.local/share/woowbk-dirs/postgres,
  files of container uid 70). The app connects as its own role `dirs_app` (like Nextcloud's oc_admin)
  with the password from the Podman secret woowbk-dirs-role-password, to two databases: `dirs` (owned by
  the superuser `dirs`, table items owned by dirs_app) and `dirs_audit` (owned by dirs_app). Roles,
  passwords, owners and grants only survive a restore at file level (cold backup), which is the point.
* the host directory ~/woowbk-dirs/data mounted at /srv/data: the owner's files at the top (container
  root, like Home Assistant's config) and www/ written by this app (uid 33): nested docs/<xx>/<yy>/
  files, hard links in archive/, a relative symlink `latest`, user.* xattrs and a SQLite database in
  WAL mode (www/db/app.sqlite; checkpoints are disabled and the process exits without closing it, so
  committed rows stay in app.sqlite-wal and a restore must bring the pair back);
* Podman secrets (role password, HMAC key of the item signatures) and the env file (APP_TITLE).

GET /api/summary condenses everything into values compared before/after a restore:
  items, events      rows in dirs.items / dirs_audit.events (read as dirs_app)
  db_digest          sha256 of {"items": [[id, name, sha256, signature]...], "events": [[id, item_id, action, name]...]}
  db_meta            {"user", "system_identifier", "server_major", "roles", "owners"}: the cluster identity
                     (pg_control) and the role/owner catalog, unchanged only by a file-level restore
  tree, tree_digest  entry count and digest of treelist.listing(/srv/data) (types, modes, container ids,
                     sizes, sha256, file mtimes, symlink targets, user xattrs, hard-link groups)
  sqlite             {"docs", "digest"} of the docs table read through SQLite (WAL included)
  title              APP_TITLE from the env file
  signatures_valid   every item signature recomputed with the *current* app key

Endpoints: GET /healthz, GET /api/summary, GET/POST /api/items, DELETE /api/items/<id>, GET /api/tree,
GET /api/sqlite, GET /api/db. `python3 app.py --healthcheck` probes /healthz for the container health
check. Secret values are never logged or returned.
"""
import errno
import hashlib
import hmac
import json
import os
import re
import signal
import sqlite3
import stat
import sys
import tempfile
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import treelist  # noqa: E402  (shared with tools/check.py and the lab driver)

DB = {
    'host': os.environ.get('DB_HOST', 'woowbk-dirs-db'),
    'port': int(os.environ.get('DB_PORT', '5432')),
    'user': os.environ.get('DB_USER', 'dirs_app'),
}
DATABASES = {'main': os.environ.get('DB_NAME', 'dirs'), 'audit': os.environ.get('DB_AUDIT_NAME', 'dirs_audit')}
PASSWORD_FILE = os.environ.get('DB_PASSWORD_FILE', '/run/secrets/woowbk-dirs-role-password')
APP_KEY_FILE = os.environ.get('APP_KEY_FILE', '/run/secrets/woowbk-dirs-app-key')
DATA_DIR = os.environ.get('DATA_DIR', '/srv/data')
WWW = os.path.join(DATA_DIR, 'www')
DOCS = os.path.join(WWW, 'docs')
ARCHIVE = os.path.join(WWW, 'archive')
SQLITE_DIR = os.path.join(WWW, 'db')
SQLITE_PATH = os.path.join(SQLITE_DIR, 'app.sqlite')
LATEST = os.path.join(WWW, 'latest')
LISTEN = os.environ.get('LISTEN_ADDRESS', '0.0.0.0')
PORT = int(os.environ.get('PORT', '8080'))
APP_TITLE = os.environ.get('APP_TITLE', '')

MAX_BODY = 64 * 1024
MAX_JSON = MAX_BODY * 4 + 4096
MAX_LIST = 1000
NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')
XATTR = 'user.woowbk.item'
SCHEMAS = {
    'main': """CREATE TABLE IF NOT EXISTS items (
                   id bigserial PRIMARY KEY,
                   name text NOT NULL,
                   sha256 text NOT NULL,
                   signature text NOT NULL,
                   created timestamptz NOT NULL DEFAULT now())""",
    'audit': """CREATE TABLE IF NOT EXISTS events (
                    id bigserial PRIMARY KEY,
                    item_id bigint NOT NULL,
                    action text NOT NULL,
                    name text NOT NULL,
                    created timestamptz NOT NULL DEFAULT now())""",
}
SQLITE_SCHEMA = ('CREATE TABLE IF NOT EXISTS docs (item_id INTEGER PRIMARY KEY, name TEXT NOT NULL, '
                 'path TEXT NOT NULL, sha256 TEXT NOT NULL)')

_schema_lock = threading.Lock()
_schema_ready = set()
_sqlite_lock = threading.Lock()
_sqlite = None
_write_lock = threading.Lock()  # one item change at a time: files, links, SQLite and both databases


class Unavailable(Exception):
    """A database or the data directory cannot be used (maps to HTTP 503)."""


class BadRequest(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def read_secret(path):
    # Exact bytes: a restore that changes even a trailing newline must be detectable.
    with open(path, 'rb') as handle:
        return handle.read()


def connect(which):
    """New connection per request (the fixture favours simplicity over pooling)."""
    import pg8000.native  # imported lazily so --healthcheck and the offline tests work without the driver
    try:
        password = read_secret(PASSWORD_FILE).decode('utf-8')
        conn = pg8000.native.Connection(password=password, database=DATABASES[which], timeout=10,
                                        application_name='woowbk-dirs', **DB)
    except Exception as error:  # noqa: BLE001 - every connect failure is "unavailable"
        raise Unavailable(f'{which}: {type(error).__name__}') from None
    if which not in _schema_ready:
        with _schema_lock:
            if which not in _schema_ready:
                try:
                    conn.run(SCHEMAS[which])
                except Exception:
                    conn.close()
                    raise
                _schema_ready.add(which)
    return conn


def query(which, sql, **params):
    conn = connect(which)
    try:
        return conn.run(sql, **params)
    finally:
        conn.close()


def sqlite_db():
    """The process-wide SQLite connection (WAL, no automatic checkpoints, never closed on purpose)."""
    global _sqlite
    with _sqlite_lock:
        if _sqlite is None:
            try:
                created = not os.path.exists(SQLITE_PATH)
                os.makedirs(SQLITE_DIR, mode=0o700, exist_ok=True)
                db = sqlite3.connect(SQLITE_PATH, timeout=10, isolation_level=None, check_same_thread=False)
                if created:
                    os.chmod(SQLITE_PATH, 0o600)
                db.execute('PRAGMA journal_mode=WAL')
                db.execute('PRAGMA wal_autocheckpoint=0')
                db.execute('PRAGMA synchronous=FULL')
                db.execute(SQLITE_SCHEMA)
            except (OSError, sqlite3.Error) as error:
                raise Unavailable(f'sqlite: {type(error).__name__}') from None
            _sqlite = db
        return _sqlite


def sqlite_rows():
    db = sqlite_db()
    with _sqlite_lock:
        try:
            return [list(r) for r in db.execute('SELECT item_id, name, path, sha256 FROM docs ORDER BY item_id')]
        except sqlite3.Error as error:
            raise Unavailable(f'sqlite: {type(error).__name__}') from None


def sqlite_exec(sql, params=()):
    db = sqlite_db()
    with _sqlite_lock:
        db.execute(sql, params)


def sign(key, item_id, name, sha256):
    message = json.dumps([item_id, name, sha256], ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def canonical_sha256(value):
    data = json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def doc_rel(item_id, name):
    """docs/<xx>/<yy>/<id>-<name>.txt: two levels of nested directories, like Nextcloud's appdata."""
    shard = hashlib.sha256(str(item_id).encode('ascii')).hexdigest()
    return f'docs/{shard[:2]}/{shard[2:4]}/{item_id:05d}-{name}.txt'


def archive_rel(item_id, name):
    return f'archive/{item_id:05d}-{name}.txt'


def items_rows():
    rows = query('main', 'SELECT id, name, sha256, signature, created FROM items ORDER BY id')
    return [{'id': int(r[0]), 'name': r[1], 'sha256': r[2], 'signature': r[3], 'created': r[4].isoformat()}
            for r in rows]


def events_rows():
    rows = query('audit', 'SELECT id, item_id, action, name FROM events ORDER BY id')
    return [[int(r[0]), int(r[1]), r[2], r[3]] for r in rows]


def db_meta():
    conn = connect('main')
    try:
        user, major = conn.run("SELECT current_user::text, current_setting('server_version_num')::int / 10000")[0]
        try:
            ident = str(conn.run('SELECT system_identifier FROM pg_control_system()')[0][0])
        except Exception:  # noqa: BLE001 - no EXECUTE privilege: report it instead of failing the summary
            ident = None
        roles = [[r[0], bool(r[1]), bool(r[2])] for r in
                 conn.run("SELECT rolname::text, rolcanlogin, rolsuper FROM pg_roles WHERE rolname !~ '^pg_' "
                          'ORDER BY rolname')]
        owners = {f'database:{r[0]}': r[1] for r in
                  conn.run('SELECT datname::text, pg_get_userbyid(datdba)::text FROM pg_database '
                           'WHERE datname IN (:main, :audit) ORDER BY datname', **DATABASES)}
        rows = conn.run("SELECT tableowner::text FROM pg_tables WHERE schemaname = 'public' AND tablename = 'items'")
        owners[f'table:{DATABASES["main"]}.items'] = rows[0][0] if rows else None
    finally:
        conn.close()
    rows = query('audit', "SELECT tableowner::text FROM pg_tables WHERE schemaname = 'public' AND tablename = 'events'")
    owners[f'table:{DATABASES["audit"]}.events'] = rows[0][0] if rows else None
    return {'user': user, 'system_identifier': ident, 'server_major': int(major), 'roles': roles, 'owners': owners}


def tree():
    try:
        return treelist.listing(DATA_DIR)
    except OSError as error:
        raise Unavailable(f'data: {type(error).__name__}') from None


def summary():
    key = read_secret(APP_KEY_FILE)
    items = items_rows()
    events = events_rows()
    rows = [[i['id'], i['name'], i['sha256'], i['signature']] for i in items]
    docs = sqlite_rows()
    entries = tree()
    return {
        'items': len(rows),
        'events': len(events),
        'db_digest': canonical_sha256({'items': rows, 'events': events}),
        'db_meta': db_meta(),
        'tree': len(entries),
        'tree_digest': treelist.digest(entries),
        'sqlite': {'docs': len(docs), 'digest': canonical_sha256(docs)},
        'title': APP_TITLE,
        'signatures_valid': all(hmac.compare_digest(sign(key, i, n, s), sig) for i, n, s, sig in rows),
    }


def _write_file(path, data, mode):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.tmp-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _set_xattr(path, value):
    try:
        os.setxattr(path, XATTR, value, follow_symlinks=False)
    except OSError as error:
        if error.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP):
            raise


def _point_latest(rel):
    """Atomically (re)point www/latest, a relative symlink, at `rel`; remove it when rel is None."""
    if rel is None:
        try:
            os.unlink(LATEST)
        except FileNotFoundError:
            pass
        return
    tmp = os.path.join(WWW, f'.tmp-latest-{os.getpid()}-{threading.get_ident()}')
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    os.symlink(rel, tmp)
    os.replace(tmp, LATEST)


def _remove(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def add_item(name, body):
    key = read_secret(APP_KEY_FILE)
    data = body.encode('utf-8')
    sha = hashlib.sha256(data).hexdigest()
    with _write_lock:
        item_id = int(query('main', "SELECT nextval(pg_get_serial_sequence('items', 'id'))")[0][0])
        doc, link = doc_rel(item_id, name), archive_rel(item_id, name)
        doc_path, link_path = os.path.join(WWW, doc), os.path.join(WWW, link)
        created = []
        try:
            _write_file(doc_path, data, 0o640)
            created.append(doc_path)
            _set_xattr(doc_path, str(item_id).encode('ascii'))
            os.makedirs(os.path.dirname(link_path), mode=0o750, exist_ok=True)
            os.link(doc_path, link_path)
            created.append(link_path)
            sqlite_exec('INSERT INTO docs (item_id, name, path, sha256) VALUES (?, ?, ?, ?)', (item_id, name, doc, sha))
            query('main', 'INSERT INTO items (id, name, sha256, signature) VALUES (:id, :name, :sha, :sig)',
                  id=item_id, name=name, sha=sha, sig=sign(key, item_id, name, sha))
        except BaseException:
            for path in created:
                _remove(path)
            try:
                sqlite_exec('DELETE FROM docs WHERE item_id = ?', (item_id,))
            except Unavailable:
                pass
            raise
        query('audit', "INSERT INTO events (item_id, action, name) VALUES (:id, 'create', :name)", id=item_id, name=name)
        _point_latest(doc)
    return {'id': item_id, 'name': name, 'sha256': sha, 'path': doc, 'archive': link}


def delete_item(item_id):
    with _write_lock:
        rows = query('main', 'DELETE FROM items WHERE id = :id RETURNING name', id=item_id)
        if not rows:
            raise BadRequest(404, '找不到此項目。')
        name = rows[0][0]
        _remove(os.path.join(WWW, doc_rel(item_id, name)))
        _remove(os.path.join(WWW, archive_rel(item_id, name)))
        sqlite_exec('DELETE FROM docs WHERE item_id = ?', (item_id,))
        query('audit', "INSERT INTO events (item_id, action, name) VALUES (:id, 'delete', :name)", id=item_id, name=name)
        remaining = sqlite_rows()
        _point_latest(remaining[-1][2] if remaining else None)
    return {'id': item_id, 'name': name, 'deleted': True}


def health():
    result = {'database': False, 'audit_database': False, 'data_writable': False, 'sqlite': False}
    for which, key in (('main', 'database'), ('audit', 'audit_database')):
        try:
            query(which, 'SELECT 1')
            result[key] = True
        except Exception:  # noqa: BLE001
            pass
    try:
        with tempfile.NamedTemporaryFile(dir=WWW, prefix='.healthz-') as probe:
            probe.write(b'ok')
            probe.flush()
            os.fsync(probe.fileno())
        result['data_writable'] = True
    except OSError:
        pass
    try:
        db = sqlite_db()
        with _sqlite_lock:
            db.execute('SELECT count(*) FROM docs').fetchone()
        result['sqlite'] = True
    except (Unavailable, sqlite3.Error):
        pass
    ok = all(result.values())
    return ok, {'ok': ok, **result}


class Handler(BaseHTTPRequestHandler):
    server_version = 'woowbk-dirs/1'

    def log_message(self, fmt, *args):  # request line + status only, never bodies
        sys.stderr.write('%s %s\n' % (self.address_string(), fmt % args))

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def dispatch(self, method):
        path = urllib.parse.urlsplit(self.path).path
        try:
            if method == 'GET' and path == '/healthz':
                ok, detail = health()
                return self.send_json(200 if ok else 503, detail)
            if method == 'GET' and path == '/':
                return self.send_json(200, {'app': 'woowbk-dirs', 'title': APP_TITLE})
            if method == 'GET' and path == '/api/summary':
                return self.send_json(200, summary())
            if method == 'GET' and path == '/api/tree':
                entries = tree()
                return self.send_json(200, {'root': DATA_DIR, 'count': len(entries), 'digest': treelist.digest(entries),
                                            'entries': entries})
            if method == 'GET' and path == '/api/sqlite':
                return self.send_json(200, {'docs': sqlite_rows()})
            if method == 'GET' and path == '/api/db':
                return self.send_json(200, {'items': items_rows(), 'events': events_rows(), 'meta': db_meta()})
            if path == '/api/items':
                if method == 'GET':
                    return self.send_json(200, {'items': items_rows()[-MAX_LIST:]})
                if method == 'POST':
                    return self.post_item()
            match = re.fullmatch(r'/api/items/([0-9]{1,12})', path)
            if match and method == 'DELETE':
                return self.send_json(200, delete_item(int(match.group(1))))
            raise BadRequest(404 if method == 'GET' else 405, '找不到此路徑或不支援此方法。')
        except BadRequest as error:
            self.send_json(error.status, {'error': error.message})
        except Unavailable as error:
            self.send_json(503, {'error': '資料庫或資料目錄目前無法使用。', 'detail': str(error)})
        except Exception as error:  # noqa: BLE001
            sys.stderr.write(f'error: {type(error).__name__}\n')
            self.send_json(500, {'error': '內部錯誤。'})

    def post_item(self):
        try:
            length = int(self.headers.get('Content-Length', ''))
        except ValueError:
            raise BadRequest(411, '需要 Content-Length。') from None
        if not 0 <= length <= MAX_JSON:
            raise BadRequest(413, '內容過大。')
        try:
            data = json.loads(self.rfile.read(length).decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            raise BadRequest(400, '內容必須是 JSON。') from None
        if not isinstance(data, dict) or set(data) - {'name', 'body'}:
            raise BadRequest(400, '只接受 name 與 body 欄位。')
        name, body = data.get('name'), data.get('body', '')
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise BadRequest(400, 'name 必須是英數字開頭、可含 . _ - 的 1 到 64 字元名稱。')
        if not isinstance(body, str) or len(body) > MAX_BODY:
            raise BadRequest(400, f'body 必須是最多 {MAX_BODY} 字元的字串。')
        self.send_json(201, add_item(name, body))

    def do_GET(self):  # noqa: N802
        self.dispatch('GET')

    def do_POST(self):  # noqa: N802
        self.dispatch('POST')

    def do_DELETE(self):  # noqa: N802
        self.dispatch('DELETE')


def healthcheck():
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f'http://127.0.0.1:{PORT}/healthz', timeout=8) as response:
            return 0 if response.status == 200 else 1
    except Exception:  # noqa: BLE001
        return 1


def prepare_www():
    """Create the app's own subdirectories when www/ is usable; a missing or foreign www/ is left to /healthz."""
    try:
        st = os.stat(WWW)
    except OSError:
        return
    if not stat.S_ISDIR(st.st_mode) or not os.access(WWW, os.W_OK):
        return
    for path, mode in ((DOCS, 0o750), (ARCHIVE, 0o750), (SQLITE_DIR, 0o700)):
        try:
            os.mkdir(path, mode)
        except FileExistsError:
            pass
        except OSError:
            return


def main(argv):
    if argv[1:] == ['--healthcheck']:
        return healthcheck()
    os.umask(0o027)
    prepare_www()
    server = ThreadingHTTPServer((LISTEN, PORT), Handler)
    server.daemon_threads = True

    def stop(_signum, _frame):
        # As PID 1 without a handler SIGTERM would be ignored and podman would wait for SIGKILL.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    sys.stderr.write(f'woowbk-dirs listening on {LISTEN}:{PORT} as uid {os.getuid()}\n')
    server.serve_forever()
    server.server_close()
    sys.stderr.flush()
    # Leave the SQLite connection open on purpose: closing the last connection would checkpoint the WAL into
    # app.sqlite and delete app.sqlite-wal. Exiting like this keeps committed rows only in the WAL (a valid,
    # durable state SQLite recovers on the next open), so a backup must capture the -wal file with the database.
    os._exit(0)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
