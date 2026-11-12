#!/usr/bin/env python3
"""woowbk-demo: a tiny notes service used as the backup/restore test fixture.

State lives in three places a restore has to bring back together:
* PostgreSQL (pg8000, password from the Podman secret woowbk-demo-db-password): notes signed with
  HMAC-SHA256 using the secret woowbk-demo-app-key;
* the volume mounted at /data: uploaded files in /data/files;
* the env file (EnvironmentFile=): APP_TITLE.

GET /api/summary condenses everything into values that can be compared before/after a restore:
  notes             number of rows in the notes table
  files             number of regular files in /data/files
  digest            sha256 of the canonical JSON
                      {"files": [[name, sha256], ...sorted by name],
                       "notes": [[id, title, body, signature], ...sorted by id]}
                    (sort_keys, separators (',', ':'), ensure_ascii=False, UTF-8)
  title             APP_TITLE from the environment
  signatures_valid  every stored signature recomputed with the *current* app key

Endpoints: GET /healthz, GET /api/summary, GET/POST /api/notes, GET /api/files,
POST /api/files?name=<name> (raw body), GET /api/files/<name>.
`python3 app.py --healthcheck` probes /healthz for the container health check.
Secret values are never logged or returned.
"""
import hashlib
import hmac
import json
import os
import re
import signal
import stat
import sys
import tempfile
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = {
    'host': os.environ.get('DB_HOST', 'woowbk-demo-db'),
    'port': int(os.environ.get('DB_PORT', '5432')),
    'database': os.environ.get('DB_NAME', 'notes'),
    'user': os.environ.get('DB_USER', 'notes'),
}
DB_PASSWORD_FILE = os.environ.get('DB_PASSWORD_FILE', '/run/secrets/woowbk-demo-db-password')
APP_KEY_FILE = os.environ.get('APP_KEY_FILE', '/run/secrets/woowbk-demo-app-key')
DATA_DIR = os.environ.get('DATA_DIR', '/data')
FILES_DIR = os.path.join(DATA_DIR, 'files')
LISTEN = os.environ.get('LISTEN_ADDRESS', '0.0.0.0')
PORT = int(os.environ.get('PORT', '8080'))
APP_TITLE = os.environ.get('APP_TITLE', '')

MAX_TITLE = 200
MAX_BODY = 64 * 1024
MAX_JSON = MAX_BODY * 4 + 4096
MAX_FILE = 16 * 1024 * 1024
MAX_LIST = 1000
NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
SCHEMA = """
CREATE TABLE IF NOT EXISTS notes (
    id bigserial PRIMARY KEY,
    title text NOT NULL,
    body text NOT NULL,
    signature text NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
)"""

_schema_lock = threading.Lock()
_schema_ready = False


class Unavailable(Exception):
    """The database cannot be reached (maps to HTTP 503)."""


class BadRequest(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def read_secret(path):
    # Exact bytes: a restore that changes even a trailing newline must be detectable.
    with open(path, 'rb') as handle:
        return handle.read()


def connect():
    """New connection per request (the fixture favours simplicity over pooling)."""
    global _schema_ready
    import pg8000.native  # imported lazily so --healthcheck works without the driver
    try:
        password = read_secret(DB_PASSWORD_FILE).decode('utf-8')
        conn = pg8000.native.Connection(password=password, timeout=10, application_name='woowbk-demo', **DB)
    except Exception as error:  # noqa: BLE001 - every connect failure is "unavailable"
        raise Unavailable(type(error).__name__) from None
    if not _schema_ready:
        with _schema_lock:
            if not _schema_ready:
                try:
                    conn.run(SCHEMA)
                except Exception:
                    conn.close()
                    raise
                _schema_ready = True
    return conn


def sign(key, note_id, title, body):
    message = json.dumps([note_id, title, body], ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b''):
            digest.update(chunk)
    return digest.hexdigest()


def list_files():
    try:
        names = sorted(os.listdir(FILES_DIR))
    except FileNotFoundError:
        return []
    result = []
    for name in names:
        if not NAME_RE.fullmatch(name):  # skips ".upload-*" temporaries
            continue
        path = os.path.join(FILES_DIR, name)
        st = os.lstat(path)
        if stat.S_ISREG(st.st_mode):
            result.append({'name': name, 'size': st.st_size, 'sha256': file_sha256(path)})
    return result


def all_notes():
    conn = connect()
    try:
        rows = conn.run('SELECT id, title, body, signature, created FROM notes ORDER BY id')
    finally:
        conn.close()
    return [{'id': int(r[0]), 'title': r[1], 'body': r[2], 'signature': r[3], 'created': r[4].isoformat()}
            for r in rows]


def summary():
    key = read_secret(APP_KEY_FILE)
    notes = all_notes()
    files = list_files()
    rows = [[n['id'], n['title'], n['body'], n['signature']] for n in notes]
    canonical = json.dumps({'notes': rows, 'files': [[f['name'], f['sha256']] for f in files]},
                           ensure_ascii=False, separators=(',', ':'), sort_keys=True)
    valid = all(hmac.compare_digest(sign(key, i, t, b), s) for i, t, b, s in rows)
    return {'notes': len(rows), 'files': len(files), 'digest': hashlib.sha256(canonical.encode('utf-8')).hexdigest(),
            'title': APP_TITLE, 'signatures_valid': valid}


def add_note(title, body):
    key = read_secret(APP_KEY_FILE)
    conn = connect()
    try:
        note_id = int(conn.run("SELECT nextval(pg_get_serial_sequence('notes', 'id'))")[0][0])
        signature = sign(key, note_id, title, body)
        created = conn.run('INSERT INTO notes (id, title, body, signature) VALUES (:id, :title, :body, :sig) '
                           'RETURNING created', id=note_id, title=title, body=body, sig=signature)[0][0]
    finally:
        conn.close()
    return {'id': note_id, 'title': title, 'body': body, 'signature': signature, 'created': created.isoformat()}


def save_file(name, stream, length):
    os.makedirs(FILES_DIR, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.upload-', dir=FILES_DIR)
    digest, remaining = hashlib.sha256(), length
    try:
        with os.fdopen(fd, 'wb') as handle:
            while remaining:
                chunk = stream.read(min(remaining, 1 << 16))
                if not chunk:
                    raise BadRequest(400, '上傳內容不完整。')
                handle.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(FILES_DIR, name))
        tmp = None
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return {'name': name, 'size': length, 'sha256': digest.hexdigest()}


def health():
    db_ok = data_ok = False
    try:
        conn = connect()
        try:
            conn.run('SELECT 1')
            db_ok = True
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        db_ok = False
    try:
        os.makedirs(FILES_DIR, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=DATA_DIR, prefix='.healthz-') as probe:
            probe.write(b'ok')
            probe.flush()
            os.fsync(probe.fileno())
        data_ok = True
    except OSError:
        data_ok = False
    return db_ok and data_ok, {'ok': db_ok and data_ok, 'database': db_ok, 'data_writable': data_ok}


class Handler(BaseHTTPRequestHandler):
    server_version = 'woowbk-demo/1'

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

    def content_length(self, limit):
        try:
            length = int(self.headers.get('Content-Length', ''))
        except ValueError:
            raise BadRequest(411, '需要 Content-Length。') from None
        if length < 0:
            raise BadRequest(400, 'Content-Length 不正確。')
        if length > limit:
            raise BadRequest(413, f'內容超過上限（{limit} 位元組）。')
        return length

    def dispatch(self, method):
        url = urllib.parse.urlsplit(self.path)
        path = url.path
        try:
            if method == 'GET' and path == '/healthz':
                ok, detail = health()
                return self.send_json(200 if ok else 503, detail)
            if method == 'GET' and path == '/':
                return self.send_json(200, {'app': 'woowbk-demo', 'title': APP_TITLE})
            if method == 'GET' and path == '/api/summary':
                return self.send_json(200, summary())
            if path == '/api/notes':
                if method == 'GET':
                    return self.send_json(200, {'notes': all_notes()[-MAX_LIST:]})
                return self.post_note()
            if path == '/api/files':
                if method == 'GET':
                    return self.send_json(200, {'files': list_files()})
                query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
                names = query.get('name', [])
                if len(names) != 1 or not NAME_RE.fullmatch(names[0]):
                    raise BadRequest(400, '檔名不正確（英數字開頭，可含 . _ -，最長 128 字元）。')
                length = self.content_length(MAX_FILE)
                return self.send_json(201, save_file(names[0], self.rfile, length))
            if method == 'GET' and path.startswith('/api/files/'):
                return self.get_file(urllib.parse.unquote(path[len('/api/files/'):]))
            raise BadRequest(404 if method == 'GET' else 405, '找不到此路徑或不支援此方法。')
        except BadRequest as error:
            self.send_json(error.status, {'error': error.message})
        except Unavailable:
            self.send_json(503, {'error': '資料庫目前無法連線。'})
        except Exception as error:  # noqa: BLE001
            sys.stderr.write(f'error: {type(error).__name__}\n')
            self.send_json(500, {'error': '內部錯誤。'})

    def post_note(self):
        length = self.content_length(MAX_JSON)
        try:
            data = json.loads(self.rfile.read(length).decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            raise BadRequest(400, '內容必須是 JSON。') from None
        if not isinstance(data, dict) or set(data) - {'title', 'body'}:
            raise BadRequest(400, '只接受 title 與 body 欄位。')
        title, body = data.get('title'), data.get('body', '')
        if not isinstance(title, str) or not title.strip() or len(title) > MAX_TITLE:
            raise BadRequest(400, f'title 必須是 1 到 {MAX_TITLE} 字元的字串。')
        if not isinstance(body, str) or len(body) > MAX_BODY:
            raise BadRequest(400, f'body 必須是最多 {MAX_BODY} 字元的字串。')
        self.send_json(201, add_note(title, body))

    def get_file(self, name):
        if not NAME_RE.fullmatch(name):
            raise BadRequest(400, '檔名不正確。')
        path = os.path.join(FILES_DIR, name)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            raise BadRequest(404, '找不到檔案。') from None
        with os.fdopen(fd, 'rb') as handle:
            st = os.fstat(handle.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise BadRequest(404, '找不到檔案。')
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(st.st_size))
            self.end_headers()
            for chunk in iter(lambda: handle.read(1 << 16), b''):
                self.wfile.write(chunk)

    def do_GET(self):  # noqa: N802
        self.dispatch('GET')

    def do_POST(self):  # noqa: N802
        self.dispatch('POST')


def healthcheck():
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{PORT}/healthz', timeout=8) as response:
            return 0 if response.status == 200 else 1
    except Exception:  # noqa: BLE001
        return 1


def main(argv):
    if argv[1:] == ['--healthcheck']:
        return healthcheck()
    os.makedirs(FILES_DIR, exist_ok=True)
    server = ThreadingHTTPServer((LISTEN, PORT), Handler)
    server.daemon_threads = True

    def stop(_signum, _frame):
        # As PID 1 without a handler SIGTERM would be ignored and podman would wait for SIGKILL.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    sys.stderr.write(f'woowbk-demo listening on {LISTEN}:{PORT}\n')
    server.serve_forever()
    server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
