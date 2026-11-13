#!/usr/bin/env python3
"""Seed (or mutate) the woowbk-dirs app as its owner. Test fixture only; stdlib only.

Run as the app owner inside a lab device, for example
    woowbk-owner python3 /opt/woowbk-dirs/tools/seed.py --items 6

Every step is idempotent:
1. Podman secrets with random values via `podman secret create NAME -` (value on stdin: never in argv,
   environment or output), kept when they exist:
     woowbk-dirs-db-password    superuser `dirs` (POSTGRES_PASSWORD, only used when the cluster is created)
     woowbk-dirs-role-password  the app's own role `dirs_app` (like Nextcloud's oc_admin)
     woowbk-dirs-app-key        HMAC key of the item signatures
2. ~/.config/woowbk-dirs/app.env (0600, directory 0700) holds APP_TITLE; rewritten only when --title
   differs from the current value (a running app is then restarted to pick it up).
3. Host directories and their fixed content, each item only when it is missing (ids as the containers see them):
     ~/.local/share/woowbk-dirs/postgres  0700  uid/gid 70 (postgres; set with `podman unshare chown`)
     ~/woowbk-dirs                        0750  the owner
     ~/woowbk-dirs/data                   0755  the owner = container root, like Home Assistant's config directory:
                                                README.txt (0644, user.* xattr), .storage/core.json, the empty
                                                directory .storage/empty, 共享/說明 文件.txt (UTF-8 name with a
                                                space), 共享/唯讀.txt (0444) and 共享/設定連結, a symlink that points
                                                OUTSIDE the directory (../../../.config/woowbk-dirs/app.env): a
                                                backup must keep it as a link, never follow it
     ~/woowbk-dirs/data/www               0750  uid/gid 33, written by the app; www/tmp is an empty 0700
                                                directory of uid 33 (an engine that drops empty directories or
                                                their owners is caught by the tree digest)
4. `systemctl --user start woowbk-dirs-db.service`, wait for pg_isready.
5. Bootstrap once, as the superuser over the container's local socket (SQL on stdin): role dirs_app LOGIN
   with a SCRAM-SHA-256 verifier computed here (the clear password never reaches the server or a log),
   GRANT USAGE, CREATE ON SCHEMA public in `dirs`, database dirs_audit OWNER dirs_app.
6. `systemctl --user start woowbk-dirs-app.service`, wait for GET /healthz == 200.
7. --items N new items (POST /api/items, multi-byte UTF-8 bodies), --delete K oldest items
   (DELETE /api/items/<id>), --owner-note T rewrites README.txt as the owner (container root).
Prints a JSON report ending with the resulting /api/summary.

`--items 0 --no-start` only prints the summary; run again with small numbers, --delete, --title or
--owner-note to mutate the data after a backup.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

APP = 'woowbk-dirs'
DB_UNIT, APP_UNIT = 'woowbk-dirs-db.service', 'woowbk-dirs-app.service'
DB_CONTAINER = 'woowbk-dirs-db'
SUPERUSER, MAIN_DB, ROLE, AUDIT_DB = 'dirs', 'dirs', 'dirs_app', 'dirs_audit'
ROLE_SECRET = 'woowbk-dirs-role-password'
SECRETS = {
    'woowbk-dirs-db-password': lambda: secrets.token_urlsafe(24).encode('ascii'),
    ROLE_SECRET: lambda: secrets.token_urlsafe(24).encode('ascii'),
    'woowbk-dirs-app-key': lambda: secrets.token_hex(32).encode('ascii'),
}
ENV_REL = '.config/woowbk-dirs/app.env'
PG_DIR_REL = '.local/share/woowbk-dirs/postgres'
TOP_REL = 'woowbk-dirs'
DATA_REL = 'woowbk-dirs/data'
WWW_REL = 'woowbk-dirs/data/www'
PG_ID, WWW_ID = 70, 33  # container ids: alpine's postgres, Debian's www-data (the app's User=33:33)
# An owner symlink that leaves the data directory (relative, up to the home, then to the env file). Restores keep it
# verbatim; an engine that followed it would put the env file's bytes into the directory tar.
OUTSIDE_LINK_REL, OUTSIDE_LINK_TARGET = f'{DATA_REL}/共享/設定連結', '../../../.config/woowbk-dirs/app.env'
PHRASES = ['會議紀錄', '主機資料夾備份測試', '客戶需求整理', '採購清單：螺絲、電線、插座', '多位元組字元 𠮷野家 ✓',
           '週報：進度正常', 'Mixed ASCII and 中文 text', '待辦：確認還原後資料一致']
NAMES = ['report', 'invoice', 'photo-notes', 'minutes', 'plan', 'contract', 'todo', 'readme']


def die(message):
    sys.stderr.write(f'seed: {message}\n')
    sys.exit(1)


def owner_env():
    env = dict(os.environ)
    uid = os.getuid()
    env.setdefault('XDG_RUNTIME_DIR', f'/run/user/{uid}')
    env.setdefault('DBUS_SESSION_BUS_ADDRESS', f'unix:path={env["XDG_RUNTIME_DIR"]}/bus')
    return env


def run(argv, *, input=None, check=True, timeout=600):
    result = subprocess.run(argv, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=owner_env(),
                            timeout=timeout)
    if check and result.returncode != 0:
        tail = result.stderr.decode('utf-8', 'replace').strip().splitlines()[-3:]
        die(f'{" ".join(argv[:4])} failed ({result.returncode}): {" | ".join(tail)}')
    return result


def home(rel=''):
    return os.path.join(os.path.expanduser('~'), rel) if rel else os.path.expanduser('~')


# ------------------------------------------------------------------ secrets and settings

def ensure_secrets():
    """Create missing secrets; returns {name: value} for the ones created now (values stay in memory)."""
    created = {}
    for name, make in SECRETS.items():
        if run(['podman', 'secret', 'exists', name], check=False).returncode == 0:
            continue
        value = make()
        run(['podman', 'secret', 'create', name, '-'], input=value)
        created[name] = value
    return created


def secret_value(name):
    """Read a secret back (podman prints the value plus one newline); used only to compute a SCRAM verifier."""
    out = run(['podman', 'secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', name]).stdout
    return out[:-1] if out.endswith(b'\n') else out


def scram_verifier(password, *, salt=None, iterations=4096):
    """PostgreSQL's SCRAM-SHA-256 verifier (RFC 5802/7677), as `\\password` computes it client-side."""
    salt = salt if salt is not None else os.urandom(16)
    salted = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
    client_key = hmac.new(salted, b'Client Key', hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b'Server Key', hashlib.sha256).digest()
    b64 = lambda raw: base64.b64encode(raw).decode('ascii')  # noqa: E731
    return f'SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}'


def read_title(path):
    try:
        with open(path, encoding='utf-8') as handle:
            for line in handle:
                if line.startswith('APP_TITLE='):
                    return line[len('APP_TITLE='):].rstrip('\n')
    except FileNotFoundError:
        return None
    return ''


def write_private_text(path, text, mode, dir_mode=0o700):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=dir_mode, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.tmp-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def write_env(path, title):
    write_private_text(path, '# woowbk-dirs settings (EnvironmentFile=). Backed up as a config file.\n'
                             f'APP_TITLE={title}\n', 0o600)


# ------------------------------------------------------------------ host directories

def unshare(*argv):
    return run(['podman', 'unshare', *argv])


def write_owner_note(text):
    """README.txt in the data root, written by the owner (container root inside the app), 0644 + a user xattr."""
    path = home(f'{DATA_REL}/README.txt')
    write_private_text(path, text if text.endswith('\n') else text + '\n', 0o644, dir_mode=0o755)
    try:
        os.setxattr(path, 'user.woowbk.role', b'owner', follow_symlinks=False)
    except OSError:
        pass  # filesystems without user xattrs: the listing simply has none


def _mkdir(rel, mode, created, owner_id=None):
    """mkdir ~/<rel> with exactly `mode` when missing.

    owner_id: container uid/gid that gets the directory. Then it is created inside the owner's user namespace
    (`podman unshare`, root there), because its parent may already belong to that id (www/tmp inside www/)."""
    path = home(rel)
    if os.path.lexists(path):
        return False
    # A parent owned by a container id (www/ is 0750 for uid 33) hides its children from the owner's host view, so
    # lexists() above says "missing" for an existing www/tmp; check again inside the user namespace.
    if owner_id is not None and run(['podman', 'unshare', 'test', '-e', path], check=False).returncode == 0:
        return False
    if owner_id is None:
        os.mkdir(path, mode)
        os.chmod(path, mode)
    else:
        unshare('mkdir', '-m', f'{mode:04o}', '--', path)
        unshare('chown', f'{owner_id}:{owner_id}', '--', path)
    created.append(rel)
    return True


def _owner_file(rel, text, mode, created):
    """A file of the owner (container root in the app) with exactly `mode`, written only when missing."""
    path = home(rel)
    if os.path.lexists(path):
        return
    write_private_text(path, text, mode, dir_mode=0o755)
    created.append(rel)


def _owner_symlink(rel, target, created):
    """A symlink of the owner, created only when the name is free (never followed, never replaced)."""
    path = home(rel)
    if os.path.lexists(path):
        return
    os.symlink(target, path)
    created.append(rel)


def ensure_dirs():
    """Create every host directory item that does not exist yet (never changes existing ones); returns them."""
    created = []
    pg = home(PG_DIR_REL)
    if not os.path.lexists(pg):
        os.makedirs(os.path.dirname(pg), mode=0o700, exist_ok=True)
    _mkdir(PG_DIR_REL, 0o700, created, PG_ID)
    _mkdir(TOP_REL, 0o750, created)
    _mkdir(DATA_REL, 0o755, created)
    if not os.path.lexists(home(f'{DATA_REL}/README.txt')):
        write_owner_note(f'woowbk-dirs 主機資料夾（{socket.gethostname()}）。這個檔案由擁有者建立（容器內為 root）。')
        created.append(f'{DATA_REL}/README.txt')
    _mkdir(f'{DATA_REL}/.storage', 0o755, created)
    _owner_file(f'{DATA_REL}/.storage/core.json',
                json.dumps({'version': 1, 'minor_version': 3, 'key': 'core.config',
                            'data': {'location_name': '示範', 'time_zone': 'Asia/Taipei'}},
                           ensure_ascii=False, indent=2) + '\n', 0o644, created)
    _mkdir(f'{DATA_REL}/.storage/empty', 0o755, created)
    _mkdir(f'{DATA_REL}/共享', 0o755, created)
    _owner_file(f'{DATA_REL}/共享/說明 文件.txt', '檔名含中文與空白，還原後必須完全相同。\n', 0o644, created)
    _owner_file(f'{DATA_REL}/共享/唯讀.txt', '唯讀檔案（0444）。\n', 0o444, created)
    _owner_symlink(OUTSIDE_LINK_REL, OUTSIDE_LINK_TARGET, created)
    _mkdir(WWW_REL, 0o750, created, WWW_ID)
    _mkdir(f'{WWW_REL}/tmp', 0o700, created, WWW_ID)
    return created


# ------------------------------------------------------------------ database bootstrap

def pg_ready():
    return run(['podman', 'exec', DB_CONTAINER, 'pg_isready', '-q', '-h', '127.0.0.1', '-p', '5432', '-U', SUPERUSER,
                '-d', MAIN_DB], check=False, timeout=30).returncode == 0


def wait_pg(timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pg_ready():
            return
        time.sleep(2)
    die(f'PostgreSQL not ready after {timeout}s; see `journalctl --user -u {DB_UNIT}`')


def psql(sql):
    """SQL on stdin to psql as the superuser over the container's local socket (trust); returns stdout."""
    return run(['podman', 'exec', '-i', DB_CONTAINER, 'psql', '-X', '-w', '-q', '-At', '-v', 'ON_ERROR_STOP=1',
                '-U', SUPERUSER, '-d', MAIN_DB], input=sql.encode('utf-8')).stdout.decode('utf-8', 'replace')


def bootstrap(created_secrets):
    """Role dirs_app, its grant in `dirs`, database dirs_audit. Returns what was created or changed."""
    report = {'role_created': False, 'role_password_set': False, 'database_created': False}
    exists = psql(f"SELECT count(*) FROM pg_roles WHERE rolname = '{ROLE}';").strip() == '1'
    if not exists or ROLE_SECRET in created_secrets:
        password = created_secrets.get(ROLE_SECRET) or secret_value(ROLE_SECRET)
        verifier = scram_verifier(password)
        if not exists:
            psql(f"CREATE ROLE {ROLE} LOGIN PASSWORD '{verifier}';")
            report['role_created'] = True
        else:
            psql(f"ALTER ROLE {ROLE} WITH LOGIN PASSWORD '{verifier}';")
        report['role_password_set'] = True
    psql(f'GRANT USAGE, CREATE ON SCHEMA public TO {ROLE};')
    if psql(f"SELECT count(*) FROM pg_database WHERE datname = '{AUDIT_DB}';").strip() != '1':
        psql(f'CREATE DATABASE {AUDIT_DB} OWNER {ROLE};')
        report['database_created'] = True
    return report


# ------------------------------------------------------------------ app API

def http(base, method, path, body=None, content_type=None, timeout=30):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(base + path, data=body, method=method)
    if content_type:
        request.add_header('Content-Type', content_type)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def wait_healthy(base, timeout):
    deadline = time.monotonic() + timeout
    last = 'no response'
    while time.monotonic() < deadline:
        try:
            status, body = http(base, 'GET', '/healthz', timeout=10)
            if status == 200:
                return
            last = f'HTTP {status} {body[:200].decode("utf-8", "replace")}'
        except OSError as error:
            last = type(error).__name__
        time.sleep(2)
    die(f'app not healthy after {timeout}s ({last}); see `journalctl --user -u {APP_UNIT}`')


def get_json(base, path):
    status, body = http(base, 'GET', path)
    if status != 200:
        die(f'GET {path} -> HTTP {status} {body[:200].decode("utf-8", "replace")}')
    return json.loads(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--items', type=int, default=6, help='items to add (default 6)')
    parser.add_argument('--delete', type=int, default=0, help='oldest items to delete (default 0)')
    parser.add_argument('--title', help='APP_TITLE for the env file (default: keep, or 主機資料夾示範（<hostname>）)')
    parser.add_argument('--owner-note', help='rewrite README.txt in the data root as the owner')
    parser.add_argument('--seed', type=int, help='random seed for item names and bodies')
    parser.add_argument('--url', default='http://127.0.0.1:18091', help='app base URL')
    parser.add_argument('--no-start', action='store_true', help='do not create secrets/settings/dirs or start units')
    parser.add_argument('--timeout', type=int, default=300, help='seconds to wait for the database and /healthz')
    args = parser.parse_args()
    if os.geteuid() == 0:
        die('run as the app owner (e.g. woowbk-owner python3 seed.py), not as root')
    if not (0 <= args.items <= 2000 and 0 <= args.delete <= 2000):
        die('out-of-range --items/--delete')
    report = {'secrets_created': [], 'env_changed': False, 'dirs_created': [], 'bootstrap': None}

    if not args.no_start:
        created_secrets = ensure_secrets()
        report['secrets_created'] = sorted(created_secrets)
        env_path = home(ENV_REL)
        current = read_title(env_path)
        wanted = args.title if args.title is not None else current
        if wanted is None:
            wanted = f'主機資料夾示範（{socket.gethostname()}）'
        if '\n' in wanted or len(wanted) > 200:
            die('--title must be one line of at most 200 characters')
        if current != wanted:
            write_env(env_path, wanted)
            report['env_changed'] = True
        report['dirs_created'] = ensure_dirs()
        if args.owner_note is not None:
            if len(args.owner_note) > 2000:
                die('--owner-note is limited to 2000 characters')
            write_owner_note(args.owner_note)
            report['owner_note_written'] = True
        run(['systemctl', '--user', 'start', DB_UNIT], timeout=900)
        wait_pg(args.timeout)
        report['bootstrap'] = bootstrap(created_secrets)
        if report['env_changed'] and run(['systemctl', '--user', 'is-active', '--quiet', APP_UNIT],
                                         check=False).returncode == 0:
            run(['systemctl', '--user', 'restart', APP_UNIT], timeout=300)
        run(['systemctl', '--user', 'start', APP_UNIT], timeout=300)
    wait_healthy(args.url, args.timeout)

    rng = random.Random(args.seed if args.seed is not None else secrets.randbits(64))
    batch = secrets.token_hex(2)
    added, deleted = [], []
    for i in range(args.items):
        payload = {'name': f'{rng.choice(NAMES)}-{batch}-{i + 1:02d}',
                   'body': f'{rng.choice(PHRASES)}\n標記 {rng.getrandbits(64):016x}\n' + 'x' * rng.randint(0, 4096)}
        status, body = http(args.url, 'POST', '/api/items', json.dumps(payload, ensure_ascii=False).encode('utf-8'),
                            'application/json; charset=utf-8')
        if status != 201:
            die(f'POST /api/items -> HTTP {status} {body[:200].decode("utf-8", "replace")}')
        added.append(json.loads(body)['id'])
    if args.delete:
        for item in get_json(args.url, '/api/items')['items'][:args.delete]:
            status, body = http(args.url, 'DELETE', f'/api/items/{item["id"]}')
            if status != 200:
                die(f'DELETE /api/items/{item["id"]} -> HTTP {status}')
            deleted.append(item['id'])
    report.update({'batch': batch, 'items_added': added, 'items_deleted': deleted,
                   'summary': get_json(args.url, '/api/summary')})
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
