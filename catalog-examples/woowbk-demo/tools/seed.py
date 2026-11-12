#!/usr/bin/env python3
"""Seed (or mutate) the woowbk-demo app as its owner. Test fixture only; stdlib only.

Run as the app owner inside a lab device, for example
    woowbk-owner python3 /opt/woowbk-demo/tools/seed.py --notes 12 --files 4

Every step is idempotent:
1. Podman secrets woowbk-demo-db-password and woowbk-demo-app-key are created with random values
   via `podman secret create NAME -` (value on stdin: never in argv, environment or output) when
   they do not exist yet. Existing secrets are kept (rotating them would orphan the database
   password and invalidate every note signature).
2. ~/.config/woowbk-demo/app.env (0600, directory 0700) holds APP_TITLE. It is rewritten only when
   --title differs from the current value; a running app is then restarted to pick it up.
3. `systemctl --user start woowbk-demo-app.service` (Requires= pulls in the database), unless
   --no-start.
4. Waits for GET /healthz == 200, POSTs N notes and M files with random content (including
   multi-byte UTF-8) and prints the resulting /api/summary as JSON.

Use `--notes 0 --files 0 --no-start` to only print the summary; run again with small numbers or
a new --title to mutate the data after a backup.
"""
import argparse
import hashlib
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

SECRETS = {
    'woowbk-demo-db-password': lambda: secrets.token_urlsafe(24).encode('ascii'),
    'woowbk-demo-app-key': lambda: secrets.token_hex(32).encode('ascii'),
}
APP_UNIT = 'woowbk-demo-app.service'
ENV_REL = '.config/woowbk-demo/app.env'
PHRASES = ['今天的會議紀錄', '備份還原測試資料', '客戶需求整理', '採購清單：螺絲、電線、插座',
           '多位元組字元測試 𠮷野家 ✓', '週報：進度正常', 'Mixed ASCII and 中文 text', '待辦：確認還原後資料一致']


def die(message):
    sys.stderr.write(f'seed: {message}\n')
    sys.exit(1)


def owner_env():
    env = dict(os.environ)
    uid = os.getuid()
    env.setdefault('XDG_RUNTIME_DIR', f'/run/user/{uid}')
    env.setdefault('DBUS_SESSION_BUS_ADDRESS', f'unix:path={env["XDG_RUNTIME_DIR"]}/bus')
    return env


def run(argv, *, input=None, check=True):
    result = subprocess.run(argv, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=owner_env())
    if check and result.returncode != 0:
        tail = result.stderr.decode('utf-8', 'replace').strip().splitlines()[-3:]
        die(f'{" ".join(argv[:4])} failed ({result.returncode}): {" | ".join(tail)}')
    return result


def ensure_secrets():
    created = []
    for name, make in SECRETS.items():
        if run(['podman', 'secret', 'exists', name], check=False).returncode == 0:
            continue
        run(['podman', 'secret', 'create', name, '-'], input=make())
        created.append(name)
    return created


def read_title(path):
    try:
        with open(path, encoding='utf-8') as handle:
            for line in handle:
                if line.startswith('APP_TITLE='):
                    return line[len('APP_TITLE='):].rstrip('\n')
    except FileNotFoundError:
        return None
    return ''


def write_env(path, title):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.app.env-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write('# woowbk-demo settings (EnvironmentFile=). Backed up as a config file.\n')
            handle.write(f'APP_TITLE={title}\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def http(base, method, path, body=None, content_type=None, timeout=15):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--notes', type=int, default=12, help='notes to add (default 12)')
    parser.add_argument('--files', type=int, default=4, help='files to add (default 4)')
    parser.add_argument('--file-size', type=int, default=64 * 1024, help='max bytes per file (default 65536)')
    parser.add_argument('--title', help='APP_TITLE for the env file (default: keep, or 示範筆記（<hostname>）)')
    parser.add_argument('--seed', type=int, help='random seed for note/file content')
    parser.add_argument('--url', default='http://127.0.0.1:18090', help='app base URL')
    parser.add_argument('--no-start', action='store_true', help='do not create secrets/env or start units')
    parser.add_argument('--timeout', type=int, default=240, help='seconds to wait for /healthz')
    args = parser.parse_args()
    if os.geteuid() == 0:
        die('run as the app owner (e.g. woowbk-owner python3 seed.py), not as root')
    if not (0 <= args.notes <= 10000 and 0 <= args.files <= 1000 and 1 <= args.file_size <= 16 * 1024 * 1024):
        die('out-of-range --notes/--files/--file-size')
    report = {'secrets_created': [], 'env_changed': False}

    if not args.no_start:
        report['secrets_created'] = ensure_secrets()
        env_path = os.path.join(os.path.expanduser('~'), ENV_REL)
        current = read_title(env_path)
        wanted = args.title if args.title is not None else current
        if wanted is None:
            wanted = f'示範筆記（{socket.gethostname()}）'
        if '\n' in wanted or len(wanted) > 200:
            die('--title must be one line of at most 200 characters')
        if current != wanted:
            write_env(env_path, wanted)
            report['env_changed'] = True
        if report['env_changed'] and run(['systemctl', '--user', 'is-active', '--quiet', APP_UNIT],
                                         check=False).returncode == 0:
            run(['systemctl', '--user', 'restart', APP_UNIT])
        run(['systemctl', '--user', 'start', APP_UNIT])
    wait_healthy(args.url, args.timeout)

    rng = random.Random(args.seed if args.seed is not None else secrets.randbits(64))
    batch = secrets.token_hex(3)
    notes, files = [], []
    for i in range(args.notes):
        payload = {'title': f'筆記 {batch}-{i + 1:03d}',
                   'body': f'{rng.choice(PHRASES)}\n標記 {rng.getrandbits(64):016x}'}
        status, body = http(args.url, 'POST', '/api/notes', json.dumps(payload, ensure_ascii=False).encode('utf-8'),
                            'application/json; charset=utf-8')
        if status != 201:
            die(f'POST /api/notes -> HTTP {status} {body[:200].decode("utf-8", "replace")}')
        notes.append(json.loads(body)['id'])
    for i in range(args.files):
        name = f'seed-{batch}-{i + 1:02d}.bin'
        data = rng.randbytes(rng.randint(1, args.file_size))
        status, body = http(args.url, 'POST', f'/api/files?name={name}', data, 'application/octet-stream', timeout=60)
        if status != 201 or json.loads(body).get('sha256') != hashlib.sha256(data).hexdigest():
            die(f'POST /api/files?name={name} -> HTTP {status}')
        files.append(name)

    status, body = http(args.url, 'GET', '/api/summary')
    if status != 200:
        die(f'GET /api/summary -> HTTP {status}')
    report.update({'batch': batch, 'notes_added': notes, 'files_added': files, 'summary': json.loads(body)})
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
