#!/usr/bin/env python3
"""Marker data in dev-e's apps (batch2_baseline.py), created and read through each app's own interfaces inside dev-e.

    python3 -I -c "$(cat tests/e2e/lab/batch2_markers.py)" <nextcloud|opendesign> read
    python3 -I -c "$(cat tests/e2e/lab/batch2_markers.py)" <nextcloud|opendesign> seed <baseline|after> <stamp>

Runs as appowner inside dev-e (woowbk-owner) and prints one JSON line. stdin: {"password": <the baseline marker
account's password>} (Nextcloud only; generated once by batch2_baseline.py, never printed).
  nextcloud   users (occ user:list, as www-data in nextcloud-app) and the files of woowbk-lab-baseline through WebDAV
              (http://127.0.0.1:18081/remote.php/dav, Basic auth of that user), each with the sha256 of its content.
              baseline: user woowbk-lab-baseline (occ user:add --password-from-env) and its file woowbk-lab-baseline.txt
              (WebDAV PUT, UTF-8 with CJK text). after: user woowbk-lab-after (a random password that nobody keeps: the
              restore removes the user) and woowbk-lab-after.txt in woowbk-lab-baseline's files.
  opendesign  projects (GET /api/projects through the nginx front, Basic auth open-design:<API token>; the token is read
              from the podman secret open-design-api-token in memory) and the files of project woowbk-lab-baseline
              (GET /api/projects/<id>/files, sha256 of each file in the daemon's data volume).
              baseline: project woowbk-lab-baseline with woowbk-lab-baseline.txt (JSON upload, base64). after: project
              woowbk-lab-after.
Seeding only creates what is missing. Every marker name starts with woowbk-lab-."""
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

APP, ACTION = sys.argv[1], sys.argv[2]
TAG = sys.argv[3] if len(sys.argv) > 3 else None
STAMP = sys.argv[4] if len(sys.argv) > 4 else None
INPUT = json.loads(sys.stdin.read() or '{}')
BASE = 'woowbk-lab-baseline'
AFTER = 'woowbk-lab-after'
CONTENT = {BASE: f'{BASE}：實驗室基準檔案（Nextcloud／OpenDesign HA 匯入第二批）\n'.encode(),
           AFTER: f'{AFTER}：備份之後才建立，原位還原後必須消失\n'.encode()}


def run(argv, env=None, timeout=300, data=None):
    proc = subprocess.run(argv, env=env, input=data, capture_output=True, timeout=timeout)
    if proc.returncode:
        raise SystemExit(f'{argv[:6]} failed ({proc.returncode}): {proc.stderr.decode(errors="replace")[-400:]}')
    return proc.stdout


def http(method, url, auth, body=None, headers=None, retry=180):
    """One request with Basic auth; retries refused connections and 502/503 while the app (re)starts."""
    deadline = time.monotonic() + retry
    while True:
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header('Authorization', 'Basic ' + base64.b64encode(auth.encode()).decode())
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            if error.code in (502, 503) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return error.code, error.read()
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)


def sha(data):
    return hashlib.sha256(data).hexdigest()


# ---- Nextcloud ---------------------------------------------------------------------------------------------------
NC = 'http://127.0.0.1:18081'


def occ(*args, password=None):
    argv = ['podman', 'exec']
    env = None
    if password is not None:
        argv += ['-e', 'OC_PASS']
        env = dict(os.environ, OC_PASS=password)
    argv += ['-u', 'www-data', 'nextcloud-app', 'php', '/var/www/html/occ', *args]
    return run(argv, env=env)


def nc_users():
    users = json.loads(occ('user:list', '--output=json', '--limit=1000'))
    return sorted(u for u in users if u.startswith('woowbk-lab-'))


def nc_dav(method, user, password, name='', body=None, headers=None):
    return http(method, f'{NC}/remote.php/dav/files/{user}/{name}', f'{user}:{password}', body, headers)


def nc_files(password):
    status, body = nc_dav('PROPFIND', BASE, password, headers={'Depth': '1'})
    if status != 207:
        raise SystemExit(f'PROPFIND {BASE}: HTTP {status}')
    out = []
    marker = f'/remote.php/dav/files/{BASE}/'
    for part in body.decode().split('<d:href>')[1:]:
        href = part.split('</d:href>', 1)[0]
        name = urllib.parse.unquote(href.split(marker, 1)[-1])
        if name.startswith('woowbk-lab-'):
            status, content = nc_dav('GET', BASE, password, name)
            out.append(f'{name}:{sha(content) if status == 200 else "HTTP" + str(status)}')
    return sorted(out)


def nc_read():
    users = nc_users()
    files = nc_files(INPUT['password']) if BASE in users else []
    return {'users': users, 'files': files}


def nc_seed(tag):
    password = INPUT['password']
    created = []
    if tag == 'baseline':
        if BASE not in nc_users():
            occ('user:add', '--password-from-env', '--display-name', 'woowbk-lab baseline', BASE, password=password)
            created.append(f'user {BASE}')
        name = f'{BASE}.txt'
        status, _ = nc_dav('GET', BASE, password, name)
        if status != 200:
            status, _ = nc_dav('PUT', BASE, password, name, CONTENT[BASE], {'Content-Type': 'text/plain; charset=utf-8'})
            if status not in (201, 204):
                raise SystemExit(f'PUT {name}: HTTP {status}')
            created.append(f'file {name} {sha(CONTENT[BASE])[:12]}')
    else:
        occ('user:add', '--password-from-env', '--display-name', 'woowbk-lab after', AFTER,
            password=secrets.token_urlsafe(24))
        created.append(f'user {AFTER}')
        status, _ = nc_dav('PUT', BASE, password, f'{AFTER}.txt', CONTENT[AFTER], {'Content-Type': 'text/plain; charset=utf-8'})
        if status not in (201, 204):
            raise SystemExit(f'PUT {AFTER}.txt: HTTP {status}')
        created.append(f'file {AFTER}.txt')
    return {'created': created, 'stamp': STAMP}


# ---- OpenDesign ----------------------------------------------------------------------------------------------------
OD = 'http://127.0.0.1:7456'


def od_auth():
    token = run(['podman', 'secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', 'open-design-api-token'])
    return 'open-design:' + token.decode().strip()


def od_json(method, path, auth, payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    status, data = http(method, OD + path, auth, body, {'Content-Type': 'application/json'} if body else None)
    try:
        return status, json.loads(data or b'null')
    except ValueError:
        return status, None


def od_projects(auth):
    status, data = od_json('GET', '/api/projects', auth)
    if status != 200:
        raise SystemExit(f'GET /api/projects: HTTP {status}')
    items = data.get('projects', data) if isinstance(data, dict) else data
    return {p['id']: p.get('name') for p in items or [] if isinstance(p, dict) and 'id' in p}


def od_files(auth, project):
    status, data = od_json('GET', f'/api/projects/{project}/files', auth)
    if status != 200:
        raise SystemExit(f'GET /api/projects/{project}/files: HTTP {status}')
    items = data.get('files', data) if isinstance(data, dict) else data
    names = sorted(f.get('name') for f in items or [] if isinstance(f, dict) and str(f.get('name', '')).startswith('woowbk-lab-'))
    out = []
    for name in names:
        digest = run(['podman', 'exec', 'open-design', 'sha256sum', f'/app/.od/projects/{project}/{name}']).split()[0]
        out.append(f'{name}:{digest.decode()}')
    return out


def od_read():
    auth = od_auth()
    projects = od_projects(auth)
    ours = sorted(i for i in projects if i.startswith('woowbk-lab-'))
    return {'projects': ours, 'files': od_files(auth, BASE) if BASE in ours else []}


def od_seed(tag):
    auth = od_auth()
    created = []
    project = BASE if tag == 'baseline' else AFTER
    if project not in od_projects(auth):
        status, data = od_json('POST', '/api/projects', auth, {'id': project, 'name': project})
        if status not in (200, 201):
            raise SystemExit(f'POST /api/projects {project}: HTTP {status} {str(data)[:200]}')
        created.append(f'project {project}')
    if tag == 'baseline':
        name = f'{BASE}.txt'
        if not any(f.startswith(name + ':') for f in od_files(auth, BASE)):
            status, data = od_json('POST', f'/api/projects/{BASE}/files', auth,
                                   {'name': name, 'content': base64.b64encode(CONTENT[BASE]).decode(), 'encoding': 'base64'})
            if status not in (200, 201):
                raise SystemExit(f'POST /api/projects/{BASE}/files: HTTP {status} {str(data)[:200]}')
            created.append(f'file {name} {sha(CONTENT[BASE])[:12]}')
    return {'created': created, 'stamp': STAMP}


ACTIONS = {('nextcloud', 'read'): nc_read, ('opendesign', 'read'): od_read}
if ACTION == 'read':
    result = ACTIONS[(APP, 'read')]()
elif ACTION == 'seed' and TAG in ('baseline', 'after'):
    result = {'nextcloud': nc_seed, 'opendesign': od_seed}[APP](TAG)
else:
    raise SystemExit('usage: <nextcloud|opendesign> read | seed <baseline|after> <stamp>')
print(json.dumps(result, ensure_ascii=False))
