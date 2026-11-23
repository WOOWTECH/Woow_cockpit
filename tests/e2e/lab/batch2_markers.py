#!/usr/bin/env python3
"""Marker data in dev-e's apps (batch2_baseline.py), created and read through each app's own interfaces inside dev-e.

    python3 -I -c "$(cat tests/e2e/lab/batch2_markers.py)" <nextcloud|opendesign|code-server> read
    python3 -I -c "$(cat tests/e2e/lab/batch2_markers.py)" <nextcloud|opendesign|code-server> seed <baseline|after> <stamp>
    python3 -I -c "$(cat tests/e2e/lab/batch2_markers.py)" code-server login

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
  code-server one marker in each of the three areas the catalog entry woow-code-server backs up: an IDE snippet
              (snippets/ in the woow-code-server-ide volume), a pi skill (skills/<name>/SKILL.md in the
              woow-code-server-pi-data volume) and a workspace file (~/Desktop, the container's /workspace), written as
              appowner the way the container's coder sees them (podman unshare), each read with its sha256.
              baseline: exactly the device markers of lane codeserver-import's harness (codeserver_full_flow.py
              DEVICE_MARKERS), so that harness finds them and seeds nothing; after: the same with woowbk-lab-after.
              login: the real browser login inside dev-e: POST /login with the password from the podman secret
              code-server-config (302 + code-server-session cookie); GET / with that cookie (302 ./?folder=/workspace, the
              default folder) and that page (200, the workbench); GET / without it (302 ./login); a wrong password (no
              cookie). Only status codes and redirect paths are printed, never the password or the cookie.
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


# ---- code-server -------------------------------------------------------------------------------------------------
# Areas as appowner sees them: the IDE volume (the container's /home/coder/.local/share/code-server/User), the agents'
# volume (/data/pi-agent) and the workspace folder (catalog data_dirs Desktop, the container's /workspace).
CS_VOLUMES = {'ide': 'woow-code-server-ide', 'pi': 'woow-code-server-pi-data'}
CS_DESKTOP = os.path.join(os.path.expanduser('~'), 'Desktop')   # woowbk-owner sets HOME=/home/appowner
CS_PORT = int(os.environ.get('WOOWBK_LAB_CS_PORT') or 18443)   # dev-e: always 18443 (woowbk-owner clears the env)
# The baseline markers are byte for byte the device markers of lane codeserver-import's harness
# (tests/e2e/lab/codeserver_full_flow.py DEVICE_MARKERS, branch feat/ha-import-code-server-20261123): that harness then
# finds them in place, seeds nothing and leaves dev-e's baseline as it found it.
CS_MARKERS = {
    BASE: {'ide:snippets/woowbk-lab-baseline.code-snippets':
           '{"woowbk-lab-baseline": {"prefix": "woowbk", "body": "實驗室基準片段（code-server HA 匯入）"}}\n',
           'pi:skills/woowbk-lab-baseline/SKILL.md': '# woowbk-lab-baseline\n實驗室基準技能（code-server HA 匯入）\n',
           'desktop:woowbk-lab-baseline.txt': '實驗室基準工作區檔案（code-server HA 匯入）\n'},
    AFTER: {'ide:snippets/woowbk-lab-after.code-snippets':
            '{"woowbk-lab-after": {"prefix": "woowbk", "body": "備份之後才建立，原位還原後必須消失"}}\n',
            'pi:skills/woowbk-lab-after/SKILL.md': '# woowbk-lab-after\n備份之後才建立，原位還原後必須消失\n',
            'desktop:woowbk-lab-after.txt': 'woowbk-lab-after：備份之後才建立，原位還原後必須消失\n'},
}
# Every woowbk-lab-* entry of the three areas with the sha256 of its content (a skill: of its SKILL.md), as
# "<kind>\t<name>\t<sha256|missing|not-a-file>" lines. Runs under `podman unshare` (the volumes' files belong to the
# container's coder, i.e. appowner, and to its subordinate ids).
CS_LIST = r"""set -eu
digest() { if [ -f "$1" ]; then sha256sum < "$1" | cut -d' ' -f1; elif [ -e "$1" ]; then echo not-a-file; else echo missing; fi; }
for f in "$1"/snippets/woowbk-lab-*; do [ -e "$f" ] && printf 'snippets\t%s\t%s\n' "${f##*/}" "$(digest "$f")"; done
for d in "$2"/skills/woowbk-lab-*; do [ -e "$d" ] && printf 'skills\t%s\t%s\n' "${d##*/}" "$(digest "$d/SKILL.md")"; done
for f in "$3"/woowbk-lab-*; do [ -e "$f" ] && printf 'files\t%s\t%s\n' "${f##*/}" "$(digest "$f")"; done
true
"""


def cs_mount(area):
    return run(['podman', 'volume', 'inspect', '--format', '{{.Mountpoint}}', CS_VOLUMES[area]]).decode().strip()


def cs_path(spec):
    area, rel = spec.split(':', 1)
    return area, os.path.join(CS_DESKTOP if area == 'desktop' else cs_mount(area), rel)


def cs_read():
    out = run(['podman', 'unshare', 'sh', '-c', CS_LIST, 'sh', cs_mount('ide'), cs_mount('pi'), CS_DESKTOP]).decode()
    found = {'snippets': [], 'skills': [], 'files': []}
    for line in out.splitlines():
        kind, name, digest = line.split('\t')
        found[kind].append(f'{name}:{digest}')
    return {kind: sorted(items) for kind, items in found.items()}


def cs_seed(tag):
    name = BASE if tag == 'baseline' else AFTER
    created = []
    for spec, text in CS_MARKERS[name].items():
        area, path = cs_path(spec)
        data = text.encode()
        if area == 'desktop':
            if os.path.exists(path):
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as handle:
                handle.write(data)
        else:
            if subprocess.run(['podman', 'unshare', 'test', '-e', path], capture_output=True, timeout=120).returncode == 0:
                continue
            run(['podman', 'unshare', 'sh', '-c', 'mkdir -p "$(dirname "$1")" && cat > "$1" && chmod 0644 "$1"', 'sh', path],
                data=data)
        created.append(f'{spec} {sha(data)[:12]}')
    return {'created': created, 'stamp': STAMP}


def cs_password():
    """The login password from the podman secret code-server-config (YAML `password: ...`); never printed."""
    data = run(['podman', 'secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', 'code-server-config']).decode()
    for line in data.splitlines():
        key, sep, value = line.partition(':')
        if sep and key.strip() == 'password':
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
                value = value[1:-1]
            return value
    raise SystemExit('no password in the code-server-config secret')


def cs_request(method, path, body=None, headers=None, want_body=False):
    import http.client
    conn = http.client.HTTPConnection('127.0.0.1', CS_PORT, timeout=60)
    try:
        conn.request(method, path, body=body, headers=dict(headers or {}))
        response = conn.getresponse()
        data = response.read()
        return (response.status, response.getheaders(), data) if want_body else (response.status, response.getheaders())
    finally:
        conn.close()


def cs_location(headers):
    return next((value for key, value in headers if key.lower() == 'location'), '')


def cs_session(headers):
    """The code-server-session cookie of a response (name=value only), or None."""
    for key, value in headers:
        if key.lower() == 'set-cookie' and value.startswith('code-server-session='):
            return value.split(';', 1)[0]
    return None


def cs_login():
    """The real browser login: POST /login with the device's password gives a session cookie; with it / redirects to the
    default folder (code-server 4.139.1: 302 ./?folder=/workspace) and that page is the workbench (200); without it /
    redirects to ./login; a wrong password gets no cookie. Only status codes and the redirect paths are reported."""
    form = {'Content-Type': 'application/x-www-form-urlencoded'}
    deadline = time.monotonic() + 180
    while True:
        try:
            health = cs_request('GET', '/healthz')[0]
        except OSError:
            health = None
        if health == 200 or time.monotonic() > deadline:
            break
        time.sleep(3)
    status, headers = cs_request('POST', '/login', urllib.parse.urlencode({'password': cs_password()}), form)
    cookie = cs_session(headers)
    root = folder = page = None
    workbench = False
    if cookie:
        root, root_headers = cs_request('GET', '/', headers={'Cookie': cookie})
        folder = cs_location(root_headers)
        if root == 302 and folder.startswith('./?folder='):
            page, _headers, body = cs_request('GET', folder[1:], headers={'Cookie': cookie}, want_body=True)
            workbench = b'workbench' in body
    anonymous, anonymous_headers = cs_request('GET', '/')
    wrong_status, wrong_headers = cs_request('POST', '/login',
                                             urllib.parse.urlencode({'password': 'woowbk-lab-' + secrets.token_hex(12)}),
                                             form)
    result = {'healthz': health, 'login': status, 'session_cookie': cookie is not None, 'root_with_cookie': root,
              'root_redirect': folder, 'page_with_cookie': page, 'workbench': workbench,
              'page_without_cookie': anonymous, 'anonymous_redirect': cs_location(anonymous_headers),
              'wrong_password': wrong_status, 'wrong_password_cookie': cs_session(wrong_headers) is not None}
    result['ok'] = (health == 200 and status == 302 and cookie is not None and root == 302 and page == 200 and workbench
                    and anonymous == 302 and result['anonymous_redirect'].startswith('./login')
                    and wrong_status != 302 and not result['wrong_password_cookie'])
    return result


ACTIONS = {('nextcloud', 'read'): nc_read, ('opendesign', 'read'): od_read, ('code-server', 'read'): cs_read,
           ('code-server', 'login'): cs_login}
if ACTION in ('read', 'login') and (APP, ACTION) in ACTIONS:
    result = ACTIONS[(APP, ACTION)]()
elif ACTION == 'seed' and TAG in ('baseline', 'after'):
    result = {'nextcloud': nc_seed, 'opendesign': od_seed, 'code-server': cs_seed}[APP](TAG)
else:
    raise SystemExit('usage: <nextcloud|opendesign|code-server> read | seed <baseline|after> <stamp> | code-server login')
print(json.dumps(result, ensure_ascii=False))
