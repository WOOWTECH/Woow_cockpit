"""Marker data in dev-d's Omnigent, Hermes, EMQX and Headscale, through each app's own API, CLI or code.

Runs INSIDE dev-d as appowner; batch1_baseline.py starts it with
    woowbk-owner python3 -I -c "<this file>" <app> seed <tag> <stamp>     stdin: {"password": "..."} (or {})
    woowbk-owner python3 -I -c "<this file>" <app> read
and gets one JSON object back. Every marker is named woowbk-lab-<tag> (tag: [a-z0-9-]+).

seed <tag> creates what is missing (the "baseline" tag gets the full set, other tags only the first item):
  omnigent   a non-admin user (invited by the admin, the given password), and for "baseline" a project and a
             paused yearly scheduled task of the first agent (REST: /auth/login, /auth/invite, /auth/register,
             /v1/projects, /v1/agents, /v1/scheduled-tasks)
  hermes     a session with one message in state.db (hermes_state.SessionDB), and for "baseline" a MEMORY.md
             entry (tools.memory_tool.MemoryStore) and a paused cron job (cron.jobs.create_job), all as the
             hermes user inside hermes-agent
  emqx       an MQTT user of the built-in database authenticator (the given password) and a retained message,
             and for "baseline" a banned client id (REST /api/v5 as the dashboard admin)
  headscale  a user, and for "baseline" a reusable pre-auth key (the key text is dropped), a node (a pending
             registration with throwaway keys from `headscale debug create-node`, approved with `headscale auth
             register`) and a MagicDNS extra record
read returns what exists of all of them (names, ids, states; never a key or a password).

No secret is printed: the admins' passwords are read from the apps' podman secrets inside this process, the
marker passwords arrive on stdin, and API tokens stay in memory.
"""
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

APP, ACTION = sys.argv[1], sys.argv[2]
TAG = sys.argv[3] if len(sys.argv) > 3 else ''
STAMP = sys.argv[4] if len(sys.argv) > 4 else time.strftime('%Y%m%dT%H%M%S')
if ACTION == 'seed' and not re.fullmatch(r'[a-z0-9-]{1,32}', TAG):
    sys.exit('tag must be [a-z0-9-]{1,32}')
NAME = f'woowbk-lab-{TAG}'
FULL = TAG == 'baseline'
HOME = os.path.expanduser('~')


def run(*argv, input=None, check=True, timeout=120):
    proc = subprocess.run(list(argv), input=input, capture_output=True, text=True, timeout=timeout)
    if check and proc.returncode:
        # stderr of the apps' CLIs never carries the secrets used here (they are not passed to them)
        raise SystemExit(f'{" ".join(argv[:4])}… exited {proc.returncode}: {proc.stderr.strip()[-300:]}')
    return proc.stdout


def secret(name):
    value = run('podman', 'secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', name)
    return value.rstrip('\n')


def env_value(path, key, default=''):
    try:
        for line in open(os.path.join(HOME, path), encoding='utf-8'):
            if line.startswith(key + '='):
                return line.split('=', 1)[1].strip()
    except OSError:
        pass
    return default


def http(method, url, body=None, token=None, ok=(200, 201, 204), wait=180):
    """One API call. A refused connection, a 502/503/504 from an entrance whose app is still starting, or EMQX's
    400 "not_initialized" (its authenticators load after the dashboard answers) is retried for up to `wait` seconds:
    a backup or restore job ends once the units are started, and EMQX's catalog entry has no health URL the job
    could wait for."""
    data = None if body is None else json.dumps(body).encode()
    deadline = time.monotonic() + wait
    while True:
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header('Content-Type', 'application/json')
        if token:
            request.add_header('Authorization', f'Bearer {token}')
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                code, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            code, raw = error.code, error.read()
        except (urllib.error.URLError, ConnectionError, TimeoutError) as error:
            if time.monotonic() > deadline:
                raise SystemExit(f'{method} {urllib.parse.urlsplit(url).path}: {error}')
            time.sleep(2)
            continue
        starting = code in (502, 503, 504) or (code == 400 and b'not_initialized' in raw)
        if starting and time.monotonic() < deadline:
            time.sleep(2)
            continue
        break
    if ok is not None and code not in ok:
        raise SystemExit(f'{method} {urllib.parse.urlsplit(url).path} -> HTTP {code}: {raw[:300]!r}')
    try:
        return code, json.loads(raw) if raw else None
    except ValueError:
        return code, None


def stdin_password():
    data = json.loads(sys.stdin.read() or '{}')
    return data.get('password') or secrets.token_urlsafe(24)


# ---------------------------------------------------------------- Omnigent
OMNI = 'http://127.0.0.1:{}'.format(env_value('.config/omnigent/omnigent.env', 'OMNIGENT_PORT', '8000'))


def omni_sql(statement):
    return run('podman', 'exec', 'omnigent-postgres', 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'omnigent',
               '-d', 'omnigent', '-Atc', statement).strip()


def omnigent_seed():
    password = stdin_password()
    admin = env_value('.config/omnigent/omnigent.env', 'OMNIGENT_ADMIN_USERNAME', 'admin')
    _, login = http('POST', OMNI + '/auth/login', {'username': admin, 'password': secret('omnigent-admin-password')})
    token = login['token']
    out = {}
    if not omni_sql(f"SELECT 1 FROM users WHERE id = '{NAME}'"):
        _, invite = http('POST', OMNI + '/auth/invite', {'is_admin': False}, token)
        _, reg = http('POST', OMNI + '/auth/register', {'invite': invite['token'], 'username': NAME, 'password': password})
        out['user'] = reg['user']['id']
    if not FULL:
        return out
    if not omni_sql(f"SELECT 1 FROM projects WHERE name = '{NAME}'"):
        _, project = http('POST', OMNI + '/v1/projects', {'name': NAME}, token)
        out['project'] = project.get('id')
    if not omni_sql(f"SELECT 1 FROM scheduled_tasks WHERE name = '{NAME}'"):
        _, agents = http('GET', OMNI + '/v1/agents', None, token)
        items = agents if isinstance(agents, list) else (agents.get('agents') or agents.get('data') or agents.get('items') or [])
        agent_id = items[0]['id']
        _, task = http('POST', OMNI + '/v1/scheduled-tasks',
                       {'name': NAME, 'prompt': f'WOOWBK lab marker {STAMP}: never runs (paused, yearly).',
                        'rrule': 'FREQ=YEARLY;BYMONTH=1;BYMONTHDAY=1', 'timezone': 'Asia/Taipei', 'agent_id': agent_id},
                       token)
        http('PATCH', f'{OMNI}/v1/scheduled-tasks/{task["id"]}', {'state': 'paused'}, token)
        _, task = http('GET', f'{OMNI}/v1/scheduled-tasks/{task["id"]}', None, token)
        out['scheduled_task'] = {'id': task['id'], 'state': task.get('state'), 'agent_id': agent_id}
    return out


def omnigent_read():
    rows = lambda sql: [r for r in omni_sql(sql).splitlines() if r]
    return {'users': rows("SELECT id || ':' || is_admin FROM users WHERE id LIKE 'woowbk-lab-%' ORDER BY id"),
            'projects': rows("SELECT name FROM projects WHERE name LIKE 'woowbk-lab-%' ORDER BY name"),
            'scheduled_tasks': rows("SELECT name || ':state=' || state FROM scheduled_tasks "
                                    "WHERE name LIKE 'woowbk-lab-%' ORDER BY name"),
            'user_count': int(omni_sql('SELECT count(*) FROM users')),
            'alembic': omni_sql('SELECT version_num FROM alembic_version')}


# ---------------------------------------------------------------- Hermes
HERMES_PY = r'''
import json, sys
mode, name, stamp, full = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1"
from hermes_state import SessionDB
out = {}
if mode == "seed":
    db = SessionDB()
    if not db.get_session(name):
        db.create_session(session_id=name, source="woowbk-lab", display_name=f"WOOWBK lab {name}")
        db.append_message(name, role="user", content=f"WOOWBK lab marker {name} {stamp}")
        out["session"] = name
    if full:
        from tools import memory_tool
        from tools.memory_tool import MemoryStore
        memory = memory_tool.get_memory_dir() / "MEMORY.md"
        if name not in (memory.read_text() if memory.exists() else ""):
            store = MemoryStore()
            store.load_from_disk()
            result = store.add("memory", f"WOOWBK lab marker {name} {stamp}")
            out["memory"] = result.get("success", result) if isinstance(result, dict) else result
        from cron.jobs import create_job, list_jobs
        if not any(j.get("name") == name for j in list_jobs(include_disabled=True)):
            job = create_job(f"WOOWBK lab marker {stamp}: never runs (paused).", "0 9 1 1 *", name=name,
                             paused=True, paused_reason="woowbk lab marker")
            out["cron_job"] = job.get("id")
else:
    import sqlite3
    from hermes_state import DEFAULT_DB_PATH
    conn = sqlite3.connect(f"file:{DEFAULT_DB_PATH}?mode=ro", uri=True)
    out["sessions"] = {sid: {"messages": n} for sid, n in conn.execute(
        "SELECT s.id, (SELECT count(*) FROM messages m WHERE m.session_id = s.id) FROM sessions s "
        "WHERE s.id LIKE 'woowbk-lab-%' ORDER BY s.id")}
    out["session_count"] = conn.execute("SELECT count(*) FROM sessions").fetchone()[0]
    out["schema_version"] = conn.execute("SELECT max(version) FROM schema_version").fetchone()[0]
    conn.close()
    from tools import memory_tool
    memory = memory_tool.get_memory_dir() / "MEMORY.md"
    text = memory.read_text() if memory.exists() else ""
    out["memory_markers"] = sorted(set(w for w in text.split() if w.startswith("woowbk-lab-")))
    from cron.jobs import list_jobs
    out["cron_jobs"] = sorted(f'{j.get("name")}:enabled={j.get("enabled")}:state={j.get("state")}'
                              for j in list_jobs(include_disabled=True) if str(j.get("name", "")).startswith("woowbk-lab-"))
print(json.dumps(out))
'''


def hermes_call(mode):
    raw = run('podman', 'exec', '--user', 'hermes', '-w', '/opt/data', 'hermes-agent', '/opt/hermes/.venv/bin/python',
              '-c', HERMES_PY, mode, NAME, STAMP, '1' if FULL else '0', timeout=180)
    return json.loads(raw.strip().splitlines()[-1])


def hermes_seed():
    sys.stdin.read()
    return hermes_call('seed')


def hermes_read():
    return hermes_call('read')


# ---------------------------------------------------------------- EMQX
EMQX = 'http://127.0.0.1:{}'.format(env_value('.config/emqx/emqx.env', 'WOOW_EMQX_PORT_DASHBOARD', '18083'))
AUTHN = '/api/v5/authentication/password_based:built_in_database'


def emqx_token():
    _, login = http('POST', EMQX + '/api/v5/login',
                    {'username': 'admin', 'password': secret('woow-emqx-dashboard-password')})
    return login['token']


def emqx_seed():
    password = stdin_password()
    token = emqx_token()
    out = {}
    have = emqx_read(token)
    if NAME not in have['mqtt_users']:
        http('POST', EMQX + AUTHN + '/users', {'user_id': NAME, 'password': password, 'is_superuser': False}, token)
        out['mqtt_user'] = NAME
    topic = f'woowbk-lab/{TAG}'
    if topic not in have['retained']:
        # 202 = published, no subscriber matched; the retainer stores it either way
        http('POST', EMQX + '/api/v5/publish', {'topic': topic, 'payload': f'WOOWBK lab marker {STAMP}', 'qos': 1,
                                                 'retain': True}, token, ok=(200, 202))
        out['retained'] = topic
    if FULL and NAME not in have['banned']:
        http('POST', EMQX + '/api/v5/banned', {'as': 'clientid', 'who': NAME, 'reason': f'WOOWBK lab marker {STAMP}',
                                               'until': '2099-12-31T23:59:59+08:00'}, token)
        out['banned_clientid'] = NAME
    return out


def emqx_read(token=None):
    token = token or emqx_token()
    _, users = http('GET', EMQX + AUTHN + '/users?limit=1000', None, token)
    users = [u['user_id'] for u in (users or {}).get('data', [])]
    _, retained = http('GET', EMQX + '/api/v5/mqtt/retainer/messages?limit=1000', None, token)
    _, banned = http('GET', EMQX + '/api/v5/banned?limit=1000', None, token)
    return {'mqtt_users': sorted(u for u in users if u.startswith('woowbk-lab-')),
            'retained': sorted(m['topic'] for m in (retained or {}).get('data', []) if m['topic'].startswith('woowbk-lab/')),
            'banned': sorted(b['who'] for b in (banned or {}).get('data', []) if str(b.get('who', '')).startswith('woowbk-lab-')),
            'mqtt_user_count': len(users)}


# ---------------------------------------------------------------- Headscale
def hs(*args, check=True):
    return run('podman', 'exec', 'headscale', 'headscale', *args, check=check)


def hs_json(*args):
    raw = hs(*args, '-o', 'json').strip()
    return (json.loads(raw) if raw else None) or []  # an empty list prints as null


def headscale_seed():
    sys.stdin.read()
    out = {}
    have = headscale_read()
    if NAME not in have['users']:
        hs('users', 'create', NAME, '--display-name', f'WOOWBK lab {TAG}')
        out['user'] = NAME
    if not FULL:
        return out
    user = next(u for u in hs_json('users', 'list') if u.get('name') == NAME)
    if not any(k.startswith(NAME + ':') for k in have['preauthkeys']):
        # -o json prints the new key; only its id is kept, the key text is dropped here
        key = json.loads(hs('preauthkeys', 'create', '--user', str(user['id']), '--reusable', '--expiration', '8760h',
                            '-o', 'json'))
        out['preauthkey_id'] = key.get('id')
    if NAME not in have['nodes']:
        # A pending registration with throwaway node and machine keys (debug create-node), then approved for the user
        # (auth register): a real node row, as a Tailscale client's /register would leave.
        auth_id = 'hskey-authreq-' + secrets.token_urlsafe(18)
        hs('debug', 'create-node', '--key', auth_id, '--name', NAME, '--user', NAME)
        hs('auth', 'register', '--auth-id', auth_id, '--user', NAME)
        out['node'] = NAME
    records = json.loads(run('podman', 'exec', 'headscale', 'cat', '/var/lib/headscale/extra_records.json') or '[]')
    if not any(r.get('name') == f'{NAME}.ts.local' for r in records):
        # Headscale watches this file (extra_records_path, in the data volume) and reloads it
        records.append({'name': f'{NAME}.ts.local', 'type': 'A', 'value': '100.64.255.250'})
        run('podman', 'exec', '-i', 'headscale', 'sh', '-c',
            'cat > /var/lib/headscale/extra_records.json.new && mv /var/lib/headscale/extra_records.json.new '
            '/var/lib/headscale/extra_records.json', input=json.dumps(records, indent=2) + '\n')
        out['dns_record'] = f'{NAME}.ts.local'
    return out


def headscale_read():
    users = hs_json('users', 'list')
    nodes = hs_json('nodes', 'list')
    records = json.loads(run('podman', 'exec', 'headscale', 'cat', '/var/lib/headscale/extra_records.json') or '[]')
    lab_users = {u['id']: u['name'] for u in users if str(u.get('name', '')).startswith('woowbk-lab-')}
    keys = []  # only ids and flags: the list may carry key material
    for key in hs_json('preauthkeys', 'list'):
        owner = (key.get('user') or {}).get('name', '')
        if owner.startswith('woowbk-lab-'):
            keys.append(f'{owner}:id={key.get("id")}:reusable={key.get("reusable")}')
    return {'users': sorted(lab_users.values()),
            'nodes': sorted({n.get(k) for n in nodes for k in ('name', 'given_name') if str(n.get(k)).startswith('woowbk-lab-')}),
            'preauthkeys': sorted(keys),
            'dns_records': sorted(r['name'] for r in records if str(r.get('name', '')).startswith('woowbk-lab-')),
            'user_count': len(users), 'node_count': len(nodes)}


HANDLERS = {('omnigent', 'seed'): omnigent_seed, ('omnigent', 'read'): omnigent_read,
            ('hermes', 'seed'): hermes_seed, ('hermes', 'read'): hermes_read,
            ('emqx', 'seed'): emqx_seed, ('emqx', 'read'): emqx_read,
            ('headscale', 'seed'): headscale_seed, ('headscale', 'read'): headscale_read}
if (APP, ACTION) not in HANDLERS:
    sys.exit('usage: <omnigent|hermes|emqx|headscale> <seed TAG STAMP|read>')
print(json.dumps(HANDLERS[(APP, ACTION)](), sort_keys=True))
