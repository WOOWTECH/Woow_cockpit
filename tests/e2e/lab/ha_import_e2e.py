#!/usr/bin/env python3
"""Home Assistant import, end to end on lab device dev-c (docs/testing.md "HA import"; CONTRACT section 13).

dev-c runs production-like copies of Odoo (tenant, PostgreSQL 17) and n8n (queue mode) with fresh secrets
(tests/e2e/lab/README.md, dev-c). This driver uploads the real HA test backups, runs the engine's HA check and convert
jobs through the installed helper (as root inside the device, like Cockpit), restores the converted backup with the
existing restore job and verifies the apps from the inside: Odoo partners, attachment, custom module and logins, the
upgrade gate, web.base.url and health; n8n owner login, workflows, the credential's decrypted value (compared inside the
device), executions and health. Secrets (test passwords, the HA key, the credential value) are read from files and
never printed: every evidence line is redacted.

  python3 -I tests/e2e/lab/ha_import_e2e.py [--deploy LAB_DIR --src TREE] [scenario ...]
  scenarios: upload keys check convert restore verify db2 testmode cleanup leaks  (default: all, in that order);
  `baseline` (with --baseline ODOO_ID,N8N_ID) first restores dev-c's own backups made before any import, so the custom
  module is copied again and the result shows the import from a clean device.

Options: --fixtures DIR (default ~/.woowbk-lab/ha-fixtures/20261118), --creds FILE (haimport testdata creds.env),
--n8n-data FILE (the test-data script holding the credential value). Evidence: ~/.woowbk-lab/evidence/ha-import/<ts>/.
Only ~/.woowbk-lab/bin/labpodman is used; nothing on the host itself is touched.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

LAB = Path.home() / '.woowbk-lab'
LP = str(LAB / 'bin' / 'labpodman')
DEVICE = 'woowbk-dev-c'
HELPER = '/usr/local/libexec/woowtech-cockpit-backup'
OWNER = '/usr/local/bin/woowbk-owner'
SCRATCH = Path('/tmp/claude-1000/-home-woowtechopenclaw/fbefdf50-77b9-4f2f-a609-4d7d82a72cee/scratchpad/haimport')
FIXTURES = LAB / 'ha-fixtures' / '20261118'
NAMES = {'enc': 'woow-import-test-enc', 'plain': 'woow-import-test-plain',
         'unc': 'woow-import-test-enc-uncompressed'}
PARTNER = 'HA 匯入測試聯絡人'
PROBE_RECORD = '來自 HA 的測試紀錄'
OWNER_EMAIL = 'ha-probe@probe.invalid'
SCHEDULED = 'WOOW 匯入測試 - 排程'
CREDENTIAL = 'HA probe header'
ALL = ('upload', 'keys', 'check', 'convert', 'restore', 'verify', 'db2', 'testmode', 'cleanup', 'leaks')
EXTRA = ('baseline',)  # opt-in: restore dev-c's pre-import backups (--baseline IDS) first


class Failed(Exception):
    pass


class Secrets:
    """Test secrets from files; `redact` replaces every value (and the HA key pattern) in evidence text."""

    def __init__(self, creds, n8n_data):
        self.values = {}
        for line in Path(creds).read_text(encoding='utf-8').splitlines():
            key, sep, value = line.strip().partition('=')
            if sep and not key.startswith('#'):
                self.values[key.strip()] = value.strip().strip('"\'')
        text = Path(n8n_data).read_text(encoding='utf-8')
        match = re.search(r'"name":"HA probe header".*?"value":"([^"]+)"', text)
        if not match:
            raise Failed('the n8n test-data script does not name the credential value')
        self.values['N8N_CREDENTIAL_VALUE'] = match.group(1)

    def __getitem__(self, name):
        return self.values[name]

    def redact(self, value):
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        for name, secret in sorted(self.values.items(), key=lambda kv: -len(kv[1])):
            if secret:
                text = text.replace(secret, f'<{name}>')
        return re.sub(r'[A-Z0-9]{4}(?:-[A-Z0-9]{4}){6}', '<HA-KEY>', text)


class Evidence:
    def __init__(self, secrets):
        stamp = time.strftime('%Y%m%dT%H%M%S')
        self.dir = LAB / 'evidence' / 'ha-import' / stamp
        self.dir.mkdir(parents=True, exist_ok=False)
        os.chmod(self.dir, 0o700)
        self.secrets = secrets
        self.results = []
        self.log_path = self.dir / 'run.log'

    def log(self, text):
        line = f'{time.strftime("%H:%M:%S")} {self.secrets.redact(str(text))}'
        print(line, flush=True)
        with open(self.log_path, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')

    def check(self, name, ok, detail=''):
        self.results.append({'check': name, 'ok': bool(ok), 'detail': self.secrets.redact(str(detail))[:500]})
        self.log(f'{"PASS" if ok else "FAIL"} {name}{": " + str(detail)[:300] if detail else ""}')
        return bool(ok)

    def save(self, name, value):
        path = self.dir / name
        path.write_text(self.secrets.redact(value if isinstance(value, str) else
                                            json.dumps(value, ensure_ascii=False, indent=1)), encoding='utf-8')
        os.chmod(path, 0o600)

    def finish(self):
        failed = [r for r in self.results if not r['ok']]
        self.save('results.json', {'passed': len(self.results) - len(failed), 'failed': len(failed),
                                   'results': self.results})
        self.log(f'RESULT {len(self.results) - len(failed)}/{len(self.results)} passed; evidence {self.dir}')
        return not failed


def run(argv, *, input=None, timeout=600, check=False):
    proc = subprocess.run(argv, input=input, capture_output=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise Failed(f'{argv[:6]} exit {proc.returncode}: {proc.stderr.decode("utf-8", "replace")[-300:]}')
    return proc


def root(*argv, input=None, timeout=600, check=False):
    return run([LP, 'exec', '-i', DEVICE, *argv], input=input, timeout=timeout, check=check)


def owner(*argv, input=None, timeout=600, check=False):
    return run([LP, 'exec', '-i', DEVICE, OWNER, *argv], input=input, timeout=timeout, check=check)


def helper(command, request=None, *, timeout=1800):
    data = b'' if request is None else json.dumps(request, ensure_ascii=False).encode('utf-8')
    proc = root(HELPER, command, input=data, timeout=timeout)
    lines = [line for line in proc.stdout.decode('utf-8', 'replace').splitlines() if line.strip()]
    if len(lines) != 1:
        raise Failed(f'{command}: {len(lines)} reply lines (rc={proc.returncode})')
    return proc.returncode, json.loads(lines[0])


def ok(command, request=None, *, ev, timeout=1800):
    rc, reply = helper(command, request, timeout=timeout)
    if rc != 0:
        raise Failed(f'{command} refused: {ev.secrets.redact(reply.get("error"))}')
    return reply


def request_id(tag):
    return f'ha-e2e-{tag}-{int(time.time() * 1000)}'


def wait_job(job_id, *, ev, timeout=3600):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        reply = ok('job-status', {'job_id': job_id}, ev=ev)
        job = reply['job']
        if job['phase'] != last:
            last = job['phase']
            ev.log(f'  job {job_id} {job["state"]} phase={job["phase"]} {job["progress"].get("message")}')
        if job['state'] not in ('queued', 'running'):
            ev.save(f'job-{job_id}.json', {'job': job, 'log': reply.get('log')})
            return job
        time.sleep(3)
    raise Failed(f'job {job_id} did not finish in {timeout} s')


# ---------------------------------------------------------------- device-side probes

def psql(container, user, database, sql):
    proc = owner('podman', 'exec', '-i', container, 'psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U', user,
                 '-d', database, '-f', '-', input=sql.encode('utf-8'), timeout=120)
    if proc.returncode != 0:
        raise Failed(f'psql {container}/{database}: {proc.stderr.decode("utf-8", "replace")[-300:]}')
    return proc.stdout.decode('utf-8', 'replace').strip()


def http_code(url):
    proc = root('curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20', url, timeout=60)
    return proc.stdout.decode('ascii', 'replace').strip()


# Runs inside the device (python3 of Ubuntu); the secrets come on stdin, only verdicts go to stdout.
DEVICE_PROBE = r'''
import http.cookiejar, json, sys, urllib.request
req = json.loads(sys.stdin.read())
out = {}
def post(opener, url, body, headers=None):
    r = urllib.request.Request(url, data=json.dumps(body).encode(), headers=dict({"Content-Type": "application/json"}, **(headers or {})))
    with opener.open(r, timeout=60) as resp:
        return resp.status, json.loads(resp.read() or b"null")
def get(opener, url, headers=None):
    r = urllib.request.Request(url, headers=headers or {})
    with opener.open(r, timeout=60) as resp:
        return resp.status, json.loads(resp.read() or b"null")
if req.get("odoo"):
    for login, password in req["odoo"]["logins"]:
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        try:
            status, body = post(opener, "http://127.0.0.1:18069/web/session/authenticate",
                                {"jsonrpc": "2.0", "params": {"db": "odoo", "login": login, "password": password}})
            uid = ((body or {}).get("result") or {}).get("uid")
            out["odoo_login_" + login] = bool(uid)
            if login == "admin" and uid:
                status, body = post(opener, "http://127.0.0.1:18069/web/dataset/call_kw",
                                    {"jsonrpc": "2.0", "params": {"model": "ir.attachment", "method": "search_read",
                                     "args": [[["name", "=", "ha-probe.txt"]]], "kwargs": {"fields": ["datas"]}}})
                rows = (body or {}).get("result") or []
                datas = rows[0].get("datas") if rows else None
                import base64
                data = base64.b64decode(datas) if isinstance(datas, str) else b""
                out["odoo_attachment"] = data == b"woow ha import probe file\n"
        except Exception as exc:
            out["odoo_login_" + login] = False
            out["odoo_error_" + login] = type(exc).__name__
if req.get("n8n"):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    headers = {"browser-id": "woow-ha-e2e"}
    try:
        status, body = post(opener, "http://127.0.0.1:15678/rest/login",
                            {"emailOrLdapLoginId": req["n8n"]["email"], "password": req["n8n"]["password"]}, headers)
        out["n8n_login"] = status == 200
        status, body = get(opener, "http://127.0.0.1:15678/rest/credentials", headers)
        creds = [c for c in (body or {}).get("data", []) if c.get("name") == req["n8n"]["credential"]]
        out["n8n_credential_found"] = bool(creds)
    except Exception as exc:
        out["n8n_login"] = out.get("n8n_login", False)
        out["n8n_error"] = type(exc).__name__
print(json.dumps(out))
'''


# The credential's decrypted value: n8n's own CLI in the running n8n container (the REST API redacts secrets); the
# export lives only inside the container and the comparison runs in the device, only the verdict comes out.
CREDENTIAL_PROBE = r'''
import json, subprocess, sys
req = json.loads(sys.stdin.read())
owner = ["/usr/local/bin/woowbk-owner", "podman", "exec", "n8n"]
try:
    proc = subprocess.run(owner + ["n8n", "export:credentials", "--all", "--decrypted", "--output=/tmp/woowbk-creds.json"],
                          capture_output=True, timeout=300)
    data = subprocess.run(owner + ["cat", "/tmp/woowbk-creds.json"], capture_output=True, timeout=60).stdout
    rows = json.loads(data or b"[]")
    row = next((r for r in rows if r.get("name") == req["name"]), None)
    print(json.dumps({"found": row is not None, "match": bool(row) and (row.get("data") or {}).get("value") == req["value"]}))
finally:
    subprocess.run(owner + ["rm", "-f", "/tmp/woowbk-creds.json"], capture_output=True, timeout=60)
'''


def credential_probe(name, value):
    proc = root('python3', '-I', '-c', CREDENTIAL_PROBE, input=json.dumps({'name': name, 'value': value}).encode(),
                timeout=600)
    try:
        return json.loads(proc.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {'found': False, 'match': False, 'error': proc.stderr.decode('utf-8', 'replace')[-200:]}


def device_probe(request):
    proc = root('python3', '-I', '-c', DEVICE_PROBE, input=json.dumps(request).encode('utf-8'), timeout=300)
    try:
        return json.loads(proc.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Failed(f'device probe failed: {proc.stderr.decode("utf-8", "replace")[-300:]}') from None


# ---------------------------------------------------------------- scenarios

STATE = {}


def state_path():
    return LAB / 'run' / 'ha_import_e2e.json'


def save_state():
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(STATE, indent=1), encoding='utf-8')


def load_state():
    try:
        STATE.update(json.loads(state_path().read_text(encoding='utf-8')))
    except (OSError, ValueError):
        pass


def upload(path, *, ev):
    size = path.stat().st_size
    begin = ok('upload-begin', {'filename': path.name, 'size': size}, ev=ev)
    with open(path, 'rb') as handle:
        proc = run([LP, 'exec', '-i', DEVICE, 'sh', '-c', 'cat > "$1"', 'sh', begin['path']], input=handle.read(),
                   timeout=600)
    if proc.returncode != 0:
        raise Failed('copying the upload into the device failed')
    rc, reply = helper('upload-finish', {'upload_id': begin['upload_id']})
    if rc != 0:
        ok('upload-abort', {'upload_id': begin['upload_id']}, ev=ev)
    return rc, reply


def scenario_upload(ev, args):
    for tag, name in NAMES.items():
        path = Path(args.fixtures) / name / f'{name}.tar'
        started = time.monotonic()
        rc, reply = upload(path, ev=ev)
        meta = reply.get('ha_backup') or {}
        ev.check(f'upload {tag}: upload-finish answers ha_backup', rc == 0 and meta.get('id', '').startswith('ha-'),
                 f'{time.monotonic() - started:.1f} s {meta.get("id")}')
        STATE[f'ha_{tag}'] = meta.get('id')
        apps = {a['app_id']: a['installed'] for a in meta.get('importable_apps') or []}
        ev.check(f'upload {tag}: Odoo and n8n importable and installed', apps == {'odoo': True, 'n8n': True}, apps)
    listing = ok('list', ev=ev)
    ids = [item['id'] for item in listing.get('ha_backups') or []]
    ev.check('list shows the three HA backups', all(STATE.get(f'ha_{t}') in ids for t in NAMES), ids)
    save_state()


def start(command, request, *, ev):
    rc, reply = helper(command, request, timeout=300)
    return rc, reply


def scenario_keys(ev, args):
    ha = STATE['ha_enc']
    rc, reply = start('ha-check-start', {'ha_backup_id': ha, 'apps': ['odoo'], 'request_id': request_id('nokey')},
                      ev=ev)
    ev.check('check without a key: key-required', rc == 1 and reply['error']['code'] == 'key-required',
             reply.get('error'))
    rc, reply = start('ha-check-start', {'ha_backup_id': ha, 'apps': ['odoo'], 'request_id': request_id('wrong'),
                                         'key': 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG'}, ev=ev)
    ev.check('check with a wrong key: wrong-key', rc == 1 and reply['error']['code'] == 'wrong-key', reply.get('error'))
    rc, reply = start('ha-convert-start', {'ha_backup_id': ha, 'apps': ['n8n'], 'test_mode': False, 'confirm': True,
                                           'request_id': request_id('wrongc'), 'key': args.secrets['HA_BACKUP_KEY'][:-1]
                                           + ('A' if args.secrets['HA_BACKUP_KEY'][-1] != 'A' else 'B')}, ev=ev)
    ev.check('convert with a wrong key: wrong-key', rc == 1 and reply['error']['code'] == 'wrong-key',
             reply.get('error'))


def run_check(ha, apps, *, ev, key=None, tag='check'):
    request = {'ha_backup_id': ha, 'apps': apps, 'request_id': request_id(tag)}
    if key is not None:
        request['key'] = key
    reply = ok('ha-check-start', request, ev=ev, timeout=300)
    job = wait_job(reply['job_id'], ev=ev)
    return job


def scenario_check(ev, args):
    key = args.secrets['HA_BACKUP_KEY']
    for tag in ('enc', 'plain', 'unc'):
        started = time.monotonic()
        job = run_check(STATE[f'ha_{tag}'], ['odoo', 'n8n'], ev=ev, key=None if tag == 'plain' else key,
                        tag=f'check-{tag}')
        took = time.monotonic() - started
        ok_ = job['state'] == 'succeeded'
        ev.check(f'check {tag}: job succeeded', ok_, f'{took:.0f} s {job.get("error")}')
        if not ok_:
            continue
        apps = {a['app_id']: a for a in job['result']['ha_check']['apps']}
        odoo, n8n = apps.get('odoo') or {}, apps.get('n8n') or {}
        dbs = {d['name']: d for d in (odoo.get('odoo') or {}).get('databases') or []}
        ev.check(f'check {tag}: Odoo ok, woowtest and woowtest2 can move',
                 odoo.get('ok') and dbs.get('woowtest', {}).get('ok') and dbs.get('woowtest2', {}).get('ok'),
                 {k: (v['ok'], v['blockers'][:1]) for k, v in dbs.items()} or odoo.get('blockers'))
        woowtest = dbs.get('woowtest') or {}
        custom = [m['name'] for m in woowtest.get('custom_modules') or []]
        # A device that already holds the module (an earlier import) needs no copy: then none is listed.
        present = 'woow_import_probe' in owner('ls', '.local/share/odoo18/addons').stdout.decode().split()
        ev.check(f'check {tag}: woowtest counts and custom module woow_import_probe '
                 f'({"already on this device" if present else "copied from the backup"})',
                 woowtest.get('partners', 0) >= 5 and woowtest.get('attachments', 0) >= 1
                 and (('woow_import_probe' in custom) != present),
                 {k: woowtest.get(k) for k in ('partners', 'users', 'attachments', 'modules', 'mail_servers_active',
                                               'crons_active')} | {'custom': custom})
        info = n8n.get('n8n') or {}
        names = [w['name'] for w in info.get('workflows_to_fix') or []]
        ev.check(f'check {tag}: n8n ok with owner, 3 workflows, 1 active, 1 credential, executions',
                 n8n.get('ok') and info.get('owner_email') == OWNER_EMAIL and info.get('workflows') == 3
                 and info.get('workflows_active') == 1 and info.get('credentials') == 1
                 and info.get('executions', 0) >= 1,
                 {k: info.get(k) for k in ('owner_email', 'workflows', 'workflows_active', 'credentials',
                                           'executions', 'users')} | {'blockers': n8n.get('blockers')})
        ev.check(f'check {tag}: the workflow that needs fixing is listed', 'WOOW 匯入測試 - 需修正' in names, names)
        ev.check(f'check {tag}: versions shown', odoo.get('version') == '0.4.12' and n8n.get('version') == '2.43.6'
                 and n8n.get('target_version') == '2.43.6',
                 {a: (apps[a].get('version'), apps[a].get('target_version')) for a in apps})
        STATE[f'check_{tag}'] = job['result']
        leftovers = owner('podman', 'ps', '-a', '--filter', 'label=io.woowtech.backup.job', '--format',
                          '{{.Names}}').stdout.decode().split()
        volumes = owner('podman', 'volume', 'ls', '--filter', 'label=io.woowtech.backup.job', '--format',
                        '{{.Name}}').stdout.decode().split()
        ev.check(f'check {tag}: no throwaway container or volume left', not leftovers and not volumes,
                 leftovers + volumes)
    save_state()


def live_odoo_facts():
    return {'base_url': psql('odoo18-db', 'postgres', 'odoo',
                             "SELECT value FROM ir_config_parameter WHERE key = 'web.base.url';"),
            'marker': psql('odoo18-db', 'postgres', 'odoo',
                           "SELECT value FROM ir_config_parameter WHERE key = 'woow_paas_platform.upgrade_done';")}


def convert(ha, apps, database, test_mode, *, ev, key, tag):
    if 'odoo' in apps:
        # The target's address and gate marker right before this import (an Odoo admin login without the freeze flag
        # moves web.base.url to the address it used, e.g. the probe's 127.0.0.1:18069).
        STATE['live_before'] = live_odoo_facts()
    request = {'ha_backup_id': ha, 'apps': apps, 'test_mode': test_mode, 'confirm': True,
               'request_id': request_id(tag)}
    if database:
        request['odoo_database'] = database
    if key:
        request['key'] = key
    started = time.monotonic()
    reply = ok('ha-convert-start', request, ev=ev, timeout=300)
    job = wait_job(reply['job_id'], ev=ev, timeout=5400)
    return job, time.monotonic() - started


def scenario_convert(ev, args):
    job, took = convert(STATE['ha_enc'], ['odoo', 'n8n'], 'woowtest', False, ev=ev, key=args.secrets['HA_BACKUP_KEY'],
                        tag='convert')
    ok_ = job['state'] == 'succeeded' and isinstance((job.get('result') or {}).get('backup_id'), str)
    ev.check('convert enc (woowtest, odoo+n8n): job succeeded with a backup id', ok_,
             f'{took:.0f} s {job.get("error") or job["result"].get("backup_id")}')
    if not ok_:
        save_state()
        return
    result = job['result']
    STATE['converted'] = result['backup_id']
    imp = result.get('ha_import') or {}
    ev.check('convert: ha_import shape', set(imp) >= {'ha_backup_id', 'name', 'date', 'apps', 'odoo_database',
                                                       'test_mode', 'workflows_to_fix', 'reminders'}
             and imp.get('apps') == ['odoo', 'n8n'] and imp.get('odoo_database') == 'woowtest', imp)
    listing = ok('list', ev=ev)
    meta = next((b for b in listing['backups'] if b['id'] == result['backup_id']), {})
    ev.check('list: the converted backup is a manual backup with from_ha and the HA note',
             meta.get('type') == 'manual' and (meta.get('from_ha') or {}).get('ha_backup_id') == STATE['ha_enc']
             and meta.get('note', '').startswith('由 HA 備份轉換：') and meta.get('key_available') is True,
             {k: meta.get(k) for k in ('type', 'note', 'encrypted', 'key_available', 'verified')})
    inspect = ok('inspect', {'backup_id': result['backup_id']}, ev=ev, timeout=600)
    ev.save('inspect-converted.json', inspect)
    checks = [c for c in (inspect.get('preflight') or {}).get('checks') or []]
    failed = [c for c in checks if c.get('status') == 'fail']
    ev.check('inspect: preflight passes for both apps (settings same)', not failed and all(
        (app.get('settings') or {}).get('state') == 'same' for app in (inspect.get('preflight') or {}).get('apps') or []),
        failed[:3] or [(a.get('id'), (a.get('settings') or {}).get('state')) for a in
                       (inspect.get('preflight') or {}).get('apps') or []])
    save_state()


def restore(backup_id, apps, *, ev, tag):
    started = time.monotonic()
    reply = ok('restore-start', {'backup_id': backup_id, 'apps': apps, 'confirm': True,
                                 'request_id': request_id(tag)}, ev=ev, timeout=300)
    job = wait_job(reply['job_id'], ev=ev, timeout=5400)
    return job, time.monotonic() - started


def scenario_restore(ev, args):
    job, took = restore(STATE['converted'], ['odoo', 'n8n'], ev=ev, tag='restore')
    ev.check('restore of the converted backup succeeded', job['state'] == 'succeeded',
             f'{took:.0f} s {job.get("error")} safety={(job.get("result") or {}).get("safety_backup_id")}')
    STATE['restore_safety'] = (job.get('result') or {}).get('safety_backup_id')
    health = (job.get('result') or {}).get('health') or []
    ev.check('restore: every health check ok', health and all(h.get('status') == 'ok' for h in health),
             [(h.get('id'), h.get('status')) for h in health])
    save_state()


def scenario_verify(ev, args, *, database='woowtest', test_mode=False, label='import'):
    secrets = args.secrets
    count = psql('odoo18-db', 'postgres', 'odoo', f"SELECT count(*) FROM res_partner WHERE name LIKE '{PARTNER}%';")
    if database == 'woowtest':
        ev.check(f'{label}: Odoo has the 5 test partners', count == '5', count)
        state = psql('odoo18-db', 'postgres', 'odoo',
                     "SELECT state FROM ir_module_module WHERE name = 'woow_import_probe';")
        record = psql('odoo18-db', 'postgres', 'odoo',
                      f"SELECT count(*) FROM woow_import_probe WHERE name = '{PROBE_RECORD}';")
        ev.check(f'{label}: module woow_import_probe installed with its record', state == 'installed' and record == '1',
                 f'{state} {record}')
        files = owner('ls', '.local/share/odoo18/addons').stdout.decode().split()
        ev.check(f'{label}: the custom module is in the custom modules folder', 'woow_import_probe' in files, files)
    facts = live_odoo_facts()
    before = STATE.get('live_before') or {}
    ev.check(f'{label}: web.base.url unchanged and the upgrade marker is the device\'s',
             facts['base_url'] == before.get('base_url') and facts['marker'] == before.get('marker'),
             {'after': facts, 'before': before})
    gate = owner('systemctl', '--user', 'show', 'odoo.service', '-p', 'ActiveState', '-p', 'Result').stdout.decode()
    ev.check(f'{label}: odoo.service active (upgrade gate passed)', 'ActiveState=active' in gate, gate.strip())
    codes = {url: http_code(url) for url in ('http://127.0.0.1:18069/web/health', 'http://127.0.0.1:18080/web/health',
                                             'http://127.0.0.1:15678/healthz/readiness', 'http://127.0.0.1:15679/healthz')}
    ev.check(f'{label}: health 200 everywhere', all(code == '200' for code in codes.values()), codes)
    probe = device_probe({'odoo': {'logins': [['admin', secrets['ODOO_ADMIN_PW']], ['ha-probe', secrets['ODOO_PROBE_PW']]]}
                          if database == 'woowtest' else None,
                          'n8n': {'email': OWNER_EMAIL, 'password': secrets['N8N_OWNER_PW'], 'credential': CREDENTIAL,
                                  'value': secrets['N8N_CREDENTIAL_VALUE']}})
    ev.save(f'probe-{label}.json', probe)
    if database == 'woowtest':
        ev.check(f'{label}: Odoo admin and ha-probe can log in', probe.get('odoo_login_admin') and
                 probe.get('odoo_login_ha-probe'), probe)
        ev.check(f'{label}: attachment ha-probe.txt readable', probe.get('odoo_attachment') is True, probe)
    ev.check(f'{label}: n8n owner can log in', probe.get('n8n_login') is True, probe)
    decrypted = credential_probe(CREDENTIAL, secrets['N8N_CREDENTIAL_VALUE'])
    ev.check(f'{label}: credential "{CREDENTIAL}" decrypts to the expected value', decrypted.get('match') is True,
             decrypted)
    rows = psql('n8n-postgres', 'n8n', 'n8n', 'SELECT name || \'|\' || active FROM workflow_entity ORDER BY name;')
    flows = dict(line.split('|', 1) for line in rows.splitlines() if '|' in line)
    if test_mode:
        ev.check(f'{label}: 3 workflows, all unpublished',
                 len(flows) == 3 and all(v == 'false' for v in flows.values()), flows)
    else:
        ev.check(f'{label}: 3 workflows with "{SCHEDULED}" active', len(flows) == 3 and flows.get(SCHEDULED) == 'true',
                 flows)
    executions = psql('n8n-postgres', 'n8n', 'n8n', 'SELECT count(*) FROM execution_entity;')
    ev.check(f'{label}: at least one execution moved', executions.isdigit() and int(executions) >= 1, executions)


def scenario_db2(ev, args):
    job, took = convert(STATE['ha_plain'], ['odoo'], 'woowtest2', False, ev=ev, key=None, tag='convert-db2')
    ok_ = job['state'] == 'succeeded'
    ev.check('convert plain (woowtest2, odoo only): job succeeded', ok_, f'{took:.0f} s {job.get("error")}')
    if not ok_:
        return
    STATE['converted_db2'] = job['result']['backup_id']
    job, took = restore(job['result']['backup_id'], ['odoo'], ev=ev, tag='restore-db2')
    ev.check('restore of woowtest2 succeeded', job['state'] == 'succeeded', f'{took:.0f} s {job.get("error")}')
    expected = ((STATE.get('check_plain') or {}).get('ha_check') or {}).get('apps') or []
    odoo = next((a for a in expected if a['app_id'] == 'odoo'), {})
    want = next((d['partners'] for d in (odoo.get('odoo') or {}).get('databases') or [] if d['name'] == 'woowtest2'),
                None)
    count = psql('odoo18-db', 'postgres', 'odoo', 'SELECT count(*) FROM res_partner;')
    ev.check('woowtest2: partner count as the check reported', want is not None and count == str(want),
             f'{count} vs {want}')
    codes = {url: http_code(url) for url in ('http://127.0.0.1:18069/web/health', 'http://127.0.0.1:18080/web/health')}
    ev.check('woowtest2: Odoo health 200', all(code == '200' for code in codes.values()), codes)
    save_state()


def scenario_testmode(ev, args):
    uuid_ha = psql('odoo18-db', 'postgres', 'odoo', "SELECT value FROM ir_config_parameter WHERE key = 'database.uuid';")
    job, took = convert(STATE['ha_unc'], ['odoo', 'n8n'], 'woowtest', True, ev=ev, key=args.secrets['HA_BACKUP_KEY'],
                        tag='convert-test')
    ok_ = job['state'] == 'succeeded'
    ev.check('convert enc-uncompressed in test mode: job succeeded', ok_, f'{took:.0f} s {job.get("error")}')
    if not ok_:
        return
    job, took = restore(job['result']['backup_id'], ['odoo', 'n8n'], ev=ev, tag='restore-test')
    ev.check('restore of the test-mode backup succeeded', job['state'] == 'succeeded', f'{took:.0f} s {job.get("error")}')
    neutral = psql('odoo18-db', 'postgres', 'odoo',
                   "SELECT coalesce((SELECT value FROM ir_config_parameter WHERE key = 'database.is_neutralized'), '')"
                   " || '|' || (SELECT count(*) FROM ir_mail_server WHERE active AND smtp_host <> 'invalid') || '|' || "
                   "(SELECT value FROM ir_config_parameter WHERE key = 'database.uuid');")
    flag, servers, uuid = (neutral.split('|') + ['', '', ''])[:3]
    # odoo neutralize deactivates every mail server and adds its own active one pointing at the host "invalid".
    ev.check('test mode: Odoo neutralised (no real mail server active) with a new database.uuid',
             flag.lower() in ('true', '1') and servers == '0' and uuid and uuid != uuid_ha,
             f'neutralized={flag} mail_servers={servers} new_uuid={uuid != uuid_ha}')
    scenario_verify(ev, args, test_mode=True, label='test mode')


def scenario_cleanup(ev, args):
    leftovers = owner('podman', 'ps', '-a', '--filter', 'label=io.woowtech.backup.job', '--format',
                      '{{.Names}}').stdout.decode().split()
    volumes = owner('podman', 'volume', 'ls', '--filter', 'label=io.woowtech.backup.job', '--format',
                    '{{.Name}}').stdout.decode().split()
    networks = owner('podman', 'network', 'ls', '--filter', 'label=io.woowtech.backup.job', '--format',
                     '{{.Name}}').stdout.decode().split()
    ev.check('no throwaway container, volume or network left', not (leftovers or volumes or networks),
             leftovers + volumes + networks)
    staging = root('ls', '-A', '/var/lib/woowtech-backup/staging').stdout.decode().split()
    keys = root('sh', '-c', 'ls -A /run/woowtech-backup | grep "^key-" || true').stdout.decode().split()
    ev.check('no staging folder and no key file left', not staging and not keys, staging + keys)


# Secrets in the engine's files and the device's journal: the values come on stdin, only hit counts come out.
LEAK_SCAN = r'''
import json, os, subprocess, sys
secrets = [s.encode() for s in json.loads(sys.stdin.read()) if s]
hits, scanned = {}, 0
roots = ["/var/lib/woowtech-backup/jobs", "/var/lib/woowtech-backup/archives", "/var/lib/woowtech-backup/ha-backups",
         "/var/lib/woowtech-backup/ha-imports.json", "/run/woowtech-backup", "/var/lib/woowtech-backup/uploads"]
for root in roots:
    paths = [root] if os.path.isfile(root) else [os.path.join(d, f) for d, _s, fs in os.walk(root) for f in fs]
    for path in paths:
        if path.endswith(".tar") and "/ha-backups/" in path:
            continue  # the uploaded HA files themselves are encrypted or the test data
        if path.endswith(".tar") and "/archives/" in path:
            continue  # backups hold app secrets by design (encrypted)
        try:
            data = open(path, "rb").read(64 * 1024 * 1024)
        except OSError:
            continue
        scanned += 1
        for i, secret in enumerate(secrets):
            if secret in data:
                hits[f"{path} #{i}"] = data.count(secret)
journal = subprocess.run(["journalctl", "-o", "cat", "--no-pager"], capture_output=True).stdout
for i, secret in enumerate(secrets):
    if secret in journal:
        hits[f"journal #{i}"] = journal.count(secret)
print(json.dumps({"scanned": scanned, "journal_bytes": len(journal), "hits": hits}))
'''


def scenario_leaks(ev, args):
    secrets = args.secrets
    values = [secrets[name] for name in ('HA_BACKUP_KEY', 'ODOO_ADMIN_PW', 'ODOO_PROBE_PW', 'N8N_OWNER_PW',
                                         'N8N_CREDENTIAL_VALUE', 'ODOO_MASTER_PW', 'ODOO_DB_PW')]
    proc = root('python3', '-I', '-c', LEAK_SCAN, input=json.dumps(values).encode(), timeout=600)
    try:
        report = json.loads(proc.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Failed(f'leak scan failed: {proc.stderr.decode("utf-8", "replace")[-300:]}') from None
    ev.save('leaks.json', report)
    ev.check('no test secret in the engine\'s records, logs, index, registry or the device journal',
             not report['hits'], f'{report["scanned"]} files, journal {report["journal_bytes"]} bytes, '
                                 f'hits {report["hits"]}')


def scenario_baseline(ev, args):
    """dev-c back to its own data from before any import (prodlike_baseline.py's encrypted backups)."""
    if not args.baseline:
        raise Failed('baseline needs --baseline ODOO_BACKUP_ID,N8N_BACKUP_ID')
    for backup_id, app_id in zip(args.baseline.split(','), ('odoo', 'n8n')):
        job, took = restore(backup_id, [app_id], ev=ev, tag=f'baseline-{app_id}')
        ev.check(f'baseline: {app_id} restored from {backup_id}', job['state'] == 'succeeded',
                 f'{took:.0f} s {job.get("error")}')
    files = owner('ls', '.local/share/odoo18/addons').stdout.decode().split()
    partners = psql('odoo18-db', 'postgres', 'odoo', f"SELECT count(*) FROM res_partner WHERE name LIKE '{PARTNER}%';")
    workflows = psql('n8n-postgres', 'n8n', 'n8n', 'SELECT count(*) FROM workflow_entity;')
    ev.check('baseline: no imported data left (no custom module, no test partner, no workflow)',
             'woow_import_probe' not in files and partners == '0' and workflows == '0',
             {'files': files, 'partners': partners, 'workflows': workflows})


def deploy(args, ev):
    script = Path(args.deploy) / 'deploy-src.sh'
    ev.log(f'deploying {args.src} to dev-c')
    proc = run([str(script), 'c', '--src', args.src, '--no-demo-catalog'], timeout=1800)
    ev.save('deploy.log', proc.stdout.decode('utf-8', 'replace')[-20000:] + proc.stderr.decode('utf-8', 'replace')[-5000:])
    if proc.returncode != 0:
        raise Failed(f'deploy failed ({proc.returncode})')
    status = ok('status', ev=ev)
    ev.log(f'engine {status.get("version")} apps {[(a["id"], a["state"]) for a in status.get("apps") or []]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('scenarios', nargs='*')
    parser.add_argument('--deploy', help='lab script directory with deploy-src.sh (deploys --src first)')
    parser.add_argument('--src', help='the Woow_cockpit tree to deploy')
    parser.add_argument('--fixtures', default=str(FIXTURES))
    parser.add_argument('--creds', default=str(SCRATCH / 'testdata' / 'creds.env'))
    parser.add_argument('--n8n-data', default=str(SCRATCH / 'testha-scripts' / 'n8n-testdata.filled.sh'))
    parser.add_argument('--baseline', help='ODOO_BACKUP_ID,N8N_BACKUP_ID of dev-c backups from before any import')
    args = parser.parse_args()
    args.secrets = Secrets(args.creds, args.n8n_data)
    ev = Evidence(args.secrets)
    load_state()
    scenarios = args.scenarios or list(ALL)
    try:
        if args.deploy:
            deploy(args, ev)
        for name in scenarios:
            if name not in ALL + EXTRA:
                raise Failed(f'unknown scenario {name}')
            ev.log(f'== {name}')
            if name == 'verify':
                scenario_verify(ev, args)
            else:
                globals()[f'scenario_{name}'](ev, args)
    except Failed as error:
        ev.check('driver', False, str(error))
    finally:
        save_state()
    sys.exit(0 if ev.finish() else 1)


if __name__ == '__main__':
    main()
