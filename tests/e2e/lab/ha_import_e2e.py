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
  review fixes (opt-in, FIXPLAN item 21): kill cancel space pull c19 rollback (they need `upload` first);
  `baseline` (with --baseline ODOO_ID,N8N_ID) first restores dev-c's own backups made before any import, so the custom
  module is copied again and the result shows the import from a clean device; `live` only records the target's
  web.base.url and upgrade marker for a later `verify`, when the import itself runs elsewhere (ha_import_ui.mjs);
  `restart` restarts the imported Odoo and n8n units and checks data, logins and the credential again; `n8ndiag`
  measures n8n's registry-bound package list next to the registry-free local probe (root cause of the old timeout).
  armcompare with --source-capture explains differing rows one by one (odoo_explain.py), otherwise they stay unverified.

Options: --fixtures DIR (default ~/.woowbk-lab/ha-fixtures/20261118),
--creds FILE (default ~/.woowbk-lab/secrets/ha-import-creds.env), --n8n-data FILE (the test-data script holding the
credential value, default ~/.woowbk-lab/secrets/ha-import-n8n-testdata.sh), --evidence NAME (default ha-import).
Evidence: ~/.woowbk-lab/evidence/<NAME>/<ts>/.
Only ~/.woowbk-lab/bin/labpodman is used; nothing on the host itself is touched.
"""
import argparse
from datetime import datetime, timezone
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
SECRET_DIR = LAB / 'secrets'
FIXTURES = LAB / 'ha-fixtures' / '20261118'
NAMES = {'enc': 'woow-import-test-enc', 'plain': 'woow-import-test-plain',
         'unc': 'woow-import-test-enc-uncompressed'}
EXPECT = {'odoo_addon': '0.4.12', 'arch': 'amd64'}  # of the backups under test (--odoo-addon-version, --arch)
PARTNER = 'HA 匯入測試聯絡人'
PROBE_RECORD = '來自 HA 的測試紀錄'
OWNER_EMAIL = 'ha-probe@probe.invalid'
SCHEDULED = 'WOOW 匯入測試 - 排程'
CREDENTIAL = 'HA probe header'
ALL = ('upload', 'keys', 'check', 'convert', 'restore', 'verify', 'db2', 'testmode', 'cleanup', 'leaks')
# opt-in: restore dev-c's pre-import backups (--baseline IDS); record live facts; the review-fix scenarios
# (FIXPLAN item 21): a job killed mid-convert, a cancel mid-convert, too little space (refused and aborted), the
# PostgreSQL 16 download, live PostgreSQL settings carried over (C-19), a failed restore of a converted backup.
# Backups from a real ARM HA (--arch aarch64, opt-in): the decrypted copy HA's page downloads, ARM-only code in a custom
# module and a community node, PostgreSQL stopped uncleanly, and the imported tables against the source's fingerprint.
EXTRA = ('baseline', 'live', 'kill', 'cancel', 'space', 'pull', 'c19', 'rollback', 'armdownload', 'armnative', 'armcrash',
         'armcompare', 'n8ndiag', 'restart')
STAGING = '/var/lib/woowtech-backup/staging'
JOB_LABEL = 'label=io.woowtech.backup.job'


class Failed(Exception):
    pass


def require_isolated_device():
    """Fail before credentials, deployment or jobs; inspect the lab store only."""
    try:
        result = subprocess.run(
            [LP, 'container', 'inspect', DEVICE, '--format',
             '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'],
            capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Failed('lab isolation inspection unavailable') from None
    if result.returncode != 0 or result.stdout.strip() != b'true none {}':
        raise Failed('lab must be running with network=none and no published ports')


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
        safe = self.redact_tree(value)
        return safe if isinstance(safe, str) else json.dumps(safe, ensure_ascii=False)

    def _redact_text(self, text):
        for name, secret in sorted(self.values.items(), key=lambda kv: -len(kv[1])):
            if secret:
                text = text.replace(secret, f'<{name}>')
        return re.sub(r'[A-Z0-9]{4}(?:-[A-Z0-9]{4}){6}', '<HA-KEY>', text)

    def redact_tree(self, value):
        """Redact strings and object keys before JSON or Python string escaping."""
        if isinstance(value, str):
            return self._redact_text(value)
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                safe_key = self._redact_text(key) if isinstance(key, str) else key
                if safe_key in result:
                    raise ValueError('redacted evidence contains duplicate keys')
                result[safe_key] = self.redact_tree(item)
            return result
        if isinstance(value, (list, tuple)):
            return [self.redact_tree(item) for item in value]
        return value


class Evidence:
    def __init__(self, secrets, area='ha-import'):
        stamp = time.strftime('%Y%m%dT%H%M%S')
        self.dir = LAB / 'evidence' / area / stamp
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
        safe_name = self.secrets.redact(str(name))
        safe_detail = self.secrets.redact(detail)
        self.results.append({'check': safe_name, 'ok': bool(ok), 'detail': safe_detail[:500]})
        self.log(f'{"PASS" if ok else "FAIL"} {safe_name}{": " + safe_detail[:300] if detail else ""}')
        return bool(ok)

    def save(self, name, value):
        path = self.dir / name
        safe = self.secrets.redact_tree(value)
        path.write_text(safe if isinstance(safe, str) else json.dumps(safe, ensure_ascii=False, indent=1),
                        encoding='utf-8')
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
LOCAL_COMMUNITY_PROBE = r"""
import json
import subprocess
import urllib.request

PACKAGE = 'n8n-nodes-globals'
VERSION = '1.1.0'
OWNER = '/usr/local/bin/woowbk-owner'
SQL = '''BEGIN READ ONLY; SET LOCAL statement_timeout = '5s';
SELECT json_build_object('package', "packageName", 'version', "installedVersion", 'nodes',
 (SELECT coalesce(json_agg(json_build_object('type', type, 'version', "latestVersion")), '[]'::json)
 FROM installed_nodes WHERE package = 'n8n-nodes-globals'))
FROM installed_packages WHERE "packageName" = 'n8n-nodes-globals'; ROLLBACK;'''
MANIFEST_JS = r'''
const fs=require('fs'),path=require('path');
const base='/home/node/.n8n/nodes/node_modules/n8n-nodes-globals';
const file=base+'/package.json';
if(!fs.existsSync(file)){console.log('{}');process.exit(0)}
const p=JSON.parse(fs.readFileSync(file,'utf8'));const nodes=p.n8n?.nodes;
const valid=Array.isArray(nodes)&&nodes.length>0&&nodes.length<=32&&nodes.every(n=>{
 if(typeof n!=='string')return false;
 const f=path.resolve(base,n);if(!f.startsWith(base+'/')||!fs.existsSync(f))return false;
 return fs.realpathSync(f).startsWith(fs.realpathSync(base)+'/')&&fs.statSync(f).isFile();
});
console.log(JSON.stringify({name:p.name,version:p.version,node_files_valid:valid,node_count:Array.isArray(nodes)?nodes.length:0}));
'''

def local_inventory():
    def command(args):
        p = subprocess.run([OWNER, 'podman', 'exec', *args], capture_output=True, timeout=12)
        if p.returncode:
            raise RuntimeError('local_inventory_command_failed')
        return p.stdout.decode()
    rows = command(['n8n-postgres','psql','-X','-qAt','-U','n8n','-d','n8n','-c',SQL]).strip().splitlines()
    if len(rows) > 1:
        raise ValueError('ambiguous_package_rows')
    db = json.loads(rows[0]) if rows else {}
    manifest = json.loads(command(['n8n','node','-e',MANIFEST_JS]))
    return db, manifest

def assess_inventory(db, manifest):
    if db.get('package') != PACKAGE or db.get('version') != VERSION:
        raise ValueError('package_db_missing_or_version_mismatch')
    if manifest.get('name') != PACKAGE or manifest.get('version') != VERSION or manifest.get('node_files_valid') is not True:
        raise ValueError('package_manifest_or_files_invalid')
    nodes = db.get('nodes')
    if not isinstance(nodes,list) or not 0 < len(nodes) <= 32:
        raise ValueError('installed_nodes_missing')
    if len({n.get('type') for n in nodes}) != len(nodes):
        raise ValueError('duplicate_node_types')
    for n in nodes:
        if not isinstance(n.get('type'),str) or not n['type'].startswith(PACKAGE+'.') or not n['type'][len(PACKAGE)+1:]:
            raise ValueError('unexpected_node_type')
        if type(n.get('version')) not in (float,int) or n['version'] <= 0:
            raise ValueError('invalid_node_version')
    return nodes

def local_community_probe(opener, headers, inventory=local_inventory):
    result = {'n8n_packages': [], 'n8n_community_probe': 'local-db-manifest-authenticated-node-types'}
    try:
        db, manifest = inventory()
        nodes = assess_inventory(db, manifest)
        for node in nodes:
            request = urllib.request.Request('http://127.0.0.1:15678/rest/node-types',
                data=json.dumps({'nodeInfos':[{'name':node['type'],'version':node['version']}]}).encode(),
                headers={'Content-Type':'application/json',**headers}, method='POST')
            with opener.open(request, timeout=5) as response:
                if response.status != 200:
                    raise ValueError('node_types_http_failure')
                body=json.load(response)
            descriptions=body.get('data') if isinstance(body,dict) else None
            if not isinstance(descriptions,list) or len(descriptions)!=1:
                raise ValueError('node_type_not_loaded')
            desc=descriptions[0]
            names=(node['type'],node['type'][len(PACKAGE)+1:])
            if not isinstance(desc,dict) or desc.get('name') not in names:
                raise ValueError('node_type_identity_mismatch')
            versions=desc.get('version');versions=versions if isinstance(versions,list) else [versions]
            if node['version'] not in versions:
                raise ValueError('node_type_version_mismatch')
        result['n8n_packages']=[[PACKAGE,VERSION,False]]
        result['n8n_community_nodes_checked']=len(nodes)
    except Exception as exc:
        # Never expose HTTP bodies, subprocess stderr, auth headers or exception messages.
        result['n8n_community_error_type']=type(exc).__name__
        if isinstance(exc,ValueError) and str(exc) in {
            'package_db_missing_or_version_mismatch','package_manifest_or_files_invalid',
            'installed_nodes_missing','duplicate_node_types','unexpected_node_type','invalid_node_version',
            'node_types_http_failure','node_type_not_loaded','node_type_identity_mismatch','node_type_version_mismatch'}:
            result['n8n_community_error_code']=str(exc)
    return result"""

DEVICE_PROBE = LOCAL_COMMUNITY_PROBE + r'''
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
        if req.get("local_community_probe"):
            out.update(local_community_probe(opener, headers))
        else:
            status, body = get(opener, "http://127.0.0.1:15678/rest/community-packages", headers)
            out["n8n_packages"] = [[p.get("packageName"), p.get("installedVersion"), bool(p.get("failedLoading"))]
                                   for p in (body or {}).get("data", [])]
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
    require_isolated_device()
    request = dict(request, local_community_probe=EXPECT['arch'] == 'aarch64')
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
        ev.check(f'check {tag}: versions shown', odoo.get('version') == EXPECT['odoo_addon']
                 and n8n.get('version') == '2.43.6' and n8n.get('target_version') == '2.43.6',
                 {a: (apps[a].get('version'), apps[a].get('target_version')) for a in apps})
        ev.check(f'check {tag}: the source processor is {EXPECT["arch"]}',
                 odoo.get('arch') == EXPECT['arch'] and n8n.get('arch') == EXPECT['arch'],
                 {a: apps[a].get('arch') for a in apps})
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
        STATE['live_freeze'] = psql('odoo18-db', 'postgres', 'odoo',
                                    "SELECT value FROM ir_config_parameter WHERE key = 'web.base.url.freeze';")
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
    STATE.pop('converted', None)  # a failed conversion must not leave an earlier run's backup for `restore`
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
    if not STATE.get('converted'):
        raise Failed('restore needs the converted backup of this run (convert failed or did not run)')
    # armcompare's row evidence: anything Odoo's scheduler writes is after this moment.
    STATE['restore_started_epoch'] = time.time()
    STATE['restore_started_utc'] = datetime.fromtimestamp(STATE['restore_started_epoch'], timezone.utc).replace(
        tzinfo=None).isoformat()
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
    if EXPECT['arch'] == 'aarch64':
        ev.check(f'{label}: the JavaScript community node moved and loads here',
                 ['n8n-nodes-globals', '1.1.0', False] in (probe.get('n8n_packages') or []), probe.get('n8n_packages'))
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


# ---------------------------------------------------------------- backups from a real ARM HA

def arm_upload(args, name, ev):
    rc, reply = upload(Path(args.fixtures) / name / f'{name}.tar', ev=ev)
    meta = reply.get('ha_backup') or {}
    if rc != 0 or not meta.get('id'):
        raise Failed(f'upload of {name} refused: {ev.secrets.redact(reply.get("error"))}')
    return meta['id']


def arm_import(ev, ha, apps, label, tag):
    job, took = convert(ha, apps, 'woowtest', False, ev=ev, key=None, tag=tag)
    if not ev.check(f'{label}: conversion succeeded', job['state'] == 'succeeded', f'{took:.0f} s {job.get("error")}'):
        return False
    job, took = restore(job['result']['backup_id'], apps, ev=ev, tag=f'{tag}-restore')
    return ev.check(f'{label}: import succeeded', job['state'] == 'succeeded', f'{took:.0f} s {job.get("error")}')


def scenario_armdownload(ev, args):
    ha = arm_upload(args, 'woow-arm-downloaded', ev)
    job = run_check(ha, ['odoo', 'n8n'], ev=ev, tag='arm-downloaded')
    ev.check('downloaded copy: the check passes without a key', job['state'] == 'succeeded'
             and all(a['ok'] for a in job['result']['ha_check']['apps']), job.get('error'))
    if arm_import(ev, ha, ['odoo', 'n8n'], 'downloaded copy', 'arm-downloaded'):
        scenario_verify(ev, args, label='downloaded copy')


def scenario_armnative(ev, args):
    ha = arm_upload(args, 'woow-arm-native', ev)
    job = run_check(ha, ['odoo', 'n8n'], ev=ev, tag='arm-native')
    if not ev.check('ARM-only code: the check job ran', job['state'] == 'succeeded', job.get('error')):
        return
    apps = {a['app_id']: a for a in job['result']['ha_check']['apps']}
    dbs = {d['name']: d for d in apps['odoo']['odoo']['databases']}
    ev.check('ARM-only code: the database using the module is refused, naming it',
             not dbs['woowtest']['ok'] and any('woow_arm_native_probe' in b and 'ARM' in b for b in dbs['woowtest']['blockers']),
             dbs['woowtest']['blockers'])
    ev.check('ARM-only code: the other database can still move', dbs['woowtest2']['ok'], dbs['woowtest2']['blockers'])
    ev.check('ARM-only code: n8n moves with a warning naming the community node',
             apps['n8n']['ok'] and any('n8n-nodes-woow-native-probe' in w for w in apps['n8n']['warnings']),
             apps['n8n']['warnings'])
    rc, reply = helper('ha-convert-start', {'ha_backup_id': ha, 'apps': ['odoo'], 'odoo_database': 'woowtest',
                                            'test_mode': False, 'confirm': True, 'request_id': request_id('arm-native')},
                       timeout=300)
    state = wait_job(reply['job_id'], ev=ev)['state'] if rc == 0 else 'refused'
    ev.check('ARM-only code: the conversion does not go through', state != 'succeeded', state)
    if arm_import(ev, ha, ['n8n'], 'ARM-only community node', 'arm-native-n8n'):
        codes = {url: http_code(url) for url in ('http://127.0.0.1:15678/healthz/readiness', 'http://127.0.0.1:15679/healthz')}
        ev.check('ARM-only community node: n8n starts and answers', all(code == '200' for code in codes.values()), codes)
        probe = device_probe({'odoo': None, 'n8n': {'email': OWNER_EMAIL, 'password': args.secrets['N8N_OWNER_PW'],
                                                    'credential': CREDENTIAL, 'value': args.secrets['N8N_CREDENTIAL_VALUE']}})
        ev.check('ARM-only community node: the owner logs in and the JavaScript node still loads',
                 probe.get('n8n_login') is True and ['n8n-nodes-globals', '1.1.0', False] in (probe.get('n8n_packages') or []), probe)


def scenario_armcrash(ev, args):
    ha = arm_upload(args, 'woow-arm-crash', ev)
    if not arm_import(ev, ha, ['odoo'], 'unclean stop', 'arm-crash'):
        return
    marker = psql('odoo18-db', 'postgres', 'odoo', "SELECT value FROM ir_config_parameter WHERE key = 'woow.arm.crash.marker';")
    ev.check('unclean stop: the last committed row survived (ARM WAL replayed here)', marker.startswith('arm-crash-'), marker)
    count = psql('odoo18-db', 'postgres', 'odoo', f"SELECT count(*) FROM res_partner WHERE name LIKE '{PARTNER}%';")
    ev.check('unclean stop: the data is complete', count == '5', count)
    codes = {url: http_code(url) for url in ('http://127.0.0.1:18069/web/health', 'http://127.0.0.1:18080/web/health')}
    ev.check('unclean stop: Odoo health 200', all(code == '200' for code in codes.values()), codes)


FINGERPRINT_SQL = (r"SELECT format('%s.%s %s %s', schemaname, relname, (xpath('/row/c/text()', query_to_xml(format("
                   r"'select count(*) as c from %I.%I', schemaname, relname), false, true, '')))[1]::text, (xpath('/row/m/"
                   r"text()', query_to_xml(format('select md5(coalesce(string_agg(t::text, %L order by t::text), %L)) as m "
                   r"from %I.%I t', E'\n', '', schemaname, relname), false, true, '')))[1]::text) FROM pg_stat_user_tables "
                   r"ORDER BY schemaname, relname;")


def parse_arm_fingerprint(text, *, source=False):
    """Strict metadata-only parsing for the fixed 205-table ARM woowtest fixture."""
    result, current, sections = {}, None, 0
    for line in text.splitlines():
        line = line.strip()
        if source and line.startswith('#DB '):
            parts = line.split()
            if len(parts) != 2:
                raise Failed('invalid fingerprint database header')
            current = parts[1]
            sections += current == 'woowtest'
            continue
        if not line:
            continue
        if line.startswith('#'):
            if not source:
                raise Failed('unexpected target fingerprint comment')
            continue
        if source and current != 'woowtest':
            continue
        fields = line.split()
        if (len(fields) != 3 or not re.fullmatch(r'public\.[A-Za-z_][A-Za-z_0-9]*', fields[0])
                or not re.fullmatch(r'0|[1-9][0-9]*', fields[1])
                or not re.fullmatch(r'[0-9a-f]{32}', fields[2])):
            raise Failed('invalid fingerprint row (contents withheld)')
        table, count, digest = fields
        if table in result:
            raise Failed('duplicate fingerprint table')
        result[table] = (count, digest)
    if source and sections != 1:
        raise Failed('expected exactly one woowtest fingerprint section')
    if not result:
        raise Failed('empty fingerprint')
    return result


def sibling(name):
    """odoo_capture / odoo_explain next to this driver (python3 -I leaves the script folder off sys.path)."""
    if name in sys.modules:
        return sys.modules[name]
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules[name] = module
    return module


def arm_row_capture(args):
    """Row evidence inputs: the source rows (odoo_capture.py's source_cold stage of this very HA archive, fetched to
    --source-capture) and the target now, every table's fingerprint and the four tables row by row in ONE snapshot."""
    oc = sibling('odoo_capture')
    directory = Path(args.source_capture)
    manifest = oc.loads((directory / 'complete.json').read_bytes())
    raw = (directory / 'source_cold.json').read_bytes()
    if manifest.get('status') != 'complete' or (manifest.get('files') or {}).get('source_cold.json') != oc.digest(raw):
        raise Failed('source capture incomplete or altered')
    cap = oc.loads(raw)
    archive = Path(args.fixtures) / NAMES['enc'] / f'{NAMES["enc"]}.tar'
    if cap.get('stage') != 'source_cold' or cap.get('archive_sha256') != oc.file_hash(archive):
        raise Failed('source capture is not of this HA archive')
    source_tables = oc.validate(cap['records'], quiet=True)
    source_prints = oc.fingerprints(cap['records'])
    if not source_prints:
        raise Failed('source capture has no table fingerprints (schema version 1)')
    require_isolated_device()
    sql = Path(__file__).with_name('odoo_capture.sql').read_text(encoding='utf-8')
    proc = owner('podman', 'exec', '-i', 'odoo18-db', 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres',
                 '-d', 'odoo', '-f', '-', input=sql.encode(), timeout=600)
    if proc.returncode != 0:
        raise Failed('target capture failed')
    records = [oc.loads(line) for line in proc.stdout.decode('utf-8').splitlines() if line.strip()]
    target_tables = oc.validate(records)
    lines = '\n'.join(r['line'] for r in records if r.get('kind') == 'table_fingerprint')
    meta = next(r for r in records if r.get('kind') == 'capture_metadata')
    return {'source_tables': source_tables, 'source_prints': source_prints, 'target_tables': target_tables,
            'target_prints': parse_arm_fingerprint(lines), 'captured_at': meta['captured_at'],
            'source_capture_run': manifest.get('run_id'), 'archive_sha256': cap['archive_sha256']}


def odoo_cron_log(since_epoch):
    """ir.cron jobs Odoo's own log (the device journal) shows starting since a moment."""
    oc = sibling('odoo_capture')
    proc = root('journalctl', '--since', '@%d' % int(since_epoch), '--no-pager', '-o', 'cat',
                'CONTAINER_NAME=odoo18-web', timeout=120)
    if proc.returncode != 0:
        raise Failed('the Odoo log could not be read')
    started, completed, lines = set(), set(), 0
    for line in proc.stdout.decode('utf-8', 'replace').splitlines():
        match = oc.CRON_LINE.search(line)
        if match:
            lines += 1
            (started if match.group(2) == 'starting' else completed).add(int(match.group(1)))
    return {'started': sorted(started), 'completed': sorted(completed), 'lines': lines}


def arm_row_evidence(capture, source, changed):
    """Every differing row of the four tables against a vendor-cited rule (odoo_explain); fail closed."""
    oc, ox = sibling('odoo_capture'), sibling('odoo_explain')
    binding = oc.table_delta(source, capture['source_prints'])
    if not (STATE.get('restore_started_utc') and STATE.get('restore_started_epoch') and STATE.get('live_before')):
        raise Failed('row evidence needs this run\'s convert and restore')
    log = odoo_cron_log(STATE['restore_started_epoch'] - 5)
    live = {'web.base.url': STATE['live_before'].get('base_url') or None,
            'web.base.url.freeze': STATE.get('live_freeze') or None,
            'woow_paas_platform.upgrade_done': STATE['live_before'].get('marker') or None}
    events = ox.explain(capture['source_tables'], capture['target_tables'], rules=('import', 'runtime'), live=live,
                        restore_start=ox.ts(STATE['restore_started_utc']),
                        captured_at=ox.ts(capture['captured_at']), cron_log_ids=log['started'])
    with_events = sorted({e['table'] for e in events})
    expected = sorted(t for t in changed if t in ox.TABLES)
    outside = sorted(t for t in changed if t not in ox.TABLES)
    complete = with_events == expected and not binding
    explained = [t for t in expected if complete and all(e['explained'] for e in events if e['table'] == t)]
    return {'source_capture_run': capture['source_capture_run'], 'archive_sha256': capture['archive_sha256'],
            'binding_ok': not binding, 'binding': {'tables': len(source), 'differ_from_ha_fingerprint': binding},
            'restore_started_utc': STATE['restore_started_utc'], 'captured_at': capture['captured_at'],
            'cron_log': log, 'tables_with_row_events': with_events, 'tables_outside_row_evidence': outside,
            'explained_tables': explained, 'all_explained': complete and not outside and len(explained) == len(expected),
            'summary': ox.summary(events), 'events': [ox.public_event(e) for e in events]}


def scenario_armcompare(ev, args):
    capture = None
    try:
        source = parse_arm_fingerprint(Path(args.fingerprint).read_text(encoding='utf-8'), source=True)
        if len(source) != 205:
            raise Failed('expected 205 source tables for the fixed ARM fixture')
        required = {'public.res_partner', 'public.woow_import_probe',
                    'public.res_partner_category', 'public.res_country'}
        if not required <= source.keys():
            raise Failed('required source fingerprint tables missing')
        if getattr(args, 'source_capture', None):
            capture = arm_row_capture(args)
            here = capture['target_prints']
        else:
            here = parse_arm_fingerprint(psql('odoo18-db', 'postgres', 'odoo', FINGERPRINT_SQL))
    except (Failed, OSError, UnicodeError, ValueError, KeyError, StopIteration) as error:
        ev.save('arm-compare.json', {'schema_version': 1, 'status': 'invalid_input',
                                   'error_type': type(error).__name__})
        ev.check('ARM fingerprint input valid', False, type(error).__name__)
        return
    same = sorted(t for t in source if here.get(t) == source[t])
    rows_differ = sorted(t for t in source if t in here and here[t][0] != source[t][0])
    content_differs = sorted(t for t in source if t in here and here[t][0] == source[t][0] and here[t][1] != source[t][1])
    missing, added = sorted(set(source) - set(here)), sorted(set(here) - set(source))
    # Every changed table needs evidence. No table name grants an exemption: only rows the explainer matches to a
    # vendor-cited rule, from a capture of this very archive, count as explained.
    changed = sorted(set(rows_differ) | set(content_differs))
    rows, explained = None, set()
    if capture is not None and changed:
        try:
            rows = arm_row_evidence(capture, source, changed)
            explained = set(rows['explained_tables']) if rows['all_explained'] else set()
        except (Failed, OSError, ValueError, KeyError) as error:
            rows = {'status': 'invalid_row_evidence', 'error_type': type(error).__name__}
    unresolved = sorted((set(changed) - explained) | set(missing) | set(added))
    ev.save('arm-compare.json', {'schema_version': 2 if capture is not None else 1,
            'status': 'unverified_differences' if unresolved else (
                'explained_row_differences' if changed else 'equal_fingerprints'),
            'source_tables': len(source), 'target_tables': len(here),
            'unverified_tables': unresolved, 'identical': len(same),
            'rows_differ': {t: (source[t][0], here[t][0]) for t in rows_differ},
            'content_differs': content_differs, 'missing': missing, 'added': added,
            'requires_row_evidence': changed, 'row_evidence': rows})
    ev.check('ARM source and x86 copy: exact table inventory', not missing and not added,
             {'missing': missing, 'added': added})
    suffix = '' if capture is None else ' (apart from rows explained one by one in arm-compare.json)'
    ev.check('ARM source and x86 copy: all table row counts identical' + suffix,
             not (set(rows_differ) - explained), rows_differ)
    ev.check('ARM source and x86 copy: all equal-count table contents identical' + suffix,
             not (set(content_differs) - explained), content_differs)
    if capture is not None and changed:
        ev.check('ARM row evidence: the source capture is this HA archive and equals the HA-side fingerprint of '
                 'all 205 tables', bool(rows and rows.get('binding_ok')), (rows or {}).get('binding') or rows)
        ev.check('ARM row evidence: every differing row matches a vendor-cited rule (no schema change, no other table)',
                 bool(rows and rows.get('all_explained')), (rows or {}).get('summary') or rows)
    if unresolved:
        ev.log('Unverified table differences; no automatic exemption: ' + ', '.join(unresolved))


# n8n's package list (GET /rest/community-packages) awaits `npm outdated --json` whenever a community package is
# installed (n8n 2.43.6 dist/modules/community-packages/community-packages.lifecycle.service.js:62-90; npm-utils.js:118
# runs npm with no timeout), i.e. it needs the npm registry. This measures that request with a longer limit while it
# samples the n8n container's processes, then runs the registry-free local probe on the same session.
N8N_DIAGNOSIS = LOCAL_COMMUNITY_PROBE + r"""
import http.cookiejar, json, subprocess, sys, threading, time, urllib.request
req = json.loads(sys.stdin.read())
out = {}
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
headers = {"browser-id": "woow-ha-e2e"}
try:
    login = urllib.request.Request("http://127.0.0.1:15678/rest/login", data=json.dumps(
        {"emailOrLdapLoginId": req["email"], "password": req["password"]}).encode(),
        headers=dict({"Content-Type": "application/json"}, **headers))
    with opener.open(login, timeout=60) as resp:
        out["login"] = resp.status == 200
except Exception as exc:
    out["login"] = False
    out["login_error_type"] = type(exc).__name__
listing = {}
def run_listing():
    began = time.monotonic()
    try:
        r = urllib.request.Request("http://127.0.0.1:15678/rest/community-packages", headers=headers)
        with opener.open(r, timeout=req["timeout"]) as resp:
            body = json.loads(resp.read() or b"null")
            listing["status"] = resp.status
            listing["packages"] = [[p.get("packageName"), p.get("installedVersion"), bool(p.get("failedLoading"))]
                                   for p in (body or {}).get("data", [])]
    except Exception as exc:
        listing["error_type"] = type(exc).__name__
    listing["seconds"] = round(time.monotonic() - began, 1)
PROCS = ["/usr/local/bin/woowbk-owner", "podman", "exec", "n8n", "sh", "-c",
         'for f in /proc/[0-9]*/cmdline; do tr "\\000" " " < "$f" 2>/dev/null; echo; done']
seen, samples = [], 0
if out.get("login"):
    thread = threading.Thread(target=run_listing, daemon=True)
    began = time.monotonic()
    thread.start()
    while thread.is_alive() and time.monotonic() - began < req["timeout"] + 15:
        p = subprocess.run(PROCS, capture_output=True, timeout=30)
        samples += 1
        if any("npm" in line and "outdated" in line for line in p.stdout.decode("utf-8", "replace").splitlines()):
            seen.append(round(time.monotonic() - began, 1))
        time.sleep(3)
    thread.join(5)
    started = time.monotonic()
    out.update(local_community_probe(opener, headers))
    out["local_probe_seconds"] = round(time.monotonic() - started, 1)
out["listing"] = listing
out["process_samples"] = samples
out["npm_outdated_seen"] = [seen[0], seen[-1], len(seen)] if seen else []
print(json.dumps(out))
"""


def scenario_n8ndiag(ev, args):
    """Root cause of the old 60 s probe timeout: the package list waits on the npm registry, the node itself loads."""
    require_isolated_device()
    request = {'email': OWNER_EMAIL, 'password': args.secrets['N8N_OWNER_PW'], 'timeout': 150}
    proc = root('python3', '-I', '-c', N8N_DIAGNOSIS, input=json.dumps(request).encode(), timeout=400)
    try:
        result = json.loads(proc.stdout.decode('utf-8', 'replace').strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Failed('n8n diagnosis failed') from None
    ev.save('n8n-diagnosis.json', result)
    listing = result.get('listing') or {}
    ev.check('n8n diagnosis: the owner logs in', result.get('login') is True, result.get('login_error_type'))
    if EXPECT['arch'] == 'aarch64':
        waited = listing.get('error_type') in ('TimeoutError', 'URLError', 'timeout') or listing.get('seconds', 0) >= 60
        ev.check('n8n diagnosis: with the community package installed, GET /rest/community-packages waits on '
                 '`npm outdated` (npm registry; this lab has no network)',
                 bool(result.get('npm_outdated_seen')) and waited,
                 {'listing': listing, 'npm_outdated_seen': result.get('npm_outdated_seen'),
                  'samples': result.get('process_samples')})
        ev.check('n8n diagnosis: the same restored node loads without the registry (database row, package files, '
                 'runtime node type)',
                 result.get('n8n_packages') == [['n8n-nodes-globals', '1.1.0', False]]
                 and result.get('n8n_community_nodes_checked', 0) >= 1,
                 {k: result.get(k) for k in ('n8n_packages', 'n8n_community_nodes_checked', 'n8n_community_error_type',
                                             'n8n_community_error_code', 'local_probe_seconds')})
    else:
        ev.check('n8n diagnosis: without community packages the list answers at once and runs no npm',
                 listing.get('status') == 200 and listing.get('packages') == [] and listing.get('seconds', 99) < 10
                 and not result.get('npm_outdated_seen'),
                 {'listing': listing, 'npm_outdated_seen': result.get('npm_outdated_seen')})


def wait_healthy(seconds):
    urls = ('http://127.0.0.1:18069/web/health', 'http://127.0.0.1:18080/web/health',
            'http://127.0.0.1:15678/healthz/readiness', 'http://127.0.0.1:15679/healthz')
    deadline = time.monotonic() + seconds
    while True:
        codes = {url: http_code(url) for url in urls}
        if all(code == '200' for code in codes.values()) or time.monotonic() > deadline:
            return codes
        time.sleep(5)


def scenario_restart(ev, args, *, database='woowtest'):
    """The imported apps survive a full restart of their units: Odoo's database, web and gateway, and n8n.target
    (its 7 services); then the data, logins, the credential and (ARM) the community node are checked again."""
    names = ('odoo18-db', 'odoo18-web', 'odoo18-gateway', 'n8n-postgres', 'n8n', 'n8n-worker')
    def started():
        return {n: owner('podman', 'inspect', '--format', '{{.State.StartedAt}}', n).stdout.decode().strip()
                for n in names}
    before = started()
    odoo_rc = owner('systemctl', '--user', 'restart', 'odoo-db.service', 'odoo.service', 'odoo-gateway.service',
                    timeout=900).returncode
    n8n_rc = owner('systemctl', '--user', 'restart', 'n8n.target', timeout=900).returncode
    codes = wait_healthy(420)
    after = started()
    ev.check('restart: Odoo (database, web, gateway) and n8n.target restarted with new containers',
             odoo_rc == 0 and n8n_rc == 0 and all(after[n] and after[n] != before[n] for n in names),
             {'odoo_rc': odoo_rc, 'n8n_rc': n8n_rc, 'new_start': sorted(n for n in names if after[n] != before[n])})
    ev.check('restart: health 200 everywhere', all(code == '200' for code in codes.values()), codes)
    gate = owner('systemctl', '--user', 'show', 'odoo.service', '-p', 'ActiveState', '-p', 'Result').stdout.decode()
    ev.check('restart: odoo.service active again (upgrade gate passed on start)', 'ActiveState=active' in gate,
             gate.strip())
    count = psql('odoo18-db', 'postgres', 'odoo', f"SELECT count(*) FROM res_partner WHERE name LIKE '{PARTNER}%';")
    record = psql('odoo18-db', 'postgres', 'odoo', f"SELECT count(*) FROM woow_import_probe WHERE name = '{PROBE_RECORD}';")
    ev.check('restart: Odoo still has the 5 test partners and the probe record', count == '5' and record == '1',
             f'{count} {record}')
    secrets = args.secrets
    probe = device_probe({'odoo': {'logins': [['admin', secrets['ODOO_ADMIN_PW']], ['ha-probe', secrets['ODOO_PROBE_PW']]]},
                          'n8n': {'email': OWNER_EMAIL, 'password': secrets['N8N_OWNER_PW'], 'credential': CREDENTIAL,
                                  'value': secrets['N8N_CREDENTIAL_VALUE']}})
    ev.save('probe-restart.json', probe)
    ev.check('restart: Odoo admin and ha-probe log in, attachment readable',
             probe.get('odoo_login_admin') and probe.get('odoo_login_ha-probe') and probe.get('odoo_attachment') is True,
             probe)
    ev.check('restart: n8n owner logs in and the credential is listed',
             probe.get('n8n_login') is True and probe.get('n8n_credential_found') is True, probe)
    if EXPECT['arch'] == 'aarch64':
        ev.check('restart: the JavaScript community node still loads',
                 ['n8n-nodes-globals', '1.1.0', False] in (probe.get('n8n_packages') or []), probe.get('n8n_packages'))
    decrypted = credential_probe(CREDENTIAL, secrets['N8N_CREDENTIAL_VALUE'])
    ev.check(f'restart: credential "{CREDENTIAL}" still decrypts to the expected value', decrypted.get('match') is True,
             decrypted)
    rows = psql('n8n-postgres', 'n8n', 'n8n', 'SELECT name || \'|\' || active FROM workflow_entity ORDER BY name;')
    flows = dict(line.split('|', 1) for line in rows.splitlines() if '|' in line)
    executions = psql('n8n-postgres', 'n8n', 'n8n', 'SELECT count(*) FROM execution_entity;')
    ev.check(f'restart: 3 workflows with "{SCHEDULED}" active and the executions kept',
             len(flows) == 3 and flows.get(SCHEDULED) == 'true' and executions.isdigit() and int(executions) >= 1,
             {'workflows': flows, 'executions': executions})


# ---------------------------------------------------------------- review-fix scenarios (FIXPLAN item 21)

def labelled():
    """The owner's throwaway containers, volumes and networks (the job label)."""
    found = {}
    for kind, argv, fmt in (('containers', ('ps', '-a'), '{{.Names}}'), ('volumes', ('volume', 'ls'), '{{.Name}}'),
                            ('networks', ('network', 'ls'), '{{.Name}}')):
        found[kind] = owner('podman', *argv, '--filter', JOB_LABEL, '--format', fmt).stdout.decode().split()
    return found


def registry_rows(job_id):
    proc = root('cat', '/var/lib/woowtech-backup/ha-imports.json')
    try:
        rows = json.loads(proc.stdout.decode('utf-8') or '{}').get('imports') or {}
    except ValueError:
        return ['unreadable']
    return [bid for bid, row in rows.items() if row.get('job_id') == job_id]


def job_record(job_id):
    proc = root('cat', f'/var/lib/woowtech-backup/jobs/{job_id}.json')
    return json.loads(proc.stdout.decode('utf-8') or '{}')


def nothing_left(ev, label, job_id, backups_before):
    objects = labelled()
    staging = root('ls', '-A', STAGING).stdout.decode().split()
    keys = root('sh', '-c', 'ls -A /run/woowtech-backup | grep "^key-" || true').stdout.decode().split()
    rows = registry_rows(job_id)
    backups = [b['id'] for b in ok('list', ev=ev)['backups']]
    record = job_record(job_id)
    ev.check(f'{label}: nothing left (throwaway objects, staging, key file, ha-imports.json row, new backup, '
             f'temp_owners)', not any(objects.values()) and not staging and not keys and not rows
             and sorted(backups) == sorted(backups_before) and not record.get('temp_owners'),
             {**objects, 'staging': staging, 'keys': keys, 'rows': rows,
              'new_backups': sorted(set(backups) - set(backups_before)), 'temp_owners': record.get('temp_owners')})


def apps_healthy(ev, label):
    codes = {url: http_code(url) for url in ('http://127.0.0.1:18069/web/health', 'http://127.0.0.1:18080/web/health',
                                             'http://127.0.0.1:15678/healthz/readiness', 'http://127.0.0.1:15679/healthz')}
    ev.check(f'{label}: the live apps were never touched (health 200 everywhere)',
             all(code == '200' for code in codes.values()), codes)


def start_convert(args, *, ev, tag, apps=('odoo', 'n8n')):
    request = {'ha_backup_id': STATE['ha_enc'], 'apps': list(apps), 'test_mode': False, 'confirm': True,
               'request_id': request_id(tag), 'key': args.secrets['HA_BACKUP_KEY']}
    if 'odoo' in apps:
        request['odoo_database'] = 'woowtest'
    return ok('ha-convert-start', request, ev=ev, timeout=300)['job_id']


def wait_for_container(job_id, *, ev, roles=('hapg', 'odoo-db', 'n8n-pg', 'n8n-export', 'n8n-import'), timeout=900):
    """Until the job runs one of these throwaway containers (a long container step); returns its name."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        names = owner('podman', 'ps', '--filter', JOB_LABEL, '--format', '{{.Names}}').stdout.decode().split()
        hit = next((n for n in names if n.startswith(f'woowbk-{job_id}-') and n.rsplit(f'{job_id}-', 1)[1] in roles),
                   None)
        if hit:
            return hit
        job = ok('job-status', {'job_id': job_id}, ev=ev)['job']
        if job['state'] not in ('queued', 'running'):
            raise Failed(f'job {job_id} ended ({job["state"]}) before a container step: {job.get("error")}')
        time.sleep(0.5)
    raise Failed(f'job {job_id} ran no container step in {timeout} s')


def scenario_kill(ev, args):
    """A conversion killed in the middle of a container step: the recovery marks it interrupted and its throwaway
    containers, volumes and networks (they outlive the job's process) are removed."""
    before = [b['id'] for b in ok('list', ev=ev)['backups']]
    job_id = start_convert(args, ev=ev, tag='kill')
    name = wait_for_container(job_id, ev=ev)
    unit = f'woowtech-backup-{job_id}.service'
    root('systemctl', 'kill', '--signal=SIGKILL', unit)
    for _ in range(60):
        if root('systemctl', 'is-active', unit).stdout.decode().strip() != 'active':
            break
        time.sleep(1)
    left = labelled()
    ev.check('kill: the throwaway objects outlive the killed job process', any(left.values()),
             {'killed during': name, **left})
    ok('status', ev=ev)  # the recovery runs here
    job = ok('job-status', {'job_id': job_id}, ev=ev)['job']
    ev.save(f'job-{job_id}.json', job)
    ev.check('kill: the job is interrupted with the HA message', job['state'] == 'interrupted' and
             '轉換 HA 備份的作業意外中斷' in ((job.get('error') or {}).get('message') or ''), job.get('error'))
    nothing_left(ev, 'kill', job_id, before)
    apps_healthy(ev, 'kill')


def scenario_cancel(ev, args):
    """A cancel in the middle of a long container step stops the conversion within seconds (review C-15)."""
    before = [b['id'] for b in ok('list', ev=ev)['backups']]
    job_id = start_convert(args, ev=ev, tag='cancel')
    name = wait_for_container(job_id, ev=ev)
    started = time.monotonic()
    rc, reply = helper('job-cancel', {'job_id': job_id})
    ev.check('cancel: job-cancel accepted during a container step', rc == 0, f'{name} {reply}')
    job = wait_job(job_id, ev=ev, timeout=600)
    took = time.monotonic() - started
    ev.check('cancel: the job ends cancelled within 30 s', job['state'] == 'cancelled' and took < 30,
             f'{took:.1f} s after the request, during {name.rsplit(job_id + "-", 1)[1]}: {job["state"]}')
    nothing_left(ev, 'cancel', job_id, before)
    apps_healthy(ev, 'cancel')


def device_free(path):
    out = root('python3', '-I', '-c', 'import os, sys; s = os.statvfs(sys.argv[1]); print(s.f_bavail * s.f_frsize, '
               's.f_blocks * s.f_frsize)', path).stdout.decode().split()
    return int(out[0]), int(out[1])


def scenario_space(ev, args):
    """Too little space, simulated with a size-limited tmpfs over the staging folder (inside dev-c only; the device
    disk is the host's and is never filled): refused before any work, and stopped in the middle of the conversion
    (the space watchdog / the measured estimate), each time with nothing left and the apps untouched."""
    _free, total = device_free('/var/lib/woowtech-backup')
    floor = max(512 << 20, min(max(2 << 30, total // 20), 10 << 30)) + (512 << 20)  # running reserve + margin
    member = 26503359  # the Odoo member of the encrypted test backup
    up_front = 3 * member
    for label, size, words in (('refused', floor + up_front - (64 << 20), '空間不足'),
                               ('aborted', floor + up_front + (24 << 20), '空間不足')):
        before = [b['id'] for b in ok('list', ev=ev)['backups']]
        if root('mount', '-t', 'tmpfs', '-o', f'size={size},mode=0700,uid=0,gid=0', 'tmpfs', STAGING).returncode:
            raise Failed('mounting the size-limited staging failed')
        try:
            job_id = start_convert(args, ev=ev, tag=f'space-{label}', apps=('odoo',))
            job = wait_job(job_id, ev=ev, timeout=900)
        finally:
            root('umount', STAGING)
        log = ok('job-status', {'job_id': job_id}, ev=ev).get('log') or []
        error = job.get('error') or {}
        phases = [p['id'] for p in job['phases'] if p['state'] in ('done', 'active', 'failed')]
        ev.check(f'space {label}: the conversion fails with insufficient-space',
                 job['state'] == 'failed' and error.get('code') == 'insufficient-space' and words in error.get('message', ''),
                 f'{error} phases reached {phases}')
        if label == 'aborted':
            ev.check('space aborted: stopped after the work had started (not by the first estimate)',
                     any(p in phases for p in ('decrypt', 'convert')), {'phases': phases, 'log': log[-6:]})
        nothing_left(ev, f'space {label}', job_id, before)
        apps_healthy(ev, f'space {label}')


def scenario_pull(ev, args):
    """The device has no PostgreSQL 16 image of its own: the check downloads the pinned postgres:16.15-alpine by its
    Docker Hub digest and runs HA's cluster from that very reference. dev-c's only PG16 image (n8n's) is untagged for
    the check and tagged again afterwards (the running n8n-postgres container keeps its image)."""
    ref = 'docker.io/library/postgres:16.15-alpine'
    image_id = owner('podman', 'image', 'inspect', '--format', '{{.Id}}', ref).stdout.decode().strip()
    if not image_id:
        raise Failed(f'{ref} is not on dev-c')
    owner('podman', 'untag', image_id, ref, check=True)
    try:
        job = run_check(STATE['ha_enc'], ['odoo'], ev=ev, key=args.secrets['HA_BACKUP_KEY'], tag='pull')
        log = ok('job-status', {'job_id': job['id']}, ev=ev).get('log') or []
        pulled = owner('podman', 'image', 'inspect', '--format', '{{.Id}} {{.RepoDigests}}',
                       'docker.io/library/postgres:16.15-alpine@sha256:'
                       'aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139').stdout.decode().strip()
        apps = (job.get('result') or {}).get('ha_check', {}).get('apps') or [{}]
        ev.check('pull: the check downloaded the pinned image and succeeded with it',
                 job['state'] == 'succeeded' and apps[0].get('ok') is True and any('下載固定版本' in l for l in log)
                 and bool(pulled), {'state': job['state'], 'error': job.get('error'), 'pulled': pulled[:120],
                                    'log': [l for l in log if '下載' in l]})
    finally:
        owner('podman', 'tag', image_id, ref)
    again = owner('podman', 'image', 'inspect', '--format', '{{.Id}}', ref).stdout.decode().strip()
    ev.check('pull: n8n\'s PostgreSQL image is tagged as before', again == image_id, again)
    apps_healthy(ev, 'pull')


# search_path is a list: one literal per element (a single literal of the whole text would be ONE schema name and
# leave Odoo without `public` -- the very mistake review C-06 is about).
C19_SETTINGS = (('work_mem', "'8MB'", '8MB'), ('search_path', "'$user', 'public', 'woowlab'", '"$user", public, woowlab'))


def live_settings_rows():
    return psql('odoo18-db', 'postgres', 'postgres',
                "SELECT name || '|' || setting || '|' || source FROM pg_settings WHERE name IN ('work_mem', 'search_path') "
                "ORDER BY name;")


def scenario_c19(ev, args):
    """Review C-19 proof: settings set on the live cluster (ALTER SYSTEM) reach the converted cluster -- the old
    single-transaction ALTER SYSTEM made every such conversion fail at its last step -- and the restored database
    runs with them; then dev-c's own settings are reset."""
    for name, literal, _shown in C19_SETTINGS:
        psql('odoo18-db', 'postgres', 'postgres', f'ALTER SYSTEM SET {name} = {literal};')
    psql('odoo18-db', 'postgres', 'postgres', 'SELECT pg_reload_conf();')
    rows = live_settings_rows()
    ev.check('c19: the live cluster sets work_mem and search_path in its configuration',
             rows.count('configuration file') == 2, rows)
    try:
        job, took = convert(STATE['ha_enc'], ['odoo'], 'woowtest', False, ev=ev, key=args.secrets['HA_BACKUP_KEY'],
                            tag='c19')
        log = ok('job-status', {'job_id': job['id']}, ev=ev).get('log') or []
        carried = [line for line in log if '沿用這台 PostgreSQL 的設定' in line]
        ev.check('c19: the conversion succeeds and carries both settings', job['state'] == 'succeeded'
                 and any('search_path' in l and 'work_mem' in l for l in carried),
                 f'{took:.0f} s {job.get("error")} {carried}')
        if job['state'] != 'succeeded':
            return
        STATE['converted_c19'] = job['result']['backup_id']
        restored, took = restore(job['result']['backup_id'], ['odoo'], ev=ev, tag='c19-restore')
        ev.check('c19: the converted backup restores', restored['state'] == 'succeeded',
                 f'{took:.0f} s {restored.get("error")}')
        shown = {name: psql('odoo18-db', 'postgres', 'odoo', f'SHOW {name};') for name, _l, _s in C19_SETTINGS}
        ev.check('c19: the restored cluster runs with the carried settings (list setting element by element)',
                 all(shown[name] == expected for name, _l, expected in C19_SETTINGS), shown)
        apps_healthy(ev, 'c19')
    finally:
        for name, _literal, _shown in C19_SETTINGS:
            psql('odoo18-db', 'postgres', 'postgres', f'ALTER SYSTEM RESET {name};')
        psql('odoo18-db', 'postgres', 'postgres', 'SELECT pg_reload_conf();')
    rows = live_settings_rows()
    ev.check('c19: dev-c\'s own settings are reset', 'configuration file' not in rows, rows)


F8_DROPIN = '.config/systemd/user/odoo-db.service.d/woowbk-f8.conf'
F8_MARKER = '.woowbk-f8-fail-once'


def f8_inject(enable):
    """The next start of odoo-db.service fails once (an ExecStartPost= that consumes a marker file); the rollback's
    start then succeeds (cli_e2e.py's F8 for the demo app)."""
    if enable:
        script = (f'mkdir -p "$HOME/{Path(F8_DROPIN).parent}" && touch "$HOME/{F8_MARKER}" && '
                  f'printf "%s\\n" "[Service]" '
                  f'"ExecStartPost=/bin/sh -c \'test ! -e $HOME/{F8_MARKER} || {{ rm -f $HOME/{F8_MARKER}; exit 1; }}\'" '
                  f'> "$HOME/{F8_DROPIN}" && systemctl --user daemon-reload')
    else:
        script = (f'rm -f "$HOME/{F8_DROPIN}" "$HOME/{F8_MARKER}"; rmdir "$HOME/{Path(F8_DROPIN).parent}" 2>/dev/null; '
                  'systemctl --user daemon-reload')
    owner('sh', '-c', script, check=True)


def scenario_rollback(ev, args):
    """A restore of a converted backup that fails after the destructive step (injected: the database's first start
    fails) rolls back automatically: Odoo has exactly the data from before the restore."""
    backup_id = STATE.get('converted_c19') or STATE.get('converted')
    if not backup_id:
        raise Failed('rollback needs a converted backup (run c19 or convert first)')
    marker = f'before-rollback-{int(time.time())}'
    psql('odoo18-db', 'postgres', 'odoo',
         "INSERT INTO ir_config_parameter (key, value, create_uid, create_date, write_uid, write_date) VALUES "
         f"('woowbk.lab.rollback', '{marker}', 1, now(), 1, now()) ON CONFLICT (key) DO UPDATE SET value = "
         "EXCLUDED.value;")
    f8_inject(True)
    try:
        job, took = restore(backup_id, ['odoo'], ev=ev, tag='rollback')
    finally:
        f8_inject(False)
    result = job.get('result') or {}
    ev.check('rollback: the failed restore rolled back', job['state'] == 'rolled-back' and result.get('rolled_back')
             is True, f'{took:.0f} s {job["state"]} {job.get("error")} safety={result.get("safety_backup_id")}')
    value = psql('odoo18-db', 'postgres', 'odoo', "SELECT value FROM ir_config_parameter WHERE key = 'woowbk.lab.rollback';")
    ev.check('rollback: Odoo has the data from before the restore', value == marker, value)
    psql('odoo18-db', 'postgres', 'odoo', "DELETE FROM ir_config_parameter WHERE key = 'woowbk.lab.rollback';")
    gate = owner('systemctl', '--user', 'show', 'odoo.service', '-p', 'ActiveState').stdout.decode().strip()
    ev.check('rollback: odoo.service active again', gate == 'ActiveState=active', gate)
    apps_healthy(ev, 'rollback')


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
    # prodlike_baseline.py wrote these rows right before it made the two backups: they prove dev-c's own data is back.
    markers = {'odoo': psql('odoo18-db', 'postgres', 'odoo',
                            "SELECT value FROM ir_config_parameter WHERE key = 'woowbk.lab.baseline.before';"),
               'n8n': psql('n8n-postgres', 'n8n', 'n8n', "SELECT value FROM settings WHERE key = 'woowbk.lab.baseline.before';")}
    ev.check('baseline: the lab data is back (prodlike_baseline.py markers in Odoo and n8n)',
             all(value.startswith('before-backup-') for value in markers.values()), markers)
    codes = {url: http_code(url) for url in ('http://127.0.0.1:18069/web/health', 'http://127.0.0.1:18080/web/health',
                                             'http://127.0.0.1:15678/healthz/readiness', 'http://127.0.0.1:15679/healthz')}
    ev.check('baseline: health 200 everywhere', all(code == '200' for code in codes.values()), codes)


def scenario_live(ev, args):
    """The target's web.base.url and upgrade marker right before an import started elsewhere (ha_import_ui.mjs drives
    it through the page), so that `verify` afterwards compares with them like after `convert`."""
    STATE['live_before'] = live_odoo_facts()
    ev.check('live: recorded web.base.url and the upgrade marker of this device', all(STATE['live_before'].values()),
             STATE['live_before'])
    save_state()


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
    parser.add_argument('--prefix', default='woow-import-test', help='file name prefix of the three HA backups')
    parser.add_argument('--odoo-addon-version', default=EXPECT['odoo_addon'], help='the Odoo add-on version in the backups')
    parser.add_argument('--arch', default=EXPECT['arch'], choices=('amd64', 'aarch64'), help='the processor of the source HA')
    parser.add_argument('--fingerprint', default=str(LAB / 'evidence' / 'arm-ha-import' / 'source-fingerprint.txt'),
                        help='armcompare: the table fingerprints taken on the source HA before its backups')
    parser.add_argument('--creds', default=str(SECRET_DIR / 'ha-import-creds.env'))
    parser.add_argument('--n8n-data', default=str(SECRET_DIR / 'ha-import-n8n-testdata.sh'))
    parser.add_argument('--baseline', help='ODOO_BACKUP_ID,N8N_BACKUP_ID of dev-c backups from before any import')
    parser.add_argument('--source-capture', help='armcompare row evidence: odoo_capture.py fetch directory of the same '
                                                 'ARM archive (schema version 2); without it differences stay unverified')
    parser.add_argument('--evidence', default='ha-import', help='evidence folder below ~/.woowbk-lab/evidence')
    args = parser.parse_args()
    try:
        require_isolated_device()
    except Failed as error:
        parser.exit(2, str(error) + '\n')
    EXPECT.update(odoo_addon=args.odoo_addon_version, arch=args.arch)
    NAMES.update({tag: name.replace('woow-import-test', args.prefix) for tag, name in NAMES.items()})
    args.secrets = Secrets(args.creds, args.n8n_data)
    ev = Evidence(args.secrets, re.sub(r'[^A-Za-z0-9_.-]', '', args.evidence) or 'ha-import')
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
            elif name in ('kill', 'cancel', 'space', 'pull', 'rollback') and not STATE.get('ha_enc'):
                raise Failed(f'{name} needs the uploads (run upload first)')
            else:
                globals()[f'scenario_{name}'](ev, args)
    except Failed as error:
        ev.check('driver', False, str(error))
    finally:
        save_state()
    sys.exit(0 if ev.finish() else 1)


if __name__ == '__main__':
    main()
