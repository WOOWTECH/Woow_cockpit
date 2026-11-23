#!/usr/bin/env python3
"""LiteLLM: the owner-made REAL HA backup of the showcase's woow-litellm 0.1.15 add-on (LiteLLM 1.104.0, PostgreSQL
18.6, encrypted) -> dev-d's LiteLLM installed from the WOOWTECH Podman package (Woow_podman_litellm dd690ae, PostgreSQL
17) through the PRODUCT HA-import flow, exactly the helper commands the Cockpit page sends (lane litellm-product,
2026-11-23, owner decision 「決定1 做」: the product path, trusted schema and HA's rows only, HA's salt moved).

  python3 -I tests/e2e/lab/services_a_capture.py --private=FILE <evidence.json> <scope> -- \\
      python3 -I tests/e2e/lab/litellm_full_flow.py --run
  python3 -I tests/e2e/lab/litellm_full_flow.py --self-check      (offline; never touches a device or a secret)

One run = one hold of the dev-d mutation lock (blocking like `flock -w 3600`, never taken while emqx-main's waiting
file exists), dev-d's outer isolation recorded before and after, the checkout committed. Every engine call is the
root helper the page calls (one JSON request on stdin, one JSON reply), with the engine of THIS tree installed by
deploy-src.sh. Phases:

  setup     the scheduled-backup timer masked for the run; deploy-src.sh d --src <this tree>; installed engine == tree;
            LiteLLM deployed from the package: the package copy (git archive dd690ae), the lab images already in
            dev-d (PostgreSQL 17.11 alpine 094ecc9c re-tagged and pinned to its device digest; the app = the lab build
            0c71bec8 of the package on the public LiteLLM 1.104.0 base, derived once with USER 1000:0 and its prisma
            folder owned by it, because dev-d maps container IDs 0..55000 and the image's 65534 cannot run -- the
            lab difference services-b used too), scripts/install.sh --no-pull (fresh secrets, units, smoke); the
            catalog entry from catalog-suggest -> catalog-install; key-init; this device's OWN data seeded through
            the API with its master key (a credential, a model using it, a virtual key with a value chosen here)
  before    this device's own state: secret digests, DB counts and salt digest, schema signature digest, own key 200
  upload    upload-begin, the file copied to the path the helper gave, upload-finish
  check     ha-check-start litellm with the HA key: ok, versions 0.1.15 / 1.104.0, PG 18 -> 17, counts 1/1/24, keys,
            the derived key_users (dev-d's real catalog and configuration)
  convert   the real free space and the product floor, ha-convert-start (real SpaceGuard/Watchdog), the job log
            names the trusted-schema steps, the list row, inspect (preflight in place, settings same)
  autorb    restore-start with a one-shot ExecStartPre failure of litellm.service: must end rolled-back with THIS
            device's own salt, data and key back (automatic rollback restores the old secret and database)
  import    restore-start of the converted backup: succeeded, safety backup, health ok
  verify    HA's test virtual key 200 on /key/info (alias), users/teams/models 1/1/24, every stored provider value
            decrypts in the running app with the moved salt and none with a random one, the litellm-salt-key secret
            and the database salt are HA's, the master key / UI password / DB password / DB URL secrets unchanged,
            this device's master key works, this device's own key 401, the schema is this device's (signature)
  restart   systemctl --user restart litellm-postgres.service litellm.service: verified again
  rollback  restore-start of the import's safety backup: this device's own salt, data and key back, HA's key 401
  cleanup   test backups deleted, the HA store record this run made deleted, the catalog entry removed, LiteLLM
            removed from dev-d (units, volume, network, secrets, config, package copy, the derived image tag, the
            PG17 tag), no job object, staging or key file; the baseline containers as found
  leaks     every registered value (HA key, HA test key, HA's four secret files, the own seed credential and key,
            dev-d's five LiteLLM secrets) looked for in the engine's records, uploads, staging, run dir, the device
            journal and this run's private evidence (before the LiteLLM secrets are removed)

stdout carries only fixed lines (`<check>: PASS|FAIL`, the isolation line, the source commit, lock time); details go to
the private, redacted evidence folder ~/.woowbk-lab/evidence/litellm-product/<time>/ (0700).
Not covered (stated): the browser page itself (dev-d publishes no port; the helper calls are the page's), provider
calls and ChatGPT token refresh (dev-d has no network: real provider keys stay inside), the product UID 65534.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets as pysecrets
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
LOCK = Path('/tmp/woowbk-dev-d-mutation.lock')
WAITING = Path('/tmp/woowbk-dev-d-emqx-main-waiting')
LOCK_TIMEOUT = 3600
OPTIONAL_BUDGET = 25 * 60       # no optional phase (autorb, restart) starts after this many seconds of the hold
MIN_DEVICE_HEADROOM = 1900 * 1024 * 1024
MIN_HOST_AVAILABLE_KIB = 1200 * 1024
MIN_DISK_FREE = 13 * 1024 ** 3
FIXTURE = LAB / 'ha-fixtures/20261123-litellm/x86/woow-litellm-x86-enc/woow-litellm-x86-enc-20261123.tar'
FIXTURE_SHA256 = '9dc5994497d9d6ff4c3ee8d3fcf86f295cf25c69d1eae98227854fee85286f27'
EXPECTED_ALIAS = 'woow-import-test-20261123'
EXPECTED = {'users': 1, 'teams': 1, 'models': 24}
PACKAGE = Path.home() / 'Woow_podman_litellm'
PACKAGE_REV = 'dd690ae'
DEST = 'Woow_podman_litellm'
APP_BASE = 'sha256:0c71bec8f80e3445267e9bc08495d3782b5c80c8fb7ca18261f07abad00ce312'
APP_TAG = 'localhost/woow-litellm:1.104.0-0.3.16'
PG17_ID = 'sha256:094ecc9ca4ea66931822a93f1d814e059deda57f355d9416fa72f85170871cb7'
PG17_TAG = 'docker.io/library/postgres:17.11-alpine3.23'
PG17_PINNED = PG17_TAG + '@sha256:bc2701f9a79f9248bcb18743bc9b2c732d9a1d16737ca44a8f577752fc43b61f'
DERIVE = ('FROM ' + APP_BASE + '\nUSER 0\nRUN chown -R 1000:0 /app/.venv/lib/python3.13/site-packages/prisma\n'
          'USER 1000:0\nLABEL io.woowtech.lab.derived-from=' + APP_BASE + '\n')
UNITS = ('litellm-postgres.service', 'litellm.service')
LITELLM_SECRETS = ['litellm-database-url', 'litellm-master-key', 'litellm-postgres-password', 'litellm-salt-key',
                   'litellm-ui-password']
TIMER = 'woowtech-cockpit-backup-schedule.timer'
DROPIN_DIR_REL = '.config/systemd/user/litellm.service.d'
DROPIN_REL = DROPIN_DIR_REL + '/zz-litellm-product-fail-once.conf'
MARKER_REL = '.litellm-product-fail-once'
SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ,()/:'<>.=_-]")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drv = _load('ha_import_b1_e2e')
Failed = drv.Failed
drv.state_path = lambda: LAB / 'run' / 'litellm_full_flow.json'   # never the b1 driver's own state file


def label(text):
    return SAFE_LABEL.sub(' ', str(text))[:140].strip() or 'check'


def emit(line):
    print(line, flush=True)


class Ev(drv.Evidence):
    """The b1 driver's private, redacted evidence folder; stdout gets only `<label>: PASS|FAIL`."""

    def log(self, text):
        line = f'{time.strftime("%H:%M:%S")} {self.secrets.redact(str(text))}'
        with open(self.log_path, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')

    def check(self, name, ok, detail=''):
        result = super().check(name, ok, detail)
        emit(f'{label(name)}: {"PASS" if result else "FAIL"}')
        return result


class _Tick(Exception):
    pass


def _tick(_signum, _frame):
    raise _Tick()


def _block(fd, seconds):
    """A kernel-queued `flock` wait of at most `seconds` (True: held)."""
    import fcntl
    import signal
    previous = signal.signal(signal.SIGALRM, _tick)
    signal.alarm(max(1, int(seconds)))
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return True
    except _Tick:
        return False
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def acquire(lock=LOCK, waiting=WAITING, timeout=LOCK_TIMEOUT, *, sleep=time.sleep, clock=time.monotonic, tick=30,
            block=_block):
    """The dev-d mutation lock like `flock -w <timeout>`: a kernel-queued waiter like the other lanes' drivers (the
    omnigent-product driver's method; this driver's earlier 5-second polling lost every turn to them, attempt 6),
    never taken while emqx-main asks for the next turn (its waiting file exists) and given back at once when that
    file appeared meanwhile. Returns (fd, waited seconds)."""
    import fcntl
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o664)
    started = clock()
    try:
        while True:
            if clock() - started > timeout:
                raise Failed('dev-d mutation lock not acquired in time')
            if waiting.exists():
                sleep(5)
                continue
            if not block(fd, tick):
                continue
            if waiting.exists():
                fcntl.flock(fd, fcntl.LOCK_UN)
                sleep(5)
                continue
            return fd, int(clock() - started)
    except BaseException:
        os.close(fd)
        raise


def clean_tree(repo=REPO):
    out = subprocess.run(['git', '-C', str(repo), 'status', '--porcelain', '--untracked-files=all'],
                         capture_output=True, text=True, timeout=60, check=True).stdout
    changed = [line[3:] for line in out.splitlines() if line.strip()]
    dirty = [p for p in changed if not p.startswith(('tests/e2e/lab/evidence/', 'tests/backup/evidence/'))]
    return not dirty, dirty


def head(repo=REPO):
    return subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=60,
                          check=True).stdout.strip()


def verify_isolation():
    proc = subprocess.run([str(HERE / 'owner.sh'), 'd', '--verify-isolation'], capture_output=True, text=True,
                          timeout=60)
    line = proc.stdout.strip()
    if proc.returncode != 0 or line != 'dev-d isolation: true none {}':
        raise Failed('dev-d isolation check failed')
    return line


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def ha_secret_files(key):
    """HA's four secret files of the backup (stripped bytes as str), read in this process by the product reader."""
    sys.path.insert(0, str(REPO / 'backup-engine'))
    from woowbackup import habackup, hasecuretar, hastore
    wanted = ('master_key', 'salt_key', 'pg_password', 'ui_password')
    found = {}
    with habackup.open_backup(FIXTURE) as ha:
        members = [m for m in ha.layout.members if m.role == 'addon' and hastore.addon_suffix(m.slug) == 'woow-litellm']
        if len(members) != 1:
            raise Failed('litellm member missing')
        select = habackup.Select(include=tuple(f'data/secrets/{n}' for n in wanted), symlinks=(), hardlinks=False)
        with ha.open_member(members[0].name, hasecuretar.Keys(key)) as stream:
            for entry in habackup.iter_entries(stream, select, habackup.Report(), addon=True):
                if entry.kind == 'file':
                    found[entry.name.rsplit('/', 1)[1]] = entry.read_all(1024).strip().decode('ascii')
    if set(found) != set(wanted):
        raise Failed('HA secret files missing')
    return found


# ---------------------------------------------------------------- device-side programs (no secret ever printed)

ENGINE_HASHES = r'''
import hashlib, json, os
lib = "/usr/local/lib/woowtech-cockpit-backup/woowbackup"
out = {"lib": {}, "helper": None}
for d, dirs, files in os.walk(lib):
    dirs[:] = [x for x in dirs if x != "__pycache__"]
    for f in files:
        if f.endswith(".py"):
            p = os.path.join(d, f)
            out["lib"][os.path.relpath(p, lib)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
out["helper"] = hashlib.sha256(open("/usr/local/libexec/woowtech-cockpit-backup", "rb").read()).hexdigest()
print(json.dumps(out))
'''

SPACE = r'''
import json, os, sys
sys.path.insert(0, "/usr/local/lib/woowtech-cockpit-backup")
from types import SimpleNamespace
from woowbackup import flows, haimport, storage
from woowbackup.paths import Paths
paths = Paths()
st = storage.Storage(paths)
ctx = SimpleNamespace(storage=st, paths=paths)
reserve = flows.running_reserve(ctx)
folders = ["/var/lib/woowtech-backup/staging", "/home/appowner", "/home/appowner/.local/share/containers/storage"]
free = {}
for f in folders:
    s = os.statvfs(f)
    free[f] = s.f_bavail * s.f_frsize
print(json.dumps({"total": int(st.total_bytes()), "running_reserve": int(reserve), "watch_margin": int(haimport.WATCH_MARGIN),
                  "floor": int(reserve + haimport.WATCH_MARGIN), "min_free": min(free.values())}))
'''

# Runs INSIDE the live litellm container (python -I -): every stored provider value through LiteLLM's own decryptor,
# with the container's LITELLM_SALT_KEY and with a random salt from stdin; only counts leave.
DECRYPT = r'''
import json, os, sys
import psycopg
from litellm.proxy.common_utils.encrypt_decrypt_utils import _decrypt_with_signing_key as dec
wrong = json.loads(sys.stdin.readline())["wrong"]
salt = os.environ["LITELLM_SALT_KEY"]
def ok(v, k):
    try:
        return isinstance(dec(value=v, signing_key=k), str)
    except Exception:
        return False
r = {"model_values": 0, "model_ok": 0, "model_wrong_ok": 0, "stored_values": 0, "stored_ok": 0, "stored_wrong_ok": 0}
with psycopg.connect(host=os.environ["DATABASE_HOST"], user=os.environ["DATABASE_USERNAME"],
                     password=os.environ["DATABASE_PASSWORD"], dbname=os.environ["DATABASE_NAME"], connect_timeout=10) as db:
    for (p,) in db.execute('SELECT litellm_params FROM public."LiteLLM_ProxyModelTable"').fetchall():
        p = json.loads(p) if isinstance(p, str) else (p or {})
        for v in p.values():
            if isinstance(v, str) and v:
                r["model_values"] += 1; r["model_ok"] += ok(v, salt); r["model_wrong_ok"] += ok(v, wrong)
    for (c,) in db.execute('SELECT credential_values FROM public."LiteLLM_CredentialsTable"').fetchall():
        c = json.loads(c) if isinstance(c, str) else (c or {})
        for v in c.values():
            if isinstance(v, str) and v:
                r["stored_values"] += 1; r["stored_ok"] += ok(v, salt); r["stored_wrong_ok"] += ok(v, wrong)
print(json.dumps(r))
'''

# As appowner inside dev-d: secret digests, live DB counts and salt digest (the installed engine's own SQL for the
# schema signature), API answers for the given keys (values from the request or read here; never printed).
PROBE = r'''
import hashlib, json, subprocess, sys, time, urllib.error, urllib.request
sys.path.insert(0, "/usr/local/lib/woowtech-cockpit-backup")
from woowbackup import ha_litellm
REQ = json.loads(sys.stdin.readline() or "{}")
B = "http://127.0.0.1:4000"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def run(*argv, input=None, timeout=300):
    p = subprocess.run(list(argv), input=input, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout
def secret(name):
    rc, out = run("podman", "secret", "inspect", "--showsecret", "--format", "{{.SecretData}}", name, timeout=60)
    return out.rstrip(b"\n").decode() if rc == 0 else None
def call(method, path, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(B + path, data=data, method=method, headers=headers)
    try:
        with OPENER.open(req, timeout=60) as r:
            raw = r.read(4 * 1024 * 1024)
            return r.status, (json.loads(raw) if raw[:1] in (b"{", b"[") else None)
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None
def sql(statement):
    rc, out = run("podman", "exec", "litellm-postgres", "psql", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1",
                  "-U", "litellm", "-d", "litellm", "-c", statement)
    return json.loads(out) if rc == 0 and out.strip() else None
def canon(v):
    return hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
out = {}
values = {n: secret(n) for n in REQ.get("secrets", [])}
out["secret_sha256"] = {n: (hashlib.sha256(v.encode()).hexdigest() if v else None) for n, v in values.items()}
master = values.get("litellm-master-key")
deadline = time.time() + REQ.get("wait", 0)
while True:
    code, _ = call("GET", "/health/readiness")
    if code == 200 or time.time() > deadline:
        break
    time.sleep(5)
out["readiness"] = code
if REQ.get("action") == "seed":
    s = REQ["seed"]
    c1, _ = call("POST", "/credentials", master, {"credential_name": "woowbk-own-cred",
                 "credential_values": {"api_key": s["credential"]}, "credential_info": {"custom_llm_provider": "openai"}})
    c2, _ = call("POST", "/model/new", master, {"model_name": "woowbk-own-model",
                 "litellm_params": {"model": "openai/woowbk-own", "api_key": s["credential"], "api_base": "http://127.0.0.1:9/v1"},
                 "model_info": {"id": "woowbk-own-model-id"}})
    c3, body = call("POST", "/key/generate", master, {"key": s["key"], "key_alias": "woowbk-own-key", "models": ["woowbk-own-model"]})
    out["seed"] = {"credential": c1, "model": c2, "key": c3, "key_echo_matches": bool(body) and body.get("key") == s["key"]}
counts = sql("SELECT json_build_object("
             "'users', (SELECT count(*) FROM public.\"LiteLLM_UserTable\"), "
             "'teams', (SELECT count(*) FROM public.\"LiteLLM_TeamTable\"), "
             "'keys', (SELECT count(*) FROM public.\"LiteLLM_VerificationToken\" WHERE coalesce(team_id, '') <> 'litellm-dashboard'), "
             "'models', (SELECT count(*) FROM public.\"LiteLLM_ProxyModelTable\"), "
             "'credentials', (SELECT count(*) FROM public.\"LiteLLM_CredentialsTable\"), "
             "'spend_logs', (SELECT count(*) FROM public.\"LiteLLM_SpendLogs\"), "
             "'chatgpt_accounts', (SELECT count(*) FROM woow_platform.chatgpt_accounts), "
             "'migrations', (SELECT count(*) FROM public.\"_prisma_migrations\" WHERE finished_at IS NOT NULL), "
             "'major', current_setting('server_version_num')::int / 10000)")
out["counts"] = counts
salt_rows = sql(ha_litellm.SALT_DIGEST_SQL)
out["db_salt_sha256"] = salt_rows[0] if isinstance(salt_rows, list) and len(salt_rows) == 1 else None
sig = sql(ha_litellm.SIGNATURE_SQL)
out["signature_sha256"] = canon(sig) if sig is not None else None
out["signature_parts"] = {k: canon(v) for k, v in (sig or {}).items()}
keys = {}
for name, token in (REQ.get("keys") or {}).items():
    code, body = call("GET", "/key/info", token)
    info = (body or {}).get("info") if isinstance(body, dict) else None
    keys[name] = {"key_info": code, "alias": (info or {}).get("key_alias") if isinstance(info, dict) else None,
                  "models": call("GET", "/v1/models", token)[0]}
out["keys"] = keys
code, body = call("GET", "/user/list", master)
out["master_user_list"] = code
code, body = call("GET", "/v1/models", master)
out["master_models"] = code
out["router_models"] = len((body or {}).get("data") or []) if isinstance(body, dict) else None
if REQ.get("decrypt"):
    rc, res = run("podman", "exec", "-i", "litellm", "python", "-I", "-c", REQ["decrypt"],
                  input=(json.dumps({"wrong": REQ["wrong_salt"]}) + "\n").encode(), timeout=300)
    try:
        out["decrypt"] = json.loads(res.strip().splitlines()[-1]) if rc == 0 else {"rc": rc}
    except Exception:
        out["decrypt"] = {"rc": rc}
EGRESS = ("import socket, sys\nok = 0\nfor host, port in ((\"1.1.1.1\", 443), (\"8.8.8.8\", 53), (\"api.openai.com\", 443)):\n"
          "    try:\n        socket.create_connection((host, port), timeout=4).close()\n        ok += 1\n"
          "    except Exception:\n        pass\nprint(ok)")
rc, res = run("podman", "exec", "litellm", "python", "-I", "-c", EGRESS, timeout=120)
out["egress_connections"] = int(res.strip() or b"-1") if rc == 0 and res.strip().isdigit() else None
units = {}
for u in ("litellm-postgres.service", "litellm.service"):
    rc, state = run("systemctl", "--user", "is-active", u, timeout=60)
    units[u] = state.decode().strip()
out["units"] = units
print(json.dumps(out))
'''


# The leak scan (root, inside dev-d), like omnigent_full_flow.LEAKS (91a3086): the b1 driver's LEAK_SCAN requires
# /var/lib/woowtech-backup/index.json, which this engine does not keep; these are the engine's records as dev-d holds them.
LEAKS = 'import json\n' + __import__('inspect').getsource(drv.secret_scan_needles) + r"""
import os, subprocess, sys
req = json.loads(sys.stdin.read())
secrets = {name: value.encode() for name, value in req["secrets"].items() if value}
def owner(*argv):
    return subprocess.run(["runuser", "-u", "appowner", "--", "env", "-i", "PATH=/usr/bin:/bin", "HOME=/home/appowner",
                           "XDG_RUNTIME_DIR=/run/user/%d" % req["uid"], *argv], capture_output=True, timeout=120)
for name in req["podman_secrets"]:
    p = owner("podman", "secret", "inspect", "--showsecret", "--format", "{{.SecretData}}", name)
    value = p.stdout.rstrip(b"\n")
    if p.returncode != 0 or len(value) < 8:
        raise RuntimeError("cannot inspect required device secret")
    secrets["device:" + name] = value
needles = secret_scan_needles(secrets.values())
hits, scanned = 0, 0
roots = ["/var/lib/woowtech-backup/jobs", "/var/lib/woowtech-backup/ha-backups", "/var/lib/woowtech-backup/ha-imports.json",
         "/var/lib/woowtech-backup/archives", "/run/woowtech-backup", "/var/lib/woowtech-backup/uploads",
         "/var/lib/woowtech-backup/staging", "/var/lib/woowtech-backup/requests.json"]
def walk_error(error):
    raise RuntimeError("scan enumeration failed") from error
for root in roots:
    if not os.path.exists(root) or os.path.islink(root):
        raise RuntimeError("required scan root missing or unsafe")
    paths = [root] if os.path.isfile(root) else []
    if os.path.isdir(root):
        for d, dirs, files in os.walk(root, onerror=walk_error, followlinks=False):
            paths.extend(os.path.join(d, f) for f in files)
    for path in paths:
        if path.endswith(".tar") and ("/ha-backups/" in path or "/archives/" in path):
            continue  # the uploaded HA files themselves and the (encrypted) backups
        if os.path.islink(path):
            raise RuntimeError("unsafe scan path")
        data = open(path, "rb").read()
        scanned += 1
        hits += sum(data.count(s) for s in needles)
journal = subprocess.run(["journalctl", "-o", "cat", "--no-pager"], capture_output=True, check=True).stdout
hits += sum(journal.count(s) for s in needles)
print(json.dumps({"scanned": scanned, "journal_bytes": len(journal), "names": len(secrets), "hits": hits}))
"""


# ---------------------------------------------------------------- the run

class Run:
    def __init__(self, args, ev):
        self.args = args
        self.ev = ev
        self.lock_started = time.monotonic()
        self.installed_entry = self.deployed = self.timer_masked_here = self.dropin = False
        self.created_store = None
        self.before = {}
        self.converted = self.safety = self.store_id = None
        self.ha_salt_sha = self.own_key = None
        self.baseline_containers = []
        self.key_users = None

    def optional(self, phase):
        return time.monotonic() - self.lock_started <= OPTIONAL_BUDGET

    def headroom(self):
        proc = drv.root('sh', '-c', 'echo "$(cat /sys/fs/cgroup/memory.current) $(cat /sys/fs/cgroup/memory.max)"',
                        timeout=60)
        try:
            current, maximum = (int(x) for x in drv.out(proc).split())
        except ValueError:
            raise Failed('cannot read dev-d cgroup memory') from None
        available = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                         if line.startswith('MemAvailable:'))
        st = os.statvfs('/')
        free = st.f_bavail * st.f_frsize
        emit(f'dev-d memory current={current} limit={maximum}; headroom >= {MIN_DEVICE_HEADROOM / 1024 ** 3:.2f} GiB; '
             f'host MemAvailable {available} KiB')
        if maximum - current < MIN_DEVICE_HEADROOM:
            raise Failed('dev-d memory headroom too small')
        if available < MIN_HOST_AVAILABLE_KIB:
            raise Failed('host MemAvailable too low')
        if free - FIXTURE.stat().st_size < MIN_DISK_FREE:
            raise Failed('host disk free below the reserve')

    # -------- secrets (harness reader + the backup's own files in memory; never printed)
    def load_secrets(self):
        s = self.args.secrets
        for name in ('HA_BACKUP_KEY', 'LITELLM_TEST_VKEY'):
            if not s.values.get(name):
                raise Failed(f'{name} missing from the harness reader')
        files = ha_secret_files(s['HA_BACKUP_KEY'])
        for name, value in files.items():
            s.register(f'HA_LITELLM_{name.upper()}', value)
        self.ha_salt_sha = hashlib.sha256(files['salt_key'].encode()).hexdigest()
        self.own_key = 'sk-woowbk-own-' + pysecrets.token_hex(20)
        s.register('OWN_LITELLM_KEY', self.own_key)
        s.register('OWN_SEED_CREDENTIAL', 'sk-woowbk-seed-' + pysecrets.token_hex(20))
        s.register('WRONG_SALT', 'sk-' + pysecrets.token_hex(32))
        self.ev.check('secrets: HA key, HA test key, HA\'s four secret files, own key and seed registered (memory only)',
                      True, {'ha_files': sorted(files)})

    # -------- setup
    def setup(self):
        ev = self.ev
        self.baseline_containers = sorted(drv.out(drv.owner('podman', 'ps', '-a', '--format', '{{.Names}}')).split())
        ev.save('baseline-containers.json', self.baseline_containers)
        state = drv.out(drv.root('systemctl', 'is-enabled', TIMER, timeout=60)).strip()
        if state != 'masked':
            proc = drv.root('systemctl', 'mask', '--now', TIMER, timeout=120)
            self.timer_masked_here = proc.returncode == 0
        ev.check('setup: the scheduled-backup timer is masked for the run (shared lab)',
                 drv.out(drv.root('systemctl', 'is-enabled', TIMER, timeout=60)).strip() == 'masked', {'before': state})
        proc = drv.run(['bash', str(HERE / 'deploy-src.sh'), 'd', '--src', str(REPO), '--no-demo-catalog'], timeout=1800)
        ev.save('deploy.log', drv.out(proc)[-20000:] + proc.stderr.decode('utf-8', 'replace')[-5000:])
        if not ev.check('setup: deploy-src.sh d --src <this tree> --no-demo-catalog', proc.returncode == 0,
                        f'rc {proc.returncode}'):
            raise Failed('deploy failed')
        installed = drv.device_python(ENGINE_HASHES, {}, as_owner=False, timeout=300)
        base = REPO / 'backup-engine' / 'woowbackup'
        tree = {str(p.relative_to(base)): sha256_file(p) for p in base.rglob('*.py') if '__pycache__' not in p.parts}
        lib = installed.get('lib') or {}
        differ = sorted(k for k in set(tree) | set(lib) if tree.get(k) != lib.get(k))
        if not ev.check('setup: the installed engine is this tree (every module and the helper SHA-256 equal)',
                        not differ and installed.get('helper') == sha256_file(REPO / 'backup-engine' /
                                                                              'woowtech-cockpit-backup'),
                        {'modules': len(tree), 'differ': differ[:10]}):
            raise Failed('installed engine differs')
        self.deploy_litellm()
        status = drv.ok('status', ev=ev)
        if 'litellm' not in {a['id'] for a in status.get('apps') or []}:
            suggestion = drv.ok('catalog-suggest', {'owner': 'appowner'}, ev=ev, timeout=300)
            ev.save('catalog-suggest.json', suggestion)
            app = next((a for a in suggestion.get('apps') or [] if a.get('id') == 'litellm'), {})
            variant = next((v for v in app.get('variants') or [] if v.get('id') == 'database'), {})
            # The production catalog of this package (tests/backup/test_suggest.py fixture, facts CAT): the single
            # database mode (postgres item main), no built-in digests, the readiness URL within 300 s.
            entry = json.loads(json.dumps(variant.get('entry'))) if isinstance(variant.get('entry'), dict) else None
            if entry is not None:
                # The package's production entry (tests/backup/test_suggest.py fixture, facts CAT): no built-in
                # digests, GET /health/readiness (the draft proposes the Quadlet's liveness URL), both config files.
                entry['verify'] = []
                # Lab difference: up to 600 s (catalog maximum) on the loaded lab host; production allows 300 s.
                entry['health'] = [{'type': 'http', 'url': 'http://127.0.0.1:4000/health/readiness', 'expect_status': 200,
                                    'timeout_seconds': 600}]
                files = [c for c in entry.get('config_files') or [] if c.get('path') != '.config/litellm/litellm.env']
                entry['config_files'] = files + [{'path': '.config/litellm/litellm.env', 'mode': '0600'}]
            if not ev.check('setup: catalog-suggest proposes the litellm entry (single-database mode) from the installed '
                            'Quadlet files', isinstance(entry, dict) and variant.get('valid') is True,
                            {'apps': [a.get('id') for a in suggestion.get('apps') or []],
                             'variants': [v.get('id') for v in app.get('variants') or []]}):
                raise Failed('no litellm suggestion')
            preview = drv.ok('catalog-install', {'entry': entry}, ev=ev, timeout=300)
            if not ev.check('setup: catalog-install preview of the litellm entry is valid', preview.get('valid') is True,
                            {k: preview.get(k) for k in ('valid', 'errors', 'warnings', 'conflicts')}):
                raise Failed('catalog preview refused')
            drv.ok('catalog-install', {'entry': entry, 'confirm': True,
                                       'expected_sha256': preview.get('expected_sha256')}, ev=ev, timeout=300)
            self.installed_entry = True
        entry = drv.catalog('litellm')
        ev.save('catalog-litellm-installed.json', entry)
        pg = (entry.get('postgres') or [{}])[0]
        ev.check('setup: the litellm catalog entry has the package units, the postgres item main, the five secrets, '
                 'both config files and the readiness health URL', set(UNITS) <= set(entry.get('units') or [])
                 and sorted(c.get('path') for c in entry.get('config_files') or []) == ['.config/litellm/config.yaml',
                                                                                    '.config/litellm/litellm.env']
                 and (pg.get('id'), pg.get('container'), pg.get('database'), pg.get('user')) ==
                 ('main', 'litellm-postgres', 'litellm', 'litellm')
                 and sorted(s['name'] for s in entry.get('secrets') or []) == LITELLM_SECRETS
                 and any('/health/readiness' in h.get('url', '') for h in entry.get('health') or []),
                 {'units': entry.get('units'), 'postgres': pg, 'secrets': [s['name'] for s in entry.get('secrets') or []]})
        key = drv.ok('key-init', ev=ev)
        ev.check('setup: a device key exists (key-init)', bool((key.get('key') or {}).get('key_id')),
                 {'created': key.get('created')})
        s = self.args.secrets
        seeded = self.probe('seed', action='seed', seed={'credential': s['OWN_SEED_CREDENTIAL'], 'key': self.own_key},
                            wait=600)
        sd = seeded.get('seed') or {}
        ev.check("setup: this device's own data seeded with its master key (credential, model, key with a chosen value)",
                 sd.get('credential') == 200 and sd.get('model') == 200 and sd.get('key') == 200
                 and sd.get('key_echo_matches') is True, sd)

    def deploy_litellm(self):
        """The package in dev-d (see the module docstring), skipped when its units already run (a re-run)."""
        ev = self.ev
        active = {u: drv.out(drv.owner('systemctl', '--user', 'is-active', u, timeout=60)).strip() for u in UNITS}
        if all(v == 'active' for v in active.values()):
            ev.check('setup: LiteLLM already deployed and active in dev-d (re-run)', True, active)
            self.deployed = True
            return
        rev = subprocess.run(['git', '-C', str(PACKAGE), 'rev-parse', '--verify', PACKAGE_REV + '^{commit}'],
                             capture_output=True, text=True, timeout=60, check=True).stdout.strip()
        home = '/home/appowner'
        if drv.owner('test', '-d', f'{home}/{DEST}', timeout=60).returncode != 0:
            drv.owner('mkdir', '-p', f'{home}/{DEST}', timeout=60, check=True)
            archive = subprocess.run(['git', '-C', str(PACKAGE), 'archive', '--format=tar', rev], capture_output=True,
                                     timeout=300, check=True).stdout
            drv.owner('tar', '-C', f'{home}/{DEST}', '-xf', '-', input=archive, timeout=300, check=True)
            drv.owner('sh', '-c', f'printf "%s\\n" {rev} > {home}/{DEST}.lab-source', timeout=60, check=True)
        self.deployed = True
        for image in (APP_BASE, PG17_ID):
            if drv.owner('podman', 'image', 'exists', image, timeout=60).returncode != 0:
                raise Failed('a lab image is missing in dev-d')
        drv.owner('podman', 'tag', PG17_ID, PG17_TAG, timeout=120, check=True)
        digest = drv.out(drv.owner('podman', 'image', 'inspect', '--format', '{{.Digest}}', PG17_TAG, timeout=60)).strip()
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest) or drv.owner(
                'podman', 'image', 'exists', f'{PG17_TAG}@{digest}', timeout=60).returncode != 0:
            raise Failed('PG17 device digest does not resolve')
        path = f'{home}/{DEST}/quadlet/litellm-postgres.container'
        text = drv.out(drv.owner('cat', path, timeout=60, check=True))
        if text.count(PG17_PINNED) == 1:
            write_owner_file(f'{DEST}/quadlet/litellm-postgres.container',
                             text.replace(PG17_PINNED, f'{PG17_TAG}@{digest}').encode(), '0644')
        if drv.owner('podman', 'image', 'exists', APP_TAG, timeout=60).returncode != 0:
            proc = drv.owner('sh', '-c', 'd=$(mktemp -d /tmp/woowbk-litellm-derive-XXXXXXXX) || exit 9; '
                             'cat > "$d/Containerfile" && podman build --network=none --pull=never --memory=512m -q '
                             '-t "$1" -f "$d/Containerfile" "$d"; rc=$?; rm -rf -- "$d"; exit $rc', 'sh', APP_TAG,
                             input=DERIVE.encode(), timeout=1800)
            if not ev.check('setup: lab app image derived from the lab build 0c71bec8 (USER 1000:0, prisma folder; '
                            'dev-d maps IDs 0..55000)', proc.returncode == 0, f'rc {proc.returncode}'):
                raise Failed('derived image build failed')
        started = time.monotonic()
        # QL_HEALTH_ACTIVE=0 (the package library's own knob): its waiter otherwise runs `podman healthcheck run` every
        # 2 s, and each run uses one of the 40 startup-probe attempts the unit plans 15 s apart; on the loaded lab host
        # podman then restarts LiteLLM after ~2.5 min, before it is ready (attempt 2, 2026-11-23 18:33-18:48).
        proc = drv.owner('env', 'QL_HEALTH_ACTIVE=0', f'{home}/{DEST}/scripts/install.sh', '--no-pull', timeout=1800)
        ev.save('package-install.log', drv.out(proc)[-30000:] + proc.stderr.decode('utf-8', 'replace')[-20000:])
        if not ev.check('setup: Woow_podman_litellm dd690ae scripts/install.sh --no-pull in dev-d (fresh secrets, units, '
                        'health, smoke)', proc.returncode == 0,
                        f'rc {proc.returncode} {time.monotonic() - started:.0f} s'):
            raise Failed('package install failed')

    def probe(self, label_text, *, keys=None, decrypt=False, wait=300, **extra):
        s = self.args.secrets
        request = dict(extra, secrets=LITELLM_SECRETS, keys=keys or {}, wait=wait)
        if decrypt:
            request.update(decrypt=DECRYPT, wrong_salt=s['WRONG_SALT'])
        found = drv.device_python(PROBE, request, as_owner=True, timeout=wait + 900)
        self.ev.save(f'probe-{label_text.replace(" ", "-")}.json', found)
        return found

    def keys(self, *names):
        s = self.args.secrets
        table = {'ha': s['LITELLM_TEST_VKEY'], 'own': self.own_key}
        return {n: table[n] for n in names}

    def wait_units(self, label_text, timeout=420):
        deadline = time.monotonic() + timeout
        states = {}
        while time.monotonic() < deadline:
            states = {u: drv.out(drv.owner('systemctl', '--user', 'is-active', u, timeout=60)).strip() for u in UNITS}
            if all(v == 'active' for v in states.values()):
                break
            time.sleep(5)
        self.ev.check(f'{label_text}: litellm-postgres and litellm are active', all(v == 'active' for v in states.values()),
                      states)

    # -------- this device's own state
    def step_before(self):
        found = self.probe('before', keys=self.keys('own', 'ha'), decrypt=True)
        self.before = found
        c = found.get('counts') or {}
        d = found.get('decrypt') or {}
        self.ev.check("before: this device's own LiteLLM: own key 200, HA test key 401, own model and credential decrypt, "
                      'PG 17, schema signature read', (found.get('keys') or {}).get('own', {}).get('key_info') == 200
                      and (found.get('keys') or {}).get('ha', {}).get('key_info') in (401, 403)
                      and d.get('stored_values', 0) >= 1 and d.get('stored_ok') == d.get('stored_values')
                      and d.get('stored_wrong_ok') == 0 and c.get('major') == 17 and found.get('signature_sha256'),
                      {'counts': c, 'decrypt': d, 'keys': found.get('keys')})
        own_salt = (found.get('secret_sha256') or {}).get('litellm-salt-key')
        self.ev.check("before: this device's salt secret is its own (not HA's) and equals its database's",
                      own_salt and own_salt != self.ha_salt_sha and found.get('db_salt_sha256') == own_salt, '')

    def own_state(self, label_text):
        """This device's own data, salt and key are back (after an automatic or manual rollback)."""
        found = self.probe(label_text, keys=self.keys('own', 'ha'), decrypt=True, wait=600)
        before = self.before
        keys = found.get('keys') or {}
        d = found.get('decrypt') or {}
        self.ev.check(f"{label_text}: this device's own salt secret and database salt are back; master key, UI and DB "
                      'secrets unchanged', found.get('secret_sha256') == before.get('secret_sha256')
                      and found.get('db_salt_sha256') == before.get('db_salt_sha256'),
                      {'equal': {n: (found.get('secret_sha256') or {}).get(n) == (before.get('secret_sha256') or {}).get(n)
                                 for n in LITELLM_SECRETS}})
        # spend_logs is left out of the equality: LiteLLM logs the probes' own-key calls themselves, so the safety
        # backup (taken when the restore starts) holds more rows than the `before` probe saw (attempt 4: 1 -> 3).
        def stable(counts):
            return {k: v for k, v in (counts or {}).items() if k != 'spend_logs'}

        self.ev.check(f"{label_text}: this device's own data is back (counts, schema), own key 200, HA test key refused",
                      stable(found.get('counts')) == stable(before.get('counts'))
                      and (found.get('counts') or {}).get('spend_logs', -1) >= (before.get('counts') or {}).get('spend_logs', 0)
                      and found.get('signature_sha256') == before.get('signature_sha256')
                      and keys.get('own', {}).get('key_info') == 200 and keys.get('ha', {}).get('key_info') in (401, 403),
                      {'counts': [before.get('counts'), found.get('counts')], 'keys': keys})
        self.ev.check(f"{label_text}: this device's own stored values decrypt with its own salt again",
                      d.get('stored_values', 0) >= 1 and d.get('stored_ok') == d.get('stored_values')
                      and d.get('stored_wrong_ok') == 0, d)

    # -------- upload (page path) and check
    def step_upload(self):
        ev = self.ev
        sha = sha256_file(FIXTURE)
        if not ev.check('upload: the local file is the owner-made real LiteLLM HA backup (sha256)', sha == FIXTURE_SHA256,
                        sha[:16]):
            raise Failed('fixture changed')
        store_id = 'ha-' + sha[:20]
        listed = {h.get('id') for h in drv.ok('list', ev=ev).get('ha_backups') or []}
        started = time.monotonic()
        rc, reply = drv.upload(FIXTURE, ev=ev)
        meta = reply.get('ha_backup') or {}
        ev.save('upload-reply.json', reply)
        ev.check('upload: upload-begin, copy, upload-finish answer the HA store record (id from the SHA-256)',
                 rc == 0 and meta.get('id') == store_id, {'took_s': round(time.monotonic() - started, 1),
                                                         'existed_before': store_id in listed})
        found = {a['app_id']: a['installed'] for a in meta.get('importable_apps') or []}
        ev.check('upload: litellm is importable and installed here', found.get('litellm') is True, found)
        if store_id not in listed:
            self.created_store = store_id
        self.store_id = store_id
        if rc != 0 or meta.get('id') != store_id:
            raise Failed('upload refused')

    def step_check(self):
        ev = self.ev
        job, took = drv.run_check(self.store_id, ['litellm'], ev=ev, key=self.args.secrets['HA_BACKUP_KEY'],
                                  tag='check-litellm')
        if not ev.check('check: ha-check-start litellm job succeeded', job['state'] == 'succeeded',
                        f'{took:.0f} s {job.get("error")}'):
            raise Failed('check job failed')
        result = job['result']['ha_check']['apps'][0]
        ev.save('check-litellm.json', result)
        section = result.get('litellm') or {}
        ev.check('check: ok, no blockers (salt bound to HA\'s database, data shape equals this device\'s)',
                 result.get('ok') is True and not result.get('blockers'), result.get('blockers'))
        ev.check('check: source amd64, add-on 0.1.15 (LiteLLM 1.104.0), this device 1.104.0, PostgreSQL 18 -> 17',
                 (result.get('arch'), result.get('version'), result.get('target_version'), section.get('litellm_version'),
                  section.get('pg_major'), section.get('target_pg_major')) == ('amd64', '0.1.15', '1.104.0', '1.104.0',
                                                                                  18, 17),
                 {k: result.get(k) for k in ('arch', 'version', 'target_version')})
        ev.check('check: users, teams and models 1/1/24 and the test key among the virtual keys',
                 all(section.get(k) == v for k, v in EXPECTED.items()) and section.get('keys', 0) >= 1,
                 {k: section.get(k) for k in ('users', 'teams', 'models', 'keys', 'credentials', 'chatgpt_accounts')})
        self.key_users = section.get('key_users')
        ev.check("check: key_users derived from dev-d's real catalog and configuration (option A reminder)",
                 isinstance(self.key_users, list), {'key_users': self.key_users, 'warnings': result.get('warnings')})
        leftovers = drv.labelled()
        ev.check('check: no throwaway container, volume or network left', not any(leftovers.values()), leftovers)

    def step_convert(self):
        ev = self.ev
        space = drv.device_python(SPACE, {}, as_owner=False, timeout=120)
        ev.save('space-before-convert.json', space)
        ev.check("convert: real space: free space above the product's floor (running reserve + watch margin)",
                 isinstance(space.get('floor'), int) and space['min_free'] > space['floor'],
                 {k: space.get(k) for k in ('total', 'running_reserve', 'watch_margin', 'floor', 'min_free')})
        before_ids = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        job, took = drv.convert(self.store_id, ['litellm'], False, ev=ev, key=self.args.secrets['HA_BACKUP_KEY'],
                                tag='convert-litellm')
        ev.save('convert-job.json', job)
        if not ev.check('convert: ha-convert-start job succeeded with a backup id', job['state'] == 'succeeded'
                        and (job.get('result') or {}).get('backup_id'), f'{took:.0f} s {job.get("error")}'):
            raise Failed('convert failed')
        result = job['result']
        self.converted = result['backup_id']
        drv.created_backup(self.converted)
        imp = result.get('ha_import') or {}
        notes = '\n'.join(imp.get('notes') or [])
        ev.check('convert: ha_import: apps litellm, the salt note, the trusted-schema note, the MCP lines',
                 imp.get('apps') == ['litellm'] and 'litellm-salt-key' in notes and '資料庫結構' in notes
                 and any('Woow LiteLLM MCP Server' in line for line in (imp.get('reminders_by_app') or {}).get('litellm')
                         or []), {k: imp.get(k) for k in ('apps', 'test_mode')})
        log = '\n'.join(str(line) for line in (drv.ok('job-status', {'job_id': job['id']}, ev=ev).get('log') or []))
        ev.save('convert-log.txt', log)
        ev.check("convert: the job log names the product steps (PG 18 rows only, this device's schema in one snapshot, "
                 'the role without privileges, counts equal, HA salt used for litellm-salt-key)',
                 '只當作資料來源' in log and '同一個快照' in log and '沒有任何管理權限的暫用角色' in log
                 and '筆數都和 HA 相同' in log and '使用 HA 備份帶來的值' in log, {'log_lines': log.count('\n') + 1})
        listing = drv.ok('list', ev=ev)
        row = next((b for b in listing['backups'] if b['id'] == self.converted), {})
        ev.check('convert: the converted backup is listed as manual, encrypted, with its HA origin',
                 self.converted not in before_ids and row.get('type') == 'manual' and row.get('encrypted') is True
                 and (row.get('from_ha') or {}).get('ha_backup_id') == self.store_id,
                 {'type': row.get('type'), 'encrypted': row.get('encrypted')})
        inspect = drv.ok('inspect', {'backup_id': self.converted}, ev=ev, timeout=900)
        pre = inspect.get('preflight') or {}
        failed = [c for c in pre.get('checks') or [] if c.get('status') == 'fail']
        app = next((a for a in (inspect.get('manifest') or {}).get('apps') or [] if a.get('id') == 'litellm'), {})
        ev.check('convert: inspect: preflight passes in place with settings same; postgres main is PG 17; 5 secrets',
                 pre.get('ok') and not failed and all((a.get('settings') or {}).get('state') == 'same'
                                                      and a.get('mode') == 'inplace' for a in pre.get('apps') or [])
                 and [(p.get('id'), p.get('major')) for p in app.get('postgres') or []] == [('main', 17)]
                 and app.get('secrets_count') == 5, {'failed': failed[:3], 'postgres': app.get('postgres')})

    # -------- the automatic rollback of a failing import restore (this device's salt and data come back)
    def inject_on(self):
        drv.owner('mkdir', '-p', f'/home/appowner/{DROPIN_DIR_REL}', timeout=60)
        text = ('[Service]\nExecStartPre=/bin/sh -c \'if test -f %h/' + MARKER_REL + '; then rm -f %h/' + MARKER_REL
                + '; exit 1; fi\'\n')
        write_owner_file(DROPIN_REL, text.encode(), '0644')
        self.dropin = True
        owner_ok('systemctl', '--user', 'daemon-reload')
        write_owner_file(MARKER_REL, b'fail-once\n', '0600')

    def inject_off(self):
        if not self.dropin:
            return
        drv.owner('rm', '-f', f'/home/appowner/{DROPIN_REL}', f'/home/appowner/{MARKER_REL}', timeout=60)
        drv.owner('rmdir', f'/home/appowner/{DROPIN_DIR_REL}', timeout=60)
        drv.owner('systemctl', '--user', 'daemon-reload', timeout=120)
        self.dropin = owner_exists(DROPIN_REL) or owner_exists(MARKER_REL)

    def step_auto_rollback(self):
        ev = self.ev
        self.inject_on()
        try:
            job, took = drv.restore(self.converted, ['litellm'], ev=ev, tag='restore-inject-litellm')
        finally:
            consumed = not owner_exists(MARKER_REL)
            self.inject_off()
        ev.save('restore-inject-job.json', job)
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        ev.check('auto rollback: the import restore with a one-shot ExecStartPre failure of litellm.service ends '
                 'rolled-back (automatic rollback; the failure was consumed)', job['state'] == 'rolled-back'
                 and result.get('rolled_back') is True and consumed,
                 {'state': job['state'], 'error': job.get('error'), 'took_s': round(took, 1)})
        ev.check('auto rollback: the injected drop-in and marker are gone', not self.dropin, '')
        self.wait_units('auto rollback')
        self.own_state('auto rollback')

    # -------- the import
    def step_import(self):
        ev = self.ev
        job, took = drv.restore(self.converted, ['litellm'], ev=ev, tag='restore-litellm')
        ev.save('restore-job.json', job)
        result = job.get('result') or {}
        self.safety = result.get('safety_backup_id')
        drv.created_backup(self.safety)
        health = result.get('health') or []
        if not ev.check('import: restore-start of the converted backup succeeded with a safety backup, not rolled back, '
                        'every health check ok', job['state'] == 'succeeded' and self.safety
                        and result.get('rolled_back') is False and health and all(h.get('status') == 'ok' for h in health),
                        {'state': job['state'], 'error': job.get('error'), 'took_s': round(took, 1),
                         'health': [(h.get('id'), h.get('status')) for h in health]}):
            raise Failed('restore failed')
        drv.save_state()

    def verify(self, label_text):
        ev = self.ev
        self.wait_units(label_text)
        found = self.probe(label_text, keys=self.keys('ha', 'own'), decrypt=True, wait=600)
        keys = found.get('keys') or {}
        c = found.get('counts') or {}
        d = found.get('decrypt') or {}
        sha = found.get('secret_sha256') or {}
        before = self.before.get('secret_sha256') or {}
        ev.check(f"{label_text}: HA's test virtual key answers /key/info 200 with its alias and lists models",
                 keys.get('ha', {}).get('key_info') == 200 and keys.get('ha', {}).get('alias') == EXPECTED_ALIAS
                 and keys.get('ha', {}).get('models') == 200, keys.get('ha'))
        ev.check(f'{label_text}: users, teams and models are 1/1/24 like HA; PG 17', all(c.get(k) == v for k, v in
                                                                                       EXPECTED.items())
                 and c.get('major') == 17, c)
        ev.check(f'{label_text}: every stored provider value decrypts in the running app with the moved salt, none with '
                 'a random one', d.get('model_values', 0) > 0 and d.get('model_ok') == d.get('model_values')
                 and d.get('stored_values', 0) > 0 and d.get('stored_ok') == d.get('stored_values')
                 and d.get('model_wrong_ok') == 0 and d.get('stored_wrong_ok') == 0, d)
        ev.check(f"{label_text}: litellm-salt-key and the database salt are HA's; the master key, UI password, DB "
                 'password and URL secrets are unchanged', sha.get('litellm-salt-key') == self.ha_salt_sha
                 and found.get('db_salt_sha256') == self.ha_salt_sha
                 and all(sha.get(n) == before.get(n) for n in LITELLM_SECRETS if n != 'litellm-salt-key'),
                 {'salt_is_ha': sha.get('litellm-salt-key') == self.ha_salt_sha,
                  'unchanged': {n: sha.get(n) == before.get(n) for n in LITELLM_SECRETS if n != 'litellm-salt-key'}})
        ev.check(f"{label_text}: this device's master key works; this device's own key no longer does (keys replaced)",
                 found.get('master_user_list') == 200 and found.get('master_models') == 200
                 and keys.get('own', {}).get('key_info') in (401, 403),
                 {'master': [found.get('master_user_list'), found.get('master_models')], 'own': keys.get('own')})
        ev.check(f'{label_text}: the lab LiteLLM has no outbound network (0 of 3 connections from inside the container: '
                 'public IP, DNS server, provider host)', found.get('egress_connections') == 0,
                 {'egress_connections': found.get('egress_connections')})
        ev.check(f"{label_text}: the live schema is this device's (signature equal to before the import)",
                 found.get('signature_sha256') == self.before.get('signature_sha256'),
                 {'differ': sorted(k for k, v in (found.get('signature_parts') or {}).items()
                                   if v != (self.before.get('signature_parts') or {}).get(k))})
        drv.app_health(ev, 'litellm', label_text)

    def step_restart(self):
        ev = self.ev
        started = time.monotonic()
        proc = drv.owner('systemctl', '--user', 'restart', 'litellm-postgres.service', 'litellm.service', timeout=900)
        ev.check('restart: systemctl --user restart litellm-postgres.service litellm.service', proc.returncode == 0,
                 f'rc {proc.returncode} {time.monotonic() - started:.0f} s')
        self.verify('restart')

    def step_rollback_to_own(self):
        ev = self.ev
        started = time.monotonic()
        reply = drv.ok('restore-start', {'backup_id': self.safety, 'apps': ['litellm'], 'confirm': True,
                                         'request_id': drv.request_id('rollback-litellm')}, ev=ev, timeout=300)
        job = drv.wait_job(reply['job_id'], ev=ev, timeout=5400)
        ev.save('rollback-job.json', job)
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        health = result.get('health') or []
        ev.check("rollback: restore-start of the import's safety backup succeeded, every health check ok",
                 job['state'] == 'succeeded' and result.get('rolled_back') is False and health
                 and all(h.get('status') == 'ok' for h in health),
                 {'state': job['state'], 'error': job.get('error'), 'took_s': round(time.monotonic() - started, 1)})
        self.wait_units('rollback')
        self.own_state('rollback')

    # -------- leaks, then cleanup
    def step_leaks(self):
        ev = self.ev
        s = self.args.secrets
        names = [n for n in s.values if n not in s.names and n.startswith(
            ('HA_BACKUP_KEY', 'LITELLM_TEST_VKEY', 'HA_LITELLM_', 'OWN_', 'WRONG_SALT', 'ISSUED_TOKEN_'))]
        request = {'secrets': {n: s[n] for n in names if s[n]}, 'podman_secrets': LITELLM_SECRETS, 'uid': 1019}
        if len(request['secrets']) < 8:
            raise Failed('a lane secret is missing from the scan request')
        report = drv.device_python(LEAKS, request, as_owner=False, timeout=900)
        host = drv.scan_host_evidence(ev.dir, s)
        ev.save('leaks.json', {'device': report, 'host': host, 'names': sorted(names)})
        ev.check("leaks: no registered value (HA key, HA test key, HA's secret files, own key and seed, dev-d's LiteLLM "
                 "secrets) in the engine records, uploads, staging, journal or this run's evidence",
                 isinstance(report, dict) and report.get('hits') == 0 and report.get('scanned', 0) > 0
                 and host.get('hits') == 0, {'device': report, 'host': host})

    def step_cleanup(self):
        ev = self.ev
        self.inject_off()
        objects = drv.labelled()
        ev.check('cleanup: no throwaway container, volume or network of a job left', not any(objects.values()), objects)
        listing = drv.device_python(drv.RUN_LIST, as_owner=False)
        staging = listing.get(drv.STAGING)
        keys = [n for n in listing.get('/run/woowtech-backup') or [] if isinstance(n, str) and n.startswith('key-')]
        ev.check('cleanup: no staging folder and no key file left', staging in ([], 'missing') and not keys, listing)
        present = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        created = list(drv.STATE.get('created_backups') or [])
        deleted, refused = [], []
        for backup_id in created:
            if backup_id in present:
                rc, _reply = drv.helper('delete', {'backup_id': backup_id})
                (deleted if rc == 0 else refused).append(backup_id)
        left = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        ev.check("cleanup: the test's converted and safety backups are deleted", not (left & set(created)),
                 {'deleted': len(deleted), 'refused': refused})
        drv.STATE['created_backups'] = [b for b in created if b not in deleted]
        if self.created_store:
            rc, _reply = drv.helper('ha-delete', {'ha_backup_id': self.created_store, 'confirm': True})
            ev.check('cleanup: the HA store record this run created is deleted', rc == 0, self.created_store)
        if self.installed_entry:
            preview = drv.ok('catalog-remove', {'id': 'litellm'}, ev=ev)
            rc, reply = drv.helper('catalog-remove', {'id': 'litellm', 'confirm': True,
                                                      'expected_sha256': preview.get('expected_sha256')})
            ev.check('cleanup: the litellm catalog entry this run installed is removed (catalog as found)', rc == 0,
                     {'rc': rc, 'error': (reply or {}).get('error')})
        if self.deployed:
            self.remove_litellm()
        names = sorted(drv.out(drv.owner('podman', 'ps', '-a', '--format', '{{.Names}}')).split())
        ev.check('cleanup: the containers are the ones found before the run (no LiteLLM container left)',
                 set(names) <= set(self.baseline_containers) and not {'litellm', 'litellm-postgres'} & set(names),
                 {'before': self.baseline_containers, 'after': names})
        if self.timer_masked_here:
            proc = drv.root('systemctl', 'unmask', TIMER, timeout=120)
            drv.root('systemctl', 'start', TIMER, timeout=120)
            ev.check('cleanup: the scheduled-backup timer is back as found (unmasked)', proc.returncode == 0, '')
        drv.save_state()

    def remove_litellm(self):
        """LiteLLM out of dev-d again: the package's uninstall (units), then its data, network, secrets, files, tags."""
        ev = self.ev
        home = '/home/appowner'
        if drv.owner('test', '-x', f'{home}/{DEST}/scripts/uninstall.sh', timeout=60).returncode == 0:
            proc = drv.owner(f'{home}/{DEST}/scripts/uninstall.sh', '--yes', timeout=900)
            ev.save('package-uninstall.log', drv.out(proc)[-10000:] + proc.stderr.decode('utf-8', 'replace')[-5000:])
        for unit in UNITS:
            drv.owner('systemctl', '--user', 'stop', unit, timeout=300)
        drv.owner('podman', 'rm', '-f', '-t', '10', 'litellm', 'litellm-postgres', timeout=300)
        drv.owner('podman', 'volume', 'rm', '-f', 'litellm-pgdata', timeout=300)
        drv.owner('podman', 'network', 'rm', '-f', 'litellm-net', timeout=300)
        for name in LITELLM_SECRETS:
            drv.owner('podman', 'secret', 'rm', name, timeout=60)
        drv.owner('rm', '-rf', f'{home}/.config/litellm', f'{home}/{DEST}', f'{home}/{DEST}.lab-source',
                  f'{home}/backups/litellm', timeout=300)
        for name in ('litellm-postgres.container', 'litellm.container', 'litellm.network', 'litellm-pgdata.volume',
                     'litellm-backup.timer', 'litellm-backup.service'):
            drv.owner('rm', '-f', f'{home}/.config/containers/systemd/{name}', f'{home}/.config/systemd/user/{name}',
                      timeout=60)
        drv.owner('systemctl', '--user', 'daemon-reload', timeout=120)
        drv.owner('podman', 'rmi', APP_TAG, timeout=300)
        drv.owner('podman', 'untag', PG17_ID, PG17_TAG, timeout=120)
        secrets_left = [n for n in drv.out(drv.owner('podman', 'secret', 'ls', '--format', '{{.Name}}')).split()
                        if n.startswith('litellm')]
        volumes_left = [n for n in drv.out(drv.owner('podman', 'volume', 'ls', '--format', '{{.Name}}')).split()
                        if n.startswith('litellm')]
        units_left = drv.out(drv.owner('systemctl', '--user', 'list-units', '--all', '--no-legend', 'litellm*')).strip()
        ev.check('cleanup: LiteLLM removed from dev-d (units, volume, network, secrets, config, package copy, derived '
                 'image tag; the lab base images stay)', not secrets_left and not volumes_left and not units_left
                 and drv.owner('podman', 'image', 'exists', APP_TAG, timeout=60).returncode != 0
                 and drv.owner('podman', 'image', 'exists', APP_BASE, timeout=60).returncode == 0,
                 {'secrets': secrets_left, 'volumes': volumes_left, 'units': units_left[:200]})


def owner_ok(*argv, timeout=600):
    proc = drv.owner(*argv, timeout=timeout)
    if proc.returncode != 0:
        raise Failed(f'owner command failed: {argv[0]} rc {proc.returncode}')
    return drv.out(proc)


def write_owner_file(rel, data, mode='0644'):
    proc = drv.run([drv.LP, 'exec', '-i', drv.DEVICE, drv.OWNER, 'sh', '-c',
                    'umask 077 && cat > "$1" && chmod "$2" "$1"', 'sh', f'/home/appowner/{rel}', mode],
                   input=data, timeout=60)
    if proc.returncode != 0:
        raise Failed(f'writing ~/{rel} failed')


def owner_exists(rel):
    return drv.owner('test', '-e', f'/home/appowner/{rel}', timeout=60).returncode == 0


def run_all(run):
    ev = run.ev
    failure = None
    phases = [('secrets', run.load_secrets, False), ('setup', run.setup, False), ('before', run.step_before, False),
              ('upload', run.step_upload, False), ('check', run.step_check, False), ('convert', run.step_convert, False),
              ('autorb', run.step_auto_rollback, True), ('import', run.step_import, False),
              ('verify', lambda: run.verify('restore'), False), ('restart', run.step_restart, True)]
    try:
        for name, step, optional in phases:
            if optional and not run.optional(name):
                ev.check(f'{name}: skipped (lock hold budget)', False, '')
                continue
            ev.log(f'== {name}')
            step()
    except Exception as error:  # noqa: BLE001 - whatever stopped a phase, the cleanup below always runs
        failure = error
        ev.check(f'phase stopped: {type(error).__name__}', False, str(error)[:300])
    try:
        run.inject_off()
    except Exception as error:  # noqa: BLE001
        ev.check('inject off: ran', False, type(error).__name__)
    if run.safety:
        try:
            run.step_rollback_to_own()
        except Exception as error:  # noqa: BLE001
            failure = failure or error
            ev.check('rollback: ran', False, type(error).__name__)
    if run.deployed:
        try:
            run.step_leaks()
        except Exception as error:  # noqa: BLE001
            failure = failure or error
            ev.check('leaks: ran', False, type(error).__name__)
    try:
        run.step_cleanup()
    except Exception as error:  # noqa: BLE001
        failure = failure or error
        ev.check('cleanup: ran', False, type(error).__name__)
    return failure


def self_check():
    for name, program in (('SPACE', SPACE), ('PROBE', PROBE), ('ENGINE_HASHES', ENGINE_HASHES), ('DECRYPT', DECRYPT),
                          ('LEAKS', LEAKS)):
        compile(program, name, 'exec')
    if not re.fullmatch(r'[0-9a-f]{64}', FIXTURE_SHA256) or 'USER 1000:0' not in DERIVE:
        raise SystemExit('bad constants')
    print('offline self-check passed: 5 embedded programs compiled, fixture digest and derive recipe fixed')


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--self-check', action='store_true')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args(argv)
    if args.self_check:
        self_check()
        return 0
    if not args.run:
        parser.error('--run required')
    clean, _dirty = clean_tree()
    commit = head()
    emit(f'source commit {commit}')
    if not clean:
        emit('source tree committed: FAIL')
        return 2
    emit('source tree committed: PASS')
    fd, waited = acquire()
    started = time.monotonic()
    emit(f'dev-d mutation lock acquired: PASS (waited {waited} s)')
    rc = 1
    try:
        emit(verify_isolation())
        args.secrets = drv.Secrets([drv.SECRET_DIR / 'b1-creds.env', drv.SECRET_DIR / 'ha-import-creds.env'],
                                   drv.SECRET_DIR / 'dev-d-markers.json')
        ev = Ev(args.secrets, 'litellm-product')
        drv.STATE.clear()
        drv.load_state()
        drv.STATE['created_backups'] = []
        run = Run(args, ev)
        run.lock_started = started
        run.headroom()
        failure = run_all(run)
        failed = [r for r in ev.results if not r['ok']]
        ev.save('results.json', {'passed': len(ev.results) - len(failed), 'failed': len(failed),
                                 'failed_checks': [r['check'] for r in failed], 'results': ev.results,
                                 'source_commit': commit})
        drv.save_state()
        emit(f'litellm full flow x86 enc: {len(ev.results) - len(failed)}/{len(ev.results)} '
             f'{"PASS" if not failed and failure is None else "FAIL"}')
        rc = 0 if not failed and failure is None else 1
    finally:
        try:
            emit(verify_isolation())
        except Failed:
            emit('dev-d isolation after the run: FAIL')
            rc = 1
        emit(f'lock held for {int(time.monotonic() - started)} s')
        os.close(fd)
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
