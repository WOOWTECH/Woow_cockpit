#!/usr/bin/env python3
"""OpenDesign: the real x86 showcase HA backup (encrypted, add-on woow_ha_opendesign 0.2.15) -> dev-e's INSTALLED
OpenDesign (Podman package 4.2.1) through the product's full HA-import flow, exactly the helper commands the Cockpit
page sends (lane opendesign-import, 2026-11-23).

  python3 -I tests/e2e/lab/services_a_capture.py --private=FILE <evidence.json> opendesign-x86 -- \\
      python3 -I tests/e2e/lab/opendesign_full_flow.py --run
  python3 -I tests/e2e/lab/opendesign_full_flow.py --self-check      (offline; never touches a device or a secret)

One run = one hold of /tmp/woowbk-dev-e-mutation.lock (flock, blocking up to an hour), dev-e's outer isolation
(`true none {}`) recorded before and after, the checkout committed (no tracked change). Every engine call is the root
helper the page calls (one JSON request on stdin, one JSON reply; /usr/local/libexec/woowtech-cockpit-backup inside
dev-e), with the engine of THIS tree installed by deploy-src.sh (dev-e's own OpenDesign, catalog entry, secrets and
device key, deployed by lane batch2-lab, are used as they are):

  setup      the schedule timer masked, deploy-src.sh e --src <this tree> --no-demo-catalog, installed engine == tree,
             the open-design catalog entry (four units, the two volumes, the health URL), a device key (key-init)
  before     dev-e's own markers (batch2_markers.py opendesign read: project woowbk-lab-baseline and its file), the
             fingerprints of what must stay (home/, integrations/, paseo/, installation.json of the data volume; the
             whole MCP volume), this device's MCP token answers initialize
  upload     upload-begin, the file copied to the path the helper gave, upload-finish: the record is the fixture
  check      ha-check-start open-design (the HA key on stdin only): no blocker, amd64, add-on 0.2.15, target 0.24.1,
             the section's counts equal the backup's facts (12 projects, 12 conversations, 22 messages, 77 files)
  import     the real free space and the product's floor, ha-convert-start (the convert job's own SpaceGuard and
             Watchdog), inspect (preflight), restore-start (safety backup, in place, health checks)
  verify     the client: GET /api/projects through nginx with Basic auth open-design:<this device's API token> lists
             HA's 12 projects with the HA-side marker project and name, its files' contents through the API have the
             recorded SHA-256, the conversations through the API, unauthenticated and wrong-password requests get
             401; the MCP client (POST /mcp, Bearer = this device's MCP token) initializes and lists tools (SSE
             answers read), a wrong token gets 401; every member of the data volume is owned 0:0 (the daemon's user
             through keep-id); the MCP volume is byte-identical; every kept entry OpenDesign does not rewrite itself
             (RUNTIME_KEPT, measured without an import) is byte-identical, the identity files named; mcp-config.json
             holds only this device's own Paseo entry; the preferences this device keeps are its own
  restart    systemctl --user restart open-design.service: health, the client checks again
  rollback   (a) automatic: a second restore of the converted backup with a one-shot ExecStartPre failure on
             open-design.service must end `rolled-back` and leave HA's imported data; (b) the first restore's safety
             backup restored: dev-e's own markers are back, HA's marker project is gone
  cleanup    drop-in gone, the test's converted and safety backups deleted, the HA store record this run created
             deleted, no job container/volume/network, staging or key file left, the device-side needle file removed
  leaks      the HA backup key, this device's API and MCP tokens and HA's moved third-party credential values
             (collected inside dev-e from the restored volume, never leaving it) are looked for in the engine's
             records, uploads, staging, run dir and the whole device journal: 0 hits

stdout carries only fixed lines (`<check>: PASS|FAIL`, the isolation line, the source commit, lock time); details go
to the private, redacted evidence folder ~/.woowbk-lab/evidence/opendesign-odff/<time>/ (0700).
Not covered (stated): the browser page itself (dev-e publishes no port; the helper calls are the page's), a provider
login in the agents (O1 keeps this device's), Omnigent/Paseo pairing (O2 keeps this device's), HA's MCP token (never
imported; not read from the backup), a host reboot.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
DEVICE = 'woowbk-dev-e'
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
HOLD_BUDGET = 40 * 60
MIN_HOST_AVAILABLE_KIB = 1024 * 1024
MIN_DEVICE_HEADROOM = 1024 * 1024 * 1024   # the jobs, the SQLite child and the daemon's growth above idle
OD_IDLE = 1280 * 1024 * 1024              # OpenDesign's four containers when started (idle ~0.8 GiB, facts 2.4)
FLOOR = 12 * 1024 ** 3          # the team keeps >= 12 GiB free on the host at every moment
MARGIN = 256 * 1024 ** 2
# What each step may still write on the host disk (dev-e's volumes live there): checked before the step, so the floor
# holds at every moment (attempt 1 refused with one static 3 GiB estimate at 14.15 GiB free).
NEEDS = {'upload': None, 'check': 64 * 1024 ** 2, 'convert': 512 * 1024 ** 2, 'restore': 256 * 1024 ** 2}
FIXTURE = (LAB / 'ha-fixtures' / '20261123-batch2' / 'x86' / 'woow-b2-opendesign-x86-enc'
           / 'woow-b2-opendesign-x86-enc-20261123.tar')
FIXTURE_SHA = 'c3d23cedc831d14a221f9be6063c23913fb896f39e882127a52aac7039178dd7'
# Facts of the backup (showcase-backups-2 evidence f884a0a; the importer's own scan of this file, dev check 16:59)
# mcp-config.json holds one server, HA's own Paseo entry `woow-paseo` (stdio; HA's paths): not moved (O2), so 0 servers
# move and 1 integration entry stays on HA (kinds of its values checked in a network-none container, 17:31).
SOURCE = {'version': '0.2.15', 'arch': 'amd64', 'target_version': '0.24.1', 'projects': 12, 'conversations': 12,
          'messages': 22, 'files': 77, 'mcp_servers': 0, 'mcp_integration_entries': 1, 'routines': 0}
MARKER_PROJECT = 'woow-import-test-20261123'
MARKER_NAME = 'WOOW匯入測試 20261123'
MARKER_FILES = {'woow-import-test.txt': '540d9ac26237dbb1', 'woow-import-cjk.txt': 'f2e0dc84bf608ae9'}
BASE_PROJECT = 'woowbk-lab-baseline'
TIMER = 'woowtech-cockpit-backup-schedule.timer'
UNITS = ('open-design.service', 'open-design-mcp.service', 'open-design-nginx.service', 'open-design-terminal.service')
DATA_VOL, MCP_VOL = 'open-design_open_design_data', 'open-design_mcp_data'
KEPT = ('home', 'integrations', 'paseo', 'installation.json')
DROPIN_DIR_REL = '.config/systemd/user/open-design.service.d'
DROPIN_REL = DROPIN_DIR_REL + '/zz-odff-fail-once.conf'
MARKER_REL = '.odff-fail-once'
NEEDLES = '/var/lib/woowbk-odff/needles.json'     # root 0600 inside dev-e (network none); removed at the end
# Kept entries OpenDesign rewrites ITSELF: measured on dev-e 2026-11-23 17:4x with no import at all (60 s idle, then a
# plain `systemctl --user restart open-design.service`): codex's temporary launchers, opencode's locks, log and database,
# Paseo's runtime state, pid, log, locks and its per-start local credential. Every other kept entry (the agents' logins
# such as home/.pi/agent/auth.json, Omnigent's integrations/omnigent/state.json, Paseo's identity daemon-keypair.json,
# server-id, cli-client-id, host-registration.json, ...) must be byte-identical before and after the import.
RUNTIME_KEPT = re.compile(r'(?:home/\.codex/tmp|home/\.local/state/opencode/locks|home/\.local/share/opencode/log)(?:/.*)?'
                          r'|home/\.local/share/opencode/opencode\.db(?:-shm|-wal)?'
                          r'|paseo/(?:bridge\.json|state\.json|supervisor\.json|host-mcp\.json|runtime\.lock'
                          r'|bridge-lifecycle\.lock(?:/.*)?|daemon/(?:daemon\.log|paseo\.pid|local-credential))')
IDENTITY = re.compile(r'.*(?:auth\.json|\.credentials\.json|keypair\.json|server-id|cli-client-id|host-registration\.json'
                      r'|pairing[^/]*|integrations/omnigent/state\.json|\.claude\.json)')
SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ,()/:'<>.=_-]")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drv = _load('ha_import_b1_e2e')
drv.DEVICE = DEVICE                       # every helper/owner/root call of the b1 driver goes to dev-e
drv.state_path = lambda: LAB / 'run' / 'opendesign_full_flow.json'
Failed = drv.Failed


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


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------- device-side programs (python3 -I -c, stdin JSON)

COMMON = r'''
import base64, hashlib, json, os, subprocess, sys, time, urllib.error, urllib.request
REQ = json.loads(sys.stdin.read() or "{}")
OD = "http://127.0.0.1:7456"
def run(argv, timeout=300):
    p = subprocess.run(argv, capture_output=True, timeout=timeout)
    if p.returncode:
        raise SystemExit("command failed: %s rc=%d" % (argv[0:3], p.returncode))
    return p.stdout
def http(method, path, *, basic=None, bearer=None, body=None, headers=None, retry=0):
    deadline = time.monotonic() + retry
    while True:
        req = urllib.request.Request(OD + path, data=body, method=method)
        if basic is not None:
            req.add_header("Authorization", "Basic " + base64.b64encode(basic.encode()).decode())
        if bearer is not None:
            req.add_header("Authorization", "Bearer " + bearer)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            if e.code in (502, 503) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return e.code, e.read(), dict(e.headers)
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            if time.monotonic() >= deadline:
                return 0, b"", {}
            time.sleep(3)
def api_token():
    return run(["podman", "secret", "inspect", "--showsecret", "--format", "{{.SecretData}}",
                "open-design-api-token"]).decode().strip()
def mountpoint(volume):
    return run(["podman", "volume", "inspect", "--format", "{{.Mountpoint}}", volume]).decode().strip()
WALK = """
import hashlib, json, os, stat, sys
root, parts = sys.argv[1], sys.argv[2:]
rows, nonroot, total, missing, entries = [], 0, 0, [], {}
def one(path, rel):
    global nonroot, total
    st = os.lstat(path)
    total += 1
    if st.st_uid != 0 or st.st_gid != 0:
        nonroot += 1
    if stat.S_ISREG(st.st_mode):
        h = hashlib.sha256(open(path, "rb").read()).hexdigest()
        rows.append("f %s %o %s" % (rel, st.st_mode & 0o7777, h))
        entries[rel] = "f %o %d %s" % (st.st_mode & 0o7777, st.st_size, h[:8])
    elif stat.S_ISLNK(st.st_mode):
        rows.append("l %s %s" % (rel, os.readlink(path)))
        entries[rel] = "l " + hashlib.sha256(os.readlink(path).encode()).hexdigest()[:8]
    else:
        rows.append("d %s %o" % (rel, st.st_mode & 0o7777))
        entries[rel] = "d %o" % (st.st_mode & 0o7777)
for part in parts or ["."]:
    top = os.path.join(root, part)
    if not os.path.lexists(top):
        missing.append(part)
        continue
    one(top, part)
    if os.path.isdir(top) and not os.path.islink(top):
        for d, dirs, files in os.walk(top, followlinks=False):
            for n in sorted(dirs) + sorted(files):
                p = os.path.join(d, n)
                one(p, os.path.relpath(p, root))
rows.sort()
print(json.dumps({"entries": total, "nonroot": nonroot, "missing": missing,
                  "fingerprint": hashlib.sha256("\\n".join(rows).encode()).hexdigest()[:16],
                  "map": entries if len(entries) <= 5000 else None}))
"""
def walk(volume, parts):
    return json.loads(run(["podman", "unshare", "python3", "-I", "-c", WALK, mountpoint(volume), *parts], timeout=600))
def target_prefs():
    # sha256 prefixes of the preferences this device keeps (installationId, agentCliEnv, agentCliEnvIntent): equal
    # before and after the import, whatever HA's were (never a value)
    p = subprocess.run(["podman", "unshare", "cat", os.path.join(mountpoint("open-design_open_design_data"),
                                                                 "app-config.json")], capture_output=True, timeout=120)
    if p.returncode != 0:
        return {}
    doc = json.loads(p.stdout)
    return {k: hashlib.sha256(json.dumps(doc[k], sort_keys=True).encode()).hexdigest()[:12]
            for k in ("installationId", "agentCliEnv", "agentCliEnvIntent") if k in doc}
def mcp_entries():
    # {server id: sha256 prefix of the entry} of the daemon's mcp-config.json (ids are names, never values)
    p = subprocess.run(["podman", "unshare", "cat", os.path.join(mountpoint("open-design_open_design_data"),
                                                                 "mcp-config.json")], capture_output=True, timeout=120)
    if p.returncode != 0:
        return {}
    try:
        servers = json.loads(p.stdout).get("servers") or []
    except (ValueError, AttributeError):
        return {"unreadable": ""}
    return {str(e.get("id"))[:64]: hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()[:12]
            for e in servers if isinstance(e, dict)}
def mcp_token():
    data = run(["podman", "unshare", "cat", os.path.join(mountpoint("open-design_mcp_data"), "state", "state.json")])
    return json.loads(data).get("token")
def mcp(token, method, params, session=None, ident=1):
    # A notification carries no id. The child answers requests as an SSE stream (the gateway relays it; only the
    # initialize answer is turned into JSON for a JSON-only client), so `rpc` reads both.
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if session:
        headers["Mcp-Session-Id"] = session
    message = {"jsonrpc": "2.0", "method": method, "params": params}
    if ident is not None:
        message["id"] = ident
    return http("POST", "/mcp", bearer=token, body=json.dumps(message).encode(), headers=headers)
def rpc(body):
    """The JSON-RPC answer of a reply body: plain JSON, or the last `data:` event of an SSE stream; None."""
    try:
        return json.loads(body)
    except ValueError:
        pass
    data = [line[5:].strip() for line in body.decode("utf-8", "replace").splitlines() if line.startswith("data:")]
    for item in reversed(data):
        try:
            return json.loads(item)
        except ValueError:
            continue
    return None
'''

# The client checks of the restored OpenDesign (as appowner; prints one JSON line of facts, never a value).
CLIENT = COMMON + r'''
out = {}
health = http("GET", "/api/health", retry=300)[0]
out["health"] = health
token = api_token()
auth = "open-design:" + token
status, body, _h = http("GET", "/api/version", basic=auth)
out["version_status"] = status
try:
    doc = json.loads(body)
    info = doc.get("version") if isinstance(doc, dict) else None     # {version: {version, channel, ...}}
    out["version"] = info.get("version") if isinstance(info, dict) else info
except ValueError:
    out["version"] = None
status, body, _h = http("GET", "/api/projects", basic=auth)
out["projects_status"] = status
items = []
try:
    doc = json.loads(body)
    items = doc.get("projects", doc) if isinstance(doc, dict) else doc
except ValueError:
    pass
projects = {p["id"]: p.get("name") for p in items or [] if isinstance(p, dict) and isinstance(p.get("id"), str)}
out["projects"] = len(projects)
out["lab_projects"] = sorted(i for i in projects if i.startswith("woowbk-lab-"))
marker = REQ["marker"]
out["marker_present"] = marker in projects
out["marker_name_ok"] = projects.get(marker) == REQ["marker_name"]
conversations = 0
for pid in sorted(projects):
    status, body, _h = http("GET", "/api/projects/%s/conversations" % pid, basic=auth)
    if status == 200:
        try:
            doc = json.loads(body)
            rows = doc.get("conversations", doc) if isinstance(doc, dict) else doc
            conversations += len(rows) if isinstance(rows, list) else 0
        except ValueError:
            pass
out["conversations"] = conversations
files = {}
if marker in projects:
    status, body, _h = http("GET", "/api/projects/%s/files" % marker, basic=auth)
    out["files_status"] = status
    try:
        doc = json.loads(body)
        rows = doc.get("files", doc) if isinstance(doc, dict) else doc
        names = sorted(f.get("name") for f in rows or [] if isinstance(f, dict) and isinstance(f.get("name"), str))
    except ValueError:
        names = []
    out["marker_files"] = names
    for name in REQ["files"]:
        status, body, _h = http("GET", "/api/projects/%s/raw/%s" % (marker, name), basic=auth)
        files[name] = hashlib.sha256(body).hexdigest()[:16] if status == 200 else "HTTP %d" % status
out["file_sha16"] = files
out["anonymous"] = http("GET", "/api/projects")[0]
out["wrong_password"] = http("GET", "/api/projects", basic="open-design:wrong-" + "x" * 24)[0]
token_mcp = mcp_token()
status, body, headers = mcp(token_mcp, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                       "clientInfo": {"name": "woowbk-odff", "version": "1"}})
out["mcp_initialize"] = status
doc = rpc(body)
out["mcp_server"] = ((doc.get("result") or {}).get("serverInfo") or {}).get("name") if isinstance(doc, dict) else None
session = {k.lower(): v for k, v in headers.items()}.get("mcp-session-id")
if session:
    mcp(token_mcp, "notifications/initialized", {}, session=session, ident=None)
status, body, _h = mcp(token_mcp, "tools/list", {}, session=session, ident=2)
out["mcp_tools_status"] = status
out["mcp_session"] = bool(session)
doc = rpc(body)
tools = (doc.get("result") or {}).get("tools") if isinstance(doc, dict) else None
out["mcp_tools"] = len(tools) if isinstance(tools, list) else None
error = doc.get("error") if isinstance(doc, dict) else None
out["mcp_tools_error"] = [error.get("code"), str(error.get("message"))[:120]] if isinstance(error, dict) else (
    None if doc is not None else "unreadable")
out["mcp_wrong_token"] = mcp("wrong-" + "y" * 30, "initialize", {})[0]
data = walk("open-design_open_design_data", [])
out["data_entries"], out["data_nonroot"] = data["entries"], data["nonroot"]
kept = walk("open-design_open_design_data", REQ["kept"])
out["kept_fingerprint"], out["kept_missing"], out["kept_map"] = kept["fingerprint"], kept["missing"], kept["map"]
out["mcp_fingerprint"] = walk("open-design_mcp_data", [])["fingerprint"]
out["target_prefs"] = target_prefs()
out["mcp_entries"] = mcp_entries()
print(json.dumps(out))
'''

# The state of dev-e's OpenDesign before the import (fingerprints and MCP; as appowner).
BEFORE = COMMON + r'''
out = {"health": http("GET", "/api/health", retry=300)[0]}
kept = walk("open-design_open_design_data", REQ["kept"])
out["kept_fingerprint"], out["kept_missing"], out["kept_map"] = kept["fingerprint"], kept["missing"], kept["map"]
out["mcp_fingerprint"] = walk("open-design_mcp_data", [])["fingerprint"]
status, body, _h = mcp(mcp_token(), "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                    "clientInfo": {"name": "woowbk-odff", "version": "1"}})
out["mcp_initialize"] = status
out["target_prefs"] = target_prefs()
out["mcp_entries"] = mcp_entries()
print(json.dumps(out))
'''

# HA's moved third-party credential values (string values of at least 12 characters of the moved JSON settings),
# collected inside dev-e from the restored volume into a root 0600 file for the leak scan; prints only a count.
COLLECT = r'''
import json, os, subprocess, sys
req = json.loads(sys.stdin.read())
def owner(*argv):
    return subprocess.run(["runuser", "-u", "appowner", "--", "env", "-i", "PATH=/usr/bin:/bin", "HOME=/home/appowner",
                           "XDG_RUNTIME_DIR=/run/user/%d" % req["uid"], *argv], capture_output=True, timeout=120)
mp = owner("podman", "volume", "inspect", "--format", "{{.Mountpoint}}", "open-design_open_design_data").stdout.decode().strip()
values = set()
import re
def strings(value):
    # credentials only: a path (`/...`) or a URL without userinfo, query or fragment is no secret (attempt 2 counted
    # the moved HOME=/app/.od/home of HA's Paseo MCP entry in the journal: 9 false hits)
    if isinstance(value, str):
        if len(value) >= 12 and not value.startswith("/") and not re.fullmatch(r"https?://[^@?#\s]*", value):
            values.add(value)
    elif isinstance(value, list):
        for item in value:
            strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            strings(item)
names = ["mcp-tokens.json", "mcp-oauth-clients.json", "media-config.json"]
ls = owner("podman", "unshare", "ls", "-1", os.path.join(mp, "connectors"))
names += ["connectors/" + n for n in ls.stdout.decode().split() if n.endswith(".json") and n != "composio-catalog-cache.json"]
for name in names:
    p = owner("podman", "unshare", "cat", os.path.join(mp, name))
    if p.returncode == 0:
        try:
            strings(json.loads(p.stdout))
        except ValueError:
            pass
p = owner("podman", "unshare", "cat", os.path.join(mp, "mcp-config.json"))
if p.returncode == 0:
    try:
        for server in json.loads(p.stdout).get("servers") or []:
            for key in ("env", "headers"):
                strings((server or {}).get(key))
    except (ValueError, AttributeError):
        pass
os.makedirs(os.path.dirname(req["path"]), mode=0o700, exist_ok=True)
fd = os.open(req["path"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as handle:
    json.dump(sorted(values), handle)
print(json.dumps({"values": len(values)}))
'''

LEAKS = 'import json\n' + __import__('inspect').getsource(drv.secret_scan_needles) + r'''
import os, subprocess, sys
req = json.loads(sys.stdin.read())
secrets = {name: value.encode() for name, value in req["secrets"].items() if value}
def owner(*argv):
    return subprocess.run(["runuser", "-u", "appowner", "--", "env", "-i", "PATH=/usr/bin:/bin", "HOME=/home/appowner",
                           "XDG_RUNTIME_DIR=/run/user/%d" % req["uid"], *argv], capture_output=True, timeout=120)
p = owner("podman", "secret", "inspect", "--showsecret", "--format", "{{.SecretData}}", "open-design-api-token")
if p.returncode != 0 or len(p.stdout.strip()) < 8:
    raise RuntimeError("cannot inspect the device's API token")
secrets["device:api-token"] = p.stdout.strip()
mp = owner("podman", "volume", "inspect", "--format", "{{.Mountpoint}}", "open-design_mcp_data").stdout.decode().strip()
p = owner("podman", "unshare", "cat", os.path.join(mp, "state", "state.json"))
token = json.loads(p.stdout).get("token") if p.returncode == 0 else None
if not token or len(token) < 8:
    raise RuntimeError("cannot read the device's MCP token")
secrets["device:mcp-token"] = token.encode()
moved = json.load(open(req["needles"])) if os.path.exists(req["needles"]) else None
if moved is None:
    raise RuntimeError("the moved-credential needle file is missing")
for i, value in enumerate(moved):
    secrets["moved:%d" % i] = value.encode()
needles = secret_scan_needles(secrets.values())
hits, scanned = 0, 0
roots = ["/var/lib/woowtech-backup/jobs", "/var/lib/woowtech-backup/ha-backups", "/var/lib/woowtech-backup/ha-imports.json",
         "/var/lib/woowtech-backup/archives", "/run/woowtech-backup", "/var/lib/woowtech-backup/uploads",
         "/var/lib/woowtech-backup/staging", "/var/lib/woowtech-backup/pending", "/var/lib/woowtech-backup/exports"]
for root in roots:
    if not os.path.exists(root):
        continue
    if os.path.islink(root):
        raise RuntimeError("unsafe scan root")
    paths = [root] if os.path.isfile(root) else []
    for d, dirs, files in os.walk(root, followlinks=False):
        paths.extend(os.path.join(d, f) for f in files)
    for path in paths:
        if path.endswith(".tar") and ("/ha-backups/" in path or "/archives/" in path):
            continue  # the uploaded HA file itself and the (encrypted) backups
        if os.path.islink(path):
            raise RuntimeError("unsafe scan path")
        data = open(path, "rb").read()
        scanned += 1
        hits += sum(data.count(s) for s in needles)
journal = subprocess.run(["journalctl", "-o", "cat", "--no-pager"], capture_output=True, check=True).stdout
hits += sum(journal.count(s) for s in needles)
print(json.dumps({"scanned": scanned, "journal_bytes": len(journal), "names": len(secrets), "moved_values": len(moved),
                  "hits": hits}))
'''

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
    if os.path.isdir(f):
        s = os.statvfs(f)
        free[f] = s.f_bavail * s.f_frsize
print(json.dumps({"running_reserve": int(reserve), "watch_margin": int(haimport.WATCH_MARGIN),
                  "floor": int(reserve + haimport.WATCH_MARGIN), "free": free, "min_free": min(free.values())}))
'''


# ---------------------------------------------------------------- device helpers

def owner_ok(*argv, timeout=600):
    proc = drv.owner(*argv, timeout=timeout)
    if proc.returncode != 0:
        raise Failed(f'{argv[:3]} failed (rc {proc.returncode})')
    return drv.out(proc)


def owner_exists(rel):
    return drv.owner('test', '-e', f'/home/appowner/{rel}', timeout=60).returncode == 0


def write_owner_file(rel, data, mode='0644'):
    proc = drv.owner('sh', '-c', 'umask 077; cat > "$1" && chmod "$2" "$1"', 'sh', f'/home/appowner/{rel}', mode,
                     input=data, timeout=60)
    if proc.returncode != 0:
        raise Failed(f'cannot write ~/{rel}')


def unit_state(unit):
    return drv.out(drv.owner('systemctl', '--user', 'is-active', unit, timeout=60)).strip()


def wait_units(ev, label_text, timeout=420):
    deadline = time.monotonic() + timeout
    states = {}
    while time.monotonic() < deadline:
        states = {u: unit_state(u) for u in UNITS}
        if all(s == 'active' for s in states.values()):
            break
        time.sleep(5)
    ev.check(f'{label_text}: the four OpenDesign units are active', all(s == 'active' for s in states.values()), states)


def kept_compare(before, after):
    """(differences outside RUNTIME_KEPT, entries compared, identity files compared, runtime entries that differ)."""
    before, after = before or {}, after or {}
    stable = lambda m: {k: v for k, v in m.items() if not RUNTIME_KEPT.fullmatch(k)}
    b, a = stable(before), stable(after)
    differ = sorted(set(b) ^ set(a) | {k for k in set(b) & set(a) if b[k] != a[k]})
    runtime = sorted(k for k in set(before) | set(after) if RUNTIME_KEPT.fullmatch(k)
                     and before.get(k) != after.get(k))
    identity = sorted(k for k in b if IDENTITY.fullmatch(k) and not b[k].startswith('d '))
    return differ, len(b), identity, runtime


def device_uid():
    return int(drv.out(drv.root('id', '-u', 'appowner', check=True)).strip())


def isolation():
    proc = subprocess.run([drv.LP, 'inspect', DEVICE, '--format',
                           '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'],
                          capture_output=True, timeout=60)
    return proc.stdout.decode().strip()


def clean_tree():
    proc = subprocess.run(['git', '-C', str(REPO), 'status', '--porcelain', '--untracked-files=no'],
                          capture_output=True, timeout=60, check=True)
    return not proc.stdout.strip()


# ---------------------------------------------------------------- the run

class Run:
    def __init__(self, args, ev):
        self.args, self.ev = args, ev
        self.lock_started = time.monotonic()
        self.created_store = self.store_id = self.converted = self.safety = None
        self.dropin = False
        self.needles = False
        self.before = {}
        self.uid = None
        self.found_units = {}
        self.timer_found = None

    def budget(self, phase):
        if time.monotonic() - self.lock_started > HOLD_BUDGET:
            raise Failed(f'lock hold budget reached before {phase}')

    def device_memory(self):
        """(memory that cannot be reclaimed: anon + kernel, the cgroup limit) of dev-e; its page cache is reclaimable."""
        proc = drv.root('sh', '-c', 'grep -E "^(anon|kernel) " /sys/fs/cgroup/memory.stat; cat /sys/fs/cgroup/memory.max',
                        timeout=60)
        try:
            lines = drv.out(proc).split('\n')
            used = sum(int(line.split()[1]) for line in lines if line.startswith(('anon ', 'kernel ')))
            maximum = int(next(line for line in lines if line.strip().isdigit()))
        except (ValueError, StopIteration, IndexError):
            raise Failed('cannot read dev-e cgroup memory') from None
        return used, maximum

    def headroom(self):
        used, maximum = self.device_memory()
        need = MIN_DEVICE_HEADROOM + (OD_IDLE if any(s != 'active' for s in self.found_units.values()) else 0)
        ok = maximum - used >= need
        self.ev.check('preflight: dev-e memory headroom for OpenDesign and the jobs (before any change)', ok,
                      {'unreclaimable_mib': used >> 20, 'limit_mib': maximum >> 20, 'need_mib': need >> 20,
                       'units': self.found_units})
        if not ok:
            raise Failed('dev-e memory headroom too small')
        available = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                         if line.startswith('MemAvailable:'))
        if not self.ev.check('preflight: host MemAvailable >= 1 GiB', available >= MIN_HOST_AVAILABLE_KIB,
                             {'mem_available_kib': available}):
            raise Failed('host memory')
        self.space('preflight', 'upload')

    def space(self, label_text, step):
        """The host keeps FLOOR free after what `step` may write (the upload: the HA file plus a margin)."""
        st = os.statvfs('/')
        free = st.f_bavail * st.f_frsize
        need = (FIXTURE.stat().st_size if NEEDS[step] is None else NEEDS[step]) + MARGIN
        ok = free - need >= FLOOR
        self.ev.check(f'{label_text}: host disk keeps the 12 GiB floor after the {step} step\'s writes', ok,
                      {'free_gib': round(free / 1024 ** 3, 2), 'need_mib': need >> 20})
        if not ok:
            raise Failed(f'host disk before {step}')

    # -------- setup
    def setup(self):
        ev = self.ev
        state = isolation()
        emit(f'dev-e isolation: {state}')
        if not ev.check('preflight: dev-e runs with network none and no published port', state == 'true none {}', state):
            raise Failed('dev-e isolation')
        if not ev.check('preflight: the checkout has no tracked change (the source commit describes the code)',
                        clean_tree()):
            raise Failed('dirty tree')
        sha = sha256_file(FIXTURE)
        if not ev.check('preflight: the local file is the recorded showcase OpenDesign backup (sha256)', sha == FIXTURE_SHA,
                        sha[:16]):
            raise Failed('fixture changed')
        self.found_units = {u: unit_state(u) for u in UNITS}
        self.headroom()
        self.uid = device_uid()
        if any(state != 'active' for state in self.found_units.values()):
            proc = drv.owner('systemctl', '--user', 'start', 'open-design.service', timeout=900)
            ev.check('setup: dev-e\'s OpenDesign was stopped (lane batch2-lab saves RAM); started for the run', proc.returncode == 0,
                     self.found_units)
            wait_units(ev, 'setup start')
        self.timer_found = drv.out(drv.root('systemctl', 'is-enabled', TIMER, timeout=60)).strip()
        proc = drv.root('systemctl', 'mask', TIMER, timeout=120)
        ev.check('setup: the scheduled-backup timer is masked (shared lab, no schedule)', proc.returncode == 0,
                 self.timer_found)
        proc = drv.run(['bash', str(HERE / 'deploy-src.sh'), 'e', '--src', str(REPO), '--no-demo-catalog'], timeout=1800)
        ev.save('deploy.log', drv.out(proc)[-20000:] + proc.stderr.decode('utf-8', 'replace')[-5000:])
        if not ev.check('setup: deploy-src.sh e --src <this tree> --no-demo-catalog', proc.returncode == 0,
                        f'rc {proc.returncode}'):
            raise Failed('deploy failed')
        installed = drv.device_python(ENGINE_HASHES, {}, as_owner=False, timeout=300)
        base = REPO / 'backup-engine' / 'woowbackup'
        tree = {str(p.relative_to(base)): sha256_file(p) for p in base.rglob('*.py') if '__pycache__' not in p.parts}
        lib = installed.get('lib') or {}
        differ = sorted(k for k in set(tree) | set(lib) if tree.get(k) != lib.get(k))
        ev.check('setup: the installed engine is this tree (every module and the helper SHA-256 equal)',
                 not differ and installed.get('helper') == sha256_file(REPO / 'backup-engine' / 'woowtech-cockpit-backup'),
                 {'modules': len(tree), 'differ': differ[:10]})
        status = drv.ok('status', ev=ev)
        ev.check('setup: the helper answers status with this tree\'s VERSION',
                 status.get('version') == (REPO / 'VERSION').read_text().strip(), status.get('version'))
        entry = drv.catalog('open-design')
        ev.save('catalog-open-design.json', entry)
        if not ev.check('setup: the open-design catalog entry names the four units, both volumes and the health URL',
                        set(UNITS) <= set(entry.get('units') or []) and sorted(v['name'] for v in entry.get('volumes') or [])
                        == sorted((DATA_VOL, MCP_VOL)) and not entry.get('postgres') and len(entry.get('health') or []) >= 1,
                        {'units': entry.get('units'), 'volumes': [v['name'] for v in entry.get('volumes') or []]}):
            raise Failed('catalog entry')
        key = drv.ok('key-init', ev=ev)
        ev.check('setup: a device key exists (key-init)', bool((key.get('key') or {}).get('key_id')),
                 {'created': key.get('created')})
        wait_units(ev, 'setup')

    # -------- before
    def markers(self):
        script = (HERE / 'batch2_markers.py').read_text(encoding='utf-8')
        proc = drv.owner('python3', '-I', '-c', script, 'opendesign', 'read', input=b'{}', timeout=600)
        try:
            return json.loads(drv.out(proc).strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise Failed(f'batch2_markers.py opendesign read failed (rc {proc.returncode})') from None

    def step_before(self):
        ev = self.ev
        found = self.markers()
        ev.save('markers-before.json', found)
        ev.check('before: dev-e\'s own marker project woowbk-lab-baseline and its file (batch2_markers.py read)',
                 BASE_PROJECT in (found.get('projects') or []) and any(f.startswith('woowbk-lab-baseline.txt:')
                                                                       for f in found.get('files') or []),
                 found.get('projects'))
        state = drv.device_python(BEFORE, {'kept': list(KEPT)}, timeout=900)
        self.before = state
        ev.save('state-before.json', state)
        ev.check('before: dev-e\'s OpenDesign is healthy and its MCP token answers initialize',
                 state.get('health') == 200 and state.get('mcp_initialize') == 200,
                 {k: state.get(k) for k in ('health', 'mcp_initialize', 'kept_missing')})
        self.base_marker = found

    # -------- upload and check
    def step_upload(self):
        ev = self.ev
        self.space('upload', 'upload')
        store_id = 'ha-' + FIXTURE_SHA[:20]
        listed = {h.get('id') for h in drv.ok('list', ev=ev).get('ha_backups') or []}
        started = time.monotonic()
        rc, reply = drv.upload(FIXTURE, ev=ev)
        meta = reply.get('ha_backup') or {}
        ev.save('upload-reply.json', reply)
        ok = rc == 0 and meta.get('id') == store_id
        ev.check('upload: upload-begin, copy, upload-finish answer the HA store record (id from the SHA-256)', ok,
                 {'took_s': round(time.monotonic() - started, 1), 'existed_before': store_id in listed})
        found = {a['app_id']: a['installed'] for a in meta.get('importable_apps') or []}
        ev.check('upload: open-design is importable and installed here', found.get('open-design') is True, found)
        if store_id not in listed:
            self.created_store = store_id
        self.store_id = store_id
        if not ok:
            raise Failed('upload refused')

    def step_check(self):
        ev = self.ev
        self.space('check', 'check')
        job, took = drv.run_check(self.store_id, ['open-design'], ev=ev, key=self.args.secrets['HA_BACKUP_KEY'],
                                  tag='check-od-x86')
        if not ev.check('check: ha-check-start job succeeded', job['state'] == 'succeeded',
                        f'{took:.0f} s {job.get("error")}'):
            raise Failed('check job failed')
        result = job['result']['ha_check']['apps'][0]
        ev.save('check-result.json', result)
        section = result.get('open-design') or {}
        ev.check('check: ok, no blockers', result.get('ok') is True and not result.get('blockers'), result.get('blockers'))
        ev.check('check: source amd64, add-on 0.2.15, this device\'s OpenDesign 0.24.1, same core revision',
                 result.get('arch') == SOURCE['arch'] and result.get('version') == SOURCE['version']
                 and result.get('target_version') == SOURCE['target_version']
                 and section.get('source_revision') == section.get('target_revision') == '05b23f5a',
                 {k: result.get(k) for k in ('arch', 'version', 'target_version')})
        counts = {k: section.get(k) for k in ('projects', 'conversations', 'messages', 'files', 'mcp_servers',
                                              'mcp_integration_entries', 'routines')}
        ev.check('check: the section counts equal the backup\'s facts (projects, conversations, messages, files)',
                 counts == {k: SOURCE[k] for k in counts}, counts)
        ev.check('check: home, paseo, integrations and installation.json stay on HA (left out)',
                 {'home', 'paseo', 'integrations', 'installation.json'} <= set(section.get('left_out') or {}),
                 section.get('left_out'))
        leftovers = drv.labelled()
        ev.check('check: no throwaway container, volume or network left', not any(leftovers.values()), leftovers)

    # -------- import
    def step_import(self):
        ev = self.ev
        space = drv.device_python(SPACE, {}, as_owner=False, timeout=120)
        ev.save('space-before-convert.json', space)
        ev.check('import: real space above the product\'s floor (running reserve + watch margin) the convert job enforces',
                 isinstance(space.get('floor'), int) and space['min_free'] > space['floor'],
                 {k: space.get(k) for k in ('running_reserve', 'watch_margin', 'floor', 'min_free')})
        before_ids = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        self.space('import', 'convert')
        job, took = drv.convert(self.store_id, ['open-design'], False, ev=ev, key=self.args.secrets['HA_BACKUP_KEY'],
                                tag='convert-od-x86')
        ev.save('convert-job.json', job)
        if not ev.check('import: ha-convert-start job succeeded with a backup id', job['state'] == 'succeeded'
                        and (job.get('result') or {}).get('backup_id'), f'{took:.0f} s {job.get("error")}'):
            raise Failed('convert failed')
        result = job['result']
        self.converted = result['backup_id']
        drv.created_backup(self.converted)
        imp = result.get('ha_import') or {}
        reminders = (imp.get('reminders_by_app') or {}).get('open-design') or []
        ev.check('import: ha_import names open-design, the OpenDesign note and its reminders (login, agents, MCP)',
                 imp.get('apps') == ['open-design'] and imp.get('test_mode') is False
                 and any(n.startswith('OpenDesign') for n in imp.get('notes') or [])
                 and any('open-design' in r for r in reminders) and any('MCP' in r for r in reminders),
                 {'notes': len(imp.get('notes') or []), 'reminders': len(reminders)})
        row = next((b for b in drv.ok('list', ev=ev)['backups'] if b['id'] == self.converted), {})
        ev.check('import: the converted backup is listed as manual with its HA origin, encrypted',
                 self.converted not in before_ids and row.get('type') == 'manual'
                 and (row.get('from_ha') or {}).get('ha_backup_id') == self.store_id and bool(row.get('key_id')),
                 {'type': row.get('type'), 'from_ha': bool(row.get('from_ha')), 'size': row.get('size')})
        inspect = drv.ok('inspect', {'backup_id': self.converted}, ev=ev, timeout=900)
        pre = inspect.get('preflight') or {}
        failed = [c for c in pre.get('checks') or [] if c.get('status') == 'fail']
        ev.check('import: inspect: preflight passes, settings same, in place',
                 pre.get('ok') and not failed and all((a.get('settings') or {}).get('state') == 'same'
                                                      and a.get('mode') == 'inplace' for a in pre.get('apps') or []),
                 failed[:3] or [(a.get('id'), a.get('mode'), (a.get('settings') or {}).get('state'))
                                for a in pre.get('apps') or []])
        self.space('import', 'restore')
        rjob, rtook = drv.restore(self.converted, ['open-design'], ev=ev, tag='restore-od-x86')
        ev.save('restore-job.json', rjob)
        rresult = rjob.get('result') or {}
        self.safety = rresult.get('safety_backup_id')
        drv.created_backup(self.safety)
        health = rresult.get('health') or []
        if not ev.check('import: restore-start of the converted backup succeeded with a safety backup, not rolled back, '
                        'every health check ok', rjob['state'] == 'succeeded' and self.safety
                        and rresult.get('rolled_back') is False and health
                        and all(h.get('status') == 'ok' for h in health),
                        {'state': rjob['state'], 'error': rjob.get('error'), 'took_s': round(rtook, 1),
                         'downtime_s': rresult.get('downtime_seconds')}):
            raise Failed('restore failed')
        drv.save_state()

    # -------- verification (the client)
    def verify(self, label_text, *, imported=True):
        ev = self.ev
        wait_units(ev, label_text)
        state = drv.device_python(CLIENT, {'marker': MARKER_PROJECT, 'marker_name': MARKER_NAME,
                                           'files': sorted(MARKER_FILES), 'kept': list(KEPT)}, timeout=1200)
        ev.save(f'client-{label(label_text).replace(" ", "-")}.json', state)
        ev.check(f'{label_text}: health 200, /api/version {SOURCE["target_version"]} (Basic auth with this device\'s token)',
                 state.get('health') == 200 and state.get('version_status') == 200
                 and state.get('version') == SOURCE['target_version'],
                 {k: state.get(k) for k in ('health', 'version_status', 'version')})
        ev.check(f'{label_text}: unauthenticated and wrong-password API requests get 401',
                 state.get('anonymous') == 401 and state.get('wrong_password') == 401,
                 {k: state.get(k) for k in ('anonymous', 'wrong_password')})
        ev.check(f'{label_text}: the MCP client with this device\'s token initializes and lists tools; a wrong token gets '
                 '401', state.get('mcp_initialize') == 200 and state.get('mcp_tools_status') == 200
                 and (state.get('mcp_tools') or 0) > 0 and state.get('mcp_wrong_token') == 401,
                 {k: state.get(k) for k in ('mcp_initialize', 'mcp_server', 'mcp_tools_status', 'mcp_tools',
                                            'mcp_wrong_token')})
        differ, compared, identity, runtime = kept_compare(self.before.get('kept_map'), state.get('kept_map'))
        ev.check(f'{label_text}: the MCP volume is byte-identical and every kept entry OpenDesign does not rewrite itself '
                 '(agent logins, Omnigent, Paseo identity) is this device\'s, unchanged',
                 state.get('mcp_fingerprint') == self.before.get('mcp_fingerprint') and not differ and identity
                 and state.get('kept_missing') == self.before.get('kept_missing') and state.get('kept_map') is not None,
                 {'mcp_equal': state.get('mcp_fingerprint') == self.before.get('mcp_fingerprint'),
                  'compared': compared, 'differ': differ[:30], 'identity_files': identity[:30],
                  'runtime_changed': runtime[:20], 'kept_missing': state.get('kept_missing')})
        ev.check(f'{label_text}: mcp-config.json holds this device\'s own Paseo entry and no other server (HA moves none)',
                 sorted(state.get('mcp_entries') or {}) == sorted(e for e in self.before.get('mcp_entries') or {}
                                                                   if e == 'woow-paseo'),
                 {'after': sorted(state.get('mcp_entries') or {}), 'before': sorted(self.before.get('mcp_entries') or {}),
                  'paseo_entry_unchanged': (state.get('mcp_entries') or {}).get('woow-paseo')
                  == (self.before.get('mcp_entries') or {}).get('woow-paseo')})
        if imported:
            ev.check(f'{label_text}: HA\'s {SOURCE["projects"]} projects through the API, the HA-side marker project with '
                     'its name, no lab project left', state.get('projects') == SOURCE['projects']
                     and state.get('marker_present') and state.get('marker_name_ok') and not state.get('lab_projects'),
                     {k: state.get(k) for k in ('projects', 'marker_present', 'marker_name_ok', 'lab_projects')})
            ev.check(f'{label_text}: the marker files through the API have the recorded SHA-256',
                     state.get('file_sha16') == MARKER_FILES and set(MARKER_FILES) <= set(state.get('marker_files') or []),
                     state.get('file_sha16'))
            ev.check(f'{label_text}: HA\'s {SOURCE["conversations"]} conversations through the API',
                     state.get('conversations') == SOURCE['conversations'], state.get('conversations'))
            ev.check(f'{label_text}: every member of the data volume is owned 0:0 (the daemon\'s user via keep-id); '
                     'the preferences this device keeps (installation id, agent CLI environment) are its own, not HA\'s',
                     state.get('data_nonroot') == 0 and state.get('target_prefs') == self.before.get('target_prefs'),
                     {'data_entries': state.get('data_entries'), 'data_nonroot': state.get('data_nonroot'),
                      'target_prefs_equal': state.get('target_prefs') == self.before.get('target_prefs'),
                      'target_prefs_keys': sorted(state.get('target_prefs') or {})})
        return state

    def collect_needles(self):
        report = drv.device_python(COLLECT, {'uid': self.uid, 'path': NEEDLES}, as_owner=False, timeout=300)
        self.needles = True
        self.ev.check('leaks: HA\'s moved third-party credential values collected inside dev-e (root 0600 file, never '
                      'leaving the device)', isinstance(report.get('values'), int), report)

    # -------- restart and rollbacks
    def step_restart(self):
        ev = self.ev
        started = time.monotonic()
        proc = drv.owner('systemctl', '--user', 'restart', 'open-design.service', timeout=600)
        ev.check('restart: systemctl --user restart open-design.service', proc.returncode == 0,
                 f'rc {proc.returncode} {time.monotonic() - started:.0f} s')
        self.verify('restart')

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
        self.space('auto rollback', 'restore')
        self.inject_on()
        try:
            job, took = drv.restore(self.converted, ['open-design'], ev=ev, tag='restore-inject-od-x86')
        finally:
            consumed = not owner_exists(MARKER_REL)
            self.inject_off()
        ev.save('restore-inject-job.json', job)
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        ev.check('auto rollback: a restore with a one-shot ExecStartPre failure ends rolled-back (the failure was '
                 'consumed)', job['state'] == 'rolled-back' and result.get('rolled_back') is True and consumed,
                 {'state': job['state'], 'error': job.get('error'), 'took_s': round(took, 1)})
        ev.check('auto rollback: the injected drop-in and marker are gone', not self.dropin)
        self.verify('auto rollback')

    def step_rollback_to_own(self):
        ev = self.ev
        self.space('rollback', 'restore')
        job, took = drv.restore(self.safety, ['open-design'], ev=ev, tag='rollback-od-x86')
        ev.save('rollback-job.json', job)
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        health = result.get('health') or []
        ev.check('rollback: restore-start of the import\'s safety backup succeeded, every health check ok',
                 job['state'] == 'succeeded' and result.get('rolled_back') is False and health
                 and all(h.get('status') == 'ok' for h in health),
                 {'state': job['state'], 'error': job.get('error'), 'took_s': round(took, 1)})
        state = self.verify('rollback', imported=False)
        found = self.markers()
        ev.save('markers-rollback.json', found)
        ev.check('rollback: dev-e\'s own markers are back exactly, HA\'s marker project is gone',
                 found == self.base_marker and state.get('marker_present') is False,
                 {'projects': found.get('projects'), 'marker_present': state.get('marker_present')})

    # -------- cleanup and leaks
    def step_leaks(self):
        ev = self.ev
        request = {'secrets': {'HA_BACKUP_KEY': self.args.secrets['HA_BACKUP_KEY']}, 'uid': self.uid,
                   'needles': NEEDLES}
        report = drv.device_python(LEAKS, request, as_owner=False, timeout=900)
        host = drv.scan_host_evidence(ev.dir, self.args.secrets)
        ev.save('leaks.json', {'device': report, 'host': host})
        ev.check('leaks: no registered value (HA key, this device\'s API and MCP tokens, HA\'s moved credential values) in '
                 'the engine\'s records, uploads, staging, run dir or the device journal; none in this evidence',
                 report.get('hits') == 0 and report.get('scanned', 0) > 0 and not host.get('hits'),
                 {'device': report, 'host_hits': host.get('hits')})

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
        ev.check('cleanup: the test\'s converted and safety backups are deleted', not (left & set(created)),
                 {'deleted': len(deleted), 'refused': refused})
        drv.STATE['created_backups'] = [b for b in created if b not in deleted]
        if self.created_store:
            rc, _reply = drv.helper('ha-delete', {'ha_backup_id': self.created_store, 'confirm': True})
            ev.check('cleanup: the HA store record this run created is deleted', rc == 0)
        if self.needles:
            proc = drv.root('rm', '-rf', os.path.dirname(NEEDLES), timeout=60)
            gone = drv.root('test', '-e', os.path.dirname(NEEDLES), timeout=60).returncode != 0
            ev.check('cleanup: the device-side needle file is removed', proc.returncode == 0 and gone)
            self.needles = not gone
        if self.timer_found not in (None, 'masked', 'masked-runtime'):
            proc = drv.root('systemctl', 'unmask', TIMER, timeout=120)
            ev.check('cleanup: the scheduled-backup timer is unmasked again (as found)', proc.returncode == 0,
                     self.timer_found)
        if self.found_units and all(state != 'active' for state in self.found_units.values()):
            proc = drv.owner('systemctl', '--user', 'stop', *UNITS, timeout=600)
            ev.check('cleanup: dev-e\'s OpenDesign is stopped again (as found)', proc.returncode == 0,
                     {u: unit_state(u) for u in UNITS})
        drv.save_state()


def run_all(run):
    ev = run.ev
    steps = (('setup', run.setup), ('before', run.step_before), ('upload', run.step_upload), ('check', run.step_check),
             ('import', run.step_import), ('verify', lambda: run.verify('verify')),
             ('needles', run.collect_needles), ('restart', run.step_restart),
             ('auto rollback', run.step_auto_rollback), ('rollback', run.step_rollback_to_own))
    failed = None
    try:
        for name, step in steps:
            run.budget(name)
            ev.log(f'== {name}')
            step()
    except (Failed, subprocess.TimeoutExpired, OSError, ValueError, KeyError) as error:
        failed = error
        ev.check(f'run stopped in a step ({type(error).__name__})', False, str(error)[:300])
    finally:
        try:
            if run.needles:
                run.step_leaks()
        except (Failed, subprocess.TimeoutExpired, OSError, ValueError, KeyError) as error:
            ev.check(f'leaks: scan failed ({type(error).__name__})', False, str(error)[:300])
        try:
            run.step_cleanup()
        except (Failed, subprocess.TimeoutExpired, OSError, ValueError, KeyError) as error:
            ev.check(f'cleanup: failed ({type(error).__name__})', False, str(error)[:300])
        state = isolation()
        emit(f'dev-e isolation: {state}')
        ev.check('after: dev-e still runs with network none and no published port', state == 'true none {}', state)
    return failed is None


def self_check():
    for script in (CLIENT, BEFORE, COLLECT, LEAKS, ENGINE_HASHES, SPACE):
        compile(script, '<device program>', 'exec')
    assert FIXTURE_SHA.startswith('c3d23ced') and len(MARKER_FILES) == 2
    assert all(label(x) == x for x in ('check: ok, no blockers', 'restart: systemctl --user restart open-design.service'))
    print('self-check: PASS')
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--self-check', action='store_true')
    args = parser.parse_args(argv)
    if args.self_check or not args.run:
        return self_check()
    commit = subprocess.run(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], capture_output=True, text=True,
                            check=True).stdout.strip()
    emit(f'source commit {commit}')
    secret_dir = LAB / 'secrets'
    args.secrets = drv.Secrets([secret_dir / 'b1-creds.env', secret_dir / 'ha-import-creds.env'],
                               secret_dir / 'dev-d-markers.json')
    if len(args.secrets.values.get('HA_BACKUP_KEY', '')) < 16:
        raise SystemExit('HA_BACKUP_KEY missing')
    ev = Ev(args.secrets, area='opendesign-odff')
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    waited = time.monotonic()
    deadline = time.monotonic() + 3600
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() > deadline:
                emit('lock: FAIL')
                return 3
            time.sleep(5)
    run = Run(args, ev)
    run.lock_started = time.monotonic()
    emit(f'lock waited {int(run.lock_started - waited)} s')
    try:
        ok = run_all(run)
    finally:
        emit(f'lock held for {int(time.monotonic() - run.lock_started)} s')
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    passed = ev.finish()
    results = ev.results
    emit(f'opendesign full flow: {sum(r["ok"] for r in results)}/{len(results)} {"PASS" if ok and passed else "FAIL"}')
    return 0 if ok and passed else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
