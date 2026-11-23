#!/usr/bin/env python3
"""code-server: the real x86 showcase HA backup (encrypted, add-on woow_ha_code_server 0.1.14, no share folder) ->
dev-e's INSTALLED code-server (Podman package 4.139.1-8) through the product's full HA-import flow, exactly the helper
commands the Cockpit page sends (lane codeserver-import, 2026-11-23).

  python3 -I tests/e2e/lab/services_a_capture.py --private=FILE <evidence.json> codeserver-x86 -- \\
      python3 -I tests/e2e/lab/codeserver_full_flow.py --run
  python3 -I tests/e2e/lab/codeserver_full_flow.py --self-check      (offline; never touches a device or a secret)

One run = one hold of /tmp/woowbk-dev-e-mutation.lock (flock, waiting up to an hour), dev-e's outer isolation
(`true none {}`) recorded before and after, the checkout committed (no tracked change). Every engine call is the root
helper the page calls (one JSON request on stdin, one JSON reply), with the engine of THIS tree installed by
deploy-src.sh; dev-e's code-server, its secret and env file (deployed by lane batch2-lab) are used as they are, the
catalog entry woow-code-server is this tree's tests/e2e/lab/catalog/woow-code-server.json (installed by batch2-lab).

  setup      the schedule timer masked, deploy-src.sh e --src <this tree> --no-demo-catalog, installed engine == tree,
             the woow-code-server catalog entry (one unit, three volumes, the workspace folder, health), a device key
  before     this run's device markers seeded when missing (a snippet in the IDE volume, a skill in the agents' volume, a
             file in the workspace) and a generated test login file in the agents' volume (only when the device has
             none; never a real credential); fingerprints of what must stay (the login and connector files, the IDE's
             machine id and workspace state, the extensions volume, the workspace, the password secret and the env
             file: SHA-256 prefixes only), then a plain restart and a second look: entries the app rewrites by itself
             are measured, not guessed, and left out of the comparison
  upload     upload-begin, the file copied to the path the helper gave, upload-finish: the record is the fixture
  check      ha-check-start woow-code-server (the HA key on stdin only): no blocker, amd64, add-on 0.1.14, target 4.139.1,
             the four program versions equal, the section's counts equal the backup's facts
  import     the real free space and the product's floor, ha-convert-start, inspect (preflight), restore-start (safety
             backup, in place, health)
  verify     the client: /healthz 200; POST /login with this device's password (read inside dev-e from the secret,
             never printed) gives the session cookie, the workbench page loads with it, without it / redirects to the
             login, a wrong password gets no cookie; the HA-side markers (snippet, skill) are served by the logged-in
             IDE's resource route with the recorded SHA-256 and seen by the IDE's user inside the container; the
             device markers and the test login stay; settings.json merged (this device's ACP agents pi/claude/codex,
             no zsh default, HA's own keys); HA's 28 Pi sessions, Claude and Codex history; nothing of HA's logins,
             connector state, SSH key, git identity or shell history in the volumes; every kept file unchanged
  restart    systemctl --user restart code-server.service: health, the client checks again
  rollback   (a) automatic: a second restore of the converted backup with a one-shot ExecStartPre failure on
             code-server.service must end `rolled-back` and leave HA's imported data; (b) the import's safety backup
             restored: the device markers are back, HA's markers are gone
  cleanup    drop-in gone, the test's converted and safety backups deleted, the HA store record this run created
             deleted, no job container/volume/network, staging or key file left, this run's seeded files removed
  leaks      the HA key, this device's password, the generated test login and HA's moved MCP header/env values
             (collected inside dev-e, never leaving it) in the engine's records, uploads, staging, run dir and the
             device journal outside the app's own unit: 0 hits (hits in code-server's own log are counted apart)

stdout carries only fixed lines (`<check>: PASS|FAIL`, the isolation line, the source commit, lock time); details go
to the private, redacted evidence folder ~/.woowbk-lab/evidence/codeserver-csff/<time>/ (0700).
Not covered (stated): the browser page itself (dev-e publishes no port; the helper calls are the page's), agent
provider logins (D2 a keeps this device's; none exist in the lab), Omnigent/Paseo pairing (D3 keeps this device's),
the workspace move (this backup has no share folder: only the refusal-free "no workspace" path is real), a host reboot.
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
HOLD_BUDGET = 45 * 60
MIN_HOST_AVAILABLE_KIB = 1024 * 1024
MIN_DEVICE_HEADROOM = 1024 * 1024 * 1024   # the jobs, the SQLite child and one throwaway version container
FLOOR = 12 * 1024 ** 3          # the team keeps >= 12 GiB free on the host at every moment
MARGIN = 256 * 1024 ** 2
NEEDS = {'upload': None, 'check': 64 * 1024 ** 2, 'convert': 768 * 1024 ** 2, 'restore': 512 * 1024 ** 2}
FIXTURE = (LAB / 'ha-fixtures' / '20261123-batch2' / 'x86' / 'woow-b2-codeserver-x86-enc'
           / 'woow-b2-codeserver-x86-enc-20261123.tar')
FIXTURE_SHA = '8f2dc23fd17b115c7317cf07f90b2fc685e901ead9282be3f3da8cef16c9856f'
# Facts of the backup: showcase-backups-2 (strict walk, markers) and the importer's own scan of this file in a
# network-none lab container (2026-11-23 ~19:00): 377 + 9 files move, 28 Pi sessions, 20 Claude Code and 15 Codex
# session files, 3 skills (+ .system), 1 snippet, no user extension (the 2 are the seeded connector VSIX), 9 shared
# MCP servers, codex-bootstrap unknown (left in HA with a warning).
SOURCE = {'version': '0.1.14', 'arch': 'amd64', 'target_version': '4.139.1', 'sessions': 28, 'claude_projects': 20,
          'codex_sessions': 15, 'skills': 3, 'snippets': 1, 'extensions': 0, 'mcp_servers': 9, 'files': 386}
PINS = {'code-server': '4.139.1', 'pi': '0.99.1', 'claude': '2.1.285', 'codex': '0.167.0'}
HA_MARKERS = {'ide:snippets/woow-import-test-20261123.code-snippets': 'dcae1e20ae973d5c',
              'pi:skills/woow-import-test-20261123/SKILL.md': '48d2358822db7c52'}
BASE = 'woowbk-lab-baseline'
DEVICE_MARKERS = {'ide:snippets/woowbk-lab-baseline.code-snippets':
                  '{"woowbk-lab-baseline": {"prefix": "woowbk", "body": "實驗室基準片段（code-server HA 匯入）"}}\n',
                  'pi:skills/woowbk-lab-baseline/SKILL.md': '# woowbk-lab-baseline\n實驗室基準技能（code-server HA 匯入）\n',
                  'desktop:woowbk-lab-baseline.txt': '實驗室基準工作區檔案（code-server HA 匯入）\n'}
TEST_LOGIN = 'pi:auth.json'     # a generated test login file, only when the device has none
TIMER = 'woowtech-cockpit-backup-schedule.timer'
UNIT = 'code-server.service'
VOLUMES = {'pi': 'woow-code-server-pi-data', 'ide': 'woow-code-server-ide', 'ext': 'woow-code-server-extensions'}
CONTAINER_PATHS = {'pi': '/data/pi-agent', 'ide': '/home/coder/.local/share/code-server/User',
                   'ext': '/home/coder/.local/share/code-server/extensions'}
# What must stay this device's (compared by SHA-256 prefix, before and after; app churn measured and left out)
KEPT = {'pi': ['auth.json', 'mcp-auth.json', 'connectors-primary', 'claude/.credentials.json', 'codex/auth.json', 'bin',
               'skills/woowbk-lab-baseline', 'settings.json'],
        'ide': ['machineid', 'workspaceStorage', 'globalStorage/woowtech.omnigent', 'globalStorage/woowtech.paseo',
                'snippets/woowbk-lab-baseline.code-snippets'],
        'ext': ['.']}
# HA-side names the import never brings (their existence must not change; the device may have its own `connectors/`)
NEVER = {'pi': ['connectors', 'omnigent', 'codex-bootstrap', 'trust.json', 'mcp-auth.json', 'claude/.credentials.json',
                'codex/auth.json'],
         'ide': ['workspaceStorage/-296a321', 'caches/CachedConfigurations']}
DROPIN_DIR_REL = '.config/systemd/user/code-server.service.d'
DROPIN_REL = DROPIN_DIR_REL + '/zz-csff-fail-once.conf'
MARKER_REL = '.csff-fail-once'
NEEDLES = '/var/lib/woowbk-csff/needles.json'     # root 0600 inside dev-e (network none); removed at the end
SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ,()/:'<>.=_-]")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drv = _load('ha_import_b1_e2e')
drv.DEVICE = DEVICE                       # every helper/owner/root call of the b1 driver goes to dev-e
drv.state_path = lambda: LAB / 'run' / 'codeserver_full_flow.json'
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
import hashlib, json, os, subprocess, sys, time, urllib.parse
import http.client as httpclient
REQ = json.loads(sys.stdin.read() or "{}")
VOLUMES = {"pi": "woow-code-server-pi-data", "ide": "woow-code-server-ide", "ext": "woow-code-server-extensions"}
HOME = "/home/appowner"
PORT = int(REQ.get("port", 18443))   # dev-e's code-server (inside dev-e only; the self-check uses a local fake)
def run(argv, timeout=300, check=True, input=None):
    p = subprocess.run(argv, capture_output=True, timeout=timeout, input=input)
    if check and p.returncode:
        raise SystemExit("command failed: %s rc=%d" % (argv[0:3], p.returncode))
    return p.stdout
def mountpoint(volume):
    return run(["podman", "volume", "inspect", "--format", "{{.Mountpoint}}", volume]).decode().strip()
def where(spec):
    area, rel = spec.split(":", 1)
    base = os.path.join(HOME, "Desktop") if area == "desktop" else mountpoint(VOLUMES[area])
    return area, os.path.join(base, rel)
def read_file(spec):
    area, path = where(spec)
    argv = ["cat", path] if area == "desktop" else ["podman", "unshare", "cat", path]
    p = subprocess.run(argv, capture_output=True, timeout=120)
    return p.stdout if p.returncode == 0 else None
def sha16(data):
    return hashlib.sha256(data).hexdigest()[:16] if data is not None else None
def password():
    data = run(["podman", "secret", "inspect", "--showsecret", "--format", "{{.SecretData}}", "code-server-config"]).decode()
    for line in data.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() == "password":
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            return value
    raise SystemExit("no password in the code-server-config secret")
def http(method, path, *, body=None, headers=None, retry=0):
    deadline = time.monotonic() + retry
    while True:
        try:
            conn = httpclient.HTTPConnection("127.0.0.1", PORT, timeout=60)
            conn.request(method, path, body=body, headers=dict(headers or {}))
            r = conn.getresponse()
            data = r.read()
            hdrs = r.getheaders()
            conn.close()
            if r.status in (502, 503) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return r.status, data, hdrs
        except (ConnectionError, OSError, httpclient.HTTPException):
            if time.monotonic() >= deadline:
                return 0, b"", []
            time.sleep(3)
def header(hdrs, name):
    return [v for k, v in hdrs if k.lower() == name.lower()]
def login(pw):
    body = urllib.parse.urlencode({"password": pw}).encode()
    status, data, hdrs = http("POST", "/login", body=body, headers={
        "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://127.0.0.1:%d" % PORT})
    cookie = None
    for item in header(hdrs, "Set-Cookie"):
        first = item.split(";", 1)[0]
        if first.startswith("code-server-session="):
            cookie = first
    return status, cookie, header(hdrs, "Location")
WALK = """
import hashlib, json, os, stat, sys
root, parts = sys.argv[1], sys.argv[2:]
entries, nonroot, total, missing = {}, 0, 0, []
def one(path, rel):
    global nonroot, total
    st = os.lstat(path)
    total += 1
    if st.st_uid != 0 or st.st_gid != 0:
        nonroot += 1
    if stat.S_ISREG(st.st_mode):
        h = hashlib.sha256(open(path, "rb").read()).hexdigest()
        entries[rel] = "f %o %d %s" % (st.st_mode & 0o7777, st.st_size, h[:12])
    elif stat.S_ISLNK(st.st_mode):
        entries[rel] = "l " + hashlib.sha256(os.readlink(path).encode()).hexdigest()[:12]
    else:
        entries[rel] = "d %o" % (st.st_mode & 0o7777)
for part in parts or ["."]:
    top = os.path.normpath(os.path.join(root, part))
    if not os.path.lexists(top):
        missing.append(part)
        continue
    one(top, os.path.relpath(top, root))
    if os.path.isdir(top) and not os.path.islink(top):
        for d, dirs, files in os.walk(top, followlinks=False):
            for n in sorted(dirs) + sorted(files):
                p = os.path.join(d, n)
                one(p, os.path.relpath(p, root))
print(json.dumps({"entries": total, "nonroot": nonroot, "missing": missing, "map": entries if len(entries) <= 20000 else None}))
"""
def walk(area, parts):
    base = os.path.join(HOME, "Desktop") if area == "desktop" else mountpoint(VOLUMES[area])
    argv = ["python3", "-I", "-c", WALK, base, *parts]
    if area != "desktop":
        argv = ["podman", "unshare"] + argv
    return json.loads(run(argv, timeout=900))
def secret_hash():
    return hashlib.sha256(run(["podman", "secret", "inspect", "--showsecret", "--format", "{{.SecretData}}",
                               "code-server-config"])).hexdigest()[:16]
def env_hash():
    try:
        return hashlib.sha256(open(os.path.join(HOME, ".config/woow-code-server/woow-code-server.env"), "rb").read()).hexdigest()[:16]
    except OSError:
        return None
def snapshot():
    out = {}
    for area, parts in REQ["kept"].items():
        w = walk(area, parts)
        out[area] = {"map": w["map"], "missing": w["missing"]}
    out["desktop"] = {"map": walk("desktop", [])["map"]}
    out["secret"] = secret_hash()
    out["env"] = env_hash()
    return out
'''

# Seed this run's device markers and the generated test login where they are missing (as appowner; prints names).
SEED = COMMON + r'''
created = []
for spec, text in REQ["markers"].items():
    if read_file(spec) is not None:
        continue
    area, path = where(spec)
    data = text.encode()
    if area == "desktop":
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
    else:
        run(["podman", "unshare", "sh", "-c", 'mkdir -p "$(dirname "$1")" && cat > "$1" && chmod 0644 "$1"', "sh", path],
            input=data)
    created.append(spec)
if REQ.get("login") and read_file(REQ["login"]) is None:
    _area, path = where(REQ["login"])
    run(["podman", "unshare", "sh", "-c", 'umask 077; cat > "$1"', "sh", path], input=REQ["login_data"].encode())
    created.append(REQ["login"])
print(json.dumps({"created": created}))
'''

# Remove what SEED created (names from the run's own record; as appowner).
UNSEED = COMMON + r'''
removed = []
for spec in REQ["created"]:
    area, path = where(spec)
    argv = ["rm", "-f", path] if area == "desktop" else ["podman", "unshare", "rm", "-f", path]
    if subprocess.run(argv, capture_output=True, timeout=120).returncode == 0:
        removed.append(spec)
    parent = os.path.dirname(path)
    if spec.startswith("pi:skills/"):
        subprocess.run(["podman", "unshare", "rmdir", parent], capture_output=True, timeout=120)
print(json.dumps({"removed": removed, "left": [s for s in REQ["created"] if read_file(s) is not None]}))
'''

# The state before the import (fingerprints only; as appowner).
BEFORE = COMMON + r'''
out = {"health": http("GET", "/healthz", retry=300)[0]}
out.update(snapshot())
out["never_missing"] = {area: walk(area, parts)["missing"] for area, parts in REQ["never"].items()}
print(json.dumps(out))
'''

# The client checks of the restored code-server (as appowner; prints one JSON line of facts, never a value).
CLIENT = COMMON + r'''
out = {"health": http("GET", "/healthz", retry=420)[0]}
pw = password()
status, cookie, location = login(pw)
out["login_status"], out["login_cookie"], out["login_location"] = status, bool(cookie), location[:1]
status, body, hdrs = http("GET", "/", headers={"Cookie": cookie} if cookie else {})
out["workbench_status"] = status
out["workbench_page"] = b"workbench" in body or b"vscode" in body.lower()
status, _b, hdrs = http("GET", "/")
out["anonymous_status"] = status
out["anonymous_to_login"] = any("login" in v for v in header(hdrs, "Location"))
if REQ.get("wrong"):
    status, wrong_cookie, _l = login("wrong-" + "x" * 30)
    out["wrong_status"], out["wrong_cookie"] = status, bool(wrong_cookie)
served, seen = {}, {}
for spec in REQ["ha_markers"]:
    area, rel = spec.split(":", 1)
    path = REQ["container_paths"][area] + "/" + rel
    if cookie:
        status, body, _h = http("GET", "/vscode-remote-resource?path=" + urllib.parse.quote(path), headers={"Cookie": cookie})
        served[spec] = sha16(body) if status == 200 else "HTTP %d" % status
    p = subprocess.run(["podman", "exec", "code-server", "cat", path], capture_output=True, timeout=120)
    seen[spec] = sha16(p.stdout) if p.returncode == 0 else "rc %d" % p.returncode
out["served"], out["seen"] = served, seen
out["device_markers"] = {spec: sha16(read_file(spec)) for spec in REQ["device_markers"]}
settings = read_file("ide:settings.json")
try:
    doc = json.loads(settings) if settings is not None else {}
except ValueError:
    doc = None
if isinstance(doc, dict):
    agents = doc.get("acp.agents") if isinstance(doc.get("acp.agents"), dict) else {}
    out["acp_agents"] = {k: (v or {}).get("command") for k, v in agents.items() if isinstance(v, dict)}
    out["default_shell"] = doc.get("terminal.integrated.defaultProfile.linux")
    out["ha_keys"] = {k: k in doc for k in REQ["ha_setting_keys"]}
    out["trust_enabled"] = doc.get("security.workspace.trust.enabled")
else:
    out["settings_unreadable"] = True
pi = walk("pi", ["sessions", "claude/projects", "codex/sessions", "codex/archived_sessions", "skills"])
m = pi["map"] or {}
out["pi_sessions"] = sum(1 for k, v in m.items() if k.startswith("sessions/") and k.endswith(".jsonl") and v.startswith("f"))
out["claude_projects"] = sum(1 for k, v in m.items() if k.startswith("claude/projects/") and k.endswith(".jsonl") and v.startswith("f"))
out["codex_sessions"] = sum(1 for k, v in m.items() if k.startswith(("codex/sessions/", "codex/archived_sessions/"))
                            and k.endswith(".jsonl") and v.startswith("f"))
out["skills"] = sorted({k.split("/")[1] for k in m if k.startswith("skills/") and k.count("/") >= 1})
never = {}
for area, parts in REQ["never"].items():
    never[area] = walk(area, parts)["missing"]
out["never_missing"] = never
ide = walk("ide", [])
out["ide_nonroot"] = ide["nonroot"]
ha_owned = walk("pi", ["skills/woow-import-test-20261123", "sessions"])
out["ha_nonroot"] = ha_owned["nonroot"]
out.update({"snapshot": snapshot()})
print(json.dumps(out))
'''

# HA's moved MCP header/env values (strings of at least 12 characters in the restored shared/mcp.json), collected
# inside dev-e into a root 0600 file for the leak scan; prints only a count.
COLLECT = r'''
import json, os, subprocess, sys
req = json.loads(sys.stdin.read())
def owner(*argv):
    return subprocess.run(["runuser", "-u", "appowner", "--", "env", "-i", "PATH=/usr/bin:/bin", "HOME=/home/appowner",
                           "XDG_RUNTIME_DIR=/run/user/%d" % req["uid"], *argv], capture_output=True, timeout=120)
mp = owner("podman", "volume", "inspect", "--format", "{{.Mountpoint}}", "woow-code-server-pi-data").stdout.decode().strip()
values = set()
import re
def strings(value):
    # secret-looking values only: 16+ characters, letters and digits, no space, no path, no URL without userinfo or
    # query (generic header values such as "application/json" would match ordinary log lines)
    if isinstance(value, str):
        if (len(value) >= 16 and " " not in value and not value.startswith("/") and re.search(r"[0-9]", value)
                and re.search(r"[A-Za-z]", value) and not re.fullmatch(r"https?://[^@?#\s]*", value)):
            values.add(value)
    elif isinstance(value, list):
        for item in value:
            strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            strings(item)
p = owner("podman", "unshare", "cat", os.path.join(mp, "shared", "mcp.json"))
if p.returncode == 0:
    try:
        for server in (json.loads(p.stdout).get("mcpServers") or {}).values():
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
p = owner("podman", "secret", "inspect", "--showsecret", "--format", "{{.SecretData}}", "code-server-config")
pw = None
for line in p.stdout.decode().splitlines():
    k, sep, v = line.partition(":")
    if sep and k.strip() == "password":
        pw = v.strip().strip("\"'")
if not pw or len(pw) < 8:
    raise RuntimeError("cannot read the device's code-server password")
secrets["device:password"] = pw.encode()
moved = json.load(open(req["needles"])) if os.path.exists(req["needles"]) else None
if moved is None:
    raise RuntimeError("the moved-value needle file is missing")
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
app_hits, journal_hits, journal_bytes = 0, 0, 0
proc = subprocess.run(["journalctl", "-o", "json", "--no-pager"], capture_output=True, check=True)
for line in proc.stdout.splitlines():
    try:
        entry = json.loads(line)
    except ValueError:
        continue
    message = entry.get("MESSAGE")
    if isinstance(message, list):
        message = bytes(message)
    elif isinstance(message, str):
        message = message.encode("utf-8", "surrogateescape")
    else:
        continue
    journal_bytes += len(message)
    count = sum(message.count(s) for s in needles)
    if not count:
        continue
    unit = entry.get("_SYSTEMD_USER_UNIT") or entry.get("_SYSTEMD_UNIT") or ""
    ident = entry.get("SYSLOG_IDENTIFIER") or ""
    if unit == "code-server.service" or ident == "code-server" or entry.get("CONTAINER_NAME") == "code-server":
        app_hits += count
    else:
        journal_hits += count
print(json.dumps({"scanned": scanned, "journal_bytes": journal_bytes, "names": len(secrets), "moved_values": len(moved),
                  "hits": hits, "journal_hits": journal_hits, "app_log_hits": app_hits}))
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


def unit_state(unit=UNIT):
    return drv.out(drv.owner('systemctl', '--user', 'is-active', unit, timeout=60)).strip()


def wait_unit(ev, label_text, timeout=420):
    deadline = time.monotonic() + timeout
    state = ''
    while time.monotonic() < deadline:
        state = unit_state()
        if state == 'active':
            break
        time.sleep(5)
    ev.check(f'{label_text}: code-server.service is active', state == 'active', state)


SNAP_AREAS = ('pi', 'ide', 'ext', 'desktop')


def compare(before, after, churn=()):
    """{area: [names that differ]} of two snapshots' maps, without the names in `churn` (measured app rewrites)."""
    differ = {}
    for area in SNAP_AREAS:
        b = before.get(area) if isinstance(before.get(area), dict) else {}
        a = after.get(area) if isinstance(after.get(area), dict) else {}
        if b.get('missing') != a.get('missing'):
            differ.setdefault(area, []).extend(f'missing:{name}' for name in sorted(
                set(b.get('missing') or []) ^ set(a.get('missing') or [])))
        b, a = b.get('map') or {}, a.get('map') or {}
        names = sorted(k for k in set(b) | set(a) if b.get(k) != a.get(k) and f'{area}:{k}' not in churn)
        if names:
            differ.setdefault(area, []).extend(names)
    return differ


def churn_of(first, second):
    """`area:name` of the entries that changed across a plain restart (the app's own rewrites)."""
    found = set()
    for area, names in compare(first, second).items():
        found.update(f'{area}:{name}' for name in names)
    return found


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
        self.churn = set()
        self.seeded = []
        self.uid = None
        self.timer_found = None
        self.unit_found = None

    def budget(self, phase):
        if time.monotonic() - self.lock_started > HOLD_BUDGET:
            raise Failed(f'lock hold budget reached before {phase}')

    def device_memory(self):
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
        ok = maximum - used >= MIN_DEVICE_HEADROOM
        self.ev.check('preflight: dev-e memory headroom for code-server and the jobs (before any change)', ok,
                      {'unreclaimable_mib': used >> 20, 'limit_mib': maximum >> 20,
                       'need_mib': MIN_DEVICE_HEADROOM >> 20, 'unit': self.unit_found})
        if not ok:
            raise Failed('dev-e memory headroom too small')
        available = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                         if line.startswith('MemAvailable:'))
        if not self.ev.check('preflight: host MemAvailable >= 1 GiB', available >= MIN_HOST_AVAILABLE_KIB,
                             {'mem_available_kib': available}):
            raise Failed('host memory')
        self.space('preflight', 'upload')

    def space(self, label_text, step):
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
        if not ev.check('preflight: the local file is the recorded showcase code-server backup (sha256)',
                        sha == FIXTURE_SHA, sha[:16]):
            raise Failed('fixture changed')
        self.unit_found = unit_state()
        if not ev.check('preflight: dev-e\'s code-server is running (deployed by lane batch2-lab)',
                        self.unit_found == 'active', self.unit_found):
            raise Failed('code-server is not running on dev-e')
        self.headroom()
        self.uid = device_uid()
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
        entry = drv.catalog('woow-code-server')
        ev.save('catalog-woow-code-server.json', entry)
        mine = json.loads((HERE / 'catalog' / 'woow-code-server.json').read_text(encoding='utf-8'))
        if not ev.check('setup: the woow-code-server catalog entry is this tree\'s lab entry (one unit, three volumes, '
                        'the workspace folder, health)', entry == mine,
                        {'units': entry.get('units'), 'volumes': [v['name'] for v in entry.get('volumes') or []],
                         'data_dirs': [d['path'] for d in entry.get('data_dirs') or []]}):
            raise Failed('catalog entry')
        key = drv.ok('key-init', ev=ev)
        ev.check('setup: a device key exists (key-init)', bool((key.get('key') or {}).get('key_id')),
                 {'created': key.get('created')})
        wait_unit(ev, 'setup')

    # -------- before
    def step_before(self):
        ev = self.ev
        login_data = json.dumps({'woowbk-lab-test': {'type': 'api_key', 'key': self.args.test_login}}) + '\n'
        seeded = drv.device_python(SEED, {'markers': DEVICE_MARKERS, 'login': TEST_LOGIN, 'login_data': login_data},
                                   timeout=300)
        self.seeded = list(seeded.get('created') or [])
        drv.STATE['codeserver_seeded'] = self.seeded
        drv.save_state()
        ev.check('before: this run\'s device markers and the generated test login are in place (created when missing)',
                 isinstance(seeded.get('created'), list), {'created': self.seeded})
        first = drv.device_python(BEFORE, {'kept': KEPT, 'never': NEVER}, timeout=900)
        ev.check('before: dev-e\'s code-server is healthy', first.get('health') == 200, first.get('health'))
        proc = drv.owner('systemctl', '--user', 'restart', UNIT, timeout=600)
        ev.check('before: a plain restart (to measure what the app rewrites by itself)', proc.returncode == 0,
                 f'rc {proc.returncode}')
        wait_unit(ev, 'before restart')
        time.sleep(20)
        second = drv.device_python(BEFORE, {'kept': KEPT, 'never': NEVER}, timeout=900)
        self.churn = churn_of(first, second)
        self.before = second
        ev.save('state-before.json', {'first': first, 'second': second, 'churn': sorted(self.churn)})
        ev.check('before: the app\'s own rewrites across a restart are measured (left out of the comparison)',
                 second.get('health') == 200 and first.get('secret') == second.get('secret'),
                 {'churn': sorted(self.churn)[:40], 'secret_equal': first.get('secret') == second.get('secret')})

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
        ev.check('upload: woow-code-server is importable and installed here', found.get('woow-code-server') is True, found)
        if store_id not in listed:
            self.created_store = store_id
        self.store_id = store_id
        if not ok:
            raise Failed('upload refused')

    def step_check(self):
        ev = self.ev
        self.space('check', 'check')
        job, took = drv.run_check(self.store_id, ['woow-code-server'], ev=ev, key=self.args.secrets['HA_BACKUP_KEY'],
                                  tag='check-cs-x86')
        if not ev.check('check: ha-check-start job succeeded', job['state'] == 'succeeded',
                        f'{took:.0f} s {job.get("error")}'):
            raise Failed('check job failed')
        result = job['result']['ha_check']['apps'][0]
        ev.save('check-result.json', result)
        section = result.get('woow-code-server') or {}
        ev.check('check: ok, no blockers', result.get('ok') is True and not result.get('blockers'), result.get('blockers'))
        ev.check('check: source amd64, add-on 0.1.14, this device\'s code-server 4.139.1, the four programs equal',
                 result.get('arch') == SOURCE['arch'] and result.get('version') == SOURCE['version']
                 and result.get('target_version') == SOURCE['target_version']
                 and section.get('pins') == PINS and section.get('target_pins') == PINS,
                 {k: result.get(k) for k in ('arch', 'version', 'target_version')} | {'target_pins': section.get('target_pins')})
        counts = {k: section.get(k) for k in ('sessions', 'claude_projects', 'codex_sessions', 'skills', 'snippets',
                                              'extensions', 'mcp_servers', 'files')}
        ev.check('check: the section counts equal the backup\'s facts (sessions, skills, snippets, MCP servers, files)',
                 counts == {k: SOURCE[k] for k in counts}, counts)
        ev.check('check: no workspace (no share folder) and codex-bootstrap named as not moved; warnings say so',
                 section.get('share') is False and section.get('workspace') is False
                 and section.get('unknown') == ['codex-bootstrap']
                 and any('share' in w for w in result.get('warnings') or []),
                 {'warnings': len(result.get('warnings') or []), 'unknown': section.get('unknown')})
        leftovers = drv.labelled()
        ev.check('check: no throwaway container, volume or network left (the version container is gone)',
                 not any(leftovers.values()), leftovers)

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
        job, took = drv.convert(self.store_id, ['woow-code-server'], False, ev=ev,
                                key=self.args.secrets['HA_BACKUP_KEY'], tag='convert-cs-x86')
        ev.save('convert-job.json', job)
        if not ev.check('import: ha-convert-start job succeeded with a backup id', job['state'] == 'succeeded'
                        and (job.get('result') or {}).get('backup_id'), f'{took:.0f} s {job.get("error")}'):
            raise Failed('convert failed')
        result = job['result']
        self.converted = result['backup_id']
        drv.created_backup(self.converted)
        imp = result.get('ha_import') or {}
        reminders = (imp.get('reminders_by_app') or {}).get('woow-code-server') or []
        ev.check('import: ha_import names woow-code-server, the code-server notes and its reminders (logins, history, '
                 'connectors, SSH, workspace)', imp.get('apps') == ['woow-code-server'] and imp.get('test_mode') is False
                 and any(n.startswith('code-server') for n in imp.get('notes') or [])
                 and any('/login' in r for r in reminders) and any('/share/projects' in r for r in reminders),
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
        rjob, rtook = drv.restore(self.converted, ['woow-code-server'], ev=ev, tag='restore-cs-x86')
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
    def verify(self, label_text, *, imported=True, wrong=False):
        ev = self.ev
        wait_unit(ev, label_text)
        state = drv.device_python(CLIENT, {'ha_markers': sorted(HA_MARKERS), 'device_markers': sorted(DEVICE_MARKERS),
                                           'container_paths': CONTAINER_PATHS, 'kept': KEPT, 'never': NEVER,
                                           'wrong': wrong, 'ha_setting_keys': ['editor.rulers', 'esphome.validator']},
                                  timeout=1500)
        ev.save(f'client-{label(label_text).replace(" ", "-")}.json', state)
        ev.check(f'{label_text}: /healthz 200; POST /login with this device\'s password gives the session cookie; the '
                 'workbench loads with it; without it / redirects to the login',
                 state.get('health') == 200 and state.get('login_status') == 302 and state.get('login_cookie')
                 and state.get('workbench_status') == 200 and state.get('workbench_page')
                 and state.get('anonymous_status') == 302 and state.get('anonymous_to_login'),
                 {k: state.get(k) for k in ('health', 'login_status', 'login_cookie', 'workbench_status',
                                            'workbench_page', 'anonymous_status', 'anonymous_to_login')})
        if wrong:
            ev.check(f'{label_text}: a wrong password gets no session cookie', state.get('wrong_cookie') is False,
                     {'wrong_status': state.get('wrong_status'), 'wrong_cookie': state.get('wrong_cookie')})
        markers = {spec: sha is not None for spec, sha in (state.get('device_markers') or {}).items()}
        ev.check(f'{label_text}: this device\'s markers (snippet, skill, workspace file) are there',
                 all(markers.values()) and len(markers) == len(DEVICE_MARKERS), markers)
        snap = state.get('snapshot') or {}
        differ = compare(self.before, snap, self.churn)
        ev.check(f'{label_text}: what stays this device\'s is unchanged: the test login, connector state, IDE machine id '
                 'and workspace state, the extensions volume, the workspace, the password secret and the env file',
                 not differ and snap.get('secret') == self.before.get('secret') and snap.get('env') == self.before.get('env'),
                 {'differ': {a: n[:15] for a, n in differ.items()}, 'secret_equal': snap.get('secret') == self.before.get('secret'),
                  'env_equal': snap.get('env') == self.before.get('env')})
        if imported:
            ev.check(f'{label_text}: HA\'s marker snippet and skill are served by the logged-in IDE (resource route) and '
                     'seen by its user in the container with the recorded SHA-256',
                     state.get('served') == HA_MARKERS and state.get('seen') == HA_MARKERS,
                     {'served': state.get('served'), 'seen': state.get('seen')})
            ev.check(f'{label_text}: settings.json merged: this device\'s ACP agents pi/claude/codex, no zsh default, '
                     'workspace trust off as here, HA\'s own keys present',
                     state.get('acp_agents', {}).get('pi') == 'pi-code'
                     and state.get('acp_agents', {}).get('claude') == 'claude-agent-acp'
                     and state.get('acp_agents', {}).get('codex') == 'codex-code'
                     and state.get('default_shell') != 'zsh' and state.get('trust_enabled') is False
                     and all((state.get('ha_keys') or {}).values()),
                     {k: state.get(k) for k in ('acp_agents', 'default_shell', 'trust_enabled', 'ha_keys')})
            ev.check(f'{label_text}: HA\'s {SOURCE["sessions"]} Pi sessions, Claude Code and Codex history and skills are '
                     'there (this device\'s own too)',
                     state.get('pi_sessions', 0) >= SOURCE['sessions'] and state.get('claude_projects', 0) >= SOURCE['claude_projects']
                     and state.get('codex_sessions', 0) >= SOURCE['codex_sessions']
                     and {'woow-import-test-20261123', BASE} <= set(state.get('skills') or []),
                     {k: state.get(k) for k in ('pi_sessions', 'claude_projects', 'codex_sessions', 'skills')})
            missing, was = state.get('never_missing') or {}, self.before.get('never_missing') or {}
            ev.check(f'{label_text}: nothing of HA\'s logins, connector state, unknown leftovers or HA-only files came over '
                     '(their existence here is as before the import)',
                     all(sorted(missing.get(a) or []) == sorted(was.get(a) or []) for a in NEVER),
                     {'after_missing': missing, 'before_missing': was})
            ev.check(f'{label_text}: HA\'s moved entries are owned 0:0 in the owner\'s namespace (coder via keep-id)',
                     state.get('ha_nonroot') == 0, {'ha_nonroot': state.get('ha_nonroot'),
                                                    'ide_nonroot': state.get('ide_nonroot')})
        else:
            ev.check(f'{label_text}: HA\'s markers are gone', all(not str(v).startswith(('dcae', '48d2'))
                                                                  for v in (state.get('seen') or {}).values()),
                     state.get('seen'))
        return state

    def collect_needles(self):
        report = drv.device_python(COLLECT, {'uid': self.uid, 'path': NEEDLES}, as_owner=False, timeout=300)
        self.needles = True
        self.ev.check('leaks: HA\'s moved MCP header/env values collected inside dev-e (root 0600 file, never leaving '
                      'the device)', isinstance(report.get('values'), int), report)

    # -------- restart and rollbacks
    def step_restart(self):
        ev = self.ev
        started = time.monotonic()
        proc = drv.owner('systemctl', '--user', 'restart', UNIT, timeout=600)
        ev.check('restart: systemctl --user restart code-server.service', proc.returncode == 0,
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
            job, took = drv.restore(self.converted, ['woow-code-server'], ev=ev, tag='restore-inject-cs-x86')
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
        job, took = drv.restore(self.safety, ['woow-code-server'], ev=ev, tag='rollback-cs-x86')
        ev.save('rollback-job.json', job)
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        health = result.get('health') or []
        ev.check('rollback: restore-start of the import\'s safety backup succeeded, every health check ok',
                 job['state'] == 'succeeded' and result.get('rolled_back') is False and health
                 and all(h.get('status') == 'ok' for h in health),
                 {'state': job['state'], 'error': job.get('error'), 'took_s': round(took, 1)})
        self.verify('rollback', imported=False, wrong=True)

    # -------- cleanup and leaks
    def step_leaks(self):
        ev = self.ev
        request = {'secrets': {'HA_BACKUP_KEY': self.args.secrets['HA_BACKUP_KEY'], 'TEST_LOGIN': self.args.test_login},
                   'uid': self.uid, 'needles': NEEDLES}
        report = drv.device_python(LEAKS, request, as_owner=False, timeout=900)
        host = drv.scan_host_evidence(ev.dir, self.args.secrets)
        ev.save('leaks.json', {'device': report, 'host': host})
        ev.check('leaks: no registered value (HA key, this device\'s password, the test login, HA\'s moved MCP values) in '
                 'the engine\'s records, uploads, staging, run dir or the device journal outside the app; none in this '
                 'evidence', report.get('hits') == 0 and report.get('journal_hits') == 0 and report.get('scanned', 0) > 0
                 and not host.get('hits'),
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
        if self.seeded:
            report = drv.device_python(UNSEED, {'created': self.seeded}, timeout=300)
            ev.check('cleanup: this run\'s seeded markers and test login are removed (dev-e as found)',
                     not report.get('left'), report)
            if not report.get('left'):
                drv.STATE['codeserver_seeded'] = []
        if self.timer_found not in (None, 'masked', 'masked-runtime'):
            proc = drv.root('systemctl', 'unmask', TIMER, timeout=120)
            ev.check('cleanup: the scheduled-backup timer is unmasked again (as found)', proc.returncode == 0,
                     self.timer_found)
        drv.save_state()


def run_all(run):
    ev = run.ev
    steps = (('setup', run.setup), ('before', run.step_before), ('upload', run.step_upload), ('check', run.step_check),
             ('import', run.step_import), ('verify', lambda: run.verify('verify', wrong=True)),
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


def http_self_check():
    """COMMON's login and HTTP helpers against a local fake of code-server's routes (an ephemeral port on 127.0.0.1;
    never a device, never the host's real code-server)."""
    import http.server
    import threading

    class Fake(http.server.BaseHTTPRequestHandler):
        def _send(self, status, headers=(), body=b''):
            self.send_response(status)
            for key, value in headers:
                self.send_header(key, value)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            data = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
            if self.path == '/login' and data == 'password=right+one':
                self._send(302, [('Location', './'), ('Set-Cookie', 'other=1; Path=/'),
                                 ('Set-Cookie', 'code-server-session=fake; Path=/; HttpOnly')])
            else:
                self._send(200, body=b'<html>login</html>')

        def do_GET(self):
            authed = 'code-server-session=fake' in (self.headers.get('Cookie') or '')
            if self.path == '/healthz':
                self._send(200, body=b'{"status":"alive"}')
            elif self.path == '/':
                self._send(200, body=b'<meta id="vscode-workbench-web-configuration">') if authed else \
                    self._send(302, [('Location', './login')])
            elif self.path.startswith('/vscode-remote-resource?path=') and authed:
                self._send(200, body=b'marker')
            else:
                self._send(404)

        def log_message(self, *_args):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 0), Fake)
    port = server.server_address[1]
    assert port != 18443
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        ns = {}
        exec(COMMON.replace('REQ = json.loads(sys.stdin.read() or "{}")', f'REQ = {{"port": {port}}}'), ns)
        status, cookie, location = ns['login']('right one')
        assert (status, cookie, location) == (302, 'code-server-session=fake', ['./']), (status, cookie, location)
        assert ns['login']('wrong')[:2] == (200, None)
        assert ns['http']('GET', '/healthz')[0] == 200
        status, body, _h = ns['http']('GET', '/', headers={'Cookie': cookie})
        assert status == 200 and b'workbench' in body
        status, _b, headers = ns['http']('GET', '/')
        assert status == 302 and ns['header'](headers, 'location') == ['./login']
        status, body, _h = ns['http']('GET', '/vscode-remote-resource?path=%2Fdata%2Fx', headers={'Cookie': cookie})
        assert (status, ns['sha16'](body)) == (200, hashlib.sha256(b'marker').hexdigest()[:16])
    finally:
        server.shutdown()
        server.server_close()


def walk_self_check():
    """COMMON's WALK program on a temporary tree (pure Python, no device)."""
    import tempfile
    ns = {}
    exec(COMMON.replace('REQ = json.loads(sys.stdin.read() or "{}")', 'REQ = {}'), ns)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / 'skills' / 'a').mkdir(parents=True)
        (root / 'skills' / 'a' / 'SKILL.md').write_bytes(b'# a')
        os.symlink('SKILL.md', root / 'skills' / 'a' / 'link')
        proc = subprocess.run([sys.executable, '-I', '-c', ns['WALK'], str(root), 'skills', 'missing.json'],
                              capture_output=True, timeout=60, check=True)
        doc = json.loads(proc.stdout)
        assert doc['missing'] == ['missing.json'] and doc['entries'] == 4, doc
        assert doc['map']['skills/a/SKILL.md'].startswith('f ') and doc['map']['skills/a/link'].startswith('l ')
        proc = subprocess.run([sys.executable, '-I', '-c', ns['WALK'], str(root), '.'], capture_output=True,
                              timeout=60, check=True)
        assert set(json.loads(proc.stdout)['map']) == {'.', 'skills', 'skills/a', 'skills/a/SKILL.md', 'skills/a/link'}


def self_check():
    for script in (BEFORE, CLIENT, SEED, UNSEED, COLLECT, LEAKS, ENGINE_HASHES, SPACE):
        compile(script, '<device program>', 'exec')
    assert FIXTURE_SHA.startswith('8f2dc23f') and len(HA_MARKERS) == 2 and len(DEVICE_MARKERS) == 3
    entry = json.loads((HERE / 'catalog' / 'woow-code-server.json').read_text(encoding='utf-8'))
    assert entry['id'] == 'woow-code-server' and [v['name'] for v in entry['volumes']] == list(VOLUMES.values())
    a = {'pi': {'map': {'x': 'f 644 1 aa', 'churn': 'f 644 1 bb'}, 'missing': []}, 'secret': 's', 'health': 200,
         'never_missing': {'pi': ['x']}}
    b = {'pi': {'map': {'x': 'f 644 1 aa', 'churn': 'f 644 1 cc'}, 'missing': []}, 'secret': 's', 'health': 200}
    assert churn_of(a, b) == {'pi:churn'} and compare(a, b, {'pi:churn'}) == {}
    assert compare(a, {'pi': {'map': {'x': 'f 644 1 zz'}, 'missing': []}}) == {'pi': ['churn', 'x']}
    assert compare(a, {'pi': {'map': {'x': 'f 644 1 aa', 'churn': 'f 644 1 bb'}, 'missing': ['auth.json']}}) == {
        'pi': ['missing:auth.json']}
    assert all(label(x) == x for x in ('check: ok, no blockers', 'restart: systemctl --user restart code-server.service'))
    http_self_check()
    walk_self_check()
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
    import secrets as _secrets
    args.test_login = 'woowbk-test-' + _secrets.token_urlsafe(24)   # generated per run, never a real credential
    args.secrets.register('CSFF_TEST_LOGIN', args.test_login)
    ev = Ev(args.secrets, area='codeserver-csff')
    drv.load_state()
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
    emit(f'code-server full flow: {sum(r["ok"] for r in results)}/{len(results)} {"PASS" if ok and passed else "FAIL"}')
    return 0 if ok and passed else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
