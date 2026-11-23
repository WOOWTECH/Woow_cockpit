#!/usr/bin/env python3
"""Headscale: the real b1 HA backups (plain) -> dev-d's INSTALLED Headscale through the product's full HA-import
flow, exactly the helper commands the Cockpit page sends (lane services-a-2, 2026-11-23).

  python3 -I tests/e2e/lab/services_a_capture.py --private=FILE <evidence.json> <scope> -- \\
      python3 -I tests/e2e/lab/headscale_full_flow.py --run --arch x86|arm
  python3 -I tests/e2e/lab/headscale_full_flow.py --self-check      (offline; never touches a device or a secret)

One run = one hold of the dev-d mutation lock (dev_d_guard: blocking like `flock -w`, yields to emqx-main's waiting
file), dev-d's outer isolation recorded before and after (`owner.sh d --verify-isolation`), the checkout committed
(no change outside the evidence folders). Every engine call is the root helper the page calls (one JSON request on
stdin, one JSON reply; /usr/local/libexec/woowtech-cockpit-backup inside dev-d), with the engine of THIS tree
installed by deploy-src.sh:

  setup      the schedule timer masked (shared lab), deploy-src.sh d --src <this tree> --no-demo-catalog, installed
             engine == tree (SHA-256 of every module and the helper); the `headscale` catalog entry is the one
             carried by dev-d's own Headscale baseline backup 20261119T072939Z-d52b60b2 (inspect with dev-d's 11-19
             emergency kit, then catalog-install of exactly that entry); key-init (the new kit is never read)
  lab config dev-d's Headscale (the WOOWTECH Podman package's installed units headscale/headplane/headscale-entrance,
             server_url http://localhost:28080) cannot start in a network-none lab: its DERP map is empty and
             Headscale 0.29.4 refuses that (hscontrol/app.go:656 errEmptyInitialDERPMap). For the run only its
             config.yaml gets the embedded DERP region 999 (urls: [] kept, nothing else changed); the original file
             is kept next to it and written back at the end (stated simulation)
  before     dev-d's own markers (batch1_markers.py read: woowbk-lab-baseline user, pre-auth key, node, DNS record)
             and the server state (users, nodes, API key prefixes, DNS records, public Noise key)
  upload     upload-begin, the file copied to the path the helper gave, upload-finish (strict outer check, SHA-256
             of every byte, hastore.publish): the HA store record is the fixture (id from its SHA-256)
  check      ha-check-start headscale: job succeeded, no blocker, arch/add-on/target versions, the section equals
             the recorded source facts, no throwaway object left
  import     the real free space and the product's own floor (running reserve + watch margin) recorded, then
             ha-convert-start (the convert job's SpaceGuard/Watchdog are the product's, nothing simulated),
             inspect (preflight), restore-start (safety backup, in place, health checks)
  verify     users, nodes (ids, users, addresses), approved route, HA's pre-auth keys, the DNS record, only this
             device's API key prefixes (identity = prefix: hscontrol/db/api_key.go:262, types/api_key.go:22-23;
             the row id is a new autoincrement) and it works, HA's Headplane API key does NOT, HA's Noise key
             (content SHA-256 and public key), metrics/health, engine status, the catalog health URLs
  clients    arm: the REAL tailscale client state made against the RPi5's Headscale (lab volume b1-ts-alice-state,
             node b1-ts-alice) re-pointed with `tailscale up --login-server=http://localhost:28080` and NO auth key:
             same node id, node key and addresses, no new node, the DNS record through the client; both arches:
             new device(s) join with HA's reusable pre-auth key (read through the b1 harness reader, handed over in
             a 0600 file, never argv) and exchange pings through the DERP region
  restart    systemctl --user restart headscale.service: server state again, every client reconnects by itself
  rollback   (a) automatic: a second restore of the converted backup with a one-shot ExecStartPre failure must end
             `rolled-back` and leave HA's imported state (and the clients) as they were; (b) the first restore's
             safety backup restored: dev-d's own markers are back, nothing of HA's left
  cleanup    clients removed, the original config.yaml back (sha256 equal), drop-in/marker gone, the test's
             converted and safety backups deleted, the catalog entry removed again when this run installed it, HA
             store records this run created deleted, no job container/volume/network, staging or key file
  leaks      every registered value (HA pre-auth keys, HA's Noise key and Headplane API key/cookie, the real
             client's private keys, every new device's keys, each server volume's Noise/DERP keys, dev-d's
             Headscale Podman secrets, the kit) is looked for in the engine's records, uploads, staging, run dir,
             the whole device journal, the client logs and this run's private evidence: 0 hits

stdout carries only fixed lines (`<check>: PASS|FAIL`, the isolation line, the source commit, lock time); details
go to the private, redacted evidence folder ~/.woowbk-lab/evidence/services-a-2-hsff/<time>/ (0700).
Clients: each tailscaled (userspace networking) runs as a transient unit of dev-d in a FRESH network namespace whose
only way out is a relay from its 127.0.0.1:28080 to dev-d's 127.0.0.1:28080 (= server_url http://localhost:28080), and
a veth pair with a TEST-NET address and no peer: tailscale pauses its control client while no non-loopback interface
is up (attempt 2 on 11-23: a client in dev-d's loopback-only namespace stayed in NeedsLogin, `control: setPaused(true)`).
Not covered (stated): the browser page itself (dev-d publishes no port; the helper calls are the page's), Headplane's
UI, a host reboot, a client on another machine (DERP over plain HTTP via TS_DEBUG_USE_DERP_HTTP), HA's second node
(no live client).
"""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
HOLD_BUDGET = 30 * 60          # no new phase after this many seconds of holding the lock (cleanup fits in 40 min)
MIN_DEVICE_HEADROOM = 1280 * 1024 * 1024
MIN_HOST_AVAILABLE_KIB = 1024 * 1024
MIN_DISK_FREE = 13 * 1024 ** 3  # the team keeps >= 12 GiB free at every moment (plus the upload copy)
BASELINE = '20261119T072939Z-d52b60b2'   # dev-d's own Headscale baseline backup (11-19 device key)
OLD_KIT = LAB / 'secrets' / 'dev-d-kit.txt'
TIMER = 'woowtech-cockpit-backup-schedule.timer'
FIXTURE_SHA = {'arm': '1e6a4665315bc69fd114f8d43f7d429aecab53f07d07793ecf8c2c057a92c5d4',
               'x86': '3871a468e2f3a11488df7c6a00a4a8ed7c5b89c3ba2dbc2903ec3bd677013516'}
HS_URL = 'http://localhost:28080'
CONFIG_REL = '.config/headscale/headscale/config.yaml'
ORIG_REL = CONFIG_REL + '.services-a2-orig'
UNITS = ('headscale.service', 'headplane.service', 'headscale-entrance.service')
DROPIN_DIR_REL = '.config/systemd/user/headscale.service.d'
DROPIN_REL = DROPIN_DIR_REL + '/zz-services-a2-fail-once.conf'
MARKER_REL = '.services-a2-fail-once'
PRIVATE_RE = re.compile(r'/home/appowner/\.services-a2-hsff\.[A-Za-z0-9]{8}')
CLIENT_PREFIX = 'woowbk-hsff-'
# The clients are the tailscale 1.104.7 binaries of the lab image that made the real client's state
# (~/.woowbk-lab/run/b1-import/ts-bin, copied out of b1-ts-alice; dev-d's tailscale image is the same version).
TS_BIN = LAB / 'run' / 'b1-import' / 'ts-bin'
TS_SHA = {'tailscale': '27727240e017011fa068', 'tailscaled': 'feb7193e43600f6c2e70'}   # sha256 prefixes
CLIENT_ROOT = '/var/lib/woowbk-hsff'    # root 0700 in dev-d: binaries, relay, each client's state, client logs
CLIENT_RUN = '/run/woowbk-hsff'         # each client's relay socket and tailscaled socket
HS_SECRETS = ['headscale-headplane-api-key', 'headscale-headplane-cookie', 'headscale-entrance-password']
BASE_MARKERS = {'users:woowbk-lab-baseline', 'preauthkeys:woowbk-lab-baseline', 'nodes:woowbk-lab-baseline',
                'dns_records:woowbk-lab-baseline.ts.local'}
LAB_DERP = '''derp:
  # services-a-2 lab run only (dev-d has network none): the embedded DERP region instead of the public map URL.
  server:
    enabled: true
    region_id: 999
    region_code: lab
    region_name: Isolated lab
    stun_listen_addr: 0.0.0.0:3478
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: 127.0.0.1
  urls: []
  paths: []
  auto_update_enabled: false
  update_frequency: 24h
'''
SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ,()/:'<>.=_-]")


def _load_driver():
    spec = importlib.util.spec_from_file_location('ha_import_b1_e2e', HERE / 'ha_import_b1_e2e.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_guard():
    spec = importlib.util.spec_from_file_location('dev_d_guard', HERE / 'dev_d_guard.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drv = _load_driver()
guard = _load_guard()
Failed = drv.Failed
drv.state_path = lambda: LAB / 'run' / 'headscale_full_flow.json'   # never the b1 driver's own state file


# ---------------------------------------------------------------- fixed output and private evidence

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


# ---------------------------------------------------------------- pure helpers (unit-tested)

def lab_config(original):
    """`original` with its one top-level `derp:` block replaced by LAB_DERP (nothing else changes)."""
    lines = original.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if re.match(r'derp:\s*(#.*)?$', line.rstrip('\n'))]
    if len(starts) != 1:
        raise Failed('the live Headscale config has no single top-level derp block')
    start = starts[0]
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or lines[end][:1] in (' ', '\t', '#')):
        end += 1
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    if any(re.match(r'(server_url|listen_addr|prefixes|database|noise|dns|policy):', line) for line in
           lines[start + 1:end]):
        raise Failed('unexpected keys inside the derp block')
    return ''.join(lines[:start]) + LAB_DERP + ''.join(lines[end:])


def state_private_keys(data):
    """Private key strings (privkey:/nlpriv:) of a tailscaled.state file (JSON of base64 values)."""
    found = set()
    try:
        doc = json.loads(data)
    except ValueError:
        raise Failed('client state is not JSON') from None
    if not isinstance(doc, dict):
        raise Failed('client state is not an object')

    def walk(value):
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str):
            for match in re.findall(r'(?:privkey|nlpriv):[0-9a-f]{64}', value):
                if set(match.split(':', 1)[1]) != {'0'}:
                    found.add(match)

    for raw in doc.values():
        try:
            decoded = base64.b64decode(raw, validate=True).decode('utf-8', 'replace')
        except (ValueError, TypeError):
            continue
        if decoded.startswith('{'):
            try:
                walk(json.loads(decoded))
            except ValueError:
                walk(decoded)
        else:
            walk(decoded)
    return sorted(found)


def ha_member_secrets(fixture):
    """HA's Noise key, Headplane API key and cookie secret from the plain b1 backup's Headscale member, in memory
    (streamed: the member also carries the add-on image). Returns ({name: value}, sha256 of the Noise key text)."""
    wanted = {'data/noise_private.key': 'HA_HS_NOISE_KEY', 'data/.headplane_api_key': 'HA_HEADPLANE_API_KEY',
              'data/.headplane_cookie_secret': 'HA_HEADPLANE_COOKIE'}
    values = {}
    with tarfile.open(fixture, 'r:') as outer:
        member = next((m for m in outer.getmembers() if m.name.endswith('_woow-headscale.tar.gz')), None)
        if member is None:
            raise Failed('no Headscale member in the HA backup')
        stream = outer.extractfile(member)
        with tarfile.open(fileobj=stream, mode='r|gz') as inner:
            for entry in inner:
                name = entry.name[2:] if entry.name.startswith('./') else entry.name
                if name in wanted and entry.isfile() and entry.size <= 4096:
                    values[wanted[name]] = inner.extractfile(entry).read().decode('ascii').strip()
    if set(values) != set(wanted.values()) or not re.fullmatch(r'privkey:[0-9a-f]{64}', values['HA_HS_NOISE_KEY']):
        raise Failed('HA Headscale member secrets not found')
    return values, hashlib.sha256(values['HA_HS_NOISE_KEY'].encode()).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def fixture_path(arch):
    name = f'woow-b1-{arch}-plain'
    return drv.FIXTURES / arch / name / f'{name}.tar'


def node_rows(probe):
    """{given_name: (id, user, ips, routes, online)} of a probe's node list."""
    return {n[1]: (n[0], n[2], n[3], n[4], n[5]) for n in probe.get('nodes') or [] if isinstance(n, list)}


def expected_nodes(src):
    return {n['given_name']: (n['id'], n['user'], n['ip_addresses']) for n in src['nodes']}


def ha_nodes_match(probe, src):
    rows = node_rows(probe)
    return all(name in rows and rows[name][:3] == want for name, want in expected_nodes(src).items())


# ---------------------------------------------------------------- device programs

HS_PROBE = drv.PROBE_COMMON + r'''
out = {}
def hs(*args):
    rc, so, se = pexec("headscale", "headscale", *args, "-o", "json")
    if rc != 0:
        return {"error": "rc %d" % rc}
    try:
        return json.loads(so) if so.strip() else []
    except ValueError:
        return {"error": "json"}
code, _ = call("http://127.0.0.1:28080", "GET", "/health", raw=True, wait=REQ.get("wait", 120))
out["health"] = code
code, _ = call("http://127.0.0.1:29090", "GET", "/metrics", raw=True, wait=30)
out["metrics"] = code
users = hs("users", "list")
out["users"] = sorted([u.get("id"), u.get("name")] for u in users if isinstance(u, dict)) if isinstance(users, list) else users
nodes = hs("nodes", "list")
out["nodes"] = sorted([n.get("id"), n.get("given_name"), (n.get("user") or {}).get("name"), n.get("ip_addresses"),
                       n.get("approved_routes"), bool(n.get("online")), sorted(n.get("tags") or [])]
                      for n in nodes if isinstance(n, dict)) if isinstance(nodes, list) else nodes
keys = hs("apikeys", "list")
out["apikeys"] = sorted([k.get("id"), k.get("prefix")] for k in keys if isinstance(k, dict)) if isinstance(keys, list) else keys
pak = hs("preauthkeys", "list")
out["preauthkeys"] = sorted([k.get("id"), (k.get("user") or {}).get("name"), bool(k.get("reusable")), bool(k.get("used")),
                             sorted(k.get("acl_tags") or [])] for k in pak if isinstance(k, dict)) if isinstance(pak, list) else pak
rc, so, se = pexec("headscale", "cat", "/var/lib/headscale/extra_records.json")
try:
    out["dns_records"] = sorted([r.get("name"), r.get("type"), r.get("value")] for r in json.loads(so or "[]"))
except ValueError:
    out["dns_records"] = "unreadable"
rc, so, se = pexec("headscale", "cat", "/var/lib/headscale/noise_private.key")
out["noise_text_sha256"] = hashlib.sha256(so.strip().encode()).hexdigest() if rc == 0 and so.strip() else None
code, body = call("http://127.0.0.1:28080", "GET", "/key?v=120")
out["server_public_key"] = (body or {}).get("publicKey")
code, body = call("http://127.0.0.1:28080", "GET", "/api/v1/node", token=secret("headscale-headplane-api-key"))
out["api_device_key"] = [code, len((body or {}).get("nodes") or [])]
if REQ.get("ha_api_key"):
    code, body = call("http://127.0.0.1:28080", "GET", "/api/v1/node", token=REQ["ha_api_key"])
    out["api_ha_key"] = code
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
print(json.dumps({"total": int(st.total_bytes()), "reserve_bytes": int(paths.reserve_bytes), "running_reserve": int(reserve),
                  "watch_margin": int(haimport.WATCH_MARGIN), "floor": int(reserve + haimport.WATCH_MARGIN),
                  "free": free, "min_free": min(free.values())}))
'''

# Keeps the Noise and DERP keys of the CURRENT headscale-data volume (read from its export) in the run's private
# directory (0600) so the final scan looks for them; values never leave dev-d.
KEEP_KEYS = r'''
import json, os, subprocess, sys, tarfile, io
req = json.loads(sys.stdin.read())
private = req["private"]
p = subprocess.run(["podman", "volume", "export", "headscale-data"], capture_output=True, timeout=300)
if p.returncode != 0:
    raise SystemExit("volume export failed")
kept = []
with tarfile.open(fileobj=io.BytesIO(p.stdout), mode="r:") as tar:
    for m in tar.getmembers():
        name = m.name[2:] if m.name.startswith("./") else m.name
        if name in ("noise_private.key", "derp_server_private.key") and m.isfile() and m.size <= 4096:
            kept.append(tar.extractfile(m).read().decode("ascii", "replace").strip())
path = os.path.join(private, "keys.json")
old = json.load(open(path)) if os.path.exists(path) else []
fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as h:
    json.dump(sorted(set(old) | set(k for k in kept if k)), h)
os.replace(path + ".new", path)
print(json.dumps({"kept": len([k for k in kept if k])}))
'''

# relay.py outer <unix socket> <host> <port>            : unix socket -> TCP host:port (dev-d's network namespace)
# relay.py inner <unix socket> <port> <address> -- <cmd...> : in a FRESH network namespace: lo up, a veth pair with
#   <address>/24 and a default route (no peer: nothing is reachable through it; tailscale only needs an interface
#   that is up), 127.0.0.1/::1:<port> -> unix socket, then <cmd> (tailscaled) runs there.
RELAY = r'''
import os, socket, subprocess, sys, threading
def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
def serve(listener, connect):
    while True:
        conn, _ = listener.accept()
        try:
            peer = connect()
        except OSError:
            conn.close()
            continue
        threading.Thread(target=pipe, args=(conn, peer), daemon=True).start()
        threading.Thread(target=pipe, args=(peer, conn), daemon=True).start()
mode, path = sys.argv[1], sys.argv[2]
if mode == "outer":
    host, port = sys.argv[3], int(sys.argv[4])
    if os.path.exists(path):
        os.remove(path)
    ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ls.bind(path)
    os.chmod(path, 0o600)
    ls.listen(64)
    serve(ls, lambda: socket.create_connection((host, port), timeout=10))
else:
    port, address = int(sys.argv[3]), sys.argv[4]
    cmd = sys.argv[sys.argv.index("--") + 1:]
    for argv in (["ip", "link", "set", "lo", "up"],
                 ["ip", "link", "add", "hsff0", "type", "veth", "peer", "name", "hsff1"],
                 ["ip", "addr", "add", address + "/24", "dev", "hsff0"],
                 ["ip", "link", "set", "hsff1", "up"], ["ip", "link", "set", "hsff0", "up"],
                 ["ip", "route", "add", "default", "dev", "hsff0"]):
        subprocess.run(argv, check=True)
    def unix():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path)
        return s
    for family, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        try:
            ls = socket.socket(family, socket.SOCK_STREAM)
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind((addr, port))
            ls.listen(64)
        except OSError as error:
            if family == socket.AF_INET:
                raise
            print("relay: no IPv6 loopback listener:", error.errno, flush=True)
            continue
        threading.Thread(target=serve, args=(ls, unix), daemon=True).start()
    sys.exit(subprocess.call(cmd))
'''

# A new device joins with a pre-auth key: the key goes into a root 0600 file of its state directory, `tailscale up
# --auth-key=file:` reads it, the file is removed at once. Only the exit code comes back.
JOIN = r'''
import json, os, subprocess, sys
req = json.loads(sys.stdin.read())
path = os.path.join(req["state_dir"], ".authkey")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as h:
    h.write(req["key"])
try:
    p = subprocess.run([req["cli"], "--socket=" + req["socket"], "up", "--login-server=" + req["url"],
                        "--auth-key=file:" + path, "--hostname=" + req["hostname"], "--accept-dns=false", "--timeout=90s"],
                       capture_output=True, timeout=150)
    rc = p.returncode
finally:
    os.unlink(path)
print(json.dumps({"rc": rc, "removed": not os.path.exists(path)}))
'''

LEAKS = 'import json\n' + __import__('inspect').getsource(drv.secret_scan_needles) + r'''
import base64, glob, os, re, subprocess, sys
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
private = req["private"]
kept = json.load(open(os.path.join(private, "keys.json")))
for i, value in enumerate(kept):
    secrets["volume:%d" % i] = value.encode()
states = sorted(glob.glob(os.path.join(req["client_root"], "*", "tailscaled.state")))
if len(states) != req["clients"]:
    raise RuntimeError("client state files missing")
for path in states:
    doc = json.load(open(path))
    found = set()
    for raw in doc.values():
        try:
            text = base64.b64decode(raw).decode("utf-8", "replace")
        except Exception:
            continue
        for m in re.findall(r"(?:privkey|nlpriv):[0-9a-f]{64}", text):
            if set(m.split(":", 1)[1]) != {"0"}:
                found.add(m)
    if not found:
        raise RuntimeError("no private key in a client state")
    for i, value in enumerate(sorted(found)):
        secrets["client:%s:%d" % (os.path.basename(os.path.dirname(path)), i)] = value.encode()
needles = secret_scan_needles(secrets.values())
hits, scanned = 0, 0
roots = ["/var/lib/woowtech-backup/jobs", "/var/lib/woowtech-backup/ha-backups", "/var/lib/woowtech-backup/ha-imports.json",
         "/var/lib/woowtech-backup/archives", "/run/woowtech-backup", "/var/lib/woowtech-backup/uploads",
         "/var/lib/woowtech-backup/staging", "/var/lib/woowtech-backup/requests.json", "/var/lib/woowtech-backup/pending",
         "/var/lib/woowtech-backup/exports", os.path.join(req["client_root"], "logs")]
for root in roots:
    if not os.path.exists(root) or os.path.islink(root):
        raise RuntimeError("required scan root missing or unsafe")
    paths = [root] if os.path.isfile(root) else []
    if os.path.isdir(root):
        def walk_error(error):
            raise RuntimeError("scan enumeration failed") from error
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
logs = len(os.listdir(os.path.join(req["client_root"], "logs")))
journal = subprocess.run(["journalctl", "-o", "cat", "--no-pager"], capture_output=True, check=True).stdout
hits += sum(journal.count(s) for s in needles)
print(json.dumps({"scanned": scanned, "client_logs": logs, "journal_bytes": len(journal), "names": len(secrets),
                  "volume_keys": len(kept), "client_states": len(states), "hits": hits}))
'''


# ---------------------------------------------------------------- device helpers

def owner_ok(*argv, timeout=600):
    proc = drv.owner(*argv, timeout=timeout)
    if proc.returncode != 0:
        raise Failed(f'owner command failed: {argv[0]} {argv[1] if len(argv) > 1 else ""} (rc {proc.returncode})')
    return drv.out(proc)


def write_owner_file(rel, data, mode='0644'):
    """Atomic write of a file in appowner's home (as appowner)."""
    if not re.fullmatch(r'[A-Za-z0-9_./-]{1,200}', rel) or '..' in rel.split('/'):
        raise Failed('unsafe owner path')
    proc = drv.owner('sh', '-c', 'umask 077; cat > "$HOME/$1.new" && chmod "$2" "$HOME/$1.new" && mv -f "$HOME/$1.new" '
                     '"$HOME/$1"', 'sh', rel, mode, input=data, timeout=120)
    if proc.returncode != 0:
        raise Failed('owner file write failed')


def read_owner_file(rel):
    proc = drv.owner('cat', f'/home/appowner/{rel}', timeout=60)
    if proc.returncode != 0:
        raise Failed('owner file read failed')
    return proc.stdout


def owner_exists(rel):
    return drv.owner('test', '-e', f'/home/appowner/{rel}', timeout=60).returncode == 0


def unit_state(unit):
    return drv.out(drv.owner('systemctl', '--user', 'is-active', unit, timeout=60)).strip()


def wait_units(ev, label_text, units=UNITS, timeout=240):
    deadline = time.monotonic() + timeout
    states = {}
    while time.monotonic() < deadline:
        states = {u: unit_state(u) for u in units}
        if all(s == 'active' for s in states.values()):
            break
        time.sleep(3)
    return ev.check(f'{label_text}: headscale, headplane and headscale-entrance are active', all(
        s == 'active' for s in states.values()), states)


def probe(ev, label_text, *, ha_api_key=None, wait=120):
    request = {'wait': wait}
    if ha_api_key:
        request['ha_api_key'] = ha_api_key
    result = drv.device_python(HS_PROBE, request, timeout=600)
    ev.save(f'probe-{re.sub(r"[^a-z0-9-]", "-", label_text.lower())[:60]}.json', result)
    return result


def markers(ev, label_text):
    proc = drv.run([drv.LP, 'exec', '-i', drv.DEVICE, drv.OWNER, 'python3', '-I', '-c', drv.MARKERS, 'headscale', 'read'],
                   input=b'{}', timeout=600)
    try:
        found = json.loads(drv.out(proc).strip().splitlines()[-1])
    except (ValueError, IndexError):
        found = {'error': f'rc {proc.returncode}'}
    ev.save(f'markers-{re.sub(r"[^a-z0-9-]", "-", label_text.lower())[:60]}.json', found)
    return drv.marker_names(found)


def keep_volume_keys(ev, private, label_text):
    proc = drv.run([drv.LP, 'exec', '-i', drv.DEVICE, drv.OWNER, 'python3', '-I', '-c', KEEP_KEYS],
                   input=json.dumps({'private': private}).encode(), timeout=600)
    try:
        kept = json.loads(drv.out(proc).strip().splitlines()[-1]).get('kept')
    except (ValueError, IndexError):
        kept = None
    ev.check(f'{label_text}: the server volume\'s Noise/DERP keys are registered for the leak scan (kept in the '
             'private run folder)', proc.returncode == 0 and isinstance(kept, int) and kept >= 1, {'kept': kept})


def app_status(ev, label_text):
    status = drv.ok('status', ev=ev)
    state = next((a for a in status.get('apps') or [] if a['id'] == 'headscale'), {})
    return ev.check(f'{label_text}: engine status: headscale running, no problems',
                    state.get('state') == 'running' and not state.get('problems'),
                    {k: state.get(k) for k in ('state', 'problems')})


# ---------------------------------------------------------------- the run

class Run:
    def __init__(self, args, ev):
        self.args = args
        self.ev = ev
        self.arch = args.arch
        self.src = drv.source(self.arch)['headscale']
        self.fixture = fixture_path(self.arch)
        self.private = None
        self.original_config = None
        self.installed_entry = False
        self.created_store = None
        self.clients = []          # client names (real, new1, new2): transient units woowbk-hsff-<name>-ts/-relay
        self.client_dirs = False
        self.client_states = 0
        self.dropin = False
        self.lock_started = time.monotonic()
        self.before = {}
        self.converted = self.safety = self.store_id = self.real = self.kit = self.ha_noise_sha = None
        self.found_state = None

    # -------- guards
    def budget(self, phase):
        if time.monotonic() - self.lock_started > HOLD_BUDGET:
            raise Failed(f'lock hold budget reached before {phase}')

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
            raise Failed('host MemAvailable below 1 GiB')
        if free - self.fixture.stat().st_size < MIN_DISK_FREE:
            raise Failed('host disk free below the reserve')

    # -------- secrets
    def load_secrets(self):
        s = self.args.secrets
        for name in (f'B1_{self.arch.upper()}_HS_KEY_BOB_REUSABLE', f'B1_{self.arch.upper()}_HS_KEY_ALICE_SINGLE'):
            if not s.values.get(name, '').startswith('hskey-auth-'):
                raise Failed('unexpected HA pre-auth key format')
        values, noise_sha = ha_member_secrets(self.fixture)
        for name, value in values.items():
            s.register(name, value)
        self.ha_noise_sha = noise_sha
        if self.arch == 'arm':
            state = (LAB / 'storage' / 'volumes' / 'b1-ts-alice-state' / '_data' / 'tailscaled.state').read_bytes()
            for i, key in enumerate(state_private_keys(state)):
                s.register(f'REAL_CLIENT_KEY_{i}', key)
        kit = OLD_KIT.read_text(encoding='utf-8')
        lines = [line.strip() for line in kit.splitlines() if line.strip().startswith('AGE-SECRET-KEY-')]
        if len(lines) != 1:
            raise Failed('the 11-19 kit does not hold exactly one key line')
        s.register('DEV_D_KIT_1119', lines[0])
        self.kit = kit
        self.ev.check('secrets: HA pre-auth keys, HA Noise key and Headplane API key/cookie, the real client\'s keys and '
                      'the kit registered (in memory only)', True,
                      {'ha_member_values': len(values), 'noise_sha_equals_source_fact':
                       noise_sha == self.src_noise_sha()})

    def src_noise_sha(self):
        return drv.source(self.arch)['headscale']['noise_private_key_sha256']

    # -------- setup
    def setup(self):
        ev = self.ev
        proc = drv.root('systemctl', 'mask', TIMER, timeout=120)
        ev.check('setup: the scheduled-backup timer is masked (shared lab, no schedule)', proc.returncode == 0,
                 drv.out(proc)[-200:])
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
        ev.check('setup: the installed engine is this tree (every module and the helper SHA-256 equal)',
                 not differ and installed.get('helper') == sha256_file(REPO / 'backup-engine' / 'woowtech-cockpit-backup'),
                 {'modules': len(tree), 'differ': differ[:10]})
        status = drv.ok('status', ev=ev)
        version = (REPO / 'VERSION').read_text().strip()
        ev.check('setup: the installed helper answers status with this tree\'s VERSION',
                 status.get('version') == version, {'installed': status.get('version'), 'tree': version})
        catalog = {a['id'] for a in status.get('apps') or []}
        if 'headscale' not in catalog:
            if not self.kit:
                raise Failed('the 11-19 kit is not loaded (secrets phase first)')
            reply = drv.ok('inspect', {'backup_id': BASELINE, 'key': self.kit}, ev=ev, timeout=900)
            apps = (reply.get('preflight') or {}).get('apps') or []
            carried = next((a.get('settings') or {} for a in apps if a.get('id') == 'headscale'), {})
            entry = carried.get('entry')
            ev.check('setup: dev-d\'s Headscale baseline backup opens with the 11-19 emergency kit and carries its '
                     'catalog entry', isinstance(entry, dict) and entry.get('id') == 'headscale'
                     and carried.get('state') == 'missing', {'state': carried.get('state'),
                                                             'owner': (entry or {}).get('owner')})
            if not isinstance(entry, dict):
                raise Failed('no carried Headscale catalog entry')
            ev.save('catalog-entry-headscale.json', entry)
            preview = drv.ok('catalog-install', {'entry': entry}, ev=ev, timeout=300)
            ev.save('catalog-preview.json', preview)
            if not ev.check('setup: catalog-install preview of the carried entry is valid', preview.get('valid') is True,
                            {k: preview.get(k) for k in ('valid', 'errors', 'warnings', 'conflicts')}):
                raise Failed('catalog preview refused')
            done = drv.ok('catalog-install', {'entry': entry, 'confirm': True,
                                              'expected_sha256': preview.get('expected_sha256')}, ev=ev, timeout=300)
            ev.save('catalog-install.json', done)
            self.installed_entry = True
        entry = drv.catalog('headscale')
        ev.save('catalog-headscale-installed.json', entry)
        ev.check('setup: the headscale catalog entry names the package\'s units, both volumes and its health URLs',
                 set(UNITS) <= set(entry.get('units') or []) and sorted(v['name'] for v in entry.get('volumes') or [])
                 == ['headplane-data', 'headscale-data'] and len(entry.get('health') or []) >= 1,
                 {'units': entry.get('units'), 'volumes': [v['name'] for v in entry.get('volumes') or []],
                  'health': [(h.get('url'), h.get('expect_status')) for h in entry.get('health') or []]})
        key = drv.ok('key-init', ev=ev)
        ev.check('setup: a device key exists (key-init; the kit is never read)', bool((key.get('key') or {}).get('key_id')),
                 {'created': key.get('created'), 'key_id': (key.get('key') or {}).get('key_id')})
        stage = owner_ok('mktemp', '-d', '/home/appowner/.services-a2-hsff.XXXXXXXX').strip()
        if not PRIVATE_RE.fullmatch(stage):
            raise Failed('unexpected private directory')
        self.private = stage
        self.client_setup()

    # -------- lab configuration
    def lab_config_on(self):
        ev = self.ev
        if owner_exists(ORIG_REL):
            raise Failed('a previous run left its original config copy; restore it first')
        original = read_owner_file(CONFIG_REL)
        self.original_config = original
        self.original_sha = hashlib.sha256(original).hexdigest()
        write_owner_file(ORIG_REL, original, '0644')
        variant = lab_config(original.decode('utf-8')).encode('utf-8')
        write_owner_file(CONFIG_REL, variant, '0644')
        ev.check('lab config: dev-d\'s Headscale config.yaml gets the embedded DERP region (only the derp block '
                 'changed; the original kept next to it)', read_owner_file(CONFIG_REL) == variant
                 and read_owner_file(ORIG_REL) == original, {'original_sha256': self.original_sha,
                                                              'variant_sha256': hashlib.sha256(variant).hexdigest()})
        proc = drv.owner('systemctl', '--user', 'restart', 'headscale.service', timeout=360)
        ev.check('lab config: systemctl --user restart headscale.service', proc.returncode == 0, f'rc {proc.returncode}')
        wait_units(ev, 'lab config')
        first = probe(ev, 'lab config')
        ev.check('lab config: dev-d\'s own Headscale serves (health 200, metrics 200)',
                 first.get('health') == 200 and first.get('metrics') == 200,
                 {k: first.get(k) for k in ('health', 'metrics')})

    def lab_config_off(self):
        ev = self.ev
        if self.original_config is None:
            return
        write_owner_file(CONFIG_REL, self.original_config, '0644')
        same = hashlib.sha256(read_owner_file(CONFIG_REL)).hexdigest() == self.original_sha
        if same:
            drv.owner('rm', '-f', f'/home/appowner/{ORIG_REL}', timeout=60)
        # --no-block: on the original (empty DERP map) config headscale crash-loops again and headplane's ExecStartPre
        # waits up to 180 s for it -- exactly the state dev-d was found in; nothing to wait for.
        proc = drv.owner('systemctl', '--user', 'restart', '--no-block', *UNITS, timeout=120)
        ev.check('cleanup: the original config.yaml is back (sha256 equal), its copy removed, the units restarted on it',
                 same and not owner_exists(ORIG_REL), {'restart_rc': proc.returncode,
                                                        'states': {u: unit_state(u) for u in UNITS}})
        self.original_config = None

    # -------- before
    def step_before(self):
        ev = self.ev
        have = markers(ev, 'before')
        ev.check('before: dev-d\'s own Headscale markers (woowbk-lab-baseline user, pre-auth key, node, DNS record)',
                 BASE_MARKERS <= have, sorted(have))
        state = probe(ev, 'before', ha_api_key=self.args.secrets['HA_HEADPLANE_API_KEY'])
        self.before = state
        ev.check('before: no HA node and not HA\'s Noise key on dev-d', not any(
            (n[1] or '').startswith('b1-') for n in state.get('nodes') or []) and state.get('server_public_key')
            not in (drv.source('x86')['headscale']['server_public_key'], drv.source('arm')['headscale']['server_public_key'])
            and state.get('api_device_key', [0])[0] == 200, {'nodes': state.get('nodes'), 'apikeys': state.get('apikeys')})
        keep_volume_keys(ev, self.private, 'before')
        app_status(ev, 'before')

    # -------- upload (page path) and check
    def step_upload(self):
        ev = self.ev
        sha = sha256_file(self.fixture)
        ev.check(f'upload {self.arch}-plain: the local file is the recorded b1 fixture (sha256)',
                 sha == FIXTURE_SHA[self.arch], sha[:16])
        if sha != FIXTURE_SHA[self.arch]:
            raise Failed('fixture changed')
        store_id = 'ha-' + sha[:20]
        listed = {h.get('id') for h in drv.ok('list', ev=ev).get('ha_backups') or []}
        started = time.monotonic()
        rc, reply = drv.upload(self.fixture, ev=ev)
        took = time.monotonic() - started
        meta = reply.get('ha_backup') or {}
        ev.save('upload-reply.json', reply)
        ev.check(f'upload {self.arch}-plain: upload-begin, copy, upload-finish answer the HA store record (id from the '
                 'SHA-256)', rc == 0 and meta.get('id') == store_id, {'took_s': round(took, 1), 'id': meta.get('id'),
                                                                     'existed_before': store_id in listed})
        found = {a['app_id']: a['installed'] for a in meta.get('importable_apps') or []}
        ev.check(f'upload {self.arch}-plain: headscale is importable and installed here', found.get('headscale') is True,
                 found)
        stored = json.loads(drv.out(drv.root('cat', f'/var/lib/woowtech-backup/ha-backups/{store_id}.json', check=True)))
        ev.check(f'upload {self.arch}-plain: the stored sidecar names the fixture SHA-256', stored.get('sha256') == sha,
                 {'filename': stored.get('filename')})
        if store_id not in listed:
            self.created_store = store_id
        self.store_id = store_id
        drv.STATE[f'ha_{self.arch}-plain'] = store_id
        if rc != 0 or meta.get('id') != store_id:
            raise Failed('upload refused')

    def step_found_state_check(self):
        """The page's ha-check while dev-d's Headscale is as found (crash-looping on its empty DERP map). Recorded as
        evidence, not assumed: the product's deployment probe looks at Quadlet files, loaded and masked units only
        (adapters/quadlet_postgres.py probe), so the check is expected to report no blocker for a crash-looping
        target; the restore's health checks and automatic rollback are what protect such a device. The check job must
        still finish as a job and leave nothing behind."""
        ev = self.ev
        tag = f'{self.arch}-plain'
        states = {u: unit_state(u) for u in UNITS}
        job, took = drv.run_check(self.store_id, ['headscale'], ev=ev, tag=f'check-found-{tag}-headscale')
        apps = ((job.get('result') or {}).get('ha_check') or {}).get('apps') or [{}]
        result = apps[0]
        self.found_state = {'units': states, 'job_state': job.get('state'), 'ok': result.get('ok'),
                            'blockers': result.get('blockers') or []}
        ev.save('check-found-state.json', {'units': states, 'job_state': job.get('state'), 'result': result})
        leftovers = drv.labelled()
        ev.check('found state: the page\'s ha-check on dev-d\'s crash-looping Headscale finishes as a job and leaves '
                 'nothing (its verdict is recorded)', job.get('state') == 'succeeded' and isinstance(result.get('ok'), bool)
                 and not any(leftovers.values()), {'units': states, 'ok': result.get('ok'),
                                                   'blockers': result.get('blockers'), 'took_s': round(took, 1)})
        emit(json.dumps({'stage': 'found_state_check', 'ha_check_ok': result.get('ok') is True,
                         'blockers': len(result.get('blockers') or []),
                         'headscale_unit': re.sub(r'[^a-z-]', '', states.get('headscale.service', ''))[:20]},
                        sort_keys=True))

    def step_check(self):
        ev = self.ev
        tag = f'{self.arch}-plain'
        job, took = drv.run_check(self.store_id, ['headscale'], ev=ev, tag=f'check-{tag}-headscale')
        if not ev.check(f'check {tag}/headscale: job succeeded', job['state'] == 'succeeded', f'{took:.0f} s {job.get("error")}'):
            raise Failed('check job failed')
        result = job['result']['ha_check']['apps'][0]
        ev.save(f'check-{tag}-headscale.json', result)
        ev.check(f'check {tag}/headscale: ok, no blockers', result.get('ok') is True and not result.get('blockers'),
                 result.get('blockers'))
        ev.check(f'check {tag}/headscale: source {drv.ARCH[self.arch]}, add-on 0.1.3, target 0.29.4',
                 result.get('arch') == drv.ARCH[self.arch] and result.get('version') == '0.1.3'
                 and result.get('target_version') == '0.29.4', {k: result.get(k) for k in ('arch', 'version', 'target_version')})
        drv.compare_check(ev, f'check {tag}/headscale', 'headscale', result, self.arch, True, tag)
        ev.check(f'check {tag}/headscale: the only warning is that HA\'s API key does not move',
                 len(result.get('warnings') or []) == 1 and 'API 金鑰不會搬過來' in result['warnings'][0], result.get('warnings'))
        leftovers = drv.labelled()
        ev.check('check: no throwaway container, volume or network left', not any(leftovers.values()), leftovers)

    # -------- import (convert, inspect, restore)
    def step_import(self):
        ev = self.ev
        tag = f'{self.arch}-plain'
        space = drv.device_python(SPACE, {}, as_owner=False, timeout=120)
        ev.save('space-before-convert.json', space)
        ev.check(f'import {tag}: real space: free space of staging/home/storage above the product\'s floor (running '
                 'reserve + watch margin) the convert job enforces', isinstance(space.get('floor'), int)
                 and space['floor'] >= 2 * 1024 ** 3 and space['min_free'] > space['floor'],
                 {k: space.get(k) for k in ('total', 'running_reserve', 'watch_margin', 'floor', 'min_free')})
        before_ids = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        job, took = drv.convert(self.store_id, ['headscale'], False, ev=ev, key=None, tag=f'convert-{tag}-headscale')
        ev.save('convert-job.json', job)
        if not ev.check(f'import {tag}: ha-convert-start job succeeded with a backup id', job['state'] == 'succeeded'
                        and (job.get('result') or {}).get('backup_id'), f'{took:.0f} s {job.get("error")}'):
            raise Failed('convert failed')
        result = job['result']
        self.converted = result['backup_id']
        drv.created_backup(self.converted)
        phases = [p.get('id') for p in (job.get('progress') or {}).get('phases') or []] or job.get('phases')
        imp = result.get('ha_import') or {}
        ev.check(f'import {tag}: ha_import: apps headscale, not test mode, the Headscale note, reminders name this '
                 'device\'s URL', imp.get('apps') == ['headscale'] and imp.get('test_mode') is False
                 and any('Headscale' in n for n in imp.get('notes') or [])
                 and any(HS_URL in line for line in (imp.get('reminders_by_app') or {}).get('headscale') or []),
                 {k: imp.get(k) for k in ('apps', 'test_mode', 'notes', 'reminders_by_app')})
        listing = drv.ok('list', ev=ev)
        row = next((b for b in listing['backups'] if b['id'] == self.converted), {})
        ev.check(f'import {tag}: the converted backup is listed as manual with its HA origin',
                 self.converted not in before_ids and row.get('type') == 'manual'
                 and (row.get('from_ha') or {}).get('ha_backup_id') == self.store_id,
                 {'type': row.get('type'), 'from_ha': bool(row.get('from_ha')), 'encrypted': row.get('encrypted'),
                  'phases': phases})
        inspect = drv.ok('inspect', {'backup_id': self.converted}, ev=ev, timeout=900)
        pre = inspect.get('preflight') or {}
        failed = [c for c in pre.get('checks') or [] if c.get('status') == 'fail']
        ev.check(f'import {tag}: inspect: preflight passes, settings same, in place',
                 pre.get('ok') and not failed and all((a.get('settings') or {}).get('state') == 'same'
                                                      and a.get('mode') == 'inplace' for a in pre.get('apps') or []),
                 failed[:3] or [(a.get('id'), a.get('mode'), (a.get('settings') or {}).get('state')) for a in
                                pre.get('apps') or []])
        rjob, rtook = drv.restore(self.converted, ['headscale'], ev=ev, tag=f'restore-{tag}-headscale')
        ev.save('restore-job.json', rjob)
        rresult = rjob.get('result') or {}
        self.safety = rresult.get('safety_backup_id')
        drv.created_backup(self.safety)
        health = rresult.get('health') or []
        if not ev.check(f'import {tag}: restore-start of the converted backup succeeded with a safety backup, not rolled '
                        'back, every health check ok', rjob['state'] == 'succeeded' and self.safety
                        and rresult.get('rolled_back') is False and health and all(h.get('status') == 'ok' for h in health),
                        {'state': rjob['state'], 'error': rjob.get('error'), 'safety': self.safety,
                         'health': [(h.get('id'), h.get('status')) for h in health], 'took_s': round(rtook, 1)}):
            raise Failed('restore failed')
        drv.STATE.setdefault('imports', {})[f'{tag}/headscale'] = {'backup_id': self.converted, 'safety': self.safety}
        drv.save_state()

    # -------- verification of the restored server
    def verify(self, label_text, *, extra_nodes=0):
        ev, src = self.ev, self.src
        state = probe(ev, label_text, ha_api_key=self.args.secrets['HA_HEADPLANE_API_KEY'])
        ev.check(f'{label_text}: health 200 and metrics 200', state.get('health') == 200 and state.get('metrics') == 200,
                 {k: state.get(k) for k in ('health', 'metrics')})
        ev.check(f'{label_text}: users default, alice, bob (HA\'s ids)', state.get('users') == src['users'], state.get('users'))
        rows = node_rows(state)
        ev.check(f'{label_text}: HA\'s nodes with their ids, users and addresses', ha_nodes_match(state, src)
                 and len(rows) == len(src['nodes']) + extra_nodes, state.get('nodes'))
        ev.check(f'{label_text}: the approved route 192.168.88.0/24 of b1-bob-nas',
                 (rows.get('b1-bob-nas') or (None,) * 5)[3] == ['192.168.88.0/24'], rows.get('b1-bob-nas'))
        paks = [(k[1], k[2]) for k in state.get('preauthkeys') or [] if isinstance(k, list)]
        ev.check(f'{label_text}: HA\'s pre-auth keys (alice single-use, bob reusable)',
                 sorted(paks) == [('alice', False), ('bob', True)], state.get('preauthkeys'))
        ev.check(f'{label_text}: the DNS extra record b1-nas.ts.local', ['b1-nas.ts.local', 'A', '100.64.0.250']
                 in (state.get('dns_records') or []), state.get('dns_records'))
        before = sorted(k[1] for k in self.before.get('apikeys') or [])
        after = sorted(k[1] for k in state.get('apikeys') or [])
        ev.check(f'{label_text}: only this device\'s API keys are left (same prefixes as before) and its key works; '
                 'HA\'s Headplane API key is refused', after == before and bool(after)
                 and (state.get('api_device_key') or [0])[0] == 200 and state.get('api_ha_key') == 401,
                 {'before': before, 'after': after, 'device_key': state.get('api_device_key'),
                  'ha_key': state.get('api_ha_key'), 'ids_after': [k[0] for k in state.get('apikeys') or []]})
        ev.check(f'{label_text}: HA\'s Noise key is installed (content SHA-256) and served (public key)',
                 state.get('noise_text_sha256') == self.ha_noise_sha == self.src_noise_sha()
                 and state.get('server_public_key') == src['server_public_key'],
                 {'public': state.get('server_public_key')})
        return state

    # -------- clients (tailscaled in its own network namespace, reaching only dev-d's localhost:28080)
    def client_setup(self):
        ev = self.ev
        found = {name: sha256_file(TS_BIN / name) for name in ('tailscale', 'tailscaled')}
        if any(not found[name].startswith(prefix) for name, prefix in TS_SHA.items()):
            raise Failed('the lab tailscale binaries changed')
        if drv.root('test', '-e', CLIENT_ROOT, timeout=60).returncode == 0 or \
                drv.root('test', '-e', CLIENT_RUN, timeout=60).returncode == 0:
            raise Failed('a previous run left its client folders')
        drv.root('install', '-d', '-m', '0700', CLIENT_ROOT, f'{CLIENT_ROOT}/bin', f'{CLIENT_ROOT}/logs', CLIENT_RUN,
                 check=True)
        self.client_dirs = True
        for name in ('tailscale', 'tailscaled'):
            drv.run([drv.LP, 'cp', str(TS_BIN / name), f'{drv.DEVICE}:{CLIENT_ROOT}/bin/{name}'], check=True, timeout=120)
        drv.root('chmod', '0755', f'{CLIENT_ROOT}/bin/tailscale', f'{CLIENT_ROOT}/bin/tailscaled', check=True)
        drv.root('python3', '-I', '-c', 'import sys\nopen(sys.argv[1], "w").write(sys.stdin.read())',
                 f'{CLIENT_ROOT}/relay.py', input=RELAY.encode(), check=True)
        version = drv.out(drv.root(f'{CLIENT_ROOT}/bin/tailscale', 'version', timeout=60)).splitlines()[:1]
        ev.check('setup: the lab tailscale client binaries are staged in dev-d (sha256 as recorded)', version == ['1.104.7'],
                 {'version': version, 'sha256': {k: v[:20] for k, v in found.items()}})

    def client_start(self, client, state_dir, index):
        units = (f'{CLIENT_PREFIX}{client}-relay', f'{CLIENT_PREFIX}{client}-ts')
        drv.root('install', '-d', '-m', '0700', f'{CLIENT_RUN}/{client}', check=True)
        sock = f'{CLIENT_RUN}/{client}/hs.sock'
        proc = drv.root('systemd-run', f'--unit={units[0]}', '--quiet', 'python3', '-I', f'{CLIENT_ROOT}/relay.py', 'outer',
                        sock, '127.0.0.1', '28080', timeout=120)
        if proc.returncode != 0:
            raise Failed(f'client relay {client} did not start')
        self.clients.append(client)
        for _ in range(20):
            if drv.root('test', '-S', sock, timeout=30).returncode == 0:
                break
            time.sleep(0.5)
        proc = drv.root('systemd-run', f'--unit={units[1]}', '--quiet', '--setenv=TS_DEBUG_USE_DERP_HTTP=true',
                        '--setenv=TS_DEBUG_ALWAYS_USE_DERP=true', '--setenv=TS_NO_LOGS_NO_SUPPORT=true',
                        'unshare', '-n', 'python3', '-I', f'{CLIENT_ROOT}/relay.py', 'inner', sock, '28080',
                        f'192.0.2.{10 + index}', '--', f'{CLIENT_ROOT}/bin/tailscaled', '--tun=userspace-networking',
                        f'--state={state_dir}/tailscaled.state', f'--socket={CLIENT_RUN}/{client}/tailscaled.sock',
                        '--no-logs-no-support', '--encrypt-state=false', '--port=0', timeout=120)
        if proc.returncode != 0:
            raise Failed(f'client daemon {client} did not start')
        for _ in range(30):
            if self.ts_status(client).get('BackendState'):
                return
            time.sleep(1)
        raise Failed(f'client daemon {client} did not answer')

    def ts(self, client, *argv, timeout=120):
        return drv.root(f'{CLIENT_ROOT}/bin/tailscale', f'--socket={CLIENT_RUN}/{client}/tailscaled.sock', *argv,
                        timeout=timeout)

    def ts_status(self, client):
        proc = self.ts(client, 'status', '--json')
        try:
            data = json.loads(drv.out(proc))
        except ValueError:
            return {'error': f'rc {proc.returncode}'}
        me = data.get('Self') or {}
        return {'BackendState': data.get('BackendState'), 'AuthURL': bool(data.get('AuthURL')), 'ID': me.get('ID'),
                'HostName': me.get('HostName'), 'TailscaleIPs': me.get('TailscaleIPs'), 'PublicKey': me.get('PublicKey'),
                'Online': me.get('Online'),
                'Peers': sorted([p.get('HostName'), (p.get('TailscaleIPs') or [None])[0], p.get('Online'), p.get('Relay')]
                                for p in (data.get('Peer') or {}).values())}

    def wait_running(self, client, seconds=120):
        deadline = time.monotonic() + seconds
        status = {}
        attempts = 0
        while time.monotonic() < deadline:
            attempts += 1
            status = self.ts_status(client)
            if status.get('BackendState') == 'Running' and status.get('TailscaleIPs') and not status.get('AuthURL'):
                break
            time.sleep(2)
        return status, attempts

    def real_client(self):
        ev = self.ev
        client = drv.source('arm')['tailscale_client']
        volume = LAB / 'storage' / 'volumes' / 'b1-ts-alice-state' / '_data'
        state_dir = f'{CLIENT_ROOT}/real'
        drv.root('install', '-d', '-m', '0700', state_dir, check=True)
        tar = drv.run(['tar', '-C', str(volume), '-cf', '-', '.'], timeout=120, check=True).stdout
        proc = drv.root('tar', '-C', state_dir, '--no-same-owner', '-xf', '-', input=tar, timeout=120)
        if proc.returncode != 0:
            raise Failed('client state copy failed')
        self.client_states += 1
        name = 'real'
        self.client_start(name, state_dir, 0)
        version = drv.out(self.ts(name, 'version')).splitlines()[:1]
        first = {}
        for _ in range(20):
            first = self.ts_status(name)
            if first.get('BackendState') not in (None, 'NoState'):
                break
            time.sleep(1)
        ev.log(f'real client {version}: state right after the start (old server unreachable): {first}')
        ev.check('client arm: the real client starts on its RPi5-made state without reaching its old server',
                 first.get('BackendState') in ('NoState', 'Starting', 'NeedsLogin', 'Stopped', 'Running') and
                 first.get('ID') in (None, '', client['NodeID']), {'state': first.get('BackendState')})
        if first.get('BackendState') == 'Running':
            self.ts(name, 'down')
        started = time.monotonic()
        proc = self.ts(name, 'up', f'--login-server={HS_URL}', '--hostname=b1-ts-alice', '--accept-dns=false',
                       '--timeout=90s', timeout=150)
        took = time.monotonic() - started
        up_text = (drv.out(proc) + proc.stderr.decode('utf-8', 'replace'))[-800:]
        ev.check('client arm: tailscale up --login-server=<this device> (no auth key, no --force-reauth) succeeds',
                 proc.returncode == 0, f'rc {proc.returncode} in {took:.1f} s: {up_text}')
        after, attempts = self.wait_running(name)
        ev.save('real-client-status.json', {'before': first, 'after': after, 'up_output': up_text})
        ev.check('client arm: Running again as the same node (id, node key, addresses), no login URL',
                 after.get('BackendState') == 'Running' and not after.get('AuthURL') and after.get('ID') == client['NodeID']
                 and after.get('PublicKey') == client['NodePublicKey'] and after.get('TailscaleIPs') == client['TailscaleIPs'],
                 {'after': after, 'attempts': attempts})
        prefs = drv.out(self.ts(name, 'debug', 'prefs'))
        try:
            control = json.loads(prefs).get('ControlURL')
        except ValueError:
            control = None
        ev.check('client arm: the client\'s control server is now this device\'s URL', control == HS_URL, control)
        state = probe(ev, 'client arm')
        rows = node_rows(state)
        alice = rows.get('b1-ts-alice')
        ev.check('client arm: this device lists b1-ts-alice online with HA\'s id 2 and 100.64.0.2, no new node',
                 alice is not None and alice[0] == 2 and alice[4] is True and alice[2] == client['TailscaleIPs']
                 and len(rows) == len(self.src['nodes']), state.get('nodes'))
        query = self.ts(name, 'dns', 'query', 'b1-nas.ts.local', 'A')
        text = drv.out(query) + query.stderr.decode('utf-8', 'replace')
        ev.check('client arm: the DNS extra record resolves through the client (b1-nas.ts.local -> 100.64.0.250)',
                 '100.64.0.250' in text, text[-300:])
        self.real = name

    def new_device(self, index):
        ev = self.ev
        name = f'new{index}'
        state_dir = f'{CLIENT_ROOT}/{name}'
        drv.root('install', '-d', '-m', '0700', state_dir, check=True)
        self.client_states += 1
        self.client_start(name, state_dir, index)
        key = self.args.secrets[f'B1_{self.arch.upper()}_HS_KEY_BOB_REUSABLE']
        result = drv.device_python(JOIN, {'state_dir': state_dir, 'key': key, 'url': HS_URL, 'hostname': f'hsff-new{index}',
                                          'cli': f'{CLIENT_ROOT}/bin/tailscale',
                                          'socket': f'{CLIENT_RUN}/{name}/tailscaled.sock'},
                                   as_owner=False, timeout=300)
        status, attempts = self.wait_running(name)
        ok = result.get('rc') == 0 and result.get('removed') is True and status.get('BackendState') == 'Running'
        ev.check(f'client {self.arch}: new device {index} joins with HA\'s reusable pre-auth key (key file removed)', ok,
                 {'rc': result.get('rc'), 'removed': result.get('removed'), 'state': status.get('BackendState'),
                  'ips': status.get('TailscaleIPs'), 'attempts': attempts})
        return name, status

    def derp_ping(self, source, target_ip, label_text):
        deadline = time.monotonic() + 90
        text = ''
        attempts = 0
        while time.monotonic() < deadline:
            attempts += 1
            proc = self.ts(source, 'ping', '--c=1', '--timeout=3s', '--until-direct=false', target_ip, timeout=30)
            text = drv.out(proc) + proc.stderr.decode('utf-8', 'replace')
            if proc.returncode == 0 and 'via DERP(lab)' in text:
                break
            time.sleep(2)
        ok = 'via DERP(lab)' in text
        pongs = 0
        if ok:
            for _ in range(10):
                proc = self.ts(source, 'ping', '--c=1', '--timeout=3s', '--until-direct=false', target_ip, timeout=30)
                pongs += int(proc.returncode == 0 and 'pong' in drv.out(proc))
        ev = self.ev
        ev.check(f'{label_text}: pings through the embedded DERP region (10/10 pongs)', ok and pongs == 10,
                 {'attempts': attempts, 'pongs': pongs, 'last': text[-200:]})

    def clients_phase(self):
        ev = self.ev
        if self.arch == 'arm':
            self.real_client()
            new1, status1 = self.new_device(1)
            peers = [self.real]
            self.verify('clients arm (real client and one new device)', extra_nodes=1)
            self.derp_ping(self.real, (status1.get('TailscaleIPs') or [''])[0], 'client arm: real client -> new device')
        else:
            new1, status1 = self.new_device(1)
            new2, status2 = self.new_device(2)
            peers = [new2]
            self.verify('clients x86 (two new devices)', extra_nodes=2)
            self.derp_ping(new2, (status1.get('TailscaleIPs') or [''])[0], 'client x86: new device 2 -> new device 1')
        self.client_names = [c for c in self.clients]
        ev.log(f'clients: {self.client_names} peers {peers}')

    def clients_reconnect(self, label_text):
        ev = self.ev
        results = {}
        deadline = time.monotonic() + 180       # one budget for all clients: a working client is back in seconds
        for name in self.clients:
            status, attempts = self.wait_running(name, seconds=max(5, deadline - time.monotonic()))
            results[name] = (status.get('BackendState'), status.get('ID'), attempts)
        state = probe(ev, f'{label_text} nodes')
        online = {n[1]: n[5] for n in state.get('nodes') or [] if isinstance(n, list)}
        expected_online = (['b1-ts-alice', 'hsff-new1'] if self.arch == 'arm' else ['hsff-new1', 'hsff-new2'])
        deadline = time.monotonic() + 60
        while not all(online.get(n) for n in expected_online) and time.monotonic() < deadline:
            time.sleep(3)
            state = probe(ev, f'{label_text} nodes')
            online = {n[1]: n[5] for n in state.get('nodes') or [] if isinstance(n, list)}
        ev.check(f'{label_text}: every client reconnected by itself (Running, online on the server, same node)',
                 all(r[0] == 'Running' for r in results.values()) and all(online.get(n) for n in expected_online)
                 and (self.arch != 'arm' or results.get('real', (None, None))[1]
                      == drv.source('arm')['tailscale_client']['NodeID']), {'clients': results, 'online': online})

    def clients_stop(self):
        for client in list(self.clients):
            units = [f'{CLIENT_PREFIX}{client}-ts.service', f'{CLIENT_PREFIX}{client}-relay.service']
            drv.root('systemctl', 'stop', *units, timeout=120)
            log = drv.root('journalctl', '-u', units[0], '-o', 'cat', '--no-pager', timeout=120).stdout
            drv.root('python3', '-I', '-c', 'import os, sys\nfd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | '
                     'os.O_TRUNC, 0o600)\nos.write(fd, sys.stdin.buffer.read())', f'{CLIENT_ROOT}/logs/{client}.log',
                     input=log, timeout=120)
            drv.root('systemctl', 'reset-failed', *units, timeout=60)
            self.clients.remove(client)

    # -------- restart and rollbacks
    def step_restart(self):
        ev = self.ev
        started = time.monotonic()
        proc = drv.owner('systemctl', '--user', 'restart', 'headscale.service', timeout=360)
        ev.check('restart: systemctl --user restart headscale.service', proc.returncode == 0,
                 f'rc {proc.returncode} {time.monotonic() - started:.0f} s')
        wait_units(ev, 'restart')
        self.verify('restart', extra_nodes=1 if self.arch == 'arm' else 2)
        self.clients_reconnect('restart')
        keep_volume_keys(ev, self.private, 'restart')

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
        extra = 1 if self.arch == 'arm' else 2
        self.inject_on()
        try:
            job, took = drv.restore(self.converted, ['headscale'], ev=ev, tag=f'restore-inject-{self.arch}-headscale')
        finally:
            consumed = not owner_exists(MARKER_REL)
            self.inject_off()
        ev.save('restore-inject-job.json', job)
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        ev.check('auto rollback: a restore with a one-shot ExecStartPre failure ends rolled-back (automatic rollback, '
                 'the failure was consumed)', job['state'] == 'rolled-back' and result.get('rolled_back') is True
                 and consumed, {'state': job['state'], 'error': job.get('error'), 'took_s': round(took, 1),
                                'safety': result.get('safety_backup_id')})
        ev.check('auto rollback: the injected drop-in and marker are gone', not self.dropin, '')
        wait_units(ev, 'auto rollback')
        self.verify('auto rollback', extra_nodes=extra)
        self.clients_reconnect('auto rollback')
        app_status(ev, 'auto rollback')

    def step_rollback_to_own(self):
        ev = self.ev
        job, took = drv.restore(self.safety, ['headscale'], ev=ev, tag=f'rollback-{self.arch}-headscale')
        ev.save('rollback-job.json', job)
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        health = result.get('health') or []
        ev.check('rollback: restore-start of the import\'s safety backup succeeded, every health check ok',
                 job['state'] == 'succeeded' and result.get('rolled_back') is False and health
                 and all(h.get('status') == 'ok' for h in health),
                 {'state': job['state'], 'error': job.get('error'), 'took_s': round(took, 1),
                  'health': [(h.get('id'), h.get('status')) for h in health]})
        wait_units(ev, 'rollback')
        have = markers(ev, 'rollback')
        ev.check('rollback: dev-d\'s own markers are back (batch1_markers.py read)', BASE_MARKERS <= have, sorted(have))
        state = probe(ev, 'rollback', ha_api_key=self.args.secrets['HA_HEADPLANE_API_KEY'])
        keep = ('users', 'nodes', 'apikeys', 'preauthkeys', 'dns_records', 'server_public_key', 'noise_text_sha256')
        differ = [k for k in keep if state.get(k) != self.before.get(k) and k != 'nodes']
        before_nodes = [n[:5] for n in self.before.get('nodes') or []]
        after_nodes = [n[:5] for n in state.get('nodes') or []]
        ev.check('rollback: dev-d\'s Headscale equals its state before the import (users, nodes, API keys, pre-auth '
                 'keys, DNS records, Noise key); nothing of HA\'s left', not differ and before_nodes == after_nodes
                 and state.get('api_device_key', [0])[0] == 200 and state.get('api_ha_key') == 401,
                 {'differ': differ, 'nodes': after_nodes})
        keep_volume_keys(ev, self.private, 'rollback')
        app_status(ev, 'rollback')

    # -------- cleanup and leaks
    def step_cleanup(self):
        ev = self.ev
        objects = drv.labelled()
        ev.check('cleanup: no throwaway container, volume or network of a job left', not any(objects.values()), objects)
        listing = drv.device_python(drv.RUN_LIST, as_owner=False)
        staging = listing.get(drv.STAGING)
        keys = [n for n in listing.get('/run/woowtech-backup') or [] if isinstance(n, str) and n.startswith('key-')]
        ev.check('cleanup: no staging folder and no key file left', staging in ([], 'missing') and not keys, listing)
        present = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        created = [b for b in drv.STATE.get('created_backups') or [] if b != BASELINE]
        deleted, refused = [], []
        for backup_id in created:
            if backup_id in present:
                rc, _reply = drv.helper('delete', {'backup_id': backup_id})
                (deleted if rc == 0 else refused).append(backup_id)
        left = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        ev.check('cleanup: the test\'s converted and safety backups are deleted, dev-d\'s baseline stays',
                 BASELINE in left and not (left & set(created)), {'deleted': len(deleted), 'refused': refused})
        drv.STATE['created_backups'] = [b for b in drv.STATE.get('created_backups') or [] if b not in deleted]
        if self.created_store:
            rc, _reply = drv.helper('ha-delete', {'ha_backup_id': self.created_store, 'confirm': True})
            ev.check('cleanup: the HA store record this run created is deleted', rc == 0, self.created_store)
        if self.installed_entry:
            preview = drv.ok('catalog-remove', {'id': 'headscale'}, ev=ev)
            rc, reply = drv.helper('catalog-remove', {'id': 'headscale', 'confirm': True,
                                                      'expected_sha256': preview.get('expected_sha256')})
            ev.check('cleanup: the headscale catalog entry this run installed is removed again (catalog as found)',
                     rc == 0, {'rc': rc, 'error': (reply or {}).get('error')})
        drv.save_state()

    def step_leaks(self):
        ev = self.ev
        s = self.args.secrets
        names = [n for n in s.values if n not in s.names and (n.startswith(('B1_ARM_HS_', 'B1_X86_HS_', 'HA_H',
                                                                            'REAL_CLIENT_KEY_', 'DEV_D_KIT_')))]
        request = {'secrets': {n: s[n] for n in names}, 'podman_secrets': HS_SECRETS, 'uid': 1019,
                   'private': self.private, 'clients': self.client_states, 'client_root': CLIENT_ROOT}
        expected = 4 + 3 + (1 if self.arch == 'arm' else 0)
        if len(request['secrets']) < expected:
            raise Failed('a lane secret is missing from the scan request')
        report = drv.device_python(LEAKS, request, as_owner=False, timeout=900)
        host = drv.scan_host_evidence(ev.dir, s)
        ev.save('leaks.json', {'device': report, 'host': host})
        ev.check('leaks: no registered value (HA keys, client keys, volume keys, dev-d Headscale secrets, kit) in the '
                 'engine records, uploads, staging, journal, client logs or this run\'s evidence',
                 isinstance(report, dict) and report.get('hits') == 0 and report.get('scanned', 0) > 0
                 and report.get('volume_keys', 0) >= 2 and report.get('client_states') == self.client_states
                 and report.get('client_logs') == self.client_states and host.get('hits') == 0,
                 {'device': report, 'host': host})

    def remove_private(self):
        gone = True
        if self.private:
            drv.owner('rm', '-rf', '--', self.private, timeout=120)
            gone = drv.owner('test', '-e', self.private, timeout=60).returncode != 0
            if gone:
                self.private = None
        if self.client_dirs:
            drv.root('rm', '-rf', '--', CLIENT_ROOT, CLIENT_RUN, timeout=120)
            left = any(drv.root('test', '-e', path, timeout=60).returncode == 0 for path in (CLIENT_ROOT, CLIENT_RUN))
            self.client_dirs = left
            gone = gone and not left
        return gone


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


def run_all(run):
    ev = run.ev
    phases = [('secrets', run.load_secrets), ('setup', run.setup), ('upload', run.step_upload),
              ('found state', run.step_found_state_check), ('lab config', run.lab_config_on),
              ('before', run.step_before), ('check', run.step_check),
              ('import', run.step_import), ('verify', lambda: run.verify('restore')),
              ('volume keys', lambda: keep_volume_keys(ev, run.private, 'restore')),
              ('status', lambda: (app_status(ev, 'restore'), drv.app_health(ev, 'headscale', 'restore'))),
              ('clients', run.clients_phase), ('restart', run.step_restart),
              ('auto rollback', run.step_auto_rollback)]
    failure = None
    try:
        for name, step in phases:
            run.budget(name)
            ev.log(f'== {name}')
            step()
    except Exception as error:  # noqa: BLE001 - whatever stopped a phase, the cleanup below always runs
        failure = error
        ev.check(f'phase stopped: {type(error).__name__}', False, str(error)[:300])
    # Always: clients off, dev-d's own data back, the lab config back, cleanup, leaks, private folder removed.
    for name, step in (('clients stop', run.clients_stop), ('inject off', run.inject_off)):
        try:
            step()
        except Exception as error:  # noqa: BLE001 - keep cleaning up
            ev.check(f'{name}: ran', False, type(error).__name__)
    if getattr(run, 'safety', None):
        try:
            run.step_rollback_to_own()
        except Exception as error:  # noqa: BLE001
            ev.check('rollback: ran', False, type(error).__name__)
    for name, step in (('lab config off', run.lab_config_off), ('cleanup', run.step_cleanup)):
        try:
            step()
        except Exception as error:  # noqa: BLE001
            ev.check(f'{name}: ran', False, type(error).__name__)
    if run.private:
        try:
            run.step_leaks()
        except Exception as error:  # noqa: BLE001
            ev.check('leaks: ran', False, type(error).__name__)
        ev.check('cleanup: the run\'s private folders (kept keys; client binaries, states and logs) are removed',
                 run.remove_private(), '')
    return failure


def self_check():
    for name, program in (('HS_PROBE', HS_PROBE), ('SPACE', SPACE), ('KEEP_KEYS', KEEP_KEYS), ('RELAY', RELAY),
                          ('JOIN', JOIN), ('LEAKS', LEAKS), ('ENGINE_HASHES', ENGINE_HASHES)):
        compile(program, name, 'exec')
    print('offline self-check passed: 7 embedded programs compiled')


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--self-check', action='store_true')
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--arch', choices=('x86', 'arm'))
    args = parser.parse_args(argv)
    if args.self_check:
        self_check()
        return 0
    if not args.run or not args.arch:
        parser.error('--run --arch x86|arm required')
    clean, dirty = guard.clean_tree(REPO)
    commit = guard.head(REPO)
    emit(f'source commit {commit}')
    if not clean:
        emit('source tree committed: FAIL')
        return 2
    emit('source tree committed: PASS')
    fd, waited = guard.acquire()
    started = time.monotonic()
    emit(f'dev-d mutation lock acquired: PASS (waited {waited} s)')
    rc = 1
    try:
        emit(guard.verify_isolation(HERE / 'owner.sh'))
        args.secrets = drv.Secrets([drv.SECRET_DIR / 'b1-creds.env'], drv.SECRET_DIR / 'dev-d-markers.json')
        ev = Ev(args.secrets, 'services-a-2-hsff')
        drv.STATE.clear()
        drv.load_state()
        drv.STATE['created_backups'] = []
        run = Run(args, ev)
        run.lock_started = started
        run.headroom()
        failure = run_all(run)
        failed = [r for r in ev.results if not r['ok']]
        ev.save('results.json', {'passed': len(ev.results) - len(failed), 'failed': len(failed),
                                 'failed_checks': [r['check'] for r in failed], 'results': ev.results})
        drv.save_state()
        emit(f'headscale full flow {args.arch}: {len(ev.results) - len(failed)}/{len(ev.results)} '
             f'{"PASS" if not failed and failure is None else "FAIL"}')
        rc = 0 if not failed and failure is None else 1
    finally:
        try:
            emit(guard.verify_isolation(HERE / 'owner.sh'))
        except guard.GuardError:
            emit('dev-d isolation after the run: FAIL')
            rc = 1
        emit(f'lock held for {int(time.monotonic() - started)} s')
        os.close(fd)
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
