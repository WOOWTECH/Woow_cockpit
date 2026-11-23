#!/usr/bin/env python3
"""Hermes: the real x86 HA backups -> dev-d's Hermes through the installed product helper (lane hermes-real).

  python3 -I tests/e2e/lab/hermes_real_capture.py <evidence.json> <scope> -- \\
      python3 -I tests/e2e/lab/hermes_real_ha.py <step> [<step> ...]
  python3 -I tests/e2e/lab/hermes_real_ha.py --self-check        (offline; never touches a device or a secret)

The owner authorized real Hermes testing on 2026-11-23. Every step runs inside ONE hold of the dev-d mutation lock
(/tmp/woowbk-dev-d-mutation.lock; never while /tmp/woowbk-dev-d-emqx-main-waiting exists, emqx-main has priority),
with dev-d's outer isolation asserted before and after (owner.sh d --verify-isolation: running, network none, no
published port) and a memory/disk headroom check before each step. A new step is not started after HOLD_BUDGET
seconds or while emqx-main waits, so the lock is never held much longer than 40 minutes.

What is real: dev-d's production-like Hermes v0.22.5 (Quadlet units hermes-agent/-postgres/-redis, image
woow-hermes-agent:v0.22.5-woow4) and the real batch-1 x86 Home Assistant backups of add-on 9c1a67eb_woow-hermes
(plain, encrypted, encrypted-uncompressed; the stored HA files are bound to the local fixtures by SHA-256). The
engine is THIS tree, installed in dev-d by deploy-src.sh; every engine call is the helper command the Cockpit page
sends (root, one JSON request on stdin, one JSON reply): inspect, catalog-install, key-init, ha-check-start,
ha-convert-start, restore-start, job-status, list, status, delete.

Steps (run in the order given):
  setup        deploy this tree (the schedule timer is masked first: dev-d is shared and no schedule is wanted);
               Hermes's catalog entry is the one carried by dev-d's own Hermes baseline backup (inspect with dev-d's
               11-19 emergency kit, then catalog-install of exactly that entry); a device key (key-init; its kit is
               never read: test backups are deleted at cleanup)
  before       dev-d's Hermes before any import: baseline markers (batch1_markers.py read), file owners, state digest
  check        ha-check-start (hermes) on x86-enc, x86-plain, x86-unc; the result equals the recorded source facts
  import:TAG   (TAG = x86-enc | x86-plain | x86-unc) convert, inspect, restore; continuity through Hermes itself
               (dashboard API: sessions, messages, full-text search with FTS5 snippets; FTS5 integrity-check on a copy
               inside the container); the b1 driver's Hermes verification; restart hermes-agent and recheck; roll back
               with the restore's own safety backup; dev-d's baseline is back (markers, digest equal to `before`)
  kit-baseline restore dev-d's own Hermes baseline backup 20261119T072434Z-45b29e52 (made with the 11-19 device key,
               opened with the emergency kit exactly like the page's 輸入緊急金鑰); markers and digest
  cleanup      the test's converted and safety backups deleted; no job container/volume/network, staging or key file
  leaks        no test secret (HA key, b1 test passwords, dev-d's Hermes secrets, the kit) in the engine's records,
               logs, journal or this run's private evidence

stdout carries only fixed status lines (STEP/CHECK/RESULT ...); details go to the private, redacted evidence folder
~/.woowbk-lab/evidence/hermes-real/<time>/ (0700). Secrets are read only by the b1 harness reader (Secrets) and the
kit file, inside this process, and are never printed.
Not covered (stated in the evidence): the browser page itself (dev-d publishes no port; the helper calls are the
page's), a chat with a model (dev-d runs Hermes --no-llm and HA's config points to an HA-internal URL), the ARM side
(Hermes add-on is amd64 only).
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
LOCK = Path('/tmp/woowbk-dev-d-mutation.lock')
WAITING = Path('/tmp/woowbk-dev-d-emqx-main-waiting')
LOCK_WAIT = 3600
HOLD_BUDGET = 30 * 60          # no new step after this many seconds of holding the lock
MIN_DEVICE_HEADROOM = 1536 * 1024 * 1024
MIN_HOST_AVAILABLE_KIB = 1024 * 1024
MIN_DISK_FREE = 13 * 1024 ** 3  # the team keeps >= 12 GiB free at every moment
BASELINE = '20261119T072434Z-45b29e52'   # dev-d's own Hermes baseline backup (11-19 device key)
OLD_KIT = LAB / 'secrets' / 'dev-d-kit.txt'
TIMER = 'woowtech-cockpit-backup-schedule.timer'
TAGS = ('x86-enc', 'x86-plain', 'x86-unc')
STORE_IDS = {'x86-enc': 'ha-f82422e327f151ec819d', 'x86-plain': 'ha-3871a468e2f3a11488df',
             'x86-unc': 'ha-d32d92f6d60c0e70f5e6'}
# Terms of the full-text check. s2/s3: the user markers "b1-hermes-s2"/"b1-hermes-s3" the fixture's seed sent
# (testha-b1/hermes-3.sh); mock: every mock-model reply ("B1 mock reply #n: ok"); WOOWBK: dev-d's own baseline
# session ("WOOWBK lab marker woowbk-lab-baseline ..."); the last one is in neither.
HA_TERMS = {'s2': 'b1-hermes-s2', 's3': 'b1-hermes-s3', 'mock': 'mock'}
BASE_TERMS = {'WOOWBK': 'WOOWBK lab marker'}
NEG_TERMS = {'zzqx7negative': 'zzqx7negative'}
BASE_SESSION = 'woowbk-lab-baseline'
HERMES_SECRETS = ['hermes-api-server-key', 'hermes-webhook-secret', 'hermes-dashboard-session-secret',
                  'hermes-dashboard-password', 'hermes-postgres-password']
SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ,()/:'<>.=_+#-]")


def _load_driver():
    spec = importlib.util.spec_from_file_location('ha_import_b1_e2e', HERE / 'ha_import_b1_e2e.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drv = _load_driver()
Failed = drv.Failed
drv.state_path = lambda: LAB / 'run' / 'hermes_real_ha.json'   # never the b1 driver's own state file


def label(text):
    return SAFE_LABEL.sub('_', str(text))[:200] or 'unnamed'


def emit(line):
    print(line, flush=True)


class Evidence(drv.Evidence):
    """The b1 driver's redacted evidence folder; stdout gets only `CHECK <label>: PASS|FAIL` (no detail)."""

    def __init__(self, secrets):
        super().__init__(secrets, 'hermes-real')

    def log(self, text):
        line = f'{time.strftime("%H:%M:%S")} {self.secrets.redact(str(text))}'
        with open(self.log_path, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')

    def check(self, name, ok, detail=''):
        result = super().check(name, ok, detail)
        emit(f'CHECK {label(self.secrets.redact(str(name)))}: {"PASS" if result else "FAIL"}')
        return result


# ---------------------------------------------------------------- device-side probes (as appowner in dev-d)

CONTINUITY = drv.PROBE_COMMON + r'''
import http.cookiejar, urllib.parse
D = "http://127.0.0.1:19119"
out = {}
for name, url in (("api", "http://127.0.0.1:18642/health"), ("webhook", "http://127.0.0.1:18644/health")):
    code, _ = call(url, "GET", "", raw=True, wait=300)
    out["health_" + name] = code
def dash_login(password):
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    body = json.dumps({"provider": "basic", "username": "admin", "password": password, "next": "/"}).encode()
    deadline = time.monotonic() + 240
    while True:
        r = urllib.request.Request(D + "/auth/password-login", data=body, headers={"Content-Type": "application/json"})
        try:
            with op.open(r, timeout=30) as resp:
                return resp.status, op
        except urllib.error.HTTPError as e:
            if e.code in (502, 503, 504) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return e.code, op
        except OSError:
            if time.monotonic() < deadline:
                time.sleep(3)
                continue
            return 0, op
def get(op, path):
    try:
        with op.open(D + path, timeout=60) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None
    except (OSError, ValueError):
        return 0, None
def digest(value):
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
code, op = dash_login(secret("hermes-dashboard-password"))
out["login"] = code
c, body = get(op, "/api/sessions?limit=100")
out["list_code"] = c
out["sessions"] = {s.get("id"): {k: s.get(k) for k in ("message_count", "source", "model", "title", "started_at")}
                   for s in ((body or {}).get("sessions") or []) if isinstance(s, dict)}
out["messages"] = {}
for sid in REQ["session_ids"]:
    c, body = get(op, "/api/sessions/" + urllib.parse.quote(sid, safe="") + "/messages?limit=500&order=oldest")
    rows = (body.get("messages") or []) if isinstance(body, dict) else []
    out["messages"][sid] = {"code": c, "rows": [[m.get("id"), m.get("role"), digest(m.get("content"))]
                                                for m in rows if isinstance(m, dict)]}
out["search"] = {}
for term in REQ["terms"]:
    c, body = get(op, "/api/sessions/search?q=" + urllib.parse.quote(term) + "&limit=50")
    res = (body.get("results") or []) if isinstance(body, dict) else []
    hits = []
    for r in res:
        if isinstance(r, dict):
            snippet = r.get("snippet") or ""
            hits.append([r.get("session_id"), ">>>" in snippet and "<<<" in snippet])
    out["search"][term] = {"code": c, "hits": sorted(hits)}
INNER = r"""
import hashlib, json, os, re, sqlite3, sys, tempfile
req = json.loads(sys.stdin.read())
o = {}
def digest(v):
    return hashlib.sha256((v if isinstance(v, str) else json.dumps(v, sort_keys=True)).encode("utf-8")).hexdigest()
c = sqlite3.connect("file:/opt/data/state.db?mode=ro", uri=True)
o["messages"] = {sid: [[i, r, digest(t)] for i, r, t in c.execute(
    "SELECT id, role, content FROM messages WHERE session_id = ? ORDER BY id", (sid,))] for sid in req["session_ids"]}
o["message_total"] = c.execute("SELECT count(*) FROM messages").fetchone()[0]
o["sessions_all"] = sorted([r[0], r[1]] for r in c.execute("SELECT id, source FROM sessions"))
o["like"] = {t: sorted(r[0] for r in c.execute("SELECT DISTINCT session_id FROM messages WHERE content LIKE ?",
                                                ("%" + s + "%",))) for t, s in req["like"].items()}
o["fts_tables"] = sorted(r[0] for r in c.execute(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND sql LIKE 'CREATE VIRTUAL TABLE%' AND lower(sql) LIKE '%fts5%'"))
o["fts_match"] = {}
for t in req["like"]:
    try:
        o["fts_match"][t] = sorted(set(r[0] for r in c.execute(
            "SELECT m.session_id FROM messages_fts f JOIN messages m ON m.id = f.rowid WHERE messages_fts MATCH ?",
            ('"' + t.replace('"', '""') + '"',))))
    except sqlite3.Error as e:
        o["fts_match"][t] = "error " + type(e).__name__
o["schema_version"] = c.execute("SELECT max(version) FROM schema_version").fetchone()[0]
o["quick_check"] = c.execute("PRAGMA quick_check").fetchone()[0]
fd, copy = tempfile.mkstemp(prefix="hr-fts-", suffix=".db", dir="/tmp")
os.close(fd)
try:
    d = sqlite3.connect(copy)
    c.backup(d)
    o["copy_integrity"] = d.execute("PRAGMA integrity_check").fetchone()[0]
    o["fts_integrity"] = {}
    for t in o["fts_tables"]:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,60}", t):
            o["fts_integrity"][t] = "refused name"
            continue
        try:
            d.execute('INSERT INTO "%s"("%s") VALUES (?)' % (t, t), ("integrity-check",))
            o["fts_integrity"][t] = "ok"
        except sqlite3.Error as e:
            o["fts_integrity"][t] = "error " + str(e)[:120]
    d.close()
finally:
    os.unlink(copy)
c.close()
print(json.dumps(o))
"""
rc, so, se = pexec("--user", "hermes", "-w", "/opt/data", "hermes-agent", "/opt/hermes/.venv/bin/python", "-c", INNER,
                   input=json.dumps({"session_ids": REQ["session_ids"], "like": REQ["like"]}))
try:
    out["inner"] = json.loads(so.strip().splitlines()[-1])
except (ValueError, IndexError):
    out["inner"] = {"error": "inner probe failed rc=%d" % rc}
print(json.dumps(out))
'''

# The logical state of dev-d's Hermes (inside hermes-agent as the hermes user, read-only): sessions with each
# message's digest, memories, skills, cron jobs, kanban tasks, config.yaml and the .env key names (never values).
DIGEST = drv.PROBE_COMMON + r'''
INNER = r"""
import hashlib, json, os, sqlite3
h = "/opt/data"
def sha(path):
    try:
        return hashlib.sha256(open(path, "rb").read()).hexdigest()
    except OSError:
        return None
o = {}
c = sqlite3.connect("file:" + h + "/state.db?mode=ro", uri=True)
rows = {}
for sid, title, source in c.execute("SELECT id, title, source FROM sessions ORDER BY id"):
    msgs = [[r, hashlib.sha256((t or "").encode()).hexdigest()] for r, t in c.execute(
        "SELECT role, content FROM messages WHERE session_id = ? ORDER BY id", (sid,))]
    rows[sid] = {"title": title, "source": source, "messages": msgs}
o["sessions"] = rows
c.close()
o["memories"] = {n: sha(os.path.join(h, "memories", n)) for n in ("MEMORY.md", "USER.md")}
o["skills"] = sorted(os.path.relpath(d, os.path.join(h, "skills")) for d, _s, fs in os.walk(os.path.join(h, "skills"))
                     if "SKILL.md" in fs)
try:
    jobs = json.load(open(os.path.join(h, "cron", "jobs.json")))
    jobs = jobs.get("jobs", jobs) if isinstance(jobs, dict) else jobs
    o["cron"] = sorted([j.get("id"), j.get("name"), j.get("enabled"), j.get("state")] for j in jobs)
except (OSError, ValueError):
    o["cron"] = None
try:
    k = sqlite3.connect("file:" + h + "/kanban.db?mode=ro", uri=True)
    o["kanban"] = sorted([r[0], r[1]] for r in k.execute("SELECT id, title FROM tasks"))
    k.close()
except sqlite3.Error:
    o["kanban"] = None
o["config_sha256"] = sha(os.path.join(h, "config.yaml"))
keys = []
try:
    for line in open(os.path.join(h, ".env"), encoding="utf-8", errors="replace"):
        name, sep, _value = line.strip().partition("=")
        if sep and not name.startswith("#"):
            keys.append(name.strip())
except OSError:
    pass
o["env_keys"] = sorted(keys)
print(json.dumps(o))
"""
rc, so, se = pexec("--user", "hermes", "-w", "/opt/data", "hermes-agent", "/opt/hermes/.venv/bin/python", "-c", INNER)
try:
    print(json.dumps({"digest": json.loads(so.strip().splitlines()[-1])}))
except (ValueError, IndexError):
    print(json.dumps({"error": "digest probe failed rc=%d" % rc}))
'''

# The b1 driver's needle builder (raw bytes and one JSON escaping layer) over this lane's secrets: the HA key, HA's
# Hermes test secrets, the 11-19 kit and dev-d's Hermes podman secrets (read inside the device, never output). Roots:
# the engine's records (sealed .tar archives and HA files skipped), its run dir, and the device journal since the run
# started (other lanes' services are not this lane's evidence). Only counts come back.
LEAK_SCAN = 'import json\n' + __import__('inspect').getsource(drv.secret_scan_needles) + r'''
import json, os, subprocess, sys
req = json.loads(sys.stdin.read())
secrets = {name: value.encode() for name, value in req["secrets"].items() if value}
for name in req["podman_secrets"]:
    p = subprocess.run(["runuser", "-u", "appowner", "--", "env", "-i", "PATH=/usr/bin:/bin", "HOME=/home/appowner",
                        "XDG_RUNTIME_DIR=/run/user/%d" % req["uid"], "podman", "secret", "inspect", "--showsecret",
                        "--format", "{{.SecretData}}", name], capture_output=True, timeout=60)
    value = p.stdout.rstrip(b"\n")
    if p.returncode != 0 or len(value) < 8:
        raise SystemExit("cannot inspect a required device secret")
    secrets["device:" + name] = value
needles = secret_scan_needles(secrets.values())
hits, scanned = 0, 0
base = "/var/lib/woowtech-backup/"
roots = [base + n for n in ("jobs", "ha-backups", "ha-imports.json", "requests.json", "archives", "uploads", "staging",
                            "pending", "exports")] + ["/run/woowtech-backup", "/etc/woowtech-cockpit/backup/apps"]
for root in roots:
    if not os.path.exists(root) or os.path.islink(root):
        raise SystemExit("required scan root missing or unsafe: " + root)
    paths = [root] if os.path.isfile(root) else []
    for d, dirs, files in (os.walk(root, followlinks=False) if os.path.isdir(root) else ()):
        paths.extend(os.path.join(d, f) for f in files)
    for path in paths:
        if path.endswith(".tar") and ("/ha-backups/" in path or "/archives/" in path):
            continue
        if os.path.islink(path):
            raise SystemExit("unsafe scan path")
        data = open(path, "rb").read()
        scanned += 1
        hits += sum(data.count(s) for s in needles)
journal = subprocess.run(["journalctl", "-o", "cat", "--no-pager", "--since", "@%d" % req["since"]],
                         capture_output=True, check=True).stdout
hits += sum(journal.count(s) for s in needles)
print(json.dumps({"scanned": scanned, "journal_bytes": len(journal), "names": len(secrets), "hits": hits}))
'''
LANE_SECRETS = ('HA_BACKUP_KEY', 'B1_HERMES_DASHBOARD_PW', 'B1_HERMES_API_KEY', 'B1_HERMES_WEBHOOK_SECRET',
                'B1_HERMES_ROUTE_SECRET', 'B1_HERMES_DUMMY_KEY', 'DEV_D_KIT_1119')
PROGRAMS = {'CONTINUITY': CONTINUITY, 'DIGEST': DIGEST, 'LEAK_SCAN': LEAK_SCAN}


# ---------------------------------------------------------------- lab guards

def git(*args):
    return subprocess.run(['git', '-C', str(REPO), *args], capture_output=True, text=True, timeout=60).stdout.strip()


def clean_tree():
    proc = subprocess.run(['git', '-C', str(REPO), 'status', '--porcelain'],
                          capture_output=True, text=True, timeout=60)
    return proc.returncode == 0 and not proc.stdout.strip()


def verify_isolation():
    proc = subprocess.run(['bash', str(HERE / 'owner.sh'), 'd', '--verify-isolation'], capture_output=True, text=True,
                          timeout=120)
    line = proc.stdout.strip()
    if proc.returncode != 0 or line != 'dev-d isolation: true none {}':
        raise Failed('dev-d isolation assertion failed')
    emit(line)


def headroom():
    proc = drv.root('sh', '-c', 'echo "$(cat /sys/fs/cgroup/memory.current) $(cat /sys/fs/cgroup/memory.max)"',
                    timeout=60)
    try:
        current, maximum = (int(x) for x in drv.out(proc).split())
    except ValueError:
        raise Failed('cannot read dev-d cgroup memory') from None
    available = 0
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            available = int(line.split()[1])
    st = os.statvfs('/')
    free = st.f_bavail * st.f_frsize
    emit(f'dev-d memory current={current} limit={maximum} headroom={maximum - current}')
    emit(f'host MemAvailable={available} KiB disk free={free} B')
    if maximum - current < MIN_DEVICE_HEADROOM:
        raise Failed('dev-d memory headroom below 1.5 GiB')
    if available < MIN_HOST_AVAILABLE_KIB:
        raise Failed('host MemAvailable below 1 GiB')
    if free < MIN_DISK_FREE:
        raise Failed('host disk free below 13 GiB')


def acquire_lock():
    """The dev-d mutation lock, never taken while emqx-main is waiting for it (its waiting file exists)."""
    fd = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
        os.close(fd)
        raise Failed('unsafe dev-d lock file')
    started = time.monotonic()
    while True:
        if not WAITING.exists():
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                if not WAITING.exists():
                    emit(f'lock acquired after {int(time.monotonic() - started)} s')
                    return fd
                fcntl.flock(fd, fcntl.LOCK_UN)
        if time.monotonic() - started > LOCK_WAIT:
            os.close(fd)
            raise Failed('dev-d lock not acquired within 3600 s')
        time.sleep(15)


# ---------------------------------------------------------------- helpers

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def fixture_path(tag):
    name = drv.UPLOADS[tag][1]
    return drv.FIXTURES / 'x86' / name / f'{name}.tar'


def source_sessions():
    return {s['id']: s for s in drv.source('x86')['hermes']['sessions']}


def markers(ev, label_text):
    proc = drv.run([drv.LP, 'exec', '-i', drv.DEVICE, drv.OWNER, 'python3', '-I', '-c', drv.MARKERS, 'hermes', 'read'],
                   input=b'{}', timeout=600)
    try:
        found = json.loads(drv.out(proc).strip().splitlines()[-1])
    except (ValueError, IndexError):
        found = {'error': 'marker read failed'}
    ev.save(f'markers-{label(label_text).replace(" ", "-")}-{int(time.time())}.json', found)
    have = drv.marker_names(found)
    want = drv.BASELINE_MARKERS['hermes']
    ev.check(f'{label_text}: dev-d\'s own Hermes baseline markers (batch1_markers.py read)',
             want <= have and not (have - want), sorted(have))
    return found


def state_digest(ev, label_text):
    probe = drv.device_python(DIGEST, {}, timeout=600)
    ev.save(f'digest-{label(label_text).replace(" ", "-")}-{int(time.time())}.json', probe)
    if 'digest' not in probe:
        raise Failed(f'{label_text}: state digest probe failed')
    return probe['digest']


def continuity(ev, label_text, mode):
    """mode 'ha': HA's data served by the running Hermes; mode 'base': dev-d's own baseline is back, HA's is gone."""
    src = source_sessions()
    ha_ids = sorted(src)
    terms = dict(HA_TERMS, **BASE_TERMS, **NEG_TERMS)
    probe = drv.device_python(CONTINUITY, {'session_ids': ha_ids + [BASE_SESSION], 'terms': sorted(terms),
                                           'like': terms}, timeout=900)
    ev.save(f'continuity-{label(label_text).replace(" ", "-")}-{int(time.time())}.json', probe)
    inner = probe.get('inner') or {}
    ev.check(f'{label_text}: Hermes healthy (API and webhook /health 200) and the dashboard takes this device\'s '
             f'password', probe.get('health_api') == 200 and probe.get('health_webhook') == 200
             and probe.get('login') == 200 and probe.get('list_code') == 200,
             {k: probe.get(k) for k in ('health_api', 'health_webhook', 'login', 'list_code')})
    listed = probe.get('sessions') or {}
    api_msgs = probe.get('messages') or {}
    db_msgs = inner.get('messages') or {}
    ev.check(f'{label_text}: state.db readable in the container (quick_check ok, schema 32)',
             inner.get('quick_check') == 'ok' and inner.get('schema_version') == 32,
             {k: inner.get(k) for k in ('quick_check', 'schema_version', 'error')})
    fts = inner.get('fts_integrity') or {}
    ev.check(f'{label_text}: FTS5 tables pass integrity-check on a consistent copy (integrity_check ok)',
             len(fts) >= 2 and all(v == 'ok' for v in fts.values()) and inner.get('copy_integrity') == 'ok',
             {'fts_integrity': fts, 'copy_integrity': inner.get('copy_integrity')})
    search = probe.get('search') or {}
    like = inner.get('like') or {}
    match = inner.get('fts_match') or {}

    def hits(term):
        return sorted({h[0] for h in (search.get(term) or {}).get('hits') or []})

    def all_fts(term):
        return all(h[1] for h in (search.get(term) or {}).get('hits') or [])

    neg = 'zzqx7negative'
    ev.check(f'{label_text}: a term in no message finds nothing', (search.get(neg) or {}).get('code') == 200
             and not hits(neg) and like.get(neg) == [] and match.get(neg) == [], search.get(neg))
    if mode == 'ha':
        want_list = {sid: [s['message_count'], s['source'], s['model'], s['title'], s['started_at']]
                     for sid, s in src.items()}
        got_list = {sid: [listed.get(sid, {}).get(k) for k in ('message_count', 'source', 'model', 'title', 'started_at')]
                    for sid in src}
        ev.check(f'{label_text}: the dashboard lists HA\'s 5 sessions with HA\'s message counts, sources, models, '
                 f'titles and start times', got_list == want_list, {'got': got_list})
        same = {sid: (api_msgs.get(sid) or {}).get('rows') == db_msgs.get(sid) for sid in src}
        counts = {sid: len(db_msgs.get(sid) or []) for sid in src}
        ev.check(f'{label_text}: every HA message is served by Hermes (API rows = state.db rows: id, role, sha256)',
                 all(same.values()) and counts == {sid: s['message_count'] for sid, s in src.items()}
                 and sum(counts.values()) == 15, {'same': same, 'counts': counts})
        for term, needle in HA_TERMS.items():
            truth = like.get(term)
            ok = (isinstance(truth, list) and truth and set(truth) <= set(src) and hits(term) == truth
                  and match.get(term) == truth and all_fts(term) and (search.get(term) or {}).get('code') == 200)
            if term in ('s2', 's3'):
                ok = ok and len(truth) == 1
            ev.check(f'{label_text}: full-text search "{term}" through Hermes finds exactly the HA sessions holding '
                     f'"{needle}" (FTS5 snippet)', ok, {'api': search.get(term), 'like': truth, 'match': match.get(term)})
        ev.check(f'{label_text}: the s2 and s3 markers are in two different HA sessions',
                 like.get('s2') and like.get('s3') and like.get('s2') != like.get('s3'),
                 {'s2': like.get('s2'), 's3': like.get('s3')})
        # (the b1 driver's webhook check posts "woowbk lab seamless check", so later WOOWBK hits may exist; only
        # the baseline session itself must be gone)
        ev.check(f'{label_text}: dev-d\'s own baseline session is replaced by HA\'s data (not listed, no message)',
                 BASE_SESSION not in listed and not db_msgs.get(BASE_SESSION) and BASE_SESSION not in hits('WOOWBK')
                 and not like.get('WOOWBK'), {'listed': BASE_SESSION in listed,
                                             'rows': len(db_msgs.get(BASE_SESSION) or [])})
    else:
        ev.check(f'{label_text}: no HA session is left (dashboard list and state.db)',
                 not (set(listed) & set(src)) and not any(db_msgs.get(sid) for sid in src),
                 {'listed': sorted(set(listed) & set(src))})
        for term in HA_TERMS:
            ev.check(f'{label_text}: full-text search "{term}" finds nothing of HA\'s',
                     not hits(term) and not like.get(term) and (search.get(term) or {}).get('code') == 200,
                     search.get(term))
        base = like.get('WOOWBK')
        ev.check(f'{label_text}: full-text search "WOOWBK" through Hermes finds dev-d\'s baseline session (FTS5 snippet)',
                 base == [BASE_SESSION] and hits('WOOWBK') == base and match.get('WOOWBK') == base and all_fts('WOOWBK'),
                 {'api': search.get('WOOWBK'), 'like': base, 'match': match.get('WOOWBK')})
        ev.check(f'{label_text}: the dashboard lists dev-d\'s baseline session with its message',
                 BASE_SESSION in listed and (api_msgs.get(BASE_SESSION) or {}).get('rows') == db_msgs.get(BASE_SESSION)
                 and len(db_msgs.get(BASE_SESSION) or []) == 1, {'listed': listed.get(BASE_SESSION)})
    return probe


def engine_running(ev, label_text):
    drv.app_health(ev, 'hermes', label_text)


def restart_hermes(ev, label_text):
    started = time.monotonic()
    proc = drv.owner('systemctl', '--user', 'restart', 'hermes-agent.service', timeout=600)
    took = time.monotonic() - started
    ev.check(f'{label_text}: systemctl --user restart hermes-agent.service', proc.returncode == 0,
             f'rc {proc.returncode} {took:.0f} s')
    ev.time('restart', '-', 'hermes', took)


def restore_with(ev, backup_id, tag, key=None):
    request = {'backup_id': backup_id, 'apps': ['hermes'], 'confirm': True, 'request_id': drv.request_id(tag)}
    if key is not None:
        request['key'] = key
    started = time.monotonic()
    reply = drv.ok('restore-start', request, ev=ev, timeout=300)
    job = drv.wait_job(reply['job_id'], ev=ev, timeout=3600)
    took = time.monotonic() - started
    result = job.get('result') or {}
    drv.created_backup(result.get('safety_backup_id'))
    ev.time('restore', tag, 'hermes', took, job)
    health = result.get('health') or []
    ok = (job['state'] == 'succeeded' and result.get('rolled_back') is False and bool(result.get('safety_backup_id'))
          and health and all(h.get('status') == 'ok' for h in health))
    ev.check(f'{tag}: restore of {backup_id} succeeded with a safety backup and every health check ok', ok,
             {'state': job['state'], 'error': job.get('error'), 'safety': result.get('safety_backup_id'),
              'rolled_back': result.get('rolled_back'), 'downtime_s': result.get('downtime_seconds'),
              'health': [(h.get('id'), h.get('status')) for h in health], 'took_s': round(took, 1)})
    return job


def diff_digest(a, b):
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))


# ---------------------------------------------------------------- steps

def step_setup(ev, args):
    proc = drv.root('systemctl', 'mask', TIMER, timeout=120)
    ev.check('setup: the scheduled-backup timer is masked before the install (shared lab, no schedule wanted)',
             proc.returncode == 0, drv.out(proc)[-200:])
    script = HERE / 'deploy-src.sh'
    proc = drv.run(['bash', str(script), 'd', '--src', str(REPO), '--no-demo-catalog'], timeout=1800)
    ev.save('deploy.log', drv.out(proc)[-20000:] + proc.stderr.decode('utf-8', 'replace')[-5000:])
    if not ev.check('setup: deploy-src.sh d --src <this tree> --no-demo-catalog', proc.returncode == 0,
                    f'rc {proc.returncode}'):
        raise Failed('deploy failed')
    status = drv.ok('status', ev=ev)
    version = (REPO / 'VERSION').read_text().strip()
    ev.check('setup: the installed helper answers status with this tree\'s VERSION',
             status.get('version') == version, {'installed': status.get('version'), 'tree': version})
    kit = load_kit(args)
    catalog = {a['id'] for a in status.get('apps') or []}
    if 'hermes' not in catalog:
        reply = drv.ok('inspect', {'backup_id': BASELINE, 'key': kit}, ev=ev, timeout=900)
        apps = (reply.get('preflight') or {}).get('apps') or []
        carried = next((a.get('settings') or {} for a in apps if a.get('id') == 'hermes'), {})
        entry = carried.get('entry')
        ev.check('setup: dev-d\'s Hermes baseline backup opens with the 11-19 emergency kit and carries its catalog entry',
                 isinstance(entry, dict) and entry.get('id') == 'hermes' and carried.get('state') == 'missing',
                 {'state': carried.get('state'), 'owner': (entry or {}).get('owner')})
        if not isinstance(entry, dict):
            raise Failed('no carried Hermes catalog entry')
        ev.save('catalog-entry-hermes.json', entry)
        preview = drv.ok('catalog-install', {'entry': entry}, ev=ev, timeout=300)
        ev.save('catalog-preview.json', preview)
        if not ev.check('setup: catalog-install preview of the carried entry is valid', preview.get('valid') is True,
                        {k: preview.get(k) for k in ('valid', 'errors', 'warnings', 'conflicts')}):
            raise Failed('catalog preview refused')
        done = drv.ok('catalog-install', {'entry': entry, 'confirm': True,
                                          'expected_sha256': preview.get('expected_sha256')}, ev=ev, timeout=300)
        ev.save('catalog-install.json', done)
    key = drv.ok('key-init', ev=ev)
    ev.check('setup: a device key exists (key-init; the kit is never read)', bool((key.get('key') or {}).get('key_id')),
             {'created': key.get('created'), 'key_id': (key.get('key') or {}).get('key_id')})
    status = drv.ok('status', ev=ev)
    state = next((a for a in status.get('apps') or [] if a['id'] == 'hermes'), {})
    ev.check('setup: status: hermes running, no problems', state.get('state') == 'running' and not state.get('problems'),
             {k: state.get(k) for k in ('state', 'problems')})


def step_before(ev, args):
    markers(ev, 'before')
    drv.STATE.pop('hermes_owner_exceptions_before', None)
    drv.hermes_owner_baseline(ev)
    digest = state_digest(ev, 'before')
    drv.STATE['digest_before'] = digest
    drv.save_state()
    ev.check('before: dev-d\'s Hermes holds only its own baseline session (no HA session)',
             set(digest['sessions']) == {BASE_SESSION}, sorted(digest['sessions']))
    continuity(ev, 'before', 'base')


def bind_store(ev):
    listing = drv.ok('list', ev=ev)
    present = {h.get('id') for h in listing.get('ha_backups') or []}
    for tag in TAGS:
        store_id = STORE_IDS[tag]
        meta = json.loads(drv.out(drv.root('cat', f'/var/lib/woowtech-backup/ha-backups/{store_id}.json', check=True)))
        local = drv.STATE.setdefault('fixture_sha256', {}).get(tag)
        if local is None:
            local = sha256_file(fixture_path(tag))
            drv.STATE['fixture_sha256'][tag] = local
        ok = store_id in present and meta.get('sha256') == local and store_id == 'ha-' + local[:20]
        ev.check(f'store {tag}: the stored HA file is the real fixture (SHA-256 equal, id from it)', ok,
                 {'store': store_id, 'listed': store_id in present, 'filename': meta.get('filename')})
        if not ok:
            raise Failed(f'HA store entry {tag} not bound to its fixture')
        drv.STATE[f'ha_{tag}'] = store_id
    drv.save_state()


def step_check(ev, args):
    bind_store(ev)
    key = args.secrets['HA_BACKUP_KEY']
    for tag in TAGS:
        needs_key = drv.UPLOADS[tag][2]
        job, took = drv.run_check(drv.STATE[f'ha_{tag}'], ['hermes'], ev=ev, key=key if needs_key else None,
                                  tag=f'check-{tag}-hermes')
        ev.time('check', tag, 'hermes', took, job)
        label_text = f'check {tag}/hermes'
        if not ev.check(f'{label_text}: job succeeded', job['state'] == 'succeeded', f'{took:.0f} s {job.get("error")}'):
            continue
        result = job['result']['ha_check']['apps'][0]
        ev.save(f'check-{tag}-hermes.json', result)
        ev.check(f'{label_text}: ok, no blockers', result.get('ok') is True and not result.get('blockers'),
                 result.get('blockers'))
        ev.check(f'{label_text}: source amd64, add-on 0.1.14, target 0.22.5', result.get('arch') == 'amd64'
                 and result.get('version') == '0.1.14' and str(result.get('target_version')).lstrip('v') == '0.22.5',
                 {k: result.get(k) for k in ('arch', 'version', 'target_version')})
        section = drv.compare_check(ev, label_text, 'hermes', result, 'x86', True, tag)
        ev.check(f'{label_text}: the HA-internal URL of config.yaml is named (warning + ha_urls)',
                 any('9c1a67eb-woow-hermes' in u for u in section.get('ha_urls') or [])
                 and any('9c1a67eb-woow-hermes' in w for w in result.get('warnings') or []), section.get('ha_urls'))
    leftovers = drv.labelled()
    ev.check('check: no throwaway container, volume or network left', not any(leftovers.values()), leftovers)


def step_import(ev, args, tag):
    if tag not in TAGS:
        raise Failed(f'unknown import tag {tag}')
    if drv.STATE.get(f'ha_{tag}') != STORE_IDS[tag] or 'digest_before' not in drv.STATE:
        raise Failed('run setup, before and check first (store binding and the before digest are missing)')
    if set(state_digest(ev, f'{tag} pre')['sessions']) != {BASE_SESSION}:
        raise Failed('dev-d\'s Hermes is not at its baseline; refusing to import over unknown data')
    label_text = f'import {tag}/hermes'
    drv.import_once(ev, args, tag, ['hermes'], verify=False)
    record = (drv.STATE.get('imports') or {}).get(f'{tag}/hermes') or {}
    safety = record.get('safety')
    if not record.get('backup_id') or not safety:
        raise Failed(f'{label_text}: no converted backup or no safety backup recorded')
    emit(f'backup id converted {record["backup_id"]}')
    emit(f'backup id safety {safety}')
    try:
        continuity(ev, f'{label_text} after restore', 'ha')
        drv.verify_hermes(ev, args, 'x86', f'{label_text} after restore')
        engine_running(ev, f'{label_text} after restore')
        restart_hermes(ev, f'{label_text}')
        continuity(ev, f'{label_text} after restart', 'ha')
        engine_running(ev, f'{label_text} after restart')
    finally:
        restore_with(ev, safety, f'rollback-{tag}')
        markers(ev, f'{label_text} after rollback')
        continuity(ev, f'{label_text} after rollback', 'base')
        engine_running(ev, f'{label_text} after rollback')
        after = state_digest(ev, f'{label_text} after rollback')
        before = drv.STATE['digest_before']
        ev.check(f'{label_text} after rollback: Hermes state digest equals the one before any import',
                 after == before, {'differs': diff_digest(after, before)})


def step_kit_baseline(ev, args):
    restore_with(ev, BASELINE, 'kit-baseline', key=load_kit(args))
    markers(ev, 'kit-baseline')
    continuity(ev, 'kit-baseline', 'base')
    engine_running(ev, 'kit-baseline')
    after = state_digest(ev, 'kit-baseline')
    before = drv.STATE.get('digest_before') or {}
    ev.check('kit-baseline: Hermes state digest equals the one before any import', after == before,
             {'differs': diff_digest(after, before)})


def step_cleanup(ev, args):
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
            rc, reply = drv.helper('delete', {'backup_id': backup_id})
            (deleted if rc == 0 else refused).append(backup_id)
    left = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
    ev.check('cleanup: the test\'s converted and safety backups are deleted, dev-d\'s baseline stays',
             BASELINE in left and not (left & set(created)), {'deleted': len(deleted), 'refused': refused})
    drv.STATE['created_backups'] = [b for b in drv.STATE.get('created_backups') or [] if b not in deleted]
    drv.save_state()
    names = drv.out(drv.owner('podman', 'ps', '--format', '{{.Names}}')).split()
    ev.check('cleanup: Hermes runs (hermes-agent, hermes-postgresql, hermes-redis) and no test container exists',
             {'hermes-agent', 'hermes-postgresql', 'hermes-redis'} <= set(names)
             and not [n for n in names if n.startswith(('woowbk-j', 'woowbk-hr'))], names)


def load_kit(args):
    if getattr(args, 'kit', None):
        return args.kit
    kit = OLD_KIT.read_text(encoding='utf-8')
    lines = [line.strip() for line in kit.splitlines() if line.strip().startswith('AGE-SECRET-KEY-')]
    if len(lines) != 1:
        raise Failed('the 11-19 kit does not hold exactly one key line')
    args.secrets.register('DEV_D_KIT_1119', lines[0])
    args.kit = kit
    return kit


def step_leaks(ev, args):
    load_kit(args)
    since = drv.STATE.get('run_started') or int(time.time()) - 6 * 3600
    request = {'secrets': {n: args.secrets[n] for n in LANE_SECRETS if args.secrets.values.get(n)},
               'podman_secrets': HERMES_SECRETS, 'uid': 1019, 'since': int(since)}
    if len(request['secrets']) != len(LANE_SECRETS):
        raise Failed('a lane secret is missing from the readers')
    report = drv.device_python(LEAK_SCAN, request, as_owner=False, timeout=900)
    host = drv.scan_host_evidence(ev.dir, args.secrets)
    ev.save('leaks.json', {'device': report, 'host': host})
    ev.check('leaks: no test secret, HA key, kit or dev-d Hermes secret in engine records, logs, journal or evidence',
             isinstance(report, dict) and report.get('hits') == 0 and report.get('scanned', 0) > 0
             and host.get('hits') == 0, {'device': {k: report.get(k) for k in ('scanned', 'names', 'hits')},
                                         'host': host})


STEPS = {'setup': step_setup, 'before': step_before, 'check': step_check, 'kit-baseline': step_kit_baseline,
         'cleanup': step_cleanup, 'leaks': step_leaks}


def self_check():
    for name, program in PROGRAMS.items():
        compile(program, name, 'exec')
    for tag in TAGS:
        assert drv.UPLOADS[tag][0] == 'x86' and 'hermes' in drv.UPLOADS[tag][3]
    print(f'offline self-check passed: {len(PROGRAMS)} embedded programs compiled, {len(TAGS)} x86 uploads known')


def main(argv):
    if argv == ['--self-check']:
        self_check()
        return 0
    steps = argv
    if not steps or any(s not in STEPS and not (s.startswith('import:') and s[7:] in TAGS) for s in steps):
        print('usage: hermes_real_ha.py <setup|before|check|import:TAG|kit-baseline|cleanup|leaks> ...', file=sys.stderr)
        return 2
    if not clean_tree():
        print('commit tested code first', file=sys.stderr)
        return 2
    emit(f'source commit {git("rev-parse", "HEAD")}')
    secrets = drv.Secrets([drv.SECRET_DIR / 'b1-creds.env', drv.SECRET_DIR / 'ha-import-creds.env'],
                          drv.SECRET_DIR / 'dev-d-markers.json')
    args = type('Args', (), {})()
    args.secrets = secrets
    args.kit = None
    ev = Evidence(secrets)
    drv.load_state()
    drv.STATE.setdefault('run_started', int(time.time()) - 60)
    for tag in TAGS:   # hash the fixtures before taking the lock (host only)
        if tag not in drv.STATE.setdefault('fixture_sha256', {}):
            drv.STATE['fixture_sha256'][tag] = sha256_file(fixture_path(tag))
    drv.save_state()
    verify_isolation()
    fd = acquire_lock()
    held = time.monotonic()
    failed_steps = []
    try:
        verify_isolation()
        for name in steps:
            if time.monotonic() - held > HOLD_BUDGET:
                emit(f'STEP {name}: SKIP hold_budget=1')
                failed_steps.append(name)
                continue
            if WAITING.exists():
                emit(f'STEP {name}: SKIP emqx_main_waiting=1')
                failed_steps.append(name)
                continue
            try:
                headroom()
            except Failed as error:
                ev.check(f'{name}: headroom before the step', False, str(error))
                emit(f'STEP {name}: SKIP headroom=1')
                failed_steps.append(name)
                break
            ev.log(f'== {name}')
            started = time.monotonic()
            try:
                if name.startswith('import:'):
                    step_import(ev, args, name[7:])
                else:
                    STEPS[name](ev, args)
            except Failed as error:
                ev.check(f'{name}: step ran to the end', False, str(error))
            except Exception as error:  # noqa: BLE001 - recorded (type only), the lock is still released below
                ev.check(f'{name}: step ran to the end', False, f'{type(error).__name__}')
            finally:
                drv.save_state()
            took = time.monotonic() - started
            bad = [r for r in ev.results if not r['ok'] and r.get('step') is None]
            for r in ev.results:
                r.setdefault('step', name)
            emit(f'STEP {name}: {"FAIL" if bad else "PASS"} seconds={took:.0f}')
            if bad:
                failed_steps.append(name)
                if name in ('setup', 'before', 'check'):
                    break
    finally:
        try:
            verify_isolation()
        finally:
            emit(f'lock held for {int(time.monotonic() - held)} s')
            os.close(fd)
    ok = ev.finish()
    passed = sum(1 for r in ev.results if r['ok'])
    emit(f'RESULT {passed}/{len(ev.results)} passed')
    return 0 if ok and not failed_steps else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
