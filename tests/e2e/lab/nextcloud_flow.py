#!/usr/bin/env python3
"""Nextcloud: real x86 showcase HA backups (add-on woow-nextcloud-office 0.2.3, encrypted) -> dev-e's INSTALLED
Nextcloud (Podman package 19a7609, Nextcloud 35.0.1) through the product's HA-import flow, exactly the helper commands
the Cockpit page sends (lane nextcloud-import, 2026-11-23).

  python3 -I tests/e2e/lab/services_a_capture.py --private=FILE <evidence.json> nextcloud-x86-noshare -- \\
      python3 -I tests/e2e/lab/nextcloud_flow.py --negative
  python3 -I tests/e2e/lab/nextcloud_flow.py --self-check      (offline; never touches a device or a secret)

--negative: the real backup WITHOUT HA's share folder (woow-b2-nextcloud-x86-enc-noshare: database, config.php and
custom apps, but none of the users' files). One hold of /tmp/woowbk-dev-e-mutation.lock; dev-e's outer isolation
(`true none {}`) before and after; the checkout committed; deploy-src.sh e --src <this tree> --no-demo-catalog and the
installed engine == this tree; Nextcloud's five units active and status.php installed, 35.0.1.1, not in maintenance.
  before   dev-e's own markers (batch2_markers.py nextcloud read: the woowbk-lab-* users and the baseline user's WebDAV
           files with their SHA-256), config.php's SHA-256, the users, the storages, the data dir's top entries
  upload   upload-begin, the fixture copied to the given path, upload-finish: the record is the fixture, nextcloud is
           importable and installed
  check    ha-check-start nextcloud (the HA key on stdin only): the job succeeds, nextcloud is NOT ok, its blocker names
           the missing share folder and /share/nextcloud, and it is the only blocker; the section equals the backup's
           facts (Nextcloud 35.0.1.1, PostgreSQL 16, users 3, file cache 300, shares 1, tokens 125, calendar objects 2,
           contacts 3, custom apps notes/richdocuments/tasks, data directory /share/nextcloud not in the backup): HA's
           real cluster was opened and read by the product
  convert  ha-convert-start nextcloud: the job fails with the same blocker, no backup is added
  after    everything of `before` is unchanged; units active; status.php the same
  cleanup  the HA store record deleted; no job container, volume, network, staging folder or key file left
  leaks    the HA key and the HA-side test credentials appear nowhere in the engine's records, uploads, staging, run dir
           or the device journal, nor in this evidence

--candidate (INTERNAL candidate, never acceptance; same fixture): the same setup, before, upload and check; then
ha-convert-start is created through the helper's own command code, but its job runs in a root process inside dev-e
where ONLY ha_nextcloud.datadir_pass is replaced (the users' files are not in this backup: the data dir gets just
`.ncdata`); the product's refusal stays in the installed engine and in every public route. It exercises the real
conversion: pg_dump of HA's real database, the new cluster from the live image/env/secret, the live role and grants,
pg_restore as that role, the storage/Office/cron fix-ups and their verification against the live database, the
PostgreSQL settings, config.php merged and parsed back by the live PHP, the html/PostgreSQL/Redis dir tars and the
packaging. The converted backup is inspected (preflight passes, the four data dirs, settings same) and deleted, never
restored; dev-e's Nextcloud must be unchanged (after), cleanup and leaks as above.

--run --facts FILE (the share-including backup; the acceptance run): FILE (JSON, private, written from the showcase
lane's READY line and its walk of the backup) names the fixture and its SHA-256, the HA test users and the NAMES of
their secrets in the lab cred files (user_pw, app_pw, user2_pw, link_token, link_pw), the marker files {WebDAV name:
SHA-256 or its 16-character prefix}, the per-user manifest digests of the data directory, the shared file, the
CalDAV/CardDAV objects with their UIDs, the versioned file and its version count, and the expected check section.
Steps: setup, before (also dev-e's own account through the client: logins, Office capabilities, data fingerprint),
upload, check (nextcloud ok, no blocker, the section as FILE says), import (ha-convert-start with the product's space
guard and the host-floor watchdog; notes; inspect: preflight passes; restore-start in place with its safety backup
and health checks; the uploaded HA file is deleted first, as the page allows: the restores need the space), verify
(status.php; the marker files and every HA user's files on disk against the backup's digests; OCS with the HA password and with
HA's app password, a wrong password 401; the second user reads the shared file; the public link with its password,
401 without or with a wrong one; CalDAV and CardDAV objects; the older version on disk and in the versions API;
richdocuments wopi keys and the cron mode exactly dev-e's; Office capabilities as for dev-e's own account; the
discovery on this device's gateway; a new data fingerprint; root storage and table owners), restart
(nextcloud-app.service restarted, verify again), rollback (a: a second restore with a one-shot ExecStartPre failure
must end rolled-back, verify again; b: the import's safety backup restored: dev-e's own markers are back, the HA-only
users are gone, dev-e's own account logs in), after (as --negative), cleanup, leaks (every secret named above).

stdout carries only fixed lines (`<check>: PASS|FAIL`, the source commit, the lock time); details go to the private,
redacted evidence folder ~/.woowbk-lab/evidence/nextcloud-flow/<time>/ (0700). Not covered by --negative (stated):
a restore (the product refuses to build one), the users' files, Office, a browser.
"""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
DEVICE = 'woowbk-dev-e'
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
HOLD_BUDGET = 40 * 60
RUN_HOLD_BUDGET = 100 * 60  # the share run: upload, check, convert, restore x3, restart
FLOOR = 12 * 1024 ** 3          # the team keeps >= 12 GiB free on the host at every moment
NEED = 1536 * 1024 ** 2         # the upload copy in dev-e plus the check's throwaway cluster, with margin
CANDIDATE_NEED = 4608 * 1024 ** 2  # the candidate: live html pack + html dir tar + cluster export + the archive
# The share run: before the upload only the fixture plus the check's throwaway cluster is asked for; the conversion's
# own need is computed after the check from dev-e's live html and PostgreSQL dirs and HA's data dir (convert_need);
# every restore checks its own need (restore_need) and the host-floor watchdog guards each job.
RUN_CHECK_NEED = 1024 ** 3
RUN_START_NEED = 3 * 1024 ** 3   # at the start of a share run: the conversion's need after the upload, with margin
LIVE_ROOT = '/home/appowner/.local/share/nextcloud-office'
WATCH_FLOOR = FLOOR + 256 * 1024 ** 2  # below it every running job of dev-e is cancelled (the job cleans up)
FIXTURE = (LAB / 'ha-fixtures' / '20261123-batch2' / 'x86' / 'woow-b2-nextcloud-x86-enc-noshare'
           / 'woow-b2-nextcloud-x86-enc-noshare-20261123.tar')
FIXTURE_SHA = '88e0f79415473c3453fb2889375b5fe0167e5d0a685d17da768ccc641c3c027f'
# calendar_objects/contacts: the showcase lane listed 2 and 3 BEFORE its marker user; Nextcloud 35.0.1 adds the new
# user's card to the system address book (apps/dav/lib/Listener/UserEventsListener.php:89) and example content at the
# first login (:79-80, :157, ExampleContactService/ExampleEventService): +2 and +2 per user, as the share backup's
# markers show (2 users + 1 event + 1 contact: 2 -> 7 and 3 -> 8). Real attempt 1 read 4 and 5.
SECTION = {'nextcloud_version': '35.0.1.1', 'pg_version': '16', 'users': 3, 'files': 300, 'shares': 1, 'tokens': 125,
           'calendar_objects': 4, 'contacts': 5, 'custom_apps': ['notes', 'richdocuments', 'tasks'],
           'datadir': '/share/nextcloud', 'datadir_in_backup': False}
UNITS = ('nextcloud-db.service', 'nextcloud-redis.service', 'nextcloud-app.service', 'nextcloud-office.service',
         'nextcloud-gateway.service')
SHARE_TEXT = '沒有包含 share 資料夾'
SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ,()/:'<>.=_-]")
SECRET_FILES = (LAB / 'secrets' / 'ha-import-creds.env', LAB / 'secrets' / 'b1-creds.env')
MARKERS = LAB / 'secrets' / 'dev-e-markers.json'
BASE_USER = 'woowbk-lab-baseline'  # dev-e's own marker account (batch2_markers.py)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drv = _load('ha_import_b1_e2e')
drv.DEVICE = DEVICE                       # every helper/owner/root call of the b1 driver goes to dev-e
drv.state_path = lambda: LAB / 'run' / 'nextcloud_flow.json'
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

STATE = r'''
import json, subprocess, sys
REQ = json.loads(sys.stdin.read() or "{}")
def run(*argv):
    return subprocess.run(list(argv), capture_output=True, timeout=300)
def text(p):
    return p.stdout.decode("utf-8", "replace") if p.returncode == 0 else None
cfg = text(run("podman", "exec", "nextcloud-app", "sha256sum", "/var/www/html/config/config.php"))
users = text(run("podman", "exec", "-u", "www-data", "nextcloud-app", "php", "/var/www/html/occ", "user:list",
                 "--output=json", "--limit=1000"))
status = text(run("podman", "exec", "nextcloud-app", "curl", "-fsS", "-m", "20", "http://localhost/status.php"))
sql = "SELECT json_build_object('storages', (SELECT json_agg(id ORDER BY numeric_id) FROM oc_storages), " \
      "'users', (SELECT count(*) FROM oc_users))"
files = text(run("podman", "exec", "nextcloud-db", "psql", "-X", "-At", "-U", "nextcloud", "-d", "nextcloud", "-c",
                 "SELECT count(*) FROM oc_filecache"))
db = text(run("podman", "exec", "nextcloud-db", "psql", "-X", "-At", "-U", "nextcloud", "-d", "nextcloud", "-c", sql))
top = text(run("podman", "exec", "nextcloud-app", "ls", "-1A", "/var/www/html/data"))
office = text(run("podman", "exec", "nextcloud-db", "psql", "-X", "-At", "-U", "nextcloud", "-d", "nextcloud", "-c",
                  "SELECT coalesce(json_object_agg(appid || '.' || configkey, configvalue ORDER BY appid, configkey), '{}') "
                  "FROM oc_appconfig WHERE (appid = 'richdocuments' AND configkey IN ('wopi_url', 'public_wopi_url', "
                  "'wopi_callback_url', 'wopi_allowlist', 'disable_certificate_verification')) "
                  "OR (appid = 'core' AND configkey = 'backgroundjobs_mode')"))
fp = run("podman", "exec", "-u", "www-data", "nextcloud-app", "php", "/var/www/html/occ", "config:system:get",
         "data-fingerprint")
fp = fp.stdout.decode("utf-8", "replace").strip() if fp.returncode == 0 else ""
units = {u: (text(run("systemctl", "--user", "is-active", u)) or "inactive").strip() for u in REQ["units"]}
print(json.dumps({"config_sha256": cfg.split()[0] if cfg else None,
                  "users": sorted(json.loads(users)) if users else None,
                  "status": json.loads(status) if status else None,
                  "db": json.loads(db) if db else None,
                  "data_top": sorted(top.split()) if top is not None else None, "units": units,
                  "office": json.loads(office) if office else None,
                  "fingerprint": __import__("hashlib").sha256(fp.encode()).hexdigest()[:16] if fp else None,
                  "filecache_rows": int(files) if files and files.strip().isdigit() else None}))
'''

ENGINE_HASHES = r'''
import hashlib, json, os
lib = "/usr/local/lib/woowtech-cockpit-backup/woowbackup"
out = {}
for d, dirs, files in os.walk(lib):
    dirs[:] = [x for x in dirs if x != "__pycache__"]
    for f in files:
        if f.endswith(".py"):
            p = os.path.join(d, f)
            out[os.path.relpath(p, lib)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
print(json.dumps(out))
'''

LEAKS = 'import json\n' + __import__('inspect').getsource(drv.secret_scan_needles) + r'''
import os, subprocess, sys
req = json.loads(sys.stdin.read())
secrets = {name: value.encode() for name, value in req["secrets"].items() if value}
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
# The whole device journal, entry by entry. A public link's token is part of its URL (Nextcloud
# apps/dav/lib/Connector/Sabre/PublicAuth.php:104-109 reads it from public.php/dav/files/<token>/) and the web servers log
# every request line (the gateway's nginx.conf:23,27 `$request`/`$remote_user`, Apache's apache2.conf:213 `%r`/`%u`):
# for the names in `url_tokens` ONLY, hits in an HTTP access-log entry of the Nextcloud gateway or app unit that
# requests public.php/ are counted apart (the client's own public-link requests); everything else counts as a hit.
url_needles = secret_scan_needles([secrets[n] for n in req.get("url_tokens", []) if n in secrets])
other = [s for s in needles if s not in url_needles]
ACCESS_UNITS = ("nextcloud-gateway.service", "nextcloud-app.service")
def access_line(entry):
    try:
        e = json.loads(entry)
    except ValueError:
        return False
    msg = e.get("MESSAGE")
    msg = bytes(msg).decode("utf-8", "replace") if isinstance(msg, list) else str(msg or "")
    return e.get("_SYSTEMD_USER_UNIT") in ACCESS_UNITS and "public.php/" in msg and " HTTP/" in msg
journal = subprocess.run(["journalctl", "-o", "json", "--no-pager"], capture_output=True, check=True).stdout
access, outside_access = 0, 0
for entry in journal.splitlines():
    hits += sum(entry.count(s) for s in other)
    url_hits = sum(entry.count(s) for s in url_needles)
    if url_hits:
        if access_line(entry):
            access += url_hits
        else:
            outside_access += url_hits
hits += outside_access
print(json.dumps({"scanned": scanned, "journal_bytes": len(journal), "names": len(secrets), "hits": hits,
                  "url_token_access_log_hits": access, "url_token_hits_elsewhere": outside_access}))
'''


CANDIDATE = r'''
import io, json, sys, time
sys.path.insert(0, "/usr/local/lib/woowtech-cockpit-backup")
from unittest import mock
from woowbackup import cli, ha_nextcloud
from woowbackup.paths import Paths
req = json.loads(sys.stdin.read())
NCDATA = b"# Nextcloud data directory\n# Do not change this file\n"
def relaxed(work, src, *, out=None, ids=None):
    data = ha_nextcloud.DataDir()
    data.present = data.ncdata = True
    if out is not None:
        out.add(".ncdata", "file", mode=0o644, uid=ids[0], gid=ids[1], mtime=time.time(), size=len(NCDATA),
                fileobj=io.BytesIO(NCDATA))
    work.log("INTERNAL CANDIDATE: the users' files are not in this backup; the data dir gets only .ncdata")
    return data
svc = cli.Services(Paths(), launcher=lambda job_id: None)
def call(argv, request=None):
    out = io.StringIO()
    code = cli.main(argv, stdin=io.StringIO(json.dumps(request) if request is not None else ""), stdout=out,
                    services=svc)
    lines = out.getvalue().strip().splitlines()
    return code, json.loads(lines[-1]) if lines else {}
code, reply = call(["ha-convert-start"], req["request"])
if code != 0 or not reply.get("job_id"):
    print(json.dumps({"started": False, "error": (reply.get("error") or {}).get("code")}))
    sys.exit(0)
with mock.patch.object(ha_nextcloud, "datadir_pass", relaxed):
    code, run = call(["run-job", reply["job_id"]])
print(json.dumps({"started": True, "job_id": reply["job_id"], "state": run.get("state"), "code": code}))
'''


CLIENT = r'''
import base64, hashlib, json, re, subprocess, sys, urllib.error, urllib.parse, urllib.request
REQ = json.loads(sys.stdin.read())
NC = "http://127.0.0.1:18081"
NAME = re.compile(r"[A-Za-z0-9._@-]{1,64}")
def call(method, path, user=None, password=None, headers=None, body=None):
    h = dict(headers or {})
    if user is not None:
        h["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(NC + path, method=method, headers=h, data=body)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
def q(text):
    return urllib.parse.quote(text, safe="/")
def sha(code, data):
    return hashlib.sha256(data).hexdigest() if code == 200 else "HTTP%d" % code
def short(value):
    return hashlib.sha256(value.encode()).hexdigest()[:16] if value else None
def sql(statement):
    p = subprocess.run(["podman", "exec", "nextcloud-db", "psql", "-X", "-At", "-U", "nextcloud", "-d", "nextcloud",
                        "-c", statement], capture_output=True, timeout=120)
    return p.stdout.decode().strip() if p.returncode == 0 else None
def app_sh(script, *args):
    p = subprocess.run(["podman", "exec", "-u", "www-data", "nextcloud-app", "sh", "-c", script, "sh", *args],
                       capture_output=True, timeout=900)
    return p.stdout.decode("utf-8", "replace").strip() if p.returncode == 0 else "rc%d" % p.returncode
PROP = (b'<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop>%s</d:prop>'
        b'</d:propfind>')
DAVX = {"Depth": "0", "Content-Type": "application/xml"}
user, pw = REQ["user"], REQ["user_pw"]
assert NAME.fullmatch(user) and all(NAME.fullmatch(u) for u in REQ.get("digest_users", []))
out = {}
code, body = call("GET", "/status.php")
out["status"] = json.loads(body) if code == 200 else None
ocs = {}
for kind, secret in (("password", pw), ("app_password", REQ.get("app_pw")), ("wrong", pw + "-wrong")):
    if secret is None:
        continue
    c, data = call("GET", "/ocs/v2.php/cloud/user?format=json", user, secret, {"OCS-APIRequest": "true"})
    try:
        ident = json.loads(data)["ocs"]["data"]["id"] if c == 200 else None
    except (ValueError, KeyError, TypeError):
        ident = None
    ocs[kind] = [c, ident == user]
out["ocs"] = ocs
# Office as this Nextcloud sees it (richdocuments capabilities; `collabora` is what it read from its WOPI server).
c, data = call("GET", "/ocs/v2.php/cloud/capabilities?format=json", user, pw, {"OCS-APIRequest": "true"})
office = None
if c == 200:
    try:
        rd = json.loads(data)["ocs"]["data"]["capabilities"].get("richdocuments") or {}
        cfg = rd.get("config") if isinstance(rd.get("config"), dict) else {}
        col = rd.get("collabora")
        office = {"keys": sorted(rd)[:40], "config": {k: cfg[k] for k in ("wopi_url", "public_wopi_url", "wopi_callback_url",
                                                                       "disable_certificate_verification") if k in cfg},
                  "collabora": sorted(col)[:30] if isinstance(col, dict) else bool(col),
                  "product": str(rd.get("productName") or "")[:60]}
    except (ValueError, KeyError, TypeError, AttributeError):
        office = "unreadable"
out["capabilities"] = [c, office]
c, data = call("PROPFIND", "/remote.php/dav/files/%s/" % q(user), user, pw, DAVX, PROP % b"<oc:data-fingerprint/>")
m = re.search(rb"<oc:data-fingerprint>([^<]*)</oc:data-fingerprint>", data or b"")
out["fingerprint"] = [c, short(m.group(1).decode()) if m else None]
c, data = call("GET", "/hosting/discovery")
out["discovery"] = [c, b"<wopi-discovery" in data and b"urlsrc" in data]
out["files"] = {name: sha(*call("GET", "/remote.php/dav/files/%s/%s" % (q(user), q(name)), user, pw))
                for name in REQ.get("files", [])}
if REQ.get("user2"):
    assert NAME.fullmatch(REQ["user2"])
    out["user2_file"] = sha(*call("GET", "/remote.php/dav/files/%s/%s" % (q(REQ["user2"]), q(REQ["user2_file"])),
                                  REQ["user2"], REQ["user2_pw"]))
if REQ.get("link_token"):
    path = "/public.php/dav/files/%s/%s" % (q(REQ["link_token"]), q(REQ["link_file"]))
    out["link"] = [sha(*call("GET", path, "anonymous", REQ["link_pw"])), call("GET", path)[0],
                   call("GET", path, "anonymous", REQ["link_pw"] + "-wrong")[0]]
for kind, base in (("caldav", "/remote.php/dav/calendars/%s/"), ("carddav", "/remote.php/dav/addressbooks/users/%s/")):
    if REQ.get(kind):
        c, data = call("GET", base % q(user) + q(REQ[kind]), user, pw)
        out[kind] = [c, c == 200 and ("UID:" + REQ[kind + "_uid"]).encode() in data]
if REQ.get("versioned"):
    c, data = call("PROPFIND", "/remote.php/dav/files/%s/%s" % (q(user), q(REQ["versioned"])), user, pw, DAVX,
                   PROP % b"<oc:fileid/>")
    m = re.search(rb"<oc:fileid>([0-9]{1,18})</oc:fileid>", data or b"")
    listed = None
    if m:
        c2, data2 = call("PROPFIND", "/remote.php/dav/versions/%s/versions/%s" % (q(user), m.group(1).decode()), user, pw,
                         {"Depth": "1"})
        listed = [c2, len(re.findall(rb"<d:response>", data2)) - 1 if c2 == 207 else None]
    out["versions"] = {"dav": listed, "on_disk": app_sh('find "$1" -type f 2>/dev/null | wc -l',
                                                        "/var/www/html/data/%s/files_versions" % user)}
# Per-user manifest digests of the data dir, the showcase method: cd D; find . -type f -print0 | LC_ALL=C sort -z |
# xargs -0 -r sha256sum | sha256sum.
out["digests"] = {u: app_sh('cd "$1" 2>/dev/null || exit 3; find . -type f -print0 | LC_ALL=C sort -z | '
                            'xargs -0 -r sha256sum | sha256sum | cut -c1-64', "/var/www/html/data/%s/files" % u)
                  for u in REQ.get("digest_users", [])}
out["storage"] = sql("SELECT id FROM oc_storages WHERE id LIKE 'local::%' ORDER BY numeric_id")
out["owners"] = sql("SELECT string_agg(DISTINCT tableowner, ',') FROM pg_tables WHERE schemaname = 'public'")
out["lastcron"] = sql("SELECT configvalue FROM oc_appconfig WHERE appid = 'core' AND configkey = 'lastcron'")
print(json.dumps(out))
'''
DROPIN_DIR_REL = '.config/systemd/user/nextcloud-app.service.d'
DROPIN_REL = DROPIN_DIR_REL + '/zz-ncflow-fail-once.conf'
FAIL_MARKER_REL = '.ncflow-fail-once'


def isolation():
    proc = subprocess.run([drv.LP, 'inspect', DEVICE, '--format',
                           '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'],
                          capture_output=True, timeout=60)
    return proc.stdout.decode().strip()


def clean_tree():
    proc = subprocess.run(['git', '-C', str(REPO), 'status', '--porcelain', '--untracked-files=no'],
                          capture_output=True, timeout=60, check=True)
    return not proc.stdout.strip()


def host_free():
    st = os.statvfs('/')
    return st.f_bavail * st.f_frsize


def tree_hashes():
    lib = REPO / 'backup-engine' / 'woowbackup'
    return {str(p.relative_to(lib)): sha256_file(p) for p in sorted(lib.rglob('*.py')) if '__pycache__' not in p.parts}


class Run:
    def __init__(self, args, ev):
        self.args, self.ev = args, ev
        self.lock_started = time.monotonic()
        self.created_store = None
        self.before = {}
        self.section = {}
        self.safety = None          # the import's safety backup: dev-e's own Nextcloud before the import
        self.restored_back = False  # True once that safety backup is restored (manual rollback)

    def budget(self, phase, need=NEED, *, timed=True):
        """Before a step: the lock hold budget (`timed`; never for putting dev-e's own data back) and the host floor."""
        if timed and time.monotonic() - self.lock_started > (RUN_HOLD_BUDGET if self.args.run else HOLD_BUDGET):
            raise Failed(f'lock hold budget reached before {phase}')
        free = host_free()
        if free < WATCH_FLOOR + need:  # the watchdog's floor: a step that fits the 12 GiB floor only would trip it
            raise Failed(f'host free space {free} below the watch floor plus the step need {need} before {phase}')

    def state(self):
        return drv.device_python(STATE, {'units': list(UNITS)}, timeout=600)

    def markers(self):
        password = json.loads(MARKERS.read_text(encoding='utf-8'))['nextcloud']
        script = (HERE / 'batch2_markers.py').read_text(encoding='utf-8')
        proc = drv.owner('python3', '-I', '-c', script, 'nextcloud', 'read',
                         input=json.dumps({'password': password}).encode(), timeout=600)
        lines = [line for line in drv.out(proc).splitlines() if line.strip()]
        if proc.returncode != 0 or not lines:
            raise Failed('batch2_markers.py nextcloud read failed')
        return json.loads(lines[-1])

    def setup(self):
        ev = self.ev
        self.budget('setup')
        proc = subprocess.run([str(HERE / 'deploy-src.sh'), 'e', '--src', str(REPO), '--no-demo-catalog'],
                              capture_output=True, timeout=1800)
        ev.save('deploy-src.log', proc.stdout.decode('utf-8', 'replace')[-20000:] + proc.stderr.decode('utf-8', 'replace')[-5000:])
        if not ev.check('setup: deploy-src.sh e --src this tree', proc.returncode == 0, f'rc={proc.returncode}'):
            raise Failed('deploy-src')
        installed = drv.device_python(ENGINE_HASHES, as_owner=False)
        tree = tree_hashes()
        differ = sorted(k for k in set(tree) | set(installed) if tree.get(k) != installed.get(k))
        if not ev.check('setup: the installed engine is exactly this tree', not differ,
                        {'modules': len(tree), 'differ': differ[:10]}):
            raise Failed('engine differs')
        status = drv.ok('status', ev=ev)
        ev.check('setup: the helper answers status with this tree\'s VERSION',
                 status.get('version') == (REPO / 'VERSION').read_text().strip(), status.get('version'))
        entry = drv.catalog('nextcloud')
        ev.save('catalog-nextcloud.json', entry)
        ok = (set(UNITS) <= set(entry.get('units') or []) and not entry.get('postgres') and not entry.get('volumes')
              and len(entry.get('data_dirs') or []) == 4)
        if not ev.check('setup: the nextcloud catalog entry names the five units and the four data dirs', ok,
                        {'units': entry.get('units'), 'data_dirs': entry.get('data_dirs')}):
            raise Failed('catalog entry')
        key = drv.ok('key-init', ev=ev)
        ev.check('setup: a device key exists (key-init)', bool((key.get('key') or {}).get('key_id')),
                 {'created': key.get('created')})
        state = self.state()
        ev.save('state-setup.json', state)
        running = all(v == 'active' for v in (state.get('units') or {}).values())
        status = state.get('status') or {}
        if not ev.check('setup: Nextcloud runs (five units active, status.php installed 35.0.1.1, no maintenance)',
                        running and status.get('installed') is True and status.get('version') == '35.0.1.1'
                        and status.get('maintenance') is False, {'units': state.get('units'), 'status': status}):
            raise Failed('Nextcloud not running')

    def base_client(self):
        """dev-e's own account through the same client program (read only): logins, Office capabilities, the data
        fingerprint, the discovery."""
        return drv.device_python(CLIENT, {'user': BASE_USER, 'user_pw': self.args.secrets['DEV_D_MARKER_NEXTCLOUD']},
                                 timeout=600)

    @staticmethod
    def live_sizes():
        """Bytes of dev-e's live Nextcloud dirs (podman unshare du as appowner; read only)."""
        sizes = {}
        for name in ('html', 'postgres', 'data'):
            proc = drv.owner('podman', 'unshare', 'du', '-sb', f'{LIVE_ROOT}/{name}', timeout=900)
            try:
                sizes[name] = int(drv.out(proc).split()[0]) if proc.returncode == 0 else None
            except (ValueError, IndexError):
                sizes[name] = None
        return sizes

    def convert_need(self, datadir_bytes):
        """The conversion's staging peak (ha_nextcloud.convert order): HA's data dir tar and the PostgreSQL dir tar
        stay while the cluster work (dump + volume, volume + export: about 3x the cluster), then the live html pack plus
        the html dir tar (2x html), then the dir tars plus the archive (code and the cluster compress to about half,
        the users' files not at all); plus margin."""
        sizes = self.before.get('sizes') or {}
        html = sizes.get('html') or 2 * 1024 ** 3
        pg = sizes.get('postgres') or 1024 ** 3
        data = int(datadir_bytes or 0)
        archive = data + (html + pg) // 2
        return (data + pg + max(3 * pg, 2 * html, html + archive) + 512 * 1024 ** 2
                + int(self.args.facts.get('extra_need', 0)))

    def before_state(self):
        ev = self.ev
        self.before = {'markers': self.markers(), 'state': self.state(), 'client': self.base_client(),
                       'sizes': self.live_sizes()}
        ev.save('before.json', self.before)
        ev.check('before: dev-e\'s own markers read (baseline user and its WebDAV file)',
                 BASE_USER in (self.before['markers'].get('users') or [])
                 and bool(self.before['markers'].get('files')), self.before['markers'])
        client = self.before['client']
        ev.check('before: dev-e\'s own account logs in (OCS) and the wrong password is refused',
                 (client.get('ocs') or {}).get('password') == [200, True]
                 and ((client.get('ocs') or {}).get('wrong') or [None])[0] == 401, client.get('ocs'))
        ev.log(f'before: capabilities {client.get("capabilities")} discovery {client.get("discovery")} '
               f'fingerprint set {bool((client.get("fingerprint") or [None, None])[1])} office {self.before["state"].get("office")}')

    def upload(self):
        ev = self.ev
        self.budget('upload', (RUN_CHECK_NEED if self.args.run else NEED) + FIXTURE.stat().st_size)
        if not ev.check('upload: the fixture has the recorded SHA-256', sha256_file(FIXTURE) == FIXTURE_SHA):
            raise Failed('fixture differs')
        started = time.monotonic()
        rc, reply = drv.upload(FIXTURE, ev=ev)
        meta = reply.get('ha_backup') or {}
        self.created_store = meta.get('id') if rc == 0 else None
        ev.save('ha-backup.json', meta)
        found = {a['app_id']: a['installed'] for a in meta.get('importable_apps') or []}
        ev.check('upload: upload-finish answers the HA record', rc == 0 and str(meta.get('id', '')).startswith('ha-'),
                 f'{time.monotonic() - started:.1f} s')
        ev.check('upload: nextcloud is importable and installed here', found.get('nextcloud') is True, found)
        if not self.created_store:
            raise Failed('upload')

    def check(self):
        ev = self.ev
        self.budget('check', RUN_CHECK_NEED if self.args.run else NEED)
        job, took = drv.run_check(self.created_store, ['nextcloud'], ev=ev, key=self.args.secrets['HA_BACKUP_KEY'])
        ev.time('check', 'share' if self.args.run else 'noshare', 'nextcloud', took, job)
        result = (job.get('result') or {}).get('ha_check') or {}
        apps = result.get('apps') or []
        app = apps[0] if apps else {}
        ev.save('check-result.json', result)
        ev.check('check: the job succeeds and answers one app', job.get('state') == 'succeeded' and len(apps) == 1,
                 {'state': job.get('state'), 'error': job.get('error')})
        blockers = app.get('blockers') or []
        if self.args.run:
            ev.check('check: nextcloud is ok with no blocker', app.get('ok') is True and not blockers, blockers)
        else:
            self.negative_blockers(blockers, app)
        section = self.section = app.get('nextcloud') or {}
        differ = {k: [v, section.get(k)] for k, v in SECTION.items() if section.get(k) != v}
        ev.check('check: the section equals the backup facts (HA cluster opened and read: users, files, tokens, apps)',
                 not differ, differ or section)
        ev.check('check: amd64, add-on 0.2.3, target 35.0.1.1',
                 (app.get('arch'), app.get('version'), app.get('target_version')) == ('amd64', '0.2.3', '35.0.1.1'),
                 {k: app.get(k) for k in ('arch', 'version', 'target_version')})

    def negative_blockers(self, blockers, app):
        ev = self.ev
        ev.check('check: nextcloud is not ok and the first blocker names the missing share folder and /share/nextcloud',
                 app.get('ok') is False and bool(blockers) and SHARE_TEXT in blockers[0] and '/share/nextcloud' in blockers[0],
                 blockers)
        ev.check('check: the missing user files are the only blocker', len(blockers) == 1, blockers)

    def convert(self):
        ev = self.ev
        self.budget('convert')
        before = {b['id'] for b in drv.ok('list', ev=ev).get('backups') or []}
        job, took = drv.convert(self.created_store, ['nextcloud'], False, ev=ev, key=self.args.secrets['HA_BACKUP_KEY'],
                                tag='nc-noshare-convert')
        ev.time('convert', 'noshare', 'nextcloud', took, job)
        error = job.get('error') or {}
        ev.save('convert-job.json', {'state': job.get('state'), 'error': error})
        ev.check('convert: the job fails incompatible with the same sentence (nothing is built)',
                 job.get('state') == 'failed' and error.get('code') == 'incompatible'
                 and SHARE_TEXT in str(error.get('message')) and '/share/nextcloud' in str(error.get('message')),
                 {'state': job.get('state'), 'code': error.get('code')})
        after = {b['id'] for b in drv.ok('list', ev=ev).get('backups') or []}
        ev.check('convert: no backup was added', after == before, sorted(after - before))

    def watch_host(self, stop, tripped):
        """While the candidate runs: the host floor (dev-e's engine only sees its own floor). On a breach every running
        job of dev-e is cancelled through the helper; the job stops and removes its objects itself."""
        while not stop.wait(2):
            if host_free() >= WATCH_FLOOR:
                continue
            tripped.append(host_free())
            try:
                jobs = drv.ok('jobs', ev=self.ev).get('jobs') or []
                for job in jobs:
                    if job.get('state') in ('queued', 'running'):
                        drv.helper('job-cancel', {'job_id': job['id']})
            except Failed:
                pass
            return

    @contextlib.contextmanager
    def watching(self, tripped):
        stop = threading.Event()
        watcher = threading.Thread(target=self.watch_host, args=(stop, tripped), daemon=True)
        watcher.start()
        try:
            yield
        finally:
            stop.set()
            watcher.join(timeout=60)

    def candidate(self):
        ev = self.ev
        self.budget('candidate')
        if not ev.check('candidate: the host keeps 12 GiB plus the candidate\'s need free', host_free() >= FLOOR + CANDIDATE_NEED,
                        f'{host_free()} B'):
            return
        before = {b['id'] for b in drv.ok('list', ev=ev).get('backups') or []}
        request = {'ha_backup_id': self.created_store, 'apps': ['nextcloud'], 'test_mode': False, 'confirm': True,
                   'request_id': drv.request_id('nc-candidate'), 'key': self.args.secrets['HA_BACKUP_KEY']}
        started = time.monotonic()
        stop, tripped = threading.Event(), []
        watcher = threading.Thread(target=self.watch_host, args=(stop, tripped), daemon=True)
        watcher.start()
        try:
            run = drv.device_python(CANDIDATE, {'request': request}, as_owner=False, timeout=5400)
        finally:
            stop.set()
            watcher.join(timeout=60)
        took = time.monotonic() - started
        ev.check('candidate: the host floor held during the conversion (no cancel needed)', not tripped, tripped)
        ev.save('candidate-run.json', run)
        job = drv.ok('job-status', {'job_id': run.get('job_id')}, ev=ev).get('job') if run.get('started') else {}
        ev.time('candidate-convert', 'noshare', 'nextcloud', took, job)
        result = (job or {}).get('result') or {}
        ev.save('candidate-job.json', {'job': job})
        backup = result.get('backup_id')
        if backup:
            drv.STATE.setdefault('created_backups', []).append(backup)
        if not ev.check('candidate: the internal conversion job succeeds (real dump, new cluster, role, restore, '
                        'fix-ups verified against the live database, PHP check, dir tars, packaging)',
                        run.get('started') and (job or {}).get('state') == 'succeeded' and bool(backup),
                        {'run': run, 'state': (job or {}).get('state'), 'error': (job or {}).get('error')}):
            return
        self.converted = backup
        row = result.get('ha_import') or {}
        ev.check('candidate: the notes and reminders name Collabora, the share folder rule and the MCP admin lines',
                 any('Collabora' in n for n in row.get('notes') or [])
                 and any('Woow Nextcloud MCP Server' in r for r in (row.get('reminders_by_app') or {}).get('nextcloud') or []),
                 row)
        inspect = drv.ok('inspect', {'backup_id': backup}, ev=ev, timeout=900)
        ev.save('candidate-inspect.json', inspect)
        pre = inspect.get('preflight') or {}
        failed = [c for c in pre.get('checks') or [] if c.get('status') == 'fail']
        ev.check('candidate: inspect: preflight passes, settings same, in place',
                 pre.get('ok') and not failed and all((a.get('settings') or {}).get('state') == 'same'
                                                      and a.get('mode') == 'inplace' for a in pre.get('apps') or []),
                 failed[:3] or [(a.get('id'), a.get('mode')) for a in pre.get('apps') or []])
        apps = (inspect.get('manifest') or {}).get('apps') or []
        dirs = sorted(d.get('path') for a in apps for d in a.get('data_dirs') or [] if isinstance(d, dict))
        ev.check('candidate: the converted backup holds the four Nextcloud data dirs',
                 dirs == sorted(f'.local/share/nextcloud-office/{n}' for n in ('data', 'html', 'postgres', 'redis')),
                 dirs)
        after = {b['id'] for b in drv.ok('list', ev=ev).get('backups') or []}
        ev.check('candidate: exactly the converted backup was added', after - before == {backup}, sorted(after - before))

    # -------- the acceptance run (share-including backup)
    def restore_need(self, backup_id):
        """Host bytes a restore of `backup_id` may write while the old and the new dirs both exist: the pending copy of
        the live dirs and the safety package made from it (2 x the live dirs), the restored dirs (2 x the backup:
        code and the cluster compress to about half), with margin. Attempt 3 (2026-11-24) measured ~3.7 GB for the
        import's restore against the 2 x backup + 2 GiB used until then."""
        backups = {b['id']: b for b in drv.ok('list', ev=self.ev).get('backups') or []}
        size = int((backups.get(backup_id) or {}).get('size') or 0)
        live = sum(v for v in (self.before.get('sizes') or {}).values() if isinstance(v, int)) or 2 * 1024 ** 3
        return 2 * size + 2 * live + 2 * 1024 ** 3

    def import_real(self):
        ev, facts = self.ev, self.args.facts
        need = self.convert_need(self.section.get('datadir_bytes'))
        ev.log(f'import: conversion need {need} B (live sizes {self.before.get("sizes")})')
        self.budget('import', need)
        tripped = []
        with self.watching(tripped):
            job, took = drv.convert(self.created_store, ['nextcloud'], False, ev=ev,
                                    key=self.args.secrets['HA_BACKUP_KEY'], tag='nc-share-convert')
        ev.time('convert', 'share', 'nextcloud', took, job)
        result = job.get('result') or {}
        ev.save('convert-job.json', {'state': job.get('state'), 'error': job.get('error'), 'result': result})
        self.converted = result.get('backup_id')
        drv.created_backup(self.converted)
        if not ev.check('import: ha-convert-start succeeds (the product\'s space guard; host floor held)',
                        job.get('state') == 'succeeded' and bool(self.converted) and not tripped,
                        {'state': job.get('state'), 'error': job.get('error'), 'tripped': tripped}):
            raise Failed('convert')
        row = result.get('ha_import') or {}
        ev.check('import: the notes and reminders name Collabora, the data fingerprint and the MCP admin lines',
                 any('Collabora' in n for n in row.get('notes') or []) and any('資料指紋' in n for n in row.get('notes') or [])
                 and any('Woow Nextcloud MCP Server' in r for r in (row.get('reminders_by_app') or {}).get('nextcloud') or []),
                 row)
        inspect = drv.ok('inspect', {'backup_id': self.converted}, ev=ev, timeout=900)
        ev.save('inspect.json', inspect)
        pre = inspect.get('preflight') or {}
        failed = [c for c in pre.get('checks') or [] if c.get('status') == 'fail']
        if not ev.check('import: inspect: preflight passes, settings same, in place',
                        pre.get('ok') and not failed and all((a.get('settings') or {}).get('state') == 'same'
                                                             and a.get('mode') == 'inplace' for a in pre.get('apps') or []),
                        failed[:3] or [(a.get('id'), a.get('mode')) for a in pre.get('apps') or []]):
            raise Failed('inspect')
        need = self.restore_need(self.converted)
        if self.created_store:
            # The page lets the user delete the HA file at any time; the share run does it before the restore, so the
            # restores and rollbacks have the host space they write (attempt 3 tripped the watchdog with it kept).
            rc, _reply = drv.helper('ha-delete', {'ha_backup_id': self.created_store, 'confirm': True})
            ev.check('import: the uploaded HA file is deleted before the restore (as the page allows; host space)',
                     rc == 0)
            if rc == 0:
                self.created_store = None
        self.budget('restore', need)
        tripped = []
        with self.watching(tripped):
            job, took = drv.restore(self.converted, ['nextcloud'], ev=ev, tag='nc-share-restore')
        ev.time('restore', 'share', 'nextcloud', took, job)
        result = job.get('result') or {}
        self.safety = result.get('safety_backup_id')
        drv.created_backup(self.safety)
        health = result.get('health') or []
        ev.save('restore-job.json', {'state': job.get('state'), 'error': job.get('error'), 'health': health})
        if not ev.check('import: restore-start succeeds with its safety backup and every health check ok',
                        job.get('state') == 'succeeded' and bool(self.safety) and bool(health) and not tripped
                        and all(h.get('status') == 'ok' for h in health),
                        {'state': job.get('state'), 'error': job.get('error'), 'took_s': round(took, 1), 'tripped': tripped}):
            raise Failed('restore')

    def client(self):
        facts, secrets = self.args.facts, self.args.secrets
        request = {'user': facts['user'], 'user_pw': secrets[facts['user_pw']], 'app_pw': secrets[facts['app_pw']],
                   'files': sorted(facts['files']), 'digest_users': sorted(facts.get('digests') or {}),
                   'versioned': facts.get('versioned')}
        if facts.get('user2'):
            request.update(user2=facts['user2'], user2_pw=secrets[facts['user2_pw']], user2_file=facts['user2_file'])
        if facts.get('link_token'):
            request.update(link_token=secrets[facts['link_token']], link_pw=secrets[facts['link_pw']],
                           link_file=facts['link_file'])
        for kind in ('caldav', 'carddav'):
            if facts.get(kind):
                request.update({kind: facts[kind], f'{kind}_uid': facts[f'{kind}_uid']})
        return drv.device_python(CLIENT, request, timeout=1800)

    @staticmethod
    def same_sha(found, want):
        """A full SHA-256 equals; a recorded 16-character prefix (the showcase lane prints prefixes) is its start."""
        return isinstance(found, str) and isinstance(want, str) and len(want) >= 16 and found.startswith(want)

    def verify(self, phase):
        ev, facts = self.ev, self.args.facts
        found = self.client()
        state = self.state()
        ev.save(f'client-{phase}.json', {'client': found, 'state': state})
        status = found.get('status') or {}
        ev.check(f'{phase}: status.php installed 35.0.1.1, no maintenance, no database upgrade needed',
                 status.get('installed') is True and status.get('version') == '35.0.1.1' and status.get('maintenance') is False
                 and status.get('needsDbUpgrade') is False, status)
        files = found.get('files') or {}
        ev.check(f'{phase}: the HA test user\'s WebDAV files (CJK names, nested, 4 MiB binary) have the recorded SHA-256',
                 set(files) == set(facts['files']) and all(self.same_sha(files[n], facts['files'][n]) for n in files),
                 {n: (v[:16] if isinstance(v, str) else v) for n, v in files.items()})
        digests = found.get('digests') or {}
        ev.check(f'{phase}: every HA user\'s files on disk equal the backup (per-user manifest digests, showcase method)',
                 bool(digests) and digests == facts.get('digests'), {u: str(d)[:16] for u, d in digests.items()})
        ocs = found.get('ocs') or {}
        ev.check(f'{phase}: OCS login with the HA password and with HA\'s app password (secret moved); wrong password 401',
                 ocs.get('password') == [200, True] and ocs.get('app_password') == [200, True]
                 and (ocs.get('wrong') or [None])[0] == 401, ocs)
        if facts.get('user2'):
            ev.check(f'{phase}: the second HA user reads the file shared with them (user share moved)',
                     self.same_sha(found.get('user2_file'), facts['files'].get(facts['user2_shared'])),
                     str(found.get('user2_file'))[:16])
        if facts.get('link_token'):
            link = found.get('link') or [None, None, None]
            ev.check(f'{phase}: the password-protected public link serves the file; without or with a wrong password 401',
                     self.same_sha(link[0], facts['files'].get(facts['user2_shared'])) and link[1] == 401 and link[2] == 401,
                     [str(link[0])[:16], link[1], link[2]])
        for kind, text in (('caldav', 'CalDAV event'), ('carddav', 'CardDAV contact')):
            if facts.get(kind):
                ev.check(f'{phase}: the HA test user\'s {text} is served with its UID', found.get(kind) == [200, True],
                         found.get(kind))
        if facts.get('versioned'):
            versions = found.get('versions') or {}
            dav = versions.get('dav') or [None, None]
            ev.check(f'{phase}: the older version is on disk and listed by the versions API',
                     str(versions.get('on_disk')) == str(facts['versions']) and dav[0] == 207
                     and isinstance(dav[1], int) and dav[1] >= int(facts['versions']), versions)
        before = self.before['state']
        ev.check(f'{phase}: Office settings (richdocuments wopi keys) and the cron mode are exactly this device\'s',
                 state.get('office') == before.get('office') and bool(before.get('office')),
                 {'before': before.get('office'), 'now': state.get('office')})
        caps = found.get('capabilities') or [None, None]
        base_caps = (self.before.get('client') or {}).get('capabilities') or [None, None]
        ev.check(f'{phase}: Nextcloud reports this device\'s Office server (capabilities as for dev-e\'s own account)',
                 caps[0] == 200 and isinstance(caps[1], dict) and caps[1] == base_caps[1], {'now': caps, 'before': base_caps})
        ev.check(f'{phase}: Collabora discovery is served on this device\'s gateway', found.get('discovery') == [200, True],
                 found.get('discovery'))
        fp = found.get('fingerprint') or [None, None]
        ev.check(f'{phase}: clients see a new data fingerprint (restored-from-backup signal), the one in config.php',
                 fp[0] == 207 and bool(fp[1]) and fp[1] == state.get('fingerprint')
                 and fp[1] != ((self.before.get('client') or {}).get('fingerprint') or [None, None])[1],
                 {'dav': fp, 'config': state.get('fingerprint')})
        ev.check(f'{phase}: database: root storage is this device\'s data dir, tables owned by oc_admin',
                 found.get('storage') == 'local::/var/www/html/data/' and found.get('owners') == 'oc_admin',
                 {k: found.get(k) for k in ('storage', 'owners')})
        ev.log(f'{phase}: lastcron {found.get("lastcron")}')
        return found

    def restart(self):
        ev = self.ev
        drv.owner('systemctl', '--user', 'restart', 'nextcloud-app.service', timeout=900)
        deadline = time.monotonic() + 600
        state = {}
        while time.monotonic() < deadline:
            state = self.state()
            if all(v == 'active' for v in (state.get('units') or {}).values()) and (state.get('status') or {}).get('installed'):
                break
            time.sleep(10)
        ev.check('restart: nextcloud-app restarted, five units active, status.php answers',
                 all(v == 'active' for v in (state.get('units') or {}).values())
                 and bool((state.get('status') or {}).get('installed')), state.get('units'))
        self.verify('restart')

    def inject(self, on):
        home = '/home/appowner/'
        if on:
            drv.owner('mkdir', '-p', home + DROPIN_DIR_REL, timeout=60)
            text = ("[Service]\nExecStartPre=/bin/sh -c 'if test -f %h/" + FAIL_MARKER_REL + "; then rm -f %h/"
                    + FAIL_MARKER_REL + "; exit 1; fi'\n")
            for rel, data, mode in ((DROPIN_REL, text.encode(), '0644'), (FAIL_MARKER_REL, b'fail-once\n', '0600')):
                drv.owner('sh', '-c', 'umask 077; cat > "$1" && chmod "$2" "$1"', 'sh', home + rel, mode, input=data,
                          timeout=60)
            drv.owner('systemctl', '--user', 'daemon-reload', timeout=120)
        else:
            drv.owner('rm', '-f', home + DROPIN_REL, home + FAIL_MARKER_REL, timeout=60)
            drv.owner('rmdir', home + DROPIN_DIR_REL, timeout=60)
            drv.owner('systemctl', '--user', 'daemon-reload', timeout=120)

    def rollback(self):
        ev = self.ev
        self.budget('auto rollback', self.restore_need(self.converted))
        self.inject(True)
        tripped = []
        try:
            with self.watching(tripped):
                job, took = drv.restore(self.converted, ['nextcloud'], ev=ev, tag='nc-share-restore-inject')
        finally:
            consumed = drv.owner('test', '-e', '/home/appowner/' + FAIL_MARKER_REL, timeout=60).returncode != 0
            self.inject(False)
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        ev.save('rollback-auto-job.json', {'state': job.get('state'), 'error': job.get('error'),
                                           'rolled_back': result.get('rolled_back')})
        ev.check('auto rollback: a restore with a one-shot ExecStartPre failure ends rolled-back',
                 job.get('state') == 'rolled-back' and result.get('rolled_back') is True and consumed and not tripped,
                 {'state': job.get('state'), 'took_s': round(took, 1), 'consumed': consumed, 'tripped': tripped})
        self.verify('auto rollback')
        extra = result.get('safety_backup_id')
        if extra and extra != self.safety:  # a backup of the imported state; not needed after this check
            rc, _reply = drv.helper('delete', {'backup_id': extra})
            ev.check('auto rollback: its own safety backup (the imported state) is deleted', rc == 0)
            if rc == 0:
                self.deleted = getattr(self, 'deleted', set()) | {extra}
        self.manual_rollback('rollback')

    def manual_rollback(self, phase):
        """Restore the import's safety backup (dev-e's own Nextcloud): the manual rollback, and the recovery when a run
        stops after the import's restore. Never limited by the lock hold budget; the host floor still applies."""
        ev = self.ev
        self.budget(phase, self.restore_need(self.safety), timed=False)
        tripped = []
        with self.watching(tripped):
            job, took = drv.restore(self.safety, ['nextcloud'], ev=ev, tag=f'nc-share-{phase.replace(" ", "-")}')
        result = job.get('result') or {}
        drv.created_backup(result.get('safety_backup_id'))
        ev.save(f'{phase.replace(" ", "-")}-job.json', {'state': job.get('state'), 'error': job.get('error'),
                                                       'health': result.get('health')})
        self.restored_back = job.get('state') == 'succeeded'
        ev.check(f'{phase}: the import\'s safety backup restored (manual rollback), every health check ok',
                 self.restored_back and not tripped and all(h.get('status') == 'ok' for h in result.get('health') or []),
                 {'state': job.get('state'), 'took_s': round(took, 1), 'tripped': tripped})
        found = self.markers()
        users = self.state().get('users') or []
        ha_only = set(self.args.facts.get('digests') or {}) - set(self.before['state'].get('users') or [])
        ev.check(f'{phase}: dev-e\'s own markers are back exactly and the HA-only users are gone',
                 found == self.before['markers'] and bool(ha_only) and not ha_only & set(users),
                 {'markers_same': found == self.before['markers'], 'users': users, 'ha_only': sorted(ha_only)})
        client = self.base_client()
        ev.check(f'{phase}: dev-e\'s own account logs in again (OCS)', (client.get('ocs') or {}).get('password') == [200, True],
                 client.get('ocs'))

    def after_state(self):
        ev = self.ev
        after = {'markers': self.markers(), 'state': self.state()}
        ev.save('after.json', after)
        ev.check('after: dev-e\'s own markers are unchanged', after['markers'] == self.before['markers'])
        b, a = self.before['state'], after['state']
        # The file cache row count is recorded only (dev-e's own cron job may change it at any time).
        ev.log(f'filecache rows before {b.get("filecache_rows")} after {a.get("filecache_rows")}')
        for key, text in (('config_sha256', 'config.php'), ('users', 'the users'), ('db', 'the storages and user count in the database'),
                          ('data_top', 'the data dir top entries'), ('units', 'the five units'), ('status', 'status.php'),
                          ('office', 'the Office settings and the cron mode')):
            ev.check(f'after: {text} unchanged', a.get(key) == b.get(key) and a.get(key) is not None,
                     {'before': b.get(key), 'after': a.get(key)} if key != 'config_sha256' else '')

    def cleanup(self):
        ev = self.ev
        for backup_id in [getattr(self, 'converted', None)] + list(drv.STATE.get('created_backups') or []):
            if backup_id and backup_id not in getattr(self, 'deleted', set()):
                rc, _reply = drv.helper('delete', {'backup_id': backup_id})
                ev.check('cleanup: a backup this run created is deleted', rc == 0)
                self.deleted = getattr(self, 'deleted', set()) | {backup_id}
        if self.created_store:
            rc, _reply = drv.helper('ha-delete', {'ha_backup_id': self.created_store, 'confirm': True})
            ev.check('cleanup: the HA store record of this run is deleted', rc == 0)
            if rc == 0:
                self.created_store = None
        objects = drv.labelled()
        ev.check('cleanup: no throwaway container, volume or network of a job left', not any(objects.values()), objects)
        listing = drv.device_python(drv.RUN_LIST, as_owner=False)
        staging = listing.get(drv.STAGING)
        keys = [n for n in listing.get('/run/woowtech-backup') or [] if isinstance(n, str) and n.startswith('key-')]
        ev.check('cleanup: no staging folder and no key file left', staging in ([], 'missing') and not keys, listing)

    def leaks(self):
        ev = self.ev
        names = ['HA_BACKUP_KEY', 'B2_NC_X86_NOSHARE_USER_PW', 'B2_NC_X86_NOSHARE_APP_PW', 'DEV_D_MARKER_NEXTCLOUD']
        if self.args.run:
            facts = self.args.facts
            names += [facts[k] for k in ('user_pw', 'app_pw', 'user2_pw', 'link_pw', 'link_token') if facts.get(k)]
        url_tokens = [self.args.facts['link_token']] if self.args.run and self.args.facts.get('link_token') else []
        request = {'secrets': {name: self.args.secrets[name] for name in names}, 'url_tokens': url_tokens}
        report = drv.device_python(LEAKS, request, as_owner=False, timeout=900)
        host = drv.scan_host_evidence(ev.dir, self.args.secrets)
        ev.save('leaks.json', {'device': report, 'host': host})
        ev.check('leaks: the HA key and the HA test credentials are in no engine record, upload, staging, run dir or the '
                 'device journal, and not in this evidence',
                 report.get('hits') == 0 and report.get('scanned', 0) > 0 and not host.get('hits'),
                 {'device': report, 'host_hits': host.get('hits')})
        if url_tokens:
            ev.check('leaks: the public link token is only in the Nextcloud web servers\' access logs of the client\'s own '
                     'public-link requests (a public link carries its token in the URL)',
                     report.get('url_token_access_log_hits', 0) > 0 and report.get('url_token_hits_elsewhere') == 0,
                     {k: report.get(k) for k in ('url_token_access_log_hits', 'url_token_hits_elsewhere')})


def negative(args):
    secrets = drv.Secrets(SECRET_FILES, MARKERS)
    args.secrets = secrets
    ev = Ev(secrets, area='nextcloud-flow')
    emit(f'source commit {subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()}')
    if not ev.check('preflight: the checkout has no tracked change', clean_tree()):
        return 2
    if not ev.check('preflight: dev-e isolation true none {}', isolation() == 'true none {}', isolation()):
        return 2
    # The share run's start need: the upload copy plus the conversion's own need, which comes right after it
    # (attempt 1-3: 2.54 GB); measured against the watchdog's floor, so a run never starts that would stop there.
    need = FIXTURE.stat().st_size + RUN_START_NEED + int(args.facts.get('extra_need', 0)) if args.run else NEED
    floor = WATCH_FLOOR if args.run else FLOOR
    if not ev.check('preflight: the host keeps 12 GiB plus this run\'s need free', host_free() >= floor + need,
                    f'{host_free()} B, need {need} B'):
        return 2
    with open(LOCK, 'a') as lock:
        deadline = time.monotonic() + 3600
        while True:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    ev.check('preflight: the dev-e mutation lock within an hour', False)
                    return 2
                time.sleep(10)
        run = Run(args, ev)
        try:
            if args.run:
                steps = (run.setup, run.before_state, run.upload, run.check, run.import_real,
                         lambda: run.verify('import'), run.restart, run.rollback, run.after_state)
            else:
                steps = (run.setup, run.before_state, run.upload, run.check,
                         run.candidate if args.candidate else run.convert, run.after_state)
            for step in steps:
                step()
        except Failed as error:
            ev.check(f'run stopped: {label(error)}', False)
        finally:
            if args.run and run.safety and not run.restored_back:
                try:  # the run stopped after the import's restore: put dev-e's own Nextcloud back before cleanup
                    run.manual_rollback('recovery')
                except Failed as error:
                    ev.check(f'recovery stopped: {label(error)}', False)
            try:
                if args.run and run.safety and not run.restored_back:
                    raise Failed('dev-e still holds the imported data; the safety backup is kept (no cleanup of backups)')
                run.cleanup()
                run.leaks()
            except Failed as error:
                ev.check(f'cleanup stopped: {label(error)}', False)
            held = int(time.monotonic() - run.lock_started)
            emit(f'lock held for {held} s')
    ev.check('end: dev-e isolation true none {}', isolation() == 'true none {}', isolation())
    return 0 if ev.finish() else 1


def self_check():
    compile((HERE / 'nextcloud_flow.py').read_text(encoding='utf-8'), 'nextcloud_flow.py', 'exec')
    for script in (STATE, ENGINE_HASHES, LEAKS, CANDIDATE, CLIENT):
        compile(script, 'device', 'exec')
    assert all(SAFE_LABEL.sub('', name) == name for name in ('check: amd64, add-on 0.2.3, target 35.0.1.1',))
    print('self-check: PASS')
    return 0


def main(argv):
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--negative', action='store_true')
    group.add_argument('--candidate', action='store_true')
    group.add_argument('--run', action='store_true')
    parser.add_argument('--facts', type=Path)
    group.add_argument('--self-check', action='store_true')
    args = parser.parse_args(argv)
    if args.self_check:
        return self_check()
    if args.run:
        if args.facts is None:
            parser.error('--run needs --facts FILE')
        args.facts = json.loads(args.facts.read_text(encoding='utf-8'))
        global FIXTURE, FIXTURE_SHA, SECTION
        FIXTURE, FIXTURE_SHA = Path(args.facts['fixture']), args.facts['sha256']
        SECTION = dict(args.facts['section'])
    return negative(args)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
