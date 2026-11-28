#!/usr/bin/env python3
"""CODE ONLY until separately leased: R6 skipped entries -- the HA -> Podman import of a Nextcloud whose users' data holds
a nested .htaccess and a symbolic link, which the product must list, have confirmed and leave out (DESIGN NC-26, NC-27).

  python3 -B -I tests/e2e/lab/focus_nextcloud_r6_skipped.py                 offline: the contract (no device, no secret)
  .../heavy.sh python3 -B -I tests/e2e/lab/focus_nextcloud_r6_skipped.py --plan
        HOST ONLY, before any lease: derive the backup as a stream from the original full-share fixture (read once),
        read it straight back with the product's own readers, write the provenance (private, 0600, never overwritten)
  python3 -B -I tests/e2e/lab/focus_nextcloud_r6_skipped.py --lease-template   the lease fields this checkout + plan bind
  HEAVY_FREE=/tmp/woowbk-dev-e-mutation.lock .../heavy.sh python3 -B -I tests/e2e/lab/focus_nextcloud_r6_skipped.py \\
        --run --lease FILE

The fixture (focus_nextcloud_r6_skipped_derive, reviewed in snippets/focus-nextcloud-r6/README.md): the original encrypted
x86 full-share backup (4,467,947,520 bytes, SHA-256 2dcfc676...) with exactly three entries added in a folder of their own
below HA's data directory -- woowbk-r6-skipped-entries/{control.txt, .htaccess (Require all granted), control-link.txt ->
control.txt} -- every original byte kept (the share member is re-encrypted with the same HA key; its plaintext is the
reviewed gzip member followed by the original gzip stream byte for byte). It is never materialised: the plan streams it
into a hash and the product's readers; the run makes the same bytes again (the plan's derivation salt and secretstream
header, bound by the lease through the provenance's SHA-256) straight into dev-e's upload file: the host reads the
original once and writes the derived bytes into R6's bounded in-device writer (focus_nextcloud_r6_upload.WRITER: size,
SHA-256, expiry, reserve and memory checked inside dev-e), like fullshare05's upload, never through a second file on the
host or in dev-e and never in chunks through the helper.

Under ONE lease, on R6's cold-to-cold path (focus_nextcloud_r6_case.run with BINDING, focus_nextcloud_r6.run_locked with
Variant: request recording, job waits, watchdog, recovery, rollback, cleanup and leak gates are reused, not copied):
  admission  the exact lease (this commit, the frozen product of S5-B, the provenance, its derived SHA-256/bytes, the
             two bound keys, the window with HEADROOM left), the heavy seat, the blocking dev-e lock; dev-e cold and
             isolated, no job running, no receipt of this lane pending, the derived HA record absent; the original
             fixture is the prepared one and the key opens it (before anything is written)
  source     whatever engine dev-e runs is captured, the frozen product installed, the captured prior returned at the end
  wake       pinned same-config units started, dev-e's own baseline verified independently
  before     R6's (the encrypted baseline opens, dev-e's markers and own account, live sizes, the budget for the derived
             size); the derived folder is not in dev-e's live data dir
  upload     upload-begin with the derived size, the derivation streamed once into the upload file (bytes and SHA-256
             exact on both ends, the original's SHA-256 exact), upload-finish publishes exactly the derived record, the
             published file is the written inode, its SHA-256 again
  check      exactly nextcloud.symlinks-skipped [nextcloud/woowbk-r6-skipped-entries/control-link.txt] and
             nextcloud.htaccess-skipped [woowbk-r6-skipped-entries/.htaccess], the product's texts and the bound keys; no
             stop, no file-list warning; the section the original's with the control file as one more file
  convert    without any acknowledgement: refused at the link line; with the link's key only: refused at the .htaccess
             line; then with exactly both bound keys (schema fields only, the HA key on stdin)
  import     R6/nextcloud_flow's: inspect, the uploaded HA file deleted, restore with its safety backup
  verify     after the restore, after a restart and after the automatic rollback: nextcloud_flow's full-share checks
             (the original users' files, manifests, logins, shares, CalDAV/CardDAV, versions, Office, files:scan clean,
             nothing served below the data dir) and: no nested .htaccess and no symbolic link anywhere below the data
             dir, the derived folder holds exactly the control file byte for byte (owned like the protection file), the
             data dir's protection file is this device's own (exact SHA-256), the derived folder's URLs answer 403/404
  rollback   R6's: injected automatic rollback, manual rollback to the import's safety backup, the baseline verified
             independently BEFORE any owned artifact is deleted, exact after-state, owned cleanup, leak scans, cold
             return, the exact prior engine back; then this driver's own store and evidence scans
"""
import argparse
import datetime
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))   # python3 -I puts no script directory on the path; only this committed directory
import focus_nextcloud_r6 as r6   # noqa: E402
import focus_nextcloud_r6_case as case   # noqa: E402
import focus_nextcloud_r6_s5 as s5   # noqa: E402
import focus_nextcloud_r6_s5b as s5b   # noqa: E402
import focus_nextcloud_r6_skipped_derive as derive   # noqa: E402
import focus_nextcloud_r6_source as source   # noqa: E402
import focus_nextcloud_r6_upload as upload   # noqa: E402
import focus_nextcloud_r6_wake as wake   # noqa: E402
from focus_nextcloud_r6_inventory import FIXTURE, FIXTURE_SHA   # noqa: E402
from focus_nextcloud_r6_plan import (DEVICE_CAP, FIXTURE_BYTES, GIB, RESERVE, confirmation_keys,   # noqa: E402
                                     lease_check)
from woowbackup import ha_nextcloud   # noqa: E402  (derive put the product on the path)
from woowbackup.errors import BackupError   # noqa: E402

REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
PHASE = 'skipped-entries-import'
AREA = 'focus-nextcloud-r6-skipped'
RECEIPT = LAB / 'run/focus_nextcloud_r6_skipped.json'
PROVENANCE = LAB / 'run/focus-nextcloud-r6-skipped/derivation-provenance.json'
CREDS = LAB / 'secrets/ha-import-creds.env'
HEADROOM = 120 * 60        # lease seconds left once the mutex is held: case.run's 100-minute case budget after the source
WINDOW_MINUTES = 150
# The frozen product of S5-B (b058df27: every Nextcloud fix; its ha_nextcloud, habackup, hasecuretar and haissues are
# byte-identical to this checkout's, which the offline round trip runs: tests compare the git blobs).
PRODUCT_COMMIT, FROZEN, NC_SHA = s5b.PRODUCT_COMMIT, s5b.FROZEN, s5b.NC_SHA
UPLOAD_NAME = 'woow-b2-nextcloud-x86-enc-share-20261123-r6-skipped.tar'
UPLOAD_ROUTE = 'host-derivation-streamed-once-into-the-upload-file'
ADDED_NAMES = [item['name'] for item in derive.ADDED]
SECTION_VERSIONS = ('amd64', '0.2.3', '35.0.1.1')   # what fullshare05's check read from the original (the derivative too)
WEB_PATHS = tuple('data/' + derive.FOLDER + suffix for suffix in ('/control.txt', '/', '/.htaccess', '/control-link.txt'))
LEASE_KEYS = ('lane', 'device', 'phases', 'source_commit', 'product_commit', 'product_checkout', 'product_manifest_sha256',
              'fixture_sha256', 'fixture_bytes', 'provenance_sha256', 'builder_sha256', 'derived_sha256', 'derived_bytes',
              'confirmation_keys', 'added_entries', 'upload_route', 'source_policy', 'pin_refresh_policy',
              'recovery_grace_seconds', 'original_inactive_units', 'reserve_bytes', 'memory_cap_bytes', 'not_before_utc',
              'expires_utc', 'image_operations', 'host_fixture_copy', 'derived_materialized')
PROVENANCE_LIMIT = 4 * 1024 * 1024


def require(ok, reason):
    if not ok:
        raise ValueError('fixed-skipped-' + reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_creds(path=None):
    """{name: value} of the lab's credential file, read the way the R6 drivers read it (b1 driver Secrets); never
    printed, never written. Only the coordinator's own process calls this, at run time."""
    values = {}
    for line in Path(CREDS if path is None else path).read_text(encoding='utf-8').splitlines():
        key, sep, value = line.strip().partition('=')
        if sep and not key.startswith('#'):
            values[key.strip()] = value.strip().strip('"\'')
    require(len(values.get('HA_BACKUP_KEY', '')) >= 6, 'ha-key-missing')
    return values


def secret_needles(values):
    """The credential values a leak scan looks for: everything but user names (b1 driver Secrets.names)."""
    return sorted({v for k, v in values.items() if not re.search(r'_USER\d*$', k) and isinstance(v, str) and len(v) >= 6})


def expected_section(section):
    """The original full share's check section with the control file as one more file of the data directory (the two
    entries that are left out are no file of it; the database is the original's)."""
    out = dict(section)
    for key, extra in (('datadir_files', 1), ('datadir_bytes', len(derive.CONTROL_DATA))):
        if type(out.get(key)) is int:
            out[key] += extra
    return out


# ====================================================================== the plan (host only) and its provenance

def private_write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())


def plan(out, *, fixture=None, fixture_sha=None, fixture_bytes=None, password=None):
    """HOST ONLY (no device, no lease): derive the backup from the original as a stream with a fresh derivation salt and
    secretstream header, read it straight back with the product's readers (derive.verify), write the provenance once.
    Returns 0 when every reviewed fact holds."""
    out = Path(out)
    require(not os.path.lexists(out), 'provenance-exists')
    fixture = Path(FIXTURE if fixture is None else fixture)
    fixture_sha = FIXTURE_SHA if fixture_sha is None else fixture_sha
    fixture_bytes = FIXTURE_BYTES if fixture_bytes is None else fixture_bytes
    password = read_creds()['HA_BACKUP_KEY'] if password is None else password
    commit, clean = s5.checkout(REPO)
    started = time.monotonic()
    record = {'kind': 'r6-skipped-entries-plan', 'status': 'failed', 'source_commit': commit, 'clean_checkout': clean,
              'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'fixture': str(fixture),
              'device_access': False, 'materialized': False, 'fixed_failure': None}
    try:
        d = derive.Derivation(fixture, password, derivation_salt=os.urandom(derive.SALT_BYTES),
                              stream_header=os.urandom(derive.STREAM_HEADER_BYTES), expected_sha=fixture_sha,
                              expected_size=fixture_bytes)
        d.prepare()
        facts, seen, checks = derive.verify(d, password)
        record.update(facts=facts, verification=seen, checks=checks,
                      status='passed' if checks and all(checks.values()) else 'failed')
    except BackupError as error:
        record['fixed_failure'] = 'fixed-skipped-plan-' + error.code
    except (ValueError, OSError) as error:
        record['fixed_failure'] = str(error) if str(error).startswith('fixed-') else 'fixed-skipped-plan-' + type(error).__name__
    finally:
        password = None   # noqa: F841 - the key leaves this frame with nothing but hasecuretar.Keys holding it
    record['duration_s'] = round(time.monotonic() - started, 1)
    private_write(out, record)
    summary = {k: record.get(k) for k in ('status', 'fixed_failure', 'duration_s', 'source_commit')}
    if record['status'] == 'passed':
        summary.update(derived=record['facts']['derived'], provenance=str(out), provenance_sha256=sha(out.read_bytes()),
                       keys=list(derive.KEYS), failed_checks=[])
    else:
        summary['failed_checks'] = sorted(k for k, v in (record.get('checks') or {}).items() if not v)
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0 if record['status'] == 'passed' else 1


def load_provenance(path=None, *, fixture=None, fixture_sha=None, fixture_bytes=None):
    """The plan's provenance, strictly: passed, made by THIS builder with THESE product readers, of the bound original,
    with exactly the reviewed additions and keys and a derivation salt and secretstream header to make the same bytes."""
    path = Path(PROVENANCE if path is None else path)
    fixture = Path(FIXTURE if fixture is None else fixture)
    fixture_sha = FIXTURE_SHA if fixture_sha is None else fixture_sha
    fixture_bytes = FIXTURE_BYTES if fixture_bytes is None else fixture_bytes
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= PROVENANCE_LIMIT, 'provenance-file')
        raw = f.read(PROVENANCE_LIMIT + 1)
    try:
        doc = json.loads(raw)
    except ValueError:
        raise ValueError('fixed-skipped-provenance-json') from None
    facts = doc.get('facts') if isinstance(doc, dict) else None
    facts = facts if isinstance(facts, dict) else {}
    share = next((m for m in facts.get('members') or [] if isinstance(m, dict) and m.get('derived')), {})
    derived = facts.get('derived') or {}
    hexed = lambda value, n: isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % n, value) is not None   # noqa: E731
    require(doc.get('kind') == 'r6-skipped-entries-plan' and doc.get('status') == 'passed' and doc.get('clean_checkout')
            and isinstance(doc.get('checks'), dict) and doc['checks'] and all(v is True for v in doc['checks'].values())
            and facts.get('kind') == 'r6-skipped-entries-derivation', 'provenance-status')
    require(facts.get('builder_sha256') == derive.module_sha(), 'provenance-builder')
    require(facts.get('product_readers') == derive.reader_hashes(), 'provenance-product-readers')
    require(facts.get('original') == {'name': fixture.name, 'bytes': fixture_bytes, 'sha256': fixture_sha,
                                      'expected_sha256_matched': True}, 'provenance-original')
    require(facts.get('added') == derive.added_rows()
            and facts.get('expected_check') == {k: {'items': v['items'], 'key': v['key']} for k, v in derive.EXPECTED.items()}
            and facts.get('control') == {'path': derive.CONTROL, 'bytes': len(derive.CONTROL_DATA),
                                         'sha256': sha(derive.CONTROL_DATA)}, 'provenance-additions')
    require(hexed(share.get('derivation_salt'), 2 * derive.SALT_BYTES)
            and hexed(share.get('stream_header'), 2 * derive.STREAM_HEADER_BYTES)
            and (share.get('prefix_gzip') or {}).get('sha256') == sha(derive.PREFIX_GZIP), 'provenance-share')
    require(type(derived.get('bytes')) is int and derived['bytes'] > 0 and derived['bytes'] % derive.RECORD == 0
            and hexed(derived.get('sha256'), 64), 'provenance-derived')
    return SimpleNamespace(path=path, sha256=sha(raw), facts=facts, derived_sha=derived['sha256'],
                           derived_bytes=derived['bytes'], salt=bytes.fromhex(share['derivation_salt']),
                           header=bytes.fromhex(share['stream_header']), source_commit=doc.get('source_commit'),
                           ha_id='ha-' + derived['sha256'][:20])


# ====================================================================== the lease

def lease_template(repo=REPO, prov=None):
    """The lease fields this checkout and the plan's provenance bind; the time window is the coordinator's."""
    commit, clean = s5.checkout(repo)
    require(prov is not None, 'provenance-required')
    return {'lane': 'nextcloud-r6', 'device': 'woowbk-dev-e', 'phases': [PHASE],
            'source_commit': commit if clean else 'REQUIRES_A_CLEAN_COMMITTED_CHECKOUT',
            'product_commit': PRODUCT_COMMIT, 'product_checkout': str(FROZEN),
            'product_manifest_sha256': source.manifest_hash(s5b.git_manifest(repo)),
            'fixture_sha256': FIXTURE_SHA, 'fixture_bytes': FIXTURE_BYTES, 'provenance_sha256': prov.sha256,
            'builder_sha256': derive.module_sha(), 'derived_sha256': prov.derived_sha, 'derived_bytes': prov.derived_bytes,
            'confirmation_keys': list(derive.KEYS), 'added_entries': list(ADDED_NAMES), 'upload_route': UPLOAD_ROUTE,
            'source_policy': case.SOURCE_POLICY, 'pin_refresh_policy': case.PIN_POLICY, 'recovery_grace_seconds': 1800,
            'original_inactive_units': list(r6.INACTIVE_UNITS), 'reserve_bytes': RESERVE, 'memory_cap_bytes': DEVICE_CAP,
            'not_before_utc': 'REQUIRES_GRANTED_START',
            'expires_utc': 'REQUIRES_GRANTED_START_PLUS_%d_MINUTES' % WINDOW_MINUTES,
            'image_operations': [], 'host_fixture_copy': False, 'derived_materialized': False}


def admit_lease(lease, commit, repo, frozen_rows, prov, *, now=None):
    """Exactly the template's fields and values (only the window is free: timezone-aware, now inside it, HEADROOM
    left), the frozen checkout's manifest equal to the git one."""
    require(isinstance(lease, dict) and sorted(lease) == sorted(LEASE_KEYS), 'lease-fields')
    when = datetime.datetime.fromtimestamp(time.time() if now is None else now, datetime.timezone.utc)
    lease_check(lease, commit, PHASE, when)
    expected = lease_template(repo, prov)
    for key in LEASE_KEYS:
        if key not in ('not_before_utc', 'expires_utc', 'source_commit'):
            require(lease[key] == expected[key], 'lease-' + key.replace('_', '-'))
    require(lease['source_commit'] == commit == expected['source_commit'], 'lease-source-commit')
    require(source.manifest_hash(frozen_rows) == lease['product_manifest_sha256'], 'frozen-checkout-manifest')
    deadline = datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z', '+00:00')).timestamp()
    require(deadline - when.timestamp() >= HEADROOM, 'lease-headroom')
    return deadline


def locked_admission(lease, commit, deadline, *, now=None):
    """Right after the BLOCKING dev-e lock (heavy.sh only waited for it to be free): still inside, HEADROOM left."""
    when = datetime.datetime.fromtimestamp(time.time() if now is None else now, datetime.timezone.utc)
    lease_check(lease, commit, PHASE, when)
    require(deadline - when.timestamp() >= HEADROOM, 'lease-headroom-after-lock')


# ====================================================================== the device probe (rendered; also unit-tested)

def need(ok, reason):
    if not ok:
        raise ValueError('fixed-skipped-' + reason)


def tar_rows(stream, limit, file_limit):
    """{name: row} of a small tar stream (names without './' or a trailing '/'): type, mode, owner, size, the SHA-256 of
    a regular file's bytes (never the bytes), a link's target."""
    import hashlib
    import tarfile
    rows = {}
    with tarfile.open(fileobj=stream, mode='r|') as archive:
        for m in archive:
            need(len(rows) < limit, 'probe-entries')
            name = m.name
            while name.startswith('./'):
                name = name[2:]
            name = name.rstrip('/') or '.'
            kind = ('dir' if m.isdir() else 'file' if m.isreg() else 'symlink' if m.issym() else 'hardlink' if m.islnk()
                    else 'other')
            row = {'type': kind, 'mode': m.mode & 0o7777, 'uid': m.uid, 'gid': m.gid, 'size': m.size}
            if m.issym() or m.islnk():
                row['linkname'] = m.linkname[:200]
            if m.isreg():
                need(m.size <= file_limit, 'probe-file-size')
                row['sha256'] = hashlib.sha256(archive.extractfile(m).read()).hexdigest()
            rows[name] = row
    return rows


def listing(argv, root, limit):
    """How many lines a bounded find printed, and the first ten names below `root`."""
    import subprocess
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=600)
    need(p.returncode == 0 and len(p.stdout) <= limit, 'probe-find')
    names = [line[len(root):].lstrip('/') if line.startswith(root) else line
             for line in p.stdout.decode('utf-8', 'replace').splitlines() if line]
    return {'count': len(names), 'first': sorted(names)[:10]}


def web_codes(base, paths, opener):
    """The HTTP status of an anonymous GET of each path (None: no answer)."""
    import urllib.error
    import urllib.parse
    import urllib.request
    out = {}
    for path in paths:
        request = urllib.request.Request(base + '/' + urllib.parse.quote(path), method='GET')
        try:
            with opener(request, timeout=60) as reply:
                code = reply.status
        except urllib.error.HTTPError as error:
            code = error.code
        except (urllib.error.URLError, OSError):
            code = None
        out[path] = code
    return out


PROBE_BODY = r'''
q=json.load(sys.stdin)
script='cd "$1" || exit 3; if [ -e "$2" ] || [ -L "$2" ]; then exec tar -cf - -- .htaccess "$2"; fi; exec tar -cf - -- .htaccess'
p=subprocess.Popen([*EXEC,'sh','-c',script,'sh',DATA_ROOT,FOLDER],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                   stderr=subprocess.DEVNULL)
try:
 entries=tar_rows(p.stdout,ENTRY_LIMIT,FILE_LIMIT)
 while p.stdout.read(65536):pass
finally:
 p.stdout.close();code=p.wait(timeout=600)
need(code==0,'probe-tar')
links=listing([*EXEC,'find',DATA_ROOT,'-type','l','-print'],DATA_ROOT,OUTPUT_LIMIT)
nested=listing([*EXEC,'find',DATA_ROOT,'-mindepth','2','-name','.htaccess','-print'],DATA_ROOT,OUTPUT_LIMIT)
import urllib.request
web=web_codes(BASE,WEB_PATHS,urllib.request.urlopen)
print(json.dumps({'entries':entries,'links':links,'nested_htaccess':nested,'web':web}))
'''
DEVICE = {'EXEC': ('podman', 'exec', '-u', 'www-data', 'nextcloud-app'), 'DATA_ROOT': '/var/www/html/data',
          'FOLDER': derive.FOLDER, 'BASE': 'http://127.0.0.1:18081', 'WEB_PATHS': WEB_PATHS, 'ENTRY_LIMIT': 64,
          'FILE_LIMIT': 1024 * 1024, 'OUTPUT_LIMIT': 1024 * 1024}


def programs(overrides=None):
    """The device program of this case, rendered from the functions above and DEVICE (tests render it against local
    directories with `overrides`). appowner, read only: the data dir's top .htaccess and the derived folder through tar
    in the app container, every symlink and nested .htaccess below the data dir (find), the derived folder's URLs."""
    values = dict(DEVICE, **(overrides or {}))
    head = ('import hashlib,json,subprocess,sys,tarfile\nsys.dont_write_bytecode=True\n'
            + ''.join(f'{k}={v!r}\n' for k, v in sorted(values.items())))
    return {'probe': head + '\n'.join(inspect.getsource(f) for f in (need, tar_rows, listing, web_codes)) + PROBE_BODY}


PROGRAMS = programs()


def folder_rows(entries):
    return {n: r for n, r in (entries or {}).items() if n == derive.FOLDER or n.startswith(derive.FOLDER + '/')}


def judge_before(probe):
    """Before the import: dev-e's own data dir has no derived folder (whatever is there afterwards came from it)."""
    return not folder_rows(probe.get('entries')) and isinstance(probe.get('web'), dict)


def judge_skipped(probe):
    """After the restore (and the restart, and the automatic rollback that keeps the imported data): the verdicts."""
    entries = probe.get('entries') or {}
    rows = folder_rows(entries)
    top, folder, control = entries.get('.htaccess') or {}, rows.get(derive.FOLDER) or {}, rows.get(derive.CONTROL) or {}
    links, nested, web = probe.get('links') or {}, probe.get('nested_htaccess') or {}, probe.get('web') or {}
    owner = (top.get('uid'), top.get('gid'))
    return {
        'absent': (derive.HTACCESS not in entries and derive.LINK not in entries and links.get('count') == 0
                   and nested.get('count') == 0),
        'control': (set(rows) == {derive.FOLDER, derive.CONTROL} and folder.get('type') == 'dir'
                    and control.get('type') == 'file' and control.get('sha256') == sha(derive.CONTROL_DATA)
                    and control.get('size') == len(derive.CONTROL_DATA) and None not in owner
                    and (control.get('uid'), control.get('gid')) == owner == (folder.get('uid'), folder.get('gid'))),
        'protection': (top.get('type') == 'file' and top.get('sha256') == sha(ha_nextcloud.DATA_HTACCESS)
                       and top.get('size') == len(ha_nextcloud.DATA_HTACCESS)),
        'web': sorted(web) == sorted(WEB_PATHS) and all(code in (403, 404) for code in web.values())}


# ====================================================================== verdicts of the helper's answers

def convert_request(ha, apps, test_mode, key, keys, request_id):
    """ha-convert-start with fields of the product's schema only (cli.SPECS): the HA key (the backup is protected) and,
    unless `keys` is None, {'nextcloud': keys} acknowledged."""
    request = {'ha_backup_id': ha, 'apps': list(apps), 'test_mode': test_mode, 'confirm': True, 'request_id': request_id,
               'key': key}
    if keys is not None:
        request['acknowledged'] = {'nextcloud': list(keys)}
    return request


def judge_check(job, section):
    """The check verdict, every line recorded: {base, lines, others, section, versions, lines_recorded, section_differ}."""
    result = (job.get('result') or {}).get('ha_check') or {}
    apps = result.get('apps') or []
    app = apps[0] if len(apps) == 1 else {}
    issues = app.get('issues') or []
    confirms = [i for i in issues if i.get('level') == 'confirm']
    by_id = {i.get('id'): i for i in confirms}

    def exact(issue_id):
        want, have = derive.EXPECTED[issue_id], by_id.get(issue_id) or {}
        return (have.get('items') == want['items'] and have.get('more') == 0 and have.get('key') == want['key']
                and have.get('message') == want['message'])
    try:
        keys = confirmation_keys(job, 'skipped-files')
    except ValueError:
        keys = None
    others = [i for i in issues if i.get('level') != 'confirm']
    texts = [str(i.get('message')) for i in others] + [str(w) for w in app.get('warnings') or []]
    have = app.get('nextcloud') or {}
    return {
        'base': (job.get('state') == 'succeeded' and len(apps) == 1 and app.get('app_id') == 'nextcloud'
                 and app.get('importable') is True and not any(i.get('level') == 'stop' for i in issues)),
        'lines': (len(confirms) == 2 and set(by_id) == {derive.SYMLINK_ID, derive.HTACCESS_ID} and exact(derive.SYMLINK_ID)
                  and exact(derive.HTACCESS_ID) and keys == list(derive.KEYS)),
        'others': (all(i.get('level') in ('notice', 'auto') for i in others)
                   and not any('檔案清單' in text for text in texts)),
        'section': bool(section) and all(have.get(k) == v for k, v in section.items()),
        'versions': (app.get('arch'), app.get('version'), app.get('target_version')) == SECTION_VERSIONS,
        'lines_recorded': [{k: i.get(k) for k in ('id', 'level', 'message', 'items', 'more', 'key')} for i in issues],
        'section_differ': {k: [v, have.get(k)] for k, v in section.items() if have.get(k) != v}}


def judge_refusal(rc, reply, job, before, after, *, found, raised, acknowledged=None):
    """A conversion refused at the line of `raised` (its bound key): refused at the start (confirmation-required) or the
    job fails with it, Nextcloud skipped, the row holding exactly the confirmation lines `found` (the acknowledged ones
    met before it and it, in the order met), the one it names - the row's lines minus the keys the request acknowledged
    (`acknowledged`) - exactly `raised` and the last of them, no stop, no backup added. The job's error keeps only its
    code and message (dev-e, 2026-11-28: no `details`), so the row names the line, as S5-B judged it."""
    added = sorted(set(after) - set(before))
    if rc != 0:
        refused = (reply.get('error') or {}).get('code') == 'confirmation-required' and job is None
        return refused and not added, {'start_refused': True, 'code': (reply.get('error') or {}).get('code'), 'added': added}
    error = (job or {}).get('error') or {}
    results = ((job or {}).get('result') or {}).get('results') or []
    row = results[0] if len(results) == 1 else {}
    issues = row.get('issues') or []
    keys = [i.get('key') for i in issues if i.get('level') == 'confirm']
    named = [key for key in keys if key not in set(acknowledged or ())]
    ok = ((job or {}).get('state') == 'failed' and error.get('code') == 'confirmation-required'
          and row.get('app_id') == 'nextcloud' and row.get('status') == 'skipped' and row.get('code') == 'confirmation-required'
          and sorted(keys) == sorted(found) and named == [raised] and keys[-1:] == [raised]
          and not any(i.get('level') == 'stop' for i in issues) and not added)
    return ok, {'start_refused': False, 'state': (job or {}).get('state'), 'error': error.get('code'), 'named': named,
                'result': {k: row.get(k) for k in ('app_id', 'status', 'code')}, 'confirm_keys': keys, 'added': added}


def judge_import_row(job):
    results = ((job or {}).get('result') or {}).get('results') or []
    row = results[0] if len(results) == 1 else {}
    issues = row.get('issues') or []
    keys = sorted(i.get('key') for i in issues if i.get('level') == 'confirm')
    ok = (row.get('app_id') == 'nextcloud' and row.get('status') == 'converted' and keys == list(derive.KEYS)
          and not any(i.get('level') == 'stop' for i in issues))
    return ok, {'status': row.get('status'), 'confirm_keys': keys}


# ====================================================================== the upload: the derivation streamed into dev-e

def writer_command(q):
    """R6's bounded in-device writer (focus_nextcloud_r6_upload.WRITER) of the owned upload file."""
    return [str(upload.LP), 'exec', '-i', upload.DEVICE, 'python3', '-I', '-c', upload.WRITER, json.dumps(q)]


def stream_derived(state, begin, ev, deadline, derivation, prov):
    """Make the derived bytes while reading the original once and write them into the upload file upload-begin made,
    through R6's writer: it stops at the lease end, below the reserve or above the memory limit, and passes only when the
    exact size and SHA-256 arrived. The host refuses more bytes than bound, and passes only when its own count and
    SHA-256 of what it sent and the original's SHA-256 are the bound ones. Private events and the writer's answer are
    kept first (focus_nextcloud_r6_upload.stream's discipline). Returns (writer answer, host facts)."""
    q = {'deadline': deadline, 'path': begin['path'], 'upload_id': state['upload_id'], 'size': prov.derived_bytes,
         'sha256': prov.derived_sha}
    offset, next_checkpoint, last = 0, upload.THROTTLE, time.monotonic()
    state['writer_reaped'] = False
    stream = derivation.stream()
    with (ev.path / 'writer.stdout.private').open('xb') as out, (ev.path / 'writer.stderr.private').open('xb') as err:
        p = subprocess.Popen(writer_command(q), stdin=subprocess.PIPE, stdout=out, stderr=err)
        try:
            os.set_blocking(p.stdin.fileno(), False)
            for chunk in stream.pieces():
                if offset + len(chunk) > prov.derived_bytes:
                    raise ValueError('fixed-skipped-upload-host-length-bound')
                data = memoryview(chunk)
                while data:
                    if time.time() >= deadline:
                        raise TimeoutError('fixed-skipped-upload-host-expiry')
                    if p.poll() is not None:
                        raise BrokenPipeError(32, 'fixed-skipped-upload-writer-exited')
                    if not select.select([], [p.stdin], [], 1)[1]:
                        continue
                    try:
                        n = os.write(p.stdin.fileno(), data)
                    except BlockingIOError:
                        continue
                    offset += n
                    state['chunk_offset'] = offset
                    data = data[n:]
                if offset >= next_checkpoint or time.monotonic() - last >= 15:
                    ev.event({'stage': 'host-derived-stream', 'chunk_offset': offset, 'writer_transport_returncode': p.poll()})
                    next_checkpoint, last = offset + upload.THROTTLE, time.monotonic()
            if not (stream.ended and offset == prov.derived_bytes and stream.sha256 == prov.derived_sha
                    and derivation.original_ok):
                raise ValueError('fixed-skipped-upload-host-sha-length')
        except BaseException as error:
            ev.event(upload.diagnostic(error, 'host-derived-stream', offset))
            raise
        finally:
            try:
                stream.close()
            finally:
                try:
                    p.stdin.close()
                finally:
                    p.wait(timeout=120)
                    state['writer_reaped'] = True
                    ev.event({'stage': 'writer-reaped-before-cleanup', 'chunk_offset': offset, 'transport_returncode': p.returncode,
                              'stderr_sha256': source.digest(ev.path / 'writer.stderr.private')})
                    with (ev.path / 'writer.stdout.private').open('rb') as f:
                        raw = f.read(65537)
                    try:
                        if len(raw) > 65536:
                            raise ValueError('fixed-skipped-upload-writer-diagnostic-bound')
                        reply = json.loads(raw)
                    except (ValueError, UnicodeError):
                        reply = {'status': 'unreadable', 'raw_sha256': sha(raw)}
                    ev.save('writer-diagnostic.private.json', reply)
    if p.returncode or reply.get('status') != 'passed':
        raise RuntimeError('fixed-skipped-upload-writer-failed')
    if reply.get('bytes') != offset or reply.get('sha256') != prov.derived_sha:
        raise ValueError('fixed-skipped-upload-writer-proof-mismatch')
    facts = derivation.facts(stream)
    return reply, {'original': facts['original'], 'derived': facts['derived'], 'sent_bytes': offset}


def trace(body, request, ev, prefix, timeout):
    """focus_nextcloud_r6_upload.device_process: a bounded root program with its private stdout/stderr kept first."""
    return upload.device_process(body, [], ev, prefix, json.dumps(request).encode(), timeout)


# ====================================================================== the case on R6's machinery

def make_run(Base, ctx, variant):
    """R6's Run (focus_nextcloud_r6.run_locked) with this case's steps: the derived upload, the exact check, the two
    refused conversions, the skipped-entry verification; restart, rollbacks, after-state, cleanup and leaks are R6's."""
    d, ev, secrets, require_check, wait = ctx.d, ctx.ev, ctx.secrets, ctx.require, ctx.wait
    prov = variant.prov

    class SkippedRun(Base):
        def setup(self):
            super().setup()
            require_check('setup: the installed engine, helper and VERSION are the frozen product',
                          wake.device(s5.ENGINE_PROGRAM, root=True) == variant.product_engine)

        def before_state(self):
            super().before_state()
            probe = d.device_python(PROGRAMS['probe'], {}, timeout=900)
            ev.save('skipped-before.json', probe)
            require_check('before: the derived folder is not in dev-e\'s own data dir (anything there later came from the '
                          'import)', judge_before(probe))

        def upload(self):
            self.budget('upload', prov.derived_bytes + 3 * GIB)
            sent = time.time()
            begin = d.ok('upload-begin', {'filename': UPLOAD_NAME, 'size': prov.derived_bytes}, ev=ev)
            d.STATE['begin_window'] = [sent, time.time()]
            upload_id = upload.validate_begin(begin)
            d.STATE['upload_id'] = upload_id
            d.save_state()
            trace_ev = upload.Evidence(ev.dir / 'upload-trace')
            state = {'upload_id': upload_id}
            started = time.monotonic()
            writer, host = stream_derived(state, begin, trace_ev, ctx.expires, variant.derivation, prov)
            ev.save('upload-stream.json', {'writer': {k: writer.get(k) for k in ('status', 'bytes', 'sha256', 'identity')},
                                           'host': host, 'seconds': round(time.monotonic() - started, 1)})
            require_check('upload: the derived backup is made while the original is read once and streamed once into the '
                          'upload file (the original\'s SHA-256, the derived bytes and SHA-256 exact on the host and inside '
                          'dev-e; nothing materialised)',
                          host['original']['sha256'] == FIXTURE_SHA and host['original']['bytes'] == FIXTURE_BYTES
                          and host['derived'] == {'bytes': prov.derived_bytes, 'sha256': prov.derived_sha}
                          and writer.get('bytes') == prov.derived_bytes and writer.get('sha256') == prov.derived_sha)
            reply = d.ok('upload-finish', {'upload_id': upload_id}, ev=ev, timeout=1800)
            record = reply.get('ha_backup') or {}
            # Whatever this upload published is this run's (the record was absent before): owned for ha-delete.
            self.created_store = record.get('id') if re.fullmatch(r'ha-[0-9a-f]{20}', str(record.get('id'))) else None
            d.STATE.update(upload_id=None, finished_upload_id=upload_id, ha_backup_id=self.created_store)
            d.save_state()
            ev.save('ha-backup.json', record)
            found = {a.get('app_id'): a.get('installed') for a in record.get('importable_apps') or []}
            require_check('upload: upload-finish publishes the HA record of exactly the derived file (id, SHA-256, size), '
                          'nextcloud importable and installed here',
                          self.created_store == prov.ha_id and record.get('sha256') == prov.derived_sha
                          and record.get('size') == prov.derived_bytes and found.get('nextcloud') is True)
            proof = trace(upload.VERIFY, {'deadline': ctx.expires, 'ha_backup_id': prov.ha_id, 'expected_id': prov.ha_id,
                                          'sha256': prov.derived_sha, 'size': prov.derived_bytes},
                          trace_ev, 'verify-published', 1800)
            require_check('upload: the published HA file is the inode written inside dev-e, its full SHA-256 again',
                          proof.get('status') == 'passed' and proof.get('identity') == writer.get('identity')
                          and proof.get('sha256') == prov.derived_sha and proof.get('bytes') == prov.derived_bytes)

        def check(self):
            self.budget('check', GIB)
            job, took = d.run_check(self.created_store, ['nextcloud'], ev=ev, key=secrets['HA_BACKUP_KEY'])
            ev.time('check', 'skipped', 'nextcloud', took, job)
            self.check_id = job.get('id')
            result = (job.get('result') or {}).get('ha_check') or {}
            ev.save('check-result.json', result)
            verdict = judge_check(job, variant.section)
            ev.save('check-lines.json', {'lines': verdict['lines_recorded'], 'section_differ': verdict['section_differ']})
            require_check('check: the job succeeds for nextcloud alone, importable, no stop', verdict['base'])
            require_check('check: exactly two lines to confirm: nextcloud.symlinks-skipped naming exactly the reviewed link '
                          'and nextcloud.htaccess-skipped naming exactly the reviewed .htaccess, the product\'s texts, each '
                          'with the key bound to that name', verdict['lines'])
            require_check('check: every other line is a notice or an automatic step, none about file lists (the control '
                          'file is no user\'s file), all recorded', verdict['others'])
            require_check('check: the section is the original full share\'s with the control file as one more file of the '
                          'data directory', verdict['section'])
            require_check('check: amd64, add-on 0.2.3, target 35.0.1.1', verdict['versions'])
            apps = result.get('apps') or [{}]
            self.section = apps[0].get('nextcloud') or {}
            self.keys = list(derive.KEYS)

        def refused(self, label, keys, found, raised, text):
            self.budget('refused convert', GIB)
            before = {b['id'] for b in d.ok('list', ev=ev).get('backups') or []}
            request = convert_request(self.created_store, ['nextcloud'], False, secrets['HA_BACKUP_KEY'], keys,
                                      d.request_id('focus-skipped-' + label))
            rc, reply = d.helper('ha-convert-start', request, timeout=300)
            job = wait(reply['job_id'], ev=ev) if rc == 0 and reply.get('job_id') else None
            after = {b['id'] for b in d.ok('list', ev=ev).get('backups') or []}
            ok, detail = judge_refusal(rc, reply, job, before, after, found=found, raised=raised, acknowledged=keys)
            ev.save(f'convert-refused-{label}.json', detail)
            require_check(text, ok)

        def refused_conversion(self):
            self.refused('unacknowledged', None, [derive.SYMLINK_KEY], derive.SYMLINK_KEY,
                         'convert: without any acknowledgement the conversion is refused at the link line (confirmation-'
                         'required naming exactly it with its bound key, Nextcloud skipped, no stop, no backup added)')

        def partial_conversion(self):
            self.refused('link-only', [derive.SYMLINK_KEY], list(derive.KEYS), derive.HTACCESS_KEY,
                         'convert: with the link\'s bound key alone the conversion passes that line and is refused at the '
                         '.htaccess line (confirmation-required naming exactly it with its bound key, no backup added)')

        def import_real(self):
            inner, seen = d.convert, {}

            def convert(*args, **kwargs):
                job, took = inner(*args, **kwargs)
                seen['job'] = job
                return job, took
            d.convert = convert
            try:
                super().import_real()
            finally:
                d.convert = inner
            ok, detail = judge_import_row(seen.get('job'))
            ev.save('convert-results.json', ((seen.get('job') or {}).get('result') or {}).get('results'))
            ev.check('import: nextcloud converted with exactly the two acknowledged lines (their bound keys), no stop', ok,
                     detail)

        def verify(self, phase):
            found = super().verify(phase)
            probe = d.device_python(PROGRAMS['probe'], {}, timeout=900)
            verdict = judge_skipped(probe)
            ev.save(f'skipped-{phase.replace(" ", "-")}.json', {'probe': probe, 'verdict': verdict})
            ev.check(f'{phase}: the two left-out entries are not on disk: no nested .htaccess and no symbolic link anywhere '
                     'below the data dir, neither left-out name in the derived folder', verdict['absent'],
                     {'links': probe.get('links'), 'nested_htaccess': probe.get('nested_htaccess')})
            ev.check(f'{phase}: the control file next to them is there byte for byte (SHA-256, size; owned like the data '
                     'dir\'s protection file) and the derived folder holds nothing else', verdict['control'],
                     folder_rows(probe.get('entries')))
            ev.check(f'{phase}: the data dir\'s protection file is the one this device writes (Nextcloud\'s own rules, '
                     'exact SHA-256)', verdict['protection'], (probe.get('entries') or {}).get('.htaccess'))
            ev.check(f'{phase}: the web server serves nothing of the derived folder (control file, folder and both '
                     'left-out names: 403/404)', verdict['web'], probe.get('web'))
            return found
    return SkippedRun


class Variant:
    """What focus_nextcloud_r6.run_locked takes from this case (its `variant` hook)."""
    area = AREA

    def __init__(self, prov, product_engine, derivation, facts):
        self.prov, self.product_engine, self.derivation = prov, product_engine, derivation
        self.receipt = RECEIPT
        self.uploaded_bytes = prov.derived_bytes
        self.section = expected_section(facts['section'])

    def prepare(self, secrets):
        """No secret beyond R6's own: the HA key and the HA test credentials are registered by run_locked already."""

    @staticmethod
    def convert_request(ha, apps, test_mode, key, keys, request_id):
        return convert_request(ha, apps, test_mode, key, keys, request_id)

    @staticmethod
    def steps(r):
        return (r.setup, r.before_state, r.upload, r.check, r.refused_conversion, r.partial_conversion, r.import_real,
                lambda: r.verify('import'), r.restart, r.rollback, r.after_state)

    def scope(self, r):
        return {'case': PHASE, 'product_commit': PRODUCT_COMMIT, 'original_fixture_reused': True,
                'fixture': {'path': str(FIXTURE), 'sha256': FIXTURE_SHA, 'bytes': FIXTURE_BYTES},
                'derived': {'sha256': self.prov.derived_sha, 'bytes': self.prov.derived_bytes, 'ha_id': self.prov.ha_id,
                            'provenance_sha256': self.prov.sha256, 'materialized': False, 'upload_route': UPLOAD_ROUTE},
                'added_entries': list(ADDED_NAMES), 'confirmation_keys': list(derive.KEYS)}

    def run_class(self, Base, ctx):
        return make_run(Base, ctx, self)


def baseline_verify():
    return r6.baseline_verify()


def run_locked(args, lease, commit, facts, inventory):
    """focus_nextcloud_r6_case.run's case body (`flow.run_locked`): R6's, with this case's variant."""
    return r6.run_locked(args, lease, commit, facts, inventory, variant=args.skipped_variant)


BINDING = SimpleNamespace(phase=PHASE, product_commit=PRODUCT_COMMIT, frozen_manifest=lambda path: s5b.frozen_manifest(path),
                          area=AREA + '-control', result_phase=PHASE + '-cold-return')


def pending_receipts():
    """Every receipt of this lane whose run may have left dev-e needing recovery."""
    return (r6.RECEIPT, s5b.RECEIPT, LAB / 'run/focus_nextcloud_r6_page.json', RECEIPT)


def run_case(args, lease, commit, deadline, prov):
    """Caller holds the dev-e mutex. Read-only proofs first (no mutation), then R6's cold-to-cold path, then this
    driver's end checks (the prior engine back, the store holding only this run's traces, no secret in the evidence)."""
    require(lease.get('provenance_sha256') == prov.sha256 and lease.get('derived_sha256') == prov.derived_sha
            and lease.get('derived_bytes') == prov.derived_bytes, 'provenance-binding')
    ev = upload.Evidence(LAB / 'evidence' / (AREA + '-run') / time.strftime('%Y%m%dT%H%M%S'))
    lease_sha = source.manifest_hash(lease)
    for receipt in pending_receipts():
        require(not s5b.pending(receipt), 'recovery-pending')
    creds = read_creds()
    facts = json.loads(Path(args.facts).read_text())
    r6.validate_facts(facts, 'fullshare')   # the original full share's facts: its data is the derivative's data
    product_engine = s5.engine_manifest(REPO, PRODUCT_COMMIT)
    prior_engine = wake.device(s5.ENGINE_PROGRAM, root=True)
    require(isinstance(prior_engine, dict) and {'helper', 'lib/VERSION', 'lib/woowbackup/cli.py'} <= set(prior_engine),
            'prior-engine-unreadable')
    derivation = derive.Derivation(FIXTURE, creds['HA_BACKUP_KEY'], derivation_salt=prov.salt, stream_header=prov.header,
                                   expected_sha=FIXTURE_SHA, expected_size=FIXTURE_BYTES)
    prepared = derivation.prepare()   # the key opens the original; the exact derived size, before any write
    require(prepared['derived_bytes'] == prov.derived_bytes, 'derived-size-changed')
    ev.save('binding.json', {'source_commit': commit, 'lease_sha256': lease_sha, 'product_commit': PRODUCT_COMMIT,
                             'provenance_sha256': prov.sha256, 'provenance_source_commit': prov.source_commit,
                             'derived': {'sha256': prov.derived_sha, 'bytes': prov.derived_bytes, 'ha_id': prov.ha_id},
                             'prior_engine_captured': prior_engine,
                             'prior_engine_manifest_sha256': s5.manifest_hash(prior_engine),
                             'prior_differs_from_frozen_product': s5.engine_differs(prior_engine, product_engine)})
    store_before = wake.device(s5.TARGET_STATE, root=True)
    ev.save('store-before.json', store_before)
    require(not any(row[0].startswith(prov.ha_id + '.') for row in store_before.get('ha-backups') or []),
            'ha-store-entry-present')
    args.case, args.product_source, args.retained_upload_receipt = PHASE, FROZEN, None
    args.skipped_variant = Variant(prov, product_engine, derivation, facts)
    marker = LAB / 'run/focus-nextcloud-r6-skipped-leases'
    marker.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(marker / (lease_sha + '.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)  # one attempt
    with os.fdopen(fd, 'w') as f:
        json.dump({'source_commit': commit, 'private_receipt_dir': str(ev.path)}, f)
        f.flush()
        os.fsync(f.fileno())
    rc, failure = 1, None
    try:
        rc = case.run(args, lease, commit, facts, sys.modules[__name__], binding=BINDING)
    except Exception as error:   # noqa: BLE001 - a refusal before or a failure after; the record says which
        failure = 'fixed-skipped-cold-to-cold-' + type(error).__name__
    engine_back = clean = evidence_clean = False
    delta = leak = None
    try:
        engine_back = wake.device(s5.ENGINE_PROGRAM, root=True) == prior_engine
        store_after = wake.device(s5.TARGET_STATE, root=True)
        ev.save('store-after.json', store_after)
        receipt = json.loads(RECEIPT.read_text()) if RECEIPT.exists() else {'pending': True}
        clean, delta = s5b.owned_store_clean(store_before, store_after, receipt)
        needles = secret_needles(creds)
        leak = s5b.scan_evidence([LAB / 'evidence' / area for area in (AREA, AREA + '-control', AREA + '-run')], needles)
        raw = prov.path.read_bytes()
        leak['provenance_hits'] = sum(raw.count(n.encode('utf-8')) for n in needles)
        evidence_clean = leak['hits'] == 0 and leak['provenance_hits'] == 0 and leak['files'] > 0
    except Exception as error:   # noqa: BLE001
        failure = failure or 'fixed-skipped-end-check-' + type(error).__name__
    passed = rc == 0 and engine_back and clean and evidence_clean
    record = {'status': 'passed' if passed else 'failed', 'phase': PHASE, 'source_commit': commit,
              'product_commit': PRODUCT_COMMIT, 'provenance_sha256': prov.sha256,
              'fixture_sha256': FIXTURE_SHA, 'fixture_bytes': FIXTURE_BYTES,
              'derived_sha256': prov.derived_sha, 'derived_bytes': prov.derived_bytes, 'derived_materialized': False,
              'upload_route': UPLOAD_ROUTE, 'confirmation_keys': list(derive.KEYS), 'added_entries': list(ADDED_NAMES),
              'prior_engine_manifest_sha256': s5.manifest_hash(prior_engine), 'case_rc': rc,
              'prior_engine_returned_exactly': engine_back, 'owned_store_clean': clean, 'store_delta': delta,
              'evidence_leak_scan': leak, 'fixed_failure': failure, 'pulls': 0, 'private_receipt_dir': str(ev.path),
              'case_evidence': [str(max((LAB / 'evidence' / area).glob('*'), default=''))
                                for area in (AREA + '-control', AREA)]}
    ev.save('fixed-result.json', record)
    print(json.dumps({k: record[k] for k in ('status', 'phase', 'case_rc', 'prior_engine_returned_exactly',
                                             'owned_store_clean', 'fixed_failure')}))
    return 0 if passed else 1


def contract():
    return {'phase': PHASE, 'code_only_until_leased': True, 'product_commit': PRODUCT_COMMIT, 'product_checkout': str(FROZEN),
            'fixture': str(FIXTURE), 'fixture_sha256': FIXTURE_SHA, 'fixture_bytes': FIXTURE_BYTES,
            'added_entries': list(ADDED_NAMES), 'control_file': derive.CONTROL,
            'confirmations': {k: {'items': v['items'], 'key': v['key']} for k, v in derive.EXPECTED.items()},
            'upload_route': UPLOAD_ROUTE, 'derived_materialized': False, 'provenance': str(PROVENANCE),
            'reserve_bytes': RESERVE, 'device_memory_cap_bytes': DEVICE_CAP, 'lease_headroom_seconds': HEADROOM,
            'lease_window_minutes': WINDOW_MINUTES, 'mutations': 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--lease', type=Path)
    parser.add_argument('--lease-template', action='store_true')
    parser.add_argument('--provenance', type=Path, default=None)
    parser.add_argument('--facts', type=Path, default=r6.FACTS)
    args = parser.parse_args(argv)
    provenance = args.provenance or PROVENANCE
    if args.plan:
        return plan(provenance)
    if args.lease_template:
        print(json.dumps(lease_template(REPO, load_provenance(provenance)), indent=2, sort_keys=True))
        return 0
    if not args.run:
        print(json.dumps(contract(), indent=2, sort_keys=True))
        return 0
    require(args.lease is not None, 'lease-required')
    commit, clean = s5.checkout(REPO)
    require(clean, 'clean-checkout')
    lease = json.loads(args.lease.read_text())
    prov = load_provenance(provenance)
    _paths, rows = s5b.frozen_manifest(FROZEN)
    deadline = admit_lease(lease, commit, REPO, rows, prov)
    require(os.environ.get('HEAVY_FREE') == LOCK, 'heavy-seat-required')
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)   # blocking: heavy.sh only waited for the lock to be free
        locked_admission(lease, commit, deadline)
        return run_case(args, lease, commit, deadline, prov)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, RuntimeError, subprocess.CalledProcessError, BackupError) as error:
        # Everything after the first mutation is caught and recorded inside run_case; what lands here refused before.
        reason = (str(error) if str(error).startswith('fixed-') else
                  'fixed-skipped-' + error.code if isinstance(error, BackupError) else type(error).__name__)
        print('fixed-skipped-preflight-refused-no-mutation: ' + reason, file=sys.stderr)
        sys.exit(2)
