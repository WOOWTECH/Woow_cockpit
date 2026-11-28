#!/usr/bin/env python3
"""CODE ONLY until separately leased: S5-B, the import acceptance of the S5-A server-side-encrypted Nextcloud backup.

S5-A (focus_nextcloud_r6_s5.py) leaves a generated HA-shaped TEST backup inside dev-e (never a HAOS export): Nextcloud
35.0.1 in master-key mode, one file written before encryption, two after, the installer's skeleton in plaintext, every
key file in the share member. Its backup.json says protected: false and compressed: false, so no HA key exists for it
and none is sent in any request (the R6 HA-key leak scan still runs and must find nothing).

Which S5-A fixture: the ACTIVE result S5A_RESULT (s5a-source-fixture-rebuild-result.json), committed by the coordinator
after the real rebuild, checked strictly (s5a_binding: passed, the real add-on's database s5.FIXTURE_SHAPE, opened by the
product's own check before S5-A accepted it, its source commit and builder in this history, a proof root of its own) and
named by the lease (s5a_result, s5a_source_commit, s5a_builder_sha256, s5a_command_records, fixture_shape,
product_open_check). Without it nothing runs. The first build (4163367c, s5a-source-fixture-20261128-result.json) has no
role postgres; it stays as HISTORY for the diagnostic and the retirement of its proof root only.

Under ONE lease (--lease-template prints the fields this checkout binds), on the R6 cold-to-cold path
(focus_nextcloud_r6_case.run with BINDING, focus_nextcloud_r6.run_locked with Variant -- their request recording, job
waits, watchdog, recovery, rollback, cleanup and leak gates are reused, not copied):
  admission  the exact lease; the frozen clean product checkout of PRODUCT_COMMIT (contains the fix FIX_COMMIT); dev-e
             cold, isolated, no active job, the baseline present, the S5-A proof root exactly as S5-A left it, the
             fixture's SHA-256 and the provenance read inside dev-e
  source     whatever engine/helper/VERSION dev-e has (no prior is assumed: another lane may have deployed its own) is
             captured at run time -- byte for byte inside R6's source transaction, its manifest by this driver -- the
             frozen product installed and proven installed, and exactly the captured prior returned at the end
  wake       pinned same-config units started, dev-e's own baseline verified independently
  upload     upload-begin, the fixture copied INSIDE dev-e into the upload file (never through the host), upload-finish,
             the published file's inode and full SHA-256 checked again
  check      exactly the confirmation nextcloud.server-side-encryption (reasons files_encryption and encryption_enabled,
             its bound key, the "not tested yet" text); no stop; other lines only reviewed notices, all recorded
  convert    without the acknowledgement: refused (confirmation-required, Nextcloud skipped, no backup); then with exactly
             the bound key (schema fields only)
  import     inspect, the uploaded HA file deleted, restore with its safety backup
  verify     after the restore, after a restart and after the automatic rollback: every ciphertext and key file on disk
             byte for byte as S5-A wrote it, the plaintext of the S5-A files and of a skeleton sample through WebDAV with
             the s5owner credentials, a NEW file written through WebDAV after the import stored with the native header and
             only its master-key share key, read back
  rollback   injected automatic rollback, manual rollback to the import's safety backup, dev-e's baseline verified,
             exact after-state, owned cleanup, leak scans (also the s5owner password, HA's config.php secret values and
             the master/public-share private key files), cold return, the exact prior engine back
  remove     only when every step above passed: the S5-A proof root (a literal, nonce-bound, lease-bound path) is removed
             entry by entry after it was proven unchanged; anything failed: it stays
"""
import argparse
import base64
import datetime
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import secrets as nonce_source
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))   # python3 -I puts no script directory on the path; only this committed directory
import focus_nextcloud_r6 as r6   # noqa: E402
import focus_nextcloud_r6_case as case   # noqa: E402
import focus_nextcloud_r6_s5 as s5   # noqa: E402
import focus_nextcloud_r6_source as source   # noqa: E402
import focus_nextcloud_r6_upload as upload   # noqa: E402
import focus_nextcloud_r6_wake as wake   # noqa: E402
from focus_nextcloud_r6_plan import DEVICE_CAP, GIB, MARGIN, MIB, RESERVE, lease_check   # noqa: E402

REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
PHASE = 's5-import-acceptance'
AREA = 'focus-nextcloud-r6-s5b'
RECEIPT = LAB / 'run/focus_nextcloud_r6_s5b.json'
HEADROOM = 80 * 60   # lease seconds left once the mutex is held: case.run's own 75 minutes after the read-only proofs
# The frozen product: a detached clean checkout the coordinator creates (`git worktree add --detach FROZEN PRODUCT_COMMIT`).
FROZEN = Path('/tmp/parity-focus-nc-product-s5b')
PRODUCT_COMMIT = 'b058df278d661cc6195cd40936ff6494036c63a1'
FIX_COMMIT = '50a29370b17bbc8fe63131f1c9f8ee9ffd5b8628'      # ha_nextcloud.nc_true: '1'/true/yes/on (Nextcloud 35 stores '1')
NC_SHA = '192bf019565ced71bbde05ea0b39b8f43e40f5a91267b36e605d3ea187deb138'   # ha_nextcloud.py of PRODUCT_COMMIT
# No prior engine is bound: dev-e's engine/helper/VERSION are captured when the run starts and returned exactly.
# The S5-A fixture, inside dev-e, bound from S5-A's committed result evidence (never from a device).
EVIDENCE = REPO / 'tests/backup/evidence/focus-nextcloud-r6-20261127'
S5A_LEAVES = ('artifact', 'credentials.private.json', 'fixed-result.json', 'nc-identity.json', 'occ-gate.private.json',
              'pg-identity.json', 'redis-identity.json', 'source-result.json')
S5A_ARTIFACT = ('generated-s5-source.tar', 'provenance.private.json')
ARTIFACT_TAIL = '/owned/artifact/generated-s5-source.tar'
COMMAND_RE = r'command-[0-9]{4}\.(?:json|stdout\.private|stderr\.private)'
S5A_ENGINE_COMMIT = s5.ENGINE_COMMIT    # the engine S5-A runs next to (its result says so); a fact of that evidence only
# HISTORY: the first S5-A build (4163367c, 2026-11-28). Its cluster was initialised with POSTGRES_USER=nextcloud, so it has
# no role postgres and the product's check cannot open it (focus_nextcloud_r6_s5_diag). Kept as history: only the
# diagnostic and the retirement of its proof root bind it, never an S5-B run.
HISTORY_RESULT = EVIDENCE / 's5a-source-fixture-20261128-result.json'
HISTORY = SimpleNamespace(
    source_commit='4163367cf67776c1e65c41cb51cda42761b2e1fc', engine_commit=s5.ENGINE_COMMIT,
    proof_root='/var/lib/woowbk-nextcloud-s5-afe8d885402badf3',
    fixture='/var/lib/woowbk-nextcloud-s5-afe8d885402badf3' + ARTIFACT_TAIL,
    provenance='/var/lib/woowbk-nextcloud-s5-afe8d885402badf3/owned/artifact/provenance.private.json',
    credentials='/var/lib/woowbk-nextcloud-s5-afe8d885402badf3/owned/credentials.private.json',
    fixture_sha='5aac0fccb4f44c05efb0c8224278dbf47de3975d339bb18bcd69ec5688f5e8a7', fixture_bytes=127600640,
    provenance_sha='094bd5e8afa4f558ffb38a3673333329b247c5d0b429c552bbaebc53cd031403', command_records=339)
# ACTIVE: the rebuilt fixture S5-B imports (the real add-on's database, s5.FIXTURE_SHAPE, opened by the product's own check
# before S5-A accepted it). After the real rebuild the coordinator commits S5-A's fixed-result.json under this name: that
# one reviewed commit is the switch; every value below comes from it (bind, s5a_binding) and the lease template names it.
S5A_RESULT = EVIDENCE / 's5a-source-fixture-rebuild-result.json'
S5A = None                    # the active binding (s5a_binding), None while no rebuild result is committed
S5A_ERROR = 'fixed-s5b-s5a-rebuild-result-not-committed'
PROOF_ROOT = FIXTURE = PROVENANCE = CREDENTIALS = FIXTURE_SHA = FIXTURE_BYTES = PROVENANCE_SHA = None
S5A_COMMAND_RECORDS = S5A_SOURCE_COMMIT = HA_ID = None
USER = s5.USER
SECRET_KEYS = ('secret', 'passwordsalt', 'dbpassword', 'mail_smtppassword')   # ha_nextcloud.SECRET_KEYS
PRIVATE_KEY_RE = r'nextcloud/files_encryption/OC_DEFAULT_MODULE/((?:master|pubShare)_[0-9a-f]{8})\.privateKey'
KEY_LAYOUT = rb'(?:[0-9a-f]{2})+\|[0-9a-f]{32}\|[0-9a-f]+\|3'    # s5.KEY_RE: hex ciphertext|hex iv|hex hmac|3
# What the check must say (the product's own texts of PRODUCT_COMMIT; tests compare them with ha_nextcloud).
SSE_ID = 'nextcloud.server-side-encryption'
SSE_REASONS = ('files_encryption', 'encryption_enabled')
SSE_TEXT = ('HA 的 Nextcloud 開啟了伺服器端加密。金鑰和檔案會一起搬，但這種備份這台還沒有實測過；'
            '匯入後如果檔案打不開，請用匯入前自動做的備份退回。')
UNTESTED = '還沒有實測過'   # stays in the product until S5 passed
# The only other lines a check may carry, each a legacy.warning notice of ha_nextcloud (recorded either way):
NOTICES = {
    # merge_config's keys of HA's config.php that are not carried (fullshare05's check on dev-e had this one line)
    'settings-not-carried': re.compile(r'HA 的 Nextcloud 設定 [A-Za-z0-9_.、 -]{1,400}(?: 等 [0-9]+ 個)? 不會搬過來（以這台的設定為準）。'),
    # lists_differ: the database records plaintext sizes, the share member holds ciphertext (MSG_LISTS + scan hint)
    'file-lists-differ': re.compile(r'HA 備份裡有 1 位 Nextcloud 使用者（例如 ' + USER + r'）的檔案清單（資料庫）和實際檔案不一致：'
                                    r'HA 先備份資料庫、Nextcloud 重新啟動後才備份使用者檔案，備份時可能有人在使用。'
                                    r'匯入後請在這台執行一次檔案掃描（podman exec -u www-data [a-z0-9-]{1,40} php occ files:scan --all）。'),
}
SECTION = {'nextcloud_version': '35.0.1.1', 'pg_version': '16', 'users': 1, 'shares': 0, 'datadir': '/share/nextcloud',
           'datadir_in_backup': True}
SAMPLE = 8                     # skeleton files read through WebDAV besides the S5-A files (spread over the sorted names)
LEASE_KEYS = ('lane', 'device', 'phases', 'source_commit', 'product_commit', 'product_checkout', 'product_manifest_sha256',
              'fix_commit', 'fixture_sha256', 'fixture_bytes',
              'proof_root', 's5a_result_sha256', 'provenance_sha256', 'source_policy', 'pin_refresh_policy',
              'recovery_grace_seconds', 'original_inactive_units', 'reserve_bytes', 'memory_cap_bytes', 'not_before_utc',
              'expires_utc', 'proof_root_removal', 'image_operations', 'host_fixture_copy',
              # the active S5-A rebuild (S5A_RESULT): which result, made by which commit and builder, its shape and gate
              's5a_result', 's5a_source_commit', 's5a_builder_sha256', 's5a_command_records', 'fixture_shape',
              'product_open_check')
REMOVAL = 'only-after-everything-passed'


def require(ok, reason):
    if not ok:
        raise ValueError('fixed-s5b-' + reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def confirm_key(app_id, issue_id, items, database=None):
    """haissues.confirm_key, written out (tests compare it with the product's): `<id>:` + 16 hex of a sha256 over
    [app, id, database, all names sorted]."""
    body = json.dumps([app_id, issue_id, database, sorted(str(item) for item in items)], ensure_ascii=False,
                      separators=(',', ':'))
    return issue_id + ':' + hashlib.sha256(body.encode('utf-8', 'surrogatepass')).hexdigest()[:16]


SSE_KEY = confirm_key('nextcloud', SSE_ID, SSE_REASONS)


# ====================================================================== device programs (rendered; also unit-tested)

def need(ok, reason):
    if not ok:
        raise ValueError('fixed-s5b-' + reason)


def ident(st):
    return [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size, st.st_mtime_ns,
            st.st_ctime_ns]


def read_small(path, limit, mode=None):
    """A small regular single-link file, read without following a link, unchanged while it was read."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= limit
             and (mode is None or stat.S_IMODE(st.st_mode) == mode), 'small-file')
        raw = f.read(limit + 1)
        need(len(raw) == st.st_size and ident(os.fstat(f.fileno())) == ident(st), 'small-file-changed')
    return raw


def sealed_digest(path, size, check):
    """(sha256, identity) of the exact `size` bytes of a regular single-link file, unchanged from first to last byte."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size == size, 'fixture-identity')
        h = hashlib.sha256(); count = 0
        for block in iter(lambda: f.read(1024 * 1024), b''):
            check(); count += len(block); need(count <= size, 'fixture-size'); h.update(block)
        need(count == size and ident(os.fstat(f.fileno())) == ident(st), 'fixture-changed')
    need(ident(os.lstat(path)) == ident(st), 'fixture-changed')
    return h.hexdigest(), ident(st)


def proof_root_state(root, leaves, records, artifact, command_re, owner_uid, root_uid=0):
    """The S5-A proof root exactly as S5-A left it: root (root's, nothing writable for others) holding only `owned`
    (the owner's, 0700) with exactly `leaves` plus `records` command records, `artifact` holding exactly the fixture and
    its provenance; every file regular, single-link, the owner's, on the root's filesystem; no other directory."""
    top = Path(root); st = top.lstat(); parent = top.parent.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == root_uid and not st.st_mode & 0o022, 'proof-root')
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == root_uid and not parent.st_mode & 0o022, 'proof-root-parent')
    need(sorted(os.listdir(top)) == ['owned'], 'proof-root-children')
    owned = top / 'owned'; o = owned.lstat()
    need(stat.S_ISDIR(o.st_mode) and o.st_dev == st.st_dev and o.st_uid == owner_uid and stat.S_IMODE(o.st_mode) == 0o700,
         'proof-root-owned')
    names = os.listdir(owned)
    commands = [n for n in names if re.fullmatch(command_re, n)]
    need(sorted(set(names) - set(commands)) == sorted(leaves) and len(commands) == records, 'proof-root-leaves')
    art = owned / 'artifact'; a = art.lstat()
    need(stat.S_ISDIR(a.st_mode) and a.st_dev == st.st_dev and a.st_uid == owner_uid, 'proof-root-artifact')
    need(sorted(os.listdir(art)) == sorted(artifact), 'proof-root-artifact-files')
    files = []
    for directory in (owned, art):
        for name in sorted(os.listdir(directory)):
            p = directory / name
            if p == art:
                continue
            s = p.lstat()
            need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_dev == st.st_dev and s.st_uid == owner_uid,
                 'proof-root-file')
            files.append((str(p.relative_to(top)), s.st_size))
    return {'files': len(files), 'bytes': sum(size for _name, size in files), 'paths': [name for name, _size in files]}


def compact_provenance(raw, fixture_sha, fixture_bytes, user):
    """What S5-B compares with, from S5-A's provenance (hashes only): every file of the user's files and every key file
    of the source data dir, the plaintext digests, the master key id; consistent with the fixture and itself."""
    doc = json.loads(raw)
    need(isinstance(doc, dict) and doc.get('kind') == 'generated-ha-shaped-test-fixture' and doc.get('haos_export') is False,
         'provenance-kind')
    need(doc.get('archive') == {'bytes': fixture_bytes, 'sha256': fixture_sha}, 'provenance-archive')
    proof, data = doc['native_proof'], doc['source_files']['data']
    need(all(proof.get(k) is True for k in ('webdav_before', 'webdav_after_restart', 'plaintext_before_encryption',
                                            'master_key_mode', 'pg_shutdown')), 'provenance-proof')
    master = proof['master_key_id']
    need(isinstance(master, str) and re.fullmatch(r'master_[0-9a-f]{8}', master) is not None, 'provenance-master')
    home = user + '/files/'
    files = {rel: {'bytes': row['bytes'], 'sha256': row['sha256']} for rel, row in data.items() if row.get('sha256')}
    user_files = {rel[len(home):]: row for rel, row in files.items() if rel.startswith(home)}
    key_files = {rel: row for rel, row in files.items() if 'files_encryption' in rel.split('/')[:2]}
    plain = proof['plaintext']
    need(sorted(plain) == ['before', 'encrypted'] and plain['before'] and plain['encrypted'], 'provenance-plaintext')
    need(sorted(proof['encrypted_files']) == sorted(home + name for name in plain['encrypted']), 'provenance-encrypted')
    for rel, row in proof['cipher_and_keys'].items():
        need(files.get(rel) == row, 'provenance-binding')
    for name, row in plain['before'].items():
        need(user_files.get(name) == row, 'provenance-plaintext-before')
    for name, row in plain['encrypted'].items():
        disk = user_files.get(name)
        need(disk is not None and disk['sha256'] != row['sha256'] and disk['bytes'] > row['bytes'], 'provenance-ciphertext')
    shares = {rel for rel in key_files if rel.startswith(user + '/files_encryption/')}
    need(shares == {user + '/files_encryption/keys/files/' + name + '/OC_DEFAULT_MODULE/' + master + '.shareKey'
                    for name in plain['encrypted']}, 'provenance-share-keys')
    system = {rel for rel in key_files if rel.startswith('files_encryption/')}
    need({'files_encryption/OC_DEFAULT_MODULE/' + master + '.publicKey',
          'files_encryption/OC_DEFAULT_MODULE/' + master + '.privateKey'} <= system
         and set(key_files) == shares | system, 'provenance-system-keys')
    facts = proof.get('facts') or {}
    return {'master_key_id': master, 'plaintext': plain, 'encrypted': sorted(plain['encrypted']),
            'user_files': user_files, 'key_files': key_files, 'data_files': len(files),
            'facts': {k: facts.get(k) for k in ('encryption_app_version', 'use_master_key', 'core_encryption_enabled')}}


def owner_password(raw, user):
    """The generated admin password S5-A kept for S5-B (credentials.private.json); never written anywhere by S5-B."""
    doc = json.loads(raw)
    need(isinstance(doc, dict) and set(doc) == {'user', 'password', 'use'} and doc['user'] == user
         and isinstance(doc['password'], str) and re.fullmatch('[0-9a-f]{48}', doc['password']) is not None, 'credentials')
    return doc['password']


def config_values(raw, keys):
    """The values of `keys` in a config.php as Nextcloud writes it (var_export: one `'key' => 'value',` per line,
    single-quoted with \\\\ and \\' escapes); each at most once; secret and passwordsalt required."""
    found = {}
    pattern = r"^\s*'(" + '|'.join(re.escape(k) for k in keys) + r")'\s*=>\s*'((?:[^'\\]|\\.)*)',?\s*$"
    for key, value in re.findall(pattern, raw.decode('utf-8'), re.M):
        need(key not in found, 'config-duplicate')
        found[key] = re.sub(r'\\(.)', r'\1', value)
    need(len(found.get('secret', '')) >= 6 and len(found.get('passwordsalt', '')) >= 6, 'config-identity')
    return {key: value for key, value in found.items() if len(value) >= 6}


def fixture_secrets(path, slug, keys, key_re, check):
    """From the fixture inside dev-e: HA's config.php secret values (`keys`) and every master / public-share private key
    file, the needles of the S5-B leak scan. backup.json must say protected false (no HA key exists)."""
    config, private, doc = None, {}, None
    with tarfile.open(path, 'r:') as outer:
        members = outer.getmembers()
        need(sorted(m.name for m in members) == sorted([slug + '.tar', 'share.tar', './backup.json'])
             and all(m.isreg() for m in members), 'outer-members')
        with outer.extractfile('./backup.json') as f:
            doc = json.loads(f.read(1024 * 1024))
        need(doc.get('protected') is False and doc.get('compressed') is False, 'fixture-not-plain')
        with outer.extractfile(slug + '.tar') as raw, tarfile.open(fileobj=raw, mode='r|') as inner:
            for m in inner:
                check()
                if m.name == 'data/nextcloud/config/config.php':
                    need(m.isreg() and 0 < m.size <= 1024 * 1024 and config is None, 'config-member')
                    config = inner.extractfile(m).read()
        with outer.extractfile('share.tar') as raw, tarfile.open(fileobj=raw, mode='r|') as inner:
            for m in inner:
                check()
                match = re.fullmatch(key_re, m.name)
                if match:
                    need(m.isreg() and 0 < m.size <= 65536 and match.group(1) not in private, 'key-member')
                    private[match.group(1)] = inner.extractfile(m).read().decode('ascii')
    need(config is not None and any(name.startswith('master_') for name in private), 'fixture-secrets-missing')
    return {'config': config_values(config, keys), 'private_keys': private}


def resource_watch(deadline, floor, memory_cap, memory_file, disks):
    """The in-device stop rule of R6 (focus_nextcloud_r6_upload.WATCH): lease end, the reserve, the memory limit."""
    def check():
        need(time.time() < deadline, 'watch-expired')
        need(min(shutil.disk_usage(d).free for d in disks) >= floor, 'watch-reserve')
        need(int(Path(memory_file).read_text()) <= memory_cap, 'watch-memory')
    return check


def copy_fixture(source, part, size, digest, check):
    """Copy the fixture into the upload file upload-begin made (root's, empty, single link), inside dev-e: bounded,
    hashed, synced; the source must stay unchanged. Returns the written file's identity for the finish check."""
    src = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        dst = os.open(part, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            s, t = os.fstat(src), os.fstat(dst)
            need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size == size, 'copy-source')
            need(stat.S_ISREG(t.st_mode) and t.st_nlink == 1 and t.st_size == 0 and t.st_uid == os.geteuid()
                 and not t.st_mode & 0o022, 'copy-target')
            h = hashlib.sha256(); count = 0
            while True:
                check()
                block = os.read(src, 1024 * 1024)
                if not block:
                    break
                count += len(block); need(count <= size, 'copy-size'); h.update(block)
                view = memoryview(block)
                while view:
                    view = view[os.write(dst, view):]
            os.fsync(dst)
            need(count == size and h.hexdigest() == digest and ident(os.fstat(src)) == ident(s), 'copy-proof')
            return {'status': 'passed', 'bytes': count, 'sha256': h.hexdigest(), 'identity': {'dev': t.st_dev, 'ino': t.st_ino}}
        finally:
            os.close(dst)
    finally:
        os.close(src)


def scan_tar(stream, headers, key_layout, check, limit):
    """A tar stream of the live data dir's user files and key files: {path: {bytes, sha256}}, every entry that is no
    file or directory (named), the first 8192 bytes of the `headers` paths (base64) and, for every key file, whether it
    is in the native key layout (the bytes never leave dev-e)."""
    files, special, head, layout = {}, [], {}, {}
    with tarfile.open(fileobj=stream, mode='r|') as archive:
        for m in archive:
            check()
            need(len(files) + len(special) < 20000, 'scan-bound')
            if m.isdir():
                continue
            if not m.isreg():
                special.append(m.name); continue
            keyfile = 'files_encryption' in m.name.split('/')[:2]
            f = archive.extractfile(m); h = hashlib.sha256(); count = 0; first = b''; whole = b''
            for block in iter(lambda: f.read(1024 * 1024), b''):
                count += len(block); need(count <= limit, 'scan-file-bound'); h.update(block)
                if len(first) < 8192:
                    first += block[:8192 - len(first)]
                if keyfile:
                    whole += block; need(len(whole) <= 1024 * 1024, 'scan-key-bound')
            need(count == m.size, 'scan-short')
            files[m.name] = {'bytes': count, 'sha256': h.hexdigest()}
            if m.name in headers:
                head[m.name] = base64.b64encode(first).decode('ascii')
            if keyfile:
                layout[m.name] = re.fullmatch(key_layout, whole) is not None
    return {'files': files, 'special': special, 'headers': head, 'layouts': layout}


def dav(base, user, password, ops, opener):
    """WebDAV of `user` with Basic auth (the client's own route, as nextcloud_flow.CLIENT): PUT/GET, a wrong password
    by `suffix`. Statuses, sizes and SHA-256 only."""
    import urllib.error, urllib.parse, urllib.request
    out = []
    for op in ops:
        need(op['method'] in ('PUT', 'GET') and re.fullmatch(r'[A-Za-z0-9._-]{1,120}', op['name']) is not None, 'dav-op')
        auth = base64.b64encode((user + ':' + password + op.get('suffix', '')).encode()).decode()
        url = base + '/remote.php/dav/files/' + urllib.parse.quote(user) + '/' + urllib.parse.quote(op['name'])
        data = base64.b64decode(op['data']) if op['method'] == 'PUT' else None
        request = urllib.request.Request(url, method=op['method'], data=data, headers={'Authorization': 'Basic ' + auth})
        try:
            with opener(request, timeout=120) as reply:
                code, body = reply.status, reply.read()
        except urllib.error.HTTPError as error:
            code, body = error.code, error.read()
        out.append({'status': code, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()})
    return out


def remove_root(root, leaves, records, artifact, command_re, owner_uid, fixture, fixture_bytes, fixture_sha, provenance,
                provenance_sha, check, root_uid=0):
    """Only after S5-B passed: the S5-A proof root, proven unchanged (layout, fixture and provenance hashes), removed
    entry by entry: each proven file unlinked, then the two directories and the root removed with rmdir, which refuses
    anything that appeared meanwhile."""
    state = proof_root_state(root, leaves, records, artifact, command_re, owner_uid, root_uid)
    need(sealed_digest(fixture, fixture_bytes, check)[0] == fixture_sha, 'remove-fixture-changed')
    need(hashlib.sha256(read_small(provenance, 64 * 1024 * 1024)).hexdigest() == provenance_sha, 'remove-provenance-changed')
    top = Path(root)
    for rel in state['paths']:
        check(); os.unlink(top / rel)
    for directory in (top / 'owned' / 'artifact', top / 'owned', top):
        os.rmdir(directory)
    need(not os.path.lexists(root), 'remove-still-present')
    return {'status': 'removed', 'files': state['files'], 'bytes': state['bytes']}


def device_values():
    """The values the device programs are rendered with (the active S5-A binding's, see bind)."""
    return {
        'PROOF_ROOT': PROOF_ROOT, 'FIXTURE': FIXTURE, 'PROVENANCE': PROVENANCE, 'CREDENTIALS': CREDENTIALS,
        'FIXTURE_SHA': FIXTURE_SHA, 'FIXTURE_BYTES': FIXTURE_BYTES, 'PROVENANCE_SHA': PROVENANCE_SHA, 'USER': USER,
        'HA_ID': HA_ID, 'S5A_LEAVES': S5A_LEAVES, 'S5A_COMMAND_RECORDS': S5A_COMMAND_RECORDS, 'S5A_ARTIFACT': S5A_ARTIFACT,
        'COMMAND_RE': COMMAND_RE, 'OWNER': 'appowner', 'ROOT_UID': 0, 'SLUG': s5.SLUG, 'SECRET_KEYS': SECRET_KEYS,
        'PRIVATE_KEY_RE': PRIVATE_KEY_RE, 'KEY_LAYOUT': KEY_LAYOUT, 'STORE': '/var/lib/woowtech-backup',
        'FLOOR': RESERVE + MARGIN, 'MEMORY_CAP': DEVICE_CAP - MARGIN, 'MEMORY_FILE': '/sys/fs/cgroup/memory.current',
        'DISKS': ('/home', '/var/lib'), 'EXEC': ('podman', 'exec', '-u', 'www-data', 'nextcloud-app'),
        'DATA_ROOT': '/var/www/html/data', 'DAV_BASE': 'http://127.0.0.1:18081', 'SCAN_LIMIT': 512 * MIB,
    }


DEVICE = device_values()
BODIES = {
    # root, read only: the proof root as S5-A left it, the fixture's SHA-256, the compact provenance, the shape of the
    # credentials file (never its content), the HA store entry still absent
    'state': r'''
q=json.load(sys.stdin);owner=pwd.getpwnam(OWNER).pw_uid
out={'proof_root':proof_root_state(PROOF_ROOT,S5A_LEAVES,S5A_COMMAND_RECORDS,S5A_ARTIFACT,COMMAND_RE,owner,ROOT_UID)}
digest,identity=sealed_digest(FIXTURE,FIXTURE_BYTES,lambda:None)
need(digest==FIXTURE_SHA,'fixture-sha')
raw=read_small(PROVENANCE,64*1024*1024)
need(hashlib.sha256(raw).hexdigest()==PROVENANCE_SHA,'provenance-sha')
out['provenance']=compact_provenance(raw,FIXTURE_SHA,FIXTURE_BYTES,USER)
owner_password(read_small(CREDENTIALS,4096,0o600),USER)
out['credentials']={'present':True,'mode':'0600'}
ha=Path(STORE)/'ha-backups'
out['ha_store_entry_absent']=not any(os.path.lexists(ha/(HA_ID+suffix)) for suffix in ('.tar','.json'))
out['fixture']={'sha256':digest,'identity':identity}
print(json.dumps(out))
''',
    # root, read only: the needles of the S5-B leak scan (printed to the driver's pipe only)
    'secrets': r'''
q=json.load(sys.stdin)
found=fixture_secrets(FIXTURE,SLUG,SECRET_KEYS,PRIVATE_KEY_RE,lambda:None)
found['password']=owner_password(read_small(CREDENTIALS,4096,0o600),USER)
print(json.dumps(found))
''',
    # root: the fixture into the owned upload file, inside dev-e
    'copy': r'''
q=json.load(sys.stdin)
need(re.fullmatch('u[0-9a-f]{16}',q['upload_id']) is not None and q['part']==STORE+'/uploads/'+q['upload_id']+'.part','copy-binding')
need(q['source']==FIXTURE and q['size']==FIXTURE_BYTES and q['sha256']==FIXTURE_SHA,'copy-fixture-binding')
check=resource_watch(q['deadline'],FLOOR,MEMORY_CAP,MEMORY_FILE,DISKS)
print(json.dumps(copy_fixture(FIXTURE,q['part'],FIXTURE_BYTES,FIXTURE_SHA,check)))
''',
    # appowner: the live data dir's user files and key files through tar in the app container
    'disk': r'''
q=json.load(sys.stdin)
roots=[USER+'/files','files_encryption',USER+'/files_encryption']
p=subprocess.Popen([*EXEC,'tar','-C',DATA_ROOT,'-cf','-','--',*roots],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                   stderr=subprocess.DEVNULL)
try:
 result=scan_tar(p.stdout,set(q.get('headers') or ()),KEY_LAYOUT,lambda:None,SCAN_LIMIT)
 while p.stdout.read(65536):pass
finally:
 p.stdout.close();code=p.wait(timeout=600)
need(code==0,'disk-tar-failed')
print(json.dumps(result))
''',
    # appowner: WebDAV of the S5-A user (password on stdin)
    'dav': r'''
import urllib.request
q=json.load(sys.stdin);need(q['user']==USER,'dav-user')
print(json.dumps(dav(DAV_BASE,q['user'],q['password'],q['ops'],urllib.request.urlopen)))
''',
    # root: the proof root, only after everything passed
    'remove': r'''
q=json.load(sys.stdin);need(q.get('root')==PROOF_ROOT and q.get('removal')=='only-after-everything-passed','remove-binding')
owner=pwd.getpwnam(OWNER).pw_uid
print(json.dumps(remove_root(PROOF_ROOT,S5A_LEAVES,S5A_COMMAND_RECORDS,S5A_ARTIFACT,COMMAND_RE,owner,FIXTURE,FIXTURE_BYTES,
                             FIXTURE_SHA,PROVENANCE,PROVENANCE_SHA,lambda:None,ROOT_UID)))
''',
}
FUNCTIONS = {'state': (ident, read_small, sealed_digest, proof_root_state, compact_provenance, owner_password),
             'secrets': (ident, read_small, owner_password, config_values, fixture_secrets),
             'copy': (ident, resource_watch, copy_fixture), 'disk': (scan_tar,), 'dav': (dav,),
             'remove': (ident, read_small, sealed_digest, proof_root_state, remove_root)}


def programs(overrides=None):
    """Every device program of S5-B, rendered from the functions above and DEVICE (tests render them against local
    directories with `overrides`)."""
    values = dict(DEVICE, **(overrides or {}))
    head = ('import base64,hashlib,json,os,pwd,re,shutil,stat,subprocess,sys,tarfile,time\nfrom pathlib import Path\n'
            'sys.dont_write_bytecode=True\n' + ''.join(f'{k}={v!r}\n' for k, v in sorted(values.items())))
    return {name: head + '\n'.join(inspect.getsource(f) for f in (need, *FUNCTIONS[name])) + body
            for name, body in BODIES.items()}


PROGRAMS = programs()


def trace(body, request, ev, prefix, timeout):
    """focus_nextcloud_r6_upload.device_process: a bounded root program with its private stdout/stderr kept first."""
    return upload.device_process(body, [], ev, prefix, json.dumps(request).encode(), timeout)


# ====================================================================== offline gates (no I/O beyond git and this repo)

def git_manifest(repo, commit=PRODUCT_COMMIT, nc_sha=NC_SHA):
    """The frozen checkout's manifest (focus_nextcloud_r6_source.frozen_manifest rows: helper, VERSION, every file of
    backup-engine/woowbackup) of `commit`, from this repository's git objects: the lease value before the checkout exists."""
    git = ['git', '-C', str(repo)]
    listing = subprocess.check_output(git + ['ls-tree', '-r', '-z', '--full-tree', commit, '--', 'backup-engine/woowbackup',
                                             'backup-engine/woowtech-cockpit-backup', 'VERSION'])
    rows = {}
    for record in listing.split(b'\0'):
        if not record:
            continue
        meta, _, path = record.partition(b'\t')
        mode, kind, obj = meta.split()
        path = path.decode('utf-8')
        require(kind == b'blob' and mode in (b'100644', b'100755'), 'product-tree-entry')
        name = ('helper' if path == 'backup-engine/woowtech-cockpit-backup' else 'VERSION' if path == 'VERSION'
                else 'woowbackup/' + path[len('backup-engine/woowbackup/'):])
        blob = subprocess.check_output(git + ['cat-file', 'blob', obj.decode('ascii')])
        rows[name] = {'size': len(blob), 'sha256': sha(blob)}
    source.validate_manifest(rows)
    require(rows['woowbackup/ha_nextcloud.py']['sha256'] == nc_sha, 'product-nextcloud-sha')
    return rows


def frozen_manifest(path=FROZEN):
    """(paths, rows) of the frozen clean product checkout: R6's own reader with this binding."""
    return source.frozen_manifest(path, commit=PRODUCT_COMMIT, nc_sha=NC_SHA)


BINDING = SimpleNamespace(phase=PHASE, product_commit=PRODUCT_COMMIT, frozen_manifest=lambda path: frozen_manifest(path),
                          area=AREA + '-control', result_phase=PHASE + '-cold-return')


def fix_included(repo, commit=PRODUCT_COMMIT, fix=FIX_COMMIT):
    return subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', fix, commit],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def history_result(path=HISTORY_RESULT):
    """The committed FIRST S5-A result, exactly HISTORY (passed, its fixture, root, provenance and records): its SHA-256.
    For the diagnostic and the retirement of its proof root only."""
    raw = Path(path).read_bytes(); doc = json.loads(raw); fixture = doc.get('fixture') or {}
    require(doc.get('status') == 'passed' and doc.get('phase') == s5.PHASE and doc.get('source_commit') == HISTORY.source_commit
            and doc.get('original_target_exact') is True and doc.get('engine_commit') == HISTORY.engine_commit
            and fixture.get('archive') == HISTORY.fixture and fixture.get('sha256') == HISTORY.fixture_sha
            and fixture.get('bytes') == HISTORY.fixture_bytes and fixture.get('provenance_sha256') == HISTORY.provenance_sha
            and fixture.get('haos_export') is False and fixture.get('s5_import_acceptance') is False
            and doc.get('owned_leftovers') == {'leaves': list(S5A_LEAVES), 'command_records': HISTORY.command_records,
                                               'artifact': list(S5A_ARTIFACT)}, 'history-result')
    return sha(raw)


def git_is_ancestor(repo, commit):
    return subprocess.run(['git', '-C', str(repo), 'merge-base', '--is-ancestor', commit, 'HEAD'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def git_blob(repo, commit, path):
    p = subprocess.run(['git', '-C', str(repo), 'show', f'{commit}:{path}'], stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL)
    return p.stdout if p.returncode == 0 else None


def s5a_binding(path=None, *, repo=REPO, verify_git=True):
    """The ACTIVE S5-A result (S5A_RESULT), strictly: a passed rebuild with the real add-on's database
    (s5.FIXTURE_SHAPE), opened by the product's own check before S5-A accepted it (every s5.OPEN_CHECKS true), its owned
    source removed and its fixture under a proof root of its own (never the history's root or bytes). `verify_git`: its
    source commit is in this checkout's history and the builder there is the one the result names. Returns the binding."""
    path = Path(S5A_RESULT if path is None else path)
    raw = path.read_bytes()
    try:
        doc = json.loads(raw)
    except ValueError:
        raise ValueError('fixed-s5b-s5a-rebuild-result') from None
    doc = doc if isinstance(doc, dict) else {}
    fixture, left, gate = (doc.get(k) if isinstance(doc.get(k), dict) else {}
                           for k in ('fixture', 'owned_leftovers', 'product_open_check'))
    archive, commit, builder = fixture.get('archive'), doc.get('source_commit'), doc.get('builder_sha256')
    root = archive[:-len(ARTIFACT_TAIL)] if isinstance(archive, str) and archive.endswith(ARTIFACT_TAIL) else ''
    hexed = lambda value, n: isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % n, value) is not None   # noqa: E731
    require(len(raw) <= 1024 * 1024 and doc.get('status') == 'passed' and doc.get('phase') == s5.PHASE
            and doc.get('native_status') == 'passed' and doc.get('original_target_exact') is True
            and doc.get('runtime_s5_import_acceptance') is False and doc.get('engine_commit') == S5A_ENGINE_COMMIT
            and hexed(commit, 40) and hexed(builder, 64) and doc.get('fixture_shape') == s5.FIXTURE_SHAPE
            and re.fullmatch(s5.ROOT_RE, root) is not None and root != HISTORY.proof_root
            and fixture.get('status') == 'passed' and fixture.get('kind') == 'generated-ha-shaped-test-fixture'
            and fixture.get('haos_export') is False and fixture.get('s5_import_acceptance') is False
            and hexed(fixture.get('sha256'), 64) and fixture['sha256'] != HISTORY.fixture_sha
            and type(fixture.get('bytes')) is int and 0 < fixture['bytes'] <= s5.FIXTURE_CAP
            and hexed(fixture.get('provenance_sha256'), 64)
            and left.get('leaves') == list(S5A_LEAVES) and left.get('artifact') == list(S5A_ARTIFACT)
            and type(left.get('command_records')) is int and 0 < left['command_records'] < 30000
            and doc.get('owned_removal') == {'status': 'owned-source-removed', 'removed': ['html', 'pg', 'data'],
                                             'fixture_retained': True}
            and gate.get('status') == 'passed' and isinstance(gate.get('job_id'), str)
            and re.fullmatch(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', gate['job_id']) is not None
            and gate.get('checks') == {name: True for name in s5.OPEN_CHECKS}, 's5a-rebuild-result')
    if verify_git:
        require(git_is_ancestor(repo, commit), 's5a-rebuild-source-commit')
        blob = git_blob(repo, commit, 'tests/e2e/lab/focus_nextcloud_r6_s5.py')
        require(blob is not None and sha(blob) == builder, 's5a-rebuild-builder')
    return SimpleNamespace(result=path, result_sha256=sha(raw), source_commit=commit, builder_sha256=builder,
                           proof_root=root, fixture=archive, provenance=root + '/owned/artifact/provenance.private.json',
                           credentials=root + '/owned/credentials.private.json', fixture_sha=fixture['sha256'],
                           fixture_bytes=fixture['bytes'], provenance_sha=fixture['provenance_sha256'],
                           command_records=left['command_records'], open_check_job=gate['job_id'])


def bind(binding, error=None):
    """Every module value S5-B takes from the S5-A fixture, from the active binding (s5a_binding); None while no rebuild
    result is committed: the values stay None and nothing can run (S5A_ERROR says why)."""
    global S5A, S5A_ERROR, PROOF_ROOT, FIXTURE, PROVENANCE, CREDENTIALS, FIXTURE_SHA, FIXTURE_BYTES, PROVENANCE_SHA
    global S5A_COMMAND_RECORDS, S5A_SOURCE_COMMIT, HA_ID, DEVICE, PROGRAMS
    S5A, S5A_ERROR = binding, (None if binding is not None else error or 'fixed-s5b-s5a-rebuild-result-not-committed')
    b = binding or SimpleNamespace(proof_root=None, fixture=None, provenance=None, credentials=None, fixture_sha=None,
                                   fixture_bytes=None, provenance_sha=None, command_records=None, source_commit=None)
    PROOF_ROOT, FIXTURE, PROVENANCE, CREDENTIALS = b.proof_root, b.fixture, b.provenance, b.credentials
    FIXTURE_SHA, FIXTURE_BYTES, PROVENANCE_SHA = b.fixture_sha, b.fixture_bytes, b.provenance_sha
    S5A_COMMAND_RECORDS, S5A_SOURCE_COMMIT = b.command_records, b.source_commit
    HA_ID = 'ha-' + FIXTURE_SHA[:20] if FIXTURE_SHA else None
    DEVICE = device_values()
    PROGRAMS = programs()
    Variant.uploaded_bytes = FIXTURE_BYTES


def s5a_result(path=None):
    """The active S5-A result's SHA-256 after the strict check (s5a_binding)."""
    return s5a_binding(path).result_sha256


def in_repo(path, repo=REPO):
    """`path` as the lease names it: relative to the checkout (the committed result always is), else as it is."""
    path, repo = Path(path), Path(repo)
    return str(path.relative_to(repo)) if path.is_relative_to(repo) else str(path)


def lease_template(repo=REPO):
    """The lease fields this checkout binds; the time window is the coordinator's. Refused while no S5-A rebuild result
    is committed, and when the committed one is not the one this process bound its device programs to."""
    commit, clean = s5.checkout(repo)
    require(S5A is not None, (S5A_ERROR or 'fixed-s5b-').replace('fixed-s5b-', ''))
    active = s5a_binding(S5A_RESULT, repo=repo)
    require(active.result_sha256 == S5A.result_sha256, 's5a-binding-changed')
    return {'lane': 'nextcloud-r6', 'device': 'woowbk-dev-e', 'phases': [PHASE],
            'source_commit': commit if clean else 'REQUIRES_A_CLEAN_COMMITTED_CHECKOUT',
            'product_commit': PRODUCT_COMMIT, 'product_checkout': str(FROZEN),
            'product_manifest_sha256': source.manifest_hash(git_manifest(repo)), 'fix_commit': FIX_COMMIT,
            'fixture_sha256': active.fixture_sha, 'fixture_bytes': active.fixture_bytes, 'proof_root': active.proof_root,
            's5a_result_sha256': active.result_sha256, 'provenance_sha256': active.provenance_sha,
            's5a_result': in_repo(active.result, repo), 's5a_source_commit': active.source_commit,
            's5a_builder_sha256': active.builder_sha256, 's5a_command_records': active.command_records,
            'fixture_shape': dict(s5.FIXTURE_SHAPE), 'product_open_check': active.open_check_job,
            'source_policy': case.SOURCE_POLICY, 'pin_refresh_policy': case.PIN_POLICY, 'recovery_grace_seconds': 1800,
            'original_inactive_units': list(r6.INACTIVE_UNITS), 'reserve_bytes': RESERVE, 'memory_cap_bytes': DEVICE_CAP,
            'not_before_utc': 'REQUIRES_GRANTED_START', 'expires_utc': 'REQUIRES_GRANTED_START_PLUS_120_MINUTES',
            'proof_root_removal': REMOVAL, 'image_operations': [], 'host_fixture_copy': False}


def admit_lease(lease, commit, repo, frozen_rows, *, now=None):
    """Exactly the template's fields and values (only the window is free: timezone-aware, now inside it, HEADROOM
    left), the frozen checkout's manifest equal to the git one, the fix inside the product commit."""
    require(isinstance(lease, dict) and sorted(lease) == sorted(LEASE_KEYS), 'lease-fields')
    when = datetime.datetime.fromtimestamp(time.time() if now is None else now, datetime.timezone.utc)
    lease_check(lease, commit, PHASE, when)
    expected = lease_template(repo)
    for key in LEASE_KEYS:
        if key not in ('not_before_utc', 'expires_utc', 'source_commit'):
            require(lease[key] == expected[key], 'lease-' + key.replace('_', '-'))
    require(lease['source_commit'] == commit == expected['source_commit'], 'lease-source-commit')
    require(source.manifest_hash(frozen_rows) == lease['product_manifest_sha256'], 'frozen-checkout-manifest')
    require(fix_included(repo), 'fix-not-in-product')
    deadline = datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z', '+00:00')).timestamp()
    require(deadline - when.timestamp() >= HEADROOM, 'lease-headroom')
    return deadline


def locked_admission(lease, commit, deadline, *, now=None):
    """Right after the BLOCKING dev-e lock (heavy.sh only waited for it to be free): still inside, HEADROOM left."""
    when = datetime.datetime.fromtimestamp(time.time() if now is None else now, datetime.timezone.utc)
    lease_check(lease, commit, PHASE, when)
    require(deadline - when.timestamp() >= HEADROOM, 'lease-headroom-after-lock')


def convert_request(ha, apps, test_mode, keys, request_id):
    """ha-convert-start with fields of the product's schema only (cli.SPECS). No key: the fixture is not protected.
    `keys` None: no acknowledgement at all (the refusal step); else {'nextcloud': keys}."""
    request = {'ha_backup_id': ha, 'apps': list(apps), 'test_mode': test_mode, 'confirm': True, 'request_id': request_id}
    if keys is not None:
        request['acknowledged'] = {'nextcloud': list(keys)}
    return request


def judge_check(job):
    """The S5 check verdict, every line recorded: {base, sse, others, section, versions, lines, notices}."""
    result = (job.get('result') or {}).get('ha_check') or {}
    apps = result.get('apps') or []
    app = apps[0] if len(apps) == 1 else {}
    issues = app.get('issues') or []
    lines = [{'id': i.get('id'), 'level': i.get('level'), 'message': i.get('message'), 'items': i.get('items'),
              'more': i.get('more'), 'key': i.get('key')} for i in issues]
    confirms = [i for i in issues if i.get('level') == 'confirm']
    sse = confirms[0] if len(confirms) == 1 else {}
    others = [i for i in issues if i is not sse]
    notices = {}
    for line in others:
        kind = next((k for k, rule in NOTICES.items() if isinstance(line.get('message'), str)
                     and rule.fullmatch(line['message'])), None)
        known = (line.get('id') == 'legacy.warning' and line.get('level') in ('notice', 'auto') and kind is not None
                 and not line.get('items') and not line.get('more'))
        notices.setdefault(kind if known else 'unexpected', []).append(line.get('id'))
    section = app.get('nextcloud') or {}
    return {
        'base': (job.get('state') == 'succeeded' and len(apps) == 1 and app.get('app_id') == 'nextcloud'
                 and app.get('importable') is True and not any(i.get('level') == 'stop' for i in issues)),
        'sse': (sse.get('id') == SSE_ID and sorted(sse.get('items') or []) == sorted(SSE_REASONS)
                and len(sse.get('items') or []) == len(SSE_REASONS) and sse.get('more') == 0
                and sse.get('key') == SSE_KEY and sse.get('message') == SSE_TEXT and UNTESTED in SSE_TEXT),
        'others': 'unexpected' not in notices and all(i.get('level') in ('notice', 'auto') for i in others),
        'section': all(section.get(k) == v for k, v in SECTION.items()),
        'versions': (app.get('arch'), app.get('version'), app.get('target_version')) == ('amd64', s5.PROFILE, s5.VERSION),
        'lines': lines, 'notices': notices}


def judge_refusal(rc, reply, job, before, after):
    """Conversion without the acknowledgement: refused at the start (confirmation-required) or the job fails with it,
    Nextcloud skipped by exactly the encryption line (its bound key), no stop, and no backup added."""
    added = sorted(set(after) - set(before))
    if rc != 0:
        refused = (reply.get('error') or {}).get('code') == 'confirmation-required' and job is None
        return refused and not added, {'start_refused': True, 'code': (reply.get('error') or {}).get('code'), 'added': added}
    results = ((job or {}).get('result') or {}).get('results') or []
    row = results[0] if len(results) == 1 else {}
    issues = row.get('issues') or []
    keys = [i.get('key') for i in issues if i.get('level') == 'confirm']
    ok = ((job or {}).get('state') == 'failed' and ((job or {}).get('error') or {}).get('code') == 'confirmation-required'
          and row.get('app_id') == 'nextcloud' and row.get('status') == 'skipped' and row.get('code') == 'confirmation-required'
          and keys == [SSE_KEY] and not any(i.get('level') == 'stop' for i in issues) and not added)
    return ok, {'start_refused': False, 'state': (job or {}).get('state'), 'error': ((job or {}).get('error') or {}).get('code'),
                'result': {k: row.get(k) for k in ('app_id', 'status', 'code')}, 'confirm_keys': keys, 'added': added}


def showcase_digest(rows):
    """nextcloud_flow.CLIENT's per-user manifest digest of `<user>/files` (`find . -type f -print0 | LC_ALL=C sort -z |
    xargs -0 -r sha256sum | sha256sum`) from {path under files/: sha256}."""
    names = sorted(('./' + name).encode('utf-8') for name in rows)
    require(all(b'\\' not in n and b'\n' not in n for n in names), 'digest-name')   # sha256sum would escape these
    return sha(b''.join(rows[n[2:].decode('utf-8')].encode() + b'  ' + n + b'\n' for n in names))


def webdav_expectations(p, new_file=None):
    """{name under the user's files: plaintext SHA-256}: the S5-A files (pre-encryption and encrypted), SAMPLE skeleton
    files spread over the sorted names plus the largest (plaintext on disk: their disk SHA-256), the new file."""
    known = {**{n: r['sha256'] for n, r in p['plaintext']['before'].items()},
             **{n: r['sha256'] for n, r in p['plaintext']['encrypted'].items()}}
    skeleton = sorted(n for n in p['user_files'] if n not in known)
    picked = {skeleton[i * len(skeleton) // SAMPLE] for i in range(min(SAMPLE, len(skeleton)))}
    if skeleton:
        picked.add(max(skeleton, key=lambda n: (p['user_files'][n]['bytes'], n)))
    out = dict(known, **{n: p['user_files'][n]['sha256'] for n in picked})
    if new_file:
        out[new_file['name']] = new_file['plain_sha256']
    return out


def expected_disk(p, new_file=None):
    user, keys = dict(p['user_files']), dict(p['key_files'])
    if new_file and new_file.get('disk'):
        user[new_file['name']] = new_file['disk']
        if new_file.get('share'):
            keys[new_file['share_key']] = new_file['share']
    return user, keys


def split_disk(disk):
    home = USER + '/files/'
    files = disk.get('files') or {}
    user = {rel[len(home):]: row for rel, row in files.items() if rel.startswith(home)}
    keys = {rel: row for rel, row in files.items() if 'files_encryption' in rel.split('/')[:2]}
    others = sorted(rel for rel in files if not rel.startswith(home) and rel not in keys)
    return user, keys, others


def judge_disk(disk, p, new_file=None):
    """Every user file and key file on disk byte for byte what S5-A wrote (plus the run's new file once written)."""
    want_user, want_keys = expected_disk(p, new_file)
    user, keys, others = split_disk(disk)
    differ = lambda have, want: sorted(n for n in set(have) | set(want) if have.get(n) != want.get(n))   # noqa: E731
    bad_layout = sorted(k for k in keys if (disk.get('layouts') or {}).get(k) is not True)
    detail = {'user_files': len(user), 'key_files': len(keys), 'differ_user': differ(user, want_user)[:10],
              'differ_keys': differ(keys, want_keys)[:10], 'others': others[:10], 'special': (disk.get('special') or [])[:10],
              'key_layout_refused': bad_layout[:10]}
    ok = (not detail['differ_user'] and not detail['differ_keys'] and not others and not disk.get('special')
          and not bad_layout and bool(want_user) and bool(want_keys))
    return ok, detail


def judge_new_file(disk, p, name, plain, ops):
    """A new file written through WebDAV after the import: 201, read back exactly, a wrong password 401; on disk the
    native header of the installed module and more bytes than the plaintext; exactly one new key file, its master-key
    share key in the native layout (no fileKey); every S5-A file and key unchanged."""
    home = USER + '/files/'
    rel = home + name
    share = USER + '/files_encryption/keys/files/' + name + '/OC_DEFAULT_MODULE/' + p['master_key_id'] + '.shareKey'
    want_user, want_keys = expected_disk(p)
    user, keys, others = split_disk(disk)
    put, get, wrong = (list(ops) + [{}, {}, {}])[:3]
    try:
        header = s5.native_header(base64.b64decode((disk.get('headers') or {}).get(rel, '')))
    except ValueError:
        header = 'unreadable'
    row = user.get(name) or {}
    record = {'put': put.get('status'), 'get': get, 'wrong': wrong.get('status'), 'disk': row, 'header': header,
              'extra_user': sorted(set(user) - set(want_user)), 'extra_keys': sorted(set(keys) - set(want_keys)),
              'share_layout': (disk.get('layouts') or {}).get(share)}
    ok = (put.get('status') == 201 and get == {'status': 200, 'bytes': len(plain), 'sha256': sha(plain)}
          and wrong.get('status') == 401 and record['extra_user'] == [name] and record['extra_keys'] == [share]
          and all(user.get(n) == r for n, r in want_user.items()) and all(keys.get(k) == r for k, r in want_keys.items())
          and row.get('bytes', 0) > len(plain) and row.get('sha256') != sha(plain) and header == s5.HEADER
          and record['share_layout'] is True and not others and not disk.get('special'))
    new_file = ({'name': name, 'plain_sha256': sha(plain), 'plain_bytes': len(plain), 'disk': row,
                 'share_key': share, 'share': keys.get(share)} if row else None)
    return ok, record, new_file


def owned_store_clean(before, after, state):
    """The engine store after the run: archives and the HA store exactly as before (every backup and the HA record of
    this run deleted); new job records only of recorded jobs (old ones may go: the product's own retention); new upload
    files only this run's completed-upload cache (old ones may go: upload-begin's own 24 h cleanup). Delta recorded."""
    names = lambda rows: {row[0] for row in rows}   # noqa: E731
    jobs = {job_id + suffix for job_id in (state.get('jobs') or {}) for suffix in ('.json', '.log', '.lock', '.cancel')}
    upload_done = {state['finished_upload_id'] + '.done'} if state.get('finished_upload_id') else set()
    delta = {kind: {'added': sorted(names(after.get(kind, [])) - names(before.get(kind, []))),
                    'removed': sorted(names(before.get(kind, [])) - names(after.get(kind, [])))}
             for kind in ('archives', 'ha-backups', 'uploads', 'jobs')}
    ok = (not delta['archives']['added'] and not delta['archives']['removed'] and not delta['ha-backups']['added']
          and not delta['ha-backups']['removed'] and set(delta['jobs']['added']) <= jobs
          and set(delta['uploads']['added']) <= upload_done)
    return ok, delta


# ====================================================================== the case on R6's machinery

def make_run(Base, ctx, variant):
    """R6's Run (focus_nextcloud_r6.run_locked) with the S5 steps: in-device upload, the exact check, the refused
    unacknowledged conversion, the S5 verification and the S5 leak scan; restart, rollbacks, after-state and cleanup
    are R6's own."""
    d, nc, ev, secrets, require_check, wait = ctx.d, ctx.nc, ctx.ev, ctx.secrets, ctx.require, ctx.wait
    p, password = variant.inputs.provenance, variant.inputs.password
    home = USER + '/files/'

    class S5BRun(Base):
        new_file = None

        def setup(self):
            super().setup()
            require_check('setup: the installed engine, helper and VERSION are the frozen product (with the fix)',
                          wake.device(s5.ENGINE_PROGRAM, root=True) == variant.product_engine)

        def upload(self):
            self.budget('upload', FIXTURE_BYTES + 3 * GIB)
            sent = time.time()
            begin = d.ok('upload-begin', {'filename': Path(FIXTURE).name, 'size': FIXTURE_BYTES}, ev=ev)
            d.STATE['begin_window'] = [sent, time.time()]
            upload_id = upload.validate_begin(begin)
            d.STATE['upload_id'] = upload_id
            d.save_state()
            copied = wake.device(PROGRAMS['copy'], {'source': FIXTURE, 'part': begin['path'], 'upload_id': upload_id,
                                                    'size': FIXTURE_BYTES, 'sha256': FIXTURE_SHA,
                                                    'deadline': ctx.expires}, root=True, timeout=1800)
            ev.save('upload-copy.json', copied)
            require_check('upload: the S5-A fixture is copied inside dev-e into the upload file (bytes and SHA-256 exact, '
                          'never through the host)',
                          copied.get('status') == 'passed' and copied.get('bytes') == FIXTURE_BYTES
                          and copied.get('sha256') == FIXTURE_SHA)
            reply = d.ok('upload-finish', {'upload_id': upload_id}, ev=ev, timeout=1800)
            record = reply.get('ha_backup') or {}
            # Whatever this upload published is this run's (the store entry was absent before): owned for ha-delete.
            self.created_store = record.get('id') if re.fullmatch(r'ha-[0-9a-f]{20}', str(record.get('id'))) else None
            d.STATE.update(upload_id=None, finished_upload_id=upload_id, ha_backup_id=self.created_store)
            d.save_state()
            ev.save('ha-backup.json', record)
            found = {a.get('app_id'): a.get('installed') for a in record.get('importable_apps') or []}
            require_check('upload: upload-finish publishes the HA record of exactly this fixture (id, SHA-256, size), '
                          'nextcloud importable and installed here',
                          self.created_store == HA_ID and record.get('sha256') == FIXTURE_SHA
                          and record.get('size') == FIXTURE_BYTES and found.get('nextcloud') is True)
            proof = trace(upload.VERIFY, {'deadline': ctx.expires, 'ha_backup_id': HA_ID, 'expected_id': HA_ID,
                                          'sha256': FIXTURE_SHA, 'size': FIXTURE_BYTES},
                          upload.Evidence(ev.dir / 'upload-trace'), 'verify-published', 1800)
            require_check('upload: the published HA file is the inode written inside dev-e, its full SHA-256 again',
                          proof.get('status') == 'passed' and proof.get('identity') == copied.get('identity')
                          and proof.get('sha256') == FIXTURE_SHA and proof.get('bytes') == FIXTURE_BYTES)

        def check(self):
            self.budget('check', GIB)
            job, took = d.run_check(self.created_store, ['nextcloud'], ev=ev)   # no key: protected false
            ev.time('check', 's5', 'nextcloud', took, job)
            self.check_id = job.get('id')
            result = (job.get('result') or {}).get('ha_check') or {}
            ev.save('check-result.json', result)
            verdict = judge_check(job)
            ev.save('check-lines.json', {'lines': verdict['lines'], 'notices': verdict['notices']})
            require_check('check: the job succeeds for nextcloud alone, importable, no stop', verdict['base'])
            require_check('check: exactly one confirmation: nextcloud.server-side-encryption, reasons exactly '
                          'files_encryption and encryption_enabled, its bound key, the not-yet-tested text', verdict['sse'])
            require_check('check: every other line is a reviewed notice (settings not carried, file lists differ), all '
                          'recorded', verdict['others'])
            require_check('check: the section is the generated source (35.0.1.1, PostgreSQL 16, one user, no share, the '
                          'data dir in the backup)', verdict['section'])
            require_check('check: amd64, add-on 0.2.3, target 35.0.1.1', verdict['versions'])
            apps = result.get('apps') or [{}]
            self.section = apps[0].get('nextcloud') or {}
            self.keys = [SSE_KEY]

        def refused_conversion(self):
            self.budget('unacknowledged convert', GIB)
            before = {b['id'] for b in d.ok('list', ev=ev).get('backups') or []}
            request = convert_request(self.created_store, ['nextcloud'], False, None, d.request_id('focus-s5b-unconfirmed'))
            rc, reply = d.helper('ha-convert-start', request, timeout=300)
            job = wait(reply['job_id'], ev=ev) if rc == 0 and reply.get('job_id') else None
            after = {b['id'] for b in d.ok('list', ev=ev).get('backups') or []}
            ok, detail = judge_refusal(rc, reply, job, before, after)
            ev.save('unacknowledged-convert.json', detail)
            require_check('convert: without the acknowledgement the conversion is refused (confirmation-required, '
                          'Nextcloud skipped by exactly the encryption line, no stop, no backup added)', ok)

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
            results = ((seen.get('job') or {}).get('result') or {}).get('results') or []
            row = results[0] if len(results) == 1 else {}
            issues = row.get('issues') or []
            ev.save('convert-results.json', results)
            ev.check('import: nextcloud converted with exactly the acknowledged encryption line (its bound key), no stop',
                     row.get('app_id') == 'nextcloud' and row.get('status') == 'converted'
                     and [i.get('key') for i in issues if i.get('level') == 'confirm'] == [SSE_KEY]
                     and not any(i.get('level') == 'stop' for i in issues), {'status': row.get('status')})

        def verify(self, phase):
            disk = d.device_python(PROGRAMS['disk'], {'headers': []}, timeout=900)
            ok_disk, disk_detail = judge_disk(disk, p, self.new_file)
            want = webdav_expectations(p, self.new_file)
            user_rows = expected_disk(p, self.new_file)[0]
            found = d.device_python(nc.CLIENT, {'user': USER, 'user_pw': password, 'files': sorted(want),
                                                'digest_users': [USER]}, timeout=1800)
            state = self.state()
            ev.save(f'client-{phase}.json', {'client': found, 'state': state, 'disk': disk_detail})
            status = found.get('status') or {}
            ev.check(f'{phase}: status.php installed 35.0.1.1, no maintenance, no database upgrade needed',
                     status.get('installed') is True and status.get('version') == '35.0.1.1'
                     and status.get('maintenance') is False and status.get('needsDbUpgrade') is False, status)
            ocs = found.get('ocs') or {}
            ev.check(f'{phase}: {USER} logs in with the S5-A password (OCS, the password moved); a wrong one is refused 401',
                     ocs.get('password') == [200, True] and (ocs.get('wrong') or [None])[0] == 401, ocs)
            ev.check(f'{phase}: every S5-A ciphertext, plaintext and key file is on disk byte for byte as S5-A wrote it '
                     '(per-file SHA-256, native key layout)', ok_disk, disk_detail)
            files = found.get('files') or {}
            ev.check(f'{phase}: the plaintext of the S5-A files (pre-encryption and encrypted) and of {SAMPLE}+ skeleton '
                     'files read through WebDAV equals the recorded SHA-256', files == want,
                     {n: (v[:16] if isinstance(v, str) else v) for n, v in files.items()})
            ev.check(f'{phase}: {USER}\'s files on disk equal the S5-A source (per-user manifest digest)',
                     (found.get('digests') or {}).get(USER) == showcase_digest({n: r['sha256'] for n, r in user_rows.items()}),
                     str((found.get('digests') or {}).get(USER))[:16])
            fp = found.get('fingerprint') or [None, None]
            ev.check(f'{phase}: clients see a new data fingerprint (restored-from-backup signal), the one in config.php',
                     fp[0] == 207 and bool(fp[1]) and fp[1] == state.get('fingerprint')
                     and fp[1] != ((self.before.get('client') or {}).get('fingerprint') or [None, None])[1], fp)
            scan = found.get('scan') or {}
            ev.check(f'{phase}: occ files:scan --all: nothing new, nothing removed, no error',
                     scan.get('rc') == 0 and scan.get('files', 0) > 0
                     and all(scan.get(k) == 0 for k in ('new', 'removed', 'errors')), scan)
            setup = found.get('setup') or {}
            ev.check(f'{phase}: Nextcloud\'s own setup check says the data directory is protected',
                     setup.get('data_dir') == 'success' and setup.get('checks', 0) > 20, setup)
            web = found.get('web') or {}
            ev.check(f'{phase}: the web server serves nothing below the data dir (protection file; static control served)',
                     web.get('control') == 200 and web.get('picked') is True and len(web.get('codes') or []) == 4
                     and all(code in (403, 404) for code in web['codes']) and web.get('htaccess_below') == '0'
                     and web.get('htaccess') == sha(nc.ha_nextcloud.DATA_HTACCESS), web)
            ev.check(f'{phase}: database: root storage is this device\'s data dir, tables owned by oc_admin',
                     found.get('storage') == 'local::/var/www/html/data/' and found.get('owners') == 'oc_admin',
                     {k: found.get(k) for k in ('storage', 'owners')})
            ev.log(f'{phase}: recorded only: capabilities {found.get("capabilities")} discovery {found.get("discovery")}')
            if phase == 'import':
                self.write_new_file()
            else:
                ev.check(f'{phase}: the file written after the import still reads back and is unchanged on disk',
                         self.new_file is not None and files.get(self.new_file['name']) == self.new_file['plain_sha256']
                         and ok_disk, (self.new_file or {}).get('name'))

        def write_new_file(self):
            name = 's5b-written-after-import-' + nonce_source.token_hex(4) + '.txt'
            plain = ('S5-B: written through WebDAV after the import of the server-side-encrypted backup (%s)\n'
                     % name).encode() * 300
            data = base64.b64encode(plain).decode('ascii')
            ops = d.device_python(PROGRAMS['dav'], {'user': USER, 'password': password, 'ops': [
                {'method': 'PUT', 'name': name, 'data': data}, {'method': 'GET', 'name': name},
                {'method': 'GET', 'name': name, 'suffix': '-wrong'}]}, timeout=600)
            disk = d.device_python(PROGRAMS['disk'], {'headers': [home + name]}, timeout=900)
            ok, record, new_file = judge_new_file(disk, p, name, plain, ops)
            ev.save('new-file-import.json', record)
            self.new_file = new_file
            ev.check('import: a new file written through WebDAV after the import is stored with the native encryption '
                     'header and only its master-key share key, reads back exactly, a wrong password 401, nothing else '
                     'changed', ok, record)

        def leaks(self):
            super().leaks()
            values = {k: v for k, v in secrets.values.items() if k.startswith('S5B_')}
            report = d.device_python(nc.LEAKS, {'secrets': values, 'url_tokens': []}, as_owner=False, timeout=900)
            host = d.scan_host_evidence(ev.dir, secrets)
            ev.save('s5-secret-leak-summary.json', {'device': report, 'host': host, 'names': sorted(values)})
            require_check('leaks: the s5owner password, HA\'s config.php secret values and the master and public-share '
                          'private key files are in no engine record, upload, staging, run dir or the device journal, and '
                          'not in this evidence',
                          report.get('hits') == 0 and report.get('scanned', 0) > 0 and report.get('names') == len(values)
                          and len(values) >= 4 and not host.get('hits'))
    return S5BRun


class Variant:
    """What focus_nextcloud_r6.run_locked takes from S5-B (its `variant` hook)."""
    area = AREA
    uploaded_bytes = FIXTURE_BYTES

    def __init__(self, inputs, product_engine):
        self.inputs, self.product_engine, self.receipt = inputs, product_engine, RECEIPT

    def prepare(self, secrets):
        """Before any evidence exists: every S5 needle is a registered secret (redacted, scanned on the host)."""
        secrets.register('S5B_OWNER_PASSWORD', self.inputs.password)
        for key, value in sorted(self.inputs.config.items()):
            secrets.register('S5B_CONFIG_' + key.upper(), value)
        for name, value in sorted(self.inputs.private_keys.items()):
            secrets.register('S5B_PRIVATE_KEY_' + name.upper(), value)

    @staticmethod
    def convert_request(ha, apps, test_mode, _key, keys, request_id):
        return convert_request(ha, apps, test_mode, keys, request_id)   # never the HA key: protected false

    @staticmethod
    def steps(r):
        return (r.setup, r.before_state, r.upload, r.check, r.refused_conversion, r.import_real,
                lambda: r.verify('import'), r.restart, r.rollback, r.after_state)

    def scope(self, r):
        return {'case': PHASE, 'product_commit': PRODUCT_COMMIT, 'fix_commit': FIX_COMMIT, 'original_fixture_reused': False,
                'fixture': {'path': FIXTURE, 'sha256': FIXTURE_SHA, 'bytes': FIXTURE_BYTES, 'in_device_copy': True,
                            'ha_key_needed': False}, 'new_file': (r.new_file or {}).get('name')}

    def run_class(self, Base, ctx):
        return make_run(Base, ctx, self)


def baseline_verify():
    return r6.baseline_verify()


def run_locked(args, lease, commit, facts, inventory):
    """focus_nextcloud_r6_case.run's case body (`flow.run_locked`): R6's, with the S5-B variant."""
    return r6.run_locked(args, lease, commit, facts, inventory, variant=args.s5b_variant)


def pending(path):
    return path.exists() and json.loads(path.read_text()).get('pending') is not False


def scan_evidence(roots, values):
    """Every file below `roots` (this lane's S5-B evidence folders) for the S5 needles: raw and one JSON-escaped layer in
    both Unicode modes (the b1 driver's secret_scan_needles); links refused."""
    marks = set()
    for value in values:
        marks.add(value.encode('utf-8'))
        marks.update(json.dumps(value, ensure_ascii=flag)[1:-1].encode('utf-8') for flag in (False, True))
    files = hits = 0
    for root in roots:
        if not root.exists():
            continue
        require(root.is_dir() and not root.is_symlink(), 'evidence-root')
        for directory, dirs, names in os.walk(root, followlinks=False):
            for name in dirs + names:
                require(not (Path(directory) / name).is_symlink(), 'evidence-link')
            for name in names:
                data = (Path(directory) / name).read_bytes()
                files += 1
                hits += sum(data.count(mark) for mark in marks)
    return {'files': files, 'hits': hits}


def run_case(args, lease, commit, deadline):
    """Caller holds the dev-e mutex. Read-only proofs first (no mutation), then R6's cold-to-cold path, then the S5-B
    end checks; the proof root goes only when all of it passed."""
    require(S5A is not None and lease.get('proof_root') == PROOF_ROOT and lease.get('s5a_result_sha256') == S5A.result_sha256,
            'active-s5a-binding')
    ev = upload.Evidence(LAB / 'evidence' / (AREA + '-run') / time.strftime('%Y%m%dT%H%M%S'))
    lease_sha = source.manifest_hash(lease)
    require(not pending(r6.RECEIPT), 'r6-recovery-pending')
    require(not pending(RECEIPT), 's5b-recovery-pending')
    product_engine = s5.engine_manifest(REPO, PRODUCT_COMMIT)
    # Whatever dev-e runs now (another lane may have deployed its own checkout) is the prior: captured here as its
    # {name: sha256} and, byte for byte with modes and times, by R6's source transaction, which returns exactly it.
    prior_engine = wake.device(s5.ENGINE_PROGRAM, root=True)
    require(isinstance(prior_engine, dict) and {'helper', 'lib/VERSION', 'lib/woowbackup/cli.py'} <= set(prior_engine),
            'prior-engine-unreadable')
    ev.save('binding.json', {'source_commit': commit, 'lease_sha256': lease_sha, 'product_commit': PRODUCT_COMMIT,
                             'fix_commit': FIX_COMMIT, 'prior_engine_captured': prior_engine,
                             'prior_engine_manifest_sha256': s5.manifest_hash(prior_engine),
                             'prior_differs_from_frozen_product': s5.engine_differs(prior_engine, product_engine)})
    state = wake.device(PROGRAMS['state'], root=True, timeout=900)
    ev.save('s5a-state.json', state)
    require(state.get('ha_store_entry_absent') is True and state['fixture']['sha256'] == FIXTURE_SHA, 's5a-state')
    found = wake.device(PROGRAMS['secrets'], root=True, timeout=900)   # never saved: needles of the leak scan
    inputs = SimpleNamespace(provenance=state['provenance'], password=found['password'], config=found['config'],
                             private_keys=found['private_keys'])
    del found
    store_before = wake.device(s5.TARGET_STATE, root=True)
    ev.save('store-before.json', store_before)
    facts = {'fixture': FIXTURE, 'sha256': FIXTURE_SHA, 'section': dict(SECTION),
             'digests': {USER: showcase_digest({n: r['sha256'] for n, r in inputs.provenance['user_files'].items()})}}
    args.case, args.product_source, args.retained_upload_receipt = PHASE, FROZEN, None
    args.s5b_variant = Variant(inputs, product_engine)
    marker = LAB / 'run/focus-nextcloud-r6-s5b-leases'
    marker.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(marker / (lease_sha + '.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)  # one attempt
    with os.fdopen(fd, 'w') as f:
        json.dump({'source_commit': commit, 'private_receipt_dir': str(ev.path)}, f); f.flush(); os.fsync(f.fileno())
    rc, failure = 1, None
    try:
        rc = case.run(args, lease, commit, facts, sys.modules[__name__], binding=BINDING)
    except Exception as error:   # noqa: BLE001 - a refusal before or a failure after; the record says which
        failure = 'fixed-s5b-cold-to-cold-' + type(error).__name__
    engine_back = clean = removed = evidence_clean = False
    delta = removal = leak = None
    try:
        engine_back = wake.device(s5.ENGINE_PROGRAM, root=True) == prior_engine
        store_after = wake.device(s5.TARGET_STATE, root=True)
        ev.save('store-after.json', store_after)
        receipt = json.loads(RECEIPT.read_text()) if RECEIPT.exists() else {'pending': True}
        clean, delta = owned_store_clean(store_before, store_after, receipt)
        leak = scan_evidence([LAB / 'evidence' / area for area in (AREA, AREA + '-control', AREA + '-run')],
                             [inputs.password, *inputs.config.values(), *inputs.private_keys.values()])
        evidence_clean = leak['hits'] == 0 and leak['files'] > 0
        if rc == 0 and engine_back and clean and evidence_clean and receipt.get('pending') is False:
            removal = wake.device(PROGRAMS['remove'], {'root': lease['proof_root'], 'removal': REMOVAL}, root=True,
                                  timeout=900)
            removed = removal.get('status') == 'removed'
    except Exception as error:   # noqa: BLE001
        failure = failure or 'fixed-s5b-end-check-' + type(error).__name__
    passed = rc == 0 and engine_back and clean and evidence_clean and removed
    record = {'status': 'passed' if passed else 'failed', 'phase': PHASE, 'source_commit': commit,
              'product_commit': PRODUCT_COMMIT, 'fix_commit': FIX_COMMIT, 's5a_result_sha256': S5A.result_sha256,
              's5a_source_commit': S5A.source_commit,
              'prior_engine_manifest_sha256': s5.manifest_hash(prior_engine), 'fixture_sha256': FIXTURE_SHA, 'fixture_bytes': FIXTURE_BYTES, 'ha_key_needed': False,
              'host_fixture_copy': False, 'case_rc': rc, 'prior_engine_returned_exactly': engine_back,
              'owned_store_clean': clean, 'store_delta': delta, 'evidence_leak_scan': leak, 'proof_root': PROOF_ROOT,
              'proof_root_removed': removed, 'proof_root_removal': removal, 'fixed_failure': failure,
              'pulls': 0, 'private_receipt_dir': str(ev.path),
              'case_evidence': [str(max((LAB / 'evidence' / area).glob('*'), default='')) for area in (AREA + '-control', AREA)]}
    ev.save('fixed-result.json', record)
    print(json.dumps({k: record[k] for k in ('status', 'phase', 'case_rc', 'prior_engine_returned_exactly',
                                             'owned_store_clean', 'proof_root_removed', 'fixed_failure')}))
    return 0 if passed else 1


def contract():
    return {'phase': PHASE, 'code_only_until_leased': True, 'product_commit': PRODUCT_COMMIT, 'product_checkout': str(FROZEN),
            'fix_commit': FIX_COMMIT, 'prior_engine': 'captured at run time (source transaction), returned exactly',
            's5a_result': in_repo(S5A_RESULT), 's5a_bound': S5A is not None, 's5a_binding_error': S5A_ERROR,
            'fixture_shape': dict(s5.FIXTURE_SHAPE), 'fixture': FIXTURE,
            'fixture_sha256': FIXTURE_SHA, 'fixture_bytes': FIXTURE_BYTES, 'ha_key_needed': False,
            'confirmation': {'id': SSE_ID, 'reasons': list(SSE_REASONS), 'key': SSE_KEY},
            'reserve_bytes': RESERVE, 'device_memory_cap_bytes': DEVICE_CAP, 'lease_headroom_seconds': HEADROOM,
            'proof_root_removal': REMOVAL, 'mutations': 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true'); parser.add_argument('--lease', type=Path)
    parser.add_argument('--lease-template', action='store_true')
    args = parser.parse_args(argv)
    if args.lease_template:
        print(json.dumps(lease_template(REPO), indent=2, sort_keys=True)); return 0
    if not args.run:
        print(json.dumps(contract(), indent=2, sort_keys=True)); return 0
    require(args.lease is not None, 'lease-required')
    commit, clean = s5.checkout(REPO)
    require(clean, 'clean-checkout')
    lease = json.loads(args.lease.read_text())
    _paths, rows = frozen_manifest(FROZEN)
    deadline = admit_lease(lease, commit, REPO, rows)
    require(os.environ.get('HEAVY_FREE') == LOCK, 'heavy-seat-required')
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)   # blocking: heavy.sh only waited for the lock to be free
        locked_admission(lease, commit, deadline)
        return run_case(args, lease, commit, deadline)


# The active binding, as committed: format and values only here (no git at import); the lease template and the admission
# check it again in full (s5a_binding with verify_git) before anything runs.
try:
    bind(s5a_binding(verify_git=False))
except FileNotFoundError:
    bind(None)
except (ValueError, KeyError, TypeError, OSError) as _error:
    bind(None, str(_error) if str(_error).startswith('fixed-') else 'fixed-s5b-s5a-rebuild-result-unreadable')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        # Everything after the first mutation is caught and recorded inside run_case; what lands here refused before.
        print('fixed-s5b-preflight-refused-no-mutation: '
              + (str(error) if str(error).startswith('fixed-') else type(error).__name__), file=sys.stderr)
        sys.exit(2)
