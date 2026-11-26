#!/usr/bin/env python3
"""EMQX: the real batch-1 HA backups -> dev-d's EMQX through the installed product helper (lane emqx-product).

  python3 -I tests/e2e/lab/emqx_product_real_capture.py <evidence.json> <scope> -- \\
      python3 -I tests/e2e/lab/emqx_product_real_ha.py <step> [<step> ...]
  python3 -I tests/e2e/lab/emqx_product_real_ha.py --self-check       (offline; never touches a device or a secret)

The owner decided on 2026-11-23 ("決定1 做") that the HA EMQX import becomes a real product import. This harness
drives it exactly as the Cockpit page does: every engine call is the helper command the page sends (root inside
dev-d, one JSON request on stdin, one JSON reply): status, list, inspect, catalog-install, key-init, backup-start,
ha-check-start, ha-convert-start, restore-start, job-status, delete. The HA files are the ones already in dev-d's HA
store, bound to the local fixtures by SHA-256 (the cold encrypted backups of add-on 1b7b4ce7_woow-emqx, made with
EMQX stopped: arm = the real RPi5, x86 = the real x86 HA).

Every step runs inside ONE hold of the dev-d mutation lock (/tmp/woowbk-dev-d-mutation.lock, waited for like
`flock -w 3600`; never taken while /tmp/woowbk-dev-d-emqx-main-waiting is fresh), with dev-d's outer isolation
asserted before and after (owner.sh d --verify-isolation: running, network none, no published port) and a
memory/disk headroom check before each step. No new step starts after HOLD_BUDGET seconds of holding the lock (only the
short closing steps still do), nor when the hold so far plus the step's estimate (ESTIMATE) would pass HOLD_LIMIT (40 min).

Steps (run in the order given):
  setup        deploy THIS tree into dev-d (deploy-src.sh d --src <tree> --no-demo-catalog; the schedule timer is
               masked first); EMQX's catalog entry is the one carried by dev-d's own EMQX baseline backup (inspect
               with the 11-19 emergency kit, catalog-install of exactly that entry) when it is missing; a device key
  before       dev-d's EMQX as it is: the probe as this device's admin (state digest, markers); the test's own
               baseline backup B0 (backup-start emqx, the device key) is made once and reused
  check        ha-check-start (emqx) on arm-cold and x86-cold against dev-d's own target (the ACL file only): the
               check REFUSES with the owner's text (OWNER DECISION 2026-11-23 「C」: HA's backups carry ACL rows),
               HA's facts equal the recorded source, nothing changed
  check-hot    ha-check-start (emqx) on arm-enc and x86-enc (made while EMQX ran): the hot backup is named
  import:TAG:file
               decision C on dev-d's own target (the ACL file only): ha-check refuses with the owner's text (one
               blocker), ha-convert (the real space check) is refused with the same text before any candidate, no
               backup and no throwaway object is left, dev-d's EMQX state digest still equals `before`
  import:TAG:builtin
               TAG = arm-cold | x86-cold; the built-in database authorization source is added to dev-d's EMQX through
               its REST API first (after the file ACL: what the owner's text tells the customer to do in the
               Dashboard; the import itself never adds a source). Then: ha-check (ok), ha-convert (the real space check), inspect,
               restore (its readback must pass), the client probe after the restore, `systemctl --user restart
               emqx.service` and the probe again; the imported state is recorded for:
               Before that restore the FIRST import attempt is made to fail twice from this device's own state (arm-cold,
               x86-cold and x86-fileonly; asked for on 2026-11-24): a one-shot start failure, then a one-shot change of the
               restored data that the readback must name; this older first-import case expects rollback in both rounds
               (the current D0/E-90 wrapper skips it; its start-failure round runs in rollback:TAG instead)
  import:x86-fileonly:file | import:x86-noacl:file
               decision C's other half, the usual customer case: a backup WITHOUT ACL rows on dev-d's own target (the
               ACL file only, nothing added) is imported: the same chain as builtin (check ok, real conversion,
               restore + readback, probe, restart, probe) with this device's file ACL governing. The input is LAB-MADE
               (emqx_noacl_fixture.py: the real x86 cold backup with EMQX's ACL table cleared by EMQX itself;
               x86-fileonly: HA's built-in source removed too, as the add-on is installed; x86-noacl: HA keeps it),
               uploaded through the page's upload-begin/-finish and deleted again by cleanup (ha-delete)
  rollback:TAG the rollback rounds in their own lock hold, from the recorded imported state (proven again first): an
               AUTOMATIC rollback (a one-shot ExecStartPre failure of emqx.service armed right before a second
               restore of the same converted backup: the restore must fail and roll back by itself; the probe
               again), the READBACK reminder (a one-shot ExecStartPre appends one HOCON line to the restored
               cluster.hocon: the restore's readback must name 設定（log） and keep the restored data; the probe again),
               and the MANUAL rollback to the baseline (restore of B0: the state digest equals `before`, the
               markers are back)
  suggest-health
               the catalog entry a customer installs from the page's own draft (needs the suggest.py fix after a3a0479,
               whose own real run attempt-30 failed: the Dashboard page answers the engine's check 406): dev-d's EMQX
               entry is removed, a fresh catalog-suggest draft must ask the broker's public API through the entrance (not
               the container-only /readyz, 403 from the device), it is installed, EMQX is backed up and that backup restored
               with the proposed health check (must succeed, not roll back), then dev-d's own entry is installed again
               (same SHA-256) and the EMQX state digest equals the one before
  catalog-draft / catalog-own
               the steps between the two run with the page's own fresh draft as the installed EMQX entry, unedited (its health
               check and its data digests included, as on a customer's device); catalog-own installs dev-d's own entry again
               (same SHA-256). A draft left behind by a stopped run is put back by cleanup
  cleanup      the test's converted and safety backups deleted (B0 stays until `cleanup-baseline`); no job
               container/volume/network, staging or key file; no drop-in or marker left
  cleanup-baseline
               B0 deleted too
  reclaim      lab-only headroom for the next steps (no headroom check before it): dev-d's archived journal files older
               than 24 h leave its tmpfs journal and clean page cache is returned to the host (dev-d's own
               memory.reclaim, swappiness 0, bounded); counters before/after printed, no service, unit, configuration
               or container change, the OOM events must not move. This run's own journal (younger than 24 h) stays
  leaks        no test secret (HA key, b1 test passwords, dev-d's EMQX secrets, issued Dashboard tokens) in the
               engine's records, logs, journal or this run's private evidence (the issued tokens are those of this
               very run: put it after the probes of the same run)

The client probe (inside dev-d, as appowner, through the b1 credential-event transport: every Dashboard login it makes
is registered before it is acknowledged) checks with HA's credentials: Dashboard logins, MQTT logins of HA's three
users, wrong password / anonymous / banned client refused, this device's bootstrap user still logs in, the 2 retained
messages (MQTT payload == stored payload), the authorization sources and settings are THIS device's (the file ACL
read back byte-equal to this device's acl.conf), HA's ACL rows active through the API (builtin: since decision C the
file target is refused, never imported), allowed and denied MQTT operations, rule delivery (HA's republish
rule delivers to a subscriber; HA's HTTP action executes: its rule and action counters move), HA's API key works.
stdout carries only fixed status lines (STEP/CHECK/RESULT ...); details go to the private, redacted evidence folder
~/.woowbk-lab/evidence/emqx-product/<time>/ (0700). Secrets are read only by the b1 harness reader and the kit file.
Not covered (stated in the evidence): the browser page itself (dev-d publishes no port; the helper calls are the
page's), production, MQTT devices outside dev-d.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
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
HOLD_BUDGET = 32 * 60          # no new step after this many seconds of holding the lock (< 40 min per hold)
MIN_DEVICE_HEADROOM = 1536 * 1024 * 1024
MIN_HOST_AVAILABLE_KIB = 1024 * 1024
MIN_DISK_FREE = 13 * 1024 ** 3  # the team keeps >= 12 GiB free at every moment
BASELINE = '20261119T072831Z-168aaa02'   # dev-d's own EMQX baseline backup (11-19 device key): carries the entry
OLD_KIT = LAB / 'secrets' / 'dev-d-kit.txt'
TIMER = 'woowtech-cockpit-backup-schedule.timer'
TAGS = ('arm-cold', 'x86-cold')
MODES = ('file', 'builtin')
STORE_IDS = {'arm-cold': 'ha-b6eb257cc5790bee3050', 'x86-cold': 'ha-0a53e93888209316040a'}
FIXTURE_SHA256 = {'arm-cold': 'b6eb257cc5790bee30500f929d51ade66bfa8354dbe5bb61ba7c4bc08582f664',
                  'x86-cold': '0a53e93888209316040af505484bba3ee3891c2ad2df7ae689bc0d4fd02690f9'}
# LAB-MADE (emqx_noacl_fixture.py): the real x86 cold backup whose emqx_acl table EMQX 5.8.9 itself cleared; unencrypted.
# x86-fileonly: EMQX also removed HA's built-in database source (HA authorizes with its ACL file only, as installed).
LAB_FOLDER = LAB / 'ha-fixtures' / '20261124-emqx-noacl-lab'
LAB_MADE = {'x86-fileonly': 'woow-b1-x86-emqx-stopped-fileonly', 'x86-noacl': 'woow-b1-x86-emqx-stopped-noacl',
            'x86-bcrypt': 'woow-b1-x86-emqx-stopped-bcrypt', 'x86-plain': 'woow-b1-x86-emqx-stopped-plain'}
LAB_SHA256 = {'x86-fileonly': '503f9b1bba23bd2a93454f8aaf9218b936d5c4d76edbc99103113c85b719faf4', 'x86-noacl': '59f3062cce8734babf67035552ed088ec0200f986b9aa5096a22ce3a8f0845cf',
              'x86-bcrypt': '1b76fc196be173652576077a59a8c5f4d4d9f08d0ed6f76b9a595a6d38c5abd9',
              'x86-plain': '9643c8716c1e2dbe08f8418d3114645839f6839314924d093c2e9526cd0cf200'}
# SR-5 (OWNER DECISION 2026-11-24, option C; lane emqx-sr5): the x86-fileonly variant whose HA built-in password database
# EMQX itself switched to bcrypt (HA's three users got their b1 passwords again) or to plain (emqx_noacl_fixture.py
# fileonly hash=...). Step sr5:TAG: bcrypt = the check warns and names this device's own MQTT accounts, the import goes
# on, exactly those accounts are refused afterwards while HA's log in, the warning's own remedy for a bootstrap account
# works, then B0 comes back; plain = the check refuses, the conversion too, and nothing on dev-d changes.
SR5 = {'x86-bcrypt': 'bcrypt', 'x86-plain': 'plain'}
ACL_ROWS = {'arm-cold': 4, 'x86-cold': 4, **{tag: 0 for tag in LAB_MADE}}
EMQX_SECRETS = ['woow-emqx-dashboard-password', 'woow-emqx-mqtt-password', 'woow-emqx-node-cookie',
                'woow-emqx-mqtt-bootstrap']
LANE_SECRETS = ('HA_BACKUP_KEY', 'B1_EMQX_ADMIN_PW', 'B1_EMQX_USER2_PW', 'B1_MQTT_PW1', 'B1_MQTT_PW2', 'B1_MQTT_PW3',
                'B1_ARM_EMQX_API_KEY', 'B1_ARM_EMQX_API_SECRET', 'B1_X86_EMQX_API_KEY', 'B1_X86_EMQX_API_SECRET')
UNIT = 'emqx.service'
DROPDIR = '.config/systemd/user/emqx.service.d'
DROPIN = DROPDIR + '/woowbk-emqx-product-fail-once.conf'
MARKER = '.config/emqx-woowbk-fail-once'
# The one-shot start failure also records, at the moment the unit fails, whether the data volume holds HA's data (HA's
# rule in the restored cluster.hocon): a restore that changed nothing could otherwise look like one that rolled back.
FAIL_SCRIPT = '.config/emqx-woowbk-fail.sh'
FAIL_SEEN = '.config/emqx-woowbk-fail-seen'
FAIL_ONCE = (b'#!/bin/sh\n'
             b'm="$HOME/.config/emqx-woowbk-fail-once"\n'
             b'[ -f "$m" ] || exit 0\n'
             b'rm -f "$m"\n'
             b'd=$(podman volume inspect woow_emqx_data --format "{{.Mountpoint}}")\n'
             b'podman unshare grep -c b1_rule_republish "$d/configs/cluster.hocon" '
             b'> "$HOME/.config/emqx-woowbk-fail-seen" 2>/dev/null\n'
             b'exit 1\n')
FAIL_FILES = (DROPIN, FAIL_SCRIPT, MARKER, FAIL_SEEN)
# The readback under test: a one-shot ExecStartPre that changes the RESTORED data right before the broker starts (one
# HOCON line appended to the restored configs/cluster.hocon), so the restored broker no longer equals what the
# conversion verified; E-90 says the restore names the changed root in a reminder. Not log.console.level: dev-d's EnvironmentFile
# sets EMQX_LOG__CONSOLE__LEVEL and environment overrides win over cluster.hocon (emqx_config.erl:365-366, 455-461).
TAMPER_DROPIN = DROPDIR + '/woowbk-emqx-product-tamper-once.conf'
TAMPER_SCRIPT = '.config/emqx-woowbk-tamper.sh'
TAMPER_MARKER = '.config/emqx-woowbk-tamper-once'
TAMPER = (b'#!/bin/sh\n'
          b'm="$HOME/.config/emqx-woowbk-tamper-once"\n'
          b'[ -f "$m" ] || exit 0\n'
          b'rm -f "$m"\n'
          b'd=$(podman volume inspect woow_emqx_data --format "{{.Mountpoint}}") || exit 0\n'
          b'podman unshare sh -c "printf \'\\nlog.console.formatter = json\\n\' >> \'$d/configs/cluster.hocon\'"\n'
          b'exit 0\n')
TAMPER_FILES = (TAMPER_DROPIN, TAMPER_SCRIPT, TAMPER_MARKER)
READBACK_LOG = 'EMQX 還原後核對一致'
# Only the tampered root may differ: every other configuration root and every table of the running broker equals what the
# conversion verified, i.e. HA's data really ran (compare_readback names each differing root and table).
READBACK_DIFF = 'EMQX 還原後的設定（log）和轉換時核對的不同'
# The imports whose FIRST attempt is made to fail from this device's own state (the third lab-made variant repeats the
# second one's target).
FIRST_ROUNDS = ('arm-cold', 'x86-cold', 'x86-fileonly')
# OWNER DECISION 2026-11-23 「C」, the owner's text verbatim (independent of the product constant on purpose).
OWNER_ACL_TEXT = ('Podman 上的 EMQX 沒有開啟『內建資料庫』權限，HA 的裝置權限搬過去不會生效，裝置會被拒絕。'
                  '請先在 Podman EMQX 的管理頁「存取控制 → 授權」新增「內建資料庫」（排在檔案規則之後），再匯入。')
# SR-5 (OWNER DECISION 2026-11-24, option C), the engine's texts verbatim (independent of the product constants on purpose).
SR5_PLAIN = ('HA 的 EMQX 用「plain」（不加密）的方式保存 MQTT 帳號的密碼，搬過來會把明文密碼留在這台，所以不能匯入。'
             '請先在 HA 的 EMQX 管理頁「存取控制 → 認證」把內建資料庫的密碼雜湊方式（password_hash_algorithm）改成 plain '
             '以外的方式（例如 sha256 並加鹽，或 bcrypt），再替每個 MQTT 帳號重新設定一次密碼（EMQX 不會轉換已經存好的密碼，'
             '沒有重設的帳號在改完後就無法登入），然後重新製作 HA 備份再匯入。')
SR5_RESET = ('到這台 EMQX 管理頁「存取控制 → 認證」的內建資料庫替這些帳號重設密碼或重新建立；由這台 bootstrap 帳號檔建立的帳號，'
             '刪除後重新啟動 EMQX 就會用原本的密碼建回。')
SR5_WARNING = ('HA 的 EMQX 保存 MQTT 密碼的方式（{ha}）和這台（{mine}）不同，匯入後以 HA 的為準：這台現有的 MQTT 帳號'
               '（{names}）匯入後無法再用原本的密碼登入，要在匯入後重新設定：' + SR5_RESET)
SR5_NOTE = ('HA 的 EMQX 保存 MQTT 密碼的方式（{ha}）和這台（{mine}）不同，匯入後以 HA 的為準：'
            '這台原本的 MQTT 帳號（{names}）無法再用原本的密碼登入。')
SR5_REMINDER = '請重新設定這台原本的 MQTT 帳號（{names}）：' + SR5_RESET
# dev-d's EMQX hashes like the product package's base.hocon (Woow_podman_emqx: sha256, salt suffix).
SR5_DEVICE_HASHING = 'sha256，鹽在後'
# dev-d's own built-in database accounts (attempt-sr5-01 read them from its API): the bootstrap user woow (its password
# is read inside dev-d from its podman secret) and the batch1 baseline marker user, created through the API by
# batch1_markers.py (its password: the harness secret DEV_D_MARKER_EMQX). Every account the check names must be one of
# these, so that each can be logged in and shown to fail after the import.
SR5_OWN = {'woow': None, 'woowbk-lab-baseline': 'DEV_D_MARKER_EMQX'}
SAFE_LABEL = re.compile(r"[^A-Za-z0-9 ,()/:'<>.=_+#-]")
OWNER_UID = 1019


def _load_driver():
    spec = importlib.util.spec_from_file_location('ha_import_b1_e2e', HERE / 'ha_import_b1_e2e.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drv = _load_driver()
Failed = drv.Failed
drv.state_path = lambda: LAB / 'run' / 'emqx_product_real_ha.json'   # never the b1 driver's own state file
for _tag in LAB_MADE:
    drv.UPLOADS[_tag] = ('x86', 'lab-made, see LAB_MADE', False, ('emqx',), False)
    STORE_IDS[_tag] = 'ha-' + LAB_SHA256[_tag][:20]


def label(text):
    return SAFE_LABEL.sub('_', str(text))[:200] or 'unnamed'


def slug(text):
    return re.sub(r'[^A-Za-z0-9_.-]+', '-', str(text)).strip('-')[:120] or 'unnamed'


def emit(line):
    print(line, flush=True)


class Evidence(drv.Evidence):
    """The b1 driver's redacted evidence folder; stdout gets only `CHECK <label>: PASS|FAIL` (no detail)."""

    def __init__(self, secrets):
        super().__init__(secrets, 'emqx-product')

    def log(self, text):
        line = f'{time.strftime("%H:%M:%S")} {self.secrets.redact(str(text))}'
        with open(self.log_path, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')

    def check(self, name, ok, detail=''):
        result = super().check(name, ok, detail)
        emit(f'CHECK {label(self.secrets.redact(str(name)))}: {"PASS" if result else "FAIL"}')
        return result


# ---------------------------------------------------------------- the device-side probe (as appowner in dev-d)

MQTT = r'''
import socket, struct
def _str(s):
    b = s.encode() if isinstance(s, str) else s
    return struct.pack("!H", len(b)) + b
def _len(n):
    o = bytearray()
    while True:
        d = n % 128
        n //= 128
        o.append(d | (0x80 if n else 0))
        if not n:
            return bytes(o)
def _recv(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf
def read_packet(s):
    h = _recv(s, 1)[0]
    mult, n = 1, 0
    while True:
        b = _recv(s, 1)[0]
        n += (b & 0x7F) * mult
        mult *= 128
        if not b & 0x80:
            break
    return h >> 4, h & 0x0F, _recv(s, n)
def connect(client_id, user=None, password=None):
    """MQTT 3.1.1 -> (socket or None, CONNACK return code or an error word)"""
    try:
        s = socket.create_connection(("127.0.0.1", 1883), timeout=10)
    except OSError as e:
        return None, "connect:" + type(e).__name__
    flags = 0x02
    payload = _str(client_id)
    if user is not None:
        flags |= 0x80
        payload += _str(user)
    if password is not None:
        flags |= 0x40
        payload += _str(password)
    body = _str("MQTT") + bytes([4, flags]) + struct.pack("!H", 60) + payload
    try:
        s.sendall(bytes([0x10]) + _len(len(body)) + body)
        t, f, data = read_packet(s)
    except (EOFError, OSError) as e:
        s.close()
        return None, "closed:" + type(e).__name__
    if t != 2:
        s.close()
        return None, "type%d" % t
    if data[1] != 0:
        s.close()
        return None, data[1]
    return s, 0
def drain(s, wait, got, stop=None):
    """Collect PUBLISH packets (topic, retain flag, payload sha256, payload) for `wait` s."""
    deadline = time.monotonic() + wait
    other = []
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return other
        s.settimeout(left)
        try:
            t, f, data = read_packet(s)
        except (socket.timeout, EOFError, OSError):
            return other
        if t == 3:
            tl = struct.unpack("!H", data[:2])[0]
            top = data[2:2 + tl].decode("utf-8", "replace")
            q = (f >> 1) & 3
            pos = 2 + tl
            if q:
                pid = data[pos:pos + 2]
                pos += 2
                try:
                    s.sendall(bytes([0x40, 2]) + pid)
                except OSError:
                    pass
            payload = data[pos:]
            got.append((top, f & 1, hashlib.sha256(payload).hexdigest(), payload))
            if stop is not None and stop(got):
                return other
        else:
            other.append((t, data))
def subscribe(s, topic, qos=1, wait=3.0):
    """-> (SUBACK code, [(topic, retain, sha256, payload)] received within `wait` s)"""
    body = struct.pack("!H", 7) + _str(topic) + bytes([qos])
    code, got = None, []
    try:
        s.sendall(bytes([0x82]) + _len(len(body)) + body)
        s.settimeout(10)
        while code is None:
            t, f, data = read_packet(s)
            if t == 9:
                code = data[2]
            elif t == 3:
                tl = struct.unpack("!H", data[:2])[0]
                top = data[2:2 + tl].decode("utf-8", "replace")
                q = (f >> 1) & 3
                pos = 2 + tl
                if q:
                    pid = data[pos:pos + 2]
                    pos += 2
                    s.sendall(bytes([0x40, 2]) + pid)
                got.append((top, f & 1, hashlib.sha256(data[pos:]).hexdigest(), data[pos:]))
    except (socket.timeout, EOFError, OSError):
        return None, got
    drain(s, wait, got)
    return code, got
def publish(s, topic, payload, pid=11):
    """QoS 1 publish -> True when the PUBACK of `pid` came back (MQTT 3.1.1 PUBACK has no reason code)."""
    body = _str(topic) + struct.pack("!H", pid) + payload
    try:
        s.sendall(bytes([0x32]) + _len(len(body)) + body)
        s.settimeout(10)
        while True:
            t, f, data = read_packet(s)
            if t == 4 and data[:2] == struct.pack("!H", pid):
                return True
    except (socket.timeout, EOFError, OSError):
        return False
def close(s):
    try:
        s.sendall(b"\xe0\x00")
        s.close()
    except OSError:
        pass
'''

PROBE = drv.PROBE_COMMON + MQTT + r'''
import base64, urllib.parse, secrets as _rnd
out = {"mode": REQ["mode"]}
E = "http://127.0.0.1:18083"
started = time.monotonic()
# The Dashboard answers some seconds after EMQX starts: wait with an unauthenticated GET (401 = up). A login is never
# retried (the credential-event transport counts every login), so it comes only once the API answers.
ready, _ = call(E, "GET", "/api/v5/nodes", wait=240)
while ready != 401 and time.monotonic() - started < 240:   # a starting Dashboard answers 404 before its routes exist
    time.sleep(2)                                          # (attempt-05: a login right after a restore got 404)
    ready, _ = call(E, "GET", "/api/v5/nodes", wait=30)
out["api_ready_after_s"] = round(time.monotonic() - started, 1)
out["api_ready_code"] = ready
# Exactly three Dashboard logins, always in this order (the event transport registers each issued token). The
# entrance rate-limits /api/v5/login (10/min, burst 5): 7 s between them never touches the limit.
code_ha, body_ha = call(E, "POST", "/api/v5/login", {"username": "admin", "password": REQ["ha_admin_password"]})
time.sleep(7)
code_u2, body_u2 = call(E, "POST", "/api/v5/login", {"username": REQ["user2"], "password": REQ["user2_password"]})
time.sleep(7)
code_dev, body_dev = call(E, "POST", "/api/v5/login", {"username": "admin", "password": secret("woow-emqx-dashboard-password")})
out["login"] = {"ha_admin": code_ha, "ha_user2": code_u2, "device_admin": code_dev}
token = None
if code_ha == 200:
    token = (body_ha or {}).get("token")
elif code_dev == 200:
    token = (body_dev or {}).get("token")
out["token_from"] = "ha_admin" if code_ha == 200 else ("device_admin" if code_dev == 200 else None)
def get(path, wait=0):
    return call(E, "GET", path, token=token, wait=wait)
if token and REQ.get("authz_add"):
    c, b = call(E, "POST", "/api/v5/authorization/sources", {"type": "built_in_database", "enable": True}, token=token)
    out["authz_add"] = c
    # EMQX 5.8.9 PREPENDS a created source (emqx_authz_api_sources.erl:258-259, ?CMD_PREPEND); the owner's text says
    # 「排在檔案規則之後」: move it after the file source (same file :71 /move, :315, :587-600 position "after:file").
    c, b = call(E, "POST", "/api/v5/authorization/sources/built_in_database/move", {"position": "after:file"},
                token=token)
    out["authz_move"] = c
if token and REQ.get("delete_mqtt_user"):
    c, _ = call(E, "DELETE", "/api/v5/authentication/password_based:built_in_database/users/"
                + urllib.parse.quote(REQ["delete_mqtt_user"], safe=""), token=token)
    out["delete_mqtt_user"] = c
if token and REQ.get("create_mqtt_user"):
    c, _ = call(E, "POST", "/api/v5/authentication/password_based:built_in_database/users",
                {"user_id": REQ["create_mqtt_user"][0], "password": REQ["create_mqtt_user"][1], "is_superuser": False},
                token=token)
    out["create_mqtt_user"] = c
if token:
    c, body = get("/api/v5/authentication/password_based:built_in_database/users?limit=1000", wait=120)
    out["mqtt_users"] = sorted([u.get("user_id"), u.get("is_superuser")] for u in items(body))
    c, body = get("/api/v5/authentication")
    out["authenticators"] = sorted([a.get("id"), a.get("enable")] for a in items(body))
    c, body = get("/api/v5/authorization/settings")
    out["authz_settings"] = {k: (body or {}).get(k) for k in ("no_match", "deny_action")}
    c, body = get("/api/v5/authorization/sources")
    sources = items(body, "sources")
    out["authz_sources"] = [[x.get("type"), x.get("enable")] for x in sources]
    with open(os.path.expanduser("~/.config/emqx/acl.conf"), "rb") as handle:
        acl_file = handle.read()
    files = [x for x in sources if x.get("type") == "file"]
    out["file_acl_readback_equal"] = (len(files) == 1 and isinstance(files[0].get("rules"), str)
                                     and files[0]["rules"].encode() == acl_file)
    acl = {}
    for kind, path in (("users", "/api/v5/authorization/sources/built_in_database/rules/users?limit=1000"),
                       ("clients", "/api/v5/authorization/sources/built_in_database/rules/clients?limit=1000")):
        c, body = get(path)
        acl[kind] = [c, sorted([r.get("username") or r.get("clientid"), len(r.get("rules") or [])] for r in items(body))]
    c, body = get("/api/v5/authorization/sources/built_in_database/rules/all")
    acl["all"] = [c, len((body or {}).get("rules") or [])]
    out["acl_api"] = acl
    c, body = get("/api/v5/mqtt/retainer/messages?limit=1000")
    stored = {}
    for m in items(body):
        topic = m.get("topic")
        c2, one = get("/api/v5/mqtt/retainer/message/" + urllib.parse.quote(topic, safe=""))
        payload = base64.b64decode((one or {}).get("payload") or "") if c2 == 200 else None
        stored[topic] = hashlib.sha256(payload).hexdigest() if payload is not None else None
    out["retained_api"] = stored
    c, body = get("/api/v5/rules?limit=1000")
    out["rules"] = sorted([r.get("id"), r.get("enable")] for r in items(body))
    c, body = get("/api/v5/connectors")
    out["connectors"] = sorted([x.get("type"), x.get("name"), x.get("status")] for x in items(body))
    c, body = get("/api/v5/actions")
    out["actions"] = sorted([x.get("type"), x.get("name"), x.get("status")] for x in items(body))
    c, body = get("/api/v5/banned?limit=1000")
    out["banned"] = sorted([b.get("as"), b.get("who")] for b in items(body))
    c, body = get("/api/v5/users")
    out["dashboard_users"] = sorted(u.get("username") for u in items(body))
    c, body = get("/api/v5/api_key")
    out["api_keys"] = sorted([k.get("name"), k.get("enable")] for k in items(body))
    c, body = get("/api/v5/nodes")
    out["nodes"] = [[n.get("node"), n.get("version"), n.get("node_status")] for n in items(body)]
if REQ.get("api_key"):
    c, _ = call(E, "GET", "/api/v5/nodes", basic=(REQ["api_key"], REQ["api_secret"]))
    out["api_key_works"] = c
COUNT = ("[{T, case catch mnesia:table_info(T, size) of N when is_integer(N) -> N; _ -> -1 end} || T <- ["
         "emqx_authn_mnesia, emqx_authn_scram_mnesia, emqx_acl, emqx_banned, emqx_banned_rules, emqx_admin, "
         "emqx_app, emqx_psk, emqx_retainer_message]].")
rc, so, se = pexec("woow-emqx", "emqx", "eval", COUNT)
counts = {}
for name, number in __import__("re").findall(r"\{([a-z_]+),\s*(-?[0-9]+)\}", so or ""):
    counts[name] = int(number)
out["native_counts"] = counts
CFG = 'io:format("WOOWCFG:~s:END~n", [base64:encode(emqx_utils_json:encode(emqx:get_raw_config([])))]).'
rc, so, se = pexec("woow-emqx", "emqx", "eval", CFG)
raw = (so or "").strip()
try:
    # canonical JSON (key order never matters), the same reader the product uses
    doc = json.loads(base64.b64decode(raw[len("WOOWCFG:"):raw.index(":END")]))
    out["config_sha256"] = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    out["config_roots"] = len(doc)
except (ValueError, TypeError):
    out["config_sha256"] = None
if REQ.get("own_mqtt"):
    own = {}
    for user, password in REQ["own_mqtt"]:
        s, rc = connect("woowbk-own-" + user, user, password)
        own["ha_" + user] = rc
        if s:
            close(s)
    s, rc = connect("woowbk-own-bootstrap", "woow", secret("woow-emqx-mqtt-password"))
    own["bootstrap_woow"] = rc
    if s:
        close(s)
    out["own_mqtt"] = own
if REQ.get("logins"):
    found = {}
    for user, password in REQ["logins"]:
        s, rc = connect("woowbk-login-" + user, user, password)
        found[user] = rc
        if s:
            close(s)
    out["logins"] = found
if REQ.get("mqtt"):
    users = REQ["mqtt"]
    mq = {}
    for user, password in users:
        s, rc = connect("b1lab-login-" + user, user, password)
        mq["login_" + user] = rc
        if s:
            close(s)
    sensor, gateway, admin = users[0], users[1], users[2]
    s, rc = connect("b1lab-wrong", gateway[0], "wrong-password-for-the-test")
    mq["wrong_password"] = rc
    if s:
        close(s)
    s, rc = connect("b1lab-anonymous")
    mq["anonymous"] = rc
    if s:
        close(s)
    s, rc = connect("b1-banned-client", gateway[0], gateway[1])
    mq["banned_client"] = rc
    if s:
        close(s)
    s, rc = connect("b1lab-bootstrap", "woow", secret("woow-emqx-mqtt-password"))
    mq["bootstrap_woow"] = rc
    if s:
        close(s)
    def sub_once(client, cred, topic, wait=3.0):
        s, rc = connect(client, cred[0], cred[1])
        if not s:
            return {"connack": rc}
        code, got = subscribe(s, topic, wait=wait)
        close(s)
        return {"connack": rc, "suback": code, "retained": sorted([t, h] for t, r, h, p in got if r)}
    mq["admin_retained"] = sub_once("b1lab-admin-retained", admin, "b1/retained/#")
    mq["gateway_retained"] = sub_once("b1lab-gateway-retained", gateway, "b1/retained/#")
    mq["sensor_secret"] = sub_once("b1lab-sensor-secret", sensor, "b1/secret/#", wait=1.0)
    mq["sensor_retained"] = sub_once("b1lab-sensor-retained", sensor, "b1/retained/#", wait=1.0)
    # This device's file rule: every user may use "<username>/#" (pub/sub round trip, the same user).
    own = gateway[0] + "/woowbk-probe/" + _rnd.token_hex(4)
    s1, rc1 = connect("b1lab-own-sub", gateway[0], gateway[1])
    s2, rc2 = connect("b1lab-own-pub", gateway[0], gateway[1])
    own_result = {"connack": [rc1, rc2]}
    if s1 and s2:
        code, got = subscribe(s1, own, wait=0.5)
        own_result["suback"] = code
        own_result["puback"] = publish(s2, own.encode(), b"woowbk-own-topic")
        drain(s1, 3.0, got, stop=lambda g: len(g) >= 1)
        own_result["received"] = len([1 for t, r, h, p in got if t == own and p == b"woowbk-own-topic"])
    for x in (s1, s2):
        if x:
            close(x)
    mq["own_topic"] = own_result
    out["mqtt"] = mq
    # Rule delivery: HA's republish rule (b1/sensor/# with payload.temp > 30 -> b1/alerts/${clientid}) and HA's HTTP
    # action rule (b1/cmd/#). Builtin mode uses HA's own roles (sensor publishes, gateway subscribes); file mode uses
    # HA's superuser for both ends, because this device's file ACL only lets a user use "<username>/#".
    publisher = sensor if REQ["mode"] == "builtin" else admin
    listener = gateway if REQ["mode"] == "builtin" else admin
    cmd_sender = gateway if REQ["mode"] == "builtin" else admin
    pub_id = "b1lab-dlv-" + _rnd.token_hex(4)
    delivery = {"publisher": publisher[0], "listener": listener[0]}
    def metrics(path):
        c, body = get(path)
        if c != 200 or not isinstance(body, dict):
            return None
        m = body.get("metrics") or {}
        return {k: m.get(k) for k in ("matched", "passed", "failed", "success", "actions.total", "actions.success",
                                      "actions.failed", "dropped", "late_reply", "retried", "queuing", "inflight")
                if k in m}
    if token:
        before = {"republish": metrics("/api/v5/rules/b1_rule_republish/metrics"),
                  "http_rule": metrics("/api/v5/rules/b1_rule_http/metrics"),
                  "http_action": metrics("/api/v5/actions/http:b1_http_action/metrics")}
    alerts = "b1/alerts/" + pub_id
    sl, rl = connect("b1lab-dlv-listen-" + _rnd.token_hex(3), listener[0], listener[1])
    sp, rp = connect(pub_id, publisher[0], publisher[1])
    delivery["connack"] = [rl, rp]
    if sl and sp:
        code, got = subscribe(sl, alerts, wait=0.5)
        delivery["suback"] = code
        temp = 31 + _rnd.randbelow(60)
        sensor_topic = "b1/sensor/" + publisher[0] + "/delivery-" + _rnd.token_hex(4)
        delivery["puback"] = publish(sp, sensor_topic.encode(), json.dumps({"temp": temp}).encode())
        drain(sl, 8.0, got, stop=lambda g: len(g) >= 1)
        drain(sl, 1.0, got)
        delivery["received"] = len([1 for t, r, h, p in got if t == alerts])
        delivery["payload_equal"] = [p for t, r, h, p in got if t == alerts] == [str(temp).encode()]
    for x in (sl, sp):
        if x:
            close(x)
    sc, rc = connect("b1lab-dlv-cmd-" + _rnd.token_hex(3), cmd_sender[0], cmd_sender[1])
    if sc:
        delivery["cmd_puback"] = publish(sc, ("b1/cmd/delivery-" + _rnd.token_hex(4)).encode(), b'{"cmd":"woowbk"}')
        close(sc)
    time.sleep(6)
    if token:
        after = {"republish": metrics("/api/v5/rules/b1_rule_republish/metrics"),
                 "http_rule": metrics("/api/v5/rules/b1_rule_http/metrics"),
                 "http_action": metrics("/api/v5/actions/http:b1_http_action/metrics")}
        delivery["metrics_before"] = before
        delivery["metrics_after"] = after
    out["delivery"] = delivery
rc, so, se = pexec("woow-emqx", "emqx", "ctl", "status")
out["ctl_status"] = so.strip().splitlines()[:2]
finish(out)
'''

DIGEST_KEYS = ('mqtt_users', 'authenticators', 'authz_settings', 'authz_sources', 'file_acl_readback_equal', 'acl_api',
               'retained_api', 'rules', 'connectors', 'actions', 'banned', 'dashboard_users', 'api_keys',
               'native_counts', 'config_sha256')

PROGRAMS = {'PROBE': PROBE}


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


class _Tick(Exception):
    pass


def waiting_mtime():
    try:
        return WAITING.stat().st_mtime_ns
    except FileNotFoundError:
        return None


def emqx_main_holds_lock():
    """True only while an emqx-main real run HOLDS the lock (a FLOCK `lock:` line in /proc/<pid>/fdinfo)."""
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            cmd = (proc / 'cmdline').read_bytes()
            if b'run_emqx_real_owner.sh' not in cmd and b'emqx_real_owner_transport.py' not in cmd:
                continue
            for fd in (proc / 'fd').iterdir():
                if os.readlink(fd) == str(LOCK):
                    info = (proc / 'fdinfo' / fd.name).read_text()
                    if any(line.startswith('lock:') and 'FLOCK' in line for line in info.splitlines()):
                        return True
        except OSError:
            continue
    return False


def _tick(_signum, _frame):
    raise _Tick()


def acquire_lock():
    """The dev-d mutation lock, waited for like `flock -w` (blocking), released at once while emqx-main waits."""
    fd = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
        os.close(fd)
        raise Failed('unsafe dev-d lock file')
    previous = signal.signal(signal.SIGALRM, _tick)
    started = time.monotonic()
    stale = None
    try:
        while True:
            if time.monotonic() - started > LOCK_WAIT:
                os.close(fd)
                raise Failed('dev-d lock not acquired within 3600 s')
            mtime = waiting_mtime()
            if mtime is not None and emqx_main_holds_lock():
                stale = mtime
            if mtime is not None and mtime != stale:
                time.sleep(5)
                continue
            signal.alarm(30)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except _Tick:
                continue
            finally:
                signal.alarm(0)
            mtime = waiting_mtime()
            if mtime is not None and mtime != stale:
                fcntl.flock(fd, fcntl.LOCK_UN)
                time.sleep(5)
                continue
            emit(f'lock acquired after {int(time.monotonic() - started)} s')
            return fd
    finally:
        signal.signal(signal.SIGALRM, previous)


# ---------------------------------------------------------------- helpers

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def fixture_path(tag):
    if tag in LAB_MADE:
        return LAB_FOLDER / LAB_MADE[tag] / f'{LAB_MADE[tag]}.tar'
    machine, name = drv.UPLOADS[tag][0], drv.UPLOADS[tag][1]
    return drv.FIXTURES / machine / name / f'{name}.tar'


def machine_of(tag):
    return drv.UPLOADS[tag][0]


def ha_key(args, tag):
    """The HA key of an encrypted upload, None for an unencrypted one (the page asks for no key then)."""
    return args.secrets['HA_BACKUP_KEY'] if drv.UPLOADS[tag][2] else None


def probe_request(args, mode, tag=None, *, authz_add=False, own_mqtt=False, delete_user=None, create_user=None,
                  logins=()):
    s = args.secrets
    request = {'mode': mode, 'ha_admin_password': s['B1_EMQX_ADMIN_PW'], 'user2': s['B1_EMQX_USER2'],
               'user2_password': s['B1_EMQX_USER2_PW'], 'authz_add': authz_add}
    if delete_user is not None:
        request['delete_mqtt_user'] = delete_user
    if create_user is not None:   # a user name whose password is a harness secret (SR5_OWN)
        request['create_mqtt_user'] = [create_user, s[SR5_OWN[create_user]]]
    if logins:                    # user names whose passwords are harness secrets (SR5_OWN)
        request['logins'] = [[user, s[SR5_OWN[user]]] for user in logins]
    if tag is not None:
        prefix = 'B1_ARM' if machine_of(tag) == 'arm' else 'B1_X86'
        request.update(mqtt=[[s[f'B1_MQTT_USER{i}'], s[f'B1_MQTT_PW{i}']] for i in (1, 2, 3)],
                       api_key=s[f'{prefix}_EMQX_API_KEY'], api_secret=s[f'{prefix}_EMQX_API_SECRET'])
    if own_mqtt:
        request['own_mqtt'] = [[s[f'B1_MQTT_USER{i}'], s[f'B1_MQTT_PW{i}']] for i in (1, 2, 3)]
    return request


def run_probe(ev, args, label_text, mode, tag=None, *, authz_add=False, own_mqtt=False, delete_user=None,
              create_user=None, logins=()):
    probe = drv.event_device_python(PROBE, probe_request(args, mode, tag, authz_add=authz_add, own_mqtt=own_mqtt,
                                                         delete_user=delete_user, create_user=create_user,
                                                         logins=logins),
                                    args.secrets, [('/api/v5/login', ('token',), False)] * 3, timeout=900)
    ev.save(f'probe-{slug(label_text)}-{int(time.time())}.json', probe)
    # Every successful login issued one token: the leak scan of this run must look for that many (step leaks).
    args.logins = getattr(args, 'logins', 0) + sum(1 for code in (probe.get('login') or {}).values() if code == 200)
    return probe


def digest(probe):
    """The state a probe saw; EMQX's own $SYS retained messages (rewritten at every start) are left out."""
    found = {key: probe.get(key) for key in DIGEST_KEYS}
    found['retained_api'] = {t: h for t, h in (probe.get('retained_api') or {}).items() if not t.startswith('$SYS/')}
    return found


def diff_digest(a, b):
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))


def evaluate_imported(probe, src, mode, *, acl_rows=4):
    """[(check name, ok, detail)] of one probe after an import of `src` (the recorded HA facts) in `mode`; `acl_rows` =
    the ACL rows of the imported HA backup (0 = the lab-made one)."""
    results = []
    login = probe.get('login') or {}
    results.append(('the Dashboard takes HA\'s admin and HA\'s second user; this device\'s old admin password no '
                    'longer logs in', login.get('ha_admin') == 200 and login.get('ha_user2') == 200
                    and login.get('device_admin') == 401, login))
    users = probe.get('mqtt_users') or []
    want_users = sorted([u['user_id'], u['is_superuser']] for u in src['mqtt_users'])
    results.append(('HA\'s three MQTT users and this device\'s bootstrap user woow',
                    all(u in users for u in want_users) and ['woow', False] in users, users))
    results.append(('authorization settings are this device\'s (no_match deny, deny_action ignore)',
                    probe.get('authz_settings') == {'no_match': 'deny', 'deny_action': 'ignore'},
                    probe.get('authz_settings')))
    want_sources = [['file', True]] + ([['built_in_database', True]] if mode == 'builtin' else [])
    results.append((f'authorization sources are this device\'s ({"file + built-in database" if mode == "builtin" else "file only"})',
                    probe.get('authz_sources') == want_sources, probe.get('authz_sources')))
    results.append(('the file ACL reads back byte-equal to this device\'s acl.conf',
                    probe.get('file_acl_readback_equal') is True, probe.get('file_acl_readback_equal')))
    acl = probe.get('acl_api') or {}
    counts = probe.get('native_counts') or {}
    if mode == 'builtin':
        results.append(('HA\'s ACL rules are active in the built-in database (2 users, 1 client, 1 for all)',
                        acl.get('users') == [200, [['b1-gateway', 2], ['b1-sensor', 2]]]
                        and acl.get('clients') == [200, [['b1-dashboard-panel', 1]]] and acl.get('all') == [200, 1], acl))
    else:
        what = ('HA\'s ACL rows are in the built-in database table (4 rows) but inactive' if acl_rows else
                'the HA backup holds no ACL row: the built-in database table is empty (0 rows)')
        results.append((f'{what}: the source is not '
                        'configured here (API 404)', counts.get('emqx_acl') == acl_rows
                        and all((acl.get(k) or [None])[0] == 404 for k in ('users', 'clients', 'all')),
                        {'emqx_acl': counts.get('emqx_acl'), 'api': {k: (acl.get(k) or [None])[0] for k in acl}}))
    retained = probe.get('retained_api') or {}
    results.append(('the 2 retained messages are stored', set(src['retained_messages']) <= set(retained)
                    and all(retained.get(t) for t in src['retained_messages']), sorted(retained)))
    rules = [r[0] for r in probe.get('rules') or []]
    results.append(('rules b1_rule_republish and b1_rule_http, connector b1_http, action b1_http_action',
                    all(r in rules for r in src['rules']) and any(c[1] == 'b1_http' for c in probe.get('connectors') or [])
                    and any(a[1] == 'b1_http_action' for a in probe.get('actions') or []),
                    {k: probe.get(k) for k in ('rules', 'connectors', 'actions')}))
    results.append(('the banned client', ['clientid', 'b1-banned-client'] in (probe.get('banned') or []),
                    probe.get('banned')))
    results.append(('Dashboard users admin and b1ops', all(u in (probe.get('dashboard_users') or [])
                                                           for u in src['dashboard_users']), probe.get('dashboard_users')))
    results.append(('HA\'s API key b1-import-key is there and works', ['b1-import-key', True] in (probe.get('api_keys') or [])
                    and probe.get('api_key_works') == 200, {'keys': probe.get('api_keys'), 'works': probe.get('api_key_works')}))
    mq = probe.get('mqtt') or {}
    names = [u['user_id'] for u in src['mqtt_users']]
    results.append(('MQTT: HA\'s three users log in with HA\'s passwords',
                    all(mq.get(f'login_{u}') == 0 for u in names), {k: v for k, v in mq.items() if k.startswith('login_')}))
    results.append(('MQTT: wrong password, anonymous login and the banned client id are refused',
                    all(mq.get(k) not in (0, None) for k in ('wrong_password', 'anonymous', 'banned_client')),
                    {k: mq.get(k) for k in ('wrong_password', 'anonymous', 'banned_client')}))
    results.append(('MQTT: this device\'s bootstrap user woow still logs in', mq.get('bootstrap_woow') == 0,
                    mq.get('bootstrap_woow')))
    stored = sorted([t, h] for t, h in retained.items() if t in src['retained_messages'])
    admin = mq.get('admin_retained') or {}
    results.append(('MQTT: HA\'s superuser gets the 2 retained messages; each payload equals the stored one',
                    admin.get('suback') in (0, 1) and admin.get('retained') == stored and len(stored) == 2,
                    {'suback': admin.get('suback'), 'topics': [t for t, _h in admin.get('retained') or []]}))
    gateway = mq.get('gateway_retained') or {}
    sensor_secret = mq.get('sensor_secret') or {}
    if mode == 'builtin':
        results.append(('MQTT: b1-gateway (HA\'s rule, active here) subscribes b1/retained/# and gets the 2 retained '
                        'messages', gateway.get('suback') in (0, 1) and gateway.get('retained') == stored,
                        {'suback': gateway.get('suback'), 'topics': [t for t, _h in gateway.get('retained') or []]}))
    else:
        results.append(('MQTT: b1-gateway on b1/retained/# is refused (SUBACK 0x80): this device\'s file ACL governs, '
                        'not HA\'s rows', gateway.get('suback') == 0x80 and not gateway.get('retained'),
                        {'suback': gateway.get('suback')}))
    results.append(('MQTT: b1-sensor on b1/secret/# is refused (SUBACK 0x80)', sensor_secret.get('suback') == 0x80,
                    sensor_secret.get('suback')))
    own = mq.get('own_topic') or {}
    results.append(('MQTT: this device\'s file rule still lets b1-gateway use b1-gateway/# (subscribe, publish, '
                    'receive)', own.get('suback') in (0, 1) and own.get('puback') is True and own.get('received') == 1,
                    own))
    delivery = probe.get('delivery') or {}
    results.append(('rule delivery: HA\'s republish rule delivers exactly one message with the rendered payload',
                    delivery.get('suback') in (0, 1) and delivery.get('puback') is True
                    and delivery.get('received') == 1 and delivery.get('payload_equal') is True,
                    {k: delivery.get(k) for k in ('publisher', 'listener', 'suback', 'puback', 'received',
                                                  'payload_equal')}))
    before, after = delivery.get('metrics_before') or {}, delivery.get('metrics_after') or {}
    def moved(name, key, by=1):
        a, b = (before.get(name) or {}).get(key), (after.get(name) or {}).get(key)
        return isinstance(a, int) and isinstance(b, int) and b - a >= by
    results.append(('rule delivery: the republish rule and HA\'s HTTP action rule matched (+1 each) and the HTTP '
                    'action ran (its counters moved)', moved('republish', 'matched') and moved('http_rule', 'matched')
                    and (moved('http_action', 'success') or moved('http_action', 'failed') or moved('http_action', 'matched')),
                    {'before': before, 'after': after}))
    results.append(('emqx ctl status: the node is started', any('is started' in line for line in probe.get('ctl_status') or []),
                    probe.get('ctl_status')))
    return results


def check_imported(ev, label_text, probe, src, mode, tag=None):
    for name, ok, detail in evaluate_imported(probe, src, mode, acl_rows=ACL_ROWS.get(tag, 4)):
        ev.check(f'{label_text}: {name}', ok, detail)


def markers(ev, label_text):
    proc = drv.run([drv.LP, 'exec', '-i', drv.DEVICE, drv.OWNER, 'python3', '-I', '-c', drv.MARKERS, 'emqx', 'read'],
                   input=b'{}', timeout=600)
    try:
        found = json.loads(drv.out(proc).strip().splitlines()[-1])
    except (ValueError, IndexError):
        found = {'error': 'marker read failed'}
    ev.save(f'markers-{slug(label_text)}-{int(time.time())}.json', found)
    have = drv.marker_names(found)
    want = drv.BASELINE_MARKERS['emqx']
    ev.check(f'{label_text}: dev-d\'s own EMQX baseline markers (batch1_markers.py read)', want <= have, sorted(have))
    return found


def job_log_has(job_reply_log, words):
    return any(words in (line.get('message') if isinstance(line, dict) else str(line)) for line in job_reply_log or [])


def run_job(ev, command, request, label_text, *, timeout=3600):
    request = dict(request, request_id=drv.request_id(label_text))
    started = time.monotonic()
    reply = drv.ok(command, request, ev=ev, timeout=300)
    job = drv.wait_job(reply['job_id'], ev=ev, timeout=timeout)
    took = time.monotonic() - started
    status = drv.ok('job-status', {'job_id': reply['job_id']}, ev=ev)
    return job, status.get('log') or [], took


def restore_with(ev, backup_id, label_text, key=None):
    request = {'backup_id': backup_id, 'apps': ['emqx'], 'confirm': True}
    if key is not None:
        request['key'] = key
    job, log, took = run_job(ev, 'restore-start', request, label_text)
    result = job.get('result') or {}
    drv.created_backup(result.get('safety_backup_id'))
    if job['state'] != 'succeeded':
        error = job.get('error') or {}
        drv.created_backup((error.get('details') or {}).get('safety_backup_id') if isinstance(error, dict) else None)
    ev.time('restore', label_text, 'emqx', took, job)
    return job, log, took


def restart_emqx(ev, label_text):
    started = time.monotonic()
    proc = drv.owner('systemctl', '--user', 'restart', UNIT, timeout=600)
    took = time.monotonic() - started
    ev.check(f'{label_text}: systemctl --user restart {UNIT}', proc.returncode == 0, f'rc {proc.returncode} {took:.0f} s')
    ev.time('restart', '-', 'emqx', took)


def stat_owner(paths):
    script = ('import json, os, sys\nhome = os.path.expanduser("~")\nout = {}\n'
              'for p in json.loads(sys.stdin.read()):\n'
              '    out[p] = os.path.lexists(os.path.join(home, p))\nprint(json.dumps(out))\n')
    proc = drv.run([drv.LP, 'exec', '-i', drv.DEVICE, drv.OWNER, 'python3', '-I', '-c', script],
                   input=json.dumps(list(paths)).encode(), timeout=120)
    return json.loads(drv.out(proc).strip().splitlines()[-1])


def arm(files, script, dropin, marker_text):
    """A one-shot ExecStartPre of emqx.service: [drop-in, script, marker] written, never over an existing one. Returns
    whether the drop-in folder existed."""
    exists = stat_owner([DROPDIR, *files])
    if any(exists[path] for path in files):
        raise Failed('a drop-in, script, marker or record of an earlier round exists')
    dropin_path, script_path, marker_path = files[:3]
    request = {'script': script.decode(), 'dropin': dropin, 'marker': marker_text}
    program = ('import json, os, sys\nhome = os.path.expanduser("~")\nreq = json.loads(sys.stdin.read())\n'
               f'os.makedirs(os.path.join(home, {DROPDIR!r}), mode=0o700, exist_ok=True)\n'
               f'fd = os.open(os.path.join(home, {script_path!r}), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)\n'
               'os.write(fd, req["script"].encode()); os.close(fd)\n'
               f'with open(os.path.join(home, {dropin_path!r}), "x") as h:\n    h.write(req["dropin"])\n'
               f'with open(os.path.join(home, {marker_path!r}), "x") as h:\n    h.write(req["marker"])\n')
    proc = drv.run([drv.LP, 'exec', '-i', drv.DEVICE, drv.OWNER, 'python3', '-I', '-c', program],
                   input=json.dumps(request).encode(), timeout=120)
    if proc.returncode != 0:
        raise Failed('cannot write the one-shot drop-in')
    if drv.owner('systemctl', '--user', 'daemon-reload', timeout=120).returncode != 0:
        raise Failed('daemon-reload after the drop-in failed')
    return exists[DROPDIR]


def arm_fail_once():
    """The next start of emqx.service fails once (and records what the data volume held)."""
    return arm(FAIL_FILES, FAIL_ONCE, '[Service]\nExecStartPre=/bin/sh %h/' + FAIL_SCRIPT + '\n', 'fail once\n')


def arm_tamper_once():
    """The next start of emqx.service appends one HOCON line to the restored cluster.hocon first."""
    return arm(TAMPER_FILES, TAMPER, '[Service]\nExecStartPre=/bin/sh %h/' + TAMPER_SCRIPT + '\n', 'tamper once\n')


def disarm(files, dir_existed):
    """The round's files are removed (and the drop-in folder when the round made it); what was found, per file."""
    script = ('import os, json\nhome = os.path.expanduser("~")\nout = {}\n'
              f'for p in {tuple(files)!r}:\n'
              '    try:\n        os.remove(os.path.join(home, p)); out[p] = "removed"\n'
              '    except FileNotFoundError:\n        out[p] = "absent"\n'
              + ('' if dir_existed else
                 f'try:\n    os.rmdir(os.path.join(home, {DROPDIR!r})); out["dir"] = "removed"\n'
                 'except OSError:\n    out["dir"] = "kept"\n') +
              'print(json.dumps(out))\n')
    proc = drv.run([drv.LP, 'exec', '-i', drv.DEVICE, drv.OWNER, 'python3', '-I', '-c', script], timeout=120)
    drv.owner('systemctl', '--user', 'daemon-reload', timeout=120)
    try:
        return json.loads(drv.out(proc).strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {'error': 'disarm output unreadable'}


def disarmed(ev, label_text, what, files, dir_existed):
    """The drop-in of a round is gone: removed by this step (the drop-in and its script were there) and read back."""
    removed = disarm(files, dir_existed)
    left = stat_owner(files)
    ev.check(f'{label_text}: the {what} drop-in, script and marker are removed again (read back: nothing left)',
             removed.get(files[0]) == 'removed' and removed.get(files[1]) == 'removed' and not any(left.values()),
             {'removed': removed, 'left': [path for path, there in left.items() if there]})


def start_failure_round(ev, label_text, converted, name):
    """A restore of `converted` whose broker fails to start once: it must roll back by itself. The failing start itself
    records whether the data volume held HA's data at that moment (the restore had really replaced the data)."""
    dir_existed = arm_fail_once()
    try:
        job, _log, took = restore_with(ev, converted, name)
        error, result = job.get('error') or {}, job.get('result') or {}
        left = stat_owner([MARKER])
        ev.check(f'{label_text}: a restore whose EMQX fails to start rolls back by itself (job rolled-back, '
                 'result rolled_back, the one-shot failure consumed)',
                 job['state'] == 'rolled-back' and result.get('rolled_back') is True and not left[MARKER],
                 {'state': job['state'], 'code': error.get('code') if isinstance(error, dict) else None,
                  'rolled_back': result.get('rolled_back'), 'marker_left': left[MARKER], 'took_s': round(took, 1)})
        seen = drv.out(drv.owner('sh', '-c', f'cat "$HOME/{FAIL_SEEN}"', timeout=60)).strip()
        ev.check(f'{label_text}: when that start failed the data volume held HA\'s data (HA\'s rule in the restored '
                 'cluster.hocon)', seen.isdigit() and int(seen) > 0, {'rule_lines': seen[:20]})
    finally:
        disarmed(ev, label_text, 'fail-once', FAIL_FILES, dir_existed)


def readback_round(ev, label_text, converted, name):
    """E-90: a changed setting is named in the log, and the restore stays successful."""
    dir_existed = arm_tamper_once()
    try:
        job, log, took = restore_with(ev, converted, name)
        left = stat_owner([TAMPER_MARKER])
        readback_lines = [message for line in log
                          if (message := line.get('message') if isinstance(line, dict) else str(line))
                          and 'EMQX 還原後的' in message]
        ev.check(f'{label_text}: E-90 keeps a restore with only changed settings and consumes the one-shot change',
                 job['state'] == 'succeeded' and not left[TAMPER_MARKER],
                 {'state': job['state'], 'marker_left': left[TAMPER_MARKER], 'took_s': round(took, 1)})
        ev.check(f'{label_text}: the readback names only the changed log setting and explains no rollback',
                 len(readback_lines) == 1 and READBACK_DIFF in readback_lines[0]
                 and '提醒：' in readback_lines[0] and '沒有回復' in readback_lines[0]
                 and not job_log_has(log, READBACK_LOG),
                 {'readback_lines': len(readback_lines), 'names_log': any(READBACK_DIFF in line for line in readback_lines),
                  'reminded': any('提醒：' in line for line in readback_lines)})
    finally:
        disarmed(ev, label_text, 'tamper', TAMPER_FILES, dir_existed)


def own_state(ev, args, label_text, own, mode):
    """This device's OWN state is back: digest, markers, its own users and authorization; nothing of HA."""
    probe = run_probe(ev, args, label_text, 'base', own_mqtt=True)
    base_checks(ev, label_text, probe, mode)
    logins = probe.get('own_mqtt') or {}
    refused = {k: v for k, v in logins.items() if k.startswith('ha_')}
    ev.check(f'{label_text}: MQTT: this device\'s bootstrap user logs in, HA\'s three users are refused',
             logins.get('bootstrap_woow') == 0 and len(refused) == 3 and all(v not in (0, None) for v in refused.values()),
             logins)
    markers(ev, label_text)
    ev.check(f'{label_text}: EMQX state digest equals this device\'s own state right before that restore',
             digest(probe) == own, {'differs': diff_digest(digest(probe), own)})


def first_import_rounds(ev, args, label_text, converted, tag, mode, own):
    """The FIRST import attempt fails, from this device's own state (nothing of HA was ever restored here): a one-shot
    start failure, then a one-shot change the readback names. Each must bring exactly the own state back."""
    for what, failing in (('start failure', start_failure_round), ('readback', readback_round)):
        failing(ev, f'{label_text}: FIRST import attempt ({what})', converted, f'first-{what.split()[0]}-{tag}-{mode}')
        own_state(ev, args, f'{label_text} after the failed first attempt ({what})', own, mode)


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
        ok = (store_id in present and meta.get('sha256') == local == FIXTURE_SHA256[tag]
              and store_id == 'ha-' + local[:20])
        ev.check(f'store {tag}: the stored HA file is the real fixture (SHA-256 equal, id from it)', ok,
                 {'store': store_id, 'listed': store_id in present, 'filename': meta.get('filename')})
        if not ok:
            raise Failed(f'HA store entry {tag} not bound to its fixture')
        drv.STATE[f'ha_{tag}'] = store_id
    drv.save_state()


def bind_lab_made(ev, tag):
    """The lab-made upload: exactly the recorded file, uploaded through the page's upload commands when it is missing."""
    path = fixture_path(tag)
    local = sha256_file(path)
    if not ev.check(f'store {tag}: the lab-made file is the recorded one (SHA-256)', local == LAB_SHA256[tag],
                    {'sha256': local}):
        raise Failed('the lab-made fixture is not the recorded file')
    listed = {h.get('id') for h in drv.ok('list', ev=ev).get('ha_backups') or []}
    if STORE_IDS[tag] not in listed:
        started = time.monotonic()
        rc, reply = drv.upload(path, ev=ev)
        meta = reply.get('ha_backup') or {}
        ev.time('upload', tag, '-', time.monotonic() - started)
        found = {a['app_id']: a['installed'] for a in meta.get('importable_apps') or []}
        ev.check(f'store {tag}: uploaded through the page\'s upload-begin/-finish; importable app is EMQX', rc == 0
                 and meta.get('id') == STORE_IDS[tag] and found == {'emqx': True}, {'id': meta.get('id'), 'apps': found})
        if rc != 0 or meta.get('id') != STORE_IDS[tag]:
            raise Failed('the upload of the lab-made file failed')
    drv.STATE[f'ha_{tag}'] = STORE_IDS[tag]
    drv.save_state()


def compare_lab_made(ev, label_text, result):
    """The check's EMQX facts of a lab-made backup: the recorded x86 source facts with 0 ACL rows."""
    src = drv.source('x86')['emqx']
    sizes, found = src['mnesia_sizes'], result.get('emqx') or {}
    want = {'emqx_version': src['version'], 'target_version': '5.8.9', 'node_name': src['node'],
            'mqtt_users': sizes['emqx_authn_mnesia'], 'acl_rules': 0, 'dashboard_users': sizes['emqx_admin'],
            'api_keys': sizes['emqx_app'], 'banned': sizes['emqx_banned'], 'psk': sizes['emqx_psk'],
            'default_dashboard_password': False, 'anonymous': False, 'hot_backup': False}
    diff = {k: (found.get(k), v) for k, v in want.items() if found.get(k) != v}
    retained = found.get('retained_messages')
    ev.check(f'{label_text}: emqx section equals the source facts with 0 ACL rows (2 retained messages at least)',
             not diff and isinstance(retained, int) and retained >= 2, diff or {'retained_messages': retained})


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


ENGINE_HASHES = r'''
import hashlib, json, os
def sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()
base = "/usr/local/lib/woowtech-cockpit-backup/woowbackup"
lib = {}
for root, dirs, files in os.walk(base):
    dirs[:] = [d for d in dirs if d != "__pycache__"]
    for name in files:
        if name.endswith(".py"):
            path = os.path.join(root, name)
            lib[os.path.relpath(path, base)] = sha(path)
print(json.dumps({"lib": lib, "helper": sha("/usr/local/libexec/woowtech-cockpit-backup")}))
'''
PROGRAMS['ENGINE_HASHES'] = ENGINE_HASHES


# ---------------------------------------------------------------- steps

def installed_engine():
    """(same, modules, differ): dev-d's installed engine modules and helper against this tree (SHA-256)."""
    installed = drv.device_python(ENGINE_HASHES, {}, as_owner=False, timeout=300)
    base = REPO / 'backup-engine' / 'woowbackup'
    tree = {str(p.relative_to(base)): sha256_file(p) for p in base.rglob('*.py') if '__pycache__' not in p.parts}
    lib = installed.get('lib') or {}
    differ = sorted(k for k in set(tree) | set(lib) if tree.get(k) != lib.get(k))
    same = not differ and installed.get('helper') == sha256_file(REPO / 'backup-engine' / 'woowtech-cockpit-backup')
    return same, len(tree), differ


def step_setup(ev, args):
    proc = drv.root('systemctl', 'mask', TIMER, timeout=120)
    ev.check('setup: the scheduled-backup timer is masked before the install (shared lab, no schedule wanted)',
             proc.returncode == 0, drv.out(proc)[-200:])
    # Other lanes install their own trees into dev-d between the holds: every attempt starts with this tree.
    if installed_engine()[0]:
        ev.log('setup: dev-d already runs this tree\'s engine and helper; deploy skipped')
    else:
        proc = drv.run(['bash', str(HERE / 'deploy-src.sh'), 'd', '--src', str(REPO), '--no-demo-catalog'],
                       timeout=1800)
        ev.save('deploy.log', drv.out(proc)[-20000:] + proc.stderr.decode('utf-8', 'replace')[-5000:])
        if not ev.check('setup: deploy-src.sh d --src <this tree> --no-demo-catalog', proc.returncode == 0,
                        f'rc {proc.returncode}'):
            raise Failed('deploy failed')
    same, modules, differ = installed_engine()
    ev.check('setup: the installed engine is this tree (every module and the helper SHA-256 equal)', same,
             {'modules': modules, 'differ': differ[:10]})
    status = drv.ok('status', ev=ev)
    version = (REPO / 'VERSION').read_text().strip()
    ev.check('setup: the installed helper answers status with this tree\'s VERSION', status.get('version') == version,
             {'installed': status.get('version'), 'tree': version})
    catalog = {a['id'] for a in status.get('apps') or []}
    if 'emqx' not in catalog:
        kit = load_kit(args)
        reply = drv.ok('inspect', {'backup_id': BASELINE, 'key': kit}, ev=ev, timeout=900)
        apps = (reply.get('preflight') or {}).get('apps') or []
        carried = next((a.get('settings') or {} for a in apps if a.get('id') == 'emqx'), {})
        entry = carried.get('entry')
        ev.check('setup: dev-d\'s EMQX baseline backup opens with the 11-19 emergency kit and carries its catalog entry',
                 isinstance(entry, dict) and entry.get('id') == 'emqx' and carried.get('state') == 'missing',
                 {'state': carried.get('state'), 'owner': (entry or {}).get('owner')})
        if not isinstance(entry, dict):
            raise Failed('no carried EMQX catalog entry')
        ev.save('catalog-entry-emqx.json', entry)
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
    state = next((a for a in status.get('apps') or [] if a['id'] == 'emqx'), {})
    ev.check('setup: status: emqx running, no problems', state.get('state') == 'running' and not state.get('problems'),
             {k: state.get(k) for k in ('state', 'problems')})
    leftovers = stat_owner([*FAIL_FILES, *TAMPER_FILES])
    ev.check('setup: no fail-once or tamper drop-in, script or marker of an earlier run', not any(leftovers.values()),
             leftovers)


def base_checks(ev, label_text, probe, mode='file'):
    login = probe.get('login') or {}
    ev.check(f'{label_text}: this device\'s admin logs in; HA\'s admin password does not', login.get('device_admin') == 200
             and login.get('ha_admin') == 401, login)
    sources = [['file', True]] + ([['built_in_database', True]] if mode == 'builtin' else [])
    ev.check(f'{label_text}: authorization is this device\'s own '
             f'({"file ACL + the added built-in database" if mode == "builtin" else "file ACL only"}, no_match deny)',
             probe.get('authz_sources') == sources and probe.get('authz_settings') ==
             {'no_match': 'deny', 'deny_action': 'ignore'} and probe.get('file_acl_readback_equal') is True,
             {k: probe.get(k) for k in ('authz_sources', 'authz_settings', 'file_acl_readback_equal')})
    names = {u[0] for u in probe.get('mqtt_users') or []}
    ev.check(f'{label_text}: no HA data (no b1 user, rule, retained message or API key)',
             not any(n.startswith('b1-') for n in names) and not probe.get('rules')
             and not any(t.startswith('b1/') for t in probe.get('retained_api') or {})
             and not any(k[0] == 'b1-import-key' for k in probe.get('api_keys') or []), sorted(names))


def step_before(ev, args):
    probe = run_probe(ev, args, 'before', 'base')
    base_checks(ev, 'before', probe)
    markers(ev, 'before')
    current = digest(probe)
    first = drv.STATE.setdefault('digest_first', drv.STATE.get('digest_before') or current)
    ev.check('before: EMQX state digest equals the first one recorded before any import (every earlier rollback was '
             'exact)', current == first, {'differs': diff_digest(current, first)})
    drv.STATE['digest_before'] = current
    if not drv.STATE.get('baseline_b0'):
        job, _log, took = run_job(ev, 'backup-start', {'apps': ['emqx'], 'note': 'emqx-product baseline B0'}, 'baseline-b0')
        result = job.get('result') or {}
        b0 = result.get('backup_id')
        ev.check('before: the test\'s own baseline backup B0 of EMQX (backup-start, encrypted with the device key)',
                 job['state'] == 'succeeded' and bool(b0) and result.get('encrypted') is True,
                 {'state': job['state'], 'error': job.get('error'), 'id': b0, 'took_s': round(took, 1)})
        if job['state'] != 'succeeded' or not b0:
            raise Failed('no baseline backup')
        drv.STATE['baseline_b0'] = b0
        drv.created_backup(b0)
        after = digest(run_probe(ev, args, 'before after B0', 'base'))
        ev.check('before: the backup changed nothing (digest equal after it)', after == current,
                 {'differs': diff_digest(after, current)})
    emit(f'backup id baseline {drv.STATE["baseline_b0"]}')
    drv.save_state()


def check_one(ev, args, tag, *, mode):
    """ha-check-start (emqx) of one cold upload, as the page starts it. builtin target: ok, no blocker. file target
    (dev-d's own): refused with exactly the owner's text (decision C). The app's result, or None when the job failed."""
    key = ha_key(args, tag)
    job, took = drv.run_check(drv.STATE[f'ha_{tag}'], ['emqx'], ev=ev, key=key, tag=f'check-{tag}-{mode}-emqx')
    ev.time('check', tag, 'emqx', took, job)
    label_text = f'check {tag}/emqx ({mode} target)'
    if not ev.check(f'{label_text}: job succeeded', job['state'] == 'succeeded', f'{took:.0f} s {job.get("error")}'):
        return None
    result = job['result']['ha_check']['apps'][0]
    ev.save(f'check-{tag}-{mode}-emqx.json', result)
    section = result.get('emqx') or {}
    if mode == 'builtin' or tag in LAB_MADE:
        ev.check(f'{label_text}: ok, no blockers', result.get('ok') is True and not result.get('blockers'),
                 result.get('blockers'))
        profile = ['file', 'built_in_database'] if mode == 'builtin' else ['file']
        reads = 'file + built-in database' if mode == 'builtin' else 'file only'
        ev.check(f'{label_text}: this device\'s authorization reads {reads}',
                 section.get('target_authorization') == profile, section.get('target_authorization'))
    else:
        ev.check(f'{label_text}: refused at check time with exactly the owner\'s text, the only blocker (decision C)',
                 result.get('ok') is False and result.get('blockers') == [OWNER_ACL_TEXT], result.get('blockers'))
        ev.check(f'{label_text}: this device\'s authorization reads file only', section.get('target_authorization') == ['file'],
                 section.get('target_authorization'))
    arch = 'aarch64' if machine_of(tag) == 'arm' else 'amd64'
    ev.check(f'{label_text}: source {arch}, add-on 5.9.1, target 5.8.9', result.get('arch') == arch
             and result.get('version') == '5.9.1' and result.get('target_version') == '5.8.9',
             {k: result.get(k) for k in ('arch', 'version', 'target_version')})
    if tag in LAB_MADE:
        compare_lab_made(ev, label_text, result)
    else:
        drv.compare_check(ev, label_text, 'emqx', result, machine_of(tag), False, tag)
    warnings = result.get('warnings') or []
    ev.check(f'{label_text}: no ACL warning (decision C made it a blocker)', not any('不會生效' in w for w in warnings),
             warnings)
    ev.check(f'{label_text}: no hot-backup warning (the add-on was stopped)', not any('執行中製作' in w for w in warnings),
             warnings)
    return result


def step_check(ev, args):
    bind_store(ev)
    for tag in TAGS:
        check_one(ev, args, tag, mode='file')
    leftovers = drv.labelled()
    ev.check('check: no throwaway container, volume or network left', not any(leftovers.values()), leftovers)


def refuse_file(ev, args, tag, label_text):
    """Decision C on dev-d's own target (the ACL file only, as installed): the check refuses with the owner's text;
    the conversion, started through the helper anyway (the page offers no 轉換 after a blocker), is refused with the
    same text before any candidate; nothing is left and dev-d's EMQX is unchanged."""
    if check_one(ev, args, tag, mode='file') is None:
        raise Failed('the check job failed')
    leftovers = drv.labelled()
    ev.check(f'{label_text}: the check left no throwaway container, volume or network', not any(leftovers.values()),
             leftovers)
    before_ids = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
    job, took = drv.convert(drv.STATE[f'ha_{tag}'], ['emqx'], False, ev=ev, key=args.secrets['HA_BACKUP_KEY'],
                            tag=f'convert-{tag}-file-emqx')
    ev.time('convert', tag, 'emqx', took, job)
    error = job.get('error') if isinstance(job.get('error'), dict) else {}
    ev.check(f'{label_text}: the conversion is refused (incompatible) with the owner\'s text',
             job['state'] == 'failed' and error.get('code') == 'incompatible'
             and OWNER_ACL_TEXT in (error.get('message') or ''),
             {'state': job['state'], 'code': error.get('code'), 'message': error.get('message'),
              'took_s': round(took, 1)})
    if job['state'] == 'succeeded':   # never expected: keep the backup for cleanup
        drv.created_backup((job.get('result') or {}).get('backup_id'))
    objects = drv.labelled()
    after_ids = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
    ev.check(f'{label_text}: the refused conversion left nothing (no backup, no throwaway object)',
             after_ids == before_ids and not any(objects.values()), {'new': sorted(after_ids - before_ids), **objects})
    post = run_probe(ev, args, f'{label_text} after the refusal', 'base')
    base_checks(ev, f'{label_text} after the refusal', post)
    markers(ev, f'{label_text} after the refusal')
    return ev.check(f'{label_text}: dev-d\'s EMQX is unchanged (state digest equals the one before)',
                    digest(post) == drv.STATE['digest_before'],
                    {'differs': diff_digest(digest(post), drv.STATE['digest_before'])})


def step_import(ev, args, tag, mode):
    if not (tag in TAGS and mode in MODES or tag in LAB_MADE and mode == 'file'):
        raise Failed(f'unknown import {tag}:{mode}')
    if tag in LAB_MADE:
        bind_lab_made(ev, tag)
    elif drv.STATE.get(f'ha_{tag}') != STORE_IDS[tag]:
        bind_store(ev)
    if 'digest_before' not in drv.STATE or not drv.STATE.get('baseline_b0'):
        raise Failed('run setup and before first (the before digest or B0 is missing)')
    if drv.STATE.get('imported'):
        raise Failed('an imported state waits for its rollback step (rollback:TAG) first')
    label_text = f'import {tag}/emqx ({mode} target)'
    src = drv.source(machine_of(tag))['emqx']
    pre = run_probe(ev, args, f'{label_text} pre', 'base')
    if digest(pre) != drv.STATE['digest_before']:
        raise Failed('dev-d\'s EMQX is not at its baseline; refusing to import over unknown data')
    if mode == 'file' and tag not in LAB_MADE:
        if not refuse_file(ev, args, tag, label_text):
            manual_baseline(ev, args, label_text, False)   # never expected: bring the baseline back
        return
    draft_installed(ev, label_text)
    own_expected = digest(pre)
    changed = False     # dev-d's EMQX may differ from the baseline: the finally block restores B0 ...
    kept = False        # ... unless the imported state was recorded for the rollback step (step_rollback)
    try:
        if mode == 'builtin':
            changed = True
            added = run_probe(ev, args, f'{label_text} add builtin', 'base', authz_add=True)
            if not ev.check(f'{label_text}: the built-in database source was added through the API and moved after '
                            'the file source (file + built-in)',
                            added.get('authz_add') in (200, 204) and added.get('authz_move') in (200, 204)
                            and added.get('authz_sources') == [['file', True], ['built_in_database', True]],
                            {'add': added.get('authz_add'), 'move': added.get('authz_move'),
                             'sources': added.get('authz_sources')}):
                raise Failed('the builtin source could not be added')
            own_expected = digest(added)
        if check_one(ev, args, tag, mode=mode) is None:
            raise Failed('the check job failed')
        before_ids = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        job, took = drv.convert(drv.STATE[f'ha_{tag}'], ['emqx'], False, ev=ev, key=ha_key(args, tag),
                                tag=f'convert-{tag}-{mode}-emqx')
        ev.time('convert', tag, 'emqx', took, job)
        if not ev.check(f'{label_text}: conversion succeeded with a backup id', job['state'] == 'succeeded',
                        f'{took:.0f} s {job.get("error")}'):
            objects = drv.labelled()
            after_ids = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
            ev.check(f'{label_text}: the refused conversion left nothing (no backup, no throwaway object)',
                     after_ids == before_ids and not any(objects.values()),
                     {'new': sorted(after_ids - before_ids), **objects})
            return
        result = job['result']
        converted = result['backup_id']
        drv.created_backup(converted)
        emit(f'backup id converted {converted}')
        imp = result.get('ha_import') or {}
        ev.save(f'ha-import-{tag}-{mode}.json', imp)
        ev.check(f'{label_text}: ha_import names emqx with its note and reminders', imp.get('apps') == ['emqx']
                 and any('EMQX' in n for n in imp.get('notes') or [])
                 and bool((imp.get('reminders_by_app') or {}).get('emqx')), {k: imp.get(k) for k in ('apps', 'notes')})
        inspect = drv.ok('inspect', {'backup_id': converted}, ev=ev, timeout=900)
        pre_flight = inspect.get('preflight') or {}
        failed = [c for c in pre_flight.get('checks') or [] if c.get('status') == 'fail']
        ev.check(f'{label_text}: inspect: preflight passes, settings same, in place',
                 pre_flight.get('ok') and not failed and all((a.get('settings') or {}).get('state') == 'same'
                                                             and a.get('mode') == 'inplace'
                                                             for a in pre_flight.get('apps') or []),
                 failed[:3] or [(a.get('id'), a.get('mode'), (a.get('settings') or {}).get('state'))
                                for a in pre_flight.get('apps') or []])
        own = digest(run_probe(ev, args, f'{label_text} before the first restore', 'base'))
        ev.check(f'{label_text}: the check and the conversion changed nothing on this device (state digest equal)',
                 own == own_expected, {'differs': diff_digest(own, own_expected)})
        changed = True
        if tag in FIRST_ROUNDS:
            if mode == 'builtin':
                # A source added at runtime gets the schema's defaults at the next boot (attempt-05): the own state that
                # must come back is the booted one. The conversion above saw the device as it was changed at runtime.
                restart_emqx(ev, f'{label_text} (this device\'s own state)')
                own = digest(run_probe(ev, args, f'{label_text} own state after a restart', 'base'))
            first_import_rounds(ev, args, label_text, converted, tag, mode, own)
        rjob, rlog, rtook = restore_with(ev, converted, f'restore-{tag}-{mode}')
        rresult = rjob.get('result') or {}
        safety = rresult.get('safety_backup_id')
        if safety:
            emit(f'backup id safety {safety}')
        if not ev.check(f'{label_text}: restore of the converted backup succeeded with a safety backup, not rolled back',
                        rjob['state'] == 'succeeded' and bool(safety) and rresult.get('rolled_back') is False,
                        {'state': rjob['state'], 'error': rjob.get('error'), 'took_s': round(rtook, 1)}):
            return
        ev.check(f'{label_text}: the restore\'s own readback check passed (job log)', job_log_has(rlog, READBACK_LOG),
                 [str(line)[-300:] for line in rlog if 'EMQX' in str(line)][-6:])
        if drv.STATE.get('own_entry'):
            ev.check(f'{label_text}: the draft\'s own health check passed after the restore (job log)',
                     job_log_has(rlog, '健康檢查通過') and not job_log_has(rlog, '健康檢查未通過'),
                     [str(line)[-200:] for line in rlog if '健康檢查' in str(line)][-4:])
        imported = run_probe(ev, args, f'{label_text} after restore', mode, tag)
        check_imported(ev, f'{label_text} after restore', imported, src, mode, tag)
        restart_emqx(ev, label_text)
        restarted = run_probe(ev, args, f'{label_text} after restart', mode, tag)
        check_imported(ev, f'{label_text} after restart', restarted, src, mode, tag)
        if not ev.check(f'{label_text} after restart: the same state as right after the restore',
                        stable(restarted) == stable(imported),
                        {'differs': diff_digest(stable(restarted), stable(imported))}):
            return
        # The rollback rounds run in their own lock hold (step rollback:TAG; one hold stays under 40 min): dev-d's
        # EMQX keeps this imported state in between, recorded here and proven again before the rounds.
        drv.STATE['imported'] = {'tag': tag, 'mode': mode, 'backup_id': converted, 'stable': stable(restarted)}
        drv.save_state()
        kept = True
    finally:
        if changed and not kept:
            manual_baseline(ev, args, label_text, False)


def step_rollback(ev, args, tag):
    """From imported state: start failure rolls back; settings-only readback warns; then restore B0."""
    mode = 'file' if tag in LAB_MADE else 'builtin'
    label_text = f'import {tag}/emqx ({mode} target)'
    imported = drv.STATE.get('imported') or {}
    if imported.get('tag') != tag or imported.get('mode', 'builtin') != mode or not imported.get('backup_id'):
        raise Failed(f'run import:{tag}:{mode} first (no imported state recorded)')
    converted = imported['backup_id']
    src = drv.source(machine_of(tag))['emqx']
    draft_installed(ev, f'{label_text} before the rollback rounds')
    tested = False
    try:
        restarted = run_probe(ev, args, f'{label_text} before the rollback rounds', mode, tag)
        check_imported(ev, f'{label_text} before the rollback rounds', restarted, src, mode, tag)
        if not ev.check(f'{label_text} before the rollback rounds: dev-d\'s EMQX still holds the imported state',
                        stable(restarted) == imported['stable'],
                        {'differs': diff_digest(stable(restarted), imported['stable'])}):
            raise Failed('the imported state changed between the lock holds')
        # AUTOMATIC rollback: the same converted backup again, a one-shot start failure armed right before it.
        start_failure_round(ev, label_text, converted, f'autorollback-{tag}-{mode}')
        rolled = run_probe(ev, args, f'{label_text} after automatic rollback', mode, tag)
        check_imported(ev, f'{label_text} after automatic rollback', rolled, src, mode, tag)
        ev.check(f'{label_text} after automatic rollback: the state equals the one before that restore',
                 stable(rolled) == stable(restarted), {'differs': diff_digest(stable(rolled), stable(restarted))})
        # E-90: a setting changes just before start; the readback names the root but keeps the restored data.
        readback_round(ev, label_text, converted, f'readback-{tag}-{mode}')
        tampered = run_probe(ev, args, f'{label_text} after the readback reminder', mode, tag)
        check_imported(ev, f'{label_text} after the readback reminder', tampered, src, mode, tag)
        ev.check(f'{label_text} after the readback reminder: only the log configuration differs from before',
                 diff_digest(stable(tampered), stable(rolled)) == ['config_sha256'],
                 {'differs': diff_digest(stable(tampered), stable(rolled))})
        tested = True
    finally:
        manual_baseline(ev, args, label_text, tested)
        drv.STATE['imported'] = None
        drv.save_state()


def sr5_warnings(result):
    return [w for w in (result or {}).get('warnings') or [] if '保存 MQTT 密碼的方式' in w]


def evaluate_sr5(probe, src, others=()):
    """[(check name, ok, detail)] of one probe after the import of the bcrypt variant: everything the x86-fileonly import
    proves, except that this device's own accounts (the check named them) are now refused with their own passwords:
    the bootstrap user woow (its row stays, hashed the old way) and `others` (probe `logins`: gone with the import)."""
    results = []
    for name, ok, detail in evaluate_imported(probe, src, 'file', acl_rows=0):
        if name == 'MQTT: this device\'s bootstrap user woow still logs in':
            code = (probe.get('mqtt') or {}).get('bootstrap_woow')
            name, ok, detail = ('MQTT: this device\'s own account woow (named by the check) is refused with its own '
                                'password (CONNACK 4/5)', code in (4, 5), code)
        results.append((name, ok, detail))
    if others:
        logins = probe.get('logins') or {}
        results.append(('MQTT: this device\'s other own accounts (named by the check) are refused with their own '
                        'passwords (CONNACK 4/5)', sorted(logins) == sorted(others)
                        and all(logins.get(user) in (4, 5) for user in others), logins))
    return results


def own_logins(ev, label_text, probe, *, own_ok, others=()):
    """The own_mqtt part of a 'base' probe: woow with this device's bootstrap password, HA's three users; and
    `others` (probe `logins`), this device's other own accounts with their passwords."""
    logins = probe.get('own_mqtt') or {}
    refused = {k: v for k, v in logins.items() if k.startswith('ha_')}
    ev.check(f'{label_text}: MQTT: this device\'s bootstrap user woow logs in, HA\'s three users are refused', own_ok
             and logins.get('bootstrap_woow') == 0 and len(refused) == 3
             and all(v not in (0, None) for v in refused.values()), logins)
    if others:
        found = probe.get('logins') or {}
        ev.check(f'{label_text}: MQTT: this device\'s other own accounts log in with their own passwords',
                 sorted(found) == sorted(others) and all(found.get(user) == 0 for user in others), found)


def step_sr5(ev, args, tag):
    """SR-5 on dev-d's own target (the ACL file only, as installed) with a lab-made x86 backup (no ACL rows) whose HA
    hashes MQTT passwords differently. plain: the check refuses with the owner-decided text (the only blocker), the
    conversion is refused with it before anything, nothing is left and dev-d's EMQX state digest is unchanged. bcrypt:
    the check is ok and its warning names exactly this device's own MQTT accounts; the conversion repeats them (note,
    reminder); nothing changed by the check or the conversion; after the restore (and after a restart) HA's three users
    log in with their passwords while this device's woow is refused; the warning's own remedy for a bootstrap account
    (delete it, restart EMQX) brings woow back with its own password; then the manual rollback to B0 (digest equal, woow
    logs in again)."""
    variant = SR5.get(tag)
    if variant is None:
        raise Failed(f'unknown SR-5 upload {tag}')
    if 'digest_before' not in drv.STATE or not drv.STATE.get('baseline_b0'):
        raise Failed('run setup and before first (the before digest or B0 is missing)')
    if drv.STATE.get('imported'):
        raise Failed('an imported state waits for its rollback step (rollback:TAG) first')
    bind_lab_made(ev, tag)
    label_text = f'sr5 {tag}/emqx (file target)'
    src = drv.source('x86')['emqx']
    others = sorted(user for user in SR5_OWN if user != 'woow')
    pre = run_probe(ev, args, f'{label_text} pre', 'base', own_mqtt=True, logins=others)
    if digest(pre) != drv.STATE['digest_before']:
        raise Failed('dev-d\'s EMQX is not at its baseline; refusing to go on over unknown data')
    own_users = sorted(u[0] for u in pre.get('mqtt_users') or [])
    if not ev.check(f'{label_text}: this device\'s own MQTT accounts (listed by its API) are exactly the ones whose '
                    'passwords this harness knows (woow, woowbk-lab-baseline)', own_users == sorted(SR5_OWN), own_users):
        raise Failed('this device holds an MQTT account this run cannot log in')
    own_logins(ev, f'{label_text} pre', pre, own_ok=True, others=others)
    before_ids = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
    job, took = drv.run_check(drv.STATE[f'ha_{tag}'], ['emqx'], ev=ev, key=None, tag=f'check-{tag}-file-emqx')
    ev.time('check', tag, 'emqx', took, job)
    if not ev.check(f'{label_text}: check job succeeded', job['state'] == 'succeeded', f'{took:.0f} s {job.get("error")}'):
        raise Failed('the check job failed')
    result = job['result']['ha_check']['apps'][0]
    ev.save(f'check-{tag}-file-emqx.json', result)
    compare_lab_made(ev, label_text, result)
    ev.check(f'{label_text}: this device\'s authorization reads file only',
             (result.get('emqx') or {}).get('target_authorization') == ['file'],
             (result.get('emqx') or {}).get('target_authorization'))
    leftovers = drv.labelled()
    ev.check(f'{label_text}: the check left no throwaway container, volume or network', not any(leftovers.values()),
             leftovers)
    if variant == 'plain':
        ev.check(f'{label_text}: refused at check time with exactly the plain text, the only blocker (SR-5)',
                 result.get('ok') is False and result.get('blockers') == [SR5_PLAIN], result.get('blockers'))
        ev.check(f'{label_text}: no account warning next to the refusal', not sr5_warnings(result), result.get('warnings'))
        job, took = drv.convert(drv.STATE[f'ha_{tag}'], ['emqx'], False, ev=ev, key=None, tag=f'convert-{tag}-file-emqx')
        ev.time('convert', tag, 'emqx', took, job)
        error = job.get('error') if isinstance(job.get('error'), dict) else {}
        ev.check(f'{label_text}: the conversion is refused (incompatible) with the plain text',
                 job['state'] == 'failed' and error.get('code') == 'incompatible'
                 and SR5_PLAIN in (error.get('message') or ''),
                 {'state': job['state'], 'code': error.get('code'), 'message': error.get('message'),
                  'took_s': round(took, 1)})
        if job['state'] == 'succeeded':   # never expected: keep the backup for cleanup
            drv.created_backup((job.get('result') or {}).get('backup_id'))
        objects = drv.labelled()
        after_ids = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        ev.check(f'{label_text}: the refused conversion left nothing (no backup, no throwaway object)',
                 after_ids == before_ids and not any(objects.values()), {'new': sorted(after_ids - before_ids), **objects})
        post = run_probe(ev, args, f'{label_text} after the refusals', 'base', own_mqtt=True, logins=others)
        base_checks(ev, f'{label_text} after the refusals', post)
        own_logins(ev, f'{label_text} after the refusals', post, own_ok=True, others=others)
        markers(ev, f'{label_text} after the refusals')
        ev.check(f'{label_text}: dev-d\'s EMQX is unchanged (state digest equals the one before)',
                 digest(post) == drv.STATE['digest_before'],
                 {'differs': diff_digest(digest(post), drv.STATE['digest_before'])})
        return
    names = '、'.join(own_users)
    texts = {'ha': variant, 'mine': SR5_DEVICE_HASHING, 'names': names}
    ev.check(f'{label_text}: ok, no blockers', result.get('ok') is True and not result.get('blockers'),
             result.get('blockers'))
    ev.check(f'{label_text}: the check warns BEFORE any conversion and names exactly this device\'s own MQTT accounts '
             '(the owner-decided text, the only such warning)', sr5_warnings(result) == [SR5_WARNING.format(**texts)],
             sr5_warnings(result))
    own_expected = digest(pre)
    changed = tested = False
    try:
        job, took = drv.convert(drv.STATE[f'ha_{tag}'], ['emqx'], False, ev=ev, key=None, tag=f'convert-{tag}-file-emqx')
        ev.time('convert', tag, 'emqx', took, job)
        if not ev.check(f'{label_text}: conversion succeeded with a backup id', job['state'] == 'succeeded',
                        f'{took:.0f} s {job.get("error")}'):
            objects = drv.labelled()
            after_ids = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
            ev.check(f'{label_text}: the failed conversion left nothing (no backup, no throwaway object)',
                     after_ids == before_ids and not any(objects.values()),
                     {'new': sorted(after_ids - before_ids), **objects})
            return
        converted = job['result']['backup_id']
        drv.created_backup(converted)
        emit(f'backup id converted {converted}')
        imp = job['result'].get('ha_import') or {}
        ev.save(f'ha-import-{tag}-file.json', imp)
        notes = [n for n in imp.get('notes') or [] if '保存 MQTT 密碼的方式' in n]
        reminders = [r for r in (imp.get('reminders_by_app') or {}).get('emqx') or [] if r.startswith('請重新設定這台原本的')]
        ev.check(f'{label_text}: the conversion repeats the accounts in its note and its EMQX reminder (shown before and '
                 'after the restore)', notes == [SR5_NOTE.format(**texts)] and reminders == [SR5_REMINDER.format(**texts)],
                 {'notes': notes, 'reminders': reminders})
        inspect = drv.ok('inspect', {'backup_id': converted}, ev=ev, timeout=900)
        pre_flight = inspect.get('preflight') or {}
        failed = [c for c in pre_flight.get('checks') or [] if c.get('status') == 'fail']
        ev.check(f'{label_text}: inspect: preflight passes, settings same, in place',
                 pre_flight.get('ok') and not failed and all((a.get('settings') or {}).get('state') == 'same'
                                                             and a.get('mode') == 'inplace'
                                                             for a in pre_flight.get('apps') or []),
                 failed[:3] or [(a.get('id'), a.get('mode'), (a.get('settings') or {}).get('state'))
                                for a in pre_flight.get('apps') or []])
        own = run_probe(ev, args, f'{label_text} before the restore', 'base', own_mqtt=True, logins=others)
        own_logins(ev, f'{label_text} before the restore', own, own_ok=True, others=others)
        ev.check(f'{label_text}: the check and the conversion changed nothing on this device (state digest equal)',
                 digest(own) == own_expected, {'differs': diff_digest(digest(own), own_expected)})
        changed = True
        rjob, rlog, rtook = restore_with(ev, converted, f'restore-{tag}-file')
        rresult = rjob.get('result') or {}
        safety = rresult.get('safety_backup_id')
        if safety:
            emit(f'backup id safety {safety}')
        if not ev.check(f'{label_text}: restore of the converted backup succeeded with a safety backup, not rolled back',
                        rjob['state'] == 'succeeded' and bool(safety) and rresult.get('rolled_back') is False,
                        {'state': rjob['state'], 'error': rjob.get('error'), 'took_s': round(rtook, 1)}):
            return
        ev.check(f'{label_text}: the restore\'s own readback check passed (job log)', job_log_has(rlog, READBACK_LOG),
                 [str(line)[-300:] for line in rlog if 'EMQX' in str(line)][-6:])
        imported = run_probe(ev, args, f'{label_text} after restore', 'file', tag, logins=others)
        for name, ok, detail in evaluate_sr5(imported, src, others):
            ev.check(f'{label_text} after restore: {name}', ok, detail)
        restart_emqx(ev, label_text)
        restarted = run_probe(ev, args, f'{label_text} after restart', 'file', tag, logins=others)
        for name, ok, detail in evaluate_sr5(restarted, src, others):
            ev.check(f'{label_text} after restart: {name}', ok, detail)
        # The warning's own remedies: an account of this device's bootstrap file is deleted and EMQX restarted (the file
        # brings it back, hashed HA's way); every other account is created again with its password.
        removed = run_probe(ev, args, f'{label_text} remedy: delete woow', 'file', delete_user='woow')
        ev.check(f'{label_text} remedy: woow deleted through the API as HA\'s admin (204)',
                 removed.get('delete_mqtt_user') == 204 and ['woow', False] not in (removed.get('mqtt_users') or []),
                 {'code': removed.get('delete_mqtt_user'), 'users': removed.get('mqtt_users')})
        for user in others:
            made = run_probe(ev, args, f'{label_text} remedy: create {user}', 'file', create_user=user)
            ev.check(f'{label_text} remedy: {user} created again through the API as HA\'s admin (201)',
                     made.get('create_mqtt_user') in (200, 201) and [user, False] in (made.get('mqtt_users') or []),
                     {'code': made.get('create_mqtt_user')})
        restart_emqx(ev, f'{label_text} remedy')
        fixed = run_probe(ev, args, f'{label_text} after the remedy', 'file', tag, logins=others)
        mq, logins = fixed.get('mqtt') or {}, fixed.get('logins') or {}
        ha_names = [u['user_id'] for u in src['mqtt_users']]
        ev.check(f'{label_text} after the remedy: the bootstrap file brought woow back and it logs in with this '
                 'device\'s password, the account created again logs in with its password; HA\'s three users still log in',
                 mq.get('bootstrap_woow') == 0 and ['woow', False] in (fixed.get('mqtt_users') or [])
                 and sorted(logins) == others and all(logins.get(user) == 0 for user in others)
                 and all(mq.get(f'login_{u}') == 0 for u in ha_names),
                 {'woow': mq.get('bootstrap_woow'), 'others': logins, 'ha': {u: mq.get(f'login_{u}') for u in ha_names}})
        tested = True
    finally:
        if changed:
            manual_baseline(ev, args, label_text, tested)
            back = run_probe(ev, args, f'{label_text} after the baseline restore (own accounts)', 'base', own_mqtt=True,
                             logins=others)
            own_logins(ev, f'{label_text} after the baseline restore', back, own_ok=True, others=others)


def stable(probe):
    """The imported state without the counters a probe itself moves (rule metrics, retained $SYS messages)."""
    found = digest(probe)
    found.pop('native_counts', None)   # emqx_retainer_message moves with $SYS retained messages
    return found


def manual_baseline(ev, args, label_text, tested):
    """MANUAL rollback to the baseline: the test's own B0 through restore-start (the page's 還原)."""
    bjob, _blog, btook = restore_with(ev, drv.STATE['baseline_b0'], f'baseline-{slug(label_text)}')
    ev.check(f'{label_text}: manual rollback to the baseline (restore of B0) succeeded',
             bjob['state'] == 'succeeded', {'state': bjob['state'], 'error': bjob.get('error'), 'took_s': round(btook, 1),
                                            'after_full_chain': tested})
    base = run_probe(ev, args, f'{label_text} after the baseline restore', 'base')
    base_checks(ev, f'{label_text} after the baseline restore', base)
    markers(ev, f'{label_text} after the baseline restore')
    ev.check(f'{label_text} after the baseline restore: EMQX state digest equals the one before any import',
             digest(base) == drv.STATE['digest_before'], {'differs': diff_digest(digest(base), drv.STATE['digest_before'])})


def delete_created(ev, keep=()):
    present = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
    created = [b for b in drv.STATE.get('created_backups') or [] if b not in keep and b != BASELINE]
    deleted, refused = [], []
    for backup_id in created:
        if backup_id in present:
            rc, _reply = drv.helper('delete', {'backup_id': backup_id})
            (deleted if rc == 0 else refused).append(backup_id)
        else:
            deleted.append(backup_id)
    drv.STATE['created_backups'] = [b for b in drv.STATE.get('created_backups') or [] if b not in deleted]
    drv.save_state()
    left = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
    return deleted, refused, left


def step_cleanup(ev, args):
    objects = drv.labelled()
    ev.check('cleanup: no throwaway container, volume or network of a job left', not any(objects.values()), objects)
    listing = drv.device_python(drv.RUN_LIST, as_owner=False)
    staging = listing.get(drv.STAGING)
    keys = [n for n in listing.get('/run/woowtech-backup') or [] if isinstance(n, str) and n.startswith('key-')]
    ev.check('cleanup: no staging folder and no key file left', staging in ([], 'missing') and not keys, listing)
    if drv.STATE.get('own_entry'):
        step_catalog_own(ev, args)
    b0 = drv.STATE.get('baseline_b0')
    lab_made = {STORE_IDS[t] for t in LAB_MADE} & {h.get('id') for h in drv.ok('list', ev=ev).get('ha_backups') or []}
    if lab_made:
        codes = [drv.helper('ha-delete', {'ha_backup_id': store_id, 'confirm': True})[0] for store_id in sorted(lab_made)]
        listed = {h.get('id') for h in drv.ok('list', ev=ev).get('ha_backups') or []}
        ev.check('cleanup: the lab-made uploads (no ACL rows) are deleted from the HA store; the real uploads stay',
                 codes == [0] * len(lab_made) and not (lab_made & listed) and {STORE_IDS[t] for t in TAGS} <= listed,
                 {'deleted': len(lab_made), 'listed': len(listed)})
    deleted, refused, left = delete_created(ev, keep=(b0,) if b0 else ())
    ev.check('cleanup: the test\'s converted and safety backups are deleted (B0 and dev-d\'s own backups stay)',
             not refused and BASELINE in left and (not b0 or b0 in left) and not (left & set(deleted)),
             {'deleted': len(deleted), 'refused': refused})
    leftovers = stat_owner([*FAIL_FILES, *TAMPER_FILES])
    ev.check('cleanup: no fail-once or tamper drop-in, script or marker left', not any(leftovers.values()), leftovers)
    names = drv.out(drv.owner('podman', 'ps', '--format', '{{.Names}}')).split()
    ev.check('cleanup: woow-emqx and woow-emqx-entrance run, no job container exists',
             {'woow-emqx', 'woow-emqx-entrance'} <= set(names) and not [n for n in names if n.startswith('woowbk-j')],
             names)


def step_cleanup_baseline(ev, args):
    b0 = drv.STATE.get('baseline_b0')
    if b0:
        rc, _reply = drv.helper('delete', {'backup_id': b0})
        ev.check('cleanup-baseline: B0 deleted', rc == 0, b0)
        drv.STATE['created_backups'] = [b for b in drv.STATE.get('created_backups') or [] if b != b0]
        drv.STATE['baseline_b0'] = None
        drv.save_state()


def suggested_emqx(ev):
    reply = drv.ok('catalog-suggest', {'owner': 'appowner'}, ev=ev, timeout=600)
    return next((a for a in reply.get('apps') or [] if a.get('id') == 'emqx'), {})


def catalog_put(ev, entry, label_text):
    preview = drv.ok('catalog-install', {'entry': entry}, ev=ev, timeout=300)
    if not ev.check(f'{label_text}: catalog-install preview valid', preview.get('valid') is True, preview.get('error')):
        raise Failed('catalog-install preview refused')
    return drv.ok('catalog-install', {'entry': entry, 'confirm': True, 'expected_sha256': preview.get('expected_sha256')},
                  ev=ev, timeout=300)


def read_own_entry(ev, name):
    """dev-d's own installed EMQX entry and its SHA-256."""
    installed = suggested_emqx(ev).get('installed') or {}
    original = installed.get('entry')
    if not ev.check(f'{name}: dev-d\'s installed EMQX entry is read (catalog-suggest)',
                    isinstance(original, dict) and original.get('id') == 'emqx' and bool(installed.get('sha256')),
                    {'sha256': installed.get('sha256')}):
        raise Failed('no installed EMQX entry')
    ev.save('catalog-entry-original.json', original)
    return original, installed['sha256']


def install_fresh_draft(ev, name):
    """dev-d's EMQX entry is removed, a FRESH draft is scanned (nothing of the old entry is carried over) and installed
    unedited, as a customer does on the page."""
    preview = drv.ok('catalog-remove', {'id': 'emqx'}, ev=ev)
    drv.ok('catalog-remove', {'id': 'emqx', 'confirm': True, 'expected_sha256': preview['expected_sha256']}, ev=ev)
    fresh = suggested_emqx(ev)
    entry = fresh.get('entry') or {}
    ev.save('suggested-emqx.json', fresh)
    ev.check(f'{name}: a fresh draft asks the broker\'s public API through the entrance (/api/v5/error_codes, 200), not the '
             'container-only /readyz',
             [(h.get('url'), h.get('expect_status')) for h in entry.get('health') or []]
             == [('http://127.0.0.1:18083/api/v5/error_codes', 200)] and fresh.get('valid') is True, entry.get('health'))
    ev.check(f'{name}: the draft says why (/readyz answers 403 from the device)',
             any('/readyz' in h and '403' in h for h in fresh.get('hints') or []), fresh.get('hints'))
    catalog_put(ev, entry, f'{name}: the fresh draft')


def reinstall_own_entry(ev, name, original, sha256):
    done = catalog_put(ev, original, f'{name}: dev-d\'s own entry again')
    if not ev.check(f'{name}: dev-d\'s own EMQX entry is installed again (same SHA-256)', done.get('sha256') == sha256,
                    {'now': done.get('sha256')}):
        raise Failed('dev-d\'s own EMQX entry is not back')


def draft_installed(ev, label_text):
    """Between catalog-draft and catalog-own: prove that the installed entry is the page's own draft, unedited."""
    if drv.STATE.get('own_entry'):
        found = suggested_emqx(ev)
        ev.check(f'{label_text}: the installed EMQX entry is the page\'s own unedited draft (health check included)',
                 (found.get('installed') or {}).get('same') is True and bool((found.get('entry') or {}).get('health')),
                 {'changes': (found.get('installed') or {}).get('changes')})


def step_catalog_draft(ev, args):
    name = 'catalog-draft'
    if drv.STATE.get('own_entry'):
        raise Failed('a draft is installed already (catalog-own first)')
    original, sha256 = read_own_entry(ev, name)
    drv.STATE['own_entry'] = {'entry': original, 'sha256': sha256}
    drv.save_state()
    install_fresh_draft(ev, name)
    status = drv.ok('status', ev=ev)
    state = next((a for a in status.get('apps') or [] if a['id'] == 'emqx'), {})
    ev.check(f'{name}: status: emqx running, no problems, with the draft installed', state.get('state') == 'running'
             and not state.get('problems'), {k: state.get(k) for k in ('state', 'problems')})


def step_catalog_own(ev, args):
    own = drv.STATE.get('own_entry')
    if not own:
        raise Failed('no draft of this test is installed')
    reinstall_own_entry(ev, 'catalog-own', own['entry'], own['sha256'])
    drv.STATE['own_entry'] = None
    drv.save_state()


def step_suggest_health(ev, args):
    name = 'suggest-health'
    if drv.STATE.get('imported'):
        raise Failed('an imported state waits for its rollback step (rollback:TAG) first')
    if drv.STATE.get('own_entry'):
        raise Failed('a draft is installed already (catalog-own first)')
    before = digest(run_probe(ev, args, f'{name} before', 'base'))
    original, sha256 = read_own_entry(ev, name)
    try:
        install_fresh_draft(ev, name)
        job, log, took = run_job(ev, 'backup-start', {'apps': ['emqx'], 'note': 'emqx-product suggest-health'},
                                 'suggest-health-backup')
        backup_id = (job.get('result') or {}).get('backup_id')
        drv.created_backup(backup_id)
        if not ev.check(f'{name}: backup of EMQX with the proposed entry, its health check passed (no warning)',
                        job['state'] == 'succeeded' and bool(backup_id) and not job_log_has(log, '健康檢查未通過'),
                        {'state': job['state'], 'error': job.get('error'), 'took_s': round(took, 1)}):
            raise Failed('the backup with the proposed entry failed')
        rjob, rlog, rtook = restore_with(ev, backup_id, 'suggest-health-restore')
        result = rjob.get('result') or {}
        ev.check(f'{name}: a restore with the proposed health check succeeds and is not rolled back (health passed)',
                 rjob['state'] == 'succeeded' and result.get('rolled_back') is False
                 and job_log_has(rlog, '健康檢查通過'),
                 {'state': rjob['state'], 'error': rjob.get('error'), 'took_s': round(rtook, 1)})
    finally:
        reinstall_own_entry(ev, name, original, sha256)
    after = digest(run_probe(ev, args, f'{name} after', 'base'))
    ev.check(f'{name}: EMQX state digest equals the one before', after == before, {'differs': diff_digest(after, before)})


# The engine's whole state (records, requests, uploads, exports, pending, staging) instead of the b1 driver's list of
# paths, which names a file this engine does not have (index.json; attempt-22 stopped there). The backups themselves (.tar
# in archives/ and ha-backups/) stay out, as in the driver.
DRIVER_ROOTS = ('roots = ["/var/lib/woowtech-backup/jobs", "/var/lib/woowtech-backup/ha-backups", '
                '"/var/lib/woowtech-backup/ha-imports.json",\n'
                '         "/var/lib/woowtech-backup/index.json", "/var/lib/woowtech-backup/archives", "/run/woowtech-backup",\n'
                '         "/var/lib/woowtech-backup/uploads", "/var/lib/woowtech-backup/staging"]\n')
if drv.LEAK_SCAN.count(DRIVER_ROOTS) != 1:
    raise SystemExit('the b1 driver\'s leak scan changed: review its roots')
LEAK_SCAN = drv.LEAK_SCAN.replace(DRIVER_ROOTS, 'roots = ["/var/lib/woowtech-backup", "/run/woowtech-backup"]\n')
PROGRAMS['LEAK_SCAN'] = LEAK_SCAN
MEMORY_COUNTERS = ('cat /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.max; '
                   'grep -E "^(anon|file|shmem) " /sys/fs/cgroup/memory.stat; '
                   'grep -E "^(oom|oom_kill|oom_group_kill) " /sys/fs/cgroup/memory.events; '
                   'df -B1 --output=used /var/log/journal | tail -1')


def memory_counters():
    out = drv.out(drv.root('sh', '-c', MEMORY_COUNTERS, timeout=60)).split('\n')
    stats = dict(line.split() for line in out[2:5])
    events = dict(line.split() for line in out[5:8])
    return {'current': int(out[0]), 'max': int(out[1]), **{k: int(v) for k, v in stats.items()},
            'events': {k: int(v) for k, v in events.items()}, 'journal_used': int(out[8])}


def step_reclaim(ev, args):
    before = memory_counters()
    vacuum = drv.root('journalctl', '--vacuum-time=24h', timeout=180)
    rounds = 0
    # Clean page cache only (swappiness 0), 128 MiB at a time, until 2.5 GiB of headroom or the kernel gives nothing more.
    while rounds < 12 and (lambda c: c['max'] - c['current'])(memory_counters()) < 2560 * 1024 * 1024:
        rounds += 1
        proc = drv.root('sh', '-c', 'echo "128M swappiness=0" > /sys/fs/cgroup/memory.reclaim', timeout=120)
        if proc.returncode != 0:
            break
    after = memory_counters()
    ev.save('reclaim.json', {'before': before, 'after': after, 'rounds': rounds})
    emit(f'dev-d reclaim headroom_before={before["max"] - before["current"]} headroom_after={after["max"] - after["current"]} '
         f'journal_before={before["journal_used"]} journal_after={after["journal_used"]} rounds={rounds}')
    ev.check('reclaim: journalctl --vacuum-time=24h and bounded clean-cache reclaim (limit unchanged, no OOM event)',
             vacuum.returncode == 0 and before['max'] == after['max'] and before['events'] == after['events'],
             {'rounds': rounds})


def step_leaks(ev, args):
    load_kit(args)
    since = drv.STATE.get('run_started') or int(time.time()) - 6 * 3600
    request = {'secrets': {n: args.secrets[n] for n in LANE_SECRETS if args.secrets.values.get(n)},
               'podman_secrets': EMQX_SECRETS, 'uid': OWNER_UID, 'since': int(since)}
    if len(request['secrets']) != len(LANE_SECRETS):
        raise Failed('a lane secret is missing from the readers')
    issued = {k: v for k, v in args.secrets.values.items() if k.startswith('ISSUED_TOKEN_') and v}
    request['secrets'].update(issued)
    logins = getattr(args, 'logins', 0)
    ev.check(f'leaks: every Dashboard token issued to this run\'s probes ({len(issued)}) is in the scan (one per successful '
             'login)', len(issued) == logins, {'issued_values': len(issued), 'successful_logins': logins})
    report = drv.device_python(LEAK_SCAN, request, as_owner=False, timeout=900)
    host = drv.scan_host_evidence(ev.dir, args.secrets)
    ev.save('leaks.json', {'device': report, 'host': host})
    ev.check('leaks: no test secret, HA key, kit, dev-d EMQX secret or issued token in engine records, logs, journal or '
             'evidence', isinstance(report, dict) and report.get('hits') == 0 and report.get('scanned', 0) > 0
             and host.get('hits') == 0, {'device': {k: report.get(k) for k in ('scanned', 'names', 'hits')},
                                         'host': host})


HOT_TAGS = ('arm-enc', 'x86-enc')
HOT_STORE_IDS = {'arm-enc': 'ha-6d0647f0acb2e0d95043', 'x86-enc': 'ha-f82422e327f151ec819d'}


def step_check_hot(ev, args):
    """The encrypted backups made while EMQX ran: the check names the hot backup (warning, or the stop-the-add-on
    advice as its blocker when HA's database did not load) -- the hint stays."""
    key = args.secrets['HA_BACKUP_KEY']
    for tag in HOT_TAGS:
        store_id = HOT_STORE_IDS[tag]
        meta = json.loads(drv.out(drv.root('cat', f'/var/lib/woowtech-backup/ha-backups/{store_id}.json', check=True)))
        local = drv.STATE.setdefault('fixture_sha256', {}).get(tag) or sha256_file(fixture_path(tag))
        drv.STATE['fixture_sha256'][tag] = local
        if not ev.check(f'store {tag}: the stored HA file is the real fixture (SHA-256 equal, id from it)',
                        meta.get('sha256') == local and store_id == 'ha-' + local[:20], {'store': store_id}):
            continue
        job, took = drv.run_check(store_id, ['emqx'], ev=ev, key=key, tag=f'check-{tag}-emqx')
        ev.time('check', tag, 'emqx', took, job)
        label_text = f'check {tag}/emqx (hot backup)'
        if not ev.check(f'{label_text}: job succeeded', job['state'] == 'succeeded', f'{took:.0f} s {job.get("error")}'):
            continue
        result = job['result']['ha_check']['apps'][0]
        ev.save(f'check-{tag}-emqx.json', result)
        warnings, blockers = result.get('warnings') or [], result.get('blockers') or []
        section = result.get('emqx') or {}
        # dev-d's own target is [file]: HA's ACL rows add decision C's blocker, so `ok` alone says nothing here.
        named = ((any('執行中製作' in w for w in warnings) and section.get('hot_backup') is True)
                 or (result.get('ok') is False and any('停止 EMQX 附加元件' in b for b in blockers)))
        ev.check(f'{label_text}: the hot backup is named (warning, or the stop-the-add-on advice as the blocker)',
                 named, {'ok': result.get('ok'), 'blockers': blockers, 'warnings': warnings})
        if isinstance(section.get('acl_rules'), int) and section['acl_rules'] > 0 and section.get('target_authorization') == ['file']:
            ev.check(f'{label_text}: HA\'s ACL rows on this file-only target also give the decision-C blocker',
                     result.get('ok') is False and OWNER_ACL_TEXT in blockers, blockers)


STEPS = {'setup': step_setup, 'before': step_before, 'check': step_check, 'check-hot': step_check_hot,
         'suggest-health': step_suggest_health, 'catalog-draft': step_catalog_draft, 'catalog-own': step_catalog_own,
         'cleanup': step_cleanup, 'reclaim': step_reclaim,
         'cleanup-baseline': step_cleanup_baseline, 'leaks': step_leaks}


def parse_step(name):
    if name in STEPS:
        return name, None, None
    parts = name.split(':')
    if len(parts) == 3 and parts[0] == 'import' and parts[1] in TAGS and parts[2] in MODES:
        return 'import', parts[1], parts[2]
    if len(parts) == 3 and parts[0] == 'import' and parts[1] in LAB_MADE and parts[1] not in SR5 and parts[2] == 'file':
        return 'import', parts[1], 'file'
    if len(parts) == 2 and parts[0] == 'rollback' and parts[1] in TAGS:
        return 'rollback', parts[1], 'builtin'
    if len(parts) == 2 and parts[0] == 'rollback' and parts[1] in LAB_MADE and parts[1] not in SR5:
        return 'rollback', parts[1], 'file'
    if len(parts) == 2 and parts[0] == 'sr5' and parts[1] in SR5:
        return 'sr5', parts[1], 'file'
    return None, None, None


# Minutes a step is expected to hold dev-d (measured 2026-11-23/24: the slowest full import chain took 988 s under host
# load ~50, the slowest rollback rounds 723 s; refined after each attempt):
# a step only starts when the hold so far plus its estimate stays within HOLD_LIMIT.
HOLD_LIMIT = 40 * 60
SHORT_STEP = 5 * 60
ESTIMATE = {'setup': 6, 'before': 6, 'check': 12, 'check-hot': 12, 'import:file': 15, 'import:builtin': 22, 'import:first': 28,
            'rollback': 24, 'suggest-health': 10, 'catalog-draft': 3, 'catalog-own': 2, 'cleanup': 4, 'cleanup-baseline': 2, 'reclaim': 3, 'leaks': 4,
            'sr5:plain': 10, 'sr5:bcrypt': 31}


def estimate(name):
    kind, tag, mode = parse_step(name)
    if kind == 'sr5':
        kind = f'sr5:{SR5[tag]}'
    if kind == 'import':
        kind = 'import:builtin' if tag in LAB_MADE else f'import:{mode}'   # the whole chain, or the short refusal
        if kind == 'import:builtin' and tag in FIRST_ROUNDS:
            kind = 'import:first'
    return 60 * ESTIMATE[kind]


def hold_spent(index, spent, name):
    """No new step that would pass HOLD_LIMIT (40 min); after HOLD_BUDGET only the short closing steps (reclaim, leaks,
    catalog-own, cleanup, at most 5 minutes) still start, so that a slow import on a loaded host keeps its leak scan."""
    if index and spent + estimate(name) > HOLD_LIMIT:
        return True
    return spent > HOLD_BUDGET and estimate(name) > SHORT_STEP


def self_check():
    for name, program in PROGRAMS.items():
        compile(program, name, 'exec')
    for tag in TAGS:
        assert drv.UPLOADS[tag][3] == ('emqx',) and drv.UPLOADS[tag][2] is True and drv.UPLOADS[tag][4] is False
        assert STORE_IDS[tag] == 'ha-' + FIXTURE_SHA256[tag][:20]
    print(f'offline self-check passed: {len(PROGRAMS)} embedded programs compiled, {len(TAGS)} cold uploads known')


ANONYMOUS_RE = re.compile(r'[0-9a-f]{64}')   # podman's generated name of an anonymous volume


def dangling_volumes():
    """Names of dev-d's owner ANONYMOUS volumes (podman's generated 64 hex digits) and of job volumes (woowbk-*) that no
    container uses: a throwaway whose image VOLUME path had no mount leaves one behind (2026-11-24: one per EMQX check
    and conversion before be5bc6f). Another app's NAMED volume is no such leftover: it counts as dangling whenever that
    app's container is absent, and dev-d's headscale.service has been restarting in a loop for days (attempt-21: its
    headscale-data and headscale-run appeared as 2 "new" ones within the 24 s of a setup step, with 97 anonymous
    volumes before and after). Names only, never contents."""
    proc = drv.owner('podman', 'volume', 'ls', '--filter', 'dangling=true', '--format', '{{.Name}}', timeout=120)
    if proc.returncode:
        raise Failed('cannot list dev-d\'s dangling volumes')
    return {name for name in drv.out(proc).split() if ANONYMOUS_RE.fullmatch(name) or name.startswith('woowbk-')}


def main(argv):
    if argv == ['--self-check']:
        self_check()
        return 0
    steps = argv
    if not steps or any(parse_step(s)[0] is None for s in steps):
        print('usage: emqx_product_real_ha.py <setup|before|check|check-hot|import:TAG:MODE|rollback:TAG|sr5:TAG|suggest-health|catalog-draft|catalog-own|cleanup|cleanup-baseline|reclaim|leaks> ...',
              file=sys.stderr)
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
        for index, name in enumerate(steps):
            spent = time.monotonic() - held
            if hold_spent(index, spent, name):
                emit(f'STEP {name}: SKIP hold_budget=1')
                failed_steps.append(name)
                continue
            try:
                if name != 'reclaim':
                    headroom()
            except Failed as error:
                ev.check(f'{name}: headroom before the step', False, str(error))
                emit(f'STEP {name}: SKIP headroom=1')
                failed_steps.append(name)
                break
            ev.log(f'== {name}')
            started = time.monotonic()
            kind, tag, mode = parse_step(name)
            try:
                left_before = dangling_volumes()
            except Failed:
                left_before = None
            try:
                if kind == 'import':
                    step_import(ev, args, tag, mode)
                elif kind == 'rollback':
                    step_rollback(ev, args, tag)
                elif kind == 'sr5':
                    step_sr5(ev, args, tag)
                else:
                    STEPS[kind](ev, args)
            except Failed as error:
                ev.check(f'{name}: step ran to the end', False, str(error))
            except Exception as error:  # noqa: BLE001 - recorded (type only), the lock is still released below
                ev.check(f'{name}: step ran to the end', False, f'{type(error).__name__}')
            finally:
                drv.save_state()
            try:
                if left_before is None:
                    raise Failed('cannot list dev-d\'s dangling volumes before the step')
                new = dangling_volumes() - left_before
                ev.check(f'{name}: no anonymous volume left on dev-d (every image VOLUME path of a throwaway mounted)',
                         not new, {'new_dangling_volumes': len(new)})
            except Failed as error:
                ev.check(f'{name}: no anonymous volume left on dev-d', False, str(error))
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
