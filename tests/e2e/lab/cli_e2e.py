#!/usr/bin/env python3
"""CLI-level end-to-end runner for backup & restore in the lab devices (integrator).

Every engine call is made the way the Cockpit page makes it: the installed helper
`/usr/local/libexec/woowtech-cockpit-backup <command>` runs as root inside the device, the request
JSON goes to stdin and exactly one JSON object comes back on stdout. Downloads and uploads use the
device's real `cockpit-bridge` (run as root, like the superuser bridge): `fsread1` (binary raw,
max_read_size -1) for the download and `fsreplace1` with `size` + `"send-acks": "bytes"`, 64 KiB
frames and at most 2 MiB unacknowledged for the upload, exactly the channel options the page uses.

    python3 -I tests/e2e/lab/cli_e2e.py s1        # dev-a: key, seed, backup (+images), mutate, in-place restore
    python3 -I tests/e2e/lab/cli_e2e.py s2        # A -> B: download, upload, key-required, kit key, fresh restore
    python3 -I tests/e2e/lab/cli_e2e.py faults    # truncated/flipped/foreign uploads, verify, F12
    python3 -I tests/e2e/lab/cli_e2e.py s3        # backup without images; dev-b torn down -> preflight fails, nothing changes
    python3 -I tests/e2e/lab/cli_e2e.py s2-again  # S2 again onto the torn-down dev-b (leaves it restored)
    python3 -I tests/e2e/lab/cli_e2e.py f8        # restore fails after the destructive step -> automatic rollback
    python3 -I tests/e2e/lab/cli_e2e.py f9        # SIGKILL a restore -> interrupted; the safety backup restores the app
    python3 -I tests/e2e/lab/cli_e2e.py cancel    # cancel a backup while packaging: nothing listed, writers running
    python3 -I tests/e2e/lab/cli_e2e.py leaks     # secrets/keys never in job records, logs, index or journal
    python3 -I tests/e2e/lab/cli_e2e.py all

Key material: dev-a's emergency kit is a throwaway lab key stored at
~/.woowbk-lab/secrets/dev-a-kit.txt (0600). The secret only travels in the stdin field `key`;
nothing secret is printed or written to the evidence directory (~/.woowbk-lab/evidence/integration/).
Only labpodman is used; nothing on the host's own Podman is touched.
"""
import argparse
import hashlib
import json
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

LAB = Path.home() / '.woowbk-lab'
LP = str(LAB / 'bin' / 'labpodman')
SECRETS_DIR = LAB / 'secrets'
KIT_FILE = SECRETS_DIR / 'dev-a-kit.txt'
DOWNLOADS = LAB / 'downloads'
EVIDENCE = LAB / 'evidence' / 'integration'
STATE_FILE = EVIDENCE / 'state.json'
HELPER = '/usr/local/libexec/woowtech-cockpit-backup'
OWNER_WRAPPER = '/usr/local/bin/woowbk-owner'
DEVICES = {'a': {'name': 'woowbk-dev-a', 'uid': 1001}, 'b': {'name': 'woowbk-dev-b', 'uid': 1007}}
APP = 'woowbk-demo'
APP_URL = 'http://127.0.0.1:18090'
SECRET_RE = re.compile(r'AGE-SECRET-KEY-1[0-9A-Za-z]+')
CHUNK = 64 * 1024
WINDOW = 2 * 1024 * 1024
COMPARE = ('notes', 'files', 'digest', 'title', 'signatures_valid')


class Failed(Exception):
    pass


# ------------------------------------------------------------------ evidence

def redact(value):
    if isinstance(value, dict):
        return {k: ('<redacted>' if k in ('key', 'content') and isinstance(v, str) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return SECRET_RE.sub('[secret]', value)
    return value


class Evidence:
    def __init__(self, scenario):
        stamp = time.strftime('%Y%m%dT%H%M%S')
        self.dir = EVIDENCE / f'{stamp}-{scenario}'
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.dir / 'driver.log'
        self.checks = []
        self.timings = {}
        self.t0 = time.monotonic()

    def log(self, message):
        line = f'{time.strftime("%H:%M:%S")} +{time.monotonic() - self.t0:7.1f}s {redact(str(message))}'
        print(line, flush=True)
        with open(self.log_path, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')

    def save(self, name, obj):
        path = self.dir / f'{name}.json'
        path.write_text(json.dumps(redact(obj), ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
        return path

    def check(self, name, condition, detail=''):
        ok = bool(condition)
        self.checks.append({'check': name, 'ok': ok, 'detail': redact(str(detail))[:600]})
        self.log(f'{"PASS" if ok else "FAIL"} {name}' + (f' -- {detail}' if detail else ''))
        return ok

    def require(self, name, condition, detail=''):
        if not self.check(name, condition, detail):
            raise Failed(name)

    def finish(self, extra=None):
        passed = sum(1 for c in self.checks if c['ok'])
        result = {'checks': self.checks, 'passed': passed, 'total': len(self.checks), 'timings': self.timings,
                  **(extra or {})}
        self.save('result', result)
        self.log(f'RESULT {passed}/{len(self.checks)} checks passed; evidence in {self.dir}')
        return passed == len(self.checks)


def load_state():
    try:
        return json.loads(STATE_FILE.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


def save_state(**fields):
    state = load_state()
    state.update(fields)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(redact(state), ensure_ascii=False, indent=1) + '\n', encoding='utf-8')


def write_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(data)


# ------------------------------------------------------------------ device access

def dev_name(dev):
    return DEVICES[dev]['name']


def helper(dev, command, request=None, *, timeout=1200, ev=None):
    """One helper call as the page makes it; returns (exit code, reply object)."""
    data = b'' if request is None else json.dumps(request, ensure_ascii=False).encode('utf-8')
    proc = subprocess.run([LP, 'exec', '-i', dev_name(dev), HELPER, command], input=data, capture_output=True,
                          timeout=timeout)
    lines = [line for line in proc.stdout.decode('utf-8', 'replace').splitlines() if line.strip()]
    if len(lines) != 1:
        raise Failed(f'{command}: expected exactly one JSON line on stdout, got {len(lines)} '
                     f'(rc={proc.returncode}, stderr={redact(proc.stderr.decode("utf-8", "replace")[-400:])})')
    reply = json.loads(lines[0])
    if (proc.returncode == 0) != (reply.get('ok') is True) or proc.returncode not in (0, 1):
        raise Failed(f'{command}: exit code {proc.returncode} does not match ok={reply.get("ok")}')
    if ev is not None:
        shown = redact(reply)
        if not reply.get('ok'):
            ev.log(f'helper {command} -> rc={proc.returncode} error={shown.get("error")}')
        if proc.stderr.strip():
            ev.log(f'helper {command} stderr tail: {redact(proc.stderr.decode("utf-8", "replace")[-600:])}')
    return proc.returncode, reply


def ok(dev, command, request=None, *, ev, timeout=1200):
    rc, reply = helper(dev, command, request, timeout=timeout, ev=ev)
    if rc != 0:
        raise Failed(f'{command} failed: {redact(reply.get("error"))}')
    return reply


def sh(dev, script, *, input=None, timeout=600, check=True):
    proc = subprocess.run([LP, 'exec', '-i', dev_name(dev), 'sh', '-c', script], input=input, capture_output=True,
                          timeout=timeout)
    if check and proc.returncode != 0:
        raise Failed(f'device {dev}: `{script[:120]}` failed rc={proc.returncode}: '
                     f'{redact(proc.stderr.decode("utf-8", "replace")[-400:])}')
    return proc


def owner(dev, *argv, input=None, timeout=600, check=True):
    proc = subprocess.run([LP, 'exec', '-i', dev_name(dev), OWNER_WRAPPER, *argv], input=input, capture_output=True,
                          timeout=timeout)
    if check and proc.returncode != 0:
        raise Failed(f'device {dev} owner `{" ".join(argv)[:120]}` failed rc={proc.returncode}: '
                     f'{redact(proc.stderr.decode("utf-8", "replace")[-400:])}')
    return proc


def app_get(dev, path, timeout=20):
    proc = sh(dev, f'curl -sS --max-time {timeout} -o - -w "\\n%{{http_code}}" {APP_URL}{path}', check=False,
              timeout=timeout + 30)
    body, _, status = proc.stdout.decode('utf-8', 'replace').rpartition('\n')
    return int(status or 0), body


def app_json(dev, path):
    status, body = app_get(dev, path)
    if status != 200:
        raise Failed(f'GET {path} on dev-{dev} -> HTTP {status}')
    return json.loads(body)


def app_post(dev, path, data, content_type):
    proc = sh(dev, f'curl -sS --max-time 30 -o - -w "\\n%{{http_code}}" -X POST -H "Content-Type: {content_type}" '
                   f'--data-binary @- "{APP_URL}{path}"', input=data, check=False, timeout=90)
    body, _, status = proc.stdout.decode('utf-8', 'replace').rpartition('\n')
    return int(status or 0), body


def summary(dev):
    return app_json(dev, '/api/summary')


def content_state(dev):
    """Full content (notes with signatures, file names + sha256): stronger than the digest alone."""
    notes = app_json(dev, '/api/notes')['notes']
    files = app_json(dev, '/api/files')['files']
    return {'notes': sorted([n['id'], n['title'], n['body'], n['signature']] for n in notes),
            'files': sorted([f['name'], f['size'], f['sha256']] for f in files)}


def wait_healthy(dev, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if app_get(dev, '/healthz', timeout=5)[0] == 200:
            return True
        time.sleep(2)
    return False


def request_id():
    return str(uuid.uuid4())  # what the page sends (crypto.randomUUID())


def wait_job(dev, job_id, *, ev, timeout=1800, label='job'):
    """Poll job-status every 1.5 s like the page; logs every phase change; returns (job, log lines)."""
    deadline = time.monotonic() + timeout
    seen_phase, seen_message, started = None, None, time.monotonic()
    phase_times = {}
    while True:
        _rc, reply = helper(dev, 'job-status', {'job_id': job_id}, ev=ev)
        if not reply.get('ok'):
            raise Failed(f'job-status failed: {redact(reply.get("error"))}')
        job = reply['job']
        if job.get('phase') != seen_phase:
            seen_phase = job.get('phase')
            phase_times[seen_phase] = round(time.monotonic() - started, 1)
            ev.log(f'{label} {job_id}: state={job["state"]} phase={seen_phase} '
                   f'progress={job["progress"].get("percent")}% cancellable={job.get("cancellable")}')
        message = job['progress'].get('message')
        if message != seen_message:
            seen_message = message
        if job['state'] not in ('queued', 'running'):
            ev.log(f'{label} {job_id}: finished state={job["state"]} after {time.monotonic() - started:.1f}s '
                   f'error={redact(job.get("error"))}')
            job['_phase_first_seen_s'] = phase_times
            return job, reply.get('log') or []
        if time.monotonic() > deadline:
            raise Failed(f'{label} {job_id} still {job["state"]} after {timeout}s')
        time.sleep(1.5)


class HealthMonitor:
    """Samples GET /healthz inside the device every 0.25 s; reports the longest unhealthy window."""

    CODE = r'''
import json, sys, time, urllib.request, urllib.error
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
end = time.time() + float(sys.argv[1])
while time.time() < end:
    t = time.time()
    try:
        with opener.open("http://127.0.0.1:18090/healthz", timeout=2) as r:
            s = r.status
    except urllib.error.HTTPError as e:
        s = e.code
    except Exception:
        s = 0
    print(json.dumps([round(t, 3), s]), flush=True)
    time.sleep(0.25)
'''

    def __init__(self, dev, seconds):
        self.dev = dev
        self.proc = subprocess.Popen([LP, 'exec', '-i', dev_name(dev), 'python3', '-I', '-c', self.CODE, str(seconds),
                                      'woowbk-e2e-monitor'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL)
        self.samples = []
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        for line in self.proc.stdout:
            try:
                self.samples.append(json.loads(line))
            except ValueError:
                pass

    def stop(self):
        sh(self.dev, 'pkill -f woowbk-e2e-monitor || true', check=False)
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.thread.join(timeout=5)
        longest, start, total_bad = 0.0, None, 0
        for t, status in self.samples:
            if status != 200:
                total_bad += 1
                start = t if start is None else start
            elif start is not None:
                longest = max(longest, t - start)
                start = None
        if start is not None and self.samples:
            longest = max(longest, self.samples[-1][0] - start)
        return {'samples': len(self.samples), 'unhealthy_samples': total_bad, 'longest_unhealthy_s': round(longest, 2),
                'ended_healthy': bool(self.samples) and self.samples[-1][1] == 200}


# ------------------------------------------------------------------ cockpit-bridge channels

class Bridge:
    """The device's real cockpit-bridge over stdio, as root (what superuser: "require" channels reach)."""

    def __init__(self, dev):
        self.proc = subprocess.Popen([LP, 'exec', '-i', dev_name(dev), 'cockpit-bridge'], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.lock = threading.Lock()
        self.controls = queue.Queue()
        self.sinks = {}
        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()
        init = self.next_control({'init'}, timeout=60)
        if init.get('version') != 1:
            raise Failed(f'unexpected bridge init {init}')
        self.control(command='init', version=1, host='localhost')

    def _frame(self, channel, payload):
        data = channel.encode() + b'\n' + payload
        with self.lock:
            self.proc.stdin.write(str(len(data)).encode() + b'\n' + data)
            self.proc.stdin.flush()

    def control(self, **message):
        self._frame('', json.dumps(message).encode())

    def send(self, channel, payload):
        self._frame(channel, payload)

    def _read_exact(self, size):
        chunks, left = [], size
        while left:
            chunk = self.proc.stdout.read(left)
            if not chunk:
                raise EOFError
            chunks.append(chunk)
            left -= len(chunk)
        return b''.join(chunks)

    def _read_loop(self):
        try:
            while True:
                length = b''
                while not length.endswith(b'\n'):
                    ch = self.proc.stdout.read(1)
                    if not ch:
                        raise EOFError
                    length += ch
                data = self._read_exact(int(length))
                channel, _, payload = data.partition(b'\n')
                channel = channel.decode()
                if channel == '':
                    message = json.loads(payload)
                    if message.get('command') == 'ping':
                        self.control(**{**message, 'command': 'pong'})
                        continue
                    self.controls.put(message)
                else:
                    sink = self.sinks.get(channel)
                    if sink is not None:
                        sink(payload)
        except (EOFError, ValueError, OSError):
            self.controls.put({'command': '_eof'})

    def next_control(self, wanted=None, timeout=600):
        deadline = time.monotonic() + timeout
        while True:
            message = self.controls.get(timeout=max(0.1, deadline - time.monotonic()))
            if message.get('command') == '_eof':
                raise Failed('cockpit-bridge exited: ' + self.proc.stderr.read().decode('utf-8', 'replace')[-400:])
            if wanted is None or message.get('command') in wanted:
                return message

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def bridge_download(dev, path, dest, *, ev):
    """fsread1 {binary: raw, max_read_size: -1}: the options of the page's external download channel."""
    bridge = Bridge(dev)
    digest, size = hashlib.sha256(), [0]
    write_private(dest, b'')
    handle = open(dest, 'wb')

    def sink(payload):
        handle.write(payload)
        digest.update(payload)
        size[0] += len(payload)

    bridge.sinks['d1'] = sink
    started = time.monotonic()
    bridge.control(command='open', channel='d1', payload='fsread1', path=path, binary='raw', max_read_size=-1,
                   superuser='require', **{'flow-control': True})
    hint = None
    while True:
        message = bridge.next_control()
        if message.get('channel') != 'd1':
            continue
        if message.get('command') == 'ready':
            hint = message.get('size-hint')
        if message.get('command') == 'close':
            break
    handle.close()
    bridge.close()
    elapsed = time.monotonic() - started
    if message.get('problem'):
        raise Failed(f'fsread1 closed with problem {message.get("problem")}')
    ev.log(f'download via fsread1: {size[0]} bytes in {elapsed:.1f}s, size-hint={hint}')
    return {'bytes': size[0], 'sha256': digest.hexdigest(), 'seconds': round(elapsed, 1), 'size_hint': hint}


def bridge_upload(dev, path, source, *, ev, truncate_to=None, flip_at=None):
    """fsreplace1 {size, send-acks: bytes}, 64 KiB frames, <= 2 MiB unacknowledged, done, wait for close."""
    total = os.path.getsize(source) if truncate_to is None else truncate_to
    bridge = Bridge(dev)
    started = time.monotonic()
    bridge.control(command='open', channel='u1', payload='fsreplace1', path=path, binary='raw', size=total,
                   superuser='require', **{'send-acks': 'bytes', 'flow-control': True})
    first = bridge.next_control({'ready', 'close'})
    if first.get('command') == 'close':
        raise Failed(f'fsreplace1 refused: {first}')
    sent = acked = acks = 0
    max_unacked = 0
    with open(source, 'rb') as handle:
        while sent < total:
            while sent - acked >= WINDOW:
                message = bridge.next_control({'ack', 'close'})
                if message.get('command') == 'close':
                    raise Failed(f'fsreplace1 closed early: {message}')
                acked += int(message.get('bytes') or 0)
                acks += 1
            chunk = handle.read(min(CHUNK, total - sent))
            if not chunk:
                break
            if flip_at is not None and sent <= flip_at < sent + len(chunk):
                mutable = bytearray(chunk)
                mutable[flip_at - sent] ^= 0x01
                chunk = bytes(mutable)
            bridge.send('u1', chunk)
            sent += len(chunk)
            max_unacked = max(max_unacked, sent - acked)
    bridge.control(command='done', channel='u1')
    closed = None
    while closed is None:
        message = bridge.next_control({'ack', 'close', 'done'})
        if message.get('command') == 'ack':
            acked += int(message.get('bytes') or 0)
            acks += 1
        elif message.get('command') == 'close':
            closed = message
    bridge.close()
    elapsed = time.monotonic() - started
    if closed.get('problem'):
        raise Failed(f'fsreplace1 closed with problem {closed.get("problem")}')
    ev.log(f'upload via fsreplace1: sent {sent} bytes, acked {acked} in {acks} acks, max unacked {max_unacked}, '
           f'{elapsed:.1f}s')
    return {'sent': sent, 'acked': acked, 'acks': acks, 'max_unacked': max_unacked, 'seconds': round(elapsed, 1)}


# ------------------------------------------------------------------ helpers for the scenarios

def kit_secret():
    text = KIT_FILE.read_text(encoding='utf-8')
    found = SECRET_RE.findall(text)
    if len(found) != 1:
        raise Failed('the kit file must contain exactly one secret key line')
    return found[0]


def compare(a, b):
    return {k: (a.get(k), b.get(k)) for k in COMPARE if a.get(k) != b.get(k)}


def phase_states(job):
    return {p['id']: p['state'] for p in job['phases']}


def log_window(lines, start_marker, end_marker):
    """Seconds between the first log line containing start_marker and the first later one with end_marker."""
    def ts(line):
        try:
            return time.mktime(time.strptime(line[:20], '%Y-%m-%dT%H:%M:%SZ'))
        except ValueError:
            return None
    start = None
    for line in lines:
        if start is None and start_marker in line:
            start = ts(line)
        elif start is not None and end_marker in line:
            end = ts(line)
            return None if end is None or start is None else end - start
    return None


def archive_list(dev):
    proc = sh(dev, 'ls -l --time-style=+%s /var/lib/woowtech-backup/archives/ /var/lib/woowtech-backup/uploads/ '
                   '/var/lib/woowtech-backup/staging/ /run/woowtech-backup/ 2>&1', check=False)
    return proc.stdout.decode('utf-8', 'replace')


# ------------------------------------------------------------------ S1

def scenario_s1(ev):
    dev = 'a'
    _rc, status = helper(dev, 'status', ev=ev)
    ev.save('s1-status-before', status)
    app = next((a for a in status.get('apps', []) if a['id'] == APP), None)
    ev.require('S1 status ok, app deployed and running on dev-a',
               status.get('ok') and app and app['deployed'] and app['state'] == 'running', app)

    # Key setup as the page does it: key-init -> key-kit (kit shown/downloaded) -> key-confirm.
    reply = ok(dev, 'key-init', ev=ev)
    key_id = reply['key']['key_id']
    ev.check('key-init returns key{key_id,created,kit_confirmed} + created(bool)',
             re.fullmatch(r'[0-9A-F]{4}(-[0-9A-F]{4}){3}', key_id) and isinstance(reply['created'], bool), redact(reply))
    again = ok(dev, 'key-init', ev=ev)
    ev.check('key-init is idempotent (same key, created=false)', again['key']['key_id'] == key_id and not again['created'])
    kit = ok(dev, 'key-kit', ev=ev)
    content = kit['content']
    ev.check('key-kit returns key_id, filename and kit text with exactly one secret line and the key id',
             kit['key_id'] == key_id and kit['filename'].endswith('.txt') and len(SECRET_RE.findall(content)) == 1
             and key_id in content, f'filename={kit["filename"]}')
    write_private(KIT_FILE, content.encode('utf-8'))
    ev.log(f'kit saved to {KIT_FILE} (0600, throwaway lab key, not shown)')
    ok(dev, 'key-confirm', {'key_id': key_id}, ev=ev)
    status = ok(dev, 'status', ev=ev)
    ev.check('status.key shows kit_confirmed after key-confirm', status['key'] and status['key']['kit_confirmed'] is True
             and status['key']['key_id'] == key_id, status['key'])

    # Known data.
    seed = owner(dev, 'python3', '/opt/woowbk-demo/tools/seed.py', '--notes', '3', '--files', '2', '--seed', '20261113',
                 timeout=600)
    seeded = json.loads(seed.stdout)
    ev.log(f'seeded batch {seeded["batch"]}: +{len(seeded["notes_added"])} notes, +{len(seeded["files_added"])} files')
    snapshot = summary(dev)
    content_before = content_state(dev)
    ev.save('s1-snapshot', {'summary': snapshot, 'content': content_before})
    ev.log(f'snapshot before backup: {snapshot}')

    # Backup with images, request_id deduplication on a retry (F10).
    request = {'apps': [APP], 'include_images': True, 'note': 'S1 整合測試（含映像）', 'request_id': request_id()}
    monitor = HealthMonitor(dev, 900)
    t0 = time.monotonic()
    start = ok(dev, 'backup-start', request, ev=ev)
    retry = ok(dev, 'backup-start', request, ev=ev)
    ev.check('F10 retry with the same request_id returns the same job (deduplicated=true)',
             retry['job_id'] == start['job_id'] and retry['deduplicated'] is True and start['deduplicated'] is False,
             f'{start} / {retry}')
    _rc, busy = helper(dev, 'backup-start', {**request, 'request_id': request_id()}, ev=ev)
    ev.check('F10 a different request while the job runs is refused with busy + details.job_id',
             not busy['ok'] and busy['error']['code'] == 'busy'
             and busy['error']['details'].get('job_id') == start['job_id'], busy.get('error'))
    job, log = wait_job(dev, start['job_id'], ev=ev, label='backup')
    backup_wall = time.monotonic() - t0
    health = monitor.stop()
    ev.save('s1-backup-job', {'job': job, 'log': log, 'health_monitor': health})
    ev.require('S1 backup job succeeded', job['state'] == 'succeeded', job.get('error'))
    result = job['result']
    backup_id = result['backup_id']
    ev.check('backup phases all done', all(s == 'done' for s in phase_states(job).values()), phase_states(job))
    ev.check('backup result has backup_id, size, apps, downtime_seconds',
             set(result) >= {'backup_id', 'size', 'apps', 'downtime_seconds'} and result['apps'] == [APP], result)
    ev.check('backup job log never contains key material', not any(SECRET_RE.search(line) for line in log))
    ev.timings['s1_backup_wall_s'] = round(backup_wall, 1)
    ev.timings['s1_backup_size_bytes'] = result['size']
    ev.timings['s1_backup_downtime_reported_s'] = result['downtime_seconds']
    ev.timings['s1_backup_healthz_longest_unhealthy_s'] = health['longest_unhealthy_s']
    ev.log(f'backup {backup_id}: {result["size"]} bytes, {backup_wall:.1f}s wall, reported downtime '
           f'{result["downtime_seconds"]}s, healthz longest unhealthy {health["longest_unhealthy_s"]}s')
    ev.check('app healthy again after the backup', health['ended_healthy'] and wait_healthy(dev, 60), health)
    ev.check('backup did not change application data', compare(summary(dev), snapshot) == {})

    listed = ok(dev, 'list', ev=ev)['backups']
    meta = next((b for b in listed if b['id'] == backup_id), None)
    ev.save('s1-list-after-backup', listed)
    ev.require('list shows the new backup', meta is not None)
    ev.check('BackupMeta: manual, key available, images included, verified ok, inspected, size/sha256',
             meta['type'] == 'manual' and meta['key_available'] is True and meta['include_images'] is True
             and (meta['verified'] or {}).get('ok') is True and meta['inspected'] is True
             and meta['size'] == result['size'] and re.fullmatch(r'[0-9a-f]{64}', meta['sha256'] or ''), meta)
    ev.check('BackupMeta has every contract field',
             set(meta) >= {'id', 'type', 'created', 'note', 'apps', 'size', 'sha256', 'key_id', 'key_available',
                           'include_images', 'filename', 'source', 'verified', 'inspected'}, sorted(meta))
    info = ok(dev, 'download-info', {'backup_id': backup_id}, ev=ev)
    ev.check('download-info: path inside archives/, contract filename, size',
             info['path'] == f'/var/lib/woowtech-backup/archives/{backup_id}.woowbackup'
             and re.fullmatch(r'woowtech-backup-woowbk-dev-a-[0-9]{8}-[0-9]{4}\.woowbackup', info['filename'])
             and info['size'] == meta['size'], info)

    # Inspect on the source device (key held): preflight must say in-place.
    inspected = ok(dev, 'inspect', {'backup_id': backup_id}, ev=ev)
    ev.save('s1-inspect', inspected)
    papp = inspected['preflight']['apps'][0]
    mapp = inspected['manifest']['apps'][0]
    ev.check('inspect: preflight ok, app restorable in-place',
             inspected['preflight']['ok'] and papp['restorable'] and papp['mode'] == 'inplace', papp)
    ev.check('inspect: manifest summary lists both images as included, owner uid 1001, 1 db, 1 volume, 2 secrets, 1 config',
             all(i['included'] for i in mapp['images']) and len(mapp['images']) == 2 and mapp['owner']['uid'] == 1001
             and len(mapp['postgres']) == 1 and len(mapp['volumes']) == 1 and mapp['secrets_count'] == 2
             and mapp['config_files_count'] == 1, mapp)
    ev.check('inspect: verify_snapshot in the manifest equals the snapshot taken before the backup',
             compare(mapp['verify_snapshot'].get('summary', {}), snapshot) == {}, mapp['verify_snapshot'])

    # Mutate: add notes/files, change APP_TITLE (env file) + restart, delete a note and a file.
    mutate = owner(dev, 'python3', '/opt/woowbk-demo/tools/seed.py', '--notes', '2', '--files', '2',
                   '--title', '已變更的標題（S1 還原測試）', timeout=600)
    mutated_report = json.loads(mutate.stdout)
    ev.check('mutation rewrote the env file and restarted the app', mutated_report['env_changed'] is True)
    victim_note = min(n[0] for n in content_before['notes'])
    owner(dev, 'podman', 'exec', 'woowbk-demo-db', 'psql', '-X', '-w', '-U', 'notes', '-d', 'notes', '-c',
          f'DELETE FROM notes WHERE id = {int(victim_note)}')
    victim_file = sorted(f[0] for f in content_before['files'])[0]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', victim_file):
        raise Failed('unexpected file name')
    owner(dev, 'podman', 'exec', 'woowbk-demo-app', 'rm', '-f', f'/data/files/{victim_file}')
    mutated = summary(dev)
    ev.save('s1-mutated', mutated)
    ev.check('mutation changed notes, files, digest and title',
             all(mutated[k] != snapshot[k] or k in ('notes', 'files') for k in ('digest', 'title'))
             and (mutated['notes'], mutated['files']) != (snapshot['notes'], snapshot['files']), compare(mutated, snapshot))
    ev.log(f'mutated: {mutated}')

    # In-place restore.
    monitor = HealthMonitor(dev, 1200)
    t0 = time.monotonic()
    start = ok(dev, 'restore-start', {'backup_id': backup_id, 'apps': [APP], 'request_id': request_id(),
                                      'confirm': True}, ev=ev)
    job, log = wait_job(dev, start['job_id'], ev=ev, label='restore')
    restore_wall = time.monotonic() - t0
    health = monitor.stop()
    ev.save('s1-restore-job', {'job': job, 'log': log, 'health_monitor': health})
    ev.require('S1 in-place restore succeeded', job['state'] == 'succeeded', job.get('error'))
    result = job['result']
    ev.check('restore result: safety backup id, health ok, verification match, not rolled back',
             result['safety_backup_id'] and result['rolled_back'] is False and result['health']
             and all(c['status'] == 'ok' for c in result['health'])
             and [v['match'] for v in result['verification']] == [True], result)
    ev.check('restore phases: all done (no skip needed for in-place)', all(s == 'done' for s in phase_states(job).values()),
             phase_states(job))
    after = summary(dev)
    ev.save('s1-after-restore', {'summary': after, 'content': content_state(dev)})
    ev.require('S1 /api/summary after restore equals the backup-time snapshot', compare(after, snapshot) == {},
               compare(after, snapshot))
    ev.check('S1 full content (notes incl. signatures, files incl. sha256) equals the backup time',
             content_state(dev) == content_before)
    listed = ok(dev, 'list', ev=ev)['backups']
    safety = next((b for b in listed if b['id'] == result['safety_backup_id']), None)
    ev.save('s1-list-after-restore', listed)
    ev.check('S1 safety backup is listed (type safety, verified, app woowbk-demo)',
             safety and safety['type'] == 'safety' and (safety['verified'] or {}).get('ok')
             and [a['id'] for a in safety['apps']] == [APP], safety)
    ev.timings['s1_restore_wall_s'] = round(restore_wall, 1)
    ev.timings['s1_restore_healthz_longest_unhealthy_s'] = health['longest_unhealthy_s']
    ev.timings['s1_restore_stop_to_app_start_s'] = log_window(log, '停止服務 woowbk-demo-app.service',
                                                               '啟動服務 woowbk-demo-app.service')
    ev.timings['s1_safety_backup_size_bytes'] = safety['size'] if safety else None
    ev.log(f'restore {start["job_id"]}: {restore_wall:.1f}s wall, safety {result["safety_backup_id"]}, '
           f'healthz longest unhealthy {health["longest_unhealthy_s"]}s')
    status = ok(dev, 'status', ev=ev)
    app = next(a for a in status['apps'] if a['id'] == APP)
    ev.check('status after restore: running, last_backup is the safety backup',
             app['state'] == 'running' and (app['last_backup'] or {}).get('id') in (result['safety_backup_id'], backup_id),
             app)
    save_state(s1={'backup_id': backup_id, 'key_id': key_id, 'snapshot': snapshot,
                   'safety_backup_id': result['safety_backup_id'], 'size': meta['size'], 'sha256': meta['sha256']})
    return {'backup_id': backup_id}


# ------------------------------------------------------------------ S2

def scenario_s2(ev):
    state = load_state().get('s1')
    if not state:
        raise Failed('run s1 first (no backup id recorded)')
    backup_id, snapshot = state['backup_id'], state['snapshot']
    secret = kit_secret()

    # Download on A through the bridge (fsread1), as the page's hidden-iframe download does.
    info = ok('a', 'download-info', {'backup_id': backup_id}, ev=ev)
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    os.chmod(DOWNLOADS, 0o700)
    local = DOWNLOADS / info['filename']
    got = bridge_download('a', info['path'], local, ev=ev)
    ev.timings['s2_download_s'] = got['seconds']
    ev.require('S2 download: byte count and sha256 equal the index on dev-a',
               got['bytes'] == state['size'] == info['size'] and got['sha256'] == state['sha256'],
               {k: got[k] for k in ('bytes', 'seconds', 'size_hint')})

    # Device B must be a fresh target: no deployment and no backups (a previous run may have restored it).
    reset_target('b', ev)
    status = ok('b', 'status', ev=ev)
    app = next(a for a in status['apps'] if a['id'] == APP)
    ev.save('s2-status-before', status)
    ev.require('S2 dev-b: app not deployed', app['state'] == 'not-deployed' and not app['deployed'], app)
    uid_b = int(sh('b', 'id -u appowner').stdout.decode().strip())
    ev.check('dev-b appowner uid differs from dev-a (1007 vs 1001)', uid_b == 1007, uid_b)

    begin = ok('b', 'upload-begin', {'filename': info['filename'], 'size': got['bytes']}, ev=ev)
    ev.check('upload-begin: helper-generated .part path in uploads/, max_size >= size',
             re.fullmatch(r'/var/lib/woowtech-backup/uploads/[A-Za-z0-9_-]+\.part', begin['path'])
             and begin['max_size'] >= got['bytes'], begin)
    sent = bridge_upload('b', begin['path'], local, ev=ev)
    ev.timings['s2_upload_s'] = sent['seconds']
    ev.check('upload: 64 KiB frames, never more than 2 MiB unacknowledged, every byte acknowledged',
             sent['max_unacked'] <= WINDOW and sent['acked'] == sent['sent'] == got['bytes'], sent)
    finish = ok('b', 'upload-finish', {'upload_id': begin['upload_id']}, ev=ev, timeout=1800)
    uploaded = finish['backup']
    ev.save('s2-upload-finish', finish)
    ev.require('S2 upload-finish: BackupMeta type uploaded, same id + key id, key not on dev-b',
               uploaded['type'] == 'uploaded' and uploaded['id'] == backup_id and uploaded['key_id'] == state['key_id']
               and uploaded['key_available'] is False and uploaded['size'] == got['bytes'], uploaded)

    # Inspect without the key -> key-required (the wizard's key step).
    _rc, reply = helper('b', 'inspect', {'backup_id': backup_id}, ev=ev)
    ev.check('S2 inspect without key -> key-required with details.key_id',
             not reply['ok'] and reply['error']['code'] == 'key-required'
             and reply['error']['details'].get('key_id') == state['key_id'], reply.get('error'))

    # F1: a valid but different key -> wrong-key (generated inside dev-b, never printed or stored).
    other = sh('b', 'age-keygen 2>/dev/null').stdout.decode()
    other_secret = SECRET_RE.findall(other)[0]
    _rc, reply = helper('b', 'inspect', {'backup_id': backup_id, 'key': other_secret}, ev=ev)
    ev.check('F1 inspect with a different valid key -> wrong-key', not reply['ok'] and reply['error']['code'] == 'wrong-key',
             reply.get('error'))
    _rc, reply = helper('b', 'inspect', {'backup_id': backup_id, 'key': 'AGE-SECRET-KEY-1NOTAKEY'}, ev=ev)
    ev.check('inspect with a malformed key -> invalid-request or wrong-key (no crash)',
             not reply['ok'] and reply['error']['code'] in ('invalid-request', 'wrong-key'), reply.get('error'))

    # Inspect with the kit key (key only in the stdin field `key`, not saved).
    inspected = ok('b', 'inspect', {'backup_id': backup_id, 'key': secret}, ev=ev)
    ev.save('s2-inspect', inspected)
    papp = inspected['preflight']['apps'][0]
    mapp = inspected['manifest']['apps'][0]
    ev.check('S2 inspect with kit key: manifest from dev-a (owner uid 1001), preflight fresh + restorable',
             mapp['owner']['uid'] == 1001 and inspected['manifest']['source']['hostname'] == 'woowbk-dev-a'
             and papp['mode'] == 'fresh' and papp['restorable'] and inspected['preflight']['ok'], papp)
    ev.check('S2 preflight names the local owner and uid 1007',
             any('1007' in c['message'] for c in papp['checks']), [c['message'] for c in papp['checks']][:3])
    ev.check('inspect without save_key did not import the key',
             ok('b', 'status', ev=ev)['imported_keys'] == [] and not ok('b', 'list', ev=ev)['backups'][0]['key_available'])

    # Fresh restore with the key.
    t0 = time.monotonic()
    start = ok('b', 'restore-start', {'backup_id': backup_id, 'apps': [APP], 'request_id': request_id(),
                                      'confirm': True, 'key': secret}, ev=ev)
    job, log = wait_job('b', start['job_id'], ev=ev, label='restore')
    wall = time.monotonic() - t0
    ev.save('s2-restore-job', {'job': job, 'log': log})
    ev.require('S2 fresh restore succeeded', job['state'] == 'succeeded', job.get('error'))
    result = job['result']
    ev.check('S2 result: no safety backup (fresh), health ok, verification match, not rolled back',
             result['safety_backup_id'] is None and result['rolled_back'] is False
             and all(c['status'] == 'ok' for c in result['health']) and [v['match'] for v in result['verification']] == [True],
             result)
    ev.check('S2 phases: safety skipped, the rest done',
             phase_states(job).get('safety') == 'skipped'
             and all(s == 'done' for p, s in phase_states(job).items() if p != 'safety'), phase_states(job))
    ev.timings['s2_restore_wall_s'] = round(wall, 1)
    after = summary('b')
    ev.save('s2-after-restore', after)
    ev.require('S2 /api/summary on dev-b equals the backup-time snapshot from dev-a', compare(after, snapshot) == {},
               compare(after, snapshot))
    ev.check('job key file removed and no imported key left on dev-b',
             'key-' not in sh('b', 'ls /run/woowtech-backup').stdout.decode()
             and ok('b', 'status', ev=ev)['imported_keys'] == [])

    # The restored app accepts new data (DB writes with the restored password, files in the volume).
    status_code, body = app_post('b', '/api/notes', json.dumps({'title': 'B 還原後新增', 'body': '跨設備還原後可寫入 𠮷'},
                                                               ensure_ascii=False).encode(), 'application/json')
    ev.check('S2 POST /api/notes on dev-b -> 201', status_code == 201, body[:200])
    blob = secrets.token_bytes(4096)
    status_code, body = app_post('b', '/api/files?name=after-restore-b.bin', blob, 'application/octet-stream')
    ev.check('S2 POST /api/files on dev-b -> 201 with the right sha256',
             status_code == 201 and json.loads(body).get('sha256') == hashlib.sha256(blob).hexdigest(), body[:200])
    final = summary('b')
    ev.check('S2 counts +1/+1 and all signatures valid after new writes',
             final['notes'] == snapshot['notes'] + 1 and final['files'] == snapshot['files'] + 1
             and final['signatures_valid'] is True, final)
    owners = owner('b', 'podman', 'exec', 'woowbk-demo-app', 'sh', '-c',
                   'stat -c "%u:%g %a %n" /data /data/files /data/files/*').stdout.decode()
    host_view = sh('b', 'stat -c "%u:%g %n" /home/appowner/.local/share/containers/storage/volumes/woowbk-demo-files/_data/files/* '
                        '| sort | uniq -c | head -20').stdout.decode()
    ev.save('s2-ownership', {'in_container': owners, 'device_view': host_view})
    ev.check('S2 restored and new files are owned by container root (= appowner 1007 on the device)',
             all(line.startswith('0:0 ') for line in owners.splitlines() if line.strip())
             and all(' 1007:1007 ' in f' {line.strip()} ' for line in host_view.splitlines() if line.strip()),
             host_view.strip()[:300])
    status = ok('b', 'status', ev=ev)
    app = next(a for a in status['apps'] if a['id'] == APP)
    ev.check('dev-b status: app deployed and running', app['deployed'] and app['state'] == 'running', app)
    save_state(s2={'backup_id': backup_id, 'restore_job': start['job_id'], 'download': str(local)})
    return {}


# ------------------------------------------------------------------ fault scenarios

def upload_file(dev, source, *, ev, filename=None, truncate_to=None, flip_at=None):
    """upload-begin -> fsreplace1 -> upload-finish; a refused finish is followed by upload-abort, like the page."""
    size = os.path.getsize(source) if truncate_to is None else truncate_to
    begin = ok(dev, 'upload-begin', {'filename': filename or Path(source).name, 'size': size}, ev=ev)
    bridge_upload(dev, begin['path'], source, ev=ev, truncate_to=truncate_to, flip_at=flip_at)
    rc, reply = helper(dev, 'upload-finish', {'upload_id': begin['upload_id']}, ev=ev, timeout=1800)
    if not reply['ok']:
        ok(dev, 'upload-abort', {'upload_id': begin['upload_id']}, ev=ev)
        left = sh(dev, 'ls -A /var/lib/woowtech-backup/uploads').stdout.decode()
        ev.check(f'upload-abort after a refused upload leaves nothing in uploads/ ({begin["upload_id"]})',
                 begin['upload_id'] not in left, left.strip()[:200])
    return begin, (rc, reply)


def scenario_faults(ev):
    state = load_state()
    s1 = state.get('s1') or {}
    local = Path((state.get('s2') or {}).get('download') or '')
    if not s1 or not local.is_file():
        raise Failed('run s1 and s2 first')
    tmp = LAB / 'run'
    tmp.mkdir(parents=True, exist_ok=True)
    secret = kit_secret()
    before_summary = summary('b')

    # F4: a file that is not a backup, and a future format version.
    foreign = tmp / 'woowbk-not-a-backup.bin'
    foreign.write_bytes(b'PK\x03\x04 this is not a woowtech backup\n' + secrets.token_bytes(4096))
    _begin, (_rc, reply) = upload_file('b', foreign, ev=ev, filename='notes.zip')
    ev.check('F4 foreign file -> upload-finish not-a-backup', not reply['ok'] and reply['error']['code'] == 'not-a-backup',
             reply.get('error'))
    future = tmp / 'woowbk-future.woowbackup'
    future.write_bytes(b'WOOWTECH-BACKUP/2\n{"format":2}\n' + secrets.token_bytes(4096))
    _begin, (_rc, reply) = upload_file('b', future, ev=ev)
    ev.check('F4 WOOWTECH-BACKUP/2 -> unsupported-format', not reply['ok'] and reply['error']['code'] == 'unsupported-format',
             reply.get('error'))

    # F2 truncated / F3 flipped byte: the outer header passes, the full check must fail before any change.
    size = local.stat().st_size
    cases = {'F2 truncated (half)': {'truncate_to': size // 2}, 'F3 flipped byte in the payload': {'flip_at': size // 2}}
    for label, options in cases.items():
        # dev-b already holds this backup id (S2), so delete it first; it is uploaded intact again below.
        ok('b', 'delete', {'backup_id': s1['backup_id']}, ev=ev)
        _begin, (_rc, reply) = upload_file('b', local, ev=ev, **options)
        if not reply['ok']:
            ev.check(f'{label} -> rejected at upload-finish', reply['error']['code'] in ('corrupt-archive', 'invalid-request'),
                     reply.get('error'))
            continue
        status_before = ok('b', 'status', ev=ev)
        start = ok('b', 'verify-start', {'backup_id': s1['backup_id'], 'request_id': request_id(), 'key': secret}, ev=ev)
        job, _log = wait_job('b', start['job_id'], ev=ev, label='verify')
        ev.check(f'{label} -> verify job fails with corrupt-archive',
                 job['state'] == 'failed' and job['error']['code'] == 'corrupt-archive', job.get('error'))
        listed = next(b for b in ok('b', 'list', ev=ev)['backups'] if b['id'] == s1['backup_id'])
        ev.check(f'{label} -> BackupMeta.verified.ok is false after the failed verify',
                 (listed.get('verified') or {}).get('ok') is False, listed.get('verified'))
        restore = ok('b', 'restore-start', {'backup_id': s1['backup_id'], 'apps': [APP], 'request_id': request_id(),
                                            'confirm': True, 'key': secret}, ev=ev)
        rjob, _log = wait_job('b', restore['job_id'], ev=ev, label='restore')
        after = summary('b')
        ev.check(f'{label} -> restore job fails in decrypt, before any change; app data untouched',
                 rjob['state'] == 'failed' and rjob['error']['code'] == 'corrupt-archive'
                 and phase_states(rjob).get('decrypt') == 'failed' and phase_states(rjob).get('stop') == 'pending'
                 and compare(after, before_summary) == {}
                 and next(a for a in status_before['apps'] if a['id'] == APP)['state'] == 'running',
                 {'error': rjob.get('error'), 'phases': phase_states(rjob)})
        ev.check(f'{label} -> staging empty and no job key file afterwards',
                 sh('b', 'ls -A /var/lib/woowtech-backup/staging').stdout.strip() == b''
                 and b'key-' not in sh('b', 'ls -A /run/woowtech-backup').stdout)
    ok('b', 'delete', {'backup_id': s1['backup_id']}, ev=ev)
    _begin, (_rc, reply) = upload_file('b', local, ev=ev)
    ev.check('intact archive uploads again after the fault cases', reply['ok'], reply.get('error'))
    start = ok('b', 'verify-start', {'backup_id': s1['backup_id'], 'request_id': request_id(), 'key': secret}, ev=ev)
    job, _log = wait_job('b', start['job_id'], ev=ev, label='verify')
    ev.check('verify job of the intact upload with the kit key succeeds (ok, entries, bytes)',
             job['state'] == 'succeeded' and job['result']['ok'] is True and job['result']['entries'] > 0
             and job['result']['bytes'] > 0, job.get('result'))

    # F12: a non-root caller (Cockpit without administrative access) gets permission-denied, nothing runs.
    proc = subprocess.run([LP, 'exec', '-i', '--user', 'devadmin', dev_name('a'), HELPER, 'status'], input=b'',
                          capture_output=True, timeout=120)
    lines = [line for line in proc.stdout.decode().splitlines() if line.strip()]
    reply = json.loads(lines[0]) if len(lines) == 1 else {}
    ev.check('F12 helper as non-root -> permission-denied (exit 1, exactly one JSON object)',
             proc.returncode == 1 and reply.get('error', {}).get('code') == 'permission-denied', reply)
    return {}


TEARDOWN = r"""
set -u
cd "$HOME"
systemctl --user stop woowbk-demo-app.service woowbk-demo-db.service woowbk-demo-network.service 2>/dev/null
rm -f .config/containers/systemd/woowbk-demo.network .config/containers/systemd/woowbk-demo-db.container \
      .config/containers/systemd/woowbk-demo-app.container
systemctl --user daemon-reload
systemctl --user reset-failed 2>/dev/null
podman volume rm -f woowbk-demo-files woowbk-demo-pgdata >/dev/null
podman secret rm woowbk-demo-db-password woowbk-demo-app-key >/dev/null 2>&1
rm -f .config/woowbk-demo/app.env
podman network rm -f woowbk-demo >/dev/null 2>&1
podman rmi -f localhost/woowbk-demo-app:1 >/dev/null 2>&1
true
"""


def owner_footprint(dev):
    """What exists of the demo app for the owner: quadlets, env file, volumes, secrets, app image."""
    script = ('cd "$HOME"; ls .config/containers/systemd/ 2>/dev/null | grep woowbk; ls .config/woowbk-demo/ 2>/dev/null; '
              'podman volume ls -q | grep woowbk; podman secret ls --format "{{.Name}}" | grep woowbk; '
              'podman image exists localhost/woowbk-demo-app:1 && echo image:localhost/woowbk-demo-app:1; true')
    return owner(dev, 'sh', '-c', script).stdout.decode().split()


def reset_target(dev, ev):
    """Fresh restore target: delete its backups and remove the demo deployment owner-side (operator action)."""
    for backup in ok(dev, 'list', ev=ev)['backups']:
        ok(dev, 'delete', {'backup_id': backup['id']}, ev=ev)
    owner(dev, 'sh', '-c', TEARDOWN, timeout=600)
    ev.log(f'dev-{dev} reset to a fresh target (no backups, no woowbk-demo deployment)')


def scenario_s3(ev):
    """S3: backup without images; on a device without the local-only app image preflight fails, nothing changes."""
    secret = kit_secret()
    reset_target('b', ev)
    status = ok('b', 'status', ev=ev)
    app = next(a for a in status['apps'] if a['id'] == APP)
    ev.require('dev-b torn down: app not deployed, no footprint', app['state'] == 'not-deployed' and owner_footprint('b') == [],
               owner_footprint('b'))

    start = ok('a', 'backup-start', {'apps': [APP], 'include_images': False, 'note': 'S3 不含映像',
                                     'request_id': request_id()}, ev=ev)
    job, _log = wait_job('a', start['job_id'], ev=ev, label='backup')
    ev.require('S3 backup without images succeeded on dev-a', job['state'] == 'succeeded', job.get('error'))
    s3_id = job['result']['backup_id']
    ev.timings['s3_backup_size_bytes'] = job['result']['size']
    info = ok('a', 'download-info', {'backup_id': s3_id}, ev=ev)
    s3_local = DOWNLOADS / info['filename'].replace('.woowbackup', '-s3.woowbackup')
    bridge_download('a', info['path'], s3_local, ev=ev)
    _begin, (_rc, reply) = upload_file('b', s3_local, ev=ev)
    ev.require('S3 archive uploaded to dev-b', reply['ok'], reply.get('error'))
    ev.check('uploaded file name that does not match the contract pattern is replaced by woowtech-backup-uploaded-…',
             reply['backup']['filename'].startswith('woowtech-backup-uploaded-'), reply['backup']['filename'])
    inspected = ok('b', 'inspect', {'backup_id': s3_id, 'key': secret}, ev=ev)
    ev.save('s3-inspect', inspected)
    papp = inspected['preflight']['apps'][0]
    failing = [c for c in papp['checks'] if c['status'] == 'fail']
    ev.check('S3 preflight: app not restorable because localhost/woowbk-demo-app:1 is neither included nor obtainable',
             not inspected['preflight']['ok'] and not papp['restorable']
             and any('localhost/woowbk-demo-app:1' in c['message'] for c in failing), failing)
    ev.check('S3 manifest summary: images listed as not included',
             not any(i['included'] for i in inspected['manifest']['apps'][0]['images']))
    # The page never offers a non-restorable app; the engine must refuse it anyway.
    start = ok('b', 'restore-start', {'backup_id': s3_id, 'apps': [APP], 'request_id': request_id(), 'confirm': True,
                                      'key': secret}, ev=ev)
    job, log = wait_job('b', start['job_id'], ev=ev, label='restore')
    ev.save('s3-restore-job', {'job': job, 'log': log})
    ev.check('S3 restore job fails with incompatible in the preflight phase',
             job['state'] == 'failed' and job['error']['code'] == 'incompatible'
             and phase_states(job).get('preflight') == 'failed' and phase_states(job).get('stop') == 'pending',
             {'error': job.get('error'), 'phases': phase_states(job)})
    ev.check('S3 nothing was created on dev-b (no quadlets, env file, volumes, secrets)', owner_footprint('b') == [],
             owner_footprint('b'))
    ok('b', 'delete', {'backup_id': s3_id}, ev=ev)
    save_state(s3={'backup_id': s3_id})
    return {}


def owner_write_title(dev, title):
    """Rewrite APP_TITLE in the env file as the owner WITHOUT restarting the app."""
    code = ('import os, sys, tempfile\n'
            'p = os.path.expanduser("~/.config/woowbk-demo/app.env")\n'
            'fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p))\n'
            'os.write(fd, ("# woowbk-demo settings (EnvironmentFile=). Backed up as a config file.\\n"'
            ' "APP_TITLE=" + sys.argv[1] + "\\n").encode())\n'
            'os.fchmod(fd, 0o600); os.fsync(fd); os.close(fd); os.replace(tmp, p)\n')
    owner(dev, 'python3', '-I', '-c', code, title)


def scenario_f8(ev):
    """F8: a restore that fails after the destructive step rolls back automatically; data equals pre-restore."""
    dev = 'a'
    running_title = summary(dev)['title']
    # Backup whose env file disagrees with the running app (an edit that was never applied): restoring it
    # restarts the app with the other title, so the data verification mismatches after the destructive step.
    owner_write_title(dev, 'F8 尚未套用的標題')
    start = ok(dev, 'backup-start', {'apps': [APP], 'include_images': False, 'note': 'F8 回復測試',
                                     'request_id': request_id()}, ev=ev)
    job, _log = wait_job(dev, start['job_id'], ev=ev, label='backup')
    ev.require('F8 backup succeeded', job['state'] == 'succeeded', job.get('error'))
    # The backup restarted the writer, which applied the pending title. Make the device consistent again
    # (env file == running app) so the safety backup taken by the restore is self-consistent.
    owner(dev, 'python3', '/opt/woowbk-demo/tools/seed.py', '--notes', '0', '--files', '0', '--title', running_title)
    ev.check('device consistent before the restore (running title == env title)', summary(dev)['title'] == running_title)
    f8_id = job['result']['backup_id']
    status_code, _body = app_post(dev, '/api/notes', json.dumps({'title': 'F8 還原前的新筆記', 'body': '回復後必須還在'},
                                                                ensure_ascii=False).encode(), 'application/json')
    ev.check('pre-restore change: POST /api/notes -> 201', status_code == 201)
    pre, pre_content = summary(dev), content_state(dev)
    t0 = time.monotonic()
    start = ok(dev, 'restore-start', {'backup_id': f8_id, 'apps': [APP], 'request_id': request_id(), 'confirm': True},
               ev=ev)
    job, log = wait_job(dev, start['job_id'], ev=ev, label='restore')
    ev.save('f8-restore-job', {'job': job, 'log': log})
    ev.timings['f8_restore_with_rollback_wall_s'] = round(time.monotonic() - t0, 1)
    result = job.get('result') or {}
    ev.check('F8 job state rolled-back, error job-failed, result.rolled_back true, safety backup recorded',
             job['state'] == 'rolled-back' and job['error']['code'] == 'job-failed' and result.get('rolled_back') is True
             and result.get('safety_backup_id'), {'state': job['state'], 'error': job.get('error')})
    ev.check('F8 phases: rollback appended and done, the failing check phase marked failed',
             phase_states(job).get('rollback') == 'done' and phase_states(job).get('check') == 'failed',
             phase_states(job))
    ev.check('F8 verification entry reports the mismatch (match=false on title)',
             any(v['match'] is False for v in result.get('verification') or []), result.get('verification'))
    after = summary(dev)
    ev.check('F8 data after rollback equals the pre-restore state (summary)', compare(after, pre) == {}, compare(after, pre))
    ev.check('F8 data after rollback equals the pre-restore state (full content)', content_state(dev) == pre_content)
    ev.check('F8 app healthy after rollback', wait_healthy(dev, 60))
    save_state(f8={'backup_id': f8_id, 'job': start['job_id']})
    return {}


def scenario_f9(ev):
    """F9: SIGKILL a restore after its safety backup -> interrupted + guidance; the safety backup restores the app."""
    dev = 'a'
    target = (load_state().get('s3') or {}).get('backup_id')
    if not target:
        raise Failed('run s3 first (needs the backup without images on dev-a)')
    pre, pre_content = summary(dev), content_state(dev)
    start = ok(dev, 'restore-start', {'backup_id': target, 'apps': [APP], 'request_id': request_id(), 'confirm': True},
               ev=ev)
    job_id = start['job_id']
    deadline = time.monotonic() + 300
    killed_in = None
    while time.monotonic() < deadline:
        _rc, reply = helper(dev, 'job-status', {'job_id': job_id})
        job = reply['job']
        if job['phase'] in ('restore', 'start') and job['state'] == 'running':
            sh(dev, f'systemctl kill --signal=SIGKILL woowtech-backup-{job_id}.service')
            killed_in = job['phase']
            break
        if job['state'] not in ('queued', 'running'):
            break
        time.sleep(0.2)
    ev.require('F9 restore job killed with SIGKILL after the destructive step began', killed_in is not None,
               f'last phase {job["phase"]} state {job["state"]}')
    ev.log(f'killed job {job_id} in phase {killed_in}')
    time.sleep(2)
    job, log = wait_job(dev, job_id, ev=ev, timeout=120, label='killed-restore')
    ev.save('f9-killed-job', {'job': job, 'log': log})
    safety = (job.get('result') or {}).get('safety_backup_id')
    ev.check('F9 job becomes interrupted with zh-TW guidance naming the safety backup',
             job['state'] == 'interrupted' and job['error']['code'] == 'job-failed' and safety
             and safety in job['error']['message'], job.get('error'))
    ev.check('F9 interrupted job: staging and job key removed',
             sh(dev, 'ls -A /var/lib/woowtech-backup/staging').stdout.strip() == b''
             and b'key-' not in sh(dev, 'ls -A /run/woowtech-backup').stdout)
    ev.check('F9 nothing is replayed: job-status again keeps the interrupted state',
             helper(dev, 'job-status', {'job_id': job_id})[1]['job']['state'] == 'interrupted')
    t0 = time.monotonic()
    start = ok(dev, 'restore-start', {'backup_id': safety, 'apps': [APP], 'request_id': request_id(), 'confirm': True},
               ev=ev)
    job, log = wait_job(dev, start['job_id'], ev=ev, label='restore-safety')
    ev.save('f9-restore-safety-job', {'job': job, 'log': log})
    ev.timings['f9_restore_safety_wall_s'] = round(time.monotonic() - t0, 1)
    ev.check('F9 restoring the safety backup succeeds', job['state'] == 'succeeded', job.get('error'))
    after = summary(dev)
    ev.check('F9 data equals the state before the killed restore (summary)', compare(after, pre) == {}, compare(after, pre))
    ev.check('F9 data equals the state before the killed restore (full content)', content_state(dev) == pre_content)
    status = ok(dev, 'status', ev=ev)
    app = next(a for a in status['apps'] if a['id'] == APP)
    ev.check('F9 app running afterwards and no active job', app['state'] == 'running' and status['active_job'] is None, app)
    safeties = [b for b in ok(dev, 'list', ev=ev)['backups'] if b['type'] == 'safety']
    ev.check('at most 3 safety backups are kept for the app', len(safeties) <= 3, [b['id'] for b in safeties])
    return {}


def scenario_cancel(ev):
    """Contract section 8: a backup is cancellable while packaging; the partial archive is discarded, writers run."""
    dev = 'a'
    before = {b['id'] for b in ok(dev, 'list', ev=ev)['backups']}
    start = ok(dev, 'backup-start', {'apps': [APP], 'include_images': True, 'note': '取消測試',
                                     'request_id': request_id()}, ev=ev)
    job_id = start['job_id']
    deadline = time.monotonic() + 300
    refused = cancelled = None
    while time.monotonic() < deadline:
        job = helper(dev, 'job-status', {'job_id': job_id})[1]['job']
        if job['phase'] in ('stop', 'dump', 'export', 'start') and not job['cancellable'] and refused is None:
            refused = helper(dev, 'job-cancel', {'job_id': job_id}, ev=ev)[1]
        if job['phase'] in ('package', 'verify') and job['cancellable']:
            cancelled = ok(dev, 'job-cancel', {'job_id': job_id}, ev=ev)
            break
        if job['state'] not in ('queued', 'running'):
            break
        time.sleep(0.3)
    if refused is not None:
        ev.check('job-cancel while writers are stopped -> not-cancellable', not refused['ok']
                 and refused['error']['code'] == 'not-cancellable', refused.get('error'))
    ev.require('job-cancel accepted while packaging', cancelled is not None, job.get('phase'))
    job, log = wait_job(dev, job_id, ev=ev, timeout=300, label='cancel')
    ev.save('cancel-job', {'job': job, 'log': log})
    ev.check('cancelled job ends in state cancelled with remaining phases skipped',
             job['state'] == 'cancelled' and all(s in ('done', 'skipped') for s in phase_states(job).values()),
             {'state': job['state'], 'phases': phase_states(job)})
    after = {b['id'] for b in ok(dev, 'list', ev=ev)['backups']}
    ev.check('no backup was listed for the cancelled job', after == before, sorted(after - before))
    leftovers = sh(dev, 'ls -A /var/lib/woowtech-backup/staging; ls -A /var/lib/woowtech-backup/archives | '
                        'grep -v -E "^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\\.(woowbackup|json)$" || true').stdout.decode().split()
    ev.check('partial archive and staging discarded', leftovers == [], leftovers)
    app = next(a for a in ok(dev, 'status', ev=ev)['apps'] if a['id'] == APP)
    ev.check('writers are running after the cancel', app['state'] == 'running', app['units'])
    return {}


# ------------------------------------------------------------------ leak scan

LEAK_SCAN = r'''
import json, os, re, subprocess, sys
owner = 'appowner'
env = ['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'HOME=/home/appowner', 'LANG=C.UTF-8',
       'XDG_RUNTIME_DIR=/run/user/%s' % sys.argv[1], 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%s/bus' % sys.argv[1]]
needles = {}
for name in ('woowbk-demo-db-password', 'woowbk-demo-app-key'):
    out = subprocess.run(['/usr/sbin/runuser', '-u', owner, '--', *env, 'podman', 'secret', 'inspect', '--showsecret',
                          '--format', '{{.SecretData}}', name], capture_output=True, cwd='/home/appowner').stdout
    if out.endswith(b'\n') and len(out) > 8:
        needles[name] = out[:-1]
keydir = '/etc/woowtech-cockpit/backup/keys'
for fname in sorted(os.listdir(keydir)) if os.path.isdir(keydir) else []:
    if fname.endswith('.key'):
        data = open(os.path.join(keydir, fname), 'rb').read()
        for m in re.findall(rb'AGE-SECRET-KEY-1[0-9A-Z]+', data):
            needles['key:' + fname] = m
needles['age-secret-pattern'] = None
files = []
for root in ('/var/lib/woowtech-backup',):
    for base, dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(base, n)
            if p.endswith('.woowbackup') or '/uploads/' in p:
                continue
            files.append(p)
journal = subprocess.run(['journalctl', '-o', 'cat', '--no-pager'], capture_output=True).stdout
report = {'files_scanned': len(files), 'needles': sorted(k for k in needles), 'hits': {}}
blobs = {p: open(p, 'rb').read() for p in files}
blobs['<journal>'] = journal
for label, needle in needles.items():
    for where, blob in blobs.items():
        hit = re.search(rb'AGE-SECRET-KEY-1', blob) if needle is None else (needle in blob)
        if hit:
            report['hits'].setdefault(label, []).append(where)
report['run_dir'] = sorted(os.listdir('/run/woowtech-backup')) if os.path.isdir('/run/woowtech-backup') else []
report['staging'] = sorted(os.listdir('/var/lib/woowtech-backup/staging')) if os.path.isdir('/var/lib/woowtech-backup/staging') else []
print(json.dumps(report))
'''


def scenario_leaks(ev):
    secret = kit_secret() if KIT_FILE.exists() else None
    for dev in ('a', 'b'):
        proc = sh(dev, f'python3 -I - {DEVICES[dev]["uid"]}', input=LEAK_SCAN.encode(), timeout=300)
        report = json.loads(proc.stdout)
        ev.save(f'leaks-dev-{dev}', report)
        ev.check(f'dev-{dev}: no app secret or age key in job records/logs/index/requests/journal',
                 report['hits'] == {}, report['hits'])
        ev.check(f'dev-{dev}: no transient key files in /run/woowtech-backup and no staging left',
                 not any(n.startswith('key-') for n in report['run_dir']) and report['staging'] == [],
                 {'run': report['run_dir'], 'staging': report['staging']})
    hits = []
    for base, _dirs, names in os.walk(EVIDENCE):
        for name in names:
            data = Path(base, name).read_bytes()
            if SECRET_RE.search(data.decode('utf-8', 'replace')) or (secret and secret.encode() in data):
                hits.append(str(Path(base, name)))
    ev.check('host evidence directory contains no key material', hits == [], hits)
    return {}


# ------------------------------------------------------------------ main

SCENARIOS = {'s1': scenario_s1, 's2': scenario_s2, 'faults': scenario_faults, 's3': scenario_s3,
             's2-again': scenario_s2, 'f8': scenario_f8, 'f9': scenario_f9, 'cancel': scenario_cancel,
             'leaks': scenario_leaks}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('scenario', choices=[*SCENARIOS, 'all'])
    args = parser.parse_args()
    names = list(SCENARIOS) if args.scenario == 'all' else [args.scenario]
    all_ok = True
    for name in names:
        ev = Evidence(name)
        try:
            extra = SCENARIOS[name](ev) or {}
        except Failed as error:
            ev.log(f'ABORTED: {error}')
            extra = {'aborted': str(error)}
        except Exception as error:  # noqa: BLE001 - record and continue to the summary
            ev.log(f'ABORTED with {type(error).__name__}: {redact(str(error))}')
            extra = {'aborted': f'{type(error).__name__}: {redact(str(error))}'}
        all_ok = ev.finish(extra) and 'aborted' not in extra and all_ok
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
