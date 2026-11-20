#!/usr/bin/env python3
"""Private acknowledged synthetic Headscale credential events and evidence boundary.

Only the four named producers in this harness are covered. On any incomplete
stream or failed probe, suppress all child output; never print credentials.
"""
import json
import os
import re
import selectors
import signal
import socket
import subprocess
import sys
import time

EXPECTED = ('source_api', 'client_a_preauth', 'client_b_preauth', 'target_api')
LOGS = ('source_server', 'target_initial', 'target_converted', 'client_a', 'client_b')
MAX_SECRET = 16384
MAX_OUTPUT = 8 * 1024 * 1024
MAX_LOG = 1024 * 1024
MAX_FRAME = 8 * 1024 * 1024
TIMEOUT = 900
CLEANUP_GRACE = 90
KEY = re.compile(r'hskey-(?:auth|api)-[A-Za-z0-9_-]{12,}')


class CleanupUnverified(RuntimeError):
    """Failure occurred; independent verification of cleanup is required."""

    def __init__(self, forced=False, output=b''):
        self.forced = forced
        lines = output.splitlines()
        self.outcomes = {}
        for name in ('AUTO_RECONNECT', 'MANUAL_RECOVERY'):
            matches = [line for line in lines if line in (f'{name}=PASS'.encode(), f'{name}=FAIL'.encode())]
            if len(matches) == 1:
                self.outcomes[name] = matches[0].decode().split('=', 1)[1]
        for name in ('AUTO_ELAPSED_SECONDS', 'AUTO_ATTEMPTS'):
            prefix = (name + '=').encode()
            matches = [line[len(prefix):] for line in lines if line.startswith(prefix)]
            if len(matches) == 1 and re.fullmatch(rb'[0-9]{1,6}', matches[0]):
                self.outcomes[name] = matches[0].decode()
        super().__init__('cleanup unverified' + ('; forced termination' if forced else ''))


def terminate_and_drain(proc, selector, grace=CLEANUP_GRACE):
    """Allow the runner's EXIT trap to run while discarding all private output.

    A process exit alone does not establish that detached Podman objects were
    removed. The caller must always report cleanup as unverified on failure.
    """
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + grace
    while proc.poll() is None and time.monotonic() < deadline:
        for selected, _ in selector.select(min(0.25, max(0, deadline - time.monotonic()))):
            try:
                data = os.read(selected.fileobj.fileno(), 65536)
            except OSError:
                data = b''
            if not data:
                selector.unregister(selected.fileobj)
    forced = proc.poll() is None
    if forced:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        forced = True
    return forced


def register(source, *, log=False):
    limit = MAX_LOG if log else MAX_SECRET
    data = sys.stdin.buffer.read(limit + 1)
    if len(data) > limit or (log and source not in LOGS) or (not log and (source not in EXPECTED or len(data) < 6)):
        raise ValueError('invalid source credential')
    value = data.decode('utf-8')
    if not log and ('\n' in value or '\r' in value or '\x00' in value):
        raise ValueError('invalid source credential')
    sock = socket.socket(fileno=int(os.environ['HEADSCALE_EVENT_FD']))
    frame = json.dumps({'source': source, 'log' if log else 'credential': value}, ensure_ascii=True).encode() + b'\n'
    sock.sendall(frame)
    ack = b''
    while len(ack) < 3:
        chunk = sock.recv(3 - len(ack))
        if not chunk:
            break
        ack += chunk
    if ack != b'OK\n':
        raise ValueError('registration not acknowledged')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


def scan_needles(values):
    needles = set()
    for value in values:
        needles.add(value.encode())
        for ascii_only in (False, True):
            needles.add(json.dumps(value, ensure_ascii=ascii_only)[1:-1].encode())
    return needles


def run(argv, timeout=TIMEOUT):
    parent, child = socket.socketpair()
    env = dict(os.environ, HEADSCALE_EVENT_FD=str(child.fileno()))
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, pass_fds=(child.fileno(),), env=env,
                            start_new_session=True)
    child.close()
    selector = selectors.DefaultSelector()
    selector.register(parent, selectors.EVENT_READ, 'event')
    selector.register(proc.stdout, selectors.EVENT_READ, 'output')
    credentials, logs, pending, output = {}, {}, b'', bytearray()
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('timeout')
            ready = selector.select(remaining)
            if not ready:
                raise ValueError('timeout')
            for selected, _ in ready:
                data = os.read(selected.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(selected.fileobj)
                    continue
                if selected.data == 'output':
                    output.extend(data)
                    if len(output) > MAX_OUTPUT:
                        raise ValueError('output limit')
                    continue
                pending += data
                if len(pending) > MAX_FRAME:
                    raise ValueError('event limit')
                while b'\n' in pending:
                    line, pending = pending.split(b'\n', 1)
                    event = json.loads(line, object_pairs_hook=unique)
                    if not isinstance(event, dict):
                        raise ValueError('invalid event')
                    if set(event) == {'source', 'log'}:
                        source, value = event['source'], event['log']
                        if source not in LOGS or source in logs or not isinstance(value, str) or len(value.encode()) > MAX_LOG:
                            raise ValueError('invalid log source')
                        logs[source] = value
                        parent.sendall(b'OK\n')
                        continue
                    if set(event) != {'source', 'credential'}:
                        raise ValueError('invalid event')
                    source, value = event['source'], event['credential']
                    if (source not in EXPECTED or source in credentials or not isinstance(value, str)
                            or not 6 <= len(value) <= MAX_SECRET or any(c in value for c in '\r\n\x00')):
                        raise ValueError('invalid credential')
                    if source != EXPECTED[len(credentials)] or value in credentials.values():
                        raise ValueError('unexpected credential source')
                    credentials[source] = value  # register BEFORE acknowledging the producer
                    parent.sendall(b'OK\n')
        if pending or proc.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise ValueError('incomplete producer')
        if tuple(credentials) != EXPECTED:
            raise ValueError('credential coverage incomplete')
        if set(logs) != set(LOGS):
            raise ValueError('log coverage incomplete')
        needles = scan_needles(credentials.values())
        if any(needle in log.encode('utf-8') for log in logs.values() for needle in needles):
            raise ValueError('synthetic container log leak')
        # All output is withheld until every required producer has registered.
        text = output.decode('utf-8', 'replace')
        for source, value in sorted(credentials.items(), key=lambda item: -len(item[1])):
            text = text.replace(value, '<' + source + '>')
            for ascii_only in (False, True):
                text = text.replace(json.dumps(value, ensure_ascii=ascii_only)[1:-1], '<' + source + '>')
        text = KEY.sub('hskey-<redacted>', text)
        safe = text.encode('utf-8')
        if any(needle in safe for needle in needles):
            raise ValueError('evidence scan failed')
        return text
    except Exception:
        forced = terminate_and_drain(proc, selector, CLEANUP_GRACE)
        raise CleanupUnverified(forced, bytes(output)) from None
    finally:
        selector.close()
        proc.stdout.close()
        parent.close()


def main():
    try:
        if len(sys.argv) == 3 and sys.argv[1] == '--register':
            register(sys.argv[2])
        elif len(sys.argv) == 3 and sys.argv[1] == '--scan-log':
            register(sys.argv[2], log=True)
        elif len(sys.argv) >= 4 and sys.argv[1:3] == ['--controller', '--']:
            result = run(sys.argv[3:])
            sys.stdout.write(result)
            print('Synthetic credential coverage: four sources acknowledged; five submitted log snapshots (possibly empty) and redacted output scanned')
        else:
            raise ValueError('invalid invocation')
    except Exception as error:
        detail = '; cleanup unverified' if isinstance(error, CleanupUnverified) else ''
        if isinstance(error, CleanupUnverified) and 'forced termination' in str(error):
            detail += '; cleanup deadline exceeded, forced termination'
        print('Synthetic credential coverage incomplete; raw output suppressed' + detail, file=sys.stderr)
        if isinstance(error, CleanupUnverified):
            for name, value in error.outcomes.items():
                print(f'{name}={value} (preliminary; credential coverage incomplete)', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
