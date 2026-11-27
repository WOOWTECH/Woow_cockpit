"""Private, acknowledged credential events from a short-lived lab probe."""
import json
import os
import selectors
import signal
import subprocess
import time


class Incomplete(RuntimeError):
    """The producer did not establish a complete event stream."""


MAX_REQUEST = 64 * 1024
MAX_FRAME = 1024 * 1024
MAX_STREAM = 8 * 1024 * 1024


def run_events(argv, request, register, expected_auth, timeout=600):
    """Register each complete credential event before acknowledging the producer.

    No raw stdout/stderr is exposed on errors. A summary is usable only after a
    contiguous stream, the expected number of auth outcomes, an end frame, EOF,
    and successful process exit. The producer must wait for each acknowledgement.
    """
    try:
        request_bytes = json.dumps(request, ensure_ascii=False).encode('utf-8') + b'\n'
    except (TypeError, ValueError, UnicodeError):
        raise Incomplete('invalid credential request') from None
    if len(request_bytes) > MAX_REQUEST:
        raise Incomplete('credential request too large')
    deadline = time.monotonic() + timeout
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, start_new_session=True, bufsize=0)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    buffer = b''
    sequence = auth_count = 0
    summary = None
    ended = False
    total = 0
    error = None
    os.set_blocking(proc.stdin.fileno(), False)

    def write_deadline(data):
        with selectors.DefaultSelector() as writer:
            writer.register(proc.stdin, selectors.EVENT_WRITE)
            while data:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not writer.select(remaining):
                    raise Incomplete('credential event stream timed out')
                try:
                    count = os.write(proc.stdin.fileno(), data)
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise Incomplete('credential event stream incomplete')
                data = data[count:]

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate event field')
            result[key] = value
        return result

    def consume(line, acknowledge):
        nonlocal sequence, auth_count, summary, ended
        try:
            event = json.loads(line, object_pairs_hook=unique_object)
            if not isinstance(event, dict):
                raise ValueError()
            # Preserve complete credentials even if the frame sequence is bad.
            if event.get('type') == 'auth' and isinstance(event.get('credentials'), dict):
                for value in event['credentials'].values():
                    if isinstance(value, str) and value:
                        register(value)
            if type(event.get('sequence')) is not int or event['sequence'] != sequence or ended:
                raise ValueError()
            sequence += 1
            kind = event.get('type')
            if kind == 'auth':
                values, status = event.get('credentials'), event.get('status')
                if (summary is not None or auth_count >= len(expected_auth) or not isinstance(values, dict)
                        or type(status) is not int or not 100 <= status <= 599):
                    raise ValueError()
                source, fields, must_succeed = expected_auth[auth_count]
                if event.get('source') != source or (must_succeed and not 200 <= status < 300):
                    raise ValueError()
                if any(not isinstance(k, str) or not isinstance(v, str) or len(v) < 6
                       for k, v in values.items()):
                    raise ValueError()
                if 200 <= status < 300 and set(values) != set(fields):
                    raise ValueError()
                auth_count += 1
            elif kind == 'summary':
                if summary is not None or auth_count != len(expected_auth) or not isinstance(event.get('data'), dict):
                    raise ValueError()
                summary = event['data']
            elif kind == 'end':
                if summary is None:
                    raise ValueError()
                ended = True
            else:
                raise ValueError()
            if acknowledge:
                write_deadline(b'OK\n')
        except Exception:
            raise Incomplete('credential event stream incomplete') from None

    try:
        write_deadline(request_bytes)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Incomplete('credential event stream timed out')
            ready = selector.select(remaining)
            if not ready:
                raise Incomplete('credential event stream timed out')
            chunk = os.read(proc.stdout.fileno(), 65536)
            if not chunk:
                if buffer:
                    raise Incomplete('credential event stream truncated')
                break
            total += len(chunk)
            buffer += chunk
            if total > MAX_STREAM or len(buffer) > MAX_FRAME:
                raise Incomplete('credential event frame too large')
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                if len(line) > MAX_FRAME:
                    raise Incomplete('credential event frame too large')
                consume(line, True)
        if not ended or auth_count != len(expected_auth) or proc.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise Incomplete('credential event stream incomplete')
        return summary
    except (Incomplete, OSError, subprocess.TimeoutExpired) as exc:
        error = exc if isinstance(exc, Incomplete) else Incomplete('credential event stream incomplete')
        # Kill first to close the writer; then preserve any complete frames already
        # in the pipe even when the producer exited or the deadline elapsed.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        os.set_blocking(proc.stdout.fileno(), False)
        while True:
            try:
                chunk = os.read(proc.stdout.fileno(), 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            if len(buffer) + len(chunk) > MAX_FRAME:
                break
            buffer += chunk
        for line in buffer.split(b'\n')[:-1]:
            try:
                consume(line, False)
            except Incomplete:
                pass
        raise error from None
    finally:
        selector.close()
        proc.stdin.close()
        proc.stdout.close()
