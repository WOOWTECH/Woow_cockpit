"""Private, acknowledged credential events from a short-lived lab probe."""
import json
import os
import selectors
import signal
import subprocess
import time


class Incomplete(RuntimeError):
    """The producer did not establish a complete event stream."""


def run_events(argv, request, register, expected_auth, timeout=600):
    """Register each complete credential event before acknowledging the producer.

    No raw stdout/stderr is exposed on errors. A summary is usable only after a
    contiguous stream, the expected number of auth outcomes, an end frame, EOF,
    and successful process exit. The producer must wait for each acknowledgement.
    """
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, start_new_session=True, bufsize=0)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    buffer = b''
    sequence = auth_count = 0
    summary = None
    ended = False
    deadline = time.monotonic() + timeout
    error = None

    def consume(line, acknowledge):
        nonlocal sequence, auth_count, summary, ended
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError()
            # Preserve complete credentials even if the frame sequence is bad.
            if event.get('type') == 'auth' and isinstance(event.get('credentials'), list):
                for value in event['credentials']:
                    if isinstance(value, str) and len(value) >= 6:
                        register(value)
            if type(event.get('sequence')) is not int or event['sequence'] != sequence or ended:
                raise ValueError()
            sequence += 1
            kind = event.get('type')
            if kind == 'auth':
                values, status = event.get('credentials'), event.get('status')
                if (summary is not None or not isinstance(values, list) or type(status) is not int or
                    not 100 <= status <= 599 or any(not isinstance(v, str) or len(v) < 6 for v in values) or
                    (200 <= status < 300 and not values)):
                    raise ValueError()
                auth_count += 1
            elif kind == 'summary':
                if summary is not None or auth_count != expected_auth or not isinstance(event.get('data'), dict):
                    raise ValueError()
                summary = event['data']
            elif kind == 'end':
                if summary is None:
                    raise ValueError()
                ended = True
            else:
                raise ValueError()
            if acknowledge:
                proc.stdin.write(b'OK\n')
                proc.stdin.flush()
        except Exception:
            raise Incomplete('credential event stream incomplete') from None

    try:
        proc.stdin.write(json.dumps(request, ensure_ascii=False).encode('utf-8') + b'\n')
        proc.stdin.flush()
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
            buffer += chunk
            if len(buffer) > 4 * 1024 * 1024:
                raise Incomplete('credential event frame too large')
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                consume(line, True)
        if not ended or auth_count != expected_auth or proc.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
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
