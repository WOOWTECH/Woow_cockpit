#!/usr/bin/env python3
"""Run one services-a real lab attempt and write its evidence JSON (never overwrites an attempt).

  python3 tests/e2e/lab/services_a_capture.py <evidence.json> <scope> -- <command...>

The JSON holds: source commit, scope, exit code, elapsed seconds, SHA-256 of the
complete stdout, only the stdout lines matching a fixed status vocabulary (no
free text, no values), the number of stderr bytes (never published) and
commercial_acceptance "not-complete" (a single real run is not the full
end-to-end commercial acceptance). The full stdout is kept only in a private
0600 file next to the caller's scratch area when --private is given.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[3]
# Fixed status vocabulary: a whole line must match one of these.
STATUS = [re.compile(p) for p in (
    r'[A-Z0-9_]+=(PASS|FAIL)( [a-z_]+=[A-Za-z0-9_.:-]+)*',
    r'[A-Z0-9_]+=[a-z_]+:(PASS|FAIL) attempts=[0-9]+ elapsed=[0-9.]+s( client=(real|none))?',
    r'[A-Za-z0-9 ,()/:\'<>.=_-]{3,140}: (PASS|FAIL)( \([A-Za-z0-9 :,_-]{1,60}\))?',
    r'[A-Za-z0-9 ,()/:\'<>.=_-]{3,140}: [0-9]{1,3}/[0-9]{1,3} (PASS|FAIL)',
    r'product convert: (PASS|FAIL)( [a-z_]+=[A-Za-z0-9_]{0,80})*',
    r'CHECK [a-z-]+: FAIL [a-z_]+',
    r'controller exit=[0-9]{1,3}',
    r'cleanup: verified no test objects or private run files remain',
    r'Synthetic credential coverage: named authorization and private-key sources acknowledged; submitted log '
    r'snapshots \(possibly empty\) and redacted output scanned',
    r'Synthetic credential coverage incomplete; raw output suppressed.*',
    r'(AUTO_RECONNECT|MANUAL_RECOVERY)=(PASS|FAIL).*',
    r'DERP convergence: elapsed=[0-9]{1,4}s',
    r'tailscale up --login-server=<target URL> \(no auth key\): rc=[0-9]{1,3} in [0-9]{1,4}s',
    r'Real client state right after start \(HA server unreachable\): [A-Za-z]{1,20}',
    r'lock held for [0-9]{1,6} s',
    r'last runner step: [a-z0-9_]{1,40}',
    r'up refused: non-default flags',
    r'up output mentions login',
    r'dev-d memory current=[0-9]{1,12} limit=[0-9]{1,12}; headroom >= [0-9.]{1,5} GiB; host MemAvailable [0-9]{1,12} KiB',
    r'dev-d isolation: true none \{\}',
    r'source commit [0-9a-f]{40}',
)]


def git(*args):
    return subprocess.run(['git', '-C', str(REPO), *args], stdout=subprocess.PIPE, check=True,
                          timeout=60).stdout.decode().strip()


SAFE_TEXT = re.compile(r'[A-Za-z0-9_.:-]{0,80}')


def _safe_value(value, depth=0):
    if value is None or isinstance(value, bool) or isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        return SAFE_TEXT.fullmatch(value) is not None
    if isinstance(value, list) and depth < 2 and len(value) <= 40:
        return all(_safe_value(v, depth + 1) for v in value)
    if isinstance(value, dict) and depth < 2 and len(value) <= 20:
        return all(SAFE_TEXT.fullmatch(k) and _safe_value(v, depth + 1) for k, v in value.items())
    return False


def json_event(line):
    """A harness event line: a JSON object with a fixed-word 'stage' and only bools, numbers and short fixed-word
    strings (or small lists/objects of them). Anything else (free text, values with spaces or symbols) is dropped."""
    if not (line.startswith('{') and line.endswith('}')) or len(line) > 2000:
        return False
    try:
        doc = json.loads(line)
    except ValueError:
        return False
    return (isinstance(doc, dict) and isinstance(doc.get('stage'), str)
            and re.fullmatch(r'[a-z_]{1,40}', doc['stage']) is not None
            and all(re.fullmatch(r'[a-z_0-9]{1,60}', k) and _safe_value(v) for k, v in doc.items()))


def status_lines(text):
    return [line for line in text.splitlines() if any(p.fullmatch(line) for p in STATUS) or json_event(line)]


def main(argv):
    private = None
    if argv and argv[0].startswith('--private='):
        private = Path(argv.pop(0).split('=', 1)[1])
    target, scope, sep, *command = argv
    if sep != '--' or not command:
        raise SystemExit('usage: services_a_capture.py [--private=FILE] <evidence.json> <scope> -- <command...>')
    target = Path(target)
    if target.exists():
        raise SystemExit('evidence file exists; never overwrite an attempt')
    commit = git('rev-parse', 'HEAD')
    started = time.monotonic()
    proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=REPO)
    elapsed = time.monotonic() - started
    text = proc.stdout.decode('utf-8', 'replace')
    doc = {'source_commit': commit, 'scope': scope, 'exit': proc.returncode, 'elapsed_seconds': round(elapsed, 1),
           'stdout_sha256': hashlib.sha256(proc.stdout).hexdigest(), 'fixed_status': status_lines(text),
           'stderr_bytes_not_published': len(proc.stderr), 'commercial_acceptance': 'not-complete'}
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, 'x', encoding='utf-8') as handle:
        json.dump(doc, handle, indent=1, ensure_ascii=False)
        handle.write('\n')
    if private is not None:
        fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(proc.stdout + b'\n--- stderr ---\n' + proc.stderr)
    print(json.dumps({k: doc[k] for k in ('exit', 'elapsed_seconds', 'stdout_sha256')}))
    for line in doc['fixed_status']:
        print(line)
    return proc.returncode


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
