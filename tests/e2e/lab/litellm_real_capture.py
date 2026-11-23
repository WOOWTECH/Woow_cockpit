#!/usr/bin/env python3
"""Run one real LiteLLM lab attempt and write its evidence JSON (never overwrites an attempt).

  python3 tests/e2e/lab/litellm_real_capture.py <evidence.json> -- <command...>

The JSON holds the source commit, exit code, elapsed seconds, SHA-256 of the complete stdout, only the stdout lines
that are harness events (a JSON object with a fixed-word stage and only booleans, numbers and short fixed-word strings,
or small objects/lists of them), the number of stderr bytes (never published) and commercial_acceptance
"not-complete". Pattern of services_a_capture.py (test/services-a-final-20261123), with a wider object budget for the
per-table row counts.
"""
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WORD = re.compile(r'[A-Za-z0-9_.:-]{0,80}\Z')
KEY = re.compile(r'[A-Za-z0-9_]{1,60}\Z')
STAGE = re.compile(r'[a-z_]{1,40}\Z')


def safe_value(value, depth=0):
    if value is None or isinstance(value, (bool, int, float)):
        return True
    if isinstance(value, str):
        return WORD.fullmatch(value) is not None
    if isinstance(value, list) and depth < 2 and len(value) <= 64:
        return all(safe_value(v, depth + 1) for v in value)
    if isinstance(value, dict) and depth < 2 and len(value) <= 64:
        return all(isinstance(k, str) and KEY.fullmatch(k) and safe_value(v, depth + 1) for k, v in value.items())
    return False


def event_line(line):
    if not (line.startswith('{') and line.endswith('}')) or len(line) > 4000:
        return False
    try:
        doc = json.loads(line)
    except ValueError:
        return False
    return (isinstance(doc, dict) and isinstance(doc.get('stage'), str) and STAGE.fullmatch(doc['stage']) is not None
            and all(KEY.fullmatch(k) and safe_value(v) for k, v in doc.items()))


def status_lines(text):
    return [line for line in text.splitlines() if event_line(line)]


def main(argv):
    target, sep, *command = argv
    if sep != '--' or not command:
        raise SystemExit('usage: litellm_real_capture.py <evidence.json> -- <command...>')
    target = Path(target)
    if target.exists():
        raise SystemExit('evidence file exists; never overwrite an attempt')
    commit = subprocess.run(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], stdout=subprocess.PIPE, check=True,
                            timeout=60).stdout.decode().strip()
    started = time.monotonic()
    proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=REPO)
    elapsed = time.monotonic() - started
    lines = status_lines(proc.stdout.decode('utf-8', 'replace'))
    doc = {'source_commit': commit, 'scope': 'litellm-real-ha-x86-internal-candidate', 'exit': proc.returncode,
           'elapsed_seconds': round(elapsed, 1), 'stdout_sha256': hashlib.sha256(proc.stdout).hexdigest(),
           'fixed_status': lines, 'stderr_bytes_not_published': len(proc.stderr),
           'commercial_acceptance': 'not-complete'}
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, 'x', encoding='utf-8') as handle:
        json.dump(doc, handle, indent=1, ensure_ascii=False)
        handle.write('\n')
    print(json.dumps({k: doc[k] for k in ('exit', 'elapsed_seconds', 'stdout_sha256')}))
    for line in lines:
        print(line)
    return proc.returncode


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
