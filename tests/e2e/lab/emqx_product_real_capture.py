#!/usr/bin/env python3
"""Run one emqx-product lab attempt and write its evidence JSON (never overwrites an attempt).

  python3 -I tests/e2e/lab/emqx_product_real_capture.py [--private=FILE] <evidence.json> <scope> -- <command...>

The JSON holds the source commit, the scope, the exit code, the elapsed seconds, the SHA-256 of the complete stdout,
only the stdout lines of a fixed status vocabulary (emqx_product_real_ha.py prints nothing else that is published), the
number of stderr bytes (never published) and commercial_acceptance "not-complete". With --private the complete
stdout and stderr go to that new 0600 file (outside the repository). stdout of this wrapper: the summary and the
FAIL/SKIP lines only.
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
STATUS = [re.compile(p) for p in (
    r'source commit [0-9a-f]{40}',
    r'dev-d isolation: true none \{\}',
    r'lock acquired after [0-9]{1,6} s',
    r'lock held for [0-9]{1,6} s',
    r'dev-d memory current=[0-9]{1,12} limit=[0-9]{1,12} headroom=-?[0-9]{1,12}',
    r'host MemAvailable=[0-9]{1,12} KiB disk free=[0-9]{1,15} B',
    r'dev-d reclaim headroom_before=-?[0-9]{1,12} headroom_after=-?[0-9]{1,12} journal_before=[0-9]{1,12} '
    r'journal_after=[0-9]{1,12} rounds=[0-9]{1,3}',
    r'STEP [a-z0-9:-]{1,40}: (PASS|FAIL|SKIP)( [a-z_]{1,30}=[0-9.]{1,12})?',
    r"CHECK [A-Za-z0-9 ,()/:'<>.=_+#-]{1,200}: (PASS|FAIL)",
    r'RESULT [0-9]{1,5}/[0-9]{1,5} passed',
    r'backup id (converted|safety|baseline) [0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',
    r'offline self-check passed: [A-Za-z0-9 ,.-]{1,120}',
)]


def status_lines(text):
    return [line for line in text.splitlines() if any(p.fullmatch(line) for p in STATUS)]


def git(*args):
    return subprocess.run(['git', '-C', str(REPO), *args], stdout=subprocess.PIPE, check=True,
                          timeout=60).stdout.decode().strip()


def main(argv):
    private = None
    if argv and argv[0].startswith('--private='):
        private = Path(argv.pop(0).split('=', 1)[1])
    if len(argv) < 4 or argv[2] != '--':
        raise SystemExit('usage: emqx_product_real_capture.py [--private=FILE] <evidence.json> <scope> -- <command...>')
    target, scope, _sep, *command = argv
    target = Path(target)
    if target.exists():
        raise SystemExit('evidence file exists; never overwrite an attempt')
    if not re.fullmatch(r'[a-z0-9:+-]{1,80}', scope):
        raise SystemExit('scope must be a short fixed word')
    commit = git('rev-parse', 'HEAD')
    started = time.monotonic()
    proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=REPO)
    elapsed = time.monotonic() - started
    text = proc.stdout.decode('utf-8', 'replace')
    lines = status_lines(text)
    doc = {'source_commit': commit, 'scope': scope, 'exit': proc.returncode, 'elapsed_seconds': round(elapsed, 1),
           'stdout_sha256': hashlib.sha256(proc.stdout).hexdigest(), 'fixed_status': lines,
           'stdout_lines_not_published': len(text.splitlines()) - len(lines),
           'stderr_bytes_not_published': len(proc.stderr), 'commercial_acceptance': 'not-complete'}
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, 'x', encoding='utf-8') as handle:
        json.dump(doc, handle, indent=1, ensure_ascii=False)
        handle.write('\n')
    if private is not None:
        fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(proc.stdout + b'\n--- stderr ---\n' + proc.stderr)
    passed = sum(1 for line in lines if line.startswith('CHECK ') and line.endswith(': PASS'))
    failed = [line for line in lines if line.startswith('CHECK ') and line.endswith(': FAIL')]
    print(json.dumps({k: doc[k] for k in ('exit', 'elapsed_seconds', 'stdout_sha256')} | {'checks_passed': passed}))
    for line in failed + [line for line in lines if line.startswith(('STEP ', 'RESULT ', 'lock '))]:
        print(line)
    return proc.returncode


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
