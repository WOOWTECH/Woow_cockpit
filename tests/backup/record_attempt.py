#!/usr/bin/env python3
"""Run one real bounded probe attempt and record evidence next to the earlier attempts.
python3 tests/backup/record_attempt.py --name large-negatives-8193mib -- tests/backup/bounded_large_negatives.py --mib 8193

Refuses a dirty tree (the source commit must describe the code that ran). The probe runs under nice -n 10 ionice -c3.
Writes tests/backup/evidence/<name>[-attemptN].stdout.json (the probe's own JSON report, byte for byte) and
<name>[-attemptN].attempt.json: exit code, fixed status lines derived from the report, elapsed seconds, stdout sha256,
source commit, commercial_acceptance 'not-complete'. stderr is never stored, only its size and sha256.
Existing attempts are never overwritten.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'tests' / 'backup' / 'evidence'


def git(*args):
    return subprocess.run(['git', '-C', str(ROOT), *args], capture_output=True, text=True, check=True).stdout.strip()


def status_lines(report):
    lines = [f"status={report.get('status')}"]
    for key in ('error_type', 'error_code', 'harness_check'):
        if report.get(key):
            lines.append(f'{key}={report[key]}')
    for name, case in (report.get('cases') or {}).items():
        outcome = case.get('error_code') or case.get('exception') or ''
        lines.append(f"case {name}: {case.get('status', 'not-finished')} {outcome}".rstrip())
    return lines


def target(name):
    attempt = 1
    while True:
        stem = name if attempt == 1 else f'{name}-attempt{attempt}'
        if not (EVIDENCE / f'{stem}.attempt.json').exists() and not (EVIDENCE / f'{stem}.stdout.json').exists():
            return stem, attempt
        attempt += 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('probe', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    probe = [part for part in args.probe if part != '--']
    if not probe or not probe[0].startswith('tests/backup/') or not probe[0].endswith('.py'):
        parser.error('probe must be a tests/backup/*.py script and its arguments')
    if git('status', '--porcelain', '--untracked-files=no'):
        print('refusing: tracked files are modified; commit tested code first', file=sys.stderr)
        return 2
    commit = git('rev-parse', 'HEAD')
    stem, attempt = target(args.name)
    started = time.monotonic()
    begun = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    proc = subprocess.run(['nice', '-n', '10', 'ionice', '-c3', sys.executable, *probe], cwd=ROOT,
                          capture_output=True, check=False)
    elapsed = round(time.monotonic() - started, 3)
    stdout_path = EVIDENCE / f'{stem}.stdout.json'
    stdout_path.write_bytes(proc.stdout)
    try:
        report = json.loads(proc.stdout)
    except ValueError:
        report = {'status': 'unparseable-report'}
    record = dict(name=args.name, attempt=attempt, command=' '.join(['python3', *probe]),
                  runner='nice -n 10 ionice -c3', source_commit=commit, started_utc=begun,
                  finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
                  exit_code=proc.returncode, elapsed_seconds=elapsed, stdout_file=stdout_path.name,
                  stdout_sha256=hashlib.sha256(proc.stdout).hexdigest(), stdout_bytes=len(proc.stdout),
                  stderr_sha256=hashlib.sha256(proc.stderr).hexdigest(), stderr_bytes=len(proc.stderr),
                  stderr_stored=False, status_lines=status_lines(report),
                  commercial_acceptance='not-complete')
    (EVIDENCE / f'{stem}.attempt.json').write_text(json.dumps(record, indent=2, ensure_ascii=False) + '\n')
    print('\n'.join([f'evidence={stem}', f'exit_code={proc.returncode}', f'elapsed_seconds={elapsed}',
                     *record['status_lines']]))
    return proc.returncode


if __name__ == '__main__':
    sys.exit(main())
