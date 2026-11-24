#!/usr/bin/env python3
"""Mutation check of the pg-stdin fix (2026-11-24): each protection of ha_odoo.Cluster listed in MUTATIONS is removed,
one place at a time, in a throwaway copy of the repository, and the unit tests must FAIL for each (and pass on the
unmodified copy). The protections: Cluster.write_file reads the written file back (size and digest), writes it
again at most twice more and then stops; Cluster.script opens and closes its own transaction in the input and
requires this call's end mark at the end of psql's output; Cluster.statement stays outside a transaction block.
CONTROLS change a comment only and must go unnoticed. Nothing here touches Podman, a device or a secret.

  python3 -I tests/backup/pg_stdin_mutations.py [--json OUT] [--only ID,ID]

Prints one fixed line per mutation (`<id> <name>: caught|MISSED (<failures>/<tests>)`); exit 0 only when the baseline
passes, every mutation is caught and no control is noticed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
OD = 'woowbackup/ha_odoo.py'
TESTS = ('tests.backup.test_ha_pg_stdin', 'tests.backup.test_ha_odoo', 'tests.backup.test_ha_flows')

# (id, protection, module, exact text, replacement, occurrences)
MUTATIONS = (
    ('P01', 'write_file reads the written file back', OD,
     '            found = self._read_back(path, timeout)\n', '            return\n', 1),
    ('P02', 'a short copy is written again', OD,
     'WRITE_ATTEMPTS = 3        #', 'WRITE_ATTEMPTS = 1        #', 1),
    ('P03', 'at most 2 more writes, then the job stops', OD,
     'WRITE_ATTEMPTS = 3        #', 'WRITE_ATTEMPTS = 4        #', 1),
    ('P04', 'the digest is compared, not only the size', OD,
     '                if expected[kind] == (size, value):\n', '                if expected[kind][0] == size:\n', 1),
    ('P05', 'a read-back that failed is no proof', OD,
     '        if result.returncode != 0 or len(lines) < 3 or', '        if len(lines) < 3 or', 1),
    ('P06', "POSIX cksum's length bytes", OD,
     '    while length:\n        crc = _cksum_update(crc, bytes([length & 0xFF]))\n        length >>= 8\n', '', 1),
    ('P07', 'an open file is rewound for every attempt', OD,
     '            if start is not None:\n                source.seek(start)\n            self.tmp.exec(',
     '            self.tmp.exec(', 1),
    ('P08', 'a pause between the attempts', OD,
     '                self.sleep(WRITE_RETRY_PAUSE)\n', '', 1),
    ('P09', 'script: the input opens and closes its own transaction', OD,
     "        self._run(f'BEGIN;\\n{sql}\\nCOMMIT;\\n', database, timeout)\n",
     "        self._run(f'{sql}\\n', database, timeout)\n", 1),
    ('P10', 'script/statement: the end mark is required', OD,
     "        if out.rstrip(b'\\n').rsplit(b'\\n', 1)[-1] != mark.encode('ascii'):\n"
     "            raise BackupError('job-failed', INCOMPLETE_SQL)\n", '', 1),
    ('P11', 'a new end mark for every call', OD,
     '        mark = SQL_END_MARK + secrets.token_hex(8)\n', "        mark = SQL_END_MARK + '0' * 16\n", 1),
    ('P12', 'the end mark must END the output', OD,
     "        if out.rstrip(b'\\n').rsplit(b'\\n', 1)[-1] != mark.encode('ascii'):\n",
     "        if mark.encode('ascii') not in out:\n", 1),
    ('P13', 'statement stays outside a transaction block (review C-19)', OD,
     "        self._run(sql.strip().rstrip(';') + ';\\n', database, timeout)\n",
     "        self._run('BEGIN;\\n' + sql.strip().rstrip(';') + ';\\nCOMMIT;\\n', database, timeout)\n", 1),
    ('P14', 'the retry note names no content and the attempt', OD,
     "重新寫入（第 {attempt + 1} 次，共 {WRITE_ATTEMPTS} 次）。", "重新寫入。", 1),
    ('P15', 'the final failure is the zh-TW INCOMPLETE_FILE message', OD,
     "        raise BackupError('job-failed', INCOMPLETE_FILE)\n", "        raise BackupError('job-failed', '失敗。')\n", 1),
)

CONTROLS = (
    ('C01', 'a changed comment in ha_odoo.py', OD, '# Cluster.write_file: the first write and at most 2 more',
     '# Cluster.write_file: the first write and up to 2 more', 1),
)


def outcome(text):
    """(tests run, failures and errors) from unittest's own summary lines, wherever they are."""
    ran, failures = 0, 0
    for line in text.splitlines():
        if m := re.fullmatch(r'Ran (\d+) tests? in .*', line):
            ran, failures = int(m.group(1)), 0
        elif ran and (m := re.fullmatch(r'FAILED \((.*)\)', line)):
            failures = sum(int(n) for n in re.findall(r'(?<!expected )\b(?:failures|errors)=(\d+)', m.group(1)))
    return ran, failures


def run_tests(root, failfast=True):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(root / 'backup-engine'), str(root)]),
               PYTHONDONTWRITEBYTECODE='1')
    proc = subprocess.run([sys.executable, '-m', 'unittest', *(['-f'] if failfast else []), *TESTS], cwd=root, env=env,
                          capture_output=True, timeout=1800)
    return proc.returncode, *outcome(proc.stderr.decode('utf-8', 'replace'))


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--json')
    parser.add_argument('--only', help='comma-separated mutation ids (a subset; the baseline always runs)')
    args = parser.parse_args(argv)
    only = set(args.only.split(',')) if args.only else None
    source = (REPO / 'backup-engine' / OD).read_text(encoding='utf-8')
    results, controls = [], []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='pg-stdin-mutation-') as directory:
        root = Path(directory)
        skip = shutil.ignore_patterns('__pycache__', '.git', 'node_modules', 'evidence', 'e2e')
        for item in REPO.iterdir():
            if item.name in ('.git', 'node_modules'):
                continue
            if item.is_dir():
                shutil.copytree(item, root / item.name, ignore=skip, symlinks=True)
            else:
                shutil.copy2(item, root / item.name)
        target = root / 'backup-engine' / OD
        rc, ran, failures = run_tests(root, failfast=False)
        baseline = {'returncode': rc, 'tests': ran, 'failures': failures}
        print(f'baseline: {"pass" if rc == 0 else "FAIL"} ({failures}/{ran})', flush=True)
        for ident, name, _module, old, new, count in MUTATIONS:
            if only is not None and ident not in only:
                continue
            if source.count(old) != count:
                results.append({'id': ident, 'protection': name, 'applied': False})
                print(f'{ident} {name}: NOT APPLIED (pattern count {source.count(old)})', flush=True)
                continue
            target.write_text(source.replace(old, new), encoding='utf-8')
            rc, ran, failures = run_tests(root)
            target.write_text(source, encoding='utf-8')
            caught = rc != 0 and failures > 0
            results.append({'id': ident, 'protection': name, 'applied': True, 'caught': caught, 'failures': failures,
                            'tests': ran})
            print(f'{ident} {name}: {"caught" if caught else "MISSED"} ({failures}/{ran})', flush=True)
        for ident, name, _module, old, new, count in CONTROLS:
            applied = source.count(old) == count
            rc, ran, failures = 1, 0, 0
            if applied:
                target.write_text(source.replace(old, new), encoding='utf-8')
                rc, ran, failures = run_tests(root)
                target.write_text(source, encoding='utf-8')
            quiet = applied and rc == 0 and ran > 0
            controls.append({'id': ident, 'change': name, 'applied': applied, 'unnoticed': quiet, 'failures': failures,
                             'tests': ran})
            print(f'{ident} control, {name}: {"not noticed" if quiet else "NOTICED"} ({failures}/{ran})', flush=True)
    ok = (baseline['returncode'] == 0 and all(r.get('applied') and r.get('caught') for r in results)
          and all(c['unnoticed'] for c in controls))
    summary = {'module_sha256': hashlib.sha256(source.encode('utf-8')).hexdigest(), 'tests': list(TESTS),
               'baseline': baseline, 'mutations': results, 'controls': controls, 'all_caught': ok,
               'subset': sorted(only) if only is not None else None, 'seconds': round(time.monotonic() - started, 1)}
    if args.json:
        Path(args.json).write_text(json.dumps(summary, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    print(f'mutation check: {"PASS" if ok else "FAIL"} ({sum(1 for r in results if r.get("caught"))}/{len(results)} caught)')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
