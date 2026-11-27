#!/usr/bin/env python3
"""Hand mutants of ha_odoo.py against a few named test targets (light: seconds per mutant, nothing but unit doubles).
usage: python3 -I hm.py --repo /tmp/parity-odoo-20261125 --muts muts.py [--only ID,ID]
muts.py defines MUTS = [(id, tests tuple/list of unittest names, old text (once in ha_odoo.py), new text)]
The mutant runs in a COPY (scratchpad/parity-odoo/hm/work); the worktree is never touched. Exit text: 'caught' when the
targets fail (or error) on the mutant, 'SURVIVED' when they pass; the unmodified copy must pass first."""
import argparse, runpy, shutil, subprocess, sys, time
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('--repo', required=True)
ap.add_argument('--muts', required=True)
ap.add_argument('--only')
args = ap.parse_args()
repo = Path(args.repo)
work = Path('/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/parity-odoo/hm/work')
if work.exists():
    shutil.rmtree(work)
work.mkdir(parents=True)
for rel in ('backup-engine', 'tests/backup', 'tests/e2e/lab'):
    shutil.copytree(repo / rel, work / rel, ignore=shutil.ignore_patterns('__pycache__'))
(work / 'tests' / '__init__.py').write_text('')
MUTS = runpy.run_path(args.muts)['MUTS']
if args.only:
    keep = set(args.only.split(','))
    MUTS = [m for m in MUTS if m[0] in keep]
target = work / 'backup-engine' / 'woowbackup' / 'ha_odoo.py'
original = target.read_text(encoding='utf-8')
env = {'PYTHONPATH': f'{work}/backup-engine:{work}/tests/e2e/lab:{work}', 'PYTHONDONTWRITEBYTECODE': '1', 'PATH': '/usr/bin:/bin'}


def run(tests):
    t0 = time.time()
    res = subprocess.run([sys.executable, '-m', 'unittest', *tests], cwd=work, env=env, capture_output=True, text=True,
                         timeout=900)
    tail = (res.stderr or '').strip().splitlines()[-1:] or ['']
    return res.returncode, tail[0][:100], time.time() - t0


alltests = sorted({t for m in MUTS for t in m[1]})
rc, tail, sec = run(alltests)
print(f'control (unmodified): rc={rc} {tail} {sec:.0f}s')
if rc != 0:
    sys.exit(1)
survived = []
for mid, tests, old, new in MUTS:
    if original.count(old) != 1:
        print(mid, 'TEXT NOT ONCE', original.count(old))
        survived.append(mid)
        continue
    target.write_text(original.replace(old, new), encoding='utf-8')
    rc, tail, sec = run(tests)
    verdict = 'caught' if rc != 0 else 'SURVIVED'
    if rc == 0:
        survived.append(mid)
    print(f'{mid} {verdict} ({tail}) {sec:.0f}s')
target.write_text(original, encoding='utf-8')
print('survivors:', survived or 'none')
