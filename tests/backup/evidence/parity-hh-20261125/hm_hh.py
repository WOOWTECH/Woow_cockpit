#!/usr/bin/env python3
"""Hand mutants of ha_hermes.py and ha_headscale.py against named test targets (lane HERMES-HEADSCALE, HH-OWNER-1905).
Each rule or protection of the lane is removed, one place at a time, in a COPY of the repository (never the worktree); the named
tests must FAIL for each mutant and PASS on the unmodified copy. CONTROLS change a comment only and must go unnoticed. Nothing here
touches Podman, a device or a secret (the tests use doubles only).

usage: python3 -I hm_hh.py --repo /tmp/parity-hh-20261125 --muts muts_hh.py [--only ID,ID] [--out FILE.json]
muts_hh.py defines MUTS = [(id, 'ha_hermes.py'|'ha_headscale.py', tests tuple, old text (once in the module), new text)]
"""
import argparse, json, runpy, shutil, subprocess, sys, time
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument('--repo', required=True)
ap.add_argument('--muts', required=True)
ap.add_argument('--only')
ap.add_argument('--out')
args = ap.parse_args()
repo = Path(args.repo)
work = Path('/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/parity-hh/hm/work')
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
originals = {name: (work / 'backup-engine' / 'woowbackup' / name).read_text(encoding='utf-8') for name in {m[1] for m in MUTS}}
env = {'PYTHONPATH': f'{work}/backup-engine:{work}/tests/e2e/lab:{work}', 'PYTHONDONTWRITEBYTECODE': '1', 'PATH': '/usr/bin:/bin'}
GUARD = '/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/integration-3/guard.py'


def run(tests, tag):
    t0 = time.time()
    res = subprocess.run(['nice', '-n', '15', 'ionice', '-c3', sys.executable, GUARD, '--log', str(work / f'{tag}.log'), *tests],
                         cwd=work, env=env, capture_output=True, text=True, timeout=1800)
    tail = (res.stdout or '').strip().splitlines()[:1] or ['']
    return res.returncode, tail[0][:110], time.time() - t0


alltests = sorted({t for m in MUTS for t in m[2]})
rc, tail, sec = run(alltests, 'control')
print(f'control (unmodified): rc={rc} {tail} {sec:.0f}s', flush=True)
if rc != 0:
    sys.exit(1)
results, survived = [], []
for mid, module, tests, old, new in MUTS:
    original = originals[module]
    target = work / 'backup-engine' / 'woowbackup' / module
    control = mid.startswith('C')
    if original.count(old) != 1:
        print(mid, 'TEXT NOT ONCE', original.count(old), flush=True)
        survived.append(mid)
        results.append({'id': mid, 'verdict': 'NOT-APPLIED'})
        continue
    target.write_text(original.replace(old, new), encoding='utf-8')
    try:
        rc, tail, sec = run(tests, mid)
    finally:
        target.write_text(original, encoding='utf-8')
    verdict = ('unnoticed (control ok)' if rc == 0 else 'CONTROL NOTICED') if control else ('caught' if rc != 0 else 'SURVIVED')
    if (not control and rc == 0) or (control and rc != 0):
        survived.append(mid)
    results.append({'id': mid, 'verdict': verdict, 'tail': tail})
    print(f'{mid} {verdict} ({tail}) {sec:.0f}s', flush=True)
print('problems:', survived or 'none', flush=True)
if args.out:
    Path(args.out).write_text(json.dumps({'results': results, 'problems': survived}, ensure_ascii=False, indent=1))
sys.exit(1 if survived else 0)
