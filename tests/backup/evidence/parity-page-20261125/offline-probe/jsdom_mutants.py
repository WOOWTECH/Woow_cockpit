#!/usr/bin/env python3
"""Mutation sweep of lane PAGE judged by the jsdom scenarios (light: no browser). The same 27 mutants as page_mutants.py (one change of backup.js each)."""
import os, shutil, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = '/tmp/parity-page-20261125'
src = open(os.path.join(HERE, 'page_mutants.py'), encoding='utf-8').read()
start, end = src.index('MUTANTS = ['), src.index('def run(')
pre = '\n'.join(line for line in src[:src.index('MUTANTS = [')].splitlines() if line.startswith(('MAIN', 'DB', 'RETRY', 'NOANS', 'ADOPT', 'KEY', 'NOKEY', 'NOKEY2', 'STOPAFTER', 'CANCEL', 'RECONF', 'JOB', 'RELOAD', 'LEGACY', 'RESTORE', 'CHOICE')))
ns = {}
exec(pre + '\n' + src[start:end], ns)
MUTANTS = ns['MUTANTS']
SCEN = {'m01': 'main', 'm02': 'main', 'm03': 'main', 'm04': 'main', 'm05': 'main', 'm06': 'main', 'm07': 'main', 'm08': 'database', 'm09': 'main', 'm10': 'main', 'm11': 'database',
        'm12': 'retry', 'm13': 'adopt', 'm14': 'key with a Tab', 'm15': 'job not found', 'm16': 'no device key', 'm17': 'main', 'm18': 'main', 'm19': 'stop after', 'm20': 'restore of a converted',
        'm21': 'no device key', 'm22': 'legacy engine', 'm23': 'main', 'm24': 'choice', 'm25': 'reconfirm', 'm26': 'cancel the whole', 'm27': 'reload'}
OUT = sys.argv[1]
ONLY = sys.argv[2:]
os.makedirs(OUT, exist_ok=True)

def tree(name, change):
    root = os.path.join(OUT, name)
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(os.path.join(root, 'backup'))
    for item in os.listdir(os.path.join(REPO, 'backup')):
        shutil.copy2(os.path.join(REPO, 'backup', item), os.path.join(root, 'backup', item))
    os.symlink(os.path.join(REPO, 'tests'), os.path.join(root, 'tests'))
    if change:
        path = os.path.join(root, 'backup', 'backup.js')
        text = open(path, encoding='utf-8').read()
        if text.count(change[0]) != 1:
            return None
        open(path, 'w', encoding='utf-8').write(text.replace(change[0], change[1]))
    return root

def run(root, scenario):
    started = time.time()
    done = subprocess.run(['node', os.path.join(HERE, 'jsdom', 'scenarios.cjs'), scenario], env=dict(os.environ, PAGE_REPO=root), capture_output=True, text=True, timeout=300)
    return done.returncode, round(time.time() - started, 1), done.stdout[-400:].replace('\n', ' | ')

summary = open(os.path.join(OUT, 'summary.txt'), 'w', encoding='utf-8')
def note(line):
    summary.write(line + '\n'); summary.flush(); print(line, flush=True)
root = tree('control', None)
for scenario in sorted(set(SCEN.values())):
    code, secs, tail = run(root, scenario)
    note(f'control {scenario!r} rc={code} {secs}s')
caught = 0
for mid, what, old, new, _tests in MUTANTS:
    if ONLY and mid not in ONLY:
        continue
    root = tree(mid, (old, new))
    if root is None:
        note(f'{mid} BROKEN-MUTANT :: {what}'); continue
    code, secs, tail = run(root, SCEN[mid])
    caught += code != 0
    note(f'{mid} {"CAUGHT" if code != 0 else "NOT-CAUGHT"} rc={code} {secs}s by {SCEN[mid]!r} :: {what}')
    shutil.rmtree(root, ignore_errors=True)
note(f'done: {caught} caught of {len([m for m in MUTANTS if not ONLY or m[0] in ONLY])}')
