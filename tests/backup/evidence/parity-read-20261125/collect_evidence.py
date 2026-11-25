"""Collects the records of a verification chain (runs/TAG-*) into the evidence folder of the lane's snippets: summaries and counts only (no test
output with values, no names of secrets), the scripts that made them, status.json. usage: collect_evidence.py TAG   (the chain run-it3.sh TAG)"""
import json, os, re, shutil, subprocess, sys
S = '/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad'
P, R = S + '/parity-read', S + '/parity-read/runs'
OUT = S + '/parity/snippets/parity-read/evidence'
TAG = sys.argv[1]

def read(name, default=''):
    try:
        return open(os.path.join(R, name), encoding='utf-8', errors='replace').read()
    except OSError:
        return default

def summary_of_guard(out):
    """The summary line of the guard and the ids of the tests that did not pass (no messages)."""
    lines = out.splitlines()
    head = next((l for l in lines if l.startswith('tests=')), '')
    bad = [re.sub(r' blocked_in_test=.*', '', l) for l in lines if l.startswith(('FAIL ', 'ERROR '))]
    return head, bad

shutil.rmtree(OUT, ignore_errors=True)
os.makedirs(OUT, exist_ok=True)
status = {'lane': 'READ', 'owner_instance': 'READ-OWNER-1605', 'iteration': 3, 'branch': 'parity/read-20261125', 'commercial_acceptance': 'not-complete',
          'tip': read(TAG + '.tip').strip(), 'merge_tree': read(TAG + '-merge.head').strip(), 'steps': {}}
for step in ('b1', 'ha118', 'merge-b1'):
    out = read(f'{TAG}-{step}.out')
    head, bad = summary_of_guard(out)
    status['steps'][step] = {'exit': read(f'{TAG}-{step}.exit').strip(), 'summary': head, 'not_ok': bad}
    open(os.path.join(OUT, 'suite-' + step + '.txt'), 'w').write(head + '\n' + '\n'.join(bad) + '\n')
if read(TAG + '-units.out') or read(TAG + '-units.err'):
    text = read(TAG + '-units.out') + read(TAG + '-units.err')
    open(os.path.join(OUT, 'units.txt'), 'w').write(text)
    status['steps']['units'] = {'exit': read(TAG + '-units.exit').strip(), 'last_line': text.strip().splitlines()[-1][:200]}
mut = json.loads(read(TAG + '-mut.json', '{}') or '{}')
if mut:
    tally = {}
    for r in mut['results']:
        tally[r['result']] = tally.get(r['result'], 0) + 1
    status['steps']['mutations'] = {'tally': tally, 'survivors': [r['label'] for r in mut['results'] if r['result'] != 'caught'], 'seconds': mut['seconds'],
                                    'one_run': True}
    shutil.copy(os.path.join(R, TAG + '-mut.json'), os.path.join(OUT, 'mutations.json'))
for step, dest in (('diffsmall', 'diff-small.json'), ('difflarge', 'diff-large.json'), ('realfiles', 'real_files.json')):
    if os.path.exists(os.path.join(R, TAG + '-' + step + '.json')):
        shutil.copy(os.path.join(R, TAG + '-' + step + '.json'), os.path.join(OUT, dest))
for step, dest in (('realfiles', 'real_files.out'), ('fuzz', 'long-fuzz.out'), ('mem4m', 'mem4m.out'), ('mem4m1', 'mem4m1.out'),
                   ('check_schema', 'check_schema.out'), ('diff_tarfile', 'diff_tarfile.out'), ('struct_fuzz', 'struct_fuzz.out'),
                   ('struct_fuzz2', 'struct_fuzz2.out'), ('job_level', 'job_level.out'), ('kinds', 'kinds.out'),
                   ('tests-on-engine-it2', 'tests-on-engine-iteration2.out'), ('probe_diff', 'probe_diff.out'), ('quickmut-intended', 'mutants-vs-their-own-test.out')):
    own = read(TAG + '-' + step + '.out')
    text = own or (read('it2b-' + step + '.out') if step in ('mem4m', 'mem4m1') else '')
    if text:
        open(os.path.join(OUT, dest), 'w').write(text)
        status['steps'][step] = {'exit': read(TAG + '-' + step + '.exit').strip(), 'last_line': text.strip().splitlines()[-1][:300]}
        if not own:
            status['steps'][step] = {'note': 'NOT repeated in iteration 3 (stopped on purpose: the walk and the names table are unchanged, the host was saturated); this is the record of it2b',
                                     'last_line': text.strip().splitlines()[-1][:300]}
if read('probe_cost.out'):
    open(os.path.join(OUT, 'probe_cost.out'), 'w').write(read('probe_cost.out'))
old = read('old-tests-it2b.log')
if old:
    fails = sorted({re.sub(r' \(tests\.backup.*', '', l) for l in old.splitlines() if l.startswith(('FAIL:', 'ERROR:'))})
    open(os.path.join(OUT, 'old-tests.txt'), 'w').write('\n'.join(fails) + '\n' + (old.strip().splitlines()[-1] if old.strip() else '') + '\n')
    status['steps']['old-tests'] = {'note': 'run at iteration 2 (it2b); the reading paths of those tests are unchanged since (iteration 3 changed the probe behind a plain tar and the header sum only)'}
for script in ('differential.py', 'real_files.py', 'mutations.py', 'long_fuzz.py', 'mem4m.py', 'diff_tarfile.py', 'struct_fuzz.py', 'struct_fuzz2.py',
               'check_schema.py', 'job_level.py', 'member_kinds.py', 'probe_cost.py', 'probe_diff.py', 'quickmut.py', 'run-it3.sh', 'run-it3-mut.sh', 'run-it3-group.sh', 'skip-mem4m.sh',
               'run-mut-some.sh', 'refresh-mut-tree.sh',
               'collect_evidence.py', 'make_readme.py', 'scan_evidence.py', 'evidence-README.template.md'):
    if os.path.exists(os.path.join(P, script)):
        shutil.copy(os.path.join(P, script), os.path.join(OUT, script))
json.dump(status, open(os.path.join(OUT, 'status.json'), 'w'), indent=1, ensure_ascii=False)
print(json.dumps({k: (v if k != 'steps' else list(v)) for k, v in status.items()}, ensure_ascii=False))
