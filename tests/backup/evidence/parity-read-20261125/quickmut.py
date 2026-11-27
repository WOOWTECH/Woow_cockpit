"""quickmut.py TREE 'label|label' test.id [test.id ...]: apply the named mutants of mutations.py one by one to TREE (a private copy of
the lane tree) and run only the named tests (seconds, not the module): prints caught / SURVIVED / NOT-APPLIED. TREE is restored after each."""
import os, subprocess, sys
tree, only, tests = sys.argv[1], sys.argv[2], sys.argv[3:]
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mutations.py')).read()
head = src.split('results, t0 =')[0]
sys.argv = ['mutations.py', tree, '/dev/null']
ns = {}
exec(compile(head, 'mutations.py', 'exec'), ns)
env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH='backup-engine:tests/e2e/lab')
for label, path, old, new, count in ns['M']:
    if not any(part in label for part in only.split('|')):
        continue
    full = os.path.join(tree, path)
    source = open(full, encoding='utf-8').read()
    if source.count(old) != count:
        print('NOT-APPLIED', label, source.count(old), flush=True)
        continue
    open(full, 'w', encoding='utf-8').write(source.replace(old, new))
    try:
        try:
            run = subprocess.run([sys.executable, '-m', 'unittest', *tests], cwd=tree, env=env, capture_output=True, timeout=300)
            caught, why = run.returncode != 0, (run.stderr.decode('utf-8', 'replace').strip().splitlines() or [''])[-1]
        except subprocess.TimeoutExpired:
            caught, why = True, 'timeout'
    finally:
        open(full, 'w', encoding='utf-8').write(source)
    print('caught  ' if caught else 'SURVIVED', label, '|', why[:70], flush=True)
