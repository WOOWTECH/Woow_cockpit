"""Mutation sweep of lane PKG (iteration 2): each change of a copy must make the tests fail, each control must not.
usage: mutate5.py <worktree> <workdir> <report> [label words...]   (works on `git archive HEAD` of the worktree plus its three files)"""
import importlib.util, json, os, shutil, subprocess, sys, time
from pathlib import Path

TREE, WORK, REPORT = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
spec = importlib.util.spec_from_file_location('mutations', os.environ.get('MUTATIONS_FILE') or Path(__file__).with_name('mutations.py'))
mutations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mutations)
M, B = mutations.M, mutations.B
TESTS = ['tests.test_manage.HostToolsContract', 'tests.test_manage.BootstrapContract']


def run(tree):
    env = {**os.environ, 'PYTHONPATH': f'{tree}/backup-engine:{tree}/tests/e2e/lab', 'PYTHONDONTWRITEBYTECODE': '1'}
    proc = subprocess.run([sys.executable, '-m', 'unittest', '-f', *TESTS], cwd=tree, env=env, capture_output=True, text=True,
                          timeout=900)
    lines = proc.stderr.strip().splitlines()
    failed = [line.split()[1] for line in lines if line.startswith(('FAIL:', 'ERROR:'))]
    return proc.returncode, lines[-1] if lines else '', sorted(set(failed))


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    tree = WORK / 'tree'
    tree.mkdir()
    head = subprocess.run(['git', '-C', str(TREE), 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True).stdout.strip()
    archive = subprocess.run(['git', '-C', str(TREE), 'archive', 'HEAD', '--', '.', ':(exclude)tests/backup', ':(exclude)tests/e2e',
                              ':(exclude)docs', ':(exclude)reports', ':(exclude)research'], capture_output=True, check=True).stdout
    subprocess.run(['tar', '-x', '-C', str(tree)], input=archive, check=True)
    original = {name: (tree / name).read_text() for name in (M, B)}
    report = {'started': time.strftime('%Y-%m-%d %H:%M:%S'), 'head': head, 'results': []}
    code, last, failed = run(tree)
    report['baseline'] = {'code': code, 'last': last, 'failed': failed}
    print('baseline', code, last, flush=True)
    if code != 0:
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=1))
        return 2
    only = sys.argv[4:]
    wrong = 0
    todo = [(m, False) for m in mutations.MUTATIONS] + [(m, True) for m in mutations.CONTROLS]
    for (label, name, old, new), control in todo:
        if only and not any(word in label for word in only):
            continue
        text = original[name]
        if text.count(old) != 1:
            report['results'].append({'mutation': label, 'verdict': f'not applied ({text.count(old)} matches)'})
            print('NOT APPLIED', label, text.count(old), flush=True)
            wrong += 1
            continue
        (tree / name).write_text(text.replace(old, new))
        code, last, failed = run(tree)
        (tree / name).write_text(original[name])
        verdict = ('unnoticed (as a control must be)' if code == 0 else 'NOTICED (control broken)') if control else ('caught' if code != 0 else 'SURVIVED')
        wrong += (code != 0) if control else (code == 0)
        report['results'].append({'mutation': label, 'file': name, 'verdict': verdict, 'last': last, 'failed': failed})
        print(verdict, label, '|', last, '|', ','.join(failed)[:140], flush=True)
    code, last, _failed = run(tree)
    report['baseline_after'] = {'code': code, 'last': last}
    report['wrong'] = wrong
    report['total'] = len(mutations.MUTATIONS)
    report['controls'] = len(mutations.CONTROLS)
    report['caught'] = sum(1 for r in report['results'] if r['verdict'] == 'caught')
    report['finished'] = time.strftime('%Y-%m-%d %H:%M:%S')
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=1))
    print('mutations', report['total'], 'caught', report['caught'], 'wrong', wrong, 'after', code, last, flush=True)
    shutil.rmtree(WORK, ignore_errors=True)
    return 1 if wrong else 0


sys.exit(main())
