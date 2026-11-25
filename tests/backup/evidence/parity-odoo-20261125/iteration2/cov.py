#!/usr/bin/env python3
"""Line coverage of one product file by some unittest modules (stdlib only: sys.monitoring, Python 3.12).
usage (from the worktree): PYTHONPATH=backup-engine:tests/e2e/lab python3 -I cov.py FILE.py module [module...]
prints the lines with code that no test ran, grouped by function. Not a mutation test: only shows what is never executed."""
import dis
import os
import sys
import types
import unittest

target = os.path.abspath(sys.argv[1])
mods = sys.argv[2:]
mon = sys.monitoring
TOOL = mon.COVERAGE_ID
seen = set()


def on_line(code, line):
    if code.co_filename == target:
        seen.add(line)
    else:
        return mon.DISABLE


mon.use_tool_id(TOOL, 'cov')
mon.register_callback(TOOL, mon.events.LINE, on_line)
mon.set_events(TOOL, mon.events.LINE)
suite = unittest.TestLoader().loadTestsFromNames(mods)
res = unittest.TextTestRunner(stream=open(os.devnull, 'w'), verbosity=0).run(suite)
mon.set_events(TOOL, 0)
print('tests', res.testsRun, 'failures', len(res.failures), 'errors', len(res.errors))

src = open(target, encoding='utf-8').read()
top = compile(src, target, 'exec')
execable = {}   # line -> innermost function name


def walk(code, name):
    for _, _, line in code.co_lines():
        if line is not None:
            execable.setdefault(line, name)
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            walk(const, (name + '.' if name != '<module>' else '') + const.co_name)


walk(top, '<module>')
# lines that are only a docstring or def/decorator headers are executed at import: keep what the import ran
missing = sorted(l for l in execable if l not in seen)
by = {}
for line in missing:
    by.setdefault(execable[line], []).append(line)
lines = src.splitlines()
total = len(execable)
print('executable lines', total, 'never run', len(missing), 'coverage %.1f%%' % (100.0 * (total - len(missing)) / total))
for name, ls in sorted(by.items(), key=lambda kv: kv[1][0]):
    ranges, start, prev = [], ls[0], ls[0]
    for l in ls[1:]:
        if l == prev + 1:
            prev = l
            continue
        ranges.append((start, prev))
        start = prev = l
    ranges.append((start, prev))
    print(f'{name}: ' + ', '.join(f'{a}' if a == b else f'{a}-{b}' for a, b in ranges))
