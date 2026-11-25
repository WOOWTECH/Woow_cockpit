"""Which block of the HA import was changed where: every row of the HAOS parity list (owner's decision 2026-11-25) is in
`ha_parity_rows.json` with its lane, the issues it became and the tests that show it. Team E2.

The file (one row per line, so lanes merge cleanly):

    {"schema": 1, "lanes": {<lane>: {"rows": [...], "owner": [...], "keep": [...]}}, "rows": {<row id>: ROW}}

    ROW = {"lane", "app", "act", "status", "issues", "tests", "note"}
      lane    the lane of DESIGN F-a that owns the row (fixed here)
      app     the app of the row's text (fixed here); act: auto | skip_one | remove | warn | owner | keep (fixed here)
      status  todo     the lane has not delivered it
              done     as DESIGN says
              part     done as far as this lane can (note: what is missing and who does it)
              open     left as it is on purpose (note: why, with the evidence)
              later    wave 2 or an open question of the owner (DESIGN E2, H)
      issues  {issue id: level} the row became ({} when nothing is said about it any more)
      tests   ["tests/backup/test_x.py::Class.test_name" | "tests/backup-ui.mjs::title"]
      note    one line; needed for part and open

Rules checked below: no row is missing or in two lanes; a `done`/`part` row has tests that exist (two for an `auto` row:
it works, and what it cannot handle stops only that app; three for a row with a line to confirm: not confirmed, confirmed,
one more name - DESIGN G1); its issues are declared with that level in the module that uses them (haissues); a removed
block stops nothing; a skip stops one app.

A lane never edits this file: it hands over `<snippets>/<lane>/ha_parity_rows.json`,

    {"lane": "<lane>", "rows": {<row id>: {"status", "issues", "tests", "note"}}}

and the integrator merges it:   python3 tests/backup/test_ha_parity_rows.py --merge <file> [<file> ...]
`--report` prints what is done per lane. WOOWBK_PARITY_STRICT=1 (the last lane) also refuses a `todo`.
"""
import ast
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / 'tests' / 'backup' / 'ha_parity_rows.json'
ACTS = ('auto', 'skip_one', 'remove', 'warn', 'owner', 'keep')
STATUS = ('todo', 'done', 'part', 'open', 'later')
FIELDS = ('lane', 'app', 'act', 'status', 'issues', 'tests', 'note')
OPEN_LANES = ('wave2', 'unclear')
# DESIGN J / K: rows, owner rows and keep rows of every lane.
EXPECTED = {
    'F1-foundation': (14, 0, 0), 'READ': (83, 0, 0), 'PKG': (4, 0, 0), 'F2-chain': (14, 0, 0), 'F3-helpers': (12, 0, 0),
    'PAGE': (10, 0, 0), 'RESTORE': (28, 2, 0), 'EMQX-A': (37, 11, 0), 'ODOO': (41, 1, 0), 'N8N': (15, 0, 0),
    'NEXTCLOUD': (20, 1, 2), 'OMNIGENT': (36, 0, 0), 'LITELLM': (33, 1, 0), 'HERMES-HEADSCALE': (43, 2, 0),
    'OPENDESIGN-CODESERVER': (26, 0, 0), 'EMQX-B': (20, 0, 0), 'CLEANUP-LC': (16, 0, 0), 'REAL': (0, 0, 0),
    'wave2': (59, 0, 0), 'unclear': (1, 0, 0),
}
# sha256 of "lane:row" lines, sorted: a row cannot change its lane or disappear unnoticed.
ROWS_SHA256 = '4c3f36fdc40b8cf12ad71a4d33e6e7c40c191def7ec60b24fc75e8335879a23b'


def load(path=REGISTRY):
    def strict(pairs):
        value = dict(pairs)
        if len(value) != len(pairs):
            raise ValueError('duplicate key')
        return value
    return json.loads(Path(path).read_text(encoding='utf-8'), object_pairs_hook=strict)


def dump(doc):
    """The file's text: one lane and one row per line."""
    def line(value):
        return json.dumps(value, ensure_ascii=False, separators=(', ', ': '))
    lanes = ',\n'.join(f'  {line(name)}: {line(value)}' for name, value in doc['lanes'].items())
    rows = ',\n'.join(f'  {line(row_id)}: {line({key: row[key] for key in FIELDS})}' for row_id, row in doc['rows'].items())
    return f'{{"schema": 1,\n "lanes": {{\n{lanes}\n }},\n "rows": {{\n{rows}\n }}}}\n'


def rows_sha256(doc):
    lines = sorted(f'{lane}:{row_id}' for lane, value in doc['lanes'].items()
                   for kind in ('rows', 'owner', 'keep') for row_id in value[kind])
    return hashlib.sha256('\n'.join(lines).encode()).hexdigest()


_PARSED = {}


def test_exists(test_id, repo=REPO):
    """True when the named test is in the source ("<file>::<Class>.<method>" of a Python test, "<file>::<title>" of a page
    test)."""
    name, sep, test = test_id.partition('::')
    path = repo / name
    if not sep or not test or '..' in name or not name.startswith('tests/') or not path.is_file():
        return False
    if path.suffix != '.py':
        return test in path.read_text(encoding='utf-8')
    if path not in _PARSED:
        _PARSED[path] = {f'{node.name}.{item.name}' for node in ast.parse(path.read_bytes()).body
                         if isinstance(node, ast.ClassDef) for item in node.body
                         if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}
    return test in _PARSED[path]


test_exists.__test__ = False


def problems(doc, levels, *, strict=False, exists=test_exists):
    """[what is wrong with the registry] ([] = nothing). `levels`: {issue id: level} of the declared issues."""
    found = []
    if doc.get('schema') != 1 or set(doc) != {'schema', 'lanes', 'rows'}:
        return ['not a schema 1 registry']
    counts = {name: tuple(len(value[kind]) for kind in ('rows', 'owner', 'keep')) for name, value in doc['lanes'].items()}
    if counts != EXPECTED:
        found.append('the lanes do not hold the rows of DESIGN K')
    if rows_sha256(doc) != ROWS_SHA256:
        found.append('a row moved to another lane, or is missing')
    owners = {}
    for lane, value in doc['lanes'].items():
        for kind in ('rows', 'owner', 'keep'):
            for row_id in value[kind]:
                if row_id in owners:
                    found.append(f'{row_id}: in two lanes')
                owners[row_id] = (lane, kind)
    if set(owners) != set(doc['rows']):
        found.append(f'rows without an entry, or entries without a lane: {sorted(set(owners) ^ set(doc["rows"]))[:5]}')
    for row_id, row in doc['rows'].items():
        if set(row) != set(FIELDS):
            found.append(f'{row_id}: fields {sorted(row)}')
            continue
        lane, kind = owners.get(row_id, (None, None))
        if row['lane'] != lane:
            found.append(f'{row_id}: lane {row["lane"]}, listed in {lane}')
        if row['act'] not in ACTS or (kind == 'owner') != (row['act'] == 'owner') or (kind == 'keep') != (row['act'] == 'keep'):
            found.append(f'{row_id}: act {row["act"]}')
        if row['status'] not in STATUS or (lane in OPEN_LANES) != (row['status'] == 'later'):
            found.append(f'{row_id}: status {row["status"]}')
            continue
        if strict and row['status'] == 'todo':
            found.append(f'{row_id}: not delivered')
        if not isinstance(row['note'], str) or len(row['note']) > 400 or '\n' in row['note']:
            found.append(f'{row_id}: note')
        if row['status'] in ('part', 'open') and not row['note']:
            found.append(f'{row_id}: a {row["status"]} row says why')
        for issue_id, level in row['issues'].items():
            if levels.get(issue_id) != level:
                found.append(f'{row_id}: {issue_id} is {levels.get(issue_id)}, not {level}')
        if row['status'] in ('todo', 'later', 'open'):
            continue
        if len(set(row['tests'])) != len(row['tests']):
            found.append(f'{row_id}: a test twice')
        for test_id in row['tests']:
            if not exists(test_id):
                found.append(f'{row_id}: no test {test_id}')
        need = 3 if 'confirm' in row['issues'].values() else 2 if row['act'] == 'auto' else 1
        if len(row['tests']) < need:
            found.append(f'{row_id}: {len(row["tests"])} tests, needs {need}')
        if row['act'] == 'remove' and 'stop' in row['issues'].values():
            found.append(f'{row_id}: a removed block stops nothing')
        if row['act'] == 'skip_one' and row['issues'] and not {'stop', 'confirm'} & set(row['issues'].values()):
            found.append(f'{row_id}: a skip stops one app (or lists what it leaves out)')
    return found


def merge(doc, snippet):
    """`doc` with a lane's snippet merged in; ValueError when the snippet is not only about its own rows."""
    if set(snippet) != {'lane', 'rows'} or snippet['lane'] not in doc['lanes']:
        raise ValueError('not a snippet: {"lane", "rows"}')
    for row_id, change in snippet['rows'].items():
        row = doc['rows'].get(row_id)
        if row is None or row['lane'] != snippet['lane']:
            raise ValueError(f'{row_id} is not a row of {snippet["lane"]}')
        if not set(change) <= {'status', 'issues', 'tests', 'note'}:
            raise ValueError(f'{row_id}: only status, issues, tests and note')
        row.update(change)
    return doc


def report(doc):
    lines = []
    for lane, value in doc['lanes'].items():
        ids = [row_id for kind in ('rows', 'owner', 'keep') for row_id in value[kind]]
        if ids:
            counts = {status: sum(doc['rows'][i]['status'] == status for i in ids) for status in STATUS}
            lines.append(f'{lane}: ' + ', '.join(f'{status} {n}' for status, n in counts.items() if n))
    return lines


class ParityRowsTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        from tests.backup.test_ha_issues import tables
        cls.levels = {issue_id: level for table in tables().values() for issue_id, level in table.items()}
        cls.doc = load()

    def copy(self):
        return json.loads(json.dumps(self.doc))

    def test_every_row_is_registered_and_shown_by_its_tests(self):
        self.assertEqual(problems(self.doc, self.levels, strict=os.environ.get('WOOWBK_PARITY_STRICT') == '1'), [])

    def test_the_file_is_written_the_merge_way(self):
        self.assertEqual(REGISTRY.read_text(encoding='utf-8'), dump(self.doc), 'one row per line: use --merge')

    def test_the_owner_sees_every_row(self):
        self.assertEqual(len(self.doc['rows']), 532)
        self.assertEqual(sum(sum(counts) for counts in EXPECTED.values()), 532)

    def test_a_lost_moved_or_doubled_row_is_noticed(self):
        for change in (lambda d: d['rows'].pop('HA-12'), lambda d: d['lanes']['READ']['rows'].remove('UP-03'),
                       lambda d: d['lanes']['READ']['rows'].append('HA-12'),
                       lambda d: (d['lanes']['F1-foundation']['rows'].remove('HA-12'),
                                  d['lanes']['F1-foundation']['rows'].append('UP-03'),
                                  d['lanes']['READ']['rows'].remove('UP-03'), d['lanes']['READ']['rows'].append('HA-12')),
                       lambda d: d['rows']['HA-12'].update(lane='READ'), lambda d: d['rows']['HA-12'].update(act='owner'),
                       lambda d: d['rows']['HA-12'].update(extra=1), lambda d: d.update(schema=2)):
            doc = self.copy()
            change(doc)
            self.assertTrue(problems(doc, self.levels))

    def test_a_row_is_done_only_with_its_tests_and_issues(self):
        row_id = next(i for i, row in self.doc['rows'].items() if row['status'] == 'done' and row['act'] == 'auto')
        for change in ({'tests': []}, {'tests': self.doc['rows'][row_id]['tests'][:1]},
                       {'tests': ['tests/backup/test_ha_issues.py::Nope.test_x', 'tests/backup/x.py::A.b']},
                       {'tests': self.doc['rows'][row_id]['tests'][:1] * 2}, {'issues': {'ha.nope': 'stop'}},
                       {'issues': {'ha.addon-missing': 'notice'}}, {'status': 'fine'}, {'status': 'later'},
                       {'status': 'part', 'note': ''}, {'note': 'a\nb'}, {'act': 'remove', 'issues': {
                           'ha.addon-missing': 'stop'}}):
            doc = self.copy()
            doc['rows'][row_id].update(change)
            self.assertTrue(problems(doc, self.levels), change)
        doc = self.copy()
        doc['rows'][row_id].update(issues={'x.confirm': 'confirm'})
        doc['rows'][row_id]['tests'] = doc['rows'][row_id]['tests'][:2]
        self.assertIn(f'{row_id}: 2 tests, needs 3', problems(doc, {**self.levels, 'x.confirm': 'confirm'}))

    def test_a_lane_that_has_not_delivered_is_refused_at_the_end(self):
        doc = self.copy()
        doc['rows']['HA-12'].update(status='todo')
        self.assertEqual(problems(doc, self.levels), [])
        self.assertIn('HA-12: not delivered', problems(doc, self.levels, strict=True))

    def test_tests_are_looked_up_in_the_source(self):
        self.assertTrue(test_exists('tests/backup/test_ha_parity_rows.py::ParityRowsTests.test_the_owner_sees_every_row'))
        for bad in ('tests/backup/test_ha_parity_rows.py::ParityRowsTests.test_nope', 'test_ha_parity_rows.py::x',
                    'tests/backup/test_ha_parity_rows.py', 'tests/../tests/backup/test_ha_parity_rows.py::x', 'tests/x.py::A.b',
                    'tests/backup-ui.mjs::no such title at all 12345'):
            self.assertFalse(test_exists(bad), bad)

    def test_a_snippet_changes_only_its_own_rows(self):
        doc = merge(self.copy(), {'lane': 'READ', 'rows': {'UP-03': {'status': 'open', 'note': 'x'}}})
        self.assertEqual((doc['rows']['UP-03']['status'], doc['rows']['UP-03']['lane']), ('open', 'READ'))
        for bad in ({'lane': 'READ', 'rows': {'HA-12': {'status': 'done'}}}, {'lane': 'nope', 'rows': {}},
                    {'rows': {}}, {'lane': 'READ', 'rows': {'UP-03': {'lane': 'PKG'}}},
                    {'lane': 'READ', 'rows': {'XX-01': {}}}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                merge(self.copy(), bad)

    def test_the_report_counts_every_lane(self):
        lines = report(self.doc)
        self.assertEqual(len(lines), len([lane for lane, counts in EXPECTED.items() if any(counts)]))


def main(argv):
    if argv[:1] == ['--merge'] and len(argv) > 1:
        doc = load()
        for name in argv[1:]:
            merge(doc, json.loads(Path(name).read_text(encoding='utf-8')))
        REGISTRY.write_text(dump(doc), encoding='utf-8')
        print(f'merged {len(argv) - 1} snippet(s); run: python3 -m unittest tests.backup.test_ha_parity_rows')
        return 0
    if argv == ['--report']:
        print('\n'.join(report(load())))
        return 0
    return None


if __name__ == '__main__':
    result = main(sys.argv[1:])
    if result is None:
        unittest.main()
    sys.exit(result)
