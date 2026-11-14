"""Built-in data digests (CONTRACT sections 4, 5, 9): strict parsing of owner-side listings, canonical PostgreSQL lines,
the comparison of two listings. Owner: E2 engine core."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from woowbackup import digests
from woowbackup.errors import BackupError


def line(kind, path, *, mode='0644', uid=0, gid=0, size=0, sha='-', target=None):
    return (f'{kind} {mode} {uid} {gid} {size} {sha} {target.hex() if target is not None else "-"} '
            f'{path.hex()}\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


LISTING = [line('d', b'.', mode='0755'), line('f', b'a.txt', size=5, sha=sha(b'hello')),
           line('d', b'sub', mode='2770', uid=70, gid=70), line('l', b'sub/link', mode='0777', target=b'../a.txt'),
           line('p', b'sub/pipe'), line('f', b'sub/\xffraw', size=1, sha=sha(b'x'))]


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def file(self, name, lines):
        path = self.root / name
        path.write_bytes(b''.join(lines))
        return path


class FilesListingTests(Case):
    def test_summary_and_digest_of_a_valid_listing(self):
        lines = sorted(LISTING, key=lambda item: bytes.fromhex(item.split()[-1].decode()))
        path = self.file('ok', lines)
        summary, digest = digests.read_files_detail(path, what='t')
        self.assertEqual(summary, {'entries': 6, 'files': 2, 'dirs': 2, 'symlinks': 1, 'other': 1, 'bytes': 6})
        self.assertEqual(digest, sha(b''.join(lines)))

    def test_untrusted_listings_are_refused(self):
        good = sorted(LISTING, key=lambda item: bytes.fromhex(item.split()[-1].decode()))
        cases = {
            'unsorted': list(reversed(good)),
            'duplicate': good + [good[-1]],
            'bad kind': [line('s', b'sock')],
            'bad mode': [b'f 0999 0 0 0 - - 61\n'],
            'odd hex': [b'f 0644 0 0 0 - - 6\n'],
            'missing newline': [b'f 0644 0 0 0 - - 61'],
            'extra field': [b'f 0644 0 0 0 - - 61 61\n'],
            'short sha': [b'f 0644 0 0 1 abcd - 61\n'],
            'too long': [b'f 0644 0 0 0 - - ' + b'61' * 20000 + b'\n'],
            'control text': [b'f 0644 0 0 0 - - \x1b[31m\n'],
        }
        for label, lines in cases.items():
            with self.subTest(label), self.assertRaises(BackupError) as caught:
                digests.read_files_detail(self.file(label.replace(' ', '-'), lines), what='資料卷 x')
            self.assertEqual(caught.exception.code, 'job-failed')

    def test_diff_names_missing_extra_and_changed_items(self):
        before = self.file('before', [line('f', b'a', size=1, sha=sha(b'1')), line('f', b'b', size=1, sha=sha(b'2')),
                                      line('d', b'c', mode='0755'), line('l', b'd', target=b'x')])
        after = self.file('after', [line('f', b'a', size=1, sha=sha(b'9')), line('d', b'c', mode='0700', uid=33),
                                    line('f', b'd', size=0, sha=sha(b'')), line('f', b'e', size=1, sha=sha(b'1'))])
        result = digests.diff('files-digest', before, after)
        self.assertEqual((result['missing'], result['extra'], result['changed']), (1, 1, 3))
        details = {item['item']: (item['change'], item['detail']) for item in result['samples']}
        self.assertEqual(details['a'], ('changed', '內容不同'))
        self.assertEqual(details['b'], ('missing', '還原後沒有這個項目'))
        self.assertEqual(details['c'], ('changed', '權限 0755 → 0700、擁有者 0:0 → 33:0'))
        self.assertEqual(details['d'][1], '類型 符號連結 → 檔案、內容不同、連結目標不同')
        self.assertEqual(details['e'], ('extra', '還原後多出這個項目'))

    def test_diff_samples_are_bounded(self):
        before = self.file('b', [line('f', f'{i:04d}'.encode(), size=1, sha=sha(b'1')) for i in range(50)])
        after = self.file('a', [])
        result = digests.diff('files-digest', before, after)
        self.assertEqual(result['missing'], 50)
        self.assertEqual(len(result['samples']), digests.SAMPLES)


class PostgresListingTests(Case):
    TABLES = {'notes': [['public', 'notes', 'r', '12', '-123', '456'], ['public', 'notes_id_seq', 'S', '1', '7', '-8']],
              'odoo_prod': [['public', 'res_partner', 'r', '500', '1', '2']]}
    ROLES = [[['oc_admin', False, True, False, True, True, False, False, -1, None, 'a' * 32],
              ['readonly', False, True, False, False, False, False, False, -1, '2027-01-01 00:00:00+00', None]],
             [['readonly', 'oc_admin', False]]]

    def test_canonical_lines_summary_and_order_independence(self):
        lines = digests.pg_lines(self.TABLES, self.ROLES)
        self.assertEqual(lines, sorted(lines))
        path = self.root / 'pg'
        digests.write_lines(path, lines)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        summary, digest = digests.read_pg_detail(path, what='t')
        self.assertEqual(summary, {'databases': 2, 'tables': 2, 'sequences': 1, 'rows': 512, 'roles': 2})
        reordered = {'odoo_prod': self.TABLES['odoo_prod'], 'notes': list(reversed(self.TABLES['notes']))}
        self.assertEqual(digests.pg_lines(reordered, self.ROLES), lines, 'the order psql printed does not matter')

    def test_shapes_from_inside_the_container_are_checked(self):
        bad_tables = [{'notes': [['public', 'notes', 'v', '1', '1', '1']]}, {'notes': [['public', 'n', 'r', '-1', '1', '1']]},
                      {'notes': [['public', 'n', 'r', '1', '--1', '1']]}, {'notes': [['public', 'n', 'r', '1', '1', '1.5']]},
                      {'notes': [['public', 'n', 'r', '1', '1']]}, {'notes': 'x'}, {'notes': [['', 'n', 'r', '1', '1', '1']]}]
        for tables in bad_tables:
            with self.subTest(tables), self.assertRaises(BackupError):
                digests.pg_lines(tables)
        bad_roles = [[[]], [[['r', 'x', True, True, True, True, True, True, -1, None, None]], []],
                     [[['r', False, True, False, True, True, False, False, -1, None, 'not-md5']], []]]
        for roles in bad_roles:
            with self.subTest(roles), self.assertRaises(BackupError):
                digests.pg_lines({}, roles)

    def test_diff_tells_rows_from_content_and_roles(self):
        before = self.root / 'before'
        digests.write_lines(before, digests.pg_lines(self.TABLES, self.ROLES))
        tables = {'notes': [['public', 'notes', 'r', '11', '1', '2'], ['public', 'notes_id_seq', 'S', '1', '7', '9']],
                  'odoo_prod': [['public', 'res_partner', 'r', '500', '1', '2']]}
        roles = [[['oc_admin', False, True, False, True, True, False, False, -1, None, 'b' * 32]], []]
        after = self.root / 'after'
        digests.write_lines(after, digests.pg_lines(tables, roles))
        result = digests.diff('postgres-digest', before, after)
        details = {item['item']: item['detail'] for item in result['samples']}
        self.assertEqual(details['資料表 notes:public.notes'], '資料列 12 → 11')
        self.assertEqual(details['序列 notes:public.notes_id_seq'], '內容不同（筆數相同）')
        self.assertEqual(details['角色 oc_admin'], '密碼不同')
        self.assertEqual(details['角色 readonly'], '還原後沒有這個項目')
        self.assertEqual(details['角色成員 oc_admin ∈ readonly'], '還原後沒有這個項目')
        self.assertEqual((result['missing'], result['extra'], result['changed']), (2, 0, 3))

    def test_an_empty_database_counts_and_its_absence_differs(self):
        before = self.root / 'before'
        digests.write_lines(before, digests.pg_lines({'postgres': [], 'notes': self.TABLES['notes']}))
        self.assertEqual(digests.read_pg_detail(before, what='t')[0]['databases'], 2, 'a database without tables counts')
        after = self.root / 'after'
        digests.write_lines(after, digests.pg_lines({'notes': self.TABLES['notes']}))
        result = digests.diff('postgres-digest', before, after)
        self.assertEqual(result['samples'], [{'item': '資料庫 postgres', 'change': 'missing', 'detail': '還原後沒有這個項目'}])

    def test_listing_files_are_validated(self):
        for label, data in {'unsorted': b'T 61 62 63 r 1 1 1\nM 61 62 t\n', 'garbage': b'X\n',
                            'bad kind': b'T 61 62 63 v 1 1 1\n', 'bad flags': b'R 61 ttt -1 - -\n'}.items():
            with self.subTest(label), self.assertRaises(BackupError):
                path = self.root / label.replace(' ', '-')
                path.write_bytes(data)
                digests.read_pg_detail(path, what='t')

    def test_query_builders(self):
        self.assertNotIn('c.oid IN', digests.tables_sql())
        self.assertIn(' AND c.oid IN (5,17)) r', digests.tables_sql([5, 17]))
        self.assertIn('c.oid IN (0)', digests.tables_sql([]), 'everything excluded: nothing is read')
        with self.assertRaises(ValueError):
            digests.tables_sql(['1); DROP TABLE x; --'])
        self.assertTrue(digests.excluded_table(['public.cron_*'], 'public', 'cron_job_run'))
        self.assertFalse(digests.excluded_table(['public.cron_*'], 'cron', 'job'))
        self.assertIn('-c TimeZone=UTC', digests.PG_OPTIONS)
        self.assertIn('-c standard_conforming_strings=on', digests.PG_OPTIONS)


if __name__ == '__main__':
    unittest.main()
