"""Candidate archive selection and public guard remain independent."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from woowbackup import ha_omnigent as omni
from woowbackup.errors import BackupError

class TrustedDataTests(unittest.TestCase):
    def test_schema_entries_are_not_selected(self):
        toc = ('; archive\n1; 0 0 TABLE public users owner\n'
               '2; 0 0 TABLE DATA public users owner\n'
               '3; 0 0 CHECK CONSTRAINT public users evil owner\n'
               '4; 0 0 SEQUENCE SET public id_seq owner\n'
               '5; 0 0 COMMENT - TABLE DATA public users owner\n')
        self.assertEqual(omni.data_only_toc(toc),
                         '2; 0 0 TABLE DATA public users owner\n4; 0 0 SEQUENCE SET public id_seq owner\n')

    def test_malformed_or_duplicate_or_empty_fails(self):
        for toc in ('', 'garbage', '1; 0 0 TABLE public x owner',
                    '1; 0 0 TABLE DATA public x owner\n1; 0 0 DEFAULT public x owner'):
            with self.subTest(toc=toc), self.assertRaises(BackupError):
                omni.data_only_toc(toc)

    def test_public_guards_stay_closed(self):
        work = Mock()
        with self.assertRaises(BackupError):
            omni.convert(work, SimpleNamespace(id='omnigent'), False, None)
        with self.assertRaises(BackupError):
            omni.restore_dump(work, None, None, None)
        self.assertEqual(work.method_calls, [])

    def test_candidate_uses_target_schema_and_restricted_loader(self):
        import tempfile
        from pathlib import Path
        tmp = Mock()
        tmp.exec.return_value.stdout = (b'1; 0 0 TABLE DATA public users owner\n'
                                        b'2; 0 0 CHECK CONSTRAINT public users evil owner\n')
        work = SimpleNamespace(log=Mock())
        columns = [['users', 'id', 'text', True, '', '']]
        tmp.exec.side_effect = lambda role, argv, **kw: SimpleNamespace(stdout=(
            b'[["users","id","text",true,"",""]]' if argv[0] == 'psql' and '-c' in argv else
            b'1; 0 0 TABLE DATA public users owner\n2; 0 0 CHECK CONSTRAINT public users evil owner\n'))
        with tempfile.TemporaryDirectory() as directory:
            schema, data = Path(directory) / 's', Path(directory) / 'd'
            schema.write_bytes(b'trusted-schema')
            data.write_bytes(b'untrusted-data')
            omni.restore_trusted_data(work, tmp, schema, data, 'omnigent', source_columns=columns)
        calls = tmp.exec.call_args_list
        restores = [c for c in calls if c.args[1][0] == 'pg_restore']
        self.assertEqual(len(restores), 4)  # listing, pre-data, data, post-data
        self.assertIn('--section=pre-data', restores[1].args[1])
        self.assertIn('woowbk_restore', restores[2].args[1])
        self.assertIn('-L', restores[2].args[1])
        self.assertIn('--section=post-data', restores[3].args[1])
        writes = [c for c in calls if c.args[1][:2] == ['sh', '-c']]
        self.assertEqual(writes[0].kwargs['input'], b'1; 0 0 TABLE DATA public users owner\n')
        scripts = [c.kwargs['input'] for c in calls if c.args[1][0] == 'psql' and 'input' in c.kwargs]
        grant = b''.join(scripts)
        self.assertIn(b'NOSUPERUSER', grant)
        self.assertNotIn(b'GRANT CREATE', grant)
