"""The trusted-schema load: archive selection (data only, trusted names once), the restricted loader and the
snapshot provider's failure cleanup."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
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

    def test_strict_list_takes_each_trusted_name_once(self):
        toc = ('1; 0 0 TABLE DATA public users owner\n2; 0 0 SEQUENCE SET public users_id_seq owner\n'
               '3; 0 0 DEFAULT public users x owner\n')
        self.assertEqual(omni.data_only_toc(toc, tables=['users'], sequences=['users_id_seq']),
                         '1; 0 0 TABLE DATA public users owner\n2; 0 0 SEQUENCE SET public users_id_seq owner\n')
        # A name with a line break in HA's database could add any entry id: an unknown or repeated name is refused.
        for extra in ('4; 0 0 TABLE DATA public users other\n', '4; 0 0 TABLE DATA public evil owner\n',
                      '4; 0 0 SEQUENCE SET public other_seq owner\n', '4; 0 0 TABLE DATA other users owner\n',
                      '4; 0 0 TABLE DATA public users two owners\n'):
            with self.subTest(extra=extra), self.assertRaises(BackupError) as caught:
                omni.data_only_toc(toc + extra, tables=['users'], sequences=['users_id_seq'])
            self.assertIn('不屬於這台 Omnigent 資料庫結構', caught.exception.message)

    def test_the_old_public_guards_are_replaced_by_the_product_checks(self):
        self.assertFalse(hasattr(omni, 'SECURITY_BLOCKER'))
        self.assertFalse(hasattr(omni, 'restore_dump'))
        self.assertEqual(omni.SIGNATURE_KEYS[:3], ('relations', 'columns', 'constraints'))

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

    def test_snapshot_failure_removes_capture(self):
        import tempfile
        from pathlib import Path
        class Runner:
            def __init__(self, mode): self.mode = mode
            def podman(self, *args, **kwargs):
                if self.mode == 'timeout':
                    raise BackupError('job-failed', 'synthetic timeout')
                kwargs['stdout'].write(b'invalid-json\nPGDMP')
        for mode in ('timeout', 'invalid'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'schema'
                work = SimpleNamespace(runner=lambda app: Runner(mode),
                    guard=SimpleNamespace(budget=lambda: 1024, check=lambda n: None), abort=lambda: None)
                with self.assertRaises(BackupError):
                    omni.capture_consistent_target_schema(work, SimpleNamespace(id='omnigent'),
                        SimpleNamespace(db_container='synthetic', db_user='postgres'), path, ['revision'])
                self.assertFalse(path.exists())
                self.assertFalse(path.with_name(path.name + '.capture').exists())

    def test_snapshot_failure_preserves_preexisting_files(self):
        import tempfile
        from pathlib import Path
        class Runner:
            def podman(self, *args, **kwargs):
                kwargs['stdout'].write(b'[["users","id","text",true,"",""]]\nPGDMP')
        for occupied in ('output', 'capture'):
            with self.subTest(occupied=occupied), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'schema'
                existing = path if occupied == 'output' else path.with_name('schema.capture')
                existing.write_bytes(b'existing-private-data')
                work = SimpleNamespace(runner=lambda app: Runner(),
                    guard=SimpleNamespace(budget=lambda: 1024, check=lambda n: None), abort=None)
                with self.assertRaises(FileExistsError):
                    omni.capture_consistent_target_schema(work, SimpleNamespace(id='omnigent'),
                        SimpleNamespace(db_container='synthetic', db_user='postgres'), path, ['revision'])
                self.assertEqual(existing.read_bytes(), b'existing-private-data')

    def test_snapshot_partial_output_removed_on_copy_failure(self):
        import tempfile
        from pathlib import Path
        class Runner:
            def podman(self, *args, **kwargs):
                kwargs['stdout'].write(b'[["users","id","text",true,"",""]]\nPGDMP')
        def fail_copy(source, dest, *args):
            dest.write(b'partial')
            raise OSError('synthetic disk failure')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'schema'
            work = SimpleNamespace(runner=lambda app: Runner(),
                guard=SimpleNamespace(budget=lambda: 1024, check=lambda n: None), abort=None)
            with patch('shutil.copyfileobj', side_effect=fail_copy), self.assertRaises(OSError):
                omni.capture_consistent_target_schema(work, SimpleNamespace(id='omnigent'),
                    SimpleNamespace(db_container='synthetic', db_user='postgres'), path, ['revision'])
            self.assertFalse(path.exists())
            self.assertFalse(path.with_name('schema.capture').exists())
