"""The trusted-schema load: archive selection (data only, trusted names once), the restricted loader, the snapshot
provider's failure cleanup and the script it runs in the live database's container (by a real shell, with stand-ins
for psql and pg_dump)."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from woowbackup import ha_omnigent as omni
from woowbackup.errors import BackupError
from woowbackup.podman import CommandError, Result

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
        self.assertEqual(omni.SIGNATURE_KEYS, (   # every part of a schema that is compared (none may go missing)
            'relations', 'columns', 'constraints', 'indexes', 'sequences', 'types', 'functions', 'triggers', 'rules',
            'views', 'policies', 'extensions', 'schemas', 'other'))

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
                kwargs['stdout'].write(self.mode + b'\nPGDMP')
        # not JSON, JSON that is no list (an object, a number), no columns, a row that is no column
        for mode in ('timeout', b'invalid-json', b'{"users": 1}', b'5', b'[]', b'[["users", "id"]]',
                     b'[["users", "id", "text", true, "", ""], 1]'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'schema'
                work = SimpleNamespace(runner=lambda app: Runner(mode),
                    guard=SimpleNamespace(budget=lambda: 1024, check=lambda n: None), abort=lambda: None)
                with self.assertRaises(BackupError) as caught:
                    omni.capture_consistent_target_schema(work, SimpleNamespace(id='omnigent'),
                        SimpleNamespace(db_container='synthetic', db_user='postgres'), path, ['revision'])
                self.assertEqual(caught.exception.message, 'synthetic timeout' if mode == 'timeout' else
                                 '目標 Omnigent 的結構快照格式不正確。')
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


class SnapshotScriptTests(unittest.TestCase):
    """SNAPSHOT_SCRIPT as the capture runs it (`podman exec -i <live database> sh -s -- <user> <database>`), here by a
    real shell of this machine whose PATH starts with stand-ins: psql answers the script's statements into the `\\o`
    files they name, pg_dump records its arguments. No PostgreSQL, no container."""
    COLUMNS = [['users', 'id', 'character varying(128)', True, '', '']]
    SNAPSHOT = '00000003-0000001B-1'
    PSQL = r"""#!/bin/sh
printf '%s\n' "$@" > "$STUB/psql.argv"
folder=$(dirname "$(readlink /proc/self/fd/0)")
printf '%s\n' "$folder" "$(stat -c %a "$folder")" "$(stat -c %a "$folder/in")" > "$STUB/psql.folder"
out=/dev/null
while IFS= read -r line; do
    printf '%s\n' "$line" >> "$STUB/psql.stdin"
    case $line in
        '\o '*) out=${line#* } ;;
        '\o') out=/dev/null ;;
        'SELECT pg_export_snapshot();') printf '%s\n' "$STUB_SNAPSHOT" > "$out" ;;
        'LOCK TABLE '*) [ "$STUB_LOCKED" = no ] || exit 3 ;;
        'SELECT CASE WHEN '*) printf '%s\n' "$STUB_REVISION" > "$out" ;;
        'SELECT coalesce(json_agg(json_build_array(c.relname, '*) printf '%s\n' "$STUB_COLUMNS" > "$out" ;;
        '\q') exit 0 ;;
    esac
done
"""
    PG_DUMP = r"""#!/bin/sh
printf '%s\n' "$@" > "$STUB/pg_dump.argv"
cp "$STUB/psql.stdin" "$STUB/psql.stdin.at-dump"
[ "$STUB_DUMP" = ok ] || exit 1
printf 'PGDMP-schema-only'
"""

    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='omni-snapshot-')
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        for name, text in (('psql', self.PSQL), ('pg_dump', self.PG_DUMP)):
            stub = self.root / 'bin' / name
            stub.parent.mkdir(exist_ok=True)
            stub.write_text(text, encoding='utf-8')
            stub.chmod(0o755)
        self.path = self.root / 'target-schema.dump'
        self.calls = []

    def capture(self, **answers):
        env = {'PATH': f'{self.root / "bin"}:/usr/bin:/bin', 'LC_ALL': 'C', 'STUB': str(self.root),
               'STUB_SNAPSHOT': self.SNAPSHOT, 'STUB_REVISION': 'ok', 'STUB_COLUMNS': json.dumps(self.COLUMNS),
               'STUB_LOCKED': 'no', 'STUB_DUMP': 'ok', **answers}

        def podman(*args, input, stdout, **kwargs):
            self.calls.append(args)
            script = subprocess.run(['sh', *args[args.index('sh') + 1:]], input=input, stdout=stdout,
                                    stderr=subprocess.PIPE, env=env, timeout=300, start_new_session=True)
            if script.returncode:
                raise CommandError(f'podman exec 執行失敗（結束碼 {script.returncode}）。', returncode=script.returncode,
                                   stderr=script.stderr)
            return Result(0, None, b'')
        work = SimpleNamespace(runner=lambda app: SimpleNamespace(podman=podman), abort=lambda: None,
                               guard=SimpleNamespace(budget=lambda: 1024 * 1024, check=lambda n: None))
        return omni.capture_consistent_target_schema(
            work, SimpleNamespace(id='omnigent'),
            SimpleNamespace(db_container='omnigent-postgres', db_user='appuser'), self.path, ['d0a1f879a01d'])

    def recorded(self, name):
        path = self.root / name
        return path.read_text(encoding='utf-8').splitlines() if path.exists() else None

    def assert_private_folder_removed(self):
        folder, *modes = self.recorded('psql.folder')
        self.assertRegex(folder, r'\A/tmp/woowbk-schema\.[A-Za-z0-9]{8}\Z')
        self.assertEqual(modes, ['700', '600'])
        self.assertFalse(os.path.exists(folder), "the script's private folder is removed")
        return folder

    def test_the_dump_is_schema_only_and_reads_the_exported_snapshot(self):
        """pg_dump of the live database takes its schema and nothing else (`--schema-only`: this device's rows --
        accounts, sessions, keys -- are never written into the job's staging folder), as the exported snapshot shows
        it, while the transaction that exported it is still open."""
        self.assertEqual(self.capture(), self.COLUMNS)
        self.assertEqual(self.calls, [('exec', '-i', 'omnigent-postgres', 'sh', '-s', '--', 'appuser', 'omnigent')])
        self.assertEqual(self.recorded('pg_dump.argv'),
                         ['-U', 'appuser', '-d', 'omnigent', '-Fc', '--schema-only', '--no-owner', '--no-acl',
                          '--lock-wait-timeout=15s', f'--snapshot={self.SNAPSHOT}'])
        self.assertEqual(self.recorded('psql.argv'), ['-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-U', 'appuser',
                                                      '-d', 'omnigent'])
        folder = self.assert_private_folder_removed()
        sent = ['BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;',
                "SET LOCAL application_name = 'woowbk-schema-snapshot';", "SET LOCAL lock_timeout = '15s';",
                "SET LOCAL idle_in_transaction_session_timeout = '10920s';",
                'LOCK TABLE public.alembic_version IN ACCESS SHARE MODE;',
                f'\\o {folder}/snapshot', 'SELECT pg_export_snapshot();', f'\\o {folder}/revision',
                "SELECT CASE WHEN (SELECT coalesce(json_agg(version_num ORDER BY version_num), '[]'::json)::text "
                'FROM public.alembic_version) = \'["d0a1f879a01d"]\' THEN \'ok\' ELSE \'mismatch\' END;',
                f'\\o {folder}/columns', ' '.join(omni.SCHEMA_COLUMNS_SQL.split()) + ';', '\\o']
        self.assertEqual(self.recorded('psql.stdin'), sent + ['COMMIT;', '\\q'])
        self.assertIn(self.recorded('psql.stdin.at-dump'), (sent, sent[:-1]), 'the transaction is open while pg_dump runs')
        self.assertEqual(self.path.read_bytes(), b'PGDMP-schema-only', 'the archive without the columns line')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual([p.name for p in self.root.iterdir() if p.name.startswith('target')], ['target-schema.dump'])

    def test_nothing_is_dumped_when_the_snapshot_is_not_the_expected_one(self):
        for name, code, answers in (
                ('another revision inside the snapshot', 22, {'STUB_REVISION': 'mismatch'}),
                ('no revision', 22, {'STUB_REVISION': ''}),
                ('not a snapshot id', 23, {'STUB_SNAPSHOT': '00000003-0000001B-1 --file=/tmp/x'}),
                ('no snapshot id', 23, {'STUB_SNAPSHOT': ''}),
                ('a lock that was not granted ends psql', 21, {'STUB_LOCKED': 'yes'})):
            with self.subTest(name=name):
                for file in ('pg_dump.argv', 'psql.stdin', 'psql.folder'):
                    (self.root / file).unlink(missing_ok=True)
                with self.assertRaises(CommandError) as caught:
                    self.capture(**answers)
                self.assertEqual(caught.exception.returncode, code)
                self.assertIsNone(self.recorded('pg_dump.argv'), 'pg_dump never ran')
                self.assertEqual([p.name for p in self.root.iterdir() if p.name.startswith('target')], [])
                self.assert_private_folder_removed()

    def test_a_failed_dump_is_not_a_schema(self):
        with self.assertRaises(CommandError):
            self.capture(STUB_DUMP='fails')
        self.assertEqual([p.name for p in self.root.iterdir() if p.name.startswith('target')], [])
        self.assertNotIn('COMMIT;', self.recorded('psql.stdin'))
        self.assert_private_folder_removed()


if __name__ == '__main__':
    unittest.main()
