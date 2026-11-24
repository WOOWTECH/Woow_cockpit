"""B1-01 (HA-written DEFAULT/CHECK/DOMAIN expressions running as the app's superuser): the security hold is replaced
by the product's trusted-schema conversion (owner decision 2026-11-23). What must stay true: the unsafe helpers that
restored HA's DDL or wrote as the superuser are gone; nothing touches a container before the catalog's secrets are
known; HA's dump reaches the new cluster only through the data-only list, as the role without privileges."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock

from woowbackup import ha_omnigent
from woowbackup.errors import BackupError


class OmnigentTrustedSchemaContractTest(unittest.TestCase):
    def test_the_helpers_that_ran_has_ddl_or_wrote_as_superuser_are_gone(self):
        for name in ('restore_dump', 'carry_accounts', 'SECURITY_BLOCKER'):
            self.assertFalse(hasattr(ha_omnigent, name), name)

    def test_convert_touches_nothing_before_the_secrets_are_registered(self):
        for test_mode in (False, True):
            with self.subTest(test_mode=test_mode):
                work = Mock()
                work.quadlets.return_value = {'omnigent-server.container':
                                              '[Container]\nSecret=omnigent-database-url,type=env,target=DATABASE_URL\n'}
                app = SimpleNamespace(id='omnigent', secrets=[])
                with self.assertRaises(BackupError) as caught:
                    ha_omnigent.convert(work, app, test_mode, Mock())
                self.assertEqual(caught.exception.code, 'incompatible')
                self.assertIn('機密未完整登記', caught.exception.message)
                self.assertEqual([c[0] for c in work.mock_calls], ['quadlets'], 'nothing but the Quadlet files read')

    def test_has_dump_is_only_ever_loaded_as_data_by_the_restricted_role(self):
        listing = (b'1; 0 0 TABLE public users owner\n2; 0 0 DEFAULT public users x owner\n'
                   b'3; 0 0 CHECK CONSTRAINT public users evil owner\n4; 0 0 TABLE DATA public users owner\n'
                   b'5; 0 0 DOMAIN public evil owner\n')
        tmp = Mock()
        tmp.exec.side_effect = lambda role, argv, **kw: SimpleNamespace(stdout=(
            b'[["users","id","text",true,"",""]]' if argv[0] == 'psql' and '-c' in argv else listing))
        with TemporaryDirectory() as directory:
            schema, data = Path(directory) / 'schema', Path(directory) / 'data'
            schema.write_bytes(b'TRUSTED')
            data.write_bytes(b'HA')
            ha_omnigent.restore_trusted_data(SimpleNamespace(log=Mock()), tmp, schema, data, 'omnigent',
                                             source_columns=[['users', 'id', 'text', True, '', '']],
                                             tables=['users'], sequences=[])
        for call in tmp.exec.call_args_list:
            argv, given = call.args[1], call.kwargs.get('input')
            if argv[0] != 'pg_restore' or argv[1] == '-l':
                continue
            source = given.name if hasattr(given, 'name') else ''
            if source.endswith('/data'):
                self.assertEqual(argv[argv.index('-U') + 1], ha_omnigent.RESTORE_ROLE)
                self.assertIn('-L', argv)
            else:
                self.assertTrue(source.endswith('/schema'), 'every other restore reads the trusted schema only')
        written = [c.kwargs['input'] for c in tmp.exec.call_args_list if c.args[1][:2] == ['sh', '-c']]
        self.assertEqual(written, [b'4; 0 0 TABLE DATA public users owner\n'])


if __name__ == '__main__':
    unittest.main()
