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

from . import hafakes


class OmnigentTrustedSchemaContractTest(unittest.TestCase):
    def test_the_helpers_that_ran_has_ddl_or_wrote_as_superuser_are_gone(self):
        for name in ('restore_dump', 'carry_accounts', 'SECURITY_BLOCKER'):
            self.assertFalse(hasattr(ha_omnigent, name), name)

    def test_the_quadlet_secrets_are_read_by_name_only_and_are_no_refusal(self):
        """O-48 (HAOS parity 2026-11-25): a Quadlet secret that the app settings do not list is a notice (the secret is
        there on this device; it only matters when the backup is restored on a new one), no longer a refusal before anything
        runs. What stays true: only the Quadlet files are read, and only the names of secrets come out of them."""
        work = Mock()
        work.quadlets.return_value = {'omnigent-server.container':
                                      '[Container]\nSecret=omnigent-database-url,type=env,target=DATABASE_URL\n'}
        for declared, names in (([], ['omnigent-database-url']), ([{'name': 'omnigent-database-url'}], []),
                                ([{'name': 'omnigent-database-url'}] * 2, ['omnigent-database-url'])):
            work.reset_mock()
            self.assertEqual(ha_omnigent.unregistered_secrets(work, SimpleNamespace(id='omnigent', secrets=declared)), names)
            self.assertEqual([c[0] for c in work.mock_calls], ['quadlets'], 'nothing but the Quadlet files read')

    def test_has_dump_is_only_ever_loaded_as_data_by_the_restricted_role(self):
        listing = (b'1; 0 0 TABLE public users owner\n2; 0 0 DEFAULT public users x owner\n'
                   b'3; 0 0 CHECK CONSTRAINT public users evil owner\n4; 0 0 TABLE DATA public users owner\n'
                   b'5; 0 0 DOMAIN public evil owner\n')
        tmp, files = Mock(), hafakes.ContainerFiles()
        tmp.exec.side_effect = lambda role, argv, **kw: hafakes.container_reply(
            files, role, argv, kw.get('input')) or SimpleNamespace(stdout=(
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
        written = [c.kwargs['input'] for c in tmp.exec.call_args_list
                   if c.args[1][:2] == ['sh', '-c'] and 'input' in c.kwargs]   # not the read-backs (no input)
        self.assertEqual(written, [b'4; 0 0 TABLE DATA public users owner\n'])
        self.assertEqual(files.files, {('omni-db', '/tmp/woowbk-omnigent.toc'): b'4; 0 0 TABLE DATA public users owner\n'})


if __name__ == '__main__':
    unittest.main()
