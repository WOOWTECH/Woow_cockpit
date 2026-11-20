"""Offline synthetic HA backup fixture checks; never starts a broker."""
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from emqx_ha_candidate import backup_from_volume, SLUG
from emqx_adapter_fixture import Fixture
from woowbackup import habackup, ha_emqx


class SourceBackupTests(unittest.TestCase):
    def test_real_ha_reader_accepts_wrapped_synthetic_volume(self):
        blob = io.BytesIO()
        with tarfile.open(fileobj=blob, mode='w') as archive:
            for name, body in [('mnesia/emqx@127.0.0.1', None),
                               ('mnesia/emqx@127.0.0.1/schema.DAT', b'synthetic')]:
                item = tarfile.TarInfo(name)
                if body is None:
                    item.type = tarfile.DIRTYPE
                else:
                    item.size = len(body)
                archive.addfile(item, None if body is None else io.BytesIO(body))

        class SyntheticRunner:
            def relay(self, args, *, stdout, **kwargs):
                self.args = args
                stdout.write(blob.getvalue())

        runner = SyntheticRunner()
        fixture = Fixture('woowbk-emqxlab-12345678', 'appowner', '3f60addfad2b' + '0' * 52)
        with tempfile.TemporaryDirectory() as tmp:
            backup = backup_from_volume(runner, fixture, Path(tmp))
            self.assertEqual(runner.args, ['volume', 'export', fixture.volumes[0]])
            with habackup.open_backup(backup) as opened:
                with opened.open_addon(SLUG) as member:
                    source = ha_emqx.scan_member(member, habackup.Report())
            self.assertEqual(ha_emqx.node_name(source), ('emqx@127.0.0.1', None))
            self.assertEqual(source.addon.version, '5.9.1')


if __name__ == '__main__':
    unittest.main()
