"""Real tar assembly with fixture transport and bounded root-stat boundary."""
import io
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from woowbackup import ha_omnigent as omni
from woowbackup.errors import BackupError

class ServerVolumeTests(unittest.TestCase):
    def run_volume(self, root_entry):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live = root / 'live.tar'
            def entry(tar, name, data=None, mode=0o600):
                item = tarfile.TarInfo(name)
                item.uid, item.gid, item.mode = 37, 41, mode
                if data is None:
                    item.type = tarfile.DIRTYPE
                else:
                    item.size = len(data)
                tar.addfile(item, io.BytesIO(data) if data is not None else None)
            with tarfile.open(live, 'w') as tar:
                if root_entry is not None:
                    entry(tar, '.', mode=root_entry)
                entry(tar, 'artifacts', mode=0o750)
                entry(tar, 'artifacts/obsolete', b'old')
                entry(tar, 'sharing_mode', b'off')
            with tarfile.open(root / 'ha-artifacts.tar', 'w') as tar:
                entry(tar, 'artifacts', mode=0o755)
                entry(tar, 'artifacts/accounts-cookie-secret', b'synthetic-cookie')
            (root / 'out/volumes').mkdir(parents=True)
            work = SimpleNamespace(guard=SimpleNamespace(wrote=lambda n: None))
            with patch.object(omni.hacommon, 'live_export', return_value=live), \
                 patch.object(omni.ha_n8n, 'volume_root', return_value=(37, 41, 0o710)) as metadata:
                output = omni.server_volume(work, SimpleNamespace(id='omnigent'),
                    SimpleNamespace(server_volume='test-server'), root, root / 'out')
                metadata.assert_called_once()
            with tarfile.open(output) as tar:
                members = {m.name: m for m in tar}
                self.assertEqual((members['.'].uid, members['.'].gid, members['.'].mode), (37,41,0o710))
                self.assertEqual(sum(m.name == '.' for m in tar.getmembers()), 1)
                self.assertNotIn('artifacts/obsolete', members)
                self.assertEqual(tar.extractfile('sharing_mode').read(), b'off')
                self.assertEqual(tar.extractfile('artifacts/accounts-cookie-secret').read(), b'synthetic-cookie')
                self.assertEqual(members['artifacts/accounts-cookie-secret'].mode, 0o600)

    def test_podman_export_without_root_preserves_actual_root(self):
        self.run_volume(None)

    def test_matching_export_root_is_not_duplicated(self):
        self.run_volume(0o710)

    def test_root_metadata_change_refused(self):
        with self.assertRaises(BackupError):
            self.run_volume(0o777)
