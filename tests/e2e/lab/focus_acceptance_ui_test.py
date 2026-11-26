"""Offline safety boundaries only; no browser, relay listener or lab device."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


ui = module('prepared_ui', 'focus_acceptance_ui.py')
relay = module('prepared_relay', 'focus_acceptance_ui_relay.py')


class OfflineSafetyTests(unittest.TestCase):
    def test_default_does_not_enter_runtime(self):
        with patch.object(ui, 'run', side_effect=AssertionError('unleased runtime')) as run:
            self.assertEqual(ui.main([]), 0)
            run.assert_not_called()

    def test_relay_object_does_not_start_a_listener(self):
        with patch.object(relay.asyncio, 'start_server', side_effect=AssertionError('unleased listener')) as start:
            value = relay.Relay()
            self.assertIsNone(value.thread)
            self.assertEqual(value.children, set())
            start.assert_not_called()

    def test_fixed_stdio_command_uses_unprivileged_lab_exec(self):
        cmd = relay.command()
        self.assertEqual(cmd[:7], [str(relay.LP), 'exec', '-i', '--user', 'devadmin', 'woowbk-dev-d', 'python3'])
        self.assertEqual(cmd[7:9], ['-I', '-c'])
        self.assertIn('socket.create_connection(("127.0.0.1", 9090)', cmd[9])
        self.assertNotIn('.bind(', cmd[9])
        self.assertNotIn('podman run', cmd[9])
        compile(cmd[9], '<fixed remote client>', 'exec')


class DerivedCopyTests(unittest.TestCase):
    def original(self, folder, *, omit=False, link=False):
        path = folder/'original.tar'
        with tarfile.open(path, 'w') as archive:
            for name in ['backup.json', 'homeassistant.tar.gz', 'omni.tar.gz', 'hermes.tar.gz', 'headscale.tar.gz'] + ([] if omit else [ui.BROKEN]):
                info = tarfile.TarInfo(name)
                data = (name.encode()+b'\x00\xff')*100
                info.size = len(data)
                if link and name == ui.BROKEN:
                    info.type = tarfile.SYMTYPE
                    info.linkname = '/outside'
                    info.size = 0
                archive.addfile(info, io.BytesIO(data) if info.isfile() else None)
        return path

    def test_copy_changes_only_last64bytes_of_reviewed_member(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            original = self.original(folder)
            before = original.read_bytes()
            output = folder/'derived.tar'
            ui.derive(original, output)
            self.assertEqual(original.read_bytes(), before)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with tarfile.open(original) as left, tarfile.open(output) as right:
                self.assertEqual(left.getnames(), right.getnames())
                for name in left.getnames():
                    want = left.extractfile(name).read()
                    self.assertEqual(right.extractfile(name).read(), want[:-64] if name == ui.BROKEN else want)

    def test_original_and_existing_destination_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            original = self.original(Path(folder))
            with self.assertRaises(ValueError):
                ui.derive(original, original)
            other = Path(folder)/'existing.tar'
            other.write_bytes(b'keep')
            with self.assertRaises(FileExistsError):
                ui.derive(original, other)
            self.assertEqual(other.read_bytes(), b'keep')

    def test_missing_member_and_outer_link_are_refused(self):
        for options in ({'omit':True}, {'link':True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as folder:
                original = self.original(Path(folder), **options)
                before = original.read_bytes()
                with self.assertRaises(ValueError):
                    ui.derive(original, Path(folder)/'derived.tar')
                self.assertEqual(original.read_bytes(), before)


class CurrentPageContractTests(unittest.TestCase):
    def records(self):
        rows = [{'type':kind,'state':'succeeded'} for kind in ('backup','restore','backup','restore')]
        rows[-1]['result']={'group':{'results':[{'app_id':x,'status':'imported'} for x in ('hermes','omnigent')]}}
        return rows

    def test_two_importable_apps_make_four_jobs(self):
        self.assertTrue(ui.chain_complete(self.records()))

    def test_old_five_job_assumption_and_partial_success_are_not_accepted(self):
        rows = self.records()
        self.assertFalse(ui.chain_complete([{'type':'backup','state':'failed'}]+rows))
        rows[1]['state']='rolled-back'
        self.assertFalse(ui.chain_complete(rows))
        rows = self.records()
        rows[-1]['result']['group']['results'][0]['app_id']='emqx'
        self.assertFalse(ui.chain_complete(rows))

    def test_read_only_marker_wrapper_requires_known_producer_boundary(self):
        source = Path(__file__).with_name('batch1_markers.py').read_text()
        prepared = ui.marker_program(source)
        compile(prepared, '<observed existing markers>', 'exec')
        self.assertIn('issued.append(token)', prepared)
        with self.assertRaises(ValueError):
            ui.marker_program('unreviewed_call()')


if __name__ == '__main__':
    unittest.main()
