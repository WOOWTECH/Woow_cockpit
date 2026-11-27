"""Only the new namespace/proof contract; no repeat of the source2 FSM suite."""
from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import focus_n8n_instance_acceptance_reinstall as host
import focus_n8n_instance_acceptance_source2_ops as ops
import focus_n8n_instance_acceptance_source2_test as fixtures


class ReinstallTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.FileFSMTests()
        probe = patch.object(ops.base, 'tool_probe', side_effect=self.fixture.probe_import)
        probe.start(); self.addCleanup(probe.stop)

    def setup_proof(self, folder):
        proof = self.fixture.setup_tree(folder)
        proof.prepare(fixtures.candidate(), {}); proof.publish(fixtures.candidate()); proof.restore()
        ns = dict(vars(ops)); exec(host.EXTENSION, ns)
        ns['SOURCE2_RETURN_SHA'] = ops.checked_file(proof.path/'state.json')['sha256']
        current = ns['FullflowTransaction'](proof.name, lib=proof.lib, helper=proof.helper,
            parent=proof.path.parent, trusted_root=proof.trusted_root)
        return proof, current

    def test_new_namespace_reuses_per_file_roundtrip_and_leaves_proof_tree_exact(self):
        with tempfile.TemporaryDirectory() as folder:
            proof, current = self.setup_proof(folder)
            before = ops.checked_tree(proof.path); candidate = ops.checked_tree(proof.libown)
            self.assertNotEqual(proof.path, current.path); self.assertNotEqual(proof.libown, current.libown)
            self.assertNotEqual(proof.helpown, current.helpown)
            current.prepare(fixtures.candidate(), {}); current.publish(fixtures.candidate()); current.restore()
            self.assertEqual(ops.checked_tree(current.lib), proof.state['original'])
            self.assertEqual(ops.checked_file(current.helper), proof.state['helper'])
            self.assertEqual(ops.checked_tree(proof.path), before)
            self.assertEqual(ops.checked_tree(proof.libown), candidate)
            with self.assertRaises(ValueError): current.prepare(fixtures.candidate(), {})

    def test_changed_source2_journal_or_copy_refuses_before_first_live_write(self):
        for kind in ('journal', 'private', 'candidate'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                proof, current = self.setup_proof(folder); before = ops.checked_tree(current.lib)
                target = {'journal':proof.path/'state.json', 'private':proof.path/'private-library/VERSION',
                    'candidate':proof.newlib/'VERSION'}[kind]
                target.write_bytes(b'foreign edit')
                with self.assertRaises(ValueError): current.prepare(fixtures.candidate(), {})
                self.assertEqual(ops.checked_tree(current.lib), before)
                self.assertFalse(current.path.exists())

    def test_proof_changed_after_publish_stops_return_before_any_live_write(self):
        with tempfile.TemporaryDirectory() as folder:
            proof, current = self.setup_proof(folder)
            current.prepare(fixtures.candidate(), {}); current.publish(fixtures.candidate())
            (proof.path/'private-helper').chmod(0o640); before = ops.checked_tree(current.lib)
            with self.assertRaises(ValueError): current.restore()
            self.assertEqual(ops.checked_tree(current.lib), before)

    def test_default_offline_and_new_lease_reject_old_authorization(self):
        with patch.object(host, 'invoke', side_effect=AssertionError('no device')), redirect_stdout(io.StringIO()):
            self.assertEqual(host.main([]), 0)
        payload = fixtures.candidate(); image = {'name':fixtures.NAME, 'images_ready':True,
            'owned_images':list(host.previous.plan.ARCHIVES)}
        lease = {'granted':True, 'device':host.previous.plan.DEVICE, 'case':host.CASE,
            'method':host.source2.METHOD, 'source2_return_journal_sha256':host.PROOF_SHA,
            'phases':list(host.PHASES), 'driver_commit':'a'*40, 'source_commit':ops.base.FROZEN,
            'name':fixtures.NAME, 'source_manifest_sha256':host.previous.manifest_sha(payload),
            'bounds':host.bounds(payload),
            'protected_capture_sha256':host.previous.plan.sha(host.previous.REPO/'snippets'/
                host.previous.plan.AREA/'protected-baselines-readonly.json'),
            'not_before_utc':datetime.fromtimestamp(900, timezone.utc).isoformat(),
            'expires_utc':datetime.fromtimestamp(2000, timezone.utc).isoformat()}
        self.assertEqual(host.validate(lease, host.PHASES[0], 'a'*40, payload, image, 1000), 2000)
        for key, value in (('case',host.source2.CASE), ('phases',list(host.source2.PHASES)),
                ('source2_return_journal_sha256','f'*64), ('driver_commit','b'*40)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                host.validate(dict(lease, **{key:value}), host.PHASES[0], 'a'*40, payload, image, 1000)

    def test_source_only_computed_disk_boundary_keeps_13gib_ram_and_old_defaults(self):
        budget = host.source_budget(fixtures.candidate())['write_budget_bytes']
        self.assertLessEqual(budget, 256*1024**2)
        floor = 13*1024**3+budget
        wire = SimpleNamespace(root=lambda *a, **kw:SimpleNamespace(returncode=0, stdout=str(1900*1024**2).encode()))
        fakepath = SimpleNamespace(read_text=lambda:'MemAvailable: 1228800 kB\n')
        with patch.object(host.previous, 'Path', return_value=fakepath), \
                patch.object(host.previous.os, 'statvfs', return_value=SimpleNamespace(f_bavail=floor, f_frsize=1)) as stat:
            host.previous.resources(wire, time.time()+1000, write_budget_bytes=budget)
            stat.return_value.f_bavail = floor-1
            with self.assertRaises(RuntimeError): host.previous.resources(wire, time.time()+1000, write_budget_bytes=budget)
            stat.return_value.f_bavail = floor
            with self.assertRaises(RuntimeError): host.previous.resources(wire, time.time()+1000)  # old8GiB default
            fakepath.read_text = lambda:'MemAvailable: 1228799 kB\n'
            with self.assertRaises(RuntimeError): host.previous.resources(wire, time.time()+1000, write_budget_bytes=budget)
            fakepath.read_text = lambda:'MemAvailable: 1228800 kB\n'
            wire.root = lambda *a, **kw:SimpleNamespace(returncode=0, stdout=str(1900*1024**2-1).encode())
            with self.assertRaises(RuntimeError): host.previous.resources(wire, time.time()+1000, write_budget_bytes=budget)


if __name__ == '__main__': unittest.main()
