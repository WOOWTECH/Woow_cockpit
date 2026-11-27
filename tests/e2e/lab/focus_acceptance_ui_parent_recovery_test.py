"""Targeted offline review of immutable real parent facts; no lab calls."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import focus_acceptance_ui as ui
import focus_acceptance_ui_parent_recovery as parent


class ParentRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.guard = ui.STATE.read_bytes()
        self.proof = ui.REPO/'tests/backup/evidence/focus-acceptance-20261127/r8-owned-catalog-return.json'

    def test_real_parent_CAT25_and_probe02_allow_only_readiness_with12_retained(self):
        before = self.proof.read_bytes()
        old, provenance = ui.verified_recovery(self.guard, self.proof, parent.CAT_SHA)
        self.assertFalse(provenance['acceptance_passed'])
        self.assertFalse(provenance['cookie_coverage_of_old_attempt'])
        self.assertTrue(provenance['fresh_originals_and_retained_inventory_required_before_arming'])
        self.assertEqual(len(provenance['retained_case_archive_ids']), 12)
        self.assertLessEqual(set(old['created_backups']), set(provenance['retained_case_archive_ids']))
        self.assertFalse(set(parent.PRUNES) & set(provenance['retained_case_archive_ids']))
        self.assertEqual(self.proof.read_bytes(), before)
        self.assertEqual(ui.STATE.read_bytes(), self.guard)

    def test_different_guard_or_claimed_proof_hash_cannot_use_parent_route(self):
        for guard, sha in ((self.guard+b' ', parent.CAT_SHA), (self.guard, '0'*64)):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                parent.verify(guard, self.proof, sha, ui.LAB/'evidence')

    def test_tampered_or_symlinked_catalog_receipt_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'proof.json'
            path.write_bytes(self.proof.read_bytes()+b' ')
            with self.assertRaises(ValueError):
                parent.verify(self.guard, path, parent.CAT_SHA, ui.LAB/'evidence')
            path.unlink(); path.symlink_to(self.proof)
            with self.assertRaises(ValueError):
                parent.verify(self.guard, path, parent.CAT_SHA, ui.LAB/'evidence')

    def test_new_case_pruning_needs_owned_safety_and_actual_successful_event(self):
        old = json.loads(self.guard); case = Path(old['evidence_dir'])
        bid = next(iter(parent.PRUNES)); spec = parent.PRUNES[bid]
        raw = (case/spec[4]).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), spec[5])
        before = {bid: {'type': 'safety'}}
        proved = ui.case_safety_prunes(before, set(), [bid], {spec[4]: raw})
        self.assertEqual(proved[0]['id'], bid)
        for rows, owned, capture in (({bid: {'type': 'manual'}}, [bid], raw),
                (before, [], raw), (before, [bid], json.dumps({'job': {'state': 'succeeded',
                'type': 'restore', 'id': 'example'}, 'log': []}).encode())):
            with self.subTest(owned=bool(owned)), self.assertRaises(ValueError):
                ui.case_safety_prunes(rows, set(), owned, {spec[4]: capture})


if __name__ == '__main__':
    unittest.main()
