"""Exact stored parent PAGE4 recovery route. Read files only; never call D.

CAT25 proves original state/catalog return. Probe02 independently proves its
new credentials and static scan. Neither proves PAGE4's lost cookie absence.
The page controller still checks fresh originals and every retained ID before
arming. This route neither rewrites a failed receipt nor deletes old copies.
"""
import hashlib
import json
import os
from pathlib import Path

CAT_SHA = '420b9d4fe582af93eef3aa37b958d6b71b57a0580e8775eda39c0478720490fb'
GUARD_SHA = '329fba10a4e4e290209fa7ae5e5545549214227a38d0c0033473234569581b67'
WRAPPER_SHA = 'ceb5fa417fe393f463b4658422bc5b370350c7118a8c6fb918e7b7225237923e'
CASE_HASHES = {
    'summary.json': 'cf5a768f42a68b794412782247557f4c44b194d0b875f4ca80fe80f3adf08f09',
    'results.json': '0b93f211864505c73b778c6ee84804588b79a2da63127dfc4ec87b9912076c1c',
    'recovery.json': 'e5719be24e5d6d7baae85e02e709b437b8949df328e07c907207da1aaab5a270',
    'browser.json': '0917d61d111e17ccb039281b3a18ce84b5f2bbe626a70c4a1730e01cc38b41ca',
}
PRUNES = {
    '20261126T225357Z-193816e7': ('hermes', '20261127T064505',
        'job-j20261126T225310Z-09bf3b35.json', '030af00d943fd61a79b4b32276a1742fee33810fd015a85031603d62bad58a40',
        'job-j20261127T002848Z-4e68c8e4.json', '40e07c08c419e4c7e780e493d5731803465c08aa29744e21060aba2807e310e3'),
    '20261126T225552Z-2e6d3671': ('omnigent', '20261127T064505',
        'job-j20261126T225519Z-92fea35e.json', 'd727c80a49d065753d67566c58aab08a5d448623fa5dec50ef191ffadab11107',
        'job-j20261127T002653Z-89390b89.json', '1be02156144bd39115d3f56da55d920835a579c46657e0f88032dc87fd469106'),
    '20261126T234230Z-11508663': ('omnigent', '20261127T073833',
        'job-j20261126T234156Z-a3792bfa.json', '60819dfc7022c04c3ad941248897c5fb8049e0d7bd59bedbcf44ab5c995ad91c',
        'job-j20261127T003437Z-8b92dfb8.json', 'a774990271660b69c413efdc4d3f03e2e24fb20dfd7522c201807c25045df29a'),
    '20261126T234446Z-20a51c66': ('hermes', '20261127T073833',
        'job-j20261126T234341Z-0198cb43.json', '9c1847d25a47b1dbb1e0e5e30c73dbb1e947e5a929062bd3a996d956443d8397',
        'job-j20261127T003248Z-5c5a8cc3.json', '634505e5ecfd88c43ce6f37250941c77094a4c4501786717a52c40e395ad3062'),
}


def checked(path, expected):
    path = Path(path)
    if (path.is_symlink() or path.resolve() != path.absolute() or not path.is_file()
            or path.stat().st_uid != os.getuid()):
        raise ValueError('unsafe parent recovery evidence path')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('parent recovery evidence hash mismatch')
    return json.loads(raw)


def verify(guard, proof, expected_sha, evidence_root):
    """Accept only this exact immutable parent proof, never a generic exemption."""
    if expected_sha != CAT_SHA or hashlib.sha256(guard).hexdigest() != GUARD_SHA:
        raise ValueError('exact parent PAGE4 guard and CAT25 proof required')
    cat = checked(proof, CAT_SHA)
    if (cat['scope'] != 'only-own-catalog-return' or cat['status'] != 'passed'
            or cat['guard_sha256'] != GUARD_SHA or cat['wrapper_sha256'] != WRAPPER_SHA
            or len(cat['checks']) != 25 or any(c['ok'] is not True for c in cat['checks'])
            or cat['active_jobs'] != 0 or cat['imports_restores_deploys_image_changes'] != 0
            or any(cat[k] is not True for k in ('original_catalog_equal',
                'archive_and_ha_inventory_unchanged', 'original_markers_units_images_timer_verified',
                'old_failed_guard_evidence_unchanged'))):
        raise ValueError('parent original-state/catalog proof incomplete')
    old = json.loads(guard)
    root = Path(evidence_root)
    case = root/'focus-acceptance-ui/20261127T082326'
    if (Path(old['evidence_dir']) != case or old['phase'] != 'recovery-retained'
            or old['baseline_restored'] is not True or old.get('inflight')
            or old['recovery_verified'] is not False):
        raise ValueError('parent failed PAGE4 state changed')
    for name, expected in CASE_HASHES.items():
        checked(case/name, expected)
    # Actual successful restore-job logs, NOT journals. Pin both creation and
    # deletion captures; missing manual, baseline and unknown IDs never qualify.
    pruning = old['prior_case_safety_pruning']
    if len(pruning) != 4 or {p['id'] for p in pruning} != set(PRUNES):
        raise ValueError('exact prior owned safety accounting required')
    for bid, (app, origin, creation, creation_sha, deletion, deletion_sha) in PRUNES.items():
        created = checked(root/'focus-acceptance-ui'/origin/creation, creation_sha)['job']
        deleted = checked(case/deletion, deletion_sha)
        row = next(p for p in pruning if p['id'] == bid)
        if (row['type'] != 'safety' or row['events'] != [{'file': deletion,
                'sha256': deletion_sha, 'job_id': deleted['job']['id']}]
                or created.get('state') != 'succeeded' or created.get('type') != 'restore'
                or created.get('params', {}).get('apps') != [app]
                or created.get('result', {}).get('safety_backup_id') != bid
                or deleted['job'].get('state') != 'succeeded' or deleted['job'].get('type') != 'restore'
                or not any(isinstance(line, str) and line.endswith('已刪除較舊的還原前備份 '+bid)
                           for line in deleted.get('log', []))):
            raise ValueError('actual own safety creation/pruning not proved')
    declared = set(old['created_backups']) | set(old['protected_existing_backups'])
    retained = declared-set(PRUNES)
    if (len(old['created_backups']) != 6 or len(retained) != 12
            or not set(PRUNES) <= set(old['protected_existing_backups'])
            or set(PRUNES) & set(old['created_backups'])):
        raise ValueError('parent retained/pruned accounting invalid')
    # This is an independent later scan, explicitly bound to DIFFERENT cookies.
    folder = root/'focus-acceptance-ui-cookie/20261127T090930'
    receipt_sha = '6355a40ca3636f88fa1107d507368165e16cd11c12c5877eb2e73a17890230e7'
    result_sha = '91797d3bfd7efee47aa986e942e0d262eca4c9ab30edc5b0ff3fe94ed4c7b3a6'
    receipt = checked(folder/'receipt.json', receipt_sha)
    result = checked(folder/'result.json', result_sha)
    if (receipt['guard_sha256'] != GUARD_SHA or receipt['result_sha256'] != result_sha
            or receipt['exit'] != 0 or any(receipt[k] is not True for k in (
                'protected_case_files_unchanged', 'catalog_archive_HA_schedule_inventory_unchanged',
                'network_isolation_preserved'))
            or any(result[k] is not True for k in ('diagnostic_completed', 'observations_complete',
                'strict_credential_zero_hits', 'registered_credentials_zero_hits'))
            or result['acceptance_passed'] is not False
            or result['proves_old_page4_cookie_absence'] is not False
            or result['regular_json_roots'] != 2 or result['archive_index_sidecars'] != 17
            or result['actual_archive_index_sidecars_expected'] != 17):
        raise ValueError('independent scan or explicit cookie limitation missing')
    return old, {'path': str(proof), 'sha256': CAT_SHA, 'old_guard_sha256': GUARD_SHA,
        'scope': 'parent-CAT25-plus-independent-probe02-recovery-readiness-only',
        'acceptance_passed': False, 'cookie_coverage_of_old_attempt': False,
        'independent_probe_receipt_sha256': receipt_sha, 'independent_probe_result_sha256': result_sha,
        'retained_case_archive_ids': sorted(retained), 'proved_prior_owned_safety_pruning': pruning,
        'fresh_originals_and_retained_inventory_required_before_arming': True}
