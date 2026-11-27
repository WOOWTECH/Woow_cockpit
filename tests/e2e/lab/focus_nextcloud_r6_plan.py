#!/usr/bin/env python3
"""Offline R6 resource/lease/confirmation gates. Importing this file does no I/O."""
import argparse
import datetime
import json
import re
from pathlib import Path

GIB = 1024 ** 3
MIB = 1024 ** 2
RESERVE = 13 * GIB
MARGIN = GIB // 2
DEVICE_CAP = 3 * GIB
FIXTURE_BYTES = 4467947520
BASELINE = '20261123T132013Z-34811d90'
CASES = {'fullshare': set(),
         'skipped-files': {'nextcloud.symlinks-skipped', 'nextcloud.htaccess-skipped'},
         'server-encryption': {'nextcloud.server-side-encryption'}}


def image_budget(sizes):
    """Sequential compressed directory transfer: previous images + image + 2 transfers.

    Compressed output is capped at Size+16MiB (no assumed compression ratio).
    Three GiB additional first-start ID mapping is the existing controller bound.
    Existing host source images and the original HA fixture already occupy disk.
    """
    loaded = 0
    phases = []
    for size in sizes:
        if not isinstance(size, int) or size <= 0:
            raise ValueError('fixed-image-size-refused')
        compressed_cap = size + 16 * MIB
        phases.append({'image_bytes': size, 'compressed_cap_bytes': compressed_cap,
                       'additional_peak_bytes': loaded + size + 2 * compressed_cap + MARGIN})
        loaded += size
    wake_peak = loaded + 3 * GIB + MARGIN
    peak = max([wake_peak] + [x['additional_peak_bytes'] for x in phases])
    return {'images_total_bytes': loaded, 'sequential_phases': phases,
            'wake_additional_peak_bytes': wake_peak, 'additional_peak_bytes': peak,
            'minimum_start_free_bytes': RESERVE + peak, 'reserve_bytes': RESERVE,
            'device_memory_cap_bytes': DEVICE_CAP}


def acceptance_budget(html, pg, data, converted, safety, *, uploaded=FIXTURE_BYTES):
    """Current measured inputs, pessimistic uncompressed packaging, retained safety.

    Bounds include one uploaded HA copy (original path is reused), conversion,
    then upload deletion before any restore. Converted and initial safety copies
    are retained while an automatic/manual rollback creates its temporary copy.
    Runtime preflights must recompute from actual sizes; this is not an admission
    promise derived from historical compression.
    """
    if any(not isinstance(x, int) or x < 0 for x in (html, pg, data, converted, safety, uploaded)):
        raise ValueError('fixed-case-size-refused')
    live = html + pg + data
    archive = html + pg + data
    conversion = data + pg + max(3 * pg, 2 * html, html + archive) + MARGIN
    upload_convert = uploaded + conversion
    restore = converted + safety + 2 * max(converted, safety) + 2 * live + 2 * GIB
    peak = max(upload_convert, restore) + MARGIN
    return {'upload_and_convert_peak_bytes': upload_convert,
            'restore_with_retained_safety_peak_bytes': restore,
            'additional_peak_bytes': peak, 'minimum_after_wake_free_bytes': RESERVE + peak,
            'reserve_bytes': RESERVE, 'extra_original_fixture_copy_bytes': 0}


def verified_credit_budget(bound,credit):
    # Caller obtains credit ONLY from fresh retained_credit(receipt,current-file-proof).
    if 'verified_owned_ha_credit_bytes' in bound or type(credit) is not int or not 0<=credit<=FIXTURE_BYTES:
        raise ValueError('fixed-owned-ha-credit-refused')
    out=dict(bound)
    out['uncredited_additional_peak_bytes']=bound['additional_peak_bytes']
    out['verified_owned_ha_credit_bytes']=credit
    out['additional_peak_bytes']=max(0,bound['additional_peak_bytes']-credit)
    out['minimum_after_wake_free_bytes']=RESERVE+out['additional_peak_bytes']
    return out


def confirmation_keys(job, case):
    """Only the reviewed issue IDs may be acknowledged, using their actual bound keys."""
    if case not in CASES or job.get('state') != 'succeeded':
        raise ValueError('fixed-check-not-ready')
    check = (job.get('result') or {}).get('ha_check') or {}
    apps = check.get('apps') or []
    if len(apps) != 1 or apps[0].get('app_id') != 'nextcloud' or apps[0].get('importable') is not True:
        raise ValueError('fixed-nextcloud-not-importable')
    issues = apps[0].get('issues') or []
    if any(x.get('level') == 'stop' for x in issues):
        raise ValueError('fixed-stop-issue')
    confirms = [x for x in issues if x.get('level') == 'confirm']
    if len(confirms) != len(CASES[case]) or {x.get('id') for x in confirms} != CASES[case]:
        raise ValueError('fixed-unreviewed-confirmation')
    keys = []
    for issue in confirms:
        key = issue.get('key', '')
        if not re.fullmatch(re.escape(issue['id']) + r':[0-9a-f]{16}', key):
            raise ValueError('fixed-confirmation-key-refused')
        keys.append(key)
    return sorted(keys)


def lease_check(lease, commit, phase, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        expires = datetime.datetime.fromisoformat(lease['expires_utc'].replace('Z', '+00:00'))
        starts = datetime.datetime.fromisoformat(lease['not_before_utc'].replace('Z', '+00:00'))
    except (KeyError, ValueError, TypeError):
        raise ValueError('fixed-lease-time-refused') from None
    if (lease.get('device') != 'woowbk-dev-e' or lease.get('source_commit') != commit
            or lease.get('lane') != 'nextcloud-r6' or phase not in lease.get('phases', [])
            or lease.get('reserve_bytes') != RESERVE or lease.get('memory_cap_bytes') != DEVICE_CAP
            or starts.tzinfo is None or expires.tzinfo is None or not starts <= now < expires):
        raise ValueError('fixed-lease-scope-refused')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sources', type=Path, required=True)
    p.add_argument('--inventory', type=Path, required=True)
    args = p.parse_args()
    sources = json.loads(args.sources.read_text())
    inventory = json.loads(args.inventory.read_text())
    if not sources.get('all_originals_present_and_matching'):
        raise SystemExit('fixed-source-originals-missing')
    images = image_budget([x['identity']['size'] for x in sources['images']])
    # Historical values are explicit estimates, to be replaced by fresh live sizes.
    case = acceptance_budget(849259813, 75382634, 234187031, 506583040, 422031360)
    free = min(inventory['host_free_bytes'], inventory['root']['varlib_free_bytes'])
    print(json.dumps({'status': 'offline-budget-only', 'observed_free_bytes': free,
                      'recovery': images, 'historical_case_estimate': case,
                      'remaining_after_recovery_and_case_bytes': free - images['additional_peak_bytes'] - case['additional_peak_bytes'],
                      'live_recalculation_required': True, 'mutations': 0}, indent=2))


if __name__ == '__main__':
    main()
