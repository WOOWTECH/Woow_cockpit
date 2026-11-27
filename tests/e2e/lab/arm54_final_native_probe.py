"""Component probe on .54 (lane arm54-2): the native-code verdicts of fix ee5a3cc / ed3758e on the real ARM64 device, with the real
RPi5 backup e10f1abc of 2026-11-19 (an Odoo module and an n8n community package that contain code built for ARM only).

The product's own scanners (ha_odoo.scan_member, ha_n8n.scan_member) read the archive twice: once as this device is (aarch64)
and once with the processor the old code assumed (x86-64, host_elf_machine patched). No container, no network, no change to
the machine; the archive is already in the workspace. Only module/package names and counts leave this script."""
import json
import os
from pathlib import Path
import shutil
import sys
import time
from unittest import mock

from arm54_final_runtime import ROOT, private_dir, report, sha256_file

from woowbackup import habackup, ha_n8n, ha_odoo, hastore  # noqa: E402

SHA = '7fc768a38011acd8681292b62ee9750014ac25137712738442eb616fd1023e29'
ARCHIVE = ROOT / 'input/ha-backup-arm-native.tar'
out = {'status': 'failed', 'kind': 'component probe (product scanners on the real archive); not an import', 'archive_sha256': SHA,
       'commercial_acceptance': 'not-complete'}
started = time.monotonic()
work = private_dir('work', 'native-probe-%d' % int(time.time()))


def scan(tag):
    result = {}
    with habackup.open_backup(ARCHIVE) as opened:
        for member in opened.layout.members:
            if member.role != 'addon':
                continue
            suffix = hastore.addon_suffix(member.slug)
            with opened.open_member(member.name) as stream:
                if suffix == 'odoo18ce':
                    src = ha_odoo.scan_member(stream, habackup.Report())
                    result['odoo_modules'] = len(src.modules)
                    result['odoo_foreign'] = sorted(m for m, info in src.modules.items() if info.get('foreign'))
                elif suffix == ha_n8n.SLUG:
                    staging = work / tag
                    staging.mkdir(mode=0o700)
                    src = ha_n8n.scan_member(stream, habackup.Report(), staging)
                    result['n8n_native_files'] = src.native
                    result['n8n_packages'] = sorted(p['name'] for p in src.packages)
                    result['n8n_not_fitting'] = sorted(src.native_bad)
    return result


try:
    assert sha256_file(ARCHIVE) == SHA, 'archive-differs-from-the-record'
    out['device_machine'] = os.uname().machine
    out['elf_machine'] = ha_odoo.host_elf_machine()
    out['as_this_device'] = scan('device')
    with mock.patch.object(ha_odoo, 'host_elf_machine', lambda: ha_odoo.EM_X86_64), \
            mock.patch.object(ha_n8n, 'host_elf_machine', lambda: ha_odoo.EM_X86_64):
        out['as_the_old_code_assumed_x86_64'] = scan('x86')
    device, old = out['as_this_device'], out['as_the_old_code_assumed_x86_64']
    out['checks'] = {
        'device_is_aarch64': out['device_machine'] == 'aarch64' and out['elf_machine'] == ha_odoo.EM_AARCH64,
        'odoo_arm_module_fits_this_device': device['odoo_foreign'] == [] and old['odoo_foreign'] == ['woow_arm_native_probe'],
        'n8n_arm_package_fits_this_device': device['n8n_not_fitting'] == []
        and old['n8n_not_fitting'] == ['n8n-nodes-woow-native-probe'],
        'same_files_scanned': device['odoo_modules'] == old['odoo_modules'] and device['n8n_native_files']
        == old['n8n_native_files'] >= 1}
    out['status'] = 'passed' if all(out['checks'].values()) else 'failed'
except Exception as error:  # noqa: BLE001 - type and a short fixed reason only
    out['error'] = type(error).__name__
    out['error_detail'] = str(error)[:80] if isinstance(error, AssertionError) else None
finally:
    shutil.rmtree(work, ignore_errors=True)
    out['elapsed_seconds'] = round(time.monotonic() - started, 1)
    report(ROOT / 'native-probe-result.json', out)
    print(json.dumps(out, sort_keys=True))
sys.exit(0 if out['status'] == 'passed' else 1)
