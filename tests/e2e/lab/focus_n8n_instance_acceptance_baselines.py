#!/usr/bin/env python3
"""Fixed read-only protected-baseline provenance; no helper, SQL or service start.

This explicit probe only inspects the isolated existing dev-c and hashes two
known archive files plus their per-id sidecars. It never exports their contents.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import focus_n8n_instance_acceptance as plan


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--read-only-inventory', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.read_only_inventory:
        parser.error('explicit --read-only-inventory required')
    if args.output.exists(): raise ValueError('never overwrite a captured baseline')
    import ha_import_e2e as h
    h.DEVICE = plan.DEVICE
    h.require_isolated_device()
    fixed = (HERE/'focus_n8n_instance_acceptance_ops.py').read_text()
    # Module main is intentionally not invoked; append only the fixed read path.
    script = "__name__='fixed_readonly_baselines'\n" + fixed + '''
try:
 sys.path.insert(0,'/usr/local/lib/woowtech-cockpit-backup')
 from woowbackup.storage import Storage
 from woowbackup.paths import Paths
 storage=Storage(Paths()); protected=protected_inventory()
 for bid,rec in protected.items():
  assert storage.archive_path(bid).name == rec['archive']['filename']
  assert storage.index_path(bid).name == bid+'.json'
 sources={}
 for name in ('storage.py','paths.py'):
  p=Path('/usr/local/lib/woowtech-cockpit-backup/woowbackup')/name
  sources[name]=read_regular(p)[1]['sha256']
 print(json.dumps({'protected':protected,'installed_storage_sources':sources}))
except Exception as error:
 print(json.dumps({'error_class':type(error).__name__}),file=sys.stderr)
 raise SystemExit(1)
'''
    p = h.root('python3', '-B', '-I', '-c', script, timeout=120)
    if p.returncode:
        raise RuntimeError('fixed read-only baseline capture failed; raw stderr withheld')
    result = json.loads(p.stdout)
    result.update(device=plan.DEVICE, observed_utc=datetime.now(timezone.utc).isoformat(),
                  operation='fixed-read-only-baseline-files', database_opened=False,
                  service_started=False, helper_called=False, mutation=False,
                  probe_sha256=plan.sha(__file__), ops_sha256=plan.sha(HERE/'focus_n8n_instance_acceptance_ops.py'),
                  production_source_commit='d09f4fe8e06305aff6a1150f41d6de719e7b7f6a',
                  driver_commit=subprocess.check_output(['git','-C',str(plan.REPO),'rev-parse','HEAD'],text=True).strip())
    with args.output.open('x', encoding='utf-8') as out:
        json.dump(result,out,indent=2);out.write('\n')
    print(json.dumps({'stage':'readonly_baselines_captured','files':sum(1+(v['sidecar'] is not None)
                     for v in result['protected'].values()),'sha256':plan.sha(args.output),'mutation':False}))
    return 0


if __name__ == '__main__': raise SystemExit(main())
