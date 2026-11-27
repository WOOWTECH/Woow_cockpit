#!/usr/bin/env python3
"""Read-only leak scan of dev-e after the journal cleanup (lab only): nextcloud_flow.py's own LEAKS program with the share run's
secret NAMES (values only on stdin, never printed): the engine's records, uploads, staging, run dir and the whole device journal.
    flock -w 3600 /tmp/woowbk-dev-e-mutation.lock python3 -I tests/e2e/lab/nextcloud_leak_rescan.py <facts.json> <evidence.json>
stdout: fixed lines only; the evidence holds counts only. Exit 0 only with 0 hits, the public link token's included."""
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nextcloud_flow', HERE / 'nextcloud_flow.py')
nf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nf)


def main(argv):
    facts = json.loads(Path(argv[0]).read_text(encoding='utf-8'))
    target = Path(argv[1])
    if target.exists():
        raise SystemExit('evidence file exists; never overwrite an attempt')
    secrets = nf.drv.Secrets(nf.SECRET_FILES, nf.MARKERS)
    names = ['HA_BACKUP_KEY', 'B2_NC_X86_NOSHARE_USER_PW', 'B2_NC_X86_NOSHARE_APP_PW', 'DEV_D_MARKER_NEXTCLOUD']
    names += [facts[k] for k in ('user_pw', 'app_pw', 'user2_pw', 'link_pw', 'link_token') if facts.get(k)]
    report = nf.drv.device_python(nf.LEAKS, {'secrets': {n: secrets[n] for n in names}, 'url_tokens': [facts['link_token']]},
                                  as_owner=False, timeout=900)
    iso = nf.isolation()
    checks = {'leak re-scan: no secret in the engine records, uploads, staging, run dir or the device journal':
              report.get('hits') == 0 and report.get('scanned', 0) > 0,
              'leak re-scan: the public link token is in no access log entry any more':
              report.get('url_token_access_log_hits') == 0 and report.get('url_token_hits_elsewhere') == 0,
              'dev-e isolation true none {}': iso == 'true none {}'}
    doc = {'kind': 'nextcloud-leak-rescan', 'date': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
           'source_commit': subprocess.run(['git', '-C', str(HERE), 'rev-parse', 'HEAD'], capture_output=True,
                                           text=True).stdout.strip(),
           'device': nf.DEVICE, 'report': report, 'checks': {k: 'PASS' if v else 'FAIL' for k, v in checks.items()},
           'acceptance': 'not acceptance (lab hygiene after the last share attempt)'}
    with open(target, 'x', encoding='utf-8') as handle:
        json.dump(doc, handle, indent=1, ensure_ascii=False)
        handle.write('\n')
    for name, value in doc['checks'].items():
        print(f'{name}: {value}')
    return 0 if all(checks.values()) else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
