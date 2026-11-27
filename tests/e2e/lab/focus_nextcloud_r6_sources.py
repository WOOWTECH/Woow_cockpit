#!/usr/bin/env python3
"""Inspect only the five original R6 host image identities; never export or mutate.

Uses the exact host `podman image inspect` route in deploy-batch2.sh:copy_image.
The coordinator explicitly authorized this read-only source-store inspection.
"""
import argparse
import datetime
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from focus_nextcloud_r6_inventory import ORIGINALS

FORMAT = ('{"id":"{{.Id}}","architecture":"{{.Architecture}}","os":"{{.Os}}",'
          '"size":{{.Size}},"repo_tags":{{json .RepoTags}},"repo_digests":{{json .RepoDigests}}}')


def inspect(ref):
    proc = subprocess.run(['podman', 'image', 'inspect', '--format', FORMAT, ref],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    if proc.returncode:
        return None
    if len(proc.stdout) > 65536:
        raise RuntimeError('fixed-source-inspect-size-refused')
    row = json.loads(proc.stdout)
    row['id'] = 'sha256:' + row['id'].removeprefix('sha256:')
    return row


def collect():
    rows = []
    for ref, expected in ORIGINALS.items():
        identity = inspect(expected)
        tag_identity = inspect(ref)
        match = (identity is not None and identity['id'] == 'sha256:' + expected
                 and identity['architecture'] == 'amd64' and identity['os'] == 'linux')
        rows.append({'ref': ref, 'expected_config_id': 'sha256:' + expected,
                     'present': identity is not None, 'identity': identity,
                     'identity_matches': match,
                     'canonical_ref_config_id': tag_identity['id'] if tag_identity else None,
                     'canonical_ref_matches': bool(match and tag_identity
                                                  and tag_identity['id'] == identity['id'])})
    return {'status': 'read-only-source-inspected', 'device': 'woowbk-dev-e',
            'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'controller_route': 'deploy-batch2.sh:copy_image:podman image inspect',
            'images': rows, 'all_originals_present_and_matching': all(x['identity_matches'] for x in rows),
            'host_mutations': 0, 'device_mutations': 0, 'image_bytes_copied': 0, 'pulls': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit('choose-new-source-output')
    record = collect()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as output:
        output.write(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': record['status'],
                      'matching_originals': sum(x['identity_matches'] for x in record['images']),
                      'canonical_refs_match': all(x['canonical_ref_matches'] for x in record['images']),
                      'total_image_bytes': sum(x['identity']['size'] for x in record['images'] if x['identity']),
                      'image_bytes_copied': 0, 'pulls': 0}))


if __name__ == '__main__':
    main()
