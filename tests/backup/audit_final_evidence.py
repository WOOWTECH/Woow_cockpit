#!/usr/bin/env python3
"""Offline evidence audit: git blobs only; never imports/executes remote harnesses.

Run from repository root. This checks recorded artifacts, not service acceptance.
The fixed refs intentionally preserve the integration snapshot being audited.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASE = '3fe2ff3d8dba1ac1eb18e5c23aa00475d70bd6e2'
MAIN = 'c8471ed8bf1582ccea8d626da102cdd4b045da8f'
OUT = Path('tests/backup/evidence/final-acceptance-delta-20261122')
ARM = 'tests/e2e/lab/evidence/arm54-service-20261122/'
R2 = 'tests/backup/evidence/final-private-dispatch-20261122/'
LARGE = 'tests/backup/evidence/'


def git(*args):
    return subprocess.check_output(['git', *args])


def blob(path, ref=MAIN):
    return git('show', f'{ref}:{path}')


def data(path):
    return json.loads(blob(path))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    paths = [p for p in git('diff', '--name-only', BASE, MAIN).decode().splitlines()
             if '/evidence/' in p]
    inventory = []
    snapshots = {}
    parsed = 0
    for p in paths:
        raw = blob(p)
        inventory.append({'path': p, 'bytes': len(raw), 'sha256': sha(raw)})
        if p.endswith('.source.txt'):
            snapshots[p] = sha(raw)
        if p.endswith('.json'):
            json.loads(raw)
            parsed += 1
    manifests = [
        (ARM + 'source-hashes.json', 'files'),
        (ARM + 'final-harness-hashes.json', None),
        (LARGE + 'large-encrypted-provenance.json', 'sha256'),
        (R2 + 'results.json', 'source_sha256_before'),
        (R2 + 'results.json', 'source_sha256_after'),
    ]
    bindings = []
    for p, field in manifests:
        hashes = data(p)
        if field:
            hashes = hashes[field]
        for source, recorded in sorted(hashes.items()):
            actual = sha(blob(source))
            matches = [s for s, h in snapshots.items() if h == recorded]
            bindings.append({'manifest': p, 'field': field, 'source': source,
                             'recorded_sha256': recorded, 'main_sha256': actual,
                             'matches_main': actual == recorded,
                             'matching_execution_snapshots': matches})
    mismatches = [b for b in bindings if not b['matches_main']]
    assert len(mismatches) == 1, mismatches
    assert mismatches[0]['source'] == 'tests/e2e/lab/arm54_build_native.py'
    assert mismatches[0]['matching_execution_snapshots'] == [ARM + 'native-package-build.source.txt']
    # A final harness hash is a source inventory, not proof every final harness ran.
    snapshot_bindings = []
    final_harness = data(ARM + 'final-harness-hashes.json')
    for p, h in sorted(snapshots.items()):
        snapshot_bindings.append({'snapshot': p, 'sha256': h,
                                 'exact_final_harness_matches': [s for s, v in final_harness.items() if v == h]})
    save('source-bindings.json', {'audited_main': MAIN, 'bindings': bindings,
         'execution_snapshots': snapshot_bindings,
         'mismatch_interpretation': 'Initial build source matches its failed execution snapshot. Final build hash matches main; do not relabel the initial run as final-source execution.',
         'limits': ['SHA equality binds committed bytes, not authenticated remote execution.',
                    'Uploaded bundle and removed payload/image/key artifacts unavailable for independent rehash.',
                    'Initial R2 failure is historical, not the accepted final-source run.']})

    checks = []
    def check(name, condition):
        checks.append({'name': name, 'passed': bool(condition)})
        assert condition, name

    r = data(R2 + 'results.json')
    check('R2 final log hash', sha(blob(r['log'])) == r['log_sha256'])
    initial = data(R2 + 'initial-results.json')
    check('R2 initial failed log hash preserved', sha(blob(initial['log'])) == initial['log_sha256'])
    check('R2 32 actual methods, zero skip/error/failure/xfail', r['tests_run'] == 32 and
          len(r['executed_methods']) == 32 and len(r['selected_methods']) == 32 and
          {m['id'] for m in r['selected_methods']} == set(r['executed_methods']) and
          all(r[k] == 0 for k in ['failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes']))
    check('R2 sources unchanged during run', r['source_sha256_before'] == r['source_sha256_after'])
    large = data(LARGE + 'large-encrypted-8193mib.json')
    check('encrypted real 8193MiB member internal consistency', large['payload_bytes'] == 8193*1024**2 ==
          large['verified_bytes'] == large['extracted_bytes'] == large['actual_inner_member']['size'] and
          large['source_sha256'] == large['extracted_sha256'] and not large['sparse'] and
          large['source_allocated_bytes'] >= large['payload_bytes'] and
          large['extracted_allocated_bytes'] >= large['payload_bytes'])
    check('encrypted cleanup/key rejection recorded', large['ephemeral_keys_removed'] and
          large['temporary_payloads_removed'] and large['tool_children_remaining'] == 0 and
          large['key_rejections'] == {'missing': 'key-required', 'wrong': 'wrong-key'})
    check('encrypted outer archive is below 8GiB', large['archive_bytes'] == 34519040 < 8*1024**3)
    life = data(ARM + 'native-tempobjects-lifecycle.json')
    completion = data(ARM + 'native-tempobjects-completion.json')
    old_checks = {k for k, v in life['checks'].items() if v is True}
    all_checks = {k for k, v in completion['checks'].items() if v is True}
    check('lifecycle six across two attempts, three inherited', len(old_checks) == 3 and
          len(all_checks) == 6 and old_checks <= all_checks and life['status'] == 'failed' and
          life['error_code'] == 'ValueError' and completion['status'] == 'passed')
    check('completion source imports earlier checks', b"checks.update(previous['checks'])" in blob(ARM + 'native-tempobjects-completion.source.txt'))
    check('cleanup failure explicitly injected', any(c[0] == 'injected-transport-failure'
          for c in completion['checks']['cleanup_retry_transport_commands']))
    service = data(ARM + 'synthetic-service-converter-restore.json')
    check('service success bounded to CLI with zero nodes', service['status'] == 'passed' and
          service['users'] == 1 and service['nodes'] == 0 and not service['installer_rollback_tested'] and
          not service['tailscale_vpn_client_tested'] and not service['cleanup_left'] and
          any(c[0] == 'rootful-direct-namespace' for c in service['commands']))
    exits = []
    for p in paths:
        if p.startswith(ARM) and p.endswith('.exit.json'):
            result_path = p.removesuffix('.exit.json') + '.json'
            result = data(result_path)
            exit_code = data(p)['ssh_exit']
            status = result.get('status') if isinstance(result, dict) else None
            if status in ('passed', 'failed'):
                check('exit agrees with status: ' + Path(result_path).name,
                      (exit_code == 0) == (status == 'passed'))
            exits.append({'result': result_path, 'ssh_exit': exit_code, 'status': status})
    check('VPN latest verified registration attempt failed', data(ARM + 'tailscale-direct-loopback-verified.json')['status'] == 'failed')
    # Verify integration retains original artifacts, not just their summary claims.
    origins = [('0168078', '36d13a9'), ('25d5cf2', '7566d44'), ('cd849408', 'fe30094')]
    integration = []
    for original, integrated in origins:
        original = git('rev-parse', original).decode().strip()
        integrated = git('rev-parse', integrated).decode().strip()
        introduced = git('diff-tree', '--no-commit-id', '--name-only', '-r', original).decode().splitlines()
        evidence = [p for p in introduced if '/evidence/' in p]
        equal = all(blob(p, original) == blob(p, integrated) == blob(p) for p in evidence)
        check('original evidence preserved: ' + original[:7], equal)
        integration.append({'original': original, 'integrated': integrated, 'evidence_files': len(evidence), 'all_equal_to_main': equal})
    # These direct imports were omitted by the producer's four-file manifest.
    # Bind repository identity retrospectively, without inventing run-time hashes.
    dependency_rows = []
    producer = git('rev-parse', '0168078').decode().strip()
    producer_base = data(LARGE + 'large-encrypted-provenance.json')['base_commit']
    for source in ['backup-engine/woowbackup/util.py', 'backup-engine/woowbackup/errors.py',
                   'backup-engine/woowbackup/paths.py', 'tests/backup/test_archive.py',
                   'tests/backup/test_archive_v2.py']:
        hashes = {ref: sha(blob(source, ref)) for ref in [producer_base, producer, MAIN]}
        check('encrypted omitted direct dependency unchanged: ' + source, len(set(hashes.values())) == 1)
        dependency_rows.append({'source': source, 'sha256_by_commit': hashes})
    save('encrypted-dependency-sidecar.json', {
         'reason': 'Direct harness imports and archive/key utility dependencies omitted from original four-file manifest.',
         'binding_kind': 'retrospective repository identity; not runtime attestation',
         'producer_commit': producer, 'audited_main': MAIN, 'dependencies': dependency_rows,
         'limits': 'Does not establish a complete dynamic dependency closure or runtime environment identity.'})
    product_delta = git('diff', '--name-only', BASE, MAIN, '--', 'backup-engine').decode().splitlines()
    check('no engine changes since R2/ARM base', not product_delta)
    save('integrity.json', {'mode': 'independent local git-blob validation; no test-suite rerun',
         'base': BASE, 'audited_main': MAIN, 'new_evidence_files': len(paths), 'json_parsed': parsed,
         'source_binding_entries': len(bindings), 'source_binding_matches': len(bindings)-len(mismatches),
         'explained_historical_mismatches': len(mismatches), 'checks': checks,
         'integration': integration, 'recorded_remote_exits': exits, 'artifacts': inventory,
         'limits': 'Internal consistency and exact committed byte identity only; removed runtime artifacts and actual remote execution were not revalidated.'})

    patterns = {
        'private-key': rb'-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY)-----',
        'age-secret': rb'AGE-SECRET-KEY-[A-Z0-9]{20,}',
        'tailscale-secret': rb'tskey-[A-Za-z0-9_-]{12,}',
        'jwt': rb'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        'bearer-literal': rb'(?i)Bearer[ \t]+[A-Za-z0-9._~+/-]{20,}',
        'github-token': rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})',
        'aws-access-key': rb'(?:AKIA|ASIA)[A-Z0-9]{16}',
        'slack-token': rb'xox[baprs]-[A-Za-z0-9-]{20,}',
        'credential-url': rb'(?i)https?://[^/\s:@]{1,80}:[^/\s@]{4,120}@',
        'quoted-credential': rb'''(?i)["'](?:password|passwd|access_token|refresh_token|authkey|api_key|private_key|client_secret)["']\s*[:=]\s*["']([^"'\r\n]{16,})["']''',
    }
    findings = []
    for p in paths:
        raw = blob(p)
        for category, pattern in patterns.items():
            for m in re.finditer(pattern, raw):
                findings.append({'path': p, 'line': raw[:m.start()].count(b'\n')+1, 'category': category})
    save('secret-scan.json', {'scope': {'from': BASE, 'to': MAIN, 'new_or_changed_committed_evidence_files': len(paths)},
         'rules': {k: v.decode() for k, v in patterns.items()}, 'findings': findings,
         'result': 'no matching secret literals' if not findings else 'manual classification required',
         'limits': 'Pattern scan of committed evidence only, not proof against arbitrary encoded or unknown-format secrets; paths and public digests are not secret material. No runtime key stores accessed.'})
    assert not findings, findings
    print(json.dumps({'checks_passed': len(checks), 'evidence_files': len(paths),
                      'bindings': len(bindings), 'historical_mismatches': len(mismatches), 'secret_findings': len(findings)}))


if __name__ == '__main__':
    main()
