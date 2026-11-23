#!/usr/bin/env python3
"""Public evidence JSON for one real Odoo/n8n attempt on dev-c (committed next to the earlier attempts).

  python3 -I odoo_n8n_evidence.py driver  --results DIR  --out FILE --label NAME --command TEXT --rc N --elapsed S
                                          --stdout FILE --source-commit HASH --engine-sha256 HASH
  python3 -I odoo_n8n_evidence.py capture --comparison FILE --out FILE ... (same attempt fields)

Only fixed status lines (PASS/FAIL and the check name), counts and the already-sanitised row/diagnosis summaries are
copied; check details, logs and private files stay in the private evidence folder. Commercial acceptance stays
"not-complete": one lane's lab attempt never completes the commercial end-to-end by itself.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

# Anything that looks like a credential in a copied string fails the build instead of being published.
SUSPICIOUS = re.compile(r'(?i)(pass(word)?|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S{6,}'
                        r'|-----BEGIN|[A-Z0-9]{4}(-[A-Z0-9]{4}){6}')


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def pick(doc, keys):
    return {k: doc.get(k) for k in keys if k in doc} if isinstance(doc, dict) else None


def driver_sections(results_dir):
    d = Path(results_dir)
    results = load(d / 'results.json')
    out = {'passed': results['passed'], 'failed': results['failed'],
           'status_lines': [f'{"PASS" if r["ok"] else "FAIL"} {r["check"]}' for r in results['results']]}
    if (d / 'arm-compare.json').exists():
        compare = load(d / 'arm-compare.json')
        section = pick(compare, ('schema_version', 'status', 'source_tables', 'target_tables', 'identical',
                                 'rows_differ', 'content_differs', 'missing', 'added', 'unverified_tables',
                                 'requires_row_evidence'))
        rows = compare.get('row_evidence')
        if isinstance(rows, dict):
            section['row_evidence'] = pick(rows, ('status', 'error_type', 'source_capture_run', 'archive_sha256',
                                                  'binding_ok', 'binding', 'restore_started_utc', 'captured_at',
                                                  'cron_log', 'tables_with_row_events',
                                                  'tables_outside_row_evidence', 'explained_tables', 'all_explained',
                                                  'summary', 'events'))
        out['armcompare'] = section
    if (d / 'capture-compare.json').exists():
        compare = load(d / 'capture-compare.json')
        section = pick(compare, ('schema_version', 'status', 'source_tables', 'target_tables', 'identical', 'changed',
                                 'missing', 'added', 'unverified_tables'))
        rows = compare.get('row_evidence')
        if isinstance(rows, dict):
            section['row_evidence'] = pick(rows, ('status', 'error_type', 'source_capture_run', 'archive_sha256',
                                                  'restore_started_utc', 'captured_at', 'cron_log',
                                                  'tables_with_row_events', 'tables_outside_row_evidence',
                                                  'explained_tables', 'all_explained', 'summary', 'events'))
        out['capcompare'] = section
    if (d / 'n8n-diagnosis.json').exists():
        out['n8n_diagnosis'] = pick(load(d / 'n8n-diagnosis.json'),
                                    ('login', 'listing', 'process_samples', 'npm_outdated_seen', 'n8n_packages',
                                     'n8n_community_nodes_checked', 'n8n_community_error_type',
                                     'n8n_community_error_code', 'local_probe_seconds', 'n8n_community_probe'))
    if (d / 'leaks.json').exists():
        leaks = load(d / 'leaks.json')
        out['leak_scan'] = {'files_scanned': leaks.get('scanned'), 'journal_bytes': leaks.get('journal_bytes'),
                            'hits': len(leaks.get('hits') or {})}
    return out


def capture_sections(comparison):
    doc = load(comparison)
    out = pick(doc, ('status', 'acceptance', 'run_id', 'schema_version', 'source_vs_ha_fingerprint',
                     'restore_start_utc', 'runtime_wait_seconds', 'cron_log', 'limits'))
    out['edges'] = {name: pick(edge, ('rules', 'ok', 'other_tables_differ', 'summary', 'events'))
                    for name, edge in (doc.get('edges') or {}).items()}
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('kind', choices=('driver', 'capture'))
    parser.add_argument('--results')
    parser.add_argument('--comparison')
    parser.add_argument('--out', required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--command', required=True)
    parser.add_argument('--rc', type=int, required=True)
    parser.add_argument('--elapsed', type=int, required=True)
    parser.add_argument('--stdout', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--engine-sha256', required=True)
    parser.add_argument('--started-utc', required=True)
    parser.add_argument('--private', required=True, help='private evidence folder (path only)')
    parser.add_argument('--note', action='append', default=[])
    args = parser.parse_args()
    body = driver_sections(args.results) if args.kind == 'driver' else capture_sections(args.comparison)
    doc = {'schema_version': 1, 'attempt': args.label, 'kind': args.kind, 'device': 'woowbk-dev-c (lab; network none, '
           'no published ports)', 'started_utc': args.started_utc, 'source_commit': args.source_commit,
           'engine_files_sha256': args.engine_sha256, 'command': args.command, 'exit_code': args.rc,
           'elapsed_seconds': args.elapsed, 'stdout_sha256': sha256_file(args.stdout),
           'private_evidence': args.private, **body, 'notes': args.note,
           'commercial_acceptance': 'not-complete'}
    text = json.dumps(doc, ensure_ascii=False, indent=1)
    if SUSPICIOUS.search(text):
        print('refused: a copied value looks like a credential', file=sys.stderr)
        return 2
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'x', encoding='utf-8') as handle:   # never overwrite an earlier attempt
        handle.write(text + '\n')
    print(json.dumps({'written': str(path), 'passed': body.get('passed'), 'failed': body.get('failed'),
                      'status': body.get('status')}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
