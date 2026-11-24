#!/usr/bin/env python3
"""Mutation check of the Omnigent product import (B1-01 trusted schema, owner decision 2026-11-23): every protection
the lab proved is removed, one at a time, in a throwaway copy of the engine, and the Omnigent unit tests must FAIL
for each (and pass on the unmodified copy). Nothing here touches Podman, a device or a secret.

  python3 -I tests/backup/omnigent_product_mutations.py [--json OUT] [--refusals | --named]

Prints one fixed line per mutation (`<id> <name>: caught|MISSED (<failures>/<tests>) [by <the failing test>]`, the run
of a mutation stops at its first failing test since 2026-11-24); exit 0 only when the baseline passes and every
mutation is caught.
`--refusals` checks instead of the list below what the module itself says no to: every `raise` and every blocker or
problem it collects is removed, one at a time (`R<line>`), and so is every operand of an `or` that decides about one
(`R<line>.<operand>`). An operand of REDUNDANT that no test needs is printed as `redundant`, with the reason.
`--named` checks only the mutations of NAMED, and each one by its own test alone (about a minute).
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
MODULE = 'woowbackup/ha_omnigent.py'
TESTS = ('tests.backup.test_ha_omnigent', 'tests.backup.test_ha_omnigent_candidate',
         'tests.backup.test_ha_omnigent_trusted', 'tests.backup.test_b1_01_guard',
         'tests.backup.test_ha_omnigent_server_volume', 'tests.backup.test_ha_omnigent_install')

# (id, protection, exact text, replacement, occurrences[, module under backup-engine/; default MODULE])
MUTATIONS = (
    ('M01', 'only TABLE DATA / SEQUENCE SET of HA restored (data-only list)',
     "        if match.group(2).startswith(('TABLE DATA ', 'SEQUENCE SET ')):\n",
     "        if True:\n", 1),
    ('M02', 'each selected entry names a trusted table/sequence once (line-break injection)',
     '    strict = tables is not None or sequences is not None\n', '    strict = False\n', 1),
    ('M03', "HA's data loaded by the role without privileges, never the superuser",
     "    load_into_new_cluster(tmp, role, ['pg_restore', '-U', RESTORE_ROLE, '--no-owner', '--no-acl', '--exit-on-error',\n"
     "                                      '--single-transaction', '-L', '/tmp/woowbk-omnigent.toc', '-d', DATABASE],\n",
     "    load_into_new_cluster(tmp, role, ['pg_restore', '-U', superuser, '--no-owner', '--no-acl', '--exit-on-error',\n"
     "                                      '--single-transaction', '-L', '/tmp/woowbk-omnigent.toc', '-d', DATABASE],\n", 1),
    ('M04', "pre-data comes from this device's schema, never HA's archive",
     "    with open(schema_dump, 'rb') as handle:\n        tmp.exec(role, ['pg_restore', '-U', superuser, '--no-owner', "
     "'--no-acl', '--exit-on-error',\n                        '--single-transaction', '--section=pre-data'",
     "    with open(data_dump, 'rb') as handle:\n        tmp.exec(role, ['pg_restore', '-U', superuser, '--no-owner', "
     "'--no-acl', '--exit-on-error',\n                        '--single-transaction', '--section=pre-data'", 1),
    ('M05', 'no DDL during the capture: live schema before == after == snapshot columns',
     '    if columns != before.columns or after != before:\n', '    if False:\n', 1),
    ('M06', 'the live revision did not move since the check (before the capture)',
     '    if before.alembic != sorted(alembic or []):\n', '    if False:\n', 1),
    ('M07', "HA's columns, sequences and types equal the trusted schema (convert)",
     '    differ = schema_differences(ha_schema, trusted)\n', '    differ = []\n', 1),
    ('M08', "the new cluster's schema equals the trusted one (after post-data and after the last write)",
     "    differ = [key for key in SIGNATURE_KEYS if found.get(key) != trusted.signature.get(key)]\n",
     '    differ = []\n', 1),
    ('M09', 'the new cluster holds no other role, setting, ALTER SYSTEM value or large object',
     '    if problems:\n        raise BackupError(\'job-failed\', f\'新的 PostgreSQL 叢集含有不應存在的內容',
     '    if False:\n        raise BackupError(\'job-failed\', f\'新的 PostgreSQL 叢集含有不應存在的內容', 1),
    ('M10', "this device's accounts are added back by the restricted role, never the superuser",
     '        loader = ha_odoo.Cluster(cluster.tmp, cluster.role, superuser=RESTORE_ROLE, log=cluster.log)\n',
     '        loader = cluster\n', 1),
    ('M11', 'test mode pauses the scheduled tasks as the restricted role',
     "        ha_odoo.Cluster(tmp, 'omni-db', superuser=RESTORE_ROLE, log=work.log).script(PAUSE_SQL, DATABASE)\n",
     '        pg.script(PAUSE_SQL, DATABASE)\n', 1),
    ('M12', 'the loader role has no privilege (NOSUPERUSER ...)',
     "f'CREATE ROLE {RESTORE_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\\n'",
     "f'CREATE ROLE {RESTORE_ROLE} LOGIN SUPERUSER;\\n'", 1),
    ('M13', 'the loader role is dropped before the export',
     "    cluster.script(f'DROP OWNED BY {RESTORE_ROLE};\\nDROP ROLE {RESTORE_ROLE};\\n', DATABASE)\n",
     '    pass\n', 1),
    ('M14', "every Quadlet secret is registered in the catalog before anything runs",
     '    require_registered_secrets(work, app)\n    adapter = work.adapter(app)\n',
     '    adapter = work.adapter(app)\n', 1),
    ('M15', 'the check names a schema difference as a blocker',
     '        if differ:\n            blockers.append(schema_blocker(differ))\n', '        pass\n', 1),
    ('M16', 'the new cluster runs with a read-only root and a noexec data volume',
     "            volumes=[(tmp.name('omni-db'), target.db_target, 'rw,noexec,nosuid,nodev')],\n"
     "            env=target.db_env, secrets=target.db_secrets, read_only_root=True)\n",
     "            volumes=[(tmp.name('omni-db'), target.db_target, 'rw')],\n"
     "            env=target.db_env, secrets=target.db_secrets, read_only_root=False)\n", 1),
    ('M17', "the runner's pi volume is this device's (never HA's)",
     '    hacommon.live_export(work, app, target.pi_volume, pi_path)\n',
     "    import shutil as _s\n    _s.copyfile(server_path, pi_path)\n", 1),
    # security review 2026-11-23 (SR-OWNER-1942) findings, fixed on the product branch:
    ('M18', "HA's answers (accounts, schedules, shares, keys, counts) re-derived on the trusted new cluster (SR-1)",
     '    require_answers(pg, found)\n', '', 1),
    ('M19', 'SEQUENCE SET entries are only bare setval calls of trusted sequences (SR-3)',
     "        require_sequence_sets(script.decode('utf-8', 'surrogateescape'), len(sets), sequences)\n",
     '        pass\n', 1),
    ('M20', "HA's pg_dump runs as an OS user unrelated to HA's server (SR-2b)",
     "['pg_dump', '-U', 'postgres', '-Fc', '-d', DATABASE], user=dump_user(ids, pg_ids),",
     "['pg_dump', '-U', 'postgres', '-Fc', '-d', DATABASE], user='postgres',", 1),
    ('M23', "HA's pg_dump uid is one the owner's id maps hold and never root or the image's postgres (SR-2b, dev-d)",
     '        if candidate in (0, *pg_ids):\n            continue\n', '', 1),
    ('M24', "HA's pg_dump uid is mapped in the owner's uid and gid maps (dev-d maps 1..55000: 65534 failed for real)",
     '        if uids is not None and (candidate not in uids or candidate not in gids):\n            continue\n', '', 1),
    ('M25', "the names in the SR-1 message are cut and without control characters (verifier, SR-4 class)",
     '                shown = hacommon.names([name])\n', '                shown = name\n', 1),
    ('M26', "every job log line stays one line without control characters: HA's PG_VERSION and backup name "
            "(secreview SR-6, shared jobs.py)",
     "        line = LOG_CONTROL_RE.sub(' ', redact(message))[:MAX_LOG_LINE]\n",
     "        line = redact(message).replace('\\r', ' ').replace('\\n', ' ')[:MAX_LOG_LINE]\n", 1,
     'woowbackup/jobs.py'),
    ('M27', "a job log line keeps its reading order: every Unicode bidirectional control becomes a space (the "
            "verifier's SR-6 gap, shared jobs.py)",
     "LOG_CONTROL_RE = re.compile(r'[\\x00-\\x1f\\x7f-\\x9f\\u2028\\u2029\\u061c\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]')\n",
     "LOG_CONTROL_RE = re.compile(r'[\\x00-\\x1f\\x7f-\\x9f\\u2028\\u2029]')\n", 1, 'woowbackup/jobs.py'),
    ('M28', "names from HA's backup reach a message without a Unicode bidirectional control (the verifier's "
            "SR-6 gap, shared hacommon)",
     "CONTROL_RE = re.compile(r'[\\x00-\\x1f\\x7f-\\x9f\\u2028\\u2029\\u061c\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]')\n",
     "CONTROL_RE = re.compile(r'[\\x00-\\x1f\\x7f-\\x9f\\u2028\\u2029]')\n", 1, 'woowbackup/hacommon.py'),
    ('M21', "HA-controlled names reach the job log and the page without control characters (SR-4, shared hacommon)",
     "    items = [CONTROL_RE.sub('?', str(item)[:60]) for item in items]\n",
     '    items = [str(item)[:60] for item in items]\n', 1, 'woowbackup/hacommon.py'),
    ('M22', "HA's rows that this device's schema refuses end with the plain message, never their values (review v5)",
     "            if DATA_REFUSED_RE.search(error.stderr or b''):\n", '            if False:\n', 1),
    # the independent verifier's gaps X7..X15 (2026-11-24): protections no unit test failed without until iteration 5
    ('M29', 'the conversion itself refuses a version that does not match, not only the check (X7)',
     "    if blocker:\n        raise BackupError('incompatible', f'Omnigent 不能搬過來：{blocker}', app=app.id)\n", '', 1),
    ('M30', "after the last write every table holds HA's rows (users this device's kept accounts too) and the revision "
            "is HA's (X8)",
     "    if differ or sorted(now_alembic or []) != sorted(found['alembic']):\n", '    if False:\n', 1),
    ('M31', 'the row counts of that final comparison (X8)',
     "    if differ or sorted(now_alembic or []) != sorted(found['alembic']):\n",
     "    if sorted(now_alembic or []) != sorted(found['alembic']):\n", 1),
    ('M32', 'the revision of that final comparison (X8)',
     "    if differ or sorted(now_alembic or []) != sorted(found['alembic']):\n", '    if differ:\n', 1),
    ('M33', 'a cluster whose stop did not end with 0 is never exported (X9)',
     "    if code != 0:\n        raise BackupError('job-failed', f'新的 PostgreSQL 叢集沒有正常關閉（結束碼 {code}）。')\n",
     '', 1),
    ('M34', 'only a cluster that pg_controldata calls "shut down" is exported (X10)',
     "    if not re.search(rb'Database cluster state:\\s+shut down\\s*$', state, re.M):\n", '    if False:\n', 1),
    ('M35', 'exactly "shut down", not "shut down in recovery" (X10)',
     "    if not re.search(rb'Database cluster state:\\s+shut down\\s*$', state, re.M):\n",
     "    if not re.search(rb'Database cluster state:\\s+shut down', state, re.M):\n", 1),
    ('M36', 'test mode asks again after its pause: no task is left active (X11)',
     "        if ha_odoo._int(pg.query_json(ACTIVE_SQL, DATABASE)):\n", '        if False:\n', 1),
    ('M37', 'every volume is checked as a restore would read it before it is packed (X13)',
     '        ha_odoo.check_volume_tar(path, ids)\n', '        pass\n', 1),
    ('M38', "the server and pi volumes too, not only the database's (X13)",
     '    for path in (db_path, server_path, pi_path):\n        ha_odoo.check_volume_tar(path, ids)\n',
     '    for path in (db_path,):\n        ha_odoo.check_volume_tar(path, ids)\n', 1),
    ('M39', "that check uses the owner's id maps (X13)",
     '        ha_odoo.check_volume_tar(path, ids)\n', '        ha_odoo.check_volume_tar(path, None)\n', 1),
    ('M40', "the capture dumps this device's schema only, never its rows (X15)",
     ' -Fc --schema-only --no-owner --no-acl ', ' -Fc --no-owner --no-acl ', 1),
    ('M41', 'the capture dumps what the exported snapshot shows (X15, the same line)',
     ' --lock-wait-timeout=15s --snapshot="$snapshot"\n', ' --lock-wait-timeout=15s\n', 1),
    ('M42', 'the capture reads the revision inside the snapshot again (the same script)',
     '[ -s "$snapdir/columns" ] && [ "$(cat "$snapdir/revision")" = ok ] || exit 22\n',
     '[ -s "$snapdir/columns" ] || exit 22\n', 1),
    ('M43', "only a snapshot id reaches pg_dump's arguments (the same script)",
     "printf '%s' \"$snapshot\" | grep -Eq '^[0-9A-Fa-f-]+$' || exit 23\n", '', 1),
    # found while closing them (2026-11-24): protections that are no refusal (--refusals covers those)
    ('M44', "HA's cluster is removed before the new cluster starts",
     "    tmp.remove('hapg')\n    tmp.remove_volume('hapg')\n    work.checkpoint()\n", '    work.checkpoint()\n', 1),
    ('M45', "the new cluster is ready when it answers on TCP, not the image's temporary server",
     '    pg.wait_ready(tcp=True, checkpoint=work.checkpoint)\n', '    pg.wait_ready(checkpoint=work.checkpoint)\n', 1),
    ('M46', "HA's dump is private to the job (0600)",
     "    with open(dump, 'xb') as handle:\n        os.fchmod(handle.fileno(), 0o600)\n",
     "    with open(dump, 'xb') as handle:\n", 1),
    ('M47', "the new cluster's export is private to the job (0600)",
     "    with open(db_path, 'xb') as handle:\n        os.fchmod(handle.fileno(), 0o600)\n",
     "    with open(db_path, 'xb') as handle:\n", 1),
    ('M48', "this device's schema dump is private to the job (0600)",
     '                os.fchmod(dest.fileno(), 0o600)\n', '', 1),
    ('M49', 'the conversion checks the space it needs before it starts a cluster',
     '    work.guard.check(2 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE)\n', '', 1),
    ('M50', 'a live account row nobody asked for is not carried',
     "        if not isinstance(row, dict) or row.get('id') not in target.own_users:\n",
     '        if not isinstance(row, dict):\n', 1),
    ('M51', "the live version is asked on the loopback address only",
     "        if parts.scheme == 'http' and parts.hostname in ('127.0.0.1', 'localhost'):\n", '        if True:\n', 1),
    ('M52', 'an error page is no live version', '    if status != 200:\n        return None\n', '', 1),
    ('M53', 'only x.y.z is a live version',
     '    return version if isinstance(version, str) and SERVER_VERSION_RE.fullmatch(version) else None\n',
     '    return version if isinstance(version, str) else None\n', 1),
)


# The test of each protection added in iteration 5: it alone must fail without the protection (--named).
OMNI, SCRIPT = 'tests.backup.test_ha_omnigent.', 'tests.backup.test_ha_omnigent_trusted.SnapshotScriptTests.'
NAMED = {ident: test for test, idents in (
    (OMNI + 'ConvertTests.test_a_version_that_does_not_match_stops_the_conversion_itself', ('M29',)),
    (OMNI + 'ConvertTests.test_counts_that_differ_stop_the_conversion', ('M30', 'M31', 'M32')),
    (OMNI + 'ConvertTests.test_a_cluster_that_did_not_stop_cleanly_is_never_exported', ('M33',)),
    (OMNI + 'ConvertTests.test_only_a_cluster_that_pg_controldata_calls_shut_down_is_exported', ('M34', 'M35')),
    (OMNI + 'ConvertTests.test_test_mode_that_left_a_task_active_stops_the_conversion', ('M36',)),
    (OMNI + 'ConvertTests.test_a_volume_podman_could_not_import_is_never_packed', ('M37', 'M38', 'M39')),
    (SCRIPT + 'test_the_dump_is_schema_only_and_reads_the_exported_snapshot', ('M40', 'M41')),
    (SCRIPT + 'test_nothing_is_dumped_when_the_snapshot_is_not_the_expected_one', ('M42', 'M43')),
    (OMNI + 'ConvertTests.test_the_whole_conversion_in_test_mode', ('M44', 'M45')),
    (OMNI + 'ConvertTests.test_what_the_job_writes_is_private_to_it', ('M46', 'M47', 'M48')),
    (OMNI + 'RefusalTests.test_the_space_check_of_the_conversion', ('M49',)),
    (OMNI + 'ConvertTests.test_a_same_named_ha_account_wins', ('M50',)),
    (OMNI + 'RefusalTests.test_a_live_version_that_cannot_be_read_is_no_version', ('M51', 'M52', 'M53')),
) for ident in idents}

# Operands that cannot decide alone because another check of the product refuses the same thing first.
REDUNDANT = {
    'entry.linkname == ARTIFACTS': 'habackup.iter_entries hands out no hard link to a folder, and nothing below a file',
    'not self.pgdata': 'none only without a data mount, and the volume comparison before it refuses that',
}


def refusals(source):
    """(id, name, the whole mutated text, why it is redundant or None) of every `raise`, every
    `blockers|problems|odd.append|insert(...)` and every operand of an `or` that is the condition of one."""
    tree, raw = ast.parse(source), source.encode('utf-8')
    starts = [0]
    for line in raw.split(b'\n'):
        starts.append(starts[-1] + len(line) + 1)
    scopes = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.ClassDef))]
    found = []

    def refuses(node):
        call = node.value if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) else None
        return isinstance(node, ast.Raise) or (
            call is not None and isinstance(call.func, ast.Attribute) and call.func.attr in ('append', 'insert')
            and isinstance(call.func.value, ast.Name) and call.func.value.id in ('blockers', 'problems', 'odd'))

    def add(number, node, replacement):
        start = starts[node.lineno - 1] + node.col_offset
        end = starts[node.end_lineno - 1] + node.end_col_offset
        inside = [s for s in scopes if s.lineno <= node.lineno <= s.end_lineno]
        scope = min(inside, key=lambda s: s.end_lineno - s.lineno).name if inside else '<module>'
        text = ' '.join(raw[start:end].decode('utf-8').split())
        mutated = (raw[:start] + replacement + raw[end:]).decode('utf-8')
        found.append((node.lineno, number, f'{scope}: {text[:100]}', mutated, REDUNDANT.get(text) if number else None))

    for node in ast.walk(tree):
        if refuses(node):
            add(0, node, b'pass')
        elif (isinstance(node, ast.If) and isinstance(node.test, ast.BoolOp) and isinstance(node.test.op, ast.Or)
              and any(refuses(inner) for item in node.body for inner in ast.walk(item))):
            for number, operand in enumerate(node.test.values, 1):
                add(number, operand, b'(False)')
    return [(f'R{line}.{number}' if number else f'R{line}', name, mutated, why)
            for line, number, name, mutated, why in sorted(found, key=lambda entry: entry[:3])]


def run_tests(root, *options, tests=TESTS):
    """The Omnigent tests in the throwaway copy `root` (tests/backup/__init__.py puts ITS backup-engine first)."""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(root / 'backup-engine'), str(root)]),
               PYTHONDONTWRITEBYTECODE='1')
    proc = subprocess.run([sys.executable, '-m', 'unittest', *options, *tests], cwd=root, env=env, capture_output=True,
                          timeout=1800)
    tail = proc.stderr.decode('utf-8', 'replace').strip().splitlines()
    ran = next((int(m.group(1)) for line in tail if (m := re.match(r'Ran (\d+) tests?', line))), 0)
    last = tail[-1] if tail else ''
    failures = sum(int(n) for n in re.findall(r'(?:failures|errors)=(\d+)', last))
    failed = [m.group(1) for line in tail if (m := re.match(r'(?:FAIL|ERROR): (\w+)', line))]
    return proc.returncode, ran, failures, list(dict.fromkeys(failed))


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--json')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--refusals', action='store_true')
    mode.add_argument('--named', action='store_true')
    args = parser.parse_args(argv)
    all_tests = tuple(dict.fromkeys(NAMED.values())) if args.named else TESTS
    modules = sorted({MODULE} | {m[5] for m in MUTATIONS if len(m) > 5})
    sources = {module: (REPO / 'backup-engine' / module).read_text(encoding='utf-8') for module in modules}
    source = sources[MODULE]
    results = []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='omni-mutation-') as directory:
        root = Path(directory)
        skip = shutil.ignore_patterns('__pycache__', '.git', 'node_modules', 'evidence', 'e2e')
        for item in REPO.iterdir():
            if item.name in ('.git', 'node_modules'):
                continue
            if item.is_dir():
                shutil.copytree(item, root / item.name, ignore=skip, symlinks=True)
            else:
                shutil.copy2(item, root / item.name)
        engine = root / 'backup-engine'
        rc, ran, failures, failed = run_tests(root, tests=all_tests)
        baseline = {'returncode': rc, 'tests': ran, 'failures': failures, 'failed': failed}
        print(f'baseline: {"pass" if rc == 0 else "FAIL"} ({failures}/{ran})', flush=True)
        listed = [m for m in MUTATIONS if m[0] in NAMED] if args.named else MUTATIONS
        for ident, name, *change in refusals(source) if args.refusals else listed:
            module = change[3] if len(change) > 3 else MODULE
            original = sources[module]
            why = None
            if args.refusals:
                mutated, why = change
            else:
                old, new, count = change[:3]
                mutated = original.replace(old, new)
                if original.count(old) != count:
                    results.append({'id': ident, 'protection': name, 'module': module, 'applied': False})
                    print(f'{ident} {name}: NOT APPLIED (pattern count {original.count(old)})', flush=True)
                    continue
            (engine / module).write_text(mutated, encoding='utf-8')
            try:
                rc, ran, failures, failed = run_tests(root, '--failfast',
                                                      tests=(NAMED[ident],) if args.named else TESTS)
            finally:
                (engine / module).write_text(original, encoding='utf-8')
            caught = rc != 0 and failures > 0
            results.append({'id': ident, 'protection': name, 'module': module, 'applied': True, 'caught': caught,
                            'failures': failures, 'tests': ran, 'failed': failed,
                            **({'redundant': why} if why and not caught else {})})
            verdict = 'caught' if caught else f'redundant, {why}' if why else 'MISSED'
            by = f' by {failed[0]}' if failed else ''
            print(f'{ident} {name}: {verdict} ({failures}/{ran}){by}', flush=True)
    ok = baseline['returncode'] == 0 and all(
        r.get('applied') and (r.get('caught') or r.get('redundant')) for r in results)
    what = 'every refusal of the module' if args.refusals else (
        'the mutations of NAMED, each by its own test alone' if args.named else 'the list MUTATIONS')
    summary = {'what': what, 'module': MODULE,
               'module_sha256': hashlib.sha256(source.encode('utf-8')).hexdigest(),
               'modules_sha256': {m: hashlib.sha256(t.encode('utf-8')).hexdigest() for m, t in sources.items()},
               'tests': list(all_tests), 'baseline': baseline, 'mutations': results, 'all_caught': ok,
               'seconds': round(time.monotonic() - started, 1)}
    if args.json:
        Path(args.json).write_text(json.dumps(summary, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    redundant = sum(1 for r in results if r.get('redundant'))
    print(f'mutation check: {"PASS" if ok else "FAIL"} ({sum(1 for r in results if r.get("caught"))}/{len(results)} caught'
          f'{f", {redundant} redundant" if redundant else ""})')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
