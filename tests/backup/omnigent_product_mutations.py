#!/usr/bin/env python3
"""Mutation check of the Omnigent product import (B1-01 trusted schema, owner decision 2026-11-23): every protection
the lab proved is removed, one at a time, in a throwaway copy of the engine, and the Omnigent unit tests must FAIL
for each (and pass on the unmodified copy). Nothing here touches Podman, a device or a secret.

  python3 -I tests/backup/omnigent_product_mutations.py [--json OUT]

Prints one fixed line per mutation (`<id> <name>: caught|MISSED (<failures>/<tests>)`); exit 0 only when the
baseline passes and every mutation is caught.
"""
import argparse
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
         'tests.backup.test_ha_omnigent_install')

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
    ('M21', "HA-controlled names reach the job log and the page without control characters (SR-4, shared hacommon)",
     "    items = [CONTROL_RE.sub('?', str(item)[:60]) for item in items]\n",
     '    items = [str(item)[:60] for item in items]\n', 1, 'woowbackup/hacommon.py'),
    ('M22', "HA's rows that this device's schema refuses end with the plain message, never their values (review v5)",
     "            if DATA_REFUSED_RE.search(error.stderr or b''):\n", '            if False:\n', 1),
)


def run_tests(root):
    """The Omnigent tests in the throwaway copy `root` (tests/backup/__init__.py puts ITS backup-engine first)."""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(root / 'backup-engine'), str(root)]),
               PYTHONDONTWRITEBYTECODE='1')
    proc = subprocess.run([sys.executable, '-m', 'unittest', *TESTS], cwd=root, env=env, capture_output=True,
                          timeout=1800)
    tail = proc.stderr.decode('utf-8', 'replace').strip().splitlines()
    ran = next((int(m.group(1)) for line in tail if (m := re.match(r'Ran (\d+) tests?', line))), 0)
    last = tail[-1] if tail else ''
    failures = sum(int(n) for n in re.findall(r'(?:failures|errors)=(\d+)', last))
    return proc.returncode, ran, failures


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--json')
    args = parser.parse_args(argv)
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
        rc, ran, failures = run_tests(root)
        baseline = {'returncode': rc, 'tests': ran, 'failures': failures}
        print(f'baseline: {"pass" if rc == 0 else "FAIL"} ({failures}/{ran})', flush=True)
        for ident, name, old, new, count, *where in MUTATIONS:
            module = where[0] if where else MODULE
            original = sources[module]
            if original.count(old) != count:
                results.append({'id': ident, 'protection': name, 'module': module, 'applied': False})
                print(f'{ident} {name}: NOT APPLIED (pattern count {original.count(old)})', flush=True)
                continue
            (engine / module).write_text(original.replace(old, new), encoding='utf-8')
            try:
                rc, ran, failures = run_tests(root)
            finally:
                (engine / module).write_text(original, encoding='utf-8')
            caught = rc != 0 and failures > 0
            results.append({'id': ident, 'protection': name, 'module': module, 'applied': True, 'caught': caught,
                            'failures': failures, 'tests': ran})
            print(f'{ident} {name}: {"caught" if caught else "MISSED"} ({failures}/{ran})', flush=True)
    ok = baseline['returncode'] == 0 and all(r.get('applied') and r.get('caught') for r in results)
    summary = {'module': MODULE, 'module_sha256': hashlib.sha256(source.encode('utf-8')).hexdigest(),
               'modules_sha256': {m: hashlib.sha256(t.encode('utf-8')).hexdigest() for m, t in sources.items()},
               'tests': list(TESTS), 'baseline': baseline, 'mutations': results, 'all_caught': ok,
               'seconds': round(time.monotonic() - started, 1)}
    if args.json:
        Path(args.json).write_text(json.dumps(summary, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    print(f'mutation check: {"PASS" if ok else "FAIL"} ({sum(1 for r in results if r.get("caught"))}/{len(results)} caught)')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
