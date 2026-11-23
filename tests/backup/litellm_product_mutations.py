#!/usr/bin/env python3
"""Mutation check of the LiteLLM product import (owner decision 2026-11-23 「決定1 做」: the lab-proven method as the
product, with the trust rules of the Omnigent import): every protection the lab proved -- and each one the product
adds -- is removed, one at a time, in a throwaway copy of the engine, and the LiteLLM unit tests must FAIL for each
(and pass on the unmodified copy). Nothing here touches Podman, a device or a secret.

  python3 -I tests/backup/litellm_product_mutations.py [--json OUT]

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
LL = 'woowbackup/ha_litellm.py'
QP = 'woowbackup/adapters/quadlet_postgres.py'
HI = 'woowbackup/haimport.py'
TESTS = ('tests.backup.test_ha_litellm', 'tests.backup.test_adapter_import_secrets',
         'tests.backup.test_ha_litellm_candidate')

# (id, protection, module, exact text, replacement, occurrences)
MUTATIONS = (
    ('M01', "HA's rows are loaded by the role without privileges, never the superuser", LL,
     "tmp.exec(role, ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-1', '-U', RESTORE_ROLE, '-d', DATABASE,",
     "tmp.exec(role, ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-1', '-U', superuser, '-d', DATABASE,", 1),
    ('M02', "HA's rows are read with this device's column list only", LL,
     "    return f'COPY {_q(schema, table)} ({_cols(columns)}) TO STDOUT'\n",
     "    return f'COPY {_q(schema, table)} TO STDOUT'\n", 1),
    ('M03', 'the loader role has no privilege (NOSUPERUSER ...)', LL,
     "    lines = [f'CREATE ROLE {RESTORE_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;']\n",
     "    lines = [f'CREATE ROLE {RESTORE_ROLE} LOGIN SUPERUSER;']\n", 1),
    ('M04', 'the loader role is dropped before the export', LL,
     "    cluster.script(f'DROP OWNED BY {RESTORE_ROLE};\\nDROP ROLE {RESTORE_ROLE};\\n', DATABASE)\n",
     '    pass\n', 1),
    ('M05', 'sequence values are set by the restricted role', LL,
     "        ha_odoo.Cluster(tmp, role, superuser=RESTORE_ROLE, log=work.log).script(script, DATABASE)\n",
     '        cluster.script(script, DATABASE)\n', 1),
    ('M06', 'no DDL during the capture: live schema before == after == snapshot columns', LL,
     '    if columns != before.columns or after != before:\n', '    if False:\n', 1),
    ('M07', 'the live migrations did not move since the check (before the capture)', LL,
     '    if before.migrations != sorted(migrations or []):\n', '    if False:\n', 1),
    ('M08', 'the live database holds no other schema (the capture would take it)', LL,
     "    if [s for s in before.signature.get('schemas') or [] if s != 'woow_platform']:\n", '    if False:\n', 1),
    ('M09', "HA's columns, sequences and types equal the trusted schema (convert)", LL,
     '    differ = schema_differences(ha_schema, trusted)\n', '    differ = []\n', 1),
    ('M10', 'the check names a schema difference as a blocker', LL,
     '        if differ:\n            blockers.append(schema_blocker(differ))\n', '        pass\n', 1),
    ('M11', "the new cluster's schema equals the trusted one (after post-data and after the last write)", LL,
     "    differ = [key for key in SIGNATURE_KEYS if found.get(key) != trusted.signature.get(key)]\n",
     '    differ = []\n', 1),
    ('M12', 'the new cluster holds no other role, setting, ALTER SYSTEM value or large object', LL,
     "    if problems:\n        raise BackupError('job-failed', f'新的 PostgreSQL 叢集含有不應存在的內容",
     "    if False:\n        raise BackupError('job-failed', f'新的 PostgreSQL 叢集含有不應存在的內容", 1),
    ('M13', "every table's row count and the migrations equal HA's", LL,
     "    if differ or now != found['migrations'] or len(expected) != len(tables):\n", '    if False:\n', 1),
    ('M14', 'the salt file must be the salt HA\'s database is bound to', LL,
     "    if binding != 'match':\n", '    if False:\n', 1),
    ('M15', 'the salt row the new database got equals the salt that moves', LL,
     "    if salt_rows != [hashlib.sha256(src.salt()).hexdigest()]:\n", '    if False:\n', 1),
    ('M16', "HA's salt becomes the converted backup's litellm-salt-key", LL,
     "            'secrets': {SALT_SECRET: salt_path},\n", "            'secrets': {},\n", 1),
    ('M17', 'the HA salt is masked in every log line', LL,
     "        jobs.mask_secret(src.salt().decode('ascii'))  # every log line, progress message and error of this job\n",
     '        pass\n', 1),
    ('M18', "HA's cluster runs with a read-only root and a noexec data volume", LL,
     "    tmp.run('hapg', image, ha_server_args(), detach=True, read_only_root=True, env={'PGDATA': HA_PGDATA},\n"
     "            volumes=[(tmp.name('hapg'), HA_PGDATA, 'rw,noexec,nosuid,nodev')])\n",
     "    tmp.run('hapg', image, ha_server_args(), detach=True, read_only_root=False, env={'PGDATA': HA_PGDATA},\n"
     "            volumes=[(tmp.name('hapg'), HA_PGDATA, 'rw')])\n", 1),
    ('M19', "HA's cluster gets every library/command setting overridden", LL,
     "        args += ['-c', setting]\n    return args + ['-c', 'event_triggers=off']\n",
     "    return args + ['-c', 'event_triggers=off']\n", 1),
    ('M20', 'the new cluster runs with a read-only root and a noexec data volume', LL,
     "            volumes=[(tmp.name('ll-db'), target.db_target, 'rw,noexec,nosuid,nodev')],\n"
     "            env=target.db_env, secrets=target.db_secrets, read_only_root=True)\n",
     "            volumes=[(tmp.name('ll-db'), target.db_target, 'rw')],\n"
     "            env=target.db_env, secrets=target.db_secrets, read_only_root=False)\n", 1),
    ('M21', 'a pulled PostgreSQL 18 must be the pinned image by content', LL,
     "    raise BackupError('job-failed', '下載的 PostgreSQL 18 映像不是預期的版本，已停止，這台的應用沒有任何變更。', app=app.id)\n",
     '    return PG18_PINNED\n', 1),
    ('M22', 'only public/woow_platform/woow schemas in HA', LL,
     "    odd = [s for s in schemas if s not in ('woow_platform', 'woow')]\n", '    odd = []\n', 1),
    ('M23', 'HA objects only a superuser creates refuse', LL,
     "    if found['superuser']:\n", '    if False:\n', 1),
    ('M24', 'a symlink (tablespace) in HA\'s cluster refuses', LL,
     '    if src.symlinks:\n', '    if False:\n', 1),
    ('M25', "state.json's LiteLLM version must be the add-on's", LL,
     '    if src.state_version is not None and expected is not None and src.state_version != expected:\n',
     '    if False:\n', 1),
    ('M26', 'table/column names are plain identifiers before any HA row is read', LL,
     '    require_names(trusted, app)\n', '    pass\n', 1),
    ('M27', 'the target reads litellm-salt-key as LITELLM_SALT_KEY', LL,
     "                or len(salt_specs) != 1 or f'target={SALT_ENV}' not in salt_specs[0].split(',')[1:]\n", '', 1),
    ('M28', 'the converted dump is read in full once', LL,
     "        tmp.exec('ll-db', ['pg_restore', '-f', '/dev/null'], user='postgres', input=handle, timeout=DUMP_TIMEOUT,\n"
     "                 max_output=1024 * 1024)\n", '        pass\n', 1),
    ('M29', 'the apps that use LiteLLM keys are named (option A)', LL,
     '                if _uses_litellm_text(text):\n', '                if False:\n', 1),
    ('M30', 'pre-data and post-data come from the trusted archive', LL,
     "    with open(schema_dump, 'rb') as handle:\n        tmp.exec(role, ['pg_restore', '-U', superuser, '--no-owner', "
     "'--no-acl', '--exit-on-error',\n                        '--single-transaction', '--section=post-data'",
     "    with open(schema_dump, 'rb') as handle:\n        tmp.exec(role, ['pg_restore', '-U', superuser, '--no-owner', "
     "'--no-acl', '--exit-on-error',\n                        '--single-transaction', '--section=data'", 1),
    ('A01', 'a converted secret must be one the catalog declares', QP,
     "        if not set(replaced) <= {s['name'] for s in app.secrets}:\n", '        if False:\n', 1),
    ('A02', 'a converted secret is one small regular file', QP,
     '        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= MAX_SECRET_BYTES:\n', '        if False:\n', 1),
    ('A03', 'the conversion hands its secrets to import_manifest', HI,
     "ITEM_KEYS = ('volumes', 'postgres', 'dirs', 'secrets')", "ITEM_KEYS = ('volumes', 'postgres', 'dirs')", 1),
    # Security review 2026-11-23 (tests/backup/evidence/litellm-product-security-review-20261123): SR-1..SR-5.
    ('M34', "every session in HA's cluster sends the pinned client options (SR-1/SR-2)", LL,
     "    cluster = ha_odoo.Cluster(HaSessions(tmp, 'hapg'), 'hapg', log=work.log)\n",
     "    cluster = ha_odoo.Cluster(tmp, 'hapg', log=work.log)\n", 1),
    ('M35', "the superuser's sessions fire no event trigger and load no preload library (SR-3)", LL,
     "HA_SUPERUSER_OPTIONS = HA_SESSION_OPTIONS + ' -c session_preload_libraries= -c event_triggers=off'\n",
     "HA_SUPERUSER_OPTIONS = HA_SESSION_OPTIONS\n", 1),
    ('M36', "HA's server starts with event triggers off (SR-3)", LL,
     "    return args + ['-c', 'event_triggers=off']\n", "    return args\n", 1),
    ('M37', "_prisma_migrations is read only as an ordinary table (SR-1)", LL,
     "MIGRATIONS_TABLE_SQL = (\"SELECT to_json(coalesce((SELECT c.relkind = 'r' FROM pg_catalog.pg_class c \"\n",
     "MIGRATIONS_TABLE_SQL = (\"SELECT to_json(coalesce((SELECT true FROM pg_catalog.pg_class c \"\n", 1),
    ('M38', "backup_label/tablespace_map never reach HA's volume (SR-4)", LL,
     "                src.recovery_files += 1  # never reaches the volume (SR-4); the verdict refuses\n"
     "                continue\n",
     "                src.recovery_files += 1  # never reaches the volume (SR-4); the verdict refuses\n", 1),
    ('M39', "backup_label/tablespace_map refuse (SR-4)", LL,
     "    if src.recovery_files:\n", "    if False:\n", 1),
    ('M40', "HA's stored proxy settings are named in the check (SR-5)", LL,
     "    stored_line = stored_settings_line(settings)\n    if stored_line:\n        warnings.append(stored_line)\n",
     "    stored_line = None\n", 1),
    ('M41', "HA's stored proxy settings are named in the import notes (SR-5)", LL,
     "    stored_line = stored_settings_line(data.get('stored_settings'))\n"
     "    if stored_line:\n        notes.append(stored_line)\n",
     "", 1),
    ('M42', "stored settings that load and run code refuse in the check (SR-6)", LL,
     "    hooks = stored_hooks_blocker(settings)\n    if hooks:\n        blockers.append(hooks)\n", "", 1),
    ('M43', "stored settings that load and run code stop the conversion first (SR-6)", LL,
     "    if hooks:\n        raise BackupError('incompatible', f'LiteLLM 不能搬過來：{hooks}', app=app.id)\n", "", 1),
    ('M44', "a callback with a dot in its name is a module load (SR-6)", LL,
     "[f'litellm_settings 回呼 {c}'[:60] for c in callbacks if '.' in c]", "[]", 1),
)


def run_tests(root):
    """The LiteLLM tests in the throwaway copy `root` (tests/backup/__init__.py puts ITS backup-engine first)."""
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
    sources = {name: (REPO / 'backup-engine' / name).read_text(encoding='utf-8') for name in (LL, QP, HI)}
    results = []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='litellm-mutation-') as directory:
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
        for ident, name, module, old, new, count in MUTATIONS:
            source = sources[module]
            if source.count(old) != count:
                results.append({'id': ident, 'protection': name, 'module': module, 'applied': False})
                print(f'{ident} {name}: NOT APPLIED (pattern count {source.count(old)})', flush=True)
                continue
            (engine / module).write_text(source.replace(old, new), encoding='utf-8')
            rc, ran, failures = run_tests(root)
            (engine / module).write_text(source, encoding='utf-8')
            caught = rc != 0 and failures > 0
            results.append({'id': ident, 'protection': name, 'module': module, 'applied': True, 'caught': caught,
                            'failures': failures, 'tests': ran})
            print(f'{ident} {name}: {"caught" if caught else "MISSED"} ({failures}/{ran})', flush=True)
    ok = baseline['returncode'] == 0 and all(r.get('applied') and r.get('caught') for r in results)
    summary = {'modules': {name: hashlib.sha256(text.encode('utf-8')).hexdigest() for name, text in sources.items()},
               'tests': list(TESTS), 'baseline': baseline, 'mutations': results, 'all_caught': ok,
               'seconds': round(time.monotonic() - started, 1)}
    if args.json:
        Path(args.json).write_text(json.dumps(summary, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    print(f'mutation check: {"PASS" if ok else "FAIL"} ({sum(1 for r in results if r.get("caught"))}/{len(results)} caught)')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
