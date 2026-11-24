#!/usr/bin/env python3
"""Mutation check of the LiteLLM product import (owner decision 2026-11-23 「決定1 做」: the lab-proven method as the
product, with the trust rules of the Omnigent import): each protection listed in MUTATIONS is removed, one place at a
time, in a throwaway copy of the engine, and the LiteLLM unit tests must FAIL for each (and pass on the unmodified
copy). The list is what the lane, the security review and the lane verifiers named, not a proof that no other line
matters: the verifier's own 26 removals of 2026-11-24 found 16 that no test noticed (N01..N34 here, each with its
test). The catalog-suggest mutations (owner decision 2026-11-23 23:28: LiteLLM's health checks wait 600 s, every other
app keeps its limit; and the draft the import can fill) run tests.backup.test_suggest instead. Nothing here touches
Podman, a device or a secret.

  python3 -I tests/backup/litellm_product_mutations.py [--json OUT] [--only ID,ID]

Prints one fixed line per mutation (`<id> <name>: caught|MISSED (<failures>/<tests>)`); exit 0 only when the
baseline passes and every mutation is caught. A mutation's run stops at its first failing test (`-f`: 1 failure is
enough), the baseline runs every test.
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
SG = 'woowbackup/suggest.py'
TESTS = ('tests.backup.test_ha_litellm', 'tests.backup.test_adapter_import_secrets',
         'tests.backup.test_ha_litellm_candidate')
SUGGEST_TESTS = ('tests.backup.test_suggest',)

# (id, protection, module, exact text, replacement, occurrences[, test modules (default TESTS)])
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
    # one place each: the two calls, and what the comparison covers (until 2026-11-24 one entry disabled all three)
    ('M11', "the new cluster's schema equals the trusted one after the post-data section", LL,
     "    require_schema(cluster, trusted, 'restored')\n", '    pass\n', 1),
    ('M11b', 'every part of the schema signature is compared', LL,
     "    differ = [key for key in SIGNATURE_KEYS if found.get(key) != trusted.signature.get(key)]\n",
     "    differ = [key for key in SIGNATURE_KEYS[:8] if found.get(key) != trusted.signature.get(key)]\n", 1),
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
     # the same removal as before; the text now names its line because the trusted re-check (M55) repeats it
     "    settings = stored_settings(cluster, ha_schema)\n    hooks = stored_hooks_blocker(settings)\n"
     "    if hooks:\n        raise BackupError('incompatible', f'LiteLLM 不能搬過來：{hooks}', app=app.id)\n",
     "    settings = stored_settings(cluster, ha_schema)\n", 1),
    ('M44', "a callback with a dot in its name is a module load (SR-6)", LL,
     "[f'litellm_settings 回呼 {c}'[:60] for c in callbacks if '.' in c]", "[]", 1),
    # Option A, iteration 2: the Pi agent provider list (pi-web / Omnigent's runner models.json).
    ('M45', 'an app whose Pi agent provider list points at this LiteLLM is named (option A)', LL,
     " or pi_agent_uses_litellm(work, other, quadlets))\n", ")\n", 1),
    ('M46', "only a provider at this device's LiteLLM counts, not any provider (option A)", LL,
     "            if isinstance(value, str) and value.strip() and LITELLM_URL_RE.search(value.strip()[:2048]):\n",
     "            if isinstance(value, str) and value.strip():\n", 1),
    # Real attempt 7: HA's sessions (search_path=pg_catalog, SR-1) and this device's rendered enum types differently.
    ('M47', 'every columns/signature read pins search_path=pg_catalog (all sides render names alike)', LL,
     "PIN_SEARCH_PATH = 'SET search_path = pg_catalog; '\n", "PIN_SEARCH_PATH = ''\n", 1),
    # Review iteration 2: the rest of the vendor's code-loading keys, fail closed, the trusted re-check (SR-8).
    ('M48', 'a stored-settings answer over the limit or timed out refuses (fail closed)', LL,
     "    except BackupError:\n        return dict(UNREADABLE)\n", "    except BackupError:\n        return None\n", 1),
    ('M49', 'a stored-settings answer that is not an object refuses (fail closed)', LL,
     "    if not isinstance(found, dict):\n        return dict(UNREADABLE)\n",
     "    if not isinstance(found, dict):\n        return None\n", 1),
    ('M50', 'an unreadable answer is a blocker', LL,
     "    if found and found.get('unreadable'):\n", "    if False:\n", 1),
    ('M51', 'the nested code places count as hooks', LL,
     "names(found.get('hooks')) + names(found.get('nested'))", "names(found.get('hooks'))", 1),
    ('M52', 'router_settings.plugins is asked (not in the vendor list)', LL,
     "    ('router_settings', 'plugins', f'lax $.plugins[*] ? ({_TEXT})'),\n", "", 1),
    ('M53', 'a dotted guardrail callback is asked', LL,
     "    ('litellm_settings', 'guardrails', f'lax $.guardrails[*].*.callbacks[*] ? ({_TEXT} && @ like_regex \"[.]\")'),\n",
     "", 1),
    ('M54', 'a string-form callbacks value is asked', LL,
     "jsonb_typeof(c.param_value -> 'callbacks') = 'string'", "false", 1),
    ('M55', 'the conversion decides again in the new cluster (SR-8)', LL,
     "    settings = stored_settings(pg, trusted)\n    hooks = stored_hooks_blocker(settings)\n"
     "    if hooks:\n        raise BackupError('incompatible', f'LiteLLM 不能搬過來：{hooks}', app=app.id)\n", "", 1),
    ('M57', 'a dotted callback is found by the query, however many plain names come first', LL,
     "AND strpos(v.value, '.') > 0\"", "AND false\"", 1),
    ('M58', 'a custom secret manager path is asked (it loads a .py file at every start)', LL,
     "    ('general_settings', 'custom_secret_manager',\n"
     "     f'lax $.key_management_settings.custom_secret_manager ? ({_TEXT})'),\n", "", 1),
    ('M56', "the import notes name what moved, not what HA's cluster said (SR-8)", LL,
     "    settings = stored_settings(pg, trusted)\n    hooks = stored_hooks_blocker(settings)\n",
     "    moved = stored_settings(pg, trusted)\n    hooks = stored_hooks_blocker(moved)\n", 1),
    # The lane verifier's own removals (2026-11-24) that no unit test noticed, by the verifier's ids.
    ('N01', 'a version the check refuses never converts', LL,
     "    if blocker:\n        raise BackupError('incompatible', f'LiteLLM 不能搬過來：{blocker}', app=app.id)\n", '', 1),
    ('N09', "the new cluster's major is this device's", LL,
     '    if type(major) is not int or major != target_major:\n', '    if False:\n', 1),
    ('N10', 'an empty converted dump is refused', LL, '    if dump.stat().st_size == 0:\n', '    if False:\n', 1),
    ('N11', "HA's cluster is opened by PostgreSQL 18 only", LL, '    if major != HA_PG_MAJOR:\n', '    if False:\n', 1),
    ('N12', "the conversion's space is checked before HA's cluster starts", LL,
     '    work.guard.check(3 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE)\n', '    pass\n', 1),
    ('N12b', "that space is three times HA's cluster and the write-ahead allowance", LL,
     '    work.guard.check(3 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE)\n',
     '    work.guard.check(2 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE)\n', 1),
    ('N14', 'the salt file is a regular file', LL,
     "            if entry.kind != 'file' or entry.size > MAX_SALT_FILE or salts > 1:\n",
     '            if entry.size > MAX_SALT_FILE or salts > 1:\n', 1),
    ('N14b', 'the salt file is at most 1024 bytes', LL,
     "            if entry.kind != 'file' or entry.size > MAX_SALT_FILE or salts > 1:\n",
     "            if entry.kind != 'file' or salts > 1:\n", 1),
    ('N14c', 'a second salt file refuses', LL,
     "            if entry.kind != 'file' or entry.size > MAX_SALT_FILE or salts > 1:\n",
     "            if entry.kind != 'file' or entry.size > MAX_SALT_FILE:\n", 1),
    ('N16', "the new cluster's schema equals the trusted one after the last write", LL,
     "    require_schema(pg, trusted, 'loaded')\n", '    pass\n', 1),
    ('N18', "the schema snapshot's migrations are the ones the check saw (the script inside litellm-postgres)", LL,
     '[ -s "$snapdir/columns" ] && [ "$(cat "$snapdir/revision")" = ok ] || exit 22',
     '[ -s "$snapdir/columns" ] || exit 22', 1),
    ('N19', "the new cluster holds HA's columns before any row is loaded", LL,
     "    if _columns(cluster.query_json(COLUMNS_SQL, DATABASE), '新的 PostgreSQL 叢集') != ha_columns:\n",
     '    if False:\n', 1),
    ('N21', 'an entry with a volume (the cold draft) is refused', LL,
     "app.postgres[0].get('scope', 'database') != 'database' or app.volumes\n                or app.data_dirs):\n",
     "app.postgres[0].get('scope', 'database') != 'database'\n                or app.data_dirs):\n", 1),
    ('N21b', 'an entry with a host directory is refused', LL,
     "app.postgres[0].get('scope', 'database') != 'database' or app.volumes\n                or app.data_dirs):\n",
     "app.postgres[0].get('scope', 'database') != 'database' or app.volumes):\n", 1),
    ('N21c', 'a whole-instance entry is refused', LL,
     "        if (len(app.postgres) != 1 or app.postgres[0].get('scope', 'database') != 'database' or app.volumes\n",
     '        if (len(app.postgres) != 1 or app.volumes\n', 1),
    ('N21d', 'an entry with two databases is refused', LL,
     "        if (len(app.postgres) != 1 or app.postgres[0].get('scope', 'database') != 'database' or app.volumes\n",
     "        if (not app.postgres or app.postgres[0].get('scope', 'database') != 'database' or app.volumes\n", 1),
    ('N28', "HA's database must have the woow_platform schema", LL,
     "    if odd or 'woow_platform' not in schemas:\n", '    if odd:\n', 1),
    ('N29', "this device's PostgreSQL major must be known", LL,
     '    if target_major is None or not 13 <= target_major < HA_PG_MAJOR + 1:\n',
     '    if target_major is not None and not 13 <= target_major < HA_PG_MAJOR + 1:\n', 1),
    ('N29b', "this device's PostgreSQL major is not newer than HA's", LL,
     '    if target_major is None or not 13 <= target_major < HA_PG_MAJOR + 1:\n',
     '    if target_major is None or not 13 <= target_major:\n', 1),
    ('N29c', "this device's PostgreSQL major is at least 13", LL,
     '    if target_major is None or not 13 <= target_major < HA_PG_MAJOR + 1:\n',
     '    if target_major is None or not target_major < HA_PG_MAJOR + 1:\n', 1),
    ('N30', 'the check names ChatGPT sign-ins', LL,
     "    if ha_odoo._int((detail or {}).get('chatgpt_accounts')):\n        warnings.append(",
     '    if False:\n        warnings.append(', 1),
    ('N32', "HA's staged rows leave the disk as they are loaded", LL,
     '        os.unlink(path)\n        work.checkpoint()\n    if sequences:\n',
     '        work.checkpoint()\n    if sequences:\n', 1),
    ('N33', 'a new database without the salt row is refused', LL,
     '    if salt_rows != [hashlib.sha256(src.salt()).hexdigest()]:\n',
     '    if salt_rows and salt_rows != [hashlib.sha256(src.salt()).hexdigest()]:\n', 1),
    ('N34', "the check removes HA's cluster before it reads this device", LL,
     "    tmp.remove('hapg')\n    tmp.remove_volume('hapg')\n    blockers, warnings = verdict(",
     '    blockers, warnings = verdict(', 1),
    ('N34b', "the conversion removes HA's cluster before the new one starts", LL,
     "    tmp.remove('hapg')\n    tmp.remove_volume('hapg')\n    work.checkpoint()\n\n    work.log('建立新的",
     "    work.checkpoint()\n\n    work.log('建立新的", 1),
    ('N35', 'the refusal of another mode says what to choose and where', LL,
     "請到「應用設定」掃描，在 LiteLLM 的草稿選「單一資料庫」並安裝，'\n", "'\n", 1),
    # The table digest the suggested entry has: the import compares nothing, both rollbacks compare (test_adapter_...).
    ('D01', 'a backup without the digest is a warning before the restore, never a refusal', QP,
     "            add('digests-missing', 'warn',", "            add('digests-missing', 'fail',", 1),
    ('D02', "a rollback compares this device's own rows", QP,
     "            result.update(before=before, after=after['summary'], match=after['digest'] == before_digest)\n",
     "            result.update(before=before, after=after['summary'], match=True)\n", 1),
    # Readiness limit (owner decision 2026-11-23 23:28): LiteLLM 600 s, every other app unchanged.
    ('M59', "LiteLLM's drafted health checks wait 600 s (no per-app limit)", SG,
     "HEALTH_TIMEOUTS = {'litellm': 600}\n", "HEALTH_TIMEOUTS = {}\n", 1, SUGGEST_TESTS),
    ('M60', "LiteLLM's limit is 600 s, not the generic 300 s", SG,
     "HEALTH_TIMEOUTS = {'litellm': 600}\n", "HEALTH_TIMEOUTS = {'litellm': 300}\n", 1, SUGGEST_TESTS),
    ('M61', 'a new draft uses the per-app limit', SG,
     "        timeout = HEALTH_TIMEOUTS.get(app['id'])\n", '        timeout = None\n', 1, SUGGEST_TESTS),
    ('M62', 'every other app keeps the generic 300 s / 180 s', SG,
     '            timeout = 300 if len(containers) >= 3 or any(self._database(c) for c in containers) else 180\n',
     '            timeout = 600\n', 1, SUGGEST_TESTS),
    ('M63', "the draft of an installed LiteLLM entry raises a shorter limit", SG,
     "            raised = raise_health_timeouts(app['id'], variant['entry']) or raised\n", '', 1, SUGGEST_TESTS),
    ('M64', 'only the listed apps are raised', SG,
     '    limit = HEALTH_TIMEOUTS.get(app_id)\n', '    limit = 600\n', 1, SUGGEST_TESTS),
    ('M65', "a check without a limit (the catalog's 60 s) is raised too", SG,
     "        current = item.get('timeout_seconds', 60)\n", "        current = item.get('timeout_seconds', 600)\n", 1,
     SUGGEST_TESTS),
    ('M66', 'a limit already at 600 s is left alone (no note)', SG,
     '        if type(current) is int and current < limit:\n', '        if type(current) is int and current <= limit:\n',
     1, SUGGEST_TESTS),
    ('M67', 'the draft says what it raised (health-timeout note)', SG,
     "        if raised:\n            limit = HEALTH_TIMEOUTS[app['id']]\n",
     "        if False:\n            limit = HEALTH_TIMEOUTS[app['id']]\n", 1, SUGGEST_TESTS),
    # The draft the import can fill as it is (lane verifier 2026-11-24: a new draft was cold mode, which it refuses).
    ('S01', 'a new LiteLLM draft is the single-database mode', SG,
     "PREFERRED_MODES = {'litellm': 'database'}\n", 'PREFERRED_MODES = {}\n', 1, SUGGEST_TESTS),
    ('S02', "an installed entry's mode is never switched", SG,
     '        elif installed is None:\n', '        elif True:\n', 1, SUGGEST_TESTS),
    ('S03', 'a mode that cannot be installed is not preselected', SG,
     "        if not any(v['id'] == preferred and v['valid'] for v in variants):\n",
     "        if not any(v['id'] == preferred for v in variants):\n", 1, SUGGEST_TESTS),
    ('S04', 'the draft of another installed mode says what to choose for an import', SG,
     "            app['notes'].append(_warn('import-mode', f'已安裝的應用設定不是",
     "            app['skipped'].append(_warn('import-mode', f'已安裝的應用設定不是", 1, SUGGEST_TESTS),
    ('S05', "LiteLLM's drafted health check asks for readiness", SG,
     "READY_PATHS = {('litellm', '/health/liveliness'): '/health/readiness'}\n", 'READY_PATHS = {}\n', 1,
     SUGGEST_TESTS),
    ('S06', "the package's settings file stays in the draft", SG,
     "PACKAGE_CONFIGS = {'litellm': ('.config/litellm/litellm.env',)}\n", 'PACKAGE_CONFIGS = {}\n', 1, SUGGEST_TESTS),
    ('S07', 'a settings file the owner does not have is not proposed', SG,
     "            if isinstance(state, dict) and state.get('type') == 'file':\n                add(rel, state.get('mode'), 'env')\n"
     '        return result\n',
     "            if isinstance(state, dict):\n                add(rel, state.get('mode'), 'env')\n        return result\n", 1,
     SUGGEST_TESTS),
    ('S08', 'a kept table digest takes the form the chosen mode needs', SG,
     "        kept = [digest_for_mode(item, installed, entry) for item in json.loads(json.dumps(installed['verify']))]\n",
     "        kept = json.loads(json.dumps(installed['verify']))\n", 1, SUGGEST_TESTS),
    ('S09', "the changed digest keeps the installed check's id, label and exclusions", SG,
     "    return {**own, 'id': item.get('id'), **{key: item[key] for key in ('label', 'exclude_tables') if key in item}}\n",
     '    return dict(own)\n', 1, SUGGEST_TESTS),
    ('S10', 'a digest that fits the mode is left alone', SG,
     "        if container not in exported.values():\n            return item\n", '', 1, SUGGEST_TESTS),
)


def run_tests(root, tests=TESTS, failfast=True):
    """The unit tests `tests` in the throwaway copy `root` (tests/backup/__init__.py puts ITS backup-engine first)."""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(root / 'backup-engine'), str(root)]),
               PYTHONDONTWRITEBYTECODE='1')
    proc = subprocess.run([sys.executable, '-m', 'unittest', *(['-f'] if failfast else []), *tests], cwd=root, env=env,
                          capture_output=True, timeout=1800)
    tail = proc.stderr.decode('utf-8', 'replace').strip().splitlines()
    ran = next((int(m.group(1)) for line in tail if (m := re.match(r'Ran (\d+) tests?', line))), 0)
    last = tail[-1] if tail else ''
    failures = sum(int(n) for n in re.findall(r'(?:failures|errors)=(\d+)', last))
    return proc.returncode, ran, failures


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--json')
    parser.add_argument('--only', help='comma-separated mutation ids (a subset; the baseline always runs)')
    args = parser.parse_args(argv)
    only = set(args.only.split(',')) if args.only else None
    sources = {name: (REPO / 'backup-engine' / name).read_text(encoding='utf-8') for name in (LL, QP, HI, SG)}
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
        rc, ran, failures = run_tests(root, TESTS + SUGGEST_TESTS, failfast=False)
        baseline = {'returncode': rc, 'tests': ran, 'failures': failures}
        print(f'baseline: {"pass" if rc == 0 else "FAIL"} ({failures}/{ran})', flush=True)
        for ident, name, module, old, new, count, *tests in MUTATIONS:
            tests = tests[0] if tests else TESTS
            if only is not None and ident not in only:
                continue
            source = sources[module]
            if source.count(old) != count:
                results.append({'id': ident, 'protection': name, 'module': module, 'applied': False})
                print(f'{ident} {name}: NOT APPLIED (pattern count {source.count(old)})', flush=True)
                continue
            (engine / module).write_text(source.replace(old, new), encoding='utf-8')
            rc, ran, failures = run_tests(root, tests)
            (engine / module).write_text(source, encoding='utf-8')
            caught = rc != 0 and failures > 0
            results.append({'id': ident, 'protection': name, 'module': module, 'applied': True, 'caught': caught,
                            'failures': failures, 'tests': ran, 'test_modules': list(tests)})
            print(f'{ident} {name}: {"caught" if caught else "MISSED"} ({failures}/{ran})', flush=True)
    ok = baseline['returncode'] == 0 and all(r.get('applied') and r.get('caught') for r in results)
    summary = {'modules': {name: hashlib.sha256(text.encode('utf-8')).hexdigest() for name, text in sources.items()},
               'tests': list(TESTS + SUGGEST_TESTS), 'baseline': baseline, 'mutations': results, 'all_caught': ok,
               'subset': sorted(only) if only is not None else None,
               'seconds': round(time.monotonic() - started, 1)}
    if args.json:
        Path(args.json).write_text(json.dumps(summary, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    print(f'mutation check: {"PASS" if ok else "FAIL"} ({sum(1 for r in results if r.get("caught"))}/{len(results)} caught)')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
