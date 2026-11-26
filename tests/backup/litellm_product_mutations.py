#!/usr/bin/env python3
"""Mutation check of the LiteLLM product import (owner decision 2026-11-23 「決定1 做」: the lab-proven method as the
product, with the trust rules of the Omnigent import): each protection listed in MUTATIONS is removed, one place at a
time, in a throwaway copy of the engine, and the LiteLLM unit tests must FAIL for each (and pass on the unmodified
copy). The list is what the lane, the security review and the lane verifiers named, not a proof that no other line
matters: the verifier's own 26 removals of 2026-11-24 found 16 that no test noticed (all 26 are N01..N34 here). The
catalog-suggest mutations (owner decision 2026-11-23 23:28: LiteLLM's health checks wait 600 s, every other
app keeps its limit; and the draft the import can fill) run tests.backup.test_suggest instead. Nothing here touches
Podman, a device or a secret.

  python3 -I tests/backup/litellm_product_mutations.py [--json OUT] [--only ID,ID]

Prints one fixed line per mutation (`<id> <name>: caught|MISSED (<failures>/<tests>)`); exit 0 only when the
baseline passes, every mutation is caught and no control (CONTROLS: a changed comment) is noticed. A mutation's run stops
at its first failing test (`-f`: 1 failure is enough), the baseline and the controls run every test.
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
    ('M01', ("HA's rows are loaded by the role without privileges, never the "
       'superuser'), LL,
     ("'-v', 'ON_ERROR_STOP=1', '-U', RESTORE_ROLE, '-d', DATABASE, '-f', "
       "'-'],"),
     "'-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', DATABASE, '-f', '-'],", 1),
    ('M02', "HA's rows are read with this device's column list only", LL,
     "    return f'COPY {_q(schema, table)} ({_cols(columns)}) TO STDOUT'\n",
     "    return f'COPY {_q(schema, table)} TO STDOUT'\n", 1),
    ('M03', 'the loader role has no privilege (NOSUPERUSER ...)', LL,
     ("    lines = [f'CREATE ROLE {RESTORE_ROLE} LOGIN NOSUPERUSER "
       "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;']\n"),
     "    lines = [f'CREATE ROLE {RESTORE_ROLE} LOGIN SUPERUSER;']\n", 1),
    ('M04', 'the loader role is dropped before the export', LL,
     ("    cluster.script(f'DROP OWNED BY {RESTORE_ROLE};\\nDROP ROLE "
       "{RESTORE_ROLE};\\n', DATABASE)\n"),
     '    pass\n', 1),
    ('M05', 'sequence values are set by the restricted role', LL,
     ('        ha_odoo.Cluster(tmp, role, superuser=RESTORE_ROLE, '
       'log=work.log).script(script, DATABASE)\n'),
     '        cluster.script(script, DATABASE)\n', 1),
    ('M06', ("no DDL during the capture: the snapshot's columns are the live ones "
       'before it'), LL,
     '    if columns != before.columns or after != before:\n',
     '    if after != before:\n', 1),
    ('M06b', 'no DDL during the capture: the live schema after it is the one before', LL,
     '    if columns != before.columns or after != before:\n',
     '    if columns != before.columns:\n', 1),
    ('M07', 'the live migrations did not move since the check (before the capture)', LL,
     '    if before.migrations != sorted(migrations or []):\n',
     '    if False:\n', 1),
    ('M09', "HA's columns, sequences and types equal the trusted schema (convert)", LL,
     '    differ = schema_differences(ha_schema, live)\n    if differ:\n',
     '    differ = []\n    if differ:\n', 1),
    ('M11', ("the new cluster's schema equals the trusted one after the post-data "
       'section'), LL,
     "    require_schema(cluster, trusted, 'restored', notes)\n",
     '    pass\n', 1),
    ('M11b', 'every part of the schema signature is compared', LL,
     ('    differ = [key for key in SIGNATURE_KEYS if seen.get(key) != '
       'wanted.get(key)]\n'),
     ('    differ = [key for key in SIGNATURE_KEYS[:8] if seen.get(key) != '
       'wanted.get(key)]\n'), 1),
    ('M12', 'the new cluster holds no other role', LL,
     "    if found.get('roles') != [superuser]:\n",
     '    if False:\n', 1),
    ('M12b', 'the new cluster holds no role or database setting', LL,
     "('role_settings', '角色或資料庫設定'), ",
     '', 1),
    ('M12c', 'the new cluster holds no ALTER SYSTEM value', LL,
     ("    for key, label in (('role_settings', '角色或資料庫設定'), ('auto_conf', "
       "'ALTER SYSTEM 設定'),\n"),
     "    for key, label in (('role_settings', '角色或資料庫設定'),\n", 1),
    ('M12d', 'the new cluster holds no large object', LL,
     ("('auto_conf', 'ALTER SYSTEM 設定'),\n                       "
       "('large_objects', '大型物件')):\n"),
     "('auto_conf', 'ALTER SYSTEM 設定')):\n", 1),
    ('M12e', "what the new cluster's audit found stops the conversion", LL,
     ("    if problems:\n        raise BackupError('job-failed', f'新的 "
       'PostgreSQL 叢集含有不應存在的內容'),
     ("    if False:\n        raise BackupError('job-failed', f'新的 PostgreSQL "
       '叢集含有不應存在的內容'), 1),
    ('M13', "every table's row count equals HA's", LL,
     ("    if differ or now != found['migrations'] or len(expected) != "
       'len(tables):\n'),
     "    if now != found['migrations'] or len(expected) != len(tables):\n", 1),
    ('M13b', "the loaded migrations equal HA's", LL,
     ("    if differ or now != found['migrations'] or len(expected) != "
       'len(tables):\n'),
     '    if differ or len(expected) != len(tables):\n', 1),
    ('M13c', 'every table was counted in HA', LL,
     ("    if differ or now != found['migrations'] or len(expected) != "
       'len(tables):\n'),
     "    if differ or now != found['migrations']:\n", 1),
    ('M14', "the salt file must be the salt HA's database is bound to", LL,
     "    if binding != 'match':\n",
     '    if False:\n', 1),
    ('M15', 'the salt row the new database got equals the salt that moves', LL,
     '    if salt_rows != [hashlib.sha256(src.salt()).hexdigest()]:\n',
     '    if False:\n', 1),
    ('M16', "HA's salt becomes the converted backup's litellm-salt-key", LL,
     "'dirs': carried['dirs'], 'secrets': {SALT_SECRET: salt_path},",
     "'dirs': carried['dirs'], 'secrets': {},", 1),
    ('M17', 'the HA salt is masked in every log line', LL,
     ("        jobs.mask_secret(src.salt().decode('ascii'))  # every log "
       'line, progress message and error of this job\n'),
     '        pass\n', 1),
    ('M18', "HA's cluster runs with a read-only root", LL,
     ("    tmp.run('hapg', image, ha_server_args(), detach=True, "
       "read_only_root=True, env={'PGDATA': HA_PGDATA},\n"),
     ("    tmp.run('hapg', image, ha_server_args(), detach=True, "
       "read_only_root=False, env={'PGDATA': HA_PGDATA},\n"), 1),
    ('M18b', "HA's cluster runs on a noexec data volume", LL,
     ("            volumes=[(tmp.name('hapg'), HA_PGDATA, "
       "'rw,noexec,nosuid,nodev')])\n"),
     ("            volumes=[(tmp.name('hapg'), HA_PGDATA, "
       "'rw,nosuid,nodev')])\n"), 1),
    ('M19', "HA's cluster gets every library/command setting overridden", LL,
     ("        args += ['-c', setting]\n    return args + ['-c', "
       "'event_triggers=off']\n"),
     "    return args + ['-c', 'event_triggers=off']\n", 1),
    ('M20', 'the new cluster runs with a read-only root', LL,
     ('            env=target.db_env, secrets=target.db_secrets, '
       'read_only_root=True)\n'),
     ('            env=target.db_env, secrets=target.db_secrets, '
       'read_only_root=False)\n'), 1),
    ('M21', 'a pulled PostgreSQL 18 must be the pinned image by content', LL,
     ("    raise BackupError('job-failed', '下載的 PostgreSQL 18 "
       "映像不是預期的版本，已停止，這台的應用沒有任何變更。', app=app.id)\n"),
     '    return PG18_PINNED\n', 1),
    ('M22', 'only public/woow_platform/woow schemas in HA', LL,
     "    odd = [s for s in schemas if s not in ('woow_platform', 'woow')]\n",
     '    odd = []\n', 1),
    ('M23', 'HA objects only a superuser creates refuse', LL,
     "    if found['superuser']:   # L-23",
     '    if False:   # L-23', 1),
    ('M24', "a symlink (tablespace) in HA's cluster refuses", LL,
     '    if src.symlinks:\n',
     '    if False:\n', 1),
    ('M26', 'table/column names are plain identifiers before any HA row is read', LL,
     '    require_names(trusted, app)\n',
     '    pass\n', 1),
    ('M27', 'the target reads litellm-salt-key as LITELLM_SALT_KEY', LL,
     ("                or len(salt_specs) != 1 or f'target={SALT_ENV}' not "
       "in salt_specs[0].split(',')[1:]\n"),
     '                or len(salt_specs) != 1\n', 1),
    ('M28', 'the converted dump is read in full once', LL,
     ("            tmp.exec('ll-db', ['pg_restore', '-f', '/dev/null'], "
       "user='postgres', input=handle, timeout=DUMP_TIMEOUT,\n                 "
       '    max_output=1024 * 1024)\n'),
     '            pass\n', 1),
    ('M29', 'the apps that use LiteLLM keys are named (option A)', LL,
     '                if _uses_litellm_text(text):\n',
     '                if False:\n', 1),
    ('M30', 'post-data comes from the trusted archive', LL,
     ("    with open(schema_dump, 'rb') as handle:\n        tmp.exec(role, "
       "['pg_restore', '-U', superuser, '--no-owner', '--no-acl', "
       "'--exit-on-error',\n                        '--single-transaction', "
       "'--section=post-data'"),
     ("    with open(schema_dump, 'rb') as handle:\n        tmp.exec(role, "
       "['pg_restore', '-U', superuser, '--no-owner', '--no-acl', "
       "'--exit-on-error',\n                        '--single-transaction', "
       "'--section=data'"), 1),
    ('A01', 'a converted secret must be one the catalog declares', QP,
     "        if not set(replaced) <= {s['name'] for s in app.secrets}:\n",
     '        if False:\n', 1),
    ('A02', 'a converted secret is a regular file', QP,
     ('        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= '
       'MAX_SECRET_BYTES:\n'),
     '        if not 0 < st.st_size <= MAX_SECRET_BYTES:\n', 1),
    ('A02b', 'a converted secret is not empty', QP,
     ('        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= '
       'MAX_SECRET_BYTES:\n'),
     ('        if not stat.S_ISREG(st.st_mode) or not st.st_size <= '
       'MAX_SECRET_BYTES:\n'), 1),
    ('A02c', 'a converted secret is at most the size podman takes', QP,
     ('        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= '
       'MAX_SECRET_BYTES:\n'),
     '        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size:\n', 1),
    ('A03', 'the conversion hands its secrets to import_manifest', HI,
     "'secrets'", "'unused_secrets'", 1),
    ('M34', ("every session in HA's cluster sends the pinned client options "
       '(SR-1/SR-2)'), LL,
     ("    cluster = ha_odoo.Cluster(HaSessions(tmp, 'hapg'), 'hapg', "
       'log=work.log)\n'),
     "    cluster = ha_odoo.Cluster(tmp, 'hapg', log=work.log)\n", 1),
    ('M35', "the superuser's sessions fire no event trigger (SR-3)", LL,
     ("HA_SUPERUSER_OPTIONS = HA_SESSION_OPTIONS + ' -c "
       "session_preload_libraries= -c event_triggers=off'\n"),
     ("HA_SUPERUSER_OPTIONS = HA_SESSION_OPTIONS + ' -c "
       "session_preload_libraries='\n"), 1),
    ('M35b', "the superuser's sessions load no preload library (SR-3)", LL,
     ("HA_SUPERUSER_OPTIONS = HA_SESSION_OPTIONS + ' -c "
       "session_preload_libraries= -c event_triggers=off'\n"),
     "HA_SUPERUSER_OPTIONS = HA_SESSION_OPTIONS + ' -c event_triggers=off'\n", 1),
    ('M36', "HA's server starts with event triggers off (SR-3)", LL,
     "    return args + ['-c', 'event_triggers=off']\n",
     '    return args\n', 1),
    ('M37', '_prisma_migrations is read only as an ordinary table (SR-1)', LL,
     ('MIGRATIONS_TABLE_SQL = ("SELECT to_json(coalesce((SELECT c.relkind = '
       '\'r\' FROM pg_catalog.pg_class c "\n'),
     ('MIGRATIONS_TABLE_SQL = ("SELECT to_json(coalesce((SELECT true FROM '
       'pg_catalog.pg_class c "\n'), 1),
    ('M38', "backup_label/tablespace_map never reach HA's volume (SR-4)", LL,
     ('                src.recovery_files += 1  # never reaches the volume '
       '(SR-4); the verdict refuses\n                continue\n'),
     ('                src.recovery_files += 1  # never reaches the volume '
       '(SR-4); the verdict refuses\n'), 1),
    ('M39', 'backup_label/tablespace_map refuse (SR-4)', LL,
     '    if src.recovery_files:\n',
     '    if False:\n', 1),
    ('M40', "HA's stored proxy settings are named in the check (SR-5)", LL,
     ('    line = stored_settings_line(found)\n    if line:\n        '
       "sink.notice('litellm.stored-settings', line)\n"),
     '    line = None\n', 1),
    ('M41', "HA's stored proxy settings are named in the import notes (SR-5)", LL,
     ("    stored_line = stored_settings_line(data.get('stored_settings'))\n  "
       '  if stored_line:\n        notes.append(stored_line)\n'),
     '', 1),
    ('M42', 'stored settings that load and run code refuse in the check (SR-6)', LL,
     ("        sink.confirm('litellm.hooks-removed', HOOKS_REMOVED, "
       "found['hooks'])\n"),
     '        pass\n', 1),
    ('M44', 'a callback with a dot in its name is a module load (SR-6)', LL,
     "[f'litellm_settings 回呼 {c}'[:60] for c in callbacks if '.' in c]",
     '[]', 1),
    ('M45', ('an app whose Pi agent provider list points at this LiteLLM is named '
       '(option A)'), LL,
     ' or pi_agent_uses_litellm(work, other, quadlets))\n',
     ')\n', 1),
    ('M46', ("only a provider at this device's LiteLLM counts, not any provider "
       '(option A)'), LL,
     ('            if isinstance(value, str) and value.strip() and '
       'LITELLM_URL_RE.search(value.strip()[:2048]):\n'),
     '            if isinstance(value, str) and value.strip():\n', 1),
    ('M47', ('every columns/signature read pins search_path=pg_catalog (all sides '
       'render names alike)'), LL,
     "PIN_SEARCH_PATH = 'SET search_path = pg_catalog; '\n",
     "PIN_SEARCH_PATH = ''\n", 1),
    ('M48', ('a stored-settings answer over the limit or timed out refuses (fail '
       'closed)'), LL,
     '            raise\n        return dict(UNREADABLE)\n',
     '            raise\n        return None\n', 1),
    ('M49', 'a stored-settings answer that is not an object refuses (fail closed)', LL,
     '    if not isinstance(found, dict):\n        return dict(UNREADABLE)\n',
     '    if not isinstance(found, dict):\n        return None\n', 1),
    ('M51', 'the nested code places count as hooks', LL,
     "    hooks = (names(found.get('hooks')) + names(found.get('nested'))\n",
     "    hooks = (names(found.get('hooks'))\n", 1),
    ('M52', 'router_settings.plugins is asked (not in the vendor list)', LL,
     "    ('router_settings', 'plugins', f'lax $.plugins[*] ? ({_TEXT})'),\n",
     '', 1),
    ('M53', 'a dotted guardrail callback is asked', LL,
     ("    ('litellm_settings', 'guardrails', f'lax "
       '$.guardrails[*].*.callbacks[*] ? ({_TEXT} && @ like_regex "[.]")\'),\n'),
     '', 1),
    ('M54', 'a string-form callbacks value is asked', LL,
     "jsonb_typeof(c.param_value -> 'callbacks') = 'string'",
     'false', 1),
    ('M55', 'the conversion decides again in the new cluster (SR-8)', LL,
     ('    settings = take_out_hooks(sink, pg, trusted) if moves_config else '
       'None\n'),
     '    settings = None\n', 1),
    ('M57', ('a dotted callback is found by the query, however many plain names '
       'come first'), LL,
     'AND strpos(v.value, \'.\') > 0"',
     'AND false"', 1),
    ('M58', ('a custom secret manager path is asked (it loads a .py file at every '
       'start)'), LL,
     ("    ('general_settings', 'custom_secret_manager',\n     f'lax "
       "$.key_management_settings.custom_secret_manager ? ({_TEXT})'),\n"),
     '', 1),
    ('M56', "the import notes name what moved, not what HA's cluster said (SR-8)", LL,
     ("'tables': len(tables), 'key_users': users, 'stored_settings': "
       'settings,'),
     "'tables': len(tables), 'key_users': users, 'stored_settings': None,", 1),
    ('N04', "the check refuses another PostgreSQL major of HA's data", LL,
     '    if ha_major != HA_PG_MAJOR or src.pg_version is None:\n',
     '    if False:\n', 1),
    ('N06', "HA's database must be UTF8", LL,
     "    if objects.get('encoding') != 'UTF8':\n",
     '    if False:\n', 1),
    ('N07', "HA's migrations must be this device's", LL,
     ('    if ha_migrations is None or live_migrations_value is None or '
       'ha_migrations != live_migrations_value:\n'),
     '    if False:\n', 1),
    ('N09', "the new cluster's major is this device's", LL,
     '    if type(major) is not int:   # L-53',
     '    if False:   # L-53', 1),
    ('N10', 'an empty converted dump is refused', LL,
     '    if dump.stat().st_size == 0:\n',
     '    if False:\n', 1),
    ('N12', "the conversion's space is checked before HA's cluster starts", LL,
     '    work.guard.check(3 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE)\n',
     '    pass\n', 1),
    ('N12b', "that space is three times HA's cluster and the write-ahead allowance", LL,
     '    work.guard.check(3 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE)\n',
     '    work.guard.check(2 * src.pg_bytes + ha_odoo.WAL_ALLOWANCE)\n', 1),
    ('N14', 'the salt file is a regular file', LL,
     ("            if entry.kind != 'file' or entry.size > MAX_SALT_FILE or "
       'salts > 1:\n'),
     '            if entry.size > MAX_SALT_FILE or salts > 1:\n', 1),
    ('N14b', 'the salt file is at most 1024 bytes', LL,
     ("            if entry.kind != 'file' or entry.size > MAX_SALT_FILE or "
       'salts > 1:\n'),
     "            if entry.kind != 'file' or salts > 1:\n", 1),
    ('N14c', 'a second salt file refuses', LL,
     ("            if entry.kind != 'file' or entry.size > MAX_SALT_FILE or "
       'salts > 1:\n'),
     "            if entry.kind != 'file' or entry.size > MAX_SALT_FILE:\n", 1),
    ('N16', "the new cluster's schema equals the trusted one after the last write", LL,
     "    require_schema(pg, trusted, 'loaded', versions)\n",
     '    pass\n', 1),
    ('N17', 'the new cluster is audited', LL,
     '    audit_new_cluster(pg, target.db_user)\n',
     '    pass\n', 1),
    ('N18', ("the schema snapshot's migrations are the ones the check saw (the "
       'script inside litellm-postgres)'), LL,
     ('[ -s "$snapdir/columns" ] && [ "$(cat "$snapdir/revision")" = ok ] || '
       'exit 22'),
     '[ -s "$snapdir/columns" ] || exit 22', 1),
    ('N19', "the new cluster holds HA's columns before any row is loaded", LL,
     ("    if _columns(cluster.query_json(COLUMNS_SQL, DATABASE), '新的 "
       "PostgreSQL 叢集') != ha_columns:\n"),
     '    if False:\n', 1),
    ('N23', ("the app's own MCP administration is not named as another app that "
       'uses the keys'), LL,
     ('        if other_id == app.id or '
       "other_id.startswith(f'{app.id}-mcp'):\n"),
     '        if other_id == app.id:\n', 1),
    ('N26', 'a salt file that cannot be read is not a match', LL,
     ('    if not src.salt_valid or src.salt() is None:\n        return '
       "'invalid_source'\n"),
     ('    if not src.salt_valid or src.salt() is None:\n        return '
       "'match'\n"), 1),
    ('N30', 'the check names ChatGPT sign-ins', LL,
     ("    if ha_odoo._int((detail or {}).get('chatgpt_accounts')):\n        "
       'sink.notice('),
     '    if False:\n        sink.notice(', 1),
    ('N31', "the new cluster's data volume is noexec", LL,
     ("            volumes=[(tmp.name('ll-db'), target.db_target, "
       "'rw,noexec,nosuid,nodev')],\n"),
     "            volumes=[(tmp.name('ll-db'), target.db_target, 'rw')],\n", 1),
    ('N32', "HA's staged rows leave the disk as they are loaded", LL,
     '        os.unlink(path)\n        work.checkpoint()\n    if sequences:\n',
     '        work.checkpoint()\n    if sequences:\n', 1),
    ('N33', 'a new database without the salt row is refused', LL,
     '    if salt_rows != [hashlib.sha256(src.salt()).hexdigest()]:\n',
     ('    if salt_rows and salt_rows != '
       '[hashlib.sha256(src.salt()).hexdigest()]:\n'), 1),
    ('N34', "the check removes HA's cluster before it reads this device", LL,
     "    tmp.remove('hapg')\n    tmp.remove_volume('hapg')\n    judge(sink,",
     '    judge(sink,', 1),
    ('N34b', "the conversion removes HA's cluster before the new one starts", LL,
     ("    tmp.remove('hapg')\n    tmp.remove_volume('hapg')\n    "
       "work.checkpoint()\n\n    work.log('建立新的"),
     "    work.checkpoint()\n\n    work.log('建立新的", 1),
    ('R03', 'the columns answer is a list of rows', LL,
     ('    if (not isinstance(value, list) or not value or len(value) > '
       '20000\n            or any(not isinstance(row, list) or len(row) != 7 '
       'for row in value)):\n'),
     '    if False:\n', 1),
    ('R03b', 'no columns at all is not a schema', LL,
     ('    if (not isinstance(value, list) or not value or len(value) > '
       '20000\n'),
     '    if (not isinstance(value, list) or len(value) > 20000\n', 1),
    ('R03c', 'the columns answer is bounded', LL,
     ('    if (not isinstance(value, list) or not value or len(value) > '
       '20000\n'),
     '    if (not isinstance(value, list) or not value\n', 1),
    ('R03d', 'each column row has its seven values', LL,
     ('            or any(not isinstance(row, list) or len(row) != 7 for row '
       'in value)):\n'),
     '            or any(not isinstance(row, list) for row in value)):\n', 1),
    ('R04', 'the signature answer has every part and no other', LL,
     ('    if not isinstance(value, dict) or set(value) != '
       'set(SIGNATURE_KEYS):\n'),
     '    if not isinstance(value, dict):\n', 1),
    ('R05', "this device's migrations must be readable", LL,
     ("    if migrations is None:\n        raise BackupError('incompatible', "
       "'無法讀取這台 LiteLLM 的資料庫結構版本"),
     ("    if False:\n        raise BackupError('incompatible', '無法讀取這台 "
       'LiteLLM 的資料庫結構版本'), 1),
    ('R08', 'a salt that could not be compared is not a match', LL,
     "    except BackupError:\n        return 'unknown'\n",
     "    except BackupError:\n        return 'match'\n", 1),
    ('R09', "HA's cluster must hold the litellm database", LL,
     '    if DATABASE not in databases:',
     '    if False:', 1),
    ('R10', "what HA's database holds must be readable", LL,
     '    if not isinstance(objects, dict):\n',
     '    if False:\n', 1),
    ('R11', 'no snapshot is taken for migrations that are not known', LL,
     ('    if any(not isinstance(v, str) or not MIGRATION_RE.fullmatch(v) '
       'for v in values):\n'),
     '    if False:\n', 1),
    ('R12', 'a new cluster that cannot be audited stops', LL,
     ('    if not isinstance(found, dict):\n        raise '
       "BackupError('job-failed', '無法檢查新的 PostgreSQL 叢集。')\n"),
     '    if not isinstance(found, dict):\n        return\n', 1),
    ('R13', 'a sequence value that is not one stops', LL,
     ('        if (not isinstance(value, list) or len(value) != 2 or '
       'type(value[0]) is not int\n                or not isinstance(value[1], '
       'bool)):\n'),
     ('        if not isinstance(value, list) or len(value) != 2 or '
       'type(value[0]) is not int:\n'), 1),
    ('R14', 'a cluster version that is not a plain number is not known', LL,
     ('                    src.pg_version = text if '
       "re.fullmatch(r'[1-9][0-9]?', text) else None\n"),
     '                    src.pg_version = text\n', 1),
    ('R15', 'a state.json that is not a file is not read', LL,
     ("        elif name == STATE_FILE and entry.kind == 'file' and "
       'entry.size <= 65536:\n'),
     '        elif name == STATE_FILE and entry.size <= 65536:\n', 1),
    ('R15b', 'a large state.json is not read', LL,
     ("        elif name == STATE_FILE and entry.kind == 'file' and "
       'entry.size <= 65536:\n'),
     "        elif name == STATE_FILE and entry.kind == 'file':\n", 1),
    ('T01', "the entry's database is litellm", LL,
     ('        if (self.database != DATABASE or '
       "self.db_env.get('POSTGRES_DB', self.db_user) != DATABASE\n"),
     "        if (self.db_env.get('POSTGRES_DB', self.db_user) != DATABASE\n", 1),
    ('T02', "the container's database is litellm", LL,
     ('        if (self.database != DATABASE or '
       "self.db_env.get('POSTGRES_DB', self.db_user) != DATABASE\n"),
     '        if (self.database != DATABASE\n', 1),
    ('T03', "the container's user is the entry's", LL,
     ("                or self.db_env.get('POSTGRES_USER', 'postgres') != "
       'self.db_user\n'),
     '', 1),
    ('T04', 'the user name is plain', LL,
     ('                or not isinstance(self.db_user, str) or not '
       'IDENT_RE.fullmatch(self.db_user)\n'),
     '                or not isinstance(self.db_user, str)\n', 1),
    ('T05', 'the database container has an image', LL,
     'or not self.db_image or not self.app_image or self.db_volume is None',
     'or not self.app_image or self.db_volume is None', 1),
    ('T06', 'the proxy has an image', LL,
     'or not self.db_image or not self.app_image or self.db_volume is None',
     'or not self.db_image or self.db_volume is None', 1),
    ('T07', "the container's data volume is the entry's", LL,
     'or self.db_volume is None or self.db_volume != wanted_volume',
     '', 1),
    ('T08', 'PGDATA is a plain path', LL,
     ('                or not self.pgdata or not '
       'tempctr.TARGET_RE.fullmatch(self.pgdata)\n'),
     '                or not self.pgdata\n', 1),
    ('T09', 'the proxy reads the salt secret once', LL,
     ("                or len(salt_specs) != 1 or f'target={SALT_ENV}' not "
       "in salt_specs[0].split(',')[1:]\n"),
     ("                or not salt_specs or f'target={SALT_ENV}' not in "
       "salt_specs[0].split(',')[1:]\n"), 1),
    ('T10', 'the entry declares the salt secret', LL,
     ('                or SALT_SECRET not in declared or len(declared) != '
       'len(set(declared))):\n'),
     '                or len(declared) != len(set(declared))):\n', 1),
    ('T11', 'the entry declares each secret once', LL,
     ('                or SALT_SECRET not in declared or len(declared) != '
       'len(set(declared))):\n'),
     '                or SALT_SECRET not in declared):\n', 1),
    ('T12', "the database's Quadlet file exists", LL,
     '        if db_file is None or not proxies:\n',
     '        if not proxies:\n', 1),
    ('T12b', "the proxy's Quadlet file exists", LL,
     '        if db_file is None or not proxies:\n',
     '        if db_file is None:\n', 1),
    ('K01', "LiteLLM's own drop-in that joins the app's network names the app", LL,
     ('                        or bool(joined & _network_names(quadlets)) or '
       'pi_agent_uses_litellm(work, other, quadlets))\n'),
     ('                        or pi_agent_uses_litellm(work, other, '
       'quadlets))\n'), 1),
    ('K02', "a container on LiteLLM's network names the app", LL,
     ('                uses = (any(_uses_litellm_text(text) or '
       '_joins_litellm_network(text) for text in texts)\n'),
     ('                uses = (any(_uses_litellm_text(text) for text in '
       'texts)\n'), 1),
    ('K03', 'a setting in a Quadlet file names the app', LL,
     ('                uses = (any(_uses_litellm_text(text) or '
       '_joins_litellm_network(text) for text in texts)\n'),
     ('                uses = (any(_joins_litellm_network(text) for text in '
       'texts)\n'), 1),
    ('K04', "a network without a NetworkName has systemd's name", LL,
     ('        found.add(names[-1] if names else '
       'f\'systemd-{name[:-len(".network")]}\')\n'),
     '        found.update(names[-1:])\n', 1),
    ('K05', "a network's own file name counts", LL,
     "        found.add(name[:-len('.network')])\n",
     '', 1),
    ('K06', "a Pi agent's plain named volume is read", LL,
     ('            elif VOLUME_NAME_RE.fullmatch(source):\n                '
       "found.append(('volume', source))\n"),
     '', 1),
    ('K07', "a Pi agent's folder in the owner's home is read", LL,
     '                rel = source\n',
     "                rel = ''\n", 1),
    ('D01', ('a backup without the digest is a warning before the restore, never a '
       'refusal'), QP,
     "            add('digests-missing', 'warn',",
     "            add('digests-missing', 'fail',", 1),
    ('D02', "a rollback compares this device's own rows", QP,
     ("            result.update(before=before, after=after['summary'], "
       "match=after['digest'] == before_digest)\n"),
     ("            result.update(before=before, after=after['summary'], "
       'match=True)\n'), 1),
    ('M59', "LiteLLM's drafted health checks wait 600 s (no per-app limit)", SG,
     "HEALTH_TIMEOUTS = {'litellm': 600}\n",
     'HEALTH_TIMEOUTS = {}\n', 1, ('tests.backup.test_suggest',)),
    ('M60', "LiteLLM's limit is 600 s, not the generic 300 s", SG,
     "HEALTH_TIMEOUTS = {'litellm': 600}\n",
     "HEALTH_TIMEOUTS = {'litellm': 300}\n", 1, ('tests.backup.test_suggest',)),
    ('M61', 'a new draft uses the per-app limit', SG,
     "        timeout = HEALTH_TIMEOUTS.get(app['id'])\n",
     '        timeout = None\n', 1, ('tests.backup.test_suggest',)),
    ('M62', 'every other app keeps the generic 300 s / 180 s', SG,
     ('            timeout = 300 if len(containers) >= 3 or '
       'any(self._database(c) for c in containers) else 180\n'),
     '            timeout = 600\n', 1, ('tests.backup.test_suggest',)),
    ('M63', 'the draft of an installed LiteLLM entry raises a shorter limit', SG,
     ("            raised = raise_health_timeouts(app['id'], "
       "variant['entry']) or raised\n"),
     '', 1, ('tests.backup.test_suggest',)),
    ('M64', 'only the listed apps are raised', SG,
     '    limit = HEALTH_TIMEOUTS.get(app_id)\n',
     '    limit = 600\n', 1, ('tests.backup.test_suggest',)),
    ('M65', "a check without a limit (the catalog's 60 s) is raised too", SG,
     "        current = item.get('timeout_seconds', 60)\n",
     "        current = item.get('timeout_seconds', 600)\n", 1, ('tests.backup.test_suggest',)),
    ('M66', 'a limit already at 600 s is left alone (no note)', SG,
     '        if type(current) is int and current < limit:\n',
     '        if type(current) is int and current <= limit:\n', 1, ('tests.backup.test_suggest',)),
    ('M67', 'the draft says what it raised (health-timeout note)', SG,
     "        if raised:\n            limit = HEALTH_TIMEOUTS[app['id']]\n",
     "        if False:\n            limit = HEALTH_TIMEOUTS[app['id']]\n", 1, ('tests.backup.test_suggest',)),
    ('S01', 'a new LiteLLM draft is the single-database mode', SG,
     "PREFERRED_MODES = {'litellm': 'database'",
     "PREFERRED_MODES = {'not-litellm': 'database'", 1, ('tests.backup.test_suggest',)),
    ('S02', "an installed entry's mode is never switched", SG,
     '        elif installed is None:\n',
     '        elif True:\n', 1, ('tests.backup.test_suggest',)),
    ('S03', 'a mode that cannot be installed is not preselected', SG,
     ("        if not any(v['id'] == preferred and v['valid'] for v in "
       'variants):\n'),
     "        if not any(v['id'] == preferred for v in variants):\n", 1, ('tests.backup.test_suggest',)),
    ('S04', 'the draft of another installed mode says what to choose for an import', SG,
     "            app['notes'].append(_warn('import-mode', f'已安裝的應用設定不是",
     "            app['skipped'].append(_warn('import-mode', f'已安裝的應用設定不是", 1, ('tests.backup.test_suggest',)),
    ('S05', "LiteLLM's drafted health check asks for readiness", SG,
     ("READY_PATHS = {('litellm', '/health/liveliness'): "
       "'/health/readiness'}\n"),
     'READY_PATHS = {}\n', 1, ('tests.backup.test_suggest',)),
    ('S06', "the package's settings file stays in the draft", SG,
     "PACKAGE_CONFIGS = {'litellm': ('.config/litellm/litellm.env',)}\n",
     'PACKAGE_CONFIGS = {}\n', 1, ('tests.backup.test_suggest',)),
    ('S07', 'a settings file the owner does not have is not proposed', SG,
     ("            if isinstance(state, dict) and state.get('type') == "
       "'file':\n                add(rel, state.get('mode'), 'env')\n        "
       'return result\n'),
     ('            if isinstance(state, dict):\n                add(rel, '
       "state.get('mode'), 'env')\n        return result\n"), 1, ('tests.backup.test_suggest',)),
    ('S08', 'a kept table digest takes the form the chosen mode needs', SG,
     ('        kept = [digest_for_mode(item, installed, entry) for item in '
       "json.loads(json.dumps(installed['verify']))]\n"),
     "        kept = json.loads(json.dumps(installed['verify']))\n", 1, ('tests.backup.test_suggest',)),
    ('S09', ("the changed digest keeps the installed check's id, label and "
       'exclusions'), SG,
     ("    return {**own, 'id': item.get('id'), **{key: item[key] for key in "
       "('label', 'exclude_tables') if key in item}}\n"),
     '    return dict(own)\n', 1, ('tests.backup.test_suggest',)),
    ('S10', 'a digest that fits the mode is left alone', SG,
     ('        if container not in exported.values():\n            return '
       'item\n'),
     '', 1, ('tests.backup.test_suggest',)),
    ('L03a', 'an entry that dumps the whole instance stops this app', LL,
     ("        if any(isinstance(pg, dict) and pg.get('scope', 'database') "
       "== 'instance' for pg in pgs):\n"),
     '        if False:\n', 1),
    ('L03b', 'an entry with two database items stops this app', LL,
     ('        if len(pgs) > 1:\n            raise _layout_stop(app, '
       'LAYOUT_MANY)\n'),
     '        if False:\n            raise _layout_stop(app, LAYOUT_MANY)\n', 1),
    ('L03c', 'an entry that names no database stops this app', LL,
     '        if not pgs and not declared_volumes:\n',
     '        if False:\n', 1),
    ('L03d', "this device's other volumes and folders go along as they are", LL,
     '    if target.extra_volumes or target.extra_dirs:   # L-03',
     '    if False:   # L-03', 1),
    ('L03e', 'a cold entry is filled with the new cluster as the data volume', LL,
     "    if target.mode == 'cold':\n",
     '    if False:\n', 1),
    ('L03f', 'the cold cluster is exported only after a clean shutdown (controldata)', LL,
     ("        if not re.search(rb'Database cluster state:\\s+shut down\\s*$', "
       'state, re.M):\n'),
     '        if False:\n', 1),
    ('L04', 'the proxy is found by the salt secret it mounts', LL,
     ("    return any(spec.split(',', 1)[0] == SALT_SECRET for spec in "
       'tempctr.quadlet_secrets(_text_of(text)))\n'),
     '    return False\n', 1),
    ('L08', 'a database without finished migrations gets the proxy first start', LL,
     ('    hatarget.ensure_running(work, app, target.app_container, '
       'ready=_migrations_ready(target), timeout=FIRST_START_WAIT)\n'),
     '    pass\n', 1),
    ('L08b', 'migrations that stay unreadable stop this app', LL,
     '    if migrations is None:   # L-08',
     '    if False:   # L-08', 1),
    ('L10a', 'a quote inside a name is doubled', LL,
     '    return \'"\' + name.replace(\'"\', \'""\') + \'"\'\n',
     '    return \'"\' + name + \'"\'\n', 1),
    ('L10b', 'a quote inside a literal is doubled', LL,
     '    return "\'" + text.replace("\'", "\'\'") + "\'"\n',
     '    return "\'" + text + "\'"\n', 1),
    ('L10c', 'a database without a table stops', LL,
     '    if not schema.tables():\n',
     '    if False:\n', 1),
    ('L13a', 'a stored-settings table that cannot be read is not moved', LL,
     '    skipped = set() if moves_config else {CONFIG_TABLE}',
     '    skipped = set()', 1),
    ('L13b', ('a stored-settings answer that cannot be read is named in a line to '
       'confirm'), LL,
     ("    if found and found.get('unreadable'):\n        "
       "sink.confirm('litellm.config-unreadable', CONFIG_UNREADABLE, "
       '[CONFIG_TABLE[1]])\n        return False\n'),
     '    if False:\n        return False\n', 1),
    ('L13c', 'the stored-settings read is tried again once', LL,
     'attempts=2, pause_first=2.0,',
     'attempts=1, pause_first=2.0,', 1),
    ('L14a', 'the settings that load code are taken out of the new cluster', LL,
     "        pg.script(removal_sql(found['labels']), DATABASE)\n",
     '        pass\n', 1),
    ('L14b', 'a setting that is still there after the removal stops this app', LL,
     ("        if found is None or found.get('unreadable') or "
       "found.get('hooks'):\n            raise BackupError('job-failed', "
       'HOOKS_STAYED)\n'),
     '        pass\n', 1),
    ('L14c', 'the new cluster must show the names the customer confirmed', LL,
     ("    if not any(known.id == issue.id and known.level == 'confirm' and "
       'known.key(sink.app_id) == key for known in sink.found):\n        '
       'sink.add(issue)\n'),
     '    pass\n', 1),
    ('L14d', 'the new cluster that cannot be read stops this app', LL,
     ("    if found.get('unreadable'):\n        raise "
       "BackupError('job-failed', '無法完整讀取匯入後"),
     "    if False:\n        raise BackupError('job-failed', '無法完整讀取匯入後", 1),
    ('L14e', 'every label of the detection has a removal', LL,
     '    for key in CALLBACK_KEYS:\n',
     '    for key in CALLBACK_KEYS[1:]:\n', 1),
    ('L21', 'the schemas HA has beyond LiteLLM are named in a line to confirm', LL,
     '    if odd:   # L-21',
     '    if False:   # L-21', 1),
    ('L24', 'large objects are a reminder', LL,
     '    if large:   # L-24',
     '    if False:   # L-24', 1),
    ('L34', 'a version that differs is a reminder and no stop', LL,
     "        if issue.id == 'version.different':\n",
     '        if False:\n', 1),
    ('L36', 'a capture that came out wrong is taken again', LL,
     ('    return hatarget.retry(once, attempts=3, pause_first=5.0, '
       'longest=30.0, retry_if=_unsteady, abort=work.abort,\n                  '
       "        log=work.log, what='讀取這台 LiteLLM 的資料庫結構')\n"),
     '    return once()\n', 1),
    ('L54', 'only the exit codes of a busy device are tried again', LL,
     "getattr(error, 'returncode', None) in (21, 22)",
     "getattr(error, 'returncode', None) in (21, 22, 23)", 1),
    ('L38a', 'the pre-restore backup is kept when this device has other schemas', LL,
     "        converted['keep_safety'] = True\n",
     '        pass\n', 1),
    ('L38b', 'without a way to keep it the import stops (fail closed)', LL,
     '        if not keep_supported():\n',
     '        if False:\n', 1),
    ('L38c', 'the line about other schemas is found before anything is captured', LL,
     ('    schema_stops(sink, ha_schema, live_schema(work, app, target))   # '
       'before anything'),
     '    pass   # before anything', 1),
    ('L40', 'extension versions are told, not compared', LL,
     '    seen = comparable(found)\n',
     '    seen = found\n', 1),
    ('L57', 'the version file is read by its first bytes only', LL,
     ("                    text = entry.peek(64).decode('ascii', "
       "'replace').strip()\n"),
     ("                    text = entry.read_all(64).decode('ascii', "
       "'replace').strip()\n"), 1),
    ('L58', 'the PostgreSQL 18 image is fetched with a second try and the reason', LL,
     '    hatarget.ensure_image(work, app, PG18_PINNED)',
     ("    work.runner(app).podman('pull', '--quiet', PG18_PINNED, "
       'timeout=1800, max_output=64 * 1024, abort=work.abort)'), 1),
    ('F2a', ("a table's rows travel in a script that ends with a mark the load "
       'looks for'), LL,
     ("    if out.rstrip(b'\\n').rsplit(b'\\n', 1)[-1] != "
       "mark.encode('ascii'):\n        raise BackupError('job-failed', "
       'ha_odoo.INCOMPLETE_SQL)\n'),
     '    pass\n', 1),
    ('F2b', "a table's script opens its transaction itself", LL,
     "    return (f'BEGIN;\\nCOPY {_q(schema, table)}",
     "    return (f'COPY {_q(schema, table)}", 1),
    ('F2c', "a table's script commits itself before the mark", LL,
     "f'\\\\.\\nCOMMIT;\\n\\\\echo {mark}\\n')",
     "f'\\\\.\\n\\\\echo {mark}\\n')", 1),
    ('SK', 'what the reader left out is one line to confirm', LL,
     ('        sink.skipped(report, *[kind for kind in habackup.SKIP_KINDS '
       "if kind != 'symlink'])\n"),
     '        pass\n', 1),
)

# One changed comment per module: no test may notice it. A run in which these were "caught" would call every removal caught
# (a test that looks at the source text, a broken copy, a failing baseline).
CONTROLS = (
    ('C01', 'a changed comment in ha_litellm.py', LL, '# The catalog entry the import fills (L-03): one single-database',
     '# The catalog entry an import fills (L-03): one single-database', 1, TESTS),
    ('C02', 'a changed comment in quadlet_postgres.py', QP, '# Exactly the databases the backup read (also for "all")',
     '# Just the databases the backup read (also for "all")', 1, TESTS),
    ('C03', 'a changed comment in haimport.py', HI, "# what a module's convert hands to adapter.import_manifest",
     "# what a module's convert gives to adapter.import_manifest", 1, TESTS),
    ('C04', 'a changed comment in suggest.py', SG, '# The PostgreSQL mode a draft of an app that is not installed yet defaults to',
     '# The PostgreSQL mode the draft of an app that is not installed yet defaults to', 1, SUGGEST_TESTS),
)


def outcome(text):
    """(tests run, failures and errors) of unittest's own summary: its `Ran N tests` line and the `FAILED (...)` line after
    it, wherever they are. Neither is always the last line: an archive writer a failed conversion left open is collected
    when the interpreter ends and Python prints `Exception ignored in ...` after the summary (reading the last line called
    13 of 106 caught mutations MISSED on 2026-11-24)."""
    ran, failures = 0, 0
    for line in text.splitlines():
        if m := re.fullmatch(r'Ran (\d+) tests? in .*', line):
            ran, failures = int(m.group(1)), 0
        elif ran and (m := re.fullmatch(r'FAILED \((.*)\)', line)):
            failures = sum(int(n) for n in re.findall(r'(?<!expected )\b(?:failures|errors)=(\d+)', m.group(1)))
    return ran, failures


def run_tests(root, tests=TESTS, failfast=True):
    """The unit tests `tests` in the throwaway copy `root` (tests/backup/__init__.py puts ITS backup-engine first)."""
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(root / 'backup-engine'), str(root)]),
               PYTHONDONTWRITEBYTECODE='1')
    proc = subprocess.run([sys.executable, '-m', 'unittest', *(['-f'] if failfast else []), *tests], cwd=root, env=env,
                          capture_output=True, timeout=1800)
    return proc.returncode, *outcome(proc.stderr.decode('utf-8', 'replace'))


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
        controls = []
        for ident, name, module, old, new, count, tests in CONTROLS:
            source = sources[module]
            applied = source.count(old) == count
            rc, ran, failures = 1, 0, 0
            if applied:
                (engine / module).write_text(source.replace(old, new), encoding='utf-8')
                rc, ran, failures = run_tests(root, tests)
                (engine / module).write_text(source, encoding='utf-8')
            quiet = applied and rc == 0 and ran > 0
            controls.append({'id': ident, 'change': name, 'module': module, 'applied': applied, 'unnoticed': quiet,
                             'failures': failures, 'tests': ran, 'test_modules': list(tests)})
            print(f'{ident} control, {name}: {"not noticed" if quiet else "NOTICED"} ({failures}/{ran})', flush=True)
    ok = (baseline['returncode'] == 0 and all(r.get('applied') and r.get('caught') for r in results)
          and all(c['unnoticed'] for c in controls))
    summary = {'modules': {name: hashlib.sha256(text.encode('utf-8')).hexdigest() for name, text in sources.items()},
               'tests': list(TESTS + SUGGEST_TESTS), 'baseline': baseline, 'mutations': results, 'controls': controls,
               'all_caught': ok,
               'subset': sorted(only) if only is not None else None,
               'seconds': round(time.monotonic() - started, 1)}
    if args.json:
        Path(args.json).write_text(json.dumps(summary, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    print(f'mutation check: {"PASS" if ok else "FAIL"} ({sum(1 for r in results if r.get("caught"))}/{len(results)} caught)')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
