#!/usr/bin/env python3
"""Mutation check of the Omnigent product import (B1-01 trusted schema, owner decision 2026-11-23): every protection
the lab proved is removed, one at a time, in a throwaway copy of the engine, and the Omnigent unit tests must FAIL
for each (and pass on the unmodified copy). Nothing here touches Podman, a device or a secret.

  python3 -I tests/backup/omnigent_product_mutations.py [--json OUT] [--only P01,P02] [--refusals | --named]

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
         'tests.backup.test_ha_omnigent_server_volume', 'tests.backup.test_ha_omnigent_install', 'tests.backup.test_jobs')

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
     '    differ = schema_differences(ha_schema, trusted, ignore=ignored)\n', '    differ = []\n', 1),
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
    ('M14', "the conversion tells the Quadlet secrets that the app settings do not list (O-48: a notice, no refusal)",
     '    note_secrets(sink, unregistered)\n', '', 1),
    ('M15', 'the check names a schema difference as a stop',
     "    if differ:\n        sink.stop('omnigent.schema-different', schema_blocker(differ), action=ACTION_UNCHANGED)\n    names, counts",
     '    names, counts', 1),
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
     "    return ''.join('?' if unicodedata.category(ch) in HIDDEN_CATEGORIES else ch for ch in str(text)[:limit])\n",
     '    return str(text)[:limit]\n', 1, 'woowbackup/hacommon.py'),
    ('M22', "HA's rows that this device's schema refuses end with the plain message, never their values (review v5)",
     "            if DATA_REFUSED_RE.search(error.stderr or b''):\n", '            if False:\n', 1),
    # the independent verifier's gaps X7..X15 (2026-11-24): protections no unit test failed without until iteration 5
    ('M29', "the conversion itself stops on another structure version, not only the check (X7, O-19)",
     '    elif not ha_alembic or sorted(ha_alembic) != sorted(live_alembic_value):\n', '    elif False:\n', 1),
    ('M30', "after the last write every table holds HA's rows (users this device's kept accounts too) and the revision "
            "is HA's (X8)",
     "    if differ or sorted(now_alembic or []) != sorted(found['alembic']):\n", '    if False:\n', 1),
    ('M31', 'the row counts of that final comparison (X8)',
     "    if differ or sorted(now_alembic or []) != sorted(found['alembic']):\n",
     "    if sorted(now_alembic or []) != sorted(found['alembic']):\n", 1),
    ('M32', 'the revision of that final comparison (X8)',
     "    if differ or sorted(now_alembic or []) != sorted(found['alembic']):\n", '    if differ:\n', 1),
    ('M33', "O-54 is gone: the exit code of the stop is no refusal on its own (pg_controldata is the proof)",
     "    if code != 0:    # O-54: the control file below is the proof of a clean stop (a PostgreSQL that was killed says so there)\n"
     "        work.log(f'新的 PostgreSQL 叢集關閉時結束碼是 {code}；以 pg_controldata 的狀態判斷它有沒有正常關閉。')\n",
     "    if code != 0:\n        raise BackupError('job-failed', f'新的 PostgreSQL 叢集沒有正常關閉（結束碼 {code}）。')\n", 1),
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
    # HAOS parity (2026-11-25, lane OMNIGENT): what the new behaviour must still refuse, and the old refusals that must stay gone
    ('P01', 'O-01: any other id both maps hold runs the dump when the list has none',
     '    spare = _spare_id(uids, gids, {0, *pg_ids}) if uids is not None else None\n', '    spare = None\n', 1),
    ('P02', "O-01: a spare id is never root or the image's postgres",
     '            if candidate not in avoid:\n                return candidate\n', '            return candidate\n', 1),
    ('P03', "O-02: a hard link in HA's database folder is copied as a file",
     '                entry.copy_later()      # the same name comes again after the walk as a file with the content\n', '                pass\n', 1),
    ('P04', "O-03: a hard link of the artifact store to a file outside it is never carried",
     "            if copied or (entry.kind == 'hardlink' and (not ha_odoo._under(entry.linkname, ARTIFACTS)\n",
     "            if copied or (entry.kind == 'hardlink' and (False\n", 1),
    ('P05', "O-03: a copy of a file outside the artifact store is never carried either",
     "            if copied or (entry.kind == 'hardlink' and", "            if (entry.kind == 'hardlink' and", 1),
    ('P06', 'O-20: an empty or huge login key is not carried',
     '                    if not src.cookie:\n                        continue\n', '', 1),
    ('P07', "O-61: PG_VERSION is read by its start (the old limit of 64 KiB is not back)",
     "                    head = entry.peek(64).split(b'\\n', 1)[0]\n",
     "                    head = entry.read_all(ha_odoo.MAX_SMALL_FILE).split(b'\\n', 1)[0]\n", 1),
    ('P08', "O-12: HA's tables that are not Omnigent's are not compared (and not moved)",
     '    ignored = set(ignore)\n', '    ignored = set()\n', 1),
    ('P09', "O-28: an entry of the dump list that is not this device's is not selected, it does not stop",
     '                    if skipped is not None:\n                        skipped.add(match.group(2)[:200])\n                    continue\n',
     "                    raise BackupError('incompatible', 'HA 的資料庫匯出清單有不屬於這台 Omnigent 資料庫結構的資料項目，無法安全地搬過來。')\n", 1),
    ('P10', 'O-28: a trusted name twice in the dump list stops the conversion',
     '                if entry.groups()[:2] in named:\n', '                if False:\n', 1),
    ('P11', 'O-21: an artifact key may not contain a . or .. part',
     "        part and part not in ('.', '..') and len(part) <= MAX_PART_CHARS", '        part and len(part) <= MAX_PART_CHARS', 1),
    ('P12', 'O-21: the locations that could leave the store are cleared in the new cluster',
     '        blank_locations(pg, unsafe)\n', '        pass\n', 1),
    ('P13', 'O-21: they are cleared by the role without privileges',
     '    loader = ha_odoo.Cluster(cluster.tmp, cluster.role, superuser=RESTORE_ROLE, log=cluster.log)\n    loader.script("UPDATE',
     '    cluster.script("UPDATE', 1),
    ('P14', 'O-21: nothing unsafe is left in the new cluster after the clearing',
     '        if bundle_locations({\'keys\': pg.query_json(KEYS_SQL, DATABASE) or {}})[1]:\n', '        if False:\n', 1),
    ('P15', 'O-22: files the database names that the backup lacks are asked about',
     "    if lost:\n        sink.confirm('omnigent.files-missing'", "    if False:\n        sink.confirm('omnigent.files-missing'", 1),
    ('P16', 'O-12/O-14/O-15/O-16: what is left out is asked about (the one line)',
     "    if names.count:\n        what = ", "    if False:\n        what = ", 1),
    ('P17', 'O-18: a PostgreSQL that is newer than the image stops this app',
     '    if ha_major is not None and target_major is not None and ha_major > target_major:\n',
     '    if False:\n', 1),
    ('P18', "O-18: an image without PG_MAJOR is no gate",
     '    if ha_major is not None and target_major is not None and ha_major > target_major:\n',
     '    if ha_major is None or target_major is None or ha_major > target_major:\n', 1),
    ('P19', 'O-25: a version that differs is a notice, never a stop',
     "        sink.notice('omnigent.version-different',", "        sink.stop('omnigent.version-different',", 1),
    ('P20', 'O-32, O-33, O-58, O-59: the snapshot is taken again',
     '    return hatarget.retry(attempt, attempts=SNAPSHOT_ATTEMPTS,', '    return hatarget.retry(attempt, attempts=1,', 1),
    ('P21', 'O-59: each try waits longer for the columns',
     "        script = script.replace('__WAIT__', str(60 * len(tries)))\n", "        script = script.replace('__WAIT__', '60')\n", 1),
    ('P22', 'O-23 (snapshot): a snapshot id that is no id is never tried again',
     "    return hatarget.transient(error) and getattr(error, 'returncode', None) != 23\n",
     '    return hatarget.transient(error)\n', 1),
    ('P23', 'O-42, O-43: a structure that is still moving is waited for',
     '    return hatarget.retry(attempt, attempts=STEADY_ATTEMPTS,', '    return hatarget.retry(attempt, attempts=1,', 1),
    ('P24', 'O-40, O-41: an odd answer of this device is read again',
     '    return hatarget.retry(action, attempts=READ_ATTEMPTS,', '    return hatarget.retry(action, attempts=1,', 1),
    ('P25', 'O-44: only the version of an extension may differ',
     "    if len(now) != len(found) or len(live) != len(trusted) or set(now) != set(live):\n", '    if False:\n', 1),
    ('P26', 'O-44: a newer extension version of the new cluster is no difference',
     "        if versions is not None:\n            differ.remove('extensions')\n", '        if False:\n            differ.remove(\'extensions\')\n', 1),
    ('P27', 'O-56: no promise about this device\'s DDL is asked of the compatibility entry',
     'def _convert_candidate(work, app, test_mode, out_dir, *, schema_ddl_quiesced=None):\n',
     'def _convert_candidate(work, app, test_mode, out_dir, *, schema_ddl_quiesced=None):\n'
     "    if schema_ddl_quiesced is not True:\n        raise BackupError('incompatible', '目標資料庫結構變更未暫停，無法擷取安全快照。', app=app.id)\n", 1),
    ('P28', 'O-09: this device\'s accounts that cannot be read are not kept and the import goes on',
     '        if not (isinstance(error, _Odd) or hatarget.transient(error)):\n            raise\n', '        raise\n', 1),
    ('P29', "O-09: a read that is refused (not a read that failed for a moment) still stops this app",
     '        if not (isinstance(error, _Odd) or hatarget.transient(error)):\n', '        if False:\n', 1),
    ('P30', "O-07: this device's other volumes of the app are carried",
     '    if target.extra_volumes:   # O-07: this device\'s other volumes of the app, as they are\n', '    if False:\n', 1),
    ('P31', 'O-07: the three volumes of the package must all be there',
     '        if (len(needed) != 3 or not needed <= set(declared) or len(declared) != len(set(declared))\n',
     '        if (len(needed) != 3 or len(declared) != len(set(declared))\n', 1),
    ('P32', 'O-10: HA without an omnigent database stops this app',
     "    if DATABASE not in databases:\n        (sink if sink is not None else haissues.Sink(APP_ID)).refuse(",
     "    if False:\n        (sink if sink is not None else haissues.Sink(APP_ID)).refuse(", 1),
    ('P33', 'O-48: the secrets that are not listed are told in the check',
     '    note_secrets(sink, unregistered_secrets(work, app))\n', '', 1),
    ('P34', 'O-20: a missing login key is told',
     "    if not src.cookie:\n        sink.notice('omnigent.cookie-missing'", "    if False:\n        sink.notice('omnigent.cookie-missing'", 1),
    ('P35', 'O-13: a table HA lacks is found by the comparison of the columns',
     "    differ |= {t for t in set(ha_cols) | set(trusted_cols) if t not in ignored and ha_cols.get(t) != trusted_cols.get(t)}\n",
     "    differ |= {t for t in set(ha_cols) & set(trusted_cols) if t not in ignored and ha_cols.get(t) != trusted_cols.get(t)}\n", 1),
    ('P36', 'O-02: hard links that were copied are told (an auto line)',
     "    if src.pg_links.count:\n        sink.auto('omnigent.hardlinks-copied', f'HA 的資料庫資料夾裡有 {src.pg_links.count} 個硬連結（正常的資料庫不會有），'\n"
     "                  '匯入時會把它們當成一般檔案複製。', src.pg_links)\n    work.phase('check')\n",
     "    work.phase('check')\n", 1),
    ('P37', 'the conversion asks the same questions as the check (the same sink calls, before anything of HA is dumped)',
     '    judge(sink, src, found, live_alembic_value=alembic, ha_major=_ha_major(src), target_major=pg_major(work, app, target))\n',
     '', 1),
    ('P38', 'the blanking role gets the right to read and change ONE column, nothing else',
     "    cluster.script(f'GRANT SELECT (bundle_location), UPDATE (bundle_location) ON public.agents TO {RESTORE_ROLE};\\n', DATABASE)\n",
     "    cluster.script(f'GRANT ALL ON ALL TABLES IN SCHEMA public TO {RESTORE_ROLE};\\n', DATABASE)\n", 1),
    ('P39', 'O-12: the sequences of the tables that are not moved are not compared either',
     '               if ha_seq.get(s) != trusted_seq.get(s) and not (s not in trusted_seq and own(ha_seq[s][1]))}\n',
     '               if ha_seq.get(s) != trusted_seq.get(s)}\n', 1),
    ('P40', 'O-12: the columns of the tables that are moved are what the new cluster is compared with',
     '    return [row for row in columns if row[0] not in set(ignore)]\n', '    return list(columns)\n', 1),
    ('P41', 'O-21: an artifact key has no invisible or control character',
     '        and not any(unicodedata.category(ch) in haissues.HIDDEN_CATEGORIES for ch in part) for part in parts))\n',
     '        for part in parts))\n', 1),
    ('P42', 'O-21: an artifact key has no backslash', "        part and part not in ('.', '..') and len(part) <= MAX_PART_CHARS and '\\\\' not in part\n",
     "        part and part not in ('.', '..') and len(part) <= MAX_PART_CHARS\n", 1),
    ('P43', 'O-21: an artifact key has at most 16 parts', '    return (len(parts) <= MAX_KEY_PARTS and all(', '    return (all(', 1),
    ('P44', 'O-22: the line says when the store holds none of the files',
     "all='（備份的檔案區裡完全沒有它們要的檔案）' if len(lost) == len(set(wanted)) else ''),", "all=''),", 1),
    ('P45', 'pg-stdin F4: a listing that came back short stops the conversion',
     '    if declared is not None and not declared - len(ARCHIVE_SETTINGS) - LISTING_SLACK <= entries <= declared:\n', '    if False:\n', 1),
    ('P46', 'pg-stdin F4: the tolerance is the three archive settings, not more',
     '    if declared is not None and not declared - len(ARCHIVE_SETTINGS) - LISTING_SLACK <= entries <= declared:\n',
     '    if declared is not None and not declared - 30 <= entries <= declared:\n', 1),
    ('P47', 'O-02: a hard link in the cluster folder that came as a copy is told (counted once, at the copy)',
     '            if copied:\n                src.pg_links.add(rel)   # counted once: here, where the copy arrives\n', '', 1),
)


# The test of each protection added in iteration 5: it alone must fail without the protection (--named).
OMNI, SCRIPT = 'tests.backup.test_ha_omnigent.', 'tests.backup.test_ha_omnigent_trusted.SnapshotScriptTests.'
NAMED = {ident: test for test, idents in (
    (OMNI + 'ConvertTests.test_another_structure_version_stops_the_conversion_itself', ('M29',)),
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
    # the summary line is `FAILED (failures=1, errors=2)`; noise can follow it (a tar of a double that is collected later)
    last = next((line for line in reversed(tail) if re.match(r'(?:OK|FAILED)\b', line)), '')
    failures = sum(int(n) for n in re.findall(r'(?:failures|errors)=(\d+)', last))
    failed = [m.group(1) for line in tail if (m := re.match(r'(?:FAIL|ERROR): (\w+)', line))]
    return proc.returncode, ran, failures, list(dict.fromkeys(failed))


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--json')
    parser.add_argument('--only', help='comma separated mutation ids (a part of the list, or of NAMED with --named)')
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
        if args.only:
            wanted = set(args.only.split(','))
            listed = [m for m in listed if m[0] in wanted]
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
