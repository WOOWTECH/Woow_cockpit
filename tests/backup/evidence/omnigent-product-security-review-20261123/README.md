# Omnigent HA import (product path) — independent adversarial security review (2026-11-23)

Lane omnigent-secreview (owner instance SR-OWNER-1942). Reviewed: R-COCKPIT `feat/ha-import-omnigent-product-20261123`
(lane omnigent-product) at `3707724` — its diff against the merge-base with `integration/ha-import-batch1-20261123`
(`82ac971`): `ha_omnigent.py` (trusted schema, data-only restore, the removed `SECURITY_BLOCKER`), `haimport.py`, the
page text, docs and tests — and the shared code that path relies on (`ha_odoo.start_ha_cluster`/`PgSink`/`Cluster`,
`tempctr`, `habackup`, `hacommon`, `nested`). The product lane's later commits are covered in "Final diff".

Fixes: R-COCKPIT `review/omnigent-product-secreview-20261123` (parent `3707724`), to be cherry-picked onto the
product branch: `f13c3bf` (SR-1), `aa5f48e` (SR-3, SR-4), `3b792ee` (SR-2 documentation), `3e7837d` (SR-2b).
`64081f2` and `4d1a59b` only add harness variants.

## How it was attacked (real code, real PostgreSQL, real HA data)

- Harness `tests/e2e/lab/omnigent_secreview_attacks.py <scratch> <out.json> <variant>...`. Every malicious HA backup
  is built from the REAL b1 x86 HA backup (`woow-b1-x86-plain.tar`, sha256 `3871a468…`): the product's own member
  pass streams its Omnigent cluster into a lab volume, a PostgreSQL 16 started on it runs the attacker's superuser
  SQL (what anyone can do on their own HA box), stops cleanly, and the cluster plus the real artifact store become the
  `data/` of a new HA backup (outer tar + gzip inner tar, the real format). The attacker also writes `data/postgres`
  files directly (configuration, recovery and script files).
- The product's code then runs unmodified: `ha_omnigent.check()` and `ha_omnigent.convert()` (member pass, PgSink,
  `start_ha_cluster`, `analyse`, `verdict`, the trusted-schema capture, `restore_trusted_data`, `require_schema`,
  `carry_accounts_restricted`, `audit_new_cluster`, counts, `server_volume`, `nested.check_volume`).
- Only the environment is shimmed: `ha_omnigent.Target` returns a lab target whose "live" database is a lab
  PostgreSQL 16 holding the real Omnigent 0.21.0 schema (schema-only dump of the real backup's cluster: 20 tables,
  16 CHECK constraints, no sequence, alembic `d0a1f879a01d`) plus this device's `admin`/`operator` rows with generated
  canary hashes; `target_version` returns `0.21.0` (no live HTTP server). Simulated steps are named in each result
  (`simulated`).
- Everything ran in the ISOLATED lab Podman store (`~/.woowbk-lab/bin/labpodman`: its own storage, production
  containers are invisible to it; the harness refuses to run any other podman), containers made by the product's
  `tempctr.TempObjects` (`--network none`, `no-new-privileges`, pids and memory limits, read-only root where the
  product asks). Nothing ran on production and no attack ran on dev-d. Only generated test credentials.
- What a restore would install: the converted `omnigent-postgres-data` tar is imported into a fresh lab volume,
  started with the live environment and compared with the live target: `pg_dump --schema-only` text, the product's
  `SCHEMA_SIGNATURE_SQL`, and an independent inventory (functions, triggers, rules, views, policies, event triggers,
  schemas, roles, superusers, role/database settings, large objects, extensions, domains, comments, sequences,
  digests of every default and constraint).
- Leak scan: every job log line, every returned value and every error (`as_dict()` and `str()`) is searched for the
  generated canaries (this device's admin hash; a canary planted in HA's rows). The failed command's stderr, which the
  product keeps on the exception only, is searched separately to show what the product did NOT surface.

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| SR-1 | Medium | The facts the check and the conversion SHOW and VALIDATE (accounts and conflicts, active schedules, public shares, stored external credentials, artifact keys, counts) are answers of HA's own cluster, which the crafted backup controls. Proven (v2): a `pg_`-named schema (catalog rename; skipped by the check's schema list and by pg_dump) of same-row-count views hidden as `pg_trgm` extension members, plus the superuser's per-role `search_path` (per-role settings beat the server's command line). Real check: 0 blockers, 0 warnings, `scheduled_tasks_active 0`; real convert (real move): OK, no active-schedule reminder; the restored database had an ACTIVE scheduled task that would run on this device's runner. The same views hide account conflicts (HA's `admin` silently wins), public shares, encrypted connections and bad/missing artifact keys. | **Fixed `f13c3bf`**: `require_answers()` re-reads `DETAIL_SQL`, `KEYS_SQL` and every table count on the new cluster (HA's data on this device's schema and server, before anything of this device is added) and stops `incompatible` before anything is exported; lists compared as sets, values never repeated in the message. Unit test (5 subtests; all fail with the call removed). Real re-run (attack-08 v2): check still lies, convert refused 「…不一致的項目：scheduled_tasks_active。」. |
| SR-2 | Medium (pre-existing, shared `ha_odoo.start_ha_cluster`; containment held) | A crafted backup runs shell commands INSIDE the throwaway HA cluster during the check: the per-role `search_path` shadows a builtin the product's analysis calls (`pg_encoding_to_char`) with a superuser plpgsql function → `COPY … TO PROGRAM`. HA's per-database `session_preload_libraries` overrode `HA_SERVER_SETTINGS` (`SHOW` = `auto_explain`). Read from inside: uid 70, only `lo`, no route, CapEff 0, NoNewPrivs 1, read-only root, `/tmp` writable and NOT noexec, no secrets, pids.max 1024, memory limit, egress blocked. PgSink's file replacement held (archive off, listen '', ssl off, no shared_preload_libraries, recovery.signal dropped). | Containment is the boundary and held; not changed (shared with Odoo/n8n). Docstrings corrected (`3b792ee`). Every output of that container is now treated as hostile: answers (SR-1), SEQUENCE SET SQL (SR-3), pg_dump's process (SR-2b). Hardening options under "Residual risk". |
| SR-2b | Medium (real on 0.21.0; bounded by `woowbk_restore`) | HA's `pg_dump` ran as the HA server's own OS user (postgres, uid 70) in the same container as that code. Proven (v3b, writing nothing): a process the HA cluster's code left behind (`setsid`) found pg_dump as uid 70 and could OPEN ITS STDOUT FOR WRITING through `/proc/<pid>/fd/1` (a same-uid READ-mode check that Yama `ptrace_scope` 1 does not restrict) and SIGNAL it, i.e. replace the archive the conversion restores; any TABLE DATA entry's COPY statement is SQL pg_restore runs (bounded like v4b: the restricted role). | **Fixed `3e7837d`**: pg_dump runs as `65534:65534` (owns nothing in the container; connects over the 3777 socket directory as database user postgres, trust). Unit test (fails if reverted). Real re-run (attack-09 v3b): `pgdump_uid=65534`, stdout open denied, signal denied; conversion OK, restored = live. A server that answers pg_dump falsely can still only produce row data and bare setval statements (SR-3). |
| SR-3 | Low on 0.21.0 (latent; Medium for any schema with a sequence) | pg_dump writes a sequence's `last_value` AS THE SERVER SENT IT into the SEQUENCE SET statement, unquoted (PostgreSQL `src/bin/pg_dump/pg_dump.c` `dumpSequenceData`). Proven (pg_dump 16.16): a table made a sequence in the catalog (relkind `S` + a `pg_sequence` row) with a TEXT `last_value` gave an archive whose SEQUENCE SET entry is a whole `DO` block (`pg_restore -f -` shows it). 0.21.0's schema has no sequence, so data_only_toc's strict names refuse it (v4). With a trusted sequence of the same name (v4b, simulating a future schema) the real check passed, the real convert SUCCEEDED and the injected SQL ran in the new cluster as `woowbk_restore`: CREATE TABLE / CREATE FUNCTION / SUPERUSER / `pg_read_file` / `COPY TO PROGRAM` denied; TEMP table, its own role setting, `UPDATE scheduled_tasks`, `SELECT users` allowed; the exported cluster kept two extra (empty) temp namespaces. | **Fixed `aa5f48e`**: the selected SEQUENCE SET entries are printed by pg_restore itself (`-f - -L`, the text `-d` runs) before anything is restored and must be exactly one `SELECT pg_catalog.setval('public.<trusted>', <integer>, true|false);` each after pg_restore's own header lines (taken from real 16.16 output). Unit test (5 subtests; all fail without the check). Real re-run (attack-06 v4b): refused before any data load. |
| SR-4 | Low | HA-controlled names reached blocker messages raw: v4's check blocker carried a LINE BREAK from a crafted table name (`hacommon.names` cut at 60 characters but kept control characters) → job-log/page line forging (the page renders text nodes only: no HTML injection). | **Fixed `aa5f48e`**: `hacommon.names` shows control characters (C0, DEL, C1, U+2028/2029) as `?`; alembic values go through it. Unit test (fails without the fix). |
| SR-5 | Info (UX) | HA data that violates one of this device's CHECK constraints (HA's own constraint dropped; constraints are not compared) stops the data load with the generic `podman exec … 執行失敗（結束碼 1）`. No leak: the canary row was in the kept stderr (PostgreSQL "Failing row contains") but in no message or log line (v5). | Not changed (fails closed, safe). |

## What was tried (all real, lab store; evidence `attack-*.json`)

| Attack | Variant / evidence | Outcome |
|---|---|---|
| Malicious DDL visible to the check: plpgsql function that creates a SUPERUSER role, a large object and a database setting, used as column DEFAULT, CHECK, row + statement trigger, view, rule, RLS policy; extra schema and table, large object, SUPERUSER role, database/role settings, `GRANT ALL … TO PUBLIC`, comment, event trigger | v1, attack-07 | Real check: 2 blockers (functions/triggers/views/rules/policies/other schema; EVENT TRIGGER). Real convert: refused by the verdict. Verdict bypassed (simulated): refused by data_only_toc's strict names (the extra table) before any data load. |
| Same DDL on Omnigent's own tables only (restore stage reached) | v1b, attack-09 | Verdict bypassed (simulated): the whole conversion ran (316 s) and what a restore would install = live: same `pg_dump --schema-only`, same signature, 0 functions/triggers/rules/views/policies/event triggers/large objects/role settings, roles [omnigent], no extra schema; no canary leak. |
| Hidden DDL + lying answers (pg_-named schema, extension-member views, per-role search_path), real move | v2, attack-02 / attack-08 | Before SR-1: check 0 warnings, convert OK, restored DB has 1 active task (no reminder); restored schema = live. After SR-1: convert refused (`scheduled_tasks_active`). |
| Code in the throwaway HA cluster (search_path-shadowed builtin → COPY TO PROGRAM), per-database `session_preload_libraries`, crafted `postgresql.conf`/`postgresql.auto.conf`/`pg_hba.conf`/`recovery.signal` | v3, attack-01 | Commands ran (proof above); library override effective; config files replaced; containment held; the conversion's output equal to the live schema; no canary leak. |
| pg_dump's process reachable from that code (same uid, same pid namespace)? | v3b, attack-08 / attack-09 | Before SR-2b: yes (stdout open for write, signal allowed; uid 70 both). After: no (pg_dump uid 65534; open and signal denied); conversion OK, restored = live. With SR-1 in place the hostile-but-truthful backup still converts (no false positive on the real b1 data). |
| Fake sequence (text `last_value` → SQL in SEQUENCE SET), table name with a line break forging a TOC line, domain | v4, attack-03 | Real check: 2 blockers. Verdict and schema_differences bypassed (simulated): data_only_toc refused before any data load. `pg_restore -l` flattens the line break (`237; … TABLE public atk 1; 0 0 TABLE DATA public users omnigent postgres`). |
| Same fake sequence with a trusted sequence of that name | v4b, attack-05 / attack-06 | Before SR-3: check and convert passed, injected SQL ran as `woowbk_restore` (privilege probe above). After SR-3: refused before any data load. |
| Honest sequence of a trusted schema (positive path of the SR-3 check) | v4c, attack-10 | NO RESULT: the harness failed on a `podman container inspect` timeout (120 s) at host load average 164; not retried to spare the host. Covered by the unit tests (every conversion test passes the check with pg_restore 16.16's real header text and a clean setval). |
| Row violating a trusted CHECK with a canary | v5, attack-03 / attack-04 | Data load stops (job-failed); canary not in any message/log/result; it was in the kept stderr only. |
| Artifact store: `..` names, absolute names, symlink out, symlink dir then file below it, hard link to `data/postgres`, to `.cache`, forward, to itself, to a directory, to the cookie, FIFO and device, duplicate file, setuid/sticky modes, control characters in names, store being a file, `x/../..` in the middle, 3000-character path, PAX size lie | tar-attacks, attack-07 | All hostile cases refused (`corrupt-archive`, or `incompatible` for the hard link to the cluster). Accepted: symlink (skipped, not carried), hard link to the cookie (same inode, stays 0600), setuid/sticky (normalized 0644/0755), long names; those trees pass `nested.check_volume` and a real `podman volume import` shows only directories and regular files, modes 600/644/755, nothing outside. |
| Leak of this device's admin hash or HA row data | every variant | No canary in any job log line, result, message or error. |

## Defense in depth that held (B1-01 not reopened)

The original B1-01 finding (HA-written DEFAULT/CHECK/DOMAIN/trigger expressions running with superuser rights and
persisting into this device's database) is NOT reopened by removing the hold:

- v1b / v2 / v3: with malicious objects visible (verdict bypassed) or hidden from the check (real check), the
  conversion ran and what a restore would install was identical to the live target: same `pg_dump --schema-only`,
  same signature, 0 functions/triggers/rules/views/policies/event triggers/large objects/role settings, roles =
  [omnigent], extensions = [pg_trgm, plpgsql].
- The only HA-written SQL that still reached the new cluster was the SEQUENCE SET text (SR-3, reachable only with a
  trusted sequence); it is now validated. HA's data is loaded as `woowbk_restore` (no DDL, no superuser, no file or
  program access: measured in v4b), and `require_schema` (twice), `audit_new_cluster` and now `require_answers` run
  on the new cluster before anything is exported.

## Residual risk (owner awareness)

1. An HA backup is trusted with the app's identity by design: HA's accounts (including admins), HA's session-cookie
   key (`accounts-cookie-secret`: whoever has the backup can mint a session cookie for any account of the imported
   Omnigent, this device's kept `admin`/`operator` included), HA's agents, policies and connections. Import only
   backups you made yourself.
2. A real (not test) move keeps HA's ACTIVE scheduled tasks active: they run agent sessions on this device's runner,
   whose tools run commands with the runner's own logins. With SR-1 fixed the conversion's facts are true; the owner
   may want a real move to pause them too, or to list them before the restore (product decision).
3. Code inside the throwaway HA cluster (SR-2) is contained, not prevented: it can use that container's CPU share,
   pids (1024) and memory (`tempctr.MEMORY` = 2g per container, on a host with ~3.5 GB free and full swap) and write
   into its own volume until the job's Watchdog stops it at the free-space floor (HA-SEC-04). Options: mount `/tmp`
   noexec for the HA cluster (podman's read-only tmpfs is exec), a lower memory limit for it, and client options that
   override HA's per-database/per-role settings (`PGOPTIONS=-c search_path=pg_catalog -c session_preload_libraries=
   -c local_preload_libraries=` with schema-qualified queries). A crafted catalog (edited `pg_proc` rows of builtins)
   still runs code there, so the container stays the boundary.
4. The check page still SHOWS HA's answers before the conversion; a lying backup is stopped by the conversion (SR-1).

## Not covered

- The page in a browser (dev-d publishes no port). A lying backup was not sent through dev-d's installed helper; the
  honest real backups were (product lane, and the fixed-engine re-run below).
- Kernel or container-runtime escapes from the throwaway containers; hosts with Yama `ptrace_scope` 0 (this host: 1).
- Writing a forged archive through pg_dump's pipe end to end (v3b tests the access only, writing nothing).
- PostgreSQL other than 16.15/16.16; Omnigent other than 0.21.0 (alembic `d0a1f879a01d`); ARM HA clusters in the
  attack harness (the product lane's real ARM runs cover the honest path).
- The Hermes FTS/SQLite review (separate manual item) and the Pi agent (out of scope).

## Unit tests

`PYTHONPATH=backup-engine:tests/backup python3 -m unittest`: the Omnigent modules (`test_ha_omnigent`,
`_candidate`, `_trusted`, `_install`, `_install_harness`, `_real_app_fixture`, `_server_volume`, `test_b1_01_guard`,
`test_ha_common`, `test_ha_odoo`) pass; all 431 `tests/backup/test_ha*` tests: only the 10 pre-existing EMQX
PRESERVATION_BLOCKER failures (identical on `3707724` without these changes). Pre-existing flake, not from these
changes: `test_ha_omnigent_real_app_fixture.ProducerContractTests.test_missing_end_truncation_and_timeout_are_not_evidence`
fails about 1 run in 3 on the loaded host, also on `3707724`. Every new regression test was mutation-checked (it fails
with its fix removed). New tests: `TrustedSchemaTests.test_answers_of_has_cluster_that_lie_stop_the_conversion` (SR-1),
`ConvertTests.test_a_sequence_value_that_is_sql_never_runs` (SR-3), `ConvertTests.test_has_pg_dump_runs_as_another_os_user_than_has_server`
(SR-2b), `CheckTests.test_names_from_has_database_cannot_forge_lines` (SR-4).

## Real product-flow re-run of the fixed engine (dev-d)

PENDING (see the lane hand-off): `omnigent_full_flow.py --run --arch x86 --form plain` from this branch @ `4d1a59b`
(engine = the product branch's), queued for dev-d's lock since 21:12 behind litellm_full_flow and emqx-product.

## Final diff

Product branch `feat/ha-import-omnigent-product-20261123` @ `8b78ada` (product lane iteration 2, 21:33): it
cherry-picked these fixes (`95b2338` `65d8a51` `9e5156e` `40844ae` `f3b7d2c` `1203cef` = `f13c3bf` `aa5f48e` `64081f2`
`3b792ee` `3e7837d` `4d1a59b`), added `cdbc430` (docs/backup.md: the two new refusals, accurate) and `8b78ada` (its
mutation check now also removes M18 SR-1, M19 SR-3, M20 SR-2b, M21 SR-4). `git diff 4d1a59b 8b78ada -- backup-engine
backup` is EMPTY: the product code on the branch is exactly the code reviewed and attacked here. The product lane
added no product code after `3707724` other than these fixes.
