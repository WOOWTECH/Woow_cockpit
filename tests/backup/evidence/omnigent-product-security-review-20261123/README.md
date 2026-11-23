# Omnigent HA import (product path) — independent adversarial security review (2026-11-23)

Lane omnigent-secreview (owner instance SR-OWNER-1942). Reviewed: R-COCKPIT `feat/ha-import-omnigent-product-20261123`
(lane omnigent-product) at `3707724` — its diff against the merge-base with `integration/ha-import-batch1-20261123`
(`82ac971`): `ha_omnigent.py` (trusted schema, data-only restore, the removed `SECURITY_BLOCKER`), `haimport.py`, the
page text, docs and tests — and the shared code that path relies on (`ha_odoo.start_ha_cluster`/`PgSink`/`Cluster`,
`tempctr`, `habackup`, `hacommon`, `nested`). The product lane's later commits are covered in "Final diff".

Fixes: R-COCKPIT `review/omnigent-product-secreview-20261123` (parent `3707724`), to be cherry-picked onto the
product branch: `f13c3bf` (SR-1), `aa5f48e` (SR-3, SR-4), `3b792ee` (SR-2 documentation), `3e7837d` (SR-2b; corrected by `f95d34e`, see SR-2b).
`64081f2` and `4d1a59b` only add harness variants.

**Iteration 2 (2026-11-23 23:28 – 2026-11-24, same owner instance):** a narrow re-review of the product lane's changes
after `7a319f1` up to its head `bd0f630` (product code: only `ha_omnigent.py` — `dump_user` = this review's `f95d34e`,
and `1c81437`, the verifier's finding: HA's answer names through `hacommon.names`), the page's test mode (unchanged
since `3707724`, not covered by iteration 1), re-runs of the relevant attacks on that head, the two gaps the verifier
listed (a real decompression bomb; rollback with a malicious backup), and a recommendation on hardening the shared HA
cluster. Commits: R-COCKPIT `review/omnigent-product-secreview-iter2-20261123` (parent `bd0f630`): `97b21c3`,
`a8a5978`, `e8d608b` (harness and lab probe only), `b85f2c9` (SR-6 fix + tests + mutation M26), and this README with
the evidence `attack-11..` / `hardening-probe-*` (see "Iteration 2" below).

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
| SR-2b | Medium (real on 0.21.0; bounded by `woowbk_restore`) | HA's `pg_dump` ran as the HA server's own OS user (postgres, uid 70) in the same container as that code. Proven (v3b, writing nothing): a process the HA cluster's code left behind (`setsid`) found pg_dump as uid 70 and could OPEN ITS STDOUT FOR WRITING through `/proc/<pid>/fd/1` (a same-uid READ-mode check that Yama `ptrace_scope` 1 does not restrict) and SIGNAL it, i.e. replace the archive the conversion restores; any TABLE DATA entry's COPY statement is SQL pg_restore runs (bounded like v4b: the restricted role). | **Fixed `3e7837d`; corrected by `f95d34e` (product branch `fb37656`)**: pg_dump runs as an OS user that is not the HA server's and owns nothing writable (connects over the socket directory as database user postgres, trust). `3e7837d` used `65534:65534`; the real dev-d flow then FAILED (`podman exec 65534:65534 … 執行失敗（結束碼 255）`: dev-d's owner has 55000 subordinate ids; dev-d attempt 1, kept). `f95d34e` takes the first of 65534/32767/9999/999 that the owner's uid AND gid maps hold, never root or the image's postgres ids (dev-d: 32767); dev-d attempt 2 ran it. The product lane had also written a fixed `1:1` variant (`1b6228e`); it REVERTED it (`1ca1602`) and cherry-picked `f95d34e` (`fb37656`), so only this one SR-2b change is on the product branch, and no dev-d run of the `1:1` variant exists (the product lane stopped those runs before they got the lock). Lab re-run (attack-09 v3b, 65534): stdout open denied, signal denied; conversion OK, restored = live. A server that answers pg_dump falsely can still only produce row data and bare setval statements (SR-3). |
| SR-3 | Low on 0.21.0 (latent; Medium for any schema with a sequence) | pg_dump writes a sequence's `last_value` AS THE SERVER SENT IT into the SEQUENCE SET statement, unquoted (PostgreSQL `src/bin/pg_dump/pg_dump.c` `dumpSequenceData`). Proven (pg_dump 16.16): a table made a sequence in the catalog (relkind `S` + a `pg_sequence` row) with a TEXT `last_value` gave an archive whose SEQUENCE SET entry is a whole `DO` block (`pg_restore -f -` shows it). 0.21.0's schema has no sequence, so data_only_toc's strict names refuse it (v4). With a trusted sequence of the same name (v4b, simulating a future schema) the real check passed, the real convert SUCCEEDED and the injected SQL ran in the new cluster as `woowbk_restore`: CREATE TABLE / CREATE FUNCTION / SUPERUSER / `pg_read_file` / `COPY TO PROGRAM` denied; TEMP table, its own role setting, `UPDATE scheduled_tasks`, `SELECT users` allowed; the exported cluster kept two extra (empty) temp namespaces. | **Fixed `aa5f48e`**: the selected SEQUENCE SET entries are printed by pg_restore itself (`-f - -L`, the text `-d` runs) before anything is restored and must be exactly one `SELECT pg_catalog.setval('public.<trusted>', <integer>, true|false);` each after pg_restore's own header lines (taken from real 16.16 output). Unit test (5 subtests; all fail without the check). Real re-run (attack-06 v4b): refused before any data load. |
| SR-4 | Low | HA-controlled names reached blocker messages raw: v4's check blocker carried a LINE BREAK from a crafted table name (`hacommon.names` cut at 60 characters but kept control characters) → job-log/page line forging (the page renders text nodes only: no HTML injection). | **Fixed `aa5f48e`**: `hacommon.names` shows control characters (C0, DEL, C1, U+2028/2029) as `?`; alembic values go through it. Unit test (fails without the fix). |
| SR-4b | Low (verifier 2026-11-23, in SR-1's fix) | `require_answers` listed the KEY names of HA's answers raw in HA_ANSWERS_DIFFER (no `hacommon.names`, no length cap). Iteration 2 made it real (v2b): a plpgsql `json_build_object` with DETAIL_SQL's exact argument types, first on HA's per-role `search_path`, added a key with a line break, U+2028 and 300 characters; the check could not see it (0 warnings). | Fixed by the product lane `1c81437`; real proof on `bd0f630` (v2b): convert stops `incompatible`, the name is shown as `atk?2026-11-23T15:00:00Z JOB DONE: every app imported?yyyyyy` (no line break, 60 characters). |
| SR-6 | Low (shared `jobs.py`: every HA import, every job) | A job log line could be FORGED. `JobStore.append_log` replaced only `\r` and `\n`, but `read_log` (what the page shows) split with `str.splitlines()`, which also splits on `\x0b \x0c \x1c-\x1e \x85 U+2028 U+2029`. HA-chosen text reaches the log as HA wrote it: the HA backup's NAME (`hastore` refuses only C0 controls, so U+2028 passes; `haimport` logs 「檢查 HA 備份「name」」: 200 characters of any text) and Omnigent's/Odoo's `PG_VERSION` text (16 ASCII characters; PostgreSQL reads only the number of its first token, so `16.\x0bFORGED OK` starts). Real on `bd0f630` (v7): 9 lines logged, 11 read back, one starting `FORGED`. No code, no secret: it can only mislead a reader of the log (the job's state is shown separately). | FIXED `b85f2c9` (iteration 2): `append_log` turns every C0/C1 control and U+2028/U+2029 into a space, `read_log` splits on `\n` only (an older log still reads one line per newline). Tests `test_jobs…test_a_log_line_stays_one_line`, `test_ha_omnigent.CheckTests.test_has_pg_version_and_backup_name_cannot_forge_a_job_log_line` (both fail with the writer reverted; the first also with the reader reverted), mutation M26. Real re-run on the fixed engine: see Iteration 2. |
| SR-5 | Info (UX) | HA data that violates one of this device's CHECK constraints (HA's own constraint dropped; constraints are not compared) stops the data load with the generic `podman exec … 執行失敗（結束碼 1）`. No leak: the canary row was in the kept stderr (PostgreSQL "Failing row contains") but in no message or log line (v5). | Fixed by the product lane `ae29256`: such failures now end `incompatible` with a plain message (DATA_REFUSED), chosen from pg_restore's kept stderr, which is still never shown; reviewed (the classification only changes the message of a failure that already stops the job). |

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
- Added in iteration 2 (the verifier noted these were tried only partly and not listed): rollback with a MALICIOUS
  backup on dev-d (needs dev-d's installed Omnigent; dev-d was held by the priority lanes all night). What bounds it:
  a malicious backup's converted volumes hold only this device's schema with HA rows that passed its constraints
  (v1b, v3b, v6: restored schema == live), and the rollback restores the safety backup taken from this device, never
  from HA's data; the product lane's real runs prove restore → injected failure → auto-rollback → rollback with honest
  backups. The CPU side of a decompression bomb (habackup inflates a member to at most max(32 GiB, 100 × its size) of
  work: not run on this production host); v8 covers the disk side. `habackup`/`hastore` refuse only C0 controls in
  names (C1 and U+2028/U+2029 pass): with SR-6 the job log is safe and the Omnigent messages use `hacommon.names`;
  aligning those two `CONTROL_RE` with `hacommon`'s is recommended (shared code, not changed here).

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

Driver: the product lane's `tests/e2e/lab/omnigent_full_flow.py --run --arch x86 --form plain` (wrapped by
`services_a_capture.py`) from this branch, i.e. the real b1 x86 backup through dev-d's INSTALLED Omnigent and the
page's helper commands, the engine of this tree deployed.

- Attempt 1 (`4d1a59b`, lock 515 s): exit 1, 27/29 — `ha-convert-start` failed at the HA export
  (`podman exec 65534:65534 …-hapg` exit 255: uid 65534 is not in dev-d's nested user namespace). Cleanup (catalog as
  found, no job object, staging or key file), leak scan and isolation before/after: PASS. Evidence
  `tests/e2e/lab/evidence/omnigent-product-20261123/omnigent-x86-plain-secreview-fixes-attempt1.json`. This is the
  finding that made the SR-2b correction (`f95d34e`, on the product branch as `fb37656`): a unit- or lab-only fix
  would have shipped broken.
- Attempt 2 (`e463fc5`: product code = `8b78ada` + my `f95d34e`, dump uid 32767 on dev-d): exit 0, **111/111 PASS**, lock 869 s (22:13-22:28), elapsed
  1184 s. The real b1 x86 plain backup through dev-d's installed Omnigent with every fix of this review in the engine
  (SR-1 `require_answers`, SR-3 SEQUENCE SET check, SR-4 names, SR-2b pg_dump as uid 32767 there): check, convert,
  restore with a safety backup, HA's and this device's logins, data, counts, runner online, cookie key, pi volume
  unchanged, live schema = dev-d's; restart; injected failure → rolled back; rollback to the safety backup → dev-d's own
  state; cleanup; leak scan of every registered value; dev-d isolation before and after. Evidence
  `tests/e2e/lab/evidence/omnigent-product-20261123/omnigent-x86-plain-secreview-fixes-attempt2.json`. So the
  answers check does not refuse an honest real backup, and a mapped non-postgres dump uid works in the real flow.
  (Corrected 2026-11-23 by the product lane after the independent verifier: there is no uid-1 run; the product
  branch uses `f95d34e`, and its own real runs of the final engine are listed in
  `tests/e2e/lab/evidence/omnigent-product-20261123/README.md`.)

## Final diff

(Rewritten by the product lane on 2026-11-23 after the independent verifier found the first version stale: it
described `7a319f1` with the reverted `1:1` variant.) Product branch `feat/ha-import-omnigent-product-20261123`: it
cherry-picked these fixes (`95b2338` `65d8a51` `9e5156e` `40844ae` `f3b7d2c` `1203cef` = `f13c3bf` `aa5f48e`
`64081f2` `3b792ee` `3e7837d` `4d1a59b`; then `7452196` `fb37656` `1f77388` = `416fa58` `f95d34e` `e463fc5`, and this
README's `455aeda`) and added: `cdbc430`, `f0a13e1`, `fdf68dd` (docs/backup.md and CONTRACT), `8b78ada` / `fdf68dd`
(mutation check M18..M24), `ae29256` (SR-5: `DATA_REFUSED`), `1b6228e` + its revert `1ca1602` (the `1:1` variant,
gone), `1c81437` (the verifier's Low finding: the names in the SR-1 message go through `hacommon.names`; test + M25),
`deffc57` / `6a17eaa` (its lab driver) and evidence commits. So against this review's code the product engine adds
exactly the `DATA_REFUSED` classification (reviewed above) and the `hacommon.names` call in `require_answers`; the
SR-2b code is `f95d34e`'s.

## Iteration 2 (2026-11-23 23:28 – 2026-11-24): re-review of `7a319f1..bd0f630`, test mode, new attacks

### Verdict

- Product code after `7a319f1` (`git diff 7a319f1 bd0f630 -- backup-engine backup backup-ui` = `ha_omnigent.py`
  only): `dump_user()` is this review's `f95d34e` unchanged (the `1:1` variant is reverted), and `1c81437` passes every
  name of HA's answers through `hacommon.names` (60 characters, C0/C1/U+2028/U+2029 shown as `?`) while the count
  values are integers (`ha_odoo._int`). Sound. A sweep of every other f-string message and log line of
  `ha_omnigent.py` found HA-controlled text only behind `hacommon.names`, `ha_odoo._int` or fixed labels — except
  `PG_VERSION` in the job log, which led to SR-6 (shared `jobs.py`, fixed in `b85f2c9`).
- No open security finding on `bd0f630` + `b85f2c9`. New: SR-4b (the verifier's, fixed by the product lane, now
  proven real: v2b) and SR-6 (Low, fixed here: v7 before/after). Info only: an aborted member pass leaves PgSink's tar
  stream unclosed (a Python "Exception ignored" line on the engine's stderr, v8); `habackup`/`hastore` refuse only C0
  controls in names (see Not covered).
- Re-runs on the head of the attacks the iteration-2 changes touch (v3b SR-2b, v4b SR-3, tar t01-t18) give the same
  outcomes as iteration 1's fixed engine. The test mode is correct against the vendor source and fails closed (v6,
  v6b). A real 3 GiB gzip bomb is stopped by the product's SpaceGuard (v8).

### Test mode (the page's 測試匯入): reviewed against the vendor source

Code (unchanged since `3707724`): after the data load, `require_schema` and `require_answers`, the restore role
(`woowbk_restore`: INSERT for the data load, SELECT on `users`/`scheduled_tasks`, UPDATE only on `scheduled_tasks`) runs `UPDATE scheduled_tasks SET state = 2 WHERE
state = 1`; the superuser then counts `state = 1` on the new cluster and the job fails if any is left; the paused
count (an integer) goes to the log and to the page reminder. Vendor omnigent 0.21.0: `db/db_models.py:1557-1561`
(`active=1, paused=2, deleted=3, completed=4`, CHECK `state IN (1, 2, 3, 4)` at `:1576`); only `state == active` is
dispatched (`stores/scheduled_task_store/sqlalchemy_store.py:314, 335, 1022, 1112`); a completed task becomes active
again only through a user's edit or resume (`_refresh_schedule`, `:917-921`); recovery of an interrupted firing never
resends its prompt (`server/scheduled/fire.py:2264-2267`). So 1 → 2 stops every HA schedule from firing on this
device, and the re-count makes it fail closed. A lying backup cannot skip it: the count is taken on the new cluster
(this device's schema and server), and `require_answers` runs before it (v6b). By design test mode does not touch
HA's public shares, connections or agents (residual risk 1, 2).
Real (table below): with HA tasks in all four states, test mode paused exactly the two active ones and left deleted
and completed rows alone (v6); a backup lying about its active tasks is refused before the pause (v6b).

### What was tried in iteration 2 (all real: lab store, `--network none`, the product's real check/convert)

Engine = the product head `bd0f630` unless a row says otherwise; harness `tests/e2e/lab/omnigent_secreview_attacks.py`
(crafted backups built from the REAL b1 x86 HA cluster, as in iteration 1).

| Attack | Evidence | Outcome |
|---|---|---|
| v2b: forged answer KEY (plpgsql `json_build_object` with DETAIL_SQL's exact argument types on HA's per-role `search_path`; the key holds `\n`, U+2028 and 300 characters) | attack-11 | Check: ok, 0 blockers, 0 warnings (it cannot see the shadow). Convert: `incompatible` HA_ANSWERS_DIFFER before anything is exported; the name shown cut and without line breaks (message 132 characters, 0 line-break characters, longest attacker run 6). Job log through the real JobStore: 8 lines logged, 8 read back. No leak, lab left empty. |
| v7: `PG_VERSION` = `16.\x0bFORGED OK` | attack-12 (head), attack-14 (fixed engine `e8d608b`) | Head: PostgreSQL started on it, check and convert passed, restored schema == live; job log through the real JobStore: 9 lines logged, **11 read back, one starting `FORGED`** (SR-6). Fixed engine (`e8d608b`): the product still logs HA's text as it is (the `\x0b` is in the logged line), but through the fixed JobStore 9 lines logged, **9 read back**, none starting `FORGED`, 0 line-break characters in the log file; check, convert and restored == live as before. |
| v6b: the v2 lying backup (every task active, HA's answers say 0) with TEST MODE on | attack-12 | Check: ok, 0 warnings (the lie). Convert: `incompatible` HA_ANSWERS_DIFFER `scheduled_tasks_active` before the pause and before any export: a lying backup cannot get around the test-mode pause or its warning. |
| v6: HA tasks in every lifecycle state (all HA tasks made active + copies in states 1, 2, 3, 4) — with and without test mode | attack-12 | Check: warns "2 個啟用中的排程 … 測試匯入會先全部暫停". Test mode: paused 2; restored database 0 active, states {paused 3, deleted 1, completed 1}; schema, signature and schema dump == live. Without test mode: paused 0, restored states {active 2, paused 1, deleted 1, completed 1} and the page reminder names the active schedules (residual risk 2, by design). No leak, lab empty. |
| v3b on the head (code in HA's cluster vs. HA's pg_dump) | attack-12 | The HA cluster's code ran again (proof: uid 70, only `lo`, no egress, CapEff 0, NoNewPrivs, read-only root, `/tmp` writable and exec, pids 1024, memory 768m in the lab); pg_dump ran as `dump_user` = 65534 in the lab store: stdout open for write **no**, signal **denied**. Convert ok, restored == live. SR-2b holds on the head. |
| Artifact-store tar attacks t01–t18 on the head | attack-12 | Identical outcomes to iteration 1 (attack-07): every hostile case refused; the accepted ones normalized (symlink dropped, setuid/sticky bits removed, a hard link to the cookie stays the same 0600 file inside `artifacts/`). |
| v8: gzip bomb — one honest 3 GiB file of zeros in `data/postgres` (14 MB backup) | attack-12 | The product's SpaceGuard (lab floor = free space minus 512 MiB) stopped the member pass after 21.8 s: `insufficient-space`, nothing kept (free 17.37 GiB before, 17.38 GiB after), lab left empty. Info: the aborted pass leaves PgSink's tar stream unclosed; Python prints "Exception ignored … write to closed file" when it is garbage-collected (engine stderr only; no effect on the job, its log or data; a `finally` closing the sink with errors suppressed would silence it). |
| v4b on the head (SR-3: a fake sequence value that is SQL, with a trusted sequence of that name) | attack-13 | Check: ok, 0 warnings. Convert: `incompatible` 「HA 的資料庫匯出清單裡的序號（SEQUENCE SET）項目含有序號值以外的內容…」 before any HA row was loaded (the observation hook before the restore role is dropped never ran). Same as iteration 1 after the fix (attack-06). |
| Lab probe of the recommended HA-cluster hardening | hardening-probe-attempt1/2 | See the recommendation below. |

### Recommendation (not a change): harden the shared throwaway HA cluster

Scope: `ha_odoo.start_ha_cluster` (the HA side of the Odoo, n8n, Omnigent and LiteLLM imports), where a crafted HA
catalog runs SQL and shell commands as the database superuser (SR-2; every lab variant v3/v3b proved it). Today it
gets `tempctr`'s flags (`--network none`, `no-new-privileges`, `--pids-limit 1024`, `--memory 2g`, `--read-only`)
and a `rw,noexec,nosuid,nodev` data volume. Lab probe `tests/e2e/lab/ha_cluster_hardening_probe.py` (lab store,
`--network none`, the product's server arguments; evidence `hardening-probe-attempt2.json`):

| | today (A) | recommended (B) |
|---|---|---|
| `/tmp`, `/var/tmp`, `/run` (podman's read-only tmpfs) | **exec**: as the superuser, an image library copied there LOADs (native code in the server) and copied binaries (busybox, `pg_isready`) run, in all three | `noexec`: LOAD refused (`Operation not permitted`), copied binaries refused, everywhere |
| `/dev/shm`, data volume | noexec (refused) | noexec (refused) |
| memory | `memory.max` = `memory.swap.max` = the limit (lab 768m; product 2g, i.e. up to 2g RAM + 2g swap), `oom_score_adj` 200 | 256m, swap 0, `oom_score_adj` 1000 |
| server starts, answers | yes | yes (entrypoint recreates the socket dir 3775) |
| query asking far more than the limit (`work_mem` 2GB, 40M-row DISTINCT) | not run (it would take up to the product's 2g of a host with ~3.5 GB free) | backend OOM-killed INSIDE the container (`oom_kill` 1), server back after crash recovery, nothing outside touched |

Flags (B): `--tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 --tmpfs /var/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777
--tmpfs /run:rw,noexec,nosuid,nodev,size=16m,mode=755 --memory <limit> --memory-swap <same> --oom-score-adj 1000`,
for the HA cluster container only (a `start_ha_cluster` argument, not `tempctr`'s defaults).

- **What it blocks:** the step from "SQL and the image's shell" to "any native code": no attacker library or binary
  can be mapped executable anywhere the server can write, so a kernel-exploit attempt needs a bug reachable through
  the image's own programs. And a memory bomb (HA's per-database `work_mem`/`hash_mem_multiplier` beat the command
  line, SR-2) dies inside a small cgroup, without swap, and is the kernel's first OOM victim under host pressure
  instead of a production service. **What it does not block:** shell scripts through `/bin/sh` and busybox applets
  (`COPY ... TO PROGRAM` still ran `id`), C-language functions pointing at symbols of the image's own libraries (a
  crafted catalog), lying answers (SR-1 handles those) and CPU use (bounded by `--cpus`, the job's time limits).
- **What could break:** (1) `--read-only-tmpfs=false` must NOT be used: it also removes the writable `/dev/shm` and
  PostgreSQL stops at start (attempt 1 of the probe, `hardening-probe-attempt1.json`, and a diagnosis run: `could not
  open shared memory segment "/PostgreSQL.…": Read-only file system`); explicit `--tmpfs` mounts replace podman's
  read-only tmpfs at those paths and the server starts. (2) A limit below a real database's need fails a legitimate
  import (`job-failed`; it fails closed, nothing changes, but the owner cannot import): the analysis queries
  aggregate up to 1,000,000 Omnigent file keys (`MAX_KEYS`) in one JSON value, `psql` buffers each answer, Odoo
  databases are the largest; tmpfs pages count against the same limit. (3) Other images (Debian-based PostgreSQL,
  other majors, ARM) were not probed. Nothing in PostgreSQL needs to exec from `/tmp` (JIT is off; libraries load
  from `$libdir` on the read-only root).
- **How to test it:** (a) unit: `start_ha_cluster` passes the three `--tmpfs` entries, `--memory-swap` equal to
  `--memory` and `--oom-score-adj 1000` for `hapg` only; the new cluster and helper containers keep theirs. (b) lab:
  this probe — B must show `noexec` everywhere, every LOAD/exec refused, the server ready, the memory hog killed
  inside; and the attack harnesses again (`omnigent_secreview_attacks.py v3 v3b`: proof lines `tmp_noexec=1`,
  `memmax`; `litellm_sandbox_review.py`). (c) measure first: read the `hapg` container's `memory.peak` (cgroup v2) at
  the end of the check and the conversion of the largest real backup of each app (Odoo and n8n on dev-c, Omnigent and
  LiteLLM on dev-d, the large-archive fixture, ARM on .54) and set the limit to at least twice the largest peak.
  (d) then the real product flows again on each device with the flags in the engine.


### Unit tests and mutation checks (iteration 2)

- Product head `bd0f630`: the 9 Omnigent modules + `test_b1_01_guard` + `test_ha_common`: 103 tests OK.
- With `b85f2c9`: `test_jobs` + `test_ha_omnigent` 112 OK; `test_ha_redact` + `test_ha_import` 29 OK; the whole
  `tests/backup` suite on `e8d608b` (host-heavy lock): queued behind other lanes' suites at the time of this commit;
  its result is recorded in the next commit (or, if it could not run, there).
- Mutation-checked by hand (throwaway copy): `append_log` reverted → both new tests fail; `read_log` reverted to
  `splitlines()` → the JobStore test fails (the Omnigent test still passes: the fixed writer leaves nothing to split).
  M26 (writer reverted) added to `tests/backup/omnigent_product_mutations.py` for the product lane's next full run.

### Commits of iteration 2 (R-COCKPIT `review/omnigent-product-secreview-iter2-20261123`, parent `bd0f630`)

Cherry-pick onto the product branch the whole range `bd0f630..review/omnigent-product-secreview-iter2-20261123`, in
order: `97b21c3` (harness), `a8a5978` (v8 budget + lab probe), `b85f2c9` (SR-6 fix + tests + M26), `e8d608b` (probe
flags), then the README/evidence commit that carries this section. No conflict expected: `append_log`/`read_log` are
identical on all 25 local branches.
