# Omnigent HA import as a product path (owner decision 2026-11-23, 「決定1 做」)

Branch `feat/ha-import-omnigent-product-20261123` (R-COCKPIT, from `integration/ha-import-batch1-20261123` 82ac971).
The `SECURITY_BLOCKER` hold of `ha_omnigent.py` (review finding B1-01: HA-written DEFAULT/CHECK/DOMAIN expressions
would run as the app's superuser, an `lo_export` code-execution path) is removed in the same change that makes the
product path itself enforce every protection the lab-proven internal candidate had (services-a real runs
2026-11-23, `tests/e2e/lab/evidence/services-a-real-20261123/`), plus the ones a caller used to promise:

| Protection | Where (ha_omnigent.py) | Mutation |
| --- | --- | --- |
| Only HA's TABLE DATA / SEQUENCE SET entries are restored (`pg_restore -L`); HA's DDL, defaults, checks, domains, functions never run | `data_only_toc`, `restore_trusted_data` | M01 |
| Every selected entry names a trusted table/sequence, each once (a name cannot add a dump id of its choice) | `data_only_toc(tables=, sequences=)` | M02 |
| HA's data is loaded by `woowbk_restore` (`NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, no `CREATE`), never the app's superuser | `restore_trusted_data` | M03, M12 |
| Pre-data and post-data come from THIS device's `pg_dump --schema-only` (one exported snapshot) | `capture_consistent_target_schema`, `restore_trusted_data` | M04 |
| No DDL during the capture: the live schema signature, columns and alembic before == after, snapshot columns == live (replaces the caller flag `schema_ddl_quiesced`) | `trusted_schema` | M05, M06 |
| HA's columns (order, types, not null, identity, generated), sequences and types equal the trusted schema (convert refuses, check names the tables) | `schema_differences`, `schema_blocker`, `check` | M07, M15 |
| The new cluster's schema signature equals the trusted one after post-data and after the last write | `require_schema` | M08 |
| The new cluster holds only its bootstrap role, no role/database setting, no ALTER SYSTEM setting, no large object | `audit_new_cluster` | M09 |
| This device's admin/runner accounts and the test-mode pause are written by `woowbk_restore`, which is dropped before the export | `carry_accounts_restricted`, `convert`, `finish_trusted_data` | M10, M11, M13 |
| Every Quadlet `Secret=` is declared in the catalog before anything runs | `require_registered_secrets` | M14 |
| The new cluster runs with a read-only root and a `noexec,nosuid,nodev` data volume | `convert` | M16 |
| The runner's pi volume is this device's live export (pairing and identity never move) | `convert` | M17 |
| The conversion itself refuses a version that does not match (add-on version table against the live `/v1/info`), not only the check | `convert` (`_prepare`'s blocker) | M29 |
| After the last write every table holds HA's rows (`users` this device's kept accounts too) and the revision is HA's | `convert` (final comparison) | M30–M32 |
| Only a cluster whose stop ended with 0 and that `pg_controldata` calls exactly "shut down" is exported | `convert` | M33–M35 |
| Test mode counts the active tasks again after its pause; one left stops the job | `convert` | M36 |
| Each of the three volume tars is read as a restore would read it (the owner's id maps) before it is packed | `convert` (`ha_odoo.check_volume_tar`) | M37–M39 |
| The capture script dumps the live schema only (`--schema-only`), as the exported snapshot shows it, after it read the revision inside that snapshot again; only a snapshot id reaches pg_dump | `SNAPSHOT_SCRIPT` | M40–M43 |

(M18–M28 are the security review's and the verifier's, listed in the iteration 2 and 3 sections below. M29–M53 were
added in iteration 5, M44–M53 are listed there: the code of these protections has not changed since 82ac971, but no unit
test failed without them until then -- `mutation-before-iter5.json`: 0 of the 25 caught by the tests of fdc922f.)

Removed: `SECURITY_BLOCKER`, `restore_dump` (restored HA's DDL), `carry_accounts` (wrote as the superuser through
`pg_read_file`), `haimport._run_ha_convert(omnigent_candidate=)`. Kept for the lab harnesses of 2026-11-20..23:
`haimport._run_omnigent_candidate` / `ha_omnigent._convert_candidate` (same argument checks) now run exactly the
product conversion; `haimport._install_omnigent_candidate` is the ordinary restore.

## Mutation check (`mutation-check.json`)

`python3 -I tests/backup/omnigent_product_mutations.py --json tests/backup/evidence/omnigent-product-20261123/mutation-check.json`
copies the repository (without `.git`, `node_modules`, `evidence`, `e2e`) to a throwaway folder, removes each
protection there (exact text, applied once) and runs `tests.backup.test_ha_omnigent`, `test_ha_omnigent_candidate`,
`test_ha_omnigent_trusted`, `test_b1_01_guard`, `test_ha_omnigent_install` (51 tests). Baseline: 51/51 pass. Each of
the 17 mutations is caught (1–24 failing tests each). `module_sha256` names the exact `ha_omnigent.py` checked. Offline
only: no Podman, no device, no secret.

## Unit tests rewritten to the new contract

**Correction (2026-11-24, iteration 5).** This heading used to end with "(no coverage deleted)". That was too strong.
`test_counts_that_differ_stop_the_conversion` kept its text, but since SR-1 (95b2338) `require_answers` stops its
conversion first: the final row-count and revision comparison was reached by no unit test any more (the independent
verifier set it to `if False:` and every test still passed). Iteration 5 restored it (below). What the rewrite dropped
on purpose, because the code it tested is gone or the rule changed: the two assertions that `convert` and
`restore_dump` refuse before any work (`SECURITY_BLOCKER`; the new contract test checks what must hold instead), that a
function entry in HA's dump list refuses the conversion (it is skipped now: only data entries are selected; a function
in HA's catalog still refuses it), `REASSIGN OWNED BY woowbk_restore` (no longer used: the tables are this device's
own) and the accounts' temporary file (they travel on the restricted loader's stdin).

* `tests.backup.test_ha_omnigent`: the 7 tests that failed only because of the hold now test the product path (check
  without hold, versions, refusals, schema blocker naming tables; whole conversion: three restores -- trusted pre-data,
  HA data as `woowbk_restore` via `-L`, trusted post-data --, hashes only on the restricted loader's stdin, audit,
  volumes; code in HA's database never runs; a line-break name cannot add an entry) plus `TrustedSchemaTests` (DDL
  during capture, snapshot columns, moved revision, HA columns/sequences/types, defaults/checks/indexes NOT compared
  because never used, restored schema, audit findings, unregistered secrets).
* `test_ha_omnigent_candidate`: the compatibility entries are the product conversion; request fields
  (`schema_ddl_quiesced`, `omnigent_candidate`, `trusted_schema`) are refused by the helper and cannot skip a check.
* `test_ha_omnigent_trusted`: strict data-only list; the old guards replaced by the product checks.
* `test_b1_01_guard`: the unsafe helpers are gone; nothing runs before the secrets are registered; HA's dump only ever
  loaded as data by the restricted role.

## Iteration 2 (2026-11-23 evening): the security review's fixes, two more, the final mutation check

The security review (lane omnigent-secreview, `tests/backup/evidence/omnigent-product-security-review-20261123/`)
found SR-1..SR-5 on this branch. Its fixes are cherry-picked here (SR-1 `require_answers`, SR-3
`require_sequence_sets`, SR-4 `hacommon.names` without control characters, SR-2b HA's `pg_dump` under another OS
user, docs) together with its README and attack evidence. Two more changes of this lane:

* `DATA_REFUSED` (`load_into_new_cluster`, review v5 / SR-5 UX): HA rows that this device's schema refuses (its
  CHECK / NOT NULL constraints at the data load; its primary keys, unique indexes and foreign keys at post-data; a
  value its column types reject) end the job `incompatible` with a plain message instead of
  `podman exec … 執行失敗（結束碼 1）`; pg_restore's stderr (it holds HA's row values) only classifies and is never
  shown or logged. Real check with the review harness in the lab store (real PostgreSQL 16.16, crafted backup from the
  real b1 x86 cluster): `secreview-v5-data-refused-lab.json` (check ok, conversion refused with `DATA_REFUSED`,
  canary in no message, log or kept stderr, nothing left).
* SR-2b on dev-d: the review's `65534:65534` failed in the REAL product flow (dev-d's owner maps only uids
  1..55000, `podman exec` exit 255; evidence `tests/e2e/lab/evidence/omnigent-product-20261123/
  omnigent-x86-plain-secreview-fixes-attempt1.json`). The review's `dump_user` (first of 65534, 32767, 9999, 999 in
  the owner's uid AND gid maps, never root or the image's postgres ids) is the one kept; this lane's own variant
  (fixed uid 1, 1b6228e) was reverted (1ca1602) so that only one SR-2b change exists.

`mutation-check-final.json` (engine `ha_omnigent.py` sha256 44c47017…, `hacommon.py` 67f2ed25…; first run on
f3090f78… 24/24, then rerun after 1c81437): baseline 58/58 pass; **25/25 protections caught** -- M01..M17 as above plus M18 `require_answers` (SR-1), M19
`require_sequence_sets` (SR-3), M20 pg_dump under `dump_user` (SR-2b), M21 `hacommon.names` control characters
(SR-4, shared module), M22 `DATA_REFUSED` classification, M23 never root/postgres for the dump uid, M24 the dump uid
mapped in the owner's uid and gid maps, M25 the names in the SR-1 message through `hacommon.names` (the independent
verifier's Low finding, fixed in 1c81437). The script now names the module each mutation changes.

Unit tests on this tip: Omnigent modules (`test_ha_omnigent*`, `test_b1_01_guard`, `test_ha_common`) OK;
`test_ha_headscale`, `test_ha_hermes`, `test_ha_litellm_candidate`, `test_ha_flows`, `test_ha_import`,
`test_ha_registry` OK (the shared fake `hab1fakes` now keeps the child's stderr on `CommandError` like
`podman.Runner.run`); `test_ha_emqx`: the same 10 pre-existing PRESERVATION_BLOCKER failures as before.

## Iteration 3 (2026-11-24 night): the review's iteration 2 (SR-6), the bidi gap, final checks

The security review's iteration 2 (`tests/backup/evidence/omnigent-product-security-review-20261123/README.md`,
section "Iteration 2") is cherry-picked here (97b21c3 a8a5978 b85f2c9 e8d608b 27b8341 66bb9b6 → 95a1b29 f4ca61c
5b7be1f 1186fbb ee5f7f6 4a3622b): SR-6 (shared `jobs.py`: a job log line stays one line; `append_log` writes every
C0/C1 control and U+2028/U+2029 as a space, `read_log` splits on `\n` only), its tests, mutation M26, the review
harness, its attack evidence and README. `git diff 66bb9b6 4a3622b -- backup-engine backup docs` is empty: the product
code is exactly what the review tested.

One more change of this lane, **97c994f** (the independent verifier's SR-6 gap: Unicode bidirectional controls passed
`jobs.LOG_CONTROL_RE`, `hacommon.names` and the hastore name check, so HA text could reorder how the rest of its line
reads, e.g. U+202E in the backup name): both shared regexes also cover the 12 Bidi_Control code points (U+061C,
U+200E, U+200F, U+202A–U+202E, U+2066–U+2069; log: a space, names: `?`). Tests, each failing with its regex reverted
(checked by hand in a throwaway copy, then by the mutation check): `test_jobs` `StoreTests.test_a_log_line_keeps_its_reading_order`
(the explicit-formatting classes come from `unicodedata`), `test_ha_common` `NamesTests.test_names_carry_no_control_or_bidirectional_character`,
`test_ha_omnigent` `CheckTests.test_has_text_cannot_reorder_a_message_or_a_log_line` (HA backup name and table name
through the real check and the real `JobStore`). hastore/habackup input checks are NOT changed (no backup is refused
for its name; a bidi control in a list cell stays a display-only residual).

`mutation-check-iter3-4a3622b.json` (4a3622b = review e8d608b code; `ha_omnigent.py` 44c47017…, `hacommon.py`
67f2ed25…, `jobs.py` e38ff425…): baseline 59/59 pass; **26/26 caught** (M26 SR-6 caught).
`mutation-check-iter3-final.json` (97c994f; `ha_omnigent.py` 44c47017…, `hacommon.py` ad058935…, `jobs.py` c6e62948…): baseline 60/60 pass; **28/28 caught** (M27 `jobs.LOG_CONTROL_RE` bidi set and M28 `hacommon.CONTROL_RE` bidi set caught by the new Omnigent check test).

Unit and suites:
* 4a3622b: Omnigent modules (9) + `test_jobs` + `test_ha_common` + `test_ha_import` + `test_ha_redact` 215 OK, lab
  Omnigent 20 OK; trial merge into `integration/ha-import-batch1-20261123` 62fa9af (no conflict, `git merge-tree`
  rc 0): the same 215 + `test_ha_flows`/`test_ha_registry` 13 + lab 24 OK.
* 97c994f: every non-EMQX `test_ha_*` module + `test_jobs` + `test_b1_01_guard` 445 OK (1 skipped); `test_ha_emqx*`:
  the same 10 pre-existing PRESERVATION_BLOCKER failures; lab Omnigent 20 OK.
* Full `tests/backup` under the host-heavy lock: 5833258 (= 4a3622b code; lock 02:47:06-02:59:56): 1420 run, not ok = the 10 pre-existing `test_ha_emqx` PRESERVATION_BLOCKER tests + 1 flake `test_bounded_large_archive.HarnessSafetyTests.test_runtime_space_loss_aborts_and_cleans` (its child reported `ImportError` instead of `BackupError` under host load ~25; file unchanged since the base 82ac971, passed in the review's full suite on the same code; reruns of the module: 1 failed, then 6/6 OK); 97c994f (`full-suite-97c994f.json`; lock 03:42:01-03:48:14): 1423 run, 6 skipped, not ok = only the 10 pre-existing `test_ha_emqx` PRESERVATION_BLOCKER tests (the flake above passed).

## Iteration 5 (2026-11-24): the independent verifier's gaps (tests, mutations and text only; no run on dev-d)

The product did not change: `ha_omnigent.py` without its docstrings parses to the same code as at 97c994f (the commit of
the last real run) and at f2c9e03 (the integration tip merged into this branch), and no other file under
`backup-engine`, `backup`, `docs` or `scripts` differs from that tip.

The verifier removed protections one at a time on 97c994f and 7 of them were caught by none of 147 tests (its X7, X8,
X9, X10, X11, X13, X15). Branch `fix/omnigent-test-gaps-20261124` (from integration fdc922f) adds a test for each that
fails when the protection is removed, and the mutations M29–M43 (the verifier's own 7 replacements: M29, M30, M33, M34,
M36, M37, M40; the others are halves and neighbours of them). No test showed a defect: the only change of the product
module is the docstring of `capture_consistent_target_schema` (it still said "The public import remains guarded until
that precondition is established").

| Gap | Protection | Test (fails without it) |
| --- | --- | --- |
| X7 | version refusal of the conversion | `ConvertTests.test_a_version_that_does_not_match_stops_the_conversion_itself`: add-on version of another Omnigent, unknown add-on version, other live version, unreadable live version; exact messages; no throwaway container, HA's cluster not read |
| X8 | final row-count and revision comparison | `ConvertTests.test_counts_that_differ_stop_the_conversion`: what the new cluster answers is changed only after the restricted role was dropped (answers, schema and audit were fine before): a row less, a row more, a table without an answer, the kept accounts missing, two tables, another / a second / no revision; nothing exported, cluster not stopped |
| X9 | the new cluster's stop code | `ConvertTests.test_a_cluster_that_did_not_stop_cleanly_is_never_exported`: 137, 1, 143; not even `pg_controldata` runs |
| X10 | `pg_controldata` "shut down" | `ConvertTests.test_only_a_cluster_that_pg_controldata_calls_shut_down_is_exported`: every other state of PostgreSQL 16 and no state, in its whole output; live image, volume read only, no network, read-only root |
| X11 | test mode's second count of active tasks | `ConvertTests.test_test_mode_that_left_a_task_active_stops_the_conversion` |
| X13 | `check_volume_tar` | `ConvertTests.test_a_volume_podman_could_not_import_is_never_packed`: an owner id outside the owner's maps, a symlink out of the volume, a device node, in the database, server and pi volume |
| X15 | `--schema-only` of the capture | `SnapshotScriptTests` (`test_ha_omnigent_trusted`): the real script under a real shell with stand-ins for psql and pg_dump: pg_dump's exact arguments, the transaction still open while it runs, the archive without the columns line (0600), the private folder removed; another revision, no revision, no or a wrong snapshot id, a lock not granted and a failed pg_dump never become a schema |

### The same question asked of the other refusals (tests only, same branch)

X7–X15 were found by removing some protections. Every refusal of the module, and ten protections that are no refusal,
got the same question.

* **`omnigent_product_mutations.py --refusals`** (new) removes what the module itself says no to, one at a time: all 61
  `raise` statements and collected blockers or problems, and all 48 operands of an `or` that decides about one. (How many
  of the 61 no test failed without before iteration 5 was not measured; of the 48 operands it was 12 at a85e0ef: 10 have
  a test now, 2 are redundant, see below.) Tests added:
  * `RefusalTests` (new): a device that is not set up like the package is no target (database items, host folders, a
    missing PostgreSQL/server/runner file, one volume more, less or of another name, two folders in one volume, another
    database, user name or data folder, no image); what HA's database must be (each part of the verdict on its own, in
    the check and in the conversion); answers that are not what was asked for (no database, no objects, columns,
    signatures, revisions, accounts, audit: nothing, the wrong type or a part missing, from HA's, the live and the new
    cluster); a live version that cannot be read (an error page, no JSON, no text, not x.y.z; a health address that is
    not the loopback one is never asked); a schema that changed with the last write; the space check of the conversion.
  * `ConvertTests.test_the_sequence_script_is_one_setval_for_each_selected_sequence`: SR-3's rule on its own (nothing
    but comments after a setval, not even one of pg_restore's header lines: an injected value that ends in a comment
    could set a search path; as many setval as selected entries, each of another trusted sequence).
  * a secret declared twice, a tablespace or symlink in HA's cluster, no or a malformed expected revision before the
    capture, captured columns that are not JSON, an object, a number, empty or have a short row, the whole list
    `SIGNATURE_KEYS`.
* Two operands cannot decide alone (`REDUNDANT` in the script, printed as such): `entry.linkname == ARTIFACTS`
  (`habackup.iter_entries` hands out no hard link to a folder and no entry below a file) and `not self.pgdata` (None only
  without a data mount, which the volume comparison before it refuses).
* **M44–M53**, protections that are no refusal: HA's cluster and its volume are removed before the new cluster starts
  (M44); the new cluster is ready when it answers on TCP, not the image's temporary server of its first start (M45);
  HA's dump, this device's schema dump and the new cluster's export are 0600 in a 0700 folder (M46–M48,
  `test_what_the_job_writes_is_private_to_it`); the space check before a cluster starts (M49); a live account row nobody
  asked for is not carried (M50); the live version is asked on the loopback address only, from an answer with status 200
  and only x.y.z (M51–M53).

Not claimed: that every statement of the module has a test that fails without it. Mutated were the list, every refusal
and every `or` operand of a refusal.

### Results (offline: no Podman, no device, no secret; heavy steps through heavy.sh)

| Record | Commit | What ran | Result |
| --- | --- | --- | --- |
| `mutation-before-iter5.json` | fdc922f (the base) | M29–M53 against the tests as they were before iteration 5 (63) | 0/25 caught |
| `mutation-named-iter5.json` | 01b36b4 | `--named`: M29–M53, each against its own test alone (13 tests) | 25/25 caught |
| `mutation-check-iter5.json` | 04d8e50 | the whole list M01–M53 against the six Omnigent modules (80 tests) | 53/53 caught |
| `mutation-refusals-iter5.json` | 04d8e50 | `--refusals`: 61 statements and 48 operands | 107/109 caught, the 2 of `REDUNDANT` not |
| `full-suite-iter5.json` | 01b36b4 | full `tests/backup` under the host-heavy lock | 1681 run, OK, 6 skipped |

01b36b4 differs from 04d8e50 only in `omnigent_product_mutations.py` (it names the failing test; `--named`). Both
contain integration f2c9e03. Also run directly on the branch: the six Omnigent modules 80 OK (also without PYTHONPATH,
as CI does, two of them), lab Omnigent 24 OK, `test_ha_registry`/`test_ha_flows`/`test_ha_redact`/`test_ha_common`/
`test_ha_omnigent_install_harness` 41 OK, `scripts/check_source.py` passed. `SnapshotScriptTests` eight times at load
18–20: 24/24 OK; once by hand with busybox ash (the shell of the PostgreSQL image) as `sh`: 3/3 OK. A mutation counts
as caught when the run stops at a failing test (`--failfast`), so `failures` is 1 in these records.

Nothing of this is a real run: the real runs are those of `tests/e2e/lab/evidence/omnigent-product-20261123/`
(`commercial_acceptance` stays not-complete).
