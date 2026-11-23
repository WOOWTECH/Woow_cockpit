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

## Unit tests rewritten to the new contract (no coverage deleted)

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

`mutation-check-final.json` (engine `ha_omnigent.py` sha256 f3090f78…, `hacommon.py` 67f2ed25…): baseline 57/57
pass; **24/24 protections caught** -- M01..M17 as above plus M18 `require_answers` (SR-1), M19
`require_sequence_sets` (SR-3), M20 pg_dump under `dump_user` (SR-2b), M21 `hacommon.names` control characters
(SR-4, shared module), M22 `DATA_REFUSED` classification, M23 never root/postgres for the dump uid, M24 the dump uid
mapped in the owner's uid and gid maps. The script now names the module each mutation changes.

Unit tests on this tip: Omnigent modules (`test_ha_omnigent*`, `test_b1_01_guard`, `test_ha_common`) OK;
`test_ha_headscale`, `test_ha_hermes`, `test_ha_litellm_candidate`, `test_ha_flows`, `test_ha_import`,
`test_ha_registry` OK (the shared fake `hab1fakes` now keeps the child's stderr on `CommandError` like
`podman.Runner.run`); `test_ha_emqx`: the same 10 pre-existing PRESERVATION_BLOCKER failures as before.
