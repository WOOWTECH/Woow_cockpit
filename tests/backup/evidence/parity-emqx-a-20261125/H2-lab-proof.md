# H2 lab proof (lane EMQX-A, 2026-11-25): does the EMQX package's smoke test fail after a Home Assistant import, and would its upgrade roll back?

Proposed place: tests/backup/evidence/parity-emqx-a-20261125/H2-lab-proof.md (the five small files in the folder h2/ beside it: smoke-lines.txt, check-result-final-tip.json,
authz-facts-after-import.json, leak-scan-run-r4.json, timings.txt; all masked by the lab harness's own redaction, scanned for the lab secret values: 5 files, 0 hits).

ANSWER: YES, in the lab, for the real x86 cold HA backup. After the import the package's own `tests/smoke.sh` FAILS (A4 and A10), so `scripts/upgrade.sh` would roll every
later upgrade back, and its rollback check (`smoke.sh --quick`, which contains A4) fails too ("upgrade failed and the rollback is unhealthy too"). With the one-file draft fix
(a marker file in the data volume turns A4, A5, A6, A10 into warnings) the same install passes. Without the marker the fixed script gives exactly the lines of the unmodified one.

## What was real, what was simulated

REAL (woowbk-dev-d, the lab device: its own rootless Podman, EMQX 5.8.9 image, the product package installed the package's way; the dev-d mutation lock held through
`team/heavy.sh`; `owner.sh d --verify-isolation` = `true none {}` before and after every run):
- The engine of the tip d5ddf6a (45 modules, every SHA-256 equal to the tree) deployed by the lab's own `deploy-src.sh`, driven through the helper commands the page sends
  (`ha-check-start`, `ha-convert-start`, `restore-start`), with the real x86 HA backup of the add-on `woow-emqx` 5.9.1 (cold, encrypted, made on the real x86 HA).
- The package's `tests/smoke.sh` byte-identical to the repository HEAD ea5886c (SHA-256 of smoke.sh, upgrade.sh and common.sh compared with dev-d's copy), run as the owner account
  inside dev-d with its real podman secrets, MQTT clients (pinned mosquitto image) and Dashboard logins.
- The draft fix `fix/smoke-after-ha-import-20261125@1ea37da` (Woow_podman_emqx, local branch, never pushed): its `tests/smoke.sh` in a temporary copy of the package inside dev-d.
SIMULATED / NOT RUN: `scripts/upgrade.sh` itself (it pulls images and backs up; the lab has no network). Its DECISION was taken from the exit codes of the real
`smoke.sh` runs: upgrade.sh runs `install.sh --no-smoke && tests/smoke.sh` and rolls back on a non-zero exit, then runs `tests/smoke.sh --quick` as the rollback check.
Also not covered: other fixtures (the ARM cold backup, lab-made variants), HA without authentication, a device whose built-in authorization source HA does not have.

## Results (final tip d5ddf6a; runs r3 + r4, lock held 1070 s and 938 s; the same numbers on the earlier tip 3fd576d in runs r1 + r2)

| run of smoke.sh | passed | failed | warnings | exit code |
|---|---|---|---|---|
| dev-d as it is (no import), unmodified script | 16 | 0 | 1 | 0 |
| after the import, unmodified, full (upgrade.sh's decision) | 14 | 2 (A4, A10) | 1 | 1 |
| after the import, unmodified, `--quick` (upgrade.sh's rollback check) | 9 | 1 (A4) | 0 | 1 |
| after a restart of emqx.service, unmodified, `--quick` | 9 | 1 (A4) | 0 | 1 |
| after the import, draft-fixed, full | 11 | 0 | 2 (A4 skipped; A5/A6/A10 skipped) | 0 |
| after the import, draft-fixed, `--quick` | 8 | 0 | 1 (A4 skipped) | 0 |
| baseline again (B0 restored, no marker), draft-fixed, full | 16 | 0 | 1 | 0 (the lines equal the unmodified baseline run's) |

Why A4 and A10 fail and A5/A6 pass for this backup: A4 logs in to the Dashboard with the generated password of the package (`woow-emqx-dashboard-password`): HA's Dashboard
accounts replaced the device's (D2), so it answers 401 (admin/public is still rejected: HA's admin has a real password). A10 subscribes to another user's topics and expects the
broker's denial: HA's `no_match` is `allow` (D0), so it is not denied. A5 (anonymous refused) passes because HA's broker has authentication; A6 passes because this device's
bootstrap account `woow` is attached to HA's built-in authenticator (E-68) and HA's rules allow its topic. For other backups A5/A6 can fail too (HA without authentication: S2).

## What the real run proved about the engine (R4, the part of it this run could reach)

- check (it builds the candidate: H7) 269 s at host load ~16, 527 s at load 20-30; convert 406 s / 454 s; restore 81 s / 348 s (with the safety backup and its readback
  "EMQX 還原後核對一致"). The check's answer: importable, no confirmation line for this backup, two lines (the automatic "access settings are HA's", the API-key notice).
- Result on the device after the restore (client probe + the API): HA's Dashboard admin and second user log in, this device's old admin password answers 401; authorization sources
  `[built_in_database, file]` in HA's order with `no_match = allow`, `deny_action = ignore`; authenticator `password_based:built_in_database`; HA's three MQTT users and this device's
  bootstrap user `woow` in the built-in database; 4 ACL rows, 5 retained messages, HA's two rules, HA's API key works; anonymous, wrong password and the banned client refused.
- After the import the file authorization source is `path = data/authz/acl.conf` (HA's own file, imported into the data volume): this device's mounted `acl.conf` is no longer used
  (R4 d answered). EMQX's import MERGES lists (apps/emqx_auth/src/emqx_authn/emqx_authn.erl `import_config` and emqx_authz.erl `import_config`, through emqx_utils:merge_lists: the
  element with the same id/type is replaced in this device's position, new ones are appended; EMQX v5.8.9 source), so right after `data import` the candidate holds (by that rule; the run did not log it) the sources
  `[file, built_in_database]` and an authenticator WITHOUT this device's bootstrap file. The run ended with HA's order `[built_in_database, file]` and the bootstrap file attached,
  and the engine's own read-back (apply_ha_access, E-80: identities, enable flags, order, `no_match`, `deny_action`, bootstrap file) passed: so `conf load --replace` of a changed
  `authentication` list and of a re-ordered `authorization` list WAS accepted by a real 5.8.9 (R4 b, the non-empty part). The order of the data import is config roots first, then the
  tables (emqx_mgmt_data_backup.erl do_import: import_cluster_hocon, then import_mnesia_tabs; R4 a).
- Rolled back to the baseline backup B0: the state digest equals the one before the import, the marker is gone. Leak scan (the harness's, every issued Dashboard token included):
  device 649 files, 104 MB of journal, 0 hits; host evidence 16 files, 0 hits.
- FOUND AND FIXED by it: the conversion's job log named THIS device's own no-match rule (read before the import) as HA's ("改成 HA 的「deny」" while HA allows); commit d5ddf6a,
  two tests fail on the old line, the final-tip run prints 「允許」.

NOT proven by this run (still R4 for the REAL lane; the EMQX source, v5.8.9, says what should happen): `authentication = []` through `conf load --replace` (S2, HA without authentication:
a plain-list replace by `[]` makes emqx_authn_config delete every authenticator, post_config_update `delete_authenticators`: should work); the two-step removal of a built-in source that
HA does not have (`ensure_deleted(#{enable := false}, _) -> ok` skips `emqx_authz_mnesia:destroy`, which clears `emqx_acl`; `update/1` of the built-in source clears nothing: the ACL rows
should survive); the real output of a partial import (E-67: the code reads root and table names out of it); HA's add-on option `env_vars` (D0 4, not read: READ's policy); the ARM
fixture and the lab-made variants.

## How to run it again

`scratchpad/parity-emqx-a/h2/run_h2.sh TAG steps...` (a scratch driver outside the repository that reuses `tests/e2e/lab/emqx_product_real_ha.py` of a clean detached worktree of the tip):
`setup before smoke-base check convert` (24 min hold at most), then `restore smoke-after baseline smoke-fixed-base cleanup leaks`, then `cleanup-baseline`. Each call takes dev-d's
mutation lock itself and goes through `team/heavy.sh` with `HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock`. dev-d was left as found (B0 and the test's backups deleted).
