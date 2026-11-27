# Evidence of lane F2-chain (HAOS parity, 2026-11-25) — UNIT LEVEL ONLY

Branch `parity/f2-20261125` (base `feat/ha-import-haos-parity-20261125` = `1dc9108`). Product code: `backup-engine/woowbackup/hachain.py` (new), `jobs.py`,
`cli.py`; tests: `tests/backup/test_ha_chain.py` (new), `test_jobs.py`, `test_ha_cli.py`. `flows.py` and every importer are untouched.
No device, no podman, no systemd unit was used: what is **real** and what is **simulated** is listed below. `commercial_acceptance` stays **not-complete**.

## What was run (all on a clean detached worktree of the commit named in `status.json`, through `team/heavy.sh`)
| What | Result |
|---|---|
| `tests/backup` full, guard `--b1` (no podman, systemd, ssh), tip 6de94f6 | tests=2279 failures=2 errors=3 skipped=1 blocked=6 = exactly the 5 known `test_litellm_lab_runner` guard refusals (`final-b1.head.txt`) |
| `RealBackupTests` (27 real HA backups, offline) | 1/1 OK |
| top-level `tests/test_*.py` through the guard | 153 OK |
| `node tests/backup-ui.mjs` (the page file is not changed by this lane) | 108/108 |
| unit modules of the lane alone: test_ha_chain 102, test_jobs 87, test_ha_cli 71 | OK (also under the guard: 256 tests, no process spawned, nothing blocked) |
| mutation sweep 1 (`mutation-check-first-sweep.json`, commit 906c496): 65 mutations of hachain.py, jobs.py, cli.py + 2 controls | 60 caught; the 5 not noticed (C11, C21, C26, J21, L10) got tests afterwards |
| mutation sweep 2 (`mutation-check-final-tip.json`, tip 6de94f6): the changed and added mutations (13 incl. 2 controls) | 12 of 13 counted caught, C11 is an equivalent mutant (below); controls unnoticed. J26 (stale listing of live imports in a recovery pass) was shown caught by hand: the test fails when the line is mutated |

C11 (`_outer_file_damaged`: the size comparison after the file was opened) is an **equivalent mutant**: `HaStore.get` already refuses a file whose size is not the one
recorded at upload ("找不到指定的 HA 備份"), and `_outer_file_damaged` answers True for any exception, so the comparison is a second guard (as in `haimport._open`) that no
input reaches. `OuterFileTests` shows both outcomes (a damaged member: not damaged; changed, replaced, unreadable, gone file: damaged).

## Real or simulated
* REAL: the `jobs.run_job` loop (locks `flock` on the engine lock, the record locks, the start lock, threads that wait for them, real SIGTERM in the test process, the deferral of a
  signal, recovery of records, retention sweeps), `hachain.py`, `cli.py` commands, `flows.run_restore` (preflight, safety backup, restore, health, automatic rollback) against fake
  adapters, `haimport.run_ha_convert` with the app steps stubbed (cli tests; HA key in memory, registry rows), `nested.py` checks on hostile tars (X-NS rows), the stored HA file probe
  on real `hastore`/`habackup` files.
* SIMULATED: the app adapters (fake: no containers, no systemd), the app conversion steps in the chain tests (stubs), a killed process (`BaseException` whose `finally` blocks run,
  the unit not being alive is a test parameter), the adapter's own refusals for a missing file in the backup (X-AD-30: the real text raised by the fake adapter) and the
  data cut short while it is prepared (X-NS-10: the real `BackupError` of `nested.pipe_from` on a truncated tar, raised where the real adapter raises it).
* NOT DONE (needs the REAL lane, see `FOR-REAL.txt`): isolation, cancel, kill, reboot and memory peak on a lab device; a measured peak of one process for ten apps; the page.

## Rows (all `done` in `ha_parity_rows.json`; each row's tests are listed there)
FL-08, FL-09, FL-20, X-NS-01, X-NS-02, X-NS-04, X-NS-05, X-NS-06, X-NS-07, X-NS-10, X-AR-12, X-AD-20, X-AD-30, X-AD-33. All are `skip_one` rows: the chain makes one job one app, so what one app meets
(the restore check, an unexpected error, a hostile nested archive, an app the backup does not hold, a service that does not start) stops or rolls back that app only; the checks themselves are
not loosened (nested.py is untouched and its real refusal is what the chain tests run).

## Reproduce
    git worktree add --detach <dir> <commit>; cd <dir>
    PYTHONPATH=backup-engine:tests/e2e/lab python3 -m unittest tests.backup.test_ha_chain tests.backup.test_jobs tests.backup.test_ha_cli
    python3 -I evidence/f2_mutations.py --repo <dir> [--only ID,ID] --json out.json        (through team/heavy.sh: it runs the tests ~70 times)
