# Omnigent HA import through the PRODUCT flow on dev-d (lane omnigent-product, 2026-11-23)

Source: R-COCKPIT branch `feat/ha-import-omnigent-product-20261123` (the product path that replaced the
`SECURITY_BLOCKER` hold; design, unit tests and the 17/17 mutation check in
`tests/backup/evidence/omnigent-product-20261123/`). Driver: `tests/e2e/lab/omnigent_full_flow.py`, wrapped by
`tests/e2e/lab/services_a_capture.py` (one JSON per attempt: exit, fixed status lines only, elapsed seconds, stdout
SHA-256, source commit, `commercial_acceptance: not-complete`). Failed attempts are kept.

What one run is (all through the root helper the Cockpit page calls, inside dev-d; the engine of the attempt's commit
installed by `deploy-src.sh` and checked module by module):

1. setup: schedule timer masked for the run; catalog entry `omnigent` from dev-d's own baseline backup
   `20261119T072103Z-ea792b52` when missing (removed again at the end); device key present.
2. before: dev-d's own markers (`woowbk-lab-baseline` user, project, paused task), live schema signature, the
   runner's pi volume files and the server's cookie key (SHA-256 only).
3. upload (`upload-begin` → copy → `upload-finish` = `hastore.publish`), `ha-check-start`, `ha-convert-start` (real
   SpaceGuard/Watchdog), list row, `inspect`, `restore-start` (safety backup, health checks).
4. verify (b1 harness probe with credential events): HA's admin `woow` and member log in with HA's passwords; this
   device's `admin` and runner `operator` with this device's; HA's admin refuses this device's password; users,
   agent, paused task, session title/labels/comment, attachment SHA-256, member session, alembic, every table count;
   this device's runner logs in and its host comes online; HA's cookie key installed; pi volume unchanged; live schema
   signature equal to before (this device's schema, not HA's); engine status and catalog health URL.
5. restart (`omnigent-server`, `omnigent-runner`) → verify; automatic rollback (one-shot `ExecStartPre` failure →
   `rolled-back`) → verify; manual rollback to the first restore's safety backup → dev-d's own markers, schema, pi
   volume and cookie key back.
6. cleanup (test backups deleted, HA store record deleted when created, catalog as found, no job object, staging or
   key file left) and leak scan (registered values in engine records, uploads, staging, run dir, journal, evidence).

Stated limits: the browser page itself is not driven (dev-d publishes no port; the helper calls are the page's);
no host reboot; the Pi agent / model provider is out of scope; HA's own runner stays offline after the move (by
design); tokens the server issues to the runner itself are not observable by the leak scan; the server-data and
pi-data volumes are live exports during the convert (CONTRACT B1-11, unchanged).

## Attempts

| Backup | Attempt | Commit | Result | Seconds (lock) | What it showed |
| --- | --- | --- | --- | --- | --- |
| x86 plain (`woow-b1-x86-plain`, sha256 3871a468…) | 1 | 805ff1b | exit 1, 110/111 | 949.2 (948) | Every product-flow step PASSED on the real backup into dev-d's installed Omnigent: ha-check 33 s (no blocker, schema equal), ha-convert 79 s (trusted schema enforced end to end), inspect, restore 110 s (safety backup, health ok); HA's `woow`/`b1member` log in with HA's passwords, `admin`/`operator` with dev-d's, HA's admin refuses dev-d's password, agent/paused task/session/labels/comment/attachment SHA-256/member session/alembic/all table counts, dev-d's runner online, HA cookie key installed, pi volume unchanged, live schema signature = before; the same after restart; injected failure → `rolled-back` (191.6 s) and the same checks; rollback to the safety backup (139.2 s): dev-d's markers, schema, pi volume and own cookie key back; cleanup PASS; isolation `true none {}` before and after. FAIL: only the harness leak scan (the b1 driver's `LEAK_SCAN` requires `/var/lib/woowtech-backup/index.json`, which this engine does not keep) -- fixed in the driver's own `LEAKS` program. |
