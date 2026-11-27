# Stopped-main and destination-endpoint follow-up

This supersedes the source freeze in HANDOFF.md only for the parent-requested lifecycle/endpoint fixes. Existing `read_app_connection(runner, quadlets)` still returns exactly two fields and remains read-only.

## Final API for Kuhn / parent

| API | Result | Service mutation |
| --- | --- | --- |
| `main_container(runner, quadlets)` | Unique main container name | None |
| `read_app_endpoint(runner, quadlets)` | `{'database': str, 'user': str, 'host': str, 'port': int}` | None |
| `read_app_connection(runner, quadlets)` | Exact `{'database': str, 'user': str}` projection | None |
| `read_target_connection(runner, container)` | Same two-field projection for a selected container | None |
| `prepare_app_endpoint(work, app, *, quadlets=None)` | Same four-field endpoint | Temporarily starts stopped main/dependencies; registers restoration in `work.temp(app)` |

All endpoint fields come from the SAME trusted installed Config/Env class and process selection, including actual n8n process.title, entrypoint environment, vendor dotenv, direct/_FILE precedence and defaults. The class contains only database/user/host/port, with String metadata for the first three and Number metadata for port, matching pinned vendor source. No full DatabaseConfig, passwords or raw stderr are returned. Host is a bounded DNS/container name or IP (including IPv6); port is an integer1..65535. Defaults are n8n/postgres/localhost/5432. The earlier pinned source identities/hashes remain unchanged; tests additionally verify actual vendor host/port defaults.

Main selection uses default/start command plus data mount; worker/webhook containers sharing that mount are excluded. Restore must remove its independent backend probe/main selector and consume this endpoint. Matching database alone is insufficient: compare the current host/port to the actual destination catalog PostgreSQL endpoint and reject a mismatch before DROP. Future retained-configuration validation remains in Kuhn's shared boundary.

## Startup and restoration

Target now calls `prepare_app_endpoint` before choosing the converted database. A running main only gets the existing readiness/read check; services are not started/stopped. For a stopped main, the hook reads actual systemd Id/LoadState/ActiveState/Requires/Wants/BindsTo for app container units, including overrides. It validates the reachable graph and starts prerequisites before main with `hatarget.ensure_running` (PostgreSQL readiness for catalog DB containers; fixed endpoint reader for main readiness). Unknown foreign service dependencies, unstable states and cycles stop before starting anything. Standard Quadlet auxiliary resource units retain their normal lifecycle.

The existing ensure_running registers cleanup after successful systemctl start, so the hook also registers `TempObjects.put_back_later` BEFORE each initially stopped service start. This covers a failed or cancelled start that already brought its unit/dependencies up. Cleanup stops main before its prerequisites and does not pass the cancelled watchdog to stop commands. Originally running dependencies remain running. Check/conversion reuse their existing app/job temp lifecycle, including failure and cancellation.

## Exact shared restore caller boundary

Call inside `QuadletPostgresAdapter.preflight()` for validated marked n8n HA inplace restore, before any normal restore service stop/DROP. `flows._preflight` calls adapter preflight before the safety backup; temporary reading must finish and put services back before that phase ends so the safety backup observes original service state.

Provide a scoped work facade containing `runner(app)`, `quadlets(app)` and `temp(app)` returning the SAME scoped TempObjects. Optional `abort`, `sink`/`log` and `ha` retain existing cancellation/reporting/size semantics. Call `prepare_app_endpoint`, compare marked database and catalog host/port, and do any required live preflight capture while the scope remains alive. In `finally`, clean up that scope on success, error and cancellation. Check cleanup's returned pending labels: if services could not be restored, fail preflight and retain existing retry cleanup; do not continue into safety backup/DROP/normal restore. Preserve cancellation as the primary error while retaining cleanup retries.

Do not attach these borrowed-service stop callbacks to a scope that survives into normal restore: a later cleanup could stop a newly restored main. The scoped-hook test explicitly restarts the application after successful preflight cleanup and proves subsequent cleanup has no callback left to stop it. No adapter/common code was changed in this lane.

## Final verification

`/tmp/parity-focus-20261127/instance-db-resolution-stopped-endpoint-final.log`: **33 tests passed**, zero failures/errors/skips/blocked processes/shim hits, `RUN_NATIVE: absent`, 12 seconds. This is the final follow-up source gate, distinct from earlier26/48/45 counts; no counts are summed.

The gate exercises real ensure_running and TempObjects through model HA check/conversion and scoped restore preflight: stopped main+database with running queue retained; partial main/dependency start failure; real flows.Cancelled during start/read; readiness failure; conversion failure after live read; already-running preservation; cycle/foreign-dependency rejection before start; read-only helper does not start a stopped main. Vendor-backed endpoint cases cover direct/_FILE/dotenv/title/default/queue selection and host/port validation. Includes both-database automation marker/drop regression, normal single-DB conversion and cold-volume preservation. No broad suites, native runtime, devices or installs were used.

Final source SHA256:

- `ha_n8n.py`: `cfbd7cd0085225d582d77d0dfcb54569fd3be132c2d0afc52bad9fedcf0159c7`
- `test_ha_n8n.py`: `c66879945a3a58cf2c5ef09bc14392c0779c454b201d79b513104a8ebe0681c1`

Failed initial guard history is preserved: CommandError import corrected to podman; cancellation fixtures corrected to real flows.Cancelled. No production validation was relaxed.
