# Frozen P1 handoff

Source commit: `52817237a17aa2d40da8d0d65a97db0e04aa7c02`. P1 Python source, tests and API are frozen. This handoff adds documentation only; no further tests or device activity were performed.

Frozen SHA256 bindings:

- `backup-engine/woowbackup/ha_n8n.py`: `d586ce14709be7dc9e6ffa8d8b70d2fc3f64a77a4541031ebeac94a279fcfedc`
- `tests/backup/test_ha_n8n.py`: `6fabff66531a7f18de2ba6052630b4e0bf87ed1a37b34e36b5b462e4a429eb6b`

## API for shared preflight

`ha_n8n.read_app_connection(runner, current_quadlets)` returns exactly `{'database': str, 'user': str}`. It selects the default/start main container using the n8n data mount, excluding worker/webhook containers. Lower-level `read_target_connection(runner, container)` returns the same fields. Both raise an app-specific stop if the live connection cannot be established.

Call before stopping the application or any DROP. Compare the live database to archived `ha_database`; mismatch requires an explicit reconversion stop. Kuhn owns shared restore preflight, retained/future configuration validation, object owner/access preservation, and LiteLLM DATABASE_URL selection. This live API does not establish configuration edits that the running app has never loaded.

## Final verification references

All logs are under `/tmp/parity-focus-20261127/`. These runs overlap; do not report their sum as a unique test count.

| Log | Passed | Source stage / scope |
| --- | ---: | --- |
| `instance-db-resolution-api-final.log` | 48 | After vendor process-title, actual Config/Env/dotenv, entrypoint environment and API refinements; includes conversion plus old single-DB/cold paths. Before the final queue-selector adjustment. |
| `instance-db-resolution-queue-final.log` | 5 | After the final selector adjustment: excludes shared-volume worker/webhook, tolerates timezone mount, checks reference-host layout and both-database `automation` marker/drop regression. |
| `instance-db-resolution-source-binding.log` | 1 | After source commit: verifies pinned vendor source hashes and actual database/user defaults, including final license/source manifest. |

Every listed run had zero failures, errors, skips, blocked processes and shim hits; `RUN_NATIVE: absent`. The earlier **45-test** `instance-db-resolution-final.log` predates process-title/dotenv/API refinements and is historical evidence only.

The database regression uses the real converter and adapter with a stateful database model; vendor tests execute pinned actual vendor code under existing Node22. These are guarded local/model checks, not native PostgreSQL or HA full-flow acceptance. No additional broad tests are pending in this lane.

No material new finding was identified during this documentation handoff. Once Kuhn's candidate is committed, a bounded read-only review may cover the three accepted findings: application database selection/name drift, object owner/access preservation, and retained database/authentication configuration.
