# P1: resolve n8n's application database before instance conversion

## Change

`Target` now selects the n8n database using the live n8n application's actual configuration. An instance catalog's `database=postgres` remains the maintenance database, and its user remains the trusted cluster bootstrap role. Server `POSTGRES_DB` never supplies an application database default. n8n's defaults are database `n8n`, user `postgres`.

The fixed reader runs through the existing owner runner. It selects exactly one actual Node n8n start process, including the CLI's `n8n` / `n8n start` process title. It reads only selected settings from that process's initial environment, capturing environment changes made by an entrypoint before exec. Podman has already applied inline Environment, EnvironmentFile and env secrets. The trusted installed n8n vendor Config/Env decorators resolve a class containing only database and user fields; the full DatabaseConfig and password are never instantiated. Its installed dotenv parser reproduces the known CLI's cwd `.env` loading without overriding existing process settings.

Setting-file reads are lazy, regular-file only, at most4096 bytes; unused `_FILE` inputs stay unopened. Probe process bootstrap clears NODE_OPTIONS/NODE_PATH. Limits: 256 processes, 4096 bytes per cmdline, 256KiB selected-process environment input, 64KiB `.env`, 1024-byte returned JSON, 30-second timeout. No shell, database connection, password file, raw environment or raw stderr is returned or logged. Unreadable/stopped/ambiguous application, unknown startup, custom N8N_CONFIG_FILES or code-loading NODE_OPTIONS, unsupported vendor config, malformed identifiers and template DBs stop only n8n before conversion work. Ordinary Node memory/source-map/CA flags are accepted.

## Restore API for Kuhn / coordinator

```python
connection = ha_n8n.read_app_connection(runner, current_quadlets)
# {'database': 'automation', 'user': 'n8n'}
```

Call before services stop or any DROP. Main selection uses `/home/node/.n8n` and default/start command; worker/webhook containers sharing the same volume are excluded, unrelated unsupported mounts are ignored, and ambiguity stops. The lower-level `read_target_connection(runner, container)` has the same result contract. Both are side-effect-free reads of current live state.

The shared HA restore preflight must compare `connection['database']` to marked `ha_database`; a mismatch requires an explicit reconversion stop, even when both databases exist. This lane changes no adapter/shared contract. The API does not claim to resolve a future configuration edit that the running app has never loaded; that belongs to the caller's retained-configuration boundary. Likewise files used at startup must remain stable while reading; custom runtime configuration mutation that cannot be established is unsupported. No arbitrary config code from HA is executed.

## Trusted vendor identity / semantics

`vendor/source.json` binds exact source bytes/hashes to n8n tag `n8n@2.43.6`, revision `ffbb9ec54fc02e7f8b54a0b6f41d0a84d0a817f5` (independently read using git ls-remote). Included: actual Config/Env decorators, database defaults, CLI, entrypoint, licenses. Pinned n8n workspace selects dotenv17.2.3; its parser/package/license are included with individual hashes. No mutable master URL is the evidence anchor.

Vendor `readEnv` prefers a present direct value (including empty) over `_FILE`; only when direct is absent does a nonempty `_FILE` path load content. File content is trimmed; string config then trims and removes matching surrounding quotes. Empty direct settings therefore fail our identifier validation rather than falling back to a file/default. Tests execute this actual pinned Config/Env implementation with DI registration and process locations modeled, using existing Node22's type stripping; production uses the device's installed vendor code directly. No fetching or installation occurs in tests.

## Evidence

- Red: `instance-db-resolution-red.log`: 1 regression failed with old marker `n8n`, expected `automation`.
- `instance-db-resolution-api-final.log`: 48 targeted tests passed, no failures/errors/skips, blocked0/shim0, native absent. Covers live fixed-field reader, actual vendor direct/file precedence and whitespace, defaults, dotenv, entrypoint environment, failure boundaries, conversion, old single-DB and cold paths.
- `instance-db-resolution-queue-final.log`: 5 tests passed after final main-selection refinement, including the real reference queue layout (shared data volume in main/worker/webhook), timezone mount handling, and both-database marker/drop regression.
- Regression runs the real converter plus real instance-import adapter against a stateful database model: both `n8n` and `automation` exist, application envfile names `automation`, converted marker and every converted table/count/dump use `automation`, and the adapter's selective database loader drops only `automation`; unrelated `n8n` rows survive. This is model/Node evidence, not native PostgreSQL or HA full-flow acceptance.

Private/generated fixture diagnostic history is retained in the lane scratch directory. Earlier failures were PATH choosing system Node20 for TypeScript stripping and a test attempting to open a staging dump after normal conversion cleanup; both were fixed without relaxing database checks. No devices, host installs, full suite, common adapter or other worker files were changed.
