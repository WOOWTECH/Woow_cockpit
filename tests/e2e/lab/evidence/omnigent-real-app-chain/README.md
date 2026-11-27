# Isolated real-Omnigent cold chain — verified scope

## Latest real run — 2026-11-21: isolated chain passed; slot released

Executed the prepared `d8998cf` chain after Headscale's reported `dbcd6c` pass and
exclusive slot handoff. Actual read-only outer lab inspection returned
`running none {}` before execution; owner-only loopback/memory preflight passed.
All nested device operations used `tests/e2e/lab/owner.sh d`; outer configuration
verification used only the isolated lab wrapper's read-only `inspect`, never host
Podman. No original service was stopped or original volume written by this probe.

The first attempt at `d8998cf` exited 1 at line 400 after `source_cold`:
`cookie_from_container` stripped a newline that `cookie_from_tar` preserved.
The pinned image's `omnigent.server.accounts_secret` source confirms the writer
stores `fresh.encode("ascii") + b"\n"`. A focused synthetic live-reader/archive-reader
regression failed before the fix. Commit `0fd7311` preserves exact cookie-file
bytes while registering both raw and trimmed forms for masking. All **32 focused
local tests passed** after the fix, including retained public guards.

The justified real rerun at **`0fd7311` exited 0**. Evidence:

- [Successful masked JSONL](slot-20261121-0fd7311/run.jsonl),
  [exact tested commit, command and source hashes](slot-20261121-0fd7311/manifest.json),
  [exit status](slot-20261121-0fd7311/exit-status),
  [sanitized postcheck](slot-20261121-0fd7311/postcheck.json).
- [Preserved failed-attempt JSONL](slot-20261121-d8998cf/run.jsonl),
  [failure manifest](slot-20261121-d8998cf/manifest.json),
  [failed-attempt postcheck](slot-20261121-d8998cf/postcheck.json).

The successful run exercised the real Supervisor parser and streamed member,
independent source/target app initialization, real `Target`/`_prepare`, exported
PostgreSQL snapshot, restricted restore, account carry and output-volume boot.
Both snapshot failure probes removed captures and left zero holders. The restored
app passed health, both synthetic logins, prior-token identity and invalid-token
rejection, exact cookie-file continuity, and API session marker ID/title continuity.

Acknowledged producer/consumer coverage includes all eight required login fields,
three cookie sources, and eight private archive scans. Registered raw and escaped
values produced zero evidence hits. App logging was disabled; **zero log reads
were available**, so this is not a claim that app logs were scanned. Both attempts'
stderr was empty. Private inventory and empty stderr capture files were removed
only after comparison; no private credentials or raw responses are published.

Final cleanup reported all synthetic objects removed. Separate postchecks after
both attempts found exactly unchanged container IDs/names/states, volume names,
and secret IDs/names against the pre-run inventory. This also covers the disposable
read-only image-source diagnostic processes. Outer isolation remained
`running none {}`. These inventory comparisons are not content hashes of original
volumes; their contents were not inspected. The heavyweight slot is released.

Scope remains explicit: the catalog and Quadlets are synthetic, and the target's
actual `/v1/info` payload is replayed while its synthetic app is stopped for DDL
quiescence. This is a passing **real synthetic chain**, not blanket commercial
acceptance, real-HA-backup provenance, production discovery, encryption/installer/
rollback acceptance, or a general live-DDL guarantee. Public security guards stay
closed. No Hermes review was performed, reassigned or bypassed; no original
credential replay, conversation runner/model/workspace operation or omnigent stop
was performed. Historical/preparation sections below retain their original scope.


## Independent target and authenticated continuity — verified

Command: `python3 tests/e2e/lab/omnigent_real_app_chain.py --run`. Actual masked stdout is [run-independent-verified.jsonl](run-independent-verified.jsonl); exit 0. The source and target are separate fresh PostgreSQL volumes and are independently initialized by the actual app image with separately generated synthetic credentials. The source's PostgreSQL volume was exported cold and its actual app artifacts were placed in a synthetic HA add-on tar. Product `member_pass`, hardened HA cluster, target exported-snapshot provider, restricted restore, target account carry, output-volume creation and tar validation ran. The target application was stopped before schema capture, satisfying this fixture's `schema_ddl_quiesced=True` precondition.

Both output volumes were installed into new volumes and the actual app image was started against the converted PostgreSQL output. Health passed; the synthetic source and target accounts both logged in; the original source token and a newly issued source token both identified the same `source-admin` via `/auth/me`; an invalid token was rejected with 401/403. The HA source cookie and output artifact cookie matched byte-for-byte. No cookie, response body, password, token, or hash is included in evidence. The probe used product `default_runner`, explicit output bounds, timeouts and abort propagation. Before any resource creation the executed harness checked the random fixture container, volume and secret names were absent; its separate temporary-job names were not yet included in that check. Final cleanup verified all test objects absent, and an independent postcheck found no app-chain secrets. dev-d remained `running none {}`.

The immediately preceding independently initialized attempt had these older assertions but failed cleanup because two generated synthetic secrets were not removed. They were removed by their exact run-specific names and independently verified absent; that attempt was not counted as a passing run. The corrected attempt above adds secret removal and verifies the stricter authentication and cookie properties. Prior evidence with the unbounded runner remains scoped to controlled test data as stated above.

Hashes for the verified run:

```text
01e74f8e14fc1aaafe37abfb3fc896970af55b39f88f3457903b2d7170a58384  backup-engine/woowbackup/ha_omnigent.py
97f62e1d0181cd9e3ca2e88d70a6e4826a74ecbb52b320b79b37c52463773d78  tests/e2e/lab/omnigent_real_app_chain.py
6aefe5a0450284a64fef800067e0a1ec6adeeb7ba8a6f12700b11718b684eb20  tests/e2e/lab/omnigent_lab_runner.py
```

Scope limits: the fixture patches `_prepare` with explicitly created synthetic target metadata; it does not exercise the outer Supervisor envelope, production catalog/Quadlet discovery, packaged backup encryption, production installer, automatic rollback, runner login or workspace, real HA backups, or a general DDL-quiescence mechanism. The first-level target is stopped before snapshot capture and no other target writer exists. Public security guards remain unchanged. The earlier cold-chain run, including its old unbounded lab wrapper, remains limited to controlled synthetic data; its revised bounded wrapper has not been independently rerun.

After the verified run, the preflight was extended to check the temporary job's `ids-pg`, `hapg`, `omni-db` and `controldata` container names and `hapg`/`omni-db` volume names as well. The older cold-chain harness also received absence checks and pre-registration of its own names. This is an offline-tested safety-only harness change; the revised harness has not been rerun in dev-d. Post-change hashes:

```text
9df79026f48fe5e3a8a5e7835032120187d045c82aa9ef4dd7ff3cd15d44608d  tests/e2e/lab/omnigent_real_app_chain.py
96d9d2ff087aa15621d37257f28d732dd659008fad0ed7be5f32bc0bf55a2946  tests/e2e/lab/omnigent_lab_runner.py
8431d366023498228ebd0384f6b810825dbd776b9d3c7bd13392cb375b13374d  tests/e2e/lab/omnigent_ha_chain_pg.py
```

## Historical failed attempt

`attempt-before-independent-target.jsonl` records the earlier run using the actual Omnigent 0.21.0 image and synthetic credentials. The application created the schema, its cold PostgreSQL volume and real artifact tree were wrapped in a synthetic HA add-on tar, the private candidate ran, and the output volumes were installed into new containers. The restored application was healthy; both synthetic accounts logged in and a source token issued before conversion still worked.

This attempt **did not pass as a whole**: cleanup reported false because the synthetic source password secret was not removed by the harness. The secret was subsequently removed by exact name and verified absent; its containers and volumes were separately checked absent. In addition, this earlier attempt cloned the source database to seed the target schema and used an unbounded `subprocess.run` wrapper. Therefore it does not prove independent target-schema trust or bounded execution. It uses controlled synthetic data only. Public guards stayed enabled.

## Next acceptance extension — prepared, not lab-verified

The revised harness wraps the cold add-on in a synthetic Supervisor outer tar and uses `habackup.open_backup` to locate and stream it. Synthetic Quadlet and catalog data now exercise the real `Target` and `_prepare`; only the loopback HTTP transport is replaced with the target app's actual `/v1/info` response captured before that app is stopped for schema-DDL quiescence. The intended marker is a session created and read through the real application API, then read again after restoration. These changes have offline fixture coverage only and have not yet been run against dev-d.

All four synthetic login operations are required to register both `token` and `refresh_token` using the acknowledged event transport copied from the main branch. The expected list is source, target, restored-source, and restored-target login, each with both fields; an extra or missing issued field stops the probe. Source, target, and restored cookie values are privately registered before login. Private fixture archives and readable app-log output are scanned without printing values; the application containers use `--log-driver=none`, so log-read availability is reported rather than assumed. Event/evidence output is checked against raw and JSON-escaped registered values. No runner, model, workspace, real credential or public guard is changed.


## Slot handoff — 2026-11-20, implementation only

Prepared from worktree base `9abec06`. Headscale retains the slot. This revision
has **not** run in dev-d and is **not commercial acceptance**. No Hermes review
was performed, reassigned, or bypassed. Public product files and their guards are
unchanged. Existing historical JSONL records above do not validate this revision.

Every device command now uses `tests/e2e/lab/owner.sh d`; the probe has no direct
host Podman or labpodman call. Because that wrapper cannot inspect outer container
configuration, the slot owner must first verify dev-d is running with outer
`network=none` and no published ports. Only then use the explicit confirmation
flag below. The probe independently checks that the device namespace has only
loopback and at least 1400 MiB of finite cgroup headroom; this is not a substitute
for the outer configuration verification. Do not change network settings, stop
existing services, or remove existing data to satisfy this preflight.

After Headscale releases the slot and the slot is assigned to this probe, run
exactly from the assigned worktree (plain Python, never `-O`, because this existing
harness includes assertions):

```bash
cd /tmp/omnigent-trusted-work
umask 077
run_dir=$(mktemp -d "$PWD/tests/e2e/lab/evidence/omnigent-real-app-chain/slot-XXXXXXXX")
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:. python3 tests/e2e/lab/omnigent_real_app_chain.py --run --outer-isolation-confirmed >"$run_dir/run.jsonl" 2>"$run_dir/stderr.private"
run_status=$?
printf '%s\n' "$run_status" >"$run_dir/exit-status"
```

Keep stderr private; do not publish raw app logs, archives, HTTP responses, tokens,
passwords, cookies, hashes of credentials, or SQL data. Generated test passwords,
login tokens/refresh tokens and cookies are synthetic. No original grant/login
attempt is repeated. Session creation occurs only in the newly created synthetic
application; no conversation runner, model or workspace is configured or invoked.
Do not blindly retry a failed run or remove unknown leftovers.

Required evidence contract for a successful isolated run:

- Exit status 0, no `failed` event, and final `cleanup.synthetic_objects_removed=true`.
- `preflight`: operator confirmation is separate from observed loopback-only state;
  pinned PostgreSQL image and actual app image are recorded by the harness.
- `source_session_marker`: real API create/read; `supervisor_envelope`: actual
  `habackup.open_backup` parser and streamed add-on member.
- `real_target_bootstrap`: independent real-app initialization and login.
  `target_discovery` is emitted only after conversion returns, with real `Target`
  and `_prepare`, **synthetic catalog/Quadlets**, replayed captured `/v1/info`, and
  stopped target app for schema-DDL quiescence. This does not prove production
  discovery or live loopback HTTP transport.
- Both `snapshot_failure` events report removed captures and zero snapshot holders.
- `credential_coverage`: exactly eight field sources (token and refresh_token for
  source, target, restored-source and restored-target logins), three cookie sources,
  eight private files scanned, zero evidence/readable-log hits. Log driver is `none`;
  available log reads are reported and do not prove unavailable logs were scanned.
  Each complete credential event is registered before validation/acknowledgement;
  unexpected issued fields fail before ACK. Missing end, truncation, or timeout
  cannot produce accepted evidence.
- `restored_session_marker`: same real API session ID **and** title;
  `restored_real_app`: health, both logins, old/new source token identity, invalid
  token rejection and cookie-byte continuity; `cold_ha_to_candidate`: actual
  PostgreSQL snapshot/restore and output volumes. No model generation is requested.

Offline verification command (no device commands or commercial claims):

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:. python3 -m unittest tests.backup.test_ha_omnigent_real_app_fixture tests.backup.test_ha_omnigent_candidate tests.backup.test_ha_omnigent_trusted tests.backup.test_ha_omnigent_server_volume
```

Result: **31 tests passed**. Includes public guard retention, real Supervisor parser
with synthetic archives, Target resolution with synthetic Quadlets, marker identity
checks, owner-only namespace/memory preflight, actual credential producer code
against an offline HTTP fixture, extra/missing credential rejection, stream failure,
and escaped-secret evidence suppression. These local fixtures are implementation
checks, not proof of the unexecuted real-app chain. `git diff --check` also passes.
