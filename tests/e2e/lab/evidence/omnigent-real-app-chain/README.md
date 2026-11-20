# Isolated real-Omnigent cold chain — verified scope

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
