# Omnigent trusted-schema candidate — isolated evidence

The public check, convert and old restore helper remain blocked. The private candidate now requires its caller to explicitly guarantee that target schema DDL is quiescent during capture. It uses a PostgreSQL exported snapshot provider; this does not itself establish that guarantee for a live service. No production service was touched.

## Provider contract

The provider opens a read-only repeatable-read transaction, takes `ACCESS SHARE` on `public.alembic_version` with a 15-second lock timeout, exports its snapshot, and reads the Alembic values and public table-column signature in that transaction. It rejects an unexpected revision. While the transaction is still open, a schema-only `pg_dump --snapshot` imports that snapshot. It cleans its private temporary files and closes the holder after the dump; an idle transaction timeout bounds orphaned holders. The private candidate compares the target snapshot columns against HA's columns, and compares the reconstructed schema again before restoring HA data.

The caller's no-concurrent-DDL guarantee covers schema objects beyond the locked Alembic table. A table-level lock is not a general lock against creating new tables, changing types, or other DDL; column signatures also do not compare every constraint, function or type property. The public guard must remain until the caller can establish and validate that guarantee for the actual service, and remaining review/restore work is complete. PostgreSQL describes synchronized snapshots and dump locking in its [pg_dump documentation](https://www.postgresql.org/docs/16/app-pgdump.html) and [transaction snapshot documentation](https://www.postgresql.org/docs/16/sql-set-transaction.html).

## Reproducible real PostgreSQL probe

From this worktree on the lab host, with dev-d already running:

```sh
python3 tests/e2e/lab/omnigent_trusted_pg.py --run
```

The script requires labpodman to report dev-d `running none {}` and checks the existing image ID `4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873` (`docker.io/library/postgres:16.15-alpine3.24`). It creates a randomly named, dedicated container, with no ports, host mounts, production data or secrets:

```text
podman run -d --name <random-synthetic-name> --network none --pull=never --read-only --memory 256m --pids-limit 96 \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev \
  --tmpfs /run/postgresql:rw,nosuid,nodev --tmpfs /tmp:rw,noexec,nosuid,nodev \
  -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_USER=omnigent -e POSTGRES_DB=omnigent <image-id>
```

The test creates trusted, HA-source and candidate-destination databases inside that container. It calls the real provider, verifies revision mismatch rejection, and holds the snapshot while a concurrent `ALTER TABLE alembic_version` fails on lock timeout. It runs the actual restricted restore and a malicious source `NOT VALID` CHECK that would write a marker on inserting the carried account. It also invokes `_convert_candidate` with actual PostgreSQL dump, snapshot, column comparison, data-only restore, account carry, and test-mode pause. The candidate test deliberately uses synthetic adapters for HA archive staging/analysis and volume creation/export, and emulates separate clusters as databases in the dedicated container. **It is not an actual HA archive-to-restored-backup integration test.** Separate unit fixtures exercise the HA archive and packaging flow with fake Podman.

The equal-revision negative test adds an extra source column and verifies refusal before any source data is copied. The script prints only fixed stage names, booleans and the image ID; SQL, data, stderr and credentials are not printed. Its `finally` removes only its randomly named container and checks that it is absent.

Recorded masked output:

```jsonl
{"image_id":"4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873","outer_network":"none","published_ports":0,"stage":"preflight"}
{"revision_mismatch_rejected":true,"schema_archive":true,"stage":"snapshot_provider"}
{"concurrent_alembic_ddl_blocked":true,"dump_completed":true,"stage":"snapshot_lock"}
{"carried_account_valid":true,"data_and_sequence_valid":true,"loader_removed":true,"marker_absent":true,"rejected":true,"stage":"malicious_check"}
{"accounts_and_pause":true,"complete":true,"real_snapshot_and_restore":true,"source_analysis_fixture":true,"stage":"candidate_real_pg","volume_adapters_fixture":true}
{"rejected_before_data":true,"stage":"same_revision_column_mismatch","users_empty":true}
{"stage":"cleanup","synthetic_container_removed":true}
```

Run the focused tests with:

```sh
PYTHONPATH=backup-engine:. python3 -m unittest tests.backup.test_ha_omnigent_candidate tests.backup.test_ha_omnigent_trusted
```

Eight tests pass. The older `tests.backup.test_ha_omnigent` suite predates the public guard and expects public import to succeed; five assertions fail and two tests error on that retained blocker.
