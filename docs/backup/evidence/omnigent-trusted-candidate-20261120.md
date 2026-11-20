# Omnigent trusted-schema candidate — synthetic evidence

The public check, convert, and old restore helper remain blocked. The internal candidate also fails closed because `capture_consistent_target_schema` has no implemented, authorized snapshot/DDL-lock protocol. No production service was touched.

## Full internal conversion with synthetic HA backup

Run from the worktree:

```sh
PYTHONPATH=backup-engine:. python3 -m unittest tests.backup.test_ha_omnigent_candidate tests.backup.test_ha_omnigent_trusted
```

Result: 8 tests passed. The candidate tests route the importer to `_convert_candidate` **only inside a test patch** and replace target schema capture with a synthetic fixture. They exercise the actual HA outer and add-on tar parsing, PostgreSQL staging/analysis via fake Podman, trusted/data-only restore command ordering, artifact merge, volume output, and backup packaging. Fake Podman is not PostgreSQL: these are not a real PostgreSQL end-to-end test. They also prove that equal Alembic values with different column signatures are refused before data restoration, that a missing snapshot provider is refused, and that the public guards remain closed.

## Reproducible real PostgreSQL probe

Run from this worktree, on the lab host with dev-d already running:

```sh
python3 tests/e2e/lab/omnigent_trusted_pg.py --run
```

The script refuses to start unless labpodman reports dev-d `running none {}` and the already-present image has ID `4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873` (`docker.io/library/postgres:16.15-alpine3.24`). It makes a randomly named, dedicated container using the following nested Podman options, with no ports, host mounts, production data, or secrets:

```text
podman run -d --name <random-synthetic-name> --network none --pull=never --read-only \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev \
  --tmpfs /run/postgresql:rw,nosuid,nodev --tmpfs /tmp:rw,noexec,nosuid,nodev \
  -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_USER=omnigent -e POSTGRES_DB=omnigent <image-id>
```

It generates separate trusted and hostile databases, dumps them, and invokes the actual `restore_trusted_data`, restricted account carry, pause and role cleanup against PostgreSQL. A malicious `NOT VALID` CHECK attempts to write a marker when the preserved account is inserted. It also verifies equal Alembic rows and then adds an extra HA column. The real restore must reject that mismatch before copying data. The script emits only fixed stage names, booleans and the non-secret image ID; it does not print SQL, dump data, stderr or credentials. Finally it force-removes **only its own random container** and checks that it no longer exists.

Recorded output:

```jsonl
{"image_id":"4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873","outer_network":"none","published_ports":0,"stage":"preflight"}
{"carried_account_valid":true,"data_and_sequence_valid":true,"loader_removed":true,"marker_absent":true,"rejected":true,"stage":"malicious_check"}
{"rejected_before_data":true,"stage":"same_revision_column_mismatch","users_empty":true}
{"stage":"cleanup","synthetic_container_removed":true}
```

This probe exercises the real restore helper, not a complete real-PostgreSQL `_convert_candidate` or a restore of the generated backup. The full candidate fixture above exercises its complete control flow with fake container operations. The old `tests.backup.test_ha_omnigent` suite predates the guard and expects the public path to succeed; five assertions fail and two tests error with the expected blocker.

## Snapshot limitation and remaining work

A schema-only `pg_dump` sees a database snapshot; merely reading Alembic before and after it cannot prove that the schema was unchanged. PostgreSQL provides exported snapshots for coordinating transactions, and pg_dump takes shared locks on dumped tables, but a viable design must keep the exporting transaction alive, read the revision in that snapshot, and establish that relevant DDL—including object creation and changes not covered by table locks—cannot race with the dump. Table locks can block other sessions and broad catalog locks may have wider effects. The present user authorization does not permit changing or disrupting the existing service to test such a scheme. Do not infer that `--serializable-deferrable`, two revision reads, or this column comparison alone solve concurrent DDL.

References: [PostgreSQL 16 pg_dump](https://www.postgresql.org/docs/16/app-pgdump.html), [PostgreSQL 16 transaction snapshots](https://www.postgresql.org/docs/16/sql-set-transaction.html), [PostgreSQL 16 explicit locking](https://www.postgresql.org/docs/16/explicit-locking.html).

Before any public enablement, independently establish a bounded and authorized consistent-schema capture protocol, test it against concurrent relevant DDL, run the full candidate with a real synthetic HA PostgreSQL backup and perform backup restore verification. Also review schema/object compatibility beyond the column signature and post-conversion filesystem/config integrity.
