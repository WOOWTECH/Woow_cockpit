# Omnigent trusted-schema candidate — isolated PostgreSQL evidence

Base: `a4f182b`. The public check, convert, and old restore helper remain blocked. This is an internal candidate, not approval to enable import.

On dev-d the outer container was inspected as `running none {}` (network mode `none`, no published ports). A separate container `woowbk-omni-synthetic-20261120` was started from the already-present `docker.io/library/postgres:16.15-alpine3.24` image, with `--network none --pull=never --read-only`, tmpfs PostgreSQL data, socket and `/tmp`, and synthetic trust authentication. No pre-existing application container or volume was mounted or modified. The dedicated container was removed after testing.

The test constructed separate synthetic source, trusted-schema, and destination databases. Source contained an attacker-written `NOT VALID` CHECK on `users` attempting `lo_export` to `/tmp/woowbk-pwned` when `admin` is inserted. It contained a user, a scheduled task, a dependent foreign-key row, an Alembic row and an identity sequence. The actual `restore_trusted_data`, `carry_accounts_restricted`, restricted pause and `finish_trusted_data` functions were called. Result:

```text
PASS synthetic PostgreSQL trusted schema/data-only: {"users" : 2, "admin" : 1, "active" : 0, "child" : 1, "evil" : 0, "role" : 0, "seq" : 2}
PASS malicious CHECK absent; no marker file; loader removed
PASS mismatched extra HA column rejected; data transaction rolled back (users=0)
```

The scripts used for this one-off run are `/tmp/omni_synthetic_test.py` and `/tmp/omni_synthetic_negative.py`; they target only the named synthetic container and require it to be created first. They are not an automated product end-to-end test. `tests.backup.test_ha_omnigent_trusted` additionally checks the data-only TOC, malformed/duplicate lists, restore ordering and the public guards. The pre-existing `tests.backup.test_ha_omnigent` expects the disabled public path to succeed; with the guard retained it reports five failures and two errors.

Not established: full HA archive-to-backup conversion and restore, target-schema snapshot stability under concurrent target DDL, complete adversarial archive coverage, or post-conversion filesystem/config integrity. Preserve the guards until those are independently validated.
