# Nextcloud focus integration handoff

Source commits: `f7dd2630`, `511fef7a`, `2d9555e4` on `focus/nextcloud-20261127`, based on `e4a0d836`.
The successful runtime proof used exact committed source `2d9555e4c0c180c24ce470e37c6825a135119225`.

Assigned source paths: `backup-engine/woowbackup/ha_nextcloud.py`, the new Nextcloud-only helper
`backup-engine/woowbackup/ha_nextcloud_memories.py`, and `tests/backup/test_ha_nextcloud.py`.
Coordinator-owned registry and shared documentation have not been edited. Apply the three row replacements from
`ha_parity_rows.json` and the text in `CONTRACT.md` / `docs-backup.md` when integrating the lane.

Vendor provenance is in `vendor.json`: local vendor tree and two Git blob/SHA256 hashes, compared byte for byte with
release v11.1.4 commit `3ec040e55d2cfc8bd0e339c6338946d1513d15ae`. Both trigger identity/body and system config were checked.
The key's default is false; SystemConfig reads IConfig::getSystemValue and writes IConfig::setSystemValue. Only after
successful reconstruction does the converted config.php enable `memories.db.triggers.fcu`.

Tests: the original two new regressions failed on the baseline. Live-target22 passed; module128 passed; module133 had a
single test fixture error (invalid cancellation error code), corrected to the real flows.Cancelled exception. The final
focused17 checks passed with zero failures/errors/skips/guard blocks/shim hits. They include changed conversion paths,
catalog recovery/mismatch/cancellation, unknown-name reconfirmation, post-rebuild failures, Memories row loss, old mocked
build results, cold backup, normal directory restore, directory rollback and orchestration safety rollback. No broad suite.

The leased generated PostgreSQL probe uses an existing dev-d image, verified read-only as amd64
`docker.io/library/postgres:16.15-alpine3.24`, ID
`sha256:4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873`. It opens no existing application database. It creates
one randomly named owner container and volume, caps memory/swap at384MiB and CPU at0.5, uses96pids, no network/ports,
read-only root and an ordinary image user. Cleanup intent is set before podman run, so a partial run failure still cleans
the owned name. Durable volume inventory, catalog/Quadlet file hashes, own-object absence and outer isolation must remain
equal. Container lifecycle churn is recorded separately and is not treated as an exact inventory match.

Reviewed lease command, under the global heavy wrapper and the script's dev-d mutation lock:

```sh
python3 -B -I snippets/focus-nextcloud/nextcloud_pg_probe.py --run --out /tmp/parity-focus-20261127/nextcloud-pg-runtime.json
```

The probe records source commit and source hashes, creates two tiny ordinary tables and a plain loader, fires the fixed
trigger, checks unchanged row counts and matching-parent updates, rejects body/security/search-path/trigger/type tampering,
checks full object identity/shape and compares real NC-09 catalog queries. This is a generated database proof; the original
Nextcloud HA full-flow and all-service acceptance remain separate coordinator gates. Never run the probe without a lease.

Runtime result: `generated-pg16-proof.json` has27/27 checks PASS. These are real psql output cells parsed as JSON, with no
mocked database. Table guards, exact function/trigger proof and the privilege scalar explicitly return JSON booleans;
plain PostgreSQL t/f would fail the JSON reader. Source/helper hashes and all observations are recorded in that artifact.
The dev-d lease is released; no further device work is running in this lane.

Attempt1 is retained in `generated-pg16-attempt1-failed.json`. It failed before the table guard; the initial harness omitted
podman exec -i, so setup SQL was not forwarded, and the original product guard scalars also lacked to_json wrappers.
The initial failure did not capture SQLSTATE; do not invent one. Subsequent diagnostics record fixed step/command class,
SQLSTATE where available and bounded private own-fixture stderr. The initial inventory equality remains recorded false.
`attempt1-events.json` preserves a read-only event summary for that interval: exactly one named probe volume created and
removed, no anonymous volume creation, and ten independent Headscale create/start/die/remove cycles. No unknown volume
was deleted. Attempt2's clean baseline is not used to rewrite the historical failed check.

Proposed registry replacements mark NC-09/38/45 done for this implementation plus generated PostgreSQL proof. They retain
the original-flow acceptance limitation. Truly unreadable underlying role/extension catalogs still stop safely: no trusted
source can establish the expected inventory, so replacing it with an empty list or availability inventory would weaken
the required postcheck. This fundamental failure is separate from recoverable combined-query/view reads.
