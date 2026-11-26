# Target conversion binds the actual endpoint to catalog PG

Parent authorized the stable shared API from `7cee385d`:

`ha_instance_access.local_backend(found, quadlets, mainFilename, postgres) -> bool`

Target now passes the full prepared endpoint to that helper before projecting database/user, selecting the application DB, or reaching any SQL snapshot/conversion work. It resolves mainFilename using `hacommon.container_file(quadlets, main_container(runner, quadlets))`; the first shared-volume mount may be a worker/webhook and is not the main selector. A remote host or noncatalog port stops this app with n8n.layout-unsupported.

The shared helper owns all matching rules: catalog PG ContainerName/NetworkAlias, a shared non-host/non-none network, port5432. This lane adds no backend-matching implementation. Public endpoint/connection/main-selector APIs and stopped-service lifecycle are unchanged. hacommon is imported at the callsite because a top-level import creates a cycle with its n8n workflow constants.

## Dependencies / integration

Parent explicitly authorized upstream dependency cherry-picks `651afd3c` and `7cee385d`. Local copies are `58bfa8ca` and `f6454d12`; routine context conflicts in upstream snippets/test fixtures were resolved to the exact incoming versions. These are dependency copies only: parent already has upstream changes and should pick only this lane's subsequent binding commit, not replay the local dependency copies. No writes were made in Kuhn's worktree and no shared helper implementation was edited here.

Pinned helper source SHA256: `786df177311ee197e001a461701a6ffadf29c645bf8373ad8e2997884bbb9152` (the published7cee source).

## Evidence

- `/tmp/parity-focus-20261127/instance-db-resolution-backend-final.log`: **8/8 passed**, no failures/errors/skips/blocked processes/shim hits, native absent, 11seconds. Remote host and noncatalog port refuse before snapshot hook/temp import/container runs/output; local PG name and NetworkAlias pass. Includes main filename selection, stopped-state restoration, exact two-field reader projection, normal conversion and cold-volume preservation.
- `/tmp/parity-focus-20261127/instance-db-resolution-backend-queue-order.log`: **1/1 passed**, no failures/errors/skips/blocked processes/shim hits, native absent. Final check puts worker/webhook entries before main, with different networks; verifies the shared helper receives `n8n.container` and the local main endpoint. This overlaps the8-test run and is not an additional unique test count.

Existing fixtures now supply actual local DB host/network rather than an implicit localhost endpoint. Source hashes:

- `ha_n8n.py`: `1f9af9160e5f1430c7ebdbf901ca45c0fb800db8fd815614ba06b3c04fc46744`
- `test_ha_n8n.py`: `d07a90700dd9b457bca157694574db59e8cc09651eb5cb607b08bed952664b0c`

No broad suite, native runtime, devices, installations or extra feature work. Earlier failed fixture/import attempts remain in scratch logs and are not reported as successful gates. The two independent review findings remain Kuhn's fixes; this binding change does not modify their shared files.
