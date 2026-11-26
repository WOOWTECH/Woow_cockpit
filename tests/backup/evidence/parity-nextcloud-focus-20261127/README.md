# Nextcloud NC-09 / NC-38 / NC-45 (2026-11-27)

Product source `2d9555e4` passed 27/27 checks on a generated PostgreSQL16 database in isolated dev-d: real psql JSON output, ordinary loader, fixed trusted Memories trigger execution, exact definition/privilege/type/shape checks, tamper refusals, unchanged rows, NC09 catalog equality, cleanup and isolation. The integrated source is byte-for-byte the same for these modules.

Targeted final guarded regressions:17 tests,0failures/errors/skips/guardblocks/shimhits, including backup/normal restore/automatic rollback preservation. Earlier module128 passed; subsequent133 had one invalid cancellation-fixture error corrected before the final17. The earlier128 is not presented as a full final-tip suite.

First generated attempt failed because the probe did not forward SQL stdin. The production JSON scalar format was also corrected after review before successful proof. Failed evidence is retained. The initial full-container inventory false check reflects independently restarting Headscale: retained event summary records196 events, zero anonymous-volume creations and ten Headscale lifecycle cycles. No unknown volume was deleted. Final durable volume/catalog/Quadlet invariants and own-resource absence passed.

Vendor fixed definitions are from reviewed Memories v11.1.4 commit3ec040e55d2cfc8bd0e339c6338946d1513d15ae; source hashes are in vendor.json. Full procedure and event history are retained in [lane handoff](../../../../snippets/focus-nextcloud/README.md).

This is generated-database runtime proof plus unit/flow regressions. Original HA Nextcloud full-flow and ten-service commercial acceptance remain pending. `commercial_acceptance`: `not-complete`.
