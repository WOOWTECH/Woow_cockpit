# HA Odoo cold PostgreSQL preservation (2026-11-26)

The isolated dev-c lab found a data-loss gap in H4. Its Odoo catalog declares the whole PostgreSQL data volume and has `postgres: []`. The existing kept-copy path inspected only logical PostgreSQL entries, so a one-action HA import succeeded while a second target database disappeared. The first lab run recorded 31 passing and 2 failing checks; it restored the original Odoo baseline afterwards.

Commits `a32e49be` and `80fb6dcf` derive the cold database service from the installed Quadlets, show its databases in the first HA confirmation, keep a complete cluster copy before the restore, and put databases absent from the new cluster back automatically. If the logical export fails, the import stops before the old volume is replaced. If putting a database back fails, the restore rolls the whole cluster back from the kept copy. An ordinary restore keeps its previous behavior (owner decision H6).

Verification:

- `tests.backup.test_kept`, `test_flows`, `test_ha_odoo`, and `test_ha_import`: 521 run, 0 failures, 0 errors, 2 skipped; `scripts/check_source.py` passed.
- Full guarded `tests/backup` suite on integrated tip `80fb6dcf`: 3,350 tests, 0 failures, 0 errors, 2 skipped, 0 blocked, 0 guard shims used; elapsed 701 seconds. Local output: `/tmp/parity-int-odoo-cold-full-20261126.log`.
- Isolated dev-c, encrypted real x86 HA backup with `odoo18ce`: 37/37 checks passed. A target-only database and its marker row survived the one-action import; the selected HA Odoo database reached the target; the kept copy and automatic put-back were recorded; Odoo web and gateway stayed healthy. The test restored the lab baseline and removed its uploaded file, backup copies, temporary objects, and key file. Leak scan: 0 matches.
- Private, redacted result: `/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/parity-real/runs/odoo-cold-keep-full-20261126.json`.

This dev-c run used public substitute images for the Odoo web and PostgreSQL containers because the original private images were unavailable. It demonstrates the product's data-preservation path on a real PostgreSQL/Odoo lab stack, not acceptance on the original tenant image. No production service was touched. `commercial_acceptance`: `not-complete`.
