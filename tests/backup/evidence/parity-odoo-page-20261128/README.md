# Odoo (substitute images) through dev-c's real Cockpit page (2026-11-28)

`odoo_cold_keep_flow.py --run --via-page --source <clean bfe7b914 checkout>` (driver `f4c41494`, merged here) ran the
Odoo cold-cluster keep import on woowbk-dev-c with the documented SUBSTITUTE images (dev-c's original tenant image is
not available to the lab): web `localhost/woow-odoo-substitute:18.0-20260926` (ID 1616522e, digest accb85d5), db
`localhost/woow-odoo-pg17-substitute:0.8.6` (17a06c0a, e2617d46), gateway (47ce8258, 7b40c8ed). The web and db images
were NOT downloaded: they were reloaded from the 2026-11-26 space lane's docker-archives
(`~/.woowbk-lab/evidence/parity-space-20261126/dev-c-images/<id>.docker.tar.gz`, SHA-256 equal to that lane's index)
and match the Quadlet pins exactly.

Under one hold of the dev-c lock: its own fresh baseline backup and an extra target database, the encrypted HA backup
uploaded through the real page, only Odoo selected, the check offering two databases with no default and the page
choosing the named one (woowtest2) from what the check offered, its two confirmation lines (databases left on HA,
other databases on this device) acknowledged once, one import click whose conversion and restore ran as two linked jobs
(the restore keeping a copy of the whole database service), the kept copy and the put-back verified, contact counts and
health, then the baseline restored, every backup the run made deleted, secrets scanned, dev-c exactly as before.
**80/80** in 268 s.

Two harness fixes came from the real runs (no product change):
- attempt 01 refused at preflight (nothing changed): one older Odoo safety backup (20261124T152230Z-5f41c20c,
  protected by the N8-01 n8n receipt) would have been pruned by the product's keep-3 rule; `43b36922`/`0a62fba1` move
  such backups out of the product's view whole before the first restore and return them byte for byte on every path
  (returned: names, mode, owner, mtime, SHA-256, listed as before).
- attempt 02 (59/63; the import itself succeeded, dev-c fully recovered): the product's result lists the restore's
  kept copy as its own row (`li.ha-group-row.ha-kept-item`); the page's exact row count took it for an app row.
  `f4c41494` subtracts kept-copy rows only when the count differs (every earlier config asks the page exactly what it
  asked before).

`page-cold-keep.json` is the capture's fixed-status record (83 lines). Private run:
`~/.woowbk-lab/evidence/odoo-cold-keep/20261128T110324/`, full stdout `/tmp/parity-focus-20261127/odoo-page-20261128-03.private.log`.
Substitute-image evidence is NOT original-tenant acceptance. `commercial_acceptance`: `not-complete`.
