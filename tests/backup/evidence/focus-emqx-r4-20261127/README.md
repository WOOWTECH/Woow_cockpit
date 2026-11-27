# R4 generated ordinary authentication case

**2026-11-28: the remaining eight generated cases passed too** (all eleven are done); see [generated-20261128-README.md](generated-20261128-README.md).

The plain-password case passed 23/23 at source `27cb52c4` against the existing pinned EMQX 5.8.9 image. Real vendor export/import, counts, plain/cleared-row notices, restart/login, complete configuration/table/admin receipts and the real postcheck passed. A wrong admin receipt was refused. The generated target stayed unchanged.

This is a generated candidate/restart delta; it is not package smoke or a replacement for the original HA D0 full-flow evidence. The other R4 variants remain separate cases.

TempObjects ended empty. An independent read-only scan found zero owned containers, volumes, networks or payload directories; durable image/volume inventories matched inside the run. No catalog or installed engine access occurred. Catalog content was not separately hashed. Unrelated existing container churn was observed separately.

No package installer/upgrader or external endpoint was used. `commercial_acceptance`: `not-complete`.
