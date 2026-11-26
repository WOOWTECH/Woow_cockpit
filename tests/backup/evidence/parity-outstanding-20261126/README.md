# Outstanding integration rows, 2026-11-26

This audit checks the integrated product at `d0cfef06` (still the product tree in `3699c07a`). It closes stale hand-off markers after inspecting the callers in the integrated tree. It changes the registry and evidence; no product code changed.

| Rows closed | Integrated behavior checked |
| --- | --- |
| CM-01, CM-02 | An unknown add-on version or unreadable target version is a notice. Importers use `VersionTable.issues`, `haissues.version_issues`, or product-specific equivalents (OpenDesign revision and code-server's four program versions). Actual schema/data incompatibility still stops the affected app. |
| IN-19, IN-27, IN-28, IN-35, IN-38, IN-39 | The reader's skipped entries reach one confirmation line in check and conversion. Odoo's oversized manifest and the final EMQX/Headscale caller fixes are integrated. The existing issue-key tests cover unconfirmed, confirmed and changed-name cases. |
| CM-11 | Importers copy resolvable hard-link content or list the excluded link for confirmation, preserving secret exclusions and filtered-file behavior. |
| X-PD-04 | The common scalable JSON/output paths are used by the callers, including Odoo's module list and Nextcloud's database queries; finite resource limits remain. |
| X-NS-08 | Live-copy reports are passed through Odoo's web/module folders, Headscale's extra data, Omnigent's server volume and the other importers' `carry` calls. Unmovable links are listed and require confirmation. |

The selected existing tests ran through the integration guard: **70 tests, 0 failures, 0 errors, 0 skips, 0 blocked commands, 0 shim hits**, in 19 seconds. `selected-tests.json` holds the 60 selected test/class identifiers; class expansion accounts for the total of 70. The complete masked runner output is `focused-tests.log`. This is unit/integration-double evidence, not a new device acceptance run. The already-passing complete guarded suite on the same product was 3357 tests (2 skips).

The two follow-up rows CM-06 and O-31 were completed in `parity-cm06-o31-20261126/README.md`. The complete constructed-real-source Omnigent flow subsequently closed O-15 (`parity-omnigent-r7-20261126/README.md`), and OpenDesign's current real encrypted-backup flow passed 85/85 checks (`parity-opendesign-r8-20261126/README.md`). Current registry: 463 done and 9 part for wave 1 (472 rows); 60 deferred rows are unchanged. These counts describe checklist rows, not a percentage of total engineering or acceptance effort. The remaining product cases and ten-service real-device acceptance stay open; `commercial_acceptance` remains `not-complete`.
