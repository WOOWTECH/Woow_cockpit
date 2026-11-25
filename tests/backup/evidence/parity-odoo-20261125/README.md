# Evidence of lane ODOO (HAOS parity, parity-odoo OWNER OD-OWNER-1735), 2026-11-25

Branch parity/odoo-20261125 (local, never pushed), 25 commits on 3db6988 (= F1 + PKG + READ + F3, the integrator's trial tip); tip 3e77cf2. Iteration 1 = 17 commits (tip 5644712),
iteration 2 = 8 more (line-coverage pass, real-package cross-checks, real-backup tests; the three small product fixes are 68aa336 and 4e74d57). Product file:
backup-engine/woowbackup/ha_odoo.py (1845 -> about 2520 lines). Tests: tests/backup/test_ha_odoo.py, test_ha_flows.py, test_ha_pg_stdin.py, hafixtures.py (one helper).
**Unit level only**: no device, no real podman, psql, pg_restore, systemd or loginctl was run; every container step is a test double (hafakes.FakeTmp/Psql and the
fake owner of test_ha_flows). commercial_acceptance stays not-complete.

## Counts (non-heavy runs, this host, hash seed random)
| set | tests | result |
|---|---|---|
| the lane's three modules at the iteration-2 tip: test_ha_odoo + test_ha_pg_stdin (32) + test_ha_flows | 213 (iteration 1: 168; the base had 68) | OK: 210 run + 3 skipped without WOOWBK_HA_FIXTURES; all 213 with it (hash seed 77) |
| the 21-module neighbour set (importers n8n/nextcloud/omnigent/litellm/hermes/headscale/opendesign/codeserver, import, cli, registry, common, tempctr, issues, links, sqlite, space, parity rows + the lane's 3), iteration 2 | 851 (iteration 1: 810) | OK, 3 skipped (run at 4e74d57; the last commit only adds 4 tests) |
| line coverage of ha_odoo.py by the lane's three modules (stdlib sys.monitoring, evidence/iteration2/cov.py) | 1793 executable lines | 98.5% (iteration 1: 93.8% of 1779); 27 lines never run: trivial or defensive |
| tests/e2e/lab test_arm54_final + test_litellm_negative_flow (they mention ha_odoo) | 112 | OK |
| the lane's three + the importers (n8n, nextcloud, omnigent, litellm, hermes, headscale, opendesign, codeserver), import, cli, registry, common, tempctr, issues, parity rows, links, sqlite, space | 810 | OK (run at 594a979; the product is identical to the tip except one condition of 0fbf8a3) |
| test_ha_parity_rows + test_ha_issues with this lane's rows merged (scratchpad/parity/snippets/parity-odoo/ha_parity_rows.json) | 65 | OK; `--report`: ODOO done 39, part 3 |
| scripts/check_source.py | - | OK |
| hand mutants of iteration 2 (evidence/iteration2/hm.py + muts_*.py: a COPY of the tree, one at a time, each against the few test classes that pin the line) | 68 | all caught (the first try of 3 survived: fixed by a stronger test) |
HEAVY (through team/heavy.sh, detached; run m4, see the lane file): tests/backup --b1 full suite, ha118, the mutation sweep (now 107 mutants + 2 controls: 15 were added for the iteration-2 product changes): RESULTS BELOW WHEN FINISHED (none yet: the host's heavy queue was long and loaded; the verify worktree was moved to the iteration-2 tip while m4 still waited).

## Rows
42 rows (41 + UI-20): done 39, part 3 -- OD-23 (the PostgreSQL 16 image is downloaded when missing; bundling it in the installer is the owner's decision), OD-57 (vector part
done; a superuser password only in an EnvironmentFile is said at once as a stop, not read), UI-20 (engine part; the wording on the page is PAGE's). Every row names its tests in
ha_parity_rows.json; every `auto` row has two (it works, what it cannot handle stops only that app), every row with a line to confirm three (not confirmed -> only that app stops;
confirmed -> goes on; one more name -> confirm again: VerdictTests.test_every_line_to_confirm_is_confirmed_by_exactly_its_names and the flow tests).
Also done on the way: the reader's skipped entries are the one `files.skipped` line in the check and the conversion (READ's IN-19/27/28/35/38/39 call site for this importer), a link of this
device's own live data that the restore would refuse is left out and listed once (F3's X-NS-08 call site), pg-stdin follow-ups F3 (the rewrite note reaches the job log) and F4 (the
`pg_restore -l` list is cross-checked against its own header), the PostgreSQL 16/17 waits and the room for answers grow with the data.

## What is simulated, and what a real run must show (also in FOR-REAL.txt)
* `pg_restore -l` and its header `TOC Entries` (hafixtures.toc_listing): the exact relation `header = lines + 3 archive settings` of iterations 1-2 was WRONG for the one real listing
  there is (PostgreSQL 16.15, Nextcloud database, lane probe 2026-11-24: 1131 lines, header 1136); iteration 3 (6f35b77) checks with a slack of 9 over the settings not shown and logs the
  two numbers. No PostgreSQL tool is on the host: an Odoo listing is still to be seen in the real run.
* PGDATABASE as a plain database name (libpq documentation), the scanner script in a real Odoo image, the upgrade marker against the real upgrade-gate.sh, `trusted` in
  pg_available_extension_versions of the PostgreSQL 17 image, the tools wc/sha256sum/cksum in each PostgreSQL image (amd64 and arm64) -- none of these ran.
* CONF_SCRIPT (the odoo.conf reader) was run by a real Python on the committed template of the tenant install (rendered with test values): prints only db_name, db_user, db_password.

## Security review (DESIGN H-c; looked at the code, not only the tests)
* OD-41/OD-58 (objects only a superuser can create): they are never created -- the restore list has their lines commented out and the restore still runs as the ordinary role
  (`--no-owner --no-acl --exit-on-error --single-transaction`); a C-language function cannot be left out and then fails the restore (stop of Odoo). No weaker than before: the old way refused.
* OD-39 (extensions): created only when this device's own PostgreSQL image lists the name AND PostgreSQL calls it trusted (or it was on the old list); the name is matched
  by a strict rule and quoted; a hostile name is never in the device's catalog (test_an_extension_name_of_a_hostile_backup_never_reaches_a_statement).
* OD-20/21 (password of odoo.conf): read in a throwaway container (network none, read-only root, only the secret mounted), only three keys printed, masked in every log at once,
  sent on psql's stdin, never in argv, a message or a log (test_a_password_of_the_configuration_never_reaches_a_command_line_or_a_log); a parse error prints the error class only.
* OD-31 (names): an HA database name never stands in a command line (PGDATABASE; names with control characters or over 63 bytes are refused); psql `-d` is only used for plain names.
* OD-08/09 (mounts): a mount that is skipped is never mounted into any throwaway container; the other importers' refusal is unchanged (test_the_other_importers_still_get_a_refusal).
* Hostile-archive protections, the checks after the conversion, the throwaway containers' isolation (network none, read-only root), the safety backup and the automatic rollback
  are untouched; the check after the conversion stays (it only no longer fails for three reminders: address, website domains, modules left in HA's state).

## Files
ha_parity_rows.json (rows), CONTRACT.md, docs-backup.md.upload.md, NOTES.txt, FOR-PAGE.txt, FOR-REAL.txt, FOR-INT.txt, FOR-N8N.txt; evidence/: mutations.py, build_rows.py, run.sh.
Secret scan: the diff 3db6988..HEAD, these snippets and the lane file were searched for the values of the lab credential file (read in process, nothing printed): 0 hits; no long token-like added line.

## Iteration 2 (OD-OWNER-1735): what the second look found and fixed
Method: (1) a line-coverage pass (no coverage.py on the host: a stdlib sys.monitoring script) listed the lines of ha_odoo.py that no test ran; each was looked at and the ones that are changed
code or protections got a test (OdooGapTests 13, GapTests 16, MoreGapTests 4); hand mutants prove each test pins its line. (2) The REAL tenant package that is on the host (Woow_podman_odoo
c578b8a: scripts/upgrade-gate.sh, odoo-helpers.sh, migrate-tenant-db-role.sh, restore-online.sh, tests/smoke.sh, the Quadlet files and odoo.conf.template) was read against the engine.
(3) Real HA backups (fixtures) were put through the strict pass and through the flows (RealOdooBackupTests 2, RealOdooFlowTests 1: skipped without WOOWBK_HA_FIXTURES).
Found and fixed (product, each with tests):
* 68aa336 the marker's core_date was the RAW dpkg version; the gate makes `18.0.<8 digits>` of it (epoch and suffix cut, three fields): gate_core(), a unit test runs the gate's own shell lines
  with the real bash on 22 versions and compares.
* 4e74d57 the standard role of OD-20/21/22 had CREATEDB; the package's role (and its smoke test T0) is NOCREATEDB. And the filestore of the chosen HA database was always put under
  filestore/odoo although OD-15 reads the database name from odoo.conf: it is now named like the configured database.
Pinned by new tests: a live export that ends too early is job-failed (no test said it), the checks after the conversion (exit code, controldata state, verify problems), what ends the whole job
is never a database's fault (restore, vector image, extension list, release date), the script that lists the device's modules (run by a real Python against a stub of Odoo's names), the share
folder's modules (also a too large manifest there), the package's own Quadlet files, a real x86 add-on and a real ARM add-on with a native module (OD-46 on real bytes).
Corrected: OD-57's reason (see its row note): an EnvironmentFile could be handed over with podman --env-file; it is a non-standard target and stays a clear stop of Odoo only.
Not run by me through heavy.sh (disclosed): the hand mutants (68 single-class runs of 1-30 s in a scratch copy, one at a time), the 21-module neighbour set (two runs, ~7 min each) and the coverage runs;
none of them is a full tests/backup suite, a UI test or the lane's sweep (those are in run m4).
