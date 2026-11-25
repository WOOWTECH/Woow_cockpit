# Evidence of lane ODOO (HAOS parity, parity-odoo OWNER OD-OWNER-1735), 2026-11-25

Branch parity/odoo-20261125 (local, never pushed), 32 commits on 3db6988 (= F1 + PKG + READ + F3, the integrator's trial tip); tip 413d5f3 (iteration 4). Iteration 1 = 17 commits (tip 5644712),
iteration 3 = 2 more (6f35b77 the real pg_restore -l header, be07df7), iteration 4 = 5 more (6d913d6 e3d652c a07b7ad 8599ae8 413d5f3: see the last section),
iteration 2 = 8 more (line-coverage pass, real-package cross-checks, real-backup tests; the three small product fixes are 68aa336 and 4e74d57). Product file:
backup-engine/woowbackup/ha_odoo.py (1845 -> about 2520 lines). Tests: tests/backup/test_ha_odoo.py, test_ha_flows.py, test_ha_pg_stdin.py, hafixtures.py (one helper).
**Unit level only**: no device, no real podman, psql, pg_restore, systemd or loginctl was run; every container step is a test double (hafakes.FakeTmp/Psql and the
fake owner of test_ha_flows). commercial_acceptance stays not-complete.

## Counts (non-heavy runs, this host, hash seed random)
| set | tests | result |
|---|---|---|
| the lane's three modules at the iteration-3 tip be07df7: test_ha_odoo + test_ha_pg_stdin (34) + test_ha_flows | 215 (iteration 2: 213; iteration 1: 168; the base had 68) | OK: 212 run + 3 skipped without WOOWBK_HA_FIXTURES (iteration 2: all 213 with them, hash seed 77; the two changed tests do not touch the fixtures) |
| the 21-module neighbour set at be07df7 (iteration 3, after the list-check fix 6f35b77) | 857 | OK, 3 skipped (430 s at nice 15, host load 25-30) |
| the 21-module neighbour set (importers n8n/nextcloud/omnigent/litellm/hermes/headscale/opendesign/codeserver, import, cli, registry, common, tempctr, issues, links, sqlite, space, parity rows + the lane's 3), iteration 2 | 851 (iteration 1: 810) | OK, 3 skipped (run at 4e74d57; the last commit only adds 4 tests) |
| line coverage of ha_odoo.py by the lane's three modules (stdlib sys.monitoring, evidence/iteration2/cov.py) | 1793 executable lines | 98.5% (iteration 1: 93.8% of 1779); 27 lines never run: trivial or defensive |
| tests/e2e/lab test_arm54_final + test_litellm_negative_flow (they mention ha_odoo) | 112 | OK |
| the lane's three + the importers (n8n, nextcloud, omnigent, litellm, hermes, headscale, opendesign, codeserver), import, cli, registry, common, tempctr, issues, parity rows, links, sqlite, space | 810 | OK (run at 594a979; the product is identical to the tip except one condition of 0fbf8a3) |
| test_ha_parity_rows + test_ha_issues with this lane's rows merged (scratchpad/parity/snippets/parity-odoo/ha_parity_rows.json) | 65 | OK; `--report`: ODOO done 39, part 3 |
| scripts/check_source.py | - | OK |
| hand mutants of iteration 2 (evidence/iteration2/hm.py + muts_*.py: a COPY of the tree, one at a time, each against the few test classes that pin the line) | 68 | all caught (the first try of 3 survived: fixed by a stronger test) |
HEAVY (through team/heavy.sh, detached; run m6 = watch.sh m6 mut real ha118 b1 on the verify worktree, queued 20:18 at be07df7; it starts only when <= 6 heavy.sh wait and the 5-minute load is < 20): the mutation sweep (113 mutants + 2 controls: M109-M113 are new in iteration 3), the lane's two real-HA-backup test classes (group `real`), ha118 and tests/backup --b1: RESULTS BELOW WHEN FINISHED (none yet: the host is overloaded; m4 and m5 were cancelled before any step ran because the product code moved on).

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
none of them is a full tests/backup suite, a UI test or the lane's sweep (those are in run m6).

## Iteration 4 (OD-OWNER-1735, 2026-11-25 evening): 5 commits on be07df7, tip 413d5f3 (unit level + a hostile-value fuzz, doubles only; no device)
| what | numbers | result |
|---|---|---|
| the lane's three modules at 413d5f3 | 228 tests (iteration 3: 215) | OK, 3 skipped without WOOWBK_HA_FIXTURES |
| the 21-module neighbour set at e3d652c | 869 | OK, 3 skipped (109 s at nice 15) |
| line coverage of ha_odoo.py by the lane's three modules (evidence/iteration2/cov.py, run without -I) | 1848 executable lines | 99.1% (17 lines never run: defensive) |
| hostile-value fuzz of the CHECK flow (iteration4/fuzz_flows.py: random module rows, versions, states, extensions, settings, addresses, markers, role rows, custom modules with oddly typed manifests) | 3000 + 1500 + 400 cases after the two fixes (the first run of 200 on the old code found the manifest TypeError at once) | 0 findings (an exception that is no BackupError ends as failure.internal-error: none) |
| hostile-value fuzz of the CONVERSION (same harness, convert mode; the confirmations of the check are passed on) | 1200 + 5000 + 300 + 2000 cases (776 of the last 2000 ran through to the end) | 1 finding in 8500: a control character in this device's own web.base.url (fixed, 8599ae8); the other flagged cases are an artifact of the fake world (a NUL in the configured database name makes the fake's tar duplicate) |
| hand mutants of iteration 4 (iteration4/muts_it4.py: M88 M93 M114-M137, a COPY of the tree, one at a time against the few classes that pin the line) | 26 | all caught (M93, M124, M132 survived first: three tests strengthened; M136 is pinned by SqlTests) |
| the sweep (mutations.py) now has 137 mutants + 2 controls; `--check-text`: all found once | 137 + 2 | NOT RUN YET as a whole (run m7 = watch.sh m7 mut real waits for a quiet host) |
Found and fixed (product, each with tests that fail on the old code):
* 6d913d6 parse_manifest raised TypeError for "external_dependencies": {"python": 5} (True, 3.5, a bare string, a dict): such a manifest is unreadable now; version_key raised ValueError for a
  superscript two (str.isdigit() accepts it) or thousands of digits: only ASCII digits, at most 18 per part. Both ended the whole Odoo app in the generic "unexpected error" stop.
* 8599ae8 web.base.url and the freeze flag of this device's own database were checked for type and length only: a control character passed the check and was refused by sql_literal AFTER the dump,
  the new cluster and the restore (a late internal-error stop). SQL_UNSAFE_RE is looked for when the values are read now (the default address and the existing reminder).
Built (row OD-57 is done now): a07b7ad + e3d652c + 413d5f3 an EnvironmentFile of the database container is read for its non-secret keys and handed to the new cluster by podman (--env-file), the password
is never read; unsafe forms stop only Odoo naming file and key; the job log names the files; a password written plainly in Environment= stays a stop (EnvironmentFileTests 9, two flow tests).
Registry: ODOO done 40, part 2 (OD-23: the installer image is the owner's; UI-20: the engine part is done, the wording is PAGE's).
Not done (honest): the sweep m7, the real runs (FOR-REAL.txt 1-12), the aborted member pass leaves its tar stream to the garbage collector, which prints 'Exception ignored in _Stream.__del__' to the
journal (cosmetic: nothing is written anywhere; seen in 26-95% of the hostile fuzz cases, in none of a normal check or conversion).
DENIED by auto mode (rule 4): pip install --target + import of the downloaded pglast wheel (to parse the lane's SQL with the real PostgreSQL grammar): not retried, not worked around.
Not run through heavy.sh (disclosed): the fuzz runs, the hand mutants, the lane's modules and the 21-module set (all nice 15 + idle I/O, one process at a time; none is a full tests/backup suite, a UI test or the sweep).
