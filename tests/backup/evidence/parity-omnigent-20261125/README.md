# Lane OMNIGENT (HAOS parity, 2026-11-25): evidence and safety review

Owner instance OM-OWNER-1905, branch `parity/omnigent-20261125` (from 25f4487 = F1 + PKG + READ + F3 + F2), product code
`backup-engine/woowbackup/ha_omnigent.py`. **Unit level only.** Every container, `psql`, `pg_dump`, `pg_restore`, `podman` and
`systemctl` of these tests is a double (tests/backup/hab1fakes.py + the World of tests/backup/test_ha_omnigent.py, and a real
shell with stand-ins for `psql` and `pg_dump` for the snapshot script). Nothing here was run against a real PostgreSQL, a real
Omnigent, a device or a real HA backup of the owner; `commercial_acceptance` stays **not-complete**.

## What the lane changed (36 rows)

| Group | Rows | What it does now |
|---|---|---|
| auto | O-01 | pg_dump of HA's cluster runs as any other id both id maps hold (never root, never the image's postgres), when none of 65534/32767/9999/999 is mapped |
| | O-02 | a hard link in HA's database folder is copied as an ordinary file (the reader hands the name out again as a file); told as an `auto` line |
| | O-07 | volumes of the app settings beyond the three are carried as they are (`hatarget.carry`) |
| | O-18 | an image without PG_MAJOR is asked through the database it runs here; only "HA newer than the image" stops |
| | O-25, O-49 | a different Omnigent version is a notice (`omnigent.version-different`); the structure version and the columns decide |
| | O-32, O-33, O-58, O-59 | the snapshot of this device's structure is taken again (3 tries, wait 60/120/180 s) |
| | O-40, O-41 | this device's structure is read again when the answer is odd; a stopped database is started and put back (hatarget via hacommon.live_json) |
| | O-42, O-43 | a structure that is still moving is waited for (3 tries, pauses 5/15 s) |
| | O-44 | a different VERSION of an extension both clusters have is no difference (`omnigent.extension-version`, auto) |
| | O-50 | the conversion asks the same questions again (`judge`), stops first, then asks |
| skip_one | O-03, O-12, O-14, O-15, O-16, O-21, O-28 | ONE line to confirm (`omnigent.skipped`), every name in the key; nothing of it is moved |
| | O-10 | no `omnigent` database: stop of this app with what to do |
| remove | O-13, O-23, O-24, O-54, O-56, O-57, O-61 | the block is gone; the test shows the new behaviour and that this app still stops where it must |
| warn | O-09, O-20, O-22, O-48 | notices (O-22: a line to confirm) |
| open | O-31 | **left as it is on purpose** (see below) |

Also done from the lane notes: pg-stdin follow-up F4 for Omnigent (the listing of `pg_restore -l` is counted against its own
header: `check_listing`), the READ snippet's `sink.skipped(report)` at the check and the conversion, F3's call sites
(`ensure_image`, `live_json` retry, `carry`, `copy_live(report=)` for the server volume).

## Row O-31 is NOT implemented (reason and evidence)

DESIGN says "remove": this device's structure version empty or malformed. The check is the injection guard of a value that is
put into the shell script of the snapshot (`SNAPSHOT_SCRIPT`, an unquoted heredoc, `ALEMBIC_RE`); it cannot be reached in the
normal flow (O-19 makes HA's revision equal to this device's first, and HA's must be non-empty), so the customer never sees it.
Removing it would weaken a protection for no customer benefit: left as it is, test
`CandidateFlowTests.test_invalid_revision_rejected_before_capture` (existing) shows it.

## Security re-review (DESIGN H-b/H-c: O-15 and the rows that relax a refusal), by the lane itself

The separate source review is recorded in [independent-review-20261126.md](independent-review-20261126.md). The real run (R7), including a real PostgreSQL TOC probe, is still to do; O-15 stays `part` until then.

Threat model (unchanged): the HA backup is attacker data; HA's PostgreSQL is hostile code, not only hostile data (security review
2026-11-23: HA's answers can lie, code can run inside the throwaway container, whose boundary -- no network, read-only root, data
volume noexec, limits, pg_dump as an unrelated uid -- is what holds).

1. **O-15 (superuser-only objects) was a refusal after the cluster had been opened and queried anyway.** What a continued
   conversion adds is the `pg_dump` run on a cluster that holds event triggers, foreign data wrappers/servers, C functions,
   casts, languages, access methods. `pg_dump` issues no DDL (event triggers do not fire), does not read foreign tables'
   data (no `--include-foreign-data`), qualifies every catalog name and runs as uid 65534-class, over the socket, in the same
   isolated container. A library of HA's cannot be loaded from the noexec data volume. So the marginal exposure is the one the check
   already had; it is bounded by the same containment. Nothing of these objects can reach the new cluster:
   `test_nothing_of_the_superuser_kinds_is_ever_selected` (the dump list carries every kind of `SUPERUSER_KINDS` plus functions,
   triggers, views, rules, policies, extensions, schemas, foreign tables, large objects: only the table data and sequence values of
   this device's tables are selected, by the role without privileges), and the new cluster's whole schema signature (functions,
   triggers, rules, policies, extensions, schemas, event triggers, FDWs, casts, languages, ...) must equal this device's after the
   post-data section and after the last write (`test_the_new_clusters_schema_must_be_the_trusted_one`), and its roles/settings/
   large objects are audited.
2. **O-12 / O-28 (tables and dump entries that are not this device's).** An entry is selected only when it names one of THIS
   device's tables or sequences, exactly once (a second entry with a trusted name stops the app: a table name with a line break
   cannot add an entry); anything else is not selected and told. The tables HA has that the module does not know are not compared
   and not moved; if this device had such a table too (a future Omnigent), the columns of the tables that are moved are compared
   with the new cluster's first and the conversion stops (`test_a_table_both_have_that_this_module_does_not_know_...`).
3. **O-21 (bundle locations).** The only new privilege in the lane: after the new cluster answered like HA's (`require_answers`)
   and before the role is dropped, `woowbk_restore` gets `SELECT` and `UPDATE` on the ONE column `agents.bundle_location` and
   clears the rows whose location is in the confirmed list (`UPDATE ... WHERE bundle_location IN (SELECT
   json_array_elements_text('<one JSON literal>'::json))`; the names travel on stdin as ONE JSON text, `ensure_ascii`, never in a
   command line, nothing of HA's text outside that literal: `test_the_locations_that_could_leave_the_store_are_cleared_by_the_role_
   without_privileges`). `DROP OWNED BY` revokes it; the audit requires the bootstrap role only; the answers are asked again and a
   location still unsafe stops the job (`test_a_location_that_is_still_unsafe_after_the_clearing_stops_the_conversion`). The rule
   (`key_ok`): not empty, no empty/`.`/`..` part, not absolute (a leading `/` is an empty first part), no backslash, control or
   invisible character, at most 512 characters, 255 per part, 16 parts. Keys of file blobs are 16-byte UUIDs hex-encoded by the
   query: they cannot hold a path.
4. **O-02 / O-03 (hard links).** In HA's database folder a link is copied into the throwaway cluster only (content of HA's own
   file; counted in the space check and the global limits). In the artifact store (downloadable through Omnigent) a link to a file
   outside the store is never carried, whether the reader hands it out as a link (its file was handed out) or copies the file it
   names (its file is none of the selected areas): detected by `report.copied_links`; listed, confirmed once.
5. **O-20.** A login key that is empty or larger than 4096 bytes is not carried (an empty key would sign with nothing); Omnigent
   makes a new one.
6. **O-54.** The exit code of the stop alone is no refusal; `pg_controldata` must still say exactly "shut down" before anything is
   exported (a killed cluster says so there: `test_a_cluster_that_did_not_stop_cleanly_is_never_exported`, both directions).
7. **O-44.** Only the version of an extension that both clusters have, with the same name and schema, is tolerated; one more, one
   less or another schema stops (`test_another_set_of_extensions_still_stops`).
8. **O-56, O-57, O-09, O-48, O-61, O-13, O-23, O-24, O-25.** No protection involved: the flag was a lab promise that `trusted_schema`
   proves itself; the top folder's owner/mode is the one read last; unreadable accounts are told; an unregistered secret is a
   notice; PG_VERSION is read by its start (the database that opens the folder refuses a damaged one); a table HA lacks is found by
   the comparison of the columns; versions inform.
9. **Mask / names.** Names from HA are items (cleaned by `haissues.Issue.shown`: every invisible character a space, cut) or go
   through `hacommon.names` in a message; no value of HA, no password hash, no key is in an issue, a log line or a statement.

## What was NOT done / not proven

* No real run: R7 (Omnigent 112) must show the real `pg_restore -l` header relation (`check_listing` tolerates 0-3 hidden
  archive settings; a header that is absent is let through), `GRANT SELECT (col), UPDATE (col)` and the UPDATE on PostgreSQL 16, the
  extension versions of the real images, the hard-link copy through the real reader on a real backup, a stopped database started
  by `hatarget.ensure_running`, and the snapshot retry on a busy device.
* `hatarget.carry` copies the volumes of the app settings beyond the three while the app runs; the pi volume is still copied as
  it is (`live_export`), so a customer's own symlink that leaves that volume is still refused by `nested.check_volume` at the
  end (X-NS-08 is applied to the server volume and the carried volumes only).
* O-31 (above). The tool check (`sha256sum`, `cksum`, `wc`) in the Omnigent PostgreSQL image needs a real run.
* `--refusals` mode of tests/backup/omnigent_product_mutations.py (one mutant per raise) was not run on the new code.
