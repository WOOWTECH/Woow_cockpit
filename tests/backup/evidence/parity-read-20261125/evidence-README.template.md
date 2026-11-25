# parity-read-20261125 (proposed place: tests/backup/evidence/parity-read-20261125/README.md; raw files: evidence/ next to this snippet)

Lane READ (DESIGN section D, 83 rows): read HA backups as tolerantly as HAOS, keep every protection against hostile and damaged files. Branch
parity/read-20261125 on e7d687b (tip: @@TIP@@; the verification chain it2b ran on @@CHAIN_TIP@@, @@PRODUCT_SAME@@); product files
backup-engine/woowbackup/{habackup,hasecuretar,hastore,storage}.py, tests tests/backup/{test_ha_backup,test_ha_securetar,test_ha_store,
test_ha_links,test_storage,hafixtures}.py. No other file. Nothing was deployed, no service, device or network was touched; the real HA backups were
only read. commercial_acceptance: not-complete. Everything below was made by the scripts next to this file (evidence/), counts and equality only.

| what | result | kind |
| --- | --- | --- |
| the lane's five test modules | @@UNITS@@ | unit tests (synthetic files, the committed securetar fixtures; GNU tar 1.35 and busybox of the host repack them) |
| full tests/backup --b1 through integration-3 guard.py, this branch alone | @@B1@@ | unit tests |
| the same on a throw-away merge of F1 (0f6e4d4) + READ (691d39e) + READ's snippets (CONTRACT, cli, test_ha_cli, test_ha_omnigent, haissues, test_ha_issues, rows) | @@MERGE@@ | unit tests |
| RealBackupTests (--ha118) | @@HA118@@ | real HA backups, read only |
| old reader (e7d687b) against the new one, entry by entry and byte by byte | @@DIFF@@ | real HA backups, read only (differential.py, diff-*.json) |
| changed copies of two real HA backups | @@REAL@@ | real files, changed copies (real_files.py) |
| HAOS parity table | @@SCHEMA@@ | unit test + check_schema.py |
| inner tars against Python's tarfile | @@TARFILE@@ | one-off (diff_tarfile.py) |
| structure fuzz | @@STRUCT@@ | one-off (struct_fuzz*.py) |
| byte-level fuzz (fixed seeds) | @@FUZZ@@ | one-off (long_fuzz.py); a short form is in the unit tests |
| 4,000,000 entries | @@MEM@@ | measurement (mem4m.py) |
| the old tests on the new engine | @@OLD@@ | unit tests (old-tests.txt) |
| mutation sweep | @@MUT@@ | mutations of the four product files (mutations.json) |

## Found in iteration 2 (fixed, with tests and mutants)

1. The names table (IN-34): every entry walked every folder above its name and hashed each prefix. The limit of entries went from 2 to 4 million
   (IN-34), which doubled what a crafted tar could cost: entries on two alternating paths of 1000 folders took 39 ms each (4 million: 43 hours; the
   reader of e7d687b had the same loop). A name in the table was admitted with every folder above it checked and a folder never becomes anything else,
   so the walk now ends at the first folder that is there: 0.05 ms per entry on the same sample. Tested against the rules written the plain way
   (400 random rounds: the same entries are refused for the same reason).
2. Extended headers (UP-12, IN-24): their size went from 64 KiB to 1 MiB, but reading their records is Python work (2.5 us each, 88,000 records in a
   megabyte = 250 ms). Within the inflate budget a tar of 262,000 such headers would have kept a job busy for 18 hours (ten times the old worst case).
   The records of all the extended headers of one tar are counted now; the limit is 50 million (an HA backup has one or two records for each of at most
   4 million entries). Above it an inner tar stops its member (limit-exceeded of one member), the outer tar the file.
3. A limit that stops ONE member (an inner tar, an add-on's addon.json, a gzip stream, a file read whole) is limit-exceeded with scope "member" and a text
   that says only that member is left out; a limit of the outer tar or backup.json has no scope. Every site is asserted by a test.
4. The survivor of iteration 1's mutation sweep ("the second pass ends early") is caught: a link that names nothing ends the pass at the end of the
   archive, and the rest of the stream behind the marker still has to hold its checksum.
5. The sweep of iteration 2 found a limit nobody tested: the notes about what links name (for the chains behind them) are bounded by MAX_LINK_COPIES; a chain
   longer than the notes reach is listed, not followed (test_the_notes_about_chains_are_bounded; without it the mutant survived: it2b-mutOld). It also showed
   seven mutant definitions of iteration 1 that no longer matched the code after later commits (they had silently not run); they were corrected and run.

## Security review (DESIGN H-c)

IN-39 / CM-11 (hard links as copies): a hard link is never followed on disk; the content comes from the same member of the same open file in a further pass
after the first pass passed every checksum and authentication; a link that names NEVER_READ (or anything below), addon.json of an add-on or an excluded
area gives nothing, at any step of a chain (checked once, by name, when the link is seen); targets with `..`, absolute, blank or of another kind give
nothing; copies count into the byte budget; at most 100,000 waiting links and 4 passes; files with several links are kept in memory up to 1 MiB only; every
pass has its own checks, also when it ends at the end of the archive (a test). What an importer itself decides not to keep (copy_later) is its own
responsibility (FOR-APP-LANES.txt point 3). The writes of the copies go through each importer's SpaceGuard (every 64 MiB) and the watchdog.
Limits: they grow, none is gone (the mutation sweep has one mutant for the value of each and one for each check). New: the records count above.
Algorithmic cost: every loop of the reader is linear in the bytes it reads except the names table, which is now linear in the names it creates.

## Decisions a reviewer should look at

(1) KEY-13 vs KEY-07/UP-45: a v2/v3 member that is LONGER than its header says is read up to what the header says (securetar does the same); SHORTER stays
refused, a smaller size in the header is detected (final tag, padding, gzip/tar end). (2) IN-41: a plain, unencrypted tar that goes on behind its end marker
is still refused, because zeros in its middle would otherwise pass for its end; a compressed or encrypted stream is read to its checksum and the rest is
ignored. (3) IN-07: zero padding behind a gzip stream is accepted like gzip(1) does. (4) the outer tar accepts a global PAX header only when it says nothing
about names and sizes. (5) UP-16 (kept): an outer tar that lacks only its end marker is refused as cut off (Python's tarfile reads it; HaosParityTests lists it
with its reason). (6) the new limit of 50 million extended header records is not in DESIGN D; it is the price of raising the size of one header.

Tests of other lanes that fail on this branch alone: test_ha_cli.UploadFinishTests.test_a_broken_ha_file (protected='yes' is taken now; F1 already changed it)
and two of test_ha_omnigent.CheckTests (HA's backup name is cleaned when the file is read; test_ha_omnigent.py.patch). All pass in the merge with the patches
of NOTES.txt. In the throw-away merge with F1 the full suite shows, besides the 5 guard refusals, test_ha_litellm SingleProtectionTests.test_n14_a_second_salt_file_refuses:
F1's own test_ha_litellm.py.patch (its INTEGRATION.txt step d) changes it and it passes with that patch applied (run by hand on the same tree).

Not done here: any real import on a device (R1 of DESIGN G4), the page, and the customer's confirmation for skipped items (every importer must hand
Report.skips on: haissues.py.patch gives them `sink.skipped(report)`; until it is used a skipped entry is only a line in the job log).
