# parity-read-20261125 (proposed place: tests/backup/evidence/parity-read-20261125/README.md; raw files: evidence/ next to this snippet)

Lane READ (DESIGN section D, 83 rows): read HA backups as tolerantly as HAOS, keep every protection against hostile and damaged files. Branch
parity/read-20261125 on e7d687b (tip: @@TIP@@; iteration 3; the verification chain it3b ran on @@CHAIN_TIP@@, @@PRODUCT_SAME@@); product files
backup-engine/woowbackup/{habackup,hasecuretar,hastore,storage}.py, tests tests/backup/{test_ha_backup,test_ha_securetar,test_ha_store,
test_ha_links,test_storage,hafixtures}.py. No other file. Nothing was deployed, no service, device or network was touched; the real HA backups were
only read. commercial_acceptance: not-complete. Everything below was made by the scripts next to this file (evidence/), counts and equality only.

Words used in the "kind" column, so that nothing reads wider than it is: "unit tests" = synthetic files and the committed securetar fixtures, in this
repository's test modules; "real HA files, read only" = the real HA backup files of the lab read by the reader (opened, walked, compared) -- no device, no
import, no restore, no importer; "fakes" = the importers' own checks are replaced by test doubles. Nothing in this lane ran on a device (R1 of DESIGN G4).

| what | result | kind |
| --- | --- | --- |
| the lane's five test modules | @@UNITS@@ | unit tests (synthetic files, the committed securetar fixtures; GNU tar 1.35 and busybox of the host repack them for real; bsdtar and macOS repacks are hand-built imitations of what those tools write, labelled so in test_bsdtar_and_macos: there is no bsdtar on the host) |
| full tests/backup --b1 through integration-3 guard.py, this branch alone | @@B1@@ | unit tests |
| the same on a throw-away merge of the integrated BASE 1dc9108 (F1 + PKG + READ 691d39e + their snippets applied) and this branch | @@MERGE@@ | unit tests |
| RealBackupTests (--ha118) | @@HA118@@ | real HA files, read only |
| job level, twelve ways one add-on member can be broken (job_level.py, job_level.out), F1's check with the importers' checks mocked | @@JOBLEVEL@@ | fakes (F1's flows.run_verify, small synthetic members): not real, not a device |
| old reader (e7d687b) against the new one, entry by entry and byte by byte | @@DIFF@@ | real HA files, read only (differential.py, diff-*.json) |
| changed copies of two real HA backups | @@REAL@@ | changed copies of real HA files, read only (real_files.py) |
| HAOS parity table | @@SCHEMA@@ | unit test + check_schema.py |
| inner tars against Python's tarfile | @@TARFILE@@ | one-off (diff_tarfile.py) |
| structure fuzz | @@STRUCT@@ | one-off (struct_fuzz*.py) |
| byte-level fuzz (fixed seeds) | @@FUZZ@@ | one-off (long_fuzz.py); a short form is in the unit tests |
| 4,000,000 entries | @@MEM@@ | measurement (mem4m.py) |
| cost of the probe behind a plain tar on crafted fillers, same machine, before and after | @@PROBE@@ | measurement (probe_cost.py, probe_cost.out) |
| the probe behind a plain tar against the probe of iteration 2 (same answers) | @@PROBEDIFF@@ | one-off (probe_diff.py), besides the 600 rounds of the unit test |
| the tests of this iteration (four classes) against the engine of iteration 2 (691d39e) | @@ON_IT2@@ | unit tests (tests-on-engine-iteration2.out): the five blind spots were right in the code, only the tests were blind; the cost of the probe is what changed |
| the old tests on the new engine | @@OLD@@ | unit tests (old-tests.txt; run at iteration 2, the product files of those paths are unchanged) |
| mutation sweep (ONE run of one list on the tip of this iteration) | @@MUT@@ | mutations of the four product files (mutations.json) |

## Found in iteration 3 (the verifier's findings, with tests and mutants)

1. Five protections that were in the code and that no test noticed (the verifier removed each one and every test passed). Each has a test now and a
   mutant in the sweep: (a) the checkpoint of the reading in _Reader._fill every CHECK_BYTES (64 MiB): a cancel or the watchdog reaches a walk that skips
   data nobody selected; the old test said "at least 2 calls" and the entry count alone gave them; now every call is checked by its stream position, a
   cancel at the first and at the third, and the entry count apart from the bytes (EntryTests); (b) the entry and byte checkpoints of the second (hard link
   copy) pass, and (c) the inflate budget of the member for that pass: a stream that is opened again and holds more than the first time is
   limit-exceeded of one member, the ratio of the stored size counts and not only the floor (HardLinkTests.test_the_second_pass_...); (d) O_NOFOLLOW where
   the stale-upload drop opens the record of an upload: a link put there is neither locked nor removed (test_storage); (e) the key of the names table:
   16 bytes, new for every table and every walk, part of every digest (NamesTests). The sweep of iteration 2 had no checkpoint mutant at all. The sweep of this iteration catches every one of the new mutants; and for 16 of them (the lines of the five
   blind spots) each is caught by the one test written for it when only that test is run (mutants-vs-their-own-test.out; quickmut.py).
2. The probe behind a plain, unencrypted tar (IN-41; the tar must not go on behind its end marker): it asked for every word 'ustar' in the tail and ran
   its loop once per word, so a crafted tail cost 89 s of CPU per GiB on this machine (the verifier measured 139 s). It now asks for the next word only
   from the magic place of the next block, and gives the same answers (differential test against the old probe: 600 random rounds in 6 buffer sizes, headers
   good and damaged, words and zeros at any offset, a reader that had read some bytes, tails that are no whole block). The signed byte sum of the header
   checksum (the fallback tarfile accepts) was a Python generator over the block, 33 us per block, and a crafted tail with the magic in every block paid it
   2 million times per GiB; it is counted in C now (proven equal to the sums written out byte by byte on 4000 random blocks). A cost test counts the lines
   of the probe and of the header sum (at most 40 per block over 2048 blocks of any filler; the probe needs 8 to 13, the one of iteration 2 needed 409 to 517), not
   seconds; a mutant that counts the sum byte by byte in Python again is caught by it. The refusals are exactly the ones of
   before (every case of test_what_follows_the_end; the differential test).
   Measured worst cases (probe_cost.out; this machine, CPU seconds per GiB): 'ustar' words 89 -> 4.5; the magic in every block with a wrong checksum
   68 -> 18.5; zeros and random bytes 1.7-2.3 (unchanged). Bounded by the size of the member and cancellable (every 64 MiB).
3. Wording of the earlier evidence, corrected: the job level result is 11 of 12, not 12 (see the table: the cut gzip is not seen at check time with a
   small fake member, the reader itself stops it when it is read to its end); the 27 real HA backups hold v3 members (40) and unencrypted ones (31) only,
   v1 and v2 are read from the committed fixtures that the real securetar library wrote; bsdtar and macOS repacks are imitations; the mutation count is
   one run; "real" means real HA files read by the reader.

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
Limits: they grow, none is gone (the sweep has a mutant for the value of each limit and for most of the checks; five protections that it did not cover are listed under iteration 3). New: the records count above.
Algorithmic cost: every loop of the reader is linear in the bytes it reads (the probe behind a plain tar since iteration 3: a few steps per block) except the names table, which is linear in the names it creates.

## Decisions a reviewer should look at

(1) KEY-13 vs KEY-07/UP-45: a v2/v3 member that is LONGER than its header says is read up to what the header says (securetar does the same); SHORTER stays
refused, a smaller size in the header is detected (final tag, padding, gzip/tar end). (2) IN-41: a plain, unencrypted tar that goes on behind its end marker
is still refused, because zeros in its middle would otherwise pass for its end; a compressed or encrypted stream is read to its checksum and the rest is
ignored. (3) IN-07: zero padding behind a gzip stream is accepted like gzip(1) does. (4) the outer tar accepts a global PAX header only when it says nothing
about names and sizes. (5) UP-16 (kept): an outer tar that lacks only its end marker is refused as cut off (Python's tarfile reads it; HaosParityTests lists it
with its reason). (6) the new limit of 50 million extended header records is not in DESIGN D; it is the price of raising the size of one header.

Tests of other lanes that fail on this branch ALONE (so "only the 5 known" is not the whole truth for the branch by itself): test_ha_cli.UploadFinishTests.test_a_broken_ha_file
(protected='yes' is taken now; F1 already changed it) and two of test_ha_omnigent.CheckTests (HA's backup name is cleaned when the file is read;
test_ha_omnigent.py.patch). They are the 3 beside the 5 test_litellm_lab_runner guard refusals in the line "this branch alone" of the table. On the integrated
BASE 1dc9108 (where those snippets are applied) plus this branch: @@OTHERLANE@@

Not done here: any real import on a device (R1 of DESIGN G4), the page, and the customer's confirmation for skipped items (every importer must hand
Report.skips on: haissues.py.patch gives them `sink.skipped(report)`; until it is used a skipped entry is only a line in the job log).
