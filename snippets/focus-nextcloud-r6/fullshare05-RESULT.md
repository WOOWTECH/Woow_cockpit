# R6 full share on the current source: PASSED (fullshare05, 2026-11-27)

The original encrypted x86 Home Assistant full-share backup (4,467,947,520 bytes, SHA-256 `2dcfc676…`) was
imported into dev-e's installed Nextcloud by the engine of draft PR #23 (`5168f1ec`, frozen detached worktree,
manifest `ce554fc7…`, 53 files), through the helper commands the Cockpit page sends. **118 of 118 checks passed.**
dev-e was returned exactly afterwards. This is real lab/helper/API evidence; the browser page itself was not driven.

| Run | Driver | Result |
|---|---|---|
| upload03 | `0377b530` | passed: whole file streamed once, hash and file identity proven, kept for the case |
| fullshare03 | `0377b530` | failed before conversion: the driver's request was refused (see below); dev-e restored exactly |
| upload04 | `282bfba1` | passed |
| fullshare04 | `282bfba1` | import, restart and Office passed (77 checks); stopped at the automatic rollback by a false watchdog trip; dev-e restored exactly |
| upload05 | `550478ae` | passed |
| **fullshare05** | **`550478ae`** | **passed 118/118**, cold return exact |

## What fullshare05 proved

- Check of the current backup: the facts match the original full-share source, nothing needs a confirmation (the
  Redis locator fix of `6daaa15c`, integrated as `9e085a09`, now finds the SHA-pinned Redis).
- Conversion (310 s) to an encrypted Woow backup of about 1.2 GiB, its notes and reminders, and inspect (preflight
  passes, settings same, in place); the uploaded HA file is deleted before the restore, as the page allows.
- Restore (268 s), then the client checks after the import and again after a restart: Nextcloud status, the HA
  users' WebDAV files (CJK names, nested, a 4 MiB binary) and per-user manifests, OCS login with the HA password and
  app password (wrong password 401), the user share and the password-protected public link, CalDAV and CardDAV,
  the versions API, this device's Office settings and cron mode, `occ files:scan --all` clean, the data directory
  protected, and Office: Collabora opens the HA document over WOPI, a typed text is saved into Nextcloud.
- Automatic rollback: a second restore with a one-shot `ExecStartPre` failure ended `rolled-back` and left the
  imported data in place (job `j20261127T144938Z-ada48f85`).
- Manual rollback: the import's safety backup restored with every health check ok; dev-e's own markers are back.
- Cleanup and leaks: the run's backups, job objects, staging and key files are gone; the HA key, the HA test
  credentials and the existing baseline kit are in no engine record, upload, staging, run dir or the device
  journal; the public link token appears only in the web servers' access logs of the client's own requests.
- Cold return: the prior engine, helper and VERSION, the Quadlets, the five units' stopped state, the images,
  the catalog, the baseline archive and the isolation (network none, 3 GiB cap) equal the state before; no pull,
  no installer, no copy of the fixture.
- Watchdog samples: minimum 26.9 GiB free (stop at 13.5 GiB), peak device `memory.current` 1.26 GiB (stop at
  2.5 GiB); 4 resource probes failed on the loaded host, never 3 in a row.

## The two failed attempts (driver bugs, not product defects)

- **fullshare03:** `ha-convert-start` was refused at request time because the R6 convert wrapper also sent
  `check_job_id`, which only `ha-import-start` accepts; the product refuses unsupported fields. That wrapper had
  never run for real (fullshare01 stopped at the upload, fullshare02 at the check). Fixed in `282bfba1`: the
  request is built from the schema's fields only and a test validates it with the product's own `cli.validate`;
  the stop line now carries the redacted reason instead of the class name `Failed`.
- **fullshare04:** the watchdog cancelled the automatic-rollback restore 44 s into its decrypt phase. Its samples
  showed no breach (27.3 GiB free, 1.59 GiB used) and the lease had 85 minutes left, so the trip came from one
  failed or timed-out probe while the host ran at load 26 with swap full. Fixed in `550478ae`: a breach or the
  lease end still stops at once, failed probes only after 3 in a row, and the reason is recorded.
- Also `0377b530`: the upload driver no longer refuses day-old `.done` replay caches; it admits exactly the
  product's own 24-hour cleanup at `upload-begin` (removed: 6, then 1, then 1 caches older than a day).

## Evidence

Public copies in `tests/backup/evidence/focus-nextcloud-r6-20261127/`: `fullshare05-checks.txt` (the 118 fixed
check lines), `fullshare05-fixed-result.json` (cold return), `fullshare05-receipt.json` (requests, jobs, timings),
`fullshare05-scope.json` (watchdog samples), `fullshare03-fixed-result.json`, `fullshare04-fixed-result.json` and
`upload03/04/05-fixed-result.json`. Private, redacted run folders: `~/.woowbk-lab/evidence/focus-nextcloud-r6/20261127T223330/`
and `~/.woowbk-lab/evidence/focus-nextcloud-r6-control/20261127T223305/`.

Still open for Nextcloud: a genuine server-side-encryption source (S5) and the confirmation and restore of
skipped items. The ten-service commercial acceptance remains `not-complete`.
