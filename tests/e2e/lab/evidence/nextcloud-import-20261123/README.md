# Nextcloud HA import as the PRODUCT path: real HA backup with its share folder -> dev-e (2026-11-23/24, lane nextcloud-import)

Owner decision 2026-11-23 「決定2 A」: HA -> Podman import of the WOOWTECH Nextcloud Office add-on
(`backup-engine/woowbackup/ha_nextcloud.py`, registered in `haapps`; CONTRACT section 9 "Batch 2: Nextcloud"; facts
`phase3/facts/nextcloud.md`, decisions D1-D5 applied with their recommended answers).

Driver: `tests/e2e/lab/nextcloud_flow.py` (`--negative`, `--run --facts FILE`, `--run --draft-entry`), evidence by
`tests/e2e/lab/services_a_capture.py` (fixed status lines only, stdout SHA-256, exit, elapsed, source commit,
`commercial_acceptance: not-complete`). Every attempt file is kept, failed ones included. Private, redacted details:
`~/.woowbk-lab/evidence/nextcloud-flow/<time>/` (0700). The same in numbers: `status.json`.

## Real sources

Owner-authorized backups of the showcase x86 HA's own add-on `1b7b4ce7_woow-nextcloud-office` 0.2.3 (Nextcloud 35.0.1.1,
PostgreSQL 16, amd64 only), encrypted (securetar v3), cold, partial, made by the lanes showcase-backups-2 and
showcase-nc-share:

- without the share folder: `woow-b2-nextcloud-x86-enc-noshare`, SHA-256 `88e0f794...` (the refusal);
- with the share folder: `woow-b2-nextcloud-x86-enc-share`, 4,467,947,520 B, SHA-256 `2dcfc676...` (the acceptance run): four
  HA users with 221 files, CJK names, a 4 MiB binary, a file with an older version, a user share, a password-protected public
  link, a calendar event, a contact, app passwords. The share member also holds about 4.8 GB of other folders of the owner:
  never written anywhere.

HA key, test passwords, app password and link token are read through the harness reader by name; no value is printed, logged
or stored here.

## What a share run does (dev-e: network none, no published port, mutation lock held, isolation checked before and after)

1. Setup: the engine of this tree installed by `deploy-src.sh` and compared file by file; Nextcloud 35.0.1 + Collabora from the
   WOOWTECH Podman package with the reference host's images; dev-e's own markers, state and account read. `--draft-entry`
   (since attempt 7): the catalog entry is the page's own draft (`catalog-suggest`), unedited, installed with
   `catalog-install`, as a customer has it; dev-e's own entry file is put back byte for byte at the end.
2. Page path: `upload-begin` / copy / `upload-finish`, `ha-check-start`, `ha-convert-start` (real space guard), `inspect`, the HA
   file deleted (`ha-delete`), `restore-start`: exactly the helper commands the page sends (no browser: dev-e publishes no
   port).
3. Client checks as HA's users, after the import, after a restart and after the automatic rollback: status.php; WebDAV files by
   SHA-256; every HA user's files on disk by the showcase's manifest digest; OCS with the HA password and with HA's app
   password (wrong one 401); the user share; the public link (401 without and with a wrong password); CalDAV and CardDAV by
   UID; the older version; Office settings, cron mode, capabilities and discovery of THIS device; the new data fingerprint;
   root storage and table owners. Since attempt 5 also: the users' file lists of HA's database equal the files; nothing below
   the data dir is served by the web server; Office: a document opened in this device's Collabora over WOPI and the websocket,
   its text read back, an edit saved into Nextcloud. Since attempt 6 also: `occ files:scan --all` finds nothing new, nothing
   removed and no error; Nextcloud's own setup check calls the data directory protected.
4. Automatic rollback: a second restore with a one-shot `ExecStartPre` failure must end `rolled-back`; manual rollback: the
   import's safety backup restored: dev-e's markers exactly back, the HA-only users gone, its own account logs in; with the draft
   entry the safety backup's data checks (database, Redis, html and data digests) must all be equal.
5. After: dev-e's markers, config.php, users, storages, data dir, units and Office settings unchanged. Cleanup: every backup
   this run made and the HA record deleted, no throwaway object, staging folder or key file left. Leak scan of the engine's
   records and the whole device journal. Isolation.

Simulated, stated: the upload is a root copy to the helper's upload path (the page sends chunks); Collabora's call back to
Nextcloud goes to this device's own public address, which on dev-e is 127.0.0.1:18081, so inside the Office container a throwaway
relay (the gateway's image) passes that one hop on to the gateway; no browser.

`occ files:scan` right after the import updates rows of the file cache (155 in attempt 6) and nothing on the runs after it. Read
from the real share member and HA's real database (counts only): 89 of the 221 files and 9 of the 18 folders have a file time on
HA's own disk that is later than the one HA's own database holds (89 = the files of the users admin, 88, and woow-mcp-test, 1; the
132 files of the two test users are equal), so the same scan would update them on HA too. The import keeps HA's file times and
HA's rows as they are.

## Attempts

| Evidence | Source | Exit | Result |
|---|---|---|---|
| `nextcloud-x86-noshare-attempt1.json` | 162a51c | 1 | 33/34: the product's refusal correct; the FAIL was the harness's expected calendar/contact counts (1dd0106) |
| `nextcloud-x86-noshare-attempt2.json` | 1dd0106 | 0 | **34/34 PASS**: the real backup without HA's share folder is refused at check and convert; dev-e unchanged |
| `nextcloud-x86-noshare-attempt3.json` | 6ecb7a0 | 0 | **34/34 PASS**: the same on the code after the self review |
| `nextcloud-x86-noshare-attempt4.json` | 7e969f0 | 0 | **34/34 PASS**: the refusal run on the lane tip (integration 0562c55 merged, the Team folders fix) |
| `nextcloud-x86-share-attempt1.json` | 863179e | 1 | 85/86: every import, client, restart, rollback and cleanup check PASS; the FAIL was the leak scan's scope (the public link token in dev-e's own web access logs, scoped in 3ade81d) |
| `nextcloud-x86-share-attempt2.json` | 3ade81d | 1 | 20/21: stopped by the host-floor guard before the check (other lanes' disk use); dev-e untouched |
| `nextcloud-x86-share-attempt3.json` | aaed6cf | 1 | 32/35: the host floor touched while the safety backup was packaged; the recovery put dev-e's own Nextcloud back (harness fix c91b3c1) |
| `nextcloud-x86-share-attempt4.json` | 02f5d40 | 0 | **87/87 PASS**: nothing of HA's database runs as code with the superuser; it outlived the 03:33 kill of all agents |
| `nextcloud-x86-share-attempt5.json` | 94caf03 | 1 | 95/103: the new Office check found a real gap: right after the import documents did not open (HTTP 500) until cron refreshed the Office app's cached Collabora answers; everything else PASS (fixed in acf1bbd) |
| `nextcloud-x86-share-attempt6.json` | fbcf7dd | 0 | **109/109 PASS**: the Office fix, `occ files:scan` and the setup check |
| `nextcloud-x86-share-attempt7.json` | 6a67eef | 0 | **113/113 PASS**: the integrated engine (integration af92b38) with the Team folders fix, and the page's own catalog draft unedited (its data checks included) |

Read-only measurements (not acceptance): `noshare-member-scan.json` (the add-on member), `nextcloud-x86-share-shape-probe.json`
(database shape and dump kinds of the real HA database), `nextcloud-x86-share-lists-probe.json` (the users' file lists of HA's
real database equal the files in the share member), `nextcloud-webroot-probe.json` (dev-e: why the import writes
`data/.htaccess` itself).

## Reviews (no separate security-review lane exists for Nextcloud)

Attack runs against the real importer steps in the isolated lab store: `tests/e2e/lab/nextcloud_sandbox_review.py`,
`nextcloud-sandbox-review-attempt1.json` (14/15; the one FAIL was the harness's expectation), `-attempt2.json` (that case) and
`-attempt3.json` (16/16 on the final importer): crafted HA clusters (objects a compromised Nextcloud role in HA can plant; a data
directory whose `pg_get_indexdef` lies, so the dump's INDEX entries carry any SQL; a planted aggregate on this device's live
database). Every one was refused or held, no attacker code ran as the superuser, and controls show that the attacks work without
the defence; the honest clusters (`clean`, `team_folders`) convert.

Found and fixed, each with unit tests and mutants:

- 2779441 ..: nothing of HA's database runs as code with the superuser (pinned sessions, dump kinds and database shape refused,
  fix-ups and table reads as the Nextcloud role, role attributes and grants verified).
- 191f4c0: the users' files stay private. Here the data dir is inside Apache's web root (`AllowOverride All`); measured on dev-e
  (`nextcloud-webroot-probe.json`): without `data/.htaccess` a user's picture is served without a login, and a folder with its own
  `.htaccess` is served and its PHP file runs. The conversion always writes Nextcloud's own rules and refuses any other
  `.htaccess` in HA's data directory. Also: the two-factor keys are one policy (never mixed, never weaker), the live database is
  read with `search_path = pg_catalog`, the new cluster may hold no other database, HA's file lists are compared with the files.
- e7d481e: HA's texts are shown without control or bidirectional characters; `backup_label`/`tablespace_map` refused unstarted.
- acf1bbd: Office works right after the import (this device's cached Collabora answers carried, the refresh job made due).
- 4fb7af7 (fresh review): Team folders keep their storages (next section); only the web updater's own `updater-<instanceid>` folder
  is skipped, not every folder named `updater-...` (a user may have such a name, his files would have been left out).

### Team folders (`nextcloud-team-folders-attempt1.json`, `-attempt2.json`)

The real HA backup has no Team folder, so `tests/e2e/lab/nextcloud_team_folders.py` shows the change on a real Nextcloud 35.0.1.1
(dev-e's own image, throwaway container and volume, network none, SQLite) with the real app (groupfolders 23.0.2, its release
archive): the app keeps `local::<datadirectory>/__groupfolders/1/` as a storage of its own and its folder row names it by number.
Control, only the root storage row renamed (the importer before 4fb7af7): the folder's file answers HTTP 500, the share of it 503.
With the rows the importer's `storage_moves` names: same file number, content, listing and share, and using it adds no storage.
Synthetic data; the importer function itself; not a whole import.

By design (owner decision D2, shown to the administrator before the restore): HA's custom apps are PHP code and come along, so an
HA backup is as trusted as the HA it came from; its Nextcloud administrators become this Nextcloud's administrators.

## Unit tests (fakes, not acceptance)

`tests/backup/test_ha_nextcloud.py`: 47 OK. Mutation run `nextcloud-mutations.json` (source c9b1e26): 88 one-place changes of
`ha_nextcloud.py` (43 of the first self review, 13 of the Office fix and the file lists, 32 of the Team folders change), each must
make the test module fail: 88/88 killed. Full guarded `tests/backup` on 501a13f (host podman and other host tools refused by the
guard): 1766 run, 0 failures, 0 errors, 6 skipped, 0 refused calls.

## Not covered

- A browser: the Cockpit page itself (its Nextcloud cases are in `tests/backup-ui.mjs`) and the Office page's JavaScript.
- Collabora's call back over a real network address (see "Simulated").
- A whole import of a real HA backup that holds a Team folder (see above), TOTP / two-factor logins (none in the test backup),
  passkeys and security keys (bound to HA's address: they have to be registered again), server-side encryption and object storage
  (refused by design, unit tested only).
- HA Nextclouds that had the Memories app are refused: it creates a database function and a trigger (pulsejet/memories
  `lib/Db/FilecacheTriggers.php`). Leaving exactly these two out would be possible (Memories creates them again); that relaxes a
  security check and is the owner's decision.
- ARM: the add-on is amd64 only.
