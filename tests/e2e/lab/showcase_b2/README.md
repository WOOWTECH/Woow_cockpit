# Batch-2 real HA source backups (x86 showcase HA), 2026-11-23

Owner decision 2026-11-23 「決定2 A」: build HA -> Podman import for OpenDesign, Nextcloud and code-server. These scripts
made the REAL source backups from the showcase HA's own add-ons (owner-authorized like LiteLLM). Real data may only be
opened inside network-none labs and is deleted after the project's tests. This is source preparation, not an import
attempt: `commercial_acceptance` stays `not-complete`.

Evidence (names, sizes, counts, hashes only; no secret values): `../evidence/ha-b2-source-backups-20261123.json`.

## How it ran

Every `*.sh` except `dl.sh` and `run_verify.sh` runs ON the showcase with `bash -s` through the lab helper
`rr.sh x86 <script>` (scratchpad `phase3/testha-b1/rr.sh` of the batch-1 session). rr.sh exports the generated lab test
credentials into that SSH session only and stores server-generated test secrets printed as `@@CRED@@ NAME=value` lines
in `~/.woowbk-lab/secrets/b1-creds.env` without showing them. The SSH password is given inline as `TESTHA_PW` on the
command line and is never written anywhere.

1. `inv.sh`, `inv2.sh`, `inv3.sh`, `inv4.sh`, `nc-inv.sh`: read-only inventory (versions, states, option names, sizes,
   counts, special files).
2. Per add-on, one at a time: `*-a.sh` (start when it was paused, wait healthy, create the test marker), `*-b.sh`
   (`backup-one.sh`: one encrypted partial backup through the Supervisor API, key `HA_BACKUP_KEY` via `jq env`, then
   wait healthy and check the marker), `*-c.sh` (remove only this lane's marker; put the add-on back in its earlier
   state).
3. `dl.sh`: `cat` over the SSH helper into `~/.woowbk-lab/ha-fixtures/20261123-batch2/x86/<name>/` (0700/0600), refuses
   when the host would keep less than 13 GiB free, compares sha256.
4. `run_verify.sh` + `verify_b2.py`: strict walk of each downloaded backup with the product reader
   (`backup-engine/woowbackup/habackup.py`, R-COCKPIT feat/ha-import-batch1 b2f63ce) inside a throwaway
   `--network none --read-only` labpodman container (`woowbk-device:noble`, the host's PyNaCl and libsodium mounted
   read-only). The key goes to the container on stdin only.

## Result

| App | Backup (HA slug) | Add-on | Bytes | sha256 | Strict walk | Markers |
|---|---|---|---|---|---|---|
| OpenDesign | a64c4ba7 | 1b7b4ce7_woow_ha_opendesign 0.2.15 | 1,116,784,640 | c3d23ced…8dd7 | complete, 6716 entries | 2/2 match |
| code-server | 69cafef5 | 1b7b4ce7_woow_ha_code_server 0.1.14 | 627,415,040 | 8f2dc23f…856f | complete, 28905 entries | 2/2 match |
| Nextcloud (no share) | 2d7882d8 | 1b7b4ce7_woow-nextcloud-office 0.2.3 | 248,125,440 | 88e0f794…027f | complete, 7020 entries | DB-level only |

- All three are securetar v3, compressed, partial, cold. No update was needed (OpenDesign 0.2.15 = Podman core;
  code-server 0.1.14 pins = 0.1.15 per its CHANGELOG; Nextcloud 0.2.3 = 35.0.1.1).
- The Nextcloud backup has NO share folder, so the user files are not in it: a partial/negative fixture (the real
  import must refuse it). The share folder is 4,892,906,973 B (4.56 GiB), over the 3 GiB limit, so the
  share-including Nextcloud backup (and the code-server workspace `/share/projects`) waits for the owner.
- Nextcloud `data/` had no device nodes, FIFOs, sockets, hard links or symlinks; the strict walker accepted the whole
  member (facts risk R1 did not occur in this backup). `data/postgres/PG_VERSION` is owned 102:104 in the backup.

## Nextcloud WITH the share folder (2026-11-23 evening, lane showcase-nc-share)

MAIN decision 17:30 (within the owner's rotation rule): the share-including Nextcloud backup is approved and runs last,
after the OpenDesign and code-server real runs passed and both were rotated out of dev-e. Started 20:35 (both passed
85/85 and 87/87, ROTATED 19:44 and 20:32, host 31.9 GiB free). Evidence: `../evidence/ha-b2-nc-share-20261123.json`.

1. `ncs-a.sh` (on the showcase): markers that live IN the share folder: users `woow-import-share` (A) and
   `woow-import-share2` (B), A's app password, WebDAV files (ASCII, CJK name, nested CJK folders with a 4 MiB random
   file, one file with an older version), a read-only user share A->B, a password-protected public link (expires
   2026-12-07), one CalDAV event, one CardDAV contact. Generated secrets went out only as `@@CRED@@` lines
   (`B2_NC_X86_SHARE_*` in `~/.woowbk-lab/secrets/b1-creds.env`).
2. `ncs-b.sh`: ONE encrypted partial backup (add-on + `share`) as a Supervisor background job, polled every 2 s:
   the add-on was stopped at +4 s and started again at +22 s (stage `addons`, cold); the share folder was written
   after the restart (stage `folders`); 222 s in all, healthz 200. HA slug `507c3510`, 4,467,947,520 B, sha256
   `2dcfc6769d6fed7dd5c375fc379aac43da606931c8378e3970c33f78a4bded9d`. Per-user file manifests, `/share/projects`
   and the share totals were identical before and after the backup.
3. `ncs-c.sh`: both test users deleted; every counted row, the share size and entry count are back to the 17:31
   baseline (`ncs-inv.sh` end-state check), Nextcloud started, healthz 200.
4. Download: attempt 1 (`ncs-dl.sh`, one SSH stream) broke after 1.96 GB (`client_loop: send disconnect: Broken
   pipe`) and its guard deleted the partial file. Attempt 2 (`ncs-dl-chunked.sh`, 17 chunks of 256 MiB, each checked
   against a sha256 list made on the showcase, 1 chunk retried) took 3548 s; whole-file sha256 MATCH; lowest
   projected host free 16.5 GiB (floor 12 GiB kept throughout).
5. `ncs-run-verify.sh` + `ncs_verify.py` (product reader, network-none read-only lab container): add-on member
   complete (7168 entries), share member complete (24,422 entries = `find /share -xdev | wc -l` at backup time;
   2722 dirs, 21,672 files, 28 symlinks all handed out, no FIFO/device/never-read entry). The per-user manifest
   digests computed from the backup equal the showcase's for all four users (admin 88 files, woow-mcp-test 1,
   A 68, B 64; versions and trash counts equal), `/share/projects` (1488 files) equal, `.ncdata` present, the 4 marker
   files present with the showcase's sha256 and owner 33:33.
6. The showcase is not short of space (672.6 GB free of 983.7 GB), so backup `507c3510` stays there with the other
   three for the main session to delete at the end. `ncs_evidence.py` built the evidence; `ncs_leakscan.py`: 0 hits.
