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
