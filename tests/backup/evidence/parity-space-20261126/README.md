# Space inventory, 2026-11-26

Candidate discovery is read-only. The separately recorded changes archive this task's inactive source snapshots and unused lab images before removing their source copies, and rotate the completed OpenDesign lab after its baseline check. Values are GiB (2^30 bytes). They are potential candidates, not a promise that all reported space can be freed.

| Candidate | Measured size / estimate | Conditions before cleanup |
| --- | ---: | --- |
| Host Podman images not used by a current container | 33.30 reported reclaimable | Host reports 1103 images, 39 active image references and 52 running containers. Inspect tags, rollback/deployment needs, shared layers and active builds first. No host image was removed by this inventory. The figure is not additive with lab storage estimates. |
| Rotated system log `/var/log/syslog.1` | 3.13 | Last modified 2026-11-22. Compressing and verifying it can preserve the log while reclaiming most of its space. Check for open writers first. System administrator access is required; `sudo -n` is unavailable. |
| System journals `/var/log/journal` | 1.97 | Reduce archived retention only after choosing the required history; active journals and recent diagnostics remain. Requires system administrator access. Not counted as wholly reclaimable. |
| Isolated lab outer image cache | 3.21 reported reclaimable | 23 images and 4 active image references. Preserve the current device image, PostgreSQL probe source and fixtures. Inspect per-image dependencies or archive first. Never use a global prune. |
| Isolated lab stopped container layers | 0.84 reported reclaimable | Includes the preserved pre-isolation devices and earlier client/runner test containers. These are recovery references; export or obtain a decision before discarding. |
| pnpm store `~/.local/share/pnpm/store` | 0.95 | `pnpm store prune` can remove unused packages; not the entire installed runtime or shared files. Reinstallation can require the network. |
| npx cache `~/.npm/_npx` | 0.30 | Rebuildable downloads. Confirm no active command is using the selected cache directories. |
| Old `/var/tmp` image transfer and build cache | 0.44 | 0.25 GiB in `container_images_oci1032315544`, 0.19 GiB in `buildah-cache-1000`. Confirm no active build/import, open descriptors or unique result before deleting. |
| Old Headplane checkout dependencies `~/work/headplane-patch-test/node_modules` | 0.90 | Rebuildable from its lockfile after confirming no process uses this checkout. This is another task's workspace; leave it for the owner to select. |
| Avatar checkout `~/work/woowtechbot-ha-avatar-checkout/.build` | 0.68 | Rebuildable compiler outputs after checking for an active build. This is another task's workspace. |

Do not add all table rows: Podman may count shared layers and nested lab storage differently from filesystem allocation. `podman system df` also lists about 1.29 GiB in host volumes not used by a current container; an unused volume can still contain customer data and is excluded from the cleanup candidates.

The active `/var/log/syslog` is 9.01 GiB and must be rotated by the logging service before considering compression. Backups in `~/backups` occupy 4.48 GiB; the real HA fixtures occupy 9.94 GiB; both are retained. The agent runtime, history, evidence and current checkouts are retained.

## Work performed within this task

The previously archived source snapshots remain under `~/.woowbk-lab/evidence/parity-space-20261126`. The stopped dev-c image archival uses its mutation lock, asserts zero containers, preserves the volume inventory, saves each image, verifies its original config digest and all layer hashes, and only then removes that image without force. Archives and their hashes are recorded in `dev-c-images/index.json` in the same private evidence directory.

The earlier OCI archive of the Odoo substitute changed its config digest during Docker-to-OCI conversion; it was never accepted as an exact-ID replacement and its source image was retained. A Docker archive is used for the exact-ID replacement. The superseded OCI copy is removed only after that replacement is verified.

Raw size inventories are `/tmp/parity-space-top-20261126.txt`, `/tmp/parity-space-candidates-20261126.txt`, `/tmp/parity-space-large-dirs-20261126.txt` and `/tmp/parity-space-backups-tmp-20261126.txt`. They contain sizes and paths, not file contents or credentials.

## dev-e image-copy budget

The image-copy script now checks save and load separately. It reserves a whole image plus 13 GiB before saving, measures the compressed directory, then rereads free space before loading. The load check reserves one unpacked image plus one additional compressed copy; the original copy already occupies disk. The 12 GiB floor, extra 1 GiB preflight reserve and 12.25 GiB watchdog remain. Four boundary tests passed (save refusal, measured-size acceptance, larger transfer/other writer refusal with cleanup, exact-boundary acceptance). The complete batch-2 script suite passed 39 tests.

Two further unused outer lab images (an old Nextcloud image and the Podman build image) were archived with exact config/layer verification and removed without force; no container referenced them and the volume inventory stayed unchanged. Archive indexes are included alongside this file. Free space after these steps and the Omnigent cleanup was 25.73 GiB, compared with about 22.13 GiB at the beginning of this pass; other writers make the difference approximate. Historical size estimates in the candidate table predate these two removals.

## OpenDesign environment restored

Using the measured-copy budget, the exact OpenDesign image `5bf5f9b959b3` (6367 MiB) and nginx `1ae82dcc4a34` (66 MiB) were copied into isolated dev-e. The main transfer was 2359 MiB compressed, took 831 seconds and reached a minimum host available space of 15596 MiB. Transfer directories were removed. The subsequent guarded wake completed in 307 seconds: all four units and their health checks passed, the health URL returned 200, and no failed user unit remained. Available host space was 15071 MiB after startup. See `opendesign-images.txt` and `opendesign-wake.txt`. These prove restoration of the lab environment; the HA import acceptance run is recorded separately.

Additional completed verifier/lane work folders and unused outer PostgreSQL images were also archived after checking for active use, verifying the saved data and retaining exact image configs and layer hashes. Their indexes are `verifier-archives.json`, `additional-task-archives.json`, `completed-lane-archives.json` and `outer-image-archives.json`. The archives themselves remain private, outside Git; the indexes contain their locations and hashes. No root/system log, host image or host volume was removed.

At 21:42 Asia/Taipei, after OpenDesign's 85/85 real checks, its separate 7/7 baseline verification and lab rotation, and the completed Omnigent O-15 flow, `/` had 28,755,521,536 available bytes (26.78 GiB). The beginning-of-pass reading was about 22.13 GiB, for an approximate net gain of 4.65 GiB despite concurrent writers. The remaining system-log and package-cache sizes were rechecked: rotated syslog 3.13 GiB, journals 1.97 GiB, pnpm store 0.95 GiB, npx 0.30 GiB, and the two `/var/tmp` caches 0.44 GiB combined. The outer lab cache estimate in the table is historical, before the archived removals, and must not be treated as space still fully available to reclaim. The ten-service final acceptance remains incomplete.

## code-server recovery and final space

The pinned code-server image was also recovered and started under the same disk/isolation guards. Its current real encrypted-backup flow passed 87/87, followed by independent baseline verification 8/8. Only after that verification were the lab services stopped and the cached image removed; data, settings, secrets, units and baseline backup were retained. Rotation reported 27386 MiB available (26.74 GiB), approximately 4.61 GiB more than the beginning of this pass. The image load's lowest available space was 16811 MiB and the ID-mapped copy's was 16513 MiB. See `../parity-codeserver-r8-20261126/README.md` for the complete result and the guarded one-line lab manifest-reference repair.

`host-image-candidates.json` adds a later read-only metadata snapshot and the largest 20 image entries not referenced by any existing host container. The snapshot reports 1102 image entries and 1062 without a current container reference. Its largest entries include very recent candidate builds and shared parent layers; their full reported sizes are not independent reclaimable amounts. An absent container reference alone does not establish that a build or deployment no longer needs an image. No image in this host-store list was selected or deleted.
