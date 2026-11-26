# Space inventory, 2026-11-26

This inventory is read-only except the separately recorded, verified archival of this task's stopped dev-c image cache. Values are GiB (2^30 bytes). They are potential candidates, not a promise that all reported space can be freed.

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
