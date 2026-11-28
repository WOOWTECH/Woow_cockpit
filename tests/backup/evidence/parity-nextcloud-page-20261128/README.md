# Nextcloud (no share) through dev-e's real Cockpit page (2026-11-28)

`focus_nextcloud_r6_page.py` (driver `687cc9b7`, cherry-picked here as `18f60897`) ran the no-share Nextcloud import
of the actual encrypted x86 Home Assistant backup through the real Cockpit backup page on woowbk-dev-e, cold to cold
under one lease and one hold of the dev-e lock: admission (dev-e cold and isolated, the five original images loaded,
Quadlets unpinned, the 13 GiB reserve after the historical peak, no job, no pending receipt), the scheduled-backup timer
masked, `deploy-src.sh` of this checkout while cold (the page and the engine), the five Quadlets pinned to their loaded
config IDs and the stack started, the original baseline verified, then the page import (upload, Nextcloud only, the
check and its no-share confirmation acknowledged once, one import whose conversion and restore ran as two linked jobs),
the 36 facts of the earlier no-share run judged on the page's own jobs, read-only verification, the import's safety
backup restored, the baseline verified again and every after-state check, then deletion of exactly what this run made,
the leak scans (incl. the Cockpit password and the baseline kit), the cold stop, the pins reverted and the timer as
found. **82/82** in 1,147 s (the lock held 1,146 s); receipt `~/.woowbk-lab/run/focus_nextcloud_r6_page.json` ends
`pending: false`.

The cold return compared units, Quadlets, images, catalog, the baseline archive, isolation and the memory cap with the
admission's (equal; the engine modules are this checkout's, whose product code equals `b058df27`). A separate read-only
R6 inventory afterwards (`/tmp/parity-focus-20261127/r6-inventory-after-nc-page-20261128.json`): every Nextcloud unit
inactive, five images present, 0 device mutations, 0 pulls.

`page-noshare-case.json` is the capture's fixed-status record (85 lines) and stdout hash. Private run:
`~/.woowbk-lab/evidence/focus-nextcloud-r6-page/20261128T084711/`, full stdout in
`/tmp/parity-focus-20261127/nc-page-20261128-01.private.log`. The full-share import's page run is not part of this
case (its helper run passed 118/118 on 2026-11-27). `commercial_acceptance`: `not-complete`.
