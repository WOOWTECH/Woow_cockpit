# Nextcloud (full share) through dev-e's real Cockpit page (2026-11-28)

`focus_nextcloud_r6_fullshare_page.py` (driver `22fd2cb4`, merged here) ran the full-share Nextcloud import of the
actual encrypted x86 Home Assistant backup (4.47 GB, share member included) through the real Cockpit backup page on
woowbk-dev-e, cold to cold under one lease and one hold of the dev-e lock (2,096 s): admission (cold, isolated, the
five original images, Quadlets unpinned, the 13 GiB reserve after the page upload's peak, no job, no pending receipt;
the share facts bound by their SHA-256), the scheduled-backup timer masked, `deploy-src.sh` of this checkout while cold,
pin and wake, the original baseline verified; then the page import: the 4.47 GB upload through the page (bridge
`waits`: upload, check and result waits for this size; page cap 50 min), Nextcloud only, the check (no stop line, zero
confirmation lines, acknowledged once all the same), one import click whose conversion and restore ran as two linked
jobs; every fact the full-share helper flow (fullshare05, 118/118) proved, judged on the page's own jobs: the section,
file lists, amd64/0.2.3/35.0.1.1, the conversion's notes and reminders, inspect, the restore, client verification after
the import and after a restart including Office open, edit and save, the automatic rollback (R6's own injection), the
manual rollback, data dir protection, storage and table owners; then owned-only deletion, leak scans, the cold stop,
the pins reverted and the timer as found. **145/145**; receipt `focus_nextcloud_r6_fullshare_page.json` ends
`pending: false`. A separate read-only R6 inventory afterwards: every unit inactive, five images present.

`page-fullshare-case.json` is the capture's fixed-status record (148 lines). Private run:
`~/.woowbk-lab/evidence/focus-nextcloud-r6-fullshare-page/20261128T122251/`, full stdout in
`/tmp/parity-focus-20261127/ncfs-page-20261128-01.private.log`. `commercial_acceptance`: `not-complete`.
