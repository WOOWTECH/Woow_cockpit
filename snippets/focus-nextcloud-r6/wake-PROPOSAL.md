# R6 next phase proposal: wake / baseline / cold return

This is a draft for parent review after image-only ea17ae79 finishes. No wake,
pin refresh, deployment, install, fixture creation or restore has run. The current
image lease authorizes none of this phase. A separate exact commit lease is needed.

Proposed45minutes, entire dev-e mutex and global heavy wrapper. Source files are
`focus_nextcloud_r6_wake.py`, new focused tests and an inert lease template.

1. Require all five exact original Linux/amd64 image config IDs already loaded;
   original Quadlets/units/catalog; every captured unit inactive/dead; cap3GiB,
   networknone/no ports. Require hostRAM>=2200MiB, device headroom>=1536MiB,
   free>=17GiB before first start (13GiB reserve +3GiB existing first-start mapping
   bound +1GiB margin). Retain13GiB; abort below13.5GiB. No image recovery or pull.
2. Stream SHA256 of original baseline archive/metadata before and after. Privately
   capture exact prior five Quadlet bytes, SHA, UID/GID/mode/mtime before any write.
   Copies are host700 directory/600 files; never print bodies/environment values.
3. Resolve both each original Image= and its canonical original tag locally.
   They must BOTH resolve to the same exact expected config ID/amd64/linux.
   Refuse unresolvable/different IDs, link/hardlink units, ambiguous Image/Pull
   directives, nonstandard xattrs or changed current bytes. No blind re-pin.
4. Atomic appowner writes pin Image=sha256:<same config ID> and explicit Pull=never.
   Preserve all other bytes/attributes. daemon-reload, then start target/cron under
   an INSIDE-device supervisor with reserve, expiry, memory and process wait gates.
   No installer, source deployment, apt, catalog change, image pull or restore.
5. Existing `batch2_baseline.py --verify nextcloud`: original markers/file SHA,
   running/no-problem engine status, health URLs, original encrypted baseline
   record identity. This read-only verifier does not restore anything.
6. Always stop the exact native stack/timer under the same mutex. Confirm inactive
   before reverting. Restore exact prior Quadlet bytes/modes/ownership/mtime,
   daemon-reload, compare all prior unit/enablement states, Quadlet hashes, catalog,
   baseline archive SHA, cap and isolation. A foreign edit blocks overwrite.
   Preserve private copies and a fixed failure receipt on uncertainty. No retry.
7. Keep all five recovered images and their mapping cache for later leases. Do
   not call the old `rotate:nextcloud` (it deletes images), rm stores, delete the
   baseline, or touch other services/credentials. Ordinary inactive units stay
   inactive; no enable/disable state change.

After reviewed commit and separate lease, exact command from R6 worktree:

```sh
HEAVY_FREE=/tmp/woowbk-dev-e-mutation.lock /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/focus_nextcloud_r6_wake.py --run --lease /tmp/parity-focus-20261127/lease-nextcloud-r6-wake.json
```

Product source remains as installed for this baseline-only phase; installed hashes
are recorded. Frozen product `/tmp/parity-focus-final-gate-20261127 @86e06b43`
is available for a later separately reviewed source-only deployment/full-share
phase. It has no NC adapter changes from3e3e9315. No source deployment is included
in this proposal. Genuine S5 and skipped-entry fixtures/flows remain independent
preparation work, never a reason to postpone this bounded recovery/control phase.
