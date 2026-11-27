# R6 upload preflight correction

The one507b upload-only attempt stopped before upload-begin. Its ten entries are
native completion caches, not persistent lock files. No transfer or cleanup ran.
The original fullshare upload stop cause remains UNKNOWN.

## Read-only facts

E mutex held during inventory. All10entries are valid `u<16hex>.done`, regular,
root:root0600, nlink1,80bytes, with exactly `{ha_backup_id,at}`. Identical names to
the failed preflight; bytes/metadata unchanged across the probe. No `.part`,
`.json`, unknown names, active jobs/helper processes, open upload FDs or matching
upload locks. No references to these upload IDs in scanned native registries or
the existing R6 host receipt. `fuser` unavailable; complete bounded `/proc` census
used instead. No package installation or device mutation.

Installed `storage.py` SHA256
`d515431db2990025e7acf7cf3d1fd720622865e4dd0fcee3d59c59912c1b703b`
exactly matches the checkout. `_mark_done` creates completion records;
`_upload_lock` flocks `.json`. `abort_upload` removes unfinished files, while
`begin_upload` invokes native24h cleanup. At inventory, caches were11481–74447s
old; none crosses24h during55min plus300s cleanup. The harness refuses such a
boundary instead of authorizing deletion or ignoring missing records.

Private exact paths, UID/GID/mode/size/mtime/ctime/dev/inode, content hashes,
records, registry references and process/lock evidence:
`~/.woowbk-lab/evidence/focus-nextcloud-r6-upload-inventory-20261127T091155/`.
`inventory.private.json` SHA256:
`13a44b964704174156cdaa967a1f31db25e89d267d167dd6c62f05aa7c424f5b`.
Earlier failed attempt and private evidence remain immutable.

## Patch and checks

Only the R6 harness changes. Validate bounded native completion caches, require
no native helper/open upload FD, and compare exact pre-existing snapshots after
the attempt. Only its bound finished upload may add one `.done`. Every unfinished,
unknown, linked, changed, malformed or unsafe entry refuses. Raw writer JSON is
read and persisted in the reaping `finally`, before abort on host EPIPE as well.

Two regressions reproduced both issues before the patch. Targeted upload module
25/25 passed under global heavy/guard; no neighbor rerun. Actual corrected metadata
probe passed under E mutex: old source exact,10caches, HA absent,9processes/152FDs,
0writers. Probe source SHA256:
`ac730d4a7c76bc28303ec931ffe5c4a81141223d2deccc03cbd981f72de2f6f2`.

No E transfer until parent confirms LL image SUCCESS/release and grants a new
exact-source upload-only lease. Same command/resource/cold preservation contract
as [the proposal](upload-only-PROPOSAL.md). No fullshare/S5 lease or retry assumed.
