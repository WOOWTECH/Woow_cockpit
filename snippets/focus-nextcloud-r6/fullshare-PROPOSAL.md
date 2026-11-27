# R6 source-only deployment and original full-share case: parent review

Prepared and tested offline. No deployment, upload, import or restore executed.
The completed image and wake leases do not authorize this case. Parent can grant
this exact controller a new **110 minute fullshare lease**, with **30 minutes
only for cancellation/reconciliation/baseline recovery/cold return** after expiry.
The template is expired and inert. No owner/code confirmation is needed.

## Exact launcher

From `/tmp/parity-focus-nextcloud-r6-20261127`, clean at the reviewed commit:

```sh
HEAVY_FREE=/tmp/woowbk-dev-e-mutation.lock /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/focus_nextcloud_r6.py --run --case fullshare --product-source /tmp/parity-focus-final-gate2-20261127 --lease /tmp/parity-focus-20261127/lease-nextcloud-r6-fullshare.json
```

The entire case owns the global heavy seat and dev-e mutex. No new authentication
route, host image operation, image recovery, package install, apt, manage.py,
key initialization/import, catalog replacement, scheduler enablement or cap change.

## Frozen source and protected transaction

Product clean fullSHA **d09f4fe8e06305aff6a1150f41d6de719e7b7f6a**. Engine,
helper and existing VERSION only: **53 files / 2809669 bytes**, manifest SHA256
**966472487e9f53b1d39263ae4f7dfb86ac948a5b6aa8667ff1183fee40f38d79**.
VERSION remains **2026.11.19.2**; no repository version edit. Nextcloud SHA256
**b888cbff8a47e01791b277916394e90b13b3ddc673c2d893368ddf3c06cbcf56**
is identical to the R6 base. The public JSON records every source SHA/size and the
reviewed deploy-src.sh SHA. Other d09 engine files are deployed from d09 too.

Reuse deploy-src's stream/stage/root ownership pattern without its installer.
`focus_nextcloud_r6_source.py` emits USTAR through the existing isolated wrapper;
receiver copies only exact regular manifest members, hashes in <=1MiB blocks,
refuses links, duplicate/foreign paths, PAX metadata, missing/wrong bytes and
oversize files. Limits: 2MiB/file, 16MiB total. Only new protected leaves:

- `/usr/local/lib/.focus-nextcloud-r6-<16hex>/`
- `/usr/local/libexec/.focus-nextcloud-r6-<same16hex>/`

Both have root-owned, non-writable parents and 0700 leaves. Prior library (including
VERSION and all prior cache bytes/attributes) and helper move intact into these
leaves on their destination filesystems. A durable private transaction journal
precedes renames. It records exact bytes, UID/GID/mode/mtime for both prior and new
installations. Native `jobs.lock` then `engine.lock` are acquired without waiting;
all job records and inactive original backup schedule timer **and service** are
rechecked under both locks before the first library rename. Busy/queued writers
refuse. Locks cover only the swap, and are reacquired for return.

Install mismatches, interrupted swaps and `preparing`/`prepared` resource failures
have a bounded return using only proven prior/current copies. Foreign edits stop
CAS replacement. After data recovery and native cold return, **always return exact
prior library/helper/VERSION**, even on a passing proof. New source/staging and
private journal remain for review; no broad deletion. Runtime standalone imports
set `dont_write_bytecode` and a separate cache prefix before loading the engine;
the unmodified installed helper already suppresses bytecode. No existing cache is
removed or ignored in prior-state comparisons.

## Device and resource gates

Keep 3GiB cap, network none, ports {}, every original unit inactive initially,
original enablement and catalog SHA. Loaded Linux/amd64 configs must be exactly:

| Original canonical ref | Exact config ID |
| --- | --- |
| localhost/woow-nextcloud:35.0.1-office2 | e80170f48ac2534abd0960be4838dbe9fcdc498da924a62f2436cd470dab4165 |
| docker.io/collabora/code:26.04.4.2.1 | a35ff1de149aeae0b1c9ecc83ab9406bd14a788cd61284e95b88b602df4a6ba3 |
| docker.io/pgvector/pgvector:0.8.6-pg16 | 9b05db12a35460fff0587e009f9326e414a53e9484555547f96d214a2ba98ef7 |
| docker.io/library/redis:8.10.1-alpine | d1e21a26915a35a6eb5d820018cd55adfcda02e02f7d629e1f42df397d5494ad |
| docker.io/nginxinc/nginx-unprivileged:1.29.3-alpine | 696695300a3c18a324c07ecb41f220e8c470302148b0378770cf5c70e6458ea0 |

Fresh host available >=2200MiB; device headroom >=1536MiB; cold free >=17GiB.
The last independent cold result was free29021827072 / memory554872832 bytes.
These are historical observations; collect fresh before any write. Native wake
has an inside-device expiry/reserve/memory supervisor and reaps its exact client.
Use min(/home free,/var/lib free) on the actual backing filesystem, reserve13GiB,
abort at13.5GiB; monitor cgroup memory <=2.5GiB (remaining512MiB), unchanged cap3GiB.
This is conservative and may abort on cache pressure; it never raises the cap.

Once awake, fresh html/PG/data sizes must pass `acceptance_budget` before upload.
The conservative historical estimate is **9296980812 additional bytes**, requiring
**23255624524 free after wake**, including the unchanged13GiB reserve. Initial
safety/converted bounds are each1GiB; actual package sizes gate each restore. New
source payload adds only2.81MB (16MiB receiver cap), not another image or share.
Images total3.918GB are already loaded; no second recovery/copy is budgeted.

## Actual flow and recovery

1. Privately capture exact prior Quadlets/attributes, inventory and streaming
   original encrypted baseline archive+manifest hashes. Resolve BOTH original
   Image= and original canonical refs to the five expected IDs. Same-config pin
   and Pull=never; daemon reload; controlled native wake. All exact units are
   stopped again at return; no enable/disable changes.
2. Verify the original baseline independently, then open its encrypted manifest
   with the existing private dev-e kit. Use native KeyStore.temp_identity's valid
   `key-inspect-focus-r6` name and context-manager cleanup, with no key import or
   metadata update. Require current preflight `ok`, one restorable Nextcloud,
   settings same/inplace; original app35.0.1.1 healthy and installed engine hashes
   exact d09. Fail before HA upload if any assurance fails.
3. Reuse the **original existing** fixture in place:
   `~/.woowbk-lab/ha-fixtures/20261123-batch2/x86/woow-b2-nextcloud-x86-enc-share/woow-b2-nextcloud-x86-enc-share-20261123.tar`,
   **4467947520 bytes**, SHA256
   **2dcfc6769d6fed7dd5c375fc379aac43da606931c8378e3970c33f78a4bded9d**.
   Reuse original scratchpad/nc-import/share-facts.json; no new full fixture copy.
   Stream1MiB host chunks; bound/hash bytes on host and in the exact device writer,
   whose reserve/expiry checks run inside dev-e. Close/wait the writer on failure;
   refuse upload-finish on mismatch, abort only its recorded upload.
4. Require current ha-check job facts (including PG16/NC35.0.1.1), exact one
   importable Nextcloud, no stop or unexpected confirmation. Convert with actual
   check_job_id and the exact bound keys (empty for original fullshare). Inspect
   converted preflight/settings/data, delete this case's uploaded HA store before
   restore, retaining original host fixture and original native baseline.
5. Reuse historical113 client checks: all-user digests/CJK/binary, OCS password and
   app password, wrong login, user share/password-protected public link controls,
   CalDAV/CardDAV/versions, Office/WOPI edit-save, protected web paths, restart,
   forced one-shot failure/automatic rollback and manual initial-safety rollback.
   Relay/injection paths have unique owned IDs; relay uses exact loaded nginx ID,
   pull=never/image-volume=ignore. No duplicate completed no-share case.
6. Persist start request IDs without key bodies before API calls, reply job IDs
   before waiting, then every own upload/native backup/safety ID. Cancel/reconcile
   only recorded own jobs. Unknown jobs block cleanup. Baseline and foreign IDs
   are forbidden for delete/restore; safety recovery uses only this case's IDs.
   Prove exact original markers/users/config/units/Office settings and independent
   baseline verification before deleting any owned converted/safety copies.
7. Stop and join reserve/expiry/memory monitors; recovery has an explicit30-minute
   grace and its own watch. Before cold/source return, independently require no
   active job in the complete store. On uncertain writers/data, retain current
   engine and private copies/receipt for coordinator reconciliation, no retry or
   unsafe overwrite. No live source/library swap while any job is active.
8. Proven recovery: stop stack/cron, restore exact prior Quadlet bytes/attributes,
   daemon reload, restore prior engine/helper/VERSION under native locks. Compare
   original unit states/enablement, all five images, catalog, baseline archive+
   manifest SHA, isolation/cap and installed hashes. Keep images loaded. Private
   leak scans include the baseline kit and HA/client credentials; fixed public
   result contains only counts/IDs/hashes/statuses/resource measurements.

## Verification and remaining scope

New source final **21/21**, failures/errors/skips0, includes actual compiled native
KeyStore+age+encrypted archive success/wrong-key cleanup, all rendered probes,
prepared reserve failure, four interrupted install renames and four interrupted
return renames, foreign edits, malformed source tar, deletion ownership and real
native flock refusal/release tests. One final neighbor run **47/47**,0fail/error/skip.
The first15-case run had5 test setup errors from group-writable temp fixtures;
fixtures were fixed to real deployment modes. Ownership validation was preserved.

This proves preparation only. Current-source fullshare acceptance awaits this
phase's parent lease and actual execution. Genuine server-side encryption S5 and
skipped-link/.htaccess acceptance require separate genuine fixtures/oracles and
remain gated; HA archive encryption is not S5 proof.
