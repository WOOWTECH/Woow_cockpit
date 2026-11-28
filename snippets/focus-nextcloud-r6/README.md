# R6 preparation, 2026-11-27

**Latest (2026-11-27 23:05 Asia/Taipei): the full share on the current source PASSED 118/118** (fullshare05,
driver `550478ae`, engine of draft PR #23 `5168f1ec`, dev-e returned exactly). Two earlier attempts that day failed
on driver bugs, now fixed (`282bfba1`: a field the convert request may not carry; `550478ae`: one failed resource
probe stopped the run). Details and evidence: [fullshare05-RESULT.md](fullshare05-RESULT.md). The sections below
are the earlier history, oldest first.

**2026-11-28: S5-A (the server-side-encryption source) built and verified on dev-e.** The builder (`focus_nextcloud_r6_s5.py`,
run at `4163367c` = `c46f9a31` here) started a throwaway Nextcloud 35.0.1 + PostgreSQL 16 + Redis inside dev-e from
the original images, enabled server-side encryption with Nextcloud's own commands (master key; every step checked
against an occ help contract taken from the v35.0.1 source), wrote one plain file before and files after enabling
it, proved ciphertext, the native header, master key and one share key per file on disk, re-read everything after a
restart, and packed an HA-shaped test backup (`generated-s5-source.tar`, 127,600,640 bytes, kept inside dev-e; it is
generated, not a HAOS export). dev-e's own Nextcloud was exactly unchanged; the throwaway source was removed, the
fixture and the S5-B inputs kept. Result: `tests/backup/evidence/focus-nextcloud-r6-20261127/s5a-source-fixture-20261128-result.json`.
The builder's review also found a product defect, fixed in `50a29370`: the importer accepted only 'yes' for
core/encryption_enabled, while Nextcloud 35 stores '1'.

**2026-11-28 09:5x: S5-B (the import acceptance of the server-side-encrypted source) PASSED 96/96 on dev-e**
(attempt 04, driver `3f284a39`, frozen product `b058df27` with `50a29370`). History, all with a clean recovery:
- attempt 01: the product's check stopped with "database not ready": the first fixture had no `postgres` role (its
  container ran with POSTGRES_USER=nextcloud) while the product opens HA clusters as postgres; the one-shot diagnostic
  (`focus_nextcloud_r6_s5_diag.py`, verdict `missing-postgres-role`:
  `tests/backup/evidence/focus-nextcloud-r6-20261127/s5-diagnosis-20261128-result.json`) proved it. The misleading
  sentence itself was a product defect (podman.REASONS order), fixed on the integration branch in `7a2023e8`.
- the builder was fixed (`0c874b63`, `04bca4d6`: the real add-on's database shape - superuser postgres, role,
  database and tables owned by nextcloud, member directory entries - and a gate that opens the packed fixture through
  the product's own check path, 12/12), the first proof root retired against the diagnostic evidence, and S5-A rebuilt:
  `s5a-source-fixture-rebuild-result.json` (127,467,520 bytes, sha256 `df9a7adf...`), the switch commit `46a13766`.
- attempt 02 stopped at a one-off unparseable engine-hash probe before any upload (not reproducible in six retries);
  attempt 03 passed upload and every substantive check fact and stopped only at the processor: the generated add-on
  names no HA image, so the product truthfully says `unknown` (HA-06); S5-B expects that since `3f284a39`.
- attempt 04: check (importable, exactly one confirmation nextcloud.server-side-encryption with files_encryption and
  encryption_enabled), the unacknowledged conversion refused, the acknowledged import, every ciphertext, plaintext and
  key file byte for byte, decryption through WebDAV, a new file stored with the native header, restart, an injected
  failure rolled back automatically, the manual rollback, dev-e exactly as before, cleanup and leak scans:
  `s5b-import-acceptance-20261128-result.json`. The proof root was removed only after everything passed.

Read-only inventory and original image identity checks are complete. **No image
bytes copied, no device mutation, no pulls.** This worktree starts at main
`3e3e9315`. OD-23's final separate handoff commit is `081278f1`; its worktree,
retained release and failed-export quarantines are preserved.

The statement above describes phase0. **Phase1 image-only recovery has now
PASSED on exact source `ea17ae7964201e43c0a3f318019dfa97652fa86a` under the
parent's55minute image-only lease.** All five exact original IDs are loaded;
source metadata is unchanged, pulls0. Units/Quadlets/catalog/baseline metadata
and3GiB cap/isolation match before/after exactly. Independent post-run inventories
confirm this. Minimum completed transfer free28,070MiB; final fresh free
29,423,403,008 bytes and memory271,290,368. Images retained. No wake, install,
deployment, fixture copy, catalog write or restore was performed.

Actual receipt is `image-recovery-result.json` in this lane's evidence folder;
private controller evidence is
`~/.woowbk-lab/evidence/focus-nextcloud-r6-recovery/20261127T071755/`.
The original NC image alone used the reviewed lab `ignore_chown_errors` option:
UID65534 exceeds the unchanged nested range. The config ID remains exact; this
is an explicit lab mapping limitation.

**Next proposal:** [wake-PROPOSAL.md](wake-PROPOSAL.md), executable
`focus_nextcloud_r6_wake.py` and inert `lease-wake.template.json`. Eleven focused
offline tests pass (0failure/error/skip), including functional snapshot/pin/revert
on disposable local files, wrong identity/no writes, tampered copy and foreign
edit refusal, default no device access, and image-only lease refusing wake.
It requires a NEW parent-reviewed wake-baseline lease. No wake is authorized by
the existing image lease. Whole mutex; same-config pin refresh with exact private
prior copies; baseline verification; original inactive/enablement state and
Quadlet bytes restored; retain loaded images. No installer/source deployment.

**Phase2 strict wake/baseline has now PASSED on exact `e365ac88`**, under its
separate parent lease. All five original Image references and canonical tags
resolved to the trusted config IDs before writes; no guard correction was needed.
Read-only baseline verification7/7 passed. Prior unit bytes, UID/GID/mode/mtime,
original references and config bindings were independently re-read after return
and exactly equal. Original inactive/enablement states, catalog, baseline archive
and manifest streaming hashes, installed engine hashes, cap and isolation all
match. Five images retained; pulls0. No restore or source deployment occurred.

Actual source `e365ac88bc5e536ea632dda39c24f01a1d1b6e20`; private evidence
`~/.woowbk-lab/evidence/focus-nextcloud-r6-wake/20261127T074932/` (including exact
prior and independently re-read post-revert units, both private). Public files
`wake-baseline-result.json`, `wake-baseline-verifier-summary.json` and
`inventory-after-wake-baseline.json` are in this lane's evidence folder.
Start minimum free28,905,500,672 bytes, peak measured memory809,451,520;
fresh cold free29,021,827,072 and memory554,872,832 under the unchanged3GiB cap.
No additional tests were run for this evidence-only retention.

## Exact original source images

Live host fixed-field inspection uses the same `podman image inspect` route as
`deploy-batch2.sh:copy_image`. All five are present, Linux/amd64, with their
canonical tags resolving to these exact config IDs. Full RepoDigests are in
`tests/backup/evidence/focus-nextcloud-r6-20261127/readonly-source-images.json`.

| Image | Config ID (sha256) | Image bytes |
| --- | --- | ---: |
| localhost/woow-nextcloud:35.0.1-office2 | e80170f48ac2534abd0960be4838dbe9fcdc498da924a62f2436cd470dab4165 | 1,969,012,061 |
| docker.io/collabora/code:26.04.4.2.1 | a35ff1de149aeae0b1c9ecc83ab9406bd14a788cd61284e95b88b602df4a6ba3 | 1,329,397,778 |
| docker.io/pgvector/pgvector:0.8.6-pg16 | 9b05db12a35460fff0587e009f9326e414a53e9484555547f96d214a2ba98ef7 | 446,255,297 |
| docker.io/library/redis:8.10.1-alpine | d1e21a26915a35a6eb5d820018cd55adfcda02e02f7d629e1f42df397d5494ad | 119,464,062 |
| docker.io/nginxinc/nginx-unprivileged:1.29.3-alpine | 696695300a3c18a324c07ecb41f220e8c470302148b0378770cf5c70e6458ea0 | 54,273,323 |
| **Total** | | **3,918,402,521** |

## Baseline and original full-share fixture

Dev-e has a **3GiB** cap, network `none`, ports `{}`, no nested original images,
and all captured Nextcloud units/timers inactive/dead. Keep their enablement
states. No cap increase is proposed. Catalog SHA256:
`3a7af03b966f90a172e417a3ea69d7b36bf98a23af8d27b0c074bd01b6f335d6`.
Original encrypted baseline `20261123T132013Z-34811d90` remains present
(422,031,360 bytes); decrypt/restore feasibility and live baseline verification
require a reviewed wake. Image-only recovery does not wake or modify the app.

Reuse this existing file; no full host fixture copy:

```
~/.woowbk-lab/ha-fixtures/20261123-batch2/x86/woow-b2-nextcloud-x86-enc-share/woow-b2-nextcloud-x86-enc-share-20261123.tar
```

Size 4,467,947,520; trusted SHA256
`2dcfc6769d6fed7dd5c375fc379aac43da606931c8378e3970c33f78a4bded9d`.
Fresh full SHA is deferred to the leased streaming upload (inventory checked
existence/size). The original private facts are already saved at
`scratchpad/nc-import/share-facts.json` under the existing session scratchpad.
They contain four marker hashes, four user manifest digests, shared/public-link,
CalDAV/CardDAV, versions, Office checks, and credential **names**. Read credentials
only with the existing private readers. Never publish facts or raw helper logs.

Historical original full-share proof: 113/113, source `6a67eefa`, 2697.3 seconds.
Current completed no-share proof: 36/36, source `a3f49012`; excluded from this plan.
The current full-share acceptance candidate binds conversion to the current
check job and exact reviewed confirmation keys. It reuses the original client,
restart and automatic/manual rollback checks. It never bypasses the adapter.

## Resource phases

Observed free: 33,807,986,688 bytes. Reserve: **13,958,643,712 (13GiB)** throughout.
Images/fixture already in the host source store are already charged to that free
space. Transfers run sequentially and are removed between images.

| Phase | Additional peak bytes | Gate |
| --- | ---: | --- |
| Compressed image transfer/load | 6,527,630,739 maximum | Prior loaded images + image + twice compressed transfer; compression capped at image size +16MiB, plus512MiB margin |
| All images + first-start copy | 7,676,498,905 | All3,918,402,521 image bytes +3GiB controller ID mapping allowance +512MiB margin |
| Full-share after wake, using historical actual package sizes | 7,859,348,300 | Includes4.47GB upload, pessimistic uncompressed conversion packaging, retained safety/rollback and512MiB margin |
| Full-share admission with1GiB converted and1GiB safety bounds | 9,296,980,812 | Recompute from fresh live html/PG/data sizes; actual package sizes gate every restore |

Conservative combined last two applicable peaks leave **16,834,506,971 bytes**,
2,875,863,259 above the reserve. The historical estimate leaves18,272,139,483.
These are estimates, not a waiver of live admission. Recompute after recovery,
after wake, after check and before each restore. The uploaded HA copy is deleted
after conversion inspection, before any restore; original fixture stays.
No additional full fixture or simultaneous variant staging is budgeted.

Image recovery's initial gate includes the controller's additional1GiB admission
margin: **22,708,884,441 free bytes required**. The retained13GiB floor is raised
from the old controller's12GiB; its existing extra1GiB admission reserve remains.
Host RAM admission >=2200MiB (global heavy wrapper may demand3000 for slot2).
Device headroom admission >=1536MiB under the unchanged3GiB cap. Fresh live
headroom after wake must pass before starting the case; otherwise stop and retain
the recovered images, without increasing the cap.

## Exact first lease proposal: image recovery only

Review `tests/e2e/lab/focus_nextcloud_r6_recover.py` and the inert JSON template
here. Fill the committed HEAD and actual time window in a NEW private lease.
Proposed duration45minutes. Scope:

- Host source store: only fixed-field inspect and save of those exact five IDs.
- Save via the existing controller's compressed Docker-directory route into its
  exact five absent `/home/.woowbk-xfer/<config-id-first-12>` transfer leaves on
  dev-e's existing home backing volume. Refuse any pre-existing leaf/link.
- Nested appowner load/tag to the five exact refs; Nextcloud alone retains the
  controller's existing lab `ignore_chown_errors=true` flag (65534 exceeds the
  unchanged nested UID range). No host tag/load/delete/pull.
- Frozen controller SHA is checked before bounded adaptation. Keep its original
  algorithm; raise floor13GiB, cap compression, enforce lease expiry. Nested load
  is supervised inside dev-e: on reserve/expiry stop, terminate its exact process
  group and wait before returning. The outer RPC client alone is not the writer.
- No wake, install, deploy, fixture copy, key init, catalog write, baseline restore
  or cache/image deletion. Preserve units/Quadlets/catalog/baseline metadata;
  re-inspect exact source identities after recovery. Any failure stops the phase;
  do not automatically retry or delete new image stores.

From `/tmp/parity-focus-nextcloud-r6-20261127`, after review and lease only:

```sh
HEAVY_FREE=/tmp/woowbk-dev-e-mutation.lock /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/focus_nextcloud_r6_recover.py --run --lease /tmp/parity-focus-20261127/lease-nextcloud-r6-images.json
```

The launcher acquires the whole device mutex after the heavy wrapper's queue.
Default invocation is offline and cannot copy anything. First lease result must
be reviewed before waking/installing/running acceptance. Retain recovered images
for those later leased cases; all original units remain inactive after phase1.

## Full-share and remaining cases: later lease boundaries

Before full-share: reviewed source-only deployment of the committed candidate;
first inspect installed tools, avoid apt/package/image recovery. Verify every
installed module hash, catalog, original image IDs, isolation and3GiB cap. Wake
using only loaded images under the same13GiB monitor, then independent
`batch2_baseline.py --verify nextcloud` before accepting any import mutation.
Full-share candidate command is `focus_nextcloud_r6.py --run --case fullshare
--lease <new-exact-lease>`; requires original inactive unit scope in the lease.
It streams upload1MiB at a time, records jobs before waits, cancels only its own
IDs and retains recovery artifacts on uncertainty. It independently verifies the
baseline before cleanup, then stops the original Nextcloud stack/timer and checks
the inactive states and enablement. Whole-case launcher/wake/source deployment
must be reviewed together before that second lease; no command in this paragraph
has been run.

**2026-11-28: skipped entries PASSED 140/140 on dev-e** (attempt 02, driver `3b4d8823`, frozen product `b058df27`):
the streamed derivative of the original full-share backup (`focus_nextcloud_r6_skipped_derive.py`: one relative symlink,
one nested `.htaccess` with `Require all granted` and a control file in a folder no user owns; the share member
re-encrypted with the same HA key, the original gzip byte for byte after the added segment; 4,467,947,520 bytes,
sha256 `757ab01f...`; never materialized, streamed from the host into dev-e's upload file) gave exactly the two lines
`nextcloud.symlinks-skipped` and `nextcloud.htaccess-skipped`; the unacknowledged conversion was refused at the link
line, the link's key alone at the `.htaccess` line, both keys imported; after the import, a restart and the automatic
rollback the skipped entries were absent, the control file byte for byte, the device's protection file exact and the
derived folder 403/404; dev-e returned exactly. Attempt 01 stopped at a judgement that read the named line from
`error.details` (job records keep only code and message; fixed in `3b4d8823`). The derivative is not a HAOS export
(HA never writes a multi-segment gzip member; the product's reader accepts it). Results:
`tests/backup/evidence/focus-nextcloud-r6-20261127/skipped-entries-20261128-*.json`.

(History, before 2026-11-28:) **Skipped symlink/.htaccess and genuine server encryption are not ready to run.**
The candidate explicitly refuses those cases pending separately reviewed fixture
construction/oracles. This is a recorded remaining gate, not acceptance evidence.

**2026-11-28: skipped entries prepared as code, NOT run** (`focus_nextcloud_r6_skipped_derive.py` builds the
derivative, `focus_nextcloud_r6_skipped.py` is the leased case on R6's machinery, offline tests
`tests/backup/test_focus_nextcloud_r6_skipped.py`). The three reviewed additions sit in a folder of their own below
HA's data directory (`woowbk-r6-skipped-entries/`: `control.txt`, `.htaccess` with `Require all granted`,
`control-link.txt -> control.txt`), so no user's file list, files:scan or manifest changes. The share member is
re-encrypted (SecureTar v3, the same HA key and root salt) around a plaintext that is the reviewed gzip member followed by
the original gzip stream byte for byte. `--plan` (host only, no lease) streams the derivative into a hash and back
through the product's own readers and writes the private provenance; the leased run makes the same bytes again straight
into dev-e's upload file through R6's in-device writer (nothing materialised). Expected check: exactly
`nextcloud.symlinks-skipped` [`nextcloud/woowbk-r6-skipped-entries/control-link.txt`] and
`nextcloud.htaccess-skipped` [`woowbk-r6-skipped-entries/.htaccess`]; two refused conversions (none, the link key only),
then both keys. A passing run prints 140 fixed lines (fullshare05's 118 plus 22).

For skipped entries, use a streamed derivative of the original share fixture:
add one harmless relative symlink, one nested `.htaccess` with an unsafe allow
directive, and an ordinary control file. Preserve all original bytes/metadata
apart from those reviewed additions. Avoid materializing another4.47GB archive;
stream the derived upload, measure/hash it, and retain provenance. Check must
require exactly `nextcloud.symlinks-skipped` and `nextcloud.htaccess-skipped`;
unacknowledged conversion refuses. Confirm using actual bound keys. After real
restore and restart, skipped paths must be absent, control file/ordinary original
data intact, device-generated root protection hash exact, data URLs403/404.
Then independent baseline recovery before deleting owned artifacts.

For S5, HA securetar encryption is insufficient. No genuine SSE fixture was found.
Prepare a **new isolated source fixture while the target is cold** using these
original Nextcloud/PG16/Redis images, no network/pulls, bounded source containers
(proposed Nextcloud900MiB + PG256MiB + Redis64MiB). Review exact local OCC help and
master-key/user-key procedure before constructing it. Enable the real encryption
app, write a small known file through WebDAV, verify plaintext response SHA,
different ciphertext bytes and actual encryption key files, then cold-snapshot
the genuine PG16/config/data into a private HA fixture. Do not substitute a SQL
flag or manufactured key directory. Proposed separate source build budget7GiB
(filesystem/mapping + source + <=1GiB fixture + temporary packaging); admit only
if free>=20GiB and retain13GiB. Tear down only the new source containers/stores
before waking the target. Acceptance must prove the same plaintext SHA through
WebDAV after restore and restart with actual keys/ciphertext preserved, plus
baseline rollback. Review the exact builder/driver and measured sizes before a
new S5 lease; the source budget is a proposal, not an executed or proven bound.

No central docs or registry changes are included. No Nextcloud product changes,
no duplicate no-share acceptance, no R8 interruption, no ARM/auth work.

## Verification performed

One guarded focused run of `tests.backup.test_focus_nextcloud_r6`: **18 tests,
0 failures, 0 errors, 0 skips**. These are offline boundary checks: image/disk
accounting, lease expiry/scope/cap/reserve, exact confirmation IDs/keys, refusing
fake S5 facts, default entrypoints without device access, fixed source inspect,
frozen controller adaptation/shell syntax and simulated inside-device load
termination/reaping. Guard log:
`/tmp/parity-focus-20261127/nextcloud-r6-boundaries-01.log`.
No actual image recovery, wake, acceptance or fixture construction was performed.

## Current full-share proposal (d09)

Strict wake proof is committed in f0ae8b95, independent7/7 and exact cold return.
Next executable phase is [fullshare-PROPOSAL.md](fullshare-PROPOSAL.md), with inert
[lease-fullshare.template.json](lease-fullshare.template.json). It uses frozen d09
source-only deployment, protected prior engine/helper/VERSION, original4.47GB
fullshare fixture in place, and full data/source/unit rollback. No deployment or
fullshare execution has occurred. Preparation result and every frozen source
file hash are retained under the lane's public evidence directory.

## Actual full-share attempt01 and recovery

[fullshare-attempt-01-RESULT.md](fullshare-attempt-01-RESULT.md): original fullshare
stopped during upload; cause unrecorded, no check/conversion/app restore occurred.
Known Office failed flag blocked cold return before either revert. Parent-approved
recovery using unchanged d7 primitives passed exact original source/unit return;
all fixed failed/recovery evidence and SHA bindings retained. Dev-e/heavy released.
Fullshare/S5/skipped acceptance remains pending; no retry is authorized.

## Next cold upload-only proposal

[upload-only-PROPOSAL.md](upload-only-PROPOSAL.md) and inert
[lease-upload-only.template.json](lease-upload-only.template.json): isolate only
begin/bounded SHA stream/finish/own abort with complete private error diagnostics,
apps cold and exact restored old helper. One verified owned HA store can be
retained and lease-bound for later fullshare reuse; no duplicate transfer or
unverified disk credit. Current fullshare/cold-return code has the narrow owned
Office post-STOP exit137 gate. No new runtime lease/execution yet.
