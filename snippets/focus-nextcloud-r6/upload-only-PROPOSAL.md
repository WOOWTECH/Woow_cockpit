# R6 cold UPLOAD ONLY: bounded minimal repro for parent review

CODE PREPARATION ONLY. Original failed fullshare upload cause stays **unknown**;
this controller has not run on dev-e. No new runtime lease exists. Parent can grant
**55 minutes upload-only +5 minutes only for own abort/reaping** using the inert
lease template. Exact source commit must match the reviewed checkout; one use of
that exact lease is claimed with an exclusive immutable host marker before begin.
No automatic retry. The earlier failed receipts and recovery evidence stay intact.

## Exact command

From clean `/tmp/parity-focus-nextcloud-r6-20261127` at the reviewed commit:

```sh
HEAVY_FREE=/tmp/woowbk-dev-e-mutation.lock /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/focus_nextcloud_r6_upload.py --run --lease /tmp/parity-focus-20261127/lease-nextcloud-r6-upload-only.json
```

Whole dev-e mutex and global heavy seat throughout. Apps/timers stay cold. No
source deployment, wake, baseline/client rerun, PostgreSQL, HA check/conversion,
app restore, installer, apt, key operation, pull, tag, image recovery, resets or
new full host fixture copy. Existing d7 fullshare lease authorizes no such rerun.

## Existing helper and fresh admission

Require the exact restored prior library/cache/helper/VERSION against its retained
root journal (state restored, aggregate SHA256
`cb23acdb178c1614b0cbc24b5d294a0652959ac36c2c0a651ff44917da8c02e1`).

- Helper SHA256 `539c32a6a0c7689797f2d571f2ea56a038a79a647955df42f4cfb97a6bc03678`
- VERSION SHA256 `29ddb46f49384f63c69c2112c1e9b03c1ff2c4993904cc4723ff544fcb32ee92`
- Root regular/non-writable helper, isolated shebang and no-bytecode/separate-cache
  policy checked. Same helper hash rechecked inside each upload RPC supervisor.
- This exact binding was independently read-only confirmed after recovery. No
  native helper command was executed for that preparation read.

Fresh original cold unit/enablement/image/catalog/isolation/cap inventory,
no active engine jobs, host available>=2200MiB, device headroom>=1536MiB,
cap3221225472. Retain reserve13958643712 bytes (13GiB). Upload-only additional
allocation bound: **4467947520 +536870912 bytes**, requiring
**18963462144 bytes free** on min(host backing free, device /var/lib free).
This is above the existing17GiB cold gate. One device upload is renamed into the
HA store; no second4.47GB file is created. Metadata/log margin512MiB is conservative.

Require upload directory empty and all existing HA store files paired/root-owned
regular files. Expected HA record must be **absent before begin**, preventing a
native deduplicating upload from granting ownership of someone else's record.
Only one original file is read from its existing host path:

`~/.woowbk-lab/ha-fixtures/20261123-batch2/x86/woow-b2-nextcloud-x86-enc-share/woow-b2-nextcloud-x86-enc-share-20261123.tar`

Size **4467947520**, SHA256
`2dcfc6769d6fed7dd5c375fc379aac43da606931c8378e3970c33f78a4bded9d`.
Expected native HA ID **ha-2dcfc6769d6fed7dd5c3**.

## Minimal workflow and observable failures

1. Only existing old helper upload-begin; record exact request phase before call,
   transport/helper return codes and private stdout/stderr. Validate returned uID
   and exact `/var/lib/woowtech-backup/uploads/<uID>.part` path. Never guess an ID.
2. Stream original file in<=1MiB host chunks, with nonblocking pipe writes,
   partial-write accounting, exact host SHA/count, writer return code and own EOF
   reaping. Device writer uses<=64KiB reads, O_NOFOLLOW, root regular/nlink1/empty
   file and captures its original dev/inode. Hash/count before successful EOF.
3. Writer checks actual min(/home,/var/lib) free>=13.5GiB, expiry, cgroup memory
   <=2.5GiB under unchanged3GiB cap. Helpers have an inside-device process-group
   supervisor with the same watcher while hashing/describing/publishing; bounded
   stdout/stderr, cancellation and exact child wait/reap. No host RPC per chunk.
   Host checkpoints every64MiB or15s are private progress events only; host expiry
   checked while waiting/writing. Writer itself continues enforcing the resource
   floor even while host/pipe stalls.
4. Every failure saves **exact exception class, errno, fixed stage, chunk offset,
   private exception text/traceback, raw private writer stderr, RPC helper and
   transport return codes, and actual watcher failure reason/class/errno**. Error
   events fsync before any own abort. Raw device stdout/stderr stay in0600 files
   under0700 evidence directory, with hashes in private diagnostics. Public output
   contains fixed status/counts/hashes, never raw archive/member/error contents.
5. Lost begin reply: retain evidence, no guessed cleanup. Unreaped writer: no
   abort race. Finish-requested/lost reply/publication uncertainty: retain known
   upload/store and receipts; no abort or broad HA deletion. Only a known own
   begun/streaming/streamed upload whose writer is reaped may call upload-abort.
   Abort has the explicit5-minute cleanup grace; resource floor remains checked.
   If cleanup cannot pass its guards, stop and preserve evidence for review.
6. Existing helper upload-finish only after both stream proofs. Require exact
   HA ID/size/SHA; independently stream-hash the retained root-protected file,
   verify native sidecar SHA/size, inode identical to the original writer inode,
   and unchanged stat identity while reading. No decrypt or HA check. A successful
   file is retained, never deleted in this phase. A failed/unconfirmed result does
   not become an ownership/space-credit receipt.
7. Compare exact cold units, enablement, original images/catalog/isolation/cap and
   complete prior source/cache/helper/VERSION again. Full job store still active0.
   Retain immutable fixed-result.json and all private raw failure evidence.

## Next full-share reuse (code prepared, runtime separately gated)

The upload receipt records its source commit, original absent-before proof, uID,
expected HA ID, full SHA/length, writer/published inode, sidecar SHA and allocated
bytes. A future fullshare lease binds the **exact receipt file SHA256** and supplies
`--retained-upload-receipt <fixed-result.json>`. The receipt is opened once with
O_NOFOLLOW, bounded to64KiB and hashed from the exact bytes parsed.

Before any source stage/app wake, independently hash the device file again and
match root ownership, SHA/length, inode and sidecar. Only then adopt it as this
case's owned HA store and skip the transfer. Credit only
`min(logical verified length, actual st_blocks*512)` already allocated bytes. The
same archive is deleted before app restore, so this credit reduces remaining
peak once;13GiB reserve never changes. Duplicate/negative/oversize credit is
refused. No receipt or current file proof means no credit/adoption.

Future fullcase still needs current HA check and actual bound acknowledgement
keys, conversion inspection, actual clients/restart/automatic+manual baseline
rollback and exact source/unit return. No successful transfer is repeated.

## Narrow cold-return correction (future fullcase only)

`focus_nextcloud_r6_cold.py` claims the Office unit invocation/PID after this case
wakes it. STOP and monotonic start time are captured inside the same owner process.
Only if original Office was inactive, claimed invocation still active immediately
before STOP, and its exact same invocation exits137 **after** STOP with PID0 and
unchanged enablement, may that unit's failed flag be cleared. Complete tuple is
re-read before reset. No pre-existing failure, unrelated invocation, OOM/result,
other exit code, live PID or other unit is reset. This upload-only phase never
calls the cold-return reset path because it never starts an app.

## Verification

New FSM/provenance/diagnostic/watch/cold tests **18/18**; single final neighbor run
**57/57**,0fail/error/skip. Injected partial EPIPE retains errno32 and exact offset
before abort; lost replies and live writers retain uncertain objects; tampered
receipt/inode/sidecar rejects adoption; actual rendered watcher distinguishes
expiry/reserve/memory from a probe errno; all device programs compile. No broad
suite or real upload runtime was run. The initial failure remains unknown.
