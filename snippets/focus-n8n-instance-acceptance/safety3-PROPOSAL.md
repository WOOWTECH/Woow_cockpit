# SAFETY attempt3 — code ready; fresh lease required

This packet supersedes only the aggregate-inventory assumption of cbbc68f7.
`safety-attempt2-failure.json` preserves the exact failed run and evidence SHA.
The old proposal and attempt2 public/private captures are unchanged.

## Actual cause and safe state

SAFETY2 cbbc68f74756330304ff4dfc09f6a9182d96c6bc exited1/4.4s at
`preserved_safety_prepare`: native ValueError, fixed literal
`preserved inventory bound`, errno null. The outer RuntimeError is its wrapper.
Bounded c-mutex read-only diagnosis called original `current()` without calling
prepare/operate again. It found124 managed files,566,460,445bytes, largest
12,564,480bytes; the128MiB total limit was too small. There was no private
preservation directory, state or saved root failure record. This was before
timer/catalog intents, PG, service writes or any job. No retry or recovery ran.

All10 durable comparisons match the source-fullflow original baseline, covering
the4 manual protected files. Both older pairs match their pinned sidecar SHA,
type/apps/archive SHA/size/owner/mtime. No running containers or active jobs;
c mutex released. D09 remains installed; source1/source2/source-fullflow proof
namespaces have not been modified by this attempt. The latest read-only pass
did not independently rehash every source-copy file; prior exact-source proofs
remain historical and are not presented as a new source validation.

## Narrow fix and complete-payload regression

Only the preservation helper inventory changes. Stream every managed file in
1MiB chunks, retaining ALL hashes/bytes/mode/UID/GID/mtime. Per-file64MiB and
1024-file bounds remain. The total read limit becomes1GiB, the next power of
two above the measured566,460,445bytes, leaving507,281,379bytes for this tiny
case's new archives. This is an I/O limit, not disk allocation. The13GiB reserve
+8GiB DATA and both RAM floors remain unchanged. Exceeding any limit still
refuses before service writes; no archive is skipped. File descriptor identity,
size, mode, ownership, mtime and ctime must match before/after streaming and the
current pathname. No old archive, sidecar, retention config or product changes.

`focus_n8n_instance_acceptance_payload_test.PayloadTests` executes the EXACT
Controller-rendered root payload, including helper module creation, real
`__main__` JSON dispatch, inventory, local flock, Store, copying and failure
journal. Fake boundaries supply only root identity, absolute filesystem paths,
pinned synthetic fixture bindings and fixed readonly command replies. No
operation/dispatch/Store/read/hash function is replaced. One minimal sparse
inventory above128MiB failed with the same literal before the fix and passes
after it. Every inventoried hash/metadata is also compared with the independent
existing reader. Corrupting a private copy makes the full payload refuse and
save the exact operation/ValueError/null-errno record without original writes.
These are LOCAL integration guards, not native/vendor acceptance.

The two payload tests plus the existing three preservation file tests pass:
5/5,0fail/error/skip/blocked/shim, native denied. Earlier fixture-boundary setup
failures and the actual pre-fix red log are retained; repeated runs do not add
distinct tests. No broad suite, PG, images or original34 repeat.

## Fresh exact command — NOT GRANTED

Clean checkout `/tmp/parity-focus-n8n-instance-flow-20261127`; full new driver SHA
and file hashes are in external `n8n-safety3-bindings.json`. Product remains
`/tmp/parity-focus-final-gate2-20261127`
@d09f4fe8e06305aff6a1150f41d6de719e7b7f6a, same original case/image receipt.
Request a NEW25minute lease; attempt2's grant is consumed and is not reused.
Parent must admit current host/device floors and global2heavy/c mutex.

```sh
HEAVY_FREE=/tmp/woowbk-dev-c-mutation.lock HEAVY_WAIT=0 /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/services_a_capture.py --private=/tmp/parity-focus-20261127/n8n-safety-attempt3.private.log /tmp/parity-focus-20261127/n8n-safety-attempt3.json n8n-instance-safety3 -- python3 -B -I tests/e2e/lab/focus_n8n_instance_acceptance_run.py --execute --phase safety --lease /tmp/parity-focus-20261127/lease-n8n-instance-safety3-dev-c.json --source /tmp/parity-focus-final-gate2-20261127 --receipt /home/woowtechopenclaw/.woowbk-lab/run/focus_n8n_instance_acceptance.json
```

All previous preservation and native safety requirements remain: FIRST verify
private exact copies of BOTH NOTOWN older pairs in the still-absent separate
0700case, originals stay visible; only then fresh encrypted/unmarked full
instance safety/allDBs/roles. SAFETY executes no restore/old prune. Require the
manifest and exact original10durables/fourmanual+oldtwo pairs/cold catalog/timer
return. Keep fresh safety and private copies for a separate reviewed40minute
FLOW. On any failure preserve full private fixed diagnostics and stop; no
automatic retry/recovery. No source/image/old34/nativePG/FLOW action is granted
by this proposal. The older exact O_EXCL return and own successful-pruning-event
requirements in `safety-preservation-PROPOSAL.md` remain unchanged.
