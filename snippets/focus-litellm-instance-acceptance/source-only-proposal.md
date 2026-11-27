# LiteLLM preparation: protected dev-d source update

CODE ONLY. No dev-d read, source update, LL init or image build has been run
for this phase. Parent terminal release after the cookie probe and exact owned
Omnigent catalog return is required before even the fresh read-only snapshot.
The image controller remains at reviewed `dd2f5165` bytes.

## Exact files and bindings

The new source controller reads immutable Git blobs, checks blob modes and
compiles every candidate Python file and helper without executing the helper.
It updates only 51 engine Python files, library VERSION and the helper. The
case journal and private staging/copies are the only additional writes.

| Binding | Value |
| --- | --- |
| Old source | `1adf4df2b548bff1626e21d1d84e677f9622e4bc` |
| New source | `59a1b0f95132ea51c899f590eea7e3b02c5dba43` |
| Old managed manifest SHA256 | `d4c3f8f263af4abbe4a0a3dae04200683afd04a3782eef1268384d0a063d44cc` |
| New 53-file manifest SHA256 | `cd4817d7979b5f114ca403f2281531131f32e6ffd9b7efb870bdbf9bdd624912` |
| Whole encoded payload SHA256 | `0a5e2ba951588e609b13a734d7c380d8bd513892350e697f29c3acfef9721840` |
| Method | `per-file-os.replace-whole-prior-cas-v1` |
| Proposed case name | `woowbk_focus_litellm_source_73cb85d09a42` |
| Root journal | `/var/lib/woowtech-backup/focus-litellm-source/woowbk_focus_litellm_source_73cb85d09a42/state.json` |

The lease binds the exact full driver commit, all five source bindings above,
case/name/device/method, allowed phases, bounds, timezone-aware start/expiry,
and the freshly approved **source** baseline SHA for install/recover. An image
lease does not authorize this source phase. No lease is created by this patch.

## Read-only snapshot and running app protection

After parent releases dev-d, a separately reviewed `source-snapshot` invocation
captures the full raw inventory in a private host receipt and emits its canonical
SHA256. Parent approves that SHA for `source-install`/`source-recover` in a new
lease/output. New IDs created by R8 are valid inputs to this fresh capture.

The snapshot covers every catalog, declared app config file, root backup
config/keys, template catalog and UI tree; owner Quadlets; catalog unit states;
container/external-container IDs and running names; image IDs/tags; networks,
volume creation identities and secret IDs. Fixed inspect fields bind the eight
required running containers to their unique Quadlet and actual image config:
woow-emqx, woow-emqx-entrance, hermes-postgresql, hermes-redis, hermes-agent,
omnigent-postgres, omnigent-server and omnigent-runner. Other catalog app states
must also stay equal. No app is stopped or started. All IDs remain strict: any
unrelated churn is retained in before/after receipts and fails the phase. No
post-update baseline reset is supported.

Archive inventory walks directories and records arbitrary regular sidecars by
metadata. It does not treat JSON sidecars as directories or read archive bodies.
Only hashes/metadata cross the protocol. Config/secret contents are never output.

The source baseline includes extra protected fields and has its own SHA. The
image controller still needs its separate fresh image inventory/approved SHA
before any LL init/build. The old image baseline pin is stale and cannot be used.

## Source transaction and recovery

1. Hold existing dev-d mutation mutex/global heavy slot; defer to EMQX priority.
   In device, acquire existing `jobs.lock` then `engine.lock`, nonblocking.
   Require zero queued/running job records and active job units. Require the
   existing schedule timer already masked and inactive; leave it that way.
2. Verify all live managed hashes against exact old source. Reject unsafe
   parents, symlinks, hardlinks, xattrs, unknown Python paths or unexpected new
   directories. Capture the **whole** prior library, including opaque files and
   caches, plus helper in root-private storage. Record SHA, mode, UID/GID and
   nanosecond mtime. Verify completed copies before any live source change.
3. Stage the full candidate privately. Check existing age, age-keygen, zstd,
   PyNaCl and cryptography availability with existing tools only. Import actual
   CLI/LiteLLM/PG adapter from the staged source using `-B -I`,
   `dont_write_bytecode` and a nonexistent private pycache prefix. This avoids
   both reading old caches and writing new caches. Verify tree equality afterward.
4. Journal each file's prior fingerprint/absence and exact desired fingerprint
   durably before publication/deletion. Write an inode-recorded private temporary
   on the destination filesystem, fsync, then `os.replace` the **file**, fsync
   destination directory. Publish Python, remove only trusted stale Python,
   publish VERSION and helper last. Keep the live merged directory inode.
   Source mtimes come from the frozen commit; usable stale bytecode collisions
   refuse before publication while retaining the original cache files.
5. Import actual installed modules with the same cache isolation; verify all 53
   hashes, full protected snapshot equality and resource floors. Keep `59a`
   installed and retain private prior copies/journal.

Every install failure/cancellation after a live intent attempts exact source
return under the same locks. Recovery validates **all** current library files,
opaque/cache bytes, directories, helper and private copies before any return
write. Only original fingerprints or exact journaled prospective fingerprints
are accepted. New files are removed only at their exact owned fingerprint;
deleted files are rebuilt from the verified prior copy. Original directory
mtimes are restored. Interrupted publication/return is recoverable from durable
intent; install is never replayed. Foreign edits stop recovery with copies kept.

A lost response can invoke the explicitly leased `source-recover` phase, with
a unique attempt output. That phase requires the protected baseline still
equal. Later helper jobs can legitimately change caches; exact recovery then
refuses those changes and retains all source copies. Recovery does not replay
old caches over later engine work or change app state to make a check pass.

No installer/deploy-src, package manager, daemon reload, UI deployment, catalog
edit, key initialization, app installation, DB connection or image operation is
part of this source phase. Existing DB/native proof is reused separately.

## Bounds and proposed commands

Separate source lease: `case=litellm-instance-source`, device `woowbk-dev-d`,
name above, method above, phases initially `source-snapshot`, then a reviewed
lease with `source-install` and `source-recover`. Time window at most45min;
admission keeps600s recovery reserve. Device timeout300s sends TERM, KILL after
45s; outer transport390s. Soft cancellation runs journal recovery; a hard kill
retains journal/copies for explicit recovery.

Admission requires host1200MiB available and device1900MiB headroom; **13GiB plus
512MiB** free on host checkout, appowner filesystem, actual engine staging/data,
and both live source parent filesystems. Per-tree maximum64MiB/4096 objects.
No engine/resource guard is lowered. Existing global maximum2 heavy jobs applies.

Local immutable-blob measurements: old50 managed files total2,740,420 bytes;
new53 total2,810,511 bytes; helper2,278 bytes in each; largest managed file
284,110 bytes. Encoded new request is3,753,952 bytes. These are source bytes,
with no image/archive space assumption. The whole prior library cap includes
opaque files/caches (64MiB). Staging adds2.7MiB. At most256 journaled temporaries
can remain, capped by the exact source manifests at72,732,160 bytes total;
publication refuses a further temporary before a live write. Journals/host
receipts each cap8MiB, including atomic replacement overhead. Allowing directory
and block rounding, this is below200MiB of device source-phase storage. The
512MiB budget retains margin and does not inherit the image phase's8GiB peak.
The reviewed image21GiB admission floor stays unchanged. No owned disposable
image/archive has been identified for cleanup in this source preparation.

After release and exact lease review, proposed read-only capture command:

```bash
env HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock HEAVY_WAIT=1800 \
  /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
  timeout --signal=TERM --kill-after=60 900 \
  python3 -B -I /tmp/parity-focus-litellm-instance-acceptance-20261127/tests/e2e/lab/focus_litellm_instance_acceptance_source.py \
  --execute --phase source-snapshot \
  --lease /tmp/parity-focus-20261127/lease-litellm-source-dev-d.json \
  --receipt /tmp/parity-focus-20261127/litellm-source-baseline-01.private.json \
  --output /tmp/parity-focus-20261127/litellm-source-baseline-01.json
```

After parent approves the source baseline SHA and install/recover phases, use
the same controller with `--phase source-install`, a NEW
`litellm-source-73cb85d09a42.private.json` receipt and
`litellm-source-install-01.json` output. Recovery uses that private install
receipt with `--phase source-recover` and NEW `litellm-source-recover-01.json`.
Public outputs contain phase/status and receipt hash; snapshot also exposes the
baseline hash. Fixed error class/errno/stage stay in the private receipts/journal.

## Targeted verification

The new source tests exercise real files/syscalls, killed child processes,
all53 actual frozen files/imports, exact whole return, cache and private-copy
foreign edits, helper metadata CAS, old-source mismatch, symlink/hardlink
refusal, lock order/busy-lock release, masked-schedule/running-app boundary,
probe failure automatic return, unrelated protected churn and arbitrary archive
sidecars. Existing DB proof and the19 reviewed image gates are unchanged.

Completed guarded evidence: source packet17/17 in
`/tmp/parity-focus-20261127/litellm-source-packet05.log`; final bounded delta3/3
(temporary cap, usable stale-cache refusal and full actual payload publication,
staged/live imports and exact return) in `litellm-source-bounds06.log`.
Both gates have zero failures/errors/skips/blocked/shim hits and no native access.
The new source test module now contains18 tests; the final delta gate is reported
separately from the earlier17-test packet rather than claiming a new full run.
