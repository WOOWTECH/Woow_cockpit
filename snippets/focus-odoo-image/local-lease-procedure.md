# OD-23 exact local dev-d lease procedure (supersedes ARM-first proposal)

Required product delta: `749974aa` (only pg16_bundle.py + its tests). Base feature commits00ac1dd8+86a53e75 are already integrated by coordinator. Layer verifier checks independently pinned config SHA, complete rootfs.diff_ids list/count/hex format, and SHA256 of EACH ordered uncompressed layer. Plain/gzip data is streamed in <=1MiB reads, expanded bytes capped at2GiB total, with cancellation/storage abort checks. Wrong layer bytes, absent/malformed/count/order/digest lists, gzip corruption and expansion limit stop. No artifact extraction or whole-image buffering.

Verification: final neighbor run304 tests/0fail/0error/3real-fixture skips/0blocked/0shim; subsequent verifier-only focused32/32 + new missing/order/digest/abort regressions3/3; isolated driver normalization4/4. No further broad rerun needed. Logs are /tmp/parity-focus-20261127/odoo-image-{final-neighbors,layer-binding,layer-regressions,proof-driver}.log.

## Exact source/trust resolution

Read-only dev-d nested appowner store contains Linux/amd64 image config ID:

`sha256:4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873`

Only tag: `docker.io/library/postgres:16.15-alpine3.24`. Actual saved Docker v2 manifest hashes to its observed RepoDigest `sha256:8d16e6f18cc33ffb153211c40b45056a3589d49c245530469843b368d6786069`. Independently fetched official immutable index `sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139` hashes correctly, selects amd64 platform manifest `sha256:ac838714b7d794185a866e5a6b479b954e7d8a070568aa0acac6fe07c3070bf5`, whose config descriptor is exactly4278 above. The raw index/amd64 manifest are retained here and rehashed offline by the driver. They came from registry-1.docker.io/v2/library/postgres/manifests/<digest> using existing read-only registry metadata helper; no image blob/pull was fetched. Source config JSON also rehashed to4278 inside its own nested owner store. Registry media type/compressed layer representation can differ; it is not a program difference and is not required to survive save/load. Coordinator explicitly approved resolving actual byte identity via the official config's ordered uncompressed diff_ids. Exported layer bytes remain pending until the lease proof; metadata alone is NOT an actual-artifact pass.

Read-only evidence: dev-d-inventory-20261127.json + dev-d-pinned-source-verification.json. dev_d_inventory.py reproduces source/config facts without changes. Latest observed host free26185064448bytes; reserve13958643712bytes. Live checks are repeated before mutation. Earlier ARM authentication blocker is irrelevant to this local path.

## Exact command AFTER coordinator dev-d lease (after EMQX)

```
/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
  python3 /tmp/parity-focus-odoo-image-20261127/snippets/focus-odoo-image/run_dev_d_proof.py \
  --proof-root /var/lib/woowbk-odoo-pg16-proof-20261127-od23
```

Reviewable code: run_dev_d_proof.py (local launcher) + dev_d_offline_proof.py (remote body). Neither has been run for mutation before lease. Outer labpodman isolation must equal `true none {}`. The launcher takes existing /tmp/woowbk-dev-d-mutation.lock nonblocking, respects the existing EMQX-priority waiter, and uses only ~/.woowbk-lab/bin/labpodman (explicit isolated OUTER store). Device-side OwnerRunner uses only dev-d's nested store; no host default-store Podman. Existing source image is only inspected/saved. No package/account/auth/service/global source deployment changes occur.

Root-protected proof root is a NEW `/var/lib/woowbk-odoo-pg16-proof-20261127-od23` inside dev-d. All code/export/release/installed generation files stay root-owned below root0755 parents on the actual backing volume. Only new `preparation-store` and `owner-store` leaves/subdirectories are chowned to existing appowner,0700. No /tmp tmpfs stage or trust-anchor bypass. Every disk check/watchdog uses THIS /var/lib filesystem, retaining13GiB at all times; conservative starting headroom4GiB is required (17GiB total), covering multiple archives + two disposable VFS stores. No reserve is lowered.

1. Rehash official index/platform manifest; assert platform/config matches expected4278; inspect the exact existing source image/ref fields. Save existing source tag with root-protected streamed stdout.
2. Produce a quarantined verification view by copying tar headers/payload chunks and changing ONLY the single approved source RepoTag/repositories tag in bounded JSON. Reject links/extensions/multiimages/unrelated tags; no extraction. Original config/layer bytes stay unchanged (focused tests compare them). Production validate_archive verifies canonical view against official4278 config SHA and EVERY ordered uncompressed layer diff_id, including abort/size constraints, BEFORE ANY load. This authenticates original exported config/layer bytes without requiring registry manifest encoding to survive export.
3. Load the verified original into NEW preparation-store as appowner; inspect exact ID, tag canonical `docker.io/library/postgres:16.15-alpine` ONLY there, remove the source alias ONLY there, assert exactly one canonical RepoTag, and let Podman export the actual canonical release archive. Original store is never retagged. The default release packager still rejects wrong/multiple RepoTags.
4. Run the actual release packager and install_bundle into `<proof-root>/install-root` (full default root trust chain), verifying all bytes again. These image files are external artifacts, never committed to Git.
5. In separate EMPTY owner-store, invoke real ha_odoo.pick_pg16 through production OwnerRunner with explicit new graphroot/runroot/tmpdir. It must load the trusted installed bundle exactly once, return4278, and make no pull. Run PostgreSQL16.15 `--pull=never --network=none --image-volume=ignore --read-only --memory=128m`. The VOLUME-ignore flag prevents unrequested anonymous volumes. Repeat selection and inspect config ID to prove local reuse with no second load.
6. Remove only the proof's uniquely named smoke container in its new store (intent exists before run); assert target containers/volumes empty; re-inspect source and compare all fixed fields exactly; record public result.json and remaining free bytes. No original volumes/images/baselines are deleted. Keep proof artifacts/new stores for coordinator review and ONLY lease-scoped cleanup afterward.

Expected public result: exact pinned config/arch/ref, official config+each ordered uncompressed layer verified, artifact size/SHA, trusted manifest SHA, preparation_loads1, bundle loads1, pulls0, PostgreSQL16.15, anonymous_volumes0, containers_remaining0, source fixed fields unchanged, free bytes >=13GiB. Actual result is pending; no all-service/commercial acceptance is implied.
## Corrective Docker-directory retry (r3)

r2 OCI export was also preserved: correct source ref annotation, but converted config7a50f22eb109878acd1ec8e00764853737d8903faf444b5d67d9d0fa36268831
differs from trusted4278. It correctly stopped before any load with fixed oci-config-ref-pin-mismatch.
No config substitution/semantic matching/pin relaxation. The next NEW root is `...-od23-r3`.

Use Docker directory transport to preserve original Docker config bytes without legacy archive links. Source export
data stays solely in the NEW preparation store's owned temporary leaf. The strict adapter refuses links/extra files,
verifies descriptor SHA/size, pinned4278, and every ordered diff_id while producing a separate root-protected archive.
No owner-writable archive is installed or loaded. Only then load the NEW preparation store; canonical-tag/export there
with Docker directory transport; actual packager input_format=docker-dir + install_bundle + owner-load/smoke/reuse.
Fresh17GiB/13GiB reserve/headroom/RAM/expiry/whole-case mutex rules remain identical. Failed roots are preserved.

## Previous OCI attempt (preserved, superseded)

First root `/var/lib/woowbk-odoo-pg16-proof-20261127-od23` is preserved. Its Docker export's pinned config SHA and
all11 ordered layer diff_ids passed read-only checks, but11 unused legacy symlink aliases correctly triggered the
fixed `source-archive-header-refused` / `unsafe-docker-member` rejection before any load. No original-store change.

Retry ONLY in NEW `/var/lib/woowbk-odoo-pg16-proof-20261127-od23-r2` using the existing70min lease and heavy/device
mutex. Launcher rechecks lease expiry, committed tracked code, original lease root/suffix, host RAM>=1200MiB,
device headroom>=512MiB, and both filesystems free>=17GiB. Retain13GiB throughout streaming phases.

The source is now exported as OCI. The strict regular-only OCI adapter copies authenticated config/layer blobs into
quarantine and runs production ordered-layer verification BEFORE ANY load. This link-free verified view loads into
the NEW preparation store, where canonical tagging/export alone occurs. Export canonical OCI there, then run the
real packager with `input_format='oci-archive'`, install_bundle, owner-load, offline smoke/reuse/cleanup checks.
The original Docker archive and failed quarantine remain untouched. New result filenames include the proof root
and use exclusive creation, preserving earlier attempts. No auth/host/network/pull/package/account changes.

## Runtime path correction (r4)

r3 verified exact config4278 and every ordered layer before load, then Podman rejected its long runtime path with
exact fixed error owner-runroot-too-long. New r4 uses an owner Python process anchored by its cwd to each exact NEW
store leaf; /proc/<owner-pid>/cwd/run and /tmp are short aliases to those SAME physical leased directories. No filesystem
symlink/new root/runtime outside the lease or auth route is created. Anchors use the existing OwnerRunner prefix and
remain live throughout the case; finally close their stdin and wait. No production path behavior changes.

After successful version/reuse/source-unchanged/empty-store checks, the driver removes only its2 exact new VFS store
leaves (checked owner0700/no nested mounts/symlink-safe rmtree), retaining release/staged archives and manifests.
All first/r2/r3 failed artifacts remain preserved. Reserve/headroom/expiry/wholecase mutex remain identical.

## Final runtime correction (r5; proc anchor superseded)

The rootless namespace transition could not use another process's /proc cwd. A bounded metadata probe PASSED with
`unshare --mount --propagation private`, binding the same leased root onto the existing empty /mnt solely in that
private mount namespace. New store run/tmp paths are short /mnt/<owned-leaf>/run and /tmp. XDG_RUNTIME_DIR also
points to that exact NEW owned run leaf, keeping the original store's rootless pause/mount namespace unchanged.
No new filesystem root, source runtime setting, network, authentication, or persistent device mount change. All data
physically stays under the reviewed /var/lib proof root; inode/device equality and same-filesystem reserve enforced.
The store's scoped system migrate stops its private pause process after empty container/volume checks, then exact
owned leaves are removed. New r5 root only; preserve original/r2/r3/r4 protected failed artifacts.
