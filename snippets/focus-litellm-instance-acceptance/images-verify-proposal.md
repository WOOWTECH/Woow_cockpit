# One read-only images-verify phase

CODE ONLY; requires a NEW exact lease. The parent ran images01 at218bfbc0:
builder/derivation passed, final application equality failed. Its specific
failing inventory was not saved; historical cause remains unproved. Preserve
images01 FAIL and all raw history. Diagnosis01 found recorded build-before,
build-after and current strict equality true, with no builder container left.
Diagnosis02 reproduced strict failure solely from an unselected auto-restarting
Headscale container. This phase has **no Headscale filter**.

Entrypoint: `tests/e2e/lab/focus_litellm_instance_acceptance_images_verify.py`.
The original dd2 image builder/controller, 218 source packet and product59
bytes are unchanged. No image build, baseline reset, removal, root file write,
app/service/PG operation or credential read exists in this phase.

## Exact proof and history

- Same case `woowbk_focus_litellm_a2c39e761b04`, host case receipt
  `/tmp/parity-focus-20261127/litellm-instance-a2c39e761b04.private.json`.
- Original canonical baseline remains
  `298e4a88feb3356979e4f5dab8a6155fa418e834ec44d887cf7cff79a7719c82`.
- Existing derived config must remain
  `af291cf14dba64dd3331179696d9bdfd70f5cacf0c92c53202d0998fe15ecaff`.
- Read the actual root-owned build journal: stored original before, build before,
  build after, terminal+ok+verified result, exact recipe SHA, iid and sole owned
  image. Unknown images refuse. Re-read its exact fingerprint after capture.
- Read all current image config identities, architecture/OS, labels, USER,
  declared volumes, full RootFS arrays and tags. Every original config must be
  identical. Derived tag/config/USER/case/base labels must match the journal and
  exact cached base RootFS prefix. Both recorded after and current inventories
  must contain only the one derived image/tag delta.
- Capture the current FULL inventory and installed53 source hashes. Save the
  complete actual proof plus prior case receipt in a NEW immutable private
  capture **before** the acceptance assertions. Compare strict `unchanged()`
  against the original before, including every container/external ID, running
  name, file, catalog, volume, network, secret, unit, timer and absent LL namespace.
  Compare actual installed source to frozen59 including helper and VERSION.
- PASS can CAS-update only the host case receipt's `images_ready` and append a
  distinct `images_verification` record referencing the immutable capture/current
  inventory hash. The old phase_succeeded=false and images01 public FAIL remain.
  FAIL preserves the capture and leaves readiness unchanged. No automatic retry.

## Bounds, lease, command

Metadata-only admission: host1200MiB available, device1900MiB headroom and
**13GiB+512MiB** free on host and actual appowner/data/staging filesystems.
Capture/output each cap8MiB. No image writes: the build's8GiB peak is not needed
for this read-only phase. **Full flow retains its21GiB admission floor.**
Global maximum2 heavy jobs, existing dev-d mutex and EMQX priority apply.
Device timeout180s, TERM then KILL after30s; transport240s; proposed outer300s.

Lease: `granted=true`, `case=litellm-instance-images-verify`, device `woowbk-dev-d`,
same name above, exact new full driver SHA from handoff, source
`59a1b0f95132ea51c899f590eea7e3b02c5dba43`, phases `["images-verify"]`,
method `stored-build-strict-current-no-writes-v1`, original baseline SHA and
derived config above, recipe SHA
`b15f9c4d19b95f51e85e8ec5b6ca1e52b63e064298b8bc3b0b9eb80c912a555a`,
timezone-aware expiry within45min and exact BOUNDS from the module. Bind
`capture_filename=litellm-instance-images-verify-01.capture.private.json` and
`output_filename=litellm-instance-images-verify-01.json`; existing paths refuse.

```bash
env HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock HEAVY_WAIT=1200 \
  /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
  timeout --signal=TERM --kill-after=45 300 \
  python3 -B -I /tmp/parity-focus-litellm-instance-acceptance-20261127/tests/e2e/lab/focus_litellm_instance_acceptance_images_verify.py \
  --execute --lease /tmp/parity-focus-20261127/lease-litellm-images-verify-dev-d.json \
  --receipt /tmp/parity-focus-20261127/litellm-instance-a2c39e761b04.private.json \
  --capture /tmp/parity-focus-20261127/litellm-instance-images-verify-01.capture.private.json \
  --output /tmp/parity-focus-20261127/litellm-instance-images-verify-01.json
```

Two targeted refusal tests cover unknown original diffs (including Headscale)
and unknown images/tags or wrong case labels despite a valid terminal build.
The19 original controller gates are reused, not rerun. This is an independent
verification of a retained image artifact, not a reclassification of images01.
