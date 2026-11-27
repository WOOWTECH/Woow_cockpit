# Opt-in retention after a pre-conversion refusal

CODE ONLY; no runtime or upload scheduled. A future fullshare lease must explicitly
set `retain_verified_ha_on_preconversion_refusal=true` and bind a NEW successful
retained-upload receipt SHA. The deleted fullshare02 HA supplies no current credit.

At the existing recovery cleanup boundary, retention requires all of:

- Independent baseline safe and nonempty exact `after:` comparisons passed.
- Already verified retained-upload ownership; run/state/receipt HA ID and receipt
  SHA binding agree, with no unfinished upload.
- No conversion or restore start request, converted ID or safety ID.
- Complete bounded native job store has0active jobs, freshly checked before and
  after the existing streaming HA verifier checks all bytes, inode and sidecar.
- Native root/regular/single-link/size/SHA/sidecar/stable-metadata verification and
  original absent-before/upload-ID provenance pass. No additional budget credit.

Persist fresh proof and retained ownership before cleanup. Suppress only this
HA deletion; restore its in-memory ownership even if other cleanup fails. All
ordinary owned backup/relay/temp-object cleanup and leak checks continue. Default
cleanup is preserved when opt-in is absent or conversion/restore was requested.
Unproven baseline, active jobs or changed/unowned bytes stop retention and cleanup.

One focused regression passes13scenarios: actual STOP remains refused, proven
owned retention, opt-out/conversion/restore paths, unsafe/inexact baseline,
active job before/after hashing, wrong SHA/inode/store/receipt binding. No25upload,
138product or neighbor tests repeated. Product remains frozen6daaa15c on d09;
53-file manifest remains b19d03e5a8cdaf850038fbba7f0bd9a061603a47808196582f713733d84231ae.

Retaining HA occupies4.47GB and gives no N8 disk-release checkpoint. Parent must
schedule combined peaks or separately authorize exact owned cleanup. E remains
held for a new lease behind LL/N8 work. S5, skipped fixtures and full acceptance
remain outstanding; original initial upload failure remains UNKNOWN.
