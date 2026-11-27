# Reference prep attempt1 — exact failure, cause and fix

Facts only; no private values. Attempt1 ran at 2026-11-27 13:32 (Asia/Taipei) on dev-c under a 25 minute lease,
driver `719ebd7ee0d3c5e9de1ce28c4b9588b22731143a`, source `d09f4fe8`. Exit 1 after 15.8 s.

## What happened (verified on the device, read-only)

- Resource floors, installed engine check and `reference-snapshot` passed; both planned aliases were found missing.
- `reference-bind` for `docker.io/n8nio/n8n:2.43.6`: the tag intent was journaled, the real `podman tag` ran, and the
  validation AFTER the tag refused with the fixed code `fixed-reference-cache-fields-changed`.
- Device state now: `docker.io/n8nio/n8n:2.43.6` exists (image exists exit 0); `docker.io/n8nio/runners:2.43.6` does not
  (exit 1). Journal root `/var/lib/woowtech-backup/focus-n8n-image-references/woowbk_focus_n8n_28a4a4b1cbcd` has
  `intents[n8n]={done:false}` and the failure record. No service, SQL, catalog, timer, backup or other image changed.
- My first reading of the failure (before the device was read) assumed no tag had been applied. That was wrong and was
  corrected by `podman image exists` and the retained private inspection rows.

## Cause

The retained raw `podman image inspect` rows (18 files: before, before-bind, after-bind for 6 configs) show that after the
tag ONLY three paths differ for the tagged config: `RepoTags` (0 to 1), `RepoDigests` (0 to 1, value
`docker.io/n8nio/n8n@<Digest>`) and `NamesHistory` (null to one name). `Digest` and every other field are identical, and the
other five configs are byte-identical. `RepoDigests` is derived from names, but the validator kept it inside the strict
`stable_fields_sha256`, so a correct tag looked like a field change. The offline tests did not catch it because their fake
`podman tag` only changed tags and history.

## Fix (this commit)

- `cache()` leaves `RepoDigests` out of the stable hash and returns `digests` and `digest`.
- `validate()` keeps `Digest` strict and allows `RepoDigests` to change ONLY by exactly `repo@Digest` for an alias added by
  an applied intent; any other entry still refuses (`fixed-reference-unapproved-digest-delta`).
- Journal root for the next attempt is `.../focus-n8n-image-references-2`; the attempt1 root stays untouched.
- Tests: RED against the old validator (the real `cache()` test fails with the same `fixed-reference-cache-fields-changed`),
  GREEN on the fix: 11 of 11 (8 earlier + 3 new), 0 blocked, 0 shim, native denied. Logs: n8n-ref-red-01.log and
  n8n-ref-green-01.log in the Claude takeover scratchpad.

## Next

Attempt2 runs `image-references` again with a new lease, a new journal root and a new host receipt (the attempt1 receipt is
renamed aside, not deleted). Its snapshot sees the n8n alias as already correct and plans only `runners:2.43.6`. The n8n alias
therefore belongs to attempt1 and the runners alias to attempt2; both stay retained for the case.
