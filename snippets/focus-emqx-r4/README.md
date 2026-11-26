# EMQX R4: plain delta proven; remaining cases/package pending

Base: `a154751429ab5cfeb1dad75860b11946b2eaef01`. Assigned new files only. One plain generated delta ran23/23PASS from frozen27cb52c4 (coordinator-promoted `tests/backup/evidence/focus-emqx-r4-20261127/`); no installer, upgrader or new package smoke ran. No product/package/shared registry file was changed. E44's branch remains clean. The package draft remains local and unpushed.

## Evidence already complete and preserved

- `tests/backup/evidence/parity-emqx-r4-d0-20261126/README.md`: real HA D0 check ARM+x8631/31, x86 import56/56, rollback/E9076/76, cleanup11/11. Do not repeat this as an R4 matrix baseline.
- `tests/backup/evidence/parity-emqx-a-20261125/H2-lab-proof.md`: real HA import followed by unchanged package smoke14pass/2fail(A4,A10); quick9pass/1fail(A4). The local marker-aware draft passed in that historical fixture. The upgrader itself was **not** executed; rollback was inferred from its decision branch.
- E44 native33/33 is separate evidence under `tests/backup/evidence/parity-emqx-plugins-focus-20261127/`.

## Exact remaining matrix

Plain is **23/23PASS generated delta**; the other ten rows remain **prepared / native pending**. Every positive broker case uses a real vendor-generated export, product `candidate_from_target`, actual target snapshot and vendor import, row-count check, named issue boundary, exact acknowledgement/no-ack refusal when required, restart and full configuration/admin receipts, unmocked postcheck plus negative admin-receipt refusal. Its target is generated, not an installed app. This is the internal conversion delta; public helper/package/install/safety-rollback acceptance remains the preserved real D0 evidence plus the separately pending package phase.

| Case ID | Decision | Generated input and required distinct result | New package smoke |
|---|---|---|---|
| `plain` | D1 | Normal plain bootstrap with actual synthetic account; notices `plain-passwords` and `clear-rows`; account works after import/restart | Pending exact unchanged script |
| `dead_row` | D1 | Same real plain account, then ordinary vendor config change to sha256 without resetting password; clear-row notice; row preserved and remains unable to log in | Pending |
| `noauth` | D5/S2 | Explicit authentication=[]; exact no-auth confirmation; no-ack refuses; anonymous CONNECT works after restart | Pending; record A5 failure rather than waiver |
| `http_dummy` | D4/S1 | Enabled HTTP authn/authz only at broker loopback18091; fixed responder discards requests, returns fixture allow; exact HTTP confirmation names; synthetic CONNECT works | Pending; callback must be restarted in fresh fixture broker |
| `file_dummy` | D4/S1 | Enabled MQTT connector to its own loopback1883, password `file:///fixture/file-dummy.txt`; only owned mount is readable; exact connector name confirmed and retained | Pending |
| `jq_constant` | D4/S1 | Enabled rule, pure `.fixture` jq filter, no actions or external sink; named confirmation, filter result and rule/config persist | Pending |
| `env_dummy` | D4/S1 | Same benign rule, only `env.WOOW_R4_DUMMY`; fixed synthetic value provided by driver to both brokers; no whole-env access/capture | Pending; **not proof of HA addon env_vars** |
| `admin_public` | D2/H3 | Real generated admin/public; local notice and synthetic exposure-metadata confirmation branch; actual outer/broker ports stay closed | Pending A4 result; physical network exposure is not tested |
| `changed_acl` | D3 | Different generated ACL files in source/target; a real ordinary vendor management ACL row is retained while target's built-in source is disabled/removed; exact source file bytes, allowed/denied subscriptions survive | Pending A6/A10 results |
| `psk` | E-43 | Different generated PSKs for same owned identity; named device-PSK confirmation; vendor lookup returns source value after import/restart; full receipts remain mandatory | Pending; this is PSK data/lookup proof, not TLS interoperability |
| `lost_auth_setting` | E-67/D0 | Ordinary generated HTTP source, vendor export deliberately omits authentication root; real product import must refuse missing HA setting before packaging, target unchanged | No smoke: there must be no successful conversion |

### Acceptance gaps and intentional policy

1. **Environment policy:** H1 says this device's environment wins. Current `ha_emqx.OPTIONS_NOT_MOVED` explicitly says addon options/env_vars are not moved; this is intentional current policy, not an automatically authorized missing feature. `addon_options()` records a synthetic policy example only. G4's older source-addon-env wording must be reconciled with that policy. The remaining acceptance check is native device-environment precedence and its notice/restart behavior, not adding source option import. The current `env_dummy` case proves only the named synthetic jq variable; it does not establish that separate H1 check. No side-channel source env-file injection or product change is made here.
2. **Package upgrade:** H2's failure is already real evidence; the local fix is `Woow_podman_emqx fix/smoke-after-ha-import-20261125@5c748a6617cbb4847e8b4eca1e4b1f8841f4b864`. This worker neither applies that fix nor turns smoke failures into warnings. Installer/upgrader side effects are reviewed in `package-review.md`; neither command is in an executable path of these drivers.

## Reviewable drivers

- `tests/e2e/lab/focus_emqx_r4.py`: plan by default; one exact case per fresh coordinator lease. Sends only committed ordinary Python source + immutable fixture module to a private HOME payload. Holds the existing dev-d mutex throughout. No real HA backup/credential readers.
- `focus_emqx_r4_runtime.py`: owned TempObjects, no network/ports, image-volume ignore and rm --volumes, exact-image pin, resource floors, mutation target validation, private bounded diagnostics and fixed JSON checks. Source is removed before target+candidate start, so at most2 brokers run. Successful payloads are deleted; failed payloads remain explicitly named for scoped diagnosis/cleanup.
- `focus_emqx_r4_package.py`: default plan only; exact unchanged smoke executor for a **separately provisioned owned synthetic device**. Requires its own lease, device label/mounts/UID1031/fixture marker, package hashes and already cached pinned client. It does not provision that device, copy candidate data or promote a candidate into package Quadlets. The new provisioning transaction is described below; a matching package-profile artifact and verified OCI inputs remain prerequisites.
- `focus_emqx_r4_tests.py`: targeted offline input/lease/resource/mutation-target checks, never a native runtime.

See `lease-plan.md` for the next bounded case and cleanup, `package-source.json` for exact reviewed package hashes, and `matrix.json` for machine-readable scope/status. No R4 closure or ten-service completion is claimed.

## Package provisioning source ready for review

The new `_provision.py` transaction, `_artifact.py` verifier/export hook, `_inner.py` real fixture setup/postcheck/smoke, `_client_guard.py` resource wrapper and `_provision_tests.py` now implement the separate provisioning/cleanup driver. Initial offline11/11PASS; final12-case gate pending an available heavy slot; no fresh device or package command executed. See `package-provision.md` for exact image IDs, command, new lease schema, resource bounds and recovery. A matching package-profile candidate producer/artifact and verified OCI archives are prerequisites still pending; queued27cb broker-only runs are not promoted. The earlier standalone `_package.py` executor is not the provisioning entrypoint. Plain lease released, owned resources/payloads0; dead_row/noauth await R8 retry release.
