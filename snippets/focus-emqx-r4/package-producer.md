# Package-profile producer and cached archives — code prepared, no execution

New code: `focus_emqx_r4_profile.py`, `_producer_runtime.py`, `_cached_images.py`, `_prepare.py`, `_prepare_tests.py`. The default controller prints a plan. No producer, image archive export, transfer, new device, installer, upgrader or package smoke ran during this preparation. The separately leased dead-row23/23 result used only frozen27cb52c4.

## Shared exact profile

`package-profile.json` records the definition hash, all eleven public package source hashes and every fixed synthetic mount hash. Producer and receiver import the same profile factory. The artifact manifest now requires that exact profile hash and a complete original target record as well as the complete converted record. Before resource creation, a receiver rejects artifacts missing those fields; none of the earlier broker-only runs emitted compatible artifacts.

Producer starts a new source, creates a genuine vendor export, then stops/removes that source before starting a fresh package target and candidate. At most two brokers run. The target begins with **empty cluster.hocon**, reviewed package base/ACL files, the exact package bootstrap path/bytes, UID/GID1000/mode0400, package operational environment, node and scheduler1:1. It does not start from the existing broker-only target config or accept a caller-supplied volume/candidate/HA backup.

Producer boundary: package effective settings/files are reproduced under job-owned names using a private profile volume, read-only file binds and known synthetic env values. It does not use fixed package service/container/secret names on dev-d. It is not proof of installer or installed Quadlet/secret-object behavior. The separately owned receiver still uses real fixed package Quadlets, actual Podman secrets, strict complete configuration/table comparison, actual product postcheck and unchanged full smoke. Existing real D0 remains the fullflow evidence.

## Actual candidate and artifact gates

1. Fresh ordinary plain/dead-row/noauth source, actual account behavior and nonempty admin receipts. Dead-row uses only a normal vendor algorithm change. No supplied database payload, host credential or existing app/source/catalog read.
2. Real vendor export of data roots/table sets; actual `candidate_from_target` captures the new package target, clones it, imports the vendor data, restores all operational settings and applies HA access roots using unchanged product protections.
3. Real row counts, exact required notice/confirmation IDs, no-ack refusal and exact-ack acceptance when a confirmation exists. This occurs in temporary synthetic brokers; no customer enabled service is changed. The final artifact is not exported before that boundary passes.
4. All config roots and all seven table receipts must exist, including nonempty admin. Restart candidate, compare every root and receipt, probe the expected source/noauth/dead behavior, run actual `verify_restored`, and require negative wrong-admin refusal. Recheck original package target config/tables unchanged.
5. Recheck actual candidate file SHA256s for package base, ACL, bootstrap and all fixed `/fixture` inputs. Verify actual bootstrap0400/UID1000/GID1000. Require actual package Dashboard18093 and WS entrance8093. Thus setting only a profile name on a broker-only artifact is insufficient.
6. Stop the actual candidate and export only its owned data volume. Strict data tar validation and profile/target/converted receipts precede transfer. Host rehashes/revalidates both files, then removes only this invocation's private payload after proving its job containers/volumes/networks absent. Product TempObjects cleans all temporary resources, including the additional owned profile volume. No arbitrary backup plugin code is restored.

All vendor/profile behavior above is **prepared, not native-proven**. A failure stops the case, preserves fixed result/private payload, and needs diagnosis before retry. No postcheck, E90/config comparison, HA-admin receipt or archive protection is waived.

## Separate future lease and commands

The old generated-case and package-device leases do not authorize these phases. `validate_lease` requires exact clean source SHA, exact profile SHA from `package-profile.json`, all three immutable configs, exact phase/case, controlled inputs, `artifact_export=true`, `package_commands=false`, exact fresh12hex token/output path and >=20min remaining. Cleanup gets a separate `cleanup_only=true` lease binding the original result SHA. A new phase is not allowed while R8 owns D.

Concrete producer proposal: noauth, token `0ab7c8d9e641`, output `/tmp/parity-focus-20261127/emqx-r4-prepared-producer-noauth-0ab7c8d9e641`, device payload `/home/appowner/woowbk-r4-prepare-0ab7c8d9e641`. No such payload/output was created. Lease fields:

```json
{
  "case":"EMQX-R4-package-producer:noauth",
  "phase":"producer",
  "generated_case":"noauth",
  "device":"woowbk-dev-d",
  "source_commit":"<reviewed clean commit>",
  "profile_sha256":"<package-profile.json profile_sha256>",
  "image_configs":{"broker":"<exact3f60>","entrance":"<exact47ce>","client":"<exact93a0>"},
  "inputs":"controlled-generated-only",
  "artifact_export":true,
  "package_commands":false,
  "payload_token":"0ab7c8d9e641",
  "output_dir":"/tmp/parity-focus-20261127/emqx-r4-prepared-producer-noauth-0ab7c8d9e641",
  "expires":"<timezone-aware; >=20min remain>"
}
```

Future reviewed invocation only:

```sh
HEAVY_WAIT=45 HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
  python3 -B -I tests/e2e/lab/focus_emqx_r4_prepare.py --run \
  --lease /tmp/parity-focus-20261127/lease-emqx-r4-package-producer-noauth.json \
  > /tmp/parity-focus-20261127/emqx-r4-package-producer-noauth-native01.json
```

No such lease exists from this preparation. Expected duration unmeasured; bounded work15min including transfer, plus5min cleanup; remaining wall time bounds each owner command. Cleanup-only execution gets its own5min ceiling. Two brokers max768MiB=swap/.5CPU/256pids, readonly roots/capdrop/no-newprivs, no network/ports/pulls, image VOLUMEs ignored. Fresh host>=1200MiB, device headroom>=1900MiB, disk13GiB+512MiB; combined own source/staging/artifact files<=512MiB. Cleanup remains permitted below floors. Mutex acquire15sec and globalheavy wait45sec; no multi-case retry/wait loop inside a slot.

Successful outputs are `candidate.tar`, `candidate.json`, `result.json`; result binds data/manifest SHA256 and checks. A subsequent provisioning lease must bind those measured hashes and the actual producer commit. H1 device-env-wins policy is unchanged; no source-addon env import feature or new H2 package fix.

## Exact cached-image archive/hash proposal

`cached-image-archives.json` gives exact IDs, source references and argv. Source cache is dev-d UID1019; all three configs were already read-only identified. Broker cached manifest is separately pinned to `d4ec63c4...`; entrance/client actual cached manifest metadata remains to be captured. No archive exists, so archive SHA256/layer metadata is explicitly null, not guessed from an image ID.

The separate images lease uses case `EMQX-R4-cached-image-export`, phase `images`, `generated_case=null`, token `b6f4e120d93a`, output `/tmp/parity-focus-20261127/emqx-r4-prepared-images-b6f4e120d93a`; other exact lease fields match the producer proposal. Same controller/locks/floors, no brokers. Only private regular OCI/provenance files are written. No pull/load/tag, app inspect, container/service/secret operation or cache deletion.

Exact sequence per role:

- Inspect only Id/Digest/OS/architecture/size/RepoDigests for the fixed cached reference; require known config and linux/amd64. Client is inspected and saved by the **full unchanged pinned client reference**. RepoDigests may omit the tag; only its metadata comparison accepts the canonical repository@digest form. This never substitutes the client run/save operand.
- Cache inspection uses Podman's Go field `{{json .ID}}`; JSON's `Id` key spelling is not used as a Go field. The dedicated offline cache gate exercises the real inspect function and checks its exact argv/template for all three approved references, plus unknown-role refusal before any command. This corrects the reported Podman6.1.1 failure before export; no native cache-export proof is inferred.
- `podman image save --format oci-archive --output <owned-artifact>/<role>.oci.tar <fixed-reference>`. Validate archive members, every blob descriptor SHA/size, exact config SHA, ordered compressed layer digests and uncompressed diffIDs. Bound all private source+archive bytes to512MiB and preserve13GiB disk.
- Record whole archive SHA256, actual archive manifest digest, layer digests/diffIDs, exact cached metadata, source commit and byte counts in `images.json`; verify cached metadata and complete image catalog unchanged. Host hashes/verifies all copied bytes again before private-payload cleanup.
- Original cached manifest and OCI archive manifest are recorded as separate identities; transport conversion may produce a different manifest representation. Exact config+ordered rootfs hashes remain mandatory. No claimed whole-archive hash exists until this execution occurs.

**Hard client gate:** fresh fixture load must resolve the full unchanged `eclipse-mosquitto:2.0.22@sha256:212f89...` to config93a0. Source cache provenance or a matching config alone does not prove that destination reference. If OCI transport loses it, stop before package smoke and retain the receipts. No tag/digest alias, pull, changed smoke, or wrapper image-operand substitution is automatic. Any alternate digest-preserving transport or explicit config-binding choice needs separate coordinator source review and a new lease; this code does not claim that unresolved transport behavior already passes.

## Recovery and offline evidence

Private payload root has an exact context marker and producer job marker before resource creation. Cleanup validates both, refuses if any exact job-prefixed container/volume/network remains, then removes only that marked private directory. It never sweeps/prunes the broker store. Crash recovery command uses `--run --cleanup --lease <new cleanup lease>`; it preserves the original result and never restarts the producer. Failure results and host artifacts remain at the owned output directory for review.

Guarded gates:23/23 initial profile+dependent provisioning;3/3 cached RepoDigest normalization;7/7 transport/lease/recovery/deadline;6/6 actual material and exact destination-client binding. Counts overlap; details and log hashes in `package-profile-offline.json`. All0fail/error/skip/blocked/shim,run_native absent. No new device, producer, archive export, package smoke or vendor-schema runtime proof is inferred from these checks.

The subsequent focused cache-template gate is4/4PASS,0fail/error/skip/blocked/shim,run_native absent. It covers the actual `json .ID` inspect argv, approved cached metadata/save boundaries and source parsing; source/log hashes are recorded in `package-profile-offline.json`. No broad suite or device operation ran for this correction.
