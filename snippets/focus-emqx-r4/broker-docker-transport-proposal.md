# One-broker transport proof — source/research proposal only

No D calls, save/export/load/build/tag/delete, new containers, cleanup or package execution occurred for this proposal. LL owns D until its terminal release. Future diagnostic code remains commit230ad6b4; retained failed17e payload/archive and original failure history remain intact. The host has no broker OCI copy; this research uses the already captured fixed metadata and immutable local source, not a new device read.

## Primary-source and existing native findings

Podman documents Docker archive, OCI archive and Docker directory outputs; Docker directory uses Docker schema2. In the v6.1.1 save implementation, both Docker outputs request that manifest type. This supports investigating preservation of the original Docker config; it does not prove the EMQX export or destination digest lookup. [Versioned save documentation](https://raw.githubusercontent.com/containers/podman/v6.1.1/docs/source/markdown/podman-save.1.md.in), [versioned save implementation](https://raw.githubusercontent.com/containers/podman/v6.1.1/vendor/go.podman.io/common/libimage/save.go).

The matching vendored containers-image Docker tar writer explicitly emits legacy layer symlinks. Direct Docker archive is therefore a concrete link-refusal risk, not a presumed passing alternative. [Versioned archive writer](https://raw.githubusercontent.com/containers/podman/v6.1.1/vendor/go.podman.io/image/v5/docker/internal/tarfile/writer.go).

OD already observed both issues on this device: its first Docker archive had11 forbidden unused legacy aliases; its OCI retry had a changed config digest. Successful native source516e02a2808e8fe709d91dda976fac42990ec6c7 used `docker-dir` and the existing strict adapter, then verified the exact4278 config and all11 ordered diff IDs. Its retained manifest is f563a9bf4123af20f65247ab752169e4664c7e0d179806711c7957d70687f9aa. These are OD evidence, not new EMQX transport proof. Read immutable main@b8a8e21d paths `snippets/focus-odoo-image/{contract.md,dev-d-first-export-diagnosis.json,retained-release.json}` and `tests/backup/evidence/parity-odoo-pg16-offline-20261127/`.

For EMQX, only the retained-artifact reproduction is established: OCI config1b8bcb21 differs from required3f60addf and the unchanged validator refuses. The original inner message/stage was lost. No historical conversion cause is inferred from source documentation.

No new host/device `podman --help` was invoked. The versioned command documentation was read instead; the exact locally compiled library revision is not independently attested by this research.

## Two exact prepared choices; choose one future case

| Choice | One future save, after fresh source-ID/ref verification | Acceptance consequence |
|---|---|---|
| Recommended: Docker directory -> regular-only Docker archive | `podman image save --format docker-dir --output /home/appowner/woowbk-r4-broker-transport-c9e32a7f6410/broker.dir docker.io/emqx/emqx:5.8.9` | Reuse strict OD directory/descriptor/config/layer validation and archive construction. Native EMQX config preservation remains unproven. |
| Direct Docker archive, if selected as a diagnostic | `podman image save --format docker-archive --output /home/appowner/woowbk-r4-broker-transport-c9e32a7f6410/broker.docker.tar docker.io/emqx/emqx:5.8.9` | Refuse every link/PAX/device/duplicate/unsafe/extra/multiimage member. Stop on legacy aliases; do not strip them or automatically save again in another format. |

The literal broker tag above is the sole name attached to3f60 in the existing read-only catalog capture. Fresh inspection must bind it to config `sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b` and cached manifest `sha256:d4ec63c4065c745507e7652d9c0213134697dc1317d8a431b167ae7651c4e937` before the one save. No source tag creation or alias is involved. A mismatch stops before save. Only the broker is in this case; entrance/client are excluded from its lease.

### Validation reuse boundary and concrete unapplied patch

Use main@b8a8e21d's existing `pg16_docker_dir.convert_directory`, `pg16_bundle.validate_archive` and their secure-file, raw-header, streaming descriptor/config and ordered-layer checks. The current EMQX branch predates the integrated Docker-directory module; the future caller must be based on the reviewed main modules, not silently import a different local copy.

`validate_archive` currently requires `RepoTags=[pg16_bundle.TAG]`, and the directory converter emits that same PostgreSQL tag. Calling the PG16 packager unchanged would mislabel EMQX. [od-validator-expected-tag-PROPOSAL.patch](od-validator-expected-tag-PROPOSAL.patch) proposes only an explicit trusted `expected_tag` keyword for those two functions. Defaults retain the existing PG16 tag; the EMQX caller supplies the fixed broker tag above. The PG16 bundle schema/ref/install/load paths stay PG16-only and are not used to package EMQX. No globals are monkeypatched, no fake PostgreSQL metadata is supplied, and config/layer/link protections are unchanged.

The patch is **unapplied**: own writes are new lab/snippet files, so product API changes are prepared for coordinator review. `git apply --check` passes against the integrated main files. No behavior test or native success is inferred. After source review, the bounded offline gate must cover default PG16 behavior, explicit EMQX tag/config, wrong tag/config, ordered-layer mismatch, and retained link refusal using the actual shared functions. No broad suite is proposed.

## Exact broker artifact proof required

1. Persist an immutable private source/cached-catalog snapshot **before** save, with exact owner/rootless store, broker tag/config/manifest/platform and ordered source RootFS layer IDs. Hash it; retain it even on failure. Capture the same fields/catalog afterward. This repairs the original exporter's missing historical-baseline evidence in the future case only.
2. Require the raw artifact config SHA256 to equal exact3f60. That pins every config byte/field, including execution configuration, history and RootFS; matching selected fields or accepting1b8 as equivalent is insufficient. Expected3f60 comes from the reviewed source facts, never from the new archive. Record whole-config SHA and field-name/section hashes without printing raw values.
3. Check Linux/amd64, rootfs.type=layers, full ordered diff-ID list/count and every actual exported layer's uncompressed SHA256 using the shared streaming verifier. Compare the source RootFS receipt. Do not extract layers. Keep strict descriptor SHA/size checks for directory input and the unchanged regular-only archive member rules. Compression changes are allowed only where the existing verifier proves the same pinned uncompressed layer bytes; config bytes cannot change.
4. Require exactly one image and the fixed verified broker tag. Record measured raw-input and normalized-archive SHA256/size, raw config identity, all layer digests/diff IDs, source before/after snapshot hashes, validators' immutable source hashes and any fixed failure phase. Transfer and reverify the accepted archive before any separately leased consumer receives it.
5. No load is part of this proof. A passing broker artifact alone does not establish a usable new package device. The unchanged MQTT client full pinned reference remains a separate **destination** gate. Neither Docker format nor OD's config-ID load success proves that EMQX client's RepoDigest lookup will survive; no alias, operand substitution or pin waiver follows.

## Proposed next lease boundary; not a runnable lease yet

- Case `EMQX-R4-broker-transport:docker-dir` (recommended) **or** `EMQX-R4-broker-transport:docker-archive`; one format and one save only, no automatic fallback. Fixed token `c9e32a7f6410`; device root shown above; host output `/tmp/parity-focus-20261127/emqx-r4-broker-transport-c9e32a7f6410`. No such root/output was created here.
- A small caller using the reviewed shared API is still required before an exact clean-SHA lease can be issued. The existing three-image `focus_emqx_r4_prepare.py` images phase does not implement this one-broker case and must not be invoked under the old lease.
- After LL terminal release only: globalheavy max2 with `HEAVY_WAIT=0`, existing D mutex acquisition<=15sec, new lease>=20min remaining. Work<=900sec including transfer, one save<=240sec, cleanup allowance<=300sec. No container/network/volume/port creation, pull/load/tag/build, app/service/source/secret operations or package scripts.
- Combined source/directory/archive/staging<=512MiB, measured continuously and during copies; refuse before save if the reviewed source size and worst permitted staging cannot fit. Preserve>=13GiB own reserve and the coordinator's active21GiB DATA floor where applicable; start floors must include the512MiB staging allowance. Host memory>=1200MiB/device headroom>=1900MiB. Shared OD expanded-layer verification remains bounded to2GiB with1MiB reads and abort callbacks; no whole-layer buffering.
- Failure retains fixed result, private phase/error, source snapshot and owned bytes; D/heavy release promptly. No cleanup of the prior b6f payload or this new failed root without its matching cleanup lease. Success cleanup removes only the new context-marked payload after verified host retention; never prune or touch cached images/apps/catalogs.

This single transport proof advances the artifact prerequisite for original-package H2. Matching package-profile producer, fresh owned service fixture, full unchanged smoke/actual service evidence and remaining R4 cases still need their own review/proof. The three generated deltas and preserved D0 remain separately scoped.
