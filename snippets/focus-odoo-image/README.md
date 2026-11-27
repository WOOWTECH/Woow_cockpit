# OD-23: retained offline PG16 release proof

## Deliverable

Host release directory (outside Git): `/tmp/parity-focus-20261127/odoo-pg16-release-amd64`.
Device copy: `/var/lib/woowbk-odoo-pg16-proof-20261127-od23-r5/release` on isolated dev-d.
Both contain `manifest.json` and `postgres16.docker.tar`; host also contains `manifest.sha256`.

| Field | Value |
|---|---|
| Trusted manifest SHA256 | `f563a9bf4123af20f65247ab752169e4664c7e0d179806711c7957d70687f9aa` |
| Archive SHA256 | `e2f6b112b442a4862cf472b5c9dd59de17db489dd5ba608001c9b1bbe700eeb2` |
| Archive bytes | `297140736` (283.4 MiB; exact observed size replaces the planning estimate) |
| Platform | Linux/amd64 |
| Config ID | `sha256:4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873` |
| Release ref | `docker.io/library/postgres:16.15-alpine@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139` |
| Official amd64 manifest | `sha256:ac838714b7d794185a866e5a6b479b954e7d8a070568aa0acac6fe07c3070bf5` |
| Runtime proof source | `516e02a2808e8fe709d91dda976fac42990ec6c7` |

Public index/platform descriptor bytes are retained in `upstream-pg16-*.json`. Their SHA256 chain independently
binds the official pinned ref to config4278. Every ordered exported uncompressed layer was hashed against that
config's `rootfs.diff_ids` before any load. Registry manifest/compression encoding need not survive an export.
No source-store retag, substitute image, pull, package install, network change or host/default-store image operation.

## Actual result and cleanup

`woowbk-odoo-pg16-proof-20261127-od23-r5-result.json`: actual release packager with Docker directory transport,
root-trusted installation, production Odoo selection and real OwnerRunner load into an empty owned store. Target
load1, preparation load1, repeat selection reuses image, pulls0. Real `postgres --version` reports PostgreSQL16.15
with networknone/pullnever/image-volumeignore/readonly; anonymous volumes0 and remaining containers0. Original
config/architecture/OS/RepoTags/RepoDigests unchanged. The two r5 VFS stores were scoped-migrated and removed.

`retained-release.json`: device bundle fully reverified, streamed outside Git with1MiB reads, independently rehashed
on the host. Host free33937575936bytes after retention. No image binary is committed or buffered whole.

`failed-owned-store-cleanup.json`: exact r3/r4 preparation leaves also checked empty (images/containers/volumes0),
scoped-migrated and removed. Protected failed quarantines remain; original/r2 exports untouched. Original source
rechecked unchanged, pulls0. Final observed device free34531409920bytes. All operations used existing heavy/device
mutex. Each case required17GiB initially and retained the unchanged13GiB reserve on the same backing filesystem.
No worker mutex or active OD device job remains; R8 may proceed.

## Preserved failed history

| Attempt | Exact fixed reason | Finding / correction |
|---|---|---|
| Original, source4176d841 | `source-archive-header-refused` / `unsafe-docker-member` | Docker-save added11 redundant symlink aliases. Config4278 and all11 ordered layers passed independent read-only hashing. Every archive link stays forbidden. |
| r2, source360829c7 | `oci-config-ref-pin-mismatch` | OCI exporter rewrote config to7a50… despite correct source ref. Exact config pin stayed enforced; no config substitution. |
| r3, source0123142e | `owner-runroot-too-long` | Docker directory export preserved exact config/layers; Podman refused long runtime path before storage initialization. |
| r4, sourcec036ef02 | `rootless-proc-cwd-runtime-unusable` | Rootless namespace could not use the owner process proc cwd anchor. No image load/storage initialization. |
| r5, source516e02a2 | PASS | Private mount view aliases the SAME leased root at existing empty/mnt; private runtime stays within each owned store. Normal device/source mount and runtime views unchanged. |

Each failed result and bounded fixed diagnosis is retained separately. No raw artifact contents or private error logs
are included in public evidence. Short private-runtime metadata probe passed before the final retry.

## Integration and test scope

Production correction: `360829c7` then **`0123142e`**. Proof-only runtime fixes: `c036ef02`, `516e02a2`.
Actual proof/retention: `6a27230b`, `5e834331`; final evidence/registry snippet follows this README.
Parent independently rehashed the retained host manifest/archive, matching size and both SHA256 values; OD-23
closed in integrated main `3e3e9315` (470done/2part). The final failed-store cleanup receipt confirms all four new
owned stores are gone; no OD mutex remains held.
`ha_parity_rows.json` proposes OD-23 done with exact existing test refs; coordinator owns the shared registry/docs.
`contract.md` records schema, installer flags, Docker directory input and unchanged offline-update contract.

Verification: prior affected neighbor run304 tests/0fail/0error/3real-fixture skips; corrective focused42/42;
reserve/cancellation8/8; Docker-directory focused neighbor7/7; fixed runtime reason1/1. All guarded runs0blocked/
0shim. Parent reports integrated source check51pass. No repeated broad run after the actual proof.

Scope remains opt-in packaging. Ordinary installs/offline Cockpit updates, local-first selection and pinned online
retry remain supported. ARM64 has synthetic archive coverage; this retained real artifact is amd64. No automatic
app installation/version change/wave2, native ARM real proof, published release distribution or all-service/commercial
acceptance is claimed.
