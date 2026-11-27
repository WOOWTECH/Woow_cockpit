# Native ARM / cross-physical probe — 2026-11-22

Dedicated branch `test/arm54-isolated-20261122`, base `5c99b00`, worktree
`/tmp/ha-arm54-isolated-20261122`. The user exclusively authorized this worker
for `.54` test mutations. No applicable AGENTS.md was found in the source repo
or its ancestor directories. Existing lab harnesses were read first; the
Headscale harness assumes dev-d uid 1019, its installed image and shared storage,
so it was not run against this target.

## Achieved, with exact scope

On the source x86_64 host the unmodified backup engine wrote a native format-2
plain/gzip archive: 8,407,040 bytes containing two entries (8,396,860 payload
bytes). A nested volume contains an 8 MiB deterministic, non-secret binary;
the other entry is synthetic JSON. Nothing came from any real application.

The exact source archive was SHA256-checked on a second physical machine,
192.168.2.54, and then verified and extracted by the same engine on native
Linux aarch64. All entry hashes and the nested binary hash matched. ARM then
wrote a second native archive; that archive was transferred back to x86,
SHA256-checked, verified, extracted and compared again. This is archive-level
cross-physical evidence, not HA conversion or service restore acceptance.

| Object | SHA256 |
|---|---|
| Source archive / ARM received bytes | `0f1aa87f29c8e26c64306799d2362de833436957941d9a846dd127a9fcf22012` |
| ARM-written archive / x86 received bytes | `972a546b22ac07306cfd49bea47c0956138660b568108d874cdb8e5df12e38ec` |
| Nested synthetic 8 MiB binary on both machines | `ca55fe6930b07cafdcacc5362d40674c01d7613b1c538fdc0799678dceb18dab` |

`source-hashes.json` records every transferred engine Python file, its base
commit, the probe file and bundle SHA256. `source-before-transfer.json`,
`native-unpack.json`, and `source-return.json` record the actual hashes/results.
The generated archive and payloads are not committed.

## Isolation and capacity

Target: Armbian Debian 12, aarch64, kernel `6.18.38-ophub`, Podman 6.1.1.
Unique root-owned 0700 workspace:
`/var/tmp/woow-arm54-ha-20261122-63f4j7hb` (now removed).
No large payload or storage was placed on the target's 2 GiB `/tmp` tmpfs.
Every mutating Podman argv used this prefix:

```sh
podman --root /var/tmp/woow-arm54-ha-20261122-63f4j7hb/store \
  --runroot /var/tmp/woow-arm54-ha-20261122-63f4j7hb/run \
  --storage-driver vfs --events-backend file \
  --tmpdir /var/tmp/woow-arm54-ha-20261122-63f4j7hb/tmp
```

The registry auth file was new/empty; HOME, XDG_CONFIG_HOME, REGISTRY_AUTH_FILE
and TMPDIR pointed into this workspace. No existing image was reused. The
native version container used network none, 256 MiB RAM with no additional
swap, 128 pids, 0.5 CPU, read-only root, cap-drop ALL, no-new-privileges,
log-driver none and pull never. No port was published. A separately created,
never-started container was inspected and removed, independently confirming
network none, no port bindings, no mounts, unprivileged, 256 MiB and read-only
root (`product-service-gate.json`). The archive code never calls Podman.

The 12 GiB reserve was checked before work, at extraction, around image
preparation and after cleanup. Manifest compressed bytes were capped at
128 MiB, expanded image bytes at 512 MiB, archive extracted bytes at 32 MiB;
image preparation also required at least 1 GiB MemAvailable before a 256 MiB
container. Minimum observed free space was **16.926 GiB**, final **17.259 GiB**.
These are measured phase checks and bounded small workloads, not new hard quota
or continuous free-space monitoring claims.

## Service preparation and real blocker

Public image: `docker.io/headscale/headscale:0.29.4`, ARM64 descriptor pinned to
`sha256:2df4cb333db8496801780b8b15ac13026dbe5c0b5207fca4abdde33e1cffaa31`.
Its manifest digest was checked directly against the public registry response
before pull. Anonymous registry tokens existed only in memory, never evidence.
Compressed image: 30,288,742 bytes; image size: 85,697,475 bytes.
Local image ID: `e37980719fa723cb0364743e29180a9f14511c3feac8de68c1a0436ccd0f92ab`.
Native binary reports Headscale v0.29.4, revision
`8106636c7f8d0cf8c9d4fb0beae94415069b768b`, Go linux/arm64.

**Service restore remains blocked.** The unmodified product
`hacommon.image_labels` reads no `org.opencontainers.image.version` from this
public image. `ha_headscale.VERSIONS.blocker('0.1.3', None)` returns
「無法讀取這台 Headscale 的版本。」 A binary version probe is not a replacement
for the product's target-version evidence. No image was relabeled, no guard
was removed, no service restore was attempted, and no HA fixture was relabeled
as accepted. A reviewed compatible ARM target image/version-evidence path is
needed before proceeding with actual HA conversion and restore.

Attempt history is retained:

1. `service-prepare-attempt1.json`: SSH exit 0 but report blocked, Podman
   `manifest inspect <single-OCI-digest>` exit 125. Podman says treating single
   images as manifest lists is not implemented. Fixed by direct public manifest
   fetch + SHA verification, not an unpinned pull.
2. `service-prepare-attempt2.json`: native `version` command exit 0, but the
   harness expected a bare version instead of Headscale's version/revision
   banner. Also corrected OCI labels lookup to Config.Labels.
3. `native-version-check.json`: exact public binary banner, exit 0.
4. `service-prepare.json`: native pinned image preparation passed, SSH exit 0.
5. `product-service-gate.json`: actual product version refusal and successful
   isolation inspection, SSH exit 0; service acceptance remains false.

## Cleanup and preservation

Only the private store was mutated. Its test containers, images and volumes
were verified empty; no mount under the workspace remained, then the entire
workspace was deleted. No global prune/reset or default-storage mutation ran.

`cleanup-attempt1.json` records real successful deletion and equal default
inventory, but SSH exit 1 because the final StartedAt check parsed Go's display
format incorrectly. No cleanup was repeated. `arm54_verify_cleanup.py` then
performed a read-only recheck using JSON timestamps: SSH exit 0, local evidence
assertions passed. `cleanup-verification.json` is the final result.

Original container IDs/image inventory/volumes/networks/default storage matched
before/after; `woow-auth-gateway`, `matter-server`, `homeassistant` all remain
running, with start dates before the probe (November 10/10/15 respectively).
No production secret/configuration/application data was read. Bind mount
contents and application health/business behavior were not inspected; inventory
and start timestamps are the preservation evidence, not full service UAT.

## Commands and local validation

The actual transfer command was `python3 /tmp/arm54-control.py` (exit 0).
Its exact executed source is retained as `executed-transfer-driver.py.txt`;
`harness-hashes.json` records its hash and the final harness source hashes.
`arm54_native_transfer.py` is the same driver parameterized for private local
source/state/evidence paths; that parameterization was syntax-checked, not
rerun against the already cleaned target.

The generated-source and actual native extraction commands were:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine python3 tests/e2e/lab/native_arm_archive.py make /tmp/arm54-source-20261122
# Remote (PYTHONPATH=<workspace>/source/backup-engine, TMPDIR=<workspace>/tmp):
python3 <workspace>/source/native_arm_archive.py arm-unpack <workspace>/native --expected <workspace>/source/expected.json --archive <workspace>/source/roundtrip.tar
# Source host, same engine PYTHONPATH:
python3 tests/e2e/lab/native_arm_archive.py source-unpack /tmp/arm54-source-20261122/return --expected /tmp/arm54-source-20261122/arm-expected.json --archive /tmp/arm54-source-20261122/arm-roundtrip.tar
```

Each exited 0. The SSH helpers were streamed via `python3 - <workspace>`:
service preparation, product gate and cleanup scripts listed above; the final
read-only verifier also received the local before-evidence timestamp. SSH used
StrictHostKeyChecking=yes, the user-provided `/tmp/ha-test-54-known-hosts`, and
the user-provided askpass script reading ARMHA_PW. Credential values are not
stored in harnesses, argv or evidence.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:tests/e2e/lab python3 -m unittest test_native_arm_archive -v
# 3 tests passed in 0.005 s; exit 0, no skips
git diff --exit-code 5c99b00 -- backup-engine tests/backup
# exit 0: product engine and public guard files unchanged
git diff --check
# exit 0
```

Seven harness/test files parsed successfully with ast.parse; evidence hashes
and cross-machine payload consistency assertions passed. No old 74-test suite
rerun. Unproved: encrypted archives (no age/zstd on ARM), large archives,
>8 GiB members, HA source DB conversion, actual service restoration, installer,
rollback, client reconnect, API authorization/ACL, or original service health.
No real originals, Hermes review retry, omnigent stop, or runner/model changes.
