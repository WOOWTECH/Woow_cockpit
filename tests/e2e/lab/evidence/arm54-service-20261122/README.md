# ARM54 supported service path and lifecycle — 2026-11-22

Base **3fe2ff3**, dedicated branch `test/arm54-service-20261122`, separate worktree
`/tmp/ha-arm54-service-20261122`. This worker retained exclusive .54 mutation
ownership; Lorentz did not operate it. No archive roundtrip was repeated.
No applicable AGENTS.md was found in the previously checked repository/ancestor
paths or the inspected package. Only new harness/evidence files are changed.

## Supported image path resolved truthfully

The default local package checkout was old (0.29.3). Git object
**0afdfa464a5ae55c85145c242f5b38ac88eea969** is the actual Woow 0.29.4 package
recorded by the existing acceptance documentation. Its `Containerfile` explicitly
builds a local runtime; it does not claim a shipped GHCR runtime image.
`package.Containerfile` is its exact unmodified recipe. `package-provenance.json`
records Git source and file hashes. No --label or build-arg override was used.

Both original recipe inputs are public multi-architecture indexes with ARM64:

| Input | Exact recipe index digest | ARM64 child digest |
|---|---|---|
| ghcr.io/juanfont/headscale:v0.29.4 | `8833f828b414c0907b7e5c71da76473216fe17cce0818a166b536ec552c0903f` | `2df4cb333db8496801780b8b15ac13026dbe5c0b5207fca4abdde33e1cffaa31` |
| docker.io/library/debian:12.11-slim | `b1a741487078b369e78119849663d7f1a5341ef2768798f7b7406c4240f86aef` | `f6af819c6ac3902cbd1df3c4a00208abf8bfbbdf65fd25bbb330d2f8ad961d29` |

Registry bytes/config digests were verified; ARM input layers total under 128 MiB.
The recipe was built **natively on .54**, network none, pull never at build,
512 MiB build limit, using separately pulled pinned public inputs. It is a
**local rebuild of the official package recipe**, not a shipped runtime image.
Tag: `localhost/woow-headscale:0.29.4-arm54-local`.
Image: `a792d2bd0935634c6889aecda76f8b3303c0ca6cfaf4182f16b32b6a86000ab6`,
arm64, 149,745,951 bytes. Actual product `hacommon.image_labels` and
`ha_headscale.VERSIONS.blocker('0.1.3', version)` accept real label 0.29.4.
The package binary and pinned upstream binary are byte-identical:
`cbad8f02524cc6a94955a107a72e1d4cc652ae3f22e740d5c60884e7f384d60e`
(49,283,234 bytes). No fabricated label, version-table edit or guard bypass.

## Passed synthetic service chain (gRPC CLI client, zero VPN nodes)

`synthetic-service-converter-restore.json`: SSH exit **0**, status **passed**.
A real native service created source user `arm54source`; an independent target
created `targetonly`. Source stopped before its data was exported into a newly
constructed cold HA archive (add-on0.1.3 / upstream0.29.4 / ARM).
Generated HA SHA256:
`362979eadca873ad358083d2f206f8c835b3cc135f526fc2055e22bb93ff8e3d`.

The real, unchanged `ha_headscale.convert` performed source scan, sandboxed
SQLite checks/key-row replacement, target checks, configtest and tar validation.
Its result was imported into a new isolated volume, then the same native runtime
started on that restored volume with target configuration. Real `headscale
health` and gRPC Unix-socket CLI `users list` proved startup and source user
present / target-only user absent. Source Noise bytes, target config SHA256 and
the target Headplane marker were preserved. Target/source API key counts were
zero; this is not evidence of nonempty API-key preservation.

This is an internal converter + explicit private-volume import service test,
not a public installer/rollback or production restore acceptance. The logical
Quadlet work adapter describes the actual isolated image/volumes/config; no
systemd units were installed. Rootful .54 rejects `podman unshare` (exit125,
`please use unshare with rootless`). A bounded test transport executes only
real `/proc/self/{uid,gid}_map` reads and stat of this store's own volume paths
directly in the actual rootful namespace. IDs/stat outputs are not fabricated;
all other Podman calls use the private storage. This does not prove a rootless
OwnerRunner deployment. Three new local boundary tests verify its restrictions.

## Tailscale VPN client not passed

The optional stronger client attempt used public official ARM image
`docker.io/tailscale/tailscale@sha256:8934bed5f68e80c5f9c881f62c65909223ee660432946c10ad212d958fc2c2bb`
(59,280,179 compressed bytes), pinning the observed stable ARM descriptor.
Only its client binaries were copied into the test's private directory and
executed inside the Headscale container's network-none namespace. Generated
preauth keys were kept in a 0700 directory / 0600 file, masked in memory, never
argv values or evidence. Runtime had no external route or published port.

Source registration via `tailscale up` did **not** pass. A direct127.0.0.1 URL,
private certificate SAN, and empty proxy settings on this client process did
not resolve it; localhost TCP was independently reachable. Wrapper SSH exit1;
fixed diagnostics contain timeout/network-unreachable indications, but their
causal relation to control registration is not established. Root cause remains
unresolved. No same-ID/IP recovery, restart without reauth, relay or VPN-node
assertion passed. No broad networking or host defaults were changed to force it.
All raw daemon logs, TLS keys, preauth files and state were deleted with the
private workspace; only fixed predicates/vocabulary and sanitized status remain.

## Real TempObjects lifecycle (product3fe2ff3)

Six scenario checks passed, final `native-tempobjects-completion.json` exit0:

- Real volume import/export SHA256 equality.
- Actual container exit23, same-name container+volume removal, idempotent cleanup.
- Same job/role reused successfully after failed run and cleanup.
- Actual volume-import producer cancellation with product `flows.Cancelled`;
  producer error propagated, real partial volume removed.
- `sweep` retained an alive job and removed a dead job's real container+volume.
- One **explicitly injected transport refusal** on volume removal left a real
  tracked volume; a subsequent real cleanup removed it. This is not a claimed
  kernel/disk/Podman removal failure.

The first three checks passed in the initial run; only the remaining checks
were run on completion. Initial cancellation fixture used a nonexistent
BackupError code and was corrected to product Cancelled. The final self-contained
lifecycle harness includes that correction, syntax-checked without repeating
passed remote scenarios. Every attempt's actual source is retained separately.

## Isolation, failed attempts and cleanup

Unique0700 workspace `/var/tmp/woow-arm54-ha-20261122-et19nil2` used dedicated
`--root .../store --runroot .../run --storage-driver vfs --events-backend file
--tmpdir .../tmp`, private HOME/config/authfile, empty public-registry auth and
no target /tmp payload storage. Runtime was network none, pull never,
log-driver none, no-new-privileges, bounded memory/pids/CPU. No default-store
mutation, old image reuse, public port, service unit install, production access,
Hermes review or runner/model setting change occurred.

All attempt result/exit/source snapshots are retained, including:
initial build's overstrict loopback-only assertion (Armbian also creates
unconfigured sit0/ip6tnl0; no IPv4 routes), an early service invocation before
probe metadata was available, rootful unshare incompatibility, a synthetic
absolute Quadlet path rejected by the product (corrected to supported %h/ path),
the invalid cancellation fixture, and one client probe quoting SyntaxError.
These are harness failures, not omitted passes or product guard removals.
`namespace-and-product-version.json` captures actual namespace/proc data.

`cleanup.json` SSH exit0 / status passed: test containers, volumes and images
empty; no workspace mount remains; entire workspace/store/private artifacts
removed. Default containers/images/volumes/networks/store match the baseline.
All three original containers are running with their original pre-probe start
timestamps (Nov10/10/15). Minimum observed free space was 16.166 GiB; final was 17.259 GiB; all exceed the **12 GiB** reserve. This is phase sampling and
bounded small images/data, not a continuous-reserve or hard-quota claim.

## Exact commands / validation

Credentials were supplied only to the existing askpass environment; all SSH
used StrictHostKeyChecking=yes and `/tmp/ha-test-54-known-hosts`. Values are not
committed. Local control commands were:

```sh
python3 tests/e2e/lab/arm54_image_sources.py
python3 tests/e2e/lab/arm54_remote_control.py init
python3 tests/e2e/lab/arm54_remote_control.py upload
python3 tests/e2e/lab/arm54_remote_control.py run --script arm54_build_native.py --output native-package-build
python3 tests/e2e/lab/arm54_remote_control.py run --script arm54_namespace_native.py --output namespace-and-product-version
python3 tests/e2e/lab/arm54_remote_control.py run --script arm54_service_native.py --output synthetic-service-converter-restore
python3 tests/e2e/lab/arm54_remote_control.py run --script arm54_lifecycle_native.py --output native-tempobjects-completion
python3 tests/e2e/lab/arm54_remote_control.py run --script arm54_binary_provenance_native.py --output package-binary-provenance
python3 tests/e2e/lab/arm54_remote_control.py run --script arm54_service_client_native.py --output tailscale-direct-loopback-verified
python3 tests/e2e/lab/arm54_remote_control.py run --script arm54_cleanup.py --output cleanup
```

Build initial wrapper exit1 was the harness isolation assertion after successful
build/version gate; namespace/version and binary provenance commands exit0.
Service-converter-restore, lifecycle completion and cleanup exit0. VPN-client
wrapper exit1 remains a failure. `.source.txt` + `.exit.json` capture exact
executed revisions and statuses (final reusable files may include later fixes).
Empty stdout is retained in `.stdout.txt` with an explicit JSON descriptor.
Every source engine file/bundle SHA is in source-hashes.json; final harness
hashes are separate. No archive roundtrip or old74-test suite rerun.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:tests/e2e/lab python3 -m unittest test_arm54_rootful_boundary -v
# 3 tests passed in 0.021s, no skips; exit0
git diff --exit-code 3fe2ff3 -- backup-engine tests/backup
# exit0: engine/public guard files unchanged
git diff --check
# exit0
```

Unproved: VPN client identity/reconnect/relay, real originals, public
installer/rollback, rootless deployment, Headplane UI and nonempty API key
behavior, complete real-source secret scanner coverage, disk-full/real deletion
failure, large archives and >8GiB members. Existing production application
health/business behavior was not exercised.
