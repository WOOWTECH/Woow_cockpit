# Prepared package fixture controller — native provisioning not run

Source: `tests/e2e/lab/focus_emqx_r4_provision.py` with `_artifact.py`, `_inner.py`, `_client_guard.py`, and `_provision_tests.py`. Default invocation prints a plan and starts nothing. This is source ready for coordinator review; it is not a package smoke result or an installer/upgrader run.

## Exact inputs and prerequisites

| Role | Existing immutable image config |
|---|---|
| Outer base | `sha256:3d718d475d99c635dadfa271c8bd6854931ec5904172d36f3b716455bd551362` |
| EMQX5.8.9 | `sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b` |
| Entrance | `sha256:47ce8258a10e28ce4b4498588c25ef77ae328f4c56cbe3e8d5dcf4f6d8019997` |
| MQTT client | `sha256:93a0bdfcbd9b7a86b36127cb81f54e1afd2019f12f39033458df405a027c03e3` |

The controller accepts three regular, uncompressed OCI archives named `broker.oci.tar`, `entrance.oci.tar`, and `client.oci.tar`. It reads/hashes every descriptor, compressed layer and ordered uncompressed layer diffID against the pinned config; one linux/amd64 image per archive, <=512MiB combined transfer, <=1GiB expansion per image. It never extracts layer files on this host. Archive SHA256s must be in the new lease. Preparing those archives from existing isolated caches needs a separately reviewed read-only export command; this driver does not select dev-d or pull images. No image archive has been created by this preparation.

The broker/entrance fixture units explicitly bind the reviewed cached config IDs: the package's literal digest references do not currently resolve in the source cache. The MQTT client's unchanged literal reference `docker.io/library/eclipse-mosquitto:2.0.22@sha256:212f89e1eaeb2c322d6441b64396e3346026674db8fa9c27beac293405c32b3c` **must resolve after load**, or provisioning stops. No synthesized digest alias or pin waiver.

The candidate input is `candidate.tar` + `candidate.json`, produced from the actual owned converted candidate after its native restart and full postcheck. `_artifact.export_candidate()` is a producer hook; it rechecks the actual broker's complete configuration/table receipt, requires a nonempty admin table and package listener layout, calls the real product `verify_restored`, then stops and exports only that owned candidate data volume. It accepts no arbitrary source-volume CLI. Tar data must be <=256MiB, regular files/directories with UID/GID1000, no links/sparse/traversal/duplicates/cookies/plugin-code paths; database+cluster config are mandatory. Both artifact hashes and the producer commit must be in the lease. Every copied byte is rehashed before any outer resource is created, and verified again in the fresh device.

**Remaining native producer prerequisite:** the queued27cb52c4 broker-only plain/dead_row/noauth runs do not create package artifacts. The separate producer implementation is now prepared in `package-producer.md` and `focus_emqx_r4_prepare.py`; it has not run. Its future reviewed lease must create the target using profile `emqx-r4-package-v1` from the start: the exact package base/ACL/bootstrap files and environment, dashboard backend18093, WS entrance8093, scheduler1:1, synthetic cookie/admin/bootstrap, matching `/fixture` dependencies. `PACKAGE_ENV` records the required EMQX overrides. Silently changing the plain candidate's operational settings after export is prohibited. The receiver also requires the shared profile hash, full original target record, actual mounted-file hashes/bootstrap metadata, and exact config behind the unchanged MQTT client pin. It compares *all* effective config roots and *all seven* table receipts before accepting it; an incomplete or mismatched profile fails. A matching artifact has not been generated or transferred yet.

## New lease and invocation

A provision lease is distinct from the three queued generated-case leases. Required fields:

```json
{
  "case": "EMQX-R4-package-fixture:plain",
  "source_commit": "<exact committed controller SHA>",
  "artifact_source_commit": "<exact reviewed producer SHA>",
  "device": "woowbk-r4-package-<12 lowercase hex>",
  "expires": "<timezone-aware; at least 40min remain>",
  "base_image": "<exact base config above>",
  "image_configs": {"broker":"<above>","entrance":"<above>","client":"<above>"},
  "image_archives": {"broker":"<archive SHA256>","entrance":"<archive SHA256>","client":"<archive SHA256>"},
  "data_sha256": "<candidate.tar SHA256>",
  "manifest_sha256": "<candidate.json SHA256>",
  "inputs": "controlled-generated-only",
  "package_smoke": true,
  "installer_or_upgrader": false
}
```

Concrete first proposal: case `noauth`, device `woowbk-r4-package-9d42f305c7a1`, volumes `woowbk-r4-package-9d42f305c7a1-home`, `woowbk-r4-package-9d42f305c7a1-varlib`, and `woowbk-r4-package-9d42f305c7a1-containers`. These names are reserved only by the future exact lease; no resources exist from this preparation, and the controller must prove all four absent before creation.

Cases initially supported: plain, dead_row, noauth, one invocation per lease. Proposed smallest package turn is noauth after its separate package-profile producer succeeds: ~35min runtime hard budget +5min cleanup. Runtime duration has not been measured. Review the privileged/systemd outer lab model before any lease; it remains inside the existing rootless isolated lab store.

```sh
HEAVY_WAIT=45 HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
  python3 -B -I tests/e2e/lab/focus_emqx_r4_provision.py --run \
  --lease /tmp/parity-focus-20261127/lease-emqx-r4-package-fixture-noauth.json \
  --artifact /tmp/parity-focus-20261127/owned-package-candidate-noauth \
  --images /tmp/parity-focus-20261127/owned-emqx-r4-oci \
  > /tmp/parity-focus-20261127/emqx-r4-package-noauth-native01.json
```

Do not run the earlier standalone `_package.py --run` against existing apps. The new controller invokes full unchanged smoke only within its own create/prove/cleanup transaction, including real bounded clients; `_package.smoke_status` is reused only to parse fixed check IDs/statuses.

## Bounds, commands and effects

- Only `/home/woowtechopenclaw/.woowbk-lab/bin/labpodman`. Every mutation/exec selects one exact fresh `woowbk-r4-package-<12hex>`; dev-d is never an exec/lifecycle target. Before intent, prove that device and all three volume names absent; bind `io.woowtech.r4.fixture=<device>` labels.
- Exactly `<device>-home:/home`, `<device>-varlib:/var/lib/woowtech-backup`, `<device>-containers:/var/lib/containers`; no host bind mounts. All image VOLUMEs ignored. Outer networknone, zero published ports,2304MiB=swap/2CPU/2048pids. Existing lab `--privileged --systemd=always --device /dev/fuse` only for this fresh nested device. Allowed runtime tmpfs mounts are checked explicitly.
- Fresh floors: host MemAvailable>=3000MiB, disk>=16GiB; retain13GiB before mutating phases; combined staging<=512MiB. Shared device mutex acquisition15sec, globalheavy wait45sec. No wait loop holding either slot and no automatic retry. Cleanup is allowed below floors.
- Only the new device's existing `woowbk-provision --appowner-uid1031` receives a fixed synthetic login on stdin; only its user manager is restarted. No `up.sh`, installed helper deployment, app baseline copy or real password reader.
- Eleven exact public package blobs from `ea5886c58ef2c6ab1f4e6a4d01908cc9dc4525de`, hashes in `package-provision-source.json`. `git show` reads immutable blobs; no working-tree package execution. Installer/upgrader files are not transferred or called. Local H2 draft remains local/unpushed.
- Generated env0600 + four synthetic Podman secrets; base/ACL/entrance from reviewed package; ordinary owned `/fixture` inputs. Actual Quadlet generation/load/start must succeed. Five broker ports bind127.0.0.1 inside the fresh device. Broker768MiB/.5CPU/256pids; entrance128MiB/.25CPU/128pids; clients128MiB/.25CPU/64pids. No pull, imagevolumeignore, capdrop.
- Receiver imports only verified candidate data, preserves node UID1000, waits real broker readiness, compares all config roots and complete admin/ACL/account/PSK receipts, then calls the real product postcheck. No vendor/admin validation skipped and no E90 mismatch waiver.
- Full unchanged `bash tests/smoke.sh` has no skip options. Real fixture-only Podman PATH wrapper adds resource bounds/no-pull to exact pinned clients and permits fixed owned reads and the unchanged active healthcheck calls; it does not fabricate outputs or modify authentication/check outcomes. All checks including A4/A5/A6/A10 retain their actual FAILs. Synthetic retained message is cleared by the unchanged script. Only check IDs/statuses/exit code leave the fixture; no raw logs/inspect/secrets/credentials. A smoke exit1 is captured evidence, not a product/package patch or passing acceptance.

## Failure, receipts and cleanup

Private atomic recovery receipt `/tmp/parity-focus-20261127/emqx-r4-package-<12hex>.recovery.json` records source/payload/artifact hashes, prior absence, creation intents before each write, phases, fixed results and cleanup state. On any concrete failure retain that result and stop; no blind retry.

Finally, the controller proves exact label/base/network/mount ownership, removes only this device with `rm --force --volumes`, removes only the three exact labelled volumes backed by its intent/prior-absence receipt, verifies all four resources absent and compares the preexisting outer container/volume/image inventory. No prune, baseline/catalog mutation or original app selection. The temporary host payload is deleted on normal unwind. Mark cleanup complete only after original inventory matches; uncertain cleanup remains false.

Crash recovery: a new cleanup lease binds the same source/device and exact private `receipt_sha256`, with >=5min left; run the same reviewed command with `--run --cleanup --lease <cleanup-lease>` under globalheavy/shared mutex. No candidate/image arguments are needed. Label/receipt/prior-absence checks still apply. Cleanup never guesses a name or deletes an unproven resource.

Offline boundary gate:12/12PASS,0fail/error/skip/blocked/shim,run_native absent. This does not validate actual image save/load identity preservation, fresh device provisioning, generated Quadlets, candidate transfer or smoke runtime. Those remain next reviewed native prerequisites. Existing D0 real fullflow stays the fullflow evidence; H1 device-env-wins policy and remaining R4 cases are unchanged.

Prepared producer/cache-export commands, exact profile hash and archive-provenance measurement plan are in `package-producer.md`, `package-profile.json` and `cached-image-archives.json`. No artifact/archive SHA is fabricated: all output hashes remain null until separately leased execution. Existing generated27cb leases cannot authorize those exports.
