# Package smoke and H2 — source/command review, execution pending

Reviewed exact package HEAD `ea5886c58ef2c6ab1f4e6a4d01908cc9dc4525de` in `/home/woowtechopenclaw/Woow_podman_emqx`; selected tracked source bytes equal HEAD (`package-source.json`). The existing unrelated untracked compose file is untouched. Local draft `5c748a6617cbb4847e8b4eca1e4b1f8841f4b864` remains unpushed. Existing real H2 proof is preserved; do not rerun the upgrader merely to repeat its known smoke exit-code decision.

| Command | Actual source-side effects | This preparation |
|---|---|---|
| `tests/smoke.sh` (no flags) | Reads package env, Podman secrets/inspect/logs and user journal; attempts Dashboard logins; creates transient pinned mosquitto clients on package network with `--pull=missing`; writes/clears a generated retained MQTT message; deletes own TMP | Reviewed, not executed. Only a fresh synthetic fixture device can contain its fixed names/values. FAIL lines remain FAIL. |
| `tests/smoke.sh --quick` | Skips MQTT/file/log checks, still performs A1-A4/A9 | Historical H2 evidence exists; not a substitute for each new full smoke. |
| `scripts/install.sh --accept-defaults --no-smoke` | Preflight/linger and package lock; writes per-user env/settings, renders/dry-runs Quadlets, pulls images, creates/replaces package secrets/bootstrap CSV; installs/prunes files, daemon-reloads/restarts units, records env hash and checks health/HTTP | **Not run and not called by these drivers.** `--no-smoke` does not make it read-only. |
| `scripts/upgrade.sh --no-backup` | Creates unit/image snapshot; installer still pulls/writes/restarts; smoke failure restores unit files/manifest, daemon-reloads and restarts broker/entrance/ngrok, quick rollback check | **Not run.** `--no-backup` is not a safe dry run; it suppresses a safety backup. |
| Marker-aware local draft smoke | A4/A5/A6/A10 become warnings under import marker | Historical proof only. Do not use to conceal current matrix failures or call upgrade accepted. |

## Why exact smoke is not run against current dev-d

The script addresses `woow-emqx`, `emqx.service`, `woow_emqx_network` and package secret names directly. Changing names, stubbing `systemctl` or secret readers, or pretending a fresh generated broker is that installed package would not prove the exact package behavior. Existing dev-d apps must remain untouched. A fresh fixture device gives those names their literal meaning and contains only synthetic values.

## Initial proposal: a fresh package-shaped device (current driver: package-provision.md)

Controller must remain the existing isolated lab tool, never host Podman. Exact existing clean device image was read-only inspected:

`sha256:3d718d475d99c635dadfa271c8bd6854931ec5904172d36f3b716455bd551362`,238086639bytes (`localhost/woowbk-device:noble`).

Proposed disposable name `woowbk-r4-package-<12 lowercase hex>`; label `io.woowtech.r4.fixture=<same name>`, networknone, zero outer ports;3new volumes `<name>-home`, `<name>-varlib`, `<name>-containers`. Maximum2304MiB memory=swap,2CPU,2048pids; host MemAvailable>=3000MiB,disk>=16GiB; max45min fixture lease, smoke<=10min/case, image/artifact staging<=512MiB. Inner broker768MiB/0.5CPU/256pids; entrance128MiB/0.25CPU/128pids; one client128MiB/0.25CPU/64pids. Cases and package smoke serial, never overlap with native dev-d mutation lease.

Reviewed outer creation command shape (prepared only; fresh names must first be proven absent, label every new volume):

```sh
# LP is /home/woowtechopenclaw/.woowbk-lab/bin/labpodman (isolated lab store).
"$LP" run --detach --name "$r4_device" --hostname "$r4_device" \
  --label "io.woowtech.r4.fixture=$r4_device" --pull=never --image-volume=ignore \
  --network none --systemd=always --privileged --device /dev/fuse \
  --memory 2304m --memory-swap 2304m --cpus 2 --pids-limit 2048 \
  --volume "$r4_device-home:/home" \
  --volume "$r4_device-varlib:/var/lib/woowtech-backup" \
  --volume "$r4_device-containers:/var/lib/containers" \
  sha256:3d718d475d99c635dadfa271c8bd6854931ec5904172d36f3b716455bd551362
```

This follows the existing lab systemd/nested-Podman device model, including its privileged flag **inside the rootless isolated lab store**. It is a separate review item, not a silent extension of the two-broker dev-d lease. No device/provisioner command has been executed.

Initial sequencing below predates the provisioning code; `package-provision.md` now supplies the reviewed-source candidate for the next provisioning lease:

1. New device only: use image's existing `woowbk-provision --appowner-uid 1031` with a fixed **synthetic** disposable login on stdin; never `up.sh` (it reads the existing lab password). Start/wait its user manager; only fresh device's passwd/subuid/systemd state changes. Do not copy existing app HOME/volume/secrets/catalog/helper data.
2. Copy selected exact package source/config/Quadlet templates into `/home/appowner/r4-package`, verify `package-source.json` hashes. Transfer only the already cached exact EMQX/nginx/mosquitto images through bounded save/load; no pulls. Require the unchanged smoke's pinned client reference exists before it runs; if archive load loses digest identity, stop and prepare an explicit image binding rather than waive the pin.
3. Generate synthetic package env, bootstrap/dashboard/cookie secrets and fresh units from those reviewed templates. Add limits/no-pull/image-volumeignore **to fixture units only**. Publish the five broker ports on127.0.0.1 **inside this isolated device**, no host/outer ports; real entrance and internal package network. This is generated fixture setup, not running the installer/upgrader.
4. A verified candidate must be copied/promoted into those owned package volumes with its own generated bootstrap/file/env/HTTP dummy dependencies. The current broker-delta driver deletes its payload on success, so it does **not** supply this transfer. Prepare that owned artifact handoff before claiming the package phase runnable end to end; do not substitute a preconfigured expected state for an imported candidate. Create `/home/appowner/r4-owned-inputs.json` with the reviewed source commit/case/device/input scope.
5. Then run the prepared exact executor under globalheavy/shared mutex:

```sh
HEAVY_WAIT=45 HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
  python3 -B -I tests/e2e/lab/focus_emqx_r4_package.py --run --case noauth \
  --lease /tmp/parity-focus-20261127/lease-emqx-r4-package-noauth.json
```

The executor requires lease case `EMQX-R4-package:noauth`, exact `source_commit`, `device`, `fixture_inputs=synthetic-owned-only`, `installer_or_upgrader=false`, and expiry. It verifies outer label/isolation/owned mounts, UID1031, fixture marker, unchanged package hashes and cached pinned MQTT client. It executes full unmodified `bash /home/appowner/r4-package/tests/smoke.sh` through the fixture's owner helper, retains only check IDs/statuses/exit code. A smoke exit1 is evidence, not a reason to disable checks. Actual upgrade acceptance stays pending.

6. Before lease release: retain fixed smoke statuses and artifact/fixture provenance, stop/remove only that exact labelled outer device with `rm --force --volumes`, verify no inner resources remain with its namespace destroyed, then remove only the three exact labelled owned volumes. Never `system prune`, no baseline cleanup. Independent existing device/catalog/volume/image/source invariants and shared-mutex release must be recorded by the provisioning driver. The executor deliberately does not own/provision/delete that device by itself.

This initial proposal led to the new provisioning controller in `package-provision.md`. Native package-profile generation, transfer, provisioning and smoke remain pending. No installer/upgrader lease is requested.

## Current implementation update

The preceding section records the original proposal. The separate provisioning/verification/cleanup driver is now implemented in new focus_emqx_r4 files and passed12/12 guarded offline boundary checks. `package-provision.md` is the current exact command/lease/recovery contract and supersedes the earlier standalone smoke invocation above. No provisioning, image archive export, package-profile candidate generation, installer/upgrader or smoke has run. The matching candidate producer/artifact and verified OCI archives remain explicit prerequisites, not completed transfer proof.
