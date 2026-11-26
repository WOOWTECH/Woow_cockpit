# Proposed next lease — one case, no package/install commands

Suggested first group: **plain → dead_row → noauth**, three independent exact-case leases/invocations. Below is the noauth command; substitute the matching case in command/lease/output for the other two. No case starts before coordinator review or ahead of queued R8/OD work. Device: existing isolated `woowbk-dev-d`, through `owner.sh d`; other apps/catalog/units/installed engine/baselines are untouched. Exact existing image:

`sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b` (EMQX5.8.9 linux/amd64, previously executed by E44).

The coordinator must review the committed driver and issue a **new R4 lease** before running. No E44/NC lease is reusable. Native image schema/launcher/behavior has not been validated for these newly generated cases.

```sh
HEAVY_WAIT=45 HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock \
  /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
  python3 -B -I tests/e2e/lab/focus_emqx_r4.py --run --case noauth \
  > /tmp/parity-focus-20261127/emqx-r4-noauth-native01.json
```

Lease location: `/tmp/parity-focus-20261127/lease-emqx-r4-noauth.json`. Fields required by the driver:

```json
{
  "device": "woowbk-dev-d",
  "case": "EMQX-R4-generated:noauth",
  "source_commit": "<reviewed clean driver commit>",
  "image_config": "sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b",
  "command": "python3 -B -I tests/e2e/lab/focus_emqx_r4.py --run --case noauth",
  "package_commands": false,
  "expires": "<timezone-aware expiry at least 15min after execution begins>"
}
```

Request20min per case including diagnosis/cleanup; runtime capped15min (child840s, supervisor870s, host900s), one case per invocation. Native broker time estimate8-12min/case, not a measured duration for these inputs. The three leases may be issued together with the same reviewed commit; coordinator still schedules separate turns after R8/OD and between other workers. Globalheavy waits at most45s before refusing a slot; the device mutex acquisition times out after15s. On refusal, yield/requeue outside the heavy slot; no automatic retry loop. Remaining order: admin_public, changed_acl, psk, http_dummy, file_dummy, jq_constant, env_dummy, lost_auth_setting. The separate H1 device-env acceptance check is still to be prepared under current policy.

## Resource and scope bounds

- At most2 running brokers, each768MiB memory+swap,0.5CPU,256pids,+S1:1; short image ID helper uses same bounds. Source stops/removes before target+candidate start.
- Staging/file output256MiB; source payload<=16MiB and file<=4MiB. Device headroom>=1900MiB, host MemAvailable>=1200MiB; disk>=13GiB+256MiB before writes,13GiB during writes. Cleanup is allowed below the floor.
- Existing globalheavy + `/tmp/woowbk-dev-d-mutation.lock` held for whole run. Verify outer networknone/ports{} before/after. Every broker uses networknone, no ports, no pull, readonly root, no-new-privileges, capdropALL, image-volumeignore. No external HTTP/DNS target; HTTP callbacks are inside each broker's own loopback. MQTT clients are fixed in-image Erlang loopback probes, no downloaded client/compiler/BEAM.
- Generated files only: own bootstrap CSV, ACL, file dummy, one named environment dummy and PSK. No imported executable/plugin/SQL, no host credential/file/environment inputs, no original HA fixtures or fixture-capture helpers. Pure jq uses a constant or exact synthetic variable; no arbitrary filter or path argument.
- Mutations must target the job's exact `woowbk-<job>-<role>`, own volume path or private payload. No catalog/service/package operations exist in the native runner. Durable volume/image inventories compare before/after; unrelated container churn is observed separately.

## Cleanup/evidence

TempObjects removes owned containers with rm --volumes and owned named volumes. Image VOLUMEs never create anonymous volumes. Require empty TempObjects and equal durable inventories; retain fixed success/failure JSON without raw values. On failure, private bounded diagnostics remain only under the named owned HOME payload. Before deleting it, verify exact path/UID/reviewed fixture-source digest, and independently check that job-label containers/volumes/networks are zero; use same mutex. Never prune/sweep names or remove any baseline. Close mutex and report lease released in own status. No broad tests or D0 rerun are requested.
