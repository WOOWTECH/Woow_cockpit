# Real synthetic installer-phase client continuity

Exclusive coordinator slot: `headscale-continuity-next`, 2026-11-21.
**PASS on one justified retry at source 91758a2.** First run failed at d11f9bb;
both outcomes and the intervening memory gate are preserved. Slot released only
after independent cleanup verification (`slot-status.json`). Not commercial completion.

## Exact sources and command

- Run 1: **d11f9bbdaaee73bc1dc4e7a2905aacdf2c2207a3**, exit 1, approximately 124s.
- Run 2: **91758a2d53b5924e9bb8bf010be4c74418b6f866**, exit 0, approximately 209s.

Both invoked exactly:

```bash
cd /home/woowtechopenclaw/work/headscale-isolated-derp
bash tests/e2e/lab/headscale-product-test.sh --installer
```

The source was committed before each invocation. Only evidence files differed
from HEAD during run 2. `run1-source.json` / `run2-source.json` record source
hashes, including the unmodified engine flows and adapter. The corresponding
`.txt`, `.exit` and `-timing.json` files preserve sanitized controller output,
inner command status and timestamps. The route output in run2.txt retains its
original trailing space; that captured line is the sole evidence whitespace-check
warning and has not been rewritten. Source whitespace checks pass.
Capture wrappers themselves exit 0 after
successfully writing evidence; use the recorded inner `.exit` files for results.

## Preflight and bounded retry

Actual `owner.sh d --verify-isolation` returned `true none {}` before both runs.
Before run 1: cgroup current 2,112,876,544 / maximum 4,294,967,296 bytes; headroom
2,182,090,752 bytes. Host MemAvailable was 4,573,556,736 bytes. This cleared
>=2 GiB cgroup headroom and a conservative >=3 GiB host gate (2 GiB allowance
plus 1 GiB reserve). No competing heavyweight harness process was found using
ancestor-excluding pgrep. No synthetic active container or io.woowtech.test /
io.woowtech.backup.job labelled container, job volume or job network was present.
The eight original dev-d services were running.

After run 1 cleanup, memory temporarily fell below the cgroup headroom gate.
Four checks 15 seconds apart all refused permission to launch a retry; see
`retry-memory-checks.json`. Memory then recovered during the final inventory
capture, before the slot was released; this snapshot is saved as `recovered-*`.
The slot remained held and gates were rechecked immediately. `run2-gates.json`
records headroom **2,165,927,936 bytes**, host availability **4,426,792,960 bytes**,
isolation and no competing jobs. The wrapper independently rechecked isolation
and >=2 GiB headroom. Only then was the single justified retry launched.
No guard was weakened, service stopped, cache dropped, map changed or cgroup
limit modified to manufacture headroom. The retry used a fresh random namespace.

## Run 1 failure and correction

The controller reported conversion AUTO_RECONNECT=PASS and MANUAL_RECOVERY=PASS
(27 attempts / 49 seconds), explicitly **preliminary** because credential coverage
was incomplete. Installer failure prevented the final client private-state/log
registrations, so raw child output was correctly suppressed. Run 1 established
no installer-phase continuity PASS.

The retained installer directory contained one encrypted manual candidate and
no safety archive. Its exact saved Quadlet failed the installed generator with
unsupported `NetworkAlias=` and no generated service. The original full exception
was suppressed; this diagnosis is based on a deterministic retained-artifact
reproduction, not a claimed original traceback.

`quadlet-generator-probe.json` records the differential reproduction through
`/usr/lib/systemd/system-generators/podman-system-generator --dryrun --user --no-kmsg-log`.
QUADLET_UNIT_DIRS was confined to temporary directories beneath this run's private
synthetic root. Original: exit 1, no service, NetworkAlias rejected. Patched copy:
exit 0, service generated, both Podman endpoint flags present, no published ports.
No unit was installed by the probe.

Fix commit **91758a2** changes only the synthetic installer and regression test.
It uses `PodmanArgs=--network-alias=headscale.lab --ip=<validated synthetic IP>`
(the same Podman flags exercised by the converted server), instead of standalone
NetworkAlias/IP Quadlet directives (NetworkAlias was the rejected key). Network validation, no ports, resource limits,
client identity/process checks and shared deadlines remain intact.

The new regression test was observed red before the fix and green afterward.
**48 local tests passed**, zero skipped, in 12.360s, plus bash syntax, Python
compilation and diff checks. `local-tests.json` records the commands and results.
The exact corrected source then passed run 2 without further source edits.

## Run 2 observed results

The credential controller released scanned output with complete named synthetic
authorization/private-key registration and submitted log-snapshot coverage.

| Phase | Result | Attempts | Observation elapsed |
| --- | --- | ---: | ---: |
| Installed | PASS | 14 | 29.8s |
| Automatically rolled back | PASS | 15 | 28.1s |
| Separate restart | PASS | 19 | 34.8s |

Every phase checked unchanged pre-conversion client Self ID, PublicKey and IPs;
unchanged client container ID, StartedAt and PID; both matching Headscale nodes
online; and a successful DERP(lab) pong in **each direction**. Process identities
were checked again after pings. Both clients stayed running across the installer
phase, without new auth keys, down/up or client restart. Earlier conversion-phase
manual reconnect remains in the existing harness and is not hidden by this claim.

These are bounded observation durations after restore/safety verification and
health readiness, not total outage or zero-downtime measurements. Each phase
shares a 60-second deadline, per-command min(5s, remaining) timeout and bounded
output capture.

Other observed acceptance:

- Conversion automatic reconnect: 21 attempts / 37s since source shutdown;
  subsequent explicit reconnect and ten-packet DERP stability passed 10/10.
- Target API credential returned 200; removed source credential returned 401.
- Real adapter import_manifest, encrypted package and flows.run_restore succeeded.
- One-shot ExecStartPre failure triggered actual flows.RolledBack, exactly once.
- Both safety archives encrypted and privately extracted successfully.
- Exact cold-export node IDs/keys/machine keys/IPs and Noise metadata/content
  matched, as did headplane content/mode/UID/GID and distinguishing rollback markers.
- Pinned Headscale image, selected internal network/IP, no port bindings, active
  unit and consumed one-shot marker passed checks. Separate restart reverified.
- HEADSCALE_INSTALL_ROLLBACK=PASS and HEADSCALE_INSTALL_CLEANUP=PASS.
- Synthetic internal network had no default route; external probe was rejected.

Resolved images remained Headscale
`a5f7b9715dea9116f435ff7892e6925895d1c92d4a265cc02eff1a2abadb227d` and Tailscale
`62dc2e673073db15c940b08320bc15303dce144ccb4fdf40b88a3c09dbbf027f`.
No image pulls. Both clients exceeded SIGTERM's 10-second teardown grace and
Podman used SIGKILL, recorded in run2.txt. Do not claim graceful client shutdown.

## Independent cleanup and slot release

Inventories were collected independently through owner.sh d: podman ps -a,
volume ls, network ls, secret ls, labelled-object filters, systemctl --user
list-units hs-install-*, and glob metadata checks for installer Quadlets,
drop-ins, failure markers and private installer directories. Container/network
IDs accompany names. Original running container IDs, StartedAt and PIDs were
compared exactly. No production credential or original volume contents were read.

Run 1's runtime inventories matched immediately; its intentionally retained
private installer directory was the sole cleanup-path discrepancy. After saving
sanitized metadata and generator diagnosis, only that exact run-owned directory
was removed (`run1-private-cleanup.json`). Its exact enclosing fixture and staged
engine directory were then removed (`run1-scratch-cleanup.json`).

Run 2's independent inventories all matched, and its installer private directory
had already been removed by successful harness cleanup (`after-run2-*`). After
preserving scanned output, its exact remaining fixture and staged-engine directory
were removed; the staged installer hash was checked against run2-source.json
before removal (`run2-scratch-cleanup.json`). No broad wildcard deletions.

**final-comparison.json: all true.** Containers, volumes, networks, secrets,
labelled objects, units, original process identities, isolation and cleanup paths
match the initial snapshot. No installer path remains; both runs' fixture/stage
directories are removed. The original eight dev-d services retain their original
process identities. Outer isolation remains `true none {}`. Slot released only
following these checks; no third run or further live mutation is pending.

## Remaining limits

This closes the synthetic installer-phase continuity gap for this pinned setup.
Real customer HA backups, Headplane UI, other schemas/configurations and failure
modes, complete age-identity dynamic scanning, production activation and commercial
acceptance remain unverified. Public guards are intact. No production changes,
map changes, agent runner/model/workspace configuration changes, omnigent stop,
or Hermes review/retry occurred.
