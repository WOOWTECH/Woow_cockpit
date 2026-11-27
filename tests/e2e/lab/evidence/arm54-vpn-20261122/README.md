# ARM54 VPN registration diagnosis and restored-client acceptance

Base: `cd849408cb227fb648a94534c3964e670564cffa`. Dedicated branch/worktree:
`test/arm54-vpn-20261122`, `/tmp/ha-arm54-vpn-20261122`. Sole .54 mutation owner.
Product `backup-engine` remains byte-for-byte unchanged from base (the previously
accepted product base is `3fe2ff3`). No public import guard changes.

## Result and root cause

The original registration failed because Tailscale pauses its control client when
`interfaceState.AnyInterfaceUp()` is false. Network-none has loopback connectivity
but no active non-loopback interface. The proven dev-d runner instead creates an
internal network, with a normal interface. Its userspace daemon, CA trust and
preauth registration pattern otherwise apply. We retained the baseline failure,
then changed exactly one variable in the same running synthetic server/client
fixture: the official `TS_ASSUME_NETWORK_UP_FOR_TEST=true` daemon setting.
Registration immediately succeeded without changing TLS trust, preauth key,
server, client version, namespace, capabilities, routes or product gate.

Pinned Tailscale 1.104.7, revision
`cbc74fe48ef1b1649f69a4d9a602319427e25102`, contains that condition in
[ipn/ipnlocal/local.go](https://github.com/tailscale/tailscale/blob/cbc74fe48ef1b1649f69a4d9a602319427e25102/ipn/ipnlocal/local.go#L1157)
and exposes the development setting in
[envknob/envknob.go](https://github.com/tailscale/tailscale/blob/cbc74fe48ef1b1649f69a4d9a602319427e25102/envknob/envknob.go#L429).
Headscale 0.29.4 source revision `8106636c7f8d0cf8c9d4fb0beae94415069b768b`
requires capability >=113 (v1.80); actual successful registration establishes this
client/server pairing. See `primary-source-contract.json` for exact sources/hashes.

The initial broad keyword diagnosis was misleading: failed public DERP bootstrap
attempts produce network-unreachable messages, while the control client is paused.
The fixed-vocabulary diagnostics do not establish an auth, TLS or socket-mark
failure. Public destinations remained unreachable within network-none. No external
runtime connectivity was added to resolve this failure. The successful retry also
contains background x509 text; it does not invalidate the actual successful local
control registration. No raw log lines/state were exported.

## Exact commands and results

Run from `/tmp/ha-arm54-vpn-20261122`, using the user-supplied askpass script and
strict existing known-host file. Credential values are deliberately omitted here.
Every remote run stores the exact executed source in `<output>.source.txt`, its
structured stdout in `<output>.json`, and SSH exit in `<output>.exit.json`.

| Command | Exit | Actual assertion |
| --- | --- | --- |
| `python3 tests/e2e/lab/arm54_vpn_control.py init` | 0 | Unique 0700 private /var/tmp workspace; default baseline |
| `python3 tests/e2e/lab/arm54_vpn_control.py upload` | 0 | SHA256-verified synthetic product/harness source transfer |
| `python3 tests/e2e/lab/arm54_vpn_control.py run --script arm54_build_native.py --output private-image-setup` | 0 | Fresh isolated official recipe native build and truthful version gate |
| `python3 tests/e2e/lab/arm54_vpn_control.py run --script arm54_vpn_probe_native.py --output registration-baseline` | 1 | Reproduced client up exit 1, no registration |
| `python3 tests/e2e/lab/arm54_vpn_control.py run --script arm54_vpn_diagnose_native.py --output bounded-diagnosis` | 0 | Bounded fixed error predicates |
| `python3 tests/e2e/lab/arm54_vpn_control.py run --script arm54_vpn_diagnose_native.py --output dial-diagnosis` | 0 | Background public 443 dial failures, no local key exchange |
| `python3 tests/e2e/lab/arm54_vpn_control.py run --script arm54_vpn_diagnose_native.py --output endpoint-diagnosis` | 0 | Public DERP bootstrap endpoints distinguished from local control |
| `python3 tests/e2e/lab/arm54_vpn_control.py run --script arm54_vpn_retry_native.py --output single-variable-network-up` | 0 | Same fixture, one env change, client up 0 / Running |
| `python3 tests/e2e/lab/arm54_vpn_control.py run --script arm54_vpn_restore_native.py --output registered-converter-restore` | 0 | Continued existing registered fixture through actual product conversion, import, restart and reconnect |
| `python3 tests/e2e/lab/arm54_vpn_control.py run --script arm54_vpn_audit_native.py --output restored-control-audit` | 0 | Fresh restored daemon fetched local control key; RegisterReq, machineAuthorized=true, netmap; no authkey file |
| `python3 tests/e2e/lab/arm54_vpn_control.py run --script arm54_cleanup.py --output final-cleanup` | 0 | Empty private store, workspace removed, defaults unchanged |
| Targeted Python AST parse of 7 harness files / JSON parse of 21 then-existing evidence files | 0 | Recorded in targeted-local-validation.json |
| `git diff --check` | 0 | No whitespace errors |

The full combined service harness received only the two-line test-env fix. It was
not rerun as a whole: the exact continuation source proves the required chain from
the already registered fixture. No repeat archive roundtrip, TempObjects broad
lifecycle tests or 74-test suite was used to inflate acceptance.

## Actual service assertions

Source and restored client both reached Running with ID `1`, IPv4 `100.64.0.1`,
IPv6 `fd7a:115c:a1e0::1`. The existing client state was reused after restart with
no new up command, no authkey file, and no new preauth key. Independent bounded
restored-daemon predicates prove a new local control exchange, authorization and
netmap instead of relying only on a client status snapshot.

Unmodified internal converter accepted a synthetic HA cold backup containing the
registered source DB/Noise identity: SHA256
`13e96cd4982dd7b51bbbd589028525f4ab44ed2a55934771143eff7db77cdccb`.
Converter output contained 1 user / 1 node, was imported into a distinct private
volume, and started with target configuration. Source user replaced target-only
user; source Noise identity, target config hash and target Headplane marker were
asserted preserved. Rootful namespace adapter is the already reviewed narrow
actual-host-map/stat adapter, not a product modification.

## Exact image provenance and isolation

Woow package commit `0afdfa464a5ae55c85145c242f5b38ac88eea969`, unchanged recipe
SHA256 `02f850bfe625cec627d8da94c3b61bd802990b75b0fd55d6ef164c8c2b7f403d`.
Native local build, not a shipped Woow image:
`ee8b71d1321a95fcdf1de41a2b87d44af594e4bbdc4f052912921cae77495950`.
Recipe inputs are pinned Headscale and Debian manifests recorded in the setup
source/result and previous service evidence. No fabricated labels or gate bypass.
Public ARM client image:
`docker.io/tailscale/tailscale@sha256:8934bed5f68e80c5f9c881f62c65909223ee660432946c10ad212d958fc2c2bb`.

All test mutations used separate vfs --root/--runroot under
`/var/tmp/woow-arm54-ha-20261122-w7y2tbr0`; runtime network none, no published
ports. Public image fetches occurred during preparation only. Minimum sampled free
space 17,504,976,896 bytes (16.3028 GiB); final 18,531,127,296 bytes.
The initial probe deliberately retained its fixture for diagnosis: its empty
`cleanup_left` is not a claim that the workspace had been removed. Final cleanup
is the authoritative removal proof: private containers/volumes/images empty,
no remaining mounts, workspace absent. Default images/volumes/networks/container
inventory matched baseline, all three originals still running with pre-probe
StartedAt values. No original image, volume, secret or runtime was used.

## Limits

This proves synthetic ARM internal-converter restore and actual control-plane
registration/reconnection. It does not prove two-client VPN traffic/DERP ping,
real originals, public import/installer/rollback, reboot persistence, packet loss,
long-duration behavior or other app services. No production credentials, Hermes
review or external-runtime exceptions were used. Private generated keys, state,
logs, CA/server keys and synthetic archives were deleted with the workspace.
