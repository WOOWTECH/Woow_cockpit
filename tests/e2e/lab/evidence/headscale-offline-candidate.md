# Headscale offline candidate and internal DERP test

Base: a4f182b. The dev-d outer container was running with `NetworkMode=none`
and empty port bindings. Its pre-offline 0.29.4 configuration remains in
`config.yaml.pre-offline-lab`; its DERP URL points to the public Tailscale map.
The current offline configuration removes that URL and has no local map.
The Headscale service repeatedly exits with `initial DERPMap is empty`.
No existing Headscale configuration or data was changed during this test.

The adjacent synthetic configuration was tested in a fresh, nested
`--network=none` container using the existing 0.29.4 image, with separate
synthetic config, data and socket directories. `configtest` passed. The server
started, reported its embedded DERP region 999 and a STUN listener on
127.0.0.1:3478, and `headscale health` returned successfully. The container
had no port bindings. This proves startup only: its advertised DERP endpoint
uses HTTP while the client expects TLS, so it does not prove usable relay.

A fresh Tailscale client using the locally available image, memory-only state,
and the candidate's network namespace timed out during registration and stayed
at `NeedsLogin`; the log showed its control client paused. An attempt to add
a dummy interface inside that namespace failed with `Operation not permitted`.
External bootstrap DNS requests failed with network unreachable. No external
network was opened. Neither successful client registration nor DERP relay nor
HA-to-Podman acceptance has been established.

The two temporary candidate containers were removed. The synthetic files remain
under `/tmp/headscale-derp-candidate` inside dev-d. The original lab service and
its backup were not replaced; the public import guards remain in place.

## Internal network and two real clients (2026-11-20)

Run `bash tests/e2e/lab/headscale-internal-test.sh` from the host. The wrapper
checks dev-d is running with network `none` and no published ports. Its runner
creates an independent Podman `--internal` network and first checks its
`Internal` flag, its IPv4 and IPv6 routes, absence of a default route, and
that a reserved external address has no route. In the recorded run the only
IPv4 route was `10.89.4.0/24 dev eth0`, IPv6 only `fe80::/64`, and the
connection attempt returned `Network unreachable`.

The runner creates an ephemeral CA and TLS certificate for `headscale.lab`, a
fresh database and a fresh 0.29.4 Headscale server with embedded DERP. It
mounts the generated CA only into two fresh userspace Tailscale 1.104.7 test
clients. Both registered over HTTPS and received `100.64.0.1` and
`100.64.0.2`. With `TS_DEBUG_ALWAYS_USE_DERP=true` on both clients, ten
Tailscale pings returned `via DERP(lab)`; the first took 134 ms. The test
completed with exit 0 and removed its three containers and internal network.
Generated test files were retained in `/tmp/headscale-internal.LuDBQWEm`.

This demonstrates local TLS, two real clients and relay under the isolated
test conditions. It does not demonstrate HA backup conversion, imported node
identity or the original Headscale service's recovery. The server, CA and
client state are synthetic; the test flag forces the relay path.
