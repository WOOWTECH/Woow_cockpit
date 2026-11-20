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

## Product-chain development and cleanup correction

The first product-chain attempt reached two client registrations and ten DERP
pongs but failed before conversion: the test adapter's root-owned stdout pipe
could not be opened by appowner's Podman volume export. That attempt used the
old cleanup implementation and left its two clients and private network
running. They were explicitly removed and verified absent. The adapter now
captures output in an appowner-owned temporary file; cleanup now checks each
test object after removal and fails if anything remains or cannot be checked.

A second attempt, with checked cleanup, reached the product `Target` parser
but was rejected because the synthetic Quadlet used an absolute bind source;
the fixture now uses the supported `%h/config` form. That run verified cleanup
and did not reach conversion. The extended conversion, API key and original
client reconnection checks remain unverified pending a further run.

While another synthetic EMQX job is active, the runners do not start: each
Headscale container is capped at 384 MiB, each client at 192 MiB, the route
probe at 64 MiB, and the product configtest container at 768 MiB. The host
wrapper requires at least 2 GiB of dev-d cgroup headroom and refuses concurrent
synthetic EMQX containers. No existing service is stopped to obtain memory.

## Product-chain attempt 3 (2026-11-20)

Real product conversion succeeded: two nodes, source API key removed and one target
API key retained; Noise key bytes matched. Both original real clients reconnected
with identical node ID, public key and IP addresses. Post-conversion ping failed
the strict check: two timeouts followed by eight successful DERP pongs. This run
is FAILED, not complete acceptance. API authorization checks were not reached.
The next harness revision measures bounded reconnection convergence separately
from ten consecutive successful relay pings; it does not claim zero downtime.

## Product-chain attempt 4 (2026-11-20, exit 0)

Executed `bash tests/e2e/lab/headscale-product-test.sh` in the isolated dev-d.
Headscale image ID: `a5f7b9715dea9116f435ff7892e6925895d1c92d4a265cc02eff1a2abadb227d`.
Tailscale image ID: `62dc2e673073db15c940b08320bc15303dce144ccb4fdf40b88a3c09dbbf027f`.
The outer device remained running with network none and ports {}. The new internal
network had no default route; the external probe returned Network unreachable.

The synthetic HA tar passed the real `habackup.open_backup` and
`ha_headscale.convert` path, including live target-volume export and real
Headscale configtest. Two source nodes and Noise identity were retained; one
source API key was removed and one target API key retained. A fresh target
started from the actual converted volume tar. Both existing clients reconnected
without a new registration grant and retained ID, public key and IP addresses.
DERP convergence took two attempts / 6 seconds, followed by ten consecutive
successful relay pongs. The real API accepted the target key (HTTP 200) and
rejected the source key (HTTP 401). Cleanup independently checked absence of
all four test containers, four named volumes and the internal network.
Synthetic private files remain under `/tmp/headscale-internal.JwQv9eFA` (0700).

Limits: synthetic HA-shaped backup, fixture workload/catalog and transport
adapter, real product conversion and real services/clients. Not a real customer
backup, product installer/automatic rollback, original service recovery,
Headplane UI acceptance, or zero-downtime proof. Public import guards unchanged.

## Later harness changes: not yet lab verified

The original successful attempt explicitly ran `tailscale down` and `up`, so
it proves identity-preserving manual reconnection, not automatic recovery.
The candidate harness now reuses the stopped source's internal address for the
converted server and, before any manual action, checks both original processes,
matching node identities and IPs, two online nodes and one DERP pong. It records
bounded convergence separately; a failure remains a failure even if the later
manual recovery passes. This new check has not yet run in dev-d.

The credential event controller now gives the runner a bounded TERM cleanup
window on timeout or protocol failure while discarding output. It reports
cleanup as unverified on failure, including after forced termination; process
exit is not proof that detached resources are gone. Local tests exercise real
Bash EXIT traps on timeout and invalid events. The four synthetic API/preauth
producers are checked, and five submitted container log snapshots are scanned;
the snapshots may be empty and this is not a global secret-coverage claim.

## Private-source candidate: local tests only

The pending harness registers the synthetic CA and TLS PEM private keys;
the initial source, initial target and converted target Noise and DERP private
keys; both clients' machine and node private keys before and after conversion;
and the four API/preauth keys. Each named source must be present and
acknowledged before evidence is released. The client's synthetic state is now
written to a per-client directory inside the retained 0700 fixture directory,
rather than `mem:`. Source and converted volume snapshots likewise remain
private test fixtures and intentionally contain test secrets; they are not
public evidence and are not treated as leak-free output.

The extractor requires explicit machine/node private-key fields and recognizes
specified textual private-key formats, including bounded nested base64 JSON;
unrecognized state formats fail closed. It scans registered text and one JSON
escaping layer in the withheld output and five submitted container log
snapshots, plus PEM body and line forms. It does not register hashes as
credentials. It does not establish coverage of binary or arbitrary encodings,
transient in-memory keys, every historical rotated identity, or keys generated
inside the product's disposable `configtest` volume. Empty submitted log
snapshots remain possible. These are synthetic fixtures; no real HA or existing
service is covered. The new extractor and persistence assumptions have only
local unit-test evidence, and await a scheduled dev-d run.
