# Installer-phase client continuity — local candidate only

Latest slot result: [headscale-continuity-next/README.md](headscale-continuity-next/README.md).
The d11f9bb live run failed on unsupported Quadlet NetworkAlias. Corrected source
91758a2 passed 48 local tests, generator dry-run, then real installer/rollback/restart
client continuity in one gated retry. Independent cleanup verified; slot released.
The candidate description below is historical; see the linked live evidence.

Base: 5f5f762 (real installer evidence at source ad9ccb3). No lab execution of
this increment. Coordinator slot is required before the command below. Historical
installer acceptance does not establish acceptance of this new connected runtime.

The actual product harness previously stopped both clients before invoking the
installer, whose Quadlet had Network=none. It now stops and removes only the
converted synthetic server before the installer, releasing headscale.lab and its
internal IP. Both original client containers stay alive throughout installation,
automatic rollback and a separate restart. Client private-state registration and
log scanning occur after this exercise, once the clients stop. No new login,
auth key, down/up, or client restart is performed during installer observation.
Earlier conversion-phase manual reconnect remains part of the existing harness.

The installer still owns only fresh random hs-install-* volumes/unit/files.
The initial unrelated seed runs with Network=none. Before packaging, its Quadlet
file is updated to the run's existing hs-test-* internal network, headscale.lab
alias and validated original IPv4 address. Reload does not restart the seed;
real flows.run_restore subsequently stops/recreates the service. The candidate
and safety snapshots therefore carry the connected Quadlet. The second restore
still injects exactly one ExecStartPre failure and must raise flows.RolledBack.
No product engine, public guard, original service/volume, agent runtime/model or
workspace configuration changes are included. No production credentials read,
Hermes retry, image pull, lab command, or omnigent stop was performed.

For each installed/rolled_back/restarted phase, before the existing cold-export
verification adds another outage, the new observer requires:

- The exact suffix-derived network is internal and carries the synthetic label;
  the selected IPv4 is a usable address within that network. Installed runtime
  must have only that network, the selected IP, pinned image and no port bindings.
- Both clients retain container ID, StartedAt and PID, are running, have only the
  synthetic network and no port bindings. Process identity is rechecked after
  successful pings, too.
- Original pre-conversion Self ID, PublicKey and IPs match each live client;
  Headscale reports both corresponding node address sets online.
- A successful single DERP(lab) pong in each direction. Direct traffic, cached
  Running status, offline nodes or changed identities cannot satisfy acceptance.

Each observation shares one monotonic 60-second deadline across network inspect,
client/process/status checks, node listing, both pings and retry sleeps. Commands
have min(5 seconds, remaining budget) timeouts and 64 KiB output bounds. Transport
errors/malformed replies fail closed immediately; offline/status mismatch or
unsuccessful relay probes retry within the deadline. Constructor observations
share 30 seconds. Only fixed phase/status, attempt count and elapsed seconds are
printed; raw status, ping output, keys and transport errors are not printed.
Elapsed time is the observation window after restore/safety verification and
health readiness, NOT total installer outage or zero-downtime evidence. Outer
controller bounds, isolation/memory guards and cleanup remain in force.

## Local evidence

```bash
cd /home/woowtechopenclaw/work/headscale-isolated-derp
PYTHONPATH="$PWD/backup-engine" python3 -m unittest discover -s tests/e2e/lab -p 'test_headscale_*.py' -v
bash -n tests/e2e/lab/headscale-product-test.sh tests/e2e/lab/headscale-product-runner.sh
python3 -m py_compile tests/e2e/lab/headscale_install_rollback.py tests/e2e/lab/headscale_client_continuity.py
git diff --check
```

47 local tests pass, zero skipped: 11 new continuity fixtures, one new failure
propagation test, and 35 existing tests including phase-aware restore sequencing.
The new cases exercise both relay directions and all three phases, cached status
with offline server nodes, eventual reconnect, changed ID/key/IP, direct-only
traffic, client process replacement, transport failure, shared deadline exhaustion,
network/IP guards, symlink/oversized baseline rejection and shell lifecycle/staging.
These fixtures never execute Podman/systemd. Syntax/compile/whitespace checks pass.

## Exact command — NOT executed; coordinator slot required

```bash
cd /home/woowtechopenclaw/work/headscale-isolated-derp
bash tests/e2e/lab/headscale-product-test.sh --installer
```

Use a newly allocated exclusive dev-d slot, >=2 GiB free cgroup headroom, existing
pinned images/tools and outer network=none/no ports as required by the existing
wrapper. Allow the controller's 15-minute runtime plus cleanup grace. Before and
after inventories must independently confirm unchanged original services/volumes,
networks/secrets and absence of hs-install-* units/config/drop-ins/containers and
installer private directories. The wrapper's fresh random fixture namespace must
be used; do not reuse historical retained synthetic directories.

Expected new evidence: HEADSCALE_CLIENT_CONTINUITY=installed:PASS,
rolled_back:PASS and restarted:PASS, each with attempts/elapsed, together with
existing real restore, rollback, credential-controller and cleanup acceptance.
No local fixture result substitutes for those actual observations.

Remaining blockers: coordinator slot and actual Quadlet static-IP/alias handoff,
client reconnect/relay after restore and rollback, and independent cleanup checks
for the connected installer. Real customer backups, Headplane UI, other schemas
and failure modes, complete age-identity dynamic scanning and the rejected Hermes
review remain unverified/outside this candidate. Public activation stays guarded.
