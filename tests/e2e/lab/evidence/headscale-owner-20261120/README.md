# Headscale synthetic HA acceptance — 2026-11-20

Base commit: `ad94fda79e2d2861337609be480f388c2d380eb8`.
Worktree: `/home/woowtechopenclaw/work/headscale-isolated-derp`.
The commit containing this report records the tested harness and evidence.

## Result

`bash tests/e2e/lab/headscale-product-test.sh` exited **0** on the first
owner-only attempt. Full redacted output is in `attempt-1.txt`; no failed
commercial acceptance run is omitted. The SIGTERM timeout / SIGKILL warning
for synthetic client B is preserved verbatim. No product changes were needed.

- Real `habackup.open_backup` and `ha_headscale.convert`, real Headscale
  configtest, converted volume import and server startup passed.
- Two source nodes and source Noise key survived conversion; one source API
  key was removed and one target API key retained. Real API responses were
  target **200**, source **401**.
- Both existing client processes automatically reconnected before any manual
  down/up: **23 attempts, 55 seconds since source stop**, unchanged IDs,
  public keys and IP sets, two target nodes online and a successful DERP pong.
- Separate manual recovery passed; relay converged in 1 attempt / 1 second,
  followed by **10/10** DERP pongs. The pre-conversion check also had 10/10.
- All 16 named authorization/private-source events were acknowledged:
  CA/TLS, four API/preauth sources, source/initial-target/converted-target
  Noise and DERP keys, and both clients' machine/node identity before/after.
  Five submitted log snapshots and redacted output passed the existing scan.

## Isolation, ownership and cleanup

All lab calls used `bash tests/e2e/lab/owner.sh d`. The new
`--verify-isolation` option only inspects dev-d through the existing isolated
lab transport; it does not use the host Podman store. The runner and converter
now run as appowner (UID 1019), without root/runuser or ownership changes.
The wrapper rejects competing synthetic EMQX, product job and Headscale
containers. Before starting, a read-only process-name scan also found no
other heavyweight harness process. The user granted the exclusive test slot.

Outer isolation was `true none {}` before and after. The nested network was
internal with no default route; the reserved external address was unreachable.
Memory before the test was 1,736,081,408 / 4,294,967,296 bytes, satisfying the
2 GiB free-headroom guard. No original service was stopped for capacity.

The runner verified removal of its four containers, four volumes and network.
Independent inventories match exactly: **8 original containers (same IDs),
54 volumes, 5 networks**. See `before-*.txt`, `after-*.txt` and `cleanup.txt`.
Original services remained running. This is object-preservation evidence,
not a claim of hashing original data (none was read).
Synthetic secret fixtures remain inside dev-d at
`/tmp/headscale-internal.cLKHZNGm`, mode **0700**, owned by appowner;
they are deliberately excluded from committed evidence.

Public import guards and product implementation are unchanged. No production
secrets, original volumes/data, conversation runner/model/workspace settings,
or Omnigent stop operations were used. Hermes independent review was neither
performed, reassigned nor bypassed.

## Exact local checks

- `python3 -m unittest discover -s tests/e2e/lab -p 'test_headscale*.py'`:
  **18 tests passed**, 19.284 seconds. These are supplemental protocol and
  predicate tests, not commercial acceptance.
- `bash -n tests/e2e/lab/owner.sh tests/e2e/lab/headscale-product-test.sh tests/e2e/lab/headscale-product-runner.sh`: exit 0.
- `git diff --check`: exit 0.

The real run used the image IDs recorded in `attempt-1.txt`. This proves the
bounded synthetic HA conversion scenario, not a customer backup, installer,
automatic rollback, Headplane UI, zero downtime, all secret encodings, or
private keys created inside the product configtest volume. Submitted log
snapshots can be empty. No mocks substitute for the real service results.

**Heavyweight dev-d TEST SLOT: released after independent cleanup verification.**
