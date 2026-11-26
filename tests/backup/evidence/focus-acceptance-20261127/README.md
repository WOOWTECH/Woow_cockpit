# Focused real acceptance, 2026-11-27

This lane's current work is the independent DESIGN G4 R3 D10 case. No new
acceptance result is claimed before a real run. Offline checks are harness
verification only. `commercial_acceptance` stays `not-complete`.

The original encrypted x86 HA code-server fixture is converted through the actual
installed helper. Two disposable Quadlet services using the exact installed
code-server image mount the already-existing Desktop and whole home. The restore
must refuse without the exact named confirmation, then stop/start both consumers
when confirmed. The existing Desktop files, modes and owners must remain equal;
the replaced directory must have a new inode and each consumer must see the
baseline through its new mount. A missed polling sample can use ordered systemd
journal stop/start events together with changed invocation IDs. No product
adapter is mocked or product archive metadata manufactured by the harness.

Run only under the coordinator's dev-e lease and global heavy guard:

```sh
HEAVY_FREE=/tmp/woowbk-dev-e-mutation.lock /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/focus_acceptance_d10.py --run
```

The script takes the existing device mutation lock itself. Prerequisites: clean
committed source, dev-e `network=none`/zero published ports, installed code-server
image config `7999790230ec6267ae55b82ab0e8d725add734658d15a8ec7a139a6d4087b0a1`,
active/healthy service after the independent original-baseline verifier passes,
at least 1GiB device headroom and 1200MiB host available memory, and 13GiB disk
reserve plus step writes. The main case has a 20 minute phase budget; cleanup
waits for its own job and restores the safety backup rather than racing it.

Before ordinary safety restore, both consumers are stopped and their own
Quadlets removed. The saved original baseline is independently verified again.
Only after that and the secret scan does the existing guarded cleanup remove
case-created converted/safety backups and its new uploaded copy. Uncertain
recovery retains copies and a private `recovery.json` containing job/backup IDs,
own unit names and original service/timer state. No saved baseline or fixture is
deleted. Private evidence: `~/.woowbk-lab/evidence/focus-acceptance-d10/`.

The outer image recovery phase records code-server and its health timer as
inactive before wake; schedule timer was enabled/failed. Those outer service
states must be restored after this case, since the D10 driver starts after wake.

Prior service proofs stay applicable to their paths. Newest saved n8n34/34,
Nextcloud no-share36/36, Odoo substitute cold-preservation37/37, and LiteLLM80/80
are retained separately in the historical `scratchpad/parity-real/runs/`.
Hermes105/105, Headscale96/96, OpenDesign85/85, code-server87/87 and Omnigent's
derived-extra full flow are existing evidence, not reruns by this lane. R1's
current chain record remains70/72 with two stale separate-unit assumptions;
the independent same-unit memory check passed at29.3MiB. R1 is not blanket closed.
