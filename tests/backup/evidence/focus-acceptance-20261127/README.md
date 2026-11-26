# Focused real acceptance, 2026-11-27

The independent DESIGN G4 R3 D10 case passed **71/71** on real source
`5209c402b846ab00ae4453c5e4ca80447ed75030`, exit0 in314.6seconds.
`d10-attempt2.json` is the fixed-status capture; the failed first attempt remains
separately recorded below. Offline checks are harness verification only.
`commercial_acceptance` stays `not-complete`.

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

## Successful real run and final recovery

Both actual mount consumers were named by preflight; the unacknowledged request
started no job and changed neither consumer nor Desktop. The confirmed request
paused and restarted both consumers. Existing Desktop contents, modes and owners
were equal after replacement, its inode changed, both service invocation IDs
changed and both new mounts could read the retained baseline. This used the
original encrypted HA source, not a generated-only acceptance fixture.

Ordinary safety restore and the independent original-baseline verifier passed.
The scan covered registered credentials and moved HA values before rollback;
device records, journal and private evidence had zero hits. `d10-final-summary.json`
records numeric scan counts and confirms both public capture hashes match the
private stdout. Private attempt2 evidence remains under
`~/.woowbk-lab/evidence/focus-acceptance-d10/20261127T055945/`.

The authorized outer `deploy-batch2.sh e rotate:code-server` finished successfully.
`final-lab-state.json` confirms code-server and its health timer are inactive,
schedule is enabled/failed as originally found, zero running containers and case
units, the reviewed image rotated out, original encrypted baseline retained and
original fixture SHA unchanged. Network remains none with zero published ports.
Host disk at final verification was35265MiB free. The public inherited status
labels say12GiB/1GiB; this driver actually enforces13GiB disk reserve and1200MiB
host available RAM, plus1GiB device headroom. Image transfer separately used the
existing script's12GiB floor plus1GiB reserve and reached a minimum24726MiB free.

Guarded offline preparation check:10 tests,0 failures/errors/skips/blocks/shim
hits (`acceptance-d10-offline-06.log`). This includes the saved n8n driver's
offline default: that driver is prepared only, requires incoming instance source
and a separate dev-c lease, and was **not rerun**. Its historical34/34 remains a
different application-flow proof.

## First attempt and narrow harness repair

`d10-attempt1.json`: source `f2f58704`, exit1,143.7seconds,40/42 checks. Source
checking and encrypted conversion succeeded, but dev-e's installed Quadlet
generator rejected the newer `Entrypoint=` key, so neither temporary consumer
service existed. **No application restore started.** Cleanup retained the
converted copy/upload when stopping the nonexistent service failed.

The direct read-only generator check reproduced zero generated services from
two files. The harness now passes the same shell override through the supported
`PodmanArgs=--entrypoint=/bin/sh`; the real generator then produced both services
and systemd loaded them. `consumer-generator-proof.json` records this actual
version-specific check. The existing offline boundaries still check the pinned,
isolated shell invocation; no mocked generator result is acceptance evidence.

`attempt1-setup-recovery.json` records independent original baseline verification
and removal of only this attempt's unit files, converted archive and uploaded
copy, plus restoration of the schedule mask state. The failed attempt remains
published. Original fixtures and saved baselines were retained.

Prior service proofs stay applicable to their paths. Newest saved n8n34/34,
Nextcloud no-share36/36, Odoo substitute cold-preservation37/37, and LiteLLM80/80
are retained separately in the historical `scratchpad/parity-real/runs/`.
Hermes105/105, Headscale96/96, OpenDesign85/85, code-server87/87 and Omnigent's
derived-extra full flow are existing evidence, not reruns by this lane. R1's
current chain record remains70/72 with two stale separate-unit assumptions;
the independent same-unit memory check passed at29.3MiB. R1 is not blanket closed.
