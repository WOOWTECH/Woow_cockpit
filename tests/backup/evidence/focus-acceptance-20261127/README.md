# Focused real acceptance, 2026-11-27

## Later recovery correction: normal safety retention

The coordinator's actual `cde697b8` recovery-only run stopped after 9 passing
checks, exit1/9.2 seconds, before its scanner or catalog mutation. Its fixed
capture is `r8-attempt3-recovery-capture.json`. The assertion that all six older
test archives remained was false: two OLD OWN test safety backups had already
been removed by the product's normal three-safety-per-app retention during the
successful attempt3 baseline restores. The original baseline data had returned.

`r8-attempt3-older-safety-pruning.json` binds their creation receipts and exact
successful deletion messages in the retained restore-job captures. Four older
test archives and all six current-case archives are present: **10**, not 12.
The system journal did not provide these messages; the proof is from the actual
job logs. Missing manual, baseline or unknown archives remain a failure. No
archive is recreated, retention rule changed, or failed capture rewritten.

The corrected controller accounts only for known prior OWN safety archives with
an actual successful pruning event, and scans every sidecar actually present.
The historical exception is additionally bound to the exact two creation and
pruning file hashes. Thirty guarded offline boundaries passed after this
correction, including unknown/manual/baseline loss, failed deletion events and
changed proof files. Actual coordinator recovery02 then passed all 26 fixed
checks, exit0 in27.7 seconds. It scanned both actual JSON roots and every actual
archive index sidecar with zero registered-value hits, proved original markers,
units, images, timer and fixture, removed only the exact own catalog entry and
preserved the old guard, failed captures and current archive inventories.
`r8-attempt3-independent-recovery.json` binds a new immutable private receipt;
the actual replay validator accepts its accounting for 10 retained test archives.
Old cookie coverage remains absent, and the original R8 attempt remains
**57/60 FAIL**. A new real page proof is still required.

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

## R8 actual attempt1 failed; independent data recovery verified

`r8-attempt1.json` preserves **50/53 FAIL**, exit1 in706.8seconds, driver
`c79700cc`, frozen product source `1adf4df2`. The actual Cockpit page uploaded the
derived real fixture, selected three apps, excluded corrupt EMQX and imported
Hermes plus Omnigent with one general acknowledgement and one import click.
The four actual jobs succeeded in one systemd chain. Exact original data,
durable units and image configs returned through ordinary baseline recovery.

The browser harness incorrectly required a positive count of issue-specific
acknowledgement keys; this real check required zero. That assertion prevented
the old browser cookie scan. The later scanner also required an obsolete
aggregate index instead of the actual archive JSON sidecars. These are retained
failed checks, and **old cookie coverage remains absent**. Prepared observer and
browser-finally fixes have offline checks only; no replay has run.

Coordinator-reviewed recovery-only script `90eba761` then ran under globalheavy
and the dev-d mutex: **exit0 in22.5seconds**, with all21 fixed checks passing.
`r8-recovery-only-capture.json` records the command result;
`r8-independent-recovery.json` records independent original marker/unit/image/
timer/catalog/fixture equality, no active job and unchanged failed evidence.
Only the recorded own catalog entry was removed, using its exact SHA.
All six old archives, the old HA upload and derived host copy remain. The scan
covered640 records, including11 actual archive index sidecars, with zero hits.
This proves data recovery and does not turn attempt1 into an acceptance pass.

Immutable private receipt:
`~/.woowbk-lab/evidence/focus-acceptance-ui-recovery/20261127T070216/receipt.json`,
SHA256 `2d38f989848830193133967002449dafee97c3816ce9d75a2f0b95e0c39a0824`.
Public receipt SHA256
`edb0fd01fe188080bb65a202a896d1d47a62c88988117d141bfdbc32e6868be0`.
The old guard was not overridden or rewritten. The mutex is released for the
coordinator's one R4 plain turn; R8 readiness and replay need separate review.

`r8-replay-preparation.json` records the later local-only readiness route and
ownership fixes: exact immutable recovery receipt validation, fresh original
state checks before guard replacement, six old archives protected as existing,
and retained HA deduplication with `ha_record_owned:false`. Python16/16 and
issue-key11/11 are offline checks; browser cookie capture/finally scan remains
unproven until an actual reviewed replay. Exact bounded command and recovery
are in the replay section of `snippets/focus-acceptance/r8-lease-proposal.md`.

### Attempt2 preconditions stopped; scoped followup prepared

`r8-attempt2.json` retains **13/15 FAIL**, driver `044264f8`, exit1/36.1seconds.
Fresh resource floors, installed frozen source/page, isolation, active services
and inactive schedule passed. The combined original-map comparison failed before
state arming. No browser/upload/import or new archive; the old guard and failed
receipt/summary are unchanged. Its new evidence has an exact old guard copy.

`r8-attempt2-precondition-facts.json` records the later read-only comparison:
all four maps equal, activejobs0. The failed sample was not saved, so its exact
initial cause is not retrospectively claimed. `r8-attempt2-scope-metadata.json`
binds all eight selected image names to their installed trusted Quadlets and
records the health timer's enabled state and nonpersistent probe target. Headscale
started/failed twice during the preflight window; its unrelated state was not
changed. `r8-image-scope-sampling.json` records35 bounded read-only samples:
all selected images equal, one health timer `active/running` versus recorded
`active/waiting`, no initial failed-sample reconstruction.

The prepared followup projects images only to all eight mandatory trusted
ContainerNames, saves raw fresh maps before assertions, and compares only that
health timer's two observed active phases as equal when enablement and target/
probe metadata remain exact. Every other unit/image gate remains strict.
Targeted Python22/22 passed; `r8-scope-preparation.json` is offline preparation.
Attempt3 requires parent review and has not run; old cookie coverage is still
absent and no commercial acceptance closure is claimed.

### Attempt3 actual result and strict scanner correction

`r8-attempt3.json` preserves **57/60 FAIL**, exit1/734.8seconds, exact leased
`f0f61598` driver and frozen product `1adf4df2`. Real browser completed,12
functional checks passed, one tick/click/import intent, expected/actual issue
keys0, no page errors; Hermes/Omnigent imported and EMQX excluded. Four jobs
succeeded in one systemd chain with safety backups and real moved-data proof.
Both original baseline restores and exact marker/unit/image/schedule/fixture/
isolation checks passed. Six new and six older archives plus the old HA remain;
own catalog entry retained because hygiene prevented cleanup. Dev-d was released
after verified baseline recovery; no automatic replay.

Cookie-finally and later device scanning failed before reports. The protected
browser result has issued_scan_counts:null; actual cookie values were memory
only, not retained in protected artifacts. No recovery scan can retroactively
prove them. `r8-attempt3-terminal-facts.json` records these limits and the exact
leased source preservation hashes; failed files remain unchanged.

`r8-attempt3-scan-diagnosis.json` proves the shared scanner walked the regular
required ha-imports.json/requests.json roots and raised NotADirectoryError.
The narrow correction reads file roots directly and walks directories strictly,
retaining every actual index sidecar. `r8-scanner-fix-preparation.json` records
26/26 guarded offline tests and rendered-program parity/import checks.
The full rendered device scanner is in `snippets/focus-acceptance/r8-scan-rendered.py`.
Actual post-fix runtime is still pending reviewed recovery-only execution;
`r8-attempt3-recovery-proposal.md` gives the bounded command and required evidence.
The next proof must preserve all12 archives/HA and leave old cookie absence
explicit, then obtain new real-page cookie proof in a separately reviewed run.

### Original preparation scope

The new `focus_acceptance_ui.py`, `focus_acceptance_ui_page.mjs` and
`focus_acceptance_ui_relay.py` are a single real Cockpit case. The original
proposal received a separate dev-d lease and review. Transport, resource
needs and recovery are in `snippets/focus-acceptance/r8-lease-proposal.md`.
`r8-preparation.json` remains offline preparation only; the later actual attempt
and independent recovery above are separate evidence.

The page uploads the derived real full HA fixture, checks three selected apps,
shows corrupt EMQX blocked, and imports the other two with one acknowledgement.
Current page semantics mean four import jobs plus an excluded EMQX result;
the old direct-API five-job assumption is not used. The fixed private relay is
host127.0.0.1:ephemeral -> labpodman exec stdio as devadmin -> device127.0.0.1:9090,
with opaque TLS/WebSocket bytes and no published port or device network change.

Offline targeted9/9 verifies defaults, fixed relay destination/user, original
fixture protection and the four-job boundary. These are not real acceptance.
Only the leased real page can prove Cockpit login, TLS/WebSocket transport,
one-confirmation results and the independent application/baseline checks.
