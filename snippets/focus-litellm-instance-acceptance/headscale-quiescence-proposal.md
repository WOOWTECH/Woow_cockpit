# Separate temporary pause and resume of the known failed lab unit

CODE ONLY. Requires a NEW exact lease and parent GO. Fullflow01 stays FAIL:
strict baseline refused before credentials/install/jobs. Its failed sample was
lost, so the historical specific cause remains unproved. Subsequent immutable
read-only diagnostic609b1487 found strict baseline equality, originals8 running,
jobs0, LL absent and source53 exact. This protocol addresses the independently
observed preexisting Headscale restart race without changing the LL comparison.

## Fixed scope and transaction

New standalone `focus_litellm_instance_acceptance_quiesce.py` targets only
`headscale.service` as appowner on isolated `woowbk-dev-d`. Only `systemctl
--user stop headscale.service` and `start headscale.service` can mutate device
state. No config/data/image writes, fix, reset-failed, catalog action, package
installation, service wildcard or other unit action. Host receipts are private
0600 and fsynced. Existing engine/source/image/case files remain unchanged.

Pause records the full initial inventory before any assertion. It requires
strict original baseline equality (plus exactly the adopted derived image/tag),
then loaded/generated headscale.service, activating/auto-restart, Result=exit-code,
MainPID=0, positive NRestarts and a nonzero normal exit status. SourcePath must
be the baseline Quadlet below; its SHA/mode/uid/gid must equal the original
baseline. FragmentPath must be that owner's exact generated headscale.service.
The generated fragment metadata/hash is captured too. A healthy/unknown state
or any unknown inventory/config difference refuses without stopping anything.

Before stop, persist the complete original unit state/failure tuple, Quadlet
and generated hashes, source59, baseline SHA and pending=pause. Re-read state
and both file hashes immediately before stop; any drift refuses. After stop,
retain the complete actual capture before asserting inactive/dead/MainPID=0,
same files and strict original eight-container inventory. No Headscale filter,
baseline reset, daemon-reload, unit edit or reset-failed. Release D mutex/slot
after the pause command; the separately leased unchanged LL flow then runs.

After LL terminal plus recovery (or its admission failure before installation),
resume requires no pending/running LL jobs and completed recovery if install
intent was set. Capture and require strict original inventory BEFORE restart.
Revalidate exact recorded source/generated file hashes and unit binding; persist
pending=resume and start intent before starting this one original unit. Within
45s require the same failure tuple and known activating/auto-restart/MainPID=0
condition with positive NRestarts. A lower counter after explicit stop/start
is recorded; the failure tuple must match. Original known failure is restored,
not repaired. No source/config/image/data changes are made by the controller.

If a stop/start reply is lost, keep the durable obligation. A fresh resume can
adopt the already returned exact failure condition without starting again.
It can start an inactive unit after a pending stop; it cannot replay an
uncertain prior start into another inactive unit. Foreign config, healthy or
unknown state, timeout or unresolved LL recovery leaves pending intent. No
automatic retry. Stop/start success is proven by observed state, not exit alone.

## Bindings and proposed exact lease

| Binding | Value |
| --- | --- |
| Case | `woowbk_focus_litellm_a2c39e761b04` |
| Product source | `59a1b0f95132ea51c899f590eea7e3b02c5dba43` |
| Baseline | `298e4a88feb3356979e4f5dab8a6155fa418e834ec44d887cf7cff79a7719c82` |
| SourcePath | `/home/appowner/.config/containers/systemd/headscale.container` |
| Quadlet SHA256 | `c6d93f47a70bc29395d68a1f4b699eb3bdadd8ddf37696ef47e87915f2df81b6` |
| Unit | `headscale.service` |
| Method | `known-failed-headscale-pause-resume-v1` |
| Journal | `/tmp/parity-focus-20261127/litellm-headscale-quiescence-a2.private.json` |

Proposed new `/tmp/parity-focus-20261127/lease-litellm-quiescence-dev-d.json`:
granted=true, case=litellm-instance-quiesce, device=woowbk-dev-d, exact NEW full
driver_commit, source_commit/name/unit/method/baseline_sha256/source_path/
source_sha256 above, phases=[pause,resume], journal_filename as above,
timezone-aware expiry within90min. No expiry edits delegated. Bounds must equal
the controller BOUNDS: reserve13GiB, metadata budget512MiB, host available1200MiB,
device headroom1900MiB, command45s, resume proof45s, metadata60s/transport80s,
outer300s. Each invocation requires >6min remaining, isolated device and clean
committed controller/product trees. Global2-heavy and existing D mutex/EMQX
priority gate apply separately to pause, flow/recover and resume. No seats are
held between commands; mutex acquisition is nonblocking.

```bash
env HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock HEAVY_WAIT=60 \
 /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
 timeout --signal=TERM --kill-after=30 300 python3 -B -I \
 /tmp/parity-focus-litellm-instance-acceptance-20261127/tests/e2e/lab/focus_litellm_instance_acceptance_quiesce.py \
 --execute --phase pause \
 --lease /tmp/parity-focus-20261127/lease-litellm-quiescence-dev-d.json \
 --receipt /tmp/parity-focus-20261127/litellm-instance-a2c39e761b04.private.json \
 --journal /tmp/parity-focus-20261127/litellm-headscale-quiescence-a2.private.json \
 --output /tmp/parity-focus-20261127/litellm-headscale-pause-01.json
```

Resume is the same separately admitted command with `--phase resume` and unique
`litellm-headscale-resume-01.json` output. Fresh recovery, if needed, uses the same
persisted journal and a new unique output under an unexpired reviewed lease.
Parent must separately grant the new LL flow/recover lease at this candidate
before fullflow02; fullflow01 and image01 FAILs remain immutable. LL flow still
uses its original21GiB admission/55min TERM+20min recovery bounds. This packet
has run no new native pause/resume/flow actions.

Two focused stateful gates pass without native/blocked/shim: durable intent
before commands and fresh-process lost stop/start adoption (no duplicate start),
and refusal of healthy/unknown/foreign config plus pending resume on config drift.
The separate absent-recovery regression passed at8699fc57; original80 is not rerun.
