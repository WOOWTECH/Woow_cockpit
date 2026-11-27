# Full-flow source reinstall: CODE ONLY, fresh lease required

Source2 actual install45.5s and separately captured return39.2s both passed.
`98e99421` records independent exact73-file/helper/attributes, source1 unchanged,
all10 durable groups equal, no jobs/containers, native/c locks released. Failed
source1 history remains immutable. Original service acceptance is still pending.

## Small executable change

`focus_n8n_instance_acceptance_reinstall.py` embeds the SAME Transaction2
implementation; a narrow subclass changes only paths and adds the immutable
source2 proof to its fingerprint before every inherited mutation. No publication,
CAS/recovery, native lock or private error logic is reimplemented. Old source2
journal SHA must stay
`0f98c76b312449fd99e9bbde0bd73c6194ae1dcaaa979e79c8ebfd9570863296`.
It validates all source1/source2 copies/candidate stages. No original source1 or
source2 path is written. Prior source2 install cannot be replayed by this lease.

New paths for the SAME retained image case `woowbk_focus_n8n_28a4a4b1cbcd`:

- Device journal/full prior copy: `<case>-source-fullflow` under the existing
  root0700 `/var/lib/woowtech-backup/focus-n8n-instance`.
- Staging: `/usr/local/lib/.focus-n8n-source-fullflow-<case>` and
  `/usr/local/libexec/.focus-n8n-source-fullflow-<case>`.
- New host receipt `~/.woowbk-lab/run/focus_n8n_instance_source_fullflow.json`.
- New exact lease case `n8n-instance-source-fullflow`; method remains proven
  `samefs-per-file-os.replace-journal-v3`. Phases source-fullflow-install and
  source-fullflow-recover; no automatic return/retry/fallback.

Source is still clean frozen clone2 d09f4fe8e06305aff6a1150f41d6de719e7b7f6a;
53-file manifest6f513ec909df950d10ea32ba6f919943052d7892130c96d26be77f17b7a82de8.
Selected hashes/imports and original catalog/app files/units/timer/volumes/images/
retention/four protected archive+sidecar files must match. No helper command,
service/PG/SQL, installer, key/catalog change, image load/pull/retag in this phase.

## Source-only disk budget:237MiB plus13GiB reserve

Actual frozen payload: library2,807,391bytes, helper2,278bytes, largest selected
file284,110bytes. `reinstall-source-budget.json` records every component. The
incremental allowance includes full prior64MiB maximum + prior helper1MiB,
candidate staging2,809,669bytes and maximum same-sized live growth, TWO64MiB
temporaries (one interrupted install plus its one explicit return), journal+
atomic writer16MiB, two private host receipts16MiB, fixed captures2MiB and4MiB
allocation/metadata allowance. Existing immutable proof trees do not grow.
Total rounded up:248,512,512bytes (237MiB), bounded at256MiB. No third attempt
or arbitrary payload fits this contract. Changed payload/budget refuses before
device access. Existing source1/source2 controllers retain their8GiB default.

13GiB reserve, host1200MiB and device1900MiB RAM floors are unchanged. Safety
and actual whole-instance flow keep the separate8GiB DATA allowance. Disk
boundary tests prove exact threshold passes, one byte below fails, prior8GiB
default remains, and both RAM thresholds stay enforced.

## Exact proposed install command

After parent grants a NEW20–25minute source-only install lease for the committed
driver (inert `reinstall-lease.example.json` is NOT authorization):

```sh
HEAVY_FREE=/tmp/woowbk-dev-c-mutation.lock HEAVY_WAIT=600 /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/services_a_capture.py --private=/tmp/parity-focus-20261127/n8n-reinstall-attempt1.private.log /tmp/parity-focus-20261127/n8n-reinstall-attempt1.json n8n-instance-reinstall -- python3 -B -I tests/e2e/lab/focus_n8n_instance_acceptance_reinstall.py --execute --phase source-fullflow-install --lease /tmp/parity-focus-20261127/lease-n8n-instance-reinstall-dev-c.json --source /tmp/parity-focus-final-gate2-20261127 --receipt /home/woowtechopenclaw/.woowbk-lab/run/focus_n8n_instance_source_fullflow.json --image-receipt /home/woowtechopenclaw/.woowbk-lab/run/focus_n8n_instance_acceptance.json
```

On verified PASS retain d09 and the NEW private original copy for separately
leased safety/flow. Preserve the full fixed private install response before
later receipt updates. Any failure stops without automatic recovery or retry.
Only an explicit fresh recovery grant may run source-fullflow-recover. Use same
arguments with new lease `lease-n8n-instance-reinstall-return-dev-c.json` and
exclusive `n8n-reinstall-return-attempt1.{json,private.log}` captures, after jobs
quiescent and all app services stopped. Require entire original73-file/helper/
directory attributes and source1/source2 proofs exact; keep all private copies.

## Targeted offline evidence

`n8n-reinstall-contract-gate-1.log`:4/4, and the resource refinement
`n8n-reinstall-disk-boundary-gate-1.log`:2/2 (one overlap;5 distinct methods).
Zero failures/errors/skips/blocked/shims, native denied. Uses real local per-file
install/return preserving the old proof tree, proof corruption before publish
and before return, exact new authorization/offline default, and resource edges.
Neither original34, old15-method FSM, native PG nor images were rerun.
