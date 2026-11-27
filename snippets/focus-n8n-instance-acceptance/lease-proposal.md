# dev-c staged controller lease proposal — not granted

Actual controller code is now reviewable. No device phase has run. See
`controller-phases.md` for exact mutations, deterministic hook and recovery.
The preparer remains non-executing; the companion `*_run.py` requires --execute.

## Independent initial image phase

Proposed20minute lease includes `images` + `images-recover`, device dev-c only.
Source d09 is provided for binding but no installed helper match/deployment is
needed for this phase. Exact source/driver commit and case name are mandatory.
The inert JSON template also binds compressed SHA256/length and resource/time
bounds; changed bindings refuse before device access. Both
protected original backup archives AND actual per-ID JSON sidecars are pinned
from the fixed read-only capture (`protected-baselines-readonly.json`). This is
not the image cache: both saved compressed image archives are independently
verified too. Initially absent image IDs are recorded before
load; only owner-created missing n8n c8d7… and matching runner28c5… may be loaded
from `~/.woowbk-lab/evidence/parity-space-20261126/dev-c-images/<id>.tar.gz`.
PG4278… and Valkey650f… stay. No service/PG/database/catalog mutation or pulls.
Image recovery is included and removes only proven owned images with no-prune.
Each load rechecks the full returned config ID through `--format '{{.ID}}'`.

Concrete command, run from the committed controller worktree after parent grant:

```sh
HEAVY_FREE=/tmp/woowbk-dev-c-mutation.lock HEAVY_WAIT=600 /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/services_a_capture.py --private=/tmp/parity-focus-20261127/n8n-images-attempt1.private.log /tmp/parity-focus-20261127/n8n-images-attempt1.json n8n-instance-images -- python3 -B -I tests/e2e/lab/focus_n8n_instance_acceptance_run.py --execute --phase images --lease /tmp/parity-focus-20261127/lease-n8n-instance-images-dev-c.json --source /tmp/parity-focus-final-gate2-20261127 --receipt /home/woowtechopenclaw/.woowbk-lab/run/focus_n8n_instance_acceptance.json
```

The recovery command uses the same flags with `--phase images-recover` and fresh
exclusive capture paths. All commands acquire the existing nonblocking dev-c
mutation lock inside the controller, after the heavy slot.

## Fresh safety phase and full flow

Separate safety20minute lease: `safety` + `recover`, after final helper d09 is
already installed and all four exact images exist. Same case name and receipt;
no fixture yet. It captures a NEW encrypted whole-instance safety backup then
returns original catalog/service/timer state. This can be reviewed and run as a
separate phase while the full API case is reviewed. It does not restore the
historical single-DB backup or reuse it as whole-instance safety.

Use the same command structure with phase `safety`, a separate granted safety
lease, and `n8n-safety-attempt1` capture files. Full flow has its own <=40minute
lease, phases `flow` + `recover`; change only phase/lease/capture paths. Both
require exact frozen product SHA `d09f4fe8e06305aff6a1150f41d6de719e7b7f6a`, exact
reviewed driver commit, original catalog SHA
`3dfebaa0879d5622514276e2b834bff482f3db53618af0caaa46c5c660e968c4`, unique case name,
explicit image recovery policy, clean source and no competing job.

Host>=1200MiB available, >=13GiB reserve PLUS8GiB write budget; device>=1900MiB
reclaim-adjusted headroom. New forward work reserves600seconds for recovery;
job waits are bounded600seconds and total phase stops at lease expiry. No host
install/Podman, image pulls, helper deploy, egress or new listener. Keep original
Odoo/n8n baselines, other applications and their catalogs untouched. Retain all
recovery artifacts on an unresolved job or comparison failure.

## Lease JSON (explicitly inert example)

`images-lease.example.json` is a template, not approval. Parent must set granted,
exact driver SHA, unique name and actual future expiration; the controller
refuses this example unchanged. `source_commit` is already the exact d09 hash.
Two exact compressed image bindings and all enforced bounds are in the template.
A later phase lease lists only its reviewed phases and the same case/receipt.

No claim of actual original n8n instance acceptance follows from source,
preparation hashes or offline controller tests. Existing ordinary34 and native
Kuhn PG proofs are complementary and were not rerun here.
