# R1 isolated lab recovery (2026-11-26)

All runs used `woowbk-dev-d`, an isolated lab container with `network=none` and no published ports. They used the real encrypted four-add-on x86 Home Assistant backup. Each script checked the lab baseline, removed its uploaded backup and temporary objects, restored changed application data where needed, and scanned records and the device journal for test secrets. These are lab results, not production acceptance.

| Scenario | Integrated source | Result | What was checked |
| --- | --- | --- | --- |
| One action, two selected apps | `e59d6a9d17` | 36/36 pass | Omnigent without a catalog entry was skipped; Hermes converted and restored; Omnigent remained unchanged; Hermes baseline was restored afterwards. |
| Cancel during Hermes conversion | `a3f490125d` | 30/30 pass | The running job stopped, live Hermes data and unselected Omnigent remained unchanged, and temporary objects were removed. |
| SIGKILL during Hermes conversion | `6686f069` | 31/31 pass | Recovery marked the job interrupted; both apps' original data remained unchanged; no staging folder, key file or temporary Podman object remained. |
| Restart dev-d during Hermes conversion | `6686f069` | 31/31 pass | The restarted device recovered the interrupted job, retained both apps' original data, and left no temporary objects or key file. |

Private, redacted summaries are in `scratchpad/parity-real/runs/` under the matching `r1-*20261126.json` names; detailed private evidence stays under `~/.woowbk-lab/evidence/`. The first scenario covers a missing app registration; it does not yet cover a corrupt member in a three-app chain. Memory peak was not measured. `commercial_acceptance`: `not-complete`.
