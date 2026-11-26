# HH lane hand-off — 2026-11-26

Branch: `parity/hh-20261125`. Starting HEAD: `9da33013f98baa0ac435b447d70305eb58ce25af`. HH tests and evidence commit: `ff340b7e894a4a56aad169dd76ca5df4f3b369f3`.

The requested prior hand-off `team/parity-hh.md` and `scratchpad/parity-hh/runs/hh4-mut.json` were absent from this worktree and from the accessible `/tmp` and home paths, so this hand-off was created here. The four definitions used for the rerun are the checked-in S31, S33, S35, and S41 entries in `tests/backup/evidence/parity-f1-20261125/f1_mutations.py`. They mutate `woowbackup/haissues.py` exactly once each.

## Changes

- Added three tests in `tests/backup/test_ha_hermes.py`: a canceled check propagates out of the job (S31); an unexpected check error puts its detail in the journal while the result stays generic (S33); and an unknown add-on version plus a skipped link leaves only the link to confirm, then converts with that key (S35 and S41).
- No HH product edit was needed. All four mutants fail their assigned HH test. The isolated mutation report is `scratchpad/parity/snippets/parity-hh/hh4-targeted-mut.json`.
- Recorded the shared `test_suggest` conflict in `scratchpad/parity/snippets/parity-hh/test-suggest-handoff.md`. No shared test or `suggest.py` edit was made.

## Exact local results

All unit and mutation runs used `nice -n 15 ionice -c 3` and synthetic test inputs. No full suite, production, or device run was performed.

| Run | Result |
| --- | --- |
| Pre-edit `tests.backup.test_ha_hermes tests.backup.test_ha_headscale` | 162 tests, OK, 11 skipped, 180.705 s |
| Three new HH tests | 3 tests, OK, 1.107 s |
| Post-edit HH `CheckTests VersionTests LayoutTests` | 23 tests, OK, 2.055 s |
| Isolated copied-tree mutation baseline | 3 tests, OK, 3.5 s |
| S31, S33, S35, S41, each against its assigned HH test | 4/4 caught; each ran one test and failed in the expected test |
| Targeted `tests.backup.test_suggest` | 65 tests, one failure and one error, both in `ReferenceHostTests.test_the_default_drafts_are_the_entries_the_imports_fill`, 6.289 s |

The `test_suggest` assertion expects Hermes's `cold` variant to raise `BackupError`; HH H-03 intentionally accepts and carries a cold database volume. Its later `caught.exception` access causes the second error. The combined integration owner should reconcile the shared assertion and the still misleading `suggest._selected_variant` note for an installed cold Hermes entry. Hermes `instance` remains unsupported. The existing HH cold-entry conversion test passes.
