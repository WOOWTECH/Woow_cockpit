# CLEANUP-LC handoff (2026-11-26)

Base: `parity-int/combined-20261125` at `e6ee5048`. Local branch:
`parity/cleanup-lc-20261126` in `/tmp/parity-cleanup-lc-20261126`.

`LC-01` through `LC-16` were candidate-only refusals. The registered importer is
`ha_litellm`; its fixed, restricted salt reader now lives in that module. The
candidate module, its two candidate test modules, three candidate lab scripts,
and the two tests that imported those scripts were removed. The registry delivery
is `ha_parity_rows.json` in this directory; merge it through
`tests/backup/test_ha_parity_rows.py --merge` on the integration branch.

## Checks on this branch

- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:. nice -n 15 ionice -c 3 python3 -m unittest tests.backup.test_ha_litellm tests.backup.test_ha_registry tests.backup.test_litellm_mutation_tool -q` — 138 tests, OK. The test process printed ignored `tarfile._Stream.__del__` finalizer warnings about a closed fake output file.
- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:. nice -n 15 ionice -c 3 python3 -m unittest tests.backup.test_ha_parity_rows -q` — 9 tests, OK.
- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:. nice -n 15 ionice -c 3 python3 scripts/check_source.py` — passed, 47 engine sources.
- In-memory merge of this snippet with the registry, then `test_ha_parity_rows.problems` — 16 LC rows, 0 problems. The shared registry was not edited in this branch.
- `flock -n /tmp/woowbk-host-heavy-tests.lock env HEAVY_WAIT=0 P/team/heavy.sh env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:. nice -n 15 ionice -c 3 python3 tests/backup/litellm_product_mutations.py --only M14` (with `P` expanded to its scratchpad path) — baseline 198 tests passed; salt binding guard mutation caught; four controls unnoticed; PASS.

The full `tests/backup --b1` suite was not started: host load was about 9–12 on
four CPUs during this run. No Podman, systemctl, deployment, or production action
was run.

## REAL-lane follow-up

The old `tests/e2e/lab/litellm_real_ha.py` harness (outside this lane's file list)
still imports the retired candidate module. Its offline test currently errors at
import. The REAL lane should either move that historical harness to the product
API or retire the harness and its test. The active product flow driver is
`tests/e2e/lab/litellm_full_flow.py`; no lab or live database run was attempted here.
