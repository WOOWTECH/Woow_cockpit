# EMQX R4, current HA access policy (2026-11-26)

These are isolated dev-d lab runs using the encrypted, real B1 HA EMQX backups. The product code is `d0cfef06`; subsequent integrated commits through `411b6ef3` change tests and evidence only. No production service was touched. Private full records remain under `~/.woowbk-lab/evidence/emqx-product/`.

| Run | Result | Private evidence | Scope |
| --- | --- | --- | --- |
| D0 check, ARM and x86 | 31/31 | `20261126T175917/` | Both backups importable. HA authentication and authorization replace this device's file ACL; no blocker. |
| x86 import, repeated on the corrected test tip | 56/56 | `20261126T183358/` | Check, conversion, actual restore, Dashboard and MQTT logins, HA ACL, retained messages, rules and action delivery, restart and state consistency. |
| x86 rollback and E-90 | 76/76 | `20261126T184421/` | An injected start failure rolled the second restore back. A one-shot change to `log.console.formatter` was detected as `設定（log）` and logged as a reminder; the restore succeeded under E-90. The post-restore probe found only the log configuration changed. Restoring the test's B0 returned the device's accounts, ACL, data markers and state digest to their pre-import values. |
| Cleanup and leak scan | 11/11 | `20261126T184922/` | Test-created converted and safety backups, B0, temporary objects and fault-injection files removed; no test secrets in engine records, logs, journal or evidence; dev-d isolation verified. |

The first x86 rollback attempt (`20261126T181737/`) reported 73/76 because its older R4 harness expected a settings-only mismatch to roll back. The job itself logged the E-90 reminder and finished as specified. The test correction is in `84948b62` and `411b6ef3`; the corrected real rerun is 76/76. An injected **administrator table** mismatch has unit coverage in `test_ha_emqx_product.py`, but was not injected into this real broker run. ARM was checked, not imported in this R4 run.

`commercial_acceptance`: `not-complete` until the ten-service real rerun and the remaining first-wave rows are closed.
