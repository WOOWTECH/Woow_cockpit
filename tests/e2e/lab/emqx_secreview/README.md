# EMQX product import security review harness (2026-11-23)

Attack and regression scripts of the review in `tests/backup/evidence/emqx-product-security-review-20261123/`.
They drive the product's own code (`TempObjects`, `ha_emqx`) against the separate lab Podman store (`labpodman`,
its own `--root`); every `podman run` must carry `--network none` (the runner refuses anything else). Never run them
against `/usr/bin/podman`'s store or a device.

`SECREV_ROOT` must hold `<codebase>/backup-engine` trees (for example `final3` = `git archive <commit>
backup-engine` plus a product patch) and a `runs/` folder; run e.g. `SECREV_ROOT=/path python3 -I t2_plugin_exec.py
final3`. Credentials are generated per run; `t7_real_backup.py` reads the HA key in-process through the b1 harness's
`Secrets` reader and never prints it. Results are booleans, fixed product messages and digests of test data.
