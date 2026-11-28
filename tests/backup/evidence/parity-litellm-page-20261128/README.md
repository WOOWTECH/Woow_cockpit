# LiteLLM (whole instance, case b12) through dev-d's real Cockpit page (2026-11-28)

The leased LiteLLM whole-instance flow (`focus_litellm_instance_acceptance_run.py --execute --phase flow --via-page`,
driver `afbb90b6`, frozen product `ce8c4cfb`) imported the original encrypted HA LiteLLM backup through the real Cockpit
backup page on woowbk-dev-d: upload through the page, only LiteLLM selected, the check (importable, nothing stopped) and
its confirmation lines acknowledged once, one import click whose conversion and restore ran as two linked jobs in one
unit, then the rest of the flow unchanged: the instance verification after the import and after a restart, other
databases and role passwords kept, an injected failure rolled back automatically (the engine's own digest equal to the
safety), the whole-instance recovery to dev-d's own data (counts, schema, its own key 200, the HA test key refused, its
stored values decrypting with its own salt), secret scans incl. the Cockpit password. **92/92**, `phase_succeeded`,
`flow_verified`, `recovery_verified`, `complete` all true (02:30-02:52Z). Difference from the helper flow (68/68 on
11-27): the later-write witness runs before the page, so the outsider-preservation check proves only that the import
left the existing other databases, roles and passwords untouched.

The coordinator steps around it (runbook of `83ed6af2`/`afbb90b6`, leases from
`tests/e2e/lab/focus_litellm_instance_acceptance_leases.py`):
1. `focus_engine_patch.py`: dev-d's engine back to `ce8c4cfb` (files `ha_n8n.py`, `ha_nextcloud.py`; verified before
   and after; services and data unchanged).
2. A read-only capture of dev-d, then the differences against case b11 (`differences-before-adoption.json`): 40, all
   ids of same-named containers and secrets or volume creation times of the stacks restored by reviewed flows after
   b11 (hermes, omnigent - R1; woow-emqx - page-emqx; headscale/headplane - the Headscale page run); 0 refused (files,
   catalog, units, timers, images, running lists, new or vanished names would have been). Adopted by
   `--prepare --adopt-restored` (`prepare.json`: case `woowbk_focus_litellm_8e62a65bffe2`, baseline `94d0bfa6...`).
3. Headscale (restarting without a DERP map offline) paused under its quiescence lease (`headscale-pause.json`), the
   flow, then resumed (`headscale-resume.json`).
4. A read-only capture afterwards against the b12 receipt: 0 differences (`differences-after-run.json`).

dev-d's engine stays at `ce8c4cfb` (a restore-only lease can put the earlier one back). `flow-output.json` is the
controller's own output (92 named checks, no values). Private: `/tmp/parity-focus-20261127/` (receipts
`litellm-instance-8e62a65bffe2*.private.json`, logs `ll-b12-*.log`). `commercial_acceptance`: `not-complete`.
