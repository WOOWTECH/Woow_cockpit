# Omnigent cold PostgreSQL candidate evidence — 2026-11-20

Command: `python3 tests/e2e/lab/omnigent_ha_chain_pg.py --run`.
Final run: exit 0; `run-install.jsonl` is actual stdout with only stages/counts.
Image ID: `4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873`.
Product SHA256: `01e74f8e14fc1aaafe37abfb3fc896970af55b39f88f3457903b2d7170a58384`.
Harness SHA256: `7bb4195480f5402189642ce0dfc23b93d2a7dd13e2bda24f1dca20ee26ecbf8f`.

Real isolated PostgreSQL source was stopped and its actual named volume exported
into a synthetic HA add-on tar. Product member_pass, source-cluster startup,
analysis, exported target schema snapshot, restricted data restore, account
carry-over, schedule pause, volume assembly and tar checks executed. The output
PG tar was installed into a NEW volume and started: users=2, retained admin=1,
conversations=1, active tasks=0, restore loader roles=0. Restart retained both
users. Cookie/artifact data and target runner data were compared without printing
contents. All generated containers/volumes and TempObjects were verified absent.

Real snapshot statement-timeout and invalid-metadata injections both failed as
required, with capture files absent and pg_stat_activity snapshot holders=0.
Fixture regression additionally proves pre-existing capture/output files are
preserved and disk-copy failures remove only newly created partial output.

Earlier attempts failed at server_volume because real Podman export omitted the
root entry. Cleanup succeeded each time. The product now uses existing bounded
volume_root metadata, preserves exact uid/gid/mode, and refuses contradictory
metadata when an export does contain its root. A subsequent conversion-only run
passed before this final installation/restart run. A test authoring NameError
was fixed before the final seven snapshot tests passed; it was not product proof.

Limits: the outer HA envelope/catalog/target discovery are fixture boundaries;
_prepare is patched to a synthetic target. PostgreSQL schema is synthetic,
not the full Omnigent application schema. No original HA backup, real Omnigent
HTTP login/refresh, browser session, application startup, product installer or
automatic rollback acceptance is claimed. Public security guard remains. Test
runner data preservation does not include Pi-agent migration (excluded).
