Evidence of lane HERMES-HEADSCALE (HH-OWNER-1905), 2026-11-25. Unit level only: every container, systemctl, podman and device step is a double; the
SQLite child, the HA backup readers and the real lab backups of 2026-11-19 are real (in process). commercial_acceptance stays not-complete.
  neighbours-705.out          12 modules (import, cli, chain, links, common, registry, backup, tempctr, pg_stdin, sqlite, hermes, headscale): 705 OK, 11 skipped
                              (at the commit before 9dd7a9d; the later commits only add tests and one guard)
  lane-modules-203.out        test_ha_hermes + test_ha_headscale + test_ha_issues at 9aa9bf6: 203 OK, 11 skipped (10 need hasqlite.py.patch, 1 needs --b1)
  real-hermes-conversion.out  guard.py --b1: the real x86 lab Hermes add-on through TreeTar + the sandboxed checks + the databases written last, the tree
                              passes ha_odoo.check_volume_tar (RealHermesTests, 1 OK)
  registry-65.out             the 45 rows merged on a copy (tests/backup/test_ha_parity_rows.py --merge): test_ha_parity_rows + test_ha_issues 65 OK
  (guard.py --b1 tests.backup.test_ha_b1_real: 5 OK on the real lab backups, before and after the Headscale rewrite)
  hm_hh.py, muts_hh.py        the lane's hand mutants (28 Hermes, 42 Headscale, 2 controls; every mutant applies exactly once); results: see the hand-off
  build_rows.py, run_hh.sh    how the registry snippet and the heavy steps are made
No secret is in any of these files (the guard masks the HA key; the tests use made-up keys).
