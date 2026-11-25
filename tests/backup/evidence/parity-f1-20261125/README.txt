EVIDENCE OF LANE F1-foundation (HAOS parity, 2026-11-25) -- code only, nothing was run on a device
=================================================================================================
繁中摘要：這是「HA 備份匯入做到和 HAOS 還原一樣」的地基（問題模型、每個應用各自隔離、ha-import-start、自動建立加密金鑰）。
只有單元測試、變異檢查和離線讀真實 HA 備份檔的探測；沒有在任何設備或容器上實跑，commercial_acceptance 仍是 not-complete。

Branch parity/f1-foundation-20261125. Base feat/ha-import-haos-parity-20261125 = e7d687b; the pg-stdin fix
fix/pg-stdin-verify-20261124@6aece91 is merged in 9b05278. Owner instances F1-OWNER-0600 and F1-OWNER-1005.
Source commit of the suites: 0f6e4d4208e3f47f0264d1665e69395f7581b0cd (the tip when they ran).
The mutation sweeps and the offline probes ran on 77b33c0; it differs from the source commit in nothing but two zh-TW constants of haimport.py (NO_KEY_CREATED, NO_DATABASE: the texts gained what the customer can do; no test reads the wording).
Commits after the source commit change only this evidence folder.

WHAT THE LANE DID (14 rows of DESIGN K; the registry is tests/backup/ha_parity_rows.json, checked by test_ha_parity_rows)
  done   HA-03 HA-04 HA-05 HA-06 HA-12 HA-13 X-CLI-03 KEY-16 FL-07 X-PF-03
  part   HA-14 (the only database that can move is chosen and names of 1..63 bytes are accepted; ha_odoo itself still refuses odd
         characters until lane ODOO does OD-31), CM-01 CM-02 CM-06 (the shared judgement haissues.version_issues and
         Work.image_version exist and are tested; each importer, and hacommon.VersionTable.issues (lane F3, snippet delivered), change
         over in their own lanes)
  HA-15  removed by the owner's decision (E-87 stays); no code change, the registry says so.
Product files: haissues.py (new), haimport.py, haapps.py, cli.py, errors.py (+ ha_odoo.py only through the pg-stdin merge), CONTRACT.md,
check_source.py. Hostile-archive protections, checks after conversion, throwaway-container isolation, the pre-restore backup and the
automatic rollback were not changed (the diff touches none of habackup, hasecuretar, archive, nested, tempctr, flows).

TESTS (unit level, fakes for Podman and the app modules -- say it as it is)
  tests/backup (guard.py --b1 through team/heavy.sh): tests=2053 failures=2 errors=3 skipped=1 blocked=6
    the not-ok tests are exactly the 5 known test_litellm_lab_runner guard refusals of the earlier runs: True
    run on a tree with ONE uncommitted file, tests/backup/test_ha_litellm.py + snippets/F1-foundation/test_ha_litellm.py.patch (a LiteLLM file;
    HA-12 turns "the check job fails for a corrupt member" into "that app stops"; without the patch exactly test_n14 is not ok)
  RealBackupTests (the real HA fixtures, no container): tests=1 failures=0 errors=0 skipped=0 blocked=0
  backup-ui (node tests/backup-ui.mjs): 108 pass (# tests 108 # pass 108 # fail 0) on 77b33c0 (not repeated on 0f6e4d4: the later commits change no page file)
  the same three steps on the commit before the last text change (77b33c0): tests=2053 failures=2 errors=3 skipped=1 blocked=6; ui # tests 108 # pass 108 # fail 0
  lab discover suite (tests/e2e/lab, the unit tests of the lab harnesses; clean tree): no result yet when this folder was written (the run waits behind other lanes for the host heavy lock; parity-f1.md of the team notes says where it ends up)
  F1 modules alone: test_ha_issues 48, test_ha_import 85, test_ha_cli 52, test_ha_registry 6, test_ha_common 9, test_ha_parity_rows 9,
    test_ha_pg_stdin 25 (all OK on the source commit)
  Trial merge F1 + READ + PKG (units only, throwaway tree; recipe in snippets/F1-foundation/INTEGRATION.txt): test_ha_parity_rows 9,
    test_ha_issues 48, test_ha_import 85, test_ha_cli 53, test_ha_registry 6, test_ha_omnigent 45, test_ha_backup 102 (1 skipped),
    test_ha_securetar 24, test_ha_store 16, test_storage 31, test_ha_litellm 89, test_ha_common 9: all OK
MUTATION CHECKS (a protection or rule is removed one place at a time in a copy; the lane's units must fail)
  this lane (f1_mutations.py in this folder, mutation-check.json): 205/205 caught, missed [], controls noticed []
  pg-stdin (tests/backup/pg_stdin_mutations.py, pg-stdin-mutation-check.json): mutation check: PASS (15/15 caught)
OFFLINE PROBES ON REAL HA BACKUPS (real_file_probes.py; no container, no device, no key; only counts and codes are printed)
  selection (real-selection.txt): what ha-import-start decides without a key and with a wrong one, for every real backup of the lab fixtures
  isolation (real-isolation.json): the check job on a real unencrypted backup with four add-ons; one add-on at a time damaged by one flipped
    byte: only that app stops (failure.corrupt-archive), the other three stay importable, no staging is left. The apps' own checks are
    replaced by a complete read of their add-on (every checksum), so this shows the job's isolation on real bytes, not the apps' checks.
  the same probes on the throwaway merge F1 + READ + PKG (READ's tolerant reader with F1's job): no result yet when this folder was written (queued behind other lanes for the host heavy lock)
NOT DONE / NOT PROVEN
  - No device, no real import, no real restore, no chain (lane F2), no page (lane PAGE). commercial_acceptance stays not-complete.
  - The unit tests use fakes (hafakes.py, hab1fakes.py, FakeHaAdapter); the real runs R1/R2 of DESIGN G4 come later.
  - CM-01/CM-02/CM-06 and HA-14 are only complete when the importers adopt them (lanes ODOO, F3, EMQX-A, HERMES-HEADSCALE, ...).
  - The WIP commit 9194218 of iteration 1 keeps its title (history is never rewritten); its content is reviewed here.
HOW TO REPEAT: in a clean detached worktree of the commit: PYTHONPATH=backup-engine:tests/e2e/lab python3 -m unittest <module>; the heavy
  steps (the suites, the sweeps) through the team's heavy.sh as the rules say; python3 -I f1_mutations.py --repo <worktree> --json out.json
  (copies the repository into a temporary folder for every mutation, touches nothing else); python3 -I real_file_probes.py <worktree>
  selection|isolation <path of the real backups or of one unencrypted backup>.
