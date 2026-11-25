# parity-emqx-a-20261125 (proposed place: tests/backup/evidence/parity-emqx-a-20261125/README.md)

Lane EMQX-A (EA-OWNER-1735), 37 rows of DESIGN K plus the 11 owner rows (E-16..E-20, E-75..E-79, E-82): HA's access settings come with the
import (D0-D5), what could hurt the customer is a line of the ONE confirmation (S1, S2), nothing of this device's authorization is preserved
(the three ACL modules are deleted). Branch parity/emqx-a-20261125 on 3db6988 (tip 7840a18, local only). Product file: backup-engine/woowbackup/ha_emqx.py
(ha_emqx_settings.py untouched; ha_emqx_acl_preservation.py, ha_emqx_acl_path_proof.py, ha_emqx_authorizers.py deleted); tests tests/backup/test_ha_emqx*.py
(19 modules, 303 tests). Nothing was deployed; no device, lab machine, registry, service or podman of this host was touched.
commercial_acceptance: not-complete.

WHAT WAS REAL AND WHAT WAS SIMULATED. Every test is a unit test over generated transports: hab1fakes.World / test_ha_emqx_candidate_flow.Transport
answer the fixed `emqx eval` expressions, `emqx ctl` calls and podman commands. Real: the code under test, haimport.Work, haissues.Sink and the
issue registry, the reader and the archive schema, tarfile, the confirmation keys. Simulated: EMQX itself (what `data import` does to the configuration
and the tables, what `conf load --replace` stores, what `data import` prints when it fails), podman, systemd, the device. So the order of the import and
the two-step removal of a built-in source (D0), the output of a partial import (E-67) and the file ACL that HA's import leaves are ASSUMPTIONS the
code checks afterwards (counts, identities, enable flags, no_match, bootstrap file) and stops on, not facts proven here: R4 on dev-d proves them.

REPRODUCE. In a worktree of the tip: PYTHONPATH=backup-engine:tests/e2e/lab python3 -m unittest <the 19 tests.backup.test_ha_emqx* modules>; the rows
registry with the snippet merged (python3 tests/backup/test_ha_parity_rows.py --merge snippets/parity-emqx-a/ha_parity_rows.json, then the module's tests); the
full suite and the mutation sweep as scratchpad/parity-emqx-a/run_suite.sh and run_mut.sh (mutate.py: 38 mutants + 2 controls on ha_emqx.py, one per
protection or line: each S1/S2 line, the confirm key without names, D0 not applied, the no-match rule, the explicit empty list, the two-step removal, the
E-80 readback, the bootstrap attach, E-90 both ways, the waits, the export room, the ticker slack, the re-read, the node name, the override file, the
replaced-ACL rule, the TLS fingerprint, the receipt, the node choice, H3, H1, E-22, the jq/file regexes, E-02), both through heavy.sh.

SECURITY REVIEW (DESIGN H-c; the owner reversed SR-2/3/5/6/7 on 2026-11-25). No finding that blocks; what changed and what stayed:
1. S1 (SR-3, SR-6, SR-7; E-76..E-79): HA's settings that read this device's files or environment (file:// secrets, jq rules) or receive client credentials
   (external authenticators, external authorization sources, ExHook) run as they are. The customer confirms them BY NAME in one line each; the names are read
   from the candidate's FINISHED configuration by the same functions in the check and in the conversion, the key covers every name (haissues.Names for long
   lists), one more name is another key (tested for file-secret, jq, external-authn, exhook, import-partial), a conversion without the key stops only this app
   (confirmation-required) before anything is packaged. A name is a root or a rule id, never a value (a test puts a secret into every kind and finds it nowhere).
   Residual, said in the sentence ("only import backups you trust"): a backup the customer trusts and confirms can still make this device's EMQX read its
   bootstrap file or environment after the restore. The candidate itself has no network, so nothing leaves during the check or the conversion.
2. D1 (SR-5; E-16..E-19): clear-text rows are named (user ids, first ten, count in the message) in a notice that says the clear text stays on this device and in
   every later backup. PLAIN_EXPR still answers counts and user ids only (never a password, hash or salt). The readback redacts every secret-named value (SR-4 unchanged).
3. D2/H3 (E-20): admin/public is restored; a confirmation line when the installed Quadlet publishes the Dashboard beyond the loopback (or an entrance or a tunnel
   container exists). A tunnel is told by file name, container name or image, never by a word in a comment (tested).
4. D3 (SR-2; E-75): HA's ACL file replaces this device's (notice, nothing written back); any OTHER file of the target snapshot (a certificate, a key) must still
   be byte-identical in the finished candidate (tested with a rewritten certificate). D5 (S2): HA without authentication is restored; the line says whether the MQTT
   ports are published beyond the loopback and always that a public address cannot be told from here.
5. Unchanged: the hostile-archive protections (the reader and Select, the export listing by EMQX's own erl_tar/hocon with the member and root allow-list B1-03,
   noexec/nosuid/nodev volumes, plugins pinned off, no cookie), the isolation of the throwaway brokers (network none, read-only root, labels, the job's watchdog),
   the row counts (E-83), the readback and the automatic rollback (now only for accounts, ACL rules and keys: E-90), values never on a command line (SR-8/9:
   the candidate gets `--env-file` paths under the owner's home only, no `..`).
6. Relaxed on purpose, each with its notice or log line: E-53 (what an EnvironmentFile holds is no longer judged: the comparison E-60 shows the effect), E-54 (an image
   certificate that cannot be read is not compared), E-56 (root may own the files), E-57 (the CPU count is only logged), E-64 (the 2 GiB cap: the room for the copy
   decides, SpaceGuard.check; 64 GiB is a sanity bound per table file), E-13 (retained messages may differ by up to 64 rows only when a ticker could not be paused,
   never an account, rule or key). New: H1 names only; the data volume gets one fixed file, woow-ha-import.json (no value).

RESULTS (counts; the heavy runs are queued, see the lane file)
- tests.backup.test_ha_emqx*: 19 modules, 303 tests OK, 3 skipped (docs-quoting tests that wait for the docs snippets; with both patches applied: 59 tests of the three modules, 0 skipped).
- neighbours on the tip: test_ha_import test_ha_flows test_ha_cli test_ha_registry test_ha_issues test_ha_common test_ha_tempctr test_flows test_ha_b1_real test_ha_parity_rows:
  572 tests OK, 5 skipped (test_ha_chain is F2's, not in this base).
- rows registry with the snippet merged on a copy of 3db6988: tests.backup.test_ha_parity_rows 9 OK; EMQX-A: done 48.
- lab tests (tests/e2e/lab) that mention ha_emqx: 158 tests, failures 1, errors 17 on the tip (the old EMQX harness imports the deleted modules and pins decision C: FOR-REAL.txt).
- package smoke fix (Woow_podman_emqx, branch fix/smoke-after-ha-import-20261125): tests/smoke-a4.sh 9 scenarios OK, tests/lint-repo.sh OK. DRAFT, not lab-proven.
OPEN: D0 (4) add-on option env_vars; H2 lab proof on dev-d; R4 matrix; the lab harness (FOR-REAL.txt). commercial_acceptance: not-complete.
