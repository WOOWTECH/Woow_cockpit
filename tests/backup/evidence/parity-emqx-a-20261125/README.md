# parity-emqx-a-20261125 (proposed place: tests/backup/evidence/parity-emqx-a-20261125/README.md)

Lane EMQX-A (EA-OWNER-1735), 37 rows of DESIGN K plus the 11 owner rows (E-16..E-20, E-75..E-79, E-82): HA's access settings come with the
import (D0-D5), what could hurt the customer is a line of the ONE confirmation (S1, S2), nothing of this device's authorization is preserved
(the three ACL modules are deleted). Branch parity/emqx-a-20261125 on 3db6988 (tip d5ddf6a, local only). Product file: backup-engine/woowbackup/ha_emqx.py
(ha_emqx_settings.py untouched; ha_emqx_acl_preservation.py, ha_emqx_acl_path_proof.py, ha_emqx_authorizers.py deleted); tests tests/backup/test_ha_emqx*.py
(19 modules, 305 tests). The ONE real use of a device: the H2 lab proof on woowbk-dev-d (H2-lab-proof.md and the five small files in h2/: the real engine,
a real EMQX 5.8.9, the real x86 HA backup, the package's own smoke.sh); no production service, registry or podman store of this host was touched.
commercial_acceptance: not-complete.

WHAT WAS REAL AND WHAT WAS SIMULATED. REAL (H2-lab-proof.md): on dev-d the tip d5ddf6a checked, converted and restored the real x86 cold HA backup of the add-on `woow-emqx` on a real
EMQX 5.8.9 (check 269-527 s, convert 406-454 s, restore 81-348 s depending on the host load, the restore's readback "核對一致", then rolled back to the baseline exactly), and the
package's own tests/smoke.sh was run before and after (the table is in H2-lab-proof.md). That run answered: the import leaves HA's own ACL file (path data/authz/acl.conf) as the file
source; HA's sources, their order, no_match and authenticator are what the restored broker shows; this device's bootstrap user stays attached and logs in; and the one thing it
found in the code (the job log named this device's own no-match rule as HA's, d5ddf6a). Every OTHER test is a unit test over generated transports: hab1fakes.World /
test_ha_emqx_candidate_flow.Transport answer the fixed `emqx eval` expressions, `emqx ctl` calls and podman commands. Real there: the code under test, haimport.Work,
haissues.Sink and the issue registry, the reader and the archive schema, tarfile, the confirmation keys. Simulated there: EMQX itself, podman, systemd, the device. So these are still
ASSUMPTIONS that the code checks afterwards (counts, identities, enable flags, no_match, bootstrap file) and stops on, not facts proven: `authentication = []` through
`conf load --replace` (S2, HA without authentication), the two-step removal of a built-in source HA does not have (the ACL rows must survive), the output of a partial import (E-67),
HA's add-on option `env_vars` (D0 4: not read). R4 on dev-d (REAL lane) proves them.

REPRODUCE. In a worktree of the tip: PYTHONPATH=backup-engine:tests/e2e/lab python3 -m unittest <the 19 tests.backup.test_ha_emqx* modules>; the rows
registry with the snippet merged (python3 tests/backup/test_ha_parity_rows.py --merge snippets/parity-emqx-a/ha_parity_rows.json, then the module's tests); the
full suite and the mutation sweep as scratchpad/parity-emqx-a/run_suite.sh and run_mut.sh (mutate.py: 38 mutants + 2 controls on ha_emqx.py, one per
protection or line: each S1/S2 line, the confirm key without names, D0 not applied, the no-match rule, the explicit empty list, the two-step removal, the
E-80 readback, the bootstrap attach, E-90 both ways, the waits, the export room, the ticker slack, the re-read, the node name, the override file, the
replaced-ACL rule, the TLS fingerprint, the receipt, the node choice, H3, H1, E-22, the jq/file regexes, E-02), both through heavy.sh. The lab proof:
scratchpad/parity-emqx-a/h2/run_h2.sh (a scratch driver around tests/e2e/lab/emqx_product_real_ha.py; steps in H2-lab-proof.md).

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
7. The real run (H2): the leak scan of the harness (every Dashboard token the probes were issued included) found no lab secret in the engine's records, logs, journal (104 MB)
   or the run's evidence (0 hits; the five evidence files of this folder were scanned too: 0 hits).

RESULTS
- tests.backup.test_ha_emqx*: 19 modules, 305 tests OK, 3 skipped (docs-quoting tests that wait for the docs snippets; with both patches applied: 59 tests of the three modules, 0 skipped).
  New since the first tip: tests.backup.test_ha_emqx_parity.ConversionLogTests (2, both fail on the old log line).
- neighbours on the first tip: test_ha_import test_ha_flows test_ha_cli test_ha_registry test_ha_issues test_ha_common test_ha_tempctr test_flows test_ha_b1_real test_ha_parity_rows:
  572 tests OK, 5 skipped (test_ha_chain is F2's, not in this base). The integrator's trial line (parity-int/trial-emqxa-20261125 @ d3c71bb): 46 modules 1654 tests OK, 1 skipped.
- rows registry with the snippet merged on a copy of 3db6988: tests.backup.test_ha_parity_rows 9 OK; EMQX-A: done 48.
- H2 lab proof on dev-d (real, tip d5ddf6a; same numbers on 3fd576d): smoke.sh unmodified after an import 14 passed 2 FAILED (A4, A10) exit 1, `--quick` 9/1 exit 1 => upgrade.sh would roll
  an upgrade back and its rollback check fails too; with the draft fix 11/0/2 exit 0 (`--quick` 8/0/1 exit 0); the fixed script without the marker gives exactly the lines of the
  unmodified one (16/0/1). Details, what was simulated (upgrade.sh itself was not run) and the files: H2-lab-proof.md, h2/.
- package smoke fix (Woow_podman_emqx, local branch fix/smoke-after-ha-import-20261125@5c748a6): tests/smoke-a4.sh 9 scenarios OK, tests/lint-repo.sh OK; lab-proven (above); not pushed.
- lab tests (tests/e2e/lab) that mention ha_emqx: 158 tests, failures 1, errors 17 on the tip (the old EMQX harness imports the deleted modules and pins decision C: FOR-REAL.txt).
- full tests/backup --b1 + top-level + ha118 and the mutation sweep on the final tip: NOT RUN in iteration 2 (the host is overloaded, main's 19:55 order: no heavy step above load 20;
  the first two queued runs for the tip 3fd576d were cancelled by the lane under main's 19:0x economy rule); the integrator's trial-line suite covers the tip it merges.
OPEN: D0 (4) add-on option env_vars; the R4 matrix rest (S2 empty authentication, the two-step removal, E-67 output, the ARM fixture); the lab harness (FOR-REAL.txt); the lane's
own suite and mutation sweep on the final tip. commercial_acceptance: not-complete.
