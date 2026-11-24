# Final acceptance delta — 2026-11-22

Audited main **c8471ed8bf1582ccea8d626da102cdd4b045da8f**, after integrations
0168078→36d13a9, 25d5cf2→7566d44, cd849408→fe30094. c8471ed changes only
progress metadata. No backup-engine file changed from 3fe2ff3 to this snapshot.
This is an independent **local artifact audit**, not commercial acceptance or a
service rerun. No remote access, .54 mutation, labs, Hermes review, or passed
suite replay occurred in this lane.

| Requested gap | Accepted evidence delta | Exact boundary / next minimal uncovered test | Blocker |
| --- | --- | --- | --- |
| Large backups / single member >8GiB | Real x86 age-X25519/zstd 8193MiB nonsparse member: generated, verified, extracted; source/extracted SHA equal. Missing/wrong keys rejected. Existing plain/gzip result retained. | Ciphertext is only **34,519,040 bytes**, not >8GiB. Next: bounded large encrypted **late corruption** and **mid-stream cancellation**, asserting refusal, child termination and payload/key cleanup. Incompressible >8GiB outer archive and ARM large service restore remain separate unproved claims. | Positive-run artifacts/ephemeral keys were deleted, so no independent payload rehash now. Negatives assigned to large-archive owner; outer-archive test needs sufficient storage/reserve. |
| Native ARM service / cleanup | Real native rootful Headscale: synthetic HA converter → private import → startup → gRPC CLI source-user assertion. Real containers/volumes underpin six TempObjects checks across **two** attempts. | RootfulRunner allows direct namespace reads/stat because rootful unshare failed; **not production OwnerRunner/rootless**. One removal return125 is injected before transport, followed by real residue detection/retry. Next: production OwnerRunner lifecycle with real internal-network cleanup and actual transport-error residue/retry if claiming those guarantees. | Production namespace/deployment coverage absent. VPN registration still fails; zero nodes in passed chain. No installer/rollback, Headplane UI/nonempty API-key behavior or real-original acceptance. Banach owns remaining ARM cleanup work; no repetition of six passed scenarios requested. |
| Cross-physical-device restore | Earlier x86→ARM→x86 synthetic archive roundtrip (8,396,860 payload bytes) remains recorded. New converter/service source and target are **on the same ARM host**. | Next: one authorized physical HA-source→independent ARM-target private service restore, verifying source identity/config semantics; after registration is fixed, verify VPN node identity/IP and reconnect. | Same-host synthetic service evidence does not close physical service migration. Registration root cause unresolved; public install/rollback untested. No remote work performed/authorized by this audit. |
| Final integrated version | 32/32 explicit local R2 methods, no skips/xfails; final log and 50 before/after source hashes verified. ARM 42 engine files match main. All three original evidence sets survive integration byte-for-byte. | R2 executes real Python/archive/crypto but service/PG/owner transports are simulated. Next real R2 gap: one reviewed cold-v3 EMQX source through private build/package with real broker/runtime, complete-stream checks at each consumer, and independent cleanup evidence. Retain public refusal guards. | No real-source/broker proof in R2. Final source equality is not remote-execution attestation or commercial acceptance; rootless/public deployment remains open. |

## Integrity and provenance corrections

`python3 tests/backup/audit_final_evidence.py` passes **33 offline consistency
checks** across **80 changed/new committed evidence files**, with **165 manifest
bindings: 164 match main; one explained historical mismatch**. Detailed paths,
SHA-256 values, exit statuses and original/integrated commit IDs are in
[integrity.json](integrity.json) and [source-bindings.json](source-bindings.json).

* Initial `arm54_build_native.py` SHA `e11d25537ef3063a7c1882ef9ac4bb99965bf52e7926fe9b2c916bfd14b4d40e`
  matches `native-package-build.source.txt` (failed attempt). Final source SHA
  `2fe64604bdddd1e76b0555c6fb649d356064eda9716940628b9cb3ff69ccee54`
  matches main. The original manifest must retain the initial hash. Final harness
  inventory is not proof that every final script ran. Successful service-converter
  snapshot **does** match final `arm54_service_native.py`; neither lifecycle
  snapshot equals the final combined six-case harness.
* Initial lifecycle exited1 after three successful checks with a fixture
  `ValueError`. Completion exited0, **copied those three checks** and executed
  cancellation, sweep, and injected removal-refusal/retry. Six checks passed
  across attempts; no clean six-case final-harness execution is asserted.
* Official package recipe was locally rebuilt on ARM; binary equals pinned
  upstream. This is **not a shipped image**. Rootful adapter reads actual namespace
  IDs; it does not simulate IDs, but bypasses production OwnerRunner transport.
* Encrypted manifest's four recorded source hashes all match main. Five omitted
  direct dependencies (`util`, `errors`, `paths`, two archive test helpers) now have
  a [retrospective sidecar](encrypted-dependency-sidecar.json): identical at recorded
  base, producer commit and main. These are repository hashes, not fabricated
  runtime measurements or a complete transitive/environment manifest.
* [Secret scan](secret-scan.json): **zero matches** for private-key, age secret,
  Tailscale/GitHub/Slack/AWS token, JWT, bearer, credential-URL and quoted credential
  patterns in the 80 committed evidence files. This does not prove absence of
  arbitrary encoded/unknown-format secrets. No private runtime key store was read.

Raw failed attempts are retained. Deleted archives/images/upload bundle cannot
be independently rehashed from these committed artifacts; recorded payload/image
hashes, disk samples and remote cleanup assertions are internally checked or
classified, not replayed. Historical `.34`/`.54` metadata is evidence only.

The adjacent progress-status diff fixes the stale ARM `next` task, separates
same-host converter success from physical service migration, and links this audit.
No product/public-guard changes are needed for these provenance corrections.

## Integration status — 2026-11-23

As of 2026-11-24 08:13 Asia/Taipei. Branch `integration/ha-import-batch1-20261123` (R-COCKPIT, local only; last merge `97c22c9`).
This is the integration record, not commercial acceptance: every lab result stays `not-complete`, and the final
real re-verification of the integrated version is a separate step that has not run on this tip.

Merged (all `--no-ff`, conflicts proven per file in `tests/e2e/lab/evidence/integration-20261123/README.md`):

| Lane | Branch @ tip | Merge commit | By |
| --- | --- | --- | --- |
| hasqlite fail-closed | `fix/hasqlite-netns-fail-closed-20261123` @ `10fe446` | `7790cf8` | integration-1 |
| large-archive | `test/large-archive-final-20261123` @ `e415fc4` | `a8b7a04` | integration-1 |
| odoo-n8n | `test/odoo-n8n-final-20261123` @ `e2515f8` | `1bd5dcc` | integration-1 |
| services-a | `test/services-a-final-20261123` @ `5ab3249` | `110b881` | integration-1 |
| R-EMQX real-backup line (EMQX real restores, emqx-gaps) | `emqx/real-backup-line-20261123 (= R-EMQX feat/ha-import-batch1)` @ `ab9e4da` | `90613fc` | integration-2 |
| odoo mail reminder (owner decision A) | `feat/odoo-import-mail-reminder-20261123` @ `ae5b0d4` | `7c87560` | integration-2 |
| services-b (LiteLLM real HA backup harness) | `test/services-b-final-20261123` @ `cde33c2` | `d812699` | integration-2 |
| hermes-real | `test/hermes-real-20261123` @ `e52ffd5` | `1072954` | integration-3 |
| services-a-2 (Headscale full product flow) | `test/services-a2-20261123` @ `1214226` | `315ec8b` | integration-3 |
| opendesign-import | `feat/ha-import-opendesign-20261123` @ `13c83f3` | `ae5420d` | integration-3 |
| codeserver-import | `feat/ha-import-code-server-20261123` @ `f20ac84` | `88e7e6b` | integration-3 |
| batch2-lab (dev-e code-server and Nextcloud records) | `lab/batch2-dev-e-20261123` @ `8de186d` | `fb284b8` | integration-3 |
| showcase-nc-share (+ showcase source-backup evidence) | `evidence/ha-b2-nc-share-20261123` @ `24a045e` | `3579716` | integration-3 |
| nextcloud-import (at its iteration-2 hand-off) | `feat/ha-import-nextcloud-20261123` @ `aaed6cf` | `17c81b8` | integration-3 |
| batch2-lab again (dev-e verify, wake/rotate, journal cleanup) | `lab/batch2-dev-e-20261123` @ `472705c` | `ce6d652` | integration-3 |
| emqx-secreview (EMQX import security review: SR-1/2/3/6/7 fixes, evidence, harness) | `sec/emqx-secreview-20261123` @ `cad50dd` | `f8e0c1d` | integration-3 |
| litellm-product (owner decision 1: LiteLLM product path; contains review/litellm-secreview-fix2-20261124@7844157, real run 69/69 on the final code) | `feat/ha-import-litellm-product-20261123` @ `033f2f7` | `d72ae5f` | integration-3 |
| litellm-product again (LiteLLM health checks 600 s, owner decision 2026-11-23 23:28; real attempt 10 on the same product code 73/73 in the lane) | `feat/ha-import-litellm-product-20261123` @ `a0475c5` | `ba637b7` | integration-3 |
| omnigent-product (owner decision 1: Omnigent product path; security review iterations 1+2, real runs 112/112 and 118/118 test mode) | `feat/ha-import-omnigent-product-20261123` @ `cd96340` | `97c22c9` | integration-3 |

Still open:

| Item | Why |
| --- | --- |
| emqx-product (owner decision 1: PRESERVATION_BLOCKER removed with the enforced protections) | not merged, so the public EMQX guard is still on in this branch; the lane has to take the second security review fix abff1a0 (SR-8/SR-9: the EnvironmentFile values no longer on a command line) and the Podman 6 fix 8613ffa, rerun its real dev-d chains on the merged engine and post READY; emqx-secreview iteration 3 (regression reruns, README) is running; its fixes up to cad50dd are already here through f8e0c1d; rehearsal of 5786ae4 + abff1a0 on 97c22c9: 2 text conflicts (both sides kept), 280/280 |
| nextcloud-import follow-up | merged at aaed6cf; since then share attempt 4 (02f5d40, importer hardening) passed 87/87 in the lane; the lane now fixes four self-review findings (HA .htaccess under the web root, two-factor key groups, unpinned superuser session, extra catalog checks) and runs share attempt 5; later commits get merged again |
| litellm-product later commits | merged at a0475c5; evidence of attempts 09/10 (10 = 73/73), the review README with KNOWN OPEN RISKS and an extra negative flow are in the lane (7a4a447, b3e587d) and get merged at its READY line |
| KNOWN OPEN RISK: LiteLLM SR-7 (deferred by the owner 2026-11-24 07:22, not closed) | os.environ/ references in HA model rows make this device's LiteLLM send its own secrets (its master key in the dev-d probe) to the host the row names; the import neither refuses nor warns; wip/litellm-sr7-prep-20261124 is NOT merged |
| KNOWN OPEN RISK: LiteLLM ssl_verify-type settings | a stored litellm_settings key without a branch ends in setattr(litellm, key, value) (vendor source only, not probed); e.g. ssl_verify false turns off TLS verification of outbound provider calls and the check shows nothing |
| Omnigent owner items | a real (not test-mode) move keeps HA's active schedules active on this device (the page reminds): pause them too?; optional hardening of the shared throwaway HA cluster (noexec /tmp, memory limit) not done |
| EMQX review scope | what HA's throwaway broker loads at boot was not reviewed one by one (human review); SR-5 (HA authenticator hash settings apply to this device's bootstrap users) not exercised |
| lab/batch2-dev-e-20261123 later commits | merged up to 472705c; later commits are merged again |
| arm54-2 (test/arm54-final-20261123) | by design not merged here: the main session squash-merges it at the end (its early commits contain a test password literal); it also carries product fixes (volume_root 868894f/a351cd2, podman path a7f32e9, tempctr 98410bd and c8df1f2, hasqlite/n8n libc unshare already here); its arm54_final_omnigent.py / arm54_final_owner_omnigent.py assert ha_omnigent.SECURITY_BLOCKER, which no longer exists since 97c22c9 (records of earlier runs) |
| final real re-verification of the integrated version | not run by the integration lanes after these merges (separate final step; dev-c stopped since 11-23 16:55) |
| release step | VERSION is still 2026.11.19.2 and scripts/check_source.py ENGINE_MODULES does not yet list the second-batch and LiteLLM importers (presence check only; check_source passes) |
| Hermes security review wording | 8b47124's message and tests/backup/evidence/hermes-fts-security-review-20261123 record an owner-authorized independent FTS5 review; the lane rules still list the human Hermes review as manual; main/owner to settle |
| incidents | two production incidents on 2026-11-23 caused by the test work (20:13/20:18 Headscale restarted twice by a backquoted command in a commit message; 21:35 LiteLLM killed for memory, back 21:41) and one kernel oops on the test machine 192.168.2.54 (21:02, rebooted 2026-11-24 07:23 on the owner's instruction); they belong in the PR text |
| commercial acceptance | owner; every lab result here stays not-complete |

Public guards on this branch: EMQX `PRESERVATION_BLOCKER` is on and changes only when that product lane is merged under
owner decision 1. The Omnigent `SECURITY_BLOCKER` hold was replaced by the enforced product path in `97c22c9`, and LiteLLM is
importable through the product module `ha_litellm` since `d72ae5f` (both owner decision 1; the LiteLLM lab candidate keeps its
`GUARD`).

Unit suites: integration-3: at ae5420d tests/backup 1471 (12 not-ok = test_ha_omnigent 7 SECURITY_BLOCKER + test_litellm_lab_runner 5 guard false positive, 6/6 with --exe-only), backup-ui 100/100, lab 1090 started / 1043 ok (73 not-ok records = run_native refused + 2 stale persisted_values); at fb284b8: backup-ui 101/101, tests/backup 1488 = 1475 ok, 1 skipped, the same 12 not-ok ids, RealBackupTests 1/1, lab 1097 started / 1050 ok with the same 73 records; at 17c81b8 (nextcloud): affected modules 101/101, backup-ui 101/103 (timeout + 320 px overflow, both 2/2 alone); at f8e0c1d (batch2-lab again + EMQX security review): tests/backup 1525 = 1512 ok, 1 skipped, the same 12 not-ok ids, RealBackupTests 1/1, backup-ui 103/103, EMQX + import + flows modules 177/177, test_batch2_lab + test_dev_d_guard 43/43; at d72ae5f (litellm-product): tests/backup 1574 = 1561 ok, 1 skipped, the same 12 not-ok ids, RealBackupTests 1/1, backup-ui 105/105, 54 HA/LiteLLM modules 803 (only the 7 Omnigent), lab LiteLLM 20/20; at 97c22c9 (litellm 600 s + omnigent-product): tests/backup 1604 = 1598 ok, 1 skipped, 5 not-ok (only the litellm_lab_runner guard false positive, 6/6 with --exe-only; the 7 Omnigent SECURITY_BLOCKER not-ok are gone), RealBackupTests 1/1, backup-ui 105/105, 17 Omnigent/shared modules 317/317, lab Omnigent 31/31. Evidence: tests/e2e/lab/evidence/integration-20261123/unit-tests-step3.json, unit-tests-step3b.json, unit-tests-step3c.json, unit-tests-step3d.json, unit-tests-step3e.json, unit-tests-step3f.json.
