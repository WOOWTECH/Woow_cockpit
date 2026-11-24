# EMQX: HA backup → product import (lane emqx-product, 2026-11-23 / 2026-11-24)

Owner decisions 2026-11-23: 「決定1 做」 (the lab-proven EMQX import becomes the real product import the Cockpit page
drives; the public PRESERVATION_BLOCKER goes only in the same change that makes the product path enforce every
protection the lab proved) and 「C」 (EMQX 權限: on a device whose EMQX has no enabled 「內建資料庫」 authorization source, an HA
backup WITH ACL rows is REFUSED at check time with the owner's text; the import never adds or changes a source itself).

**Final code**: branch `feat/ha-import-emqx-product-20261124` (R-COCKPIT, local only, never pushed), product tip
`e08f8a1`, `backup-engine` tree `865c930f392006e0080de506eb7c425fd81becd7`. Everything after `e08f8a1` is evidence, lab harness or this README.
commercial_acceptance stays `not-complete` in every attempt JSON until the owner accepts.

| Commit | What |
|---|---|
| 3bb261d, 41ad5ef | merges of the security review iteration 1 (SR-1/2/3, SR-6/7) onto integration f3b3413 |
| 7449540 | the product change: guard removed; target preflight; decision C; readback (`import_check`) + comparison after the restore; SR-4 redaction; page fact; docs/CONTRACT |
| 7ce908c, 006e495, 7d9d468 | docs/backup.md + CONTRACT §9 (security refusals, 「內建資料庫」 after 「ACL 檔案」, the settings refusal names roots) |
| 16abc8a, 045b16f, 28fc390, e62b0a5, 56a6433, 1414320 | the real product-flow harness `tests/e2e/lab/emqx_product_real_ha.py` (+ capture wrapper, offline tests) |
| 28e9492 | product fix found by attempt-05: comparisons across a boot use the boot form on both sides |
| 3761d18 | product fix found by attempt-06: the candidate gets the Quadlet's `EnvironmentFile=` settings (rewritten by abff1a0) |
| fdb7cfe | product: the candidate refusal names the differing setting roots (attempt-07 could not say which) |
| 92f2461, be2c92d | product fix found by attempt-08 / 10: the candidate starts with this device's scheduler counts (ERL_AFLAGS) |
| be5bc6f | product fix: HA's throwaway broker covers both image VOLUME paths (no anonymous volume left per check/convert) |
| 0d260db | product fix found by attempt-11: a root loaded back into the candidate is compared in this device's boot form |
| 620bdd5 | merge of the security review iteration 2 fix `sec/emqx-secreview2-20261124@abff1a0` (SR-8: EnvironmentFile values never on a command line, podman reads the file; SR-9: lines read as podman reads them) |
| e08f8a1 | cherry-pick of 8613ffa (= c8df1f2): `tempctr` applies a volume tar's top-directory entry (Podman 6.1.1 ignores it) |

## What the product enforces (backup-engine/woowbackup/ha_emqx.py, haimport.py, flows.py, archive.py, tempctr.py)

| Protection | Where | Mutation ids |
|---|---|---|
| this device's broker is read first; it must run (NOT_RUNNING) | target_static, target_profile (check AND convert, before anything runs) | M07, M37 |
| authorization sources exactly [file] or [file, built_in_database] | source_profile | M05 |
| EMQX_ETC_DIR proven /opt/emqx/etc in target and candidate before `${EMQX_ETC_DIR}/acl.conf` is resolved | target_etc_dir, target_broker, disabled_intermediate | M01–M04, M06 |
| an unsupported target is the check's blocker (HA's facts stay) | check | M09 |
| **decision C**: [file] target + HA ACL rows → the owner's text as the check's blocker; the conversion stops right after HA's rows are counted, before any candidate; 0 rows → no refusal; a built-in source → import | acl_blocker, analyse, _build_candidate, convert | M08, M31–M35 |
| the finished candidate holds the profile read before the build | _build_candidate | M36 |
| readback recorded in the converted backup (`import_check`: config roots + administrator tables) | candidate_readback, convert, haimport | M10, M11 |
| the archive accepts only its own app's readback kind | archive.validate_import_check | M12 |
| a restore refuses an unknown readback before anything changes | flows._preflight, haimport.import_check_problem | M13, M20 |
| after the units started the restore compares the readback; a difference fails the restore → automatic rollback | flows.run_restore, verify_restored, compare_readback, wait_live_ready, table_receipts | M14–M19 |
| SR-4: secret-named values, `headers` values and URL user parts are redacted before hashing | redacted, config_roots | M38–M41 |
| SR-1: HA's broker pins plugins off (env) and mounts its volumes noexec,nosuid,nodev | ha_broker | M42, M45–M48 |
| SR-2: data-volume files of the target snapshot stay byte-identical | target_broker → check_snapshot_files | M43 |
| SR-3 / SR-6 / SR-7: file:// secrets, jq rules, non-built-in authenticators or ExHook refuse | target_broker | M44, M49, M50 |
| a runtime-changed device (Dashboard-added source) equals the candidate booted from its snapshot | boot_form, candidate_from_target, candidate_readback, verify_restored | M51–M54 |
| the candidate runs with the Quadlet's EnvironmentFile= settings, read by podman itself (`--env-file`); anything not exactly reproducible refuses; no value ever on a command line (SR-8, SR-9) | Target.candidate_env, target_broker, tempctr.run_argv | M55–M58, SRM1–SRM8 |
| the candidate starts with this device's scheduler counts (ERL_AFLAGS) and must answer them | schedulers, candidate_from_target, target_broker | M59–M62, M65 |
| HA's throwaway broker covers both image VOLUME paths with job volumes (noexec) | ha_broker | M63, M64 |
| a root loaded back must equal this device's boot form; after that every preserved root is compared | restore_target_settings | M66–M68 (M67 replaced M21's line) |
| a volume tar's top-directory entry is applied after `podman volume import` (Podman 6.1.1) | tempctr.volume_import, _apply_root | TC1–TC6 |
| kept from the lab line: ACL receipts, row counts, anonymous login, TLS, hot-backup hint, default admin, versions | check_counts, … | M22–M30 |

## Unit tests, mutation set, full suites (host, guarded runner: no podman/ssh/sudo/systemctl; unit results are not acceptance)

- Merged tree `e08f8a1` (engine 865c930f), guarded, through heavy.sh: EMQX modules (20) + harness + lab candidate 222 OK; shared suites (archive ×3, cli, flows, ha_cli, ha_flows, ha_import, ha_registry, tempctr) 438 OK; lab ACL component 6 OK; 0 blocked host calls.
- Mutation set, 81 protections (M01–M68 without M21, whose line became M67 in 0d260db; SRM1–8 = the review's SR-8/SR-9 set; TC1–6 = the tempctr top directory): 79 killed on e08f8a1. The two survivors were gaps of the TESTS, not of the code (M52: the fake `conf load` fills schema defaults since 0d260db; TC6: no test with a negative owner); two new unit tests (7e530cf) kill both → 81/81.
- Full `tests/backup` at e08f8a1 (heavy-tests lock): 1543 run; not ok only the 12 known ones (7 test_ha_omnigent: the old SECURITY_BLOCKER that the Omnigent product merge replaces; 5 test_litellm_lab_runner: guard false positives); RealBackupTests 1/1; `node tests/backup-ui.mjs` 100/100.
- Later, tests and harness only (engine unchanged): `fc0e3bc` 226 + 439 + 6 OK, 0 blocked. Integration tip bca3d65 + the health fix (`4ec3174`, engine 80215432): 228 + 488 (with test_suggest) + 6 OK, 0 blocked; the health fix alone: 7/7 mutations killed.
- Evidence: `unit-tests.json` (the 50-protection set at 7ce908c, full suites at 9036688) and `unit-tests-merged.json` (this engine).

## Coverage of the real chain

| Case | dev-d (x86 lab device, Podman 4.9.3, rootless, prod-like package) | ARM64 test machine (Debian 12, Podman 6.1.1; lane arm54-2) |
|---|---|---|
| ARM (real RPi5 HA) cold encrypted backup → [file, built_in_database]: check, real conversion, restore + product readback, client probes, service restart, client probes | **attempt-18 PASS 74/74** (engine 865c930f); earlier engine 5292c15d: attempt-12 66/66 | **owner-emqx-arm-attempt1 164/164** through the production OwnerRunner (rootless, systemd --user), 1778.6 s |
| ARM: automatic rollback, readback rollback (設定（log） named), manual rollback to the baseline | **attempt-19 PASS 84/84**; earlier engine: attempt-13 84/84 | the same run |
| x86 cold encrypted backup → [file, built_in_database]: the same import set | **attempt-20 PASS 66/66**; earlier engine: attempt-14 66/66 | **owner-emqx-x86-attempt1 164/164** (x86 backup on ARM64 = cross-architecture, 1790.7 s); rootful store: emqx-real-x86-attempt2 81/81 |
| x86: automatic, readback and manual rollback | **attempt-22: step PASS** (exit 1 only for the leak scan's start, see its row); earlier engine: attempt-15 85/85 | the same run as above |
| Decision C: [file] target + HA ACL rows → refusal at check AND at conversion, nothing changed (ARM and x86) | **attempt-23 PASS 55/55**; earlier: attempts 02, 03, 16 | both owner runs (package default target [file]) |
| HA backup made while EMQX ran → named (hot-backup hint) | **attempt-23** (ARM and x86); earlier: 03, 16 | - |
| Leak scan (engine records, logs, journal, private evidence) | **attempt-23, attempt-24: 0 hits** | product log secret hits 0 (their JSON) |
| Cleanup, baseline deletion, isolation | **attempt-24 PASS 20/20**; earlier: 17 (B0 deletion) | lane cleanup + audit (their README) |
| Decision C's other half: [file] target + backup WITHOUT ACL rows → imported (inputs are LAB-MADE, S7) | extra chain, attempts 31-34, on branch `fix/emqx-health-suggest-20261124` (this README there) | - |
| The page's own catalog draft (suggest) works for a real backup + restore (health check) | extra chain, attempt 30, on branch `fix/emqx-health-suggest-20261124` (this README there) | their finding: the old draft's /readyz answers 403 from the host |
| x86 built-in chain again on the INTEGRATED engine (80215432 = all product lanes + the health fix) | extra chain, attempts 35-37, on branch `fix/emqx-health-suggest-20261124` (this README there) | - |

## Real tests (dev-d, through the installed helper = the commands the page sends)

Real HA backups used (bound by SHA-256 to dev-d's HA store): the cold (EMQX stopped) encrypted batch-1 backups of add-on 5.9.1
(EMQX 5.8.9) from the real RPi5 HA (`arm-cold`) and the real x86 HA (`x86-cold`), and, for the hot hint, the encrypted ones
made while EMQX ran (`arm-enc`, `x86-enc`). dev-d's target is its own product EMQX (Woow_podman_emqx: `${EMQX_ETC_DIR}/acl.conf` on
a read-only mount, bootstrap CSV secret, sources `[file]`, no_match deny). `builtin` = the built-in database source was added
after the ACL file first (what the owner's text tells the customer to do). Every attempt is one JSON in this folder. Each import
attempt that failed (04–08, 10, 11) restored the baseline by itself (state digest equal to the one before); 01 and 09 never held
dev-d; 17, 21 and 22 failed only in lab steps around the product (see their rows).

| Attempt | Scope | Source commit / engine tree | Result | Time | Steps | What it proved or why it failed | Simulated (codes below) |
|---|---|---|---|---|---|---|---|
| attempt-01 | `setup-before-arm-file` | 16abc8a / 7376ab3f | **stopped** (exit -15) | 1253.3 s, lock never | - | Stopped by the lane while it waited for the dev-d lock (never held it, no dev-d change): the security review's SR-6/SR-7 fixes had to be merged first. | - |
| attempt-02 | `setup-before-arm-file` | 9036688 / 2411407a | **PASS 33/33** (exit 0) | 1706.0 s, lock 706 s | setup: PASS seconds=87<br>before: PASS seconds=238<br>import:arm-cold:file: PASS seconds=373 | Decision C on the real ARM backup and dev-d's own [file] target: the check refuses with exactly the owner's text, the conversion (started anyway) is refused with the same text, no backup and no throwaway object left, state digest equal; also deploy of the tree and baseline B0. | S1 S6 |
| attempt-03 | `x86-file-hot` | 448ec58 / 2411407a | **PASS 30/30** (exit 0) | 723.2 s, lock 512 s | setup: PASS seconds=19<br>import:x86-cold:file: PASS seconds=266<br>check-hot: PASS seconds=225 | The same decision-C refusal for the real x86 backup; both hot backups are named (the hot-backup hint stays). | S1 S6 |
| attempt-04 | `arm-builtin` | 037ed13 / 2411407a | **FAIL 13/15** (exit 1) | 866.7 s, lock 133 s | setup: PASS seconds=17<br>import:arm-cold:builtin: FAIL seconds=113 | FAILED in the harness's own preparation: EMQX 5.8.9 prepends a source created through REST (emqx_authz_api_sources.erl:258-259), so the order was [built_in_database, file]. No product job ran. Fixed in the harness (move after:file, as a customer does) and in the docs. dev-d's own baseline was restored by the harness itself (state digest equal to the one before). | S1 S2 S6 |
| attempt-05 | `arm-builtin` | 006e495 / 2411407a | **FAIL 21/23** (exit 1) | 1867.5 s, lock 741 s | setup: PASS seconds=21<br>import:arm-cold:builtin: FAIL seconds=717 | FAILED in the PRODUCT: 「EMQX 候選啟動後設定與目標不一致」: a source added at runtime lacks the schema default max_rules that every boot fills (emqx_config.erl:341,345). Fixed 28e9492. A second FAIL is the harness's timing only (the first login right after the baseline restore got 404; fixed e62b0a5). dev-d's own baseline was restored by the harness itself (state digest equal to the one before). | S1 S2 S6 |
| attempt-06 | `arm-builtin` | e62b0a5 / bb052f3d | **FAIL 22/23** (exit 1) | 2157.0 s, lock 571 s | setup: PASS seconds=35<br>import:arm-cold:builtin: FAIL seconds=533 | FAILED in the PRODUCT at the same check: the package's EnvironmentFile= (EMQX_LOG__CONSOLE__LEVEL) was not given to the candidate. Fixed 3761d18 (since abff1a0 podman reads the file itself). dev-d's own baseline was restored by the harness itself (state digest equal to the one before). | S1 S2 S6 |
| attempt-07 | `arm-builtin` | 3761d18 / 25c1fa0e | **FAIL 22/23** (exit 1) | 2732.8 s, lock 333 s | setup: PASS seconds=10<br>import:arm-cold:builtin: FAIL seconds=323 | FAILED at the same check with no root named; fdb7cfe makes the refusal name the differing setting roots (schema names only, never values). dev-d's own baseline was restored by the harness itself (state digest equal to the one before). | S1 S2 S6 |
| attempt-08 | `arm-builtin` | fdb7cfe / 41e74632 | **FAIL 22/23** (exit 1) | 393.7 s, lock 393 s | setup: PASS seconds=16<br>import:arm-cold:builtin: FAIL seconds=376 | FAILED, now naming `dashboard`: num_acceptors defaults to the online schedulers (emqx_dashboard_schema.erl:125-131) and the candidate runs under --cpus. Fixed 92f2461. dev-d's own baseline was restored by the harness itself (state digest equal to the one before). | S1 S2 S6 |
| attempt-09 | `arm-builtin` | 92f2461 / 0764d670 | **stopped** (exit -15) | 228.4 s, lock never | - | Stopped by the lane while it only waited for the dev-d lock (never held it, no dev-d change), to land be5bc6f first. | - |
| attempt-10 | `arm-builtin` | 56a6433 / 0e342456 | **FAIL 24/25** (exit 1) | 890.8 s, lock 625 s | setup: PASS seconds=15<br>import:arm-cold:builtin: FAIL seconds=608 | FAILED in the PRODUCT: 「暫用的 EMQX 在 300 秒內沒有就緒」: ERL_FLAGS lands after bin/emqx's trailing -emqx_data_dir (bin/emqx:570,1321-1324). Fixed be2c92d (ERL_AFLAGS). be5bc6f (no anonymous volume) proven here. dev-d's own baseline was restored by the harness itself (state digest equal to the one before). | S1 S2 S6 |
| attempt-11 | `arm-builtin` | be2c92d / 6b1181d7 | **FAIL 24/25** (exit 1) | 400.0 s, lock 398 s | setup: PASS seconds=19<br>import:arm-cold:builtin: FAIL seconds=378 | FAILED in the PRODUCT after HA's data imported: 「EMQX 匯入後未能保留目標有效設定」: `emqx ctl conf load` fills schema defaults before storing (emqx_conf_cli.erl:541-546). Fixed 0d260db. dev-d's own baseline was restored by the harness itself (state digest equal to the one before). | S1 S2 S6 |
| attempt-12 | `arm-builtin` | 0d260db / 5292c15d | **PASS 66/66** (exit 0) | 401.6 s, lock 401 s | setup: PASS seconds=10<br>import:arm-cold:builtin: PASS seconds=391 | ARM built-in, engine 5292c15d (before abff1a0/8613ffa): check ok, real conversion (real space check), inspect in place/same, restore with a safety backup and the product's own readback (「EMQX 還原後核對一致」); after the restore AND after a service restart: HA's 3 MQTT users log in with HA's passwords, wrong password / anonymous / banned client id refused, this device's bootstrap user still logs in, HA's ACL rows active (allowed, and SUBACK 0x80 denied), this device's ACL file byte-equal and still working, 2 retained messages with equal payloads, HA's republish rule delivers exactly one rendered message, HA's HTTP action rule matched and ran, HA's Dashboard users and API key work, state after the restart equal, no anonymous volume left. | S1 S2 S5 S6 |
| attempt-13 | `arm-rollback` | 6d7c1e2 / 5292c15d | **PASS 84/84** (exit 0) | 407.7 s, lock 407 s | setup: PASS seconds=5<br>rollback:arm-cold: PASS seconds=402 | ARM rollback rounds, engine 5292c15d: imported state proven again first, then AUTOMATIC rollback (start failure → job rolled-back), READBACK rollback (a changed setting → named 設定（log） → rolled back by itself), each with the full client probe after it; then MANUAL rollback = restore of baseline B0: this device's admin back, no HA data, [file] only, markers back, state digest equal to before any import. | S1 S3 S4 S5 S6 |
| attempt-14 | `x86-builtin` | cde92e4 / 5292c15d | **PASS 66/66** (exit 0) | 2341.7 s, lock 1038 s | setup: PASS seconds=45<br>import:x86-cold:builtin: PASS seconds=988 | x86 built-in, engine 5292c15d: the same full import set as attempt-12. | S1 S2 S5 S6 |
| attempt-15 | `x86-rollback` | f211688 / 5292c15d | **PASS 85/85** (exit 0) | 2244.2 s, lock 761 s | setup: PASS seconds=36<br>rollback:x86-cold: PASS seconds=723 | x86 rollback rounds, engine 5292c15d: the same rounds as attempt-13. | S1 S3 S4 S5 S6 |
| attempt-16 | `file-refusal-hot` | 4bd7fbb / 5292c15d | **PASS 48/48** (exit 0) | 818.1 s, lock 817 s | setup: PASS seconds=14<br>import:arm-cold:file: PASS seconds=441<br>import:x86-cold:file: PASS seconds=235<br>check-hot: PASS seconds=121 | Decision C for both real cold backups on dev-d's [file] target (check and conversion refused with the owner's text, nothing left, state digest equal) and both hot backups named, engine 5292c15d. | S1 S6 |
| attempt-17 | `cleanup-leaks` | 96d5239 / 5292c15d | **FAIL 15/16** (exit 1) | 13.8 s, lock 13 s | setup: PASS seconds=4<br>cleanup: PASS seconds=8<br>cleanup-baseline: PASS seconds=1<br>leaks: SKIP headroom=1 | FAILED only because the leaks step was skipped: dev-d's memory headroom (which counts page cache) was 1 576 128 512 B, below the harness limit of 1.5 GiB. cleanup (no job object, converted/safety backups deleted, no drop-in left, EMQX running) and cleanup-baseline (B0 deleted) passed. | - |
| attempt-18 | `arm-builtin` | e08f8a1 / 865c930f | **PASS 74/74** (exit 0) | 779.6 s, lock 778 s | setup: PASS seconds=26<br>before: PASS seconds=138<br>import:arm-cold:builtin: PASS seconds=614 | ARM built-in on the FINAL merged engine (865c930f): `setup` (deploy; every installed module and the helper equal to this tree), `before` (state digest equal to the first one recorded before any import; new baseline B0), then check ok, real conversion (real space check), inspect in place/same, restore with a safety backup and the product's own readback (「EMQX 還原後核對一致」); after the restore AND after a service restart: HA's 3 MQTT users log in with HA's passwords, wrong password / anonymous / banned client id refused, this device's bootstrap user still logs in, HA's ACL rows active (allowed, and SUBACK 0x80 denied), this device's ACL file byte-equal and still working, 2 retained messages with equal payloads, HA's republish rule delivers exactly one rendered message, HA's HTTP action rule matched and ran, HA's Dashboard users and API key work, state after the restart equal, no anonymous volume left. | S1 S2 S5 S6 |
| attempt-19 | `arm-rollback` | f1ec063 / 865c930f | **PASS 84/84** (exit 0) | 399.6 s, lock 398 s | setup: PASS seconds=8<br>rollback:arm-cold: PASS seconds=390 | ARM rollback rounds on the FINAL engine: imported state proven again first, then AUTOMATIC rollback (start failure → job rolled-back), READBACK rollback (a changed setting → named 設定（log） → rolled back by itself), each with the full client probe after it; then MANUAL rollback = restore of baseline B0: this device's admin back, no HA data, [file] only, markers back, state digest equal to before any import. | S1 S3 S4 S5 S6 |
| attempt-20 | `x86-builtin` | 219d567 / 865c930f | **PASS 66/66** (exit 0) | 856.9 s, lock 855 s | setup: PASS seconds=37<br>import:x86-cold:builtin: PASS seconds=817 | x86 built-in on the FINAL engine: the same full import set as attempt-18 (check, conversion, restore + readback, client probes after the restore and after the restart, state equal, no anonymous volume left). | S1 S2 S5 S6 |
| attempt-21 | `x86-rollback` | ef73c0e / 865c930f | **FAIL 6/7** (exit 1) | 24.5 s, lock 23 s | setup: FAIL seconds=23 | FAILED by a false alarm of the HARNESS in its setup step; no product step ran: 2 "new dangling volumes" were dev-d's NAMED headscale-data and headscale-run, dangling whenever the pre-existing headscale.service restart loop has no container (97 anonymous volumes before and after). Fixed f0a34e2 (only podman's generated names and woowbk-* count). dev-d's EMQX kept attempt-20's recorded imported state for attempt-22. | - |
| attempt-22 | `x86-rollback` | fc0e3bc / 865c930f | **FAIL 90/91** (exit 1) | 524.7 s, lock 524 s | reclaim: PASS seconds=2<br>setup: PASS seconds=8<br>rollback:x86-cold: PASS seconds=505<br>reclaim: PASS seconds=5<br>leaks: FAIL seconds=4 | x86 rollback rounds on the FINAL engine: the step PASSED completely (imported state proven again first, then AUTOMATIC rollback (start failure → job rolled-back), READBACK rollback (a changed setting → named 設定（log） → rolled back by itself), each with the full client probe after it; then MANUAL rollback = restore of baseline B0: this device's admin back, no HA data, [file] only, markers back, state digest equal to before any import). Exit 1 only because the leaks step could not start (harness): the b1 driver's scan requires an index.json this engine does not have; fixed c6435b4, the scan ran in the later attempts. | S1 S3 S4 S5 S6 |
| attempt-23 | `file-refusal-hot` | c6435b4 / 865c930f | **PASS 55/55** (exit 0) | 1064.9 s, lock 1063 s | reclaim: PASS seconds=10<br>setup: PASS seconds=27<br>import:arm-cold:file: PASS seconds=387<br>import:x86-cold:file: PASS seconds=398<br>check-hot: PASS seconds=231<br>reclaim: PASS seconds=4<br>leaks: PASS seconds=4 | Decision C on the FINAL engine, dev-d's own [file] target: the real ARM and the real x86 cold backup are each refused at check time with exactly the owner's text as the only blocker, the conversion (started anyway) is refused with the same text, no backup and no throwaway object left, dev-d's EMQX state digest equal; both hot backups are named (the hot-backup hint stays); LEAK SCAN (the first one of this lane that ran): 650 engine files, the whole journal and the run's private evidence against 18 secret names (HA key, b1 test passwords, dev-d's EMQX secrets, the kit, the 4 Dashboard tokens issued to this run's probes) = 0 hits. | S1 S6 |
| attempt-24 | `cleanup-leaks` | 5eb53fd / 865c930f | **PASS 20/20** (exit 0) | 33.6 s, lock 33 s | reclaim: PASS seconds=2<br>setup: PASS seconds=10<br>cleanup: PASS seconds=14<br>cleanup-baseline: PASS seconds=2<br>leaks: PASS seconds=4 | Cleanup on the FINAL engine: no throwaway container, volume or network of a job, no staging folder or key file, no drop-in, script or marker; the test's converted and safety backups and the baseline B0 deleted, dev-d's own backups stay, woow-emqx and its entrance run, no new anonymous volume; leak scan again = 0 hits; isolation true none {}. | - |

`attempt-secreview2-01` (security review lane, setup only on abff1a0, the import step skipped for dev-d headroom) is kept on
`sec/emqx-secreview2-20261124`.

## Simulated or not covered (stated plainly)

- **S1** the browser page itself: dev-d publishes no port and stays `network=none`; the harness sends the page's helper commands
  (ha-check-start, ha-convert-start, inspect, restore-start, job-status, delete, upload-begin/-finish) as root inside dev-d, one
  JSON request each. The page's own logic is covered by `tests/backup-ui.mjs`.
- **S2** the customer's Dashboard step (add 「內建資料庫」, move it after 「ACL 檔案」) is done by the harness through this device's
  REST API; the import never adds a source. The manual rollback removes it again.
- **S3** the start failure that provokes the automatic rollback is a one-shot `ExecStartPre` failure of emqx.service; the rollback
  is the product's.
- **S4** the data change that provokes the readback rollback is a one-shot `ExecStartPre` that appends one HOCON line
  (`log.console.formatter = json`) to the restored cluster.hocon; the detection and the rollback are the product's.
- **S5** HA's HTTP action targets 127.0.0.1:18083/api/v5/status (HA's own broker API); here that address is the Dashboard
  entrance, which answers 404: the action runs and its counter moves (the check accepts "ran", not "delivered").
- **S6** the MQTT clients are the harness's probe inside dev-d, logging in with HA's real (b1 test) credentials; no external
  IoT device, no TLS listener from outside dev-d.
- **S7** lab-made input: the real x86 cold backup whose `emqx_acl` table EMQX 5.8.9 itself cleared (`emqx_noacl_fixture.py`), unencrypted.
- Not covered: production (never touched), a device reboot, EMQX clusters (more than one node), other authorization sources than the
  ACL file and the built-in database, other EMQX versions than 5.8.9, HA backups made while EMQX ran (named by the check; refused or
  warned, never proven as a full import).

## Open (stated plainly)

- Security review: `tests/backup/evidence/emqx-product-security-review-20261123/README.md` (lane emqx-secreview): verdict OK for engine tree 865c930f; open for a HUMAN: the boot-time behaviour of HA's throwaway EMQX broker on HA's own files was only partly reviewed (one deeper step was stopped by a safety classifier and not repeated); a merge policy for devices whose Dashboard edited the ACL file (today the import refuses, fail closed).
- `fix/emqx-health-suggest-20261124` (a3a0479, merged by integration-3 as 66c1142): catalog-suggest drafted the entrance's `/readyz` as EMQX's health check, which answers 403 from the host (found by arm54-2 on the ARM machine, confirmed on dev-d). Written after the review ended: 42 lines of suggest.py, data mapping only.
- 97 old anonymous volumes on dev-d come from runs before be5bc6f (the fix); they were counted before and after every step and are not removed by this lane.
- commercial_acceptance stays `not-complete` until the owner accepts.
