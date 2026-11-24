# LiteLLM HA import as the PRODUCT path: real HA backup -> dev-d through the Cockpit flow (2026-11-23, lane litellm-product)

Owner decision 2026-11-23 「決定1 做」: the lab-proven LiteLLM method (lane services-b, `tests/e2e/lab/litellm_real_ha.py`,
24/24 on the owner-made real backup, evidence `../litellm-real-20261123/`) is now the real product import
(`backup-engine/woowbackup/ha_litellm.py`, registered in `haapps`), with the trust rules of the Omnigent import.

Driver: `tests/e2e/lab/litellm_full_flow.py --run`, evidence by `tests/e2e/lab/services_a_capture.py` (fixed status
lines only, stdout SHA-256, exit, elapsed, source commit, `commercial_acceptance: not-complete`). Every attempt file is
kept, failed ones included. Private, redacted details: `~/.woowbk-lab/evidence/litellm-product/<time>/` (0700).

## Real source

Owner-made backup of the showcase x86 HA's `woow-litellm` 0.1.15 add-on (LiteLLM 1.104.0, PostgreSQL 18.6, partial,
encrypted, cold): `~/.woowbk-lab/ha-fixtures/20261123-litellm/x86/woow-litellm-x86-enc/woow-litellm-x86-enc-20261123.tar`,
SHA-256 `9dc59944...86f27`, checked by the driver. HA key and test virtual key read through the harness reader
(`ha_import_b1_e2e.Secrets`), HA's four secret files read in memory by the product reader for the leak scan only; no
value is printed, logged or stored in this folder.

## What a run does (dev-d: outer network none, no published port, mutation lock held, isolation checked before/after)

1. Setup: the engine of this tree installed by `deploy-src.sh`; LiteLLM deployed from the WOOWTECH Podman package
   `Woow_podman_litellm` dd690ae (`scripts/install.sh --no-pull`: fresh secrets, units, health, smoke) with the lab
   images already in dev-d; the catalog entry from `catalog-suggest` (single-database variant, `verify: []` like the
   package's production entry); this device's OWN data seeded with its master key (credential, model, virtual key).
2. Page path: upload-begin / copy / upload-finish, `ha-check-start`, `ha-convert-start` (real SpaceGuard/Watchdog),
   `inspect`, `restore-start` -- exactly the helper commands the page sends (no browser: dev-d publishes no port).
3. Automatic rollback: the first import restore gets a one-shot `ExecStartPre` failure of `litellm.service`: it must end
   `rolled-back` with this device's own salt, data and key back.
4. Import: restore of the converted backup; then HA's test virtual key on `/key/info` (alias), users/teams/models 1/1/24,
   every stored provider value decrypting inside the running app with the moved salt and none with a random one, the
   `litellm-salt-key` secret and the database salt HA's, the other four LiteLLM secrets unchanged, this device's master
   key working and its own key refused, the live schema this device's (signature equal to before).
5. Restart (`systemctl --user restart litellm-postgres.service litellm.service`) and the same checks.
6. Manual rollback: restore of the import's safety backup: this device's own salt, data and key back.
7. Leak scan (registered values in the engine records, uploads, staging, run dir, the device journal, this run's private
   evidence), then cleanup: test backups, the HA store record, the catalog entry and the whole LiteLLM deployment removed.

## Lab differences (stated)

- App image: the lab build `0c71bec8` of the package on the public LiteLLM 1.104.0 base (the services-b image), derived
  once with `USER 1000:0` and its prisma folder owned by it: dev-d maps container IDs 0..55000, the product's 65534
  cannot run here (the same difference as services-b). PostgreSQL 17.11 alpine `094ecc9c` tagged as the package's
  reference and pinned to its device digest (`deploy-batch1.sh` repin rule).
- PostgreSQL 18.7 for HA's cluster: the official image by content (`ha_litellm.PG18_IDS`, Docker Hub index ff64c9e3);
  dev-d already holds the amd64 one, so the product picks it without a pull.
- No outbound network (dev-d network none): provider calls and ChatGPT token refresh are not exercised.

## Attempts

| attempt | source commit | result | notes |
| --- | --- | --- | --- |
| 01 | e0c9e56 | cancelled (exit -15, 354 s) | stopped by the lane while still waiting for the dev-d lock (behind integration-2's EMQX run and omnigent-product's ARM run; no dev-d object touched): the harness leak scan it would have used (b1 `LEAK_SCAN`) requires `/var/lib/woowtech-backup/index.json`, which this engine does not keep (omnigent-product's x86-plain attempt 1 failed exactly there, fixed in 91a3086); the driver now has its own `LEAKS` and an in-container egress check |
| 02 | 5faef6f | FAIL (exit 1, 11/13, 1419 s, lock 1033 s) | setup stopped at the package install: `scripts/install.sh --no-pull` waited 920 s for `litellm` to become healthy and gave up; the container was restarted every ~2.5 min before LiteLLM 1.104.0 was ready. Cause (package library, not the import): its waiter `ql_wait_container_healthy` runs `podman healthcheck run` every 2 s (`QL_HEALTH_ACTIVE=1` default), each run uses one of the 40 startup-probe attempts the unit plans 15 s apart (`HealthStartupRetries=40`, `HealthStartupInterval=15s`), so on the loaded lab host (load ~28) podman restarted the container after ~40 checks. The run's leak scan (0 hits) and cleanup (LiteLLM removed, containers as found, isolation `true none {}`) passed. Fix for the next attempt: the library's own knob `QL_HEALTH_ACTIVE=0` for the install, and the lab catalog health timeout 600 s (production entry: 300 s) |
| 03 | 5c2e435 | FAIL (exit 1, 28/33, 1216 s, lock 404 s) | the package install now passed (QL_HEALTH_ACTIVE=0, ~4 min) and this device's own data was seeded and read (own key 200, own credential decrypts, own salt in secret and DB); upload PASS. The product CHECK refused with a real finding: `資料庫結構版本不同（Prisma 遷移紀錄：只在 HA 的 未知 筆，只在這台的 未知 筆）` -- `ha_litellm.MIGRATION_RE` did not allow spaces, and one of LiteLLM 1.104.0's 189 migration names has them (litellm-proxy-extras 0.4.102.post1 `litellm_proxy_extras/migrations/20251122125322_Add organization_id to spend logs/`), so both sides read as unknown; the convert refused the same way (nothing converted, nothing changed: the guard behaved). Everything else of the check passed (versions 0.1.15 / 1.104.0, PG 18 -> 17, salt bound to HA's database, schemas, no superuser objects). Also a harness expectation: catalog-suggest proposes the Quadlet's liveness URL and only config.yaml; the production entry has `/health/readiness` and both config files. Leak scan 0 hits, cleanup and isolation PASS |
| 04 | 3bde418 | FAIL (exit 1, **67/69**, 2337 s, lock 1881 s) | (CORRECTED 2026-11-24, see Corrections: the record marks both rollbacks' own-data/key line FAIL; not every product step is proven by this attempt) The whole PRODUCT flow passed on the real backup: package install (4 min), own data seeded; ha-check 43 s ok (0.1.15 / 1.104.0, PG 18 -> 17, users/teams/models 1/1/24, keys 1, credentials 3, 2 ChatGPT sign-ins warned, key_users [] on dev-d); ha-convert 171 s (job log: HA's rows only, this device's schema in one snapshot, the role without privileges, counts equal, HA's salt used for litellm-salt-key), the converted backup manual + encrypted + from HA, inspect: in place, settings same, postgres main PG 17, 5 secrets; automatic rollback: the import restore with a one-shot ExecStartPre failure of litellm.service ended rolled-back (290 s) with this device's own salt secret and DB salt back, the other four secrets unchanged, own credential decrypts (record: PASS); its line "own data is back (counts, schema), own key 200, HA test key refused" is FAIL in the record (own key 200 / HA key 401 only from the private probe files); import restore succeeded (health ok); HA's test key /key/info 200 with its alias, /v1/models 200, users/teams/models 1/1/24, 72/72 model values and 5/5 stored values decrypt in the running app with the moved salt and 0 with a random one, litellm-salt-key and the DB salt are HA's, master key / UI password / DB password / URL unchanged, this device's master key works and its own key is 401, 0 of 3 outbound connections from the container, schema = this device's; restart: the same; manual rollback to the safety backup (324 s): own salt back (record: PASS), its own data/key line FAIL in the record like the automatic rollback's; leak scan 0 hits; cleanup (LiteLLM removed, containers as found), isolation `true none {}` before/after. The 2 FAILs are the harness's own-state equality: `spend_logs` grew 1 -> 3 -> 5 because LiteLLM logs the probes' own-key calls (every other count, the schema signature and the keys matched; checked in the private probe files) |
| 05 | db73107 | FAIL (exit 1, 45/49, 7032 s, lock 5738 s) | Run under extreme host load (load average 39 rising to 50-69): setup 10.5 min, check PASS (no blocker), convert PASS (6.5 min). Every restore then needed LiteLLM 1.104.0 to answer `/health/readiness` within the catalog window (600 s in the lab) and it did not at that load (it answered a few minutes later): the injected-failure restore's automatic rollback, the import restore (-> automatic rollback) and the manual rollback restore all ended `failed` with the engine's 「還原失敗，且自動回復未完成，需人工處理：「litellm」回復後健康檢查未通過」 and the safety backup id. What the engine had put back was verified each time: after the automatic rollback and after the manual rollback this device's own salt secret and DB salt, all five secrets, counts (spend_logs aside), schema signature, own key 200 / HA key 401 and own decryption were back. Leak scan 0, cleanup (LiteLLM removed, 4 test backups deleted), isolation `true none {}` before/after. The restart phase was skipped by the driver's hold budget. CORRECTED 2026-11-24: the import itself FAILED (its restore ended failed, the phase stopped, so no import client check ran) and both engine rollback restores (the automatic one and the manual one) ended failed as well; only the own-state probes after those failed restores passed. The lock was held 5738 s (96 min), over the 40-minute hold limit (a lane rule breach under load, recorded). Not a data bug, but a product-visible failure: on that load LiteLLM was not ready within the health window (see the readiness decision below) |
| 06 | 3c1a0a4 | cancelled (exit -15, 840 s, no lock) | Queued 22:29 (polling from 22:36) from the tree with the security-review fixes (SR-1..SR-5) and the Pi-agent key_users source. Cancelled by the lane at 22:50 while it still only polled for the dev-d lock (no dev-d object touched): its 5-second non-blocking poll could never win against the other lanes' kernel-queued waiters (emqx-product, omnigent-product; the lock went omnigent -> emqx -> emqx while it waited). The driver now waits like `flock -w 3600` (kernel-queued, the omnigent-product driver's method) and attempt 07 reruns the same product code. |
| 07 | 82e68ac | FAIL (exit 1, 30/33, 2858 s, lock 926 s) | First run with the security-review fixes (SR-1..SR-5) and the Pi-agent key_users source; the kernel-queued wait got the lock after 1930 s. Setup PASS (package install ~10 min at load 30-43), own data seeded, upload PASS. **The product check refused the real backup**: 「HA 與這台 LiteLLM 的資料庫結構不同（public.LiteLLM_CronJob）」, and the convert refused the same way (nothing converted, nothing restored). Cause (real, reproduced): SR-1 makes HA's sessions resolve names in pg_catalog only, so `format_type` renders the enum column `LiteLLM_CronJob.status` as `public."JobStatus"` there, while this device's sessions (default search_path) render `"JobStatus"`. Proven on real PostgreSQL 17.11 and 18.7 in the lab store (`tests/e2e/lab/litellm_pin_proof.py`, `tests/backup/evidence/litellm-product-20261123/search-path-pin-proof.json`): unpinned -> differences [public.LiteLLM_CronJob], pinned -> none. Fixed in the next commit (every columns/signature read pins `search_path = pg_catalog`). key_users on dev-d = [] (PASS); leaks 0, cleanup, isolation true none {}. |
| 08 | 215fdf0 | FAIL (exit 1, **68/69**, 3203 s, lock 1944 s) | **Every product step and client check PASSED on 215fdf0** (SR-1..SR-5 + Pi-agent key_users + the search_path pin; correction 01:50: NOT the final product code -- 215fdf0 lacks the review's later SR-6 refusal 1e29974 and fix2's SR-8..SR-10, final = 1a83926, see the Result section), real encrypted backup, load 16-25: setup 5 min; ha-check 36 s, no blocker (0.1.15 / 1.104.0, PG 18 -> 17, 1/1/24, key_users [], only the ChatGPT warning; no SR-5 stored-settings line); ha-convert 196 s; inspect; AUTOMATIC ROLLBACK of an injected failing import (rolled-back in 345 s: own salt, data, key back, own values decrypt); import 251 s with safety backup, health ok; HA test key `/key/info` 200 + alias + models, 1/1/24, 72/72 model values + 5/5 stored values decrypt with the moved salt (0 with a random one), salt secret + DB salt HA's, other 4 secrets unchanged, master key works, own key refused, 0/3 egress, schema = device's; restart (same checks again); MANUAL ROLLBACK 288 s (own salt/data/key back); leaks 0; job objects, staging, backups, HA record, catalog entry and LiteLLM removed; isolation true none {}. **The one FAIL** = the harness's exact container-set equality: dev-d's `headscale` container was absent at the baseline and present after. Not LiteLLM: dev-d's headscale.service is in a restart loop (NRestarts 1363, every 10 s, read-only check 00:59: 「initial DERPMap is empty, Headscale requires at least one entry」 -- the network-none lab cannot fetch the default DERP map), so a container snapshot sees it only some seconds of every cycle (attempt 07's baseline had it). |
| secreview-01 | 14be8bc (product code 1a83926, final) | **PASS (exit 0, 69/69, 2033 s, lock 1690 s)** | Run by lane litellm-secreview from its worktree with this driver (evidence attempt-secreview-01.json, merged here): the final product code (215fdf0 + the review's SR-6 gaps, SR-8 convert re-check on the new cluster, SR-9, SR-10) through the whole Cockpit helper flow on dev-d with the real encrypted backup: check, convert, automatic rollback, import, HA test key, counts, decrypt with the moved salt, restart, manual rollback, leaks 0, cleanup (this time the container snapshot matched), isolation true none {}. |
| 09 | a0475c5 | FAIL (exit 1, 1043 s, lock held 0 s) | Queued 03:20 (kernel-queued); it got the dev-d lock at ~03:37 after 1039 s, right behind another lane's heavy run, and stopped at its own memory pre-check before touching anything: dev-d's cgroup showed 2,308,022,272 of 4,294,967,296 bytes used (page cache of that run included), less than the 1.86 GiB of headroom the driver asks for. Isolation true none {} before and after; nothing deployed, no product step ran. The check was not changed. Rerun as attempt 10. |
| 10 | 6b55ec5 (product: `ha_litellm.py` of 1a83926, `suggest.py` of 98427dc = the final product code) | **PASS (exit 0, 73/73, 1738 s, lock 1737 s)** | 2026-11-24 07:37-08:07 through `team/heavy.sh` (host load 16-35, no lock wait). The whole Cockpit helper flow on dev-d with the owner's real encrypted backup: package install, own data; **`catalog-suggest` proposes 600 s for LiteLLM in every variant** (owner decision 2026-11-23 23:28, 98427dc); **option A's positive case**: the lab stub app `woowbk-llm-client` (a never-started catalog entry whose Quadlet points at LiteLLM) is named by the product's own `key_users` in the check warning, the import note and the reminders (until now the real runs had only shown `[]`); ha-check 43 s, no blocker, 1/1/24; ha-convert 249 s; automatic rollback of an injected failing import 231 s (own salt, data and key back, own values decrypt); import 236 s (HA test key `/key/info` 200 + alias, 72/72 + 5/5 decrypt with the moved salt and 0 with a random one, `litellm-salt-key` and the database salt HA's, the other four secrets unchanged, master key works, own key 401, 0/3 egress, schema = this device's, health 200); restart: the same; manual rollback 221 s (own state back); leaks 0 of 14 registered names in 645 files + the journal, 0 in the run's own evidence; cleanup (LiteLLM, the stub, the catalog entries and the HA store record removed; containers as found); isolation true none {}. |
| negative-01 | 5dcc569 (product code as attempt 10; harness b3e587d) | **PASS (exit 0, 58/58, 704 s, lock 703 s)** | A real NEGATIVE run (`litellm_negative_flow.py`): four crafted plain HA backups (generated data only: this lab LiteLLM's own dump in a throwaway PostgreSQL 18.7 of the lab store, bound to a generated salt) through the same helper commands must be refused: **salt** file not the database's (check and convert: the salt message), **version** add-on 0.1.14 (check and convert: not in this device's table), **hooks** = stored settings that load code, one of each kind, a dotted callback behind 60 plain names included (check and convert name all six places, before HA's rows are read), **hidden** = review SR-8's data directory (the built-in text equality operator edited to hide the hooks): the check is blind as the review found (ok, no blocker) and the CONVERSION refuses after loading the 86 tables into the new cluster and before the converted dump (both hooks named). After each: no converted backup, throwaway object, staging or key file. After all: this device's five secrets, database salt, data, schema, own key, health unchanged; leaks 0 of 15 names; everything removed; isolation true none {}. |

## Result so far (2026-11-23 22:00)

- (CORRECTED 2026-11-24) Attempt 04 passed every product step and the import's client checks on the real backup, but NOT both rollbacks' own-data/key lines: the record marks them FAIL. The lane's reading of its private probe files (not part of the record) is that only `spend_logs` differed (1 -> 3 -> 5, rows the probes' refused-key calls add, vendor proof in Corrections); db73107 then let `spend_logs` grow in that comparison. Both rollbacks restoring this device's state is first PROVEN in the record by attempt 08 (215fdf0) and by attempt-secreview-01 on the final code.
- A single all-green attempt is still open: attempt 05 (db73107, the fixed comparison) met host load 40-69, where LiteLLM's first readiness after a restore takes more than 10 minutes, so every restore's health window expired: the import FAILED and both rollback restores ended failed ("rollback incomplete"); only the own state found after them was verified (CORRECTED 2026-11-24).
- Stated finding for the package/product owner: on a loaded device a LiteLLM restore (also a normal backup restore, not only the HA import) can exceed the catalog health window (production entry 300 s) and end "rolled back / needs manual handling" although the data is back; and the package library's install waiter (`QL_HEALTH_ACTIVE=1`) consumes the unit's startup-probe budget.

## Result (2026-11-24 01:05)

- **Attempt 08 (215fdf0) is the real end-to-end proof of the product code as of 215fdf0** (correction 01:50: the final product code is 1a83926 = 215fdf0 + the security review's SR-6 gaps, SR-8, SR-9, SR-10 on review/litellm-secreview-fix2-20261124; its real dev-d run is the review lane's attempt-secreview-01, recorded on that branch): every product step (upload into the HA store, ha-check, ha-convert with the real space check, restore with a safety backup through the helper) and every client check (HA's test virtual key, counts 1/1/24, stored provider credentials decrypt with the moved salt, master key, egress 0) passed, plus restart, automatic rollback of a failing import, manual rollback to the baseline, leak scan, cleanup and isolation. Its single FAIL is the harness's exact container-set comparison catching dev-d's crash-looping headscale container (pre-existing, not touched by this run).
- Attempt 07 found a real product bug the unit tests could not see (fakes do not render types): the SR-1 session pin made HA's cluster render enum types schema-qualified; fixed in 215fdf0 and proven on real PostgreSQL 17.11/18.7 (`search-path-pin-proof.json`).
- commercial_acceptance stays `not-complete` (no customer device; the production catalog's readiness window is an owner decision; ARM has no LiteLLM HA backup).

## Final (2026-11-24 ~01:50)

- **The final product code 1a83926 passed the real end-to-end flow 69/69** (attempt-secreview-01, exit 0). Attempt 08 (215fdf0) had already shown every product step and client check passing before the review's iteration-2 fixes; attempt 07 found the search_path rendering bug fixed in 215fdf0.
- Branch feat/ha-import-litellm-product-20261123 contains review/litellm-secreview-fix2-20261124 (merged, no conflict). commercial_acceptance stays `not-complete`.

## Corrections (2026-11-24 ~03:00, iteration 3; the lane verifier's 02:14 findings)

- **Attempt 04 overclaim.** `attempt-04.json` marks exactly the two lines "auto rollback / rollback: this device's own
  data is back (counts, schema), own key 200, HA test key refused" FAIL. The row and the 22:00 result said both rollbacks
  brought this device's data and key back and that the whole product flow passed; the committed record does not show
  that. What the record shows for both rollbacks: the restore job result (rolled-back / succeeded), the salt secret and
  database salt back, the other secrets unchanged, own stored values decrypting (PASS). The rest came only from the
  lane's reading of the private probe files (only `spend_logs` differed: 1 -> 3 -> 5). The first committed proof of both
  rollbacks restoring this device's data and key is attempt 08 (215fdf0) and attempt-secreview-01 (final code).
- **"Two issues fixed" (attempts 02/03) overclaim.** Only one was a product fix: Prisma migration names with spaces
  (3bde418). The package install waiter (Woow_podman_litellm `scripts/lib/quadlet-lib.sh`: `QL_HEALTH_ACTIVE=1` runs
  `podman healthcheck run` every 2 s and uses up the unit's 40 startup probes) is NOT fixed: the lab install only works
  around it with the library's own knob `QL_HEALTH_ACTIVE=0` (a lab difference). It stays a package follow-up.
- **Attempt 05 overclaim.** The import itself FAILED (the import restore ended failed, the phase stopped, no import client
  check ran) and both engine rollback restores ended failed ("rollback incomplete"); "no product logic failure" is
  withdrawn. The dev-d lock was held 5738 s (96 min), over the 40-minute limit.
- **db73107 relaxed the `spend_logs` comparison (`==` -> `>=`) without citing the vendor source (rule 2).** The vendor
  proof (litellm 1.104.0 sdist from PyPI, the version in the backup and the lab image): every refused key goes to the
  failure hook (`litellm/proxy/auth/auth_exception_handler.py:220-225`, `post_call_failure_hook(... error_type=auth_error,
  route=route)`); `_ProxyDBLogger.async_post_call_failure_hook` writes a `LiteLLM_SpendLogs` row with status `failure`
  for LLM API and info routes (`litellm/proxy/hooks/proxy_track_cost_callback.py:135-175` and `:261-273`) unless
  `general_settings.disable_error_logs` is true (`:556-568`, not set by the package); `/key/info` is an info route
  (`litellm/proxy/auth/route_checks.py:480-484`, `litellm/proxy/_types.py:631-632`) and `/v1/models` an OpenAI route
  (`route_checks.py:398-399`, `_types.py:407`). Each probe calls both with a refused key (HA's before the import and after a
  rollback, this device's own after the import), so every probe adds 2 rows: 1 -> 3 -> 5, exactly what the private
  probes showed. The comparison only lets `spend_logs` grow; every other count, the schema signature and the keys must
  still be equal.
- **Option A in the real run.** The real runs check only that `key_users` is a list: dev-d's real answer is `[]` (its
  Hermes `LITELLM_API_KEY` is empty; the other hits are comments). A non-empty reminder is proven by unit and page tests
  (mocks) only.
- **Readiness decision (owner 2026-11-23 23:28) now implemented** (it was listed as "needs owner decision" although it was
  decided): 98427dc, `catalog-suggest` proposes 600 s for LiteLLM's health checks (every other app keeps 300/180 s); the
  draft of an installed LiteLLM entry raises a shorter limit with a `health-timeout` note. The host's installed production
  entry keeps 300 s until the owner installs the new draft from the page (no production file was touched).

## Iteration 4 (2026-11-24 07:35-, final)

- **Final product code** = `ha_litellm.py` and the shared import modules of 1a83926 (`3a6e928e…`) + `suggest.py` of 98427dc
  (readiness 600 s, owner decision 2026-11-23 23:28). **Attempt 10 (6b55ec5) passed the whole real flow 73/73** on it; it
  closes the two items iteration 3 left for a real run (the 600 s draft; option A's positive case).
- **Real negative run `negative-01`: 58/58.** Crafted backups are refused by the product flow itself with the specific
  message (salt, version, code hooks), and review SR-8's hidden hooks are refused by the conversion after the check was
  blinded; this device unchanged. Sandbox case `planted_objects` (DOMAIN, TRIGGER, EXTENSION, large object …): nothing ran
  (`tests/backup/evidence/litellm-product-security-review-20261123/planted-objects.json`).
- **Tests on 6b55ec5** (clean detached worktree, `team/heavy.sh` + the host-heavy lock; later commits are lab harness and
  evidence only): full `tests/backup` 1507 tests, 5 failures + 2 errors, all in `test_ha_omnigent` (this
  branch's base; the Omnigent guard, gone in the integration branch since 97c22c9), 6 skipped
  (`tests/backup/evidence/litellm-product-20261123/unit-tests-6b55ec5.json`); mutation check **67/67
  caught**, baseline 109 tests (`mutation-check-6b55ec5.json`). Lab driver tests 32 OK (b3e587d). The page
  is unchanged since e0c9e56 (101/101); the integrated page is run by integration-3.
- **KNOWN OPEN RISKS (owner 2026-11-24 07:22, 「這個可以先不用管」: deferred, not closed; to be named in the PR text):** SR-7
  (a stored `os.environ/` reference makes this device's LiteLLM send its own master key to the host the row names; proven
  on dev-d, `sr7-env-ref-probe.json`) and the `ssl_verify`-type stored settings (vendor source only). No product change was
  made for either; `wip/litellm-sr7-prep-20261124` stays unmerged. Details: the review README's section of the same name.
- **Attempt 09 is kept as a failure of the run conditions, not of the product** (dev-d memory headroom right after another
  lane's run); the driver's check was not changed.
- Not proven / open: ARM (no LiteLLM ARM HA backup exists, the add-on is amd64-only); the installed production entry keeps
  300 s until the owner installs the new draft from the page; the package's install waiter (`QL_HEALTH_ACTIVE`) stays a
  package follow-up; no browser drove the page against dev-d (it publishes no port: the runs send the helper commands the
  page sends, `tests/backup-ui.mjs` covers the page). `commercial_acceptance` stays `not-complete`.
