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
| 03 | 5c2e435 | FAIL (exit 1, see the JSON, lock ~7 min) | the package install now passed (QL_HEALTH_ACTIVE=0, ~4 min) and this device's own data was seeded and read (own key 200, own credential decrypts, own salt in secret and DB); upload PASS. The product CHECK refused with a real finding: `資料庫結構版本不同（Prisma 遷移紀錄：只在 HA 的 未知 筆，只在這台的 未知 筆）` -- `ha_litellm.MIGRATION_RE` did not allow spaces, and one of LiteLLM 1.104.0's 189 migration names has them (litellm-proxy-extras 0.4.102.post1 `litellm_proxy_extras/migrations/20251122125322_Add organization_id to spend logs/`), so both sides read as unknown; the convert refused the same way (nothing converted, nothing changed: the guard behaved). Everything else of the check passed (versions 0.1.15 / 1.104.0, PG 18 -> 17, salt bound to HA's database, schemas, no superuser objects). Also a harness expectation: catalog-suggest proposes the Quadlet's liveness URL and only config.yaml; the production entry has `/health/readiness` and both config files. Leak scan 0 hits, cleanup and isolation PASS |
