# Real HA LiteLLM backup -> isolated dev-d LiteLLM (2026-11-23, lane services-b)

Driver: `tests/e2e/lab/litellm_real_ha.py --run --outer-isolation-confirmed`, evidence by
`tests/e2e/lab/litellm_real_capture.py` (fixed JSON event lines only, stdout SHA-256, exit,
elapsed, source commit, `commercial_acceptance: not-complete`). Each attempt file is kept,
failed and cancelled ones included.

## Real source

Owner-made backup of the showcase x86 HA's `woow-litellm` 0.1.15 add-on (LiteLLM 1.104.0,
PostgreSQL 18.6, partial, encrypted, cold), `~/.woowbk-lab/ha-fixtures/20261123-litellm/x86/`,
SHA-256 `9dc59944...86f27` checked before every run. The HA backup key and the test virtual
key are read through `ha_import_b1_e2e.Secrets`; the add-on's own four secret files are read
from the backup in memory. No value is printed, logged or stored in this folder.

## What a run does (all in dev-d: outer network none, no published port, lock held)

1. Product reader: `habackup` + `hasecuretar` decrypt, `ha_litellm_candidate.scan_member`
   (0.1.15 / 1.104.0 / PG 18 / control file / salt format), public `convert` still refuses.
2. Internal candidate `ha_litellm_candidate.cluster_member` streams `data/postgres` through
   the product `ha_odoo.PgSink` into a throwaway PostgreSQL 18.7 (read-only root, `noexec`
   volume, HA's configuration replaced, library/command settings overridden).
3. Product `read_source_salt_binding`: `match` for HA's salt, `mismatch` for another.
4. The package's PostgreSQL 17.11 (alpine) with its own SCRAM password (Podman secret from
   stdin) and the real app image (lab build of Woow_podman_litellm on the public LiteLLM
   1.104.0 base, patches included) seeds its own model and credential.
5. Import in `scripts/restore.sh` order: drop, create, load HA's plain `pg_dump` in one
   transaction; row digests of every table, sequences and schema compared with HA's.
6. Package entrypoint `/opt/woow/start.sh` with HA's salt moved (target keeps its own master
   key, UI password, database password): HA virtual key `/key/info` and `/v1/models`,
   stored models served by the router, users, teams, every stored provider value decrypted
   with the moved salt and none with the target's own salt, a new key issued by the app.
7. Restart (fresh container), the package's `WOOW_CHATGPT_ENABLED=true` stage, db_prepare
   refusing the target's own salt without changing rows, rollback to the target's own data
   (rows and schema equal, own credential decrypts, HA and issued keys refused 401).
8. Cleanup (no container, volume, network or secret of the job), baseline containers
   unchanged, isolation re-verified, credential ledger scan (13 declared sources must all be
   registered; any registered value in the output fails the run).

## Attempts

| attempt | source commit | result | notes |
| --- | --- | --- | --- |
| 01 | 8998444 | cancelled (exit -15) | blocked in flock; no dev-d object; harness changes loaded |
| 02 | 0f53ac5 | cancelled (exit -15) | blocked in flock; no dev-d object; harness changes loaded |
| 03 | aef40b1 | FAIL (exit 1, 792 s, lock 638 s) | import, row/schema/sequence equality, salt binding, HA virtual key 200 + alias, users 1, teams 1, decryption 72/72 model values + 5/5 stored values (0 with the wrong salt), issued key 200, cleanup, leak scan 0/13 sources: PASS. FAIL: 10 of 24 stored models served with the ChatGPT plugin disabled; restart container's start died in Prisma migrate (P1001, DB unreachable; not OOM) and the harness had no unit-like retry |
| 04 | 894bece | **PASS** (exit 0, 2956 s incl. 1240 s lock wait, lock 1711 s) | 24/24 checks. Same import/decryption/HA-client results as 03; model breakdown with the ChatGPT plugin off: openai 3 + openrouter 7 served, chatgpt 14 not; restart counts equal, HA and issued keys accepted (1 start); package setting WOOW_CHATGPT_ENABLED=true: 24/24 stored models served (HA key sees 17), all chatgpt 14 loaded; db_prepare refuses the target's own salt, rows unchanged; target DB oom_kill 0, peak 122 MiB; rollback rows and schema equal to the target's own data, own credential decrypts, HA and issued keys 401. The rollback app needed one unit-like retry: its first start died in the package's ui-session-reconcile with psycopg OperationalError (database reachable right after; transient connect failure under host load). Cleanup 0 objects, baseline unchanged, isolation true none {}, leak scan 13 sources/13 values/0 matches |

Independent post-run scan of this folder (lab secret files through the harness reader plus the backup's own four
secret files, 33 values, raw and JSON-escaped): 0 matches.

## Not covered (stays open)

- Product UID 65534 (dev-d maps 0..55000; the app runs as 1000:0), the package's Quadlet
  units and systemd restart policy (emulated by up to three fresh containers), provider calls
  (no network), ChatGPT token refresh (no network), the public import path (guard kept).
- Commercial acceptance: not complete.
