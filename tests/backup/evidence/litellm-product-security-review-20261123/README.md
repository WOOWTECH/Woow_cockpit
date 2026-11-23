# LiteLLM HA import — independent security review (2026-11-23)

Reviewed: the LiteLLM product import of lane litellm-product, branch `feat/ha-import-litellm-product-20261123`
(R-COCKPIT), product code at `3bde418` (its later `db73107` changes only its lab driver and evidence), as the diff
against `integration/ha-import-batch1-20261123` (merge base `d812699`): `ha_litellm.py` (new),
`adapters/quadlet_postgres.py` (`import_manifest(secrets=...)`), `haapps.py`, `haimport.py`, `backup/backup.js`, the
docs, the unit tests and the lab driver. Reviewer lane: litellm-secreview (owner instance SR-OWNER-1942).

Fixes are on branch `review/litellm-secreview-20261123` (from `3bde418`; it also contains the product lane's final
`ce95602`): `ad6745a` (SR-1..SR-4), `d31c59a` (SR-5) and `1e29974` (SR-6); the attack harness is `2284e4d`,
`cd900c5`, `f474bb5`, `7cfb585` and the `stored_settings` case. Nothing was pushed.

**Iteration 2 (2026-11-24, re-review of the final diff):** the product lane's later commits `3c1a0a4` (Pi agent
`models.json` in `key_users`) and `215fdf0` (search_path pin) were reviewed, the SR-6 refusal was attacked again and
found incomplete (more vendor code keys, fail-open on read errors) and blind under a crafted data directory (SR-8),
SR-7 was found and proven on a real LiteLLM, and SR-9 (a truncation bypass of SR-6) and SR-10 (a custom secret
manager file) were found. Fixes: branch `review/litellm-secreview-fix2-20261124` from the product's `215fdf0` (merge
`c65ef56` of the review branch, fixes `f2a2cb4`, `a06dc21`, `1a83926`); see "Iteration 2" below.

## How it was tested

- **Real attacks, real product code, throwaway containers only.** Every attack ran in rootless containers of the
  isolated lab Podman store (`~/.woowbk-lab/bin/labpodman`: its own storage root; production containers and images
  are invisible to it), started by the product's own `tempctr.TempObjects` with `--network=none`. No production
  service, secret, image or catalog was touched; dev-d was not used (its lock stayed with the product lane).
- **Images.** The pinned official PostgreSQL 18.7 alpine image, pulled into the lab store by the product's index
  digest `ff64c9e3…`; its ID is `sha256:4ea77c70…` = `ha_litellm.PG18_IDS[0]` (the product's content pin holds).
  The package's PostgreSQL 17.11 alpine image `sha256:094ecc9c…` (the same ID as dev-d's) for the load side.
- **Two threat models.** T1: HA's LiteLLM (or its database role `litellm`, which is **not** a superuser in HA) is
  compromised and plants objects it is allowed to create. T2: the whole backup is crafted (any catalog, any file).
- `tests/e2e/lab/litellm_sandbox_review.py --case <case>` crafts a malicious HA PostgreSQL 18 cluster in a
  throwaway container, packs it as an HA add-on member and runs the real product steps on it:
  `scan_member` + `PgSink` → `podman volume import` → `start_ha_cluster` → `analyse` → `salt_binding` →
  `read_schema` → `verdict` → `export_rows`. Attacker code only writes markers inside the throwaway container
  (`/tmp/woowbk-review-*`), which the harness reads back before the objects are removed.
- `tests/e2e/lab/litellm_archive_review.py`: 36 crafted add-on members through the real `scan_member` / `PgSink`
  (offline, no container).
- Every evidence file records `source.commit` and the SHA-256 of `ha_litellm.py` (`104e9ceb…` = `3bde418`'s,
  `03f3ec69…` = `d31c59a`'s, `4eb30d9f…` = the final `1e29974`'s). `original-*` ran on clean `2284e4d`/`cd900c5`
  (product code = `3bde418`), `fixed-*` on clean `d31c59a`, except `fixed-stored_settings.json` and
  `fixed-real-backup.json`, which ran on clean `1e29974`. The later `owner_view` case ran from `f474bb5`: `original-owner_view.json` with
  `3bde418`'s `ha_litellm.py` put into a throwaway worktree (hence `tracked_changes: true`), `fixed-owner_view.json`
  from the clean review worktree at `fd9e63a`.
- No secret anywhere: the salt is generated per run and never printed; the crafted clusters use trust on their unix
  socket only; the probes record environment variable names, never values.

## Results

| Attack | Product `3bde418` | Fixed `d31c59a` | Evidence |
|---|---|---|---|
| T1: `public.json_agg(name)` aggregate created by the non-superuser owner (search-path trojan) | **ran as the superuser `postgres` during `analyse`** → `COPY … TO PROGRAM` → shell uid 70 in the HA container | not resolved (search_path pg_catalog); no marker; refused (SUPERUSER_SQL reports the aggregate as FUNCTION (LANGUAGE C): an aggregate is an internal-language pg_proc row; migrations unknown) | `*-owner_trojan.json` |
| T1: `_prisma_migrations` replaced by a view over a plpgsql function (view only, no aggregate) | **ran as the superuser during `analyse`, and the check found NO blocker** (migrations read through the view) | not read: only an ordinary table is read; no marker; blocker 資料庫結構版本不同 | `*-owner_view.json` |
| T2: `login` event trigger | **ran at the engine's first connection** (before any check) | did not fire | `*-superuser_catalog.json` |
| T2: `ddl_command_end` event trigger | **ran at `salt_binding`'s GRANT**, before the EVENT TRIGGER blocker | did not fire; blocker unchanged | same |
| Per-database `session_preload_libraries = auto_explain` | **loaded** despite `-c session_preload_libraries=` | `''` | same |
| Per-database `DateStyle 'SQL, DMY'`, `extra_float_digits -10` (USERSET: the owner may set them) | exported `05/11/2026 10:00:00` for 2026-11-05 (the ISO/MDY target reads **11 May**), spend `0.12346` for 0.123456789012345 | `2026-11-05 10:00:00`, `0.123456789012345` | same |
| T2: `backup_label` + `tablespace_map`, no symlink in the member | **PG 18 created `pg_tblspc/16400 -> /tmp/woowbk-review-tablespace`** at its start (`src.symlinks` = 0); this start then failed (WAL ends before end of online backup), a complete online backup would start | never streamed into the volume; no link; blocker 不是在停止狀態下備份的 | `*-tablespace_map.json` |
| HA's stored proxy settings (`LiteLLM_Config`): env vars, named callbacks | moved silently | warning + import note name `HTTPS_PROXY`, `LANGFUSE_HOST`, `langfuse`, … (names only) | `fixed-stored_settings.json` |
| HA's stored settings that LiteLLM imports as code (`post_call_rules: "builtins.exec"`, `general_settings.custom_auth`, a dotted callback) | **moved silently; this device's LiteLLM would import and call them** (vendor source, SR-6) | **blocker** naming them; the conversion stops before reading anything | `fixed-stored_settings.json` (`stored_hooks_blocker`) |
| `COPY … FROM STDIN` data ending in `\.` with SQL or `\!` after it (PG 17.11 psql `-c`, as `load_rows` runs it) | nothing executed, SQL-as-data stays data | same | `*-copy_injection.json` |
| **The real owner-made encrypted LiteLLM HA backup** (fixture SHA-256 checked) through the fixed HA-cluster steps (`tests/e2e/lab/litellm_sandbox_real.py`, lab store, not dev-d; final `1e29974`) | (attempt 4 of lane litellm-product: whole flow) | salt binding `match`, **no blocker** (no module hook either), 189 migrations, 86 tables, 2882 rows, all 86 exported by COPY (896,181 bytes, deleted at once), 1 sequence; the sessions really ran with search_path pg_catalog, ISO dates, extra_float_digits 3, event triggers off; 1 stored settings section, no env var or callback (no SR-5 line); no marker, nothing left | `fixed-real-backup.json` |
| 36 crafted members: traversal, absolute and PAX paths, control characters, devices, sparse, FIFOs, hard links to the master key, symlinked/hard-linked/duplicate/oversized/short salt, oversized/duplicate/deep `state.json`, duplicate/oversized `PG_VERSION`, replaced config files as folders, `conf.d`, recovery and pid files, other member paths, wrong slug, truncated streams | 19 refused, 17 accepted but neutralized (modes 0600/0700, owner postgres; config files replaced; recovery and pid files dropped; secrets, `options.json`, dumps never read; a bad salt or `state.json` gives a blocker or no version); only `backup_label`/`tablespace_map` reached the volume | same, and those two no longer reach it | `*-archive.json` |

What attacker code saw inside the HA container (`original-owner_trojan.json`, `original-superuser_catalog.json`):
uid 70 postgres, CapEff 0, NoNewPrivs 1, seccomp on; interfaces `lo` only, 0 default routes, no DNS, egress refused;
read-only root, no `/run/secrets`, no host path (`/home` empty), 16 processes (its own); data volume `noexec`;
**`/tmp`, `/var/tmp` and `/run` are exec-able** (Podman's `--read-only` tmpfs has no `noexec`); memory and pids
limited (the harness ran with 1 GiB / 512, the product's defaults are 2 GiB / 1024). No anonymous volume and no
container of the review was left. (`volumes_left_behind` in `original-superuser_catalog.json` and
`original-tablespace_map.json` lists dangling volumes other lanes made meanwhile: by their content they are EMQX's
`/opt/emqx/data` and `/opt/emqx/log` anonymous volumes; reported to the EMQX lanes, not removed.)

## Checked by reading (no finding)

- **Privilege.** The engine runs Podman as the app owner (rootless); HA's server runs as uid 70 in the throwaway
  container (no capability, `no-new-privileges`). HA's rows enter the new cluster only through `COPY … FROM STDIN`
  of `woowbk_restore` (INSERT and sequence values only; dropped before the audit); the bootstrap superuser restores
  only this device's own pre-/post-data sections. Staging rows and the salt file are 0600 in 0700 folders
  (`O_EXCL|O_NOFOLLOW` for the salt). No HA string reaches SQL text: every statement uses this device's names
  (`IDENT_RE`), sequence values must be JSON integers.
- **Secrets.** The salt is masked for the whole job, never in argv, logs, errors or the page; the salt reader gets
  it back only in captured stdout. `import_manifest(secrets=…)` replaces only a secret the catalog declares, from
  one regular file of 1..511999 bytes; the other four LiteLLM secrets are read live. The product lane's evidence
  files hold fixed status lines only (scanned).
- **Rollback.** The restore's safety backup reads every secret live, so the automatic and the manual rollback put
  the own salt back with the own database (the product lane's real attempt 4 on `3bde418`: both PASS for salt and
  decryption; its own-state count FAILs were its probes' own spend logs, fixed in `db73107`).
- **Page.** `backup.js` renders the check's strings as text nodes (no `innerHTML` anywhere); HA-controlled names in
  messages are cut at 60 characters and at most 10 are listed (`hacommon.names`).

## Findings

1. **SR-1 (medium) — fixed `ad6745a`.** Code the HA database owner may create ran as the superuser in the engine's
   throwaway PostgreSQL 18: the engine's catalog queries call functions unqualified (`json_agg`, …) with the
   default search_path, and it read `public._prisma_migrations` without checking it is a table (with the view alone
   the check even passed with no blocker). Contained by the sandbox, but it turned a compromised HA LiteLLM into an
   OS shell (as postgres) inside every check and conversion of that backup. Fix: every
   session the engine opens there sends client options (`PGOPTIONS`, `HaSessions` in `start_ha_cluster`):
   `search_path=pg_catalog` and the settings below. Client options beat HA's per-database/per-role settings
   (`GucSource`: `PGC_S_CLIENT` > `PGC_S_DATABASE_USER` > `PGC_S_ARGV`, PostgreSQL `src/include/utils/guc.h`).
   `_prisma_migrations` is read only when it is an ordinary table (`MIGRATIONS_TABLE_SQL`).
2. **SR-2 (medium-low) — fixed `ad6745a`.** HA's per-database settings beat the command-line hardening (so the
   docstring's "every library/command setting overridden" was not true for them) and changed the exported rows
   silently. Fix: the sessions pin `DateStyle=ISO,MDY`, `IntervalStyle=postgres`, `extra_float_digits=3`,
   `client_encoding=UTF8`, `bytea_output=hex`, `TimeZone=UTC`, `standard_conforming_strings=on`,
   `local_preload_libraries=` (and, for the superuser, `session_preload_libraries=`), as pg_dump does for its output.
3. **SR-3 (low-medium) — fixed `ad6745a`.** Event triggers fired before the "superuser objects" refusal. Fix:
   `-c event_triggers=off` on the server command line and in every superuser session (PostgreSQL 17+). The salt
   reader, a role without privileges, gets only the settings any role may set (with `event_triggers` it could not
   log in).
4. **SR-4 (low) — fixed `ad6745a`.** `tablespace_map` bypassed the symlink refusal (PostgreSQL makes the links
   itself). Fix: `scan_member` never streams `backup_label` or `tablespace_map` into the volume and the verdict
   refuses them (a cold HA backup — the add-on is `backup: cold` — has neither).
5. **SR-5 (medium, semantic) — disclosure added `d31c59a`; refusing is an owner decision.** With
   `store_model_in_db: true` (Woow_podman_litellm `dd690ae` `config/config.yaml:6`) LiteLLM applies HA's stored
   settings at every start: `environment_variables` are decrypted with the moved salt and put into `os.environ`,
   `litellm_settings` callbacks are loaded (litellm 1.104.0 `litellm/proxy/proxy_server.py`
   `_update_config_from_db` :7741-7793; only `s3://`/`gcs://` module URLs are refused, :4486-4513). A foreign
   backup could set `HTTPS_PROXY` or a logging callback and receive this device's future LLM traffic. The check now
   warns and the import notes name the variable and callback names (never a value); nothing is refused, because
   the owner's own HA settings are meant to move.

6. **SR-6 (high for a foreign backup) — refused `1e29974`.** Some stored settings are code: LiteLLM's
   `get_instance_fn` imports ANY dotted path (`litellm/proxy/types_utils/utils.py:9-52`: `importlib.import_module`
   + `getattr`). `litellm_settings.post_call_rules: "builtins.exec"` becomes `litellm.post_call_rules`
   (`proxy_server.py:6193-6194`, reached from the DB overlay through `get_config` :5805-5825 → `load_config`
   :6048-6063) and is called with every model response text (`litellm/litellm_core_utils/rules.py:41-46`); the
   `general_settings` `custom_*` hooks and dotted callbacks load the same way; the DB overlay refuses only
   `s3://`/`gcs://` for them (:4494-4513). A crafted HA backup could make this device's LiteLLM run code with its
   master key, database URL and salt, on the Hermes and OpenDesign networks. The check refuses and the conversion
   stops (before reading HA's rows or capturing this device's schema) when any of these is stored; plain
   integration names stay an SR-5 warning. The real showcase backup has none (no blocker).

Every public refusal stayed; no check was weakened or skipped. Each SR-1..SR-4 regression test
(`SecurityReviewTests`) fails on `3bde418` and passes on the fix; SR-5/SR-6 have `StoredSettingsTests` (the two
SR-6 tests fail when the refusal is removed).

## Tests

- `tests.backup.test_ha_litellm`: 35/35 on the final fix (9 new: `SecurityReviewTests` ×4, each failing on
  `3bde418`; `StoredSettingsTests` ×5). With `test_ha_litellm_candidate`, `test_adapter_import_secrets` and
  `test_ha_odoo`: 82 OK.
  Lab unit tests `test_litellm_full_flow`, `test_litellm_real_ha`: OK.
- Full `tests/backup` on `d31c59a` (host-heavy lock): 1490 tests, only the 7 pre-existing `test_ha_omnigent` failures
  (5 failures, 2 errors; the same 7 as on `d812699` and `3bde418`, lane omnigent-product), 6 skipped. The later
  SR-6 change (`1e29974`: `ha_litellm.py` and `test_ha_litellm.py` only) was run with the affected modules (82 OK),
  not with a second full suite.
- The product's mutation check (`tests/backup/litellm_product_mutations.py`) with 11 new mutations M34–M44 (one per
  protection of SR-1..SR-6): first run (M34–M41, on `50622c3`) 40/41 caught — every new mutation caught; M19's
  text had to follow `ha_server_args`' new last line (same mutation, `7b2401c`). On the final tip (`4b70d09`,
  `ha_litellm.py` `4eb30d9f…`) all 44 are caught, run as two subsets with `--only` (the host-heavy lock was taken
  by the integrator's page suite and six waiters): the review's 12 (`mutation-check-review-ids.json`, 12/12) and
  the product's other 32 (`mutation-check-product-ids.json`, 32/32); baseline 52 tests pass in both.

## Old guard

The lab candidate's guard (`ha_litellm_candidate.GUARD`: schema and key compatibility unverified; conversion off
until a trusted schema, a secret transfer and real tests exist) still refuses in the candidate (its test passes).
The product path answers its finding: the schema is this device's own (captured in one snapshot, proven unchanged),
only HA's rows move through a role that may only insert, the salt binding refuses a mismatch, only the declared
`litellm-salt-key` can be replaced, and the product lane's real run on `3bde418` (attempt 4) decrypted 72/72 + 5/5
stored values with the moved salt (0 with a random one) and put this device's own salt and data back on both the
automatic and the manual rollback. That real proof was on `3bde418`; on the final review code (`1a83926`) the same flow passed 69/69 (iteration 2, `attempt-secreview-01.json`).

## Iteration 2 (2026-11-24): re-review of the final diff

Reviewed: the product branch's commits after the review merge `cdf6eba`: `3c1a0a4` (product: `key_users` also reads
the Pi agent provider list), `215fdf0` (product: search_path pin in every columns/signature read; the product lane's
READY line named `215fdf0`), `82e68ac`/`6c5610c` (driver and evidence only). `215fdf0` did not contain the review's
SR-6 fix (`1e29974`); the merge and the fixes below are on `review/litellm-secreview-fix2-20261124`. Fixed code:
`f2a2cb4` (`ha_litellm.py` SHA-256 `f81c9b46…`: SR-6 gaps, fail closed, SR-8), `a06dc21` (`72d6f9d8…`: SR-9) and
`1a83926` (`3a6e928e…`: SR-10, the final product code of this review). The fixes of this iteration are the
reviewer's own code (the product lane was waiting for a dev-d run); an independent look at them is welcome.

- **`215fdf0` (no finding).** It repairs a side effect of this review's SR-1 fix that the product lane's real attempt
  7 found: HA's pinned sessions rendered the enum column `LiteLLM_CronJob.status` as `public."JobStatus"`, this
  device's as `"JobStatus"`, so the check refused the owner's real backup (「資料庫結構不同」). The review's own
  real-backup sandbox run (`fixed-real-backup.json`) ran only HA's side and never compared with a live schema, so it
  could not see this. The pin only adds `SET search_path = pg_catalog;` to sessions; nothing is relaxed.
- **`3c1a0a4` (no finding; one nit).** `tests/e2e/lab/litellm_pi_models_review.py` ran the real `key_users` /
  `pi_agent_uses_litellm` / `pi_agent_sources` through the real owner file helper (`podman.FILE_HELPER`, as this lab
  user without `runuser`) on real volumes of the lab Podman store, every `models.json` holding generated canary key
  values: 14/14 as expected — a provider at this LiteLLM (also via `PI_CODING_AGENT_DIR=`, a `%h/` folder, a URL
  whose query is a canary) is named; another provider, a symlinked `models.json`, a symlinked folder, a FIFO (no
  hang: `O_NONBLOCK` + `fstat`), 2 MiB (too large), 100000 nested arrays, invalid UTF-8, `%h/../..`, `/etc`, an
  option-like volume name: not named or never read. The canary values were found nowhere (return values,
  `key_users_line`, the job log, the harness output); the only Podman call was `volume inspect`
  (`pi-models-215fdf0.json`; `fixed2-pi-models.json` ran while this README had uncommitted edits, hence its `harness_tracked_changes: true`; `fixed4-pi-models.json` on the clean final `1a83926`). Nit: `models_use_litellm` lets `RecursionError` escape;
  `key_users` then skips that app (no reminder for it) — harmless. The whole file (at most 1 MiB) is parsed in
  memory; only the base URL fields are looked at and nothing is kept.

New sandbox cases (`litellm_sandbox_review.py`, same sandbox as above):
- `stored_variants`: one clean HA cluster whose `LiteLLM_Config` is rewritten between runs of the product's
  stored-settings check, one variant per vendor code key, plus ~1M environment-variable names (an answer over 16 MiB),
  a real psql timeout (the query's timeout scaled down to 0.05 s by a wrapper; the same `TimeoutExpired` path as the
  600 s one) and controls. The rows differ only in that table, so one cluster stands for one backup per variant.
- `t2_hidden_hooks`: a crafted data directory with `post_call_rules` and `custom_auth` = `builtins.exec` whose
  superuser pointed the built-in operator `=(text,text)` at a SQL function answering "not equal" for those key
  names (`pg_operator.oprcode`). The first variant edited `pg_proc` of the built-in `jsonb_each` instead: no effect,
  PostgreSQL calls built-in functions by OID without reading `pg_proc` (`original2-t2_pgproc_edit.json`, kept). The
  case also loads the staged `LiteLLM_Config` rows into a fresh PostgreSQL 17.11 (the package's image, `COPY … FROM
  STDIN` like `load_rows`) and runs the same check there.

| Attack (real PostgreSQL 18.7 sandbox) | Review tip `4d7d9bf` (`4eb30d9f…`) | Fixed `f2a2cb4` (`f81c9b46…`), `a06dc21` (`72d6f9d8…`), `1a83926` (`3a6e928e…`) |
|---|---|---|
| `custom_provider_map[].custom_handler`, `guardrails` v1 callbacks, v2 `litellm_params.guardrail`, `pass_through_endpoints[].target` = `builtins.exec`, `litellm_jwtauth.custom_validate`, a string `callbacks`, `router_settings.plugins` | **no blocker** (7 of 7) | blocker naming the label (7 of 7) |
| A dotted `success_callback` entry after 60 plain names (sorted before it) | **no blocker** (also on `f2a2cb4`: the dot was looked for only in the first 50 names) | `a06dc21`: blocker `litellm_settings.success_callback` (`original3-`/`fixed3-stored_variants.json`) |
| `key_management_system: custom` + `key_management_settings.custom_secret_manager` | no blocker (by construction: not asked before `1a83926`) | `1a83926`: blocker `general_settings.custom_secret_manager` (`fixed4-stored_variants.json`) |
| ~1M stored environment-variable names + `post_call_rules` | **`None` → no blocker** (`limit-exceeded`) | blocker 無法完整讀取 |
| `post_call_rules` + a real query timeout | **`None` → no blocker** | blocker 無法完整讀取 |
| Controls: `post_call_rules`; plain `langfuse`/`otel`; a URL pass-through target; a string `success_callback` (iterated per character by the vendor, no import) | blocker; SR-5 names; nothing; nothing | same |
| Crafted `=(text,text)` operator (T2) | **check sees no hook** (no blocker, no superuser object, salt binding `match`); `export_rows` staged both hooks; the conversion asked the same blind question | the HA side is still blind (T2 controls that catalog); the same check on the staged rows in a fresh PostgreSQL 17.11 finds both hooks, which is what the conversion now asks after loading (refuses before the dump) |
| Iteration-1 cases (`owner_trojan`, `owner_view`, `superuser_catalog`, `tablespace_map`, `stored_settings`, `copy_injection`, 36 archive members, the real encrypted backup) | — | the same as iteration 1 (no marker, the same blockers, no link, nothing executed, the same 36 archive verdicts); the real encrypted backup: salt binding `match`, no blocker, no hook, not unreadable, 86 tables / 2882 rows exported, and the re-check on its staged rows in a fresh PostgreSQL 17.11: no blocker (`fixed2-real-backup.json` on `119ed71`; again on the final `1a83926`: `fixed4-real-backup.json`) |

Evidence: `original2-stored_variants.json`, `original2-t2_hidden_hooks.json`, `original2-t2_hidden_hooks-trusted.json`,
`original2-t2_pgproc_edit.json` (review tip `4d7d9bf`); `fixed2-*.json` (`f2a2cb4`); `original3-stored_variants.json`
(`f2a2cb4`, the SR-9 variant), `fixed3-*.json` (`a06dc21`) and `fixed4-*.json` (the final `1a83926`: stored variants
with the custom secret manager, crafted operator, stored settings, the real backup), `fixed5-stored_variants.json`
(`1a83926` with four edge shapes: an upper-case `HTTPS://` target stays a URL; a spaced or absolute-path module target
and a `custom_provider_map` object refuse; 20/20 variants as expected); `sr7-env-ref-probe*.json` (SR-7).
Each file's `source` names the clean commit and the `ha_litellm.py` SHA-256 it ran with.

Findings of iteration 2:

7. **SR-6 was incomplete (high for a foreign backup, like SR-6) — fixed `f2a2cb4`.** LiteLLM's `get_instance_fn`
   (`types_utils/utils.py:9-52`) is reached from more stored keys than `1e29974` refused — the rest of the vendor's
   own DB-overlay list (`proxy_server.py:4486-4640`): `litellm_settings.custom_provider_map[].custom_handler`
   (:6217-6231), dotted guardrail callbacks and types in both `guardrails` shapes (`guardrails/init_guardrails.py:
   101-160`, `guardrail_registry.py:580-618`), `general_settings.pass_through_endpoints[].target`
   (`pass_through_endpoints.py:1993-2001` tries every target as a module; a URL only falls back because its import
   fails), `general_settings.litellm_jwtauth.custom_validate` (`_types.py:5374-5378`); a string `callbacks` value
   (`common_utils/callback_utils.py:406-415`); and `router_settings.plugins` (:6722-6737 → `resolve_routing_plugins`
   :4767-4800), which the vendor's list misses although `router_settings` is a DB-overlay section (:5186-5193). And
   `stored_settings()` failed open: any read error returned `None` and gave no blocker. Fix: `NESTED_HOOKS` (one
   SQL/JSON path per place, labels only, never a value) refuse like the SR-6 hooks; an answer that cannot be read
   completely is `UNREADABLE` and refuses (fail closed).
8. **SR-7 (medium; owner decision) — not fixed.** HA's rows can make this device's LiteLLM send this device's own
   secrets to a host they name. Database model parameters are decrypted and then `os.environ/NAME` is resolved
   against this device's environment (`proxy_server.py:7119-7126`; a value that does not decrypt is used as plain
   text, `common_utils/encrypt_decrypt_utils.py:180-206`); the whole DB-merged configuration too (`get_config`
   :5815-5831 → `_check_for_os_environ_vars` :5508) and DB guardrails' `api_key`/`api_base`
   (`guardrail_registry.py:528-531`). This device's LiteLLM has `DATABASE_URL`, `LITELLM_MASTER_KEY`, `UI_PASSWORD`,
   `DATABASE_PASSWORD` and `LITELLM_SALT_KEY` in its environment (Woow_podman_litellm `dd690ae`
   `quadlet/litellm.container:32-38`). **Real proof** (`sr7-env-ref-probe.json`, `tests/e2e/lab/litellm_env_ref_probe.sh`):
   in a throwaway `--network=none` container of the package's LiteLLM lab build (`0c71bec8`, in dev-d, under the
   dev-d lock, 59 s, removed, isolation asserted), LiteLLM 1.104.0's own DB-model path (`ProxyConfig._add_deployment`
   → `Router` → one chat completion) sent the generated canary master key as the Bearer token to the row's
   `api_base` (a local fake provider) for a plaintext and for an HA-salt-encrypted reference (attempt 1 did not start:
   crun `setgroups` with the image user 65534, kept). Why only medium: the vendor's model API does not refuse `os.environ/`
   either (only a health test endpoint does, `health_endpoints/_health_endpoints.py:87`, :2120-2125), so any LiteLLM
   proxy admin can do this by design, and the import makes HA's admins this device's admins by design (residual
   risk); what the import adds is that it needs no network path to this device. Recommendation (owner decision):
   refuse references to the package's own secret names and warn with the names of others; seeing encrypted values
   needs decryption with HA's salt (for example in a throwaway `--network=none` container of this device's LiteLLM
   image, only names leaving it).

9. **SR-8 (high for a crafted backup) — fixed `f2a2cb4`.** The SR-6 refusal was decided only inside HA's throwaway
   cluster, whose catalog HA's data directory controls (`SUPERUSER_SQL` lists no SQL functions or edited built-in
   operators, and operators are used by OID whatever search_path says). Fix: after HA's rows are loaded, the
   conversion asks the same question in the new cluster (this device's image and schema, HA's data only as rows),
   refuses there before the converted dump is written, and the import note names what that answer found. The check
   job (HA's side only) can still be blinded by a crafted data directory; the conversion cannot.
10. **SR-9 (high for a foreign backup, like SR-6) — fixed `a06dc21`.** The SR-6 check cut the callback names to the
   first 50 before it looked for a dot, so 60 plain `success_callback` names that sort before a dotted one hid it
   (no blocker on `f2a2cb4`, `original3-stored_variants.json`; `1e29974` has the same code). LiteLLM imports every dotted entry of `success_callback`,
   `failure_callback` and `audit_log_callbacks` (`proxy_server.py:6233-6300`) and of `callbacks`
   (`callback_utils.py:150-395`) and accepts plain names there, so the padding is cheap. Fix: the query returns
   `litellm_settings.<list>` for any entry with a dot, however many names come first.

11. **SR-10 (low-medium) — fixed `1a83926`.** `general_settings.key_management_system: custom` with
   `key_management_settings.custom_secret_manager: "<file>.<Class>"` makes LiteLLM load `<config dir>/<file>.py` (or
   an absolute path) with `exec_module` at every start (`secret_managers/custom_secret_manager_loader.py:30-75`,
   from `initialize_secret_manager` `proxy_server.py:6981-6987`, which `get_config` calls on the DB-merged
   configuration :5815-5831 → :5550-5590); not in the vendor's scrub list. It needs a `.py` file that already exists,
   hence the lower weight, but it is a stored setting that runs code: it refuses like the others.

### Real end-to-end flow on the final code (iteration 2)

`tests/e2e/lab/evidence/litellm-product-20261123/attempt-secreview-01.json`: the product lane's own driver
(`litellm_full_flow.py --run` through `services_a_capture.py`) run by this review from the clean tree `14be8bc`
(product code `1a83926`, `ha_litellm.py` `3a6e928e…`) on dev-d with the owner's real encrypted LiteLLM HA backup,
2026-11-24 01:12-01:45: **exit 0, 69/69 PASS** (2033 s, dev-d lock held 1690 s after a 342 s wait). Package install,
this device's own data, upload, `ha-check` (no blocker: salt bound, data shape equal, 1/1/24, PG 18 → 17),
`ha-convert` (the conversion now also asks the stored-settings question in the new cluster — no false refusal on
the real backup), inspect, the automatic rollback of an injected failing import (own salt, data and key back, own
values decrypt), the import (HA's test key `/key/info` 200, every stored provider value decrypts with the moved
salt and none with a random one, `litellm-salt-key` and the database salt are HA's while the master key, UI and
database secrets are unchanged, this device's own key replaced, the live schema is this device's), restart (the
same checks again), the manual rollback (own state back), no registered value in the engine records, cleanup and
dev-d isolation `true none {}`. This is the real proof of the fixed code; `commercial_acceptance` stays
`not-complete` (one run, one device, x86 only; the add-on is amd64-only).

### Tests (iteration 2)

- Review tip `4d7d9bf`: `test_ha_litellm` with `test_ha_litellm_candidate`, `test_adapter_import_secrets` and
  `test_ha_odoo` = 85 OK (iteration 1 wrote 82; the verifier's 85 is right).
- Final tip (`1a83926`): `test_ha_litellm` 46 OK — new in `StoredSettingsTests`: an answer that cannot be read
  refuses in the check and stops the conversion (`limit-exceeded`, `job-failed`), every vendor code place is in the
  query and its label refuses, the conversion decides again on what moved (asked in `hapg`, then in `ll-db`; stops
  before the converted dump is written), the import notes name what moved; the old expectation that an unreadable
  answer only drops the warning line now also expects the blocker (it encoded the fail-open). With the candidate,
  adapter-secrets and `test_ha_odoo` tests: 96 OK. Lab `test_litellm_*`: 20 OK.
- Full `tests/backup` on `a06dc21` (host-heavy lock, 422 s): 1503 tests, only the 7 pre-existing `test_ha_omnigent`
  failures (5 failures, 2 errors; Omnigent's guard, lane omnigent-product), 6 skipped. `1a83926` changed only the
  stored-settings query, its tests, the mutation list and the docs; it ran with the affected modules (96 OK), not with
  a second full suite.
- Mutation check (`tests/backup/litellm_product_mutations.py`): on `f2a2cb4` 56/56 caught (baseline 63 tests;
  `mutation-check-f2a2cb4.json`); on the final `1a83926` (`ha_litellm.py` `3a6e928e…`): **58/58 caught** (baseline 63 tests, 597 s, from a clean throwaway worktree at `1a83926`; `mutation-check-1a83926.json`). New: M48–M58 (fail closed ×2, the unreadable
  blocker, the nested labels, router plugins, dotted guardrail callbacks, string callbacks, the re-check in the new
  cluster, the notes from it, the dotted-callback clause, the custom secret manager). M43's text now names its line
  (the re-check repeats the old text; same removal); the product's Pi agent and search_path mutations are M45–M47.

## Residual risk

- **A crafted data directory (T2) still runs SQL as the superuser inside the throwaway PostgreSQL 18** (it can point
  built-in operators or type output functions at its own functions). Containment is the sandbox above. Its `/tmp`
  is exec-able; mounting the tmpfs folders `noexec` would need a change in the shared `tempctr` (all importers), so
  it is a recommendation, not done here.
  Iteration 2 made the consequence concrete (SR-8): the check job's answers about HA's stored settings can be
  blinded by such a catalog; the conversion therefore asks again in the new cluster, as it already re-checked the
  salt row, the counts, the migrations and the schema signature there. The check job's warnings and blockers about
  stored settings remain advisory under a crafted data directory.
- **Other stored objects HA's data brings that LiteLLM runs or sends data to (trust model, not refused):** the
  guardrails table (`LiteLLM_GuardrailsTable`) is loaded at every start without a config path
  (`proxy_server.py:8536-8575`), so custom (dotted) guardrail types cannot load modules from it, but a `custom_code`
  guardrail runs HA's source in a RestrictedPython sandbox with HTTP primitives and may rewrite requests and responses
  (`guardrail_hooks/custom_code/custom_code_guardrail.py:118-166`, `sandbox.py`, `primitives.py:450-660`; no escape
  was tried); other guardrail types, MCP servers and pass-through URLs send this device's traffic to the hosts HA's
  rows name. Recommendation: name them in the check like SR-5 (owner decision).
- **SR-7** (above, proven on a real LiteLLM 1.104.0): `os.environ/` references in HA's rows resolve against this
  device's environment and are sent to the hosts HA's rows name (this device's master key in the probe); owner
  decision.
- **Stored environment variables bypass the vendor's own blocklist:** a config file may not set `PATH`,
  `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`, `HOME`, `NO_PROXY`, …
  (`proxy_server.py:5924-5939`), but the database path skips only the MCP stdio flag (:7347-7372). SR-5 names them
  in the warning; refusing these names would be the stricter choice (owner decision).
- **The same SR-1..SR-4 class is in the shared code the Odoo and Omnigent imports use**
  (`ha_odoo.start_ha_cluster` / `ha_odoo.Cluster` without client options; unqualified catalog queries as the
  superuser on HA's catalog). Not changed here (other lanes' code); noted for them.
- Importing HA's LiteLLM data trusts it like a LiteLLM admin: users and roles, virtual keys (budgets, expiry),
  guardrails (`litellm_settings.guardrails` and the guardrails table: not checked here) and other stored
  `general_settings` (SR-5 names env vars and callbacks, SR-6 refuses the module hooks), and the models with
  their `api_base`, stored provider credentials and ChatGPT subscription sign-ins: after the import this device's
  apps send their requests to the providers and accounts HA's data names (the notes say the models and credentials
  are replaced; the check counts the ChatGPT sign-ins). Only import a backup you made yourself.
- The salt binding proves the salt file is the database's stored salt, not that every stored value decrypts (the
  real run proved it for the real backup).
- No quota on the throwaway volumes: the job watchdog (free space every 2 s, floor = running reserve + 512 MiB,
  HA-SEC-04) is the limit; not re-tested here (filling the production host's disk is not allowed).
- The live schema capture keeps one REPEATABLE READ snapshot and an ACCESS SHARE lock on the live
  `_prisma_migrations` until it ends (idle limit 3 h): robustness, not security.

## Not covered

- Kernel or container escapes; PostgreSQL 18 bugs reachable with crafted data pages (no page fuzzing).
- The arm64 PostgreSQL 18 image (`d4e55489…`).
- Iteration 1's note that the real end-to-end flow had not run on the fixed tip is superseded: it ran on the final
  code in iteration 2 (69/69 PASS, above).
- The page was checked by reading (`backup.js` builds text nodes only, no `innerHTML`), not fuzzed.
- LiteLLM application bugs that stored data could trigger in the proxy itself.
- RestrictedPython escapes from a `custom_code` guardrail; SR-7 beyond the model path (the DB-merged configuration
  and guardrail paths were read in the vendor source, not probed).
