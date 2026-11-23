# LiteLLM HA import — independent security review (2026-11-23)

Reviewed: the LiteLLM product import of lane litellm-product, branch `feat/ha-import-litellm-product-20261123`
(R-COCKPIT), product code at `3bde418` (its later `db73107` changes only its lab driver and evidence), as the diff
against `integration/ha-import-batch1-20261123` (merge base `d812699`): `ha_litellm.py` (new),
`adapters/quadlet_postgres.py` (`import_manifest(secrets=...)`), `haapps.py`, `haimport.py`, `backup/backup.js`, the
docs, the unit tests and the lab driver. Reviewer lane: litellm-secreview (owner instance SR-OWNER-1942).

Fixes are on branch `review/litellm-secreview-20261123` (from `3bde418`; it also contains the product lane's final
`ce95602`): `ad6745a` (SR-1..SR-4), `d31c59a` (SR-5) and `1e29974` (SR-6); the attack harness is `2284e4d`,
`cd900c5`, `f474bb5`, `7cfb585` and the `stored_settings` case. Nothing was pushed.

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
  (5 failures, 2 errors; the same 7 as on `d812699` and `3bde418`, lane omnigent-product), 6 skipped.
- The product's mutation check (`tests/backup/litellm_product_mutations.py`) with 11 new mutations M34–M44 (one per
  protection of SR-1..SR-6): first run (M34–M41, on `50622c3`) 40/41 caught — every new mutation caught; M19's
  text had to follow `ha_server_args`' new last line (same mutation, `7b2401c`). Rerun of all 44 on the final tip:
  see the lane hand-off (team/litellm-secreview.md).

## Old guard

The lab candidate's guard (`ha_litellm_candidate.GUARD`: schema and key compatibility unverified; conversion off
until a trusted schema, a secret transfer and real tests exist) still refuses in the candidate (its test passes).
The product path answers its finding: the schema is this device's own (captured in one snapshot, proven unchanged),
only HA's rows move through a role that may only insert, the salt binding refuses a mismatch, only the declared
`litellm-salt-key` can be replaced, and the product lane's real run on `3bde418` (attempt 4) decrypted 72/72 + 5/5
stored values with the moved salt (0 with a random one) and put this device's own salt and data back on both the
automatic and the manual rollback. That real proof is on `3bde418`; on the fixed tip it is pending (below).

## Residual risk

- **A crafted data directory (T2) still runs SQL as the superuser inside the throwaway PostgreSQL 18** (it can point
  built-in operators or type output functions at its own functions). Containment is the sandbox above. Its `/tmp`
  is exec-able; mounting the tmpfs folders `noexec` would need a change in the shared `tempctr` (all importers), so
  it is a recommendation, not done here.
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
- **The product's real end-to-end flow on the fixed tip** (real encrypted HA backup → check → convert into
  PostgreSQL 17 → import → restart → rollback on dev-d, `litellm_full_flow.py`): not run on the fixed tip. The
  changed code (HA's cluster side) ran on the real backup in the lab sandbox (`fixed-real-backup.json`, no
  blocker); the PostgreSQL 17 side, the restore and the rollback did not change and passed on `3bde418` (lane
  litellm-product attempt 4). dev-d was held by other lanes' real runs and the host load stayed at 45-170 this
  evening; the product lane measured that LiteLLM's restore readiness needs a load below about 30.
- The page was checked by reading (`backup.js` builds text nodes only, no `innerHTML`), not fuzzed.
- LiteLLM application bugs that stored data could trigger in the proxy itself.
