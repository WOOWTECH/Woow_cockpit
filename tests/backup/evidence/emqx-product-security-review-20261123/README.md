# EMQX HA import (product path) — independent adversarial security review (2026-11-23)

Lane emqx-secreview (owner instance SR-OWNER-1942). Reviewed: the EMQX import code on
`integration/ha-import-batch1-20261123` (ae5420d: `ha_emqx.py`, `ha_emqx_acl_preservation.py`,
`ha_emqx_acl_path_proof.py`, `ha_emqx_settings.py`, the shared member reader `habackup.py`, `tempctr.py`) and the
emqx-product lane's product patch that removes the public guard `PRESERVATION_BLOCKER` (scratch
`product-engine.patch`, sha256 `442dd509…2954`; target preflight `target_static`, readback `import_check` /
`verify_restored`, `flows`/`archive`/`haimport` hooks). The product lane's READY commit `7449540` is reviewed below ("Final product diff").

Fixes: branch `sec/emqx-secreview-20261123` (local only, not pushed): **75aad7a** (SR-1, SR-2, SR-3),
**f397590** (SR-6) and **7b173af** (SR-7), on top of integration ae5420d. The product branch `feat/ha-import-emqx-product-20261123`
merged 75aad7a as its base (3bb261d) and, after this review flagged it, 7b173af (41ad5ef); its tip 9036688 has a
`backup-engine` byte-identical to the merged tree the final real runs here used (`merged`, tree 99b7cae).

## How it was tested

- The product's OWN code ran against real EMQX 5.8.9 brokers: `member_pass`/`scan_member`, `ha_broker`,
  `take_export`, `capture_target_seed`, `target_broker`, `restore_target_settings`, the readback — through the real
  `TempObjects` with an `OwnerRunner` whose executor runs only `labpodman` (a separate `--root`; the production
  `/usr/bin/podman` store is never used; the runner refuses any `podman run` without `--network none`).
- Image `docker.io/emqx/emqx:5.8.9`, copied out of dev-d's store (`podman save` of the image dev-d's woow-emqx runs,
  ID 3f60addfad2b there; re-encoded as OCI 1b8bcb217955, same layers). No dev-d mutation, no production access.
- "This device" is a stand-in broker in the lab store with the dev-d Quadlet profile (read-only): file ACL source,
  bootstrap CSV as a podman secret mount (`/opt/emqx/etc/woow-mqtt-bootstrap.csv`, uid 1000, 0400), Dashboard
  password as an env secret. Every credential is a generated throwaway value; the harness compares them inside the
  containers or in memory and prints booleans only.
- "HA" is a crafted add-on tar (`addon.json` + `data/emqx/...`) fed to the real `member_pass`; T7 uses the REAL
  batch-1 HA backups (x86 and ARM, EMQX add-on stopped, encrypted; key read in-process by the b1 harness reader).
- Harness: `tests/e2e/lab/emqx_secreview/` (`secrev_lab.py`, `t1`…`t8`). Evidence: the JSON files next to this
  README (one per attempt: exit code, stdout sha256, code identity, fixed result fields,
  `commercial_acceptance: not-complete`). Failed attempts are kept.
- Unit tests: `tests/backup/test_ha_emqx_security_review.py` (18, red without the fixes), EMQX suites +
  `test_ha_import` + `test_ha_flows` 177 OK, 0 blocked podman/ssh/sudo/systemctl calls (guarded runner).

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| SR-1 | High | B1-06 never fixed: HA's `cluster.hocon` can name a plugin staged under `certs/`; HA's broker loads and starts it (arbitrary Erlang + `os:cmd` as uid 0 in the throwaway) — also on the public CHECK path | fixed 75aad7a |
| SR-2 | High | Removing the guard reopens B1-02: a device ACL file in the data volume (where the Dashboard writes edited rules) is overwritten by HA's file ACL; all config/readback comparisons stay equal | fixed 75aad7a (fail closed) |
| SR-3 | High | Migrated connectors/authenticators with `file://` secrets read THIS device's bootstrap credentials and `/proc/self/environ` (Dashboard password) and send them to the server HA names | fixed 75aad7a |
| SR-6 | High | Migrated rule SQL `jq('env…')` exposes this device's env secrets (bypasses SR-3) | fixed f397590 |
| SR-7 | Medium | A migrated HTTP/JWT/LDAP/SQL authenticator or ExHook server would receive this device's own service logins (bootstrap passwords); vendor-proven, NOT reproduced end to end | refusal added 7b173af (defense in depth) |
| SR-4 | Low | The product readback hashes RAW config roots that contain env secrets (`dashboard.default_password`, `node.cookie`) into `import_check` | product lane (redaction), not on this branch |
| SR-5 | Low / info | HA's authenticator hash settings (e.g. `plain`) would apply to this device's bootstrap users, which the product re-attaches to HA's built-in authenticator | not exercised (T5 written, dropped for host load); residual |

### SR-1 — code execution in HA's broker (B1-06)

EMQX 5.8.9 starts every enabled plugin at boot from `plugins.install_dir`
(`apps/emqx_plugins/src/emqx_plugins_app.erl:31-33`, `emqx_plugins.erl:310-321,766-776,1023-1066`;
`code:load_file` is not stopped by `noexec`). The hardening commit e848015 (fix/b1-emqx-security) was never merged.
`check()` starts HA's broker before any blocker, so this was reachable on integration even with the guard.
A compromised HA broker can also forge the export that the candidate (which holds this device's secrets) imports;
the vendor import restores every known backup table it finds (`emqx_mgmt_data_backup.erl:706-747`).
Fix: `EMQX_PLUGINS__STATES=[]`, `EMQX_PLUGINS__INSTALL_DIR=/opt/emqx/plugins` (env wins over cluster.hocon) and
`/work` + log volumes `noexec,nosuid,nodev`.

### SR-2 — this device's ACL replaced by HA's (B1-02 reopened)

HA's export inlines HA's file ACL as `rules` (`emqx_authz_file.erl:64-65`); the import writes them to
`<data_dir>/authz/acl.conf` (`:69-75`, `:120-121`, via `validate_cluster_hocon` → `emqx_authz:maybe_write_files`).
When that file IS this device's ACL, `restore_target_settings` puts the same `path` back and every comparison is
equal, but the rules are HA's. Fix: every data-volume file of the target snapshot (except `configs/cluster.hocon`)
must be byte-identical in the finished candidate (sha256 only), else the conversion refuses
(`ha_emqx.SNAPSHOT_CHANGED`). Fail closed: such devices cannot import until a merge policy exists.

### SR-3 — device secrets through `file://`

`emqx_schema_secret.erl:74-77` / `emqx_secret_loader.erl:28-45`: a `file://` value is read on the running broker
at use time (path env-interpolated). Fix: any `file://` string or charlist in the roots HA's import brought
(DATA_ROOTS except this device's authorization) refuses the conversion (`ha_emqx.FILE_SECRET` names the roots).

### SR-6 — device env secrets through rule `jq`

`emqx_rule_funcs.erl:957-980` → `jq:process_json`; in a throwaway 5.8.9 broker `jq('env')`, `jq('$ENV')` and
`jq('env.NAME')` returned the process environment. The program can come from a message at run time, so any `jq`
token in the migrated `rule_engine` root refuses (`ha_emqx.JQ_RULE`). Rule `getenv` only reads `EMQXVAR_` names
(`emqx_variform_bif.erl:607-613`) and stays allowed.

### SR-7 — this device's service logins sent to HA's authenticators

HA's authentication chain migrates; only this device's bootstrap metadata is re-attached to the built-in database
authenticator, and this device's own services log in through that chain. An enabled HTTP authenticator posts
`${password}`; JWT/LDAP/SQL/Redis/MongoDB ones query outside; an ExHook server's `client.authenticate` hook carries
the password (`emqx_exhook_handler.erl:104,318-333`). Fix: the final candidate may hold only built-in database
authenticators (password_based or scram) and no enabled ExHook server (`ha_emqx.CREDENTIAL_RECEIVER`); disabled
leftovers stay allowed.

Real run (T8, device with the bootstrap CSV): the HTTP-authenticator backup was refused before SR-7's check by the
existing exact-equality check of the restored authentication root (「EMQX 匯入後未能保留目標有效設定」: EMQX's
`conf load` rewrites the raw HTTP authenticator), so the leak was not reproduced and that protection is accidental.
ExHook (outside the authentication root, so not caught by that check) was not exercised: it needs a gRPC server.
SR-7's refusal does not depend on EMQX's normalisation.

### SR-4 — readback hashes cover env secrets (product code)

Proven in a throwaway broker: `emqx:get_raw_config([dashboard])` has `default_password` equal to the env value and
`[node]` has `cookie` equal to the env value. The product's `config_roots` stores an unsalted SHA-256 per root in
`import_check`; a converted HA backup does not otherwise contain these podman secrets, so an unencrypted converted
backup gives offline brute-force material. Recommended (product lane): replace secret-named values before hashing.

## Final product diff (feat/ha-import-emqx-product-20261123 @ 7449540)

- **Was blocking (resolved by 41ad5ef):** `7449540` merged only 75aad7a; SR-6 (f397590) and SR-7 (7b173af) are missing, and SR-6 was proven
  for real on exactly that code state. `git merge-tree --write-tree 7449540 7b173af` is clean (tree 99b7cae); on that
  tree 426 tests pass (19 EMQX modules, test_ha_import, test_ha_flows, test_flows; 0 blocked). The product lane must
  merge `sec/emqx-secreview-20261123` and post a new READY.
- Kept: the SR-1 env pins and noexec on all three HA-broker volumes, SR-2's digest check after the settings restore,
  SR-3's refusal on the final candidate configuration.
- Owner decision C: `acl_blocker` refuses a file-only device with HA ACL rows at the check and again in
  `_build_candidate` before a candidate exists (`convert` always passes the profile from `target_profile`, which
  raises otherwise); the finished candidate must hold the same profile.
- SR-4: `redacted()` runs inside `config_roots`, used by the conversion readback and by `verify_restored`
  (secret-named keys, every `headers` value, URL user info). Over-redaction (`key`, `token` substrings) only lowers
  readback coverage.
- `archive.py`, `flows.py`, `haimport.py` hunks are the ones reviewed in the scratch patch. No new finding.

## Real attack and regression runs (lab store, `--network none`)

Each row is one attempt with its own JSON file here. "attack" rows ran the code without the fix and show the
exploit; "fixed" rows ran the same crafted backup on the fixed code. The real-backup rows are the regression on the
real batch-1 HA backups.

| Run | Result | Exit | Elapsed s | Evidence |
|---|---|---|---|---|
| SR-1 attack | HA broker started+exported; plugin ran: True | 0 | 125.0 | t2_plugin_exec-prodint.json |
| SR-1 fixed | HA broker started+exported; plugin ran: False | 0 | 159.8 | t2_plugin_exec-fixedprod.json |
| SR-2 attack | PASSED (candidate built, all product checks green); stranger before deny, candidate allow | 0 | 426.8 | t1_datadir_acl-prodint-data.json |
| SR-2 control (ro ACL) | PASSED (candidate built, all product checks green); stranger candidate deny | 0 | 456.9 | t1_datadir_acl-prodint-ro.json |
| SR-2 fixed | REFUSED: EMQX 不能搬過來：這台 EMQX 的 ACL 或憑證檔案放在資料卷裡（例如在 Dashboard  | 0 | 429.6 | t1_datadir_acl-fixedprod-data.json |
| SR-2 control rerun (flake) | no result JSON (the run failed); last line: BrokenPipeError: [Errno 32] Broken pipe | 1 |  | t1_datadir_acl-fixedprod-ro.json |
| SR-3 attack | PASSED (candidate built, all product checks green); CSV secret sent True, Dashboard password sent True | 0 | 448.0 | t3_file_secret_exfil-fixedprod.json |
| SR-3 fixed | REFUSED: EMQX 不能搬過來：HA 的 EMQX 設定（connectors）用「file://」讀取本機檔案 | 0 | 752.6 | t3_file_secret_exfil-final.json |
| SR-6 attack | PASSED (candidate built, all product checks green); republished: True (retained=1:leaked=1) | 0 | 766.4 | t6_rule_jq_env-final.json |
| SR-6 fixed | REFUSED: EMQX 不能搬過來：HA 的 EMQX 規則（1 條）使用 jq 函式；EMQX 的 jq 能讀取這 | 0 | 784.2 | t6_rule_jq_env-final3.json |
| SR-6 fixed, merged final code | REFUSED: EMQX 不能搬過來：HA 的 EMQX 規則（1 條）使用 jq 函式；EMQX 的 jq 能讀取這 | 0 | 306.5 | t6_rule_jq_env-merged.json |
| SR-7 HTTP-authenticator attempt on pre-SR-7 code (inconclusive: host-load timeout) | REFUSED: podman exec woowbk-secrev-t8-emqx emqx 執行逾時（120 秒）。 | 0 | 686.4 | t8_http_authn-final2-attempt1.json |
| SR-7 HTTP-authenticator attempt on fixed code (refused earlier by the existing authn equality check) | REFUSED: EMQX 匯入後未能保留目標有效設定，已停止。 | 0 | 673.3 | t8_http_authn-final3.json |
| Real x86 b1 backup, merged final code, device ACL file + built-in database | PASSED (candidate built, all product checks green); node emqx@127.0.0.1; rules 2; connectors 1; readback roots 44; profile ['file', 'built_in_database'] | 0 | 593.4 | t7_real_backup-merged-x86-builtin.json |
| Real ARM b1 backup, merged final code, device ACL file + built-in database | PASSED (candidate built, all product checks green); node emqx@127.0.0.1; rules 2; connectors 1; readback roots 44; profile ['file', 'built_in_database'] | 0 | 568.2 | t7_real_backup-merged-arm-builtin.json |

Mutation check of the fixes (scratch copy, each protection removed in turn, `test_ha_emqx_security_review`): all 7
removals were caught (plugin env pins, `/work` noexec, log noexec, digest check call, `file://` refusal, `jq`
refusal, credential-receiver refusal); baseline green after restoring (`mutation-check.json`).

## Attacks tried that held (no finding)

| Attack | Result | Evidence |
|---|---|---|
| 16 crafted add-on members through the real `scan_member`: absolute and escaping symlinks, hard link, `..`, absolute name, duplicate `cluster.hocon`, entry below a file, control characters, char/block devices, FIFO, PAX `path` traversal, setuid files in `certs/` and `mnesia/`, 8 MiB + 1 `cluster.hocon`, generated configs/plugins/patches | symlinks skipped, FIFO skipped, setuid neutralised (0600/0644, root), generated files never staged, every other case refused (corrupt-archive / limit-exceeded) | t4_members-fixedprod.json |
| HOCON pretty-printer injection between HA's export and this device's import (quote, triple quote, backslash, brace break, `${VAR}`, multi-line) | no injection: one root, exact round trip | vendor-probes.json |
| OS environment substitution while the import parses `cluster.hocon` | not resolved (`resolve_error`) | vendor-probes.json |
| Rule SQL `getenv` | only `EMQXVAR_` names (`emqx_variform_bif.erl:607-613`) | vendor source |
| jq `$__loc__`, `input_filename` | no environment | vendor-probes.json |
| HA `{allow, all}.` against a device ACL on a read-only mount (the dev-d profile) | device ACL still governs: stranger denied in the candidate; HA's file only lands unused in `data/authz` | t1_datadir_acl-prodint-ro.json |
| Readback record (`import_check`) | strict archive validator (kind/app, root-name regex, sha256 format); an unknown kind refuses the restore preflight; `verify_import` raises inside the health-check `try`, so a mismatch takes the existing automatic rollback | code review: archive.py `_import_check`, haimport.py `import_check_problem`/`verify_import`, flows.py `run_restore` |
| Secrets in logs, errors and the page | fixed zh-TW messages; `read_effective_config` never puts the body in errors (`from None`); the readback names roots/tables only; `ha_hosts` returns host names only (no URL user info) | code review |
| Secrets in the product lane's real-run harness | values pass through the b1 `Secrets` redactor; CHECK lines are fixed; a `leaks` step scans the evidence | code review of the draft harness |
| Privileges | throwaways are rootless, `--network none`, `no-new-privileges`, pids/memory limits; HA's broker read-only root, uid 0 inside the user namespace; the candidate runs as the image user | tempctr.py, ha_emqx.py, every run here |

## Residual risk and what was not covered

- **HA's broker still executes HA's configuration.** With SR-1 no plugin loads, but other boot-time loaders were not
  reviewed one by one (schema registry Protobuf/Avro compilation, LwM2M `xml_dir` XML parsing, durable storage). A
  compromised HA broker could still forge the export, and the vendor import restores every known backup table it
  finds (`emqx_mgmt_data_backup.erl:706-747`). Recommended defense in depth (not implemented): check the export's
  members (only the TABLE_SETS tables, `cluster.hocon` roots within DATA_ROOTS) before `data import`.
- **Migrated integrations are HA's by design.** HA's MQTT users, ACL rows, Dashboard users and API keys replace this
  device's; HTTP/MQTT connectors, actions and rules may publish to or call hosts HA's settings name, and a migrated rule
  sees every message on this broker (`SELECT * FROM "#"` + republish/forward reads this device's MQTT traffic); gateways may
  open listeners (reachable only through published ports; the dev-d Quadlet publishes on 127.0.0.1 plus the ngrok
  TCP listener). SR-3/SR-6/SR-7 only stop the paths that read THIS device's secrets. The check page lists HA-only
  hosts, not every external host; recommended: list every external host the migrated settings contact.
- Migrated `psk_authentication.init_file`, LwM2M `xml_dir` and TLS file paths may name files of this device (read
  locally; no path found that sends their content out; not exercised).
- SR-2 fails closed: a device whose Dashboard edited its ACL file cannot import until a merge policy exists.
- The throwaway brokers keep Podman's default capability set (no `--cap-drop`); HA's broker runs as uid 0 inside
  the rootless user namespace. Recommended: `--cap-drop=all` for `emqx-ha`.
- The ExHook/authenticator rule (SR-7) allows only built-in database authenticators; HA backups with an external
  authenticator or an enabled ExHook are refused (a later, reviewed migration could re-allow specific backends).
- **Not covered here:** Omnigent/LiteLLM SQL schema attacks (their own review lanes); the product lane's dev-d real
  flow with restore, readback and rollback on the device (product lane EP-OWNER-2045); ARM .54; the product lane's
  final diff (decision C blocker, SR-4 redaction) unless reviewed in the lane hand-off; the independent Hermes FTS
  review (separate). This review's real runs prove conversion behaviour in the lab store; they are not commercial
  acceptance (`commercial_acceptance: not-complete`).
