# EMQX HA import (product path) — independent adversarial security review (2026-11-23 and 2026-11-24)

Lane emqx-secreview (owner instance SR-OWNER-1942), seven iterations. This review attacked the product import as a
malicious HA backup would, fixed what it could prove, and reran the attacks against the engine that is handed over.

## Summary (read this first)

- **Eleven findings, SR-1 to SR-11.** Five High/Medium findings were confirmed by real attacks and fixed (SR-1, SR-2, SR-3,
  SR-6, SR-8); SR-7 (Medium) is a refusal added because the vendor code proves the leak, its ExHook trigger is
  exercised by T12 (iteration 2); SR-4 and SR-9 are Low and fixed. **SR-5 (Low): iteration 4's clear-text claim is disproven** by three real
  conversions with HA's `plain` authenticator and a same-hash control (Iteration 5): this device's bootstrap password is never stored in
  clear text. **The owner decided SR-5 on 2026-11-24 15:26 (option C):** the check page warns and names this device's
  MQTT accounts that stop working, and HA's `plain` is refused at check time; lane emqx-sr5 implemented it (`3c857c3`).
  **Iteration 7 re-reviewed that change and found SR-11 (Low):** `plain` outside the global chain (an MQTT listener's
  or a gateway's built-in database) and rows HA still keeps in clear text passed the refusal and reached the
  candidate as clear text (real attack, 3 of 3); fixed on `sec/emqx-secreview7-20261124` (`9665533`).
  **SR-10
  (Low) was found in iteration 4** in exactly the handed-over tree 865c930f and is fixed on the integration branch
  only (65d8a51, 97c994f): a C0/C1/bidirectional/line-separator character in an HA plugin name, a `/share` path or a
  skipped-symlink name reached a check warning raw or forged a second job-log line.
- **Where the fixes are:** SR-1, SR-2, SR-3 75aad7a; SR-6 f397590; SR-7 7b173af; SR-4 in the product's own 7449540; SR-8 and
  SR-9 abff1a0 (all in the handed-over engine 865c930f, the last merged as 620bdd5). SR-10 is on the integration branch
  (65d8a51, 97c994f), NOT in 865c930f. SR-5: owner decision C, implemented by lane emqx-sr5 (`74d237f`, engine `5142e05c`); SR-11: `9665533` (engine `3ea9610f`, Iteration 7).
- **Engine reviewed in iteration 3:** `feat/ha-import-emqx-product-20261124` @ `e08f8a1` (product READY of 08:30), `backup-engine` tree `865c930f392006e0080de506eb7c425fd81becd7` = the product tip `5786ae4` + `abff1a0` (merge `620bdd5`) + the Podman 6 tempctr fix (cherry-pick `e08f8a1`, patch id equal to `8613ffa` and `c8df1f2`); the review reruns used the same tree as trial commit `cd66230`.
- **What passing here means:** this review proves conversion and refusal behaviour of the product's own code against
  real EMQX 5.8.9 brokers in throwaway rootless lab containers with `--network none`. It is not the commercial
  acceptance; the product lane's dev-d chain and the .54 runs (Podman 6.1.1, ARM and x86 backups) are the product flow
  evidence. `commercial_acceptance: not-complete`.
- **Not covered:** see the last section. Items that need a human/owner: the boot-time behaviour of HA's throwaway
  broker on HA's own files (reviewed only in part, one analysis step stopped by a safety classifier in iterations 3
  and 4 — a human item, not retried). Decided by the owner on 2026-11-24 15:26: SR-5 = option C (implemented) and
  Dashboard-edited ACL files = option A (keep refusing, a known limitation). The independent Hermes FTS/SQLite review
  is NOT open: the main session did it on 2026-11-23 (`tests/backup/evidence/hermes-fts-security-review-20261123/`).
- **Iteration 4** worked on the independent verifier's points against iterations 1-3: SR-10 found and
  proven (fixed at integration), SR-5 reopened, B1-03 named, a first export check, and the overclaims corrected (what T4/T10/T11 really
  ran, that an exit code of 0 is not a verdict, the hard-coded `candidate_env_file_flag`, 6 of 24 volumes attributed
  by timing only, the follower ended by main at 08:14, the first T9/T10 runs with no attempt JSON, and the host-wide
  Podman event dump that iteration 2 kept and main deleted). See **## Iteration 4**.
- **Iteration 5** reviewed iteration 4's own work and found three things wrong in it: its export check (bcb6245, never
  merged) could be passed by a crafted export, its SR-5 statement was disproven by the real run, and its B1-03 "proof"
  was partly true by construction. The check was rewritten with the vendor's own parsers and proven with the real x86
  and ARM HA backups; B1-03 has real runs (T13). See **## Iteration 5**.
- **Iteration 6** harvested the runs iteration 5 left running (T13 on the integration tip, a second x86
  run, both mutation runs, a second unit run), read the rewritten check again as an attacker, added T14b (more archive
  shapes and a `hocon:binary` vs `hocon:files` differential) and handed the check over as READY (`dd3ae49`). See
  **## Iteration 6**.
- **Iteration 7 (this revision)** re-reviewed SR-5 option C (`fix/emqx-sr5-hash-warning-20261124` @ `3c857c3`): no
  password, hash or salt in any text, names sanitized, `plain` refused before HA's export, this device only read,
  the lane's dev-d evidence as claimed; T5/T5b rerun; SR-11 found, proven for real, fixed and rerun. See
  **## Iteration 7**.

## How it was tested (all iterations; details of iteration 1)

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
| SR-7 | Medium | A migrated HTTP/JWT/LDAP/SQL authenticator or ExHook server would receive this device's own service logins (bootstrap passwords); vendor-proven, the HTTP path was not reproduced end to end (stopped earlier by the authentication-equality check) | refusal 7b173af; its ExHook trigger is exercised for real by T12 (iterations 2 and 3) |
| SR-4 | Low | The product readback hashed RAW config roots that contain env secrets (`dashboard.default_password`, `node.cookie`) into `import_check` | fixed by the product lane (redaction, in 7449540); reviewed in iteration 1, unchanged since |
| SR-5 | Low | HA's authenticator hash settings (e.g. `plain`) also govern this device's bootstrap file, which the product re-attaches to HA's built-in authenticator (`preserved_bootstrap_authn`). Iteration 4 claimed that this device's bootstrap password is then stored in clear text. **Disproven** by three real conversions with `plain` and an explicit `salt_position` plus a same-hash control (Iteration 5): one row, not equal to the password, also after a restart: the candidate wrote that row under this device's OWN authenticator at its boot and a bootstrap import never overwrites a row (`emqx_authn_mnesia.erl:556-565` `override => false`, `:346-362`). What remains: after the import this device's own bootstrap MQTT account is refused (the conversion note `hash_differs` names it), and a bootstrap row written later (a new user in a `plain`-type bootstrap file, or a deleted row) is hashed with HA's algorithm (`:113-127`, `:528-545`; verbatim for `plain`, `emqx_passwd.erl:104`; vendor reading, not run). | clear-text claim disproven (T5b). Owner decision 2026-11-24 15:26: option C, implemented by lane emqx-sr5 (`3c857c3`, engine `5142e05c`), re-reviewed in iteration 7 (T5/T5b/T15: as decided, except SR-11) |
| SR-8 | Medium | 3761d18: the device's `EnvironmentFile=` values reached a world-readable command line of the candidate | fixed abff1a0, reproduced and verified for real (T9) |
| SR-9 | Low | 3761d18: the candidate's environment was not read the way podman reads it for the broker | fixed abff1a0, verified against podman (T10) |
| SR-10 | Low | A C0/C1/bidirectional/line-separator character (e.g. U+202E, U+2066, U+0085, U+2028) in an HA EMQX plugin name, a `/share` file reference or a skipped-symlink name reached a check warning raw, or forged a second job-log line, in the handed-over tree 865c930f | fixed on the integration branch only (65d8a51 `hacommon.names`; 97c994f the twelve bidi controls in names and `jobs.LOG_CONTROL_RE`); NOT in 865c930f. Proven in process: forged=True on 865c930f, forged=False on the integration tip (Iteration 4) |
| SR-11 | Low | SR-5 option C refuses `plain` only in the global chain (`HASH_EXPR` reads `[authentication]`). A `plain` built-in database of an MQTT listener or a gateway, and rows HA wrote under `plain` before it changed the algorithm, passed the check and the conversion; the export carries the whole `emqx_authn_mnesia` table (`emqx_authn_mnesia.erl:105`) and the `gateway` root is a data root, so the candidate held HA's passwords in clear text (real: 3 of 3, `iteration7/t15-sr5b.json`), against the owner's 「不會留下明文密碼」 | fixed `9665533` (`PLAIN_EXPR`, refused at the check and before HA's export; real: 3 of 3 refused, `iteration7/t15-fix7.json`) |

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

## Iteration 1: final product diff (feat/ha-import-emqx-product-20261123 @ 7449540)

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

## Iteration 1: real attack and regression runs (lab store, `--network none`)

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

### Corrections to iteration 1's own claims (independent verifier, 2026-11-23 22:42, and iteration 2/3)

| Claim of iteration 1 | What is true |
|---|---|
| "5 fixed and verified by real attacks" | SR-7 was never exercised for real in iteration 1: the HTTP-authenticator run was refused earlier by another check and ExHook was untested. Iteration 2 ran the ExHook case for real (T12, refused naming ExHook); the HTTP-authenticator path is still stopped by the earlier check, not by SR-7's own refusal. |
| "No lab leftovers" | 24 anonymous EMQX data/log volumes of 20:02 to 22:07 stayed in the lab store (one held this lane's `secrev-*.hocon` probe files). Listed and removed by name in iteration 2; none left (checked again in iteration 3). |
| T7 (real backups) covered the decision-C and profile checks | T7 called `_build_candidate` with `profile=None`. T11 (iterations 2 and 3) runs it with this device's profile. Packaging, restore, readback and rollback stay product-lane evidence (dev-d). |
| SR-2 control with a read-only ACL on fixed code | That run failed with BrokenPipe and was not rerun; iterations 2 and 3 rerun it (PASSED, stranger denied). |
| `vendor-probes.json` | A hand-written summary of vendor probes; it has no exit code and no stdout hash. |
| stdout hashes | Three iteration-1 attempts (SR-1 attack, SR-2 attack, T4) printed their result in the session and were not saved; their JSON has no stdout hash. The reruns of iterations 2 and 3 have one. |

## Iteration 2 (2026-11-24): the product delta since the 21:52 review

Reviewed: `feat/ha-import-emqx-product-20261123` from 9036688 (the tree iteration 1 approved) to 7d9d468: 28e9492
(boot-form comparisons), 3761d18 (`EnvironmentFile=` into the candidate), fdb7cfe and 0d260db (refusals name the
differing roots; a root loaded back is compared in this device's boot form), 92f2461 and be2c92d (the candidate starts
with this device's scheduler counts, `ERL_AFLAGS`), be5bc6f (HA's broker mounts a job volume at `/opt/emqx/data`),
7d9d468 (docs). `backup-engine` of 7d9d468 == 0d260db == tree 5292c15 (the engine of the product lane's dev-d attempts
12-14). Fix branch: `sec/emqx-secreview2-20261124` (local only): **abff1a0** (SR-8, SR-9) on 7d9d468, plus a merge of
the iteration-1 branch (cad50dd) for this README.

### SR-8 (Medium) — the device's EnvironmentFile values on a command line (3761d18) — fixed abff1a0

3761d18 read the Quadlet's `EnvironmentFile=` files and passed their `EMQX_*` values to the candidate as
`podman run --env KEY=VALUE`. Such a file may hold secrets (the product backs it up as a 0600 config file, CONTRACT
`config_files`; a customer may keep `EMQX_DASHBOARD__DEFAULT_PASSWORD` or `EMQX_NODE__COOKIE` there), and every local
account can read every process's command line (`/proc/<pid>/cmdline` is 0444; this host has no `hidepid`). It broke
the runner's rule (`podman.py:9-10` "Secrets and keys never appear in argv") and tempctr's own (`run_argv`: an `env`
value is never a secret). The device's own broker never exposes them: Quadlet passes `--env-file`.
**Real run T9** (lab store, `--network none`, generated canary in a 0600 env file, the product's `Target.candidate_env()`
+ `TempObjects.run('emqx-new', …)` exactly as `target_broker` calls them, a sampler reading every
`/proc/<pid>/cmdline`): on 7d9d468 the canary was in world-readable command lines of the podman processes while the
candidate started (2 in the first run, 1 in the recorded rerun; the sampler saw the `podman run` command line itself in
every run); the device's way (`--env-file`) put it in none; both containers received the value. On abff1a0: 0, and the
candidate still received the value. Exposure needs a local account on the device during each conversion; the product's
own package keeps its secrets in Podman secrets (passed by name), so dev-d was not exposed.
**Fix:** `tempctr.run_argv(env_files=…)` passes `--env-file <absolute plain path>` (no empty, `.` or `..` component);
`Target.candidate_env()` returns `(env, env_files)` and `target_broker` gives podman the device's own files, which podman
reads for the candidate exactly as for the running broker. Every refusal of 3761d18 stays (quotes, backslashes, `$`,
blanks, conflicts, files outside the owner's home). The candidate's `ERL_AFLAGS` stays on `--env`: real podman 4.9.3
applies `--env` over `--env-file` in either order. Behaviour change: the candidate now also gets the file's non-EMQX
lines, as the device's broker does (they configure nothing in EMQX; `getenv` in rules only reads `EMQXVAR_*`, which the
restored broker exposes to the same rules anyway, and no rule runs in the candidate: no client, `$SYS` ticker quiesced).

### SR-9 (Low) — the candidate's environment was not the broker's (3761d18) — fixed abff1a0

`candidate_env()` split lines with `str.splitlines()` and trimmed every Unicode blank; podman splits at `\n` only (a
final `\r` dropped) and trims blanks and tabs. **Real run T10** (podman 4.9.3 as the oracle: `--env-file` + `env -0` in
the image, 25 crafted files of generated values): on 7d9d468 13 of 25 files gave the candidate another environment than podman gives the broker (a separator character inside a value, a leading non-ASCII blank, an `export ` line), 10 the same, 2 refused (an empty value, a blank before `=`); mostly the boot-form comparison then refuses
(fail closed), but the claim "exactly what the running broker got" was false. On abff1a0, where podman reads the
files itself and the started candidate's environment is compared: 23 of 25 the same and the same 2 refused.

### Regression tests and mutation checks

- `tests/backup/test_ha_emqx_security_review2.py` (7 tests): no podman command line of a whole conversion holds an
  EnvironmentFile value, the file goes with `--env-file`, lines are read as podman reads them, `env_files` paths are
  checked. Two product assertions encoded SR-8 and now assert the opposite (EnvironmentFileTests,
  ConvertReadbackTests). The fake podman knows `--env-file`.
- EMQX modules + harness + lab candidate: 222 OK, 0 blocked (guarded runner). Shared modules that use the changed
  fakes or tempctr: 162, only the 7 known `test_ha_omnigent` SECURITY_BLOCKER refusals, identical on 7d9d468.
- Mutations of the fix: 7/7 killed (values back on `--env`, `splitlines()`, Unicode `lstrip()`, unchecked paths, no
  `--env-file`, `target_broker` without the files, a final `\r` kept): `iteration2/mutation-sr8-sr9.json`.
- Decision C on the fixed tree: 3/3 killed (`acl_blocker` never blocks; the check does not add it; the conversion skips
  it): `iteration2/mutation-decision-c.json`.

### The rest of the delta (reviewed, attacked where possible, no finding)

| Commit | What was checked | Result |
|---|---|---|
| 28e9492 boot forms | `BOOT_CONFIG_EXPR` is a fixed string; `read_effective_config(_expr=…)` accepts only the two constants. `emqx_config:fill_defaults/1` = `hocon_tconf:check_plain(…, make_serializable)` per root (`emqx_config.erl:487-523`), the processing EMQX applies at every boot and `conf load` (`:341,345`): no new evaluation of HA data; it runs in the `--network none` candidate and on the restored broker, which reads the same files at boot. Whole-root equality; filled defaults hide only "explicit default vs absent". The readback record hashes the boot form after SR-4 redaction (secret-named leaves, e.g. `node.cookie`, `dashboard.default_password`, now also when they come from an EnvironmentFile) | OK; residual: the boot form is larger (limit `MAX_HOCON` 8 MiB): a huge HA configuration refuses (availability only) |
| fdb7cfe, 0d260db root names | `hacommon.names(…, 8)` gets map keys only (cut at 60). In `target_broker` the keys come from this device and its snapshot before any HA data; in `restore_target_settings` from `preserved_settings` (non-data roots + `authorization`). HA's export carries only `DATA_ROOTS` (`--root-keys` from `ROOTS_EXPR`, `[a-z_]+`), and an added root refuses earlier with a fixed text. 0d260db: a loaded-back root (`conf load --replace` of this device's own value) must equal this device's boot form: it cannot hide an HA value other than the schema default this device's next boot uses anyway | OK: only this device's EMQX schema root names, never values |
| 92f2461, be2c92d schedulers | `VM_EXPR` fixed; the answer must be exactly `WOOWVM:a:b:END` (+`ok`), `[1-9][0-9]{0,3}`, online ≤ total ≤ 1024, else a fixed refusal; `ERL_AFLAGS` is `+S a:b` from those two integers (no injection, not secret); the candidate's own answer must equal before anything is compared. With SR-8's fix a device file's `ERL_AFLAGS` cannot replace it (`--env` wins, real podman) | OK |
| be5bc6f image volume | HA's broker mounts this job's own volume at `/opt/emqx/data` (`rw,noexec,nosuid,nodev`), removed with the job. Vendor: bin/emqx runs `nodetool hocon` at every boot (`bin/emqx:476-478,536,590`), which prepends `RUNNER_ROOT_DIR/data/patches` = `/opt/emqx/data/patches` to its code path (`bin/nodetool:28,364-374`); `noexec` does not stop BEAM loading. In HA's broker that path is the fresh job volume (image copy-up, empty `patches/`); HA's members go to `HA_DATA_DIR` (`/data/emqx/data`) only, so nothing HA controls is there at boot. SR-1 attack rerun on the fixed engine: the HA broker started and exported, the plugin did not run and left no marker (`t2-plugin-exec-fixed.json`) | OK; real runs left no anonymous volume: T11, T12 and T9 counted the dangling volumes before and after: 0 new ones |
| decision C (owner 「C」) | `acl_blocker`/`analyse`/`_build_candidate` unchanged by the delta. **Real T11** (REAL batch-1 HA backups, the product's own `target_profile` on a device stand-in with the product package's EnvironmentFile, `_build_candidate(profile=…)` as `convert()` calls it, fixed engine): x86 and ARM: on a [file] device the conversion refuses with exactly the owner's text before a candidate exists and the device's configuration digest is unchanged; on [file, built_in_database] it passes every product check (44 readback roots, HA rows ACL 4, admins 2, API keys 1, MQTT users 3, banned 1, retained 5, 2 rules), the candidate holds the same profile, and the value from the device's EnvironmentFile (`EMQX_NODE__COOKIE`, compared in memory) reached the candidate through podman | holds |

### Iteration-1 items re-checked

- **Lab volumes:** the 24 anonymous EMQX volumes iteration 1 left (2026-11-23 20:02-22:07) were listed and removed by
  name (`iteration2/lab-volume-cleanup-list.json`, `-remove.json`): 18 tied by journald `container create` events within
  2 s to this lane's `woowbk-secrev-*` probes or the `emqx-ha` brokers its runs started (pre-be5bc6f), 6 by timing to
  this lane's recorded run starts; shapes: image copy-ups of `/opt/emqx/data`, probe data dirs (one held this lane's
  `secrev-*.hocon` probe files), empty log volumes. 19 other dangling volumes (other lanes, earlier days; later also
  PostgreSQL ones from another lane) were not touched.
- **SR-7 real trigger:** T12 (HA's `cluster.hocon` with an enabled ExHook server through the conversion body, real EMQX 5.8.9): the conversion refuses and names ExHook (292.7 s); the HTTP-authenticator trigger stays refused earlier by the authentication-equality check (iteration 1)
- **SR-2 read-only control** (failed with BrokenPipe in iteration 1, never rerun): PASSED on the fixed engine; the device's read-only ACL governs, a stranger is denied in the candidate; the SR-2 attack on the
  fixed engine: REFUSED with the SNAPSHOT_CHANGED text.
- **T7 had no profile:** T11 now runs the conversion body with this device's profile (decision C, profile equality at
  the end) and the product's `Target` (EnvironmentFile through podman).
- **SR-5** (plain hashing of the device's bootstrap users): not exercised in iteration 2; exercised for real in iteration 3 (T5, refused fail-closed).

### Real runs of iteration 2 (lab store, `--network none`, generated credentials)

| Run | Code | Result | Exit | Elapsed s | Evidence (`iteration2/`) |
|---|---|---|---|---|---|
| T9 EnvironmentFile value on a command line, before the fix | 7d9d468 | EXPOSED: 1 command line(s) with the value | 0 | 20.4 | t9-tip-r2.json |
| T9, after the fix | abff1a0 | NOT-EXPOSED: 0 command line(s) with the value | 0 | 19.6 | t9-fixed-r2.json |
| T10 25 crafted env files vs podman 4.9.3, before | 7d9d468 | DIFFERENT 13, REFUSED 2, SAME 10 | 0 | 20.2 | t10-tip-r2.json |
| T10, after | abff1a0 | REFUSED 2, SAME 23 | 0 | 59.6 | t10-fixed-r2.json |
| SR-1 plugin attack, fixed engine | abff1a0 | HA's broker started+exported; plugin running False; code executed False | 0 | 101.0 | t2-plugin-exec-fixed.json |
| SR-2 control: device ACL read-only mount (rerun of iteration 1's failed run) | abff1a0 | PASSED (candidate built, all product checks green); stranger in the candidate: deny | 0 | 348.0 | t1-datadir-acl-fixed-ro.json |
| SR-2 attack: device ACL in the data volume | abff1a0 | REFUSED: EMQX 不能搬過來：這台 EMQX 的 ACL 或憑證檔案放在資料卷裡（例如在 Dashboard 編輯過授…; stranger in the candidate: allow | 0 | 257.0 | t1-datadir-acl-fixed-data.json |
| SR-7 ExHook server in HA's settings | abff1a0 | REFUSED naming ExHook | 0 | 293.0 | t12-exhook-fixed.json |
| Decision C: REAL x86 b1 backup, device [file] | abff1a0 | REFUSED with the owner's text: True; candidate built: False; device unchanged: True | 0 | 215.0 | t11-fixed-x86-file.json |
| Decision C: REAL ARM b1 backup, device [file] | abff1a0 | REFUSED with the owner's text: True; candidate built: False; device unchanged: True | 0 | 183.0 | t11-fixed-arm-file.json |
| REAL x86 b1 backup, device [file, built_in_database] | abff1a0 | PASSED; readback roots 44; profile ['file', 'built_in_database']; device unchanged: True; new dangling volumes 0 | 0 | 387.0 | t11-fixed-x86-builtin.json |
| REAL ARM b1 backup, device [file, built_in_database] | abff1a0 | PASSED; readback roots 44; profile ['file', 'built_in_database']; device unchanged: True; new dangling volumes 0 | 0 | 540.0 | t11-fixed-arm-builtin.json |

## Iteration 3 (2026-11-24): the merged engine and the Podman 6 volume fix

### What was audited before any new run

- Iteration 2's detached runs survived the 03:33 kill of all agents and ended with exit 0 (T9, T10, T11 x4, T12, T1, T2);
  their JSONs are in `iteration2/`.
- The dev-d attempt of iteration 2 did run (04:07): `attempt-secreview2-01` deployed the fixed engine (setup 8/8) and the
  harness then skipped the import step because dev-d's headroom was 1.5 GiB. Exit 1, kept as a failed attempt
  (`tests/e2e/lab/evidence/emqx-product-20261123/attempt-secreview2-01.json`). Iteration 3 queued no dev-d run: the
  product lane's own chain runs the fixed engine on dev-d.
- **Lab volumes:** of the 24 anonymous EMQX volumes of iteration 1, all 24 were removed by iteration 2 (listed first, names
  only, `iteration2/lab-volume-cleanup-*.json`). Iteration 3 looked at every remaining dangling volume: none holds EMQX
  data (the 8 newest hold PostgreSQL clusters of other lanes). Nothing is left to remove for this lane.

### Review of the merged diff

The product lane merged this review's fix twice with the same result (the first branch of 08:14, then the new owner's
branch, after its first agent got stuck): `183dd6e` + `efd620b`, and `620bdd5` + `e08f8a1`. Compared:

| Check | Result |
|---|---|
| `backup-engine`, `docs` and `tests/backup` of the merge vs abff1a0 | 0 engine lines differ (merge 183dd6e and 620bdd5); `efd620b`/`e08f8a1` change only `tempctr.py` (+53/-2) and `test_ha_tempctr.py` |
| Patch id of the cherry-pick | equal to 8613ffa and to c8df1f2 |
| `backup-engine` tree hash | `865c930f392006e0080de506eb7c425fd81becd7` on both product branches and on the trial commit that the reruns used |
| SR-8/SR-9 code and its tests after the merge | present unchanged (`candidate_env` returns `(env, env_files)`, `target_broker` passes `env_files`); the `_env_files` path check and `--env-file` order kept |
| Interplay of the two changes in `tempctr.py` | independent: `run_argv` (env files) and `volume_import`/`_apply_root` (volume owner) share no code path |
| Product evidence for the merged engine (read, not re-run here) | attempt-18 ARM full chain PASS 74/74, attempt-19 ARM rollback rounds PASS 84/84 and attempt-20 x86 full chain PASS 66/66 on dev-d (engine 865c930f); attempts 21 to 23 (x86 rollback rounds, decision-C refusal, cleanup) were still running when this README was written (attempt-21's first try failed at its own setup check, reported by the product lane as a harness false alarm on dev-d's named headscale volumes, fixed in f0a34e2; no product step ran); lane arm54-2's .54 run (`e08f8a1` merged with that lane's other Podman fixes, `ha_emqx.py` byte-equal): 164/164; unit and mutation sets of the product lane 222 + 438 + 6 OK, 81 mutations (79 killed, 2 test gaps closed in 7e530cf without an engine change) |

Verdict (iteration 3, superseded): "no new finding" for tree 865c930f was wrong. Iteration 4's independent verifier
found SR-10 (Low) in exactly that tree (control/bidirectional characters in names and a forged job-log line), fixed on
the integration branch only. SR-8 and SR-9 are fixed in the handed-over engine; SR-10 is not. See **## Iteration 4**.

### The Podman 6 volume fix (tempctr `tar_root` / `_apply_root`, c8df1f2 = 8613ffa)

`TempObjects.volume_import` now keeps the stream's first 64 KiB, reads the owner, group and mode of a leading `.`
member and applies them to the volume's mountpoint with `podman unshare chown --no-dereference` / `chmod` in the owner's
user namespace (Podman 6.1.1 ignores that entry on import; EMQX's candidate then could not write its data folder on
.54). Checked:

| Question | Answer |
|---|---|
| Can HA choose the owner or mode of a volume's top directory? | No. Every EMQX producer (`emqx-src`, `emqx-xfer`, `emqx-in`, `emqx-new`) writes the first member itself with fixed values; HA's entries are rewritten one by one (`hacommon.info`, no copied PAX records, no set-id bits), and a second `.` member is impossible (`_Sink.names`). New test `VolumeTopTests` (a hostile add-on: everything 07777, uid 4242): green on abff1a0 and on the merge; 6/6 mutations killed (`mutation-volume-top-iteration3.json`), two of them in `_apply_root` itself. |
| Which other callers use it? | Headscale `hs-check`, n8n `n8nsrc`, Odoo/Omnigent `hapg`, Odoo `odoo-addons`: all write (or stream) an engine-made tar; the top entry comes from the engine or from this device's own converted volume. |
| Is the decompression or parsing risky? | `tarfile.open(mode='r\|')` reads a plain (never compressed) stream from at most 64 KiB; errors give "no entry" and nothing is applied. |
| Can the path be redirected? | The mountpoint is Podman's own answer for a volume this job created (`^woowbk-…`), must be absolute and one line; `chown` does not follow a link; the commands run as the owner inside their user namespace. Owners are never root (catalog rejects `root`). |
| Behaviour on Podman 4.9.3 | `chown`/`chmod` to the values Podman already used: no change (the real runs below). On 6.1.1 the .54 runs of lane arm54-2 passed with it. |

### Regression reruns of the attacks on the merged engine

Every `podman run` below carried `--network none` in the separate lab store; nothing touched a device or production. One
attempt per row, JSON in `iteration3/`.

| Run | Result | Exit | Elapsed s | Evidence (`iteration3/`) |
|---|---|---|---|---|
| SR-8 env file value on a command line | NOT-EXPOSED: 0 command line(s) with the value; the candidate received it: True | 0 | 21.0 | t9-merged.json |
| SR-9 25 crafted env files vs podman | REFUSED 2, SAME 23 (podman 4.9.3) | 0 | 41.6 | t10-merged.json |
| 16 crafted add-on members | 16 crafted members: 10 refused, 6 accepted only with the hostile part dropped or neutralised | 0 | 0.6 | t4-merged.json |
| SR-1 plugin attack | HA's broker started+exported; plugin running False; code executed False | 0 | 47.9 | t2-merged.json |
| Decision C: REAL x86 b1 backup, device [file] | REFUSED with the owner's text: True; candidate built: False; device unchanged: True; new volumes 0 | 0 | 90.3 | t11-merged-x86-file.json |
| Decision C: REAL ARM b1 backup, device [file] | REFUSED with the owner's text: True; candidate built: False; device unchanged: True; new volumes 0 | 0 | 142.8 | t11-merged-arm-file.json |
| REAL ARM b1 backup, device [file, built_in_database] | PASSED (candidate built, all product checks green, profile e; readback roots 44; profile ['file', 'built_in_database']; device unchanged: True; new volumes 0 | 0 | 192.5 | t11-merged-arm-builtin.json |
| REAL x86 b1 backup, device [file, built_in_database] | PASSED (candidate built, all product checks green, profile e; readback roots 44; profile ['file', 'built_in_database']; device unchanged: True; new volumes 0 | 0 | 214.2 | t11-merged-x86-builtin.json |
| SR-7 ExHook server in HA's settings | REFUSED naming ExHook | 0 | 290.2 | t12-merged.json |
| SR-2 control: device ACL read-only mount | PASSED (candidate built, all product checks green); stranger in the (discarded) candidate: deny | 0 | 198.1 | t1-merged-ro.json |
| SR-2 attack: device ACL in the data volume | REFUSED: EMQX 不能搬過來：這台 EMQX 的 ACL 或憑證檔案放在資料卷裡（例如在 Dashboard …; stranger in the (discarded) candidate: allow | 0 | 148.8 | t1-merged-data.json |
| SR-3 file:// secrets | REFUSED: EMQX 不能搬過來：HA 的 EMQX 設定（connectors）用「file://」讀取本機檔案當作密碼；搬過來後這台的 EMQX 會讀… | 0 | 236.0 | t3-merged.json |
| SR-6 rule jq env | REFUSED: EMQX 不能搬過來：HA 的 EMQX 規則（1 條）使用 jq 函式；EMQX 的 jq 能讀取這台 EMQX 的環境變數（其中有 Das… | 0 | 249.0 | t6-merged.json |
| SR-5 plain password hash | REFUSED: EMQX 匯入後未能保留目標有效設定（authentication），已停止。; bootstrap user before (device) rows=1:plain=0, after (candidate) rows=1:plain=0; candidate authenticators [['plain', True]]; bootstrap password stored in plain text: False | 0 | 264.7 | t5-merged.json |

### Other checks of iteration 3

- Unit tests on the merged tree (EMQX modules, `test_ha_tempctr`, `test_tempctr_cleanup_dependency`, `test_ha_import`,
  `test_ha_flows`, guarded runner: no podman, ssh, sudo or systemctl): 258 tests OK, 0 blocked (`iteration3/unit-merged.json`); 260 tests OK on the merge of the product tip `fc0e3bc` and this branch (`iteration3/unit-final.json`).
- The product lane's 17 attempt JSONs and its unit-test record on the product branch (5786ae4) were scanned for
  credential-like values: none (only commit hashes, digests, test names, memory figures and fixed status lines).
- The page text and CONTRACT changes of the product delta describe what the code does (a refusal for a file-only device,
  the root names of a differing setting, the scheduler counts); the owner's decision-C text is verbatim in both.

## Residual risk and what was not covered

- **HA's throwaway broker runs HA's own files at boot.** SR-1 closes plugin loading; the other boot-time paths
  (schema registry Protobuf/Avro compilation, LwM2M `xml_dir` XML parsing, durable storage, and the broker's handling
  of HA's own database files) were not reviewed one by one. One deeper analysis step of iteration 3 in this area was stopped
  by a safety classifier and was not continued or repeated: **a human security review is needed here before commercial
  acceptance.** What contains it today: rootless, `--network none`, read-only root, `no-new-privileges`, memory and
  pids limits, no device secret or device volume mounted, the broker's own job volumes mounted `noexec,nosuid,nodev`, the
  export as its only output through a bounded reader, and the candidate's outcome checks after the import (whole-root
  equality of every setting that is not HA data, table counts, SR-2/SR-3/SR-6/SR-7 refusals, decision C). Defense in
  depth: the export's members and roots are checked before `data import` on branch `fix/emqx-export-members-20261124`
  (Iterations 5 and 6; READY at `dd3ae49`, merged when integration decides); `--cap-drop=all` for `emqx-ha` is
  recommended, not implemented.
- **Migrated integrations are HA's by design.** HA's MQTT users, ACL rows, Dashboard users and API keys replace this
  device's; HTTP/MQTT connectors, actions and rules may publish to or call hosts HA's settings name, and a migrated rule
  sees every message on this broker (`SELECT * FROM "#"` + republish/forward reads this device's MQTT traffic); gateways may
  open listeners (reachable only through published ports; the dev-d Quadlet publishes on 127.0.0.1 plus the ngrok
  TCP listener). SR-3/SR-6/SR-7 only stop the paths that read THIS device's secrets. The check page lists HA-only
  hosts, not every external host; recommended: list every external host the migrated settings contact.
- Migrated `psk_authentication.init_file`, LwM2M `xml_dir` and TLS file paths may name files of this device (read
  locally; no path found that sends their content out; not exercised).
- SR-2 fails closed: a device whose Dashboard edited its ACL file cannot import until a merge policy exists (a human
  decision, not a defect).
- The throwaway brokers keep Podman's default capability set; HA's broker runs as uid 0 inside the rootless user
  namespace.
- The ExHook/authenticator rule (SR-7) allows only built-in database authenticators; HA backups with an external
  authenticator or an enabled ExHook are refused (a later, reviewed migration could re-allow specific backends).
- SR-8/SR-9 were attacked for real against podman 4.9.3 only. Lane arm54-2's product run on .54 (Podman 6.1.1, `e08f8a1`
  merged with that lane's other Podman fixes, `ha_emqx.py` byte-equal, 164/164, note of 09:18, read here and not re-run) reports the candidate started with `--env-file` and no file setting
  name or value on its command line. Podman 6 reads an env file differently only in places the engine refuses anyway
  (quotes, backslashes, `$`, blanks); that difference was not attacked on Podman 6.
- **Not covered here:** packaging, restore, readback, restart and rollback on a device (the product lane's dev-d chain and
  the .54 runs of lane arm54-2 are that evidence); Omnigent/LiteLLM SQL schema attacks (their own review lanes); the
  Hermes FTS review (done separately by the main session on 2026-11-23, its own evidence folder); other EMQX versions than 5.8.9 and add-on versions outside VERSIONS; the host's Podman
  Quadlet generator; anything that needs a network.

## Iteration 4 (2026-11-24): the independent verifier's points, SR-10, SR-5 and B1-03

Iteration 4 (owner instance, token SR-OWNER-1942) acted only on the verifier's corrections of iterations 1-3 and the
two open items the main session named. The EMQX engine is byte-identical between the integration tip this iteration
started from (`f2c9e03`, `backup-engine` tree `80215432`) and the current tip (`0562c55`, after a LiteLLM merge):
`ha_emqx.py`, `hacommon.py`, `jobs.py`, `habackup.py`, `tempctr.py` all unchanged, so the findings below carry over.

### SR-10 (Low) — control / bidirectional / line-separator characters in HA names and the job log (found by the verifier)

The verifier contradicted iteration 3's "no new finding" for the handed-over tree `865c930f`: in that tree a C0/C1,
bidirectional (U+061C, U+200E/F, U+202A-E, U+2066-9) or line-separator (U+2028/9) character in an HA EMQX **plugin
name**, a **`/share` / `/ssl` / `/config` file reference** or a **skipped-symlink sample name** either reaches a check
warning raw (reordering how the rest of the line reads on the page, e.g. U+202E) or forges a second job-log line
(U+2028, which the old CR/LF-only log sink did not neutralise).

This is the same class as omnigent-secreview SR-4/SR-6 and is fixed on the **integration branch only**, not in
`865c930f`:

- `65d8a51` — `hacommon.names` neutralises control characters in HA names (C0/C1).
- `97c994f` — extends `hacommon.names` and `jobs.LOG_CONTROL_RE` to the twelve Unicode bidirectional controls **and**
  U+2028/U+2029, so a name reaching a warning becomes `?` and a log line can no longer be split.

Both commits are **ancestors of the integration tip** and **not ancestors of `e08f8a1`** (checked with
`git merge-base --is-ancestor`). The EMQX paths they cover: the plugin warning (`ha_emqx._source_analysis` →
`hacommon.names`), the `/share` note (`ha_emqx.hocon_notes` → `hacommon.names`) and the skipped-symlink note
(`habackup.Report.warnings`) written through the job log (`jobs.JobStore` → `jobs.LOG_CONTROL_RE`).

Proof (in process, no container, no network — a log-injection / name-spoofing check, not a network attack):
`tests/e2e/lab/emqx_secreview/sr10_control_chars.py` drives the real warning builders and the real log sink against
both trees. `iteration4/sr10-control-chars-865c930f.json`: `forged=True` (plugin warning, `/share` note and the
symlink log line all leak the thirteen test code points; the symlink log line is not single-line).
`iteration4/sr10-control-chars-integration.json`: `forged=False`, `ok=True`. The script also shows the naive
old-tree code paths would leak/forge, so the two commits are load-bearing. (The product lane may want to carry these
two commits into the product branch so the product engine alone is clean; today they arrive through integration.)

### SR-5 (Low) — decided for real: OPEN (reachable)

> **Superseded: disproven by the real runs of iteration 5.** The text below is kept as it was written; the claim
> "stored verbatim" and the remedy "re-hash with the device's own algorithm" are both wrong (one authenticator per
> mechanism and backend, `emqx_authn_config.erl:293-298`; every row of it is checked with its one algorithm).

Iteration 3 reported T5 as "refused fail closed, no finding left." The verifier showed the refusal was an **artefact**
of a crafted HOCON that omitted `salt_position`: `conf load` then fills the schema default
(`emqx_authn_password_hashing.erl` `salt_position(default) -> prefix`), and the authentication-root comparison, not a
comparison with this device's hashing, is what refused.

With an **explicit** `salt_position`, no engine check refuses a built-in-database `plain` authenticator:
`credential_receivers` allows `{password_based|scram, built_in_database}`; `preserved_bootstrap_authn` only refuses
when **this device's** `bootstrap_type` is `hash` and the algorithms differ (a `plain`-bootstrap device does not
trip it); and the final authentication-root equality holds because the engine builds the expected rows from the
already-default-filled post-import config. The device's own bootstrap MQTT users are then re-attached to HA's `plain`
authenticator and, at the candidate's boot, `boostrap_user_from_file` hashes them with `plain`:
`emqx_authn_password_hashing:hash(#{name:=plain}, P)` → `emqx_passwd:hash({plain, <<>>, _}, P)` →
`hash_data(plain, P) = P` (`emqx_passwd.erl:92-105`). So **this device's own bootstrap password is stored verbatim**
in the candidate's `emqx_authn_mnesia`, and so in the converted backup (a secret that was not in HA's backup).

Severity **Low**: it needs HA's authenticator configured with `plain` (unusual; the defaults are sha256/bcrypt), this
device to have bootstrap users, and access to the converted backup; the device's bootstrap password is already stored
in clear in its own bootstrap CSV mount, so this is an additional copy of an on-device plaintext secret into the
backup. **Remediation is an owner policy choice** (like decision C): either refuse a HA backup whose built-in-database
authenticator uses `plain` when this device has bootstrap users, or re-hash the device's bootstrap users with the
device's own prior algorithm instead of HA's. No behaviour-changing refusal was added unilaterally (a new refusal
rejects backups that convert today). Harness for the empirical confirmation:
`tests/e2e/lab/emqx_secreview/t5b_plain_explicit.py` (explicit `salt_position`, lab store, `--network none`); the
real run was queued through `heavy.sh` and was still waiting for a host heavy-slot at hand-off (recorded in the lane
file), so SR-5's decision here rests on the vendor source and the guard analysis above, with the lab run pending.

### B1-03 — non-data roots do not reach the restored target (proven), plus a pre-import hardening

> **Superseded in part by iteration 5.** In `iteration4/b103-nonroot-*.json` the fields
> `shared_non_data_roots_reverted_to_device` and `guard_names_differences_as_root_names_only` are true by construction
> (the script applies the result it then checks; the second ends in `or True`), so they prove nothing; the real runs are
> T13. The check described below (bcb6245: `check_export_members`, `export_cluster_roots`) was bypassable and is replaced.

The verifier noted B1-03 (the other half of the old preservation guard, `reports/b1-02-03.md`) was not named in the
README and that no forged export with non-data roots had been run. B1-03 holds in two layers, both verified in process
(`tests/e2e/lab/emqx_secreview/b103_nonroot.py`, `iteration4/b103-nonroot-*.json`, `ok=True` on both trees):

1. **Export scope.** `ha_broker` exports only `DATA_ROOTS` (`emqx ctl data export --root-keys <DATA_ROOTS∩present>`);
   the vendor applies `raw_conf_transform = maps:with(Keys, RawConf)` (`emqx_mgmt_data_backup.erl:525-531`), so a
   healthy export's `cluster.hocon` never carries `listeners`, `dashboard`, `node`, `log` or `cluster`.
2. **Post-import guard.** Even if a compromised HA broker ignored `--root-keys`, the vendor import only applies a root
   with an importer (`?CONF_KEYS` + the `emqx_config_backup` modules, e.g. `listeners` via
   `emqx_mgmt_listeners_conf`); `restore_target_settings` then compares every preserved (non-data) root of the
   candidate to this device's and **refuses an added root** (`EMQX 匯入新增了無法安全移除的目標設定`) or **reverts a
   shared root** to this device's value (the final whole-root equality demands this device's value). The in-process
   proof exercises `preserved_settings` and that final difference for benign forged post-import configs (an exotic
   `message_transformation` root → refused; `listeners`/`dashboard`/`node` differing → flagged then reverted).

Because the vendor import applies cluster.hocon roots **before** the product's checks run (inside the candidate that
mounts this device's secrets), iteration 4 also implemented the hardening iteration 1's README recommended — a
**pre-import export-member check** — as a product change on branch **`fix/emqx-export-members-20261124`** (from the
current integration tip `0562c55`; `backup-engine` tree `b6b1c0c1`, local only):

- `ha_emqx.check_export_members(path)`, run at the top of `target_broker` before the candidate starts, allows only
  `<name>/META.hocon`, `<name>/cluster.hocon` and `<name>/mnesia/<table in TABLES>` (each a regular file, under one
  top directory); `ha_emqx.export_cluster_roots` refuses any `cluster.hocon` top-level root outside `DATA_ROOTS`,
  scanning conservatively and fail-closed (strings/comments removed, `{}`/`[]` depth tracked; a wrapped or
  unbalanced document raises).
- Tests `tests/backup/test_ha_emqx_export_members.py` (16 cases); **7/7 mutations killed**
  (`iteration4/export-members-mutation.json`). The two internal conversion-chain doubles now emit a structurally valid
  `.tar.gz` export instead of a non-tar stub, and the focused authentication-guard test mocks the new check; EMQX
  modules + `test_ha_import` + `test_ha_flows` **245 OK, 0 blocked**. This is defence in depth; the authoritative
  guarantee stays the post-import whole-root equality.

### Corrections to iterations 1-3 (the verifier's remaining points)

| Earlier claim | What is true |
|---|---|
| "no new finding" for tree 865c930f | Wrong — SR-10 (above) is in that tree, fixed only at integration. |
| T5/SR-5 "refused fail closed, no finding left" | Artefact of a HOCON without `salt_position`; SR-5 is an open Low (above). |
| "14/14 attacks in containers with real EMQX" (iteration 3 reruns) | Not all are attacks in a broker: T4 (`t4_members`) starts no container (it drives `scan_member` in process); T10 runs `/usr/bin/env` in the image to compare env parsing, not an EMQX attack; about 5 of the 14 reruns are parser/structure or real-backup regressions, not exploit attempts. The wording "every `podman run` carried `--network none`" is right for the rows that start a broker. |
| exit code 0 means the attack was contained | No — an exit of 0 only means the harness ran; the **result fields** decide (e.g. `t9-tip-r2.json` is `EXPOSED` with exit 0). Read `conversion` / `forged` / `*_leaks_*`, not the exit code. |
| T11 `candidate_env_file_flag` | Hard-coded `True` in `t11_profile_real.py` (it asserts the Target carried env files, not that podman applied them); the SR-8/SR-9 evidence for "podman read the env file" is T9/T10, not this flag. |
| "24 anonymous EMQX volumes proven and removed" (iteration 2) | 18 were tied by journald `container create` events within 2 s of this lane's probes/brokers; **6 were attributed by run-start timing only**, not by a container-to-volume link. |
| open item "follower 634612-634614 still there" | False — main ended it at 08:14; nothing of this lane is left running except the queued T5b (recorded in the lane file). |
| first T9/T10 runs | `abff1a0`'s first T9/T10 ("2 command lines", "8 of 20") have **no attempt JSON** (overwritten by the r2 reruns); the test docstring's `iteration2/t10-tip.json` does not exist. The committed evidence is the r2 files. |
| host-wide Podman event dump | Iteration 2 kept `scratchpad/emqx-secreview2/events-2000-2210.txt` (host-wide, held production container names); it was never committed and **main deleted it**. This lane does not read the host's Podman events or store in any form (rules 11, 15). |

### Not repeated (safety classifier)

One light vendor probe of the HOCON pretty-printer/parser round trip was stopped by the safety classifier this
iteration (not a tool or permission denial). Per the standing rule it is not reproduced in any form; B1-03 was
completed defensively instead (the engine's own guards + the pre-import member check). The boot-time-loader analysis
that a classifier stopped in iteration 3 likewise stays a human item.


## Iteration 5 (2026-11-24): iteration 4's own work reviewed, the export check rewritten, SR-5 and B1-03 decided by real runs

Iteration 5 (owner instance, token SR-OWNER-1942) finished the 12:32 list of the main session and, before anything was
merged, attacked iteration 4's own changes. Engines under test: the integration tip `9ebb2bf` (`backup-engine` tree
`45db404c…`; `ha_emqx.py` is byte-equal to the reviewed `e08f8a1`) and `fix/emqx-export-members-20261124` (`3ad74ca`;
tree `345d1827…` = `45db404c` plus `ha_emqx.py` only; the later commits `8e46fb6` and `dd3ae49` add tests only).

### What was wrong in iteration 4

| Iteration 4 said | What is true (how it was found) |
|---|---|
| `check_export_members` / `export_cluster_roots` (bcb6245): "a crafted export cannot hide a non-DATA_ROOT from the scan" | False. Ten spellings of one harmless extra root (quoted key, `:` as separator, a quote inside a comment, `include`, NBSP as white space…) were not seen by the scanner, and 9 of the 25 crafted archives of T14 pass bcb6245 (folder-entry, include-directive, not-utf8, other-table-second-gzip-member, root-after-quote-in-comment, root-after-triple-quote-in-comment, root-colon, root-nbsp, root-quoted). A hand-written HOCON scan and Python's tar reader do not read every file the way EMQX does. The branch was held before any merge. |
| (not said, but true) the check had only run on test doubles | Now proven with real exports (T11, T13 below). |
| SR-5 "OPEN (reachable) … stored verbatim"; remedy "re-hash with the device's own algorithm" | Disproven by three real conversions with `plain` and a same-hash control (T5b, below). The remedy is not possible anyway (`emqx_authn_config.erl:293-298`). What remains is an owner policy item (below). |
| B1-03 "proven in process (`ok=True` on both trees)" | Two of the script's fields are true by construction. Real runs: T13. |

### The export check, rewritten (fix/emqx-export-members-20261124)

`ha_emqx.check_export` runs in `target_broker` just before `emqx ctl data import`. The candidate (this device's image)
lists HA's export on the very file the import reads, with the vendor's own libraries: `erl_tar:table` (vendor
`emqx_mgmt_data_backup.erl:880-900`) and `hocon` on `cluster.hocon` (`:904-912`). Allowed: `META.hocon`, `cluster.hocon`
(8 MiB, roots within `DATA_ROOTS`, no `include` token) and the backup files of `TABLES`, each once, a regular file, in
the export's own folder. Anything else, or an answer that is not exactly the listing, refuses (`incompatible`, member
and root names only, control characters neutralised), and nothing is imported. The expression is fixed but for the
file name, which must be a plain export name. It stays defence in depth: the comparison of every setting of this device
after the import is the authoritative guard (T13 on the tip, below).

- Tests: `tests/backup/test_ha_emqx_export_members.py` (16 test methods: healthy listings, the device's roots,
  unexpected files, kinds, duplicates, sizes, control characters, malformed answers, the expression and its file name,
  the order start → check → import, the conversion body with nothing stored, a hot backup's advice). Unit set (30
  modules, guarded runner): on `8e46fb6` tests=388 failures=0 errors=0 skipped=0 expected_failures=0 unexpected_successes=0 blocked=0; on `dd3ae49` tests=388 failures=0 errors=0 skipped=0 expected_failures=0 unexpected_successes=0 blocked=0
  (`iteration5/unit-fix.json`, `unit-fix-2.json`).
- Mutations (one place each, on copies): run 1 on `8e46fb6` **36/37 killed**, surviving:
  prefix ignored; `dd3ae49` adds the test for it ("an answer with another expression's prefix is not
  the export listing"); run 2 on `dd3ae49` **37/37 killed**
  (`iteration5/mutation-export-check-1.json`, `-2.json`).
- The verifier's surviving mutation of `tempctr.tar_root` (a first entry named `.` that is no folder) is killed by the new
  `TarRootTests` (50eaf17, on the review branch).

### Real runs of iteration 5 (lab store, `--network none`, generated credentials; HA key read in-process by the b1 reader)

| Run | Exit | Elapsed s | Evidence (`iteration5/`) |
|---|---|---|---|
| T11, REAL x86 batch-1 HA backup, device [file, built_in_database], fixed engine: PASSED (candidate built, all product checks green, profile equal); rows 16; readback roots 44; device unchanged: True | 0 | 243.0 | t11-fix-x86-builtin.json |
| T11 again (harness be36f75 reads the candidate's command line from podman instead of a constant): PASSED (candidate built, all product checks green, profile equal); rows 16; readback roots 44; device unchanged: True; candidate env file flag True, cookie on its command line False | 0 | 191.8 | t11-fix-x86-builtin-2.json |
| T11, REAL ARM batch-1 HA backup, same device, fixed engine: PASSED (candidate built, all product checks green, profile equal); rows 16; readback roots 44; device unchanged: True | 0 | 231.4 | t11-fix-arm-builtin.json |
| T13, forged export, fixed engine (rows below) | 0 | 316.5 | t13-fix.json |
| T13, forged export, integration tip without the check (rows below) | 0 | 388.2 | t13-tip.json |
| T14, check_export on EMQX's own libraries, no broker: 29/29 as expected | 0 | 60.1 | t14-fix.json |
| T14, the same archives on bcb6245 (in process): 20/29; 9 of 25 crafted ones pass | 0 | 1.9 | t14-old.json |
| T5b (SR-5), engine `80215432` (f2c9e03): `disable`: PASSED, rows=1:plain=0, after restart rows=1:plain=0, login own=refused:wrong=refused (after restart own=refused:wrong=refused) | 0 | 225.1 | t5b-cur-disable.json |
| T5b, same engine: `suffix`: PASSED, rows=1:plain=0, after restart rows=1:plain=0, login own=refused:wrong=refused (after restart own=refused:wrong=refused) | 0 | 235.2 | t5b-cur-suffix.json |
| T5b on the fixed engine, first try: failed after 1 s (this lane's own collision with the two runs above: same lab names), kept | 1 | 1.0 | t5b-fix.json |
| T5b on the fixed engine, with the same-hash `control`: `control`: PASSED, rows=1:plain=0, after restart rows=1:plain=0, login own=login:wrong=refused (after restart own=login:wrong=refused); `suffix`: PASSED, rows=1:plain=0, after restart rows=1:plain=0, login own=refused:wrong=refused (after restart own=refused:wrong=refused) | 0 | 373.5 | t5b-fix-2.json |

T13 in detail. Real: HA's throwaway broker makes the export of a crafted add-on, the device stand-in and the candidate are
real EMQX 5.8.9 brokers, the import is the vendor's. Simulated: the extra roots are written into that real export by the
harness (a healthy broker never exports them). `control` is the same export repacked by the same code without a change, so
that a refusal is not the repacking's. Values are harmless and differ from the device's.

| Case | Result |
|---|---|
| T13 fixed engine, `all` (12 forged roots) | imports: 0; device roots changed by the import: not reached (refused before the import); REFUSED: EMQX 不能搬過來：HA 匯出的資料含有不屬於這次匯入的內容（設定 alarm、broker、cluster、dashboard、flapping_detect、force_gc、listeners、log、mqtt、node 等 12 個），已在匯入前停止，這台沒有任何改變；請在 HA 停止 EMQX 附加元件後重新備份再匯入。; device unchanged: True |
| T13 fixed engine, `control` (0 forged roots) | imports: 1; device roots changed by the import: ['authorization']; PASSED (candidate built, all product checks green); device roots differing in the built candidate [], after its restart []; forged marker on disk: False; device unchanged: True |
| T13 integration tip, `all` (12 forged roots) | imports: 1; device roots changed by the import: not measured (the import failed); REFUSED: HA 的 EMQX 資料匯入時發生錯誤（部分資料無法匯入），已停止。; device unchanged: True |
| T13 integration tip, `control` (0 forged roots) | imports: 1; device roots changed by the import: ['authorization']; PASSED (candidate built, all product checks green); device roots differing in the built candidate [], after its restart []; forged marker on disk: False; device unchanged: True |
| T13 integration tip, `listeners` (1 forged root) | imports: 1; device roots changed by the import: ['authorization', 'listeners']; PASSED (candidate built, all product checks green); device roots differing in the built candidate [], after its restart []; forged marker on disk: False; device unchanged: True |

What T13 shows:

- **Fixed engine (`3ad74ca`, tree `345d1827` = `dd3ae49`):** the export with all twelve forged roots is refused by
  `check_export` **before** `emqx ctl data import` (0 imports); the refusal names the roots (names only) and says that
  nothing changed; this device's settings are unchanged. The unchanged control passes: no root of this device differs
  in the built candidate, after its restart or on its disk, and the forged marker is not on disk.
- **Integration tip without the check (`9ebb2bf`, tree `45db404c`):** with all twelve forged roots the vendor import runs
  (1 import), reports that some data could not be imported, and the product refuses ("部分資料無法匯入"); this device is
  unchanged. With a forged `listeners` root alone, the vendor import **does apply it inside the candidate**
  (`device_roots_changed_by_the_import` names `listeners`), and the product's post-import comparison puts every root of
  this device back: the built candidate, its restart and its disk hold this device's `listeners`, the forged marker
  is not on disk, the conversion passes. So B1-03 holds on the integration tip through the authoritative post-import
  guard; the check makes the same export refuse before anything is imported. While the forged listener existed it was
  inside a throwaway candidate that runs with `--network none` (tempctr), as every throwaway container of a job does.
- `control` passing on both trees shows that the refusals are not caused by the repacking.

### SR-5: decided by the real runs; the policy stays with the owner

`plain` with an explicit `salt_position` (`disable`, `suffix`) converts: HA's authenticator settings are HA's by design.
This device's bootstrap row is not rewritten (compared inside the candidate with its mounted bootstrap file: one row, not
equal to the password), neither at the re-attachment nor after a restart, because `import_users` runs with
`override => false` for a bootstrap file (`emqx_authn_mnesia.erl:556-565`; an existing row is kept, `:346-362`). So the
confidentiality claim of iteration 4 is wrong. The other half of the truth: that row is hashed this device's way while
the authenticator now checks HA's way, so **this device's own MQTT account is refused** after such an import (before:
login; the control with the same hash: login; a wrong password: always refused). The converted backup's note
(`hash_differs`) says so; the check page cannot, because `check()` passes no `live_authn` to `analyse` (observation, not
changed here). Not run, from the vendor code: a bootstrap row written AFTER the import (a new user in a `plain`-type
bootstrap file, or a row deleted and recreated at the next boot) is hashed with HA's algorithm (`:113-127`,
`:528-545`), i.e. stored verbatim when HA uses `plain` (`emqx_passwd.erl:104`), like every MQTT user HA itself has.

**Owner item (listed, not decided):** what the product should do when HA's built-in authenticator hashes differently
from this device and this device has bootstrap users: (a) keep converting with the `hash_differs` note (today's
behaviour), (b) refuse at check time with advice, or (c) say it on the check page before the import (needs `live_authn`
in `check()`). One authenticator per mechanism and backend (`emqx_authn_config.erl:293-298`) rules out keeping both hash
settings at once.

### Not repeated, not covered (iteration 5)

- The two items a safety classifier stopped (the boot-time loaders of HA's throwaway broker in iteration 3; a vendor probe
  of the HOCON pretty-printer round trip in iteration 4) were not touched; they stay human items.
- T13's forged roots are configuration only. A backup file of an allowed table whose content is crafted was not built: the
  vendor import then reports errors (`emqx_mgmt_data_backup.erl:745-760` expects exactly that table) and the product
  refuses any import that is not "imported successfully"; the candidate is thrown away.
- Two runs (T13 on the fixed engine, T11 ARM) ran while the older T5b of this lane was running: their `containers_left` 1
  and `dangling_volumes_new` -1 are that run's objects. At the end no container, volume or secret of this lane was left
  (checked by name).
- Process slips of this lane, for the record: a batch script was edited while bash was reading it (the batch's own exit 2
  after both its attempts had ended with 0), and two runs used the same lab names (attempt `t5b-fix`).

## Iteration 6 (2026-11-24): the runs iteration 5 left, the check read again, T14b, hand-over

Iteration 6 is a new owner instance (token SR-OWNER-1942) after the previous account's session limit stopped every lane
agent between 14:24 and 14:31. It started nothing again that was still alive: every detached run of iterations 4 and 5
had ended (the last, T13 on the integration tip, at 14:38) and their evidence is now in `iteration5/` (`t13-tip`,
`t11-fix-x86-builtin-2`, `unit-fix-2`, `mutation-export-check-1`/`-2`; rows above).

Correction of iteration 5's lane notes (not of its evidence): they said "8 of 23" crafted archives pass bcb6245; the
committed evidence (`iteration5/t14-old.json`) says 9 of 25, as the table above does. Lab leftovers
of this lane at the start of iteration 6: none (lab store containers, volumes and secrets checked by label and name).

### The rewritten check, read again as an attacker (dd3ae49)

- **File name into the expression.** The name enters an Erlang string literal only after `EXPORT_NAME_RE`
  (`[A-Za-z0-9.-]{1,80}\.tar\.gz\Z`, `re.match`): no quote, backslash or slash, so no expression injection and no path
  outside `/work/in`; the rest of the expression is constant.
- **Nothing skipped in the listing.** `erl_tar:table(F, [compressed, verbose])` answers a 7-tuple for every entry, so
  the comprehension's pattern drops none; a name that is not valid Unicode or any odd answer crashes the expression,
  which refuses (`EXPORT_UNREADABLE`). The Python side takes only `WOOWEXP:<base64>:END` then `ok`, strict JSON with
  exactly two keys and typed rows, 1 MiB at most.
- **Exact names.** Allowed members are looked up exactly (`limits.get(member, -1)`), so `./`, `//`, another case, an
  absolute name, links and devices refuse, and so does a duplicate. The vendor's own `validate_filenames`
  (`emqx_mgmt_data_backup.erl:887-902`) checks only the first path element; the product is stricter.
- **Same file, no window.** The product copies the export into a fresh volume `emqx-in` that only the candidate mounts
  (`target_broker`, `tmp.volume_import('emqx-in', …)`); HA's broker cannot reach it. `check_export` runs right before the
  only `data import` call (one call site in the engine).
- **One imprecise sentence (product comment, not a defect).** The check parses `cluster.hocon` with `hocon:binary` on the
  member read into memory; the vendor import uses `hocon:files` on the extracted file (`:904-909`). They are the same
  library but not literally the same call. Without `include` (refused by the token scan) both read the same bytes; T14b's
  differential below tests exactly that on every HOCON document of T14 and T14b.
- **`META.hocon` is not parsed by the check (accepted after reading the vendor code).** The import reads only `edition`
  and `version` from it (`validate_backup`, `emqx_mgmt_data_backup.erl:605-621`; its result is dropped, `:440`, `:678`)
  and reports a mismatch with fixed texts (`:363-368`), so extra keys or an `include` there bring no configuration in; the check still bounds its size and kind.
- **The refusal texts carry no HA text but names.** `hint` is the constant `HOT_HINT` or empty (`hint_for`), and member and
  root names go through `hacommon.names` (each cut at 60 characters, control characters shown as `?`; SR-10's fix).

### T14b: more archive shapes and the parser differential (`iteration6/t14b-fix.json`)

Component level, like T14: the product's unmodified expression in a throwaway container of the EMQX 5.8.9 image (its own
`erl_tar`, `hocon`, `emqx_utils`; `--network none`, read-only, no capabilities, 512 MiB), no broker; `check_export`
decides. Engine `dd3ae49` (tree `345d1827`). Exit 0, 97.2 s, harness `501a603`.
Result: **22/22 as expected** (cases with an expectation; 35 cases in all);
differential ran on 24/24 documents, equal on 22;
documents where `hocon:files` returns a root `hocon:binary` does not: ['bom-data-only', 'bom-root']; **cases the check passed
while `hocon:files` (what the import reads) returns a root outside `DATA_ROOTS`: none**; passed by the check
but failing in `hocon:files` (the import would then fail and the product refuse): none.

| Case | Expected | Check | Differential (`hocon:binary` / `hocon:files` roots) |
|---|---|---|---|
| `absolute-name` | refuse | refuse | — |
| `bom-data-only` | no expectation | refuse | DIFFERENT (error / 3 roots) |
| `bom-root` | refuse | refuse | DIFFERENT (error / 4 roots) |
| `char-device-table` | refuse | refuse | — |
| `cr-only-root` | refuse | refuse | equal (4 / 4 roots) |
| `crlf-root` | refuse | refuse | equal (4 / 4 roots) |
| `data-root-twice` | pass | pass | equal (3 / 3 roots) |
| `declared-size-over-limit` | refuse | refuse | — |
| `dot-segment-cluster-hocon` | refuse | refuse | — |
| `double-slash-cluster-hocon` | refuse | refuse | — |
| `fifo-table` | refuse | refuse | — |
| `folder-other-case` | refuse | refuse | — |
| `gnu-long-name` | refuse | refuse | — |
| `hard-link-table` | refuse | refuse | — |
| `include-required` | refuse | refuse | equal (error / error roots) |
| `include-word-in-comment` | pass | pass | equal (3 / 3 roots) |
| `include-word-in-string` | pass | pass | equal (4 / 4 roots) |
| `pax-path-cluster-hocon` | refuse | refuse | — |
| `pax-path-other-table` | refuse | refuse | — |
| `quoted-dotted-key` | refuse | refuse | equal (4 / 4 roots) |
| `slash-comment-root` | refuse | refuse | equal (4 / 4 roots) |
| `t14-document-in-braces` | no expectation | refuse | equal (4 / 4 roots) |
| `t14-healthy` | no expectation | pass | equal (3 / 3 roots) |
| `t14-include-directive` | no expectation | refuse | equal (3 / 3 roots) |
| `t14-not-hocon` | no expectation | refuse | equal (error / error roots) |
| `t14-root-after-quote-in-comment` | no expectation | refuse | equal (4 / 4 roots) |
| `t14-root-after-triple-quote-in-comment` | no expectation | refuse | equal (4 / 4 roots) |
| `t14-root-colon` | no expectation | refuse | equal (4 / 4 roots) |
| `t14-root-dotted` | no expectation | refuse | equal (4 / 4 roots) |
| `t14-root-nbsp` | no expectation | refuse | equal (4 / 4 roots) |
| `t14-root-plain` | no expectation | refuse | equal (4 / 4 roots) |
| `t14-root-quoted` | no expectation | refuse | equal (4 / 4 roots) |
| `t14-root-same-line` | no expectation | refuse | equal (5 / 5 roots) |
| `tab-root` | refuse | refuse | equal (4 / 4 roots) |
| `unicode-escape-quoted-key` | refuse | refuse | equal (4 / 4 roots) |

### Secret scan

With the existing lab reader and scanner (`ha_import_b1_e2e.Secrets`, `scan_host_evidence`: every lab secret value, raw and JSON-escaped; user names excluded; values never printed), at 2026-11-24 15:24 +0800: committed evidence (all iterations) 73 files, 0 hits; harness folder 26 files, 0 hits; iteration 5 scratch evidence 13 files, 0 hits; iteration 5 run outputs 36 files, 0 hits; iteration 6 scratch 3 files, 0 hits.

### Product flow on a device

This lane ran nothing on dev-d: lane emqx-product's chain10 held it, and that lane runs its attempts 35 and 36 (x86
built-in import, rollback rounds with the page's own draft) on a tree that contains `dd3ae49`, after this lane's READY
line (written at about 14:47). Those attempts are the packaging, restore, readback and rollback proof of the check on a
device. Result (from team/emqx-product.md, 15:11, read here and not re-run): the product lane merged `dd3ae49` into its branch as
`d6f2c2f` (backup-engine tree `f6dfa9c4`, exactly this lane's trial-merge tree; guarded unit set 259 + 503 OK, 0 blocked)
and **attempt-35 PASSED 95/95** on dev-d with that engine (product evidence commit `7631adb`, 14:52-15:11): the real x86
cold HA backup into the built-in target, check ok, the real conversion (HA's real export passed `check_export` right before
`emqx ctl data import`), two deliberately failed first attempts rolled back to dev-d's own state, then the real restore
(not rolled back), product readback, client probes after the restore and after a restart, and a leak scan with 0 hits.
Attempt-36 (rollback rounds, cleanup) was queued at that time; its result is the product lane's
(tests/e2e/lab/evidence/emqx-product-20261123/).

### Hand-over

- Product fix READY: `fix/emqx-export-members-20261124` @ `dd3ae49` (backup-engine tree `345d1827`). A trial merge onto
  the integration tip `2b5fee1` is clean (`git merge-tree` exit 0); merged backup-engine tree `f6dfa9c4` = `843f1881` plus
  `ha_emqx.py` of `dd3ae49` only.
- This review branch: `sec/emqx-secreview4-20261124` (evidence, harness, this README); its hash is in the lane file.

### Owner and human items (listed, not decided)

1. **SR-5 policy** (owner): see "SR-5: decided by the real runs" above, options (a) to (c).
2. **Boot-time loaders of HA's throwaway broker** (human security review): stopped by a safety classifier in iterations
   3 and 4, not retried in any form.
3. **Merge policy for Dashboard-edited ACL files** (owner, SR-2 fails closed today).
4. ~~Independent Hermes FTS/SQLite review~~ — corrected in iteration 7 (main session, 2026-11-24 15:23): not open; the owner authorized it on 2026-11-23 and the main session did it that day (`tests/backup/evidence/hermes-fts-security-review-20261123/README.md`).

### Not covered in iteration 6

- No new broker run: the real broker evidence is iteration 5's T11/T13/T5b. T14b is component level.
- No dev-d, dev-e or .54 run by this lane; no production access of any kind.
- The vendor's handling of the content of an allowed table file (see iteration 5) and EMQX versions other than 5.8.9.
- Process note: both heavy slots were held by long steps of other lanes, and a start of T14b outside `heavy.sh` (it is a
  light component test) was refused by the auto-mode classifier at 15:08; it was not retried in any form, and T14b runs
  only through `heavy.sh` (queued there since 14:53).
- `commercial_acceptance: not-complete` (this is a security review, not the end-to-end acceptance).

## Iteration 7 (2026-11-24): narrow re-review of SR-5 option C

Scope (main session, token SR-OWNER-1942): the owner decided SR-5 on 2026-11-24 15:26 (option C: warn on the check
page and name this device's MQTT accounts that must be set up again; refuse HA's `plain` at check time, so that no
clear-text password is left here). Lane emqx-sr5 implemented it on `fix/emqx-sr5-hash-warning-20261124` (base
`8844851`; product `74d237f`, backup-engine tree `5142e05c`, unchanged up to its READY tip `3c857c3`). This iteration
reviewed the `ha_emqx.py` diff against `8844851` for five properties, reran T5 and T5b in the lab store, attacked the
new code paths with a new harness (T15, `tests/e2e/lab/emqx_secreview/t15_sr5_review.py`), and checked the lane's
dev-d evidence. Review branch: `sec/emqx-secreview7-20261124` from `3c857c3` (local only, never pushed). The boot-time
loader review stays a human item.

### The five questions

1. **No password, hash or salt in the warning or in any other text — holds.** `HASH_EXPR` reads configuration fields
   only (`enable`, `name`, `salt_position`, `mac_fun`, `iterations`, `dk_length` of the global `password_based` +
   `built_in_database` authenticator). `USERS_EXPR` reads only the table KEYS (`mnesia:dirty_all_keys`; the key is
   `{user group, user id}`, `emqx_authn_mnesia.erl:65-70`) and prints the count and ten base64 ids. Both answers are
   parsed by full matches with token alphabets and strict base64 (the count must match the names); an unreadable answer
   refuses with a constant text, no raw output reaches a message. Real (T15): every text the product produced in a
   mode (blockers, warnings, job log, notes, reminders, refusal messages) was handed INTO the device broker and the
   candidate, which compared it with every stored `password_hash` and `salt` and with the mounted bootstrap password:
   0 / 0 / false in every mode, on the SR-5 engine and on the fix; the texts held no control character, no hex run of 24
   or more characters and no bcrypt prefix. dev-d: the saved check results and the job records of attempt-sr5-04/05
   (private run folders) hold the owner-decided texts only, 0 hex runs, 0 bcrypt prefixes
   (`iteration7/devd-sr5-evidence-check.json`).
2. **Names sanitized — holds.** `hash_change` passes the first ten ids through `hacommon.names` (each cut at 60
   characters; C0/C1, U+2028/U+2029 and the bidi controls shown as `?`) and adds 「等 N 個」 itself; the template is
   formatted once, so `{…}` in an id is inserted literally; the page renders engine texts as text (`h('li', {text})`,
   `checkList`). Real (T15 `bcrypt`): this device got 13 crafted ids next to `woow`. The first ten sorted bytewise
   (ESC, LF, TAB, U+202E, 202 characters, invalid UTF-8, `%s~p~s{0}{names}`, 、, HTML, the `WOOWUSERS:1:d29vdw==:END`
   marker) came back exactly through the base64 transport and the warning equals the independently computed text
   exactly (cut, `?` and U+FFFD where expected, 「等 14 個」); the other three (a comma, `:END`, a zero-width space) and
   `woow` sort after them and are only counted.
3. **`plain` refused before any conversion — holds for the global chain; not for the rest (SR-11).** The check adds
   `PLAIN_REFUSED` as a blocker (enabled or not) and then no account warning; the conversion raises right after HA's
   readings, before `emqx ctl data export`. Real: T5b `disable`/`suffix`, T5 (no `salt_position`) and T15 `conv-plain`
   and `plain-off` (disabled) refused with exactly that text; T15's spy on `ha_emqx.ctl` saw no `data export`; no
   candidate was built. The lane's dev-d attempt-sr5-04 shows the same on a device (43/43).
4. **The live capture is read-only — holds.** `device_execute` = `podman exec <this device's broker> emqx eval
   <constant>` as the owner (the target capture's OwnerRunner path, `check=False`, 120 s, bounded output); both
   expressions only read (`emqx:get_config`, `mnesia:dirty_all_keys`, `io:format`); no HA value reaches the command.
   Real (T15): a digest of the device's `emqx_authn_mnesia` table and raw `authentication` config before and after the
   check and the conversion of every mode: equal. dev-d attempt-sr5-05: "the check and the conversion changed nothing on
   this device (state digest equal)".
5. **The real dev-d evidence shows what is claimed — holds.** For all five attempts the source commit's backup-engine
   tree is `5142e05c`, `stdout_sha256` equals the sha256 of the stdout part of the 0600 private log, and the fixed status
   lines equal the private stdout's status lines; attempt-01's one failure is the harness's own assumption (one own
   account), fixed in `ae70328` and passed in 04/05. Inputs were LAB-MADE from the real x86 cold backup (the lane's
   `fixtures.json`); no unmodified real HA backup and no ARM backup went through the SR-5 engine on dev-d.

| attempt | scope | exit | engine | stdout sha256 = private log | status lines = private stdout | CHECK pass / fail |
|---|---|---|---|---|---|---|
| attempt-sr5-01 | sr5-plain-refusal | 1 | `5142e05c` | True | True | 41 / 1 |
| attempt-sr5-03 | sr5-cleanup | 0 | `5142e05c` | True | True | 23 / 0 |
| attempt-sr5-04 | sr5-plain-refusal | 0 | `5142e05c` | True | True | 43 / 0 |
| attempt-sr5-05 | sr5-bcrypt-warning | 0 | `5142e05c` | True | True | 91 / 0 |
| attempt-sr5-06 | sr5-cleanup | 0 | `5142e05c` | True | True | 23 / 0 |

### SR-11 (Low) — `plain` outside the global chain and rows still stored in clear text pass the SR-5 refusal

`HASH_EXPR` reads `emqx:get_config([authentication])`, the global chain only. EMQX 5.8.9 has more places for a
built-in password database: an MQTT listener (`listeners.<type>.<name>.authentication`, chain `'<type>:<name>'`:
`emqx_authn_config.erl:371-374`, created at boot with the global one: `emqx_authn_chains.erl:1015-1021`), a gateway
(`gateway.<name>.authentication`, chain `'<name>:global'`: `emqx_gateway_utils.erl:457-475`) and a gateway listener
(`emqx_gateway_insta_sup.erl:295-307`). All of them keep their rows in the one table the export carries whole
(`emqx_authn_mnesia.erl:105` `backup_tables`; the user group is the chain name), and `gateway` is a data root, so a
gateway's `plain` authenticator is imported too (later gateway users would be stored in clear text here). A row also
keeps the hashing it was written with: an algorithm change never re-hashes it (`emqx_authn_mnesia.erl:130` update =
create), and a row written under `plain` holds the password itself with an empty salt
(`emqx_authn_password_hashing.erl:206-207`, `emqx_passwd.erl:104`). `PLAIN_REFUSED`'s own advice (change the algorithm,
then set every password again) leads there when one account is skipped.

**Proven for real on the SR-5 engine** (`iteration7/t15-sr5b.json`): EMQX itself (a throwaway source broker in HA's
layout) wrote two rows under a `plain` built-in database of (a) a STOMP gateway, (b) an MQTT listener, (c) the global
chain before HA's config switched it to sha256; the product's check showed no blocker and no warning, the conversion
PASSED with HA's export, and the candidate held two rows whose stored value IS the password:
- `gw-plain`: check blockers none; no account warning; ids exact; conversion PASSED; HA export ran; candidate rows=3 clear=2; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 6: control 0, hex runs 0, bcrypt prefix 0
- `listener-plain`: check blockers none; no account warning; ids exact; conversion PASSED; HA export ran; candidate rows=3 clear=2; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 6: control 0, hex runs 0, bcrypt prefix 0
- `past-plain`: check blockers none; no account warning; ids exact; conversion PASSED; HA export ran; candidate rows=3 clear=2; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 6: control 0, hex runs 0, bcrypt prefix 0

Severity **Low**: the passwords are HA's own and were already in clear text in HA's backup; here they would sit in
the converted backup and, after the restore, in this device's EMQX data volume. But it defeats the owner's stated goal of option C (「也不會留下明文
密碼」), and path (c) follows from the product's own advice.

**Fix** (`9665533`, `ha_emqx.py` only in `backup-engine/`; tree `3ea9610f`): `PLAIN_EXPR`, evaluated in HA's broker only,
answers the number of `plain` built-in databases outside the global chain (MQTT listeners, gateways, gateway listeners),
the number of rows with an empty salt whose stored value is neither hex (every other algorithm stores lowercase hex:
`emqx_passwd.erl:106-113`, `148-150`) nor a bcrypt string (bcrypt's salt is never empty:
`emqx_authn_password_hashing.erl:221-224`), and the first ten of their user ids (base64; never a password, hash or
salt; a row of an unknown shape answers `bad`, which refuses). `parse_plain` is strict like `parse_users`.
`plain_blocker` returns `PLAIN_REFUSED` first, then `PLAIN_ELSEWHERE`, then `CLEAR_ROWS` (names through
`hacommon.names`); both new texts tell the customer what to do in HA. They refuse at the check and stop the conversion
right after HA's readings, before HA's export, like `PLAIN_REFUSED`. docs/backup.md and CONTRACT §9 quote them. The
page needs no change (a blocker disables 轉換; the lane's page test covers that for `PLAIN_REFUSED`).
Blind spot (residual): a clear-text password that is itself lowercase or uppercase hex of any even length is not
detected by the row check (the configuration checks still catch every `plain` authenticator that still exists).

**Tests:** `tests/backup/test_ha_emqx_plain_review.py` (14: refusal texts at the check and in the conversion, nothing
built or exported, order with `PLAIN_REFUSED`, no account warning next to the refusal, names sanitized and counted,
unreadable answers refuse, only HA's broker is asked, expression pins, parser and blocker units, docs quote the engine);
the World double in `test_ha_emqx.py` answers `PLAIN_EXPR`. Mutation check (`iteration7/mutation-s1-9665533.json`):
**15/15 killed**, unmutated 55 tests OK (elsewhere ignored, clear rows ignored, HA not asked, conversion refusal after the export, lenient answer, names count unchecked, names unsanitized, no count beyond ten, global text not first, bad shape accepted, listeners not read, gateways not read, gateway listeners not read, hash printed, salt not required empty). Guarded runner
(integration-3 `guard.py`, no podman/ssh/sudo/systemctl process): every `tests/backup/test_ha_emqx*` module + the lab
EMQX modules the SR-5 lane ran: tests=315 failures=0 errors=0 skipped=0 expected_failures=0 unexpected_successes=0 blocked=0 shim_hits=0 run_native=denied elapsed=14 (every tests/backup/test_ha_emqx* module + tests.e2e.lab test_emqx_product_real_ha, test_emqx_real_candidate, test_emqx_candidate_acl_component); full `tests/backup` with the real batch-1 backups (`--b1`):
tests=1828 failures=2 errors=3 skipped=1 expected_failures=0 unexpected_successes=0 blocked=6 shim_hits=0 run_native=denied elapsed=301; the only not-ok are 5 tests of tests.backup.test_litellm_lab_runner.LabRunnerTests (the known guard-blocked ones, the same 5 ids as the SR-5 lane's s2 run at ae70328 and the integration baseline) (`iteration7/units-s1-9665533.json`).

**Rerun on the fix** (`iteration7/t15-fix7.json`, all seven modes) and on HA's REAL rows (T11):
- `bcrypt`: check blockers none; account warning exact; ids exact; conversion PASSED; HA export ran; note + reminder exact; candidate rows=1 clear=0; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 9: control 0, hex runs 0, bcrypt prefix 0
- `conv-plain`: check blockers PLAIN_REFUSED; no account warning; ids exact; conversion REFUSED; HA export never ran; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 3: control 0, hex runs 0, bcrypt prefix 0
- `gw-plain`: check blockers PLAIN_ELSEWHERE; no account warning; ids exact; conversion REFUSED; HA export never ran; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 3: control 0, hex runs 0, bcrypt prefix 0
- `listener-plain`: check blockers PLAIN_ELSEWHERE; no account warning; ids exact; conversion REFUSED; HA export never ran; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 3: control 0, hex runs 0, bcrypt prefix 0
- `past-plain`: check blockers CLEAR_ROWS; no account warning; ids exact; conversion REFUSED; HA export never ran; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 3: control 0, hex runs 0, bcrypt prefix 0
- `plain-off`: check blockers PLAIN_REFUSED; no account warning; ids exact; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 3: control 0, hex runs 0, bcrypt prefix 0
- `same`: check blockers none; no account warning; ids exact; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 1: control 0, hex runs 0, bcrypt prefix 0
- T11 x86 (real b1 x86 cold backup, `[file, built_in_database]` target, conversion body with this device's profile):
  exit 0; PASSED (candidate built, all product checks green, profile equal); fixture `woow-b1-x86-emqx-stopped-enc.tar` (sha256 prefix 0a53e93888209316); HA rows: 3 MQTT users, 4 ACL, 2 Dashboard users, 5 retained; candidate profile ['file', 'built_in_database']; device config unchanged True; 44 readback roots; containers left 0, new dangling volumes 0; cookie on the command line False
- T11 ARM (real b1 RPi5 ARM cold backup, same): exit 0; PASSED (candidate built, all product checks green, profile equal); fixture `woow-b1-arm-emqx-stopped-enc.tar` (sha256 prefix b6eb257cc5790bee); HA rows: 3 MQTT users, 4 ACL, 2 Dashboard users, 5 retained; candidate profile ['file', 'built_in_database']; device config unchanged True; 44 readback roots; containers left 0, new dangling volumes 0; cookie on the command line False

### T5 and T5b on the SR-5 engine (`5142e05c`)

- T5 (iteration 3's HOCON: `plain` without `salt_position`): REFUSED with exactly 「EMQX 不能搬過來：」 + `PLAIN_REFUSED`
  (41.2 s); device bootstrap row before: rows=1:plain=0.
  Iteration 3's artefact (the authentication-root comparison) is gone: the refusal is now the decided one.
- T5b: `disable`: REFUSED (PLAIN_REFUSED), 29.6 s; `suffix`: REFUSED (PLAIN_REFUSED), 26.4 s; `control`: PASSED, 126.7 s; candidate rows=1:plain=0, own=login:wrong=refused; after restart rows=1:plain=0, own=login:wrong=refused. Device before
  rows=1:plain=0 (own=login:wrong=refused), after rows=1:plain=0.
- T15 on the SR-5 engine, the decided behaviour (`iteration7/t15-sr5.json`):
  - `bcrypt`: check blockers none; account warning exact; ids exact; conversion PASSED; HA export ran; note + reminder exact; candidate rows=1 clear=0; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 9: control 0, hex runs 0, bcrypt prefix 0
  - `conv-plain`: check blockers PLAIN_REFUSED; no account warning; ids exact; conversion REFUSED; HA export never ran; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 3: control 0, hex runs 0, bcrypt prefix 0
  - `plain-off`: check blockers PLAIN_REFUSED; no account warning; ids exact; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 3: control 0, hex runs 0, bcrypt prefix 0
  - `same`: check blockers none; no account warning; ids exact; device digest equal; leak rows 14, hash 0, salt 0, bootstrap password false; texts 1: control 0, hex runs 0, bcrypt prefix 0

### Real runs of iteration 7 (lab store `labpodman`, every container `--network none`, generated values only)

| run | engine | exit | seconds | evidence |
|---|---|---|---|---|
| T15 first attempt: 4 modes real, 3 plain-row modes = harness error (source broker data dir; fixed 698f39b, kept) | `5142e05c` | 0 | 1230.8 | `iteration7/t15-sr5.json` |
| T5b (SR-5): `disable`, `suffix` (plain) and the same-hash `control` | `5142e05c` | 0 | 197.6 | `iteration7/t5b-sr5.json` |
| T5 (SR-5): `plain` without `salt_position` (EMQX fills `prefix`) | `5142e05c` | 0 | 41.4 | `iteration7/t5-sr5.json` |
| T15 plain-row modes on the SR-5 engine (the SR-11 proof) | `5142e05c` | 0 | 643.3 | `iteration7/t15-sr5b.json` |
| T15 all 7 modes on the SR-11 fix | `3ea9610f` | 0 | 960.5 | `iteration7/t15-fix7.json` |
| T11 real b1 x86 cold backup, conversion body, `[file, built_in_database]` target, on the fix | `3ea9610f` | 0 | 211.6 | `iteration7/t11-fix7-x86-builtin.json` |
| T11 real b1 ARM (RPi5) cold backup, same, on the fix | `3ea9610f` | 0 | 227.8 | `iteration7/t11-fix7-arm-builtin.json` |

Every run went through `team/heavy.sh` under this lane's own lock. Lab left by this lane after the last run (18:25):
0 containers, 0 volumes, 0 secrets (by label and by name); T11: 0 containers and 0 new dangling volumes per run. Code identities: `5142e05c` = `3c857c3` (SR-5 READY), `3ea9610f` = `9665533` (SR-11 fix).

### Other observations (no code change here; for the product lane)

- **O-1 (UX):** the warning lists the first ten ids sorted bytewise; with more than ten accounts this device's own
  service account (`woow`, the bootstrap user) can be hidden behind 「等 N 個」 (T15: `woow` sorted last). Listing the
  bootstrap file's accounts first would help the customer.
- **O-2:** zero-width and other format characters (U+200B-U+200D, U+2060, U+FEFF, U+00AD) are not replaced by
  `hacommon.names`, so two names can look alike in the list. Shown only to this device's owner, about this device's
  own accounts; Low.
- **O-3 (the SR-5 verifier's open edge):** `hash_change` ignores HA's `enable` and a missing HA built-in database. With
  HA's built-in database disabled or absent the check names no account; on a device with bootstrap users the
  conversion then refuses (`preserved_bootstrap_authn`: no single enabled HA authenticator for the bootstrap file), so
  the check passes and the conversion refuses (fail closed, but the page does not predict it); on a device without
  bootstrap users its accounts stop working and only the general note says the MQTT accounts become HA's.
- **O-4:** accounts this device created in its Dashboard are replaced by HA's in every import (the candidate keeps only
  the bootstrap rows), equal hashing or not; the warning covers the hashing case, the general import note the rest.
- **O-5:** listener-level and gateway accounts of this device are not named by the warning (CONTRACT §9 says so).

### Secret scan

With the existing lab reader and scanner (`ha_import_b1_e2e.Secrets`, `scan_host_evidence`: every lab secret value, raw
and JSON-escaped; values never printed), at 2026-11-24 18:26 +0800: committed evidence (all iterations) 84 files, 0 hits; harness folder 21 files, 0 hits; SR-5 lane evidence (emqx-sr5-20261124) 6 files, 0 hits; EMQX product attempts folder (incl. attempt-sr5-*) 41 files, 0 hits; iteration 7 scratch evidence 24 files, 0 hits; iteration 7 run outputs 30 files, 0 hits; SR-5 private run logs 20261124T161203 16 files, 0 hits; SR-5 private run logs 20261124T161757 4 files, 0 hits; SR-5 private run logs 20261124T162320 15 files, 0 hits; SR-5 private run logs 20261124T163039 21 files, 0 hits; SR-5 private run logs 20261124T164629 4 files, 0 hits.

### Not covered in iteration 7

- **No dev-d run by this lane.** The device product flow of the SR-11 engine is the final verification's EMQX run on
  the final tip (main session 17:23 and 17:56: the real RPi5 ARM cold backup through the full chain on dev-d, after
  integration-3's final line; that run also shows that neither the SR-5 warning nor an SR-11 refusal appears for real
  backups with equal hashing). The final tip's backup-engine differs from the SR-5 engine only in `ha_emqx.py`.
- SCRAM, pbkdf2 and other salt variants (unit level and vendor reading only), the account warning for listener or
  gateway users, a device that itself uses `plain` (its own choice; only HA's side is refused), EMQX versions other
  than 5.8.9.
- The clear-row check's blind spot (a clear-text password that is entirely hex), see SR-11.
- Other secrets HA's data carries as they are, by design and outside option C (which is about MQTT account passwords):
  TLS-PSK shared secrets (`emqx_psk`, TLS-PSK needs them in clear) and passwords or tokens inside migrated connectors,
  bridges and actions (EMQX keeps those in its configuration; SR-3/SR-6/SR-7 stop the paths to THIS device's secrets).
- `commercial_acceptance: not-complete` (a security review, not the end-to-end acceptance).

### Owner and human items

1. **Boot-time loaders of HA's throwaway broker** (human security review): stopped by a safety classifier in iterations
   3 and 4, not retried in any form.
2. **SR-11 widens option C's refusal** to the other places `plain` lives (as the owner's stated goal requires); it
   refuses HA backups that `3c857c3` converted. If the owner prefers another remedy for old clear-text rows (for
   example dropping them with a note instead of refusing), that is a new decision; the code follows option C as
   worded today.
(Decided, no longer open: SR-5 = option C, implemented; Dashboard-edited ACL files = option A, a known limitation;
the Hermes FTS/SQLite review was done by the main session on 2026-11-23.)
