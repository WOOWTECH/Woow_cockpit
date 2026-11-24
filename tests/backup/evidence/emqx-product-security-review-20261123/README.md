# EMQX HA import (product path) — independent adversarial security review (2026-11-23 and 2026-11-24)

Lane emqx-secreview (owner instance SR-OWNER-1942), three iterations. This review attacked the product import as a
malicious HA backup would, fixed what it could prove, and reran the attacks against the engine that is handed over.

## Summary (read this first)

- **Ten findings, SR-1 to SR-10.** Five High/Medium findings were confirmed by real attacks and fixed (SR-1, SR-2, SR-3,
  SR-6, SR-8); SR-7 (Medium) is a refusal added because the vendor code proves the leak, its ExHook trigger is
  exercised by T12 (iteration 2); SR-4 and SR-9 are Low and fixed. **SR-5 (Low) is OPEN**: iteration 3's "refused fail
  closed, no finding left" was wrong — the verifier showed the refusal was an artefact of a crafted HOCON without an
  explicit `salt_position`; with one, no engine check refuses a built-in-database `plain` authenticator, so this
  device's own bootstrap password is stored in clear text in the migrated built-in database (see Iteration 4). **SR-10
  (Low) was found in iteration 4** in exactly the handed-over tree 865c930f and is fixed on the integration branch
  only (65d8a51, 97c994f): a C0/C1/bidirectional/line-separator character in an HA plugin name, a `/share` path or a
  skipped-symlink name reached a check warning raw or forged a second job-log line.
- **Where the fixes are:** SR-1, SR-2, SR-3 75aad7a; SR-6 f397590; SR-7 7b173af; SR-4 in the product's own 7449540; SR-8 and
  SR-9 abff1a0 (all in the handed-over engine 865c930f, the last merged as 620bdd5). SR-10 is on the integration branch
  (65d8a51, 97c994f), NOT in 865c930f. SR-5 is open (remediation is an owner policy choice, see Iteration 4).
- **Engine reviewed in iteration 3:** `feat/ha-import-emqx-product-20261124` @ `e08f8a1` (product READY of 08:30), `backup-engine` tree `865c930f392006e0080de506eb7c425fd81becd7` = the product tip `5786ae4` + `abff1a0` (merge `620bdd5`) + the Podman 6 tempctr fix (cherry-pick `e08f8a1`, patch id equal to `8613ffa` and `c8df1f2`); the review reruns used the same tree as trial commit `cd66230`.
- **What passing here means:** this review proves conversion and refusal behaviour of the product's own code against
  real EMQX 5.8.9 brokers in throwaway rootless lab containers with `--network none`. It is not the commercial
  acceptance; the product lane's dev-d chain and the .54 runs (Podman 6.1.1, ARM and x86 backups) are the product flow
  evidence. `commercial_acceptance: not-complete`.
- **Not covered:** see the last section. Items that need a human/owner: the boot-time behaviour of HA's throwaway
  broker on HA's own files (reviewed only in part, one analysis step stopped by a safety classifier in iterations 3
  and 4 — a human item, not retried), a merge policy for Dashboard-edited ACL files, the SR-5 remediation policy
  (refuse a `plain` authenticator vs re-hash the device's bootstrap users), and the independent Hermes/FTS review.
- **Iteration 4 (this revision)** closed the independent verifier's points against iterations 1-3: SR-10 found and
  proven (fixed at integration), SR-5 reopened and decided, B1-03 proven and a pre-import export-member check added as
  product hardening (branch `fix/emqx-export-members-20261124`), and the overclaims corrected (what T4/T10/T11 really
  ran, that an exit code of 0 is not a verdict, the hard-coded `candidate_env_file_flag`, 6 of 24 volumes attributed
  by timing only, the follower ended by main at 08:14, the first T9/T10 runs with no attempt JSON, and the host-wide
  Podman event dump that iteration 2 kept and main deleted). See **## Iteration 4**.

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
| SR-5 | Low | **OPEN.** HA's authenticator hash settings (e.g. `plain`) apply to this device's bootstrap users, which the product re-attaches to HA's built-in authenticator (`preserved_bootstrap_authn`). With an explicit `salt_position`, no engine check refuses a built-in-database `plain` authenticator, so this device's own bootstrap MQTT password is stored verbatim (`emqx_passwd.erl:92-105` `hash_data(plain, P) = P`) in the candidate's built-in database, and so in the converted backup. Iteration 3's "refused fail closed" was an artefact of a crafted HOCON without `salt_position` (verifier). | OPEN Low (Iteration 4); remediation is an owner policy choice (refuse a `plain` authenticator when the device has bootstrap users, or re-hash the device's bootstrap users with the device's own algorithm) |
| SR-8 | Medium | 3761d18: the device's `EnvironmentFile=` values reached a world-readable command line of the candidate | fixed abff1a0, reproduced and verified for real (T9) |
| SR-9 | Low | 3761d18: the candidate's environment was not read the way podman reads it for the broker | fixed abff1a0, verified against podman (T10) |
| SR-10 | Low | A C0/C1/bidirectional/line-separator character (e.g. U+202E, U+2066, U+0085, U+2028) in an HA EMQX plugin name, a `/share` file reference or a skipped-symlink name reached a check warning raw, or forged a second job-log line, in the handed-over tree 865c930f | fixed on the integration branch only (65d8a51 `hacommon.names`; 97c994f the twelve bidi controls in names and `jobs.LOG_CONTROL_RE`); NOT in 865c930f. Proven in process: forged=True on 865c930f, forged=False on the integration tip (Iteration 4) |

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
| Is the decompression or parsing risky? | `tarfile.open(mode='r|')` reads a plain (never compressed) stream from at most 64 KiB; errors give "no entry" and nothing is applied. |
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
  equality of every setting that is not HA data, table counts, SR-2/SR-3/SR-6/SR-7 refusals, decision C). Recommended
  defense in depth (not implemented): check the export's members before `data import` (only the TABLE_SETS tables and
  `cluster.hocon` roots within DATA_ROOTS) and `--cap-drop=all` for `emqx-ha`.
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
  independent Hermes FTS review; other EMQX versions than 5.8.9 and add-on versions outside VERSIONS; the host's Podman
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
