# EMQX SR-5: MQTT password hashing named on the check page (owner decision 2026-11-24, option C)

Lane emqx-sr5, R-COCKPIT branch `fix/emqx-sr5-hash-warning-20261124` (local only, never pushed), based on the
integration tip 8844851; merges cleanly onto the integration tip 13051d0 (`git merge-tree`). `commercial_acceptance`:
**not-complete** — the owner accepts; unit, fixture and mutation results here are not acceptance, the real attempts on
dev-d are the product-flow proof of this change only.

The owner's decision, in the owner's words: 「匯入前在檢查頁先警告，列出哪些 Podman 帳號會失效、要在匯入後重新設定；
如果 HA 用的是「不加密」的方式，就直接擋下。客戶事先就知道後果，也不會留下明文密碼。」

## What the product does now (backup-engine tree 5142e05c)

HA's `authentication` root replaces this device's during an EMQX import, and EMQX 5.8.9 checks every stored row of the
built-in password database with the authenticator's *current* hashing; it never re-hashes a stored row
(`emqx_authn_mnesia.erl:130-161`; the bootstrap import never overwrites a row, `:556-565`). So:

| HA's built-in database hashing vs this device's | check (before any conversion) | conversion |
|---|---|---|
| a row of this device still verifies (same simple algorithm and salt position; or this device writes without salt; bcrypt/bcrypt; pbkdf2 with the same MAC, iterations and derived length) | nothing added | nothing added |
| it does not, and this device has built-in users | **warning** naming those accounts (at most ten, control characters shown as `?`, 「等 N 個」 for more): they no longer log in with their passwords after the import and must be set up again, and how | goes on; the import note and the EMQX reminder name the same accounts |
| it does not, but this device has no built-in user | nothing added | nothing added |
| HA uses `plain` (enabled or not) | **blocker** with the advice (change `password_hash_algorithm` in HA, set every password again — EMQX does not convert stored passwords — then back up again) | refused right after HA's readings, before HA's export |
| HA's or this device's hashing, or this device's users, cannot be read | blocker 「無法讀取…EMQX 帳號驗證設定（MQTT 密碼的雜湊方式），已停止。」 | refused before anything is built |

Reads: HA's throwaway broker and, read-only as the owner (the OwnerRunner `podman exec` the target capture uses), this
device's running broker answer `HASH_EXPR` (enable, name, salt_position and pbkdf2's mac_fun/iterations/dk_length of the
`password_based` + `built_in_database` authenticator); this device also answers `USERS_EXPR` (the user ids of its
`'mqtt:global'` group through `mnesia:dirty_all_keys`: the count and the first ten names, base64 each; never a password
hash or salt). The old conversion-only note (「…可能無法登入（例如 woow）」, an (algorithm, salt) pair, and a check-side
warning that never fired because this device's authenticators were never passed to it) is replaced: the restore step
still names the accounts (that is when the customer acts) and the EMQX reminders say how to set them up again.

Vendor basis (emqx v5.8.9): `emqx_authn_password_hashing.erl:206-207,237-243,252-269`, `emqx_passwd.erl:67-104,140-158`,
`emqx_authn_mnesia.erl:65-70,114-161,390-401,556-565`, `emqx_authn_chains.erl:667-668,1000-1008`,
`emqx_authn_config.erl:298`, `emqx_authn_api.erl:1051-1062,1179-1183`.

## Commits (R-COCKPIT, local only)

| commit | what |
|---|---|
| 74d237f | product: `backup-engine/woowbackup/ha_emqx.py` (HASH_EXPR, USERS_EXPR, parse_hashing/parse_users, rows_still_verify, device_accounts, hash_change, PLAIN_REFUSED, ACCOUNTS_STOP, RESET_HOW; check, conversion, import texts), `docs/backup.md`, CONTRACT section 9 (EMQX), `tests/backup/test_ha_emqx_sr5.py`, the World double of `tests/backup/test_ha_emqx.py` |
| 85b24dc | tests: the two device reads pinned to the built-in database and the global chain |
| ae70328 | tests: the two gaps the first mutation run found (pbkdf2 MAC alone; excess base64 padding) + harness fix below |
| 7593108 | `tests/backup-ui.mjs`: the page shows the warning (app importable, 轉換 enabled) and the plain refusal (app blocked, 轉換 disabled); the page code is unchanged (it renders the engine's warnings and blockers) |
| 2867185, 1ebfe81 | lab fixtures: `tests/e2e/lab/emqx_noacl_fixture.py fileonly hash=bcrypt\|plain`, their SHA-256 and build facts (`fixtures.json`) |
| 074858e, ae70328 | lab harness: the emqx-product harness `tests/e2e/lab/emqx_product_real_ha.py` gets the step `sr5:TAG` (+ offline tests) |
| f0538ff, 148ecc4, 4093411, c7524f7, 64c2e58 | evidence of the real attempts (written by the chain, never edited) |

backup-engine tree **5142e05c** from 74d237f on (every later commit is tests, lab or evidence).

## Tests (not acceptance) — `unit-tests.json`

- full `tests/backup` with the real batch-1 backups (guarded, heavy.sh): **1814** tests at ae70328 (and at 85b24dc); the only
  not-ok are the 5 guard-blocked tests of `test_litellm_lab_runner`, exactly the integration baseline's.
- `backup-ui`: **108/108** at ae70328, including the new SR-5 page test.
- SR-5 module + harness offline tests: 67 OK; lab EMQX modules 61 OK; `scripts/check_source.py` passed.
- mutation sweep, 37 one-place mutations of the SR-5 code (warning names, equal hashing, salt/bcrypt/pbkdf2 rules, plain
  refusal at the check and before HA's export, unreadable answers, the users read never returning hash or salt, control
  characters, the conversion texts): **35/37** at 85b24dc (survivors: `pbkdf2 mac ignored`, `lenient base64`), the
  two tests added in ae70328, **37/37** at ae70328 (`mutation-sr5-s1-85b24dc.json`, `mutation-sr5-s2-ae70328.json`).

## Real runs on dev-d (product flow through the installed helper, the page's own commands)

Inputs (`fixtures.json`): two **lab-made** variants of the real x86 cold batch-1 HA backup, built by EMQX 5.8.9 itself in
the lab store (no ACL rows, HA authorizes with its ACL file only): `x86-bcrypt` (HA's hashing sha256/suffix -> bcrypt;
HA's three MQTT users got their b1 test passwords again through EMQX and log in with them, 3/3, a wrong one 0/3) and
`x86-plain` (-> plain/disable; no password set again, so no clear-text password in the file). The hashing was read by
the product's own HASH_EXPR on a real broker (its first real use). dev-d's own target: EMQX 5.8.9, authorization
[file], hashing sha256 with salt after (the product package's base.hocon), own built-in accounts `woow` (bootstrap file)
and `woowbk-lab-baseline` (the batch1 baseline marker, created through the API).

| attempt | hold | result | what |
|---|---|---|---|
| attempt-sr5-01 | 307 s | exit 1, 41/42 | setup (this tree into dev-d), before (B0), plain: every product check passed; the one failure was the harness's own assumption that woow is dev-d's only account (it also has woowbk-lab-baseline) — kept as evidence, fixed in ae70328 |
| attempt-sr5-03 | 34 s | 23/23 | cleanup after 01 (by design): test backups, lab-made uploads and that B0 deleted, leaks 0 |
| attempt-sr5-04 | 394 s | **43/43** | plain: the check refuses with exactly PLAIN_REFUSED as its only blocker, no account warning; the conversion (started through the helper anyway) is refused, incompatible, with the same text; no backup, no throwaway object; dev-d's EMQX state digest equal to before; markers; woow and woowbk-lab-baseline log in, HA's users are refused |
| attempt-sr5-05 | 903 s | **91/91** | bcrypt: both own accounts log in first; the check is ok and its only SR-5 warning is the owner-decided text naming exactly 「woow、woowbk-lab-baseline」 (HA bcrypt, this device sha256，鹽在後); the conversion's note and EMQX reminder name them; check and conversion changed nothing; restore ok (safety backup, the product's readback passed); after the restore and after a restart HA's three users log in with their passwords while woow (row kept, old hash: CONNACK 4) and woowbk-lab-baseline (gone: 5) are refused, and every other check of the x86-fileonly import holds (Dashboard, ACL file governs, retained messages, rules, API key, banned client, anonymous refused); the warning's remedies work: woow deleted as HA's admin + EMQX restarted = back from the bootstrap file with this device's password, woowbk-lab-baseline created again = logs in; manual rollback to B0: digest equal to the one before any import, both own accounts log in again; leaks 0 |
| attempt-sr5-06 | 31 s | **23/23** | cleanup: no job object, staging or key file; lab-made uploads, converted and safety backups deleted; B0 deleted; woow-emqx and its entrance run; leaks 0 |

Every hold through team/heavy.sh with the dev-d lock, isolation `true none {}` before and after, no anonymous volume left.
The evidence JSONs hold fixed status lines only; the complete redacted output stays in the private lab folder.

## Simulated, not covered, open

- **Lab-made inputs**: the two HA backups are the real x86 cold backup changed by EMQX itself in the lab, not backups of
  a customer HA whose owner chose bcrypt or plain. The vendor reading covers the other hashings (pbkdf2, salt
  positions); only bcrypt (warning) and plain (refusal) ran for real.
- **dev-d's own accounts**: two (a bootstrap one and an API-created one); "exactly those accounts fail" is proven for
  these two, whose passwords the harness knows. The "等 N 個" form for more than ten names is unit-tested only.
- **The page**: dev-d publishes no port, so the browser page did not run against dev-d; the helper commands are the
  page's, and the page's rendering of the engine's warning and refusal is proven by the backup-ui fixture test only.
- **MQTT clients** are the harness probe inside dev-d.
- Not covered: a SCRAM authenticator's algorithm, listener-level authenticators, a bootstrap file of type `hash` (the
  conversion still refuses one whose hashing differs, the check does not predict it), ARM HA backups for SR-5 (.54 and
  the RPi5 belong to lane arm54), production (never touched).
- Next: the narrow security re-review by emqx-secreview, then integration-3 merges. `commercial_acceptance`:
  not-complete.
