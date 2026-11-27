# R4 generated cases, the remaining eight — all passed (2026-11-28, dev-d)

With `plain`, `dead_row` and `noauth` (27cb52c4, 2026-11-27) this completes the eleven generated R4 cases of
`snippets/focus-emqx-r4/matrix.json`. Each case ran once under its own 20-minute lease on network-isolated dev-d,
on the cached EMQX 5.8.9 image `sha256:3f60addf…`, with the backup engine of the integration tip (equal to draft
PR #23): a generated source broker, the real vendor export, the product's convert and postcheck, a candidate, a
restart, and the case's own assertions, then cleanup.

| Case | Decision | Result | Driver |
|---|---|---|---|
| `admin_public` | D2/H3 | 24/24 | `42d9f5ed` |
| `changed_acl` | D3 | 31/31 | `42d9f5ed` |
| `psk` | E-43 | 26/26 | `42d9f5ed` |
| `http_dummy` | D4/S1 | 29/29 (native03) | `c1f03cf0` |
| `file_dummy` | D4/S1 | 27/27 | `c1f03cf0` |
| `jq_constant` | D4/S1 | 27/27 | `c1f03cf0` |
| `env_dummy` | D4/S1 | 27/27 | `c1f03cf0` |
| `lost_auth_setting` | E-67 | 15/15: the import is refused as expected (`incompatible`), the target unchanged | `c1f03cf0` |

Every case reports empty temporary objects, unchanged durable images and volumes, no unrelated container churn, no
catalog access, no installed-source access and no package smoke (by design).

## http_dummy needed two driver fixes, no product change

- native01 (`42d9f5ed`): the loopback HTTP dummy was ready, yet the first login was refused.
- native02 (`a968fe4f`, which added a bounded login retry): no CONNACK at all within the probe's 3 s; the device
  log shows `{badmatch,{error,timeout}}`.
- Cause: the dummy served one connection at a time and waited up to 3 s on each, while EMQX's HTTP backend keeps a
  pool of idle connections; the real authentication request queued behind them. `c1f03cf0` gives every accepted
  connection its own process and counts an unreadable answer as one more try in the HTTP cases.
- native03 recorded the login codes: source `[5, 0]`, candidate after the restart `[5, 5, 0]`, i.e. EMQX's backend
  needs a few seconds to reach a dummy that starts after the broker, then logins pass. A real deployment's auth
  server is up before the broker.

## Files

Per case `<case>/nativeNN.json` is the fixed original result (no credentials, environment, inspect output or private
logs). `generated-20261128-cleanup.json` records the independent scan afterwards (no job-owned container, volume or
network; the two failed-attempt work folders removed by literal path; the earlier lane's failed export payload left
untouched for its own cleanup lease) and every case's job id, checks and login codes.

Scope: controlled generated internal candidate, restart and postcheck deltas only. Not proven here: the exact package
per case and its smoke, the real upgrade, the H1 device-environment check (no driver yet) and ARM.
`commercial_acceptance`: `not-complete`.
