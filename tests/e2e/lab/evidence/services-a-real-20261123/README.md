# services-a real HA backup acceptance runs — 2026-11-23

Lane services-a (Omnigent and Headscale). Branch `test/services-a-final-20261123`, started from
R-COCKPIT `feat/ha-import-batch1` (b2f63ce). Every attempt is kept; each JSON holds the source
commit, exit code, elapsed seconds, the SHA-256 of the complete stdout and only fixed status lines.
`commercial_acceptance` stays `not-complete` in every file (see "What is still not proven").
All lab work ran in dev-d (`owner.sh d --verify-isolation` = `true none {}` before and after every
attempt) while holding `/tmp/woowbk-dev-d-mutation.lock`. No production host service, secret, image
or catalog was read or changed. No public import guard was touched.

## Headscale — `tests/e2e/lab/headscale-real-test.sh <arm|x86> --installer`

| Attempt | Source | Exit | Seconds | Result |
| --- | --- | ---: | ---: | --- |
| `headscale-arm-attempt1.json` | 9b3860d | 1 | 88.0 | Stopped at the runner's `target` step: the harness's disposable target had no `extra_records.json`; headscale 0.29.4 refuses to start then (`hscontrol/dns/extrarecords.go:45-48`). Fixed in a8328e2 by seeding it like the Podman package (`hs_ensure_extra_records`). Cleanup, inventory and isolation passed. |
| `headscale-arm-attempt2.json` | 8764b81 | 0 | 306.7 | **PASS** — all checks below. |
| `headscale-x86-attempt1.json` | b25aa9c | 0 | 256.1 | **PASS** — same chain on the b1 x86 backup (3 users, 2 nodes, 1 HA API key replaced, 1 DNS record, HA public Noise key). The x86 source has no real client (b1 source summary): two new devices joined with HA's x86 reusable pre-auth key and exchanged 10/10 + 1 DERP pongs; installer phases were checked server-side (`client=none`): exactly HA's nodes, exact cold-export identity, rollback markers. |

What the passing ARM run used and proved (real unless stated):

* **Source**: the actual b1 RPi5 Supervisor backup `woow-b1-arm-plain.tar` (sha256 equal to the recorded
  fixture value before staging, inside dev-d before conversion and again after it). The product parser
  read the real outer envelope, `backup.json`, the repository-prefixed add-on member and `addon.json`
  (0.1.3, aarch64, stopped).
* **Conversion**: the unmodified product `ha_headscale.convert`. The RPi5 database is a 4 KiB
  `db.sqlite` plus an uncheckpointed WAL; the product's sandboxed SQLite child applied the WAL —
  3 users and 2 nodes came out. HA's 1 API key was replaced by the target's 1 key; 1 DNS record.
  HA's Noise private key in the converted volume equals the one in the backup (compared in memory).
* **Target**: a disposable Headscale 0.29.4 in dev-d with its **own** URL (`https://headscale.lab:8080`,
  lab CA), its **own** API key and config, HA's prefixes, and a **local non-empty DERP map** (embedded
  region 999, `urls: []`, no external nameserver). dev-d's own `headscale.service` was not touched
  (it still crash-loops on its offline config with an empty DERP map).
* **Restored data**: users (ids, names), nodes (ids, names, users, IPv4/IPv6, approved route),
  pre-auth keys (count and flags), the DNS extra record, only the target API key listed, and
  `GET /key` returns HA's public Noise key.
* **Real client**: the state of the real tailscale client registered against the RPi5 Headscale on
  2026-11-19 (copy of `tailscaled.state`, node `b1-ts-alice`) ran in a nested container on an internal
  network with no default route (the RPi5 address and a reserved address unroutable). It started in
  `NoState` (its old server unreachable); `tailscale up --login-server=<target URL>` with **no auth key
  and no --force-reauth** returned 0 in 4 s; it kept node id, node key, addresses and hostname, its
  node was online and **no new node** was created.
* **Data plane**: a new device joined with HA's reusable pre-auth key (proving HA's keys moved);
  10/10 pongs from the restored node to it via `DERP(lab)` and one in reverse.
* **API**: the target key answers 200 over the target URL; an unknown key 401.
* **Installer**: the converted candidate went through the real `QuadletPostgresAdapter.import_manifest`,
  an encrypted `flows._package` and `flows.run_restore` into fresh `hs-rinstall-*` volumes/unit; a
  second restore with an injected one-shot `ExecStartPre` failure raised `flows.RolledBack` and the
  pre-failure markers (user, Headplane file) came back; then a separate restart. In each of the three
  phases the real client stayed the same process and reconnected by itself (13/9/16 attempts,
  30.8/23.1/49.4 s observation windows after health), the server listed exactly HA's nodes with the
  client's node online, and cold exports matched the candidate's node identities and Noise key exactly.
* **Credentials and logs (scan limits closed)**: CA/TLS keys, target API key, target Noise/DERP keys,
  HA Noise key, the keys `headscale configtest` created in the product's throwaway volume (exported
  just before the product removes it — instrumentation only), the real client's machine/node/old-node
  and tailnet-lock keys before and after, HA's pre-auth key, the new device's keys, the restored and
  the installed volumes' own keys. Logs submitted and scanned: target, configtest output, new device,
  restored server, the installed unit's journal (the installed Quadlet keeps its log), real client.
  The controller withholds all output until every source is registered and then scans it.
* **Cleanup**: no test container/volume/network/unit/file left; the staged private inputs (backup copy,
  client state, expectations, key) removed from dev-d; dev-d inventory fingerprint unchanged.

Stated simulations and limits: the target's config, catalog and Quadlet are lab-generated (not the
WOOWTECH package's installed files); TLS uses a lab CA; clients use userspace networking with
`TS_DEBUG_ALWAYS_USE_DERP`; HA's second node (`b1-bob-nas`) has no live client; the new device is a
lab client; Headplane UI and host-reboot persistence were not exercised (the Headplane volume is
carried and compared byte-exact); the elapsed values are observation windows, not outage measurements.

## Omnigent — `tests/e2e/lab/omnigent_real_ha.py --run --arch <x86|arm> --outer-isolation-confirmed`

The engine runs on the host and reaches dev-d's owner only through `owner.sh d` (the lab bridge of
`OwnerRunner`). The public `ha_omnigent.convert` is asserted to still refuse with `SECURITY_BLOCKER`
at the start of every run; only the internal candidate entry is used.

| Attempt | Source | Exit | Seconds | Result |
| --- | --- | ---: | ---: | --- |
| `omnigent-x86-attempt1.json` | b25aa9c | 1 | 509.3 | Real source, guard, target, HA-store publish, internal candidate conversion with real discovery, installation, HA admin/member logins, target admin login, negative login, identities, users, agent, paused task, session title/labels/comment and attachment sha256 passed; stopped at `installed_member_session_missing`: the harness read the wrong key of `GET /v1/sessions` (0.21.0 answers `PaginatedList` `data[]`, `omnigent/server/schemas.py:42`). Fixed in 5b0e782. |
| `omnigent-x86-attempt2.json` | 5b0e782 | 1 | 1051.6 | Member session passed; stopped at `installed_table_counts_differ` (no diagnostics yet). d5c40bf added table-name/count diagnostics. |
| `omnigent-x86-attempt3.json` | d5c40bf | 1 | 938.6 | Right after installation every printable table equalled HA's count plus the kept account; after this run's three refresh-issuing logins `device_grants` was 0 → 3 (vendor `server/routes/accounts_auth.py:364-371`). 974fa48 makes the pre-login equality a hard check for every table and lets only `account_tokens`/`device_grants` grow after logins. |
| `omnigent-x86-attempt4.json` | 974fa48 | 0 | 1334.4 (632 s holding the lock) | **PASS** — see below. |
| `omnigent-arm-attempt1.json` | 8e78b2c | 0 | 1101.3 (534 s holding the lock) | **PASS** — the same chain on the b1 RPi5 backup (aarch64 add-on member): every table equal to HA's count plus the kept account before any login, including HA's runner host row and its device grant (`hosts` 1, `device_grants` 1) carried as data while this device's runner pi volume stayed byte-identical (the RPi5 runner's pairing is not moved); all application checks after install, restart and automatic rollback; 31 registered values, 0 scan hits; cleanup complete. |

What the passing x86 run used and proved (real unless stated):

* **Source**: the actual b1 x86 Supervisor backup (sha256 equal to the recorded fixture), copied into the
  engine's HA store and published by the product's `HaStore.publish`; `haimport._open` opened it from the
  store (real outer envelope, `backup.json`, add-on member 0.1.23 amd64 stopped, embedded PostgreSQL 16
  cluster, artifact store with the agent bundles, upload blob and `accounts-cookie-secret`).
* **Target**: a disposable Omnigent in dev-d deployed as three real Quadlet units (PostgreSQL 16, the
  omnigent-server 0.21.0 image, a runner placeholder holding the runner's pi volume), initialised by the
  real image with a freshly generated admin password (a Podman secret). The product discovered it through
  its real adapter (`read_quadlets`, `probe`), the live `/v1/info` of the running server and its live
  alembic revision; the server was then stopped before any schema capture (no DDL writer).
* **Conversion**: `haimport._run_omnigent_candidate(..., schema_ddl_quiesced=True)` (internal entry)
  produced an encrypted candidate. The public conversion still refuses (`SECURITY_BLOCKER`).
* **Installation**: `haimport._install_omnigent_candidate` (flows.run_restore with an encrypted safety
  backup). Right after it, before any login, **every** table (19, the secret-named ones compared but not
  printed) held exactly HA's count plus this device's kept admin account.
* **Application checks** after install, after a restart and after the automatic rollback: HA's admin and
  member log in with HA's passwords (the fixture's generated test credentials, read only through the b1
  harness reader, never printed) and `/auth/me` names them with the right admin flag; this device's admin
  still logs in with its own password; HA's admin refuses this device's password; HA's agent, paused task
  (name, rrule, never ran), session (title, labels `b1=import-test`, one comment), attachment (sha256 and
  size computed inside the container), the member's session, alembic `d0a1f879a01d` and the table counts
  (only `account_tokens`/`device_grants`, which this run's own logins write, may grow); HA's cookie key bytes
  are the installed ones; the runner's pi volume (its identity/pairing) is byte-for-byte this device's.
* **Rollback**: a second installation with an injected one-shot `ExecStartPre` failure raised
  `flows.RolledBack`; the pre-failure database and server-volume markers came back.
* **Secret coverage**: 31 registered values (HA passwords, target password, both cookies, the runner
  identity marker, every issued token and refresh token from 20 login sources, users' password hashes);
  event output, the three units' journals (the server keeps its log) and 78 engine job-log lines scanned:
  0 hits. Cleanup complete, private engine root removed, dev-d containers/volumes/secrets unchanged.

Stated simulations and limits: the runner is a placeholder container (no Pi agent, no model; HA's runner
rows arrive as data and stay offline — the runner pairing is not moved); the target's catalog/Quadlets are
lab-made with random names; the engine runs on the host through the lab bridge and the live `/v1/info` GET
goes through `podman exec` into the running server; the throwaway PostgreSQL containers were capped at
512 MiB (product default 2 GiB) to fit dev-d's 4 GiB cgroup.

## services-a-2 (2026-11-23 afternoon): the verifier's two gaps

Lane services-a-2, branch `test/services-a2-20261123` from R-COCKPIT `integration/ha-import-batch1-20261123`
(82ac971, which already holds services-a's work and the sandbox fixes). Runs started from a separate run worktree at
the named commit (`git status` clean outside the evidence folders), so the code that ran is exactly that commit.

### Omnigent: isolation record and clean tree in the harness itself

`omnigent_real_ha.py` now (0cc2289) refuses to start when the checkout has any change outside the evidence folders,
prints `source commit <sha>` with a `source` event, and calls `owner.sh d --verify-isolation` right after taking the
dev-d lock and again in a `finally` after the inventory check (fixed line `dev-d isolation: true none {}` plus an
`isolation` event each time). The lock is taken through `dev_d_guard.py` (blocking like `flock -w`, yields to
emqx-main's waiting file).

| Attempt | Source | Exit | Seconds | Result |
| --- | --- | ---: | ---: | --- |
| `omnigent-x86-attempt5.json` | 0cc2289 | 0 | 673.7 (672 s holding the lock, waited 0 s) | **PASS** on the integrated code: clean tree (0 changed paths), isolation before and after, same chain as attempt 4 (HA store publish, internal candidate with live discovery, public SECURITY_BLOCKER still refuses, installer, restart, injected one-shot rollback, HA admin/member logins, 31 registered values / 0 hits, inventory unchanged). |

### Headscale: the full product flow into dev-d's INSTALLED Headscale — `tests/e2e/lab/headscale_full_flow.py --run --arch <x86|arm>`

Target: dev-d's own WOOWTECH Podman Headscale package units (`headscale`, `headplane`, `headscale-entrance`,
server_url `http://localhost:28080`), not a disposable target. Every engine call is the root helper the Cockpit page
calls (`/usr/local/libexec/woowtech-cockpit-backup`, one JSON request on stdin), with this tree's engine installed by
`deploy-src.sh d --src <tree> --no-demo-catalog` (installed modules and helper SHA-256 = tree):
`inspect` (dev-d's Headscale baseline backup with the 11-19 kit, for its catalog entry) → `catalog-install` →
`key-init` → `upload-begin`/copy/`upload-finish` (HA store) → `ha-check-start` → `ha-convert-start` → `inspect` →
`restore-start` → restart → `restore-start` with an injected one-shot failure (must end `rolled-back`) →
`restore-start` of the import's safety backup → `delete` / `catalog-remove`.

Lab precondition (stated simulation, reverted at the end of every run): since 11-20 dev-d's `config.yaml` has an empty
DERP map (`urls: []`, embedded server off), so Headscale 0.29.4 crash-loops (`initial DERPMap is empty`,
`hscontrol/app.go:656`). For the run only its `derp:` block becomes the embedded region 999 (no URL, `urls: []`);
the original file is kept next to it and written back (SHA-256 equal) after the rollback, and the units go back to
the state they were found in.

| Attempt | Source | Exit | Seconds | Result |
| --- | --- | ---: | ---: | --- |
| `headscale-fullflow-x86-attempt1.json` | 1b174e4 | 1 | 25.8 | Harness: setup inspected dev-d's Headscale baseline backup before the secrets phase had read the 11-19 kit, so the helper refused (`invalid-request`, field `key`). Nothing of dev-d's Headscale touched. Fixed in b9fc697. |
| `headscale-fullflow-x86-attempt2.json` | b9fc697 | 1 | 2976.7 (2377 s holding the lock after ~10 min behind an EMQX run) | **Product flow PASS, clients FAIL (harness)**: setup, the carried catalog entry (inspect with the 11-19 kit, catalog-install), lab config (3 units active, health/metrics 200), before markers, upload (page path; the store record is the fixture, it existed: dedupe), ha-check 44 s (section = source facts, only the API-key warning), real space (floor 11.27 GB = 10 GiB running reserve + 512 MiB vs 23.7 GB free), ha-convert 42 s (30720 B, device-key encrypted, listed as manual with its HA origin), inspect (in place, settings same), restore-start 58.9 s (safety backup, health-1/health-2 ok, writers paused 34.0 s, unavailable 36.5 s), every server check after the restore and after `systemctl --user restart headscale.service`. The new devices were tailscaled containers in dev-d's loopback-only namespace: tailscaled pauses its control client without an up non-loopback interface (`control: setPaused(true)`, NeedsLogin), so the joins, node counts, DERP pings and reconnects failed. Fixed in d1bb776 (fresh namespace per client with an up veth and a relay to localhost:28080). Then **also real and passing**: a second restore-start with a one-shot `ExecStartPre` failure ended `rolled-back` (73.4 s, `無法啟動服務：headscale.service。`, the failure consumed, drop-in gone) and left HA's imported server intact (every server check again); the import's safety backup restored (49.8 s, health ok): dev-d's own markers back and its Headscale equal to the state before the import (users, nodes, API keys, pre-auth keys, DNS, Noise key); converted and safety backups deleted, the catalog entry removed again, no job object/staging/key file; leak scan 0 hits; isolation `true none {}` after. 86/95. The original config.yaml was written back (sha256 equal) but the blocking unit restart that followed hit its 360 s timeout (`lab config off: ran: FAIL`, TimeoutExpired: headplane's ExecStartPre waits 180 s for the crash-looping headscale); since 398241d that restart is `--no-block`. |
| `headscale-fullflow-arm-attempt1.json` | cb21c08 | 0 | 1703.9 (1165 s waiting behind an EMQX run, 537 s holding the lock) | **PASS 101/101** on the real b1 RPi5 backup — see below. |

What the passing ARM run used and proved (real unless stated):

* **Flow**: only the root helper commands the Cockpit page sends, in dev-d, with this tree's engine installed
  (39 modules and the helper SHA-256 equal to the tree): the HA backup `woow-b1-arm-plain.tar` (sha256 = fixture)
  went through `upload-begin` / copy / `upload-finish` into the HA store (the record already existed: the product's
  dedupe returned it after the strict outer check and a full SHA-256), `ha-check-start` (aarch64, add-on 0.1.3,
  target 0.29.4, section = source facts, only the API-key warning), `ha-convert-start` (the job's own SpaceGuard and
  Watchdog with the real floor: 10 GiB running reserve + 512 MiB margin, recorded next to the free space),
  `inspect` (in place, settings same) and `restore-start` (safety backup, health-1/health-2 ok).
* **Restored service**: dev-d's installed `headscale`/`headplane`/`headscale-entrance` units active, health and
  metrics 200, the catalog health URLs answer; users (HA's ids), both nodes (ids, users, addresses), the approved
  route of b1-bob-nas, HA's pre-auth keys, the DNS record, only this device's API key prefix (it works; HA's own
  Headplane API key from the backup is refused with 401), HA's Noise key (content SHA-256) and public key served.
* **Real client, no new key**: the REAL tailscale client state made against the RPi5's Headscale (node
  b1-ts-alice) started in its own network namespace that reaches only `localhost:28080` (NoState: old server
  unreachable); `tailscale up --login-server=http://localhost:28080` with **no auth key and no --force-reauth**
  returned 0 in 4.6 s; Running as the same node (id 2, node key, 100.64.0.2 and fd7a:115c:a1e0::2), control URL =
  this device's, online on the server, **no new node**; `b1-nas.ts.local` resolves to 100.64.0.250 through the
  client.
* **Data plane**: a new device joined with HA's reusable pre-auth key (handed over in a 0600 file, never argv);
  10/10 pongs from the real client to it via `DERP(lab)`.
* **Restart**: `systemctl --user restart headscale.service`: every server check again; both clients Running and
  online again by themselves.
* **Automatic rollback**: a second `restore-start` with a one-shot `ExecStartPre` failure ended `rolled-back`
  (`無法啟動服務：headscale.service。`), the failure was consumed, the drop-in removed; HA's imported server
  (with the new device) and both clients came back by themselves.
* **Rollback to the device's own data**: `restore-start` of the import's safety backup: dev-d's markers back and
  its Headscale equal to the state before the import (users, nodes, API keys, pre-auth keys, DNS records, Noise key).
* **Cleanup**: original `config.yaml` written back (sha256 equal) and the units left as found; converted and safety
  backups deleted, the catalog entry removed again, no job object, staging or key file, client binaries/states/logs
  removed. **Leak scan**: HA pre-auth keys, HA's Noise key and Headplane API key/cookie, the real client's private
  keys, the new device's keys, every server volume's Noise/DERP keys, dev-d's three Headscale Podman secrets and the
  kit: 0 hits in jobs, HA store sidecars, ha-imports.json, archives' sidecars, uploads, staging, pending, exports,
  the run dir, the whole device journal, the client logs and this run's private evidence.

Recorded finding (owner/product decision): with dev-d's Headscale as found (crash-looping on its empty DERP map),
the page's ha-check answered ok with 0 blockers (`found_state_check` event): the deployment probe looks at Quadlet
files, loaded and masked units only (`adapters/quadlet_postgres.py` probe), so an unhealthy target is only stopped
by the restore's health checks and the automatic rollback, not warned about before the import.

## What is still not proven (why `commercial_acceptance` stays `not-complete`)

* Omnigent ran against a **disposable lab target** (lab-made catalog/Quadlets/config, random names), not the
  WOOWTECH package's installed units, with the engine on the host through the lab owner bridge (the internal
  candidate entry cannot be reached through the helper while the public path is blocked).
* Omnigent's **public** HA import stays blocked (`SECURITY_BLOCKER`, B1-01): these runs prove the internal
  candidate path only. Lifting the guard is an owner/product decision.
* Omnigent runner: placeholder container only (Pi agent and models out of scope); HA's runners would have to
  be re-paired by their owners (product reminder text), which was not exercised.
* Headscale (services-a-2): the full product flow ran into dev-d's installed package units, but only with the
  run-time lab DERP config (dev-d has no network; the package default fetches the public DERP map); clients are
  userspace tailscaled in private network namespaces of dev-d reaching only `localhost:28080`, DERP over plain HTTP
  (`TS_DEBUG_USE_DERP_HTTP`), no client on another machine; Headplane UI and host-reboot persistence not run.
* Headscale (services-a-2 finding, owner/product decision): the page's ha-check does not warn about a target that
  is deployed but crash-looping (the deployment probe checks files, loaded and masked units only); such an import
  is stopped later by the restore's health checks and rolled back automatically.
* Headscale (services-a, earlier): lab CA and disposable targets for the installer path.
