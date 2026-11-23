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
