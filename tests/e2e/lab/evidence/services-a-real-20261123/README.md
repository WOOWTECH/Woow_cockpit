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
