# ARM54 final lane — real RPi5 HA backup restored on the independent ARM Podman target

Date 2026-11-23 (Asia/Taipei). Branch `test/arm54-final-20261123` (from `feat/ha-import-batch1`
`b2f63ce`), worktree `/tmp/ha-arm54-final-20261123`. Sole owner of 192.168.2.54, read-only user of
192.168.2.34. `commercial_acceptance` stays **not-complete** (see "Not covered").

## Result

| Item | Result | Evidence |
| --- | --- | --- |
| SSH exit 255 cause | **Found.** Without `ARMHA_PW` in the command environment the askpass helper prints an empty password: ssh exit 255, fixed predicate `authentication_denied`. With it: exit 0 (`aarch64`). | `ssh-access-cause.*` |
| Source provenance (.34, read-only) | **Verified** for all four B1 ARM backups: `ha backups list/info` slug, date, add-on list, `/backup/<name>.tar` bytes and SHA-256 and `backup.json` SHA-256 equal the local fixtures. Re-attested after the runs and again after iteration 2: identical output (same stdout SHA-256 `9ec6d3b0…`). | `source-provenance-34.*`, `source-provenance-34-post.*`, `source-provenance-34-post2.*` |
| Headscale cross-physical restore (RPi5 → .54) | **Passed** with the real backup `45670371` (`woow-b1-arm-plain.tar`, SHA-256 `1e6a4665…92c5d4`), 38/38 checks: run of record **attempt 6** on `f67e718` (product with the hasqlite fixes below). Attempts 3 and 4 (38/38 too) ran the older product, whose SQLite sandbox child kept the host network on this Python. | `headscale-real-attempt6.*` (also 3, 4) |
| SQLite sandbox on Python 3.11 (product) | **Found and fixed on this branch**: Python < 3.12 has no `os.unshare`. On .54 (3.11.2, root) the `b2f63ce` child kept the host network (127.0.0.1 listener CONNECTED, `eth0`/`tailscale0` visible); `a9d8643` (fail-closed) refuses every read (Headscale import failed, attempt 5); `5595e3c` makes the same `unshare(CLONE_NEWNET)` call through libc and stays fail-closed: isolated (ENETUNREACH, only `lo` + unconfigured fallback tunnels), as `nobody`. | `hasqlite-sandbox-probe-py311.*`, `headscale-real-attempt5.*` |
| VPN registration failure on .54 | **Root cause reproduced with the real client and fixed** (no test-only knob). | same, `root_cause_reproduced_no_interface`, `seconds_to_running_after_interface` |
| Node identity/IP preserved, client reconnects | **Passed**: the real B1 client `b1-ts-alice` keeps node ID 2, `100.64.0.2` / `fd7a:115c:a1e0::2` and its node key after the restore, after a server restart, after a client restart, and after a re-point to the target URL; no login URL, no NeedsLogin. | same |
| .54 originals untouched, cleanup | **Identical inventory** after every completed cycle (iteration 1 cycles 2-4; iteration 2 Omnigent cycle 1, encrypted cycle 2, probe cycle 3): each equals its own baseline on 24 strict keys and the first workspace baseline (`baseline-before`, started 08:49:26 Asia/Taipei; 07:50-07:59 were read-only surveys) on 22 keys (nft keys not comparable, see below). Private store and workspace removed, no mount names the workspace. | `cleanup*.json`, `inventory-*.json`, `baseline-before*.json` |
| Omnigent cross-physical restore (RPi5 → .54) | **Passed** 72/72 with the real backup `45670371` (attempt 3 on `54c4dd9`, run of record) and 72/72 with the **encrypted** real backup `a2dc9bfd` in a fresh cycle (attempt 4 on `71eac64`): unmodified product check (only blocker: the public `SECURITY_BLOCKER`), the internal candidate after live discovery from the running arm64 Omnigent 0.21.0 target, restore, HA's admin and member log in with HA's passwords, data checks, full restart, rollback. **Made while the public import was held (SECURITY_BLOCKER, internal candidate); the public path: row "Integrated engine" below.** | `omnigent-real-attempt3.*`, `omnigent-real-attempt4-enc.*` |
| Encrypted RPi5 backups on .54 | **Passed** for Omnigent (attempt 4, 72/72) and Headscale (attempt 7, 38/38, same VPN continuity as attempt 6) with `a2dc9bfd`: the product's SecureTar v3 reader on .54 with PyNaCl 1.5.0 + cffi 1.17.1 from pinned PyPI aarch64 wheels inside the 0700 workspace (no system package). | `omnigent-real-attempt4-enc.*`, `headscale-real-attempt7-enc.*`, `upload-enc-cycle2.exit.json` |
| n8n SQLite child on Python 3.11 (product) | **Found and fixed on this branch** (`92d7c5b`): same gap as hasqlite; on .54 the `b2f63ce` child reached the parent's loopback listener (CONNECTED), the fixed child is isolated (ENETUNREACH) as `nobody`; a child that cannot leave the network now exits NO_NETNS and the check stops. | `n8n-sandbox-probe-py311.*` |
| Incompressible >8GiB outer archive on .54 (arm54-2 item A) | **Passed** (8193 MiB, real engine writer/reader/verify on .54's eMMC; host had no space): archive 8,593,295,360 B, ciphertext member above the ustar limit with an outer PAX size record, full verify, late-tail refusal, bit-exact revert; owner floor 4 GiB kept (min free 9.90 GB); inventory identical. See "arm54-2 item A". | `large-outer-8193mib-54-attempt1.*` |
| n8n ARM cross-physical restore (2026-11-19 RPi5 backup -> .54; arm54-2 item B) | **Passed** 38/38 (attempt 6): product check + convert, restore, HA owner login with HA's password, credential decrypted with HA's moved key, community node, restart, rollback; found and fixed a Podman 6.1.1 restore bug (`868894f` + follow-up). Rootful private store. | `n8n-real-attempt6.*`, `arm-provenance-20261119.*`, `n8n-volume-probe*.json` |
| Odoo ARM on .54 (owner decision 3A: SUBSTITUTE images, not the product service) | **Passed with SUBSTITUTE images, not the product service** (the product's Odoo images have no arm64 build): rootful 38/38 (`odoo-real-attempt1`) and test mode 41/41 (`odoo-real-attempt3-testmode`); production OwnerRunner on the integrated engine 95/95 (`owner-odoo-attempt2`): the catalog draft installed unchanged, first-import rollback from the device's own state, strict comparison inside the restore 204/205 tables identical (only `public.ir_config_parameter`: web.base.url, web.base.url.freeze, woow_paas_platform.upgrade_done), 17/17 filestore files, 26 modules, restart, automatic and manual rollback. See "Item B Odoo" and "Cycle owner-cycle4". | `odoo-real-*`, `owner-odoo-*` |
| EMQX on .54 (arm54-2 item D) | **Passed.** Rootful private store: real RPi5 cold backup `b6cbc980` 79/79 (`emqx-real-arm-attempt6`), real x86 cold backup `5fb6f348` 79/79 (`emqx-real-x86-attempt1`) and, with the merged reviewed tip, 81/81 (`emqx-real-x86-attempt2`); production OwnerRunner: ARM 164/164 (`owner-emqx-arm-attempt1`) and x86 164/164 (`owner-emqx-x86-attempt1`), and ARM again on the integrated engine with the drafted entry unchanged and first-import rounds 186/186 (`owner-emqx-arm-attempt2`). Attempts 1-5 found the Podman 6.1.1 top-entry defect (fixed `c8df1f2`) and two product findings (fixed by the EMQX lane). | `emqx-real-*`, `owner-emqx-*` |
| Integrated engine on .54 through the production OwnerRunner (iterations 6-7; branch `test/arm54-integrated-20261124`) | **Passed**: Headscale 55/55 (`owner-headscale-attempt10`), 66/66 (`owner-headscale-attempt11`)\*; Omnigent through the **public product path** (first time on ARM) plain, encrypted, plain again 137/137 (`owner-omnigent-public-attempt2`), 137/137 (`owner-omnigent-public-attempt3-enc`), 157/157 (`owner-omnigent-public-attempt4`)\*; EMQX ARM 186/186 (`owner-emqx-arm-attempt2`)\*; Odoo SUBSTITUTE images 95/95 (`owner-odoo-attempt2`)\*; n8n plain 147/147 (`owner-n8n-attempt5`)\*; with the integration's export check (`e92e8ae`): EMQX ARM 186/186 (`owner-emqx-arm-attempt3`)\*. Runs marked \* start with a first import that fails once and must give the device's own state back (harness `fd1393d`). Cycle audits: c10 28/28 keys identical, owner-cycle3 28/28 keys identical, owner-cycle4 28/28 keys identical, owner-cycle5 28/28 keys identical, owner-cycle6 28/28 keys identical. | `owner-*` (iterations 6-7) |
| Drafted Headscale entry importable (product fix `0316d7e`) | **Found and fixed**: catalog-suggest's Headscale draft names the read-only configuration folder as a host folder and `ha_headscale.Target` refused every entry with one; the folder is now carried live (its config.yaml must be unchanged). Real proof 66/66 (`owner-headscale-attempt11`) with the drafted entry unchanged. | `owner-headscale-attempt11.*` |

## What ran (all on .54, rootful Podman with a private store)

Runner scope, stated plainly: a `RootfulRunner` over a private `--root/--runroot` vfs store under a
0700 `/var/tmp/woow-arm54-final-20261123-*` workspace. **Not** the production `OwnerRunner`/rootless
path (see blockers). The product code is unmodified `backup-engine` from this branch.

1. Native images (`native-images*.json`): the unmodified Woow Headscale package recipe (commit
   `0afdfa4`, Containerfile SHA-256 `02f850bf…`) built on ARM as `localhost/woow-headscale:0.29.4-r1`
   (the tag `scripts/install.sh` builds; image IDs `c4a6d981…` and `a0dc0101…` — timestamps differ,
   binary is the pinned upstream), product version gate passed, `headscale version v0.29.4`.
   Client: `docker.io/tailscale/tailscale@sha256:8934bed5…` (arm64 manifest of the same 1.104.7
   index the real B1 client ran). Image fetches only here.
2. Target deployment: the package's own quadlets and config template (copied with checksums in
   `package-0afdfa4/`), rendered for .54 (`server_url http://192.168.2.54:28080`, policy mode
   database, package prefixes). Two isolation deviations: no published ports (pod with network
   none), and an embedded DERP map instead of the public URL (Headscale 0.29.4 refuses to start
   without a DERP map, `hscontrol/app.go:646-659`). The target got its own user `target-only`, an
   API key and a Headplane marker before the import.
3. Product check and convert: `ha_headscale.check` (no blockers) and `ha_headscale.convert` on the
   real archive through the product's strict HA reader (`habackup`) and the product's own
   `haimport.Work.addon_member/addon_info/open`; real live export of the running target, real
   `configtest` throwaway container, conversion temp objects removed.
4. Restore the way the product restore replaces volumes (safety export first), start, verify.

Checks of the passing runs (selection): source and converted DB `integrity_check` ok; users
(`default`, `alice`, `bob`), nodes (IDs 1/2, IPv4/IPv6, hostnames, user IDs, machine/node key
hashes) and pre-auth keys equal to the HA source before start and after both restarts; Noise
identity is HA's key; HA's DNS record file is the restored one and the client resolves
`b1-nas.ts.local → 100.64.0.250` through the restored server; API keys are the target's, not HA's
(DB comparison); the target's API key still answers HTTP 200 with HA's users; HA's Headplane API key
is never read (the product's `habackup.NEVER_READ` refuses to hand it out — asserted, not bypassed);
target Headplane data kept; rollback to the safety export brings back `target-only` and zero nodes.

## Omnigent on .54 (iteration 2)

Same runner scope (rootful private store), but the workspace uses the **overlay** driver with
`overlay.skip_mount_home=true` (chosen at `init`; vfs copies every layer in full and the 756 MB arm64
server image would not fit above the 12 GiB reserve). Only running containers hold mounts; every cleanup
proved no mount names the workspace.

1. Images (`omni-images-cycle*.json`): the references the Woow Omnigent package pins (commit `6e4f0c0`,
   quadlets copied with checksums in `omnigent-package-6e4f0c0/`): `postgres:16.15-alpine3.24@sha256:aa6cb33c…`
   (arm64 manifest `9f5be679…`, PostgreSQL 16.15) and `omnigent-server:v0.21.0@sha256:9bba2964…` (arm64
   manifest `38ed1996…`, `omnigent` 0.21.0, aarch64).
2. Target: the package quadlets rendered for .54 (admin `a54-target-admin`, runner user `a54-runner`, private
   pi volume) and translated key by key to `podman run` (names, images, volumes, env, secrets, hardening).
   Stated deviations, recorded per container in `quadlet_keys_not_translated`: one pod with network none
   instead of the bridge network, no published port, no health timers (readiness polled), memory caps, and a
   runner placeholder (the package's PostgreSQL image sleeping with `--image-volume ignore`, holding the
   runner's pi volume; the locally built runner image and the Pi agent are out of scope). Passwords are
   generated on .54 into podman secrets of the private store. The run joins the pod's network namespace
   (libc `setns`; Python 3.11 has no `os.setns`): only `lo` is up/addressed (`sit0`/`ip6tnl0` are the
   kernel's unconfigured fallback devices), so the product's own loopback GET of `/v1/info` and every login
   reach the real server at `127.0.0.1:8000`.
3. Before the import: `/v1/info` 0.21.0 and `needs_setup` false, own admin logs in, HA's admin is unknown
   (401), alembic `d0a1f879a01d` equals HA's, the target's cookie key differs from HA's.
4. Public guard (asserted, never bypassed): `ha_omnigent.convert` refuses with `SECURITY_BLOCKER`; the
   product check's only blocker is `SECURITY_BLOCKER` (no version, alembic or PostgreSQL blocker, 0
   warnings); the internal entry refuses without DDL quiescence.
5. Internal candidate exactly as `haimport._run_omnigent_candidate` wraps it: `require_registered_secrets`
   then `_convert_candidate(..., schema_ddl_quiesced=True)`, with the product's own `QuadletPostgresAdapter`
   over the private-store runner. Live discovery came from the running server (version 0.21.0, alembic);
   the server was then stopped before any schema capture (the caller's quiescence contract). Result: 2
   people, 2 conversations, 1 host, 1 scheduled task (paused in HA, none active), kept account
   `a54-target-admin`, no conflicts. Converted volumes checked before start: HA's cookie key (0600), the
   target's server settings file kept, the pi volume equal to the target's.
6. Restore (safety exports first), verify; full stack restart (containers recreated, like a quadlet unit
   restart), verify again; rollback to the safety exports.

Checks per round (`installed_*`, `restarted_*`): `/v1/info`; HA admin `woow` and member `b1member` log in
with HA's passwords; the kept target admin logs in with its own; HA's admin with the target admin's
password is refused; `/auth/me` identities; the user list holds HA's users and the kept admin; HA's agent,
paused scheduled task (name, rrule, never run), admin session title, label `b1=import-test`, 1 comment,
attachment SHA-256/bytes, the member's session; alembic; every table count equals HA's (+1 kept admin;
`account_tokens` at least HA's); HA's cookie key installed; pi volume and target settings unchanged.
Rollback: the target admin logs in, HA's admin is refused, no HA user is listed, HA's agent is 404, the
target's own cookie key and 2 user rows are back.

## VPN root cause and fix

Tailscale 1.104.7 pauses its control client while `AnyInterfaceUp()` is false
(`ipn/ipnlocal/local.go:1157`; `net/netmon/state.go:598-617`, revision `cbc74fe`): only interfaces
that are up and carry a usable (non-loopback, non-link-local) address count. A `--network none`
namespace has only `lo` (127.0.0.1, ::1), so registration never starts. This is the test topology,
not a product defect: every production Podman network gives the container a normal interface.

Proof with the real client state (attempts 2–4): the namespace had no usable address, the control
endpoint was proven reachable over the same path (`/health` 200 via `local` routes for
192.168.2.34/32 and 192.168.2.54/32 on `lo` and a relay to the server), and the client stayed
`NoState` for 40 s with a `paused` log line; then exactly one change — an unrouted TUN interface
`eth0` 10.254.54.2/24 (no carrier, no default route) — and it reached `Running` in 3.2–4.5 s.
No `TS_ASSUME_NETWORK_UP_FOR_TEST`. Attempt 1 is kept: its baseline was invalid because a /32 alias
on `lo` already counts as a usable address (it reached `Running` without the TUN interface).

Re-point: `tailscale up --login-server=<new>` on a Running client exits 1 (cli requires
`--force-reauth`, i.e. a new login); after `tailscale down` the same command exits 0 and the client
keeps node 2, its IPs and node key with the new control URL. `--force-reauth` was never used.

## Attempts (kept, never rewritten)

| Output | Commit | Exit | Note |
| --- | --- | --- | --- |
| `headscale-real-attempt1` | `3423c2d` | 1 | partial: invalid root-cause baseline (lo alias), HA API-key probe hit NEVER_READ |
| `headscale-real-attempt2` | `0ab3651` | 1 | partial: re-point refused without `tailscale down` |
| `headscale-real-attempt3` | `b290054` | 0 | passed 38/38 |
| `headscale-real-attempt4` | `e4251de` | 0 | passed 38/38 (fresh cycle: new baseline, upload, build) |
| cycle 3 `run`s | `22cda72` | — | refused by the clean-tree guard (upload had rewritten committed evidence); kept: `upload-plain-cycle3.*`, two audits taken while the workspace existed (exit 1, `var_tmp_woow`) |
| `headscale-real-attempt5` | `22cda72` | 1 | failed at product check, `job-failed`: a9d8643's child exits NO_NETNS on Python 3.11 |
| `hasqlite-sandbox-probe-py311` | `f67e718` | 0 | before-fix child not isolated, fail-closed child refuses, libc fallback isolated |
| `headscale-real-attempt6` | `f67e718` | 0 | passed 38/38 on the fixed product (run of record) |
| `inventory-after-cleanup-cycle3b`, `-cycle4`, `inventory-final-vs-original-cycle4` | `5595e3c`/`f67e718` | 0 | identical |
| `inventory-after-cleanup` | `95ed05a` | 1 | only `nft_ruleset_sha256` differed: `nft list ruleset` contains traffic counters; no podman/netavark table exists. Later inventories hash `nft -s list ruleset` |
| `inventory-after-cleanup-cycle2` | `0e1fd1b` | 0 | identical, 24 strict keys |
| `inventory-final-vs-original` | `0e1fd1b` | 0 | identical to the first workspace baseline (`baseline-before`, 08:49:26), 22 keys |
| `omnigent-real-attempt1` | `18be502` | 1 | harness check too strict: a new namespace also holds `sit0`/`ip6tnl0` (down, no address) |
| `omnigent-real-attempt2` | `b27f1e6` | 1 | 18 target checks passed; product check needed `adapter.image_inspect` (harness stub) → now the product's adapter class; one anonymous volume left by the placeholder → `--image-volume ignore`, `rm --volumes`, removed before attempt 3 |
| `omnigent-real-attempt3` | `54c4dd9` | 0 | **passed 72/72**, plain `45670371`, 558 s (run of record) |
| `cleanup-omni-cycle1`, `inventory-after-cleanup-omni-cycle1`, `inventory-final-vs-original-omni-cycle1` | `fc0d0f9`/`05c21f3` | 0 | identical (24 / 22 keys) |
| `omnigent-real-attempt4-enc` | `71eac64` | 0 | **passed 72/72**, encrypted `a2dc9bfd`, fresh cycle 2, 554 s |
| `headscale-real-attempt7-enc` | `5e06669` | 0 | **passed 38/38**, encrypted `a2dc9bfd`, cycle 2, 166 s |
| `inventory-after-cleanup-enc-cycle2`, `inventory-final-vs-original-enc-cycle2` | `142ffee` | 1 | taken while the workspace still existed (the cleanup run was first refused by the clean-tree guard): only `var_tmp_woow` |
| `cleanup-enc-cycle2`, `inventory-*-enc-cycle2b` | `92d7c5b` | 0 | identical (24 / 22 keys) |
| `n8n-sandbox-probe-py311` | `72a5a52` | 0 | `b2f63ce` n8n child CONNECTED to the host loopback; fixed child isolated |
| `cleanup-n8nprobe-cycle3`, `inventory-*-n8nprobe-cycle3` | `0389cd2` | 0 | identical (24 / 22 keys) |
| `source-provenance-34-post2` | `0389cd2` | 0 | .34 re-attested after all iteration-2 runs: same stdout SHA-256 as `source-provenance-34-post` (4 backups, all verified) |

Every `.exit.json` has exit code, elapsed seconds, stdout SHA-256 and source commit; every
`.source.txt` is the exact code that ran. Inventory keys: original containers with `StartedAt` and
PID (Home Assistant, Matter, verification gateway), images, volumes, networks, pods,
`/etc/containers/networks`, account files, linger, running services, tailscaled/ssh start times,
`pi-web` start time, links, addresses, kernel modules, package list, `/run/netns`, cgroups,
`/var/tmp/woow*`, mounts (listening sockets are reported only).

## arm54-2 item A — incompressible >8GiB outer archive on .54 (2026-11-23 11:15-12:15)

The large-archive lane's probe (`tests/backup/bounded_incompressible_outer.py`, merged from
`test/large-archive-final-20261123` e415fc4 as `6bda18d`) could not run on the production host (disk). It ran on
.54 with the uploaded, unmodified backup engine. Changes for .54 (`e3f0667`): `--reserve-gib` (default 12 = host
floor, unchanged; .54 = 4, the owner's floor) and `--deadline` (default 3600 unchanged; .54 run 7200).

**Tools.** .54 has no `age`/`age-keygen`/`zstd`. Debian bookworm arm64 `age 1.1.1-1+b3` and `zstd 1.5.4+dfsg2-5`:
`large-tools-provenance` checks the chain — `InRelease` signed (gpgv: Debian archive automatic 12 and 13 keys and the
bookworm stable release key, read from .54's own `/usr/share/keyrings`) -> `main/binary-arm64/Packages.xz` SHA-256
listed in it -> both `.deb` SHA-256 and sizes equal their Packages entries and the pinned values. They were unpacked
into the 0700 workspace (`dpkg-deb --fsys-tarfile`; the dpkg database is untouched, nothing installed) and the probe
ran in a private mount namespace (`unshare --mount --propagation private`) with the workspace tool directory
bind-mounted over `/usr/local/sbin`, so the engine's unmodified fixed-PATH lookup found them
(`dependency_paths` = `/usr/local/sbin/{age,age-keygen,zstd}`); no mount line of the host namespace named the
workspace afterwards and `/usr/local/sbin` listed the same files before and after.

**Run of record** `large-outer-8193mib-54-attempt1` (source `a212d1b`, exit 0, 1144 s; wrapper 18/18 checks):

| What | Value |
| --- | --- |
| Payload (streamed) | 8,590,983,168 B (8193 MiB) deterministic SHAKE256 keystream, 1 MiB per index, sha256 `3ec0b9e8…74598`; a sliding-window source wrote it 64 MiB ahead of the engine reader and hole-punched 16 MiB behind (max 92,278,784 B allocated); the engine's own sha256 of every byte it read equalled the precomputed keystream hash |
| Archive (real `archive.write_archive`, age X25519 + zstd) | 8,593,295,360 B (> 8 GiB), sha256 `04a3f4cb6373a1810ba8f55a6280c737a04a2e8d3638fb7605df2e2279560403`, allocated 8,593,305,600 B (not sparse), ratio 1.000267; model 8,593,308,283 B, bound 8,610,281,781 B |
| Outer member header | ciphertext member 8,593,278,426 B > ustar limit 8,589,934,591 -> PAX `size` record 8593278426, ustar size field 0 |
| Inner header (decrypted) | PAX size 8590983168 of the payload member |
| Stream hash | `archive.describe_fd(check_members=True, hasher)` read the whole file: sha256 = writer's, member sha256 = backup.json (85.2 s) |
| Verify | `verify_archive` decrypted/decompressed/parsed/hashed 8,590,983,168 B (148.7 s) |
| Keys | missing -> `key-required`, wrong -> `wrong-key` |
| Late tail | last ciphertext byte flipped in place (offset 8,593,278,425, backup.json member sha256 rewritten so the outer check passes) -> `corrupt-archive` after 8,587,047,936 B of progress (minimum for "late" 8,523,874,304); both edits reverted, file sha256 equal to the original again |
| Timings | keystream hash 97.9 s, write 450.2 s, stream hash 85.2 s, verify 148.7 s, late tail 290.0 s, probe total 1138 s |
| Resources | max RSS 53,428 KiB; probe CPU affinity 2 of 4; `nice -n 19` + `ionice -c3` (the eMMC uses mq-deadline, which does not honour I/O classes: recorded as `ionice_class_honoured_by_scheduler: false`) |
| Owner floor | free before 18,513,350,656 B; minimum 9,902,174,208 B (probe guard, 0.25 s samples) / 9,903,214,592 B (2 s sampler, 569 samples) = floor + 5,608,247,296 B; the guard would have aborted and deleted at 4 GiB + 256 MiB |
| Originals | Home Assistant frontend GET `/manifest.json` 72/72 ok, max 17 ms; default-store containers and running services identical before/after; MemAvailable min 1.81 GB; load max 5.14 |
| Cleanup | probe scratch and keys removed by the probe; `large-cleanup` removed the workspace; `large-inventory-after` identical to `large-baseline-before` (24 strict keys, informational `listening` equal too); `large-inventory-after-vs-first` identical to the first workspace baseline (22 keys; nft keys not comparable, as before) |

Smokes: `large-outer-smoke-128mib-54` and `-3` passed; `-2` failed at `tools` with FileExistsError (the first smoke
had unpacked them; fixed in `9208892`), kept. Scope: storage/stream acceptance of the engine reader on an ARM test
machine; no service restore is part of this item.

## arm54-2 item B — Odoo/n8n ARM cross-physical restore on .54 (2026-11-23 12:20-)

**Provenance (owner decision, 「Odoo/n8n 用 A」).** The 2026-11-19 RPi5 backups are no longer on .34.
`arm-provenance-20261119` (local, read-only) shows each fixture equals its 2026-11-19 records: dev-c's catalog
listing (captured 2026-11-21, `~/.woowbk-lab/evidence/odoo-capture-20261121/list.json`) holds conversions made on
2026-11-19 whose `from_ha.ha_backup_id` is `ha-` + the archive's SHA-256[:20] with HA's backup name and date; slug,
protected flag and add-ons come from `backup.json` (odoo18ce 0.4.13, woow-n8n 2.43.6).

| Fixture | slug | SHA-256 | 2026-11-19 records |
| --- | --- | --- | --- |
| woow-arm-plain.tar | 8e51e2ed | `546aecf3…73be44` | 20261119T012652Z-e71ab7cb |
| woow-arm-enc.tar | 4f5c7337 | `a5fb6268…f420e5` | 20261119T012317Z-e768af2e, 20261119T015323Z-0beea303, 20261119T033017Z-ede629d2 |
| woow-arm-enc-uncompressed.tar | ba72ee84 | `77ea8165…ba3033` | 20261119T012935Z-6902949d |

**n8n** (`arm54_final_n8n.py`; rootful private store = not OwnerRunner; restore = the product adapter's own data
methods in the product's order). Target = Woow n8n package 2ac1ae2 rendered like `app_render` in queue mode
(n8n + n8n-postgres + n8n-valkey started; worker, task runners and webhook processor not started), arm64 images by
index digest (`n8n-build-2`, `n8n-build-c2`: n8n 2.43.6, postgres 16.15-alpine = the product's PG16_PINNED, valkey
8.1.11-alpine), one pod with network none, no published port, and the whole run in its own network namespace (the
product's convert creates an internal Podman network; .54's own namespace never saw a bridge, route or nft rule:
watcher during attempt 3, cycle audits).

| Attempt | Source | Result | What it showed |
| --- | --- | --- | --- |
| `n8n-build`, `-2`, `-c2`, `-c3` | dc653c8 / 638876d / later | build 1 failed at the pod `--add-host` check (kept); the others passed | arm64 images by index digest, tags for the package's tag-only refs; `--add-host` does not reach `/etc/hosts` in a network-none pod -> the main container gets `DB_POSTGRESDB_HOST`/`QUEUE_BULL_REDIS_HOST=127.0.0.1` (stated deviation) |
| `n8n-real-attempt1` | f35e15c | exit 1 (harness) | product check passed (no blocker; 2.43.6 = 2.43.6; owner `ha-probe@probe.invalid`; 3 workflows / 1 active / 1 credential / 2 executions; n8n-nodes-globals 1.1.0); the harness compared packages as bare names |
| `n8n-real-attempt2` | 4e7a2a8 | stopped on purpose (SIGINT, cleanup ran) | before the product's convert could create its internal Podman network in .54's own namespace; from attempt 3 the run unshares its own network namespace |
| `n8n-real-attempt3` | f0f0578 | exit 1 | check + **convert passed** (convert's own row-count comparison; PG16 dump 556,201 B); host namespace stayed clean (watcher); restored n8n exited before ready (undiagnosed) |
| `n8n-real-attempt4` | 02be2e4 | exit 1 | diagnosis: `EACCES: permission denied, open '/home/node/.n8n/crash.journal'` -> `n8n-volume-probe` -> product fix `868894f` |
| `n8n-real-attempt5` | 8b8bba9 (engine 868894f) | exit 1 | 37/37 through restore + full restart; the harness rollback (raw import of `podman volume export` copies) hit the same EACCES -> `n8n-volume-probe-2` (export writes no top-directory entry) -> follow-up fix |
| **`n8n-real-attempt6`** (run of record) | ef4462e (engine with both fixes) | **exit 0, 38/38, 560 s** | see below |

Run of record: HA owner `ha-probe@probe.invalid` logs in with HA's password (target owner refused, 401);
3 workflows / 1 active including the one HA marked "needs fixing"; credential `HA probe header` listed and decrypted by
n8n's own CLI to HA's value; rows users 1 / credentials 1 / executions 2 / project 1 / workflows 3 (= convert counts);
community package `n8n-nodes-globals 1.1.0` in the database and its node type answering `/rest/node-types`;
`n8n_n8n_data/config` holds HA's key (0600, uid 1000); full stop/start: same checks pass; rollback through the
product's `_recreate_volume` of the cold safety copies: the pre-import target is back (its owner logs in, HA's
does not, rows and key equal). Cleanup: store empty but images, `veth` loaded by the throwaway network and unloaded;
`n8n-inventory-after-cycle3` identical to its baseline (24 keys) and `n8n-inventory-after-vs-first` identical to the
first workspace baseline (22 keys); cycles 1 and 2 also identical (`n8n-inventory-after-cycle1`, `-cycle2`).
Scope: rootful private store (not OwnerRunner/systemd user units), harness-driven unit order, only the main n8n
process (no worker/runners/webhook), plain backup only (the encrypted ARM fixture was not run on .54).

**Product finding and fix `868894f` (Podman 6.1.1).** Attempt 4's diagnosis: the restored n8n stopped with
`EACCES: permission denied, open '/home/node/.n8n/crash.journal'`. `n8n-volume-probe` showed Podman 6.1.1 on .54
ignores a volume tar's `.` entry on `podman volume import` and no longer chowns an imported volume to the image's
user at the first mount (a fresh volume is chowned). The product writes that entry (ha_n8n: the live root's owner and
mode), so `_recreate_volume` now applies it after the import
(`podman unshare chown --no-dereference` + `chmod` on the mountpoint, values validated like the stream; nothing is
weakened). This affects every restored volume whose top directory belongs to a non-root container user on Podman 6.x;
dev-c's real n8n restores passed, so Podman there behaves differently (its version was not checked here). Unit tests: `test_volume_root` 4 OK + 680 existing backup tests OK.

**Odoo: not run (blocked) — superseded on 2026-11-23 22:20 by owner decision 3A (substitute images), see iteration 3.** The product's Odoo target images have no arm64 build: the tenant image
`localhost/woow-odoo-tenant-ha:20261101.1152-51856b0` is a local amd64 build (Gitea paas-odoo-ci 51856b0, not on
GitHub) and `paas-postgres:17.11-20260928.1549` comes from the private jcr registry. Running Odoo on .54 needs the
owner to provide arm64 builds of both (or to accept substitutes: official `odoo:18.0` arm64 + `pgvector:pg17` arm64,
which would not be the product service and whose module versions may differ from HA's add-on).

## arm54-2 item C — production OwnerRunner rootless flow on .54 (2026-11-23 13:40-)

Owner decision 2026-11-23 (「uidmap 同意」): install `uidmap` on .54, create ONE lingering test account for the
OwnerRunner rootless flow, purge `uidmap` and delete the account afterwards, prove .54's inventory identical.

**What is real here** (unlike every earlier .54 run, which used a rootful private store): the engine's own CLI
commands as root (`cli.main` with `Paths(base=<workspace>/engine)`, the product is not installed on .54), each job
executed by `run-job <id>` in its own process with the production dependencies (`flows.default_deps` →
`default_adapter_factory` → `OwnerRunner('woowbk54t')` = runuser + rootless Podman 6.1.1 + `systemctl --user`
units from the package quadlets, health checks, digests, safety backup, the product's encrypted archive).

Cycle `owner-cycle1` (workspace `/var/tmp/woow-arm54-final-20261123-bb3d979o`, baseline
`baseline-before-owner-cycle1`): init, upload (`--owner-debs`), build, owner setup (attempt 4 passed, 21 checks:
uidmap 1:4.13+dfsg1-1+deb12u2 from the verified deb, account `woowbk54t` with subordinate ids, linger, user
manager with `PrivateNetwork=yes` (drop-in for this uid only), rootless storage in his home, runc 1.5.1 + systemd
cgroups, Headscale image loaded, package 0afdfa4 quadlets started under his user systemd).

The iteration that started item C was killed at 13:54 (session restart). The next iteration audited .54
read-only first (`owner-cycle1-killed-state-audit`, `owner-cycle1-killed-state-survey`: only the cycle's own
additions; the owner's target Headscale running in his private netns) and resumed the cycle.

### Headscale — PASSED 55/55 (run of record `owner-headscale-attempt9`, 5140be3, 185.7 s)

Real RPi5 backup 45670371 (sha256 `1e6a4665…`, attested on the RPi5) → key-init → catalog-suggest (the owner's
draft) + catalog-install → upload-begin/-finish → ha-check (9.6 s, "can import", no blocker) → ha-convert
(18.6 s; HA's API key replaced by the target's; configtest with the target image; encrypted Cockpit backup) →
restore (43.2 s; changed, safety backup, health 2/2 ok, ~31 s unavailable, unit active under the owner's systemd)
→ integrity equal to HA (users, nodes, pre-auth keys, noise key, DNS records; API keys = target's; target headplane
data kept) → the real B1 client `b1-ts-alice` keeps node 2 / 100.64.0.2 / fd7a:115c:a1e0::2 / its key on the
original URL, after the re-point to the target URL (ControlURL checked), after `systemctl --user restart
headscale.service` and after a client restart → rollback = restore-start of the restore's own safety backup
(45.5 s, digest verification match=true for both volumes) → target state and target API key back → no throwaway
container, no staging left.

Attempts (kept): 1-3 (killed iteration: engine setup, a reused file name, no `age-keygen` on .54), 4 (draft shape),
5 (product blocker "應用設定和 Quadlet 檔不一致": the draft's read-only config dir in data_dirs), 6 (packaging: no
`localhost/woow-headplane:0.7.1-woow2` image), 7 (re-point without `--accept-dns=false` left the client Stopped),
8 (one look at the server right after its restart), 9 passed. Between 7/8/9 the target was put back through the
product (`owner-reset-after-headscale-attempt7`, `-8`: restore-start of the failed attempt's safety backup).

### Omnigent — PASSED 90/90 (run of record `owner-omnigent-attempt2`, 88d1ca4 = 98410bd + harness, 693.2 s)

Target: the owner's Omnigent 0.21.0 (arm64, images pulled as the owner by index digest: `owner-images-omnigent`)
from the package 6e4f0c0 quadlets under his user systemd (port 127.0.0.1:28000 in his private netns; runner
placeholder). Engine: catalog-suggest cold variant installed unchanged (3 units, 3 volumes, 4 secrets, loopback
health, digests db-main + 2 volumes); PUBLIC ha-check (22.2 s): exactly one blocker = SECURITY_BLOCKER; PUBLIC
convert job failed with SECURITY_BLOCKER (2.5 s, target untouched). INTERNAL candidate: a job from the same public
request run by `jobs.run_job` with the production deps and handler `haimport._run_omnigent_candidate(...,
schema_ddl_quiesced=True)` (live discovery from the running server, then omnigent-server stopped before any capture)
74.1 s → encrypted Cockpit backup listed with its HA origin → PUBLIC restore-start (142.2 s; changed, safety backup,
health ok, ~123 s unavailable) → HA admin `woow` and member `b1member` log in with HA's passwords, the kept target
admin logs in, the HA admin refuses the target's password, identities, users, agent, paused scheduled task, session
title/label/comments, attachment sha256, member session, alembic = HA, table counts = HA + kept admin, HA cookie,
target pi volume and server settings kept, 3 units active; the same after a full stop/start; rollback = restore-start
of the safety backup (149.8 s, digests match=true for db-main and both volumes) → pre-import target back (target
admin only, HA admin refused, agent 404, target cookie, user rows); no throwaway container, no staging left.
Attempt 1 (kept) stopped at the product's new PostgreSQL cluster (podman exit 126, see 98410bd below);
`owner-secret-probe-1`/`-2` record the bisection and the fixed product call through OwnerRunner (10/10).

### Cleanup and an incident on .54 (2026-11-23 21:02)

`owner-cleanup-cycle1`: owner units stopped, his rootless storage reset, linger disabled, user manager stopped, no
process left, `userdel -r`, drop-in removed, uidmap purged, account backup files put back byte-exact, account files
equal (booleans only) — 11 of 12 checks; the failed one is `no_new_modules_left`: the step that unloaded the
networking modules the owner's rootless networks had loaded (`modprobe -r`, same allowlist the n8n runs used) made
.54's kernel (6.18.38-ophub) **oops** in nft_masq's exit (NULL pointer in nf_conntrack_helper_unregister ←
nf_nat_masquerade_inet_unregister_notifiers). `incident-54-kernel-oops-nft-masq` (read-only): tainted 1152 (C + D),
nft_masq stuck in state 'going'; .54's homeassistant / matter-server / woow-auth-gateway kept running with unchanged
start times, HA 8123 → 200, tailscaled and ssh active (vnstat.service failed since 2026-11-12, not this lane).
`owner-cycle1-cleanup`: private store + workspace removed. Audits: `owner-cycle1-inventory-after` identical on 27
of 28 keys vs `baseline-before-owner-cycle1`, `-vs-first` 21 of 22 vs `baseline-before`; the only difference is
`modules` (+nft_masq). **A reboot of .54 is needed** to clear it (owner decision: it restarts .54's own services);
until then no new podman bridge network or masquerade rule should be started on .54 (the masquerade notifier lock
may be held). The harness no longer unloads any module (`4ca92b5`).

### Product findings / fixes from item C (relay to the main session)

* `a7f32e9` fix(podman): .54 has Podman only in /usr/local/bin; OwnerRunner/relay/host_info hard-coded
  /usr/bin/podman (exit 127 for every owner command).
* `98410bd` fix(tempctr): rootless Podman 6.1.1 with runc 1.5.1: a throwaway container with `--read-only` and a
  secret mounted under /run/secrets exits 126 ("make mountpoint /run/secrets/…: read-only file system"); the Omnigent
  candidate's new PostgreSQL cluster (ha_omnigent.py:828) and EMQX's `emqx-new` (ha_emqx.py:816) use exactly that.
  Fix: a private tmpfs at /run/secrets for read-only roots with mounted secrets (probe `owner-secret-probe-1`).
* Finding (not changed): an unchanged catalog-suggest draft of the current Headscale package is not importable:
  suggest proposes the read-only config directory as data_dirs (with its own note "不需要時可從 data_dirs 移除") while
  ha_headscale.Target refuses any data_dirs. The run takes the note's admin step.
* Finding (not changed): import packaging needs every image of the app's quadlets to exist; the package's
  `localhost/woow-headplane:0.7.1-woow2` has no arm64 build (stand-in used, never started).

### Stated deviations (item C)

* The test owner's user manager runs in a private network namespace (lo only); the engine joins it (setns).
* The engine tools age/age-keygen/zstd (absent on .54) come from the verified Debian debs (item A provenance),
  bind-mounted over /usr/local/sbin in a private mount namespace of the engine process only.
* Headscale: headplane.service not started (stand-in image: upstream headplane 0.7.1 arm64 tagged with the package's
  name), DERP embedded/isolated, ngrok hook dropped, loopback health URLs added to the draft, read-only config dir
  removed from the draft's data_dirs.
* Omnigent: runner placeholder (pinned PostgreSQL image tagged as the runner image, a shell that traps TERM and
  sleeps), the conversion is the internal candidate in the production job runner (public guard asserted closed).
* Fresh engine directory per app (the Headscale engine was moved aside before Omnigent), not one shared catalog.

### Not covered in item C

* n8n through the OwnerRunner flow (planned; needs a new cycle with uidmap + test owner again, and the .54 reboot).
* Encrypted RPi5 backups through the OwnerRunner flow (the rootful runs covered them).
* Real runner image / Pi agent, Headplane UI, public installer, the public Omnigent import route (closed by design).

## arm54-2 iteration 3 — on the oopsed .54 kernel, before the reboot (2026-11-23 21:15-)

**.54 state (read-only, `incident-54-followup-2120-2`, 2923a5b).** Not rebooted (uptime 13.2 days), tainted 1152,
nft_masq `going`/-1, xt_MASQUERADE live, 0 tasks in uninterruptible sleep, 0 hung-task reports, 1 oops (21:02);
homeassistant / matter-server / woow-auth-gateway with unchanged start times, HA 8123 → 200, tailscaled and ssh
active; no workspace, no test owner, uidmap not installed. `rtnl` is free: the rtnl_trylock sysfs read of
`/sys/class/net/eth0/speed` answered in 8 ms. (`incident-54-followup-2120` failed in my own read-only snippet:
StartedAt parsing; kept.)

**What the oops left locked (trace + Code words).** `pc nf_conntrack_helper_unregister+0x28` ← 
`nf_nat_masquerade_inet_unregister_notifiers+0x24 [nf_nat]` ← `nft_masq_module_exit+0x34`; the faulting
instructions `ldp x0, x1, [x19]; str x0, [x1]` are an hlist delete through a NULL `pprev`, right after the call that
takes the conntrack helper mutex. Until a reboot that mutex (and most likely the masquerade notifier mutex) stays
locked; `rtnl` and `pernet_ops_rwsem` are not held (unregister_netdevice_notifier is not on the stack).
**Lane rule refined (not an owner decision):** network-none containers and INTERNAL Podman networks inside a private
network namespace use neither lock (no masquerade rule, no conntrack helper, no module unload) and may run; every run
records the kernel state (`kernel_state()`) and fails on a new oops, a new task in uninterruptible sleep or a new
hung-task report. Still waiting for the reboot: anything with masquerade (non-internal networks, e.g. the n8n
package's quadlet networks under the OwnerRunner flow), conntrack-helper module loads, any module unload.

| Run (cycle c4, source 2923a5b) | Result | What it showed |
| --- | --- | --- |
| `netprobe-internal-c4` | **exit 0, 11/11, 8.3 s** | one internal network + one throwaway container (eth0, no default route) in a private netns; kernel before/after equal (0 D-state, 0 hung-task, 1 oops, nft_masq going/-1, taint 1152); `veth` loaded |
| `n8n-enc-build-c4` | exit 0 | n8n 2.43.6 / postgres 16.15-alpine / valkey 8.1.11-alpine arm64 by index digest |
| **`n8n-enc-real-attempt1`** | **exit 0, 38/38, 575.2 s** | the **encrypted** 2026-11-19 RPi5 backup `4f5c7337` (sha256 = recorded `a5fb6268…`, owner-accepted provenance) decrypted on .54 by the product's SecureTar reader (PyNaCl 1.5.0 from the pinned workspace wheel); product ha_n8n check (owner ha-probe@probe.invalid, 3 workflows / 1 active / 1 credential / 2 executions, n8n-nodes-globals 1.1.0, no blocker) and convert (PG16 dump 556,201 B, through the product's internal throwaway network in the run's own netns); restore with the adapter's data methods; HA owner logs in with HA's password, target owner refused, credential decrypted to HA's value, community node loads, HA key in the volume; full restart; rollback via `_recreate_volume`; kernel state unchanged |
| `n8n-enc-cleanup-c4`, `n8n-enc-inventory-after-c4` | exit 0 / audit 27 of 28 keys identical | only `modules` differs: +`veth` (loaded by the internal network; never unloaded on .54 any more); workspace absent |

Scope of the n8n runs (unchanged): rootful private store (not OwnerRunner/systemd user units), main n8n process only.

### Item B Odoo — PASSED 38/38 with SUBSTITUTE images, not the product service (owner decision 3A)

`arm54_final_odoo_build.py` (`odoo-build-c5`, exit 0, 217.6 s): official `odoo:18.0-20260926` arm64 (index
`60eb1b50…`, manifest `7cda9ea19a04`; the Odoo release of the product's tenant image, dev-c's check reported
target_version 18.0-20260926; HA's add-on 0.4.13 installs the 18.0.20260930 package), `pgvector/pgvector:0.8.6-pg17`
arm64 = PostgreSQL 17.11 (the product paas-postgres minor; vector + pg_trgm), and the product's first PostgreSQL 16
choice `pgvector:0.8.6-pg16` (16.15) for HA's cluster; each by index digest with the arm64 manifest asserted.

`arm54_final_odoo.py` run of record **`odoo-real-attempt1`** (ca4ec25, **exit 0, 38/38, 404.7 s**), cycle c5 on the
oopsed kernel, everything in the run's own network namespace, pod with network none, **no podman network at all**:

* Target = Woow_podman_odoo c578b8a quadlets (`odoo-package-c578b8a`, SHA256SUMS) rendered with the tenant profile's
  values and the substitute images; fresh tenant emulated (STATED SIMULATION): role odoo (LOGIN CREATEDB, generated
  password, SQL on stdin), database odoo initialised by Odoo itself (`-i base`, no demo, 102.8 s), the target admin's
  password replaced by a generated one, the upgrade-gate marker `woow_paas_platform.upgrade_done` = {digest of the web
  image, core_date 20260926} written by the harness (the official image has no gate).
* Product (unmodified): `ha_odoo.check` + `check_blockers` — no blocker, woowtest and woowtest2 can move, woowtest
  312 partners / 26 installed modules / custom module woow_import_probe 18.0.1.0.0 from data/addons, target_version
  18.0-20260926 (so the module versions equal HA's add-on: the check refuses any difference); `ha_odoo.convert`
  (woowtest, non-test mode): DB volume 86,092,288 B, web data 153,600 B, custom modules folder 20,480 B.
* Source of truth: HA's own cluster opened by the product's `member_pass` + `start_ha_cluster` (PostgreSQL 16,
  network none), `ha_import_e2e.FINGERPRINT_SQL` (count + md5 of every row) of all 205 user tables of woowtest.
* Cold restore with the adapter's own data methods (`_recreate_volume` for both volumes, `_unpack_dir` + `_swap_dir`
  for `~/.local/share/odoo18/addons`), then before Odoo starts: **204 of 205 tables identical**; ir_config_parameter
  differs only in `web.base.url`, `web.base.url.freeze`, `woow_paas_platform.upgrade_done` (ha_odoo.settings_sql);
  26 installed modules with HA's versions; **filestore 17 files / 109,586 B equal file by file (sha256)** to HA's
  `data/odoo/filestore/woowtest` read from the backup itself.
* Clients (JSON-RPC in the pod's namespace): HA's `admin` and `ha-probe` log in with HA's passwords, the target admin's
  password is refused, `ha-probe.txt` reads back (26 B, sha1 = checksum), woow_import_probe installed with its record,
  312 partners; full restart: the same; rollback (`_recreate_volume` + folder restore of the cold safety copies): the
  pre-import tenant is back (6 partners, 5 users, its admin logs in, HA's does not, the folder has no probe module).
* Kernel state before/after equal (0 D-state, 0 hung-task, 1 oops, nft_masq going/-1); min MemAvailable 2.14 GB; min
  free 15.08 GB; 0 secret hits in the output, argv and product log.
* `odoo-cleanup-c5` + `odoo-inventory-after-c5`: **28 of 28 keys identical**, workspace absent;
  `odoo-inventory-after-c5-vs-first-2`: 21 of 22 comparable keys identical vs the 08:49 `baseline-before`, only
  `modules` (+nft_masq `going` from the 21:02 oops, +veth); `-vs-first` (no ignores) kept: its 7 extra keys are absent
  from that older baseline.

**Test mode (`--test-mode`) — PASSED 41/41.** `odoo-real-attempt2-testmode` (60550bf, exit 1, 324.3 s, kept): the
product's test-mode convert passed and neutralised the database, but my check expected 0 active mail servers; Odoo's
own `base/data/neutralize.sql` (read from the exact image: `odoo-vendor-neutralize-18.0-20260926`, sha256 `9dcfa35d…`)
:4-7 deactivates every server and drops its credentials, :10-11 inserts ONE active dummy server ('neutralization -
disable emails', smtp_host 'invalid'), :14-22 deactivates every cron but base.autovacuum_job, :25-28 sets
database.is_neutralized, :36-38 database.secret = 'dummysecret' → assertion corrected (2b17137, stricter: credentials
and crons added). Run of record **`odoo-real-attempt3-testmode`** (2b17137, **exit 0, 41/41, 407.7 s**, cycle c6):
the product's internal throwaway network for `odoo neutralize` ran inside the run's own netns; restored cold: no active
real mail server (HA had 1), exactly 1 active dummy, 0 stored mail credentials, 0 active crons but autovacuum (HA had
13), is_neutralized true, a new database.uuid; same 205-table inventory (200 identical; iap_account,
ir_config_parameter, ir_cron, ir_mail_server, ir_ui_view changed by neutralisation and the import settings); 26 modules
with HA's versions; filestore equal file by file; logins, attachment, probe module, restart, rollback as in normal mode;
kernel state unchanged. `odoo-cleanup-c6` + `odoo-inventory-after-c6`: 28 of 28 keys identical, workspace absent.

Stated deviations (Odoo): substitute images (owner decision 3A); one pod with network none instead of odoo18-network
(db_host 127.0.0.1 in the rendered odoo.conf); no gateway, health timers or published port; units in harness order;
the web container stopped while the product's check and convert run; rootful private store (not OwnerRunner).

## arm54-2 iteration 4 (2026-11-23 23:00 – 2026-11-24)

* **.54 reboot (owner decision 23:28 「兩個都照建議去做」): NOT done.** At a clean point the before-state was recorded
  read-only (`incident-54-reboot-20261123-before`, `-units-before`: boot_id `e5b15a94`, uptime 13.2 d, tainted 1152,
  oops 1, nft_masq going/-1, HA 200, Matter :5580 200; homeassistant / matter-server / woow-auth-gateway are
  quadlet-generated units with `WantedBy=multi-user.target`, `Restart=always`; tailscaled / ssh / tailscale-web
  enabled). The reboot command (`systemd-run --on-active=5 systemctl reboot` over the askpass SSH) was **denied by the
  Claude Code auto-mode classifier** [Destructive or Unwanted Actions]; nothing ran on .54 and it was not retried.
  The owner (or the main session under the user's own permission) must reboot .54; the masquerade items (n8n through
  the OwnerRunner flow) wait for it.
* **Item D (EMQX on .54)** runs on its own branch **`test/arm54-emqx-20261123`** (worktree
  `/tmp/ha-arm54-emqx-20261123`), because it needs the EMQX product line (`feat/ha-import-emqx-product-20261123`)
  merged; see that branch's README section "arm54-2 item D". This branch takes only the product fix it found:
* **PRODUCT FIX `c8df1f2` `fix(tempctr)`** (relay to the main session with `868894f`, `a351cd2`, `a7f32e9`,
  `98410bd`; keep separate): `TempObjects.volume_import` applies a tar's top-directory (`.`) entry after
  `podman volume import` — Podman 6.1.1 ignores it, so the product's EMQX candidate (data volume seeded with `.`
  owned by `emqx` 0700) exited at boot with EACCES on .54 (`emqx-real-arm-attempt1`; proven by `emqx-volume-probe-c7`
  on the item-D branch). `test_ha_tempctr` 26 OK.
* **`1daf803` test(podman)**: the relay path test (from `a7f32e9`) no longer names or starts Podman, so the team's
  host-test guard runs it (it was the one guarded error). `test_podman` 50 OK guarded.

## arm54-2 iteration 6 (2026-11-24 07:35-) — after the reboot of .54

* **.54 was rebooted once, at 2026-11-24 07:23:03, by the main session over SSH on the owner's explicit instruction**
  (the owner wrote that main may do it). This lane did not reboot it: its own attempt at about 23:30 on 2026-11-23 was denied
  by the Claude Code auto-mode classifier and was not retried through another route. Times reported by main: before-state
  07:22:43, SSH back 07:23:54, Home Assistant 200 at 07:24:52, after-state 07:26:35.
* Read-only after-state by this lane at 07:36 (`incident-54-reboot-20261123-after`): new boot_id, tainted 1024 (bit 10, the
  vendor kernel's staging driver; the oops bit 128 is gone), no oops, no D-state task, no hung-task report, `nft_masq` not
  loaded, `homeassistant` / `matter-server` / `woow-auth-gateway` / `tailscaled` / `ssh` active by themselves, HA 200,
  Matter 200; `vnstat.service` failed before (since 2026-11-12, not ours) and after.
* Audit after the reboot and after the c9 cleanup (`incident-54-reboot-20261123-audit-after` vs
  `baseline-before-owner-cycle1`): 22 of 28 keys identical, **`modules` identical again**; the six differing keys are boot
  facts only: container ids (the quadlet services create a new container at every start; names, image digests, state and
  ports are equal), container/service/pi-web start times, and the empty cgroup `libpod_parent` (already there in the first
  baseline, runtime state that the reboot removed). Record: `incident-54-reboot-20261123-record.json`.
* The cycle c9 (EMQX x86 cold, killed at 03:33 nine seconds after its result was committed) left its workspace; it was
  removed by the lane's own harness (item-D branch: `emqx-cleanup-c9` exit 1 = Podman refuses a store of an earlier boot,
  `emqx-cleanup-c9-after-reboot` exit 0 with the new `--after-reboot` step).

### Production incident caused by this lane (2026-11-23 20:13 and 20:18) — recorded truthfully

Two commit messages of this lane (`5140be3` 20:13:37 and `afcae0d` 20:18:55) were passed to git inside double quotes and
held a backquoted user-systemd restart command of `headscale.service`. bash executed that command on the HOST, so
**production Headscale was restarted twice** (host unit journal: stopping 20:13:35 / started 20:13:37 and stopping
20:18:51 / started 20:18:55; main reports about 10 s and 13 s of downtime for Headscale, Headplane and their entrance).
It was not intended, it is a violation of the no-production rule, and both commit messages still show the hole (a line that
starts with a space where the command text should be). History is not rewritten. Since then: commit messages, notes and
scripts only through heredocs with a quoted delimiter or the Write tool.

### n8n through the production OwnerRunner rootless flow — PASSED (2026-11-24 07:49-08:43, cycle owner-cycle2)

The reboot cleared the block (masquerade networks work again). Same owner approval as item C: uidmap installed and ONE
temporary linger account created (`owner-setup-cycle2-attempt1` 15/15), both removed again at the end of the cycle.

* **Target**: the Woow n8n package `2ac1ae2` rendered like its own `scripts/app.sh app_render` in queue mode and started
  through its `n8n.target` as the test owner: all SIX containers (PostgreSQL 16.15, Valkey 8.1.11, n8n 2.43.6 main, task
  runners, worker, worker runners), `n8n-network` bridge, 127.0.0.1:15678 inside the owner's private network namespace.
  Images: the package's four, arm64 by index digest (`owner-images-n8n-cycle2`). The stack keeps running during check and
  conversion, like on any device.
* **Engine**: root CLI (key-init, catalog-suggest `database` variant installed UNCHANGED, upload, ha-check, ha-convert,
  restore, job-status, list); every job by `run-job <id>` in its own process with the production dependencies (OwnerRunner
  = runuser + rootless Podman 6.1.1 + `systemctl --user`), public n8n path (n8n has no import guard).
* **`owner-n8n-attempt2` — 112/112, 883.7 s** (ee5a3cc): plain backup 8e51e2ed. Check 9.9 s (no blocker, 3 workflows / 1
  active / 1 credential / 2 executions, owner ha-probe), convert 143.6 s (encrypted Cockpit backup, HA origin listed, no
  throwaway left, the running target untouched), restore 168.0 s (141 s unavailable, health ok, safety backup). After the
  restore and after a restart of the whole target: HA's owner logs in with HA's password, the target's owner is replaced,
  workflows, credential decrypted to HA's value by n8n's own CLI, row counts, community node loads, HA's key in the data
  volume (0600), six units active, worker and both runners healthy. Manual rollback 166.2 s: digest verification true for
  both volumes and the database, the target's owner, workflow and key are back.
* **`owner-n8n-attempt3-enc` — 134/134, 1123.6 s** (3cdf8c1): the encrypted backup 4f5c7337 through the same flow, plus an
  **automatic rollback**: a second restore whose n8n start fails once (one-shot `ExecStartPre` drop-in, removed again) ends
  `rolled-back` by itself in 215.9 s and HA's data as installed passes every check again; then the manual rollback.
* **`owner-n8n-attempt1`** (ddbd6d3) was stopped on purpose (SIGINT after 723 s): every container failed with `conmon: Include
  journald in compilation path`. **Package/device finding**: .54's podman-static conmon has no journald (its own default is
  k8s-file); the n8n package pins `LogDriver=journald`.
* **`owner-n8n-attempt4-native` — 138/138, 1125.7 s** (0ff3a99): the RPi5 backup e10f1abc of 2026-11-19 (recorded 01:45Z) whose
  n8n holds a community package with a native module for aarch64 musl. With the product fix `ee5a3cc` (= `ed3758e`, branch
  `fix/ha-native-arch-20261124`) the check does not call it incompatible on this ARM64 device, and the restored n8n's own node
  loads the module (`arm64 object`) after the restore, after the restart and after the automatic rollback. Component probe
  with the same archive on .54 (item-D branch, `native-probe-cycle2`): the Odoo ARM module fits too; the old code named both.
* **End of cycle owner-cycle2**: `owner-cleanup-cycle2` (account woowbk54t, home, linger, drop-in, uidmap gone; account files and
  their backups byte-equal, no process, no journal file) and `owner-cycle2-cleanup` (workspace gone); audit
  `owner-cycle2-inventory-after` vs `baseline-before-owner-cycle2`: 27 of 28 keys identical, the 28th is `modules` (+ nft_ct, nft_fib,
  nft_fib_inet, nft_fib_ipv4, nft_fib_ipv6, nft_masq, nft_nat, veth: loaded by the kernel on demand for the rootless bridge networks,
  kept loaded on purpose, they go at the next reboot).
* The same cycle also ran EMQX through OwnerRunner (ARM + x86 164/164; evidence and README on the item-D branch
  `test/arm54-emqx-20261123`).
* `.54` during the n8n runs: own Home Assistant frontend 257/257 samples (max 0.026 s), MemAvailable never below 1.25 GB, owner's
  user manager capped (MemoryMax 1600M, MemorySwapMax 900M), no new oops / hung task / D-state task; the kernel loaded
  nft_ct, nft_fib*, nft_masq, nft_nat and veth on demand for the bridge network (never loaded or unloaded by this lane).
* **Stated deviations**: ExecStartPre of n8n and n8n-worker uses /usr/local/bin/podman (.54 has no /usr/bin/podman);
  LogDriver=k8s-file; private network namespace + memory cap of the owner's user manager; generated test secrets; webhook
  processor off (package default). **Not covered**: a public webhook, executions through the worker, Cockpit's page.

## arm54-2 item D — the HA EMQX import on .54 with the final product (2026-11-23 23:00-)

Branch **`test/arm54-emqx-20261123`** (worktree `/tmp/ha-arm54-emqx-20261123`) = `test/arm54-final-20261123`
+ `c98a198` (`--no-ff` merge of `feat/ha-import-emqx-product-20261123` @ `92e306b`: the final EMQX product import,
engine identical to `7ce908c`; owner instance EP-OWNER-2045, security review SR-OWNER-1942 SR-1..SR-7, owner
decision C) + `e35bb57` (cherry-pick of the lane's `1daf803`: guard-safe relay test) + the item-D harness. The emqx-product merge lives ONLY on this
branch; `test/arm54-final-20261123` has no emqx-product merge. `backup-engine/woowbackup/ha_emqx.py` here is
byte-identical to `92e306b`: this lane changed no EMQX product code and no guard. Product code that differs from
`92e306b`: this lane's earlier fixes only (`868894f`, `a351cd2`, `a7f32e9`, `98410bd`, `5595e3c`, `92d7c5b`,
`a9d8643`).

**Device state**: .54 still NOT rebooted (the owner approved the reboot at 23:28; the reboot command was denied
by the Claude Code auto-mode classifier, see the lane file). Item D is network-free (broker `--network none`, the
whole run in its own network namespace, no podman network, no masquerade, no module load/unload), which the
iteration-3 lane rule allows on the oopsed kernel; every run records the kernel state before/after and fails on a
new oops, D-state task or hung-task report.

**Source**: real B1 HA backups made by HA's own EMQX add-on (woow-emqx 5.9.1 = EMQX 5.8.9) while it was STOPPED
(cold): RPi5 `b6cbc980` (sha256 `b6eb257c…`, 117,207,040 B, encrypted; bytes attested against the RPi5 today in
`source-provenance-34`) and x86 `5fb6f348` (sha256 `0a53e938…`, 137,943,040 B, encrypted; the
`b1-source/backups.json` record). The recorded B1 facts (`b1-source/summary.json`, machine arm/x86, emqx part:
users, ACL counts, retained topics, rules, banned client, Dashboard users; no credential) are what the restored
broker must hold.

**Target**: the product package `Woow_podman_emqx` `ea5886c` (evidence `emqx-package-ea5886c`, the committed bytes)
with the product image itself: `docker.io/emqx/emqx:5.8.9@sha256:35b46f7a…` (multi-arch index, evidence
`emqx-image-index-35b46f7a.json`), `--arch arm64` = manifest `c455c60f…` (`emqx-build-c7`: 263 MB, user emqx,
declares VOLUME `/opt/emqx/data`, `/opt/emqx/log`; the quadlet's own tag@digest reference resolves to it). Generated
device credentials (Dashboard admin, node cookie, MQTT user `woow` + its bootstrap CSV exactly as `install.sh` step 5
derives it) live only in podman secrets of the private store and in memory.

**Method** (`arm54_final_emqx.py`, rootful private store; unmodified product calls): device before -> decision C
refusal on the product default target (`sources = [file]`): `ha_emqx.check` names exactly `ACL_NEEDS_BUILTIN`,
`ha_emqx.convert` refuses `incompatible` with it, nothing changed (state digest equal) -> the customer's step from
that text via the Dashboard API (add `built_in_database`, move `after:file`) -> `ha_emqx.check` (no blocker) ->
`ha_emqx.convert` (target preflight, HA's broker, candidate with this device's settings, row counts, readback) ->
cold safety copies -> `QuadletPostgresAdapter._recreate_volume` x2 -> `haimport.verify_import` (->
`ha_emqx.verify_restored`) -> clients: the dev-d product harness's OWN probe and acceptance function
(`emqx_product_real_ha.PROBE` / `evaluate_imported` @ `92e306b`, read with `ast`, never imported; two asserted
substitutions: Dashboard on its own listener 18093 because there is no entrance container, and the acl.conf path)
-> restart (verify_import + probe again) -> rollback from the safety copies (device state digest equal to before
the import; HA's MQTT users and API key refused) -> cleanup, counting anything the product left in the store.

**Stated deviations / simulations**: network none instead of `emqx.network` (no masquerade on the oopsed kernel);
no published ports; no entrance (nginx) container, so HA's HTTP action (which calls `127.0.0.1:18083`) fails, as on
dev-d; no systemd/quadlet units and no health timers (readiness polled; stop = `podman stop` + `rm` like quadlet's
`--rm`); memory caps; the restore runs the adapter's data methods with the broker stopped instead of
`flows.run_restore` with a package (no Cockpit install or job store on .54); rootful private store, not the
production OwnerRunner (rootless) — item C covered that runner for Headscale/Omnigent.

### Attempt 1 — exit 1 at the conversion: a real Podman 6.1.1 defect in the product's throwaway volumes

`emqx-real-arm-attempt1` (source `8ed40d9` = product `92e306b` + this lane's fixes, exit 1, 755 s; RPi5 `b6cbc980`):
24/24 checks passed up to the conversion — device before (this device's admin logs in, HA's admin and second user
do not; sources `[file]`, `no_match deny`; no HA data); **decision C on the product default target**: the check's
only blocker is exactly the owner's text (`ACL_NEEDS_BUILTIN`), the conversion refuses `incompatible` with it,
writes no volume, and the device's state digest is equal afterwards; the customer's step from that text (Dashboard
API `POST /api/v5/authorization/sources` + `move after:file`) gives `[file, built_in_database]`; the check then has
no blocker. The conversion then stopped: 「暫用的 EMQX 無法開啟這份資料（設定或資料可能不完整或不相容）。」
(`ha_emqx.wait_ready`: the candidate `emqx-new` exited at boot).

Cause, proven on .54 by `emqx-volume-probe-c7` (`21ece9f`, exit 0, 76.5 s; product image, no HA data, network
none): `ha_emqx.import_target_snapshot` seeds the candidate's data volume with a tar whose first entry is `.`
(owned by the image's `emqx` user, 0700). Podman 6.1.1 ignores a tar's `.` entry on `podman volume import` and
keeps the top directory as `volume create` made it (`0 0 755`, read back), so EMQX (uid 1000) cannot create its
own folders in `/opt/emqx/data`: the broker exits 1 after 25.6 s with EACCES/crash in its log. With the entry
applied (`podman unshare chown 1000:1000` / `chmod 0700` on the mountpoint) the same broker reaches `started` in
30.3 s. This is the Podman behaviour `868894f`/`a351cd2` already fixed for the adapter's restore, here in
`tempctr.TempObjects.volume_import`.

**PRODUCT FIX (relay to the main session, keep separate): `c8df1f2` on `test/arm54-final-20261123`
(= `8613ffa` here)** `fix(tempctr)`: `volume_import` keeps the stream's first 64 KiB; when the tar's first member
is `.`, its owner/group/mode are applied to the imported volume with the adapter's own commands. Every caller that
writes a `.` entry meant it (EMQX emqx-new/emqx-in/emqx-src/emqx-xfer, Headscale hs-check, n8n n8nsrc,
Omnigent/Odoo hapg, Odoo odoo-addons); producers without one are unchanged; on Podman versions that honour the
entry the commands change nothing. `test_ha_tempctr` 26 OK (4 new). Production targets with Podman 6.x need it
for the HA EMQX import; dev-d's Podman (another version) evidently handles it: the same candidate booted there in the R-EMQX and emqx-product runs.

Also seen: the product's throwaways left **4 anonymous volumes** (the image's `VOLUME /opt/emqx/data`,
`/opt/emqx/log` paths that a throwaway does not mount; `podman rm` without `--volumes`) — the cross-lane finding
of litellm-secreview (22:35) confirmed on .54; this run counted and removed them (`cleanup.product_left_volumes`).

### Attempt 2 — the candidate boots with the fix; the product then stops at its candidate-vs-device comparison

`emqx-real-arm-attempt2` (source `931818d` = product `e62b0a5`, i.e. with `28e9492`, + `8613ffa`; exit 1, 798 s):
the same 24/24 checks up to the conversion; the candidate now **boots** (the tempctr fix works on Podman 6.1.1),
then the product stops: 「EMQX 候選啟動後設定與目標不一致，已停止。」 (`ha_emqx.target_broker`: this device's boot
form ≠ the candidate's, right after the candidate booted from this device's snapshot, before HA's data is
imported). This is the message dev-d `attempt-05` showed, and dev-d `attempt-06` (on `e62b0a5`) also failed its
conversion. No device change (the product only compares); 4 anonymous volumes again counted and removed.

### Attempt 3 — diagnosis: only `dashboard.listeners.{http,https}.num_acceptors` differ (a CPU-dependent default)

`emqx-real-arm-attempt3-bootdiag` (`73866db`, `--record-boot-forms`, exit 1, 798 s): the run observes what the
product's own `ha_emqx.boot_form` returns (value returned unchanged; no check altered) and reports the differing
paths without values. This device's boot form and the candidate's have 44 roots each; the ONLY differences are
`dashboard.listeners.http.num_acceptors` and `dashboard.listeners.https.num_acceptors`: **device 4, candidate 1**.
Vendor (`emqx_dashboard_schema.erl:125-131`): `num_acceptors` default => `erlang:system_info(schedulers_online)`,
i.e. it depends on the CPUs the broker may use. The device's broker runs without a CPU limit; attempts 1-3 gave the
product's throwaways `--cpus 1` (this harness passed `cpus='1'` to `TempObjects`). **Product finding (relayed to
the EMQX product lane, 2026-11-24 00:35)**: the product's own job runner passes `cpus='auto'` =
`tempctr.default_cpus` = half the CPUs when the owner's user manager delegates the cpu controller, so on a
multi-core production device the same comparison (and `verify_restored`'s, candidate readback vs the restored
broker) fails the same way; `node.broker_pool_size`/`generic_pool_size` use `emqx_vm:schedulers()` (total) and stay
equal. Fix options for that lane: leave runtime-derived defaults the raw configuration does not set out of the
comparisons across a boot (both sides), or run the candidate without `--cpus`. This lane did not change `ha_emqx`.

### Attempt 4 — with the job runner's own CPU default the boot forms are equal; the product stops one step later

`emqx-real-arm-attempt4` (`62cf40f`: `TempObjects` without `cpus=`, i.e. the product job runner's `'auto'`, which
is no limit for this rootful runner; exit 1, 754 s): 24/24 up to the conversion; the candidate boots, its boot form
**equals** this device's (44 roots, no differing path), HA's data is imported, then
`ha_emqx.restore_target_settings` refuses: 「EMQX 匯入後未能保留目標有效設定，已停止。」 (its final comparison of the
device's preserved settings / bootstrap authentication with the candidate's after the settings were loaded back).
Again nothing on the device changed. Attempt 5 observes that comparison the same way (paths only).

### Attempt 5 — diagnosis: only `authorization.sources[1].max_rules` (candidate 100, device absent)

`emqx-real-arm-attempt5-settingsdiag` (`e4bab99`, exit 1, 756 s): the boot forms are equal again; the observer on
`ha_emqx.preserved_settings`/`preserved_bootstrap_authn` (values returned unchanged) shows that
`restore_target_settings`' final comparison differs ONLY in `authorization.sources[1].max_rules`: present in the
candidate after its settings were loaded back with `conf load --replace` (100, the schema default), absent in this
device's raw configuration. The built-in database source was added at runtime — exactly the step the owner's
decision-C text asks the customer to do — and EMQX stores a runtime change without defaults
(`emqx_config.erl:341,345`, the behaviour `28e9492` handled for the comparisons across a boot). **Product finding
for the EMQX product lane**: this comparison (plain raw) must use one form on both sides for that root; until then
every device that follows the owner's text is refused at this step. This lane did not change `ha_emqx`.

### Cycle c7 cleanup and what is still open

`emqx-cleanup-c7` (passed: store empty, image removed, workspace gone, no helper process) + `emqx-inventory-after-c7`:
**28/28 keys identical** to `emqx-baseline-before-c7`; .54's own services untouched throughout; the kernel state
gate held in every run (no new oops, D-state task or hung-task report; no module loaded or unloaded).
Not done for EMQX on .54 (waits for the product lane's fixes): the restore, `verify_import`, the MQTT/Dashboard
client checks of the dev-d acceptance function, restart and rollback; the x86 cold backup `5fb6f348`
(`scratchpad/arm54-2/emqx/cycle_x86.sh`). Already proven on .54: decision C refusal on ARM, the Podman 6.1.1
top-entry defect and its fix, and the exact product comparisons that refuse a device configured as the owner's
text says.

## EMQX through the production OwnerRunner rootless flow on .54 (2026-11-24, cycle owner-cycle2) — ARM and x86 PASSED 164/164

The final product EMQX import merged at emqx-product `e08f8a1` (security fix `abff1a0` SR-8/SR-9 and the tempctr fix `c8df1f2`
included; backup-engine tree `865c930f` + this lane's Podman 6.1.1 fixes `868894f`, `a351cd2`, `a7f32e9`, `98410bd`; 384 guarded unit
tests OK on the merge `918c422`), through the production engine: root CLI (key-init, catalog-suggest + catalog-install, upload,
ha-check, ha-convert, inspect, restore, job-status, list), every job by `run-job` in its own process with the production
dependencies (OwnerRunner = runuser + rootless Podman 6.1.1 + `systemctl --user` of the temporary linger test owner).

* **Target**: product package `ea5886c` as install.sh renders it (emqx.container, emqx-entrance.container, emqx.network bridge, volumes,
  base.hocon, acl.conf, entrance.conf, emqx.env), EMQX 5.8.9 and nginx-unprivileged 1.27 arm64 by index digest, ports 127.0.0.1 only,
  inside the owner's private network namespace.
* **`owner-emqx-arm-attempt1`** (1a73067, tree clean, exit 0, 1778.6 s, 164/164) — the real RPi5 cold backup b6cbc980:
  1. decision C on the [file] target: the check names exactly the owner's text as the only blocker, the conversion job is refused
     `incompatible` with it, nothing is left, the broker's state (and raw configuration digest) is unchanged;
  2. the customer's step from that text (Dashboard API: built-in database added, moved after the file source);
  3. check without blocker (113.5 s), convert 347.4 s (encrypted Cockpit backup with its HA origin, no throwaway container, network
     or anonymous volume left), inspect: preflight ok, in place, settings same;
  4. restore 92.4 s: the product's readback 「EMQX 還原後核對一致」, 41.4 s unavailable, safety backup;
  5. the dev-d harness's own probe, UNCHANGED, run as the owner, and its acceptance function 21/21: after the restore, after a restart
     of emqx.service, after the **automatic rollback** (one-shot start failure, 121.2 s) and after the **readback rollback** (one line
     appended to the restored cluster.hocon right before the start: the job names 設定（log） and rolls back by itself, 148.3 s);
  6. manual rollback 66.3 s: digest verification true for both volumes, device state equal to before the import, HA's MQTT users
     and API key refused, the bootstrap user woow works.
* **`--env-file` on Podman 6.1.1** (security fix abff1a0): the candidate (`emqx-new`) was started with `--env-file …/emqx.env` (8
  observations of its `podman run` in /proc); neither the file's setting name (`EMQX_LOG__CONSOLE__LEVEL`) nor its value was on any
  command line; the candidate booted and passed the product's boot-form comparison.
* **Product finding** (relayed to emqx-product): catalog-suggest drafts the health URL `http://127.0.0.1:18083/readyz` (the entrance's
  HealthCmd). From the host it answers 403 (`entrance.conf`: allow 127.0.0.1; deny all), so a restore with the unchanged draft would
  fail its health check and roll back. This run removed that health entry (dev-d's hand-made entry has none either) after measuring
  the 403. suggest's draft carries only its general hint that the status 200 is assumed.
* Device fact: .54's podman-static creates no healthcheck timers, so the containers' own health state stays `starting` until
  `podman healthcheck run` is called; the product does not use that state.
* .54: own Home Assistant frontend 118/118 samples (max 0.015 s), MemAvailable never below 1.65 GB, no new oops / hung task.
* **`owner-emqx-x86-attempt1`** (365c618, same code, exit 0, 1790.7 s, 164/164) — cross-architecture: the real x86 HA cold backup
  5fb6f348 (B1 record) onto this ARM64 device through exactly the same steps (check 117.9 s, convert 350.7 s, restore 92.3 s, automatic
  rollback 120.8 s, readback rollback 147.7 s, manual rollback 66.4 s; acceptance 21/21 four times; `--env-file` observed again).
  .54's own Home Assistant frontend 119/119 samples.
* Not covered: a public MQTT port, Cockpit's page, a wiped or hot backup on .54 (dev-d covers the hot hint and the [file] refusal).


## arm54-2 iterations 6 (part 2) and 7 — the INTEGRATED engine on .54 (2026-11-24 from 12:00)

Branch **`test/arm54-integrated-20261124`** (worktree `/tmp/ha-arm54-integrated-20261124`) = integration tip `af92b38` + this lane
`632f7da` (merge `a11e6a9`; one text conflict in `tests/backup/test_ha_tempctr.py`, both sides' tests kept) + item D `4df25d8`
(merge `f3ac3ca`; README/status conflicts only). Later merged into it: the integration tips `10b9594` (`cee295e`), `9ebb2bf` (`c5148ec`) and `2b5fee1` (`78ac3c2`; its subject
wrongly names `6592c76`, its second parent is `2b5fee1`), the EMQX health-check fix `4a912de` (`4f7c847`; one conflict in `suggest.py` with
LiteLLM's READY_PATHS, both kept), the Headscale fix `0316d7e` (`d8a5639`) and the Odoo OwnerRunner harness `fd1393d` (`a5b3412`).
It is the one branch to take for the .54 lane; the two older branches stay as they are. The same product bytes WITHOUT the lab
harness and evidence: **`fix/arm54-product-20261124`** @ `db4efdc` (base `6592c76`; only product, documentation and unit-test commits,
one per fix; `git diff` against this branch over `backup-engine`, `docs` and `tests/backup` is empty).

* **Found at the start** (the previous iteration-6 agent was killed at about 10:23): cycle c10 had finished by itself. Its run
  `emqx-real-x86-attempt2` (merged, reviewed EMQX tip `e08f8a1`, rootful, x86 cold backup 5fb6f348) **PASSED 81/81**, 1120.1 s,
  `--env-file` on Podman 6.1.1 recorded. c10 was cleaned (`emqx-cleanup-c10`).
* **The audit of c10 found one leftover of this lane**: the empty cgroup `/sys/fs/cgroup/libpod_parent/conmon` (the private rootful store
  runs with `--cgroup-manager cgroupfs`). It had existed since before the first baseline until the 07:23 reboot removed it, so no earlier
  audit could see it. `arm54_final_cleanup.py` now removes it (only when the cycle's baseline did not have it, only when the kernel
  reports every directory of it as unpopulated, rmdir only); for c10 the same function ran through `control cgroup-cleanup`
  (`emqx-cgroup-cleanup-c10`), then `emqx-inventory-after-c10-2`: **28/28 identical**.
* **Guard test** (integration-3's request of 08:37): `test_arm54_final` asserted the source text of both public holds. The owner's
  decision 1 replaced them; the test now requires by AST that check/convert of both modules call every step of the product paths'
  protection chain and that no hold text is left. **The Omnigent runs 72/72 (plain, encrypted) and 90/90 above were made while the
  hold was on (internal candidate).**

### Cycle owner-cycle3: Headscale and Omnigent through the production OwnerRunner on the integrated engine

Same owner approval as item C (uidmap + ONE temporary linger account, both removed at the end), `owner-setup-cycle3-attempt1` with the
new `all` (Headscale target + memory cap). Every step = root CLI + `run-job` with the production dependencies; nothing injected.

* `owner-headscale-attempt10` **55/55** (exit 0, 186.5 s, source fb1adfb): engine as merged at `fb1adfb` (Headscale from backup 45670371, real tailscale client keeps node 2; check 9.6 s, conversion 19.8 s, restore 42.8 s, manual rollback 45.7 s).
* **Omnigent through the PUBLIC product path — first time on ARM.** `arm54_final_owner_omnigent_public.py`: the entry catalog-suggest drafts
  is installed UNCHANGED (cold variant, the default), the public check and the public conversion run as ordinary jobs while the target
  keeps running (units never restarted), no internal candidate is named. Checked after the restore, after a restart and after the automatic
  rollback: HA's admin and member log in with HA's passwords, this device's admin is kept, agents/scheduled task/session/label/comment/
  attachment (sha256), table counts, HA's cookie key, the runner's pi volume and the server volume's own marker, and — new — the database
  STRUCTURE (`pg_dump --schema-only`, 374 lines) and the role list are byte-for-byte this device's own from before the import (HA's structure is
  never used); manual rollback with digests true; no throwaway, anonymous volume or staging left.
  * `owner-omnigent-public-attempt1` **34/35** (exit 1, 162.5 s, source bd9b3f6): the public check passed (ok, no blocker, no warning, 26.8 s); stopped on MY assertion (the check counts
    people, not user rows; `ha_omnigent.py:336`), corrected.
  * `owner-omnigent-public-attempt2` **137/137** (exit 0, 881.7 s, source f1bce2b): plain backup 45670371 (check 27.2 s, conversion 80.9 s, restore 142.7 s, automatic rollback 188.7 s, manual rollback 149.9 s).
  * `owner-omnigent-public-attempt3-enc` **137/137** (exit 0, 883.4 s, source 99f583f): **encrypted** backup a2dc9bfd (check 28.1 s, conversion 81.3 s, restore 142.8 s, automatic rollback 188.9 s, manual rollback 149.6 s).
  * `owner-omnigent-public-attempt4` **157/157** (exit 0, 1085.0 s, source 664da04): plain again with the FIRST-IMPORT rollback round (check 27.3 s, conversion 80.7 s, first-import rollback 189.2 s, restore 143.1 s, automatic rollback 189.1 s, manual rollback 150.0 s).
* **First-import rollback rounds** (the verifier's point about the EMQX lane, relayed by main at 12:32, holds here too: a rollback that starts
  from the imported state and restores the same converted backup cannot tell "rolled back" from "nothing changed"). Every OwnerRunner harness
  now runs, before any successful restore, one restore whose start fails once: the job must end rolled-back with changed=true, the log must
  show every data volume rebuilt twice (import, then rollback), and the device's own state from before the import must be back as a whole.
* **Product fix `0316d7e`** (branch `fix/ha-headscale-config-dir-20261124`): the entry catalog-suggest drafts for the Headscale package names its
  read-only configuration folder as the app's host folder, and `ha_headscale.Target` refused every entry with data_dirs, so a customer who
  installs the draft unchanged could never import Headscale (attempts 6-10 took the folder out by hand). Exactly that folder is now accepted
  and carried live (checked like every host folder; its config.yaml must still be the one the conversion used). 6 new unit tests, mutations
  8/8. Real proof `owner-headscale-attempt11` **66/66** (exit 0, 299.2 s, source 04a8400): the drafted folder and its digest item kept unchanged, first-import rollback (own users, API key,
  noise key, records and folder back), restore, client, restart, manual rollback with digests true for both volumes and the folder
  (check 9.6 s, conversion 20.7 s, first-import rollback 81.4 s, restore 54.5 s, manual rollback 58.3 s).
* **Product fix `d528653`** (branch `fix/suggest-import-modes-20261124`, merged into the integration as `10b9594` by main's decision): the DEFAULT
  drafts of n8n and Hermes were `cold` while their importers take only a single-database entry; new drafts default to it now.
* End of cycle3: `owner-cleanup-cycle3`, `owner-cycle3-cleanup` (with the cgroup step), audit 28/28 keys identical.

### Cycle owner-cycle4: Odoo (SUBSTITUTE images, not the product service) and EMQX through the production OwnerRunner

* **Odoo** (`arm54_final_owner_odoo.py`; owner decision 3A): the Woow_podman_odoo quadlets `c578b8a` with the official odoo:18.0-20260926 and pgvector
  0.8.6-pg17 arm64 images (index digests, `owner-images-odoo-cycle4-2`) as the test owner's systemd units; a fresh tenant is emulated like the rootful run
  (role, `-i base`, admin password, the upgrade-gate marker of the product's tenant image: STATED SIMULATION). Everything else is the production flow:
  catalog-suggest's draft installed UNCHANGED (cold, the addons folder as host folder), check, conversion of HA's database woowtest, first-import
  rollback, restore, automatic rollback, manual rollback; the target keeps running during check and conversion.
  The strict comparison runs INSIDE the restore, before the restored web container exists (a drop-in holds its ExecStartPre, at most 400 s, always opened):
  every table of HA's database (count + md5 of all rows, read from HA's own cluster opened by the product's throwaway PostgreSQL 16 as the owner) against the
  restored database, HA's filestore file by file (sha256), module versions, the custom module's folder; then logins with HA's passwords, the attachment,
  the custom module's records after the restore, after a restart and after the automatic rollback.
  * `owner-odoo-attempt1` **27/28** (exit 1, 200.4 s, source 207001e): stopped on MY emulated marker (bare image id instead of `sha256:<id>`); deployment, draft and HA's own cluster prints worked.
  * `owner-odoo-attempt2` **95/95** (exit 0, 903.7 s, source 69d43fa): check 36.6 s, conversion 91.7 s, first-import rollback 144.0 s, restore 105.0 s, automatic rollback 146.9 s, manual rollback 105.2 s.
* `owner-images-odoo-cycle4` (exit 1) was a registry failure of the first pull (it worked a minute later, `-cycle4-2`); `owner-images-emqx-cycle4` (exit 1) was
  refused by this harness's own free-space floor (14.07 of 14.1 GiB with the Odoo images): EMQX moved to cycle5.
* End of cycle4: `owner-cleanup-cycle4`, `owner-cycle4-cleanup`, audit 28/28 keys identical.

### Cycle owner-cycle5: EMQX and n8n on the integrated engine

* **EMQX**: engine with the corrected health fix (integration `431201e`): the drafted entry is installed UNCHANGED (its health check asks the broker's public
  REST API; answered to the engine's own headers), a first-import rollback and a first-import readback rollback from the device's own state before any
  successful restore, everything else as in owner-cycle2. `owner-emqx-arm-attempt2` **186/186** (exit 0, 2186.7 s, source 629a6d7): the RPi5 cold backup b6cbc980 (decision-C check on the [file] target 113.7 s, its refused conversion 123.6 s, check 113.2 s, conversion 346.0 s, first-import rollback 132.6 s, first-import readback rollback 160.7 s, restore 93.5 s, automatic rollback 142.6 s, readback rollback 171.0 s, manual rollback 88.2 s).
* **n8n**: the first pull of the cycle's n8n images failed after 6 s (`owner-images-n8n-cycle5`, exit 1: `podman pull` exit 125 on postgres:16.15-alpine,
  the same symptom as cycle4's first Odoo pull); the detached chain stopped there at 14:39 (the iteration-6 agent itself had already stopped between
  14:24 and 14:31 on the session limit of the previous Claude account). Iteration 7 (new account) found the cycle open and nothing running, pulled again in
  the SAME cycle (`owner-images-n8n-cycle5-2`: passed, exit 0, 206.3 s), then
  `owner-n8n-attempt5` **147/147** (exit 0, 1362.3 s, source 0f98ada): plain RPi5 backup 8e51e2ed (owner-accepted 2026-11-19 provenance), the package's queue mode with six containers under the owner's
  user systemd, first-import rollback round from the device's own state (check 9.6 s, conversion 141.1 s, first-import rollback 221.5 s, restore 165.5 s, automatic rollback 216.8 s, manual rollback 167.2 s).
* End of cycle5: `owner-cleanup-cycle5` (uidmap purged, the temporary account `woowbk54t` and its home removed), `owner-cycle5-cleanup` (workspace, private
  store, cgroup step), audit 28/28 keys identical. **.54 has no workspace, no test account and no uidmap now.**

### Cycle owner-cycle6 (iteration 7): EMQX ARM on the integration's export check (B1-03)

At 15:03 the integration merged `fix/emqx-export-members-20261124` (`ff16d6b`, tip `e92e8ae`): right before `emqx ctl data import` the
candidate now lists HA's export with the vendor's own parsers (erl_tar and hocon inside the EMQX candidate, `ha_emqx.check_export`, called
unconditionally at `ha_emqx.py:1417`) and refuses anything that is not META.hocon, cluster.hocon with the data roots or a table backup file. That
step had never run on ARM64 or Podman 6.1.1. This lane merged `e92e8ae` into this branch (`b6444b2`, no conflict) and ran a new cycle (run source =
`b6444b2` plus evidence commits only) with the same owner approval (uidmap + ONE temporary linger account, both removed at the end):

* Guarded unit modules on `b6444b2` (all 21 EMQX modules, tempctr, flows, podman, volume_root, adapters, suggest, the HA imports this lane touched,
  the lane's harness tests): `tests=722 failures=0 errors=0 skipped=0 expected_failures=0 unexpected_successes=0 blocked=0`.
* Guarded FULL tests/backup of `b6444b2` (suite form, 16:14-16:18; `final-full-units-b6444b2.json`): 1814 tests, 3 failures + 3 errors, 6 skipped:
  the 5 `test_litellm_lab_runner` tests the guard refuses (the same 5 the integration records at `2b5fee1`) and once
  `test_bounded_large_archive ... test_runtime_space_loss_aborts_and_cleans` (its child reported ImportError); not reproduced: that module alone 9/9
  and the first nine modules in suite order 247/247 on the same commit. Neither module is touched by this lane.
* `owner-emqx-arm-attempt3` **186/186** (exit 0, 2192.3 s, source 01ecbcb): the RPi5 cold backup b6cbc980, the drafted entry installed UNCHANGED (entry changes: none), first-import rollback and first-import readback
  rollback from the device's own state, decision C on the [file] target, everything else as in owner-cycle5 (decision-C check on the [file] target 113.8 s, its refused conversion 123.8 s, check 113.7 s, conversion (with the export check) 351.9 s, first-import rollback 132.7 s, first-import readback rollback 160.7 s, restore 93.7 s, automatic rollback 143.0 s, readback rollback 171.1 s, manual rollback 88.4 s). The conversion ran the
  export check inside the arm64 candidate and passed (a refusal would have stopped the conversion as `incompatible`). .54's own Home Assistant
  frontend 145/145 samples ok (max 0.015 s), kernel unchanged.
* End of cycle6: `owner-cleanup-cycle6`, `owner-cycle6-cleanup`, audit 28/28 keys identical. **.54 has no workspace, no test account and no uidmap now.**

### Not run (stated)

* Cross-architecture **x86 HA -> ARM** for Omnigent (public path), n8n and Odoo (planned by iteration 6 as its "cycles 6 and 7", not the owner-cycle6 above; harness branch
  `test/arm54-owner-odoo-20261124`, not merged into this branch): not in the main session's final list, so not started. x86 -> ARM is proven for EMQX
  only (`owner-emqx-x86-attempt1` 164/164, `emqx-real-x86-attempt1`/`-attempt2`).
* The product images of Odoo (`woow-odoo-tenant-ha`, `paas-postgres`) still have no arm64 build: every Odoo result on .54 is **substitute images, not the
  product service** (owner decision 3A).

## Notes on recorded flags (arm54-2 correction)

* `headscale-real-attempt7-enc.exit.json` has `tree_dirty: true`. `run` refuses a dirty tree before it starts (`require_clean`) and sends the committed script; the flag in exit.json is computed after the run, when the lane was already editing `ha_n8n.py` (committed later as `92d7c5b`). The run itself used `5e06669` as recorded.
* Before arm54-2 the absence of `uidmap` on .54 and "no odoo18ce/woow-n8n add-on on .34" were not kept as evidence files; arm54-2 records the .54 facts in its own survey (see the arm54-2 section).

## Not covered / blockers

* **Production OwnerRunner/rootless on .54**: DONE for Headscale, Omnigent (internal candidate in item C, the PUBLIC product path in
  iteration 6), n8n (plain, encrypted, ARM64-native, and plain with a first-import rollback in iteration 7), EMQX (ARM and x86) and Odoo
  (substitute images); owner-approved uidmap + ONE temporary linger account per cycle, both removed at the end of every cycle (last:
  owner-cycle6, audit 28/28 keys identical).
* **ha_n8n's SQLite child**: fixed (`92d7c5b`) and probed on .54; in the integration since then as `10fe446`, together with
  the hasqlite fix `5595e3c` (= `1eb0933`); the later n8n runs on .54 ran the fixed code.
* **Encrypted RPi5 backups on .54**: done with workspace-only wheels; a production target still needs the
  Cockpit package dependencies (`python3-nacl`) installed by the installer.
* **EMQX on .54**: item D (this branch, section "arm54-2 item D"): the FINAL product HA EMQX import (emqx-product
  line, merged here only) with the product image and package, real B1 cold backups, rootful private store, network
  none; decision C refusal proven on ARM; attempt 1 found a Podman 6.1.1 defect in the product's throwaway volumes
  (fixed: `c8df1f2` / `8613ffa`); results of the later attempts are in that section. Later PASSED: the rootful runs
  (`emqx-real-arm-attempt6`, `emqx-real-x86-attempt1`/`-attempt2`) and the production OwnerRunner flow with the product package
  (entrance container, ports on 127.0.0.1 only): ARM and x86 164/164 (owner-cycle2), ARM 186/186 (`owner-emqx-arm-attempt2`) on the integrated engine (owner-cycle5)
  and ARM 186/186 (`owner-emqx-arm-attempt3`) with the integration's export check (owner-cycle6).
  Not covered: a public MQTT port, Cockpit's page, a wiped or hot backup on .54.
* **Omnigent on .54**: done for the data and logins; not covered: the real runner image and Pi agent
  pairing (placeholder), the public installer, the `omnigent` bridge network and published port. The public
  import route was held (B1-01) during the earlier runs (iterations 1-5); after the owner's decision 1 replaced the hold it PASSED on ARM
  (`owner-omnigent-public-attempt2`, `-attempt3-enc`, `-attempt4`).
* **Unit tests outside this lane**: at `b2f63ce` `tests.backup.test_ha_omnigent` had 7 failures (they expected the
  pre-`SECURITY_BLOCKER` behaviour); on the integrated branch the owner's decision 1 replaced the hold, see the
  integration lane's suite results for the current state.
* **Odoo/n8n ARM**: n8n plain + encrypted and Odoo (substitute images) PASSED on .54 with the owner-accepted
  2026-11-19 provenance (arm54-2 items B / iteration 3). Earlier note: the 20261119-arm backups are no longer on .34 (`ha backups list` shows only the
  four B1 backups; no odoo18ce/woow-n8n add-on installed), so their origin cannot be re-attested.
* Public installer, Headplane UI, a reboot with restored services running, long-duration traffic and a second physical
  client are not covered. (`flows.run_restore` with systemd user units: covered since item C by the OwnerRunner runs,
  every restore through `run-job`.)

## Secrets

Item C (arm54-2): HA's Omnigent test logins were staged as a 0600 file through the existing lab reader
(`stage-omni`), read and unlinked at the start of each run; the Omnigent target's passwords and the Headscale target
API key were generated on .54 and kept only in the test owner's podman secrets / the 0700 workspace (both removed:
`podman system reset`, `userdel -r`, workspace deletion); every Omnigent run scanned its output for each value
(replaced by a fixed failure on a hit; none). The askpass helper holds no secret; the SSH test password stayed in
the command environment only.

Iteration 2: HA's Omnigent test logins (`b1-creds.env` through the existing lab reader) and the B1 HA
backup key were staged as 0600 files, read and unlinked at the start of each run (also on failure); the
target's passwords were generated on .54 and kept only in podman secrets of the private store (removed);
tokens and cookie keys stayed in memory; each run scanned its output and the product log for every value
(0 hits) and would have replaced the output with a fixed failure. A unit test checks that no lab login
value appears in this lane's code or evidence.

The password was only in the command environment (`ARMHA_PW`) and printed by an askpass helper that
contains no secret. The client state copy, the HA archive and converted data stayed in the 0700
workspace and were deleted with it. No key, token, password or state value is in this directory
(scan: `privkey:`, `nodekey:`, `mkey:`, `discokey:`, `tskey-`, PEM, bearer, password patterns —
zero hits). Iteration 2 (attempt4-enc, attempt7-enc) staged the B1 HA backup key on .54 as a 0600 file through the existing lab reader; each run read and unlinked it at start (also on failure); it was never printed, hashed or written to evidence. (Correction 2026-11-23 arm54-2: iteration 1 of this README said the key was never sent; that was true only before iteration 2.)

Deviation, reported: commits `3423c2d`…`7245e29` contain the owner-given test password as a literal in
one negative assertion of `tests/e2e/lab/test_arm54_final.py` (it checked that ssh arguments never
carry it). It is removed in the next commit; history was not rewritten (local commits only, nothing
pushed). If this branch is ever pushed, squash those commits first or change that test password.
