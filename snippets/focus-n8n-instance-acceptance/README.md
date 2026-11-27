# Original n8n instance path: preparation

This is a **non-executing preparation packet**. No native case has run. The new
preparer has no `--run` option or device transport. It produces source hashes,
the exact proposed catalog entry, fixed helper requests, and reviewed fixture
and probe code. The companion mutation controller is now implemented; see `controller-phases.md`
and the replaced staged `lease-proposal.md`. It binds the frozen d09 source and
still requires review and an explicit runtime lease. No device phase has run.

Fresh worktree: `/tmp/parity-focus-n8n-instance-acceptance-20261127`, branch
`focus/n8n-instance-acceptance-20261127`, integration base
`abc746834c9eb1884ca31d61250aa58a74ea29c6`. That base predates the final n8n Target
backend call site `f665cc6e`; no product files are changed in this preparation.
The final source path/SHA will be supplied by the coordinator. Regenerate the
packet against that committed checkout; do not treat this preparation SHA as
the future product deployment SHA.

## Fresh read-only facts

`found-metadata.json` records fixed selected fields read through the existing
isolated lab wrapper, without starting a service or opening a database:

- Outer dev-c is running, network `none`, ports `{}`; no running inner containers.
- Seven n8n container services are `inactive/dead/generated`.
- **n8n.target is active/active/enabled** despite the stopped services. Starting
  that already active target does not wake the services. Cleanup must stop the
  seven services explicitly and leave the target active.
- Root backup schedule timer is **active/waiting/enabled**. A leased case must
  record its full state, pause it with a runtime mask, then restore the original
  enabled/active state. It must not leave this timer disabled or masked.
- Trusted root-owned catalog mode0644, SHA256
  `3dfebaa0879d5622514276e2b834bff482f3db53618af0caaa46c5c660e968c4`:
  appowner, one database-scope `n8n-postgres`, database/user `n8n`. Full original
  entry is retained as review data. Each of the three application units has
  `EnvironmentFile=%h/.config/n8n/n8n.env` and one explicit database=n8n setting.
- PG config4278… and Valkey650f… are present. n8n2.43.6 configc8d7… and its matching
  runners28c5… are absent. Exact full IDs and saved archive SHA256/lengths appear
  in the preparer and inventory. The two archive hashes can be independently
  reread locally using `--verify-cache`; this never loads either image.

These are point-in-time facts, not a substitute for the leased run's fresh
inventory. No helper deployment, image load/pull, catalog mutation, app wakeup,
SQL, HA job, or original-baseline restore was performed by this preparation.

## Case and recovery sequence

1. **Freeze and capture.** Exact final source commit, every installed helper/module
   hash, four exact image IDs, fixture hash/size, isolation, >=1200MiB host RAM,
   >=1900MiB device headroom, and >=13GiB reserve **plus8GiB measured peak budget**.
   No active/queued job or competing lease. Record all original backup/upload IDs,
   durable volume names, secret IDs, all catalog hashes, relevant file bytes/mode/
   owner, seven service states, target state, and schedule state. Capture raw
   recovery bytes inside a new root0600 case directory; never put env/secret bytes
   in public evidence. Create the receipt before each owned mutation.
2. **Scope only.** Deep-copy the trusted original catalog; change its single PG
   scope to `instance` and remove only `database`. Production validation must
   accept it. `catalog-install` preview must return the captured SHA above;
   confirmation sends that exact `expected_sha256`. Confirm only this entry
   changed. A different catalog SHA is a stop, not a reason to refresh the CAS
   token automatically.
3. **Fresh full safety before the fixture.** Start only the existing PG service as
   required for the normal encrypted, no-images n8n backup. The main/worker/
   webhook stay stopped. Use the actual `backup-start`, wait terminal, inspect,
   and the prepared raw-manifest probe. Require a complete instance including
   all original non-template DBs, roles, globals and normal digest coverage, with
   **no ha_database marker**. This fresh backup is mandatory recovery authority.
   The historical133KB single-DB baseline `20261118T095520Z-33eb7474` cannot serve
   as the fresh full-instance safety copy.
4. **Actual resolver fixture.** With all application writers stopped and no client
   connected to the source DB, clone `n8n` into
   `woowbk_focus_n8n_<12hex>` using PostgreSQL CREATE DATABASE TEMPLATE. Original
   `n8n` remains present. The PG unit and its `POSTGRES_DB=n8n` stay byte-identical.
   Remove only the single explicit database assignment from main/worker/webhook;
   append the selected clone name to the already declared retained `n8n.env`.
   `resolver_files` refuses alternate inline/Secret/_FILE inputs, ambiguous paths,
   duplicate lines or changed layouts. All fixture writes use captured original
   hashes/mode/owner and atomic replacement; daemon-reload after all three units
   and the env file have changed. Add one uniquely named outsider DB and NOLOGIN
   owner with a marker table. Save exact outsider data/owner, original n8n DB
   fingerprint, every role attribute/password/membership fingerprint, secret IDs,
   config hashes and relevant ACL/type/extension facts privately.
5. **Stopped main, actual vendor.** Stop the seven services, preserve active target.
   Upload only the original encrypted HA fixture through the existing upload/
   credential readers. Run actual `ha-check-start`, then `ha-convert-start`, n8n
   only. Each is a separate, bounded real job with lifecycle checks. A successful
   check/conversion must leave all initially stopped services stopped. No mock
   reader or generated application schema substitutes for the installed n8n
   main process, Config/Env/dotenv, process title, or queue selector. Starting a
   needed service is authorized only by the future lease and is registered for
   restoration before start. Fail app/job on any unreviewed confirm/stop issue.
6. **Inspect the real converted manifest.** The public helper inspect summary omits
   `ha_database` and `ha_access`. Therefore use `MANIFEST_PROBE`, which opens the
   actual archive with existing device identities and returns fixed selected
   fields. Require marker=the clone, valid `ha_access`, complete original+case
   DBs/roles/globals and unchanged ordinary digest validation. Verify conversion
   changed neither live DB nor roles nor retained files. This is the two-existing-
   databases regression: the catalog maintenance DB is postgres, server init DB
   is n8n, actual n8n main DB comes from the env file and is the clone.
7. **Late retained state and refusal.** After conversion add the outsider's second
   row. Change retained app.env's DB selection back to the original n8n and
   restart the actual main/queue. Both DBs still exist. Marked restore preflight
   must stop explicitly for reconversion **before any DROP or safety/start job**;
   verify both data fingerprints and roles unchanged. Restore clone selection
   and restart. The frozen final shared preflight must also handle a file edit
   not yet loaded by the main process; an ambiguous future endpoint is a stop.
8. **Actual selective import.** Start the original seven services explicitly,
   obtain the full endpoint from `ENDPOINT_PROBE`, and require unique main=n8n,
   database=clone, user=n8n, port5432 and shared `local_backend=True` before the
   restore. Run `inspect` and `restore-start` on this run's converted archive.
   Require succeeded, automatic safety ID, no rolled_back, all health/digest
   checks intact; original n8n DB and late outsider row/owner/all roles/secret IDs/
   current config remain unchanged. Verify new HA rows in the clone, not n8n.
9. **API, credential, action, restart.** Use the imported HA owner login and REST
   credential listing; use existing CLI decryption comparison entirely inside
   the device, output boolean only. `API_ACTION_PROBE` fetches the imported manual
   workflow and permits only its two known safe node types. It submits the pinned
   vendor's trigger payload to the actual REST endpoint, polls the returned
   execution to success, and emits three verdicts only. Check the same execution
   exists in the clone and not the original DB. Restart the real n8n target and
   repeat endpoint, login, credential, manual action and outsider/role checks.
10. **Witness forced rollback.** The implemented deterministic READONLY original-
    marker hook supersedes the earlier one-shot proposal. See `controller-phases.md`
    for exact persistent fail/allow semantics, all-row stability, both witness files
    and required rolled-back/API/decryption proof. No new table is introduced.
11. **Return the original baseline.** Wait every owned job/chain terminal and confirm
    no still-owned helper process. Stop the exact seven services; restore original
    raw unit/env bytes only if current hashes are the recorded case hashes or
    already equal originals. Keep instance scope while `restore-start` restores
    the fresh full safety archive. This unmarked ordinary full restore must remove
    the case DB/role changes and restore original data/secrets/config with full
    engine checks. Then, under the engine start lock with no jobs, CAS-replace the
    single catalog entry with its **original raw bytes/mode/owner**, verify the
    original SHA and loaded catalog, and stop the seven services explicitly.
    Leave the already-active target active. Restore the schedule timer exactly.
12. **Prove before deleting.** Verify original DB/role/membership/owner/ACL/extension
    and baseline data fingerprints, file/config/secret hashes, other catalog and
    volume inventories, zero running inner containers, seven inactive services,
    active target, active enabled schedule, unchanged isolation and image policy.
    IDs of disposable live containers may legitimately change after restart;
    compare durable state and owned-resource absence, not an impossible process-ID
    equality. Register and scan HA key/test credential/cookies/issued tokens through
    the existing private evidence mechanism. Only after these checks may owned
    converted/safety/upload/case files be deleted. Retain all copies and receipt
    on any uncertainty; never delete unknown objects or historical baselines.

## Trusted vendor action source

`vendor-api-source.json` records the exact2.43.6 revision
`ffbb9ec54fc02e7f8b54a0b6f41d0a84d0a817f5` and SHA256 of four fetched primary
source files. The workflow controller uses stored workflows; ManualRunDto selects
the trigger variant when supplied. The prepared body is
`{"triggerToStartFrom":{"name":"<the stored manual trigger name>"}}`.
This avoids executing the fixture's separate workflow with file/HTTP nodes.
GET execution polling uses the matching execution controller. Runtime API shape
and action success remain unproven until the real case; offline transport tests
prove request selection and output containment only.

No ordinary34-check rerun, browser/UI proof, current ARM target proof, fresh-target
instance restore, restricted application role/vendor-flow claim, or commercial
acceptance follows from this packet. In particular dev-c's original n8n PG role
is the existing deployment role; the independent restricted-role generated PG
proof remains complementary evidence.
