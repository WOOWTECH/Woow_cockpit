# Reviewable controller and staged leases

Code now exists; **no runtime phase has executed or been authorized**. Driver:
`tests/e2e/lab/focus_n8n_instance_acceptance_run.py`; fixed operations:
`focus_n8n_instance_acceptance_ops.py`. Default invocation compiles offline and
never imports the device transport. `--execute` requires the exact driver commit,
an unexpired phase-specific coordinator lease, clean source, outer isolation,
heavy slot and dev-c lock. Source for safety/flow/recover is frozen
`/tmp/parity-focus-final-gate2-20261127` at
`d09f4fe8e06305aff6a1150f41d6de719e7b7f6a`. No product deployment is in this driver.

## Phases that can be reviewed separately now

1. `images`: independently rehash the two named saved compressed OCI archives,
   record original catalog/unit/file/volume/image IDs and original n8n/Odoo
   baseline archive AND per-ID JSON sidecar hashes/metadata, compare the pinned
   read-only provenance capture, create root0700 protected original-byte copies, then
   stream gzip into only dev-c owner `podman load`, one exact image at a time.
   Each load has intent recorded first, device timeout300+kill30 seconds, host
   wait350 seconds and exact config-ID validation with Podman's `{{.ID}}`. No app/PG start, helper call,
   SQL, catalog change, pull, host Podman or image retag. Preserve the already
   present PG4278/Valkey650f IDs. It can run before final helper deployment.
2. `images-recover`: initial absence + exact pre-load intent establish ownership,
   including a partial load. Refuse unknown extra IDs; retain and disclose them.
   Remove only proven own IDs with `image rm --no-prune`, never force or volume
   deletion. Recompare original durable state and image inventory. If the images
   lease includes recovery, the controller attempts this on a load-phase failure.
3. `safety`: require installed helper/all modules equal d09, four exact images,
   seven original services inactive, and the trusted catalog SHA. Runtime-mask
   the active enabled backup timer, CAS-switch only PG scope to instance, start
   only existing PG, prove known original settings marker, capture current all-
   database/role/password/membership/owner/type/ACL/extension fingerprints using
   the actual production digest reader. Make a real encrypted no-images full
   backup; inspect its actual manifest and require complete unmarked instance.
   Finally wait job and service exit, stop seven services, restore exact raw
   catalog bytes under start lock, restore schedule, leave active n8n.target
   active. The fresh full safety and protected receipt remain for the next phase.
4. `flow`: clone original n8n to a unique DB, select the clone in the retained
   EnvironmentFile for main+worker+webhook with original POSTGRES_DB unchanged.
   Run stopped-main HA check/convert with original fixture and installed vendor
   process/config reader, require all initially stopped services return stopped,
   validate the actual marked converted manifest and unchanged live state. Add
   late outsider data, prove actual changed destination DB is refused before a
   restore job/DROP, restore clone selection, import, test real owner REST login,
   credential listing, vendor CLI decryption and safe manual action execution in
   the clone only. Restart actual n8n.target and repeat proofs. Then deterministic
   forced rollback, followed by full original safety recovery and owned cleanup.
5. `recover`: reconcile the recorded uncertain job against the existing engine
   request journal, wait its terminal record **and systemd service exit**, then
   remove only own hook, restore original unit/env bytes by CAS, restore fresh
   full unmarked safety through normal restore-start, verify current DB/auth
   state, original declared file bytes/mode/uid/gid/mtime_ns, catalog/services/
   timer/baseline hashes, and only then clean own
   archives/upload/files. It never resends an uncertain start. Unknown/live jobs,
   file edits, cookies not registered for scanning or a failed verification keep
   the recovery copies and receipt. No old single-DB backup is substituted.

The receipt is private0600 and atomically fsynced. Original raw environment
bytes never leave the device's root0700 directory. Public events contain only
fixed check names/status/counts; keys travel through the existing reader and
stdin, and are never written into the receipt. Cookies issued by each API probe
stay in the protected device directory and are included in the existing secret
scan before deletion. Private CLI credential export uses a unique checked-absent
case path and existing finally cleanup, not an unowned fixed temporary filename.

`protected-baselines-readonly.json` is actual fixed read-only dev-c evidence:
both named originals are `<id>.tar` with separate `<id>.json` sidecars. The fixed
probe checks the installed production Storage's exact archive/index paths;
installed storage.py and paths.py hashes match d09. Source before the final
commit was dirty relative to c0f140c6; the capture records exact ops/probe hashes.
The controller checks both archive and sidecar bytes, size, mode, owner and
mtime_ns, including absence if a sidecar is absent. Duplicate archive formats,
symlinks, unreadable files, or changes refuse. It never reads an aggregate index.
Recovery preserves nanosecond mtime after atomic original-byte replacement,
including after the engine's full archive restore. Inode, ctime and access time
are outside the equality claim; inode/ctime necessarily change on replacement.

## Deterministic rollback hook

The old one-shot proposal is superseded. The implemented hook runs a fixed
Python predicate at main-service startup with Restart=no. It executes only:

`SELECT to_json(count(*)=1) FROM public.settings WHERE key='woowbk.lab.baseline.before';`

The known original marker is copied from original n8n into the imported clone
before this test, in its existing settings table. Scheduled writes are paused
through the pinned actual vendor API; exact all-row state must be stable. Every
start while forward HA data lacks the marker fails; full safety rollback restores
it and the same hook permits startup. Own refused/allowed witness files prove
both branches actually ran. Require rolled-back job/result/safety ID, exact
full pre-restore DB fingerprints, preserved marker/outsiders/roles/types/access,
then actual imported owner API/action/credential decryption. A preflight refusal,
one healthy start, changed snapshot or timeout cannot pass the rollback case.

## Protection gates and boundaries

- Refuse finite n8n manual-retention policy or pre-existing n8n safety archives
  before safety-phase writes. Standard engine housekeeping must not prune an
  earlier lane's backup. The driver neither edits retention nor deletes old
  safety archives to make this pass. Original n8n/Odoo baseline bytes are hashed
  before every stage and after recovery and excluded from owned cleanup.
- Catalog has no configured postgres-digest checks (`verify: []`). The controller
  does not invent a passing engine verification or remove checks: every real
  returned digest must match, and its own full snapshots use the actual trusted
  production digest reader plus type/ACL/extension and all-role coverage.
- Loaded Requires/Wants/BindsTo are checked before a start; unknown/foreign
  application services refuse before start. All seven initially stopped app
  units are registered before any partial start/implicit app dependency start.
- Image policy is explicit: retain-for-case after initial stage, or remove own
  images after complete recovery. No broad cache/volume cleanup or force delete.
- Native behavior is unproven until the reviewed leased phase actually runs.
  All controller tests are offline transport/state/file/predicate evidence. The
  previous34 ordinary vendor checks and Kuhn's restricted-role generated PG
  proof remain distinct. No browser, ARM target or commercial closure is claimed.
