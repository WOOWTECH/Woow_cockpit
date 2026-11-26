# Candidate dev-c lease: n8n original instance path

**DRAFT / not granted / not ready to execute.** Preparation is complete enough
to review the exact resources, source requirements, operations and recovery.
A mutating controller is not included or dispatched by the preparer. The parent
must supply its frozen final integration SHA/path and review that controller
before an executable runtime lease is issued. No `--run` invocation is valid in
this preparation commit. Do not run the historical34 driver as a substitute.

## Proposed limits

- One dev-c lease, <=40minutes including recovery; heavy.sh global slot plus
  `/tmp/woowbk-dev-c-mutation.lock`, `flock LOCK_EX|LOCK_NB` before any mutation.
  Do not hold the device while waiting for a global slot. Reserve a recovery
  window rather than killing the controller at40minutes.
- Host>=1200MiB available, disk>=13GiB reserve PLUS8GiB peak budget after expected
  writes, device>=1900MiB reclaim-adjusted headroom under its existing memory cap.
  Stop on resource shortfall; no automatic resource-limit change or image rotation.
- Exact source: final coordinator SHA, installed helper and every `.py` hash equal
  the packet. Include f665cc6e binding plus coordinator-approved final shared
  instance preflight/access fixes. Pin driver commit separately; no deploy here.
- One original encrypted x86 HA fixture, n8n selected only. Original old n8n and
  Odoo baseline archives are immutable. Other applications and DBs on other PG
  instances are outside the mutation scope. No host Podman/install/pull, egress,
  helper deployment, generated mock n8n, browser listener, or new host package.
- Allowed future mutations: existing n8n seven services and schedule timer,
  exactly one CAS catalog file, three exact app Quadlets and retained n8n.env,
  uniquely named DBs/NOLOGIN role, temporary main-service failure hook, actual HA
  check/convert/restore/rollback/jobs, case-created backups/upload/receipt. Safety
  recovery may rebuild the original n8n PG volume through the normal full restore.

## Image prerequisite: separate explicit approval required

Read-only inventory confirmed n8n and runner images missing, PG/Valkey present.
Restore only the following already saved, original dev-c OCI archives if approved:

| config ID | compressed SHA256 | bytes |
| --- | --- | ---: |
| c8d7cd6bf08e1837180b767d77903889e0f3f022accda90579f5e99ca2a2bdfb | 0a7352186122520e86fa3b22d0239ab611387e61bb863d082410c38e71f62ccb | 296256084 |
| 28c5a510d7624e5ce079d2204e4d8421bc96ced83ebc2e1717d6ee33a0ccc1bb | 7fa274ed6a93924cf90420433d5e0928d72183029ea80437fdf4ebc89e70580f | 196625268 |

Files: `~/.woowbk-lab/evidence/parity-space-20261126/dev-c-images/<config>.tar.gz`.
After the original archive length/hash and trusted config/layers are checked,
the command class is a bounded gzip reader piped into the **existing device's**
owner `podman load`, sequentially, under heavy+dev-c lock. Require resulting
config ID exactly as above; no pull or retag fallback. Do not load the Odoo
archives alongside these. No image load has been approved or performed yet.
Whether to keep or rotate these two images back out after successful recovery
must be explicit in the final lease; the preparer authorizes neither deletion
nor leaving an unrecorded image-inventory delta.

## Exact non-mutating preparation command

Run from the committed new worktree (replace SHA with that checkout's exact
commit; a stale SHA or dirty checkout is refused). The new output must not exist:

```sh
/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/focus_n8n_instance_acceptance.py --source /tmp/parity-focus-n8n-instance-acceptance-20261127 --expected-source <exact-preparation-commit> --verify-cache --output /tmp/parity-focus-20261127/n8n-instance-preparation-unique.json
```

This only reads local Git/source/cache and writes the named new JSON. It cannot
wake dev-c or execute its prepared device programs. After final integration,
regenerate against the final source checkout and review changed module hashes;
do not silently accept source movement during a runtime lease.

## Controller requirements before runtime command approval

Use the existing `ha_import_e2e` private credential reader/transport and
`services_a_capture.py`; preserve every failed attempt with an exclusive new
public JSON and0600 private log. The new controller must implement the ordered
steps in README, write a crash-recovery receipt BEFORE start/clone/upload/CAS/
hook intent, resolve every own job by recorded ID/request ID on uncertain
responses, and wait terminal before rollback. Never race a timed-out active job.
No cleanup deletes a full safety copy until `may_clean` is true. Recovery begins
with the exact recorded fresh full safety, not the old single-DB baseline.

The real runtime command will be a separately committed/frozen controller through
the same heavy+capture path. Its final SHA, exact command, expiration, image policy
and private receipt path must appear in the granted lease. This draft does not
ask for or infer that approval; the current user instruction remains PREPARATION
ONLY.
