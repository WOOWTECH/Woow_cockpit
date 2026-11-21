# Omnigent internal candidate installer / rollback — local evidence

Base: clean `/tmp/omnigent-trusted-work` at `c7b7bb4`. No applicable AGENTS.md
was found at the worktree, its ancestors, or beneath backup-engine/tests.
Existing real Supervisor/app-chain evidence at `0fd7311`, recorded by `c7b7bb4`,
is retained unchanged; no device operation was run for this change.

## Callable boundary

Trusted internal Python callers can now use:

```python
converted = haimport._run_omnigent_candidate(
    conversion_ctx,
    {'ha_backup_id': uploaded_id, 'apps': ['omnigent'],
     'encrypt': True, 'test_mode': True},
    schema_ddl_quiesced=True,
)
# Separate job ID/context, same storage/keys/catalog and ordinary job ownership.
installed = haimport._install_omnigent_candidate(restore_ctx, converted['backup_id'])
```

These are not CLI/RPC/UI routes. Public check/convert and the old restore guard
remain blocked; request fields cannot select the internal converter. Only exactly
one Omnigent selection and the literal `True` guarantee are accepted. Conversion
uses the existing HA workflow, adapter import_manifest, packaging and origin
registry. The installer requires an Omnigent origin record, rejects absent or
unreadable records, and delegates to unmodified `flows.run_restore`. The origin
record is a routing check, **not cryptographic attestation or a release approval**;
ordinary archive/key/preflight checks still apply. Registration failure leaves a
backup in accordance with the existing workflow, but this installer refuses it.

The caller must already hold the ordinary job serialization/ownership boundary.
This helper does not acquire a lab slot or prove that an arbitrary device is safe.

## Secrets and restricted schema

Before conversion, every `Secret=` reference in the target Quadlets must appear
in the catalog secret list; duplicate declarations also fail. Names are parsed
using the same strict secret-spec parser as temporary containers. No secret value
is read for this dependency check. The real import adapter subsequently reads and
privately packages declared secrets; a registered but missing secret prevents
publication. The fixtures explicitly declare PostgreSQL password and DATABASE_URL.
Real deployments must also register any bootstrap, runner, or other referenced
secret; these two fixture names are not a production inventory.

Cookie/artifact credentials and pi auth travel in their corresponding volumes,
not Podman secret declarations. Secret declaration coverage does not prove all
embedded credentials are masked. The existing real-probe credential registration
contract (register complete issued fields before ACK, raw/escaped masking,
private files, no raw credential output) is unchanged. No real credentials were
read and no original 400/401 request was retried.

`schema_ddl_quiesced=True` is a trusted caller assertion, **not enforcement**.
The caller must exclude migration/bootstrap jobs and every other DDL session
against the target through conversion, including types, functions, constraints,
extensions and new objects, not just the Alembic table. A stopped app alone is
insufficient when another DDL actor exists. Existing restricted-schema object,
revision and column checks, exported snapshot, target-derived schema and restricted
HA data loading remain intact. Column signatures do not establish equivalence of
all schema properties. No live/general-schema guarantee is claimed. The installer
uses the catalog's stopped writers; the fixture declares all three Omnigent units.

## Local verification

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:. python3 -m unittest \
  tests.backup.test_ha_omnigent_install \
  tests.backup.test_ha_omnigent_candidate \
  tests.backup.test_ha_omnigent_trusted \
  tests.backup.test_ha_omnigent_server_volume \
  tests.backup.test_ha_import \
  tests.backup.test_ha_emqx_candidate_flow \
  tests.backup.test_ha_emqx_bootstrap_flow
python3 scripts/check_source.py
git diff --check
```

**71 tests passed**, source check passed, diff whitespace check passed. The seven
new installer tests cover successful installation/safety backup, late volume
import failure after the candidate cookie is already installed, post-import health
failure, rollback failure, absent/corrupt origin registry, and a missing declared
secret. Successful rollback checks original file payloads in all three volumes,
exact original secret bytes (including a value changed after conversion), running
units and cleared masks. Failed rollback retains the safety backup and masks.
Candidate-entry tests cover literal quiescence, mixed selections, missing/duplicate
secret registration and public-route guard retention.

The restore, rollback, safety-copy handling, preflight and import_manifest methods
are real production code, not mocked. Podman/systemd owner transport and HTTP are
stateful local fixtures. Conversion PostgreSQL, snapshot and source discovery are
fixtures. Archive encryption is FakeArchive; therefore this does **not** establish
real PostgreSQL, systemd, encryption, device recovery or commercial acceptance.
Volume assertions compare extracted file payloads; they are not byte-identical tar
or full filesystem metadata verification.

Supplemental unchanged `test_ha_omnigent_real_app_fixture` had an intermittent
failure in `test_missing_end_truncation_and_timeout_are_not_evidence`: its 0.3-second
subprocess test sometimes reached its assertion without a registered token. The single test
passed separately. A full 18-test diagnostic run also passed, observing registered
credentials for incomplete/truncated/timed-out streams (0.195/0.141/0.303 seconds).
Two earlier broader/module runs failed this assertion. Startup timing is a
hypothesis, not a proven root cause. No timeout, registration requirement, producer
or acceptance rule was relaxed. Do not report this supplemental suite as reliably
green based on the later pass; retain this timing issue for follow-up.

## Main-agent handoff / not verified

Kuhn owns dev-d for LiteLLM; do not run this installer there until the main agent
assigns an exclusive slot. No real installer/rollback harness or device run is
claimed by this change. Next slot work must adapt the existing isolated real
Supervisor chain to these separate conversion/restore contexts and real adapter
transport, supply a complete synthetic secret/catalog inventory, establish DDL
quiescence, and prove normal install plus induced failure/automatic rollback with
private credential evidence and synthetic-only cleanup. Preserve the prior pass;
run only the missing installer/rollback portion as dependencies permit.

No production data, conversation runner/model/workspace settings, `omnigent stop`,
public guard release, or Hermes review was touched or performed.

## Follow-up candidate review — 2026-11-21, base 91c9762

The worktree was clean at `91c976208d4a1bf36b7806efb4faaa55a5602b35`.
This follow-up adds three local installer regressions, without changing runtime
code or public guards:

- A registry row naming another app refuses before any owner command.
- Missing target images fail preflight before stopping writers; volumes, secrets,
  active units and masks remain unchanged.
- Failure exporting the pi volume for the safety copy reports `safety_failed=True`
  and `changed=False`, restarts all writers, clears masks, and never imports a
  candidate volume or enters rollback. The result is carried by the raised
  exception, not by the reporter's partial-result dictionary.

The same seven-module command above now passes **74 tests**. Source check and
`git diff --check` pass. During test development the safety-failure assertion
initially read the reporter dictionary and raised KeyError; it was corrected to
check the actual exception result. No runtime defect was established by this
review, so no speculative runtime change was made. The earlier intermittent
real-app-fixture timeout test was not changed or rerun by this follow-up.

Historical evidence was checked directly in
`tests/e2e/lab/evidence/omnigent-real-app-chain/slot-20261121-0fd7311/`:
`exit-status` is 0; postcheck records unchanged container, volume and secret
inventories, outer `running none {}`, and zero stderr bytes. The recorded
`run.jsonl` SHA-256 and all five source SHA-256 values match the manifest at
`0fd7311b35ffee2ff49cfacf8dad7791ef9eda81`. This establishes consistency of the
committed historical evidence, not a new device run or the present device state.
That run proves the recorded synthetic app-chain scope, not installer/rollback.

### Scheduling handoff (not executed)

The existing runnable heavy command, from the reviewed checkout, is:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:. python3 \
  tests/e2e/lab/omnigent_real_app_chain.py --run --outer-isolation-confirmed
```

**This is app-chain only. Do not schedule it as an installer/rollback test or
repeat the historical pass merely to fill that gap.** The script has no
installer/rollback mode; there is currently no reviewed executable command for
that missing acceptance. Before scheduling the missing work, implement and review
a harness that uses the private conversion/install Python entries shown above,
separate job contexts with ordinary job serialization, real archive encryption
and a real adapter transport restricted to synthetic lab resources. Do not
substitute the local FakeOwner/FakeArchive suite for device acceptance.

The slot owner must first allocate dev-d exclusively (old slot ownership notes
are historical, not a current reservation), verify its outer network is `none`
and published ports empty, verify the pinned images already exist, and establish
sufficient disk/memory/time budgets. The new transport must support systemd
writers and the owner file helper as well as Podman; the existing app-chain
Runner only bridges Podman and its Quadlets are synthetic, not installed units.
Catalog every referenced synthetic secret and every writer, exclude all target
DDL actors throughout conversion, register issued credentials before ACK, keep
private evidence masked, and prove random resource names absent before creation.
No production owners, secrets or resources may be used.

Required device cases: successful install with readable encrypted safety backup;
late import failure and post-import health failure with automatic rollback;
verification of original DB/application markers, cookie/auth continuity, exact
synthetic secret bytes, volume metadata and writer states after recovery; and
synthetic-only cleanup with before/after inventories. Retain safety evidence on
failed rollback and report incomplete recovery. A future concrete harness command
and reviewed revision must be supplied before that slot starts. No dev-d command,
Hermes re-review, conversation setting change, or `omnigent stop` was performed.

## Executable transport harness — follow-up to 0d03bec

The earlier "no executable installer harness" gap is now addressed by
`tests/e2e/lab/omnigent_install_rollback.py`. This is a **candidate for a scheduled
synthetic dev-d run**, not device acceptance: it has not been run against dev-d.
The local worktree base is `0d03bec`; the coordinator reports that `91c9762` and
`0d03bec` have been integrated on main as `092a92e`. No main checkout was changed.

### Concrete scheduled command

From a checkout containing this follow-up, on the lab host (not inside dev-d):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:. python3 \
  tests/e2e/lab/omnigent_install_rollback.py --run --outer-isolation-confirmed
```

Both flags are mandatory before any device contact. Only the main coordinator
may allocate the dev-d slot; it remains reserved for LiteLLM during this work.
Before running, the slot owner must verify outer dev-d network=none, no published
ports, the existing pinned PG/app images, appowner UID 1019, working user systemd
and Quadlet generation, and available memory/disk. Host age, age-keygen and zstd
are required. The script reuses app-chain's loopback-only and memory preflight;
outer isolation is still explicitly operator-attested. It does not start or
reconfigure the outer device, pull images, or touch production Podman.

### Executed path and evidence contract

The existing app-chain builds a cold synthetic Supervisor backup from the pinned
real app and PostgreSQL images, independently bootstraps the target, stops the
application to hold DDL quiescence and invokes the restricted candidate converter.
An internal Python callback receives those real converted volumes before the old
manual restored-container step. Ordinary app-chain invocation is unchanged.
The converter's existing captured `/v1/info` replay and synthetic catalog remain
explicit fixture boundaries; this is not a new public HA import route.

The new callback installs uniquely named synthetic Quadlets for the target DB,
server and a **sleep-only synthetic pi-volume writer**. It does not run an AI
runner, modify conversation settings or exercise model execution. It uses a real
`OwnerRunner` over `owner.sh d` for systemd, Podman, file-helper and relay calls;
no production OwnerRunner command is executed on the host. Runtime inspection
checks pinned image identity, exact volume mounts, no ports, isolated networking
and memory limits before packaging and after restore/rollback. Secret inventory
contains the one synthetic bootstrap password referenced by these Quadlets; DB
uses isolated trust authentication, not a production password inventory.

Following the EMQX real adapter pattern (read from the separate candidate checkout's
`emqx_adapter_driver.py` / `emqx_adapter_provision.py`), the callback uses real
`QuadletPostgresAdapter.import_manifest`, `_package`, age/zstd encryption and
`flows.run_restore`. The converted volumes are packaged directly; it does not
fabricate an origin registry row or claim coverage of the full public conversion
job. Each restore gets a distinct context/job ID. A private local job lock and
exclusive owner-side installer lock serialize this harness; the team slot remains
necessary for coordination with other harnesses.

First restore must install the candidate, decrypt its safety backup, read the
source session with the pre-conversion token, preserve cookie and pi-auth bytes,
and authenticate both synthetic accounts. Before the second restore, distinct
DB/server/pi markers are written. The adapter's ordinary imported hook arms one
systemd ExecStartPre failure **after all candidate volumes have been imported**.
The marker is consumed exactly once; unmodified `flows.run_restore` must raise
`RolledBack`, and rollback must restore all three markers, marker mode/UID/GID,
synthetic secret bytes, cookie/token/login continuity and active unmasked writers.
Its safety archive is also decrypted with the real key.

Cleanup removes only invocation-owned units/drop-ins/markers/containers. App-chain
then removes its invocation-owned volumes/secrets, and an outer before/after
inventory comparison must match. The success path removes host private staging.
On failure the `/tmp/woowbk-omni-install-*` engine directory (0700, including keys
and safety archives) is retained and only its path is reported. Cleanup failure is
a failure, never a success event. Engine log text and exception messages are not
published; credential issuance retains app-chain's register-before-ACK transport.
No resource names, credentials, database rows or raw HTTP bodies are printed by
the new harness. A `cleanup` event alone is not an acceptance verdict: the
scheduled caller must require exit 0 and both adapter success events plus the
unchanged-inventory event.

### Local verification only

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:. python3 -m unittest \
  tests.backup.test_ha_omnigent_install_harness \
  tests.backup.test_ha_omnigent_install \
  tests.backup.test_ha_omnigent_candidate \
  tests.backup.test_ha_omnigent_trusted \
  tests.backup.test_ha_omnigent_server_volume \
  tests.backup.test_ha_import \
  tests.backup.test_ha_emqx_candidate_flow \
  tests.backup.test_ha_emqx_bootstrap_flow \
  tests.backup.test_ha_omnigent_real_app_fixture
python3 scripts/check_source.py
git diff --check
```

**108 tests passed**, including six offline harness tests and ten installer tests
repeated with real age/zstd instead of FakeArchive. A subsequent 16-test harness
run also passed after switching those ten cases to real Storage and KeyStore.
Owner/systemd/Podman and
conversion PG in those local regressions remain fixtures. The previously flaky
credential-event timeout test passed in this run without changing its timeout or
contract. These results do not prove the new live Quadlets or transport flow on
dev-d; the concrete command above is now ready for that scheduled validation.
