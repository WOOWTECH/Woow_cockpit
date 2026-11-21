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
