# Internal encrypted cold-source caller — 2026-11-21

Reviewed main read-only at `9f5f4df` in the coordinator-provided `wt-b1` checkout.
Its `emqx_ha_candidate.py` matches this candidate's synthetic builder: the source
slug/add-on version, target version and fixture target settings are hardcoded.
Main already includes the earlier CLI tests as `412124e`; this increment does
not replay that commit. The synthetic builder and public product files are
unchanged.

## Opt-in integration contract

`emqx_real_candidate.build_verified_candidate(work, app, adapter, target,
backup, staging, job_id, *, expected_sha256, keys)` is a separate internal
Python entry point. It is not registered in any CLI, service driver or public
import API, and does not install a result. A future authorized owner supplies:

- An existing work object with bounded guard, owner runner, abort/checkpoint,
  phase and private logging hooks, plus its app and adapter.
- A reviewed disposable target, including its actual configuration, mounts,
  secrets and data/log volumes. Its image must be an immutable local
  `sha256:<64 lowercase hex>` ID. The product image-label reader determines
  the target version; no caller-supplied version is trusted.
- An unchanged original encrypted archive and independently recorded SHA256,
  plus an in-memory `hasecuretar.Keys` object. Private stdin can be parsed with
  the existing bounded `read_private_keys`; no key argument/env/file is added.
- Private, quota-bounded staging and an authorized job ID. The caller owns
  staging cleanup and must discard all outputs whenever this function raises.

The existing `source_binding` now optionally requires a specific encryption
format; its default remains unchanged for prior callers. This caller requires
v3, revalidates the digest, stopped state, exact source/target version mapping,
architecture, required member layout and strict archive completion before
creating temporary roles. It installs the binding callbacks only on a shallow
copy of work. Actual repository-prefixed member identity and AddonInfo reach
`_build_candidate`, which still performs its product source scan and checks.
The binding stays open through packaging and cleanup, including its final
source-change check. `_package_candidate` uses the supplied target's volume
names and owner IDs. Temporary roles are cleaned in `finally`; cleanup failure
rejects the result. No public preservation blocker is removed.

Key material is neither returned nor saved by the adapter. Decrypted source
bytes pass through the existing product staging stream rather than a new
plaintext source archive. Product temporary volumes, broker exports and
packaged candidates can contain source/target secrets: they remain private
artifacts, not publishable evidence. A cleanup failure or late source-change
failure can leave candidate files in staging even though no result is returned.
The owner must discard them; this function does not delete arbitrary caller
staging. Python memory is not claimed to be securely zeroized.

## Local evidence and exact limitations

Seven new caller tests use generated SecureTar v3 ciphertext and fixture-only
passwords. Source binding, open_backup/open_addon, decryption, product member
scan, `_build_candidate`, source analysis, count checks, `_package_candidate`
and tar validation are real. Runtime boundaries are fakes: TempObjects,
ha_broker, take_export, candidate_from_target and owner transport. No Podman
command is executed. Existing candidate-flow tests separately cover the target
settings/ACL logic with fake transport.

The successful caller cases use repository prefix `fedcba98`, add-on versions
5.9.0 (aarch64) and 5.8.9 (amd64), and target image label 5.8.9. They verify actual
source data reached staging, source cookie/options did not enter the staging
tar, packaged output modes are 0600, fixture keys were not saved to files, and
original work callbacks remain untouched. Negative cases cover hot/plaintext
source, unsupported version, wrong/missing keys, wrong digest, missing or
mismatched image label, unpinned image, wrong app, malformed digest, builder
failure, late source mutation and cleanup failure.

The initial five-test caller run passed in 3.687 s. After adding source-change
and input-gate coverage, the combined 55-test suite passed in 6.197 s. Final
verification after tightening the artifact key scan is recorded below.

## Remaining gates before any real workload run

1. Headscale owns dev-d. Obtain a separately scheduled exclusive slot and pass
   the existing isolation/headroom checks; this code grants no slot or runtime
   authorization. Do not invoke the adapter against current lab targets now.
2. Establish authorized fixture provenance, selected archive hash and cold
   source baseline. Digest binding proves byte identity, not trust or semantic
   validity. Generated Mnesia test bytes are not broker acceptance evidence.
3. Register all real source/target private material with bounded scanners before
   any broker execution or evidence collection: backup key, source options,
   cookie/credentials, MQTT hashes, API keys, TLS material, bootstrap/dashboard
   secrets and connector credentials, including supported encodings and all
   derived private staging/export artifacts. Reject unregistered or unsupported
   secret sources; provide fixed-field sanitized failure reporting. This caller
   does not implement that registration/reporting layer or attest its coverage.
4. Verify the disposable target's actual effective settings, ACL references,
   bootstrap/TLS/plugin compatibility and pinned image. Exercise real MQTT
   authentication, ACL allow/deny, retained data and source/target count
   baselines; prove target settings persist and account/API-key behavior matches
   the contract. Fixture transport is not evidence for these claims.
5. Run a separately authorized candidate/installer/rollback chain, with failure
   injection, original-service preservation and independent cleanup evidence.
   Neither a packaged candidate nor a passing metadata gate authorizes restore.
   Public guard removal remains a separate decision.

No real restore, lab command, production credential access, Hermes review
retry, runner/model/workspace change or omnigent stop occurred. All changes
and generated test files stayed in the owned candidate checkout. Main was
read only.

## Final verification

**55 tests passed in 4.503 s**, no failures or skips. `git diff --check` passed.
The seven new caller tests are included in that total; the unchanged synthetic
source test and both public preservation-guard tests also passed.

```sh
TMPDIR="$PWD/.cli-test-tmp" PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=backup-engine:.:tests/e2e/lab python3 -m unittest \
  test_emqx_real_candidate test_emqx_ha_candidate test_ha_real_fixture \
  tests.backup.test_ha_emqx_preservation_guard \
  tests.backup.test_ha_emqx_candidate_flow tests.backup.test_ha_emqx_package
git diff --check
```

The temporary directory was inside the owned checkout and removed after the
run. No generated archive, key or candidate output is committed.
