# Real encrypted HA → same issued owner fixture: code-only foundation

Base: `7e48717`. This change adds an internal operation and generated boundary
tests, not a host CLI, transfer mode or runtime authorization. Main retains sole
dev-d ownership. No lab, actual HA archive, native helper or broker was run here.
No fixture declarations or product/public guard files are changed.

`emqx_real_owner_workflow.run_real_framed_owner` selects only the existing fixed
ARM/x86 SQL source modes. It uses `staged_owner_frame`: bounded RAM backup key,
compiled archive SHA/profile, ciphertext-only staging, full EOF/finish before
runtime creation. The source-only/registration entry points are unchanged.
There is no synthetic source volume export/backup producer in this path.

The call chain is concrete:

1. Require the fixed issued-fixture composite observer API before provisioning.
2. Instantiate actual `OwnerProvision`/`LabOwnerRunner`, require the actual 1800
   MiB full-flow cgroup headroom, stage the frame, and create one issued fixture.
3. Generate bootstrap/dashboard credentials solely for that fixture; read its
   actual isolated runtime. Persistent broker logging refuses before source use.
4. Enter actual `capture_owner_source` with product selection/native HOCON/cold
   decoder and the fixed profile's historical receipt/architecture checks.
5. Hold the same fixture's no-client/ticker lease through actual target readers,
   the required composite observer, `owner_preflight`, and
   `build_captured_candidate`. The bridge retains its source/session capabilities
   and actual product `_build_candidate`/`_package_candidate` gates.
6. Release the observation lease while retaining the source context. Package the
   converted volumes with actual `QuadletPostgresAdapter.import_manifest` and
   `flows._package` into a private `Paths` root, then use `flows.run_restore`.
7. Restore the same package again with a fixture-scoped one-shot startup failure;
   require product `RolledBack` and a consumed failure marker, remove the drop-in,
   restart the same unit, check readiness, and clean issued/private resources.

Every adapter is the actual product class, bound to the same runner. Only app ID
is aliased to `emqx` in a private catalog. Unit, writer unit, volume, secret,
Quadlet and config declarations remain those of the original fixture. The public
catalog validator still rejects fixture config paths under ID `emqx`: first the
original fixture is fully validated, then a private immutable App clone receives
only the logical ID, corresponding raw ID and digest. This private alias is not
an installable catalog entry or an expansion of the public catalog namespace.
The factory checks this exact clone plus the actual issued file capability;
another fixture, FreshTarget or renamed volume cannot be substituted.

## Unfinished dependencies — keep refused

The first blocking stage is `observer_dependency`. Proposed fixed Hooke API:

```
emqx_target_vendor_policy.fixture_vendor_observer(provision=actual_owner_provision)
    -> held callback(generation=..., private_values=...)
```

It must be compatible with the existing `owner_target_readers` policy constructor,
validate the actual `FixtureFiles` capability, bind the capability's runner/CID and
same held generation, fully register vendor files plus issued base HOCON/custom
ACL/Podman bootstrap secret values, and recheck the lease. A receipt dict,
boolean acknowledgment, vendor-only replacement, omitted dependency or no-op
callback cannot authorize this path. This change does not invent that policy or
modify the vendor consumer to accept custom paths. Main/Hooke must implement and
prove the composite contract. Missing/noncallable API refuses before any runtime
resource or frame read.

The current fixture unit does not explicitly set `--log-driver=none`; this driver
requires actual inspected logging `none`. Main must establish a compatible
issued-unit contract before runtime use; this change does not rewrite the unit
or relax observation. Existing target/dashboard/reference gates also remain.

A later fixed bounded RAM field frame is still required for source-client MQTT
credentials. No original source credentials are read from a file, argv, env,
hash, or another fresh broker. This foundation does not prove source MQTT
allowed/deny, retained payload equivalence, source final-row state or commercial
HA readiness. Readiness/flow return codes and rollback exceptions alone are not
those proofs. The result explicitly leaves these assessments incomplete.

Generated tests execute actual capability issuance against generated private
files, catalog validation and actual adapter/context construction. Package and
restore IO is substituted at the declared orchestration boundary to prove exact
same-target arguments, imported-hook ordering and drop-in cleanup. These are not
real package/restore/rollback evidence. Existing source/candidate capability tests
remain necessary and unchanged. Runtime execution requires an explicit main
ownership handoff and separately reviewed host transport; none is added here.
