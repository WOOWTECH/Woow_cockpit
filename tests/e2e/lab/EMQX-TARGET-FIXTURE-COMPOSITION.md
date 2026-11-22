# Issued fixture + vendor target observation

Base includes main a724005/7e48717 fixture observer and 1ecf9a0 dashboard fix.
No lab or actual full-product joined target invocation was performed here.

Owner callable (after successful **same** OwnerProvision.create/start):

```python
vendor_eval, vendor_inspect = bounded_vendor_callbacks(
    broker=provision.fixture.prefix, runner=provision.runner)
observer = vendor_observer(
    broker=provision.fixture.prefix, owned_container_id=actual_cid,
    private_eval=vendor_eval, private_inspect=vendor_inspect,
    fixture_capability=provision.file_capability)
with broker_target_readers(
        broker=provision.fixture.prefix, checked=owner_native_checked,
        quiesce=owner_actual_writer_exclusion,
        vendor_observer=observer) as readers:
    # Existing exact five-category registration and full private scan.
    ...
# Accept only after normal lease exit, which reobserves every dependency.
```

The token is not importable from JSON or an inspection acknowledgment. Only
OwnerProvision.create issues it into the existing WeakKey registry. The fixture
observer first proves base.hocon, lab-acl.conf and issued lab-bootstrap.csv
secret against the same live owner, binding the actual cid. Only that live bound
token permits the vendor observer's exact emqxlab8 broker name; original
fresh/workload regex is unchanged. It still checks immutable image, environment,
network/ports/log policy and excludes every overlap with vendor paths. The
fixture observer retains exact source/RO mounts/secret mapping and native
mode/UID/GID/full-byte/parse/EOF checks. No arbitrary mount permission was added.

The composed private observation is separately WeakKey-bound to the actual
helper calls and native generation. Policy only extends the already exact global
builtin/plain bootstrap and root-bound file authorizer to the two fixed issued
absolute lab paths. Public defaults still require their five vendor receipts.
All three actual fixture files and five public vendor files feed the same Values;
there is no empty ACL, loss of bootstrap semantics or replacement inventory.
The lease rechecks both sources, token lifetime, actual cid/file identity/content
and receipt binding. Unknown/custom file paths remain refused.

94 tests passed: generated real create/issuance registry + actual fixture helper
+ synthetic vendor transport + exact native consumer composition; fake token,
unbound/wrong cid, wrong generation, forged receipt object, revoke and target
identity changes refuse. Native vendor baseline is patched in composition tests.
Existing independent pinned-schema fixtures run offline; no actual commercial
or live joined-target success is claimed. Wrapper shell syntax passed.

Caller limits: fresh_target_quiescence is still fresh/workload-only; it was NOT
broadened for emqxlab. The same owner must provide actual client/ticker/writer
exclusion and retain native table/config/provider stability checks. Vendor helper
still requires log driver none; caller fixture must meet this actual inspection
policy, or refuse. No default/fake quiescence or global log policy waiver exists.
Turing owns the full-product driver and must test this composition on the same
fixture/unit/volumes/secrets after main's public target profile acceptance.

## Direct provision-bound caller API

Turing's driver can use this instead of constructing `_held_vendor_observer`:

```python
from emqx_target_fixture_policy import issued_fixture_observer

observer = issued_fixture_observer(provision)  # lazy, no inspect at construction
with owner_target_readers(private_eval=owner_native_eval,
        quiesce=owner_actual_writer_exclusion, vendor_observer=observer) as readers:
    # existing held source + exact owner_preflight/session consumer
    ...
```

No caller cid/runner/paths/receipts are accepted by this factory. Original issued
provision identity must match the WeakKey token owner. Actual cid discovery is
inside the owner's writer exclusion with inspect 5s/64KiB; full fixture proof
binds that cid independently before vendor access. Eval uses 10s/MAX_WIRE.
Initial inspect cannot authorize a mount or substitute for native content proof.
Changed initial cid vs independent actual fixture proof refuses before vendor
baseline read. A token transplanted into another provision-like object refuses
before transport. Factory performs no lab work until its owner-held context is
entered. Driver remains responsible for actual writer/client/ticker exclusion.
