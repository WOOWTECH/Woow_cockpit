# Fixed ARM/x86 source modes (code-only handoff)

Based on `5ba520c`, rebased onto official vendor reader main `9642f57`.
No lab/native process, real fixture/key, production workload or real source test
was used. Hooke keeps dev-d ownership. A real run must wait for owner handoff.

The existing `run_emqx_arm_cold.sh` passes exactly one of these modes through the
existing transfer/bootstrap to source owner. Do not run without ownership.

| Fixed flag | Frame byte | Source | Spool | File dependency |
| --- | --- | --- | --- | --- |
| `--source` | S | ARM | default256MiB | strict |
| `--x86-source` | X | x86 | owner-x86-20261121 | strict |
| `--source-vendor-acl` | V | ARM | default256MiB | owner-pinned-image-vendor-acl-v1 |
| `--x86-source-vendor-acl` | W | x86 | owner-x86-20261121 | owner-pinned-image-vendor-acl-v1 |

`emqx_source_profiles.py` shares frozen policy between controller and owner.
ARM retains its original fixed path/SHA/aarch64 and exact28/57502 cold receipt.
X86 binds the fixed x86 sibling fixture path and SHA
`0a53e93888209316040af505484bba3ee3891c2ad2df7ae689bc0d4fd02690f9`, amd64,
and the explicit digest-bound fixture profile. Its existing spool implementation
requires exact290785280 expanded bytes/finish with its120-second monotonic bound;
default256MiB/reserve/per-file/semantic limits are unchanged. No Bernoulli-owned
spool, semantic consumer, owner capture or vendor reader implementation is edited.

X86 cold file count and byte total are NOT guessed or copied from ARM. The actual
Capture's receipt must have exactly scope/files/bytes/final_state, historical-
values-only scope, final_state is False, strict integer nonempty<=64 files and
bounded bytes<=32MiB (also<=files*8MiB). Actual Capture still validates every
selected file and exactly one schema. The bound addon_info must report amd64.
No code-only result establishes a real x86 cold measurement.

Vendor modes compile the exact file_dependency_profile and
`emqx_native_runtime.IMAGE`; callers cannot provide profile/image/path/key/SHA
arguments. They use the official source binding's post-digest activation, bounded
complete vendor file observer and receipt handling. Strict modes pass neither
file profile nor image and continue to refuse the observed ACL dependency.
These modes do not remove any reference, file, public or prior audit gate.

Private stdin framing, fixed archive digest plus source-stat stability,
HA_BACKUP_KEY-only RAM handling, nonroot dev-d realm,180-second owner alarm,
locks/isolation/resource checks and mandatory postflight remain. New code and
vendor observer modules/scripts are included in the transfer git archive. The
controller's ONLY change is adding `emqx-vendor-acl-private-*` to its existing
postflight private-directory glob set; its status propagation is unchanged.

No target documents are created. Registry remains unsealed. Owner emits no
source bytes, values, counts, receipts or replay. Source-only exit0 still does
NOT mean full scan, full source/target completeness, restore or HA commercial
acceptance. Historical prior refusal evidence is unchanged.

Generated verification (no native suite duplication):

```sh
PYTHONPATH=backup-engine:tests/e2e/lab python3 -m unittest \
  test_emqx_arm_source_owner test_emqx_source_transfer \
  test_emqx_source_profiles test_emqx_arm_controller -q
```

21/21 passed. X86 generated encrypted backup integration uses real source_binding,
actual Capture and private spool with scaled test-only profile SHA/size; native
contracts are generated at the trusted adapter boundary. Vendor tests exercise
the official full vendor reader with generated observer output; strict variants
refuse without observer IO. Fake-child controller tests verify all four framing
bytes, RAM key placement, required bundle files, wrong digest, same-content
changed file stamp, child status propagation and rejection of extra arguments
before key/archive access. No real x86 source result is claimed.
