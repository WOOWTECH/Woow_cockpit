# ARM owner source-only subcase (code-only)

Base: immutable main `af89ca5`. This adds new modules only; the main-owned
owner/transfer/controller and public guards are unchanged. No dev-d operation,
actual source/credentials, broker, native process or main native suite was used.
A real execution requires a separate explicit owner handoff; Hooke retains it.

Entry: `emqx_arm_source_owner.main(['--source'])` in the owner's already bootstrapped
private Python process. Standalone `emqx_arm_source_owner.py --source` accepts
only that fixed mode; it refuses non-dev-d/root realms, extra options and all
path/key/SHA overrides. It emits no stdout or stderr, including on success.
The top-level CLI owns a180-second alarm. Do not use argv/env for secrets.

Input is the existing private owner frame AFTER controller code/dependency frames
have been consumed: network-order uint32 key length, ASCII key bytes, uint64
ciphertext length, exact encrypted archive bytes, then EOF. Key is bounded1..1024,
ciphertext is bounded512MiB, and the original fixed ARM archive SHA is compiled
in. Short frames, extra trailing bytes, wrong SHA, invalid keys, authentication
and source failures refuse. No key is written to disk; ciphertext alone is staged
0600 in an invocation-private0700 directory. The prefix matches the existing
`woowbk-arm-cold-private-*` postflight cleanup family. Only its own staging is
removed. There is no generic directory discovery or removal.

The subcase invokes `capture_owner_source`, hence actual `Capture.source_only`,
product selection, native HOCON, native cold-history decoder, strict tar EOF/
finish, bounded256MiB private spool and source_binding final consistency checks.
It does not hand-walk tar or use the historical inventory loop as a replacement
consumer. Actual cold receipts must remain28 files/57502B/final_state=False;
the source consumer still requires exactly one schema and rejects unknown
selected files or unsupported configuration. Source cookie remains NEVER_READ.

No target document is manufactured or supplied. The registry must still refuse
summary as incomplete; an unexpectedly sealed registry is an error. No source
values, replay callback or private binding are returned by this subcase.
After source-context and encrypted-staging cleanup, the callable
`consume_source_frame(stream, staging_parent=...)` returns only static scope:
source-only-registration, registry unsealed, source/target completeness
not-assessed, full_scan/restore not-performed. This static receipt is NOT
full-registry scan evidence and should not be published as such. The CLI ignores
it and emits no receipt, avoiding output collisions with short private values.

Exit codes:

- 0: source-only registration plus cleanup succeeded; no full scan/restore,
  complete target inventory or commercial HA acceptance is asserted.
- 1: realm, frame, authentication, Capture, native, inventory, timeout,
  cancellation or cleanup failed. No raw errors or values are printed.
- 2: missing/unknown mode or extra CLI options; stdin is not read.

## Main-owned integration points (not modified here)

The existing transfer git-archive list already carries consumer/native/script
modules. Add these TWO files to its explicit archive list:

- `tests/e2e/lab/emqx_arm_source_owner.py`
- `tests/e2e/lab/emqx_owner_source_capture.py`

After its existing code/dependency bootstrap has read a reviewed new source-mode
byte, dispatch in that same private process, before consuming the key frame:

```python
from emqx_arm_source_owner import main
raise SystemExit(main(['--source']))
```

Do not route the new mode to the previous cold-history hand loop. Keep the
controller's existing owner locks/isolation/resource checks, RAM-only key loading,
fixed encrypted archive SHA transfer, child status and mandatory postflight.
No new host credential lookup, fake target JSON or public guard change is needed.
Only the main owner should wire the mode byte and actually execute after handoff.

## Generated integration validation

37 tests passed with:

```sh
PYTHONPATH=backup-engine:tests/e2e/lab python3 -m unittest \
  test_emqx_arm_source_owner test_emqx_owner_source_capture \
  test_emqx_source_cold_capture test_emqx_source_consumer \
  test_emqx_private_spool -q
```

Eight new tests exercise real generated SecureTar v3 decryption, source_binding,
actual Capture and private disk cleanup with generated native contracts at the
adapter boundary. They cover silent unsealed success, bounded/truncated/trailing
frames, fixed-SHA refusal before Capture, wrong-key authentication, late decoder
failure, fixed inventory mismatch, cancellation, CLI status and realm/mode gates.
They do not execute Erlang/Podman, access real archives or duplicate main's actual
native suite. A real ARM `--source` result remains unassessed.
