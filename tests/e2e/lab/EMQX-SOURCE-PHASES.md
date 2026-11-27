# Fixed source-only phase diagnostics

Code-only delivery based on2e9e6e2. No lab, dev-d, real archive, real credentials,
public guard change, target acknowledgement, full scan or restore is performed.

The host transfer accepts one existing fixed source flag followed by the exact
`--diagnose` option, for example:

```
python3 tests/e2e/lab/emqx_arm_cold_transfer.py --source-vendor-acl-http-body --diagnose
python3 tests/e2e/lab/emqx_arm_cold_transfer.py --x86-source-vendor-acl-http-body --diagnose
```

These commands are for the main sole lab owner, NOT executed in this worktree.
The extra fixed frame prefix Q precedes the unchanged fixed source mode byte.
Only source modes accept this prefix; configuration/probe diagnostics refuse.
No path/hash/key/image overrides, key environment/argv, dependency discovery or
new module are introduced. All existing bundle modules including the verified
capture capability bridge remain included. Owner realm, deadline and controller
postflight behavior are retained.

Default source CLI remains silent with the existing return codes. Diagnostic
mode prints exactly one fixed line after consume_source_frame unwinds private
contexts: `SOURCE <PHASE> REFUSED`, or `SOURCE COMPLETE PASSED` on successful
source-only registration and cleanup. Failure remains exit1. Success is still
unsealed and not a full scan/restore. Realm refusal is `SOURCE REALM REFUSED`.
No exception text, paths, node names, source labels, values, counts, hashes,
private native JSON, replay, key bytes or broker output is printed.

The enum is bounded in emqx_private_boundary.SOURCE_PHASES; unknown phase
attributes become CAPTURE. SourcePhaseFailure preserves the original fixed
owner/frame private failure strings and adds only a sanitized phase attribute.
Cancellation remains refusal. Capture stores only a last fixed checkpoint;
this diagnoses the active boundary, not arbitrary underlying exception details
or proof that a later independent postflight has passed.

Boundaries include FRAME_PROFILE/KEY/ARCHIVE/DIGEST, BIND (archive binding),
PROFILE, SPOOL (including decrypt/authentication/full finish), TAR, SELECT,
ADDON_METADATA, HOCON_NATIVE, HOCON_CONTRACT, HOCON_SYNTAX/HOCON_WALK,
VENDOR_OBSERVER/RECEIPT, HOCON_REGISTER, COLD_INVENTORY/NATIVE/TYPED/FINISH,
REGISTER, BIND_FINISH (late source stamp), CAPABILITY, RECEIPT, ARCH, UNSEALED,
and CLEANUP. COMPLETE means only the existing successful source-only receipt.
No reader, format, coverage, capacity or reference gate is bypassed.

Previously read_hocon discarded OwnerFileRefused's bounded phase while wrapping
its exception. It now passes only five whitelisted structural phase names as a
private exception attribute, all other phases become contract. Exception string
and class at the semantic boundary remain the same generic SemanticRefused.
Capture distinguishes native parser failure before it returns from typed
contract failure after it returns; the same split exists for cold decoding.

Generated tests cover wrong digest/profile, native versus contract failure,
typed syntax, vendor observer, cold native versus typed receipt, registry
registration, late source binding, capability and cleanup failures. They verify
private spool removal, fixed error codes, unknown phase/error sanitization,
default silence, opt-in fixed-only stdout and the exact diagnostic frame prefix.
All fake native failures/keys/errors are generated and private; no native or lab
process is launched for this diagnostic implementation test.

During implementation, an initial regression exposed owner errors escaping the
frame's original fixed failure code; this was corrected while retaining the
phase. A second test exposed phase loss in read_hocon, leading to the bounded
attribute described above. These failures were not real source observations.

Final generated verification:

```
PYTHONPATH=tests/e2e/lab:backup-engine:. python3 -m unittest \
 test_emqx_source_phases test_emqx_owner_source_capture \
 test_emqx_arm_source_owner test_emqx_source_transfer \
 test_emqx_owner_file_hocon test_emqx_semantic_readers \
 test_emqx_source_cold_capture test_emqx_source_consumer -q
```

67 tests passed in10.290s; git diff --check passed. Bootstrap syntax is compiled
by the generated transfer diagnostic test. No previous native/lab suite was
rerun. These tests establish implementation boundaries, not actual ARM results.
