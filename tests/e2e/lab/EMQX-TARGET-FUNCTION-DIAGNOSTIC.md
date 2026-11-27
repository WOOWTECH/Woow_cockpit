One-shot fresh synthetic config-function diagnostic, base main 9e48d0e

This increment changes diagnostics only; no function serialization is broadened.
Main owner_target.py, its newer fixed consumer phases and file guard are untouched.
Only rejected config functions receive extra diagnostics. No observed fun, loader,
unwrap function or callback is executed. env output is primitive type only (empty,
binary, atom, integer, float, tuple, list, map, function, pid, reference, port, other,
multiple); no env values, sizes, paths, dynamic keys, hashes or rendered terms.

Public code identity is exposed only when the module is one of seven fixed pinned
public modules, the on-image BEAM MD5 AND loaded module MD5 equal the fixed expected
hash, the local fun new_uniq equals that hash, and name/arity occurs in public BEAM
symbols (local captured arity included). External fun names must be exported and
env empty. The companion static public symbol catalogue validates output again in
Python. It was generated solely from the local cached pinned image's public BEAMs.
Unloaded/unrecognized/modified module or unverified name remains unknown. No custom
names or computed hashes are published. This is a limited diagnostic catalogue,
not authority to execute or accept these functions.

Path output uses fixed schema categories only. Dynamic file handler names and
unrecognized keys become a fixed category, never raw strings. Profiles distinguish
public code, exact named secret wrap candidate (identity/env refusal), loader
refusal, and unverified identity. A candidate name alone never authorizes capture.
Original unsupported_function refusal remains; no stateless function support has
been added before actual evidence. Successful recognized wrappers produce no
extra diagnostic frame. Extra frame is accepted only together with the fixed
serialize_config/unsupported_function failure. Unknown/extra/duplicate/forged
fields or public name/hash mismatch refuse diagnostic parsing.

Local synthetic public fixtures: 28 existing targeted tests and two new native
metadata/parser tests pass, zero skips. Native adversarial closure has a private
synthetic env and dynamic path; neither appears in diagnostic bytes and the closure
is never invoked. Public local secret wrappers and exported schema identity are
validated against the BEAM catalogue. Private identity/env payload negatives refuse.
Fixed expression parsed in local cached pinned runtime. No core/public guard change.

Actual one-shot attempt10 on committed 9d661e2 completed (exit 1):
serialize_config/unsupported_function, consumer wire. Fixed function diagnostic:
path listeners, external type, EMPTY env. Public identity remained UNVERIFIED:
module/name/arity/md5 unknown. This does not establish which callback it is, nor
whether the cause is an uncatalogued module, mismatched/unloaded public code or
an unexported external reference. In particular, it does not prove a log callback,
a secret wrapper or any particular listener callback. Do not infer identity from
the empty environment. No functional serializer support is authorized by this
result; current refusal stays. Further identity diagnosis requires a subsequent
owner-controlled test with a broader pinned-public diagnostic catalogue or more
specific fixed listener path categories, not arbitrary function execution.

Actual ticker identity/status before and after, no clients before and after,
expression parse, broker/client/private-files cleanup all passed. Final outer
postflight network none, ports empty, owned containers/volumes zero. No active
invocation or held locks remained. Ownership explicitly returned to main; no
second lab attempt. Original local private stdout/stderr retained in /tmp,
fixed public reports preserved as attempt10-fixed-function.json/jsonl.
