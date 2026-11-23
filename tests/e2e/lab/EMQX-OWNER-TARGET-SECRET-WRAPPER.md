Config-only secret wrapper increment, base main c45b9f2

Main attempt8 actual schema/folds/ticker passed but serialize_config refused
unsupported_function. That evidence does not identify the actual closure: the
next actual test must confirm whether it fits this restricted supported profile.
No broker/dev-d/owner wrapper operation performed here. Main retains ownership.

Public pinned constructor:
https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx/src/emqx_secret.erl
wrap(Term) captures Term and returns it. unwrap/1 executes arbitrary closures;
term/1 accepts all emqx_secret funs and takes last(env). Neither is used here.
wrap_load/1 is a different constructor whose body invokes the loader, so it is
explicitly unsupported. No file/environment loader reads occur.

Local cached pinned image synthetic constructor probe measured module/name/arity/
type/index/new_index/uniq/new_uniq and module MD5. Exact profile is recorded in
public-secret-wrapper-profile.json. Native policy compares the complete fixed
identity tuple including new_uniq, then inspects env inertly with fun_info only.
Only a single bounded binary environment is supported. Other funs, same-arity
closures, external funs, nested wrapped funs, structured/PID/ref env, loader funs,
more than 128 wrappers, oversized values/depth remain refused. A changed BEAM hash
refuses; ARM image compatibility is untested. No arbitrary closure is invoked.

Capability is ONLY ConfigSecrets(Before/After,...), never generic Typed.
Rows/schema/provider still use Typed and reject every fun, including known secret
wrappers. Full cooked defaults/maps/keys/lists/tuples remain traversed. Binary
secret values replace only recognized closures; raw HOCON is not substituted.
Raw Before==After cooked config receipt remains; normalized full config + complete
wrapper provenance gets a second pre/post fingerprint comparison. All old schema,
fold/count/ticker/generation/provider/metadata guards remain.

Explicit private envelope emqx-owner-live-target-v2 adds config_secret_wrappers,
whose typed entries contain full singleton binary env, path, and every validated
code identity field. Runtime creator PID is not a persistent secret constructor
attribute and is not serialized. No claim of full VM-handle metadata coverage.
The config field is the complete cooked data tree with known wrappers normalized;
it is not claimed byte-for-byte identical to the original function-bearing term.
Consumer accepts exact v1 legacy or exact v2 key sets; v2 requires provenance,
strict metadata identity/env bounds, unique paths and exact env-to-config binding.
Every provenance leaf is decoded into private Values and full-scanned alongside
all config/provider/schema/rows. Secret registry schema, unknownref rules, public
evidence guard and file-type guard are unchanged. Existing core consumer receives
only additive v2 handling, retaining main 668d112 corrections; old core tests intact.

Validation: 27 targeted tests PASS, zero skips, including local cached pinned
constructor/adversarial native fixture and entire expression parse, generated
native metadata -> Python consumer -> five exact readers/private leak scans,
provenance mismatch/unknown/missing/duplicate negatives, canonical/storage fixtures
and prior file-type/unknown-ref cases. Fixtures use synthetic literals only.
Limits: actual function in attempt8 not inspected, no live broker/full target
acceptance or ARM wrapper-profile claim. Unsupported wrappers must keep refusing.
