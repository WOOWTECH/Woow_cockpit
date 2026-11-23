Actual descriptor diagnosis and code-only inert TLS callback candidate

Lab ownership returned to main immediately after the single authorized attempt11.
No active invocation/child, both existing readonly locks released; cleanup checks
all passed, final network none/ports empty/owned containers and volumes zero.
No second lab attempt. Main core owner_target.py/phase6b04/file guard/tests unchanged.

Actual source f278ba6 refused serialize_config/unsupported_function, consumer wire.
Only code descriptor {module,name,arity,type} was hashed for external empty-env
functions, using SHA256(term_to_binary(...)); env and dynamic path values were not
hashed/printed. Fixed path category: ssl_default_user_lookup_fun. Actual hash:
DE702B30F75648B1435B584233503E51347F769A39B94DC5A2237781179633D6.

Offline fixed-image scan read ALL /opt/emqx/lib/*/ebin/*.beam export/MD5 metadata
and reached EOF. It never loaded or executed catalogue modules, called their
module_info, or triggered their on_load. Exactly one public export matched:
emqx_tls_psk:lookup/3, external; BEAM MD5 F2653DFD1072A73E2E6FEC1D77865D1F.
The immutable image's app directory is emqx-5.5.5 (internal application version);
broker release remains pinned 5.8.9. Matching uses image contents, not directory
name as release proof. The prior loaded-code seven-module catalogue did not prove
this identity; the offline full export match now does.

Public schema source supplies the exact default, not a guessed identity:
https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx/src/emqx_schema.erl
server SSL options default user_lookup_fun to emqx_tls_psk:lookup; its fixed
converter creates {fun Mod:Fun/3,undefined}. No such callback is executed here.
https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx/src/emqx_tls_psk.erl
lookup/3 normally resolves PSK via hooks. Capturing its identity does not capture
hook implementation behavior or claim a stateless runtime result. TLS must remain
disabled in this supported target profile, as enforced by the existing consumer.

CODE-ONLY functional candidate: ConfigSecrets recognizes ONLY exact external
emqx_tls_psk:lookup/3 with env=[] at listeners.ssl.default.ssl_options.user_lookup_fun
or listeners.wss.default.ssl_options.user_lookup_fun, tuple element zero. Both
are fixed public default callback sites. No custom listener name/path, other
identity/arity/type or captured env accepted. It reads the one fixed public BEAM
path, checks exact MD5 and export metadata, and checks loaded-code MD5 if already
loaded via a metadata BIF; it does not require the target module
loaded or load it itself. Missing/changed public BEAM still refuses.

The function leaf becomes an explicitly tagged owner_fixed_public_callback MAP,
not a string, plaintext secret, empty value or skipped field. It retains identity,
complete empty env, explicit profile, matching descriptor SHA256 and BEAM MD5.
Its tuple sibling state and full surrounding cooked config remain captured. The
main consumer's generic private typed-data decoder retains and scans ALL these
provenance leaves. No consumer/file/schema/unknownref relaxation is needed. This
is an inert description of a public function, not a claim the original cooked
term was data-only or that the callback's execution was observed.

Raw Before==After receipt remains unchanged; complete normalized config plus
wrapper/provenance pre/post hashes remain. Generic Typed still rejects ALL funs
in rows/schema/provider (including this callback). Other config funs still refuse.
Known secret wrapper support remains binary-only. Public evidence guard unchanged.

Validation: 34 targeted local tests PASS, zero skips: existing 30 + two inert TLS
native/generated-consumer tests + offline positive/negative full-export matching.
Native fixture asserts callback module stays UNLOADED, unknown/path/arity cases
refuse, generic Typed refuses the callback, private full scan detects provenance,
and TLS-enabled config still refuses. Full fixed expression parser exercised.
All fixtures use synthetic literals or public immutable BEAM metadata only.
Candidate has NOT run on a broker or ARM. Actual attempt11 predates the candidate
and remains a refusal; full target commercial acceptance is not claimed. Main can
run the next fresh target test after integrating this code-only candidate.
