Target vendor policy handoff

Base: 6cfaa6d. Requires Bernoulli's emqx_owner_vendor_files.py (separate commit).
No lab operations or real vendor-key reads were performed for this increment.

The owner binds vendor_observer to the same broker/container and private eval /
inspect transport. owner_target_readers holds quiescence, enters observer before
native capture, carries the same Values through complete config/provider/schema/
row decoding, and holds observation through consumer use. Lease exit repeats the
complete helper observation and requires identical receipts. Helper failures never
produce authorized readers. Callers must only accept results after context exit.

Allowed leaves are exactly listeners.{ssl,wss}.default.ssl_options.
{certfile,keyfile,cacertfile}, with listener enable atom false and exact
${EMQX_ETC_DIR}/certs/{cert.pem,key.pem,cacert.pem} literals. No other path,
active listener, file authorizer, or reference gets an exemption. Existing generic
name validators, unknownref and secret schema rules remain unchanged.

Content authority is the fixed immutable IMAGE in emqx_native_runtime, not a
caller-supplied expected hash: helper compares actual bytes to image bytes, checks
container/mount/file identity, registers full bytes and PEM representations in
Values, and returns per-file hash/identity receipts. The lease adapter consumes
that trusted helper API; receipt JSON alone cannot establish observation.

32 synthetic and existing regression tests passed; shell syntax passed. Synthetic
observer fixtures prove path restrictions, registry scanner inclusion, lease
ordering and changed post-receipt refusal. They do not prove native caller success.
Main must integrate the helper commit and test its rootless-crun image baseline
runner in the dev-d wrapper context before claiming actual acceptance. Packaging
now includes policy/helper/native runner. This branch does not copy the worker's
helper or change source/file-authorizer policy.

Policy-session automatic approval rejected a probe extracting/persisting the
pinned image TLS private key. That probe was not executed or retried. Actual
key-containing observation remains unexecuted here; explicit authorization must
resolve that boundary before such a test in this session.

Bounded callback followup: actual vendor eval/inspect now use LabOwnerRunner,
not runtime_live.podman. Eval has timeout=10/max_output=helper MAX_WIRE;
inspect timeout=5/max_output=helper LIMIT. Product runner enforces stdout bounds
while draining pipes, bounded stderr tail, and process-group kill/reap on abort.
Runner initialization is lazy inside the held observation, retaining existing
host/uid/rootless owner checks. Adapter owner/fixture/provision modules are bundled.
Native core private_checked is unchanged. 36 tests passed, including local
synthetic overflow and timeout/fork-child cleanup tests; no lab was run.

Receipt followup: cross-lease comparison uses path/image/container_id/bytes/
sha256/target_identity. Image-side identity is validated within each helper read
but can change across ephemeral baseline sidecars. Synthetic image-inode change
passes; target-inode and content-hash changes refuse. No mount check removed.
Reference diagnostics now recognize fixed check_origins/origins/responder_url
keys and WS/TCP enable contexts; URL policy remains unchanged. Public pinned
emqx_schema.erl defines check_origins default at lines 953-958, but this change
does not infer actual cooked shape or waive unknown URLs. 38 tests passed.

Exact inactive websocket-origin profile (code-only): pinned v5.8.9
apps/emqx/src/emqx_schema.erl lines 936-959 defines check_origin_enable=false
and check_origins comma_separated_binary default
http://localhost:18083, http://127.0.0.1:18083. Lines 2759-2760 split tokens and
convert each to binary. emqx_ws_connection.erl lines 266-284 compare inbound
Origin with lists:member only when check_origin_enable=true; false returns ok.
No outbound fetch or userinfo interpretation occurs in that implementation.

Policy requires exact listeners.{ws,wss}.default.websocket.check_origins path,
exact ordered two-binary default list, listener enable=false and
check_origin_enable=false. No other URLs/listeners/custom lists qualify. Values
are decoded and registered before this policy; scanner tests still reject both
origin strings in public payload. 40 synthetic/regression tests passed. Actual
cooked target profile match remains unexecuted; main's fixed diagnostic can
confirm whether this public default is the observed next refusal.

Active bootstrap extension: pinned emqx_authn_mnesia_schema.erl:76-90 defines
${EMQX_ETC_DIR}/auth-built-in-db-bootstrap.csv and plain type default.
emqx_authn_mnesia.erl:556-579 expands that path, reads whole file and calls
import_users with override=false. This is an active startup dependency, not an
inactive exemption. Main's fixed public-image presence probe proved REGULAR.

Policy now requests the fixed bootstrap file plus three TLS files. Requires
Bernoulli helper extension: regular nonempty bounded whole CSV with EOF,
pinned-image/actual-byte equality, full CSV parse and every cell registered in
same Values, original parent/mount/identity checks unchanged. Existing receipt
shape applies. Accept only authentication[0].bootstrap_file with exact literal,
single enabled password_based/built_in_database username auth and plain type.
No rewrite of config, no fake absence, no API hash/plaintext substitution.
Custom/hash/mounted dependencies remain unsupported by this narrow increment.
Helper without this fixed path extension will refuse, never silently waive it.
43 synthetic/regression tests passed, including whole CSV/cell private companion
scan and missing/empty receipt refusal. Native helper extension and actual target
caller remain unexecuted in this worktree. No lab commands were issued.

Vendor ACL increment: REFERENCES now contains five fixed files (TLS three, auth
bootstrap CSV, vendor ACL). Existing helper actual/pinned full ACL byte comparison
and complete literal-term EOF/all-leaf registration remain mandatory. Receipt
validation accepts the fixed ACL path; lease recheck still compares target file
identity/content. No mount exception is added.

The file-authorizer object guard only permits config.authorization.sources[i]
when the very same object is bound at that index, type=file, enable is a decoded
typed true/false atom, and explicit path is exactly ${EMQX_ETC_DIR}/acl.conf or
/opt/emqx/etc/acl.conf. Native string charlist and binary representations of the
same literals are supported. Scalar/charlist path permission repeats the same
root/object guard. All other fields recurse normally; unknown refs still refuse.
Implicit path/custom mount/other roots/no receipt/no policy all retain refusal.
No sources are deleted or rewritten. Public emqx_authz_file_schema fields(file)
requires path; emqx_authz_file reads complete rules with file:consult and uses
explicit path. 46 tests passed, synthetic helper provenance only in this worktree;
main actual target18 already proved bootstrap capture, not this new ACL caller.

Batched reference diagnostics: refusal now includes consumer_fixed_references,
a sorted deduplicated bounded set of {reason,root,key,context}, plus fixed
consumer_fixed_references_truncated boolean. Original first failure/reference
remains unchanged. Max 128 distinct classifications; traversal continues on
truncation and never authorizes anything. No dynamic names, paths, values,
backend aliases or counts are emitted. Approved policy leaves are excluded.

All 44 root names were extracted from the cached immutable image using only
hocon_schema:roots(emqx_conf_schema) public metadata, then frozen as enums. A
native offline fixture verifies exact catalog equality (50 total tests passed).
Known fixed directory/root keys and fixed root enable/builtin-storage contexts
were added. Unknown roots/keys stay other_root/other_key. This increment adds no
output-directory/inactive profile before actual classification. No lab used.
