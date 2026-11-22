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
