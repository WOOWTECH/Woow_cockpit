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
