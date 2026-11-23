Provider-bound generated ACL path proof (replaces the earlier raw-path guess)

Candidate-only, same fixed emqx-new role and invocation-owned DATA_TARGET volume.
No original target admission/public guard/count/schema registry changes.

Primary pinned source a8319fe:
* emqx_authz_file.erl read_files exports rules; write_files writes those rules and
  puts acl_conf_file() into raw path. acl_conf_file uses filename:join of actual
  emqx:data_dir() plus authz/acl.conf.
* emqx.erl:290-291 emqx:data_dir is application env default "data"; absolute raw
  node.data_dir is not assumed by this patch.
* emqx_utils_json.erl:126-127 recursively encodes lists, explaining ASCII arrays.
* emqx_authz.erl:656-665 uses emqx_conf:update([authorization],map,override_to=cluster).

The SAME fixed native query reads actual raw node.data_dir, app data_dir, provider
acl_conf_file(), cwd and complete raw-config DIGEST. It resolves all using actual
cwd, requiring canonical/no-traversal /opt/emqx/data and generated ACL exactly
/opt/emqx/data/authz/acl.conf. Every parent is no-follow directory; generated file
is regular/single-link. Descriptor identity must match pre/post no-follow metadata,
full bounded read (64KiB) must reach EOF, file/parent identities and content digest
must be stable. Node/start-time binding excludes a replaced/restarted broker.
The product role/mount is its preexisting invocation-created emqx-new volume;
this helper neither discovers nor selects any host filesystem/container.

No complete raw config or file content is emitted by the new query. The existing
read_effective_config privately retains SHA256 of its exact native JSON bytes;
proof compares native encoded-config digest to that value, with no Python JSON
reencoding assumptions. Private sidecar contains only bounded path metadata,
identities and digests (16KiB wire bound,10s). Never publish these receipts.

An opaque WeakKey receipt binds candidate object, exact captured config, provider
path, native runtime and file state. Caller JSON flags/receipts are not admitted.
Only an ASCII int-not-bool list exactly equal to the actually observed provider
path can pass imported-only. Raw data_dir and path representations stay unchanged.
No missing defaults, guessed relative spelling or config path rewrite is used.

The fixed VM-side disable observes/compares file state inside its update, changes
only raw builtin enable=false and returns metadata/digests. Complete expected raw
intermediate readback and ACL row/schema receipts remain mandatory. Provider path
proof is rechecked after-disable and after-final restore (including exact final
raw-config digest). Original target settings still load normally and remain exact.
The original final STRICT/count gates and all three complete ACL receipts remain.

Native refusal stages are allowlisted: release/clean/cwd/raw_root/app_root/
provider_root/parents/file/read/stable/config_digest/disable/native. Host stages
are digest/binding/state/wire. All feed existing product stage diagnostics without
raw terms, paths, values or counts. Unknown native reason maps to native.

Host-only tests model actual transport and fixed query replies. They are not
native execution proof. This increment has run NO lab/native/container operation;
main must verify actual syntax/runtime/schema/filesystem compatibility. The full
raw-config sidecar proposal was rejected by automatic tool approval as sensitive
data egress; it was not executed. This metadata+digest-only design removes that
extra egress and does not retry or indirectly execute the rejected design.
