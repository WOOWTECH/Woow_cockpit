Imported-only exact vendor ACL path preservation

Primary pinned source a8319fe:
* apps/emqx_auth/src/emqx_authz/emqx_authz_schema.erl:257-262 default_authz
  declares exact ${EMQX_ETC_DIR}/acl.conf (NOT etc/acl.conf as schema default).
* apps/emqx_auth/src/emqx_authz/sources/emqx_authz_file.erl:84-90,116-117:
  filename performs naive_env_interpolation; validate calls file:consult on the
  resulting path. Relative names retain process-CWD semantics.
* rebar.config.erl:501 installs apps/emqx_auth/etc/acl.conf as etc/acl.conf.
* Dockerfile.ubuntu20.04.runner:15 has WORKDIR /opt/emqx, but is expressly a test
  runner Dockerfile: not independent proof of the actual immutable image's cwd.
* Existing public native evidence emqx-public-vendor-acl-20261122.json proves the
  pinned image has the fixed vendor file at /opt/emqx/etc/acl.conf; it does not
  prove a particular failed capture's raw path string or add a new cwd receipt.

Only disabled_intermediate's IMPORTED side accepts the two exact strings above.
It preserves the existing imported config literally, changes only builtin enable,
and uses the SAME invocation candidate/process/environment/working directory.
No path resolution, equivalence assertion, default insertion, host/broker file
read, or mount/observer waiver is added. The broker has already performed its
import before this step; this is retention of a fixed existing source reference,
not admission of a new target file. Actual native reload validation still must
succeed; complete raw intermediate and final target readbacks remain mandatory.

Original target paths do not gain either exception. Existing target references,
mount gates, final explicit policy, native row/schema receipts, counts and public
guards remain unchanged. Unknown variables, other relative names, traversal,
controls, URIs and noncanonical absolute paths refuse with fixed path classes.
No path values appear in diagnostics. Absolute ordinary paths retain the old
profile, with canonical/control checks tightened.

Host-only entry tests verify both literals stay exact through the first load,
only enable changes, final target paths/settings are exact, and rows/digests are
retained. Negative tests cover target-side aliases and unknown/malformed paths.
No lab/native execution; main's actual candidate must establish which literal
was involved and verify compatibility. No immutable-image cwd proof is claimed.
