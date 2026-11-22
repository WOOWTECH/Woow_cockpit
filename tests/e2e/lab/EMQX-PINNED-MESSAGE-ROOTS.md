# Pinned message fields in exact owner template contexts

Functional increment based on43687d8. Main observed the real source payload
UNKNOWN_ROOT; this worktree has not inspected real payloads or operated lab.
The existing explicit source profiles now collect additional PROVEN public
EMQX5.8.9 message field accessors instead of rejecting them as unknown roots.
This is configuration value collection, not rendering, message delivery,
source completeness, full scan, target coverage or restore acceptance.

New exact scalar/accessor names:

- id, peerhost, peername, publish_received_at, event, timestamp, node
- metadata.rule_id (exact accessor only)

Allowed dotted map-accessor roots:

- payload (existing), flags, headers, pub_props, client_attrs

Existing topic/clientid/username/qos/retain/flags.retain permissions are retained.
Map paths still use the same conservative ASCII dotted grammar and MAX_DEPTH;
quoted/bracket/function/fallback/loader forms do not gain permission. No
arbitrary scalar children are accepted. metadata.unknown and timestamp.secret
refuse FIELD_CONTRACT; arbitrary roots/aliases refuse UNKNOWN_ROOT. The latter
is still a fixed public classification, never a raw token/name dump.

Public proof (cached source tag v5.8.9 and actual immutable native image):

- emqx_rule_events:eventmsg_publish/1 constructs id/clientid/username/payload,
  peerhost/peername/topic/qos/flags/pub_props/publish_received_at/client_attrs.
- with_basic_columns/3 adds event/timestamp/node. eventmsg_publish also returns
  action environment #{headers => Headers}; on_message_publish documents it.
- emqx_rule_runtime:apply_rule/3 adds metadata.rule_id through add_metadata/2.
- emqx_rule_actions:parse_payload uses emqx_template:parse. Accessors are pure
  data lookups through emqx_jsonish; this producer never invokes rendering.

The native test constructs only a generated in-memory message and calls the
actual eventmsg_publish function. It asserts its EXACT15-key column set plus
headers environment, checks runtime beam abstract code for metadata/rule_id,
and passes every new accessor through the actual republish preprocessor and
placeholder parser. Only a fixed proof result is output; no generated event
values, node names or timestamps are published. No broker starts and no HTTP,
MQTT, host environment, filesystem dependency or external service is queried.

Permission is still limited to the original native action/connector contexts
already selected by the digest-verified owner profile. Keys, outside strings,
headers as configuration TEMPLATE locations, unknown functions/actions and
unbound historical occurrences cannot borrow permission. The complete native
multiplicity ledger and original/effective/overridden/concat value registration
remain unchanged. Default strict HOCON still rejects these references. File,
env, vault and include roots remain refused; a field called headers is message
DATA, not an OS/environment/file resolver.

Standard field availability after SQL selection is not asserted: this is a
nonrendering literal collector and does not prove a rule's runtime output.
No SQL alias is inferred or enabled. Additional aliases require a separately
bound native SQL AST contract with no function evaluation/code execution.
Unknown aliases remain fail-closed even if they look like field identifiers.
No fixture names or unobserved private source tokens are assumed.

The actual source Capture regression uses a generated encrypted archive and
real source_binding/authentication/full EOF/native HOCON/context reader/
capability verification/registry registration. Only generated cold decoding
and vendor observation are test doubles. It verifies the new literals and
fragments are registered, target categories remain missing, seal/summary/scan
remain refused, and private spool is empty afterward. No target docs are faked.
All existing source digest/arch/receipt/capacity/public guards remain in place.
The existing bundle already includes the changed helper; no flag or module
addition is needed. Main can run the SAME source HTTP profile with --diagnose.

Validation (PYTHONPATH=tests/e2e/lab:backup-engine:.):

- python3 -m unittest test_emqx_message_roots -q: initial3 tests passed in6.639s
  (positive/negative collection, native context/default refusal, pinned native
  event schema and republish preprocessor).
- Actual-owner test plus test_emqx_republish_templates, the payload grammar
  reference-negative test and test_emqx_source_phases:16 tests passed in7.143s.
- After tightening standard scalar-child diagnosis, the focused accessor test
  passed again. git diff --check passed.

These are generated/public implementation tests. Main owns all real source/lab
execution and must retain any later failure rather than infer success here.
