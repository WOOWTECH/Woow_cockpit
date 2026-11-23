# Explicit source HTTP body context

This adds a separate owner opt-in, not permission for HTTP/network execution,
real ARM acceptance, a complete scan or restore. The default strict and v1
republish context profiles still refuse HTTP body message templates.

Profile: `owner-pinned-image-vendor-acl-http-body-context-v1`.
Fixed transfer/owner flags: `--source-vendor-acl-http-body` (ARM/H) and
`--x86-source-vendor-acl-http-body` (x86/J). Existing archive/digest/arch and
capacity policy are inherited without overrides; ARM28/57502 remains enforced.
The 3420042 capture capability bridge and its bundled emqx_captured_candidate
module are retained. No new runtime dependency module is added to the bundle.

Inside actual capture_owner_source, only after archive digest binding succeeds,
the fixed profile plus immutable image select native_hocon_http_context. Actual
Capture still authenticates/full-finishes, product-selects and registers source
values. Source-only registration does not supply target documents or seal the
registry. The existing fixed diagnostics, key RAM/stdin boundary, realm, alarm,
cleanup, source-stability checks and public guard are unchanged.

The new native envelope is `emqx-hocon-http-context-json-v1`. Its complete
original occurrence ledger has the same input SHA/length, syntax_strings,
string_bindings and concat_strings as v1. Only this explicit native mode may
emit `http-body-value`. An original action object at actions.http.<id> must have
exactly one direct singleton string connector declaration. That connector name
must be an ASCII identifier and bind to a nonempty configured HTTP connector.
Permission follows that ORIGINAL object into its parameters.body only; later
connector declarations, unknown locations or equal strings elsewhere grant no
permission. Every occurrence, key and override is still checked. Python checks
the full multiplicity ledger and effective action/connector binding too.

The effective map is used only to validate configured connector inventory; the
collector still walks the untouched original AST, before expansion/concat can
merge declarations. Its original strings include historical values. Supported
non-template scalar concat results, including overridden results, remain
registered. Split/multi-component template concatenations refuse with no
fallback. No values are dropped from other roots to admit HTTP body strings.

Pinned public EMQX5.8.9 HTTP connector source establishes this narrow semantic
basis: preprocess_request calls maybe_parse_template(body, Req), parse_template
calls emqx_template:parse, and render_template uses emqx_jsonish. Tests check the
actual cached image's beam abstract code for the first two calls and invoke only
the public parser. They do NOT invoke render_template, process_request or HTTP.
Source reference: apps/emqx_bridge_http/src/emqx_bridge_http_connector.erl at
public tag v5.8.9 (body parse lines765-772; formatter lines828-847).

The accepted placeholder subset deliberately matches the existing conservative
republish payload collector: payload dotted map access, topic, clientid,
username, qos, retain, flags.retain and whole-message `${.}`. Full strings,
fragments, placeholder tokens/accessor components and all ordinary config
strings stay private and registered. File/env/vault, includes, lexer variables,
unknown roots/functions and unsupported loader keys still refuse. HTTP headers,
URL/path/method templates and all other action types are outside this profile.
No message, environment, path, vault or secret is resolved; no bounds increase.

Generated validation covers mixed republish/HTTP configurations, exact native
context, old profile refusal, missing/duplicate/unknown connectors, headers,
wrong action type, key/value equality spoof, overwritten invalid declarations,
split concat and loader references. A generated framed encrypted fixture runs
actual source binding, authenticated EOF, Capture and the native adapter, then
checks private registry values, missing target acknowledgements, unsealed gate
and full staging/spool cleanup. Only generated cold decoding and vendor bytes
are test doubles; no target document is invented. Fixed transfer tests use fake
children and never touch lab; both HTTP flags are covered and the capture bridge
module is asserted present in the bundle.

Executed validation (generated data only, cached pinned host native helper):

- `PYTHONPATH=tests/e2e/lab:backup-engine:. python3 -m unittest
  test_emqx_http_context -q`: 5 tests passed in69.647s, including16 negative
  context/connector/header/loader cases, historical declaration checks and the
  actual framed source Capture test. The public native test verifies pinned
  HTTP body parser call sites from beam abstract code and parses placeholders;
  no formatter rendering/request is invoked.
- Same PYTHONPATH, `python3 -m unittest test_emqx_source_profiles
  test_emqx_source_transfer test_emqx_owner_file_hocon
  test_emqx_owner_source_capture test_emqx_arm_source_owner -q`:
  35 tests passed in7.590s. New ARM/x86 flag frames and complete bundle are
  checked with generated files/fake child only, not lab execution.
- Shared native v1 code regression: existing
  `test_emqx_hocon_context_native.NativeContextTests.test_dotted_arrays_overrides_concat_complete_original_ledger`
  passed in7.919s; dotted/array/override/concat retention and default strict
  refusal remain covered. No previously passed full lab suite was repeated.
