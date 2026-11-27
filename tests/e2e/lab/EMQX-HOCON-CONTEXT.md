# Owner-only original-syntax HOCON collection

This is code plus generated/public-image validation, not real ARM acceptance,
full scan, final-state reconstruction or restore approval. No lab or real archive
was used for these tests. The source-only registry remains unsealed until actual
owner-observed target documents are supplied. No target documents are invented.

The new explicit profile is
`owner-pinned-image-vendor-acl-republish-context-v1`; the immutable product image
must equal `emqx_native_runtime.IMAGE`. `capture_owner_source` selects
`native_hocon_context` only inside the verified source_binding digest context.
Actual Capture still performs authenticated full-finish product selection and
registers HOCON, addon and native historical values in source-options.

Fixed framed transfer/owner modes are `--source-vendor-acl-republish` (ARM/Y)
and `--x86-source-vendor-acl-republish` (x86/Z). They add no path, digest, key,
image or profile overrides. Existing strict and vendor-only modes are unchanged.
ARM still requires 28 files/57502 bytes; x86 keeps its bounded historical receipt
contract and exact expanded-size profile. The transfer bundle includes the new
native script, occurrence validator and effective rule helper. CLI source status
remains silent and its receipt explicitly excludes full scan/restore.

The separate native adapter emits `emqx-hocon-context-json-v1` with the original
input hash/length, disabled resolution, empty references, complete effective
map, unchanged complete raw syntax_strings, concat_strings (including subsequently overridden scalar concatenations), and string_bindings entries
`{path, role, value}`. It walks the ORIGINAL boxed AST, before expand, concat or
transform, so duplicate and overridden occurrences survive. Dotted keypath
segments and quoted literal keys stay distinct; arrays use zero-based indices.
Existing lexical and AST include/variable/file-key gates remain in force.

A republish role requires one direct, singleton string function=republish in the
same original action object. Duplicate/ambiguous function declarations do not
grant permission. Only payload/topic/qos/retain at the exact builtin action
argument path qualify. A vendor-path role requires the same original file-source
object at authorization.sources[index], and its path must equal the fixed vendor
literal. Arbitrary template variables/contexts/functions still refuse. Nothing
is rendered or resolved against messages, environment, filesystem or vault.

The Python reader consumes EVERY binding and checks a multiplicity ledger
against ALL raw syntax strings, including keys and overrides. Every occurrence
must pass independently; matching another allowed string grants no permission.
The effective rule subtree also passes the conservative republish helper.
All raw syntax and effective strings, keys, historical strings, template fragments
and full vendor file bytes remain registered privately. Non-template concat
components plus every supported concatenated string result are retained, even
when a later declaration overrides that result. These results are computed by
the pinned public concat/transform pipeline on each original scalar node and
validated separately with strict string gates. Multi-component
concat containing a dollar is deliberately refused, including split references;
there is no fallback. Ambiguous object/array concatenations with templates are
also refused. This conservative subset may still refuse the real source.

Bounds remain input8MiB, tokens32768, native semantic depth32, bindings8192,
output1MiB, plus existing Python Values limits and native process limits. No
bound was increased. Default strict v1 script and reader semantics are unchanged.
OwnerFileRefused fixed diagnostics remain intact; no native JSON/value/log is
published.

Validation (PYTHONPATH=tests/e2e/lab:backup-engine:.):

- `python3 -m unittest tests/e2e/lab/test_emqx_hocon_context_native.py -q`:
  first five native tests passed; the subsequently added sixth test passed by
  its individual unittest selector. Generated AST cases cover dotted keys,
  arrays, overwritten values/actions, concat, quoted-key spoof, duplicate or
  missing bindings, wrong roles/paths, unknown action/env/file/vault references.
- The generated encrypted owner integration runs actual source_binding,
  decryption/full EOF, Capture, native syntax and registry registration. Only
  the generated cold decoder and vendor observation are test doubles. No empty
  target document is supplied; seal/summary/scan remain refused, spool is empty.
- `python3 -m unittest test_emqx_source_profiles test_emqx_source_transfer
  test_emqx_owner_file_hocon test_emqx_owner_source_capture
  test_emqx_republish_templates -q`: 30 tests passed. Transfer tests use generated
  frames and a fake child, never invoke lab, and check both new fixed modes and
  complete bundle, no stdout secret/key env/argv, wrong digest and changed stamp.
- `python3 -m unittest test_emqx_arm_source_owner -q`: 13 generated framing,
  authentication, inventory, cancellation, silent-status and cleanup tests passed.

Mixed rule-engine configurations are retained. Literal HTTP action IDs use a
separate native `action-reference` role at the exact actions[index] path. Every
historical reference must bind to actions.http.<id>.connector and a nonempty
connectors.http.<connector> object in the same parsed native document; the
full effective helper also checks that binding. Unknown types/unbound IDs and
executable functions refuse. This is private configuration collection, not HTTP
execution or proof of connectivity. Other roots still pass the complete generic
walk and syntax ledger; none is dropped to make republish pass.

Needed but intentionally unsupported: message templates under
`actions.http.<id>.parameters.body`, other HTTP fields, other configured action
types, custom functions, selected SQL alias variables, ambiguous declarations
and split template concatenations. HTTP body `${payload}` explicitly refuses
before vendor IO. A separate exact context profile needs evidence before any
such permission is added.

Additional native validation: the seventh test (mixed HTTP/republish) passed
with four negative controls. After adding historical concat-result collection,
the dotted/concat test, authenticated owner integration and ledger-tampering
test were rerun and passed. After adding bound HTTP literal references,
25 affected helper/vendor/owner regression tests passed. No real source results
are claimed by any generated test.
