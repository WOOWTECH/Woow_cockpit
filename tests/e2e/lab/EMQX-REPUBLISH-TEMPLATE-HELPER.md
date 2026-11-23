The effective helper below is now called by the separately opt-in complete native context reader; see [EMQX-HOCON-CONTEXT.md](EMQX-HOCON-CONTEXT.md). Its original standalone validation and limitations remain recorded below.

# Context-aware republish message values (helper only)

Base: immutable `f11dd76`. Actual source diagnostics establish rule_engine as
required, but not an actual action/function/variable. This helper therefore does
not enable or claim successful processing of the real source. It adds no mode,
reader default, resolver, native lexer change, target acknowledgement or seal.
All diagnostic, owner/transfer/controller and public guard files remain unchanged.

Public semantics were checked in locally cached v5.8.9 source and upstream:

- [emqx_rule_actions](https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx_rule_engine/src/emqx_rule_actions.erl):
  builtin republish preprocesses topic/payload with emqx_template, qos/retain as
  simple variables; rendering uses selected message bindings, not a host resolver.
- [emqx_template](https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx_utils/src/emqx_template.erl):
  placeholders are ASCII dotted accessors. The helper accepts a deliberately
  narrower subset, not an alternative HOCON parser or template evaluator.
- [republish schema](https://github.com/emqx/emqx/blob/v5.8.9/apps/emqx_rule_engine/src/emqx_rule_engine_schema.erl):
  republish is a specific builtin action. Qualified/custom functions are not
  admitted by this helper.

Actual pinned public-image preprocessing was independently exercised on generated
values using the existing authorized host native helper, image
sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b.
It parsed message placeholders only; no message was rendered/published, broker
started, real source/key read or dev-d operation performed. Native runner retains
networknone/read-only/lognone/image-volumeignore and invocation-owned cleanup.

## Private API

`emqx_republish_templates.collect_rule_engine_values(rule_engine, profile=PROFILE)`
takes the actual native parsed rule_engine subtree; caller retains its validated
native envelope and authentic source/context binding. PROFILE is exactly
`owner-rule-engine-republish-message-v1`. Missing/unknown profile refuses.

Only `rules.<nonempty-ruleid>.actions[index].args` with function exactly republish
can contain message templates, and only payload/topic/qos/retain fields. Unknown
functions refuse even without templates. Outside those exact locations, strict
scalar/reference/file-key checks remain; a similarly named field elsewhere gains
no exception. No bridge/custom action is inferred. Payload/topic must be strings;
qos is typed0..2 or a single whole-string message placeholder; retain is bool or
a single whole-string message placeholder. Literal prefixes or multiple variables
in qos/retain refuse, following simple-variable runtime semantics.

The conservative roots are payload (dotted map fields), topic, clientid, username,
qos, retain and flags.retain. Optional leading-dot spelling is accepted; whole
message `${.}` is accepted only for payload. Numeric map segments are data keys,
not an array-index implementation. Arbitrary SQL aliases, escapes, brackets,
functions, optional/fallback syntax, unknown roots, file/env/vault schemes and
all true HOCON include/substitution dependencies remain unsupported. There is no
IO, environment read, binding lookup, rendering, evaluation or reference loading.

Private Values retain full strings, literal fragments, full placeholder spelling,
accessor spelling/segments, keys and canonical numeric/bool/null literals. Shared
node/depth/value/total bounds remain. No short-value exemption is introduced.
The helper returns no Registry, scan/coverage capability, replay or source seal.

## Deliberate integration gate

This helper covers the EFFECTIVE rule_engine subtree. The current native
syntax_strings is a flat list without declaration locations. Do NOT permit a
syntax string merely because its value equals a template accepted elsewhere:
an overwritten out-of-context reference could share the same spelling. Complete
historical syntax must retain/prove actual declaration context before integrating
this into the full vendor source reader. Existing syntax/default/vendor gates
remain strict and tests explicitly confirm rejection. No unlocated overwritten
or concatenated syntax coverage is claimed by this helper; all such upstream
private syntax still needs collection and validation. Exact actual action and
variable classification also remains the main owner's responsibility.

## Verification

- 26 generated helper/vendor/semantic tests passed (8 new helper tests with many
  context/grammar/type/reference/bounds/default-strict negative controls).
- Two new authorized synthetic native tests passed: actual quoted HOCON message
  strings plus helper extraction, and pinned builtin republish preprocessing.
  True unquoted HOCON substitution/include remain refused. Only these new native
  cases were run, not the existing complete native suite.
- Native positive/helper case was rerun after tightening the unknown-action gate.
- No real ARM action/template acceptance, full-source scan, target completeness,
  restore or commercial HA runtime claim follows.
