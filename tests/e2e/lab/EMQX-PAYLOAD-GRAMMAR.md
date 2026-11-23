# Fixed republish payload grammar diagnosis

Based on484a9fe. Main's actual source result is REPUBLISH_PAYLOAD REFUSED;
no original payload, placeholder name or generator definition was provided to
this worktree. Repository searches found B1 acceptance names but not its actual
generator definition. No source-specific acceptance change is justified yet.
No lab/dev-d/real archive/key/target/production data was used.

Pinned public EMQX5.8.9 emqx_rule_actions:parse_payload delegates nonempty payload
to emqx_template:parse; empty payload defaults to ${.}. The native public
preprocessor test confirms whole-context ${.} and JSON-embedded known fields
parse successfully WITHOUT rendering or invoking a broker. Generated native
HOCON -> complete occurrence ledger -> actual context reader likewise accepts
both. The collector already supported these cases; no new allowance is needed
for those forms. Unknown selected aliases/message roots are not inferred from
SQL or arbitrary names, and remain refused pending evidence.

This increment preserves the exact existing template acceptance predicates and
bounds, adding a fixed refusal reason only. The private TemplateRefused remains
SemanticRefused with the same generic error string; it contains no source value.
The original-syntax stage propagates its reason only for the exact declared
republish payload context. All HTTP/other template contexts retain their existing
fixed phases, permissions, multiplicity checks and full literal registration.

The sole owner can rerun the existing source command with --diagnose. Its fixed
phase can now be HOCON_SYNTAX_REPUBLISH_PAYLOAD_ followed by exactly one of:

- SIZE: full literal type/encoding/per-value bound rejected.
- BUDGET: private value registration/storage bound rejected.
- ESCAPE: unsupported escaped-dollar form.
- LOADER: forbidden file:/env:/vault: marker, case insensitive.
- GRAMMAR: placeholder does not match the current restricted public grammar.
- UNKNOWN_ROOT: syntactically supported accessor root outside the known subset.
- DEPTH: too many accessor segments.
- FIELD_CONTRACT: placeholder shape incompatible with the declared field.

No name, value, fragment, key/path, length, count, private JSON, source error or
hash is output. Unknown reasons are sanitized to a fixed grammar reason. Every
reason is included in the finite syntax and final source phase whitelists.
All bundle modules remain unchanged; the existing helper is already bundled.
Default strict source and v1 profile behavior remain unchanged. No `${}`,
selected aliases, loaders, extra contexts, escape forms or general references
have been enabled. Source-only registry stays unsealed with target docs absent.

Controlled observation needed: main should obtain the next fixed reason under
its sole lab ownership; no raw payload or private placeholder name is needed.
If UNKNOWN_ROOT, a separately bounded classification or public generator/SQL
contract will be needed before any additional variable context is accepted.
If GRAMMAR, its exact public parser form must be established first. Neither
reason authorizes bypassing a public/reference gate.

Generated validation (PYTHONPATH=tests/e2e/lab:backup-engine:.):

- python3 -m unittest test_emqx_payload_grammar test_emqx_syntax_reasons -q:
  6 tests passed in24.249s. Includes native positive whole-context/JSON payloads,
  unknown/malformed reference negatives, finite enum membership, native occurrence
  ledger and full owner source failure/cleanup propagation.
- python3 -m unittest test_emqx_republish_templates test_emqx_source_phases
  test_emqx_semantic_readers -q: 25 tests passed in2.537s.
- The added pinned public republish preprocessor test executes only
  pre_process_action_args/2 and placeholder parsing, never render/HTTP/MQTT.
  Its individual unittest selector passed in1.926s. git diff --check passed.
All runs used generated/public inputs only; no actual source acceptance or full
scan/restore result is claimed. No existing full native/lab suite was repeated.
