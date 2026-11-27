# Fixed syntax rejection reasons

Increment based on1a6a052. Both real architectures were reported by main as
HOCON_SYNTAX REFUSED; that alone does not identify a faulty or unsupported
context. This increment adds diagnosis, without a speculative acceptance fix.
No lab/dev-d, real source, native broker, credentials or public guard change.

Use the existing source transfer HTTP profile with --diagnose. The fixed
SOURCE HOCON_SYNTAX REFUSED line can now become one of these bounded phases:

- HOCON_SYNTAX_BINDINGS / SHAPE / MULTIPLICITY / BUDGET
- HOCON_SYNTAX_HTTP_BINDING / HTTP_TEMPLATE
- HOCON_SYNTAX_ACTION_REFERENCE
- HOCON_SYNTAX_REPUBLISH_CONTEXT / REPUBLISH_PAYLOAD / REPUBLISH_TOPIC /
  REPUBLISH_QOS / REPUBLISH_RETAIN
- HOCON_SYNTAX_VENDOR_PATH / KEY_LITERAL / VALUE_LITERAL
- HOCON_SYNTAX_CONCAT_SHAPE / CONCAT_LITERAL

Each name above uses the HOCON_SYNTAX_ prefix. No paths, original keys,
variable/function/action names, string values, counts, hashes, native JSON,
exception text or source labels are appended. Enum membership is enforced
through the syntax reader, OwnerFileRefused, SemanticRefused private attribute,
Capture and the final source CLI whitelist. Unknown reasons fall back to the
existing fixed generic refusal. The old vendor-only syntax reason is retained.

The original native AST/occurrence ledger, multiplicity checks, disabled
resolution, literal HTTP binding, exact template contexts, full registration,
concat restrictions and all existing bounds are unchanged. The HTTP binding
check was factored so its refusal can be distinguished from body template
validation; both old and new call sites run the same checks. No helper enables
an unbound context or substitutes fabricated target documents. The source
registry remains unsealed and the same cleanup runs before diagnostics.

Generated pinned-native regression tests establish that a valid mixed
HTTP/republish document still passes; a bad action/connector, missing occurrence,
wrong role/key, unsupported republish argument, disallowed placeholder and
string-valued qos produce distinct fixed reasons. These negative cases remain
REFUSED; none is asserted to be the observed real source cause. In particular,
no qos coercion or additional runtime placeholder context has been enabled.
A generated encrypted fixture with a deliberately failing adapter verifies the
full owner Capture -> cleanup -> new public phase propagation; this negative
adapter is explicitly a test double, not real native-source evidence.

Validation (PYTHONPATH=tests/e2e/lab:backup-engine:.):

- python3 -m unittest test_emqx_syntax_reasons -q: 4 tests passed in15.009s,
  using cached pinned public native helper with generated inputs only.
- python3 -m unittest test_emqx_source_phases test_emqx_owner_file_hocon
  test_emqx_semantic_readers -q: 24 tests passed in1.883s.
- git diff --check passed. No existing full native/lab suite was repeated.

Main must obtain the next real fixed reason before any source-specific context
change. This code does not establish actual source completeness, target
coverage, full scan or restore acceptance.
