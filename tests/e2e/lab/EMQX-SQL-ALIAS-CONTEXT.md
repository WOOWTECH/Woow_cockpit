# Original-rule native SQL alias context

Functional code-only increment based onb01330f. No real source, lab/dev-d,
credentials, broker, SQL query/function evaluation, action execution or restore
is used here. Existing profiles remain unchanged and do NOT grant aliases.

Explicit fixed profile: owner-pinned-image-vendor-acl-sql-alias-context-v1.
Actual transfer/owner flags:

```
--source-vendor-acl-sql-aliases --diagnose
--x86-source-vendor-acl-sql-aliases --diagnose
```

ARM modeA / x86 modeB inherit the SAME compiled archive/SHA/arch/cold receipt
and capacity policies. Diagnostic prefixQ supports these modes. No paths,
credentials, hash/image/alias overrides are accepted. Owner digest verification
precedes selection of native_hocon_sql_context; that actual adapter runs inside
Capture and returns emqx-hocon-sql-context-json-v1. Source-only registration
remains unsealed without real target documents. No commercial/full scan/restore
acceptance is inferred from these generated tests.

The shared native HOCON script retains ALL original syntax_strings and their
complete occurrence ledger before expand/concat changes declaration structure.
Only the new fixed SQL mode calls emqx_rule_sqlparser:parse and select_fields;
these construct the pinned rulesql AST, never run a query or resolve functions.
The source strings are not rewritten. All original/overridden/concat SQL string
values still follow the existing full private registration path.

Alias authority requires ALL of these bindings:

1. One direct singleton SQL string in the SAME ORIGINAL rule object as the
   republish action subtree. Duplicate, split/concat and separate SQL/actions
   declarations grant no alias authority.
2. The original SQL must exactly equal the effective rule SQL. Different
   historical SQL cannot borrow the current rule's aliases.
3. Native selected AST fields must be pure known-field accessors, e.g.
   `{as,{path,[{key,payload},{key,temperature}]},{var,temperature}}` or
   `{as,{var,timestamp},{var,ts}}` (binary names in the actual AST).
4. Each granted template occurrence has its OWN zero-based binding index,
   rule_path, exact SQL SHA and alias->source-path witness. Effective alias maps
   do not bypass missing original occurrence authority.
5. Python validates every private witness: exact shape, unique valid index,
   exact republish argument path under the same rule, effective SQL digest,
   bounded alias identifiers/source paths and consistent rule alias maps.
   It then checks the full syntax multiplicity ledger and effective rule map.

The native witness is emitted only by the fixed digest-selected adapter. No
caller-supplied alias dictionary or path claim is accepted by the source owner.
Internal helper arguments are derived from validated native witnesses only.
Witnesses/SQL hashes/names are private and never diagnostic output. Alias names
and source-path components are additionally registered as private semantic
values, along with original SQL and template strings/fragments/tokens.

Allowed alias sources use the previously proven pinned message scalar fields
or payload/flags/headers/pub_props/client_attrs dotted data paths; exact
metadata.rule_id is allowed. Alias suffix lookup is permitted only for map-path
sources, with the SAME combined16-segment depth bound; scalar aliases cannot
acquire arbitrary children. All lookup here is syntax/data collection, with no
rendering or data/environment resolution.

No alias can grant env/file/vault/include/HOME/EMQX_ETC_DIR/os/system roots,
even if its SQL expression is a harmless data field. Standard message roots
cannot be shadowed by new alias authority. Existing loader marker/grammar/
context/reference gates still run independently. Unknown source roots, function
or arithmetic expressions, constants, alias chains, path/quoted alias targets,
FOREACH and ambiguous/overlapping projection targets are intentionally not
supported as alias authority. Duplicate target roots reject authority even for
otherwise pure expressions. This conservative subset can still refuse a real
source; it must not be weakened merely to obtain success. Non-alias SQL remains
registered as configuration data, not validated as executable rule behavior.
No SQL AST literals or function results are executed or fabricated.

Bounds: SQL input<=64KiB (existing per-value bound), projected fields<=64,
aliases<=64, source/accessor depth<=16, witnesses/bindings<=8192, existing input
8MiB/output1MiB, native CPU/heap/memory/time and Registry limits unchanged.
No public guard, secret scan exception or synthetic target document is added.

The actual gitarchive transfer bundle now includes emqx_sql_aliases.py, while
retaining emqx_captured_candidate.py and EVERY existing module/script. Generated
transfer tests cover both new ARM/x86 frames and diagnosticQA, and assert both
modules are present. No controller/lab command is run by these tests.

Generated validation (PYTHONPATH=tests/e2e/lab:backup-engine:.):

- python3 -m unittest test_emqx_sql_aliases -q: initial5 native/Capture tests
  passed in82.152s. Positive receipts assert exact actual AST-derived aliases,
  occurrence index, original SQL hash and full registered values. Negatives
  include overrides, split declarations, cross-rule and equality borrowing,
  concat, loader names/sources, duplicates, functions, arithmetic and witness
  mutations; all refuse before vendor observation.
- A generated fixed encrypted frame uses actual source binding, authentication,
  full EOF, Capture, native SQL/HOCON parser, private registry and capability
  bridge. Only generated cold decoding and vendor bytes are test doubles.
  New alias values are registered; target categories remain missing,
  seal/summary/scan refuse and staging/spool are removed.
- 37 affected profile/transfer/owner/vendor/phase/helper tests passed in8.716s.
- The subsequently added pinned SQL AST/preprocessor proof plus one existing
  v1 native dotted/array/override/concat regression passed in10.197s. The public
  parser demonstrably returns an external function AST without calling that
  nonexistent module; only the pure selected-field AST grants authority.
- git diff --check passed. No previously passed full lab/native suite reran.

Main alone owns real execution/evidence and must record any later refusal. This
increment provides a concrete pure-field alias path, not proof of the unknown
real alias or full source/target/restore completeness.
