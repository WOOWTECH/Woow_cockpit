Bounded inventory diagnosis, base main 888f465

Main actual attempt12 reached consumer inventory; its coarse phase alone does not
identify the failing check. The producer canonical helper already emits exactly
{Table,CreateList} pairs, not triples. A fresh pinned-runtime native Mnesia fixture
confirms that exact canonical pair -> Typed -> native JSON -> consumer path works.
No tuple/schema acceptance rule is relaxed and no speculative functional fix is
claimed. Main can run the next actual target immediately to obtain the fixed reason.

Implementation: existing inventory checks are factored without changing acceptance
into _validate_inventory. OwnerCaptureRefused keeps the original fixed phase and
message, adds a strictly allowlisted reason, and survives _build's catch without
being collapsed back to a generic phase. Harness adds consumer_fixed_reason only.
No table/attribute/name/value/count/exception text is included. All noninventory
private failures remain private_refused. Unknown diagnostic phase/reason strings
are clamped. Main phase6b04, file-type guard, exact registry schema/unknownrefs,
canonical producer, secret/callback policies and public guard remain intact.

Fixed inventory reasons cover names type/bound/shape/duplicates/missing schema;
schema container/count/pair shape/name kind/duplicates/exact binding; and tables
container/count. Relevant examples for next actual report:
- inventory_schema_entry_shape: not exactly a decoded tuple pair (lists/triples
  still refuse; no coercion).
- inventory_schema_binding: exact schema-name set differs from inventory.
- inventory_name_shape: unsupported native name shape still refuses.
- inventory_tables_count: table record count does not cover every non-schema name.
No public raw data is needed for this distinction.

Meaningful fixture: local cached pinned image starts only standard Mnesia on fresh
synthetic RAM tables, not an EMQX broker/dev-d. Its private invocation-owned writable
scratch is removed by local runtime/temporary-directory cleanup. Mnesia creates all
canonical records itself, including schema, real index metadata and a synthetic
user_property secret. The exact producer CanonicalSchema/Typed closures consume
ETS native records, lock schema/tables, check inventory/schema counts and pre/post
schema equality, fold every data table to EOF and match actual Count. emqx_app is
actually observed empty; auth/JWT are nonempty synthetic data. No handwritten
CreateList/absence dict substitutes for native observations.

The native-generated schema/tables flow through owner_target_readers to all five
exact readers; native schema/JWT/auth secret bytes must be found by private full
scan. Tests also reject each inventory failure class (including native pair
mutated to list/triple), prove fixed phase/reason preservation and report privacy.
Previously existing schematic fixtures remain but no longer stand alone as proof
of the native canonical boundary.

Validation: 37 targeted tests PASS, zero skips (local cached native fixtures plus
consumer/harness tests). No lab/owner-wrapper/locks accessed; main retains dev-d.
The actual cause of attempt12 is still unproven until main's next target run. Full
target/broker acceptance is not claimed from this local synthetic Mnesia fixture.
