# Code-only native-table diagnostic increment

Base 68e798e; branch codex/emqx-native-table-diagnostics-20261122;
worktree /tmp/ha-emqx-native-table-diagnostics-20261122. No dev-d, lab wrapper,
container, native runtime or source/secret operations were run for this change.
Main retains dev-d ownership. This is implementation, not an independent review.

The fixed expression now records table_storage, table_fragments, table_type,
table_lock, schema_metadata, table_size, table_schema, table_fold,
table_row_terms and schema_terms inside the transaction. Only fixed stage/reason
enums are retained for diagnostics; the original exception is rethrown privately
so Mnesia retains its abort/retry policy. Failed-attempt metadata is reset at each
transaction invocation. An aborted transaction no longer loses the inner stage
through the outer {atomic,...} badmatch. Unknown reasons become native_refused;
known abort wrappers are examined only to select a bounded, fixed enum.

No table name/index, storage alias/module, abort payload, stack or row/config
value is emitted. The Python receiver independently allowlists stage/reason and
no longer adds a source-variable name from raw CLI error text. Raw/oversized/
extra-field frames cannot populate diagnostic fields. Full capture remains
refused on any native failure; no success/empty-record fallback was added.

Storage acceptance is UNCHANGED: ram_copies, disc_copies, disc_only_copies only.
An observed null_copies atom reports storage_null_copies; an external tuple
reports storage_external, with no alias/module. Neither is accepted or skipped.
This does not establish which backend caused actual attempt4 native_tables.
No whitelist expansion is justified without owner evidence and exact semantics.

Official public source pin chain checked:
- EMQX v5.8.9 pins Ekka 0.23.2:
  https://raw.githubusercontent.com/emqx/emqx/v5.8.9/apps/emqx/rebar.config
- Ekka 0.23.2 pins Mria 0.8.18:
  https://raw.githubusercontent.com/emqx/ekka/0.23.2/rebar.config
- Mria registers null storage and conditionally RocksDB; this is availability,
  not proof that the failed target table uses it or that it has no private rows:
  https://raw.githubusercontent.com/emqx/mria/0.8.18/src/mria_mnesia.erl
- OTP 26.2.5.14 distinguishes builtin storage from {ext,Alias,Mod}, whose info
  operation dispatches to the backend module; arbitrary ext is not a builtin:
  https://raw.githubusercontent.com/erlang/otp/OTP-26.2.5.14/lib/mnesia/src/mnesia.erl

Validation: test_emqx_native_table_diagnostics + test_emqx_owner_target:
10 local tests passed; py_compile and git diff --check passed. New tests cover
all inner stages/enum frames, raw-table/abort payload rejection, the actual
report adapter with a local transport fixture, matching native/Python allowlists,
unchanged backend refusal and private rethrow rather than replacement abort.
These are code/local transport tests, NOT native Erlang execution/parse proof.
Owner's next authorized fresh target run must first use the existing native
parse preflight, then capture its fixed inner stage/code. No dev-d run was made
or requested by this branch, and no old failure evidence was rewritten.
