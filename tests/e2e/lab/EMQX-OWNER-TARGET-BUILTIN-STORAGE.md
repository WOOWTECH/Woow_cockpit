Owner target builtin storage increment (code-only)

Base: 5f3bf90, retaining main 668d112 owner_target.py and file-guard tests.
No lab commands, owner wrapper invocation, lock acquisition or backend execution.
This does not supersede attempt6: actual full target remains unaccepted.

Only native storage_type tuples {ext,rocksdb_copies,mnesia_rocksdb} and
{ext,null_copies,mria_mnesia_null_storage} join existing ram/disc/disc_only support.
All other external pairs, swapped pairs/custom aliases/modules and bare null_copies
still refuse before table folds. All tables are checked before collection, then
storage policy is rechecked before each table fold and storage identity must remain
stable. Full native metadata and every folded row remain private superset inputs.
Fragment/type/term/size bounds, Count==foldN, second fold and schema/config/provider
receipts, ticker identity/suspension and exact five-category guards remain intact.
Null uses the SAME two actual native folds: only observed size/counts (0,0,0,0)
accept. A nonempty result emits fixed storage_null_nonempty; no fabricated rows or
skipping null tables. Unknowns remain storage_external, without raw terms.

Public pinned implementation basis (read source, not actual runtime validation):
- EMQX v5.8.9 rebar.config pins ekka 0.23.2; ekka pins mria 0.8.18;
  mria rebar.config pins mnesia_rocksdb 0.1.17.
  https://github.com/emqx/emqx/blob/v5.8.9/rebar.config
  https://github.com/emqx/ekka/blob/0.23.2/rebar.config
  https://github.com/emqx/mria/blob/0.8.18/rebar.config
- OTP 26.2.5.14 mnesia:foldl/3 transaction iteration uses dirty_first/dirty_next,
  reads each key, and returns only after '$end_of_table'. mnesia_lib db_first and
  db_next_key dispatch external tuples to Mod:first(Alias,Tab)/next(Alias,Tab,Key).
  https://github.com/erlang/otp/blob/OTP-26.2.5.14/lib/mnesia/src/mnesia.erl
  https://github.com/erlang/otp/blob/OTP-26.2.5.14/lib/mnesia/src/mnesia_lib.erl
- Null backend info(size) returns 0, first/next/select return '$end_of_table'.
  https://github.com/emqx/mria/blob/0.8.18/src/mria_mnesia_null_storage.erl
- Rocks backend info(size) uses retrieve_size, first/next use native iterators,
  lookup restores record keys. Iterator errors can become EOF in this backend;
  Count/fold matching and repeated receipts are required but are NOT proof against
  all native IO failures or concurrent/background writers. Size errors/noninteger
  values refuse; zero is never substituted for unavailable size.
  https://github.com/emqx/mnesia_rocksdb/blob/0.1.17/src/mnesia_rocksdb.erl
Main 8d76e65 established the same exact registration pairs for inert cold metadata;
that evidence alone does not demonstrate runtime folding.

Tests: Python code-only suite (owner_storage/native_table_diagnostics/fresh_ticker/
owner_target): 19 passed, 1 skipped; bash -n wrapper passed. Supplied executable
emqx_owner_storage_fixture.escript extracts/evaluates the actual fixed expression's
policy and receipt closures, testing exact allowed pairs, unknown/swapped pairs
refused before the simulated fold boundary, and each null count mismatch.
It is SKIPPED locally because escript is absent. It does not emulate native storage.
Future owner can execute it OFFLINE with:
  escript emqx_owner_storage_fixture.escript emqx_owner_target.expr
Native parser/full-expression/backend size/fold/EOF and full target registry are
UNEXECUTED for this increment; no ARM/x86 runtime success claim.

Wrapper follows main 05c25dd: existing regular owned nonsymlink lock paths only,
read-only FDs, inode identity plus owned regular file and single-link checks.
Missing/unsafe locks refuse, never create/truncate them. Both flocks remain.
