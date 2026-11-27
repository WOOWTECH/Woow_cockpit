Exact pinned live MRIA sync table support, base main 1a6a052

Public proof (no broker inventory/config read): cached pinned image BEAM atom
metadata identifies '$mria_rlog_sync'; mria_schema BEAM record abstract metadata
proves the exact record/attributes, with public BEAM MD5 recorded separately.
No target module was loaded/executed for this metadata proof.
https://github.com/emqx/mria/blob/0.8.18/src/mria_rlog.hrl
Defines rlog_sync='$mria_rlog_sync', record fields reply_to/shard/extra.
https://github.com/emqx/mria/blob/0.8.18/src/mria_schema.erl#L334
Creates this exact Mnesia table with the same record name/attributes and
null_copies, via the builtin create_table path. '$mria_meta_shard' is a SHARD
identifier, not an additionally approved table. Dotted/custom names are not added.

Functional scope: only owner_target's LIVE producer after existing pinned release/
OTP/envelope validation gets _live_table_name's exact '$mria_rlog_sync' exception.
Generic native_name and every private_table filename/callback validator remain
unchanged and still reject it. No cold schema/registry changes or exporter edits.
Ordinary names keep the existing bounded lowercase/number/underscore policy.

The special table must have the exact same record, exact attributes, zero integer
row_count and rows=[]; complete canonical schema must match name/record/attributes,
nonempty native atom null_copies nodes, and empty ram/disc/disc_only copies. Unknown
or nonempty/mismatched profiles refuse with fixed inventory_builtin_profile.
All original full-inventory/schema-name binding/table-key validation stays.
Other tables cannot acquire a special record-name exemption. No name is used as
code, path or filename. This only admits a proven builtin shape into the existing
private value/receipt path; it does not authorize arbitrary leading '$' names.

Empty is observed, not invented: updated local native fixture actually registers
the pinned mria_mnesia_null_storage backend, creates the exact builtin table from
its public declaration, asserts storage_type {ext,null_copies,mria_mnesia_null_storage},
observes size zero, folds every table twice to native EOF with size/count equality,
and feeds complete native canonical records to the exact producer Typed/consumer.
Existing producer already checks the same exact backend pair, empty counts,
stable full metadata/config/provider receipts and ticker; none is weakened.
Metadata/rows continue through full private scanning, including the builtin atom.
Nonempty unknown runtime references still refuse; there is no fake empty shortcut.

Validation: 52 targeted tests PASS, zero skips, including native fixture, exact
builtin profile and unsafe/unknown '$'/dot/path names, schema/storage/record/rows
negatives, and unchanged generic persisted-value callback/path regressions.
Main original file/ref guards and tests unchanged. References are NOT relaxed in
anticipation of the next phase; any future inactive-file profile requires its own
actual fixed reason and pinned vendor proof.

Actual target13 only proved inventory_name_shape; it did not publish the offending
name. This change fixes a concrete normal pinned builtin rejected by old code and
is ready for main's target14. It is NOT a claim that the actual broker now fully
passes or that no other unsupported name/reference exists. No lab commands,
owner wrapper or locks were used; main retains sole lab ownership.
