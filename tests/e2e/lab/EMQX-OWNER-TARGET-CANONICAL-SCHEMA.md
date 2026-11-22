Minimal target canonical schema increment, base main 265a452

Actual attempt7 (reported by main) passed storage/ticker/folds but refused at
schema_terms/unsupported_term. This does not identify the actual unsupported kind.
No actual broker/dev-d invocation is performed by this increment.

schema_metadata now covers COMPLETE native persistent CreateLists, including
schema itself and all inventoried tables. It no longer claims to capture all
VM-local runtime table_info(all) metadata (which may contain ETS handles/PIDs).
The fixed producer locks schema for read inside the existing transaction, then
reads ets:lookup(schema,T) for every All entry. Each result must be exactly one
{schema,T,CreateList}, with a proper bounded list of unique atom-keyed properties.
It preserves every property/value, including index definitions, user properties,
backend registrations/storage definitions, cookies and version. There is no
property allowlist or unknown-field filtering. Unsupported values still refuse.
The envelope retains existing {T,CreateList} pairs: only the fixed record tag is
structurally validated/unwrapped. Core consumer/schema and public guard unchanged.

Pinned OTP 26.2.5.14 source explains the exact access mechanism:
https://github.com/erlang/otp/blob/OTP-26.2.5.14/lib/mnesia/src/mnesia.erl
read/5 has guard Tab /= schema; using read(schema,T,read) would always refuse.
read_lock_table/schema is allowed by lock_table's atom guard.
https://github.com/erlang/otp/blob/OTP-26.2.5.14/lib/mnesia/src/mnesia_schema.erl
get_create_list reads schema ETS field 3; insert_cstruct writes
{schema,Tab,cs2list(Cs)}. The producer reads those exact complete native records,
not a re-created runtime projection, and never calls list2cs/custom callbacks.

Pre/post schema ETS sizes must equal full inventory length; every matching key
must exist exactly once. Complete CreateList fingerprints must match before/after
folds, and final Mnesia inventory must remain identical. All old data count/fold,
stable config/provider, generation, ticker and exact builtin storage guards stay.
Full config/provider/row and canonical schema private scans remain. This is a live
persistent-schema observation, NOT historical cold checkpoint coverage or proof
that arbitrary background writers cannot mutate transiently between receipts.

Unsupported PID/reference/port/function/nonbinary-bitstring leaves now map to
fixed reason enums only. Generic bounds/depth/other unsupported terms still refuse.
Function environments are never extracted, serialized or silently discarded.
If canonical schema/config/provider/row contains one, capture refuses.

Validation: 24 targeted tests pass, zero skips, including LOCAL pinned rootless
runtime execution of public synthetic canonical/typed closures, full expression
parse, and exact builtin policy fixture. Native schema fixture asserts complete
properties retained; missing/wrong/duplicate records and duplicate/malformed
properties refuse; nested PID/ref/function/bitstring refuse by fixed kind. Python
native-envelope consumer verifies schema private properties enter full scan.
These tests do NOT start EMQX or execute live schema locking/ETS observation;
actual target compatibility/full registry acceptance remains for main's next
fresh attempt. No dev-d/owner wrapper/locks used. Main retains lab ownership.
Main owner_target.py and original file-guard tests are unchanged.
