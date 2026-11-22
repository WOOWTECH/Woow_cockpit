# Fresh fixture ticker and bounded stability checks

Scope: code addition on diagnostic branch, not production suspension. The workload
passes the Id obtained when it created its own broker. The ticker helper requires
that exact Id, pinned image, invocation-only name, running state, network none,
no published ports/implicit volumes and disabled raw logs before any suspension.
It adapts the EXISTING product SUSPEND_SYS_EXPR/TICKER_STATUS_EXPR; no product
code or guard changed. PID remains private. Before/after status checks bind the
same container Id and native emqx_sys PID in suspended state. There is no resume;
workload finally removes the fresh broker, which ends suspension even on failure.

Zero clients alone is not called quiescence. Own writer/client lists must also be
empty, and actual emqx_cm:all_channels() is checked around capture. The fixed
native expression itself requires suspended ticker identity before and after,
not merely an arbitrary Python context supplied by a caller.

Within each locked native read, Count must equal foldN; second foldN and final
size must also match. Sorted typed-row fingerprints are compared, as are repeated
full schema metadata fingerprints and exact config/provider/table-list snapshots.
These receipts are computed/checked privately by fixed native code, not manually
asserted JSON fields. Public/consumer JSON schema is unchanged. Drift refuses with
fixed count/receipt/config/provider/ticker enums. Existing storage/fragment/type
acceptance is unchanged, including refusal of all unapproved external storage.

Expiry, dirty writes, MRIA/other background tasks are NOT all suspended by this
helper. Equal bounded receipts are not a universal writer barrier and do not
prove absence of intervening/reverted changes. Report scope is explicitly
clients-and-system-ticker; other_background_writers is not-excluded. Controlled
fresh fixture observations are not a claim of arbitrary live-broker consistency
or commercial acceptance. Current known storage_external blocker still applies.

No changes to emqx_owner_target.py or test_emqx_owner_target.py are included in
this increment. Main's filetype guard and corrected pass-only negative bodies
must be retained. Integration must build on main's corrected core, not overwrite
it from the older diagnostic branch. New ticker negatives likewise use pass-only
bodies so they cannot catch their own deliberately raised self.fail.

Local code tests cover wrong production name/missing Id, container replacement,
resumed ticker, own writer exclusion, actual adapter expression dispatch and
native count/receipt checks. They use generated transport fixtures, not a lab.
Any native run is recorded separately with source commit, fixed enums and full
cleanup; no green result may be inferred from these fixture tests.
