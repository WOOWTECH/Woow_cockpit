Nextcloud NC-38 / NC-45: backup functions, procedures, aggregates and triggers are excluded from the restore. A complete
catalog inventory with exact identities is required first; an incomplete or duplicate inventory stops this app. Unknown
identities alone require confirmation, and a changed unknown-name set requires fresh confirmation. Other unsupported
objects still stop only Nextcloud.

The known Memories filecache function and trigger are reconstructed from fixed definitions reviewed against release
v11.1.4, after the restored database passes the original hostile-object gate. The ordinary loader creates them; a target
superuser receives ownership only after this work. Validation checks the exact body, owner, trusted language, invoker
rights, fixed search path, trigger conditions, integer table columns, and complete remaining database shape. Counts
include oc_memories when present and are checked after reconstruction. Existing role attributes, password fingerprint,
roles, extensions, grants, data counts and storage / Office checks remain mandatory. The verified trigger flag is written
to system config (config.php); it is not an oc_appconfig value. All four converted directories are validated before use.
Conversion returns rebuilt_apps and no longer reports known Memories objects as left_out_apps or asks for manual repair.

NC-09: an unreadable combined query no longer discards otherwise readable inventories or Office settings. Required role
and installed-extension inventories can be recovered separately from pg_authid and pg_extension, with the same final
equality checks. pg_available_extensions is optional availability information and is never substituted for the installed
extension baseline (missing control files would make that substitution incomplete). If the authoritative baseline itself
cannot be read, conversion stops before reading HA data: an unknown baseline cannot establish that the restore introduced
no additional role or extension. Office settings/cache that remain unreadable retain their existing notice behavior.

Validation scope: local guarded regressions plus a separately leased generated PostgreSQL database proof. These do not
constitute an original HA Nextcloud full-flow run or all-service commercial acceptance. See README.md and evidence.
