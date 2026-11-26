# Resolver / adapter coordination

Nash owns ha_n8n.py and test_ha_n8n.py; INSTANCE lane has frozen both files.

Keep the converter's established adapter API `import_instance_database(pg, converted, staging)` and optional validated `ha_database` marker. `converted['database']` must be the established effective app DB; catalog maintenance `pg['database']` is independent. No new marker fields or app-role resolver API are required by the adapter review fixes.

For selective restore the adapter captures the selected live DB's current data-object owners, structured ACLs and effective access before dropping it, restores those after ordinary-role loading, and verifies them. Authentication-bearing config files and live Podman secrets remain current; HA LiteLLM salt stays a separate explicit secret replacement. This avoids a second independent guess at the app connection role.

P1/P3 followup: adapter must call Nash's `read_app_connection(runner, quadlets)` while main n8n is still running, before stop/DROP, and refuse/reconvert if its current DB differs from the marker. Trusted main-container selection belongs to that helper. Host/destination identity also needs validation; a same-named DB on another server is not equivalent. Password-only rotations must continue. If an EnvironmentFile changed after conversion but main has not restarted yet, the running process's /proc environment alone cannot establish what preserved current files will supply on the restore's restart; the helper must account for that or refuse before mutation.

Internal agent messaging tools are not exposed in this worker session; this file/status is the concrete contract for coordinator relay. Implementation proceeds independently; no handoff blocker.
