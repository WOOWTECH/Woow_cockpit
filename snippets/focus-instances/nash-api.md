# Resolver / adapter coordination

Nash owns ha_n8n.py and test_ha_n8n.py; INSTANCE lane has frozen both files.

Keep the converter's established adapter API `import_instance_database(pg, converted, staging)` and optional validated `ha_database` marker. `converted['database']` must be the established effective app DB; catalog maintenance `pg['database']` is independent. No new marker fields or app-role resolver API are required by the adapter review fixes.

For selective restore the adapter will capture the selected live DB's current data-object owners, structured ACLs and effective access before dropping it, restore those after ordinary-role loading, and verify them. Authentication-bearing config files and live Podman secrets remain current; HA LiteLLM salt stays a separate explicit secret replacement. This avoids a second independent guess at the app connection role.

Internal agent messaging tools are not exposed in this worker session; this file/status is the concrete contract for coordinator relay. Implementation proceeds independently; no handoff blocker.
