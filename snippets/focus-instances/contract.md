Proposed CONTRACT section 5/9 additions (coordinator owns final docs)

An instance-mode postgres item may contain `ha_database` only for app `n8n` or `litellm`. It is a PostgreSQL database name matching exactly one non-template item in `databases`; LiteLLM requires `litellm`. The complete globals file and all database payloads are still mandatory. Older instance archives omit the optional marker and retain their behavior. Database-scope items reject the field.

For converted HA n8n/LiteLLM archives, conversion reads the actual app DB separately from the catalog's normalized maintenance DB (`postgres`). Existing n8n encryption/credential conversion and LiteLLM salt binding, trusted schema comparison, restricted row loading, migration/count/schema checks remain active.

For HA inplace restore of a marked item, retain the existing PG data volume and every live role/password. Read the application database's current owner, replace only that database, and load under that owner; missing database/owner or changed ownership at readback is a refusal/failure. Other databases (including postgres), additions/deletions, changed owners, and role/password changes after conversion remain current. Archived globals are not replayed. The existing pre-restore safety capture remains a complete instance with all roles/passwords and full current digests; failed import rolls back from that unmarked safety snapshot and verifies its digests. A marked conversion payload cannot itself be passed as an automatic rollback source.

Fresh HA restore explicitly uses the full conversion-time instance snapshot (roles/passwords included) and requires the normal freshly initialized-cluster guard. It does not merge with later state. Ordinary restores and old/unmarked HA instance restores retain the complete-instance restore path. Converted manifests contain no source-device data digest; this does not weaken app conversion checks, health checks, or safety/rollback digest comparisons.

No flows.py/kept.py contract change is needed. No host install, host container/service command, real-device change, or real acceptance claim in this patch.

Selective HA inplace import also retains current declared application secrets so a database password rotated after conversion still matches the retained live roles. LiteLLM's salt is the exception: it is replaced with HA's salt because it encrypts the imported rows. Fresh restores and ordinary restores keep their existing archived-secret behavior.
