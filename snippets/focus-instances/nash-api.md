# Stable endpoint / adapter contract

`ha_instance_access.local_backend(found, quadlets, main, postgres) -> bool` is committed in `7cee385d`.

- `found`: Nash's four-field endpoint (database, user, host, integer port), from the SAME installed vendor reader.
- `quadlets`: trusted current filename -> bytes mapping.
- `main`: the main **Quadlet filename**, such as `n8n.container`, not a container name. Obtain it with `hacommon.container_file(quadlets, ha_n8n.main_container(runner, quadlets))`. Worker/webhook selection stays entirely with Nash.
- `postgres`: catalog PostgreSQL spec, including its `container` name. The helper requires exactly one corresponding declared backend, host equal to its ContainerName or explicit NetworkAlias, port5432, and a shared declared Network excluding host/none. Unknown layouts return False. No probes, HA queries, init-setting guesses, or password reads.

Use this helper before instance conversion as well as destructive restore. Nash owns that small conversion call site; this lane does not write n8n source/tests. Ordinary single-DB/cold paths remain unchanged.

Shared restore uses `prepare_app_endpoint(work, app, quadlets=...)` through an actual short-lived TempObjects with a valid existing adapter job ID or jobs.new_job_id(). The scope ends, including successful cleanup, BEFORE safety backup and ordinary restore stop/restart. Failed cleanup refuses continuation and retains retries; cancellation remains the primary exception. LiteLLM uses its equivalent bounded prepare_app_connection hook and actual proxy URL reader.

The running endpoint does not validate unapplied next-start inputs. The adapter separately compares trusted declared Quadlets, EnvironmentFiles/config files and known secret targets against conversion inputs; only verified password-only changes are allowed. Running DB-name drift and unapplied file DB-name drift refuse before stop/DROP. Current authentication files/secrets remain live; LiteLLM HA salt is the deliberate exception.

Selective import captures current data-object ownership/access and expected installed extensions before DROP. New table/sequence names without a current ownership policy refuse before DROP; new columns retain existing table-wide grants. Ambiguous column-only privileges refuse. A same-name ordinary/partitioned kind change fails after load and invokes full current safety rollback; it cannot disappear from access postchecks.
