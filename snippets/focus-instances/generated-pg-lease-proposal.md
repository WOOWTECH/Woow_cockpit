# Exact generated PostgreSQL instance proof proposal

Driver: `snippets/focus-instances/generated_pg_probe.py`. Default invocation prints a plan and performs no device command. Fixed whitelist `--device c|d` (default d). `--run` requires a matching, unexpired coordinator lease, committed clean source, the corresponding `/tmp/woowbk-dev-{c|d}-mutation.lock`, and verified outer isolation before and after. Dev-c is the proposed next slot; the coordinator confirmed the same image already exists there. No hardware-payload changes, copy, pull or install. Global heavy wrapper still limits host-heavy jobs to two.

## Resource and filesystem bounds

- Existing selected device's owner image only: `sha256:4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873` (amd64 PostgreSQL16.15 Alpine). `--pull=never`; no installs, image imports, or helper deployment.
- Sequential n8n and LiteLLM cases. At most one new container and one named data volume active at a time. Each starts a source cluster and then a fresh full-safety rollback cluster.
- Names: `woowbk-inst-proof-<12hex>-n8n` / `woowbk-inst-proof-<12hex>-litellm`; each data volume adds `-data`. All objects have `woowbk.instance-proof=<12hex>`; a preexisting name is refused.
- Exact run limits: `--image-volume=ignore --network=none --read-only --user=70:70 --cap-drop=ALL --security-opt=no-new-privileges --memory=384m --memory-swap=384m --cpus=0.5 --pids-limit=96 --shm-size=32m`; no port publication. Private /tmp 16MiB and socket tmpfs 8MiB; owned PGDATA volume mounted `:U,noexec,nosuid,nodev`.
- Private code zip, custom dumps, globals, verification digests, retained credential file and ownership journal use a 0700 run directory directly under `/home/appowner`, never device `/tmp`. Check THAT filesystem for 13GiB reserve plus 512MiB working allowance before any container/volume creation. Host minimum 1200MiB MemAvailable and the same disk floor; selected device memory headroom >=512MiB. Keep the engine's real `default_runner` output/resource limits, including file stdout and zero-byte budgets; no reserve override.
- Remote proof budget 300s plus a total 45s cleanup budget; outer owner.sh call timeout 360s. Selected device mutation lock held for the entire remote run and cleanup.

## Actual methods and evidence

Import the committed, SHA256-checked engine from a private temporary zip, with no installed-code changes. A strict runner permits adapter exec only against the current run-owned container, using the engine's real bounded relay.

### Bounded driver delta from the previously reviewed 5bf902bf proposal

- Permit only c/d and use the selected device's exact mutex and lease device; d retains EMQX priority-marker rejection. Every resource/image/space/isolation guard stays.
- Require SCRAM for the ordinary app login; only the generated administrator uses local trust. Separate ordinary DB owner, ordinary table/sequence owner and actual app LOGIN. Preserve established table-owner membership plus direct table/sequence/schema and column ACLs. The login performs real SELECT *, INSERT, ALTER of an existing table, CREATE/INSERT/ALTER/DROP of a migration table, all inside a rollback transaction (no sequence advances).
- Inspect this owned cluster's installed `pg_available_extension_versions` for untrusted pgstattuple (preferred) or pg_stat_statements. Require one, install its exact available version, never invoke extension functions. This proves admin preseed, extension TOC/comment handling and ordinary-role load with an actual untrusted installed extension; it makes no vector claim.
- Generate real custom dumps with a new table and sequence and prove precise pre-DROP refusal plus unchanged full current state and working login. The successful HA-equivalent dump has a new column on an existing table, covered by current table-wide grants. LiteLLM also has a current safety-only L-38 schema that must stay omitted after selective import and return on full rollback.
- Rotate app-login, outsider and bootstrap passwords after conversion; retain a private current credential file, reject old app password and prove current login after import and rollback. This is actual PostgreSQL authentication evidence; application config-file retention/future-input checks are separately exercised by guarded adapter/flow tests.
- Compare semantic ACLs, schema/column/type facts, owners, all row/sequence digests, roles/memberships and password fingerprints. Corrupt/truncate a real dump only after independently proving its TOC remains readable but full data reading fails. Thus injected failure occurs AFTER replacement, followed by real full fresh current-safety restore and exact equality.
- Allow only the adapter's fixed private TOC write/removal grammar in addition to existing PostgreSQL tools. Journal exact owned IDs/mounts, signal cleanup and private errors remain mandatory.

For EACH app, actually execute `_dump_database`, `import_instance_database` (real `_dump_instance` with globals and every database), `_instance_manifest`, strict archive instance validation, `_restore_ha_instance_database`, `_ha_database_owner`, `_dump_instance` for current safety, `_restore_instance` on the fresh rollback cluster (including the new-cluster guard), and `_capture_pg_digest` for all rows/sequences/roles. SQL scripts use exec `-i`; boolean reads use `to_json`.

Generate an app DB, separate outside DB, writable postgres maintenance DB, and another DB later removed. After conversion, insert outside/maintenance rows, add another DB and role, remove the old extra DB, rotate both outside-role and bootstrap passwords, and change the app DB/table owner. Capture a NEW full safety snapshot of that current state. Import only the application DB and verify HA-equivalent rows, CURRENT DB/table ownership, unchanged outside rows/catalog/owners, role memberships, and ALL password fingerprints (including bootstrap).

Inject a truncated real custom dump so the real `pg_restore` fails AFTER the app DB has been replaced. Verify app table absence and unchanged outsiders. Rebuild only the owned disposable cluster, apply the actual FULL unmarked safety `_restore_instance`, then require exact equality of database catalog/owners, data-object/schema/column ACLs, all rows/sequences, role flags/memberships and every password fingerprint. This is a generated-PG ADAPTER proof; guarded stateful tests cover real FlowContext automatic rollback and salt/auth-secret handling. Existing real n8n34/LiteLLM80 evidence remains complementary. This does not exercise the actual installed n8n vendor reader or claim an original HA service full-flow rerun.

Record owned container IDs and fixed-field mount lists at creation AND before cleanup, plus a 0600 on-volume ownership journal with cleanup intent recorded before create/run. Remove only exact owned labelled IDs, their owned anonymous volumes (`rm --volumes`, though image volumes are ignored), and the one owned named data volume. No prune/sweep. Verify durable volume inventory and catalog/Quadlet hashes unchanged. Observe unrelated existing container restart churn separately. Public evidence contains counts, fixed statuses, owned IDs/mounts and hashes; private errors are bounded and generated secrets masked.

## Lease payload (coordinator creates this file)

```json
{
  "device": "woowbk-dev-c",
  "case": "instances-generated-pg",
  "worktree": "/tmp/parity-focus-instances-20261127",
  "source_commit": "<exact committed driver HEAD>",
  "image": "sha256:4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873",
  "resource_prefix": "woowbk-inst-proof-",
  "expires": "<coordinator UTC expiry after the queued slot>"
}
```

Exact queued command, once leased (output filenames must be new):

```sh
HEAVY_FREE=/tmp/woowbk-dev-c-mutation.lock \
/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
python3 -B -I /tmp/parity-focus-instances-20261127/snippets/focus-instances/generated_pg_probe.py \
  --device c --run --lease /tmp/parity-focus-20261127/lease-instances-dev-c.json \
  --out /tmp/parity-focus-20261127/instances-generated-pg-c-01.json
```

The driver rejects an active EMQX priority marker and mismatched/expired lease. Failed cleanup retains its private run root and ownership journal; evidence identifies only the run-owned IDs/volumes for exact recovery, never existing app resources.

Preparation validation only: outer/remote Python AST parse and read-only default plan. Runtime not yet executed and no device mutation performed by this lane.
