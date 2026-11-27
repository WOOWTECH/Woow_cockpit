# Generated PostgreSQL instance adapter proof

`generated-pg-c-04.json`: **87/87 checks PASS**, native generated PG16.15 on isolated dev-c, source commit **9561769609929d0100eb9df4935fba79f61906aa**. Its engine bytes equal058ac365; later product handover changes are NOT claimed by this native run.

Both n8n and LiteLLM cases use actual adapter dump/import/selective-restore/full-safety-restore/digest methods with real PostgreSQL. Each has4 databases and22 roles at current safety capture. An ordinary DB owner differs from ordinary table/sequence owner and actual SCRAM app LOGIN. Installed untrusted pgstattuple1.4 is provisioned through validated controls; no extension functions invoked. Current table/schema/column ACLs and owner membership support real SELECT *, INSERT, ALTER of an existing table and CREATE/INSERT/ALTER/DROP migration operations. Old password is rejected; current retained credential-file login works after import and rollback.

Later outside/maintenance writes, added/removed databases, owner changes and app/outsider/bootstrap password rotations survive selective import. New table/sequence dumps refuse before DROP with full state unchanged; a new HA column retains current table-wide app access. LiteLLM's safety-only L38 schema stays omitted after import and returns on full rollback. A genuinely TOC-readable/data-broken dump fails after replacement; full fresh current safety restore gives equal catalog/schema/column ACL, row/sequence and role/password state hashes. Actual Role/ACL/extension postchecks remain active.

One own384MiB container/named data volume at a time, network none/no ports/image volumes ignored, exact image identity/amd64 and13GiB+512MiB filesystem reserve. Source/rollback generations were each recorded at creation and cleanup (8 resource records). All resources absent, private staging removed, durable volume inventory and catalog/Quadlet hashes unchanged, outer isolation preserved; mutation mutex released. Private diagnostics and0600 journal remain under `/tmp/parity-focus-20261127/`, not committed.

Attempt history is preserved there: c01 FAIL before remote dispatch (historical isolation whitelist); c02 CANCELLED in heavy queue before admission; c03 FAIL at fixture role metadata query with verified cleanup. c04 corrects only harness compatibility metadata, with no engine or safety-control changes.

This is generated PostgreSQL adapter evidence. It does not run the installed n8n vendor reader or claim an original HA n8n/LiteLLM service full flow. Saved real n8n34/LiteLLM80 evidence remains complementary.

Separate product follow-up: explicit `take_over` receipt accepts an empty stopped-unit list; cached preflight endpoint is consumed once instead of starting/re-probing after safety capture. Both apps' actual adapter preflight→empty handover→restore cases failed red before the fix and pass green afterward. The focused12-test gate includes full safety rollback, running/unapplied DB-name drift, ordinary and fresh restore; it is the source gate for that change, not a native-tip claim. Earlier69-test boundary and140-test LiteLLM/access regressions belong to the frozen pre-followup engine and overlap.

Central integration: final six-line empty-handover receipt fix at `72ca217b` was tested by 12 guarded cases after the native proof. The native result binds pre-followup engine `058ac365` through proof commit `95617696`; it is not a native final-tip or original HA-service claim. The full 3549-test run at `86e06b43` found legacy suggest/mutation expectations; the updated suggest/mutation contract passed 70/70 before the final full rerun.

The frozen `d09f4fe8` rerun completed **3568 tests, zero failures/errors, two skips** in 868 seconds, with no blocked calls or shim hits. `integration-d09f4fe8.json` binds the original guard log by its full hash. The source checker also passed for 52 engine sources and existing asset/catalog/unit checks. This is integration evidence, not original-service acceptance; the subsequently identified standard LiteLLM companion-environment reader correction is outside this run.

The bounded LiteLLM companion-environment correction at `59a1b0f9` passed **145/145** guarded access/LiteLLM regressions in 20 seconds, including the compiled production probe and conflicting-input/local-backend refusals. No calls were blocked and no shim/native calls occurred. The 52-source checker passed again. `integration-litellm-59a1b0f9.json` records this delta gate separately from the preceding full suite.

## Real whole-instance acceptance of N8-01 and L-03 (2026-11-27 evening)

Both remaining first-wave rows passed their complete original-application whole-instance flows on isolated lab devices:

* **N8-01**, n8n 2.43.6 on dev-c, flow attempt 7: 85 checks, `runtime_acceptance: true`, 1,360 s
  ([n8n-instance-flow-attempt7.json](n8n-instance-flow-attempt7.json), stage names only). Product commits under test: d09f4fe8 plus
  `8e18f842` (the n8n connection probe ignores its own process entry) and `bfe7b914` (PostgreSQL sequences advanced after n8n's own
  `import:entities`, which advances only IDENTITY columns: every new execution collided with an imported id).
* **L-03**, LiteLLM on dev-d with PostgreSQL 17, successor case b11: 68 checks, phase succeeded, flow and recovery verified, outer
  isolation returned ([litellm-instance-fullflow-07.json](litellm-instance-fullflow-07.json)). Product under test: 59a1b0f9 plus `ce8c4cfb`
  (the PostgreSQL 17 table privilege `MAINTAIN` in the instance access whitelist).

Each app's engine code on the final integration tip is byte for byte the code that ran on its device; the only differences are other apps'
modules. The final tip `4eb41e29` passed the guarded `tests/backup` suite: 3,644 tests, zero failures/errors, two skips, no blocked calls or
shim hits ([integration-4eb41e29.json](integration-4eb41e29.json)); `dacbc5ab` afterwards changes three lab files only, and the 18 n8n and
LiteLLM lab modules pass together (241). Both devices were returned to their exact original state after every attempt (backups, uploads,
containers, catalogs, services, timer; the paused failing Headscale unit resumed). Private receipts, leases and journals stay on the host
in /tmp/parity-focus-20261127 and ~/.woowbk-lab/run. This is row acceptance, not the ten-service commercial acceptance.
