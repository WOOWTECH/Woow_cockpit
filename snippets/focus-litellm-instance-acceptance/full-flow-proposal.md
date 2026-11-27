# Original LiteLLM whole-instance flow and recovery

REVIEW PROPOSAL ONLY. No new dev-d calls, app/service/PG actions or real
credential reads occurred while preparing this packet. Parent images-verify15f
PASS adopted the existing derived image and set images_ready; immutable capture
SHA is `0c5396f61187dc666c4a67162fd813facfb8571f1ef291bb40b74558a9c1bc1f`.
Historical images01 stays FAIL. The new controller delta only fixes fresh-reader
initialization; original80 and native generatedPG87 are complementary evidence.

## Fixed inputs and fresh-process recovery

| Binding | Exact value |
| --- | --- |
| Device | `woowbk-dev-d` |
| Product source | `59a1b0f95132ea51c899f590eea7e3b02c5dba43` |
| Case | `woowbk_focus_litellm_a2c39e761b04` |
| Original canonical baseline | `298e4a88feb3356979e4f5dab8a6155fa418e834ec44d887cf7cff79a7719c82` |
| Adopted derived config | `af291cf14dba64dd3331179696d9bdfd70f5cacf0c92c53202d0998fe15ecaff` |
| Cached PG17 config | `094ecc9ca4ea66931822a93f1d814e059deda57f355d9416fa72f85170871cb7` |
| Trusted package | `dd690aee2b9032cf3db0695af714a8248a0ccb0a` |
| Original encrypted HA fixture SHA256 | `9dc5994497d9d6ff4c3ee8d3fcf86f295cf25c69d1eae98227854fee85286f27` |
| Saved80 reader/probe source SHA256 | `f9455650d20189cef7d083ed967bb8b485190fbff44a378b152bcd28f69f8cf3` |
| Derivation SHA256 | `b15f9c4d19b95f51e85e8ec5b6ca1e52b63e064298b8bc3b0b9eb80c912a555a` |

The resume fix redirects saved80 state to the case path before constructing or
loading readers. Fresh flow still calls the original saved Run.load_secrets.
A new recover process first validates and registers all persisted generated
case values, then uses the same original HA decoder to initialize HA inputs
without generating replacement own values. It restores own_key, HA salt hash
and before_probe. The live run object is assigned only after successful complete
initialization. Missing/unknown persisted names refuse without overwrite.

The two-controller regression uses the REAL saved80 Secrets and Run classes,
temporary harness inputs and a stub only for external encrypted-archive decoding
and evidence output. It proves a first controller's generated values survive a
fresh second controller with random generation forbidden. It also proves
incomplete persisted state refuses before decode/generation and leaves the
private receipt unchanged. Red2/2 then green2/2; no original80/native rerun.

## One actual full-flow invocation

Existing entrypoint `focus_litellm_instance_acceptance_run.py --phase flow`:

1. Admit under global2-heavy/dev-d mutex/priority, isolated outer device, actual
   host/appowner/data/staging free >=**21GiB** (13GiB reserve+8GiB peak), host
   available1200MiB/device headroom1900MiB. Recheck original case receipt/root
   before and strict current baseline; **no Headscale filter or rebaseline**.
   Verify every installed frozen module/helper before reading credentials.
2. Require adopted derived tag/config and fresh LL namespace. Archive exact
   trusted package into its initially absent owned directory. Temporarily tag
   the already cached PG17 config only if absent, pin its actual digest in the
   owned package, install `--no-pull --no-start` with case-private installer/tmp
   state. Start only litellm-postgres and litellm. Daily LL timer stays stopped;
   package memory limits remain1GiB PG/2GiB proxy. Preserve standard actual
   DATABASE_URL and matching HOST/NAME/USERNAME companions.
3. Use real catalog-suggest and catalog-install preview/CAS. Record/authorize raw
   catalog absence before edits. Sole instance delta is scope=instance/removing
   database, while actual proxy endpoint independently must be litellm on local
   declared backend. Ensure existing device encryption key (no rotation).
4. Seed own API key/model/credential; verify own key/decryption/salt. Capture
   original complete cluster state. Create encrypted **unmarked full-instance
   safety**, inspect all DBs/roles/digest coverage and pin its ID before creating
   the case outside DB/role or uploading/decrypting the original HA fixture.
5. Actual HA check must be importable with no unreviewed confirmation lines;
   verify fixture1user/1team/24models. Actual whole-instance conversion must carry
   validated ha_database=litellm/ha_access, globals and all three live DBs.
6. After conversion, write a later outside row and change its role password.
   Restore converted HA; require successful health/current full safety, actual
   app API/decryption and exact current outsiders/roles/settings/membership/
   owners/ACL/digest/password fingerprints preserved. Restart actual PG/proxy,
   verify again, and re-read actual proxy endpoint.
7. Create a later API credential witness. Capture current complete cluster;
   arm owned one-shot trusted startup-failure drop-in. Restore converted HA and
   require real injected failure plus **automatic current FULL safety rollback**,
   full before/after catalog/rows/role/password/access equality, witness retained,
   digest-postcheck success and actual original-HA API/provider decryption.
8. In mandatory finally recovery, settle any pending engine request by journal
   ID, remove only the exact owned hook, restore pinned original FULL safety,
   require successful digest verification and complete original cluster equality,
   then actual own key/data/decryption/salt restoration. Scan registered values
   in engine records/journal and private evidence before resource cleanup.
9. Journal current owned IDs/mounts; remove only initially absent owned package,
   config, Quadlets, secrets, PG volume/network and case-private installer state.
   Restore raw catalog absence using CAS; preserve preexisting masked schedule,
   original8/current baseline, all preexisting backups/uploads and source59.
   Delete only known case backups/upload after successful recovery/scan/strict
   original equality. Retain adopted derived image under retain-for-case policy.

Every listed check is mandatory. Saved80 setup/run_all/ordinary conversion/
cleanup and optional skips are not called. PG adapter/source proof is not rerun.
Unresolved requests, foreign identities/files or failed recovery retain copies
and stop; no forced/pruned or blanket cleanup. Strict transient-ID failure stays
a failure with evidence. No original HA-service success is claimed in advance.

## Lease and exact commands

New lease `/tmp/parity-focus-20261127/lease-litellm-fullflow-dev-d.json`:
`granted=true`, case `litellm-instance-original`, device/name/fixture/recipe/
package/product/baseline bindings above, exact NEW full driver commit from
handoff, phases `["flow","recover"]`, baseline_policy `require-litellm-absent`,
image_policy `retain-for-case`, timezone-aware expiry within80min. Parent grants
when D is free and both21GiB floors pass; metadata verification's smaller budget
does not authorize flow. Reuse the adopted image case receipt; new output.

```bash
env HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock HEAVY_WAIT=60 \
  /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
  timeout --signal=TERM --kill-after=1200 3300 \
  python3 -B -I /tmp/parity-focus-litellm-instance-acceptance-20261127/tests/e2e/lab/focus_litellm_instance_acceptance_run.py \
  --execute --phase flow --source /tmp/parity-focus-final-product-20261127 \
  --lease /tmp/parity-focus-20261127/lease-litellm-fullflow-dev-d.json \
  --receipt /tmp/parity-focus-20261127/litellm-instance-a2c39e761b04.private.json \
  --output /tmp/parity-focus-20261127/litellm-instance-fullflow-01.json
```

Launch within5min of a fresh80min lease: outer TERM at55min leaves20min grace,
maximum75min plus launch delay. Existing controller stops admitting ordinary
steps below15min remaining; each job wait is bounded900s. Soft interruption
enters mandatory finally recovery. Hard termination/lost response leaves a
durable receipt; settle/recover under an unexpired separately authorized phase.
Do not replay flow/install. Explicit fresh-process recovery command is identical
with `--phase recover` and NEW `litellm-instance-fullflow-recover-01.json` output;
it may need a renewed recover-only lease if the original window has expired.
Unknown/running jobs prevent cleanup; successful parent/native closure still
requires original resources and no active engine jobs, not only a command exit.

Keep image01 FAIL, images-verify PASS and fullflow/recovery results separate.
After actual fullflow success plus original recovery, coordinator decides the
L-03 registry closure; N8-01 remains an independent actual-service acceptance.
