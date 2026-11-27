# Original LiteLLM instance: exclusive successor case b7

CODE / HOST METADATA ONLY. No new D action. Fullflow01 and fullflow02 remain
FAIL; a2 complete cleanup and Headscale resume01 remain separate PASS evidence.
No reset/rearm of a2, no credential reuse, no image rebuild/relabel or rebaseline.

## Proven fix and fixed inputs

3537b54cae0cfaafd136afaa2f281e1516cc3a7b fixes both MD5 scalar queries with
to_json. Actual diagnostic965f0137 proved the schema-query JSONDecodeError.
One real snapshot/JSON reader/adapter digest wire-contract regression passed;
roles=True is the correct actual API. d9bc80d5845ab8c84e551c8e5accee668381ba2a
adds bounded root/host operation diagnostics before cleanup (one narrow gate).
No product deployment or new original80/generatedPG87/broad repeat is needed.

| Binding | Exact value |
| --- | --- |
| Product/source path | `/tmp/parity-focus-final-product-20261127` |
| Product commit, stays installed | `59a1b0f95132ea51c899f590eea7e3b02c5dba43` |
| Device | `woowbk-dev-d` |
| Old immutable case | `woowbk_focus_litellm_a2c39e761b04` |
| NEW case | `woowbk_focus_litellm_b7d2480c9e36` |
| NEW canonical before, includes retained image | `dc0215912c42bd645db82f339c78729176a200f4dff03d670711c2ea40b8a325` |
| Original image verification capture | `0c5396f61187dc666c4a67162fd813facfb8571f1ef291bb40b74558a9c1bc1f` |
| Retained derived config | `af291cf14dba64dd3331179696d9bdfd70f5cacf0c92c53202d0998fe15ecaff` |
| Old complete cleanup receipt SHA | `a11bebbeabd09996174a8c9f88d6a269d2455aed2b522815056f488b296dd1cc` |
| Old fullflow02 output SHA | `3e226b8d10466ad7c6987a366de1deb002cc2205bebaaa2c7b0288b7d0576793` |
| Old resume01 output SHA | `c46799f54385cfdf9b7fcfd44ea2afdbcdb5b4fb6806c45322322f8142141c1a` |
| Cached PG17 config | `094ecc9ca4ea66931822a93f1d814e059deda57f355d9416fa72f85170871cb7` |
| Trusted package | `dd690aee2b9032cf3db0695af714a8248a0ccb0a` |
| HA fixture | `9dc5994497d9d6ff4c3ee8d3fcf86f295cf25c69d1eae98227854fee85286f27` |
| Derivation | `b15f9c4d19b95f51e85e8ec5b6ca1e52b63e064298b8bc3b0b9eb80c912a555a` |

Image USER/RootFS/base/case labels remain exactly the original a2 build facts.
b7 borrows this pinned image; owned_images=[] and retain-for-case policy prevent
claiming/removing it as a new build. Only b7 installer state, root case journal,
outside DB/role, request IDs and fresh own credentials are new. Original HA
credentials still use the actual saved reader; old generated values/state files
are not copied. Source53 and actual running proxy endpoint are checked again.

## Exclusive host preparation and root adoption

New offline-only `focus_litellm_instance_acceptance_new_case.py` pins and
revalidates the original image proof plus exact complete failed-flow cleanup
receipt/output. It refuses existing output paths, retains all old bytes, and
creates two private0600 fsynced host files exclusively:

* `litellm-instance-b7d2480c9e36.private.json`: actual flow/recover receipt, no
  before/root-init claim, complete=false, install_intent=false, no jobs/safety/
  generated credentials. Carries pinned image/cleanup provenance.
* `litellm-instance-b7d2480c9e36.pause-admission.private.json`: pause-only expected
  inventory from the original immutable proof, with the retained image already
  present. It is explicitly labelled and cannot be used for resume.

This expected before is original298e plus precisely the retained derived image
and tag. Every other field remains exact; Headscale is not filtered. Pause and
flow each read actual current inventory and reject drift. No post-failure reset
or new baseline inference. R8's exact return is parent evidence; no R8 read or
new D inventory has been performed for this preparation.

During the existing flow begin(), root init still uses Store(create=True).
Before claiming the new root namespace it validates pinned reuse metadata and
reads a2's existing root package_cleaned=true/verified terminal build proof.
It records that root state SHA and the host proof SHAs in b7's root receipt,
captures catalog absence and the actual before. Existing b7 root directory
refuses; an init refusal writes no foreign root artifacts. Host operation intent
and fixed failure details remain durable. No old root state or image is edited.

```bash
python3 -B -I /tmp/parity-focus-litellm-instance-acceptance-20261127/tests/e2e/lab/focus_litellm_instance_acceptance_new_case.py \
 --prepare \
 --image-capture /tmp/parity-focus-20261127/litellm-instance-images-verify-01.capture.private.json \
 --old-receipt /tmp/parity-focus-20261127/litellm-instance-a2c39e761b04.private.json \
 --old-output /tmp/parity-focus-20261127/litellm-instance-fullflow-02.json \
 --flow-receipt /tmp/parity-focus-20261127/litellm-instance-b7d2480c9e36.private.json \
 --pause-receipt /tmp/parity-focus-20261127/litellm-instance-b7d2480c9e36.pause-admission.private.json
```

One focused successor gate verifies complete host proof adoption with the real
image verifier, fresh flags/no old credentials, exclusive host and root files,
old host/root byte preservation, truthful a2 image label, and retained root
provenance. This does not claim another native image verification or SQL proof.

## Fresh leases and native command order — REVIEW ONLY

All leases bind the NEW exact full driver commit from handoff and source59.
All commands use the existing heavy wrapper (max2), HEAVY_FREE D mutex and
HEAVY_WAIT=60; controller acquires nonblocking D lock/priority gate. No image
build/removal, source deployment, original app mutation or wider pause is allowed.

1. New `lease-litellm-quiescence-b7-dev-d.json`, same reviewed quiescence method,
   headscale.service/source path/SHA and BOUNDS, NEW name/baseline above,
   journal_filename=`litellm-headscale-quiescence-b7.private.json`, phases
   [pause,resume], expiry<=90min and >6min remaining per command. Unit SourcePath
   SHA stays c6d93f47a70bc29395d68a1f4b699eb3bdadd8ddf37696ef47e87915f2df81b6.
   Run reviewed quiesce command with `--phase pause`, the PAUSE-ADMISSION receipt,
   new journal and output `litellm-headscale-b7-pause-01.json`. Metadata admission
   remains13GiB+512MiB, outer300s+30s, same known failed/0PID/config checks.
2. ONLY after pause PASS, a fresh80min `lease-litellm-fullflow3-dev-d.json`, same
   full-flow contract (case=litellm-instance-original; phases=[flow,recover]),
   NEW name/baseline and driver, source59 and fixed fixture/package/derivation,
   baseline_policy=require-litellm-absent, image_policy=retain-for-case. No old
   fullflow lease reuse. Launch within5min with the ACTUAL FLOW receipt:

```bash
env HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock HEAVY_WAIT=60 \
 /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
 timeout --signal=TERM --kill-after=1200 3300 python3 -B -I \
 /tmp/parity-focus-litellm-instance-acceptance-20261127/tests/e2e/lab/focus_litellm_instance_acceptance_run.py \
 --execute --phase flow --source /tmp/parity-focus-final-product-20261127 \
 --lease /tmp/parity-focus-20261127/lease-litellm-fullflow3-dev-d.json \
 --receipt /tmp/parity-focus-20261127/litellm-instance-b7d2480c9e36.private.json \
 --output /tmp/parity-focus-20261127/litellm-instance-fullflow-03.json
```

   Same21GiB floors, resource/output guards, 55min TERM+20min recovery,900s jobs
   and15min step reserve. All mandatory actual original-service checkpoints in
   full-flow-proposal.md remain: fresh full safety, actual reader, HA conversion,
   later outsider writes/password, decryption/restart, injected failure/current
   FULL rollback/witness/digests, original FULL recovery, zero-secret and strict
   original8/catalog/owned-resource return. No partial acceptance/optional skip.
   On failure stop forward and execute existing mandatory recovery. A lost reply
   uses same persisted b7 credentials and a NEW explicit recover output under
   an unexpired reviewed lease; never replay flow/install or reset complete.
3. After LL terminal + complete recovery, resume using the ACTUAL FLOW receipt,
   same b7 journal, new output `litellm-headscale-b7-resume-01.json` and an
   unexpired/new reviewed resume lease. Keep pending obligation until the exact
   original failed condition/config is proven. Parent owns command scheduling.

No step has been executed on D for b7. Host preparation alone grants no runtime.
