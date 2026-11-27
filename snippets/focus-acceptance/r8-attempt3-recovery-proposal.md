# Attempt3 recovery-only proposal; review before execution

Attempt3 stays **57/60 FAIL**,734.8seconds. Actual browser `completed:true`,
12 functional checks passed,1 cookie scan check failed; one tick/click/intent,
expected/actual issue keys0, page errors0. Issued cookies stayed in browser
memory and were not retained in protected receipts/artifacts. Counts are null;
they cannot be recovered to retroactively pass this attempt. New real-page proof
is needed after recovery and scanner runtime validation.

The shared scanner called os.walk on regular required JSON files, which its
strict error handler rejected with NotADirectoryError. Actual read-only diagnosis
identified both ha-imports.json and requests.json; this was not a secret-hit scan.
The fix reads required file roots directly and walks directory roots strictly.
Archive JSON index sidecars, requests/pending/exports and journal remain covered.

## Review artifacts and offline checks

- Controller/test diff: scan_paths file/directory distinction, explicit two-JSON
  counter, immutable rendered-program parity, protected archive union across
  generations. Missing/unsafe roots and directory enumeration errors still fail.
- Full self-contained device program: `r8-scan-rendered.py`. Its actual imports
  and complete needle/path/journal/report code are committed for one review.
  Both controller/browser and recovery-only caller use these exact rendered bytes.
- Targeted guard26/26,0fail/error/skip/blocked/shim;
  `acceptance-r8-offline-09.log`. This includes real temporary JSON-file roots,
  nested archive sidecars, unsafe paths and complete rendered-source parity/
  import checks. These are offline checks, not the required actual runtime scan.
- Original leased f0 controller/page bytes are preserved separately at
  `~/.woowbk-lab/evidence/focus-acceptance-ui-handoff/20261127T075620/`;
  manifest SHA256 `3ad10f18df43963d9d4b5a82433c72f943a4b19341f7f8a821199fc616cea5ac`.
  The original failed case files and captures are unchanged.

## Exact bounded next command, after Mencius verified cleanup and parent GO

From `/tmp/parity-focus-acceptance-20261127`:

```sh
HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock HEAVY_WAIT=600 /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/services_a_capture.py --private=/tmp/parity-focus-20261127/acceptance-r8-attempt3-recovery.private.log tests/backup/evidence/focus-acceptance-20261127/r8-attempt3-recovery-capture.json r8-independent-recovery-only -- timeout --signal=TERM --kill-after=30s 20m python3 -B -I tests/e2e/lab/focus_acceptance_ui_recovery.py --run-attempt3 --guard-sha256 87341a26d5538f67ec9102ec172cd33eaf1e9a44f25dda9e6c7aecbc4b943aa3
```

This has not run. Existing dev-d lease/globalheavy/device mutex; no source/image/
package/network change, browser, upload, import or restore. Exact attempt3 case,
full f0 driver and immutable guard/summary/recovery/browser hashes are checked.
The original summary remains57/60 and cookie coverage remains false.

The script freshly proves original three-app markers, all eight trusted image
bindings/configs, selected durable units/strict health timer metadata, schedule,
fixture and no active job. All **12** case archives (six new plus six older), the
same retained HA and both derived host copies remain protected and are not deleted.
Only the recorded own catalog entry may be removed, after proof, at its exact SHA.

Before any expensive page flow, the ACTUAL rendered scanner must run against
the device, return zero registered/new-probe hits, report both required regular
JSON roots read, and scan every actual archive JSON sidecar. Its sidecar count
must equal an independent directory count and cover all12 protected archives.
It then exercises post-scan catalog equality, unchanged old guard/failed files,
unchanged backup/HA inventories and creation of NEW immutable private/public
receipts. Report includes rendered SHA, root/sidecar counts and completed
post-scan checks. Failure retains all files/copies and causes no automatic retry.

## Subsequent real page proof

Only after the new recovery-only receipt and actual scan runtime pass should one
reviewed attempt4 use new capture filenames and that NEW receipt path+SHA. They
are published by the recovery run and cannot be truthfully precomputed here.
Fresh45minutes lease time,21GiB disk/1900MiB device headroom/1200MiB host RAM,
same frozen1ad product,20minute UI/20minute recovery. No redeploy or image recovery.
The page's cookie scan must return its own real observed-value counts and both
JSON roots before close; earlier cookie absence remains explicit. No execution
is queued while Mencius owns the current D turn or before committed review.
