# R8 cookie observer: one read-only diagnostic probe

## Existing actual failure stays unchanged

Parent page4 on driver14ebdf8e exited1/757.7seconds, **59/63 FAIL**. The actual page completed, both imports/four jobs/safety backups/live data and both original baseline restores passed, and the registered-value static scan passed. Its cookie observation was complete but reported2values/8devicehits/0hosthits,648devicefiles/17sidecars/2JSONroots. Those values were memory-only and cannot be recovered or retroactively proved absent. No new full import is proposed.

The worker inspected the current private failed guard locally: case20261127T082326, baseline_restored=true, inflight=null, phase=recovery-retained. GuardSHA is `329fba10a4e4e290209fa7ae5e5545549214227a38d0c0033473234569581b67`. Failed captures/guard/case remain untouched.

## Code and primary source findings

The existing page's response observer takes every Set-Cookie first-pair value and retains it in a Set. It loses the name and expiry/lifetime attributes. The final context jar contributes additional values; overwritten or expired first-pair values remain. The device scanner scans the union without distinguishing credential values and public protocol constants. Therefore a common public constant can produce generic substring matches. **This explains a possible mechanism, not the actual page4 eight hits.** An actual credential leak, renewal/history mismatch, or observation/encoding ambiguity still needs to be ruled out by per-value counts.

Pinned Cockpit337 source at commit `2248c46ff19ce77dbf12e4d7fc6af0e702072171` shows the login-page handler calling auth_empty_cookie_value and the auth implementation returning a fixed clearing value. That exact source variant has no Expires/Max-Age. It must not be described as HTTP-expired. Normal login emits the authenticated session cookie separately. See [auth source](https://github.com/cockpit-project/cockpit/blob/2248c46ff19ce77dbf12e4d7fc6af0e702072171/src/ws/cockpitauth.c#L1609-L1624) and [login-page handler](https://github.com/cockpit-project/cockpit/blob/2248c46ff19ce77dbf12e4d7fc6af0e702072171/src/ws/cockpithandlers.c#L445-L453).

`focus_acceptance_ui_cookie_source.json` binds the exact commit/URLs/full source SHA256s. Public primary-source bytes were fetched to a separate immutable private source cache; no device was accessed. The executable probe independently rehashes both cached files before browser startup. It captures actual WebSocket init system.version, an actual root administrative Cockpit bridge (`id -u`/hostname), and native cockpit-ws package version plus binary SHA through that bridge. None of these facts come from caller-supplied booleans. The binary digest is an observation, not a reproducible-build claim.

## Strict classification

- Parse individual headerValues fields, never split on the Expires comma. Valid Max-Age controls expiry over Expires ([RFC6265](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.3)). Record expiry as a timestamp and Max-Age as an integer. Expired, renewed, overwritten, short, unknown and still-live non-sentinel values all remain strict zero-hit credentials. No length heuristic.
- Only the pinned public constant hash can be classified as a public protocol tombstone, and only after actual Cockpit337 native package/WS version, cached primary source hashes, initial HTTPS root GET200, exact rootPath/SameSiteStrict/Secure/HttpOnly attributes, genuine root bridge, a separately observed authenticated live cookie and absence of that marker from the authenticated live jar are all proved. No caller-controlled policy. Other versions/metadata remain unexempted.
- Every observed value, including any proved public marker, is still scanned. Results separate marker match counts from the credential zero-hit assertion; no hits are discarded. Exact old observer first-pair values are also retained alongside parsed values and both initial/final jars.
- Missing headers, unknown jar values, duplicate/invalid lifetime attributes, empty pairs, callback failures or late jar changes fail coverage. Expiry alone never permits an exclusion. HTTP-expired while still live is ambiguous and fails.

## Exact bounded action after review and new lease

This packet does not start a device action. Parent reported noauth24/24 and verified D release00:44; a new probe lease and exact committed driver binding are still required.

Update the existing lease: devicewoowbk-dev-d; driver_worktree `/tmp/parity-focus-acceptance-20261127`; driver_commit the full packet commit; active_reviewed_phase `cookie-observer-readonly`; cookie_probe_guard_sha256 the above329f hash; expiry with >=12minutes remaining at admission. Frozen product stays1adf4df2b548bff1626e21d1d84e677f9622e4bc and clean. No deploy/source/image/package/auth-config/network changes, uploads, HA check/import/restore, catalog changes or app API marker logins.

```bash
HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock HEAVY_WAIT=600 /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/services_a_capture.py --private=/tmp/parity-focus-20261127/acceptance-cookie-probe01.private.log tests/backup/evidence/focus-acceptance-20261127/r8-cookie-probe01.json cookie-observer-readonly -- timeout --signal=TERM --kill-after=30s 10m python3 -B -I tests/e2e/lab/focus_acceptance_ui_cookie_probe.py --run --guard-sha256 329fba10a4e4e290209fa7ae5e5545549214227a38d0c0033473234569581b67
```

Run from the assigned cde worktree after committing this packet; no parent cherry-pick required for this isolated probe. Whole-probe dev-d mutex and globalheavy; no overlap with noauth/LiteLLM. Host>=1200MiB available RAM/device>=1900MiB headroom/disk>=21GiB, retain13GiB. Existing Playwright/Chromium/Cockpit/images only. Browser deadline6min, child<=8min, outer10min. Default invocation compiles offline and opens nothing.

The same reviewed relay binds only host127.0.0.1 ephemeral, sends opaque TLS/WS through unprivileged labpodmanexecstdio to device127.0.0.1:9090. Browser logs in, elevates its session, opens the backup listing iframe and performs the real root identity/native-capability handshake. It does not enter the HA wizard. Only fixed identity/version commands and a stdin-fed read-only scanner run through the real bridge.

The full standalone scanner is `r8-cookie-scan-rendered.py` (SHA256 `50b7639d16a14dbe309f5d440f4cdee9ef9a8c665b7244bf14b9675c86445f12`). Both regular required JSON roots are read directly; all actual archive JSON sidecars are scanned and independently counted. Each input is reported only by SHA256/length with hit counts and fixed path categories: jobs,ha_metadata,ha_registry,requests,archives,archive_index_sidecars,run,uploads,staging,pending,exports,journal,private_probe_evidence. No pathname containing credentials, matching text, raw cookie/header, context state, response/frame, HAR or trace is saved. Encrypted archive data retains the existing scan exclusion.

## Receipts and recovery

New private0700/0600 evidence under `~/.woowbk-lab/evidence/focus-acceptance-ui-cookie/<stamp>/` contains metadata, full rendered source, result and immutable receipt. Cookie values and registered credentials remain in memory/stdin only. Receipt binds exact failed guard/old-case hashes and before/after archive/HA metadata/catalog/schedule inventories, activejobs0 and network isolation. Raw child stderr is suppressed; only its byte count is retained. Never rewrite old page4 evidence or claim old cookie absence. `acceptance_passed:false` and `proves_old_page4_cookie_absence:false` remain explicit even if this new probe succeeds.

On failure: close this browser/relay, release this mutex, retain new metadata/receipts and report exact per-hash/category findings. No app restoration or mutation is needed or authorized for this read-only action. No automatic retry. Parent controls the following D slot.
