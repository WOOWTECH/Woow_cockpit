# R8 proposed bounded real Cockpit case — review before dev-d lease

Current status: original driver/transport reviewed and dev-d lease granted.
Actual attempt1 remains50/53 FAIL; independent recovery-only action has passed.
The original proposal below is retained as historical scope. Its attempt1
command is not a replay command; do not overwrite its evidence paths.

## Independent recovery handoff, 2026-11-27 07:02 Taipei

Reviewed recovery-only driver `90eba761`, exit0/22.5seconds, all21 fixed checks
passed. Exact original markers, durable units, images, schedule, catalog and
fixture match; active jobs0. Own Omnigent catalog entry removed at its exact
recorded SHA. Six archives and the old HA upload/host copy remain. The old guard,
receipt, failed summary and captures are unchanged. No guard override or retry.

Private receipt:
`/home/woowtechopenclaw/.woowbk-lab/evidence/focus-acceptance-ui-recovery/20261127T070216/receipt.json`
SHA256 `2d38f989848830193133967002449dafee97c3816ce9d75a2f0b95e0c39a0824`.
Public `tests/backup/evidence/focus-acceptance-20261127/r8-independent-recovery.json`
SHA256 `edb0fd01fe188080bb65a202a896d1d47a62c88988117d141bfdbc32e6868be0`.
Current scan640 records/11 archive JSON sidecars/0 hits. Old browser cookie
coverage is absent and is not retrospectively claimed. This is data recovery
proof, not an acceptance pass. Dev-d mutex released for one R4 plain turn.
Separate readiness-guard and retained-upload ownership changes will be proposed
for review before any R8 replay, after that turn.

## Replay proposal — committed diff and parent review required

One actual browser replay after the R4 plain turn releases dev-d. Product source
remains frozen `1adf4df2b548bff1626e21d1d84e677f9622e4bc`. No source deployment,
image transfer, package repair, network change or extra fixture case is in this
command. Stop if installed helper/modules/page differ from that source.

From `/tmp/parity-focus-acceptance-20261127`:

```sh
HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock HEAVY_WAIT=600 /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/services_a_capture.py --private=/tmp/parity-focus-20261127/acceptance-r8-attempt2.private.log tests/backup/evidence/focus-acceptance-20261127/r8-attempt2.json r8-real-cockpit-three-app -- python3 -B -I tests/e2e/lab/focus_acceptance_ui.py --run --source /tmp/parity-focus-r8-source-20261127 --recovery-proof /home/woowtechopenclaw/.woowbk-lab/evidence/focus-acceptance-ui-recovery/20261127T070216/receipt.json --recovery-proof-sha256 2d38f989848830193133967002449dafee97c3816ce9d75a2f0b95e0c39a0824
```

The command is proposed for review and **has not run**. It requires the exact
existing R8 lease with at least45minutes left after heavy admission; the current
expiry is00:15:06UTC. Main browser budget20minutes, each job<=600seconds and
recovery20minutes. Fresh host disk>=21GiB (13GiB reserve plus8GiB bounded writes),
host MemAvailable>=1200MiB, dev-d4GiB cap/headroom>=1900MiB. Reuse all original
installed image configs and existing Chromium/Playwright; zero additional
image/package downloads. Fresh original markers, durable units, image configs,
schedule and catalog must still equal the recovered attempt1 snapshots.

The explicit private receipt path+SHA are mandatory for this failed-case route.
The validator checks receipt scope/data recovery, the exact old guard/recovery/
summary hashes, original-state facts, sidecar scan coverage and no active job;
`acceptance_passed` remains false and old cookie coverage remains absent.
Before setup mutation, a new private case stores the old guard bytes and proof
provenance. The guard pointer is replaced only after fresh preconditions pass;
the old failed case files/public captures are never rewritten. A precondition
failure leaves the old pointer unchanged and records a separate stopped case.

The six old archive IDs must be present in the starting inventory. They are
protected existing backups, excluded from every new case-owned cleanup list.
The old HA record must match its full recorded SHA. The actual page still uploads
the derived file; normal product deduplication reuses the retained record.
`ha_record_owned:false` prevents deletion of that record. Cleanup removes only
newly created conversion/safety archives, the new derived host copy and the
exact own temporary catalog entry after original baseline and hygiene proof.
Final backup and HA inventories must equal the starting inventories, including
all old retained records. Any uncertainty retains new recoveries too.

Browser changes compute required issue keys from actual schema2 app/shared
confirm issues (zero is valid), while still requiring one general checkbox and
one import click. The browser finally block captures/scans observed cookie
values before closing even after a failed assertion; controller SIGTERM shares
that same teardown. Missing frame/values or incomplete capture remains a failed
scan, never a substitute proof. Scan counts include device
records/journal, actual archive JSON sidecars and private case files; enumeration
errors fail the scan. These cookie changes are prepared only, not a claim about
attempt1 or a substitute for the actual replay.

Targeted offline gate: **16/16 Python tests**,0fail/error/skip/blocked/shim,
`acceptance-r8-offline-05.log`; issue-key assertions **11/11** under globalheavy.
Python default/embedded scanner and Node syntax pass. The real private receipt
also validates locally at its reviewed SHA with old guard unchanged and no
device probe. These are harness boundaries only; no second real attempt yet.

## Exact transport

The controller binds a new ephemeral TCP listener to host **127.0.0.1 only**.
For each browser connection it runs exactly:

```
~/.woowbk-lab/bin/labpodman exec -i --user devadmin woowbk-dev-d python3 -I -c <fixed byte-forwarder>
```

The fixed forwarder opens only device127.0.0.1:9090 and copies stdin/socket/stdout
bytes with half-close support. Browser HTTPS and Cockpit WebSocket upgrades pass
unchanged; TLS terminates at real Cockpit. Host and Origin therefore use the same
127.0.0.1:<ephemeral port>. No device listener/configuration, published Podman port,
network mode, public bind, SSH daemon, TLS bypass inside Cockpit, or mock Cockpit
bridge. The browser accepts this lab's existing self-signed certificate.
The listener and all exec children close when this one case exits.

## Bounded command (after reviewed commit and separate lease)

From this acceptance worktree, with the coordinator's frozen source already
installed on dev-d (helper + every engine module + backup UI SHA equality is a
hard precondition):

```sh
HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock HEAVY_WAIT=600 /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/services_a_capture.py --private=/tmp/parity-focus-20261127/acceptance-r8-attempt1.private.log tests/backup/evidence/focus-acceptance-20261127/r8-attempt1.json r8-real-cockpit-three-app -- python3 -B -I tests/e2e/lab/focus_acceptance_ui.py --run --source /tmp/parity-int-combined-20261125
```

Controller takes the existing dev-d lock. Proposed lease60minutes, main browser
flow20minutes, each job<=600seconds, recovery budget20minutes. No image or package
install is in this command; source deployment, if needed, must be named in lease
setup as existing `deploy-src.sh d --src <frozen source> --no-demo-catalog`.

## Actual current page expectation

Select EMQX+Omnigent+Hermes in the real HA wizard. One child copy of the original
full encrypted four-add-on x86 fixture truncates **only** the EMQX encrypted member
by64bytes. Check must show EMQX blocked and the other two importable. The current
page intentionally excludes blocked apps: one `#ha-ack` tick + one import click
starts **two conversions + two restores**, sharing the first systemd chain unit.
EMQX remains a visible excluded result and its live baseline stays equal. Do not
assert the R1 API-only five-job model: that older driver directly requested the
failed EMQX job, whereas the actual page sends only its two importable apps.
The derived file is uploaded through the actual page too; setup does not call
the upload/check/import helper directly. WebSocket observation discards payloads
and records only fixed command/intent counts.

## Preconditions and needs

- dev-d running, networknone/zeroports, no active backup job; Cockpit socket already
  active on9090; existing app services active and original marker baselines equal.
- Existing encrypted Hermes20261119T072434Z-45b29e52 and
  Omnigent20261119T072103Z-ea792b52 open with the retained11-19 kit. Recoverable
  trusted Omnigent catalog entry comes from its own baseline if absent; no
  replacement of an existing catalog. Snapshot all catalog hashes and service/
  timer states before the case; remove only the entry installed by this run.
- Existing exact application images, no pulls or rotation during the case. Target
  installed-unit image config IDs are recorded before and after. If any image is
  absent, stop and request the specific recovery phase instead of installing.
- Device4GiB cap with>=1900MiB reclaim-adjusted headroom before heavy phases;
  host>=1200MiB MemAvailable; host>=13GiB reserve **plus8GiB** bounded copy/job peak.
  Original fixture331694080bytes, SHA256
  `f82422e327f151ec819d8e626011af965e40bf1ac78da3fa7a7bd0f869b69e1d`;
  one derived host copy and one upload.
- Existing Chromium `/home/woowtechopenclaw/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome`
  and existing Playwright package `/home/woowtechopenclaw/Woow_cockpit/node_modules/playwright-core`;
  reuse paths, no npm/browser install. Headless single page1440x900 only.

## Recovery and evidence

Private receipt records original states, inventories, owned catalog/derived copy,
HA ID, check/chain/restore IDs and only case-created converted/safety IDs. On a
browser failure, enumerate this exact uploaded HA's new jobs and follow their
`next_job_id` to terminal before restoring. Never race an active job or guess that
no job started after a browser timeout. Restore both changed apps from the saved
original encrypted baselines, compare exact marker snapshots, preserve EMQX, check
health and catalog/service/timer equality. Delete only owned archives/upload/copy
and temporary catalog after baseline proof plus zero-hit secret scan. On any
uncertainty retain all recovery copies/receipt and the temporary catalog needed
for restore; close the host relay/browser regardless. No global backup deletion.

Public evidence contains commit/hash/count/status only; private screenshots only
at confirmation/result of the backup iframe with every input masked. No key,
password, cookie, WebSocket payload, raw console text or trace is published.
R8 has no result yet; no broader acceptance claim follows from offline checks.

Review files: `tests/e2e/lab/focus_acceptance_ui.py` (bounded controller/recovery),
`focus_acceptance_ui_page.mjs` (actual browser), `focus_acceptance_ui_relay.py`
(fixed private transport), `focus_acceptance_ui_test.py` (offline boundaries).
No device state or listener is touched by either driver's default invocation.

If automatic recovery cannot finish, do not invoke --run again: the existing
case guard refuses over `~/.woowbk-lab/run/focus_acceptance_ui.json` unless recovery
was verified. Retain that0600receipt and its `evidence_dir/recovery.json`.
Read the receipt's `inflight` with existing
`tests/e2e/lab/engine.sh d job-status '{"job_id":"<recorded id>"}'`; wait for that
job and its recorded next job before any restore. Baseline restore intent is
`restore-start` with the exact saved baseline ID above, `apps:["hermes"]` or
`["omnigent"]`, `confirm:true`, and the11-19 kit supplied **only on stdin** through
the existing credential reader. Re-inspect first; an unexpected confirmation
requires review instead of automatic acknowledgement. The controller already
implements that recovery; this manual path is only for an interrupted controller.
Keep both original baselines, every recorded case safety/converted archive and
the own catalog entry until original markers/service/image/timer states and
zero-hit scan are verified. Do not hand-clear the receipt to bypass recovery.
