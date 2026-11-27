# Proposed image-only lease — NOT authorized or executed

## Exact inputs

- Controller: clean HEAD of `focus/litellm-instance-acceptance-20261127` in
  `/tmp/parity-focus-litellm-instance-acceptance-20261127`; coordinator binds the
  full SHA reported with this proposal in `driver_commit`.
- Frozen product: `/tmp/parity-focus-final-product-20261127`,
  `59a1b0f95132ea51c899f590eea7e3b02c5dba43`. No product deployment occurs in
  either image phase.
- Existing dev-d app-owner cached base config:
  `0c71bec8f80e3445267e9bc08495d3782b5c80c8fb7ca18261f07abad00ce312`,
  amd64/Linux, USER65534, no declared VOLUMEs, 25 recorded RootFS layers.
- Trusted package: `dd690aee2b9032cf3db0695af714a8248a0ccb0a`.
  Existing saved80 source SHA256:
  `f9455650d20189cef7d083ed967bb8b485190fbff44a378b152bcd28f69f8cf3`.
- Exact saved derivation bytes SHA256:
  `b15f9c4d19b95f51e85e8ec5b6ca1e52b63e064298b8bc3b0b9eb80c912a555a`:

```Dockerfile
FROM sha256:0c71bec8f80e3445267e9bc08495d3782b5c80c8fb7ca18261f07abad00ce312
USER 0
RUN chown -R 1000:0 /app/.venv/lib/python3.13/site-packages/prisma
USER 1000:0
LABEL io.woowtech.lab.derived-from=sha256:0c71bec8f80e3445267e9bc08495d3782b5c80c8fb7ca18261f07abad00ce312
```

The builder also receives `--from sha256:<same full config>`. The resulting
image must inherit all exact base layer digests, have USER1000:0, the exact base
label and unique case label, and have an iidfile/config/tag agreement. Separate
inspection of the base alone cannot satisfy this check. The extra case label
is controller provenance; connection inputs and trusted package startup stay
unchanged.

## Namespace, baseline and receipts

Proposed name: `woowbk_focus_litellm_a2c39e761b04`.
Only new application tag: `localhost/woow-litellm:1.104.0-0.3.16`; initial absence
is mandatory. Both cached bases and every existing image/tag/layer remain
protected. PG17's human tag is absent; it is not created by the image phase.

Read-only baseline canonical SHA256:
`60a8e16f1bfe4d0a86ae9de03b3a16580884eff9e40a4922f54b2451929609aa`.
Full private baseline is
`/tmp/parity-focus-20261127/litellm-instance-image-baseline-readonly.json`;
selected metadata is in `image-readonly-facts.json`. Fresh baseline equality,
eight original container IDs/names, all Quadlet/catalog hashes, durable volumes,
networks, secret IDs, service/timer states and no active jobs are mandatory.
The current schedule is inactive/masked. This phase never changes it.

Host private receipt:
`/tmp/parity-focus-20261127/litellm-instance-a2c39e761b04.private.json`.
New public attempt result:
`/tmp/parity-focus-20261127/litellm-instance-images-01.json`.
Root-only durable journal/logs:
`/var/lib/woowtech-backup/focus-litellm-instance/woowbk_focus_litellm_a2c39e761b04/`.
Private build context:
`/home/appowner/.local/state/woowbk_focus_litellm_a2c39e761b04_images/`.

The journal records intent before context/build, owned PID/group, terminal
state, full fixed before/after inventories, all image configs/tag bindings,
new layer digests, unknown intermediates, disk before/after/minimum, current
owned full config IDs and cleanup intents. Raw errors stay private0600.
Successful image-only preparation retains the single labeled derived image for
the separately reviewed future service case and removes its build context.

## Admission and execution bounds

- Queue after R8 using existing dev-d mutex and EMQX priority marker. Global
  heavy wrapper still limits two jobs; no host Podman, pull, network, port,
  engine install, service start, database connection or credential read.
- Host available memory >=1200MiB; device reclaim-adjusted headroom >=1900MiB.
  Actual host/home/staging/storage free >=13GiB reserve +8GiB peak (21GiB).
  Observed read-only free was ~26.7GB; runtime freshness is required.
- Builder: network none, pull never, 512MiB memory+swap cap, one CPU, jobs1,
  layers false, rm+force-rm true, proxy inheritance disabled.
- **Device-side supervisor** creates its own process group; 600s build bound,
  TERM then30s KILL/wait, including early-parent-exit children. Signals and
  reserve loss take the same path. The device guard watches the actual 13GiB
  disk reserve. Host RPC720s; outer command1200s +60s final kill allowance.
  Live descendants or leftover external build containers cannot pass.
- The root supervisor launches `/usr/bin/podman` directly with the ordinary
  appowner UID/GID, empty supplementary groups and the installed
  `device/woowbk-owner` wrapper's fixed environment. It checks actual proc
  UID/GID and process group before journaling startup. This binds supervision to
  the builder itself; a runuser wrapper's separate session is not assumed.
- Suggested lease45min including queue, phases `images` and `images-recover`,
  `image_policy=retain-for-case`, `baseline_policy=require-litellm-absent`.
  Controller rejects expiry beyond80min, and requires15min recovery reserve
  before image admission. A shorter actual reviewed lease is acceptable.

Coordinator lease JSON must carry `granted=true`, case
`litellm-instance-original`, device `woowbk-dev-d`, exact driver/product SHAs,
name above, fixture SHA `9dc5994497d9d6ff4c3ee8d3fcf86f295cf25c69d1eae98227854fee85286f27`,
derivation SHA, package commit and canonical baseline SHA above, timezone-aware
`expires_utc`, phases and both explicit policies. No lease is created by this
preparation commit.

```bash
env HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock HEAVY_WAIT=1800 \
  /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
  timeout --signal=TERM --kill-after=60 1200 \
  python3 -I /tmp/parity-focus-litellm-instance-acceptance-20261127/tests/e2e/lab/focus_litellm_instance_acceptance_run.py \
  --execute --phase images --source /tmp/parity-focus-final-product-20261127 \
  --lease /tmp/parity-focus-20261127/lease-litellm-images-dev-d.json \
  --receipt /tmp/parity-focus-20261127/litellm-instance-a2c39e761b04.private.json \
  --output /tmp/parity-focus-20261127/litellm-instance-images-01.json
```

## Recovery and honest failure

`images-recover` uses the same source/receipt/lease with a NEW output ending
`images-recover-01.json`. It requires a proved terminal builder, exact original
durable application state, known labeled image IDs, no unknown image/tag
changes, and validated owned context. Removal intent precedes each full-ID
`image rm --no-prune`; no force/prune. A lost removal reply is reconciled by
the recorded intent and remaining exact config IDs. Both bases, original tags
and original eight apps must remain unchanged. Original image equality gates
the recovery result.

All raw inventories are retained. Headscale crash-loop or health timer churn
currently causes an honest failure: there is no general transient-ID exception.
A rejected baseline **before device init/build** may use a freshly reviewed
lease pin and unique output with the same private receipt; observations append,
never overwrite. Once init/build intent exists, there is no silent baseline
reset or automatic rebuild. Resource drift or unknown ownership retains the
image/context/receipts for concrete review; it cannot yield a pass or affect
an existing application. Archive lookup uses the engine's archive_path API,
never a sidecar-sensitive archive glob.

## Prepared gate and next scope

Offline controller checks cover real filesystem CAS/absence/foreign edits,
real instance catalog normalization, strict lease/default-offline boundaries,
lost job and image-removal replies, full-current-rollback equality requirements,
compiled device/reader/witness programs, exact saved source/FROM binding and
real local process-group success/timeout/resource/early-exit cleanup. Host guard
denies runtime device/native operations. This remains preparation evidence.
Final targeted gate: **19/19 PASS**, zero failure/error/skip/blocked/shim,
`litellm-instance-controller-final07.log`. The ordinary-owner identity gate
rejects root/ambiguous input before spawn; real child/group cleanup is tested
with local Python children. Actual rootless image execution remains for the
separate lease.

The later `flow` lease is separate: fresh owned package fixture, actual installed
proxy reader, original encrypted fixture, API keys/provider decryption, restart,
later outsider changes, forced automatic full-current safety rollback, original
full recovery, catalog CAS restoration and owned-resource cleanup. That flow
has not run and is not authorized by this proposal.
