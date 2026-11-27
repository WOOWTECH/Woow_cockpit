# Standalone reference prep — CODE ONLY; fresh lease required

## Native SAFETY3 failure and exact return

Driver8c28955244842bb1790f4d02283694ed1e0bd5e7 exited1/75.7s.
Job `j20261127T021303Z-e2990d01`: FAILED, code`job-failed`, phase`check`,
fixed message`找不到應用使用的映像 docker.io/n8nio/n8n:2.43.6。`.
Prepare completed; stop/dump/export/start/package/verify were not reached.
No full safety exists. This is not evidence of a PostgreSQL export failure.
`safety-attempt3-failure.json` preserves actual capture/job/log/evidence hashes.

All10 durable groups equal the NATIVE pre-service baseline, including previously
authorized retained2 config IDs; all124 preexisting managed backup files and
four old-pair private copies exact, original manual4 protected, source hashes
exact,0activejobs/0runningcontainers, catalog/cold/timer returned. The job and
all private copies remain. An erroneous first readonly diagnostic rehashed the
inventory per entry; only that exact owned probe was terminated rc143. Its empty
capture and corrected single-pass proof remain; it made no app writes. No retry,
restore/prune/delete, source install or image load/pull was performed.

## Fresh bounded read-only facts

`n8n-reference-prep-readonly.json` records six cached configurations. All four
required configs are`linux/amd64`, variant empty. ALL seven current source
Quadlets match the fixed original references below. Both canonical n8n/runner
tags are absent (`image exists` exit1), while both cached config IDs resolve
exactly. PG and Valkey existing canonical refs resolve to their pinned IDs.
Earlier direct inspect rc125 alone was not treated as proof of absence.

| Fixed reference | Cached config ID | Planned change |
| --- | --- | --- |
|docker.io/n8nio/n8n:2.43.6|c8d7cd6bf08e1837180b767d77903889e0f3f022accda90579f5e99ca2a2bdfb|add only if still absent|
|docker.io/n8nio/runners:2.43.6|28c5a510d7624e5ce079d2204e4d8421bc96ced83ebc2e1717d6ee33a0ccc1bb|add only if still absent|
|docker.io/library/postgres:16.15-alpine|4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873|existing alias must stay exact|
|docker.io/valkey/valkey:8.1.11-alpine|650ff8153447d257696648bc63a77522cf6e760145be45ce65a408a918229915|existing alias must stay exact|

Source n8n/worker/webhook all use the first ref; both runners use the second.
These values come from trusted installed Quadlet parsing, not backup metadata.
If a proposed alias already resolves correctly at admission, leave it alone
and omit it from the actual planned delta. Any foreign ref/config/platform,
missing PG/Valkey ref, non-absence error, unexpected cache ID or changed original
source/config/catalog/services/backups refuses before tagging.

## Small separate transaction

`focus_n8n_instance_acceptance_references.py` is OFFLINE by default. The explicit
`image-references` phase uses its OWN host receipt and root0700 journal:

- Host`~/.woowbk-lab/run/focus_n8n_instance_acceptance.references.json`.
- Root`/var/lib/woowtech-backup/focus-n8n-image-references/woowbk_focus_n8n_28a4a4b1cbcd/`.

The existing main flow host receipt and qualified source-fullflow receipt are
not changed. The latter SHA remains
`99b20bc3053f2f10c3541ad2cd1a78b2e6482e68b28f72f04ee81fb3799523f2`.
No original baseline is reset. This new receipt explicitly records a separate
retain-for-case reference delta and its exact before-state hash.

1. Existing C mutex, then native jobs.lock→engine.lock, all app units stopped,
   no running container/activejob. Original native Store baseline must match
   catalog/entry/files/protected/units/timer/volumes/running/jobs/retention;
   cache IDs must be exactly original+the two already authorized retained IDs.
2. BEFORE any tag, persist the complete before snapshot: every managed backup
   hash+attributes; original exact7Quadlet refs; installed full engine tree
   (including opaque/cache files), helper/VERSION; original private case trees
   and all source1/source2/source-fullflow staging; full cache config identity,
   platform, aliases/history and SHA of ALL remaining inspection fields. Config/
   environment values and raw stderr never enter public output. Existing Store,
   tree and preservation streaming readers are reused. Old private copies verify.
3. For each actually missing approved alias, recheck resource floors and the
   complete snapshot. Verify absence with `podman image exists` (exit1 only),
   durably persist its expected config and absence intent, then execute ONLY
   `podman tag sha256:<exactConfig> <fixedReference>`. Correct existing aliases
   are not tagged; a foreign alias refuses. The exclusive lease/C/native locks
   serialize authorized image writers; Podman tag itself has no atomic
   compare-and-set guarantee against an uncoordinated external writer.
4. After each call, verify exact reference identity, same ALL config IDs and
   ALL non-alias inspection fields, same source/qualified receipts/data/catalog/
   units/timer/backup files. Only the intended aliases may be added to RepoTags
   and NamesHistory; old names remain, all other aliases remain exact. Unexpected
   derived-field changes also refuse rather than weakening that comparison.
5. Any timeout/lost reply stops without repeating a tag or deleting anything.
   Separate `image-references-reconcile` reads current identity and validates the
   permitted intent subset. An exact applied tag can be reconciled; absence is
   reported incomplete; a foreign tag refuses. Reconciliation issues NO tag
   command. Complete requires all planned aliases observed. Evidence/journals
   stay on every failure. No automatic fallback, retry or cleanup.

No pulls, loads, new configs/containers/volumes, image deletion, source changes,
helper calls, SQL, package installs, catalog/timer/daemon/service actions. Both
standalone phases preserve cold state. The two added refs are explicitly
retained for this acceptance case; a later cleanup needs its own reviewed scope.

## Targeted evidence only

`n8n-reference-prep-final.log`:7/7,0fail/error/skip/blocked/shim, native denied.
Actual SAFETY wrapper with cached IDs but missing/foreign canonical refs refuses
BEFORE copy/service/SQL; all correct refs reaches the preservation boundary.
Missing-only alias selection, foreign ref refusal, durable intent before tag,
lost applied reply reconciled without another tag, changed source/backups/cache/
extra alias refusal, complete rendered module/JSON dispatch and exact lease/
offline default covered. The first rendered-entry test caught missing namespace
imports (5pass/1error); fixed and failed log retained. Six-method intermediate
and seven-method final runs overlap;7distinct methods total, not13/19.
No old5/34/nativePG87/image-load/source suite repeated.

## Concrete commands — NOT GRANTED

Fresh25minute lease, exact new driver/source/case/expected refs/allowed delta/
qualified source-receipt SHA and unchanged bounds. Product frozen clean
`/tmp/parity-focus-final-gate2-20261127`
@d09f4fe8e06305aff6a1150f41d6de719e7b7f6a. Driver full SHA and code hashes in
external`n8n-reference-prep-bindings.json`. Global2heavy; no waiting for C while
holding a heavy slot; host1200MiB/device1900MiB and13GiB+8GiB DATA floors unchanged
before snapshot and each binding. Only small journal/receipt writes; no image
payload allocation. Existing original source/image/safety evidence immutable.

```sh
HEAVY_FREE=/tmp/woowbk-dev-c-mutation.lock HEAVY_WAIT=0 /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/services_a_capture.py --private=/tmp/parity-focus-20261127/n8n-reference-prep-attempt1.private.log /tmp/parity-focus-20261127/n8n-reference-prep-attempt1.json n8n-instance-reference-prep -- python3 -B -I tests/e2e/lab/focus_n8n_instance_acceptance_references.py --execute --phase image-references --lease /tmp/parity-focus-20261127/lease-n8n-instance-references-dev-c.json --source /tmp/parity-focus-final-gate2-20261127 --receipt /home/woowtechopenclaw/.woowbk-lab/run/focus_n8n_instance_acceptance.references.json
```

Explicit reconcile ONLY if parent grants it: same command/lease/receipt, phase
`image-references-reconcile`, NEW exclusive captures
`n8n-reference-reconcile-attempt1.{json,private.log}`. No automatic reconciliation
run. Actual prep success and a separate fresh SAFETY4 lease are required before
another backup attempt. SAFETY now checks all4 canonical reference→config pins
before preservation/service/SQL; the cached-ID-only check is retained too.
