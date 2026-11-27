# Source-only d09 install/recovery — proposal, not authorized

The image-only phase is complete (01968cf7 public receipt):24 runtime checks and
15 independent read-only comparisons passed; two exact image configs retained,
all prior configs/four protected baseline files/catalog/services/volumes preserved,
heavy slot and dev-c mutex released. This proposal does not rerun those images.

## Exact payload and scope

Product `/tmp/parity-focus-final-gate2-20261127` must be clean exact
`d09f4fe8e06305aff6a1150f41d6de719e7b7f6a`. Manifest in
`source-payload-manifest.json` binds every engine Python file, installed VERSION
and helper. Host and device independently decode/compile/hash the fixed payload.
No UI, systemd unit, other source checkout, catalog, keys or app files are installed.

`deploy-src.sh` runs `manage.py install`, whose backup install also manages UI,
schedule units, live dependencies and other package state. The new controller
uses its exact trusted engine/helper/VERSION selection and modes in a smaller
protected transaction. It invokes neither installer. No apt/package operation,
pull, retag, key initialization, helper command, daemon reload, app/PG start,
SQL, catalog edit, schedule masking or image mutation is implemented here.

## Transaction and recovery

1. Require exact clean driver/source, granted phase/time/payload/bounds lease,
   successful existing private image receipt and exact case name. Heavy slot,
   nonblocking whole dev-c mutex, outer `true none {}`, fresh host>=1200MiB,
   host>=13GiB+8GiB available and device>=1900MiB reclaim-adjusted headroom.
2. Root transaction takes the same paths/order as production jobs.py: start
   decision `/run/woowtech-backup/jobs.lock`, then `engine.lock`, both nonblocking.
   Reject queued/running jobs, any running inner container, active app unit or
   changed four protected baseline facts. Schedule remains as found; the locks
   prevent a backup start while source publication is in progress.
3. Before changing installed source, snapshot the ENTIRE bounded existing library
   (including VERSION, existing bytecode and opaque regular files), helper,
   directory/file bytes, SHA, mode, uid/gid and mtime_ns. Root0700 private copy and
   journal live at `/var/lib/woowtech-backup/focus-n8n-instance/<case>-source`.
   This is a sibling of the image/flow recovery Store, so flow cleanup cannot
   remove the prior source copy. Partial copy never authorizes publication.
4. Stage root0755 directories/root0644 files beside the engine, root0755 helper
   beside the helper. Compile source and probe ONLY existing `age --version`,
   `age-keygen --version`, `zstd --version`, isolated Python nacl/cryptography and
   candidate CLI/n8n/access/adapter imports. All standalone imports disable
   bytecode writes AND set a nonexistent pycache prefix before product imports.
5. Fsync prior intent, atomically exchange engine directories with Linux
   renameat2(RENAME_EXCHANGE), atomically replace helper and fsync its directory.
   VERSION moves with the engine. Recheck every published hash and imports,
   unchanged catalog/app files/units/timer/volumes/images/protected baselines.
   Two roots are a journaled transaction, not a simultaneous multi-path swap;
   locks protect jobs and failures trigger exact original-source recovery.
6. `source-recover` checks current source is exactly original or recorded candidate;
   refuses unknown edits or damaged private copies. Rebuild original directory
   metadata from the protected copy, atomically exchange, restore exact helper
   bytes/mode/uid/gid/mtime_ns and compare the entire prior source tree. Preserve
   all private copies and recognized staging after recovery. Nothing is broadly
   deleted. A lost transport/process is recovered from the pre-publish intent;
   uncertain source-install is never replayed automatically.

Maximum source tree64MiB/4096 entries,96MiB request; phase operation300seconds,
600seconds reserved for recovery; proposed20minute lease, hard <=40minutes.
Private source state/host receipt stay0600/0700. Original source includes any
pre-existing caches; candidate imports never read/write them. Inode/ctime/access
time and parent-directory mtimes are outside exact recovery equality. Atomic
directory exchange must be available; no delete/rename-gap fallback exists.

On verified install, retain d09 and all prior-source recovery artifacts for the
separately reviewed safety/full-flow phase. On failure, attempt only granted
source-recover; preserve uncertainty and artifacts. Original source recovery is
available after later full app baseline recovery, while all services are stopped.
The retained source copies/staging need separately bounded cleanup afterward.

## Proposed commands, after exact coordinator lease only

From `/tmp/parity-focus-n8n-instance-acceptance-20261127`, after updating the inert
`source-lease.example.json` to a granted exact driver/payload/time lease:

```sh
HEAVY_FREE=/tmp/woowbk-dev-c-mutation.lock HEAVY_WAIT=600 /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh python3 -B -I tests/e2e/lab/services_a_capture.py --private=/tmp/parity-focus-20261127/n8n-source-attempt1.private.log /tmp/parity-focus-20261127/n8n-source-attempt1.json n8n-instance-source -- python3 -B -I tests/e2e/lab/focus_n8n_instance_acceptance_source.py --execute --phase source-install --lease /tmp/parity-focus-20261127/lease-n8n-instance-source-dev-c.json --source /tmp/parity-focus-final-gate2-20261127 --receipt /home/woowtechopenclaw/.woowbk-lab/run/focus_n8n_instance_source.json --image-receipt /home/woowtechopenclaw/.woowbk-lab/run/focus_n8n_instance_acceptance.json
```

Separate recovery command: identical parameters with phase `source-recover` and
fresh `n8n-source-recover-attempt1.{json,private.log}` capture paths. Driver also
attempts that phase automatically on an install failure if explicitly granted.
No source runtime is authorized by the earlier image-only lease.

## Future safety PG16 correction

`pg16-role-query-reference.json` pins the roles/settings queries extracted by AST
from Kuhn95617696, whose existing real PG16 c04 proof passed87/87. The revised
safety snapshot uses those EXACT two queries: no pg_authid.rolconfig; independent
ALL pg_db_role_setting rows joined by role/DB names. Zero/global OIDs survive as
NULL names because both joins are LEFT and no WHERE filters any row. Settings
arrays are hashed independently alongside role/password facts/memberships and
all DB/row/type/ACL/extension snapshots. Offline tests compare actual immutable
helper source and exercise changes to role-only, DB-only and both-global rows.
This reuses existing real schema/execution proof; it is not a new PG or original
n8n safety run. The failed c03 history is preserved by its owner, not counted.

All source/controller tests here are offline. The actual source transaction,
safety backup and original n8n instance full flow remain unexecuted pending lease.
