# SAFETY4 — exact failure, cause and fix

Facts only; no private values. SAFETY4 ran at 2026-11-27 13:5x (Asia/Taipei) on dev-c under a 25 minute lease, driver
`ade44a2648b93d85b66f815707402eb057468c8e`, source `d09f4fe8`. Exit 1 after 34.6 s.

## What happened

- Every admission check passed: floors, original catalog pin, protected baselines, services stopped, no active job,
  original files, installed engine, no earlier safety, all exact images, ALL FOUR canonical image reference pins
  (the reference prep fixed SAFETY3's cause), private exact copies of both NOT-OWNED old safety pairs, the retention checks,
  catalog preview/CAS and scope, and the known original baseline marker.
- `fresh_full_safety_job` was false, and the finally clause then returned the original services, catalog and timer
  (`safety_stage_returns_original_services` true).
- Device facts (read-only): the newest native job record is still the SAFETY3 job `j20261127T021303Z-e2990d01` (failed,
  phase check, mtime 10:13). SAFETY4 created NO new job; the host receipt still lists only that job.

## Cause

The controller built the request id as `<case name>-<tag>`, identical to SAFETY3's `...-full-safety`. The engine
deduplicates request ids for 24 hours and answers a repeated id with the EARLIER job, so `backup-start` handed back the failed
SAFETY3 job, `settle()` saw state failed, and no backup ever started. SAFETY1 and SAFETY2 had failed before any job existed, so
SAFETY3 was the first to use the id.

## Fix (this commit)

- `request_id(tag)` appends `-a<N>` for lease `attempt` N greater than 1; attempt 1 keeps the historical id. The lease
  `attempt` must be an integer from 1 to 99.
- `job()` refuses, and leaves nothing pending, when the engine answers a new request with a job id this receipt already
  settled (`engine answered a new request with an earlier job`).
- Tests: RED on the old run.py (the lease-attempt cases and the retry/replay case fail), GREEN on the fix; the five n8n modules
  together are 55 of 55, 0 blocked, 0 shim, native denied. Product code is untouched: the engine behaves as designed.

## Next

SAFETY5 uses a new lease with `attempt: 2`, so its request id is `...-full-safety-a2`. The failed SAFETY3 and SAFETY4 captures
and the failed host receipt copy stay as they are. Any later retry of a tag needs the next attempt number.
