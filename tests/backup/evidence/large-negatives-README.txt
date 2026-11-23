Bounded >8GiB encrypted late-tail failures and REAL job cancellation (2026-11-23, source 1e91626, x86_64 host).

Actual run (attempt 1, exit 0, 746 s):
  python3 tests/backup/record_attempt.py --name large-negatives-8193mib -- \
      tests/backup/bounded_large_negatives.py --mib 8193 --scratch-parent /tmp
  -> large-negatives-8193mib.stdout.json (probe report byte for byte, sha256 28082642c69d...6371)
     large-negatives-8193mib.attempt.json (exit code, status lines, elapsed, stdout sha256, source commit)
Real smoke (128 MiB, exit 0): large-negatives-smoke-128mib.{stdout,attempt}.json
Safety checks: large-negatives-safety-tests.txt (32 unit tests OK, includes the earlier large harness tests)
Provenance: large-negatives-provenance.json (engine files byte-identical to feat/ha-import-batch1 b2f63ce;
archive.py sha256 85b58635... is the same file the earlier 2GiB/8193MiB runs used). No product code changed,
no import guard touched.

Fixture (real): payload 8,590,983,168 bytes (8193 MiB, above 8GiB) of the existing compressible SHAKE256 tile
keystream, written by the real age X25519 + zstd writer (archive.write_archive) with a fresh ephemeral age key in
private 0700 scratch (identity 0600). Ciphertext 34,503,003 bytes, archive 34,519,040 bytes.
How the payload reached the writer (harness storage measure, stated plainly): a sliding-window REGULAR file of
logical size 8193 MiB; the harness wrote keystream 64 MiB ahead of the engine's sequential reader and punched holes
16 MiB behind it from the writer's own progress callback (which runs between reads in the reading thread), so at
most 92,278,784 bytes were ever allocated. Proof that no hole was read: the engine compares its own sha256 of every
byte it read with the independently precomputed keystream sha256 and would refuse; it accepted.

Cases (public engine calls; each counts age/zstd children while active (2 seen) and after return (0), checks every
observed child pid was reaped and that pipes/anonymous temp fds return to their baseline (delta 0)):
  control-verify            unchanged original: verify_archive passed, 8,590,983,168 bytes (attribution control)
  flip-last-byte-verify     last ciphertext byte flipped, outer backup.json size/sha256 recomputed (describe with
                            check_members passes, authenticated manifest prefix readable): corrupt-archive after
                            8,581,280,768 bytes of progress (late minimum 8,523,874,304)
  truncate-last-byte-verify last ciphertext byte removed and rewrapped the same way: corrupt-archive at
                            8,577,086,464
  truncate-last-byte-extract same archive through extract_archive: corrupt-archive at 8,581,805,056; the engine wrote
                            8,581,805,056 logical bytes; the HARNESS punched holes behind the engine's write offset
                            (max 17,825,792 bytes allocated) to keep the host reserve; before any harness cleanup the
                            extraction root existed and was EMPTY: the engine removed its partial output itself
  cancel-extract            restore 'decrypt' window: real JobStore/JobReporter/FlowContext in scratch; once progress
                            passed 4 GiB a second thread ran jobs.cancel_job (the job-cancel command's function,
                            accepted: state running, request recorded) and the real FlowContext.byte_progress('解密並驗證')
                            raised flows.Cancelled at 4,297,978,880 bytes; partial output 4,298,043,392 bytes REALLY
                            allocated (no punching); root EMPTY before harness cleanup; sampled free space rose by
                            4,298,059,776 bytes after the engine's cleanup
  cancel-write              backup 'package' window, same real job cancel during write_archive at 4,294,967,296
                            bytes: flows.Cancelled; the staged .tar.tmp and the .recipient- file were seen while
                            writing and BOTH were gone afterwards (staging empty), destination never created
After all cases: original archive sha256 unchanged, 0 files in scratch containing an age secret-key marker other than
the ephemeral identity itself, scratch and key removed by the harness, 0 tool children at exit.
Space: free before 21,362,221,056; minimum sampled 17,210,093,568 (12GiB reserve + 256MiB guard enforced every
250 ms and in every progress callback); free after cleanup 21,542,596,608. Max RSS 34,792 KiB.

Attempt with the REAL job-cancel CLI command (source 2bfe810, exit 0, 523 s,
large-negatives-cli-cancel-8193mib.{stdout,attempt}.json, --cases cancel-extract,cancel-write; the fixture write
always runs; the other cases are unchanged code and stand on the run above). Real smoke 128 MiB with all cases:
large-negatives-cli-cancel-smoke-128mib.* (exit 0). The cancel now comes from a SEPARATE PROCESS running
woowbackup.cli job-cancel with {"job_id": ...} on stdin, exactly as the Cockpit page sends it (backup.js call():
cockpit.spawn([HELPER, 'job-cancel']) + JSON input); test hooks only: Paths(base=scratch) and require_root=False.
The harness settles the job the way jobs.run_job does (finish 'cancelled', clear the request file).
  cancel-extract  command exit 0 {"ok": true, "state": "cancelled"}; flows.Cancelled at 4,301,911,040 bytes
                  (threshold 4 GiB); partial output 4,301,955,072 bytes really allocated, root EMPTY before harness
                  cleanup, sampled free space +4,302,077,952 after the engine's cleanup; job record cancelled,
                  not cancellable, request cleared; children 2 seen / 0 after, fds delta 0
  cancel-write    command exit 0 {"ok": true, "state": "cancelled"}; flows.Cancelled at 4,294,967,296 bytes;
                  staged .tar.tmp and .recipient- seen while writing, staging EMPTY after, destination never
                  created; job record cancelled; children 2 seen / 0 after, fds delta 0
  Space: free before 21,258,174,464; minimum sampled 16,786,321,408; after cleanup 21,323,923,456.

What this does NOT prove:
- The ciphertext is compressible (34.5 MB); the incompressible >8GiB OUTER archive is a separate item (below).
- Cancellation uses the real job store, the real job-cancel CLI command (separate process) and the real
  FlowContext checkpoint, but not the Cockpit bridge/UI itself, root privileges, a run-job process or systemd unit,
  or a full restore/backup flow (no apps, no Podman); the job's progress side runs inside the probe process.
- truncate-last-byte-extract output allocation was bounded by harness hole punching; the cancel-extract case is the
  one whose partial output was really allocated.
- x86_64 only; no ARM run, no service restore, no Hermes. commercial_acceptance stays not-complete.

Incompressible outer archive above 8GiB (probe tests/backup/bounded_incompressible_outer.py, source 9e30d08):
- Real smoke 128 MiB passed (large-incompressible-outer-smoke-128mib.*): SHAKE256 1MiB-per-index keystream through
  the real writer (compression ratio 1.000284), engine streaming hash via describe_fd(check_members=True, hasher)
  equals the writer's sha256, verify_archive passed, missing key -> key-required, wrong key -> wrong-key, in-place
  last-ciphertext-byte flip with consistent outer metadata refused late (corrupt-archive) and reverted bit-exact.
  At 128 MiB the outer member is a plain ustar header (no >8GiB size field exercised).
- Actual 8193 MiB attempt REFUSED BEFORE GENERATING ANYTHING (large-incompressible-outer-8193mib.*, exit 3):
  required free 21,856,942,389 bytes = 12GiB reserve + 256MiB guard + 8,610,281,781 (the writer's own archive
  bound; model of the real size 8,593,308,283) + 93,323,264 window; free at plan 21,530,435,584;
  shortfall 326,506,805 bytes. A 15-minute watch afterwards never saw more than 21,298,855,936 bytes free;
  attempt 2 (large-incompressible-outer-8193mib-attempt2.*, 2026-11-23T01:33:46Z, exit 3): free 21,104,295,936,
  shortfall 752,646,453 bytes. The archive itself must exist in full (>8GiB) for the reader/verify path, so no
  harness technique can remove this need. Unit checks of the >8GiB raw PAX size-record parser use a real engine
  header (ustar size field 0, PAX size record) but no >8GiB payload.
