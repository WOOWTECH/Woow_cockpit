Bounded encrypted large-stream failures (base 0168078).

Actual run:
  python3 tests/backup/bounded_stream_failures.py --mib 2048
Small real encrypted negative smoke:
  python3 tests/backup/bounded_stream_failures.py --mib 128
Safety checks:
  PYTHONPATH=backup-engine python3 -m unittest tests.backup.test_bounded_stream_failures

One new compressible actual regular source per invocation; default 2147483648
bytes, CLI restricted to 128..2048MiB. Uses the existing SHAKE256 tile generator
and real age/zstd/native archive writer, with a fresh private KeyStore. Source
size, allocated blocks and hash are checked; writer hashes every source byte.
No sparse or header-only payload and no complete successful verify/extract pass.
After the encrypted archive's file SHA256 is rechecked, generated source is
removed, and the ONE encrypted original is reused by all three negative cases.

1. Flip only the final ciphertext byte; run public verify_archive.
2. Remove only the final ciphertext byte; run public extract_archive.
   This is ciphertext truncation, not physical outer-tar truncation: rewrap the
   shortened ciphertext into a valid outer tar. Both mutations recompute only
   untrusted outer backup.json size/SHA256. Public describe(check_members=True)
   must pass and read_manifest must accept the authenticated prefix, proving
   the consumer isn't merely failing early on an outer size/checksum mismatch.
   No ciphertext is re-encrypted after mutation. Tail tests must report
   corrupt-archive AFTER >= payload - 64MiB of observed progress (1984MiB for
   the actual 2GiB run; 64MiB for the 128MiB smoke).
3. Public extract_archive on the unchanged original, with a progress callback
   that raises a unique ProbeCancelled instance once >= half the payload has
   been delivered. The EXACT exception instance must propagate. This exercises
   cooperative callback cancellation, not the UI job-cancellation endpoint.
   Progress is sampled at product callback granularity, not byte-exact timing.

Each case records actual progress, observed tool children, and child count after
consumer return. Extraction cases record actual partial file size/allocation
from inside the progress callback. The test never catches an arbitrary failure
as a pass: expected BackupError code or the exact cancellation object is required.
Unexpected successful verify/extract is a harness failure.

Cleanup attribution:
- Before any harness cleanup, inspect the caller-created extraction root. Record
  root existence and remaining paths. Current v2 _run_v2 finally invokes
  _Extractor.remove_all on failure and then closes it; it removes contents but
  retains the caller-owned root. The report separately proves those observations.
- Harness shutil.rmtree then removes only its own root, with a separate field.
- Final TemporaryDirectory cleanup removes owned archives and ephemeral key.
- A safety test deliberately makes a fake consumer leave partial output; the
  report MUST record engine_removed_partial_contents=false even though harness
  cleanup subsequently succeeds. Case observations survive a harness failure.

Bounds: 12GiB reserve plus 256MiB guard headroom, 250ms space/deadline monitor,
1200s cooperative deadline, two-core affinity. Preflight budgets one payload,
two capped archives and another 256MiB overhead: at 2GiB required available is
16106127360 bytes (15GiB). Each original/mutated archive is capped at 256MiB with
RLIMIT_FSIZE during construction; other files capped at payload+256MiB. Source
and extraction do not coexist; mutated variants are created/removed one at a time.
Observed space is sampled, not a reservation against unrelated host writers.
Normal failures/SIGINT/SIGTERM clean owned temporary data; SIGKILL/power loss
cannot run cleanup. No unrelated file/cache deletion.

No raw exception text, tool stderr, key contents or key identifiers are logged.
Identity directory/file modes checked as 0700/0600; core dumps disabled. Real
age/zstd children are inspected through /proc after each consumer, including
zombies. No .54, labs, Hermes, production or product guard changes. No repeated
accepted success suite, no full service restoration or UI cancellation claim.

Observed actual 2GiB negative run: PASSED
  payload_bytes: 2147483648
  fixture_generations: 1
  full_success_roundtrips: 0
  archive_bytes: 8642560
  archive_sha256: dd3d00eb7172189be2269d87b2e3cfa0810c32c7c35d29b50b18771ae30f7699
  required_free_bytes: 16106127360
  free_before: 26191966208
  minimum_free_observed: 24035389440
  free_after_cleanup: 26190684160
  elapsed_seconds: 45.565721665043384
  minimum_free_GiB: 22.384701
  flip-last-byte: progress=2133456896 bytes; outcome=corrupt-archive; children_after=0
  truncate-last-byte: progress=2132277248 bytes; outcome=corrupt-archive; children_after=0
  cancel-extract: progress=1078327296 bytes; outcome=ProbeCancelled; children_after=0
  Both extraction roots existed but were EMPTY before harness cleanup.
  Harness separately removed roots, scratch, archive copies and identity.
  Real 128MiB negative smoke + four small safety checks passed.
