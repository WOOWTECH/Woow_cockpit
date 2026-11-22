Actual >8GiB single-file lane (extends accepted a065c9c)

Re-run (opt-in; current host only, no remote access):
  python3 tests/backup/bounded_large_archive.py --profile compressible-sequential
Small smoke:
  python3 tests/backup/bounded_large_archive.py --profile compressible-sequential --mib 16
Safety tests:
  PYTHONPATH=backup-engine python3 -m unittest tests.backup.test_bounded_large_archive

The new profile defaults/caps at 8193 MiB = 8590983168 bytes (8GiB + 1MiB).
Default random profile retains its 2048MiB cap. No duplicate 2GiB run this round.
Engine requires a complete regular source: FIFO/virtual/sparse inputs aren't used.
Each MiB is physically written from a distinct SHAKE256 4KiB tile repeated 256
times. This is deliberately compressible actual data, not header-only/sparse.
Source and extracted file st_blocks must each cover the full logical byte count.

Sequence: generate+hash source; native v2 gzip write; archive SHA256 reread;
full verify_archive; independent tarfile view of actual inner member size/PAX;
delete ONLY this run's generated source; extract_archive; hash extracted file;
clean the private temporary directory. No service/application restore claim.
Archive cap: 268435456 bytes, enforced by RLIMIT_FSIZE during writer execution.
Source/extract cap: payload + 256MiB. No engine guards are changed or mocked in
real runs. Reader reserve is stricter than the engine default.

Budget for this profile:
  payload                         8590983168 bytes
  capped archive                   268435456 bytes
  additional storage margin        268435456 bytes
  planned storage                 9127854080 bytes
  guard floor (12GiB + 256MiB)    13153337344 bytes
  required available             22281191424 bytes (20.7509765625GiB)
Initial host check: 26310299648 bytes available. No unrelated files were removed.
Incompressible two-copy source+archive would need at least 30066868224 bytes
(payload*2 + 12GiB), before margins, so it cannot fit the observed host budget.

Runtime: 250ms space monitor, progress checks, 20-minute deadline, two CPU cores.
Extract preflight rechecks payload+margin after source release. Failure/SIGINT/
SIGTERM clean up owned temporary files; SIGKILL/power loss cannot run cleanup.
Free-space minima are sampled: unrelated concurrent writers remain outside our
control. The reserve includes 256MiB headroom; this is not a disk reservation.

Coverage boundary: actual >8GiB inner single file, native PAX size and gzip
streaming roundtrip. Compressed outer archive is intentionally below 256MiB.
Does not prove >8GiB compressed outer archive, incompressible throughput,
age/zstd encryption, ARM performance, or complete service restoration.
No .54 access, labs, production, Hermes retries, cache deletion or public guard
changes. Prior 2GiB evidence remains unchanged.

Observed actual run: PASSED
  payload_bytes: 8590983168
  archive_bytes: 111493120
  source_allocated_bytes: 8591114240
  extracted_allocated_bytes: 8591106048
  source_sha256: f88436d3200bc34cfa08f7362a377f17398a0cf61dc3467c1ec4554e1ee1e2b7
  archive_sha256: 80b309aab79deca53ce7797cb966fdb51c38e97974f2b5180961276182dfe6d0
  required_free_bytes: 22281191424
  free_before: 26259353600
  minimum_free_observed: 17513103360
  free_after_cleanup: 26288791552
  elapsed_seconds: 475.65977328200825
  max_rss_kib: 40524
  minimum_free_GiB: 16.310349
  Actual inner PAX size: 8590983168; source/extracted hashes equal.
  All owned large temporary files removed; six safety tests passed.
