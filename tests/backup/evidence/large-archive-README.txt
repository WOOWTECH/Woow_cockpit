Bounded native archive candidate
Base: b885925 (wt-b1); branch: test/bounded-large-archive

Re-run from this checkout:
  python3 tests/backup/bounded_large_archive.py --mib 16
  python3 tests/backup/bounded_large_archive.py --mib 2048
Capture stdout to a new JSON evidence file. Exit code 0 means passed.
The default scratch parent is /tmp; --scratch-parent selects a filesystem.
Only a freshly created private temporary directory is used and removed.
Do not run with python -O assumptions: checks use explicit exceptions.

Bounds:
- 1..2048 MiB actual random payload, no sparse creation or seek-based payload.
- Preflight reserves 12 GiB + 256 MiB, plus three payload copies + 512 MiB.
- Existing SpaceGuard, fail-closed free-space measurement, 250ms interval
  and progress callbacks; 256MiB headroom above the requested reserve.
- RLIMIT_FSIZE bounds each file to payload + 256MiB; two CPU affinity cores;
  20-minute cooperative deadline. No production, container, lab or Hermes calls.
- Timer/cleanup handle normal failures, SIGINT and SIGTERM. SIGKILL/power loss
  cannot run cleanup: any orphan is only the private woow-large-probe-* directory.
- Concurrent unrelated disk writers cannot be controlled; recorded minimum is
  sampled, not an exclusive filesystem reservation. No deliberate disk filling.

Coverage:
- Native v2 unencrypted gzip archive.write_archive / verify_archive /
  extract_archive; source and extracted SHA256 match; archive SHA256 reread.
- Actual generated and verified payload byte counts and st_blocks recorded.
- Header-only sizes 8GiB-1, 8GiB, 8GiB+1: raw 512/1536-byte fixtures,
  strict parser accepts size, absent body raises _Truncated. No sparse fixtures.
- >8GiB backup.json with leading PAX is rejected by public read_header as
  not-a-backup. Ordinary metadata >1MiB is rejected as limit-exceeded.
- Header support does NOT prove >8GiB real payload throughput, encrypted
  age/zstd throughput, application consistency, or complete service restoration.
- No engine/guard changes. Harness passes a stricter reserve to reader Limits.

Evidence:
  large-archive-smoke.json       16MiB real native round trip
  large-archive-2gib.json        2GiB real native round trip
  large-archive-regression.txt   existing archive v2/security/space tests
  large-archive-harness-tests.txt  low-space preflight + CLI cap

Observed 2GiB run:
  Passed, 2147483648 source/verified/extracted bytes; gzip archive 2148167680 bytes.
  Source and extracted SHA256:
    ac39dbd64c4a87060701e9d3e8b3178f5f361263824ba575a3f94c62159f7d95
  Elapsed 228.72s; peak RSS 58216KiB; sampled minimum free 18.510GiB.
  All temporary payloads removed; free after cleanup 24.511GiB.
  69 existing regressions + 2 harness safety tests passed.
  large-archive-provenance.json records base commit and source hashes.
