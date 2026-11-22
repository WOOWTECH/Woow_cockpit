Bounded real encrypted single-file lane, extending accepted ff4ec7e.
Main integration context supplied by user: 53ac6dc / current 3fe2ff3.
archive.py, keys.py and haimport.py are identical between this lane's base and
3fe2ff3. Only harness/tests/evidence change; no product guard changes.

Run (opt-in):
  python3 tests/backup/bounded_large_archive.py --profile compressible-sequential --encrypted
Small smoke:
  python3 tests/backup/bounded_large_archive.py --profile compressible-sequential --encrypted --mib 16
Safety checks:
  PYTHONPATH=backup-engine python3 -m unittest tests.backup.test_bounded_large_archive

Selection: age/age-keygen 1.1.1 and zstd 1.5.5 are installed; native engine uses
zstd -3 -T2 and age X25519. Initial available bytes: 26318823424. Required available
for actual 8193MiB (8590983168 bytes): 22281191424. Previous plain run took 476s,
so real >8GiB is feasible within the same 1200s cooperative deadline. No duplicate
plain8193MiB or full 2GiB roundtrip is run for this change.

Real payload: distinct deterministic 4KiB SHAKE256 tile per MiB, repeated 256
times and physically written. Source and extraction st_blocks cover full size;
no sparse creation, truncate, fake size, FIFO, or virtual source. Native public
write_archive / verify_archive / extract_archive perform compression, encryption,
authenticated decryption through EOF and payload SHA256 checks. Independent
Python tarfile parses the actual decrypted inner PAX header via the engine's
stream source; only that supplemental header pass stops early.

Space: source and extraction never coexist. Source is released only after full
verification and key/header checks. Archive is capped at 256MiB by RLIMIT_FSIZE;
source/extraction bounded at payload+256MiB. Preflight reserves 12GiB+256MiB and
budgets one payload, capped archive and another 256MiB margin. Existing SpaceGuard
checks plus 250ms monitor and extraction preflight remain active. Two-core
process affinity applies to children. No unrelated files/caches are removed.

Keys: native KeyStore generates a fresh X25519 identity under the owned private
scratch directory (0700); identity file must be 0600. A separate ephemeral wrong
identity tests rejection. No secret, recipient or key identifier is recorded in
evidence; tools receive identity file paths or private pipes. Encrypted failure
messages suppress exception text; core dumps disabled. Successful and ordinary
failure cleanup removes both key stores and all owned large files. SIGKILL or
power loss cannot execute cleanup; this is unlink cleanup, not secure erasure.

Safety checks include actual age/zstd processes hitting the small file cap,
child reaping and key cleanup; missing dependency rejection before payload work;
and a deliberately raised exception containing the REAL ephemeral private key,
which must never appear in captured stdout/stderr. Existing space/cap/order
checks remain. Large run also records missing/wrong-key rejection and zero
remaining encryption tool children.

Limits: proves actual encrypted >8GiB INNER single-file roundtrip with deliberately
compressible data. Outer encrypted archive is capped below 256MiB. Does not prove
>8GiB ciphertext storage, incompressible throughput, ARM behavior, application
consistency or complete service restoration. No .54 access, labs, production,
Hermes retries or product guard edits. Free space is sampled, not exclusively
reserved against unrelated concurrent writers.

Observed actual encrypted run: PASSED
  payload_bytes: 8590983168
  archive_bytes: 34519040
  source_allocated_bytes: 8591118336
  extracted_allocated_bytes: 8591106048
  source_sha256: f88436d3200bc34cfa08f7362a377f17398a0cf61dc3467c1ec4554e1ee1e2b7
  archive_sha256: 476a958d3c2ed20a6c55df8b7adad19f7262806d0b8562520147bde730cd4a29
  required_free_bytes: 22281191424
  free_before: 26266882048
  minimum_free_observed: 17631424512
  free_after_cleanup: 26263568384
  elapsed_seconds: 373.59300240594894
  max_rss_kib: 29196
  minimum_free_GiB: 16.420544
  Authenticated verify + extraction completed; source/extracted hashes equal.
  Actual inner PAX size: 8590983168. Missing/wrong key both rejected.
  Owned payloads and both ephemeral key stores removed; tool children: 0.
  16MiB encrypted smoke and nine safety tests passed.
