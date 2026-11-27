# Private volume source boundary — local candidate

Base: 150ee94. No lab execution or successful-chain replay in this increment.

## Historical evidence audit

Recomputed SHA-256 from git objects at recorded source
91758a2d53b5924e9bb8bf010be4c74418b6f866 for all seven entries in
headscale-continuity-next/run2-source.json: all matched. Recorded run1.exit=1,
run2.exit=0. final-comparison.json has 13 true entries; slot-status.json records
released with cleanup_verified=true. These are checks of committed historical
artifacts, not a new observation of current lab state. Historical installed,
rolled_back and restarted continuity acceptance remains scoped to that source.

## Independent minimum

volume_key opened archive paths directly, bypassing read_source policy. The new
real CLI fixture reproduced symlink acceptance, FIFO timeout at 2 seconds, and
acceptance despite a substituted 32-byte source limit. Before fix: 7 tests,
2 failures and 1 error, 2.293s. After fix: bounded no-follow/nonblocking descriptor
read before parsing plain tar. Parent directories remain trusted. Archive input
is limited to MAX_FILE (4 MiB); key member limit remains 4096 bytes. Compressed
archives now fail closed, matching the Podman plain export call site. This is
not a general archive sandbox or complete age identity dynamic scanning.

Validation:

```bash
PYTHONPATH="$PWD/backup-engine" python3 -m unittest discover -s tests/e2e/lab -p 'test_headscale_*.py' -v
bash -n tests/e2e/lab/headscale-product-test.sh tests/e2e/lab/headscale-product-runner.sh
python3 -m py_compile tests/e2e/lab/headscale-private-sources.py tests/e2e/lab/test_headscale_private_sources.py
git diff --check
```

49 tests passed, zero skipped, 17.231s. After adding compressed-input rejection
coverage, reran the affected 7 tests: PASS, 0.555s; compile and diff checks PASS.
Fixtures use only temporary synthetic material, no Podman/systemd/network.
No guards, engine, runner, production, model or workspace configuration changed.
No Hermes review or retry. No CONTEXT.md or ADR file found in this tree.

## Next independent real probe — proposed, NOT executed

Reserve an exclusive dev-d slot first, retain existing isolation/headroom guards,
and independently capture before/after inventories. This probe deliberately
uses an empty, fresh synthetic volume: verify the actual Podman export format
and size policy with the candidate without replaying installer/client success.
It does not establish populated customer-volume size compatibility.

From the repository root, after those preconditions:

```bash
bash tests/e2e/lab/owner.sh d --verify-isolation
bash tests/e2e/lab/owner.sh d python3 - <<'PY'
import io, os, subprocess, tarfile, tempfile, uuid
name = 'hs-private-probe-' + uuid.uuid4().hex[:12]
created = False
try:
    subprocess.run(['podman', 'volume', 'create', '--label', 'io.woowtech.test=true', name],
                   check=True, stdout=subprocess.DEVNULL)
    created = True
    with tempfile.TemporaryDirectory(prefix='hs-private-probe-') as directory:
        os.chmod(directory, 0o700)
        path = directory + '/export.tar'
        subprocess.run(['podman', 'volume', 'export', '--output', path, name], check=True)
        with open(path, 'rb') as source:
            data = source.read(4 * 1024 * 1024 + 1)
        assert 0 < len(data) <= 4 * 1024 * 1024
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
            assert all(m.isdir() for m in archive)
        print('PRIVATE_VOLUME_EXPORT_FORMAT=PASS bytes=' + str(len(data)))
finally:
    if created:
        subprocess.run(['podman', 'volume', 'rm', name], check=True, stdout=subprocess.DEVNULL)
PY
bash tests/e2e/lab/owner.sh d --verify-isolation
```

This proposed probe tests format/size only; the local CLI regression above tests
the helper and secret extraction. Capture inner exit status and verify the exact
probe volume is absent even on error before releasing the slot. No image pull,
service restart, original volume read, unit install, or installer invocation is
needed. Headplane UI, populated exports above 4 MiB, complete age identity
registration/scanning and commercial acceptance remain unverified.
