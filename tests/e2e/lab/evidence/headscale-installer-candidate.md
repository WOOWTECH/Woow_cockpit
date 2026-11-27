# Headscale synthetic installer/automatic rollback candidate

Latest slot result: [headscale-continuity-next/README.md](headscale-continuity-next/README.md).
The d11f9bb live run failed on unsupported Quadlet NetworkAlias. Corrected source
91758a2 passed 48 local tests, generator dry-run, then real installer/rollback/restart
client continuity in one gated retry. Independent cleanup verified; slot released.
The candidate description below is historical; see the linked live evidence.

Historical evidence below describes source ad9ccb3. The subsequent locally tested,
not lab-executed continuity increment is documented in
[headscale-installer-continuity-candidate.md](headscale-installer-continuity-candidate.md).

Status: **Synthetic dev-d installer/automatic rollback PASS** at source ad9ccb3.
See `headscale-installer-live/README.md` for the real run and independent cleanup.
This is not real customer HA backup or complete commercial acceptance. Public guards unchanged.
Base: d0d5a20. This increment does not incorporate mainline EMQX/LiteLLM changes.

## Implemented path

`headscale-product-test.sh --installer` keeps the existing isolation/memory/credential
controller and synthetic HA conversion/client flow. After those synthetic clients
stop, it invokes `headscale_install_rollback.py`. The installer uses new random
`hs-install-*` volumes and Quadlet, never transfers ownership of original volumes.
It packages actual converter output using `QuadletPostgresAdapter.import_manifest`
and encrypted `flows._package`, then calls unmodified `flows.run_restore`.
After successful install it creates distinguishing user and headplane markers;
an imported hook arms a single systemd ExecStartPre failure. Only an actual
`flows.RolledBack` with exactly one armed failure satisfies the candidate.
Both safety archives must be encrypted and successfully extracted privately.

Verification uses cold volume exports and compares exact candidate node ID,
node_key, machine_key, IPv4, IPv6 and Noise content/metadata. Headplane compares
all non-root paths/content hashes/mode/UID/GID, then a rollback marker with its
pre-failure metadata. Same-count replacement nodes do not satisfy the check.
After rollback a separate restart repeats verification. Source config remains a
read-only synthetic mount; it is not a restored config artifact. Existing
client continuity assertions precede the installer; **post-installer client
continuity is still untested**. Headplane UI behavior is not tested.

Only status/type messages are printed. Raw command stderr, config references,
node keys and newly generated age identities are not printed. Engine Reporter
and audit callbacks discard messages. Age identities and safety archives stay
inside the owner-only synthetic directory and are retained on failure, deleted
only after success and cleanup. This is output suppression, not a claim of
complete new age-identity dynamic-scan coverage. The existing credential
controller remains active for the surrounding synthetic flow.

## Local verification (15 passed, zero skipped)

```bash
cd /home/woowtechopenclaw/work/headscale-isolated-derp
PYTHONPATH="$PWD/backup-engine" python3 -m unittest discover -s tests/e2e/lab -p test_headscale_install_rollback.py -v
bash -n tests/e2e/lab/headscale-product-test.sh tests/e2e/lab/headscale-product-runner.sh
python3 -m py_compile tests/e2e/lab/headscale_install_rollback.py
git diff --check
```

Initial local run had two fixture construction errors (`RolledBack` requires a
BackupError object, not a string); the first correction referenced the wrong
module. Both were fixed, then all 15 tests passed. No live system was involved.
Fixtures cover orchestration/failure classification, single arming, host-identity
refusal, synthetic path/permission/missing/symlink rejection, exact identity,
Noise and content/ownership comparisons. They do not execute adapter subprocesses.

## Real command — executed in allocated exclusive slot

```bash
cd /home/woowtechopenclaw/work/headscale-isolated-derp
bash tests/e2e/lab/headscale-product-test.sh --installer
```

Requirements:
- dev-d outer `network=none`, `ports={}`, appowner UID 1019 and active user bus.
- At least **2 GiB free cgroup headroom**; wrapper refuses otherwise. Exclusive
  slot requested, allow up to 15 minutes controller runtime plus cleanup grace.
- Existing local Headscale tag `localhost/woow-headscale:0.29.4-r1`, image
  `a5f7b9715dea9116f435ff7892e6925895d1c92d4a265cc02eff1a2abadb227d`.
- Existing Tailscale tag `docker.io/tailscale/tailscale:stable`, previously tested
  `62dc2e673073db15c940b08320bc15303dce144ccb4fdf40b88a3c09dbbf027f` (1.104.7).
  Existing wrapper reports resolved image identities; verify tag provenance before slot.
- `age`, `age-keygen`, `zstd`, Python3, OpenSSL, rootless Podman/Quadlet inside dev-d.
- No pulling images, publishing ports, original data, original secrets, or real HA backup.

The first real run confirmed the tested node schema, tar ownership normalization,
archive/key tools, adapter/preflight, systemd rollback and cleanup for this synthetic
fixture. Other schemas/settings and other failure modes remain untested. SQLite summary rejects nonempty WAL rather
than silently reading a stale DB. It is narrowly for generated synthetic archives,
not a replacement for product untrusted-backup validators or Hermes review.
