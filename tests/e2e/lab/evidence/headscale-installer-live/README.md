# Real synthetic Headscale HA installer/automatic rollback

Slot: `headscale-install-live-next`, released after this run and independent checks.
Executed source: **ad9ccb389a56bfd55918dad1bc788fc473835a8c**, clean tree before run.
Date: 2026-11-21. Command:

```bash
bash tests/e2e/lab/headscale-product-test.sh --installer
```

**First run exit 0; no live fixes or reruns.** `run1.txt` is the credential
controller's released, scanned output; `run1.exit` records the real shell status.
Source hashes are in `source-sha256.json`. Local 15/15 tests were run before this
slot, not counted as real acceptance.

Before start, isolation was `true none {}`; memory.current 2003435520 / max
4294967296, host MemAvailable 4920856576. No matching heavy driver was active.
Wrapper rechecked available cgroup headroom >=2 GiB. No subuid changes, image
pulls, original-volume mutation, public guard changes or Hermes review occurred.

Resolved images:
- Headscale 0.29.4: a5f7b9715dea9116f435ff7892e6925895d1c92d4a265cc02eff1a2abadb227d
- Tailscale 1.104.7: 62dc2e673073db15c940b08320bc15303dce144ccb4fdf40b88a3c09dbbf027f

## Observed result

- Synthetic HA envelope parsed and converted by the existing product converter.
- Two original synthetic clients automatically reconnected: 28 attempts, 52s
  from source shutdown. Not zero downtime. Later explicit reconnect and DERP
  stability passed 10/10; target API 200 and removed source API 401.
- Actual converter volume artifacts passed adapter import_manifest, encrypted
  package creation and real flows.run_restore installation.
- Safety archives were encrypted and successfully decrypted/extracted privately.
- A real one-shot systemd ExecStartPre failure triggered flows.RolledBack.
- Installed, rolled-back and restarted data passed exact candidate node ID,
  node_key, machine_key, IPv4/IPv6 and Noise content/metadata comparisons.
- Headplane volume contents/mode/UID/GID matched; a distinguishing pre-failure
  marker and user marker survived rollback and restart.
- Runtime image, network none/no port bindings and active unit checks passed.
- Installer's internal cleanup passed; independent post-run inventories for
  containers, volumes, networks and secrets equal the pre-run sets (all true).
  No hs-install unit or config/drop-in path remains. Installer private key/safety
  directories remaining: 0. Original eight services still running (34h uptime).
- Outer isolation remains true none {} after run.

Two synthetic Tailscale clients exceeded SIGTERM grace during planned teardown
and Podman used SIGKILL after 10s. This is retained in run1.txt. Independent
inventory confirmed removal; do not claim graceful client shutdown.

The enclosing synthetic fixture directory `/tmp/headscale-internal.4mJsBps8`
remains owner-only 0700, as designed. It contains generated test artifacts, not
production credentials. The staged engine directory also remains. These are
retained files, not a claim of zero filesystem artifacts. Installer age identities
and its safety archives were removed together after success. Existing credential
controller verified its named sources/log snapshots; do not infer complete
age-identity dynamic scan coverage from suppression and private-file removal.

## Still unverified

Real customer HA backup, production activation/public guard removal, installer-
phase client continuity (clients stopped before installer), Headplane web UI,
all configuration/schema variants and other failure injection modes. No complete
commercial acceptance claimed. Other software and Hermes manual gate are outside
this result.
