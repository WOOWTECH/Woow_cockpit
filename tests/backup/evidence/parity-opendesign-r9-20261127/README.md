# OpenDesign on the PR #23 engine, isolated dev-e (2026-11-27)

The R8 run of 2026-11-26 (`3dad5e06`) was repeated on the final integration tip `4cf97c25`, whose backup engine
equals draft PR #23 (`5168f1ec`): the engine changed in shared code since R8, so the importer path was run again
instead of being carried over. All **85 checks passed**, no failure, in 466.4 seconds (the device lock was held
for 466 s).

Before the run, `deploy-batch2.sh e wake:opendesign` loaded the host's exact images into network-isolated dev-e
(`woow-open-design:4.2.1` = `5bf5f9b959b3`, nginx `1.30.4-alpine` = `1ae82dcc4a34`, IDs equal to the host's;
lowest host free 20.9 GiB during the first start) and all four services became healthy. The readiness check first
refused because two units left `failed` by the D10 lane on 2026-11-26 (exit 137 when their consumers were stopped;
their unit files were already gone) were still listed; their failed state was reset, nothing else touched, and the
check then passed.

The run took the actual encrypted x86 Home Assistant showcase backup (1,116,784,640 bytes) through the installed
helper's upload, check, conversion, encrypted packaging, preflight and restore, the page's own commands. It verified
the HA projects, marker file hashes and conversations through the real API, Basic and Bearer authentication and the
refusal of wrong credentials, the MCP client (initialize and tool listing), this device's preserved MCP, Paseo and
agent identity and settings, and ownership; it repeated the client checks after a restart and after an
intentionally failed restore rolled back automatically, then restored the lab safety backup and checked the
original marker project and file. Records, uploads, staging, the run directory, the journal and the evidence had
zero secret hits; the test's backups, the HA store record, temporary objects, staging, key and needle files were
removed and the isolation (network none, no published port) held before and after.

A separate read-only `batch2_baseline.py --verify opendesign` then passed 7/7 (baseline markers exact, no leftover
test marker, engine running, health URLs, the encrypted baseline backup still listed). Only after that did
`rotate:opendesign` stop the four units, confirm no container remained and drop the images from dev-e (data,
settings, secrets, units and the baseline backup stay; host free back to 33.0 GiB).

`current-full-flow.json` is the capture's fixed-status record (88 lines) and stdout hash; the private run is
`~/.woowbk-lab/evidence/opendesign-odff/20261127T234909/` with the full stdout in
`/tmp/parity-focus-20261127/opendesign-current-20261127.private.log`. `baseline-verify.json` records the separate
baseline check. Wake, readiness and rotation logs: `/tmp/parity-focus-20261127/opendesign-wake-20261127.log`,
`opendesign-check-after-reset.log`, `opendesign-rotate-out-20261128.log`.

dev-e now runs the engine of `4cf97c25` (the flow installs the engine of its own checkout). Real lab, helper and
API evidence; the Cockpit browser page, provider logins and model pairing, and a host reboot were not exercised.
`commercial_acceptance`: `not-complete`.
