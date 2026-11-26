# code-server R8, current integration on isolated dev-e (2026-11-26)

## Lab recovery

The host's pinned code-server 4.139.1-8 image loaded into network-isolated dev-e with its exact config ID `7999790230ec6267ae55b82ab0e8d725add734658d15a8ec7a139a6d4087b0a1`. The 5362 MiB image transferred as a 2517 MiB compressed copy in 651 seconds; the lowest host available space was 16811 MiB. Temporary transfer directories were removed. See `image-load.txt`.

The first wake correctly refused before starting a service: its installed Quadlet still pinned a manifest digest from an earlier archive load. The loaded image had the same expected config ID but a new manifest digest. Under the dev-e mutation lock, the recovery asserted that code-server was inactive, checked the exact config ID and new digest's local availability, retained a private copy of the old unit, and changed only its single `Image=` line. It then reloaded the user manager. No installer was rerun and credentials, environment settings, volumes and data stayed in place. The refusal and before/after hashes are in `first-wake-refusal.txt` and `installed-pin-recovery.json`. The private old unit is `/home/appowner/.woowbk-pin-recovery-20261126/code-server.container.before` inside dev-e.

The subsequent guarded wake created the ID-mapped copy in 339 seconds and removed its throwaway container. Its lowest available host space was 16513 MiB. The service and health timer started; the health URL returned 200 and all service/container checks passed, with no failed user unit. See `guarded-wake.txt`.

## Real encrypted HA backup, current helper

At clean source `f330d6c5`, the actual encrypted x86 showcase HA backup ran through the installed helper's check, conversion, encrypted packaging, preflight and restore. Every installed engine module and helper SHA-256 matched the source. All **87 checks passed**, with no failures, in 305.6 seconds. `current-full-flow.json` records the fixed status output, source commit and complete private-output hash.

The real IDE accepted this device's password, issued a session cookie and served its workbench and the HA snippet/skill with their recorded hashes; a wrong password received no session cookie. The 28 HA Pi sessions, Claude and Codex history and skills were present. Existing credentials, connector state, IDE machine/workspace identity, extensions and workspace markers stayed unchanged. HA login credentials and other excluded state did not move. Settings and ownership checks passed. The same checks passed after restart and after a deliberately failed restore rolled back automatically. Restoring the original safety backup brought back the device state and removed the HA markers.

The records, uploads, staging, run directory, journal outside the app, app log and host evidence scans all had zero registered-secret hits; numeric counts are in `secret-scan-counts.json`. Temporary job resources, staging/key files, test backups, uploaded source record, seeded test files and needle file were removed; the prior schedule-timer state and outer network isolation were restored. Detailed private evidence remains under `~/.woowbk-lab/evidence/codeserver-csff/20261126T220404/` and `/tmp/parity-codeserver-current-20261126.private.log`.

A separate read-only baseline verification then passed **8/8**, including original marker hashes, real login and the retained encrypted baseline backup. Only afterwards did the guarded lab rotation stop its services, confirm no container remained and remove the cached image. Data, settings, secrets, units and baseline backups remain. Host available space returned to 27386 MiB. See `baseline-verify.json` and `lab-rotation.txt`. A subsequent reload can require the same guarded manifest-reference refresh described above; the package installer was not changed in this pass.

This is real lab/helper/IDE HTTP evidence. The Cockpit browser page, provider logins, Omnigent/Paseo pairing, a workspace import with a share folder (this source has none) and host reboot were not exercised. The ten-service final acceptance remains incomplete. `commercial_acceptance`: `not-complete`.
