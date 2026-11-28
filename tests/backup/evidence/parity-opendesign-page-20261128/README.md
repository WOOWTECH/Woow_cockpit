# OpenDesign through dev-e's real Cockpit page (2026-11-28)

The first real-page run on woowbk-dev-e. The new page import bridge (`focus_page_bridge.py`, driver `c16651a8`) let
`opendesign_full_flow.py --via-page` take the actual encrypted x86 Home Assistant showcase backup through the real
Cockpit backup page in headless Chromium (reached through the per-connection relay into network-isolated dev-e):
upload through the page, only OpenDesign selected, the check calling it importable and stopping nothing, every
confirmation line the actual check listed shown and acknowledged exactly once, one import click whose request, first
job and chain carried every listed key exactly once, then one conversion and its restore as two linked jobs in the
first job's systemd unit. Every other part of the R8 OpenDesign flow ran unchanged: the HA projects, files and
conversations through the API, authentication and the refusal of wrong credentials, MCP, this device's preserved
identity and settings, ownership, the checks again after a restart and after an injected failed restore rolled back
automatically, the lab safety backup restored, the leak scans (now also for every issued Cockpit session value),
cleanup and isolation. **103/103** in 599 s (the device lock held 598 s).

Before it `deploy-batch2.sh e wake:opendesign` loaded the host's exact image IDs; after it a separate read-only
`batch2_baseline.py --verify opendesign` passed 7/7 and `rotate:opendesign` stopped the four units and dropped the
images from dev-e (data, settings, secrets, units and the baseline backup stay).

`page-full-flow.json` is the capture's fixed-status record (106 lines) and stdout hash. Private run:
`~/.woowbk-lab/evidence/opendesign-odff/20261128T071931/` (the page part under `page/`), full stdout in
`/tmp/parity-focus-20261127/opendesign-page-pilot-01.private.log`, step logs `opendesign-page-pilot-01.*.log`.
The flow installs its checkout's engine on dev-e (the follow-up engine, with the Nextcloud fix 50a29370).
`commercial_acceptance`: `not-complete`.
