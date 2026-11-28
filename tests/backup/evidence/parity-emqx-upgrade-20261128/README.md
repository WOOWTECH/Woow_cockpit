# EMQX: the package's real upgrade after an HA import (2026-11-28, dev-d)

Owner decision (2026-11-28): open-source images only (EMQX 5.9+ is BSL 1.1 / an Enterprise image; not used). The
open-source emqx/emqx has no 5.8.x after 5.8.9, so the test upgrades from the nearest older open-source release,
`docker.io/emqx/emqx:5.8.8` (Apache-2.0, same OTP; amd64 digest `2bbadcd6...`, image ID `5a96e360...`), to the version
the package pins today (WOOWTECH/Woow_podman_emqx main `c01c897`, which holds PR #11: after an HA import marker,
smoke.sh's A4/A5/A6/A10 are warnings so upgrade.sh no longer rolls back).

`emqx_upgrade_after_import.py --run` (driver `e8efa58e`, merged here; lease reviewed and granted) under one hold of the
dev-d lock (525 s), dev-d network none throughout:
1. The real x86 HA EMQX cold backup imported on dev-d's own 5.8.9 through the product (check: importable, nothing
   stops; one-action import; the restore's own safety backup; the marker `woow-ha-import.json` in the data volume - the
   product stops on `version.different`, so the import must happen on the same version as HA's add-on, 5.8.9).
2. EMQX put on 5.8.8 by a throwaway copy of the package (only Image= repinned) through its install.sh: the older broker
   started on the imported data (the downgrade risk the owner accepted did not materialize) and its smoke.sh gave
   exactly the imported set (A4 and A5/A6/A10 WARN, 11 PASS, 0 FAIL).
3. The package's REAL scripts/upgrade.sh from a throwaway copy pinned to 5.8.9 (the image already on dev-d, so no
   pull): exit 0, "upgrade complete", no rollback line, smoke exactly the imported set, the container moved from the
   5.8.8 to the 5.8.9 image ID, only emqx.container's Image= line and the Quadlet manifest changed, the pre-upgrade
   backup and unit snapshot the only new folders, the marker kept.
4. After the upgrade: the node reports 5.8.9 with the same node name; Dashboard and MQTT accounts, authenticators,
   authorization settings, sources, ACL rows, retained messages, rules, connectors, actions, banned clients and API keys
   exactly as before it; MQTT behaves as before (logins, retained delivery, ACL deny, refusals).
5. Recovery: dev-d's files put back byte for byte, its own 5.8.9 units, the 11-19 baseline restored, its own markers
   back and the import marker gone, its own smoke.sh --quick 10/0/0; owned-only cleanup, leak scans (incl. every issued
   Dashboard token), dev-d exactly as before.

**61/61**; receipt `emqx_upgrade_after_import.json` complete. The only network action: the host pulled the 5.8.8 image
by digest into the separate LAB store (never the production store); it was streamed into dev-d and afterwards removed
from both (`--remove`, `--remove-lab`). Attempts 01 and 02 failed on the driver's own judgements (the marker has no
trailing newline - `0af0f60a`; upgrade.sh prints install.sh's last words because it runs the installer first -
`e8efa58e`); in attempt 02 the upgrade itself already succeeded. `upgrade-capture.json` is the fixed-status record (64
lines). Private: `~/.woowbk-lab/evidence/emqx-upgrade-after-import/`, `/tmp/parity-focus-20261127/emqx-upgrade-0[1-3].*`.
`commercial_acceptance`: `not-complete`.
