#!/bin/bash
# ncs-run-verify.sh <fixture tar> <addon slug> <datadir in share> [share marker paths...]: strict walk of the add-on AND the
# share member inside a throwaway network-none, read-only labpodman container (1 CPU, 1 GiB), under the host heavy-test
# lock. HA_BACKUP_KEY is read from the lab creds file by a small reader (same parsing as rr.sh) and handed to the
# container on stdin only. The product reader comes read-only from this worktree's backup-engine/.
set -uo pipefail
V=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$V/../../../.." && pwd); FX=$1; shift
python3 -I -c '
from pathlib import Path
for line in (Path.home() / ".woowbk-lab/secrets/ha-import-creds.env").read_text(encoding="utf-8").splitlines():
    k, sep, v = line.strip().partition("=")
    if sep and k.strip() == "HA_BACKUP_KEY":
        print(v.strip()); break
' | flock -w 3600 /tmp/woowbk-host-heavy-tests.lock nice -n 10 ionice -c3 timeout 5400 /home/woowtechopenclaw/.woowbk-lab/bin/labpodman run --rm -i --network none --pull=never \
    --read-only --memory 1g --cpus 1 --security-opt no-new-privileges \
    -v /usr/lib/python3/dist-packages:/hostdist:ro -v /usr/lib/x86_64-linux-gnu/libsodium.so.23.3.0:/opt/hostlib/libsodium.so.23:ro \
    -e LD_LIBRARY_PATH=/opt/hostlib -v "$ROOT/backup-engine:/code/backup-engine:ro" -v "$V/ncs_verify.py:/ncs_verify.py:ro" -v "$(dirname "$FX"):/fx:ro" \
    localhost/woowbk-device:noble python3 -I /ncs_verify.py "/fx/$(basename "$FX")" "$@"
