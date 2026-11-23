#!/bin/bash
# run_verify.sh <fixture tar> <addon slug> [marker paths...]: strict walk of one batch-2 backup inside a throwaway
# network-none lab container. HA_BACKUP_KEY is read from the lab creds file by a small reader (same parsing as rr.sh)
# and handed to the container on stdin only.
set -uo pipefail
V=$(cd "$(dirname "$0")" && pwd); FX=$1; shift
python3 -I -c '
from pathlib import Path
for line in (Path.home() / ".woowbk-lab/secrets/ha-import-creds.env").read_text(encoding="utf-8").splitlines():
    k, sep, v = line.strip().partition("=")
    if sep and k.strip() == "HA_BACKUP_KEY":
        print(v.strip()); break
' | nice -n 10 ionice -c3 timeout 3000 /home/woowtechopenclaw/.woowbk-lab/bin/labpodman run --rm -i --network none --pull=never \
    --read-only --memory 1g --cpus 1 --security-opt no-new-privileges \
    -v /usr/lib/python3/dist-packages:/hostdist:ro -v /usr/lib/x86_64-linux-gnu/libsodium.so.23.3.0:/opt/hostlib/libsodium.so.23:ro \
    -e LD_LIBRARY_PATH=/opt/hostlib -v "$V/code:/code:ro" -v "$V/verify_b2.py:/verify_b2.py:ro" -v "$(dirname "$FX"):/fx:ro" \
    localhost/woowbk-device:noble python3 -I /verify_b2.py "/fx/$(basename "$FX")" "$@"
