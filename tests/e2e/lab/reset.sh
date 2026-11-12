#!/bin/bash
# Destroy a lab device AND its volumes (home incl. nested images/containers, backup data).
#   tests/e2e/lab/reset.sh <a|b> [--up]     --up recreates it fresh afterwards
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
if [ "$(container_state "$NAME")" != absent ]; then
    "$LP" rm -f -t 30 "$NAME" >/dev/null
    log "$NAME removed"
fi
for volume in "${VOLUMES[@]}"; do
    if "$LP" volume exists "$volume"; then
        "$LP" volume rm "$volume" >/dev/null
        log "volume $volume removed"
    fi
done
if [ "${2:-}" = --up ]; then
    exec "$LAB_DIR/up.sh" "$DEV"
fi
