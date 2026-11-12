#!/bin/bash
# Stop a lab device; its container and volumes are kept (up.sh starts it again).
#   tests/e2e/lab/down.sh <a|b|all> [--rm]     --rm also removes the container (volumes stay)
source "$(dirname "$0")/lib.sh"

target=${1:-}
remove=no
[ "${2:-}" = --rm ] && remove=yes
if [ "$target" = all ]; then set -- a b; else set -- "$target"; fi

for dev in "$@"; do
    device_vars "$dev"
    state=$(container_state "$NAME")
    if [ "$state" = absent ]; then
        log "$NAME does not exist"
        continue
    fi
    if [ "$state" = running ]; then
        # SIGRTMIN+3 lets systemd stop user managers and nested containers cleanly.
        "$LP" stop -t 60 "$NAME" >/dev/null
        log "$NAME stopped"
    fi
    if [ "$remove" = yes ]; then
        "$LP" rm "$NAME" >/dev/null
        log "$NAME removed (volumes kept: ${VOLUMES[*]})"
    fi
done
