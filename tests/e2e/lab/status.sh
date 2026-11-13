#!/bin/bash
# One-line overview per lab device: state, Cockpit URL, systemd state, memory, demo app health.
#   tests/e2e/lab/status.sh
source "$(dirname "$0")/lib.sh"

echo "host MemAvailable: $(mem_available_mb) MB"
image_id=$("$LP" image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || echo none)
for dev in a b; do
    device_vars "$dev"
    state=$(container_state "$NAME")
    line="$NAME state=$state cockpit=https://127.0.0.1:$PORT appowner=$OWNER_UID"
    if [ "$state" = running ]; then
        mem=$("$LP" stats --no-stream --format '{{.MemUsage}}' "$NAME" 2>/dev/null | tr -d ' ')
        sys=$("$LP" exec "$NAME" systemctl is-system-running 2>/dev/null || true)
        app=$("$LP" exec "$NAME" curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:18090/healthz 2>/dev/null || true)
        line+=" systemd=$sys mem=$mem demo-healthz=${app:-000}"
        [ "$("$LP" container inspect --format '{{.Image}}' "$NAME")" = "$image_id" ] || line+=" (older image: reset.sh to recreate)"
    fi
    echo "$line"
done
