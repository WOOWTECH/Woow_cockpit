#!/bin/bash
# One-line overview per lab device: state, Cockpit URL, systemd state, memory, subordinate ids, health of the
# demo apps (woowbk-demo 18090, woowbk-dirs 18091; 000 = not deployed or down) and, on dev-c, of the
# production-like apps (Odoo 18069 + gateway 18080, n8n 15678 readiness + webhook 15679; the catalog's URLs);
# on dev-d Omnigent 8000, Hermes 18642 + 18644, Headscale metrics 29090 + Headplane entrance 23000 (302) and
# the EMQX dashboard 18083 (its catalog entry has no health URL).
#   tests/e2e/lab/status.sh
source "$(dirname "$0")/lib.sh"

code() {
    local c
    c=$("$LP" exec "$NAME" curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$1" 2>/dev/null || true)
    echo "${c:-000}"
}

echo "host MemAvailable: $(mem_available_mb) MB"
image_id=$("$LP" image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || echo none)
for dev in a b c d; do
    device_vars "$dev"
    state=$(container_state "$NAME")
    case "$dev" in c | d) [ "$state" != absent ] || continue ;; esac
    line="$NAME state=$state cockpit=https://127.0.0.1:$PORT appowner=$OWNER_UID"
    if [ "$state" = running ]; then
        mem=$("$LP" stats --no-stream --format '{{.MemUsage}}' "$NAME" 2>/dev/null | tr -d ' ')
        sys=$("$LP" exec "$NAME" systemctl is-system-running 2>/dev/null || true)
        subids=$("$LP" exec "$NAME" awk -F: '$1 == "appowner" { print $2 ":" $3; exit }' /etc/subuid 2>/dev/null || true)
        line+=" systemd=$sys mem=$mem subuid=${subids:-?}"
        if [ "$dev" = c ]; then
            line+=" odoo=$(code http://127.0.0.1:18069/web/health)/$(code http://127.0.0.1:18080/web/health)"
            line+=" n8n=$(code http://127.0.0.1:15678/healthz/readiness)/$(code http://127.0.0.1:15679/healthz)"
        elif [ "$dev" = d ]; then
            line+=" omnigent=$(code http://127.0.0.1:8000/health)"
            line+=" hermes=$(code http://127.0.0.1:18642/health)/$(code http://127.0.0.1:18644/health)"
            line+=" headscale=$(code http://127.0.0.1:29090/metrics)/$(code http://127.0.0.1:23000/)"
            line+=" emqx-dashboard=$(code http://127.0.0.1:18083/)"
        else
            line+=" demo-healthz=$(code http://127.0.0.1:18090/healthz) dirs-healthz=$(code http://127.0.0.1:18091/healthz)"
        fi
        [ "$("$LP" container inspect --format '{{.Image}}' "$NAME")" = "$image_id" ] || line+=" (older image: reset.sh to recreate)"
    fi
    echo "$line"
done
