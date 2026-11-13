#!/bin/bash
# Start (or create) a lab device and wait until it is usable.
#   tests/e2e/lab/up.sh <a|b>
# dev-a: 127.0.0.1:19091 -> Cockpit, appowner uid 1001; dev-b: 127.0.0.1:19092, appowner uid 1007.
# Ready means: systemd finished booting, cockpit.socket listens on 9090, appowner's user manager
# (user@<uid>.service) is active with its D-Bus socket.
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
ensure_password
"$LP" image exists "$IMAGE" || die "image $IMAGE missing: run tests/e2e/lab/build.sh first"

state=$(container_state "$NAME")
case "$state" in
    running)
        log "$NAME already running"
        if [ "$("$LP" container inspect --format '{{.Image}}' "$NAME")" != "$("$LP" image inspect --format '{{.Id}}' "$IMAGE")" ]; then
            log "note: $NAME runs an older $IMAGE build; reset.sh $DEV recreates it (volumes included)"
        fi ;;
    absent)
        check_memory
        for volume in "${VOLUMES[@]}"; do
            "$LP" volume exists "$volume" || "$LP" volume create --label woowbk.lab=device "$volume" >/dev/null
        done
        log "creating $NAME (memory $DEVICE_MEMORY, cpus $DEVICE_CPUS, https://127.0.0.1:$PORT)"
        "$LP" run -d --name "$NAME" --hostname "$NAME" \
            --label woowbk.lab=device \
            --systemd=always --privileged --device /dev/fuse \
            --memory "$DEVICE_MEMORY" --cpus "$DEVICE_CPUS" \
            -p "127.0.0.1:$PORT:9090" \
            -v "$NAME-home:/home" \
            -v "$NAME-varlib:/var/lib/woowtech-backup" \
            -v "$NAME-containers:/var/lib/containers" \
            "$IMAGE" >/dev/null ;;
    *)
        check_memory
        log "starting existing $NAME (was $state)"
        "$LP" start "$NAME" >/dev/null ;;
esac

# systemd: "running" is the goal; "degraded" is reported (failed units listed) but tolerated here
# so the caller can decide; verify-device.sh treats it as a failure.
boot_done() {
    local s
    s=$("$LP" exec "$NAME" systemctl is-system-running 2>/dev/null || true)
    case "$s" in running | degraded) return 0 ;; *) return 1 ;; esac
}
wait_for 180 "$NAME systemd boot" boot_done
system_state=$("$LP" exec "$NAME" systemctl is-system-running 2>/dev/null || true)
if [ "$system_state" != running ]; then
    log "WARNING: $NAME systemd state is '$system_state'; failed units:"
    "$LP" exec "$NAME" systemctl --failed --no-legend --plain >&2 || true
fi

# A device created from an older image build still has that build's helpers; install the repo's current
# provisioning and owner wrappers first (the provisioning script keeps a device's own subordinate id range).
for helper in woowbk-provision:/usr/local/sbin woowbk-owner:/usr/local/bin; do
    "$LP" exec -i "$NAME" sh -c "cat > ${helper#*:}/.${helper%%:*}.new && chmod 0755 ${helper#*:}/.${helper%%:*}.new &&
        mv ${helper#*:}/.${helper%%:*}.new ${helper#*:}/${helper%%:*}" < "$LAB_DIR/device/${helper%%:*}"
done
dexec "$NAME" /usr/local/sbin/woowbk-provision --appowner-uid "$OWNER_UID" < "$PASS_FILE"

wait_for 60 "cockpit.socket on 9090" \
    "$LP" exec "$NAME" sh -c 'systemctl is-active --quiet cockpit.socket && ss -Hltn "sport = :9090" | grep -q 9090'
wait_for 60 "user@$OWNER_UID.service" \
    "$LP" exec "$NAME" sh -c "systemctl is-active --quiet user@$OWNER_UID.service && test -S /run/user/$OWNER_UID/bus"

machine_id=$("$LP" exec "$NAME" cat /etc/machine-id)
log "$NAME ready: systemd=$system_state cockpit=https://127.0.0.1:$PORT appowner=$OWNER_UID machine-id=${machine_id:0:8}…"
