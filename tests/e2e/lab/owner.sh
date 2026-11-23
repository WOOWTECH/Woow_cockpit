#!/bin/bash
# Run a command as appowner inside a lab device, exactly like the engine does:
# runuser -u appowner -- env -i ... XDG_RUNTIME_DIR=/run/user/<uid> DBUS_SESSION_BUS_ADDRESS=...
#   tests/e2e/lab/owner.sh <a|b|c|d> podman ps -a
#   tests/e2e/lab/owner.sh <a|b|c|d> systemctl --user status woowbk-demo-app.service
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
shift
# Read-only outer isolation assertion; never enters the host Podman store.
if [ "${1:-}" = --verify-isolation ]; then
    { [ "$DEV" = d ] || [ "$DEV" = e ]; } && [ "$#" = 1 ] || die "isolation assertion is dev-d and dev-e only"
    state=$("$LP" inspect "$NAME" --format '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}')
    [ "$state" = 'true none {}' ] || die "dev-$DEV isolation assertion failed"
    echo "dev-$DEV isolation: true none {}"
    exit 0
fi
tty_flag=()
[ -t 0 ] && [ -t 1 ] && tty_flag=(-t)
exec "$LP" exec -i "${tty_flag[@]}" "$NAME" /usr/local/bin/woowbk-owner "$@"
