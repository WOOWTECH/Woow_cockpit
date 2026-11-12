#!/bin/bash
# Run a command as appowner inside a lab device, exactly like the engine does:
# runuser -u appowner -- env -i ... XDG_RUNTIME_DIR=/run/user/<uid> DBUS_SESSION_BUS_ADDRESS=...
#   tests/e2e/lab/owner.sh <a|b> podman ps -a
#   tests/e2e/lab/owner.sh <a|b> systemctl --user status woowbk-demo-app.service
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
shift
tty_flag=()
[ -t 0 ] && [ -t 1 ] && tty_flag=(-t)
exec "$LP" exec -i "${tty_flag[@]}" "$NAME" /usr/local/bin/woowbk-owner "$@"
