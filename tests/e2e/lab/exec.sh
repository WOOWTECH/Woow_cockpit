#!/bin/bash
# Run a command as root inside a lab device (interactive shell by default).
#   tests/e2e/lab/exec.sh <a|b> [cmd...]
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
shift
[ "$#" -gt 0 ] || set -- /bin/bash -l
tty_flag=()
[ -t 0 ] && [ -t 1 ] && tty_flag=(-t)
exec "$LP" exec -i "${tty_flag[@]}" -e LANG=C.UTF-8 "$NAME" "$@"
