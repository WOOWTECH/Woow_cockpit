# Shared settings for the backup lab scripts (sourced, not executed).
# Everything goes through labpodman: a separate storage root, production containers are invisible.
set -euo pipefail

LAB_HOME=${WOOWBK_LAB_HOME:-$HOME/.woowbk-lab}
LP=$LAB_HOME/bin/labpodman
LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$LAB_DIR/../../.." && pwd)
IMAGE=localhost/woowbk-device:noble
SECRETS_DIR=$LAB_HOME/secrets
PASS_FILE=$SECRETS_DIR/devadmin.pass
EVIDENCE_DIR=$LAB_HOME/evidence/lab
# Host memory is tight: refuse to start containers below this much MemAvailable.
MIN_AVAIL_MB=${WOOWBK_MIN_AVAIL_MB:-1200}
DEVICE_MEMORY=768m
DEVICE_CPUS=1.5
OWNER=appowner

die() { echo "lab: $*" >&2; exit 1; }
log() { echo "lab: $*" >&2; }

[ -x "$LP" ] || die "missing $LP"

# device_vars <a|b>: sets DEV NAME PORT OWNER_UID VOLUMES
device_vars() {
    case "${1:-}" in
        a | dev-a | woowbk-dev-a) DEV=a; PORT=19091; OWNER_UID=1001 ;;
        b | dev-b | woowbk-dev-b) DEV=b; PORT=19092; OWNER_UID=1007 ;;
        *) die "device must be 'a' or 'b' (got '${1:-}')" ;;
    esac
    NAME=woowbk-dev-$DEV
    # /home holds appowner's nested container storage: a volume (host ext4), so nested rootless
    # overlay works natively instead of overlay-on-overlay.
    VOLUMES=("$NAME-home" "$NAME-varlib" "$NAME-containers")
}

mem_available_mb() { awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo; }

check_memory() {
    local avail
    avail=$(mem_available_mb)
    [ "$avail" -ge "$MIN_AVAIL_MB" ] || die "only ${avail} MB available (< ${MIN_AVAIL_MB} MB); stop something first"
    log "memory available: ${avail} MB"
}

container_state() { "$LP" container inspect --format '{{.State.Status}}' "$1" 2>/dev/null || echo absent; }

ensure_password() {
    install -d -m 0700 "$SECRETS_DIR"
    if [ ! -s "$PASS_FILE" ]; then
        (umask 077 && openssl rand -hex 16 > "$PASS_FILE.tmp" && mv "$PASS_FILE.tmp" "$PASS_FILE")
        log "generated $PASS_FILE"
    fi
    chmod 0600 "$PASS_FILE"
}

# dexec <name> <cmd...>: root command inside a device, stdin attached.
dexec() { local name=$1; shift; "$LP" exec -i "$name" "$@"; }

# wait_for <seconds> <description> <cmd...>
wait_for() {
    local timeout=$1 what=$2; shift 2
    local deadline=$((SECONDS + timeout))
    until "$@" >/dev/null 2>&1; do
        [ "$SECONDS" -lt "$deadline" ] || die "timed out after ${timeout}s waiting for: $what"
        sleep 2
    done
}
