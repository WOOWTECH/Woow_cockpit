#!/bin/bash
# Verify a lab device for real (exit 0 only when every check passes):
#   1. systemd state is "running" (degraded fails and lists the failed units)
#   2. cockpit.socket active and listening on 9090
#   3. appowner's user manager (user@<uid>.service) active, its own state "running"
#   4. nested rootless podman as appowner (engine-style runuser + env): alpine runs, id map is
#      the expected one, the storage driver is overlay
#   5. the Quadlet user generator turns ~/.config/containers/systemd/*.container into a user
#      service that starts and stops (probe unit removed afterwards)
#   6. Cockpit HTTPS login + administrative access via Playwright (skip with --no-browser)
#   tests/e2e/lab/verify-device.sh <a|b> [--no-browser]
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
browser=yes
[ "${2:-}" = --no-browser ] && browser=no
[ "$(container_state "$NAME")" = running ] || die "$NAME is not running (tests/e2e/lab/up.sh $DEV)"
failures=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; failures=$((failures + 1)); }
owner() { "$LP" exec -i "$NAME" /usr/local/bin/woowbk-owner "$@"; }

# 1. systemd
state=$("$LP" exec "$NAME" systemctl is-system-running 2>/dev/null || true)
if [ "$state" = running ]; then
    pass "systemd is-system-running: running"
else
    fail "systemd is-system-running: $state; failed units: $("$LP" exec "$NAME" systemctl --failed --no-legend --plain | awk '{print $1}' | xargs)"
fi

# 2. Cockpit socket
if "$LP" exec "$NAME" sh -c 'systemctl is-active --quiet cockpit.socket && ss -Hltn "sport = :9090" | grep -q 9090'; then
    pass "cockpit.socket active, listening on :9090 (host https://127.0.0.1:$PORT)"
else
    fail "cockpit.socket not listening"
fi

# 3. user manager
uid=$("$LP" exec "$NAME" id -u "$OWNER")
[ "$uid" = "$OWNER_UID" ] && pass "$OWNER uid $uid" || fail "$OWNER uid $uid, expected $OWNER_UID"
if "$LP" exec "$NAME" systemctl is-active --quiet "user@$uid.service"; then
    pass "user@$uid.service active (linger: $("$LP" exec "$NAME" sh -c "test -e /var/lib/systemd/linger/$OWNER && echo yes || echo no"))"
else
    fail "user@$uid.service not active"
fi
ustate=$(owner systemctl --user is-system-running 2>/dev/null || true)
[ "$ustate" = running ] && pass "user manager state: running" || fail "user manager state: $ustate"

# 4. nested rootless podman
info=$(owner podman info --format '{{.Store.GraphDriverName}} native-diff={{index .Store.GraphStatus "Native Overlay Diff"}} backing={{index .Store.GraphStatus "Backing Filesystem"}} net={{.Host.NetworkBackend}} runtime={{.Host.OCIRuntime.Name}} cgroups={{.Host.CgroupsVersion}}/{{.Host.CgroupManager}}' 2>&1 | tail -1)
case "$info" in overlay*) pass "podman storage: $info" ;; *) fail "podman storage: $info" ;; esac
PROBE_IMAGE=docker.io/library/alpine:3.20
had_probe_image=no
owner podman image exists "$PROBE_IMAGE" && had_probe_image=yes
probe=$(owner podman run --rm --memory 64m --name woowbk-probe-run docker.io/library/alpine:3.20 \
    sh -c 'echo "$(id -u) $(cat /sys/fs/cgroup/memory.max)"; tr -s " " < /proc/self/uid_map | xargs' 2>&1 | tail -2 | xargs)
# Each device may have its own subordinate range (subids.sh; dev-b differs on purpose): expect the configured one.
subrange=$("$LP" exec "$NAME" awk -F: -v owner="$OWNER" '$1 == owner { print $2, $3; exit }' /etc/subuid)
expected="0 67108864 0 $uid 1 1 $subrange"
[ "$probe" = "$expected" ] && pass "nested alpine: uid/memory.max/uid_map = $probe" || fail "nested alpine: got '$probe', expected '$expected'"

# 5. Quadlet generator -> user service
unit_text='[Unit]
Description=woowbk lab probe (Quadlet generator check)
[Container]
ContainerName=woowbk-probe-quadlet
Image=docker.io/library/alpine:3.20
Exec=sleep 300
PodmanArgs=--memory 64m
'
printf '%s' "$unit_text" | owner sh -c 'mkdir -p "$HOME/.config/containers/systemd" && cat > "$HOME/.config/containers/systemd/woowbk-probe.container"'
owner systemctl --user daemon-reload
source_path=$(owner systemctl --user show -P SourcePath woowbk-probe.service 2>/dev/null || true)
if [ "$source_path" = "/home/$OWNER/.config/containers/systemd/woowbk-probe.container" ]; then
    pass "quadlet generator produced woowbk-probe.service (SourcePath $source_path)"
else
    fail "quadlet generator: SourcePath '$source_path'"
fi
if owner systemctl --user start woowbk-probe.service && \
   [ "$(owner podman inspect --format '{{.State.Status}}' woowbk-probe-quadlet 2>/dev/null)" = running ]; then
    pass "woowbk-probe.service started, container running"
else
    fail "woowbk-probe.service did not start"
fi
owner systemctl --user stop woowbk-probe.service || true
owner rm -f "/home/$OWNER/.config/containers/systemd/woowbk-probe.container"
owner systemctl --user daemon-reload
owner systemctl --user reset-failed woowbk-probe.service >/dev/null 2>&1 || true
# Leave a fresh device fresh: drop the probe image unless it was already there.
if [ "$had_probe_image" = no ]; then owner podman rmi "$PROBE_IMAGE" >/dev/null 2>&1 || true; fi

# Facts for the record
echo "INFO  $("$LP" exec "$NAME" sh -c '. /etc/os-release; echo "$PRETTY_NAME"; uname -r; cat /etc/woowbk-device-versions' | xargs)"
echo "INFO  machine-id $("$LP" exec "$NAME" cat /etc/machine-id) hostname $("$LP" exec "$NAME" hostname)"
echo "INFO  subuid $("$LP" exec "$NAME" cat /etc/subuid | xargs) subgid $("$LP" exec "$NAME" cat /etc/subgid | xargs)"

# 6. Cockpit login over HTTPS + administrative access
if [ "$browser" = yes ]; then
    check_memory
    if node "$LAB_DIR/cockpit-login.mjs" "$DEV" > "$EVIDENCE_DIR/cockpit-login-$DEV.json"; then
        pass "cockpit login + administrative access ($EVIDENCE_DIR/cockpit-login-$DEV.json)"
    else
        fail "cockpit login: $(tr -d '\n' < "$EVIDENCE_DIR/cockpit-login-$DEV.json" | head -c 400)"
    fi
fi

if [ "$failures" -eq 0 ]; then echo "RESULT $NAME: all checks passed"; else echo "RESULT $NAME: $failures check(s) failed"; fi
exit $((failures > 0))
