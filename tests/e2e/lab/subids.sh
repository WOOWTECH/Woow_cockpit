#!/bin/bash
# Show or change appowner's subordinate id range on a lab device.
#   tests/e2e/lab/subids.sh <a|b>                                   # /etc/subuid, /etc/subgid, live uid_map/gid_map
#   tests/e2e/lab/subids.sh <a|b> START:COUNT --reset-storage       # e.g. b 10500:55000
#
# Why: a cross-device restore must map container ids through the TARGET owner's namespace. With the same range
# on both devices, files of container uid 33 have the same host id on both and a restore that copies host ids
# would pass unnoticed; dev-b therefore gets its own range (dev-a keeps the default 10000:55000).
# Bounds: START >= 10000 (real accounts stay below), COUNT >= 1000, START+COUNT <= 65534 (nobody stays unmapped);
# keep COUNT at 55000 so container ids up to 55000 still map (the volume fidelity case uses uid 54999).
#
# Changing the range invalidates the owner's whole Podman storage (image layers, volumes and container files
# belong to the old ids), so --reset-storage is required and does, in this order:
#   1. refuses when the owner has Quadlet files other than the lab apps woowbk-demo and woowbk-dirs;
#   2. tears both lab apps down owner-side (units stopped/unmasked, Quadlet files, secrets, settings, host
#      directories; teardown-dirs.sh for woowbk-dirs), so the device is a fresh restore target;
#   3. refuses when the owner's home still holds files of other ids outside the Podman storage;
#   4. `podman system reset --force` as the owner (old mapping), rewrites /etc/subuid and /etc/subgid,
#      `podman system migrate`, and checks the new map. Images must be pulled, built or restored again.
# woowbk-provision (run by up.sh) keeps a valid range, so the change survives restarts. Backups are not touched.
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
range=${2:-}
[ "$(container_state "$NAME")" = running ] || die "$NAME is not running (tests/e2e/lab/up.sh $DEV)"
owner() { "$LP" exec -i "$NAME" /usr/local/bin/woowbk-owner "$@"; }

show() {
    dexec "$NAME" sh -c 'echo "subuid: $(cat /etc/subuid)"; echo "subgid: $(cat /etc/subgid)"'
    owner sh -c 'echo "uid_map:" $(podman unshare cat /proc/self/uid_map); echo "gid_map:" $(podman unshare cat /proc/self/gid_map)'
}

if [ -z "$range" ]; then
    show
    exit 0
fi
[ "${3:-}" = --reset-storage ] || die "changing the range needs --reset-storage (see the header of $0)"
[[ "$range" =~ ^([0-9]+):([0-9]+)$ ]] || die "range must be START:COUNT"
start=${BASH_REMATCH[1]}
count=${BASH_REMATCH[2]}
[ "$start" -ge 10000 ] && [ "$count" -ge 1000 ] && [ $((start + count)) -le 65534 ] ||
    die "range $range outside 10000..65533 (or COUNT < 1000)"
current=$("$LP" exec "$NAME" cat /etc/subuid /etc/subgid)
if [ "$current" = "$(printf '%s:%s:%s\n%s:%s:%s' "$OWNER" "$start" "$count" "$OWNER" "$start" "$count")" ]; then
    log "$NAME already uses $range"
    show
    exit 0
fi

# 1. Only the lab apps may be deployed.
others=$(owner sh -c 'ls -A "$HOME/.config/containers/systemd" 2>/dev/null' |
    grep -v -x -E 'woowbk-demo(\.network|-db\.container|-app\.container)|woowbk-dirs(\.network|-db\.container|-app\.container)' || true)
[ -z "$others" ] || die "the owner has other Quadlet files, refusing: $(echo $others)"

# 2. Owner-side teardown of both lab apps (same steps as cli_e2e.py's reset of woowbk-demo).
log "tearing down woowbk-demo and woowbk-dirs on $NAME (owner side)"
owner sh -s <<'DEMO'
set -u
cd "$HOME"
systemctl --user stop woowbk-demo-app.service woowbk-demo-db.service woowbk-demo-network.service 2>/dev/null
for unit in woowbk-demo-app.service woowbk-demo-db.service; do
    [ -L ".config/systemd/user/$unit" ] && systemctl --user unmask "$unit"
    rm -f ".config/systemd/user/$unit.d/"woowbk-*.conf
    rmdir ".config/systemd/user/$unit.d" 2>/dev/null
done
rm -f .config/containers/systemd/woowbk-demo.network .config/containers/systemd/woowbk-demo-db.container \
      .config/containers/systemd/woowbk-demo-app.container
systemctl --user daemon-reload
systemctl --user reset-failed 2>/dev/null
podman volume rm -f woowbk-demo-files woowbk-demo-pgdata >/dev/null 2>&1
podman secret rm woowbk-demo-db-password >/dev/null 2>&1
podman secret rm woowbk-demo-app-key >/dev/null 2>&1
rm -rf .config/woowbk-demo
podman network rm -f woowbk-demo >/dev/null 2>&1
true
DEMO
"$LAB_DIR/teardown-dirs.sh" "$DEV" >&2

# 3. Files of other ids left in the home (outside the Podman storage) would become unmanageable.
uid=$("$LP" exec "$NAME" id -u "$OWNER")
gid=$("$LP" exec "$NAME" id -g "$OWNER")
stray=$("$LP" exec "$NAME" sh -c "find /home/$OWNER -xdev -path /home/$OWNER/.local/share/containers -prune -o \
    \( ! -uid $uid -o ! -gid $gid \) -print | head -20")
[ -z "$stray" ] || die "files of other ids in /home/$OWNER (remove them first): $(echo $stray)"

# 4. Reset the storage under the old mapping, switch the range, migrate.
log "podman system reset --force as $OWNER on $NAME (old mapping)"
owner podman system reset --force >/dev/null 2>&1 || die "podman system reset failed"
dexec "$NAME" sh -c "printf '%s:%s:%s\n' $OWNER $start $count > /etc/subuid && printf '%s:%s:%s\n' $OWNER $start $count > /etc/subgid &&
    chmod 0644 /etc/subuid /etc/subgid"
owner podman system migrate >/dev/null 2>&1 || die "podman system migrate failed"
map=$(owner podman unshare cat /proc/self/uid_map | tr -s ' ' | sed 's/^ //')
expected=$(printf '0 %s 1\n1 %s %s' "$uid" "$start" "$count")
[ "$map" = "$expected" ] || die "unexpected uid_map after the change: $map"
log "$NAME: appowner subordinate ids now $range (storage reset; images must be pulled, built or restored again)"
show
