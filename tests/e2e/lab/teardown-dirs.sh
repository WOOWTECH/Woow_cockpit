#!/bin/bash
# Remove the woowbk-dirs deployment from a lab device, owner-side, the way an operator would to get a fresh
# restore target (dev-b before a cross-device restore):
#   tests/e2e/lab/teardown-dirs.sh <a|b> [--keep-image]
# Stops the units, unmasks them (an interrupted restore may have left them masked), removes the lab's test
# drop-ins (woowbk-d*.conf), the Quadlet files, containers, secrets, network, the env file, both host
# directories with any leftover '.woowbk-new-*' / '.woowbk-old-*' siblings (podman unshare: the files belong to
# subordinate ids) and the app image (unless --keep-image). Backups, the trusted catalog entry
# (dirs-catalog.sh) and the woowbk-demo deployment are not touched. Prints what is left (must be nothing).
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
keep_image=no
[ "${2:-}" = --keep-image ] && keep_image=yes
[ "$(container_state "$NAME")" = running ] || die "$NAME is not running (tests/e2e/lab/up.sh $DEV)"

"$LP" exec -i "$NAME" /usr/local/bin/woowbk-owner env KEEP_IMAGE="$keep_image" sh -s <<'TEARDOWN'
set -u
cd "$HOME"
UNITS="woowbk-dirs-app.service woowbk-dirs-db.service woowbk-dirs-network.service"
systemctl --user stop $UNITS 2>/dev/null
for unit in woowbk-dirs-app.service woowbk-dirs-db.service; do
    if [ -L ".config/systemd/user/$unit" ] || [ "$(systemctl --user show -P UnitFileState "$unit" 2>/dev/null)" = masked ]; then
        systemctl --user unmask "$unit" && echo "unmasked $unit"
    fi
    rm -f ".config/systemd/user/$unit.d/"woowbk-d*.conf
    rmdir ".config/systemd/user/$unit.d" 2>/dev/null
done
rm -f .config/containers/systemd/woowbk-dirs.network .config/containers/systemd/woowbk-dirs-db.container \
      .config/containers/systemd/woowbk-dirs-app.container
systemctl --user daemon-reload
systemctl --user reset-failed $UNITS 2>/dev/null
podman rm -f -i woowbk-dirs-app woowbk-dirs-db >/dev/null 2>&1
for secret in woowbk-dirs-db-password woowbk-dirs-role-password woowbk-dirs-app-key; do
    podman secret rm "$secret" >/dev/null 2>&1
done
podman network rm -f woowbk-dirs >/dev/null 2>&1
rm -rf .config/woowbk-dirs
rm -f .woowbk-d*-marker
podman unshare rm -rf .local/share/woowbk-dirs woowbk-dirs
[ "$KEEP_IMAGE" = yes ] || podman rmi -f localhost/woowbk-dirs-app:1 >/dev/null 2>&1
echo "left after teardown:"
ls -A .config/containers/systemd/ 2>/dev/null | grep woowbk-dirs
ls -d .config/woowbk-dirs .local/share/woowbk-dirs woowbk-dirs 2>/dev/null
podman ps -a --format '{{.Names}}' | grep woowbk-dirs
podman secret ls --format '{{.Name}}' | grep woowbk-dirs
podman network ls --format '{{.Name}}' | grep woowbk-dirs
if [ "$KEEP_IMAGE" != yes ]; then podman image exists localhost/woowbk-dirs-app:1 && echo localhost/woowbk-dirs-app:1; fi
ls -A .config/systemd/user/ 2>/dev/null | grep woowbk-dirs
echo "(end)"
TEARDOWN
