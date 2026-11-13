#!/bin/bash
# Deploy the woowbk-dirs fixture by hand (NOT through the backup engine) on a lab device:
#   tests/e2e/lab/deploy-dirs.sh <a|b> [--items N] [--delete K] [--title T] [--owner-note T] [--seed S] [--no-seed]
# 1. copy catalog-examples/woowbk-dirs to /opt/woowbk-dirs (root-owned, world-readable)
# 2. as appowner: pull postgres:16-alpine (when missing), build localhost/woowbk-dirs-app:1
# 3. as appowner: install the Quadlet templates into ~/.config/containers/systemd/, daemon-reload
# 4. as appowner: tools/seed.py (random secrets, env file, host directories with their container owners,
#    database bootstrap: role dirs_app + database dirs_audit, start units, add items)
# Re-running is safe: existing secrets, settings, host directories and data are kept; items are added (none with
# --items 0, which only brings the fixture up to date: missing host-directory items are created, and running units
# are restarted when their Quadlet file or the app image changed).
# The trusted catalog entry is separate (root): tests/e2e/lab/dirs-catalog.sh <a|b> install.
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
shift
seed_args=()
seed=yes
while [ $# -gt 0 ]; do
    case "$1" in
        --items | --delete | --title | --owner-note | --seed) seed_args+=("$1" "$2"); shift 2 ;;
        --no-seed) seed=no; shift ;;
        *) die "unknown argument $1" ;;
    esac
done
[ "$(container_state "$NAME")" = running ] || die "$NAME is not running (tests/e2e/lab/up.sh $DEV)"
check_memory
owner() { "$LP" exec -i "$NAME" /usr/local/bin/woowbk-owner "$@"; }
FIXTURE=$REPO_ROOT/catalog-examples/woowbk-dirs

log "copying fixture to $NAME:/opt/woowbk-dirs"
tar -C "$FIXTURE" --exclude=__pycache__ -cf - . | dexec "$NAME" sh -c \
    'rm -rf /opt/woowbk-dirs.new && mkdir -p /opt/woowbk-dirs.new && tar -C /opt/woowbk-dirs.new --no-same-owner -xf - &&
     chmod -R u=rwX,go=rX /opt/woowbk-dirs.new && rm -rf /opt/woowbk-dirs && mv /opt/woowbk-dirs.new /opt/woowbk-dirs'

if ! owner podman image exists docker.io/library/postgres:16-alpine; then
    log "pulling docker.io/library/postgres:16-alpine as $OWNER"
    owner podman pull --quiet docker.io/library/postgres:16-alpine >/dev/null
fi
old_image=$(owner podman image inspect --format '{{.Id}}' localhost/woowbk-dirs-app:1 2>/dev/null || true)
log "building localhost/woowbk-dirs-app:1 as $OWNER"
owner podman build --quiet --memory 512m -t localhost/woowbk-dirs-app:1 /opt/woowbk-dirs/app >/dev/null
new_image=$(owner podman image inspect --format '{{.Id}}' localhost/woowbk-dirs-app:1)
owner podman image ls --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}' | grep -E 'postgres|woowbk-dirs-app' >&2

QUADLETS="woowbk-dirs.network woowbk-dirs-db.container woowbk-dirs-app.container"
quadlet_sums() { owner sh -c "cd \"\$HOME/.config/containers/systemd\" 2>/dev/null && sha256sum $QUADLETS 2>/dev/null" || true; }
old_quadlets=$(quadlet_sums)
log "installing Quadlet templates into ~$OWNER/.config/containers/systemd/"
owner sh -c 'mkdir -p -m 0700 "$HOME/.config" && mkdir -p "$HOME/.config/containers/systemd" &&
    install -m 0644 /opt/woowbk-dirs/quadlet/woowbk-dirs.network /opt/woowbk-dirs/quadlet/woowbk-dirs-db.container \
        /opt/woowbk-dirs/quadlet/woowbk-dirs-app.container "$HOME/.config/containers/systemd/"'
owner systemctl --user daemon-reload
for unit in woowbk-dirs-network.service woowbk-dirs-db.service woowbk-dirs-app.service; do
    load=$(owner systemctl --user show -P LoadState "$unit")
    [ "$load" = loaded ] || die "$unit LoadState=$load after daemon-reload"
done
log "units generated: woowbk-dirs-network.service woowbk-dirs-db.service woowbk-dirs-app.service"

# A running deployment picks up a changed definition or image only when restarted (the app's Requires= on the
# database restarts it together with the database).
if [ -n "$old_quadlets" ] && [ "$old_quadlets" != "$(quadlet_sums)" ] &&
    owner systemctl --user is-active --quiet woowbk-dirs-db.service; then
    log "Quadlet files changed: restarting woowbk-dirs-db.service (and the app with it)"
    owner systemctl --user restart woowbk-dirs-db.service woowbk-dirs-app.service
elif [ -n "$old_image" ] && [ "$old_image" != "$new_image" ] &&
    owner systemctl --user is-active --quiet woowbk-dirs-app.service; then
    log "app image changed: restarting woowbk-dirs-app.service"
    owner systemctl --user restart woowbk-dirs-app.service
fi

if [ "$seed" = yes ]; then
    owner python3 /opt/woowbk-dirs/tools/seed.py "${seed_args[@]}"
fi
