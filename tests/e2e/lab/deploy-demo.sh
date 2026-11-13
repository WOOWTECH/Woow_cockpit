#!/bin/bash
# Deploy the woowbk-demo fixture by hand (NOT through the backup engine) on a lab device:
#   tests/e2e/lab/deploy-demo.sh <a|b> [--notes N] [--files M] [--title T] [--no-seed]
# 1. copy catalog-examples/woowbk-demo to /opt/woowbk-demo (root-owned, world-readable)
# 2. as appowner: pull postgres:16-alpine, build localhost/woowbk-demo-app:1
# 3. as appowner: install the Quadlet templates into ~/.config/containers/systemd/, daemon-reload
# 4. as appowner: tools/seed.py (random secrets, env file, start units, insert notes + files)
# Re-running is safe: existing secrets, env title and data are kept; notes/files are added.
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
shift
seed_args=()
seed=yes
while [ $# -gt 0 ]; do
    case "$1" in
        --notes | --files | --title) seed_args+=("$1" "$2"); shift 2 ;;
        --no-seed) seed=no; shift ;;
        *) die "unknown argument $1" ;;
    esac
done
[ "$(container_state "$NAME")" = running ] || die "$NAME is not running (tests/e2e/lab/up.sh $DEV)"
check_memory
owner() { "$LP" exec -i "$NAME" /usr/local/bin/woowbk-owner "$@"; }
FIXTURE=$REPO_ROOT/catalog-examples/woowbk-demo

log "copying fixture to $NAME:/opt/woowbk-demo"
tar -C "$FIXTURE" --exclude=__pycache__ -cf - . | dexec "$NAME" sh -c \
    'rm -rf /opt/woowbk-demo.new && mkdir -p /opt/woowbk-demo.new && tar -C /opt/woowbk-demo.new --no-same-owner -xf - &&
     chmod -R u=rwX,go=rX /opt/woowbk-demo.new && rm -rf /opt/woowbk-demo && mv /opt/woowbk-demo.new /opt/woowbk-demo'

log "pulling docker.io/library/postgres:16-alpine and building localhost/woowbk-demo-app:1 as $OWNER"
owner podman pull --quiet docker.io/library/postgres:16-alpine >/dev/null
owner podman build --quiet --memory 512m -t localhost/woowbk-demo-app:1 /opt/woowbk-demo/app >/dev/null
owner podman image ls --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}' | grep -E 'postgres|woowbk-demo-app' >&2

log "installing Quadlet templates into ~$OWNER/.config/containers/systemd/"
owner sh -c 'mkdir -p -m 0700 "$HOME/.config" && mkdir -p "$HOME/.config/containers/systemd" &&
    install -m 0644 /opt/woowbk-demo/quadlet/woowbk-demo.network /opt/woowbk-demo/quadlet/woowbk-demo-db.container \
        /opt/woowbk-demo/quadlet/woowbk-demo-app.container "$HOME/.config/containers/systemd/"'
owner systemctl --user daemon-reload
for unit in woowbk-demo-network.service woowbk-demo-db.service woowbk-demo-app.service; do
    load=$(owner systemctl --user show -P LoadState "$unit")
    [ "$load" = loaded ] || die "$unit LoadState=$load after daemon-reload"
done
log "units generated: woowbk-demo-network.service woowbk-demo-db.service woowbk-demo-app.service"

if [ "$seed" = yes ]; then
    owner python3 /opt/woowbk-demo/tools/seed.py "${seed_args[@]}"
fi
