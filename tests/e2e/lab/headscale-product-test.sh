#!/usr/bin/env bash
set -Eeuo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
lp=${WOOWBK_LAB_HOME:-$HOME/.woowbk-lab}/bin/labpodman
state=$($lp inspect woowbk-dev-d --format '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}')
[[ "$state" == 'true none {}' ]] || { echo "dev-d is not isolated: $state" >&2; exit 1; }
memory=$($lp exec woowbk-dev-d sh -c 'read -r current </sys/fs/cgroup/memory.current; read -r max </sys/fs/cgroup/memory.max; echo "$current $max"')
read -r current max <<< "$memory"
[[ "$max" =~ ^[0-9]+$ && "$current" =~ ^[0-9]+$ ]] || { echo 'Cannot verify cgroup memory' >&2; exit 1; }
(( max - current >= 2147483648 )) || { echo "Insufficient dev-d headroom: current=$current limit=$max; need 2 GiB free" >&2; exit 1; }
active=$($lp exec woowbk-dev-d runuser -u appowner -- env XDG_RUNTIME_DIR=/run/user/1019 \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1019/bus podman ps --format '{{.Names}}')
if grep -Eq '^(woowbk-emqx-synthetic-|woowbk-j.*-emqx-(new|ha)$)' <<< "$active"; then
  echo 'Concurrent synthetic EMQX job is active; refusing to start' >&2; exit 1
fi
echo "dev-d memory current=$current limit=$max; headroom >= 2 GiB"
stage=$($lp exec woowbk-dev-d mktemp -d /tmp/headscale-product-engine.XXXXXXXX)
tar -C "$repo" --exclude=__pycache__ -cf - backup-engine tests/e2e/lab/headscale-product-convert.py | \
  "$lp" exec -i woowbk-dev-d tar -xf - -C "$stage"
"$lp" exec -i woowbk-dev-d bash -s -- "$stage" < "$here/headscale-product-runner.sh"
state=$($lp inspect woowbk-dev-d --format '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}')
[[ "$state" == 'true none {}' ]] || { echo "dev-d isolation changed: $state" >&2; exit 1; }
