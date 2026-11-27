#!/usr/bin/env bash
# Host-side entry point. The inner runner refuses routes and cleans up its own objects.
set -Eeuo pipefail
here=$(cd "$(dirname "$0")" && pwd)
labpodman=${WOOWBK_LAB_HOME:-$HOME/.woowbk-lab}/bin/labpodman
state=$("$labpodman" inspect woowbk-dev-d --format '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}')
[[ "$state" == 'true none {}' ]] || { echo "dev-d is not isolated: $state" >&2; exit 1; }
memory=$("$labpodman" exec woowbk-dev-d sh -c 'read -r current </sys/fs/cgroup/memory.current; read -r max </sys/fs/cgroup/memory.max; echo "$current $max"')
read -r current max <<< "$memory"
[[ "$max" =~ ^[0-9]+$ && "$current" =~ ^[0-9]+$ ]] || { echo 'Cannot verify cgroup memory' >&2; exit 1; }
(( max - current >= 2147483648 )) || { echo "Insufficient dev-d headroom: current=$current limit=$max; need 2 GiB free" >&2; exit 1; }
active=$("$labpodman" exec woowbk-dev-d runuser -u appowner -- env XDG_RUNTIME_DIR=/run/user/1019 \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1019/bus podman ps --format '{{.Names}}')
if grep -Eq '^(woowbk-emqx-synthetic-|woowbk-j.*-emqx-(new|ha)$)' <<< "$active"; then
  echo 'Concurrent synthetic EMQX job is active; refusing to start' >&2; exit 1
fi
"$labpodman" exec -i woowbk-dev-d runuser -u appowner -- env \
  XDG_RUNTIME_DIR=/run/user/1019 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1019/bus \
  bash -s < "$here/headscale-internal-runner.sh"
state=$("$labpodman" inspect woowbk-dev-d --format '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}')
[[ "$state" == 'true none {}' ]] || { echo "dev-d isolation changed: $state" >&2; exit 1; }
