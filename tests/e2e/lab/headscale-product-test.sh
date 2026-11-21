#!/usr/bin/env bash
set -Eeuo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
owner() { bash "$here/owner.sh" d "$@"; }
installer=0
if [[ ${1:-} == --installer ]]; then installer=1; shift; fi
[[ $# == 0 ]] || { echo 'Usage: headscale-product-test.sh [--installer]' >&2; exit 2; }
owner --verify-isolation
memory=$(owner sh -c 'read -r current </sys/fs/cgroup/memory.current; read -r max </sys/fs/cgroup/memory.max; echo "$current $max"')
read -r current max <<< "$memory"
[[ "$max" =~ ^[0-9]+$ && "$current" =~ ^[0-9]+$ ]] || { echo 'Cannot verify cgroup memory' >&2; exit 1; }
(( max - current >= 2147483648 )) || { echo "Insufficient dev-d headroom: current=$current limit=$max; need 2 GiB free" >&2; exit 1; }
active=$(owner podman ps --format '{{.Names}}')
if grep -Eq '^(woowbk-emqx-synthetic-|woowbk-j|hs-(server|target-server|install|a|b)-)' <<< "$active"; then
  echo 'Concurrent synthetic job is active; refusing to start' >&2; exit 1
fi
echo "dev-d memory current=$current limit=$max; headroom >= 2 GiB"
stage=$(owner mktemp -d /tmp/headscale-product-engine.XXXXXXXX)
trap 'owner --verify-isolation' EXIT
tar -C "$repo" --exclude=__pycache__ -cf - backup-engine tests/e2e/lab/headscale-product-convert.py \
  tests/e2e/lab/headscale-product-runner.sh tests/e2e/lab/headscale-credential-events.py \
  tests/e2e/lab/headscale-auto-reconnect-check.py tests/e2e/lab/headscale-private-sources.py \
  tests/e2e/lab/headscale_install_rollback.py | \
  owner tar -xf - -C "$stage"
owner python3 "$stage/tests/e2e/lab/headscale-credential-events.py" --controller -- \
  bash "$stage/tests/e2e/lab/headscale-product-runner.sh" "$stage" "$installer"
