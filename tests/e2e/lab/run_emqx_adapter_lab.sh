#!/bin/bash
# Only the isolated dev-d wrapper may access Podman. Never use host Podman.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
device_vars d
image_id=3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b
isolation=$("$LP" inspect --format '{{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}} {{.State.Status}}' "$NAME")
[[ "$isolation" == 'none {} running' ]] || die 'dev-d isolation is not confirmed'
read -r current maximum < <("$LP" exec "$NAME" sh -c 'printf "%s %s\n" "$(cat /sys/fs/cgroup/memory.current)" "$(cat /sys/fs/cgroup/memory.max)"')
[[ "$current" =~ ^[0-9]+$ && "$maximum" =~ ^[0-9]+$ ]] || die 'unknown cgroup memory limit'
(( maximum - current >= 1073741824 )) || die 'dev-d has less than 1 GiB cgroup headroom'
tmp=$("$LP" exec "$NAME" mktemp -d /tmp/woowbk-emqxcode-XXXXXXXX)
[[ "$tmp" =~ ^/tmp/woowbk-emqxcode-[A-Za-z0-9]{8}$ ]] || die 'unexpected staging path'
cleanup() {
    "$LP" exec "$NAME" rm -rf -- "$tmp" || { echo 'synthetic code cleanup failed' >&2; exit 1; }
}
trap cleanup EXIT
tar -C "$REPO_ROOT" -cf - backup-engine/woowbackup \
    tests/e2e/lab/emqx_adapter_fixture.py tests/e2e/lab/emqx_adapter_provision.py \
    tests/e2e/lab/emqx_adapter_flow.py tests/e2e/lab/emqx_adapter_driver.py |
    "$LP" exec -i "$NAME" tar -xf - -C "$tmp"
suffix=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
"$LP" exec "$NAME" env PYTHONPATH="$tmp/backup-engine" PYTHONDONTWRITEBYTECODE=1 \
    python3 "$tmp/tests/e2e/lab/emqx_adapter_driver.py" --image-id "$image_id" \
    --work "/tmp/woowbk-emqxlab-$suffix"
