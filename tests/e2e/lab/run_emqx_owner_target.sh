#!/bin/bash
# Owner handoff only: BOTH mutation locks, owner.sh transport, one fresh fixture.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
device_vars d
git -C "$REPO_ROOT" diff --quiet && git -C "$REPO_ROOT" diff --cached --quiet || die 'commit tested code first'
exec 9>/tmp/woowbk-dev-d-mutation.lock
flock -n 9 || die 'dev-d mutation owner busy'
exec 8>/tmp/headscale-dev-d-private-volume.lock
flock -n 8 || die 'headscale mutation owner busy'
postflight() {
    "$LAB_DIR/owner.sh" d --verify-isolation
    owned=$("$LAB_DIR/owner.sh" d podman ps -a --filter name=woowbk-emqx-workload- --format '{{.Names}}')
    [ -z "$owned" ] || die 'owned workload container remains'
    volumes=$("$LAB_DIR/owner.sh" d podman volume ls --filter name=woowbk-emqx-workload- --format '{{.Name}}')
    [ -z "$volumes" ] || die 'owned workload volume remains'
    echo '{"stage":"postflight","owned":"zero","network":"none","ports":"empty"}'
}
trap postflight EXIT
postflight
read -r current maximum < <("$LAB_DIR/owner.sh" d sh -c 'echo "$(cat /sys/fs/cgroup/memory.current) $(cat /sys/fs/cgroup/memory.max)"')
(( maximum - current >= 1073741824 )) || die 'less than 1 GiB cgroup headroom'
printf '{"stage":"source","commit":"%s"}\n' "$(git -C "$REPO_ROOT" rev-parse HEAD)"
tar -cf - -C "$REPO_ROOT" backup-engine/woowbackup -C "$LAB_DIR" \
    emqx_broker_workload.py emqx_broker_owner_target.py emqx_owner_target.py emqx_owner_target.expr emqx_owner_target_parse.escript \
    emqx_target_capture.py emqx_target_snapshots.py emqx_persisted_values.py emqx_semantic_readers.py \
    ha_real_fixture.py emqx_runtime_live.py emqx_runtime_credentials.py emqx_private_boundary.py \
    emqx_private_evidence.py emqx_real_candidate.py |
    "$LAB_DIR/owner.sh" d sh -c '
set -eu
umask 077
work=$(mktemp -d /tmp/woowbk-owner-target-code-XXXXXXXX)
trap '\''rm -rf -- "$work"'\'' EXIT
cat > "$work/code.tar"
tar -xf "$work/code.tar" -C "$work"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$work/backup-engine:$work" python3 "$work/emqx_broker_workload.py" --mode owner-target
'
