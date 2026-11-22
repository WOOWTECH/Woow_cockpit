#!/bin/bash
# Host entry: only lab wrapper and owner.sh may access isolated dev-d.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
device_vars d
git -C "$REPO_ROOT" diff --quiet && git -C "$REPO_ROOT" diff --cached --quiet || die "commit tested code first"
printf '{"stage":"source","commit":"%s"}\n' "$(git -C "$REPO_ROOT" rev-parse HEAD)"
exec 9>/tmp/woowbk-dev-d-mutation.lock
flock -n 9 || die 'dev-d mutation owner busy'
exec 8>/tmp/headscale-dev-d-private-volume.lock
flock -n 8 || die 'existing headscale mutation owner busy'
"$LAB_DIR/owner.sh" d --verify-isolation
read -r current maximum < <("$LP" exec "$NAME" sh -c 'echo "$(cat /sys/fs/cgroup/memory.current) $(cat /sys/fs/cgroup/memory.max)"')
(( maximum - current >= 1073741824 )) || die 'less than 1 GiB cgroup headroom'
printf '{"stage":"resources","memory_current":%s,"memory_max":%s}\n' "$current" "$maximum"
tar -cf - -C "$REPO_ROOT" backup-engine/woowbackup -C "$LAB_DIR" ha_real_fixture.py emqx_runtime_live.py emqx_runtime_credentials.py emqx_private_boundary.py emqx_private_evidence.py emqx_real_candidate.py emqx_candidate_stage.py |
    "$LAB_DIR/owner.sh" d sh -c '
set -eu
umask 077
work=$(mktemp -d /tmp/woowbk-runtime-code-XXXXXXXX)
trap '\''rm -rf -- "$work"'\'' EXIT
cat > "$work/code.tar"
tar -xf "$work/code.tar" -C "$work"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$work/backup-engine:$work" python3 "$work/emqx_runtime_live.py"
'

"$LAB_DIR/owner.sh" d --verify-isolation
