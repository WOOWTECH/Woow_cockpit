#!/bin/bash
# Fixed source/key paths; only owner.sh may enter dev-d. No host production Podman.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
device_vars d
git -C "$REPO_ROOT" diff --quiet && git -C "$REPO_ROOT" diff --cached --quiet || die 'commit tested code first'
exec 9>/tmp/woowbk-dev-d-mutation.lock
flock -n 9 || die 'dev-d mutation owner busy'
exec 8>/tmp/headscale-dev-d-private-volume.lock
flock -n 8 || die 'headscale owner busy'
"$LAB_DIR/owner.sh" d --verify-isolation >/dev/null
read -r current maximum < <("$LP" exec "$NAME" sh -c 'echo "$(cat /sys/fs/cgroup/memory.current) $(cat /sys/fs/cgroup/memory.max)"')
(( maximum - current >= 536870912 )) || die 'less than512MiB headroom'
# Recheck on both successful and failed owner execution. Do not delete anything
# here: a residue must fail the run and remain available for private diagnosis.
postflight() {
    original=$?
    trap - EXIT
    set +e
    "$LAB_DIR/owner.sh" d --verify-isolation >/dev/null
    isolated=$?
    "$LAB_DIR/owner.sh" d python3 -c 'import pathlib,subprocess,sys; p=subprocess.run(["podman","ps","-aq","--filter","name=emqx-native-"],capture_output=True,text=True); ok=p.returncode==0 and not p.stdout.strip() and not list(pathlib.Path("/tmp").glob("woowbk-arm-code-*")) and not list(pathlib.Path.home().glob("woowbk-arm-cold-private-*")); sys.exit(0 if ok else 1)'
    clean=$?
    if [ "$isolated" -ne 0 ] || [ "$clean" -ne 0 ]; then
        echo 'ARM POSTFLIGHT REFUSED'
        exit 1
    fi
    echo 'ARM POSTFLIGHT PASSED'
    exit "$original"
}
trap postflight EXIT
python3 "$LAB_DIR/emqx_arm_cold_transfer.py"
