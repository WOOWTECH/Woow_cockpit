#!/bin/bash
# Fixed source/key paths; only owner.sh may enter dev-d. No host production Podman.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
device_vars d
git -C "$REPO_ROOT" diff --quiet && git -C "$REPO_ROOT" diff --cached --quiet || die 'commit tested code first'
main_lock=/tmp/woowbk-dev-d-mutation.lock
[[ -f "$main_lock" && ! -L "$main_lock" && -O "$main_lock" ]] || die 'unsafe existing main lock'
exec 9<"$main_lock"
[[ /proc/self/fd/9 -ef "$main_lock" && -f /proc/self/fd/9 && -O /proc/self/fd/9 && "$(stat -Lc %h /proc/self/fd/9)" = 1 ]] || die 'main lock identity refused'
flock -n 9 || die 'dev-d mutation owner busy'
volume_lock=/tmp/headscale-dev-d-private-volume.lock
[[ -f "$volume_lock" && ! -L "$volume_lock" && -O "$volume_lock" ]] || die 'unsafe existing volume lock'
exec 8<"$volume_lock"
[[ /proc/self/fd/8 -ef "$volume_lock" && -f /proc/self/fd/8 && -O /proc/self/fd/8 && "$(stat -Lc %h /proc/self/fd/8)" = 1 ]] || die 'volume lock identity refused'
flock -n 8 || die 'headscale owner busy'
"$LAB_DIR/owner.sh" d --verify-isolation >/dev/null
read -r current maximum < <("$LP" exec "$NAME" sh -c 'echo "$(cat /sys/fs/cgroup/memory.current) $(cat /sys/fs/cgroup/memory.max)"')
preflight_mode=false
[[ "${1:-}" != --preflight && "${1:-}" != --x86-preflight ]] || preflight_mode=true
if "$preflight_mode"; then
    (( maximum - current >= 1073741824 )) || die 'less than 1 GiB preflight headroom'
fi
(( maximum - current >= 536870912 )) || die 'less than512MiB headroom'
# Recheck on both successful and failed owner execution. Do not delete anything
# here: a residue must fail the run and remain available for private diagnosis.
postflight() {
    original=$?
    trap - EXIT
    set +e
    "$LAB_DIR/owner.sh" d --verify-isolation >/dev/null
    isolated=$?
    "$LAB_DIR/owner.sh" d python3 -c 'import pathlib,subprocess,sys; p=subprocess.run(["podman","ps","-aq","--filter","name=emqx-native-"],capture_output=True,text=True); ok=p.returncode==0 and not p.stdout.strip() and not list(pathlib.Path("/tmp").glob("woowbk-arm-code-*")) and not list(pathlib.Path.home().glob("woowbk-arm-cold-private-*")) and not any(list(pathlib.Path("/tmp").glob(pattern)) for pattern in ("emqx-hocon-private-*","emqx-cold-private-*","emqx-cold-diagnostic-private-*","emqx-vendor-acl-private-*")); sys.exit(0 if ok else 1)'
    clean=$?
    if "$preflight_mode"; then
        "$LAB_DIR/owner.sh" d python3 -c 'import pathlib,subprocess,sys; c=subprocess.run(["podman","ps","-aq","--filter","name=woowbk-emqx-fresh-"],capture_output=True); v=subprocess.run(["podman","volume","ls","-q","--filter","name=woowbk-emqx-fresh-"],capture_output=True); ok=c.returncode==v.returncode==0 and not c.stdout.strip() and not v.stdout.strip() and not any(list(pathlib.Path.home().glob(p)) for p in ("emqx-preflight-private-*","emqx-framed-private-*","emqx-fresh-private-*")) and not list(pathlib.Path("/tmp").glob("emqx-vendor-files-*")); sys.exit(0 if ok else 1)'
        fresh_clean=$?
        if [ "$fresh_clean" -ne 0 ]; then clean=1; fi
    fi
    if [ "$isolated" -ne 0 ] || [ "$clean" -ne 0 ]; then
        echo 'ARM POSTFLIGHT REFUSED'
        exit 1
    fi
    echo 'ARM POSTFLIGHT PASSED'
    exit "$original"
}
trap postflight EXIT
python3 "$LAB_DIR/emqx_arm_cold_transfer.py" "$@"
