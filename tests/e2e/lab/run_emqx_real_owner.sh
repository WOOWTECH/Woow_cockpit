#!/bin/bash
# Sole main lab owner only. Fixed ARM/x86 encrypted profiles; no host Podman.
set -euo pipefail
case "${1:-}" in
    --client-sink-capabilities|--real-restore-mnesia-acl|--x86-real-restore-mnesia-acl|--real-restore|--x86-real-restore|--real-restore-staged|--x86-real-restore-staged|--real-restore-dependencies|--issued-target-probe) ;;
    *) exit 2 ;;
esac
[[ $# = 1 ]] || exit 2
[[ -z "${WOOWBK_LAB_HOME:-}" || "$WOOWBK_LAB_HOME" = /home/woowtechopenclaw/.woowbk-lab ]] || exit 2
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
[[ "$current" =~ ^[0-9]+$ && "$maximum" =~ ^[0-9]+$ ]] || die 'invalid cgroup headroom'
(( maximum - current >= 1887436800 )) || die 'less than1800MiB real-owner headroom'
check_private_cleanup() {
    "$LAB_DIR/owner.sh" d python3 -c '
import pathlib,subprocess,sys
home=pathlib.Path.home()
ok=True
for args in (("ps","-aq","--filter","name=woowbk-emqxlab-"),("ps","-aq","--filter","name=emqx-native-"),("volume","ls","-q","--filter","name=woowbk-emqxlab-"),("secret","ls","--filter","name=woowbk-emqxlab-","--format","{{.Name}}")):
 r=subprocess.run(["podman",*args],capture_output=True,timeout=15)
 ok=ok and r.returncode==0 and not r.stdout.strip()
for parent,patterns in ((home,("emqx-real-owner-private-*","emqx-framed-private-*","woowbk-arm-cold-private-*")),(home/".config",("woowbk-emqxlab-*",)),(home/".config/containers/systemd",("woowbk-emqxlab-*",)),(home/".config/systemd/user",("woowbk-emqxlab-*",)),(pathlib.Path("/dev/shm"),("woowbk-emqxlab-*-mqtt-*",)),(pathlib.Path("/tmp"),("woowbk-arm-code-*","emqx-hocon-private-*","emqx-cold-private-*","emqx-vendor-acl-private-*","emqx-vendor-files-*"))):
 ok=ok and not any(list(parent.glob(p)) for p in patterns)
sys.exit(0 if ok else 1)'
}
# An existing residue is never deleted or borrowed by this invocation.
check_private_cleanup >/dev/null || die 'real-owner preexisting residue'
postflight() {
    original=$?
    trap - EXIT
    set +e
    "$LAB_DIR/owner.sh" d --verify-isolation >/dev/null
    isolated=$?
    check_private_cleanup >/dev/null
    clean=$?
    if [ "$isolated" -ne 0 ] || [ "$clean" -ne 0 ]; then
        echo 'REAL OWNER POSTFLIGHT REFUSED'
        exit 1
    fi
    echo 'REAL OWNER POSTFLIGHT PASSED'
    exit "$original"
}
trap postflight EXIT
python3 "$LAB_DIR/emqx_real_owner_transport.py" "$@"
