#!/bin/bash
# Only the isolated dev-d wrapper may access Podman. Never use host Podman.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
device_vars d
image_id=3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b
git -C "$REPO_ROOT" diff --quiet && git -C "$REPO_ROOT" diff --cached --quiet || die 'commit the tested source first'
source_commit=$(git -C "$REPO_ROOT" rev-parse HEAD)
evidence_dir="$REPO_ROOT/tests/e2e/lab/evidence/emqx-ha-adapter-joined"
mkdir -p "$evidence_dir"
umask 077
evidence="$evidence_dir/run-$(date -u +%Y%m%dT%H%M%SZ)-$$.jsonl"
( set -o noclobber; : > "$evidence" ) || die 'cannot create evidence file'
printf '{"stage":"source","commit":"%s"}\n' "$source_commit" | tee -a "$evidence"
printf '{"stage":"images","emqx":"%s","emqx_version":"5.8.9","client":"%s"}\n' "$image_id" '93a0bdfcbd9b7a86b36127cb81f54e1afd2019f12f39033458df405a027c03e3' | tee -a "$evidence"
# Existing coordination files only: no creation, truncation or replacement.
verify_existing_lock() {
    python3 - "$@" <<'PYLOCK'
import os, stat, sys
try:
    path = os.lstat(sys.argv[1])
    if not (stat.S_ISREG(path.st_mode) and path.st_uid == os.geteuid() and path.st_nlink == 1):
        raise ValueError()
    if len(sys.argv) == 3:
        opened = os.fstat(int(sys.argv[2]))
        if not (stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid() and opened.st_nlink == 1
                and (opened.st_dev, opened.st_ino) == (path.st_dev, path.st_ino)):
            raise ValueError()
except Exception:
    sys.exit(1)
PYLOCK
}
mutation_lock=/tmp/woowbk-dev-d-mutation.lock
volume_lock=/tmp/headscale-dev-d-private-volume.lock
verify_existing_lock "$mutation_lock" || die 'invalid existing dev-d mutation lock'
exec 9<"$mutation_lock"
verify_existing_lock "$mutation_lock" 9 || die 'dev-d lock inode changed'
flock -n 9 || die 'dev-d mutation owner busy'
verify_existing_lock "$mutation_lock" 9 || die 'dev-d lock inode changed'
verify_existing_lock "$volume_lock" || die 'invalid existing headscale mutation lock'
exec 8<"$volume_lock"
verify_existing_lock "$volume_lock" 8 || die 'headscale lock inode changed'
flock -n 8 || die 'existing headscale mutation owner busy'
verify_existing_lock "$volume_lock" 8 || die 'headscale lock inode changed'
"$LAB_DIR/owner.sh" d --verify-isolation
postflight() {
    status=$?
    trap - EXIT
    if ! "$LAB_DIR/owner.sh" d --verify-isolation; then
        status=1
    fi
    exit "$status"
}
trap postflight EXIT
read -r current maximum < <("$LAB_DIR/owner.sh" d sh -c 'printf "%s %s\n" "$(cat /sys/fs/cgroup/memory.current)" "$(cat /sys/fs/cgroup/memory.max)"')
[[ "$current" =~ ^[0-9]+$ && "$maximum" =~ ^[0-9]+$ ]] || die 'unknown cgroup memory limit'
(( maximum - current >= 1887436800 )) || die 'dev-d has less than 1800 MiB cgroup headroom'
suffix=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
tar -C "$REPO_ROOT" -cf - backup-engine/woowbackup \
    tests/e2e/lab/emqx_adapter_fixture.py tests/e2e/lab/emqx_adapter_provision.py \
    tests/e2e/lab/emqx_adapter_flow.py tests/e2e/lab/emqx_adapter_driver.py \
    tests/e2e/lab/emqx_adapter_owner.py tests/e2e/lab/emqx_adapter_mqtt.py tests/e2e/lab/emqx_ha_candidate.py \
    tests/e2e/lab/emqx_owner_fixture_files.py tests/e2e/lab/emqx_owner_vendor_files.py \
    tests/e2e/lab/emqx_bootstrap_csv.py tests/e2e/lab/emqx_native_runtime.py \
    tests/e2e/lab/emqx_semantic_readers.py tests/e2e/lab/emqx_target_snapshots.py \
    tests/e2e/lab/emqx_runtime_credentials.py tests/e2e/lab/emqx_private_boundary.py \
    tests/e2e/lab/emqx_real_candidate.py tests/e2e/lab/emqx_candidate_stage.py tests/e2e/lab/ha_real_fixture.py |
    "$LAB_DIR/owner.sh" d sh -c '
set -eu
umask 077
work=$(mktemp -d /tmp/woowbk-emqxcode-XXXXXXXX)
case "$work" in /tmp/woowbk-emqxcode-????????) ;; *) exit 1 ;; esac
cleanup() {
    status=$?
    trap - EXIT
    if rm -rf -- "$work"; then
        printf "%s\n" "{\"stage\":\"wrapper_cleanup\",\"result\":\"pass\"}"
    else
        printf "%s\n" "{\"stage\":\"wrapper_cleanup\",\"result\":\"fail\"}"
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap "exit 130" INT
trap "exit 143" TERM
cat > "$work/code.tar"
tar -xf "$work/code.tar" -C "$work"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$work/backup-engine" \
    python3 "$work/tests/e2e/lab/emqx_adapter_driver.py" --image-id "$1" \
    --work "/tmp/woowbk-emqxlab-$2"
' sh "$image_id" "$suffix" | tee -a "$evidence"
