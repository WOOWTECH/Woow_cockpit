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
isolation=$("$LP" inspect --format '{{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}} {{.State.Status}}' "$NAME")
[[ "$isolation" == 'none {} running' ]] || die 'dev-d isolation is not confirmed'
read -r current maximum < <("$LP" exec "$NAME" sh -c 'printf "%s %s\n" "$(cat /sys/fs/cgroup/memory.current)" "$(cat /sys/fs/cgroup/memory.max)"')
[[ "$current" =~ ^[0-9]+$ && "$maximum" =~ ^[0-9]+$ ]] || die 'unknown cgroup memory limit'
(( maximum - current >= 1887436800 )) || die 'dev-d has less than 1800 MiB cgroup headroom'
tmp=$("$LP" exec "$NAME" mktemp -d /tmp/woowbk-emqxcode-XXXXXXXX)
[[ "$tmp" =~ ^/tmp/woowbk-emqxcode-[A-Za-z0-9]{8}$ ]] || die 'unexpected staging path'
cleanup() {
    status=$?
    if "$LP" exec "$NAME" rm -rf -- "$tmp"; then
        printf '%s\n' '{"stage":"wrapper_cleanup","result":"pass"}' | tee -a "$evidence"
    else
        printf '%s\n' '{"stage":"wrapper_cleanup","result":"fail"}' | tee -a "$evidence"
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
tar -C "$REPO_ROOT" -cf - backup-engine/woowbackup \
    tests/e2e/lab/emqx_adapter_fixture.py tests/e2e/lab/emqx_adapter_provision.py \
    tests/e2e/lab/emqx_adapter_flow.py tests/e2e/lab/emqx_adapter_driver.py tests/e2e/lab/emqx_ha_candidate.py |
    "$LP" exec -i "$NAME" tar -xf - -C "$tmp"
suffix=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
"$LP" exec "$NAME" env PYTHONPATH="$tmp/backup-engine" PYTHONDONTWRITEBYTECODE=1 \
    python3 "$tmp/tests/e2e/lab/emqx_adapter_driver.py" --image-id "$image_id" \
    --work "/tmp/woowbk-emqxlab-$suffix" | tee -a "$evidence"
