#!/usr/bin/env bash
# Real HA Headscale backup (b1 x86 or ARM/RPi5) -> product conversion -> disposable restored server,
# real client re-point (ARM), DERP data plane, target API, optional real installer + rollback; dev-d only.
#   tests/e2e/lab/headscale-real-test.sh <arm|x86> [--installer]
# Holds /tmp/woowbk-dev-d-mutation.lock for the whole run (waits up to 60 min, like the other lanes).
# Stages the real backup, the real client's state copy, the b1 expectations and the HA pre-auth key in a
# private disk-backed directory of dev-d's appowner and ALWAYS removes it. Prints only the controller's
# redacted, scanned output and fixed wrapper lines.
set -Eeuo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
owner() { bash "$here/owner.sh" d "$@"; }
die() { echo "headscale-real-test: $*" >&2; exit 1; }
arch=${1:-}
[[ $arch == arm || $arch == x86 ]] || die 'usage: headscale-real-test.sh <arm|x86> [--installer]'
installer=0
[[ ${2:-} == --installer ]] && installer=1
[[ $# -le 2 ]] || die 'too many arguments'
lab=$HOME/.woowbk-lab
backup="$lab/ha-fixtures/20261119-b1/$arch/woow-b1-$arch-plain/woow-b1-$arch-plain.tar"
declare -A fixture_sha=(
  [arm]=1e6a4665315bc69fd114f8d43f7d429aecab53f07d07793ecf8c2c057a92c5d4
  [x86]=3871a468e2f3a11488df7c6a00a4a8ed7c5b89c3ba2dbc2903ec3bd677013516
)
client_state="$lab/storage/volumes/b1-ts-alice-state/_data/tailscaled.state"

exec 9>/tmp/woowbk-dev-d-mutation.lock
flock -w 3600 9 || die 'dev-d mutation lock not obtained within 60 minutes'
lock_start=$SECONDS
echo "dev-d mutation lock held (services-a headscale-real $arch installer=$installer)"
[[ -z $(git -C "$repo" status --porcelain -- backup-engine tests/e2e/lab) ]] || die 'engine/harness changes are not committed'
echo "source commit $(git -C "$repo" rev-parse HEAD)"
owner --verify-isolation
free_kib=$(df -Pk / | awk 'NR==2 {print $4}')
size=$(stat -c %s "$backup")
(( free_kib * 1024 - 2 * size >= 12 * 1024 * 1024 * 1024 )) || die 'host disk reserve (12 GiB after the staged copy) not met'
avail_kib=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
(( avail_kib >= 2 * 1024 * 1024 )) || die "host MemAvailable below 2 GiB ($avail_kib KiB)"
memory=$(owner sh -c 'read -r current </sys/fs/cgroup/memory.current; read -r max </sys/fs/cgroup/memory.max; echo "$current $max"')
read -r current max <<< "$memory"
[[ "$max" =~ ^[0-9]+$ && "$current" =~ ^[0-9]+$ ]] || die 'cannot verify dev-d cgroup memory'
# Budget: the concurrently alive containers' limits (restored server 384M + clients 3x192M, or installer 384M +
# client 192M; configtest 768M runs alone) plus the converter, rounded up to 1.25 GiB.
(( max - current >= 1342177280 )) || die "insufficient dev-d headroom: current=$current limit=$max; need 1.25 GiB free"
echo "dev-d memory current=$current limit=$max; headroom >= 1.25 GiB; host MemAvailable ${avail_kib} KiB"
active=$(owner podman ps --format '{{.Names}}')
if grep -Eq '^(woowbk-emqx-synthetic-|woowbk-j|hs-|woowbk-omni-)' <<< "$active"; then die 'another synthetic or job container is active'; fi
# dev-d's own offline headscale.service is crash-looping (empty DERP map; see headscale-offline-candidate.md):
# its transient 'headscale' container comes and goes every ~10 s, so that one name is left out of the fingerprint.
inventory() { owner sh -c 'podman ps -a --format "{{.Names}}" | grep -vx -e headscale -e headplane | sort; echo ---; podman volume ls --format "{{.Name}}" | sort; echo ---; podman network ls --format "{{.Name}}" | sort; echo ---; podman secret ls --format "{{.Name}}" | sort' | sha256sum | cut -c1-64; }
before=$(inventory)
echo "dev-d inventory fingerprint before: $before"

sha=$(sha256sum "$backup" | cut -c1-64)
[[ $sha == "${fixture_sha[$arch]}" ]] || die 'real HA backup sha256 differs from the recorded b1 fixture'
echo "real HA backup sha256 = recorded b1 $arch fixture sha256: PASS"
private=$(mktemp -d)
stage=''
cleanup() {
  local rc=$? bad=0
  trap - EXIT
  rm -rf -- "$private"
  if [[ -n $stage ]]; then
    owner rm -rf -- "$stage" || bad=1
    if owner test -e "$stage"; then bad=1; fi
  fi
  if (( bad )); then echo 'staged private inputs: REMOVAL FAILED' >&2; rc=1; else echo 'staged private inputs removed (backup copy, client state, expectations, key): PASS'; fi
  after=$(inventory) || after=unknown
  if [[ $after == "$before" ]]; then echo 'dev-d inventory (containers, volumes, networks, secrets) unchanged: PASS'
  else echo 'dev-d inventory unchanged: FAIL' >&2; rc=1; fi
  owner --verify-isolation || rc=1
  echo "lock held for $((SECONDS - lock_start)) s"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
chmod 0700 "$private"
PYTHONPATH="$repo/backup-engine:$here" python3 - "$arch" "$private" <<'PY'
"""Expectations (no secrets) from the b1 source summary; the HA reusable pre-auth key through the existing
b1 harness reader, written 0600 only into this private host directory and never printed."""
import json, os, sys
from pathlib import Path
import ha_import_b1_e2e as b1
arch, private = sys.argv[1], Path(sys.argv[2])
summary = json.loads(b1.SOURCE.read_text(encoding='utf-8'))['machines'][arch]
hs = summary['headscale']
expect = {'users': hs['users'], 'nodes': hs['nodes'], 'preauthkeys': hs['preauthkeys'],
          'dns_extra_records': hs['dns_extra_records'], 'server_public_key': hs['server_public_key']}
if arch == 'arm':
    client = summary['tailscale_client']
    expect['client'] = {k: client[k] for k in ('NodeID', 'NodePublicKey', 'TailscaleIPs', 'HostName')}
def write(name, data):
    fd = os.open(private / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
write('expect.json', json.dumps(expect).encode())
secrets = b1.Secrets([b1.SECRET_DIR / 'b1-creds.env'], b1.SECRET_DIR / 'dev-d-markers.json')
key = secrets[f'B1_{arch.upper()}_HS_KEY_BOB_REUSABLE']
if not key.startswith('hskey-auth-') or len(key) < 20:
    raise SystemExit('unexpected pre-auth key format')
write('ha-preauth', key.encode())
print('expectations and HA pre-auth key staged privately: PASS')
PY
printf '%s\n' "$sha" > "$private/source.sha256"
if [[ $arch == arm ]]; then
  [[ -f $client_state && ! -L $client_state ]] || die 'real client state missing'
  install -m 0600 "$client_state" "$private/client.state"
fi
stage=$(owner mktemp -d /home/appowner/.services-a-hs.XXXXXXXX)
[[ $stage =~ ^/home/appowner/\.services-a-hs\.[A-Za-z0-9]{8}$ ]] || die 'unexpected stage path'
tar -C "$repo" --exclude=__pycache__ -cf - backup-engine tests/e2e/lab/headscale_real_convert.py \
  tests/e2e/lab/headscale-real-runner.sh tests/e2e/lab/headscale_real_events.py tests/e2e/lab/headscale-credential-events.py \
  tests/e2e/lab/headscale-private-sources.py tests/e2e/lab/headscale_real_checks.py tests/e2e/lab/headscale_real_install.py \
  tests/e2e/lab/headscale_install_rollback.py tests/e2e/lab/headscale_client_continuity.py \
  tests/e2e/lab/headscale-auto-reconnect-check.py | owner tar -xf - -C "$stage"
tar -C "$private" -cf - . | owner tar -xf - -C "$stage"
rm -rf -- "$private"/*
owner sh -c 'umask 077; cat > "$1"' sh "$stage/source.tar" < "$backup"
echo 'real HA backup, expectations, client state and pre-auth key staged in a private dev-d directory'
set +e
owner env HS_REAL_ARCH="$arch" HS_REAL_INSTALLER="$installer" python3 "$stage/tests/e2e/lab/headscale_real_events.py" \
  --controller -- bash "$stage/tests/e2e/lab/headscale-real-runner.sh" "$stage" "$arch" "$installer"
rc=$?
set -e
echo "controller exit=$rc"
last=$(owner sh -c 'tail -n 1 "$1" 2>/dev/null || true' sh "$stage/progress")
[[ $last =~ ^[a-z0-9_]{1,40}$ ]] && echo "last runner step: $last"
exit "$rc"
