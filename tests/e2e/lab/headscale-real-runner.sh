#!/usr/bin/env bash
# Real HA Headscale backup -> product conversion -> disposable restored server in dev-d (services-a).
# Run inside dev-d as appowner under headscale_real_events.py --controller (owner.sh d), never on the host.
#   headscale-real-runner.sh <stage> <arm|x86> <installer 0|1>
# <stage> holds: backup-engine/, tests/e2e/lab/*, source.tar (the real HA backup), source.sha256,
# expect.json (b1 source summary subset), client.state (arm: copy of the real client's tailscaled.state)
# and ha-preauth (the HA reusable pre-auth key of the b1 fixture, 0600; removed after it is read).
# Uses only new disposable containers/volumes/network; the target keeps its own URL, API key and config.
set -Eeuo pipefail
stage=$1
arch=$2
installer=${3:-0}
[[ $arch == arm || $arch == x86 ]] || exit 2
[[ $installer == 0 || $installer == 1 ]] || exit 2
[[ $(id -u) == 1019 ]] || exit 1
if [[ $installer == 1 ]]; then
  for tool in age age-keygen zstd; do command -v "$tool" >/dev/null || exit 1; done
fi
lab="$stage/tests/e2e/lab"
check() { python3 "$lab/headscale_real_checks.py" "$@"; }
events() { python3 "$lab/headscale_real_events.py" "$@"; }
podman_timeout() { timeout 5s podman "$@"; }
# Fixed step names only (no values): the host wrapper prints the last one when the controller suppresses output.
progress() { [[ $1 =~ ^[a-z0-9_]{1,40}$ ]] && printf '%s\n' "$1" >> "$stage/progress"; }
umask 077
test_dir=$(mktemp -d /tmp/headscale-real.XXXXXXXX)
suffix=${test_dir##*.}
net="hs-real-$suffix"
target_server="hs-rtarget-$suffix"
restored="hs-rserver-$suffix"
alice="hs-ralice-$suffix"
probe_a="hs-rprobe-a-$suffix"
probe_b="hs-rprobe-b-$suffix"
target_volume="hs-rtarget-$suffix"
plane_volume="hs-rplane-$suffix"
converted_volume="hs-rconverted-$suffix"
cleanup() {
  local original=$? bad=0 name status
  trap - EXIT
  for name in "$alice" "$probe_a" "$probe_b" "$restored" "$target_server"; do
    podman container exists "$name" && podman rm -f "$name" >/dev/null 2>&1 || true
    if podman container exists "$name"; then echo "cleanup: container remains: $name" >&2; bad=1; else status=$?; (( status == 1 )) || bad=1; fi
  done
  for name in "$target_volume" "$plane_volume" "$converted_volume"; do
    podman volume exists "$name" && podman volume rm "$name" >/dev/null 2>&1 || true
    if podman volume exists "$name"; then echo "cleanup: volume remains: $name" >&2; bad=1; else status=$?; (( status == 1 )) || bad=1; fi
  done
  podman network exists "$net" && podman network rm "$net" >/dev/null 2>&1 || true
  if podman network exists "$net"; then echo "cleanup: network remains: $net" >&2; bad=1; else status=$?; (( status == 1 )) || bad=1; fi
  # Private run files (CA key, client state copies, configtest export) are removed; nothing is retained.
  rm -rf -- "$test_dir" || bad=1
  [[ -e "$test_dir" ]] && bad=1
  if (( bad )); then echo 'cleanup: FAILED' >&2; exit 1; fi
  echo 'cleanup: verified no test objects or private run files remain'
  exit "$original"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
mkdir -p "$test_dir"/{config,run,target-run,alice,probe-a,probe-b}
expected_sha=$(cat "$stage/source.sha256")
[[ $expected_sha =~ ^[0-9a-f]{64}$ ]]
cp "$stage/expect.json" "$test_dir/expect.json"

progress start
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=Headscale-Real-Lab-CA \
  -keyout "$test_dir/ca.key" -out "$test_dir/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=headscale.lab -addext subjectAltName=DNS:headscale.lab \
  -keyout "$test_dir/config/server.key" -out "$test_dir/server.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:headscale.lab\nextendedKeyUsage=serverAuth\n' > "$test_dir/extensions"
openssl x509 -req -in "$test_dir/server.csr" -CA "$test_dir/ca.crt" -CAkey "$test_dir/ca.key" \
  -CAcreateserial -days 1 -extfile "$test_dir/extensions" -out "$test_dir/config/server.crt" >/dev/null 2>&1
chmod 0644 "$test_dir/config/server.crt" "$test_dir/ca.crt"
chmod 0640 "$test_dir/config/server.key"
private_source() {
  local source=$1; shift
  python3 "$lab/headscale-private-sources.py" "$@" | events --register-private "$source"
}
private_source ca_private pem "$test_dir/ca.key"
private_source tls_private pem "$test_dir/config/server.key"
# The target's own configuration: its own URL (TLS, reachable only on this run's internal network),
# HA's prefixes, MagicDNS with the extra-records file in the data volume, database policy, and a
# LOCAL non-empty DERP map (the embedded DERP region 999; no URL, nothing fetched from outside).
cat > "$test_dir/config/config.yaml" <<'EOF'
server_url: https://headscale.lab:8080
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
disable_check_updates: true
tls_cert_path: /etc/headscale/server.crt
tls_key_path: /etc/headscale/server.key
noise:
  private_key_path: /var/lib/headscale/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true
derp:
  server:
    enabled: true
    region_id: 999
    region_code: lab
    region_name: Isolated lab
    stun_listen_addr: 0.0.0.0:3478
    private_key_path: /var/lib/headscale/derp.key
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
node:
  expiry: "0"
dns:
  magic_dns: true
  base_domain: ts.local
  override_local_dns: false
  nameservers:
    global: []
  extra_records_path: /var/lib/headscale/extra_records.json
policy:
  mode: database
unix_socket: /var/run/headscale/headscale.sock
logtail:
  enabled: false
EOF
chmod 0644 "$test_dir/config/config.yaml"
chmod 0755 "$test_dir/config"
echo 'Target config: own URL, HA prefixes, local embedded DERP map (region 999, no URL), no external nameserver'

progress network
podman network create --internal --label io.woowtech.test=headscale-derp "$net" >/dev/null
[[ $(podman network inspect "$net" --format '{{.Internal}}') == true ]]
probe=$(podman run --rm --pull=never --memory=64m --network "$net" --entrypoint sh docker.io/tailscale/tailscale:stable -c \
  'ip -4 route; ip -6 route; if ip route get 192.0.2.1 >/dev/null 2>&1; then exit 42; fi; if ip route get 192.168.2.34 >/dev/null 2>&1; then exit 43; fi')
if grep -Eq '(^|[[:space:]])default([[:space:]]|$)' <<< "$probe"; then echo 'Unexpected default route' >&2; exit 1; fi
echo 'Internal network: no default route, the HA source address and a reserved address are unroutable: PASS'
podman image inspect --format 'headscale image id={{.Id}}' localhost/woow-headscale:0.29.4-r1
podman image inspect --format 'tailscale image id={{.Id}}' docker.io/tailscale/tailscale:stable
for volume in "$target_volume" "$plane_volume" "$converted_volume"; do podman volume create "$volume" >/dev/null; done

progress target
# 1. The disposable target: initialised by the real image with ITS OWN API key, then stopped (cold).
podman run -d --name "$target_server" --pull=never --memory=384m --network=none \
  -v "$test_dir/config:/etc/headscale:ro" -v "$target_volume:/var/lib/headscale" \
  -v "$test_dir/target-run:/var/run/headscale" localhost/woow-headscale:0.29.4-r1 serve >/dev/null
for _ in {1..30}; do podman exec "$target_server" headscale health >/dev/null 2>&1 && break; sleep 1; done
podman exec "$target_server" headscale health >/dev/null
echo 'Target configtest-valid config started with the local DERP map: PASS'
target_api_key=$(podman exec "$target_server" headscale apikeys create --expiration 2h)
printf '%s' "$target_api_key" | events --register target_api
podman stop "$target_server" >/dev/null
podman volume export --output "$test_dir/target-initial-private.tar" "$target_volume"
private_source target_noise volume "$test_dir/target-initial-private.tar" noise.key
private_source target_derp volume "$test_dir/target-initial-private.tar" derp.key
podman logs "$target_server" 2>&1 | events --scan-log target_initial
podman rm "$target_server" >/dev/null

progress convert
# 2. The unmodified product converter on the real HA backup.
python3 "$lab/headscale_real_convert.py" "$stage/backup-engine" "$test_dir" "$stage/source.tar" "$expected_sha" \
  "$arch" "$target_volume" "$plane_volume"
converted_tar="$test_dir/converted-output/volumes/$target_volume.tar"
private_source ha_noise volume "$converted_tar" noise.key
private_source configtest_keys volume-all "$test_dir/configtest-private.tar"
events --scan-log configtest < "$test_dir/configtest-output.log"
rm -f -- "$test_dir/configtest-private.tar" "$test_dir/configtest-output.log"

progress restored
# 3. The converted volume restored into a new server on the isolated internal network.
podman volume import "$converted_volume" "$converted_tar" >/dev/null
podman run -d --name "$restored" --pull=never --memory=384m --network "$net" --network-alias headscale.lab \
  -v "$test_dir/config:/etc/headscale:ro" -v "$converted_volume:/var/lib/headscale" \
  -v "$test_dir/run:/var/run/headscale" localhost/woow-headscale:0.29.4-r1 serve >/dev/null
for _ in {1..30}; do podman exec "$restored" headscale health >/dev/null 2>&1 && break; sleep 1; done
podman exec "$restored" headscale health >/dev/null
server_ip=$(podman inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$restored")
echo 'Restored server started from the converted HA data with the target config: PASS'
podman exec "$restored" headscale users list -o json > "$test_dir/users.json"
check users "$test_dir/expect.json" "$test_dir/users.json"
podman exec "$restored" headscale nodes list -o json > "$test_dir/nodes-0.json"
check nodes "$test_dir/expect.json" "$test_dir/nodes-0.json" '' 0
podman exec "$restored" headscale preauthkeys list -o json > "$test_dir/preauth.json"
check preauth "$test_dir/expect.json" "$test_dir/preauth.json"
podman exec "$restored" cat /var/lib/headscale/extra_records.json > "$test_dir/records.json"
check records "$test_dir/expect.json" "$test_dir/records.json"
podman exec "$restored" headscale apikeys list -o json > "$test_dir/apikeys.json"
HS_TARGET_KEY="$target_api_key" python3 - "$test_dir/apikeys.json" <<'PY'
import json, os, sys
rows = json.load(open(sys.argv[1]))
key = os.environ['HS_TARGET_KEY']
display = rows[0].get('prefix') if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) else None
# headscale 0.29.4 lists 'hskey-api-<12 chars>-***' (hscontrol/types/api_key.go Proto()).
ok = isinstance(display, str) and display.startswith('hskey-api-') and display.endswith('-***') \
    and len(display) == len('hskey-api-') + 12 + 4 and key.startswith(display[:-3])
print('Only the target API key remains (HA keys removed): ' + ('PASS' if ok else 'FAIL'))
sys.exit(0 if ok else 1)
PY

client_run() {
  # <name> <state dir> : a userspace tailscaled with only the test CA, no logs upload, forced DERP.
  podman run -d --name "$1" --hostname "${3:-$1}" --pull=never --memory=192m --network "$net" \
    -e SSL_CERT_FILE=/lab/ca.crt -e TS_DEBUG_LOG_DISABLE=true -e TS_DEBUG_ALWAYS_USE_DERP=true -e TS_NO_LOGS_NO_SUPPORT=true \
    -v "$test_dir/ca.crt:/lab/ca.crt:ro" -v "$test_dir/ca.crt:/etc/ssl/certs/ca-certificates.crt:ro" \
    -v "$2:/state" --entrypoint tailscaled docker.io/tailscale/tailscale:stable \
    --tun=userspace-networking --state=/state/tailscaled.state --socket=/tmp/tailscaled.sock --no-logs-no-support >/dev/null
  for _ in {1..20}; do podman exec "$1" tailscale --socket=/tmp/tailscaled.sock status --json >/dev/null 2>&1 && return 0; sleep 1; done
  podman exec "$1" tailscale --socket=/tmp/tailscaled.sock version >/dev/null
}
ts() { local c=$1; shift; podman exec "$c" tailscale --socket=/tmp/tailscaled.sock "$@"; }

progress server_key
# 4. The server answers with HA's control identity (public Noise key) over the target URL.
podman run --rm --pull=never --memory=64m --network "$net" -v "$test_dir/ca.crt:/etc/ssl/certs/ca-certificates.crt:ro" \
  --entrypoint wget docker.io/tailscale/tailscale:stable -q -O - 'https://headscale.lab:8080/key?v=120' > "$test_dir/server-key.json"
check server-key "$test_dir/expect.json" "$test_dir/server-key.json"

peer_a=''
if [[ $arch == arm ]]; then
  progress real_client
  # 5. The REAL client made against the RPi5 Headscale (copy of its state; node b1-ts-alice) re-pointed to
  #    this target's URL: no auth key, no --force-reauth. It must continue as the same node.
  install -m 0600 "$stage/client.state" "$test_dir/alice/tailscaled.state"
  private_source client_identity_before client "$test_dir/alice/tailscaled.state"
  client_run "$alice" "$test_dir/alice" b1-ts-alice
  ts "$alice" status --json > "$test_dir/alice-start.json" 2>/dev/null || true
  start_state=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("BackendState","?"))' "$test_dir/alice-start.json" 2>/dev/null || echo unknown)
  echo "Real client state right after start (HA server unreachable): $start_state"
  if [[ $start_state == Running ]]; then ts "$alice" down; fi
  up_start=$SECONDS
  set +e
  ts "$alice" up --login-server=https://headscale.lab:8080 --hostname=b1-ts-alice --accept-dns=false --timeout=60s \
    > "$test_dir/alice-up.txt" 2>&1
  up_rc=$?
  set -e
  echo "tailscale up --login-server=<target URL> (no auth key): rc=$up_rc in $((SECONDS-up_start))s"
  if (( up_rc != 0 )); then
    # Fixed classification only; the raw text stays private (it can name URLs/flags).
    if grep -q 'requires mentioning all non-default flags' "$test_dir/alice-up.txt"; then echo 'up refused: non-default flags'; fi
    if grep -qi 'login' "$test_dir/alice-up.txt"; then echo 'up output mentions login'; fi
    exit 1
  fi
  for _ in {1..30}; do
    ts "$alice" status --json > "$test_dir/alice-after.json" 2>/dev/null && \
      check client "$test_dir/expect.json" "$test_dir/alice-after.json" >/dev/null && break
    sleep 2
  done
  check client "$test_dir/expect.json" "$test_dir/alice-after.json"
  podman exec "$restored" headscale nodes list -o json > "$test_dir/nodes-1.json"
  alice_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["client"]["NodeID"])' "$test_dir/expect.json")
  check nodes "$test_dir/expect.json" "$test_dir/nodes-1.json" "$alice_id" 0
  echo 'No new node was created for the re-pointed real client: PASS'
  peer_a=$alice
fi

progress probe_join
# 6. A NEW device joins with HA's reusable pre-auth key (it moved with the database), then DERP relay
#    traffic between it and the restored node proves the data plane through the local DERP map.
#    The key is read once from the private stage file (removed at once), registered before any use and
#    handed to podman only through its environment (never argv).
ha_key=$(cat "$stage/ha-preauth")
rm -f -- "$stage/ha-preauth"
printf '%s' "$ha_key" | events --register ha_preauth
join() {
  client_run "$1" "$2"
  TS_AUTHKEY="$ha_key" podman exec -e TS_AUTHKEY "$1" sh -c \
    'tailscale --socket=/tmp/tailscaled.sock up --login-server=https://headscale.lab:8080 --authkey="$TS_AUTHKEY" --accept-dns=false --timeout=60s' \
    >/dev/null 2>&1
}
join "$probe_a" "$test_dir/probe-a"
extra=1
if [[ $arch == x86 ]]; then join "$probe_b" "$test_dir/probe-b"; extra=2; peer_a=$probe_b; fi
unset ha_key
echo "New device(s) joined with HA's reusable pre-auth key: PASS ($extra)"
podman exec "$restored" headscale nodes list -o json > "$test_dir/nodes-2.json"
online=''
[[ $arch == arm ]] && online=$alice_id
check nodes "$test_dir/expect.json" "$test_dir/nodes-2.json" "$online" "$extra"
progress derp
target=$(ts "$probe_a" ip -4)
convergence_start=$SECONDS
while true; do
  if probe_out=$(ts "$peer_a" ping --c=1 --timeout=3s --until-direct=false "$target" 2>&1) && [[ "$probe_out" == *'via DERP(lab)'* ]]; then break; fi
  if (( SECONDS - convergence_start >= 60 )); then echo 'DERP convergence: FAIL' >&2; exit 1; fi
  sleep 1
done
echo "DERP convergence: elapsed=$((SECONDS-convergence_start))s"
result=$(ts "$peer_a" ping --timeout=15s --until-direct=false "$target" 2>&1)
printf '%s\n' "$result" | python3 -c 'import re,sys; lines=sys.stdin.read().splitlines(); ok=[x for x in lines if re.fullmatch(r"pong from .+ via DERP\(lab\) in [0-9.]+(?:ms|s)",x)]; assert len(lines)==10 and len(ok)==10, "expected ten DERP pongs"; print("DERP pongs from the restored-identity side to the new device: 10/10 PASS")'
back=$(ts "$probe_a" ping --c=1 --timeout=5s --until-direct=false "$(ts "$peer_a" ip -4)" 2>&1)
[[ "$back" =~ ^pong\ from\ .*\ via\ DERP\(lab\)\ in\ [0-9.]+(ms|s)$ ]] && echo 'DERP pong in the reverse direction: PASS'

progress api
# 7. The target's API answers with ITS OWN key over its own URL.
response=$(HS_TEST_KEY="$target_api_key" podman exec -e HS_TEST_KEY "$probe_a" sh -c \
  'wget --server-response --header="Authorization: Bearer $HS_TEST_KEY" -O /dev/null https://headscale.lab:8080/api/v1/node 2>&1 || true')
[[ "$response" =~ HTTP/[0-9.]+[[:space:]]200([[:space:]]|$) ]] || { echo 'API target key: expected HTTP 200' >&2; exit 1; }
echo 'API with the target key over the target URL: HTTP 200 PASS'
response=$(podman exec "$probe_a" sh -c \
  'wget --server-response --header="Authorization: Bearer hskey-api-invalidinvalid-notarealsecretvalue00" -O /dev/null https://headscale.lab:8080/api/v1/node 2>&1 || true')
[[ "$response" =~ HTTP/[0-9.]+[[:space:]]401([[:space:]]|$) ]] && echo 'API with an unknown key: HTTP 401 PASS'

progress stop_probes
# 8. Probes stop (identities registered); the restored server stops and its keys are registered.
for client in "$probe_a" "$probe_b"; do
  podman container exists "$client" || continue
  podman stop "$client" >/dev/null
done
private_source probe_a_identity client "$test_dir/probe-a/tailscaled.state"
podman logs "$probe_a" 2>&1 | events --scan-log probe_a
podman rm "$probe_a" >/dev/null
if [[ $arch == x86 ]]; then
  private_source probe_b_identity client "$test_dir/probe-b/tailscaled.state"
  podman logs "$probe_b" 2>&1 | events --scan-log probe_b
  podman rm "$probe_b" >/dev/null
fi
podman stop "$restored" >/dev/null
podman volume export --output "$test_dir/restored-private.tar" "$converted_volume"
private_source restored_keys volume-all "$test_dir/restored-private.tar"
rm -f -- "$test_dir/restored-private.tar"
podman logs "$restored" 2>&1 | events --scan-log restored_server
podman rm "$restored" >/dev/null

progress installer
# 9. Installer: real adapter, encrypted package, flows.run_restore, injected one-shot failure ->
#    automatic rollback, separate restart; the real client keeps running throughout (arm).
if [[ $installer == 1 ]]; then
  PYTHONPATH="$stage/backup-engine:$lab" python3 "$lab/headscale_real_install.py" --run \
    --server-address "$server_ip" --network "$net" --client "$([[ $arch == arm ]] && echo "$alice" || true)" \
    "$test_dir" "$target_volume" "$plane_volume"
fi
if [[ $arch == arm ]]; then
  podman stop "$alice" >/dev/null
  private_source client_identity_after client "$test_dir/alice/tailscaled.state"
  podman logs "$alice" 2>&1 | events --scan-log client_alice
  podman rm "$alice" >/dev/null
fi
progress done
unset target_api_key
echo "HEADSCALE_REAL_HA_${arch^^}=PASS"
