#!/usr/bin/env bash
# Run inside dev-d as root; all Podman operations run as the lab appowner.
# Uses only new disposable containers and generated test credentials.
set -Eeuo pipefail
product_files=$1
podman() { runuser -u appowner -- env XDG_RUNTIME_DIR=/run/user/1019 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1019/bus podman "$@"; }
umask 077
test_dir=$(mktemp -d /tmp/headscale-internal.XXXXXXXX)
suffix=${test_dir##*.}
net="hs-test-$suffix"
server="hs-server-$suffix"
client_a="hs-a-$suffix"
client_b="hs-b-$suffix"
source_volume="hs-src-$suffix"
target_volume="hs-target-$suffix"
plane_volume="hs-plane-$suffix"
converted_volume="hs-converted-$suffix"
target_server="hs-target-server-$suffix"
cleanup() {
  local original=$? bad=0 name status
  trap - EXIT
  for name in "$client_a" "$client_b" "$server" "$target_server"; do
    podman container exists "$name" && podman rm -f "$name" >/dev/null 2>&1 || true
    if podman container exists "$name"; then echo "cleanup: container remains: $name" >&2; bad=1; else status=$?; (( status == 1 )) || bad=1; fi
  done
  for name in  "$source_volume" "$target_volume" "$plane_volume" "$converted_volume"; do
    podman volume exists "$name" && podman volume rm "$name" >/dev/null 2>&1 || true
    if podman volume exists "$name"; then echo "cleanup: volume remains: $name" >&2; bad=1; else status=$?; (( status == 1 )) || bad=1; fi
  done
  podman network exists "$net" && podman network rm "$net" >/dev/null 2>&1 || true
  if podman network exists "$net"; then echo "cleanup: network remains: $net" >&2; bad=1; else status=$?; (( status == 1 )) || bad=1; fi
  echo "Synthetic files retained: $test_dir"
  if (( bad )); then echo 'cleanup: FAILED' >&2; exit 1; fi
  echo 'cleanup: verified no test objects remain'
  exit "$original"
}
trap cleanup EXIT
mkdir -p "$test_dir"/{config,data,run,target-run}
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=Headscale-Lab-CA \
  -keyout "$test_dir/ca.key" -out "$test_dir/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=headscale.lab -addext subjectAltName=DNS:headscale.lab \
  -keyout "$test_dir/config/server.key" -out "$test_dir/server.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:headscale.lab\nextendedKeyUsage=serverAuth\n' > "$test_dir/extensions"
openssl x509 -req -in "$test_dir/server.csr" -CA "$test_dir/ca.crt" -CAkey "$test_dir/ca.key" \
  -CAcreateserial -days 1 -extfile "$test_dir/extensions" -out "$test_dir/config/server.crt" >/dev/null 2>&1
cat > "$test_dir/config/config.yaml" <<'EOF'
server_url: https://headscale.lab:8080
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
disable_check_updates: true
tls_cert_path: /etc/headscale/server.crt
tls_key_path: /etc/headscale/server.key
noise:
  private_key_path: /var/lib/headscale/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
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
dns:
  magic_dns: false
  override_local_dns: false
  base_domain: lab.invalid
  nameservers:
    global: []
policy:
  mode: database
unix_socket: /var/run/headscale/headscale.sock
logtail:
  enabled: false
EOF
chown -R appowner:appowner "$test_dir"
podman network create --internal --label io.woowtech.test=headscale-derp "$net" >/dev/null
[[ $(podman network inspect "$net" --format '{{.Internal}}') == true ]]
probe=$(podman run --rm --pull=never --memory=64m --network "$net" --entrypoint sh docker.io/tailscale/tailscale:stable -c \
  'ip -4 route; ip -6 route; if ip route get 192.0.2.1 >/dev/null 2>&1; then exit 42; fi; if timeout 3 wget -q -O /dev/null http://192.0.2.1:9; then exit 42; fi')
printf 'Routes:\n%s\n' "$probe"
if grep -Eq '(^|[[:space:]])default([[:space:]]|$)' <<< "$probe"; then echo 'Unexpected default route' >&2; exit 1; fi
echo 'Internal flag, no default route, external probe rejected: PASS'
podman image inspect --format 'headscale image id={{.Id}}' localhost/woow-headscale:0.29.4-r1
podman image inspect --format 'tailscale image id={{.Id}}' docker.io/tailscale/tailscale:stable
for volume in "$source_volume" "$target_volume" "$plane_volume" "$converted_volume"; do podman volume create "$volume" >/dev/null; done
podman run -d --name "$server" --pull=never --memory=384m --network "$net" --network-alias headscale.lab \
  -v "$test_dir/config:/etc/headscale:ro" -v "$source_volume:/var/lib/headscale" \
  -v "$test_dir/run:/var/run/headscale" localhost/woow-headscale:0.29.4-r1 serve >/dev/null
for _ in {1..30}; do podman exec "$server" headscale health >/dev/null 2>&1 && break; sleep 1; done
podman exec "$server" headscale health >/dev/null
podman exec "$server" headscale users create lab -o json >/dev/null
source_api_key=$(podman exec "$server" headscale apikeys create --expiration 1h)
printf '%s' "$source_api_key" | python3 "$product_files/tests/e2e/lab/headscale-credential-events.py" --register source_api
for client in "$client_a" "$client_b"; do
  podman run -d --name "$client" --hostname "$client" --pull=never --memory=192m --network "$net" \
    -e SSL_CERT_FILE=/lab/ca.crt -e TS_DEBUG_LOG_DISABLE=true -e TS_DEBUG_ALWAYS_USE_DERP=true \
    -v "$test_dir/ca.crt:/lab/ca.crt:ro" -v "$test_dir/ca.crt:/etc/ssl/certs/ca-certificates.crt:ro" \
    --entrypoint tailscaled docker.io/tailscale/tailscale:stable \
    --tun=userspace-networking --state=mem: --socket=/tmp/tailscaled.sock >/dev/null
  key=$(podman exec "$server" headscale preauthkeys create --user 1 --expiration 10m)
  if [[ "$client" == "$client_a" ]]; then source=client_a_preauth; else source=client_b_preauth; fi
  printf '%s' "$key" | python3 "$product_files/tests/e2e/lab/headscale-credential-events.py" --register "$source"
  podman exec -e TS_AUTHKEY="$key" "$client" sh -c 'tailscale --socket=/tmp/tailscaled.sock up --login-server=https://headscale.lab:8080 --authkey="$TS_AUTHKEY" --accept-dns=false --timeout=60s'
  unset key
  podman exec "$client" tailscale --socket=/tmp/tailscaled.sock status --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["BackendState"]=="Running"; print("Registered:", d["Self"]["HostName"], d["Self"]["TailscaleIPs"])'
done
addr=$(podman exec "$client_b" tailscale --socket=/tmp/tailscaled.sock ip -4)
result=$(podman exec "$client_a" tailscale --socket=/tmp/tailscaled.sock ping --timeout=15s --until-direct=false "$addr" 2>&1)
printf '%s\n' "$result"
printf '%s\n' "$result" | python3 -c 'import re,sys; lines=sys.stdin.read().splitlines(); ok=[x for x in lines if re.fullmatch(r"pong from .+ via DERP\(lab\) in [0-9.]+(?:ms|s)",x)]; assert len(lines)==10 and len(ok)==10, "expected exactly ten successful DERP pongs, with no errors"; print("DERP pongs verified: 10/10")'
echo 'Two real clients registered and DERP relay proven: PASS'
for client in "$client_a" "$client_b"; do
  podman exec "$client" tailscale --socket=/tmp/tailscaled.sock status --json > "$test_dir/$client.before.json"
done

# Start an independent target with its own API key, then shut it down before export.
podman run -d --name "$target_server" --pull=never --memory=384m --network=none \
  -v "$test_dir/config:/etc/headscale:ro" -v "$target_volume:/var/lib/headscale" \
  -v "$test_dir/target-run:/var/run/headscale" localhost/woow-headscale:0.29.4-r1 serve >/dev/null
for _ in {1..30}; do podman exec "$target_server" headscale health >/dev/null 2>&1 && break; sleep 1; done
podman exec "$target_server" headscale health >/dev/null
target_api_key=$(podman exec "$target_server" headscale apikeys create --expiration 1h)
printf '%s' "$target_api_key" | python3 "$product_files/tests/e2e/lab/headscale-credential-events.py" --register target_api
podman stop "$target_server" >/dev/null
podman logs "$target_server" 2>&1 | python3 "$product_files/tests/e2e/lab/headscale-credential-events.py" --scan-log target_initial
podman rm "$target_server" >/dev/null
# Keep the original client processes alive while stopping the source and converting its cold volume.
podman stop "$server" >/dev/null
podman logs "$server" 2>&1 | python3 "$product_files/tests/e2e/lab/headscale-credential-events.py" --scan-log source_server
podman rm "$server" >/dev/null
python3 "$product_files/tests/e2e/lab/headscale-product-convert.py" "$product_files/backup-engine" \
  "$test_dir" "$source_volume" "$target_volume" "$plane_volume"
chown -R appowner:appowner "$test_dir/converted-output"
podman volume import "$converted_volume" "$test_dir/converted-output/volumes/$target_volume.tar" >/dev/null
podman run -d --name "$target_server" --pull=never --memory=384m --network "$net" --network-alias headscale.lab \
  -v "$test_dir/config:/etc/headscale:ro" -v "$converted_volume:/var/lib/headscale" \
  -v "$test_dir/run:/var/run/headscale" localhost/woow-headscale:0.29.4-r1 serve >/dev/null
for _ in {1..30}; do podman exec "$target_server" headscale health >/dev/null 2>&1 && break; sleep 1; done
podman exec "$target_server" headscale health >/dev/null
echo 'Converted target started: PASS'
# The two client containers keep the same in-memory state; explicitly reconnect
# without a new auth key and compare their public node identity and addresses.
for client in "$client_a" "$client_b"; do
  podman exec "$client" tailscale --socket=/tmp/tailscaled.sock down
  podman exec "$client" tailscale --socket=/tmp/tailscaled.sock up --login-server=https://headscale.lab:8080 --accept-dns=false --timeout=60s
  podman exec "$client" tailscale --socket=/tmp/tailscaled.sock status --json > "$test_dir/$client.after.json"
  python3 - "$test_dir/$client.before.json" "$test_dir/$client.after.json" <<'PY'
import json, sys
before, after = (json.load(open(p)) for p in sys.argv[1:])
assert after['BackendState'] == 'Running'
for key in ('ID', 'PublicKey', 'TailscaleIPs'):
    assert before['Self'][key] == after['Self'][key], key
print('Original client reconnected with unchanged node ID, public key and IPs: PASS')
PY
done
# Reconnection is asynchronous: measure bounded convergence separately from
# the subsequent ten-packet stability check. Do not hide initial outages.
convergence_start=$SECONDS
convergence_attempts=0
while true; do
  convergence_attempts=$((convergence_attempts + 1))
  if probe=$(podman exec "$client_a" tailscale --socket=/tmp/tailscaled.sock ping --c=1 --timeout=3s --until-direct=false "$addr" 2>&1) &&
     [[ "$probe" == *'via DERP(lab)'* ]]; then
    break
  fi
  if (( SECONDS - convergence_start >= 60 )); then
    echo "Post-conversion DERP convergence failed: attempts=$convergence_attempts elapsed=$((SECONDS-convergence_start))s" >&2
    exit 1
  fi
  sleep 1
done
echo "Post-conversion DERP convergence: attempts=$convergence_attempts elapsed=$((SECONDS-convergence_start))s (not zero-downtime proof)"
result=$(podman exec "$client_a" tailscale --socket=/tmp/tailscaled.sock ping --timeout=15s --until-direct=false "$addr" 2>&1)
printf '%s\n' "$result"
printf '%s\n' "$result" | python3 -c 'import re,sys; lines=sys.stdin.read().splitlines(); assert len(lines)==10 and all(re.fullmatch(r"pong from .+ via DERP\(lab\) in [0-9.]+(?:ms|s)",x) for x in lines), "expected ten successful post-conversion DERP pongs"; print("Post-conversion DERP pongs verified: 10/10")'
# Query the real target API, with the test CA and each synthetic credential.
for which in target source; do
  if [[ $which == target ]]; then key=$target_api_key; expected=200; else key=$source_api_key; expected=401; fi
  response=$(podman exec -e HS_TEST_KEY="$key" "$client_a" sh -c \
    'wget --server-response --header="Authorization: Bearer $HS_TEST_KEY" -O /dev/null https://headscale.lab:8080/api/v1/node 2>&1 || true')
  unset key
  [[ "$response" =~ HTTP/[0-9.]+[[:space:]]$expected([[:space:]]|$) ]] || { echo "API $which credential: expected HTTP $expected" >&2; exit 1; }
  echo "API $which credential: HTTP $expected PASS"
done
podman stop "$client_a" "$client_b" "$target_server" >/dev/null
podman logs "$target_server" 2>&1 | python3 "$product_files/tests/e2e/lab/headscale-credential-events.py" --scan-log target_converted
podman logs "$client_a" 2>&1 | python3 "$product_files/tests/e2e/lab/headscale-credential-events.py" --scan-log client_a
podman logs "$client_b" 2>&1 | python3 "$product_files/tests/e2e/lab/headscale-credential-events.py" --scan-log client_b
unset source_api_key target_api_key
