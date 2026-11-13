#!/bin/bash
# Install this integration separately from Cockpit's shared backup installer.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo 'Run with sudo.' >&2; exit 1; }
pi_host=${1:-}; pi_port=${2:-19094}; pi_vpn=${3:-}
validate_ip() {
  local ip=$1 a b c d part
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo 'Supply a valid IPv4 address.' >&2; exit 1; }
  IFS=. read -r a b c d <<< "$ip"
  for part in "$a" "$b" "$c" "$d"; do ((10#$part <= 255)) || { echo 'Invalid IP.' >&2; exit 1; }; done
  ip -4 -o address show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$ip" || { echo "IP $ip is not on a local interface." >&2; exit 1; }
}
validate_ip "$pi_host"
if [[ -n "$pi_vpn" ]]; then validate_ip "$pi_vpn"; [[ "$pi_vpn" != "$pi_host" ]] || { echo 'VPN and LAN addresses must differ.' >&2; exit 1; }; fi
[[ "$pi_port" =~ ^[0-9]{1,5}$ ]] && ((pi_port >= 1024 && pi_port <= 65535)) || { echo 'Invalid port.' >&2; exit 1; }
if ! systemctl is-active --quiet woowtech-piweb-gateway.service && [[ -n "$(ss -H -ltn "( sport = :$pi_port )")" ]]; then
  echo 'The requested gateway port is already in use.' >&2; exit 1
fi
if [[ -n "$pi_vpn" ]] && ! systemctl is-active --quiet woowtech-piweb-gateway-vpn.service && ss -H -ltn "( sport = :$pi_port )" | awk '{print $4}' | grep -Fxq "$pi_vpn:$pi_port"; then
  echo 'The requested VPN gateway address and port are already in use.' >&2; exit 1
fi
[ -r /etc/cockpit/ws-certs.d/0-self-signed.cert ] || { echo 'Expected Cockpit local CA certificate is missing.' >&2; exit 1; }
pi_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
pi_cred=/etc/woowtech-cockpit/piweb-gateway
pi_pkg=/usr/local/share/cockpit/woowpiweb
# Existing credentials are not rotated on reinstall.
install -d -m 0755 "$pi_pkg"
ensure_certificate() {
  local dir=$1 ip=$2
  install -d -m 0755 "$dir"
  if [[ ! -e "$dir/key.pem" && ! -e "$dir/cert.pem" ]]; then
    (umask 077; openssl req -x509 -newkey rsa:3072 -noenc -keyout "$dir/key.pem" -out "$dir/cert.pem" -days 365 -subj "/CN=$ip" -addext "subjectAltName=IP:$ip" >/dev/null 2>&1)
  elif [[ ! -f "$dir/key.pem" || ! -f "$dir/cert.pem" ]]; then
    echo 'Partial gateway certificate exists; inspect it before retrying.' >&2; exit 1
  fi
  chmod 0600 "$dir/key.pem"; chmod 0644 "$dir/cert.pem"
  openssl x509 -in "$dir/cert.pem" -noout -checkip "$ip" | grep -q 'does match' || { echo 'Existing certificate does not match this IP.' >&2; exit 1; }
}
ensure_certificate "$pi_cred" "$pi_host"
if [[ -n "$pi_vpn" ]]; then ensure_certificate "${pi_cred}-vpn" "$pi_vpn"; fi
install -m 0755 "$pi_root/gateway.mjs" /usr/local/libexec/woowtech-piweb-gateway.mjs
install -m 0644 "$pi_root/package/index.html" "$pi_root/package/style.css" "$pi_pkg/"
sed -e "s/__GATEWAY_HOST__/$pi_host/g" -e "s/__VPN_HOST__/$pi_vpn/g" -e "s/__GATEWAY_PORT__/$pi_port/g" "$pi_root/package/app.js" > "$pi_pkg/app.js"
vpn_frame=''; if [[ -n "$pi_vpn" ]]; then vpn_frame="https://$pi_vpn:$pi_port"; fi
sed -e "s/__GATEWAY_HOST__/$pi_host/g" -e "s/__GATEWAY_PORT__/$pi_port/g" -e "s|__VPN_FRAME_SRC__|$vpn_frame|g" "$pi_root/package/manifest.json" > "$pi_pkg/manifest.json"
sed -e "s/__GATEWAY_HOST__/$pi_host/g" -e "s/__GATEWAY_PORT__/$pi_port/g" "$pi_root/woowtech-piweb-gateway.service" > /etc/systemd/system/woowtech-piweb-gateway.service
chmod 0644 "$pi_pkg/app.js" "$pi_pkg/manifest.json" /etc/systemd/system/woowtech-piweb-gateway.service
systemd-analyze verify /etc/systemd/system/woowtech-piweb-gateway.service
systemctl daemon-reload
systemctl enable woowtech-piweb-gateway.service
systemctl restart woowtech-piweb-gateway.service
systemctl is-active --quiet woowtech-piweb-gateway.service || { echo 'Gateway did not start.' >&2; exit 1; }
if [[ -n "$pi_vpn" ]]; then
  sed -e "s/__GATEWAY_HOST__/$pi_vpn/g" -e "s/__GATEWAY_PORT__/$pi_port/g" -e 's|piweb-gateway/|piweb-gateway-vpn/|g' "$pi_root/woowtech-piweb-gateway.service" > /etc/systemd/system/woowtech-piweb-gateway-vpn.service
  chmod 0644 /etc/systemd/system/woowtech-piweb-gateway-vpn.service
  systemd-analyze verify /etc/systemd/system/woowtech-piweb-gateway-vpn.service
  systemctl daemon-reload
  systemctl enable woowtech-piweb-gateway-vpn.service
  systemctl restart woowtech-piweb-gateway-vpn.service
  systemctl is-active --quiet woowtech-piweb-gateway-vpn.service || { echo 'VPN gateway did not start.' >&2; exit 1; }
fi
printf 'Installed Pi Web gateway on https://%s:%s/ . Sign out/in to refresh Cockpit package list.\n' "$pi_host" "$pi_port"
