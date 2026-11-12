#!/bin/bash
# Install this integration separately from Cockpit's shared backup installer.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo 'Run with sudo.' >&2; exit 1; }
pi_host=${1:-}; pi_port=${2:-19094}
[[ "$pi_host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo 'Supply the LAN IPv4 address.' >&2; exit 1; }
IFS=. read -r a b c d <<< "$pi_host"
for part in "$a" "$b" "$c" "$d"; do ((10#$part <= 255)) || { echo 'Invalid IP.' >&2; exit 1; }; done
[[ "$pi_port" =~ ^[0-9]{1,5}$ ]] && ((pi_port >= 1024 && pi_port <= 65535)) || { echo 'Invalid port.' >&2; exit 1; }
ip -4 -o address show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$pi_host" || { echo 'IP is not on a local interface.' >&2; exit 1; }
if ! systemctl is-active --quiet woowtech-piweb-gateway.service && [[ -n "$(ss -H -ltn "( sport = :$pi_port )")" ]]; then
  echo 'The requested gateway port is already in use.' >&2; exit 1
fi
[ -r /etc/cockpit/ws-certs.d/0-self-signed.cert ] || { echo 'Expected Cockpit local CA certificate is missing.' >&2; exit 1; }
pi_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
pi_cred=/etc/woowtech-cockpit/piweb-gateway
pi_pkg=/usr/local/share/cockpit/woowpiweb
# Existing credentials are not rotated on reinstall.
install -d -m 0755 "$pi_cred" "$pi_pkg"
if [[ ! -e "$pi_cred/key.pem" && ! -e "$pi_cred/cert.pem" ]]; then
  umask 077
  openssl req -x509 -newkey rsa:3072 -noenc -keyout "$pi_cred/key.pem" -out "$pi_cred/cert.pem" -days 365 -subj "/CN=$pi_host" -addext "subjectAltName=IP:$pi_host" >/dev/null 2>&1
elif [[ ! -f "$pi_cred/key.pem" || ! -f "$pi_cred/cert.pem" ]]; then
  echo 'Partial gateway certificate exists; inspect it before retrying.' >&2; exit 1
fi
chmod 0600 "$pi_cred/key.pem"; chmod 0644 "$pi_cred/cert.pem"
openssl x509 -in "$pi_cred/cert.pem" -noout -checkip "$pi_host" | grep -q 'does match' || { echo 'Existing certificate does not match this IP.' >&2; exit 1; }
install -m 0755 "$pi_root/gateway.mjs" /usr/local/libexec/woowtech-piweb-gateway.mjs
install -m 0644 "$pi_root/package/index.html" "$pi_root/package/style.css" "$pi_pkg/"
sed -e "s/__GATEWAY_HOST__/$pi_host/g" -e "s/__GATEWAY_PORT__/$pi_port/g" "$pi_root/package/app.js" > "$pi_pkg/app.js"
sed -e "s/__GATEWAY_HOST__/$pi_host/g" -e "s/__GATEWAY_PORT__/$pi_port/g" "$pi_root/package/manifest.json" > "$pi_pkg/manifest.json"
sed -e "s/__GATEWAY_HOST__/$pi_host/g" -e "s/__GATEWAY_PORT__/$pi_port/g" "$pi_root/woowtech-piweb-gateway.service" > /etc/systemd/system/woowtech-piweb-gateway.service
chmod 0644 "$pi_pkg/app.js" "$pi_pkg/manifest.json" /etc/systemd/system/woowtech-piweb-gateway.service
systemd-analyze verify /etc/systemd/system/woowtech-piweb-gateway.service
systemctl daemon-reload
systemctl enable woowtech-piweb-gateway.service
systemctl restart woowtech-piweb-gateway.service
systemctl is-active --quiet woowtech-piweb-gateway.service || { echo 'Gateway did not start.' >&2; exit 1; }
printf 'Installed Pi Web gateway on https://%s:%s/ . Sign out/in to refresh Cockpit package list.\n' "$pi_host" "$pi_port"
