#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install_dir="$HOME/.local/share/woowtech-cockpit-pwa"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/containers/systemd"
install -d -m 755 "$install_dir/assets" "$unit_dir"
install -m 644 "$here/nginx.conf" "$install_dir/nginx.conf"
install -m 644 "$here"/assets/* "$install_dir/assets/"
install -m 644 "$here/woow-cockpit-pwa.container" "$unit_dir/woow-cockpit-pwa.container"
systemctl --user daemon-reload
systemctl --user restart woow-cockpit-pwa.service
systemctl --user is-active woow-cockpit-pwa.service
