#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
brand=$(python3 - "${BRAND:-}" <<'PY'
import json
import sys
from pathlib import Path
p = Path('/etc/cockpit/branding/brand.json')
installed = json.loads(p.read_text())['id'] if p.exists() else 'woowtech'
requested = sys.argv[1] or installed
if requested not in ('woowtech', 'apporo') or requested != installed:
    raise SystemExit('Install the matching Cockpit brand profile before installing its PWA.')
print(requested)
PY
)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
python3 "$here/render.py" --brand "$brand" --output "$stage"
install_dir="$HOME/.local/share/woowtech-cockpit-pwa"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/containers/systemd"
install -d -m 755 "$install_dir/assets" "$unit_dir"
install -m 644 "$stage/nginx.conf" "$install_dir/nginx.conf"
install -m 644 "$stage"/assets/* "$install_dir/assets/"
install -m 644 "$here/woow-cockpit-pwa.container" "$unit_dir/woow-cockpit-pwa.container"
systemctl --user daemon-reload
systemctl --user restart woow-cockpit-pwa.service
systemctl --user is-active woow-cockpit-pwa.service
