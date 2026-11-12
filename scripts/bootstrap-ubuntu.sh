#!/usr/bin/env bash
# Install the host packages; theme deployment is a separate reviewed operation.
set -euo pipefail
mode=${1:---plan}
if [[ "$mode" != --plan && "$mode" != --apply ]]; then
  printf 'Usage: %s [--plan|--apply]\n' "$0" >&2
  exit 2
fi
. /etc/os-release
if [[ "$ID" != ubuntu || "${VERSION_ID:-}" != 24.04 ]]; then
  printf 'This bootstrap is validated for Ubuntu 24.04; found %s.\n' "$PRETTY_NAME" >&2
  exit 1
fi
packages=(cockpit cockpit-podman cockpit-storaged cockpit-networkmanager cockpit-packagekit)
printf 'Install from %s-backports: %s\nEnable: cockpit.socket\n' "$VERSION_CODENAME" "${packages[*]}"
if [[ "$mode" == --plan ]]; then
  printf 'No changes made. Run with sudo and --apply to install.\n'
  exit 0
fi
if [[ $EUID -ne 0 ]]; then
  printf 'Run --apply with sudo.\n' >&2
  exit 1
fi
apt-get update
apt-get install -y -t "${VERSION_CODENAME}-backports" "${packages[@]}"
systemctl enable --now cockpit.socket
printf 'Open https://<this-host>:9090 using an existing system account.\n'
printf 'Next: sudo python3 scripts/manage.py install\n'
