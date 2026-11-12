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
# Backup & restore engine tools from the regular archive: age encrypts (universe), zstd compresses.
backup_packages=(age zstd)
printf 'Install from %s-backports: %s\n' "$VERSION_CODENAME" "${packages[*]}"
printf 'Install from %s (universe, updates): %s\n' "$VERSION_CODENAME" "${backup_packages[*]}"
printf 'Enable: cockpit.socket\n'
for package in "${packages[@]}" "${backup_packages[@]}"; do
  if status=$(dpkg-query -W -f='${Status} ${Version}' "$package" 2>/dev/null) && [[ "$status" == 'install ok installed '* ]]; then
    printf '  %s: installed %s\n' "$package" "${status#install ok installed }"
  else
    printf '  %s: not installed\n' "$package"
  fi
done
if [[ "$mode" == --plan ]]; then
  printf 'No changes made. Run with sudo and --apply to install.\n'
  exit 0
fi
if [[ $EUID -ne 0 ]]; then
  printf 'Run --apply with sudo.\n' >&2
  exit 1
fi
apt-get update
for package in "${backup_packages[@]}"; do
  if ! apt-cache show "$package" >/dev/null 2>&1; then
    printf '%s is not available from the configured apt sources. Enable the Ubuntu "universe" component (sudo add-apt-repository universe) and re-run; nothing was installed.\n' "$package" >&2
    exit 1
  fi
done
apt-get install -y -t "${VERSION_CODENAME}-backports" "${packages[@]}"
apt-get install -y "${backup_packages[@]}"
systemctl enable --now cockpit.socket
printf 'Open https://<this-host>:9090 using an existing system account.\n'
printf 'Next: sudo python3 scripts/manage.py install\n'
