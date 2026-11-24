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
# Backup & restore engine tools from the regular archive: age encrypts (universe), zstd compresses; python3-nacl and
# python3-cryptography decrypt uploaded Home Assistant backups (securetar v3 / v1-v2).
backup_packages=(age zstd python3-nacl python3-cryptography)
printf 'Install from %s-backports: %s\n' "$VERSION_CODENAME" "${packages[*]}"
printf 'Install from %s (universe, updates): %s\n' "$VERSION_CODENAME" "${backup_packages[*]}"
printf 'Enable: cockpit.socket\n'
missing=()  # backup packages to add; one that apt-mark holds is installed too
for package in "${packages[@]}" "${backup_packages[@]}"; do
  if status=$(dpkg-query -W -f='${Status} ${Version}' "$package" 2>/dev/null) && [[ "$status" == *' ok installed '* ]]; then
    printf '  %s: installed %s\n' "$package" "${status##* }"
  else
    printf '  %s: not installed\n' "$package"
    [[ " ${backup_packages[*]} " != *" $package "* ]] || missing+=("$package")
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
# An index that cannot be refreshed (offline, a broken third-party source) decides nothing by itself.
apt-get update --error-on=any || printf '有套件索引無法更新（網路、DNS、代理伺服器或某個套件來源），先用這台現有的索引繼續。\n' >&2
for package in "${missing[@]}"; do
  if ! apt-cache show "$package" >/dev/null 2>&1; then
    printf '%s is not available from the configured apt sources. Enable the Ubuntu "universe" component (sudo add-apt-repository universe) and re-run; nothing was installed.\n' "$package" >&2
    printf '套件庫找不到 %s：請確認這台連得到 Ubuntu 套件庫並已啟用 universe，再重新執行；沒有安裝任何套件。\n' "$package" >&2
    exit 1
  fi
done
apt-get install -y -t "${VERSION_CODENAME}-backports" "${packages[@]}"
# All of them as before (newest version, kept by autoremove); when that fails, only the missing ones decide.
if ! apt-get install -y "${backup_packages[@]}" && (( ${#missing[@]} )) && ! apt-get install -y "${missing[@]}"; then
  printf '備份與還原需要的套件沒有裝好：%s。原因見上面 apt 的訊息（常見是這台連不到套件庫）；排除後重新執行即可。\n' "${missing[*]}" >&2
  exit 1
fi
systemctl enable --now cockpit.socket
printf 'Open https://<this-host>:9090 using an existing system account.\n'
printf 'Next: sudo python3 scripts/manage.py install\n'
