# Runs on the x86 showcase HA through rr.sh (bash -s). READ-ONLY inventory for batch 2 (OpenDesign, Nextcloud, code-server).
# Prints slugs, versions, states, option NAMES only (never option values), sizes and counts.
set -uo pipefail
apps() { ha apps list --raw-json 2>/dev/null | jq -c '.data.addons // .data.apps'; }
echo "== host"; ha info --raw-json | jq -c '.data | {arch, machine, hassos, supervisor, homeassistant}'
free -m | sed -n 1,3p; df -h /data /backup 2>/dev/null | tail -n +2; nproc
echo "== candidate add-ons (slug version latest state update)"
apps | jq -r '.[] | select(.slug|test("opendesign|nextcloud|code.server|code_server|vscode")) | [.slug, .name, .version, (.version_latest // "-"), .state, (.update_available // false)] | @tsv'
for s in $(apps | jq -r '.[] | select(.slug|test("opendesign|nextcloud|code.server|code_server|vscode")) | .slug'); do
  echo "== info $s"
  ha apps info "$s" --raw-json | jq -c '.data | {slug, hostname, version, version_latest, update_available, state, boot, arch, repository, ingress, ingress_port, watchdog, auto_update, startup}'
  ha apps info "$s" --raw-json | jq -r '"option names: " + ((.data.options // {}) | keys | join(","))'
  ha apps stats "$s" --raw-json 2>/dev/null | jq -c '.data | {cpu_percent, memory_usage, memory_limit}'
done
echo "== backups"; ha backups list --raw-json | jq -r '.data.backups | "count=\(length) total_mb=\(map(.size)|add)"'
ha backups list --raw-json | jq -r '.data.backups[] | select(.date >= "2026-11-22") | [.slug, .name, .date, .size, .protected] | @tsv'
echo "== /share top level (name size)"; du -sh /share/* 2>/dev/null | sort -h | tail -20; du -sh /share 2>/dev/null
echo "== /addon_configs relevant"; ls /addon_configs 2>/dev/null | grep -Ei 'opendesign|nextcloud|code' 
echo "== running containers of candidates"; docker ps --format '{{.Names}} {{.Status}}' | grep -Ei 'opendesign|nextcloud|code' 
