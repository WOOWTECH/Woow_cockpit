# READ-ONLY end-state check (bash -s on the showcase HA).
set -uo pipefail
echo "now $(date -u +%FT%TZ)"
for s in 1b7b4ce7_woow_ha_opendesign d65e8bf4_woow_ha_opendesign 1b7b4ce7_woow_ha_code_server a020c0ec_woow_ha_code_server 1b7b4ce7_woow-nextcloud-office; do
  echo "$s $(ha apps info $s --raw-json | jq -r '.data | "\(.version) \(.state) boot=\(.boot)"')"; done
C=app_1b7b4ce7_woow-nextcloud-office
echo "nextcloud: healthz=$(curl -s -o /dev/null -w '%{http_code}' -m 10 http://1b7b4ce7-woow-nextcloud-office:8090/healthz) users=$(docker exec -u www-data $C php /var/www/nextcloud/occ user:list --output=json 2>/dev/null | jq -r 'keys|join(",")') status=$(curl -s -m 10 http://1b7b4ce7-woow-nextcloud-office:8000/status.php | jq -c '{versionstring, maintenance}')"
echo "nextcloud 0.2.3 image accounts (name:uid:gid): $(docker exec $C sh -c "grep -E '^(postgres|redis|cool|www-data):' /etc/passwd | cut -d: -f1,3,4 | tr '\n' ' '")"
echo "== this lane's backups"
ha backups list --raw-json | jq -r '.data.backups[] | select(.name | startswith("WOOW匯入測試 B2")) | [.slug, .name, .date[0:19], .size, .protected] | @tsv'
ls -l /backup/woow-b2-*.tar | awk '{print $5, $NF}'
echo "== free on HA: $(df -h /backup | tail -1 | awk '{print $4}')"
