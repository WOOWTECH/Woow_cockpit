# READ-ONLY inventory part 2 (bash -s on the showcase HA). Names, sizes, counts and booleans only.
set -uo pipefail
echo "== store repositories (slug name source)"; ha store --raw-json | jq -r '.data.repositories[] | [.slug, .name, .source] | @tsv' | grep -E '^(1b7b4ce7|d65e8bf4|a020c0ec|9663031d)'
echo "== shell"; hostname; head -2 /etc/os-release | tr '\n' ' '; echo; ls -d /mnt/data/supervisor/addons/data 2>/dev/null || echo "no /mnt/data view"
echo "== add-on images (repo tag size)"; docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep -Ei 'opendesign|nextcloud|code-server' | head -12
echo "== add-on data dirs that exist (docker volume-free check via supervisor paths in container inspect)"
for s in 1b7b4ce7_woow_ha_opendesign d65e8bf4_woow_ha_opendesign 1b7b4ce7_woow_ha_code_server a020c0ec_woow_ha_code_server 1b7b4ce7_woow-nextcloud-office; do
  c=addon_$s; ex=$(docker inspect -f '{{.State.Status}}' $c 2>/dev/null || echo none)
  echo "$s container=$ex"
done
echo "== code-server config_path is the default /share/projects?"
for s in 1b7b4ce7_woow_ha_code_server a020c0ec_woow_ha_code_server; do
  echo "$s: $(ha apps info $s --raw-json | jq -r '.data.options.config_path == "/share/projects"')"
done
echo "== /share/projects (names sizes)"; du -sh /share/projects/* 2>/dev/null | head -20; ls -la /share/projects 2>/dev/null | head -12 | awk '{print $1, $3, $4, $NF}'
N=1b7b4ce7_woow-nextcloud-office; C=addon_$N
echo "== nextcloud option NEXTCLOUD_DATADIR under /share?: $(ha apps info $N --raw-json | jq -r '.data.options.NEXTCLOUD_DATADIR | tostring | startswith("/share/")')"
echo "== nextcloud config.php (non-secret keys only)"
docker exec $C sh -c "grep -E \"^[[:space:]]*'(datadirectory|version|installed|maintenance|dbtype)'[[:space:]]*=>\" /data/nextcloud/config/config.php" 2>&1 | head -6
echo "== occ status"; docker exec -u www-data $C php /var/www/nextcloud/occ status --output=json 2>&1 | tail -1 | cut -c1-280
echo "== users count"; docker exec -u www-data $C php /var/www/nextcloud/occ user:list --output=json 2>/dev/null | jq -r 'length'
echo "== apps enabled count / disabled count"; docker exec -u www-data $C php /var/www/nextcloud/occ app:list --output=json 2>/dev/null | jq -r '"\(.enabled|length) \(.disabled|length)"'
echo "== encryption"; docker exec -u www-data $C php /var/www/nextcloud/occ encryption:status --output=json 2>/dev/null | jq -c '.' | cut -c1-200
echo "== /share/nextcloud (names sizes, depth 1)"; du -sh /share/nextcloud/* /share/nextcloud/.ncdata 2>/dev/null | head -20
echo "== share totals in bytes"; du -sb /share 2>/dev/null; du -sb /share/nextcloud 2>/dev/null
echo "== nextcloud health"; curl -s -o /dev/null -w 'healthz %{http_code}\n' -m 10 http://1b7b4ce7-woow-nextcloud-office:8090/healthz
curl -s -m 10 http://1b7b4ce7-woow-nextcloud-office:8000/status.php | jq -c '{installed, version, versionstring, maintenance, needsDbUpgrade}' 2>/dev/null
