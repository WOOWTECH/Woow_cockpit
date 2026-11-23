# Nextcloud step C: delete ONLY the test user this lane created (its files and app passwords go with it). Nextcloud stays started.
set -uo pipefail
S=1b7b4ce7_woow-nextcloud-office; C=app_$S; U=woow-import-test
occ() { docker exec -u www-data $C php /var/www/nextcloud/occ "$@"; }
q() { docker exec -u postgres $C psql -h /run/postgresql -d nextcloud -Atc "$1" 2>&1 | head -1; }
occ user:delete $U 2>&1 | tail -1 | cut -c1-120
echo "after cleanup: users=$(occ user:list --output=json 2>/dev/null | jq -r length) names=$(occ user:list --output=json 2>/dev/null | jq -r 'keys|join(",")') authtoken_of_test_user=$(q "select count(*) from oc_authtoken where uid='$U'") files_dir=$([ -e /share/nextcloud/$U ] && echo present || echo absent)"
echo "state: $(ha apps info $S --raw-json | jq -r '.data | "\(.version) \(.state)"') healthz=$(curl -s -o /dev/null -w '%{http_code}' -m 10 http://1b7b4ce7-woow-nextcloud-office:8090/healthz)"
