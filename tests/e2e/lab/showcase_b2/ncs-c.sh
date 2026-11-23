# Nextcloud-with-share step C: delete ONLY the two test users this lane created (their files, versions, trash, shares,
# public link, calendar, address book and app passwords go with them). Nextcloud stays started. Counts only.
set -uo pipefail
S=1b7b4ce7_woow-nextcloud-office; C=app_$S; H=1b7b4ce7-woow-nextcloud-office; A=woow-import-share; B=woow-import-share2
occ() { docker exec -u www-data $C php /var/www/nextcloud/occ "$@"; }
q() { docker exec -u postgres $C psql -h /run/postgresql -d nextcloud -Atc "$1" 2>&1 | head -1; }
for u in $A $B; do echo "delete $u: $(occ user:delete $u 2>&1 | tail -1 | cut -c1-100)"; done
echo "after cleanup: users=$(occ user:list --output=json 2>/dev/null | jq -r length) names=$(occ user:list --output=json 2>/dev/null | jq -r 'keys|join(",")')"
echo "left of the test users: tokens=$(q "select count(*) from oc_authtoken where uid in ('$A','$B')") shares=$(q "select count(*) from oc_share where uid_owner in ('$A','$B') or share_with in ('$A','$B')") calendars=$(q "select count(*) from oc_calendars where principaluri in ('principals/users/$A','principals/users/$B')") books=$(q "select count(*) from oc_addressbooks where principaluri in ('principals/users/$A','principals/users/$B')") filecache_storages=$(q "select count(*) from oc_storages where id in ('home::$A','home::$B')") dirs=$(ls -d /share/nextcloud/$A /share/nextcloud/$B 2>/dev/null | wc -l)"
for t in oc_users oc_filecache oc_share oc_authtoken oc_calendars oc_calendarobjects oc_addressbooks oc_cards oc_storages oc_mounts; do printf '%s ' "$t=$(q "select count(*) from $t")"; done; echo
echo "state: $(ha apps info $S --raw-json | jq -r '.data | "\(.version) \(.state)"') healthz=$(curl -s -o /dev/null -w '%{http_code}' -m 10 http://$H:8090/healthz) status=$(curl -s -m 10 http://$H:8000/status.php | jq -c '{versionstring, maintenance}') $(date -u +%FT%TZ)"
