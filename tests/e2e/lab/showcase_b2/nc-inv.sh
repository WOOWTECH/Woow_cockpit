# Nextcloud READ-ONLY facts (bash -s on the showcase HA): versions, counts, sizes, special files (R1), no secret values.
set -uo pipefail
S=1b7b4ce7_woow-nextcloud-office; C=app_$S
occ() { docker exec -u www-data $C php /var/www/nextcloud/occ "$@"; }
q() { docker exec -u postgres $C psql -h /run/postgresql -d nextcloud -Atc "$1" 2>&1 | head -1; }
echo "state: $(ha apps info $S --raw-json | jq -r '.data | "\(.version) \(.state) boot=\(.boot)"') image=$(docker inspect -f '{{.Config.Image}}' $C)"
echo "tools: $(docker exec $C sh -c 'for t in curl psql sqlite3 jq; do command -v $t >/dev/null && printf "%s " $t; done')"
echo "status: $(occ status --output=json 2>/dev/null | jq -c '{installed, version, versionstring, maintenance, needsDbUpgrade}')"
echo "config (non-secret keys): datadirectory=$(occ config:system:get datadirectory 2>/dev/null) dbtype=$(occ config:system:get dbtype 2>/dev/null) version=$(occ config:system:get version 2>/dev/null) twofactor_enforced=$(occ config:system:get twofactor_enforced 2>/dev/null || echo unset) encryption_app=$(occ app:list --output=json 2>/dev/null | jq -r 'if .enabled.encryption then "enabled" else "off" end')"
echo "apps: enabled=$(occ app:list --output=json 2>/dev/null | jq -r '.enabled|length') disabled=$(occ app:list --output=json 2>/dev/null | jq -r '.disabled|length') custom_apps=$(docker exec $C sh -c 'ls -1 /data/nextcloud/custom_apps 2>/dev/null | tr "\n" ","')"
echo "users: $(occ user:list --output=json 2>/dev/null | jq -r 'length') names=$(occ user:list --output=json 2>/dev/null | jq -r 'keys|join(",")' | cut -c1-120)"
echo "pg: $(q 'show server_version') PG_VERSION=$(docker exec $C cat /data/postgres/PG_VERSION 2>/dev/null)"
for t in oc_users oc_filecache oc_share oc_authtoken oc_calendarobjects oc_cards oc_storages oc_mounts; do printf '%s ' "$t=$(q "select count(*) from $t")"; done; echo
echo "sizes: $(for d in /data /data/postgres /data/nextcloud /data/nextcloud/custom_apps /data/redis /data/coolwsd-jail /data/coolwsd-cache; do printf '%s=%s ' $d "$(docker exec $C du -sh $d 2>/dev/null | cut -f1)"; done)"
echo "R1 special entries under /data: devices=$(docker exec $C sh -c 'find /data -xdev \( -type b -o -type c \) 2>/dev/null | wc -l') fifos=$(docker exec $C sh -c 'find /data -xdev -type p 2>/dev/null | wc -l') sockets=$(docker exec $C sh -c 'find /data -xdev -type s 2>/dev/null | wc -l') hardlinked_files=$(docker exec $C sh -c 'find /data -xdev -type f -links +1 2>/dev/null | wc -l') symlinks=$(docker exec $C sh -c 'find /data -xdev -type l 2>/dev/null | wc -l')"
echo "R1 by top dir (devices+hardlinks): $(docker exec $C sh -c 'for d in /data/*; do n=$(find "$d" -xdev \( -type b -o -type c -o \( -type f -links +1 \) \) 2>/dev/null | wc -l); [ "$n" != 0 ] && printf "%s=%s " "$d" "$n"; done; true')"
echo "share user dirs: $(ls -1 /share/nextcloud 2>/dev/null | tr '\n' ',')"
echo "health: healthz=$(curl -s -o /dev/null -w '%{http_code}' -m 10 http://1b7b4ce7-woow-nextcloud-office:8090/healthz)"
