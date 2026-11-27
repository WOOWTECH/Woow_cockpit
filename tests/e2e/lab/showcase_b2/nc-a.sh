# Nextcloud step A (bash -s on the showcase HA): test markers for the DB-level continuity check of the add-on-only backup:
# test user woow-import-test (generated password), one app password, two small WebDAV files (they live in /share, so they
# are NOT in an add-on-only backup; only their DB rows are). Secrets go out only as @@CRED@@ lines (rr.sh stores + masks).
set -uo pipefail
S=1b7b4ce7_woow-nextcloud-office; C=app_$S; U=woow-import-test
occ() { docker exec -u www-data $C php /var/www/nextcloud/occ "$@"; }
q() { docker exec -u postgres $C psql -h /run/postgresql -d nextcloud -Atc "$1" 2>&1 | head -1; }
counts() { echo "users=$(occ user:list --output=json 2>/dev/null | jq -r length) authtoken=$(q 'select count(*) from oc_authtoken') filecache=$(q 'select count(*) from oc_filecache')"; }
echo "before: $(ha apps info $S --raw-json | jq -r '.data | "\(.version) \(.state)"') $(counts) $(date -u +%FT%TZ)"
if occ user:info $U >/dev/null 2>&1; then echo "STOP: test user already exists"; exit 1; fi
PW=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24)
echo "@@CRED@@ B2_NC_X86_NOSHARE_USER_PW=$PW"
OC_PASS="$PW" docker exec -e OC_PASS -u www-data $C php /var/www/nextcloud/occ user:add --password-from-env --display-name "WOOW 匯入測試" $U 2>&1 | tail -1 | cut -c1-120
AP=$(printf 'machine 127.0.0.1 login %s password %s\n' "$U" "$PW" | docker exec -i $C curl -s -m 30 --netrc-file /dev/stdin -H 'OCS-APIRequest: true' 'http://127.0.0.1:8000/ocs/v2.php/core/getapppassword?format=json' | jq -r '.ocs.data.apppassword // empty')
if [ -n "$AP" ]; then echo "@@CRED@@ B2_NC_X86_NOSHARE_APP_PW=$AP"; else echo "app password NOT created"; fi
printf 'machine 127.0.0.1 login %s password %s\n' "$U" "${AP:-$PW}" | docker exec -i $C sh -c 'umask 077; cat > /tmp/.woow-netrc'
docker exec $C sh -c "printf 'WOOW import marker 2026-11-23 Nextcloud x86\n' > /tmp/woow-m1.txt; printf '匯入測試 標記檔 2026-11-23\n' > /tmp/woow-m2.txt"
F1=woow-import-test-20261123.txt; F2=$(jq -rn --arg s '匯入測試-20261123.txt' '$s|@uri')
B=http://127.0.0.1:8000/remote.php/dav/files/$U
echo "put: $(docker exec $C curl -s -o /dev/null -w '%{http_code}' -m 30 --netrc-file /tmp/.woow-netrc -T /tmp/woow-m1.txt $B/$F1) $(docker exec $C curl -s -o /dev/null -w '%{http_code}' -m 30 --netrc-file /tmp/.woow-netrc -T /tmp/woow-m2.txt $B/$F2)"
echo "propfind with app password: $(docker exec $C curl -s -o /dev/null -w '%{http_code}' -m 30 --netrc-file /tmp/.woow-netrc -X PROPFIND -H 'Depth: 1' $B/)"
docker exec $C rm -f /tmp/.woow-netrc /tmp/woow-m1.txt /tmp/woow-m2.txt
echo "on disk: $(sha256sum /share/nextcloud/$U/files/*.txt 2>/dev/null | awk '{print substr($1,1,16)}' | tr '\n' ' ')"
echo "after: $(counts) $(date -u +%FT%TZ)"
