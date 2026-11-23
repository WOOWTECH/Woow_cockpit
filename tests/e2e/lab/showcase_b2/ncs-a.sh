# Nextcloud-with-share step A (bash -s on the showcase HA): test markers that live in the share folder, so the
# share-including backup carries them as real user files. Two test users (A owns everything, B receives a user share),
# A's app password, WebDAV files (ASCII, CJK name, nested CJK folders, a 4 MiB random binary, a file with one older
# version), a read-only user share A->B, a password-protected public link (expires 2026-12-07), one CalDAV event and
# one CardDAV contact. Generated secrets leave only as @@CRED@@ lines (rr.sh stores and masks them). Prints codes,
# counts and 16-char sha256 prefixes only. Step C (ncs-c.sh) deletes both users, which removes all of it.
set -uo pipefail
S=1b7b4ce7_woow-nextcloud-office; C=app_$S; A=woow-import-share; B=woow-import-share2
I=http://127.0.0.1:8000; DAV=$I/remote.php/dav
occ() { docker exec -u www-data $C php /var/www/nextcloud/occ "$@"; }
q() { docker exec -u postgres $C psql -h /run/postgresql -d nextcloud -Atc "$1" 2>&1 | head -1; }
gen() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24; }
enc() { jq -rn --arg s "$1" '$s|@uri'; }
counts() { echo "users=$(occ user:list --output=json 2>/dev/null | jq -r length) authtoken=$(q 'select count(*) from oc_authtoken') filecache=$(q 'select count(*) from oc_filecache') share=$(q 'select count(*) from oc_share') calendars=$(q 'select count(*) from oc_calendars') calendarobjects=$(q 'select count(*) from oc_calendarobjects') addressbooks=$(q 'select count(*) from oc_addressbooks') cards=$(q 'select count(*) from oc_cards')"; }
ca() { docker exec $C curl -s -o /dev/null -w '%{http_code}' -m 120 --netrc-file /tmp/.woow-na "$@"; }   # as A (app password)
cb() { docker exec $C curl -s -m 120 --netrc-file /tmp/.woow-nb "$@"; }                                  # as B (password)
echo "before: $(ha apps info $S --raw-json | jq -r '.data | "\(.version) \(.state)"') $(counts) $(date -u +%FT%TZ)"
for u in $A $B; do if occ user:info $u >/dev/null 2>&1; then echo "STOP: test user $u already exists"; exit 1; fi; done
PA=$(gen); PB=$(gen); PL=$(gen)
echo "@@CRED@@ B2_NC_X86_SHARE_USER_PW=$PA"
echo "@@CRED@@ B2_NC_X86_SHARE_USER2_PW=$PB"
echo "@@CRED@@ B2_NC_X86_SHARE_LINK_PW=$PL"
OC_PASS="$PA" docker exec -e OC_PASS -u www-data $C php /var/www/nextcloud/occ user:add --password-from-env --display-name "WOOW 匯入測試 share" $A 2>&1 | tail -1 | cut -c1-120
OC_PASS="$PB" docker exec -e OC_PASS -u www-data $C php /var/www/nextcloud/occ user:add --password-from-env --display-name "WOOW 匯入測試 share 2" $B 2>&1 | tail -1 | cut -c1-120
AP=$(printf 'machine 127.0.0.1 login %s password %s\n' "$A" "$PA" | docker exec -i $C curl -s -m 60 --netrc-file /dev/stdin -H 'OCS-APIRequest: true' "$I/ocs/v2.php/core/getapppassword?format=json" | jq -r '.ocs.data.apppassword // empty')
if [ -n "$AP" ]; then echo "@@CRED@@ B2_NC_X86_SHARE_APP_PW=$AP"; else echo "STOP: app password NOT created"; exit 1; fi
printf 'machine 127.0.0.1 login %s password %s\n' "$A" "$AP" | docker exec -i $C sh -c 'umask 077; cat > /tmp/.woow-na'
printf 'machine 127.0.0.1 login %s password %s\n' "$B" "$PB" | docker exec -i $C sh -c 'umask 077; cat > /tmp/.woow-nb'
docker exec $C sh -c "umask 022; printf 'WOOW import marker 2026-11-23 Nextcloud x86 with share\n' > /tmp/woow-s1.txt
  printf '匯入測試 標記檔 2026-11-23 含 share\n' > /tmp/woow-s2.txt; head -c 4194304 /dev/urandom > /tmp/woow-s3.bin
  printf 'WOOW versioned marker: version 1 (older)\n' > /tmp/woow-v1.txt; printf 'WOOW versioned marker: version 2 (current)\n' > /tmp/woow-v2.txt"
D1=$(enc '匯入資料夾'); D2=$(enc '子資料夾'); F2=$(enc '匯入測試-share-20261123.txt'); FA=$DAV/files/$A
echo "mkcol: $(ca -X MKCOL $FA/$D1) $(ca -X MKCOL $FA/$D1/$D2)"
echo "put: $(ca -T /tmp/woow-s1.txt $FA/woow-import-share-20261123.txt) $(ca -T /tmp/woow-s2.txt $FA/$F2) $(ca -T /tmp/woow-s3.bin $FA/$D1/$D2/woow-random-4m.bin) $(ca -T /tmp/woow-v1.txt $FA/woow-versioned.txt)"
sleep 3
echo "put v2: $(ca -T /tmp/woow-v2.txt $FA/woow-versioned.txt)"
SH="$I/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json"
R1=$(docker exec $C curl -s -m 60 --netrc-file /tmp/.woow-na -H 'OCS-APIRequest: true' -X POST "$SH" --data-urlencode "path=/匯入資料夾" -d shareType=0 --data-urlencode "shareWith=$B" -d permissions=1)
echo "user share A->B: status=$(printf '%s' "$R1" | jq -r '.ocs.meta.statuscode') id=$(printf '%s' "$R1" | jq -r '.ocs.data.id // "-"') msg=$(printf '%s' "$R1" | jq -r '.ocs.meta.message // ""' | cut -c1-100)"
R2=$(printf 'password=%s' "$PL" | docker exec -i $C curl -s -m 60 --netrc-file /tmp/.woow-na -H 'OCS-APIRequest: true' -X POST "$SH" -d @- --data-urlencode "path=/匯入資料夾" -d shareType=3 -d permissions=1 -d expireDate=2026-12-07)
LT=$(printf '%s' "$R2" | jq -r '.ocs.data.token // empty')
echo "public link: status=$(printf '%s' "$R2" | jq -r '.ocs.meta.statuscode') id=$(printf '%s' "$R2" | jq -r '.ocs.data.id // "-"') expiration=$(printf '%s' "$R2" | jq -r '.ocs.data.expiration // "-"') msg=$(printf '%s' "$R2" | jq -r '.ocs.meta.message // ""' | cut -c1-100)"
[ -n "$LT" ] && echo "@@CRED@@ B2_NC_X86_SHARE_LINK_TOKEN=$LT"
CAL='<?xml version="1.0" encoding="utf-8"?><c:mkcalendar xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:set><d:prop><d:displayname>WOOW 匯入測試 行事曆</d:displayname></d:prop></d:set></c:mkcalendar>'
BOOK='<?xml version="1.0" encoding="utf-8"?><d:mkcol xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:set><d:prop><d:resourcetype><d:collection/><card:addressbook/></d:resourcetype><d:displayname>WOOW 匯入測試 通訊錄</d:displayname></d:prop></d:set></d:mkcol>'
docker exec $C sh -c "printf 'BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//WOOWTECH//import-test//EN\r\nBEGIN:VEVENT\r\nUID:woow-import-share-20261123@woowtech.test\r\nDTSTAMP:20261123T090000Z\r\nDTSTART:20261201T010000Z\r\nDTEND:20261201T020000Z\r\nSUMMARY:WOOW 匯入測試 行程 2026-11-23\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n' > /tmp/woow-e.ics
  printf 'BEGIN:VCARD\r\nVERSION:3.0\r\nUID:woow-import-contact-20261123\r\nFN:WOOW 匯入測試 聯絡人\r\nN:聯絡人;WOOW 匯入測試;;;\r\nEMAIL;TYPE=INTERNET:import-test@woowtech.test\r\nEND:VCARD\r\n' > /tmp/woow-c.vcf"
echo "caldav: mkcalendar=$(ca -X MKCALENDAR -H 'Content-Type: application/xml; charset=utf-8' --data-binary "$CAL" $DAV/calendars/$A/woow-import-cal/) put=$(ca -T /tmp/woow-e.ics -H 'Content-Type: text/calendar; charset=utf-8' $DAV/calendars/$A/woow-import-cal/woow-import-event.ics) get=$(ca $DAV/calendars/$A/woow-import-cal/woow-import-event.ics)"
echo "carddav: mkcol=$(ca -X MKCOL -H 'Content-Type: application/xml; charset=utf-8' --data-binary "$BOOK" $DAV/addressbooks/users/$A/woow-import-book/) put=$(ca -T /tmp/woow-c.vcf -H 'Content-Type: text/vcard; charset=utf-8' $DAV/addressbooks/users/$A/woow-import-book/woow-import-contact.vcf) get=$(ca $DAV/addressbooks/users/$A/woow-import-book/woow-import-contact.vcf)"
echo "A propfind (app password): $(ca -X PROPFIND -H 'Depth: 1' $FA/)"
echo "B sees the shared folder: $(cb -X PROPFIND -H 'Depth: 1' $DAV/files/$B/ | grep -c "$D1/") B reads the 4 MiB file: $(cb $DAV/files/$B/$D1/$D2/woow-random-4m.bin | sha256sum | cut -c1-16)"
if [ -n "$LT" ]; then
  echo "public link (new dav, anonymous:pw): $(printf 'machine 127.0.0.1 login anonymous password %s\n' "$PL" | docker exec -i $C curl -s -m 60 --netrc-file /dev/stdin "$I/public.php/dav/files/$LT/$D2/woow-random-4m.bin" | sha256sum | cut -c1-16)"
  echo "public link (legacy webdav, token:pw): $(printf 'machine 127.0.0.1 login %s password %s\n' "$LT" "$PL" | docker exec -i $C curl -s -m 60 --netrc-file /dev/stdin "$I/public.php/webdav/$D2/woow-random-4m.bin" | sha256sum | cut -c1-16)"
  echo "public link without password: $(docker exec $C curl -s -o /dev/null -w '%{http_code}' -m 60 "$I/public.php/dav/files/$LT/$D2/woow-random-4m.bin")"
fi
docker exec $C rm -f /tmp/.woow-na /tmp/.woow-nb /tmp/woow-s1.txt /tmp/woow-s2.txt /tmp/woow-s3.bin /tmp/woow-v1.txt /tmp/woow-v2.txt /tmp/woow-e.ics /tmp/woow-c.vcf
U=/share/nextcloud/$A/files
echo "on disk (sha256/16): s1=$(sha256sum "$U/woow-import-share-20261123.txt" | cut -c1-16) s2=$(sha256sum "$U/匯入測試-share-20261123.txt" | cut -c1-16) s3=$(sha256sum "$U/匯入資料夾/子資料夾/woow-random-4m.bin" | cut -c1-16) v=$(sha256sum "$U/woow-versioned.txt" | cut -c1-16) versions=$(find /share/nextcloud/$A/files_versions -type f 2>/dev/null | wc -l) owner=$(stat -c %u:%g "$U/woow-import-share-20261123.txt")"
echo "rows of A: calendars=$(q "select count(*) from oc_calendars where principaluri='principals/users/$A'") events=$(q "select count(*) from oc_calendarobjects o join oc_calendars c on c.id=o.calendarid where c.principaluri='principals/users/$A'") books=$(q "select count(*) from oc_addressbooks where principaluri='principals/users/$A'") cards=$(q "select count(*) from oc_cards k join oc_addressbooks b on b.id=k.addressbookid where b.principaluri='principals/users/$A'") shares=$(q "select string_agg(share_type::text, ',' order by share_type) from oc_share where uid_owner='$A'") tokens=$(q "select count(*) from oc_authtoken where uid='$A'")"
echo "after: $(counts) $(date -u +%FT%TZ)"
