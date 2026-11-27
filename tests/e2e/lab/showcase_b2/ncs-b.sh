# Nextcloud-with-share step B (bash -s on the showcase HA): ONE encrypted partial HA backup of the Nextcloud add-on PLUS
# the share folder through the Supervisor API (background job), key HA_BACKUP_KEY from the lab test creds via jq env.
# Polls the job stage and the add-on state every 2 s (timestamps of every change = the downtime evidence), waits until
# Nextcloud is healthy again, prints the file's size and sha256 on the showcase, the member list, and the per-user
# file-manifest digests before and after the backup (same method as ncs-inv.sh). Names, codes, counts and hashes only.
set -uo pipefail
S=1b7b4ce7_woow-nextcloud-office; C=app_$S; H=1b7b4ce7-woow-nextcloud-office
F=${F:-woow-b2-nextcloud-x86-enc-share-20261123}; N=${N:-"WOOW匯入測試 B2 Nextcloud x86 加密 含share 2026-11-23"}
api() { curl -sS -m 120 -H "Authorization: Bearer $SUPERVISOR_TOKEN" -H "Content-Type: application/json" "$@"; }
occ() { docker exec -u www-data $C php /var/www/nextcloud/occ "$@"; }
mf() { ( cd "$1" 2>/dev/null || { echo "absent"; exit 0; }
         n=$(find . -type f | wc -l); b=$(find . -type f -exec stat -c %s {} + 2>/dev/null | awk '{s+=$1} END {print s+0}')
         d=$(find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum | sha256sum | cut -c1-64)
         echo "files=$n bytes=$b digest=$d" ); }
manifests() { for u in $(ls -1 /share/nextcloud); do [ -d "/share/nextcloud/$u/files" ] && echo "$1 user $u: $(mf "/share/nextcloud/$u/files") versions=$(find "/share/nextcloud/$u/files_versions" -type f 2>/dev/null | wc -l) trash=$(find "/share/nextcloud/$u/files_trashbin" -type f 2>/dev/null | wc -l)"; done
              echo "$1 projects: $(mf /share/projects)"
              echo "$1 share: bytes=$(du -sb /share | cut -f1) entries=$(find /share -xdev | wc -l) files=$(find /share -xdev -type f | wc -l) dirs=$(find /share -xdev -type d | wc -l) symlinks=$(find /share -xdev -type l | wc -l)"; }
st() { api http://supervisor/addons/$S/info | jq -r '.data.state'; }
[ -n "${HA_BACKUP_KEY:-}" ] || { echo "STOP: HA_BACKUP_KEY missing"; exit 1; }
[ -e "/backup/$F.tar" ] && { echo "STOP: /backup/$F.tar already exists"; exit 1; }
free=$(df -B1 -P /backup | awk 'NR==2 {print $4}'); need=$(( $(du -sb /share | cut -f1) * 2 + 2147483648 ))
echo "backup dir free=$free B need=$need B"; [ "$free" -ge "$need" ] || { echo "STOP: showcase /backup too small"; exit 1; }
h=$(curl -s -o /dev/null -w '%{http_code}' -m 10 http://$H:8090/healthz)
echo "before: $(st) healthz=$h users=$(occ user:list --output=json 2>/dev/null | jq -r 'keys|join(",")') $(date -u +%FT%TZ)"
[ "$h" = 200 ] || { echo "STOP: Nextcloud not healthy before the backup"; exit 1; }
manifests before
t0=$(date +%s)
R=$(jq -n --arg name "$N" --arg s "$S" --arg f "$F" \
     '{name:$name, addons:[$s], folders:["share"], password: env.HA_BACKUP_KEY, compressed:true, filename:($f + ".tar"), background:true}' \
     | api -X POST -d @- http://supervisor/backups/new/partial)
echo "request: result=$(printf '%s' "$R" | jq -r '.result') job=$(printf '%s' "$R" | jq -r '.data.job_id // "-"') slug=$(printf '%s' "$R" | jq -r '.data.slug // "-"') msg=$(printf '%s' "$R" | jq -r '.message // ""' | cut -c1-160)"
JOB=$(printf '%s' "$R" | jq -r '.data.job_id // empty'); SLUG=$(printf '%s' "$R" | jq -r '.data.slug // empty')
last=""; down_at=""; up_at=""
while [ -n "$JOB" ]; do
  J=$(api http://supervisor/jobs/$JOB); s=$(st)
  line="stage=$(printf '%s' "$J" | jq -r '.data.stage // "-"') done=$(printf '%s' "$J" | jq -r '.data.done') addon=$s"
  [ "$line" != "$last" ] && { echo "t+$(( $(date +%s) - t0 ))s $line"; last=$line; }
  [ "$s" != started ] && [ -z "$down_at" ] && down_at=$(date +%s)
  [ -n "$down_at" ] && [ -z "$up_at" ] && [ "$s" = started ] && up_at=$(date +%s)
  if [ "$(printf '%s' "$J" | jq -r '.data.done')" = true ]; then
    SLUG=$(printf '%s' "$J" | jq -r '.data.reference // empty')
    echo "job errors: $(printf '%s' "$J" | jq -c '[.data.errors[]? | (.message // . | tostring)[0:160]]')"; break; fi
  [ $(( $(date +%s) - t0 )) -gt 3300 ] && { echo "STOP: backup job still running after 3300 s"; break; }
  sleep 2
done
echo "backup: slug=${SLUG:--} elapsed=$(( $(date +%s) - t0 ))s addon_down_at=+$([ -n "$down_at" ] && echo $(( down_at - t0 )) || echo -)s addon_started_again_at=+$([ -n "$up_at" ] && echo $(( up_at - t0 )) || echo -)s"
h=000; for i in $(seq 1 120); do h=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://$H:8090/healthz); [ "$h" = 200 ] && break; sleep 5; done
echo "healthy again: healthz=$h at +$(( $(date +%s) - t0 ))s status=$(curl -s -m 10 http://$H:8000/status.php | jq -c '{installed, versionstring, maintenance, needsDbUpgrade}') addon=$(st) $(date -u +%FT%TZ)"
P=/backup/$F.tar
if [ -f "$P" ]; then echo "file: $P $(stat -c %s "$P") bytes"; sha256sum "$P"; else echo "file missing"; ls -t /backup | head -3; fi
[ -n "$SLUG" ] && ha backups info $SLUG --raw-json | jq -c '.data | {slug, name, date, size, protected, compressed, homeassistant, apps: [(.addons // .apps)[]? | {slug, version, size}], folders}' | cut -c1-290
tar -tvf "$P" 2>/dev/null | awk '{print $3, $6}'
manifests after
echo "users after: $(occ user:list --output=json 2>/dev/null | jq -r 'keys|join(",")') backup dir free=$(df -B1 -P /backup | awk 'NR==2 {print $4}') B"
