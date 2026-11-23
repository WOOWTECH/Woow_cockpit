export S=1b7b4ce7_woow-nextcloud-office F=woow-b2-nextcloud-x86-enc-noshare-20261123 N="WOOW匯入測試 B2 Nextcloud x86 加密 無share 2026-11-23"
# One ENCRYPTED partial HA backup of one add-on (bash -s on the showcase HA). Needs exported S (slug), F (file base name),
# N (backup display name), optional FOLDERS (comma list) and HEALTH (a shell command that prints an HTTP code; run after).
# The encryption key HA_BACKUP_KEY comes from the lab test creds as an env var and goes to the Supervisor API through jq env.
set -uo pipefail
api() { curl -sS -m 3600 -H "Authorization: Bearer $SUPERVISOR_TOKEN" -H "Content-Type: application/json" "$@"; }
st() { ha apps info $S --raw-json | jq -r '.data | "\(.version) \(.state)"'; }
[ -n "${HA_BACKUP_KEY:-}" ] || { echo "STOP: HA_BACKUP_KEY missing"; exit 1; }
echo "add-on before: $(st) $(date -u +%FT%TZ)"
t0=$(date +%s)
R=$(jq -n --arg name "$N" --arg s "$S" --arg f "$F" --arg folders "${FOLDERS:-}" \
     '{name:$name, addons:[$s], password: env.HA_BACKUP_KEY, compressed:true, filename:($f + ".tar")}
      + (if $folders == "" then {} else {folders: ($folders | split(","))} end)' \
     | api -X POST -d @- http://supervisor/backups/new/partial)
echo "backup: result=$(printf '%s' "$R" | jq -r '.result') slug=$(printf '%s' "$R" | jq -r '.data.slug // "-"') msg=$(printf '%s' "$R" | jq -r '.message // ""' | cut -c1-160) elapsed=$(( $(date +%s) - t0 ))s"
B=$(printf '%s' "$R" | jq -r '.data.slug // empty')
P=/backup/$F.tar
[ -f "$P" ] && { echo "file: $P $(stat -c %s "$P") bytes"; sha256sum "$P"; } || ls -t /backup | head -3
[ -n "$B" ] && ha backups info $B --raw-json | jq -c '.data | {slug, name, date, size, protected, compressed, homeassistant, apps: [(.addons // .apps)[]? | {slug, version, size}], folders}' | cut -c1-290
tar -tvf "$P" 2>/dev/null | awk '{print $3, $6}'
echo "add-on right after backup: $(st) $(date -u +%FT%TZ)"
C=app_$S; U=woow-import-test
h=000; for i in $(seq 1 100); do h=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://1b7b4ce7-woow-nextcloud-office:8090/healthz); [ "$h" = 200 ] && break; sleep 5; done
echo "after backup: $(st) healthz=$h status=$(curl -s -m 10 http://1b7b4ce7-woow-nextcloud-office:8000/status.php | jq -c '{installed, versionstring, maintenance, needsDbUpgrade}') $(date -u +%FT%TZ)"
echo "test user still there: $(docker exec -u www-data $C php /var/www/nextcloud/occ user:info $U --output=json 2>/dev/null | jq -r '.user_id // "no"')"
