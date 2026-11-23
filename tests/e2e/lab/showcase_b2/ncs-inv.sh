# Nextcloud + share folder READ-ONLY facts (bash -s on the showcase HA) before/after the share-including backup:
# add-on state and health, users, row counts, /share sizes and special entries, /backup free space, this project's
# backups, and per-user file-manifest digests (counts, bytes, one sha256 per user; no file names, no secret values).
# Manifest digest of a directory D: cd D; find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum | sha256sum
set -uo pipefail
S=1b7b4ce7_woow-nextcloud-office; C=app_$S; H=1b7b4ce7-woow-nextcloud-office
occ() { docker exec -u www-data $C php /var/www/nextcloud/occ "$@"; }
q() { docker exec -u postgres $C psql -h /run/postgresql -d nextcloud -Atc "$1" 2>&1 | head -1; }
mf() { ( cd "$1" 2>/dev/null || { echo "absent"; exit 0; }
          n=$(find . -type f | wc -l); b=$(find . -type f -exec stat -c %s {} + 2>/dev/null | awk '{s+=$1} END {print s+0}')
          d=$(find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum | sha256sum | cut -c1-64)
          echo "files=$n bytes=$b digest=$d" ); }
echo "now $(date -u +%FT%TZ)"
echo "state: $(ha apps info $S --raw-json | jq -r '.data | "\(.version) \(.state) boot=\(.boot)"')"
echo "health: healthz=$(curl -s -o /dev/null -w '%{http_code}' -m 10 http://$H:8090/healthz) status=$(curl -s -m 10 http://$H:8000/status.php | jq -c '{installed, versionstring, maintenance, needsDbUpgrade}')"
echo "users: $(occ user:list --output=json 2>/dev/null | jq -r 'length') names=$(occ user:list --output=json 2>/dev/null | jq -r 'keys|join(",")' | cut -c1-160)"
for t in oc_users oc_filecache oc_share oc_authtoken oc_calendars oc_calendarobjects oc_addressbooks oc_cards oc_storages oc_mounts; do printf '%s ' "$t=$(q "select count(*) from $t")"; done; echo
echo "share: bytes=$(du -sb /share | cut -f1) entries=$(find /share -xdev | wc -l) dirs=$(find /share -xdev -type d | wc -l) files=$(find /share -xdev -type f | wc -l) symlinks=$(find /share -xdev -type l | wc -l) devices=$(find /share -xdev \( -type b -o -type c \) | wc -l) fifos=$(find /share -xdev -type p | wc -l) sockets=$(find /share -xdev -type s | wc -l) hardlinked=$(find /share -xdev -type f -links +1 | wc -l) mounts_below=$(awk '$2 ~ "^/share/" {n++} END {print n+0}' /proc/mounts)"
echo "share top level: $(ls -1A /share | wc -l) entries; largest 6:"; du -sb /share/* /share/.[!.]* 2>/dev/null | sort -rn | head -6 | while read -r b d; do echo "  $(basename "$d")=$b"; done
echo "datadir: $(du -sb /share/nextcloud | cut -f1) B, top: $(ls -1A /share/nextcloud | wc -l) entries, .ncdata=$([ -f /share/nextcloud/.ncdata ] && echo yes || echo no)"
for u in $(ls -1 /share/nextcloud); do [ -d "/share/nextcloud/$u/files" ] && echo "user $u files: $(mf "/share/nextcloud/$u/files") versions=$(find "/share/nextcloud/$u/files_versions" -type f 2>/dev/null | wc -l) trash=$(find "/share/nextcloud/$u/files_trashbin" -type f 2>/dev/null | wc -l)"; done
echo "projects (code-server workspace): $(mf /share/projects)"
echo "backup dir: $(df -B1 -P /backup | awk 'NR==2 {print $4}') B free of $(df -B1 -P /backup | awk 'NR==2 {print $2}'); backups=$(ha backups list --raw-json | jq -r '.data.backups | length')"
ha backups list --raw-json | jq -r '.data.backups[] | select(.name | startswith("WOOW匯入測試 B2")) | "\(.slug) \(.name) \(.size)"'
