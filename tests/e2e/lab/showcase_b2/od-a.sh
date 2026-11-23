# OpenDesign step A (bash -s on the showcase HA): start the paused add-on, wait healthy, counts, create the test marker.
# Marker = project id woow-import-test-20261123 (name "WOOW匯入測試 20261123") with two small text files. No secrets involved.
set -uo pipefail
S=1b7b4ce7_woow_ha_opendesign; C=app_$S; PID=woow-import-test-20261123
st() { ha apps info $S --raw-json | jq -r '.data | "\(.version) \(.state) boot=\(.boot)"'; }
x() { docker exec $C "$@"; }
echo "before: $(st) $(date -u +%FT%TZ)"
if [ "$(ha apps info $S --raw-json | jq -r .data.state)" != started ]; then ha apps start $S --no-progress 2>&1 | tail -1; fi
h=000; for i in $(seq 1 60); do h=$(x curl -s -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1:7456/api/health 2>/dev/null); [ "$h" = 200 ] && break; sleep 5; done
echo "after start: $(st) health=$h $(date -u +%FT%TZ)"
[ "$h" = 200 ] || { echo "STOP: not healthy"; exit 1; }
echo "tools: $(x sh -c 'for t in curl sqlite3 node jq; do command -v $t >/dev/null && printf "%s " $t; done')"
echo "version: $(x curl -s -m 10 http://127.0.0.1:7456/api/version | jq -c '{version, appVersion: (.appVersion // .app_version // null)}' 2>/dev/null | cut -c1-120)"
echo "projects before: $(x curl -s -m 30 http://127.0.0.1:7456/api/projects | jq -r '(.projects // .) | length')"
echo "data sizes:"; x sh -c 'du -sh /data/opendesign /data/opendesign/projects /data/opendesign/home /data/mcp 2>/dev/null; ls -la /data/opendesign/app.sqlite* 2>/dev/null | awk "{print \$5, \$NF}"'
R=$(x curl -s -m 30 -H 'content-type: application/json' -d "$(jq -cn --arg id $PID '{id:$id, name:"WOOW匯入測試 20261123"}')" http://127.0.0.1:7456/api/projects)
echo "create: $(printf '%s' "$R" | jq -c '{id: (.project.id // .id // null), name: (.project.name // .name // null), error: (.error // null)}' 2>/dev/null | cut -c1-200)"
x sh -c "printf 'WOOW import marker 2026-11-23 OpenDesign x86\n' > /tmp/woow-import-test.txt; printf '匯入測試 標記檔 2026-11-23\n' > /tmp/woow-import-cjk.txt"
for f in woow-import-test.txt woow-import-cjk.txt; do
  echo "upload $f: $(x curl -s -m 30 -F file=@/tmp/$f http://127.0.0.1:7456/api/projects/$PID/files | jq -c '{name: (.file.name // .name // null), size: (.file.size // .size // null), error: (.error // null)}' 2>/dev/null | cut -c1-160)"
done
echo "marker sha256 (in container /tmp): $(x sh -c 'sha256sum /tmp/woow-import-test.txt /tmp/woow-import-cjk.txt' | awk '{print substr($1,1,16)}' | tr '\n' ' ')"
echo "files in project: $(x curl -s -m 30 http://127.0.0.1:7456/api/projects/$PID/files | jq -c '[(.files // .)[] | .name] | sort' 2>/dev/null | cut -c1-200)"
echo "on disk: $(x sh -c "ls /data/opendesign/projects/$PID 2>/dev/null | tr '\n' ' '; sha256sum /data/opendesign/projects/$PID/*.txt 2>/dev/null | awk '{print substr(\$1,1,16)}' | tr '\n' ' '")"
echo "projects after marker: $(x curl -s -m 30 http://127.0.0.1:7456/api/projects | jq -r '(.projects // .) | length')"
x rm -f /tmp/woow-import-test.txt /tmp/woow-import-cjk.txt
echo "end: $(st) $(date -u +%FT%TZ)"
