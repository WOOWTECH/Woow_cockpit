# OpenDesign step C (bash -s on the showcase HA): remove ONLY the test project this lane created, then put the add-on back
# in the stopped state it had before (it was paused by someone else at 07:07Z: backup "hm19b-pause-apps-202611231507").
set -uo pipefail
S=1b7b4ce7_woow_ha_opendesign; C=app_$S; PID=woow-import-test-20261123
st() { ha apps info $S --raw-json | jq -r '.data | "\(.version) \(.state) boot=\(.boot)"'; }
echo "before cleanup: $(st) projects=$(docker exec $C curl -s -m 30 http://127.0.0.1:7456/api/projects | jq -r '(.projects // .) | length')"
echo "delete marker: http=$(docker exec $C curl -s -o /dev/null -w '%{http_code}' -m 60 -X DELETE http://127.0.0.1:7456/api/projects/$PID)"
echo "marker now: http=$(docker exec $C curl -s -o /dev/null -w '%{http_code}' -m 10 http://127.0.0.1:7456/api/projects/$PID) dir=$(docker exec $C sh -c "[ -e /data/opendesign/projects/$PID ] && echo present || echo absent") projects=$(docker exec $C curl -s -m 30 http://127.0.0.1:7456/api/projects | jq -r '(.projects // .) | length')"
ha apps stop $S --no-progress 2>&1 | tail -1
echo "after stop: $(st) $(date -u +%FT%TZ)"
