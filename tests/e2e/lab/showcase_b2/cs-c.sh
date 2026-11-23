# code-server step C: remove ONLY this lane's two markers, then stop the add-on again (it was paused before, 07:07Z).
set -uo pipefail
S=1b7b4ce7_woow_ha_code_server; C=app_$S; M=woow-import-test-20261123
st() { ha apps info $S --raw-json | jq -r '.data | "\(.version) \(.state) boot=\(.boot)"'; }
docker exec -e SNIP_NEW="${SNIP_NEW:-0}" $C sh -c "rm -f /data/vscode/User/snippets/$M.code-snippets; rm -rf /data/pi-agent/skills/$M; [ \"\${SNIP_NEW:-}\" = 1 ] && rmdir /data/vscode/User/snippets 2>/dev/null; true"
echo "markers left: $(docker exec $C sh -c "ls -d /data/vscode/User/snippets/$M.code-snippets /data/pi-agent/skills/$M 2>/dev/null | wc -l") skills=$(docker exec $C sh -c 'ls -1 /data/pi-agent/skills 2>/dev/null | wc -l')"
ha apps stop $S --no-progress 2>&1 | tail -1
echo "after stop: $(st) $(date -u +%FT%TZ)"
