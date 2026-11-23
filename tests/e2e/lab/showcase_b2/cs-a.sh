# code-server step A (bash -s on the showcase HA): start the paused add-on, wait healthy, counts, create the test markers
# (a VS Code user snippet and a shared agent skill in /data; no secrets). The workspace (/share/projects) is NOT in an
# add-on-only backup, so no workspace marker is made (the share folder decision belongs to the owner).
set -uo pipefail
S=1b7b4ce7_woow_ha_code_server; C=app_$S; M=woow-import-test-20261123
st() { ha apps info $S --raw-json | jq -r '.data | "\(.version) \(.state) boot=\(.boot)"'; }
x() { docker exec $C "$@"; }
echo "before: $(st) $(date -u +%FT%TZ)"
if [ "$(ha apps info $S --raw-json | jq -r .data.state)" != started ]; then ha apps start $S --no-progress 2>&1 | tail -1; fi
h=000; for i in $(seq 1 100); do h=$(x curl -s -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1:1337/healthz 2>/dev/null); [ "$h" = 200 ] && break; sleep 5; done
echo "after start: $(st) healthz=$h $(date -u +%FT%TZ)"
[ "$h" = 200 ] || { echo "STOP: not healthy"; exit 1; }
echo "code-server: $(x code-server --version 2>/dev/null | head -1 | cut -c1-80)"
echo "image: $(docker inspect -f '{{.Config.Image}}' $C)"
for d in /data /data/vscode /data/vscode/extensions /data/pi-agent /data/pi-agent/sessions /data/pi-agent/claude /data/pi-agent/codex /data/pi-agent/connectors; do
  printf '%s ' "$d=$(x du -sh $d 2>/dev/null | cut -f1)"; done; echo
echo "counts: extensions=$(x sh -c 'ls -1 /data/vscode/extensions 2>/dev/null | grep -v "^\." | grep -vx extensions.json | wc -l')" \
     "pi_sessions=$(x sh -c 'find /data/pi-agent/sessions -type f -name "*.jsonl" 2>/dev/null | wc -l')" \
     "skills=$(x sh -c 'ls -1 /data/pi-agent/skills 2>/dev/null | wc -l')" \
     "snippets_dir=$(x sh -c '[ -d /data/vscode/User/snippets ] && echo existed || echo new')" \
     "skills_dir=$(x sh -c '[ -d /data/pi-agent/skills ] && echo existed || echo new')"
x sh -c "mkdir -p /data/vscode/User/snippets /data/pi-agent/skills/$M
cat > /data/vscode/User/snippets/$M.code-snippets <<'J'
{
  \"WOOW import test 2026-11-23\": {
    \"prefix\": \"woowimporttest\",
    \"body\": [\"WOOW import marker 2026-11-23 code-server x86 匯入測試\"],
    \"description\": \"HA to Podman import test marker, delete after the test\"
  }
}
J
cat > /data/pi-agent/skills/$M/SKILL.md <<'K'
---
name: woow-import-test-20261123
description: HA to Podman import test marker (2026-11-23). Not a real skill; delete after the test.
---
# WOOW 匯入測試標記 2026-11-23

This skill only marks the code-server HA to Podman import test.
K"
echo "markers: $(x sh -c "sha256sum /data/vscode/User/snippets/$M.code-snippets /data/pi-agent/skills/$M/SKILL.md" | awk '{print substr($1,1,16), $2}' | tr '\n' ' ')"
echo "end: $(st) $(date -u +%FT%TZ)"
