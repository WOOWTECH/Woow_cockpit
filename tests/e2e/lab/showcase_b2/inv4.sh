# READ-ONLY: what is happening on the showcase right now (jobs, started apps with memory, recent Supervisor events).
set -uo pipefail
echo "== now $(date -u +%FT%TZ)"
echo "== supervisor jobs in progress"; ha jobs info --raw-json 2>/dev/null | jq -r '.data.jobs[]? | select(.done != true) | [.name, (.reference // "-"), (.progress|tostring), .stage // "-"] | @tsv' | head
echo "== started apps (slug version mem_mb)"
for s in $(ha apps list --raw-json | jq -r '(.data.addons // .data.apps)[] | select(.state=="started") | .slug'); do
  m=$(ha apps stats $s --raw-json 2>/dev/null | jq -r '(.data.memory_usage // 0)/1048576 | floor'); echo "$s $m"; done | sort -k2 -n | tail -25
echo "== supervisor log events since 06:30Z (time + app + action words only)"
ha supervisor logs 2>/dev/null | grep -E '^(\x1b\[[0-9;]*m)?2026-11-23 0[6-9]' | grep -Eio '^.{0,40}|(starting|stopping|stopped|started|backup|restore|update|install|uninstall|pull)[^,]{0,80}' | paste - - 2>/dev/null | tail -40 | cut -c1-200
