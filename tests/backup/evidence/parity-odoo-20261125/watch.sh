#!/bin/bash
# parity-odoo (OD-OWNER-1735): waits until the host is quiet enough for a heavy step (main's rules of 2026-11-25 19:0x and 19:55):
# at most 6 heavy.sh processes waiting AND the 5-minute load average below 20, seen twice two minutes apart; then run.sh TAG groups...
#   watch.sh TAG group...        (W=<verify worktree> as for run.sh; JOBS=1 is the default of the sweep)
BASE=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad
quiet() {
  local load5
  load5=$(awk '{print int($2)}' /proc/loadavg)
  [ "$(ps -eo args | grep -c '[h]eavy.sh')" -le 6 ] && [ "$load5" -lt 20 ]
}
ok=0
while [ "$ok" -lt 2 ]; do
  if quiet; then ok=$((ok+1)); else ok=0; fi
  [ "$ok" -lt 2 ] && sleep 120
done
echo "watch.sh: quiet at $(date +%T) load $(cut -d' ' -f1-3 /proc/loadavg), starting run.sh $*"
exec "$BASE/parity-odoo/run.sh" "$@"
