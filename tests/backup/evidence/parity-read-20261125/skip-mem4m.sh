#!/bin/bash
# Stops the two 4,000,000-entry steps of the it3b chain as soon as they start (the walk and the names table are unchanged in iteration 3: the heavy-step
# economy note of 19:0x asks not to repeat what the change cannot affect). Kills only python3 processes of mem4m.py started by this lane's chain.
R=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/parity-read/runs
end=$((SECONDS + 14400))
while [ $SECONDS -lt $end ]; do
  for pid in $(pgrep -f '[m]em4m.py 400000'); do
    if grep -q 'parity-read' "/proc/$pid/cmdline" 2>/dev/null && ! grep -q 'bash' "/proc/$pid/cmdline" 2>/dev/null; then kill "$pid" && echo "$(date +%H:%M) killed $pid" >> "$R/it3b-skip-mem4m.log"; fi
  done
  [ -f "$R/it3b.exit" ] && break
  sleep 5
done
