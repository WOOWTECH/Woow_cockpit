#!/bin/bash
# usage: run-it3-mut.sh TAG   -- the ONE mutation sweep of iteration 3 (the whole list of mutations.py, one run) on the CURRENT committed tip of the lane
# worktree (/tmp/parity-read-20261125, must be clean): the tree scratchpad/parity-read/mut is refreshed from it, the sweep runs through heavy.sh.
# Records runs/TAG-mut.{json,out,err,exit,tip}. (run-it3.sh runs the other steps of the chain; it checks that the tip is still the same.)
S=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad
P=$S/parity-read
R=$P/runs
W=/tmp/parity-read-20261125
TAG=${1:?tag}
export PYTHONDONTWRITEBYTECODE=1
LOCK=/tmp/woowbk-host-heavy-tests.lock
tip=$(git -C "$W" rev-parse --short HEAD)
dirty=$(git -C "$W" status --porcelain --untracked-files=no | wc -l)
echo "$tip dirty=$dirty $(date +%H:%M)" > "$R/$TAG-mut.tip"
[ "$dirty" = 0 ] || { echo "worktree not clean" >> "$R/$TAG-mut.tip"; echo 3 > "$R/$TAG-mut.exit"; exit 3; }
rm -f "$R/$TAG-mut.exit"
"$P/refresh-mut-tree.sh" || { echo 5 > "$R/$TAG-mut.exit"; exit 5; }
cd "$W" || exit 2
HEAVY_FREE=$LOCK "$S/team/heavy.sh" flock -w 3600 $LOCK timeout 10000 python3 -I "$P/mutations.py" "$P/mut" "$R/$TAG-mut.json" > "$R/$TAG-mut.out" 2> "$R/$TAG-mut.err"
echo $? > "$R/$TAG-mut.exit"
