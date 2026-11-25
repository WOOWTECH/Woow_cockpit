#!/bin/bash
# usage: run-final.sh TAG   -- the verification chain of a lane iteration on the CURRENT committed tip of the lane worktree
# (/tmp/parity-read-20261125, must be clean). Every heavy step goes through heavy.sh; records: runs/TAG-<step>.{out,err,exit}.
# Steps: suite (tests/backup --b1 + RealBackupTests --ha118, on /tmp/parity-read-suite-20261125 at the tip), mut (mutation sweep on
# the copy tree), diffsmall + difflarge (old reader e7d687b against the new one on the 27 real HA backups), real_files, fuzz
# (long form), mem4m (4,000,000 and 4,000,001 entries). Nothing outside the scratchpad and the two worktrees of the lane is touched.
S=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad
P=$S/parity-read
R=$P/runs
W=/tmp/parity-read-20261125
SW=/tmp/parity-read-suite-20261125
TAG=${1:?tag}
export PYTHONDONTWRITEBYTECODE=1
LOCK=/tmp/woowbk-host-heavy-tests.lock
heavy() { HEAVY_FREE=$LOCK "$S/team/heavy.sh" flock -w 3600 $LOCK "$@"; }
tip=$(git -C "$W" rev-parse --short HEAD)
dirty=$(git -C "$W" status --porcelain --untracked-files=no | wc -l)
echo "$tip dirty=$dirty $(date +%H:%M)" > "$R/$TAG.tip"
[ "$dirty" = 0 ] || { echo "worktree not clean" >> "$R/$TAG.tip"; echo 3 > "$R/$TAG.exit"; exit 3; }
git -C "$SW" checkout -q --detach "$tip" || exit 4
"$P/refresh-mut-tree.sh" || exit 5
step() { name=$1; shift; echo "$(date +%H:%M) start $name" >> "$R/$TAG.log"; "$@" > "$R/$TAG-$name.out" 2> "$R/$TAG-$name.err"; echo $? > "$R/$TAG-$name.exit"; echo "$(date +%H:%M) end $name rc=$(cat $R/$TAG-$name.exit)" >> "$R/$TAG.log"; }
G=$S/integration-3/guard.py
cd "$SW" || exit 2
export PYTHONPATH=backup-engine:tests/e2e/lab
step b1 heavy timeout 7200 python3 "$G" --b1 --log "$R/$TAG-b1.guardlog" --discover tests/backup --top .
step ha118 heavy timeout 3600 python3 "$G" --b1 --ha118 --log "$R/$TAG-ha118.guardlog" tests.backup.test_ha_backup.RealBackupTests
cd "$W" || exit 2
unset PYTHONPATH
step mut heavy timeout 10000 python3 -I "$P/mutations.py" "$P/mut" "$R/$TAG-mut.json"
step diffsmall heavy timeout 3600 xargs -a "$R/small.txt" -d '\n' python3 "$P/differential.py" "$R/$TAG-diffsmall.json"
step difflarge heavy timeout 7200 xargs -a "$R/large.txt" -d '\n' python3 "$P/differential.py" "$R/$TAG-difflarge.json"
step realfiles heavy timeout 3600 python3 "$P/real_files.py" "$P/scratch" "$R/$TAG-realfiles.json"
export PYTHONPATH=backup-engine:tests/e2e/lab
step fuzz heavy timeout 3600 python3 "$P/long_fuzz.py" 4000
unset PYTHONPATH
step mem4m heavy timeout 3600 python3 "$P/mem4m.py" 4000000
step mem4m1 heavy timeout 3600 python3 "$P/mem4m.py" 4000001
echo done > "$R/$TAG.exit"
