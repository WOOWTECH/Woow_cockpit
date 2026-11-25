#!/bin/bash
# usage: run-it3.sh TAG   -- the verification chain of iteration 3 on the CURRENT committed tip of the lane worktree (/tmp/parity-read-20261125, must
# be clean). Like run-final.sh, plus: the five lane modules (units), the encryption kinds of the real members, job_level.py on the throw-away merge
# of the integrated BASE (1dc9108) and this branch, the full suite on that merge, and the ad-hoc checks. The mutation sweep is run-it3-mut.sh (same TAG). Every heavy step goes through heavy.sh;
# records runs/TAG-<step>.{out,err,exit}, runs/TAG.log, runs/TAG.exit (= done at the end). Nothing outside the scratchpad and the lane's worktrees is touched.
S=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad
P=$S/parity-read
R=$P/runs
W=/tmp/parity-read-20261125
SW=/tmp/parity-read-suite-20261125
M=/tmp/parity-read-merge3-20261125
BASE=1dc9108
TAG=${1:?tag}
export PYTHONDONTWRITEBYTECODE=1
LOCK=/tmp/woowbk-host-heavy-tests.lock
heavy() { HEAVY_FREE=$LOCK "$S/team/heavy.sh" flock -w 3600 $LOCK "$@"; }
tip=$(git -C "$W" rev-parse --short HEAD)
dirty=$(git -C "$W" status --porcelain --untracked-files=no | wc -l)
echo "$tip dirty=$dirty $(date +%H:%M)" > "$R/$TAG.tip"
[ "$dirty" = 0 ] || { echo "worktree not clean" >> "$R/$TAG.tip"; echo 3 > "$R/$TAG.exit"; exit 3; }
rm -f "$R/$TAG.exit" "$R/$TAG.log"
[ "$(cut -d" " -f1 "$R/$TAG-mut.tip" 2>/dev/null)" = "$tip" ] || echo "NOTE: the mutation sweep of this tag ran on another tip ($(cut -d" " -f1 "$R/$TAG-mut.tip" 2>/dev/null))" >> "$R/$TAG.log"
git -C "$SW" checkout -q --detach "$tip" || exit 4
git -C "$M" checkout -q --detach "$BASE" || exit 6
git -C "$M" merge -q --no-edit "$tip" > "$R/$TAG-merge.log" 2>&1 || exit 7
echo "$(git -C "$M" rev-parse --short HEAD) clean=$(git -C "$M" status --porcelain --untracked-files=no | wc -l)" > "$R/$TAG-merge.head"
step() { name=$1; shift; echo "$(date +%H:%M) start $name" >> "$R/$TAG.log"; "$@" > "$R/$TAG-$name.out" 2> "$R/$TAG-$name.err"; echo $? > "$R/$TAG-$name.exit"; echo "$(date +%H:%M) end $name rc=$(cat $R/$TAG-$name.exit)" >> "$R/$TAG.log"; }
G=$S/integration-3/guard.py
cd "$W" || exit 2
export PYTHONPATH=backup-engine:tests/e2e/lab
step units python3 -m unittest tests.backup.test_ha_backup tests.backup.test_ha_securetar tests.backup.test_ha_store tests.backup.test_ha_links tests.backup.test_storage
unset PYTHONPATH
step kinds python3 -I "$P/member_kinds.py" "$R/all27.txt"
step job_level python3 -I "$P/job_level.py" "$M"
heavy timeout 14400 "$P/run-it3-group.sh" "$TAG" suites
heavy timeout 14400 "$P/run-it3-group.sh" "$TAG" reader
echo done > "$R/$TAG.exit"
