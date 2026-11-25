#!/bin/bash
# parity-odoo (OD-OWNER-1735): heavy groups on a throw-away detached worktree W.   run.sh TAG group...
#   groups: b1 (full tests/backup through integration-3's guard.py --b1), ha118 (RealBackupTests), mut (this lane's mutation sweep)
# Every group goes through team/heavy.sh and the host heavy-tests lock. Records: scratchpad/parity-odoo/runs/TAG.* (0600).
set -u
umask 077
BASE=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad
S=$BASE/parity-odoo
G=$BASE/integration-3/guard.py
HEAVY=$BASE/team/heavy.sh
W=${W:-/tmp/parity-odoo-verify-20261125}
LOCK=/tmp/woowbk-host-heavy-tests.lock
R=$S/runs
TAG=$1; shift
SUM=$R/$TAG.summary
cd "$W" || exit 2
head=$(git rev-parse --short HEAD)
dirty=$(git status --porcelain --untracked-files=no | wc -l)
echo "tag $TAG head $head dirty $dirty start $(date +%T)" > "$SUM"
heavy() { HEAVY_FREE=$LOCK "$HEAVY" flock -w 3600 "$LOCK" "$@"; }
for name in "$@"; do
  t0=$SECONDS
  case $name in
    b1)
      heavy env PYTHONPATH=backup-engine:tests/e2e/lab PYTHONDONTWRITEBYTECODE=1 timeout 7200 \
        python3 "$G" --b1 --log "$R/$TAG-b1.guardlog" --discover tests/backup --top . > "$R/$TAG-b1.out" 2> "$R/$TAG-b1.err"
      rc=$?; line=$(head -1 "$R/$TAG-b1.out" | cut -c1-300) ;;
    ha118)
      heavy env PYTHONPATH=backup-engine:tests/e2e/lab PYTHONDONTWRITEBYTECODE=1 timeout 3600 \
        python3 "$G" --b1 --ha118 --log "$R/$TAG-ha118.guardlog" tests.backup.test_ha_backup.RealBackupTests \
        > "$R/$TAG-ha118.out" 2> "$R/$TAG-ha118.err"
      rc=$?; line=$(head -1 "$R/$TAG-ha118.out" | cut -c1-300) ;;
    mut)
      heavy env PYTHONDONTWRITEBYTECODE=1 timeout 10800 python3 -I "$S/mutations.py" --repo "$W" --jobs 2 \
        --json "$R/$TAG-mut.json" > "$R/$TAG-mut.out" 2> "$R/$TAG-mut.err"
      rc=$?; line=$(tail -1 "$R/$TAG-mut.out" | cut -c1-300) ;;
    *) rc=2; line="unknown group" ;;
  esac
  echo "step $name rc=$rc seconds=$((SECONDS-t0)) $line" >> "$SUM"
done
echo "end $(date +%T) head-after $(git rev-parse --short HEAD) dirty $(git status --porcelain --untracked-files=no | wc -l)" >> "$SUM"
echo done > "$R/$TAG.exit"
