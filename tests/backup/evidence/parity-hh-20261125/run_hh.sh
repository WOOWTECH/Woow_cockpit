#!/bin/bash
# parity-hh (HH-OWNER-1905): heavy groups on the lane worktree W.   run_hh.sh TAG group...
#   groups: b1 (full tests/backup through integration-3's guard.py --b1), mutH / mutS (the lane's hand mutants of ha_hermes / ha_headscale),
#           mutC (the controls), ui (node tests/backup-ui.mjs)
# Every group goes through team/heavy.sh and the host heavy-tests lock. Records: scratchpad/parity-hh/runs/TAG.*
set -u
umask 077
BASE=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad
S=$BASE/parity-hh
G=$BASE/integration-3/guard.py
HEAVY=$BASE/team/heavy.sh
W=${W:-/tmp/parity-hh-20261125}
LOCK=/tmp/woowbk-host-heavy-tests.lock
R=$S/runs
TAG=$1; shift
SUM=$R/$TAG.summary
cd "$W" || exit 2
head=$(git rev-parse --short HEAD)
dirty=$(git status --porcelain --untracked-files=no | wc -l)
echo "tag $TAG head $head dirty $dirty start $(date +%T)" > "$SUM"
heavy() { HEAVY_WAIT=${HEAVY_WAIT:-43200} HEAVY_FREE=$LOCK "$HEAVY" flock -w 3600 "$LOCK" "$@"; }
H_IDS=$(python3 -c "import runpy;print(','.join(m[0] for m in runpy.run_path('$S/muts_hh.py')['MUTS'] if m[1]=='ha_hermes.py' and not m[0].startswith('C')))")
S_IDS=$(python3 -c "import runpy;print(','.join(m[0] for m in runpy.run_path('$S/muts_hh.py')['MUTS'] if m[1]=='ha_headscale.py' and not m[0].startswith('C')))")
C_IDS=$(python3 -c "import runpy;print(','.join(m[0] for m in runpy.run_path('$S/muts_hh.py')['MUTS'] if m[0].startswith('C')))")
for name in "$@"; do
  t0=$SECONDS
  case $name in
    b1)
      heavy env PYTHONPATH=backup-engine:tests/e2e/lab PYTHONDONTWRITEBYTECODE=1 timeout 10800 \
        python3 "$G" --b1 --log "$R/$TAG-b1.guardlog" --discover tests/backup --top . > "$R/$TAG-b1.out" 2> "$R/$TAG-b1.err"
      rc=$?; line=$(head -1 "$R/$TAG-b1.out" | cut -c1-300) ;;
    mutH|mutS|mutC)
      case $name in mutH) ids=$H_IDS;; mutS) ids=$S_IDS;; mutC) ids=$C_IDS;; esac
      heavy env PYTHONDONTWRITEBYTECODE=1 timeout 21600 python3 -I "$S/hm_hh.py" --repo "$W" --muts "$S/muts_hh.py" --only "$ids" \
        --out "$R/$TAG-$name.json" > "$R/$TAG-$name.out" 2> "$R/$TAG-$name.err"
      rc=$?; line=$(tail -1 "$R/$TAG-$name.out" | cut -c1-300) ;;
    ui)
      heavy env PYTHONDONTWRITEBYTECODE=1 timeout 7200 node tests/backup-ui.mjs > "$R/$TAG-ui.out" 2> "$R/$TAG-ui.err"
      rc=$?; line=$(tail -1 "$R/$TAG-ui.out" | cut -c1-300) ;;
    *) rc=2; line="unknown group" ;;
  esac
  echo "step $name rc=$rc seconds=$((SECONDS-t0)) $line" >> "$SUM"
done
echo "end $(date +%T) head-after $(git rev-parse --short HEAD) dirty $(git status --porcelain --untracked-files=no | wc -l)" >> "$SUM"
echo done > "$R/$TAG.exit"
