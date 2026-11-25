#!/bin/bash
# usage: run-merge.sh TAG  -- full tests/backup --b1 (integration-3 guard) on the throwaway trial merge of F1 + READ + READ's snippets
# (/tmp/parity-read-merge2-20261125: detached, uncommitted patches applied; never pushed). Through heavy.sh. Records runs/TAG-merge-b1.*
S=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad
R=$S/parity-read/runs
TAG=${1:?tag}
M=/tmp/parity-read-merge2-20261125
LOCK=/tmp/woowbk-host-heavy-tests.lock
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:tests/e2e/lab
cd "$M" || exit 2
git rev-parse --short HEAD > "$R/$TAG-merge.head"
git status --porcelain --untracked-files=no | wc -l >> "$R/$TAG-merge.head"
HEAVY_FREE=$LOCK "$S/team/heavy.sh" flock -w 3600 $LOCK timeout 7200 python3 "$S/integration-3/guard.py" --b1 --log "$R/$TAG-merge-b1.guardlog" --discover tests/backup --top . > "$R/$TAG-merge-b1.out" 2> "$R/$TAG-merge-b1.err"
echo $? > "$R/$TAG-merge-b1.exit"
