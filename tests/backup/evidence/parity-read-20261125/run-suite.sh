#!/bin/bash
# full tests/backup through integration-3's guard (--b1), then RealBackupTests (--ha118), on the clean suite worktree
S=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad
G=$S/integration-3/guard.py
W=/tmp/parity-read-suite-20261125
R=$S/parity-read/runs
TAG=${1:-suite1}
umask 022
cd "$W" || exit 2
git rev-parse --short HEAD > "$R/$TAG.head"
git status --porcelain --untracked-files=no | wc -l >> "$R/$TAG.head"
export PYTHONPATH=backup-engine:tests/e2e/lab PYTHONDONTWRITEBYTECODE=1
HEAVY_FREE=/tmp/woowbk-host-heavy-tests.lock "$S/team/heavy.sh" flock -w 3600 /tmp/woowbk-host-heavy-tests.lock \
  timeout 7200 python3 "$G" --b1 --log "$R/$TAG-b1.guardlog" --discover tests/backup --top . > "$R/$TAG-b1.out" 2> "$R/$TAG-b1.err"
echo "b1 rc=$?" > "$R/$TAG.summary"
grep -m1 '^tests=' "$R/$TAG-b1.out" >> "$R/$TAG.summary"
HEAVY_FREE=/tmp/woowbk-host-heavy-tests.lock "$S/team/heavy.sh" flock -w 3600 /tmp/woowbk-host-heavy-tests.lock \
  timeout 3600 python3 "$G" --b1 --ha118 --log "$R/$TAG-ha118.guardlog" tests.backup.test_ha_backup.RealBackupTests > "$R/$TAG-ha118.out" 2> "$R/$TAG-ha118.err"
echo "ha118 rc=$?" >> "$R/$TAG.summary"
grep -m1 '^tests=' "$R/$TAG-ha118.out" >> "$R/$TAG.summary"
echo done > "$R/$TAG.exit"
