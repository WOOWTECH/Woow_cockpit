#!/bin/bash
# usage: run-suite-tip.sh TAG -- the suite worktree to the committed tip of the lane worktree (must be clean), then run-suite.sh TAG
# (tests/backup --b1 through the guard, then RealBackupTests --ha118; both through heavy.sh). Records runs/TAG-b1.*, TAG-ha118.*, TAG.summary, TAG.exit.
S=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad
W=/tmp/parity-read-20261125
[ "$(git -C $W status --porcelain --untracked-files=no | wc -l)" = 0 ] || { echo "worktree not clean" >&2; exit 3; }
git -C /tmp/parity-read-suite-20261125 checkout -q --detach "$(git -C $W rev-parse --short HEAD)" || exit 4
exec "$S/parity-read/run-suite.sh" "$1"
