#!/bin/bash
# usage: refresh-mut-tree.sh [TREE]   copies the lane worktree (backup-engine and tests, uncommitted changes included) into the
# throwaway tree the mutation sweep works on (mutations.py patches it, runs the tests there, restores it). Nothing else is touched.
S=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad
TREE=${1:-$S/parity-read/mut}
W=/tmp/parity-read-20261125
case "$TREE" in "$S"/*) ;; *) echo "refusing: tree outside the scratchpad" >&2; exit 2;; esac
mkdir -p "$TREE"
rsync -a --delete --exclude '__pycache__' "$W/backup-engine/" "$TREE/backup-engine/"
rsync -a --delete --exclude '__pycache__' "$W/tests/" "$TREE/tests/"
git -C "$W" rev-parse --short HEAD > "$TREE/.from-head"
git -C "$W" status --porcelain --untracked-files=no | wc -l >> "$TREE/.from-head"
