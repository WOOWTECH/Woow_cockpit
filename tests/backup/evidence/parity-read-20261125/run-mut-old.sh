#!/bin/bash
# usage: run-mut-old.sh TAG 'label|label'  -- like run-mut-some.sh but on the tree mut-old (the tests of the commit before the last test commit)
S=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad
R=$S/parity-read/runs
export PYTHONDONTWRITEBYTECODE=1
rm -f "$R/$1.exit"
HEAVY_FREE=/tmp/woowbk-host-heavy-tests.lock "$S/team/heavy.sh" flock -w 3600 /tmp/woowbk-host-heavy-tests.lock \
  timeout 3000 python3 -I "$S/parity-read/mutations.py" "$S/parity-read/mut-old" "$R/$1.json" "$2" > "$R/$1.out" 2> "$R/$1.err"
echo $? > "$R/$1.exit"
