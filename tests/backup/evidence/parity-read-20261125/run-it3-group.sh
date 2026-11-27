#!/bin/bash
# usage: run-it3-group.sh TAG suites|reader   -- the heavy steps of iteration 3 in two groups, each run under ONE heavy.sh slot (called by run-it3.sh):
#   suites: tests/backup --b1 on the clean suite worktree (the lane's tip), RealBackupTests --ha118, tests/backup --b1 on the throw-away merge of BASE and the branch
#   reader: the schema check, the tarfile differential, the two structure fuzzers, the old-against-new reader on the 27 real HA backups, the changed real files,
#           the long byte-level fuzz, the 4,000,000-entry run
# records runs/TAG-<step>.{out,err,exit}, runs/TAG.log
S=/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad
P=$S/parity-read
R=$P/runs
W=/tmp/parity-read-20261125
SW=/tmp/parity-read-suite-20261125
M=/tmp/parity-read-merge3-20261125
TAG=${1:?tag}
GROUP=${2:?group}
G=$S/integration-3/guard.py
export PYTHONDONTWRITEBYTECODE=1
step() { name=$1; shift; echo "$(date +%H:%M) start $name" >> "$R/$TAG.log"; "$@" > "$R/$TAG-$name.out" 2> "$R/$TAG-$name.err"; echo $? > "$R/$TAG-$name.exit"; echo "$(date +%H:%M) end $name rc=$(cat $R/$TAG-$name.exit)" >> "$R/$TAG.log"; }
case "$GROUP" in
suites)
  export PYTHONPATH=backup-engine:tests/e2e/lab
  cd "$SW" || exit 2
  step b1 timeout 7200 python3 "$G" --b1 --log "$R/$TAG-b1.guardlog" --discover tests/backup --top .
  step ha118 timeout 3600 python3 "$G" --b1 --ha118 --log "$R/$TAG-ha118.guardlog" tests.backup.test_ha_backup.RealBackupTests
  cd "$M" || exit 2
  step merge-b1 timeout 7200 python3 "$G" --b1 --log "$R/$TAG-merge-b1.guardlog" --discover tests/backup --top .
  ;;
reader)
  cd "$W" || exit 2
  step check_schema "$P/venv/bin/python" -I "$P/check_schema.py"
  step diff_tarfile python3 -I "$P/diff_tarfile.py"
  step struct_fuzz python3 -I "$P/struct_fuzz.py"
  step struct_fuzz2 python3 -I "$P/struct_fuzz2.py"
  step diffsmall timeout 3600 xargs -a "$R/small.txt" -d '\n' python3 "$P/differential.py" "$R/$TAG-diffsmall.json"
  step difflarge timeout 7200 xargs -a "$R/large.txt" -d '\n' python3 "$P/differential.py" "$R/$TAG-difflarge.json"
  step realfiles timeout 3600 python3 "$P/real_files.py" "$P/scratch" "$R/$TAG-realfiles.json"
  PYTHONPATH=backup-engine:tests/e2e/lab step fuzz timeout 3600 python3 "$P/long_fuzz.py" 4000
  step mem4m timeout 3600 python3 "$P/mem4m.py" 4000000
  step mem4m1 timeout 3600 python3 "$P/mem4m.py" 4000001
  ;;
*) echo "unknown group $GROUP" >&2; exit 2;;
esac
