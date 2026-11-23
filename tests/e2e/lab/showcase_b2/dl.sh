#!/bin/bash
# dl.sh <name> <remote path> <expected sha256> <size bytes>: copy one showcase backup to
# ~/.woowbk-lab/ha-fixtures/20261123-batch2/x86/<name>/<file> with `cat` over the SSH helper (dirs 0700, file 0600),
# refuse when the host would keep less than 13 GiB free (12 GiB floor + 1 GiB margin for the other lanes), compare sha256.
# The SSH password comes only from $TESTHA_PW on the command line.
set -uo pipefail
NAME=$1 RP=$2 SUM=$3 SIZE=$4
SSH=/tmp/claude-1000/-home-woowtechopenclaw/fbefdf50-77b9-4f2f-a609-4d7d82a72cee/scratchpad/testha/ssh-stdin.sh
BASE=~/.woowbk-lab/ha-fixtures/20261123-batch2; OUT=$BASE/x86/$NAME
umask 077; mkdir -p "$OUT"; chmod 700 "$BASE" "$BASE/x86" "$OUT"
f="$OUT/$(basename "$RP")"
if [ -f "$f" ] && [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$SUM" ]; then echo "$NAME: already here, sha256 MATCH"; exit 0; fi
free=$(df -B1 --output=avail / | tail -1)
left=$(( free - SIZE ))
echo "$NAME: host free $(( free / 1048576 )) MiB, after download $(( left / 1048576 )) MiB"
[ "$left" -ge $(( 13 * 1073741824 )) ] || { echo "$NAME: STOP, would leave less than 13 GiB free"; exit 3; }
start=$(date +%s)
timeout 3600 nice -n 10 ionice -c3 "$SSH" cat "$RP" < /dev/null > "$f" 2> "$OUT/.download.err"
chmod 600 "$f"
local_sum=$(sha256sum "$f" | cut -d' ' -f1)
echo "$NAME: $(stat -c %s "$f") bytes in $(( $(date +%s) - start ))s, remote ${SUM:0:16} local ${local_sum:0:16} $([ "$local_sum" = "$SUM" ] && echo MATCH || echo MISMATCH)"
if [ "$local_sum" = "$SUM" ]; then rm -f "$OUT/.download.err"; else grep -v 'open pidfd' "$OUT/.download.err" | head -3; exit 4; fi
