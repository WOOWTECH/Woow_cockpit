#!/bin/bash
# ncs-dl.sh <name> <remote path> <expected sha256> <size bytes>: copy one showcase backup to
# ~/.woowbk-lab/ha-fixtures/20261123-batch2/x86/<name>/<file> with `cat` over the SSH helper (dirs 0700, file 0600) and
# keep the host's 12 GiB floor the whole time: refuse to start when the host would keep less than 13 GiB free, and
# every 5 s abort + delete the partial file when free space minus the bytes still to come would drop below 12.5 GiB
# (other lanes write too). Compares sha256 at the end. The SSH password comes only from $TESTHA_PW on the command line.
set -uo pipefail
NAME=$1 RP=$2 SUM=$3 SIZE=$4
SSH=/tmp/claude-1000/-home-woowtechopenclaw/fbefdf50-77b9-4f2f-a609-4d7d82a72cee/scratchpad/testha/ssh-stdin.sh
BASE=~/.woowbk-lab/ha-fixtures/20261123-batch2; OUT=$BASE/x86/$NAME
GIB=1073741824; START_MIN=$(( 13 * GIB )); RUN_MIN=$(( 12 * GIB + GIB / 2 ))
umask 077; mkdir -p "$OUT"; chmod 700 "$BASE" "$BASE/x86" "$OUT"
f="$OUT/$(basename "$RP")"
if [ -f "$f" ] && [ "$(stat -c %s "$f")" = "$SIZE" ] && [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$SUM" ]; then echo "$NAME: already here, sha256 MATCH"; exit 0; fi
rm -f "$f"
avail() { df -B1 --output=avail / | tail -1; }
free=$(avail); left=$(( free - SIZE ))
echo "$NAME: host free $(( free / 1048576 )) MiB, after download $(( left / 1048576 )) MiB (start needs >= $(( START_MIN / 1048576 )) MiB)"
[ "$left" -ge "$START_MIN" ] || { echo "$NAME: STOP, would leave less than 13 GiB free"; exit 3; }
killtree() { local c; for c in $(pgrep -P "$1"); do killtree "$c"; done; kill -TERM "$1" 2>/dev/null; }
start=$(date +%s)
nice -n 10 ionice -c3 timeout 7200 "$SSH" cat "$RP" < /dev/null > "$f" 2> "$OUT/.download.err" &
pid=$!; lowest=$free; aborted=""
while kill -0 "$pid" 2>/dev/null; do
  sleep 5
  got=$(stat -c %s "$f" 2>/dev/null || echo 0); free=$(avail); proj=$(( free - (SIZE - got) ))
  [ "$proj" -lt "$lowest" ] && lowest=$proj
  if [ "$proj" -lt "$RUN_MIN" ] || [ "$got" -gt "$SIZE" ]; then aborted="projected free $(( proj / 1048576 )) MiB or size over"; killtree "$pid"; break; fi
  [ $(( $(date +%s) % 300 )) -lt 5 ] && echo "$NAME: $(( got / 1048576 )) MiB of $(( SIZE / 1048576 )) MiB, host free $(( free / 1048576 )) MiB"
done
wait "$pid" 2>/dev/null; rc=$?
if [ -n "$aborted" ]; then rm -f "$f"; echo "$NAME: ABORTED ($aborted), partial file deleted"; exit 5; fi
chmod 600 "$f"
local_sum=$(nice -n 10 sha256sum "$f" | cut -d' ' -f1); got=$(stat -c %s "$f")
echo "$NAME: $got bytes in $(( $(date +%s) - start ))s (ssh rc=$rc), lowest projected free $(( lowest / 1048576 )) MiB, remote ${SUM:0:16} local ${local_sum:0:16} $([ "$local_sum" = "$SUM" ] && echo MATCH || echo MISMATCH)"
if [ "$local_sum" = "$SUM" ] && [ "$got" = "$SIZE" ]; then rm -f "$OUT/.download.err"; else grep -v 'open pidfd' "$OUT/.download.err" | head -3; rm -f "$f"; echo "$NAME: mismatch, file deleted"; exit 4; fi
