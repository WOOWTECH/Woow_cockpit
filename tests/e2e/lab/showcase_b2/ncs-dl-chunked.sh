#!/bin/bash
# ncs-dl-chunked.sh <name> <remote path> <expected sha256> <size bytes> [chunk MiB, default 256]: resumable copy of one
# showcase backup in fixed-size chunks (busybox dd over the SSH helper). The showcase first lists every chunk's sha256;
# each downloaded chunk must match its size and sha256 before it is appended, in order, to
# ~/.woowbk-lab/ha-fixtures/20261123-batch2/x86/<name>/<file>.part (dirs 0700, files 0600). A broken SSH connection costs
# only that chunk (each chunk is retried up to 8 times). Same 12 GiB host floor as ncs-dl.sh: refuse to start when the host
# would keep less than 13 GiB, and before every chunk abort + DELETE the partial file when free space minus the bytes still
# to come would drop below 12.5 GiB. Whole-file sha256 at the end, then rename. Why: attempt 1 (ncs-dl.sh, one stream)
# lost its SSH connection after 1.96 GB ("client_loop: send disconnect: Broken pipe"). $TESTHA_PW only on the command line.
set -uo pipefail
NAME=$1 RP=$2 SUM=$3 SIZE=$4 CH=${5:-256}
SSH=${NCS_SSH:-/tmp/claude-1000/-home-woowtechopenclaw/fbefdf50-77b9-4f2f-a609-4d7d82a72cee/scratchpad/testha/ssh-stdin.sh}
BASE=${NCS_BASE:-$HOME/.woowbk-lab/ha-fixtures/20261123-batch2}; OUT=$BASE/x86/$NAME; f="$OUT/$(basename "$RP")"; part="$f.part"
GIB=1073741824; START_MIN=$(( 13 * GIB )); RUN_MIN=$(( 12 * GIB + GIB / 2 ))
RUN_MIN=$(( ${NCS_RUN_MIN:-0} > RUN_MIN ? ${NCS_RUN_MIN:-0} : RUN_MIN ))   # a test may only make the running floor STRICTER
CB=$(( CH * 1048576 )); n=$(( (SIZE + CB - 1) / CB ))
umask 077; mkdir -p "$OUT"; chmod 700 "$BASE" "$BASE/x86" "$OUT"
avail() { df -B1 --output=avail / | tail -1; }
sz() { stat -c %s "$1" 2>/dev/null || echo 0; }
if [ -f "$f" ] && [ "$(sz "$f")" = "$SIZE" ] && [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$SUM" ]; then echo "$NAME: already here, sha256 MATCH"; exit 0; fi
have=$(sz "$part"); [ $(( have % CB )) = 0 ] || { echo "$NAME: partial file is not chunk-aligned, deleting it"; rm -f "$part"; have=0; }
free=$(avail); echo "$NAME: $n chunks of $CH MiB, resume at chunk $(( have / CB )), host free $(( free / 1048576 )) MiB, after download $(( (free - SIZE + have) / 1048576 )) MiB"
[ $(( free - (SIZE - have) )) -ge "$START_MIN" ] || { echo "$NAME: STOP, would leave less than 13 GiB free"; exit 3; }
list="$OUT/.chunks.sha256"; t0=$(date +%s)
if [ "$( { wc -l < "$list"; } 2>/dev/null || echo 0)" != "$n" ]; then
  for t in 1 2 3 4 5 6; do
    printf 'i=0; while [ $i -lt %s ]; do dd if=%s bs=1048576 skip=$((i*%s)) count=%s 2>/dev/null | sha256sum | cut -c1-64; i=$((i+1)); done\n' "$n" "$RP" "$CH" "$CH" \
      | timeout 900 "$SSH" sh -s > "$list.tmp" 2>> "$OUT/.download.err"
    [ "$(grep -c -E '^[0-9a-f]{64}$' "$list.tmp")" = "$n" ] && { mv "$list.tmp" "$list"; break; }
    echo "$NAME: chunk list attempt $t failed"; sleep 30
  done
fi
[ "$(grep -c -E '^[0-9a-f]{64}$' "$list" 2>/dev/null)" = "$n" ] || { echo "$NAME: STOP, no chunk list from the showcase"; exit 6; }
echo "$NAME: chunk list ready in $(( $(date +%s) - t0 ))s"
lowest=$(( $(avail) - (SIZE - have) )); retries=0
for i in $(seq $(( have / CB )) $(( n - 1 ))); do
  proj=$(( $(avail) - (SIZE - $(sz "$part")) )); [ "$proj" -lt "$lowest" ] && lowest=$proj
  if [ "$proj" -lt "$RUN_MIN" ]; then rm -f "$part" "$OUT/.chunk"; echo "$NAME: ABORTED before chunk $i (projected free $(( proj / 1048576 )) MiB < 12.5 GiB), partial file deleted"; exit 5; fi
  want=$(sed -n "$(( i + 1 ))p" "$list"); len=$(( SIZE - i * CB )); [ "$len" -gt "$CB" ] && len=$CB; ok=""
  for t in 1 2 3 4 5 6 7 8; do
    nice -n 10 ionice -c3 timeout 900 "$SSH" dd if="$RP" bs=1048576 skip=$(( i * CH )) count="$CH" < /dev/null > "$OUT/.chunk" 2>> "$OUT/.download.err"
    if [ "$(sz "$OUT/.chunk")" = "$len" ] && [ "$(sha256sum "$OUT/.chunk" | cut -c1-64)" = "$want" ]; then ok=1; break; fi
    retries=$(( retries + 1 )); echo "$NAME: chunk $i try $t failed (got $(sz "$OUT/.chunk") of $len bytes)"; sleep 20
  done
  [ -n "$ok" ] || { rm -f "$OUT/.chunk"; echo "$NAME: STOP, chunk $i failed 8 times (partial file kept for a resume)"; exit 7; }
  cat "$OUT/.chunk" >> "$part" && rm -f "$OUT/.chunk"; chmod 600 "$part"
  [ $(( i % 4 )) = 3 ] && echo "$NAME: $(( $(sz "$part") / 1048576 )) MiB of $(( SIZE / 1048576 )) MiB, host free $(( $(avail) / 1048576 )) MiB, $(( $(date +%s) - t0 ))s"
done
local_sum=$(nice -n 10 sha256sum "$part" | cut -d' ' -f1); got=$(sz "$part")
echo "$NAME: $got bytes in $(( $(date +%s) - t0 ))s, $n chunks, $retries chunk retries, lowest projected free $(( lowest / 1048576 )) MiB, remote ${SUM:0:16} local ${local_sum:0:16} $([ "$local_sum" = "$SUM" ] && echo MATCH || echo MISMATCH)"
if [ "$local_sum" = "$SUM" ] && [ "$got" = "$SIZE" ]; then mv "$part" "$f"; chmod 600 "$f"; rm -f "$list" "$OUT/.download.err"; else rm -f "$part" "$list"; echo "$NAME: mismatch, partial file deleted"; exit 4; fi
