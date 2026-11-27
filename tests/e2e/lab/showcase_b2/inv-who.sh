# READ-ONLY: when were the batch-2 add-ons started again (container start times), and any new backups since 08:00Z.
set -uo pipefail
for s in 1b7b4ce7_woow_ha_opendesign d65e8bf4_woow_ha_opendesign 1b7b4ce7_woow_ha_code_server; do
  echo "$s started_at=$(docker inspect -f '{{.State.StartedAt}}' app_$s 2>/dev/null | cut -c1-19) created=$(docker inspect -f '{{.Created}}' app_$s 2>/dev/null | cut -c1-19)"; done
echo "== backups since 08:00Z"; ha backups list --raw-json | jq -r '.data.backups[] | select(.date >= "2026-11-23T08:00") | [.slug, .name, .date[0:19], .size] | @tsv'
echo "== supervisor log lines mentioning start of these apps (time + short text)"
ha supervisor logs 2>/dev/null | grep -aE 'woow_ha_opendesign|woow_ha_code_server' | grep -aiE 'start|stop' | sed -E 's/\x1b\[[0-9;]*m//g' | tail -12 | cut -c1-170
