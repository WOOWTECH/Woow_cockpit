# READ-ONLY inventory part 3 (bash -s on the showcase HA): container names, mounts (paths only), backup history of the candidates.
set -uo pipefail
echo "== containers (name image status)"; docker ps -a --format '{{.Names}} {{.Image}} {{.Status}}' | grep -Ei 'opendesign|nextcloud|code.server' | cut -c1-160
echo "== backups that contain a candidate (slug name date size_mb protected apps)"
ha backups list --raw-json | jq -r '.data.backups[] | select((.content.addons // .content.apps // []) | map(test("opendesign|nextcloud|code_server")) | any) | [.slug, .name, .date[0:16], .size, .protected, ((.content.addons // .content.apps) | join(",")), ((.content.folders // []) | join(","))] | @tsv' | sort -k3 | tail -25 | cut -c1-220
