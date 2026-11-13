#!/bin/bash
# Install, remove or show the woowbk-dirs trusted catalog entry and Quadlet templates on a lab device (root),
# like `manage.py install --backup-demo-catalog` does for woowbk-demo (CONTRACT section 3 locations):
#   tests/e2e/lab/dirs-catalog.sh <a|b> install   # /etc/woowtech-cockpit/backup/apps/woowbk-dirs.json (root 0644)
#                                                 # + /usr/local/share/woowtech-cockpit-backup/catalog/woowbk-dirs/quadlet/
#   tests/e2e/lab/dirs-catalog.sh <a|b> remove
#   tests/e2e/lab/dirs-catalog.sh <a|b> status    # files + what the installed engine says about woowbk-dirs
# The entry uses `data_dirs`: an engine without host-directory support reports it as an unsupported field
# (status `warnings`) and skips the app; nothing else is affected.
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
action=${2:-status}
[ "$(container_state "$NAME")" = running ] || die "$NAME is not running (tests/e2e/lab/up.sh $DEV)"
FIXTURE=$REPO_ROOT/catalog-examples/woowbk-dirs
ENTRY=/etc/woowtech-cockpit/backup/apps/woowbk-dirs.json
TEMPLATES=/usr/local/share/woowtech-cockpit-backup/catalog/woowbk-dirs

case "$action" in
    install)
        python3 -c 'import json, sys; json.load(open(sys.argv[1]))' "$FIXTURE/catalog.json" || die "catalog.json is not valid JSON"
        tar -C "$FIXTURE" -cf - catalog.json quadlet/woowbk-dirs.network quadlet/woowbk-dirs-db.container \
            quadlet/woowbk-dirs-app.container | dexec "$NAME" bash -c "set -euo pipefail
            work=\$(mktemp -d /var/tmp/woowbk-dirs-catalog.XXXXXX); trap 'rm -rf \"\$work\"' EXIT
            tar -C \"\$work\" --no-same-owner -xf -
            install -d -o root -g root -m 0755 /etc/woowtech-cockpit /etc/woowtech-cockpit/backup \
                /etc/woowtech-cockpit/backup/apps /usr/local/share/woowtech-cockpit-backup \
                /usr/local/share/woowtech-cockpit-backup/catalog $TEMPLATES $TEMPLATES/quadlet
            install -o root -g root -m 0644 \"\$work\"/quadlet/* $TEMPLATES/quadlet/
            install -o root -g root -m 0644 \"\$work\"/catalog.json $ENTRY"
        log "installed $ENTRY and $TEMPLATES/quadlet/ on $NAME" ;;
    remove)
        dexec "$NAME" sh -c "rm -f $ENTRY && rm -rf $TEMPLATES"
        log "removed $ENTRY and $TEMPLATES from $NAME" ;;
    status) ;;
    *) die "action must be install, remove or status" ;;
esac

dexec "$NAME" sh -c "ls -l $ENTRY $TEMPLATES/quadlet/ 2>&1; sha256sum $ENTRY 2>/dev/null"
if "$LP" exec "$NAME" test -x /usr/local/libexec/woowtech-cockpit-backup; then
    printf '' | "$LP" exec -i "$NAME" /usr/local/libexec/woowtech-cockpit-backup status | python3 -c '
import json, sys
reply = json.load(sys.stdin)
if not reply.get("ok"):
    print("engine status failed:", reply.get("error")); sys.exit(0)
app = next((a for a in reply["apps"] if a["id"] == "woowbk-dirs"), None)
notes = [w for w in reply.get("warnings", []) if "woowbk-dirs" in json.dumps(w, ensure_ascii=False)]
print("engine", reply.get("version"), "app:", json.dumps(app and {k: app[k] for k in ("state", "deployed", "units", "problems")}, ensure_ascii=False))
print("warnings about woowbk-dirs:", json.dumps(notes, ensure_ascii=False))'
fi
