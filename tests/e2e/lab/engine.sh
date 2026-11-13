#!/bin/bash
# Call the installed backup helper inside a lab device as root (what Cockpit does with
# superuser: "require") and print its single JSON reply with key material redacted.
#   tests/e2e/lab/engine.sh <a|b> <command> [request-json]
#   tests/e2e/lab/engine.sh a status
#   tests/e2e/lab/engine.sh a backup-start '{"apps":["woowbk-demo"],"include_images":false,"note":"","request_id":"lab00000001"}'
#   tests/e2e/lab/engine.sh a job-status '{"job_id":"j20261113T020000Z-0123abcd"}'
# Requests that must carry a key (key-import, inspect/restore with "key") read it from stdin
# when the JSON is "-", so the key never appears in argv:  ... restore-start - < request.json
# Exit status is the helper's (0 ok, 1 error JSON).
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
command=${2:-}
[ -n "$command" ] || die "usage: engine.sh <a|b> <command> [request-json|-]"
request=${3:-'{}'}
if [ "$request" = - ]; then request=$(cat); fi
set +e
reply=$(printf '%s' "$request" | "$LP" exec -i "$NAME" /usr/local/libexec/woowtech-cockpit-backup "$command")
status=$?
set -e
printf '%s' "$reply" | python3 -c '
import json, sys
def scrub(value):
    if isinstance(value, dict):
        return {k: ("<redacted>" if k in ("key", "content") and isinstance(v, str) else scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value
raw = sys.stdin.read()
try:
    print(json.dumps(scrub(json.loads(raw)), ensure_ascii=False, indent=1))
except ValueError:
    print("non-JSON reply (%d bytes)" % len(raw))
'
exit $status
