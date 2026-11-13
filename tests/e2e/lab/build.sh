#!/bin/bash
# Build localhost/woowbk-device:noble in the isolated lab storage.
#   tests/e2e/lab/build.sh [extra labpodman build args, e.g. --no-cache]
source "$(dirname "$0")/lib.sh"

check_memory
old_id=$("$LP" image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || true)
"$LP" build --memory 768m --layers -t "$IMAGE" -f "$LAB_DIR/Containerfile.device" "$@" "$LAB_DIR"
new_id=$("$LP" image inspect --format '{{.Id}}' "$IMAGE")
log "built $IMAGE ${new_id:0:12}"
"$LP" run --rm --memory 128m --entrypoint cat "$IMAGE" /etc/woowbk-device-versions
if [ -n "$old_id" ] && [ "$old_id" != "$new_id" ]; then
    # Drop the superseded image unless a device still uses it.
    "$LP" rmi "$old_id" >/dev/null 2>&1 && log "removed superseded image ${old_id:0:12}" || true
fi
