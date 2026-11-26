#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == --apply && $# == 1 ]] || { echo 'Usage: sudo bash /tmp/parity-system-log-cleanup-20261126.sh --apply'; exit 2; }
[[ $EUID == 0 ]] || { echo 'Root is required to replace the rotated system log and vacuum archived journals.'; exit 1; }
install -d -m 0700 /run/woowbk-log-cleanup
exec 9>/run/woowbk-log-cleanup/lock
flock -n 9 || { echo 'Another log cleanup is running.'; exit 1; }
before=$(df -B1 --output=avail / | tail -1)
source_log=/var/log/syslog.1
destination=/var/log/syslog.1.manual-20261126.gz
temporary=
trap '[[ -z ${temporary:-} ]] || rm -f -- "$temporary"' EXIT
closed_log() {
    local rc=0
    lsof -t -- "$source_log" >/dev/null 2>&1 || rc=$?
    [[ $rc == 1 ]] || { echo 'Rotated log is open, or its open-file check failed; no source removed.'; return 1; }
}
if [[ -e $source_log ]]; then
    [[ -f $source_log && ! -L $source_log ]] || { echo 'Unexpected rotated log type.'; exit 1; }
    [[ ! -e $destination ]] || { echo 'Destination already exists; preserve both and inspect before retrying.'; exit 1; }
    closed_log
    fingerprint=$(stat -c '%d:%i:%s:%y:%z' -- "$source_log")
    temporary=$(mktemp /var/log/syslog.1.cleanup.XXXXXX)
    nice -n 19 ionice -c3 gzip -1 -c -- "$source_log" >"$temporary"
    gzip -t -- "$temporary"
    cmp -s -- "$source_log" <(gzip -dc -- "$temporary") || { echo 'Compressed content differs; source retained.'; exit 1; }
    [[ $(stat -c '%d:%i:%s:%y:%z' -- "$source_log") == "$fingerprint" ]] || { echo 'Source changed; retained.'; exit 1; }
    closed_log
    chmod --reference="$source_log" "$temporary"
    chown --reference="$source_log" "$temporary"
    touch -r "$source_log" "$temporary"
    mv -n -- "$temporary" "$destination"
    [[ ! -e $temporary ]] || { echo 'Destination appeared; source retained.'; exit 1; }
    temporary=
    [[ $(stat -c '%d:%i:%s:%y:%z' -- "$source_log") == "$fingerprint" ]] || { echo 'Source changed; both retained.'; exit 1; }
    rm -- "$source_log"
    echo "Verified lossless rotated-log archive: $destination"
fi
# Retain the live logger's syslog. Journal rotation only seals active journal files;
# vacuum removes archived journals beyond the age/size limits, keeping current journals.
journalctl --rotate
journalctl --vacuum-time=7d --vacuum-size=1G
after=$(df -B1 --output=avail / | tail -1)
printf 'Available bytes: before=%s after=%s net_gain=%s\n' "$before" "$after" "$((after-before))"
