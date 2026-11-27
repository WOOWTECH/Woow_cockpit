#!/bin/bash
# Copy the CURRENT working tree (uncommitted changes included) into a lab device and install it
# there as root, the way a customer device would be installed from a checkout.
#   tests/e2e/lab/deploy-src.sh <a|b|c|d> [--src CHECKOUT] [--demo-catalog|--no-demo-catalog] [--fallback]
#
#   --src CHECKOUT      copy that Woow_cockpit checkout instead of the one holding this script (e.g. the
#                       integration worktree of a feature, while the lab scripts come from another branch)
#   --no-demo-catalog   install without the woowbk-demo fixture: only the catalog entries put there on
#                       purpose stay (default on dev-c and dev-d, which mirror production apps)
#
# 1. Tree minus .git node_modules .local design (and __pycache__) -> /opt/woow-cockpit-src,
#    root-owned and not group/world-writable (a low-privilege checkout is never the trust root).
# 2. If the installer supports it (team I):
#        python3 /opt/woow-cockpit-src/scripts/manage.py install --backup-demo-catalog
#    which installs the backup engine, UI and the woowbk-demo trusted catalog + templates
#    (without the demo catalog: `manage.py install`, which installs the backup package by default).
# 3. Otherwise the script stops with exit 3 and prints the MANUAL FALLBACK below; pass
#    --fallback to execute it. It is lab-only and mirrors CONTRACT section 3; once the installer
#    has the flag, the fallback must not be used any more.
#
# MANUAL FALLBACK (as root inside the device, from /opt/woow-cockpit-src):
#   python3 scripts/manage.py install                              # branding/preview/services
#   install -d -m 0755 /usr/local/lib/woowtech-cockpit-backup/woowbackup/adapters
#   install -m 0644 backup-engine/woowbackup/*.py /usr/local/lib/woowtech-cockpit-backup/woowbackup/
#   install -m 0644 backup-engine/woowbackup/adapters/*.py /usr/local/lib/woowtech-cockpit-backup/woowbackup/adapters/
#   install -m 0644 VERSION /usr/local/lib/woowtech-cockpit-backup/VERSION
#   install -m 0755 backup-engine/woowtech-cockpit-backup /usr/local/libexec/woowtech-cockpit-backup
#   install -d -m 0755 /usr/local/share/cockpit/woowtechbackup
#   install -m 0644 backup/{manifest.json,index.html,backup.css,backup.js} /usr/local/share/cockpit/woowtechbackup/
#   install -d -m 0755 /etc/woowtech-cockpit/backup/apps
#   install -m 0644 catalog-examples/woowbk-demo/catalog.json /etc/woowtech-cockpit/backup/apps/woowbk-demo.json
#   install -d -m 0755 /usr/local/share/woowtech-cockpit-backup/catalog/woowbk-demo/quadlet
#   install -m 0644 catalog-examples/woowbk-demo/quadlet/* /usr/local/share/woowtech-cockpit-backup/catalog/woowbk-demo/quadlet/
#   install -d -m 0700 /var/lib/woowtech-backup /etc/woowtech-cockpit/backup/keys
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
shift || true
fallback=no
tree=$REPO_ROOT
demo_catalog=yes
case "$DEV" in c | d | e) demo_catalog=no ;; esac
while [ $# -gt 0 ]; do
    case "$1" in
        --fallback) fallback=yes ;;
        --src) [ $# -ge 2 ] || die "--src needs a checkout"; tree=$(cd "$2" && pwd) || die "no such directory: $2"; shift ;;
        --demo-catalog) demo_catalog=yes ;;
        --no-demo-catalog) demo_catalog=no ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done
[ -f "$tree/scripts/manage.py" ] && [ -f "$tree/VERSION" ] || die "$tree is not a Woow_cockpit checkout"
[ "$(container_state "$NAME")" = running ] || die "$NAME is not running (tests/e2e/lab/up.sh $DEV)"
SRC=/opt/woow-cockpit-src

log "copying $tree (working tree) to $NAME:$SRC"
tar --anchored --exclude=./.git --exclude=./node_modules --exclude=./.local --exclude=./design \
    --no-anchored --exclude=__pycache__ -C "$tree" -cf - . |
    dexec "$NAME" sh -c "set -e; rm -rf $SRC.new; mkdir -p $SRC.new; tar -C $SRC.new --no-same-owner -xf -;
        chown -R root:root $SRC.new; chmod -R u+rwX,go+rX,go-w $SRC.new; rm -rf $SRC; mv $SRC.new $SRC"
log "copied: $("$LP" exec "$NAME" sh -c "find $SRC -type f | wc -l") files, VERSION $("$LP" exec "$NAME" cat $SRC/VERSION)"

if [ "$demo_catalog" = no ]; then
    "$LP" exec "$NAME" python3 "$SRC/scripts/manage.py" install --help 2>/dev/null | grep -q -- '--no-backup' ||
        die "this tree's installer does not manage the backup package; deploy it with the demo catalog (--fallback)"
    log "running manage.py install (no demo catalog)"
    dexec "$NAME" sh -c "cd $SRC && python3 scripts/manage.py install"
    exit 0
fi
if "$LP" exec "$NAME" python3 "$SRC/scripts/manage.py" install --help 2>/dev/null | grep -q -- '--backup-demo-catalog'; then
    log "running manage.py install --backup-demo-catalog"
    dexec "$NAME" sh -c "cd $SRC && python3 scripts/manage.py install --backup-demo-catalog"
    exit 0
fi

if [ "$fallback" = no ]; then
    log "scripts/manage.py has no --backup-demo-catalog yet (team I). Nothing was installed."
    log "Re-run with --fallback for the lab-only manual install documented at the top of $0."
    exit 3
fi

log "FALLBACK (lab only): manage.py install + manual backup engine/UI/demo catalog install"
dexec "$NAME" bash -s <<'FALLBACK'
set -euo pipefail
cd /opt/woow-cockpit-src
python3 scripts/manage.py install >/dev/null
LIB=/usr/local/lib/woowtech-cockpit-backup
install -d -m 0755 "$LIB" "$LIB/woowbackup" "$LIB/woowbackup/adapters"
install -m 0644 backup-engine/woowbackup/*.py "$LIB/woowbackup/"
install -m 0644 backup-engine/woowbackup/adapters/*.py "$LIB/woowbackup/adapters/"
install -m 0644 VERSION "$LIB/VERSION"
install -d -m 0755 /usr/local/libexec
install -m 0755 backup-engine/woowtech-cockpit-backup /usr/local/libexec/woowtech-cockpit-backup
if [ -f backup/manifest.json ]; then
    install -d -m 0755 /usr/local/share/cockpit/woowtechbackup
    for f in manifest.json index.html backup.css backup.js; do
        if [ -f "backup/$f" ]; then install -m 0644 "backup/$f" /usr/local/share/cockpit/woowtechbackup/; fi
    done
fi
install -d -m 0755 /etc/woowtech-cockpit /etc/woowtech-cockpit/backup /etc/woowtech-cockpit/backup/apps
install -m 0644 catalog-examples/woowbk-demo/catalog.json /etc/woowtech-cockpit/backup/apps/woowbk-demo.json
T=/usr/local/share/woowtech-cockpit-backup/catalog/woowbk-demo/quadlet
install -d -m 0755 /usr/local/share/woowtech-cockpit-backup /usr/local/share/woowtech-cockpit-backup/catalog \
    /usr/local/share/woowtech-cockpit-backup/catalog/woowbk-demo "$T"
install -m 0644 catalog-examples/woowbk-demo/quadlet/woowbk-demo.network \
    catalog-examples/woowbk-demo/quadlet/woowbk-demo-db.container \
    catalog-examples/woowbk-demo/quadlet/woowbk-demo-app.container "$T/"
install -d -m 0700 /var/lib/woowtech-backup /etc/woowtech-cockpit/backup/keys
echo "fallback install done: $(cat "$LIB/VERSION") engine=$LIB helper=/usr/local/libexec/woowtech-cockpit-backup"
FALLBACK
