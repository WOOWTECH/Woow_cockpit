#!/bin/bash
# Deploy production-like copies of the reference host's Nextcloud (with Collabora), code-server and OpenDesign onto
# dev-e (HA import batch 2): the host's own images, the real package installers at the commits the host runs, freshly
# generated secrets, the host's trusted catalog entries (owner changed), the backup engine/page and a lab device key.
#   tests/e2e/lab/deploy-batch2.sh e [--nextcloud-repo DIR] [--code-server-repo DIR] [--opendesign-repo DIR]
#       [--<app>-rev REV] [--cockpit-src DIR] PHASE...
#
#   --<app>-repo DIR    the package checkout (Woow_podman_nextcloud_fresh, Woow_podman_code_server_package,
#                       Woow_podman_opendesign). The commit the reference host runs (REV below) is copied with
#                       `git archive` to the same path under appowner's home as on the host
#   --<app>-rev REV     copy REV instead of the production commit
#   --cockpit-src DIR   Woow_cockpit tree to deploy (default: this one), passed to deploy-src.sh --src
#   PHASE               packages | images[:APP] | nextcloud | code-server | opendesign | cockpit | check[:APP] |
#                       drop-images:APP ; APP is nextcloud, code-server or opendesign
#
# dev-e has no network (it is created with --network none): nothing inside it can pull an image or reach apt, the
# Nextcloud app store or any registry, and nothing outside reaches it.
# packages  python3-nacl and python3-cryptography (HA backups) and jq (code-server's settings merge): the device image
#           has none of them and dev-e cannot reach apt, so the .deb files are downloaded once by a throwaway
#           container of the same device image (the only networked step; lab storage only, never the host's), kept
#           in ~/.woowbk-lab/cache/debs-noble with their sha256, copied in and installed with dpkg
# images    copies the images from the host's own rootless storage: `podman save --format docker-dir --compress <ID>`
#           straight into dev-e's home volume (/home/.woowbk-xfer, the host side of the volume), then `podman load` as
#           appowner, a tag by ID and the transfer directory removed. The only host Podman commands this script runs
#           are `image inspect` and `save`; it never pulls. The compressed directory keeps the peak disk use at about
#           2 x compressed + 1 x image (a `podman save | podman load` pipe needs about 3 x image: podman copies stdin to
#           a temporary file and containers/image keeps a temporary copy of every blob until the image is committed).
#           Before every image the host must keep FLOOR_GIB (12) + RESERVE_GIB (1) free after the estimated peak,
#           and a watchdog stops the copy and removes the transfer directory if free space falls to FLOOR_GIB + 0.25.
#           Image IDs equal the host's (the ID is the config digest); manifest digests change on the way, so the app
#           phases change the package copy's digest pins (quadlet/*.container Image=) to the loaded digests
# drop-images:APP  removes APP's images from dev-e (test data rotation: they can be copied again from the host)
# Every phase can be run again: loaded images and copies that are already there are kept.
# Start over with: tests/e2e/lab/reset.sh e --up
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
[ "$DEV" = e ] || die "deploy-batch2.sh is for dev-e only (memory, network none, apps)"
shift
# Where each package lives under the owner's home (the same relative path as on the reference host).
declare -A DEST=([nextcloud]=Woow_podman_nextcloud_fresh [code-server]=Woow_podman_code_server_package
                 [opendesign]=Woow_podman_opendesign)
# The commits the reference host runs (2026-11-23, see the README's dev-e section): Nextcloud 19a7609 = head of the
# open PR #7 (feat/nextcloud-office-parity, the host's checkout); code-server tag 4.139.1-8 = e7dbbea; OpenDesign
# 1067bc4 = head of PR #17 (fix/mcp-default-userns, the host's checkout, merged upstream as bbbd4de).
declare -A REV=([nextcloud]=19a7609 [code-server]=e7dbbea [opendesign]=1067bc4)
declare -A REPO=()
cockpit_src=$REPO_ROOT phases=()
while [ $# -gt 0 ]; do
    case "$1" in
        --nextcloud-repo | --code-server-repo | --opendesign-repo)
            app=${1#--}; app=${app%-repo}; REPO[$app]=${2:?$1 needs a checkout}; shift ;;
        --nextcloud-rev | --code-server-rev | --opendesign-rev)
            app=${1#--}; app=${app%-rev}; REV[$app]=${2:?$1 needs a commit}; shift ;;
        --cockpit-src) cockpit_src=${2:?--cockpit-src needs a checkout}; shift ;;
        packages | images | images:nextcloud | images:code-server | images:opendesign | nextcloud | code-server | \
            opendesign | cockpit | check | check:nextcloud | check:code-server | check:opendesign | \
            drop-images:nextcloud | drop-images:code-server | drop-images:opendesign) phases+=("$1") ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done
[ ${#phases[@]} -gt 0 ] || die "name the phases to run (see the header)"
[ "$(container_state "$NAME")" = running ] || die "$NAME is not running (tests/e2e/lab/up.sh e)"
[ "$("$LP" inspect "$NAME" --format '{{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}')" = 'none {}' ] ||
    die "$NAME must run with --network none and no published port (recreate it: tests/e2e/lab/reset.sh e --up)"

owner() { "$LP" exec -i "$NAME" /usr/local/bin/woowbk-owner "$@"; }
HOME_D=/home/$OWNER
FLOOR_GIB=12
RESERVE_GIB=1
GIB=$((1024 * 1024 * 1024))
CACHE_DIR=$LAB_HOME/cache
DEB_DIR=$CACHE_DIR/debs-noble
DEBS=(python3-nacl python3-cryptography jq)

# <the reference in the host's Quadlet files>|<name in dev-e>. Every image is saved by its ID (a docker-dir has no
# name) and tagged with the name after the load. A reference with a digest gets the plain tag in dev-e and the app
# phase pins the loaded digest.
declare -A IMAGES=(
    [nextcloud]="localhost/woow-nextcloud:35.0.1-office2|localhost/woow-nextcloud:35.0.1-office2
docker.io/collabora/code:26.04.4.2.1|docker.io/collabora/code:26.04.4.2.1
docker.io/pgvector/pgvector:0.8.6-pg16|docker.io/pgvector/pgvector:0.8.6-pg16
docker.io/library/redis:8.10.1-alpine|docker.io/library/redis:8.10.1-alpine
docker.io/nginxinc/nginx-unprivileged:1.29.3-alpine|docker.io/nginxinc/nginx-unprivileged:1.29.3-alpine"
    [code-server]="ghcr.io/woowtech/woow-code-server-amd64:4.139.1-8@sha256:fe8b6a0f1b90863cb784cc8a4d69ba33783ee7b87d6322bf975a59511905370d|ghcr.io/woowtech/woow-code-server-amd64:4.139.1-8"
    [opendesign]="localhost/woow-open-design:4.2.1|localhost/woow-open-design:4.2.1
docker.io/library/nginx:1.30.4-alpine@sha256:dc5069ad14f19660b141b21236140b91656bf89bbc3e2417c70ae650cd66104c|docker.io/library/nginx:1.30.4-alpine"
)
# Largest first: the biggest copy runs while the most space is free.
IMAGE_ORDER=(opendesign code-server nextcloud)

host_free() { df -B1 --output=avail / | tail -1; }
device_id() { owner podman image inspect --format '{{.Id}}' "$1" 2>/dev/null || true; }
device_pin() {  # <name>: name@<digest of the loaded manifest>
    local digest
    digest=$(owner podman image inspect --format '{{.Digest}}' "$1") || die "$1 is not loaded in $NAME (run the images phase)"
    [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || die "$1 has no digest in $NAME"
    owner podman image exists "$1@$digest" || die "$1@$digest does not resolve in $NAME"
    printf '%s@%s' "$1" "$digest"
}

phase_packages() {
    local installed
    installed=$("$LP" exec "$NAME" dpkg-query -W -f '${Status}\n' "${DEBS[@]}" 2>/dev/null | grep -c 'install ok installed' || true)
    if [ "$installed" = "${#DEBS[@]}" ]; then
        log "${DEBS[*]} already installed"
        return
    fi
    if ! [ -s "$DEB_DIR/SHA256SUMS" ]; then
        install -d -m 0700 "$CACHE_DIR"
        rm -rf "$DEB_DIR.new" && install -d -m 0700 "$DEB_DIR.new/partial"
        log "downloading ${DEBS[*]} with a throwaway $IMAGE container (lab storage, apt over the network)"
        "$LP" run --rm --pull=never --memory 512m -v "$DEB_DIR.new:/out" "$IMAGE" sh -c \
            'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null &&
             apt-get install --download-only -y -q --no-install-recommends -o Dir::Cache::archives=/out "$@" >/dev/null' \
            sh "${DEBS[@]}" || die "downloading the packages failed"
        rm -rf "$DEB_DIR.new/partial" "$DEB_DIR.new/lock"
        (cd "$DEB_DIR.new" && sha256sum -- *.deb > SHA256SUMS) || die "no packages were downloaded"
        rm -rf "$DEB_DIR" && mv "$DEB_DIR.new" "$DEB_DIR"
    fi
    (cd "$DEB_DIR" && tar -cf - -- *.deb SHA256SUMS) | "$LP" exec -i "$NAME" sh -c '
        set -e; d=/var/cache/woowbk-offline-debs; rm -rf "$d"; mkdir -p "$d"; tar -C "$d" -xf -; cd "$d"
        sha256sum -c --quiet SHA256SUMS; DEBIAN_FRONTEND=noninteractive dpkg -i -- *.deb >/dev/null' ||
        die "installing the packages in $NAME failed"
    "$LP" exec "$NAME" python3 -I -c 'import nacl.bindings, cryptography' || die "python3-nacl/cryptography do not import"
    log "installed $("$LP" exec "$NAME" dpkg-query -W -f '${Package}=${Version} ' "${DEBS[@]}")"
}

XFER_HOST=
xfer_cleanup() { [ -z "$XFER_HOST" ] || rm -rf -- "$XFER_HOST"; XFER_HOST=; }
trap xfer_cleanup EXIT

# guarded <seconds> <cmd...>: runs cmd in the background; stops it if host free space falls to the floor + 0.25 GiB.
# Sets MIN_FREE to the lowest free space seen.
guarded() {
    local timeout=$1 pid free deadline rc limit=$(((FLOOR_GIB * 4 + 1) * GIB / 4))
    shift
    "$@" & pid=$!
    deadline=$((SECONDS + timeout))
    while kill -0 "$pid" 2>/dev/null; do
        free=$(host_free)
        [ "$free" -ge "$MIN_FREE" ] || MIN_FREE=$free
        if [ "$free" -lt "$limit" ]; then
            kill -TERM "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
            die "host free space fell to $((free >> 20)) MiB (floor ${FLOOR_GIB} GiB): copy stopped, transfer removed"
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            kill -TERM "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
            die "timed out after ${timeout}s: $*"
        fi
        sleep 1
    done
    wait "$pid"; rc=$?
    return "$rc"
}

copy_image() {  # <host reference> <name in dev-e>
    local src=$1 name=$2 id size free need start xfer_dev compressed
    id=$(podman image inspect --format '{{.Id}}' "$src") || die "the host has no image $src"
    if [ "$(device_id "$id")" = "$id" ]; then
        [ "$(device_id "$name")" = "$id" ] || owner podman tag "$id" "$name"
        log "image $name already loaded (${id:0:12})"
        return
    fi
    size=$(podman image inspect --format '{{.Size}}' "$src")
    # Estimated peak: the compressed directory and containers/image's temporary copy of it (each at most 60 % of the
    # image here, measured 43-45 %) plus the unpacked image.
    need=$((size + 2 * size * 6 / 10))
    free=$(host_free)
    [ $((free - need)) -ge $(((FLOOR_GIB + RESERVE_GIB) * GIB)) ] ||
        die "host disk: $((free >> 30)) GiB free; $name needs up to $((need >> 30)) GiB at its peak and $((FLOOR_GIB + RESERVE_GIB)) GiB must stay free"
    install -d -m 0755 "$VOLUME_HOME/.woowbk-xfer"
    XFER_HOST=$VOLUME_HOME/.woowbk-xfer/${id:0:12}
    xfer_dev=/home/.woowbk-xfer/${id:0:12}
    rm -rf -- "$XFER_HOST"
    start=$SECONDS MIN_FREE=$free
    guarded 3600 nice -n 10 ionice -c3 podman save -q --format docker-dir --compress -o "$XFER_HOST" "$id" ||
        die "podman save of $src failed"
    compressed=$(du -sb "$XFER_HOST" | cut -f1)
    guarded 3600 nice -n 10 "$LP" exec -i "$NAME" /usr/local/bin/woowbk-owner podman load -q -i "$xfer_dev" >/dev/null ||
        die "podman load of $src in $NAME failed"
    xfer_cleanup
    [ "$(device_id "$id")" = "$id" ] || die "$src did not arrive in $NAME"
    owner podman tag "$id" "$name"
    [ "$(device_id "$name")" = "$id" ] || die "$name in $NAME has ID $(device_id "$name"), the host's is $id"
    log "image $name loaded in $((SECONDS - start))s, ID ${id:0:12} (same as the host); $((size >> 20)) MiB, compressed copy $((compressed >> 20)) MiB, lowest host free $((MIN_FREE >> 20)) MiB"
}

phase_images() {  # [app]
    local app spec specs src name
    VOLUME_HOME=$("$LP" volume inspect "$NAME-home" --format '{{.Mountpoint}}') || die "no volume $NAME-home"
    for app in "${IMAGE_ORDER[@]}"; do
        [ -z "${1:-}" ] || [ "$1" = "$app" ] || continue
        # An array, not `while read`: the labpodman exec -i calls inside would read the loop's input.
        mapfile -t specs <<<"${IMAGES[$app]}"
        for spec in "${specs[@]}"; do
            IFS='|' read -r src name <<<"$spec"
            copy_image "$src" "$name"
        done
    done
    log "host disk after the images: $(($(host_free) >> 30)) GiB free"
}

phase_drop_images() {  # <app>
    local src name id spec specs
    mapfile -t specs <<<"${IMAGES[$1]}"
    for spec in "${specs[@]}"; do
        IFS='|' read -r src name <<<"$spec"
        id=$(podman image inspect --format '{{.Id}}' "$src") || die "the host has no image $src"
        if owner podman image exists "$id"; then
            owner podman rmi -f "$id" >/dev/null || die "removing $name from $NAME failed"
            log "removed $name (${id:0:12}) from $NAME"
        fi
    done
}

copy_repo() {  # <app>: git archive of REV[app] -> ~/<DEST[app]>, remembered in ~/<DEST[app]>.lab-source
    local app=$1 repo=${REPO[$1]:-} dest=$HOME_D/${DEST[$1]} rev have
    [ -n "$repo" ] || die "the $app phase needs --$app-repo (see the header)"
    rev=$(git -C "$repo" rev-parse --verify "${REV[$app]}^{commit}") || die "$repo has no commit ${REV[$app]}"
    if owner test -d "$dest"; then
        have=$(owner cat "$dest.lab-source" 2>/dev/null || true)
        [ "$have" = "$rev" ] || die "$dest exists from '${have:-unknown}', not ${rev:0:7}; reset dev-e to change it"
        log "${dest#$HOME_D/} already holds ${rev:0:7}"
        return
    fi
    owner mkdir -p "$dest"
    git -C "$repo" archive --format=tar "$rev" | owner tar -C "$dest" -xf - || die "copying $repo failed"
    printf '%s\n' "$rev" | owner tee "$dest.lab-source" >/dev/null
    log "copied $repo ${rev:0:7} to ${dest#$HOME_D/}"
}

repin() {  # <app>: the package copy's registry digest pins -> the digests of the images loaded in dev-e
    local app=$1 spec specs src name pairs=()
    mapfile -t specs <<<"${IMAGES[$app]}"
    for spec in "${specs[@]}"; do
        IFS='|' read -r src name <<<"$spec"
        [[ $src == *@* ]] || continue
        pairs+=("$src=$(device_pin "$name")")
    done
    [ ${#pairs[@]} -gt 0 ] || return 0
    owner python3 -I - "$HOME_D/${DEST[$app]}" "${pairs[@]}" <<'PY' || die "pinning the loaded images in the $app copy failed"
import pathlib, sys
root = pathlib.Path(sys.argv[1])
pairs = [arg.split('=', 1) for arg in sys.argv[2:]]
for path in sorted((root / 'quadlet').glob('*.container')):  # quadlet/optional/ is not installed here
    text = path.read_text()
    new = text
    for old, pin in pairs:
        if old in new:
            if new.count(old) != 1:
                sys.exit(f'{path.name}: {old} more than once')
            new = new.replace(old, pin)
    if new != text:
        path.write_text(new)
        print(f'{path.relative_to(root)}: Image= pinned to the loaded digest')
    elif '@sha256:' in text:
        print(f'{path.relative_to(root)}: already pinned')
PY
}

# ---- Nextcloud ------------------------------------------------------------------------------------------------
# The host's data directories (catalog nextcloud.json data_dirs) and the richdocuments release it runs (12.0.1, read
# from custom_apps/richdocuments/appinfo/info.xml of its 2026-11-10 package backup). The package installs
# richdocuments from the Nextcloud app store, which dev-e cannot reach: the official release archive (the app
# store's download, pinned by sha256 below) is unpacked into html/custom_apps before the first start, the way
# `occ app:install` leaves it (www-data, 0644/0755); the installer then finds it (`app:getpath`) and only enables
# it, and the check phase runs `occ integrity:check-app richdocuments` against the release's signature.
NC_ROOT=.local/share/nextcloud-office
RD_VERSION=12.0.1
RD_SHA256=0639ab0e3413142a76334af20ca88cba0a351a11c9c07effa0f1eb7f05941f2c
RD_URL=https://github.com/nextcloud-releases/richdocuments/releases/download/v$RD_VERSION/richdocuments-v$RD_VERSION.tar.gz

richdocuments_archive() {  # prints the cached release archive, downloading it once (host network)
    local f=$CACHE_DIR/richdocuments-v$RD_VERSION.tar.gz
    if ! [ -s "$f" ] || [ "$(sha256sum < "$f" | cut -d' ' -f1)" != "$RD_SHA256" ]; then
        install -d -m 0700 "$CACHE_DIR"
        curl -fsSL --max-time 300 -o "$f.new" "$RD_URL" || die "downloading richdocuments $RD_VERSION failed"
        [ "$(sha256sum < "$f.new" | cut -d' ' -f1)" = "$RD_SHA256" ] || die "richdocuments $RD_VERSION: unexpected sha256"
        mv "$f.new" "$f"
    fi
    printf '%s' "$f"
}

nextcloud_env() {  # ~/.config/nextcloud/nextcloud.env: the example, the host's data dirs, HOST_BIND and PHP_MEMORY_LIMIT
    local envf=$HOME_D/.config/nextcloud/nextcloud.env
    if owner test -e "$envf"; then
        log "nextcloud.env already exists (kept)"
        return
    fi
    # Those two are tuning values, not secrets; they are read by key from the host's env file and never printed.
    # Every URL, trusted domain and proxy setting stays the example's local one (the host's name its own addresses).
    git -C "${REPO[nextcloud]}" show "${REV[nextcloud]}:config/nextcloud.env.example" | python3 -I -c '
import re, sys
host_env, root = sys.argv[1], sys.argv[2]
host = {}
for line in open(host_env, encoding="utf-8"):
    m = re.match(r"^(HOST_BIND|PHP_MEMORY_LIMIT)=(.*)$", line.rstrip("\n"))
    if m:
        host[m.group(1)] = m.group(2)
dirs = {"HOST_HTML_DIR": "html", "HOST_DATA_DIR": "data", "HOST_POSTGRES_DIR": "postgres", "HOST_REDIS_DIR": "redis"}
seen, out = set(), []
for line in sys.stdin.read().splitlines():
    m = re.match(r"^([A-Z_]+)=(.*)$", line)
    if m and m.group(1) in dirs:
        line = "%s=%%h/%s/%s" % (m.group(1), root, dirs[m.group(1)])
        seen.add(m.group(1))
    elif m and m.group(1) in host:
        line = "%s=%s" % (m.group(1), host[m.group(1)])
        seen.add(m.group(1))
    out.append(line)
want = set(dirs) | {"HOST_BIND", "PHP_MEMORY_LIMIT"}
if seen != want:
    sys.exit("nextcloud.env: could not set %s" % sorted(want - seen))
print("\n".join(out))
' "$HOME/.config/nextcloud/nextcloud.env" "$NC_ROOT" |
        owner sh -c 'umask 077 && mkdir -p "$1" && cat > "$1/nextcloud.env.new" && mv "$1/nextcloud.env.new" "$1/nextcloud.env"' \
            sh "$HOME_D/.config/nextcloud" || die "writing nextcloud.env failed"
    log "nextcloud.env written: the example with the host's data dirs, HOST_BIND and PHP_MEMORY_LIMIT (values not shown)"
}

nextcloud_seed_richdocuments() {
    local html=$HOME_D/$NC_ROOT/html archive
    if owner podman unshare test -e "$html/config/config.php"; then
        log "Nextcloud is already installed: richdocuments is not seeded again"
        return
    fi
    if owner podman unshare test -e "$html/custom_apps/richdocuments/appinfo/info.xml"; then
        log "richdocuments $RD_VERSION already seeded"
        return
    fi
    archive=$(richdocuments_archive)
    owner sh -c 'umask 077 && mkdir -p "$1"' sh "$html" || die "creating $html failed"
    owner podman unshare sh -c 'set -e; umask 022; mkdir -p "$1/custom_apps"; chmod 0755 "$1/custom_apps"
        tar -C "$1/custom_apps" --no-same-owner -xzf -
        chown -R 33:33 "$1/custom_apps/richdocuments"; chown 33:0 "$1/custom_apps"' sh "$html" < "$archive" ||
        die "seeding richdocuments failed"
    log "richdocuments $RD_VERSION (sha256 ${RD_SHA256:0:12}) unpacked into ${html#$HOME_D/}/custom_apps (www-data)"
}

phase_nextcloud() {
    copy_repo nextcloud
    repin nextcloud
    nextcloud_env
    nextcloud_seed_richdocuments
    log "running Woow_podman_nextcloud_fresh scripts/install.sh as $OWNER (fresh secrets, first install, Office, smoke)"
    owner "$HOME_D/${DEST[nextcloud]}/scripts/install.sh" || die "Nextcloud install.sh failed"
}

# ---- catalog entries, engine, device key ------------------------------------------------------------------------
declare -A CATALOG_ID=([nextcloud]=nextcloud [opendesign]=open-design [code-server]=)
declare -A FIRST_QUADLET=([nextcloud]=nextcloud-app.container [opendesign]=open-design.container
                          [code-server]=code-server.container)
deployed() { owner test -f "$HOME_D/.config/containers/systemd/${FIRST_QUADLET[$1]}"; }

phase_cockpit() {
    local app id
    "$LAB_DIR/deploy-src.sh" e --src "$cockpit_src" --no-demo-catalog
    for app in nextcloud code-server opendesign; do
        id=${CATALOG_ID[$app]}
        if [ -z "$id" ]; then
            log "$app: the host has no catalog entry (owner decision: not onboarded); the code-server import lane adds one"
            continue
        fi
        if ! deployed "$app"; then
            log "$app is not deployed yet: its catalog entry is installed when it is"
            continue
        fi
        python3 -I - "/etc/woowtech-cockpit/backup/apps/$id.json" "$OWNER" <<'PY' |
import json, sys
path, owner = sys.argv[1], sys.argv[2]
text = open(path, encoding='utf-8').read()
entry = json.loads(text)
old = '"owner": %s' % json.dumps(entry['owner'])
if text.count(old) != 1:
    sys.exit(f'{path}: expected one {old}')
new_text = text.replace(old, '"owner": %s' % json.dumps(owner))
assert json.loads(new_text) == dict(entry, owner=owner), 'unexpected change'
sys.stdout.write(new_text)
PY
            dexec "$NAME" install -m 0644 -o root -g root /dev/stdin "/etc/woowtech-cockpit/backup/apps/$id.json" ||
            die "installing the $id catalog entry failed"
        log "catalog entry $id installed (the host's file, owner -> $OWNER)"
    done
    python3 -I - "$LP" "$NAME" "$SECRETS_DIR/dev-e-kit.txt" <<'PY'
import json, os, subprocess, sys
lp, name, kit_path = sys.argv[1:4]
def helper(command, request=None):
    proc = subprocess.run([lp, 'exec', '-i', name, '/usr/local/libexec/woowtech-cockpit-backup', command],
                          input=json.dumps(request or {}).encode(), capture_output=True, timeout=120)
    reply = json.loads(proc.stdout)
    if not reply.get('ok'):
        sys.exit(f'{command}: {reply.get("error", {}).get("code")}')
    return reply
key = helper('key-init')['key']
if key['kit_confirmed']:
    print(f'device key {key["key_id"]} exists, kit confirmed')
    sys.exit(0)
kit = helper('key-kit')
os.makedirs(os.path.dirname(kit_path), mode=0o700, exist_ok=True)
fd = os.open(kit_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'w', encoding='utf-8') as handle:
    handle.write(kit['content'])
helper('key-confirm', {'key_id': key['key_id']})
print(f'device key {key["key_id"]} created; emergency kit saved to {kit_path} (0600, not shown); kit confirmed')
PY
}

# ---- check ------------------------------------------------------------------------------------------------------
STATUS_PY=$(cat <<'PY'
import json, sys
want = sys.argv[1]
apps = {a['id']: a for a in json.load(sys.stdin).get('apps', [])}
app = apps.get(want)
if not app:
    sys.exit(f'engine status: {want} missing (catalog apps {sorted(apps)})')
inactive = [u['name'] for u in app.get('units', []) if not u.get('active')]
print(f"app {want}: deployed={app['deployed']} state={app['state']} owner={app['owner']} units={len(app.get('units', []))} "
      f"inactive={inactive} problems={app['problems']}")
sys.exit(0 if app['deployed'] and app['state'] == 'running' and not app['problems'] and not inactive else 1)
PY
)
RD_ENABLED_PY=$(cat <<'PY'
import json, sys
enabled = json.loads(sys.argv[1] or '{}').get('enabled', {})
version = enabled.get('richdocuments')
print(f'nextcloud: richdocuments enabled={version is not None} version={version}')
sys.exit(0 if version == sys.argv[2] else 1)
PY
)
# The packages' own units beyond the catalog's (code-server has no catalog entry). The host's
# open-design-local-health.{service,timer} (2026-11-08) are in no commit of the OpenDesign package: not deployed here.
declare -A EXTRA_UNITS=([nextcloud]="nextcloud-cron.timer" [opendesign]=""
                        [code-server]="code-server.service code-server-health.timer")
phase_check() {  # [app]: engine status, the catalog's health URLs, every unit active, no failed user unit
    local failures=0 app id url expect code unit units state failed apps=()
    for app in nextcloud code-server opendesign; do
        [ -z "${1:-}" ] || [ "$1" = "$app" ] || continue
        deployed "$app" && apps+=("$app")
    done
    [ ${#apps[@]} -gt 0 ] || die "nothing to check: no app deployed${1:+ ($1)}"
    for app in "${apps[@]}"; do
        id=${CATALOG_ID[$app]}
        units=()
        if [ -n "$id" ] && "$LP" exec "$NAME" test -f "/etc/woowtech-cockpit/backup/apps/$id.json"; then
            "$LAB_DIR/engine.sh" e status | python3 -I -c "$STATUS_PY" "$id" || failures=1
            while IFS='|' read -r url expect; do
                code=$("$LP" exec "$NAME" curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$url" || true)
                echo "health $url -> $code (expects $expect)"
                [ "$code" = "$expect" ] || failures=1
            done < <("$LP" exec "$NAME" python3 -I -c '
import json, sys
for check in json.load(open(f"/etc/woowtech-cockpit/backup/apps/{sys.argv[1]}.json"))["health"]:
    print(check["url"] + "|" + str(check["expect_status"]))' "$id")
            mapfile -t units < <("$LP" exec "$NAME" python3 -I -c '
import json, sys
print("\n".join(json.load(open(f"/etc/woowtech-cockpit/backup/apps/{sys.argv[1]}.json"))["units"]))' "$id")
        else
            echo "app $app: no catalog entry in $NAME (units and health checked directly)"
        fi
        # shellcheck disable=SC2206 # space-separated unit names
        units+=(${EXTRA_UNITS[$app]})
        for unit in "${units[@]}"; do
            state=$(owner systemctl --user is-active "$unit" 2>/dev/null || true)
            echo "unit $unit: $state"
            [ "$state" = active ] || failures=1
        done
        "phase_check_$app" || failures=1
    done
    failed=$(owner systemctl --user list-units --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | xargs)
    echo "failed user units: ${failed:-none}"
    [ -z "$failed" ] || failures=1
    [ "$failures" = 0 ] || die "dev-e is not ready (${apps[*]})"
    log "dev-e ready: ${apps[*]} running and healthy"
}

phase_check_nextcloud() {  # richdocuments enabled at the release version and intact; Office discovery through the gateway
    local ok=0 apps discovery integrity
    apps=$(owner podman exec -u www-data nextcloud-app php /var/www/html/occ app:list --output=json 2>/dev/null) || apps=
    python3 -I -c "$RD_ENABLED_PY" "$apps" "$RD_VERSION" || ok=1
    integrity=$(owner podman exec -u www-data nextcloud-app php /var/www/html/occ integrity:check-app richdocuments 2>&1) || ok=1
    echo "nextcloud: occ integrity:check-app richdocuments -> ${integrity:-no findings}"
    [ -z "$integrity" ] || ok=1
    discovery=$("$LP" exec "$NAME" curl -fsS -m 15 http://127.0.0.1:18081/hosting/discovery 2>/dev/null | grep -c '<wopi-discovery' || true)
    echo "nextcloud: Collabora discovery through the gateway -> $([ "$discovery" -ge 1 ] && echo ok || echo missing)"
    [ "$discovery" -ge 1 ] || ok=1
    return "$ok"
}
healthchecks() {  # <container...>: podman healthcheck run for each
    local c ok=0
    for c in "$@"; do
        if owner podman healthcheck run "$c" >/dev/null 2>&1; then echo "healthcheck $c: healthy"; else echo "healthcheck $c: FAILED"; ok=1; fi
    done
    return "$ok"
}

# ---- code-server --------------------------------------------------------------------------------------------------
# The host runs tag 4.139.1-8 (e7dbbea) rendered from the example env (all ten keys equal the example) plus two hand
# edits in its installed unit: `Environment=WOOW_CONNECTOR_DATA_DIR=/data/pi-agent/connectors-primary` as the first
# line of [Container], and Image= the ghcr image by digest instead of the locally built tag (the host has no
# localhost/woow-code-server:4.139.1-8). The package copy gets the same two edits before the install, so the installed
# unit equals the host's except for the digest (the one loaded in dev-e). The installer's --no-build check wants the
# local tag: it exists only while the installer runs.
CS_LOCAL=localhost/woow-code-server:4.139.1-8
CS_GHCR=ghcr.io/woowtech/woow-code-server-amd64:4.139.1-8
CS_ENV_LINE=Environment=WOOW_CONNECTOR_DATA_DIR=/data/pi-agent/connectors-primary

code_server_edit_copy() {
    owner python3 -I - "$HOME_D/${DEST[code-server]}/quadlet/code-server.container" "$(device_pin "$CS_GHCR")" "$CS_ENV_LINE" <<'PY' ||
import sys
path, pin, env = sys.argv[1], sys.argv[2], sys.argv[3] + '\n'
text = open(path, encoding='utf-8').read()
image = 'Image=' + pin + '\n'
if env in text and image in text:
    print('quadlet/code-server.container: already has the host edits')
    sys.exit(0)
old_image = 'Image=localhost/woow-code-server:4.139.1-8\n'
if text.count('[Container]\n') != 1 or text.count(old_image) != 1 or env in text:
    sys.exit('quadlet/code-server.container: not the e7dbbea template')
text = text.replace('[Container]\n', '[Container]\n' + env).replace(old_image, image)
open(path, 'w', encoding='utf-8').write(text)
print('quadlet/code-server.container: the host edits applied (connector data dir line, Image= the loaded ghcr digest)')
PY
        die "editing the code-server copy failed"
}

phase_code_server() {
    copy_repo code-server
    code_server_edit_copy
    owner podman tag "$CS_GHCR" "$CS_LOCAL"
    log "running Woow_podman_code_server_package scripts/install.sh --no-build --yes as $OWNER (fresh password secret)"
    if ! owner "$HOME_D/${DEST[code-server]}/scripts/install.sh" --no-build --yes; then
        owner podman untag "$CS_LOCAL" "$CS_LOCAL" || true
        die "code-server install.sh failed"
    fi
    owner podman untag "$CS_LOCAL" "$CS_LOCAL" || die "removing the temporary tag $CS_LOCAL failed"
    log "temporary tag $CS_LOCAL removed (the host has none; the unit runs $CS_GHCR by digest)"
}

phase_check_code_server() {
    local ok=0 code unit=$HOME_D/.config/containers/systemd/code-server.container
    healthchecks code-server || ok=1
    code=$("$LP" exec "$NAME" curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:18443/healthz || true)
    echo "code-server: /healthz -> $code (expects 200)"
    [ "$code" = 200 ] || ok=1
    owner grep -qx "$CS_ENV_LINE" "$unit" && owner grep -q "^Image=$CS_GHCR@sha256:" "$unit" ||
        { echo "code-server: the installed unit lacks the host edits"; ok=1; }
    return "$ok"
}

# ---- OpenDesign ---------------------------------------------------------------------------------------------------
# The host's open-design.env equals the example except OD_ALLOWED_ORIGINS, WOOW_OD_PASEO (on) and
# OPENDESIGN_PASEO_ORIGIN (its public https origin). dev-e runs Paseo too, with an origin under .invalid (RFC 2606:
# never resolves) that is also an allowed origin next to the example's local ones; Paseo cannot reach its relay from
# dev-e (no network) and the launcher's supervisor restarts only Paseo. Its first start makes the ID-mapped copy of the
# image for keep-id (TimeoutStartSec 900), like the host's first start did.
OD_LAB_ORIGIN=https://opendesign.lab.invalid

phase_opendesign() {
    copy_repo opendesign
    repin opendesign
    log "running Woow_podman_opendesign scripts/install.sh --no-build --accept-defaults as $OWNER (Paseo on, $OD_LAB_ORIGIN)"
    owner "$HOME_D/${DEST[opendesign]}/scripts/install.sh" --no-build --accept-defaults --set WOOW_OD_PASEO=on \
        --set "OPENDESIGN_PASEO_ORIGIN=$OD_LAB_ORIGIN" \
        --set "OD_ALLOWED_ORIGINS=http://127.0.0.1:7456,http://localhost:7456,$OD_LAB_ORIGIN" ||
        die "OpenDesign install.sh failed"
}

phase_check_opendesign() {
    healthchecks open-design open-design-nginx open-design-mcp open-design-terminal
}

for phase in "${phases[@]}"; do
    log "== phase $phase"
    case "$phase" in
        images:*) phase_images "${phase#images:}" ;;
        drop-images:*) phase_drop_images "${phase#drop-images:}" ;;
        check:*) phase_check "${phase#check:}" ;;
        code-server) phase_code_server ;;
        *) "phase_$phase" ;;
    esac
done
