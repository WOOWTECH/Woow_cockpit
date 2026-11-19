#!/bin/bash
# Deploy production-like copies of the reference host's Omnigent, Hermes, EMQX and Headscale onto dev-d (HA import
# batch 1): the host's own images, the real package installers at the commits the host runs, freshly generated
# secrets, the host's trusted catalog entries (owner changed; Headscale without its ngrok parts), the backup
# engine/page and a lab device key.
#   tests/e2e/lab/deploy-batch1.sh d --omnigent-repo DIR --hermes-repo DIR --emqx-repo DIR --headscale-repo DIR \
#       [--<app>-rev REV] [--cockpit-src DIR] [PHASE...]
#
#   --<app>-repo DIR    the package checkout (Woow_podman_omnigent_package, Woow_podman_hermes, Woow_podman_emqx,
#                       Woow_podman_vpn_headscale_package). The commit the reference host runs (REV below) is copied
#                       with `git archive` to the same path under appowner's home as on the host; the checkout's own
#                       HEAD does not matter (the host's Headscale checkout is on an older branch than what it runs)
#   --<app>-rev REV     copy REV instead of the production commit
#   --cockpit-src DIR   Woow_cockpit tree to deploy (default: this one), passed to deploy-src.sh --src
#   PHASE               packages images omnigent hermes emqx headscale cockpit check (default: all, in this order)
#
# packages  jq (Omnigent's installer needs it), python3-nacl and python3-cryptography (HA backups) from the
#           device's apt sources; the device image has none of them
# images    streams the 10 images from the host's own rootless storage (`podman save` -> `podman load` as
#           appowner; the only host Podman commands this script runs are `image inspect` and `save`). Never pulls.
#           Image IDs equal the host's; the manifest digests change on the way, so each package copy's digest
#           pins (quadlet/*.container Image=) are changed to the loaded digests in the app phases. Headplane's
#           load ignores one chown error (see IMAGES)
# omnigent  package copy, digest pins, scripts/install.sh --no-build: omnigent.env is the package example (the
#           host uses the same values), secrets generated, admin and operator accounts created, smoke
# hermes    package copy, digest pins, scripts/install.sh --no-llm --no-build with the host's memory limit and Paseo
#           origin: hermes.env is the example otherwise (no provider key, local public URL), smoke
# emqx      package copy, digest pins, scripts/install.sh --accept-defaults: emqx.env is the example (loopback,
#           where the host binds its LAN address), smoke (it pulls the digest-pinned eclipse-mosquitto client image)
# headscale package copy, digest pin, scripts/install.sh --accept-defaults --no-build: headscale.env is the example
#           (loopback, local server_url, ngrok off: no ngrok token in the lab), smoke
# cockpit   deploy-src.sh d (no demo catalog), the host's /etc/woowtech-cockpit/backup/apps/{omnigent,hermes,emqx,
#           headscale}.json with "owner" -> appowner (headscale also without headscale-ngrok.container, its unit and
#           the headscale-ngrok-authtoken secret), device key (key-init/key-kit/key-confirm; kit in
#           ~/.woowbk-lab/secrets/dev-d-kit.txt, 0600, never printed)
# check     engine status of the four apps, the catalog's health URLs, every unit active, no failed user unit
# Every phase can be run again: copies, settings and loaded images that are already there are kept, and the
# installers are idempotent. Start over with: tests/e2e/lab/reset.sh d --up
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
[ "$DEV" = d ] || die "deploy-batch1.sh is for dev-d only (memory, ports, apps)"
shift
APPS=(omnigent hermes emqx headscale)
# Where each package lives under the owner's home (the same relative path as on the reference host).
declare -A DEST=([omnigent]=Woow_podman_omnigent_package [hermes]=Woow_podman_hermes [emqx]=Woow_podman_emqx
                 [headscale]=Woow_podman_vpn_headscale_package)
# The commits the reference host runs (2026-11-19): its installed Quadlet, unit and config files render from
# them. Hermes 63c8be1 = main, whose installed files equal 0.23.1 (f4d0757; later commits are docs only); EMQX
# ea5886c has the same tree as main 937ab4b; Headscale 0afdfa4 = main, while the host's checkout sits on d0c795d.
declare -A REV=([omnigent]=6e4f0c0 [hermes]=63c8be1 [emqx]=ea5886c [headscale]=0afdfa4)
declare -A REPO=()
cockpit_src=$REPO_ROOT phases=()
while [ $# -gt 0 ]; do
    case "$1" in
        --omnigent-repo | --hermes-repo | --emqx-repo | --headscale-repo)
            app=${1#--}; app=${app%-repo}; REPO[$app]=${2:?$1 needs a checkout}; shift ;;
        --omnigent-rev | --hermes-rev | --emqx-rev | --headscale-rev)
            app=${1#--}; app=${app%-rev}; REV[$app]=${2:?$1 needs a commit}; shift ;;
        --cockpit-src) cockpit_src=${2:?--cockpit-src needs a checkout}; shift ;;
        packages | images | omnigent | hermes | emqx | headscale | cockpit | check) phases+=("$1") ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done
[ ${#phases[@]} -gt 0 ] || phases=(packages images omnigent hermes emqx headscale cockpit check)
[ "$(container_state "$NAME")" = running ] || die "$NAME is not running (tests/e2e/lab/up.sh d)"

owner() { "$LP" exec -i "$NAME" /usr/local/bin/woowbk-owner "$@"; }
HOME_D=/home/$OWNER
MIN_FREE_GB=20

# <the reference in the host's Quadlet files>|<name in dev-d>[|ignore-chown]. A reference with a digest is saved by
# image ID (a digest cannot be written into the archive as a name) and tagged after the load; the others keep their
# name. None of the layers is zstd-compressed (checked on the host), so docker-archive carries all of them.
# ignore-chown: the Headplane image has one entry, the distroless directory /home/nonroot, owned by 65532:65532,
# above appowner's nested range (container ids 1-55000; a device has only 65536 ids). That one load runs with
# `podman --storage-opt ignore_chown_errors=true load`, so the directory belongs to the container's root instead;
# the image ID stays the host's (it is the config digest) and Headplane runs as root and never uses that directory.
IMAGES=(
    "docker.io/library/postgres:16.15-alpine3.24@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139|docker.io/library/postgres:16.15-alpine3.24"
    "ghcr.io/omnigent-ai/omnigent-server:v0.21.0@sha256:9bba2964f015ddbb61da0924267effd1801c0db8f44ecec95f401f24d9a3f90c|ghcr.io/omnigent-ai/omnigent-server:v0.21.0"
    "localhost/woow-omnigent-runner:0.21.0-2|localhost/woow-omnigent-runner:0.21.0-2"
    "localhost/woow-hermes-agent:v0.22.5-woow4|localhost/woow-hermes-agent:v0.22.5-woow4"
    "docker.io/library/postgres:15.19@sha256:9b1d34adbce1dd07ee6e94b4a2cf698884b89bd44a6c9c12f5da8f3acbfe4957|docker.io/library/postgres:15.19"
    "docker.io/library/redis:7.4.11-alpine@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf|docker.io/library/redis:7.4.11-alpine"
    "docker.io/emqx/emqx:5.8.9@sha256:35b46f7aa7a0d51f3959e4344221ac5ec7f948b03e43099286b6c40a07bb393b|docker.io/emqx/emqx:5.8.9"
    "docker.io/nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0|docker.io/nginxinc/nginx-unprivileged:1.27-alpine"
    "localhost/woow-headscale:0.29.4-r1|localhost/woow-headscale:0.29.4-r1"
    "localhost/woow-headplane:0.7.1-woow2|localhost/woow-headplane:0.7.1-woow2|ignore-chown"
)

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
    installed=$("$LP" exec "$NAME" dpkg-query -W -f '${Status}\n' jq python3-nacl python3-cryptography 2>/dev/null |
        grep -c 'install ok installed' || true)
    if [ "$installed" = 3 ]; then
        log "jq, python3-nacl and python3-cryptography already installed"
        return
    fi
    "$LP" exec -e DEBIAN_FRONTEND=noninteractive "$NAME" apt-get update -qq
    "$LP" exec -e DEBIAN_FRONTEND=noninteractive "$NAME" apt-get install -y -q --no-install-recommends \
        jq python3-nacl python3-cryptography
    log "installed $("$LP" exec "$NAME" dpkg-query -W -f '${Package}=${Version} ' jq python3-nacl python3-cryptography)"
}

phase_images() {
    local spec src name flag id size free start save_ref load_opts
    for spec in "${IMAGES[@]}"; do
        IFS='|' read -r src name flag <<<"$spec"
        id=$(podman image inspect --format '{{.Id}}' "$src") || die "the host has no image $src"
        if [ "$(device_id "$name")" = "$id" ]; then
            log "image $name already loaded (${id:0:12})"
            continue
        fi
        size=$(podman image inspect --format '{{.Size}}' "$src")
        free=$(df -B1 --output=avail "$LAB_HOME/storage" | tail -1)
        [ $((free - 2 * size)) -ge $((MIN_FREE_GB * 1024 * 1024 * 1024)) ] ||
            die "host disk: $((free >> 30)) GiB free; $name needs about $((2 * size >> 30)) GiB and $MIN_FREE_GB GiB must stay free"
        start=$SECONDS
        save_ref=$src
        [[ $src != *@* ]] || save_ref=$id
        load_opts=()
        [ "$flag" != ignore-chown ] || load_opts=(--storage-opt ignore_chown_errors=true)
        podman save --format docker-archive "$save_ref" | owner podman "${load_opts[@]}" load >/dev/null ||
            die "podman save | podman load failed for $src"
        if [ "$(device_id "$name")" != "$id" ]; then
            owner podman image exists "$id" || die "$src did not arrive in $NAME"
            owner podman tag "$id" "$name"
        fi
        [ "$(device_id "$name")" = "$id" ] || die "$name in $NAME has ID $(device_id "$name"), the host's is $id"
        log "image $name loaded in $((SECONDS - start))s, ID ${id:0:12} (same as the host)"
    done
    log "host disk after the images: $(($(df -B1 --output=avail "$LAB_HOME/storage" | tail -1) >> 30)) GiB free"
}

copy_repo() {  # <app>: git archive of REV[app] -> ~/<DEST[app]>, remembered in ~/<DEST[app]>.lab-source
    local app=$1 repo=${REPO[$1]:-} dest=$HOME_D/${DEST[$1]} rev have
    [ -n "$repo" ] || die "the $app phase needs --$app-repo (see the header)"
    rev=$(git -C "$repo" rev-parse --verify "${REV[$app]}^{commit}") || die "$repo has no commit ${REV[$app]}"
    if owner test -d "$dest"; then
        have=$(owner cat "$dest.lab-source" 2>/dev/null || true)
        [ "$have" = "$rev" ] || die "$dest exists from '${have:-unknown}', not ${rev:0:7}; reset dev-d to change it"
        log "${dest#$HOME_D/} already holds ${rev:0:7}"
        return
    fi
    owner mkdir -p "$dest"
    git -C "$repo" archive --format=tar "$rev" | owner tar -C "$dest" -xf - || die "copying $repo failed"
    printf '%s\n' "$rev" | owner tee "$dest.lab-source" >/dev/null
    log "copied $repo ${rev:0:7} to ${dest#$HOME_D/}"
}

repin() {  # <app>: the package copy's registry digest pins -> the digests of the images loaded in dev-d
    local app=$1 spec src name pairs=()
    for spec in "${IMAGES[@]}"; do
        IFS='|' read -r src name _ <<<"$spec"
        [[ $src == *@* ]] || continue
        pairs+=("$src=$(device_pin "$name")")
    done
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

phase_omnigent() {
    copy_repo omnigent
    repin omnigent
    log "running Woow_podman_omnigent_package scripts/install.sh as $OWNER (fresh secrets, admin + operator, smoke)"
    owner "$HOME_D/${DEST[omnigent]}/scripts/install.sh" --no-build || die "Omnigent install.sh failed"
}

phase_hermes() {
    copy_repo hermes
    repin hermes
    # The host's values for these two; its public URL and provider keys are host-specific or credentials.
    log "running Woow_podman_hermes scripts/install.sh --no-llm as $OWNER (fresh secrets, provisioning, smoke)"
    owner "$HOME_D/${DEST[hermes]}/scripts/install.sh" --no-llm --no-build \
        --set HERMES_PASEO_EXTRA_ORIGIN=http://127.0.0.1:19119 --set WOOW_HERMES_MEMORY=6144m ||
        die "Hermes install.sh failed"
}

phase_emqx() {
    copy_repo emqx
    repin emqx
    log "running Woow_podman_emqx scripts/install.sh --accept-defaults as $OWNER (fresh secrets, smoke)"
    owner "$HOME_D/${DEST[emqx]}/scripts/install.sh" --accept-defaults || die "EMQX install.sh failed"
}

phase_headscale() {
    copy_repo headscale
    repin headscale
    log "running Woow_podman_vpn_headscale_package scripts/install.sh --accept-defaults as $OWNER (ngrok off)"
    owner "$HOME_D/${DEST[headscale]}/scripts/install.sh" --accept-defaults --no-build || die "Headscale install.sh failed"
}

phase_cockpit() {
    "$LAB_DIR/deploy-src.sh" d --src "$cockpit_src" --no-demo-catalog
    local app
    for app in "${APPS[@]}"; do
        python3 -I - "/etc/woowtech-cockpit/backup/apps/$app.json" "$OWNER" <<'PY' |
import json, sys
path, owner = sys.argv[1], sys.argv[2]
text = open(path, encoding='utf-8').read()
entry = json.loads(text)
old = '"owner": %s' % json.dumps(entry['owner'])
if text.count(old) != 1:
    sys.exit(f'{path}: expected one {old}')
new_text = text.replace(old, '"owner": %s' % json.dumps(owner))
expected = dict(entry, owner=owner)
if entry['id'] == 'headscale':
    # No ngrok token in the lab, so no headscale-ngrok unit: the entry must not name its file, unit or secret.
    for snippet in ('"headscale-ngrok.container", ', '"headscale-ngrok.service", ', '{"name": "headscale-ngrok-authtoken"}, '):
        if new_text.count(snippet) != 1:
            sys.exit(f'{path}: expected one {snippet}')
        new_text = new_text.replace(snippet, '')
    expected['quadlet'] = {'files': [f for f in entry['quadlet']['files'] if f != 'headscale-ngrok.container']}
    expected['units'] = [u for u in entry['units'] if u != 'headscale-ngrok.service']
    expected['secrets'] = [s for s in entry['secrets'] if s['name'] != 'headscale-ngrok-authtoken']
assert json.loads(new_text) == expected, 'unexpected change'
sys.stdout.write(new_text)
PY
            dexec "$NAME" install -m 0644 -o root -g root /dev/stdin "/etc/woowtech-cockpit/backup/apps/$app.json" ||
            die "installing the $app catalog entry failed"
        log "catalog entry $app installed (the host's file, owner -> $OWNER$([ "$app" != headscale ] || echo ', without headscale-ngrok'))"
    done
    python3 -I - "$LP" "$NAME" "$SECRETS_DIR/dev-d-kit.txt" <<'PY'
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

CHECK_PY=$(cat <<'PY'
import json, sys
status = json.load(sys.stdin)
bad = 0
for app in status.get('apps', []):
    inactive = [u['name'] for u in app.get('units', []) if not u.get('active')]
    print(f"app {app['id']}: deployed={app['deployed']} state={app['state']} owner={app['owner']} "
          f"units={len(app.get('units', []))} inactive={inactive} problems={app['problems']}")
    bad += not (app['deployed'] and app['state'] == 'running' and not app['problems'] and not inactive)
ids = sorted(a['id'] for a in status.get('apps', []))
key = status.get('key') or {}
print(f"device key {key.get('key_id')} kit_confirmed={key.get('kit_confirmed')} catalog apps {ids}")
sys.exit(1 if bad or ids != ['emqx', 'headscale', 'hermes', 'omnigent'] else 0)
PY
)

phase_check() {
    local failures=0 url expect code app unit units state failed
    "$LAB_DIR/engine.sh" d status | python3 -I -c "$CHECK_PY" || failures=1
    # Every health URL of the installed catalog entries, with the status code each expects.
    while IFS='|' read -r url expect; do
        code=$("$LP" exec "$NAME" curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$url" || true)
        echo "health $url -> $code (expects $expect)"
        [ "$code" = "$expect" ] || failures=1
    done < <("$LP" exec "$NAME" python3 -I -c '
import json, sys
for app in sys.argv[1:]:
    for check in json.load(open(f"/etc/woowtech-cockpit/backup/apps/{app}.json"))["health"]:
        print(check["url"] + "|" + str(check["expect_status"]))' "${APPS[@]}")
    # The catalog units plus the packages' own helper units (health timer, provisioning oneshot).
    for app in "${APPS[@]}"; do
        mapfile -t units < <("$LP" exec "$NAME" python3 -I -c '
import json, sys
print("\n".join(json.load(open(f"/etc/woowtech-cockpit/backup/apps/{sys.argv[1]}.json"))["units"]))' "$app")
        case "$app" in
            omnigent) units+=(omnigent-server-health.timer) ;;
            hermes) units+=(hermes-provision.service) ;;
        esac
        for unit in "${units[@]}"; do
            state=$(owner systemctl --user is-active "$unit" 2>/dev/null || true)
            echo "unit $unit: $state"
            [ "$state" = active ] || failures=1
        done
    done
    failed=$(owner systemctl --user list-units --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | xargs)
    echo "failed user units: ${failed:-none}"
    [ -z "$failed" ] || failures=1
    [ "$failures" = 0 ] || die "dev-d is not ready"
    log "dev-d ready: omnigent, hermes, emqx and headscale running and healthy"
}

for phase in "${phases[@]}"; do
    log "== phase $phase"
    "phase_$phase"
done
