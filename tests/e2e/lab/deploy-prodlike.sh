#!/bin/bash
# Deploy production-like copies of the reference host's Odoo 18 (tenant cloud) and n8n (queue mode) onto
# dev-c: the host's own images, the real package installers with freshly generated secrets, the host's
# trusted catalog entries for both apps (owner changed), the backup engine/page and a lab device key.
#   tests/e2e/lab/deploy-prodlike.sh c --odoo-repo DIR --n8n-repo DIR [--cockpit-src DIR] [PHASE...]
#
#   --odoo-repo DIR     Woow_podman_odoo checkout at or after 138d10c (a fresh tenant install needs its #10
#                       fix); HEAD is copied with `git archive` to ~/migration-w2/Woow_podman_odoo
#   --n8n-repo DIR      Woow_podman_n8n checkout (2ac1ae2 = the host's); HEAD -> ~/quadlet-w1/Woow_podman_n8n
#   --cockpit-src DIR   Woow_cockpit checkout to deploy (default: this one), passed to deploy-src.sh --src
#   PHASE               packages images odoo n8n cockpit check (default: all of them, in this order)
#
# packages python3-nacl and python3-cryptography from the device's apt sources (dev-c only; the image has neither)
# images   streams the 7 images from the host's own rootless storage (`podman save` -> `podman load` as
#          appowner; the only host Podman commands this script runs are `image inspect` and `save`).
#          Never pulls: the private registry is unreachable from dev-c (lib.sh). Image IDs must equal the
#          host's; manifest digests change on the way, so the digest-pinned refs are re-pinned (odoo phase).
# odoo     package copy, gateway image pin -> the loaded digest, ~/.config/odoo18/odoo18.env from the
#          tenant profile (+ image refs, DEFAULT_DB=odoo, a lab admin login), scripts/install.sh
# n8n      package copy, ~/.config/n8n/n8n.env (the host's 18 keys, URLs on 127.0.0.1), scripts/install.sh
#          (the n8n owner account is NOT set up, like on the host)
# cockpit  deploy-src.sh c (no demo catalog), the host's /etc/woowtech-cockpit/backup/apps/{odoo,n8n}.json
#          with "owner" -> appowner, device key (key-init/key-kit/key-confirm; kit in
#          ~/.woowbk-lab/secrets/dev-c-kit.txt, 0600, never printed)
# check    engine status of both apps and the catalog's health URLs
# Every phase can be run again: copies, settings and loaded images that are already there are kept, and the
# installers are idempotent. Start over with: tests/e2e/lab/reset.sh c --up
source "$(dirname "$0")/lib.sh"

device_vars "${1:-}"
[ "$DEV" = c ] || die "deploy-prodlike.sh is for dev-c only (memory, ports, registry block)"
shift
odoo_repo='' n8n_repo='' cockpit_src=$REPO_ROOT phases=()
while [ $# -gt 0 ]; do
    case "$1" in
        --odoo-repo) odoo_repo=${2:?--odoo-repo needs a checkout}; shift ;;
        --n8n-repo) n8n_repo=${2:?--n8n-repo needs a checkout}; shift ;;
        --cockpit-src) cockpit_src=${2:?--cockpit-src needs a checkout}; shift ;;
        packages | images | odoo | n8n | cockpit | check) phases+=("$1") ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done
[ ${#phases[@]} -gt 0 ] || phases=(packages images odoo n8n cockpit check)
[ "$(container_state "$NAME")" = running ] || die "$NAME is not running (tests/e2e/lab/up.sh c)"

owner() { "$LP" exec -i "$NAME" /usr/local/bin/woowbk-owner "$@"; }
HOME_C=/home/$OWNER
ODOO_DIR=$HOME_C/migration-w2/Woow_podman_odoo
N8N_DIR=$HOME_C/quadlet-w1/Woow_podman_n8n
ODOO_TAG=localhost/woow-odoo-tenant-ha:20261101.1152-51856b0
DB_TAG=jcr-prod.woowtech.io/woow-paas-docker-local/paas-postgres:17.11-20260928.1549
GATEWAY_TAG=docker.io/nginxinc/nginx-unprivileged:1.27-alpine
# The host runs the gateway image by digest only (no tag); this is the pin in Woow_podman_odoo.
GATEWAY_PIN=$GATEWAY_TAG@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0
ODOO_ADMIN_LOGIN=labadmin@woowbk-dev-c.lab
MIN_FREE_GB=20

# <host ref>|<name in dev-c>|<save format>. docker-archive cannot carry zstd layers (n8n), and the OCI archive
# keeps the local tenant build's name; the gateway image has no tag on the host, so it is saved by ID.
IMAGES=(
    "$ODOO_TAG|$ODOO_TAG|oci-archive"
    "$DB_TAG|$DB_TAG|docker-archive"
    "${GATEWAY_PIN/:1.27-alpine/}|$GATEWAY_TAG|docker-archive"
    "docker.io/n8nio/n8n:2.43.6|docker.io/n8nio/n8n:2.43.6|oci-archive"
    "docker.io/n8nio/runners:2.43.6|docker.io/n8nio/runners:2.43.6|docker-archive"
    "docker.io/library/postgres:16.15-alpine|docker.io/library/postgres:16.15-alpine|docker-archive"
    "docker.io/valkey/valkey:8.1.11-alpine|docker.io/valkey/valkey:8.1.11-alpine|docker-archive"
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
    installed=$("$LP" exec "$NAME" dpkg-query -W -f '${Status}\n' python3-nacl python3-cryptography 2>/dev/null |
        grep -c 'install ok installed' || true)
    if [ "$installed" = 2 ]; then
        log "python3-nacl and python3-cryptography already installed"
        return
    fi
    "$LP" exec -e DEBIAN_FRONTEND=noninteractive "$NAME" apt-get update -qq
    "$LP" exec -e DEBIAN_FRONTEND=noninteractive "$NAME" apt-get install -y -q --no-install-recommends \
        python3-nacl python3-cryptography
    log "installed $("$LP" exec "$NAME" dpkg-query -W -f '${Package}=${Version} ' python3-nacl python3-cryptography)"
}

phase_images() {
    local spec src name format id size free start save_ref
    for spec in "${IMAGES[@]}"; do
        IFS='|' read -r src name format <<<"$spec"
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
        [[ $src != *@* ]] || save_ref=$id   # a digest reference cannot be written into the archive as a name
        podman save --format "$format" "$save_ref" | owner podman load >/dev/null ||
            die "podman save | podman load failed for $src"
        if [ "$(device_id "$name")" != "$id" ]; then
            owner podman image exists "$id" || die "$src did not arrive in $NAME"
            owner podman tag "$id" "$name"
        fi
        [ "$(device_id "$name")" = "$id" ] || die "$name in $NAME has ID $(device_id "$name"), the host's is $id"
        log "image $name loaded in $((SECONDS - start))s, ID ${id:0:12} (same as the host)"
    done
}

copy_repo() {  # <checkout> <dir in the device> <required ancestor or ''>
    local repo=$1 dest=$2 need=$3 rev
    [ -n "$repo" ] || die "the ${dest##*/} copy needs --${dest##*Woow_podman_}-repo (see the header)"
    rev=$(git -C "$repo" rev-parse HEAD) || die "$repo is not a git checkout"
    [ -z "$need" ] || git -C "$repo" merge-base --is-ancestor "$need" "$rev" || die "$repo HEAD ${rev:0:7} does not contain $need"
    [ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ] || log "note: $repo has uncommitted changes; HEAD ${rev:0:7} is copied"
    if owner test -d "$dest"; then
        local have
        have=$(owner cat "$dest.lab-source" 2>/dev/null || true)
        [ "$have" = "$rev" ] || die "$dest exists from '${have:-unknown}', not ${rev:0:7}; reset dev-c to change it"
        log "${dest#$HOME_C/} already holds ${rev:0:7}"
        return
    fi
    owner mkdir -p "$dest"
    git -C "$repo" archive --format=tar "$rev" | owner tar -C "$dest" -xf - || die "copying $repo failed"
    printf '%s\n' "$rev" | owner tee "$dest.lab-source" >/dev/null
    log "copied $repo ${rev:0:7} to ${dest#$HOME_C/}"
}

phase_odoo() {
    local odoo_pin db_pin gateway_pin
    odoo_pin=$(device_pin "$ODOO_TAG")
    db_pin=$(device_pin "$DB_TAG")
    gateway_pin=$(device_pin "$GATEWAY_TAG")
    copy_repo "$odoo_repo" "$ODOO_DIR" 138d10c
    # The package pins the gateway by its registry digest, which save/load does not keep: pin the loaded one.
    owner python3 -I - "$ODOO_DIR" "$GATEWAY_PIN" "$gateway_pin" <<'PY'
import pathlib, sys
root, old, new = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
for rel in ('quadlet/optional/odoo-gateway.container', 'scripts/common.sh'):
    path = root / rel
    text = path.read_text()
    if new in text:
        continue
    if text.count(old) != 1:
        sys.exit(f'{rel}: expected the gateway pin exactly once')
    path.write_text(text.replace(old, new))
    print(f'pinned the gateway image in {rel}')
PY
    owner python3 -I - "$ODOO_DIR/config/profiles/tenant-cloud.profile" "$odoo_pin" "$db_pin" "$ODOO_ADMIN_LOGIN" <<'PY'
import os, pathlib, re, sys
profile, odoo, db, login = sys.argv[1:5]
env = pathlib.Path.home() / '.config/odoo18/odoo18.env'
if env.exists():
    print(f'{env} exists (kept)')
    sys.exit(0)
values = {'WOOW_ODOO_IMAGE': odoo, 'WOOW_ODOO_DB_IMAGE': db, 'WOOW_ODOO_DEFAULT_DB': 'odoo', 'WOOW_ODOO_ADMIN_LOGIN': login}
lines = []
for line in pathlib.Path(profile).read_text().splitlines():
    m = re.match(r'^([A-Z_]+)=', line)
    if m and m.group(1) in values:
        line = f'{m.group(1)}={values.pop(m.group(1))}'
    lines.append(line)
if values:
    sys.exit(f'profile lacks {sorted(values)}')
env.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as handle:
    handle.write('# dev-c (lab): config/profiles/tenant-cloud.profile + image refs loaded from the host, DEFAULT_DB, a lab login.\n')
    handle.write('\n'.join(lines) + '\n')
print(f'wrote {env} (0600) from the tenant profile')
PY
    log "running Woow_podman_odoo scripts/install.sh as $OWNER (fresh secrets, tenant bootstrap, upgrade gate, smoke)"
    owner "$ODOO_DIR/scripts/install.sh" || die "Odoo install.sh failed"
}

phase_n8n() {
    copy_repo "$n8n_repo" "$N8N_DIR" ''
    owner python3 -I - "$N8N_DIR/config/n8n.env.example" <<'PY'
import os, pathlib, re, sys
env = pathlib.Path.home() / '.config/n8n/n8n.env'
if env.exists():
    print(f'{env} exists (kept)')
    sys.exit(0)
# The host's settings (same 18 keys); its LAN address becomes the device's loopback.
values = {'HOST_BIND': '0.0.0.0', 'HOST_PORT': '15678', 'WEBHOOK_PORT': '15679', 'N8N_HOST': '127.0.0.1',
          'N8N_PROTOCOL': 'http', 'GENERIC_TIMEZONE': 'Asia/Taipei', 'TZ': 'Asia/Taipei', 'N8N_RUNNERS_MODE': 'external',
          'EXECUTIONS_MODE': 'queue', 'WORKER_CONCURRENCY': '5', 'N8N_QUEUE_WEBHOOK_PROCESSOR': 'true',
          'N8N_QUEUE_DISABLE_MAIN_WEBHOOKS': 'true', 'N8N_BLOCK_ENV_ACCESS_IN_NODE': 'false',
          'N8N_DIAGNOSTICS_ENABLED': 'false', 'N8N_VERSION_NOTIFICATIONS_ENABLED': 'false'}
extra = {'N8N_WEBHOOK_URL': 'http://127.0.0.1:15679/', 'N8N_SECURE_COOKIE': 'false',
         'N8N_EDITOR_BASE_URL': 'http://127.0.0.1:15678/'}
lines = []
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    m = re.match(r'^([A-Z0-9_]+)=', line)
    if m and m.group(1) in values:
        line = f'{m.group(1)}={values.pop(m.group(1))}'
    lines.append(line)
if values:
    sys.exit(f'example lacks {sorted(values)}')
lines += ['', '# ---- dev-c (lab): the reference host also sets these (its LAN address -> 127.0.0.1) ----']
lines += [f'{k}={v}' for k, v in extra.items()]
env.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as handle:
    handle.write('\n'.join(lines) + '\n')
print(f'wrote {env} (0600): queue mode, webhook processor, the host\'s ports')
PY
    log "running Woow_podman_n8n scripts/install.sh as $OWNER (fresh secrets; n8n creates its own encryption key)"
    owner "$N8N_DIR/scripts/install.sh" || die "n8n install.sh failed"
}

phase_cockpit() {
    "$LAB_DIR/deploy-src.sh" c --src "$cockpit_src" --no-demo-catalog
    local app
    for app in odoo n8n; do
        python3 -I - "/etc/woowtech-cockpit/backup/apps/$app.json" "$OWNER" <<'PY' |
import json, sys
path, owner = sys.argv[1], sys.argv[2]
text = open(path, encoding='utf-8').read()
entry = json.loads(text)
old = '"owner": %s' % json.dumps(entry['owner'])
if text.count(old) != 1:
    sys.exit(f'{path}: expected one {old}')
new_text = text.replace(old, '"owner": %s' % json.dumps(owner))
changed = json.loads(new_text)
assert {k: v for k, v in changed.items() if k != 'owner'} == {k: v for k, v in entry.items() if k != 'owner'}
assert changed['owner'] == owner
sys.stdout.write(new_text)
PY
            dexec "$NAME" install -m 0644 -o root -g root /dev/stdin "/etc/woowtech-cockpit/backup/apps/$app.json" ||
            die "installing the $app catalog entry failed"
        log "catalog entry $app installed (the host's file, owner -> $OWNER)"
    done
    python3 -I - "$LP" "$NAME" "$SECRETS_DIR/dev-c-kit.txt" <<'PY'
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
    print(f"app {app['id']}: deployed={app['deployed']} state={app['state']} owner={app['owner']} problems={app['problems']}")
    bad += not (app['deployed'] and app['state'] == 'running' and not app['problems'])
ids = sorted(a['id'] for a in status.get('apps', []))
key = status.get('key') or {}
print(f"device key {key.get('key_id')} kit_confirmed={key.get('kit_confirmed')} catalog apps {ids}")
sys.exit(1 if bad or ids != ['n8n', 'odoo'] else 0)
PY
)

phase_check() {
    local url code failures=0
    "$LAB_DIR/engine.sh" c status | python3 -I -c "$CHECK_PY" || failures=1
    for url in http://127.0.0.1:18069/web/health http://127.0.0.1:18080/web/health \
        http://127.0.0.1:15678/healthz/readiness http://127.0.0.1:15679/healthz; do
        code=$("$LP" exec "$NAME" curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$url" || true)
        echo "health $url -> $code"
        [ "$code" = 200 ] || failures=1
    done
    [ "$failures" = 0 ] || die "dev-c is not ready"
    log "dev-c ready: odoo and n8n running and healthy"
}

for phase in "${phases[@]}"; do
    log "== phase $phase"
    "phase_$phase"
done
