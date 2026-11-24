#!/usr/bin/env python3
"""Team folders and the storage rows an import moves, on a real Nextcloud 35.0.1 with the real app (lab only, synthetic data).

    python3 -I tests/e2e/lab/nextcloud_team_folders.py <groupfolders.tar.gz> <evidence.json>

Why: the Team folders app (groupfolders 23.0.2 for Nextcloud 35) keeps one local storage per folder below the data
directory and names it by its number; HA's data directory is /share/nextcloud, this device's /var/www/html/data. The real HA
backup of the acceptance run has no Team folder, so this shows what the importer's storage_moves changes:
  1. a throwaway Nextcloud from dev-e's own image (its code in /usr/src/nextcloud, SQLite, configuration and data in one
     throwaway volume, network none), the app's release archive, a Team folder with a file, the file shared with a second user;
  2. "control": the data directory moved as an import does, only the root storage row renamed (the importer before 4fb7af7);
  3. "import": the same copy, the rows renamed that ha_nextcloud.storage_moves names (the product function, run on this host
     with the ids read from that database).
Compared through WebDAV as both users: the file's number, its content, the folder's listing and the share.
dev-e stays network none; its own Nextcloud is not touched (hibernated or not). The dev-e lock is held. Everything created is
removed. stdout: fixed lines; the evidence holds numbers, names and digests of this run's own synthetic data only."""
import fcntl
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / 'backup-engine'))
from woowbackup import ha_nextcloud as nc  # noqa: E402

LP = str(Path.home() / '.woowbk-lab' / 'bin' / 'labpodman')
DEVICE, LOCK = 'woowbk-dev-e', '/tmp/woowbk-dev-e-mutation.lock'
IMAGE = 'localhost/woow-nextcloud:35.0.1-office2'
NAME = 'woowbk-nctf'
HA_DATA = '/work/ha/share/nextcloud'
TEXT = 'WOOW team folder plan 2026-11-24\n'

SETUP = r'''
set -eu
umask 022
export NEXTCLOUD_CONFIG_DIR=/work/ha/config
mkdir -p /work/ha/config /work/ha/share /work/apps
tar -xzf /work/app.tar.gz -C /work/apps
cat > /work/ha/config/config.php <<'P'
<?php
$CONFIG = array(
  'apps_paths' => array(
    array('path' => '/usr/src/nextcloud/apps', 'url' => '/apps', 'writable' => false),
    array('path' => '/work/apps', 'url' => '/apps2', 'writable' => true),
  ),
  'appstoreenabled' => false,
  'has_internet_connection' => false,
  'skeletondirectory' => '',
);
P
head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > /work/pw
printf 'Aa1-' >> /work/pw
chmod 600 /work/pw
pw=$(cat /work/pw)
occ() { php -d memory_limit=512M /usr/src/nextcloud/occ --no-ansi --no-interaction "$@"; }
occ maintenance:install --database sqlite --database-name nc --admin-user admin --admin-pass "$pw" --data-dir /work/ha/share/nextcloud > /work/install.log 2>&1
occ config:system:set trusted_domains 1 --value=127.0.0.1 > /dev/null
occ app:enable groupfolders > /work/enable.log 2>&1
OC_PASS="$pw" occ user:add --password-from-env bob > /dev/null 2>&1
occ group:add team > /dev/null
occ group:adduser team admin > /dev/null
id=$(occ groupfolders:create TeamWoow | tr -dc 0-9)
occ groupfolders:group "$id" team read write share delete > /dev/null
version=$(occ status --output=json | php -r 'echo json_decode(stream_get_contents(STDIN), true)["version"];')
app=$(occ config:app:get groupfolders installed_version)
printf '{"folder_id": %s, "nextcloud": "%s", "groupfolders": "%s"}\n' "$id" "$version" "$app"
'''

STORAGES = r'''
$db = new PDO('sqlite:' . $argv[1]);
$out = ['storages' => [], 'folder' => null, 'filecache' => 0];
foreach ($db->query('SELECT numeric_id, id FROM oc_storages ORDER BY numeric_id') as $r) { $out['storages'][] = [(int)$r[0], $r[1]]; }
foreach ($db->query('SELECT folder_id, storage_id, root_id, options FROM oc_group_folders') as $r) { $out['folder'] = [(int)$r[0], (int)$r[1], (int)$r[2], $r[3]]; }
foreach ($db->query('SELECT count(*) FROM oc_filecache') as $r) { $out['filecache'] = (int)$r[0]; }
echo json_encode($out);
'''

MOVE = r'''
// php -r ... <variant dir>; stdin: {"moves": [[old, new], ...], "datadirectory": "..."}
$req = json_decode(stream_get_contents(STDIN), true);
$db = new PDO('sqlite:' . $req['datadirectory'] . '/nc.db');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->beginTransaction();
$n = 0;
foreach ($req['moves'] as $m) { $q = $db->prepare('UPDATE oc_storages SET id = ? WHERE id = ?'); $q->execute([$m[1], $m[0]]); $n += $q->rowCount(); }
$db->commit();
include '/work/ha/config/config.php';
$CONFIG['datadirectory'] = $req['datadirectory'];
file_put_contents($argv[1] . '/config/config.php', "<?php\n\$CONFIG = " . var_export($CONFIG, true) . ";\n");
echo json_encode(['renamed' => $n]);
'''

CLIENT = r'''
set -u
port=$1; first=$2
pw=$(cat /work/pw)
base=http://127.0.0.1:$port
i=0
until curl -s -o /dev/null -m 5 "$base/status.php"; do i=$((i+1)); [ $i -lt 60 ] || break; sleep 1; done
dav="$base/remote.php/dav/files"
if [ "$first" = 1 ]; then
  printf 'WOOW team folder plan 2026-11-24\n' > /work/plan.txt
  put=$(curl -s -o /dev/null -w '%{http_code}' -u "admin:$pw" -T /work/plan.txt "$dav/admin/TeamWoow/plan.txt")
  share=$(curl -s -u "admin:$pw" -H 'OCS-APIRequest: true' -d 'path=/TeamWoow/plan.txt' -d shareType=0 -d shareWith=bob -d permissions=1 "$base/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json" | php -r '$d = json_decode(stream_get_contents(STDIN), true); echo (int)($d["ocs"]["meta"]["statuscode"] ?? 0);')
else
  put=0; share=0
fi
body='<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop></d:propfind>'
list=$(curl -s -u "admin:$pw" -X PROPFIND -H 'Depth: 1' --data "$body" "$dav/admin/TeamWoow/" | grep -o '<d:href>[^<]*' | sed 's|.*/||' | sort | tr '\n' ' ')
code=$(curl -s -o /work/pf.$port -w '%{http_code}' -u "admin:$pw" -X PROPFIND -H 'Depth: 0' --data "$body" "$dav/admin/TeamWoow/plan.txt")
fileid=$(grep -o '<oc:fileid>[0-9]*' /work/pf.$port | tr -dc 0-9)
get=$(curl -s -o /work/get.$port -w '%{http_code}' -u "admin:$pw" "$dav/admin/TeamWoow/plan.txt")
sha=$(sha256sum /work/get.$port | cut -c1-64)
bob=$(curl -s -o /work/bob.$port -w '%{http_code}' -u "bob:$pw" "$dav/bob/plan.txt")
bobsha=$(sha256sum /work/bob.$port | cut -c1-64)
wrong=$(curl -s -o /dev/null -w '%{http_code}' -u "bob:wrong" "$dav/bob/plan.txt")
printf '{"put": %s, "share": %s, "list": "%s", "propfind": %s, "fileid": "%s", "get": %s, "sha256": "%s", "bob": %s, "bob_sha256": "%s", "bob_wrong": %s}\n' "$put" "$share" "$list" "$code" "$fileid" "$get" "$sha" "$bob" "$bobsha" "$wrong"
'''


class Failed(Exception):
    pass


def owner(*cmd, data=None, timeout=600):
    proc = subprocess.run(['bash', str(HERE / 'owner.sh'), 'e', *cmd], input=data, capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        raise Failed(f'{cmd[0]} {cmd[1] if len(cmd) > 1 else ""} exit {proc.returncode}')
    return proc.stdout


def inside(*cmd, data=None, env=(), detach=False, timeout=600):
    """A command in the throwaway container, as www-data."""
    options = ['-d'] if detach else ['-i']
    for item in env:
        options += ['-e', item]
    return owner('podman', 'exec', *options, NAME, *cmd, data=data, timeout=timeout)


def isolation():
    proc = subprocess.run([LP, 'inspect', DEVICE, '--format',
                           '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'],
                          capture_output=True, timeout=60)
    return proc.stdout.decode('utf-8', 'replace').strip()


def storages(datadir):
    return json.loads(inside('php', '-r', STORAGES, f'{datadir}/nc.db').decode())


def server(variant, port):
    inside('php', '-d', 'memory_limit=512M', '-S', f'127.0.0.1:{port}', '-t', '/usr/src/nextcloud',
           env=(f'NEXTCLOUD_CONFIG_DIR=/work/{variant}/config', 'PHP_CLI_SERVER_WORKERS=2'), detach=True)


def client(port, first):
    out = inside('bash', '-s', str(port), '1' if first else '0', data=CLIENT.encode(), timeout=900)
    return json.loads(out.decode('utf-8', 'replace').strip().splitlines()[-1])


def moved_copy(variant, port, moves):
    """The data directory on another path with `moves` applied to its database, served on `port`."""
    datadir = f'/work/{variant}/data'
    script = (f'set -eu; mkdir -p /work/{variant}/config; cp -a {HA_DATA} {datadir}')
    inside('bash', '-s', data=script.encode(), timeout=900)
    request = json.dumps({'moves': moves(datadir), 'datadirectory': datadir})
    done = json.loads(inside('php', '-r', MOVE, f'/work/{variant}', data=request.encode()).decode())
    before = storages(datadir)
    server(variant, port)
    seen = client(port, False)
    return {'renamed': done['renamed'], 'storages_before_use': before['storages'], 'client': seen,
            'storages_after_use': storages(datadir)['storages'], 'folder': before['folder']}


def run(archive, facts):
    # The throwaway container never sees a network; /work is its volume, the app's archive comes in on stdin.
    owner('podman', 'volume', 'create', '--label', 'woowbk.lab=nctf', NAME)
    owner('podman', 'run', '--rm', '--network', 'none', '--user', '0', '--entrypoint', 'chown', '--volume', f'{NAME}:/work',
          IMAGE, '33:33', '/work')
    owner('podman', 'run', '-d', '--name', NAME, '--label', 'woowbk.lab=nctf', '--network', 'none', '--memory', '900m',
          '--pids-limit', '256', '--security-opt', 'no-new-privileges', '--user', '33:33', '--entrypoint', 'sleep',
          '--volume', f'{NAME}:/work', IMAGE, '3000')
    inside('sh', '-c', 'cat > /work/app.tar.gz', data=archive)
    facts['ha'] = json.loads(inside('bash', '-s', data=SETUP.encode(), timeout=1500).decode().strip().splitlines()[-1])
    server('ha', 8080)
    facts['ha']['client'] = client(8080, True)
    state = storages(HA_DATA)
    facts['ha'].update(storages=state['storages'], folder=state['folder'])
    ids = [row[1] for row in state['storages']]

    def root_only(datadir):
        return [[nc.storage_id(HA_DATA), nc.storage_id(datadir)]]

    def product(datadir):
        return [list(pair) for pair in nc.storage_moves(HA_DATA, datadir, ids, [str(facts['ha']['folder_id'])])]

    facts['control'] = moved_copy('control', 8081, root_only)
    facts['import'] = moved_copy('import', 8082, product)
    facts['ha']['client_again'] = client(8080, False)


def main(argv):
    archive, target = Path(argv[0]).read_bytes(), Path(argv[1])
    if target.exists():
        raise SystemExit('evidence file exists; never overwrite an attempt')
    started = time.monotonic()
    git = lambda *a: subprocess.run(['git', '-C', str(REPO), *a], capture_output=True, text=True, timeout=60).stdout.strip()  # noqa: E731
    source, changed = git('rev-parse', 'HEAD'), bool(git('status', '--porcelain', '--untracked-files=no'))
    facts, checks, stopped = {}, {}, None
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        checks['dev-e isolation before: true none {}'] = isolation() == 'true none {}'
        try:
            if not checks['dev-e isolation before: true none {}']:
                raise Failed('isolation')
            run(archive, facts)
        except (Failed, ValueError, KeyError, subprocess.TimeoutExpired) as error:
            stopped = f'{type(error).__name__}: {str(error)[:160]}'
        finally:
            for command in (('podman', 'rm', '-f', '-t', '5', NAME), ('podman', 'volume', 'rm', '-f', NAME)):
                try:
                    owner(*command, timeout=300)
                except (Failed, subprocess.TimeoutExpired):
                    pass
            left = owner('podman', 'ps', '-aq', '--filter', 'label=woowbk.lab=nctf').strip() + owner(
                'podman', 'volume', 'ls', '-q', '--filter', 'label=woowbk.lab=nctf').strip()
            checks['nothing of this run is left in dev-e'] = left == b''
            checks['dev-e isolation after: true none {}'] = isolation() == 'true none {}'
    digest = hashlib.sha256(TEXT.encode()).hexdigest()
    ha, control, done = facts.get('ha', {}), facts.get('control', {}), facts.get('import', {})
    want = ha.get('client', {})
    sub = [row for row in ha.get('storages', []) if row[1] == f'local::{HA_DATA}/__groupfolders/{ha.get("folder_id")}/']
    checks['the app gives a new Team folder a local storage of its own below the data directory, named by its number in the folder row'] = (
        len(sub) == 1 and ha.get('folder', [0, 0])[1] == sub[0][0])
    checks['HA side: the file is written, shared and read by both users'] = (
        want.get('put') == 201 and want.get('share') == 200 and want.get('get') == 200 and want.get('sha256') == digest
        and want.get('bob') == 200 and want.get('bob_sha256') == digest and want.get('bob_wrong') == 401)
    seen = done.get('client', {})
    checks['import: the Team folder\'s file keeps its number and content, the listing and the share are the same'] = (
        bool(want.get('fileid')) and all(seen.get(k) == want.get(k) for k in ('list', 'fileid', 'sha256', 'bob_sha256'))
        and seen.get('get') == 200 and seen.get('bob') == 200 and seen.get('bob_wrong') == 401)
    checks['import: no storage row is added by using it, every row below the data directory names this device\'s path'] = (
        bool(done) and done.get('storages_after_use') == done.get('storages_before_use')
        and not [r for r in done['storages_after_use'] if HA_DATA in r[1]]
        and [r[0] for r in done['storages_after_use']] == [r[0] for r in ha.get('storages', [])])
    bad = control.get('client', {})
    checks['control (only the root row renamed): the file gets another number or the share is lost'] = bool(control) and (
        bad.get('fileid') != want.get('fileid') or bad.get('bob') != 200)
    doc = {'kind': 'nextcloud-team-folders', 'date': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'device': DEVICE, 'image': IMAGE,
           'source_commit': source, 'tracked_changes': changed, 'app_archive_sha256': hashlib.sha256(archive).hexdigest(), 'stopped': stopped, 'facts': facts,
           'checks': {k: 'PASS' if v else 'FAIL' for k, v in checks.items()},
           'elapsed_seconds': round(time.monotonic() - started, 1),
           'acceptance': 'not acceptance (real Nextcloud 35.0.1 and real Team folders app, synthetic data, SQLite; the importer '
                         'function storage_moves itself)'}
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, 'x', encoding='utf-8') as handle:
        json.dump(doc, handle, indent=1, ensure_ascii=False)
        handle.write('\n')
    for name, value in doc['checks'].items():
        print(f'{name}: {value}')
    if stopped:
        print(f'stopped: {stopped}')
    return 0 if stopped is None and all(checks.values()) else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
