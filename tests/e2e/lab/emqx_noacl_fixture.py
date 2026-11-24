#!/usr/bin/env python3
"""Lab-only: a variant of a REAL cold batch-1 HA backup (add-on woow-emqx 5.9.1, made with EMQX stopped) whose EMQX holds
NO ACL row in the built-in database. Everything else in the add-on is HA's own data, unchanged.

Why: OWNER DECISION 2026-11-23 「C」 refuses HA backups WITH ACL rows on a device that authorizes with the ACL file only;
a backup WITHOUT ACL rows is imported there (the usual customer case: EMQX in HA without built-in ACL rules). Both real
cold test backups hold 4 rows, so that path had no real input. This tool makes one, openly lab-made:

  python3 -I tests/e2e/lab/emqx_noacl_fixture.py <x86-cold|arm-cold> <private work dir> <out .tar> [fileonly] [hash=bcrypt|hash=plain]

Two variants: without `fileonly` HA keeps its authorization sources (the built-in database stays enabled, empty); with
`fileonly` EMQX also deletes HA's built-in database source (emqx_authz:update({delete, built_in_database}, #{}), what the
Dashboard does), so HA authorizes with its ACL file only, as the add-on is installed (the most common customer case).

1. the real backup (bound by SHA-256) is decrypted with the product's own reader (HA_BACKUP_KEY from the b1 harness
   secret file, in memory only);
2. HA's data directory (the items the product stages: mnesia, configs/cluster.hocon, certs, authz) is started in the
   official emqx/emqx:5.8.9 of the LAB store (labpodman, --network none, --pull=never, read-only root, the product's own
   ha_broker environment: plugins pinned off), EMQX itself runs mnesia:clear_table(emqx_acl), stops cleanly, is started
   once more from the same volume (the counts must have persisted: 0 ACL rows, every other table as before) and stops;
SR-5 variants (emqx-sr5, 2026-11-24; with `fileonly`): EMQX also changes HA's built-in password database hashing through
its own configuration update (emqx_conf:update([authentication], {update_authenticator, ...}), what the Dashboard's PUT
/authentication/{id} does: emqx_authn_api.erl:1051-1062,1179-1183). `hash=bcrypt`: then sets the password of HA's three
MQTT users again, through emqx_authn_chains:update_user (hashed with the new hashing, emqx_authn_mnesia.erl:390-401), with
the b1 test passwords the harness reader gives (piped into the throwaway's tmpfs, read and deleted there, never on a
command line or in the output); after the restart HA's users must log in with them inside the throwaway, a wrong
password must not. `hash=plain` (salt_position disable): no password is set again, so the fixture stores no clear-text
password (the import check refuses it on the configuration alone).
3. the add-on member is written again with the mnesia folder EMQX left (fileonly: and EMQX's own configs/cluster.hocon),
   every other entry byte-identical; the outer file is an UNENCRYPTED HA backup (backup.json protected false) of that one
   add-on, its name says it is lab-made.
stdout: fixed facts only (sizes, SHA-256, table counts). Secrets are never printed. All containers and volumes of this
tool are removed again.
"""
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LP = str(Path.home() / '.woowbk-lab' / 'bin' / 'labpodman')
IMAGE = 'docker.io/emqx/emqx:5.8.9'
CTR = 'b1lab-emqx-noacl'
VOLUMES = ('b1lab-emqx-noacl-src', 'b1lab-emqx-noacl-log', 'b1lab-emqx-noacl-img')
DATA = 'data/emqx/data'
NODE_FILE = 'data/emqx/node.name'
STAGED = ('mnesia', 'configs/cluster.hocon', 'certs', 'authz')
HA_DATA_DIR = '/data/emqx/data'
SLUGS = {'x86-cold': 'e2bba4b7_woow-emqx', 'arm-cold': '1b7b4ce7_woow-emqx'}
FIXTURE_SHA256 = {'arm-cold': 'b6eb257cc5790bee30500f929d51ade66bfa8354dbe5bb61ba7c4bc08582f664',
                  'x86-cold': '0a53e93888209316040af505484bba3ee3891c2ad2df7ae689bc0d4fd02690f9'}
TABLES = ('emqx_authn_mnesia', 'emqx_authn_scram_mnesia', 'emqx_acl', 'emqx_banned', 'emqx_banned_rules', 'emqx_admin',
          'emqx_app', 'emqx_psk', 'emqx_retainer_message')
COUNT_EXPR = ('[{T, case catch mnesia:table_info(T, size) of N when is_integer(N) -> N; _ -> -1 end} || T <- ['
              + ', '.join(TABLES) + ']].')
NODE_RE = re.compile(r'[A-Za-z0-9_-]{1,64}@[A-Za-z0-9.-]{1,200}')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def lp(*argv, check=True, timeout=600, stdin=None, stdout=subprocess.PIPE):
    proc = subprocess.run([LP, *argv], stdin=stdin, stdout=stdout, stderr=subprocess.PIPE, timeout=timeout)
    if check and proc.returncode:
        raise SystemExit(f'labpodman {argv[0]} failed: rc {proc.returncode}')
    return proc


def emqx(*argv, timeout=120, check=True):
    return lp('exec', CTR, 'emqx', *argv, timeout=timeout, check=check)


SOURCES_EXPR = '[maps:get(type, S) || S <- emqx:get_config([authorization, sources])].'
DELETE_EXPR = ('case emqx_authz:update({delete, built_in_database}, #{}) of {ok, _} -> deleted; _ -> failed end.')


def sources():
    return ''.join(emqx('eval', SOURCES_EXPR).stdout.decode('utf-8', 'replace').split())


def counts():
    text = emqx('eval', COUNT_EXPR).stdout.decode('utf-8', 'replace')
    found = {name: int(value) for name, value in re.findall(r'\{\s*([a-z_]+)\s*,\s*(-?[0-9]{1,12})\s*\}', text) if name in TABLES}
    if len(found) != len(TABLES):
        raise SystemExit('cannot read the table counts')
    return found


def start(node):
    env = {'EMQX_NODE__NAME': node, 'EMQX_NODE__DATA_DIR': HA_DATA_DIR, 'EMQX_DASHBOARD__DEFAULT_PASSWORD': '',
           'EMQX_PLUGINS__STATES': '[]', 'EMQX_PLUGINS__INSTALL_DIR': '/opt/emqx/plugins'}
    argv = ['run', '--detach', '--name', CTR, '--network', 'none', '--pull=never', '--user', '0', '--read-only',
            '--memory', '1g', '--pids-limit', '2048', '--security-opt', 'no-new-privileges',
            '--volume', f'{VOLUMES[0]}:{HA_DATA_DIR}:rw,noexec,nosuid,nodev',
            '--volume', f'{VOLUMES[1]}:/opt/emqx/log:rw,noexec,nosuid,nodev',
            '--volume', f'{VOLUMES[2]}:/opt/emqx/data:rw,noexec,nosuid,nodev']
    host = node.split('@', 1)[1]
    if not re.fullmatch(r'[0-9.]{7,15}', host):
        argv += ['--add-host', f'{host}:127.0.0.1']
    for key, value in sorted(env.items()):
        argv += ['--env', f'{key}={value}']
    lp(*argv, IMAGE)
    deadline = time.monotonic() + 300
    while True:
        proc = emqx('ctl', 'status', timeout=60, check=False)
        if proc.returncode == 0 and b'is started' in proc.stdout:
            return
        if time.monotonic() > deadline:
            raise SystemExit('the throwaway EMQX did not start')
        time.sleep(3)


def stop():
    lp('stop', '--time', '120', CTR, timeout=300)
    state = lp('inspect', CTR, '--format', '{{.State.ExitCode}} {{.State.OOMKilled}}').stdout.decode().strip()
    lp('rm', '--force', CTR)
    if state not in ('0 false', '143 false'):
        raise SystemExit(f'the throwaway EMQX did not stop cleanly ({state})')


def remove_all():
    lp('rm', '--force', '--time', '10', '--ignore', CTR, check=False)
    for name in VOLUMES:
        lp('volume', 'rm', '--force', name, check=False)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


HASHINGS = {'bcrypt': '#{<<"name">> => <<"bcrypt">>, <<"salt_rounds">> => 10}',
            'plain': '#{<<"name">> => <<"plain">>, <<"salt_position">> => <<"disable">>}'}
HASH_UPDATE_EXPR = ('[A0] = [A || A <- emqx:get_raw_config([<<"authentication">>], []), '
                    'maps:get(<<"mechanism">>, A, none) =:= <<"password_based">>, '
                    'maps:get(<<"backend">>, A, none) =:= <<"built_in_database">>], '
                    'A1 = A0#{<<"password_hash_algorithm">> => {hashing}}, '
                    'case emqx_conf:update([authentication], {update_authenticator, \'mqtt:global\', '
                    '<<"password_based:built_in_database">>, A1}, #{rawconf_with_defaults => true, override_to => cluster}) of '
                    '{ok, _} -> hashing_updated; _ -> hashing_failed end.')
PW_FILE = '/tmp/woowbk-fixture-pw'
_ROWS = ('{ok, B} = file:read_file("' + PW_FILE + '"), ok = file:delete("' + PW_FILE + '"), '
         'Rows = [binary:split(L, <<",">>) || L <- binary:split(B, <<"\\n">>, [global, trim_all])], ')
SET_PW_EXPR = (_ROWS + 'R = [emqx_authn_chains:update_user(\'mqtt:global\', <<"password_based:built_in_database">>, U, '
               '#{password => P}) || [U, P] <- Rows], '
               'io:format("WOOWUPD:~b:~b:END", [length(Rows), length([x || {ok, _} <- R])]).')
LOGIN_EXPR = (_ROWS + 'C = fun(U, W) -> case emqx_access_control:authenticate(#{clientid => <<"woowbk-fixture">>, '
              'username => U, password => W, zone => default, listener => \'tcp:default\', protocol => mqtt, '
              'peerhost => {127,0,0,1}, is_superuser => false, mountpoint => undefined}) of {ok, _} -> 1; _ -> 0 end end, '
              'io:format("WOOWLOGIN:~b:~b:~b:END", [length(Rows), lists:sum([C(U, P) || [U, P] <- Rows]), '
              'lists:sum([C(U, <<P/binary, "x">>) || [U, P] <- Rows])]).')


def put_passwords(rows):
    """HA's three MQTT users and their b1 test passwords into the throwaway's tmpfs (stdin; never argv or output)."""
    data = ''.join(f'{user},{password}\n' for user, password in rows).encode()
    proc = subprocess.run([LP, 'exec', '-i', CTR, 'sh', '-c', f'umask 077; cat > {PW_FILE}'], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if proc.returncode:
        raise SystemExit('the password file could not be written into the throwaway')


def answer(expression, mark):
    text = emqx('eval', expression).stdout.decode('utf-8', 'replace')
    match = re.search(mark + r'([0-9:]{1,40}):END', text)
    if not match:
        raise SystemExit('the throwaway EMQX gave no answer')
    return [int(n) for n in match.group(1).split(':')]


def main(argv):
    options = argv[3:]
    if (len(argv) < 3 or argv[0] not in SLUGS or len(set(options)) != len(options)
            or not set(options) <= {'fileonly', 'hash=bcrypt', 'hash=plain'}
            or sum(o.startswith('hash=') for o in options) > 1 or any(o.startswith('hash=') for o in options)
            and 'fileonly' not in options):
        print('usage: emqx_noacl_fixture.py <x86-cold|arm-cold> <private work dir> <out .tar> [fileonly] '
              '[hash=bcrypt|hash=plain] (hash= needs fileonly)', file=sys.stderr)
        return 2
    tag, work, out_path = argv[0], Path(argv[1]).resolve(), Path(argv[2]).resolve()
    fileonly = 'fileonly' in options
    hashing = next((o.split('=', 1)[1] for o in options if o.startswith('hash=')), None)
    if out_path.exists() or work.exists():
        raise SystemExit('work dir or output exists')
    os.umask(0o077)
    work.mkdir(parents=True)
    sys.path.insert(0, str(REPO / 'backup-engine'))
    from woowbackup import habackup, hasecuretar   # the product's own reader
    drv = load('ha_import_b1_e2e', HERE / 'ha_import_b1_e2e.py')
    machine, name = drv.UPLOADS[tag][0], drv.UPLOADS[tag][1]
    src = drv.FIXTURES / machine / name / f'{name}.tar'
    if sha256_file(src) != FIXTURE_SHA256[tag]:
        raise SystemExit('the fixture is not the recorded real backup')
    secrets = drv.Secrets([drv.SECRET_DIR / 'b1-creds.env', drv.SECRET_DIR / 'ha-import-creds.env'],
                          drv.SECRET_DIR / 'dev-d-markers.json')
    ha_users = [(secrets[f'B1_MQTT_USER{i}'], secrets[f'B1_MQTT_PW{i}']) for i in (1, 2, 3)]
    from woowbackup import ha_emqx   # the product's own reading of the hashing (HASH_EXPR, parse_hashing)
    keys = hasecuretar.Keys(secrets['HA_BACKUP_KEY'])
    member_tar = work / 'member.tar'
    with habackup.open_backup(str(src)) as backup:
        slug = SLUGS[tag]
        with open(member_tar, 'xb') as handle:
            stream = backup.open_addon(slug, keys)
            shutil.copyfileobj(stream, handle, 1 << 20)
            stream.finish()
            stream.close()
        supervisor = backup.open_member('supervisor.tar.gz', keys)
        supervisor_plain = supervisor.read()
        supervisor.finish()
        supervisor.close()
    with tarfile.open(src) as outer:
        doc = json.loads(outer.extractfile('./backup.json').read())
        outer_infos = {info.name: info for info in outer.getmembers()}
    # ---- HA's data directory into a lab volume (root-owned like on HA, as the product stages it)
    node = None
    seed = work / 'seed.tar'
    with tarfile.open(member_tar, mode='r:') as old, tarfile.open(seed, mode='w', format=tarfile.PAX_FORMAT) as new:
        for info in old:
            norm = os.path.normpath(info.name)
            if norm == NODE_FILE and info.isreg():
                node = old.extractfile(info).read(1024).decode('ascii', 'replace').strip()
            if not norm.startswith(DATA + '/'):
                continue
            rel = norm[len(DATA) + 1:]
            if not any(rel == item or rel.startswith(item + '/') for item in STAGED) or not (info.isreg() or info.isdir()):
                continue
            entry = tarfile.TarInfo(rel)
            entry.mtime, entry.uid, entry.gid = info.mtime, 0, 0
            if info.isdir():
                entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                new.addfile(entry)
            else:
                entry.size, entry.mode = info.size, 0o644
                new.addfile(entry, old.extractfile(info))
    dirs = set()
    with tarfile.open(seed) as seeded:
        for info in seeded:
            parts = info.name.split('/')
            if parts[0] == 'mnesia' and len(parts) >= 3:
                dirs.add(parts[1])
    if node is None and len(dirs) == 1:
        node = next(iter(dirs))
    if node is None or not NODE_RE.fullmatch(node) or node not in dirs:
        raise SystemExit('HA node name not found')
    remove_all()
    try:
        for volume in VOLUMES:
            lp('volume', 'create', volume)
        with open(seed, 'rb') as handle:
            lp('volume', 'import', VOLUMES[0], '-', stdin=handle, timeout=600)
        start(node)
        before = counts()
        if before['emqx_acl'] < 1:
            raise SystemExit('this backup already holds no ACL row')
        cleared = emqx('eval', 'mnesia:clear_table(emqx_acl).').stdout.decode('utf-8', 'replace').split()
        if ''.join(cleared) != '{atomic,ok}':
            raise SystemExit('clear_table was not confirmed')
        sources_before = sources()
        if fileonly and ''.join(emqx('eval', DELETE_EXPR).stdout.decode('utf-8', 'replace').split()) != 'deleted':
            raise SystemExit('the built-in database source was not deleted')
        hashing_before = updated = None
        if hashing:
            hashing_before = ha_emqx.parse_hashing(emqx('eval', ha_emqx.HASH_EXPR).stdout.decode('utf-8', 'replace'))
            reply = emqx('eval', HASH_UPDATE_EXPR.replace('{hashing}', HASHINGS[hashing])).stdout.decode()
            if reply.split() != ['hashing_updated']:
                raise SystemExit('the hashing was not changed')
            if hashing == 'bcrypt':
                put_passwords(ha_users)
                updated = answer(SET_PW_EXPR, 'WOOWUPD:')
                if updated != [3, 3]:
                    raise SystemExit('HA\'s users did not all get their password again')
        after = counts()
        stop()
        start(node)          # from the same volume: the change must have persisted
        again = counts()
        sources_after = sources()
        hashing_after = logins = None
        if hashing:
            hashing_after = ha_emqx.parse_hashing(emqx('eval', ha_emqx.HASH_EXPR).stdout.decode('utf-8', 'replace'))
            if hashing_after is None or hashing_after['name'] != hashing or not hashing_after['enable']:
                raise SystemExit('the hashing did not persist')
            if hashing == 'bcrypt':
                put_passwords(ha_users)
                logins = answer(LOGIN_EXPR, 'WOOWLOGIN:')
                if logins != [3, 3, 0]:
                    raise SystemExit('HA\'s users do not log in with the new hashing (or a wrong password does)')
        if fileonly and sources_after != '[file]':
            raise SystemExit('HA does not authorize with its ACL file only')
        if not fileonly and sources_after != sources_before:
            raise SystemExit('HA\'s authorization sources changed')
        stop()
        wanted = dict(before, emqx_acl=0)
        stable = [t for t in TABLES if t != 'emqx_retainer_message']   # EMQX rewrites its own $SYS retained messages
        if any(after[t] != wanted[t] or again[t] != wanted[t] for t in stable) or again['emqx_retainer_message'] < 2:
            raise SystemExit('a table other than emqx_acl changed')
        exported = work / 'volume.tar'
        with open(exported, 'xb') as handle:
            lp('volume', 'export', VOLUMES[0], stdout=handle, timeout=600)
    finally:
        remove_all()
    # ---- the add-on member again: the mnesia folder EMQX left, everything else byte-identical
    member_new = work / 'member.new.tar.gz'
    kept = replaced = 0
    prefix = DATA + '/mnesia'
    with tarfile.open(member_tar, mode='r:') as old, open(member_new, 'xb') as raw, \
            gzip.GzipFile(fileobj=raw, mode='wb', compresslevel=6, mtime=0) as packed, \
            tarfile.open(fileobj=packed, mode='w|', format=tarfile.PAX_FORMAT) as new:
        written = False
        hocon_written = False
        for info in old:
            norm = os.path.normpath(info.name)
            if (fileonly or hashing) and norm == f'{DATA}/configs/cluster.hocon':
                with tarfile.open(exported, mode='r:') as vol:
                    for item in vol:
                        if os.path.normpath(item.name) == 'configs/cluster.hocon' and item.isreg():
                            entry = tarfile.TarInfo(info.name)
                            entry.uid, entry.gid, entry.uname, entry.gname = info.uid, info.gid, info.uname, info.gname
                            entry.mode, entry.mtime, entry.size = info.mode, int(item.mtime), item.size
                            new.addfile(entry, vol.extractfile(item))
                            replaced += 1
                            hocon_written = True
                continue
            if norm == prefix or norm.startswith(prefix + '/'):
                if not written:
                    written = True
                    with tarfile.open(exported, mode='r:') as vol:
                        for item in vol:
                            rel = os.path.normpath(item.name)
                            if not (rel == 'mnesia' or rel.startswith('mnesia/')) or not (item.isreg() or item.isdir()):
                                continue
                            entry = tarfile.TarInfo(f'{DATA}/{rel}')
                            entry.uid, entry.gid, entry.uname, entry.gname = info.uid, info.gid, info.uname, info.gname
                            entry.mtime, entry.mode = int(item.mtime), item.mode
                            if item.isdir():
                                entry.type = tarfile.DIRTYPE
                                new.addfile(entry)
                            else:
                                entry.size = item.size
                                new.addfile(entry, vol.extractfile(item))
                            replaced += 1
                continue
            new.addfile(info, old.extractfile(info) if info.isreg() else None)
            kept += 1
        if not written or (fileonly or hashing) and not hocon_written:
            raise SystemExit('no mnesia folder or cluster.hocon in the add-on member')
    doc['name'] = (doc.get('name') or '') + ('（實驗室改製：只用 ACL 檔案、沒有 ACL 規則' if fileonly else '（實驗室改製：沒有 ACL 規則') + (
        f'、MQTT 密碼改用 {hashing}）' if hashing else '）')
    doc['protected'] = False
    doc['crypto'] = None
    out_path.parent.mkdir(parents=True, exist_ok=True)
    supervisor_gz = gzip.compress(supervisor_plain, mtime=0)
    with tarfile.open(out_path, 'x', format=tarfile.PAX_FORMAT) as dest:
        for info_name in outer_infos:
            info = outer_infos[info_name]
            entry = tarfile.TarInfo(info.name)
            entry.uid, entry.gid, entry.uname, entry.gname = info.uid, info.gid, info.uname, info.gname
            entry.mode, entry.mtime = info.mode, int(info.mtime)
            if info.name == f'{SLUGS[tag]}.tar.gz':
                entry.size = member_new.stat().st_size
                with open(member_new, 'rb') as handle:
                    dest.addfile(entry, handle)
            elif info.name == 'supervisor.tar.gz':
                entry.size = len(supervisor_gz)
                dest.addfile(entry, io.BytesIO(supervisor_gz))
            elif info.name == './backup.json':
                data = json.dumps(doc, ensure_ascii=False, indent=2).encode()
                entry.size = len(data)
                dest.addfile(entry, io.BytesIO(data))
            else:
                raise SystemExit('unexpected outer member')
    os.chmod(out_path, 0o600)
    with habackup.open_backup(str(out_path)) as made:   # the product's strict reader accepts it
        stream = made.open_addon(SLUGS[tag])
        info = habackup.read_addon_info(stream)
        stream.close()
    shutil.rmtree(work)
    print(json.dumps({'source_backup_sha256': FIXTURE_SHA256[tag], 'lab_made': True, 'out_sha256': sha256_file(out_path),
                      'out_bytes': out_path.stat().st_size, 'entries_kept': kept, 'mnesia_entries_written': replaced,
                      'addon_version': info.version, 'addon_state': info.state, 'counts_before': before,
                      'counts_after_clear': after, 'counts_after_restart': again,
                      'variant': ('fileonly' if fileonly else 'noacl') + (f'+hash={hashing}' if hashing else ''),
                      'ha_hashing_before': hashing_before, 'ha_hashing_after': hashing_after,
                      'ha_users_password_set_again': updated, 'ha_users_login_after_restart': logins,
                      'ha_sources_before': sources_before, 'ha_sources_after': sources_after}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
