"""T16P (iteration 8, 2026-11-24, lane emqx-secreview SR-OWNER-1942): the product's check path and conversion body
(T15's harness: member_pass -> node_name -> ha_broker -> target_preflight -> device_accounts -> analyse; then
_build_candidate) on crafted HA backups whose MQTT rows EMQX ITSELF wrote in a throwaway SOURCE broker (HA's layout),
against the lab stand-in device of T15 (sha256 + salt suffix, bootstrap `woow` + 13 crafted ids). LAB store only
(labpodman, every container --network none); generated or derived test values only, never printed.

Modes: the gateway-LISTENER `plain` branch (gwl-plain); rows written under `plain` with all-digit passwords
(past-digits) or passwords starting with `$2` (past-dollar2) before HA switched to sha256; clear values stored WITH a
salt by a `hash` bootstrap file (hash-boot); rows a removed STOMP gateway left behind, clear (orphan-plain) or hashed
(orphan-hash); a row of an unknown shape (bad-row, integer hash, written by mnesia:dirty_write); md5 rows under
sha256 (past-md5); controls without a false refusal (mixed-ctl: bcrypt global + pbkdf2 listener + pbkdf2 gateway +
md5 gateway listener + sha512 mqttsn gateway; ctl-sha256); HA's built-in database disabled (db-off, O-3).
Derived passwords: base64(sha256("secrev-t16:" + id)), its first 8 / 12 decimal digits, or "$2" + it; the candidate is
asked INSIDE whether a row stores one of them (counts only).
Run: python3 -I t16_product.py <codebase> <mode>[,<mode>...]"""
import base64
import hashlib
import io
import json
import os
import secrets
import sys
import tarfile
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L  # noqa: E402
import t1_datadir_acl as T1  # noqa: E402
import t15_sr5_review as T15  # noqa: E402

AUTHZ = T15.AUTHZ
SHA = T15.SHA
BCRYPT = T15.BCRYPT
PLAIN_D = T15.PLAIN_D
MD5 = b'name = md5, salt_position = suffix'
authn = T15.authn


def db(algorithm):
    return (b'{ mechanism = password_based, backend = built_in_database, enable = true, user_id_type = username, '
            b'password_hash_algorithm { ' + algorithm + b' } }')


def authn_boot(algorithm, path, kind):
    return (b'authentication = [ { mechanism = password_based, backend = built_in_database, enable = true,\n'
            b'  user_id_type = username, bootstrap_file = "' + path + b'", bootstrap_type = ' + kind +
            b', password_hash_algorithm { ' + algorithm + b' } } ]\n')


GW_LIS_PLAIN = (b'gateway.stomp {\n  mountpoint = "stomp/"\n  listeners.tcp.default { bind = "61613", authentication = '
                + db(PLAIN_D) + b' }\n}\n')
GW_PLAIN = b'gateway.stomp {\n  mountpoint = "stomp/"\n  listeners.tcp.default { bind = "61613" }\n  authentication = ' \
    + db(PLAIN_D) + b'\n}\n'
GW_SHA = b'gateway.stomp {\n  mountpoint = "stomp/"\n  listeners.tcp.default { bind = "61613" }\n  authentication = ' \
    + db(b'name = sha256, salt_position = prefix') + b'\n}\n'
MIXED = (AUTHZ + authn(BCRYPT)
         + b'listeners.tcp.default {\n  bind = "0.0.0.0:1883"\n  authentication = [ '
         + db(b'name = pbkdf2, mac_fun = sha256, iterations = 3, dk_length = 12') + b' ]\n}\n'
         + b'gateway.stomp {\n  mountpoint = "stomp/"\n  listeners.tcp.default { bind = "61613", authentication = '
         + db(MD5) + b' }\n  authentication = ' + db(b'name = pbkdf2, mac_fun = sha512, iterations = 3, dk_length = 24')
         + b'\n}\n'
         + b'gateway.mqttsn {\n  mountpoint = "mqttsn/"\n  listeners.udp.default { bind = "1884" }\n  authentication = '
         + db(b'name = sha512, salt_position = prefix') + b'\n}\n')
BOOT_PATH = b'/data/emqx/data/boot-hash.csv'
PREFIX = b'secrev-t16:'


def derived(uid, kind):
    """The test password of a row (never a real one); the source and candidate brokers compute the same inside."""
    b64 = base64.b64encode(hashlib.sha256(PREFIX + uid).digest())
    if kind == 'digits8':
        return str(int.from_bytes(hashlib.sha256(PREFIX + uid).digest(), 'big')).encode()[:8]
    if kind == 'digits12':
        return str(int.from_bytes(hashlib.sha256(PREFIX + uid).digest(), 'big')).encode()[:12]
    if kind == 'dollar2':
        return b'$2' + b64
    return b64


DERIVE = ('B = fun(U) -> base64:encode(crypto:hash(sha256, <<"secrev-t16:", U/binary>>)) end, '
          'Dg = fun(U, N) -> list_to_binary(lists:sublist(integer_to_list(binary:decode_unsigned(crypto:hash(sha256, '
          '<<"secrev-t16:", U/binary>>))), N)) end, '
          'P = fun(U, b64) -> B(U); (U, digits8) -> Dg(U, 8); (U, digits12) -> Dg(U, 12); '
          '(U, dollar2) -> <<"$2", (B(U))/binary>>; (_, random) -> base64:encode(crypto:strong_rand_bytes(12)) end, ')
CLEAR16 = ('B = fun(U) -> base64:encode(crypto:hash(sha256, <<"secrev-t16:", U/binary>>)) end, '
           'Dg = fun(U, N) -> list_to_binary(lists:sublist(integer_to_list(binary:decode_unsigned(crypto:hash(sha256, '
           '<<"secrev-t16:", U/binary>>))), N)) end, '
           'Ds = fun(U) when is_binary(U) -> [B(U), Dg(U, 8), Dg(U, 12), <<"$2", (B(U))/binary>>]; (_) -> [] end, '
           'Rows = ets:tab2list(emqx_authn_mnesia), '
           'Clear = [x || R <- Rows, lists:member(element(3, R), Ds(element(2, element(2, R))))], '
           'Groups = lists:usort([element(1, element(2, R)) || R <- Rows]), '
           'io:format("WOOWCLEAR:rows=~b:clear=~b:groups=~w:END", [length(Rows), length(Clear), Groups]).')
BAD_ROW = ('ok = mnesia:dirty_write(emqx_authn_mnesia, {user_info, {\'mqtt:global\', <<"t16-bad-int">>}, 12345, <<>>, '
           'false}), io:format("WOOWBAD:ok:END").')


def boot_csv(uids):
    lines = [b'user_id,password_hash,salt,is_superuser']
    for uid in uids:   # the clear test value stored AS the hash, with a non-empty salt (a `hash` import)
        lines.append(uid + b',' + derived(uid, 'b64') + b',' + secrets.token_hex(16).encode() + b',false')
    return b'\n'.join(lines) + b'\n'


# expect: blocker kind at the check ('PLAIN_ELSEWHERE', 'CLEAR_ROWS', 'HASH_UNREADABLE', None) + names (CLEAR_ROWS),
# warning ('ACCOUNTS_STOP', 'DB_OFF', None), conversion ('REFUSED' before the export, 'PASSED', 'REFUSED-LATE').
MODES = {
    'gwl-plain': {'staged': AUTHZ + authn(SHA) + GW_LIS_PLAIN,
                  'users': [('stomp:tcp:default', b't16-gwl-a', 'b64'), ('stomp:tcp:default', b't16-gwl-b', 'b64')],
                  'convert': True, 'blocker': 'PLAIN_ELSEWHERE'},
    'past-digits': {'staged': AUTHZ + authn(SHA), 'maker': AUTHZ + authn(PLAIN_D),
                    'users': [('mqtt:global', b't16-dig-a', 'digits8'), ('mqtt:global', b't16-dig-b', 'digits12')],
                    'convert': True, 'blocker': 'CLEAR_ROWS', 'names': [('t16-dig-a', 'mqtt:global'),
                                                                        ('t16-dig-b', 'mqtt:global')]},
    'past-dollar2': {'staged': AUTHZ + authn(SHA), 'maker': AUTHZ + authn(PLAIN_D),
                     'users': [('mqtt:global', b't16-dol-a', 'dollar2'), ('mqtt:global', b't16-dol-b', 'dollar2')],
                     'convert': True, 'blocker': 'CLEAR_ROWS', 'names': [('t16-dol-a', 'mqtt:global'),
                                                                         ('t16-dol-b', 'mqtt:global')]},
    'hash-boot': {'staged': AUTHZ + authn(SHA), 'maker': AUTHZ + authn_boot(SHA, BOOT_PATH, b'hash'),
                  'files': {'boot-hash.csv': lambda: boot_csv([b't16-hb-a', b't16-hb-b'])}, 'users': [],
                  'convert': True, 'blocker': 'CLEAR_ROWS', 'names': [('t16-hb-a', 'mqtt:global'),
                                                                      ('t16-hb-b', 'mqtt:global')]},
    'orphan-plain': {'staged': AUTHZ + authn(SHA), 'maker': AUTHZ + authn(SHA) + GW_PLAIN,
                     'users': [('stomp:global', b't16-orp-a', 'b64'), ('stomp:global', b't16-orp-b', 'b64')],
                     'convert': True, 'blocker': 'CLEAR_ROWS', 'names': [('t16-orp-a', 'stomp:global'),
                                                                         ('t16-orp-b', 'stomp:global')]},
    'orphan-hash': {'staged': AUTHZ + authn(SHA), 'maker': AUTHZ + authn(SHA) + GW_SHA,
                    'users': [('stomp:global', b't16-orh-a', 'random'), ('stomp:global', b't16-orh-b', 'random')],
                    'convert': True, 'blocker': None},
    'bad-row': {'staged': AUTHZ + authn(SHA), 'users': [('mqtt:global', b't16-bad-ok', 'random')], 'post': BAD_ROW,
                'convert': True, 'blocker': 'HASH_UNREADABLE'},
    'past-md5': {'staged': AUTHZ + authn(SHA), 'maker': AUTHZ + authn(MD5),
                 'users': [('mqtt:global', b't16-md5-a', 'random'), ('mqtt:global', b't16-md5-b', 'random')],
                 'convert': False, 'blocker': 'CLEAR_ROWS', 'names': [('t16-md5-a', 'mqtt:global'),
                                                                      ('t16-md5-b', 'mqtt:global')]},
    'mixed-ctl': {'staged': MIXED, 'users': [(c, u, 'random') for c, u in (
        ('mqtt:global', b't16-mx-g1'), ('mqtt:global', b't16-mx-g2'), ('tcp:default', b't16-mx-t1'),
        ('tcp:default', b't16-mx-t2'), ('stomp:global', b't16-mx-s1'), ('stomp:global', b't16-mx-s2'),
        ('stomp:tcp:default', b't16-mx-st1'), ('stomp:tcp:default', b't16-mx-st2'), ('mqtt-sn:global', b't16-mx-m1'),
        ('mqtt-sn:global', b't16-mx-m2'))], 'convert': True, 'blocker': None, 'warning': 'ACCOUNTS_STOP'},
    'ctl-sha256': {'staged': AUTHZ + authn(SHA), 'users': [('mqtt:global', b't16-ctl-a', 'random'),
                                                           ('mqtt:global', b't16-ctl-b', 'random')],
                   'convert': True, 'blocker': None},
    'db-off': {'staged': AUTHZ + authn(SHA, b'false'), 'users': [('mqtt:global', b't16-off-a', 'random')],
               'convert': True, 'blocker': None, 'warning': 'DB_OFF'},
}


def make_source(mode, spec):
    """EMQX itself writes the mode's rows in a throwaway source broker in HA's layout; returns ({mnesia files}, its
    own answers: rows added, crafted row, clear rows by the derived values)."""
    vol, img, log = (f'woowbk-secrev-t16src-{mode}-{part}' for part in ('data', 'img', 'log'))
    ctr = f'woowbk-secrev-t16src-{mode}-emqx'
    for name in (vol, img, log):
        L.lab('volume', 'create', '--label', L.LABEL, name)
    try:
        files = {'configs/cluster.hocon': spec.get('maker') or spec['staged'], 'authz/acl.conf': T1.HA_ACL}
        for name, make in (spec.get('files') or {}).items():
            files[name] = make()
        L.lab('volume', 'import', vol, '-', input=L.tar_bytes(files, uid=1000, gid=1000))
        del files
        L.lab('run', '-d', '--name', ctr, '--label', L.LABEL, '--network', 'none', '--pull=never', '--memory', '1g',
              '-e', 'EMQX_NODE__NAME=emqx@127.0.0.1', '-e', 'EMQX_NODE__DATA_DIR=/data/emqx/data',
              '-e', 'EMQX_DASHBOARD__DEFAULT_PASSWORD=', '-v', f'{vol}:/data/emqx/data', '-v', f'{img}:/opt/emqx/data',
              '-v', f'{log}:/opt/emqx/log', L.IMAGE)

        def execute(command):
            return L.lab('exec', ctr, *command, timeout=180, check=False)
        if not T15.wait_started(execute):
            raise RuntimeError('source broker did not start')
        out = {}
        if spec['users']:
            users = ', '.join("{'" + c + "', <<\"" + u.decode() + '">>, ' + k + '}' for c, u, k in spec['users'])
            out['added'] = T15.mark(execute(['emqx', 'eval', DERIVE + 'R = [catch emqx_authn_chains:add_user(C, '
                                             '<<"password_based:built_in_database">>, #{user_id => U, password => '
                                             'P(U, K)}) || {C, U, K} <- [' + users + ']], io:format("WOOWADD:~b:~b:END",'
                                             ' [length([x || {ok, _} <- R]), length(R)]).']), 'WOOWADD:')
        if spec.get('post'):
            out['post'] = T15.mark(execute(['emqx', 'eval', spec['post']]), 'WOOWBAD:')
        out['source_clear'] = T15.mark(execute(['emqx', 'eval', CLEAR16]), 'WOOWCLEAR:')
        L.lab('stop', '-t', '60', ctr, timeout=180)
        data = L.lab('volume', 'export', vol, timeout=300).stdout
    finally:
        L.lab('rm', '-f', '-t', '0', ctr, check=False)
        for name in (vol, img, log):
            L.lab('volume', 'rm', '-f', name, check=False)
    mnesia = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar:
            name = member.name.lstrip('./')
            if member.isfile() and name.startswith('mnesia/emqx@127.0.0.1/'):
                mnesia[name] = tar.extractfile(member).read()
    return mnesia, out


def shown(names):
    """Independent copy of how the refusal names rows: the id, a non-global group in brackets."""
    return '、'.join(u if g == 'mqtt:global' else f'{u}（{g}）' for u, g in names)


def kind_of(ha_emqx, text, device_names):
    if text == ha_emqx.PLAIN_ELSEWHERE:
        return 'PLAIN_ELSEWHERE'
    if text == ha_emqx.PLAIN_REFUSED:
        return 'PLAIN_REFUSED'
    if text.startswith(ha_emqx.HASH_UNREADABLE.format(side='HA 的')):
        return 'HASH_UNREADABLE'
    head = ha_emqx.CLEAR_ROWS.split('{names}')[0]
    if text.startswith(head):
        return 'CLEAR_ROWS'
    return 'other'


def one(ha_emqx, mode, *, runner, target, own_ids, staging_root):
    spec = MODES[mode]
    out = {'staged_sha256': L.digest(spec['staged']), 'expect': {k: spec.get(k) for k in ('blocker', 'warning')}}
    started = time.time()
    mnesia, out['source'] = make_source(mode, spec)
    out['source_mnesia_files'] = len(mnesia)
    inner = T15.addon_tar(spec['staged'], mnesia)
    app = L.SimpleNamespace(id='emqx', name='EMQX')
    texts = []
    device_names = T15.expected_names(own_ids)
    holder = {'profile': None}

    def fresh_work():
        work = L.FakeWork(runner)
        work.addon_member = lambda slug: slug
        work.open = lambda member: io.BytesIO(inner)
        work.addon_info = lambda slug: L.SimpleNamespace(version='5.9.1')
        return work

    device_reads = lambda: T15.mark(target.execute(['emqx', 'eval', T15.DIGEST]), 'WOOWDIG:')
    work = fresh_work()
    before = device_reads()
    with L.temp(runner) as tmp:
        try:
            src = ha_emqx.member_pass(work, tmp)
            node, blocker = ha_emqx.node_name(src)
            readings = None
            if blocker is None:
                readings = ha_emqx.ha_broker(work, tmp, target, src, node)
                ha_emqx._clean(tmp, 'emqx-ha', volumes=('emqx-src', 'emqx-ha-log'))
            try:
                profile, target_blocker = ha_emqx.target_preflight(work, app, target)
            except Exception as error:   # recorded, not hidden
                profile, target_blocker = None, None
                out['preflight_error'] = type(error).__name__
            holder['profile'] = profile
            device = ha_emqx.device_accounts(ha_emqx.device_execute(work, app, target))
            blockers, warnings = ha_emqx.analyse(src, readings, addon_version='5.9.1', version='5.8.9',
                                                 profile=profile, device=device)
            if blocker:
                blockers.insert(0, blocker)
            if target_blocker:
                blockers.append(target_blocker)
            texts += blockers + warnings
            kinds = [kind_of(ha_emqx, b, device_names) for b in blockers]
            sr5 = [w for w in warnings if '保存 MQTT 密碼的方式' in w]
            off = [w for w in warnings if w.startswith('HA 的 EMQX 沒有啟用內建資料庫的帳號密碼認證')]
            out['check'] = {'blockers': kinds, 'accounts_stop': len(sr5), 'db_off': len(off),
                            'plain_answer': None if readings is None else {
                                k: readings['plain'][k] for k in ('elsewhere', 'clear')}}
            if spec.get('names'):
                want = ha_emqx.CLEAR_ROWS.format(names=shown(spec['names']))
                out['check']['clear_rows_exact'] = want in blockers
            if sr5 and device is not None:
                exp = T15.STOP.format(ha=T15.words(readings['hashing']), mine=T15.words(device['hashing']),
                                      names=device_names)
                out['check']['accounts_stop_exact'] = sr5 == [exp]
            if off:
                out['check']['db_off_exact'] = off == [ha_emqx.DB_OFF.format(names=device_names)]
        except L.BackupError as error:
            out['check'] = {'refused': kind_of(ha_emqx, error.message, device_names)}
            texts.append(error.message)
    texts += work.logs
    after = device_reads()
    out['device_read_only_check'] = {'equal': before == after and before != 'unreadable'}
    if spec['convert']:
        calls = []
        real_ctl = ha_emqx.ctl

        def spy(tmp_, role, args, *rest, **kw):
            calls.append((role, list(args[:2])))
            return real_ctl(tmp_, role, args, *rest, **kw)
        ha_emqx.ctl = spy
        work = fresh_work()
        staging = Path(tempfile.mkdtemp(prefix=f't16-{mode}-', dir=staging_root))
        before = device_reads()
        try:
            with L.temp(runner) as tmp:
                try:
                    device = ha_emqx.device_accounts(ha_emqx.device_execute(work, app, target))
                    _s, _n, readings, _e, _c, _st, _la, _rb, _p = ha_emqx._build_candidate(
                        work, app, tmp, target, staging, version='5.8.9', profile=holder['profile'])
                    out['conversion'] = 'PASSED (candidate built, all product checks green)'
                    notes, reminders = ha_emqx.import_texts({'hash_change': ha_emqx.hash_change(readings['hashing'],
                                                                                               device)})
                    texts += notes + reminders
                except L.BackupError as error:
                    message = error.message
                    out['conversion'] = 'REFUSED: ' + kind_of(ha_emqx, message.replace('EMQX 不能搬過來：', '', 1),
                                                              device_names)
                    if out['conversion'] == 'REFUSED: other':
                        out['conversion'] += ' ' + message[:160]
                    texts.append(message)
                texts += work.logs
                if tmp.running('emqx-new'):
                    inside = lambda c: tmp.exec('emqx-new', c, timeout=120, check=False)
                    out['candidate_clear'] = T15.mark(inside(['emqx', 'eval', CLEAR16]), 'WOOWCLEAR:')
                    out['candidate_leak'] = T15.mark(inside(['emqx', 'eval', T15.leak_expr('\n'.join(texts))]),
                                                     'WOOWLEAK:')
        finally:
            ha_emqx.ctl = real_ctl
        out['export_called'] = any(role == 'emqx-ha' and args == ['data', 'export'] for role, args in calls)
        after = device_reads()
        out['device_read_only_conversion'] = {'equal': before == after and before != 'unreadable'}
    out['device_leak'] = T15.mark(target.execute(['emqx', 'eval', T15.leak_expr('\n'.join(texts))], timeout=180),
                                  'WOOWLEAK:')
    out['text_scan'] = T15.text_scan(texts)
    clear = out.get('candidate_clear', '')
    out['plaintext_rows_in_candidate'] = int(clear.split('clear=', 1)[1].split(':', 1)[0]) if 'clear=' in clear else 0
    out['elapsed_s'] = round(time.time() - started, 1)
    return out


def main(codebase, modes):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': 'T16P stored-form refusal, gateway-listener plain and unknown-format rows through the product '
                      'check path and conversion body (rows written by EMQX itself)',
              'codebase': codebase, 'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)',
              'modes': {}}
    runs = os.path.join(L.SR, 'runs')
    host_dir = tempfile.mkdtemp(prefix='t16-host-', dir=runs)
    os.chmod(host_dir, 0o755)
    acl_host = os.path.join(host_dir, 'acl.conf')
    with open(acl_host, 'wb') as handle:
        handle.write(T1.TARGET_ACL)
    os.chmod(acl_host, 0o644)
    secret = 'secrev-t16-bootstrap'
    pwd = secrets.token_hex(16)   # this device's own MQTT account password (generated, never printed)
    L.lab('secret', 'rm', secret, check=False)
    L.lab('secret', 'create', secret, '-', input=b'user_id,password,is_superuser\nwoow,' + pwd.encode() + b',false\n')
    del pwd
    target = L.LabTarget('t16', {'configs/cluster.hocon': T1.target_hocon('/opt/emqx/etc/acl.conf')},
                         ro_files=[(acl_host, '/opt/emqx/etc/acl.conf', 'ro')],
                         secrets_spec=[f'{secret},type=mount,target={T1.BOOT},uid=1000,gid=1000,mode=0400'])
    try:
        ids = ', '.join('base64:decode(<<"' + base64.b64encode(i).decode() + '">>)' for i in T15.CRAFTED)
        result['device_users_added'] = T15.mark(target.execute(['emqx', 'eval', 'R = [emqx_authn_chains:add_user('
                                                                '\'mqtt:global\', <<"password_based:built_in_database">>, '
                                                                '#{user_id => U, password => base64:encode(crypto:'
                                                                'strong_rand_bytes(12))}) || U <- [' + ids + ']], '
                                                                'io:format("WOOWADD:~b:END", [length([x || {ok, _} <- R])'
                                                                ']).']), 'WOOWADD:')
        own_ids = [b'woow'] + T15.CRAFTED
        runner = L.make_runner()
        for mode in modes:
            try:
                result['modes'][mode] = one(ha_emqx, mode, runner=runner, target=target, own_ids=own_ids,
                                            staging_root=runs)
            except Exception as error:   # one mode's harness failure is recorded; the others still run
                result['modes'][mode] = {'harness_error': type(error).__name__ + ': ' + str(error)[:300]}
            print(mode, json.dumps(result['modes'][mode], ensure_ascii=False)[:3000], flush=True)
    finally:
        target.remove()
        L.lab('secret', 'rm', secret, check=False)
    left = L.lab('ps', '-a', '--filter', 'label=' + L.LABEL, '--format', '{{.Names}}', check=False).stdout.split()
    vols = L.lab('volume', 'ls', '--filter', 'label=' + L.LABEL, '--format', '{{.Name}}', check=False).stdout.split()
    result['lab_left'] = {'containers': len(left), 'volumes': len(vols)}
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps({'elapsed_s': result['elapsed_s'], 'lab_left': result['lab_left']}), flush=True)
    L.evidence(os.path.join(runs, f't16p-{codebase}-{"-".join(modes)}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2].split(','))
