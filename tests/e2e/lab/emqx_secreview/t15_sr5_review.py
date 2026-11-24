"""T15 (iteration 7, 2026-11-24, lane emqx-secreview SR-OWNER-1942): narrow security re-review of SR-5 option C
(fix/emqx-sr5-hash-warning-20261124 @ 3c857c3, engine 5142e05c). The product's own code runs against real EMQX 5.8.9
brokers in the LAB store (labpodman, its own --root; every container --network none); generated values only.

- This device (LabTarget: sha256 + salt suffix, a bootstrap CSV with `woow` and a generated password as a podman
  secret) gets 13 more built-in database users with crafted ids (a terminal escape, a line break, a bidi control, HTML,
  the separators and markers of the product's own USERS_EXPR answer, 200 characters, invalid UTF-8, a zero-width
  space, a tab, format directives, the list separator). Their passwords are random INSIDE the broker, never seen here.
- Check path = the product's: member_pass -> node_name -> ha_broker -> _clean -> target_preflight ->
  device_accounts(device_execute) -> analyse. Conversion path = _build_candidate, then hash_change + import_texts.
- LEAK: every text the product produced (blockers, warnings, job log, notes, reminders, refusal messages) is handed
  INTO this device's broker (and the candidate's), which answers how many stored password hashes / salts of its rows
  and whether its bootstrap password occur in that text (counts and true/false only).
- READ-ONLY: a digest of this device's user table + raw authentication config before and after the product's reads.
- EXPORT ORDER: ha_emqx.ctl is wrapped to record whether HA's `data export` ran before a refusal.
- PLAINTEXT: rows that EMQX itself wrote under a `plain` authenticator (a STOMP gateway's, an MQTT listener's, or the
  global one before HA changed its hashing) are made in a throwaway SOURCE broker; their passwords are derived from the
  user id (base64 of sha256 of a fixed prefix + id: test values, never real) so a broker can be asked, inside, how many
  of its rows hold one in clear text.
Run: python3 -I t15_sr5_review.py <codebase> <mode>[,<mode>...]   (modes: MODES)"""
import base64
import io
import json
import os
import re
import secrets
import sys
import tarfile
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L  # noqa: E402
import t1_datadir_acl as T1  # noqa: E402

AUTHZ = (b'authorization {\n  no_match = allow\n  deny_action = ignore\n  sources = [ { type = file, enable = true, '
         b'path = "/data/emqx/data/authz/acl.conf" } ]\n}\n')
SHA = b'name = sha256, salt_position = suffix'
PLAIN_D = b'name = plain, salt_position = disable'
PLAIN_S = b'name = plain, salt_position = suffix'
BCRYPT = b'name = bcrypt, salt_rounds = 10'
BUILTIN_PLAIN = (b'{ mechanism = password_based, backend = built_in_database, enable = true, user_id_type = username, '
                 b'password_hash_algorithm { name = plain, salt_position = disable } }')
GATEWAY = (b'gateway.stomp {\n  mountpoint = "stomp/"\n  listeners.tcp.default { bind = "61613" }\n'
           b'  authentication = ' + BUILTIN_PLAIN + b'\n}\n')
LISTENER = b'listeners.tcp.default {\n  bind = "0.0.0.0:1883"\n  authentication = [ ' + BUILTIN_PLAIN + b' ]\n}\n'


def authn(algorithm, enable=b'true'):
    return (b'authentication = [ { mechanism = password_based, backend = built_in_database, enable = ' + enable +
            b',\n  user_id_type = username, password_hash_algorithm { ' + algorithm + b' } } ]\n')


# staged = HA's cluster.hocon in the backup; maker = (chain, the source broker's config when it differs) for rows
# EMQX writes under a `plain` authenticator before the backup is made.
MODES = {
    'plain-off': {'staged': AUTHZ + authn(PLAIN_S, b'false'), 'convert': False},
    'same': {'staged': AUTHZ + authn(SHA), 'convert': False},
    'bcrypt': {'staged': AUTHZ + authn(BCRYPT), 'convert': True},
    'conv-plain': {'staged': AUTHZ + authn(PLAIN_D), 'convert': True},
    'gw-plain': {'staged': AUTHZ + authn(SHA) + GATEWAY, 'maker': ('stomp:global', None), 'convert': True},
    'listener-plain': {'staged': AUTHZ + authn(SHA) + LISTENER, 'maker': ('tcp:default', None), 'convert': True},
    'past-plain': {'staged': AUTHZ + authn(SHA), 'maker': ('mqtt:global', AUTHZ + authn(PLAIN_D)), 'convert': True},
}
MAKER_USERS = (b't15-plain-a', b't15-plain-b')
DERIVE = 'D = fun(U) -> base64:encode(crypto:hash(sha256, <<"secrev-t15-plain:", U/binary>>)) end, '
CLEAR = (DERIVE + 'Rows = ets:tab2list(emqx_authn_mnesia), '
         'Clear = [x || R <- Rows, element(3, R) =:= D(element(2, element(2, R)))], '
         'Groups = lists:usort([element(1, element(2, R)) || R <- Rows]), '
         'io:format("WOOWCLEAR:rows=~b:clear=~b:groups=~w:END", [length(Rows), length(Clear), Groups]).')
DIGEST = ('io:format("WOOWDIG:~s:END", [binary:encode_hex(crypto:hash(sha256, term_to_binary({lists:sort(ets:tab2list('
          'emqx_authn_mnesia)), emqx:get_raw_config([authentication], [])}, [deterministic])))]).')
CRAFTED = [b'0-esc\x1b[31mred', b'1-newline\nINJECT', b'2-tab\tname', '3-bidi\u202etxt.exe'.encode(), b'4-' + b'x' * 200,
           b'5-\xff\xfe-invalid', b'6-%s~p~s{0}{names}', '7-\u3001separator'.encode(), b'8-<img src=x onerror=alert(1)>',
           b'WOOWUSERS:1:d29vdw==:END', b'e-comma,f-fake', b'g-marker:END', 'j-\u200bzero'.encode()]
# (sorted bytewise the first ten are the ten above 'e-'; 'woow' sorts last: the warning shows ten and the count)
# Independent copies (the harness must not trust the product's own constants): hacommon CONTROL_RE's class and the
# owner-decided texts of SR-5 option C as 3c857c3 words them.
CONTROL = re.compile('[\x00-\x1f\x7f-\x9f  ؜‎‏‪-‮⁦-⁩]')
RESET = ('到這台 EMQX 管理頁「存取控制 → 認證」的內建資料庫替這些帳號重設密碼或重新建立；由這台 bootstrap 帳號檔建立的帳號，'
         '刪除後重新啟動 EMQX 就會用原本的密碼建回。')
STOP = ('HA 的 EMQX 保存 MQTT 密碼的方式（{ha}）和這台（{mine}）不同，匯入後以 HA 的為準：這台現有的 MQTT 帳號'
        '（{names}）匯入後無法再用原本的密碼登入，要在匯入後重新設定：' + RESET)
NOTE = ('HA 的 EMQX 保存 MQTT 密碼的方式（{ha}）和這台（{mine}）不同，匯入後以 HA 的為準：這台原本的 MQTT 帳號（{names}）'
        '無法再用原本的密碼登入。')
REMINDER = '請重新設定這台原本的 MQTT 帳號（{names}）：' + RESET
PLAIN_MARK = '「plain」（不加密）'
CLEAR_MARK = '明文'
HEXRUN = re.compile(r'[0-9a-fA-F]{24,}')


def mark(out, tag):
    text = (out.stdout or b'').decode('utf-8', 'replace') if not isinstance(out, str) else out
    return text.split(tag, 1)[1].split(':END', 1)[0] if tag in text else 'unreadable'


def wait_started(execute, timeout=240):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if b'is started' in (execute(['emqx', 'ctl', 'status']).stdout or b''):
            return True
        time.sleep(3)
    return False


def make_ha_mnesia(mode, chain, maker_hocon):
    """EMQX itself writes MAKER_USERS into `chain` under the maker config's `plain` authenticator; returns
    ({'mnesia/<node>/<file>': bytes}, the source broker's own CLEAR answer). The source broker runs HA's layout (data
    dir /data/emqx/data with HA's authz/acl.conf, like ha_broker: HA's file source names that path), the image's
    VOLUME paths on labelled volumes. First attempt (t15-sr5) used /opt/emqx/data: HA's ACL path did not exist there and
    the broker never reported started (kept as evidence)."""
    vol, img, log = (f'woowbk-secrev-t15src-{mode}-{part}' for part in ('data', 'img', 'log'))
    ctr = f'woowbk-secrev-t15src-{mode}-emqx'
    for name in (vol, img, log):
        L.lab('volume', 'create', '--label', L.LABEL, name)
    try:
        L.lab('volume', 'import', vol, '-', input=L.tar_bytes({'configs/cluster.hocon': maker_hocon,
                                                               'authz/acl.conf': T1.HA_ACL}, uid=1000, gid=1000))
        L.lab('run', '-d', '--name', ctr, '--label', L.LABEL, '--network', 'none', '--pull=never', '--memory', '1g',
              '-e', 'EMQX_NODE__NAME=emqx@127.0.0.1', '-e', 'EMQX_NODE__DATA_DIR=/data/emqx/data',
              '-e', 'EMQX_DASHBOARD__DEFAULT_PASSWORD=', '-v', f'{vol}:/data/emqx/data', '-v', f'{img}:/opt/emqx/data',
              '-v', f'{log}:/opt/emqx/log', L.IMAGE)

        def execute(command):
            return L.lab('exec', ctr, *command, timeout=180, check=False)
        if not wait_started(execute):
            tail = L.lab('logs', '--tail', '40', ctr, check=False)
            private = os.path.join(L.SR, 'runs', f't15src-{mode}-logs.txt')   # lab broker output, not evidence
            with open(os.open(private, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'wb') as handle:
                handle.write((tail.stdout or b'') + b'\n--- stderr ---\n' + (tail.stderr or b''))
            raise RuntimeError(f'source broker did not start (its last log lines: {os.path.basename(private)})')
        users = ', '.join('<<"' + u.decode() + '">>' for u in MAKER_USERS)
        added = mark(execute(['emqx', 'eval', DERIVE + 'R = [emqx_authn_chains:add_user(\'' + chain + '\', '
                              '<<"password_based:built_in_database">>, #{user_id => U, password => D(U)}) || U <- ['
                              + users + ']], io:format("WOOWADD:~b:END", [length([x || {ok, _} <- R])]).']),
                     'WOOWADD:')
        source = mark(execute(['emqx', 'eval', CLEAR]), 'WOOWCLEAR:')
        L.lab('stop', '-t', '60', ctr, timeout=180)
        data = L.lab('volume', 'export', vol, timeout=300).stdout
    finally:
        L.lab('rm', '-f', '-t', '0', ctr, check=False)
        for name in (vol, img, log):
            L.lab('volume', 'rm', '-f', name, check=False)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar:
            name = member.name.lstrip('./')
            if member.isfile() and name.startswith('mnesia/emqx@127.0.0.1/'):
                files[name] = tar.extractfile(member).read()
    return files, f'added={added}:{source}'


def addon_tar(staged, mnesia):
    base = 'data/emqx/data/'
    files = {'addon.json': json.dumps({'system': {'slug': 'woow-emqx', 'name': 'EMQX'}, 'version': '5.9.1',
                                       'user': {'image': 'ghcr.io/woowtech/woow-ha-emqx-amd64'},
                                       'state': 'stopped'}).encode(),
             'data/emqx/node.name': b'emqx@127.0.0.1\n', base + 'configs/cluster.hocon': staged,
             base + 'authz/acl.conf': T1.HA_ACL}
    if mnesia:
        files.update({base + name: body for name, body in mnesia.items()})
    else:
        files[base + 'mnesia/emqx@127.0.0.1'] = None
    return L.tar_bytes(files)


def leak_expr(text):
    b64 = base64.b64encode(text.encode('utf-8')).decode()
    return ('T = base64:decode(<<"' + b64 + '">>), {ok, B} = file:read_file("' + T1.BOOT + '"), '
            '[_, Row | _] = binary:split(B, <<"\\n">>, [global]), [_, P | _] = binary:split(Row, <<",">>, [global]), '
            'In = fun(X) when is_binary(X), byte_size(X) >= 8 -> binary:match(T, X) =/= nomatch; (_) -> false end, '
            'Rows = ets:tab2list(emqx_authn_mnesia), '
            'io:format("WOOWLEAK:rows=~b:hash=~b:salt=~b:pwd=~s:END", [length(Rows), '
            'length([x || R <- Rows, In(element(3, R))]), length([x || R <- Rows, In(element(4, R))]), In(P)]).')


def text_scan(texts):
    joined = '\n'.join(texts)
    return {'texts': len(texts), 'control_chars': sum(1 for t in texts if CONTROL.search(t)),
            'hex_runs_24': len(HEXRUN.findall(joined)), 'bcrypt_prefix': joined.count('$2')}


def words(hashing):
    """Independent copy of how SR-5's texts name one hashing (3c857c3 hashing_text)."""
    if hashing['name'] == 'pbkdf2':
        length = f'，{hashing["dk_length"]} 位元組' if hashing['dk_length'] else ''
        return f'pbkdf2（{hashing["mac_fun"]}，{hashing["iterations"]} 次{length}）'
    if hashing['name'] == 'bcrypt':
        return 'bcrypt'
    return hashing['name'] + {'prefix': '，鹽在前', 'suffix': '，鹽在後', 'disable': '，不加鹽'}.get(hashing['salt'], '')


def expected_names(ids):
    ids = sorted(ids)
    first = [CONTROL.sub('?', i.decode('utf-8', 'replace')[:60]) for i in ids[:10]]
    return '、'.join(first) + (f' 等 {len(ids)} 個' if len(ids) > 10 else '')


def one(ha_emqx, mode, *, runner, target, own_ids, staging_root):
    spec = MODES[mode]
    out = {'staged_sha256': L.digest(spec['staged']), 'preflight': {}}
    started = time.time()
    mnesia = None
    if spec.get('maker'):
        chain, maker_hocon = spec['maker']
        mnesia, out['source_broker'] = make_ha_mnesia(mode, chain, maker_hocon or spec['staged'])
        out['source_mnesia_files'] = len(mnesia)
    inner = addon_tar(spec['staged'], mnesia)
    app = L.SimpleNamespace(id='emqx', name='EMQX')
    texts = []

    def fresh_work():
        work = L.FakeWork(runner)
        work.addon_member = lambda slug: slug
        work.open = lambda member: io.BytesIO(inner)
        work.addon_info = lambda slug: L.SimpleNamespace(version='5.9.1')
        return work

    device_reads = lambda: mark(target.execute(['emqx', 'eval', DIGEST]), 'WOOWDIG:')
    # ---- the check path (check() without _prepare: the target is the lab stand-in)
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
                out['preflight'] = {'profile': profile, 'blocker': target_blocker}
            except Exception as error:   # the FakeWork lacks a device adapter: recorded, not hidden
                profile, target_blocker = None, None
                out['preflight'] = {'error': type(error).__name__}
            device = ha_emqx.device_accounts(ha_emqx.device_execute(work, app, target))
            blockers, warnings = ha_emqx.analyse(src, readings, addon_version='5.9.1', version='5.8.9',
                                                 profile=profile, device=device)
            if blocker:
                blockers.insert(0, blocker)
            if target_blocker:
                blockers.append(target_blocker)
            out['check'] = {'blockers': blockers, 'warnings': warnings,
                            'hashing': (readings or {}).get('hashing'),
                            'device': None if device is None else {'hashing': device['hashing'],
                                                                   'count': device['count']}}
            texts += blockers + warnings
            stop = [w for w in warnings if '保存 MQTT 密碼的方式' in w]
            out['check']['accounts_stop'] = len(stop)
            out['check']['plain_refused'] = any(PLAIN_MARK in b or CLEAR_MARK in b for b in blockers)
            if device is not None:   # the transport of the ids (base64, count, first ten sorted bytewise)
                out['check']['device_ids_exact'] = (device['count'] == len(own_ids) and device['names'] == [
                    i.decode('utf-8', 'replace') for i in sorted(own_ids)[:10]])
            if stop and device is not None:
                names = expected_names(own_ids)
                texts_expected = STOP.format(ha=words(readings['hashing']), mine=words(device['hashing']), names=names)
                out['check']['accounts_stop_exact'] = stop == [texts_expected]
                out['check']['names_expected_sha256'] = L.digest(names)
        except L.BackupError as error:
            out['check'] = {'refused': error.message}
            texts.append(error.message)
    texts += work.logs
    after = device_reads()
    out['device_read_only_check'] = {'equal': before == after and before != 'unreadable'}
    # ---- the conversion body
    if spec['convert']:
        calls = []
        real_ctl = ha_emqx.ctl

        def spy(tmp_, role, args, *rest, **kw):
            calls.append((role, list(args[:2])))
            return real_ctl(tmp_, role, args, *rest, **kw)
        ha_emqx.ctl = spy
        work = fresh_work()
        staging = Path(tempfile.mkdtemp(prefix=f't15-{mode}-', dir=staging_root))
        before = device_reads()
        try:
            with L.temp(runner) as tmp:
                try:
                    device = ha_emqx.device_accounts(ha_emqx.device_execute(work, app, target))
                    _s, _n, readings, _e, _c, _st, _la, _rb, _p = ha_emqx._build_candidate(
                        work, app, tmp, target, staging, version='5.8.9', profile=out['preflight'].get('profile'))
                    out['conversion'] = 'PASSED (candidate built, all product checks green)'
                    notes, reminders = ha_emqx.import_texts({'hash_change': ha_emqx.hash_change(readings['hashing'],
                                                                                               device)})
                    texts += notes + reminders
                    out['conversion_notes_naming'] = sum(1 for t in notes + reminders if '這台原本的 MQTT 帳號' in t)
                    if out['conversion_notes_naming'] and device is not None:
                        words_ = {'ha': words(readings['hashing']), 'mine': words(device['hashing']),
                                  'names': expected_names(own_ids)}
                        out['conversion_texts_exact'] = (NOTE.format(**words_) in notes
                                                         and REMINDER.format(**words_) in reminders)
                except L.BackupError as error:
                    out['conversion'] = 'REFUSED: ' + error.message
                    texts.append(error.message)
                texts += work.logs
                if tmp.running('emqx-new'):
                    inside = lambda c: tmp.exec('emqx-new', c, timeout=120, check=False)
                    out['candidate_clear'] = mark(inside(['emqx', 'eval', CLEAR]), 'WOOWCLEAR:')
                    out['candidate_leak'] = mark(inside(['emqx', 'eval', leak_expr('\n'.join(texts))]), 'WOOWLEAK:')
        finally:
            ha_emqx.ctl = real_ctl
        out['export_called'] = any(role == 'emqx-ha' and args == ['data', 'export'] for role, args in calls)
        after = device_reads()
        out['device_read_only_conversion'] = {'equal': before == after and before != 'unreadable'}
    out['device_leak'] = mark(target.execute(['emqx', 'eval', leak_expr('\n'.join(texts))], timeout=180), 'WOOWLEAK:')
    out['text_scan'] = text_scan(texts)
    clear = out.get('candidate_clear', '')
    out['plaintext_rows_in_candidate'] = int(clear.split('clear=', 1)[1].split(':', 1)[0]) if 'clear=' in clear else 0
    out['elapsed_s'] = round(time.time() - started, 1)
    return out


def main(codebase, modes):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': 'T15 SR-5 option C re-review (warning leak, names, read-only device reads, plain before export, '
                      'plain rows from gateway/listener/past authenticators)',
              'codebase': codebase, 'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)',
              'modes': {}}
    runs = os.path.join(L.SR, 'runs')
    host_dir = tempfile.mkdtemp(prefix='t15-host-', dir=runs)
    os.chmod(host_dir, 0o755)
    acl_host = os.path.join(host_dir, 'acl.conf')
    with open(acl_host, 'wb') as handle:
        handle.write(T1.TARGET_ACL)
    os.chmod(acl_host, 0o644)
    secret = 'secrev-t15-bootstrap'
    pwd = secrets.token_hex(16)   # this device's own MQTT account password (generated, never printed)
    L.lab('secret', 'rm', secret, check=False)
    L.lab('secret', 'create', secret, '-', input=b'user_id,password,is_superuser\nwoow,' + pwd.encode() + b',false\n')
    del pwd
    target = L.LabTarget('t15', {'configs/cluster.hocon': T1.target_hocon('/opt/emqx/etc/acl.conf')},
                         ro_files=[(acl_host, '/opt/emqx/etc/acl.conf', 'ro')],
                         secrets_spec=[f'{secret},type=mount,target={T1.BOOT},uid=1000,gid=1000,mode=0400'])
    try:
        ids = ', '.join('base64:decode(<<"' + base64.b64encode(i).decode() + '">>)' for i in CRAFTED)
        result['device_users_added'] = mark(target.execute(['emqx', 'eval', 'R = [emqx_authn_chains:add_user('
                                                            '\'mqtt:global\', <<"password_based:built_in_database">>, '
                                                            '#{user_id => U, password => base64:encode(crypto:'
                                                            'strong_rand_bytes(12))}) || U <- [' + ids + ']], '
                                                            'io:format("WOOWADD:~b:END", [length([x || {ok, _} <- R])]).'
                                                            ]), 'WOOWADD:')
        own_ids = [b'woow'] + CRAFTED
        result['device_users_expected'] = len(own_ids)
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
    L.evidence(os.path.join(runs, f't15-{codebase}-{"-".join(modes)}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2].split(','))
