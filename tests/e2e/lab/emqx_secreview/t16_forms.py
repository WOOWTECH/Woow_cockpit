"""T16F (iteration 8, 2026-11-24, lane emqx-secreview SR-OWNER-1942): the stored-form check of the product's PLAIN_EXPR
against real EMQX 5.8.9 brokers in the LAB store (labpodman, its own --root; every container --network none), with
behavioural mutants of the expression. Generated values only; no value of any row is ever printed or kept.

Per state (F1, F2) one broker runs a configuration with built-in password databases in the global chain, MQTT
listeners, gateways (stomp, mqttsn: chain 'mqtt-sn:global', coap) and gateway listeners, each with its own hashing.
Rows: (1) EMQX itself writes users through emqx_authn_chains:add_user with random passwords made inside the broker
(`e-ok-*`: never counted; `e-cnt-*`: a `plain` chain's rows, counted); (2) crafted rows written with mnesia:dirty_write,
their values made INSIDE the broker from a shape spec (hex of a length, upper-case hex, digits, bcrypt-like strings with
a given minor / rounds / length, a clear prefix, empty), `f-ok-*` = in the form of their group's hashing (or, for a
group without an authenticator, of any hashing), `f-cnt-*` = not (the expectation is the vendor facts written by hand
in the ids, independent of the product). The product's PLAIN_EXPR must answer exactly the expected count and the first
ten (group, id) sorted; a diagnostic copy (the same expression with every counted row listed) shows any difference.
Then one row of an unknown shape (an integer hash) is added: the answer must be `bad`.
MUTANTS: one-place changes of the expression, each evaluated in both table states; a mutant is killed when an answer
differs (behaviour) or the evaluation fails (error; counted apart).
Run: python3 -I t16_forms.py <codebase> F1[,F2]"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L  # noqa: E402


def db(algorithm):
    return ('{ mechanism = password_based, backend = built_in_database, user_id_type = username, '
            'password_hash_algorithm { ' + algorithm + ' } }')


CONFIGS = {
    'F1': '\n'.join((
        'authentication = [ ' + db('name = bcrypt, salt_rounds = 5') + ' ]',
        'listeners.tcp.default { bind = "0.0.0.0:1883", authentication = [ '
        + db('name = pbkdf2, mac_fun = sha256, iterations = 2, dk_length = 12') + ' ] }',
        'listeners.ws.default { bind = "0.0.0.0:8083", authentication = [ '
        + db('name = pbkdf2, mac_fun = sha, iterations = 2, dk_length = 36') + ' ] }',
        'gateway.stomp { mountpoint = "stomp/", listeners.tcp.default { bind = "61613", authentication = '
        + db('name = pbkdf2, mac_fun = sha384, iterations = 2, dk_length = 26') + ' }, authentication = '
        + db('name = pbkdf2, mac_fun = sha512, iterations = 2, dk_length = 24') + ' }',
        'gateway.mqttsn { mountpoint = "mqttsn/", listeners.udp.default { bind = "1884", authentication = '
        + db('name = pbkdf2, mac_fun = sha256, iterations = 2, dk_length = 14') + ' }, authentication = '
        + db('name = pbkdf2, mac_fun = sha224, iterations = 2, dk_length = 30') + ' }', '')),
    'F2': '\n'.join((
        'authentication = [ ' + db('name = sha256, salt_position = prefix') + ' ]',
        'listeners.tcp.default { bind = "0.0.0.0:1883", authentication = [ '
        + db('name = md5, salt_position = suffix') + ' ] }',
        'listeners.ws.default { bind = "0.0.0.0:8083", authentication = [ '
        + db('name = sha, salt_position = disable') + ' ] }',
        'listeners.ssl.default { bind = "0.0.0.0:8883", authentication = [ '
        + db('name = pbkdf2, mac_fun = md5, iterations = 2') + ' ] }',
        'gateway.stomp { mountpoint = "stomp/", listeners.tcp.default { bind = "61613", authentication = '
        + db('name = pbkdf2, mac_fun = sha512, iterations = 2') + ' }, authentication = '
        + db('name = sha512, salt_position = prefix') + ' }',
        'gateway.mqttsn { mountpoint = "mqttsn/", listeners.udp.default { bind = "1884", authentication = '
        + db('name = pbkdf2, mac_fun = sha224, iterations = 2') + ' }, authentication = '
        + db('name = pbkdf2, mac_fun = sha, iterations = 2') + ' }',
        'gateway.coap { mountpoint = "coap/", listeners.udp.default { bind = "5683", authentication = '
        + db('name = plain, salt_position = disable') + ' }, authentication = '
        + db('name = pbkdf2, mac_fun = sha384, iterations = 2') + ' }', '')),
}
# EMQX-written users: (chain, id). A `plain` chain's rows are counted (e-cnt).
WRITTEN = {
    'F1': [(c, f'e-ok-{t}-{i}') for c, t in (('mqtt:global', 'g'), ('tcp:default', 't'), ('ws:default', 'w'),
                                              ('stomp:global', 's'), ('stomp:tcp:default', 'st'),
                                              ('mqtt-sn:global', 'm'), ('mqttsn:udp:default', 'mu'))
           for i in (1, 2)],
    'F2': [(c, f'e-ok-{t}-{i}') for c, t in (('mqtt:global', 'g2'), ('tcp:default', 't2'), ('ws:default', 'w2'),
                                              ('stomp:global', 's2'), ('stomp:tcp:default', 'st2'),
                                              ('mqtt-sn:global', 'm2'), ('mqttsn:udp:default', 'mu2'),
                                              ('coap:global', 'c2'))
           for i in (1, 2)] + [('coap:udp:default', f'e-cnt-cu-{i}') for i in (1, 2)],
}
# Crafted rows: (group, id, shape, salt). Forms by vendor (emqx_passwd.erl, emqx_authn_password_hashing.erl, bcrypt
# proven in the 5.8.9 image): md5 32, sha 40, sha256 64, sha512 128 hex any case; pbkdf2 2 x dk_length hex (sha 20,
# sha224 28, sha256 32, sha384 48, sha512 64 bytes by default); bcrypt $2[abxy]$<04..31>$ + 53 of [./A-Za-z0-9].
CRAFTED = {
    'F1': [
        # global: bcrypt
        ('mqtt:global', 'f-ok-g-b2a', ('bc', 'a', '05', 53), 'none'),
        ('mqtt:global', 'f-ok-g-b2b', ('bc', 'b', '10', 53), 'hex32'),
        ('mqtt:global', 'f-ok-g-b2x', ('bc', 'x', '04', 53), 'none'),
        ('mqtt:global', 'f-ok-g-b2y', ('bc', 'y', '31', 53), 'none'),
        ('mqtt:global', 'f-cnt-g-b2c', ('bc', 'c', '10', 53), 'none'),
        ('mqtt:global', 'f-cnt-g-b2n', ('bc', '', '10', 53), 'none'),
        ('mqtt:global', 'f-cnt-g-r03', ('bc', 'b', '03', 53), 'none'),
        ('mqtt:global', 'f-cnt-g-r32', ('bc', 'b', '32', 53), 'none'),
        ('mqtt:global', 'f-cnt-g-r1a', ('bc', 'b', '1a', 53), 'none'),
        ('mqtt:global', 'f-cnt-g-l52', ('bc', 'b', '10', 52), 'none'),
        ('mqtt:global', 'f-cnt-g-l54', ('bc', 'b', '10', 54), 'none'),
        ('mqtt:global', 'f-cnt-g-bad', ('bcbad', 53), 'none'),
        ('mqtt:global', 'f-cnt-g-dol', ('clear', '$2', 10), 'none'),
        ('mqtt:global', 'f-cnt-g-hex64', ('hex', 64), 'none'),
        ('mqtt:global', 'f-cnt-g-dig', ('digits', 8), 'none'),
        ('mqtt:global', 'f-cnt-g-emp', ('empty',), 'none'),
        # tcp:default: pbkdf2 sha256 dk 12 -> 24 hex
        ('tcp:default', 'f-ok-t-24', ('hex', 24), 'hex32'),
        ('tcp:default', 'f-ok-t-24up', ('hexup', 24), 'hex32'),
        ('tcp:default', 'f-ok-t-dig24', ('digits', 24), 'hex32'),   # residual: digits exactly in the form
        ('tcp:default', 'f-cnt-t-64', ('hex', 64), 'hex32'),
        ('tcp:default', 'f-cnt-t-23', ('hex', 23), 'hex32'),
        ('tcp:default', 'f-cnt-t-g24', ('hexg', 24), 'hex32'),
        ('tcp:default', 'f-cnt-t-salt', ('clear', 'pw-', 9), 'short'),   # a hash import's clear value with a salt
        ('ws:default', 'f-ok-w-72', ('hex', 72), 'hex32'),
        ('ws:default', 'f-cnt-w-40', ('hex', 40), 'hex32'),
        ('stomp:global', 'f-ok-s-48', ('hex', 48), 'hex32'),
        ('stomp:global', 'f-cnt-s-128', ('hex', 128), 'hex32'),
        ('stomp:tcp:default', 'f-ok-st-52', ('hex', 52), 'hex32'),
        ('stomp:tcp:default', 'f-cnt-st-96', ('hex', 96), 'hex32'),
        ('mqtt-sn:global', 'f-ok-m-60', ('hex', 60), 'hex32'),
        ('mqtt-sn:global', 'f-cnt-m-56', ('hex', 56), 'hex32'),
        ('mqttsn:udp:default', 'f-ok-mu-28', ('hex', 28), 'hex32'),
        ('mqttsn:udp:default', 'f-cnt-mu-64', ('hex', 64), 'hex32'),
        # groups no authenticator owns (a removed gateway / listener): any form
        ('zz:orphan', 'f-ok-o-64', ('hex', 64), 'hex32'),
        ('zz:orphan', 'f-ok-o-96up', ('hexup', 96), 'hex32'),
        ('zz:orphan', 'f-ok-o-bc', ('bc', 'a', '10', 53), 'none'),
        ('zz:orphan', 'f-cnt-o-48', ('hex', 48), 'hex32'),
        ('zz:orphan', 'f-cnt-o-clr', ('clear', 'pw', 12), 'none'),
        ('zz:orphan', 'f-cnt-o-dig', ('digits', 8), 'none'),
        ('lwm2m:global', 'f-cnt-l-clr', ('clear', 'x', 20), 'none'),
    ],
    'F2': [
        # global: sha256 prefix -> 64 hex
        ('mqtt:global', 'f-ok-g2-64', ('hex', 64), 'hex32'),
        ('mqtt:global', 'f-ok-g2-64up', ('hexup', 64), 'hex32'),
        ('mqtt:global', 'f-ok-g2-dig64', ('digits', 64), 'hex32'),   # residual
        ('mqtt:global', 'f-cnt-g2-63', ('hex', 63), 'hex32'),
        ('mqtt:global', 'f-cnt-g2-65', ('hex', 65), 'hex32'),
        ('mqtt:global', 'f-cnt-g2-g64', ('hexg', 64), 'hex32'),
        ('mqtt:global', 'f-cnt-g2-32', ('hex', 32), 'hex32'),
        ('mqtt:global', 'f-cnt-g2-dig8', ('digits', 8), 'none'),
        ('mqtt:global', 'f-cnt-g2-dol', ('clear', '$2', 20), 'none'),
        ('mqtt:global', 'f-cnt-g2-bc', ('bc', 'a', '10', 53), 'none'),
        ('mqtt:global', 'f-cnt-g2-saltclr', ('clear', 'pw', 10), 'hex32'),
        ('tcp:default', 'f-ok-t2-32', ('hex', 32), 'hex32'),
        ('tcp:default', 'f-cnt-t2-40', ('hex', 40), 'hex32'),
        ('ws:default', 'f-ok-w2-40', ('hex', 40), 'none'),
        ('ws:default', 'f-cnt-w2-32', ('hex', 32), 'none'),
        ('ssl:default', 'f-cnt-sl-32', ('hex', 32), 'hex32'),   # pbkdf2 with md5 cannot verify in 5.8.9
        ('ssl:default', 'f-cnt-sl-40', ('hex', 40), 'hex32'),
        ('stomp:global', 'f-ok-s2-128', ('hex', 128), 'hex32'),
        ('stomp:global', 'f-cnt-s2-64', ('hex', 64), 'hex32'),
        ('stomp:tcp:default', 'f-ok-st2-128', ('hex', 128), 'hex32'),
        ('stomp:tcp:default', 'f-cnt-st2-64', ('hex', 64), 'hex32'),
        ('mqtt-sn:global', 'f-ok-m2-40', ('hex', 40), 'hex32'),
        ('mqtt-sn:global', 'f-cnt-m2-64', ('hex', 64), 'hex32'),
        ('mqttsn:udp:default', 'f-ok-mu2-56', ('hex', 56), 'hex32'),
        ('mqttsn:udp:default', 'f-cnt-mu2-64', ('hex', 64), 'hex32'),
        ('coap:global', 'f-ok-c2-96', ('hex', 96), 'hex32'),
        ('coap:global', 'f-cnt-c2-128', ('hex', 128), 'hex32'),
        ('zz:orphan2', 'f-ok-o2-40', ('hex', 40), 'hex32'),
        ('zz:orphan2', 'f-ok-o2-56', ('hex', 56), 'hex32'),
        ('zz:orphan2', 'f-ok-o2-128', ('hex', 128), 'hex32'),
        ('zz:orphan2', 'f-ok-o2-32', ('hex', 32), 'hex32'),
        ('zz:orphan2', 'f-cnt-o2-72', ('hex', 72), 'hex32'),
        ('zz:orphan2', 'f-cnt-o2-empty', ('empty',), 'none'),
    ],
}
ELSEWHERE = {'F1': 0, 'F2': 1}
# One-place mutants of PLAIN_EXPR: (name, old, new). Each must occur exactly once; every one is valid Erlang.
MUTANTS = [
    ('hex-lower-only', 'orelse (Ch >= $A andalso Ch =< $F) end, binary_to_list(V)) end',
     'end, binary_to_list(V)) end'),
    ('hex-any-length', 'byte_size(V) =:= Len andalso ', ''),
    ('hex-g-is-hex', '(Ch >= $a andalso Ch =< $f)', '(Ch >= $a andalso Ch =< $g)'),
    ('md5-40', 'md5 -> Hx(V, 32)', 'md5 -> Hx(V, 40)'),
    ('sha-32', 'sha -> Hx(V, 40)', 'sha -> Hx(V, 32)'),
    ('sha256-128', 'sha256 -> Hx(V, 64)', 'sha256 -> Hx(V, 128)'),
    ('sha512-64', 'sha512 -> Hx(V, 128)', 'sha512 -> Hx(V, 64)'),
    ('bcrypt-anything', 'bcrypt -> Bc(V)', 'bcrypt -> true'),
    ('bcrypt-no-y', 'lists:member(Mi, "abxy")', 'lists:member(Mi, "abx")'),
    ('bcrypt-c-too', 'lists:member(Mi, "abxy")', 'lists:member(Mi, "abcxy")'),
    ('rounds-from-3', '>= 4 andalso', '>= 3 andalso'),
    ('rounds-to-32', '=< 31 andalso', '=< 32 andalso'),
    ('bcrypt-any-tail', 'when byte_size(Tb) =:= 53', 'when byte_size(Tb) >= 52'),
    ('bcrypt-any-char', 'orelse Ch =:= $. orelse Ch =:= $/ end, binary_to_list(Tb))',
     'orelse true end, binary_to_list(Tb))'),
    ('dk-ignored', 'maps:get(dk_length, Al, undefined)', 'undefined'),
    ('dk-sha512-32', 'sha512 => 64}', 'sha512 => 32}'),
    ('dk-sha-32', '#{sha => 20,', '#{sha => 32,'),
    ('unknown-mac-ok', 'error -> false end', 'error -> true end'),
    ('other-name-ok', 'end; _ -> false end end, Any', 'end; _ -> true end end, Any'),
    ('orphan-any-ok', '[] -> Any(V);', '[] -> true;'),
    ('orphan-refused', '[] -> Any(V);', '[] -> false;'),
    ('any-no-56', '[32, 40, 56, 64, 96, 128]', '[32, 40, 64, 96, 128]'),
    ('any-no-bcrypt', 'Any = fun(V) -> Bc(V) orelse ', 'Any = fun(V) -> '),
    ('listeners-unread', 'Ln(emqx:get_config([listeners], #{}))', 'Ln(#{})'),
    ('gateways-unread', 'A3 <- Lw(maps:get(authentication, Gc3, []))', 'A3 <- []'),
    ('gateway-listeners-unread', 'A4 <- Lw(maps:get(authentication, C4, []))', 'A4 <- []'),
    ('gateway-chain-naive', 'Cn(fun() -> emqx_gateway_utils:global_chain(G3) end)', '<<(Bn(G3))/binary, ":global">>'),
    ('gateway-listener-chain-naive', 'Cn(fun() -> emqx_gateway_utils:listener_chain(G4, T4, N4) end)',
     '<<(Bn(T4))/binary, ":", (Bn(N4))/binary>>'),
    ('single-map-ignored', '(X) when is_map(X) -> [X]; (_) -> [] end, ', '(X) when is_map(X) -> []; (_) -> [] end, '),
    ('global-chain-misnamed', '{<<"mqtt:global">>, global, A1}', '{<<"mqtt:globa">>, global, A1}'),
    ('elsewhere-not-plain', 'maps:get(name, H, none) =:= plain]', 'maps:get(name, H, none) =:= none]'),
    ('bad-row-ignored', '(_, {N0, U0, B0}) -> {N0, U0, B0 + 1} end', '(_, {N0, U0, B0}) -> {N0, U0, B0} end'),
    ('names-unsorted', 'lists:sublist(lists:sort(Uc), 10)', 'lists:sublist(Uc, 10)'),
    ('names-group-lost', '[[base64:encode(Ux), ".", base64:encode(Kx)]', '[[base64:encode(Ux), ".", base64:encode(Ux)]'),
]
SHAPE = {'hex': 'hex', 'hexup': 'hexup', 'hexg': 'hexg', 'digits': 'digits', 'bcbad': 'bcbad'}
WRITE_ROWS = ('Al = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", Hl = "0123456789abcdef", '
              'Dg = "0123456789", Rn = fun(A, N) -> list_to_binary([lists:nth(rand:uniform(length(A)), A) || _ <- '
              'lists:seq(1, N)]) end, '
              'Val = fun({hex, N}) -> Rn(Hl, N); ({hexup, N}) -> string:uppercase(Rn(Hl, N)); '
              '({hexg, N}) -> <<(Rn(Hl, N - 1))/binary, "g">>; ({digits, N}) -> Rn(Dg, N); '
              '({bc, Mi, R, N}) -> <<"$2", Mi/binary, "$", R/binary, "$", (Rn(Al, N))/binary>>; '
              '({bcbad, N}) -> <<"$2b$10$", (Rn(Al, N - 1))/binary, "!">>; '
              '({clear, P, N}) -> <<P/binary, (Rn(Al, N))/binary>>; (empty) -> <<>> end, '
              'Salt = fun(none) -> <<>>; (hex32) -> Rn(Hl, 32); (short) -> <<"s4lt">> end, '
              'W = [mnesia:dirty_write(emqx_authn_mnesia, {user_info, {G, U}, Val(V), Salt(S), false}) || '
              '{G, U, V, S} <- [{SPECS}]], io:format("WOOWROWS:~b:END", [length([x || ok <- W])]).')
ADD_USERS = ('R = [catch emqx_authn_chains:add_user(C, <<"password_based:built_in_database">>, #{user_id => U, '
             'password => base64:encode(crypto:strong_rand_bytes(12))}) || {C, U} <- [{USERS}]], '
             'io:format("WOOWADD:~b:~b:END", [length([x || {ok, _} <- R]), length(R)]).')
CHAINS = ('{ok, Cs} = emqx_authn_chains:list_chains(), io:format("WOOWCHAINS:~s:END", [lists:join(",", '
          'lists:sort([atom_to_list(N) || #{name := N} <- Cs]))]).')
BAD_ROW = ('ok = mnesia:dirty_write(emqx_authn_mnesia, {user_info, {\'mqtt:global\', <<"f-bad-int">>}, 12345, <<>>, '
           'false}), io:format("WOOWBADROW:ok:END").')


def erl_bin(text):
    return '<<"' + text.replace('\\', '\\\\').replace('"', '\\"') + '">>'


def spec_term(group, uid, shape, salt):
    kind = shape[0]
    if kind in SHAPE:
        value = '{' + kind + ', ' + str(shape[1]) + '}'
    elif kind == 'bc':
        value = '{bc, ' + erl_bin(shape[1]) + ', ' + erl_bin(shape[2]) + ', ' + str(shape[3]) + '}'
    elif kind == 'clear':
        value = '{clear, ' + erl_bin(shape[1]) + ', ' + str(shape[2]) + '}'
    else:
        value = 'empty'
    return "{'" + group + "', " + erl_bin(uid) + ', ' + value + ', ' + salt + '}'


def expected(state):
    rows = [(g, u) for g, u, _s, _t in CRAFTED[state] if u.startswith('f-cnt-')]
    rows += [(c, u) for c, u in WRITTEN[state] if u.startswith('e-cnt-')]
    rows.sort(key=lambda r: (r[0].encode(), r[1].encode()))
    return {'elsewhere': ELSEWHERE[state], 'clear': len(rows), 'names': [(u, g) for g, u in rows[:10]]}, rows


def mark(out, tag):
    text = (out.stdout or b'').decode('utf-8', 'replace')
    return text.split(tag, 1)[1].split(':END', 1)[0] if tag in text else 'unreadable'


def full_list_expr(expr):
    """Harness-only diagnostic: the same expression listing every counted row (ids and groups only)."""
    old = 'lists:sublist(lists:sort(Uc), 10)'
    assert expr.count(old) == 1
    return expr.replace(old, 'lists:sort(Uc)')


def answer_of(execute, ha_emqx, expr):
    out = execute(['emqx', 'eval', expr])
    text = (out.stdout or b'').decode('utf-8', 'replace')
    if out.returncode or 'WOOWPLAIN:' not in text:
        return 'error', None
    if 'WOOWPLAIN:bad:END' in text:
        return 'bad', None
    try:
        return 'answer', ha_emqx.parse_plain(text)
    except ValueError:
        return 'unparsed', None


def lenient(text):
    import base64
    import re
    match = re.search(r'WOOWPLAIN:([0-9]+):([0-9]+):([^:]*):END', text)
    if not match:
        return None
    items = [tuple(base64.b64decode(p).decode('utf-8', 'replace') for p in item.split('.'))
             for item in match.group(3).split(',') if item]
    return {'elsewhere': int(match.group(1)), 'clear': int(match.group(2)), 'rows': items}


def run_state(ha_emqx, state):
    tag = state.lower()
    vol, img, log = (f'woowbk-secrev-t16f-{tag}-{part}' for part in ('data', 'img', 'log'))
    ctr = f'woowbk-secrev-t16f-{tag}-emqx'
    out = {'config_sha256': L.digest(CONFIGS[state].encode())}
    for name in (vol, img, log):
        L.lab('volume', 'create', '--label', L.LABEL, name)
    try:
        L.lab('volume', 'import', vol, '-', input=L.tar_bytes({'configs/cluster.hocon': CONFIGS[state].encode()},
                                                              uid=1000, gid=1000))
        L.lab('run', '-d', '--name', ctr, '--label', L.LABEL, '--network', 'none', '--pull=never', '--memory', '1g',
              '-e', 'EMQX_NODE__NAME=emqx@127.0.0.1', '-e', 'EMQX_NODE__DATA_DIR=/data/emqx/data',
              '-e', 'EMQX_DASHBOARD__DEFAULT_PASSWORD=', '-v', f'{vol}:/data/emqx/data', '-v', f'{img}:/opt/emqx/data',
              '-v', f'{log}:/opt/emqx/log', L.IMAGE)

        def execute(command):
            return L.lab('exec', ctr, *command, timeout=180, check=False)
        end = time.monotonic() + 240
        while time.monotonic() < end and b'is started' not in (execute(['emqx', 'ctl', 'status']).stdout or b''):
            time.sleep(3)
        out['chains'] = mark(execute(['emqx', 'eval', CHAINS]), 'WOOWCHAINS:').split(',')
        users = ', '.join("{'" + c + "', " + erl_bin(u) + '}' for c, u in WRITTEN[state])
        out['written'] = mark(execute(['emqx', 'eval', ADD_USERS.replace('{USERS}', users)]), 'WOOWADD:')
        specs = ', '.join(spec_term(*row) for row in CRAFTED[state])
        out['crafted'] = mark(execute(['emqx', 'eval', WRITE_ROWS.replace('{SPECS}', specs)]), 'WOOWROWS:')
        want, rows = expected(state)
        out['expected'] = {'elsewhere': want['elsewhere'], 'clear': want['clear'],
                           'first_ten': [f'{g}/{u}' for u, g in want['names']]}
        expr = ha_emqx.PLAIN_EXPR
        kind, got = answer_of(execute, ha_emqx, expr)
        out['product'] = {'kind': kind, 'match': kind == 'answer' and got == want,
                          'elsewhere': None if got is None else got['elsewhere'],
                          'clear': None if got is None else got['clear']}
        diag = lenient((execute(['emqx', 'eval', full_list_expr(expr)]).stdout or b'').decode('utf-8', 'replace'))
        if diag is not None:
            seen = {(g, u) for u, g in diag['rows']}
            want_set = set(rows)
            out['product']['missed'] = sorted(f'{g}/{u}' for g, u in want_set - seen)
            out['product']['extra'] = sorted(f'{g}/{u}' for g, u in seen - want_set)
        normal = {}
        for name, old, new in MUTANTS:
            if expr.count(old) != 1:
                normal[name] = 'not-applicable'
                continue
            k, g = answer_of(execute, ha_emqx, expr.replace(old, new))
            normal[name] = 'error' if k == 'error' else ('same' if k == 'answer' and g == want else 'diff')
        out['bad_row'] = mark(execute(['emqx', 'eval', BAD_ROW]), 'WOOWBADROW:')
        kind, _got = answer_of(execute, ha_emqx, expr)
        out['product_bad'] = {'kind': kind, 'refused': kind == 'bad'}
        try:
            ha_emqx.parse_plain((execute(['emqx', 'eval', expr]).stdout or b'').decode('utf-8', 'replace'))
            out['product_bad']['parse_plain'] = 'accepted'
        except ValueError:
            out['product_bad']['parse_plain'] = 'ValueError (the callers refuse)'
        mutants = {}
        for name, old, new in MUTANTS:
            if normal[name] == 'not-applicable':
                mutants[name] = {'normal': 'not-applicable'}
                continue
            k, _g = answer_of(execute, ha_emqx, expr.replace(old, new))
            bad = 'error' if k == 'error' else ('same' if k == 'bad' else 'diff')
            verdict = ('killed (behaviour)' if 'diff' in (normal[name], bad) else
                       'killed (error)' if 'error' in (normal[name], bad) else 'SURVIVED')
            mutants[name] = {'normal': normal[name], 'bad': bad, 'verdict': verdict}
        out['mutants'] = mutants
        out['mutant_summary'] = {v: sum(1 for m in mutants.values() if m.get('verdict') == v)
                                 for v in ('killed (behaviour)', 'killed (error)', 'SURVIVED')}
        out['mutant_summary']['not_applicable'] = sum(1 for m in mutants.values() if 'verdict' not in m)
    finally:
        L.lab('rm', '-f', '-t', '0', ctr, check=False)
        for name in (vol, img, log):
            L.lab('volume', 'rm', '-f', name, check=False)
    return out


def main(codebase, states):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': 'T16F stored-form check of PLAIN_EXPR in real EMQX 5.8.9 brokers + behavioural mutants',
              'codebase': codebase, 'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)',
              'mutants': len(MUTANTS), 'states': {}}
    for state in states:
        try:
            result['states'][state] = run_state(ha_emqx, state)
        except Exception as error:   # recorded, never hidden
            result['states'][state] = {'harness_error': type(error).__name__ + ': ' + str(error)[:300]}
        print(state, json.dumps({k: v for k, v in result['states'][state].items() if k != 'mutants'},
                                ensure_ascii=False)[:3000], flush=True)
    left = L.lab('ps', '-a', '--filter', 'label=' + L.LABEL, '--format', '{{.Names}}', check=False).stdout.split()
    vols = L.lab('volume', 'ls', '--filter', 'label=' + L.LABEL, '--format', '{{.Name}}', check=False).stdout.split()
    result['lab_left'] = {'containers': len(left), 'volumes': len(vols)}
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps({'elapsed_s': result['elapsed_s'], 'lab_left': result['lab_left']}), flush=True)
    L.evidence(os.path.join(L.SR, 'runs', f't16f-{codebase}-{"-".join(states)}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2].split(','))
