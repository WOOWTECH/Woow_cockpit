"""T1 / B1-02 reopened? This device's file ACL lives in the data volume (/opt/emqx/data/authz/acl.conf, where the
EMQX Dashboard writes edited rules); a crafted HA backup's file ACL is `{allow, all}.`. Does the product's conversion
(_build_candidate, real brokers) keep this device's ACL file, or replace it while the config check still passes?
Run: python3 -I t1_datadir_acl.py <codebase> [ro]   (ro: the device ACL is a read-only mount instead, control case)"""
import io
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L

TARGET_ACL = (b'%% secrev target ACL: only woow may use everything\n'
              b'{allow, {username, "woow"}, all, ["#"]}.\n{deny, all}.\n')
HA_ACL = b'%% secrev HA ACL\n{allow, all}.\n'
AUTHN = (b'authentication = [ { mechanism = password_based, backend = built_in_database, enable = true,\n'
         b'  user_id_type = username, password_hash_algorithm { name = sha256, salt_position = suffix } } ]\n')
BOOT = '/opt/emqx/etc/woow-mqtt-bootstrap.csv'
TARGET_AUTHN = (b'authentication = [ { mechanism = password_based, backend = built_in_database, enable = true,\n'
                b'  user_id_type = username, bootstrap_file = "' + BOOT.encode() + b'", bootstrap_type = plain,\n'
                b'  password_hash_algorithm { name = sha256, salt_position = suffix } } ]\n')


def target_hocon(path):
    return (b'authorization {\n  no_match = deny\n  deny_action = ignore\n  sources = [ { type = file, enable = true, '
            b'path = "' + path.encode() + b'" } ]\n}\n' + TARGET_AUTHN)


HA_HOCON = (b'authorization {\n  no_match = allow\n  deny_action = ignore\n  sources = [ { type = file, enable = true, '
            b'path = "/data/emqx/data/authz/acl.conf" } ]\n}\n' + AUTHN)

AUTHZ_EXPR = ('C = #{clientid => <<"secrev-c">>, username => <<"stranger">>, peerhost => {127,0,0,1}, zone => default, '
              'listener => \'tcp:default\', protocol => mqtt, is_superuser => false, mountpoint => undefined}, '
              'A = #{action_type => publish, qos => 0, retain => false}, '
              'io:format("WOOWAUTHZ:~p:END", [emqx_access_control:authorize(C, A, <<"device/secret/topic">>)]).')


def addon_tar():
    base = 'data/emqx/data/'
    return L.tar_bytes({
        'addon.json': json.dumps({'system': {'slug': 'woow-emqx', 'name': 'EMQX'}, 'version': '5.9.1',
                                  'user': {'image': 'ghcr.io/woowtech/woow-ha-emqx-amd64'}, 'state': 'stopped'}).encode(),
        'data/emqx/node.name': b'emqx@127.0.0.1\n',
        base + 'mnesia/emqx@127.0.0.1': None,
        base + 'configs/cluster.hocon': HA_HOCON,
        base + 'authz/acl.conf': HA_ACL,
    })


def authz(execute):
    r = execute(['emqx', 'eval', AUTHZ_EXPR])
    out = (r.stdout or b'').decode(errors='replace')
    return out.split('WOOWAUTHZ:', 1)[1].split(':END', 1)[0] if 'WOOWAUTHZ:' in out else f'unreadable rc={r.returncode}'


def main(codebase, variant):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': 'T1 this device ACL file in the data volume vs HA file ACL {allow, all}', 'codebase': codebase,
              'variant': variant, 'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)',
              'target_acl_sha256': L.digest(TARGET_ACL), 'ha_acl_sha256': L.digest(HA_ACL)}
    host_dir = tempfile.mkdtemp(prefix='t1-host-', dir=os.path.join(L.SR, 'runs'))
    os.chmod(host_dir, 0o755)
    files = {'configs/cluster.hocon': None}
    ro = []
    if variant == 'ro':
        acl_host = os.path.join(host_dir, 'acl.conf')
        with open(acl_host, 'wb') as handle:
            handle.write(TARGET_ACL)
        os.chmod(acl_host, 0o644)
        ro = [(acl_host, '/opt/emqx/etc/acl.conf', 'ro')]
        files = {'configs/cluster.hocon': target_hocon('/opt/emqx/etc/acl.conf')}
    else:
        files = {'configs/cluster.hocon': target_hocon('/opt/emqx/data/authz/acl.conf'), 'authz/acl.conf': TARGET_ACL}
    secret = f'secrev-t1{variant}-bootstrap'
    L.lab('secret', 'rm', secret, check=False)
    L.lab('secret', 'create', secret, '-', input=b'user_id,password,is_superuser\nwoow,' +
          L.secrets.token_hex(16).encode() + b',false\n')
    spec = f'{secret},type=mount,target={BOOT},uid=1000,gid=1000,mode=0400'
    target = L.LabTarget(f't1{variant}', files, ro_files=ro, secrets_spec=[spec])
    try:
        result['target_before_authz_stranger'] = authz(target.execute)
        runner = L.make_runner()
        work = L.FakeWork(runner)
        inner = addon_tar()
        work.addon_member = lambda slug: slug
        work.open = lambda member: io.BytesIO(inner)
        work.addon_info = lambda slug: L.SimpleNamespace(version='5.9.1')
        app = L.SimpleNamespace(id='emqx', name='EMQX')
        staging = Path(tempfile.mkdtemp(prefix='t1-', dir=os.path.join(L.SR, 'runs')))
        with L.temp(runner) as tmp:
            try:
                out = ha_emqx._build_candidate(work, app, tmp, target, staging, version='5.8.9')
                result['conversion'] = 'PASSED (candidate built, all product checks green)'
                if len(out) > 7:
                    result['readback_profile'] = list(out[8])
            except L.BackupError as error:
                result['conversion'] = 'REFUSED: ' + error.message
            if tmp.running('emqx-new'):
                ex = lambda c: tmp.exec('emqx-new', c, timeout=120, check=False)
                acl = ex(['cat', '/opt/emqx/data/authz/acl.conf'])
                result['candidate_data_acl_sha256'] = L.digest(acl.stdout) if acl.returncode == 0 else None
                cfg = ha_emqx.read_effective_config(ex)
                srcs = cfg['authorization']['sources']
                result['candidate_authorization_sources'] = [
                    {'type': s.get('type'), 'path': s.get('path') if isinstance(s.get('path'), str) else repr(type(s.get('path')))}
                    for s in srcs]
                result['candidate_no_match'] = cfg['authorization'].get('no_match')
                result['candidate_authz_stranger'] = authz(ex)
        result['target_acl_replaced_by_ha'] = result.get('candidate_data_acl_sha256') == L.digest(HA_ACL)
    finally:
        target.remove()
        L.lab('secret', 'rm', secret, check=False)
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False, indent=1))
    L.evidence(os.path.join(L.SR, 'runs', f't1-{codebase}-{variant}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'data')
