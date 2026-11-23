"""T5: HA's authenticator uses `password_hash_algorithm { name = plain }`. The product keeps HA's authenticator and
re-attaches THIS device's bootstrap credential file to it (preserved_bootstrap_authn). Are this device's bootstrap
MQTT passwords then stored in plaintext in the candidate's built-in database (and so in the restored data volume)?
The comparison runs inside the candidate against its own mounted bootstrap file; only true/false leaves it.
Run: python3 -I t5_plain_bootstrap.py <codebase>"""
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

HA_HOCON = T1.HA_HOCON.replace(b'name = sha256, salt_position = suffix', b'name = plain')
CHECK = ('{ok, B} = file:read_file("' + T1.BOOT + '"), '
         '[_, Row | _] = binary:split(B, <<"\\n">>, [global]), [U, P | _] = binary:split(Row, <<",">>, [global]), '
         'Rows = [R || R <- ets:tab2list(emqx_authn_mnesia), element(2, element(2, R)) =:= U], '
         'Plain = [x || R <- Rows, element(3, R) =:= P], '
         'io:format("WOOWT5:rows=~B:plain=~B:END", [length(Rows), length(Plain)]).')


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
    result = {'test': 'T5 HA authenticator plain hashing vs this device bootstrap users', 'codebase': codebase,
              'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)'}
    host_dir = tempfile.mkdtemp(prefix='t5-host-', dir=os.path.join(L.SR, 'runs'))
    os.chmod(host_dir, 0o755)
    acl_host = os.path.join(host_dir, 'acl.conf')
    with open(acl_host, 'wb') as handle:
        handle.write(T1.TARGET_ACL)
    os.chmod(acl_host, 0o644)
    secret = 'secrev-t5-bootstrap'
    L.lab('secret', 'rm', secret, check=False)
    L.lab('secret', 'create', secret, '-', input=b'user_id,password,is_superuser\nwoow,' +
          secrets.token_hex(16).encode() + b',false\n')
    target = L.LabTarget('t5', {'configs/cluster.hocon': T1.target_hocon('/opt/emqx/etc/acl.conf')},
                         ro_files=[(acl_host, '/opt/emqx/etc/acl.conf', 'ro')],
                         secrets_spec=[f'{secret},type=mount,target={T1.BOOT},uid=1000,gid=1000,mode=0400'])
    try:
        out = target.execute(['emqx', 'eval', CHECK]).stdout.decode(errors='replace')
        result['device_before'] = out.split('WOOWT5:', 1)[-1].split(':END', 1)[0] if 'WOOWT5:' in out else 'unreadable'
        runner = L.make_runner()
        work = L.FakeWork(runner)
        inner = addon_tar()
        work.addon_member = lambda slug: slug
        work.open = lambda member: io.BytesIO(inner)
        work.addon_info = lambda slug: L.SimpleNamespace(version='5.9.1')
        app = L.SimpleNamespace(id='emqx', name='EMQX')
        staging = Path(tempfile.mkdtemp(prefix='t5-', dir=os.path.join(L.SR, 'runs')))
        with L.temp(runner) as tmp:
            try:
                ha_emqx._build_candidate(work, app, tmp, target, staging, version='5.8.9')
                result['conversion'] = 'PASSED (candidate built, all product checks green)'
            except L.BackupError as error:
                result['conversion'] = 'REFUSED: ' + error.message
            if tmp.running('emqx-new'):
                out = tmp.exec('emqx-new', ['emqx', 'eval', CHECK], timeout=120, check=False).stdout.decode(errors='replace')
                result['candidate'] = out.split('WOOWT5:', 1)[-1].split(':END', 1)[0] if 'WOOWT5:' in out else 'unreadable'
                cfg = ha_emqx.read_effective_config(lambda c: tmp.exec('emqx-new', c, timeout=120, check=False))
                result['candidate_authn_algorithms'] = [((a.get('password_hash_algorithm') or {}).get('name'),
                                                         bool(a.get('bootstrap_file'))) for a in cfg.get('authentication', [])]
    finally:
        target.remove()
        L.lab('secret', 'rm', secret, check=False)
    result['device_bootstrap_password_stored_plaintext'] = ':plain=1' in result.get('candidate', '')
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False, indent=1))
    L.evidence(os.path.join(L.SR, 'runs', f't5-{codebase}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1])
