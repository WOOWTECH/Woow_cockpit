"""T5b (SR-5, iteration 4): like T5, but HA's built-in-database authenticator carries `name = plain` WITH an EXPLICIT
`salt_position` (iteration 3's T5 omitted salt_position, so EMQX filled the default and the authentication-root
comparison refused -- an artefact, not SR-5). With an explicit salt_position the question SR-5 asks stands: does the
product conversion refuse a HA backup whose authenticator hashes with `plain`, or does it keep it and thereby store
THIS device's own bootstrap MQTT password in clear text in the candidate's built-in database (and so in the converted
backup)? Vendor: emqx_authn_password_hashing:hash(#{name:=plain}, P) -> emqx_passwd:hash({plain,<<>>,_}, P) ->
hash_data(plain, P) = P (emqx_passwd.erl:92-105). The comparison runs inside the candidate against its own mounted
bootstrap file; only true/false and row counts leave it. Lab store, --network none, generated credentials.
Run: python3 -I t5b_plain_explicit.py <codebase> [disable|prefix|suffix]"""
import io
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L  # noqa: E402
import t1_datadir_acl as T1  # noqa: E402
from t5_plain_bootstrap import CHECK  # noqa: E402  (reads the bootstrap CSV's first user and whether its hash == pwd)


def ha_hocon(salt_position):
    return T1.HA_HOCON.replace(b'name = sha256, salt_position = suffix',
                               b'name = plain, salt_position = ' + salt_position.encode())


def addon_tar(salt_position):
    base = 'data/emqx/data/'
    return L.tar_bytes({
        'addon.json': json.dumps({'system': {'slug': 'woow-emqx', 'name': 'EMQX'}, 'version': '5.9.1',
                                  'user': {'image': 'ghcr.io/woowtech/woow-ha-emqx-amd64'}, 'state': 'stopped'}).encode(),
        'data/emqx/node.name': b'emqx@127.0.0.1\n',
        base + 'mnesia/emqx@127.0.0.1': None,
        base + 'configs/cluster.hocon': ha_hocon(salt_position),
        base + 'authz/acl.conf': T1.HA_ACL,
    })


def main(codebase, salt_position='disable'):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': 'T5b SR-5 HA plain authenticator with explicit salt_position vs this device bootstrap users',
              'codebase': codebase, 'salt_position': salt_position, 'image': L.IMAGE, 'network': 'none',
              'store': 'labpodman (separate --root)', 'ha_hocon_sha256': L.digest(ha_hocon(salt_position))}
    host_dir = tempfile.mkdtemp(prefix='t5b-host-', dir=os.path.join(L.SR, 'runs'))
    os.chmod(host_dir, 0o755)
    acl_host = os.path.join(host_dir, 'acl.conf')
    with open(acl_host, 'wb') as handle:
        handle.write(T1.TARGET_ACL)
    os.chmod(acl_host, 0o644)
    secret = 'secrev-t5b-bootstrap'
    pwd = secrets.token_hex(16)   # this device's own MQTT account password (generated, never printed)
    L.lab('secret', 'rm', secret, check=False)
    L.lab('secret', 'create', secret, '-', input=b'user_id,password,is_superuser\nwoow,' + pwd.encode() + b',false\n')
    target = L.LabTarget('t5b', {'configs/cluster.hocon': T1.target_hocon('/opt/emqx/etc/acl.conf')},
                         ro_files=[(acl_host, '/opt/emqx/etc/acl.conf', 'ro')],
                         secrets_spec=[f'{secret},type=mount,target={T1.BOOT},uid=1000,gid=1000,mode=0400'])
    try:
        out = target.execute(['emqx', 'eval', CHECK]).stdout.decode(errors='replace')
        result['device_before'] = out.split('WOOWT5:', 1)[-1].split(':END', 1)[0] if 'WOOWT5:' in out else 'unreadable'
        runner = L.make_runner()
        work = L.FakeWork(runner)
        inner = addon_tar(salt_position)
        work.addon_member = lambda slug: slug
        work.open = lambda member: io.BytesIO(inner)
        work.addon_info = lambda slug: L.SimpleNamespace(version='5.9.1')
        app = L.SimpleNamespace(id='emqx', name='EMQX')
        staging = Path(tempfile.mkdtemp(prefix='t5b-', dir=os.path.join(L.SR, 'runs')))
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
    result['conversion_refused'] = result['conversion'].startswith('REFUSED')
    result['device_bootstrap_password_stored_plaintext'] = ':plain=1' in result.get('candidate', '')
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False, indent=1))
    L.evidence(os.path.join(L.SR, 'runs', f't5b-{codebase}-{salt_position}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'disable')
