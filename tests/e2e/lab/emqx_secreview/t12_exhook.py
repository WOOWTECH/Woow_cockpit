"""T12 (SR-7 real trigger): a crafted HA backup whose cluster.hocon enables an ExHook server (loopback URL; no gRPC
server: EMQX keeps the configuration and reconnects). Its client.authenticate hook would receive every login,
including this device's own services' bootstrap passwords (emqx_exhook_handler.erl:104,318-333). The product
conversion body must refuse it after HA's data is imported into the candidate (credential_receivers), naming ExHook.
Lab store, --network none, generated credentials. Run: python3 -I t12_exhook.py <codebase>"""
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

EXHOOK = (b'exhook {\n  servers = [\n    { name = "secrev", enable = true, url = "http://127.0.0.1:9000",\n'
          b'      request_timeout = "1s", auto_reconnect = "60s" }\n  ]\n}\n')
HA_HOCON = T1.HA_HOCON + b'\n' + EXHOOK


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
    result = {'test': 'T12 migrated ExHook server (SR-7) through the conversion body', 'codebase': codebase,
              'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)',
              'ha_hocon_sha256': L.digest(HA_HOCON)}
    host_dir = tempfile.mkdtemp(prefix='t12-host-', dir=os.path.join(L.SR, 'runs'))
    os.chmod(host_dir, 0o755)
    acl_host = os.path.join(host_dir, 'acl.conf')
    with open(acl_host, 'wb') as handle:
        handle.write(T1.TARGET_ACL)
    os.chmod(acl_host, 0o644)
    secret = 'secrev-t12-bootstrap'
    L.lab('secret', 'rm', secret, check=False)
    L.lab('secret', 'create', secret, '-', input=b'user_id,password,is_superuser\nwoow,' +
          secrets.token_hex(16).encode() + b',false\n')
    target = L.LabTarget('t12', {'configs/cluster.hocon': T1.target_hocon('/opt/emqx/etc/acl.conf')},
                         ro_files=[(acl_host, '/opt/emqx/etc/acl.conf', 'ro')],
                         secrets_spec=[f'{secret},type=mount,target={T1.BOOT},uid=1000,gid=1000,mode=0400'])
    dangling_before = L.dangling_names()
    try:
        runner = L.make_runner()
        work = L.FakeWork(runner)
        inner = addon_tar()
        work.addon_member = lambda slug: slug
        work.open = lambda member: io.BytesIO(inner)
        work.addon_info = lambda slug: L.SimpleNamespace(version='5.9.1')
        app = L.SimpleNamespace(id='emqx', name='EMQX')
        staging = Path(tempfile.mkdtemp(prefix='t12-', dir=os.path.join(L.SR, 'runs')))
        with L.temp(runner) as tmp:
            try:
                out = ha_emqx._build_candidate(work, app, tmp, target, staging, version='5.8.9')
                result['conversion'] = 'PASSED (candidate built, all product checks green)'
                result['ha_roots_exported'] = sorted(r for r in ha_emqx.DATA_ROOTS if r in out[2]['roots'])
            except L.BackupError as error:
                result['conversion'] = 'REFUSED: ' + error.message
            result['refused_naming_exhook'] = result['conversion'].startswith('REFUSED') and 'ExHook' in \
                result['conversion']
    finally:
        target.remove()
        L.lab('secret', 'rm', secret, check=False)
    result['dangling_volumes_new'] = L.new_dangling(dangling_before)
    result['containers_left'] = len(L.lab('ps', '-a', '--filter', 'name=woowbk-j', '-q').stdout.split())
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False))
    L.evidence(os.path.join(L.SR, 'runs', f't12-{codebase}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1])
