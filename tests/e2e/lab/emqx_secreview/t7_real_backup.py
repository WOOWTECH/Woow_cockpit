"""T7: regression on REAL data. The real batch-1 HA backups (EMQX add-on stopped, encrypted; x86 and ARM) go through
the fixed conversion body (_build_candidate: member pass, HA's broker on HA's real Mnesia, export, this device's
candidate, settings restore, SR-2/SR-3/SR-6 checks, row counts, readback) in the lab store (--network none) against a
device stand-in with the dev-d profile (ro ACL mount at /opt/emqx/etc/acl.conf, bootstrap CSV secret, Dashboard
password env secret). The HA key is read in-process by the b1 harness's own Secrets reader and never printed.
Run: python3 -I t7_real_backup.py <codebase> <x86|arm>"""
import glob
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

FIXTURES = {'x86': '/home/woowtechopenclaw/.woowbk-lab/ha-fixtures/20261119-b1/x86/woow-b1-x86-emqx-stopped-enc/*.tar',
            'arm': '/home/woowtechopenclaw/.woowbk-lab/ha-fixtures/20261119-b1/arm/woow-b1-arm-emqx-stopped-enc/*.tar'}
LAB_TESTS = os.environ.get('SECREV_LAB_TESTS') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(codebase, arch):
    ha_emqx = L.use(codebase)
    sys.path.append(LAB_TESTS)
    from woowbackup import habackup, hasecuretar
    import ha_import_b1_e2e as b1
    started = time.time()
    path = sorted(glob.glob(FIXTURES[arch]))[0]
    result = {'test': 'T7 real batch-1 HA backup through the fixed conversion', 'codebase': codebase, 'arch': arch,
              'fixture': os.path.basename(path), 'fixture_sha256_prefix': L.digest(open(path, 'rb').read())[:16],
              'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)'}
    creds = b1.Secrets([b1.SECRET_DIR / 'b1-creds.env', b1.SECRET_DIR / 'ha-import-creds.env'],
                       b1.SECRET_DIR / 'dev-d-markers.json')
    keys = hasecuretar.Keys(creds['HA_BACKUP_KEY'])
    with habackup.open_backup(path) as hb:
        slugs = [m.slug for m in hb.layout.members if m.role == 'addon' and m.slug.endswith('woow-emqx')]
        result['addon_versions'] = [a.get('version') for a in hb.layout.doc['addons'] if str(a.get('slug', '')).endswith('woow-emqx')]
    result['addon_slug'] = slugs[0] if slugs else 'missing'
    host_dir = tempfile.mkdtemp(prefix='t7-host-', dir=os.path.join(L.SR, 'runs'))
    os.chmod(host_dir, 0o755)
    acl_host = os.path.join(host_dir, 'acl.conf')
    with open(acl_host, 'wb') as handle:
        handle.write(T1.TARGET_ACL)
    os.chmod(acl_host, 0o644)
    s_boot, s_dash = f'secrev-t7{arch}-bootstrap', f'secrev-t7{arch}-dashboard'
    for name, value in ((s_boot, b'user_id,password,is_superuser\nwoow,' + secrets.token_hex(16).encode() + b',false\n'),
                        (s_dash, secrets.token_hex(12).encode())):
        L.lab('secret', 'rm', name, check=False)
        L.lab('secret', 'create', name, '-', input=value)
    target = L.LabTarget(f't7{arch}', {'configs/cluster.hocon': T1.target_hocon('/opt/emqx/etc/acl.conf')},
                         ro_files=[(acl_host, '/opt/emqx/etc/acl.conf', 'ro')],
                         secrets_spec=[f'{s_boot},type=mount,target={T1.BOOT},uid=1000,gid=1000,mode=0400',
                                       f'{s_dash},type=env,target=EMQX_DASHBOARD__DEFAULT_PASSWORD'])
    try:
        runner = L.make_runner()
        work = L.FakeWork(runner)
        hb = habackup.open_backup(path)
        work.addon_member = lambda slug: slug
        work.open = lambda member: hb.open_addon(slugs[0], keys)
        version = (result['addon_versions'] or ['5.9.1'])[0]
        work.addon_info = lambda slug: L.SimpleNamespace(version=version)
        app = L.SimpleNamespace(id='emqx', name='EMQX')
        staging = Path(tempfile.mkdtemp(prefix='t7-', dir=os.path.join(L.SR, 'runs')))
        with L.temp(runner) as tmp:
            try:
                out = ha_emqx._build_candidate(work, app, tmp, target, staging, version='5.8.9')
                result['conversion'] = 'PASSED (candidate built, all product checks green)'
                src, node, readings = out[0], out[1], out[2]
                result['ha_node'] = node
                result['ha_counts'] = {k: v for k, v in sorted(readings['counts'].items())}
                result['ha_roots_exported'] = sorted(r for r in ha_emqx.DATA_ROOTS if r in readings['roots'])
                if len(out) > 8:
                    result['readback_roots'] = len(out[7]['config_roots'])
                    result['readback_profile'] = list(out[8])
                cfg = ha_emqx.read_effective_config(lambda c: tmp.exec('emqx-new', c, timeout=120, check=False))
                result['candidate_rules'] = len(((cfg.get('rule_engine') or {}).get('rules') or {}))
                result['candidate_connectors'] = sum(len(v) for v in (cfg.get('connectors') or {}).values()
                                                     if isinstance(v, dict))
            except L.BackupError as error:
                result['conversion'] = 'REFUSED: ' + error.message
        hb.close()
    finally:
        target.remove()
        for name in (s_boot, s_dash):
            L.lab('secret', 'rm', name, check=False)
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False, indent=1))
    L.evidence(os.path.join(L.SR, 'runs', f't7-{codebase}-{arch}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
