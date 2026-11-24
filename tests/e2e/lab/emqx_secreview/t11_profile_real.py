"""T11: the REAL batch-1 HA backups through the public conversion body WITH this device's profile (decision C) and
the product's Target (its EnvironmentFile= read by podman, SR-8/SR-9 fix), in the lab store (--network none).

The device stand-in runs the image like the product package: an EnvironmentFile (EMQX_LOG__CONSOLE__LEVEL=warning and
a generated EMQX_NODE__COOKIE), a read-only ACL file, a bootstrap CSV secret and a Dashboard password secret. The
profile comes from ha_emqx.target_profile() (fixed eval on the stand-in, read only); _build_candidate gets it like
convert() does. Variants: `file` (authorization [file]: decision C must refuse with the owner's text before any
candidate is built, the device unchanged) and `builtin` ([file, built_in_database]: the conversion must pass and the
candidate must hold the same profile). The HA key is read in-process by the b1 harness's Secrets reader (never printed).
Run: python3 -I t11_profile_real.py <codebase> <x86|arm> <file|builtin>"""
import glob
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
from t7_real_backup import FIXTURES, LAB_TESTS, BUILTIN_SOURCES  # noqa: E402


class OwnerFiles:
    def __init__(self, home):
        self.home = home

    def read_file(self, rel, max_bytes):
        fd = os.open(os.path.join(self.home, rel), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as handle:
            return handle.read(max_bytes)


def product_target(ha_emqx, lab_target, home):
    """The product's Target class (isinstance -> candidate_env) carrying the stand-in's resolved Quadlet values."""
    target = ha_emqx.Target.__new__(ha_emqx.Target)
    for name in ('container', 'data_volume', 'log_volume', 'image', 'env', 'node', 'files', 'secrets'):
        setattr(target, name, getattr(lab_target, name))
    target.env_files = ['%h/.config/emqx/emqx.env']
    target._runner = OwnerFiles(home)
    return target


def main(codebase, arch, variant):
    ha_emqx = L.use(codebase)
    sys.path.append(LAB_TESTS)
    from woowbackup import habackup, hasecuretar
    import ha_import_b1_e2e as b1
    started = time.time()
    path = sorted(glob.glob(FIXTURES[arch]))[0]
    result = {'test': 'T11 real batch-1 HA backup, conversion body with this device\'s profile and EnvironmentFile',
              'codebase': codebase, 'arch': arch, 'device_sources': variant, 'fixture': os.path.basename(path),
              'fixture_sha256_prefix': L.digest(open(path, 'rb').read())[:16], 'image': L.IMAGE, 'network': 'none',
              'store': 'labpodman (separate --root)'}
    creds = b1.Secrets([b1.SECRET_DIR / 'b1-creds.env', b1.SECRET_DIR / 'ha-import-creds.env'],
                       b1.SECRET_DIR / 'dev-d-markers.json')
    keys = hasecuretar.Keys(creds['HA_BACKUP_KEY'])
    with habackup.open_backup(path) as hb:
        slugs = [m.slug for m in hb.layout.members if m.role == 'addon' and m.slug.endswith('woow-emqx')]
        versions = [a.get('version') for a in hb.layout.doc['addons'] if str(a.get('slug', '')).endswith('woow-emqx')]
    host_dir = tempfile.mkdtemp(prefix='t11-host-', dir=os.path.join(L.SR, 'runs'))
    os.chmod(host_dir, 0o755)
    acl_host = os.path.join(host_dir, 'acl.conf')
    with open(acl_host, 'wb') as handle:
        handle.write(T1.TARGET_ACL)
    os.chmod(acl_host, 0o644)
    home = os.path.join(host_dir, 'home')
    os.makedirs(os.path.join(home, '.config', 'emqx'), mode=0o700)
    env_file = os.path.join(home, '.config', 'emqx', 'emqx.env')
    cookie = secrets.token_hex(16)
    with open(env_file, 'w') as handle:
        handle.write(f'# woow emqx\nEMQX_LOG__CONSOLE__LEVEL=warning\nEMQX_NODE__COOKIE={cookie}\nWOOW_EMQX_BIND=0.0.0.0\n')
    os.chmod(env_file, 0o600)
    s_boot, s_dash = f'secrev-t11{arch}-bootstrap', f'secrev-t11{arch}-dashboard'
    for name, value in ((s_boot, b'user_id,password,is_superuser\nwoow,' + secrets.token_hex(16).encode() + b',false\n'),
                        (s_dash, secrets.token_hex(12).encode())):
        L.lab('secret', 'rm', name, check=False)
        L.lab('secret', 'create', name, '-', input=value)
    hocon = T1.target_hocon('/opt/emqx/etc/acl.conf')
    if variant == 'builtin':
        hocon = BUILTIN_SOURCES + hocon.split(b'}\n', 1)[1]
    lab_target = L.LabTarget(f't11{arch}', {'configs/cluster.hocon': hocon},
                             ro_files=[(acl_host, '/opt/emqx/etc/acl.conf', 'ro')],
                             secrets_spec=[f'{s_boot},type=mount,target={T1.BOOT},uid=1000,gid=1000,mode=0400',
                                           f'{s_dash},type=env,target=EMQX_DASHBOARD__DEFAULT_PASSWORD'],
                             env_file=env_file)
    dangling_before = len(L.lab('volume', 'ls', '--filter', 'dangling=true', '-q').stdout.split())
    try:
        runner = L.make_runner()
        work = L.FakeWork(runner)
        hb = habackup.open_backup(path)
        work.addon_member = lambda slug: slug
        work.open = lambda member: hb.open_addon(slugs[0], keys)
        version = (versions or ['5.9.1'])[0]
        work.addon_info = lambda slug: L.SimpleNamespace(version=version)
        app = L.SimpleNamespace(id='emqx', name='EMQX')
        target = product_target(ha_emqx, lab_target, home)
        before_cfg = ha_emqx.read_effective_config(lab_target.execute)
        before_digest = L.digest(json.dumps(before_cfg, sort_keys=True))
        profile = ha_emqx.target_profile(work, app, target)
        result['device_profile'] = list(profile)
        staging = Path(tempfile.mkdtemp(prefix='t11-', dir=os.path.join(L.SR, 'runs')))
        with L.temp(runner) as tmp:
            try:
                out = ha_emqx._build_candidate(work, app, tmp, target, staging, version='5.8.9', profile=profile)
                result['conversion'] = 'PASSED (candidate built, all product checks green, profile equal)'
                readings = out[2]
                result['ha_counts'] = {k: v for k, v in sorted(readings['counts'].items())}
                result['readback_roots'] = len(out[7]['config_roots'])
                result['candidate_profile'] = list(out[8])
                cfg = ha_emqx.read_effective_config(lambda c: tmp.exec('emqx-new', c, timeout=120, check=False))
                result['candidate_rules'] = len(((cfg.get('rule_engine') or {}).get('rules') or {}))
                inside = tmp.exec('emqx-new', ['printenv', 'EMQX_NODE__COOKIE'], check=False, timeout=60)
                result['candidate_has_env_file_cookie'] = (inside.stdout or b'').strip() == cookie.encode()
                # podman's own record of the candidate's command line (was a constant until iteration 5)
                created = json.loads(L.lab('container', 'inspect', '--format', '{{json .Config.CreateCommand}}',
                                           tmp.name('emqx-new')).stdout)
                result['candidate_env_file_flag'] = '--env-file' in created
                result['candidate_cookie_on_command_line'] = any(cookie in arg for arg in created)
            except L.BackupError as error:
                result['conversion'] = 'REFUSED: ' + error.message
                result['refused_with_owner_text'] = ha_emqx.ACL_NEEDS_BUILTIN in error.message
                result['candidate_built'] = 'emqx-new' in [c.rsplit('-', 1)[-1] for c in tmp.containers] or any(
                    c.endswith('-emqx-new') for c in tmp.containers)
        hb.close()
        after_cfg = ha_emqx.read_effective_config(lab_target.execute)
        result['device_config_unchanged'] = L.digest(json.dumps(after_cfg, sort_keys=True)) == before_digest
    finally:
        lab_target.remove()
        for name in (s_boot, s_dash):
            L.lab('secret', 'rm', name, check=False)
        os.unlink(env_file)
    result['dangling_volumes_new'] = len(L.lab('volume', 'ls', '--filter', 'dangling=true', '-q').stdout.split()) \
        - dangling_before
    result['containers_left'] = len(L.lab('ps', '-a', '--filter', 'name=woowbk-j', '-q').stdout.split())
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False))
    L.evidence(os.path.join(L.SR, 'runs', f't11-{codebase}-{arch}-{variant}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3])
