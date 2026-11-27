"""T16R (iteration 8, 2026-11-24, lane emqx-secreview SR-OWNER-1942): the REAL batch-1 HA backups (EMQX add-on stopped,
encrypted; x86 and the RPi5 ARM one) through the product's CHECK path (member_pass -> node_name -> ha_broker ->
target_preflight -> device_accounts -> analyse) against T11's device stand-in with the [file, built_in_database]
profile, in the lab store (--network none). Shows whether the iteration-8 stored-form check or the DB_OFF warning fires
on HA's real rows (no false refusal). The HA key is read in-process by the b1 harness's Secrets reader (never printed).
Recorded: counts, hashing names and the KINDS of blockers and warnings only (HA's real user ids are not kept).
Run: python3 -I t16_real_check.py <codebase> <x86|arm>"""
import glob
import json
import os
import secrets
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L  # noqa: E402
import t1_datadir_acl as T1  # noqa: E402
from t7_real_backup import FIXTURES, LAB_TESTS, BUILTIN_SOURCES  # noqa: E402
from t11_profile_real import product_target  # noqa: E402

KINDS = (('CLEAR_ROWS', lambda e: e.CLEAR_ROWS.split('{names}')[0]), ('PLAIN_ELSEWHERE', lambda e: e.PLAIN_ELSEWHERE),
         ('PLAIN_REFUSED', lambda e: e.PLAIN_REFUSED), ('HASH_UNREADABLE', lambda e: e.HASH_UNREADABLE.split('{side}')[0]),
         ('DB_OFF', lambda e: e.DB_OFF.split('{names}')[0]), ('ACCOUNTS_STOP', lambda e: e.ACCOUNTS_STOP.split('{ha}')[0]))


def kind(ha_emqx, text):
    for name, head in KINDS:
        if text.startswith(head(ha_emqx)):
            return name
    return 'other:' + L.digest(text.encode())[:12]


def main(codebase, arch):
    ha_emqx = L.use(codebase)
    sys.path.append(LAB_TESTS)
    from woowbackup import habackup, hasecuretar
    import ha_import_b1_e2e as b1
    started = time.time()
    path = sorted(glob.glob(FIXTURES[arch]))[0]
    result = {'test': 'T16R real batch-1 HA backup through the product check path (iteration 8)', 'codebase': codebase,
              'arch': arch, 'fixture': os.path.basename(path),
              'fixture_sha256_prefix': L.digest(open(path, 'rb').read())[:16], 'image': L.IMAGE, 'network': 'none',
              'store': 'labpodman (separate --root)'}
    creds = b1.Secrets([b1.SECRET_DIR / 'b1-creds.env', b1.SECRET_DIR / 'ha-import-creds.env'],
                       b1.SECRET_DIR / 'dev-d-markers.json')
    keys = hasecuretar.Keys(creds['HA_BACKUP_KEY'])
    with habackup.open_backup(path) as hb:
        slugs = [m.slug for m in hb.layout.members if m.role == 'addon' and m.slug.endswith('woow-emqx')]
        versions = [a.get('version') for a in hb.layout.doc['addons'] if str(a.get('slug', '')).endswith('woow-emqx')]
    host_dir = tempfile.mkdtemp(prefix='t16r-host-', dir=os.path.join(L.SR, 'runs'))
    os.chmod(host_dir, 0o755)
    acl_host = os.path.join(host_dir, 'acl.conf')
    with open(acl_host, 'wb') as handle:
        handle.write(T1.TARGET_ACL)
    os.chmod(acl_host, 0o644)
    home = os.path.join(host_dir, 'home')
    os.makedirs(os.path.join(home, '.config', 'emqx'), mode=0o700)
    env_file = os.path.join(home, '.config', 'emqx', 'emqx.env')
    with open(env_file, 'w') as handle:
        handle.write(f'# woow emqx\nEMQX_LOG__CONSOLE__LEVEL=warning\nEMQX_NODE__COOKIE={secrets.token_hex(16)}\n'
                     'WOOW_EMQX_BIND=0.0.0.0\n')
    os.chmod(env_file, 0o600)
    s_boot, s_dash = f'secrev-t16r{arch}-bootstrap', f'secrev-t16r{arch}-dashboard'
    for name, value in ((s_boot, b'user_id,password,is_superuser\nwoow,' + secrets.token_hex(16).encode() + b',false\n'),
                        (s_dash, secrets.token_hex(12).encode())):
        L.lab('secret', 'rm', name, check=False)
        L.lab('secret', 'create', name, '-', input=value)
    hocon = BUILTIN_SOURCES + T1.target_hocon('/opt/emqx/etc/acl.conf').split(b'}\n', 1)[1]
    lab_target = L.LabTarget(f't16r{arch}', {'configs/cluster.hocon': hocon},
                             ro_files=[(acl_host, '/opt/emqx/etc/acl.conf', 'ro')],
                             secrets_spec=[f'{s_boot},type=mount,target={T1.BOOT},uid=1000,gid=1000,mode=0400',
                                           f'{s_dash},type=env,target=EMQX_DASHBOARD__DEFAULT_PASSWORD'],
                             env_file=env_file)
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
        with L.temp(runner) as tmp:
            try:
                src = ha_emqx.member_pass(work, tmp)
                node, blocker = ha_emqx.node_name(src)
                readings = None
                if blocker is None:
                    readings = ha_emqx.ha_broker(work, tmp, target, src, node)
                    ha_emqx._clean(tmp, 'emqx-ha', volumes=('emqx-src', 'emqx-ha-log'))
                profile, target_blocker = ha_emqx.target_preflight(work, app, target)
                device = ha_emqx.device_accounts(ha_emqx.device_execute(work, app, target))
                blockers, warnings = ha_emqx.analyse(src, readings, addon_version=version, version='5.8.9',
                                                     profile=profile, device=device)
                if blocker:
                    blockers.insert(0, blocker)
                if target_blocker:
                    blockers.append(target_blocker)
                hashing = (readings or {}).get('hashing')
                result['check'] = {
                    'blockers': [kind(ha_emqx, b) for b in blockers],
                    'warnings': [kind(ha_emqx, w) for w in warnings],
                    'ha_hashing': None if hashing is None else {k: hashing[k] for k in ('enable', 'name', 'salt')},
                    'ha_plain': None if readings is None else {k: readings['plain'][k] for k in ('elsewhere', 'clear')},
                    'ha_mqtt_users': max((readings or {}).get('counts', {}).get('emqx_authn_mnesia', 0), 0),
                    'device_profile': list(profile or ()),
                    'device_hashing': None if device is None else device['hashing']['name'] + '/' + str(
                        device['hashing']['salt'])}
            except L.BackupError as error:
                result['check'] = {'refused': kind(ha_emqx, error.message)}
        hb.close()
    finally:
        lab_target.remove()
        for name in (s_boot, s_dash):
            L.lab('secret', 'rm', name, check=False)
        os.unlink(env_file)
    result['containers_left'] = len(L.lab('ps', '-a', '--filter', 'name=woowbk-j', '-q').stdout.split())
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False))
    L.evidence(os.path.join(L.SR, 'runs', f't16r-{codebase}-{arch}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
