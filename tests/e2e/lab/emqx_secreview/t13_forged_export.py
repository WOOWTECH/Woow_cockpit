"""T13 (B1-03, iteration 5): an EMQX export that brings configuration roots of THIS device, through the product's real
candidate (candidate_from_target: capture of the device, candidate, import, settings restore, every product check) in
real EMQX 5.8.9 brokers.

What is real: HA's throwaway broker makes the export of a crafted add-on (member_pass, ha_broker, take_export), the
device stand-in and the candidate are real brokers, the import is the vendor's `emqx ctl data import`. What is
simulated: the extra roots are written into the export by this harness (a healthy broker never exports them,
ha_broker's --root-keys), with harmless values that differ from the device's. Variants:
  control    the export repacked by the same code without a change (must pass, so a refusal is not the repacking's)
  all        listeners, the generic roots the vendor import applies (mqtt, sysmon, log, broker, ...) and the roots it has
             no importer for (dashboard, node, cluster, rpc), all at once
  listeners  listeners only (the vendor import has an importer for it)
  generic    mqtt, sysmon, log, broker, force_gc, alarm, flapping_detect
  boot       dashboard, node, cluster, rpc
For every variant: was `data import` reached, which roots of the device had changed right after it, what the product
did, and, when a candidate was built: which of the device's roots differ in it, in the configuration it keeps on disk
and after a restart of its container. Root names and booleans only.
Run: python3 -I t13_forged_export.py <codebase> <variant>[,<variant>...]"""
import base64
import io
import json
import os
import secrets
import sys
import tarfile
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L  # noqa: E402
import t1_datadir_acl as T1  # noqa: E402

LISTENERS = ('listeners {\n  tcp {\n    default {max_connections = 4321}\n'
             '    secrev {bind = "127.0.0.1:18831", max_connections = 7}\n  }\n}\n')
GENERIC = ('mqtt {max_packet_size = 2MB}\nsysmon {os {cpu_check_interval = 71s}}\nlog {console {level = error}}\n'
           'broker {shared_subscription_strategy = hash_clientid}\nforce_gc {count = 17000}\n'
           'alarm {size_limit = 1234}\nflapping_detect {max_count = 23}\n')
BOOT = ('dashboard {token_expired_time = 47m}\nnode {process_limit = 1048577}\ncluster {autoclean = 23h}\n'
        'rpc {call_receive_timeout = 16s}\n')
VARIANTS = {'control': '', 'listeners': LISTENERS, 'generic': GENERIC, 'boot': BOOT, 'all': LISTENERS + GENERIC + BOOT}
KEPT_EXPR = ('io:format("WOOWK:~s:END", [base64:encode(emqx_utils_json:encode('
             'emqx_config:read_override_conf(#{override_to => cluster})))]).')


def forge(export, text, out):
    """The same archive with `text` appended to cluster.hocon (the same members, names and order)."""
    with tarfile.open(export, 'r:gz') as src, tarfile.open(out, 'w:gz', format=tarfile.USTAR_FORMAT) as dst:
        for member in src:
            data = src.extractfile(member).read()
            if member.name.endswith('/cluster.hocon') and text:
                data += b'\n' + text.encode()
            member.size = len(data)
            dst.addfile(member, io.BytesIO(data))


def kept_on_disk(execute):
    out = (execute(['emqx', 'eval', KEPT_EXPR]).stdout or b'').decode(errors='replace')
    return json.loads(base64.b64decode(out.split('WOOWK:', 1)[1].split(':END', 1)[0]))


def wait_started(execute, timeout=240):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = execute(['emqx', 'ctl', 'status'])
        if r.returncode == 0 and b'is started' in (r.stdout or b''):
            return True
        time.sleep(3)
    return False


def one(ha_emqx, label, text, *, work, app, runner, target, export, ids, device):
    out = {'forged_roots': sorted({line.split(' ', 1)[0] for line in text.splitlines() if line[:1].isalpha()})}
    data_roots = set(ha_emqx.DATA_ROOTS) - {'authorization'}
    differ = lambda a, b: sorted(k for k in (set(a) | set(b)) - data_roots if a.get(k) != b.get(k))
    real_restore, real_ctl = ha_emqx.restore_target_settings, ha_emqx.ctl
    imports = []

    def spy_restore(tmp, original, read_candidate, **kwargs):
        seen = ha_emqx.read_effective_config(read_candidate, allow_authz_omission=True)
        out['device_roots_changed_by_the_import'] = differ(seen, original)
        return real_restore(tmp, original, read_candidate, **kwargs)

    def spy_ctl(tmp, role, args, **kwargs):
        if list(args[:2]) == ['data', 'import']:
            imports.append(role)
        return real_ctl(tmp, role, args, **kwargs)
    staging = Path(tempfile.mkdtemp(prefix=f't13-{label}-', dir=os.path.join(L.SR, 'runs')))
    forged = staging / os.path.basename(export)
    forge(export, text, forged)
    ha_emqx.restore_target_settings, ha_emqx.ctl = spy_restore, spy_ctl
    started = time.time()
    try:
        with L.temp(runner) as tmp:
            try:
                ha_emqx.candidate_from_target(work, app, tmp, target, staging, str(forged), ids)
                out['conversion'] = 'PASSED (candidate built, all product checks green)'
                inside = lambda c: tmp.exec('emqx-new', c, timeout=120, check=False)
                out['device_roots_differing_in_the_candidate'] = differ(ha_emqx.boot_form(inside),
                                                                       ha_emqx.boot_form(target.execute))
                kept = kept_on_disk(inside)
                out['device_roots_kept_on_disk'] = sorted(set(kept) - data_roots)
                out['forged_marker_on_disk'] = 'secrev' in json.dumps(kept.get('listeners', {}))
                boot_before = ha_emqx.boot_form(target.execute)
                L.lab('restart', '-t', '60', tmp.name('emqx-new'), timeout=300)
                out['candidate_restarted'] = wait_started(inside)
                out['device_roots_differing_after_restart'] = differ(ha_emqx.boot_form(inside), boot_before)
            except L.BackupError as error:
                out['conversion'] = 'REFUSED: ' + error.message
    finally:
        ha_emqx.restore_target_settings, ha_emqx.ctl = real_restore, real_ctl
        for name in sorted(os.listdir(staging)):
            if (staging / name).is_file():
                os.unlink(staging / name)
    out['data_imports'] = len(imports)
    out['device_unchanged'] = ha_emqx.read_effective_config(target.execute) == device
    out['elapsed_s'] = round(time.time() - started, 1)
    return out


def main(codebase, variants):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': 'T13 an export that brings roots of this device (B1-03)', 'codebase': codebase, 'image': L.IMAGE,
              'network': 'none', 'store': 'labpodman (separate --root)',
              'simulated': 'the extra roots are written into the real export by the harness', 'variants': {}}
    host_dir = tempfile.mkdtemp(prefix='t13-host-', dir=os.path.join(L.SR, 'runs'))
    os.chmod(host_dir, 0o755)
    acl_host = os.path.join(host_dir, 'acl.conf')
    with open(acl_host, 'wb') as handle:
        handle.write(T1.TARGET_ACL)
    os.chmod(acl_host, 0o644)
    s_boot, s_dash = 'secrev-t13-bootstrap', 'secrev-t13-dashboard'
    for name, value in ((s_boot, b'user_id,password,is_superuser\nwoow,' + secrets.token_hex(16).encode() + b',false\n'),
                        (s_dash, secrets.token_hex(12).encode())):
        L.lab('secret', 'rm', name, check=False)
        L.lab('secret', 'create', name, '-', input=value)
    target = L.LabTarget('t13', {'configs/cluster.hocon': T1.target_hocon('/opt/emqx/etc/acl.conf')},
                         ro_files=[(acl_host, '/opt/emqx/etc/acl.conf', 'ro')],
                         secrets_spec=[f'{s_boot},type=mount,target={T1.BOOT},uid=1000,gid=1000,mode=0400',
                                       f'{s_dash},type=env,target=EMQX_DASHBOARD__DEFAULT_PASSWORD'])
    dangling = L.dangling_names()
    try:
        runner = L.make_runner()
        work = L.FakeWork(runner)
        inner = T1.addon_tar()
        work.addon_member = lambda slug: slug
        work.open = lambda member: io.BytesIO(inner)
        work.addon_info = lambda slug: L.SimpleNamespace(version='5.9.1')
        app = L.SimpleNamespace(id='emqx', name='EMQX')
        device = ha_emqx.read_effective_config(target.execute)
        staging = Path(tempfile.mkdtemp(prefix='t13-', dir=os.path.join(L.SR, 'runs')))
        with L.temp(runner) as tmp:
            src = ha_emqx.member_pass(work, tmp)
            node, blocker = ha_emqx.node_name(src)
            readings = ha_emqx.ha_broker(work, tmp, target, src, node, out_dir=staging)
            tmp.stop('emqx-ha', timeout=60)
            tmp.remove('emqx-ha')
            export = ha_emqx.take_export(work, tmp, readings['export'], staging)
            ids = tmp.user_ids('ids-emqx', target.image, 'emqx')
        with tarfile.open(export, 'r:gz') as archive:
            result['real_export_members'] = [m.name.split('/', 1)[1] for m in archive]
        for label in variants:
            result['variants'][label] = one(ha_emqx, label, VARIANTS[label], work=work, app=app, runner=runner,
                                            target=target, export=str(export), ids=ids, device=device)
            print(label, json.dumps(result['variants'][label], ensure_ascii=False), flush=True)
        os.unlink(export)
    finally:
        target.remove()
        for name in (s_boot, s_dash):
            L.lab('secret', 'rm', name, check=False)
    result['dangling_volumes_new'] = L.new_dangling(dangling)
    result['containers_left'] = len(L.lab('ps', '-a', '--filter', 'name=woowbk-j', '-q').stdout.split())
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False))
    L.evidence(os.path.join(L.SR, 'runs', f't13-{codebase}-{"-".join(variants)}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2].split(','))
