"""T5b (SR-5, iterations 4 and 5): like T5, but HA's built-in-database authenticator carries `name = plain` WITH an
EXPLICIT `salt_position` (iteration 3's T5 omitted it, so EMQX filled the default and the authentication-root comparison
refused -- an artefact, not SR-5). The question: does the product conversion keep HA's `plain` authenticator and thereby
store THIS device's own bootstrap MQTT password in clear text in the candidate's built-in database (and so in the
converted backup)? And can this device's own MQTT account still log in?
Vendor: hash_data(plain, P) = P (emqx_passwd.erl:92-105) for a user row written under such an authenticator, but a
bootstrap import never overwrites an existing row (emqx_authn_mnesia.erl boostrap_user_from_file, override => false), and
the candidate already wrote the row under the device's own authenticator at its boot, before HA's data came.
Everything is compared inside the brokers against the mounted bootstrap file; only true/false and row counts leave them.
Mode `control`: HA's authenticator hashes like the device's (sha256, suffix); the login must work, or the login check is
no check. Lab store, --network none, generated credentials.
Run: python3 -I t5b_plain_explicit.py <codebase> [disable|prefix|suffix|control][,...]"""
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

# This device's bootstrap account against the broker's own authentication, with its password and with a wrong one.
LOGIN = ('{ok, B} = file:read_file("' + T1.BOOT + '"), '
         '[_, Row | _] = binary:split(B, <<"\\n">>, [global]), [U, P | _] = binary:split(Row, <<",">>, [global]), '
         'C = #{clientid => <<"secrev">>, username => U, zone => default, listener => \'tcp:default\', protocol => mqtt, '
         'peerhost => {127,0,0,1}, is_superuser => false, mountpoint => undefined}, '
         'F = fun(W) -> case emqx_access_control:authenticate(C#{password => W}) of {ok, _} -> "login"; '
         '{error, _} -> "refused"; _ -> "other" end end, '
         'io:format("WOOWL:own=~s:wrong=~s:END", [F(P), F(<<P/binary, "x">>)]).')


def ha_hocon(mode):
    if mode == 'control':
        return T1.HA_HOCON
    return T1.HA_HOCON.replace(b'name = sha256, salt_position = suffix',
                               b'name = plain, salt_position = ' + mode.encode())


def addon_tar(mode):
    base = 'data/emqx/data/'
    return L.tar_bytes({
        'addon.json': json.dumps({'system': {'slug': 'woow-emqx', 'name': 'EMQX'}, 'version': '5.9.1',
                                  'user': {'image': 'ghcr.io/woowtech/woow-ha-emqx-amd64'}, 'state': 'stopped'}).encode(),
        'data/emqx/node.name': b'emqx@127.0.0.1\n',
        base + 'mnesia/emqx@127.0.0.1': None,
        base + 'configs/cluster.hocon': ha_hocon(mode),
        base + 'authz/acl.conf': T1.HA_ACL,
    })


def read(execute, expression, mark):
    out = (execute(['emqx', 'eval', expression]).stdout or b'').decode(errors='replace')
    return out.split(mark, 1)[1].split(':END', 1)[0] if mark in out else 'unreadable'


def one(ha_emqx, mode, *, runner, target):
    out = {'ha_hocon_sha256': L.digest(ha_hocon(mode))}
    started = time.time()
    work = L.FakeWork(runner)
    inner = addon_tar(mode)
    work.addon_member = lambda slug: slug
    work.open = lambda member: io.BytesIO(inner)
    work.addon_info = lambda slug: L.SimpleNamespace(version='5.9.1')
    app = L.SimpleNamespace(id='emqx', name='EMQX')
    staging = Path(tempfile.mkdtemp(prefix='t5b-', dir=os.path.join(L.SR, 'runs')))
    with L.temp(runner) as tmp:
        try:
            ha_emqx._build_candidate(work, app, tmp, target, staging, version='5.8.9')
            out['conversion'] = 'PASSED (candidate built, all product checks green)'
        except L.BackupError as error:
            out['conversion'] = 'REFUSED: ' + error.message
        if tmp.running('emqx-new'):
            inside = lambda c: tmp.exec('emqx-new', c, timeout=120, check=False)
            out['candidate'] = read(inside, CHECK, 'WOOWT5:')
            out['candidate_login'] = read(inside, LOGIN, 'WOOWL:')
            cfg = ha_emqx.read_effective_config(inside)
            out['candidate_authn_algorithms'] = [((a.get('password_hash_algorithm') or {}).get('name'),
                                                  bool(a.get('bootstrap_file'))) for a in cfg.get('authentication', [])]
            # The restored broker boots the same files: a restart of the candidate imports the bootstrap file again.
            L.lab('restart', '-t', '60', tmp.name('emqx-new'), timeout=300)
            end = time.monotonic() + 240
            while time.monotonic() < end and b'is started' not in (inside(['emqx', 'ctl', 'status']).stdout or b''):
                time.sleep(3)
            out['candidate_after_restart'] = read(inside, CHECK, 'WOOWT5:')
            out['candidate_login_after_restart'] = read(inside, LOGIN, 'WOOWL:')
    out['conversion_refused'] = out['conversion'].startswith('REFUSED')
    out['device_bootstrap_password_stored_plaintext'] = any(
        ':plain=1' in out.get(key, '') for key in ('candidate', 'candidate_after_restart'))
    out['elapsed_s'] = round(time.time() - started, 1)
    return out


def main(codebase, modes):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': 'T5b SR-5 HA plain authenticator with explicit salt_position vs this device bootstrap users',
              'codebase': codebase, 'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)', 'modes': {}}
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
        result['device_before'] = read(target.execute, CHECK, 'WOOWT5:')
        result['device_login_before'] = read(target.execute, LOGIN, 'WOOWL:')
        runner = L.make_runner()
        for mode in modes:
            result['modes'][mode] = one(ha_emqx, mode, runner=runner, target=target)
            print(mode, json.dumps(result['modes'][mode], ensure_ascii=False), flush=True)
        result['device_after'] = read(target.execute, CHECK, 'WOOWT5:')
    finally:
        target.remove()
        L.lab('secret', 'rm', secret, check=False)
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False))
    L.evidence(os.path.join(L.SR, 'runs', f't5b-{codebase}-{"-".join(modes)}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else 'disable').split(','))
