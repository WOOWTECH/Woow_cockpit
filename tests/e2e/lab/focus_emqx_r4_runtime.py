#!/usr/bin/env python3
"""Device-side synthetic R4 case. Only invocation-owned paths/resources; never a catalog/helper/package install.

PREPARED, NOT NATIVE-VALIDATED. Fixed evidence names only; any vendor/schema surprise fails the case.
"""
import base64
import copy
import io
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import focus_emqx_r4_fixtures as fx
from woowbackup import ha_emqx as emqx, haissues, tempctr
from woowbackup.errors import BackupError

LIMIT = 256 * 1024**2
JOB = ''
CHECKS = []
PROBES = []  # every login's CONNACK codes, in order (login_code)
OBSERVED = {}  # values a case records without judging them (H1: the effective no_match right after the import)
STAGE = 'preflight'
HTTP_AUTH_CASES = ('http_dummy', 'lost_auth_setting')
HTTP_AUTH_SETTLE = 45  # seconds a refused login is retried while EMQX's HTTP backend reconnects to the dummy
HTTP_AUTH_PAUSE = 3


def check(name, value=True):
    CHECKS.append({'name': name, 'ok': bool(value)})
    if not value:
        raise RuntimeError('fixed_check_failed')


class Runner:
    """No foreign target, network creation, image load/pull, secrets, service or catalog operations."""
    owner, uid, home = 'appowner', 1019, '/home/appowner'

    def own(self, name):
        return bool(re.fullmatch(re.escape('woowbk-' + JOB + '-') + r'[a-z0-9-]+', name))

    def validate(self, args):
        verb = args[0]
        if verb == 'run':
            if (args.count('--name') != 1 or not self.own(args[args.index('--name') + 1])
                    or args.count(fx.IMAGE) != 1 or '--pull=never' not in args
                    or args[args.index('--network') + 1] != 'none'
                    or any(x in args for x in ('--publish', '-p', '--privileged', '--secret'))):
                raise ValueError('foreign_or_unbounded_run')
            for i, value in enumerate(args):
                if value == '--volume':
                    source = args[i + 1].split(':', 1)[0]
                    if not self.own(source) and not Path(source).resolve().is_relative_to(ROOT):
                        raise ValueError('foreign_host_mount')
            if args[args.index('--memory') + 1] != '768m':
                raise ValueError('fixture_memory_budget')
        elif verb == 'exec':
            # Product TempObjects can prepend --interactive/--user/--env before the container.
            index = 1
            while index < len(args) and args[index].startswith('--'):
                option = args[index]; index += 1
                if option in ('--user', '--env', '--workdir'): index += 1
                elif option != '--interactive': raise ValueError('unexpected_exec_option')
            if index >= len(args) or not self.own(args[index]):
                raise ValueError('foreign_exec')
        elif verb in ('stop', 'start', 'rm'):
            index = 1
            while index < len(args) and args[index].startswith('--'):
                option = args[index]; index += 1
                if option == '--time':
                    if index >= len(args) or not args[index].isdigit(): raise ValueError('lifecycle_timeout')
                    index += 1
                elif option not in ('--force', '--ignore', '--volumes'):
                    raise ValueError('unexpected_lifecycle_option')
            if index != len(args) - 1 or not self.own(args[index]):
                raise ValueError('foreign_lifecycle')
        elif verb == 'volume':
            if args[1] in ('create', 'export', 'rm', 'inspect', 'exists'):
                if not self.own(args[-1]): raise ValueError('foreign_volume')
            elif args[1] == 'import':
                if len(args) != 4 or not self.own(args[2]) or args[3] != '-':
                    raise ValueError('foreign_volume')
            elif args[1] != 'ls': raise ValueError('unexpected_volume_operation')
        elif verb == 'unshare':
            # Product uid adjustment only, to this invocation's Podman volume directory.
            if args[1] not in ('chown', 'chmod') or not re.search('/volumes/' + re.escape('woowbk-' + JOB + '-')
                                                               + r'[a-z0-9-]+/_data/?$', args[-1]):
                raise ValueError('foreign_volume_chown')
        elif verb == 'container':
            if args[1] not in ('inspect', 'exists') or not self.own(args[-1]): raise ValueError('foreign_inspect')
        elif verb == 'image':
            if not (args[1] == 'ls' or (args[1] == 'inspect' and args[2] == fx.IMAGE)):
                raise ValueError('image_mutation_refused')
        elif verb not in ('ps', 'info'):
            raise ValueError('unreviewed_operation')

    def podman(self, *args, **kwargs):
        args = list(args); self.validate(args)
        if args[0] == 'run':
            args[1:1] = ['--image-volume=ignore', '--cap-drop=ALL', '--memory-swap=768m']
        if args[0] == 'rm': args.insert(1, '--volumes')
        if args[0] in ('run', 'exec', 'start') or args[:2] in (['volume', 'create'], ['volume', 'import']):
            if shutil.disk_usage(ROOT).free < 13 * 1024**3:
                raise RuntimeError('disk_floor')
        incoming = kwargs.get('input'); streamed = hasattr(incoming, 'read'); output = kwargs.get('stdout')
        proc = subprocess.run(['podman', '--runtime=crun', *args], stdin=incoming if streamed else None,
            input=None if streamed else incoming, stdout=output if output is not None else subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=min(kwargs.get('timeout', 120), 180))
        if len(proc.stdout or b'') > (kwargs.get('max_output') or 8 * 1024**2):
            raise RuntimeError('output_budget')
        if output is not None and output.tell() > LIMIT:
            raise RuntimeError('file_budget')
        if proc.returncode and kwargs.get('check', True):
            # Only reviewed fixture diagnostics, private and bounded by RLIMIT_FSIZE. Never print these bytes.
            with (ROOT / 'private.log').open('ab') as log: log.write((proc.stdout or b'') + proc.stderr)
            raise RuntimeError('nested_command_failed')
        return proc

    def relay(self, args, **kwargs):
        return self.podman(*args, **kwargs)


class Budget:
    used = 0
    def budget(self): return LIMIT - self.used
    def check(self, size):
        if not 0 <= size <= self.budget(): raise RuntimeError('staging_budget')
    def account(self, size): self.check(size); self.used += size
    def forget(self, size): self.used = max(0, self.used - size)


def inventory(runner):
    calls = [('ps', '-a', '--format', '{{.ID}}'), ('volume', 'ls', '--format', '{{.Name}}'),
             ('image', 'ls', '--no-trunc', '--format', '{{.ID}} {{.Repository}}:{{.Tag}}')]
    return [sorted(runner.podman(*args).stdout.splitlines()) for args in calls]


def seed(tmp, role, conf, acl, ids):
    tmp.volume(role)
    def write(out):
        with tarfile.open(fileobj=out, mode='w|') as archive:
            for directory in ('.', 'configs', 'authz'):
                item = tarfile.TarInfo(directory); item.type = tarfile.DIRTYPE
                item.mode = 0o755; item.uid, item.gid = ids; archive.addfile(item)
            for name, data in [('configs/cluster.hocon', json.dumps(conf).encode()), ('authz/acl.conf', acl)]:
                item = tarfile.TarInfo(name); item.size = len(data); item.mode = 0o600; item.uid, item.gid = ids
                archive.addfile(item, io.BytesIO(data))
    tmp.volume_import(role, write)


def exec_read(tmp, role):
    return lambda command: tmp.exec(role, command, timeout=120, max_output=emqx.MAX_HOCON, check=False)


# Local HTTP dummy discards the entire bounded request and returns only fixed fixture authorization.
# No request body, credentials, file, environment, response token or external address is logged/captured.
# Each accepted connection gets its own process: EMQX's HTTP backend keeps a pool of idle connections open, and a
# loop that waited on one connection at a time queued the real request behind them (http_dummy native01/02).
HTTP_DUMMY = '''case whereis(woow_r4_http) of undefined ->
{ok,L}=gen_tcp:listen(18091,[binary,{active,false},{reuseaddr,true},{ip,{127,0,0,1}}]),
Serve=fun(Sock) -> case gen_tcp:recv(Sock,0,30000) of {ok,B} when byte_size(B)=<8192 ->
Body = <<"{\\"result\\":\\"allow\\",\\"is_superuser\\":false}">>,
gen_tcp:send(Sock,["HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nConnection: close\\r\\nContent-Length: ",
integer_to_list(byte_size(Body)),"\\r\\n\\r\\n",Body]);_->ok end,gen_tcp:close(Sock) end,
P=spawn(fun() -> Loop=fun F() -> case gen_tcp:accept(L,1000) of
{ok,S}->C=spawn(fun() -> receive {go,T} -> Serve(T) end end),
ok=gen_tcp:controlling_process(S,C),C ! {go,S},F();
{error,timeout}->F();_->ok end end,Loop() end),
true=register(woow_r4_http,P),ok=gen_tcp:controlling_process(L,P);_->ok end,
io:format("WOOWHTTP:ready:END").'''

ACL_ROW = ('ok=emqx_authz_mnesia:store_rules({username,<<"r4_source">>},'
           '[#{<<"permission">>=><<"allow">>,<<"action">>=><<"all">>,<<"topic">>=><<"r4/#">>}]),'
           'io:format("WOOWACL:seeded:END").')


def case_assertions(tmp, case_id, *, restarted=False):
    """Only fixed owned inputs; no general file/env reader or caller-supplied evaluation expression."""
    if case_id == 'env_wins_h1':
        # The import applies HA's settings to the running broker; this device's environment takes over at the next start,
        # as the product's env-wins notice says (native01 saw HA's allow right after the import). So only the restarted
        # broker is judged; the import's value is recorded. HA's value must be in the file both times.
        value = no_match(tmp, 'emqx-new')
        if restarted:
            check('h1_device_environment_wins_after_the_restart', value == fx.H1_ENV['EMQX_AUTHORIZATION__NO_MATCH'])
        else:
            OBSERVED['h1_no_match_after_import'] = value
        conf = tmp.exec('emqx-new', ['cat', '/opt/emqx/data/configs/cluster.hocon']).stdout
        check('h1_config_file_holds_has_value', re.findall(rb'no_match\s*[=:]\s*"?(allow|deny)', conf) == [b'allow'])
    if case_id == 'changed_acl':
        result = tmp.exec('emqx-new', ['cat', '/opt/emqx/data/authz/acl.conf']).stdout
        check('owned_source_acl_bytes_replace_target', result == fx.SOURCE_ACL)
        check('inactive_builtin_acl_rows_survive_source_removal',
              emqx.parse_counts(emqx.evaluate(tmp, 'emqx-new', emqx.COUNT_EXPR))['emqx_acl'] > 0)
        check('owned_acl_allows_own_topic', mqtt_probe(tmp, 'emqx-new', topic='r4/probe') == 1)
        check('owned_acl_denies_other_topic', mqtt_probe(tmp, 'emqx-new', topic='forbidden/probe') == 128)
    if case_id == 'psk':
        expr = ('io:format("WOOWPSK:~p:END",[emqx_psk:on_psk_lookup(<<"r4_shared">>,undefined)'
                ' =:= {stop,{ok,<<"' + fx.DUMMY_PSK + '">>}}]).')
        check('source_psk_replaces_same_owned_target_identity', 'WOOWPSK:true:END' in emqx.evaluate(tmp, 'emqx-new', expr))
    if case_id in ('jq_constant', 'env_dummy'):
        query = '.fixture' if case_id == 'jq_constant' else 'env.WOOW_R4_DUMMY'
        expected = 'r4' if case_id == 'jq_constant' else fx.DUMMY_ENV
        expr = ('V=emqx_rule_funcs:jq(<<"' + query + '">>, <<"{\\"fixture\\":\\"r4\\"}">>),'
                'io:format("WOOWJQ:~p:END",[V =:= [<<"' + expected + '">>]]).')
        check('pure_jq_or_exact_named_dummy_environment_only', 'WOOWJQ:true:END' in emqx.evaluate(tmp, 'emqx-new', expr))
    if case_id == 'file_dummy':
        config = emqx.read_effective_config(exec_read(tmp, 'emqx-new'))
        connector = config.get('connectors', {}).get('mqtt', {}).get('r4_dummy', {})
        check('owned_file_dummy_connector_retained', connector.get('enable') is True
              and connector.get('server') == '127.0.0.1:1883'
              and connector.get('password') == 'file:///fixture/file-dummy.txt')


def mqtt_packet(username=None, password=None):
    def field(value):
        data = value.encode(); return len(data).to_bytes(2, 'big') + data
    flags = 2 | (128 if username is not None else 0) | (64 if password is not None else 0)
    body = b'\x00\x04MQTT\x04' + bytes([flags]) + b'\x00\x0a' + field('r4-owned-probe')
    if username is not None: body += field(username)
    if password is not None: body += field(password)
    if len(body) >= 128: raise ValueError('fixture_packet_budget')
    return b'\x10' + bytes([len(body)]) + body


def mqtt_probe(tmp, role, username='r4_source', password=fx.DUMMY_PASSWORD, *, topic=None):
    packet = base64.b64encode(mqtt_packet(username, password)).decode()
    tail = 'gen_tcp:close(S),io:format("WOOWMQTT:~B:END",[Code]).'
    if topic is not None:
        if topic not in ('r4/probe', 'forbidden/probe'): raise ValueError('owned_topics_only')
        body = b'\x00\x01' + len(topic).to_bytes(2, 'big') + topic.encode() + b'\x01'
        subscribe = base64.b64encode(b'\x82' + bytes([len(body)]) + body).decode()
        tail = ('0=Code,ok=gen_tcp:send(S,base64:decode(<<"' + subscribe + '">>)),'
                '{ok,<<144,3,0,1,SubCode>>}=gen_tcp:recv(S,5,3000),gen_tcp:close(S),'
                'io:format("WOOWMQTT:~B:END",[SubCode]).')
    expr = ('{ok,S}=gen_tcp:connect({127,0,0,1},1883,[binary,{active,false}],3000),'
            'ok=gen_tcp:send(S,base64:decode(<<"' + packet + '">>)),'
            '{ok,<<32,2,_,Code>>}=gen_tcp:recv(S,4,3000),' + tail)
    answer = emqx.evaluate(tmp, role, expr)
    match = re.search(r'WOOWMQTT:(0|1|2|3|4|5|128):END', answer)
    if not match: raise RuntimeError('mqtt_probe_unreadable')
    return int(match[1])


def login_code(tmp, role, case_id, *args, **kwargs):
    """mqtt_probe's CONNACK code. The HTTP-authentication cases start their loopback dummy only after the broker
    booted, so EMQX's HTTP backend may still be reconnecting to it (it retries on its resource health check): there
    a refused login is tried again for up to HTTP_AUTH_SETTLE seconds. Only the last code counts; all are in PROBES
    (-1: no readable CONNACK within the probe's 3 s, which there counts as one more refused try)."""
    http = case_id in HTTP_AUTH_CASES
    def attempt():
        try:
            return mqtt_probe(tmp, role, *args, **kwargs)
        except RuntimeError as error:
            if not http or str(error) != 'mqtt_probe_unreadable': raise
            return -1
    codes = [attempt()]
    deadline = time.monotonic() + (HTTP_AUTH_SETTLE if http else 0)
    while codes[-1] != 0 and time.monotonic() < deadline:
        time.sleep(HTTP_AUTH_PAUSE)
        codes.append(attempt())
    PROBES.append({'role': role, 'codes': codes})
    return codes[-1]


def restart_stable(case_id, record, after):
    """The restart check: normally nothing may differ from the import's record. H1: this device's environment takes over
    the authorization setting at this start, and the product's own restore check reminds of a settings difference and
    fails only on a table one (compare_parts, E-90), so there exactly the authorization setting may differ."""
    if case_id != 'env_wins_h1':
        return not emqx.compare_readback(record, after)
    settings, tables = emqx.compare_parts(record, after)
    OBSERVED['h1_restart_settings_difference'] = settings
    only_authorization = emqx.compare_readback({'config_roots': {'authorization': 0}}, {'config_roots': {'authorization': 1}})
    return not tables and settings == only_authorization


NO_MATCH_EXPR = 'io:format("WOOWNM:~s:END",[emqx:get_config([authorization,no_match])]).'


def no_match(tmp, role):
    """The broker's effective authorization.no_match: what decides, whatever the files say (H1)."""
    match = re.search(r'WOOWNM:(allow|deny):END', emqx.evaluate(tmp, role, NO_MATCH_EXPR))
    if not match: raise RuntimeError('no_match_unreadable')
    return match[1]


def device_target(tmp, mounts, env):
    """H1: this generated device as the product's own Target, read from a Quadlet file the way the product reads the
    live one, so the candidate gets this device's EMQX_* environment and the env-wins notice is the product's own."""
    lines = ['[Container]', 'Image=' + fx.IMAGE, 'ContainerName=' + tmp.name('emqx-ha'),
             'Volume=' + tmp.name('device') + ':' + emqx.DATA_TARGET,
             'Volume=' + tmp.name('device-log') + ':' + emqx.LOG_TARGET]
    home = tmp.runner.home.rstrip('/') + '/'
    for source, target, option in mounts:   # the product accepts host paths only as %h/... (its own home)
        if not source.startswith(home): raise ValueError('h1_mount_outside_home')
        lines.append('Volume=%h/' + source[len(home):] + ':' + target + ':' + option)
    lines += ['Environment=' + key + '=' + value for key, value in sorted(env.items()) if key.startswith('EMQX_')]
    body = ('\n'.join(lines) + '\n').encode()
    app = SimpleNamespace(id='emqx', volumes=[{'name': tmp.name('device')}, {'name': tmp.name('device-log')}],
                          postgres=None, data_dirs=[])
    work = SimpleNamespace(quadlets=lambda _app: {'emqx.container': body}, runner=lambda _app: tmp.runner)
    return emqx.Target(work, app)


def read_source(tmp):
    readings = {'counts': emqx.parse_counts(emqx.evaluate(tmp, 'emqx-ha', emqx.COUNT_EXPR)),
        'authn': emqx.parse_authn(emqx.evaluate(tmp, 'emqx-ha', emqx.AUTHN_EXPR)),
        'authz': emqx.parse_authz(emqx.evaluate(tmp, 'emqx-ha', emqx.AUTHZ_EXPR)),
        'strict': emqx.parse_strict(emqx.evaluate(tmp, 'emqx-ha', emqx.STRICT_EXPR)),
        'default_admin': 'default' in emqx.evaluate(tmp, 'emqx-ha', emqx.DEFAULT_ADMIN_EXPR).split(),
        'hashing': emqx.parse_hashing(emqx.evaluate(tmp, 'emqx-ha', emqx.HASH_EXPR)),
        'plain': emqx.parse_plain(emqx.evaluate(tmp, 'emqx-ha', emqx.PLAIN_EXPR)),
        'hash_unreadable': False, 'ticker': True}
    check('complete_nonempty_admin_tables', len(readings['counts']) == len(emqx.TABLES)
          and readings['counts'].get('emqx_admin', 0) > 0)
    return readings


def remove_candidate(tmp, staging):
    tmp.stop('emqx-new', timeout=60); tmp.remove('emqx-new')
    for role in ('emqx-new', 'emqx-new-log', 'emqx-in'):
        check('remove_first_' + role, tmp.remove_volume(role))
    (staging / 'emqx-target-config-snapshot.tar').unlink()


def lines(tmp, target, readings, notes, acknowledged=None):
    sink = haissues.Sink('emqx', acknowledged=acknowledged)
    emqx.source_lines(sink, target, readings)
    emqx.candidate_lines(sink, target, readings, notes, None)
    return sink


def verify(tmp, record, case_id=None):
    body = ('[Container]\nImage=' + fx.IMAGE + '\nContainerName=' + tmp.name('emqx-new') + '\n' +
            'Volume=' + tmp.name('emqx-new') + ':/opt/emqx/data\n' +
            'Volume=' + tmp.name('emqx-new-log') + ':/opt/emqx/log\n').encode()
    adapter = SimpleNamespace(runner=tmp.runner, read_quadlets=lambda: {'fixture.container': body})
    app = SimpleNamespace(id='emqx', volumes=[{'name': tmp.name('emqx-new')}, {'name': tmp.name('emqx-new-log')}],
                          postgres=None, data_dirs=[])
    messages = []
    emqx.verify_restored(adapter, app, record, log=messages.append)
    if case_id == 'env_wins_h1':   # E-90: the setting this device's environment took over is reminded, never failed
        check('h1_restore_check_reminds_not_fails',
              len(messages) == 1 and messages[0].startswith('提醒') and 'authorization' in messages[0])
    else:
        check('unmocked_postcheck_has_no_skipped_receipt', len(messages) == 1 and '核對一致' in messages[0])
    corrupt = copy.deepcopy(record); corrupt['tables']['emqx_admin'][0] += 1
    try: emqx.verify_restored(adapter, app, corrupt, log=lambda _: None)
    except BackupError as error: check('wrong_admin_receipt_refuses', error.code == 'job-failed')
    else: check('wrong_admin_receipt_refuses', False)


def main(case_id):
    global STAGE, JOB
    case = fx.BY_ID[case_id]
    JOB = time.strftime('j%Y%m%dT%H%M%SZ-', time.gmtime()) + secrets.token_hex(4)
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
    def alarm(_s, _f): raise TimeoutError('case_wall_budget')
    signal.signal(signal.SIGALRM, alarm); signal.alarm(840)
    check('appowner_only', os.getuid() == 1019 and Path.home() == Path('/home/appowner') and ROOT.parent == Path.home())
    check('device_headroom', int(Path('/sys/fs/cgroup/memory.max').read_text())
          - int(Path('/sys/fs/cgroup/memory.current').read_text()) >= 1900 * 1024**2)
    check('disk_floor', shutil.disk_usage(ROOT).free >= 13 * 1024**3 + LIMIT)
    runner = Runner()
    check('nested_rootless', runner.podman('info', '--format', '{{.Host.Security.Rootless}}').stdout.strip() == b'true')
    check('exact_image', runner.podman('image', 'inspect', fx.IMAGE, '--format', '{{.Id}}').stdout.strip().decode()
          .removeprefix('sha256:') == fx.IMAGE.removeprefix('sha256:'))
    before = inventory(runner)
    fixture = ROOT / 'fixture'; fixture.mkdir(mode=0o755)
    for name, data in fx.files().items():
        path = fixture / name; path.write_bytes(data); path.chmod(0o644)
    (fixture / 'dead-update.json').write_text(json.dumps(fx.dead_row_update()))
    mounts = [(str(fixture), '/fixture', 'ro')]
    staging = ROOT / 'staging'; staging.mkdir()
    work = SimpleNamespace(runner=lambda _: runner, guard=Budget(), abort=None, checkpoint=lambda: None,
                           log=lambda _: None)
    app = SimpleNamespace(id='emqx')
    env = {'EMQX_NODE__NAME': fx.NODE, 'ERL_AFLAGS': '+S 1:1', 'EMQX_PLUGINS__STATES': '[]',
           'EMQX_PLUGINS__INSTALL_DIR': '/opt/emqx/plugins', 'WOOW_R4_DUMMY': fx.DUMMY_ENV}
    source_env = dict(env, EMQX_DASHBOARD__DEFAULT_PASSWORD='public' if case_id == 'admin_public' else fx.DUMMY_PASSWORD)
    target_env = dict(env, EMQX_DASHBOARD__DEFAULT_PASSWORD='r4-owned-target-admin')
    if case_id == 'env_wins_h1':
        target_env.update(fx.H1_ENV)
    with tempctr.TempObjects(runner, JOB, memory='768m', pids=256, cpus='0.5') as tmp:
        ids = tmp.user_ids('ids', fx.IMAGE, 'emqx')
        seed(tmp, 'source', fx.config(case_id), fx.SOURCE_ACL, ids)
        tmp.volume('source-log'); tmp.volume('emqx-xfer')
        tmp.volume_import('emqx-xfer', lambda out: emqx._folder_tar(out, 'out', *ids))
        def boot(data, log, boot_env):
            tmp.run('emqx-ha', fx.IMAGE, [], detach=True, read_only_root=True, env=boot_env,
                volumes=[(tmp.name(data), emqx.DATA_TARGET, None), (tmp.name(log), emqx.LOG_TARGET, None),
                         (tmp.name('emqx-xfer'), '/work', None)] + mounts)
            emqx.wait_ready(tmp, 'emqx-ha', checkpoint=work.checkpoint)
            check('source_or_target_ticker_paused', emqx.quiesce_system_ticker(tmp, 'emqx-ha') is not None)
        STAGE = 'generated_source'
        boot('source', 'source-log', source_env)
        if case_id == 'env_wins_h1':
            check('h1_ha_broker_allows_unmatched_topics', no_match(tmp, 'emqx-ha') == 'allow')
        if case_id == 'changed_acl':
            check('seed_nonempty_acl_through_vendor_management_api',
                  'WOOWACL:seeded:END' in emqx.evaluate(tmp, 'emqx-ha', ACL_ROW))
        if case_id in ('http_dummy', 'lost_auth_setting'):
            check('source_loopback_dummy', 'WOOWHTTP:ready:END' in emqx.evaluate(tmp, 'emqx-ha', HTTP_DUMMY))
        if case_id == 'dead_row':
            check('plain_row_initially_logs_in', mqtt_probe(tmp, 'emqx-ha') == 0)
            emqx.ctl(tmp, 'emqx-ha', ['conf', 'load', '--replace', '/fixture/dead-update.json'])
            check('normal_hash_change_makes_row_dead', mqtt_probe(tmp, 'emqx-ha') != 0)
        else:
            code = (login_code(tmp, 'emqx-ha', case_id, None, None) if case_id == 'noauth'
                    else login_code(tmp, 'emqx-ha', case_id))
            check('synthetic_source_connects', code == 0)
        readings = read_source(tmp)
        raw = emqx.read_effective_config(exec_read(tmp, 'emqx-ha'))
        roots = [x for x in emqx.DATA_ROOTS if x in raw and not (case_id == 'lost_auth_setting' and x == 'authentication')]
        out = emqx.ctl(tmp, 'emqx-ha', ['data', 'export', '--root-keys', ','.join(roots), '--table-sets',
            ','.join(emqx.TABLE_SETS), '--dir', '/work/out'], timeout=180).stdout
        match = emqx.EXPORT_RE.search(out or b''); check('real_vendor_export', match is not None)
        export = emqx.take_export(work, tmp, match.group(1).decode(), staging)
        tmp.stop('emqx-ha', timeout=60); tmp.remove('emqx-ha')
        STAGE = 'generated_target_and_candidate'
        seed(tmp, 'device', fx.config(case_id, target=True), fx.TARGET_ACL, ids)
        tmp.volume('device-log'); boot('device', 'device-log', target_env)
        if case_id == 'env_wins_h1':
            check('h1_device_environment_makes_it_deny', no_match(tmp, 'emqx-ha') == 'deny')
            target = device_target(tmp, mounts, target_env)
        else:
            target = SimpleNamespace(container=tmp.name('emqx-ha'), data_volume=tmp.name('device'),
                log_volume=tmp.name('device-log'), image=fx.IMAGE, env=target_env, files=mounts, secrets=[], publish=[],
                other_publish=[], tunnels=[])
        original = emqx.boot_form(exec_read(tmp, 'emqx-ha'))
        notes = {}
        try:
            seeded, counts, _, _ = emqx.candidate_from_target(work, app, tmp, target, staging, export, ids,
                                                            readings=readings, notes=notes)
        except BackupError as error:
            if case.expected != 'incompatible-before-packaging': raise
            check('lost_auth_setting_refused', error.code == 'incompatible' and '沒有出現' in error.message)
        else:
            check('positive_case_not_negative', case.expected == 'candidate-and-restart')
            check('vendor_counts_match', not emqx.check_counts(readings['counts'], seeded, counts))
            if case_id == 'http_dummy':
                check('candidate_loopback_dummy', 'WOOWHTTP:ready:END' in emqx.evaluate(tmp, 'emqx-new', HTTP_DUMMY))
            sink = lines(tmp, target, readings, notes)
            found = {x.id: x for x in sink.found}
            for name in case.confirms: check('confirm_' + name, name in found and found[name].level == 'confirm')
            for name in case.notices: check('notice_' + name, name in found and found[name].level == 'notice')
            if case_id == 'env_wins_h1':   # names only, never a value
                check('h1_notice_names_only_the_variable', found['emqx.env-wins'].names == tuple(fx.H1_ENV))
            security = emqx.security_items(fx.config(case_id))
            for kind, issue in [('file_secret', 'emqx.file-secret'), ('jq_rule', 'emqx.jq-rule'),
                                ('external_authn', 'emqx.external-authn'), ('external_authz', 'emqx.external-authz')]:
                if issue in case.confirms:
                    check('exact_names_' + issue, found[issue].names == tuple(security[kind]))
            keys = [x.key('emqx') for x in sink.found if x.level == 'confirm']
            if keys:
                try: lines(tmp, target, readings, notes, [])
                except BackupError as error: check('no_ack_refuses', error.code == 'confirmation-required')
                else: check('no_ack_refuses', False)
                lines(tmp, target, readings, notes, keys); check('exact_ack_accepted')
            if case_id == 'admin_public':
                # Metadata-only H3 branch. Actual fixture ports remain unpublished.
                exposed = copy.copy(target); exposed.publish = [emqx.parse_publish('0.0.0.0:18083:18083')]
                exposed_sink = lines(tmp, exposed, readings, notes)
                check('exposure_metadata_requires_confirmation', any(x.id == 'emqx.default-dashboard-exposed'
                    and x.level == 'confirm' for x in exposed_sink.found))
                check('admin_public_restored', 'default' in emqx.evaluate(tmp, 'emqx-new', emqx.DEFAULT_ADMIN_EXPR).split())
            case_assertions(tmp, case_id)
            emqx.write_marker(tmp)
            record = emqx.candidate_readback(tmp, notes=notes)
            check('all_receipts_recorded', record.get('tables') is not None and record['tables']['emqx_admin'][0] > 0)
            tmp.stop('emqx-new', timeout=60); runner.podman('start', tmp.name('emqx-new'))
            emqx.wait_ready(tmp, 'emqx-new', checkpoint=work.checkpoint)
            check('restart_ticker_paused', emqx.quiesce_system_ticker(tmp, 'emqx-new') is not None)
            after = emqx.candidate_readback(tmp)
            check('h1_restart_changes_only_the_authorization_setting' if case_id == 'env_wins_h1'
                  else 'all_roots_and_tables_stable_after_restart', restart_stable(case_id, record, after))
            if case_id == 'http_dummy': emqx.evaluate(tmp, 'emqx-new', HTTP_DUMMY)
            case_assertions(tmp, case_id, restarted=True)
            if case_id == 'dead_row': check('dead_row_remains_dead', login_code(tmp, 'emqx-new', case_id) != 0)
            elif case_id == 'noauth':
                check('anonymous_remains_enabled', login_code(tmp, 'emqx-new', case_id, None, None) == 0)
            else: check('source_account_works_after_restart', login_code(tmp, 'emqx-new', case_id) == 0)
            verify(tmp, record, case_id)
        check('generated_target_unchanged', original == emqx.boot_form(exec_read(tmp, 'emqx-ha')))
    STAGE = 'cleanup'
    check('tempobjects_empty', not tmp.containers and not tmp.volumes and not tmp.networks)
    after = inventory(runner)
    check('durable_images_volumes_unchanged', after[1:] == before[1:])
    return {'ok': True, 'case': case_id, 'job_id': JOB, 'checks': CHECKS, 'image': fx.IMAGE,
        'scope': 'generated internal candidate/restart/postcheck delta, not package install or original D0 fullflow',
        'package_smoke_executed': False, 'catalog_access': False, 'installed_source_access': False,
        'unrelated_container_churn': after[0] != before[0], 'probes': PROBES, 'observed': OBSERVED}


if __name__ == '__main__':
    try: result = main(sys.argv[1])
    except Exception as error:
        result = {'ok': False, 'case': sys.argv[1], 'job_id': JOB, 'stage': STAGE,
                  'reason': type(error).__name__, 'checks': CHECKS, 'probes': PROBES, 'observed': OBSERVED,
                  'private_dir': str(ROOT)}
    print(json.dumps(result, sort_keys=True)); raise SystemExit(0 if result['ok'] else 1)
