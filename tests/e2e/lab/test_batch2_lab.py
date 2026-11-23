"""Offline checks of the dev-e (HA import batch 2) lab definition: no labpodman, no device, no network.

    PYTHONPATH=backup-engine:tests/e2e/lab python3 -m unittest tests/e2e/lab/test_batch2_lab.py
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def device_vars(dev):
    """Source lib.sh with a stand-in labpodman and print what device_vars sets."""
    with tempfile.TemporaryDirectory() as lab:
        lp = Path(lab, 'bin', 'labpodman')
        lp.parent.mkdir()
        lp.write_text('#!/bin/sh\nexit 1\n')
        lp.chmod(0o755)
        script = (f'source {HERE / "lib.sh"}; device_vars {dev}; '
                  'echo "$DEV|$NAME|$PORT|$OWNER_UID|$DEVICE_MEMORY|$DEVICE_CPUS|$DEVICE_NETWORK|${DEVICE_RUN_ARGS[*]}|${VOLUMES[*]}"')
        proc = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                              env=dict(os.environ, WOOWBK_LAB_HOME=lab), timeout=30)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


class DeviceVarsTest(unittest.TestCase):
    def test_dev_e_is_network_none_without_a_port(self):
        rc, out, _ = device_vars('e')
        self.assertEqual(rc, 0)
        self.assertEqual(out, 'e|woowbk-dev-e||1025|3g|2|none||'
                              'woowbk-dev-e-home woowbk-dev-e-varlib woowbk-dev-e-containers')

    def test_other_devices_keep_their_settings(self):
        self.assertEqual(device_vars('d')[1], 'd|woowbk-dev-d|19094|1019|4g|2|||'
                                              'woowbk-dev-d-home woowbk-dev-d-varlib woowbk-dev-d-containers')
        self.assertEqual(device_vars('c')[1].split('|')[:8],
                         ['c', 'woowbk-dev-c', '19093', '1013', '3g', '2', '', '--add-host jcr-prod.woowtech.io:127.0.0.1'])
        self.assertEqual(device_vars('a')[1].split('|')[:7], ['a', 'woowbk-dev-a', '19091', '1001', '768m', '1.5', ''])

    def test_unknown_device_is_refused(self):
        rc, _, err = device_vars('f')
        self.assertNotEqual(rc, 0)
        self.assertIn("'a', 'b', 'c', 'd' or 'e'", err)


class CompareMaskTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('compare_batch2_src', HERE / 'compare_batch2.py')
        source = (HERE / 'compare_batch2.py').read_text()
        # Only the helpers: the module body below the definitions talks to labpodman.
        cls.ns = {}
        exec(compile(source.split('\napps = ')[0], str(spec.origin), 'exec'), cls.ns)

    def test_secret_like_lines_are_masked(self):
        masked = self.ns['masked']
        self.assertEqual(masked('+Environment=SMTP_PASSWORD=abc'), '+Environment=<masked>')
        self.assertEqual(masked('-ANTHROPIC_API_KEY=sk-123'), '-ANTHROPIC_API_KEY=<masked>')
        self.assertEqual(masked('+Secret=nextcloud-db-password,type=env,target=POSTGRES_PASSWORD'),
                         '+Secret=nextcloud-db-password,type=env,target=POSTGRES_PASSWORD')
        self.assertEqual(masked('+Image=docker.io/library/nginx:1.30.4-alpine'), '+Image=docker.io/library/nginx:1.30.4-alpine')

    def test_env_values_shown_only_for_tuning_keys(self):
        safe, secretish = self.ns['SAFE_KEYS'], self.ns['SECRETISH']
        shown = [k for k in ('HOST_BIND', 'PHP_MEMORY_LIMIT', 'HOST_DATA_DIR', 'WOOW_OD_MEMORY', 'NEXTCLOUD_PUBLIC_URL',
                             'OD_ALLOWED_ORIGINS', 'SMTP_PASSWORD', 'OPENAI_API_KEY', 'NEXTCLOUD_TRUSTED_DOMAINS')
                 if safe.search(k) and not secretish.search(k.replace('WOOW_OD_AUTH', ''))]
        self.assertEqual(shown, ['HOST_BIND', 'PHP_MEMORY_LIMIT', 'HOST_DATA_DIR', 'WOOW_OD_MEMORY'])


class Batch2ScriptsTest(unittest.TestCase):
    def test_shell_scripts_parse(self):
        for name in ('deploy-batch2.sh', 'lib.sh', 'up.sh', 'down.sh', 'status.sh', 'owner.sh', 'verify-device.sh',
                     'deploy-src.sh'):
            proc = subprocess.run(['bash', '-n', str(HERE / name)], capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, f'{name}: {proc.stderr}')

    def test_deploy_batch2_pins_the_production_commits_and_never_pulls(self):
        text = (HERE / 'deploy-batch2.sh').read_text()
        self.assertIn('declare -A REV=([nextcloud]=19a7609 [code-server]=e7dbbea [opendesign]=1067bc4)', text)
        self.assertNotIn('podman pull', text)
        self.assertIn('RD_SHA256=0639ab0e3413142a76334af20ca88cba0a351a11c9c07effa0f1eb7f05941f2c', text)
        self.assertIn('FLOOR_GIB=12', text)

    def test_every_app_has_its_check_function(self):
        """phase_check calls phase_check_<app> with '-' as '_' (code-server -> phase_check_code_server)."""
        text = (HERE / 'deploy-batch2.sh').read_text()
        self.assertIn('"phase_check_${app//-/_}" || failures=1', text)
        for app in ('nextcloud', 'code-server', 'opendesign'):
            self.assertIn(f'phase_check_{app.replace("-", "_")}() {{', text)


# Stand-ins for deploy-batch2.sh's rotate:APP and wake:APP: a labpodman that keeps dev-e's unit, container and image
# state in a JSON file (starting a unit makes its containers, stopping removes them: quadlet's --rm), a host podman
# that only answers `image inspect` (anything else, e.g. save, is UNEXPECTED), and a df with a chosen free space.
# Every call is logged. Nothing reaches a real labpodman, the host's Podman or a device.
FAKE_DEVICE_LP = r'''#!/usr/bin/env python3
import json, os, sys
argv = sys.argv[1:]
path = os.environ['FAKE_STATE']
st = json.load(open(path))
def save():
    json.dump(st, open(path, 'w'))
def log(*entry):
    with open(os.environ['FAKE_LOG'], 'a') as handle:
        handle.write(json.dumps(list(entry)) + '\n')
def out(text, rc=0):
    if text:
        print(text)
    save(); sys.exit(rc)
CONTAINERS = st['unit_containers']
if argv[:2] == ['container', 'inspect']:
    out('running')
if argv[:2] == ['inspect', 'woowbk-dev-e']:
    out('none {}')
if argv[:2] == ['volume', 'inspect']:
    out(st['volume'])
if argv[:4] == ['exec', '-i', 'woowbk-dev-e', '/usr/local/libexec/woowtech-cockpit-backup']:
    log('engine', argv[4])
    apps = [{'id': i, 'deployed': True, 'state': 'running', 'owner': 'appowner', 'problems': [],
             'units': [{'name': u, 'active': st['units'].get(u) == 'active'} for u in entry['units']]}
            for i, entry in st['catalog'].items()]
    out(json.dumps({'ok': True, 'apps': apps}))
if argv[:4] == ['exec', '-i', 'woowbk-dev-e', '/usr/local/bin/woowbk-owner']:
    cmd = argv[4:]
    if cmd[:2] == ['test', '-f']:
        out('', 0 if os.path.basename(cmd[2]) in st['quadlets'] else 1)
    if cmd[:2] == ['systemctl', '--user']:
        verb, unit = cmd[2], (cmd[3] if len(cmd) > 3 else '')
        if verb in ('start', 'stop'):
            log('systemctl', verb, unit)
            if verb == 'start' and unit in st.get('fail_start', []):
                out('', 1)
            if verb == 'start':
                st['units'][unit] = 'active'
                st['containers'] += [c for c in CONTAINERS.get(unit, []) if c not in st['containers']]
            elif unit not in st.get('stuck', []):
                if st['units'].get(unit) != 'failed':
                    st['units'][unit] = 'inactive'
                st['containers'] = [c for c in st['containers']
                                    if c not in CONTAINERS.get(unit, []) or c in st.get('leftover', [])]
            out('')
        if verb == 'is-active':
            state = st['units'].get(unit, 'inactive')
            out(state, 0 if state == 'active' else 3)
        if verb == 'list-units':
            out('')
    if cmd[:2] == ['podman', 'ps']:
        out('\n'.join(st['containers']))
    if cmd[:3] == ['podman', 'image', 'inspect']:
        ref = cmd[-1]
        out(st['images'][ref], 0) if ref in st['images'] else out('', 125)
    if cmd[:3] == ['podman', 'image', 'exists']:
        out('', 0 if cmd[3] in st['images'] or cmd[3] in st.get('pinned', []) else 1)
    if cmd[:2] == ['podman', 'rmi']:
        log('rmi', cmd[-1])
        st['images'] = {k: v for k, v in st['images'].items() if v != cmd[-1]}
        st['pinned'] = []
        out('')
    if cmd[:2] == ['podman', 'tag']:
        st['images'][cmd[3]] = cmd[2]
        out('')
    if cmd[:2] == ['podman', 'create']:
        log('create', cmd[cmd.index('--name') + 1], cmd[cmd.index('--userns') + 1])
        st['containers'].append(cmd[cmd.index('--name') + 1])
        out('')
    if cmd[:2] == ['podman', 'rm']:
        name = cmd[-1]
        was = name in st['containers']
        st['containers'] = [c for c in st['containers'] if c != name]
        out('', 0 if was or '-f' in cmd else 1)
    if cmd[:3] == ['podman', 'healthcheck', 'run']:
        out('')
    if cmd[:1] == ['sed']:
        out(st['quadlet_image'].get(os.path.basename(cmd[-1])[:-len('.container')], ''))
    if cmd[:1] == ['grep']:
        out('')
if argv[:2] == ['exec', 'woowbk-dev-e']:
    cmd = argv[2:]
    if cmd[:2] == ['test', '-f']:
        out('')
    if cmd[:3] == ['python3', '-I', '-c']:
        entry = st['catalog'][cmd[4]]
        field = cmd[5] if len(cmd) > 5 else ('health' if '"health"' in cmd[3] else 'units')
        out('\n'.join(f"{h['url']}|{h['expect_status']}" for h in entry['health']) if field == 'health'
            else '\n'.join(entry['units']))
    if cmd[:1] == ['curl']:
        log('curl', cmd[-1])
        print(st.get('http', {}).get(cmd[-1], '200'), end=''); save(); sys.exit(0)
log('UNEXPECTED', 'labpodman', argv)
save(); sys.exit(97)
'''
FAKE_HOST_PODMAN = r'''#!/usr/bin/env python3
import json, os, sys
argv = sys.argv[1:]
st = json.load(open(os.environ['FAKE_STATE']))
if argv[:3] == ['image', 'inspect', '--format'] and argv[3] == '{{.Id}}':
    print(st['host_ids'][argv[4]]); sys.exit(0)
with open(os.environ['FAKE_LOG'], 'a') as handle:
    handle.write(json.dumps(['UNEXPECTED', 'host podman', argv]) + '\n')
sys.exit(97)
'''
FAKE_DF = '#!/bin/sh\necho Avail\necho "$FAKE_FREE"\n'
CS_ID = '7999790230ec' + '0' * 52
CS_REF = 'ghcr.io/woowtech/woow-code-server-amd64:4.139.1-8'
OD_IDS = {'localhost/woow-open-design:4.2.1': '5bf5f9b959b3' + '1' * 52,
          'docker.io/library/nginx:1.30.4-alpine': '1ae82dcc4a34' + '2' * 52}


class RotationPhasesTest(unittest.TestCase):
    """deploy-batch2.sh e rotate:APP / wake:APP against the stand-ins: order of the steps and every refusal."""

    def device(self, app, awake, loaded, free_gib=30, **extra):
        import json
        home = Path(self.enterContext(tempfile.TemporaryDirectory()))
        lab, fake_bin = home / '.woowbk-lab', home / 'fakebin'
        (lab / 'bin').mkdir(parents=True)
        fake_bin.mkdir()
        for path, text in ((lab / 'bin' / 'labpodman', FAKE_DEVICE_LP), (fake_bin / 'podman', FAKE_HOST_PODMAN),
                           (fake_bin / 'df', FAKE_DF)):
            path.write_text(text)
            path.chmod(0o755)
        if app == 'code-server':
            units = {'code-server.service': ['code-server'], 'code-server-health.timer': [],
                     'code-server-health.service': []}
            catalog = {'woow-code-server': {'units': ['code-server.service'],
                                            'health': [{'url': 'http://127.0.0.1:18443/healthz', 'expect_status': 200}]}}
            host_ids = {CS_REF + '@sha256:fe8b6a0f1b90863cb784cc8a4d69ba33783ee7b87d6322bf975a59511905370d': CS_ID}
            images = {CS_REF: CS_ID, CS_ID: CS_ID} if loaded else {}
            quadlets, quadlet_image = ['code-server.container'], {'code-server': CS_REF + '@sha256:' + 'e' * 64}
            pinned = [CS_REF + '@sha256:' + 'e' * 64] if loaded else []
        else:
            names = ['open-design', 'open-design-nginx', 'open-design-mcp', 'open-design-terminal']
            units = {f'{n}.service': [n] for n in names}
            catalog = {'open-design': {'units': [f'{n}.service' for n in names],
                                       'health': [{'url': 'http://127.0.0.1:7456/api/health', 'expect_status': 200}]}}
            host_ids = {'localhost/woow-open-design:4.2.1': OD_IDS['localhost/woow-open-design:4.2.1'],
                        'docker.io/library/nginx:1.30.4-alpine@sha256:dc5069ad14f19660b141b21236140b91656bf89bbc3e2417c70ae650cd66104c':
                            OD_IDS['docker.io/library/nginx:1.30.4-alpine']}
            images = {**OD_IDS, **{i: i for i in OD_IDS.values()}} if loaded else {}
            quadlets = [f'{n}.container' for n in names]
            quadlet_image = {'open-design': 'localhost/woow-open-design:4.2.1', 'open-design-nginx':
                             'docker.io/library/nginx:1.30.4-alpine', 'open-design-mcp': 'localhost/woow-open-design:4.2.1',
                             'open-design-terminal': 'localhost/woow-open-design:4.2.1'}
            pinned = []
        state = {'units': {u: ('active' if awake else 'inactive') for u in units}, 'unit_containers': units,
                 'containers': [c for cs in units.values() for c in cs] if awake else [], 'images': images,
                 'pinned': pinned, 'catalog': catalog, 'host_ids': host_ids, 'quadlets': quadlets,
                 'quadlet_image': quadlet_image, 'volume': str(home / 'volume-home')}
        state.update(extra)
        (home / 'state.json').write_text(json.dumps(state))
        env = dict(os.environ, HOME=str(home), WOOWBK_LAB_HOME=str(lab), FAKE_STATE=str(home / 'state.json'),
                   FAKE_LOG=str(home / 'calls.log'), FAKE_FREE=str(free_gib * 1024 ** 3),
                   PATH=f'{fake_bin}:{os.environ["PATH"]}', WAKE_READY_S='20')
        return home, env

    def run_phase(self, home, env, phase):
        import json
        proc = subprocess.run(['bash', str(HERE / 'deploy-batch2.sh'), 'e', phase], capture_output=True, text=True,
                              env=env, timeout=300)
        log = home / 'calls.log'
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        self.assertNotIn('UNEXPECTED', [c[0] for c in calls], calls)
        return proc, calls, json.loads((home / 'state.json').read_text())

    def test_rotate_stops_everything_then_drops_the_images(self):
        home, env = self.device('code-server', awake=True, loaded=True)
        proc, calls, state = self.run_phase(home, env, 'rotate:code-server')
        self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
        stops = [c[2] for c in calls if c[:2] == ['systemctl', 'stop']]
        self.assertEqual(stops, ['code-server-health.timer', 'code-server-health.service', 'code-server.service'])
        self.assertEqual([c for c in calls if c[0] == 'rmi'], [['rmi', CS_ID]])
        self.assertGreater(calls.index(['rmi', CS_ID]), calls.index(['systemctl', 'stop', 'code-server.service']))
        self.assertEqual(state['images'], {})
        self.assertEqual(state['containers'], [])

    def test_rotate_keeps_the_images_when_a_unit_stays_active(self):
        home, env = self.device('code-server', awake=True, loaded=True, stuck=['code-server.service'])
        proc, calls, state = self.run_phase(home, env, 'rotate:code-server')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('code-server.service is active after the stop (images kept)', proc.stderr)
        self.assertEqual([c for c in calls if c[0] == 'rmi'], [])
        self.assertIn(CS_ID, state['images'].values())

    def test_rotate_keeps_the_images_when_a_container_is_left(self):
        home, env = self.device('opendesign', awake=True, loaded=True, leftover=['open-design-mcp'])
        proc, calls, state = self.run_phase(home, env, 'rotate:opendesign')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('containers still there: open-design-mcp (images kept)', proc.stderr)
        self.assertEqual([c for c in calls if c[0] == 'rmi'], [])

    def test_rotate_accepts_a_failed_health_run(self):
        home, env = self.device('code-server', awake=True, loaded=True)
        state = __import__('json').loads((home / 'state.json').read_text())
        state['units']['code-server-health.service'] = 'failed'
        (home / 'state.json').write_text(__import__('json').dumps(state))
        proc, calls, state = self.run_phase(home, env, 'rotate:code-server')
        self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
        self.assertIn('code-server-health.service is failed (its last run failed; not running)', proc.stderr)

    def test_wake_code_server_copies_first_then_starts_then_checks(self):
        home, env = self.device('code-server', awake=False, loaded=True)
        proc, calls, state = self.run_phase(home, env, 'wake:code-server')
        self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
        create = ['create', 'woowbk-lab-cs-idmap-copy', 'keep-id:uid=1000,gid=1000']
        start_service = ['systemctl', 'start', 'code-server.service']
        start_timer = ['systemctl', 'start', 'code-server-health.timer']
        self.assertLess(calls.index(create), calls.index(start_service))
        self.assertLess(calls.index(start_service), calls.index(start_timer))
        self.assertLess(calls.index(start_timer), max(i for i, c in enumerate(calls) if c[0] == 'engine'))
        self.assertIn('dev-e ready: code-server running and healthy', proc.stderr)
        self.assertEqual(state['containers'], ['code-server'])  # the throwaway copy container is gone

    def test_wake_refuses_an_unloaded_pinned_image_before_any_start(self):
        home, env = self.device('code-server', awake=False, loaded=True, pinned=[])
        proc, calls, _ = self.run_phase(home, env, 'wake:code-server')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('installed units name images that are not loaded: code-server.container', proc.stderr)
        self.assertEqual([c for c in calls if c[:2] == ['systemctl', 'start'] or c[0] == 'create'], [])

    def test_wake_refuses_when_the_first_start_copy_would_cross_the_floor(self):
        home, env = self.device('opendesign', awake=False, loaded=True, free_gib=19)
        proc, calls, _ = self.run_phase(home, env, 'wake:opendesign')
        self.assertEqual(proc.returncode, 1)
        self.assertIn("opendesign's first start needs up to 7 GiB and 13 GiB must stay free (images kept, nothing started)",
                      proc.stderr)
        self.assertEqual([c for c in calls if c[:2] == ['systemctl', 'start']], [])

    def test_wake_stops_at_a_unit_that_does_not_start(self):
        home, env = self.device('opendesign', awake=False, loaded=True, free_gib=21, fail_start=['open-design-nginx.service'])
        proc, calls, _ = self.run_phase(home, env, 'wake:opendesign')
        self.assertEqual(proc.returncode, 1)
        self.assertIn('wake:opendesign: starting open-design-nginx.service failed (the units after it were not started)',
                      proc.stderr)
        self.assertEqual([c[2] for c in calls if c[:2] == ['systemctl', 'start']],
                         ['open-design.service', 'open-design-nginx.service'])

    def test_wake_opendesign_starts_its_four_units_in_order(self):
        home, env = self.device('opendesign', awake=False, loaded=True, free_gib=21)
        proc, calls, state = self.run_phase(home, env, 'wake:opendesign')
        self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
        self.assertEqual([c[2] for c in calls if c[:2] == ['systemctl', 'start']],
                         ['open-design.service', 'open-design-nginx.service', 'open-design-mcp.service',
                          'open-design-terminal.service'])
        self.assertEqual(sorted(state['containers']), sorted(['open-design', 'open-design-nginx', 'open-design-mcp',
                                                              'open-design-terminal']))



def _layer(entries, gzip=False):
    """A layer tarball (bytes) with (name, uid, gid) regular files and directories (names ending in /)."""
    import io, tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz' if gzip else 'w') as tar:
        for name, uid, gid in entries:
            info = tarfile.TarInfo(name.rstrip('/'))
            info.uid, info.gid = uid, gid
            if name.endswith('/'):
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            else:
                data = b'x'
                info.size, info.mode = len(data), 0o644
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class ImageIdRangeTest(unittest.TestCase):
    LAYERS = [[('usr/', 0, 0), ('usr/bin/tool', 0, 0)],
              [('usr/src/nextcloud/', 65534, 65534), ('usr/src/nextcloud/occ', 65534, 65534), ('var/www/', 33, 33),
               ('home/nonroot/', 65532, 65532), ('etc/ok', 55000, 55000)]]

    def run_scan(self, args, data=None):
        proc = subprocess.run([sys.executable, '-I', str(HERE / 'image_id_range.py'), *args], input=data,
                              capture_output=True, timeout=60)
        return proc.returncode, proc.stdout.decode(), proc.stderr.decode()

    def check(self, rc, out):
        import json
        self.assertEqual(rc, 3)
        result = json.loads(out)
        self.assertEqual((result['layers'], result['entries'], result['out_of_range']), (2, 7, 3))
        self.assertEqual(result['owners'], {'65534:65534': 2, '65532:65532': 1})
        self.assertEqual(result['top'], {'/usr/src': 2, '/home/nonroot': 1})
        self.assertEqual(sorted(result['sample']), ['/home/nonroot', '/usr/src/nextcloud', '/usr/src/nextcloud/occ'])

    def test_docker_dir_with_gzip_layers(self):
        import hashlib, json
        with tempfile.TemporaryDirectory() as d:
            layers = []
            for entries in self.LAYERS:
                blob = _layer(entries, gzip=True)
                digest = hashlib.sha256(blob).hexdigest()
                Path(d, digest).write_bytes(blob)
                layers.append({'digest': 'sha256:' + digest})
            Path(d, 'manifest.json').write_text(json.dumps({'layers': layers}))
            self.check(*self.run_scan([d, '55000'])[:2])
            rc, out, _ = self.run_scan([d, '65534'])
            self.assertEqual((rc, json.loads(out)['out_of_range']), (0, 0))

    def test_docker_archive_on_stdin(self):
        import io, tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as outer:
            for index, entries in enumerate(self.LAYERS):
                blob = _layer(entries)
                info = tarfile.TarInfo(f'{index:064x}.tar')
                info.size = len(blob)
                outer.addfile(info, io.BytesIO(blob))
            info = tarfile.TarInfo('manifest.json')
            info.size = 2
            outer.addfile(info, io.BytesIO(b'[]'))
        self.check(*self.run_scan(['-', '55000'], buf.getvalue())[:2])

    def test_bad_arguments(self):
        self.assertEqual(self.run_scan(['/nonexistent', '55000'])[0], 2)
        self.assertEqual(self.run_scan(['-', 'many'])[0], 2)

if __name__ == '__main__':
    unittest.main()


FAKE_PODMAN = r'''#!/bin/sh
# Stand-in for podman in CodeServerMarkersTest: volumes are directories under $FAKE_VOLUMES, unshare runs the command.
case "$1 $2" in
    "volume inspect") eval "name=\${$#}"; printf '%s\n' "$FAKE_VOLUMES/$name" ;;
    "secret inspect") printf 'bind-addr: 127.0.0.1:8080\nauth: password\npassword: "%s"\ncert: false\n' "$FAKE_PASSWORD" ;;
    unshare*) shift; exec "$@" ;;
    *) echo "fake podman: unexpected $*" >&2; exit 2 ;;
esac
'''
# The device markers of lane codeserver-import's harness (tests/e2e/lab/codeserver_full_flow.py DEVICE_MARKERS on
# feat/ha-import-code-server-20261123): dev-e's code-server baseline must be exactly these, byte for byte.
HARNESS_DEVICE_MARKERS = {
    'snippets': ('woowbk-lab-baseline.code-snippets',
                 '{"woowbk-lab-baseline": {"prefix": "woowbk", "body": "實驗室基準片段（code-server HA 匯入）"}}\n'),
    'skills': ('woowbk-lab-baseline', '# woowbk-lab-baseline\n實驗室基準技能（code-server HA 匯入）\n'),
    'files': ('woowbk-lab-baseline.txt', '實驗室基準工作區檔案（code-server HA 匯入）\n'),
}


class CodeServerMarkersTest(unittest.TestCase):
    """batch2_markers.py code-server read/seed/login against a fake podman and a fake code-server (no device)."""

    def setUp(self):
        import hashlib
        self.sha = lambda text: hashlib.sha256(text.encode()).hexdigest()
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / 'bin').mkdir()
        fake = root / 'bin' / 'podman'
        fake.write_text(FAKE_PODMAN)
        fake.chmod(0o755)
        for volume in ('woow-code-server-ide', 'woow-code-server-pi-data'):
            (root / 'volumes' / volume).mkdir(parents=True)
        (root / 'home').mkdir()
        self.root = root
        self.env = dict(os.environ, PATH=f'{root / "bin"}:{os.environ["PATH"]}', HOME=str(root / 'home'),
                        FAKE_VOLUMES=str(root / 'volumes'), FAKE_PASSWORD='lab-test-pw')

    def tearDown(self):
        self.tmp.cleanup()

    def markers(self, *args, env=None):
        import json
        proc = subprocess.run([sys.executable, '-I', '-c', (HERE / 'batch2_markers.py').read_text(), 'code-server', *args],
                              input=b'{}', capture_output=True, timeout=120, env=env or self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        return json.loads(proc.stdout.decode().strip().splitlines()[-1])

    def test_baseline_equals_the_harness_device_markers_and_seeding_is_idempotent(self):
        created = self.markers('seed', 'baseline', '20261123T000000')['created']
        self.assertEqual(len(created), 3, created)
        found = self.markers('read')
        want = {kind: [f'{name}:{self.sha(text)}'] for kind, (name, text) in HARNESS_DEVICE_MARKERS.items()}
        self.assertEqual(found, want)
        self.assertTrue((self.root / 'volumes/woow-code-server-pi-data/skills/woowbk-lab-baseline/SKILL.md').is_file())
        self.assertTrue((self.root / 'volumes/woow-code-server-ide/snippets/woowbk-lab-baseline.code-snippets').is_file())
        self.assertTrue((self.root / 'home/Desktop/woowbk-lab-baseline.txt').is_file())
        self.assertEqual(self.markers('seed', 'baseline', '20261123T000001')['created'], [])

    def test_after_markers_are_listed_next_to_the_baseline(self):
        self.markers('seed', 'baseline', '20261123T000000')
        self.assertEqual(len(self.markers('seed', 'after', '20261123T000002')['created']), 3)
        found = self.markers('read')
        names = {kind: [item.split(':')[0] for item in items] for kind, items in found.items()}
        self.assertEqual(names, {'snippets': ['woowbk-lab-after.code-snippets', 'woowbk-lab-baseline.code-snippets'],
                                 'skills': ['woowbk-lab-after', 'woowbk-lab-baseline'],
                                 'files': ['woowbk-lab-after.txt', 'woowbk-lab-baseline.txt']})

    def test_a_skill_without_skill_md_is_reported_missing(self):
        (self.root / 'volumes/woow-code-server-pi-data/skills/woowbk-lab-stray').mkdir(parents=True)
        self.assertEqual(self.markers('read')['skills'], ['woowbk-lab-stray:missing'])

    def test_login_checks_status_codes_only(self):
        import http.server
        import threading
        import urllib.parse

        class Fake(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, code, headers=()):
                self.send_response(code)
                for key, value in headers:
                    self.send_header(key, value)
                self.send_header('Content-Length', '0')
                self.end_headers()

            def do_GET(self):  # code-server 4.139.1 as measured in dev-e
                if self.path == '/healthz':
                    self.reply(200)
                elif self.headers.get('Cookie') != 'code-server-session=s3ss10n':
                    self.reply(302, [('Location', './login')])
                elif self.path == '/':
                    self.reply(302, [('Location', './?folder=/workspace')])
                else:
                    body = b'<html><div class="monaco-workbench"></div></html>'
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length') or 0)).decode()
                if urllib.parse.parse_qs(body).get('password') == ['lab-test-pw']:
                    self.reply(302, [('Location', './'), ('Set-Cookie', 'code-server-session=s3ss10n; Path=/; HttpOnly')])
                else:
                    self.reply(200)

        server = http.server.HTTPServer(('127.0.0.1', 0), Fake)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            env = dict(self.env, WOOWBK_LAB_CS_PORT=str(server.server_address[1]))
            result = self.markers('login', env=env)
            self.assertEqual(result, {'healthz': 200, 'login': 302, 'session_cookie': True, 'root_with_cookie': 302,
                                      'root_redirect': './?folder=/workspace', 'page_with_cookie': 200,
                                      'workbench': True, 'page_without_cookie': 302, 'anonymous_redirect': './login',
                                      'wrong_password': 200, 'wrong_password_cookie': False, 'ok': True})
            bad = self.markers('login', env=dict(env, FAKE_PASSWORD='not-the-password'))
            self.assertFalse(bad['ok'])
            self.assertNotIn('lab-test-pw', json_dumps(result) + json_dumps(bad))
            self.assertNotIn('s3ss10n', json_dumps(result) + json_dumps(bad))
        finally:
            server.shutdown()


def json_dumps(value):
    import json
    return json.dumps(value)


class BaselineDriverTest(unittest.TestCase):
    def test_after_marker_uses_the_baseline_password(self):
        """Nextcloud's after file is a WebDAV PUT into the baseline user's files: the driver must pass that user's
        password (a random one gave HTTP 401 on the first real Nextcloud baseline, 2026-11-23 21:12)."""
        text = (HERE / 'batch2_baseline.py').read_text()
        self.assertIn("created = markers(app, 'seed', 'after', time.strftime('%Y%m%dT%H%M%S'))\n", text)
        self.assertNotIn("'after', time.strftime('%Y%m%dT%H%M%S'), secrets.", text)


# A stand-in labpodman for batch2_baseline.py --verify: answers from a scenario file and logs every call, so the tests
# see exactly what the read-only mode asks dev-e to do. It never reaches a real labpodman or device.
FAKE_LP = r'''#!/usr/bin/env python3
import json, os, sys
argv = sys.argv[1:]
scenario = json.load(open(os.environ['FAKE_LP_SCENARIO']))
def log(entry):
    with open(os.environ['FAKE_LP_LOG'], 'a') as handle:
        handle.write(json.dumps(entry) + '\n')
if argv[:2] == ['inspect', 'woowbk-dev-e']:
    log(['inspect']); print(scenario.get('inspect', 'true none {}')); sys.exit(0)
if argv[:3] == ['exec', '-i', 'woowbk-dev-e'] and argv[3] == '/usr/local/libexec/woowtech-cockpit-backup':
    request = sys.stdin.read()
    log(['engine', argv[4], request]); print(json.dumps(scenario['engine'][argv[4]])); sys.exit(0)
if argv[:4] == ['exec', '-i', 'woowbk-dev-e', '/usr/local/bin/woowbk-owner'] and argv[4:7] == ['python3', '-I', '-c']:
    app, action = argv[8], argv[9]
    log(['markers', app, action, argv[10:], json.loads(sys.stdin.read() or '{}') != {}])
    print(json.dumps(scenario['markers'][app][action])); sys.exit(0)
if argv[:3] == ['exec', 'woowbk-dev-e', 'cat']:
    log(['cat', argv[3]]); print(json.dumps(scenario['catalog'][argv[3].rsplit('/', 1)[1][:-5]])); sys.exit(0)
if argv[:3] == ['exec', 'woowbk-dev-e', 'curl']:
    log(['curl', argv[-1]]); print(scenario.get('http', {}).get(argv[-1], '200'), end=''); sys.exit(0)
log(['UNEXPECTED', argv]); sys.exit(97)
'''
NC_SHA = 'woowbk-lab-baseline.txt:' + '5' * 64
CS_READ = {'snippets': ['woowbk-lab-baseline.code-snippets:' + 'a' * 64], 'skills': ['woowbk-lab-baseline:' + 'b' * 64],
           'files': ['woowbk-lab-baseline.txt:' + 'c' * 64]}


class VerifyModeTest(unittest.TestCase):
    """batch2_baseline.py --verify against the stand-in labpodman: read only, and every way it must fail."""

    def run_verify(self, apps, read=None, listed=True, inspect='true none {}', http=None, password=True):
        import json
        home = Path(self.enterContext(tempfile.TemporaryDirectory()))
        lab = home / '.woowbk-lab'
        (lab / 'bin').mkdir(parents=True)
        lp = lab / 'bin' / 'labpodman'
        lp.write_text(FAKE_LP)
        lp.chmod(0o755)
        if password:
            (lab / 'secrets').mkdir(mode=0o700)
            (lab / 'secrets' / 'dev-e-markers.json').write_text(json.dumps({'nextcloud': 'not-a-real-one'}))
        baseline_reads = {'nextcloud': {'users': ['woowbk-lab-baseline'], 'files': [NC_SHA]}, 'code-server': CS_READ}
        for app, found in baseline_reads.items():
            run = lab / 'evidence' / 'batch2-lab' / '20261123T211623-baseline'
            run.mkdir(parents=True, exist_ok=True)
            (run / f'{app}-markers-after-restore.json').write_text(json.dumps(found))
        ids = {app: json.loads((HERE / 'evidence' / 'batch2-lab-20261123' / f'{app}-baseline.json').read_text())['backup_id']
               for app in ('nextcloud', 'code-server')}
        catalog_id = {'nextcloud': 'nextcloud', 'code-server': 'woow-code-server'}
        scenario = {
            'inspect': inspect, 'http': http or {},
            'engine': {'status': {'ok': True, 'key': {'key_id': 'lab-key'},
                                  'apps': [{'id': i, 'deployed': True, 'state': 'running', 'problems': []}
                                           for i in catalog_id.values()]},
                       'list': {'ok': True, 'backups': [{'id': ids[a], 'encrypted': True, 'key_id': 'lab-key',
                                                         'apps': [{'id': catalog_id[a]}]} for a in ids if listed]}},
            'markers': {app: {'read': (read or {}).get(app, found), 'login': {'ok': True}}
                        for app, found in baseline_reads.items()},
            'catalog': {i: {'health': [{'url': f'http://127.0.0.1/{i}', 'expect_status': 200}]} for i in catalog_id.values()},
        }
        (home / 'scenario.json').write_text(json.dumps(scenario))
        env = dict(os.environ, HOME=str(home), WOOWBK_LAB_HOME=str(lab), FAKE_LP_SCENARIO=str(home / 'scenario.json'),
                   FAKE_LP_LOG=str(home / 'calls.log'))
        proc = subprocess.run([sys.executable, '-I', str(HERE / 'batch2_baseline.py'), '--verify', *apps],
                              capture_output=True, text=True, env=env, timeout=120)
        calls = [json.loads(line) for line in (home / 'calls.log').read_text().splitlines()]
        results = sorted((lab / 'evidence' / 'batch2-lab').glob('*-verify/result.json'))
        result = json.loads(results[-1].read_text()) if results else None
        return proc, calls, result, lab

    def failed(self, result):
        return [c['check'] for c in result['checks'] if not c['ok']]

    def test_baseline_state_passes_and_only_reads(self):
        proc, calls, result, lab = self.run_verify(['nextcloud', 'code-server'])
        self.assertEqual(proc.returncode, 0, proc.stdout[-2000:] + proc.stderr[-2000:])
        self.assertEqual(self.failed(result), [])
        self.assertEqual(result['passed'], result['total'])
        self.assertEqual({c[1] for c in calls if c[0] == 'engine'}, {'status', 'list'})  # no job, key or restore command
        self.assertEqual({c[2] for c in calls if c[0] == 'markers'}, {'read', 'login'})  # never seed
        self.assertNotIn('UNEXPECTED', [c[0] for c in calls])
        self.assertTrue(any(c == ['markers', 'nextcloud', 'read', [], True] for c in calls))  # the password goes by stdin
        self.assertNotIn('not-a-real-one', proc.stdout + proc.stderr + json_dumps(result))
        self.assertIn(['markers', 'code-server', 'login', [], False], calls)
        self.assertEqual(list((lab / 'evidence' / 'batch2-lab').glob('*-baseline/*-backup-job.json')), [])
        # Every check and the total come out as fixed status lines that services_a_capture.py keeps.
        import services_a_capture
        kept = services_a_capture.status_lines(proc.stdout)
        self.assertIn(f'batch2 verify nextcloud code-server: {result["total"]}/{result["total"]} PASS', kept)
        self.assertEqual(len(kept), result['total'] + 1, kept)

    def test_a_leftover_after_marker_fails(self):
        read = {'nextcloud': {'users': ['woowbk-lab-after', 'woowbk-lab-baseline'], 'files': [NC_SHA]}}
        proc, _, result, _ = self.run_verify(['nextcloud'], read=read)
        self.assertEqual(proc.returncode, 1)
        failed = self.failed(result)
        self.assertEqual(len(failed), 2, failed)
        self.assertTrue(failed[0].startswith('nextcloud: only the baseline markers'))
        self.assertTrue(failed[1].startswith("nextcloud: marker read equals the baseline's"))
        self.assertIn('nextcloud: only the baseline markers (no leftover test marker): FAIL', proc.stdout)
        self.assertRegex(proc.stdout, r'batch2 verify nextcloud: [0-9]+/[0-9]+ FAIL')

    def test_a_changed_file_fails(self):
        read = {'code-server': dict(CS_READ, files=['woowbk-lab-baseline.txt:' + 'd' * 64])}
        proc, _, result, _ = self.run_verify(['code-server'], read=read)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(len(self.failed(result)), 1)
        self.assertTrue(self.failed(result)[0].startswith("code-server: marker read equals the baseline's"))

    def test_a_missing_baseline_backup_a_bad_health_answer_and_a_network_fail(self):
        proc, _, result, _ = self.run_verify(['nextcloud'], listed=False, inspect='true bridge {}',
                                             http={'http://127.0.0.1/nextcloud': '503'})
        self.assertEqual(proc.returncode, 1)
        failed = self.failed(result)
        self.assertEqual(len(failed), 3, failed)
        self.assertEqual(failed[0], 'dev-e: running, network none, no published port')
        self.assertTrue(failed[1].startswith('nextcloud: catalog health URLs'))
        self.assertTrue(failed[2].startswith('nextcloud: baseline backup'))

    def test_verify_never_creates_the_password_file(self):
        proc, calls, result, lab = self.run_verify(['code-server'], password=False)
        self.assertEqual(proc.returncode, 0, proc.stdout[-2000:])
        self.assertFalse((lab / 'secrets' / 'dev-e-markers.json').exists())


class CodeServerCatalogTest(unittest.TestCase):
    def test_lab_entry_matches_what_the_baseline_and_markers_use(self):
        import json
        entry = json.loads((HERE / 'catalog' / 'woow-code-server.json').read_text(encoding='utf-8'))
        self.assertEqual(entry['id'], 'woow-code-server')
        self.assertEqual(entry['owner'], 'appowner')
        self.assertEqual(entry['units'], ['code-server.service'])
        volumes = {v['name'] for v in entry['volumes']}
        self.assertLessEqual({'woow-code-server-ide', 'woow-code-server-pi-data'}, volumes)
        self.assertEqual([d['path'] for d in entry['data_dirs']], ['Desktop'])
        self.assertEqual([h['url'] for h in entry['health']], ['http://127.0.0.1:18443/healthz'])
        text = (HERE / 'deploy-batch2.sh').read_text()
        self.assertIn('[code-server]=woow-code-server', text)
        self.assertIn("'code-server': 'woow-code-server'", (HERE / 'batch2_baseline.py').read_text())
