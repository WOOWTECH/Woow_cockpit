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

            def do_GET(self):
                if self.path == '/healthz':
                    self.reply(200)
                elif self.headers.get('Cookie') == 'code-server-session=s3ss10n':
                    self.reply(200)
                else:
                    self.reply(302, [('Location', './login')])

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
            self.assertEqual(result, {'healthz': 200, 'login': 302, 'session_cookie': True, 'page_with_cookie': 200,
                                      'page_without_cookie': 302, 'wrong_password': 200,
                                      'wrong_password_cookie': False, 'ok': True})
            bad = self.markers('login', env=dict(env, FAKE_PASSWORD='not-the-password'))
            self.assertFalse(bad['ok'])
            self.assertNotIn('lab-test-pw', json_dumps(result) + json_dumps(bad))
            self.assertNotIn('s3ss10n', json_dumps(result) + json_dumps(bad))
        finally:
            server.shutdown()


def json_dumps(value):
    import json
    return json.dumps(value)


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
