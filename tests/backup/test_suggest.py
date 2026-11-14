"""catalog-suggest: Quadlet analysis, grouping into apps and catalog drafts. Owner: catalog + retention engineer.

`fixtures/reference-host/` mirrors the Quadlet shapes of the 20 apps on the reference host (names, mounts, ports,
dependencies; no secret values, the LAN address replaced by a documentation address). The owner-side helpers
(SCAN_HELPER and FILE_HELPER `stat`) run for real against a temporary home; podman and systemctl answers are canned.
EXPECTED holds the structural facts of the hand-written production entries; on the lab host the test also checks
them against /home/woowtechopenclaw/.woowbk-lab/evidence/prod-catalogs (the read-only reference).
"""
import copy
import json
import os
import shutil
import tempfile
import types
import unittest
from pathlib import Path

from woowbackup import catalog, podman, suggest
from woowbackup.errors import BackupError
from woowbackup.paths import Paths

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'reference-host'
REFERENCE = Path('/home/woowtechopenclaw/.woowbk-lab/evidence/prod-catalogs')
OWNER = 'woowtechopenclaw'
LEAK_MARKER = 'FIXTURE-ENV-CONTENT-MUST-NOT-LEAK'
DUMMY_SECRET = 'fixture-dummy-value-0000'  # the only literal Environment= value that looks like a password

EXPECTED = {'emqx': {'files': ['emqx-data.volume',
                    'emqx-entrance.container',
                    'emqx-log.volume',
                    'emqx.container',
                    'emqx.network'],
          'units': ['emqx-entrance.service', 'emqx.service'],
          'writers': ['emqx-entrance.service', 'emqx.service'],
          'postgres': [],
          'volumes': ['woow_emqx_data', 'woow_emqx_log'],
          'dirs': [],
          'secrets': ['woow-emqx-dashboard-password', 'woow-emqx-mqtt-bootstrap', 'woow-emqx-node-cookie'],
          'configs': [('.config/emqx/acl.conf', '0644'),
                      ('.config/emqx/base.hocon', '0644'),
                      ('.config/emqx/emqx.env', '0600'),
                      ('.config/emqx/entrance.conf', '0644')],
          'health': []},
 'emqx-mcp-admin': {'files': ['emqx-mcp-admin.container', 'emqx-mcp-admin.network', 'emqx-mcp-admin.volume'],
                    'units': ['emqx-mcp-admin.service'],
                    'writers': ['emqx-mcp-admin.service'],
                    'postgres': [],
                    'volumes': ['emqx_mcp_admin_data'],
                    'dirs': [],
                    'secrets': ['emqx-mcp-admin-jwt-secret', 'emqx-mcp-admin-password'],
                    'configs': [('.config/emqx-mcp-admin/emqx-mcp-admin.env', '0600')],
                    'health': ['http://127.0.0.1:18501/healthz']},
 'headscale': {'files': ['headplane-data.volume',
                         'headplane.container',
                         'headscale-data.volume',
                         'headscale-entrance.container',
                         'headscale-ngrok.container',
                         'headscale-run.volume',
                         'headscale.container',
                         'headscale.network'],
               'units': ['headplane.service',
                         'headscale-entrance.service',
                         'headscale-ngrok.service',
                         'headscale.service'],
               'writers': ['headplane.service', 'headscale-entrance.service', 'headscale.service'],
               'postgres': [],
               'volumes': ['headplane-data', 'headscale-data'],
               'dirs': [],
               'secrets': ['headscale-headplane-api-key', 'headscale-headplane-cookie', 'headscale-ngrok-authtoken'],
               'configs': [('.config/headscale/entrance/htpasswd', '0644'),
                           ('.config/headscale/entrance/nginx.conf', '0644'),
                           ('.config/headscale/headplane/config.yaml', '0644'),
                           ('.config/headscale/headscale.env', '0600'),
                           ('.config/headscale/headscale/config.yaml', '0644'),
                           ('.config/headscale/headscale/extra_records.json', '0644'),
                           ('.config/headscale/headscale/policy.json', '0644')],
               'health': ['http://127.0.0.1:23000/', 'http://127.0.0.1:29090/metrics']},
 'headscale-mcp-admin': {'files': ['headscale-mcp-admin.container', 'headscale-mcp.network', 'headscale-mcp.volume'],
                         'units': ['headscale-mcp-admin.service'],
                         'writers': ['headscale-mcp-admin.service'],
                         'postgres': [],
                         'volumes': ['headscale_mcp_data'],
                         'dirs': [],
                         'secrets': ['headscale-mcp-admin-jwt-secret', 'headscale-mcp-admin-password'],
                         'configs': [],
                         'health': ['http://127.0.0.1:18500/healthz']},
 'hermes': {'files': ['hermes-agent.container',
                      'hermes-data.volume',
                      'hermes-postgres-data.volume',
                      'hermes-postgres.container',
                      'hermes-redis-data.volume',
                      'hermes-redis.container',
                      'hermes.network'],
            'units': ['hermes-agent.service', 'hermes-postgres.service', 'hermes-redis.service'],
            'writers': ['hermes-agent.service', 'hermes-redis.service'],
            'postgres': [{'container': 'hermes-postgresql',
                          'data_volume': 'hermes-postgres-data',
                          'database': 'hermes',
                          'id': 'main',
                          'unit': 'hermes-postgres.service',
                          'user': 'hermes'}],
            'volumes': ['hermes-data', 'hermes-redis-data'],
            'dirs': [],
            'secrets': ['hermes-api-server-key',
                        'hermes-dashboard-password',
                        'hermes-dashboard-session-secret',
                        'hermes-postgres-password',
                        'hermes-webhook-secret'],
            'configs': [('.config/hermes/hermes.env', '0600')],
            'health': ['http://127.0.0.1:18642/health', 'http://127.0.0.1:18644/health']},
 'hermes-mcp-admin': {'files': ['hermes-mcp-admin.container', 'hermes-mcp-admin.network', 'hermes-mcp-admin.volume'],
                      'units': ['hermes-mcp-admin.service'],
                      'writers': ['hermes-mcp-admin.service'],
                      'postgres': [],
                      'volumes': ['hermes_mcp_admin_data'],
                      'dirs': [],
                      'secrets': ['hermes-mcp-admin-jwt-secret', 'hermes-mcp-admin-password'],
                      'configs': [('.config/hermes-mcp-admin/hermes-mcp-admin.env', '0600')],
                      'health': ['http://127.0.0.1:18502/healthz']},
 'homeassistant': {'files': ['homeassistant-matter-data.volume',
                             'homeassistant-matter.container',
                             'homeassistant-mcp.container',
                             'homeassistant.container'],
                   'units': ['homeassistant-matter.service', 'homeassistant-mcp.service', 'homeassistant.service'],
                   'writers': ['homeassistant-matter.service', 'homeassistant-mcp.service', 'homeassistant.service'],
                   'postgres': [],
                   'volumes': ['homeassistant-matter-data'],
                   'dirs': ['homeassistant/config-preinstalled'],
                   'secrets': ['homeassistant-mcp-token'],
                   'configs': [],
                   'health': ['http://127.0.0.1:8123/manifest.json']},
 'k8s-mcp-admin': {'files': ['k8s-mcp-admin.container', 'k8s-mcp-admin.network', 'k8s-mcp-admin.volume'],
                   'units': ['k8s-mcp-admin.service'],
                   'writers': ['k8s-mcp-admin.service'],
                   'postgres': [],
                   'volumes': ['k8s_mcp_admin_data'],
                   'dirs': [],
                   'secrets': ['k8s-mcp-admin-jwt-secret', 'k8s-mcp-admin-password'],
                   'configs': [('.config/k8s-mcp-admin/k8s-mcp-admin.env', '0600')],
                   'health': ['http://127.0.0.1:18508/healthz']},
 'litellm': {'files': ['litellm-pgdata.volume', 'litellm-postgres.container', 'litellm.container', 'litellm.network'],
             'units': ['litellm-postgres.service', 'litellm.service'],
             'writers': ['litellm.service'],
             'postgres': [{'container': 'litellm-postgres',
                           'data_volume': 'litellm-pgdata',
                           'database': 'litellm',
                           'id': 'main',
                           'unit': 'litellm-postgres.service',
                           'user': 'litellm'}],
             'volumes': [],
             'dirs': [],
             'secrets': ['litellm-database-url',
                         'litellm-master-key',
                         'litellm-postgres-password',
                         'litellm-salt-key',
                         'litellm-ui-password'],
             'configs': [('.config/litellm/config.yaml', '0644'), ('.config/litellm/litellm.env', '0600')],
             'health': ['http://127.0.0.1:4000/health/readiness']},
 'litellm-mcp-admin': {'files': ['litellm-mcp-admin.container',
                                 'litellm-mcp-admin.network',
                                 'litellm-mcp-admin.volume'],
                       'units': ['litellm-mcp-admin.service'],
                       'writers': ['litellm-mcp-admin.service'],
                       'postgres': [],
                       'volumes': ['litellm_mcp_admin_data'],
                       'dirs': [],
                       'secrets': ['litellm-mcp-admin-jwt-secret', 'litellm-mcp-admin-password'],
                       'configs': [('.config/litellm-mcp-admin/litellm-mcp-admin.env', '0600')],
                       'health': ['http://127.0.0.1:18505/healthz']},
 'n8n': {'files': ['n8n-data.volume',
                   'n8n-postgres-data.volume',
                   'n8n-postgres.container',
                   'n8n-runners.container',
                   'n8n-valkey-data.volume',
                   'n8n-valkey.container',
                   'n8n-webhook.container',
                   'n8n-worker-runners.container',
                   'n8n-worker.container',
                   'n8n.container',
                   'n8n.network'],
         'units': ['n8n-postgres.service',
                   'n8n-runners.service',
                   'n8n-valkey.service',
                   'n8n-webhook.service',
                   'n8n-worker-runners.service',
                   'n8n-worker.service',
                   'n8n.service'],
         'writers': ['n8n-valkey.service', 'n8n-webhook.service', 'n8n-worker.service', 'n8n.service'],
         'postgres': [{'container': 'n8n-postgres',
                       'data_volume': 'n8n_postgres_data',
                       'database': 'n8n',
                       'id': 'main',
                       'unit': 'n8n-postgres.service',
                       'user': 'n8n'}],
         'volumes': ['n8n_n8n_data', 'n8n_valkey_data'],
         'dirs': [],
         'secrets': ['n8n-db-password', 'n8n-runners-auth-token', 'n8n-valkey-password'],
         'configs': [('.config/n8n/n8n-task-runners.json', '0644'),
                     ('.config/n8n/n8n.env', '0600'),
                     ('.config/n8n/start-valkey.sh', '0644')],
         'health': ['http://127.0.0.1:15678/healthz/readiness', 'http://127.0.0.1:15679/healthz']},
 'n8n-mcp-admin': {'files': ['n8n-mcp-admin.container', 'n8n-mcp-admin.network', 'n8n-mcp-admin.volume'],
                   'units': ['n8n-mcp-admin.service'],
                   'writers': ['n8n-mcp-admin.service'],
                   'postgres': [],
                   'volumes': ['n8n_mcp_admin_data'],
                   'dirs': [],
                   'secrets': ['n8n-mcp-admin-jwt-secret', 'n8n-mcp-admin-password'],
                   'configs': [('.config/n8n-mcp-admin/n8n-mcp-admin.env', '0600')],
                   'health': ['http://127.0.0.1:18503/healthz']},
 'nextcloud': {'files': ['nextcloud-app.container',
                         'nextcloud-db.container',
                         'nextcloud-gateway.container',
                         'nextcloud-office.container',
                         'nextcloud-redis.container',
                         'nextcloud.network'],
               'units': ['nextcloud-app.service',
                         'nextcloud-db.service',
                         'nextcloud-gateway.service',
                         'nextcloud-office.service',
                         'nextcloud-redis.service'],
               'writers': ['nextcloud-app.service',
                           'nextcloud-db.service',
                           'nextcloud-gateway.service',
                           'nextcloud-redis.service'],
               'postgres': [],
               'volumes': [],
               'dirs': ['.local/share/nextcloud-office/data',
                        '.local/share/nextcloud-office/html',
                        '.local/share/nextcloud-office/postgres',
                        '.local/share/nextcloud-office/redis'],
               'secrets': ['nextcloud-admin-password', 'nextcloud-db-password', 'nextcloud-office-password'],
               'configs': [('.config/nextcloud/gateway.conf', '0644'), ('.config/nextcloud/nextcloud.env', '0600')],
               'health': ['http://127.0.0.1:18081/status.php']},
 'nextcloud-mcp-admin': {'files': ['nextcloud-mcp-admin.container',
                                   'nextcloud-mcp-admin.network',
                                   'nextcloud-mcp-admin.volume'],
                         'units': ['nextcloud-mcp-admin.service'],
                         'writers': ['nextcloud-mcp-admin.service'],
                         'postgres': [],
                         'volumes': ['nextcloud_mcp_admin_data'],
                         'dirs': [],
                         'secrets': ['nextcloud-mcp-admin-jwt-secret', 'nextcloud-mcp-admin-password'],
                         'configs': [('.config/nextcloud-mcp-admin/nextcloud-mcp-admin.env', '0600')],
                         'health': ['http://127.0.0.1:18506/healthz']},
 'odoo': {'files': ['odoo-db-data.volume',
                    'odoo-db.container',
                    'odoo-gateway.container',
                    'odoo-web-data.volume',
                    'odoo.container',
                    'odoo.network'],
          'units': ['odoo-db.service', 'odoo-gateway.service', 'odoo.service'],
          'writers': ['odoo-db.service', 'odoo-gateway.service', 'odoo.service'],
          'postgres': [],
          'volumes': ['odoo18-db-data-isolated', 'odoo18-web-data'],
          'dirs': ['.local/share/odoo18/addons'],
          'secrets': ['odoo18-gateway-conf', 'odoo18-odoo-conf', 'odoo18-postgres-super-password'],
          'configs': [],
          'health': ['http://127.0.0.1:18069/web/health', 'http://127.0.0.1:18080/web/health']},
 'odoo-mcp-admin': {'files': ['odoo-mcp-admin.container', 'odoo-mcp-admin.network', 'odoo-mcp-admin.volume'],
                    'units': ['odoo-mcp-admin.service'],
                    'writers': ['odoo-mcp-admin.service'],
                    'postgres': [],
                    'volumes': ['odoo_mcp_admin_data'],
                    'dirs': [],
                    'secrets': ['odoo-mcp-admin-jwt-secret', 'odoo-mcp-admin-password'],
                    'configs': [('.config/odoo-mcp-admin/odoo-mcp-admin.env', '0600')],
                    'health': ['http://127.0.0.1:18504/healthz']},
 'open-design': {'files': ['open-design-data.volume',
                           'open-design-mcp-data.volume',
                           'open-design-mcp-run.volume',
                           'open-design-mcp.container',
                           'open-design-nginx.container',
                           'open-design-terminal.container',
                           'open-design.container',
                           'open-design.network'],
                 'units': ['open-design-mcp.service',
                           'open-design-nginx.service',
                           'open-design-terminal.service',
                           'open-design.service'],
                 'writers': ['open-design-mcp.service',
                             'open-design-nginx.service',
                             'open-design-terminal.service',
                             'open-design.service'],
                 'postgres': [],
                 'volumes': ['open-design_mcp_data', 'open-design_open_design_data'],
                 'dirs': [],
                 'secrets': ['open-design-api-token', 'open-design-htpasswd'],
                 'configs': [('.config/open-design/nginx-auth.conf', '0644'),
                             ('.config/open-design/nginx-paseo.conf', '0644'),
                             ('.config/open-design/nginx.conf', '0644'),
                             ('.config/open-design/od-export-bridge.js', '0644'),
                             ('.config/open-design/open-design.env', '0600')],
                 'health': ['http://127.0.0.1:7456/api/health']},
 'opendesign-mcp-admin': {'files': ['opendesign-mcp-admin.container',
                                    'opendesign-mcp-admin.network',
                                    'opendesign-mcp-admin.volume'],
                          'units': ['opendesign-mcp-admin.service'],
                          'writers': ['opendesign-mcp-admin.service'],
                          'postgres': [],
                          'volumes': ['opendesign_mcp_admin_data'],
                          'dirs': [],
                          'secrets': ['opendesign-mcp-admin-jwt-secret', 'opendesign-mcp-admin-password'],
                          'configs': [('.config/opendesign-mcp-admin/opendesign-mcp-admin.env', '0600')],
                          'health': ['http://127.0.0.1:18507/healthz']},
 'vk-mcp-admin': {'files': ['vk-mcp-admin.container', 'vk-mcp-admin.network', 'vk-mcp-admin.volume'],
                  'units': ['vk-mcp-admin.service'],
                  'writers': ['vk-mcp-admin.service'],
                  'postgres': [],
                  'volumes': ['vk_mcp_admin_data'],
                  'dirs': [],
                  'secrets': ['vk-mcp-admin-jwt-secret', 'vk-mcp-admin-password'],
                  'configs': [('.config/vk-mcp-admin/vk-mcp-admin.env', '0600')],
                  'health': ['http://127.0.0.1:18509/healthz']}}


def facts(entry):
    """The structural facts compared with EXPECTED (labels, names, timeouts and checks are left to review)."""
    return {
        'files': sorted(entry['quadlet']['files']), 'units': sorted(entry['units']),
        'writers': sorted(entry.get('writer_units', [])),
        'postgres': [{key: p[key] for key in ('id', 'container', 'unit', 'database', 'user', 'data_volume')}
                     for p in entry.get('postgres', [])],
        'volumes': sorted(v['name'] for v in entry.get('volumes', [])),
        'dirs': sorted(d['path'] for d in entry.get('data_dirs', [])),
        'secrets': sorted(s['name'] for s in entry.get('secrets', [])),
        'configs': sorted((c['path'], c['mode']) for c in entry.get('config_files', [])),
        'health': sorted(h['url'] for h in entry.get('health', [])),
    }


def lookup_for(home, uid=1000):
    def lookup(name):
        if name == OWNER:
            return types.SimpleNamespace(pw_name=OWNER, pw_uid=uid, pw_gid=uid, pw_dir=str(home))
        if name == 'otherowner':
            return types.SimpleNamespace(pw_name=name, pw_uid=1500, pw_gid=1500, pw_dir='/home/otherowner')
        if name == 'rootalias':
            return types.SimpleNamespace(pw_name=name, pw_uid=0, pw_gid=0, pw_dir='/root')
        raise KeyError(name)
    return lookup


class FakeOwner:
    """Runner for OwnerRunner: owner-side Python helpers run for real (HOME = the temp home, env -i as in production);
    `podman secret|volume ls` and `systemctl --user show` are answered from the fixture."""

    def __init__(self, secrets=None, volumes=None, states=None, fail_podman=False):
        self.calls = []
        self.secrets, self.volumes = secrets, volumes
        self.states = states or {}
        self.fail_podman = fail_podman

    def __call__(self, argv, *, input=None, stdout=None, timeout=None, cwd=None, env=None, max_output=None):
        assert argv[:4] == ['/usr/sbin/runuser', '-u', OWNER, '--'], argv[:4]
        inner = argv[4:]
        command = inner[7:]
        self.calls.append(command)
        if command[0] == '/usr/bin/python3':
            return podman.default_runner(inner, input=input, stdout=stdout, timeout=timeout, cwd=cwd, env=env,
                                         max_output=max_output)
        if command[0] == '/usr/bin/podman':
            names = {'secret': self.secrets, 'volume': self.volumes}.get(command[1])
            if self.fail_podman or names is None or command[2] != 'ls':
                return podman.Result(125, b'', b'Error: cannot connect')
            return podman.Result(0, '\n'.join(sorted(names)).encode(), b'')
        if command[0] == '/usr/bin/systemctl':
            assert command[1:3] == ['--user', 'show'], command
            units = command[command.index('--') + 1:]
            blocks = [f'Id={u}\nLoadState=loaded\nActiveState={self.states.get(u, "active")}' for u in units]
            return podman.Result(0, '\n\n'.join(blocks).encode(), b'')
        raise AssertionError(f'unexpected owner command {command}')


def build_home(base, quadlets=None, layout=None):
    home = Path(base) / 'home'
    qdir = home / '.config/containers/systemd'
    qdir.mkdir(parents=True)
    if quadlets is None:
        for path in sorted((FIXTURES / 'quadlet').iterdir()):
            shutil.copy(path, qdir / path.name)
    else:
        for name, text in quadlets.items():
            (qdir / name).write_text(text)
    layout = layout if layout is not None else json.loads((FIXTURES / 'home.json').read_text())
    for rel, mode in layout.get('dirs', {}).items():
        path = home / rel
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(int(mode, 8))
    for rel, mode in layout.get('files', {}).items():
        path = home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f'{LEAK_MARKER}\n')
        path.chmod(int(mode, 8))
    return home


def run_suggest(base, home, *, installed=(), fake=None, linger=()):
    lookup = lookup_for(home)
    fake = fake or FakeOwner()
    runner = podman.OwnerRunner(OWNER, runner=fake, user_lookup=lookup)
    paths = Paths(base=Path(base))
    cat = catalog.Catalog()
    for entry in installed:
        app = catalog.validate_entry(entry, paths=paths, user_lookup=lookup)
        cat[app.id] = app
    linger_dir = Path(base) / 'linger'
    linger_dir.mkdir(exist_ok=True)
    for name in linger:
        (linger_dir / name).touch()
    result = suggest.suggest(OWNER, paths=paths, catalog=cat, runner=runner, user_lookup=lookup,
                             linger_dir=str(linger_dir))
    return result, fake


def variant(app, mode):
    for item in app['variants']:
        if item['id'] == mode:
            return item
    raise AssertionError(f'{app["id"]} has no variant {mode}')


def mode_of(expected):
    return 'database' if expected['postgres'] else 'cold'


def entry_for(app, mode):
    return variant(app, mode)['entry'] if app['variants'] else app['entry']


def quadlet(name):
    return suggest.parse_unit((FIXTURES / 'quadlet' / name).read_text())


class ReferenceHostTests(unittest.TestCase):
    """The 20 apps of the reference host, suggested from their Quadlet files."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.home = build_home(cls.tmp.name)
        secrets = {s for facts_ in EXPECTED.values() for s in facts_['secrets']} | {'code-server-unused'}
        volumes = {v for facts_ in EXPECTED.values() for v in facts_['volumes']} | {
            'n8n_postgres_data', 'litellm-pgdata', 'hermes-postgres-data', 'code-server-data', 'code-server-config',
            'code-server-cache', 'headscale-run', 'open-design_mcp_run'}
        secrets.discard('headscale-ngrok-authtoken')  # one missing secret: reported, never fatal
        fake = FakeOwner(secrets=secrets, volumes=volumes, states={'code-server.service': 'inactive'})
        cls.result, cls.fake = run_suggest(cls.tmp.name, cls.home, fake=fake, linger=(OWNER, 'root', 'Bad Name'))
        cls.apps = {app['id']: app for app in cls.result['apps']}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_groups_the_directory_into_the_reference_apps(self):
        self.assertEqual(sorted(self.apps), sorted(set(EXPECTED) | {'code-server'}))
        self.assertEqual(self.result['state'], 'ok')
        self.assertEqual(self.result['unassigned'], [])
        self.assertEqual(self.result['unsupported'], [])
        self.assertEqual(self.result['owners'], [{'name': OWNER, 'uid': 1000, 'linger': True, 'catalog_apps': []}])

    def test_drafts_match_the_hand_written_entries(self):
        for app_id, expected in EXPECTED.items():
            with self.subTest(app=app_id):
                entry = entry_for(self.apps[app_id], mode_of(expected))
                got = facts(entry)
                want = copy.deepcopy(expected)
                # A bind-mounted configuration directory is proposed as a host directory; the reference lists the
                # files in it one by one (it predates host directories). Every such file must be covered.
                covered = [c for c in want['configs'] if any(catalog.paths_overlap(d, c[0]) for d in got['dirs'])]
                extra_dirs = sorted(set(got['dirs']) - set(want['dirs']))
                for directory in extra_dirs:
                    self.assertTrue(any(catalog.paths_overlap(directory, c[0]) for c in covered), directory)
                want['configs'] = [c for c in want['configs'] if c not in covered]
                want['dirs'] = sorted(set(want['dirs']) | set(extra_dirs))
                self.assertEqual(got, want)
        self.assertEqual(facts(entry_for(self.apps['headscale'], 'cold'))['dirs'], ['.config/headscale/headscale'])

    def test_embedded_expectations_are_the_reference_entries(self):
        if not REFERENCE.is_dir():
            self.skipTest('the lab reference directory is not on this machine')
        seen = set()
        for path in sorted(REFERENCE.glob('*.json')):
            entry = json.loads(path.read_text())
            seen.add(entry['id'])
            expected = EXPECTED[entry['id']]
            self.assertEqual(facts(entry), {**expected, 'configs': sorted(expected['configs'])}, path.name)
        self.assertEqual(seen, set(EXPECTED))

    def test_every_draft_and_variant_passes_the_catalog_validator(self):
        for app in self.result['apps']:
            self.assertTrue(app['valid'], (app['id'], app['problem']))
            for item in app['variants']:
                self.assertTrue(item['valid'], (app['id'], item['id'], item['problem']))
                catalog.validate_entry(item['entry'], paths=Paths(base=Path(self.tmp.name)),
                                       user_lookup=lookup_for(self.home))

    def test_databases_default_to_cold_with_export_variants(self):
        n8n = self.apps['n8n']
        self.assertEqual(n8n['variant'], 'cold')
        self.assertEqual([v['id'] for v in n8n['variants']], ['cold', 'instance', 'database'])
        cold = n8n['entry']
        self.assertEqual(cold['postgres'], [])
        self.assertIn({'name': 'n8n_postgres_data', 'label': 'PostgreSQL 資料（冷備份）'}, cold['volumes'])
        self.assertIn('n8n-postgres.service', cold['writer_units'])
        self.assertEqual(cold['units'][0], 'n8n-postgres.service')
        instance = variant(n8n, 'instance')['entry']
        self.assertEqual(instance['postgres'], [{'id': 'main', 'container': 'n8n-postgres',
                                                 'unit': 'n8n-postgres.service', 'user': 'n8n',
                                                 'data_volume': 'n8n_postgres_data', 'scope': 'instance'}])
        self.assertNotIn('n8n-postgres.service', instance['writer_units'])
        self.assertNotIn('n8n_postgres_data', [v['name'] for v in instance['volumes']])
        self.assertEqual(n8n['databases'], [{'unit': 'n8n-postgres.service', 'container': 'n8n-postgres',
                                             'kind': 'postgres', 'image': 'docker.io/library/postgres:16-alpine',
                                             'major': 16,
                                             'database': 'n8n', 'user': 'n8n', 'guessed': False,
                                             'data': {'volume': 'n8n_postgres_data'}},
                                            {'unit': 'n8n-valkey.service', 'container': 'n8n-valkey', 'kind': 'cache',
                                             'image': 'docker.io/valkey/valkey:8-alpine'}])
        # Data in a host directory: only the cold pattern exists.
        nextcloud = self.apps['nextcloud']
        self.assertEqual([v['id'] for v in nextcloud['variants']], ['cold'])
        self.assertIn('db-dir', [n['code'] for n in nextcloud['notes']])
        self.assertIn({'path': '.local/share/nextcloud-office/postgres', 'label': 'PostgreSQL 資料（冷備份）'},
                      nextcloud['entry']['data_dirs'])

    def test_start_order_follows_the_dependencies(self):
        for app in self.result['apps']:
            for mode_entry in [app['entry']] + [v['entry'] for v in app['variants']]:
                units = mode_entry['units']
                for unit in units:
                    sections = quadlet(unit.replace('.service', '.container'))
                    needed = set()
                    for key in ('After', 'Requires', 'Wants', 'BindsTo'):
                        for value in suggest.values(sections, 'Unit', key):
                            needed |= set(value.split())
                    network = suggest.last(sections, 'Container', 'Network') or ''
                    if network.startswith('container:'):
                        needed.add(network.split(':', 1)[1] + '.service')
                    for dependency in needed & set(units):
                        self.assertLess(units.index(dependency), units.index(unit), (app['id'], unit, dependency))
        self.assertEqual(self.apps['nextcloud']['entry']['units'],
                         ['nextcloud-db.service', 'nextcloud-redis.service', 'nextcloud-app.service',
                          'nextcloud-office.service', 'nextcloud-gateway.service'])

    def test_writers_follow_stop_propagation_namespaces_and_database_clients(self):
        writers = {app_id: set(entry_for(self.apps[app_id], mode_of(EXPECTED[app_id]))['writer_units'])
                   for app_id in EXPECTED}
        self.assertIn('emqx-entrance.service', writers['emqx'])            # shares the broker's network namespace
        self.assertIn('homeassistant-mcp.service', writers['homeassistant'])  # Requires= the core
        self.assertIn('litellm.service', writers['litellm'])               # client of the exported database
        self.assertIn('open-design-nginx.service', writers['open-design'])
        self.assertNotIn('n8n-runners.service', writers['n8n'])            # Wants= only, no data
        self.assertNotIn('headscale-ngrok.service', writers['headscale'])
        self.assertNotIn('nextcloud-office.service', writers['nextcloud'])
        self.assertNotIn('litellm-postgres.service', writers['litellm'])   # export mode: the database stays up

    def test_runtime_volumes_and_system_paths_are_skipped_with_a_reason(self):
        skipped = {app_id: {(s['kind'], s.get('name') or s.get('path')) for s in app['skipped']}
                   for app_id, app in self.apps.items()}
        self.assertIn(('volume', 'headscale-run'), skipped['headscale'])
        self.assertIn(('volume', 'open-design_mcp_run'), skipped['open-design'])
        self.assertIn(('bind', '/run/dbus'), skipped['homeassistant'])
        self.assertIn(('bind', '/etc/localtime'), skipped['homeassistant'])

    def test_read_only_directories_are_noted(self):
        noted = {app_id: {n['path'] for n in app['notes'] if n['code'] == 'dir-read-only'}
                 for app_id, app in self.apps.items()}
        self.assertEqual(noted['odoo'], {'.local/share/odoo18/addons'})
        self.assertEqual(noted['headscale'], {'.config/headscale/headscale'})
        self.assertEqual(noted['nextcloud'], set())  # html is read-only for the gateway but written by the app

    def test_personal_folders_login_keys_and_files_outside_the_app_are_flagged(self):
        app = self.apps['code-server']
        codes = [(w['code'], w.get('path')) for w in app['warnings']]
        self.assertIn(('bind-forbidden', '.ssh'), codes)
        self.assertIn(('bind-forbidden', '.local/bin'), codes)
        self.assertIn(('bind-sensitive', 'Desktop'), codes)
        self.assertIn('environment-secret', [w['code'] for w in app['warnings']])
        self.assertNotIn('data_dirs', app['entry'])
        self.assertIn(('config', '.gitconfig'), {(s['kind'], s.get('path')) for s in app['skipped']})
        self.assertEqual([v['name'] for v in app['entry']['volumes']],
                         ['code-server-data', 'code-server-config', 'code-server-cache'])
        self.assertEqual(app['entry']['health'][0]['url'], 'http://127.0.0.1:8443/healthz')
        self.assertIn('not-running', [w['code'] for w in app['warnings']])

    def test_no_secret_value_or_environment_file_content_leaves_the_helper(self):
        text = json.dumps(self.result, ensure_ascii=False)
        self.assertNotIn(DUMMY_SECRET, text)
        self.assertNotIn(LEAK_MARKER, text)
        self.assertNotIn('PASSWORD=', text)

    def test_health_urls_come_from_health_commands_and_loopback_ports(self):
        self.assertEqual(self.apps['emqx']['entry']['health'], [])  # published on a LAN address only
        self.assertTrue(any('5678' in hint for hint in self.apps['n8n']['hints']))  # the worker publishes nothing
        self.assertEqual([h['url'] for h in self.apps['homeassistant']['entry']['health']],
                         ['http://127.0.0.1:8123/manifest.json'])  # Network=host
        self.assertEqual(self.apps['odoo']['entry']['health'][1]['url'], 'http://127.0.0.1:18080/web/health')  # port 80
        self.assertEqual({h['timeout_seconds'] for h in self.apps['vk-mcp-admin']['entry']['health']}, {180})
        self.assertEqual({h['timeout_seconds'] for h in self.apps['odoo']['entry']['health']}, {300})

    def test_config_file_modes(self):
        configs = {c['path']: c['mode'] for c in self.apps['n8n']['entry']['config_files']}
        self.assertEqual(configs, {'.config/n8n/n8n.env': '0600', '.config/n8n/start-valkey.sh': '0644',
                                   '.config/n8n/n8n-task-runners.json': '0644'})
        flagged = {w.get('path') for w in self.apps['n8n']['warnings'] if w['code'] == 'config-mode'}
        self.assertEqual(flagged, {'.config/n8n/start-valkey.sh', '.config/n8n/n8n-task-runners.json'})

    def test_built_in_digest_checks_are_proposed(self):
        nextcloud = self.apps['nextcloud']['entry']['verify']
        self.assertEqual(nextcloud[0], {'id': 'db-main', 'type': 'postgres-digest', 'container': 'nextcloud-db',
                                        'unit': 'nextcloud-db.service', 'user': 'nextcloud',
                                        'label': 'PostgreSQL 資料表內容'})
        self.assertEqual([v.get('data_dir') for v in nextcloud[1:]],
                         ['.local/share/nextcloud-office/redis', '.local/share/nextcloud-office/html',
                          '.local/share/nextcloud-office/data'])  # the table digest covers the database directory
        exported = variant(self.apps['n8n'], 'database')['entry']['verify']
        self.assertEqual(exported[0], {'id': 'db-main', 'type': 'postgres-digest', 'postgres': 'main',
                                       'label': 'PostgreSQL 資料表內容'})
        self.assertEqual({v['volume'] for v in exported[1:]}, {'n8n_n8n_data', 'n8n_valkey_data'})

    def test_missing_secrets_and_volumes_are_reported(self):
        codes = [w['message'] for w in self.apps['headscale']['warnings'] if w['code'] == 'secret-missing']
        self.assertEqual(len(codes), 1)
        self.assertIn('headscale-ngrok-authtoken', codes[0])

    def test_only_read_only_owner_commands_ran(self):
        helpers = [c for c in self.fake.calls if c[0] == '/usr/bin/python3']
        self.assertEqual(helpers[0][:4], ['/usr/bin/python3', '-I', '-c', suggest.SCAN_HELPER])
        self.assertEqual(helpers[0][4:], ['.config/containers/systemd'])
        for command in helpers[1:]:
            self.assertEqual(command[3:5], [podman.FILE_HELPER, 'stat'])
        others = [c for c in self.fake.calls if c[0] != '/usr/bin/python3']
        self.assertEqual(sorted(tuple(c[:3]) for c in others),
                         [('/usr/bin/podman', 'secret', 'ls'), ('/usr/bin/podman', 'volume', 'ls'),
                          ('/usr/bin/systemctl', '--user', 'show')])


def installed_n8n():
    """The production n8n entry as written by hand (export mode), with one volume missing on purpose."""
    return {
        'schema': 1, 'id': 'n8n', 'name': 'n8n 工作流程', 'description': 'n8n 佇列模式', 'owner': OWNER,
        'adapter': 'quadlet-postgres',
        'quadlet': {'files': ['n8n.network', 'n8n-data.volume', 'n8n-postgres-data.volume', 'n8n-valkey-data.volume',
                              'n8n-postgres.container', 'n8n-valkey.container', 'n8n.container', 'n8n-worker.container',
                              'n8n-webhook.container', 'n8n-runners.container', 'n8n-worker-runners.container']},
        'units': ['n8n-postgres.service', 'n8n-valkey.service', 'n8n.service', 'n8n-worker.service',
                  'n8n-webhook.service', 'n8n-runners.service', 'n8n-worker-runners.service'],
        'writer_units': ['n8n-valkey.service', 'n8n.service', 'n8n-worker.service', 'n8n-webhook.service'],
        'postgres': [{'id': 'main', 'container': 'n8n-postgres', 'unit': 'n8n-postgres.service', 'database': 'n8n',
                      'user': 'n8n', 'data_volume': 'n8n_postgres_data'}],
        'volumes': [{'name': 'n8n_n8n_data', 'label': 'n8n 設定與加密金鑰'}],
        'secrets': [{'name': 'n8n-db-password'}, {'name': 'n8n-runners-auth-token'}, {'name': 'n8n-valkey-password'}],
        'config_files': [{'path': '.config/n8n/n8n.env', 'mode': '0600'},
                         {'path': '.config/n8n/n8n-task-runners.json', 'mode': '0644'},
                         {'path': '.config/n8n/start-valkey.sh', 'mode': '0644'}],
        'health': [{'type': 'http', 'url': 'http://127.0.0.1:15678/healthz/readiness', 'expect_status': 200,
                    'timeout_seconds': 300}],
        'verify': [],
    }


class InstalledEntryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = build_home(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_draft_keeps_the_installed_mode_and_wording_and_reports_drift(self):
        result, _ = run_suggest(self.tmp.name, self.home, installed=[installed_n8n()])
        app = next(a for a in result['apps'] if a['id'] == 'n8n')
        self.assertEqual(app['variant'], 'database')  # switching to cold would strand the existing backups
        self.assertIn('installed-mode', [n['code'] for n in app['notes']])
        entry = app['entry']
        self.assertEqual(entry['name'], 'n8n 工作流程')
        self.assertEqual(entry['volumes'][0], {'name': 'n8n_n8n_data', 'label': 'n8n 設定與加密金鑰'})
        self.assertEqual(entry['health'], installed_n8n()['health'])
        installed = app['installed']
        self.assertEqual(installed['id'], 'n8n')
        self.assertEqual(len(installed['sha256']), 64)
        self.assertEqual(installed['drift'], ['Quadlet 使用資料卷 n8n_valkey_data，但已安裝的設定沒有列入：它不會被備份。'])
        paths = {(c['path'], c['op']) for c in installed['changes']}
        self.assertIn(('volumes[name=n8n_valkey_data]', 'add'), paths)
        self.assertIn(('verify[id=db-main]', 'add'), paths)
        self.assertNotIn(('units', 'order'), paths)  # the draft follows the installed order
        self.assertFalse(installed['same'])

    def test_keys_the_installed_entry_leaves_out_stay_out_when_empty(self):
        mcp = {'schema': 1, 'id': 'headscale-mcp-admin', 'name': 'Headscale MCP 管理', 'description': '', 'owner': OWNER,
               'adapter': 'quadlet-postgres',
               'quadlet': {'files': ['headscale-mcp.network', 'headscale-mcp.volume', 'headscale-mcp-admin.container']},
               'units': ['headscale-mcp-admin.service'], 'writer_units': ['headscale-mcp-admin.service'],
               'volumes': [{'name': 'headscale_mcp_data', 'label': 'MCP 管理資料'}],
               'secrets': [{'name': 'headscale-mcp-admin-jwt-secret'}, {'name': 'headscale-mcp-admin-password'}],
               'health': [{'type': 'http', 'url': 'http://127.0.0.1:18500/healthz', 'expect_status': 200,
                           'timeout_seconds': 180}],
               'verify': [{'id': 'files', 'type': 'files-digest', 'volume': 'headscale_mcp_data'}]}
        result, _ = run_suggest(self.tmp.name, self.home, installed=[mcp])
        app = next(a for a in result['apps'] if a['id'] == 'headscale-mcp-admin')
        self.assertNotIn('postgres', app['entry'])
        self.assertNotIn('config_files', app['entry'])
        self.assertEqual(app['entry']['verify'], mcp['verify'])  # the digest of that volume exists already
        self.assertTrue(app['installed']['same'], app['installed']['changes'])
        self.assertEqual(app['installed']['drift'], [])

    def test_installed_id_is_adopted_for_the_same_files(self):
        renamed = installed_n8n()
        renamed['id'] = 'workflows'
        renamed['config_files'] = []
        result, _ = run_suggest(self.tmp.name, self.home, installed=[renamed])
        ids = [a['id'] for a in result['apps']]
        self.assertIn('workflows', ids)
        self.assertNotIn('n8n', ids)
        app = next(a for a in result['apps'] if a['id'] == 'workflows')
        self.assertIn('installed-id', [n['code'] for n in app['notes']])
        # .config/n8n/ is not this id's directory: the files are reported instead of producing an invalid draft.
        self.assertTrue(app['valid'], app['problem'])
        self.assertIn('.config/n8n/n8n.env', [s.get('path') for s in app['skipped']])

    def test_id_of_another_owner_is_reported(self):
        other = installed_n8n()
        other.update(owner='otherowner', id='vk-mcp-admin', config_files=[])
        result, _ = run_suggest(self.tmp.name, self.home, installed=[other])
        app = next(a for a in result['apps'] if a['id'] == 'vk-mcp-admin')
        self.assertIn('id-taken', [w['code'] for w in app['warnings']])
        # review M3: installing it would take over the other owner's entry and backups -- not installable as is
        self.assertEqual(next(w['level'] for w in app['warnings'] if w['code'] == 'id-taken'), 'error')
        self.assertFalse(app['valid'])
        self.assertEqual(app['field'], 'id')
        self.assertIn('改成其他名稱', app['problem'])


def analyze(quadlets, *, files=(), dirs=(), installed=(), home='/home/woowtechopenclaw'):
    """Analyzer on inline Quadlet text; `files`/`dirs` are the bind sources that exist (relative to the home)."""
    entries = [{'name': name, 'type': 'file', 'size': len(text), 'mode': 0o644, 'text': text}
               for name, text in quadlets.items()]
    known = {**{rel: {'path': rel, 'type': 'file', 'size': 1, 'mode': 0o644} for rel in files},
             **{rel: {'path': rel, 'type': 'dir', 'size': 0, 'mode': 0o755} for rel in dirs}}

    def stat(rels):
        return {rel: known.get(rel, {'path': rel, 'type': 'missing'}) for rel in rels}

    lookup = lookup_for(home)
    analyzer = suggest.Analyzer(OWNER, 1000, home, entries, stat=stat, installed=installed,
                                paths=Paths(base=Path('/nonexistent-woowbk')), user_lookup=lookup)
    result = analyzer.analyze()
    return result, {app['id']: app for app in result['apps']}


def container(image='docker.io/library/nginx:1.27', extra='', unit=''):
    return f'[Unit]\n{unit}\n[Container]\nImage={image}\n{extra}\n'


class GroupingTests(unittest.TestCase):
    def test_a_shared_network_does_not_merge_unrelated_apps(self):
        result, apps = analyze({'proxy.network': '[Network]\nNetworkName=proxy\n',
                                'blog.container': container(extra='Network=proxy.network'),
                                'wiki.container': container(extra='Network=proxy.network')})
        self.assertEqual(sorted(apps), ['blog', 'wiki'])
        files = [apps['blog']['entry']['quadlet']['files'], apps['wiki']['entry']['quadlet']['files']]
        self.assertEqual(sum('proxy.network' in f for f in files), 1)
        self.assertIn('shared-file', [w['code'] for app in apps.values() for w in app['warnings']])

    def test_hard_labels_split_and_report_cross_links(self):
        result, apps = analyze({
            'shop.network': '[Network]\n',
            'shop-db.container': container('docker.io/library/postgres:16',
                                           'Network=shop.network\nLabel=io.woowtech.app=store\n'
                                           'Volume=shop-pg:/var/lib/postgresql/data\nVolume=shared-assets:/srv'),
            'shop-app.container': container(extra='Network=shop.network\nLabel=io.woowtech.app=store'),
            'shop-admin.container': container(extra='Network=shop.network\nLabel=io.woowtech.app=backoffice\n'
                                                    'Volume=shared-assets:/srv')})
        self.assertEqual(sorted(apps), ['backoffice', 'store'])
        self.assertEqual(apps['backoffice']['entry']['units'], ['shop-admin.service'])
        self.assertIn('cross-app-link', [w['code'] for w in result['warnings']])

    def test_app_label_pod_and_namespace_link_containers(self):
        _, apps = analyze({
            'one.container': container(extra='Label=app=suite'),
            'two.container': container(extra='Label="app=suite" "tier=web"'),
            'stack.pod': '[Pod]\nPublishPort=127.0.0.1:18200:80\n',
            'alpha.container': container(extra='Pod=stack.pod\nHealthCmd=curl -f http://localhost/ping'),
            'beta.container': container(extra='Pod=stack.pod'),
            'core.container': container(extra='Volume=core-data:/data'),
            'side.container': container(extra='Network=core.container')})
        self.assertEqual(sorted(apps), ['alpha', 'core', 'suite'])  # no common prefix: the app label names it
        self.assertEqual(sorted(apps['suite']['entry']['units']), ['one.service', 'two.service'])
        self.assertEqual(apps['alpha']['entry']['quadlet']['files'][0], 'stack.pod')
        self.assertEqual(apps['alpha']['entry']['health'][0]['url'], 'http://127.0.0.1:18200/ping')  # pod port
        core = apps['core']['entry']
        self.assertEqual(core['units'], ['core.service', 'side.service'])
        self.assertEqual(core['writer_units'], ['core.service', 'side.service'])

    def test_mount_and_podman_args_forms(self):
        _, apps = analyze({
            'app.container': container(extra=(
                'Mount=type=bind,source=%h/app/data,destination=/data\n'
                'Mount=type=bind,src=%h/.config/app/app.conf,dst=/etc/app.conf,ro=true\n'
                'Mount=type=volume,source=app-cache,destination=/cache\n'
                'Mount=type=tmpfs,destination=/tmp\n'
                'PodmanArgs=-v %h/app/extra:/extra --secret app-token,type=env,target=TOKEN '
                '--env-file=%h/.config/app/app.env --publish 127.0.0.1:18300:8000 --stop-timeout 30\n'
                'HealthCmd=wget -qO- http://0.0.0.0:8000/health'))},
            files=['.config/app/app.conf', '.config/app/app.env'], dirs=['app/data', 'app/extra'])
        entry = apps['app']['entry']
        self.assertEqual([d['path'] for d in entry['data_dirs']], ['app/data', 'app/extra'])
        self.assertEqual(entry['config_files'], [{'path': '.config/app/app.env', 'mode': '0600'},
                                                 {'path': '.config/app/app.conf', 'mode': '0644'}])
        self.assertEqual(entry['secrets'], [{'name': 'app-token'}])
        self.assertEqual([v['name'] for v in entry['volumes']], ['app-cache'])
        self.assertEqual(entry['health'][0]['url'], 'http://127.0.0.1:18300/health')

    def test_a_health_url_query_string_never_reaches_the_draft(self):
        # review L5: `?token=...` in a HealthCmd would land in the world-readable catalog entry and in job logs
        _, apps = analyze({'tok.container': container(extra=(
            'PublishPort=127.0.0.1:18400:8080\n'
            'HealthCmd=curl -fs http://127.0.0.1:8080/health?token=s3cr3t-value&full=1'))})
        app = apps['tok']
        self.assertEqual(app['entry']['health'][0]['url'], 'http://127.0.0.1:18400/health')
        self.assertNotIn('s3cr3t-value', json.dumps(app, ensure_ascii=False))
        self.assertTrue(any('查詢參數' in hint for hint in app['hints']))

    def test_nested_and_overlapping_directories_are_merged(self):
        _, apps = analyze({'app.container': container(extra='Volume=%h/srv/app:/a\nVolume=%h/srv/app/media:/m:ro\n'
                                                            'Volume=%h/srv/app/conf/x.conf:/x.conf:ro')},
                          files=['srv/app/conf/x.conf'], dirs=['srv/app', 'srv/app/media'])
        app = apps['app']
        self.assertEqual([d['path'] for d in app['entry']['data_dirs']], ['srv/app'])
        self.assertEqual(app['entry']['config_files'], [])
        codes = [n['code'] for n in app['notes']]
        self.assertIn('dir-nested', codes)

    def test_unusual_mounts_are_reported(self):
        _, apps = analyze({'odd.container': container(extra=(
            'Volume=/data\nVolume=%i/x:/x\nVolume=%t/podman/podman.sock:/run/podman.sock\nVolume=%h:/home\n'
            'Volume=%h/missing:/m\nVolume=%h/odd name:/n\nVolume=bad$name:/b'))})
        app = apps['odd']
        codes = [w['code'] for w in app['warnings']]
        self.assertIn('podman-socket', codes)
        self.assertIn('bind-home', codes)
        self.assertIn('bind-missing', codes)
        reasons = ' '.join(s['reason'] for s in app['skipped'])
        self.assertIn('匿名資料卷', reasons)
        self.assertIn('%i', reasons)
        self.assertIn('不支援的字元', reasons)
        self.assertTrue(app['valid'], app['problem'])

    def test_database_detection_guesses_and_dependency_warnings(self):
        _, apps = analyze({
            'acme-db.container': container('quay.io/example/pgvector:pg17',
                                           'Volume=acme-pg:/var/lib/postgresql/data\n'
                                           'HealthCmd=pg_isready -U acme -d acmedb', unit='Requires=acme-web.service'),
            'acme-web.container': container(extra='Volume=acme-files:/srv', unit='After=acme-db.service'),
            'acme-old.container': container('docker.io/library/mariadb', 'Volume=acme-maria:/var/lib/mysql',
                                            unit='Wants=acme-web.service')})
        app = apps['acme']
        db = next(d for d in app['databases'] if d['kind'] == 'postgres')
        self.assertEqual((db['database'], db['user'], db['major'], db['guessed']), ('acmedb', 'acme', 17, True))
        codes = [w['code'] for w in app['warnings']] + [n['code'] for n in app['notes']]
        self.assertIn('db-depends-on-writer', codes)
        self.assertIn('db-tag', codes)  # mariadb without a pinned major
        self.assertIn('db-other', codes)
        self.assertIn('db-guessed', codes)
        self.assertIn('acme-old.service', app['entry']['writer_units'])  # other databases are always cold

    def test_dependency_cycles_still_produce_an_order(self):
        _, apps = analyze({'cyc-a.container': container(unit='After=cyc-b.service'),
                           'cyc-b.container': container(unit='After=cyc-a.service')})
        app = apps['cyc']
        self.assertEqual(sorted(app['entry']['units']), ['cyc-a.service', 'cyc-b.service'])
        self.assertIn('dependency-cycle', [w['code'] for w in app['warnings']])

    def test_unsupported_and_unreadable_directory_entries(self):
        entries = [
            {'name': 'site.kube', 'type': 'file', 'size': 1, 'mode': 0o644, 'text': '[Kube]\n'},
            {'name': 'web@.container', 'type': 'file', 'size': 1, 'mode': 0o644, 'text': container()},
            {'name': 'linked.container', 'type': 'link', 'size': 0, 'mode': 0o777},
            {'name': 'big.container', 'type': 'file', 'size': 2 << 20, 'mode': 0o644, 'skipped': 'too-large'},
            {'name': 'apps', 'type': 'dir', 'size': 0, 'mode': 0o755},
            {'name': 'web.container.d', 'type': 'dir', 'size': 0, 'mode': 0o755},
            {'name': 'notes.txt', 'type': 'file', 'size': 1, 'mode': 0o644},
            {'name': 'stray.volume', 'type': 'file', 'size': 1, 'mode': 0o644, 'text': '[Volume]\n'},
            {'name': 'Bad Name.container', 'type': 'file', 'size': 1, 'mode': 0o644, 'text': container()},
        ]
        result = suggest.Analyzer(OWNER, 1000, '/home/woowtechopenclaw', entries).analyze()
        self.assertEqual(result['apps'], [])
        self.assertEqual([u['file'] for u in result['unsupported']], ['site.kube', 'web@.container'])
        self.assertEqual(result['unassigned'][0]['file'], 'stray.volume')
        codes = sorted(w['code'] for w in result['warnings'])
        self.assertEqual(codes, ['dropin', 'file-name', 'file-unread', 'subdir', 'symlink'])

    def test_an_unused_volume_file_joins_the_app_of_its_name(self):
        _, apps = analyze({'wiki.container': container(), 'wiki-old.volume': '[Volume]\nVolumeName=wiki_old\n'})
        app = apps['wiki']
        self.assertEqual(app['entry']['quadlet']['files'], ['wiki-old.volume', 'wiki.container'])
        self.assertEqual(app['entry']['volumes'], [])  # nothing mounts it: not proposed for backup
        self.assertIn('aux-by-name', [n['code'] for n in app['notes']])

    def test_repeated_keys_are_bounded(self):
        lines = '\n'.join(f'Volume=v{i}:/d{i}' for i in range(suggest.MAX_ITEMS + 50))
        _, apps = analyze({'many.container': container(extra=lines)})
        app = apps['many']
        self.assertEqual(len(app['entry']['volumes']), suggest.MAX_ITEMS)
        self.assertIn('too-many', [w['code'] for w in app['warnings']])
        self.assertFalse(app['valid'])  # 128 volumes are more than the catalog allows (32): reported, not hidden
        self.assertEqual(app['field'], 'volumes')

    def test_installed_split_and_ids_stay_unique(self):
        _, apps = analyze({'x1.container': container(), 'x1-b.volume': '[Volume]\n'})
        self.assertEqual(sorted(apps), ['x1'])
        self.assertEqual(suggest.sanitize_id('A'), 'a-app')
        self.assertEqual(suggest.sanitize_id('My_App..Prod'), 'my-app-prod')


class ParserTests(unittest.TestCase):
    def test_unit_syntax(self):
        sections = suggest.parse_unit('# c\n[Unit]\nAfter=a.service \\\n  # comment inside\n  b.service\n'
                                      '[Container]\n; c\nVolume=x:/y\nVolume=z:/w\nBroken line\nKey = spaced value \n')
        self.assertEqual(suggest.values(sections, 'Unit', 'After'), ['a.service b.service'])
        self.assertEqual(suggest.values(sections, 'Container', 'Volume'), ['x:/y', 'z:/w'])
        self.assertEqual(suggest.last(sections, 'Container', 'Key'), 'spaced value')
        self.assertEqual(suggest.split_words('A="b c" D=e \'f g\''), ['A=b c', 'D=e', 'f g'])
        self.assertEqual(suggest.split_words('unbalanced "quote'), ['unbalanced', '"quote'])

    def test_publish_forms(self):
        parse = suggest.parse_publish
        self.assertEqual(parse('127.0.0.1:4000:4000'), [('127.0.0.1', 4000, 4000, 'tcp')])
        self.assertEqual(parse('8080:80/udp'), [('', 8080, 80, 'udp')])
        self.assertEqual(parse('80'), [('', None, 80, 'tcp')])
        self.assertEqual(parse('127.0.0.1::80'), [('127.0.0.1', None, 80, 'tcp')])
        self.assertEqual(parse('[::1]:8080:80'), [('::1', 8080, 80, 'tcp')])
        self.assertEqual(parse('9000-9001:8000-8001'), [('', 9000, 8000, 'tcp'), ('', 9001, 8001, 'tcp')])
        self.assertEqual(parse('1:2:3:4'), [])
        self.assertEqual(parse('x:y'), [])
        self.assertEqual(parse('1-3:1-2'), [])
        self.assertFalse(suggest.loopback_usable('192.0.2.10'))
        self.assertTrue(suggest.loopback_usable('0.0.0.0'))

    def test_images_and_names(self):
        self.assertEqual(suggest.repository_name('docker.io/library/postgres:16-alpine'), ('postgres', '16-alpine'))
        self.assertEqual(suggest.repository_name('ghcr.io/x/y@sha256:abc'), ('y', ''))
        self.assertEqual(suggest.image_major('postgres:17'), 17)
        self.assertEqual(suggest.image_major('pgvector/pgvector:pg16'), 16)
        self.assertEqual(suggest.image_major('postgis/postgis:16-3.4'), 16)
        self.assertIsNone(suggest.image_major('postgres:latest'))
        self.assertIsNone(suggest.image_major('postgres'))
        self.assertEqual(suggest.image_major('docker.io/library/mongo:7', 1, 999), 7)
        self.assertEqual(suggest.common_dash_prefix(['n8n', 'n8n-worker']), 'n8n')
        self.assertEqual(suggest.common_dash_prefix(['headscale', 'headplane']), '')
        self.assertEqual(suggest.quadlet_unit('a.network'), 'a-network.service')

    def test_directory_and_config_rules(self):
        self.assertIsNone(suggest._dir_problem('homeassistant/config-preinstalled'))
        self.assertIsNone(suggest._dir_problem('.config/headscale/headscale'))
        self.assertEqual(suggest._dir_problem('.SSH/keys')[0], 'bind-forbidden')
        self.assertEqual(suggest._dir_problem('.config')[0], 'bind-forbidden')  # it contains .config/systemd
        self.assertEqual(suggest._dir_problem('.cache')[0], 'bind-sensitive')
        self.assertEqual(suggest._dir_problem('.local/state')[0], 'bind-sensitive')
        self.assertEqual(suggest._dir_problem('Documents/app')[0], 'bind-sensitive')
        self.assertEqual(suggest._dir_problem('data/x.woowbk-new-j1')[0], 'bind-path-unsupported')
        self.assertTrue(suggest.config_path_ok('.config/app/a.env', 'app'))
        self.assertTrue(suggest.config_path_ok('.local/share/app/x/y.conf', 'app'))
        self.assertFalse(suggest.config_path_ok('.config/other/a.env', 'app'))
        self.assertFalse(suggest.config_path_ok('.config/systemd/user/a.service', 'systemd'))
        self.assertFalse(suggest.config_path_ok('.config/app/../x', 'app'))


class OwnerSideTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_scan_helper_reads_only_quadlet_files_and_never_follows_links(self):
        home = build_home(self.tmp.name, quadlets={'a.container': '[Container]\nImage=x\n# 中文註解\n'}, layout={})
        qdir = home / '.config/containers/systemd'
        (qdir / 'notes.txt').write_text('not read')
        (qdir / 'bin.container').write_bytes(b'\xff\xfe')
        os.symlink('/etc/passwd', qdir / 'link.container')
        os.mkfifo(qdir / 'fifo.network')
        (qdir / 'sub').mkdir()
        runner = podman.OwnerRunner(OWNER, runner=FakeOwner(), user_lookup=lookup_for(home))
        scan = suggest.scan_quadlet_dir(runner)
        rows = {row['name']: row for row in scan['entries']}
        self.assertEqual(rows['a.container']['text'], '[Container]\nImage=x\n# 中文註解\n')
        self.assertNotIn('text', rows['notes.txt'])
        self.assertEqual(rows['bin.container']['skipped'], 'binary')
        self.assertEqual((rows['link.container']['type'], 'text' in rows['link.container']), ('link', False))
        self.assertEqual(rows['fifo.network']['type'], 'other')
        self.assertEqual(rows['sub']['type'], 'dir')

    def test_missing_or_symlinked_quadlet_directory(self):
        home = Path(self.tmp.name) / 'home'
        home.mkdir()
        result, _ = run_suggest(self.tmp.name, home)
        self.assertEqual((result['state'], result['apps']), ('missing', []))
        self.assertEqual(result['warnings'][0]['code'], 'dir-missing')
        (home / '.config').mkdir()
        (home / 'elsewhere').mkdir()
        os.symlink(home / 'elsewhere', home / '.config/containers')
        result, _ = run_suggest(self.tmp.name, home)
        self.assertEqual(result['state'], 'blocked')

    def test_hostile_helper_answers_are_refused(self):
        bad_answers = [b'not json', b'[]', json.dumps({'state': 'ok', 'entries': [], 'more': -1}).encode(),
                       json.dumps({'state': 'ok', 'entries': [{'name': '../x', 'type': 'file', 'size': 1, 'mode': 0}],
                                   'more': 0}).encode(),
                       json.dumps({'state': 'ok', 'entries': [{'name': 'a.container', 'type': 'dir', 'size': 0,
                                                               'mode': 0, 'text': 'x'}], 'more': 0}).encode(),
                       json.dumps({'state': 'weird', 'entries': [], 'more': 0}).encode(),
                       b'[' * 100000]
        for answer in bad_answers:
            def runner(argv, **_kwargs):
                return podman.Result(0, answer, b'')
            owner = podman.OwnerRunner(OWNER, runner=runner, user_lookup=lookup_for('/home/x'))
            with self.assertRaises(BackupError) as caught:
                suggest.scan_quadlet_dir(owner)
            self.assertEqual(caught.exception.code, 'job-failed')

        def failing(argv, **_kwargs):
            return podman.Result(1, b'', b'boom')
        owner = podman.OwnerRunner(OWNER, runner=failing, user_lookup=lookup_for('/home/x'))
        with self.assertRaises(BackupError):
            suggest.scan_quadlet_dir(owner)

    def test_podman_listing_failures_only_skip_existence_checks(self):
        home = build_home(self.tmp.name, quadlets={'solo.container': container(extra='Secret=solo-key')}, layout={})
        result, _ = run_suggest(self.tmp.name, home, fake=FakeOwner(fail_podman=True))
        self.assertIn('podman-list', [w['code'] for w in result['warnings']])
        self.assertEqual(result['apps'][0]['entry']['secrets'], [{'name': 'solo-key'}])

    def test_owner_validation_and_owner_list(self):
        lookup = lookup_for('/home/x')
        with self.assertRaises(BackupError):
            suggest.suggest('root', paths=Paths(base=Path(self.tmp.name)), user_lookup=lookup)
        with self.assertRaises(BackupError) as caught:
            suggest.suggest('nobody-here', paths=Paths(base=Path(self.tmp.name)), user_lookup=lookup)
        self.assertEqual(caught.exception.code, 'owner-missing')
        linger = Path(self.tmp.name) / 'linger'
        linger.mkdir()
        for name in (OWNER, 'root', 'rootalias', 'ghost', 'Bad'):
            (linger / name).touch()
        app = types.SimpleNamespace(id='shop', owner='otherowner')
        rows = suggest.suggest(None, paths=Paths(base=Path(self.tmp.name)), catalog={'shop': app}, user_lookup=lookup,
                               linger_dir=str(linger))
        self.assertEqual(rows, {'owners': [
            {'name': 'otherowner', 'uid': 1500, 'linger': False, 'catalog_apps': ['shop']},
            {'name': OWNER, 'uid': 1000, 'linger': True, 'catalog_apps': []}]})


if __name__ == '__main__':
    unittest.main()
