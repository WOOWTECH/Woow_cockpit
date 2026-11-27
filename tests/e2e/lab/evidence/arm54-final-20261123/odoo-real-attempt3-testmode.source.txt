"""SUBSTITUTE IMAGES, NOT THE PRODUCT SERVICE. Lane arm54-2 item B, Odoo part (owner decision 3A, 2026-11-23
「決定3 A」): a real RPi5 HA backup of 2026-11-19 (add-ons odoo18ce 0.4.13 + woow-n8n 2.43.6; owner-accepted
provenance = the 2026-11-19 records, like arm54_final_n8n.py) -> the unmodified product Odoo check and convert
(woowbackup.ha_odoo; Odoo has no import guard) -> HA's database woowtest, its filestore and its custom module restored
on .54 under the official odoo:18.0 arm64 image (18.0-20260926) and the official PostgreSQL 17 + pgvector arm64 image
(pgvector 0.8.6-pg17); arm54_final_odoo_build.py pins them.

Target: the Woow_podman_odoo quadlets (c578b8a, evidence odoo-package-c578b8a) rendered with the tenant profile's values
(POSTGRES_USER postgres, secret odoo18-postgres-super-password, volume odoo18-db-data-isolated, custom modules
%h/.local/share/odoo18/addons, odoo.conf from config/odoo.conf.template: db_name odoo, dbfilter ^odoo$, list_db False)
and the two substitute images, translated to podman run. A fresh tenant is emulated first: role odoo (LOGIN CREATEDB
NOSUPERUSER, generated password), database odoo initialised by Odoo itself (-i base, no demo), the target admin's
password replaced by a generated one, and the upgrade-gate marker the product's tenant image writes
(woow_paas_platform.upgrade_done = {digest: <web image id>, core_date: <ODOO_RELEASE>}) written by this harness: the
official image has no upgrade gate (STATED SIMULATION).
Stated deviations: ONE pod with network none instead of odoo18-network (db_host 127.0.0.1 in the rendered odoo.conf),
no published port, no gateway, no health timers (readiness polled here), memory caps, harness-driven unit order; the web
container is stopped while the product check and convert run (they read the live database container, the volumes and
the folder; memory). Default: the product's normal mode (no podman network at all). `--test-mode`: the product's test
mode, whose convert runs `odoo neutralize` in a throwaway Odoo on the product's internal throwaway network (inside the
run's own network namespace; lane rule after the .54 oops: internal networks only); the cold comparison then keeps the
table inventory, the installed modules, the filestore and the counts strict and checks the neutralisation itself (no
active mail server, database.is_neutralized, a new database.uuid) instead of table-by-table equality.
Restore (cold, both containers stopped): the product adapter's own data methods (_recreate_volume for both declared
volumes, _unpack_dir + _swap_dir for the custom modules folder).
Strict comparison: every user table of HA's database woowtest (count + md5 of all rows = ha_import_e2e.FINGERPRINT_SQL)
read from HA's own cluster opened by the product's throwaway PostgreSQL 16, against the restored database odoo before
Odoo starts: identical except ir_config_parameter, whose differing rows must be exactly import-settings keys of
ha_odoo.settings_sql (web.base.url, web.base.url.freeze, woow_paas_platform.upgrade_done/_attempt); installed modules and
versions equal; HA's filestore of woowtest equal file by file (sha256) to filestore/odoo in the restored data volume.
Clients (JSON-RPC in the pod's namespace): HA's admin and ha-probe log in with HA's passwords, the target admin is
refused, the attachment ha-probe.txt reads back (sha1 = its checksum), woow_import_probe installed with its record;
full restart; rollback through _recreate_volume + the folder restore of the cold safety copies (the pre-import tenant is
back: its admin logs in, HA's does not).
Network: the whole run in a network namespace of its own (libc unshare at start; only lo up); no podman network is
created (non-test mode). .54 kernel oops 2026-11-23 21:02: the kernel state is recorded before/after; a new oops, task
in uninterruptible sleep or hung-task report fails the run.
Secrets: HA's Odoo passwords arrive in a 0600 file read and unlinked at start; the target's passwords are generated here
and only reach podman secrets of the private store and Odoo; the session cookies stay in memory; the output, the
recorded podman argv and the product log are scanned for every value before printing."""
import base64
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.error
import urllib.request
from types import MethodType, SimpleNamespace

from arm54_final_runtime import (DRIVER, ENV, LABEL, ROOT, RootfulRunner, kernel_state, private_dir, report,
                                 sha256_file, store_objects)

from woowbackup import habackup, haimport, ha_odoo, podman as podman_mod, tempctr  # noqa: E402
from woowbackup.adapters.quadlet_postgres import QuadletPostgresAdapter  # noqa: E402
from woowbackup.podman import Result  # noqa: E402

LABEL_TEXT = 'substitute images, not the product service (owner decision 3A)'
TEST_MODE = '--test-mode' in sys.argv[2:]
RECORDED = {'8e51e2ed': '546aecf3be5a13642603bd901d49ee4de01313049d4cddf8805ef8c2b973be44',
            '4f5c7337': 'a5fb626820a0947482a394094cd004715eb348fc92cec760c0dc7d9546f420e5'}
CHAIN = json.loads((ROOT / 'input/chain.json').read_text())
ARCHIVE = ROOT / 'input' / CHAIN['archive']
KEY_FILE = ROOT / 'input' / CHAIN['key_file'] if CHAIN.get('key_file') else None
CREDS_FILE = ROOT / 'input/odoo-creds.json'
PACKAGE = ROOT / 'source/tests/e2e/lab/evidence/arm54-final-20261123/odoo-package-c578b8a'
ODOO_IMAGE = 'docker.io/library/odoo:18.0-20260926'
DB_IMAGE = 'docker.io/pgvector/pgvector:0.8.6-pg17'
PG16_IMAGE = 'docker.io/pgvector/pgvector:0.8.6-pg16'
POD = 'a54o-odoo-pod'
DB, WEB = 'odoo18-db', 'odoo18-web'
DBVOL, WEBVOL = 'odoo18-db-data-isolated', 'odoo18-web-data'
VOLUMES = (DBVOL, WEBVOL)
ADDONS_REL = '.local/share/odoo18/addons'
SUPER_SECRET, CONF_SECRET = 'odoo18-postgres-super-password', 'odoo18-odoo-conf'
SECRET_NAMES = (SUPER_SECRET, CONF_SECRET)
HA_DB = 'woowtest'
TARGET_DB = 'odoo'
PROBE_MODULE = 'woow_import_probe'
ATTACHMENT = 'ha-probe.txt'
MEMORY = {DB: '512m', WEB: '1g'}
JOB_CHECK, JOB_PRINT, JOB_CONVERT = ('j20261123T140000Z-a54d0c01', 'j20261123T140000Z-a54d0c02',
                                     'j20261123T140000Z-a54d0c03')
IMPORT_KEYS = frozenset({'web.base.url', 'web.base.url.freeze', 'woow_paas_platform.upgrade_done',
                         'woow_paas_platform.upgrade_attempt'})
BASE_URL = 'http://127.0.0.1:8069'
CLONE_NEWNET = 0x40000000
# ha_import_e2e.FINGERPRINT_SQL (the dev-c strict comparison), one JSON array of its lines.
PRINTS_SQL = (r"SELECT coalesce(json_agg(x ORDER BY x), '[]'::json) FROM (SELECT format('%s.%s %s %s', schemaname, "
              r"relname, (xpath('/row/c/text()', query_to_xml(format('select count(*) as c from %I.%I', schemaname, "
              r"relname), false, true, '')))[1]::text, (xpath('/row/m/text()', query_to_xml(format('select "
              r"md5(coalesce(string_agg(t::text, %L order by t::text), %L)) as m from %I.%I t', E'\n', '', schemaname, "
              r"relname), false, true, '')))[1]::text) AS x FROM pg_stat_user_tables) s")
ICP_SQL = ("SELECT coalesce(json_agg(json_build_array(key, md5(t::text)) ORDER BY key), '[]'::json) "
           "FROM ir_config_parameter t")
MODULES_SQL = ("SELECT coalesce(json_agg(json_build_array(name, latest_version) ORDER BY name), '[]'::json) "
               "FROM ir_module_module WHERE state = 'installed'")
COUNTS_SQL = ("SELECT json_build_object('partners', (SELECT count(*) FROM res_partner), 'users', (SELECT count(*) "
              "FROM res_users), 'attachments', (SELECT count(*) FROM ir_attachment), 'probe_rows', (SELECT count(*) "
              "FROM pg_class WHERE relname = 'woow_import_probe'))")

# Odoo's own neutralisation (image odoo:18.0-20260926, odoo/addons/base/data/neutralize.sql, sha256 9dcfa35d...,
# evidence odoo-vendor-neutralize-18.0-20260926): :4-7 every mail server inactive with smtp_user/smtp_pass NULL,
# :10-11 one active dummy server 'neutralization - disable emails' (smtp_host 'invalid'), :14-22 every cron inactive
# except base.autovacuum_job, :25-28 database.is_neutralized = true, :36-38 database.secret = 'dummysecret'.
NEUTRAL_SQL = ("SELECT json_build_object("
               "'mail_servers_active_real', (SELECT count(*) FROM ir_mail_server WHERE active AND NOT ("
               "name = 'neutralization - disable emails' AND smtp_host = 'invalid')), "
               "'mail_servers_active_dummy', (SELECT count(*) FROM ir_mail_server WHERE active AND "
               "name = 'neutralization - disable emails' AND smtp_host = 'invalid'), "
               "'mail_servers_with_credentials', (SELECT count(*) FROM ir_mail_server WHERE smtp_user IS NOT NULL OR "
               "smtp_pass IS NOT NULL), "
               "'crons_active_but_autovacuum', (SELECT count(*) FROM ir_cron c WHERE c.active AND c.id NOT IN ("
               "SELECT res_id FROM ir_model_data WHERE model = 'ir.cron' AND name = 'autovacuum_job' AND "
               "module = 'base')), "
               "'is_neutralized', (SELECT value FROM ir_config_parameter WHERE key = 'database.is_neutralized'), "
               "'uuid_md5', (SELECT md5(value) FROM ir_config_parameter WHERE key = 'database.uuid'))")
NEUTRAL_KEYS = ('mail_servers_active_real', 'mail_servers_active_dummy', 'mail_servers_with_credentials',
                'crons_active_but_autovacuum', 'is_neutralized')
LIBC = ctypes.CDLL(None, use_errno=True)
NS = {}


def enter_private_netns():
    if LIBC.unshare(CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), 'unshare')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, timeout=30, capture_output=True)
    NS['private'] = os.open('/proc/self/ns/net', os.O_RDONLY)
    NS['private_inode'] = os.stat('/proc/self/ns/net').st_ino


def setns(fd):
    if LIBC.setns(fd, CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), 'setns')


class InPod:
    def __enter__(self):
        setns(NS['pod'])

    def __exit__(self, *exc):
        setns(NS['private'])
        return False


class OdooRunner(RootfulRunner):
    """RootfulRunner + the product's owner-side folder helper (podman.DIR_HELPER), run as root with HOME = this 0700
    workspace (rootful: no user namespace); the product's dir_* methods of OwnerRunner are used unchanged."""
    home = str(ROOT)

    def _dir_argv(self, op, *args):
        return [sys.executable, '-I', '-c', podman_mod.DIR_HELPER, op, *args]

    def run(self, argv, *, input=None, stdout=None, timeout=300, check=True, max_output=None, abort=None):
        argv = [str(a) for a in argv]
        assert argv[:3] == [sys.executable, '-I', '-c'] and argv[3] == podman_mod.DIR_HELPER, 'dir-helper-only'
        self.commands.append(['dir-helper', *argv[4:]])
        stream = hasattr(input, 'read')
        p = subprocess.run(argv, env=dict(ENV, HOME=str(ROOT)), stdin=input if stream else None,
                           input=None if stream else input, stdout=stdout if stdout is not None else subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=min(timeout, 3600))
        out = p.stdout if stdout is None else b''
        if max_output is not None and stdout is None and len(out) > max_output:
            raise RuntimeError('capture-limit-refused')
        result = Result(p.returncode, out, p.stderr[-8192:])
        if check and p.returncode:
            raise RuntimeError('dir-helper-failed')
        return result

    def dir_pack(self, rel_path, *, stdout, timeout=3 * 3600, max_output=None, abort=None):
        podman_mod.validate_rel_path(rel_path)
        result = self.run(self._dir_argv('pack', rel_path), stdout=stdout, timeout=timeout, check=False)
        if result.returncode:
            raise self._dir_failure(result, rel_path, '讀取')


for _name in ('dir_unpack', 'dir_swap', 'dir_revert', 'dir_drop', 'dir_back', 'dir_states', '_dir_failure'):
    setattr(OdooRunner, _name, getattr(podman_mod.OwnerRunner, _name))
for _name in ('_check_token', '_dir_answer'):
    setattr(OdooRunner, _name, staticmethod(getattr(podman_mod.OwnerRunner, _name)))


HOST_NETNS_INODE = os.stat('/proc/self/ns/net').st_ino
enter_private_netns()
r = OdooRunner()
checks = {}
facts = {}
PRIVATE = []
LOGS = []
SPECS = {}
out = {'status': 'failed', 'phase': 'start', 'commercial_acceptance': 'not-complete', 'store_driver': DRIVER,
       'label': LABEL_TEXT, 'mode': 'test' if TEST_MODE else 'normal',
       'runner': 'rootful private store (RootfulRunner + product DIR_HELPER); not production OwnerRunner/rootless',
       'source': {'device': 'RPi5 HAOS 192.168.2.34 (2026-11-19; backups no longer there)', 'slug': CHAIN['slug'],
                  'archive_sha256': RECORDED.get(CHAIN['slug']), 'addons': 'odoo18ce 0.4.13, woow-n8n 2.43.6',
                  'encrypted_backup': KEY_FILE is not None, 'database': HA_DB,
                  'provenance': 'owner-accepted 2026-11-19 records (ha_backup_id = ha-<sha256[:20]>)'},
       'target': {'web_image': ODOO_IMAGE, 'db_image': DB_IMAGE, 'package': 'Woow_podman_odoo c578b8a quadlets',
                  'label': LABEL_TEXT},
       'checks': checks, 'facts': facts}
started = time.monotonic()
KERNEL_BEFORE = kernel_state()
facts['kernel_before'] = dict(KERNEL_BEFORE, modules=len(KERNEL_BEFORE['modules']))


def private(value):
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, bytes) and len(value.strip()) >= 6:
        PRIVATE.append(value)
        PRIVATE.append(value.strip())
    return value


def check(name, ok, **detail):
    checks[name] = bool(ok)
    if detail:
        facts[name] = detail
    return bool(ok)


def must(name, ok, **detail):
    if not check(name, ok, **detail):
        raise AssertionError(name)


def podman(*args, **kw):
    return r.podman(*args, **kw)


def text(*args, **kw):
    return podman(*args, **kw).stdout.decode('utf-8', 'replace')


MEM = []


def sample_mem():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            value = int(line.split()[1]) * 1024
            MEM.append(value)
            assert value > 400 * 1024 ** 2, 'memory-headroom-refused'   # never push .54's originals towards OOM


# ---------------------------------------------------------------- target (package quadlets, rendered)

def render(data, values):
    for key, value in values.items():
        data = data.replace('@@%s@@' % key, value)
    assert '@@' not in data, 'unrendered-placeholder'
    return data


QUADLET_VALUES = {'DB_IMAGE': DB_IMAGE, 'ODOO_IMAGE': ODOO_IMAGE, 'DB_BOOTSTRAP_USER': 'postgres',
                  'DB_BOOTSTRAP_SECRET': SUPER_SECRET, 'DB_VOLUME_NAME': DBVOL, 'ODOO_PUBLISH': '127.0.0.1:18069',
                  'ODOO_PRESTART': '', 'WOOW_ODOO_ADDONS_DIR': '%h/' + ADDONS_REL}


def package_quadlets():
    files = {}
    for name in ('odoo-db.container', 'odoo.container', 'odoo-db-data.volume', 'odoo-web-data.volume',
                 'odoo.network'):
        files[name] = render((PACKAGE / 'quadlet' / name).read_text(), QUADLET_VALUES)
    return files


def odoo_conf(db_password, admin_password):
    """config/odoo.conf.template with the tenant profile's choices; stated deviation: db_host is the pod's loopback."""
    values = {'POSTGRES_PASSWORD': db_password, 'ODOO_ADMIN_PASSWORD': admin_password, 'WOOW_ODOO_LIST_DB': 'False',
              'DB_NAME_LINE': 'db_name = odoo', 'DB_FILTER_LINE': 'dbfilter = ^odoo$', 'WOOW_ODOO_WORKERS': '0',
              'WOOW_ODOO_MAX_CRON_THREADS': '2', 'WOOW_ODOO_DB_MAXCONN': '8', 'WOOW_ODOO_LIMIT_TIME_CPU': '600',
              'WOOW_ODOO_LIMIT_TIME_REAL': '1200', 'WOOW_ODOO_LIMIT_TIME_REAL_CRON': '600',
              'WOOW_ODOO_LIMIT_REQUEST': '65536', 'SMTP_LINES': ''}
    text_ = render((PACKAGE / 'config/odoo.conf.template').read_text(), values)
    lines = ['db_host = 127.0.0.1' if line.strip().startswith('db_host') else line for line in text_.splitlines()]
    return '\n'.join(lines) + '\n'


def volume_name(quadlets, source):
    if source.endswith('.volume'):
        return [v for k, v in tempctr.parse_unit(quadlets[source]).get('Volume', []) if k == 'VolumeName'][-1]
    return source


def container_args(quadlets, name):
    """(container name, `podman run` argv, image ref, quadlet keys not translated, core argv): the core argv (volumes,
    environment, secrets, label, no-new-privileges) is shared with the one-shot tenant initialisation."""
    parsed = tempctr.parse_unit(quadlets[name]).get('Container', [])
    core, used = [], set()
    container_name = image_ref = None
    for key, value in parsed:
        used.add(key)
        if key == 'ContainerName':
            container_name = value
        elif key == 'Image':
            image_ref = value
        elif key == 'Volume':
            source, _sep, rest = value.partition(':')
            source = source.replace('%h', str(ROOT))
            rest = ','.join(opt for opt in rest.split(',') if opt != 'Z')  # .54 has no SELinux
            core += ['--volume', volume_name(quadlets, source) + ':' + rest]
        elif key == 'Environment':
            for item in shlex.split(value):
                core += ['--env', item]
        elif key == 'Secret':
            core += ['--secret', value]
        elif key == 'Label':
            core += ['--label', value]
        elif key == 'NoNewPrivileges' and value == 'true':
            core += ['--security-opt', 'no-new-privileges']
    skipped = sorted(used - {'ContainerName', 'Image', 'Volume', 'Environment', 'Secret', 'Label', 'NoNewPrivileges'})
    args = ['--detach', '--pod', POD, '--label', LABEL, '--pull=never', *core, '--name', container_name,
            '--memory', MEMORY[container_name], '--pids-limit', '1024', image_ref]
    return container_name, args, image_ref, skipped, core


# ---------------------------------------------------------------- the pod's namespace: HTTP / JSON-RPC

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def http(method, path, body=None, cookie=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    if cookie:
        headers['Cookie'] = 'session_id=' + cookie
    request = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
    try:
        with InPod(), OPENER.open(request, timeout=timeout) as response:
            raw = response.read(16 * 1024 * 1024 + 1)
            assert len(raw) <= 16 * 1024 * 1024, 'response-too-large'
            jar = [h for k, h in response.headers.items() if k.lower() == 'set-cookie']
            try:
                return response.status, (json.loads(raw) if raw else None), jar
            except ValueError:
                return response.status, None, jar
    except urllib.error.HTTPError as error:
        return error.code, None, []
    except (urllib.error.URLError, OSError):
        return None, None, []


def rpc(path, params, cookie=None):
    status, body, jar = http('POST', path, {'jsonrpc': '2.0', 'method': 'call', 'params': params}, cookie)
    return status, body if isinstance(body, dict) else {}, jar


def login(user, password):
    """(uid or None, session cookie or None) of /web/session/authenticate on database odoo."""
    _s, body, jar = rpc('/web/session/authenticate', {'db': TARGET_DB, 'login': user, 'password': password})
    result = body.get('result') if isinstance(body.get('result'), dict) else {}
    uid = result.get('uid') if isinstance(result.get('uid'), int) and not body.get('error') else None
    cookie = None
    for header in jar:
        first = header.split(';', 1)[0]
        if first.startswith('session_id='):
            cookie = first[len('session_id='):]
    if cookie:
        private(cookie)
    return uid, (cookie if uid else None)


def call_kw(cookie, model, method, args, kwargs=None):
    _s, body, _jar = rpc('/web/dataset/call_kw', {'model': model, 'method': method, 'args': args,
                                                  'kwargs': kwargs or {}}, cookie)
    return body.get('result'), bool(body.get('error'))


LOG_PATTERNS = ('Traceback', 'ERROR', 'CRITICAL', 'password authentication failed', 'could not connect',
                'No such file or directory', 'Permission denied', 'Killed', 'MemoryError', 'already exists',
                'not installable', 'upgrade', 'Registry')


def diagnose(name, tag):
    p = podman('container', 'inspect', name, '--format',
               '{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}', check=False, timeout=30)
    state = p.stdout.decode('utf-8', 'replace').split() if p.returncode == 0 else []
    logs = podman('logs', '--tail', '300', name, check=False, timeout=60, max_output=4 * 1024 * 1024)
    lines = (logs.stdout + logs.stderr).decode('utf-8', 'replace').splitlines()
    errors = [line.strip()[:200] for line in lines if 'ERROR' in line or 'rror:' in line][-5:]
    facts['diagnosis_' + tag] = {'state': state, 'log_lines': len(lines),
                                 'patterns': sorted(pat for pat in LOG_PATTERNS if any(pat in l for l in lines)),
                                 'error_lines': errors}


def setns_pod():
    infra = text('pod', 'inspect', POD, '--format', '{{.InfraContainerID}}').strip()
    pid = int(text('inspect', infra, '--format', '{{.State.Pid}}').strip())
    NS['pod'] = os.open('/proc/%d/ns/net' % pid, os.O_RDONLY)
    with InPod():
        addrs = subprocess.run(['ip', '-o', 'addr', 'show'], capture_output=True, text=True, timeout=30).stdout
    return sorted({line.split()[1] for line in addrs.split('\n') if line.strip()})


def sql_json(statement, database=TARGET_DB, user='postgres'):
    raw = podman('exec', '-i', DB, 'psql', '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-U', user, '-d', database,
                 '-f', '-', input=statement.encode(), timeout=600, max_output=16 * 1024 * 1024).stdout
    return json.loads(raw.strip() or b'null')


def sql_exec(statement, database='postgres'):
    podman('exec', '-i', DB, 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', database, '-f', '-',
           input=statement.encode(), timeout=600, max_output=1024 * 1024)


def wait_db(seconds=300):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        p = podman('exec', DB, 'pg_isready', '-h', '127.0.0.1', '-p', '5432', '-U', 'postgres', '-d', 'postgres',
                   check=False, timeout=20)
        if p.returncode == 0:
            return True
        time.sleep(2)
    diagnose(DB, 'db')
    raise AssertionError('db-not-ready')


def wait_web(seconds=1200, tag='web'):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if http('GET', '/web/health', timeout=10)[0] == 200:
            return True
        sample_mem()
        p = podman('container', 'inspect', WEB, '--format', '{{.State.Status}}', check=False, timeout=30)
        if p.returncode != 0 or p.stdout.strip() != b'running':
            diagnose(WEB, tag)
            raise AssertionError('odoo-exited-before-ready')
        time.sleep(3)
    diagnose(WEB, tag)
    raise AssertionError('odoo-not-ready')


def start(name, tag=None):
    podman('run', *SPECS[name][1], timeout=300)
    sample_mem()
    if name == DB:
        wait_db()
    else:
        wait_web(tag=tag or 'web')


def stop_all():
    for name in (WEB, DB):
        podman('stop', '--time', '60', name, check=False, timeout=120)
        podman('rm', '--force', name, check=False, timeout=60)


def export_file(volume, path):
    with open(path, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        podman('volume', 'export', volume, stdout=handle, timeout=1800, max_output=4 * 1024 ** 3)
    return path


def pack_dir(path):
    with open(path, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        r.dir_pack(ADDONS_REL, stdout=handle)
    return path


def volume_files(path, prefix):
    """{rel: [size, sha256]} of the regular files below `prefix` in a volume export tar."""
    found = {}
    with tarfile.open(path) as tar:
        for member in tar:
            name = member.name.removeprefix('./')
            if member.isfile() and name.startswith(prefix):
                found[name[len(prefix):]] = [member.size, hashlib.sha256(tar.extractfile(member).read()).hexdigest()]
    return found


def ha_filestore(work):
    """{rel: [size, sha256]} of HA's filestore of woowtest, read from the add-on in the backup itself."""
    prefix = ha_odoo.FILESTORE_PREFIX + '/' + HA_DB
    select = habackup.Select(include=(prefix,), exclude=(), symlinks=(), hardlinks=False)
    found = {}
    with work.open(work.addon_member(ha_odoo.SLUG)) as stream:
        for entry in habackup.iter_entries(stream, select, habackup.Report()):
            if entry.kind == 'file':
                data = entry.read_all(256 * 1024 * 1024)
                found[entry.name[len(prefix) + 1:]] = [len(data), hashlib.sha256(data).hexdigest()]
    return found


def prints_map(lines):
    found = {}
    for line in lines or []:
        table, count, md5 = line.split(' ')
        found[table] = (int(count), md5)
    return found


def compare_cold(source, restored, src_icp, new_icp):
    """Every table identical except ir_config_parameter; its differing rows are import-settings keys only."""
    differ = sorted(t for t in set(source) | set(restored) if source.get(t) != restored.get(t))
    src_rows, new_rows = dict(map(tuple, src_icp)), dict(map(tuple, new_icp))
    keys = sorted(k for k in set(src_rows) | set(new_rows) if src_rows.get(k) != new_rows.get(k))
    return differ, keys


def verify_restored(phase, creds, cold_counts, target_admin_password):
    sample_mem()
    uid, cookie = login('admin', creds['admin_password'])
    must(phase + '_ha_admin_logs_in_with_ha_password', uid is not None and cookie is not None)
    p_uid, p_cookie = login('ha-probe', creds['probe_password'])
    must(phase + '_ha_probe_logs_in_with_ha_password', p_uid is not None and p_cookie is not None)
    t_uid, _c = login('admin', target_admin_password)
    must(phase + '_target_admin_password_refused', t_uid is None)
    rows, error = call_kw(cookie, 'ir.attachment', 'search_read', [[['name', '=', ATTACHMENT]]],
                          {'fields': ['datas', 'checksum', 'file_size']})
    rows = rows if isinstance(rows, list) else []
    blob = base64.b64decode(rows[0]['datas']) if len(rows) == 1 and rows[0].get('datas') else b''
    must(phase + '_attachment_reads_back', not error and len(rows) == 1 and len(blob) == rows[0].get('file_size')
         and hashlib.sha1(blob).hexdigest() == rows[0].get('checksum'), size=len(blob))
    counts = sql_json(COUNTS_SQL)
    probe_records = sql_json('SELECT to_json(count(*)) FROM woow_import_probe') if counts.get('probe_rows') else 0
    modules = dict(map(tuple, sql_json(MODULES_SQL)))
    must(phase + '_counts_and_probe_module', counts['partners'] == cold_counts['partners']
         and counts['users'] == cold_counts['users'] and PROBE_MODULE in modules and probe_records >= 1,
         counts=counts, probe_records=probe_records)
    return modules


try:
    out['phase'] = 'inputs'
    before = store_objects(r)
    facts['store_before_run'] = {k: len(v) for k, v in before.items()}
    must('store_clean_before_run', not before['volumes'] and not before['containers'] and not before['pods'])
    must('archive_sha256_equals_recorded_2026_11_19', CHAIN['slug'] in RECORDED and CHAIN.get('sha256')
         == RECORDED[CHAIN['slug']] and sha256_file(ARCHIVE) == RECORDED[CHAIN['slug']])
    KEYS = None
    if KEY_FILE is not None:
        from woowbackup import hasecuretar
        key_text = haimport.read_key_file(KEY_FILE)
        private(key_text)
        KEYS = hasecuretar.Keys(key_text)
        del key_text
        os.unlink(KEY_FILE)
    raw = json.loads(CREDS_FILE.read_text())
    CREDS_FILE.unlink()
    creds = {'admin_password': raw['admin_password'], 'probe_password': raw['probe_password']}
    for value in creds.values():
        private(value)
    images = text('images', '--format', '{{.Repository}}:{{.Tag}}')
    must('images_present', all(ref in images for ref in (ODOO_IMAGE, DB_IMAGE, PG16_IMAGE)))
    web_info = json.loads(text('image', 'inspect', ODOO_IMAGE))[0]
    web_env = dict(i.split('=', 1) for i in (web_info.get('Config') or {}).get('Env') or [] if '=' in i)
    facts['web_image'] = {'id': web_info['Id'], 'odoo_version': web_env.get('ODOO_VERSION'),
                          'odoo_release': web_env.get('ODOO_RELEASE')}

    out['phase'] = 'target-deploy'
    app = SimpleNamespace(id='odoo', name='Odoo 18', owner='arm54-rootful-private-store',
                          volumes=[{'name': DBVOL}, {'name': WEBVOL}], data_dirs=[{'path': ADDONS_REL}], secrets=[],
                          postgres=[], units=['odoo-db.service', 'odoo.service'],
                          health=[{'type': 'http', 'url': 'http://127.0.0.1:18069/web/health', 'timeout_seconds': 120}])
    adapter = QuadletPostgresAdapter(app, r, LOGS.append)
    quadlets = package_quadlets()
    for name in ('odoo-db.container', 'odoo.container'):
        SPECS[DB if name == 'odoo-db.container' else WEB] = container_args(quadlets, name)
    must('package_images', SPECS[DB][2] == DB_IMAGE and SPECS[WEB][2] == ODOO_IMAGE)
    facts['quadlet_keys_not_translated'] = {name: SPECS[name][3] for name in SPECS}
    passwords = {'super': secrets.token_urlsafe(32), 'odoo_role': secrets.token_urlsafe(32),
                 'master': secrets.token_urlsafe(32), 'target_admin': 'A1' + secrets.token_urlsafe(18)}
    for value in passwords.values():
        private(value)
    podman('secret', 'create', '--label', LABEL, SUPER_SECRET, '-', input=passwords['super'].encode(), timeout=60)
    podman('secret', 'create', '--label', LABEL, CONF_SECRET, '-',
           input=odoo_conf(passwords['odoo_role'], passwords['master']).encode(), timeout=60)
    for volume in VOLUMES:
        podman('volume', 'create', '--label', LABEL, volume, timeout=60)
    addons = ROOT / ADDONS_REL
    addons.mkdir(parents=True, exist_ok=True)
    for path in (ROOT / '.local', ROOT / '.local/share', ROOT / '.local/share/odoo18', addons):
        os.chmod(path, 0o755)   # Odoo (uid 100 in the container) reads the folder: o+rX like install.sh checks
    podman('pod', 'create', '--name', POD, '--label', LABEL, '--network', 'none', timeout=120)
    podman('pod', 'start', POD, timeout=120)
    infra = text('pod', 'inspect', POD, '--format', '{{.InfraContainerID}}').strip()
    must('pod_network_none', text('inspect', infra, '--format', '{{.HostConfig.NetworkMode}}').strip() == 'none')
    facts['netns_addressed'] = setns_pod()
    must('pod_netns_only_lo_configured', facts['netns_addressed'] == ['lo'])
    must('run_in_its_own_netns_not_the_hosts', NS['private_inode'] != HOST_NETNS_INODE
         and os.stat('/proc/self/ns/net').st_ino == NS['private_inode'])
    start(DB)
    # Fresh tenant (emulated): role odoo with a generated password (SQL on stdin, never in argv), database odoo
    # initialised by Odoo itself, then the target admin's own password, then the upgrade-gate marker.
    sql_exec("CREATE ROLE odoo LOGIN NOSUPERUSER CREATEDB NOCREATEROLE PASSWORD '%s';" % passwords['odoo_role'])
    t0 = time.monotonic()
    init = podman('run', '--rm', '--pod', POD, '--label', LABEL, '--pull=never', *SPECS[WEB][4], '--memory',
                  MEMORY[WEB], '--pids-limit', '1024', ODOO_IMAGE, 'odoo', '-d', TARGET_DB, '-i', 'base',
                  '--without-demo=all', '--stop-after-init', '--no-http', check=False, timeout=1800,
                  max_output=8 * 1024 * 1024)
    facts['tenant_init'] = {'exit': init.returncode, 'seconds': round(time.monotonic() - t0, 1)}
    must('tenant_database_initialised_by_odoo', init.returncode == 0)
    marker = json.dumps({'digest': adapter.image_inspect(ODOO_IMAGE)['id'], 'core_date': web_env.get('ODOO_RELEASE') or ODOO_IMAGE.rsplit('-', 1)[1]},
                        separators=(',', ':'))
    sql_exec("INSERT INTO ir_config_parameter (key, value, create_uid, create_date, write_uid, write_date) VALUES "
             "('woow_paas_platform.upgrade_done', '%s', 1, now() AT TIME ZONE 'UTC', 1, now() AT TIME ZONE 'UTC');"
             % marker, TARGET_DB)
    start(WEB, 'tenant')
    uid, cookie = login('admin', 'admin')
    must('fresh_tenant_admin_default_login', uid is not None)
    changed, error = call_kw(cookie, 'res.users', 'change_password', ['admin', passwords['target_admin']])
    must('target_admin_password_replaced', changed and not error)
    t_uid, _c = login('admin', passwords['target_admin'])
    must('target_admin_login_before_import', t_uid is not None)
    ha_uid, _c = login('admin', creds['admin_password'])
    must('ha_admin_password_unknown_before_import', ha_uid is None)
    target_counts = sql_json(COUNTS_SQL)
    facts['target_before_import'] = target_counts
    podman('stop', '--time', '60', WEB, timeout=120)   # stated: memory while the product reads and converts
    podman('rm', '--force', WEB, timeout=60)

    out['phase'] = 'product-check'
    staging = private_dir('work', 'staging')
    temps = {'current': tempctr.TempObjects(r, JOB_CHECK, memory='1g', pids=1024, cpus='1')}
    opened = habackup.open_backup(ARCHIVE)
    work = SimpleNamespace(ha=opened, keys=KEYS, _addons={}, staging=staging,
                           guard=haimport.SpaceGuard([staging, ROOT], 12 * 1024 ** 3 + 128 * 1024 ** 2),
                           quadlets=lambda a: quadlets, runner=lambda a: r, adapter=lambda a: adapter,
                           temp=lambda a: temps['current'], abort=lambda: None, checkpoint=sample_mem,
                           phase=lambda p: None, log=LOGS.append)
    for method in ('addon_member', 'addon_info', 'open', 'share_member'):
        setattr(work, method, MethodType(getattr(haimport.Work, method), work))
    try:
        found = ha_odoo.check(work, app)
    finally:
        left = temps['current'].cleanup()
    must('check_temp_objects_removed', not left)
    blockers = ha_odoo.check_blockers(found)
    databases = {db['name']: db for db in found['odoo']['databases']}
    facts['product_check'] = {'target_version': found.get('target_version'), 'blockers': len(blockers),
                              'databases': {n: {k: db.get(k) for k in ('ok', 'partners', 'users', 'attachments',
                                                                       'modules', 'filestore_files',
                                                                       'filestore_bytes', 'custom_modules')}
                                            for n, db in databases.items()},
                              'db_blockers': {n: db.get('blockers') for n, db in databases.items()},
                              'warnings': {n: len(db.get('warnings') or []) for n, db in databases.items()}}
    must('product_check_no_blocker', blockers == [])
    must('product_check_woowtest_can_move', databases.get(HA_DB, {}).get('ok') is True
         and not databases[HA_DB].get('blockers'))
    facts['target_release'] = {'check_target_version': found.get('target_version'),
                               'image_odoo_release': web_env.get('ODOO_RELEASE')}

    out['phase'] = 'source-prints'
    temps['current'] = tempctr.TempObjects(r, JOB_PRINT, memory='768m', pids=1024, cpus='1')
    try:
        image16 = ha_odoo.pick_pg16(work, app)
        pg_ids = temps['current'].user_ids('ids-pg', image16, 'postgres')
        src, _candidates = ha_odoo.member_pass(work, app, temps['current'], pg_ids)
        cluster = ha_odoo.start_ha_cluster(work, temps['current'], image16)
        source_prints = prints_map(cluster.query_json(PRINTS_SQL, HA_DB))
        source_icp = cluster.query_json(ICP_SQL, HA_DB)
        source_modules = dict(map(tuple, cluster.query_json(MODULES_SQL, HA_DB)))
        source_counts = cluster.query_json(COUNTS_SQL, HA_DB)
        source_neutral = cluster.query_json(NEUTRAL_SQL, HA_DB)
    finally:
        left = temps['current'].cleanup()
    must('source_temp_objects_removed', not left)
    facts['source'] = {'pg16_image': image16, 'pg_version': src.pg_version, 'tables': len(source_prints),
                       'modules_installed': len(source_modules), 'counts': source_counts}
    must('source_matches_check', source_counts['partners'] == databases[HA_DB]['partners']
         and len(source_modules) == databases[HA_DB]['modules'])
    ha_files = ha_filestore(work)
    facts['ha_filestore'] = {'files': len(ha_files), 'bytes': sum(v[0] for v in ha_files.values()),
                             'check_files': databases[HA_DB].get('filestore_files'),
                             'check_bytes': databases[HA_DB].get('filestore_bytes')}
    must('ha_filestore_read_from_the_backup', len(ha_files) >= 1)

    out['phase'] = 'product-convert'
    shutil.rmtree(staging / 'odoo-work', ignore_errors=True)
    temps['current'] = tempctr.TempObjects(r, JOB_CONVERT, memory='1g', pids=1024, cpus='1')
    converted_dir = private_dir('work', 'converted')
    try:
        converted = ha_odoo.convert(work, app, HA_DB, TEST_MODE, converted_dir)
    finally:
        left = temps['current'].cleanup()
        opened.close()
        opened = None
    must('convert_temp_objects_removed', not left)
    must('convert_items', sorted(converted['volumes']) == sorted(VOLUMES) and list(converted['dirs']) == [ADDONS_REL]
         and converted.get('database') == HA_DB
         and [m.get('name') for m in converted.get('custom_modules') or []] == [PROBE_MODULE])
    facts['converted'] = {'counts': converted.get('counts'), 'volume_bytes': {
        k: os.path.getsize(v) for k, v in converted['volumes'].items()},
        'dir_bytes': os.path.getsize(converted['dirs'][ADDONS_REL])}

    out['phase'] = 'restore'
    stop_all()
    safety = private_dir('work', 'safety')
    for volume in VOLUMES:   # harness rollback copies (cold: both containers stopped)
        export_file(volume, safety / (volume + '.tar'))
    pack_dir(safety / 'addons.tar')
    for volume in VOLUMES:
        adapter._recreate_volume(volume, converted['volumes'][volume])
    adapter._unpack_dir(ADDONS_REL, converted['dirs'][ADDONS_REL], rollback=False)
    adapter._swap_dir(ADDONS_REL, fresh=False, rollback=False)
    must('custom_module_in_the_folder', (ROOT / ADDONS_REL / PROBE_MODULE / '__manifest__.py').is_file())
    start(DB)
    restored_prints = prints_map(sql_json(PRINTS_SQL))
    restored_icp = sql_json(ICP_SQL)
    differ, keys = compare_cold(source_prints, restored_prints, source_icp, restored_icp)
    facts['cold_compare'] = {'tables_source': len(source_prints), 'tables_restored': len(restored_prints),
                             'identical': sum(1 for t in source_prints if restored_prints.get(t) == source_prints[t]),
                             'differing_tables': differ, 'differing_config_keys': keys}
    must('cold_same_table_inventory', set(source_prints) == set(restored_prints))
    if not TEST_MODE:
        must('cold_every_table_identical_but_import_settings', differ in ([], ['public.ir_config_parameter']))
        must('cold_config_rows_differ_only_in_import_settings', set(keys) <= IMPORT_KEYS
             and 'woow_paas_platform.upgrade_done' in keys)
    else:
        neutral = sql_json(NEUTRAL_SQL)
        facts['test_mode_state'] = {'source': {k: source_neutral[k] for k in NEUTRAL_KEYS},
                                    'restored': {k: neutral[k] for k in NEUTRAL_KEYS}}
        must('test_mode_no_real_mail_server_active', source_neutral['mail_servers_active_real'] >= 1
             and neutral['mail_servers_active_real'] == 0 and neutral['mail_servers_active_dummy'] == 1
             and neutral['mail_servers_with_credentials'] == 0)
        must('test_mode_crons_inactive_but_autovacuum', source_neutral['crons_active_but_autovacuum'] >= 1
             and neutral['crons_active_but_autovacuum'] == 0)
        must('test_mode_marks_database_neutralised', str(neutral['is_neutralized']).lower() in ('true', 't', '1'))
        must('test_mode_new_database_uuid', neutral['uuid_md5'] is not None
             and neutral['uuid_md5'] != source_neutral['uuid_md5'])
        must('test_mode_import_settings_present', 'woow_paas_platform.upgrade_done' in keys)
    restored_modules = dict(map(tuple, sql_json(MODULES_SQL)))
    must('cold_installed_modules_and_versions_equal_ha', restored_modules == source_modules,
         modules=len(restored_modules))
    restored_files = volume_files(export_file(WEBVOL, private_dir('work', 'cold') / 'web.tar'), 'filestore/odoo/')
    must('filestore_equal_to_ha_file_by_file', restored_files == ha_files, files=len(restored_files))
    start(WEB, 'installed')
    modules_live = verify_restored('installed', creds, source_counts, passwords['target_admin'])
    must('installed_modules_after_start_equal_ha', modules_live == source_modules)

    out['phase'] = 'restart'
    stop_all()
    start(DB)
    start(WEB, 'restarted')
    verify_restored('restarted', creds, source_counts, passwords['target_admin'])

    out['phase'] = 'rollback'
    stop_all()
    for volume in VOLUMES:
        adapter._recreate_volume(volume, safety / (volume + '.tar'))
    adapter._unpack_dir(ADDONS_REL, safety / 'addons.tar', rollback=True)
    adapter._swap_dir(ADDONS_REL, fresh=False, rollback=True)
    start(DB)
    start(WEB, 'rolled-back')
    t_uid, _c = login('admin', passwords['target_admin'])
    ha_uid, _c = login('admin', creds['admin_password'])
    rows = sql_json(COUNTS_SQL)
    must('rollback_restores_pre_import_tenant', t_uid is not None and ha_uid is None
         and (rows['partners'], rows['users']) == (target_counts['partners'], target_counts['users'])
         and not (ROOT / ADDONS_REL / PROBE_MODULE).exists(), rows=rows)
    stop_all()
    out.update(status='passed' if all(checks.values()) else 'partial', phase='done',
               false_checks=sorted(k for k, v in checks.items() if not v))
except Exception as error:  # noqa: BLE001
    out['error_code'] = type(error).__name__
    out['error_where'] = [[Path(f.filename).name, f.lineno, f.name]
                          for f in traceback.extract_tb(error.__traceback__)[-4:]]
    if isinstance(error, (AssertionError, KeyError)):
        out['failed_check'] = str(error)[:80]
    if hasattr(error, 'code'):
        out['product_error_code'] = error.code
finally:
    cleanup = {}
    for staged in (KEY_FILE, CREDS_FILE):
        if staged is not None and staged.exists():
            cleanup['staged_file_removed_late'] = True
            staged.unlink()
    if 'opened' in dir() and opened is not None:
        opened.close()
    if 'temps' in dir():
        cleanup['temp_left'] = len(temps['current'].cleanup() or [])
    r.podman('pod', 'rm', '--force', POD, check=False, timeout=180)
    for volume in VOLUMES:
        r.podman('volume', 'rm', '--force', volume, check=False, timeout=60)
    for name in SECRET_NAMES:
        r.podman('secret', 'rm', name, check=False, timeout=60)
    shutil.rmtree(ROOT / 'work', ignore_errors=True)
    shutil.rmtree(ROOT / '.local', ignore_errors=True)
    objects = store_objects(r)
    baseline_modules = set(json.loads((ROOT / 'baseline.json').read_text()).get('modules') or [])
    lsmod = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=30).stdout.splitlines()[1:]
    cleanup['modules_left'] = sorted({line.split()[0] for line in lsmod if line.strip()} - baseline_modules)
    after = kernel_state()
    cleanup['kernel_after'] = dict(after, modules=len(after['modules']))
    cleanup['no_new_oops'] = after['oops_count'] == KERNEL_BEFORE['oops_count']
    cleanup['no_new_d_state_task'] = after['d_state'] <= KERNEL_BEFORE['d_state']
    cleanup['no_new_hung_task_report'] = after['hung_task_reports'] == KERNEL_BEFORE['hung_task_reports']
    cleanup.update(store_after={k: len(v) for k, v in objects.items()}, work_removed=not (ROOT / 'work').exists(),
                   no_lab_containers=not objects['containers'], no_lab_pods=not objects['pods'],
                   no_lab_volumes=not objects['volumes'], no_lab_secrets=not objects['secrets'],
                   creds_file_removed=not CREDS_FILE.exists(), workspace_mode_restored=(
                       ROOT.stat().st_mode & 0o777) == 0o700,
                   unlock_file_removed=KEY_FILE is None or not KEY_FILE.exists())
    out['cleanup'] = cleanup
    if out['status'] == 'passed' and not all(cleanup[k] for k in (
            'no_lab_containers', 'no_lab_pods', 'no_lab_volumes', 'no_lab_secrets', 'creds_file_removed',
            'unlock_file_removed', 'workspace_mode_restored', 'no_new_oops', 'no_new_d_state_task',
            'no_new_hung_task_report')):
        out['status'] = 'failed'
        out['failed_check'] = 'cleanup'
    out['elapsed_seconds'] = round(time.monotonic() - started, 1)
    out['podman_commands'] = len(r.commands)
    out['free_bytes_min'] = min(r.free) if r.free else None
    out['mem_available_min'] = min(MEM) if MEM else None
    out['product_log_lines'] = len(LOGS)
    needles = {v for v in PRIVATE if len(v) >= 6}
    out['product_log_secret_hits'] = sum(line.encode().count(v) for line in LOGS for v in needles)
    encoded = json.dumps(out, sort_keys=True, ensure_ascii=False).encode()
    commands = json.dumps(r.commands).encode()
    if any(v in encoded or json.dumps(v.decode('latin-1'))[1:-1].encode() in encoded for v in needles) or \
            any(v in commands for v in needles):
        out = {'status': 'failed', 'failed_check': 'secret_in_output_suppressed', 'commercial_acceptance': 'not-complete',
               'label': LABEL_TEXT}
    report(ROOT / 'odoo-result.json', out)
    print(json.dumps(out, sort_keys=True))
    sys.exit(0 if out['status'] == 'passed' else 1)
