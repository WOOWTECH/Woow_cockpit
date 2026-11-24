"""Item C/D, EMQX (lane arm54-2): a REAL B1 HA backup (HA's EMQX add-on stopped when it was made) through the FINAL
product HA EMQX import and the PRODUCTION engine on .54 into the test owner's rootless EMQX 5.8.9 (arm64, product
package with its entrance) under his user systemd.

usage (through arm54_final_control.py run): arm54_final_owner_emqx.py <workspace> b1-arm-cold|b1-x86-cold

One attempt = (1) remove what an earlier attempt left (units, quadlets, containers, volumes, secrets; the engine
directory is moved aside), (2) deploy the target from the Woow EMQX package ea5886c (emqx.container, emqx-entrance.container,
network, volumes, base.hocon, acl.conf, entrance.conf, emqx.env as install.sh renders them) as the owner (systemctl
--user), (3) the engine: key-init, catalog-suggest + catalog-install, upload-begin/-finish, ha-check-start,
ha-convert-start, restore-start, job-status, list through cli.main as root, every job executed by `run-job <id>` in its
own process with the production dependencies (OwnerRunner; nothing is injected), (4) decision C on the product default
target (authorization = the ACL file only): the check names exactly the owner's text, the conversion is refused, the
broker is unchanged; then the customer's step from that text (Dashboard API); check, conversion, restore with the
product's own readback; the dev-d product harness's own probe (unchanged, run as the owner like on dev-d) and its own
acceptance function (emqx_product_real_ha.PROBE / evaluate_imported, read from the source, never executed as a module);
restart; FIRST-IMPORT rollbacks before any successful restore (a restore whose broker start fails once, and one whose
cluster.hocon is tampered with right before the start): what comes back must be this device's own state from before the import,
every volume rebuilt twice by the job's log (asked for by the EMQX lane's verifier: a rollback that starts from the imported
state cannot tell "rolled back" from "nothing changed"); an AUTOMATIC rollback (a restore whose broker start fails once), a READBACK rollback (one line appended to
the restored cluster.hocon right before the start: the restore must name 設定（log） and roll back by itself), the MANUAL
rollback (restore-start of the first restore's own safety backup; state digest equal to before the import).

Stated deviations: the owner's user manager runs in a private network namespace (lo only) with a memory cap
(arm54_final_owner_common); ports 127.0.0.1 only, inside that namespace; generated test secrets instead of the
installer's (same bootstrap CSV form). The candidate gets this device's EnvironmentFile with podman --env-file
(security fix abff1a0): every throwaway run command the engine starts is watched in /proc while it runs (names and
option words only), the run records whether the candidate used --env-file and that no value of that file was on a command
line. Modules the kernel loads on demand for the package's bridge network are reported, never loaded or unloaded here.
Secrets: HA's passwords, API key and the HA backup key arrive in 0600 files read and unlinked at start; the target's
credentials are generated here and only reach the owner's podman secrets; the output is scanned for every value before
it is printed and replaced by a fixed failure on a hit."""
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid

from arm54_final_runtime import ROOT, kernel_state, private_dir, report, sha256_file
import arm54_final_owner_common as oc
from arm54_final_emqx_lib import bootstrap_csv, dev_d_probe_program, function_from, string_constant

from woowbackup import cli, haimport, ha_emqx, suggest  # noqa: E402
from woowbackup.paths import Paths  # noqa: E402

KIND = sys.argv[2] if len(sys.argv) > 2 else ''
assert KIND in ('b1-arm-cold', 'b1-x86-cold'), 'kind-refused'
RECORDED = {'b6cbc980': 'b6eb257cc5790bee30500f929d51ade66bfa8354dbe5bb61ba7c4bc08582f664',
            '5fb6f348': '0a53e93888209316040af505484bba3ee3891c2ad2df7ae689bc0d4fd02690f9'}
CHAIN = json.loads((ROOT / 'input' / ('chain-%s.json' % KIND)).read_text())
EXPECT = json.loads((ROOT / 'input' / ('emqx-expect-%s.json' % KIND)).read_text())
ARCHIVE = ROOT / 'input' / CHAIN['archive']
KEY_FILE = ROOT / 'input' / CHAIN['key_file']
CREDS_FILE = ROOT / 'input/emqx-creds.json'
PATHS = Paths(base=ROOT / 'engine')
LAB_SOURCE = ROOT / 'source/tests/e2e/lab'
PACKAGE = LAB_SOURCE / 'evidence/arm54-final-20261123/emqx-package-ea5886c'
IMAGES = {'emqx': 'docker.io/emqx/emqx:5.8.9@sha256:35b46f7aa7a0d51f3959e4344221ac5ec7f948b03e43099286b6c40a07bb393b',
          'entrance': 'docker.io/nginxinc/nginx-unprivileged:1.27-alpine'
                      '@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0'}
BROKER, ENTRANCE = 'woow-emqx', 'woow-emqx-entrance'
CONTAINERS = (BROKER, ENTRANCE)
UNITS = ('emqx.service', 'emqx-entrance.service')
RESOURCE_UNITS = ('emqx-data-volume.service', 'emqx-log-volume.service', 'emqx-network.service')
VOLUMES = ('woow_emqx_data', 'woow_emqx_log')
NETWORK = 'woow_emqx_network'
SECRET_NAMES = ('woow-emqx-dashboard-password', 'woow-emqx-node-cookie', 'woow-emqx-mqtt-password',
                'woow-emqx-mqtt-bootstrap')
MQTT_USER = 'woow'
PORTS = {'MQTT': 1883, 'MQTTS': 8883, 'WS': 8083, 'WSS': 8084, 'DASHBOARD': 18083}
QUADLET_DIR, CONFIG_DIR, USER_UNIT_DIR = '.config/containers/systemd', '.config/emqx', '.config/systemd/user'
DROPDIR = USER_UNIT_DIR + '/emqx.service.d'
FAIL_DROPIN, FAIL_MARKER = DROPDIR + '/50-a54-fail-once.conf', '.config/a54-emqx-fail-once'
TAMPER_DROPIN, TAMPER_SCRIPT = DROPDIR + '/51-a54-tamper-once.conf', '.config/a54-emqx-tamper.sh'
TAMPER_MARKER = '.config/a54-emqx-tamper-once'
# emqx_product_real_ha.TAMPER with this run's marker name (EMQX_LOG__CONSOLE__LEVEL of emqx.env wins over cluster.hocon,
# so the formatter is the changed line, as on dev-d).
TAMPER = ('#!/bin/sh\nm="$HOME/%s"\n[ -f "$m" ] || exit 0\nrm -f "$m"\n'
          'd=$(podman volume inspect woow_emqx_data --format "{{.Mountpoint}}") || exit 0\n'
          'podman unshare sh -c "printf \'\\nlog.console.formatter = json\\n\' >> \'$d/configs/cluster.hocon\'"\n'
          'exit 0\n') % TAMPER_MARKER
READBACK_LOG = 'EMQX 還原後核對一致'
DASHBOARD = 'http://127.0.0.1:%d' % PORTS['DASHBOARD']
ENGINE_HEADERS = {'User-Agent': 'woowtech-cockpit-backup', 'Accept': 'application/json'}
DIGEST_KEYS = ('mqtt_users', 'authenticators', 'authz_settings', 'authz_sources', 'file_acl_readback_equal', 'acl_api',
               'retained_api', 'rules', 'connectors', 'actions', 'banned', 'dashboard_users', 'api_keys',
               'native_counts', 'config_sha256')  # emqx_product_real_ha.DIGEST_KEYS (asserted equal below)
RUN_JOB = '''import sys
for path in (%r, %r):
    sys.path.insert(0, path)
from woowbackup import cli
from woowbackup.paths import Paths
sys.exit(cli.main(['run-job', sys.argv[1]], paths=Paths(base=%r)))
''' % (str(ROOT / 'pydeps'), str(ROOT / 'source/backup-engine'), str(ROOT / 'engine'))
FRONTEND = 'http://127.0.0.1:8123/manifest.json'
MEM_FLOOR = 250 * 1024 ** 2

checks, facts, jobs_seen = {}, {}, {}
PRIVATE = []
out = {'status': 'failed', 'phase': 'start', 'commercial_acceptance': 'not-complete', 'owner': oc.OWNER,
       'runner': 'production OwnerRunner (runuser + rootless Podman + systemd --user) via the root CLI and run-job',
       'product': 'final HA EMQX import (feat/ha-import-emqx-product-20261124 merged into this branch)',
       'source': {'slug': CHAIN['slug'], 'archive_sha256': RECORDED.get(CHAIN['slug']), 'machine': EXPECT['machine'],
                  'addon': 'woow-emqx 5.9.1 (EMQX 5.8.9), stopped when the backup was made (cold)',
                  'encrypted_backup': True, 'provenance': EXPECT['provenance']},
       'checks': checks, 'facts': facts, 'jobs': jobs_seen}
started = time.monotonic()
launched = []
WORK = private_dir('work', 'owner-emqx-%d' % int(time.time()))
KERNEL_BEFORE = kernel_state()
facts['kernel_before'] = dict(KERNEL_BEFORE, modules=len(KERNEL_BEFORE['modules']))


def private(value):
    if isinstance(value, str) and len(value.strip()) >= 6:
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


class Watch(threading.Thread):
    """In .54's own network namespace: MemAvailable every 5 s and .54's own Home Assistant frontend every 15 s (as the
    n8n run); every 0.2 s the option words of a running `podman run` of the conversion's candidate (emqx-new): whether
    --env-file and which --env NAMES are on its command line (names only, a value is never kept)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.stop = threading.Event()
        self.min_mem, self.samples, self.low, self.tripped = None, 0, 0, False
        self.frontend = {'every_seconds': 15, 'ok': 0, 'failed': 0, 'max_latency_seconds': 0.0, 'over_5s': 0}
        self.candidate = {'seen': 0, 'env_file_options': 0, 'env_names': set(), 'env_file_names': set(),
                          'value_hits': 0}
        self.env_values = []

    def look(self):
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue
            try:
                argv = Path('/proc', entry, 'cmdline').read_bytes().split(b'\0')
            except OSError:
                continue
            if b'run' not in argv or not any(a.endswith(b'-emqx-new') for a in argv):
                continue
            self.candidate['seen'] += 1
            for i, word in enumerate(argv[:-1]):
                if word == b'--env-file':
                    self.candidate['env_file_options'] += 1
                    self.candidate['env_file_names'].add(argv[i + 1].rsplit(b'/', 1)[-1].decode('utf-8', 'replace'))
                elif word == b'--env':
                    self.candidate['env_names'].add(argv[i + 1].split(b'=', 1)[0].decode('utf-8', 'replace'))
            text = b'\0'.join(argv)
            self.candidate['value_hits'] += sum(text.count(value) for value in self.env_values)

    def run(self):
        last_mem = last_front = 0.0
        while not self.stop.is_set():
            now = time.monotonic()
            self.look()
            if now - last_mem >= 5:
                last_mem = now
                for line in Path('/proc/meminfo').read_text().splitlines():
                    if line.startswith('MemAvailable:'):
                        value = int(line.split()[1]) * 1024
                        self.min_mem = value if self.min_mem is None else min(self.min_mem, value)
                        self.low = self.low + 1 if value < MEM_FLOOR else 0
                self.samples += 1
                if self.low >= 3 and not self.tripped:
                    self.tripped = True
                    oc.systemctl('stop', *UNITS, timeout=300, check=False)
            if now - last_front >= 15:
                last_front = now
                t0 = time.monotonic()
                try:
                    with urllib.request.urlopen(FRONTEND, timeout=20) as response:
                        ok = response.status == 200
                except Exception:  # noqa: BLE001 - informational sample
                    ok = False
                took = time.monotonic() - t0
                self.frontend['ok' if ok else 'failed'] += 1
                self.frontend['max_latency_seconds'] = round(max(self.frontend['max_latency_seconds'], took), 3)
                self.frontend['over_5s'] += took > 5
            self.stop.wait(0.2)


def rid(tag):
    return 'a54e-%s-%s' % (tag, uuid.uuid4().hex[:12])


def call(command, request=None):
    buf = io.StringIO()
    svc = cli.Services(PATHS, launcher=launched.append, unit_active=lambda unit: False)
    code = cli.main([command], stdin=io.StringIO(json.dumps(request or {})), stdout=buf, services=svc)
    reply = json.loads(buf.getvalue().strip().splitlines()[-1])
    if code != 0 or not reply.get('ok'):
        err = reply.get('error') or {}
        facts['cli_refusal'] = {'command': command, 'code': err.get('code'),
                                'message': oc.LONG_TOKEN.sub('<masked>', str(err.get('message')))[:400]}
        raise RuntimeError('cli-refused')
    return reply


def run_job(label, start_command, request, timeout, expect='succeeded'):
    before = len(launched)
    job_id = call(start_command, request)['job_id']
    must('%s_launched_once' % label, launched[before:] == [job_id])
    t0 = time.monotonic()
    p = subprocess.run(['/usr/bin/python3', '-I', '-c', RUN_JOB, job_id], capture_output=True, timeout=timeout,
                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    status = call('job-status', {'job_id': job_id})
    job, log = status['job'], status.get('log') or []
    lines = [str(l) for l in (log if isinstance(log, list) else str(log).splitlines())]
    jobs_seen[label] = {'job_id': job_id, 'type': job.get('type'), 'state': job.get('state'),
                        'run_job_exit': p.returncode, 'seconds': round(time.monotonic() - t0, 1),
                        'error': (job.get('error') or {}).get('code'),
                        'log_tail': [oc.safe_tail(l, 200) for l in lines[-8:]]}
    must('%s_%s' % (label, expect.replace('-', '_')), job.get('state') == expect, state=job.get('state'),
         error=jobs_seen[label]['error'], message=oc.safe_tail((job.get('error') or {}).get('message'), 300))
    return job, lines


def verification_view(result):
    return [(e.get('app'), e.get('match'), [(c.get('id'), c.get('match')) for c in e.get('checks') or []])
            for e in result.get('verification') or [] if isinstance(e, dict)]


def http_code(url, timeout=10, headers=None):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (urllib.error.URLError, OSError):
        return None


def active(unit):
    return oc.systemctl('is-active', unit, check=False).stdout.decode().strip()


def restarts(unit):
    text = oc.systemctl('show', '-p', 'NRestarts', '--value', unit, check=False).stdout.decode().strip()
    return int(text) if text.isdigit() else 0


def wait_running(seconds=600):
    before = {unit: restarts(unit) for unit in UNITS}
    deadline = time.monotonic() + seconds
    states, again = {}, {}
    while time.monotonic() < deadline:
        states = {unit: active(unit) for unit in UNITS}
        if all(v == 'active' for v in states.values()):
            p = oc.podman('exec', BROKER, 'emqx', 'ctl', 'status', check=False, timeout=60)
            if p.returncode == 0 and b'is started' in (p.stdout or b'') and http_code(DASHBOARD + '/healthz') == 200:
                return
        again = {unit: restarts(unit) - before[unit] for unit in UNITS}
        if max(again.values()) > 6:
            break
        time.sleep(4)
    facts['start_states'], facts['start_restarts'] = states, again
    raise AssertionError('broker-not-running')


def start_stack():
    for unit in UNITS:
        oc.systemctl('start', unit, timeout=700, check=False)
    wait_running()


def stop_stack():
    oc.systemctl('stop', *reversed(UNITS), timeout=300, check=False)


def remove_previous():
    home = Path(oc.account().pw_dir)
    qdir = home / QUADLET_DIR
    left = sorted(p.name for p in qdir.iterdir() if p.name.startswith('emqx')) if qdir.is_dir() else []
    facts['previous_attempt_left'] = {'quadlets': len(left), 'engine_dir': (ROOT / 'engine').exists()}
    if left:
        stop_stack()
        oc.systemctl('stop', *RESOURCE_UNITS, timeout=200, check=False)
        oc.owner(['/bin/rm', '-f', *[str(qdir / name) for name in left]], timeout=60)
    oc.owner(['/bin/rm', '-rf', *[str(home / rel) for rel in (CONFIG_DIR, DROPDIR, FAIL_MARKER, TAMPER_MARKER,
                                                             TAMPER_SCRIPT)]], timeout=60)
    oc.systemctl('daemon-reload', timeout=120)
    for name in reversed(CONTAINERS):
        oc.podman('rm', '--force', '--volumes', '--time', '10', name, timeout=120, check=False)
    for volume in VOLUMES:
        oc.podman('volume', 'rm', '--force', volume, timeout=60, check=False)
    for name in SECRET_NAMES:
        oc.podman('secret', 'rm', name, timeout=60, check=False)
    oc.podman('network', 'rm', '--force', NETWORK, timeout=60, check=False)
    if (ROOT / 'engine').exists():
        n = 1
        while (ROOT / ('engine-before-emqx-%d' % n)).exists():
            n += 1
        os.rename(ROOT / 'engine', ROOT / ('engine-before-emqx-%d' % n))
        facts['engine_moved_to'] = 'engine-before-emqx-%d' % n


def package_files():
    """The package as install.sh renders it for the example settings (bind 127.0.0.1, default ports)."""
    files = {}
    for path in sorted((PACKAGE / 'quadlet').iterdir()):
        text = path.read_text()
        for name, port in PORTS.items():
            text = text.replace('@@EMQX_PUBLISH_%s@@' % name, '127.0.0.1:%d' % port)
        assert '@@' not in text, 'unrendered-placeholder'
        files[QUADLET_DIR + '/' + path.name] = ('0644', text)
    for name in ('base.hocon', 'acl.conf', 'entrance.conf'):
        files[CONFIG_DIR + '/' + name] = ('0644', (PACKAGE / 'config' / name).read_text())
    files[CONFIG_DIR + '/emqx.env'] = ('0600', (PACKAGE / 'config/emqx.env.example').read_text())
    return files


def arm(dropin, marker, text, extra=None):
    files = {dropin: ('0644', text), marker: ('0600', 'a54 once\n')}
    files.update(extra or {})
    oc.write_owner_files(files)
    oc.systemctl('daemon-reload', timeout=120)


def disarm():
    home = Path(oc.account().pw_dir)
    oc.owner(['/bin/rm', '-rf', *[str(home / rel) for rel in (DROPDIR, FAIL_MARKER, TAMPER_MARKER, TAMPER_SCRIPT)]],
             timeout=60)
    oc.systemctl('daemon-reload', timeout=120)


def digest(doc):
    """The device's state as the probe sees it, comparable across a start: without EMQX's own $SYS retained messages and
    without the raw configuration's digest (a source added at runtime is stored without the defaults a boot fills in)."""
    found = {key: doc.get(key) for key in DIGEST_KEYS if key != 'config_sha256'}
    found['retained_api'] = {t: h for t, h in (doc.get('retained_api') or {}).items() if not t.startswith('$SYS/')}
    found['native_counts'] = {t: n for t, n in (doc.get('native_counts') or {}).items() if t != 'emqx_retainer_message'}
    return found


def stable(doc):
    """emqx_product_real_ha.stable: everything including the configuration digest, without the native counters."""
    found = digest(doc)
    found.pop('native_counts', None)
    found['config_sha256'] = doc.get('config_sha256')
    return found


def differs(a, b):
    return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))


PROBES = {}


def probe(tag, mode, creds, *, ha=False, authz_add=False):
    req = {'mode': mode, 'ha_admin_password': creds['ha_admin_password'], 'user2': creds['user2'],
           'user2_password': creds['user2_password'], 'authz_add': authz_add}
    if ha:
        req.update(mqtt=creds['mqtt'], api_key=creds['api_key'], api_secret=creds['api_secret'])
    time.sleep(8)  # the entrance's login rate limit (10/min, burst 5) also counts the probe before
    p = oc.owner(['/usr/bin/python3', '-I', '-c', PROGRAM], input=(json.dumps(req) + '\n').encode(), timeout=900,
                 check=False)
    try:
        doc = json.loads(p.stdout.decode().strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise AssertionError('probe-output-%s-exit-%s' % (tag, p.returncode)) from None
    for secret_name in list(doc):
        assert secret_name not in ('token', 'password'), 'probe-returned-a-secret-field'
    PROBES[tag] = doc
    facts.setdefault('probes', {})[tag] = {k: doc.get(k) for k in ('mode', 'login', 'authz_sources', 'authz_settings',
                                                                   'mqtt_users', 'rules', 'native_counts',
                                                                   'api_ready_after_s', 'api_key_works')}
    return doc


def device_state(tag, doc, sources):
    login = doc.get('login') or {}
    names = {u[0] for u in doc.get('mqtt_users') or []}
    must(tag + '_device_admin_logs_in_ha_admin_does_not', login.get('device_admin') == 200
         and login.get('ha_admin') == 401 and login.get('ha_user2') == 401, login=login)
    must(tag + '_authorization_is_this_devices', doc.get('authz_sources') == sources
         and doc.get('authz_settings') == {'no_match': 'deny', 'deny_action': 'ignore'}
         and doc.get('file_acl_readback_equal') is True, sources=doc.get('authz_sources'))
    must(tag + '_no_ha_data', names == {MQTT_USER} and not doc.get('rules') and not doc.get('api_keys')
         and not [t for t in (doc.get('retained_api') or {}) if not t.startswith('$SYS/')]
         and doc.get('dashboard_users') == ['admin'], users=sorted(names))


def evaluate(tag, doc):
    results = evaluate_imported(doc, EXPECT['emqx'], 'builtin')
    failed = [name for name, ok, _d in results if not ok]
    facts.setdefault('acceptance', {})[tag] = {'checks': len(results), 'failed': failed}
    for name, ok, _detail in results:
        check('%s: %s' % (tag, name), ok)
    must(tag + '_dev_d_acceptance_all_pass', bool(results) and not failed, failed=failed)


BASE_OBJECTS = {}


def owner_objects():
    return {'containers': set(oc.podman('ps', '-a', '--format', '{{.Names}}').stdout.decode().split()),
            'volumes': set(oc.podman('volume', 'ls', '--format', '{{.Name}}').stdout.decode().split()),
            'networks': set(oc.podman('network', 'ls', '--format', '{{.Name}}').stdout.decode().split())}


def throwaways():
    """What neither this deployment nor the account before it holds (the n8n cycle's stopped volumes stay)."""
    own = {'containers': set(CONTAINERS), 'volumes': set(VOLUMES), 'networks': {NETWORK, 'podman'}}
    now = owner_objects()
    return {kind: sorted(now[kind] - own[kind] - BASE_OBJECTS.get(kind, set())) for kind in now}


watch = Watch()
try:
    out['phase'] = 'inputs'
    product_source = (LAB_SOURCE / 'emqx_product_real_ha.py').read_text()
    b1_source = (LAB_SOURCE / 'ha_import_b1_e2e.py').read_text()
    PROGRAM = dev_d_probe_program(product_source, b1_source)
    evaluate_imported = function_from(product_source, 'evaluate_imported')
    owner_text = string_constant(product_source, 'OWNER_ACL_TEXT')
    must('owner_text_is_the_products', owner_text == ha_emqx.ACL_NEEDS_BUILTIN)
    acct = oc.account()
    must('owner_present', acct is not None)
    pid = oc.manager_pid(acct.pw_uid)
    manager = subprocess.run(['systemctl', 'show', 'user@%d.service' % acct.pw_uid, '-p', 'MemoryMax', '-p',
                              'MemorySwapMax', '-p', 'PrivateNetwork'], capture_output=True, text=True, timeout=30)
    facts['owner_manager'] = dict(l.split('=', 1) for l in manager.stdout.splitlines() if '=' in l)
    must('owner_manager_private_network_and_memory_cap', facts['owner_manager'].get('PrivateNetwork') == 'yes'
         and facts['owner_manager'].get('MemoryMax', 'infinity') != 'infinity')
    must('archive_sha256_equals_the_b1_record', CHAIN['slug'] in RECORDED and CHAIN.get('sha256')
         == RECORDED[CHAIN['slug']] and sha256_file(ARCHIVE) == RECORDED[CHAIN['slug']])
    key_text = private(haimport.read_key_file(KEY_FILE))
    KEY_FILE.unlink()
    raw = json.loads(CREDS_FILE.read_text())
    CREDS_FILE.unlink()
    creds = {'ha_admin_password': private(raw['ha_admin_password']), 'user2': raw['user2'],
             'user2_password': private(raw['user2_password']),
             'mqtt': [[user, private(password)] for user, password in raw['mqtt']],
             'api_key': private(raw['api_key']), 'api_secret': private(raw['api_secret'])}
    must('ha_mqtt_users_are_the_recorded_ones', [u for u, _p in creds['mqtt']]
         == [u['user_id'] for u in EXPECT['emqx']['mqtt_users']])
    watch.env_values = [line.split('=', 1)[1].encode() for line in
                        (PACKAGE / 'config/emqx.env.example').read_text().splitlines()
                        if line.startswith('EMQX_') and len(line.split('=', 1)[1]) >= 5]
    facts['environment_file_emqx_settings'] = sorted(
        line.split('=', 1)[0] for line in (PACKAGE / 'config/emqx.env.example').read_text().splitlines()
        if line.startswith('EMQX_'))
    watch.start()
    time.sleep(1)
    host_mnt, host_net = os.stat('/proc/1/ns/mnt').st_ino, oc.netns_inode(1)
    facts['engine_tools'] = oc.enter_tools_namespace(ROOT)
    oc.join_netns(pid)
    must('engine_in_private_mount_and_owner_netns', os.stat('/proc/self/ns/mnt').st_ino != host_mnt
         and os.stat('/proc/thread-self/ns/net').st_ino == oc.netns_inode(pid) != host_net)

    out['phase'] = 'previous-attempt'
    remove_previous()
    BASE_OBJECTS.update(owner_objects())
    facts['account_objects_before'] = {k: sorted(v) for k, v in BASE_OBJECTS.items()}

    out['phase'] = 'target-images'
    for name, ref in IMAGES.items():
        info = json.loads(oc.podman('image', 'inspect', ref, timeout=60).stdout)[0]
        must('owner_image_arm64_' + name, info.get('Architecture') == 'arm64', id=info['Id'][:12])

    out['phase'] = 'target-deploy'
    files = package_files()
    publish = sorted(line for _m, t in files.values() for line in t.splitlines() if line.startswith('PublishPort='))
    must('published_only_on_loopback', publish == sorted('PublishPort=127.0.0.1:%d:%d' % (p, p) for p in PORTS.values()),
         publish=publish)
    oc.write_owner_files(files)
    facts['installed_files'] = sorted(files)
    device = {'dashboard': private(secrets.token_urlsafe(24)), 'cookie': private(secrets.token_urlsafe(24)),
              'mqtt': private(secrets.token_urlsafe(24))}
    values = {'woow-emqx-dashboard-password': device['dashboard'], 'woow-emqx-node-cookie': device['cookie'],
              'woow-emqx-mqtt-password': device['mqtt'],
              'woow-emqx-mqtt-bootstrap': bootstrap_csv(MQTT_USER, device['mqtt'])}
    for name in SECRET_NAMES:
        oc.podman('secret', 'create', name, '-', input=values[name].encode(), timeout=60)
    oc.systemctl('daemon-reload', timeout=120)
    start_stack()
    for unit in UNITS:
        must('target_unit_active_' + unit, active(unit) == 'active')
    must('host_netns_has_no_test_listener', b':%d' % PORTS['DASHBOARD'] not in subprocess.run(
        ['nsenter', '--net=/proc/1/ns/net', 'ss', '-H', '-lnt'], capture_output=True, timeout=30).stdout)
    info = json.loads(oc.podman('inspect', BROKER).stdout)[0]
    must('broker_on_the_packages_bridge_network', sorted((info.get('NetworkSettings') or {}).get('Networks') or {})
         == [NETWORK])
    facts['device_schedulers'] = list(ha_emqx.schedulers(
        lambda command: oc.podman('exec', BROKER, *command, check=False, timeout=120)))

    out['phase'] = 'device-before'
    d0 = probe('device-before', 'file', creds)
    device_state('device_before', d0, [['file', True]])
    digest_d0 = digest(d0)

    out['phase'] = 'engine-setup'
    PATHS.data.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    call('key-init')
    suggested = call('catalog-suggest', {'owner': oc.OWNER})
    apps = [a for a in suggested.get('apps') or [] if a.get('id') == 'emqx']
    must('product_suggest_found_emqx', len(apps) == 1,
         ids=[[a.get('id'), len(a.get('variants') or [])] for a in suggested.get('apps') or []])
    entry = json.loads(json.dumps(apps[0]['entry']))
    facts['suggested'] = {k: entry.get(k) for k in ('owner', 'units', 'writer_units', 'volumes', 'secrets', 'health',
                                                    'data_dirs', 'config_files')}
    facts['suggested']['verify'] = [(v.get('id'), v.get('type')) for v in entry.get('verify') or []]
    facts['suggested']['valid'] = apps[0].get('valid')
    facts['suggest_notes'] = sorted({n.get('code') for n in apps[0].get('notes') or []})
    facts['suggest_warnings'] = sorted({w.get('code') for w in apps[0].get('warnings') or []})
    must('suggest_draft_valid_and_names_the_package', apps[0].get('valid') is True
         and sorted(entry['units']) == sorted(UNITS) and sorted(v['name'] for v in entry['volumes']) == sorted(VOLUMES))
    changes = []
    health = []
    for item in entry.get('health') or []:
        # the engine's own headers (adapters/quadlet_postgres.py loopback_get): the Dashboard page answers 406 to them
        code = http_code(item.get('url'), headers=ENGINE_HEADERS) if item.get('type') == 'http' else None
        facts.setdefault('suggested_health_answers', []).append([item.get('url'), code])
        if item.get('type') != 'http' or code == item.get('expect_status', 200):
            health.append(item)
        else:
            changes.append('health %s removed (answers %s to a caller outside the container)' % (item.get('url'), code))
    entry['health'] = health
    facts['installed_entry_changes'] = changes
    # suggest.HEALTH_PATHS (fix/emqx-health-suggest-20261124): the draft asks the broker's public REST API; installed unchanged
    fixed = getattr(suggest, 'HEALTH_PATHS', {}).get(('emqx', '/readyz'))
    must('suggested_health_unchanged_with_the_health_path_fix', fixed is None or (changes == [] and [
        h.get('url') for h in health] == [DASHBOARD + (fixed[0] if isinstance(fixed, tuple) else fixed)]), changes=changes,
         answers=facts.get('suggested_health_answers'))
    preview = call('catalog-install', {'entry': entry})
    must('catalog_preview_valid', preview.get('valid') is True and bool(preview.get('new_sha256'))
         and preview.get('expected_sha256') is None, error=(preview.get('error') or {}).get('code'))
    call('catalog-install', {'entry': entry, 'confirm': True, 'expected_sha256': preview['expected_sha256']})

    out['phase'] = 'ha-upload'
    begun = call('upload-begin', {'filename': 'ha-%s.tar' % CHAIN['slug'], 'size': ARCHIVE.stat().st_size})
    shutil.copyfile(ARCHIVE, begun['path'])
    ha = call('upload-finish', {'upload_id': begun['upload_id']}).get('ha_backup') or {}
    must('ha_backup_registered_with_emqx', ha.get('id') == 'ha-' + RECORDED[CHAIN['slug']][:20]
         and 'emqx' in json.dumps(ha.get('importable_apps')))

    def ha_check(label):
        job, _lines = run_job(label, 'ha-check-start', {'ha_backup_id': ha['id'], 'apps': ['emqx'],
                                                        'request_id': rid(label.replace('_', '-')), 'key': key_text}, 1800)
        return next((a for a in ((job.get('result') or {}).get('ha_check') or {}).get('apps') or []
                     if a.get('app_id') == 'emqx'), {})

    out['phase'] = 'decision-c'
    row = ha_check('check_file')
    facts['check_file'] = {'blockers': len(row.get('blockers') or []), 'warnings': len(row.get('warnings') or []),
                           'arch': row.get('arch'), 'version': row.get('version'),
                           'target_version': row.get('target_version')}
    must('decision_c_check_names_exactly_the_owners_text', row.get('ok') is False
         and row.get('blockers') == [owner_text])
    before_ids = {b['id'] for b in call('list').get('backups') or []}
    job, _lines = run_job('convert_file', 'ha-convert-start', {'ha_backup_id': ha['id'], 'apps': ['emqx'],
                                                               'test_mode': False, 'confirm': True,
                                                               'request_id': rid('cfile'), 'key': key_text}, 1800,
                          expect='failed')
    err = job.get('error') or {}
    must('decision_c_convert_refused_incompatible_with_the_owners_text', err.get('code') == 'incompatible'
         and owner_text in str(err.get('message')))
    must('decision_c_left_nothing', {b['id'] for b in call('list').get('backups') or []} == before_ids
         and not any(throwaways().values()), **throwaways())
    d0b = probe('device-after-refusal', 'file', creds)
    must('decision_c_device_unchanged', digest(d0b) == digest_d0 and stable(d0b) == stable(d0),
         differing=differs(stable(d0b), stable(d0)))

    out['phase'] = 'customer-adds-built-in-database'
    d1 = probe('customer-adds-built-in-database', 'file', creds, authz_add=True)
    must('built_in_database_added_after_the_file_source', d1.get('authz_add') in (200, 204)
         and d1.get('authz_move') in (200, 204)
         and d1.get('authz_sources') == [['file', True], ['built_in_database', True]],
         add=d1.get('authz_add'), move=d1.get('authz_move'), sources=d1.get('authz_sources'))
    d1b = probe('device-before-import', 'builtin', creds)
    device_state('device_before_import', d1b, [['file', True], ['built_in_database', True]])
    digest_d1 = digest(d1b)

    out['phase'] = 'ha-check'
    row = ha_check('check_builtin')
    section = row.get('emqx') or {}
    facts['check_builtin'] = {'blockers': row.get('blockers'), 'warnings': len(row.get('warnings') or []),
                              'arch': row.get('arch'), 'version': row.get('version'),
                              'target_version': row.get('target_version'),
                              'target_authorization': section.get('target_authorization')}
    must('product_check_no_blocker', row.get('ok') is True and (row.get('blockers') or []) == [])
    must('product_check_facts', row.get('version') == '5.9.1' and row.get('target_version') == '5.8.9'
         and row.get('arch') == ('aarch64' if EXPECT['machine'] == 'arm' else 'amd64')
         and section.get('target_authorization') == ['file', 'built_in_database'])
    must('check_left_no_throwaway', not any(throwaways().values()), **throwaways())

    out['phase'] = 'ha-convert'
    job, _lines = run_job('ha_convert', 'ha-convert-start', {'ha_backup_id': ha['id'], 'apps': ['emqx'],
                                                             'test_mode': False, 'confirm': True,
                                                             'request_id': rid('convert'), 'key': key_text}, 3600)
    converted = job.get('result') or {}
    backup_id = converted.get('backup_id')
    must('converted_backup_made_encrypted', bool(backup_id) and converted.get('encrypted') is True,
         apps=converted.get('apps'), size=converted.get('size'))
    listed = next((b for b in call('list').get('backups') or [] if b.get('id') == backup_id), {})
    origin = listed.get('from_ha') or {}
    must('converted_backup_lists_its_ha_origin', origin.get('ha_backup_id') == ha['id'] and origin.get('apps') == ['emqx'])
    must('convert_left_no_throwaway_and_no_anonymous_volume', not any(throwaways().values()), **throwaways())
    facts['candidate_command_line'] = {k: (sorted(v) if isinstance(v, set) else v) for k, v in watch.candidate.items()}
    must('candidate_started_with_env_file_on_this_podman', watch.candidate['seen'] > 0
         and watch.candidate['env_file_options'] > 0 and watch.candidate['env_file_names'] == {'emqx.env'})
    must('no_environment_file_value_or_name_on_the_command_line', watch.candidate['value_hits'] == 0
         and not (watch.candidate['env_names'] & set(facts['environment_file_emqx_settings'])))
    inspected = call('inspect', {'backup_id': backup_id})
    flight = inspected.get('preflight') or {}
    facts['inspect'] = {'ok': flight.get('ok'), 'apps': [(a.get('id'), a.get('mode'), (a.get('settings') or {}).get('state'))
                                                         for a in flight.get('apps') or []],
                        'failed': [c.get('id') for c in flight.get('checks') or [] if c.get('status') == 'fail']}
    must('inspect_preflight_in_place_same_settings', flight.get('ok') is True and not facts['inspect']['failed']
         and all(a.get('mode') == 'inplace' and (a.get('settings') or {}).get('state') == 'same'
                 for a in flight.get('apps') or []))

    def rebuilt(lines_):
        return {v: sum(('已重建資料卷 ' + v) in line for line in lines_) for v in VOLUMES}

    def own_state(phase):
        back_ = probe(phase, 'builtin', creds, ha=True)
        device_state(phase.replace('-', '_'), back_, [['file', True], ['built_in_database', True]])
        must(phase.replace('-', '_') + '_device_state_equal_to_before_import', digest(back_) == digest_d1,
             differing=differs(digest(back_), digest_d1))
        mq_ = back_.get('mqtt') or {}
        must(phase.replace('-', '_') + '_ha_mqtt_users_refused_bootstrap_user_kept',
             all(mq_.get('login_' + u) not in (0, None) for u, _p in creds['mqtt']) and mq_.get('bootstrap_woow') == 0)
        must(phase.replace('-', '_') + '_ha_api_key_refused', back_.get('api_key_works') in (401, 403),
             code=back_.get('api_key_works'))

    out['phase'] = 'first-import-rollback'
    marker = Path(acct.pw_dir) / FAIL_MARKER
    arm(FAIL_DROPIN, FAIL_MARKER, '[Service]\nExecStartPre=/bin/sh -c \'if test -f %h/' + FAIL_MARKER + '; then rm -f %h/'
        + FAIL_MARKER + '; exit 1; fi\'\n')
    must('first_import_failure_armed', marker.exists())
    job, lines = run_job('first_import_rollback', 'restore-start', {'backup_id': backup_id, 'apps': ['emqx'],
                                                                    'confirm': True, 'request_id': rid('first')}, 2400,
                         expect='rolled-back')
    first = job.get('result') or {}
    must('first_import_changed_then_rolled_back', first.get('changed') is True and first.get('rolled_back') is True
         and not marker.exists() and all(n == 2 for n in rebuilt(lines).values()), rebuilt=rebuilt(lines))
    disarm()
    wait_running()
    own_state('first-import-rolled-back')

    out['phase'] = 'first-import-readback-rollback'
    marker = Path(acct.pw_dir) / TAMPER_MARKER
    arm(TAMPER_DROPIN, TAMPER_MARKER, '[Service]\nExecStartPre=/bin/sh %h/' + TAMPER_SCRIPT + '\n',
        {TAMPER_SCRIPT: ('0700', TAMPER)})
    must('first_import_tamper_armed', marker.exists())
    job, lines = run_job('first_import_readback_rollback', 'restore-start', {'backup_id': backup_id, 'apps': ['emqx'],
                                                                             'confirm': True, 'request_id': rid('firstrb')},
                         2400, expect='rolled-back')
    first = job.get('result') or {}
    must('first_import_readback_named_the_changed_root_and_rolled_back', first.get('rolled_back') is True
         and not marker.exists() and '設定（log）' in str((job.get('error') or {}).get('message'))
         and not any(READBACK_LOG in line for line in lines) and all(n == 2 for n in rebuilt(lines).values()),
         rebuilt=rebuilt(lines))
    disarm()
    wait_running()
    own_state('first-import-readback-rolled-back')

    out['phase'] = 'restore'
    job, lines = run_job('restore', 'restore-start', {'backup_id': backup_id, 'apps': ['emqx'], 'confirm': True,
                                                      'request_id': rid('restore')}, 2400)
    restored = job.get('result') or {}
    safety = restored.get('safety_backup_id')
    facts['restore'] = {'changed': restored.get('changed'), 'rolled_back': restored.get('rolled_back'),
                        'safety_backup_id': safety, 'timing': restored.get('timing'),
                        'health': [(c.get('id'), c.get('status')) for c in restored.get('health') or []],
                        'verification': verification_view(restored), 'warnings': len(restored.get('warnings') or [])}
    must('restore_changed_not_rolled_back_with_safety', restored.get('changed') is True
         and restored.get('rolled_back') is False and bool(safety))
    must('restore_health_checks_ok', all(c.get('status') == 'ok' for c in restored.get('health') or [])
         and len(restored.get('health') or []) == len(health), checks=len(restored.get('health') or []))
    must('restore_readback_logged_equal', any(READBACK_LOG in line for line in lines))
    wait_running()
    imported = probe('imported', 'builtin', creds, ha=True)
    evaluate('imported', imported)

    out['phase'] = 'restart'
    oc.systemctl('restart', 'emqx.service', timeout=700)
    wait_running()
    restarted = probe('restarted', 'builtin', creds, ha=True)
    evaluate('restarted', restarted)
    must('state_after_restart_equals_state_after_restore', stable(restarted) == stable(imported),
         differing=differs(stable(restarted), stable(imported)))

    out['phase'] = 'automatic-rollback'
    marker = Path(acct.pw_dir) / FAIL_MARKER
    arm(FAIL_DROPIN, FAIL_MARKER, '[Service]\nExecStartPre=/bin/sh -c \'if test -f %h/' + FAIL_MARKER + '; then rm -f %h/'
        + FAIL_MARKER + '; exit 1; fi\'\n')
    must('one_shot_failure_armed', marker.exists())
    job, lines = run_job('automatic_rollback', 'restore-start', {'backup_id': backup_id, 'apps': ['emqx'],
                                                                 'confirm': True, 'request_id': rid('auto')}, 2400,
                         expect='rolled-back')
    auto = job.get('result') or {}
    must('automatic_rollback_reported_and_failure_fired', auto.get('rolled_back') is True and not marker.exists())
    disarm()
    wait_running()
    after_auto = probe('after-automatic-rollback', 'builtin', creds, ha=True)
    evaluate('after_automatic_rollback', after_auto)
    must('state_after_automatic_rollback_equal', stable(after_auto) == stable(restarted),
         differing=differs(stable(after_auto), stable(restarted)))

    out['phase'] = 'readback-rollback'
    marker = Path(acct.pw_dir) / TAMPER_MARKER
    arm(TAMPER_DROPIN, TAMPER_MARKER, '[Service]\nExecStartPre=/bin/sh %h/' + TAMPER_SCRIPT + '\n',
        {TAMPER_SCRIPT: ('0700', TAMPER)})
    must('tamper_armed', marker.exists())
    job, lines = run_job('readback_rollback', 'restore-start', {'backup_id': backup_id, 'apps': ['emqx'],
                                                                'confirm': True, 'request_id': rid('readback')}, 2400,
                         expect='rolled-back')
    tampered = job.get('result') or {}
    must('readback_named_the_changed_root_and_rolled_back', tampered.get('rolled_back') is True and not marker.exists()
         and '設定（log）' in str((job.get('error') or {}).get('message'))
         and not any(READBACK_LOG in line for line in lines))
    disarm()
    wait_running()
    after_readback = probe('after-readback-rollback', 'builtin', creds, ha=True)
    evaluate('after_readback_rollback', after_readback)
    must('state_after_readback_rollback_equal', stable(after_readback) == stable(after_auto),
         differing=differs(stable(after_readback), stable(after_auto)))

    out['phase'] = 'rollback'
    job, _lines = run_job('rollback', 'restore-start', {'backup_id': safety, 'apps': ['emqx'], 'confirm': True,
                                                        'request_id': rid('rollback')}, 2400)
    rolled = job.get('result') or {}
    facts['rollback'] = {'changed': rolled.get('changed'), 'rolled_back': rolled.get('rolled_back'),
                         'health': [(c.get('id'), c.get('status')) for c in rolled.get('health') or []],
                         'verification': verification_view(rolled)}
    must('rollback_restore_ok', rolled.get('changed') is True and rolled.get('rolled_back') is False
         and all(c.get('status') == 'ok' for c in rolled.get('health') or [])
         and all(e.get('match') is not False for e in rolled.get('verification') or []))
    wait_running()
    back = probe('rolled-back', 'builtin', creds, ha=True)
    device_state('rolled_back', back, [['file', True], ['built_in_database', True]])
    must('rollback_device_state_equal_to_before_import', digest(back) == digest_d1,
         differing=differs(digest(back), digest_d1))
    mq = back.get('mqtt') or {}
    must('rollback_ha_mqtt_users_refused_bootstrap_user_kept', all(mq.get('login_' + u) not in (0, None)
                                                                  for u, _p in creds['mqtt'])
         and mq.get('bootstrap_woow') == 0, mqtt={k: v for k, v in mq.items() if k.startswith('login_')})
    must('rollback_ha_api_key_refused', back.get('api_key_works') in (401, 403), code=back.get('api_key_works'))

    out['phase'] = 'engine-leftovers'
    must('no_throwaway_container_network_or_volume_left', not any(throwaways().values()), **throwaways())
    staging = sorted(os.listdir(PATHS.staging)) if PATHS.staging.exists() else []
    must('no_staging_left', staging == [], staging=staging)
    must('memory_watch_never_stopped_the_stack', watch.tripped is False)
    out['status'] = 'passed'
    out['phase'] = 'done'
except Exception as error:  # noqa: BLE001
    out['error'] = type(error).__name__
    out['error_where'] = [[Path(f.filename).name, f.lineno, f.name] for f in traceback.extract_tb(error.__traceback__)[-4:]]
    if isinstance(error, (AssertionError, RuntimeError, oc.OwnerCommandFailed)):
        out['error_detail'] = oc.safe_tail(str(error), 400)
    try:
        facts['diagnosis_units'] = {u: active(u) for u in UNITS}
        rows = oc.podman('ps', '-a', '--format', '{{.Names}}|{{.Status}}', check=False, timeout=60).stdout.decode()
        facts['diagnosis_containers'] = sorted(l for l in rows.splitlines() if l.strip())[:20]
        facts['candidate_command_line'] = {k: (sorted(v) if isinstance(v, set) else v)
                                           for k, v in watch.candidate.items()}
    except Exception:  # noqa: BLE001
        facts['diagnosis_units'] = 'unknown'
finally:
    for staged in (KEY_FILE, CREDS_FILE):
        if staged.exists():
            staged.unlink()
            facts['staged_file_removed_late'] = True
    try:
        disarm()
        stop_stack()
        facts['units_after_attempt'] = {u: active(u) for u in UNITS}
    except Exception:  # noqa: BLE001
        facts['units_after_attempt'] = 'unknown'
    watch.stop.set()
    if watch.is_alive():
        watch.join(timeout=30)
    facts['watch'] = {'samples': watch.samples, 'mem_available_min': watch.min_mem, 'tripped': watch.tripped,
                      'home_assistant_frontend': watch.frontend}
    shutil.rmtree(WORK, ignore_errors=True)
    after = kernel_state()
    facts['kernel_after'] = dict(after, modules=len(after['modules']))
    facts['modules_loaded_by_the_kernel_during_the_run'] = sorted(set(after['modules']) - set(KERNEL_BEFORE['modules']))
    for name, ok in (('no_new_oops', after['oops_count'] == KERNEL_BEFORE['oops_count']),
                     ('no_new_hung_task_report', after['hung_task_reports'] == KERNEL_BEFORE['hung_task_reports']),
                     ('no_new_d_state_task', after['d_state'] <= KERNEL_BEFORE['d_state']),
                     ('kernel_taint_unchanged', after['tainted'] == KERNEL_BEFORE['tainted'])):
        if not check(name, ok) and out['status'] == 'passed':
            out['status'] = 'failed'
    out['elapsed_seconds'] = round(time.monotonic() - started, 1)
    out['failed_check'] = next((k for k, v in checks.items() if not v), None)
    out['checks_total'], out['checks_true'] = len(checks), sum(checks.values())
    needles = {v for v in PRIVATE if len(v) >= 6}
    encoded = json.dumps(out, sort_keys=True, ensure_ascii=False)
    if any(v in encoded or json.dumps(v)[1:-1] in encoded for v in needles):
        out = {'status': 'failed', 'failed_check': 'secret_in_output_suppressed', 'commercial_acceptance': 'not-complete',
               'phase': out.get('phase')}
    report(ROOT / 'owner-emqx-result.json', out)
    print(json.dumps(out, sort_keys=True))
sys.exit(0 if out['status'] == 'passed' else 1)
