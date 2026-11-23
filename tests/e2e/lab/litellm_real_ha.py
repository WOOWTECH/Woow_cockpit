#!/usr/bin/env python3
"""REAL HA LiteLLM backup -> isolated dev-d LiteLLM (the package's PostgreSQL 17 + the real LiteLLM 1.104.0 app image).

  python3 -I tests/e2e/lab/litellm_real_ha.py --run --outer-isolation-confirmed

What is real: the owner-made HA backup of the showcase's woow-litellm 0.1.15 add-on (PG 18.6, encrypted), opened and
decrypted by the product reader (habackup/hasecuretar), checked by the product preflight (ha_litellm_candidate
.scan_member), its cluster streamed by the INTERNAL candidate (ha_litellm_candidate.cluster_member) through the product
PgSink into a throwaway PostgreSQL 18 (HA's configuration replaced, every library/command setting overridden), the
product salt/database binding reader, a pg_dump of HA's database restored into the package's PostgreSQL 17 image the
way the package's restore.sh does (drop, create, load), the HA salt moved (the target keeps its own master key, UI
password and database password), the package's own entrypoint (/opt/woow/start.sh: db_prepare salt gate, Prisma
migrate, UI session revocation) and the real app API: the HA-issued virtual key, its model list, the stored models,
users, teams, decryption of every stored provider value, a key issued by the restored app, restart, wrong-salt
refusal, rollback to the target's own data, cleanup.

What it is NOT: the public import (ha_litellm_candidate.convert still refuses; litellm is not in haimport.APPS), the
package's systemd/Quadlet units (throwaway containers stand in for them), the product UID 65534 (dev-d maps 0..55000
only, so the app runs as 1000:0 like the earlier rehearsal), ChatGPT subscription restore (WOOW_CHATGPT_ENABLED=false
here) or provider calls (no network). commercial_acceptance stays "not-complete".

Secrets: read through ha_import_b1_e2e.Secrets or from the backup in memory, passed to containers on stdin (the
target database password as a Podman secret created from stdin), registered in a credential_ledger.Ledger whose
declared sources must all be registered before the final scan of everything this run printed. Output: fixed JSON
event lines (stage, booleans, counts); private failure details only in a 0600 file outside the repository.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
for _path in (str(REPO / 'backup-engine'), str(HERE)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from woowbackup import habackup, haimport, hasecuretar, hastore, ha_litellm_candidate as candidate, ha_odoo, tempctr  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402
from woowbackup.podman import OutputLimitExceeded, Result, default_runner  # noqa: E402
from credential_ledger import CoverageError, Ledger  # noqa: E402

LAB = Path.home() / '.woowbk-lab'
FIXTURE = LAB / 'ha-fixtures/20261123-litellm/x86/woow-litellm-x86-enc/woow-litellm-x86-enc-20261123.tar'
FIXTURE_SHA256 = '9dc5994497d9d6ff4c3ee8d3fcf86f295cf25c69d1eae98227854fee85286f27'
# Already loaded in dev-d (image inspect 2026-11-23): lab build of the package app on the public LiteLLM 1.104.0 base,
# PostgreSQL 18.7 (source side), PostgreSQL 17.11 alpine (the package's litellm-postgres image).
APP_IMAGE = 'sha256:0c71bec8f80e3445267e9bc08495d3782b5c80c8fb7ca18261f07abad00ce312'
PG18_IMAGE = 'sha256:4ea77c7055dec6a632156aa2cd9f1abaaedeba5f812f104f4e9e1ac37363469b'
PG17_IMAGE = 'sha256:094ecc9ca4ea66931822a93f1d814e059deda57f355d9416fa72f85170871cb7'
EXPECTED_ALIAS = 'woow-import-test-20261123'   # the test key alias recorded when the backup was made (not secret)
OWNER = HERE / 'owner.sh'
LOCK = Path('/tmp/woowbk-dev-d-mutation.lock')
WAITING = Path('/tmp/woowbk-dev-d-emqx-main-waiting')
LOCK_WAIT = 3600
HA_PGDATA = '/var/lib/postgresql'          # the PG18 image's VOLUME path: no anonymous volume is created
MAX_DUMP = 160 * 1024 * 1024
APP_MEMORY = '1408m'                       # measured peak 1.26 GiB in the 2026-11-21 rehearsal (resource-summary-14)
MIN_DEVICE_HEADROOM = 1900 * 1024 * 1024
MIN_HOST_AVAILABLE_KIB = 2300 * 1024
MIN_DISK_FREE = 13 * 1024 ** 3
SOFT_DEADLINE = 33 * 60                    # lock hold stays under 40 min: optional stages are skipped past this
WORKER = (HERE / 'litellm_real_worker.py').read_text(encoding='utf-8')
SECRET_NAME = re.compile(r'PWD|PASS|KEY|TOKEN|SECRET|CRED|AUTH|SIG', re.I)

SOURCES = ('lab.ha_backup_key', 'lab.test_virtual_key', 'ha.salt_key', 'ha.master_key', 'ha.pg_password',
           'ha.ui_password', 'target.master_key', 'target.ui_password', 'target.pg_password', 'target.salt_key',
           'target.database_url', 'target.seed_credential', 'issued.virtual_key')

# Full structural inventory (from the rehearsal litellm_actual_candidate.py at f0f8cb9): PG18 duplicates attnotnull in
# pg_constraint (type n), PG17 does not, so NOT NULL stays in the column inventory only.
SCHEMA = r"""SELECT coalesce(json_agg(x ORDER BY x::text), '[]'::json) FROM (
 SELECT json_build_array('column',n.nspname,c.relname,a.attname,
   format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,
   pg_get_expr(d.adbin,d.adrelid)) AS x
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace
 LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p','v','m','S')
 AND n.nspname IN ('public','woow_platform','woow')
 UNION ALL SELECT json_build_array('constraint',n.nspname,c.relname,k.conname,pg_get_constraintdef(k.oid))
 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname IN ('public','woow_platform','woow') AND k.contype <> 'n'
 UNION ALL SELECT json_build_array('index',schemaname,tablename,indexname,indexdef)
 FROM pg_indexes WHERE schemaname IN ('public','woow_platform','woow')
 UNION ALL SELECT json_build_array('enum',n.nspname,t.typname,e.enumsortorder,e.enumlabel)
 FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid JOIN pg_namespace n ON n.oid=t.typnamespace
 WHERE n.nspname IN ('public','woow_platform','woow')
 UNION ALL SELECT json_build_array('trigger',n.nspname,c.relname,t.tgname,pg_get_triggerdef(t.oid))
 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE NOT t.tgisinternal AND n.nspname IN ('public','woow_platform','woow')
 UNION ALL SELECT json_build_array('function',n.nspname,p.proname,pg_get_functiondef(p.oid))
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE p.prokind IN ('f','p') AND n.nspname IN ('public','woow_platform','woow')
) s"""
TABLES = ("SELECT coalesce(json_agg(json_build_array(schemaname,tablename) ORDER BY schemaname,tablename),'[]'::json)"
          " FROM pg_tables WHERE schemaname IN ('public','woow_platform','woow')")
SEQUENCES = ("SELECT coalesce(json_agg(json_build_array(schemaname,sequencename,start_value,min_value,max_value,"
             "increment_by,cycle,cache_size,last_value) ORDER BY schemaname,sequencename),'[]'::json) "
             "FROM pg_sequences WHERE schemaname IN ('public','woow_platform','woow')")
READER_SQL = ("CREATE ROLE woowbk_litellm_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;\n"
              "GRANT USAGE ON SCHEMA woow, woow_platform TO woowbk_litellm_reader;\n"
              "GRANT SELECT ON woow.meta, woow_platform.settings TO woowbk_litellm_reader;\n")
RECREATE = ('DROP DATABASE IF EXISTS litellm WITH (FORCE)', 'CREATE DATABASE litellm OWNER litellm')

EVENTS = []
LEDGER = None
PRIVATE = None


class Failed(Exception):
    """A failed check; the message is a fixed label (never a value)."""


def require(condition, label):
    if not condition:
        raise Failed(label)


def emit(stage, **values):
    line = json.dumps({'stage': stage, **values}, sort_keys=True)
    if LEDGER is not None and LEDGER.contains(line):
        line = json.dumps({'stage': 'suppressed_event', 'original_stage': stage}, sort_keys=True)
    EVENTS.append(line.encode('utf-8'))
    print(line, flush=True)


def private_note(data):
    """Bounded private diagnostics (0600, outside the repository); may hold lab secrets, never published."""
    if PRIVATE is None:
        return
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(PRIVATE / 'diagnostics.log', 'ab') as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(data[-65536:] + b'\n')


class DevDRunner:
    """Rootless Podman of dev-d's appowner through owner.sh; failure output goes to the private note only."""
    uid = None
    last_stderr = b''

    def podman(self, *args, input=None, stdout=None, timeout=120, check=True, max_output=None, abort=None):
        argv = [str(OWNER), 'd', 'podman', *args]
        try:
            result = default_runner(argv, input=input, stdout=stdout, timeout=timeout, max_output=max_output,
                                    abort=abort)
        except OutputLimitExceeded:
            raise BackupError('limit-exceeded', '隔離實驗室命令輸出超過上限。') from None
        except subprocess.TimeoutExpired:
            raise BackupError('job-failed', '隔離實驗室命令執行逾時。') from None
        except OSError:
            raise BackupError('job-failed', '無法執行隔離實驗室命令。') from None
        self.last_stderr = (result.stderr or b'')[-16384:]
        if check and result.returncode:
            private_note(b'podman ' + ' '.join(a for a in args[:3] if isinstance(a, str)).encode() + b' rc=' +
                         str(result.returncode).encode() + b'\n' + (result.stderr or b'')[-16384:])
            raise BackupError('job-failed', '隔離實驗室命令失敗。')
        return Result(result.returncode, result.stdout, b'')

    def relay(self, args, *, stdout=None, timeout=120, max_output=None, abort=None):
        return self.podman(*args, stdout=stdout, timeout=timeout, max_output=max_output, abort=abort)


class FreshLabObjects(tempctr.TempObjects):
    """Refuse name collisions before TempObjects registers anything for cleanup (from the rehearsal)."""

    def absent(self, kind, role):
        result = self.runner.podman(kind, 'exists', self.name(role), check=False, timeout=30, max_output=4096)
        if result.returncode != 1:
            raise Failed('object_name_collision')

    def volume(self, role):
        self.absent('volume', role)
        return super().volume(role)

    def network(self, role):
        self.absent('network', role)
        return super().network(role)

    def run(self, role, image, *args, **kwargs):
        self.absent('container', role)
        return super().run(role, image, *args, **kwargs)


# ---------------------------------------------------------------- guards (lock, isolation, resources, tree)

def git(*args):
    return subprocess.run(['git', '-C', str(REPO), *args], capture_output=True, text=True, timeout=60).stdout.strip()


def verify_isolation(label):
    proc = subprocess.run(['bash', str(OWNER), 'd', '--verify-isolation'], capture_output=True, text=True, timeout=120)
    require(proc.returncode == 0 and proc.stdout.strip() == 'dev-d isolation: true none {}', label)
    emit(label, isolation='true_none_no_ports')


def waiting_mtime():
    try:
        return WAITING.stat().st_mtime_ns
    except FileNotFoundError:
        return None


def emqx_main_holds_lock():
    """From hermes_real_ha.py (test/hermes-real-20261123): an emqx-main run holding the lock while its own waiting file
    exists is not a request for the next turn."""
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            cmd = (proc / 'cmdline').read_bytes()
            if b'run_emqx_real_owner.sh' not in cmd and b'emqx_real_owner_transport.py' not in cmd:
                continue
            if any(os.readlink(fd) == str(LOCK) for fd in (proc / 'fd').iterdir()):
                return True
        except OSError:
            continue
    return False


class _Tick(Exception):
    pass


def _tick(_signum, _frame):
    raise _Tick()


def acquire_lock():
    """flock like `flock -w 3600`, yielding to emqx-main (priority on dev-d) while its waiting file is fresh."""
    fd = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
        os.close(fd)
        raise Failed('unsafe_lock_file')
    previous = signal.signal(signal.SIGALRM, _tick)
    started = time.monotonic()
    stale = None
    try:
        while True:
            if time.monotonic() - started > LOCK_WAIT:
                os.close(fd)
                raise Failed('lock_not_acquired_3600s')
            mtime = waiting_mtime()
            if mtime is not None and emqx_main_holds_lock():
                stale = mtime
            if mtime is not None and mtime != stale:
                time.sleep(5)
                continue
            signal.alarm(30)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except _Tick:
                continue
            finally:
                signal.alarm(0)
            mtime = waiting_mtime()
            if mtime is not None and mtime != stale:
                fcntl.flock(fd, fcntl.LOCK_UN)
                time.sleep(5)
                continue
            emit('lock_acquired', waited_s=int(time.monotonic() - started))
            return fd
    finally:
        signal.signal(signal.SIGALRM, previous)


def outer_cgroup():
    """dev-d's cgroup on the host (read-only), from the lab Podman's inspect of the device container."""
    out = subprocess.run([str(LAB / 'bin/labpodman'), 'inspect', '--format', '{{.State.CgroupPath}}', 'woowbk-dev-d'],
                         capture_output=True, text=True, timeout=60).stdout.strip()
    path = (Path('/sys/fs/cgroup') / out.lstrip('/')).resolve()
    require(out and path.is_relative_to('/sys/fs/cgroup') and (path / 'memory.max').is_file(), 'device_cgroup')
    return path


def memory_now(cgroup):
    """(current, max, host MemAvailable KiB, clean inactive page cache of dev-d: reclaimable, credited up to 512 MiB)."""
    current = int((cgroup / 'memory.current').read_text())
    maximum = int((cgroup / 'memory.max').read_text())
    available = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                     if line.startswith('MemAvailable:'))
    stats = dict(line.split() for line in (cgroup / 'memory.stat').read_text().splitlines())
    clean = max(0, int(stats['inactive_file']) - int(stats['file_dirty']) - int(stats['file_writeback']))
    return current, maximum, available, min(clean, 512 * 1024 * 1024)


def pressure_guard(cgroup):
    """TempObjects abort hook: stop only this job on live memory pressure (cleanup never uses it)."""
    def check():
        try:
            current, maximum, available, credit = memory_now(cgroup)
        except (OSError, ValueError, StopIteration, KeyError):
            return BackupError('job-failed', 'live resource check unavailable')
        if available < 400 * 1024 or maximum - current + credit < 160 * 1024 * 1024:
            return BackupError('job-failed', 'live memory pressure: lab job aborted')
        return None
    return check


def headroom(runner, cgroup):
    current, maximum, available, credit = memory_now(cgroup)
    st = os.statvfs('/')
    free = st.f_bavail * st.f_frsize
    names = runner.podman('ps', '-a', '--format', '{{.Names}}', max_output=16384).stdout.decode().split()
    competing = [n for n in names if n.startswith('woowbk-j')]
    emit('headroom', device_headroom_mib=(maximum - current) // 2 ** 20, reclaimable_credit_mib=credit // 2 ** 20,
         host_available_mib=available // 1024, disk_free_gib=free // 2 ** 30, competing_job_containers=len(competing))
    require(maximum - current + credit >= MIN_DEVICE_HEADROOM, 'device_headroom_low')
    require(available >= MIN_HOST_AVAILABLE_KIB, 'host_memory_low')
    require(free >= MIN_DISK_FREE, 'disk_free_low')
    require(not competing, 'competing_job_containers')
    return sorted(names)


def running_names(runner):
    return sorted(runner.podman('ps', '--format', '{{.Names}}', max_output=16384).stdout.decode().split())


# ---------------------------------------------------------------- database helpers

def digests(db):
    """Per-table row count and MD5 of every row (one MVCC snapshot per table, UTC rendering) plus sequence state.
    Comparable across PostgreSQL 18 and 17; values never leave the database, only digests do."""
    tables = db.query_json(TABLES, 'litellm')
    selects = []
    for schema, table in tables:
        quoted = '.'.join('"' + part.replace('"', '""') + '"' for part in (schema, table))
        label = "'" + (schema + '.' + table).replace("'", "''") + "'"
        selects.append("SELECT json_build_array(" + label + ", count(*), coalesce(md5(string_agg(h, '' ORDER BY h "
                       "COLLATE \"C\")), '')) AS v FROM (SELECT md5(to_jsonb(t)::text) AS h FROM " + quoted + " t) s")
    result = {}
    if selects:
        # One statement: one snapshot for every table, one podman exec.
        # No SET in the same -c string (psql >= 15 prints every result); both servers run in UTC (time_zone event).
        rows = db.query_json("SELECT json_agg(v) FROM (" + " UNION ALL ".join(selects) + ") u", 'litellm')
        result = {name: [count, digest] for name, count, digest in rows}
    result['sequence-state'] = hashlib.sha256(json.dumps(db.query_json(SEQUENCES, 'litellm')).encode()).hexdigest()
    return result


def schema_difference(source, target):
    """Counts of schema items per kind present on one side only (no names: they could carry data)."""
    a = {json.dumps(item) for item in source or []}
    b = {json.dumps(item) for item in target or []}
    def by_kind(items):
        kinds = {}
        for text in items:
            kind = json.loads(text)[0]
            kinds[kind] = kinds.get(kind, 0) + 1
        return dict(sorted(kinds.items()))
    return by_kind(a - b), by_kind(b - a)


def printable_counts(found):
    """Row counts of tables whose names carry no secret word (owner rule); secret-named ones are compared only."""
    return {name.split('.', 1)[1][:40]: value[0] for name, value in sorted(found.items())
            if name != 'sequence-state' and not SECRET_NAME.search(name)}


def dump(tmp, role, user):
    data = tmp.exec(role, ['pg_dump', '-U', user, '-d', 'litellm', '--no-owner', '--no-acl'], user='postgres',
                    timeout=600, max_output=MAX_DUMP).stdout
    require(data and len(data) <= MAX_DUMP, 'dump_bound')
    return data


def recreate_and_load(tmp, db, data):
    """The package's scripts/restore.sh order: drop and create the database, then load (here a plain dump, one
    transaction, stop at the first error; nothing in the dump is rewritten)."""
    for statement in RECREATE:
        db.statement(statement, 'postgres')
    tmp.exec(db.role, ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-1', '-U', db.superuser, '-d', 'litellm',
                       '-f', '-'], user='postgres', input=data, timeout=900, max_output=1024 * 1024)


def quiesce(db):
    for _ in range(20):
        active = db.query_json("SELECT to_json(count(*)) FROM pg_stat_activity WHERE datname='litellm' "
                               "AND backend_type='client backend' AND pid<>pg_backend_pid()", 'postgres')
        if active == 0:
            return
        time.sleep(1)
    raise Failed('database_sessions_not_quiesced')


# ---------------------------------------------------------------- app helpers

PRINTABLE_LABELS = {'vkey_models': 'client_models', 'issued_key_info': 'issued_client_status',
                    'test_key_status': 'ha_client_status', 'test_key_alias_matches': 'ha_client_alias_matches'}


def printable(counts):
    """Worker counts under names without the owner's secret words (values are counts or statuses only)."""
    out = {}
    for key, value in counts.items():
        key = PRINTABLE_LABELS.get(key, key)
        if not SECRET_NAME.search(key) and isinstance(value, (bool, int)):
            out[key] = value
    return out


CHECKS = {}


def soft(name, condition):
    """A result check that does not stop the run (later stages still give evidence); the final status needs all."""
    CHECKS[name] = bool(condition)
    return bool(condition)


def worker(tmp, role, action, env, **fields):
    payload = json.dumps(dict(action=action, env=env, **fields)) + '\n'
    result = tmp.exec(role, ['python', '-I', '-c', WORKER], input=payload.encode(),
                      timeout=660 if action == 'start' else 300, max_output=8192, check=False)
    out = result.stdout or b''
    try:
        reply = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
    except ValueError:
        reply = {}
    for key in reply.get('issued', []) if isinstance(reply, dict) else []:
        LEDGER.register('issued.virtual_key', key)          # registered before anything else uses the reply
    if result.returncode != 0 or not isinstance(reply, dict) or reply.get('ok') is not True:
        private_note(b'worker ' + action.encode() + b' rc=' + str(result.returncode).encode() + b'\n' +
                     getattr(getattr(tmp, 'runner', None), 'last_stderr', b''))
        raise Failed('worker_' + action.replace('-', '_'))
    return reply


def app_start(tmp, role, network, env):
    tmp.memory = APP_MEMORY
    # dev-d maps IDs 0..55000 only: image USER 65534 cannot start here; non-root 1000 with GID 0 (rehearsal choice).
    tmp.run(role, APP_IMAGE, ['-I', '-c', 'import time; time.sleep(3600)'], entrypoint='python', user='1000:0',
            detach=True, network=network)
    tmp.exec(role, ['python', '-I', '-c',
                    "import os; from pathlib import Path; "
                    "root=Path('/app/.venv/lib/python3.13/site-packages/prisma'); "
                    "paths=[root]+list(root.rglob('*')); "
                    "[os.chown(p,1000,0,follow_symlinks=False) for p in paths]"],
             user='0', timeout=120, max_output=4096)
    started = time.monotonic()
    worker(tmp, role, 'start', env)
    return round(time.monotonic() - started, 1)


def app_stop(tmp, role):
    tmp.stop(role, timeout=20)
    tmp.remove(role)


def target_env(host, pg_password, master, salt, ui_password):
    url = f'postgresql://litellm:{pg_password}@{host}:5432/litellm'
    LEDGER.register('target.database_url', url)
    # The package's litellm.container environment (dd690ae) minus the ChatGPT subscription restore.
    return {'DATABASE_HOST': host, 'DATABASE_USERNAME': 'litellm', 'DATABASE_PASSWORD': pg_password,
            'DATABASE_NAME': 'litellm', 'DATABASE_URL': url, 'LITELLM_MASTER_KEY': master, 'LITELLM_SALT_KEY': salt,
            'UI_USERNAME': 'admin', 'UI_PASSWORD': ui_password, 'STORE_MODEL_IN_DB': 'True',
            'LITELLM_MODE': 'PRODUCTION', 'LITELLM_LOG': 'ERROR', 'DISABLE_SCHEMA_UPDATE': 'true',
            'LITELLM_LOCAL_MODEL_COST_MAP': 'True', 'LITELLM_TELEMETRY': 'False', 'PYTHONPATH': '/opt/woow/plugin',
            'WOOW_UI_TOKEN_HTTPONLY': 'true', 'WOOW_UI_SESSION_POLICY_VERSION': '2',
            'WOOW_MAX_REQUEST_SIZE_MB': '32', 'WOOW_CHATGPT_ENABLED': 'false', 'WOOW_PROXY_PORT': '4000'}


def ha_server_args():
    """ha_odoo.HA_SERVER_SETTINGS (every library/command setting off, socket only) with this mount's file paths."""
    args = ['postgres']
    for setting in ha_odoo.HA_SERVER_SETTINGS:
        if setting.startswith('hba_file='):
            setting = f'hba_file={HA_PGDATA}/pg_hba.conf'
        elif setting.startswith('ident_file='):
            setting = f'ident_file={HA_PGDATA}/pg_ident.conf'
        args += ['-c', setting]
    return args + ['-c', 'shared_buffers=16MB']


# ---------------------------------------------------------------- the run

def load_secrets():
    import ha_import_b1_e2e as b1
    s = b1.Secrets([b1.SECRET_DIR / 'b1-creds.env', b1.SECRET_DIR / 'ha-import-creds.env'],
                   b1.SECRET_DIR / 'dev-d-markers.json')
    return s['HA_BACKUP_KEY'], s['LITELLM_TEST_VKEY']


def fixture_sha256():
    digest = hashlib.sha256()
    with open(FIXTURE, 'rb') as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run(args):
    global LEDGER
    started = time.monotonic()
    LEDGER = Ledger(SOURCES)
    emit('source_commit', commit=git('rev-parse', 'HEAD'), clean_tree=not git('status', '--porcelain'))
    require(not git('status', '--porcelain'), 'dirty_tree')
    require(fixture_sha256() == FIXTURE_SHA256, 'fixture_sha256_mismatch')
    emit('real_source', fixture_sha256_matches_record=True, addon='woow-litellm', arch='x86', encrypted=True)
    backup_key, test_vkey = load_secrets()
    LEDGER.register('lab.ha_backup_key', backup_key)
    LEDGER.register('lab.test_virtual_key', test_vkey)

    # The public import stays blocked: only the internal candidate reader is used below.
    try:
        candidate.convert(None, type('App', (), {'id': 'litellm'})(), False, None)
    except BackupError as error:
        require(error.code == 'incompatible' and error.message == candidate.GUARD, 'public_guard_changed')
    else:
        raise Failed('public_guard_missing')
    require('litellm' not in haimport.APPS, 'litellm_registered_publicly')
    emit('public_guard', convert_refuses=True, not_registered=True)

    keys = hasecuretar.Keys(backup_key)
    with habackup.open_backup(FIXTURE) as ha:
        found = [m for m in ha.layout.members if m.role == 'addon' and hastore.addon_suffix(m.slug) == candidate.SLUG]
        require(len(found) == 1, 'addon_member_count')
        member = found[0]
        with ha.open_member(member.name, keys) as stream:
            source = candidate.scan_member(stream)
        require((source.addon_version, source.product_version, source.pg_major) == ('0.1.15', '1.104.0', 18),
                'source_versions')
        require(source.control_present and source.salt_valid, 'source_files')
        emit('source_scan', addon_version=source.addon_version, product_version=source.product_version,
             pg_major=source.pg_major, control_present=True, salt_file_valid=True, member_encrypted=member.encrypted)
        if not args.run:
            emit('offline_ok', note='no_lab_operation')
            return 0

        verify_isolation('isolation_before')
        lock_fd = acquire_lock()
        lock_started = time.monotonic()
        runner = DevDRunner()
        try:
            return lab_run(args, ha, member, keys, runner, test_vkey, started, lock_started)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
            emit('lock_released', held_s=int(time.monotonic() - lock_started))


def lab_run(args, ha, member, keys, runner, test_vkey, started, lock_started):
    cgroup = outer_cgroup()
    headroom(runner, cgroup)
    baseline_running = running_names(runner)
    job = 'j' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(4)
    secret_name = f'woowbk-{job}-pgpass'
    secret_made = False
    passed = False
    notes = []
    master, ui_password = 'sk-' + secrets.token_hex(32), secrets.token_urlsafe(24)
    pg_password, target_salt = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    seed_credential = 'sk-lab-' + secrets.token_hex(24)
    for source, value in (('target.master_key', master), ('target.ui_password', ui_password),
                          ('target.pg_password', pg_password), ('target.salt_key', target_salt),
                          ('target.seed_credential', seed_credential)):
        LEDGER.register(source, value)
    stage = 'start'
    try:
        with FreshLabObjects(runner, job, memory='256m', pids=512, cpus=None, log=notes.append,
                             abort=pressure_guard(cgroup)) as tmp:
            network = tmp.network('net')
            # 1. HA's cluster into a throwaway PostgreSQL 18 (no network, read-only root, noexec data volume).
            stage = 'source_cluster'
            uid, gid = tmp.user_ids('ids18', PG18_IMAGE, 'postgres')
            holder = {}

            def produce(out):
                sink = ha_odoo.PgSink(out, uid, gid)
                with ha.open_member(member.name, keys) as stream:
                    holder['src'] = candidate.cluster_member(stream, sink)
                sink.close()

            tmp.volume('hapg')
            tmp.volume_import('hapg', produce)
            src = holder['src']
            for name in candidate.SECRET_NAMES:
                LEDGER.register('ha.' + name, src.secrets.value(name))
            ha_salt = src.secrets.value('salt_key').decode('ascii')
            require(src.pg_version == '18', 'source_cluster_major')
            emit('source_cluster_streamed', pg_files=src.pg_files, pg_mib=src.pg_bytes // 2 ** 20,
                 ha_private_files=len(src.secrets.names()))
            tmp.memory = '256m'
            tmp.run('hapg', PG18_IMAGE, ha_server_args(), detach=True, read_only_root=True,
                    env={'PGDATA': HA_PGDATA}, volumes=[(tmp.name('hapg'), HA_PGDATA, 'rw,noexec,nosuid,nodev')])
            hapg = ha_odoo.Cluster(tmp, 'hapg')
            hapg.wait_ready(timeout=300)
            require(hapg.query_json("SELECT to_json(current_setting('server_version_num')::int/10000)", 'litellm')
                    == 18, 'source_server_major')
            hapg.script(READER_SQL, 'litellm')
            binding = candidate.read_source_salt_binding(hapg, ha_salt.encode('ascii'))
            negative = candidate.read_source_salt_binding(hapg, target_salt.encode('ascii'))
            emit('source_salt_binding', ha_salt=binding, other_salt=negative)
            soft('source_salt_binding_match', binding == 'match')
            soft('source_salt_binding_discriminates', negative == 'mismatch')
            source_tz = hapg.query_json("SELECT to_json(current_setting('TimeZone'))", 'litellm')
            source_schema = hapg.query_json(SCHEMA, 'litellm')
            source_rows = digests(hapg)
            source_dump = dump(tmp, 'hapg', 'postgres')
            emit('source_inventory', tables=len(source_rows) - 1, dump_mib=round(len(source_dump) / 2 ** 20, 1),
                 counts=printable_counts(source_rows))
            tmp.stop('hapg', timeout=20)
            tmp.remove('hapg')
            tmp.remove_volume('hapg')
            emit('source_cluster_released', ok=True)

            # 2. The package's PostgreSQL 17 with its own password (Podman secret from stdin) and its own app data.
            stage = 'target_db'
            runner.podman('secret', 'create', secret_name, '-', input=pg_password.encode(), max_output=4096)
            secret_made = True
            tmp.volume('target-data')
            tmp.memory = '256m'
            tmp.run('target', PG17_IMAGE, ['postgres', '-c', 'shared_buffers=16MB', '-c', 'max_connections=40'],
                    detach=True, network=network, read_only_root=True,
                    env={'POSTGRES_USER': 'litellm', 'POSTGRES_DB': 'litellm',
                         'POSTGRES_PASSWORD_FILE': '/run/secrets/postgres-password',
                         'PGDATA': '/var/lib/postgresql/data/pgdata'},
                    volumes=[(tmp.name('target-data'), '/var/lib/postgresql/data', 'rw,noexec,nosuid,nodev')],
                    secrets=[f'{secret_name},type=mount,target=/run/secrets/postgres-password,mode=0400'])
            target = ha_odoo.Cluster(tmp, 'target', superuser='litellm')
            target.wait_ready(tcp=True, timeout=300)
            require(target.query_json("SELECT to_json(current_setting('server_version_num')::int/10000)", 'litellm')
                    == 17, 'target_server_major')
            target_tz = target.query_json("SELECT to_json(current_setting('TimeZone'))", 'litellm')
            soft('both_servers_utc', source_tz in ('UTC', 'Etc/UTC') and target_tz in ('UTC', 'Etc/UTC'))
            emit('time_zone', source=str(source_tz)[:20].replace('/', '_'), target=str(target_tz)[:20].replace('/', '_'))
            host = tmp.name('target')
            env_before = target_env(host, pg_password, master, target_salt, ui_password)
            env_after = dict(env_before, LITELLM_SALT_KEY=ha_salt)
            emit('target_db_ready', pg_major=17, scram_auth=True)

            stage = 'target_before'
            seconds = app_start(tmp, 'target-before', network, env_before)
            worker(tmp, 'target-before', 'seed', env_before, marker='woowbk-rollback-marker', credential=seed_credential)
            worker(tmp, 'target-before', 'verify', env_before, marker='woowbk-rollback-marker',
                   credential=seed_credential)
            app_stop(tmp, 'target-before')
            quiesce(target)
            before_schema = target.query_json(SCHEMA, 'litellm')
            before_rows = digests(target)
            before_dump = dump(tmp, 'target', 'litellm')
            only_ha, only_target = schema_difference(source_schema, before_schema)
            emit('target_before', app_start_s=seconds, own_model_seeded=True, own_provider_value_decrypts=True,
                 schema_items_only_in_ha=only_ha, schema_items_only_in_target=only_target)

            # 3. Import: the package restore order, HA's dump, HA's salt moved; target keeps its other credentials.
            stage = 'import'
            recreate_and_load(tmp, target, source_dump)
            restored_rows = digests(target)
            restored_schema = target.query_json(SCHEMA, 'litellm')
            only_source, only_restored = schema_difference(source_schema, restored_schema)
            rows_equal = soft('restored_rows_equal_source',
                              {k: v for k, v in restored_rows.items() if k != 'sequence-state'}
                              == {k: v for k, v in source_rows.items() if k != 'sequence-state'})
            sequences_equal = soft('restored_sequences_equal_source',
                                   restored_rows['sequence-state'] == source_rows['sequence-state'])
            schema_equal = soft('restored_schema_equal_source', restored_schema == source_schema)
            emit('ha_restored', all_tables_rows_equal=rows_equal, sequences_equal=sequences_equal,
                 schema_equal=schema_equal, schema_items_only_in_ha=only_source,
                 schema_items_only_in_restored=only_restored,
                 tables_differing=sum(1 for k in source_rows.keys() | restored_rows.keys()
                                      if source_rows.get(k) != restored_rows.get(k)))

            stage = 'target_after'
            seconds = app_start(tmp, 'target-after', network, env_after)
            reply = worker(tmp, 'target-after', 'ha-verify', env_after, test_vkey=test_vkey,
                           expected_alias=EXPECTED_ALIAS, wrong_salt=target_salt,
                           issued_alias='woowbk-lab-issued-' + secrets.token_hex(4))
            counts = reply['counts']
            issued_key = reply['issued'][0]
            soft('ha_client_accepted', counts['test_key_status'] == 200)
            soft('ha_client_alias_matches', counts['test_key_alias_matches'] is True)
            soft('ha_client_sees_models', counts['vkey_models'] >= 1)
            soft('issued_client_usable', counts['issued_key_info'] == 200)
            soft('salt_row_matches', counts['salt_row_matches'] is True)
            soft('model_values_all_decrypt', counts['model_values'] > 0
                 and counts['model_values_ok'] == counts['model_values'])
            soft('stored_values_all_decrypt', counts['stored_values_ok'] == counts['stored_values'])
            soft('wrong_salt_decrypts_nothing', counts['model_values_wrong_ok'] == 0
                 and counts['stored_values_wrong_ok'] == 0)
            soft('app_serves_all_stored_models', counts['api_models'] >= counts['db_models'])
            emit('ha_import_verified', app_start_s=seconds, **printable(counts))

            stage = 'restart'
            if time.monotonic() - lock_started < SOFT_DEADLINE:
                app_stop(tmp, 'target-after')
                seconds = app_start(tmp, 'target-restart', network, env_after)
                again = worker(tmp, 'target-restart', 'recheck', env_after, test_vkey=test_vkey,
                               expected_alias=EXPECTED_ALIAS, issued_key=issued_key)['counts']
                same = soft('restart_counts_equal', all(again[key] == counts[key] for key in
                                                       ('vkey_models', 'api_models', 'users', 'teams', 'db_models',
                                                        'orgs')))
                issued_ok = soft('restart_issued_client_usable', again['issued_key_info'] == 200)
                ha_ok = soft('restart_ha_client_accepted', again['test_key_status'] == 200)
                emit('restart_verified', app_start_s=seconds, counts_equal=same, ha_client_accepted=ha_ok,
                     issued_client_accepted=issued_ok)
                app_stop(tmp, 'target-restart')
            else:
                emit('restart_skipped', reason='soft_deadline')
                app_stop(tmp, 'target-after')

            # 4. The target's own salt cannot open the imported database (db_prepare refuses, rows unchanged).
            stage = 'salt_controls'
            quiesce(target)
            tmp.memory = '512m'
            tmp.run('salt-controls', APP_IMAGE, ['-I', '-c', 'import time; time.sleep(3600)'], entrypoint='python',
                    user='1000:0', detach=True, network=network)
            unchanged = digests(target)
            worker(tmp, 'salt-controls', 'salt-refusal', env_before)
            worker(tmp, 'salt-controls', 'salt-accept', env_after)
            rows_kept = soft('salt_checks_rows_unchanged', digests(target) == unchanged)
            app_stop(tmp, 'salt-controls')
            emit('wrong_salt_refused', db_prepare_refuses_target_salt=True, ha_salt_accepted=True,
                 rows_unchanged=rows_kept)

            # 5. Rollback to the target's own data and salt.
            stage = 'rollback'
            recreate_and_load(tmp, target, before_dump)
            back_rows = soft('rollback_rows_equal_before', digests(target) == before_rows)
            back_schema = soft('rollback_schema_equal_before', target.query_json(SCHEMA, 'litellm') == before_schema)
            seconds = app_start(tmp, 'target-rollback', network, env_before)
            worker(tmp, 'target-rollback', 'verify', env_before, marker='woowbk-rollback-marker',
                   credential=seed_credential)
            gone = worker(tmp, 'target-rollback', 'rollback-verify', env_before, test_vkey=test_vkey,
                          issued_key=issued_key)['counts']
            soft('rollback_removes_ha_and_issued_clients', gone['test_vkey_status'] == 401
                 and gone['issued_key_status'] == 401)
            app_stop(tmp, 'target-rollback')
            emit('rollback_verified', app_start_s=seconds, rows_equal_before=back_rows,
                 schema_equal_before=back_schema, own_provider_value_decrypts=True,
                 ha_client_status=gone['test_vkey_status'], issued_client_status=gone['issued_key_status'])
            passed = True
    except Failed as exc:
        emit('failed', at=stage, label=str(exc))
        private_note(traceback.format_exc().encode())
    except Exception as exc:  # noqa: BLE001 - classified, details private
        emit('failed', at=stage, label='exception_' + type(exc).__name__)
        private_note(traceback.format_exc().encode())
    finally:
        if secret_made:
            runner.podman('secret', 'rm', secret_name, check=False, max_output=4096)
        stage = 'cleanup'
    try:
        leftovers = {kind: [name for name in runner.podman(*argv, max_output=262144).stdout.decode().split()
                            if job in name] for kind, argv in (
            ('containers', ('ps', '-a', '--format', '{{.Names}}')),
            ('volumes', ('volume', 'ls', '--format', '{{.Name}}')),
            ('networks', ('network', 'ls', '--format', '{{.Name}}')),
            ('secrets', ('secret', 'ls', '--format', '{{.Name}}')))}
        after_running = running_names(runner)
    except BackupError:
        leftovers = {'containers': ['?'], 'volumes': [], 'networks': [], 'secrets': []}
        after_running = []
    clean = not any(leftovers.values()) and not notes
    emit('cleanup_verified' if clean else 'cleanup_incomplete', containers=len(leftovers['containers']),
         volumes=len(leftovers['volumes']), networks=len(leftovers['networks']), secrets=len(leftovers['secrets']),
         notes=len(notes))
    baseline_ok = after_running == baseline_running
    emit('baseline_unchanged' if baseline_ok else 'baseline_changed', running=len(after_running))
    verify_isolation('isolation_after')
    try:
        scan = LEDGER.require_clean(EVENTS)
        emit('leak_scan', sources=scan['sources'], values=scan['values'], lines=len(EVENTS), matches=0,
             missing_sources=0)
        scanned = True
    except CoverageError as exc:
        missing = LEDGER.missing()
        emit('leak_scan_failed', missing_sources=len(missing), missing=[m.replace('.', '_') for m in missing],
             detail='matches' if not missing else 'missing')
        private_note(str(exc).encode())
        scanned = False
    failed_checks = sorted(name for name, value in CHECKS.items() if not value)
    emit('checks', passed=sum(CHECKS.values()), total=len(CHECKS), failed=failed_checks)
    ok = passed and clean and baseline_ok and scanned and not failed_checks
    emit('result', status='PASS' if ok else 'FAIL', elapsed_s=int(time.monotonic() - started),
         commercial_acceptance='not-complete')
    return 0 if ok else 1


def main(argv=None):
    global PRIVATE
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--run', action='store_true', help='operate dev-d (otherwise: offline source checks only)')
    parser.add_argument('--outer-isolation-confirmed', action='store_true')
    parser.add_argument('--private-dir', default='')
    args = parser.parse_args(argv)
    if args.run and not args.outer_isolation_confirmed:
        parser.error('--run needs --outer-isolation-confirmed (dev-d network none, no ports)')
    if args.private_dir:
        PRIVATE = Path(args.private_dir)
        require(not PRIVATE.resolve().is_relative_to(REPO), 'private_dir_inside_repository')
    try:
        return run(args)
    except Failed as exc:
        emit('failed', at='preflight', label=str(exc))
        emit('result', status='FAIL', commercial_acceptance='not-complete')
        return 1


if __name__ == '__main__':
    sys.exit(main())
