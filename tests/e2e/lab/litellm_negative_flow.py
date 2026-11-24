#!/usr/bin/env python3
"""Real NEGATIVE run of the LiteLLM product import on dev-d (lane litellm-product, 2026-11-24): crafted HA LiteLLM
backups go through the same Cockpit helper commands a customer's backup goes through and must be REFUSED with the
specific message, with this device unchanged.

Why: refusals were proven by unit tests and by the review's sandbox (single steps on real PostgreSQL 18.7); the
product's own convert() had never been run on the crafted data directory of review SR-8 (verifier 2026-11-24 02:14).

  python3 -I tests/e2e/lab/services_a_capture.py --private=FILE <evidence.json> "<scope>" -- \
      python3 -I tests/e2e/lab/litellm_negative_flow.py --run

Setup and cleanup are litellm_full_flow.py's (the engine of this tree, the LiteLLM package deployed into dev-d, its own
generated data, everything removed again); the lock, isolation, headroom and leak rules are the same.

The crafted backups hold generated data only (no real backup, no real provider key): this lab LiteLLM's own database
(pg_dump in dev-d) is loaded as the non-superuser owner `litellm` into a throwaway PostgreSQL 18.7 of the isolated LAB
Podman store (the product's pinned image, --network=none: litellm_sandbox_review's method), bound to a generated salt
(woow_platform.settings + woow.meta fingerprint), stopped cleanly and packed as a plain (unencrypted) HA add-on backup
with generated secret files. Cases, each: upload -> ha-check-start -> ha-convert-start:

  salt     the salt file is not the salt HA's database is bound to
  version  an add-on version this import does not know (0.1.14)
  hooks    LiteLLM_Config holds settings that load code (post_call_rules, custom_auth, a guardrail module, a module
           pass-through target, router plugins, a dotted callback behind 60 plain names)
  hidden   review SR-8: the same kind of hooks, and the data directory's superuser pointed the built-in text equality
           operator at a function that hides their names, so HA's side (the check) is blind; the conversion decides
           again on the rows that moved and must refuse BEFORE the converted backup is written

Expected: check answers not ok with that blocker (hidden: the check is blind -- recorded as found, not as a pass of
the check) and the conversion ends failed with that message; no converted backup, no throwaway object, no staging
left, and this device's own LiteLLM (secrets, salt, data, schema, keys) is the one before the run.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets as pysecrets
import shutil
import sys
import tarfile
import tempfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


flow = _load('litellm_full_flow')
review = _load('litellm_sandbox_review')      # puts backup-engine on sys.path
drv = flow.drv
Failed = flow.Failed
emit = flow.emit

from woowbackup import ha_litellm, ha_odoo, tempctr  # noqa: E402

SLUG = 'c0ffee01_woow-litellm'
VERSION, UPSTREAM, OTHER_VERSION = '0.1.15', '1.104.0', '0.1.14'
CONFIG = 'public."LiteLLM_Config"'
HOOK = review.HOOK
# The label names the product must give (ha_litellm.MODULE_HOOKS / NESTED_HOOKS): one of each kind.
HOOK_ROWS = {
    'litellm_settings': {'post_call_rules': HOOK,
                         'guardrails': [{'guardrail_name': 'woowbk_g2',
                                         'litellm_params': {'guardrail': HOOK, 'mode': 'pre_call'}}],
                         'success_callback': [f'a{i:02d}' for i in range(60)] + ['zz_woowbk.review_marker']},
    'general_settings': {'custom_auth': HOOK, 'pass_through_endpoints': [{'path': '/woowbk', 'target': HOOK}]},
    'router_settings': {'plugins': [HOOK]},
}
HOOK_LABELS = ('litellm_settings.post_call_rules', 'litellm_settings.guardrails', 'litellm_settings.success_callback',
               'general_settings.custom_auth', 'general_settings.pass_through_endpoints', 'router_settings.plugins')
HIDDEN_ROWS = {'litellm_settings': {'post_call_rules': HOOK}, 'general_settings': {'custom_auth': HOOK}}
HIDDEN_LABELS = ('litellm_settings.post_call_rules', 'general_settings.custom_auth')
# review's T2 operator edit without its LiteLLM_Config rows (config_sql writes ours)
OPERATOR_SQL = review.T2_SQL[review.T2_SQL.index('CREATE FUNCTION public.woowbk_texteq'):]
HOOK_WORDS = '在資料庫裡存了會載入並執行程式的設定'   # not the text of an unreadable answer
MIN_HOST_AVAILABLE_KIB = 900 * 1024


def config_sql(rows):
    """LiteLLM_Config rewritten to exactly `rows` {param_name: JSON value}."""
    return f'DELETE FROM {CONFIG};\n' + ''.join(
        f"INSERT INTO {CONFIG} (param_name, param_value) VALUES ('{name}', {review._j(value)});\n"
        for name, value in rows.items())


def bind_sql(salt):
    fingerprint = hashlib.sha256(b'woow-litellm-salt-v1:' + salt.encode()).hexdigest()[:16]
    return ("CREATE SCHEMA woow AUTHORIZATION postgres;\n"
            "CREATE TABLE woow.meta (key text PRIMARY KEY, value text NOT NULL);\n"
            f"INSERT INTO woow.meta VALUES ('salt_fingerprint_v1', '{fingerprint}');\n"
            f"UPDATE woow_platform.settings SET value = '{salt}' WHERE key = 'litellm_salt_key';\n")


def craft(dump, salt, scratch):
    """{'clean'|'hooks'|'hidden': exported volume tar} of one throwaway PostgreSQL 18 cluster of the LAB store."""
    runner = review.LabRunner()
    exports = {}
    with tempctr.TempObjects(runner, review.job_id('negcraft'), memory='1g', pids=512, cpus='1') as tmp:
        tmp.volume('craft')

        def start():
            tmp.run('craft', review.PG18, ['postgres'], detach=True,
                    env={'POSTGRES_HOST_AUTH_METHOD': 'trust', 'PGDATA': review.CRAFT_DATA},
                    volumes=[(tmp.name('craft'), '/var/lib/postgresql', 'rw')])
            cluster = ha_odoo.Cluster(tmp, 'craft')
            cluster.wait_ready(tcp=True)
            return cluster

        def export(name):
            if tmp.stop('craft', timeout=90) != 0:  # a clean (cold) stop, like the add-on's cold backup
                raise Failed('the crafted cluster did not stop cleanly')
            tmp.remove('craft')
            path = scratch / f'{name}-volume.tar'
            with open(path, 'xb') as handle:
                os.fchmod(handle.fileno(), 0o600)
                tmp.volume_export('craft', handle)
            exports[name] = path

        cluster = start()
        cluster.statement('CREATE ROLE litellm LOGIN NOSUPERUSER', 'postgres')
        cluster.statement("CREATE DATABASE litellm OWNER litellm ENCODING 'UTF8' TEMPLATE template0", 'postgres')
        tmp.exec('craft', ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'litellm', '-d', 'litellm', '-f', '-'],
                 user='postgres', input=dump, max_output=1024 * 1024, timeout=900)
        cluster.script(bind_sql(salt), 'litellm')
        export('clean')
        cluster = start()
        cluster.script(config_sql(HOOK_ROWS), 'litellm')
        export('hooks')
        cluster = start()
        cluster.script(config_sql(HIDDEN_ROWS), 'litellm')
        cluster.script(OPERATOR_SQL, 'litellm')
        export('hidden')
    return exports


def addon_doc(version):
    return {'user': {'version': version, 'image': 'ghcr.io/woowtech/woow-ha-litellm-amd64', 'options': {}},
            'system': {'slug': 'woow-litellm', 'name': 'Woow LiteLLM', 'version': version, 'arch': ['amd64']},
            'version': version, 'state': 'started'}


def write_backup(export, path, secret_files, *, version=VERSION, upstream=UPSTREAM):
    """A plain HA backup (partial, the one add-on) around an exported volume tar; streamed, 0600, never overwritten."""
    inner_path = path.with_suffix('.inner')
    with open(inner_path, 'xb') as raw:
        os.fchmod(raw.fileno(), 0o600)
        with gzip.GzipFile(fileobj=raw, mode='wb', compresslevel=1, mtime=0) as packed, \
                tarfile.open(fileobj=packed, mode='w|', format=tarfile.PAX_FORMAT) as dest:
            def add(name, data=None, kind=tarfile.REGTYPE, mode=0o600):
                info = tarfile.TarInfo(name)
                info.type, info.mode, info.uid, info.gid, info.mtime = kind, mode, 70, 70, 1763900000
                if data is not None:
                    info.size = len(data)
                dest.addfile(info, io.BytesIO(data) if data is not None else None)
            add('.', kind=tarfile.DIRTYPE, mode=0o755)
            add('./addon.json', json.dumps(addon_doc(version)).encode(), mode=0o644)
            for folder in ('data', 'data/secrets', 'data/woow', 'data/postgres'):
                add(folder, kind=tarfile.DIRTYPE, mode=0o700)
            for name, value in sorted(secret_files.items()):
                add(f'data/secrets/{name}', value.encode() + b'\n')
            add('data/woow/state.json', json.dumps({'litellm_version': upstream}).encode())
            with tarfile.open(export, mode='r') as source:
                for info in source:
                    name = info.name.lstrip('./') if info.name not in ('.', './') else ''
                    rel = name[len('craft'):].lstrip('/') if name == 'craft' or name.startswith('craft/') else ''
                    if not rel:
                        continue
                    info.name = f'data/postgres/{rel}'
                    if info.isfile():
                        dest.addfile(info, source.extractfile(info))
                    elif info.isdir():
                        dest.addfile(info)
                    else:
                        raise Failed('unexpected member in the crafted cluster')
    doc = {'slug': 'c0ffee02', 'version': 2, 'name': 'woowbk-negative', 'date': '2026-11-24T00:00:00.000000+00:00',
           'type': 'partial', 'supervisor_version': '2026.11.0', 'extra': {}, 'homeassistant': None,
           'repositories': [], 'compressed': True, 'protected': False, 'folders': [],
           'addons': [{'slug': SLUG, 'name': 'Woow LiteLLM', 'version': version, 'size': 0.0}]}
    with open(path, 'xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        with tarfile.open(fileobj=handle, mode='w', format=tarfile.PAX_FORMAT) as outer, open(inner_path, 'rb') as inner:
            info = tarfile.TarInfo(f'{SLUG}.tar.gz')
            info.size, info.mtime = inner_path.stat().st_size, 1763900000
            outer.addfile(info, inner)
            data = json.dumps(doc).encode()
            info = tarfile.TarInfo('./backup.json')
            info.size, info.mtime = len(data), 1763900000
            outer.addfile(info, io.BytesIO(data))
    inner_path.unlink()
    return path


class NegativeRun(flow.Run):
    def __init__(self, args, ev):
        super().__init__(args, ev)
        self.stores, self.scratch, self.files, self.salt = [], None, {}, None
        self.backup_ids = None

    # -------- generated secrets only (the harness reader's values are used for the leak scan and the refused key)
    def load_secrets(self):
        s = self.args.secrets
        for name in ('HA_BACKUP_KEY', 'LITELLM_TEST_VKEY'):
            if not s.values.get(name):
                raise Failed(f'{name} missing from the harness reader')
        self.salt = 'sk-' + pysecrets.token_hex(32)
        self.files = {'salt_key': self.salt, 'master_key': 'sk-' + pysecrets.token_hex(32),
                      'pg_password': pysecrets.token_hex(24), 'ui_password': pysecrets.token_hex(24)}
        for name, value in self.files.items():
            s.register(f'HA_LITELLM_CRAFTED_{name.upper()}', value)
        s.register('HA_LITELLM_CRAFTED_OTHER_SALT', 'sk-' + pysecrets.token_hex(32))
        self.ha_salt_sha = hashlib.sha256(self.salt.encode()).hexdigest()
        self.own_key = 'sk-woowbk-own-' + pysecrets.token_hex(20)
        s.register('OWN_LITELLM_KEY', self.own_key)
        s.register('OWN_SEED_CREDENTIAL', 'sk-woowbk-seed-' + pysecrets.token_hex(20))
        s.register('WRONG_SALT', 'sk-' + pysecrets.token_hex(32))
        self.ev.check('secrets: generated values for the crafted backups, own key and seed registered (memory only; no '
                      'real backup is read)', True, '')

    def add_stub(self):
        """Option A's stub belongs to the full flow; nothing here needs it."""

    # -------- the crafted backups
    def step_craft(self):
        ev, s = self.ev, self.args.secrets
        available = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                         if line.startswith('MemAvailable:'))
        if available < MIN_HOST_AVAILABLE_KIB:
            raise Failed('host MemAvailable too low for crafting')
        started = time.monotonic()
        proc = drv.owner('podman', 'exec', 'litellm-postgres', 'pg_dump', '-U', 'litellm', '-d', 'litellm',
                         '--no-owner', '--no-acl', timeout=600)
        dump = proc.stdout
        if not ev.check("craft: this lab LiteLLM's own database dumped (generated data only)",
                        proc.returncode == 0 and len(dump) > 100000, {'rc': proc.returncode, 'bytes': len(dump)}):
            raise Failed('dump failed')
        run_dir = flow.LAB / 'run'
        run_dir.mkdir(mode=0o700, exist_ok=True)
        self.scratch = Path(tempfile.mkdtemp(prefix='litellm-negative-', dir=run_dir))
        os.chmod(self.scratch, 0o700)
        exports = craft(dump, self.salt, self.scratch)
        other = dict(self.files, salt_key=s['HA_LITELLM_CRAFTED_OTHER_SALT'])
        self.backups = {
            'salt': write_backup(exports['clean'], self.scratch / 'neg-salt.tar', other),
            'version': write_backup(exports['clean'], self.scratch / 'neg-version.tar', self.files,
                                    version=OTHER_VERSION),
            'hooks': write_backup(exports['hooks'], self.scratch / 'neg-hooks.tar', self.files),
            'hidden': write_backup(exports['hidden'], self.scratch / 'neg-hidden.tar', self.files)}
        for path in exports.values():
            path.unlink()
        left = [n for n in drv.out(drv.run([str(review.LABPODMAN), 'ps', '-a', '--format', '{{.Names}}'],
                                           timeout=120)).split() if n.startswith('woowbk-j') and n.endswith('-craft')]
        ev.check('craft: four crafted plain HA backups written (0600), no craft container left in the lab store',
                 len(self.backups) == 4 and not left,
                 {'bytes': {k: p.stat().st_size for k, p in self.backups.items()}, 'left': left,
                  'took_s': round(time.monotonic() - started, 1)})

    # -------- one case: upload, check, convert
    def step_case(self, case):
        ev = self.ev
        path = self.backups[case]
        rc, reply = drv.upload(path, ev=ev)
        meta = reply.get('ha_backup') or {}
        path.unlink()
        store_id = meta.get('id')
        if store_id:
            self.stores.append(store_id)
        found = {a['app_id']: a['installed'] for a in meta.get('importable_apps') or []}
        if not ev.check(f'{case}: the crafted backup is uploaded through upload-begin and upload-finish and LiteLLM is '
                        'importable here', rc == 0 and found.get('litellm') is True, {'rc': rc, 'found': found}):
            raise Failed('upload refused')
        if self.backup_ids is None:
            self.backup_ids = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        job, took = drv.run_check(store_id, ['litellm'], ev=ev, tag=f'neg-check-{case}')
        ev.check(f'{case}: ha-check-start job finished', job['state'] == 'succeeded', f'{took:.0f} s {job.get("error")}')
        result = ((job.get('result') or {}).get('ha_check') or {}).get('apps') or [{}]
        result = result[0]
        ev.save(f'{case}-check.json', result)
        blockers = [str(b) for b in result.get('blockers') or []]
        wanted, labels = self.wanted(case)
        if case == 'hidden':
            ev.check("hidden: HA's side is blind as the review found (the check shows no hook blocker: advisory under a "
                     'crafted data directory)', not any(HOOK_WORDS in b for b in blockers),
                     {'ok': result.get('ok'), 'blockers': blockers})
        else:
            ev.check(f'{case}: the check refuses with the specific message', result.get('ok') is False
                     and any(wanted in b for b in blockers) and all(any(x in b for b in blockers) for x in labels),
                     {'ok': result.get('ok'), 'blockers': blockers})
        job, took = drv.convert(store_id, ['litellm'], False, ev=ev, key=None, tag=f'neg-convert-{case}')
        log = '\n'.join(str(line) for line in (drv.ok('job-status', {'job_id': job['id']}, ev=ev).get('log') or []))
        ev.save(f'{case}-convert.json', job)
        ev.save(f'{case}-convert-log.txt', log)
        error = job.get('error') or {}
        message = str(error.get('message') if isinstance(error, dict) else error)
        ev.check(f'{case}: the conversion ends failed with the specific message (nothing converted)',
                 job['state'] == 'failed' and wanted in message and all(x in message for x in labels),
                 {'state': job['state'], 'message': message, 'took_s': round(took, 1)})
        ev.check(f'{case}: the failed conversion names no backup', not (job.get('result') or {}).get('backup_id'),
                 job.get('result'))
        if case == 'hidden':
            ev.check("hidden: the refusal came after HA's rows were loaded into the new cluster and before the converted "
                     'dump was written (SR-8 re-check in convert)',
                     '沒有任何管理權限的暫用角色' in log and '筆數都和 HA 相同' not in log,
                     {'log_lines': log.count('\n') + 1})
        elif case in ('salt', 'hooks'):
            ev.check(f"{case}: the refusal came before HA's rows were read for the import",
                     '匯出 HA 的 LiteLLM 資料' not in log, {'log_lines': log.count('\n') + 1})
        now = {b['id'] for b in drv.ok('list', ev=ev)['backups']}
        objects = drv.labelled()
        listing = drv.device_python(drv.RUN_LIST, as_owner=False)
        keys = [n for n in listing.get('/run/woowtech-backup') or [] if isinstance(n, str) and n.startswith('key-')]
        ev.check(f'{case}: no converted backup, throwaway object, staging folder or key file left',
                 now == self.backup_ids and not any(objects.values())
                 and listing.get(drv.STAGING) in ([], 'missing') and not keys,
                 {'new': sorted(now - self.backup_ids), 'objects': objects, 'run': listing})

    def wanted(self, case):
        """(text the message must hold, labels it must name)."""
        if case == 'salt':
            return ha_litellm.SALT_MISMATCH.split('，')[0], ()
        if case == 'version':
            return ha_litellm.VERSIONS.blocker(OTHER_VERSION, UPSTREAM).split('（')[0], ()
        return HOOK_WORDS, (HOOK_LABELS if case == 'hooks' else HIDDEN_LABELS)

    def step_unchanged(self):
        self.wait_units('after the refused imports')
        self.own_state('after the refused imports')
        drv.app_health(self.ev, 'litellm', 'after the refused imports')

    def step_cleanup(self):
        ev = self.ev
        if self.stores:
            answers = [drv.helper('ha-delete', {'ha_backup_id': store, 'confirm': True})[0] for store in self.stores]
            ev.check('cleanup: the HA store records of the crafted backups are deleted', not any(answers),
                     {'rc': answers})
        if self.scratch is not None:
            shutil.rmtree(self.scratch, ignore_errors=True)
            ev.check('cleanup: the crafted files on the host are deleted', not self.scratch.exists(), '')
        super().step_cleanup()


def run_all(run):
    ev = run.ev
    failure = None
    phases = [('secrets', run.load_secrets), ('setup', run.setup), ('before', run.step_before), ('craft', run.step_craft)]
    phases += [(case, lambda case=case: run.step_case(case)) for case in ('salt', 'version', 'hooks', 'hidden')]
    phases += [('unchanged', run.step_unchanged)]
    try:
        for name, step in phases:
            ev.log(f'== {name}')
            step()
    except Exception as error:  # noqa: BLE001 - whatever stopped a phase, the cleanup below always runs
        failure = error
        ev.check(f'phase stopped: {type(error).__name__}', False, str(error)[:300])
    if run.deployed:
        try:
            run.step_leaks()
        except Exception as error:  # noqa: BLE001
            failure = failure or error
            ev.check('leaks: ran', False, type(error).__name__)
    try:
        run.step_cleanup()
    except Exception as error:  # noqa: BLE001
        failure = failure or error
        ev.check('cleanup: ran', False, type(error).__name__)
    return failure


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args(argv)
    if not args.run:
        parser.error('--run required')
    drv.state_path = lambda: flow.LAB / 'run' / 'litellm_negative_flow.json'
    clean, _dirty = flow.clean_tree()
    commit = flow.head()
    emit(f'source commit {commit}')
    if not clean:
        emit('source tree committed: FAIL')
        return 2
    emit('source tree committed: PASS')
    fd, waited = flow.acquire()
    started = time.monotonic()
    emit(f'dev-d mutation lock acquired: PASS (waited {waited} s)')
    rc = 1
    try:
        emit(flow.verify_isolation())
        args.secrets = drv.Secrets([drv.SECRET_DIR / 'b1-creds.env', drv.SECRET_DIR / 'ha-import-creds.env'],
                                   drv.SECRET_DIR / 'dev-d-markers.json')
        ev = flow.Ev(args.secrets, 'litellm-negative')
        drv.STATE.clear()
        drv.load_state()
        drv.STATE['created_backups'] = []
        run = NegativeRun(args, ev)
        run.lock_started = started
        run.headroom()
        failure = run_all(run)
        failed = [r for r in ev.results if not r['ok']]
        ev.save('results.json', {'passed': len(ev.results) - len(failed), 'failed': len(failed),
                                 'failed_checks': [r['check'] for r in failed], 'results': ev.results,
                                 'source_commit': commit})
        drv.save_state()
        emit(f'litellm negative flow: {len(ev.results) - len(failed)}/{len(ev.results)} '
             f'{"PASS" if not failed and failure is None else "FAIL"}')
        rc = 0 if not failed and failure is None else 1
    finally:
        try:
            emit(flow.verify_isolation())
        except Failed:
            emit('dev-d isolation after the run: FAIL')
            rc = 1
        emit(f'lock held for {int(time.monotonic() - started)} s')
        os.close(fd)
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
