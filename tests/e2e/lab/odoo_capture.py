#!/usr/bin/env python3
"""Private same-run Odoo capture and fail-closed cell comparison; no table exemptions.

run is HOST-only through labpodman; requires an allocated heavyweight slot.
compare is entirely offline. Private artifacts contain cell hashes (not anonymized).
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

TABLES = {'public.' + t for t in ('ir_config_parameter', 'ir_cron', 'ir_cron_progress', 'bus_bus')}
STAGES = ('target_before', 'source_cold', 'restored_cold', 'converted_cold', 'runtime', 'quiescent')
HEX = re.compile(r'[0-9a-f]{64}')


def require(ok):
    if not ok:
        raise ValueError('capture contract rejected; contents withheld')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def file_hash(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def unique(pairs):
    obj = {}
    for k, v in pairs:
        require(k not in obj)
        obj[k] = v
    return obj


def loads(text):
    return json.loads(text, object_pairs_hook=unique)


def private_write(path, data):
    # Exclusive creation: never reuse a previous successful capture.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def validate(records, *, quiet=False):
    meta = [r for r in records if r.get('kind') == 'capture_metadata']
    require(len(meta) == 1 and meta[0].get('schema_version') == 1)
    require(isinstance(meta[0].get('database'), str) and bool(meta[0]['database']))
    require(type(meta[0].get('other_clients')) is int and meta[0]['other_clients'] >= 0)
    if quiet:
        require(meta[0]['other_clients'] == 0)
    tables = {t: {'schema': {}, 'rows': {}, 'count': None} for t in TABLES}
    for r in records:
        kind = r.get('kind')
        if kind == 'capture_metadata':
            continue
        require(kind in ('column', 'row', 'count') and r.get('table') in TABLES)
        table = tables[r['table']]
        if kind == 'column':
            name = r.get('name')
            require(isinstance(name, str) and name and name not in table['schema'])
            require(type(r.get('position')) is int and r['position'] > 0)
            require(isinstance(r.get('type'), str) and r['type'])
            require(type(r.get('primary_key')) is bool and type(r.get('not_null')) is bool)
            table['schema'][name] = {k: r[k] for k in ('position', 'type', 'not_null', 'primary_key', 'identity', 'generated', 'collation', 'default_sha256')}
        elif kind == 'count':
            require(table['count'] is None and type(r.get('count')) is int and r['count'] >= 0)
            table['count'] = r['count']
        else:
            ident = r.get('id')
            require(type(ident) is int and str(ident) not in table['rows'])
            require(isinstance(r.get('row_sha256'), str) and HEX.fullmatch(r['row_sha256']))
            fields = r.get('field_sha256')
            require(isinstance(fields, dict) and all(isinstance(v, str) and HEX.fullmatch(v) for v in fields.values()))
            table['rows'][str(ident)] = {'hash': r['row_sha256'], 'fields': fields}
    for table in tables.values():
        schema = table['schema']
        require(schema and [k for k, v in schema.items() if v['primary_key']] == ['id'])
        require(schema['id']['not_null'])
        require(len({c['position'] for c in schema.values()}) == len(schema))
        require(table['count'] == len(table['rows']))
        require(all(set(row['fields']) == set(schema) for row in table['rows'].values()))
    return tables


def differences(left, right):
    out = []
    for table in sorted(TABLES):
        a, b = left[table], right[table]
        if a['schema'] != b['schema']:
            out.append({'table': table, 'kind': 'schema'})
        for ident in sorted(set(a['rows']) | set(b['rows'])):
            x, y = a['rows'].get(ident), b['rows'].get(ident)
            if x is None or y is None:
                out.append({'table': table, 'id': ident, 'kind': 'added' if x is None else 'removed'})
                continue
            fields = sorted(k for k in set(x['fields']) | set(y['fields']) if x['fields'].get(k) != y['fields'].get(k))
            if fields or x['hash'] != y['hash']:
                out.append({'table': table, 'id': ident, 'kind': 'changed', 'fields': fields,
                            'hash_consistent': bool(fields) == (x['hash'] != y['hash'])})
    return out


def compare(directory):
    directory = Path(directory)
    manifest = loads((directory / 'complete.json').read_bytes())
    require(manifest['status'] == 'complete' and manifest['baseline_restored'] is True)
    captures, previous, common = {}, None, None
    for stage in STAGES:
        raw = (directory / (stage + '.json')).read_bytes()
        require(manifest['files'].get(stage + '.json') == digest(raw))
        cap = loads(raw)
        require(cap['stage'] == stage and cap['previous'] == previous)
        require(cap['run_id'] == manifest['run_id'])
        require(all(isinstance(cap[k], str) and HEX.fullmatch(cap[k]) for k in ('archive_sha256', 'engine_sha256', 'sql_sha256')))
        identity = tuple(cap[k] for k in ('run_id', 'archive_sha256', 'ha_backup_id', 'engine_sha256', 'sql_sha256', 'convert_job'))
        require(common is None or common == identity)
        common = identity
        require(cap['end_ns'] >= cap['start_ns'] and (previous is None or cap['start_ns'] >= prior_end))
        if stage in ('runtime', 'quiescent'):
            require(cap.get('restore_job') == manifest['restore_job'] and cap['restore_job'])
            require(cap.get('converted_backup_id') == manifest['converted_backup_id'] and cap['converted_backup_id'])
        if stage == 'quiescent':
            require(cap.get('odoo_active') == 'inactive')
        captures[stage] = validate(cap['records'], quiet=stage in ('source_cold', 'restored_cold', 'converted_cold', 'quiescent'))
        meta = next(r for r in cap['records'] if r['kind'] == 'capture_metadata')
        require(meta['database'] == (manifest['source_database'] if stage == 'source_cold' else 'odoo'))
        prior_end, previous = cap['end_ns'], digest(raw)
    require(manifest['files'].get('runtime-journal.bin') == file_hash(directory / 'runtime-journal.bin'))
    edges = [('source_cold', 'restored_cold'), ('restored_cold', 'converted_cold'),
             ('converted_cold', 'runtime'), ('runtime', 'quiescent'),
             ('source_cold', 'quiescent'), ('converted_cold', 'quiescent')]
    delta = {a + '->' + b: differences(captures[a], captures[b]) for a, b in edges}
    return {'status': 'unverified_differences' if any(delta.values()) else 'equal_four_table_cells',
            'acceptance': not any(delta.values()), 'run_id': manifest['run_id'], 'differences': delta,
            'limits': 'Four table schema/cells only. Runtime journal is evidence, never an exemption. No full application parity claim.'}


class Recorder:
    def __init__(self, directory, identity, sql):
        self.directory, self.identity, self.sql = Path(directory), identity, sql
        self.previous = None
        self.files = {}
        self.index = 0

    def capture(self, stage, query, **extra):
        require(stage == STAGES[self.index])
        start = time.time_ns()
        data = query(self.sql)
        records = [loads(line) for line in data.splitlines() if line.strip()]
        validate(records, quiet=stage in ('source_cold', 'restored_cold', 'converted_cold', 'quiescent'))
        cap = dict(self.identity, stage=stage, previous=self.previous, start_ns=start, end_ns=time.time_ns(),
                   records=records, **extra)
        raw = encoded(cap)
        private_write(self.directory / (stage + '.json'), raw)
        self.files[stage + '.json'] = self.previous = digest(raw)
        self.index += 1


@contextlib.contextmanager
def conversion_hooks(module, recorder, database):
    """In-process only: existing hardened member_pass/start_ha_cluster opens real archive.
    Capture the same ephemeral source and destination used by this conversion job.
    No alternate source path or baseline-as-source parameter exists.
    """
    from unittest.mock import patch
    original_start, original_restore = module.start_ha_cluster, module.restore_dump
    original_live, original_carry = module.live_settings, module.carry_settings

    def temporary(cluster, db):
        def query(sql):
            return cluster.tmp.exec(cluster.role, ['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                '-U', cluster.superuser, '-d', db, '-f', '-'], user='postgres', input=sql.encode(),
                timeout=120, max_output=32 * 1024 * 1024).stdout
        return query

    def live(work, app, config, image):
        def query(sql):
            return work.runner(app).podman('exec', '-i', config.db_container, 'psql', '-X', '-qAt',
                '-v', 'ON_ERROR_STOP=1', '-U', config.db_user, '-d', 'odoo', '-f', '-',
                input=sql.encode(), timeout=120, max_output=32 * 1024 * 1024).stdout
        recorder.capture('target_before', query)
        return original_live(work, app, config, image)

    def source(work, tmp, image):
        cluster = original_start(work, tmp, image)
        recorder.capture('source_cold', temporary(cluster, database))
        return cluster

    def restored(work, tmp, dump, db):
        result = original_restore(work, tmp, dump, db)
        recorder.capture('restored_cold', temporary(module.Cluster(tmp, 'odoo-db'), 'odoo'))
        return result

    def converted(work, app, config, cluster):
        result = original_carry(work, app, config, cluster)
        recorder.capture('converted_cold', temporary(cluster, 'odoo'))
        return result

    with patch.object(module, 'live_settings', live), patch.object(module, 'start_ha_cluster', source), \
         patch.object(module, 'restore_dump', restored), patch.object(module, 'carry_settings', converted):
        yield


def checked(argv, **kwargs):
    p = subprocess.run(argv, capture_output=True, timeout=kwargs.pop('timeout', 120), **kwargs)
    require(p.returncode == 0)
    return p.stdout


def device_run(request, sql):
    # Called only by the host guard below, in dev-c's private mount namespace.
    sys.path.insert(0, '/usr/local/lib/woowtech-cockpit-backup')
    from woowbackup import jobs, ha_odoo, hastore
    from woowbackup.paths import Paths
    paths = Paths()
    run_id = uuid.uuid4().hex
    directory = Path('/var/lib/woowtech-backup/odoo-captures') / run_id
    directory.mkdir(parents=True, mode=0o700)
    archive = hastore.HaStore(paths).file_path(request['ha_backup_id'])
    archive_hash = file_hash(archive)
    require(archive_hash == request['archive_sha256'])
    engine = Path('/usr/local/lib/woowtech-cockpit-backup/woowbackup')
    engine_files = {str(p.relative_to(engine)): file_hash(p) for p in sorted(engine.rglob('*.py'))}
    require(bool(engine_files))
    engine_hash = digest(encoded(engine_files))
    def job(kind, params, key=None):
        reply = jobs.start_job(paths, kind, params, str(uuid.uuid4()), key_text=key,
                               key_kind='ha', launcher=lambda ident: None)
        return reply['job_id']
    def execute(ident):
        result = jobs.run_job(paths, ident)
        require(result['state'] == 'succeeded')
        return result.get('result') or {}
    params = {'source': 'ha', 'ha_backup_id': request['ha_backup_id'], 'apps': ['odoo'],
              'odoo_database': request['database'], 'test_mode': False, 'encrypt': True,
              'key_provided': request.get('key') is not None}
    convert_job = job('backup', params, request.get('key'))
    identity = dict(run_id=run_id, archive_sha256=archive_hash, engine_sha256=engine_hash,
                    sql_sha256=digest(sql.encode()), ha_backup_id=request['ha_backup_id'], convert_job=convert_job)
    recorder = Recorder(directory, identity, sql)
    owner = ['/usr/local/bin/woowbk-owner']
    def live_query(query):
        return checked(owner + ['podman', 'exec', '-i', 'odoo18-db', 'psql', '-X', '-qAt', '-v',
            'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'odoo', '-f', '-'], input=query.encode())
    touched = False
    restore_job = None
    baseline_ok = False
    start = str(int(time.time()))
    try:
        with conversion_hooks(ha_odoo, recorder, request['database']):
            converted = execute(convert_job)
        require(file_hash(archive) == archive_hash)
        restore_job = job('restore', {'backup_id': converted['backup_id'], 'apps': ['odoo'], 'key_provided': False})
        touched = True
        execute(restore_job)
        recorder.capture('runtime', live_query, restore_job=restore_job, converted_backup_id=converted['backup_id'])
        checked(owner + ['systemctl', '--user', 'stop', 'odoo.service'])
        state = checked(owner + ['systemctl', '--user', 'show', 'odoo.service', '-p', 'ActiveState', '--value']).decode().strip()
        require(state == 'inactive')
        recorder.capture('quiescent', live_query, restore_job=restore_job, odoo_active=state,
                         converted_backup_id=converted['backup_id'])
        journal = checked(['journalctl', '--since', '@' + start, '--no-pager', '-o', 'json'], timeout=120)
        private_write(directory / 'runtime-journal.bin', journal)
        recorder.files['runtime-journal.bin'] = digest(journal)
    finally:
        try:
            if touched:
                # Recover even when capture or the candidate restore fails.
                baseline = job('restore', {'backup_id': request['baseline'], 'apps': ['odoo'], 'key_provided': False})
                execute(baseline)
                checked(owner + ['systemctl', '--user', 'start', 'odoo.service'])
                baseline_ok = True
        finally:
            private_write(directory / 'outcome.json', encoded({'run_id': run_id, 'baseline_restored': baseline_ok,
                                                               'stages': recorder.index, 'restore_job': restore_job}))
    require(recorder.index == len(STAGES) and baseline_ok and file_hash(archive) == archive_hash)
    require(engine_files == {str(p.relative_to(engine)): file_hash(p) for p in sorted(engine.rglob('*.py'))})
    private_write(directory / 'complete.json', encoded({'status': 'complete', 'run_id': run_id,
        'files': recorder.files, 'baseline_restored': baseline_ok, 'restore_job': restore_job, 'source_database': request['database'],
        'converted_backup_id': converted['backup_id'], 'baseline_backup_id': request['baseline']}))
    report = compare(directory)
    private_write(directory / 'comparison.json', encoded(report))
    return {'directory': str(directory), 'status': report['status'], 'acceptance': report['acceptance']}


def isolation(lp):
    require(checked([lp, 'container', 'inspect', 'woowbk-dev-c', '--format',
        '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}']).strip() == b'true none {}')


def fetch(lp, run_id, destination):
    isolation(lp)
    require(re.fullmatch(r'[0-9a-f]{32}', run_id))
    destination = Path(destination)
    destination.mkdir(mode=0o700)  # no mixing runs or stale files
    for name in [stage + '.json' for stage in STAGES] + ['runtime-journal.bin', 'outcome.json', 'complete.json']:
        data = checked([lp, 'exec', 'woowbk-dev-c', 'cat',
                        '/var/lib/woowtech-backup/odoo-captures/' + run_id + '/' + name])
        private_write(destination / name, data)
    return compare(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    offline = sub.add_parser('compare')
    offline.add_argument('directory')
    run = sub.add_parser('run')
    run.add_argument('--slot-granted', action='store_true', required=True)
    run.add_argument('--request', required=True, help='0600 JSON: ha_backup_id, archive_sha256, database, baseline, optional lab key')
    download = sub.add_parser('fetch')
    download.add_argument('--run-id', required=True)
    download.add_argument('--output', required=True)
    args = parser.parse_args()
    if args.command == 'compare':
        result = compare(args.directory)
    elif args.command == 'fetch':
        result = fetch(str(Path.home() / '.woowbk-lab/bin/labpodman'), args.run_id, args.output)
    else:
        lp = str(Path.home() / '.woowbk-lab/bin/labpodman')
        isolation(lp)
        path = Path(args.request)
        require(path.is_file() and not path.is_symlink() and path.stat().st_mode & 0o077 == 0)
        request = loads(path.read_bytes())
        require(HEX.fullmatch(request['archive_sha256']) and re.fullmatch(r'woowtest(?:2)?', request['database']))
        # No host Podman store, shell command construction, or persistent runner modification.
        script = Path(__file__).read_text()
        sql = Path(__file__).with_name('odoo_capture.sql').read_text()
        bootstrap = "import json,sys; p=json.load(sys.stdin); n={'__name__':'capture_module'}; exec(p['script'],n); print(json.dumps(n['device_run'](p['request'],p['sql'])))"
        data = checked([lp, 'exec', '-i', 'woowbk-dev-c', 'python3', '-I', '-c', bootstrap],
                       input=encoded({'script': script, 'sql': sql, 'request': request}), timeout=14400)
        result = loads(data)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['acceptance'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('{"status":"invalid_or_incomplete","acceptance":false}', file=sys.stderr)
        sys.exit(2)
